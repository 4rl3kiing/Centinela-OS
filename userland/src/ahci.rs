//! Polled AHCI (SATA) access for Ring 3 drivers.
//!
//! The HBA registers (ABAR, BAR 5) are mapped by the kernel (uncached, NX);
//! the command list, received-FIS area, command table and data buffers live
//! in DMA pages that are also mapped in the controller's IOMMU domain.
//! The first port with an ATA disk attached is used; commands are polled.

use crate::{DmaRegion, Line, dma_alloc, sleep};

pub const PAGE: usize = 4096;
/// DMA pages: 0 command list + received FIS, 1 command table, 2..=4
/// scratch (identify), 5 and 6 data buffers (same indices as the NVMe
/// driver so callers can share code).
pub const DMA_PAGES: u64 = 7;

const GHC: u64 = 0x04;
const PI: u64 = 0x0c;
const PORT_BASE: u64 = 0x100;
const PORT_STRIDE: u64 = 0x80;
const PX_CLB: u64 = 0x00;
const PX_FB: u64 = 0x08;
const PX_IS: u64 = 0x10;
const PX_CMD: u64 = 0x18;
const PX_TFD: u64 = 0x20;
const PX_SIG: u64 = 0x24;
const PX_SSTS: u64 = 0x28;
const PX_SERR: u64 = 0x30;
const PX_CI: u64 = 0x38;
const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const SIG_ATA: u32 = 0x0000_0101;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_IDENTIFY: u8 = 0xec;
const ATA_FLUSH_EXT: u8 = 0xea;

pub struct Ahci {
    mmio: u64,
    port: u64,
    pub dma: DmaRegion,
    /// Disk size in 512-byte sectors.
    pub blocks: u64,
    pub block_size: usize,
}

fn put(base: *mut u8, offset: usize, bytes: &[u8]) {
    for (index, byte) in bytes.iter().enumerate() {
        // SAFETY: Callers stay inside their own DMA pages.
        unsafe { core::ptr::write_volatile(base.add(offset + index), *byte) };
    }
}

fn get(base: *const u8, offset: usize) -> u8 {
    // SAFETY: As in `put`.
    unsafe { core::ptr::read_volatile(base.add(offset)) }
}

impl Ahci {
    fn read32(&self, register: u64) -> u32 {
        // SAFETY: The kernel mapped the HBA register BAR at `mmio`.
        unsafe { core::ptr::read_volatile((self.mmio + register) as *const u32) }
    }
    fn write32(&self, register: u64, value: u32) {
        // SAFETY: As in `read32`.
        unsafe { core::ptr::write_volatile((self.mmio + register) as *mut u32, value) }
    }
    fn port_read(&self, register: u64) -> u32 {
        self.read32(PORT_BASE + self.port * PORT_STRIDE + register)
    }
    fn port_write(&self, register: u64, value: u32) {
        self.write32(PORT_BASE + self.port * PORT_STRIDE + register, value);
    }
    fn page(&self, index: usize) -> *mut u8 {
        // SAFETY: Callers pass indices below DMA_PAGES.
        unsafe { self.dma.address.add(index * PAGE) }
    }
    fn iova(&self, index: usize) -> u64 {
        self.dma.iova + (index * PAGE) as u64
    }

    pub fn write_page(&self, page: usize, offset: usize, bytes: &[u8]) -> bool {
        let fits = page < DMA_PAGES as usize
            && offset
                .checked_add(bytes.len())
                .is_some_and(|end| end <= PAGE);
        if fits {
            put(self.page(page), offset, bytes);
        }
        fits
    }

    pub fn read_page(&self, page: usize, offset: usize, out: &mut [u8]) -> bool {
        let fits = page < DMA_PAGES as usize
            && offset.checked_add(out.len()).is_some_and(|end| end <= PAGE);
        if fits {
            for (index, byte) in out.iter_mut().enumerate() {
                *byte = get(self.page(page), offset + index);
            }
        }
        fits
    }

    fn wait(&self, done: impl Fn(&Self) -> bool) -> bool {
        for _ in 0..300 {
            for _ in 0..10_000 {
                if done(self) {
                    return true;
                }
                core::hint::spin_loop();
            }
            sleep(1);
        }
        false
    }

    /// Enables AHCI mode, finds the first port with an ATA disk, sets up its
    /// command list and identifies the disk. `line` receives a description.
    pub fn bring_up(mmio: u64, line: &mut Line) -> Result<Self, (&'static str, u64)> {
        let dma = dma_alloc(DMA_PAGES).ok_or(("ahci: no DMA pages", 4))?;
        let mut hba = Self {
            mmio,
            port: 0,
            dma,
            blocks: 0,
            block_size: 512,
        };
        hba.write32(GHC, hba.read32(GHC) | 1 << 31);
        let implemented = hba.read32(PI);
        let port = (0..32u64).find(|&port| {
            implemented & (1 << port) != 0 && {
                hba.port = port;
                hba.port_read(PX_SSTS) & 0xf == 3 && hba.port_read(PX_SIG) == SIG_ATA
            }
        });
        let Some(port) = port else {
            return Err(("ahci: no SATA disk attached", 30));
        };
        hba.port = port;
        // Stop the port before pointing it at our memory.
        hba.port_write(PX_CMD, hba.port_read(PX_CMD) & !(CMD_ST | CMD_FRE));
        if !hba.wait(|h| h.port_read(PX_CMD) & (CMD_CR | CMD_FR) == 0) {
            return Err(("ahci: port did not stop", 31));
        }
        let command_list = hba.iova(0);
        hba.port_write(PX_CLB, command_list as u32);
        hba.port_write(PX_CLB + 4, (command_list >> 32) as u32);
        let fis = command_list + 1024;
        hba.port_write(PX_FB, fis as u32);
        hba.port_write(PX_FB + 4, (fis >> 32) as u32);
        hba.port_write(PX_SERR, u32::MAX);
        hba.port_write(PX_IS, u32::MAX);
        hba.port_write(PX_CMD, hba.port_read(PX_CMD) | CMD_FRE);
        hba.port_write(PX_CMD, hba.port_read(PX_CMD) | CMD_ST);
        if !hba.command(ATA_IDENTIFY, 0, 1, 2, false) {
            return Err(("ahci: IDENTIFY failed", 32));
        }
        let mut words = [0u8; 512];
        hba.read_page(2, 0, &mut words);
        let word =
            |index: usize| u64::from(u16::from_le_bytes([words[index * 2], words[index * 2 + 1]]));
        hba.blocks = word(100) | word(101) << 16 | word(102) << 32 | word(103) << 48;
        if hba.blocks < 16 {
            return Err(("ahci: disk unusable (no LBA48 size)", 33));
        }
        let mut model = [0u8; 40];
        for (index, pair) in model.chunks_mut(2).enumerate() {
            pair[0] = words[54 + index * 2 + 1];
            pair[1] = words[54 + index * 2];
        }
        for byte in model.iter_mut() {
            if !(0x20..0x7f).contains(byte) {
                *byte = b'?';
            }
        }
        line.push(b"ahci: port ")
            .number(port)
            .push(b" disk '")
            .push(model.trim_ascii_end())
            .push(b"'");
        Ok(hba)
    }

    /// One polled ATA command through command slot 0.
    fn command(&self, ata: u8, lba: u64, count: u16, page: usize, write: bool) -> bool {
        // Command header: CFL = 5 dwords, W, PRDTL = 1, CTBA = page 1.
        let mut header = [0u8; 32];
        let flags = 5u16 | if write { 1 << 6 } else { 0 };
        header[0..2].copy_from_slice(&flags.to_le_bytes());
        header[2..4].copy_from_slice(&1u16.to_le_bytes());
        header[8..16].copy_from_slice(&self.iova(1).to_le_bytes());
        put(self.page(0), 0, &header);
        // Command table: H2D register FIS, then one PRD entry at 0x80.
        let mut table = [0u8; 0x90];
        table[0] = 0x27;
        table[1] = 0x80;
        table[2] = ata;
        let bytes_lba = lba.to_le_bytes();
        table[4..7].copy_from_slice(&bytes_lba[0..3]);
        table[7] = if ata == ATA_IDENTIFY { 0 } else { 1 << 6 };
        table[8..11].copy_from_slice(&bytes_lba[3..6]);
        table[12..14].copy_from_slice(&count.to_le_bytes());
        let bytes = if ata == ATA_FLUSH_EXT {
            0
        } else {
            u32::from(count) * 512
        };
        table[0x80..0x88].copy_from_slice(&self.iova(page).to_le_bytes());
        if bytes != 0 {
            table[0x8c..0x90].copy_from_slice(&(bytes - 1).to_le_bytes());
        } else {
            header[2..4].copy_from_slice(&0u16.to_le_bytes());
            put(self.page(0), 0, &header);
        }
        put(self.page(1), 0, &table);
        self.port_write(PX_IS, u32::MAX);
        self.port_write(PX_CI, 1);
        let finished =
            self.wait(|h| h.port_read(PX_CI) & 1 == 0 || h.port_read(PX_IS) & (1 << 30) != 0);
        finished && self.port_read(PX_TFD) & 1 == 0 && self.port_read(PX_IS) & (1 << 30) == 0
    }

    /// Reads or writes `count` sectors (at most one page) through `page`.
    pub fn transfer(&mut self, write: bool, lba: u64, count: u16, page: usize) -> bool {
        if count == 0 || usize::from(count) * 512 > PAGE || page >= DMA_PAGES as usize {
            return false;
        }
        let ata = if write {
            ATA_WRITE_DMA_EXT
        } else {
            ATA_READ_DMA_EXT
        };
        self.command(ata, lba, count, page, write)
    }

    pub fn flush(&mut self) -> bool {
        self.command(ATA_FLUSH_EXT, 0, 0, 2, false)
    }
}
