//! Ring 3 installer: puts Centinela-OS on the NVMe disk.
//!
//! Layout (GPT): partition 1 = EFI system partition (FAT32, 160 MiB) with
//! the signed Limine loader, its config, the kernel and the user programs
//! (all from the hashed `install-payload` boot module, lent read-only);
//! partition 2 = the CFS system volume (rest of the disk).
//!
//! Safety: without the explicit "erase" boot entry the installer only
//! writes to a blank disk (no partition table, first sectors all zero).
//! It has no other authority: NVMe registers and DMA confined to the
//! controller's IOMMU domain, and the payload is read-only.
#![no_std]
#![no_main]

use centinela_cfs::{BLOCK_SIZE, Block, BlockDevice, Volume};
use centinela_disk::fat32::{self, FileSpec};
use centinela_disk::gpt::{self, CFS_TYPE, ESP_TYPE, Partition};
use centinela_disk::payload::Payload;
use centinela_disk::{SECTOR, Sector, SectorDevice};
use centinela_userland::nvme::Nvme;
use centinela_userland::{Line, exit, write};

/// Kernel convention: MMIO window and lent module locations.
const MMIO_BASE: u64 = 0x0000_5000_0000_0000;
const MODULE_BASE: u64 = 0x0000_4000_0000_0000;
const ESP_FIRST: u64 = 2048;
const ESP_SECTORS: u64 = 160 * 1024 * 1024 / SECTOR as u64;

static mut BITMAP: [u64; 4096] = [0; 4096];

struct Disk {
    nvme: Nvme,
    sectors: u64,
}

impl SectorDevice for Disk {
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, buffer: &mut Sector) -> Result<(), centinela_disk::Error> {
        if lba >= self.sectors
            || !self.nvme.transfer(false, lba, 1, 6)
            || !self.nvme.read_page(6, 0, buffer)
        {
            return Err(centinela_disk::Error::Io);
        }
        Ok(())
    }
    fn write(&mut self, lba: u64, buffer: &Sector) -> Result<(), centinela_disk::Error> {
        if lba >= self.sectors
            || !self.nvme.write_page(6, 0, buffer)
            || !self.nvme.transfer(true, lba, 1, 6)
        {
            return Err(centinela_disk::Error::Io);
        }
        Ok(())
    }
}

/// CFS on partition 2: 4 KiB blocks over 512-byte sectors.
struct PartitionBlocks<'a> {
    disk: &'a mut Disk,
    first: u64,
    blocks: u64,
}

impl BlockDevice for PartitionBlocks<'_> {
    fn block_count(&self) -> u64 {
        self.blocks
    }
    fn read(&mut self, block: u64, buffer: &mut Block) -> Result<(), centinela_cfs::Error> {
        let lba = self.first + block * 8;
        if block >= self.blocks
            || !self.disk.nvme.transfer(false, lba, 8, 5)
            || !self.disk.nvme.read_page(5, 0, buffer)
        {
            return Err(centinela_cfs::Error::Io);
        }
        Ok(())
    }
    fn write(&mut self, block: u64, buffer: &Block) -> Result<(), centinela_cfs::Error> {
        let lba = self.first + block * 8;
        if block >= self.blocks
            || !self.disk.nvme.write_page(5, 0, buffer)
            || !self.disk.nvme.transfer(true, lba, 8, 5)
        {
            return Err(centinela_cfs::Error::Io);
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), centinela_cfs::Error> {
        if self.disk.nvme.flush() {
            Ok(())
        } else {
            Err(centinela_cfs::Error::Io)
        }
    }
}

fn fail(message: &str, code: u64) -> ! {
    write(message);
    exit(code)
}

fn guid(seed: u64) -> gpt::Guid {
    // Uniqueness, not secrecy: TSC mixed with a per-partition seed.
    // SAFETY: RDTSC is unprivileged.
    let mut x = unsafe { core::arch::x86_64::_rdtsc() } ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut out = [0u8; 16];
    for chunk in out.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    out[7] = (out[7] & 0x0f) | 0x40; // version 4
    out[8] = (out[8] & 0x3f) | 0x80; // RFC 4122 variant
    out
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_unused: u64, payload_len: u64, _unused2: u64, wipe: u64) -> ! {
    // SAFETY: The kernel lent the payload module read-only at MODULE_BASE,
    // `payload_len` bytes long.
    let bytes =
        unsafe { core::slice::from_raw_parts(MODULE_BASE as *const u8, payload_len as usize) };
    let Some(payload) = Payload::parse(bytes) else {
        fail(
            "installer: install payload is malformed; nothing written",
            2,
        )
    };
    let mut model = Line::new();
    let nvme = match Nvme::bring_up(MMIO_BASE, &mut model) {
        Ok(nvme) => nvme,
        Err((message, code)) => fail(message, code),
    };
    if nvme.block_size != SECTOR {
        fail(
            "installer: only 512-byte-sector NVMe disks are supported for now",
            3,
        );
    }
    let sectors = nvme.blocks;
    let mut disk = Disk { nvme, sectors };
    model
        .push(b"; ")
        .number(sectors * SECTOR as u64 / (1024 * 1024))
        .push(b" MiB")
        .print();

    // Refuse a disk with content unless the erase entry was chosen.
    let mut sector = [0u8; SECTOR];
    let mut blank = true;
    for lba in (0..34).chain([sectors - 1]) {
        if disk.read(lba, &mut sector).is_err() {
            fail("installer: cannot read the disk", 4);
        }
        blank &= sector.iter().all(|&b| b == 0);
    }
    if !blank && wipe == 0 {
        fail(
            "installer: the disk is not blank; choose the 'erase disk' boot entry to overwrite it",
            5,
        );
    }

    let Some((_, last)) = gpt::usable_range(sectors) else {
        fail("installer: disk too small", 6)
    };
    let cfs_first = ESP_FIRST + ESP_SECTORS;
    // CFS blocks are 4 KiB: round the partition down to whole blocks.
    let cfs_last = cfs_first + ((last + 1 - cfs_first) / 8) * 8 - 1;
    if cfs_last <= cfs_first + 64 * 8 {
        fail("installer: disk too small (need about 200 MiB)", 6);
    }
    let partitions = [
        Partition {
            type_guid: ESP_TYPE,
            unique_guid: guid(1),
            first_lba: ESP_FIRST,
            last_lba: ESP_FIRST + ESP_SECTORS - 1,
            name: gpt::name(b"EFI system"),
        },
        Partition {
            type_guid: CFS_TYPE,
            unique_guid: guid(2),
            first_lba: cfs_first,
            last_lba: cfs_last,
            name: gpt::name(b"Centinela system"),
        },
    ];
    if gpt::write(&mut disk, &guid(3), &partitions).is_err() {
        fail("installer: writing the partition table failed", 7);
    }
    Line::new()
        .push(b"installer: GPT written (ESP 160 MiB, CFS system ")
        .number((cfs_last + 1 - cfs_first) * SECTOR as u64 / (1024 * 1024))
        .push(b" MiB)")
        .print();

    let mut files = [FileSpec {
        path: b"",
        data: b"",
    }; 64];
    for (index, slot) in files.iter_mut().enumerate().take(payload.len()) {
        if let Some(file) = payload.file(index) {
            *slot = FileSpec {
                path: file.path,
                data: file.data,
            };
        }
    }
    if fat32::format_with_files(
        &mut disk,
        ESP_FIRST,
        ESP_SECTORS,
        b"CENTINELA  ",
        &files[..payload.len()],
    )
    .is_err()
    {
        fail("installer: writing the EFI system partition failed", 8);
    }
    Line::new()
        .push(b"installer: EFI system partition (FAT32) holds ")
        .number(payload.len() as u64)
        .push(b" files: loader, config, kernel and programs")
        .print();

    let blocks = (cfs_last + 1 - cfs_first) / 8;
    let mut volume_device = PartitionBlocks {
        disk: &mut disk,
        first: cfs_first,
        blocks,
    };
    if centinela_cfs::format(&mut volume_device, b"centinela-system").is_err() {
        fail("installer: formatting the CFS system volume failed", 9);
    }
    // SAFETY: Single-threaded task; the bitmap is only lent to the volume.
    let bitmap = unsafe { &mut *core::ptr::addr_of_mut!(BITMAP) };
    let words = centinela_cfs::bitmap_words(blocks);
    if words > bitmap.len() {
        fail(
            "installer: system volume larger than 512 MiB is not supported yet",
            10,
        );
    }
    let Ok(mut volume) = Volume::mount(volume_device, &mut bitmap[..words]) else {
        fail("installer: the new system volume does not mount", 11)
    };
    let note = b"Instalado por el instalador de Centinela-OS.";
    if volume.write_file(0, b"install-info", note).is_err() {
        fail("installer: writing install-info failed", 12);
    }
    let _ = BLOCK_SIZE;
    write("installer: CFS system volume formatted; install-info recorded");
    write("installer: installation complete");
    exit(0)
}
