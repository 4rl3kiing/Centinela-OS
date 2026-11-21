//! Ring 3 persistent storage service: NVMe driver + CFS filesystem.
//!
//! The volume lives on NVMe namespace 1 (minus its last 4 KiB, reserved for
//! the driver self-test). A blank disk is formatted on first use. Every
//! client is identified by the badge of its capability, which CFS stores as
//! the file owner, so clients only ever see their own files.
//!
//! The block service and the filesystem share this task until capability-
//! based shared memory exists (phase 8); IPC messages are 4 words, so file
//! contents travel 16 bytes per message.
//!
//! Requests (word 0 = op): 1 BEGIN(name lo, name hi) starts staging a file;
//! 2 DATA(len, bytes lo, bytes hi) appends up to 16 bytes; 3 COMMIT writes the
//! staged file atomically; 4 READ(name lo, name hi, offset) returns up to 16
//! bytes; 5 DELETE(name lo, name hi); 6 LIST(index) returns name and size.
//! Names are up to 16 bytes. Replies: [status, a, b, c].
#![no_std]
#![no_main]

use centinela_cfs::{BLOCK_SIZE, Block, BlockDevice, Error, Volume, format};
use centinela_disk::gpt::{self, CFS_TYPE, MAX_PARTITIONS, Partition};
use centinela_disk::{Sector, SectorDevice};
use centinela_userland::nvme::Nvme;
use centinela_userland::{FLAG_KERNEL_ORIGIN, Line, exit, pack, reply_and_wait, reply_wait, write};

/// Largest volume served (bitmap of 1024 words = 65536 blocks = 256 MiB).
const MAX_VOLUME_BLOCKS: u64 = 65536;
const STAGING: usize = 64 * 1024;
const ENOENT: u64 = 4;
const EINVAL: u64 = 3;
const EBUSY: u64 = 16;
const EIO: u64 = 5;
const ENOSPC: u64 = 28;
const ECORRUPT: u64 = 74;

static mut BITMAP: [u64; 1024] = [0; 1024];
static mut STAGED: [u8; STAGING] = [0; STAGING];

struct Disk {
    nvme: Nvme,
    /// First LBA of the volume (the CFS partition on an installed disk).
    first: u64,
    blocks: u64,
    sectors_per_block: u64,
}

/// Raw 512-byte sector access for reading the partition table.
struct Sectors<'a>(&'a mut Nvme);

impl SectorDevice for Sectors<'_> {
    fn sectors(&self) -> u64 {
        self.0.blocks
    }
    fn read(&mut self, lba: u64, buffer: &mut Sector) -> Result<(), centinela_disk::Error> {
        if self.0.transfer(false, lba, 1, 6) && self.0.read_page(6, 0, buffer) {
            Ok(())
        } else {
            Err(centinela_disk::Error::Io)
        }
    }
    fn write(&mut self, _: u64, _: &Sector) -> Result<(), centinela_disk::Error> {
        Err(centinela_disk::Error::Io)
    }
}

impl BlockDevice for Disk {
    fn block_count(&self) -> u64 {
        self.blocks
    }
    fn read(&mut self, block: u64, buffer: &mut Block) -> Result<(), Error> {
        if block >= self.blocks
            || !self.nvme.transfer(
                false,
                self.first + block * self.sectors_per_block,
                self.sectors_per_block as u16,
                5,
            )
            || !self.nvme.read_page(5, 0, buffer)
        {
            return Err(Error::Io);
        }
        Ok(())
    }
    fn write(&mut self, block: u64, buffer: &Block) -> Result<(), Error> {
        if block >= self.blocks
            || !self.nvme.write_page(5, 0, buffer)
            || !self.nvme.transfer(
                true,
                self.first + block * self.sectors_per_block,
                self.sectors_per_block as u16,
                5,
            )
        {
            return Err(Error::Io);
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        if self.nvme.flush() {
            Ok(())
        } else {
            Err(Error::Io)
        }
    }
}

fn fail(message: &str, code: u64) -> ! {
    write(message);
    exit(code)
}

fn status(error: Error) -> u64 {
    match error {
        Error::NotFound => ENOENT,
        Error::NoSpace | Error::DirectoryFull | Error::FileTooLarge => ENOSPC,
        Error::Corrupt => ECORRUPT,
        Error::InvalidName => EINVAL,
        _ => EIO,
    }
}

/// Unpacks a name from two words (up to 16 bytes, zero-terminated).
fn name(low: u64, high: u64, out: &mut [u8; 16]) -> usize {
    out[..8].copy_from_slice(&low.to_le_bytes());
    out[8..].copy_from_slice(&high.to_le_bytes());
    out.iter().position(|&b| b == 0).unwrap_or(16)
}

fn boot_count<D: BlockDevice>(volume: &mut Volume<'_, D>) -> Result<u64, Error> {
    let mut digits = [0u8; 20];
    let previous = match volume.read(0, b"boot-count", 0, &mut digits) {
        Ok(length) => core::str::from_utf8(&digits[..length])
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .unwrap_or(0),
        Err(Error::NotFound) => 0,
        Err(error) => return Err(error),
    };
    let next = previous + 1;
    let mut text = Line::new();
    text.number(next);
    volume.write_file(0, b"boot-count", text.as_str().as_bytes())?;
    Ok(next)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(endpoint: u64, _unused: u64, _unused2: u64, mmio: u64) -> ! {
    let mut model = Line::new();
    let mut nvme = match Nvme::bring_up(mmio, &mut model) {
        Ok(nvme) => nvme,
        Err((message, code)) => fail(message, code),
    };
    let sectors_per_block = (BLOCK_SIZE / nvme.block_size) as u64;
    // An installed disk carries a GPT with a CFS partition; a bare disk (the
    // test harness, or a disk prepared with cfs-tool) is used whole, minus
    // its last 4 KiB.
    let mut partitions = [Partition::default(); MAX_PARTITIONS];
    let system = if nvme.block_size == 512 {
        gpt::read(&mut Sectors(&mut nvme), &mut partitions)
            .ok()
            .and_then(|count| {
                partitions[..count]
                    .iter()
                    .find(|p| p.type_guid == CFS_TYPE)
                    .copied()
            })
    } else {
        None
    };
    let (first, blocks) = match system {
        Some(partition) => (partition.first_lba, partition.sectors() / sectors_per_block),
        None => (0, nvme.blocks / sectors_per_block - 1),
    };
    let blocks = blocks.min(MAX_VOLUME_BLOCKS);
    let mut disk = Disk {
        nvme,
        first,
        blocks,
        sectors_per_block,
    };
    // SAFETY: Single-threaded task; the bitmap is only lent to the volume.
    let bitmap = unsafe { &mut *core::ptr::addr_of_mut!(BITMAP) };
    let mut formatted = false;
    let mut volume = match Volume::mount(&mut disk, bitmap) {
        Ok(volume) => volume,
        Err(Error::NotFormatted) => {
            // Format only a blank disk (first blocks all zero). Foreign data
            // and damaged volumes are refused, never "repaired" by formatting.
            let mut block = [0u8; BLOCK_SIZE];
            let blank = (0..3)
                .all(|index| disk.read(index, &mut block).is_ok() && block.iter().all(|&b| b == 0));
            if !blank {
                fail(
                    "storage: disk holds unknown data; refusing to format it",
                    25,
                );
            }
            if format(&mut disk, b"centinela").is_err() {
                fail("storage: format failed", 21);
            }
            formatted = true;
            // SAFETY: As above; the failed mount released its borrow.
            let bitmap = unsafe { &mut *core::ptr::addr_of_mut!(BITMAP) };
            match Volume::mount(&mut disk, bitmap) {
                Ok(volume) => volume,
                Err(_) => fail("storage: fresh volume does not mount", 22),
            }
        }
        Err(_) => fail(
            "storage: volume rejected (corrupt or not CFS); refusing to touch it",
            23,
        ),
    };
    let count = match boot_count(&mut volume) {
        Ok(count) => count,
        Err(_) => fail("storage: could not update boot-count", 24),
    };
    let sb = volume.superblock();
    let mut line = Line::new();
    line.push(b"storage: CFS volume of ")
        .number(sb.block_count)
        .push(b" blocks")
        .push(if formatted {
            b" (blank disk formatted)"
        } else {
            b""
        })
        .push(b", generation ")
        .number(sb.generation)
        .push(b", ")
        .number(volume.entries().len() as u64)
        .push(if system.is_some() {
            b" files on GPT partition 'Centinela system'"
        } else {
            b" files"
        })
        .push(b"; boot count now ")
        .number(count)
        .print();
    let mut info = [0u8; 80];
    if let Ok(length) = volume.read(0, b"install-info", 0, &mut info) {
        Line::new()
            .push(b"storage: install-info: ")
            .push(info[..length].trim_ascii_end())
            .print();
    }
    let mut welcome = [0u8; 60];
    if let Ok(length) = volume.read(0, b"welcome.txt", 0, &mut welcome) {
        let shown = welcome[..length].trim_ascii_end();
        Line::new()
            .push(b"storage: welcome.txt written by the host tool: ")
            .push(shown)
            .print();
    }

    // Client service loop.
    let mut staged_by: Option<(u64, [u8; 16], usize)> = None;
    let mut staged_len = 0usize;
    let mut message = reply_wait(endpoint);
    loop {
        let words = message.words;
        let badge = message.badge;
        let reply = if message.status != 0 || message.flags & FLAG_KERNEL_ORIGIN != 0 {
            [EINVAL, 0, 0, 0]
        } else {
            let mut buffer = [0u8; 16];
            match words[0] {
                1 => {
                    let length = name(words[1], words[2], &mut buffer);
                    match staged_by {
                        Some((owner, _, _)) if owner != badge => [EBUSY, 0, 0, 0],
                        _ => {
                            staged_by = Some((badge, buffer, length));
                            staged_len = 0;
                            [0, 0, 0, 0]
                        }
                    }
                }
                2 => match staged_by {
                    Some((owner, _, _)) if owner == badge => {
                        let length = words[1] as usize;
                        if length > 16 || staged_len + length > STAGING {
                            [ENOSPC, 0, 0, 0]
                        } else {
                            buffer[..8].copy_from_slice(&words[2].to_le_bytes());
                            buffer[8..].copy_from_slice(&words[3].to_le_bytes());
                            // SAFETY: Single-threaded; bounds checked above.
                            let staged = unsafe { &mut *core::ptr::addr_of_mut!(STAGED) };
                            staged[staged_len..staged_len + length]
                                .copy_from_slice(&buffer[..length]);
                            staged_len += length;
                            [0, staged_len as u64, 0, 0]
                        }
                    }
                    _ => [EBUSY, 0, 0, 0],
                },
                3 => match staged_by.take() {
                    Some((owner, file, length)) if owner == badge => {
                        // SAFETY: As above.
                        let staged = unsafe { &*core::ptr::addr_of!(STAGED) };
                        match volume.write_file(owner, &file[..length], &staged[..staged_len]) {
                            Ok(()) => [0, staged_len as u64, volume.superblock().generation, 0],
                            Err(error) => [status(error), 0, 0, 0],
                        }
                    }
                    other => {
                        staged_by = other;
                        [EBUSY, 0, 0, 0]
                    }
                },
                4 => {
                    let length = name(words[1], words[2], &mut buffer);
                    let mut data = [0u8; 16];
                    match volume.read(badge, &buffer[..length], words[3], &mut data) {
                        Ok(count) => [0, count as u64, pack(&data[..8]), pack(&data[8..])],
                        Err(error) => [status(error), 0, 0, 0],
                    }
                }
                5 => {
                    let length = name(words[1], words[2], &mut buffer);
                    match volume.delete(badge, &buffer[..length]) {
                        Ok(()) => [0, 0, 0, 0],
                        Err(error) => [status(error), 0, 0, 0],
                    }
                }
                6 => {
                    let visible = volume.entries().iter().filter(|entry| entry.owner == badge);
                    match visible.clone().nth(words[1] as usize) {
                        Some(entry) if entry.name().len() <= 16 => {
                            let mut padded = [0u8; 16];
                            padded[..entry.name().len()].copy_from_slice(entry.name());
                            [0, pack(&padded[..8]), pack(&padded[8..]), entry.size]
                        }
                        _ => [ENOENT, 0, 0, 0],
                    }
                }
                _ => [EINVAL, 0, 0, 0],
            }
        };
        message = reply_and_wait(endpoint, reply);
    }
}
