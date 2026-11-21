extern crate std;

use std::vec;
use std::vec::Vec;

use super::*;

/// RAM disk.
#[derive(Clone)]
struct Memory {
    blocks: Vec<Block>,
}

impl Memory {
    fn new(count: usize) -> Self {
        Self {
            blocks: vec![[0u8; BLOCK_SIZE]; count],
        }
    }
}

impl BlockDevice for Memory {
    fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }
    fn read(&mut self, block: u64, buffer: &mut Block) -> Result<(), Error> {
        *buffer = *self.blocks.get(block as usize).ok_or(Error::Io)?;
        Ok(())
    }
    fn write(&mut self, block: u64, buffer: &Block) -> Result<(), Error> {
        *self.blocks.get_mut(block as usize).ok_or(Error::Io)? = *buffer;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Power loss after `budget` writes: later writes never reach the disk; the
/// write at the budget boundary may be torn (first half only).
struct Crashing<'a> {
    disk: &'a mut Memory,
    budget: usize,
    torn: bool,
}

impl BlockDevice for Crashing<'_> {
    fn block_count(&self) -> u64 {
        self.disk.blocks.len() as u64
    }
    fn read(&mut self, block: u64, buffer: &mut Block) -> Result<(), Error> {
        *buffer = self.disk.blocks[block as usize];
        Ok(())
    }
    fn write(&mut self, block: u64, buffer: &Block) -> Result<(), Error> {
        if self.budget == 0 {
            return Ok(());
        }
        self.budget -= 1;
        if self.budget == 0 && self.torn {
            self.disk.blocks[block as usize][..BLOCK_SIZE / 2]
                .copy_from_slice(&buffer[..BLOCK_SIZE / 2]);
        } else {
            self.disk.blocks[block as usize] = *buffer;
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

fn fresh(blocks: usize) -> Memory {
    let mut disk = Memory::new(blocks);
    format(&mut &mut disk, b"test").unwrap();
    disk
}

fn read_all(volume: &mut Volume<'_, impl BlockDevice>, owner: u64, name: &[u8]) -> Vec<u8> {
    let size = volume.lookup(owner, name).unwrap().size as usize;
    let mut out = vec![0u8; size];
    assert_eq!(volume.read(owner, name, 0, &mut out).unwrap(), size);
    out
}

#[test]
fn format_mount_write_read_and_remount() {
    let mut disk = fresh(64);
    let mut bitmap = [0u64; 1];
    let payload: Vec<u8> = (0..10_000u32).map(|i| (i * 7) as u8).collect();
    {
        let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
        assert_eq!(volume.entries().len(), 0);
        volume.write_file(0, b"notes.txt", &payload).unwrap();
        volume.write_file(0, b"empty", b"").unwrap();
        assert_eq!(read_all(&mut volume, 0, b"notes.txt"), payload);
    }
    let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
    assert_eq!(volume.entries().len(), 2);
    assert_eq!(read_all(&mut volume, 0, b"notes.txt"), payload);
    assert_eq!(read_all(&mut volume, 0, b"empty"), b"");
    assert_eq!(volume.check().unwrap(), 2);
}

#[test]
fn overwrite_and_delete_reclaim_space() {
    let mut disk = fresh(32);
    let mut bitmap = [0u64; 1];
    let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
    let free = volume.free_blocks();
    for round in 0..50u8 {
        volume.write_file(0, b"counter", &[round; 5000]).unwrap();
    }
    assert_eq!(read_all(&mut volume, 0, b"counter"), vec![49u8; 5000]);
    volume.delete(0, b"counter").unwrap();
    assert_eq!(volume.free_blocks(), free, "every block reclaimed");
    assert_eq!(volume.delete(0, b"counter"), Err(Error::NotFound));
}

#[test]
fn owners_have_separate_namespaces() {
    let mut disk = fresh(32);
    let mut bitmap = [0u64; 1];
    let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
    volume.write_file(1, b"doc", b"tenant-A").unwrap();
    volume.write_file(2, b"doc", b"tenant-B").unwrap();
    assert_eq!(read_all(&mut volume, 1, b"doc"), b"tenant-A");
    assert_eq!(read_all(&mut volume, 2, b"doc"), b"tenant-B");
    assert_eq!(volume.lookup(3, b"doc"), None);
}

#[test]
fn limits_are_enforced() {
    let mut disk = fresh(16);
    let mut bitmap = [0u64; 1];
    let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
    assert_eq!(volume.write_file(0, b"", b"x"), Err(Error::InvalidName));
    assert_eq!(volume.write_file(0, b"a/b", b"x"), Err(Error::InvalidName));
    assert_eq!(
        volume.write_file(0, b"bad\x1b", b"x"),
        Err(Error::InvalidName)
    );
    assert_eq!(
        volume.write_file(0, &[b'a'; 41], b"x"),
        Err(Error::InvalidName)
    );
    assert_eq!(
        volume.write_file(0, b"big", &vec![0u8; MAX_FILE_SIZE + 1]),
        Err(Error::FileTooLarge)
    );
    // Too big for this 16-block volume: fails cleanly, volume unchanged.
    assert_eq!(
        volume.write_file(0, b"big", &vec![1u8; 20 * BLOCK_SIZE]),
        Err(Error::NoSpace)
    );
    assert_eq!(volume.entries().len(), 0);
    volume.write_file(0, b"ok", b"still works").unwrap();
    assert_eq!(read_all(&mut volume, 0, b"ok"), b"still works");
}

#[test]
fn bitmap_must_cover_the_device() {
    let mut disk = fresh(200);
    let mut small = [0u64; 1];
    assert_eq!(
        Volume::mount(&mut disk, &mut small).err(),
        Some(Error::TooLarge)
    );
}

/// Power loss at every possible write of an update (clean and torn): the
/// volume must always mount and show either the old or the new content.
#[test]
fn crash_at_any_point_leaves_old_or_new_state() {
    for torn in [false, true] {
        let mut writes_needed = 0;
        for budget in 0..64 {
            let mut disk = fresh(48);
            let mut bitmap = [0u64; 1];
            {
                let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
                volume.write_file(0, b"file", &[0xaa; 9000]).unwrap();
            }
            let device = Crashing {
                disk: &mut disk,
                budget,
                torn,
            };
            {
                let mut volume = Volume::mount(device, &mut bitmap).unwrap();
                let _ = volume.write_file(0, b"file", &[0xbb; 9000]);
            }
            let mut volume = Volume::mount(&mut disk, &mut bitmap).expect("mounts after crash");
            let content = read_all(&mut volume, 0, b"file");
            assert!(
                content == vec![0xaa; 9000] || content == vec![0xbb; 9000],
                "budget {budget} torn {torn}: mixed content"
            );
            volume.check().unwrap();
            if content == vec![0xbb; 9000] && writes_needed == 0 {
                writes_needed = budget;
            }
        }
        // Data (3) + inode + directory + superblock = 6 writes.
        assert_eq!(writes_needed, if torn { 7 } else { 6 });
    }
}

#[test]
fn corruption_is_detected_never_returned() {
    let mut disk = fresh(32);
    let mut bitmap = [0u64; 1];
    {
        let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
        volume.write_file(0, b"file", &[7u8; 6000]).unwrap();
    }
    // Flip one byte in every block in turn.
    for block in 0..32 {
        for offset in [0usize, 100, 4000] {
            let mut copy = disk.clone();
            copy.blocks[block][offset] ^= 0x40;
            let mut bitmap = [0u64; 1];
            match Volume::mount(&mut copy, &mut bitmap) {
                Err(_) => {}
                Ok(mut volume) => match volume.lookup(0, b"file") {
                    None => panic!("block {block}: file vanished without an error"),
                    Some(_) => {
                        let mut out = vec![0u8; 6000];
                        match volume.read(0, b"file", 0, &mut out) {
                            Ok(_) => {
                                assert_eq!(out, vec![7u8; 6000], "block {block}: silent corruption")
                            }
                            Err(error) => assert_eq!(error, Error::Corrupt),
                        }
                    }
                },
            }
        }
    }
}

#[test]
fn shared_blocks_are_rejected() {
    let mut disk = fresh(32);
    let mut bitmap = [0u64; 1];
    let (sb, root) = {
        let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
        volume.write_file(0, b"a", b"one").unwrap();
        volume.write_file(0, b"b", b"two").unwrap();
        let sb = volume.superblock();
        (sb, sb.root)
    };
    // Point entry 1's inode at entry 0's inode, re-sealing everything so only
    // the structural check can catch it.
    let mut directory = disk.blocks[root as usize];
    let first = get_u32(&directory, 16 + 56);
    let first_crc = get_u32(&directory, 16 + 60);
    put_u32(&mut directory, 16 + 64 + 56, first);
    put_u32(&mut directory, 16 + 64 + 60, first_crc);
    // Same size so the inode decodes for both entries.
    put_u64(&mut directory, 16 + 64 + 48, 3);
    seal(&mut directory);
    disk.blocks[root as usize] = directory;
    let forged = Superblock {
        root_crc: get_u32(&directory, CRC_OFFSET),
        ..sb
    };
    disk.blocks[(sb.generation % 2) as usize] = forged.encode();
    assert_eq!(
        Volume::mount(&mut disk, &mut bitmap).err(),
        Some(Error::Corrupt)
    );
}

#[test]
fn random_images_never_panic() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..300 {
        let mut disk = fresh(16);
        {
            let mut bitmap = [0u64; 1];
            let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
            volume
                .write_file(round, b"seed", &[round as u8; 300])
                .unwrap();
        }
        // Randomize a few bytes, sometimes re-sealing so parsing goes deeper.
        for _ in 0..1 + next() % 8 {
            let block = (next() % 16) as usize;
            let offset = (next() % BLOCK_SIZE as u64) as usize;
            disk.blocks[block][offset] = next() as u8;
            if next() % 2 == 0 {
                seal(&mut disk.blocks[block]);
            }
        }
        let mut bitmap = [0u64; 1];
        if let Ok(mut volume) = Volume::mount(&mut disk, &mut bitmap) {
            let _ = volume.check();
            let _ = volume.write_file(1, b"after", b"x");
        }
    }
}

#[test]
fn damaged_superblocks_are_corrupt_not_blank() {
    let mut disk = fresh(16);
    disk.blocks[0][20] ^= 1; // break the only valid superblock's checksum
    let mut bitmap = [0u64; 1];
    assert_eq!(
        Volume::mount(&mut disk, &mut bitmap).err(),
        Some(Error::Corrupt)
    );
    let mut blank = Memory::new(16);
    assert_eq!(
        Volume::mount(&mut blank, &mut bitmap).err(),
        Some(Error::NotFormatted)
    );
}
