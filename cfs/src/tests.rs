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
                    // A damaged newest superblock (generation 2, slot 0)
                    // falls back to the previous, intact generation.
                    None if block == 0 && volume.superblock().generation == 1 => {}
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
    disk.blocks[1][20] ^= 1; // break the only valid superblock's checksum
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

/// Re-seals the superblock in `slot` with a forged generation.
fn forge_generation(disk: &mut Memory, slot: usize, generation: u64) {
    let mut sb = Superblock::decode(&disk.blocks[slot], disk.blocks.len() as u64).unwrap();
    sb.generation = generation;
    disk.blocks[slot] = sb.encode();
}

#[test]
fn impossible_generations_are_mount_errors_not_panics() {
    for forged in [0, u64::MAX] {
        let mut disk = fresh(16);
        forge_generation(&mut disk, 1, forged);
        let mut bitmap = [0u64; 1];
        assert_eq!(
            Volume::mount(&mut disk, &mut bitmap).err(),
            Some(Error::Corrupt),
            "generation {forged}"
        );
    }
    // A forged u64::MAX copy is ignored when the other copy is valid.
    let mut disk = fresh(16);
    {
        let mut bitmap = [0u64; 1];
        let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
        volume.write_file(0, b"f", b"data").unwrap(); // generation 2, slot 0
    }
    forge_generation(&mut disk, 1, u64::MAX);
    let mut bitmap = [0u64; 1];
    let volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
    assert_eq!(volume.superblock().generation, 2);
}

#[test]
fn generation_at_the_limit_refuses_updates_without_panicking() {
    let mut disk = fresh(16);
    forge_generation(&mut disk, 1, MAX_GENERATION);
    let before = disk.clone();
    let mut bitmap = [0u64; 1];
    {
        let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
        assert_eq!(volume.write_file(0, b"f", b"x"), Err(Error::Corrupt));
        assert_eq!(volume.delete(0, b"f"), Err(Error::NotFound));
        assert_eq!(volume.free_blocks(), 16 - 3, "staged blocks were released");
    }
    // Nothing reachable changed: both superblocks are untouched.
    assert!(disk.blocks[..2] == before.blocks[..2]);
    let volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
    assert_eq!(volume.superblock().generation, MAX_GENERATION);
    // One below the limit still commits, reaching exactly the limit.
    let mut disk = fresh(16);
    forge_generation(&mut disk, 1, MAX_GENERATION - 1);
    let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
    volume.write_file(0, b"f", b"x").unwrap();
    assert_eq!(volume.superblock().generation, MAX_GENERATION);
}

#[test]
fn commits_never_overwrite_the_current_superblock() {
    // New format: generation 1 in slot 1, the first commit goes to slot 0.
    let mut disk = fresh(16);
    let current = disk.blocks[1];
    {
        let mut bitmap = [0u64; 1];
        let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
        volume.write_file(0, b"f", b"x").unwrap();
    }
    assert!(disk.blocks[1] == current);
    // Legacy layout (generation 1 in slot 0, slot 1 blank): the first commit
    // must go to slot 1, not over the only valid superblock.
    let mut legacy = fresh(16);
    legacy.blocks[0] = legacy.blocks[1];
    legacy.blocks[1] = [0; BLOCK_SIZE];
    let current = legacy.blocks[0];
    let mut bitmap = [0u64; 1];
    {
        let mut volume = Volume::mount(&mut legacy, &mut bitmap).unwrap();
        volume.write_file(0, b"f", b"x").unwrap();
        volume.write_file(0, b"g", b"y").unwrap();
    }
    let sb1 = Superblock::decode(&legacy.blocks[1], 16).unwrap();
    let sb0 = Superblock::decode(&legacy.blocks[0], 16).unwrap();
    assert_eq!((sb0.generation, sb1.generation), (3, 2));
    assert!(legacy.blocks[0] != current);
    let mut volume = Volume::mount(&mut legacy, &mut bitmap).unwrap();
    assert_eq!(read_all(&mut volume, 0, b"g"), b"y");
}

#[test]
fn extreme_superblock_and_inode_values_are_rejected() {
    let mut disk = fresh(16);
    let mut sb = Superblock::decode(&disk.blocks[1], 16).unwrap();
    sb.block_count = MAX_BLOCKS + 1;
    assert_eq!(Superblock::decode(&sb.encode(), u64::MAX), None);
    sb.block_count = MAX_BLOCKS;
    assert!(Superblock::decode(&sb.encode(), u64::MAX).is_some());
    sb.block_count = u64::MAX;
    sb.root = u64::MAX - 1;
    assert_eq!(Superblock::decode(&sb.encode(), u64::MAX), None);
    // Inode sizes that would overflow or truncate in a cast.
    for size in [u64::MAX, u64::MAX - 4095, MAX_FILE_SIZE as u64 + 1, 1 << 32] {
        let mut block = [0u8; BLOCK_SIZE];
        block[..4].copy_from_slice(INODE_MAGIC);
        put_u32(&mut block, 4, MAX_FILE_BLOCKS as u32);
        put_u64(&mut block, 8, size);
        seal(&mut block);
        assert!(Inode::decode(&block, size).is_none(), "size {size}");
    }
    // A directory entry claiming a huge size is a mount error.
    let mut bitmap = [0u64; 1];
    {
        let mut volume = Volume::mount(&mut disk, &mut bitmap).unwrap();
        volume.write_file(0, b"f", b"abc").unwrap();
    }
    let mut sb = Superblock::decode(&disk.blocks[0], 16).unwrap();
    let mut directory = disk.blocks[sb.root as usize];
    put_u64(&mut directory, 16 + 48, u64::MAX);
    seal(&mut directory);
    disk.blocks[sb.root as usize] = directory;
    sb.root_crc = get_u32(&directory, CRC_OFFSET);
    disk.blocks[0] = sb.encode();
    assert_eq!(
        Volume::mount(&mut disk, &mut bitmap).err(),
        Some(Error::Corrupt)
    );
}
