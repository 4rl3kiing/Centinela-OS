#![no_std]
#![deny(unsafe_code)]

//! CFS: the Centinela copy-on-write filesystem (ADR-0007, option A), v1.
//!
//! Shared by the Ring 3 storage service and the host tools (mkfs, fsck).
//!
//! # On-disk format (4 KiB blocks, little endian)
//!
//! - Blocks 0 and 1: superblocks. Each holds a generation number; the valid
//!   one (magic, bounds, CRC32C) with the highest generation is current.
//! - The superblock points at one directory block (63 entries). An entry
//!   names a file, its owner (the badge of the client that created it), its
//!   size and its inode block.
//! - An inode block lists up to 509 data blocks, each with its CRC32C.
//! - There is no on-disk allocation bitmap: free space is whatever the
//!   current tree does not reference, recomputed at mount, so there is no
//!   bitmap to corrupt or to keep consistent.
//!
//! # Crash consistency
//!
//! Every update is copy-on-write: new data, inode and directory blocks go
//! to blocks unused by the committed tree, the device is flushed, then the
//! superblock *not* holding the current generation is overwritten with
//! generation + 1 and flushed again. A crash before that last write leaves
//! the old tree intact and current; a torn superblock fails its checksum and
//! the other copy wins. Blocks of the committed tree are never written.
//!
//! # Hostile images
//!
//! Every byte read from the device is untrusted: magic, version, bounds,
//! checksums, names, sizes and block references are validated, and a block
//! referenced twice (shared or cyclic structure) rejects the volume.
//! Checksums (CRC32C, unkeyed) detect accidental corruption only, not
//! tampering: an attacker who can write the disk offline can forge any
//! structure and recompute its checksum. CFS v1 is therefore NOT resistant
//! to offline manipulation; its guarantee against hostile images is limited
//! to "never panic, loop or touch blocks outside the volume". Integrity
//! against tampering needs the planned keyed per-volume MACs/encryption.
//!
//! Counters taken from the disk are bounded: a superblock generation must be
//! in `1..=MAX_GENERATION` (a forged `u64::MAX` is rejected at mount, and a
//! commit that would exceed the limit fails with [`Error::Corrupt`] instead
//! of overflowing), and `block_count` must fit the u32 block references.

pub mod crc32c;

use crc32c::crc32c;

pub const BLOCK_SIZE: usize = 4096;
pub const MAGIC: &[u8; 8] = b"CNTLAFS1";
pub const VERSION: u32 = 1;
pub const MAX_ENTRIES: usize = 63;
pub const MAX_NAME: usize = 40;
pub const MAX_FILE_BLOCKS: usize = 509;
pub const MAX_FILE_SIZE: usize = MAX_FILE_BLOCKS * BLOCK_SIZE;
/// Smallest volume: two superblocks, a directory and room to update it.
pub const MIN_BLOCKS: u64 = 8;
/// Largest volume: block references are stored as u32.
pub const MAX_BLOCKS: u64 = 1 << 32;
/// Largest valid superblock generation (0 is never written; `u64::MAX` is
/// reserved so `generation + 1` can never overflow).
pub const MAX_GENERATION: u64 = u64::MAX - 1;
const DIR_MAGIC: &[u8; 4] = b"CDIR";
const INODE_MAGIC: &[u8; 4] = b"CINO";
const CRC_OFFSET: usize = BLOCK_SIZE - 4;

pub type Block = [u8; BLOCK_SIZE];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Io,
    /// Neither superblock is valid.
    NotFormatted,
    /// A structure failed validation (bad magic, bounds, checksum, name...).
    Corrupt,
    /// The volume or the allocation bitmap the caller provided is too small.
    TooLarge,
    NotFound,
    NoSpace,
    InvalidName,
    FileTooLarge,
    DirectoryFull,
}

/// A device of 4 KiB blocks.
pub trait BlockDevice {
    fn block_count(&self) -> u64;
    fn read(&mut self, block: u64, buffer: &mut Block) -> Result<(), Error>;
    fn write(&mut self, block: u64, buffer: &Block) -> Result<(), Error>;
    /// Makes every completed write durable.
    fn flush(&mut self) -> Result<(), Error>;
}

impl<T: BlockDevice> BlockDevice for &mut T {
    fn block_count(&self) -> u64 {
        (**self).block_count()
    }
    fn read(&mut self, block: u64, buffer: &mut Block) -> Result<(), Error> {
        (**self).read(block, buffer)
    }
    fn write(&mut self, block: u64, buffer: &Block) -> Result<(), Error> {
        (**self).write(block, buffer)
    }
    fn flush(&mut self) -> Result<(), Error> {
        (**self).flush()
    }
}

fn put_u32(block: &mut Block, offset: usize, value: u32) {
    block[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(block: &mut Block, offset: usize, value: u64) {
    block[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get_u32(block: &Block, offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&block[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}
fn get_u64(block: &Block, offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&block[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

fn seal(block: &mut Block) {
    let crc = crc32c(&block[..CRC_OFFSET]);
    put_u32(block, CRC_OFFSET, crc);
}

fn sealed(block: &Block) -> bool {
    crc32c(&block[..CRC_OFFSET]) == get_u32(block, CRC_OFFSET)
}

/// File names: 1..=40 printable ASCII bytes, no '/' (flat namespace in v1).
pub fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.iter().all(|&b| (0x21..0x7f).contains(&b) && b != b'/')
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
    pub block_count: u64,
    pub generation: u64,
    pub root: u64,
    pub root_crc: u32,
    pub label: [u8; 32],
}

impl Superblock {
    fn encode(&self) -> Block {
        let mut block = [0u8; BLOCK_SIZE];
        block[..8].copy_from_slice(MAGIC);
        put_u32(&mut block, 8, VERSION);
        put_u64(&mut block, 16, self.block_count);
        put_u64(&mut block, 24, self.generation);
        put_u64(&mut block, 32, self.root);
        put_u32(&mut block, 40, self.root_crc);
        block[48..80].copy_from_slice(&self.label);
        seal(&mut block);
        block
    }

    fn decode(block: &Block, device_blocks: u64) -> Option<Self> {
        if &block[..8] != MAGIC || get_u32(block, 8) != VERSION || !sealed(block) {
            return None;
        }
        let sb = Self {
            block_count: get_u64(block, 16),
            generation: get_u64(block, 24),
            root: get_u64(block, 32),
            root_crc: get_u32(block, 40),
            label: block[48..80].try_into().ok()?,
        };
        let sane = sb.block_count >= MIN_BLOCKS
            && sb.block_count <= device_blocks
            && sb.block_count <= MAX_BLOCKS
            && (1..=MAX_GENERATION).contains(&sb.generation)
            && sb.root >= 2
            && sb.root < sb.block_count;
        sane.then_some(sb)
    }
}

/// One directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    pub name: [u8; MAX_NAME],
    pub name_len: u8,
    pub owner: u64,
    pub size: u64,
    pub inode: u32,
    pub inode_crc: u32,
}

impl Entry {
    const EMPTY: Self = Self {
        name: [0; MAX_NAME],
        name_len: 0,
        owner: 0,
        size: 0,
        inode: 0,
        inode_crc: 0,
    };

    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }
}

/// The in-memory copy of the directory (always validated).
#[derive(Clone, Copy)]
struct Directory {
    entries: [Entry; MAX_ENTRIES],
    count: usize,
}

impl Directory {
    fn encode(&self) -> Block {
        let mut block = [0u8; BLOCK_SIZE];
        block[..4].copy_from_slice(DIR_MAGIC);
        put_u32(&mut block, 4, self.count as u32);
        for (index, entry) in self.entries[..self.count].iter().enumerate() {
            let at = 16 + index * 64;
            block[at..at + MAX_NAME].copy_from_slice(&entry.name);
            put_u64(&mut block, at + 40, entry.owner);
            put_u64(&mut block, at + 48, entry.size);
            put_u32(&mut block, at + 56, entry.inode);
            put_u32(&mut block, at + 60, entry.inode_crc);
        }
        seal(&mut block);
        block
    }

    fn decode(block: &Block) -> Option<Self> {
        if &block[..4] != DIR_MAGIC || !sealed(block) {
            return None;
        }
        let count = get_u32(block, 4) as usize;
        if count > MAX_ENTRIES {
            return None;
        }
        let mut directory = Self {
            entries: [Entry::EMPTY; MAX_ENTRIES],
            count,
        };
        for index in 0..count {
            let at = 16 + index * 64;
            let raw = &block[at..at + MAX_NAME];
            let name_len = raw.iter().position(|&b| b == 0).unwrap_or(MAX_NAME);
            // Bytes after the terminator must be zero (canonical encoding).
            if !valid_name(&raw[..name_len]) || raw[name_len..].iter().any(|&b| b != 0) {
                return None;
            }
            let mut name = [0u8; MAX_NAME];
            name.copy_from_slice(raw);
            let entry = Entry {
                name,
                name_len: name_len as u8,
                owner: get_u64(block, at + 40),
                size: get_u64(block, at + 48),
                inode: get_u32(block, at + 56),
                inode_crc: get_u32(block, at + 60),
            };
            // Names are unique per owner.
            if directory.entries[..index]
                .iter()
                .any(|other| other.owner == entry.owner && other.name() == entry.name())
            {
                return None;
            }
            directory.entries[index] = entry;
        }
        Some(directory)
    }

    fn find(&self, owner: u64, name: &[u8]) -> Option<usize> {
        self.entries[..self.count]
            .iter()
            .position(|entry| entry.owner == owner && entry.name() == name)
    }
}

/// Decoded inode: data blocks and their checksums.
struct Inode {
    size: u64,
    count: usize,
    blocks: [(u32, u32); MAX_FILE_BLOCKS],
}

impl Inode {
    fn encode(&self) -> Block {
        let mut block = [0u8; BLOCK_SIZE];
        block[..4].copy_from_slice(INODE_MAGIC);
        put_u32(&mut block, 4, self.count as u32);
        put_u64(&mut block, 8, self.size);
        for (index, &(data, crc)) in self.blocks[..self.count].iter().enumerate() {
            put_u32(&mut block, 16 + index * 8, data);
            put_u32(&mut block, 20 + index * 8, crc);
        }
        seal(&mut block);
        block
    }

    fn decode(block: &Block, expected_size: u64) -> Option<Self> {
        if &block[..4] != INODE_MAGIC || !sealed(block) {
            return None;
        }
        let count = get_u32(block, 4) as usize;
        let size = get_u64(block, 8);
        // The block count must match the size exactly.
        // Compare in u64 first so no cast can truncate a hostile size.
        if count > MAX_FILE_BLOCKS || size != expected_size || size > MAX_FILE_SIZE as u64 {
            return None;
        }
        if count != (size as usize).div_ceil(BLOCK_SIZE) {
            return None;
        }
        let mut inode = Self {
            size,
            count,
            blocks: [(0, 0); MAX_FILE_BLOCKS],
        };
        for index in 0..count {
            inode.blocks[index] = (
                get_u32(block, 16 + index * 8),
                get_u32(block, 20 + index * 8),
            );
        }
        Some(inode)
    }
}

/// Free-space bitmap over a caller-provided buffer (one bit per block).
struct Bitmap<'a> {
    words: &'a mut [u64],
}

impl Bitmap<'_> {
    fn clear(&mut self) {
        self.words.fill(0);
    }
    fn used(&self, block: u64) -> bool {
        self.words[(block / 64) as usize] >> (block % 64) & 1 != 0
    }
    fn set(&mut self, block: u64) {
        self.words[(block / 64) as usize] |= 1 << (block % 64);
    }
}

/// A mounted volume.
pub struct Volume<'a, D: BlockDevice> {
    device: D,
    superblock: Superblock,
    directory: Directory,
    bitmap: Bitmap<'a>,
    /// Allocation cursor (spreads writes, avoids immediate reuse).
    cursor: u64,
    /// Superblock slot (0 or 1) holding the current generation; commits
    /// always write the other one.
    slot: u64,
}

/// Writes an empty filesystem. Any previous content becomes unreachable.
pub fn format<D: BlockDevice>(device: &mut D, label: &[u8]) -> Result<(), Error> {
    let blocks = device.block_count();
    if blocks < MIN_BLOCKS {
        return Err(Error::TooLarge);
    }
    let directory = Directory {
        entries: [Entry::EMPTY; MAX_ENTRIES],
        count: 0,
    };
    let root = directory.encode();
    device.write(2, &root)?;
    let mut name = [0u8; 32];
    let length = label.len().min(32);
    name[..length].copy_from_slice(&label[..length]);
    let superblock = Superblock {
        block_count: blocks.min(MAX_BLOCKS),
        generation: 1,
        root: 2,
        root_crc: get_u32(&root, CRC_OFFSET),
        label: name,
    };
    device.flush()?;
    // Generation g lives in slot g % 2, so the first commit (generation 2)
    // goes to slot 0 and never overwrites the current superblock.
    device.write(1, &superblock.encode())?;
    // Invalidate the other slot so an older filesystem cannot win.
    device.write(0, &[0u8; BLOCK_SIZE])?;
    device.flush()
}

/// Bitmap words needed for a device of `blocks` blocks.
pub const fn bitmap_words(blocks: u64) -> usize {
    blocks.div_ceil(64) as usize
}

impl<'a, D: BlockDevice> Volume<'a, D> {
    /// Mounts the newest valid superblock and validates the whole tree
    /// (structure and metadata checksums; data checksums are verified on
    /// every read and by [`Volume::check`]).
    pub fn mount(mut device: D, bitmap: &'a mut [u64]) -> Result<Self, Error> {
        let device_blocks = device.block_count();
        if bitmap.len() < bitmap_words(device_blocks) {
            return Err(Error::TooLarge);
        }
        let mut block = [0u8; BLOCK_SIZE];
        let mut best: Option<(Superblock, u64)> = None;
        let mut magic_seen = false;
        for slot in 0..2 {
            device.read(slot, &mut block)?;
            magic_seen |= &block[..8] == MAGIC;
            if let Some(sb) = Superblock::decode(&block, device_blocks)
                && best.is_none_or(|(b, _)| sb.generation > b.generation)
            {
                best = Some((sb, slot));
            }
        }
        // A CFS signature without a valid superblock is a damaged (or
        // mismatched) volume, never a blank disk: callers must not reformat.
        let (superblock, slot) = best.ok_or(if magic_seen {
            Error::Corrupt
        } else {
            Error::NotFormatted
        })?;
        let mut volume = Self {
            device,
            superblock,
            directory: Directory {
                entries: [Entry::EMPTY; MAX_ENTRIES],
                count: 0,
            },
            bitmap: Bitmap { words: bitmap },
            cursor: 3,
            slot,
        };
        volume.load_tree()?;
        Ok(volume)
    }

    /// Reads and validates the directory and every inode of the current
    /// tree, rebuilding the free-space bitmap.
    fn load_tree(&mut self) -> Result<(), Error> {
        let sb = self.superblock;
        let mut block = [0u8; BLOCK_SIZE];
        self.device.read(sb.root, &mut block)?;
        if get_u32(&block, CRC_OFFSET) != sb.root_crc {
            return Err(Error::Corrupt);
        }
        let directory = Directory::decode(&block).ok_or(Error::Corrupt)?;
        self.bitmap.clear();
        self.bitmap.set(0);
        self.bitmap.set(1);
        self.bitmap.set(sb.root);
        for entry in &directory.entries[..directory.count] {
            let inode_block = u64::from(entry.inode);
            if !self.claim(inode_block) {
                return Err(Error::Corrupt);
            }
            self.device.read(inode_block, &mut block)?;
            if get_u32(&block, CRC_OFFSET) != entry.inode_crc {
                return Err(Error::Corrupt);
            }
            let inode = Inode::decode(&block, entry.size).ok_or(Error::Corrupt)?;
            for &(data, _) in &inode.blocks[..inode.count] {
                if !self.claim(u64::from(data)) {
                    return Err(Error::Corrupt);
                }
            }
        }
        self.directory = directory;
        Ok(())
    }

    /// Marks a referenced block used; false if out of range or shared.
    fn claim(&mut self, block: u64) -> bool {
        if block < 2 || block >= self.superblock.block_count || self.bitmap.used(block) {
            return false;
        }
        self.bitmap.set(block);
        true
    }

    fn allocate(&mut self) -> Result<u64, Error> {
        let total = self.superblock.block_count;
        for step in 0..total {
            let block = 2 + (self.cursor - 2 + step) % (total - 2);
            if !self.bitmap.used(block) {
                self.bitmap.set(block);
                self.cursor = block + 1;
                if self.cursor >= total {
                    self.cursor = 2;
                }
                return Ok(block);
            }
        }
        Err(Error::NoSpace)
    }

    pub fn superblock(&self) -> Superblock {
        self.superblock
    }

    pub fn entries(&self) -> &[Entry] {
        &self.directory.entries[..self.directory.count]
    }

    /// Free blocks in the committed tree.
    pub fn free_blocks(&self) -> u64 {
        (0..self.superblock.block_count)
            .filter(|&b| !self.bitmap.used(b))
            .count() as u64
    }

    pub fn lookup(&self, owner: u64, name: &[u8]) -> Option<Entry> {
        self.directory
            .find(owner, name)
            .map(|index| self.directory.entries[index])
    }

    /// Reads up to `out.len()` bytes at `offset`; returns the count read.
    /// Every data block's checksum is verified.
    pub fn read(
        &mut self,
        owner: u64,
        name: &[u8],
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let entry = self.lookup(owner, name).ok_or(Error::NotFound)?;
        if offset >= entry.size {
            return Ok(0);
        }
        let mut block = [0u8; BLOCK_SIZE];
        self.device.read(u64::from(entry.inode), &mut block)?;
        if get_u32(&block, CRC_OFFSET) != entry.inode_crc {
            return Err(Error::Corrupt);
        }
        let inode = Inode::decode(&block, entry.size).ok_or(Error::Corrupt)?;
        let wanted = (out.len() as u64).min(entry.size - offset) as usize;
        let mut done = 0;
        while done < wanted {
            let position = offset as usize + done;
            let (data, crc) = inode.blocks[position / BLOCK_SIZE];
            self.device.read(u64::from(data), &mut block)?;
            if crc32c(&block) != crc {
                return Err(Error::Corrupt);
            }
            let within = position % BLOCK_SIZE;
            let take = (BLOCK_SIZE - within).min(wanted - done);
            out[done..done + take].copy_from_slice(&block[within..within + take]);
            done += take;
        }
        Ok(done)
    }

    /// Atomically creates or replaces a whole file.
    pub fn write_file(&mut self, owner: u64, name: &[u8], data: &[u8]) -> Result<(), Error> {
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        if data.len() > MAX_FILE_SIZE {
            return Err(Error::FileTooLarge);
        }
        let mut directory = self.directory;
        let index = match directory.find(owner, name) {
            Some(index) => index,
            None if directory.count == MAX_ENTRIES => return Err(Error::DirectoryFull),
            None => {
                directory.count += 1;
                directory.count - 1
            }
        };
        let result = self.stage_file(&mut directory, index, owner, name, data);
        match result {
            Ok(()) => self.commit(directory),
            Err(error) => {
                // Drop the blocks allocated for the failed update.
                self.load_tree()?;
                Err(error)
            }
        }
    }

    fn stage_file(
        &mut self,
        directory: &mut Directory,
        index: usize,
        owner: u64,
        name: &[u8],
        data: &[u8],
    ) -> Result<(), Error> {
        let mut inode = Inode {
            size: data.len() as u64,
            count: data.len().div_ceil(BLOCK_SIZE),
            blocks: [(0, 0); MAX_FILE_BLOCKS],
        };
        let mut block = [0u8; BLOCK_SIZE];
        for (slot, chunk) in data.chunks(BLOCK_SIZE).enumerate() {
            block.fill(0);
            block[..chunk.len()].copy_from_slice(chunk);
            let target = self.allocate()?;
            let reference = u32::try_from(target).map_err(|_| Error::TooLarge)?;
            self.device.write(target, &block)?;
            inode.blocks[slot] = (reference, crc32c(&block));
        }
        let encoded = inode.encode();
        let inode_block = self.allocate()?;
        let inode_reference = u32::try_from(inode_block).map_err(|_| Error::TooLarge)?;
        self.device.write(inode_block, &encoded)?;
        let mut stored = [0u8; MAX_NAME];
        stored[..name.len()].copy_from_slice(name);
        directory.entries[index] = Entry {
            name: stored,
            name_len: name.len() as u8,
            owner,
            size: data.len() as u64,
            inode: inode_reference,
            inode_crc: get_u32(&encoded, CRC_OFFSET),
        };
        Ok(())
    }

    /// Removes a file atomically.
    pub fn delete(&mut self, owner: u64, name: &[u8]) -> Result<(), Error> {
        let index = self.directory.find(owner, name).ok_or(Error::NotFound)?;
        let mut directory = self.directory;
        directory
            .entries
            .copy_within(index + 1..directory.count, index);
        directory.count -= 1;
        directory.entries[directory.count] = Entry::EMPTY;
        self.commit(directory)
    }

    /// Writes the new directory, then the superblock in the other slot.
    fn commit(&mut self, directory: Directory) -> Result<(), Error> {
        // Mount only accepts generations up to MAX_GENERATION, so this fails
        // (never overflows) on a forged near-limit generation.
        let Some(generation) = self
            .superblock
            .generation
            .checked_add(1)
            .filter(|&next| next <= MAX_GENERATION)
        else {
            self.load_tree()?;
            return Err(Error::Corrupt);
        };
        let encoded = directory.encode();
        let root = match self.allocate() {
            Ok(root) => root,
            Err(error) => {
                self.load_tree()?;
                return Err(error);
            }
        };
        self.device.write(root, &encoded)?;
        self.device.flush()?;
        let superblock = Superblock {
            generation,
            root,
            root_crc: get_u32(&encoded, CRC_OFFSET),
            ..self.superblock
        };
        // Always the slot NOT holding the current generation (volumes
        // formatted before generation 1 moved to slot 1 keep it in slot 0).
        let slot = 1 - self.slot;
        self.device.write(slot, &superblock.encode())?;
        self.device.flush()?;
        self.superblock = superblock;
        self.slot = slot;
        // The old tree's blocks become free only now that the switch is durable.
        self.load_tree()
    }

    /// fsck: verifies every data block checksum too. Returns the number of
    /// files checked.
    pub fn check(&mut self) -> Result<usize, Error> {
        let mut buffer = [0u8; 512];
        for index in 0..self.directory.count {
            let entry = self.directory.entries[index];
            let mut offset = 0;
            while offset < entry.size {
                offset += self.read(entry.owner, entry.name(), offset, &mut buffer)? as u64;
            }
        }
        Ok(self.directory.count)
    }

    /// Gives the device back (e.g. to unmount).
    pub fn into_device(self) -> D {
        self.device
    }
}

#[cfg(test)]
mod tests;
