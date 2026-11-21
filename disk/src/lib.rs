#![no_std]
#![deny(unsafe_code)]

//! Disk layout for installation: GPT partition tables, a FAT32 writer for
//! the EFI system partition and the installer payload format. Shared by the
//! Ring 3 installer and storage services and by host tests. Everything read
//! from a disk or a payload is treated as untrusted input.

pub mod crc32;
pub mod fat32;
pub mod gpt;
pub mod payload;

pub const SECTOR: usize = 512;
pub type Sector = [u8; SECTOR];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Io,
    TooSmall,
    Invalid,
    Full,
    NotFound,
}

/// A device of 512-byte sectors (LBAs).
pub trait SectorDevice {
    fn sectors(&self) -> u64;
    fn read(&mut self, lba: u64, buffer: &mut Sector) -> Result<(), Error>;
    fn write(&mut self, lba: u64, buffer: &Sector) -> Result<(), Error>;
}

impl<T: SectorDevice> SectorDevice for &mut T {
    fn sectors(&self) -> u64 {
        (**self).sectors()
    }
    fn read(&mut self, lba: u64, buffer: &mut Sector) -> Result<(), Error> {
        (**self).read(lba, buffer)
    }
    fn write(&mut self, lba: u64, buffer: &Sector) -> Result<(), Error> {
        (**self).write(lba, buffer)
    }
}

pub(crate) fn put_u16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn get_u32(buffer: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buffer[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}
pub(crate) fn get_u64(buffer: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buffer[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
pub(crate) mod testdisk {
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::{Error, SECTOR, Sector, SectorDevice};

    pub struct Ram(pub Vec<u8>);

    impl Ram {
        pub fn new(sectors: usize) -> Self {
            Self(vec![0u8; sectors * SECTOR])
        }
    }

    impl SectorDevice for Ram {
        fn sectors(&self) -> u64 {
            (self.0.len() / SECTOR) as u64
        }
        fn read(&mut self, lba: u64, buffer: &mut Sector) -> Result<(), Error> {
            let at = lba as usize * SECTOR;
            buffer.copy_from_slice(self.0.get(at..at + SECTOR).ok_or(Error::Io)?);
            Ok(())
        }
        fn write(&mut self, lba: u64, buffer: &Sector) -> Result<(), Error> {
            let at = lba as usize * SECTOR;
            self.0
                .get_mut(at..at + SECTOR)
                .ok_or(Error::Io)?
                .copy_from_slice(buffer);
            Ok(())
        }
    }
}
