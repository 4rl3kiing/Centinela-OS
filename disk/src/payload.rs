//! Installer payload (`CPKG`): the files of an installed system, packed at
//! ISO build time and carried as a hashed boot module.
//!
//! Layout: magic `CPKG0001`, file count (u32), reserved (u32), then one
//! 96-byte entry per file (path, 80 bytes zero padded; offset; size) and
//! the file data. Parsing is defensive: bounded count, entries and data
//! inside the payload, clean relative paths only.

use crate::{get_u32, get_u64};

pub const MAGIC: &[u8; 8] = b"CPKG0001";
pub const MAX_FILES: usize = 64;
pub const PATH_LEN: usize = 80;
const ENTRY: usize = 96;

#[derive(Clone, Copy, Debug)]
pub struct File<'a> {
    pub path: &'a [u8],
    pub data: &'a [u8],
}

/// Clean relative path: printable ASCII, '/' separators, no empty, '.' or
/// '..' components, no leading or trailing '/'.
pub fn valid_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path.len() <= PATH_LEN
        && path
            .iter()
            .all(|&b| (0x21..0x7f).contains(&b) && b != b'\\')
        && path
            .split(|&b| b == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}

/// A validated payload.
pub struct Payload<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> Payload<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 16 || &bytes[..8] != MAGIC {
            return None;
        }
        let count = get_u32(bytes, 8) as usize;
        if count == 0 || count > MAX_FILES || 16 + count * ENTRY > bytes.len() {
            return None;
        }
        let payload = Self { bytes, count };
        for index in 0..count {
            payload.file(index)?;
        }
        Some(payload)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn file(&self, index: usize) -> Option<File<'a>> {
        if index >= self.count {
            return None;
        }
        let at = 16 + index * ENTRY;
        let raw = &self.bytes[at..at + PATH_LEN];
        let length = raw.iter().position(|&b| b == 0).unwrap_or(PATH_LEN);
        let path = &raw[..length];
        let offset = usize::try_from(get_u64(self.bytes, at + PATH_LEN)).ok()?;
        let size = usize::try_from(get_u64(self.bytes, at + PATH_LEN + 8)).ok()?;
        let end = offset.checked_add(size)?;
        if !valid_path(path) || offset < 16 + self.count * ENTRY || end > self.bytes.len() {
            return None;
        }
        Some(File {
            path,
            data: &self.bytes[offset..end],
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;

    pub fn pack(files: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(files.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        let mut offset = 16 + files.len() * ENTRY;
        for (path, data) in files {
            let mut name = [0u8; PATH_LEN];
            name[..path.len()].copy_from_slice(path);
            out.extend_from_slice(&name);
            out.extend_from_slice(&(offset as u64).to_le_bytes());
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            offset += data.len();
        }
        for (_, data) in files {
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn parses_and_validates() {
        let bytes = pack(&[
            (b"EFI/BOOT/BOOTX64.EFI", b"efi"),
            (b"boot/limine/limine.conf", b"conf"),
        ]);
        let payload = Payload::parse(&bytes).unwrap();
        assert_eq!(payload.len(), 2);
        assert_eq!(payload.file(1).unwrap().data, b"conf");
        for bad in [&b"../etc"[..], b"/abs", b"a//b", b"a/./b", b"back\\slash"] {
            assert!(Payload::parse(&pack(&[(bad, b"x")])).is_none(), "{bad:?}");
        }
        let mut truncated = bytes.clone();
        truncated.truncate(bytes.len() - 1);
        assert!(Payload::parse(&truncated).is_none());
    }
}
