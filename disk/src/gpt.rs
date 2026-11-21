//! GUID Partition Table (UEFI 2.10, chapter 5): writer and validating reader.

use crate::crc32::crc32;
use crate::{Error, SECTOR, Sector, SectorDevice, get_u32, get_u64, put_u16, put_u32, put_u64};

/// GUID in its on-disk byte order.
pub type Guid = [u8; 16];

/// Converts the textual form's fields to on-disk bytes (first three fields
/// little endian, the rest big endian).
pub const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> Guid {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

/// EFI system partition: C12A7328-F81F-11D2-BA4B-00A0C93EC93B.
pub const ESP_TYPE: Guid = guid(
    0xc12a_7328,
    0xf81f,
    0x11d2,
    [0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b],
);
/// Centinela CFS system volume: 6C5E2A1D-4B7F-4C1E-9A3D-C3E7A1F00C05.
pub const CFS_TYPE: Guid = guid(
    0x6c5e_2a1d,
    0x4b7f,
    0x4c1e,
    [0x9a, 0x3d, 0xc3, 0xe7, 0xa1, 0xf0, 0x0c, 0x05],
);

const ENTRIES: u64 = 128;
const ENTRY_SIZE: usize = 128;
const ENTRY_SECTORS: u64 = ENTRIES * ENTRY_SIZE as u64 / SECTOR as u64; // 32
pub const MAX_PARTITIONS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Partition {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    pub last_lba: u64,
    /// ASCII name (stored as UTF-16LE, up to 36 characters).
    pub name: [u8; 36],
}

impl Default for Partition {
    fn default() -> Self {
        Self {
            type_guid: [0; 16],
            unique_guid: [0; 16],
            first_lba: 0,
            last_lba: 0,
            name: [0; 36],
        }
    }
}

impl Partition {
    pub fn sectors(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
}

/// First and last LBA usable for partitions on a disk of `sectors`.
pub fn usable_range(sectors: u64) -> Option<(u64, u64)> {
    let first = 2 + ENTRY_SECTORS;
    let last = sectors.checked_sub(2 + ENTRY_SECTORS)?;
    (last > first).then_some((first, last))
}

fn entry_bytes(partitions: &[Partition], index: u64) -> [u8; ENTRY_SIZE] {
    let mut entry = [0u8; ENTRY_SIZE];
    if let Some(p) = partitions.get(index as usize) {
        entry[..16].copy_from_slice(&p.type_guid);
        entry[16..32].copy_from_slice(&p.unique_guid);
        put_u64(&mut entry, 32, p.first_lba);
        put_u64(&mut entry, 40, p.last_lba);
        for (i, &c) in p.name.iter().enumerate() {
            put_u16(&mut entry, 56 + 2 * i, u16::from(c));
        }
    }
    entry
}

fn entries_crc(partitions: &[Partition]) -> u32 {
    // CRC over the whole 16 KiB array, streamed entry by entry.
    let mut all = [0u8; ENTRY_SIZE * 4];
    let mut crc_state = Crc::new();
    for chunk in 0..ENTRIES / 4 {
        for slot in 0..4 {
            let entry = entry_bytes(partitions, chunk * 4 + slot);
            all[slot as usize * ENTRY_SIZE..(slot as usize + 1) * ENTRY_SIZE]
                .copy_from_slice(&entry);
        }
        crc_state.update(&all);
    }
    crc_state.finish()
}

/// Incremental CRC-32 (same polynomial as `crc32`).
struct Crc(u32);

impl Crc {
    fn new() -> Self {
        Self(!0)
    }
    fn update(&mut self, bytes: &[u8]) {
        // crc32() of a concatenation, computed incrementally.
        let mut crc = self.0;
        for &byte in bytes {
            let index = ((crc ^ u32::from(byte)) & 0xff) as usize;
            crc = TABLE_REF[index] ^ (crc >> 8);
        }
        self.0 = crc;
    }
    fn finish(self) -> u32 {
        !self.0
    }
}

const TABLE_REF: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
};

fn header(sectors: u64, disk_guid: &Guid, primary: bool, array_crc: u32) -> Sector {
    let (first, last) = usable_range(sectors).unwrap_or((0, 0));
    let mut h = [0u8; SECTOR];
    h[..8].copy_from_slice(b"EFI PART");
    put_u32(&mut h, 8, 0x0001_0000);
    put_u32(&mut h, 12, 92);
    let (current, backup, array) = if primary {
        (1, sectors - 1, 2)
    } else {
        (sectors - 1, 1, sectors - 1 - ENTRY_SECTORS)
    };
    put_u64(&mut h, 24, current);
    put_u64(&mut h, 32, backup);
    put_u64(&mut h, 40, first);
    put_u64(&mut h, 48, last);
    h[56..72].copy_from_slice(disk_guid);
    put_u64(&mut h, 72, array);
    put_u32(&mut h, 80, ENTRIES as u32);
    put_u32(&mut h, 84, ENTRY_SIZE as u32);
    put_u32(&mut h, 88, array_crc);
    let crc = crc32(&h[..92]);
    put_u32(&mut h, 16, crc);
    h
}

/// Writes a protective MBR and primary + backup GPT for `partitions`.
pub fn write<D: SectorDevice>(
    device: &mut D,
    disk_guid: &Guid,
    partitions: &[Partition],
) -> Result<(), Error> {
    let sectors = device.sectors();
    let (first, last) = usable_range(sectors).ok_or(Error::TooSmall)?;
    if partitions.len() > MAX_PARTITIONS {
        return Err(Error::Invalid);
    }
    for (i, p) in partitions.iter().enumerate() {
        if p.first_lba < first || p.last_lba > last || p.first_lba > p.last_lba {
            return Err(Error::Invalid);
        }
        if partitions[..i]
            .iter()
            .any(|q| p.first_lba <= q.last_lba && q.first_lba <= p.last_lba)
        {
            return Err(Error::Invalid);
        }
    }
    // Protective MBR: one 0xEE partition covering the disk.
    let mut mbr = [0u8; SECTOR];
    mbr[446 + 4] = 0xee;
    put_u32(&mut mbr, 446 + 8, 1);
    put_u32(
        &mut mbr,
        446 + 12,
        u32::try_from(sectors - 1).unwrap_or(u32::MAX),
    );
    mbr[446 + 1..446 + 4].copy_from_slice(&[0x00, 0x02, 0x00]);
    mbr[446 + 5..446 + 8].copy_from_slice(&[0xff, 0xff, 0xff]);
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    device.write(0, &mbr)?;
    let array_crc = entries_crc(partitions);
    let mut sector = [0u8; SECTOR];
    for index in 0..ENTRY_SECTORS {
        for slot in 0..4 {
            let entry = entry_bytes(partitions, index * 4 + slot);
            sector[slot as usize * ENTRY_SIZE..(slot as usize + 1) * ENTRY_SIZE]
                .copy_from_slice(&entry);
        }
        device.write(2 + index, &sector)?;
        device.write(sectors - 1 - ENTRY_SECTORS + index, &sector)?;
    }
    device.write(1, &header(sectors, disk_guid, true, array_crc))?;
    device.write(sectors - 1, &header(sectors, disk_guid, false, array_crc))
}

/// Reads and validates the GPT (primary, falling back to the backup).
/// Returns the non-empty partitions.
pub fn read<D: SectorDevice>(
    device: &mut D,
    out: &mut [Partition; MAX_PARTITIONS],
) -> Result<usize, Error> {
    let sectors = device.sectors();
    let mut last_error = Error::NotFound;
    for lba in [1, sectors.saturating_sub(1)] {
        match read_at(device, lba, sectors, out) {
            Ok(count) => return Ok(count),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn read_at<D: SectorDevice>(
    device: &mut D,
    lba: u64,
    sectors: u64,
    out: &mut [Partition; MAX_PARTITIONS],
) -> Result<usize, Error> {
    let mut h = [0u8; SECTOR];
    device.read(lba, &mut h)?;
    if &h[..8] != b"EFI PART" {
        return Err(Error::NotFound);
    }
    let size = get_u32(&h, 12) as usize;
    let stored = get_u32(&h, 16);
    if !(92..=SECTOR).contains(&size) {
        return Err(Error::Invalid);
    }
    let mut copy = h;
    put_u32(&mut copy, 16, 0);
    if crc32(&copy[..size]) != stored || get_u64(&h, 24) != lba {
        return Err(Error::Invalid);
    }
    let first = get_u64(&h, 40);
    let last = get_u64(&h, 48);
    let array = get_u64(&h, 72);
    let count = u64::from(get_u32(&h, 80));
    let entry_size = get_u32(&h, 84) as usize;
    if entry_size != ENTRY_SIZE || count == 0 || count > 1024 || last >= sectors || first > last {
        return Err(Error::Invalid);
    }
    let array_sectors = (count * ENTRY_SIZE as u64).div_ceil(SECTOR as u64);
    if array
        .checked_add(array_sectors)
        .is_none_or(|end| end > sectors)
    {
        return Err(Error::Invalid);
    }
    let mut crc = Crc::new();
    let mut found = 0;
    let mut sector = [0u8; SECTOR];
    for index in 0..array_sectors {
        device.read(array + index, &mut sector)?;
        let valid =
            ((count * ENTRY_SIZE as u64) - index * SECTOR as u64).min(SECTOR as u64) as usize;
        crc.update(&sector[..valid]);
        for slot in 0..valid / ENTRY_SIZE {
            let e = &sector[slot * ENTRY_SIZE..(slot + 1) * ENTRY_SIZE];
            if e[..16].iter().all(|&b| b == 0) {
                continue;
            }
            if found == MAX_PARTITIONS {
                return Err(Error::Full);
            }
            let mut p = Partition::default();
            p.type_guid.copy_from_slice(&e[..16]);
            p.unique_guid.copy_from_slice(&e[16..32]);
            p.first_lba = get_u64(e, 32);
            p.last_lba = get_u64(e, 40);
            for i in 0..36 {
                let c = u16::from_le_bytes([e[56 + 2 * i], e[57 + 2 * i]]);
                p.name[i] = if (0x20..0x7f).contains(&c) {
                    c as u8
                } else {
                    0
                };
            }
            if p.first_lba < first || p.last_lba > last || p.first_lba > p.last_lba {
                return Err(Error::Invalid);
            }
            out[found] = p;
            found += 1;
        }
    }
    if crc.finish() != get_u32(&h, 88) {
        return Err(Error::Invalid);
    }
    for i in 0..found {
        for j in 0..i {
            if out[i].first_lba <= out[j].last_lba && out[j].first_lba <= out[i].last_lba {
                return Err(Error::Invalid);
            }
        }
    }
    Ok(found)
}

/// Encodes an ASCII name for a partition entry.
pub fn name(text: &[u8]) -> [u8; 36] {
    let mut out = [0u8; 36];
    let length = text.len().min(36);
    out[..length].copy_from_slice(&text[..length]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdisk::Ram;

    fn layout(sectors: u64) -> [Partition; 2] {
        let (_, last) = usable_range(sectors).unwrap();
        [
            Partition {
                type_guid: ESP_TYPE,
                unique_guid: [1; 16],
                first_lba: 2048,
                last_lba: 4095,
                name: name(b"EFI system"),
            },
            Partition {
                type_guid: CFS_TYPE,
                unique_guid: [2; 16],
                first_lba: 4096,
                last_lba: last,
                name: name(b"Centinela system"),
            },
        ]
    }

    #[test]
    fn round_trip_and_backup_recovery() {
        let mut disk = Ram::new(16384);
        let parts = layout(16384);
        write(&mut disk, &[9; 16], &parts).unwrap();
        let mut out = [Partition::default(); MAX_PARTITIONS];
        assert_eq!(read(&mut disk, &mut out).unwrap(), 2);
        assert_eq!(out[..2], parts);
        // Destroy the primary header: the backup is used.
        disk.0[SECTOR + 20] ^= 0xff;
        assert_eq!(read(&mut disk, &mut out).unwrap(), 2);
        assert_eq!(out[1].type_guid, CFS_TYPE);
    }

    #[test]
    fn rejects_overlaps_and_corruption() {
        let mut disk = Ram::new(16384);
        let mut parts = layout(16384);
        parts[1].first_lba = 4000;
        assert_eq!(write(&mut disk, &[9; 16], &parts), Err(Error::Invalid));
        let parts = layout(16384);
        write(&mut disk, &[9; 16], &parts).unwrap();
        // Corrupt an entry in both copies: CRC mismatch everywhere.
        disk.0[2 * SECTOR + 40] ^= 1;
        let end = 16384 - 1 - 32;
        disk.0[end * SECTOR + 40] ^= 1;
        let mut out = [Partition::default(); MAX_PARTITIONS];
        assert_eq!(read(&mut disk, &mut out), Err(Error::Invalid));
        // A blank disk has no GPT.
        let mut blank = Ram::new(1024);
        assert_eq!(read(&mut blank, &mut out), Err(Error::NotFound));
    }
}
