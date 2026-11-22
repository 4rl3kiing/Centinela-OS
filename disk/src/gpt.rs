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

/// Which GPT copies were usable when the table was read.
///
/// Policy: both headers are always read and validated on their own
/// (signature, revision, CRCs, position, usable range, array placement,
/// entries). Then:
/// - both valid: they must agree on everything (cross-referenced my/alternate
///   LBA, usable range, disk GUID, entry count/size, array CRC and the decoded
///   partitions), otherwise the table is ambiguous and rejected
///   ([`Error::Invalid`]); we never guess which copy is right;
/// - one valid: its table is used and the result is marked degraded, so the
///   caller can warn and the other copy can be rewritten;
/// - none valid: error.
///
/// CRC32 detects accidental damage only; anyone who can write the disk can
/// forge a consistent GPT, so this is robustness, not authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    /// Both copies valid and identical.
    Intact,
    /// Primary valid; the backup is missing, unreadable or invalid.
    BackupInvalid,
    /// Backup valid; the primary is missing, unreadable or invalid.
    PrimaryInvalid,
    /// Primary valid but its alternate LBA lies before the last sector (the
    /// disk grew, or an image was copied to a larger disk). The backup is
    /// looked for at that alternate LBA, then at the last LBA; if found it
    /// must agree with the primary, but it may also be missing. The backup
    /// should be rewritten at the end of the disk. (An alternate LBA past the
    /// end, i.e. a shrunk disk, invalidates the primary.)
    Relocated,
}

/// Header fields that both copies must share.
#[derive(Clone, Copy, Eq, PartialEq)]
struct Header {
    first: u64,
    last: u64,
    disk_guid: Guid,
    count: u64,
    array_crc: u32,
}

/// Reads and validates the GPT (see [`Health`] for the policy). Returns the
/// non-empty partitions.
pub fn read<D: SectorDevice>(
    device: &mut D,
    out: &mut [Partition; MAX_PARTITIONS],
) -> Result<usize, Error> {
    read_with_health(device, out).map(|(count, _)| count)
}

/// Like [`read`], also reporting whether a copy was unusable.
pub fn read_with_health<D: SectorDevice>(
    device: &mut D,
    out: &mut [Partition; MAX_PARTITIONS],
) -> Result<(usize, Health), Error> {
    let last = device
        .sectors()
        .checked_sub(1)
        .filter(|&lba| lba > 1)
        .ok_or(Error::NotFound)?;
    let mut backup = [Partition::default(); MAX_PARTITIONS];
    let primary = read_at(device, true, last, out);
    let alternate = primary
        .as_ref()
        .map_or(last, |&(_, _, alternate)| alternate);
    let relocated = alternate < last;
    let mut secondary = read_at(device, false, alternate, &mut backup);
    if relocated && secondary.is_err() {
        secondary = read_at(device, false, last, &mut backup);
    }
    match (primary, secondary) {
        (Ok((p, n, _)), Ok((b, m, _))) => {
            if p != b || n != m || out[..n] != backup[..m] {
                return Err(Error::Invalid);
            }
            Ok((
                n,
                if relocated {
                    Health::Relocated
                } else {
                    Health::Intact
                },
            ))
        }
        (Ok((_, n, _)), Err(_)) if relocated => Ok((n, Health::Relocated)),
        (Ok((_, n, _)), Err(_)) => Ok((n, Health::BackupInvalid)),
        (Err(_), Ok((_, m, _))) => {
            *out = backup;
            Ok((m, Health::PrimaryInvalid))
        }
        (Err(a), Err(b)) => Err(if a == Error::NotFound { b } else { a }),
    }
}

/// Validates one header and its entry array on their own. The primary is at
/// LBA 1 and its alternate LBA may be any LBA in `2..=backup_lba` (the last
/// sector, or earlier on a grown disk); a backup must be at `backup_lba` and
/// point back to LBA 1. Returns the backup LBA the header implies.
fn read_at<D: SectorDevice>(
    device: &mut D,
    primary: bool,
    backup_lba: u64,
    out: &mut [Partition; MAX_PARTITIONS],
) -> Result<(Header, usize, u64), Error> {
    let lba = if primary { 1 } else { backup_lba };
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
    if crc32(&copy[..size]) != stored
        || get_u32(&h, 8) != 0x0001_0000
        || get_u32(&h, 20) != 0
        || get_u64(&h, 24) != lba
    {
        return Err(Error::Invalid);
    }
    let alternate = get_u64(&h, 32);
    let backup_lba = if primary {
        if !(2..=backup_lba).contains(&alternate) {
            return Err(Error::Invalid);
        }
        alternate
    } else if alternate != 1 {
        return Err(Error::Invalid);
    } else {
        backup_lba
    };
    let first = get_u64(&h, 40);
    let last = get_u64(&h, 48);
    let array = get_u64(&h, 72);
    let count = u64::from(get_u32(&h, 80));
    let entry_size = get_u32(&h, 84) as usize;
    if entry_size != ENTRY_SIZE || count == 0 || count > 1024 {
        return Err(Error::Invalid);
    }
    let array_sectors = (count * ENTRY_SIZE as u64).div_ceil(SECTOR as u64);
    // The usable range must exclude every GPT structure: MBR (0), primary
    // header (1) and array (right after it), backup array (right before the
    // backup header) and backup header (last LBA). Both arrays have the same
    // size, so this holds even when only one copy can be read.
    let max_last = backup_lba.checked_sub(array_sectors + 1);
    if first < 2 + array_sectors || max_last.is_none_or(|max| last > max) || first > last {
        return Err(Error::Invalid);
    }
    // This copy's array must sit between its header and the usable range.
    let end = array.checked_add(array_sectors).ok_or(Error::Invalid)?;
    let placed = if primary {
        array >= 2 && end <= first
    } else {
        array > last && end <= backup_lba
    };
    if !placed {
        return Err(Error::Invalid);
    }
    let mut disk_guid = [0u8; 16];
    disk_guid.copy_from_slice(&h[56..72]);
    let header = Header {
        first,
        last,
        disk_guid,
        count,
        array_crc: get_u32(&h, 88),
    };
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
    if crc.finish() != header.array_crc {
        return Err(Error::Invalid);
    }
    for i in 0..found {
        for j in 0..i {
            if out[i].first_lba <= out[j].last_lba && out[j].first_lba <= out[i].last_lba {
                return Err(Error::Invalid);
            }
        }
    }
    Ok((header, found, backup_lba))
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

    const DISK: u64 = 16384;
    const BACKUP: u64 = DISK - 1;
    const BACKUP_ARRAY: u64 = DISK - 1 - ENTRY_SECTORS;

    fn fresh() -> Ram {
        let mut disk = Ram::new(DISK as usize);
        write(&mut disk, &[9; 16], &layout(DISK)).unwrap();
        disk
    }

    /// Edits a header in place and re-seals its CRC (a forged but
    /// checksum-valid header).
    fn patch(disk: &mut Ram, lba: u64, edit: impl FnOnce(&mut Sector)) {
        let at = lba as usize * SECTOR;
        let mut h = [0u8; SECTOR];
        h.copy_from_slice(&disk.0[at..at + SECTOR]);
        edit(&mut h);
        put_u32(&mut h, 16, 0);
        let crc = crc32(&h[..92]);
        put_u32(&mut h, 16, crc);
        disk.0[at..at + SECTOR].copy_from_slice(&h);
    }

    fn patch_both(disk: &mut Ram, edit: impl Fn(&mut Sector)) {
        patch(disk, 1, &edit);
        patch(disk, BACKUP, &edit);
    }

    /// Edits entry `index` in one array and re-seals that header's array CRC.
    fn patch_entry(
        disk: &mut Ram,
        header: u64,
        array: u64,
        index: usize,
        edit: impl Fn(&mut [u8]),
    ) {
        let base = array as usize * SECTOR;
        let at = base + index * ENTRY_SIZE;
        edit(&mut disk.0[at..at + ENTRY_SIZE]);
        let crc = crc32(&disk.0[base..base + ENTRY_SECTORS as usize * SECTOR]);
        patch(disk, header, |h| put_u32(h, 88, crc));
    }

    fn health(disk: &mut Ram) -> Result<(usize, Health), Error> {
        let mut out = [Partition::default(); MAX_PARTITIONS];
        read_with_health(disk, &mut out)
    }

    #[test]
    fn degraded_policy_is_explicit() {
        assert_eq!(health(&mut fresh()), Ok((2, Health::Intact)));
        // Unreadable / damaged backup: primary accepted, marked degraded.
        let mut disk = fresh();
        disk.0[BACKUP as usize * SECTOR + 20] ^= 0xff;
        assert_eq!(health(&mut disk), Ok((2, Health::BackupInvalid)));
        // Truncated image: the backup is gone and the primary's alternate LBA
        // no longer names the last sector, so neither copy is trusted.
        let mut disk = fresh();
        disk.0.truncate((DISK as usize - 1) * SECTOR);
        assert_eq!(health(&mut disk), Err(Error::Invalid));
        // Damaged primary: backup used, marked degraded, partitions intact.
        let mut disk = fresh();
        disk.0[2 * SECTOR + 40] ^= 1;
        let mut out = [Partition::default(); MAX_PARTITIONS];
        assert_eq!(
            read_with_health(&mut disk, &mut out),
            Ok((2, Health::PrimaryInvalid))
        );
        assert_eq!(out[..2], layout(DISK));
    }

    #[test]
    fn copies_must_agree() {
        // Each field differs only in the (checksum-valid) backup.
        let edits: [&dyn Fn(&mut Sector); 3] = [
            &|h| h[56] ^= 1, // disk GUID
            &|h| {
                let first = get_u64(h, 40);
                put_u64(h, 40, first + 1); // first usable
            },
            &|h| {
                let last = get_u64(h, 48);
                put_u64(h, 48, last - 1); // last usable
            },
        ];
        for edit in edits {
            let mut disk = fresh();
            // Leave room at the end so a smaller last usable LBA is valid.
            for (header, array) in [(1, 2), (BACKUP, BACKUP_ARRAY)] {
                patch_entry(&mut disk, header, array, 1, |e| put_u64(e, 40, 8000));
            }
            assert_eq!(health(&mut disk), Ok((2, Health::Intact)));
            patch(&mut disk, BACKUP, edit);
            assert_eq!(health(&mut disk), Err(Error::Invalid));
        }
        // Same header fields but a different (re-sealed) backup table.
        let mut disk = fresh();
        patch_entry(&mut disk, BACKUP, BACKUP_ARRAY, 0, |e| put_u64(e, 40, 3000));
        assert_eq!(health(&mut disk), Err(Error::Invalid));
    }

    #[test]
    fn headers_must_sit_at_their_positions() {
        // Wrong my_lba or alternate_lba in one copy: that copy is unusable.
        for (offset, value) in [
            (24, 2),
            (24, u64::MAX),
            (32, 1),
            (32, BACKUP - 1),
            (32, u64::MAX),
        ] {
            let mut disk = fresh();
            patch(&mut disk, 1, |h| put_u64(h, offset, value));
            assert_eq!(
                health(&mut disk),
                Ok((2, Health::PrimaryInvalid)),
                "{offset}={value}"
            );
        }
        // Primary and backup swapped (each claims the other's position).
        let mut disk = fresh();
        patch(&mut disk, 1, |h| {
            put_u64(h, 24, BACKUP);
            put_u64(h, 32, 1);
        });
        patch(&mut disk, BACKUP, |h| {
            put_u64(h, 24, 1);
            put_u64(h, 32, BACKUP);
        });
        assert_eq!(health(&mut disk), Err(Error::Invalid));
    }

    #[test]
    fn gpt_structures_must_stay_out_of_the_usable_range() {
        let backup_array_end = BACKUP - 1;
        let cases: [(usize, u64); 9] = [
            (40, 0), // first usable over the MBR
            (40, 1), // ... over the primary header
            (40, 2), // ... over the primary array
            (40, 2 + ENTRY_SECTORS - 1),
            (48, BACKUP),           // last usable over the backup header
            (48, backup_array_end), // ... over the backup array
            (48, BACKUP_ARRAY),
            (48, u64::MAX),
            (40, u64::MAX),
        ];
        for (offset, value) in cases {
            let mut disk = fresh();
            patch_both(&mut disk, |h| put_u64(h, offset, value));
            assert_eq!(health(&mut disk), Err(Error::Invalid), "{offset}={value}");
        }
        // Arrays relocated inside the usable range (content and CRC intact,
        // so only the placement check can catch it).
        let mut disk = fresh();
        let array = disk.0[2 * SECTOR..(2 + ENTRY_SECTORS as usize) * SECTOR].to_vec();
        disk.0[100 * SECTOR..100 * SECTOR + array.len()].copy_from_slice(&array);
        patch_both(&mut disk, |h| put_u64(h, 72, 100));
        assert_eq!(health(&mut disk), Err(Error::Invalid));
        // Arrays overlapping their own header or past the end.
        for array in [
            0,
            1,
            BACKUP - ENTRY_SECTORS + 1,
            BACKUP,
            u64::MAX,
            u64::MAX - 31,
        ] {
            let mut disk = fresh();
            patch_both(&mut disk, |h| put_u64(h, 72, array));
            assert_eq!(health(&mut disk), Err(Error::Invalid), "array {array}");
        }
    }

    #[test]
    fn partitions_must_lie_inside_the_usable_range() {
        let (first, last) = usable_range(DISK).unwrap();
        let ranges = [
            (first - 1, 4095),
            (1, 1),
            (BACKUP, BACKUP),
            (4096, last + 1),
            (4096, u64::MAX),
            (u64::MAX, u64::MAX),
            (5000, 4096),
        ];
        for (start, end) in ranges {
            let mut disk = fresh();
            for (header, array) in [(1, 2), (BACKUP, BACKUP_ARRAY)] {
                patch_entry(&mut disk, header, array, 1, |e| {
                    put_u64(e, 32, start);
                    put_u64(e, 40, end);
                });
            }
            assert_eq!(health(&mut disk), Err(Error::Invalid), "{start}..={end}");
        }
    }

    /// The image of `fresh()` copied to a disk `extra` sectors larger.
    fn grown(extra: usize) -> Ram {
        let mut disk = fresh();
        disk.0.resize((DISK as usize + extra) * SECTOR, 0);
        disk
    }

    #[test]
    fn grown_disk_is_accepted_as_relocated() {
        // Backup still at its old position (BACKUP), now before the end.
        let mut disk = grown(1000);
        let mut out = [Partition::default(); MAX_PARTITIONS];
        assert_eq!(
            read_with_health(&mut disk, &mut out),
            Ok((2, Health::Relocated))
        );
        assert_eq!(out[..2], layout(DISK));
        // The old backup is there but disagrees: ambiguous, rejected.
        let mut disk = grown(1000);
        patch(&mut disk, BACKUP, |h| h[56] ^= 1);
        assert_eq!(health(&mut disk), Err(Error::Invalid));
        // No backup anywhere (old copy wiped): primary alone, relocated.
        let mut disk = grown(1000);
        disk.0[BACKUP as usize * SECTOR..(BACKUP as usize + 1) * SECTOR].fill(0);
        assert_eq!(health(&mut disk), Ok((2, Health::Relocated)));
        // Backup moved to the new last LBA (array just before it).
        let mut disk = grown(1000);
        let new_backup = DISK + 999;
        let from = BACKUP_ARRAY as usize * SECTOR;
        let to = (new_backup - ENTRY_SECTORS) as usize * SECTOR;
        let len = (ENTRY_SECTORS as usize + 1) * SECTOR;
        let moved = disk.0[from..from + len].to_vec();
        disk.0[from..from + len].fill(0);
        disk.0[to..to + len].copy_from_slice(&moved);
        patch(&mut disk, new_backup, |h| {
            put_u64(h, 24, new_backup);
            put_u64(h, 72, new_backup - ENTRY_SECTORS);
        });
        assert_eq!(health(&mut disk), Ok((2, Health::Relocated)));
        // A damaged primary on a grown disk: the backup is no longer at the
        // last LBA, so nothing trustworthy is found.
        let mut disk = grown(1000);
        disk.0[SECTOR + 20] ^= 0xff;
        assert!(health(&mut disk).is_err());
    }

    #[test]
    fn extreme_header_values_never_panic() {
        let edits: [(usize, u32); 8] = [
            (12, 0), // header size
            (12, u32::MAX),
            (8, 0x0002_0000), // revision
            (20, 1),          // reserved
            (80, 0),          // entry count
            (80, u32::MAX),
            (84, 0), // entry size
            (84, u32::MAX),
        ];
        for (offset, value) in edits {
            let mut disk = fresh();
            patch_both(&mut disk, |h| put_u32(h, offset, value));
            assert!(health(&mut disk).is_err(), "{offset}={value}");
        }
        // Disks too small to hold a GPT, blank or not.
        for sectors in [0, 1, 2, 3, 34, 67, 68] {
            let mut disk = Ram::new(sectors);
            assert!(health(&mut disk).is_err(), "{sectors} sectors");
            disk.0.fill(0xff);
            assert!(health(&mut disk).is_err(), "{sectors} sectors");
        }
    }
}
