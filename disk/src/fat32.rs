//! FAT32 writer for the EFI system partition (Microsoft FAT specification
//! 1.03): formats a partition and lays out a fixed set of files in one pass,
//! with VFAT long names. No heap: the tree is built in fixed-size arrays.
//!
//! Files and directories occupy contiguous cluster runs, so the FAT is
//! generated from the run list instead of being edited in place.

use crate::{Error, SECTOR, SectorDevice, put_u16, put_u32};

pub const MAX_NODES: usize = 96;
const MIN_CLUSTERS: u64 = 65_525;
const RESERVED: u64 = 32;
const EOC: u32 = 0x0fff_ffff;
/// 2026-11-21 in FAT date format.
const DATE: u16 = ((2026 - 1980) << 9) | (11 << 5) | 21;

/// A file to place on the volume (path with '/' separators).
#[derive(Clone, Copy)]
pub struct FileSpec<'a> {
    pub path: &'a [u8],
    pub data: &'a [u8],
}

#[derive(Clone, Copy)]
struct Node<'a> {
    name: &'a [u8],
    parent: usize,
    directory: bool,
    data: &'a [u8],
    first: u32,
    clusters: u32,
    short: [u8; 11],
    long: bool,
}

struct Geometry {
    first_lba: u64,
    spc: u64,
    fat_sectors: u64,
    clusters: u64,
}

impl Geometry {
    fn new(first_lba: u64, sectors: u64) -> Option<Self> {
        for spc in [8u64, 4, 2, 1] {
            let mut fat_sectors = 1;
            loop {
                let data = sectors.checked_sub(RESERVED + 2 * fat_sectors)?;
                let clusters = data / spc;
                let needed = ((clusters + 2) * 4).div_ceil(SECTOR as u64);
                if needed <= fat_sectors {
                    if (MIN_CLUSTERS..0x0fff_fff5).contains(&clusters) {
                        return Some(Self {
                            first_lba,
                            spc,
                            fat_sectors,
                            clusters,
                        });
                    }
                    break;
                }
                fat_sectors = needed;
            }
        }
        None
    }

    fn cluster_bytes(&self) -> u64 {
        self.spc * SECTOR as u64
    }

    fn cluster_lba(&self, cluster: u32) -> u64 {
        self.first_lba + RESERVED + 2 * self.fat_sectors + (u64::from(cluster) - 2) * self.spc
    }
}

fn is_short_char(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit() || b"$%'-_@~`!(){}^#&".contains(&b)
}

/// The name as an exact 8.3 short name, if it already is one (uppercase).
fn exact_short(name: &[u8]) -> Option<[u8; 11]> {
    let mut out = [b' '; 11];
    let (base, ext) = match name.iter().position(|&b| b == b'.') {
        Some(dot) => (&name[..dot], &name[dot + 1..]),
        None => (name, &[][..]),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || ext.contains(&b'.') {
        return None;
    }
    if !base.iter().chain(ext).all(|&b| is_short_char(b)) {
        return None;
    }
    out[..base.len()].copy_from_slice(base);
    out[8..8 + ext.len()].copy_from_slice(ext);
    Some(out)
}

/// Generated short name "BASIS~N.EXT" for a long name.
fn generated_short(name: &[u8], ordinal: u32) -> [u8; 11] {
    let mut out = [b' '; 11];
    let dot = name.iter().rposition(|&b| b == b'.');
    let (base, ext) = match dot {
        Some(dot) if dot > 0 => (&name[..dot], &name[dot + 1..]),
        _ => (name, &[][..]),
    };
    let tail_len = if ordinal < 10 { 2 } else { 3 };
    let mut length = 0;
    for &b in base {
        let b = b.to_ascii_uppercase();
        if length < 8 - tail_len && is_short_char(b) {
            out[length] = b;
            length += 1;
        }
    }
    if length == 0 {
        out[0] = b'X';
        length = 1;
    }
    out[length] = b'~';
    if ordinal < 10 {
        out[length + 1] = b'0' + ordinal as u8;
    } else {
        out[length + 1] = b'0' + (ordinal / 10 % 10) as u8;
        out[length + 2] = b'0' + (ordinal % 10) as u8;
    }
    let mut e = 0;
    for &b in ext {
        let b = b.to_ascii_uppercase();
        if e < 3 && is_short_char(b) {
            out[8 + e] = b;
            e += 1;
        }
    }
    out
}

fn short_checksum(short: &[u8; 11]) -> u8 {
    short
        .iter()
        .fold(0u8, |sum, &b| sum.rotate_right(1).wrapping_add(b))
}

fn lfn_entries(name: &[u8]) -> usize {
    (name.len() + 1).div_ceil(13)
}

/// Writes directory entry `index` of directory node `dir` into `out`.
/// Returns false past the last entry.
fn dir_entry(
    nodes: &[Node<'_>],
    count: usize,
    dir: usize,
    index: usize,
    label: &[u8; 11],
    out: &mut [u8],
) -> bool {
    out.fill(0);
    let short_entry = |out: &mut [u8], name: &[u8; 11], attr: u8, first: u32, size: u32| {
        out[..11].copy_from_slice(name);
        out[11] = attr;
        put_u16(out, 16, DATE);
        put_u16(out, 18, DATE);
        put_u16(out, 20, (first >> 16) as u16);
        put_u16(out, 24, DATE);
        put_u16(out, 26, first as u16);
        put_u32(out, 28, size);
    };
    let mut cursor = if dir == 0 { 1 } else { 2 };
    if dir == 0 {
        if index == 0 {
            short_entry(out, label, 0x08, 0, 0);
            return true;
        }
    } else {
        if index == 0 {
            short_entry(out, b".          ", 0x10, nodes[dir].first, 0);
            return true;
        }
        if index == 1 {
            let parent = nodes[dir].parent;
            let first = if parent == 0 { 0 } else { nodes[parent].first };
            short_entry(out, b"..         ", 0x10, first, 0);
            return true;
        }
    }
    for node in nodes[..count].iter().skip(1).filter(|n| n.parent == dir) {
        let lfns = if node.long { lfn_entries(node.name) } else { 0 };
        if index < cursor + lfns {
            // LFN entries come in reverse order: the last part first.
            let order = lfns - (index - cursor);
            out[0] = order as u8 | if order == lfns { 0x40 } else { 0 };
            out[11] = 0x0f;
            out[13] = short_checksum(&node.short);
            let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
            for (slot, &at) in offsets.iter().enumerate() {
                let position = (order - 1) * 13 + slot;
                let unit: u16 = match position.cmp(&node.name.len()) {
                    core::cmp::Ordering::Less => u16::from(node.name[position]),
                    core::cmp::Ordering::Equal => 0,
                    core::cmp::Ordering::Greater => 0xffff,
                };
                put_u16(out, at, unit);
            }
            return true;
        }
        cursor += lfns;
        if index == cursor {
            let (attr, size) = if node.directory {
                (0x10, 0)
            } else {
                (0x20, node.data.len() as u32)
            };
            short_entry(out, &node.short, attr, node.first, size);
            return true;
        }
        cursor += 1;
    }
    false
}

fn dir_entry_count(nodes: &[Node<'_>], count: usize, dir: usize) -> usize {
    let base = if dir == 0 { 1 } else { 2 };
    base + nodes[..count]
        .iter()
        .skip(1)
        .filter(|n| n.parent == dir)
        .map(|n| 1 + if n.long { lfn_entries(n.name) } else { 0 })
        .sum::<usize>()
}

/// Formats sectors `first_lba..first_lba + sectors` as FAT32 and writes
/// `files`. Directories are created as needed.
pub fn format_with_files<D: SectorDevice>(
    device: &mut D,
    first_lba: u64,
    sectors: u64,
    label: &[u8; 11],
    files: &[FileSpec<'_>],
) -> Result<(), Error> {
    if first_lba
        .checked_add(sectors)
        .is_none_or(|end| end > device.sectors())
    {
        return Err(Error::TooSmall);
    }
    let geometry = Geometry::new(first_lba, sectors).ok_or(Error::TooSmall)?;
    let empty = Node {
        name: &[],
        parent: 0,
        directory: true,
        data: &[],
        first: 0,
        clusters: 0,
        short: [b' '; 11],
        long: false,
    };
    let mut nodes = [empty; MAX_NODES];
    let mut count = 1; // node 0 = root
    for file in files {
        let mut parent = 0;
        let mut parts = file.path.split(|&b| b == b'/').peekable();
        while let Some(part) = parts.next() {
            let last = parts.peek().is_none();
            if part.is_empty()
                || part.len() > 255
                || !part.iter().all(|&b| (0x20..0x7f).contains(&b))
            {
                return Err(Error::Invalid);
            }
            let existing = (1..count)
                .find(|&i| nodes[i].parent == parent && nodes[i].name.eq_ignore_ascii_case(part));
            match existing {
                Some(i) if !last && nodes[i].directory => parent = i,
                Some(_) => return Err(Error::Invalid),
                None => {
                    if count == MAX_NODES {
                        return Err(Error::Full);
                    }
                    nodes[count] = Node {
                        name: part,
                        parent,
                        directory: !last,
                        data: if last { file.data } else { &[] },
                        ..empty
                    };
                    parent = count;
                    count += 1;
                }
            }
        }
    }
    // Short names (unique per directory) and cluster runs.
    for i in 1..count {
        match exact_short(nodes[i].name) {
            Some(short) => nodes[i].short = short,
            None => {
                let mut ordinal = 1;
                loop {
                    let candidate = generated_short(nodes[i].name, ordinal);
                    let taken = (1..i)
                        .any(|j| nodes[j].parent == nodes[i].parent && nodes[j].short == candidate);
                    if !taken {
                        nodes[i].short = candidate;
                        break;
                    }
                    ordinal += 1;
                    if ordinal > 99 {
                        return Err(Error::Full);
                    }
                }
                nodes[i].long = true;
            }
        }
    }
    let cluster_bytes = geometry.cluster_bytes();
    let mut next: u32 = 2;
    for i in 0..count {
        let bytes = if nodes[i].directory {
            (dir_entry_count(&nodes, count, i) * 32) as u64
        } else {
            nodes[i].data.len() as u64
        };
        let clusters = bytes.div_ceil(cluster_bytes);
        let clusters = if nodes[i].directory {
            clusters.max(1)
        } else {
            clusters
        };
        nodes[i].clusters = clusters as u32;
        nodes[i].first = if clusters == 0 { 0 } else { next };
        next += clusters as u32;
    }
    if u64::from(next) - 2 > geometry.clusters {
        return Err(Error::Full);
    }

    // Boot sector, FSInfo and their backups.
    let mut boot = [0u8; SECTOR];
    boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"MSWIN4.1");
    put_u16(&mut boot, 11, SECTOR as u16);
    boot[13] = geometry.spc as u8;
    put_u16(&mut boot, 14, RESERVED as u16);
    boot[16] = 2;
    boot[21] = 0xf8;
    put_u16(&mut boot, 24, 63);
    put_u16(&mut boot, 26, 255);
    put_u32(
        &mut boot,
        28,
        u32::try_from(first_lba).map_err(|_| Error::Invalid)?,
    );
    put_u32(
        &mut boot,
        32,
        u32::try_from(sectors).map_err(|_| Error::Invalid)?,
    );
    put_u32(&mut boot, 36, geometry.fat_sectors as u32);
    put_u32(&mut boot, 44, 2);
    put_u16(&mut boot, 48, 1);
    put_u16(&mut boot, 50, 6);
    boot[64] = 0x80;
    boot[66] = 0x29;
    put_u32(&mut boot, 67, 0x4345_4e54);
    boot[71..82].copy_from_slice(label);
    boot[82..90].copy_from_slice(b"FAT32   ");
    boot[510] = 0x55;
    boot[511] = 0xaa;
    let mut info = [0u8; SECTOR];
    put_u32(&mut info, 0, 0x4161_5252);
    put_u32(&mut info, 484, 0x6141_7272);
    put_u32(
        &mut info,
        488,
        (geometry.clusters - (u64::from(next) - 2)) as u32,
    );
    put_u32(&mut info, 492, next);
    put_u32(&mut info, 508, 0xaa55_0000);
    let zero = [0u8; SECTOR];
    for lba in 0..RESERVED {
        let sector = match lba {
            0 | 6 => &boot,
            1 | 7 => &info,
            _ => &zero,
        };
        device.write(first_lba + lba, sector)?;
    }
    // Both FATs, generated from the runs.
    let entries_per_sector = (SECTOR / 4) as u64;
    let mut sector = [0u8; SECTOR];
    for index in 0..geometry.fat_sectors {
        let base = index * entries_per_sector;
        if base > u64::from(next) {
            sector.fill(0);
        } else {
            for slot in 0..entries_per_sector {
                let cluster = base + slot;
                let value = match cluster {
                    0 => 0x0fff_fff8,
                    1 => EOC,
                    c if c >= u64::from(next) => 0,
                    c => {
                        let node = nodes[..count]
                            .iter()
                            .find(|n| {
                                n.clusters > 0
                                    && c >= u64::from(n.first)
                                    && c < u64::from(n.first + n.clusters)
                            })
                            .ok_or(Error::Invalid)?;
                        if c + 1 == u64::from(node.first + node.clusters) {
                            EOC
                        } else {
                            c as u32 + 1
                        }
                    }
                };
                put_u32(&mut sector, (slot * 4) as usize, value);
            }
        }
        device.write(first_lba + RESERVED + index, &sector)?;
        device.write(first_lba + RESERVED + geometry.fat_sectors + index, &sector)?;
    }
    // Directory and file contents.
    for i in 0..count {
        let node = nodes[i];
        if node.clusters == 0 {
            continue;
        }
        let lba = geometry.cluster_lba(node.first);
        let total = u64::from(node.clusters) * geometry.spc;
        for s in 0..total {
            sector.fill(0);
            if node.directory {
                for slot in 0..SECTOR / 32 {
                    let index = s as usize * (SECTOR / 32) + slot;
                    if !dir_entry(
                        &nodes,
                        count,
                        i,
                        index,
                        label,
                        &mut sector[slot * 32..slot * 32 + 32],
                    ) {
                        sector[slot * 32..].fill(0);
                        break;
                    }
                }
            } else {
                let start = s as usize * SECTOR;
                if start < node.data.len() {
                    let end = (start + SECTOR).min(node.data.len());
                    sector[..end - start].copy_from_slice(&node.data[start..end]);
                }
            }
            device.write(lba + s, &sector)?;
        }
    }
    Ok(())
}

/// Sectors a FAT32 volume needs at least (for layout planning).
pub const MIN_SECTORS: u64 = 66_600;

#[cfg(test)]
mod tests {
    extern crate std;
    use std::process::Command;
    use std::vec::Vec;

    use super::*;
    use crate::testdisk::Ram;

    #[test]
    fn short_names() {
        assert_eq!(&exact_short(b"BOOTX64.EFI").unwrap(), b"BOOTX64 EFI");
        assert_eq!(exact_short(b"limine.conf"), None);
        assert_eq!(&generated_short(b"limine.conf", 1), b"LIMINE~1CON");
        assert_eq!(&generated_short(b"centinela-kernel", 2), b"CENTIN~2   ");
        assert_eq!(&generated_short(b"x", 12), b"X~12       ");
    }

    /// Builds a volume and checks it with the host's dosfstools/mtools when
    /// they are installed (CI installs them).
    #[test]
    fn host_tools_accept_the_volume() {
        let sectors = 140_000u64;
        let mut disk = Ram::new(sectors as usize + 64);
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        let files = [
            FileSpec {
                path: b"EFI/BOOT/BOOTX64.EFI",
                data: &big,
            },
            FileSpec {
                path: b"boot/limine/limine.conf",
                data: b"timeout: 3\n",
            },
            FileSpec {
                path: b"boot/centinela-kernel",
                data: b"kernel",
            },
            FileSpec {
                path: b"boot/user/uart-driver",
                data: b"",
            },
        ];
        format_with_files(&mut disk, 64, sectors, b"CENTINELA  ", &files).unwrap();
        let has = |tool: &str| {
            Command::new("sh")
                .arg("-c")
                .arg(std::format!("command -v {tool}"))
                .output()
                .is_ok_and(|o| o.status.success())
        };
        if !has("fsck.fat") || !has("mcopy") {
            std::eprintln!("dosfstools/mtools missing: host check skipped");
            return;
        }
        let path = std::env::temp_dir().join(std::format!("cfat-{}.img", std::process::id()));
        std::fs::write(&path, &disk.0[64 * SECTOR..]).unwrap();
        let fsck = Command::new("fsck.fat")
            .arg("-n")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            fsck.status.success(),
            "fsck.fat: {}",
            std::string::String::from_utf8_lossy(&fsck.stdout)
        );
        let read = |name: &str| {
            let out = Command::new("mtype")
                .arg("-i")
                .arg(&path)
                .arg(std::format!("::/{name}"))
                .output()
                .unwrap();
            assert!(out.status.success(), "mtype {name}");
            out.stdout
        };
        assert_eq!(read("EFI/BOOT/BOOTX64.EFI"), big);
        assert_eq!(read("boot/limine/limine.conf"), b"timeout: 3\n");
        assert_eq!(read("boot/centinela-kernel"), b"kernel");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refuses_bad_input() {
        let mut disk = Ram::new(1000);
        assert_eq!(
            format_with_files(&mut disk, 0, 1000, b"X          ", &[]),
            Err(Error::TooSmall)
        );
        let mut disk = Ram::new(70_000);
        let dup = [
            FileSpec {
                path: b"a/b",
                data: b"",
            },
            FileSpec {
                path: b"A/B",
                data: b"",
            },
        ];
        assert_eq!(
            format_with_files(&mut disk, 0, 70_000, b"X          ", &dup),
            Err(Error::Invalid)
        );
    }
}
