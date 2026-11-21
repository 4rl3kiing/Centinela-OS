//! Defensive ELF64 loader planning (pure logic, host-tested).
//!
//! Every image is treated as hostile even though the boot chain verifies its
//! hash: the parser only reads within bounds, accepts static x86_64
//! executables, and produces a mapping plan that the kernel then executes.
//! Rejected:
//! - malformed headers, wrong class/endianness/machine/type, truncation;
//! - segments outside the user window, overflowing or overlapping pages;
//! - segments that are both writable and executable (W^X);
//! - segments whose file and memory offsets are not congruent mod 4 KiB;
//! - an entry point that is not inside an executable segment;
//! - images that would need more pages than the per-image limit.

/// Lowest address a user segment may occupy (keeps page 0 unmapped).
pub const USER_IMAGE_BASE: u64 = 0x0000_0000_0040_0000;
/// Exclusive upper bound for user segments (below the stack region).
pub const USER_IMAGE_LIMIT: u64 = 0x0000_7000_0000_0000;
pub const MAX_SEGMENTS: usize = 8;
pub const MAX_IMAGE_PAGES: u64 = 512;
const PAGE: u64 = 4096;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    Truncated,
    BadMagic,
    Unsupported,
    BadProgramHeaders,
    TooManySegments,
    SegmentOutOfBounds,
    SegmentOutsideUserWindow,
    MisalignedSegment,
    OverlappingSegments,
    WritableAndExecutable,
    EntryNotExecutable,
    TooLarge,
    NoLoadableSegments,
}

/// One loadable segment, validated and page-expanded.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Segment {
    /// Page-aligned first virtual page.
    pub page_start: u64,
    /// Page-aligned end (exclusive).
    pub page_end: u64,
    /// Exact virtual address where file bytes start.
    pub vaddr: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadPlan {
    pub entry: u64,
    pub segments: [Segment; MAX_SEGMENTS],
    pub count: usize,
}

impl LoadPlan {
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.count]
    }

    pub fn total_pages(&self) -> u64 {
        self.segments()
            .iter()
            .map(|segment| (segment.page_end - segment.page_start) / PAGE)
            .sum()
    }
}

fn read_u16(image: &[u8], offset: usize) -> Result<u16, ElfError> {
    let bytes = image.get(offset..offset + 2).ok_or(ElfError::Truncated)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(image: &[u8], offset: usize) -> Result<u32, ElfError> {
    let bytes = image.get(offset..offset + 4).ok_or(ElfError::Truncated)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(image: &[u8], offset: usize) -> Result<u64, ElfError> {
    let bytes = image.get(offset..offset + 8).ok_or(ElfError::Truncated)?;
    let mut array = [0u8; 8];
    array.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(array))
}

/// Validates `image` and returns the mapping plan.
pub fn plan(image: &[u8]) -> Result<LoadPlan, ElfError> {
    if image.len() < 64 {
        return Err(ElfError::Truncated);
    }
    if image[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfError::BadMagic);
    }
    // ELFCLASS64, little endian, current version, ET_EXEC, EM_X86_64.
    if image[4] != 2 || image[5] != 1 || image[6] != 1 {
        return Err(ElfError::Unsupported);
    }
    if read_u16(image, 16)? != 2 || read_u16(image, 18)? != 0x3e || read_u32(image, 20)? != 1 {
        return Err(ElfError::Unsupported);
    }
    let entry = read_u64(image, 24)?;
    let phoff = read_u64(image, 32)?;
    let phentsize = u64::from(read_u16(image, 54)?);
    let phnum = u64::from(read_u16(image, 56)?);
    if phentsize != 56 {
        return Err(ElfError::BadProgramHeaders);
    }
    let table_end = phnum
        .checked_mul(phentsize)
        .and_then(|size| size.checked_add(phoff))
        .ok_or(ElfError::BadProgramHeaders)?;
    if table_end > image.len() as u64 {
        return Err(ElfError::BadProgramHeaders);
    }

    let mut segments = [Segment::default(); MAX_SEGMENTS];
    let mut count = 0usize;
    for index in 0..phnum {
        let base = (phoff + index * phentsize) as usize;
        if read_u32(image, base)? != PT_LOAD {
            continue;
        }
        let flags = read_u32(image, base + 4)?;
        let offset = read_u64(image, base + 8)?;
        let vaddr = read_u64(image, base + 16)?;
        let file_size = read_u64(image, base + 32)?;
        let mem_size = read_u64(image, base + 40)?;
        if mem_size == 0 {
            continue;
        }
        if count == MAX_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }
        let writable = flags & PF_W != 0;
        let executable = flags & PF_X != 0;
        if writable && executable {
            return Err(ElfError::WritableAndExecutable);
        }
        if flags & PF_R == 0 && !executable {
            // x86 cannot express write-only or no-access mappings.
            return Err(ElfError::Unsupported);
        }
        if file_size > mem_size {
            return Err(ElfError::SegmentOutOfBounds);
        }
        let file_end = offset
            .checked_add(file_size)
            .ok_or(ElfError::SegmentOutOfBounds)?;
        if file_end > image.len() as u64 {
            return Err(ElfError::SegmentOutOfBounds);
        }
        if vaddr % PAGE != offset % PAGE {
            return Err(ElfError::MisalignedSegment);
        }
        let end = vaddr
            .checked_add(mem_size)
            .ok_or(ElfError::SegmentOutsideUserWindow)?;
        if vaddr < USER_IMAGE_BASE || end > USER_IMAGE_LIMIT {
            return Err(ElfError::SegmentOutsideUserWindow);
        }
        let page_start = vaddr & !(PAGE - 1);
        let page_end = end.div_ceil(PAGE) * PAGE;
        for existing in &segments[..count] {
            if page_start < existing.page_end && existing.page_start < page_end {
                return Err(ElfError::OverlappingSegments);
            }
        }
        segments[count] = Segment {
            page_start,
            page_end,
            vaddr,
            file_offset: offset,
            file_size,
            writable,
            executable,
        };
        count += 1;
    }
    if count == 0 {
        return Err(ElfError::NoLoadableSegments);
    }
    let plan = LoadPlan {
        entry,
        segments,
        count,
    };
    if plan.total_pages() > MAX_IMAGE_PAGES {
        return Err(ElfError::TooLarge);
    }
    let entry_ok = plan
        .segments()
        .iter()
        .any(|segment| segment.executable && entry >= segment.vaddr && entry < segment.page_end);
    if !entry_ok {
        return Err(ElfError::EntryNotExecutable);
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::{ElfError, plan};
    use std::vec::Vec;

    /// Builds a minimal ELF64 executable with the given PT_LOAD segments:
    /// (flags, file offset, vaddr, file size, memory size).
    fn image(entry: u64, segments: &[(u32, u64, u64, u64, u64)], size: usize) -> Vec<u8> {
        let mut bytes = std::vec![0u8; size.max(64 + 56 * segments.len())];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&entry.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&(segments.len() as u16).to_le_bytes());
        for (index, (flags, offset, vaddr, filesz, memsz)) in segments.iter().enumerate() {
            let base = 64 + index * 56;
            bytes[base..base + 4].copy_from_slice(&1u32.to_le_bytes());
            bytes[base + 4..base + 8].copy_from_slice(&flags.to_le_bytes());
            bytes[base + 8..base + 16].copy_from_slice(&offset.to_le_bytes());
            bytes[base + 16..base + 24].copy_from_slice(&vaddr.to_le_bytes());
            bytes[base + 32..base + 40].copy_from_slice(&filesz.to_le_bytes());
            bytes[base + 40..base + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        bytes
    }

    const RX: u32 = 5;
    const R: u32 = 4;
    const RW: u32 = 6;
    const RWX: u32 = 7;

    #[test]
    fn accepts_a_wx_clean_static_executable() {
        let bytes = image(
            0x40_0010,
            &[
                (RX, 0x1000, 0x40_0000, 0x100, 0x100),
                (R, 0x2000, 0x40_1000, 0x80, 0x80),
                (RW, 0x3000, 0x40_2000, 0x10, 0x2000),
            ],
            0x4000,
        );
        let plan = plan(&bytes).unwrap();
        assert_eq!(plan.count, 3);
        assert_eq!(plan.entry, 0x40_0010);
        assert_eq!(plan.total_pages(), 4, "bss expands to its own pages");
        assert!(plan.segments()[0].executable && !plan.segments()[0].writable);
    }

    #[test]
    fn rejects_writable_executable_segments() {
        let bytes = image(0x40_0000, &[(RWX, 0x1000, 0x40_0000, 0x10, 0x10)], 0x2000);
        assert_eq!(plan(&bytes), Err(ElfError::WritableAndExecutable));
    }

    #[test]
    fn rejects_kernel_or_null_page_addresses() {
        for vaddr in [0xffff_ffff_8000_0000, 0, 0x1000] {
            let bytes = image(vaddr, &[(RX, 0x1000, vaddr, 0x10, 0x10)], 0x2000);
            assert_eq!(
                plan(&bytes),
                Err(ElfError::SegmentOutsideUserWindow),
                "{vaddr:#x}"
            );
        }
    }

    #[test]
    fn rejects_overlap_truncation_and_bad_entry() {
        let overlap = image(
            0x40_0000,
            &[
                (RX, 0x1000, 0x40_0000, 0x10, 0x10),
                (RW, 0x1800, 0x40_0800, 0x10, 0x10),
            ],
            0x2000,
        );
        assert_eq!(plan(&overlap), Err(ElfError::OverlappingSegments));
        let truncated = image(
            0x40_0000,
            &[(RX, 0x1000, 0x40_0000, 0x5000, 0x5000)],
            0x2000,
        );
        assert_eq!(plan(&truncated), Err(ElfError::SegmentOutOfBounds));
        let entry_in_data = image(
            0x40_1000,
            &[
                (RX, 0x1000, 0x40_0000, 0x10, 0x10),
                (RW, 0x2000, 0x40_1000, 0x10, 0x10),
            ],
            0x3000,
        );
        assert_eq!(plan(&entry_in_data), Err(ElfError::EntryNotExecutable));
        let misaligned = image(0x40_0000, &[(RX, 0x1004, 0x40_0000, 0x10, 0x10)], 0x2000);
        assert_eq!(plan(&misaligned), Err(ElfError::MisalignedSegment));
    }

    #[test]
    fn rejects_garbage_and_hostile_headers() {
        assert_eq!(plan(&[0u8; 16]), Err(ElfError::Truncated));
        assert_eq!(plan(&[0u8; 64]), Err(ElfError::BadMagic));
        let mut huge_table = image(0x40_0000, &[(RX, 0x1000, 0x40_0000, 0x10, 0x10)], 0x2000);
        huge_table[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(plan(&huge_table), Err(ElfError::BadProgramHeaders));
        let mut overflowing = image(0x40_0000, &[(RX, 0x1000, 0x40_0000, 0x10, 0x10)], 0x2000);
        overflowing[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(plan(&overflowing), Err(ElfError::BadProgramHeaders));
        let huge = image(
            0x40_0000,
            &[(RX, 0x1000, 0x40_0000, 0x10, 0x1000_0000)],
            0x2000,
        );
        assert_eq!(plan(&huge), Err(ElfError::TooLarge));
    }
}
