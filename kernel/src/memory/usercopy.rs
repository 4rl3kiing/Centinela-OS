//! Validated copies out of user address spaces.
//!
//! The kernel treats every user pointer as hostile. A copy succeeds only if
//! the whole range lies in the user half below `USER_ADDRESS_LIMIT` and every
//! page is present and user-accessible in the task's own page tables. Data is
//! read from the physical frames through a kernel alias, so the kernel never
//! dereferences a user virtual address and SMAP never has to be relaxed.

use super::vmm::{PAGE_SIZE, PageTableMemory, PageTableWalker, VirtAddr};
use centinela_hal::syscall::USER_ADDRESS_LIMIT;

/// Physical memory reader used to fetch validated user pages.
///
/// # Safety
/// `read_physical` must copy exactly `out.len()` bytes starting at `physical`
/// (never crossing the containing page) or return `false` without reading.
pub unsafe trait PhysicalMemory {
    fn read_physical(&self, physical: u64, out: &mut [u8]) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserCopyError {
    /// Some byte lies outside the user half (kernel pointer or overflow).
    OutsideUserSpace,
    /// A page is not mapped in the task's address space.
    NotMapped,
    /// A page is mapped but not accessible from Ring 3.
    NotUserAccessible,
    ReadFailed,
}

/// Returns true when `[address, address + length)` lies in user space.
pub const fn is_user_range(address: u64, length: u64) -> bool {
    match address.checked_add(length) {
        Some(end) => end <= USER_ADDRESS_LIMIT,
        None => false,
    }
}

/// Copies `out.len()` bytes from user address `address` of the address space
/// described by `walker`.
pub fn copy_from_user<M: PageTableMemory, P: PhysicalMemory>(
    walker: &PageTableWalker<'_, M>,
    physical: &P,
    address: u64,
    out: &mut [u8],
) -> Result<(), UserCopyError> {
    if !is_user_range(address, out.len() as u64) {
        return Err(UserCopyError::OutsideUserSpace);
    }
    let mut copied = 0usize;
    while copied < out.len() {
        let current = address + copied as u64;
        let in_page = (PAGE_SIZE - (current & (PAGE_SIZE - 1))) as usize;
        let chunk = in_page.min(out.len() - copied);
        let virtual_address =
            VirtAddr::new(current).map_err(|_| UserCopyError::OutsideUserSpace)?;
        let translation = walker
            .translate(virtual_address)
            .map_err(|_| UserCopyError::NotMapped)?;
        if !translation.user_accessible {
            return Err(UserCopyError::NotUserAccessible);
        }
        if !physical.read_physical(
            translation.physical_address,
            &mut out[copied..copied + chunk],
        ) {
            return Err(UserCopyError::ReadFailed);
        }
        copied += chunk;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PhysicalMemory, UserCopyError, copy_from_user, is_user_range};
    use crate::memory::vmm::{
        NO_EXECUTE_FOR_TESTS, PRESENT, PageTableMemory, PageTableWalker, PhysAddr, USER, WRITABLE,
        WalkError,
    };
    use centinela_hal::syscall::USER_ADDRESS_LIMIT;

    /// Root 0x1000 → 0x2000 → 0x3000 → PT 0x4000 maps 0x0..0x2000:
    /// page 0 user-accessible at frame 0xa000, page 1 supervisor-only at 0xb000.
    struct Tables;
    // SAFETY: Fixed in-memory table model.
    unsafe impl PageTableMemory for Tables {
        fn read_entry(&self, table: PhysAddr, index: u16) -> Result<u64, WalkError> {
            let parent = PRESENT | WRITABLE | USER;
            Ok(match (table.get(), index) {
                (0x1000, 0) => 0x2000 | parent,
                (0x2000, 0) => 0x3000 | parent,
                (0x3000, 0) => 0x4000 | parent,
                (0x4000, 0) => 0xa000 | PRESENT | USER | NO_EXECUTE_FOR_TESTS,
                (0x4000, 1) => 0xb000 | PRESENT | NO_EXECUTE_FOR_TESTS,
                _ => 0,
            })
        }
    }

    struct Frames;
    // SAFETY: Synthesizes bytes without touching real memory.
    unsafe impl PhysicalMemory for Frames {
        fn read_physical(&self, physical: u64, out: &mut [u8]) -> bool {
            for (offset, byte) in out.iter_mut().enumerate() {
                *byte = ((physical >> 12) as u8) ^ (offset as u8);
            }
            true
        }
    }

    fn walker(tables: &Tables) -> PageTableWalker<'_, Tables> {
        PageTableWalker::new(tables, PhysAddr::new(0x1000).unwrap())
    }

    #[test]
    fn copies_from_mapped_user_page() {
        let tables = Tables;
        let mut out = [0u8; 4];
        assert_eq!(
            copy_from_user(&walker(&tables), &Frames, 0x10, &mut out),
            Ok(())
        );
        assert_eq!(out, [0xa, 0xb, 0x8, 0x9]);
    }

    #[test]
    fn rejects_kernel_pointers_and_overflowing_ranges() {
        let tables = Tables;
        let mut out = [0u8; 16];
        for hostile in [0xffff_ffff_8000_0000, USER_ADDRESS_LIMIT - 8, u64::MAX - 4] {
            assert_eq!(
                copy_from_user(&walker(&tables), &Frames, hostile, &mut out),
                Err(UserCopyError::OutsideUserSpace)
            );
        }
        assert!(!is_user_range(u64::MAX, 2));
    }

    #[test]
    fn rejects_supervisor_and_unmapped_pages_even_when_straddling() {
        let tables = Tables;
        let mut out = [0u8; 16];
        // Starts in the user page, ends in the supervisor-only page.
        assert_eq!(
            copy_from_user(&walker(&tables), &Frames, 0x1000 - 8, &mut out),
            Err(UserCopyError::NotUserAccessible)
        );
        assert_eq!(
            copy_from_user(&walker(&tables), &Frames, 0x5000, &mut out),
            Err(UserCopyError::NotMapped)
        );
    }
}
