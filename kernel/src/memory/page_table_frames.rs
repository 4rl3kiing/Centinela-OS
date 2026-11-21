//! Zero-before-use allocator for page-table frames.
//!
//! This is an ownership primitive only. It does not map, unmap, or install
//! page tables. The caller must serialize access while the kernel is single-core.

use super::pmm::{Pmm, PmmError};

/// A physical frame exclusively owned by the page-table subsystem.
///
/// This is a linear ownership token: it is neither `Copy` nor `Clone`, and it
/// must be handed back through `PageTableFrameAllocator::release`.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "dropping a PageTableFrame leaks the physical frame"]
pub struct PageTableFrame(u64);

impl PageTableFrame {
    /// Borrows the address without consuming the ownership token (taking
    /// `self` by value made the frame impossible to release afterwards).
    pub const fn physical_address(&self) -> u64 {
        self.0
    }
}

/// Errors while acquiring or releasing page-table frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageTableFrameError {
    OutOfMemory,
    Pmm(PmmError),
    ZeroingFailed,
    RollbackFailed(PmmError),
}

/// Errors reported by a page-table frame zeroing backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameZeroError {
    MappingUnavailable,
    WriteFailed,
}

/// Provides a writable mapping for clearing a complete physical frame.
///
/// # Safety
/// Implementations must ensure that `zero_frame` writes zero to every byte
/// in the requested 4 KiB physical frame, through a valid writable mapping.
/// The mapping must refer to that exact physical frame and remain valid for
/// the duration of the call. The implementation must not retain aliases or
/// expose the frame to another CPU/device. The caller serializes access.
pub unsafe trait PageTableFrameMemory {
    /// Clears the complete frame or returns an error without claiming success.
    ///
    /// # Safety
    /// The caller must own the frame exclusively and must not concurrently
    /// access it through another alias.
    unsafe fn zero_frame(&mut self, physical_address: u64) -> Result<(), FrameZeroError>;
}

/// Couples PMM ownership with the requirement that page-table frames are zeroed
/// before they can be published to a page-table builder.
pub struct PageTableFrameAllocator<'p, 'm, M: PageTableFrameMemory> {
    pmm: &'p mut Pmm<'m>,
    memory: M,
}

impl<'p, 'm, M: PageTableFrameMemory> PageTableFrameAllocator<'p, 'm, M> {
    pub fn new(pmm: &'p mut Pmm<'m>, memory: M) -> Self {
        Self { pmm, memory }
    }

    /// Allocates and clears a frame. On zeroing failure, returns the frame to
    /// PMM; a rollback failure is surfaced rather than silently leaking it.
    pub fn allocate(&mut self) -> Result<PageTableFrame, PageTableFrameError> {
        let physical_address = self
            .pmm
            .allocate_frame()
            .ok_or(PageTableFrameError::OutOfMemory)?;

        // SAFETY: PMM just transferred exclusive ownership of this allocated
        // frame to this allocator; callers serialize allocator access.
        if unsafe { self.memory.zero_frame(physical_address) }.is_err() {
            return match self.pmm.free_frame(physical_address) {
                Ok(()) => Err(PageTableFrameError::ZeroingFailed),
                Err(error) => Err(PageTableFrameError::RollbackFailed(error)),
            };
        }

        Ok(PageTableFrame(physical_address))
    }

    /// Returns an unused page-table frame to PMM.
    ///
    /// The caller must first ensure the frame is no longer referenced by any
    /// page-table entry, hardware walker, or software alias.
    pub fn release(&mut self, frame: PageTableFrame) -> Result<(), PageTableFrameError> {
        self.pmm
            .free_frame(frame.0)
            .map_err(PageTableFrameError::Pmm)
    }

    /// Borrows the frame-zeroing backend for diagnostics or platform checks.
    pub fn memory(&self) -> &M {
        &self.memory
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FrameZeroError, PageTableFrameAllocator, PageTableFrameError, PageTableFrameMemory,
    };
    use crate::memory::pmm::{LimineMemoryMapEntry, LimineMemoryMapResponse, PAGE_SIZE, Pmm};

    struct FakeMemory {
        fail: bool,
        last_zeroed: Option<u64>,
    }

    // SAFETY: This test backend models an exclusive, complete-frame zeroing
    // operation and does not expose or retain aliases to the frame.
    unsafe impl PageTableFrameMemory for FakeMemory {
        unsafe fn zero_frame(&mut self, physical_address: u64) -> Result<(), FrameZeroError> {
            self.last_zeroed = Some(physical_address);
            if self.fail {
                Err(FrameZeroError::WriteFailed)
            } else {
                Ok(())
            }
        }
    }

    fn initialized_pmm<'a>(bitmap: &'a mut [u64; 2], allocated: &'a mut [u64; 2]) -> Pmm<'a> {
        let mut pmm = Pmm::new(bitmap, allocated).expect("valid bitmap sizes");
        let usable = LimineMemoryMapEntry {
            base: 0,
            length: 128 * PAGE_SIZE,
            entry_type: 0,
        };
        let entries = [&usable as *const LimineMemoryMapEntry];
        let response = LimineMemoryMapResponse {
            revision: 0,
            entry_count: 1,
            entries: entries.as_ptr(),
        };
        // SAFETY: The response and pointed-to data remain valid for this call.
        unsafe { pmm.initialize_from_limine(&response, 2 * PAGE_SIZE, 4 * PAGE_SIZE) }
            .expect("valid memory map");
        pmm
    }

    #[test]
    fn allocated_page_table_frame_is_zeroed_before_return() {
        let mut bitmap = [u64::MAX; 2];
        let mut allocated = [0_u64; 2];
        let mut pmm = initialized_pmm(&mut bitmap, &mut allocated);
        let memory = FakeMemory {
            fail: false,
            last_zeroed: None,
        };
        let mut allocator = PageTableFrameAllocator::new(&mut pmm, memory);

        let frame = allocator.allocate().expect("frame should be allocated");
        assert_eq!(frame.physical_address(), PAGE_SIZE);
        assert_eq!(allocator.memory().last_zeroed, Some(PAGE_SIZE));
    }

    #[test]
    fn zeroing_failure_rolls_back_the_pmm_allocation() {
        let mut bitmap = [u64::MAX; 2];
        let mut allocated = [0_u64; 2];
        let mut pmm = initialized_pmm(&mut bitmap, &mut allocated);
        let before = pmm.free_frames();
        let memory = FakeMemory {
            fail: true,
            last_zeroed: None,
        };
        let mut allocator = PageTableFrameAllocator::new(&mut pmm, memory);

        assert_eq!(
            allocator.allocate(),
            Err(PageTableFrameError::ZeroingFailed)
        );
        assert_eq!(allocator.pmm.free_frames(), before);
        assert_eq!(allocator.memory().last_zeroed, Some(PAGE_SIZE));
    }

    #[test]
    fn release_returns_owned_frame_to_pmm() {
        let mut bitmap = [u64::MAX; 2];
        let mut allocated = [0_u64; 2];
        let mut pmm = initialized_pmm(&mut bitmap, &mut allocated);
        let memory = FakeMemory {
            fail: false,
            last_zeroed: None,
        };
        let mut allocator = PageTableFrameAllocator::new(&mut pmm, memory);
        let before = allocator.pmm.free_frames();
        let frame = allocator.allocate().expect("frame should be allocated");

        allocator
            .release(frame)
            .expect("owned frame should be releasable");
        assert_eq!(allocator.pmm.free_frames(), before);
    }
}
