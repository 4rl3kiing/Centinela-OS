//! Physical memory manager for 4 KiB frames.
//!
//! The bootstrap implementation tracks physical memory below 64 GiB. Memory
//! outside that ceiling remains reserved until a larger bitmap strategy exists.
//! It is deliberately single-core: callers must serialize access until the
//! kernel's SMP and locking layers are implemented.

pub const PAGE_SIZE: u64 = 4096;
pub const MAX_PHYSICAL_ADDRESS: u64 = 64 * 1024 * 1024 * 1024;
pub const FRAME_COUNT: usize = (MAX_PHYSICAL_ADDRESS / PAGE_SIZE) as usize;
pub const BITMAP_WORDS: usize = FRAME_COUNT.div_ceil(u64::BITS as usize);

pub const LIMINE_MEMMAP_USABLE: u64 = 0;

const MAX_MEMORY_MAP_ENTRIES: u64 = 4096;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LimineMemoryMapEntry {
    pub base: u64,
    pub length: u64,
    pub entry_type: u64,
}

#[repr(C)]
pub struct LimineMemoryMapResponse {
    pub revision: u64,
    pub entry_count: u64,
    pub entries: *const *const LimineMemoryMapEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmmError {
    InvalidBitmapSize,
    NullMemoryMap,
    InvalidEntryCount,
    NullMemoryMapEntry,
    InvalidMemoryRegion,
    InvalidKernelRange,
    FrameOutOfRange,
    FrameAlreadyFree,
    FrameNotAllocated,
}

pub struct Pmm<'a> {
    bitmap: &'a mut [u64],
    allocated: &'a mut [u64],
    free_frames: u64,
    allocation_hint: usize,
}

impl<'a> Pmm<'a> {
    /// Creates a manager with every frame reserved.
    pub fn new(
        bitmap: &'a mut [u64],
        allocated: &'a mut [u64],
    ) -> Result<Self, PmmError> {
        if bitmap.is_empty() || bitmap.len() != allocated.len() {
            return Err(PmmError::InvalidBitmapSize);
        }

        bitmap.fill(u64::MAX);
        allocated.fill(0);
        Ok(Self {
            bitmap,
            allocated,
            free_frames: 0,
            allocation_hint: 1,
        })
    }

    /// Initializes the allocator from the Limine physical memory map.
    ///
    /// # Safety
    /// The response and every entry pointer in its array must refer to readable,
    /// correctly aligned Limine bootloader data that remains valid for the
    /// duration of this call. The caller must also serialize access to self.
    pub unsafe fn initialize_from_limine(
        &mut self,
        response: *const LimineMemoryMapResponse,
        kernel_physical_start: u64,
        kernel_physical_end: u64,
    ) -> Result<(), PmmError> {
        if response.is_null() {
            return Err(PmmError::NullMemoryMap);
        }
        if kernel_physical_start >= kernel_physical_end {
            return Err(PmmError::InvalidKernelRange);
        }

        // SAFETY: The caller guarantees the response pointer is readable.
        let response = unsafe { &*response };
        if response.entry_count == 0 || response.entry_count > MAX_MEMORY_MAP_ENTRIES {
            return Err(PmmError::InvalidEntryCount);
        }
        if response.entries.is_null() {
            return Err(PmmError::NullMemoryMap);
        }

        self.bitmap.fill(u64::MAX);
        self.allocated.fill(0);
        self.free_frames = 0;
        self.allocation_hint = 1;

        for index in 0..response.entry_count as usize {
            // SAFETY: The caller guarantees a readable entry pointer array
            // with entry_count elements.
            let entry_pointer = unsafe { response.entries.add(index).read() };
            if entry_pointer.is_null() {
                return Err(PmmError::NullMemoryMapEntry);
            }

            // SAFETY: The caller guarantees every entry pointer is readable.
            let entry = unsafe { &*entry_pointer };
            if entry.length == 0 {
                continue;
            }

            let region_end = entry
                .base
                .checked_add(entry.length)
                .ok_or(PmmError::InvalidMemoryRegion)?;

            if entry.entry_type != LIMINE_MEMMAP_USABLE {
                continue;
            }

            let start = align_up(entry.base, PAGE_SIZE).ok_or(PmmError::InvalidMemoryRegion)?;
            let end = region_end.min(MAX_PHYSICAL_ADDRESS) & !(PAGE_SIZE - 1);
            if start < end {
                self.mark_free_range(start / PAGE_SIZE, end / PAGE_SIZE);
            }
        }

        // Keep physical frame zero unavailable and reserve the complete kernel
        // load image, including its zero-initialized BSS.
        self.reserve_range(0, 1);
        let kernel_start = kernel_physical_start / PAGE_SIZE;
        let kernel_end = align_up(kernel_physical_end, PAGE_SIZE)
            .ok_or(PmmError::InvalidKernelRange)?
            / PAGE_SIZE;
        self.reserve_range(kernel_start, kernel_end);

        Ok(())
    }

    pub fn allocate_frame(&mut self) -> Option<u64> {
        if self.free_frames == 0 {
            return None;
        }

        let frame_count = self.frame_count();
        for offset in 0..frame_count {
            let frame = (self.allocation_hint + offset) % frame_count;
            if !self.is_free(frame) {
                continue;
            }

            self.set_allocated(frame);
            self.free_frames -= 1;
            self.allocation_hint = (frame + 1) % frame_count;
            return Some((frame as u64) * PAGE_SIZE);
        }

        None
    }

    /// Releases a frame previously returned by allocate_frame.
    pub fn free_frame(&mut self, physical_address: u64) -> Result<(), PmmError> {
        if physical_address & (PAGE_SIZE - 1) != 0 {
            return Err(PmmError::FrameOutOfRange);
        }

        let frame = (physical_address / PAGE_SIZE) as usize;
        if frame == 0 || frame >= self.frame_count() {
            return Err(PmmError::FrameOutOfRange);
        }
        if !self.is_allocated(frame) {
            return if self.is_free(frame) {
                Err(PmmError::FrameAlreadyFree)
            } else {
                Err(PmmError::FrameNotAllocated)
            };
        }

        self.set_free(frame);
        self.free_frames += 1;
        if frame < self.allocation_hint {
            self.allocation_hint = frame;
        }
        Ok(())
    }

    pub fn free_frames(&self) -> u64 {
        self.free_frames
    }

    pub fn total_frames(&self) -> usize {
        self.frame_count()
    }

    fn frame_count(&self) -> usize {
        self.bitmap.len() * u64::BITS as usize
    }

    fn is_free(&self, frame: usize) -> bool {
        let word = frame / u64::BITS as usize;
        let bit = frame % u64::BITS as usize;
        self.bitmap[word] & (1_u64 << bit) == 0
    }

    fn is_allocated(&self, frame: usize) -> bool {
        let word = frame / u64::BITS as usize;
        let bit = frame % u64::BITS as usize;
        self.allocated[word] & (1_u64 << bit) != 0
    }

    fn set_allocated(&mut self, frame: usize) {
        let word = frame / u64::BITS as usize;
        let bit = frame % u64::BITS as usize;
        self.bitmap[word] |= 1_u64 << bit;
        self.allocated[word] |= 1_u64 << bit;
    }

    fn set_reserved(&mut self, frame: usize) {
        let word = frame / u64::BITS as usize;
        let bit = frame % u64::BITS as usize;
        self.bitmap[word] |= 1_u64 << bit;
        self.allocated[word] &= !(1_u64 << bit);
    }

    fn set_free(&mut self, frame: usize) {
        let word = frame / u64::BITS as usize;
        let bit = frame % u64::BITS as usize;
        self.bitmap[word] &= !(1_u64 << bit);
        self.allocated[word] &= !(1_u64 << bit);
    }

    fn mark_free_range(&mut self, start_frame: u64, end_frame: u64) {
        let end = end_frame.min(self.frame_count() as u64);
        for frame in start_frame.min(end)..end {
            let frame = frame as usize;
            if !self.is_free(frame) {
                self.set_free(frame);
                self.free_frames += 1;
            }
        }
    }

    fn reserve_range(&mut self, start_frame: u64, end_frame: u64) {
        let end = end_frame.min(self.frame_count() as u64);
        for frame in start_frame.min(end)..end {
            let frame = frame as usize;
            if self.is_free(frame) {
                self.set_reserved(frame);
                self.free_frames -= 1;
            }
        }
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value.checked_add(alignment - 1).map(|aligned| aligned & !(alignment - 1))
}

#[cfg(test)]
mod tests {
    use super::{Pmm, PmmError, PAGE_SIZE};

    #[test]
    fn allocation_and_free_are_accounted() {
        let mut bitmap = [u64::MAX; 2];
        let mut allocated = [0_u64; 2];
        let mut pmm =
            Pmm::new(&mut bitmap, &mut allocated).expect("bitmaps should be accepted");
        pmm.mark_free_range(1, 128);
        assert_eq!(pmm.free_frames(), 127);

        let first = pmm.allocate_frame().expect("one frame should be available");
        assert_eq!(first, PAGE_SIZE);
        assert_eq!(pmm.free_frames(), 126);

        pmm.free_frame(first).expect("allocated frame should be releasable");
        assert_eq!(pmm.free_frames(), 127);
    }

    #[test]
    fn frame_zero_and_double_free_are_rejected() {
        let mut bitmap = [u64::MAX; 1];
        let mut allocated = [0_u64; 1];
        let mut pmm =
            Pmm::new(&mut bitmap, &mut allocated).expect("bitmaps should be accepted");
        pmm.mark_free_range(0, 64);

        assert_eq!(pmm.free_frame(0), Err(PmmError::FrameOutOfRange));
        assert_eq!(pmm.free_frame(PAGE_SIZE), Err(PmmError::FrameAlreadyFree));
    }

    #[test]
    fn unaligned_and_out_of_range_addresses_are_rejected() {
        let mut bitmap = [u64::MAX; 1];
        let mut allocated = [0_u64; 1];
        let mut pmm =
            Pmm::new(&mut bitmap, &mut allocated).expect("bitmaps should be accepted");

        assert_eq!(pmm.free_frame(1), Err(PmmError::FrameOutOfRange));
        assert_eq!(
            pmm.free_frame(64 * PAGE_SIZE),
            Err(PmmError::FrameOutOfRange)
        );
    }

    #[test]
    fn allocation_returns_none_when_no_frames_are_free() {
        let mut bitmap = [u64::MAX; 1];
        let mut pmm = Pmm::new(&mut bitmap).expect("bitmap should be accepted");
        assert_eq!(pmm.allocate_frame(), None);
    }
}
