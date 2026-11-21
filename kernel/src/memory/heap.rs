//! Hardened kernel heap (roadmap gate G4).
//!
//! A slab allocator over whole 4 KiB pages taken from the frame allocator.
//! It is built to make heap corruption loud instead of exploitable:
//!
//! - **Out-of-line metadata.** Slab descriptors (owner page, size class,
//!   free bitmap) live in a fixed table outside the heap pages. An overflow
//!   from one object can never rewrite allocator state.
//! - **Redzone canaries.** The last 8 bytes of every slot hold
//!   `secret ^ slot_address`, written on allocation and checked on free. A
//!   linear overflow into the neighbouring slot is caught at the next free.
//! - **Poison on free, verified on reuse.** Freed slots are filled with
//!   `0xDE`; allocation checks the pattern, so a write after free is caught.
//! - **Double and invalid free detection** through the descriptor bitmap
//!   and slot alignment.
//! - **Randomized placement.** A new object takes a random free slot of its
//!   slab, so heap layouts are not predictable across boots.
//! - **Zeroed allocations.** Memory handed out never carries old contents.
//!
//! Any detected corruption is fatal: the kernel halts (fail closed) rather
//! than continue with a damaged heap. Objects up to 4 KiB are supported;
//! larger requests return null (the kernel keeps large state in frames it
//! manages explicitly).
//!
//! The allocator must not be used from interrupt handlers; kernel code runs
//! with interrupts disabled, so the internal spin lock cannot be re-entered.

use core::alloc::Layout;

/// Page size backing every slab.
pub const PAGE: usize = 4096;
/// Bytes reserved at the end of each slot for the canary.
pub const REDZONE: usize = 8;
/// Slot sizes (including the redzone). The 4096 class is a whole page and
/// carries no canary (nothing follows it inside the page).
pub const CLASSES: [usize; 8] = [32, 64, 128, 256, 512, 1024, 2048, 4096];
/// Maximum number of slabs (pages) the heap may own: 16 MiB.
pub const MAX_SLABS: usize = 4096;
const TABLE: usize = MAX_SLABS * 2;
const POISON: u8 = 0xde;

/// Where heap pages come from (the frame allocator through the HHDM in the
/// kernel, a host buffer in tests).
///
/// # Safety
/// `alloc_page` must return a page-aligned, writable, exclusively owned
/// 4 KiB region that stays valid until passed to `free_page`.
pub unsafe trait PageSource {
    fn alloc_page(&mut self) -> Option<usize>;
    fn free_page(&mut self, page: usize);
}

/// Random numbers for canaries and slot choice.
pub trait Random {
    fn next(&mut self) -> u64;
}

/// Heap corruption that the allocator detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Corruption {
    /// Freed pointer is not inside any heap slab.
    InvalidFree,
    /// Freed pointer is inside a slab but not at a slot start.
    MisalignedFree,
    /// Slot was already free.
    DoubleFree,
    /// Redzone canary overwritten (overflow from this object).
    Overflow,
    /// Poison pattern of a free slot changed (write after free).
    UseAfterFree,
    /// Layout given to free does not match the slab's class.
    WrongSize,
}

#[derive(Clone, Copy)]
struct Slab {
    page: usize,
    class: u8,
    /// Bit set = slot free.
    free: u128,
}

const EMPTY: usize = 0;
const TOMBSTONE: usize = 1;

/// Allocator state. All methods require external mutual exclusion.
pub struct Heap<S: PageSource, R: Random> {
    source: S,
    random: R,
    secret: u64,
    slabs: [Slab; TABLE],
    slab_count: usize,
    /// Allocated bytes by class, for diagnostics and leak tests.
    live: [usize; CLASSES.len()],
}

fn slots(class: usize) -> usize {
    PAGE / CLASSES[class]
}

fn all_free(class: usize) -> u128 {
    let n = slots(class);
    if n == 128 {
        u128::MAX
    } else {
        (1u128 << n) - 1
    }
}

/// Size class for a layout, or `None` if it is too large.
pub fn class_for(layout: Layout) -> Option<usize> {
    if layout.align() > PAGE {
        return None;
    }
    CLASSES.iter().position(|&slot| {
        let usable = if slot == PAGE { PAGE } else { slot - REDZONE };
        // Slots are naturally aligned to their size (powers of two).
        usable >= layout.size() && slot >= layout.align()
    })
}

impl<S: PageSource, R: Random> Heap<S, R> {
    pub fn new(source: S, mut random: R) -> Self {
        let secret = random.next() | 1;
        Self {
            source,
            random,
            secret,
            slabs: [Slab {
                page: EMPTY,
                class: 0,
                free: 0,
            }; TABLE],
            slab_count: 0,
            live: [0; CLASSES.len()],
        }
    }

    /// Bytes currently allocated (by slot size).
    pub fn live_bytes(&self) -> usize {
        self.live
            .iter()
            .zip(CLASSES)
            .map(|(n, size)| n * size)
            .sum()
    }

    /// Pages currently owned by the heap.
    pub fn pages(&self) -> usize {
        self.slab_count
    }

    fn hash(page: usize) -> usize {
        ((page / PAGE).wrapping_mul(0x9e37_79b9_7f4a_7c15)) % TABLE
    }

    fn find(&self, page: usize) -> Option<usize> {
        let mut index = Self::hash(page);
        for _ in 0..TABLE {
            match self.slabs[index].page {
                EMPTY => return None,
                found if found == page => return Some(index),
                _ => index = (index + 1) % TABLE,
            }
        }
        None
    }

    fn insert(&mut self, slab: Slab) -> Option<usize> {
        let mut index = Self::hash(slab.page);
        for _ in 0..TABLE {
            if matches!(self.slabs[index].page, EMPTY | TOMBSTONE) {
                self.slabs[index] = slab;
                return Some(index);
            }
            index = (index + 1) % TABLE;
        }
        None
    }

    fn canary(&self, slot: usize) -> u64 {
        self.secret ^ slot as u64
    }

    /// Allocates zeroed memory for `layout`. `Ok(None)` means out of memory
    /// or too large; `Err` means corruption was found.
    pub fn allocate(&mut self, layout: Layout) -> Result<Option<usize>, Corruption> {
        let Some(class) = class_for(layout) else {
            return Ok(None);
        };
        // Prefer a partially used slab of this class; otherwise a new page.
        let index = match (0..TABLE).find(|&i| {
            let slab = &self.slabs[i];
            slab.page > TOMBSTONE && usize::from(slab.class) == class && slab.free != 0
        }) {
            Some(index) => index,
            None => {
                if self.slab_count >= MAX_SLABS {
                    return Ok(None);
                }
                let Some(page) = self.source.alloc_page() else {
                    return Ok(None);
                };
                // SAFETY: `PageSource` guarantees an exclusive writable page.
                unsafe { core::ptr::write_bytes(page as *mut u8, POISON, PAGE) };
                let Some(index) = self.insert(Slab {
                    page,
                    class: class as u8,
                    free: all_free(class),
                }) else {
                    self.source.free_page(page);
                    return Ok(None);
                };
                self.slab_count += 1;
                index
            }
        };
        let slab = self.slabs[index];
        let size = CLASSES[class];
        // Random free slot: rotate the bitmap by a random amount, take the
        // lowest set bit, rotate back.
        let n = slots(class) as u32;
        let rotation = (self.random.next() % u64::from(n)) as u32;
        let rotated = if n == 128 {
            slab.free.rotate_right(rotation)
        } else {
            let mask = all_free(class);
            ((slab.free >> rotation) | (slab.free << (n - rotation))) & mask
        };
        let slot_index = (rotated.trailing_zeros() + rotation) % n;
        let slot = slab.page + slot_index as usize * size;
        // SAFETY: The slot lies inside the slab page owned by the heap.
        let bytes = unsafe { core::slice::from_raw_parts_mut(slot as *mut u8, size) };
        if bytes.iter().any(|&byte| byte != POISON) {
            return Err(Corruption::UseAfterFree);
        }
        bytes.fill(0);
        if size != PAGE {
            let canary = self.canary(slot).to_ne_bytes();
            bytes[size - REDZONE..].copy_from_slice(&canary);
        }
        self.slabs[index].free &= !(1u128 << slot_index);
        self.live[class] += 1;
        Ok(Some(slot))
    }

    /// Frees an object. Detected corruption is returned and the slot is left
    /// untouched, so the caller can halt with the evidence intact.
    pub fn free(&mut self, pointer: usize, layout: Layout) -> Result<(), Corruption> {
        let page = pointer & !(PAGE - 1);
        let index = self.find(page).ok_or(Corruption::InvalidFree)?;
        let slab = self.slabs[index];
        let class = usize::from(slab.class);
        if class_for(layout) != Some(class) {
            return Err(Corruption::WrongSize);
        }
        let size = CLASSES[class];
        let offset = pointer - page;
        if !offset.is_multiple_of(size) {
            return Err(Corruption::MisalignedFree);
        }
        let slot_index = offset / size;
        if slab.free & (1u128 << slot_index) != 0 {
            return Err(Corruption::DoubleFree);
        }
        // SAFETY: The slot lies inside the slab page owned by the heap.
        let bytes = unsafe { core::slice::from_raw_parts_mut(pointer as *mut u8, size) };
        if size != PAGE && bytes[size - REDZONE..] != self.canary(pointer).to_ne_bytes() {
            return Err(Corruption::Overflow);
        }
        bytes.fill(POISON);
        let free = slab.free | (1u128 << slot_index);
        self.live[class] -= 1;
        if free == all_free(class) {
            // Empty slab: return the page (wiped, so no heap data leaks into
            // the next owner of the frame).
            // SAFETY: Whole slab page owned by the heap.
            unsafe { core::ptr::write_bytes(page as *mut u8, 0, PAGE) };
            self.slabs[index] = Slab {
                page: TOMBSTONE,
                class: 0,
                free: 0,
            };
            self.slab_count -= 1;
            self.source.free_page(page);
        } else {
            self.slabs[index].free = free;
        }
        Ok(())
    }
}

#[cfg(target_os = "none")]
pub mod global {
    //! The kernel's `#[global_allocator]` over the shared frame allocator.

    use super::{Corruption, Heap, PageSource, Random};
    use crate::memory::hhdm_backend::PmmLock;
    use crate::memory::vmm::{HhdmOffset, PhysAddr};
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicBool, Ordering};

    pub struct Frames {
        hhdm: HhdmOffset,
        pmm: &'static PmmLock<'static>,
    }

    // SAFETY: Frames come from the PMM and are reached through the HHDM,
    // which maps all usable RAM writable; each frame is owned exclusively
    // until returned.
    unsafe impl PageSource for Frames {
        fn alloc_page(&mut self) -> Option<usize> {
            let physical = self.pmm.with(|pmm| pmm.allocate_frame())?;
            let virt = PhysAddr::new(physical)
                .ok()
                .and_then(|p| self.hhdm.physical_to_virtual(p).ok())
                .map(|v| v.get() as usize);
            if virt.is_none() {
                let _ = self.pmm.with(|pmm| pmm.free_frame(physical));
            }
            virt
        }

        fn free_page(&mut self, page: usize) {
            let physical = page as u64 - self.hhdm.get();
            let _ = self.pmm.with(|pmm| pmm.free_frame(physical));
        }
    }

    /// RDRAND when available, otherwise a TSC-seeded xorshift.
    pub struct Entropy(u64);

    impl Random for Entropy {
        fn next(&mut self) -> u64 {
            if let Some(value) = centinela_hal::entropy::rdrand_u64() {
                return value;
            }
            let mut x = self.0 ^ read_tsc();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn read_tsc() -> u64 {
        // SAFETY: RDTSC has no memory effects.
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    pub struct KernelHeap {
        locked: AtomicBool,
        heap: UnsafeCell<Option<Heap<Frames, Entropy>>>,
    }

    // SAFETY: All access to `heap` happens with `locked` held.
    unsafe impl Sync for KernelHeap {}

    impl KernelHeap {
        pub const fn new() -> Self {
            Self {
                locked: AtomicBool::new(false),
                heap: UnsafeCell::new(None),
            }
        }

        fn with<T>(&self, f: impl FnOnce(&mut Option<Heap<Frames, Entropy>>) -> T) -> T {
            while self
                .locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            // SAFETY: The lock is held.
            let result = f(unsafe { &mut *self.heap.get() });
            self.locked.store(false, Ordering::Release);
            result
        }

        /// Connects the heap to the frame allocator. Allocations before this
        /// return null.
        pub fn install(&self, hhdm: HhdmOffset, pmm: &'static PmmLock<'static>) {
            let seed = read_tsc();
            self.with(|slot| {
                if slot.is_none() {
                    *slot = Some(Heap::new(Frames { hhdm, pmm }, Entropy(seed | 1)));
                }
            });
        }

        /// Bytes and pages currently held (diagnostics).
        pub fn usage(&self) -> (usize, usize) {
            self.with(|slot| {
                slot.as_ref()
                    .map_or((0, 0), |h| (h.live_bytes(), h.pages()))
            })
        }
    }

    impl Default for KernelHeap {
        fn default() -> Self {
            Self::new()
        }
    }

    fn corrupted(kind: Corruption) -> ! {
        panic!("kernel heap corruption detected: {kind:?}");
    }

    // SAFETY: `Heap` returns slots that are aligned to their (power of two)
    // size, at least as large as the layout, and exclusively owned until
    // freed; corruption halts instead of returning damaged memory.
    unsafe impl GlobalAlloc for KernelHeap {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            match self.with(|slot| slot.as_mut().map(|heap| heap.allocate(layout))) {
                Some(Ok(Some(address))) => address as *mut u8,
                Some(Err(kind)) => corrupted(kind),
                _ => core::ptr::null_mut(),
            }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            let result = self.with(|slot| {
                slot.as_mut()
                    .map(|heap| heap.free(pointer as usize, layout))
            });
            if let Some(Err(kind)) = result {
                corrupted(kind);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    struct HostPages {
        outstanding: usize,
        limit: usize,
        /// Pages currently handed out, released on drop so tests that end
        /// with live objects do not leak (Miri checks this).
        live: Vec<usize>,
    }

    impl Drop for HostPages {
        fn drop(&mut self) {
            let layout = Layout::from_size_align(PAGE, PAGE).unwrap();
            for &page in &self.live {
                // SAFETY: Allocated in `alloc_page` with this layout.
                unsafe { std::alloc::dealloc(page as *mut u8, layout) };
            }
        }
    }

    // SAFETY: Pages come from the system allocator with page alignment and
    // are owned by the heap until returned.
    unsafe impl PageSource for HostPages {
        fn alloc_page(&mut self) -> Option<usize> {
            if self.outstanding >= self.limit {
                return None;
            }
            let layout = Layout::from_size_align(PAGE, PAGE).ok()?;
            // SAFETY: Non-zero size layout.
            let page = unsafe { std::alloc::alloc(layout) } as usize;
            self.outstanding += 1;
            self.live.push(page);
            Some(page)
        }
        fn free_page(&mut self, page: usize) {
            // Pages must come back wiped.
            // SAFETY: Page from `alloc_page`.
            let bytes = unsafe { core::slice::from_raw_parts(page as *const u8, PAGE) };
            assert!(bytes.iter().all(|&b| b == 0), "page returned unwiped");
            let layout = Layout::from_size_align(PAGE, PAGE).unwrap();
            // SAFETY: Allocated above with the same layout.
            unsafe { std::alloc::dealloc(page as *mut u8, layout) };
            self.outstanding -= 1;
            self.live.retain(|&p| p != page);
        }
    }

    struct Counter(u64);
    impl Random for Counter {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 11
        }
    }

    fn heap(limit: usize) -> std::boxed::Box<Heap<HostPages, Counter>> {
        std::boxed::Box::new(Heap::new(
            HostPages {
                outstanding: 0,
                limit,
                live: Vec::new(),
            },
            Counter(7),
        ))
    }

    fn layout(size: usize) -> Layout {
        Layout::from_size_align(size, 8).unwrap()
    }

    #[test]
    fn classes_respect_size_and_alignment() {
        assert_eq!(class_for(layout(1)), Some(0));
        assert_eq!(class_for(layout(24)), Some(0));
        assert_eq!(class_for(layout(25)), Some(1));
        assert_eq!(class_for(layout(4096)), Some(7));
        assert_eq!(class_for(layout(4097)), None);
        assert_eq!(class_for(Layout::from_size_align(8, 256).unwrap()), Some(3));
        assert_eq!(class_for(Layout::from_size_align(8, 8192).unwrap()), None);
    }

    #[test]
    fn allocations_are_zeroed_aligned_distinct_and_reclaimed() {
        let mut heap = heap(64);
        let mut seen = Vec::new();
        for size in [1, 24, 100, 500, 2000, 4096, 24, 24] {
            let p = heap.allocate(layout(size)).unwrap().unwrap();
            let class = class_for(layout(size)).unwrap();
            assert_eq!(p % CLASSES[class], 0);
            // SAFETY: Fresh allocation of `size` bytes.
            let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, size) };
            assert!(bytes.iter().all(|&b| b == 0));
            assert!(!seen.contains(&p));
            seen.push(p);
        }
        for (p, size) in seen.iter().zip([1, 24, 100, 500, 2000, 4096, 24, 24]) {
            heap.free(*p, layout(size)).unwrap();
        }
        assert_eq!(heap.live_bytes(), 0);
        assert_eq!(heap.pages(), 0);
        assert_eq!(heap.source.outstanding, 0);
    }

    #[test]
    fn detects_overflow_into_redzone() {
        let mut heap = heap(4);
        let p = heap.allocate(layout(24)).unwrap().unwrap();
        // SAFETY: Deliberate one-byte overflow inside the slot's redzone.
        unsafe { (p as *mut u8).add(24).write(0x41) };
        assert_eq!(heap.free(p, layout(24)), Err(Corruption::Overflow));
    }

    #[test]
    fn detects_double_invalid_misaligned_and_wrong_size_frees() {
        let mut heap = heap(4);
        let p = heap.allocate(layout(24)).unwrap().unwrap();
        let q = heap.allocate(layout(24)).unwrap().unwrap();
        assert_eq!(
            heap.free(p + 8, layout(24)),
            Err(Corruption::MisalignedFree)
        );
        assert_eq!(heap.free(p, layout(200)), Err(Corruption::WrongSize));
        assert_eq!(
            heap.free(0x1000_0000, layout(24)),
            Err(Corruption::InvalidFree)
        );
        heap.free(p, layout(24)).unwrap();
        assert_eq!(heap.free(p, layout(24)), Err(Corruption::DoubleFree));
        heap.free(q, layout(24)).unwrap();
    }

    #[test]
    fn detects_write_after_free() {
        let mut heap = heap(4);
        // Keep the slab alive with a second object so the page stays mapped.
        let keep = heap.allocate(layout(2000)).unwrap().unwrap();
        let p = heap.allocate(layout(2000)).unwrap().unwrap();
        heap.free(p, layout(2000)).unwrap();
        // SAFETY: Deliberate write into a freed slot (still heap-owned).
        unsafe { (p as *mut u8).add(100).write(0x41) };
        assert_eq!(heap.allocate(layout(2000)), Err(Corruption::UseAfterFree));
        let _ = keep;
    }

    #[test]
    fn out_of_memory_is_null_not_corruption() {
        let mut heap = heap(1);
        assert!(heap.allocate(layout(4096)).unwrap().is_some());
        assert_eq!(heap.allocate(layout(4096)), Ok(None));
        assert_eq!(heap.allocate(layout(8192)), Ok(None));
    }

    #[test]
    fn placement_is_randomized() {
        let mut heap = heap(4);
        let first: Vec<usize> = (0..16)
            .map(|_| heap.allocate(layout(24)).unwrap().unwrap())
            .collect();
        let page = first[0] & !(PAGE - 1);
        let offsets: Vec<usize> = first.iter().map(|p| (p - page) / 32).collect();
        let sequential: Vec<usize> = (0..16).collect();
        assert_ne!(offsets, sequential);
    }
}
