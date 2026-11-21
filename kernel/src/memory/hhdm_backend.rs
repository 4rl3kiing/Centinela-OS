//! Page-table and frame access through Limine's higher-half direct map.
//!
//! The kernel reads and writes task memory only through the HHDM alias of the
//! physical frame, never through the task's own virtual addresses. That keeps
//! SMAP permanently armed (no STAC windows) and makes the kernel immune to a
//! task remapping its buffers while the kernel is using them.

use super::pmm::Pmm;
use super::usercopy::PhysicalMemory;
use super::vmm::{
    HhdmOffset, MutationBackendError, PAGE_SIZE, PageTableMemory, PageTableMutationMemory,
    PhysAddr, VirtAddr, WalkError,
};

/// Kernel-owned page tables and frames, accessed through the HHDM.
pub struct HhdmFrameMemory<'p, 'b> {
    hhdm: HhdmOffset,
    pmm: &'p mut Pmm<'b>,
}

impl<'p, 'b> HhdmFrameMemory<'p, 'b> {
    /// # Safety
    /// The HHDM must map every frame the PMM can return and every page-table
    /// frame passed to this backend, writable and for the backend's lifetime.
    /// Access must be serialized (single CPU, interrupts disabled).
    pub unsafe fn new(hhdm: HhdmOffset, pmm: &'p mut Pmm<'b>) -> Self {
        Self { hhdm, pmm }
    }

    fn alias(&self, physical: u64) -> Result<*mut u8, MutationBackendError> {
        let frame = PhysAddr::new(physical & !(PAGE_SIZE - 1))
            .map_err(|_| MutationBackendError::ReadFailed)?;
        let base = self
            .hhdm
            .physical_to_virtual(frame)
            .map_err(|_| MutationBackendError::ReadFailed)?;
        Ok((base.get() + (physical & (PAGE_SIZE - 1))) as *mut u8)
    }

    /// Copies `bytes` to the start of a frame owned by the caller.
    ///
    /// # Safety
    /// `frame` must be exclusively owned by the caller and not yet reachable
    /// by any other address space.
    pub unsafe fn write_frame(
        &mut self,
        frame: PhysAddr,
        bytes: &[u8],
    ) -> Result<(), MutationBackendError> {
        // SAFETY: Same contract as `write_frame_at`.
        unsafe { self.write_frame_at(frame, 0, bytes) }
    }

    /// Copies `bytes` into a caller-owned frame starting at `offset`.
    ///
    /// # Safety
    /// Same as [`Self::write_frame`].
    pub unsafe fn write_frame_at(
        &mut self,
        frame: PhysAddr,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), MutationBackendError> {
        match offset.checked_add(bytes.len()) {
            Some(end) if end <= PAGE_SIZE as usize => {}
            _ => return Err(MutationBackendError::WriteFailed),
        }
        let destination = self.alias(frame.get() + offset as u64)?;
        // SAFETY: Exclusive frame, HHDM-mapped per the constructor contract.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len()) };
        Ok(())
    }

    pub fn free_frames(&self) -> u64 {
        self.pmm.free_frames()
    }
}

// SAFETY: Frames come from the PMM (exclusive) and are zeroed before return;
// entries are accessed with aligned volatile 64-bit operations through the
// HHDM; invalidation is local INVLPG, valid because the kernel is single-CPU
// and every address space runs only on that CPU.
unsafe impl PageTableMutationMemory for HhdmFrameMemory<'_, '_> {
    fn allocate_zeroed_table_frame(&mut self) -> Result<PhysAddr, MutationBackendError> {
        let physical = self
            .pmm
            .allocate_frame()
            .ok_or(MutationBackendError::AllocationFailed)?;
        let frame = PhysAddr::new(physical).map_err(|_| MutationBackendError::AllocationFailed)?;
        let Ok(alias) = self.alias(physical) else {
            let _ = self.pmm.free_frame(physical);
            return Err(MutationBackendError::AllocationFailed);
        };
        // SAFETY: The PMM transferred exclusive ownership; the HHDM maps it.
        unsafe { core::ptr::write_bytes(alias, 0, PAGE_SIZE as usize) };
        Ok(frame)
    }

    fn release_table_frame(&mut self, frame: PhysAddr) -> Result<(), MutationBackendError> {
        self.pmm
            .free_frame(frame.get())
            .map_err(|_| MutationBackendError::ReleaseFailed)
    }

    fn read_entry(&self, table: PhysAddr, index: u16) -> Result<u64, MutationBackendError> {
        if index >= 512 {
            return Err(MutationBackendError::ReadFailed);
        }
        let entry = self.alias(table.get() + u64::from(index) * 8)?;
        // SAFETY: Aligned entry inside an HHDM-mapped page-table frame.
        Ok(unsafe { core::ptr::read_volatile(entry.cast::<u64>()) })
    }

    fn write_entry(
        &mut self,
        table: PhysAddr,
        index: u16,
        value: u64,
    ) -> Result<(), MutationBackendError> {
        if index >= 512 {
            return Err(MutationBackendError::WriteFailed);
        }
        let entry = self.alias(table.get() + u64::from(index) * 8)?;
        // SAFETY: Aligned entry inside an HHDM-mapped page-table frame owned
        // by the caller's mapper (exclusive access via &mut self).
        unsafe { core::ptr::write_volatile(entry.cast::<u64>(), value) };
        Ok(())
    }

    fn invalidate_page(&mut self, virtual_address: VirtAddr) -> Result<(), MutationBackendError> {
        // SAFETY: CPL 0; single CPU, so local invalidation is complete.
        unsafe { centinela_hal::cpu::invalidate_page_local(virtual_address.get()) }
            .map_err(|_| MutationBackendError::TlbInvalidationFailed)
    }
}

// SAFETY: Reads only HHDM aliases of frames mapped by validated user pages.
unsafe impl PhysicalMemory for HhdmFrameMemory<'_, '_> {
    fn read_physical(&self, physical: u64, out: &mut [u8]) -> bool {
        let Ok(source) = self.alias(physical) else {
            return false;
        };
        // SAFETY: The caller (usercopy) never crosses a page boundary, and
        // every physical page reachable from a task table is HHDM-mapped.
        unsafe { core::ptr::copy_nonoverlapping(source, out.as_mut_ptr(), out.len()) };
        true
    }
}

/// Read-only walker adapter over kernel-owned (task) page tables.
pub struct OwnedTableReader<'a, M: PageTableMutationMemory>(pub &'a M);

// SAFETY: Delegates to PageTableMutationMemory::read_entry, whose contract
// already guarantees valid, aligned access to page-table frames.
unsafe impl<M: PageTableMutationMemory> PageTableMemory for OwnedTableReader<'_, M> {
    fn read_entry(&self, table: PhysAddr, index: u16) -> Result<u64, WalkError> {
        self.0
            .read_entry(table, index)
            .map_err(|_| WalkError::MemoryReadFailed)
    }
}

/// Read-only HHDM view of page tables and frames (no allocator access).
#[derive(Clone, Copy)]
pub struct HhdmReader {
    hhdm: HhdmOffset,
}

impl HhdmReader {
    /// # Safety
    /// Every page-table frame walked and every frame read through this reader
    /// must be mapped by the HHDM for the reader's lifetime.
    pub const unsafe fn new(hhdm: HhdmOffset) -> Self {
        Self { hhdm }
    }

    fn alias(&self, physical: u64) -> Option<*const u8> {
        let frame = PhysAddr::new(physical & !(PAGE_SIZE - 1)).ok()?;
        let base = self.hhdm.physical_to_virtual(frame).ok()?;
        Some((base.get() + (physical & (PAGE_SIZE - 1))) as *const u8)
    }
}

// SAFETY: Aligned volatile reads of HHDM-mapped table frames (constructor contract).
unsafe impl PageTableMemory for HhdmReader {
    fn read_entry(&self, table: PhysAddr, index: u16) -> Result<u64, WalkError> {
        if index >= 512 {
            return Err(WalkError::MemoryReadFailed);
        }
        let entry = self
            .alias(table.get() + u64::from(index) * 8)
            .ok_or(WalkError::AddressOverflow)?;
        // SAFETY: Aligned entry inside an HHDM-mapped page-table frame.
        Ok(unsafe { core::ptr::read_volatile(entry.cast::<u64>()) })
    }
}

// SAFETY: Reads stay inside one HHDM-mapped page (usercopy splits at pages).
unsafe impl PhysicalMemory for HhdmReader {
    fn read_physical(&self, physical: u64, out: &mut [u8]) -> bool {
        let in_page = (PAGE_SIZE - (physical & (PAGE_SIZE - 1))) as usize;
        if out.len() > in_page {
            return false;
        }
        let Some(source) = self.alias(physical) else {
            return false;
        };
        // SAFETY: Within one HHDM-mapped page per the check above.
        unsafe { core::ptr::copy_nonoverlapping(source, out.as_mut_ptr(), out.len()) };
        true
    }
}
