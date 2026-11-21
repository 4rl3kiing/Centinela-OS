//! Per-task address spaces with a supervisor-only kernel half.
//!
//! Each task receives its own PML4. The upper half (entries 256..512) is
//! copied from the kernel template with the USER bit **stripped** at the top
//! level: because x86 grants user access only when every level allows it, a
//! stray USER bit anywhere below (from the bootloader or from corruption) can
//! never expose kernel memory to Ring 3. The lower half starts empty and only
//! ever contains pages explicitly mapped for that task, so tasks cannot see
//! each other's memory.
//!
//! Destruction frees only lower-half page tables and the frames they map;
//! kernel-half tables are shared and are never touched.

use super::vmm::{
    HUGE_PAGE, MutationBackendError, PHYSICAL_ADDRESS_MASK, PRESENT, PageTableMutationMemory,
    PhysAddr, USER,
};

/// First PML4 slot of the canonical upper (kernel) half.
pub const KERNEL_HALF_FIRST_INDEX: u16 = 256;
const ENTRIES_PER_TABLE: u16 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceError {
    Backend(MutationBackendError),
    /// A user-half entry claimed a huge page; this kernel never creates one,
    /// so the hierarchy is treated as corrupted and nothing is freed.
    HugePageInUserHalf,
    /// A user-half entry pointed at an invalid physical address.
    CorruptEntry,
}

impl From<MutationBackendError> for AddressSpaceError {
    fn from(error: MutationBackendError) -> Self {
        Self::Backend(error)
    }
}

/// Result of cloning the kernel half into a new root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelHalfReport {
    pub entries_shared: u16,
    /// USER bits removed from kernel-half PML4 entries (should be zero; a
    /// nonzero value means the template tried to expose kernel memory).
    pub user_bits_stripped: u16,
}

/// Creates a task root: supervisor-only kernel half, empty user half.
pub fn create_user_address_space<M: PageTableMutationMemory>(
    memory: &mut M,
    kernel_root: PhysAddr,
) -> Result<(PhysAddr, KernelHalfReport), AddressSpaceError> {
    let root = memory.allocate_zeroed_table_frame()?;
    let mut report = KernelHalfReport {
        entries_shared: 0,
        user_bits_stripped: 0,
    };
    for index in KERNEL_HALF_FIRST_INDEX..ENTRIES_PER_TABLE {
        let copied = memory.read_entry(kernel_root, index).and_then(|entry| {
            if entry & PRESENT == 0 {
                return Ok(None);
            }
            memory.write_entry(root, index, entry & !USER)?;
            Ok(Some(entry & USER != 0))
        });
        match copied {
            Ok(Some(stripped)) => {
                report.entries_shared += 1;
                report.user_bits_stripped += u16::from(stripped);
            }
            Ok(None) => {}
            Err(error) => {
                // The new root was never installed, so it can be released.
                let _ = memory.release_table_frame(root);
                return Err(error.into());
            }
        }
    }
    Ok((root, report))
}

/// Frees every lower-half table and mapped frame, then the root itself.
///
/// The caller must have switched CR3 away from `root` (which also flushes its
/// non-global translations) before calling this function. Kernel-half entries
/// are left untouched because their tables are shared by every task.
pub fn destroy_user_address_space<M: PageTableMutationMemory>(
    memory: &mut M,
    root: PhysAddr,
) -> Result<(), AddressSpaceError> {
    for index in 0..KERNEL_HALF_FIRST_INDEX {
        let entry = memory.read_entry(root, index)?;
        if entry & PRESENT == 0 {
            continue;
        }
        let child = table_address(entry)?;
        free_subtree(memory, child, 3)?;
        memory.write_entry(root, index, 0)?;
    }
    memory.release_table_frame(root)?;
    Ok(())
}

fn table_address(entry: u64) -> Result<PhysAddr, AddressSpaceError> {
    if entry & HUGE_PAGE != 0 {
        return Err(AddressSpaceError::HugePageInUserHalf);
    }
    let address = entry & PHYSICAL_ADDRESS_MASK;
    if address == 0 {
        return Err(AddressSpaceError::CorruptEntry);
    }
    PhysAddr::new(address).map_err(|_| AddressSpaceError::CorruptEntry)
}

/// `level` 3 = PDPT, 2 = PD, 1 = PT (whose entries map data frames).
fn free_subtree<M: PageTableMutationMemory>(
    memory: &mut M,
    table: PhysAddr,
    level: u8,
) -> Result<(), AddressSpaceError> {
    for index in 0..ENTRIES_PER_TABLE {
        let entry = memory.read_entry(table, index)?;
        if entry & PRESENT == 0 {
            continue;
        }
        if level == 1 {
            let frame = PhysAddr::new(entry & PHYSICAL_ADDRESS_MASK)
                .map_err(|_| AddressSpaceError::CorruptEntry)?;
            memory.release_table_frame(frame)?;
        } else {
            free_subtree(memory, table_address(entry)?, level - 1)?;
        }
    }
    memory.release_table_frame(table)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AddressSpaceError, create_user_address_space, destroy_user_address_space};
    use crate::memory::vmm::{
        HUGE_PAGE, MutationBackendError, PRESENT, PageMapping, PageTableMapper,
        PageTableMutationMemory, PhysAddr, USER, VirtAddr, WRITABLE,
    };
    use centinela_security::permissions::PagePermissions;
    use std::collections::{BTreeMap, BTreeSet};

    /// Sparse page-table memory with a bump allocator and ownership tracking.
    struct MockMemory {
        entries: BTreeMap<(u64, u16), u64>,
        next_frame: u64,
        live_frames: BTreeSet<u64>,
    }

    impl MockMemory {
        fn new() -> Self {
            Self {
                entries: BTreeMap::new(),
                next_frame: 0x10_0000,
                live_frames: BTreeSet::new(),
            }
        }
        fn allocate_data_frame(&mut self) -> u64 {
            self.allocate_zeroed_table_frame().unwrap().get()
        }
    }

    // SAFETY: Entries live in a private map; frames are unique bump addresses.
    unsafe impl PageTableMutationMemory for MockMemory {
        fn allocate_zeroed_table_frame(&mut self) -> Result<PhysAddr, MutationBackendError> {
            let frame = self.next_frame;
            self.next_frame += 0x1000;
            self.live_frames.insert(frame);
            Ok(PhysAddr::new(frame).unwrap())
        }
        fn release_table_frame(&mut self, frame: PhysAddr) -> Result<(), MutationBackendError> {
            if !self.live_frames.remove(&frame.get()) {
                return Err(MutationBackendError::ReleaseFailed);
            }
            self.entries.retain(|(table, _), _| *table != frame.get());
            Ok(())
        }
        fn read_entry(&self, table: PhysAddr, index: u16) -> Result<u64, MutationBackendError> {
            Ok(*self.entries.get(&(table.get(), index)).unwrap_or(&0))
        }
        fn write_entry(
            &mut self,
            table: PhysAddr,
            index: u16,
            value: u64,
        ) -> Result<(), MutationBackendError> {
            self.entries.insert((table.get(), index), value);
            Ok(())
        }
        fn invalidate_page(&mut self, _: VirtAddr) -> Result<(), MutationBackendError> {
            Ok(())
        }
    }

    const KERNEL_ROOT: u64 = 0x1000;

    fn kernel_template(memory: &mut MockMemory) {
        let root = PhysAddr::new(KERNEL_ROOT).unwrap();
        memory
            .write_entry(root, 0, 0x5000 | PRESENT | WRITABLE | USER)
            .unwrap(); // bootloader lower half
        memory
            .write_entry(root, 256, 0x2000 | PRESENT | WRITABLE)
            .unwrap(); // HHDM
        memory
            .write_entry(root, 511, 0x3000 | PRESENT | WRITABLE | USER)
            .unwrap(); // hostile USER bit
    }

    #[test]
    fn task_root_shares_kernel_half_supervisor_only_and_starts_empty() {
        let mut memory = MockMemory::new();
        kernel_template(&mut memory);
        let (root, report) =
            create_user_address_space(&mut memory, PhysAddr::new(KERNEL_ROOT).unwrap()).unwrap();

        assert_eq!(report.entries_shared, 2);
        assert_eq!(report.user_bits_stripped, 1);
        assert_eq!(
            memory.read_entry(root, 0),
            Ok(0),
            "user half must start empty"
        );
        assert_eq!(
            memory.read_entry(root, 256),
            Ok(0x2000 | PRESENT | WRITABLE)
        );
        assert_eq!(
            memory.read_entry(root, 511).unwrap() & USER,
            0,
            "kernel half must never be user-accessible"
        );
    }

    #[test]
    fn destroy_frees_user_frames_and_tables_but_not_kernel_half() {
        let mut memory = MockMemory::new();
        kernel_template(&mut memory);
        let before = memory.live_frames.clone();
        let (root, _) =
            create_user_address_space(&mut memory, PhysAddr::new(KERNEL_ROOT).unwrap()).unwrap();

        let code = memory.allocate_data_frame();
        let stack = memory.allocate_data_frame();
        let mut mapper = PageTableMapper::new(&mut memory, root);
        let rx = PagePermissions::new(true, false, true, true).unwrap();
        let rw = PagePermissions::new(true, true, false, true).unwrap();
        mapper
            .map_4k(PageMapping::new(0x40_0000, code, rx).unwrap())
            .unwrap();
        mapper
            .map_4k(PageMapping::new(0x7fff_0000_0000 - 0x1000, stack, rw).unwrap())
            .unwrap();

        destroy_user_address_space(&mut memory, root).unwrap();
        assert_eq!(
            memory.live_frames, before,
            "every task frame must be reclaimed"
        );
        let kernel = PhysAddr::new(KERNEL_ROOT).unwrap();
        assert_eq!(
            memory.read_entry(kernel, 256),
            Ok(0x2000 | PRESENT | WRITABLE)
        );
    }

    #[test]
    fn destroy_refuses_corrupted_huge_page_in_user_half() {
        let mut memory = MockMemory::new();
        let (root, _) =
            create_user_address_space(&mut memory, PhysAddr::new(KERNEL_ROOT).unwrap()).unwrap();
        memory
            .write_entry(root, 1, 0x40_0000 | PRESENT | HUGE_PAGE)
            .unwrap();
        assert_eq!(
            destroy_user_address_space(&mut memory, root),
            Err(AddressSpaceError::HugePageInUserHalf)
        );
    }
}
