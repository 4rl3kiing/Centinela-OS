//! x86_64 virtual-address and page-table entry primitives.
//!
//! This module deliberately does not install a new CR3 or mutate Limine's
//! active page tables yet. It provides checked address/index/entry encoding
//! primitives for the VMM implementation milestone.

use super::pmm::{LimineMemoryMapEntry, LimineMemoryMapResponse};
use centinela_security::permissions::PagePermissions;

pub const PAGE_SIZE: u64 = 4096;
const ADDRESS_BITS: u32 = 48;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const CR3_ADDRESS_MASK: u64 = PHYSICAL_ADDRESS_MASK;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const NO_EXECUTE: u64 = 1 << 63;
const RESERVED_HIGH_BITS: u64 = 0x7ff0_0000_0000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtAddr(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysAddr(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HhdmOffset(u64);

/// Snapshot of the bootloader's active paging root and its HHDM alias.
/// This records the existing address space; it does not own or modify it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootPagingInfo {
    root_physical: PhysAddr,
    root_virtual: VirtAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableIndices {
    pub pml4: u16,
    pub pdpt: u16,
    pub pd: u16,
    pub pt: u16,
    pub offset: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableEntry(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    NonCanonical,
    Unaligned,
    PhysicalAddressOutOfRange,
    HhdmOverflow,
    InvalidPageTableRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryError {
    Address(AddressError),
    WriteExecuteViolation,
    UnreadablePageUnsupported,
}

impl VirtAddr {
    pub const fn new(value: u64) -> Result<Self, AddressError> {
        if is_canonical(value) {
            Ok(Self(value))
        } else {
            Err(AddressError::NonCanonical)
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn page_table_indices(self) -> PageTableIndices {
        PageTableIndices {
            pml4: ((self.0 >> 39) & 0x1ff) as u16,
            pdpt: ((self.0 >> 30) & 0x1ff) as u16,
            pd: ((self.0 >> 21) & 0x1ff) as u16,
            pt: ((self.0 >> 12) & 0x1ff) as u16,
            offset: (self.0 & 0xfff) as u16,
        }
    }
}

impl PhysAddr {
    pub const fn new(value: u64) -> Result<Self, AddressError> {
        if value & (PAGE_SIZE - 1) != 0 {
            return Err(AddressError::Unaligned);
        }
        if value & !PHYSICAL_ADDRESS_MASK != 0 {
            return Err(AddressError::PhysicalAddressOutOfRange);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl HhdmOffset {
    pub const fn new(offset: u64) -> Result<Self, AddressError> {
        if is_canonical(offset) {
            Ok(Self(offset))
        } else {
            Err(AddressError::NonCanonical)
        }
    }

    pub const fn physical_to_virtual(self, physical: PhysAddr) -> Result<VirtAddr, AddressError> {
        match self.0.checked_add(physical.0) {
            Some(value) if is_canonical(value) => Ok(VirtAddr(value)),
            Some(_) => Err(AddressError::NonCanonical),
            None => Err(AddressError::HhdmOverflow),
        }
    }
}

impl BootPagingInfo {
    /// Captures CR3 and proves that its root address has a canonical HHDM alias.
    ///
    /// CR3's low PCID/cache-control bits are discarded. The caller must still
    /// ensure the HHDM mapping is present before dereferencing root_virtual.
    pub const fn new(cr3: u64, hhdm: HhdmOffset) -> Result<Self, AddressError> {
        let root = cr3 & CR3_ADDRESS_MASK;
        if root == 0 {
            return Err(AddressError::InvalidPageTableRoot);
        }
        let root_physical = match PhysAddr::new(root) {
            Ok(address) => address,
            Err(error) => return Err(error),
        };
        let root_virtual = match hhdm.physical_to_virtual(root_physical) {
            Ok(address) => address,
            Err(error) => return Err(error),
        };
        Ok(Self {
            root_physical,
            root_virtual,
        })
    }

    pub const fn root_physical(self) -> PhysAddr {
        self.root_physical
    }

    pub const fn root_virtual(self) -> VirtAddr {
        self.root_virtual
    }
}

impl PageTableEntry {
    pub const fn new(physical: PhysAddr, permissions: PagePermissions) -> Result<Self, EntryError> {
        if !permissions.readable {
            return Err(EntryError::UnreadablePageUnsupported);
        }
        if permissions.writable && permissions.executable {
            return Err(EntryError::WriteExecuteViolation);
        }

        let mut raw = physical.0 | PRESENT;
        if permissions.writable {
            raw |= WRITABLE;
        }
        if permissions.user_accessible {
            raw |= USER;
        }
        if !permissions.executable {
            raw |= NO_EXECUTE;
        }
        Ok(Self(raw))
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn is_present(self) -> bool {
        self.0 & PRESENT != 0
    }

    pub const fn is_writable(self) -> bool {
        self.0 & WRITABLE != 0
    }

    pub const fn is_user_accessible(self) -> bool {
        self.0 & USER != 0
    }

    pub const fn is_executable(self) -> bool {
        self.0 & NO_EXECUTE == 0
    }

    pub const fn physical_address(self) -> u64 {
        self.0 & PHYSICAL_ADDRESS_MASK
    }

    /// Encodes a non-leaf page-table pointer.
    ///
    /// Parent entries are writable so that leaf-level permissions can decide
    /// whether a mapping is writable. USER is propagated only for an address
    /// subtree that may contain user mappings; the leaf must still grant USER.
    /// NX is intentionally left clear here so the leaf controls execution.
    pub const fn new_table(
        physical: PhysAddr,
        user_accessible: bool,
    ) -> Result<Self, EntryError> {
        let mut raw = physical.0 | PRESENT | WRITABLE;
        if user_accessible {
            raw |= USER;
        }
        Ok(Self(raw))
    }

    pub const fn is_user_accessible(self) -> bool {
        self.0 & USER != 0
    }
}

const fn is_canonical(value: u64) -> bool {
    let sign = (value >> (ADDRESS_BITS - 1)) & 1;
    let upper = value >> ADDRESS_BITS;
    if sign == 0 {
        upper == 0
    } else {
        upper == 0xffff
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddressError, BootPagingInfo, EntryError, HhdmOffset, PAGE_SIZE, PageTableEntry, PhysAddr,
        VirtAddr,
    };
    use centinela_security::permissions::PagePermissions;

    #[test]
    fn validates_four_level_canonical_addresses() {
        assert!(VirtAddr::new(0x0000_7fff_ffff_ffff).is_ok());
        assert!(VirtAddr::new(0xffff_8000_0000_0000).is_ok());
        assert_eq!(
            VirtAddr::new(0x0000_8000_0000_0000),
            Err(AddressError::NonCanonical)
        );
        assert_eq!(
            VirtAddr::new(0xffff_7fff_ffff_ffff),
            Err(AddressError::NonCanonical)
        );
    }

    #[test]
    fn extracts_four_level_page_table_indices() {
        let address = VirtAddr::new(0xffff_8123_4567_89ab).expect("canonical address");
        let indices = address.page_table_indices();
        assert_eq!(indices.pml4, 0x102);
        assert_eq!(indices.pdpt, 0x08d);
        assert_eq!(indices.pd, 0x02b);
        assert_eq!(indices.pt, 0x078);
        assert_eq!(indices.offset, 0x9ab);
    }

    #[test]
    fn rejects_unaligned_and_out_of_range_physical_addresses() {
        assert_eq!(PhysAddr::new(1), Err(AddressError::Unaligned));
        assert_eq!(
            PhysAddr::new(1 << 52),
            Err(AddressError::PhysicalAddressOutOfRange)
        );
        assert_eq!(PhysAddr::new(PAGE_SIZE), Ok(PhysAddr(PAGE_SIZE)));
    }

    #[test]
    fn converts_physical_addresses_through_a_checked_hhdm_offset() {
        let hhdm = HhdmOffset::new(0xffff_8000_0000_0000).expect("canonical HHDM");
        let physical = PhysAddr::new(0x20_0000).expect("aligned physical address");
        assert_eq!(
            hhdm.physical_to_virtual(physical),
            Ok(VirtAddr(0xffff_8000_0020_0000))
        );
    }

    #[test]
    fn captures_cr3_root_and_discards_low_control_bits() {
        let hhdm = HhdmOffset::new(0xffff_8000_0000_0000).expect("canonical HHDM");
        let info = BootPagingInfo::new(0x1234_5007, hhdm).expect("valid CR3 root");
        assert_eq!(info.root_physical().get(), 0x1234_5000);
        assert_eq!(info.root_virtual().get(), 0xffff_8000_1234_5000);
        assert_eq!(
            BootPagingInfo::new(0, hhdm),
            Err(AddressError::InvalidPageTableRoot)
        );
    }

    #[test]
    fn encodes_nx_and_writable_permissions_without_wx() {
        let physical = PhysAddr::new(0x4000).expect("aligned physical address");
        let data = PageTableEntry::new(
            physical,
            PagePermissions::new(true, true, false, false).expect("RW/NX is valid"),
        )
        .expect("data page entry");
        assert!(data.is_present());
        assert!(data.is_writable());
        assert!(!data.is_executable());
        assert_eq!(data.physical_address(), 0x4000);

        let code = PageTableEntry::new(
            physical,
            PagePermissions::new(true, false, true, false).expect("RX is valid"),
        )
        .expect("code page entry");
        assert!(!code.is_writable());
        assert!(code.is_executable());
    }

    #[test]
    fn encodes_non_leaf_table_pointers_with_explicit_user_propagation() {
        let physical = PhysAddr::new(0x8000).expect("aligned table frame");
        let supervisor = PageTableEntry::new_table(physical, false).unwrap();
        assert!(supervisor.is_present());
        assert!(supervisor.is_writable());
        assert!(!supervisor.is_user_accessible());
        assert!(supervisor.is_executable());
        assert_eq!(supervisor.physical_address(), 0x8000);

        let user = PageTableEntry::new_table(physical, true).unwrap();
        assert!(user.is_user_accessible());
        assert!(user.is_writable());
        assert!(user.is_executable());
    }

    #[test]
    fn rejects_wx_and_unreadable_page_entries() {
        let physical = PhysAddr::new(0x4000).expect("aligned physical address");
        let wx = PagePermissions {
            readable: true,
            writable: true,
            executable: true,
            user_accessible: false,
        };
        assert_eq!(
            PageTableEntry::new(physical, wx),
            Err(EntryError::WriteExecuteViolation)
        );

        let unreadable = PagePermissions {
            readable: false,
            writable: false,
            executable: false,
            user_accessible: false,
        };
        assert_eq!(
            PageTableEntry::new(physical, unreadable),
            Err(EntryError::UnreadablePageUnsupported)
        );
    }
}

#[cfg(kani)]
mod verification {
    use super::{PAGE_SIZE, PageTableEntry, PhysAddr, VirtAddr, is_canonical};
    use centinela_security::permissions::PagePermissions;

    #[kani::proof]
    fn virtual_address_validation_matches_four_level_canonicality() {
        let address: u64 = kani::any();
        assert_eq!(VirtAddr::new(address).is_ok(), is_canonical(address));
    }

    #[kani::proof]
    fn page_table_entries_reject_writable_executable_combinations() {
        let writable: bool = kani::any();
        let executable: bool = kani::any();
        let physical = PhysAddr::new(PAGE_SIZE).expect("page-aligned physical address");
        let permissions = PagePermissions {
            readable: true,
            writable,
            executable,
            user_accessible: false,
        };

        let entry = PageTableEntry::new(physical, permissions);
        assert_eq!(entry.is_ok(), !(writable && executable));
    }
}

const HUGE_PAGE: u64 = 1 << 7;
const PAGE_2M_MASK: u64 = 0x000f_ffff_ffe0_0000;
const PAGE_1G_MASK: u64 = 0x000f_ffff_c000_0000;

/// Errors produced while reading a four-level page-table hierarchy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkError {
    MemoryReadFailed,
    NotMapped,
    InvalidHugePage,
    InvalidEntry,
    InvalidPhysicalAddress,
    AddressOverflow,
    InvalidMemoryMap,
    PhysicalRegionNotMapped,
}

/// Result of a read-only page-table walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Translation {
    /// Exact translated physical address, including the page offset.
    pub physical_address: u64,
    /// Size of the leaf mapping: 4 KiB, 2 MiB, or 1 GiB.
    pub page_size: u64,
    /// Effective permissions after combining all paging levels.
    pub writable: bool,
    pub user_accessible: bool,
    pub executable: bool,
}

/// Implementors must only read valid, mapped page-table memory.
///
/// # Safety
/// For every aligned physical table address supplied by the walker,
/// read_entry must either safely return the indexed 64-bit entry or return
/// an error. It must never access arbitrary or unmapped physical memory.
pub unsafe trait PageTableMemory {
    fn read_entry(&self, table: PhysAddr, index: u16) -> Result<u64, WalkError>;
}

/// Read-only page-table memory accessor through the Limine HHDM.
///
/// Constructing this value does not prove that every page-table frame is
/// mapped by the HHDM. Its PageTableMemory implementation is therefore
/// unsafe and must only be used when that mapping property is established.
const MAX_HHDM_MAP_ENTRIES: u64 = 4096;
const MEMMAP_BOOTLOADER_RECLAIMABLE: u64 = 5;

/// Read-only page-table accessor through Limine's HHDM.
/// Every table frame must belong to Limine's bootloader-reclaimable region.
#[derive(Clone, Copy)]
pub struct HhdmPageTableMemory {
    offset: HhdmOffset,
    memory_map: *const LimineMemoryMapResponse,
}

impl HhdmPageTableMemory {
    /// # Safety
    /// The response, pointer array and entries must remain valid and immutable
    /// for this reader's lifetime. They must be the original Limine revision-5
    /// memory map, and the HHDM mapping must remain active.
    pub unsafe fn new(
        offset: HhdmOffset,
        memory_map: *const LimineMemoryMapResponse,
    ) -> Result<Self, WalkError> {
        if memory_map.is_null() {
            return Err(WalkError::InvalidMemoryMap);
        }
        // SAFETY: Required by the constructor contract.
        let response = unsafe { &*memory_map };
        if response.revision != 0
            || response.entry_count == 0
            || response.entry_count > MAX_HHDM_MAP_ENTRIES
            || response.entries.is_null()
        {
            return Err(WalkError::InvalidMemoryMap);
        }
        Ok(Self { offset, memory_map })
    }

    fn table_frame_is_mapped(&self, table: PhysAddr) -> Result<bool, WalkError> {
        // SAFETY: The constructor contract keeps this response valid.
        let response = unsafe { &*self.memory_map };
        let table_end = table
            .get()
            .checked_add(PAGE_SIZE)
            .ok_or(WalkError::AddressOverflow)?;
        for index in 0..response.entry_count as usize {
            // SAFETY: The constructor contract covers the complete pointer array.
            let pointer = unsafe { response.entries.add(index).read() };
            if pointer.is_null() {
                return Err(WalkError::InvalidMemoryMap);
            }
            // SAFETY: The constructor contract covers every entry pointer.
            let entry: &LimineMemoryMapEntry = unsafe { &*pointer };
            if entry.entry_type != MEMMAP_BOOTLOADER_RECLAIMABLE {
                continue;
            }
            let region_end = entry
                .base
                .checked_add(entry.length)
                .ok_or(WalkError::InvalidMemoryMap)?;
            // Limine guarantees bootloader-reclaimable regions are 4 KiB aligned.
            if entry.base <= table.get() && table_end <= region_end {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// SAFETY: Before each read, the complete page-table frame is verified to be
// in Limine bootloader-reclaimable memory, which base revision 5 guarantees is HHDM-mapped.
unsafe impl PageTableMemory for HhdmPageTableMemory {
    fn read_entry(&self, table: PhysAddr, index: u16) -> Result<u64, WalkError> {
        if index >= 512 {
            return Err(WalkError::MemoryReadFailed);
        }
        if !self.table_frame_is_mapped(table)? {
            return Err(WalkError::PhysicalRegionNotMapped);
        }
        let virtual_table = self
            .offset
            .physical_to_virtual(table)
            .map_err(|_| WalkError::AddressOverflow)?;
        let entry_address = virtual_table
            .get()
            .checked_add(u64::from(index) * 8)
            .ok_or(WalkError::AddressOverflow)?;
        VirtAddr::new(entry_address).map_err(|_| WalkError::AddressOverflow)?;
        // SAFETY: The full frame was checked against the bootloader-reclaimable memory map.
        Ok(unsafe { core::ptr::read_volatile(entry_address as *const u64) })
    }
}
/// Walks the active four-level paging hierarchy without modifying it.
pub struct PageTableWalker<'a, M: PageTableMemory> {
    memory: &'a M,
    root: PhysAddr,
}

impl<'a, M: PageTableMemory> PageTableWalker<'a, M> {
    pub const fn new(memory: &'a M, root: PhysAddr) -> Self {
        Self { memory, root }
    }

    pub fn translate(&self, virtual_address: VirtAddr) -> Result<Translation, WalkError> {
        if self.root.get() == 0 {
            return Err(WalkError::InvalidPhysicalAddress);
        }
        let indices = virtual_address.page_table_indices();
        let mut table = self.root;
        let mut writable = true;
        let mut user_accessible = true;
        let mut executable = true;

        for (level, index) in [
            (4_u8, indices.pml4),
            (3_u8, indices.pdpt),
            (2_u8, indices.pd),
            (1_u8, indices.pt),
        ] {
            let raw = self.memory.read_entry(table, index)?;
            if raw & PRESENT == 0 {
                return Err(WalkError::NotMapped);
            }
            if raw & RESERVED_HIGH_BITS != 0 {
                return Err(WalkError::InvalidEntry);
            }

            writable &= raw & WRITABLE != 0;
            user_accessible &= raw & USER != 0;
            executable &= raw & NO_EXECUTE == 0;

            let huge = raw & HUGE_PAGE != 0;
            if huge && level == 4 {
                return Err(WalkError::InvalidHugePage);
            }
            if huge && (level == 3 || level == 2) {
                let (page_size, base_mask, offset_mask) = if level == 3 {
                    (1_u64 << 30, PAGE_1G_MASK, (1_u64 << 30) - 1)
                } else {
                    (1_u64 << 21, PAGE_2M_MASK, (1_u64 << 21) - 1)
                };
                let reserved_alignment_bits = (page_size - 1) & !0x1fff;
                if raw & reserved_alignment_bits != 0 {
                    return Err(WalkError::InvalidHugePage);
                }
                let base = raw & base_mask;
                let offset = virtual_address.get() & offset_mask;
                return Ok(Translation {
                    physical_address: base | offset,
                    page_size,
                    writable,
                    user_accessible,
                    executable,
                });
            }

            if level == 1 {
                let base = raw & PHYSICAL_ADDRESS_MASK;
                return Ok(Translation {
                    physical_address: base | u64::from(indices.offset),
                    page_size: PAGE_SIZE,
                    writable,
                    user_accessible,
                    executable,
                });
            }

            let next = raw & PHYSICAL_ADDRESS_MASK;
            if next == 0 {
                return Err(WalkError::InvalidPhysicalAddress);
            }
            table = PhysAddr::new(next).map_err(|_| WalkError::InvalidPhysicalAddress)?;
        }

        Err(WalkError::NotMapped)
    }
}

#[cfg(test)]
mod walker_tests {
    use super::{
        HUGE_PAGE, NO_EXECUTE, PAGE_SIZE, PRESENT, PageTableMemory, PageTableWalker, PhysAddr,
        Translation, USER, VirtAddr, WRITABLE, WalkError,
    };

    #[test]
    fn hhdm_reader_only_accepts_bootloader_reclaimable_frames() {
        use super::super::pmm::{LimineMemoryMapEntry, LimineMemoryMapResponse};
        use super::{HhdmOffset, HhdmPageTableMemory, WalkError};

        let reclaimable = LimineMemoryMapEntry {
            base: 0x1000,
            length: 0x4000,
            entry_type: 5,
        };
        let usable = LimineMemoryMapEntry {
            base: 0x8000,
            length: 0x4000,
            entry_type: 0,
        };
        let entries = [
            &reclaimable as *const LimineMemoryMapEntry,
            &usable as *const LimineMemoryMapEntry,
        ];
        let response = LimineMemoryMapResponse {
            revision: 0,
            entry_count: entries.len() as u64,
            entries: entries.as_ptr(),
        };
        let offset = HhdmOffset::new(0xffff_8000_0000_0000).unwrap();
        // SAFETY: The response, pointer array and entries remain valid for
        // the lifetime of this test's reader.
        let reader = unsafe { HhdmPageTableMemory::new(offset, &response) }.unwrap();

        assert_eq!(
            reader.table_frame_is_mapped(PhysAddr::new(0x1000).unwrap()),
            Ok(true)
        );
        assert_eq!(
            reader.table_frame_is_mapped(PhysAddr::new(0x4000).unwrap()),
            Ok(true)
        );
        assert_eq!(
            reader.table_frame_is_mapped(PhysAddr::new(0x8000).unwrap()),
            Ok(false)
        );
        assert_eq!(
            reader.read_entry(PhysAddr::new(0x8000).unwrap(), 0),
            Err(WalkError::PhysicalRegionNotMapped)
        );
    }

    struct MockMemory {
        entries: [(u64, u16, u64); 4],
        len: usize,
    }

    // SAFETY: The mock only returns entries from its fixed in-memory table.
    unsafe impl PageTableMemory for MockMemory {
        fn read_entry(&self, table: PhysAddr, index: u16) -> Result<u64, WalkError> {
            self.entries[..self.len]
                .iter()
                .find(|(address, entry_index, _)| *address == table.get() && *entry_index == index)
                .map(|(_, _, value)| *value)
                .ok_or(WalkError::MemoryReadFailed)
        }
    }

    #[test]
    fn walks_four_kib_mapping_and_combines_permissions() {
        let memory = MockMemory {
            entries: [
                (0x1000, 0, 0x2000 | PRESENT | WRITABLE | USER),
                (0x2000, 0, 0x3000 | PRESENT | WRITABLE | USER),
                (0x3000, 0, 0x4000 | PRESENT | WRITABLE | USER),
                (0x4000, 1, 0x9000 | PRESENT | USER | NO_EXECUTE),
            ],
            len: 4,
        };
        let root = PhysAddr::new(0x1000).expect("aligned root");
        let walker = PageTableWalker::new(&memory, root);
        let address = VirtAddr::new(0x1000).expect("canonical virtual address");
        assert_eq!(
            walker.translate(address),
            Ok(Translation {
                physical_address: 0x9000,
                page_size: PAGE_SIZE,
                writable: false,
                user_accessible: true,
                executable: false,
            })
        );
    }

    #[test]
    fn walks_two_megabyte_huge_page() {
        let memory = MockMemory {
            entries: [
                (0x1000, 0, 0x2000 | PRESENT | WRITABLE),
                (0x2000, 0, 0x3000 | PRESENT | WRITABLE),
                (0x3000, 2, 0x800000 | PRESENT | WRITABLE | HUGE_PAGE),
                (0, 0, 0),
            ],
            len: 3,
        };
        let walker = PageTableWalker::new(&memory, PhysAddr::new(0x1000).unwrap());
        let address = VirtAddr::new(0x400000).unwrap();
        assert_eq!(
            walker.translate(address).unwrap(),
            Translation {
                physical_address: 0x800000,
                page_size: 1 << 21,
                writable: true,
                user_accessible: false,
                executable: true,
            }
        );
    }

    #[test]
    fn walks_one_gibibyte_huge_page() {
        let memory = MockMemory {
            entries: [
                (0x1000, 0, 0x2000 | PRESENT),
                (0x2000, 1, 0x40000000 | PRESENT | HUGE_PAGE),
                (0, 0, 0),
                (0, 0, 0),
            ],
            len: 2,
        };
        let walker = PageTableWalker::new(&memory, PhysAddr::new(0x1000).unwrap());
        let address = VirtAddr::new((1 << 30) + 0x1234).unwrap();
        assert_eq!(
            walker.translate(address).unwrap(),
            Translation {
                physical_address: 0x40000000 + 0x1234,
                page_size: 1 << 30,
                writable: false,
                user_accessible: false,
                executable: true,
            }
        );
    }

    #[test]
    fn rejects_reserved_high_bits_in_page_table_entries() {
        let memory = MockMemory {
            entries: [
                (0x1000, 0, 0x2000 | PRESENT | (1 << 55)),
                (0, 0, 0),
                (0, 0, 0),
                (0, 0, 0),
            ],
            len: 1,
        };
        let walker = PageTableWalker::new(&memory, PhysAddr::new(0x1000).unwrap());
        assert_eq!(
            walker.translate(VirtAddr::new(0).unwrap()),
            Err(WalkError::InvalidEntry)
        );
    }

    #[test]
    fn rejects_page_size_bit_in_pml4_entry() {
        let memory = MockMemory {
            entries: [
                (0x1000, 0, 0x2000 | PRESENT | HUGE_PAGE),
                (0, 0, 0),
                (0, 0, 0),
                (0, 0, 0),
            ],
            len: 1,
        };
        let walker = PageTableWalker::new(&memory, PhysAddr::new(0x1000).unwrap());
        assert_eq!(
            walker.translate(VirtAddr::new(0).unwrap()),
            Err(WalkError::InvalidHugePage)
        );
    }

    #[test]
    fn reports_unmapped_intermediate_entries() {
        let memory = MockMemory {
            entries: [(0x1000, 0, 0), (0, 0, 0), (0, 0, 0), (0, 0, 0)],
            len: 1,
        };
        let walker = PageTableWalker::new(&memory, PhysAddr::new(0x1000).unwrap());
        assert_eq!(
            walker.translate(VirtAddr::new(0).unwrap()),
            Err(WalkError::NotMapped)
        );
    }
}
