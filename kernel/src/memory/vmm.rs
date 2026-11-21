//! x86_64 virtual-address and page-table entry primitives.
//!
//! This module deliberately does not install a new CR3 or mutate Limine's
//! active page tables yet. It provides checked address/index/entry encoding
//! primitives for the VMM implementation milestone.

use super::pmm::{LimineMemoryMapEntry, LimineMemoryMapResponse};
use centinela_security::permissions::PagePermissions;

pub const PAGE_SIZE: u64 = 4096;
const ADDRESS_BITS: u32 = 48;
pub(crate) const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const CR3_ADDRESS_MASK: u64 = PHYSICAL_ADDRESS_MASK;

pub(crate) const PRESENT: u64 = 1 << 0;
pub(crate) const WRITABLE: u64 = 1 << 1;
pub(crate) const USER: u64 = 1 << 2;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
const NO_EXECUTE: u64 = 1 << 63;
#[cfg(test)]
pub(crate) const NO_EXECUTE_FOR_TESTS: u64 = NO_EXECUTE;
/// Bits 52..62 are software-available or protection-key bits. Centinela never
/// sets them, so any value here is treated as corruption (fail closed).
const RESERVED_HIGH_BITS: u64 = 0x7ff0_0000_0000_0000;
/// First address of the canonical upper (kernel) half with 4-level paging.
pub const KERNEL_HALF_START: u64 = 0xffff_8000_0000_0000;

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
    /// The HHDM base must live in the kernel (upper) canonical half.
    HhdmNotInKernelHalf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryError {
    Address(AddressError),
    WriteExecuteViolation,
    UnreadablePageUnsupported,
}

/// A single 4 KiB mapping request validated before any page-table mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageMapping {
    virtual_address: VirtAddr,
    physical_address: PhysAddr,
    permissions: PagePermissions,
    /// Strong-uncacheable device memory (PCD|PWT), for MMIO registers.
    device: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingError {
    Address(AddressError),
    VirtualAddressUnaligned,
    UserMappingInKernelHalf,
    /// User mappings of virtual page zero are refused so that kernel NULL
    /// dereferences can never reach attacker-controlled memory.
    NullPageUserMapping,
    DeviceMappingOutsideKernelHalf,
    WriteExecuteViolation,
    UnreadablePageUnsupported,
}

impl PageMapping {
    /// Validates mapping invariants without changing page tables or ownership.
    pub const fn new(
        virtual_address: u64,
        physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<Self, MappingError> {
        if virtual_address & (PAGE_SIZE - 1) != 0 {
            return Err(MappingError::VirtualAddressUnaligned);
        }
        let virtual_address = match VirtAddr::new(virtual_address) {
            Ok(address) => address,
            Err(error) => return Err(MappingError::Address(error)),
        };
        let physical_address = match PhysAddr::new(physical_address) {
            Ok(address) => address,
            Err(error) => return Err(MappingError::Address(error)),
        };
        // PagePermissions already enforces W^X; re-checked as defense in depth.
        if permissions.writable() && permissions.executable() {
            return Err(MappingError::WriteExecuteViolation);
        }
        if !permissions.readable() {
            return Err(MappingError::UnreadablePageUnsupported);
        }
        if permissions.user_accessible() && virtual_address.get() >= KERNEL_HALF_START {
            return Err(MappingError::UserMappingInKernelHalf);
        }
        if permissions.user_accessible() && virtual_address.get() < PAGE_SIZE {
            return Err(MappingError::NullPageUserMapping);
        }
        Ok(Self {
            virtual_address,
            physical_address,
            permissions,
            device: false,
        })
    }

    /// Kernel-only, writable, non-executable, uncacheable MMIO mapping.
    /// Device registers can never be mapped into the user half this way.
    pub const fn kernel_device(
        virtual_address: u64,
        physical_address: u64,
    ) -> Result<Self, MappingError> {
        if virtual_address < KERNEL_HALF_START {
            return Err(MappingError::DeviceMappingOutsideKernelHalf);
        }
        let permissions = match PagePermissions::new(true, true, false, false) {
            Ok(permissions) => permissions,
            Err(_) => return Err(MappingError::WriteExecuteViolation),
        };
        match Self::new(virtual_address, physical_address, permissions) {
            Ok(mapping) => Ok(Self {
                device: true,
                ..mapping
            }),
            Err(error) => Err(error),
        }
    }

    pub const fn is_device(self) -> bool {
        self.device
    }

    pub const fn virtual_address(self) -> VirtAddr {
        self.virtual_address
    }
    pub const fn physical_address(self) -> PhysAddr {
        self.physical_address
    }
    pub const fn permissions(self) -> PagePermissions {
        self.permissions
    }

    /// Encodes the leaf entry after the request has passed validation.
    pub const fn leaf_entry(self) -> PageTableEntry {
        let mut raw = self.physical_address.0 | PRESENT;
        if self.permissions.writable() {
            raw |= WRITABLE;
        }
        if self.permissions.user_accessible() {
            raw |= USER;
        }
        if !self.permissions.executable() {
            raw |= NO_EXECUTE;
        }
        if self.device {
            raw |= CACHE_DISABLE | WRITE_THROUGH;
        }
        PageTableEntry(raw)
    }
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
    /// Accepts only a page-aligned, canonical, upper-half HHDM base.
    pub const fn new(offset: u64) -> Result<Self, AddressError> {
        if !is_canonical(offset) {
            return Err(AddressError::NonCanonical);
        }
        if offset & (PAGE_SIZE - 1) != 0 {
            return Err(AddressError::Unaligned);
        }
        if offset < KERNEL_HALF_START {
            return Err(AddressError::HhdmNotInKernelHalf);
        }
        Ok(Self(offset))
    }

    pub const fn get(self) -> u64 {
        self.0
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
        if !permissions.readable() {
            return Err(EntryError::UnreadablePageUnsupported);
        }
        if permissions.writable() && permissions.executable() {
            return Err(EntryError::WriteExecuteViolation);
        }

        let mut raw = physical.0 | PRESENT;
        if permissions.writable() {
            raw |= WRITABLE;
        }
        if permissions.user_accessible() {
            raw |= USER;
        }
        if !permissions.executable() {
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
    pub const fn new_table(physical: PhysAddr, user_accessible: bool) -> Result<Self, EntryError> {
        if physical.0 == 0 {
            return Err(EntryError::Address(AddressError::InvalidPageTableRoot));
        }
        let mut raw = physical.0 | PRESENT | WRITABLE;
        if user_accessible {
            raw |= USER;
        }
        Ok(Self(raw))
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
    fn validates_mapping_alignment_wx_and_user_kernel_boundary() {
        use super::{MappingError, PageMapping};
        let user = PagePermissions::new(true, true, false, true).unwrap();
        let mapping = PageMapping::new(0x4000, 0x9000, user).unwrap();
        assert!(mapping.leaf_entry().is_user_accessible());
        assert!(mapping.leaf_entry().is_writable());
        assert!(!mapping.leaf_entry().is_executable());

        assert_eq!(
            PageMapping::new(0x4001, 0x9000, user),
            Err(MappingError::VirtualAddressUnaligned)
        );
        assert_eq!(
            PageMapping::new(0xffff_8000_0000_0000, 0x9000, user),
            Err(MappingError::UserMappingInKernelHalf)
        );
        assert_eq!(
            PageMapping::new(0, 0x9000, user),
            Err(MappingError::NullPageUserMapping)
        );
        // W+X permissions are unrepresentable: PagePermissions::new rejects them.
        assert!(PagePermissions::new(true, true, true, false).is_err());
    }

    #[test]
    fn device_mappings_are_kernel_only_uncached_and_non_executable() {
        use super::{MappingError, PageMapping};
        let device = PageMapping::kernel_device(0xffff_ffff_7000_0000, 0xfee0_0000).unwrap();
        let entry = device.leaf_entry();
        assert!(device.is_device());
        assert!(!entry.is_user_accessible());
        assert!(!entry.is_executable());
        assert!(entry.is_writable());
        assert_eq!(entry.raw() & 0x18, 0x18, "PCD and PWT must be set");
        assert_eq!(
            PageMapping::kernel_device(0x40_0000, 0xfee0_0000),
            Err(MappingError::DeviceMappingOutsideKernelHalf)
        );
    }

    #[test]
    fn hhdm_offset_must_be_aligned_upper_half() {
        assert_eq!(
            HhdmOffset::new(0x0000_0000_4000_0000),
            Err(AddressError::HhdmNotInKernelHalf)
        );
        assert_eq!(
            HhdmOffset::new(0xffff_8000_0000_0800),
            Err(AddressError::Unaligned)
        );
        assert_eq!(
            HhdmOffset::new(0x0000_8000_0000_0000),
            Err(AddressError::NonCanonical)
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
    fn rejects_unreadable_page_entries() {
        let physical = PhysAddr::new(0x4000).expect("aligned physical address");
        // W+X cannot even be constructed, so the entry encoder never sees it.
        assert!(PagePermissions::new(true, true, true, false).is_err());

        let unreadable =
            PagePermissions::new(false, false, false, false).expect("unreadable is representable");
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
        match PagePermissions::new(true, writable, executable, false) {
            Ok(permissions) => {
                let entry = PageTableEntry::new(physical, permissions).expect("W^X permissions");
                assert!(!(entry.is_writable() && entry.is_executable()));
            }
            Err(_) => assert!(writable && executable),
        }
    }
}

pub(crate) const HUGE_PAGE: u64 = 1 << 7;
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

/// Backend failures are kept separate from page-table policy errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationBackendError {
    AllocationFailed,
    ReadFailed,
    WriteFailed,
    ReleaseFailed,
    TlbInvalidationFailed,
}

/// Operations required by the transactional 4 KiB mapper.
///
/// # Safety
/// Implementations must provide exclusive, correctly aligned access to page
/// table frames. Newly allocated frames must be fully zeroed before return.
/// Writes must be atomic at the entry level, and release must only reclaim
/// frames owned by this mapper and no longer reachable by hardware page walks.
/// The invalidation operation must cover every CPU that can execute the
/// affected address space. Local INVLPG is sufficient only while that address
/// space is pinned to one CPU.
pub unsafe trait PageTableMutationMemory {
    fn allocate_zeroed_table_frame(&mut self) -> Result<PhysAddr, MutationBackendError>;
    fn release_table_frame(&mut self, frame: PhysAddr) -> Result<(), MutationBackendError>;
    fn read_entry(&self, table: PhysAddr, index: u16) -> Result<u64, MutationBackendError>;
    fn write_entry(
        &mut self,
        table: PhysAddr,
        index: u16,
        value: u64,
    ) -> Result<(), MutationBackendError>;
    /// Invalidates the address on all CPUs that may run this address space.
    ///
    /// # Safety
    /// The implementation must serialize shootdown requests, wait for all
    /// required acknowledgements, and not return success while stale
    /// translations can still be used. A uniprocessor backend may use local
    /// INVLPG only if migration and concurrent execution are impossible.
    fn invalidate_page(&mut self, virtual_address: VirtAddr) -> Result<(), MutationBackendError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingTransactionError {
    Backend(MutationBackendError),
    AlreadyMapped,
    NotMapped,
    HugePageConflict,
    InvalidParentEntry,
    ParentPermissionConflict,
    RollbackFailed,
    WriteExecuteMappingFound,
    /// The leaf was cleared but stale translations may survive. The removed
    /// frame must not be recycled until an address-space flush succeeds.
    TlbInvalidationFailed {
        error: MutationBackendError,
        removed: PageMapping,
    },
}

#[derive(Clone, Copy)]
struct CreatedTable {
    parent: PhysAddr,
    index: u16,
    child: PhysAddr,
}

/// Transactional mapper for 4 KiB leaves. It never replaces existing mappings.
pub struct PageTableMapper<'a, M: PageTableMutationMemory> {
    memory: &'a mut M,
    root: PhysAddr,
}

impl<'a, M: PageTableMutationMemory> PageTableMapper<'a, M> {
    pub const fn new(memory: &'a mut M, root: PhysAddr) -> Self {
        Self { memory, root }
    }

    /// Removes one 4 KiB leaf mapping. It never frees the mapped data frame
    /// or intermediate tables; ownership and subtree-wide TLB shootdown are
    /// separate responsibilities.
    ///
    /// If invalidation fails, the leaf is already cleared in memory but stale
    /// translations may remain. The caller must complete an address-space
    /// flush before reusing the returned physical frame.
    pub fn unmap_4k(
        &mut self,
        virtual_address: VirtAddr,
    ) -> Result<PageMapping, MappingTransactionError> {
        let indices = virtual_address.page_table_indices();
        let path = [indices.pml4, indices.pdpt, indices.pd];
        let mut table = self.root;
        let mut writable = true;
        let mut user_accessible = true;
        let mut executable = true;

        for index in path {
            let raw = self
                .memory
                .read_entry(table, index)
                .map_err(MappingTransactionError::Backend)?;
            if raw & PRESENT == 0 {
                return Err(MappingTransactionError::NotMapped);
            }
            if raw & RESERVED_HIGH_BITS != 0 {
                return Err(MappingTransactionError::InvalidParentEntry);
            }
            if raw & HUGE_PAGE != 0 {
                return Err(MappingTransactionError::HugePageConflict);
            }
            writable &= raw & WRITABLE != 0;
            user_accessible &= raw & USER != 0;
            executable &= raw & NO_EXECUTE == 0;

            let next = raw & PHYSICAL_ADDRESS_MASK;
            if next == 0 {
                return Err(MappingTransactionError::InvalidParentEntry);
            }
            table = PhysAddr::new(next).map_err(|_| MappingTransactionError::InvalidParentEntry)?;
        }

        let raw = self
            .memory
            .read_entry(table, indices.pt)
            .map_err(MappingTransactionError::Backend)?;
        if raw & PRESENT == 0 {
            return Err(MappingTransactionError::NotMapped);
        }
        if raw & RESERVED_HIGH_BITS != 0 {
            return Err(MappingTransactionError::InvalidParentEntry);
        }

        writable &= raw & WRITABLE != 0;
        user_accessible &= raw & USER != 0;
        executable &= raw & NO_EXECUTE == 0;
        let physical = PhysAddr::new(raw & PHYSICAL_ADDRESS_MASK)
            .map_err(|_| MappingTransactionError::InvalidParentEntry)?;
        // A live W+X translation can only come from corruption or a foreign
        // writer; refuse to describe it as a valid PageMapping.
        let permissions = PagePermissions::new(true, writable, executable, user_accessible)
            .map_err(|_| MappingTransactionError::WriteExecuteMappingFound)?;
        let removed = PageMapping {
            virtual_address,
            physical_address: physical,
            permissions,
            device: raw & CACHE_DISABLE != 0,
        };

        self.memory
            .write_entry(table, indices.pt, 0)
            .map_err(MappingTransactionError::Backend)?;
        self.memory
            .invalidate_page(virtual_address)
            .map_err(|error| MappingTransactionError::TlbInvalidationFailed { error, removed })?;
        Ok(removed)
    }

    pub fn map_4k(&mut self, mapping: PageMapping) -> Result<(), MappingTransactionError> {
        let indices = mapping.virtual_address.page_table_indices();
        let path = [indices.pml4, indices.pdpt, indices.pd];
        let mut table = self.root;
        let mut created: [Option<CreatedTable>; 3] = [None; 3];
        let mut created_len = 0usize;

        for index in path {
            let raw = match self.memory.read_entry(table, index) {
                Ok(value) => value,
                Err(error) => {
                    return self.rollback(
                        mapping.virtual_address,
                        created,
                        created_len,
                        MappingTransactionError::Backend(error),
                    );
                }
            };

            if raw & PRESENT == 0 {
                let child = match self.memory.allocate_zeroed_table_frame() {
                    Ok(frame) => frame,
                    Err(error) => {
                        return self.rollback(
                            mapping.virtual_address,
                            created,
                            created_len,
                            MappingTransactionError::Backend(error),
                        );
                    }
                };
                let parent_entry =
                    match PageTableEntry::new_table(child, mapping.permissions.user_accessible()) {
                        Ok(entry) => entry.raw(),
                        Err(_) => {
                            let _ = self.memory.release_table_frame(child);
                            return self.rollback(
                                mapping.virtual_address,
                                created,
                                created_len,
                                MappingTransactionError::InvalidParentEntry,
                            );
                        }
                    };
                if let Err(error) = self.memory.write_entry(table, index, parent_entry) {
                    let release = self.memory.release_table_frame(child);
                    let cause = if release.is_err() {
                        MappingTransactionError::RollbackFailed
                    } else {
                        MappingTransactionError::Backend(error)
                    };
                    return self.rollback(mapping.virtual_address, created, created_len, cause);
                }
                created[created_len] = Some(CreatedTable {
                    parent: table,
                    index,
                    child,
                });
                created_len += 1;
                table = child;
            } else {
                if raw & HUGE_PAGE != 0 {
                    return self.rollback(
                        mapping.virtual_address,
                        created,
                        created_len,
                        MappingTransactionError::HugePageConflict,
                    );
                }
                if raw & RESERVED_HIGH_BITS != 0 {
                    return self.rollback(
                        mapping.virtual_address,
                        created,
                        created_len,
                        MappingTransactionError::InvalidParentEntry,
                    );
                }
                if (mapping.permissions.user_accessible() && raw & USER == 0)
                    || (mapping.permissions.writable() && raw & WRITABLE == 0)
                    || (mapping.permissions.executable() && raw & NO_EXECUTE != 0)
                {
                    return self.rollback(
                        mapping.virtual_address,
                        created,
                        created_len,
                        MappingTransactionError::ParentPermissionConflict,
                    );
                }
                let next = raw & PHYSICAL_ADDRESS_MASK;
                table = match PhysAddr::new(next) {
                    Ok(address) if next != 0 => address,
                    _ => {
                        return self.rollback(
                            mapping.virtual_address,
                            created,
                            created_len,
                            MappingTransactionError::InvalidParentEntry,
                        );
                    }
                };
            }
        }

        let leaf_index = indices.pt;
        let existing = match self.memory.read_entry(table, leaf_index) {
            Ok(value) => value,
            Err(error) => {
                return self.rollback(
                    mapping.virtual_address,
                    created,
                    created_len,
                    MappingTransactionError::Backend(error),
                );
            }
        };
        if existing & PRESENT != 0 {
            return self.rollback(
                mapping.virtual_address,
                created,
                created_len,
                MappingTransactionError::AlreadyMapped,
            );
        }
        if let Err(error) = self
            .memory
            .write_entry(table, leaf_index, mapping.leaf_entry().raw())
        {
            return self.rollback(
                mapping.virtual_address,
                created,
                created_len,
                MappingTransactionError::Backend(error),
            );
        }
        // No TLB invalidation is required here: the leaf and every newly
        // created parent changed from not-present to present, and x86 never
        // caches not-present translations (Intel SDM Vol. 3A 4.10.4.3, AMD APM
        // Vol. 2 5.5.2). Invalidating here used to return an error *after* the
        // mapping became visible, so a caller could believe the map failed,
        // recycle the frame and leave a live alias (use-after-free). A stale
        // translation left by a failed unmap is the unmap caller's contract.
        Ok(())
    }

    fn rollback(
        &mut self,
        virtual_address: VirtAddr,
        created: [Option<CreatedTable>; 3],
        created_len: usize,
        cause: MappingTransactionError,
    ) -> Result<(), MappingTransactionError> {
        if created_len == 0 {
            // Nothing was published, so no TLB or paging-structure cache can
            // reference new state. Report the real cause, not RollbackFailed.
            return Err(cause);
        }
        let mut clear_failed = false;
        for item in created[..created_len].iter().rev().flatten() {
            if self.memory.write_entry(item.parent, item.index, 0).is_err() {
                clear_failed = true;
            }
        }
        if clear_failed {
            // Some frames may still be reachable. Leak rather than risk use-after-free.
            return Err(MappingTransactionError::RollbackFailed);
        }
        if self.memory.invalidate_page(virtual_address).is_err() {
            // Page-walk caches may still reference detached tables. Leak them safely.
            return Err(MappingTransactionError::RollbackFailed);
        }
        for item in created[..created_len].iter().rev().flatten() {
            if self.memory.release_table_frame(item.child).is_err() {
                return Err(MappingTransactionError::RollbackFailed);
            }
        }
        Err(cause)
    }
}

#[cfg(test)]
mod mutation_tests {
    use super::{
        MappingTransactionError, MutationBackendError, NO_EXECUTE, PRESENT, PageMapping,
        PageTableMapper, PageTableMutationMemory, PhysAddr, USER, VirtAddr, WRITABLE,
    };
    use centinela_security::permissions::PagePermissions;

    struct MockMutationMemory {
        entries: [(u64, u16, u64); 8],
        len: usize,
        invalidations: usize,
        fail_invalidation: bool,
    }

    // SAFETY: This mock owns a fixed in-memory entry array, returns zero for
    // absent entries, and performs atomic updates to individual entries.
    unsafe impl PageTableMutationMemory for MockMutationMemory {
        fn allocate_zeroed_table_frame(&mut self) -> Result<PhysAddr, MutationBackendError> {
            Err(MutationBackendError::AllocationFailed)
        }

        fn release_table_frame(&mut self, _: PhysAddr) -> Result<(), MutationBackendError> {
            Ok(())
        }

        fn read_entry(&self, table: PhysAddr, index: u16) -> Result<u64, MutationBackendError> {
            Ok(self.entries[..self.len]
                .iter()
                .find(|(address, entry_index, _)| *address == table.get() && *entry_index == index)
                .map(|(_, _, value)| *value)
                .unwrap_or(0))
        }

        fn write_entry(
            &mut self,
            table: PhysAddr,
            index: u16,
            value: u64,
        ) -> Result<(), MutationBackendError> {
            if let Some(entry) = self.entries[..self.len]
                .iter_mut()
                .find(|(address, entry_index, _)| *address == table.get() && *entry_index == index)
            {
                entry.2 = value;
            } else if self.len < self.entries.len() {
                self.entries[self.len] = (table.get(), index, value);
                self.len += 1;
            } else {
                return Err(MutationBackendError::WriteFailed);
            }
            Ok(())
        }

        fn invalidate_page(&mut self, _: VirtAddr) -> Result<(), MutationBackendError> {
            self.invalidations += 1;
            if self.fail_invalidation {
                Err(MutationBackendError::TlbInvalidationFailed)
            } else {
                Ok(())
            }
        }
    }

    fn mapped_memory() -> MockMutationMemory {
        MockMutationMemory {
            entries: [
                (0x1000, 0, 0x2000 | PRESENT | WRITABLE | USER),
                (0x2000, 0, 0x3000 | PRESENT | WRITABLE | USER),
                (0x3000, 0, 0x4000 | PRESENT | WRITABLE | USER),
                (0x4000, 1, 0x9000 | PRESENT | USER | NO_EXECUTE),
                (0, 0, 0),
                (0, 0, 0),
                (0, 0, 0),
                (0, 0, 0),
            ],
            len: 4,
            invalidations: 0,
            fail_invalidation: false,
        }
    }

    #[test]
    fn unmap_clears_leaf_invalidates_and_returns_effective_permissions() {
        let mut memory = mapped_memory();
        let root = PhysAddr::new(0x1000).unwrap();
        let address = VirtAddr::new(0x1000).unwrap();
        let mut mapper = PageTableMapper::new(&mut memory, root);

        let removed = mapper.unmap_4k(address).unwrap();
        assert_eq!(removed.physical_address().get(), 0x9000);
        assert!(!removed.permissions().writable());
        assert!(removed.permissions().user_accessible());
        assert!(!removed.permissions().executable());
        assert_eq!(
            mapper.memory.read_entry(PhysAddr::new(0x4000).unwrap(), 1),
            Ok(0)
        );
        assert_eq!(mapper.memory.invalidations, 1);
    }

    #[test]
    fn unmap_preserves_removed_frame_when_tlb_invalidation_fails() {
        let mut memory = mapped_memory();
        memory.fail_invalidation = true;
        let root = PhysAddr::new(0x1000).unwrap();
        let address = VirtAddr::new(0x1000).unwrap();
        let mut mapper = PageTableMapper::new(&mut memory, root);

        match mapper.unmap_4k(address) {
            Err(MappingTransactionError::TlbInvalidationFailed {
                error: MutationBackendError::TlbInvalidationFailed,
                removed: mapping,
            }) => assert_eq!(mapping.physical_address().get(), 0x9000),
            other => panic!("unexpected unmap result: {:?}", other),
        }
        assert_eq!(
            mapper.memory.read_entry(PhysAddr::new(0x4000).unwrap(), 1),
            Ok(0)
        );
    }

    #[test]
    fn unmap_rejects_absent_leaf_without_invalidating() {
        let mut memory = mapped_memory();
        memory.entries[3].2 = 0;
        let root = PhysAddr::new(0x1000).unwrap();
        let address = VirtAddr::new(0x1000).unwrap();
        let mut mapper = PageTableMapper::new(&mut memory, root);

        assert_eq!(
            mapper.unmap_4k(address),
            Err(MappingTransactionError::NotMapped)
        );
        assert_eq!(mapper.memory.invalidations, 0);
    }

    fn user_rw() -> PagePermissions {
        PagePermissions::new(true, true, false, true).unwrap()
    }

    #[test]
    fn map_into_existing_tables_needs_no_tlb_invalidation() {
        let mut memory = mapped_memory();
        memory.fail_invalidation = true;
        let root = PhysAddr::new(0x1000).unwrap();
        let mut mapper = PageTableMapper::new(&mut memory, root);
        let mapping = PageMapping::new(0x2000, 0xa000, user_rw()).unwrap();

        assert_eq!(mapper.map_4k(mapping), Ok(()));
        assert_eq!(
            mapper.memory.read_entry(PhysAddr::new(0x4000).unwrap(), 2),
            Ok(mapping.leaf_entry().raw())
        );
        assert_eq!(mapper.memory.invalidations, 0);
    }

    #[test]
    fn rejected_map_without_new_tables_reports_real_cause() {
        let mut memory = mapped_memory();
        memory.fail_invalidation = true;
        let root = PhysAddr::new(0x1000).unwrap();
        let mut mapper = PageTableMapper::new(&mut memory, root);

        let existing = PageMapping::new(0x1000, 0xa000, user_rw()).unwrap();
        assert_eq!(
            mapper.map_4k(existing),
            Err(MappingTransactionError::AlreadyMapped)
        );

        let needs_table = PageMapping::new(0x20_0000, 0xa000, user_rw()).unwrap();
        assert_eq!(
            mapper.map_4k(needs_table),
            Err(MappingTransactionError::Backend(
                MutationBackendError::AllocationFailed
            ))
        );
        assert_eq!(mapper.memory.invalidations, 0);
    }

    #[test]
    fn unmap_refuses_to_describe_live_write_execute_leaf() {
        let mut memory = mapped_memory();
        memory.entries[3].2 = 0x9000 | PRESENT | USER | WRITABLE;
        let root = PhysAddr::new(0x1000).unwrap();
        let mut mapper = PageTableMapper::new(&mut memory, root);

        assert_eq!(
            mapper.unmap_4k(VirtAddr::new(0x1000).unwrap()),
            Err(MappingTransactionError::WriteExecuteMappingFound)
        );
    }
}
