//! x86_64 virtual-address and page-table entry primitives.
//!
//! This module deliberately does not install a new CR3 or mutate Limine's
//! active page tables yet. It provides checked address/index/entry encoding
//! primitives for the VMM implementation milestone.

use centinela_security::permissions::PagePermissions;

pub const PAGE_SIZE: u64 = 4096;
const ADDRESS_BITS: u32 = 48;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const CR3_ADDRESS_MASK: u64 = PHYSICAL_ADDRESS_MASK;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const NO_EXECUTE: u64 = 1 << 63;

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
        AddressError, BootPagingInfo, EntryError, HhdmOffset, PAGE_SIZE, PageTableEntry, PhysAddr, VirtAddr,
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
