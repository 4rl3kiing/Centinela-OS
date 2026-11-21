//! Intel VT-d DMA remapping, deny-by-default (phase 4, step 2).
//!
//! Every DMA-remapping unit listed in the ACPI DMAR table is pointed at an
//! empty root table and translation is enabled. With no present root or
//! context entries, every DMA request from every device is blocked and
//! logged as a fault: a compromised or malicious device (or a driver that
//! later runs in Ring 3) cannot read or write physical memory until the
//! kernel grants it an explicit, capability-backed mapping.
//!
//! Interrupts are unaffected: without interrupt remapping, MSIs keep using
//! the compatibility format (interrupt remapping is a later step).
//!
//! Policy: a machine without a DMAR table boots with a warning (no IOMMU to
//! program). A DMAR table that is malformed, or a unit that refuses to
//! enable translation, fails the boot (fail closed).

use core::fmt::Write;

use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_kernel::acpi::{self, AcpiError, DrhdUnit, PhysicalReader};
use centinela_kernel::memory::hhdm_backend::HhdmFrameMemory;
use centinela_kernel::memory::vmm::{
    PageMapping, PageTableMapper, PageTableMutationMemory, PhysAddr,
};

const MAX_UNITS: usize = 8;
const POLL_LIMIT: u32 = 10_000_000;

const REG_VERSION: usize = 0x00;
const REG_ECAP: usize = 0x10;
const REG_GCMD: usize = 0x18;
const REG_GSTS: usize = 0x1c;
const REG_RTADDR: usize = 0x20;
const REG_CCMD: usize = 0x28;
const REG_FSTS: usize = 0x34;

const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
/// GSTS bits that are status of persistent commands (one-shot bits masked),
/// per VT-d spec 11.4.4.
const GSTS_PERSISTENT_MASK: u32 = 0x96ff_ffff;

const CCMD_ICC: u64 = 1 << 63;
const CCMD_GLOBAL: u64 = 1 << 61;
const IOTLB_IVT: u64 = 1 << 63;
const IOTLB_GLOBAL: u64 = 1 << 60;

struct Registers(u64);

impl Registers {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `self.0` maps the unit's 4 KiB register page (UC, kernel
        // only) and every offset used here is a defined 32-bit register.
        unsafe { core::ptr::read_volatile((self.0 + offset as u64) as *const u32) }
    }
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: As in `read32`.
        unsafe { core::ptr::write_volatile((self.0 + offset as u64) as *mut u32, value) }
    }
    fn read64(&self, offset: usize) -> u64 {
        // SAFETY: As in `read32`, for 64-bit registers.
        unsafe { core::ptr::read_volatile((self.0 + offset as u64) as *const u64) }
    }
    fn write64(&self, offset: usize, value: u64) {
        // SAFETY: As in `read64`.
        unsafe { core::ptr::write_volatile((self.0 + offset as u64) as *mut u64, value) }
    }

    fn command(&self, bit: u32) {
        let status = self.read32(REG_GSTS) & GSTS_PERSISTENT_MASK;
        self.write32(REG_GCMD, status | bit);
    }

    fn wait32(&self, offset: usize, bit: u32, set: bool) -> bool {
        (0..POLL_LIMIT).any(|_| {
            let done = (self.read32(offset) & bit != 0) == set;
            if !done {
                core::hint::spin_loop();
            }
            done
        })
    }

    fn wait64_clear(&self, offset: usize, bit: u64) -> bool {
        (0..POLL_LIMIT).any(|_| {
            let done = self.read64(offset) & bit == 0;
            if !done {
                core::hint::spin_loop();
            }
            done
        })
    }
}

/// Firmware tables reached through the HHDM, restricted to ACPI regions of
/// the memory map so a hostile pointer cannot make the kernel read (or fault
/// on) arbitrary memory.
pub(crate) struct AcpiReader<F: Fn(u64, u64) -> bool> {
    pub(crate) hhdm: u64,
    pub(crate) in_acpi_memory: F,
}

impl<F: Fn(u64, u64) -> bool> PhysicalReader for AcpiReader<F> {
    fn bytes(&self, physical: u64, length: usize) -> Option<&[u8]> {
        let end = physical.checked_add(length as u64)?;
        if length == 0 || !(self.in_acpi_memory)(physical, end) {
            return None;
        }
        let virtual_address = self.hhdm.checked_add(physical)?;
        // SAFETY: Base revision 5 maps ACPI reclaimable/NVS/reserved-mapped
        // regions in the HHDM, and the range was checked to lie in one; the
        // tables are never written while the kernel runs.
        Some(unsafe { core::slice::from_raw_parts(virtual_address as *const u8, length) })
    }
}

fn enable_unit(registers: &Registers, root_table: PhysAddr) -> Result<(), &'static str> {
    let ecap = registers.read64(REG_ECAP);
    let iotlb = (((ecap >> 8) & 0x3ff) * 16) as usize;
    if iotlb == 0 || iotlb + 16 > 4096 {
        return Err("IOTLB registers outside the mapped page");
    }
    registers.write64(REG_RTADDR, root_table.get());
    registers.command(GCMD_SRTP);
    if !registers.wait32(REG_GSTS, GCMD_SRTP, true) {
        return Err("root table pointer not latched");
    }
    registers.write64(REG_CCMD, CCMD_ICC | CCMD_GLOBAL);
    if !registers.wait64_clear(REG_CCMD, CCMD_ICC) {
        return Err("context-cache invalidation timed out");
    }
    registers.write64(iotlb + 8, IOTLB_IVT | IOTLB_GLOBAL);
    if !registers.wait64_clear(iotlb + 8, IOTLB_IVT) {
        return Err("IOTLB invalidation timed out");
    }
    registers.command(GCMD_TE);
    if !registers.wait32(REG_GSTS, GCMD_TE, true) {
        return Err("translation enable not confirmed");
    }
    Ok(())
}

/// Discovers and enables every DMA-remapping unit. Returns `false` to fail
/// the boot.
pub(crate) fn init<R: PhysicalReader>(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    reader: Option<(&R, u64)>,
) -> bool {
    let mut writer = SerialWriter;
    let Some((reader, rsdp)) = reader else {
        serial_write("IOMMU: no ACPI tables; DMA is not remapped on this machine.\r\n");
        return true;
    };
    let table = match acpi::find_table(reader, rsdp, b"DMAR") {
        Ok(table) => table,
        Err(AcpiError::NotFound) => {
            serial_write("IOMMU: no DMAR table; DMA is not remapped on this machine.\r\n");
            return true;
        }
        Err(error) => {
            let _ = write!(writer, "Centinela-OS: ACPI tables rejected: {error:?}.\r\n");
            return false;
        }
    };
    let mut units = [DrhdUnit::default(); MAX_UNITS];
    let dmar = match acpi::parse_dmar(table, &mut units) {
        Ok(dmar) => dmar,
        Err(error) => {
            let _ = write!(writer, "Centinela-OS: DMAR table rejected: {error:?}.\r\n");
            return false;
        }
    };
    if dmar.unit_count == 0 {
        serial_write("Centinela-OS: DMAR table lists no remapping units.\r\n");
        return false;
    }
    // One empty root table shared by every unit: no device has a context.
    let Ok(root_table) = memory.allocate_zeroed_table_frame() else {
        serial_write("Centinela-OS: no frame for the IOMMU root table.\r\n");
        return false;
    };
    for unit in &units[..dmar.unit_count] {
        let Some(window) = crate::isolation::free_kernel_slot_address(memory, kernel_root) else {
            serial_write("Centinela-OS: no kernel slot for IOMMU registers.\r\n");
            return false;
        };
        let Ok(mapping) = PageMapping::kernel_device(window, unit.register_base) else {
            return false;
        };
        if PageTableMapper::new(memory, kernel_root)
            .map_4k(mapping)
            .is_err()
        {
            serial_write("Centinela-OS: failed to map IOMMU registers.\r\n");
            return false;
        }
        let registers = Registers(window);
        let version = registers.read32(REG_VERSION);
        if let Err(reason) = enable_unit(&registers, root_table) {
            let _ = write!(
                writer,
                "Centinela-OS: IOMMU unit at {:#x} failed: {reason}.\r\n",
                unit.register_base
            );
            return false;
        }
        let _ = write!(
            writer,
            "IOMMU: unit {:#x} (VT-d {}.{}, segment {}) translating; faults pending: {:#x}.\r\n",
            unit.register_base,
            (version >> 4) & 0xf,
            version & 0xf,
            unit.segment,
            registers.read32(REG_FSTS)
        );
    }
    let _ = write!(
        writer,
        "IOMMU: DMA remapping enabled on {} unit(s), deny-by-default (empty root table; {}-bit host addresses).\r\n",
        dmar.unit_count, dmar.host_address_width
    );
    true
}
