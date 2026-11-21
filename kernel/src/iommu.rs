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
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
const REG_CAP: usize = 0x08;
const REG_FSTS: usize = 0x34;
const GCMD_WBF: u32 = 1 << 27;

/// Persistent IOMMU state for per-device domains.
static ROOT_TABLE: AtomicU64 = AtomicU64::new(0);
static UNIT_WINDOWS: [AtomicU64; MAX_UNITS] = [const { AtomicU64::new(0) }; MAX_UNITS];
static UNIT_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Second-level paging depth supported by every unit (3 = 39-bit, 4 = 48-bit).
static LEVELS: AtomicUsize = AtomicUsize::new(0);
/// Units whose page-walks are not cache-coherent need explicit flushes.
static NEEDS_FLUSH: AtomicU64 = AtomicU64::new(0);
static HHDM: AtomicU64 = AtomicU64::new(0);
/// DMA faults counted at detach time (proof that confinement held).
static FAULTS_SEEN: AtomicU64 = AtomicU64::new(0);

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

fn flush_write_buffer(registers: &Registers) {
    if registers.read64(REG_CAP) & (1 << 4) != 0 {
        registers.command(GCMD_WBF);
        let _ = registers.wait32(REG_GSTS, GCMD_WBF, false);
    }
}

fn invalidate_all(registers: &Registers) -> bool {
    flush_write_buffer(registers);
    let ecap = registers.read64(REG_ECAP);
    let iotlb = (((ecap >> 8) & 0x3ff) * 16) as usize;
    registers.write64(REG_CCMD, CCMD_ICC | CCMD_GLOBAL);
    if !registers.wait64_clear(REG_CCMD, CCMD_ICC) {
        return false;
    }
    registers.write64(iotlb + 8, IOTLB_IVT | IOTLB_GLOBAL);
    registers.wait64_clear(iotlb + 8, IOTLB_IVT)
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
    ROOT_TABLE.store(root_table.get(), Ordering::Relaxed);
    let mut sagaw = 0x1f;
    let mut coherent = true;
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
        sagaw &= (registers.read64(REG_CAP) >> 8) & 0x1f;
        coherent &= registers.read64(REG_ECAP) & 1 != 0;
        let index = UNIT_COUNT.load(Ordering::Relaxed);
        UNIT_WINDOWS[index].store(window, Ordering::Relaxed);
        UNIT_COUNT.store(index + 1, Ordering::Relaxed);
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
    let levels = if sagaw & 0b010 != 0 {
        3
    } else if sagaw & 0b100 != 0 {
        4
    } else {
        0
    };
    LEVELS.store(levels, Ordering::Relaxed);
    NEEDS_FLUSH.store(u64::from(!coherent), Ordering::Relaxed);
    let _ = write!(
        writer,
        "IOMMU: DMA remapping enabled on {} unit(s), deny-by-default (empty root table; {}-bit host addresses).\r\n",
        dmar.unit_count, dmar.host_address_width
    );
    true
}

// ---------------------------------------------------------------------------
// Per-device DMA domains.
// ---------------------------------------------------------------------------

/// Lowest IOVA handed to devices; everything else in the domain is unmapped.
pub(crate) const IOVA_BASE: u64 = 0x1000_0000;
const ENTRY_READ: u64 = 1 << 0;
const ENTRY_WRITE: u64 = 1 << 1;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

fn flush_entry(physical: u64) {
    if NEEDS_FLUSH.load(Ordering::Relaxed) != 0 {
        let address = HHDM.load(Ordering::Relaxed) + physical;
        // SAFETY: HHDM alias of a table frame the kernel owns.
        unsafe { core::arch::x86_64::_mm_clflush(address as *const u8) };
    }
}

fn write_entry(
    memory: &mut HhdmFrameMemory<'_, '_>,
    table: PhysAddr,
    index: u64,
    value: u64,
) -> bool {
    // SAFETY: `table` is an IOMMU table frame owned by the kernel.
    let written =
        unsafe { memory.write_frame_at(table, (index * 8) as usize, &value.to_le_bytes()) };
    flush_entry(table.get() + index * 8);
    written.is_ok()
}

fn read_entry(memory: &HhdmFrameMemory<'_, '_>, table: PhysAddr, index: u64) -> u64 {
    PageTableMutationMemory::read_entry(memory, table, index as u16).unwrap_or(0)
}

fn invalidate() -> bool {
    (0..UNIT_COUNT.load(Ordering::Relaxed))
        .all(|unit| invalidate_all(&Registers(UNIT_WINDOWS[unit].load(Ordering::Relaxed))))
}

/// Present context-table frame for `bus`, created on demand.
fn context_table(memory: &mut HhdmFrameMemory<'_, '_>, bus: u8) -> Option<PhysAddr> {
    let root = PhysAddr::new(ROOT_TABLE.load(Ordering::Relaxed)).ok()?;
    // Root entries are 128-bit; the low word holds the context-table pointer.
    let low = read_entry(memory, root, u64::from(bus) * 2);
    if low & 1 != 0 {
        return PhysAddr::new(low & ADDRESS_MASK).ok();
    }
    let table = memory.allocate_zeroed_table_frame().ok()?;
    write_entry(memory, root, u64::from(bus) * 2, table.get() | 1).then_some(table)
}

/// Gives `device` its own, empty DMA domain. Returns the second-level root.
pub(crate) fn attach(
    memory: &mut HhdmFrameMemory<'_, '_>,
    hhdm: u64,
    device: crate::pci::Device,
    domain: u16,
) -> Option<PhysAddr> {
    HHDM.store(hhdm, Ordering::Relaxed);
    let levels = LEVELS.load(Ordering::Relaxed) as u64;
    if UNIT_COUNT.load(Ordering::Relaxed) == 0 || levels == 0 || domain == 0 {
        return None;
    }
    let context = context_table(memory, device.bus)?;
    let index = u64::from(device.devfn) * 2;
    if read_entry(memory, context, index) & 1 != 0 {
        return None; // already attached: one domain per device
    }
    let root = memory.allocate_zeroed_table_frame().ok()?;
    // High word: address width (1 = 3-level, 2 = 4-level) and domain id.
    let high = (levels - 2) | u64::from(domain) << 8;
    let ok = write_entry(memory, context, index + 1, high)
        && write_entry(memory, context, index, root.get() | 1)
        && invalidate();
    ok.then_some(root)
}

/// Maps one 4 KiB page at `iova` → `physical` (read/write) in a domain.
pub(crate) fn map(
    memory: &mut HhdmFrameMemory<'_, '_>,
    domain_root: PhysAddr,
    iova: u64,
    physical: PhysAddr,
) -> bool {
    let levels = LEVELS.load(Ordering::Relaxed) as u64;
    let mut table = domain_root;
    for level in (1..levels).rev() {
        let index = (iova >> (12 + 9 * level)) & 0x1ff;
        let entry = read_entry(memory, table, index);
        table = if entry & ENTRY_READ != 0 {
            match PhysAddr::new(entry & ADDRESS_MASK) {
                Ok(next) => next,
                Err(_) => return false,
            }
        } else {
            let Ok(next) = memory.allocate_zeroed_table_frame() else {
                return false;
            };
            if !write_entry(memory, table, index, next.get() | ENTRY_READ | ENTRY_WRITE) {
                return false;
            }
            next
        };
    }
    let index = (iova >> 12) & 0x1ff;
    write_entry(
        memory,
        table,
        index,
        physical.get() | ENTRY_READ | ENTRY_WRITE,
    ) && invalidate()
}

fn free_tables(memory: &mut HhdmFrameMemory<'_, '_>, table: PhysAddr, level: u64) {
    if level > 1 {
        for index in 0..512 {
            let entry = read_entry(memory, table, index);
            if entry & ENTRY_READ != 0
                && let Ok(next) = PhysAddr::new(entry & ADDRESS_MASK)
            {
                free_tables(memory, next, level - 1);
            }
        }
    }
    // Leaf data frames belong to the task and are freed with its address
    // space; only the domain's own table frames are released here.
    let _ = memory.release_table_frame(table);
}

/// Removes the device's domain: afterwards every DMA it issues is blocked
/// and faulted. Must run before the driver's DMA frames are freed.
pub(crate) fn detach(memory: &mut HhdmFrameMemory<'_, '_>, device: crate::pci::Device) -> u64 {
    let Some(context) = context_table(memory, device.bus) else {
        return 0;
    };
    let index = u64::from(device.devfn) * 2;
    let low = read_entry(memory, context, index);
    write_entry(memory, context, index, 0);
    write_entry(memory, context, index + 1, 0);
    // Release the bus's context table once no device uses it any more.
    if (0..512).all(|entry| read_entry(memory, context, entry) == 0)
        && let Ok(root) = PhysAddr::new(ROOT_TABLE.load(Ordering::Relaxed))
    {
        write_entry(memory, root, u64::from(device.bus) * 2, 0);
        let _ = invalidate();
        let _ = memory.release_table_frame(context);
    } else {
        let _ = invalidate();
    }
    if low & 1 != 0
        && let Ok(root) = PhysAddr::new(low & ADDRESS_MASK)
    {
        free_tables(memory, root, LEVELS.load(Ordering::Relaxed) as u64);
    }
    // Primary pending fault (PPF) or overflow: count and clear (RW1C).
    let mut faults = 0;
    for window in UNIT_WINDOWS.iter().take(UNIT_COUNT.load(Ordering::Relaxed)) {
        let registers = Registers(window.load(Ordering::Relaxed));
        let status = registers.read32(REG_FSTS);
        if status & 0b11 != 0 {
            faults += 1;
            registers.write32(REG_FSTS, status);
        }
    }
    FAULTS_SEEN.fetch_add(faults, Ordering::Relaxed);
    faults
}

/// DMA faults recorded so far (each detach counts the pending ones).
pub(crate) fn faults_seen() -> u64 {
    FAULTS_SEEN.load(Ordering::Relaxed)
}
