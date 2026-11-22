//! Intel VT-d DMA remapping, deny-by-default (phase 4, step 2).
//!
//! Every DMA-remapping unit listed in the ACPI DMAR table is pointed at an
//! empty root table and translation is enabled. With no present root or
//! context entries, every DMA request from every device is blocked and
//! logged as a fault: a compromised or malicious device (or a driver that
//! later runs in Ring 3) cannot read or write physical memory until the
//! kernel grants it an explicit, capability-backed mapping.
//!
//! Interrupt remapping (phase 6): when every unit supports it, interrupts
//! are delivered only through the kernel's interrupt remapping table (IRT).
//! Compatibility-format interrupts stay blocked (GCMD.CFI is never set), so
//! a device cannot inject an arbitrary vector with a forged MSI write; it
//! can raise only the entries the kernel programmed. All invalidations go
//! through the queued-invalidation interface, which interrupt remapping
//! requires.
//!
//! Policy: a machine without a DMAR or IVRS table boots, but fail closed:
//! no domain can be created, so no driver is ever granted DMA and Bus Master
//! stays cleared on every PCI function (see `pci`). A DMAR table that is
//! malformed, or a unit that refuses to enable translation, fails the boot.
//!
//! Teardown: a device is detached by clearing its Bus Master bit, blocking
//! it in the IOMMU tables and invalidating the caches. Tables and DMA frames
//! are released only after every unit confirmed the invalidation (VT-d wait
//! descriptor, AMD-Vi COMPLETION_WAIT, both bounded). If that fails they are
//! quarantined: left allocated forever, never reused.
//!
//! SMP: each unit's invalidation interface (queue, tail, wait word and the
//! register-based fallback) is used under that unit's lock; the tables
//! shared by every device (root, context, AMD-Vi device table and domain
//! slots) change only under the topology lock.

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_kernel::acpi::{self, AcpiError, DrhdUnit, PhysicalReader};
use centinela_kernel::dma::{self, CommandRing, RING_ENTRIES, RingState, SpinLock};
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
const REG_IQH: usize = 0x80;
const REG_IQT: usize = 0x88;
const REG_IQA: usize = 0x90;
const REG_IRTA: usize = 0xb8;
const GCMD_QIE: u32 = 1 << 26;
const GCMD_IRE: u32 = 1 << 25;
const GCMD_SIRTP: u32 = 1 << 24;
const GSTS_CFIS: u32 = 1 << 23;
const FSTS_IQE: u32 = 1 << 4;
const ECAP_QI: u64 = 1 << 1;
const ECAP_IR: u64 = 1 << 3;
/// Interrupt remapping table: one 4 KiB page of 128-bit entries.
pub(crate) const IRT_ENTRIES: u16 = 256;

/// Per-unit invalidation queue (physical address; 0 = register-based).
static QUEUES: [AtomicU64; MAX_UNITS] = [const { AtomicU64::new(0) }; MAX_UNITS];
/// Per-unit lock over the invalidation interface: queue tail and wait token
/// (inside), plus the queue page, the unit's wait word and the registers
/// used to invalidate, all of which are shared by every CPU.
static UNITS: [SpinLock<RingState>; MAX_UNITS] =
    [const { SpinLock::new(RingState::new()) }; MAX_UNITS];
/// Serialises changes to the tables every device shares (attach, detach).
/// Lock order: `TOPOLOGY`, then one unit lock at a time.
static TOPOLOGY: SpinLock<()> = SpinLock::new(());
/// Frame holding one wait-descriptor status word per unit.
static WAIT_STATUS: AtomicU64 = AtomicU64::new(0);
/// Interrupt remapping table (physical; 0 = remapping off).
static IRT: AtomicU64 = AtomicU64::new(0);

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

fn hhdm_pointer(physical: u64) -> *mut u64 {
    (HHDM.load(Ordering::Relaxed) + physical) as *mut u64
}

/// One unit's invalidation queue, as the hardware sees it. Used only while
/// the unit's `UNITS` lock is held.
struct UnitQueue<'a> {
    unit: usize,
    registers: &'a Registers,
}

impl UnitQueue<'_> {
    fn status_address(&self) -> u64 {
        WAIT_STATUS.load(Ordering::Relaxed) + self.unit as u64 * 8
    }
}

impl CommandRing for UnitQueue<'_> {
    fn head(&mut self) -> u64 {
        (self.registers.read64(REG_IQH) >> 4) & (RING_ENTRIES - 1)
    }

    fn store(&mut self, index: u64, entry: [u64; 2]) {
        let queue = QUEUES[self.unit].load(Ordering::Relaxed);
        let slot = hhdm_pointer(queue + (index % RING_ENTRIES) * 16);
        // SAFETY: The slot is inside the queue page the kernel owns; the
        // hardware only reads up to IQT.
        unsafe {
            slot.write_volatile(entry[0]);
            slot.add(1).write_volatile(entry[1]);
            core::arch::x86_64::_mm_clflush(slot as *const u8);
        }
    }

    fn publish(&mut self, tail: u64) {
        // SAFETY: Orders the descriptor stores (and their cache-line
        // flushes) before the tail doorbell.
        unsafe { core::arch::x86_64::_mm_sfence() };
        self.registers.write64(REG_IQT, tail << 4);
    }

    fn wait_command(&mut self, token: u32) -> [u64; 2] {
        let address = self.status_address();
        // SAFETY: Kernel-owned status frame, HHDM-mapped; one word per unit.
        unsafe { hhdm_pointer(address).write_volatile(0) };
        dma::vtd::wait(token, address)
    }

    fn completion(&mut self) -> u32 {
        // SAFETY: As in `wait_command`.
        unsafe { hhdm_pointer(self.status_address()).read_volatile() as u32 }
    }

    fn faulted(&mut self) -> bool {
        self.registers.read32(REG_FSTS) & FSTS_IQE != 0
    }
}

/// Queues `descriptors` plus a wait descriptor on `unit` and spins (bounded)
/// until the hardware has processed them all. `state` comes from the unit's
/// lock, which the caller holds.
fn submit(
    unit: usize,
    registers: &Registers,
    state: &mut RingState,
    descriptors: &[[u64; 2]],
) -> bool {
    if QUEUES[unit].load(Ordering::Relaxed) == 0 || WAIT_STATUS.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let mut queue = UnitQueue { unit, registers };
    match dma::submit(&mut queue, state, descriptors, POLL_LIMIT) {
        Ok(()) => true,
        Err(error) => {
            let _ = write!(
                SerialWriter,
                "Centinela-OS: IOMMU unit {unit} did not confirm an invalidation: {error:?}.\r\n"
            );
            false
        }
    }
}

/// Global context-cache and IOTLB invalidation (and interrupt entry cache
/// when remapping is on) through the queue, or the registers before the
/// queue is enabled. True only if the unit confirmed it. Runs under the
/// unit's lock: the queue, the wait word and the invalidation registers are
/// shared by every CPU.
fn invalidate_unit(unit: usize, registers: &Registers) -> bool {
    UNITS[unit].with(|state| {
        if QUEUES[unit].load(Ordering::Relaxed) == 0 {
            return invalidate_all(registers);
        }
        flush_write_buffer(registers);
        // Context cache (type 1) and IOTLB (type 2), global granularity,
        // with drain-reads/drain-writes for the IOTLB; IEC (type 4), global.
        let descriptors = [[1 | 1 << 4, 0], [2 | 1 << 4 | 1 << 6 | 1 << 7, 0], [4, 0]];
        let count = if IRT.load(Ordering::Relaxed) != 0 {
            3
        } else {
            2
        };
        submit(unit, registers, state, &descriptors[..count])
    })
}

fn enable_unit(
    unit: usize,
    registers: &Registers,
    root_table: PhysAddr,
    queue: Option<PhysAddr>,
    irt: Option<PhysAddr>,
) -> Result<(), &'static str> {
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
    if let Some(queue) = queue {
        registers.write64(REG_IQT, 0);
        // 128-bit descriptors, queue size 2^0 pages.
        registers.write64(REG_IQA, queue.get());
        UNITS[unit].with(RingState::reset);
        registers.command(GCMD_QIE);
        if !registers.wait32(REG_GSTS, GCMD_QIE, true) {
            return Err("queued invalidation not enabled");
        }
        QUEUES[unit].store(queue.get(), Ordering::Relaxed);
    }
    if let Some(irt) = irt {
        // xAPIC format (EIME = 0); size field 7 = 2^(7+1) = 256 entries.
        registers.write64(REG_IRTA, irt.get() | 7);
        registers.command(GCMD_SIRTP);
        if !registers.wait32(REG_GSTS, GCMD_SIRTP, true) {
            return Err("interrupt remapping table pointer not latched");
        }
        if !UNITS[unit].with(|state| submit(unit, registers, state, &[[4, 0]])) {
            return Err("interrupt entry cache invalidation failed");
        }
        registers.command(GCMD_IRE);
        if !registers.wait32(REG_GSTS, GCMD_IRE, true) {
            return Err("interrupt remapping not enabled");
        }
        if registers.read32(REG_GSTS) & GSTS_CFIS != 0 {
            return Err("compatibility-format interrupts still allowed");
        }
    }
    registers.command(GCMD_TE);
    if !registers.wait32(REG_GSTS, GCMD_TE, true) {
        return Err("translation enable not confirmed");
    }
    Ok(())
}

const NO_IOMMU_POLICY: &str = "IOMMU: fail-closed DMA policy: without remapping no driver is granted DMA; Bus Master stays cleared on every PCI function.\r\n";

/// True if a DMA-remapping unit (VT-d or AMD-Vi) is translating. Without
/// one no domain can exist and no device may master the bus.
pub(crate) fn available() -> bool {
    UNIT_COUNT.load(Ordering::Relaxed) != 0 || crate::amdvi::active()
}

/// Discovers and enables every DMA-remapping unit. Returns `false` to fail
/// the boot.
pub(crate) fn init<R: PhysicalReader>(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: u64,
    reader: Option<(&R, u64)>,
) -> bool {
    HHDM.store(hhdm, Ordering::Relaxed);
    let mut writer = SerialWriter;
    let Some((reader, rsdp)) = reader else {
        serial_write("IOMMU: no ACPI tables; DMA is not remapped on this machine.\r\n");
        serial_write(NO_IOMMU_POLICY);
        return true;
    };
    let table = match acpi::find_table(reader, rsdp, b"DMAR") {
        Ok(table) => table,
        Err(AcpiError::NotFound) => {
            // No Intel VT-d: try AMD-Vi.
            return match crate::amdvi::init(memory, kernel_root, hhdm, reader, rsdp) {
                Some(ok) => ok,
                None => {
                    serial_write(
                        "IOMMU: no DMAR or IVRS table; DMA is not remapped on this machine.\r\n",
                    );
                    serial_write(NO_IOMMU_POLICY);
                    true
                }
            };
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
    let mut queued = true;
    let mut remapping = true;
    // Pass 1: map every unit's registers and learn what all of them support.
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
        let ecap = registers.read64(REG_ECAP);
        sagaw &= (registers.read64(REG_CAP) >> 8) & 0x1f;
        coherent &= ecap & 1 != 0;
        queued &= ecap & ECAP_QI != 0;
        remapping &= ecap & ECAP_QI != 0 && ecap & ECAP_IR != 0;
        let index = UNIT_COUNT.load(Ordering::Relaxed);
        UNIT_WINDOWS[index].store(window, Ordering::Relaxed);
        UNIT_COUNT.store(index + 1, Ordering::Relaxed);
    }
    // Shared frames: wait-status words and the interrupt remapping table.
    let frame = |memory: &mut HhdmFrameMemory<'_, '_>| memory.allocate_zeroed_table_frame().ok();
    if queued {
        let Some(status) = frame(memory) else {
            return false;
        };
        WAIT_STATUS.store(status.get(), Ordering::Relaxed);
    }
    let irt = if remapping { frame(memory) } else { None };
    if remapping && irt.is_none() {
        return false;
    }
    // Pass 2: enable translation (and queued invalidation and interrupt
    // remapping where every unit supports them).
    for (index, unit) in units[..dmar.unit_count].iter().enumerate() {
        let registers = Registers(UNIT_WINDOWS[index].load(Ordering::Relaxed));
        let version = registers.read32(REG_VERSION);
        let queue = if queued { frame(memory) } else { None };
        if queued && queue.is_none() {
            return false;
        }
        if let Err(reason) = enable_unit(index, &registers, root_table, queue, irt) {
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
    if let Some(irt) = irt {
        IRT.store(irt.get(), Ordering::Relaxed);
        serial_write(
            "IOMMU: interrupt remapping enabled (remappable format only; compatibility format blocked).\r\n",
        );
    } else {
        serial_write(
            "IOMMU: interrupt remapping unsupported by this hardware; interrupts not remapped.\r\n",
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

/// Global invalidation on every unit; true only if all of them confirmed
/// it. Every unit is tried even after one fails.
fn invalidate() -> bool {
    let mut confirmed = true;
    let count = UNIT_COUNT.load(Ordering::Relaxed);
    for (unit, window) in UNIT_WINDOWS.iter().enumerate().take(count) {
        let registers = Registers(window.load(Ordering::Relaxed));
        confirmed &= invalidate_unit(unit, &registers);
    }
    confirmed
}

/// True once interrupt remapping is active on every unit.
pub(crate) fn interrupt_remapping() -> bool {
    IRT.load(Ordering::Relaxed) != 0
}

/// Programs remapping-table entry `index`: fixed delivery of `vector` to
/// the local APIC `destination`, edge or level triggered. When `source` is
/// given, the hardware checks the requester ID, so only that PCI function
/// can raise the entry. Returns false if remapping is off or the
/// invalidation failed.
pub(crate) fn program_interrupt(
    index: u16,
    vector: u8,
    destination: u8,
    level: bool,
    source: Option<u16>,
) -> bool {
    let irt = IRT.load(Ordering::Relaxed);
    if irt == 0 || index >= IRT_ENTRIES {
        return false;
    }
    // Low: present, physical destination mode, fixed delivery, trigger mode,
    // vector, xAPIC destination in bits 47:40.
    let low = 1 | u64::from(level) << 4 | u64::from(vector) << 16 | u64::from(destination) << 40;
    // High: source-id with SVT = 01 (verify requester ID, all bits).
    let high = source.map_or(0, |sid| u64::from(sid) | 1 << 18);
    let entry = hhdm_pointer(irt + u64::from(index) * 16);
    // SAFETY: `index` < IRT_ENTRIES, inside the kernel-owned IRT page.
    // Present (low) is written last so the entry is never half-valid.
    unsafe {
        entry.write_volatile(0);
        entry.add(1).write_volatile(high);
        entry.write_volatile(low);
        core::arch::x86_64::_mm_clflush(entry as *const u8);
    }
    invalidate()
}

/// Present context-table frame for `bus`, if the root table has one.
fn present_context_table(memory: &HhdmFrameMemory<'_, '_>, bus: u8) -> Option<PhysAddr> {
    let root = PhysAddr::new(ROOT_TABLE.load(Ordering::Relaxed)).ok()?;
    // Root entries are 128-bit; the low word holds the context-table pointer.
    let low = read_entry(memory, root, u64::from(bus) * 2);
    if low & 1 != 0 {
        PhysAddr::new(low & ADDRESS_MASK).ok()
    } else {
        None
    }
}

/// Present context-table frame for `bus`, created on demand.
fn context_table(memory: &mut HhdmFrameMemory<'_, '_>, bus: u8) -> Option<PhysAddr> {
    if let Some(table) = present_context_table(memory, bus) {
        return Some(table);
    }
    let root = PhysAddr::new(ROOT_TABLE.load(Ordering::Relaxed)).ok()?;
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
    TOPOLOGY.with(|_| {
        if crate::amdvi::active() {
            return if domain == 0 {
                None
            } else {
                crate::amdvi::attach(memory, device, domain)
            };
        }
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
        if !ok {
            // Not confirmed: the device goes back to a non-present entry. A
            // unit may have cached the new root, so that frame is quarantined
            // (left allocated) instead of being freed for reuse.
            write_entry(memory, context, index, 0);
            write_entry(memory, context, index + 1, 0);
            let _ = invalidate();
            return None;
        }
        Some(root)
    })
}

/// Maps one 4 KiB page at `iova` → `physical` (read/write) in a domain.
pub(crate) fn map(
    memory: &mut HhdmFrameMemory<'_, '_>,
    domain_root: PhysAddr,
    iova: u64,
    physical: PhysAddr,
) -> bool {
    if crate::amdvi::active() {
        return crate::amdvi::map(memory, domain_root, iova, physical);
    }
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

/// Removes the 4 KiB mapping at `iova`, if any. Returns true only when the
/// invalidation was confirmed: only then may the frame behind it be freed
/// or reused (otherwise the caller quarantines it).
pub(crate) fn unmap(
    memory: &mut HhdmFrameMemory<'_, '_>,
    domain_root: PhysAddr,
    iova: u64,
) -> bool {
    if crate::amdvi::active() {
        return crate::amdvi::unmap(memory, domain_root, iova);
    }
    let levels = LEVELS.load(Ordering::Relaxed) as u64;
    let mut table = domain_root;
    for level in (1..levels).rev() {
        let entry = read_entry(memory, table, (iova >> (12 + 9 * level)) & 0x1ff);
        match PhysAddr::new(entry & ADDRESS_MASK) {
            Ok(next) if entry & ENTRY_READ != 0 => table = next,
            // No table on the path: nothing was ever mapped here.
            _ => return invalidate(),
        }
    }
    write_entry(memory, table, (iova >> 12) & 0x1ff, 0) && invalidate()
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

/// Outcome of `detach`.
pub(crate) struct Detached {
    /// DMA faults found pending (proof that confinement held).
    pub(crate) faults: u64,
    /// True only if every unit confirmed that it no longer holds any
    /// translation of the domain. When false, the domain's tables were
    /// quarantined and the caller must do the same with its DMA frames.
    pub(crate) isolated: bool,
}

/// Removes the device's domain: afterwards every DMA it issues is blocked
/// and faulted. Must run before the driver's DMA frames are freed, and they
/// may be freed only if the result says `isolated`.
///
/// Order: Bus Master off, block the device in the tables, invalidate and
/// wait for every unit to confirm, and only then release the tables.
pub(crate) fn detach(
    memory: &mut HhdmFrameMemory<'_, '_>,
    device: crate::pci::Device,
    root: Option<PhysAddr>,
) -> Detached {
    crate::pci::disable_dma(device);
    let detached = TOPOLOGY.with(|_| {
        if crate::amdvi::active() {
            let (faults, isolated) = crate::amdvi::detach(memory, device, root);
            return Detached { faults, isolated };
        }
        let Some(context) = present_context_table(memory, device.bus) else {
            // Nothing attached on this bus: the device was already blocked.
            return Detached {
                faults: 0,
                isolated: invalidate(),
            };
        };
        let index = u64::from(device.devfn) * 2;
        let low = read_entry(memory, context, index);
        // A non-present context entry faults every request of the device.
        let mut blocked =
            write_entry(memory, context, index, 0) & write_entry(memory, context, index + 1, 0);
        // Unlink the bus's context table once no device uses it any more.
        let mut release_context = false;
        if (0..512).all(|entry| read_entry(memory, context, entry) == 0)
            && let Ok(root_table) = PhysAddr::new(ROOT_TABLE.load(Ordering::Relaxed))
        {
            release_context = write_entry(memory, root_table, u64::from(device.bus) * 2, 0);
            blocked &= release_context;
        }
        let isolated = blocked && invalidate();
        // Frames go back to the allocator only when no unit can still walk
        // or cache them; otherwise they stay allocated (quarantine).
        if isolated {
            if release_context {
                let _ = memory.release_table_frame(context);
            }
            if low & 1 != 0
                && let Ok(domain) = PhysAddr::new(low & ADDRESS_MASK)
            {
                free_tables(memory, domain, LEVELS.load(Ordering::Relaxed) as u64);
            }
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
        Detached { faults, isolated }
    });
    FAULTS_SEEN.fetch_add(detached.faults, Ordering::Relaxed);
    if !detached.isolated {
        let _ = write!(
            SerialWriter,
            "Centinela-OS: IOMMU isolation of {:02x}:{:02x}.{} not confirmed; its translation tables are quarantined (not freed).\r\n",
            device.bus,
            device.devfn >> 3,
            device.devfn & 7
        );
    }
    detached
}

/// DMA faults recorded so far (each detach counts the pending ones).
pub(crate) fn faults_seen() -> u64 {
    FAULTS_SEEN.load(Ordering::Relaxed)
}
