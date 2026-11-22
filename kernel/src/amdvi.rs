//! AMD-Vi (AMD I/O Virtualization Technology) DMA remapping, deny-by-default.
//!
//! Every one of the 65,536 device table entries is valid and points at an
//! empty page table, so any DMA from any device faults until the kernel
//! attaches the device to its own domain (same policy as VT-d). Changes are
//! made visible with INVALIDATE_DEVTAB_ENTRY / INVALIDATE_IOMMU_PAGES
//! commands, and I/O page faults are counted from the event log.
//!
//! Note: on AMD-Vi a device table entry with V=0 means *pass-through*, which
//! is why every entry is written valid before translation is enabled.

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_kernel::acpi::{self, AcpiError, PhysicalReader};
use centinela_kernel::dma::amdvi as encode;
use centinela_kernel::dma::{CommandRing, RING_ENTRIES, RingState, SpinLock, submit};
use centinela_kernel::memory::hhdm_backend::HhdmFrameMemory;
use centinela_kernel::memory::vmm::{
    PAGE_SIZE, PageMapping, PageTableMapper, PageTableMutationMemory, PhysAddr,
};

const MAX_UNITS: usize = 4;
const DEVICE_TABLE_PAGES: usize = 512; // 65,536 entries x 32 bytes
const REG_DEVICE_TABLE: u64 = 0x00;
const REG_COMMAND_BASE: u64 = 0x08;
const REG_EVENT_BASE: u64 = 0x10;
const REG_CONTROL: u64 = 0x18;
const REG_COMMAND_HEAD: u64 = 0x2000;
const REG_COMMAND_TAIL: u64 = 0x2008;
const REG_EVENT_HEAD: u64 = 0x2010;
const REG_EVENT_TAIL: u64 = 0x2018;
const CONTROL_ENABLE: u64 = 1 << 0;
const CONTROL_EVENT_LOG: u64 = 1 << 2;
const CONTROL_COMMAND_BUFFER: u64 = 1 << 12;
/// 4 KiB rings: 256 command entries (2^8), 256 event entries.
const RING_LENGTH_EXP: u64 = 8;
const LEVELS: u64 = 3;
const PRESENT: u64 = 1 << 0;
const TRANSLATION_VALID: u64 = 1 << 1;
const READ: u64 = 1 << 61;
const WRITE: u64 = 1 << 62;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;

static WINDOWS: [AtomicU64; MAX_UNITS] = [const { AtomicU64::new(0) }; MAX_UNITS];
static COMMANDS: [AtomicU64; MAX_UNITS] = [const { AtomicU64::new(0) }; MAX_UNITS];
static EVENTS: [AtomicU64; MAX_UNITS] = [const { AtomicU64::new(0) }; MAX_UNITS];
/// Frame holding one COMPLETION_WAIT store word per unit.
static WAIT: AtomicU64 = AtomicU64::new(0);
/// Per-unit command-ring lock: tail, token and the ring itself are shared by
/// every CPU, so a batch is queued and confirmed under its unit's lock.
static RINGS: [SpinLock<RingState>; MAX_UNITS] =
    [const { SpinLock::new(RingState::new()) }; MAX_UNITS];
/// Bound on each wait for ring space and for a completion.
const POLL_LIMIT: u32 = 10_000_000;
static COUNT: AtomicUsize = AtomicUsize::new(0);
static DEVICE_TABLE: AtomicU64 = AtomicU64::new(0);
static EMPTY_ROOT: AtomicU64 = AtomicU64::new(0);
static HHDM: AtomicU64 = AtomicU64::new(0);
/// Domain of each attached root (root physical address, domain id).
static DOMAINS: [(AtomicU64, AtomicU64); 16] =
    [const { (AtomicU64::new(0), AtomicU64::new(0)) }; 16];

fn mmio(unit: usize, register: u64) -> *mut u64 {
    (WINDOWS[unit].load(Ordering::Relaxed) + register) as *mut u64
}

fn read(unit: usize, register: u64) -> u64 {
    // SAFETY: The unit's register window is mapped (UC, kernel only).
    unsafe { core::ptr::read_volatile(mmio(unit, register)) }
}

fn write_register(unit: usize, register: u64, value: u64) {
    // SAFETY: As in `read`.
    unsafe { core::ptr::write_volatile(mmio(unit, register), value) }
}

fn hhdm(physical: u64) -> *mut u64 {
    (HHDM.load(Ordering::Relaxed) + physical) as *mut u64
}

/// One unit's command ring, as the hardware sees it. Used only while the
/// unit's `RINGS` lock is held.
struct UnitRing(usize);

impl UnitRing {
    fn wait_word(&self) -> *mut u64 {
        hhdm(WAIT.load(Ordering::Relaxed) + self.0 as u64 * 8)
    }
}

impl CommandRing for UnitRing {
    fn head(&mut self) -> u64 {
        (read(self.0, REG_COMMAND_HEAD) & 0xff0) >> 4
    }

    fn store(&mut self, index: u64, entry: [u64; 2]) {
        let base = COMMANDS[self.0].load(Ordering::Relaxed);
        let slot = hhdm(base + (index % RING_ENTRIES) * 16);
        // SAFETY: The slot lies inside the command ring page, which belongs
        // to the kernel (HHDM alias); the unit reads only up to its tail.
        unsafe {
            slot.write_volatile(entry[0]);
            slot.add(1).write_volatile(entry[1]);
        }
    }

    fn publish(&mut self, tail: u64) {
        // The ring stores must be globally visible before the doorbell.
        core::sync::atomic::fence(Ordering::SeqCst);
        write_register(self.0, REG_COMMAND_TAIL, tail << 4);
    }

    fn wait_command(&mut self, token: u32) -> [u64; 2] {
        // SAFETY: Kernel-owned wait frame, HHDM-mapped; one word per unit.
        unsafe { self.wait_word().write_volatile(0) };
        encode::completion_wait(
            WAIT.load(Ordering::Relaxed) + self.0 as u64 * 8,
            u64::from(token),
        )
    }

    fn completion(&mut self) -> u32 {
        // SAFETY: As in `wait_command`.
        unsafe { self.wait_word().read_volatile() as u32 }
    }

    fn faulted(&mut self) -> bool {
        // A unit that stops on an illegal command never stores the token:
        // the bounded wait reports it.
        false
    }
}

/// Queues `batch` on every unit, each followed by a COMPLETION_WAIT, and
/// returns true only when every unit stored its wait token: the commands
/// have completed, not merely been fetched. Every unit is tried even after
/// one fails.
fn commands(batch: &[[u64; 2]]) -> bool {
    let mut confirmed = true;
    let count = COUNT.load(Ordering::Relaxed);
    for (unit, ring) in RINGS.iter().enumerate().take(count) {
        let result = ring.with(|state| submit(&mut UnitRing(unit), state, batch, POLL_LIMIT));
        if let Err(error) = result {
            let _ = write!(
                SerialWriter,
                "Centinela-OS: AMD-Vi unit {unit} did not confirm its commands: {error:?}.\r\n"
            );
        }
        confirmed &= result.is_ok();
    }
    confirmed
}

fn blocked_entry() -> [u64; 4] {
    let root = EMPTY_ROOT.load(Ordering::Relaxed);
    [
        PRESENT | TRANSLATION_VALID | LEVELS << 9 | root | READ | WRITE,
        0,
        0,
        0,
    ]
}

fn set_entry(device_id: u16, entry: [u64; 4]) {
    let base = DEVICE_TABLE.load(Ordering::Relaxed) + u64::from(device_id) * 32;
    // SAFETY: The device table is kernel-owned and HHDM-mapped. The first
    // quadword (valid bit) is written last so the IOMMU never sees a mix.
    unsafe {
        for (index, word) in entry.iter().enumerate().skip(1) {
            core::ptr::write_volatile(hhdm(base + index as u64 * 8), *word);
        }
        core::ptr::write_volatile(hhdm(base), entry[0]);
    }
}

/// Discovers AMD-Vi units from IVRS. `None` if the machine has no IVRS.
pub(crate) fn init<R: PhysicalReader>(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm_base: u64,
    reader: &R,
    rsdp: u64,
) -> Option<bool> {
    let mut writer = SerialWriter;
    HHDM.store(hhdm_base, Ordering::Relaxed);
    let table = match acpi::find_table(reader, rsdp, b"IVRS") {
        Ok(table) => table,
        Err(AcpiError::NotFound) => return None,
        Err(error) => {
            let _ = write!(writer, "Centinela-OS: IVRS table rejected: {error:?}.\r\n");
            return Some(false);
        }
    };
    let mut bases = [0u64; MAX_UNITS];
    let count = match acpi::parse_ivrs(table, &mut bases) {
        Ok(0) => {
            serial_write("Centinela-OS: IVRS lists no IOMMU.\r\n");
            return Some(false);
        }
        Ok(count) => count,
        Err(error) => {
            let _ = write!(writer, "Centinela-OS: IVRS table rejected: {error:?}.\r\n");
            return Some(false);
        }
    };
    let (Some(table), Ok(empty), Ok(wait)) = (
        memory.allocate_contiguous_zeroed(DEVICE_TABLE_PAGES),
        memory.allocate_zeroed_table_frame(),
        memory.allocate_zeroed_table_frame(),
    ) else {
        serial_write("Centinela-OS: no memory for the AMD-Vi device table.\r\n");
        return Some(false);
    };
    DEVICE_TABLE.store(table.get(), Ordering::Relaxed);
    EMPTY_ROOT.store(empty.get(), Ordering::Relaxed);
    WAIT.store(wait.get(), Ordering::Relaxed);
    let blocked = blocked_entry();
    for device_id in 0..=u16::MAX {
        set_entry(device_id, blocked);
    }
    for (unit, &base) in bases[..count].iter().enumerate() {
        let Some(window) = crate::isolation::free_kernel_slot_address(memory, kernel_root) else {
            return Some(false);
        };
        // Registers span 16 KiB (0x0000-0x3FFF).
        for page in 0..4 {
            let Ok(mapping) =
                PageMapping::kernel_device(window + page * PAGE_SIZE, base + page * PAGE_SIZE)
            else {
                return Some(false);
            };
            if PageTableMapper::new(memory, kernel_root)
                .map_4k(mapping)
                .is_err()
            {
                return Some(false);
            }
        }
        let (Ok(commands), Ok(events)) = (
            memory.allocate_zeroed_table_frame(),
            memory.allocate_zeroed_table_frame(),
        ) else {
            return Some(false);
        };
        WINDOWS[unit].store(window, Ordering::Relaxed);
        COMMANDS[unit].store(commands.get(), Ordering::Relaxed);
        EVENTS[unit].store(events.get(), Ordering::Relaxed);
        COUNT.store(unit + 1, Ordering::Relaxed);
        write_register(unit, REG_CONTROL, 0);
        write_register(
            unit,
            REG_DEVICE_TABLE,
            table.get() | (DEVICE_TABLE_PAGES as u64 - 1),
        );
        write_register(
            unit,
            REG_COMMAND_BASE,
            commands.get() | RING_LENGTH_EXP << 56,
        );
        write_register(unit, REG_EVENT_BASE, events.get() | RING_LENGTH_EXP << 56);
        write_register(unit, REG_COMMAND_HEAD, 0);
        write_register(unit, REG_COMMAND_TAIL, 0);
        RINGS[unit].with(RingState::reset);
        write_register(unit, REG_EVENT_HEAD, 0);
        write_register(unit, REG_EVENT_TAIL, 0);
        write_register(
            unit,
            REG_CONTROL,
            CONTROL_ENABLE | CONTROL_EVENT_LOG | CONTROL_COMMAND_BUFFER,
        );
        if read(unit, REG_CONTROL) & CONTROL_ENABLE == 0 {
            let _ = write!(
                writer,
                "Centinela-OS: AMD-Vi unit {base:#x} did not enable.\r\n"
            );
            return Some(false);
        }
        let _ = write!(writer, "IOMMU: AMD-Vi unit {base:#x} translating.\r\n");
    }
    let _ = write!(
        writer,
        "IOMMU: DMA remapping enabled on {count} unit(s), deny-by-default (AMD-Vi: all 65536 device entries blocked).\r\n"
    );
    Some(true)
}

pub(crate) fn active() -> bool {
    COUNT.load(Ordering::Relaxed) != 0
}

fn device_id(device: crate::pci::Device) -> u16 {
    u16::from(device.bus) << 8 | u16::from(device.devfn)
}

/// Gives `device` its own empty domain; returns the domain's page-table root.
/// The caller (`iommu::attach`) holds the topology lock.
pub(crate) fn attach(
    memory: &mut HhdmFrameMemory<'_, '_>,
    device: crate::pci::Device,
    domain: u16,
) -> Option<PhysAddr> {
    // A domain ID still held by a slot is either in use or was retired
    // without a confirmed invalidation (stale IOTLB entries may carry it):
    // it is never handed out again.
    if DOMAINS.iter().any(|(root, id)| {
        root.load(Ordering::Relaxed) != 0 && id.load(Ordering::Relaxed) == u64::from(domain)
    }) {
        return None;
    }
    let slot = DOMAINS
        .iter()
        .find(|(root, _)| root.load(Ordering::Relaxed) == 0)?;
    let root = memory.allocate_zeroed_table_frame().ok()?;
    slot.0.store(root.get(), Ordering::Relaxed);
    slot.1.store(u64::from(domain), Ordering::Relaxed);
    let id = device_id(device);
    set_entry(
        id,
        [
            PRESENT | TRANSLATION_VALID | LEVELS << 9 | root.get() | READ | WRITE,
            u64::from(domain),
            0,
            0,
        ],
    );
    if commands(&[
        encode::invalidate_device(id),
        encode::invalidate_domain(domain),
    ]) {
        return Some(root);
    }
    // Not confirmed: the device goes back to the blocked entry. The unit may
    // have cached the new root under this domain ID, so the frame is
    // quarantined (left allocated) and the slot keeps the ID retired.
    set_entry(id, blocked_entry());
    None
}

fn domain_of(root: PhysAddr) -> Option<u16> {
    DOMAINS
        .iter()
        .find(|(r, _)| r.load(Ordering::Relaxed) == root.get())
        .map(|(_, d)| d.load(Ordering::Relaxed) as u16)
}

/// Maps one 4 KiB page at `iova` → `physical` (read/write) in a domain.
pub(crate) fn map(
    memory: &mut HhdmFrameMemory<'_, '_>,
    root: PhysAddr,
    iova: u64,
    physical: PhysAddr,
) -> bool {
    let Some(domain) = domain_of(root) else {
        return false;
    };
    let mut table = root;
    for level in (2..=LEVELS).rev() {
        let index = (iova >> (12 + 9 * (level - 1))) & 0x1ff;
        let entry = PageTableMutationMemory::read_entry(memory, table, index as u16).unwrap_or(0);
        table = if entry & PRESENT != 0 {
            match PhysAddr::new(entry & ADDRESS) {
                Ok(next) => next,
                Err(_) => return false,
            }
        } else {
            let Ok(next) = memory.allocate_zeroed_table_frame() else {
                return false;
            };
            let value = PRESENT | (level - 1) << 9 | next.get() | READ | WRITE;
            if PageTableMutationMemory::write_entry(memory, table, index as u16, value).is_err() {
                return false;
            }
            next
        };
    }
    let index = (iova >> 12) & 0x1ff;
    let leaf = PRESENT | physical.get() | READ | WRITE;
    PageTableMutationMemory::write_entry(memory, table, index as u16, leaf).is_ok()
        && commands(&[encode::invalidate_domain(domain)])
}

/// Removes the 4 KiB mapping at `iova`, if any. Returns true only when the
/// invalidation was confirmed: only then may the frame behind it be reused.
pub(crate) fn unmap(memory: &mut HhdmFrameMemory<'_, '_>, root: PhysAddr, iova: u64) -> bool {
    let Some(domain) = domain_of(root) else {
        return false;
    };
    let mut table = root;
    for level in (2..=LEVELS).rev() {
        let index = (iova >> (12 + 9 * (level - 1))) & 0x1ff;
        let entry = PageTableMutationMemory::read_entry(memory, table, index as u16).unwrap_or(0);
        match PhysAddr::new(entry & ADDRESS) {
            Ok(next) if entry & PRESENT != 0 => table = next,
            // No table on the path: nothing was ever mapped here.
            _ => return commands(&[encode::invalidate_domain(domain)]),
        }
    }
    let index = (iova >> 12) & 0x1ff;
    PageTableMutationMemory::write_entry(memory, table, index as u16, 0).is_ok()
        && commands(&[encode::invalidate_domain(domain)])
}

fn free_tables(memory: &mut HhdmFrameMemory<'_, '_>, table: PhysAddr, level: u64) {
    if level > 1 {
        for index in 0..512u16 {
            let entry = PageTableMutationMemory::read_entry(memory, table, index).unwrap_or(0);
            if entry & PRESENT != 0
                && let Ok(next) = PhysAddr::new(entry & ADDRESS)
            {
                free_tables(memory, next, level - 1);
            }
        }
    }
    let _ = memory.release_table_frame(table);
}

/// Prints the first logged event of a domain (type, device, address): the
/// detail needed to diagnose a DMA failure from a photo of the screen.
fn report_event(unit: usize, head: u64) {
    let base = EVENTS[unit].load(Ordering::Relaxed);
    // SAFETY: The event ring page belongs to the kernel (HHDM alias).
    let (low, address) = unsafe {
        (
            core::ptr::read_volatile(hhdm(base + head)),
            core::ptr::read_volatile(hhdm(base + head + 8)),
        )
    };
    let code = (low >> 60) & 0xf;
    let kind = match code {
        1 => "illegal device table entry",
        2 => "I/O page fault",
        3 => "device table hardware error",
        4 => "page table hardware error",
        5 => "illegal command",
        6 => "command hardware error",
        _ => "other",
    };
    let device = low & 0xffff;
    let _ = write!(
        SerialWriter,
        "IOMMU: AMD-Vi event {code} ({kind}) device {:02x}:{:02x}.{} address {address:#x} flags {:#x}\r\n",
        device >> 8,
        (device >> 3) & 0x1f,
        device & 7,
        (low >> 48) & 0xfff,
    );
}

/// Blocks the device again and returns the I/O page faults logged since the
/// last call, plus whether isolation was confirmed. The domain's tables are
/// freed only in that case: if any unit failed to confirm the invalidation
/// (COMPLETION_WAIT), it may still walk them, so they stay allocated
/// (quarantined) and the caller must not reuse the frames mapped in them.
/// The caller (`iommu::detach`) holds the topology lock and has already
/// cleared the device's Bus Master bit.
pub(crate) fn detach(
    memory: &mut HhdmFrameMemory<'_, '_>,
    device: crate::pci::Device,
    root: Option<PhysAddr>,
) -> (u64, bool) {
    let id = device_id(device);
    set_entry(id, blocked_entry());
    let domain = root.and_then(domain_of);
    let isolated = match domain {
        Some(domain) => commands(&[
            encode::invalidate_device(id),
            encode::invalidate_domain(domain),
        ]),
        None => commands(&[encode::invalidate_device(id)]),
    };
    // Without confirmation the slot stays occupied: its tables are
    // quarantined and its domain ID is never recycled (see `attach`).
    if let Some(root) = root
        && isolated
        && domain.is_some()
    {
        if let Some(slot) = DOMAINS
            .iter()
            .find(|(r, _)| r.load(Ordering::Relaxed) == root.get())
        {
            slot.0.store(0, Ordering::Relaxed);
        }
        free_tables(memory, root, LEVELS);
    }
    let mut faults = 0;
    for unit in 0..COUNT.load(Ordering::Relaxed) {
        let tail = read(unit, REG_EVENT_TAIL) & 0xff0;
        let mut head = read(unit, REG_EVENT_HEAD) & 0xff0;
        while head != tail {
            if faults == 0 {
                report_event(unit, head);
            }
            faults += 1;
            head = (head + 16) % PAGE_SIZE;
        }
        write_register(unit, REG_EVENT_HEAD, tail);
    }
    (faults, isolated && (root.is_none() || domain.is_some()))
}
