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

/// Issues commands on every unit and waits until each has consumed them.
fn command(words: [u64; 2]) -> bool {
    (0..COUNT.load(Ordering::Relaxed)).all(|unit| {
        let tail = read(unit, REG_COMMAND_TAIL) & 0xff0;
        let base = COMMANDS[unit].load(Ordering::Relaxed);
        // SAFETY: The command ring page belongs to the kernel (HHDM alias).
        unsafe {
            core::ptr::write_volatile(hhdm(base + tail), words[0]);
            core::ptr::write_volatile(hhdm(base + tail + 8), words[1]);
        }
        let next = (tail + 16) % PAGE_SIZE;
        write_register(unit, REG_COMMAND_TAIL, next);
        (0..10_000_000).any(|_| {
            let done = read(unit, REG_COMMAND_HEAD) & 0xff0 == next;
            if !done {
                core::hint::spin_loop();
            }
            done
        })
    })
}

fn invalidate_device(device_id: u16) -> bool {
    command([u64::from(device_id), 0x2 << 60])
}

fn invalidate_domain(domain: u16) -> bool {
    // All pages of the domain: address 0x7FFF_FFFF_FFFF_F000 with S=1, PDE=1.
    command([
        u64::from(domain) << 32 | 0x3 << 60,
        0x7fff_ffff_ffff_f000 | 0b11,
    ])
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
    let (Some(table), Ok(empty)) = (
        memory.allocate_contiguous_zeroed(DEVICE_TABLE_PAGES),
        memory.allocate_zeroed_table_frame(),
    ) else {
        serial_write("Centinela-OS: no memory for the AMD-Vi device table.\r\n");
        return Some(false);
    };
    DEVICE_TABLE.store(table.get(), Ordering::Relaxed);
    EMPTY_ROOT.store(empty.get(), Ordering::Relaxed);
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
pub(crate) fn attach(
    memory: &mut HhdmFrameMemory<'_, '_>,
    device: crate::pci::Device,
    domain: u16,
) -> Option<PhysAddr> {
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
    (invalidate_device(id) && invalidate_domain(domain)).then_some(root)
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
        && invalidate_domain(domain)
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

/// Blocks the device again, frees its tables and returns the I/O page
/// faults logged since the last call.
pub(crate) fn detach(
    memory: &mut HhdmFrameMemory<'_, '_>,
    device: crate::pci::Device,
    root: Option<PhysAddr>,
) -> u64 {
    let id = device_id(device);
    set_entry(id, blocked_entry());
    let _ = invalidate_device(id);
    if let Some(root) = root
        && let Some(domain) = domain_of(root)
    {
        let _ = invalidate_domain(domain);
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
    faults
}
