//! I/O APIC: routes device interrupts to Ring 3 drivers (phase 4, step 3).
//!
//! Deny-by-default: every redirection entry is masked at boot, so no device
//! interrupt reaches the CPU unless the kernel binds the line to a driver
//! that holds the corresponding grant. A delivered interrupt is masked again
//! by the kernel before the driver is notified, and only the bound driver can
//! re-arm it (`IrqAck`), so a stuck or hostile device cannot flood the CPU.

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use centinela_hal::apic;
use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_kernel::acpi::{self, Madt, PhysicalReader};
use centinela_kernel::memory::hhdm_backend::HhdmFrameMemory;
use centinela_kernel::memory::vmm::{PageMapping, PageTableMapper, PhysAddr};

static BASE: AtomicU64 = AtomicU64::new(0);
static GSI_BASE: AtomicU32 = AtomicU32::new(0);
static ENTRIES: AtomicU32 = AtomicU32::new(0);
static mut MADT: Madt = Madt {
    io_apic: None,
    overrides: [acpi::IsaOverride {
        source: 0,
        gsi: 0,
        flags: 0,
    }; acpi::MAX_OVERRIDES],
    override_count: 0,
};

const MASKED: u32 = 1 << 16;
const ACTIVE_LOW: u32 = 1 << 13;
const LEVEL: u32 = 1 << 15;

fn select(register: u32) -> *mut u32 {
    let base = BASE.load(Ordering::Relaxed);
    // SAFETY: `base` maps the I/O APIC page (UC, kernel only).
    unsafe { core::ptr::write_volatile(base as *mut u32, register) };
    (base + 0x10) as *mut u32
}

fn read(register: u32) -> u32 {
    // SAFETY: IOWIN of the mapped I/O APIC; IF=0 keeps select+access atomic.
    unsafe { core::ptr::read_volatile(select(register)) }
}

fn write(register: u32, value: u32) {
    // SAFETY: As in `read`.
    unsafe { core::ptr::write_volatile(select(register), value) }
}

/// Discovers the I/O APIC from the MADT, maps it and masks every line.
pub(crate) fn init<R: PhysicalReader>(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    reader: Option<(&R, u64)>,
) -> bool {
    let mut writer = SerialWriter;
    let Some((reader, rsdp)) = reader else {
        serial_write("IOAPIC: no ACPI tables; device interrupts unavailable.\r\n");
        return true;
    };
    let madt = match acpi::find_table(reader, rsdp, b"APIC").and_then(acpi::parse_madt) {
        Ok(madt) => madt,
        Err(error) => {
            let _ = write!(writer, "Centinela-OS: MADT rejected: {error:?}.\r\n");
            return false;
        }
    };
    let Some(io_apic) = madt.io_apic else {
        serial_write("IOAPIC: none described; device interrupts unavailable.\r\n");
        return true;
    };
    let Some(window) = crate::isolation::free_kernel_slot_address(memory, kernel_root) else {
        return false;
    };
    let Ok(mapping) = PageMapping::kernel_device(window, io_apic.address) else {
        return false;
    };
    if PageTableMapper::new(memory, kernel_root)
        .map_4k(mapping)
        .is_err()
    {
        serial_write("Centinela-OS: failed to map the I/O APIC.\r\n");
        return false;
    }
    BASE.store(window, Ordering::Relaxed);
    GSI_BASE.store(io_apic.gsi_base, Ordering::Relaxed);
    let entries = ((read(1) >> 16) & 0xff) + 1;
    ENTRIES.store(entries, Ordering::Relaxed);
    for index in 0..entries {
        write(0x10 + 2 * index, MASKED);
        write(0x11 + 2 * index, 0);
    }
    // SAFETY: Single CPU boot; written once before any interrupt is routed.
    unsafe { *core::ptr::addr_of_mut!(MADT) = madt };
    let _ = write!(
        writer,
        "IOAPIC: {entries} lines at GSI {}, all masked (deny-by-default); {} ISA overrides.\r\n",
        io_apic.gsi_base, madt.override_count
    );
    true
}

/// Redirection-table index for a legacy ISA IRQ, plus its low-word flags.
fn entry_for(isa_irq: u8) -> Option<(u32, u32)> {
    if BASE.load(Ordering::Relaxed) == 0 {
        return None;
    }
    // SAFETY: Written once during boot, read-only afterwards.
    let madt = unsafe { *core::ptr::addr_of!(MADT) };
    let (gsi, active_low, level) = madt.route_isa(isa_irq);
    let index = gsi.checked_sub(GSI_BASE.load(Ordering::Relaxed))?;
    if index >= ENTRIES.load(Ordering::Relaxed) {
        return None;
    }
    let mut flags = 0;
    if active_low {
        flags |= ACTIVE_LOW;
    }
    if level {
        flags |= LEVEL;
    }
    Some((index, flags))
}

/// Points ISA IRQ `isa_irq` at `vector` on the BSP, masked or not.
pub(crate) fn route(isa_irq: u8, vector: u8, masked: bool) -> bool {
    let Some((index, flags)) = entry_for(isa_irq) else {
        return false;
    };
    let mask = if masked { MASKED } else { 0 };
    if crate::iommu::interrupt_remapping() {
        // Remappable format: the entry only names remapping-table index
        // `index`; the IOMMU supplies vector and destination. The vector
        // field must still match for EOI broadcast.
        let destination = (apic::local_id() & 0xff) as u8;
        if index >= u32::from(crate::iommu::IRT_ENTRIES)
            || !crate::iommu::program_interrupt(
                index as u16,
                vector,
                destination,
                flags & LEVEL != 0,
                None,
            )
        {
            return false;
        }
        write(0x11 + 2 * index, (index & 0x7fff) << 17 | 1 << 16);
        write(
            0x10 + 2 * index,
            u32::from(vector) | flags | mask | ((index >> 15) & 1) << 11,
        );
    } else {
        write(0x11 + 2 * index, apic::local_id() << 24);
        write(0x10 + 2 * index, u32::from(vector) | flags | mask);
    }
    true
}

/// Masks or unmasks a routed line, preserving its vector and flags.
pub(crate) fn set_masked(isa_irq: u8, masked: bool) {
    if let Some((index, _)) = entry_for(isa_irq) {
        let low = read(0x10 + 2 * index);
        write(
            0x10 + 2 * index,
            if masked { low | MASKED } else { low & !MASKED },
        );
    }
}
