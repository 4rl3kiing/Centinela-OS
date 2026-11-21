//! Power control: ACPI S5 power-off and reset (phase 6).
//!
//! The FADT and the DSDT's `\_S5` object are parsed defensively (see
//! `centinela_kernel::acpi::parse_power`). The ports found there become
//! kernel-owned: no driver grant may include them, so no Ring 3 task can
//! power the machine off or reset it.
//!
//! After a successful self-test the kernel normally halts so the log stays
//! on screen. Only when running under a hypervisor *and* the QEMU fw_cfg
//! file `opt/centinela/poweroff` exists does it power off, which lets the
//! boot tests finish without waiting for a timeout. On bare metal the fw_cfg
//! ports are never touched.

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_kernel::acpi::{self, PhysicalReader};

/// (pm1a << 16) | pm1b.
static PM1: AtomicU32 = AtomicU32::new(0);
/// Bit 16 = present; bits 8..11 SLP_TYPa, 0..3 SLP_TYPb.
static S5: AtomicU32 = AtomicU32::new(0);
/// Bit 32 = present; bits 16..32 port, 0..8 value.
static RESET: AtomicU64 = AtomicU64::new(0);

const SLP_EN: u16 = 1 << 13;

fn outb(port: u16, value: u8) {
    // SAFETY: CPL 0; callers pass ports owned by the kernel.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags))
    }
}

fn outw(port: u16, value: u16) {
    // SAFETY: As in `outb`.
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags))
    }
}

fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: As in `outb`.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags))
    }
    value
}

/// Reads power-control data from ACPI. A machine without usable tables
/// still boots; power-off then falls back to halting.
pub(crate) fn init<R: PhysicalReader>(reader: Option<(&R, u64)>) {
    let Some((reader, rsdp)) = reader else {
        serial_write("Power: no ACPI tables; power-off unavailable.\r\n");
        return;
    };
    match acpi::parse_power(reader, rsdp) {
        Ok(power) => {
            PM1.store(
                u32::from(power.pm1a_control) << 16 | u32::from(power.pm1b_control),
                Ordering::Release,
            );
            if let Some((a, b)) = power.s5 {
                S5.store(
                    1 << 16 | u32::from(a) << 8 | u32::from(b),
                    Ordering::Release,
                );
            }
            if let Some((port, value)) = power.reset_port {
                RESET.store(
                    1 << 32 | u64::from(port) << 16 | u64::from(value),
                    Ordering::Release,
                );
            }
            let _ = write!(
                SerialWriter,
                "Power: ACPI S5 {} (PM1a control {:#x}); reset {}.\r\n",
                if power.s5.is_some() && power.pm1a_control != 0 {
                    "available"
                } else {
                    "unavailable"
                },
                power.pm1a_control,
                if power.reset_port.is_some() {
                    "via ACPI register"
                } else {
                    "via 0xCF9"
                },
            );
        }
        Err(error) => {
            let _ = write!(
                SerialWriter,
                "Power: FADT unusable ({error:?}); power-off unavailable.\r\n"
            );
        }
    }
}

/// True if `[base, base + count)` touches a port the kernel uses for power
/// control (so it can never be granted to a driver).
pub(crate) fn owns_port_range(base: u32, count: u32) -> bool {
    let pm1 = PM1.load(Ordering::Acquire);
    let reset = RESET.load(Ordering::Acquire);
    let mut ranges = [(0u32, 0u32); 4];
    ranges[0] = (pm1 >> 16, 2);
    ranges[1] = (pm1 & 0xffff, 2);
    if reset & (1 << 32) != 0 {
        ranges[2] = (((reset >> 16) & 0xffff) as u32, 1);
    }
    ranges[3] = (0xcf9, 1);
    ranges
        .iter()
        .any(|&(start, length)| start != 0 && base < start + length && start < base + count)
}

/// Enters ACPI S5. Returns only if the machine did not power off.
pub(crate) fn power_off() {
    let pm1 = PM1.load(Ordering::Acquire);
    let s5 = S5.load(Ordering::Acquire);
    if s5 & (1 << 16) == 0 || pm1 >> 16 == 0 {
        return;
    }
    serial_write("Power: entering ACPI S5 (power off).\r\n");
    let typ_a = ((s5 >> 8) & 7) as u16;
    let typ_b = (s5 & 7) as u16;
    outw((pm1 >> 16) as u16, typ_a << 10 | SLP_EN);
    if pm1 & 0xffff != 0 {
        outw((pm1 & 0xffff) as u16, typ_b << 10 | SLP_EN);
    }
    // Give the chipset a moment before reporting failure.
    for _ in 0..10_000_000 {
        core::hint::spin_loop();
    }
    serial_write("Power: ACPI S5 did not take effect.\r\n");
}

/// Resets the machine through the ACPI reset register, then 0xCF9.
#[allow(dead_code)]
pub(crate) fn reset() {
    let reset = RESET.load(Ordering::Acquire);
    if reset & (1 << 32) != 0 {
        outb(((reset >> 16) & 0xffff) as u16, (reset & 0xff) as u8);
    }
    outb(0xcf9, 0x06);
}

fn under_hypervisor() -> bool {
    // CPUID.1:ECX bit 31 is set by hypervisors and clear on bare metal.
    let ecx = core::arch::x86_64::__cpuid(1).ecx;
    ecx & (1 << 31) != 0
}

/// QEMU fw_cfg: is the file `opt/centinela/poweroff` present?
fn fw_cfg_requests_poweroff() -> bool {
    const SELECT: u16 = 0x510;
    const DATA: u16 = 0x511;
    const SIGNATURE: u16 = 0x0000;
    const DIRECTORY: u16 = 0x0019;
    const NAME: &[u8] = b"opt/centinela/poweroff";
    if !under_hypervisor() {
        return false;
    }
    outw(SELECT, SIGNATURE);
    let signature = [inb(DATA), inb(DATA), inb(DATA), inb(DATA)];
    if &signature != b"QEMU" {
        return false;
    }
    outw(SELECT, DIRECTORY);
    let count = u32::from_be_bytes([inb(DATA), inb(DATA), inb(DATA), inb(DATA)]);
    for _ in 0..count.min(256) {
        // Entry: u32 size, u16 select, u16 reserved, 56-byte name.
        let mut entry = [0u8; 64];
        for byte in entry.iter_mut() {
            *byte = inb(DATA);
        }
        let name = &entry[8..];
        let length = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        if &name[..length] == NAME {
            return true;
        }
    }
    false
}

/// End of a successful boot: power off only for the QEMU test harness.
pub(crate) fn finish_boot() {
    if fw_cfg_requests_poweroff() {
        power_off();
    }
}
