//! CMOS real-time clock reads (wall time). Ports 0x70/0x71 are kernel-owned.

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use centinela_hal::serial::SerialWriter;
use centinela_kernel::acpi::{self, PhysicalReader};
use centinela_kernel::time::RtcRegisters;

/// Unix time at boot (0 = unknown).
static BOOT_UNIX_SECONDS: AtomicU64 = AtomicU64::new(0);

fn cmos(index: u8) -> u8 {
    let value: u8;
    // SAFETY: CPL 0, IF=0; CMOS ports are kernel-owned. Bit 7 of the index
    // keeps NMIs disabled while selecting.
    unsafe {
        core::arch::asm!("out 0x70, al", in("al") index | 0x80, options(nomem, nostack, preserves_flags));
        core::arch::asm!("in al, 0x71", out("al") value, options(nomem, nostack, preserves_flags));
    }
    value
}

fn snapshot(century: u8) -> Option<RtcRegisters> {
    // Wait (bounded) until no update is in progress.
    (0..100_000).find(|_| cmos(0x0a) & 0x80 == 0)?;
    Some(RtcRegisters {
        seconds: cmos(0x00),
        minutes: cmos(0x02),
        hours: cmos(0x04),
        day: cmos(0x07),
        month: cmos(0x08),
        year: cmos(0x09),
        century: if century != 0 { cmos(century) } else { 0 },
        status_b: cmos(0x0b),
    })
}

/// Reads the RTC until two consecutive snapshots agree, then records the
/// boot time. A clock that never settles or holds an invalid date leaves the
/// time unknown.
pub(crate) fn init<R: PhysicalReader>(reader: Option<(&R, u64)>) {
    let century = reader.map_or(0, |(reader, rsdp)| acpi::rtc_century_register(reader, rsdp));
    let mut previous = None;
    let mut stable = None;
    for _ in 0..10 {
        let current = snapshot(century);
        if current.is_some() && current == previous {
            stable = current;
            break;
        }
        previous = current;
    }
    match stable.and_then(|registers| registers.decode()) {
        Some(time) => {
            BOOT_UNIX_SECONDS.store(time.unix_seconds(), Ordering::Release);
            let _ = write!(
                SerialWriter,
                "Clock: wall time {:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z (CMOS RTC).\r\n",
                time.year, time.month, time.day, time.hour, time.minute, time.second
            );
        }
        None => {
            let _ = write!(
                SerialWriter,
                "Clock: RTC unreadable or invalid; wall time unknown.\r\n"
            );
        }
    }
}

/// Unix time at boot, if the RTC was valid.
#[allow(dead_code)]
pub(crate) fn boot_unix_seconds() -> Option<u64> {
    match BOOT_UNIX_SECONDS.load(Ordering::Acquire) {
        0 => None,
        seconds => Some(seconds),
    }
}
