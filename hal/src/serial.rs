//! Early COM1 UART output for boot diagnostics.
//!
//! The interface is deliberately synchronous and intended for early boot.
//! A future concurrent logger must serialize access and define IRQ behavior.
//!
//! Output is best-effort: if no UART answers the loopback probe, writes are
//! dropped instead of spinning forever. Real machines without a legacy COM1
//! (or with a floating bus that reads 0x00) would otherwise hang the boot.

use core::sync::atomic::{AtomicBool, Ordering};

const COM1: u16 = 0x3F8;
const LINE_STATUS: u16 = COM1 + 5;
const MODEM_CONTROL: u16 = COM1 + 4;
const LSR_TRANSMIT_EMPTY: u8 = 0x20;
const LOOPBACK_PATTERN: u8 = 0xAE;
/// Upper bound on transmit-ready polls per byte (far above a 38400-baud byte).
const TRANSMIT_SPIN_LIMIT: u32 = 100_000;

static PRESENT: AtomicBool = AtomicBool::new(false);

#[inline]
fn outb(port: u16, value: u8) {
    // SAFETY: The caller is in privileged x86_64 kernel context and supplies
    // the COM1 UART ports used by this module.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: The caller is in privileged x86_64 kernel context and supplies
    // the COM1 UART registers used by this module.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Initialize COM1 for 38400 8-N-1 and probe it with a loopback test.
///
/// Returns `true` when a UART answered. Subsequent writes are no-ops when it
/// did not, so diagnostics can never block the boot path.
pub fn init() -> bool {
    outb(COM1 + 1, 0x00); // Disable UART interrupts.
    outb(COM1 + 3, 0x80); // Enable DLAB to program the divisor.
    outb(COM1, 0x03); // Divisor low byte: 38400 baud.
    outb(COM1 + 1, 0x00); // Divisor high byte.
    outb(COM1 + 3, 0x03); // 8 bits, no parity, one stop bit.
    outb(COM1 + 2, 0xC7); // Enable and clear FIFOs, 14-byte threshold.

    // Loopback self-test: a present 16550 echoes the byte back.
    outb(MODEM_CONTROL, 0x1E);
    outb(COM1, LOOPBACK_PATTERN);
    let present = inb(COM1) == LOOPBACK_PATTERN;

    // Normal operation: DTR + RTS, OUT2 left clear (no IRQ line needed).
    outb(MODEM_CONTROL, 0x03);
    PRESENT.store(present, Ordering::Relaxed);
    present
}

/// Returns whether the loopback probe found a UART.
pub fn is_present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}

fn write_byte(byte: u8) {
    for _ in 0..TRANSMIT_SPIN_LIMIT {
        if inb(LINE_STATUS) & LSR_TRANSMIT_EMPTY != 0 {
            outb(COM1, byte);
            return;
        }
        core::hint::spin_loop();
    }
    // Transmitter never became ready: drop the byte rather than hang.
}

/// Write a UTF-8 string to COM1 with a bounded wait for each byte.
///
/// The same text is mirrored to the framebuffer console when one is active,
/// so machines without COM1 still show the log.
pub fn write(message: &str) {
    let serial = is_present();
    console(|_| {
        if serial {
            for byte in message.bytes() {
                write_byte(byte);
            }
        }
        crate::framebuffer::write(message);
        record(message.as_bytes());
    });
}

/// The first 64 KiB of the boot log, kept in memory so a task holding the
/// ReadLog capability can save it to disk for hardware diagnosis.
const LOG_CAPACITY: usize = 64 * 1024;
static mut LOG: [u8; LOG_CAPACITY] = [0; LOG_CAPACITY];
static LOG_LEN: AtomicUsize = AtomicUsize::new(0);

/// Appends to the in-memory log (the caller holds the console).
fn record(bytes: &[u8]) {
    let start = LOG_LEN.load(Ordering::Relaxed);
    let take = bytes.len().min(LOG_CAPACITY - start);
    // SAFETY: Writers are serialized by the console hold; bytes below
    // LOG_LEN are never rewritten, so readers never see a torn byte.
    unsafe {
        let log = &mut *core::ptr::addr_of_mut!(LOG);
        log[start..start + take].copy_from_slice(&bytes[..take]);
    }
    LOG_LEN.store(start + take, Ordering::Release);
}

/// Copies log bytes starting at `offset` into `out`; returns the count.
pub fn log_read(offset: usize, out: &mut [u8]) -> usize {
    let length = LOG_LEN.load(Ordering::Acquire);
    if offset >= length {
        return 0;
    }
    let take = out.len().min(length - offset);
    // SAFETY: Bytes below LOG_LEN are append-only and fully written.
    unsafe {
        let log = &*core::ptr::addr_of!(LOG);
        out[..take].copy_from_slice(&log[offset..offset + take]);
    }
    take
}

use core::sync::atomic::AtomicUsize;

/// Set once per-CPU blocks exist; before that only the BSP runs.
static SMP_READY: AtomicBool = AtomicBool::new(false);
/// Console owner (CPU index + 1, 0 = free) and nesting depth.
static OWNER: AtomicUsize = AtomicUsize::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);

/// Enables console locking (call after the BSP's per-CPU block exists).
pub fn enable_locking() {
    SMP_READY.store(true, Ordering::Release);
}

/// Runs `f` holding the console, so a line from one CPU is never split by
/// another. Re-entrant on the same CPU.
#[cfg(target_os = "none")]
pub fn console<R>(f: impl FnOnce(&mut SerialWriter) -> R) -> R {
    if !SMP_READY.load(Ordering::Acquire) {
        return f(&mut SerialWriter);
    }
    let me = crate::syscall::cpu_index() + 1;
    if OWNER.load(Ordering::Acquire) == me {
        DEPTH.fetch_add(1, Ordering::Relaxed);
    } else {
        while OWNER
            .compare_exchange_weak(0, me, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        DEPTH.store(1, Ordering::Relaxed);
    }
    let result = f(&mut SerialWriter);
    if DEPTH.fetch_sub(1, Ordering::Relaxed) == 1 {
        OWNER.store(0, Ordering::Release);
    }
    result
}

/// Host builds have a single thread.
#[cfg(not(target_os = "none"))]
pub fn console<R>(f: impl FnOnce(&mut SerialWriter) -> R) -> R {
    let _ = (&SMP_READY, &OWNER, &DEPTH);
    f(&mut SerialWriter)
}

/// `core::fmt::Write` adapter for formatted diagnostics (for example panics).
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        write(text);
        Ok(())
    }

    /// A whole formatted line is written under one console hold.
    fn write_fmt(&mut self, args: core::fmt::Arguments<'_>) -> core::fmt::Result {
        console(|writer| core::fmt::write(writer, args))
    }
}
