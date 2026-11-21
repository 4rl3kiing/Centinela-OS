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
pub fn write(message: &str) {
    if !is_present() {
        return;
    }
    for byte in message.bytes() {
        write_byte(byte);
    }
}

/// `core::fmt::Write` adapter for formatted diagnostics (for example panics).
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        write(text);
        Ok(())
    }
}
