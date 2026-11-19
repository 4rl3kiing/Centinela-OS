//! Early COM1 UART output for boot diagnostics.
//!
//! The interface is deliberately synchronous and intended for early boot.
//! A future concurrent logger must serialize access and define IRQ behavior.

const COM1: u16 = 0x3F8;

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
    // the COM1 line-status register.
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

/// Initialize the COM1 UART for 8-N-1 serial diagnostics.
pub fn init() {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

/// Write a UTF-8 string to COM1, waiting for each byte to be accepted.
pub fn write(message: &str) {
    for byte in message.bytes() {
        while inb(COM1 + 5) & 0x20 == 0 {
            core::hint::spin_loop();
        }
        outb(COM1, byte);
    }
}
