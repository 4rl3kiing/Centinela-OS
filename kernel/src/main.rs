#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::panic::PanicInfo;

const COM1: u16 = 0x3F8;

#[inline]
fn outb(port: u16, value: u8) {
    // SAFETY: Writing an I/O port is an architecture-specific privileged
    // operation. This is only called during early kernel execution.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn serial_init() {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

fn serial_write(message: &str) {
    for byte in message.bytes() {
        outb(COM1, byte);
    }
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: HLT is valid in the privileged kernel context. Interrupts
        // are disabled first, so this bootstrap kernel remains halted.
        unsafe {
            asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    serial_init();
    serial_write("\r\nCentinela-OS: Rust kernel entry reached.\r\n");
    serial_write("Bootstrap milestone: serial diagnostics operational.\r\n");
    halt_forever()
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_write("\r\nCentinela-OS: PANIC. System halted.\r\n");
    halt_forever()
}
