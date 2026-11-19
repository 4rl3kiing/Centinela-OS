//! CPU control operations for the x86_64 bootstrap path.

/// Disable maskable interrupts and halt the bootstrap processor forever.
///
/// This is intended for fatal boot and panic paths only. It must not be used
/// after a scheduler or interrupt-driven idle loop has been introduced.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: This function is called only from privileged kernel context.
        // Disabling interrupts before HLT ensures the bootstrap CPU stays halted.
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}
