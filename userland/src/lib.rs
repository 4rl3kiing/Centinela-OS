#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! Minimal Centinela-OS user runtime: raw syscalls and a panic handler.
//!
//! Syscall ABI: number in RAX; arguments in RDI, RSI, RDX, R10, R8, R9;
//! result in RAX. RCX and R11 are clobbered by SYSCALL.

pub const SYS_WRITE: u64 = 1;
pub const SYS_MAP_MEMORY: u64 = 10;
pub const SYS_EXIT: u64 = 12;

/// Raw 2-argument syscall.
///
/// # Safety
/// Arguments must satisfy the contract of the syscall `number`.
pub unsafe fn syscall2(number: u64, arg0: u64, arg1: u64) -> u64 {
    let result: u64;
    // SAFETY: SYSCALL clobbers only RCX and R11 (declared); the kernel
    // validates every argument.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") arg0,
            in("rsi") arg1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    result
}

/// Writes a line to the kernel console (the kernel prefixes the task name).
pub fn write(text: &str) -> u64 {
    // SAFETY: The kernel validates the pointer/length against our page tables.
    unsafe { syscall2(SYS_WRITE, text.as_ptr() as u64, text.len() as u64) }
}

/// Maps `pages` zeroed, writable, non-executable pages; returns their base.
pub fn map_memory(pages: u64) -> Result<*mut u8, u64> {
    // SAFETY: The kernel chooses the address and enforces the quota.
    let result = unsafe { syscall2(SYS_MAP_MEMORY, pages, 0) };
    if (result as i64) < 0 {
        Err(result)
    } else {
        Ok(result as *mut u8)
    }
}

pub fn exit(code: u64) -> ! {
    // SAFETY: Exit never returns.
    unsafe {
        syscall2(SYS_EXIT, code, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

// Not in test builds, where std provides the panic runtime.
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    write("panic");
    exit(101)
}
