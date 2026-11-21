#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! Minimal Centinela-OS user runtime: raw syscalls and a panic handler.
//!
//! Syscall ABI: number in RAX; arguments in RDI, RSI, RDX, R10, R8, R9;
//! result in RAX. RCX and R11 are clobbered by SYSCALL.

pub const SYS_WRITE: u64 = 1;
pub const SYS_MAP_MEMORY: u64 = 10;
pub const SYS_EXIT: u64 = 12;
pub const SYS_IPC_REPLY_WAIT: u64 = 14;
pub const SYS_PORT_IO: u64 = 15;
pub const SYS_IRQ_ACK: u64 = 16;
/// Set by the kernel in delivered flags for kernel-originated messages.
pub const FLAG_KERNEL_ORIGIN: u64 = 1 << 16;
/// Label of the kernel notice sent when a bound IRQ fires.
pub const NOTICE_IRQ: u64 = 0x1A0_0001;

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

/// Mediated 8-bit port read (the kernel checks the port against our grant).
pub fn port_in(port: u16) -> u8 {
    // SAFETY: The kernel validates the port; out-of-grant access kills us.
    unsafe { syscall3(SYS_PORT_IO, u64::from(port), 0, 0) as u8 }
}

/// Mediated 8-bit port write.
pub fn port_out(port: u16, value: u8) {
    // SAFETY: As in `port_in`.
    unsafe {
        syscall3(SYS_PORT_IO, u64::from(port), 1, u64::from(value));
    }
}

/// Re-arms our bound interrupt line.
pub fn irq_ack() {
    // SAFETY: No arguments; the kernel acts only on our own binding.
    unsafe {
        syscall3(SYS_IRQ_ACK, 0, 0, 0);
    }
}

/// Raw 3-argument syscall.
///
/// # Safety
/// Arguments must satisfy the contract of the syscall `number`.
pub unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    let result: u64;
    // SAFETY: As in `syscall2`.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    result
}

/// A message received from an endpoint.
pub struct Received {
    pub status: u64,
    pub flags: u64,
    pub words: [u64; 4],
}

impl Received {
    /// True only for a kernel IRQ notice (tasks cannot forge the origin bit).
    pub fn is_irq_notice(&self, irq: u64) -> bool {
        self.status == 0
            && self.flags & FLAG_KERNEL_ORIGIN != 0
            && self.words[0] == NOTICE_IRQ
            && self.words[1] == irq
    }
}

/// Replies with an empty message (if serving) and waits on `endpoint`.
pub fn reply_wait(endpoint: u64) -> Received {
    let (status, flags, w0, w1, w2, w3): (u64, u64, u64, u64, u64, u64);
    // SAFETY: Register ABI of IpcReplyWait; the kernel validates the handle.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_IPC_REPLY_WAIT => status,
            in("rdi") endpoint,
            inlateout("rsi") 0u64 => flags,
            inlateout("rdx") 0u64 => w0,
            inlateout("r10") 0u64 => w1,
            inlateout("r8") 0u64 => w2,
            inlateout("r9") 0u64 => w3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    Received {
        status,
        flags,
        words: [w0, w1, w2, w3],
    }
}

/// Waits for the next IRQ notice on `endpoint`, ignoring anything else.
pub fn wait_irq(endpoint: u64, irq: u64) {
    loop {
        if reply_wait(endpoint).is_irq_notice(irq) {
            return;
        }
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
