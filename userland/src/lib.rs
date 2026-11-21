#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! Minimal Centinela-OS user runtime: raw syscalls and a panic handler.
//!
//! Syscall ABI: number in RAX; arguments in RDI, RSI, RDX, R10, R8, R9;
//! result in RAX. RCX and R11 are clobbered by SYSCALL.

pub mod nvme;

pub const SYS_WRITE: u64 = 1;
pub const SYS_MAP_MEMORY: u64 = 10;
pub const SYS_EXIT: u64 = 12;
pub const SYS_IPC_CALL: u64 = 13;
pub const SYS_IPC_REPLY_WAIT: u64 = 14;
/// ReplyWait without replying: the pending caller stays blocked.
pub const FLAG_DEFER_REPLY: u64 = 1 << 17;
/// Status returned when the endpoint has no waiting server (retry later).
pub const STATUS_NO_RECEIVER: u64 = (-3_i64) as u64;
pub const SYS_PORT_IO: u64 = 15;
pub const SYS_IRQ_ACK: u64 = 16;
pub const SYS_REVOKE: u64 = 17;
pub const SYS_DMA_ALLOC: u64 = 18;
pub const SYS_SLEEP: u64 = 19;

/// Blocks for `ticks` timer ticks (10 ms each, at most 100) without using CPU.
pub fn sleep(ticks: u64) {
    // SAFETY: The kernel clamps the duration.
    unsafe {
        syscall2(SYS_SLEEP, ticks, 0);
    }
}
/// Transfer: mint the transferred capability with the badge in word 2.
pub const FLAG_MINT_BADGE: u64 = 1 << 18;
/// SEND right bits, for capability transfers (flags bits 8-15).
pub const RIGHT_SEND: u64 = 1 << 1;
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

/// Mediated 32-bit port read.
pub fn port_in32(port: u16) -> u32 {
    // SAFETY: As in `port_in`.
    unsafe { syscall3(SYS_PORT_IO, u64::from(port), 4, 0) as u32 }
}

/// Mediated 32-bit port write.
pub fn port_out32(port: u16, value: u32) {
    // SAFETY: As in `port_in`.
    unsafe {
        syscall3(SYS_PORT_IO, u64::from(port), 5, u64::from(value));
    }
}

/// DMA memory: mapped in this task and at `iova` in our device's IOMMU
/// domain. The device can reach nothing else.
pub struct DmaRegion {
    pub address: *mut u8,
    pub iova: u64,
}

/// Allocates `pages` zeroed DMA pages.
pub fn dma_alloc(pages: u64) -> Option<DmaRegion> {
    let (address, iova): (u64, u64);
    // SAFETY: The kernel chooses both addresses and enforces the quota.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_DMA_ALLOC => address,
            in("rdi") pages,
            in("rsi") 0u64,
            inlateout("rdx") 0u64 => iova,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ((address as i64) > 0).then_some(DmaRegion {
        address: address as *mut u8,
        iova,
    })
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
    /// Badge of the capability the sender used (0: unbadged, reply, notice).
    pub badge: u64,
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

/// Raw IPC syscall: `flags` holds the length (bits 0-7) and option bits.
pub fn ipc(number: u64, endpoint: u64, flags: u64, words: [u64; 4]) -> Received {
    let (status, badge, out_flags, w0, w1, w2, w3): (u64, u64, u64, u64, u64, u64, u64);
    // SAFETY: Register ABI of the IPC syscalls; the kernel validates the
    // handle, the flags and the message bounds.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => status,
            inlateout("rdi") endpoint => badge,
            inlateout("rsi") flags => out_flags,
            inlateout("rdx") words[0] => w0,
            inlateout("r10") words[1] => w1,
            inlateout("r8") words[2] => w2,
            inlateout("r9") words[3] => w3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    Received {
        status,
        badge,
        flags: out_flags,
        words: [w0, w1, w2, w3],
    }
}

/// Replies with an empty message (if serving) and waits on `endpoint`.
pub fn reply_wait(endpoint: u64) -> Received {
    ipc(SYS_IPC_REPLY_WAIT, endpoint, 0, [0; 4])
}

/// Replies with `words` to the pending caller, then waits.
pub fn reply_and_wait(endpoint: u64, words: [u64; 4]) -> Received {
    ipc(SYS_IPC_REPLY_WAIT, endpoint, 4, words)
}

/// Waits again while the pending caller stays blocked (deferred reply).
pub fn wait_deferred(endpoint: u64) -> Received {
    ipc(SYS_IPC_REPLY_WAIT, endpoint, FLAG_DEFER_REPLY, [0; 4])
}

/// Sends a 4-word request and waits for the reply, retrying while the
/// server is busy. Returns `None` if the server never became available.
pub fn call(endpoint: u64, words: [u64; 4]) -> Option<Received> {
    for _ in 0..1_000_000 {
        let reply = ipc(SYS_IPC_CALL, endpoint, 4, words);
        if reply.status != STATUS_NO_RECEIVER {
            return (reply.status == 0).then_some(reply);
        }
        core::hint::spin_loop();
    }
    None
}

/// Replies granting a SEND copy of `cap`, minted with `badge`, then waits.
pub fn reply_minting(endpoint: u64, cap: u64, badge: u64) -> Received {
    ipc(
        SYS_IPC_REPLY_WAIT,
        endpoint,
        3 | (RIGHT_SEND << 8) | FLAG_MINT_BADGE,
        [0, 0, badge, cap],
    )
}

/// Revokes every copy of `badge` minted from the unbadged capability `cap`.
pub fn revoke(cap: u64, badge: u64) -> u64 {
    // SAFETY: The kernel checks that `cap` is an unbadged GRANT capability.
    unsafe { syscall2(SYS_REVOKE, cap, badge) }
}

/// Packs up to 8 bytes into a word (little endian).
pub fn pack(bytes: &[u8]) -> u64 {
    let mut word = [0u8; 8];
    let length = bytes.len().min(8);
    word[..length].copy_from_slice(&bytes[..length]);
    u64::from_le_bytes(word)
}

/// Unpacks a word into bytes and returns the used length.
pub fn unpack(word: u64, out: &mut [u8; 8]) -> usize {
    *out = word.to_le_bytes();
    out.iter().position(|&b| b == 0).unwrap_or(8)
}

/// Fixed-capacity text buffer for composing console lines without a heap.
pub struct Line {
    buffer: [u8; 200],
    length: usize,
}

impl Default for Line {
    fn default() -> Self {
        Self::new()
    }
}

impl Line {
    pub const fn new() -> Self {
        Self {
            buffer: [0; 200],
            length: 0,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> &mut Self {
        for &byte in bytes {
            if self.length < self.buffer.len() {
                self.buffer[self.length] = byte;
                self.length += 1;
            }
        }
        self
    }

    pub fn number(&mut self, mut value: u64) -> &mut Self {
        let mut digits = [0u8; 20];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        while count > 0 {
            count -= 1;
            self.push(&[digits[count]]);
        }
        self
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buffer[..self.length]).unwrap_or("")
    }

    pub fn print(&self) {
        write(self.as_str());
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
