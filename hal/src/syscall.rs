//! SYSCALL/SYSRET gate and the Ring 0 ⇄ Ring 3 transition primitives.
//!
//! Distrust rules enforced by this mechanism:
//! - SFMASK clears IF, TF, DF, AC, NT and IOPL on entry, so user-controlled
//!   flags can neither single-step the kernel, reverse string operations,
//!   disable SMAP (AC) nor be interrupted while on the transition path.
//! - The entry stub switches to a kernel-owned stack before touching memory
//!   and saves every user register; all of them are restored on return, so no
//!   kernel value leaks through registers.
//! - The kernel handler must sanitize the return frame (canonical lower-half
//!   RIP, fixed RFLAGS) before SYSRET; see `SyscallFrame::sanitize_for_sysret`.
//!   A non-canonical RCX would make SYSRET fault in Ring 0 on the user stack
//!   (the CVE-2012-0217 class).

use crate::gdt::{KERNEL_CODE_SELECTOR, USER_CODE_SELECTOR, USER_DATA_SELECTOR};

pub const IA32_EFER: u32 = 0xC000_0080;
pub const IA32_STAR: u32 = 0xC000_0081;
pub const IA32_LSTAR: u32 = 0xC000_0082;
pub const IA32_FMASK: u32 = 0xC000_0084;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const EFER_SCE: u64 = 1 << 0;

const RFLAGS_TF: u64 = 1 << 8;
const RFLAGS_IF: u64 = 1 << 9;
const RFLAGS_DF: u64 = 1 << 10;
const RFLAGS_IOPL: u64 = 3 << 12;
const RFLAGS_NT: u64 = 1 << 14;
const RFLAGS_AC: u64 = 1 << 18;
const RFLAGS_RESERVED_ONE: u64 = 1 << 1;

/// Flags cleared by the CPU on SYSCALL entry.
pub const SYSCALL_FLAG_MASK: u64 =
    RFLAGS_TF | RFLAGS_IF | RFLAGS_DF | RFLAGS_IOPL | RFLAGS_NT | RFLAGS_AC;

/// The only RFLAGS value user mode ever receives: interrupts enabled (so the
/// kernel watchdog can preempt it), IOPL 0, no trap/nested-task/AC flags.
pub const USER_RFLAGS: u64 = RFLAGS_IF | RFLAGS_RESERVED_ONE;

/// Exclusive upper bound for user-mode instruction and stack addresses. The
/// last canonical lower-half page is never used, so a SYSCALL executed at the
/// very end of user space cannot produce a non-canonical return address.
pub const USER_ADDRESS_LIMIT: u64 = 0x0000_7fff_ffff_f000;

/// STAR: SYSCALL loads CS=0x08/SS=0x10; SYSRET loads CS=0x23/SS=0x1b.
pub const fn star_value() -> u64 {
    // SYSRET adds 16 (CS) and 8 (SS) to the base and forces RPL 3.
    let sysret_base = (USER_DATA_SELECTOR as u64 & !3) - 8;
    ((sysret_base | 3) << 48) | ((KERNEL_CODE_SELECTOR as u64) << 32)
}

const _: () = assert!(((star_value() >> 48) & !3) + 16 == (USER_CODE_SELECTOR as u64 & !3));
const _: () = assert!(((star_value() >> 48) & !3) + 8 == (USER_DATA_SELECTOR as u64 & !3));

/// Register state saved by the SYSCALL entry stub (layout shared with asm).
///
/// Syscall ABI: number in `rax`; arguments in `rdi`, `rsi`, `rdx`, `r10`,
/// `r8`, `r9`; result in `rax`. Every other register is preserved.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallFrame {
    pub rax: u64,
    pub r9: u64,
    pub r8: u64,
    pub r10: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// User RIP (saved from RCX).
    pub rip: u64,
    /// User RFLAGS (saved from R11).
    pub rflags: u64,
    pub rsp: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReturnFrameError {
    NonUserReturnAddress,
}

impl SyscallFrame {
    /// Prepares the frame for SYSRET. Fails if the return address is not a
    /// usable lower-half address; the caller must then kill the task instead
    /// of executing SYSRET.
    pub fn sanitize_for_sysret(&mut self) -> Result<(), ReturnFrameError> {
        if self.rip >= USER_ADDRESS_LIMIT {
            return Err(ReturnFrameError::NonUserReturnAddress);
        }
        self.rflags = USER_RFLAGS;
        Ok(())
    }
}

#[cfg(target_os = "none")]
mod runtime {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static HANDLER: AtomicUsize = AtomicUsize::new(0);

    /// Kernel stack top used by the entry stub (written before entering Ring 3).
    #[unsafe(no_mangle)]
    static mut CENTINELA_SYSCALL_KERNEL_RSP: u64 = 0;
    /// Scratch slot for the user RSP during the stack switch (single CPU, IF=0).
    #[unsafe(no_mangle)]
    static mut CENTINELA_SYSCALL_USER_RSP: u64 = 0;

    core::arch::global_asm!(
        ".global centinela_syscall_entry",
        "centinela_syscall_entry:",
        // IF is already clear (SFMASK). Switch to the kernel stack first.
        "    mov [rip + CENTINELA_SYSCALL_USER_RSP], rsp",
        "    mov rsp, [rip + CENTINELA_SYSCALL_KERNEL_RSP]",
        "    push qword ptr [rip + CENTINELA_SYSCALL_USER_RSP]",
        "    push r11",
        "    push rcx",
        "    push r15",
        "    push r14",
        "    push r13",
        "    push r12",
        "    push rbx",
        "    push rbp",
        "    push rdi",
        "    push rsi",
        "    push rdx",
        "    push r10",
        "    push r8",
        "    push r9",
        "    push rax",
        "    mov rdi, rsp",
        "    cld",
        "    call {entry}",
        "    pop rax",
        "    pop r9",
        "    pop r8",
        "    pop r10",
        "    pop rdx",
        "    pop rsi",
        "    pop rdi",
        "    pop rbp",
        "    pop rbx",
        "    pop r12",
        "    pop r13",
        "    pop r14",
        "    pop r15",
        "    pop rcx",
        "    pop r11",
        // NMI and machine check use IST stacks, so nothing runs on the user
        // stack between this instruction and SYSRET.
        "    pop rsp",
        "    sysretq",
        "",
        // u64 centinela_enter_user(u64 *saved_rsp, u64 rip, u64 rsp)
        ".global centinela_enter_user",
        "centinela_enter_user:",
        "    push rbx",
        "    push rbp",
        "    push r12",
        "    push r13",
        "    push r14",
        "    push r15",
        "    mov [rdi], rsp",
        "    mov rcx, rsi",
        "    mov r11, {user_rflags}",
        "    mov rsp, rdx",
        // Start the task with no kernel data in any register.
        "    xor eax, eax",
        "    xor ebx, ebx",
        "    xor edx, edx",
        "    xor esi, esi",
        "    xor edi, edi",
        "    xor ebp, ebp",
        "    xor r8d, r8d",
        "    xor r9d, r9d",
        "    xor r10d, r10d",
        "    xor r12d, r12d",
        "    xor r13d, r13d",
        "    xor r14d, r14d",
        "    xor r15d, r15d",
        "    sysretq",
        "",
        // ! centinela_resume_kernel(u64 saved_rsp, u64 result)
        ".global centinela_resume_kernel",
        "centinela_resume_kernel:",
        "    mov rsp, rdi",
        "    mov rax, rsi",
        "    pop r15",
        "    pop r14",
        "    pop r13",
        "    pop r12",
        "    pop rbp",
        "    pop rbx",
        "    ret",
        entry = sym syscall_entry,
        user_rflags = const USER_RFLAGS,
    );

    unsafe extern "C" {
        fn centinela_syscall_entry();
        fn centinela_enter_user(saved_rsp: *mut u64, rip: u64, rsp: u64) -> u64;
        fn centinela_resume_kernel(saved_rsp: u64, result: u64) -> !;
    }

    extern "C" fn syscall_entry(frame: &mut SyscallFrame) {
        let handler = HANDLER.load(Ordering::Acquire);
        if handler == 0 {
            crate::cpu::halt_forever();
        }
        // SAFETY: Only `init` stores this value, a valid `fn(&mut SyscallFrame)`.
        let handler: fn(&mut SyscallFrame) = unsafe { core::mem::transmute(handler) };
        handler(frame);
    }

    unsafe fn write_msr(msr: u32, value: u64) {
        // SAFETY: The caller guarantees CPL 0 and an architectural MSR.
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr,
                in("eax") value as u32,
                in("edx") (value >> 32) as u32,
                options(nostack, preserves_flags)
            );
        }
    }

    unsafe fn read_msr(msr: u32) -> u64 {
        let low: u32;
        let high: u32;
        // SAFETY: The caller guarantees CPL 0 and an architectural MSR.
        unsafe {
            core::arch::asm!(
                "rdmsr",
                in("ecx") msr,
                out("eax") low,
                out("edx") high,
                options(nomem, nostack, preserves_flags)
            );
        }
        (u64::from(high) << 32) | u64::from(low)
    }

    /// Enables SYSCALL and routes it to `handler`.
    ///
    /// # Safety
    /// CPL 0, interrupts disabled, after `gdt::init` (selectors must match).
    pub unsafe fn init(handler: fn(&mut SyscallFrame)) {
        HANDLER.store(handler as usize, Ordering::Release);
        // SAFETY: Architectural MSRs written at CPL 0 per the caller contract.
        unsafe {
            write_msr(IA32_STAR, star_value());
            write_msr(IA32_LSTAR, centinela_syscall_entry as *const () as u64);
            write_msr(IA32_FMASK, SYSCALL_FLAG_MASK);
            write_msr(IA32_EFER, read_msr(IA32_EFER) | EFER_SCE);
        }
    }

    /// Runs user code until the kernel calls [`resume_kernel`]; returns the
    /// value passed to it.
    ///
    /// # Safety
    /// The active CR3 must map `rip` (user, executable) and `rsp` (user,
    /// writable); `kernel_stack_top` must be a dedicated kernel stack that is
    /// also installed as TSS.rsp0. `saved_rsp` must stay valid until resumed.
    pub unsafe fn enter_user(
        saved_rsp: *mut u64,
        rip: u64,
        rsp: u64,
        kernel_stack_top: u64,
    ) -> u64 {
        // SAFETY: Guaranteed by the caller; single CPU with IF=0.
        unsafe {
            core::ptr::addr_of_mut!(CENTINELA_SYSCALL_KERNEL_RSP).write(kernel_stack_top);
            centinela_enter_user(saved_rsp, rip, rsp)
        }
    }

    /// Abandons the current trap/syscall stack and returns `result` from the
    /// matching [`enter_user`] call.
    ///
    /// # Safety
    /// `saved_rsp` must be the value stored by the active `enter_user` call
    /// and the caller must not hold references into the abandoned stack.
    pub unsafe fn resume_kernel(saved_rsp: u64, result: u64) -> ! {
        // SAFETY: Guaranteed by the caller.
        unsafe { centinela_resume_kernel(saved_rsp, result) }
    }
}

#[cfg(target_os = "none")]
pub use runtime::{enter_user, init, resume_kernel};

#[cfg(test)]
mod tests {
    use super::{
        ReturnFrameError, SYSCALL_FLAG_MASK, SyscallFrame, USER_ADDRESS_LIMIT, USER_RFLAGS,
    };

    #[test]
    fn syscall_entry_masks_dangerous_flags() {
        for flag in [1 << 8, 1 << 9, 1 << 10, 3 << 12, 1 << 14, 1 << 18] {
            assert_eq!(SYSCALL_FLAG_MASK & flag, flag);
        }
    }

    #[test]
    fn sysret_frame_rejects_non_user_return_addresses() {
        let mut frame = SyscallFrame {
            rip: USER_ADDRESS_LIMIT,
            rflags: u64::MAX,
            ..SyscallFrame::default()
        };
        assert_eq!(
            frame.sanitize_for_sysret(),
            Err(ReturnFrameError::NonUserReturnAddress)
        );
        frame.rip = 0xffff_8000_0000_0000;
        assert!(frame.sanitize_for_sysret().is_err());

        frame.rip = 0x40_0000;
        assert_eq!(frame.sanitize_for_sysret(), Ok(()));
        assert_eq!(
            frame.rflags, USER_RFLAGS,
            "user-chosen RFLAGS are discarded"
        );
        assert_eq!(frame.rflags & (3 << 12), 0, "IOPL must stay 0");
    }
}
