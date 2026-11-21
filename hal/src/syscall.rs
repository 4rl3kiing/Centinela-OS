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

/// Complete saved user register state of a task that is not running.
///
/// Tasks leave the CPU by syscall (blocking IPC), by preemption or by
/// termination; every resume goes through one IRETQ path that loads this
/// context with fixed user selectors and RFLAGS.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,
}

impl UserContext {
    /// Context of a task blocked in a syscall. RCX/R11 are clobbered by the
    /// SYSCALL ABI and are zeroed so no kernel value is ever handed back.
    pub const fn from_syscall(frame: &SyscallFrame) -> Self {
        Self {
            rax: frame.rax,
            rbx: frame.rbx,
            rcx: 0,
            rdx: frame.rdx,
            rsi: frame.rsi,
            rdi: frame.rdi,
            rbp: frame.rbp,
            r8: frame.r8,
            r9: frame.r9,
            r10: frame.r10,
            r11: 0,
            r12: frame.r12,
            r13: frame.r13,
            r14: frame.r14,
            r15: frame.r15,
            rip: frame.rip,
            rsp: frame.rsp,
        }
    }

    /// Context of a task interrupted by the timer (every register is live).
    pub const fn from_trap(frame: &crate::idt::TrapFrame) -> Self {
        Self {
            rax: frame.rax,
            rbx: frame.rbx,
            rcx: frame.rcx,
            rdx: frame.rdx,
            rsi: frame.rsi,
            rdi: frame.rdi,
            rbp: frame.rbp,
            r8: frame.r8,
            r9: frame.r9,
            r10: frame.r10,
            r11: frame.r11,
            r12: frame.r12,
            r13: frame.r13,
            r14: frame.r14,
            r15: frame.r15,
            rip: frame.rip,
            rsp: frame.rsp,
        }
    }

    /// True when the context may be resumed in Ring 3.
    pub const fn is_resumable(&self) -> bool {
        self.rip < USER_ADDRESS_LIMIT && self.rsp <= USER_ADDRESS_LIMIT
    }
}

#[cfg(target_os = "none")]
mod runtime {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static HANDLER: AtomicUsize = AtomicUsize::new(0);

    // KPTI trampoline data: everything the entry/exit stubs touch while the
    // task's page tables are active lives in `.data.entry`, one block per
    // CPU. In kernel mode GS_BASE points at the CPU's block; in user mode the
    // block address sits in KERNEL_GS_BASE and SWAPGS exchanges them on every
    // ring transition. Tasks cannot read or change either MSR.
    #[unsafe(link_section = ".data.entry")]
    static mut PERCPU: [PerCpu; MAX_CPUS] = [const { PerCpu::new() }; MAX_CPUS];
    static KERNEL_ROOT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    core::arch::global_asm!(
        ".pushsection .text.entry, \"ax\"",
        ".global centinela_syscall_entry",
        "centinela_syscall_entry:",
        // IF is already clear (SFMASK). KPTI: switch to the kernel page
        // tables first, then to the kernel stack.
        "    swapgs",
        "    mov gs:[{p_scratch}], rax",
        "    mov rax, gs:[{p_kcr3}]",
        "    mov cr3, rax",
        "    mov rax, gs:[{p_scratch}]",
        "    mov gs:[{p_ursp}], rsp",
        "    mov rsp, gs:[{p_krsp}]",
        "    push qword ptr gs:[{p_ursp}]",
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
        // Back to the task's page tables; the trap stack stays mapped.
        "    mov rax, gs:[{p_ucr3}]",
        "    mov cr3, rax",
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
        "    swapgs",
        "    sysretq",
        "",
        // u64 centinela_resume_user(u64 *saved_rsp)
        // Builds the IRETQ frame on the trap stack (mapped in task tables),
        // switches CR3 to the task, loads every register from
        // CENTINELA_ENTRY_CONTEXT (also in the trampoline) and enters Ring 3.
        ".global centinela_resume_user",
        "centinela_resume_user:",
        "    push rbx",
        "    push rbp",
        "    push r12",
        "    push r13",
        "    push r14",
        "    push r15",
        "    mov [rdi], rsp",
        "    mov rsp, gs:[{p_krsp}]",
        "    mov rsi, gs:[{p_self}]",
        "    add rsi, {p_context}",
        "    push {user_ss}",
        "    push qword ptr [rsi + {c_rsp}]",
        "    push {user_rflags}",
        "    push {user_cs}",
        "    push qword ptr [rsi + {c_rip}]",
        "    mov rax, gs:[{p_ucr3}]",
        "    mov cr3, rax",
        "    mov rax, [rsi + {c_rax}]",
        "    mov rbx, [rsi + {c_rbx}]",
        "    mov rcx, [rsi + {c_rcx}]",
        "    mov rdx, [rsi + {c_rdx}]",
        "    mov rdi, [rsi + {c_rdi}]",
        "    mov rbp, [rsi + {c_rbp}]",
        "    mov r8, [rsi + {c_r8}]",
        "    mov r9, [rsi + {c_r9}]",
        "    mov r10, [rsi + {c_r10}]",
        "    mov r11, [rsi + {c_r11}]",
        "    mov r12, [rsi + {c_r12}]",
        "    mov r13, [rsi + {c_r13}]",
        "    mov r14, [rsi + {c_r14}]",
        "    mov r15, [rsi + {c_r15}]",
        "    mov rsi, [rsi + {c_rsi}]",
        "    swapgs",
        "    iretq",
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
        ".popsection",
        entry = sym syscall_entry,
        user_rflags = const USER_RFLAGS,
        user_ss = const crate::gdt::USER_DATA_SELECTOR as u64,
        user_cs = const crate::gdt::USER_CODE_SELECTOR as u64,
        p_self = const core::mem::offset_of!(PerCpu, self_ptr),
        p_scratch = const core::mem::offset_of!(PerCpu, scratch),
        p_ursp = const core::mem::offset_of!(PerCpu, user_rsp),
        p_krsp = const core::mem::offset_of!(PerCpu, kernel_rsp),
        p_kcr3 = const core::mem::offset_of!(PerCpu, kernel_cr3),
        p_ucr3 = const core::mem::offset_of!(PerCpu, user_cr3),
        p_context = const core::mem::offset_of!(PerCpu, context),
        c_rax = const core::mem::offset_of!(UserContext, rax),
        c_rbx = const core::mem::offset_of!(UserContext, rbx),
        c_rcx = const core::mem::offset_of!(UserContext, rcx),
        c_rdx = const core::mem::offset_of!(UserContext, rdx),
        c_rsi = const core::mem::offset_of!(UserContext, rsi),
        c_rdi = const core::mem::offset_of!(UserContext, rdi),
        c_rbp = const core::mem::offset_of!(UserContext, rbp),
        c_r8 = const core::mem::offset_of!(UserContext, r8),
        c_r9 = const core::mem::offset_of!(UserContext, r9),
        c_r10 = const core::mem::offset_of!(UserContext, r10),
        c_r11 = const core::mem::offset_of!(UserContext, r11),
        c_r12 = const core::mem::offset_of!(UserContext, r12),
        c_r13 = const core::mem::offset_of!(UserContext, r13),
        c_r14 = const core::mem::offset_of!(UserContext, r14),
        c_r15 = const core::mem::offset_of!(UserContext, r15),
        c_rip = const core::mem::offset_of!(UserContext, rip),
        c_rsp = const core::mem::offset_of!(UserContext, rsp),
    );

    unsafe extern "C" {
        fn centinela_syscall_entry();
        fn centinela_resume_user(saved_rsp: *mut u64) -> u64;
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

    /// Enters Ring 3 with the registers in `context` and runs until the
    /// kernel calls [`resume_kernel`]; returns the value passed to it.
    ///
    /// The return address and stack are re-validated here so a corrupted
    /// context can never reach IRETQ with a non-user RIP.
    ///
    /// # Safety
    /// The active CR3 must map `context.rip` (user, executable) and
    /// `context.rsp` (user, writable); `kernel_stack_top` must be a dedicated
    /// kernel stack that is also installed as TSS.rsp0. `saved_rsp` must stay
    /// valid until resumed.
    pub unsafe fn resume_user(
        saved_rsp: *mut u64,
        context: &UserContext,
        kernel_stack_top: u64,
        user_root: u64,
    ) -> Result<u64, ReturnFrameError> {
        if !context.is_resumable() {
            return Err(ReturnFrameError::NonUserReturnAddress);
        }
        // SAFETY: Guaranteed by the caller; IF=0 and the block belongs to
        // this CPU, so the stubs read these values only after the writes.
        unsafe {
            let block = current();
            (*block).kernel_rsp = kernel_stack_top;
            (*block).context = *context;
            (*block).user_cr3 = user_root;
            Ok(centinela_resume_user(saved_rsp))
        }
    }

    /// Records the page-table root every entry from Ring 3 switches to.
    /// Must precede `init_cpu` on each CPU.
    ///
    /// # Safety
    /// `root` must map the whole kernel (it becomes the active root on every
    /// trap or syscall from user mode).
    pub unsafe fn set_kernel_root(root: u64) {
        // Picked up by `init_cpu` on every CPU, which must run afterwards.
        KERNEL_ROOT.store(root, Ordering::Release);
    }

    const IA32_GS_BASE: u32 = 0xc000_0101;
    const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

    /// Binds per-CPU block `index` to the calling CPU (GS_BASE) and records
    /// the kernel page-table root for its entry stubs. Returns false if the
    /// index is out of range.
    ///
    /// # Safety
    /// CPL 0, IF=0, after this CPU loaded its GDT (segment reloads clear the
    /// GS base); each index used by exactly one CPU.
    pub unsafe fn init_cpu(index: usize) -> bool {
        if index >= MAX_CPUS {
            return false;
        }
        // SAFETY: Each index is owned by one CPU (caller contract).
        unsafe {
            let block = (core::ptr::addr_of_mut!(PERCPU) as *mut PerCpu).add(index);
            (*block).self_ptr = block as u64;
            (*block).cpu_index = index as u64;
            (*block).kernel_cr3 = KERNEL_ROOT.load(Ordering::Acquire);
            write_msr(IA32_GS_BASE, block as u64);
            write_msr(IA32_KERNEL_GS_BASE, 0);
        }
        true
    }

    /// The calling CPU's block (valid after `init_cpu`, in kernel mode).
    fn current() -> *mut PerCpu {
        let block: u64;
        // SAFETY: Reads this CPU's self pointer through GS (kernel mode).
        unsafe {
            core::arch::asm!("mov {}, gs:[{off}]", out(reg) block,
                off = const core::mem::offset_of!(PerCpu, self_ptr),
                options(nostack, readonly, preserves_flags));
        }
        block as *mut PerCpu
    }

    /// Index of the calling CPU (0 = bootstrap processor).
    pub fn cpu_index() -> usize {
        let index: u64;
        // SAFETY: As in `current`.
        unsafe {
            core::arch::asm!("mov {}, gs:[{off}]", out(reg) index,
                off = const core::mem::offset_of!(PerCpu, cpu_index),
                options(nostack, readonly, preserves_flags));
        }
        index as usize
    }

    /// Enables SYSCALL on an application processor (MSRs are per CPU).
    ///
    /// # Safety
    /// CPL 0, IF=0, after `init` ran on the BSP and this CPU loaded its GDT.
    pub unsafe fn init_ap() {
        // SAFETY: Architectural MSRs at CPL 0.
        unsafe {
            write_msr(IA32_STAR, star_value());
            write_msr(IA32_LSTAR, centinela_syscall_entry as *const () as u64);
            write_msr(IA32_FMASK, SYSCALL_FLAG_MASK);
            write_msr(IA32_EFER, read_msr(IA32_EFER) | EFER_SCE);
        }
    }

    /// Abandons the current trap/syscall stack and returns `result` from the
    /// matching [`resume_user`] call.
    ///
    /// # Safety
    /// `saved_rsp` must be the value stored by the active `resume_user` call
    /// and the caller must not hold references into the abandoned stack.
    pub unsafe fn resume_kernel(saved_rsp: u64, result: u64) -> ! {
        // SAFETY: Guaranteed by the caller.
        unsafe { centinela_resume_kernel(saved_rsp, result) }
    }
}

#[cfg(target_os = "none")]
pub use runtime::{
    cpu_index, init, init_ap, init_cpu, resume_kernel, resume_user, set_kernel_root,
};

/// Per-CPU blocks for the entry stubs (and a CPU index for the kernel).
pub const MAX_CPUS: usize = 8;

/// Entry-stub state of one CPU; lives in the KPTI trampoline.
#[repr(C)]
pub struct PerCpu {
    self_ptr: u64,
    scratch: u64,
    user_rsp: u64,
    kernel_rsp: u64,
    kernel_cr3: u64,
    user_cr3: u64,
    cpu_index: u64,
    context: UserContext,
}

/// Offsets the interrupt stubs (idt.rs) use through GS.
pub const PERCPU_KERNEL_CR3: usize = core::mem::offset_of!(PerCpu, kernel_cr3);
pub const PERCPU_USER_CR3: usize = core::mem::offset_of!(PerCpu, user_cr3);

impl PerCpu {
    pub const fn new() -> Self {
        Self {
            self_ptr: 0,
            scratch: 0,
            user_rsp: 0,
            kernel_rsp: 0,
            kernel_cr3: 0,
            user_cr3: 0,
            cpu_index: 0,
            context: UserContext {
                rax: 0,
                rbx: 0,
                rcx: 0,
                rdx: 0,
                rsi: 0,
                rdi: 0,
                rbp: 0,
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                rip: 0,
                rsp: 0,
            },
        }
    }
}

impl Default for PerCpu {
    fn default() -> Self {
        Self::new()
    }
}

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
    fn syscall_context_never_returns_kernel_rcx_r11() {
        use super::UserContext;
        let frame = SyscallFrame {
            rip: 0x40_0010,
            rsp: 0x7fff_0000_0000,
            rflags: 0x246,
            ..SyscallFrame::default()
        };
        let context = UserContext::from_syscall(&frame);
        assert_eq!((context.rcx, context.r11), (0, 0));
        assert!(context.is_resumable());
        let hostile = UserContext {
            rip: USER_ADDRESS_LIMIT,
            ..context
        };
        assert!(!hostile.is_resumable());
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
