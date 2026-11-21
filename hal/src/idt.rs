//! Interrupt Descriptor Table and trap entry stubs.
//!
//! Every gate is a DPL 0 interrupt gate, so user mode cannot raise any vector
//! with `int n` (including `int3`): such attempts fault with #GP instead of
//! impersonating an exception or a device interrupt. Interrupt gates clear IF,
//! so the kernel is never re-entered by maskable interrupts.
//!
//! All vectors funnel into one assembly path that saves every general-purpose
//! register into a [`TrapFrame`] and calls the handler registered by the
//! kernel. The policy (kill the task, halt the system, acknowledge an IRQ)
//! lives in the kernel; this module only provides the mechanism.

use crate::gdt::{IST_DOUBLE_FAULT, IST_MACHINE_CHECK, IST_NMI, KERNEL_CODE_SELECTOR};

pub const VECTOR_DIVIDE_ERROR: u64 = 0;
pub const VECTOR_DEBUG: u64 = 1;
pub const VECTOR_NMI: u64 = 2;
pub const VECTOR_BREAKPOINT: u64 = 3;
pub const VECTOR_INVALID_OPCODE: u64 = 6;
pub const VECTOR_DOUBLE_FAULT: u64 = 8;
pub const VECTOR_GENERAL_PROTECTION: u64 = 13;
pub const VECTOR_PAGE_FAULT: u64 = 14;
pub const VECTOR_MACHINE_CHECK: u64 = 18;
/// First vector used for remapped legacy PIC IRQs.
pub const VECTOR_IRQ_BASE: u64 = 0x20;
/// Vector reported for any gate above the PIC range (should never fire).
pub const VECTOR_UNEXPECTED: u64 = 0xff;

/// Register state captured on every trap (layout shared with the assembly).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrapFrame {
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
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame {
    /// True when the trap interrupted Ring 3 code.
    pub const fn from_user_mode(&self) -> bool {
        self.cs & 3 == 3
    }
}

/// Human-readable name of an architectural exception vector.
pub const fn exception_name(vector: u64) -> &'static str {
    match vector {
        0 => "divide error",
        1 => "debug",
        2 => "non-maskable interrupt",
        3 => "breakpoint",
        4 => "overflow",
        5 => "bound range exceeded",
        6 => "invalid opcode",
        7 => "device not available",
        8 => "double fault",
        10 => "invalid TSS",
        11 => "segment not present",
        12 => "stack-segment fault",
        13 => "general protection",
        14 => "page fault",
        16 => "x87 floating-point",
        17 => "alignment check",
        18 => "machine check",
        19 => "SIMD floating-point",
        20 => "virtualization",
        21 => "control protection",
        28 => "hypervisor injection",
        29 => "VMM communication",
        30 => "security",
        _ => "reserved or interrupt",
    }
}

/// Vectors for which the CPU pushes an error code.
pub const fn pushes_error_code(vector: u64) -> bool {
    matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30)
}

/// IST slot used by a vector (0 = current or rsp0 stack).
pub const fn ist_for_vector(vector: u64) -> u8 {
    match vector {
        VECTOR_DOUBLE_FAULT => IST_DOUBLE_FAULT,
        VECTOR_NMI => IST_NMI,
        VECTOR_MACHINE_CHECK => IST_MACHINE_CHECK,
        _ => 0,
    }
}

/// One 16-byte 64-bit IDT gate.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    pub const MISSING: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };

    /// Present, DPL 0, 64-bit interrupt gate (IF cleared on entry).
    pub const fn interrupt_gate(handler: u64, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE_SELECTOR,
            ist: ist & 0x7,
            attributes: 0x8e,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }

    pub const fn handler(&self) -> u64 {
        (self.offset_low as u64)
            | ((self.offset_middle as u64) << 16)
            | ((self.offset_high as u64) << 32)
    }

    pub const fn privilege_level(&self) -> u8 {
        (self.attributes >> 5) & 3
    }

    pub const fn ist(&self) -> u8 {
        self.ist
    }
}

#[cfg(target_os = "none")]
mod runtime {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Number of gates with dedicated stubs (exceptions + 16 PIC IRQs).
    const STUB_COUNT: usize = 48;

    // KPTI: the IDT is read by the CPU while the task's CR3 is still active.
    #[unsafe(link_section = ".data.entry")]
    static mut IDT: [IdtEntry; 256] = [IdtEntry::MISSING; 256];
    static HANDLER: AtomicUsize = AtomicUsize::new(0);

    macro_rules! stubs {
        ($($vector:literal),* $(,)?) => {
                        core::arch::global_asm!(
                ".pushsection .text.entry, \"ax\"",
                $(
                    concat!(".global centinela_isr_", $vector),
                    concat!("centinela_isr_", $vector, ":"),
                    concat!(".if ", $vector, " != 8 && ", $vector, " != 10 && ", $vector,
                        " != 11 && ", $vector, " != 12 && ", $vector, " != 13 && ", $vector,
                        " != 14 && ", $vector, " != 17 && ", $vector, " != 21 && ", $vector,
                        " != 29 && ", $vector, " != 30"),
                    "    push 0",
                    ".endif",
                    concat!("    push ", $vector),
                                        "    jmp centinela_isr_common",
                )*
                ".popsection",
            );
        };
    }

    core::arch::global_asm!(
        ".pushsection .text.entry, \"ax\"",
        ".global centinela_isr_unexpected",
        "centinela_isr_unexpected:",
        "    push 0",
        "    push 0xff",
        "    jmp centinela_isr_common",
        "centinela_isr_common:",
        "    push r15",
        "    push r14",
        "    push r13",
        "    push r12",
        "    push r11",
        "    push r10",
        "    push r9",
        "    push r8",
        "    push rbp",
        "    push rdi",
        "    push rsi",
        "    push rdx",
        "    push rcx",
        "    push rbx",
                "    push rax",
        // KPTI: coming from Ring 3 (saved CS at rsp + 144), switch to the
        // kernel page tables before touching anything outside the trampoline.
        "    test qword ptr [rsp + 144], 3",
        "    jz 1f",
        "    swapgs",
        "    mov rax, gs:[{kcr3}]",
        "    mov cr3, rax",
        "1:",
        "    mov rdi, rsp",
        "    cld",
        "    call {entry}",
        // Returning to Ring 3: restore the task's page tables first.
        "    test qword ptr [rsp + 144], 3",
        "    jz 2f",
        "    mov rax, gs:[{ucr3}]",
        "    mov cr3, rax",
        "    swapgs",
        "2:",
        "    pop rax",
        "    pop rbx",
        "    pop rcx",
        "    pop rdx",
        "    pop rsi",
        "    pop rdi",
        "    pop rbp",
        "    pop r8",
        "    pop r9",
        "    pop r10",
        "    pop r11",
        "    pop r12",
        "    pop r13",
        "    pop r14",
        "    pop r15",
                "    add rsp, 16",
        "    iretq",
        ".popsection",
        entry = sym trap_entry,
        kcr3 = const crate::syscall::PERCPU_KERNEL_CR3,
        ucr3 = const crate::syscall::PERCPU_USER_CR3,
    );

    // Per-vector stubs: push a zero error code when the CPU does not, push the
    // vector number, then join the common path.
    stubs!(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    );

    unsafe extern "C" {
        fn centinela_isr_unexpected();
    }

    macro_rules! stub_address {
        ($vector:literal) => {{
            unsafe extern "C" {
                #[link_name = concat!("centinela_isr_", $vector)]
                fn stub();
            }
            stub as *const () as u64
        }};
    }

    fn stub_table() -> [u64; STUB_COUNT] {
        [
            stub_address!(0),
            stub_address!(1),
            stub_address!(2),
            stub_address!(3),
            stub_address!(4),
            stub_address!(5),
            stub_address!(6),
            stub_address!(7),
            stub_address!(8),
            stub_address!(9),
            stub_address!(10),
            stub_address!(11),
            stub_address!(12),
            stub_address!(13),
            stub_address!(14),
            stub_address!(15),
            stub_address!(16),
            stub_address!(17),
            stub_address!(18),
            stub_address!(19),
            stub_address!(20),
            stub_address!(21),
            stub_address!(22),
            stub_address!(23),
            stub_address!(24),
            stub_address!(25),
            stub_address!(26),
            stub_address!(27),
            stub_address!(28),
            stub_address!(29),
            stub_address!(30),
            stub_address!(31),
            stub_address!(32),
            stub_address!(33),
            stub_address!(34),
            stub_address!(35),
            stub_address!(36),
            stub_address!(37),
            stub_address!(38),
            stub_address!(39),
            stub_address!(40),
            stub_address!(41),
            stub_address!(42),
            stub_address!(43),
            stub_address!(44),
            stub_address!(45),
            stub_address!(46),
            stub_address!(47),
        ]
    }

    extern "C" fn trap_entry(frame: &mut TrapFrame) {
        let handler = HANDLER.load(Ordering::Acquire);
        if handler == 0 {
            crate::cpu::halt_forever();
        }
        // SAFETY: Only `init` stores this value, and it stores a valid
        // `fn(&mut TrapFrame)` pointer.
        let handler: fn(&mut TrapFrame) = unsafe { core::mem::transmute(handler) };
        handler(frame);
    }

    /// Builds and loads the IDT; every trap is delivered to `handler`.
    ///
    /// # Safety
    /// Must run once at CPL 0 with interrupts disabled, after `gdt::init`
    /// (gates reference the kernel code selector and TSS IST slots).
    pub unsafe fn init(handler: fn(&mut TrapFrame)) {
        HANDLER.store(handler as usize, Ordering::Release);
        let stubs = stub_table();
        // SAFETY: Single-threaded bootstrap; no other reference to IDT exists.
        unsafe {
            let idt = &mut *addr_of_mut!(IDT);
            for (vector, entry) in idt.iter_mut().enumerate() {
                let address = stubs
                    .get(vector)
                    .copied()
                    .unwrap_or(centinela_isr_unexpected as *const () as u64);
                *entry = IdtEntry::interrupt_gate(address, ist_for_vector(vector as u64));
            }
        }
        // SAFETY: The table is fully built above.
        unsafe { load() };
    }

    /// Loads the (already built) shared IDT on the calling CPU. Gates are
    /// read-only after `init`, so every CPU can share one table.
    ///
    /// # Safety
    /// CPL 0, interrupts disabled, after `init` has run on the BSP and after
    /// this CPU loaded a GDT/TSS (gates reference IST slots).
    pub unsafe fn load() {
        #[repr(C, packed)]
        struct Pointer {
            limit: u16,
            base: u64,
        }
        let pointer = Pointer {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: addr_of!(IDT) as u64,
        };
        // SAFETY: Guaranteed by the caller; IDT is a 'static table.
        unsafe {
            core::arch::asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
        }
    }
}

#[cfg(target_os = "none")]
pub use runtime::{init, load};

#[cfg(test)]
mod tests {
    use super::{IdtEntry, ist_for_vector, pushes_error_code};

    #[test]
    fn gates_are_kernel_only_interrupt_gates() {
        let gate = IdtEntry::interrupt_gate(0xffff_ffff_8012_3456, 1);
        assert_eq!(gate.handler(), 0xffff_ffff_8012_3456);
        assert_eq!(gate.privilege_level(), 0, "user mode must not invoke gates");
        assert_eq!(gate.ist(), 1);
    }

    #[test]
    fn critical_vectors_use_dedicated_stacks() {
        assert_ne!(ist_for_vector(8), 0);
        assert_ne!(ist_for_vector(2), 0);
        assert_ne!(ist_for_vector(18), 0);
        assert_eq!(ist_for_vector(14), 0);
    }

    #[test]
    fn error_code_vectors_match_the_architecture() {
        let with_code: [u64; 10] = [8, 10, 11, 12, 13, 14, 17, 21, 29, 30];
        for vector in 0..32 {
            assert_eq!(pushes_error_code(vector), with_code.contains(&vector));
        }
    }
}
