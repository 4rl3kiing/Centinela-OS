//! Ring 3 test programs embedded in the kernel image as read-only data.
//!
//! Each program is position-independent machine code copied into a fresh
//! user frame. One is benign; the others each attack a different layer of
//! the kernel. The kernel must contain every attack and keep running.
//!
//! Syscall ABI: number in RAX (1 = write(ptr, len), 12 = exit(code)).

core::arch::global_asm!(
    ".section .rodata.centinela_user, \"a\"",
    ".balign 16",
    // Benign task: prints, proves kernel pointers are rejected, exits cleanly.
    ".global centinela_user_hello_start",
    "centinela_user_hello_start:",
    "    lea rdi, [rip + .Lhello_msg]",
    "    lea rsi, [rip + .Lhello_msg_end]",
    "    sub rsi, rdi",
    "    mov eax, 1",
    "    syscall",
    // Hand the kernel a pointer into kernel memory: must fail with EFAULT.
    "    movabs rdi, 0xffffffff80000000",
    "    mov esi, 16",
    "    mov eax, 1",
    "    syscall",
    "    cmp rax, -14",
    "    jne .Lhello_exit",
    "    lea rdi, [rip + .Lhello_efault]",
    "    lea rsi, [rip + .Lhello_efault_end]",
    "    sub rsi, rdi",
    "    mov eax, 1",
    "    syscall",
    ".Lhello_exit:",
    "    xor edi, edi",
    "    mov eax, 12",
    "    syscall",
    "    ud2",
    ".Lhello_msg:",
    // The embedded ANSI escape must be neutralized by the kernel's log filter.
    "    .ascii \"hello from an isolated Ring 3 task \\033[2J\"",
    ".Lhello_msg_end:",
    ".Lhello_efault:",
    "    .ascii \"kernel pointer rejected with EFAULT\"",
    ".Lhello_efault_end:",
    ".global centinela_user_hello_end",
    "centinela_user_hello_end:",
    "",
    // Attack: read kernel memory directly.
    ".balign 16",
    ".global centinela_user_read_kernel_start",
    "centinela_user_read_kernel_start:",
    "    movabs rax, 0xffffffff80000000",
    "    mov rax, [rax]",
    "    ud2",
    ".global centinela_user_read_kernel_end",
    "centinela_user_read_kernel_end:",
    "",
    // Attack: execute a privileged instruction.
    ".balign 16",
    ".global centinela_user_privileged_start",
    "centinela_user_privileged_start:",
    "    mov rax, cr3",
    "    ud2",
    ".global centinela_user_privileged_end",
    "centinela_user_privileged_end:",
    "",
    // Attack: talk to hardware through an I/O port (the serial console).
    ".balign 16",
    ".global centinela_user_port_io_start",
    "centinela_user_port_io_start:",
    "    mov dx, 0x3f8",
    "    mov al, 0x41",
    "    out dx, al",
    "    ud2",
    ".global centinela_user_port_io_end",
    "centinela_user_port_io_end:",
    "",
    // Attack: patch its own code (W^X: code pages are not writable).
    ".balign 16",
    ".global centinela_user_write_code_start",
    "centinela_user_write_code_start:",
    "    lea rax, [rip]",
    "    mov byte ptr [rax], 0xcc",
    "    ud2",
    ".global centinela_user_write_code_end",
    "centinela_user_write_code_end:",
    "",
    // Attack: inject code on the stack and jump to it (NX).
    ".balign 16",
    ".global centinela_user_exec_stack_start",
    "centinela_user_exec_stack_start:",
    "    lea rax, [rsp - 64]",
    "    mov byte ptr [rax], 0xc3",
    "    call rax",
    "    ud2",
    ".global centinela_user_exec_stack_end",
    "centinela_user_exec_stack_end:",
    "",
    // Attack: impersonate the timer interrupt with a software interrupt.
    ".balign 16",
    ".global centinela_user_fake_interrupt_start",
    "centinela_user_fake_interrupt_start:",
    "    int 0x20",
    "    ud2",
    ".global centinela_user_fake_interrupt_end",
    "centinela_user_fake_interrupt_end:",
    "",
    // Attack: call a syscall outside its allow-list.
    ".balign 16",
    ".global centinela_user_forbidden_syscall_start",
    "centinela_user_forbidden_syscall_start:",
    "    mov eax, 11",
    "    syscall",
    "    ud2",
    ".global centinela_user_forbidden_syscall_end",
    "centinela_user_forbidden_syscall_end:",
    "",
    // Attack: syscall allowed by policy but without the needed capability.
    ".balign 16",
    ".global centinela_user_missing_capability_start",
    "centinela_user_missing_capability_start:",
    "    mov eax, 5",
    "    syscall",
    "    ud2",
    ".global centinela_user_missing_capability_end",
    "centinela_user_missing_capability_end:",
    "",
    // Attack: probe an undefined syscall number.
    ".balign 16",
    ".global centinela_user_unknown_syscall_start",
    "centinela_user_unknown_syscall_start:",
    "    mov eax, 0x1337",
    "    syscall",
    "    ud2",
    ".global centinela_user_unknown_syscall_end",
    "centinela_user_unknown_syscall_end:",
    "",
    // Attack: monopolize the CPU forever.
    ".balign 16",
    ".global centinela_user_spin_start",
    "centinela_user_spin_start:",
    "    jmp centinela_user_spin_start",
    ".global centinela_user_spin_end",
    "centinela_user_spin_end:",
    "",
    // Attack: exhaust its stack into the guard area below it.
    ".balign 16",
    ".global centinela_user_stack_overflow_start",
    "centinela_user_stack_overflow_start:",
    "    push rax",
    "    jmp centinela_user_stack_overflow_start",
    ".global centinela_user_stack_overflow_end",
    "centinela_user_stack_overflow_end:",
    ".text",
);

macro_rules! program {
    ($name:ident, $start:ident, $end:ident) => {
        pub fn $name() -> &'static [u8] {
            unsafe extern "C" {
                static $start: u8;
                static $end: u8;
            }
            let start = core::ptr::addr_of!($start);
            let end = core::ptr::addr_of!($end);
            // SAFETY: Both labels delimit one contiguous read-only blob emitted
            // by the global_asm above, with `end` not before `start`.
            unsafe { core::slice::from_raw_parts(start, end as usize - start as usize) }
        }
    };
}

program!(hello, centinela_user_hello_start, centinela_user_hello_end);
program!(
    read_kernel,
    centinela_user_read_kernel_start,
    centinela_user_read_kernel_end
);
program!(
    privileged,
    centinela_user_privileged_start,
    centinela_user_privileged_end
);
program!(
    port_io,
    centinela_user_port_io_start,
    centinela_user_port_io_end
);
program!(
    write_code,
    centinela_user_write_code_start,
    centinela_user_write_code_end
);
program!(
    exec_stack,
    centinela_user_exec_stack_start,
    centinela_user_exec_stack_end
);
program!(
    fake_interrupt,
    centinela_user_fake_interrupt_start,
    centinela_user_fake_interrupt_end
);
program!(
    forbidden_syscall,
    centinela_user_forbidden_syscall_start,
    centinela_user_forbidden_syscall_end
);
program!(
    missing_capability,
    centinela_user_missing_capability_start,
    centinela_user_missing_capability_end
);
program!(
    unknown_syscall,
    centinela_user_unknown_syscall_start,
    centinela_user_unknown_syscall_end
);
program!(spin, centinela_user_spin_start, centinela_user_spin_end);
program!(
    stack_overflow,
    centinela_user_stack_overflow_start,
    centinela_user_stack_overflow_end
);
