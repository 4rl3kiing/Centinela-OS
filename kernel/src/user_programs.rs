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
    "",
    // Worker: announces itself, burns CPU without any syscall, then exits.
    ".balign 16",
    ".global centinela_user_worker_start",
    "centinela_user_worker_start:",
    "    lea rdi, [rip + .Lworker_start_msg]",
    "    lea rsi, [rip + .Lworker_start_msg_end]",
    "    sub rsi, rdi",
    "    mov eax, 1",
    "    syscall",
    "    mov r12d, 30000000",
    ".Lworker_loop:",
    "    dec r12",
    "    jnz .Lworker_loop",
    "    lea rdi, [rip + .Lworker_done_msg]",
    "    lea rsi, [rip + .Lworker_done_msg_end]",
    "    sub rsi, rdi",
    "    mov eax, 1",
    "    syscall",
    "    xor edi, edi",
    "    mov eax, 12",
    "    syscall",
    "    ud2",
    ".Lworker_start_msg:",
    "    .ascii \"started CPU-bound work\"",
    ".Lworker_start_msg_end:",
    ".Lworker_done_msg:",
    "    .ascii \"finished CPU-bound work\"",
    ".Lworker_done_msg_end:",
    ".global centinela_user_worker_end",
    "centinela_user_worker_end:",
    "",
    // ---- Microkernel scenario (IPC: 13 = call, 14 = reply_wait) ----
    // Request: rsi = length, rdx = op, r10/r8 = operands. Reply: rax = status,
    // rsi = length, rdx = result. The endpoint handle arrives in rdi.
    //
    // Service: adds two numbers. Op 0xdead is the fault-injection request:
    // the service then dereferences kernel memory and is terminated.
    ".balign 16",
    ".global centinela_user_adder_service_start",
    "centinela_user_adder_service_start:",
    "    mov r12, rdi",
    "    xor esi, esi",
    ".Ladder_loop:",
    "    mov rdi, r12",
    "    mov eax, 14",
    "    syscall",
    "    cmp rdx, 0xdead",
    "    je .Ladder_crash",
    "    mov rdx, r10",
    "    add rdx, r8",
    "    mov esi, 1",
    "    jmp .Ladder_loop",
    ".Ladder_crash:",
    "    movabs rax, 0xffffffff80000000",
    "    mov rax, [rax]",
    "    ud2",
    ".global centinela_user_adder_service_end",
    "centinela_user_adder_service_end:",
    "",
    // Init: Ring 3 service manager. RDI = its endpoint (RECEIVE), RSI = the
    // adder endpoint (SEND|GRANT), RDX = process capability over the adder.
    // Op 1 = look up the adder: reply with an attenuated SEND-only copy.
    // A message flagged as kernel-originated (bit 16 of RSI, which only the
    // kernel can set) announcing a death triggers a restart request.
    ".balign 16",
    ".global centinela_user_init_start",
    "centinela_user_init_start:",
    "    mov r12, rdi",
    "    mov r13, rsi",
    "    mov r14, rdx",
    "    mov r15d, 0xdead0001",
    "    xor esi, esi",
    ".Linit_loop:",
    "    mov rdi, r12",
    "    mov eax, 14",
    "    syscall",
    "    test esi, 0x10000",
    "    jnz .Linit_notice",
    "    cmp rdx, r15",
    "    je .Linit_forged",
    "    cmp rdx, 1",
    "    jne .Linit_empty",
    "    mov r9, r13",
    "    mov esi, 0x200",
    "    jmp .Linit_loop",
    ".Linit_forged:",
    "    lea rdi, [rip + .Linit_msg_forged]",
    "    lea rsi, [rip + .Linit_msg_forged_end]",
    "    call .Linit_print",
    ".Linit_empty:",
    "    xor esi, esi",
    "    jmp .Linit_loop",
    ".Linit_notice:",
    "    cmp rdx, r15",
    "    jne .Linit_empty",
    "    lea rdi, [rip + .Linit_msg_died]",
    "    lea rsi, [rip + .Linit_msg_died_end]",
    "    call .Linit_print",
    "    mov rdi, r10",
    "    mov eax, 11",
    "    syscall",
    "    test rax, rax",
    "    jnz .Linit_empty",
    "    lea rdi, [rip + .Linit_msg_restarted]",
    "    lea rsi, [rip + .Linit_msg_restarted_end]",
    "    call .Linit_print",
    "    jmp .Linit_empty",
    ".Linit_print:",
    "    sub rsi, rdi",
    "    mov eax, 1",
    "    syscall",
    "    ret",
    ".Linit_msg_forged:",
    "    .ascii \"ignored a forged service-death notice sent by a client\"",
    ".Linit_msg_forged_end:",
    ".Linit_msg_died:",
    "    .ascii \"kernel reports adder-service died; policy: restart\"",
    ".Linit_msg_died_end:",
    ".Linit_msg_restarted:",
    "    .ascii \"adder-service restarted\"",
    ".Linit_msg_restarted_end:",
    ".global centinela_user_init_end",
    "centinela_user_init_end:",
    "",
    // Client: starts with only a SEND capability to init. Asks init for the
    // adder, uses it, crashes it, then uses the instance init restarted.
    ".balign 16",
    ".global centinela_user_client_start",
    "centinela_user_client_start:",
    "    mov r12, rdi",
    "    mov rdi, r12",
    "    mov esi, 1",
    "    mov edx, 1",
    "    mov eax, 13",
    "    syscall",
    "    test rax, rax",
    "    jnz .Lclient_fail",
    "    test esi, 0x200",
    "    jz .Lclient_fail",
    "    test esi, 0x2000",
    "    jnz .Lclient_fail",
    "    mov r13, r9",
    "    lea rdi, [rip + .Lclient_msg0]",
    "    lea rsi, [rip + .Lclient_msg0_end]",
    "    call .Lclient_print",
    "    call .Lclient_add",
    "    lea rdi, [rip + .Lclient_msg1]",
    "    lea rsi, [rip + .Lclient_msg1_end]",
    "    call .Lclient_print",
    "    mov rdi, r13",
    "    mov esi, 1",
    "    mov edx, 0xdead",
    "    mov eax, 13",
    "    syscall",
    "    cmp rax, -32",
    "    jne .Lclient_fail",
    "    lea rdi, [rip + .Lclient_msg2]",
    "    lea rsi, [rip + .Lclient_msg2_end]",
    "    call .Lclient_print",
    "    call .Lclient_add",
    "    lea rdi, [rip + .Lclient_msg3]",
    "    lea rsi, [rip + .Lclient_msg3_end]",
    "    call .Lclient_print",
    "    xor edi, edi",
    "    mov eax, 12",
    "    syscall",
    ".Lclient_fail:",
    "    mov edi, 1",
    "    mov eax, 12",
    "    syscall",
    "    ud2",
    ".Lclient_add:",
    "    mov rdi, r13",
    "    mov esi, 3",
    "    mov edx, 1",
    "    mov r10d, 40",
    "    mov r8d, 2",
    "    mov eax, 13",
    "    syscall",
    "    test rax, rax",
    "    jnz .Lclient_fail",
    "    cmp rdx, 42",
    "    jne .Lclient_fail",
    "    ret",
    ".Lclient_print:",
    "    sub rsi, rdi",
    "    mov eax, 1",
    "    syscall",
    "    ret",
    ".Lclient_msg0:",
    "    .ascii \"init granted a SEND-only adder capability (no GRANT)\"",
    ".Lclient_msg0_end:",
    ".Lclient_msg1:",
    "    .ascii \"service replied 40 + 2 = 42\"",
    ".Lclient_msg1_end:",
    ".Lclient_msg2:",
    "    .ascii \"service crashed mid-request; kernel returned EPIPE\"",
    ".Lclient_msg2_end:",
    ".Lclient_msg3:",
    "    .ascii \"service restarted by init replied 40 + 2 = 42\"",
    ".Lclient_msg3_end:",
    ".global centinela_user_client_end",
    "centinela_user_client_end:",
    "",
    // Hostile: send init a fake death notice (label only; it cannot set the
    // kernel-origin flag). Init must ignore it.
    ".balign 16",
    ".global centinela_user_spoof_notice_start",
    "centinela_user_spoof_notice_start:",
    "    mov esi, 3",
    "    mov edx, 0xdead0001",
    "    mov r10d, 1",
    "    mov eax, 13",
    "    syscall",
    "    xor edi, edi",
    "    mov eax, 12",
    "    syscall",
    "    ud2",
    ".global centinela_user_spoof_notice_end",
    "centinela_user_spoof_notice_end:",
    "",
    // Hostile: obtain a SEND-only capability, then try to pass it on with
    // RECEIVE|SEND|GRANT (rights amplification).
    ".balign 16",
    ".global centinela_user_amplify_start",
    "centinela_user_amplify_start:",
    "    mov r12, rdi",
    "    mov esi, 1",
    "    mov edx, 1",
    "    mov eax, 13",
    "    syscall",
    // R9 now holds the SEND-only handle init granted.
    "    mov rdi, r12",
    "    mov esi, 0x2300",
    "    mov edx, 2",
    "    mov eax, 13",
    "    syscall",
    "    ud2",
    ".global centinela_user_amplify_end",
    "centinela_user_amplify_end:",
    "",
    // Hostile: try to receive with a SEND-only capability.
    ".balign 16",
    ".global centinela_user_rogue_receive_start",
    "centinela_user_rogue_receive_start:",
    "    xor esi, esi",
    "    mov eax, 14",
    "    syscall",
    "    ud2",
    ".global centinela_user_rogue_receive_end",
    "centinela_user_rogue_receive_end:",
    "",
    // Hostile: call through a handle value it was never granted.
    ".balign 16",
    ".global centinela_user_forged_handle_start",
    "centinela_user_forged_handle_start:",
    "    movabs rdi, 0x0000000000014567",
    "    xor esi, esi",
    "    mov eax, 13",
    "    syscall",
    "    ud2",
    ".global centinela_user_forged_handle_end",
    "centinela_user_forged_handle_end:",
    "",
    // Hostile: send a message longer than the 4-word bound.
    ".balign 16",
    ".global centinela_user_oversized_message_start",
    "centinela_user_oversized_message_start:",
    "    mov esi, 5",
    "    mov eax, 13",
    "    syscall",
    "    ud2",
    ".global centinela_user_oversized_message_end",
    "centinela_user_oversized_message_end:",
    "",
    // Attack: a driver granted COM4 reaches for COM1, the kernel console.
    ".balign 16",
    ".global centinela_user_port_escape_start",
    "centinela_user_port_escape_start:",
    "    mov edi, 0x2e8",
    "    xor esi, esi",
    "    mov eax, 15",
    "    syscall",
    "    mov edi, 0x3f8",
    "    mov esi, 1",
    "    mov edx, 0x41",
    "    mov eax, 15",
    "    syscall",
    "    xor edi, edi",
    "    mov eax, 12",
    "    syscall",
    "    ud2",
    ".global centinela_user_port_escape_end",
    "centinela_user_port_escape_end:",
    "",
    // Attack: re-arm an interrupt line it was never bound to.
    ".balign 16",
    ".global centinela_user_irq_forge_start",
    "centinela_user_irq_forge_start:",
    "    mov eax, 16",
    "    syscall",
    "    xor edi, edi",
    "    mov eax, 12",
    "    syscall",
    "    ud2",
    ".global centinela_user_irq_forge_end",
    "centinela_user_irq_forge_end:",
    "",
    // Attack: port I/O syscall without the DeviceAccess capability.
    ".balign 16",
    ".global centinela_user_no_device_cap_start",
    "centinela_user_no_device_cap_start:",
    "    mov edi, 0x60",
    "    xor esi, esi",
    "    mov eax, 15",
    "    syscall",
    "    xor edi, edi",
    "    mov eax, 12",
    "    syscall",
    "    ud2",
    ".global centinela_user_no_device_cap_end",
    "centinela_user_no_device_cap_end:",
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
program!(
    adder_service,
    centinela_user_adder_service_start,
    centinela_user_adder_service_end
);
program!(
    client,
    centinela_user_client_start,
    centinela_user_client_end
);
program!(
    rogue_receive,
    centinela_user_rogue_receive_start,
    centinela_user_rogue_receive_end
);
program!(
    forged_handle,
    centinela_user_forged_handle_start,
    centinela_user_forged_handle_end
);
program!(
    oversized_message,
    centinela_user_oversized_message_start,
    centinela_user_oversized_message_end
);
program!(init, centinela_user_init_start, centinela_user_init_end);
program!(
    spoof_notice,
    centinela_user_spoof_notice_start,
    centinela_user_spoof_notice_end
);
program!(
    amplify,
    centinela_user_amplify_start,
    centinela_user_amplify_end
);
program!(
    worker,
    centinela_user_worker_start,
    centinela_user_worker_end
);
program!(
    port_escape,
    centinela_user_port_escape_start,
    centinela_user_port_escape_end
);
program!(
    irq_forge,
    centinela_user_irq_forge_start,
    centinela_user_irq_forge_end
);
program!(
    no_device_cap,
    centinela_user_no_device_cap_start,
    centinela_user_no_device_cap_end
);
