//! Layer isolation runtime: CPU protection layer, Ring 3 tasks, syscall gate.
//!
//! Trust model: the kernel trusts no task. Every trap or syscall from Ring 3
//! is treated as potentially hostile:
//! - any CPU exception raised by a task terminates that task (never the kernel);
//! - any syscall outside the task's allow-list or capabilities terminates it;
//! - user pointers are validated against the task's own page tables and read
//!   through kernel aliases (the kernel never dereferences user addresses);
//! - user-supplied text is neutralized before reaching the console;
//! - a CPU-budget watchdog terminates tasks that never yield;
//! - every task frame and page table is reclaimed and the count is verified.
//!
//! Conversely, the kernel does not trust its own stacks: critical exceptions
//! run on IST stacks behind unmapped guard pages, and any exception raised in
//! Ring 0 halts the machine with diagnostics (fail closed) instead of
//! continuing in an unknown state.

use core::fmt::Write;
use core::ptr::{addr_of, addr_of_mut};

use centinela_hal::apic::{self, PIC_SPURIOUS_VECTOR, SPURIOUS_VECTOR, TIMER_VECTOR};
use centinela_hal::cpu::{halt_forever, load_page_table_root, page_fault_address};
use centinela_hal::gdt::{self, TssStacks};
use centinela_hal::idt::{self, TrapFrame, exception_name};
use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_hal::syscall::{self, SyscallFrame};
use centinela_kernel::memory::address_space::{
    create_user_address_space, destroy_user_address_space,
};
use centinela_kernel::memory::hhdm_backend::{HhdmFrameMemory, HhdmReader};
use centinela_kernel::memory::usercopy::copy_from_user;
use centinela_kernel::memory::vmm::{
    HhdmOffset, MappingTransactionError, PAGE_SIZE, PageMapping, PageTableMapper,
    PageTableMutationMemory, PageTableWalker, PhysAddr, VirtAddr,
};
use centinela_security::capabilities::{Capability, CapabilitySet};
use centinela_security::permissions::PagePermissions;
use centinela_security::syscall_policy::{
    Syscall, SyscallPolicy, SyscallSet, SyscallViolation, authorize,
};

use crate::user_programs;

const KERNEL_STACK_SIZE: usize = 16 * 1024;
const USER_CODE_BASE: u64 = 0x0000_0000_0040_0000;
const USER_STACK_TOP: u64 = 0x0000_7fff_0000_0000;
const USER_STACK_PAGES: u64 = 4;
/// Kernel-only virtual address of the local APIC registers (PML4 slot 511,
/// shared supervisor-only by every address space; outside HHDM and image).
const APIC_MMIO_VIRTUAL: u64 = 0xffff_ffff_7000_0000;
/// APIC timer reload (bus clock / 16). Uncalibrated: one tick is about 16 ms
/// on QEMU and longer on real buses; the budget is expressed in ticks.
const WATCHDOG_INITIAL_COUNT: u32 = 1_000_000;
/// CPU budget per task, in watchdog ticks.
const CPU_BUDGET_TICKS: u32 = 50;
const MAX_WRITE_LENGTH: u64 = 256;

const EFAULT: u64 = (-14_i64) as u64;
const EINVAL: u64 = (-22_i64) as u64;
const ENOSYS: u64 = (-38_i64) as u64;

/// A kernel stack preceded by a page that is unmapped at boot, so overflow
/// faults instead of silently corrupting adjacent kernel data.
#[repr(C, align(4096))]
struct GuardedStack {
    guard: [u8; PAGE_SIZE as usize],
    stack: [u8; KERNEL_STACK_SIZE],
}

impl GuardedStack {
    const fn new() -> Self {
        Self {
            guard: [0; PAGE_SIZE as usize],
            stack: [0; KERNEL_STACK_SIZE],
        }
    }
}

static mut TRAP_STACK: GuardedStack = GuardedStack::new();
static mut DOUBLE_FAULT_STACK: GuardedStack = GuardedStack::new();
static mut NMI_STACK: GuardedStack = GuardedStack::new();
static mut MACHINE_CHECK_STACK: GuardedStack = GuardedStack::new();

fn stack_bounds(stack: *const GuardedStack) -> (u64, u64) {
    let guard = stack as u64;
    (guard, guard + core::mem::size_of::<GuardedStack>() as u64)
}

/// How a task ended. Every variant except `Exited` is a containment event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskExit {
    Exited(u64),
    Fault {
        vector: u64,
        error_code: u64,
        rip: u64,
        address: u64,
    },
    Violation(SyscallViolation),
    BadReturnAddress,
    CpuBudgetExceeded,
}

/// Outcome the boot self-test requires for a task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Expect {
    Exit(u64),
    Fault(u64),
    PolicyDenied,
    CapabilityDenied,
    UnknownSyscall,
    CpuBudgetExceeded,
}

impl Expect {
    fn matches(self, exit: TaskExit) -> bool {
        match (self, exit) {
            (Self::Exit(code), TaskExit::Exited(actual)) => code == actual,
            (Self::Fault(vector), TaskExit::Fault { vector: actual, .. }) => vector == actual,
            (Self::PolicyDenied, TaskExit::Violation(SyscallViolation::DeniedByPolicy(_))) => true,
            (
                Self::CapabilityDenied,
                TaskExit::Violation(SyscallViolation::MissingCapability(_)),
            ) => true,
            (Self::UnknownSyscall, TaskExit::Violation(SyscallViolation::UnknownSyscall(_))) => {
                true
            }
            (Self::CpuBudgetExceeded, TaskExit::CpuBudgetExceeded) => true,
            _ => false,
        }
    }
}

struct TaskSpec {
    name: &'static str,
    attack: &'static str,
    program: fn() -> &'static [u8],
    extra_syscalls: u64,
    expect: Expect,
}

/// State of the task currently on the CPU (single CPU, IF=0 in the kernel).
struct Runtime {
    active: bool,
    name: &'static str,
    saved_kernel_rsp: u64,
    root: u64,
    policy: SyscallPolicy,
    capabilities: CapabilitySet,
    ticks: u32,
    exit: Option<TaskExit>,
    reader: Option<HhdmReader>,
    user_strip_reported: bool,
}

static mut RUNTIME: Runtime = Runtime {
    active: false,
    name: "",
    saved_kernel_rsp: 0,
    root: 0,
    policy: SyscallPolicy::new(SyscallSet::EMPTY),
    capabilities: CapabilitySet::EMPTY,
    ticks: 0,
    exit: None,
    reader: None,
    user_strip_reported: false,
};

fn runtime() -> &'static mut Runtime {
    // SAFETY: Single CPU; the kernel runs with IF=0, so trap/syscall handlers
    // and the task runner never execute concurrently.
    unsafe { &mut *addr_of_mut!(RUNTIME) }
}

/// Unmaps the guard page of each kernel stack in the active page tables.
fn install_guard_pages(memory: &mut HhdmFrameMemory<'_, '_>, kernel_root: PhysAddr) -> bool {
    let guards = [
        stack_bounds(addr_of!(TRAP_STACK)).0,
        stack_bounds(addr_of!(DOUBLE_FAULT_STACK)).0,
        stack_bounds(addr_of!(NMI_STACK)).0,
        stack_bounds(addr_of!(MACHINE_CHECK_STACK)).0,
        // The stack the kernel itself is running on right now.
        // `guard` is the first field (repr(C)), so the stack base is the guard page.
        (&raw const crate::KERNEL_STACK) as u64,
    ];
    let mut mapper = PageTableMapper::new(memory, kernel_root);
    for guard in guards {
        let Ok(address) = VirtAddr::new(guard) else {
            return false;
        };
        match mapper.unmap_4k(address) {
            // The guard frame stays reserved as part of the kernel image.
            Ok(_) => {}
            Err(MappingTransactionError::HugePageConflict) => {
                serial_write(
                    "Centinela-OS: kernel stacks are not 4 KiB mapped; no guard pages.\r\n",
                );
                return false;
            }
            Err(_) => return false,
        }
    }
    true
}

/// Installs the CPU protection layer: guard pages, GDT/TSS/IST, IDT, the
/// SYSCALL gate and the watchdog timer.
pub fn init_cpu_layer(memory: &mut HhdmFrameMemory<'_, '_>, kernel_root: PhysAddr) -> bool {
    if !install_guard_pages(memory, kernel_root) {
        serial_write("Centinela-OS: failed to install kernel stack guard pages.\r\n");
        return false;
    }
    serial_write("Isolation: kernel stacks protected by unmapped guard pages.\r\n");

    let apic_physical = apic::physical_base();
    let Ok(apic_mapping) = PageMapping::kernel_device(APIC_MMIO_VIRTUAL, apic_physical) else {
        return false;
    };
    if PageTableMapper::new(memory, kernel_root)
        .map_4k(apic_mapping)
        .is_err()
    {
        serial_write("Centinela-OS: failed to map local APIC registers.\r\n");
        return false;
    }

    let stacks = TssStacks {
        privilege0: stack_bounds(addr_of!(TRAP_STACK)).1,
        double_fault: stack_bounds(addr_of!(DOUBLE_FAULT_STACK)).1,
        nmi: stack_bounds(addr_of!(NMI_STACK)).1,
        machine_check: stack_bounds(addr_of!(MACHINE_CHECK_STACK)).1,
    };
    // SAFETY: Bootstrap CPU, CPL 0, IF=0; stacks are dedicated statics whose
    // tops are page aligned; GDT before IDT before SYSCALL as required.
    unsafe {
        gdt::init(stacks);
        idt::init(trap_handler);
        syscall::init(syscall_handler);
        apic::init(APIC_MMIO_VIRTUAL, WATCHDOG_INITIAL_COUNT);
    }
    serial_write("Isolation: GDT/TSS loaded (IST for #DF, NMI, #MC; no I/O bitmap).\r\n");
    serial_write("Isolation: IDT loaded; all gates DPL 0; Ring 0 faults fail closed.\r\n");
    serial_write("Isolation: SYSCALL gate armed (TF/IF/DF/AC/NT/IOPL masked).\r\n");
    serial_write("Isolation: legacy PIC IRQs masked; APIC timer watchdog armed.\r\n");
    true
}

fn fatal_kernel_trap(frame: &TrapFrame) -> ! {
    let mut writer = SerialWriter;
    let _ = write!(
        writer,
        "\r\nCentinela-OS: KERNEL TRAP ({}) vector={} error={:#x} rip={:#x} rsp={:#x} cr2={:#x}\r\n",
        exception_name(frame.vector),
        frame.vector,
        frame.error_code,
        frame.rip,
        frame.rsp,
        page_fault_address(),
    );
    serial_write("Centinela-OS: PANIC. Kernel integrity cannot be assumed; halting.\r\n");
    halt_forever()
}

/// Ends the current task and returns control to `run_task`.
fn terminate(exit: TaskExit) -> ! {
    let state = runtime();
    state.exit = Some(exit);
    state.active = false;
    let saved = state.saved_kernel_rsp;
    // SAFETY: `saved` was stored by the enter_user call that is still on the
    // boot stack; nothing references the abandoned trap/syscall stack.
    unsafe { syscall::resume_kernel(saved, 0) }
}

fn trap_handler(frame: &mut TrapFrame) {
    let from_user = frame.from_user_mode() && runtime().active;
    match frame.vector {
        TIMER_VECTOR => {
            apic::end_of_interrupt();
            if from_user {
                let state = runtime();
                state.ticks += 1;
                if state.ticks > CPU_BUDGET_TICKS {
                    terminate(TaskExit::CpuBudgetExceeded);
                }
            }
        }
        // Spurious APIC/PIC deliveries carry no work and must not be EOI'd.
        SPURIOUS_VECTOR | PIC_SPURIOUS_VECTOR => {}
        // NMI, double fault and machine check signal platform or kernel
        // failure: never attribute them to a task, always fail closed.
        2 | 8 | 18 => fatal_kernel_trap(frame),
        vector if from_user => terminate(TaskExit::Fault {
            vector,
            error_code: frame.error_code,
            rip: frame.rip,
            address: if vector == 14 {
                page_fault_address()
            } else {
                0
            },
        }),
        _ => fatal_kernel_trap(frame),
    }
}

fn syscall_handler(frame: &mut SyscallFrame) {
    let state = runtime();
    if !state.active {
        // A SYSCALL can only originate from a running task.
        serial_write("Centinela-OS: syscall with no active task.\r\n");
        halt_forever();
    }
    match authorize(&state.policy, state.capabilities, frame.rax) {
        Err(violation) => terminate(TaskExit::Violation(violation)),
        Ok(Syscall::Exit) => terminate(TaskExit::Exited(frame.rdi)),
        Ok(Syscall::Write) => frame.rax = sys_write(state, frame.rdi, frame.rsi),
        Ok(_) => frame.rax = ENOSYS,
    }
    if frame.sanitize_for_sysret().is_err() {
        terminate(TaskExit::BadReturnAddress);
    }
}

fn sys_write(state: &Runtime, address: u64, length: u64) -> u64 {
    if length > MAX_WRITE_LENGTH {
        return EINVAL;
    }
    let (Some(reader), Ok(root)) = (state.reader, PhysAddr::new(state.root)) else {
        return EFAULT;
    };
    let mut buffer = [0u8; MAX_WRITE_LENGTH as usize];
    let buffer = &mut buffer[..length as usize];
    let walker = PageTableWalker::new(&reader, root);
    if copy_from_user(&walker, &reader, address, buffer).is_err() {
        return EFAULT;
    }
    // Neutralize terminal control sequences and non-ASCII bytes so a task
    // cannot forge kernel log lines or attack the operator's terminal.
    for byte in buffer.iter_mut() {
        if !(0x20..0x7f).contains(byte) {
            *byte = b'.';
        }
    }
    let mut writer = SerialWriter;
    let _ = write!(writer, "[task {}] ", state.name);
    // Every byte is printable ASCII after sanitization.
    serial_write(core::str::from_utf8(buffer).unwrap_or(""));
    serial_write("\r\n");
    length
}

/// Builds the task address space, runs it to completion and reclaims it.
fn run_task(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
    spec: &TaskSpec,
) -> Result<TaskExit, &'static str> {
    let program = (spec.program)();
    if program.is_empty() || program.len() > PAGE_SIZE as usize {
        return Err("program does not fit in one page");
    }
    let (root, report) = create_user_address_space(memory, kernel_root)
        .map_err(|_| "address space creation failed")?;
    if report.user_bits_stripped != 0 && !runtime().user_strip_reported {
        // Limine marks its upper-half PML4 entries user-accessible; only the
        // leaves keep kernel pages supervisor-only. Task roots never inherit it.
        let mut writer = SerialWriter;
        let _ = write!(
            writer,
            "Isolation: kernel half shared supervisor-only ({} bootloader USER bits stripped).\r\n",
            report.user_bits_stripped
        );
        runtime().user_strip_reported = true;
    }

    let mapped = map_task_image(memory, root, program);
    if let Err(reason) = mapped {
        let _ = destroy_user_address_space(memory, root);
        return Err(reason);
    }

    let mut syscalls = (1 << Syscall::Write as u8) | (1 << Syscall::Exit as u8);
    syscalls |= spec.extra_syscalls;
    let mut capabilities = CapabilitySet::EMPTY;
    capabilities.grant(Capability::WriteConsole);

    let state = runtime();
    state.active = true;
    state.name = spec.name;
    state.root = root.get();
    state.policy = SyscallPolicy::new(SyscallSet::from_bits(syscalls));
    state.capabilities = capabilities;
    state.ticks = 0;
    state.exit = None;
    // SAFETY: Task tables and frames come from the PMM and are HHDM-mapped.
    state.reader = Some(unsafe { HhdmReader::new(hhdm) });

    let trap_top = stack_bounds(addr_of!(TRAP_STACK)).1;
    // SAFETY: The task root shares the kernel half (code, stacks, GDT/IDT/TSS
    // are mapped); entry and stack were mapped above; the trap stack is
    // dedicated and installed as rsp0. CR3 is restored before any other use.
    unsafe {
        gdt::set_privilege0_stack(trap_top);
        load_page_table_root(root.get());
        syscall::enter_user(
            addr_of_mut!(RUNTIME.saved_kernel_rsp),
            USER_CODE_BASE,
            USER_STACK_TOP,
            trap_top,
        );
        load_page_table_root(kernel_root.get());
    }

    let exit = runtime()
        .exit
        .take()
        .ok_or("task returned without an exit reason")?;
    runtime().reader = None;
    destroy_user_address_space(memory, root).map_err(|_| "address space teardown failed")?;
    Ok(exit)
}

fn map_task_image(
    memory: &mut HhdmFrameMemory<'_, '_>,
    root: PhysAddr,
    program: &[u8],
) -> Result<(), &'static str> {
    let rx = PagePermissions::new(true, false, true, true).map_err(|_| "W^X")?;
    let rw = PagePermissions::new(true, true, false, true).map_err(|_| "W^X")?;
    map_user_page(memory, root, USER_CODE_BASE, rx, Some(program))?;
    for index in 0..USER_STACK_PAGES {
        map_user_page(
            memory,
            root,
            USER_STACK_TOP - (index + 1) * PAGE_SIZE,
            rw,
            None,
        )?;
    }
    // The page below the stack stays unmapped: overflow faults the task.
    Ok(())
}

/// Allocates a zeroed frame (optionally filled with `contents`) and maps it.
/// On failure the frame is released here; frames already mapped are
/// reclaimed by `destroy_user_address_space`.
fn map_user_page(
    memory: &mut HhdmFrameMemory<'_, '_>,
    root: PhysAddr,
    address: u64,
    permissions: PagePermissions,
    contents: Option<&[u8]>,
) -> Result<(), &'static str> {
    // Frames are zeroed on allocation, so no stale data reaches the task.
    let frame = memory
        .allocate_zeroed_table_frame()
        .map_err(|_| "out of memory for task page")?;
    let mapped = (|| {
        if let Some(bytes) = contents {
            // SAFETY: Freshly allocated frame, not yet mapped anywhere.
            unsafe { memory.write_frame(frame, bytes) }.map_err(|_| "page copy failed")?;
        }
        let mapping =
            PageMapping::new(address, frame.get(), permissions).map_err(|_| "invalid mapping")?;
        PageTableMapper::new(&mut *memory, root)
            .map_4k(mapping)
            .map_err(|_| "page mapping failed")
    })();
    if mapped.is_err() {
        let _ = memory.release_table_frame(frame);
    }
    mapped
}

fn describe(exit: TaskExit, writer: &mut SerialWriter) {
    let _ = match exit {
        TaskExit::Exited(code) => write!(writer, "exited with code {code}"),
        TaskExit::Fault {
            vector,
            error_code,
            rip,
            address,
        } => {
            if vector == 14 {
                write!(
                    writer,
                    "terminated: {} (error {error_code:#x}) at rip {rip:#x}, address {address:#x}",
                    exception_name(vector)
                )
            } else {
                write!(
                    writer,
                    "terminated: {} (error {error_code:#x}) at rip {rip:#x}",
                    exception_name(vector)
                )
            }
        }
        TaskExit::Violation(SyscallViolation::DeniedByPolicy(syscall)) => {
            write!(writer, "terminated: syscall {syscall:?} denied by policy")
        }
        TaskExit::Violation(SyscallViolation::MissingCapability(syscall)) => {
            write!(writer, "terminated: syscall {syscall:?} lacks capability")
        }
        TaskExit::Violation(SyscallViolation::UnknownSyscall(number)) => {
            write!(writer, "terminated: unknown syscall {number:#x}")
        }
        TaskExit::BadReturnAddress => write!(writer, "terminated: invalid return address"),
        TaskExit::CpuBudgetExceeded => write!(writer, "terminated: CPU budget exceeded"),
    };
}

/// Runs the benign task and every hostile task; returns true if each one
/// ended exactly as required and all of its memory was reclaimed.
pub fn run_isolation_self_test(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
) -> bool {
    let tasks = [
        TaskSpec {
            name: "hello",
            attack: "none (benign)",
            program: user_programs::hello,
            extra_syscalls: 0,
            expect: Expect::Exit(0),
        },
        TaskSpec {
            name: "read-kernel",
            attack: "read kernel memory",
            program: user_programs::read_kernel,
            extra_syscalls: 0,
            expect: Expect::Fault(14),
        },
        TaskSpec {
            name: "privileged",
            attack: "privileged instruction",
            program: user_programs::privileged,
            extra_syscalls: 0,
            expect: Expect::Fault(13),
        },
        TaskSpec {
            name: "port-io",
            attack: "direct hardware port I/O",
            program: user_programs::port_io,
            extra_syscalls: 0,
            expect: Expect::Fault(13),
        },
        TaskSpec {
            name: "write-code",
            attack: "self-modifying code (W^X)",
            program: user_programs::write_code,
            extra_syscalls: 0,
            expect: Expect::Fault(14),
        },
        TaskSpec {
            name: "exec-stack",
            attack: "execute injected stack code (NX)",
            program: user_programs::exec_stack,
            extra_syscalls: 0,
            expect: Expect::Fault(14),
        },
        TaskSpec {
            name: "fake-interrupt",
            attack: "spoof timer interrupt",
            program: user_programs::fake_interrupt,
            extra_syscalls: 0,
            expect: Expect::Fault(13),
        },
        TaskSpec {
            name: "forbidden-syscall",
            attack: "syscall outside allow-list",
            program: user_programs::forbidden_syscall,
            extra_syscalls: 0,
            expect: Expect::PolicyDenied,
        },
        TaskSpec {
            name: "missing-capability",
            attack: "syscall without capability",
            program: user_programs::missing_capability,
            extra_syscalls: 1 << Syscall::Socket as u8,
            expect: Expect::CapabilityDenied,
        },
        TaskSpec {
            name: "unknown-syscall",
            attack: "probe undefined syscall",
            program: user_programs::unknown_syscall,
            extra_syscalls: 0,
            expect: Expect::UnknownSyscall,
        },
        TaskSpec {
            name: "spin",
            attack: "monopolize the CPU",
            program: user_programs::spin,
            extra_syscalls: 0,
            expect: Expect::CpuBudgetExceeded,
        },
        TaskSpec {
            name: "stack-overflow",
            attack: "overflow into guard page",
            program: user_programs::stack_overflow,
            extra_syscalls: 0,
            expect: Expect::Fault(14),
        },
    ];

    let mut writer = SerialWriter;
    let mut passed = 0usize;
    for spec in &tasks {
        let frames_before = memory.free_frames();
        let result = run_task(memory, kernel_root, hhdm, spec);
        let reclaimed = memory.free_frames() == frames_before;
        match result {
            Ok(exit) => {
                let ok = spec.expect.matches(exit) && reclaimed;
                let _ = write!(writer, "Isolation: task {} [{}]: ", spec.name, spec.attack);
                describe(exit, &mut writer);
                let _ = write!(
                    writer,
                    "; memory {}; {}\r\n",
                    if reclaimed { "reclaimed" } else { "LEAKED" },
                    if ok { "contained" } else { "UNEXPECTED" }
                );
                if ok {
                    passed += 1;
                }
            }
            Err(reason) => {
                let _ = write!(
                    writer,
                    "Isolation: task {} could not run: {reason}\r\n",
                    spec.name
                );
            }
        }
    }
    let _ = write!(
        writer,
        "Isolation: {passed}/{} tasks behaved as required; kernel still running.\r\n",
        tasks.len()
    );
    passed == tasks.len()
}
