//! Microkernel task system: scheduler, capability-checked IPC, supervision.
//!
//! The kernel provides mechanisms only: address spaces, a rendezvous IPC
//! endpoint, capability checks and fault containment. Services run in Ring 3
//! and are reached exclusively through endpoint capabilities.
//!
//! Scheduling is driven by IPC: a task runs until it blocks in IPC, exits or
//! is terminated. Ready services are preferred so that a restarted service is
//! waiting for requests before its clients resume.
//!
//! Supervision: when a restartable service dies, the kernel wakes any caller
//! that was waiting on it with `STATUS_PEER_DIED`, reclaims the service's
//! memory and starts a fresh instance with a fresh capability table. Handles
//! held by the dead instance are revoked with its table; nothing it held is
//! restored.

use core::fmt::Write;

use centinela_hal::cpu::{halt_forever, load_page_table_root, page_fault_address};
use centinela_hal::gdt;
use centinela_hal::idt::{TrapFrame, exception_name};
use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_hal::syscall::{self, SyscallFrame};
use centinela_kernel::ipc::{
    CallOutcome, Endpoint, IpcViolation, MAX_MESSAGE_WORDS, Message, RECEIVE, SEND,
    STATUS_NO_RECEIVER, STATUS_OK, STATUS_PEER_DIED, TaskId,
};
use centinela_kernel::memory::address_space::{
    create_user_address_space, destroy_user_address_space,
};
use centinela_kernel::memory::hhdm_backend::{HhdmFrameMemory, HhdmReader};
use centinela_kernel::memory::usercopy::copy_from_user;
use centinela_kernel::memory::vmm::{HhdmOffset, PAGE_SIZE, PageTableWalker, PhysAddr};
use centinela_security::capabilities::{Capability, CapabilitySet};
use centinela_security::handles::{CapabilityTable, Rights, TableError};
use centinela_security::syscall_policy::{
    Syscall, SyscallPolicy, SyscallSet, SyscallViolation, authorize,
};

use crate::isolation::{
    CPU_BUDGET_TICKS, USER_CODE_BASE, USER_STACK_TOP, fatal_kernel_trap, map_task_image,
    trap_stack_top,
};
use crate::user_programs;

const MAX_TASKS: usize = 6;
const MAX_RESTARTS: u32 = 3;
const MAX_WRITE_LENGTH: u64 = 256;
const EFAULT: u64 = (-14_i64) as u64;
const EINVAL: u64 = (-22_i64) as u64;
const ENOSYS: u64 = (-38_i64) as u64;
/// The single endpoint object of this milestone (index into `endpoints`).
const ENDPOINT_SERVICE: usize = 0;

/// How a task ended. Every variant except `Exited` and `Stopped` is a
/// containment event.
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
    Ipc(IpcViolation),
    BadReturnAddress,
    CpuBudgetExceeded,
    /// Still blocked in IPC when the system shut down (normal for services).
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Expect {
    Exit(u64),
    Fault(u64),
    PolicyDenied,
    CapabilityDenied,
    UnknownSyscall,
    CpuBudgetExceeded,
    Ipc(IpcViolation),
    /// A service that must still be serving at shutdown after this many restarts.
    Service {
        restarts: u32,
    },
}

impl Expect {
    fn matches(self, exit: TaskExit, restarts: u32) -> bool {
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
            (Self::Ipc(expected), TaskExit::Ipc(actual)) => expected == actual,
            (Self::Service { restarts: expected }, TaskExit::Stopped) => expected == restarts,
            _ => false,
        }
    }
}

#[derive(Clone, Copy)]
struct TaskSpec {
    name: &'static str,
    role: &'static str,
    program: fn() -> &'static [u8],
    extra_syscalls: u64,
    /// Rights on the service endpoint; the raw handle is passed in RDI.
    endpoint_rights: Option<Rights>,
    restartable: bool,
    expect: Expect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskState {
    Ready,
    BlockedReceive,
    BlockedReply,
    Dead,
}

struct Task {
    spec: TaskSpec,
    state: TaskState,
    root: PhysAddr,
    policy: SyscallPolicy,
    capabilities: CapabilitySet,
    endpoints: CapabilityTable<usize, 2>,
    frame: SyscallFrame,
    ticks: u32,
    /// True while this task holds a request it has not replied to.
    serving: bool,
    restarts: u32,
    exit: Option<TaskExit>,
}

/// What ended the most recent run of the current task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Blocked,
    Ended,
}

struct System {
    tasks: [Option<Task>; MAX_TASKS],
    endpoints: [Endpoint; 1],
    current: Option<TaskId>,
    saved_kernel_rsp: u64,
    event: Event,
    reader: HhdmReader,
    next_table_id: u32,
}

static mut SYSTEM: Option<System> = None;

fn system_state() -> Option<&'static mut System> {
    // SAFETY: Single CPU; the kernel runs with IF=0, so the scheduler and the
    // trap/syscall handlers never execute concurrently, and the scheduler
    // re-borrows after every return from user mode.
    unsafe { (*core::ptr::addr_of_mut!(SYSTEM)).as_mut() }
}

fn current_task(system: &mut System) -> Option<&mut Task> {
    let id = system.current?;
    system.tasks[id].as_mut()
}

/// Stops the current task's run and returns to the scheduler.
fn leave_user(system: &mut System, event: Event) -> ! {
    system.event = event;
    let saved = system.saved_kernel_rsp;
    // SAFETY: `saved` was stored by the resume_user call still on the kernel
    // stack; nothing references the abandoned trap/syscall stack.
    unsafe { syscall::resume_kernel(saved, 0) }
}

fn terminate(system: &mut System, exit: TaskExit) -> ! {
    if let Some(task) = current_task(system) {
        task.exit = Some(exit);
        task.state = TaskState::Dead;
    }
    leave_user(system, Event::Ended)
}

pub fn trap_handler(frame: &mut TrapFrame) {
    use centinela_hal::apic::{self, PIC_SPURIOUS_VECTOR, SPURIOUS_VECTOR, TIMER_VECTOR};
    let user_task = frame.from_user_mode() && system_state().is_some_and(|s| s.current.is_some());
    match frame.vector {
        TIMER_VECTOR => {
            apic::end_of_interrupt();
            if user_task && let Some(system) = system_state() {
                let over_budget = current_task(system).is_some_and(|task| {
                    task.ticks += 1;
                    task.ticks > CPU_BUDGET_TICKS
                });
                if over_budget {
                    terminate(system, TaskExit::CpuBudgetExceeded);
                }
            }
        }
        // Spurious APIC/PIC deliveries carry no work and must not be EOI'd.
        SPURIOUS_VECTOR | PIC_SPURIOUS_VECTOR => {}
        // NMI, double fault and machine check signal platform or kernel
        // failure: never attribute them to a task, always fail closed.
        2 | 8 | 18 => fatal_kernel_trap(frame),
        vector if user_task => {
            let exit = TaskExit::Fault {
                vector,
                error_code: frame.error_code,
                rip: frame.rip,
                address: if vector == 14 {
                    page_fault_address()
                } else {
                    0
                },
            };
            if let Some(system) = system_state() {
                terminate(system, exit);
            }
            fatal_kernel_trap(frame);
        }
        _ => fatal_kernel_trap(frame),
    }
}

pub fn syscall_handler(frame: &mut SyscallFrame) {
    let Some(system) = system_state() else {
        serial_write("Centinela-OS: syscall with no task system.\r\n");
        halt_forever();
    };
    let Some(task) = current_task(system) else {
        serial_write("Centinela-OS: syscall with no active task.\r\n");
        halt_forever();
    };
    match authorize(&task.policy, task.capabilities, frame.rax) {
        Err(violation) => terminate(system, TaskExit::Violation(violation)),
        Ok(Syscall::Exit) => terminate(system, TaskExit::Exited(frame.rdi)),
        Ok(Syscall::Write) => {
            let reader = system.reader;
            frame.rax = match current_task(system) {
                Some(task) => sys_write(task, reader, frame.rdi, frame.rsi),
                None => EFAULT,
            };
        }
        Ok(Syscall::IpcCall) => ipc_call(system, frame),
        Ok(Syscall::IpcReplyWait) => ipc_reply_wait(system, frame),
        Ok(_) => frame.rax = ENOSYS,
    }
    if frame.sanitize_for_sysret().is_err() {
        terminate(system, TaskExit::BadReturnAddress);
    }
}

fn sys_write(task: &Task, reader: HhdmReader, address: u64, length: u64) -> u64 {
    if length > MAX_WRITE_LENGTH {
        return EINVAL;
    }
    let mut buffer = [0u8; MAX_WRITE_LENGTH as usize];
    let buffer = &mut buffer[..length as usize];
    let walker = PageTableWalker::new(&reader, task.root);
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
    let _ = write!(writer, "[task {}] ", task.spec.name);
    serial_write(core::str::from_utf8(buffer).unwrap_or(""));
    serial_write("\r\n");
    length
}

/// Resolves the endpoint named by a raw user handle, requiring `rights`.
fn resolve_endpoint(task: &Task, raw: u64, rights: Rights) -> Result<usize, IpcViolation> {
    let handle = task.endpoints.handle_from_raw(raw);
    task.endpoints
        .get(handle, rights)
        .copied()
        .map_err(|error| match error {
            TableError::PermissionDenied => IpcViolation::MissingRights,
            _ => IpcViolation::InvalidHandle,
        })
}

fn message_from(frame: &SyscallFrame) -> Result<Message, IpcViolation> {
    Message::from_registers(frame.rsi, [frame.rdx, frame.r10, frame.r8, frame.r9])
}

/// Writes a status and message into a blocked task's saved registers.
fn deliver(frame: &mut SyscallFrame, status: u64, message: Message) {
    let words = message.words();
    frame.rax = status;
    frame.rsi = message.length() as u64;
    frame.rdx = words[0];
    frame.r10 = words[1];
    frame.r8 = words[2];
    frame.r9 = words[3];
}

fn ipc_call(system: &mut System, frame: &mut SyscallFrame) {
    let Some(caller) = system.current else { return };
    let checked = current_task(system)
        .ok_or(IpcViolation::InvalidHandle)
        .and_then(|task| {
            let endpoint = resolve_endpoint(task, frame.rdi, SEND)?;
            Ok((endpoint, message_from(frame)?))
        });
    let (endpoint, message) = match checked {
        Ok(value) => value,
        Err(violation) => terminate(system, TaskExit::Ipc(violation)),
    };
    match system.endpoints[endpoint].call(caller) {
        CallOutcome::NoReceiver => frame.rax = STATUS_NO_RECEIVER,
        CallOutcome::Delivered { server } => {
            if let Some(server) = system.tasks[server].as_mut() {
                deliver(&mut server.frame, STATUS_OK, message);
                server.serving = true;
                server.state = TaskState::Ready;
            }
            if let Some(task) = current_task(system) {
                task.frame = *frame;
                task.state = TaskState::BlockedReply;
            }
            leave_user(system, Event::Blocked);
        }
    }
}

fn ipc_reply_wait(system: &mut System, frame: &mut SyscallFrame) {
    let Some(server) = system.current else { return };
    let checked = current_task(system)
        .ok_or(IpcViolation::InvalidHandle)
        .and_then(|task| {
            let endpoint = resolve_endpoint(task, frame.rdi, RECEIVE)?;
            Ok((endpoint, message_from(frame)?))
        });
    let (endpoint, reply) = match checked {
        Ok(value) => value,
        Err(violation) => terminate(system, TaskExit::Ipc(violation)),
    };
    if let Some(caller) = system.endpoints[endpoint].reply_wait(server)
        && let Some(caller) = system.tasks[caller].as_mut()
        && caller.state == TaskState::BlockedReply
    {
        deliver(&mut caller.frame, STATUS_OK, reply);
        caller.state = TaskState::Ready;
    }
    if let Some(task) = current_task(system) {
        task.frame = *frame;
        task.serving = false;
        task.state = TaskState::BlockedReceive;
    }
    leave_user(system, Event::Blocked);
}

/// Builds a task's address space and initial register state.
fn spawn(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    spec: TaskSpec,
    table_id: u32,
    restarts: u32,
) -> Result<Task, &'static str> {
    let program = (spec.program)();
    if program.is_empty() || program.len() > PAGE_SIZE as usize {
        return Err("program does not fit in one page");
    }
    let (root, report) = create_user_address_space(memory, kernel_root)
        .map_err(|_| "address space creation failed")?;
    report_user_strip(report.user_bits_stripped);
    if let Err(reason) = map_task_image(memory, root, program) {
        let _ = destroy_user_address_space(memory, root);
        return Err(reason);
    }

    let mut endpoints = CapabilityTable::new(table_id).map_err(|_| "capability table")?;
    let mut frame = SyscallFrame {
        rip: USER_CODE_BASE,
        rsp: USER_STACK_TOP,
        ..SyscallFrame::default()
    };
    if let Some(rights) = spec.endpoint_rights {
        let handle = endpoints
            .insert(ENDPOINT_SERVICE, rights)
            .map_err(|_| "capability grant failed")?;
        frame.rdi = handle.to_raw();
    }

    let syscalls = (1 << Syscall::Write as u8) | (1 << Syscall::Exit as u8) | spec.extra_syscalls;
    let mut capabilities = CapabilitySet::EMPTY;
    capabilities.grant(Capability::WriteConsole);
    Ok(Task {
        spec,
        state: TaskState::Ready,
        root,
        policy: SyscallPolicy::new(SyscallSet::from_bits(syscalls)),
        capabilities,
        endpoints,
        frame,
        ticks: 0,
        serving: false,
        restarts,
        exit: None,
    })
}

fn report_user_strip(stripped: u16) {
    static mut REPORTED: bool = false;
    // SAFETY: Single CPU, IF=0; only the scheduler calls this.
    let reported = unsafe { &mut *core::ptr::addr_of_mut!(REPORTED) };
    if stripped != 0 && !*reported {
        // Limine marks its upper-half PML4 entries user-accessible; task
        // roots never inherit that.
        let mut writer = SerialWriter;
        let _ = write!(
            writer,
            "Isolation: kernel half shared supervisor-only ({stripped} bootloader USER bits stripped).\r\n"
        );
        *reported = true;
    }
}

/// Picks the next ready task: services first, then round-robin.
fn pick_next(system: &System, after: usize) -> Option<usize> {
    let ready = |index: usize| {
        system.tasks[index]
            .as_ref()
            .is_some_and(|task| task.state == TaskState::Ready)
    };
    let service_ready = (0..MAX_TASKS).find(|&index| {
        ready(index)
            && system.tasks[index]
                .as_ref()
                .is_some_and(|task| task.spec.restartable)
    });
    service_ready.or_else(|| {
        (1..=MAX_TASKS)
            .map(|offset| (after + offset) % MAX_TASKS)
            .find(|&index| ready(index))
    })
}

/// Final result of one task slot after the system ran.
#[derive(Clone, Copy)]
struct Outcome {
    spec: TaskSpec,
    exit: Option<TaskExit>,
    restarts: u32,
    reclaimed: bool,
}

/// Runs a set of tasks until none is ready, supervising restartable services.
fn run_system(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
    specs: &[TaskSpec],
) -> [Option<Outcome>; MAX_TASKS] {
    let mut outcomes: [Option<Outcome>; MAX_TASKS] = [None; MAX_TASKS];
    let frames_before = memory.free_frames();
    // SAFETY: Task tables and frames come from the PMM and are HHDM-mapped.
    let reader = unsafe { HhdmReader::new(hhdm) };
    // SAFETY: No task is running; nothing else references SYSTEM.
    unsafe {
        *core::ptr::addr_of_mut!(SYSTEM) = Some(System {
            tasks: [const { None }; MAX_TASKS],
            endpoints: [Endpoint::new()],
            current: None,
            saved_kernel_rsp: 0,
            event: Event::Blocked,
            reader,
            next_table_id: 1,
        });
    }
    let Some(system) = system_state() else {
        return outcomes;
    };
    for (index, spec) in specs.iter().take(MAX_TASKS).enumerate() {
        let table_id = system.next_table_id;
        system.next_table_id += 1;
        match spawn(memory, kernel_root, *spec, table_id, 0) {
            Ok(task) => system.tasks[index] = Some(task),
            Err(reason) => {
                let mut writer = SerialWriter;
                let _ = write!(
                    writer,
                    "Isolation: task {} could not run: {reason}\r\n",
                    spec.name
                );
            }
        }
    }

    let mut last = MAX_TASKS - 1;
    while let Some(system) = system_state() {
        let Some(next) = pick_next(system, last) else {
            break;
        };
        last = next;
        system.current = Some(next);
        let Some(task) = system.tasks[next].as_ref() else {
            break;
        };
        let (root, frame) = (task.root, task.frame);
        let saved = core::ptr::addr_of_mut!(system.saved_kernel_rsp);
        let trap_top = trap_stack_top();
        // SAFETY: The task root shares the kernel half (code, stacks, tables
        // are mapped); its entry/stack are mapped; the trap stack is dedicated
        // and installed as rsp0. CR3 is restored before any other use.
        let started = unsafe {
            gdt::set_privilege0_stack(trap_top);
            load_page_table_root(root.get());
            let result = syscall::resume_user(saved, &frame, trap_top);
            load_page_table_root(kernel_root.get());
            result
        };
        let Some(system) = system_state() else { break };
        system.current = None;
        if started.is_err()
            && let Some(task) = system.tasks[next].as_mut()
        {
            task.state = TaskState::Dead;
            task.exit = Some(TaskExit::BadReturnAddress);
            system.event = Event::Ended;
        }
        if system.event == Event::Ended {
            reap(memory, kernel_root, system, next, &mut outcomes);
        }
    }

    // Shutdown: tasks still blocked (servers waiting for requests) are stopped.
    if let Some(system) = system_state() {
        for index in 0..MAX_TASKS {
            if let Some(task) = system.tasks[index].as_mut() {
                task.exit = Some(TaskExit::Stopped);
                task.state = TaskState::Dead;
                reap_final(memory, system, index, &mut outcomes);
            }
        }
    }
    // SAFETY: No task is running; drop the system state.
    unsafe { *core::ptr::addr_of_mut!(SYSTEM) = None };

    let reclaimed = memory.free_frames() == frames_before;
    for outcome in outcomes.iter_mut().flatten() {
        outcome.reclaimed = reclaimed;
    }
    outcomes
}

/// Handles a task that ended: wake its waiting caller, reclaim it, and
/// restart it if it is a supervised service with restarts left.
fn reap(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    system: &mut System,
    index: usize,
    outcomes: &mut [Option<Outcome>; MAX_TASKS],
) {
    let Some(task) = system.tasks[index].as_ref() else {
        return;
    };
    let (spec, serving, restarts, exit) = (task.spec, task.serving, task.restarts, task.exit);
    for endpoint in system.endpoints.iter_mut() {
        if let Some(caller) = endpoint.on_task_death(index, serving)
            && let Some(caller) = system.tasks[caller].as_mut()
            && caller.state == TaskState::BlockedReply
        {
            deliver(&mut caller.frame, STATUS_PEER_DIED, Message::default());
            caller.state = TaskState::Ready;
        }
    }

    let mut writer = SerialWriter;
    if spec.restartable && restarts < MAX_RESTARTS && exit != Some(TaskExit::Exited(0)) {
        let _ = write!(writer, "Supervisor: service {} ", spec.name);
        if let Some(exit) = exit {
            describe(exit, &mut writer);
        }
        serial_write("\r\n");
        if let Some(old) = system.tasks[index].take() {
            // The old capability table (and every handle it issued) dies here.
            let _ = destroy_user_address_space(memory, old.root);
        }
        let table_id = system.next_table_id;
        system.next_table_id += 1;
        match spawn(memory, kernel_root, spec, table_id, restarts + 1) {
            Ok(task) => {
                system.tasks[index] = Some(task);
                let _ = write!(
                    writer,
                    "Supervisor: service {} restarted with fresh memory and capabilities (restart {}).\r\n",
                    spec.name,
                    restarts + 1
                );
            }
            Err(reason) => {
                let _ = write!(
                    writer,
                    "Supervisor: restart of {} failed: {reason}\r\n",
                    spec.name
                );
                outcomes[index] = Some(Outcome {
                    spec,
                    exit,
                    restarts,
                    reclaimed: false,
                });
            }
        }
        return;
    }
    reap_final(memory, system, index, outcomes);
}

fn reap_final(
    memory: &mut HhdmFrameMemory<'_, '_>,
    system: &mut System,
    index: usize,
    outcomes: &mut [Option<Outcome>; MAX_TASKS],
) {
    let Some(task) = system.tasks[index].take() else {
        return;
    };
    for endpoint in system.endpoints.iter_mut() {
        let _ = endpoint.on_task_death(index, false);
    }
    let reclaimed = destroy_user_address_space(memory, task.root).is_ok();
    outcomes[index] = Some(Outcome {
        spec: task.spec,
        exit: task.exit,
        restarts: task.restarts,
        reclaimed,
    });
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
        TaskExit::Ipc(IpcViolation::InvalidHandle) => {
            write!(writer, "terminated: IPC with a forged or revoked handle")
        }
        TaskExit::Ipc(IpcViolation::MissingRights) => {
            write!(writer, "terminated: IPC without the required right")
        }
        TaskExit::Ipc(IpcViolation::MalformedMessage) => write!(
            writer,
            "terminated: IPC message longer than {MAX_MESSAGE_WORDS} words"
        ),
        TaskExit::BadReturnAddress => write!(writer, "terminated: invalid return address"),
        TaskExit::CpuBudgetExceeded => write!(writer, "terminated: CPU budget exceeded"),
        TaskExit::Stopped => write!(writer, "still serving at shutdown"),
    };
}

/// Prints and checks one outcome; returns true if it matches its expectation.
fn report(outcome: &Outcome) -> bool {
    let mut writer = SerialWriter;
    let Some(exit) = outcome.exit else {
        let _ = write!(
            writer,
            "Isolation: task {} has no exit reason; UNEXPECTED\r\n",
            outcome.spec.name
        );
        return false;
    };
    let ok = outcome.spec.expect.matches(exit, outcome.restarts) && outcome.reclaimed;
    let _ = write!(
        writer,
        "Isolation: task {} [{}]: ",
        outcome.spec.name, outcome.spec.role
    );
    describe(exit, &mut writer);
    if outcome.restarts > 0 {
        let _ = write!(writer, " (restarted {}x)", outcome.restarts);
    }
    let _ = write!(
        writer,
        "; memory {}; {}\r\n",
        if outcome.reclaimed {
            "reclaimed"
        } else {
            "LEAKED"
        },
        if ok { "contained" } else { "UNEXPECTED" }
    );
    ok
}

const fn isolated(
    name: &'static str,
    role: &'static str,
    program: fn() -> &'static [u8],
    extra_syscalls: u64,
    expect: Expect,
) -> TaskSpec {
    TaskSpec {
        name,
        role,
        program,
        extra_syscalls,
        endpoint_rights: None,
        restartable: false,
        expect,
    }
}

const IPC_SYSCALLS: u64 = (1 << Syscall::IpcCall as u8) | (1 << Syscall::IpcReplyWait as u8);

/// Runs every isolation scenario and the microkernel service scenario.
pub fn run_self_test(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
) -> bool {
    use user_programs as p;
    let isolated_tasks = [
        isolated("hello", "none (benign)", p::hello, 0, Expect::Exit(0)),
        isolated(
            "read-kernel",
            "read kernel memory",
            p::read_kernel,
            0,
            Expect::Fault(14),
        ),
        isolated(
            "privileged",
            "privileged instruction",
            p::privileged,
            0,
            Expect::Fault(13),
        ),
        isolated(
            "port-io",
            "direct hardware port I/O",
            p::port_io,
            0,
            Expect::Fault(13),
        ),
        isolated(
            "write-code",
            "self-modifying code (W^X)",
            p::write_code,
            0,
            Expect::Fault(14),
        ),
        isolated(
            "exec-stack",
            "execute injected stack code (NX)",
            p::exec_stack,
            0,
            Expect::Fault(14),
        ),
        isolated(
            "fake-interrupt",
            "spoof timer interrupt",
            p::fake_interrupt,
            0,
            Expect::Fault(13),
        ),
        isolated(
            "forbidden-syscall",
            "syscall outside allow-list",
            p::forbidden_syscall,
            0,
            Expect::PolicyDenied,
        ),
        isolated(
            "missing-capability",
            "syscall without capability",
            p::missing_capability,
            1 << Syscall::Socket as u8,
            Expect::CapabilityDenied,
        ),
        isolated(
            "unknown-syscall",
            "probe undefined syscall",
            p::unknown_syscall,
            0,
            Expect::UnknownSyscall,
        ),
        isolated(
            "spin",
            "monopolize the CPU",
            p::spin,
            0,
            Expect::CpuBudgetExceeded,
        ),
        isolated(
            "stack-overflow",
            "overflow into guard page",
            p::stack_overflow,
            0,
            Expect::Fault(14),
        ),
    ];

    let mut passed = 0usize;
    for spec in &isolated_tasks {
        let outcomes = run_system(memory, kernel_root, hhdm, core::slice::from_ref(spec));
        if outcomes[0].as_ref().is_some_and(report) {
            passed += 1;
        }
    }
    let mut writer = SerialWriter;
    let _ = write!(
        writer,
        "Isolation: {passed}/{} tasks behaved as required; kernel still running.\r\n",
        isolated_tasks.len()
    );
    let isolation_ok = passed == isolated_tasks.len();

    // Microkernel scenario: a Ring 3 service reached only through an endpoint
    // capability, a client that injects a fault into it, and hostile tasks
    // that abuse IPC.
    let scenario = [
        TaskSpec {
            name: "adder-service",
            role: "Ring 3 service (RECEIVE)",
            program: p::adder_service,
            extra_syscalls: IPC_SYSCALLS,
            endpoint_rights: Some(RECEIVE),
            restartable: true,
            expect: Expect::Service { restarts: 1 },
        },
        TaskSpec {
            name: "client",
            role: "client with fault injection (SEND)",
            program: p::client,
            extra_syscalls: IPC_SYSCALLS,
            endpoint_rights: Some(SEND),
            restartable: false,
            expect: Expect::Exit(0),
        },
        TaskSpec {
            name: "rogue-receive",
            role: "receive with a SEND-only capability",
            program: p::rogue_receive,
            extra_syscalls: IPC_SYSCALLS,
            endpoint_rights: Some(SEND),
            restartable: false,
            expect: Expect::Ipc(IpcViolation::MissingRights),
        },
        TaskSpec {
            name: "forged-handle",
            role: "IPC with a forged handle",
            program: p::forged_handle,
            extra_syscalls: IPC_SYSCALLS,
            endpoint_rights: Some(SEND),
            restartable: false,
            expect: Expect::Ipc(IpcViolation::InvalidHandle),
        },
        TaskSpec {
            name: "oversized-message",
            role: "IPC message beyond bounds",
            program: p::oversized_message,
            extra_syscalls: IPC_SYSCALLS,
            endpoint_rights: Some(SEND),
            restartable: false,
            expect: Expect::Ipc(IpcViolation::MalformedMessage),
        },
        TaskSpec {
            name: "no-capability",
            role: "IPC without any endpoint capability",
            program: p::forged_handle,
            extra_syscalls: IPC_SYSCALLS,
            endpoint_rights: None,
            restartable: false,
            expect: Expect::Ipc(IpcViolation::InvalidHandle),
        },
    ];
    let outcomes = run_system(memory, kernel_root, hhdm, &scenario);
    let mut scenario_passed = 0usize;
    for outcome in outcomes.iter().flatten() {
        if report(outcome) {
            scenario_passed += 1;
        }
    }
    let _ = write!(
        writer,
        "Microkernel: {scenario_passed}/{} IPC/service checks passed; kernel still running.\r\n",
        scenario.len()
    );
    isolation_ok && scenario_passed == scenario.len()
}
