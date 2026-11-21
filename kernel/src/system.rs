//! Microkernel task system: scheduler, capability IPC and service lifecycle.
//!
//! Mechanism vs. policy:
//! - The kernel provides address spaces, rendezvous IPC endpoints, capability
//!   checks, capability transfer with attenuation, fault containment, death
//!   notices and a restart primitive.
//! - The *policy* (which service exists, who may reach it, when to restart
//!   it) lives in `init`, a Ring 3 service manager. The kernel distrusts init
//!   too: restarts need a process capability with CONTROL, the
//!   ManageProcesses capability, and stay within a kernel-enforced quota.
//!
//! Scheduling is IPC-driven: a task runs until it blocks in IPC, asks for a
//! restart, exits or is terminated. Ready priority tasks (init, services) run
//! first, so services are waiting before their clients resume.

use core::fmt::Write;

use centinela_hal::cpu::{halt_forever, load_page_table_root, page_fault_address};
use centinela_hal::gdt;
use centinela_hal::idt::{TrapFrame, exception_name};
use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_hal::syscall::{self, SyscallFrame, UserContext};
use centinela_kernel::ipc::{
    CallOutcome, Endpoint, IpcViolation, MAX_MESSAGE_WORDS, Message, MessageFlags,
    NOTICE_SERVICE_DIED, RECEIVE, SEND, STATUS_NO_RECEIVER, STATUS_OK, STATUS_PEER_DIED, TaskId,
    attenuate,
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
    CPU_BUDGET_TICKS, QUANTUM_TICKS, USER_CODE_BASE, USER_STACK_TOP, fatal_kernel_trap,
    map_task_image, trap_stack_top,
};
use crate::user_programs;

const MAX_TASKS: usize = 8;
const ENDPOINT_COUNT: usize = 2;
/// Kernel-enforced ceiling on restarts per service, whatever init requests.
const MAX_RESTARTS: u32 = 3;
const MAX_WRITE_LENGTH: u64 = 256;
const EFAULT: u64 = (-14_i64) as u64;
const EINVAL: u64 = (-22_i64) as u64;
const ENOSYS: u64 = (-38_i64) as u64;
const EPERM: u64 = (-1_i64) as u64;
const EBUSY: u64 = (-16_i64) as u64;
/// Endpoint served by init (directory and supervisor notices).
const ENDPOINT_INIT: usize = 0;
/// Endpoint served by the adder service.
const ENDPOINT_ADDER: usize = 1;

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

impl TaskExit {
    /// Compact code delivered to supervisors in death notices.
    const fn notice_code(self) -> u64 {
        match self {
            Self::Exited(_) => 0,
            Self::Fault { .. } => 1,
            Self::Violation(_) => 2,
            Self::Ipc(_) => 3,
            Self::BadReturnAddress => 4,
            Self::CpuBudgetExceeded => 5,
            Self::Stopped => 6,
        }
    }
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
    /// Still serving at shutdown after exactly this many restarts.
    Service {
        restarts: u32,
    },
    /// Exits with this code after being preempted at least once.
    ExitAfterPreemption(u64),
}

impl Expect {
    fn matches(self, exit: TaskExit, restarts: u32, preemptions: u32) -> bool {
        match (self, exit) {
            (Self::ExitAfterPreemption(code), TaskExit::Exited(actual)) => {
                code == actual && preemptions > 0
            }
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
    /// Endpoint capabilities granted at start; raw handles arrive in RDI, RSI.
    endpoints: [Option<(usize, Rights)>; 2],
    /// Process capability (CONTROL) over this task slot; raw handle in RDX.
    process: Option<usize>,
    manage_processes: bool,
    /// Scheduled before ordinary tasks (init and services).
    priority: bool,
    /// Endpoint that receives a kernel notice when this task dies.
    supervisor: Option<usize>,
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
    endpoints: CapabilityTable<usize, 8>,
    processes: CapabilityTable<usize, 4>,
    /// Raw handle this task holds for the process capability it was granted.
    process_handle: Option<(usize, u64)>,
    context: UserContext,
    ticks: u32,
    /// Ticks used in the current time slice.
    slice: u32,
    preemptions: u32,
    /// True while this task holds a request it has not replied to.
    serving: bool,
    restarts: u32,
    exit: Option<TaskExit>,
}

/// A supervised task that died and awaits a restart decision.
#[derive(Clone, Copy)]
struct Dormant {
    spec: TaskSpec,
    restarts: u32,
    exit: Option<TaskExit>,
}

#[derive(Clone, Copy, Default)]
struct EndpointState {
    rendezvous: Endpoint,
    /// Task slots whose death notice is waiting for the receiver.
    pending_notices: u8,
}

/// What ended the most recent run of the current task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Blocked,
    Ended,
    /// The current task asked the kernel to restart this dormant slot.
    Restart(usize),
    /// The current task's time slice expired; it stays ready.
    Preempted,
}

struct System {
    tasks: [Option<Task>; MAX_TASKS],
    dormant: [Option<Dormant>; MAX_TASKS],
    endpoints: [EndpointState; ENDPOINT_COUNT],
    /// Raw handle, in the supervisor's table, naming each task slot.
    notice_handles: [u64; MAX_TASKS],
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

/// Saves the caller's registers and leaves it in `state`.
fn park(system: &mut System, frame: &SyscallFrame, state: TaskState, event: Event) -> ! {
    if let Some(task) = current_task(system) {
        task.context = UserContext::from_syscall(frame);
        task.state = state;
    }
    leave_user(system, event)
}

fn another_task_ready(system: &System) -> bool {
    system.tasks.iter().enumerate().any(|(index, task)| {
        Some(index) != system.current
            && task
                .as_ref()
                .is_some_and(|task| task.state == TaskState::Ready)
    })
}

pub fn trap_handler(frame: &mut TrapFrame) {
    use centinela_hal::apic::{self, PIC_SPURIOUS_VECTOR, SPURIOUS_VECTOR, TIMER_VECTOR};
    let user_task = frame.from_user_mode() && system_state().is_some_and(|s| s.current.is_some());
    match frame.vector {
        TIMER_VECTOR => {
            apic::end_of_interrupt();
            if user_task && let Some(system) = system_state() {
                let (over_budget, slice_over) =
                    current_task(system).map_or((false, false), |task| {
                        task.ticks += 1;
                        task.slice += 1;
                        (task.ticks > CPU_BUDGET_TICKS, task.slice >= QUANTUM_TICKS)
                    });
                if over_budget {
                    terminate(system, TaskExit::CpuBudgetExceeded);
                }
                // Preemption: switch only if someone else can use the CPU.
                if slice_over && another_task_ready(system) {
                    if let Some(task) = current_task(system) {
                        task.context = UserContext::from_trap(frame);
                        task.slice = 0;
                        task.preemptions += 1;
                        task.state = TaskState::Ready;
                    }
                    leave_user(system, Event::Preempted);
                }
                if slice_over && let Some(task) = current_task(system) {
                    task.slice = 0;
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
        Ok(Syscall::CreateProcess) => process_restart(system, frame),
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

fn table_violation(error: TableError) -> IpcViolation {
    match error {
        TableError::PermissionDenied => IpcViolation::MissingRights,
        _ => IpcViolation::InvalidHandle,
    }
}

/// Resolves the endpoint named by a raw user handle, requiring `rights`.
fn resolve_endpoint(task: &Task, raw: u64, rights: Rights) -> Result<usize, IpcViolation> {
    let handle = task.endpoints.handle_from_raw(raw);
    task.endpoints
        .get(handle, rights)
        .copied()
        .map_err(table_violation)
}

/// A validated outgoing message, possibly carrying an attenuated capability.
struct Outgoing {
    message: Message,
    transfer: Option<(usize, Rights)>,
}

/// Validates flags, message bounds and any capability transfer.
fn outgoing(task: &Task, frame: &SyscallFrame) -> Result<Outgoing, IpcViolation> {
    let flags = MessageFlags::parse(frame.rsi)?;
    let transfer = match flags.grant {
        None => None,
        Some(requested) => {
            // The capability to pass travels in the last word (R9).
            let handle = task.endpoints.handle_from_raw(frame.r9);
            let held = task.endpoints.rights(handle).map_err(table_violation)?;
            let endpoint = *task.endpoints.get(handle, held).map_err(table_violation)?;
            Some((endpoint, attenuate(held, requested)?))
        }
    };
    let message =
        Message::from_registers(flags.length, [frame.rdx, frame.r10, frame.r8, frame.r9])?;
    Ok(Outgoing { message, transfer })
}

/// Writes a status, message and optional new capability into a receiver's
/// saved registers. The flags word is rebuilt by the kernel, so a sender can
/// never make a message look kernel-originated.
fn deliver(receiver: &mut Task, status: u64, outgoing: &Outgoing, kernel_origin: bool) {
    let words = outgoing.message.words();
    let mut granted = None;
    let mut last_word = words[3];
    if let Some((endpoint, rights)) = outgoing.transfer {
        // A full receiver table simply receives no capability.
        last_word = match receiver.endpoints.insert(endpoint, rights) {
            Ok(handle) => {
                granted = Some(rights);
                handle.to_raw()
            }
            Err(_) => 0,
        };
    }
    let frame = &mut receiver.context;
    frame.rax = status;
    frame.rsi = MessageFlags::delivered(outgoing.message.length() as u64, granted, kernel_origin);
    frame.rdx = words[0];
    frame.r10 = words[1];
    frame.r8 = words[2];
    frame.r9 = last_word;
}

fn deliver_status(receiver: &mut Task, status: u64) {
    let empty = Outgoing {
        message: Message::default(),
        transfer: None,
    };
    deliver(receiver, status, &empty, false);
}

fn deliver_notice(receiver: &mut Task, process_handle: u64, code: u64) {
    let notice = Outgoing {
        message: Message::from_registers(3, [NOTICE_SERVICE_DIED, process_handle, code, 0])
            .unwrap_or_default(),
        transfer: None,
    };
    deliver(receiver, STATUS_OK, &notice, true);
}

fn ipc_call(system: &mut System, frame: &mut SyscallFrame) {
    let Some(caller) = system.current else { return };
    let checked = current_task(system)
        .ok_or(IpcViolation::InvalidHandle)
        .and_then(|task| {
            let endpoint = resolve_endpoint(task, frame.rdi, SEND)?;
            Ok((endpoint, outgoing(task, frame)?))
        });
    let (endpoint, request) = match checked {
        Ok(value) => value,
        Err(violation) => terminate(system, TaskExit::Ipc(violation)),
    };
    match system.endpoints[endpoint].rendezvous.call(caller) {
        CallOutcome::NoReceiver => frame.rax = STATUS_NO_RECEIVER,
        CallOutcome::Delivered { server } => {
            if let Some(server) = system.tasks[server].as_mut() {
                deliver(server, STATUS_OK, &request, false);
                server.serving = true;
                server.state = TaskState::Ready;
            }
            park(system, frame, TaskState::BlockedReply, Event::Blocked);
        }
    }
}

fn ipc_reply_wait(system: &mut System, frame: &mut SyscallFrame) {
    let Some(server) = system.current else { return };
    let checked = current_task(system)
        .ok_or(IpcViolation::InvalidHandle)
        .and_then(|task| {
            let endpoint = resolve_endpoint(task, frame.rdi, RECEIVE)?;
            Ok((endpoint, outgoing(task, frame)?))
        });
    let (endpoint, reply) = match checked {
        Ok(value) => value,
        Err(violation) => terminate(system, TaskExit::Ipc(violation)),
    };
    if let Some(caller) = system.endpoints[endpoint].rendezvous.reply_wait(server)
        && let Some(caller) = system.tasks[caller].as_mut()
        && caller.state == TaskState::BlockedReply
    {
        deliver(caller, STATUS_OK, &reply, false);
        caller.state = TaskState::Ready;
    }
    if let Some(task) = current_task(system) {
        task.serving = false;
        task.context = UserContext::from_syscall(frame);
        task.state = TaskState::BlockedReceive;
    }
    // A pending kernel notice is delivered at once instead of blocking.
    deliver_pending_notice(system, endpoint);
    leave_user(system, Event::Blocked)
}

/// If `endpoint` has a waiting receiver and a pending notice, deliver it.
fn deliver_pending_notice(system: &mut System, endpoint: usize) {
    let Some(receiver) = system.endpoints[endpoint].rendezvous.receiver() else {
        return;
    };
    if !system.tasks[receiver]
        .as_ref()
        .is_some_and(|task| task.state == TaskState::BlockedReceive)
    {
        return;
    }
    let pending = &mut system.endpoints[endpoint].pending_notices;
    if *pending == 0 {
        return;
    }
    let slot = pending.trailing_zeros() as usize;
    *pending &= !(1 << slot);
    system.endpoints[endpoint].rendezvous.take_receiver();
    let handle = system.notice_handles[slot];
    let code = system.dormant[slot]
        .and_then(|dormant| dormant.exit)
        .map_or(0, TaskExit::notice_code);
    if let Some(task) = system.tasks[receiver].as_mut() {
        deliver_notice(task, handle, code);
        task.state = TaskState::Ready;
    }
}

/// `CreateProcess` syscall: restart a dormant supervised task.
///
/// Requires ManageProcesses (checked by `authorize`) and a process capability
/// with CONTROL over the slot (forged handles terminate the caller). Returns
/// EBUSY if the task is alive and EPERM once the kernel quota is exhausted.
fn process_restart(system: &mut System, frame: &mut SyscallFrame) {
    let resolved = current_task(system)
        .ok_or(IpcViolation::InvalidHandle)
        .and_then(|task| {
            let handle = task.processes.handle_from_raw(frame.rdi);
            task.processes
                .get(handle, Rights::CONTROL)
                .copied()
                .map_err(table_violation)
        });
    let slot = match resolved {
        Ok(slot) => slot,
        Err(violation) => terminate(system, TaskExit::Ipc(violation)),
    };
    match system.dormant[slot] {
        None => frame.rax = EBUSY,
        Some(dormant) if dormant.restarts >= MAX_RESTARTS => frame.rax = EPERM,
        Some(_) => park(system, frame, TaskState::Ready, Event::Restart(slot)),
    }
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
    let mut processes = CapabilityTable::new(table_id).map_err(|_| "capability table")?;
    let mut frame = UserContext {
        rip: USER_CODE_BASE,
        rsp: USER_STACK_TOP,
        ..UserContext::default()
    };
    let mut raw = [0u64; 2];
    for (slot, grant) in raw.iter_mut().zip(spec.endpoints) {
        if let Some((endpoint, rights)) = grant {
            *slot = endpoints
                .insert(endpoint, rights)
                .map_err(|_| "capability grant failed")?
                .to_raw();
        }
    }
    frame.rdi = raw[0];
    frame.rsi = raw[1];
    let mut process_handle = None;
    if let Some(target) = spec.process {
        let handle = processes
            .insert(target, Rights::CONTROL)
            .map_err(|_| "process capability grant failed")?
            .to_raw();
        frame.rdx = handle;
        process_handle = Some((target, handle));
    }

    let syscalls = (1 << Syscall::Write as u8) | (1 << Syscall::Exit as u8) | spec.extra_syscalls;
    let mut capabilities = CapabilitySet::EMPTY;
    capabilities.grant(Capability::WriteConsole);
    if spec.manage_processes {
        capabilities.grant(Capability::ManageProcesses);
    }
    Ok(Task {
        spec,
        state: TaskState::Ready,
        root,
        policy: SyscallPolicy::new(SyscallSet::from_bits(syscalls)),
        capabilities,
        endpoints,
        processes,
        process_handle,
        context: frame,
        ticks: 0,
        slice: 0,
        preemptions: 0,
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

/// Picks the next ready task: priority tasks first, then round-robin.
fn pick_next(system: &System, after: usize) -> Option<usize> {
    let ready = |index: usize| {
        system.tasks[index]
            .as_ref()
            .is_some_and(|task| task.state == TaskState::Ready)
    };
    let priority = (0..MAX_TASKS).find(|&index| {
        ready(index)
            && system.tasks[index]
                .as_ref()
                .is_some_and(|task| task.spec.priority)
    });
    priority.or_else(|| {
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
    preemptions: u32,
    reclaimed: bool,
}

/// Runs a set of tasks until none is ready.
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
            dormant: [None; MAX_TASKS],
            endpoints: [EndpointState::default(); ENDPOINT_COUNT],
            notice_handles: [0; MAX_TASKS],
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
        start_task(memory, kernel_root, system, index, *spec, 0, &mut outcomes);
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
        let (root, context) = (task.root, task.context);
        let saved = core::ptr::addr_of_mut!(system.saved_kernel_rsp);
        let trap_top = trap_stack_top();
        // SAFETY: The task root shares the kernel half (code, stacks, tables
        // are mapped); its entry/stack are mapped; the trap stack is dedicated
        // and installed as rsp0. CR3 is restored before any other use.
        let started = unsafe {
            gdt::set_privilege0_stack(trap_top);
            load_page_table_root(root.get());
            let result = syscall::resume_user(saved, &context, trap_top);
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
        match system.event {
            Event::Ended => reap(memory, system, next, &mut outcomes),
            Event::Restart(slot) => {
                let result = restart(memory, kernel_root, system, slot, &mut outcomes);
                if let Some(requester) = system.tasks[next].as_mut() {
                    requester.context.rax = result;
                }
            }
            Event::Blocked | Event::Preempted => {}
        }
    }

    // Shutdown: blocked tasks (servers waiting for requests) are stopped and
    // dormant tasks keep their last exit.
    if let Some(system) = system_state() {
        for index in 0..MAX_TASKS {
            if let Some(task) = system.tasks[index].as_mut() {
                task.exit = Some(TaskExit::Stopped);
                task.state = TaskState::Dead;
                reap_final(memory, system, index, &mut outcomes);
            } else if let Some(dormant) = system.dormant[index].take() {
                outcomes[index] = Some(Outcome {
                    spec: dormant.spec,
                    exit: dormant.exit,
                    restarts: dormant.restarts,
                    preemptions: 0,
                    reclaimed: true,
                });
            }
        }
    }
    // SAFETY: No task is running; drop the system state.
    unsafe { *core::ptr::addr_of_mut!(SYSTEM) = None };

    let reclaimed = memory.free_frames() == frames_before;
    for outcome in outcomes.iter_mut().flatten() {
        outcome.reclaimed = outcome.reclaimed && reclaimed;
    }
    outcomes
}

fn start_task(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    system: &mut System,
    index: usize,
    spec: TaskSpec,
    restarts: u32,
    outcomes: &mut [Option<Outcome>; MAX_TASKS],
) -> bool {
    let table_id = system.next_table_id;
    system.next_table_id += 1;
    match spawn(memory, kernel_root, spec, table_id, restarts) {
        Ok(task) => {
            if let Some((target, raw)) = task.process_handle {
                system.notice_handles[target] = raw;
            }
            system.tasks[index] = Some(task);
            true
        }
        Err(reason) => {
            let mut writer = SerialWriter;
            let _ = write!(
                writer,
                "Isolation: task {} could not run: {reason}\r\n",
                spec.name
            );
            outcomes[index] = Some(Outcome {
                spec,
                exit: None,
                restarts,
                preemptions: 0,
                reclaimed: false,
            });
            false
        }
    }
}

/// Restarts a dormant slot on behalf of its supervisor; returns the status.
fn restart(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    system: &mut System,
    slot: usize,
    outcomes: &mut [Option<Outcome>; MAX_TASKS],
) -> u64 {
    let Some(dormant) = system.dormant[slot].take() else {
        return EBUSY;
    };
    let restarts = dormant.restarts + 1;
    if start_task(
        memory,
        kernel_root,
        system,
        slot,
        dormant.spec,
        restarts,
        outcomes,
    ) {
        let mut writer = SerialWriter;
        let _ = write!(
            writer,
            "Kernel: restarted {} at init's request (fresh memory and capabilities, restart {restarts}/{MAX_RESTARTS}).\r\n",
            dormant.spec.name
        );
        STATUS_OK
    } else {
        EPERM
    }
}

/// Handles a task that ended: wake its waiting caller, reclaim its memory,
/// and either notify its supervisor (task goes dormant) or finalize it.
fn reap(
    memory: &mut HhdmFrameMemory<'_, '_>,
    system: &mut System,
    index: usize,
    outcomes: &mut [Option<Outcome>; MAX_TASKS],
) {
    let Some(task) = system.tasks[index].as_ref() else {
        return;
    };
    let (spec, serving, restarts, exit) = (task.spec, task.serving, task.restarts, task.exit);
    for endpoint in system.endpoints.iter_mut() {
        if let Some(caller) = endpoint.rendezvous.on_task_death(index, serving)
            && let Some(caller) = system.tasks[caller].as_mut()
            && caller.state == TaskState::BlockedReply
        {
            deliver_status(caller, STATUS_PEER_DIED);
            caller.state = TaskState::Ready;
        }
    }
    let Some(supervisor) = spec.supervisor else {
        reap_final(memory, system, index, outcomes);
        return;
    };

    let mut writer = SerialWriter;
    let _ = write!(writer, "Kernel: service {} ", spec.name);
    if let Some(exit) = exit {
        describe(exit, &mut writer);
    }
    serial_write("; notifying its supervisor.\r\n");
    if let Some(old) = system.tasks[index].take() {
        // Its capability tables, and every handle they issued, die here.
        let _ = destroy_user_address_space(memory, old.root);
    }
    system.dormant[index] = Some(Dormant {
        spec,
        restarts,
        exit,
    });
    system.endpoints[supervisor].pending_notices |= 1 << index;
    deliver_pending_notice(system, supervisor);
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
        let _ = endpoint.rendezvous.on_task_death(index, false);
    }
    let reclaimed = destroy_user_address_space(memory, task.root).is_ok();
    outcomes[index] = Some(Outcome {
        spec: task.spec,
        exit: task.exit,
        restarts: task.restarts,
        preemptions: task.preemptions,
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
            "terminated: malformed IPC message (over {MAX_MESSAGE_WORDS} words or invalid flags)"
        ),
        TaskExit::Ipc(IpcViolation::RightsAmplification) => {
            write!(writer, "terminated: tried to grant rights it does not hold")
        }
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
    let ok = outcome
        .spec
        .expect
        .matches(exit, outcome.restarts, outcome.preemptions)
        && outcome.reclaimed;
    let _ = write!(
        writer,
        "Isolation: task {} [{}]: ",
        outcome.spec.name, outcome.spec.role
    );
    describe(exit, &mut writer);
    if outcome.restarts > 0 {
        let _ = write!(writer, " (restarted {}x)", outcome.restarts);
    }
    if outcome.preemptions > 0 {
        let _ = write!(writer, " (preempted {}x)", outcome.preemptions);
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
        endpoints: [None, None],
        process: None,
        manage_processes: false,
        priority: false,
        supervisor: None,
        expect,
    }
}

const IPC_SYSCALLS: u64 = (1 << Syscall::IpcCall as u8) | (1 << Syscall::IpcReplyWait as u8);

/// A client-side task holding only a SEND capability to init's endpoint.
const fn init_client(
    name: &'static str,
    role: &'static str,
    program: fn() -> &'static [u8],
    expect: Expect,
) -> TaskSpec {
    TaskSpec {
        name,
        role,
        program,
        extra_syscalls: IPC_SYSCALLS,
        endpoints: [Some((ENDPOINT_INIT, SEND)), None],
        process: None,
        manage_processes: false,
        priority: false,
        supervisor: None,
        expect,
    }
}

/// Runs every isolation scenario and the service-manager scenario.
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

    // Preemption scenario: two CPU-bound tasks that never yield must both
    // finish, interleaved by the timer.
    let workers = [
        isolated(
            "worker-a",
            "CPU-bound, never yields",
            p::worker,
            0,
            Expect::ExitAfterPreemption(0),
        ),
        isolated(
            "worker-b",
            "CPU-bound, never yields",
            p::worker,
            0,
            Expect::ExitAfterPreemption(0),
        ),
    ];
    let outcomes = run_system(memory, kernel_root, hhdm, &workers);
    let preemption_ok = outcomes
        .iter()
        .flatten()
        .filter(|outcome| report(outcome))
        .count()
        == workers.len();
    let _ = write!(
        writer,
        "Scheduler: preemptive time slicing {}.\r\n",
        if preemption_ok {
            "verified (both CPU-bound tasks finished)"
        } else {
            "FAILED"
        }
    );

    // Service-manager scenario. Slot 1 is the adder service whose process
    // capability init holds.
    let scenario = [
        TaskSpec {
            name: "init",
            role: "Ring 3 service manager: directory + restart policy",
            program: p::init,
            extra_syscalls: IPC_SYSCALLS | (1 << Syscall::CreateProcess as u8),
            endpoints: [
                Some((ENDPOINT_INIT, RECEIVE)),
                Some((ENDPOINT_ADDER, SEND.union(Rights::GRANT))),
            ],
            process: Some(1),
            manage_processes: true,
            priority: true,
            supervisor: None,
            expect: Expect::Service { restarts: 0 },
        },
        TaskSpec {
            name: "adder-service",
            role: "Ring 3 service supervised by init",
            program: p::adder_service,
            extra_syscalls: IPC_SYSCALLS,
            endpoints: [Some((ENDPOINT_ADDER, RECEIVE)), None],
            process: None,
            manage_processes: false,
            priority: true,
            supervisor: Some(ENDPOINT_INIT),
            expect: Expect::Service { restarts: 1 },
        },
        init_client(
            "client",
            "gets the service from init; injects a fault",
            p::client,
            Expect::Exit(0),
        ),
        init_client(
            "spoof-notice",
            "forges a kernel death notice",
            p::spoof_notice,
            Expect::Exit(0),
        ),
        init_client(
            "amplify",
            "re-grants its SEND capability with more rights",
            p::amplify,
            Expect::Ipc(IpcViolation::RightsAmplification),
        ),
        init_client(
            "rogue-receive",
            "receive with a SEND-only capability",
            p::rogue_receive,
            Expect::Ipc(IpcViolation::MissingRights),
        ),
        init_client(
            "forged-handle",
            "IPC with a forged handle",
            p::forged_handle,
            Expect::Ipc(IpcViolation::InvalidHandle),
        ),
        init_client(
            "oversized-message",
            "IPC message beyond bounds",
            p::oversized_message,
            Expect::Ipc(IpcViolation::MalformedMessage),
        ),
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
        "Microkernel: {scenario_passed}/{} service-manager checks passed; kernel still running.\r\n",
        scenario.len()
    );
    isolation_ok && preemption_ok && scenario_passed == scenario.len()
}
