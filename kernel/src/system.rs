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

use centinela_hal::cpu::{halt_forever, page_fault_address};
use centinela_hal::gdt;
use centinela_hal::idt::{TrapFrame, exception_name};
use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_hal::syscall::{self, SyscallFrame, UserContext};
use centinela_kernel::ipc::{
    CallOutcome, Endpoint, IpcViolation, MAX_MESSAGE_WORDS, Message, MessageFlags, NOTICE_IRQ,
    NOTICE_SERVICE_DIED, RECEIVE, SEND, STATUS_NO_RECEIVER, STATUS_OK, STATUS_PEER_DIED, TaskId,
    attenuate,
};
use centinela_kernel::memory::address_space::{create_task_root, destroy_user_address_space};
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
    map_task_image, map_user_page, map_user_stack, trampoline_entries, trap_stack_top,
};
use crate::user_programs;
use centinela_kernel::elf::{self, ElfError};
use centinela_security::permissions::PagePermissions;

const MAX_TASKS: usize = 8;
const ENDPOINT_COUNT: usize = 8;
/// Interrupt vectors reserved for IRQs bound to Ring 3 drivers.
pub(crate) const DEVICE_VECTOR_BASE: u64 = 0x24;
const MAX_IRQ_ROUTES: usize = 4;
/// Idle wake-ups (timer ticks or IRQs) allowed while only drivers wait.
const MAX_IDLE_WAKEUPS: u32 = 500;
/// Port ranges the kernel never grants: interrupt controllers, PIT, system
/// control, CMOS/RTC, the kernel's own console (COM1) and PCI configuration.
const KERNEL_PORTS: [(u16, u16); 7] = [
    (0x20, 2),
    (0x40, 4),
    (0x61, 1),
    (0x70, 2),
    (0xa0, 2),
    (0x3f8, 8),
    (0xcf8, 8),
];
/// Kernel-enforced ceiling on restarts per service, whatever init requests.
const MAX_RESTARTS: u32 = 3;
const MAX_WRITE_LENGTH: u64 = 256;
/// Anonymous-memory window (above ELF images, below the stack).
const HEAP_BASE: u64 = 0x0000_7000_0000_0000;
/// Anonymous pages a task may map in total.
const HEAP_QUOTA_PAGES: u64 = 32;
const ENOMEM: u64 = (-12_i64) as u64;
const EFAULT: u64 = (-14_i64) as u64;
const EINVAL: u64 = (-22_i64) as u64;
const ENOSYS: u64 = (-38_i64) as u64;
const EPERM: u64 = (-1_i64) as u64;
const EBUSY: u64 = (-16_i64) as u64;
/// Endpoint served by init (directory and supervisor notices).
const ENDPOINT_INIT: usize = 0;
/// Endpoint served by the adder service.
const ENDPOINT_ADDER: usize = 1;
/// Endpoints on which the Ring 3 UART and keyboard drivers receive IRQs.
const ENDPOINT_UART: usize = 2;
const ENDPOINT_KBD: usize = 3;
/// Phase 5 services: serial console (COM3), RAM filesystem, network.
const ENDPOINT_CONSOLE: usize = 4;
const ENDPOINT_FS: usize = 5;
const ENDPOINT_NET: usize = 6;
/// Capability broker that mints badged filesystem capabilities.
const ENDPOINT_BROKER: usize = 7;

/// Why a driver's device access was refused (always fatal for the task).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceViolation {
    PortOutsideGrant(u16),
    InvalidOperation,
    NoInterruptGrant,
}

/// Hardware a Ring 3 driver may touch, granted by the kernel at start.
#[derive(Clone, Copy)]
struct DeviceGrant {
    /// Mediated port windows: (first port, number of ports); count 0 = unused.
    ports: [(u16, u16); 2],
    /// Legacy ISA IRQ, delivered as a kernel notice on this endpoint.
    irq: Option<(u8, usize)>,
}

impl DeviceGrant {
    fn allows_port(self, port: u64) -> bool {
        self.ports.iter().any(|&(base, count)| {
            let (base, count) = (u64::from(base), u64::from(count));
            port >= base && port < base + count
        })
    }

    fn overlaps_kernel_ports(self) -> bool {
        self.ports.iter().any(|&(base, count)| {
            let (base, count) = (u32::from(base), u32::from(count));
            KERNEL_PORTS.iter().any(|&(start, length)| {
                let (start, length) = (u32::from(start), u32::from(length));
                base < start + length && start < base + count
            })
        })
    }
}

/// An endpoint capability: the endpoint plus the badge the server sees on
/// every request sent through it (0 = unbadged minter capability).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointCap {
    endpoint: usize,
    badge: u64,
}

#[derive(Clone, Copy)]
struct IrqRoute {
    isa_irq: u8,
    endpoint: usize,
    owner: usize,
}

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
    /// The ELF loader refused the image; nothing was executed.
    LoadRejected(ElfError),
    /// A driver touched hardware outside its grant.
    Device(DeviceViolation),
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
            Self::LoadRejected(_) => 7,
            Self::Device(_) => 8,
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
    /// The loader must refuse the image for this reason.
    LoadRejected(ElfError),
    Device(DeviceViolation),
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
            (Self::LoadRejected(expected), TaskExit::LoadRejected(actual)) => expected == actual,
            (Self::Service { restarts: expected }, TaskExit::Stopped) => expected == restarts,
            (Self::Device(expected), TaskExit::Device(actual)) => expected == actual,
            _ => false,
        }
    }
}

/// Where a task's code comes from.
#[derive(Clone, Copy)]
pub enum Image {
    /// Position-independent test code mapped at `USER_CODE_BASE`.
    Flat(fn() -> &'static [u8]),
    /// A static ELF64 executable (from a hashed boot module), parsed and
    /// validated before anything is mapped.
    Elf(&'static [u8]),
}

#[derive(Clone, Copy)]
struct TaskSpec {
    name: &'static str,
    role: &'static str,
    program: Image,
    extra_syscalls: u64,
    /// Endpoint capabilities granted at start; raw handles arrive in RDI,
    /// RSI and (when no process capability is granted) RDX.
    endpoints: [Option<(usize, Rights)>; 3],
    /// Process capability (CONTROL) over this task slot; raw handle in RDX.
    process: Option<usize>,
    manage_processes: bool,
    /// Grants ManageMemory (needed for MapMemory).
    manage_memory: bool,
    /// Scheduled before ordinary tasks (init and services).
    priority: bool,
    /// Endpoint that receives a kernel notice when this task dies.
    supervisor: Option<usize>,
    /// Ports and IRQ of a Ring 3 driver (grants DeviceAccess).
    device: Option<DeviceGrant>,
    /// Start-up argument delivered in RCX (4th SysV argument of `_start`).
    arg: u64,
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
    endpoints: CapabilityTable<EndpointCap, 8>,
    processes: CapabilityTable<usize, 4>,
    /// Raw handle this task holds for the process capability it was granted.
    process_handle: Option<(usize, u64)>,
    context: UserContext,
    ticks: u32,
    /// Ticks used in the current time slice.
    slice: u32,
    preemptions: u32,
    /// Next free address and pages used in the anonymous-memory window.
    heap_next: u64,
    heap_pages: u64,
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
    /// A bound IRQ fired and its notice awaits the receiver.
    pending_irq: Option<u8>,
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
    /// The current task asked for this many anonymous pages.
    MapMemory(u64),
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
    irq_routes: [Option<IrqRoute>; MAX_IRQ_ROUTES],
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
        vector
            if (DEVICE_VECTOR_BASE..DEVICE_VECTOR_BASE + MAX_IRQ_ROUTES as u64)
                .contains(&vector) =>
        {
            device_interrupt((vector - DEVICE_VECTOR_BASE) as usize);
        }
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
        Ok(Syscall::MapMemory) => map_memory_request(system, frame),
        Ok(Syscall::PortIo) => port_io(system, frame),
        Ok(Syscall::IrqAck) => irq_ack(system, frame),
        Ok(Syscall::Revoke) => revoke(system, frame),
        Ok(_) => frame.rax = ENOSYS,
    }
    if frame.sanitize_for_sysret().is_err() {
        terminate(system, TaskExit::BadReturnAddress);
    }
}

/// A bound IRQ fired: mask the line (only the driver re-arms it), then notify
/// the driver through its endpoint as a kernel-origin message.
fn device_interrupt(route: usize) {
    let Some(system) = system_state() else {
        centinela_hal::apic::end_of_interrupt();
        return;
    };
    let Some(IrqRoute {
        isa_irq, endpoint, ..
    }) = system.irq_routes[route]
    else {
        centinela_hal::apic::end_of_interrupt();
        return;
    };
    crate::ioapic::set_masked(isa_irq, true);
    centinela_hal::apic::end_of_interrupt();
    system.endpoints[endpoint].pending_irq = Some(isa_irq);
    deliver_pending_notice(system, endpoint);
}

/// `PortIo`: one 8-bit access, mediated, inside the caller's port grant.
/// RDI = port, RSI = 0 (read) or 1 (write), RDX = value to write.
fn port_io(system: &mut System, frame: &mut SyscallFrame) {
    let grant = current_task(system).and_then(|task| task.spec.device);
    let port = frame.rdi;
    let violation = match grant {
        None => Some(DeviceViolation::PortOutsideGrant(port as u16)),
        Some(grant) if !grant.allows_port(port) => {
            Some(DeviceViolation::PortOutsideGrant(port as u16))
        }
        Some(_) if frame.rsi > 1 || frame.rdx > 0xff => Some(DeviceViolation::InvalidOperation),
        Some(_) => None,
    };
    if let Some(violation) = violation {
        terminate(system, TaskExit::Device(violation));
    }
    let port = port as u16;
    if frame.rsi == 1 {
        let value = frame.rdx as u8;
        // SAFETY: CPL 0; the port lies in a kernel-vetted driver grant that
        // excludes every kernel-owned port range.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value,
                options(nomem, nostack, preserves_flags));
        }
        frame.rax = 0;
    } else {
        let value: u8;
        // SAFETY: As above.
        unsafe {
            core::arch::asm!("in al, dx", in("dx") port, out("al") value,
                options(nomem, nostack, preserves_flags));
        }
        frame.rax = u64::from(value);
    }
}

/// `Revoke`: RDI = an unbadged endpoint capability holding GRANT (the
/// minter), RSI = badge. Removes every badged copy from every task, so all
/// outstanding handles go stale at once. Returns the number revoked.
fn revoke(system: &mut System, frame: &mut SyscallFrame) {
    let minter = current_task(system)
        .ok_or(IpcViolation::InvalidHandle)
        .and_then(|task| resolve_endpoint(task, frame.rdi, Rights::GRANT));
    let cap = match minter {
        Ok(cap) if cap.badge == 0 && frame.rsi != 0 => cap,
        Ok(_) => terminate(system, TaskExit::Ipc(IpcViolation::BadgeForgery)),
        Err(violation) => terminate(system, TaskExit::Ipc(violation)),
    };
    let target = EndpointCap {
        endpoint: cap.endpoint,
        badge: frame.rsi,
    };
    let revoked: usize = system
        .tasks
        .iter_mut()
        .flatten()
        .map(|task| task.endpoints.revoke_matching(|held| *held == target))
        .sum();
    frame.rax = revoked as u64;
}

/// `IrqAck`: re-arms the caller's own bound line; no arguments to forge.
fn irq_ack(system: &mut System, frame: &mut SyscallFrame) {
    let Some(caller) = system.current else { return };
    let route = system
        .irq_routes
        .iter()
        .flatten()
        .find(|route| route.owner == caller)
        .copied();
    match route {
        Some(route) => {
            crate::ioapic::set_masked(route.isa_irq, false);
            frame.rax = 0;
        }
        None => terminate(system, TaskExit::Device(DeviceViolation::NoInterruptGrant)),
    }
}

/// Binds the IRQ of every driver task to a device vector (masked).
fn bind_irqs(system: &mut System) -> bool {
    let mut next = 0;
    for index in 0..MAX_TASKS {
        let Some(task) = system.tasks[index].as_ref() else {
            continue;
        };
        let Some((isa_irq, endpoint)) = task.spec.device.and_then(|device| device.irq) else {
            continue;
        };
        if next >= MAX_IRQ_ROUTES
            // Bound masked: the driver arms its line with IrqAck once ready.
            || !crate::ioapic::route(isa_irq, (DEVICE_VECTOR_BASE + next as u64) as u8, true)
        {
            return false;
        }
        system.irq_routes[next] = Some(IrqRoute {
            isa_irq,
            endpoint,
            owner: index,
        });
        next += 1;
    }
    true
}

/// Masks and forgets every IRQ route owned by task `index`.
fn unbind_irqs(system: &mut System, index: usize) {
    for slot in system.irq_routes.iter_mut() {
        if let Some(route) = *slot
            && route.owner == index
        {
            crate::ioapic::set_masked(route.isa_irq, true);
            system.endpoints[route.endpoint].pending_irq = None;
            *slot = None;
        }
    }
}

/// True while some task other than a long-running service is still alive:
/// only then is it worth sleeping for hardware.
fn work_remaining(system: &System) -> bool {
    system.tasks.iter().flatten().any(|task| {
        task.state != TaskState::Dead && !matches!(task.spec.expect, Expect::Service { .. })
    })
}

/// True if a live driver is blocked waiting for its (armed) interrupt.
fn driver_waiting(system: &System) -> bool {
    system.irq_routes.iter().flatten().any(|route| {
        system.tasks[route.owner]
            .as_ref()
            .is_some_and(|task| task.state == TaskState::BlockedReceive)
    })
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
fn resolve_endpoint(task: &Task, raw: u64, rights: Rights) -> Result<EndpointCap, IpcViolation> {
    let handle = task.endpoints.handle_from_raw(raw);
    task.endpoints
        .get(handle, rights)
        .copied()
        .map_err(table_violation)
}

/// A validated outgoing message, possibly carrying an attenuated capability.
struct Outgoing {
    message: Message,
    transfer: Option<(EndpointCap, Rights)>,
    defer_reply: bool,
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
            let mut cap = *task.endpoints.get(handle, held).map_err(table_violation)?;
            if flags.mint_badge {
                // Only the unbadged minter capability may mint, never badge 0.
                if cap.badge != 0 || frame.r8 == 0 {
                    return Err(IpcViolation::BadgeForgery);
                }
                cap.badge = frame.r8;
            }
            let rights = attenuate(held, requested)?;
            Some((cap, rights))
        }
    };
    let message =
        Message::from_registers(flags.length, [frame.rdx, frame.r10, frame.r8, frame.r9])?;
    Ok(Outgoing {
        message,
        transfer,
        defer_reply: flags.defer_reply,
    })
}

/// Writes a status, message and optional new capability into a receiver's
/// saved registers. The flags word is rebuilt by the kernel, so a sender can
/// never make a message look kernel-originated.
fn deliver(receiver: &mut Task, status: u64, outgoing: &Outgoing, kernel_origin: bool, badge: u64) {
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
    // The badge of the capability the sender used (0 for replies/notices).
    frame.rdi = badge;
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
        defer_reply: false,
    };
    deliver(receiver, status, &empty, false, 0);
}

fn deliver_notice(receiver: &mut Task, process_handle: u64, code: u64) {
    let notice = Outgoing {
        message: Message::from_registers(3, [NOTICE_SERVICE_DIED, process_handle, code, 0])
            .unwrap_or_default(),
        transfer: None,
        defer_reply: false,
    };
    deliver(receiver, STATUS_OK, &notice, true, 0);
}

fn ipc_call(system: &mut System, frame: &mut SyscallFrame) {
    let Some(caller) = system.current else { return };
    let checked = current_task(system)
        .ok_or(IpcViolation::InvalidHandle)
        .and_then(|task| {
            let endpoint = resolve_endpoint(task, frame.rdi, SEND)?;
            let request = outgoing(task, frame)?;
            // Deferring is a server-side operation only.
            if request.defer_reply {
                return Err(IpcViolation::MalformedMessage);
            }
            Ok((endpoint, request))
        });
    let (endpoint, request) = match checked {
        Ok(value) => value,
        Err(violation) => terminate(system, TaskExit::Ipc(violation)),
    };
    let EndpointCap { endpoint, badge } = endpoint;
    match system.endpoints[endpoint].rendezvous.call(caller) {
        CallOutcome::NoReceiver => frame.rax = STATUS_NO_RECEIVER,
        CallOutcome::Delivered { server } => {
            if let Some(server) = system.tasks[server].as_mut() {
                deliver(server, STATUS_OK, &request, false, badge);
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
    let endpoint = endpoint.endpoint;
    let deferred = reply.defer_reply;
    if deferred {
        system.endpoints[endpoint].rendezvous.wait_deferred(server);
    } else if let Some(caller) = system.endpoints[endpoint].rendezvous.reply_wait(server)
        && let Some(caller) = system.tasks[caller].as_mut()
        && caller.state == TaskState::BlockedReply
    {
        deliver(caller, STATUS_OK, &reply, false, 0);
        caller.state = TaskState::Ready;
    }
    if let Some(task) = current_task(system) {
        if !deferred {
            task.serving = false;
        }
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
    if let Some(isa_irq) = system.endpoints[endpoint].pending_irq.take() {
        system.endpoints[endpoint].rendezvous.take_receiver();
        if let Some(task) = system.tasks[receiver].as_mut() {
            let notice = Outgoing {
                message: Message::from_registers(2, [NOTICE_IRQ, u64::from(isa_irq), 0, 0])
                    .unwrap_or_default(),
                transfer: None,
                defer_reply: false,
            };
            deliver(task, STATUS_OK, &notice, true, 0);
            task.state = TaskState::Ready;
        }
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

/// `MapMemory(pages)`: zeroed, writable, never-executable anonymous pages at
/// a kernel-chosen address, within a per-task quota. Allocation happens in
/// the scheduler (which owns the frame allocator), so the request parks.
fn map_memory_request(system: &mut System, frame: &mut SyscallFrame) {
    let pages = frame.rdi;
    let Some(task) = current_task(system) else {
        return;
    };
    if pages == 0 || pages > HEAP_QUOTA_PAGES {
        frame.rax = EINVAL;
    } else if task.heap_pages + pages > HEAP_QUOTA_PAGES {
        frame.rax = ENOMEM;
    } else {
        park(system, frame, TaskState::Ready, Event::MapMemory(pages));
    }
}

fn map_anonymous(memory: &mut HhdmFrameMemory<'_, '_>, task: &mut Task, pages: u64) -> u64 {
    let Ok(rw) = PagePermissions::new(true, true, false, true) else {
        return EINVAL;
    };
    let base = task.heap_next;
    for index in 0..pages {
        if map_user_page(memory, task.root, base + index * PAGE_SIZE, rw, None).is_err() {
            return ENOMEM;
        }
        task.heap_next += PAGE_SIZE;
        task.heap_pages += 1;
    }
    base
}

fn elf_error_text(error: ElfError) -> &'static str {
    match error {
        ElfError::Truncated => "truncated image",
        ElfError::BadMagic => "not an ELF image",
        ElfError::Unsupported => "unsupported ELF type, class or machine",
        ElfError::BadProgramHeaders => "invalid program header table",
        ElfError::TooManySegments => "too many segments",
        ElfError::SegmentOutOfBounds => "segment outside the file",
        ElfError::SegmentOutsideUserWindow => "segment outside the user window",
        ElfError::MisalignedSegment => "misaligned segment",
        ElfError::OverlappingSegments => "overlapping segments",
        ElfError::WritableAndExecutable => "segment both writable and executable (W^X)",
        ElfError::EntryNotExecutable => "entry point outside executable code",
        ElfError::TooLarge => "image exceeds the page limit",
        ElfError::NoLoadableSegments => "no loadable segments",
    }
}

/// Maps a validated ELF plan page by page; returns the entry point.
fn map_elf(
    memory: &mut HhdmFrameMemory<'_, '_>,
    root: PhysAddr,
    image: &[u8],
    plan: &elf::LoadPlan,
) -> Result<u64, &'static str> {
    for segment in plan.segments() {
        let permissions = PagePermissions::new(true, segment.writable, segment.executable, true)
            .map_err(|_| "W^X")?;
        let file_start = segment.vaddr;
        let file_end = segment.vaddr + segment.file_size;
        let mut page = segment.page_start;
        while page < segment.page_end {
            // File bytes overlapping this page; the rest stays zero (bss).
            let copy_start = file_start.max(page);
            let copy_end = file_end.min(page + PAGE_SIZE);
            let contents = if copy_start < copy_end {
                let offset = (segment.file_offset + (copy_start - file_start)) as usize;
                let length = (copy_end - copy_start) as usize;
                let bytes = image
                    .get(offset..offset + length)
                    .ok_or("segment outside the file")?;
                Some(((copy_start - page) as usize, bytes))
            } else {
                None
            };
            map_user_page(memory, root, page, permissions, contents)?;
            page += PAGE_SIZE;
        }
    }
    Ok(plan.entry)
}

/// Why a task could not be created.
#[derive(Clone, Copy, Debug)]
enum SpawnError {
    /// The ELF loader refused the image (a containment event).
    Rejected(ElfError),
    Failed(&'static str),
}

/// Builds a task's address space and initial register state.
fn spawn(
    memory: &mut HhdmFrameMemory<'_, '_>,
    // Unused since KPTI: task roots share only the entry trampoline.
    _kernel_root: PhysAddr,
    spec: TaskSpec,
    table_id: u32,
    restarts: u32,
) -> Result<Task, SpawnError> {
    // Validate an ELF image completely before allocating anything.
    let elf_plan = match spec.program {
        Image::Elf(bytes) => Some(elf::plan(bytes).map_err(SpawnError::Rejected)?),
        Image::Flat(program) => {
            let program = program();
            if program.is_empty() || program.len() > PAGE_SIZE as usize {
                return Err(SpawnError::Failed("program does not fit in one page"));
            }
            None
        }
    };
    // KPTI: the task root holds the user half plus the entry trampoline only.
    let root = create_task_root(memory, trampoline_entries())
        .map_err(|_| SpawnError::Failed("address space creation failed"))?;
    let mapped = match (spec.program, elf_plan) {
        (Image::Elf(bytes), Some(plan)) => map_elf(memory, root, bytes, &plan)
            .and_then(|entry| map_user_stack(memory, root).map(|()| entry)),
        (Image::Flat(program), _) => {
            map_task_image(memory, root, program()).map(|()| USER_CODE_BASE)
        }
        _ => Err("inconsistent image"),
    };
    let entry = match mapped {
        Ok(entry) => entry,
        Err(reason) => {
            let _ = destroy_user_address_space(memory, root);
            return Err(SpawnError::Failed(reason));
        }
    };

    let fail = |reason| move |_| SpawnError::Failed(reason);
    let mut endpoints = CapabilityTable::new(table_id).map_err(fail("capability table"))?;
    let mut processes = CapabilityTable::new(table_id).map_err(fail("capability table"))?;
    // RSP ≡ 8 (mod 16) at entry, as after a call, per the SysV ABI.
    let mut frame = UserContext {
        rip: entry,
        rsp: USER_STACK_TOP - 8,
        ..UserContext::default()
    };
    let mut raw = [0u64; 3];
    for (slot, grant) in raw.iter_mut().zip(spec.endpoints) {
        if let Some((endpoint, rights)) = grant {
            *slot = endpoints
                .insert(EndpointCap { endpoint, badge: 0 }, rights)
                .map_err(fail("capability grant failed"))?
                .to_raw();
        }
    }
    frame.rdi = raw[0];
    frame.rsi = raw[1];
    frame.rdx = raw[2];
    frame.rcx = spec.arg;
    let mut process_handle = None;
    if spec.process.is_some() && spec.endpoints[2].is_some() {
        let _ = destroy_user_address_space(memory, root);
        return Err(SpawnError::Failed(
            "RDX carries either an endpoint or a process handle",
        ));
    }
    if let Some(target) = spec.process {
        let handle = processes
            .insert(target, Rights::CONTROL)
            .map_err(fail("process capability grant failed"))?
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
    if spec.manage_memory {
        capabilities.grant(Capability::ManageMemory);
    }
    if let Some(device) = spec.device {
        if device.overlaps_kernel_ports() {
            let _ = destroy_user_address_space(memory, root);
            return Err(SpawnError::Failed(
                "device grant overlaps kernel-owned ports",
            ));
        }
        capabilities.grant(Capability::DeviceAccess);
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
        heap_next: HEAP_BASE,
        heap_pages: 0,
        serving: false,
        restarts,
        exit: None,
    })
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
            irq_routes: [None; MAX_IRQ_ROUTES],
        });
    }
    let Some(system) = system_state() else {
        return outcomes;
    };
    for (index, spec) in specs.iter().take(MAX_TASKS).enumerate() {
        start_task(memory, kernel_root, system, index, *spec, 0, &mut outcomes);
    }
    if !bind_irqs(system) {
        serial_write("Centinela-OS: could not route a driver IRQ.\r\n");
    }

    let mut last = MAX_TASKS - 1;
    let mut idle_wakeups = 0u32;
    while let Some(system) = system_state() {
        let Some(next) = pick_next(system, last) else {
            // Only drivers waiting for hardware: sleep until an interrupt.
            if driver_waiting(system) && work_remaining(system) && idle_wakeups < MAX_IDLE_WAKEUPS {
                idle_wakeups += 1;
                // SAFETY: Interrupts are enabled only for this one HLT; the
                // handlers re-borrow the system state themselves and no
                // reference to it is live across the wait.
                unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
                continue;
            }
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
        // KPTI: the entry stubs switch CR3 to the task root on the way in and
        // back to the kernel root on every trap or syscall.
        let started = unsafe {
            gdt::set_privilege0_stack(trap_top);
            syscall::resume_user(saved, &context, trap_top, root.get())
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
            Event::MapMemory(pages) => {
                if let Some(task) = system.tasks[next].as_mut() {
                    task.context.rax = map_anonymous(memory, task, pages);
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
        Err(SpawnError::Rejected(error)) => {
            let mut writer = SerialWriter;
            let _ = write!(
                writer,
                "ELF loader: refused {}: {}; nothing was mapped or executed.\r\n",
                spec.name,
                elf_error_text(error)
            );
            outcomes[index] = Some(Outcome {
                spec,
                exit: Some(TaskExit::LoadRejected(error)),
                restarts,
                preemptions: 0,
                reclaimed: true,
            });
            false
        }
        Err(SpawnError::Failed(reason)) => {
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
    unbind_irqs(system, index);
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
    unbind_irqs(system, index);
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
        TaskExit::Ipc(IpcViolation::BadgeForgery) => {
            write!(writer, "terminated: tried to mint or forge a badge")
        }
        TaskExit::Ipc(IpcViolation::RightsAmplification) => {
            write!(writer, "terminated: tried to grant rights it does not hold")
        }
        TaskExit::BadReturnAddress => write!(writer, "terminated: invalid return address"),
        TaskExit::CpuBudgetExceeded => write!(writer, "terminated: CPU budget exceeded"),
        TaskExit::Stopped => write!(writer, "still serving at shutdown"),
        TaskExit::Device(DeviceViolation::PortOutsideGrant(port)) => {
            write!(
                writer,
                "terminated: port {port:#x} outside its device grant"
            )
        }
        TaskExit::Device(DeviceViolation::InvalidOperation) => {
            write!(writer, "terminated: invalid port operation")
        }
        TaskExit::Device(DeviceViolation::NoInterruptGrant) => {
            write!(writer, "terminated: acknowledged an IRQ it does not own")
        }
        TaskExit::LoadRejected(error) => {
            write!(
                writer,
                "refused by the ELF loader: {}",
                elf_error_text(error)
            )
        }
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
        program: Image::Flat(program),
        extra_syscalls,
        endpoints: [None, None, None],
        process: None,
        manage_processes: false,
        manage_memory: false,
        priority: false,
        supervisor: None,
        device: None,
        arg: 0,
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
        program: Image::Flat(program),
        extra_syscalls: IPC_SYSCALLS,
        endpoints: [Some((ENDPOINT_INIT, SEND)), None, None],
        process: None,
        manage_processes: false,
        manage_memory: false,
        priority: false,
        supervisor: None,
        device: None,
        arg: 0,
        expect,
    }
}

/// Runs every isolation scenario and the service-manager scenario.
pub fn run_self_test(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
    modules: &[(&'static str, &'static [u8])],
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

    // ELF scenario: user programs come from hashed boot modules. One is a
    // benign Rust program; the other deliberately has a W+X segment.
    let module = |name: &str| {
        modules
            .iter()
            .find(|(module, _)| *module == name)
            .map(|(_, bytes)| *bytes)
    };
    let elf_ok = match (module("elf-hello"), module("elf-wx")) {
        (Some(hello), Some(wx)) => {
            let elf_task = |name, role, bytes, expect| TaskSpec {
                name,
                role,
                program: Image::Elf(bytes),
                extra_syscalls: 1 << Syscall::MapMemory as u8,
                endpoints: [None, None, None],
                process: None,
                manage_processes: false,
                manage_memory: true,
                priority: false,
                supervisor: None,
                device: None,
                arg: 0,
                expect,
            };
            let elf_tasks = [
                elf_task(
                    "elf-hello",
                    "Rust ELF from a verified boot module",
                    hello,
                    Expect::Exit(0),
                ),
                elf_task(
                    "elf-wx",
                    "ELF with a writable+executable segment",
                    wx,
                    Expect::LoadRejected(ElfError::WritableAndExecutable),
                ),
            ];
            let outcomes = run_system(memory, kernel_root, hhdm, &elf_tasks);
            outcomes
                .iter()
                .flatten()
                .filter(|outcome| report(outcome))
                .count()
                == elf_tasks.len()
        }
        _ => {
            serial_write("Centinela-OS: required ELF boot modules are missing.\r\n");
            false
        }
    };
    let _ = write!(
        writer,
        "ELF loader: {}.\r\n",
        if elf_ok {
            "verified (Rust ELF ran; W+X image refused)"
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
            program: Image::Flat(p::init),
            extra_syscalls: IPC_SYSCALLS | (1 << Syscall::CreateProcess as u8),
            endpoints: [
                Some((ENDPOINT_INIT, RECEIVE)),
                Some((ENDPOINT_ADDER, SEND.union(Rights::GRANT))),
                None,
            ],
            process: Some(1),
            manage_processes: true,
            manage_memory: false,
            priority: true,
            supervisor: None,
            device: None,
            arg: 0,
            expect: Expect::Service { restarts: 0 },
        },
        TaskSpec {
            name: "adder-service",
            role: "Ring 3 service supervised by init",
            program: Image::Flat(p::adder_service),
            extra_syscalls: IPC_SYSCALLS,
            endpoints: [Some((ENDPOINT_ADDER, RECEIVE)), None, None],
            process: None,
            manage_processes: false,
            manage_memory: false,
            priority: true,
            supervisor: Some(ENDPOINT_INIT),
            device: None,
            arg: 0,
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
    let drivers_ok = run_driver_scenario(memory, kernel_root, hhdm, &module);
    let services_ok = run_services_scenario(memory, kernel_root, hhdm, &module);
    let badges_ok = run_badge_scenario(memory, kernel_root, hhdm, &module);
    isolation_ok
        && preemption_ok
        && elf_ok
        && scenario_passed == scenario.len()
        && drivers_ok
        && services_ok
        && badges_ok
}

/// Identity and revocation: a broker mints badged filesystem capabilities;
/// tenants get disjoint namespaces, a relinquished badge is revoked in every
/// task at once, and re-minting a badge is refused.
fn run_badge_scenario(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
    module: &dyn Fn(&str) -> Option<&'static [u8]>,
) -> bool {
    let (Some(ramfs), Some(broker), Some(client)) =
        (module("ramfs"), module("broker"), module("badge-client"))
    else {
        serial_write("Centinela-OS: required badge boot modules are missing.\r\n");
        return false;
    };
    let spec = |name, role, image, endpoints, extra: u64, arg, expect| TaskSpec {
        name,
        role,
        program: Image::Elf(image),
        extra_syscalls: IPC_SYSCALLS | extra,
        endpoints,
        process: None,
        manage_processes: false,
        manage_memory: extra & (1 << Syscall::MapMemory as u8) != 0,
        priority: matches!(expect, Expect::Service { .. }),
        supervisor: None,
        device: None,
        arg,
        expect,
    };
    let tenant = |name, role, arg, expect| {
        spec(
            name,
            role,
            client,
            [Some((ENDPOINT_BROKER, SEND)), None, None],
            0,
            arg,
            expect,
        )
    };
    let tasks = [
        spec(
            "ramfs",
            "filesystem keyed by caller badge",
            ramfs,
            [Some((ENDPOINT_FS, RECEIVE)), None, None],
            1 << Syscall::MapMemory as u8,
            0,
            Expect::Service { restarts: 0 },
        ),
        spec(
            "broker",
            "holds the only minter capability to the filesystem",
            broker,
            [
                Some((ENDPOINT_BROKER, RECEIVE)),
                Some((ENDPOINT_FS, SEND.union(Rights::GRANT))),
                None,
            ],
            1 << Syscall::Revoke as u8,
            0,
            Expect::Service { restarts: 0 },
        ),
        tenant(
            "tenant-a",
            "badged tenant: private namespace",
            1,
            Expect::Exit(0),
        ),
        tenant(
            "tenant-b",
            "relinquishes its badge, then reuses the handle",
            2,
            Expect::Ipc(IpcViolation::InvalidHandle),
        ),
        tenant(
            "badge-forger",
            "re-mints its badge to impersonate tenant-a",
            3,
            Expect::Ipc(IpcViolation::BadgeForgery),
        ),
    ];
    let outcomes = run_system(memory, kernel_root, hhdm, &tasks);
    let passed = outcomes
        .iter()
        .flatten()
        .filter(|outcome| report(outcome))
        .count();
    let mut writer = SerialWriter;
    let _ = write!(
        writer,
        "Capabilities: {passed}/{} badge and revocation checks passed.\r\n",
        tasks.len()
    );
    passed == tasks.len()
}

/// Phase 5: a shell on the serial console driving a RAM filesystem and a
/// loopback network service, all in Ring 3, plus a hostile filesystem client.
fn run_services_scenario(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
    module: &dyn Fn(&str) -> Option<&'static [u8]>,
) -> bool {
    let mut writer = SerialWriter;
    let names = ["serial-service", "ramfs", "netsvc", "shell", "fs-fuzzer"];
    let mut images = [&[][..]; 5];
    for (image, name) in images.iter_mut().zip(names) {
        let Some(bytes) = module(name) else {
            serial_write("Centinela-OS: required service boot modules are missing.\r\n");
            return false;
        };
        *image = bytes;
    }
    let service = |name, role, image, endpoints, extra, expect| TaskSpec {
        name,
        role,
        program: Image::Elf(image),
        extra_syscalls: IPC_SYSCALLS | extra,
        endpoints,
        process: None,
        manage_processes: false,
        manage_memory: extra & (1 << Syscall::MapMemory as u8) != 0,
        priority: matches!(expect, Expect::Service { .. }),
        supervisor: None,
        device: None,
        arg: 0,
        expect,
    };
    let device_syscalls = (1 << Syscall::PortIo as u8) | (1 << Syscall::IrqAck as u8);
    let mut console = service(
        "serial-service",
        "Ring 3 console driver: COM3 ports + IRQ 4, deferred replies",
        images[0],
        [Some((ENDPOINT_CONSOLE, RECEIVE)), None, None],
        device_syscalls,
        Expect::Service { restarts: 0 },
    );
    console.device = Some(DeviceGrant {
        ports: [(0x3e8, 8), (0, 0)],
        irq: Some((4, ENDPOINT_CONSOLE)),
    });
    let tasks = [
        console,
        service(
            "ramfs",
            "Ring 3 RAM filesystem service",
            images[1],
            [Some((ENDPOINT_FS, RECEIVE)), None, None],
            1 << Syscall::MapMemory as u8,
            Expect::Service { restarts: 0 },
        ),
        service(
            "netsvc",
            "Ring 3 loopback network service",
            images[2],
            [Some((ENDPOINT_NET, RECEIVE)), None, None],
            0,
            Expect::Service { restarts: 0 },
        ),
        service(
            "shell",
            "Ring 3 shell: SEND to console, fs and net only",
            images[3],
            [
                Some((ENDPOINT_CONSOLE, SEND)),
                Some((ENDPOINT_FS, SEND)),
                Some((ENDPOINT_NET, SEND)),
            ],
            0,
            Expect::Exit(0),
        ),
        service(
            "fs-fuzzer",
            "hostile client sending malformed filesystem requests",
            images[4],
            [Some((ENDPOINT_FS, SEND)), None, None],
            0,
            Expect::Exit(0),
        ),
    ];
    let outcomes = run_system(memory, kernel_root, hhdm, &tasks);
    let passed = outcomes
        .iter()
        .flatten()
        .filter(|outcome| report(outcome))
        .count();
    let _ = write!(
        writer,
        "Services: {passed}/{} checks passed (shell over serial, ramfs, loopback network, IPC benchmark).\r\n",
        tasks.len()
    );
    passed == tasks.len()
}

/// Ring 3 drivers: hardware access only through kernel-mediated grants, and
/// IRQs delivered as kernel-origin IPC notices.
fn run_driver_scenario(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
    module: &dyn Fn(&str) -> Option<&'static [u8]>,
) -> bool {
    use user_programs as p;
    let mut writer = SerialWriter;
    let (Some(uart), Some(kbd)) = (module("uart-driver"), module("kbd-driver")) else {
        serial_write("Centinela-OS: required driver boot modules are missing.\r\n");
        return false;
    };
    let device_syscalls =
        IPC_SYSCALLS | (1 << Syscall::PortIo as u8) | (1 << Syscall::IrqAck as u8);
    let task = |name, role, program, endpoint: Option<usize>, device, expect| TaskSpec {
        name,
        role,
        program,
        extra_syscalls: device_syscalls,
        endpoints: [endpoint.map(|endpoint| (endpoint, RECEIVE)), None, None],
        process: None,
        manage_processes: false,
        manage_memory: false,
        priority: false,
        supervisor: None,
        device,
        arg: 0,
        expect,
    };
    let tasks = [
        task(
            "uart-driver",
            "Ring 3 16550 driver: COM2 ports + IRQ 3",
            Image::Elf(uart),
            Some(ENDPOINT_UART),
            Some(DeviceGrant {
                ports: [(0x2f8, 8), (0, 0)],
                irq: Some((3, ENDPOINT_UART)),
            }),
            Expect::Exit(0),
        ),
        task(
            "kbd-driver",
            "Ring 3 i8042 keyboard driver: ports 0x60/0x64 + IRQ 1",
            Image::Elf(kbd),
            Some(ENDPOINT_KBD),
            Some(DeviceGrant {
                ports: [(0x60, 1), (0x64, 1)],
                irq: Some((1, ENDPOINT_KBD)),
            }),
            Expect::Exit(0),
        ),
        task(
            "port-escape",
            "COM4 driver reaches for the kernel console",
            Image::Flat(p::port_escape),
            None,
            Some(DeviceGrant {
                ports: [(0x2e8, 8), (0, 0)],
                irq: None,
            }),
            Expect::Device(DeviceViolation::PortOutsideGrant(0x3f8)),
        ),
        task(
            "irq-forge",
            "re-arms an IRQ it was never bound to",
            Image::Flat(p::irq_forge),
            None,
            Some(DeviceGrant {
                ports: [(0x278, 3), (0, 0)],
                irq: None,
            }),
            Expect::Device(DeviceViolation::NoInterruptGrant),
        ),
        task(
            "no-device-cap",
            "port I/O syscall without DeviceAccess",
            Image::Flat(p::no_device_cap),
            None,
            None,
            Expect::CapabilityDenied,
        ),
    ];
    let outcomes = run_system(memory, kernel_root, hhdm, &tasks);
    let passed = outcomes
        .iter()
        .flatten()
        .filter(|outcome| report(outcome))
        .count();
    let _ = write!(
        writer,
        "Drivers: {passed}/{} Ring 3 driver checks passed (UART and keyboard IRQs as kernel notices).\r\n",
        tasks.len()
    );
    passed == tasks.len()
}
