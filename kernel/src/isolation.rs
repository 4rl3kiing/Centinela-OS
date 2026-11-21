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
use core::ptr::addr_of;

use centinela_hal::apic;
use centinela_hal::cpu::{halt_forever, page_fault_address};
use centinela_hal::gdt::{self, TssStacks};
use centinela_hal::idt::{self, TrapFrame, exception_name};
use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_hal::syscall;
use centinela_kernel::memory::hhdm_backend::HhdmFrameMemory;
use centinela_kernel::memory::vmm::{
    MappingTransactionError, PAGE_SIZE, PageMapping, PageTableMapper, PageTableMutationMemory,
    PhysAddr, VirtAddr,
};
use centinela_security::permissions::PagePermissions;

const KERNEL_STACK_SIZE: usize = 16 * 1024;
pub(crate) const USER_CODE_BASE: u64 = 0x0000_0000_0040_0000;
pub(crate) const USER_STACK_TOP: u64 = 0x0000_7fff_0000_0000;
const USER_STACK_PAGES: u64 = 4;
/// Kernel-only virtual address of the local APIC registers (PML4 slot 511,
/// shared supervisor-only by every address space; outside HHDM and image).
const APIC_MMIO_VIRTUAL: u64 = 0xffff_ffff_7000_0000;
/// Scheduler/watchdog tick length; the APIC timer is calibrated against the
/// PIT so this is real time, not bus-clock dependent.
pub(crate) const TICK_MS: u32 = 10;
/// Total CPU time a task may consume before the watchdog terminates it.
pub(crate) const CPU_BUDGET_MS: u32 = 2_000;
pub(crate) const CPU_BUDGET_TICKS: u32 = CPU_BUDGET_MS / TICK_MS;
/// Time slice before a ready task is preempted in favour of another.
pub(crate) const QUANTUM_TICKS: u32 = 2;
/// Fallback reload if calibration fails (QEMU's 1 GHz bus / 16 ≈ 10 ms).
const FALLBACK_INITIAL_COUNT: u32 = 625_000;

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

/// Top of the kernel stack used for traps and syscalls from Ring 3.
pub(crate) fn trap_stack_top() -> u64 {
    stack_bounds(addr_of!(TRAP_STACK)).1
}

fn stack_bounds(stack: *const GuardedStack) -> (u64, u64) {
    let guard = stack as u64;
    (guard, guard + core::mem::size_of::<GuardedStack>() as u64)
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
        idt::init(crate::system::trap_handler);
        syscall::init(crate::system::syscall_handler);
        let per_ms = apic::calibrate(APIC_MMIO_VIRTUAL);
        let reload = per_ms
            .map(|counts| (counts * u64::from(TICK_MS)).min(u64::from(u32::MAX)) as u32)
            .unwrap_or(FALLBACK_INITIAL_COUNT);
        apic::init(APIC_MMIO_VIRTUAL, reload);
        let mut writer = SerialWriter;
        match per_ms {
            Some(counts) => {
                let _ = write!(
                    writer,
                    "Isolation: APIC timer calibrated against PIT: {counts} counts/ms; {TICK_MS} ms ticks.\r\n"
                );
            }
            None => serial_write("Isolation: APIC calibration failed; using fallback tick.\r\n"),
        }
    }
    serial_write("Isolation: GDT/TSS loaded (IST for #DF, NMI, #MC; no I/O bitmap).\r\n");
    serial_write("Isolation: IDT loaded; all gates DPL 0; Ring 0 faults fail closed.\r\n");
    serial_write("Isolation: SYSCALL gate armed (TF/IF/DF/AC/NT/IOPL masked).\r\n");
    serial_write("Isolation: legacy PIC IRQs masked; APIC timer watchdog armed.\r\n");
    true
}

pub(crate) fn fatal_kernel_trap(frame: &TrapFrame) -> ! {
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

pub(crate) fn map_task_image(
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
