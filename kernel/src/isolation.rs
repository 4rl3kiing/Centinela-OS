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

use centinela_hal::apic;
use centinela_hal::cpu::{halt_forever, page_fault_address};
use centinela_hal::gdt::{self, TssStacks};
use centinela_hal::idt::{self, TrapFrame, exception_name};
use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_hal::syscall;
use centinela_kernel::memory::address_space::{create_task_root, destroy_user_address_space};
use centinela_kernel::memory::hhdm_backend::{HhdmFrameMemory, HhdmReader};
use centinela_kernel::memory::vmm::{
    HhdmOffset, MappingTransactionError, PAGE_SIZE, PageMapping, PageTableMapper,
    PageTableMutationMemory, PageTableWalker, PhysAddr, VirtAddr, WalkError,
};
use centinela_security::permissions::PagePermissions;

const KERNEL_STACK_SIZE: usize = 16 * 1024;
pub(crate) const USER_CODE_BASE: u64 = 0x0000_0000_0040_0000;
pub(crate) const USER_STACK_TOP: u64 = 0x0000_7fff_0000_0000;
const USER_STACK_PAGES: u64 = 4;
/// Finds a kernel-half PML4 slot the bootloader left empty. With KASLR the
/// kernel image and the HHDM move on every boot, so no fixed address is safe
/// for device mappings; an empty top-level slot cannot collide with either.
pub(crate) fn free_kernel_slot_address(
    memory: &HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
) -> Option<u64> {
    (256u16..511).rev().find_map(|slot| {
        let entry = memory.read_entry(kernel_root, slot).ok()?;
        (entry & 1 == 0).then_some(0xffff_0000_0000_0000 | (u64::from(slot) << 39))
    })
}
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

// KPTI: the CPU pushes trap frames onto these stacks while the task's page
// tables are still active, so they live in the entry trampoline.
#[unsafe(link_section = ".bss.entry")]
static mut TRAP_STACK: GuardedStack = GuardedStack::new();
#[unsafe(link_section = ".bss.entry")]
static mut DOUBLE_FAULT_STACK: GuardedStack = GuardedStack::new();
#[unsafe(link_section = ".bss.entry")]
static mut NMI_STACK: GuardedStack = GuardedStack::new();
#[unsafe(link_section = ".bss.entry")]
static mut MACHINE_CHECK_STACK: GuardedStack = GuardedStack::new();

unsafe extern "C" {
    static __entry_text_start: u8;
    static __entry_text_end: u8;
    static __entry_data_start: u8;
    static __entry_data_end: u8;
    static __entry_bss_start: u8;
    static __entry_bss_end: u8;
}

/// Kernel-half top-level entries shared by every task root (KPTI trampoline).
static mut TRAMPOLINE: [(u16, u64); 4] = [(0, 0); 4];
static mut TRAMPOLINE_LEN: usize = 0;

/// The KPTI trampoline entries every task root receives.
pub(crate) fn trampoline_entries() -> &'static [(u16, u64)] {
    // SAFETY: Written once by `build_trampoline` during single-CPU boot,
    // read-only afterwards.
    unsafe {
        let len = *addr_of!(TRAMPOLINE_LEN);
        let entries: &'static [(u16, u64); 4] = &*addr_of!(TRAMPOLINE);
        &entries[..len]
    }
}

/// Builds the page tables of the KPTI entry trampoline: a private subtree
/// mapping only the entry code, entry data (GDT/IDT/TSS/switch variables) and
/// entry stacks, supervisor-only, at their kernel addresses. Returns the
/// number of mapped pages.
fn build_trampoline(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
) -> Option<usize> {
    let regions = [
        (
            addr_of!(__entry_text_start) as u64,
            addr_of!(__entry_text_end) as u64,
            true,
        ),
        (
            addr_of!(__entry_data_start) as u64,
            addr_of!(__entry_data_end) as u64,
            false,
        ),
        (
            addr_of!(__entry_bss_start) as u64,
            addr_of!(__entry_bss_end) as u64,
            false,
        ),
    ];
    let shadow = memory.allocate_zeroed_table_frame().ok()?;
    // SAFETY: Kernel page tables are HHDM-mapped (base revision 5).
    let reader = unsafe { HhdmReader::new(hhdm) };
    let walker = PageTableWalker::new(&reader, kernel_root);
    let rx = PagePermissions::new(true, false, true, false).ok()?;
    let rw = PagePermissions::new(true, true, false, false).ok()?;
    let mut pages = 0;
    for (start, end, executable) in regions {
        let mut page = start & !(PAGE_SIZE - 1);
        while page < end {
            match walker.translate(VirtAddr::new(page).ok()?) {
                Ok(translation) => {
                    let frame = translation.physical_address & !(PAGE_SIZE - 1);
                    let permissions = if executable { rx } else { rw };
                    let mapping = PageMapping::new(page, frame, permissions).ok()?;
                    PageTableMapper::new(&mut *memory, shadow)
                        .map_4k(mapping)
                        .ok()?;
                    pages += 1;
                }
                // Guard pages are unmapped in the kernel and stay unmapped here.
                Err(WalkError::NotMapped) => {}
                Err(_) => return None,
            }
            page += PAGE_SIZE;
        }
    }
    let mut count = 0;
    for index in 256u16..512 {
        let entry = memory.read_entry(shadow, index).ok()?;
        if entry & 1 != 0 {
            if count == 4 {
                return None;
            }
            // SAFETY: Single-CPU boot; no reader exists yet.
            unsafe { (*addr_of_mut!(TRAMPOLINE))[count] = (index, entry) };
            count += 1;
        }
    }
    // SAFETY: As above.
    unsafe { *addr_of_mut!(TRAMPOLINE_LEN) = count };
    // The shadow root itself is only a construction aid; its subtrees live on.
    let _ = memory.release_table_frame(shadow);
    Some(pages)
}

/// Verifies on a probe task root that the kernel image and the HHDM are not
/// reachable while the entry trampoline is.
fn verify_kpti(
    memory: &mut HhdmFrameMemory<'_, '_>,
    hhdm: HhdmOffset,
    kernel_root: PhysAddr,
) -> bool {
    let Ok(probe) = create_task_root(memory, trampoline_entries()) else {
        return false;
    };
    // SAFETY: Task and trampoline tables are HHDM-mapped.
    let reader = unsafe { HhdmReader::new(hhdm) };
    let walker = PageTableWalker::new(&reader, probe);
    let mapped = |address: u64| VirtAddr::new(address).is_ok_and(|va| walker.translate(va).is_ok());
    let kernel_text = crate::_start as *const () as usize as u64;
    let hhdm_alias = hhdm
        .physical_to_virtual(kernel_root)
        .map(|va| va.get())
        .unwrap_or(0);
    let ok = mapped(addr_of!(__entry_text_start) as u64)
        && mapped(stack_bounds(addr_of!(TRAP_STACK)).1 - 8)
        && !mapped(kernel_text)
        && !mapped(hhdm_alias);
    let _ = destroy_user_address_space(memory, probe);
    ok
}

/// Top of the kernel stack used for traps and syscalls from Ring 3.
/// The calling CPU's trap stack (TSS.rsp0) top.
pub(crate) fn trap_stack_top() -> u64 {
    match syscall::cpu_index() {
        0 => stack_bounds(addr_of!(TRAP_STACK)).1,
        cpu => crate::smp::trap_stack_top(cpu - 1),
    }
}

/// APIC timer reload calibrated on the BSP, reused by every CPU.
static TIMER_RELOAD: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub(crate) fn timer_reload() -> u32 {
    TIMER_RELOAD.load(core::sync::atomic::Ordering::Relaxed)
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
pub fn init_cpu_layer(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
) -> bool {
    // Every guard page, including the application processors' entry stacks
    // in the trampoline, is removed before the trampoline is built from the
    // kernel tables, so task page tables never map a guard page.
    if !install_guard_pages(memory, kernel_root)
        || !crate::smp::install_ap_guards(memory, kernel_root)
    {
        serial_write("Centinela-OS: failed to install kernel stack guard pages.\r\n");
        return false;
    }
    serial_write("Isolation: kernel stacks protected by unmapped guard pages.\r\n");

    let Some(trampoline_pages) = build_trampoline(memory, kernel_root, hhdm) else {
        serial_write("Centinela-OS: failed to build the KPTI entry trampoline.\r\n");
        return false;
    };
    // SAFETY: The kernel root maps the whole kernel.
    unsafe { syscall::set_kernel_root(kernel_root.get()) };
    if !verify_kpti(memory, hhdm, kernel_root) {
        serial_write("Centinela-OS: KPTI verification failed.\r\n");
        return false;
    }
    let mut writer = SerialWriter;
    let _ = write!(
        writer,
        "KPTI: task page tables map only the {trampoline_pages}-page entry trampoline; kernel image and HHDM are unmapped.\r\n"
    );

    let apic_physical = apic::physical_base();
    let Some(apic_virtual) = free_kernel_slot_address(memory, kernel_root) else {
        serial_write("Centinela-OS: no free kernel slot for device mappings.\r\n");
        return false;
    };
    let Ok(apic_mapping) = PageMapping::kernel_device(apic_virtual, apic_physical) else {
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
        // Per-CPU entry block 0 for the BSP (after the GDT: segment reloads
        // clear the GS base).
        if !syscall::init_cpu(0) {
            return false;
        }
        centinela_hal::serial::enable_locking();
        idt::init(crate::system::trap_handler);
        syscall::init(crate::system::syscall_handler);
        let per_ms = apic::calibrate(apic_virtual);
        let reload = per_ms
            .map(|counts| (counts * u64::from(TICK_MS)).min(u64::from(u32::MAX)) as u32)
            .unwrap_or(FALLBACK_INITIAL_COUNT);
        apic::init(apic_virtual, reload);
        TIMER_RELOAD.store(reload, core::sync::atomic::Ordering::Relaxed);
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

/// Maps the user stack below `USER_STACK_TOP` (the page under it stays
/// unmapped, so overflow faults the task).
pub(crate) fn map_user_stack(
    memory: &mut HhdmFrameMemory<'_, '_>,
    root: PhysAddr,
) -> Result<(), &'static str> {
    let rw = PagePermissions::new(true, true, false, true).map_err(|_| "W^X")?;
    for index in 0..USER_STACK_PAGES {
        map_user_page(
            memory,
            root,
            USER_STACK_TOP - (index + 1) * PAGE_SIZE,
            rw,
            None,
        )?;
    }
    Ok(())
}

pub(crate) fn map_task_image(
    memory: &mut HhdmFrameMemory<'_, '_>,
    root: PhysAddr,
    program: &[u8],
) -> Result<(), &'static str> {
    let rx = PagePermissions::new(true, false, true, true).map_err(|_| "W^X")?;
    let rw = PagePermissions::new(true, true, false, true).map_err(|_| "W^X")?;
    map_user_page(memory, root, USER_CODE_BASE, rx, Some((0, program)))?;
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
/// Maps one zeroed user page and returns its frame (for DMA domains).
pub(crate) fn map_user_page_frame(
    memory: &mut HhdmFrameMemory<'_, '_>,
    root: PhysAddr,
    address: u64,
    permissions: PagePermissions,
) -> Result<PhysAddr, &'static str> {
    let frame = memory
        .allocate_zeroed_table_frame()
        .map_err(|_| "out of memory for DMA page")?;
    let mapping =
        PageMapping::new(address, frame.get(), permissions).map_err(|_| "invalid mapping");
    let mapped = mapping.and_then(|mapping| {
        PageTableMapper::new(&mut *memory, root)
            .map_4k(mapping)
            .map_err(|_| "page mapping failed")
    });
    match mapped {
        Ok(_) => Ok(frame),
        Err(reason) => {
            let _ = memory.release_table_frame(frame);
            Err(reason)
        }
    }
}

pub(crate) fn map_user_page(
    memory: &mut HhdmFrameMemory<'_, '_>,
    root: PhysAddr,
    address: u64,
    permissions: PagePermissions,
    contents: Option<(usize, &[u8])>,
) -> Result<(), &'static str> {
    // Frames are zeroed on allocation, so no stale data reaches the task.
    let frame = memory
        .allocate_zeroed_table_frame()
        .map_err(|_| "out of memory for task page")?;
    let mapped = (|| {
        if let Some((offset, bytes)) = contents {
            // SAFETY: Freshly allocated frame, not yet mapped anywhere.
            unsafe { memory.write_frame_at(frame, offset, bytes) }
                .map_err(|_| "page copy failed")?;
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
