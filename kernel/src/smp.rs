//! Symmetric multiprocessing bring-up (phase 4, step 1).
//!
//! Application processors (APs) are released from the bootloader's parking
//! loop through the Limine MP protocol and immediately confined:
//! - each AP abandons the bootloader stack at its first instruction and runs on
//!   private stacks behind unmapped guard pages (one kernel stack plus IST
//!   stacks for #DF, NMI and #MC);
//! - each AP loads its own GDT/TSS (no I/O bitmap) and the shared, read-only
//!   IDT whose gates are all DPL 0;
//! - each AP enables the same CPU hardening as the BSP (NX, WP, SMEP, SMAP,
//!   UMIP) and the BSP verifies it matches — a weaker AP fails the boot;
//! - APs then park with interrupts disabled. They never run Ring 3 code and
//!   never touch shared kernel state, so the single-CPU invariants of the
//!   scheduler and IPC layer still hold. Any NMI/#MC on an AP ends in the
//!   fail-closed fatal trap path.
//!
//! The APs share the BSP's kernel page tables. Because they only execute this
//! module's code and their own stacks, stale TLB entries on parked APs are
//! harmless; TLB shootdown becomes mandatory before APs run tasks.

use core::fmt::Write;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use centinela_hal::cpu::enable_boot_hardening;
use centinela_hal::gdt::{self, MAX_APS, TssStacks};
use centinela_hal::idt;
use centinela_hal::serial::{SerialWriter, write as serial_write};
use centinela_kernel::memory::hhdm_backend::HhdmFrameMemory;
use centinela_kernel::memory::vmm::{PAGE_SIZE, PageTableMapper, PhysAddr, VirtAddr};

const AP_STACK_SIZE: usize = 8 * 1024;
/// Spin iterations the BSP waits for APs before declaring bring-up failed.
const BRING_UP_SPINS: u64 = 200_000_000;

#[repr(C, align(4096))]
struct ApStack {
    guard: [u8; PAGE_SIZE as usize],
    stack: [u8; AP_STACK_SIZE],
}

#[repr(C)]
struct ApStacks {
    kernel: ApStack,
    double_fault: ApStack,
    nmi: ApStack,
    machine_check: ApStack,
}

const fn ap_stacks() -> ApStacks {
    const fn one() -> ApStack {
        ApStack {
            guard: [0; PAGE_SIZE as usize],
            stack: [0; AP_STACK_SIZE],
        }
    }
    ApStacks {
        kernel: one(),
        double_fault: one(),
        nmi: one(),
        machine_check: one(),
    }
}

static mut AP_STACKS: [ApStacks; MAX_APS] = [const { ap_stacks() }; MAX_APS];
/// Kernel stack top per AP index, read by the naked entry before any call.
static mut AP_STACK_TOPS: [u64; MAX_APS] = [0; MAX_APS];

/// APs that finished confinement and parked.
static AP_ONLINE: AtomicU32 = AtomicU32::new(0);
/// APs whose hardening differs from the BSP or that failed to confine.
static AP_REJECTED: AtomicU32 = AtomicU32::new(0);
/// BSP hardening bitmap every AP must reproduce exactly.
static BSP_HARDENING: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
pub(crate) struct LimineMpRequest {
    pub(crate) id: [u64; 4],
    pub(crate) revision: u64,
    pub(crate) response: *mut (),
    /// Bit 0 would enable x2APIC; the HAL drives the xAPIC through MMIO.
    pub(crate) flags: u64,
}

#[repr(C)]
struct LimineMpResponse {
    revision: u64,
    flags: u32,
    bsp_lapic_id: u32,
    cpu_count: u64,
    cpus: *const *mut LimineMpInfo,
}

#[repr(C)]
struct LimineMpInfo {
    processor_id: u32,
    lapic_id: u32,
    reserved: u64,
    goto_address: u64,
    extra_argument: u64,
}

const _: () = assert!(core::mem::offset_of!(LimineMpInfo, extra_argument) == 24);

fn hardening_bits(features: centinela_hal::cpu::CpuHardening) -> u32 {
    u32::from(features.write_protect)
        | u32::from(features.umip) << 1
        | u32::from(features.smep) << 2
        | u32::from(features.smap) << 3
}

/// Records the BSP's hardening so APs can be held to the same standard.
pub(crate) fn record_bsp_hardening(features: centinela_hal::cpu::CpuHardening) {
    // Bit 31 marks "recorded" so an all-zero bitmap is still distinguishable.
    BSP_HARDENING.store(hardening_bits(features) | 1 << 31, Ordering::Release);
}

fn stack_top(stack: *const ApStack) -> u64 {
    stack as u64 + core::mem::size_of::<ApStack>() as u64
}

/// AP entry: Limine jumps here with RDI = this CPU's `LimineMpInfo`, on a
/// bootloader stack without a guard page, which is abandoned immediately.
#[unsafe(naked)]
extern "C" fn ap_entry() -> ! {
    core::arch::naked_asm!(
        "mov rax, [rdi + 24]",
        "cmp rax, {max}",
        "jae 3f",
        "lea rcx, [rip + {tops}]",
        "mov rsp, [rcx + rax * 8]",
        "test rsp, rsp",
        "jz 3f",
        "xor ebp, ebp",
        "call {main}",
        "3:",
        "cli",
        "hlt",
        "jmp 3b",
        max = const MAX_APS,
        tops = sym AP_STACK_TOPS,
        main = sym ap_main,
    )
}

extern "C" fn ap_main(info: *const LimineMpInfo) -> ! {
    // SAFETY: Limine passes a valid info pointer; the entry stub already
    // bounds-checked the index it carries.
    let index = unsafe { core::ptr::read_volatile(addr_of!((*info).extra_argument)) } as usize;
    // SAFETY: CPL 0, IF=0 (Limine releases APs with interrupts disabled).
    let confined = match unsafe { enable_boot_hardening() } {
        Ok(features) => {
            let expected = BSP_HARDENING.load(Ordering::Acquire);
            expected == hardening_bits(features) | 1 << 31
        }
        Err(_) => false,
    };
    if confined {
        // SAFETY: AP_STACKS[index] belongs to this AP alone; raw pointers avoid
        // references to the shared array.
        let stacks = unsafe { (addr_of!(AP_STACKS) as *const ApStacks).add(index) };
        // SAFETY: Field projections of a valid 'static element.
        let tss = unsafe {
            TssStacks {
                privilege0: stack_top(addr_of!((*stacks).kernel)),
                double_fault: stack_top(addr_of!((*stacks).double_fault)),
                nmi: stack_top(addr_of!((*stacks).nmi)),
                machine_check: stack_top(addr_of!((*stacks).machine_check)),
            }
        };
        // SAFETY: CPL 0, IF=0, this AP owns `index`; IDT was built by the BSP.
        let loaded = unsafe { gdt::init_ap(index, tss) };
        if loaded {
            // SAFETY: GDT/TSS of this CPU are loaded.
            unsafe { idt::load() };
            AP_ONLINE.fetch_add(1, Ordering::Release);
        } else {
            AP_REJECTED.fetch_add(1, Ordering::Release);
        }
    } else {
        AP_REJECTED.fetch_add(1, Ordering::Release);
    }
    loop {
        // SAFETY: Parking: no interrupts are accepted (IF stays 0).
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Unmaps the guard page below every AP stack in the shared kernel tables.
fn install_ap_guards(memory: &mut HhdmFrameMemory<'_, '_>, kernel_root: PhysAddr) -> bool {
    let mut mapper = PageTableMapper::new(memory, kernel_root);
    for index in 0..MAX_APS {
        // SAFETY: Address computation only.
        let stacks = unsafe { (addr_of_mut!(AP_STACKS) as *mut ApStacks).add(index) };
        // `guard` is the first field (repr(C)), so each stack's base is its guard.
        // SAFETY: Field projections of a valid 'static element.
        let guards = unsafe {
            [
                addr_of!((*stacks).kernel) as u64,
                addr_of!((*stacks).double_fault) as u64,
                addr_of!((*stacks).nmi) as u64,
                addr_of!((*stacks).machine_check) as u64,
            ]
        };
        for guard in guards {
            let Ok(address) = VirtAddr::new(guard) else {
                return false;
            };
            if mapper.unmap_4k(address).is_err() {
                return false;
            }
        }
    }
    true
}

/// Releases and confines every AP. Returns `false` (fail closed) if an AP
/// is weaker than the BSP or does not report in time.
///
/// # Safety
/// BSP only, IF=0, after the BSP's GDT/IDT are loaded; `request` must be the
/// Limine MP request with its response filled in by the bootloader.
pub(crate) unsafe fn start(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    request: *const LimineMpRequest,
) -> bool {
    // SAFETY: Caller guarantees the request is valid.
    let response = unsafe { core::ptr::read_volatile(addr_of!((*request).response)) }
        as *const LimineMpResponse;
    let mut writer = SerialWriter;
    if response.is_null() {
        serial_write("SMP: bootloader provided no MP response; BSP only.\r\n");
        return true;
    }
    if !install_ap_guards(memory, kernel_root) {
        serial_write("Centinela-OS: failed to install AP stack guard pages.\r\n");
        return false;
    }
    // SAFETY: Non-null Limine response (HHDM-mapped bootloader data).
    let (bsp_lapic, count, cpus) = unsafe {
        (
            (*response).bsp_lapic_id,
            (*response).cpu_count,
            (*response).cpus,
        )
    };
    // Untrusted count: bounded before the array is touched.
    if count > 256 || (count > 0 && cpus.is_null()) {
        serial_write("Centinela-OS: implausible MP response rejected.\r\n");
        return false;
    }
    let mut started = 0u32;
    let mut skipped = 0u64;
    for slot in 0..count as usize {
        // SAFETY: `slot < count`, array provided by Limine.
        let info = unsafe { *cpus.add(slot) };
        if info.is_null() {
            continue;
        }
        // SAFETY: Valid per-CPU info structure.
        if unsafe { (*info).lapic_id } == bsp_lapic {
            continue;
        }
        let index = started as usize;
        if index >= MAX_APS {
            skipped += 1;
            continue;
        }
        // SAFETY: Index owned by the BSP until the AP is released below.
        unsafe {
            let stacks = addr_of!(AP_STACKS) as *const ApStacks;
            (*addr_of_mut!(AP_STACK_TOPS))[index] =
                stack_top(addr_of!((*stacks.add(index)).kernel));
            core::ptr::write_volatile(addr_of_mut!((*info).extra_argument), index as u64);
            // The release store publishes the stack table and argument before
            // the AP can observe its goto address.
            let goto = &*(addr_of_mut!((*info).goto_address) as *const AtomicU64);
            goto.store(ap_entry as *const () as u64, Ordering::Release);
        }
        started += 1;
    }
    let mut spins = 0u64;
    while AP_ONLINE.load(Ordering::Acquire) + AP_REJECTED.load(Ordering::Acquire) < started {
        if spins >= BRING_UP_SPINS {
            serial_write("Centinela-OS: application processors did not report in.\r\n");
            return false;
        }
        core::hint::spin_loop();
        spins += 1;
    }
    let rejected = AP_REJECTED.load(Ordering::Acquire);
    if rejected != 0 {
        let _ = write!(
            writer,
            "Centinela-OS: {rejected} application processors failed confinement.\r\n"
        );
        return false;
    }
    let online = AP_ONLINE.load(Ordering::Acquire);
    let _ = write!(
        writer,
        "SMP: {online} application processors online (isolated, parked; private GDT/TSS/IST, hardening verified).\r\n"
    );
    if skipped != 0 {
        let _ = write!(
            writer,
            "SMP: {skipped} processors left in the bootloader parking loop (limit {MAX_APS}).\r\n"
        );
    }
    true
}
