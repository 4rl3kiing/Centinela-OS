#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

// The isolation runtime drives real hardware; it only exists for the kernel
// target (host builds of this binary are used solely for linting).
#[cfg(target_os = "none")]
mod ioapic;
#[cfg(target_os = "none")]
mod iommu;
#[cfg(target_os = "none")]
mod isolation;
#[cfg(target_os = "none")]
mod pci;
#[cfg(target_os = "none")]
mod smp;
#[cfg(target_os = "none")]
mod system;
#[cfg(target_os = "none")]
mod user_programs;

use core::mem::MaybeUninit;
use core::panic::PanicInfo;
use core::ptr::{addr_of, addr_of_mut};

use centinela_hal::cpu::{
    CpuHardeningError, current_page_table_root, enable_boot_hardening, halt_forever,
};
use centinela_hal::serial::{SerialWriter, init as serial_init, write as serial_write};
use centinela_kernel::memory::hhdm_backend::HhdmFrameMemory;
use centinela_kernel::memory::pmm::{BITMAP_WORDS, LimineMemoryMapResponse, Pmm};
use centinela_kernel::memory::vmm::{
    BootPagingInfo, HhdmOffset, HhdmPageTableMemory, PageTableMemory, PageTableWalker, PhysAddr,
    VirtAddr,
};

/// Link-time virtual base (linker/x86_64.ld); Limine slides the PIE kernel.
const KERNEL_LINK_BASE: u64 = 0xffff_ffff_8000_0000;

const LIMINE_COMMON_MAGIC: [u64; 2] = [0xc7b1_dd30_df4c_8b88, 0x0a82_e883_a194_f07b];

#[repr(C)]
struct LimineRequest {
    id: [u64; 4],
    revision: u64,
    response: *mut (),
}

#[repr(C)]
struct LimineStackSizeRequest {
    id: [u64; 4],
    revision: u64,
    response: *mut (),
    stack_size: u64,
}

#[repr(C)]
struct LimineHhdmResponse {
    revision: u64,
    offset: u64,
}

#[repr(C)]
struct LimineExecutableAddressResponse {
    revision: u64,
    physical_base: u64,
    virtual_base: u64,
}

#[repr(C)]
struct LimineRequests {
    start_marker: [u64; 4],
    base_revision: [u64; 3],
    stack_size: LimineStackSizeRequest,
    hhdm: LimineRequest,
    memory_map: LimineRequest,
    executable_address: LimineRequest,
    modules: LimineRequest,
    rsdp: LimineRequest,
    #[cfg(target_os = "none")]
    mp: smp::LimineMpRequest,
    end_marker: [u64; 2],
}

#[repr(C)]
struct LimineModuleResponse {
    revision: u64,
    module_count: u64,
    modules: *const *const LimineFile,
}

#[repr(C)]
struct LimineFile {
    revision: u64,
    address: *const u8,
    size: u64,
    path: *const u8,
    string: *const u8,
}

unsafe extern "C" {
    static __kernel_virt_start: u8;
    static __kernel_virt_end: u8;
}

#[used]
#[unsafe(link_section = ".limine_requests")]
static mut LIMINE_REQUESTS: LimineRequests = LimineRequests {
    start_marker: [
        0xf6b8_f4b3_9de7_d1ae,
        0xfab9_1a69_40fc_b9cf,
        0x785c_6ed0_15d3_e316,
        0x181e_920a_7852_b9d9,
    ],
    base_revision: [0xf956_2b2d_5c95_a6c8, 0x6a7b_3849_4453_6bdc, 5],
    stack_size: LimineStackSizeRequest {
        id: [
            LIMINE_COMMON_MAGIC[0],
            LIMINE_COMMON_MAGIC[1],
            0x224e_f046_0a8e_8926,
            0xe1cb_0fc2_5f46_ea3d,
        ],
        revision: 0,
        response: core::ptr::null_mut(),
        stack_size: 256 * 1024,
    },
    hhdm: LimineRequest {
        id: [
            LIMINE_COMMON_MAGIC[0],
            LIMINE_COMMON_MAGIC[1],
            0x48dc_f1cb_8ad2_b852,
            0x6398_4e95_9a98_244b,
        ],
        revision: 0,
        response: core::ptr::null_mut(),
    },
    memory_map: LimineRequest {
        id: [
            LIMINE_COMMON_MAGIC[0],
            LIMINE_COMMON_MAGIC[1],
            0x67cf_3d9d_378a_806f,
            0xe304_acdf_c50c_3c62,
        ],
        revision: 0,
        response: core::ptr::null_mut(),
    },
    // Limine picks the kernel's physical load address; this response is the
    // authoritative source for the physical range the PMM must reserve.
    executable_address: LimineRequest {
        id: [
            LIMINE_COMMON_MAGIC[0],
            LIMINE_COMMON_MAGIC[1],
            0x71ba_7686_3cc5_5f63,
            0xb264_4a48_c516_a487,
        ],
        revision: 0,
        response: core::ptr::null_mut(),
    },
    // User programs (ELF) arrive as boot modules whose BLAKE2b hashes are
    // pinned in limine.conf, so Limine refuses tampered images.
    modules: LimineRequest {
        id: [
            LIMINE_COMMON_MAGIC[0],
            LIMINE_COMMON_MAGIC[1],
            0x3e7e_2797_02be_32af,
            0xca1c_4f3b_d128_0cee,
        ],
        revision: 0,
        response: core::ptr::null_mut(),
    },
    // ACPI root pointer (HHDM virtual address in base revision 5): DMAR.
    rsdp: LimineRequest {
        id: [
            LIMINE_COMMON_MAGIC[0],
            LIMINE_COMMON_MAGIC[1],
            0xc5e7_7b6b_397e_7b43,
            0x2763_7845_accd_cf3c,
        ],
        revision: 0,
        response: core::ptr::null_mut(),
    },
    // Application processors stay in Limine's parking loop until released.
    #[cfg(target_os = "none")]
    mp: smp::LimineMpRequest {
        id: [
            LIMINE_COMMON_MAGIC[0],
            LIMINE_COMMON_MAGIC[1],
            0x95a6_7b81_9a1b_857e,
            0xa0b6_1b72_3b6a_73e0,
        ],
        revision: 0,
        response: core::ptr::null_mut(),
        flags: 0,
    },
    end_marker: [0xadc0_e053_1bb1_0d03, 0x9572_709f_3176_4c62],
};

const MAX_MODULES: usize = 12;
const MAX_MODULE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_MODULE_NAME: usize = 32;

/// Boot modules, validated as untrusted input: count, address range, size
/// and name length are all bounded before any slice is created.
fn boot_modules(hhdm: HhdmOffset) -> ([(&'static str, &'static [u8]); MAX_MODULES], usize) {
    let mut modules: [(&'static str, &'static [u8]); MAX_MODULES] = [("", &[]); MAX_MODULES];
    // SAFETY: Reads a bootloader-populated pointer without creating a
    // reference to the mutable request structure.
    let response = unsafe {
        addr_of!(LIMINE_REQUESTS.modules.response)
            .read_volatile()
            .cast::<LimineModuleResponse>()
    };
    if response.is_null() {
        return (modules, 0);
    }
    // SAFETY: Limine keeps the response valid during boot.
    let (count, list) = unsafe { ((*response).module_count, (*response).modules) };
    if list.is_null() {
        return (modules, 0);
    }
    let hhdm_base = hhdm.physical_to_virtual(PhysAddr::new(0).unwrap_or_else(|_| halt_forever()));
    let Ok(hhdm_base) = hhdm_base else {
        return (modules, 0);
    };
    let mut found = 0;
    for index in 0..(count as usize).min(MAX_MODULES) {
        // SAFETY: `index` < module_count; Limine provides that many pointers.
        let file = unsafe { list.add(index).read() };
        if file.is_null() {
            continue;
        }
        // SAFETY: Limine file structures stay valid during boot.
        let (address, size, string) = unsafe { ((*file).address, (*file).size, (*file).string) };
        let start = address as u64;
        let in_hhdm = start >= hhdm_base.get() && start.checked_add(size).is_some();
        if address.is_null() || !in_hhdm || size == 0 || size > MAX_MODULE_SIZE || string.is_null()
        {
            continue;
        }
        let mut length = 0;
        // SAFETY: Bounded scan of a NUL-terminated string Limine provided.
        while length < MAX_MODULE_NAME && unsafe { string.add(length).read() } != 0 {
            length += 1;
        }
        // SAFETY: `length` bytes were just read; module memory is
        // EXECUTABLE_AND_MODULES (never handed out by the PMM) and HHDM-mapped.
        let (name, bytes) = unsafe {
            (
                core::slice::from_raw_parts(string, length),
                core::slice::from_raw_parts(address, size as usize),
            )
        };
        let Ok(name) = core::str::from_utf8(name) else {
            continue;
        };
        modules[found] = (name, bytes);
        found += 1;
    }
    (modules, found)
}

// A 64 GiB physical-address ceiling uses two 2 MiB bitmaps at 4 KiB granularity.
// The bitmap itself is reserved automatically as part of the kernel BSS.
static mut FRAME_BITMAP: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];
static mut ALLOCATED_BITMAP: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];
static mut PMM_STATE: MaybeUninit<Pmm<'static>> = MaybeUninit::uninit();
static mut BOOT_PAGING_INFO: MaybeUninit<BootPagingInfo> = MaybeUninit::uninit();

/// Validated boot memory state handed to the isolation layer.
struct BootMemory {
    pmm: &'static mut Pmm<'static>,
    hhdm: HhdmOffset,
    kernel_root: PhysAddr,
}

fn initialize_memory() -> Option<BootMemory> {
    // Limine sets the third base-revision field to zero when the requested
    // protocol revision is supported.
    let revision_supported =
        unsafe { addr_of!(LIMINE_REQUESTS.base_revision[2]).read_volatile() == 0 };
    if !revision_supported {
        serial_write("Centinela-OS: unsupported Limine base revision.\r\n");
        return None;
    }
    serial_write("Limine base revision 5 accepted.\r\n");

    // Read bootloader-populated response pointers without creating references
    // to the mutable request structure.
    let memory_map = unsafe {
        addr_of!(LIMINE_REQUESTS.memory_map.response)
            .read_volatile()
            .cast::<LimineMemoryMapResponse>()
    };
    let hhdm = unsafe {
        addr_of!(LIMINE_REQUESTS.hhdm.response)
            .read_volatile()
            .cast::<LimineHhdmResponse>()
    };

    if memory_map.is_null() || hhdm.is_null() {
        serial_write("Centinela-OS: required Limine memory response missing.\r\n");
        return None;
    }

    // SAFETY: Limine supplies a valid HHDM response for the lifetime of boot.
    let hhdm_revision = unsafe { addr_of!((*hhdm).revision).read() };
    let hhdm_offset = unsafe { addr_of!((*hhdm).offset).read() };
    if hhdm_revision != 0 || hhdm_offset & 0xfff != 0 {
        serial_write("Centinela-OS: unsupported or invalid HHDM response.\r\n");
        return None;
    }

    let hhdm_offset = match HhdmOffset::new(hhdm_offset) {
        Ok(offset) => offset,
        Err(_) => {
            serial_write("Centinela-OS: HHDM offset is not canonical.\r\n");
            return None;
        }
    };
    let paging_info = match BootPagingInfo::new(current_page_table_root(), hhdm_offset) {
        Ok(info) => info,
        Err(_) => {
            serial_write("Centinela-OS: active CR3 root is invalid or not HHDM-addressable.\r\n");
            return None;
        }
    };
    // The Limine protocol guarantees that its page-table pages are in
    // bootloader-reclaimable memory, which is mapped by the revision-5 HHDM.
    // The reader checks each complete table frame against that map before use.
    // SAFETY: Limine's response and entry pointers remain valid throughout boot;
    // the requested and accepted base revision is 5 and the HHDM stays active.
    let table_memory = match unsafe { HhdmPageTableMemory::new(hhdm_offset, memory_map) } {
        Ok(memory) => memory,
        Err(_) => {
            serial_write("Centinela-OS: invalid HHDM page-table memory map.\r\n");
            return None;
        }
    };
    let walker = PageTableWalker::new(&table_memory, paging_info.root_physical());
    let root_alias = match walker.translate(paging_info.root_virtual()) {
        Ok(translation) => translation,
        Err(_) => {
            serial_write("Centinela-OS: active page-table root is not readable through HHDM.\r\n");
            return None;
        }
    };
    if root_alias.physical_address != paging_info.root_physical().get() {
        serial_write("Centinela-OS: HHDM root translation mismatch.\r\n");
        return None;
    }

    let kernel_entry = match VirtAddr::new(_start as *const () as usize as u64) {
        Ok(address) => address,
        Err(_) => {
            serial_write("Centinela-OS: kernel entry virtual address is invalid.\r\n");
            return None;
        }
    };
    let entry_mapping = match walker.translate(kernel_entry) {
        Ok(translation) => translation,
        Err(_) => {
            serial_write("Centinela-OS: kernel entry mapping could not be verified.\r\n");
            return None;
        }
    };
    if !entry_mapping.executable || entry_mapping.writable {
        serial_write("Centinela-OS: kernel entry mapping violates RX permissions.\r\n");
        return None;
    }
    serial_write("VMM bootstrap: Limine page-table frames validated through HHDM.\r\n");
    serial_write("VMM bootstrap: HHDM root alias and kernel RX mapping verified.\r\n");

    // Record the bootloader-owned paging root without switching CR3.
    // The active page tables remain unchanged.
    // SAFETY: BOOT_PAGING_INFO is written exactly once during single-core
    // bootstrap, before any reader exists.
    unsafe {
        addr_of_mut!(BOOT_PAGING_INFO).write(MaybeUninit::new(paging_info));
    }

    // Limine chooses the physical load address, so the reserved range comes
    // from the executable-address response (not a link-time constant) and is
    // cross-checked against the live page tables. The image size, including
    // the PMM bitmaps in BSS, comes from linker-exported virtual bounds.
    let (kernel_start, kernel_end) = kernel_physical_range(&walker)?;

    // SAFETY: The bitmap is a unique static buffer. The kernel is single-core
    // and interrupts are not enabled at this bootstrap stage.
    let bitmap: &'static mut [u64] = unsafe {
        core::slice::from_raw_parts_mut(addr_of_mut!(FRAME_BITMAP).cast::<u64>(), BITMAP_WORDS)
    };
    // SAFETY: This is a separate, unique static bitmap with the same length.
    let allocated_bitmap: &'static mut [u64] = unsafe {
        core::slice::from_raw_parts_mut(addr_of_mut!(ALLOCATED_BITMAP).cast::<u64>(), BITMAP_WORDS)
    };
    let mut pmm = match Pmm::new(bitmap, allocated_bitmap) {
        Ok(pmm) => pmm,
        Err(_) => {
            serial_write("Centinela-OS: PMM bitmap initialization failed.\r\n");
            return None;
        }
    };

    // SAFETY: Limine's memory-map response and its entry array are valid boot
    // information, and all PMM access is serialized on this single CPU.
    if unsafe { pmm.initialize_from_limine(memory_map, kernel_start, kernel_end) }.is_err() {
        serial_write("Centinela-OS: invalid physical memory map.\r\n");
        return None;
    }

    let Some(test_frame) = pmm.allocate_frame() else {
        serial_write("Centinela-OS: no usable physical frames detected.\r\n");
        return None;
    };
    if pmm.free_frame(test_frame).is_err() {
        serial_write("Centinela-OS: PMM allocation self-test failed.\r\n");
        return None;
    }

    // Keep the initialized manager alive for subsequent kernel subsystems.
    // SAFETY: PMM_STATE is written exactly once during single-core bootstrap.
    unsafe {
        addr_of_mut!(PMM_STATE).write(MaybeUninit::new(pmm));
    }

    serial_write("PMM initialized: 4 KiB frames, 64 GiB address ceiling.\r\n");
    serial_write("PMM allocation/free self-test passed.\r\n");
    // SAFETY: PMM_STATE was initialized just above and is never moved; this
    // is the only reference handed out.
    let pmm = unsafe { (*addr_of_mut!(PMM_STATE)).assume_init_mut() };
    Some(BootMemory {
        pmm,
        hhdm: hhdm_offset,
        kernel_root: paging_info.root_physical(),
    })
}

/// Returns the kernel image's physical `[start, end)` range, or `None` after
/// logging why the executable-address response could not be trusted.
fn kernel_physical_range<M: PageTableMemory>(
    walker: &PageTableWalker<'_, M>,
) -> Option<(u64, u64)> {
    // SAFETY: Reads a bootloader-populated pointer without creating a
    // reference to the mutable request structure.
    let response = unsafe {
        addr_of!(LIMINE_REQUESTS.executable_address.response)
            .read_volatile()
            .cast::<LimineExecutableAddressResponse>()
    };
    if response.is_null() {
        serial_write("Centinela-OS: Limine executable-address response missing.\r\n");
        return None;
    }
    // SAFETY: Limine keeps the response valid and immutable during boot.
    let (revision, physical_base, virtual_base) = unsafe {
        (
            addr_of!((*response).revision).read(),
            addr_of!((*response).physical_base).read(),
            addr_of!((*response).virtual_base).read(),
        )
    };

    // addr_of! obtains linker-symbol addresses without reading their contents.
    let virt_start = addr_of!(__kernel_virt_start) as u64;
    let virt_end = addr_of!(__kernel_virt_end) as u64;
    let image_size = virt_end.checked_sub(virt_start).filter(|size| *size > 0);
    let physical_end = image_size.and_then(|size| physical_base.checked_add(size));
    let (Some(_), Some(physical_end)) = (image_size, physical_end) else {
        serial_write("Centinela-OS: invalid kernel image bounds.\r\n");
        return None;
    };
    if revision != 0
        || physical_base == 0
        || physical_base & 0xfff != 0
        || virtual_base != virt_start
    {
        serial_write("Centinela-OS: unexpected executable-address response.\r\n");
        return None;
    }

    // The response must agree with what the CPU actually translates, at both
    // ends of the image (this also proves the physical placement is linear).
    let translate = |virtual_address: u64| {
        VirtAddr::new(virtual_address)
            .ok()
            .and_then(|address| walker.translate(address).ok())
            .map(|translation| translation.physical_address)
    };
    if translate(virt_start) != Some(physical_base)
        || translate(virt_end - 1) != Some(physical_end - 1)
    {
        serial_write("Centinela-OS: kernel physical base does not match page tables.\r\n");
        return None;
    }
    serial_write("Kernel image: physical range verified against page tables.\r\n");
    let mut writer = SerialWriter;
    let _ = core::fmt::Write::write_fmt(
        &mut writer,
        format_args!(
            "Kernel image: KASLR virtual base {virtual_base:#x} (link base {KERNEL_LINK_BASE:#x}).\r\n"
        ),
    );
    Some((physical_base, physical_end))
}

/// Size of the kernel's own execution stack.
const KERNEL_STACK_SIZE: usize = 64 * 1024;

/// Kernel execution stack, preceded by a guard page that the isolation layer
/// unmaps, so a kernel stack overflow faults (double fault on an IST stack)
/// instead of silently corrupting memory. The bootloader's stack is abandoned
/// at the first instruction because it has no guard page.
#[repr(C, align(4096))]
pub(crate) struct KernelStack {
    guard: [u8; 4096],
    stack: [u8; KERNEL_STACK_SIZE],
}

pub(crate) static mut KERNEL_STACK: KernelStack = KernelStack {
    guard: [0; 4096],
    stack: [0; KERNEL_STACK_SIZE],
};

/// Entry point: switch to the guarded kernel stack, then run `kernel_main`.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "lea rsp, [rip + {stack} + {top}]",
        "xor ebp, ebp",
        "call {main}",
        "ud2",
        stack = sym KERNEL_STACK,
        top = const core::mem::size_of::<KernelStack>(),
        main = sym kernel_main,
    )
}

extern "C" fn kernel_main() -> ! {
    // Best effort: without a UART the boot continues silently instead of hanging.
    let _ = serial_init();
    serial_write("\r\nCentinela-OS: Rust kernel entry reached.\r\n");

    // SAFETY: Ring 0, bootstrap CPU, interrupts disabled (Limine hands off with
    // IF clear) and only supervisor mappings exist at this point.
    match unsafe { enable_boot_hardening() } {
        Ok(features) => {
            #[cfg(target_os = "none")]
            smp::record_bsp_hardening(features);
            serial_write("CPU hardening: NXE enabled.\r\n");
            if features.write_protect {
                serial_write("CPU hardening: CR0.WP enabled.\r\n");
            }
            if features.umip {
                serial_write("CPU hardening: UMIP enabled.\r\n");
            }
            if features.smep {
                serial_write("CPU hardening: SMEP enabled.\r\n");
            }
            if features.smap {
                serial_write("CPU hardening: SMAP enabled.\r\n");
            }
        }
        Err(CpuHardeningError::NxUnsupported) => {
            serial_write("Centinela-OS: mandatory NX support unavailable.\r\n");
            halt_forever();
        }
        Err(CpuHardeningError::FeatureEnableFailed) => {
            serial_write("Centinela-OS: CPU hardening register verification failed.\r\n");
            halt_forever();
        }
        Err(CpuHardeningError::UnsupportedPagingMode) => {
            serial_write("Centinela-OS: 5-level paging is active but unsupported.\r\n");
            halt_forever();
        }
    }

    let Some(boot) = initialize_memory() else {
        halt_forever();
    };
    serial_write("Bootstrap milestone: memory map validated and PMM online.\r\n");

    // SAFETY: The HHDM (base revision 5) maps every usable and bootloader-
    // reclaimable frame, including Limine's page tables; single CPU, IF=0.
    let mut memory = unsafe { HhdmFrameMemory::new(boot.hhdm, boot.pmm) };
    let (modules, module_count) = boot_modules(boot.hhdm);
    let mut writer = SerialWriter;
    let _ = core::fmt::Write::write_fmt(
        &mut writer,
        format_args!("Boot modules: {module_count} verified by the boot chain.\r\n"),
    );
    run_isolation(
        &mut memory,
        boot.kernel_root,
        boot.hhdm,
        &modules[..module_count],
    );
    halt_forever()
}

#[cfg(target_os = "none")]
fn run_isolation(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
    modules: &[(&'static str, &'static [u8])],
) {
    if !isolation::init_cpu_layer(memory, kernel_root, hhdm) {
        halt_forever();
    }
    if !init_platform(memory, kernel_root, hhdm) {
        halt_forever();
    }
    // SAFETY: BSP, IF=0, GDT/IDT loaded; the request lives in the Limine
    // request section and was answered before the kernel was entered.
    if !unsafe { smp::start(memory, kernel_root, &raw const LIMINE_REQUESTS.mp) } {
        halt_forever();
    }
    if system::run_self_test(memory, kernel_root, hhdm, modules) {
        serial_write(
            "Microkernel milestone: Ring 3 init manages services through capability IPC \
             and attenuated grants; every hostile task contained.\r\n",
        );
    } else {
        serial_write("Centinela-OS: microkernel self-test failed.\r\n");
    }
}

/// True if `[start, end)` lies inside one ACPI memory-map region.
#[cfg(target_os = "none")]
fn in_acpi_memory(start: u64, end: u64) -> bool {
    use centinela_kernel::memory::pmm::{LimineMemoryMapEntry, LimineMemoryMapResponse};
    // SAFETY: Response written by Limine before entry; never reclaimed (the
    // PMM only allocates USABLE frames).
    let response = unsafe {
        addr_of!(LIMINE_REQUESTS.memory_map.response)
            .read_volatile()
            .cast::<LimineMemoryMapResponse>()
    };
    if response.is_null() {
        return false;
    }
    // SAFETY: Validated by the PMM during boot (count bounded, entries non-null).
    let (count, entries) = unsafe { ((*response).entry_count, (*response).entries) };
    (0..count.min(4096) as usize).any(|index| {
        // SAFETY: `index < entry_count`.
        let entry: *const LimineMemoryMapEntry = unsafe { entries.add(index).read() };
        if entry.is_null() {
            return false;
        }
        // SAFETY: Non-null Limine entry.
        let entry = unsafe { entry.read() };
        matches!(entry.entry_type, 2 | 3 | 8)
            && entry.base <= start
            && entry
                .base
                .checked_add(entry.length)
                .is_some_and(|limit| end <= limit)
    })
}

#[cfg(target_os = "none")]
fn init_platform(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
    hhdm: HhdmOffset,
) -> bool {
    let base = hhdm.get();
    // SAFETY: Response pointer written by Limine before entry.
    let response =
        unsafe { addr_of!(LIMINE_REQUESTS.rsdp.response).read_volatile() }.cast::<[u64; 2]>();
    let reader = iommu::AcpiReader {
        hhdm: base,
        in_acpi_memory,
    };
    let rsdp = if response.is_null() {
        None
    } else {
        // SAFETY: Limine RSDP response {revision, address}; the address is an
        // HHDM virtual address in base revision 5.
        let address = unsafe { (*response)[1] };
        address
            .checked_sub(base)
            .map(|physical| (&reader, physical))
    };
    iommu::init(memory, kernel_root, rsdp) && ioapic::init(memory, kernel_root, rsdp)
}

#[cfg(not(target_os = "none"))]
fn run_isolation(
    _: &mut HhdmFrameMemory<'_, '_>,
    _: PhysAddr,
    _: HhdmOffset,
    _: &[(&'static str, &'static [u8])],
) {
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    use core::fmt::Write;

    serial_write("\r\nCentinela-OS: PANIC. System halted.\r\n");
    // Location and message make field failures diagnosable. Formatting errors
    // are ignored: the halt below must happen regardless.
    let mut writer = SerialWriter;
    if let Some(location) = info.location() {
        let _ = write!(writer, "  at {}:{}\r\n", location.file(), location.line());
    }
    let _ = write!(writer, "  {}\r\n", info.message());
    halt_forever()
}
