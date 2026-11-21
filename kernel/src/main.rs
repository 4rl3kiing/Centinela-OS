#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::mem::MaybeUninit;
use core::panic::PanicInfo;
use core::ptr::{addr_of, addr_of_mut};

use centinela_hal::cpu::{
    CpuHardeningError, current_page_table_root, enable_boot_hardening, halt_forever,
};
use centinela_hal::serial::{SerialWriter, init as serial_init, write as serial_write};
use centinela_kernel::memory::pmm::{BITMAP_WORDS, LimineMemoryMapResponse, Pmm};
use centinela_kernel::memory::vmm::{
    BootPagingInfo, HhdmOffset, HhdmPageTableMemory, PageTableMemory, PageTableWalker, VirtAddr,
};

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
    end_marker: [u64; 2],
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
    end_marker: [0xadc0_e053_1bb1_0d03, 0x9572_709f_3176_4c62],
};

// A 64 GiB physical-address ceiling uses two 2 MiB bitmaps at 4 KiB granularity.
// The bitmap itself is reserved automatically as part of the kernel BSS.
static mut FRAME_BITMAP: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];
static mut ALLOCATED_BITMAP: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];
static mut PMM_STATE: MaybeUninit<Pmm<'static>> = MaybeUninit::uninit();
static mut BOOT_PAGING_INFO: MaybeUninit<BootPagingInfo> = MaybeUninit::uninit();

fn initialize_memory() -> bool {
    // Limine sets the third base-revision field to zero when the requested
    // protocol revision is supported.
    let revision_supported =
        unsafe { addr_of!(LIMINE_REQUESTS.base_revision[2]).read_volatile() == 0 };
    if !revision_supported {
        serial_write("Centinela-OS: unsupported Limine base revision.\r\n");
        return false;
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
        return false;
    }

    // SAFETY: Limine supplies a valid HHDM response for the lifetime of boot.
    let hhdm_revision = unsafe { addr_of!((*hhdm).revision).read() };
    let hhdm_offset = unsafe { addr_of!((*hhdm).offset).read() };
    if hhdm_revision != 0 || hhdm_offset & 0xfff != 0 {
        serial_write("Centinela-OS: unsupported or invalid HHDM response.\r\n");
        return false;
    }

    let hhdm_offset = match HhdmOffset::new(hhdm_offset) {
        Ok(offset) => offset,
        Err(_) => {
            serial_write("Centinela-OS: HHDM offset is not canonical.\r\n");
            return false;
        }
    };
    let paging_info = match BootPagingInfo::new(current_page_table_root(), hhdm_offset) {
        Ok(info) => info,
        Err(_) => {
            serial_write("Centinela-OS: active CR3 root is invalid or not HHDM-addressable.\r\n");
            return false;
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
            return false;
        }
    };
    let walker = PageTableWalker::new(&table_memory, paging_info.root_physical());
    let root_alias = match walker.translate(paging_info.root_virtual()) {
        Ok(translation) => translation,
        Err(_) => {
            serial_write("Centinela-OS: active page-table root is not readable through HHDM.\r\n");
            return false;
        }
    };
    if root_alias.physical_address != paging_info.root_physical().get() {
        serial_write("Centinela-OS: HHDM root translation mismatch.\r\n");
        return false;
    }

    let kernel_entry = match VirtAddr::new(_start as *const () as usize as u64) {
        Ok(address) => address,
        Err(_) => {
            serial_write("Centinela-OS: kernel entry virtual address is invalid.\r\n");
            return false;
        }
    };
    let entry_mapping = match walker.translate(kernel_entry) {
        Ok(translation) => translation,
        Err(_) => {
            serial_write("Centinela-OS: kernel entry mapping could not be verified.\r\n");
            return false;
        }
    };
    if !entry_mapping.executable || entry_mapping.writable {
        serial_write("Centinela-OS: kernel entry mapping violates RX permissions.\r\n");
        return false;
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
    let Some((kernel_start, kernel_end)) = kernel_physical_range(&walker) else {
        return false;
    };

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
            return false;
        }
    };

    // SAFETY: Limine's memory-map response and its entry array are valid boot
    // information, and all PMM access is serialized on this single CPU.
    if unsafe { pmm.initialize_from_limine(memory_map, kernel_start, kernel_end) }.is_err() {
        serial_write("Centinela-OS: invalid physical memory map.\r\n");
        return false;
    }

    let Some(test_frame) = pmm.allocate_frame() else {
        serial_write("Centinela-OS: no usable physical frames detected.\r\n");
        return false;
    };
    if pmm.free_frame(test_frame).is_err() {
        serial_write("Centinela-OS: PMM allocation self-test failed.\r\n");
        return false;
    }

    // Keep the initialized manager alive for subsequent kernel subsystems.
    // SAFETY: PMM_STATE is written exactly once during single-core bootstrap.
    unsafe {
        addr_of_mut!(PMM_STATE).write(MaybeUninit::new(pmm));
    }

    serial_write("PMM initialized: 4 KiB frames, 64 GiB address ceiling.\r\n");
    serial_write("PMM allocation/free self-test passed.\r\n");
    true
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
    Some((physical_base, physical_end))
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Best effort: without a UART the boot continues silently instead of hanging.
    let _ = serial_init();
    serial_write("\r\nCentinela-OS: Rust kernel entry reached.\r\n");

    // SAFETY: Ring 0, bootstrap CPU, interrupts disabled (Limine hands off with
    // IF clear) and only supervisor mappings exist at this point.
    match unsafe { enable_boot_hardening() } {
        Ok(features) => {
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

    if !initialize_memory() {
        halt_forever();
    }

    serial_write("Bootstrap milestone: memory map validated and PMM online.\r\n");
    serial_write("HHDM response accepted.\r\n");
    halt_forever()
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
