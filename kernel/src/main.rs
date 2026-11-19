#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::mem::MaybeUninit;
use core::panic::PanicInfo;
use core::ptr::{addr_of, addr_of_mut};

use centinela_hal::cpu::{enable_boot_hardening, halt_forever};
use centinela_hal::serial::{init as serial_init, write as serial_write};
use centinela_kernel::memory::pmm::{BITMAP_WORDS, LimineMemoryMapResponse, Pmm};

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
struct LimineRequests {
    start_marker: [u64; 4],
    base_revision: [u64; 3],
    stack_size: LimineStackSizeRequest,
    hhdm: LimineRequest,
    memory_map: LimineRequest,
    end_marker: [u64; 2],
}

unsafe extern "C" {
    static __kernel_phys_start: u8;
    static __kernel_phys_end: u8;
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
    end_marker: [0xadc0_e053_1bb1_0d03, 0x9572_709f_3176_4c62],
};

// A 64 GiB physical-address ceiling uses two 2 MiB bitmaps at 4 KiB granularity.
// The bitmap itself is reserved automatically as part of the kernel BSS.
static mut FRAME_BITMAP: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];
static mut ALLOCATED_BITMAP: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];
static mut PMM_STATE: MaybeUninit<Pmm<'static>> = MaybeUninit::uninit();

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

    // The linker exports physical load boundaries, including the PMM bitmap
    // in BSS, so the allocator cannot hand kernel-owned frames back to callers.
    // addr_of! obtains linker-symbol addresses without reading their contents.
    let kernel_start = addr_of!(__kernel_phys_start) as u64;
    let kernel_end = addr_of!(__kernel_phys_end) as u64;

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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    serial_init();
    serial_write("\r\nCentinela-OS: Rust kernel entry reached.\r\n");

    match enable_boot_hardening() {
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
        Err(_) => {
            serial_write("Centinela-OS: mandatory NX support unavailable.\r\n");
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
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_write("\r\nCentinela-OS: PANIC. System halted.\r\n");
    halt_forever()
}
