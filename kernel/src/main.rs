#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::panic::PanicInfo;

const COM1: u16 = 0x3F8;
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
struct LimineRequests {
    start_marker: [u64; 4],
    base_revision: [u64; 3],
    stack_size: LimineStackSizeRequest,
    hhdm: LimineRequest,
    memory_map: LimineRequest,
    end_marker: [u64; 2],
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
    // Base revision 5 gives x86_64 a defined machine state at handoff.
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

#[inline]
fn outb(port: u16, value: u8) {
    // SAFETY: Writing an I/O port is an architecture-specific privileged
    // operation. This is only called during early kernel execution.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: Reading the UART line-status register is a privileged,
    // architecture-specific I/O operation in early kernel context.
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

fn serial_init() {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

fn serial_write(message: &str) {
    for byte in message.bytes() {
        while inb(COM1 + 5) & 0x20 == 0 {
            core::hint::spin_loop();
        }
        outb(COM1, byte);
    }
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: HLT is valid in the privileged kernel context. Interrupts
        // are disabled first, so this bootstrap kernel remains halted.
        unsafe {
            asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    serial_init();

    // Limine sets the third base-revision field to zero when the requested
    // protocol revision is supported. Read the bootloader-mutated field
    // without creating a Rust reference to the mutable static.
    let revision_supported =
        unsafe { core::ptr::addr_of!(LIMINE_REQUESTS.base_revision[2]).read_volatile() == 0 };

    if !revision_supported {
        serial_write("\r\nCentinela-OS: unsupported Limine base revision.\r\n");
        halt_forever();
    }

    serial_write("\r\nCentinela-OS: Rust kernel entry reached.\r\n");
    serial_write("Limine base revision 5 accepted.\r\n");
    serial_write("HHDM and memory-map requests submitted.\r\n");
    serial_write("Bootstrap milestone: serial diagnostics operational.\r\n");
    halt_forever()
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_write("\r\nCentinela-OS: PANIC. System halted.\r\n");
    halt_forever()
}
