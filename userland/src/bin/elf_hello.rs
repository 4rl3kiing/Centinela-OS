//! Benign Rust user program loaded from a hashed boot module by the kernel's
//! ELF loader. Exercises its R-X, R and RW segments and anonymous memory.
#![no_std]
#![no_main]

use centinela_userland::{exit, map_memory, write};

static GREETING: &str = "hello from a Rust ELF loaded from a verified boot module";
static mut COUNTER: u64 = 0;
static mut TABLE: [u64; 4] = [1, 2, 3, 4];

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(GREETING);

    // .bss and .data are writable, zero/initialized as the ELF specifies.
    // SAFETY: Single-threaded task; plain accesses to its own statics.
    let data_ok = unsafe {
        COUNTER += 40;
        TABLE[3] += 38;
        let counter = core::ptr::read_volatile(&raw const COUNTER);
        let table = core::ptr::read_volatile(&raw const TABLE);
        counter == 40 && table[3] == 42
    };
    if !data_ok {
        exit(1);
    }
    write("data and bss segments initialized as the ELF specifies");

    match map_memory(2) {
        Ok(base) => {
            // SAFETY: The kernel just mapped two zeroed RW pages at `base`.
            let ok = unsafe {
                let zeroed = core::ptr::read_volatile(base.add(4096 + 17)) == 0;
                core::ptr::write_volatile(base.add(4096 + 17), 0x5a);
                zeroed && core::ptr::read_volatile(base.add(4096 + 17)) == 0x5a
            };
            if !ok {
                exit(2);
            }
            write("mapped 2 zeroed anonymous RW pages with MapMemory");
        }
        Err(_) => exit(3),
    }
    exit(0)
}
