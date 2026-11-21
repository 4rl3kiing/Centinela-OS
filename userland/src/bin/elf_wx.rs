//! HOSTILE: linked with a writable+executable segment (see link-wx.ld).
//! The kernel's ELF loader must refuse to load it; this code never runs.
#![no_std]
#![no_main]

use centinela_userland::{exit, write};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write("W+X image executed: loader failed to enforce W^X");
    exit(0)
}
