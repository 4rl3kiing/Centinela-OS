#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

pub mod acpi;
pub mod elf;
pub mod ipc;
pub mod memory;
