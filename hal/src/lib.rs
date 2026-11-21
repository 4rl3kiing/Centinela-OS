#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! Narrow, audited interfaces for privileged CPU and device operations.
//!
//! Mechanism lives here; policy (which task to kill, when to halt) lives in
//! the kernel. Hardware-executing parts are compiled only for the freestanding
//! target; encoding logic is host-testable.

pub mod apic;
pub mod cpu;
pub mod entropy;
pub mod font;
pub mod framebuffer;
pub mod gdt;
pub mod idt;
pub mod serial;
pub mod syscall;
