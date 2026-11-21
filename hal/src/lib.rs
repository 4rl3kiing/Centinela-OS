#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! Narrow, audited interfaces for privileged CPU and device operations.

pub mod cpu;
pub mod entropy;
pub mod serial;
