#![no_std]
#![forbid(unsafe_code)]

//! Architecture-independent security policy primitives.
//!
//! These types define policy; they do not themselves enforce process or
//! hardware isolation until wired into the scheduler, MMU and syscall layer.

pub mod capabilities;
pub mod handles;
pub mod permissions;
pub mod syscall_policy;
