# Centinela-OS

**Centinela-OS** is an experimental operating-system project built primarily in Rust. Its initial target is x86_64, with boot support for legacy BIOS and UEFI and intended use across desktop and server systems.

The project is currently in the architecture and bring-up planning stage. It is not yet a bootable or production-ready operating system.

## Initial technical decisions

- CPU architecture: x86_64.
- Firmware boot: legacy BIOS and UEFI through a common boot protocol.
- Bootloader/protocol candidate: Limine.
- Kernel model: modular monolithic kernel.
- Kernel language: Rust, `no_std` in privileged code.
- Initial binary target: `x86_64-unknown-none`.
- Initial execution environments: QEMU first; physical hardware after repeatable virtual-machine validation.
- Product scope: desktop and server foundations, developed incrementally.

## Engineering principles

1. Establish explicit subsystem boundaries and documented interfaces.
2. Keep unsafe Rust small, justified, reviewed, and covered by invariants.
3. Prefer deterministic tests and reproducible builds.
4. Separate hardware-specific code from architecture-independent kernel logic.
5. Add concurrency and SMP only after single-core correctness is established.
6. Do not claim a feature is implemented until it builds and has test evidence.

## Documentation

- [Kernel architecture and implementation roadmap](docs/architecture/overview.md)
- [ADR-0001: x86_64, BIOS/UEFI, and boot strategy](docs/decisions/0001-platform-and-boot.md)

## Current status

Architecture baseline only. Kernel initialization, memory management, scheduling, drivers, storage, networking, and user space remain to be implemented and validated.
