# Centinela-OS

**Centinela-OS** is an experimental operating-system project built primarily in Rust. Its initial target is x86_64, with boot support for legacy BIOS and UEFI and intended use across desktop and server systems.

The project has an initial Rust workspace and a minimal freestanding kernel entry point. The kernel has passed the initial Rust formatting, Clippy, and target-compilation checks in GitHub Actions. BIOS/UEFI image generation and QEMU boot validation are now automated but remain pending successful completion.

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

## Initial implementation

- Rust workspace targeting `x86_64-unknown-none`.
- Minimal `no_std`/`no_main` kernel entry point.
- Early COM1 serial diagnostics and panic halt path.
- x86_64 ELF linker script retaining the Limine request section.
- Limine base-revision 5, stack-size, HHDM, and memory-map requests.
- Pinned Limine v12.9.6 image builder with SHA-256 verification.
- Automated BIOS and UEFI QEMU boot checks with serial-log assertions.

These files establish the bootstrap structure only. BIOS/UEFI image generation and QEMU boot validation are still pending.

## Documentation

- [Kernel architecture and implementation roadmap](docs/architecture/overview.md)
- [ADR-0001: x86_64, BIOS/UEFI, and boot strategy](docs/decisions/0001-platform-and-boot.md)

## Current status

Bootstrap source skeleton committed. Hybrid ISO generation and BIOS/UEFI QEMU boot checks are automated; their successful completion is still required before this milestone is considered closed. Memory management, scheduling, drivers, storage, networking, and user space remain unimplemented.
