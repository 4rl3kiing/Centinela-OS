# Centinela-OS

**Centinela-OS** is an experimental operating-system project built primarily in Rust. Its initial target is x86_64, with boot support for legacy BIOS and UEFI and intended use across desktop and server systems.

The project has a freestanding Rust kernel with a Limine BIOS/UEFI boot path and an initial single-core physical memory manager. The last CPU-hardening change is being revalidated; do not treat it as production-qualified until the current branch CI passes.

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
- Initial bitmap PMM for 4 KiB frames, bounded to the first 64 GiB of physical address space; single-core and validated at boot.
- Separate free/reserved and allocated-frame bitmaps, with kernel/BSS reservation and allocation/free self-test.
- Host-side PMM unit tests in CI.
- Workspace split into `kernel`, `hal` and `security` crates; privileged UART and CPU halt operations are encapsulated in HAL.
- Capability-set and W^X permission-policy primitives in the security crate; these are policy primitives, not runtime isolation.
- Early CPU hardening for NXE, SMEP, SMAP and UMIP when supported, including control-register readback.
- Word-level PMM bitmap allocation scanning to reduce the cost of searching for free frames.

The PMM is an initial single-core implementation. It is not yet a complete virtual-memory manager and does not yet provide SMP-safe allocation.

## Documentation

- [Kernel architecture and implementation roadmap](docs/architecture/overview.md)
- [ADR-0001: x86_64, BIOS/UEFI, and boot strategy](docs/decisions/0001-platform-and-boot.md)
- [Layered security hardening implementation plan](docs/security/hardening-implementation-plan.md)

## Current status

Bootstrap and initial PMM milestones passed: the kernel builds, produces a hybrid ISO, reaches its Rust entry point, validates the Limine memory map and exercises PMM allocation/free under BIOS and UEFI in QEMU. The HAL/security workspace split and CPU-hardening changes are under validation on the hardening implementation branch. VMM, enforced NX/W^X mappings, KASLR, KPTI, heap hardening, scheduling, user space, IPC, driver isolation and IOMMU remain unimplemented.
