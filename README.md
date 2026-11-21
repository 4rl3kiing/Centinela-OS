# Centinela-OS

**Centinela-OS** is an experimental operating-system project built primarily in Rust. Its initial target is x86_64, with boot support for legacy BIOS and UEFI and intended use across desktop and server systems.

The project has a freestanding Rust kernel with a Limine BIOS/UEFI boot path and an initial single-core physical memory manager. The last CPU-hardening change is being revalidated; do not treat it as production-qualified until the current branch CI passes.

## Initial technical decisions

- CPU architecture: x86_64.
- Firmware boot: legacy BIOS and UEFI through a common boot protocol.
- Bootloader/protocol candidate: Limine.
- Kernel model: capability-based hybrid microkernel. ADR-0002 acceptance is met: Ring 3 tasks, capability-checked IPC, a Ring 3 service and supervised restart under fault injection.
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
- Early CPU hardening for NXE, CR0.WP, SMEP, SMAP and UMIP when supported, including control-register readback.
- Checked x86_64 virtual/physical address types, four-level page-table index extraction, HHDM conversion and NX/W^X page-entry encoding primitives with host unit tests; active page-table management is not yet implemented.
- Feature-detected, bounded RDRAND/RDSEED hardware sampling interfaces in HAL; these samples are not yet mixed into a kernel entropy pool or used for KASLR.
- Fixed-capacity typed capability handles with per-resource rights and generation checks, plus monotonic syscall allow-list policy primitives; process/syscall integration remains pending.
- Nightly Miri workflow for host-testable workspace code, Kani bounded proofs for security/memory invariants, and a cargo-fuzz PMM/Limine memory-map harness with bounded CI smoke testing.
- Word-level PMM bitmap allocation scanning to reduce the cost of searching for free frames.

The PMM is an initial single-core implementation. It is not yet a complete virtual-memory manager and does not yet provide SMP-safe allocation.

## Documentation

- [Kernel architecture and implementation roadmap](docs/architecture/overview.md)
- [ADR-0001: x86_64, BIOS/UEFI, and boot strategy](docs/decisions/0001-platform-and-boot.md)
- [ADR-0002: capability-based hybrid microkernel](docs/decisions/0002-hybrid-microkernel.md)
- [ADR-0003: zero-trust layer isolation](docs/decisions/0003-layer-isolation-zero-trust.md)
- [Layered security hardening implementation plan](docs/security/hardening-implementation-plan.md)

## Current status

Bootstrap, PMM and hardening milestones passed under BIOS and UEFI in QEMU, with Miri, Kani and fuzz workflows.

**Microkernel foundation (zero-trust layer isolation):** GDT/TSS with IST stacks, IDT with fail-closed Ring 0 handling, guard pages on every kernel stack (including the kernel's own execution stack), per-task address spaces with a supervisor-only kernel half, a SYSCALL gate with policy plus capability authorization, validated user-memory copies that never dereference user addresses, and a local APIC watchdog. Every boot runs one benign and eleven hostile Ring 3 tasks; each attack (kernel memory reads, privileged instructions, port I/O, W^X and NX violations, spoofed interrupts, forbidden/unknown/uncapable syscalls, CPU monopolization, stack overflow) is contained, its memory reclaimed, and the kernel keeps running. See ADR-0003.

**Microkernel milestone (ADR-0002 acceptance):** a Ring 3 service is reached only through an endpoint capability (separate SEND/RECEIVE rights, 4-word bounded messages). A client injects a fault into it; the kernel returns `EPIPE` to the client, the supervisor restarts the service with fresh memory and capabilities, and the next request succeeds. Forged handles, missing rights, oversized messages and capability-less IPC terminate the offender.

Not yet implemented: capability transfer over IPC, user-space service manager, preemptive scheduler, SMP, ELF loading, KASLR, KPTI, heap hardening and IOMMU.
