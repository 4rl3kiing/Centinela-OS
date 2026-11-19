# Security hardening implementation plan

**Status:** staged implementation; not production-qualified.
**Platform baseline:** x86_64, Limine, BIOS/UEFI, single bootstrap CPU.

This document distinguishes implemented mechanisms from planned enforcement. A policy type or a detected CPU feature is not proof that the kernel enforces the corresponding security property.

## Acceptance states

- **Designed:** threat model, invariants and interfaces are documented.
- **Implemented:** executable code exists.
- **Integrated:** the relevant kernel path uses that code.
- **Validated:** automated tests and runtime evidence cover the property.

A milestone may only be called complete when all required states for that milestone are satisfied.

## Layer 0 — workspace and unsafe-code boundaries

- Keep `kernel`, `hal`, and `security` as separate workspace crates.
- Keep privileged instructions and device I/O behind narrow HAL interfaces.
- Require explicit unsafe blocks and safety comments.
- Keep policy-only security primitives free of unsafe code.
- Run formatting, Clippy, host unit tests, freestanding compilation, ISO generation and BIOS/UEFI QEMU tests.

## Layer 1 — CPU hardening

Implemented in the bootstrap path:
- Detect NX support before enabling IA32_EFER.NXE.
- Detect UMIP, SMEP and SMAP through CPUID leaf 7.
- Expose bounded, feature-detected RDRAND/RDSEED sampling through HAL; samples are raw inputs, not a complete entropy pool.
- Enable CR0.WP so supervisor writes obey read-only page permissions.
- Set only supported CR4 bits and preserve unrelated CR4 state.
- Read back EFER, CR0 and CR4 to verify activation.
- Fail closed if mandatory NX is unavailable or a supported requested control bit does not stick.

Limitations:
- NXE only makes the PTE XD/NX bit meaningful. Until the VMM marks data and stack pages NX, it does not enforce non-executable data pages.
- SMEP/SMAP currently run before user address spaces exist. Before Ring 3, implement audited copyin/copyout routines using STAC/CLAC for the minimal access window and ensure all other kernel paths keep AC clear.
- QEMU feature exposure must be checked; optional features may be absent in some CPU models.

## Layer 2 — physical and virtual memory

Required order:
1. Retain and test PMM ownership rules; keep frame zero, kernel image, boot data and MMIO reserved.
2. Replace per-frame allocation scans with bitmap-word scans.
3. Define typed physical and virtual addresses and checked HHDM conversion.
4. Establish kernel-owned page-table roots and document all mappings inherited from Limine.
5. Implement 4-level page-table map, unmap and translate operations first.
6. Enforce W^X and NX in the page-table entry constructor and mapper; reject writable+executable mappings.
7. Add page-table ownership, rollback on partial mapping failure, and TLB invalidation.
8. Add guard pages for kernel stacks and heap regions.
9. Add zero-before-reuse for frames only after the kernel can safely map and clear the entire frame.
10. Add per-process address spaces and KPTI only after privilege transitions and syscall/interrupt entry mappings are fully specified.

Do not enable LA57 or switch paging depth until a tested transition path exists. Detect support separately from enabling it.

## Layer 3 — execution and privilege boundary

- Implement GDT, TSS, IST stacks and IDT exception handlers.
- Add a single-core scheduler and context switching only after interrupt entry/exit invariants are tested.
- Introduce Ring 3, per-process address spaces and validated user-memory copies.
- Replace ambient privilege assumptions with typed object capabilities and opaque handles.
- Enforce least-privilege access rights per resource and make syscall policy reduction monotonic.
- Add syscall allow/deny policy with monotonic privilege dropping; a task may reduce its syscall set but cannot regain denied calls.
- Add IPC primitives and shared-memory ownership rules before moving drivers out of Ring 0.

## Layer 4 — device isolation

- Enumerate PCI devices and parse ACPI DMAR/IVRS tables.
- Detect Intel VT-d or AMD-Vi and validate firmware configuration.
- Implement IOMMU domain setup, device assignment, DMA mapping and invalidation before enabling bus mastering for untrusted devices.
- Keep devices in a deny-by-default DMA domain until mappings are established.
- Move complex drivers to user mode only after IPC, restart policy, resource capabilities and IOMMU isolation are operational.

An IOMMU must not be represented as enabled merely because firmware tables exist. Device DMA isolation requires successful hardware initialization and verified domain mappings.

## Layer 5 — toolchain and continuous verification

- Keep stable Rust as the required reproducible build.
- Evaluate nightly-only CFI and stack-protector support in a separate experimental CI job; do not pass unsupported `-Z` flags to the stable kernel build.
- Treat stack protectors, stack probing and interrupt-stack guard pages as separate controls.
- Run host-testable unsafe-sensitive code under Miri where supported; the current workspace host test suite passes under Miri.
- Kani proof harnesses cover W^X policy, monotonic syscall restrictions, PMM frame accounting/alignment, canonical virtual addresses and W^X PTE encoding; the bounded proof workflow passes.
- Fuzz parsers, syscall argument decoders, IPC message validation and filesystem/network parsers in host builds using cargo-fuzz; the first PMM/Limine memory-map fuzz target and bounded CI smoke run pass.
- Preserve seeds, regression cases and sanitizer findings.

Miri and Kani results apply only to the harnessed code and assumptions; they are not a proof that the complete kernel is free of undefined behavior or vulnerabilities.

## Deferred security properties

### KASLR
Requires relocatable kernel image support, relocation processing, a trustworthy entropy source, and verification that all absolute references and early mappings are handled. Hardware random instructions must be feature-detected and health/failure handled; timer jitter is not automatically cryptographic entropy. Do not claim KASLR until the kernel base is observed to vary across boots and relocation correctness is tested.

### KPTI
Requires separate kernel and user page-table roots, a minimal mapped entry/exit trampoline, safe CR3 switching, PCID/TLB policy and careful handling of exceptions/NMIs. It is not a simple second page table and must be threat-modelled against the supported CPU families.

### Hardened heap and slabs
Requires a working VMM and heap. Add guard pages, randomized freelists, metadata integrity checks/canaries, quarantine where practical, and zero-on-free. Randomization must use a sound entropy source and must not compromise allocator correctness.

## Current implementation snapshot

- Workspace split into kernel/HAL/security crates.
- Initial single-core PMM with Limine memory-map parsing and allocation/free tests.
- CPU boot hardening detects and enables NXE, CR0.WP, UMIP, SMEP and SMAP when supported, with register readback.
- HAL exposes bounded RDRAND/RDSEED reads after CPUID feature detection; these are not yet mixed into a kernel CSPRNG or used for KASLR.
- VMM groundwork provides checked 48-bit canonical virtual addresses, bounded physical addresses, HHDM conversion, four-level page-table indices and NX/W^X page-entry encoding. It does not yet install or own active page tables.
- Bootstrap now captures the active CR3 physical root and computes its checked HHDM alias before PMM initialization. This is a metadata snapshot only: it does not dereference the root, verify that the HHDM mapping is present, clone tables, or switch CR3.
- VMM now includes a read-only four-level page-table walker that combines effective RW/US/NX permissions and translates 4 KiB, 2 MiB, and 1 GiB mappings. The HHDM reader is an explicitly unsafe capability: callers must establish that every traversed page-table frame is mapped and readable through the HHDM. The walker is not yet invoked during bootstrap and no mappings are changed.
- The walker rejects reserved high-order entry bits and illegal page-size flags at the PML4 level. Its translation tests cover these malformed-entry cases in addition to the supported leaf sizes.
- PMM allocator is being optimized to scan bitmap words rather than every frame.
- W^X permission policy, fixed-capacity typed generation-tagged capability handles, and monotonic syscall allow-list primitives exist; they are not yet wired into process creation or a syscall dispatcher.

Everything else above remains planned until integrated and validated by the relevant tests.
