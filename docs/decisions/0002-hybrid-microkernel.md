# ADR-0002: Capability-based hybrid microkernel

- **Status:** Accepted
- **Date:** 2026-11-20
- **Decision owners:** Centinela-OS maintainers

## Context

The current repository is a small freestanding x86_64 Rust kernel with a Limine boot path, a single-core physical memory manager, CPU hardening, and policy primitives for capabilities and W^X. It does not yet implement a scheduler, process model, Ring 3 transitions, syscall dispatcher, or IPC. A monolithic design would place future drivers and services in the kernel's trusted computing base and increase the impact of memory-safety defects.

## Decision

Adopt a **capability-based hybrid microkernel** as the target architecture. Keep Ring 0 limited to mechanisms that require privilege: exception/interrupt entry, scheduling and context switching, address-space and page-table management, capability enforcement, IPC primitives, and minimal core memory management. Place drivers, filesystems, networking, device management, service management, and ordinary system services in isolated Ring 3 processes where practical.

All cross-process authority must be explicit. IPC endpoints and resources are accessed through typed, generation-tagged capabilities with least-privilege rights. Message sizes, queue depth, resource use, and shared-memory mappings must be bounded and validated. Shared memory is granted explicitly and mapped with W^X and least-privilege permissions. Service restart must not restore revoked capabilities or bypass resource ownership.

## Compatibility and migration

- Retain Limine, the current kernel entry point, HAL, PMM, and existing hardening until replacement paths pass equivalent tests.
- Migrate in dependency order: VMM and page permissions; GDT/TSS/IDT and privilege transitions; process/thread/scheduler; syscall boundary and safe user-memory access; IPC and capabilities; user-space init/service manager; isolated drivers.
- Introduce no user-space driver until IPC, restart supervision, resource capabilities, and IOMMU-backed DMA isolation are operational for the relevant device.
- Preserve BIOS and UEFI boot support throughout migration.

## Security invariants

1. No user-controlled pointer is dereferenced in Ring 0 without a validated copy/access primitive.
2. No process receives ambient access to kernel objects or device resources.
3. Capability transfer cannot amplify rights; revocation and generation checks prevent stale-handle reuse.
4. IPC rejects malformed, oversized, unauthorized, and quota-exceeding messages before dispatch.
5. A failed user-space service cannot write arbitrary kernel memory or prevent unrelated services from restarting.
6. Writable and executable mappings are never granted simultaneously.
7. DMA-capable devices remain in a deny-by-default isolation domain until IOMMU mappings are validated.

## Performance policy

Use measurement, not assumptions, to decide which mechanisms may remain in Ring 0. Track IPC, syscall, context-switch, scheduling, and I/O latency using fixed QEMU configurations and later physical reference hardware. Any performance exception to service isolation requires a documented threat-model review and benchmark evidence.

## Acceptance criteria

The architecture is not considered implemented merely because this ADR exists. The first end-to-end microkernel acceptance milestone requires: a user process entering Ring 3; capability-checked IPC with bounds validation; a service performing a request; and proof by fault injection that terminating/restarting that service does not corrupt or halt the kernel. BIOS and UEFI QEMU boot tests must continue to pass.

## Consequences

This decision increases implementation complexity and requires careful ABI, IPC, memory ownership, and driver isolation work. It reduces the amount of code executing with full kernel privilege and enables independent service failure/restart. A hybrid approach allows only benchmark- and security-justified fast paths to remain in Ring 0 without reverting to a broadly monolithic kernel.
