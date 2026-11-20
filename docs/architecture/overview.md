# Centinela-OS: kernel architecture baseline

**Status:** Migration target approved; staged implementation  
**Target:** x86_64, legacy BIOS + UEFI  
**Kernel language:** Rust (`no_std`)  
**Kernel model:** Capability-based hybrid microkernel (target); current bootstrap remains monolithic

## 1. Goals and non-goals

### Goals

- Build a general-purpose operating-system foundation for desktop and server workloads.
- Provide preemptive multitasking, virtual memory, process isolation, a syscall boundary, and a modular driver model.
- Keep hardware-dependent mechanisms behind narrow interfaces.
- Make performance measurable with repeatable benchmarks rather than assumptions.
- Make privileged unsafe code auditable and minimize its footprint.
- Preserve a path to additional CPU architectures without making the first milestone multi-architecture.

### Non-goals for the first milestone

- Linux binary or source compatibility.
- A production desktop environment.
- Full POSIX compatibility.
- Supporting every PC device or filesystem.
- SMP, advanced power management, and sophisticated networking before the single-core kernel is stable.
- A claim of Linux feature parity.

## 2. High-level architecture

The approved target is a capability-based hybrid microkernel. Ring 0 is restricted to the minimum mechanisms required for protection and scheduling: CPU/interrupt entry, address-space and thread primitives, capability validation, IPC fast paths, and essential memory management. Drivers, filesystems, networking, device management, service management, and ordinary system services are intended to run as isolated Ring 3 processes. Services communicate through bounded, versioned IPC endpoints and transferred capabilities; shared memory is explicit, mapped with least privilege, and never an ambient authority. Performance-critical mechanisms may remain in kernel space only after a documented threat-model and benchmark review.\n\n**Migration status:** this is the target architecture, not a claim that Ring 3, scheduling, IPC, or user-space drivers already exist. The current Limine entry path, PMM, HAL, and security policy crates are retained as bootstrap foundations while the missing mechanisms are implemented in dependency order. No existing boot or memory path is to be removed until its replacement passes BIOS/UEFI QEMU tests.

Logical layers:

1. **Boot and platform handoff** — bootloader protocol, memory map, framebuffer, firmware metadata.
2. **Architecture layer** — CPU setup, GDT, IDT, TSS, exception entry, context switching, paging, local APIC.
3. **Kernel core** — initialization, synchronization primitives, panic handling, logging, capability/handle foundations.
4. **Memory** — physical frame allocator, virtual address spaces, kernel heap, page mapping.
5. **Execution** — threads, processes, scheduler, timers, wait queues, signals/events as designed.
6. **I/O and drivers** — PCI/PCIe discovery, interrupt routing, block, console, input, network drivers.
7. **System interfaces** — syscall dispatch, VFS, IPC, executable loader.
8. **User space** — init process, service manager, shell, system utilities, desktop/server services.

These are logical boundaries, not a requirement to create a separate crate for every item on day one. The target privilege boundary is strict: only the microkernel mechanisms above execute in Ring 0; policy, protocol, and device services execute in Ring 3 wherever practical.

## 3. Boot strategy: BIOS and UEFI

Use the Limine bootloader and Limine protocol as the initial boot handoff for x86_64. Limine documents BIOS and UEFI boot paths and supports hybrid media. This avoids implementing firmware-specific boot stages inside the kernel.

The kernel must validate every boot-provided structure before use and copy essential data into kernel-owned structures before reclaiming bootloader-reclaimable memory.

Initial handoff contract:
- Kernel image in ELF format.
- Bootloader memory map.
- Higher-half direct-map information, if requested and supported by the selected protocol revision.
- Framebuffer metadata as optional data.
- ACPI RSDP or equivalent firmware-table pointer when available.
- Kernel command line and module metadata where needed.

Do not assume the bootloader's page tables, allocator, or mappings remain valid after the kernel takes control. The early boot code must establish and document the kernel's own memory-management state.

## 4. Rust and build model

- Use `#![no_std]` for the kernel.
- Start with Rust target `x86_64-unknown-none`; use a linker script and explicit kernel entry point.
- Keep host-side tools and test harnesses separate from the freestanding kernel target.
- Use `core` by default. Introduce `alloc` only after a kernel allocator exists.
- Avoid pulling in crates that assume an operating system, threads, filesystem, or standard I/O.
- Pin toolchain and dependency versions; commit lockfiles for executable/workspace builds.
- Use a small assembly boundary only where architecture entry/exit or special CPU instructions require it.

The official Rust target documentation specifies that `x86_64-unknown-none` is freestanding, has no `std` support and no default allocator. Tests that require `std` must run in host-side crates or dedicated test harnesses.

## 5. Proposed workspace layout

```text
/
├── Cargo.toml
├── rust-toolchain.toml
├── .cargo/
│   └── config.toml
├── linker/
│   └── x86_64.ld
├── boot/
│   ├── limine.conf
│   └── README.md
├── kernel/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── arch/x86_64/
│       ├── boot/
│       └── memory/
├── hal/
│   ├── Cargo.toml
│   └── src/
│       ├── cpu.rs
│       └── serial.rs
├── security/
│   ├── Cargo.toml
│   └── src/
│       ├── capabilities.rs
│       └── permissions.rs
├── crates/                 # Add only when stable shared interfaces exist
├── user/                   # Introduce after ring-3 execution is designed
└── tools/                  # Host-side build and test tools
├── tests/
│   ├── integration/
│   └── boot/
└── docs/
    ├── architecture/
    ├── decisions/
    └── testing/
```

The workspace currently has three real crates: `kernel` owns privileged kernel orchestration and memory management; `hal` encapsulates architecture-specific CPU and device operations; `security` contains architecture-independent, safe policy primitives. The `security` types are not enforcement by themselves: paging, task creation and syscall code must consume them before they provide runtime isolation. Create further crates only when ownership, build requirements or testing boundaries justify them. Avoid premature fragmentation.

## 6. Core subsystem contracts

### 6.1 Architecture and CPU setup

Responsibilities:
- GDT, IDT, TSS and privilege-level transitions.
- Exception and interrupt entry/exit.
- Per-CPU state abstraction, initially with one bootstrap processor.
- Context-switch primitives and CPU feature discovery.
- Local APIC and I/O APIC integration when interrupt infrastructure is ready.

Invariant: interrupt entry must preserve the documented register/stack contract and must not call code that can sleep unless the interrupt is converted into deferred work.

### 6.2 Memory management

Implementation order:
1. Parse and normalize the bootloader memory map.
2. Reserve kernel image, boot data, firmware tables and device/MMIO regions.
3. Implement a physical frame allocator.
4. Define virtual address-space layout and page-table ownership.
5. Establish kernel mappings and guard regions.
6. Add a kernel heap allocator.
7. Add per-process address spaces and user/kernel permission enforcement.

Use checked arithmetic and explicit page-alignment helpers. Never treat arbitrary physical addresses as safe Rust references. Keep physical, virtual and direct-map address types distinct.

### 6.3 Interrupts, timers and scheduling

Start with:
- Exception handlers and panic diagnostics.
- A reliable timer source.
- A single-core, preemptive scheduler after context switching is proven.
- Thread states and well-defined transitions.
- Scheduler queues and wait queues with documented locking rules.

Do not introduce SMP scheduling until single-core scheduling, synchronization and interrupt safety are tested. Later SMP work requires per-CPU run queues, inter-processor interrupts, CPU affinity policy and a lock-ordering strategy.

### 6.4 Processes and user mode

Define process and thread ownership separately. A process owns an address space and handles/resources; threads are schedulable execution contexts. Introduce ring-3 entry, validated syscall arguments, user-pointer copying/validation and process teardown before loading general applications.

### 6.5 Drivers and I/O

Use a staged device strategy:
1. Serial console and framebuffer text/diagnostics.
2. PCI/PCIe enumeration.
3. Virtio devices in QEMU for deterministic development.
4. Storage controller and block-device abstraction.
5. Input and network devices.
6. Physical-hardware drivers based on an explicit support matrix.

Drivers are targeted for isolated Ring 3 processes. Until process isolation, IPC, restart supervision, resource capabilities, and IOMMU-backed DMA isolation are validated, drivers remain trusted bootstrap components; no driver is to be moved out of Ring 0 prematurely.

### 6.6 Storage and VFS

First define block-device and VFS interfaces. Begin with a simple read-only or test filesystem for boot and integration tests; add a writable filesystem only after crash and consistency semantics are specified. Journaling, caching and recovery require dedicated design reviews.

### 6.7 Networking

Separate protocol logic from device drivers. Build from Ethernet and packet-buffer ownership through ARP/IPv4/IPv6, ICMP, UDP and TCP. Network services belong in user space where practical. Do not treat networking as a prerequisite for the first bootable kernel.

### 6.8 Security

Baseline controls:
- Kernel/user address-space separation.
- W^X policy where supported by the paging design.
- NX enforcement and supervisor/user page permissions.
- Checked syscall boundaries and safe user-memory access.
- Least privilege for user-space services.
- Audited unsafe blocks with safety comments and invariants.
- Dependency review and reproducible build inputs.
- No secrets in logs, crash dumps or repository history.

Secure Boot, signed updates, IOMMU isolation, kernel ASLR/KASLR and measured boot are later milestones requiring separate threat models and implementation evidence.

## 7. Performance engineering

Optimization is measurement-driven:
- Establish boot-time, context-switch, syscall, allocator and I/O baselines.
- Use microbenchmarks and workload-level benchmarks.
- Track latency distributions, throughput, CPU utilization and memory overhead.
- Compare changes against a fixed QEMU configuration and later physical reference hardware.
- Avoid architecture-specific CPU features until runtime detection and fallback paths exist.

Do not optimize scheduler policy or allocator design based only on synthetic microbenchmarks; include representative desktop and server workloads.

## 8. Development and validation gates

Every milestone must have:
- A documented scope and acceptance criteria.
- Formatting and lint checks.
- Unit tests where host-testable.
- Integration tests in QEMU.
- Boot tests for both BIOS and UEFI images when the milestone affects boot.
- Static review of unsafe code and privilege boundaries.
- Reproducible build instructions and captured logs.

Suggested gates:
- G0: workspace and toolchain build.
- G1: boot to kernel entry under QEMU BIOS and UEFI.
- G2: serial diagnostics, panic path and boot-memory validation.
- G3: kernel-owned page tables and physical allocator.
- G4: heap allocator and memory tests.
- G5: exceptions, timer and interrupt infrastructure.
- G6: context switching and preemptive single-core scheduling.
- G7: user mode, process model and syscall ABI.
- G8: drivers, block I/O and VFS.
- G9: networking and service foundations.
- G10: SMP, hardening and performance qualification.

## 9. Initial acceptance criteria

The first implementation milestone is not "Linux-like functionality". It is a deterministic, repeatable boot path:
- Build the kernel ELF from a clean checkout.
- Produce bootable BIOS and UEFI test images.
- Boot each image in QEMU.
- Reach the Rust kernel entry point.
- Print a version/build identifier over serial.
- Halt safely after reporting success.
- Preserve logs and exact build commands in CI.

No milestone is complete solely because compilation succeeds.
