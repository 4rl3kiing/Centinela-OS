# ADR-0004: SMP, IOMMU, Ring 3 drivers and first system services

- Status: Accepted (2026-11-21)
- Scope: roadmap phases 4 and 5
- Builds on: ADR-0002 (hybrid microkernel), ADR-0003 (zero-trust layer isolation)

## Context

Phases 1–3 delivered a capability microkernel on one CPU: preemptive
scheduling, ELF loading from hashed boot modules, KPTI, KASLR and Secure
Boot. Phases 4 and 5 bring in more hardware (more CPUs, DMA-capable
devices, interrupts) and the first services a user touches. Each new piece
is a new attack surface, so each one starts in a denied state.

## Decisions

### Phase 4.1: SMP with confined, parked application processors

- APs are released through the Limine MP protocol. At their first
  instruction they switch from the bootloader stack to private stacks
  behind unmapped guard pages: a kernel stack plus IST stacks for #DF,
  NMI and #MC.
- Each AP gets a private GDT/TSS with no I/O bitmap, loads the shared
  read-only IDT (all gates DPL 0) and enables NX, WP, SMEP, SMAP and UMIP.
  The BSP checks that each AP's hardening bitmap is identical to its own.
  A weaker AP fails the boot.
- APs park with IF=0. They never run tasks or touch shared kernel state,
  so the single-CPU invariants of the scheduler and IPC still hold.
- **Deferred:** running tasks on APs. That requires per-CPU scheduler
  state, locks, a TLB shootdown IPI and moving AP descriptor tables into
  the KPTI trampoline.

### Phase 4.2: IOMMU, deny-by-default

- The ACPI tables are untrusted input. Lengths are bounded and checksums
  verified, and reads are allowed only inside ACPI memory-map regions.
  Host tests cover hostile tables.
- Every VT-d unit listed in the DMAR table is pointed at one empty root
  table. The kernel then invalidates the context cache and IOTLB and
  enables translation. **All device DMA is blocked.**
- A malformed DMAR table, or a unit that does not confirm translation,
  fails the boot. A machine without a DMAR table boots with a warning.
- **Deferred:** per-device mappings granted by capability (needed for NIC
  and disk drivers) and interrupt remapping.

### Phase 4.3: Ring 3 drivers

- The I/O APIC is found through a defensively parsed MADT. Every line is
  masked at boot.
- A driver's grant (`DeviceGrant`) lists up to two port windows and one
  IRQ. The kernel refuses any grant that overlaps a kernel-owned port: the
  PIC, the PIT, 0x61, CMOS, COM1 (the kernel console) or PCI configuration.
- Port access is mediated by the `PortIo` syscall, one 8-bit access per
  call, checked against the grant. A TSS I/O bitmap was rejected: it keeps
  per-task hardware state inside the trampoline and allows no per-access
  audit. Mediation costs one syscall per port access, which is acceptable
  for legacy devices.
- When an IRQ fires, the kernel masks the line, sends EOI and delivers a
  **kernel-origin IPC notice**, which no task can forge. Only the bound
  driver can re-arm the line, with `IrqAck`, which takes no arguments.
  `PortIo` and `IrqAck` both require the `DeviceAccess` capability.
- Demonstrated with a 16550 UART driver (COM2 loopback, 9/9 bytes via
  IRQ 3) and an i8042 keyboard driver (controller self-test, then 3/3 ECHO
  replies via IRQ 1). Three hostile tasks are contained: one escapes to
  COM1, one forges an IRQ ack, one calls without the capability.

### Phase 5: services

- **Deferred replies (`FLAG_DEFER_REPLY`).** A server can wait for a
  kernel notice while its current caller stays blocked. During that time
  the endpoint answers new callers with `NO_RECEIVER` instead of letting
  them displace the pending caller. This lets a driver block a reader
  until data exists, with no busy waiting.
- **serial-service:** the COM3 console driver (IRQ 4), which feeds the
  shell.
- **ramfs:** 8 files of 4 KiB each over IPC. Every descriptor, offset and
  length is checked. A hostile `fs-fuzzer` sends 8 malformed requests;
  all 8 are rejected and the service keeps serving.
- **netsvc:** loopback UDP-style datagrams with RFC 1071 checksums. A
  physical NIC needs DMA, which stays denied until per-device IOMMU
  mappings exist.
- **shell:** holds only SEND capabilities to the console, filesystem and
  network endpoints. In CI it runs a script typed through COM3 (QEMU
  `input-path`): `help`, `echo`, `write`, `cat`, `ls`, `net`, `bench`,
  `exit`.
- **IPC benchmark:** 1000 null round trips to ramfs, measured with RDTSC.

## Consequences and limits (honest status)

- Benchmark figures come from QEMU TCG emulation (tens of thousands of
  TSC cycles per round trip) and do not represent hardware. They should
  be repeated under KVM and on physical hardware.
- None of this was tested on physical hardware: this environment only
  has QEMU (BIOS, UEFI, UEFI Secure Boot, `-smp 4`, `intel-iommu`).
- Endpoints carry no sender identity (badges). ramfs and netsvc cannot
  tell clients apart, so any holder of a SEND capability sees every file
  and every bound port. Badged endpoints, or one endpoint per client
  handed out by init, are the next step.
- The scheduler idles with `sti; hlt` only while a driver waits for
  hardware and non-service work remains, with a bound of 500 wake-ups.
