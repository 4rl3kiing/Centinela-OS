# ADR-0006: Phase 6 hardware bring-up

- Status: Accepted (2026-11-21), phase partially complete
- Scope: roadmap phase 6 (ADR-0005)
- Builds on: ADR-0003, ADR-0004, ADR-0005

## Context

Phase 6 prepares the kernel for physical machines: something visible
without a serial port, a heap for later subsystems, power control, a wall
clock, and interrupt delivery that a DMA-capable device cannot forge.

## Decisions

### Framebuffer console

- The kernel log is mirrored to the first Limine framebuffer. Only 32-bit
  RGB buffers in the higher half are accepted. Geometry, pitch, size
  (at most 256 MiB) and colour fields are validated, both ends of the
  buffer must be mapped writable, and a glyph is drawn and read back
  before the console goes live. Any refusal leaves serial as the only sink.
- Glyphs: 8x8 Basic Latin and Latin-1 tables vendored from the `font8x8`
  crate (MIT, derived from a public-domain font) as constant data, drawn
  as 8x16 cells. No build-time dependency.
- Drawing happens under the existing console lock, so lines from
  different CPUs never interleave.

### Kernel heap (gate G4)

- Slab allocator over 4 KiB frames with size classes 32–4096 bytes.
- Metadata is out of line (descriptor table outside heap pages); each
  slot ends in a canary (`secret ^ address`) checked on free; freed slots
  are poisoned and the poison is verified on reuse; double, invalid,
  misaligned and wrong-size frees are detected; slot choice is random;
  allocations are zeroed and released pages are wiped.
- Detected corruption halts the kernel. Requests over 4 KiB return null.
- Not usable from interrupt handlers (kernel code runs with IF=0).

### HHDM sealed non-executable (security fix)

- Limine maps its direct map writable **and executable**, and the kernel
  runs on Limine's tables. Every upper-half top-level slot except the
  kernel image's now gets NX, and the result is read back.
- Ordering constraint found in testing: parked APs execute Limine's wait
  loop from the HHDM, so the seal runs right after `smp::start` moves
  them into kernel code, before any task runs.

### ACPI power control

- FADT and the DSDT `\_S5` object are parsed defensively (host tests with
  hostile AML). PM1a/PM1b control ports, the ACPI reset register and
  0xCF9 become kernel-owned: a driver grant that overlaps them is refused.
- The QEMU harness asks for power-off through the fw_cfg file
  `opt/centinela/poweroff`, read only when CPUID reports a hypervisor.
  Physical machines halt with the log on screen. Boot tests now end in
  S5 instead of waiting for their timeout.

### Wall clock

- CMOS RTC read until two snapshots agree; BCD/binary and 12/24-hour
  decoding with the FADT century register; impossible dates are refused.

### VT-d queued invalidation and interrupt remapping

- All invalidations (context cache, IOTLB, interrupt entry cache) go
  through the invalidation queue with wait descriptors.
- If every unit supports it, a 256-entry interrupt remapping table is
  enabled and compatibility-format interrupts stay blocked (CFIS checked
  clear). A device can raise only entries the kernel programmed; a forged
  MSI write is no longer an arbitrary interrupt. I/O APIC lines use the
  remappable format. Entries support source-id verification (SVT=01) for
  per-device MSI.

## Remaining in phase 6

- **AMD-Vi** (AMD IOMMU) with the same deny-by-default policy.
- **MSI/MSI-X** delivery to Ring 3 drivers (planned together with the NVMe
  driver in phase 7, which is the first device that needs it).
- Source-id verification for I/O APIC entries (needs DMAR device-scope
  parsing).
- **Physical boots** on the two reference machines (owner; cannot be done
  from CI).

## Verification

Host tests: framebuffer geometry and rendering, heap corruption cases,
FADT/DSDT parsing with hostile tables, RTC decoding. QEMU (BIOS, BIOS
`-cpu max`, UEFI, `-smp 4`, `intel-iommu,intremap=on`): new required
milestones for the console readback, HHDM seal, heap self-test, ACPI S5,
wall clock and interrupt remapping; the UART and keyboard IRQ tests pass
through the remapping table.
