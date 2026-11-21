# ADR-0005: Desktop-first roadmap to version 1.0

- Status: Accepted (2026-11-21)
- Scope: roadmap phases 6 to 12
- Builds on: ADR-0002 (hybrid microkernel), ADR-0003 (zero-trust layer
  isolation), ADR-0004 (SMP, IOMMU, Ring 3 drivers, first services)

## Context

Phases 1 to 5 delivered a capability microkernel validated in QEMU only:
Secure Boot, KASLR, KPTI, preemptive scheduling, ELF loading, SMP with
partitioned task systems, VT-d with per-device DMA domains, badged
endpoints with revocation, and Ring 3 drivers (UART, i8042 keyboard,
e1000). Userland is a serial shell over a RAM filesystem and a loopback
network service.

The owner decided that version 1.0 targets the **desktop from the start**,
not a server-first release. This ADR fixes what "1.0" means and the order
of the remaining work. The zero-trust rules of ADR-0003 apply to every
new component: drivers, the compositor and applications run in Ring 3,
start with no capabilities, and treat every other component as hostile.

## Definition of version 1.0

Version 1.0 is reached when all of the following hold on **two physical
reference machines** (one Intel with VT-d, one AMD with AMD-Vi), in
addition to the existing QEMU CI:

1. Installs to and boots from an internal NVMe or SATA disk with UEFI
   Secure Boot using the project's own production keys.
2. Shows a graphical login, authenticates a local user and starts a
   desktop session.
3. The desktop has windows, a mouse pointer and keyboard input (USB and
   PS/2), and ships a terminal, a file manager, a text editor and a
   settings application.
4. Files persist across reboots on a journaled filesystem; a power cut
   during writes does not corrupt metadata.
5. Wired networking works on real hardware with DHCP, DNS, TCP and TLS
   (enough for system updates).
6. System updates are signed and applied atomically (A/B), with rollback.
7. Every driver and service is in Ring 3 with an IOMMU domain where it
   does DMA; the hostile-task suites cover each new service boundary.
8. An external security review has been done and its high findings fixed.

### Explicitly out of scope for 1.0

GPU 3D acceleration, Wi-Fi, Bluetooth, a full web browser, laptop
suspend/resume and battery management, audio beyond basic HDA output,
and Linux binary compatibility. These are post-1.0 milestones.

## Phases

Each phase ends with QEMU CI evidence and, from phase 6 on, a log from at
least one physical reference machine.

### Phase 6: hardware bring-up and a visible console

- Framebuffer console from the Limine framebuffer (kernel log on screen,
  serial stays as the second sink). Required for any machine without COM1.
- Hardened kernel heap allocator (gate G4): size classes, guard regions,
  poisoning on free, no metadata inline with user-controlled data.
- AMD-Vi IOMMU with the same deny-by-default policy as VT-d.
- Interrupt remapping (VT-d and AMD-Vi) and MSI/MSI-X delivery to Ring 3
  drivers as kernel-origin notices. Needed by NVMe, xHCI and modern NICs.
- Wall clock (RTC/HPET), TSC calibration, ACPI reset and power-off.
- First physical boots on both reference machines following
  `docs/hardware-testing.md`.

### Phase 7: storage and persistence

- Ring 3 NVMe and AHCI drivers in their own DMA domains.
- Block service with per-client capabilities (no raw disk access for
  applications) and a VFS service that replaces ramfs as the namespace.
- Persistent journaled filesystem. **Open decision:** a new
  copy-on-write filesystem written for the project versus an existing
  design reimplemented in Rust (for example ext4 read/write subset). To be
  settled in its own ADR before code is written.
- Disk encryption hooks are designed in now; full-disk encryption itself
  may land after 1.0.

### Phase 8: process model and userland platform

- Processes started from the filesystem through init, from signed
  executables (signature checked by the loader, not by the caller).
- User threads, cross-CPU task migration and load balancing (the current
  partitioned model stays as the fallback).
- Shared-memory capabilities (grant pages between tasks with explicit
  rights), required by the compositor and by fast I/O paths.
- Rust `std` support for the Centinela target, plus a small C library for
  porting tools.
- Local users, password authentication service and per-application
  capability manifests (what an app may open, which services it may call).

### Phase 9: USB and input

- Ring 3 xHCI driver; USB HID keyboard and mouse; USB mass storage over
  the block service.
- Input service that owns all input devices and forwards events only to
  the focused client (no global keylogging by applications).

### Phase 10: graphics and desktop

- Display driver in Ring 3 over the UEFI GOP framebuffer (no GPU
  acceleration); virtio-gpu for QEMU.
- Compositor service: owns the screen, composes client surfaces received
  as shared-memory capabilities, draws the pointer and decorations, and
  is the only component that sees all windows.
- Window protocol over IPC, font rendering, a small widget toolkit.
- Login screen and session manager; applications: terminal, file manager,
  text editor, settings.
- Hostile-client tests: oversized surfaces, forged window IDs, input
  snooping, screen scraping of other clients.

### Phase 11: networking on real hardware

- Network stack as a Ring 3 service (IPv4/IPv6, TCP, UDP, DHCP, DNS).
  **Open decision:** adopt an existing `no_std` Rust stack versus writing
  one; settled in its own ADR.
- TLS client library for applications and the updater.
- Drivers for common wired NICs on the reference machines (Intel e1000e
  or igc, Realtek r8169), each in its own DMA domain.
- Per-application network capabilities (no ambient network access).

### Phase 12: release engineering

- Installer, partitioning and first-boot setup.
- Signed A/B updates with automatic rollback on failed boot.
- Production Secure Boot keys and key-handling procedure (test keys never
  leave CI).
- External security review, fix of high findings, release notes and a
  1.0 tag.

## Order and dependencies

```
6 hardware/console ─┬─> 7 storage ──> 8 processes ─┬─> 10 desktop ──> 12 release
                    ├─> 9 USB/input ───────────────┘          ^
                    └─> 11 network ───────────────────────────┘
```

Phase 6 comes first because nothing else can be verified on a real
machine without a screen and interrupt remapping. Phases 9 and 11 can run
in parallel with 7 and 8.

## Consequences

- The desktop target roughly doubles the remaining work compared with a
  server-first 1.0 (USB, input, compositor, toolkit, applications).
- Physical hardware becomes a hard requirement from phase 6; two reference
  machines with a serial port or serial-over-LAN must be available.
- Two design decisions (filesystem, network stack) are deliberately left
  open and must be closed by their own ADRs before implementation.

## Amendment (2026-11-21): code first, physical testing at the end

Approved by the owner. Everything that can be implemented and verified in
QEMU (TCG and KVM) is built first; physical-machine testing becomes one
campaign at the end, and the fixes that follow are driven by its results.
The approach keeps three conditions:

1. **No QEMU-only shortcuts.** Configuration comes from the same sources
   real firmware provides (ACPI tables, PCI configuration, the device's own
   capability registers), never from values that only hold in QEMU.
2. **Diagnosis built in.** Every boot prints an `HWREPORT` block (CPU, ACPI
   tables, every PCI function and whether it has a driver), and the
   installer keeps its log, so that one physical test boot gives enough
   information to plan the corrections.
3. **Several configurations in CI.** Intel and AMD IOMMUs, BIOS and UEFI,
   different devices and memory sizes.

Accepted risk: problems that only real hardware shows (firmware quirks,
device variety, timing) surface late, in one batch, and are fixed in a
dedicated round after the campaign.
