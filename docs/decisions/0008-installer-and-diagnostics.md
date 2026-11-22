# ADR-0008: Disk installer and boot diagnostics readable from any OS

- Status: **Accepted** (2026-11-21), under the owner-approved amendment to
  ADR-0005 ("code first, physical test campaign at the end")
- Builds on: ADR-0003 (zero-trust layers), ADR-0004 (IOMMU, Ring 3 drivers),
  ADR-0007 (CFS)

## Context

The physical test campaign needs two things. First, a way to put the system
on a real disk. Second, evidence from each machine even when there is no
serial port and nobody can watch the screen.

## Decision

1. **Installer as a Ring 3 task.**
   - The installer receives only what it needs:
     - the disk controller's MMIO;
     - IOMMU-confined DMA;
     - a read-only borrowed mapping of the signed install payload (CPKG).
   - It writes a GPT with two partitions:
     - an EFI system partition: FAT32, 160 MiB, holding the loader, the
       enrolled config, the kernel and the programs;
     - the CFS system partition.
   - It runs from a separate boot entry that says the disk will be erased.
2. **Safety rules.**
   - The installer refuses a non-blank disk unless that erase entry was
     chosen.
   - The storage service never formats a disk that is non-blank or damaged.
   - The NVMe driver's self-test saves and restores the sector it writes.
3. **Drivers.** NVMe and AHCI (SATA) sit behind one `Drive` interface, so the
   installer and the storage service are disk-agnostic. On AMD machines the
   kernel uses AMD-Vi with the same domain model as VT-d.
4. **Diagnostics.**
   - Every boot prints a `HWREPORT` block (CPU, ACPI tables, PCI devices
     and driver status). The kernel keeps the first 64 KiB of its log in
     memory.
   - A new `ReadLog` capability (syscall 20) lets a task copy that log.
     Only the installer and the storage service hold it.
   - The installer preallocates `CENTINELA/INSTALL.TXT` and
     `CENTINELA/BOOTLOG.TXT` on the ESP as contiguous files, and records
     the location of `BOOTLOG.TXT` in CFS.
   - On each installed boot, the storage service checks that location
     against the ESP in the GPT, then overwrites the file in place. The FAT
     is never edited.

## Consequences

- Any operating system can read the logs from a tester's machine.
- The diagnostic path writes only inside a preallocated file in the ESP,
  and only after a bounds check.
- The boot log is exposed to two trusted services only. It contains no
  secrets: it is the same text printed on screen.
- CI covers the whole path in QEMU:
  - installation to NVMe and to SATA;
  - host-side checks with `sgdisk`, `fsck.fat`, `mtype` and `cfs-tool`;
  - a UEFI boot from the installed disk;
  - the contents of both log files.
- Limits:
  - Logs beyond 64 KiB are truncated.
  - Only the latest boot is kept.
  - The CFS volume is capped at 256 MiB until the allocator scales.
