# ADR-0007: Persistent filesystem for version 1.0

- Status: **Proposed** (2026-11-21), awaiting the owner's decision
- Scope: roadmap phase 7 (ADR-0005, open decision 1)
- Builds on: ADR-0003 (zero-trust layers), ADR-0005

## Context

Phase 7 needs a filesystem that keeps data across reboots and survives a
power cut during writes without metadata corruption (ADR-0005, 1.0
criterion 4). In Centinela-OS the filesystem runs as a Ring 3 service on
top of a block service; applications never see the disk. A filesystem
image can also arrive on removable media, so the parser must treat every
on-disk byte as hostile.

## Options

| | A. Own copy-on-write FS | B. ext4 subset in Rust | C. FAT32 only |
|---|---|---|---|
| Crash consistency | By design (CoW + atomic superblock switch) | Journal (jbd2), complex to get right | None |
| Interoperability | None (needs host tools we write) | Linux reads/writes it; mature fsck | Universal |
| Parser attack surface | Small, designed for validation | Large (extents, htree, journal, many feature flags) | Small |
| Effort to a safe 1.0 | Medium | High | Low |
| Integrity checks | Checksums on every block from day one | metadata_csum only if enabled | None |

## Recommendation

**Option A for the system and home volumes, plus read/write FAT32 for
removable media and the EFI system partition** (needed anyway for the
installer and firmware updates).

Reasons:
- Crash consistency and checksums are properties of the design instead of
  features bolted onto a large legacy format.
- The on-disk format can be kept small enough to validate completely and
  to fuzz in CI, which fits the zero-trust rule that the service distrusts
  the disk.
- ext4 interoperability is not a 1.0 requirement, and a partial ext4
  writer is a known source of corruption.

Sketch of option A (to be refined before code):
- 4 KiB blocks; two superblocks at fixed locations, alternating
  generation numbers; the newest one with a valid checksum wins.
- Every tree node and data extent carries a checksum (BLAKE2b-128 or
  CRC32C for data, BLAKE2b for metadata).
- Updates write new blocks and switch the superblock last; freed blocks
  are reclaimed only after the switch is durable (NVMe FLUSH).
- Hooks for per-volume encryption keys (full-disk encryption after 1.0).

## Consequences

- We must write mkfs, fsck and a host-side image tool (Rust, shared crate
  with the service).
- FAT32 support is still required for the EFI partition and USB sticks.

## Decision needed from the owner

Approve option A (recommended), choose B or C, or ask for a different
option. No filesystem code is written until this ADR is accepted.
