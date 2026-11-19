# ADR-0001: x86_64 platform and BIOS/UEFI boot strategy

- **Status:** Accepted for initial implementation
- **Date:** 2026-11-19

## Context

Centinela-OS targets desktop and server systems and must boot on x86_64 machines using both legacy BIOS and UEFI. Implementing separate firmware loaders inside the kernel would add complexity unrelated to kernel mechanisms.

## Decision

1. Target x86_64 first.
2. Use Limine and its boot protocol as the initial boot handoff.
3. Produce testable BIOS and UEFI boot media.
4. Build the kernel as a freestanding ELF using Rust `no_std` and the `x86_64-unknown-none` target.
5. Keep bootloader-specific structures inside a boot adapter and convert them into kernel-owned boot information.
6. Use QEMU as the first integration environment; physical hardware validation follows.

## Rationale

Limine documents x86_64 support and BIOS/UEFI installation paths, including hybrid media. A common protocol lets the kernel share one entry and initialization path across both firmware modes. Rust's `x86_64-unknown-none` target is intended for freestanding x86-64 binaries and does not provide `std` or a default allocator, which matches a kernel's early execution environment.

## Consequences

- The kernel must validate all bootloader-provided data.
- Bootloader-reclaimable memory must not be reused until required data is copied and the memory map is normalized.
- The kernel must not depend on firmware services after the handoff unless an explicit runtime interface is designed.
- BIOS and UEFI images require separate boot integration tests.
- Limine version and protocol revision must be pinned and reviewed during implementation.

## References

- Limine boot protocol: https://github.com/limine-bootloader/limine-protocol/blob/trunk/PROTOCOL.md
- Limine usage (BIOS and UEFI): https://github.com/limine-bootloader/limine/blob/v12.x/USAGE.md
- Rust x86_64-unknown-none target: https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html
