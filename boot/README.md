# Boot media

Centinela-OS uses the Limine boot protocol for x86_64. The kernel requests base
revision 5, a 256 KiB bootstrap stack, the Higher Half Direct Map (HHDM), and the
physical memory map. The kernel checks that Limine accepted the requested base
revision before continuing.

## Pinned bootloader

The image builder uses Limine `v12.9.6` and verifies the SHA-256 digest of the
binary release archive before extraction:

`b38aabb042b0c0f9f562b7741be3c1204838d7bbacfa78bb411c674bd5b984ee`

The release binaries are not committed to this repository.

## Build a hybrid ISO

Install Rust with the `x86_64-unknown-none` target, plus `make`, a C compiler,
`xorriso`, `curl`, `tar`, and `sha256sum`. Then run:

```sh
bash scripts/build-iso.sh
```

The resulting image is `build/centinela-os.iso`. It contains the Limine BIOS
and UEFI boot files and the kernel at `/boot/centinela-kernel`.

## Boot validation

Install `qemu-system-x86` and OVMF firmware, then run:

```sh
bash scripts/test-qemu.sh
```

The test starts QEMU in legacy BIOS mode and UEFI mode, captures COM1 serial
output, and requires the kernel-entry and protocol-revision messages. Logs are
written to `build/logs/`.

A successful Cargo build or ISO creation alone is not proof of a successful
firmware boot. The milestone is complete only after both QEMU boot checks pass.
