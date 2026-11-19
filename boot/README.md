# Boot media

The kernel is configured to use the Limine boot protocol. The Limine entry expects
the kernel ELF at `/boot/centinela-kernel` on the boot volume.

This repository does not yet vendor Limine binaries or generate disk/ISO images.
That packaging step is intentionally separate from compiling the kernel so that
the bootloader release and its checksums can be pinned before producing images.

The first integration gate must create both BIOS and UEFI media from the same
kernel ELF, then boot each mode in QEMU and capture serial output. Do not treat
a successful Cargo build as proof of a successful firmware boot.
