# Hardware testing procedure

Status: **not yet run on physical hardware.** Every result so far comes from
QEMU, both emulated (TCG) and hardware-virtualized (KVM, in CI). This page
describes how to run the same verification on a real machine.

## Requirements

- x86_64 machine with VT-x and VT-d (Intel) or AMD-V/AMD-Vi. The IOMMU code
  currently programs only Intel VT-d. On AMD the kernel boots with "no DMAR
  table" and DMA is not remapped.
- **A serial port (COM1, 0x3F8).** The kernel writes its whole log to COM1
  and has no framebuffer console yet. Without a serial port nothing is
  visible. Use a motherboard header, a PCIe serial card in legacy mode, or
  a machine with serial-over-LAN (IPMI/AMT).
- A null-modem cable to a second computer running a terminal at 115200 8N1,
  for example `picocom -b 115200 /dev/ttyUSB0 | tee centinela.log`.

## Steps

1. Build the ISO: `cargo build --workspace --target x86_64-unknown-none --release`,
   then `bash scripts/build-iso.sh`.
2. Write it to a USB stick (this **erases** the device):
   `sudo dd if=build/centinela-os.iso of=/dev/sdX bs=4M conv=fsync status=progress`.
3. Firmware settings: enable VT-d/IOMMU and the serial port; for a first
   run, disable Secure Boot (or enroll your own keys, never the TEST keys).
4. Boot from the USB stick and capture the serial log.
5. Check the log for the same milestones that `scripts/test-qemu.sh`
   requires (the `REQUIRED_MESSAGES` list) and for the absence of
   `PANIC`, `KERNEL TRAP`, `UNEXPECTED` or `LEAKED`.

## Expected differences from QEMU

- The shell scenario reads its commands from COM3. Without COM3 hardware the
  console service waits; the scheduler then stops it after its bounded idle
  wait (about 5 s), and the shell is reported as stopped.
- No e1000 NIC: the network DMA scenario is skipped ("no e1000 NIC present").
- The keyboard ECHO test needs an i8042 controller (PS/2 or USB legacy
  emulation).
- Benchmark cycles reflect the real CPU.

## Measured so far

| Environment | IPC round trip (TSC cycles) | Source |
|-------------|-----------------------------|--------|
| QEMU TCG (emulated) | about 30,000–66,000 | local and CI logs |
| QEMU KVM (hosted CI runner) | see the "measurements" summary of the CI run | CI |
| Physical hardware | not measured | — |
