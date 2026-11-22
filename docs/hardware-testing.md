# Hardware testing procedure

Status: **not yet run on physical hardware.** Every result so far comes from
QEMU, both emulated (TCG) and hardware-virtualized (KVM, in CI), on Intel
VT-d and AMD-Vi, with NVMe and SATA disks. ADR-0005 (amendment) puts the
physical test campaign after everything that can be coded and tested in
emulation. This page is the procedure for that campaign.

## What you need

- An x86_64 machine with UEFI and an IOMMU (Intel VT-d or AMD-Vi), and an
  internal NVMe or SATA disk **whose contents may be erased**.
  If the machine has both, the installer uses the NVMe disk.
- A USB stick (it is erased).
- A phone camera. The log is shown on screen, and a serial port is optional:
  COM1 at 115200 8N1, captured with `picocom -b 115200 /dev/ttyUSB0 | tee centinela.log`.

## Steps

1. Build the ISO:
   `cargo build --workspace --target x86_64-unknown-none --release`, then
   `bash scripts/build-iso.sh`. CI also publishes the ISO as an artifact.
2. Write it to the USB stick (this **erases** the stick):
   `sudo dd if=build/centinela-os.iso of=/dev/sdX bs=4M conv=fsync status=progress`.
3. Set the firmware options:
   - Enable VT-d or AMD-Vi (IOMMU).
   - Disable Secure Boot for the first run. Alternatively, enroll your own
     keys; never enroll the TEST keys.
4. Live run: boot the stick and choose **"Centinela-OS (probar sin instalar)"**.
   Nothing is written to the internal disk. Photograph the `HWREPORT` block,
   which lists the CPU, the ACPI tables and every PCI device with its driver
   status, and the final summary lines.
5. Installation:
   1. Boot the stick again and choose **"Instalar Centinela-OS en el disco
      interno NVMe o SATA (BORRA TODO EL DISCO)"**.
   2. The installer writes a GPT, then a FAT32 EFI partition (160 MiB) with
      the loader, kernel and programs, and finally the CFS system partition.
   3. It ends with "Installer: done. Remove the installation media and reboot."
6. First boot from the disk: remove the stick and reboot. In the boot menu
   choose the internal disk if the firmware doesn't. The system mounts its
   CFS partition and prints "boot count now 1".

## Logs to send back

On every installed boot, the system saves its log to the EFI partition,
where any operating system can read it (it is plain FAT32):

| File | Contents |
|------|----------|
| `CENTINELA/INSTALL.TXT` | full installation log, including `HWREPORT` |
| `CENTINELA/BOOTLOG.TXT` | log of the latest boot from the disk (first 64 KiB) |

To read them from another system:

- **Linux:** mount the first partition of the disk, for example
  `sudo mount /dev/nvme0n1p1 /mnt`.
- **Windows:** assign the partition a drive letter with `diskpart`.

Send both files together with the photos of the live run. If the machine never
reaches the storage service, `BOOTLOG.TXT` stays blank (spaces). In that case
the photos and `INSTALL.TXT` are the evidence.

## Expected differences from QEMU

- **Shell:** the shell scenario reads its commands from COM3. Without COM3,
  the scheduler stops it after its bounded idle wait (about 5 s).
- **Network:** with no e1000 NIC, the network DMA scenario is skipped. Other
  NICs (e1000e, igb, Realtek) have no driver yet.
- **Keyboard:** the ECHO test needs an i8042 controller (PS/2 or USB legacy
  emulation). USB keyboards without legacy emulation are not driven yet
  (no xHCI driver).
- **Interrupts:** the disk drivers poll. MSI/MSI-X is not used yet.
- **Benchmarks:** cycle counts reflect the real CPU.

## Measured so far

| Environment | IPC round trip (TSC cycles) | Source |
|-------------|-----------------------------|--------|
| QEMU TCG (emulated) | about 30,000–66,000 | local and CI logs |
| QEMU KVM (hosted CI runner) | about 2,700 | CI run 44952478373 (KVM boot log) |
| Physical hardware | not measured | — |
