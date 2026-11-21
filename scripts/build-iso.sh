#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LIMINE_VERSION="v12.9.6"
LIMINE_ARCHIVE="limine-binary.tar.gz"
LIMINE_URL="https://github.com/Limine-Bootloader/Limine/releases/download/$LIMINE_VERSION/$LIMINE_ARCHIVE"
LIMINE_SHA256="b38aabb042b0c0f9f562b7741be3c1204838d7bbacfa78bb411c674bd5b984ee"

for tool in cargo curl sha256sum b2sum xorriso make tar mcopy; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done
cargo build --release --target x86_64-unknown-none
mkdir -p build
curl --fail --location --retry 3 "$LIMINE_URL" --output "build/$LIMINE_ARCHIVE"
echo "$LIMINE_SHA256  build/$LIMINE_ARCHIVE" | sha256sum --check -
rm -rf build/limine-binary build/iso-root
tar -xzf "build/$LIMINE_ARCHIVE" -C build
make -C build/limine-binary

LIMINE_DIR="$ROOT/build/limine-binary"
ISO_ROOT="$ROOT/build/iso-root"
KERNEL="$ROOT/target/x86_64-unknown-none/release/centinela-kernel"
EFI_SYSTEM_IMAGE="$ROOT/build/limine-uefi-cd.bin"
for required in limine-bios.sys limine-bios-cd.bin limine-uefi-cd.bin BOOTX64.EFI; do
    test -s "$LIMINE_DIR/$required" || { echo "Missing or empty Limine release file: $required" >&2; exit 1; }
done
test -x "$LIMINE_DIR/limine"
test -f "$KERNEL"
mkdir -p "$ISO_ROOT/boot/limine" "$ISO_ROOT/EFI/BOOT"
install -m 0644 "$KERNEL" "$ISO_ROOT/boot/centinela-kernel"

# Bind the kernel to the config: Limine refuses to boot a kernel whose BLAKE2b
# does not match the hash appended to its path.
KERNEL_B2SUM="$(b2sum "$ISO_ROOT/boot/centinela-kernel" | cut -d' ' -f1)"
CONFIG="$ISO_ROOT/boot/limine/limine.conf"
sed "s|^path: boot():/boot/centinela-kernel\$|path: boot():/boot/centinela-kernel#$KERNEL_B2SUM|" \
    "$ROOT/boot/limine.conf" >"$CONFIG"
grep -Fq "centinela-kernel#$KERNEL_B2SUM" "$CONFIG" || { echo "Kernel hash was not injected into limine.conf" >&2; exit 1; }

# User programs travel as boot modules, each pinned by its BLAKE2b hash.
mkdir -p "$ISO_ROOT/boot/user"
for module in elf-hello elf-wx; do
    source="$ROOT/target/x86_64-unknown-none/release/$module"
    test -f "$source" || { echo "Missing user module: $module" >&2; exit 1; }
    install -m 0644 "$source" "$ISO_ROOT/boot/user/$module"
    module_b2sum="$(b2sum "$ISO_ROOT/boot/user/$module" | cut -d' ' -f1)"
    printf 'module_path: boot():/boot/user/%s#%s\nmodule_string: %s\n' "$module" "$module_b2sum" "$module" >>"$CONFIG"
done
chmod 0644 "$CONFIG"

# Bind the config to the bootloaders: enroll its BLAKE2b into the BIOS stage
# and the UEFI executable. With an enrolled hash the editor is disabled and,
# under UEFI Secure Boot, a modified config or unhashed path causes a panic.
CONFIG_B2SUM="$(b2sum "$CONFIG" | cut -d' ' -f1)"
install -m 0644 "$LIMINE_DIR/limine-bios.sys" "$ISO_ROOT/boot/limine/limine-bios.sys"
install -m 0644 "$LIMINE_DIR/limine-bios-cd.bin" "$ISO_ROOT/boot/limine/limine-bios-cd.bin"
install -m 0644 "$LIMINE_DIR/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/BOOTX64.EFI"
"$LIMINE_DIR/limine" enroll-config --quiet "$ISO_ROOT/boot/limine/limine-bios.sys" "$CONFIG_B2SUM"
"$LIMINE_DIR/limine" enroll-config --quiet "$ISO_ROOT/EFI/BOOT/BOOTX64.EFI" "$CONFIG_B2SUM"

# UEFI CD boot runs the BOOTX64.EFI inside the El Torito FAT image, so the
# enrolled executable must also replace the copy in that image.
install -m 0644 "$LIMINE_DIR/limine-uefi-cd.bin" "$EFI_SYSTEM_IMAGE"
mcopy -o -i "$EFI_SYSTEM_IMAGE" "$ISO_ROOT/EFI/BOOT/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
install -m 0644 "$EFI_SYSTEM_IMAGE" "$ISO_ROOT/boot/limine/limine-uefi-cd.bin"

# Pass the EFI FAT image as an explicit on-disk source for the appended GPT
# EFI System Partition. This avoids relying on xorriso to reopen the El Torito
# boot-image node while constructing the appended partition.
xorriso -as mkisofs -R -r -J \
    -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table \
    -hfsplus -apm-block-size 2048 \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part "$EFI_SYSTEM_IMAGE" --protective-msdos-label \
    "$ISO_ROOT" -o build/centinela-os.iso

"$LIMINE_DIR/limine" bios-install build/centinela-os.iso
echo "Created: build/centinela-os.iso"
