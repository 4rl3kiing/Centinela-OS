#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Build profile: dev (default, signing optional), test (signing required, test
# keys allowed) or production (signing and verification required, test keys
# rejected). See docs/security/secure-boot-keys.md.
PROFILE="${CENTINELA_PROFILE:-dev}"
case "$PROFILE" in
    dev|test|production) ;;
    *) echo "Invalid CENTINELA_PROFILE '$PROFILE' (use dev, test or production)" >&2; exit 1 ;;
esac
SIGN=0
[[ -n "${SB_SIGNING_KEY:-}" && -n "${SB_SIGNING_CERT:-}" ]] && SIGN=1
if [[ "$PROFILE" != dev ]]; then
    [[ "$SIGN" == 1 ]] || { echo "Profile '$PROFILE' requires SB_SIGNING_KEY and SB_SIGNING_CERT" >&2; exit 1; }
    test -f "$SB_SIGNING_KEY" && test -f "$SB_SIGNING_CERT" || { echo "Secure Boot key or certificate file not found" >&2; exit 1; }
    command -v sbsign >/dev/null || { echo "sbsign is required in profile '$PROFILE'" >&2; exit 1; }
fi
if [[ "$PROFILE" == production ]]; then
    command -v sbverify >/dev/null || { echo "sbverify is required in profile production" >&2; exit 1; }
    command -v openssl >/dev/null || { echo "openssl is required in profile production" >&2; exit 1; }
    CERT_SUBJECT="$(openssl x509 -in "$SB_SIGNING_CERT" -noout -subject 2>/dev/null)" \
        || { echo "Cannot read subject of $SB_SIGNING_CERT" >&2; exit 1; }
    [[ -n "$CERT_SUBJECT" ]] || { echo "Empty certificate subject" >&2; exit 1; }
    # scripts/secure-boot-keys.sh marks test certificates with this exact CN text.
    if [[ "$CERT_SUBJECT" == *"Centinela-OS TEST "* || "$CERT_SUBJECT" == *"(not for production)"* ]]; then
        echo "Refusing to sign a production image with a TEST certificate" >&2; exit 1
    fi
fi
echo "Build profile: $PROFILE (Secure Boot signing: $([[ "$SIGN" == 1 ]] && echo yes || echo no))"

# Signs an EFI binary in place and verifies it (sbverify is mandatory in production).
sign_efi() {
    sbsign --key "$SB_SIGNING_KEY" --cert "$SB_SIGNING_CERT" --output "$1.signed" "$1" >/dev/null
    mv "$1.signed" "$1"
    if command -v sbverify >/dev/null; then
        sbverify --cert "$SB_SIGNING_CERT" "$1" >/dev/null || { echo "Signature verification failed: $1" >&2; exit 1; }
    elif [[ "$PROFILE" == production ]]; then
        echo "sbverify missing; cannot verify $1" >&2; exit 1
    fi
}

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
SYSTEM_MODULES="elf-hello elf-wx uart-driver kbd-driver serial-service ramfs netsvc shell fs-fuzzer broker badge-client e1000-driver nvme-driver storage storage-client"
MODULE_LINES=""
for module in $SYSTEM_MODULES installer; do
    source="$ROOT/target/x86_64-unknown-none/release/$module"
    test -f "$source" || { echo "Missing user module: $module" >&2; exit 1; }
    install -m 0644 "$source" "$ISO_ROOT/boot/user/$module"
    module_b2sum="$(b2sum "$ISO_ROOT/boot/user/$module" | cut -d' ' -f1)"
    line="$(printf 'module_path: boot():/boot/user/%s#%s\nmodule_string: %s' "$module" "$module_b2sum" "$module")"
    [[ "$module" == installer ]] && INSTALLER_LINE="$line" || MODULE_LINES+="$line"$'\n'
done

# Installed system: the same entry and programs, without the installer.
INSTALLED_CONFIG="$ROOT/build/installed-limine.conf"
{ cat "$CONFIG"; printf '%s' "$MODULE_LINES"; } >"$INSTALLED_CONFIG"
INSTALLED_EFI="$ROOT/build/installed-BOOTX64.EFI"
install -m 0644 "$LIMINE_DIR/BOOTX64.EFI" "$INSTALLED_EFI"
"$LIMINE_DIR/limine" enroll-config --quiet "$INSTALLED_EFI" "$(b2sum "$INSTALLED_CONFIG" | cut -d' ' -f1)"
if [[ "$SIGN" == 1 ]]; then
    sign_efi "$INSTALLED_EFI"
fi
PAYLOAD_ARGS=("EFI/BOOT/BOOTX64.EFI=$INSTALLED_EFI" "boot/limine/limine.conf=$INSTALLED_CONFIG" \
    "boot/centinela-kernel=$ISO_ROOT/boot/centinela-kernel")
for module in $SYSTEM_MODULES; do
    PAYLOAD_ARGS+=("boot/user/$module=$ISO_ROOT/boot/user/$module")
done
python3 "$ROOT/scripts/pack-payload.py" "$ISO_ROOT/boot/user/install-payload" "${PAYLOAD_ARGS[@]}"
PAYLOAD_LINE="$(printf 'module_path: boot():/boot/user/install-payload#%s\nmodule_string: install-payload' \
    "$(b2sum "$ISO_ROOT/boot/user/install-payload" | cut -d' ' -f1)")"

# Installation media: two entries. The first runs the live system; the
# second installs it and states plainly that the disk will be erased.
HEADER="$(sed '/^\//,$d' "$CONFIG")"
BODY="$(sed '1,/^\//d' "$CONFIG")"
{
    printf '%s\n' "$HEADER"
    printf '/Centinela-OS (probar sin instalar)\n%s\n%s%s\n%s\n\n' "$BODY" "$MODULE_LINES" "$INSTALLER_LINE" "$PAYLOAD_LINE"
    printf '/Instalar Centinela-OS en el disco interno NVMe o SATA (BORRA TODO EL DISCO)\n%s\ncmdline: centinela.install=nvme-wipe\n%s%s\n%s\n' \
        "$BODY" "$MODULE_LINES" "$INSTALLER_LINE" "$PAYLOAD_LINE"
} >"$CONFIG.new"
mv "$CONFIG.new" "$CONFIG"
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

# Optional UEFI Secure Boot signing (after enrollment, which edits the binary).
# With Secure Boot active and a config hash enrolled, Limine panics on any
# config change or unhashed file, completing the chain of trust.
if [[ "$SIGN" == 1 ]]; then
    sign_efi "$ISO_ROOT/EFI/BOOT/BOOTX64.EFI"
    echo "Signed BOOTX64.EFI for UEFI Secure Boot"
fi

# UEFI CD boot runs the BOOTX64.EFI inside the El Torito FAT image, so the
# enrolled executable must also replace the copy in that image.
install -m 0644 "$LIMINE_DIR/limine-uefi-cd.bin" "$EFI_SYSTEM_IMAGE"
mcopy -o -i "$EFI_SYSTEM_IMAGE" "$ISO_ROOT/EFI/BOOT/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
if [[ "$PROFILE" == production ]]; then
    mcopy -n -i "$EFI_SYSTEM_IMAGE" ::/EFI/BOOT/BOOTX64.EFI "$ROOT/build/verify-BOOTX64.EFI"
    sbverify --cert "$SB_SIGNING_CERT" "$ROOT/build/verify-BOOTX64.EFI" >/dev/null || { echo "ESP image EFI is not signed" >&2; exit 1; }
    rm -f "$ROOT/build/verify-BOOTX64.EFI"
fi
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
