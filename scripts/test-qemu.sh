#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ISO="build/centinela-os.iso"
QEMU="${QEMU:-qemu-system-x86_64}"
TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-20}"
test -f "$ISO"
command -v "$QEMU" >/dev/null
mkdir -p build/logs
run_and_check() {
    mode="$1"; shift
    log="build/logs/qemu-$mode.log"
    set +e
    timeout "$TIMEOUT_SECONDS" "$QEMU" -machine q35 -m 512M -display none -monitor none -serial "file:$log" -no-reboot -no-shutdown "$@" >"build/logs/qemu-$mode.stderr" 2>&1
    status=$?
    set -e
    if [[ "$status" -ne 124 && "$status" -ne 0 ]]; then cat "build/logs/qemu-$mode.stderr" >&2; echo "QEMU $mode exited with status $status" >&2; exit 1; fi
    grep -Fq "Centinela-OS: Rust kernel entry reached." "$log" || { cat "$log" >&2 || true; cat "build/logs/qemu-$mode.stderr" >&2 || true; echo "Kernel entry not found for $mode boot" >&2; exit 1; }
    grep -Fq "Limine base revision 5 accepted." "$log"
    grep -Fq "PMM initialized: 4 KiB frames, 64 GiB address ceiling." "$log" || { cat "$log" >&2; echo "PMM initialization not found for $mode boot" >&2; exit 1; }
    grep -Fq "PMM allocation/free self-test passed." "$log" || { cat "$log" >&2; echo "PMM self-test not found for $mode boot" >&2; exit 1; }
    echo "PASS: $mode boot reached Rust kernel and initialized PMM"
}
run_and_check bios -cdrom "$ISO" -boot d
OVMF_CODE="${OVMF_CODE:-}"
OVMF_VARS="${OVMF_VARS:-}"
if [[ -z "$OVMF_CODE" ]]; then
    for candidate in /usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/edk2/ovmf/OVMF_CODE.fd; do
        if [[ -f "$candidate" ]]; then OVMF_CODE="$candidate"; break; fi
    done
fi
if [[ -z "$OVMF_VARS" ]]; then
    for candidate in /usr/share/OVMF/OVMF_VARS.fd /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/edk2/ovmf/OVMF_VARS.fd; do
        if [[ -f "$candidate" ]]; then OVMF_VARS="$candidate"; break; fi
    done
fi
if [[ -z "$OVMF_CODE" || ! -f "$OVMF_CODE" || -z "$OVMF_VARS" || ! -f "$OVMF_VARS" ]]; then
    echo "OVMF CODE/VARS firmware pair not found. Set OVMF_CODE and OVMF_VARS." >&2
    exit 1
fi
cp "$OVMF_VARS" build/OVMF_VARS.fd
run_and_check uefi -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" -drive "if=pflash,format=raw,file=build/OVMF_VARS.fd" -cdrom "$ISO" -boot d
