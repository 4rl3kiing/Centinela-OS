#!/usr/bin/env bash
# Boots the ISO under BIOS and UEFI (plus a feature-rich CPU model) and asserts
# that every bootstrap milestone was reached and that no failure was reported.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ISO="build/centinela-os.iso"
QEMU="${QEMU:-qemu-system-x86_64}"
TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-20}"
test -f "$ISO" || { echo "ISO not found: $ISO (run scripts/build-iso.sh)" >&2; exit 1; }
command -v "$QEMU" >/dev/null || { echo "QEMU not found: $QEMU" >&2; exit 1; }
mkdir -p build/logs

REQUIRED_MESSAGES=(
    "Centinela-OS: Rust kernel entry reached."
    "CPU hardening: NXE enabled."
    "CPU hardening: CR0.WP enabled."
    "Limine base revision 5 accepted."
    "VMM bootstrap: Limine page-table frames validated through HHDM."
    "VMM bootstrap: HHDM root alias and kernel RX mapping verified."
    "Kernel image: physical range verified against page tables."
    "Kernel image: KASLR virtual base"
    "PMM initialized: 4 KiB frames, 64 GiB address ceiling."
    "PMM allocation/free self-test passed."
    "Bootstrap milestone: memory map validated and PMM online."
    "Isolation: kernel stacks protected by unmapped guard pages."
    "Isolation: GDT/TSS loaded (IST for #DF, NMI, #MC; no I/O bitmap)."
    "Isolation: IDT loaded; all gates DPL 0; Ring 0 faults fail closed."
    "Isolation: SYSCALL gate armed (TF/IF/DF/AC/NT/IOPL masked)."
    "Isolation: legacy PIC IRQs masked; APIC timer watchdog armed."
    "Isolation: APIC timer calibrated against PIT:"
    "[task hello] hello from an isolated Ring 3 task .[2J"
    "[task hello] kernel pointer rejected with EFAULT"
    "Isolation: 12/12 tasks behaved as required; kernel still running."
    "Scheduler: preemptive time slicing verified (both CPU-bound tasks finished)."
    "Boot modules: 2 verified by the boot chain."
    "[task elf-hello] hello from a Rust ELF loaded from a verified boot module"
    "[task elf-hello] mapped 2 zeroed anonymous RW pages with MapMemory"
    "ELF loader: refused elf-wx: segment both writable and executable (W^X); nothing was mapped or executed."
    "ELF loader: verified (Rust ELF ran; W+X image refused)."
    "[task client] init granted a SEND-only adder capability (no GRANT)"
    "[task client] service replied 40 + 2 = 42"
    "[task init] kernel reports adder-service died; policy: restart"
    "Kernel: restarted adder-service at init's request (fresh memory and capabilities, restart 1/3)."
    "[task client] service crashed mid-request; kernel returned EPIPE"
    "[task client] service restarted by init replied 40 + 2 = 42"
    "[task init] ignored a forged service-death notice sent by a client"
    "Microkernel: 8/8 service-manager checks passed; kernel still running."
    "Microkernel milestone: Ring 3 init manages services through capability IPC and attenuated grants; every hostile task contained."
)

fail() {
    local log="$1" stderr="$2" message="$3"
    cat "$log" >&2 2>/dev/null || true
    cat "$stderr" >&2 2>/dev/null || true
    echo "$message" >&2
    exit 1
}

# run_and_check MODE [extra required message...] -- QEMU ARGS...
run_and_check() {
    local mode="$1"; shift
    local -a extra=()
    while [[ "$1" != "--" ]]; do extra+=("$1"); shift; done
    shift
    local log="build/logs/qemu-$mode.log"
    local stderr="build/logs/qemu-$mode.stderr"
    : >"$log"
    set +e
    timeout "$TIMEOUT_SECONDS" "$QEMU" -machine q35 -m 512M -display none -monitor none \
        -serial "file:$log" -no-reboot -no-shutdown "$@" >"$stderr" 2>&1
    local status=$?
    set -e
    # 124 = still halted when the timeout fired, which is the expected end state.
    if [[ "$status" -ne 124 && "$status" -ne 0 ]]; then
        fail "$log" "$stderr" "QEMU $mode exited with status $status"
    fi
    local message
    for message in "${REQUIRED_MESSAGES[@]}" "${extra[@]}"; do
        grep -Fq "$message" "$log" || fail "$log" "$stderr" "Missing for $mode boot: $message"
    done
    # Any kernel-reported failure or panic fails the run even if milestones passed.
    # Every "Centinela-OS: " line except the entry banner is an error report.
    if grep -E "PANIC|KERNEL TRAP|UNEXPECTED|LEAKED|could not run" "$log" >/dev/null \
        || grep -F "Centinela-OS: " "$log" | grep -vF "Centinela-OS: Rust kernel entry reached." >/dev/null; then
        fail "$log" "$stderr" "Kernel reported a failure during $mode boot"
    fi
    echo "PASS: $mode boot reached every bootstrap milestone"
}

run_and_check bios -- -cdrom "$ISO" -boot d

# A feature-rich CPU model exercises the SMEP/SMAP/UMIP enablement paths that
# the default QEMU CPU model does not advertise.
run_and_check bios-cpu-max \
    "CPU hardening: SMEP enabled." "CPU hardening: SMAP enabled." "CPU hardening: UMIP enabled." \
    -- -cpu max -cdrom "$ISO" -boot d

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
run_and_check uefi -- \
    -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,format=raw,file=build/OVMF_VARS.fd" \
    -cdrom "$ISO" -boot d

# KASLR: the three boots must not all share one kernel virtual base.
bases=$(grep -h -o "KASLR virtual base 0x[0-9a-f]*" build/logs/qemu-bios.log build/logs/qemu-bios-cpu-max.log build/logs/qemu-uefi.log | sort -u | wc -l)
if [[ "$bases" -lt 2 ]]; then
    echo "KASLR check failed: kernel virtual base did not change across boots" >&2
    exit 1
fi
echo "PASS: KASLR randomized the kernel base across boots ($bases distinct bases)"
