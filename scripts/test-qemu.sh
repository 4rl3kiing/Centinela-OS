#!/usr/bin/env bash
# Boots the ISO under BIOS and UEFI (plus a feature-rich CPU model) and asserts
# that every bootstrap milestone was reached and that no failure was reported.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ISO="build/centinela-os.iso"
QEMU="${QEMU:-qemu-system-x86_64}"
TIMEOUT_SECONDS="${BOOT_TIMEOUT_SECONDS:-30}"
test -f "$ISO" || { echo "ISO not found: $ISO (run scripts/build-iso.sh)" >&2; exit 1; }
command -v "$QEMU" >/dev/null || { echo "QEMU not found: $QEMU" >&2; exit 1; }
mkdir -p build/logs

REQUIRED_MESSAGES=(
    "Centinela-OS: Rust kernel entry reached."
    "CPU hardening: NXE enabled."
    "CPU hardening: CR0.WP enabled."
    "SMP: 3 application processors online (isolated, parked"
    "IOMMU: DMA remapping enabled on 1 unit(s), deny-by-default"
    "Drivers: 5/5 Ring 3 driver checks passed"
    "Services: 5/5 checks passed"
    "Capabilities: 5/5 badge and revocation checks passed."
    "Network: 2/2 DMA driver checks passed; out-of-domain DMA blocked by the IOMMU."
    "[task e1000-driver] e1000: link up; ARP reply from 10.0.2.2 at 52:55:0a:00:02:02"
    "[task shell] cat nota.txt: microkernel con capacidades"
    "[task shell] net: udp loopback echo 'ping' ok"
    "[task fs-fuzzer] fs-fuzzer: 8/8 malformed requests rejected by ramfs"
    "Limine base revision 5 accepted."
    "VMM bootstrap: Limine page-table frames validated through HHDM."
    "VMM bootstrap: HHDM root alias and kernel RX mapping verified."
    "Kernel image: physical range verified against page tables."
    "Kernel image: KASLR virtual base"
    "PMM initialized: 4 KiB frames, 64 GiB address ceiling."
    "PMM allocation/free self-test passed."
    "Bootstrap milestone: memory map validated and PMM online."
    "Isolation: kernel stacks protected by unmapped guard pages."
    "-page entry trampoline; kernel image and HHDM are unmapped."
    "Isolation: GDT/TSS loaded (IST for #DF, NMI, #MC; no I/O bitmap)."
    "Isolation: IDT loaded; all gates DPL 0; Ring 0 faults fail closed."
    "Isolation: SYSCALL gate armed (TF/IF/DF/AC/NT/IOPL masked)."
    "Isolation: legacy PIC IRQs masked; APIC timer watchdog armed."
    "Isolation: APIC timer calibrated against PIT:"
    "[task hello] hello from an isolated Ring 3 task .[2J"
    "[task hello] kernel pointer rejected with EFAULT"
    "Isolation: 12/12 tasks behaved as required; kernel still running."
    "Scheduler: preemptive time slicing verified (both CPU-bound tasks finished)."
    "Boot modules: 12 verified by the boot chain."
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

# Commands typed into the Ring 3 shell through COM3.
SHELL_INPUT=build/shell-input.txt
mkdir -p build
cat >"$SHELL_INPUT" <<'SHELL'
help
echo hola desde Centinela
write nota.txt microkernel con capacidades
cat nota.txt
ls
net
bench
exit
SHELL

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
    timeout "$TIMEOUT_SECONDS" "$QEMU" -machine q35 -m 512M -smp 4 -device intel-iommu -device e1000,netdev=n0 -netdev user,id=n0 -display none -monitor none \
        -serial "file:$log" -serial null \
        -chardev "file,id=shellin,path=/dev/null,input-path=$SHELL_INPUT" -serial chardev:shellin \
        -no-reboot -no-shutdown "$@" >"$stderr" 2>&1
    local status=$?
    set -e
    # 124 = still halted when the timeout fired, which is the expected end state.
    if [[ "$status" -ne 124 && "$status" -ne 0 ]]; then
        fail "$log" "$stderr" "QEMU $mode exited with status $status"
    fi
    local message
    for message in "${REQUIRED_MESSAGES[@]}" "${extra[@]}"; do
        grep -Fq -- "$message" "$log" || fail "$log" "$stderr" "Missing for $mode boot: $message"
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

# UEFI Secure Boot (optional): the signed image must boot with our keys
# enrolled, and must be refused when the firmware trusts a different db key.
if [[ "${SECURE_BOOT_TEST:-0}" == "1" ]]; then
    SB_CODE="${OVMF_SECBOOT_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}"
    KEYS="${SB_KEY_DIR:-build/sb-keys}"
    command -v virt-fw-vars >/dev/null || { echo "virt-fw-vars required for SECURE_BOOT_TEST" >&2; exit 1; }
    test -f "$SB_CODE" || { echo "Secure Boot OVMF not found: $SB_CODE" >&2; exit 1; }
    OWNER=8be4df61-93ca-11d2-aa0d-00e098032b8c
    sb_vars() {
        virt-fw-vars --input "$OVMF_VARS" --output "$2" --set-pk "$OWNER" "$KEYS/PK.crt" \
            --add-kek "$OWNER" "$KEYS/KEK.crt" --add-db "$OWNER" "$KEYS/$1.crt" --no-microsoft --sb >/dev/null
    }
    SB_MACHINE=(-machine q35,smm=on -global driver=cfi.pflash01,property=secure,value=on)
    sb_vars db build/OVMF_VARS.secboot.fd
    run_and_check uefi-secureboot -- "${SB_MACHINE[@]}" \
        -drive "if=pflash,format=raw,readonly=on,file=$SB_CODE" \
        -drive "if=pflash,format=raw,file=build/OVMF_VARS.secboot.fd" \
        -cdrom "$ISO" -boot d
    sb_vars wrong-db build/OVMF_VARS.wrongkey.fd
    log=build/logs/qemu-uefi-secureboot-wrongkey.log
    : >"$log"
    set +e
    timeout "$TIMEOUT_SECONDS" "$QEMU" "${SB_MACHINE[@]}" -m 512M -display none -monitor none \
        -serial "file:$log" -no-reboot -no-shutdown \
        -drive "if=pflash,format=raw,readonly=on,file=$SB_CODE" \
        -drive "if=pflash,format=raw,file=build/OVMF_VARS.wrongkey.fd" \
        -cdrom "$ISO" -boot d >/dev/null 2>&1
    set -e
    if grep -Fq "Centinela-OS: Rust kernel entry reached." "$log"; then
        echo "Secure Boot check failed: image signed by an untrusted key was executed" >&2
        exit 1
    fi
    echo "PASS: Secure Boot refused the image under an untrusted db key"
fi

# KASLR: the three boots must not all share one kernel virtual base.
bases=$(grep -h -o "KASLR virtual base 0x[0-9a-f]*" build/logs/qemu-bios.log build/logs/qemu-bios-cpu-max.log build/logs/qemu-uefi.log | sort -u | wc -l)
if [[ "$bases" -lt 2 ]]; then
    echo "KASLR check failed: kernel virtual base did not change across boots" >&2
    exit 1
fi
echo "PASS: KASLR randomized the kernel base across boots ($bases distinct bases)"
