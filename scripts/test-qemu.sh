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
    "Framebuffer console: online (readback verified)."
    "VMM hardening: HHDM sealed non-executable"
    "Power: ACPI S5 available"
    "Clock: wall time "
    "IOMMU: interrupt remapping enabled (remappable format only; compatibility format blocked)."
    "Kernel heap: hardened slab allocator online (canaries, poisoning, randomized slots)."
    "CPU hardening: NXE enabled."
    "CPU hardening: CR0.WP enabled."
    "SMP: 3 application processors online (isolated, parked"
    "IOMMU: DMA remapping enabled on 1 unit(s), deny-by-default"
    "Drivers: 5/5 Ring 3 driver checks passed"
    "Services: 5/5 checks passed"
    "Capabilities: 5/5 badge and revocation checks passed."
    "Network: 2/2 DMA driver checks passed; out-of-domain DMA blocked by the IOMMU."
    "SMP: CPU 1 ran 5/5 tasks on its own scheduler"
    "SMP: application processor 1 ran its own task partition concurrently with the BSP."
    "[task e1000-driver] e1000: link up; ARP reply from 10.0.2.2 at 52:55:0a:00:02:02"
    "block written and read back (IOMMU-confined DMA)"
    "Storage: 1/1 NVMe driver checks passed; out-of-domain DMA blocked by the IOMMU."
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
    "Boot modules: 13 verified by the boot chain."
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

# KVM=1: hardware virtualization (real CPU execution, timing and SMP
# concurrency). Logs get a "kvm-" prefix so TCG and KVM results coexist.
ACCEL=()
P=""
if [[ "${KVM:-0}" == "1" ]]; then
    test -w /dev/kvm || { echo "KVM=1 but /dev/kvm is not accessible" >&2; exit 1; }
    ACCEL=(-accel kvm,kernel-irqchip=split)
    P="kvm-"
fi

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

# Scratch disk for the NVMe driver scenario (contents are not preserved).
NVME_IMAGE=build/nvme.img
dd if=/dev/zero of="$NVME_IMAGE" bs=1M count=4 status=none

# run_and_check MODE [extra required message...] -- QEMU ARGS...
run_and_check() {
    local mode="$1"; shift
    local -a extra=()
    while [[ "$1" != "--" ]]; do extra+=("$1"); shift; done
    shift
    local log="build/logs/qemu-$P$mode.log"
    local stderr="build/logs/qemu-$P$mode.stderr"
    : >"$log"
    set +e
    timeout "$TIMEOUT_SECONDS" "$QEMU" -machine q35 -m 512M -smp 4 "${ACCEL[@]}" -device intel-iommu,intremap=on -device e1000,netdev=n0 -netdev user,id=n0 \
        -drive "file=$NVME_IMAGE,if=none,id=nvm,format=raw" -device nvme,serial=centinela,drive=nvm -display none -monitor none \
        -serial "file:$log" -serial null \
        -chardev "file,id=shellin,path=/dev/null,input-path=$SHELL_INPUT" -serial chardev:shellin \
        -fw_cfg name=opt/centinela/poweroff,string=1 \
        -no-reboot "$@" >"$stderr" 2>&1
    local status=$?
    set -e
    # 0 = the kernel powered off (ACPI S5) after the self-test; 124 = still
    # halted when the timeout fired (no S5 support).
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

# Screen console: boot once more with a monitor socket, wait for the final
# milestone, take a screendump and decode the framebuffer text cells.
screen_check() {
    local log="build/logs/qemu-${P}screen.log" sock="build/qemu-monitor.sock"
    local shot="build/logs/${P}screen.ppm"
    rm -f "$sock" "$shot"
    : >"$log"
    # Same machine as the other boots, minus the fw_cfg power-off request,
    # so the final screen stays up for the screendump.
    "$QEMU" -machine q35 -m 512M -smp 4 "${ACCEL[@]}" -device intel-iommu,intremap=on \
        -device e1000,netdev=n0 -netdev user,id=n0 \
        -drive "file=$NVME_IMAGE,if=none,id=nvm,format=raw" -device nvme,serial=centinela,drive=nvm \
        -display none -monitor "unix:$sock,server,nowait" \
        -serial "file:$log" -serial null \
        -chardev "file,id=shellin,path=/dev/null,input-path=$SHELL_INPUT" -serial chardev:shellin \
        -no-reboot -no-shutdown -cdrom "$ISO" -boot d >/dev/null 2>&1 &
    local pid=$!
    local waited=0
    until grep -Fq "Microkernel milestone:" "$log" || ((waited >= TIMEOUT_SECONDS * 2)); do
        sleep 1
        waited=$((waited + 1))
    done
    python3 - "$sock" "$shot" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
time.sleep(0.5)
s.sendall(f"screendump {sys.argv[2]}\n".encode())
time.sleep(2)
s.close()
PY
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    test -s "$shot" || fail "$log" /dev/null "screendump was not produced"
    python3 scripts/check-screen.py "$shot" \
        "Microkernel milestone: Ring 3 init manages services" || fail "$log" /dev/null "screen console check failed"
}
screen_check

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
    log=build/logs/qemu-${P}uefi-secureboot-wrongkey.log
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
bases=$(grep -h -o "KASLR virtual base 0x[0-9a-f]*" "build/logs/qemu-${P}bios.log" "build/logs/qemu-${P}bios-cpu-max.log" "build/logs/qemu-${P}uefi.log" | sort -u | wc -l)
if [[ "$bases" -lt 2 ]]; then
    echo "KASLR check failed: kernel virtual base did not change across boots" >&2
    exit 1
fi
echo "PASS: KASLR randomized the kernel base across boots ($bases distinct bases)"
