# Centinela-OS threat model

- **Status:** Living document (first version 2026-11-21)
- **Scope:** kernel, boot chain and Ring 3 services on x86_64
- **Related:** [ADR-0002](../decisions/0002-hybrid-microkernel.md), [ADR-0003](../decisions/0003-layer-isolation-zero-trust.md)

## Assets

| Asset | Why it matters |
|-------|----------------|
| Kernel integrity (code, page tables, capability tables) | Whoever controls Ring 0 controls every task |
| Task isolation (address spaces, capabilities) | One compromised service must not reach another |
| Boot chain (loader, config, kernel, modules) | A modified boot image bypasses every runtime control |
| Service availability | A failed or hostile task must not stop unrelated services |
| Confidentiality of task memory | Frames are reused across tasks |
| Audit trail (kernel log) | Operators must be able to trust what the kernel reports |

## Adversaries

| ID | Adversary | Capabilities assumed | In scope |
|----|-----------|----------------------|----------|
| A1 | Malicious or compromised Ring 3 task | Arbitrary code in its own address space; any syscall number and argument; any IPC it can name | Yes, primary |
| A2 | Compromised service (including init) | A1 plus the capabilities that service legitimately holds | Yes |
| A3 | Malicious IPC peer | Crafted messages, forged handles, capability-transfer abuse, fake notices | Yes |
| A4 | Attacker with offline disk access | Modify files in the boot image | Yes, with Secure Boot as the strong control |
| A5 | Malicious DMA-capable device | Read/write physical memory by DMA | Partially: IOMMU deny-by-default (phase 4) |
| A6 | Speculative-execution side channels | Meltdown/Spectre-class reads of mapped kernel memory | Partially: KPTI (phase 3) |
| A7 | Physical attacker with live access, firmware/SMM, hypervisor | Arbitrary | No (out of scope) |

## Trust boundaries and controls

| Boundary | Threats | Controls (implemented unless marked) |
|----------|---------|--------------------------------------|
| Firmware → loader → kernel | A4 tampering | BLAKE2b of kernel and modules in config; config hash enrolled in loaders; editor disabled; Secure Boot signing *(phase 3)* |
| Ring 3 → Ring 0 (syscall) | A1 privilege escalation, kernel memory read/write | Syscall allow-list **and** capability; violation kills the task; user pointers validated against the task tables and copied through kernel aliases; SYSRET/IRET only to canonical user RIP with fixed RFLAGS; SMEP/SMAP/UMIP/NX/WP |
| Ring 3 → Ring 0 (exceptions/interrupts) | A1 spoofed vectors, stack attacks | All gates DPL 0; IST stacks for #DF/NMI/#MC; guard pages on all kernel stacks; Ring 0 faults fail closed |
| Task ↔ task (memory) | A1/A2 cross-task reads, stale data | Per-task PML4; kernel half supervisor-only; frames zeroed before reuse; reclaim verified |
| Task ↔ task (IPC) | A3 forged handles, rights amplification, oversized messages, fake kernel notices | Table-tagged, generation-checked handles; GRANT-only attenuated transfer; 4-word register messages; kernel-origin flag only the kernel can set |
| Task ↔ CPU | A1 denial of service | Preemptive time slices and a per-task CPU budget *(phase 2)*; watchdog |
| Task ↔ hardware | A1/A2 direct device access | IOPL 0, no I/O bitmap; device MMIO kernel-only; drivers get only explicitly granted ports/IRQs *(phase 4)* |
| Device ↔ memory | A5 DMA attacks | IOMMU with deny-by-default *(phase 4)* |
| Kernel address-space layout | A1 exploitation reliability, A6 | KASLR and KPTI *(phase 3)* |

## Residual risks (accepted for now)

- No physical-hardware validation: all evidence is from QEMU (TCG).
- Single-CPU scheduling; SMP brings new concurrency attack surface.
- The kernel log is plain serial output; it is sanitized but not signed.
- No measured boot or remote attestation.
- Resource exhaustion inside a single service's own quota is the service's
  problem; system-wide memory pressure policy is not defined yet.

## Review rule

Every new mechanism must state which adversary it addresses, which boundary
it sits on, and how a boot-time or CI test demonstrates the control.
