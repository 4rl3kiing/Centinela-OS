# ADR-0003: Zero-trust layer isolation for the microkernel foundation

- **Status:** Accepted
- **Date:** 2026-11-21
- **Builds on:** [ADR-0002](0002-hybrid-microkernel.md)

## Context

ADR-0002 set a capability-based hybrid microkernel as the target, with Ring 0
limited to privileged mechanisms. Before services can move to Ring 3, the
kernel needs hardware protection layers and a rule for how layers treat each
other when one of them is attacked or compromised.

## Decision

Every layer distrusts the layers around it. A failure or attack is contained
in the layer where it happens, and nothing is trusted because of where it
comes from.

| Layer | Distrusts | Enforcement |
|-------|-----------|-------------|
| Boot chain | Disk contents | BLAKE2b of kernel in config; config hash enrolled in BIOS/UEFI loaders; editor disabled |
| CPU | Kernel stacks, user flags | GDT/TSS with IST stacks for #DF/NMI/#MC; guard pages on every kernel stack, including the kernel's own execution stack; SFMASK clears TF/IF/DF/AC/NT/IOPL |
| Kernel ↔ itself | Its own state after a fault | Any exception in Ring 0 halts with diagnostics (fail closed); NMI/#DF/#MC are never attributed to a task |
| Memory | Bootloader page tables, tasks | Per-task PML4; kernel half copied with USER stripped at the top level; empty user half per task; W^X; NX; NULL page unmappable for users; frames zeroed before use and reclaimed after |
| Kernel ↔ task | Every user value | Syscalls need policy **and** capability; any violation kills the task; user pointers validated against the task's own tables and read through kernel aliases (the kernel never dereferences user addresses, SMAP never relaxed); SYSRET only to canonical lower-half RIP with fixed RFLAGS; user text sanitized before logging |
| Task ↔ CPU time | Tasks that never yield | Local APIC timer watchdog with a per-task budget; legacy PIC IRQs fully masked |
| Task ↔ task (IPC) | Every other task, including services | Endpoint capabilities with separate SEND/RECEIVE rights; raw handles resolved only in the caller's table (table-tagged, generation-checked); messages bounded to 4 register words with unused words zeroed; capabilities can be passed only with GRANT and only attenuated (never more rights than held); a dead server wakes its caller with `EPIPE` |
| Kernel ↔ init | The service manager itself | Init holds restart policy, but restarts need ManageProcesses, a process capability with CONTROL, and stay within a kernel quota (3); death notices carry a kernel-origin flag that no task can set, so forged notices are recognizable |
| Task ↔ hardware | Direct device access | IOPL 0 and no TSS I/O bitmap (all ports #GP); all IDT gates DPL 0 (no `int n` spoofing); device MMIO mapped only kernel-only, uncached, NX |

Service policy (directory, restart decisions) lives in `init`, a Ring 3 task;
kernel policy lives in `kernel/src/isolation.rs` and `kernel/src/system.rs`; the mechanisms
live in the HAL (`gdt`, `idt`, `syscall`, `apic`) and memory modules
(`address_space`, `hhdm_backend`, `usercopy`).

## Verification

Every boot runs one benign task and eleven hostile tasks in Ring 3. Each must
end exactly as required and return all of its memory:

| Task | Attack | Required outcome |
|------|--------|------------------|
| hello | none; also passes a kernel pointer | exits 0; pointer gets EFAULT; escape codes neutralized |
| read-kernel | read kernel memory | killed by #PF |
| privileged | `mov rax, cr3` | killed by #GP |
| port-io | `out` to the serial port | killed by #GP |
| write-code | patch own code | killed by #PF (W^X) |
| exec-stack | run injected stack code | killed by #PF (NX) |
| fake-interrupt | `int 0x20` | killed by #GP (DPL 0 gate) |
| forbidden-syscall | syscall outside allow-list | killed (policy) |
| missing-capability | allowed syscall without capability | killed (capability) |
| unknown-syscall | undefined syscall number | killed |
| spin | infinite loop | killed by watchdog |
| stack-overflow | exhaust stack | killed by #PF on the unmapped page |

A second scenario runs `init` (Ring 3 service manager), an adder service
supervised by init, and six other tasks. The client starts with only a SEND
capability to init, receives a SEND-only (no GRANT) adder capability from it,
uses the service and then crashes it. The kernel wakes the client with
`EPIPE`, notifies init, and init requests the restart, which the kernel
performs within its quota; the next request succeeds. Hostile tasks forge a
death notice (init ignores it), try to re-grant a capability with more rights,
receive with a SEND-only capability, use a forged handle and send an oversized
message; all but the forger (which is simply ignored) are terminated.

CI boots BIOS, BIOS with `-cpu max` (SMEP/SMAP/UMIP) and UEFI and fails on any
unexpected outcome, leak, kernel trap or panic. Locally verified as well: a
kernel NULL dereference and a kernel stack overflow both halt with diagnostics
(the overflow lands in the guard page and is handled as a double fault on its
IST stack).

## Not yet covered (next milestones)

- Dynamic service registration and capability revocation trees (init's
  directory is static; restarts reuse the same program image).
- A preemptive scheduler (scheduling is IPC-driven; the watchdog terminates
  rather than preempts).
- SMP: per-CPU GDT/TSS/stacks and the TLB shootdown transport.
- ELF loading instead of embedded test programs.
- KPTI / speculative-execution mitigations: the supervisor-only kernel half is
  still mapped in task address spaces.
- Calibrated watchdog: the APIC timer budget is in uncalibrated ticks.
- IOMMU before any user-space driver gets DMA.

## Consequences

The kernel now has a real Ring 3 boundary that holds against direct attacks
on each layer, and every boot proves it. Tasks are deliberately killed on the
first violation; a later service manager decides restart policy. The local
APIC replaces the legacy PIC/PIT as the interrupt source, which is the path
needed for SMP anyway.
