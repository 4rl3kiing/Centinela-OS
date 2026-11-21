//! Global Descriptor Table and Task State Segment.
//!
//! Layout (fixed by the SYSCALL/SYSRET selector arithmetic in `syscall.rs`):
//!
//! | Index | Selector | Descriptor                    |
//! |-------|----------|-------------------------------|
//! | 0     | 0x00     | null                          |
//! | 1     | 0x08     | kernel code (64-bit, DPL 0)   |
//! | 2     | 0x10     | kernel data (DPL 0)           |
//! | 3     | 0x1b     | user data (DPL 3)             |
//! | 4     | 0x23     | user code (64-bit, DPL 3)     |
//! | 5-6   | 0x28     | 64-bit available TSS          |
//!
//! Layer-isolation properties enforced here:
//! - The TSS has no I/O permission bitmap (`iomap_base` = TSS size), so with
//!   IOPL 0 every user-mode port access raises #GP.
//! - Ring transitions always land on a kernel-owned stack (`rsp0`), never on a
//!   stack the user controls.
//! - Double fault, NMI and machine check run on dedicated IST stacks, so a
//!   corrupted or exhausted kernel stack cannot turn into a silent triple fault
//!   and an NMI can never execute on a user-controlled stack.

pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
pub const USER_DATA_SELECTOR: u16 = 0x18 | 3;
pub const USER_CODE_SELECTOR: u16 = 0x20 | 3;
pub const TSS_SELECTOR: u16 = 0x28;

/// IST slot numbers (1-based, as encoded in IDT gates).
pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;

/// Application processors that receive their own GDT/TSS. CPUs beyond this
/// bound are never released from the bootloader's parking loop.
pub const MAX_APS: usize = 7;

// Raw descriptors are consumed only by the freestanding runtime.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const KERNEL_CODE: u64 = 0x00af_9a00_0000_ffff;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const KERNEL_DATA: u64 = 0x00cf_9200_0000_ffff;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const USER_DATA: u64 = 0x00cf_f200_0000_ffff;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const USER_CODE: u64 = 0x00af_fa00_0000_ffff;

/// 64-bit Task State Segment (Intel SDM Vol. 3A, Figure 8-11).
#[repr(C, packed(4))]
pub struct TaskStateSegment {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

pub const TSS_SIZE: usize = core::mem::size_of::<TaskStateSegment>();
const _: () = assert!(TSS_SIZE == 104);

impl TaskStateSegment {
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp: [0; 3],
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            // Offset beyond the segment limit: no I/O bitmap, all ports denied.
            iomap_base: TSS_SIZE as u16,
        }
    }

    pub fn rsp0(&self) -> u64 {
        self.rsp[0]
    }

    pub fn ist(&self, slot: u8) -> u64 {
        self.ist[usize::from(slot) - 1]
    }

    pub fn iomap_base(&self) -> u16 {
        self.iomap_base
    }
}

impl Default for TaskStateSegment {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes the two 8-byte halves of a 64-bit available-TSS descriptor.
pub const fn tss_descriptor(base: u64) -> (u64, u64) {
    let limit = (TSS_SIZE - 1) as u64;
    let low = (limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0x89 << 40) // present, DPL 0, type 0x9 (available 64-bit TSS)
        | (((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    (low, base >> 32)
}

/// Stack tops installed in the TSS.
#[derive(Clone, Copy, Debug)]
pub struct TssStacks {
    /// Kernel stack used when an interrupt or exception arrives from Ring 3.
    pub privilege0: u64,
    pub double_fault: u64,
    pub nmi: u64,
    pub machine_check: u64,
}

#[cfg(target_os = "none")]
mod runtime {
    use super::*;
    use core::ptr::addr_of_mut;

    // KPTI: the CPU reads the GDT and TSS on every ring transition, so they
    // live in the entry trampoline that stays mapped in task page tables.
    #[unsafe(link_section = ".data.entry")]
    static mut TSS: TaskStateSegment = TaskStateSegment::new();
    #[unsafe(link_section = ".data.entry")]
    static mut GDT: [u64; 7] = [0, KERNEL_CODE, KERNEL_DATA, USER_DATA, USER_CODE, 0, 0];

    #[repr(C, packed)]
    struct DescriptorTablePointer {
        limit: u16,
        base: u64,
    }

    // Application processors get private descriptor tables: a TSS holds the
    // per-CPU rsp0 and IST stacks and is marked busy by `ltr`, so sharing one
    // between CPUs is architecturally invalid. APs run Ring 3 tasks, so the
    // CPU reads these on ring transitions under task page tables: they live
    // in the KPTI trampoline like the BSP's.
    #[unsafe(link_section = ".data.entry")]
    static mut AP_TSS: [TaskStateSegment; MAX_APS] = [const { TaskStateSegment::new() }; MAX_APS];
    #[unsafe(link_section = ".data.entry")]
    static mut AP_GDT: [[u64; 7]; MAX_APS] =
        [[0, KERNEL_CODE, KERNEL_DATA, USER_DATA, USER_CODE, 0, 0]; MAX_APS];

    /// Installs the GDT and TSS and reloads every segment register.
    ///
    /// # Safety
    /// Must be called once, at CPL 0, with interrupts disabled, before the IDT
    /// is loaded. Every stack top must be 16-byte aligned, mapped, writable
    /// and reserved for its purpose for the lifetime of the kernel.
    pub unsafe fn init(stacks: TssStacks) {
        // SAFETY: Single-threaded bootstrap; no other reference to TSS/GDT exists.
        unsafe { load(addr_of_mut!(GDT), addr_of_mut!(TSS), stacks) }
    }

    /// Installs the private GDT/TSS of application processor `index`.
    /// Returns `false` (and loads nothing) if `index` is out of range.
    ///
    /// # Safety
    /// Same contract as [`init`], executed on the AP itself; each `index` must
    /// be used by exactly one CPU, exactly once.
    pub unsafe fn init_ap(index: usize, stacks: TssStacks) -> bool {
        if index >= MAX_APS {
            return false;
        }
        // SAFETY: Each index is owned by one AP (caller contract); raw element
        // pointers avoid creating references to the whole shared arrays.
        unsafe {
            let gdt = (addr_of_mut!(AP_GDT) as *mut [u64; 7]).add(index);
            let tss = (addr_of_mut!(AP_TSS) as *mut TaskStateSegment).add(index);
            load(gdt, tss, stacks);
        }
        true
    }

    /// # Safety
    /// `gdt` and `tss` must be valid, 'static, owned by the calling CPU.
    unsafe fn load(gdt: *mut [u64; 7], tss: *mut TaskStateSegment, stacks: TssStacks) {
        // SAFETY: Guaranteed by the caller.
        unsafe {
            let tss_ref = &mut *tss;
            tss_ref.rsp[0] = stacks.privilege0;
            tss_ref.ist[usize::from(IST_DOUBLE_FAULT) - 1] = stacks.double_fault;
            tss_ref.ist[usize::from(IST_NMI) - 1] = stacks.nmi;
            tss_ref.ist[usize::from(IST_MACHINE_CHECK) - 1] = stacks.machine_check;

            let (low, high) = tss_descriptor(tss as u64);
            let gdt_ref = &mut *gdt;
            gdt_ref[5] = low;
            gdt_ref[6] = high;

            let pointer = DescriptorTablePointer {
                limit: (core::mem::size_of::<[u64; 7]>() - 1) as u16,
                base: gdt as u64,
            };
            core::arch::asm!(
                "lgdt [{pointer}]",
                // Reload CS with a far return to the new kernel code selector.
                "push {code}",
                "lea {tmp}, [rip + 2f]",
                "push {tmp}",
                "retfq",
                "2:",
                "mov ds, {data:x}",
                "mov es, {data:x}",
                "mov ss, {data:x}",
                "xor {tmp:e}, {tmp:e}",
                "mov fs, {tmp:x}",
                "mov gs, {tmp:x}",
                "ltr {tss:x}",
                pointer = in(reg) &pointer,
                code = const KERNEL_CODE_SELECTOR as u64,
                data = in(reg) u64::from(KERNEL_DATA_SELECTOR),
                tss = in(reg) u64::from(TSS_SELECTOR),
                tmp = lateout(reg) _,
            );
        }
    }

    /// Updates the Ring 3 → Ring 0 stack (TSS.rsp0).
    ///
    /// # Safety
    /// `top` must be a 16-byte aligned, mapped, kernel-only stack top, and no
    /// interrupt may currently be executing on the previous rsp0 stack.
    pub unsafe fn set_privilege0_stack(top: u64) {
        let cpu = crate::syscall::cpu_index();
        // SAFETY: Guaranteed by the caller; each CPU writes only its own TSS
        // with interrupts disabled.
        unsafe {
            if cpu == 0 {
                (*addr_of_mut!(TSS)).rsp[0] = top;
            } else if cpu <= MAX_APS {
                (*(addr_of_mut!(AP_TSS) as *mut TaskStateSegment).add(cpu - 1)).rsp[0] = top;
            }
        }
    }
}

#[cfg(target_os = "none")]
pub use runtime::{init, init_ap, set_privilege0_stack};

#[cfg(test)]
mod tests {
    use super::{TSS_SIZE, TaskStateSegment, tss_descriptor};

    #[test]
    fn tss_has_no_io_bitmap() {
        let tss = TaskStateSegment::new();
        assert_eq!(usize::from(tss.iomap_base()), TSS_SIZE);
    }

    #[test]
    fn encodes_tss_descriptor_base_and_limit() {
        let (low, high) = tss_descriptor(0xffff_ffff_8012_3456);
        assert_eq!(low & 0xffff, (TSS_SIZE - 1) as u64);
        assert_eq!((low >> 16) & 0xff_ffff, 0x12_3456);
        assert_eq!((low >> 40) & 0xff, 0x89);
        assert_eq!((low >> 56) & 0xff, 0x80);
        assert_eq!(high, 0xffff_ffff);
    }
}
