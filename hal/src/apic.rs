//! Local APIC: per-CPU timer used as the kernel CPU-budget watchdog.
//!
//! The legacy 8259 PICs are remapped away from the exception vectors and fully
//! masked, so no legacy device interrupt can reach the kernel. The only
//! enabled interrupt source is the local APIC timer, which fires only while a
//! task runs (the kernel always executes with IF=0).

/// Vector of the local APIC timer interrupt.
pub const TIMER_VECTOR: u64 = 0x20;
/// Spurious-interrupt vector programmed into the APIC (must be ignored, no EOI).
pub const SPURIOUS_VECTOR: u64 = 0xff;
/// Vector at which a spurious master-PIC IRQ 7 would arrive after remapping.
pub const PIC_SPURIOUS_VECTOR: u64 = 0x2f;

pub const IA32_APIC_BASE: u32 = 0x1B;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
const APIC_BASE_MASK: u64 = 0x000f_ffff_ffff_f000;

pub const REG_TPR: usize = 0x80;
pub const REG_EOI: usize = 0xB0;
pub const REG_SVR: usize = 0xF0;
pub const REG_LVT_TIMER: usize = 0x320;
pub const REG_LVT_LINT0: usize = 0x350;
pub const REG_LVT_ERROR: usize = 0x370;
pub const REG_TIMER_INITIAL: usize = 0x380;
pub const REG_TIMER_DIVIDE: usize = 0x3E0;

#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const SVR_ENABLE: u32 = 1 << 8;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const LVT_MASKED: u32 = 1 << 16;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const TIMER_DIVIDE_BY_16: u32 = 0b0011;

/// LVT timer value: periodic mode on `TIMER_VECTOR`, unmasked.
pub const fn timer_lvt() -> u32 {
    LVT_TIMER_PERIODIC | TIMER_VECTOR as u32
}

/// Extracts the APIC MMIO physical base from an IA32_APIC_BASE value.
pub const fn base_from_msr(value: u64) -> u64 {
    value & APIC_BASE_MASK
}

#[cfg(target_os = "none")]
mod runtime {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    static MMIO_BASE: AtomicU64 = AtomicU64::new(0);

    fn read_apic_base_msr() -> u64 {
        let low: u32;
        let high: u32;
        // SAFETY: CPL 0; architectural MSR.
        unsafe {
            core::arch::asm!("rdmsr", in("ecx") IA32_APIC_BASE, out("eax") low, out("edx") high,
                options(nomem, nostack, preserves_flags));
        }
        (u64::from(high) << 32) | u64::from(low)
    }

    /// Physical address of this CPU's APIC MMIO page; enables the APIC
    /// globally if firmware left it disabled.
    pub fn physical_base() -> u64 {
        let value = read_apic_base_msr();
        if value & APIC_GLOBAL_ENABLE == 0 {
            let enabled = value | APIC_GLOBAL_ENABLE;
            // SAFETY: CPL 0; sets only the architectural global-enable bit.
            unsafe {
                core::arch::asm!("wrmsr", in("ecx") IA32_APIC_BASE,
                    in("eax") enabled as u32, in("edx") (enabled >> 32) as u32,
                    options(nostack, preserves_flags));
            }
        }
        base_from_msr(value)
    }

    fn write(register: usize, value: u32) {
        let base = MMIO_BASE.load(Ordering::Relaxed);
        // SAFETY: `init` stored a kernel mapping of the APIC page (uncached);
        // registers are 32-bit aligned within that page.
        unsafe { core::ptr::write_volatile((base as usize + register) as *mut u32, value) };
    }

    fn outb(port: u16, value: u8) {
        // SAFETY: CPL 0; fixed legacy PIC ports.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value,
                options(nomem, nostack, preserves_flags));
        }
    }

    /// Remaps both 8259 PICs to 0x28-0x37 and masks every legacy IRQ.
    fn mask_legacy_pics() {
        for (command, data, base, cascade) in
            [(0x20u16, 0x21u16, 0x28u8, 0x04u8), (0xA0, 0xA1, 0x30, 0x02)]
        {
            outb(command, 0x11);
            outb(data, base);
            outb(data, cascade);
            outb(data, 0x01);
            outb(data, 0xFF);
        }
    }

    /// Masks the legacy PICs and starts the periodic APIC timer.
    ///
    /// # Safety
    /// CPL 0, interrupts disabled, IDT loaded. `mmio_virtual` must be an
    /// uncached, writable, kernel-only mapping of `physical_base()` that
    /// stays mapped in every address space (kernel half).
    pub unsafe fn init(mmio_virtual: u64, initial_count: u32) {
        mask_legacy_pics();
        MMIO_BASE.store(mmio_virtual, Ordering::Relaxed);
        write(REG_TPR, 0);
        write(REG_LVT_LINT0, LVT_MASKED);
        write(REG_LVT_ERROR, LVT_MASKED);
        write(REG_SVR, SVR_ENABLE | SPURIOUS_VECTOR as u32);
        write(REG_TIMER_DIVIDE, TIMER_DIVIDE_BY_16);
        write(REG_LVT_TIMER, timer_lvt());
        write(REG_TIMER_INITIAL, initial_count);
    }

    /// Signals end of interrupt for the current APIC interrupt.
    pub fn end_of_interrupt() {
        write(REG_EOI, 0);
    }
}

#[cfg(target_os = "none")]
pub use runtime::{end_of_interrupt, init, physical_base};

#[cfg(test)]
mod tests {
    use super::{TIMER_VECTOR, base_from_msr, timer_lvt};

    #[test]
    fn timer_lvt_is_periodic_and_unmasked() {
        let lvt = timer_lvt();
        assert_eq!(u64::from(lvt & 0xff), TIMER_VECTOR);
        assert_ne!(lvt & (1 << 17), 0);
        assert_eq!(lvt & (1 << 16), 0);
    }

    #[test]
    fn extracts_mmio_base() {
        assert_eq!(base_from_msr(0xfee0_0900), 0xfee0_0000);
    }
}
