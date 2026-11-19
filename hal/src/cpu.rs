//! x86_64 CPU control operations and boot-time hardening.

/// IA32_EFER model-specific register.
const IA32_EFER: u32 = 0xC000_0080;
const EFER_NXE: u64 = 1 << 11;

const CR4_UMIP: u64 = 1 << 11;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuHardening {
    pub nx: bool,
    pub umip: bool,
    pub smep: bool,
    pub smap: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuHardeningError {
    NxUnsupported,
    FeatureEnableFailed,
}

/// Detects supported CPU features and enables NXE, UMIP, SMEP and SMAP.
///
/// This must run in ring 0 during single-core bootstrap, before user mappings
/// or interrupt-driven concurrency are introduced. All existing mappings must
/// be supervisor mappings: SMAP intentionally blocks supervisor access to
/// user pages unless a future audited copyin/copyout path uses STAC/CLAC.
///
/// Unsupported optional CR4 features are left disabled. NX is mandatory and
/// failure to enable it aborts bootstrap.
pub fn enable_boot_hardening() -> Result<CpuHardening, CpuHardeningError> {
    // SAFETY: CPUID is available on all x86_64 processors.
    let basic = unsafe { core::arch::x86_64::__cpuid(0) };
    let leaf7_supported = basic.eax >= 7;
    let leaf7 = if leaf7_supported {
        // SAFETY: The maximum basic leaf advertises leaf 7.
        unsafe { core::arch::x86_64::__cpuid_count(7, 0) }
    } else {
        // No feature bits are advertised when the leaf is unavailable.
        unsafe { core::arch::x86_64::__cpuid(0) }
    };

    // SAFETY: Query the maximum supported extended CPUID leaf first.
    let extended = unsafe { core::arch::x86_64::__cpuid(0x8000_0000) };
    if extended.eax < 0x8000_0001 {
        return Err(CpuHardeningError::NxUnsupported);
    }
    // SAFETY: The maximum extended leaf confirms this leaf exists.
    let extended_features = unsafe { core::arch::x86_64::__cpuid(0x8000_0001) };
    let nx_supported = (extended_features.edx & (1 << 20)) != 0;
    if !nx_supported {
        return Err(CpuHardeningError::NxUnsupported);
    }

    // Enable execute-disable support before any page table uses the NX bit.
    let efer_low: u32;
    let efer_high: u32;
    // SAFETY: Reading IA32_EFER is a privileged operation in ring 0.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") IA32_EFER,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nomem, nostack, preserves_flags)
        );
    }
    let efer = (u64::from(efer_high) << 32) | u64::from(efer_low);
    let efer = efer | EFER_NXE;
    // SAFETY: Preserve all EFER bits and set only the architecturally defined NXE bit.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_EFER,
            in("eax") efer as u32,
            in("edx") (efer >> 32) as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
    let verified_efer_low: u32;
    let verified_efer_high: u32;
    // SAFETY: Read back the same privileged MSR to verify NXE became active.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") IA32_EFER,
            out("eax") verified_efer_low,
            out("edx") verified_efer_high,
            options(nomem, nostack, preserves_flags)
        );
    }
    let verified_efer = (u64::from(verified_efer_high) << 32) | u64::from(verified_efer_low);
    if verified_efer & EFER_NXE == 0 {
        return Err(CpuHardeningError::FeatureEnableFailed);
    }

    let mut cr4: u64;
    // SAFETY: Reading CR4 is a privileged operation in ring 0.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }

    let umip = leaf7_supported && (leaf7.ecx & (1 << 2)) != 0;
    let smep = leaf7_supported && (leaf7.ebx & (1 << 7)) != 0;
    let smap = leaf7_supported && (leaf7.ebx & (1 << 20)) != 0;
    if umip {
        cr4 |= CR4_UMIP;
    }
    if smep {
        cr4 |= CR4_SMEP;
    }
    if smap {
        cr4 |= CR4_SMAP;
    }

    // SAFETY: Only set CR4 feature bits advertised by CPUID; preserve other bits.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    let verified_cr4: u64;
    // SAFETY: Read back CR4 to confirm all advertised hardening bits were set.
    unsafe {
        core::arch::asm!(
            "mov {}, cr4",
            out(reg) verified_cr4,
            options(nomem, nostack, preserves_flags)
        );
    }
    let verified_umip = umip && verified_cr4 & CR4_UMIP != 0;
    let verified_smep = smep && verified_cr4 & CR4_SMEP != 0;
    let verified_smap = smap && verified_cr4 & CR4_SMAP != 0;
    if (umip && !verified_umip) || (smep && !verified_smep) || (smap && !verified_smap) {
        return Err(CpuHardeningError::FeatureEnableFailed);
    }

    Ok(CpuHardening {
        nx: true,
        umip: verified_umip,
        smep: verified_smep,
        smap: verified_smap,
    })
}

/// Disable maskable interrupts and halt the bootstrap processor forever.
///
/// This is intended for fatal boot and panic paths only. It must not be used
/// after a scheduler or interrupt-driven idle loop has been introduced.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: This function is called only from privileged kernel context.
        // Disabling interrupts before HLT ensures the bootstrap CPU stays halted.
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}
