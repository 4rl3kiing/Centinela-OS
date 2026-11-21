//! Feature-detected x86_64 hardware random-number instructions.
//!
//! These methods expose raw RDRAND/RDSEED samples only. They are not a
//! complete kernel entropy pool or a cryptographic random-number generator.
//! Callers must mix independent entropy sources and handle instruction failure.

use core::sync::atomic::{AtomicU8, Ordering};

const RDRAND_RETRIES: usize = 10;
const RDSEED_RETRIES: usize = 10;

/// Cached CPUID result: 0 = not yet probed, otherwise FEATURES_PROBED | bits.
static FEATURE_CACHE: AtomicU8 = AtomicU8::new(0);
const FEATURES_PROBED: u8 = 1 << 7;
const FEATURE_RDRAND: u8 = 1 << 0;
const FEATURE_RDSEED: u8 = 1 << 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuEntropyFeatures {
    pub rdrand: bool,
    pub rdseed: bool,
}

/// Detects hardware entropy instructions without executing them.
pub fn detect_cpu_entropy() -> CpuEntropyFeatures {
    // CPUID is available on x86_64.
    let basic = core::arch::x86_64::__cpuid(0);
    let leaf1 = if basic.eax >= 1 {
        core::arch::x86_64::__cpuid(1)
    } else {
        core::arch::x86_64::__cpuid(0)
    };
    let leaf7 = if basic.eax >= 7 {
        core::arch::x86_64::__cpuid_count(7, 0)
    } else {
        core::arch::x86_64::__cpuid(0)
    };

    decode_features(basic.eax, leaf1.ecx, leaf7.ebx)
}

fn decode_features(max_basic_leaf: u32, leaf1_ecx: u32, leaf7_ebx: u32) -> CpuEntropyFeatures {
    CpuEntropyFeatures {
        rdrand: max_basic_leaf >= 1 && leaf1_ecx & (1 << 30) != 0,
        rdseed: max_basic_leaf >= 7 && leaf7_ebx & (1 << 18) != 0,
    }
}

/// Returns cached entropy features, executing CPUID at most once per boot
/// (CPUID is serializing and traps to the hypervisor inside virtual machines).
fn cached_features() -> CpuEntropyFeatures {
    let cached = FEATURE_CACHE.load(Ordering::Relaxed);
    if cached & FEATURES_PROBED != 0 {
        return CpuEntropyFeatures {
            rdrand: cached & FEATURE_RDRAND != 0,
            rdseed: cached & FEATURE_RDSEED != 0,
        };
    }
    let features = detect_cpu_entropy();
    let mut bits = FEATURES_PROBED;
    if features.rdrand {
        bits |= FEATURE_RDRAND;
    }
    if features.rdseed {
        bits |= FEATURE_RDSEED;
    }
    FEATURE_CACHE.store(bits, Ordering::Relaxed);
    features
}

/// Rejects samples known to come from defective implementations: several AMD
/// generations returned all-ones with CF=1 after suspend/resume or with buggy
/// microcode. All-zeros is rejected for the same fail-closed reason.
const fn is_plausible_sample(value: u64) -> bool {
    value != 0 && value != u64::MAX
}

/// Returns one RDSEED sample, retrying a bounded number of times.
///
/// RDSEED can temporarily fail while its hardware conditioner is depleted.
/// Failure is represented as `None`; this function never spins indefinitely.
pub fn rdseed_u64() -> Option<u64> {
    if !cached_features().rdseed {
        return None;
    }

    for _ in 0..RDSEED_RETRIES {
        let value: u64;
        let ready: u8;
        // SAFETY: CPUID confirmed RDSEED support. The bounded retry handles CF=0.
        unsafe {
            core::arch::asm!(
                "rdseed {value}",
                "setc {ready}",
                value = out(reg) value,
                ready = out(reg_byte) ready,
                options(nomem, nostack)
            );
        }
        if ready != 0 && is_plausible_sample(value) {
            return Some(value);
        }
        core::hint::spin_loop();
    }

    None
}

/// Returns one RDRAND sample, retrying a bounded number of times.
///
/// RDRAND output must be mixed with other entropy sources before it is used
/// for security-sensitive key generation or address-space randomization.
pub fn rdrand_u64() -> Option<u64> {
    if !cached_features().rdrand {
        return None;
    }

    for _ in 0..RDRAND_RETRIES {
        let value: u64;
        let ready: u8;
        // SAFETY: CPUID confirmed RDRAND support. The bounded retry handles CF=0.
        unsafe {
            core::arch::asm!(
                "rdrand {value}",
                "setc {ready}",
                value = out(reg) value,
                ready = out(reg_byte) ready,
                options(nomem, nostack)
            );
        }
        if ready != 0 && is_plausible_sample(value) {
            return Some(value);
        }
        core::hint::spin_loop();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{CpuEntropyFeatures, decode_features, is_plausible_sample};

    #[test]
    fn rejects_stuck_hardware_samples() {
        assert!(!is_plausible_sample(u64::MAX));
        assert!(!is_plausible_sample(0));
        assert!(is_plausible_sample(0x1234_5678_9abc_def0));
    }

    #[test]
    fn detects_rdrand_and_rdseed_only_when_their_leaves_exist() {
        assert_eq!(
            decode_features(7, 1 << 30, 1 << 18),
            CpuEntropyFeatures {
                rdrand: true,
                rdseed: true,
            }
        );
        assert_eq!(
            decode_features(1, 1 << 30, 1 << 18),
            CpuEntropyFeatures {
                rdrand: true,
                rdseed: false,
            }
        );
        assert_eq!(
            decode_features(0, u32::MAX, u32::MAX),
            CpuEntropyFeatures {
                rdrand: false,
                rdseed: false,
            }
        );
    }
}
