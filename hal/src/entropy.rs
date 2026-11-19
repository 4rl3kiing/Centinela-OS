//! Feature-detected x86_64 hardware random-number instructions.
//!
//! These methods expose raw RDRAND/RDSEED samples only. They are not a
//! complete kernel entropy pool or a cryptographic random-number generator.
//! Callers must mix independent entropy sources and handle instruction failure.

const RDRAND_RETRIES: usize = 10;
const RDSEED_RETRIES: usize = 10;

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

fn decode_features(
    max_basic_leaf: u32,
    leaf1_ecx: u32,
    leaf7_ebx: u32,
) -> CpuEntropyFeatures {
    CpuEntropyFeatures {
        rdrand: max_basic_leaf >= 1 && leaf1_ecx & (1 << 30) != 0,
        rdseed: max_basic_leaf >= 7 && leaf7_ebx & (1 << 18) != 0,
    }
}

/// Returns one RDSEED sample, retrying a bounded number of times.
///
/// RDSEED can temporarily fail while its hardware conditioner is depleted.
/// Failure is represented as `None`; this function never spins indefinitely.
pub fn rdseed_u64() -> Option<u64> {
    if !detect_cpu_entropy().rdseed {
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
        if ready != 0 {
            return Some(value);
        }
    }

    None
}

/// Returns one RDRAND sample, retrying a bounded number of times.
///
/// RDRAND output must be mixed with other entropy sources before it is used
/// for security-sensitive key generation or address-space randomization.
pub fn rdrand_u64() -> Option<u64> {
    if !detect_cpu_entropy().rdrand {
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
        if ready != 0 {
            return Some(value);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{decode_features, CpuEntropyFeatures};

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
