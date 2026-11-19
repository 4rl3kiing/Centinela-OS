//! Monotonic syscall allow-list policy.
//!
//! A task may reduce its allowed syscall set after initialization, but this
//! policy type provides no operation that can restore a denied syscall.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Syscall {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Exec = 4,
    Socket = 5,
    Connect = 6,
    Accept = 7,
    Send = 8,
    Receive = 9,
    MapMemory = 10,
    CreateProcess = 11,
    Exit = 12,
}

const VALID_SYSCALL_BITS: u64 = (1 << 13) - 1;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyscallSet(u64);

impl SyscallSet {
    pub const EMPTY: Self = Self(0);
    pub const ALL: Self = Self(VALID_SYSCALL_BITS);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits & VALID_SYSCALL_BITS)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, syscall: Syscall) -> bool {
        self.0 & (1_u64 << syscall as u8) != 0
    }

    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn without(self, syscall: Syscall) -> Self {
        Self(self.0 & !(1_u64 << syscall as u8))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallPolicy {
    allowed: SyscallSet,
}

impl SyscallPolicy {
    /// Creates the initial allow-list assigned by the trusted process loader.
    pub const fn new(initial: SyscallSet) -> Self {
        Self { allowed: initial }
    }

    pub const fn allows(self, syscall: Syscall) -> bool {
        self.allowed.contains(syscall)
    }

    pub const fn allowed(self) -> SyscallSet {
        self.allowed
    }

    /// Permanently intersects the current policy with a narrower allow-list.
    pub fn restrict_to(&mut self, narrower: SyscallSet) {
        self.allowed = self.allowed.intersect(narrower);
    }

    /// Permanently denies one syscall.
    pub fn deny(&mut self, syscall: Syscall) {
        self.allowed = self.allowed.without(syscall);
    }
}

#[cfg(test)]
mod tests {
    use super::{Syscall, SyscallPolicy, SyscallSet};

    #[test]
    fn policy_can_only_be_restricted() {
        let mut policy = SyscallPolicy::new(SyscallSet::ALL);
        policy.deny(Syscall::Exec);
        policy.deny(Syscall::Open);

        assert!(!policy.allows(Syscall::Exec));
        assert!(!policy.allows(Syscall::Open));
        assert!(policy.allows(Syscall::Read));

        policy.restrict_to(SyscallSet::from_bits(
            (1 << Syscall::Read as u8) | (1 << Syscall::Exit as u8),
        ));
        assert!(policy.allows(Syscall::Read));
        assert!(policy.allows(Syscall::Exit));
        assert!(!policy.allows(Syscall::Write));
        assert!(!policy.allows(Syscall::Exec));
    }

    #[test]
    fn unknown_syscall_bits_are_discarded() {
        let set = SyscallSet::from_bits(u64::MAX);
        assert_eq!(set.bits(), SyscallSet::ALL.bits());
    }
}
