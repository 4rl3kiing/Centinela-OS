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

impl Syscall {
    /// Decodes a raw syscall number from Ring 3. Unknown numbers are `None`.
    pub const fn from_number(number: u64) -> Option<Self> {
        Some(match number {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::Open,
            3 => Self::Close,
            4 => Self::Exec,
            5 => Self::Socket,
            6 => Self::Connect,
            7 => Self::Accept,
            8 => Self::Send,
            9 => Self::Receive,
            10 => Self::MapMemory,
            11 => Self::CreateProcess,
            12 => Self::Exit,
            _ => return None,
        })
    }

    /// Capability a task must hold, in addition to the syscall policy, before
    /// this syscall is dispatched. `None` means the policy alone decides.
    pub const fn required_capability(self) -> Option<crate::capabilities::Capability> {
        use crate::capabilities::Capability;
        match self {
            Self::Read => Some(Capability::ReadConsole),
            Self::Write => Some(Capability::WriteConsole),
            Self::Open | Self::Close | Self::Exec => Some(Capability::AccessBlockDevices),
            Self::Socket | Self::Connect | Self::Accept | Self::Send | Self::Receive => {
                Some(Capability::AccessNetwork)
            }
            Self::MapMemory => Some(Capability::ManageMemory),
            Self::CreateProcess => Some(Capability::ManageProcesses),
            Self::Exit => None,
        }
    }
}

/// Why a syscall was refused. Every refusal is fatal for the calling task:
/// a task that probes outside its granted surface is treated as compromised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallViolation {
    UnknownSyscall(u64),
    DeniedByPolicy(Syscall),
    MissingCapability(Syscall),
}

/// Two independent checks (allow-list and capability) must both pass.
pub fn authorize(
    policy: &SyscallPolicy,
    capabilities: crate::capabilities::CapabilitySet,
    number: u64,
) -> Result<Syscall, SyscallViolation> {
    let syscall = Syscall::from_number(number).ok_or(SyscallViolation::UnknownSyscall(number))?;
    if !policy.allows(syscall) {
        return Err(SyscallViolation::DeniedByPolicy(syscall));
    }
    if let Some(required) = syscall.required_capability()
        && !capabilities.contains(required)
    {
        return Err(SyscallViolation::MissingCapability(syscall));
    }
    Ok(syscall)
}

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
            (1_u64 << (Syscall::Read as u8)) | (1_u64 << (Syscall::Exit as u8)),
        ));
        assert!(policy.allows(Syscall::Read));
        assert!(policy.allows(Syscall::Exit));
        assert!(!policy.allows(Syscall::Write));
        assert!(!policy.allows(Syscall::Exec));
    }

    #[test]
    fn authorization_requires_policy_and_capability() {
        use super::{SyscallViolation, authorize};
        use crate::capabilities::{Capability, CapabilitySet};

        let policy = SyscallPolicy::new(SyscallSet::from_bits(
            (1 << Syscall::Write as u8) | (1 << Syscall::Exit as u8) | (1 << Syscall::Socket as u8),
        ));
        let mut capabilities = CapabilitySet::EMPTY;
        capabilities.grant(Capability::WriteConsole);

        assert_eq!(authorize(&policy, capabilities, 1), Ok(Syscall::Write));
        assert_eq!(authorize(&policy, capabilities, 12), Ok(Syscall::Exit));
        assert_eq!(
            authorize(&policy, capabilities, 5),
            Err(SyscallViolation::MissingCapability(Syscall::Socket))
        );
        assert_eq!(
            authorize(&policy, capabilities, 11),
            Err(SyscallViolation::DeniedByPolicy(Syscall::CreateProcess))
        );
        assert_eq!(
            authorize(&policy, capabilities, 999),
            Err(SyscallViolation::UnknownSyscall(999))
        );
    }

    #[test]
    fn every_syscall_number_round_trips() {
        for number in 0..13 {
            let syscall = Syscall::from_number(number).expect("defined syscall");
            assert_eq!(syscall as u64, number);
        }
        assert_eq!(Syscall::from_number(13), None);
    }

    #[test]
    fn unknown_syscall_bits_are_discarded() {
        let set = SyscallSet::from_bits(u64::MAX);
        assert_eq!(set.bits(), SyscallSet::ALL.bits());
    }
}

#[cfg(kani)]
mod verification {
    use super::{SyscallPolicy, SyscallSet};

    #[kani::proof]
    fn restricting_policy_never_adds_syscall_permissions() {
        let initial_bits: u64 = kani::any();
        let restriction_bits: u64 = kani::any();
        let mut policy = SyscallPolicy::new(SyscallSet::from_bits(initial_bits));
        let before = policy.allowed().bits();

        policy.restrict_to(SyscallSet::from_bits(restriction_bits));
        let after = policy.allowed().bits();

        assert_eq!(after & !before, 0);
    }
}
