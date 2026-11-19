//! Explicit, least-privilege capability sets.

/// A kernel resource or operation that may be granted to a task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Capability {
    ReadConsole = 0,
    WriteConsole = 1,
    AccessBlockDevices = 2,
    AccessNetwork = 3,
    ManageProcesses = 4,
    ManageMemory = 5,
    LoadDrivers = 6,
    SystemAdministration = 7,
}

/// A compact set of granted capabilities.
///
/// This is a policy bitset, not a cryptographic token. Ownership and
/// authorization checks must be enforced by the subsystem consuming it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilitySet(u64);

impl CapabilitySet {
    pub const EMPTY: Self = Self(0);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & (1_u64 << capability as u8) != 0
    }

    pub fn grant(&mut self, capability: Capability) {
        self.0 |= 1_u64 << capability as u8;
    }

    pub fn revoke(&mut self, capability: Capability) {
        self.0 &= !(1_u64 << capability as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::{Capability, CapabilitySet};

    #[test]
    fn grants_and_revokes_individual_capabilities() {
        let mut set = CapabilitySet::EMPTY;
        set.grant(Capability::ReadConsole);
        set.grant(Capability::AccessNetwork);

        assert!(set.contains(Capability::ReadConsole));
        assert!(set.contains(Capability::AccessNetwork));
        assert!(!set.contains(Capability::SystemAdministration));

        set.revoke(Capability::AccessNetwork);
        assert!(!set.contains(Capability::AccessNetwork));
        assert!(set.contains(Capability::ReadConsole));
    }
}
