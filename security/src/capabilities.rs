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
    /// Ring 3 driver: mediated port I/O and interrupt acknowledgement.
    DeviceAccess = 7,
    /// Read the kernel's boot log (to save it for hardware diagnosis).
    ReadLog = 8,
}

const VALID_CAPABILITY_BITS: u64 = (1 << 9) - 1;

/// A compact set of granted capabilities.
///
/// This is a policy bitset, not a cryptographic token. Ownership and
/// authorization checks must be enforced by the subsystem consuming it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilitySet(u64);

impl CapabilitySet {
    pub const EMPTY: Self = Self(0);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits & VALID_CAPABILITY_BITS)
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
        assert!(!set.contains(Capability::ManageProcesses));

        set.revoke(Capability::AccessNetwork);
        assert!(!set.contains(Capability::AccessNetwork));
        assert!(set.contains(Capability::ReadConsole));
    }
}
