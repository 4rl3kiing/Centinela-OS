//! Fixed-capacity, typed object-capability handles.
//!
//! Handles are opaque generation-tagged references into a task-owned table.
//! They are not cryptographic tokens: the table is the authority boundary and
//! must remain private to the owning task/kernel subsystem.

use core::marker::PhantomData;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rights(u16);

impl Rights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const CONTROL: Self = Self(1 << 2);
    pub const MAP: Self = Self(1 << 3);
    pub const CONNECT: Self = Self(1 << 4);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// A typed, opaque handle. Its generation prevents stale-handle reuse.
pub struct CapabilityHandle<T> {
    slot: u16,
    generation: u32,
    marker: PhantomData<fn() -> T>,
}

impl<T> Copy for CapabilityHandle<T> {}

impl<T> Clone for CapabilityHandle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> PartialEq for CapabilityHandle<T> {
    fn eq(&self, other: &Self) -> bool {
        self.slot == other.slot && self.generation == other.generation
    }
}

impl<T> Eq for CapabilityHandle<T> {}

struct Slot<T> {
    generation: u32,
    rights: Rights,
    value: Option<T>,
    retired: bool,
}

impl<T> Slot<T> {
    const fn empty() -> Self {
        Self {
            generation: 1,
            rights: Rights::NONE,
            value: None,
            retired: false,
        }
    }
}

/// A no-allocation capability table for one resource type.
pub struct CapabilityTable<T, const N: usize> {
    slots: [Slot<T>; N],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    CapacityTooLarge,
    Full,
    EmptyRights,
    InvalidHandle,
    PermissionDenied,
}

impl<T, const N: usize> CapabilityTable<T, N> {
    pub fn new() -> Result<Self, TableError> {
        if N > u16::MAX as usize {
            return Err(TableError::CapacityTooLarge);
        }
        Ok(Self {
            slots: core::array::from_fn(|_| Slot::empty()),
        })
    }

    pub fn insert(
        &mut self,
        value: T,
        rights: Rights,
    ) -> Result<CapabilityHandle<T>, TableError> {
        if rights.is_empty() {
            return Err(TableError::EmptyRights);
        }

        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.value.is_none() && !slot.retired {
                slot.value = Some(value);
                slot.rights = rights;
                return Ok(CapabilityHandle {
                    slot: index as u16,
                    generation: slot.generation,
                    marker: PhantomData,
                });
            }
        }

        Err(TableError::Full)
    }

    pub fn get(
        &self,
        handle: CapabilityHandle<T>,
        required: Rights,
    ) -> Result<&T, TableError> {
        let slot = self.validated_slot(handle)?;
        if !slot.rights.contains(required) {
            return Err(TableError::PermissionDenied);
        }
        slot.value.as_ref().ok_or(TableError::InvalidHandle)
    }

    pub fn get_mut(
        &mut self,
        handle: CapabilityHandle<T>,
        required: Rights,
    ) -> Result<&mut T, TableError> {
        let slot = self.validated_slot_mut(handle)?;
        if !slot.rights.contains(required) {
            return Err(TableError::PermissionDenied);
        }
        slot.value.as_mut().ok_or(TableError::InvalidHandle)
    }

    pub fn remove(&mut self, handle: CapabilityHandle<T>) -> Result<T, TableError> {
        let slot = self.validated_slot_mut(handle)?;
        let value = slot.value.take().ok_or(TableError::InvalidHandle)?;
        slot.rights = Rights::NONE;
        match slot.generation.checked_add(1) {
            Some(next) => slot.generation = next,
            None => slot.retired = true,
        }
        Ok(value)
    }

    fn validated_slot(&self, handle: CapabilityHandle<T>) -> Result<&Slot<T>, TableError> {
        let slot = self
            .slots
            .get(handle.slot as usize)
            .ok_or(TableError::InvalidHandle)?;
        if slot.generation != handle.generation || slot.value.is_none() || slot.retired {
            return Err(TableError::InvalidHandle);
        }
        Ok(slot)
    }

    fn validated_slot_mut(
        &mut self,
        handle: CapabilityHandle<T>,
    ) -> Result<&mut Slot<T>, TableError> {
        let slot = self
            .slots
            .get_mut(handle.slot as usize)
            .ok_or(TableError::InvalidHandle)?;
        if slot.generation != handle.generation || slot.value.is_none() || slot.retired {
            return Err(TableError::InvalidHandle);
        }
        Ok(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::{CapabilityTable, Rights, TableError};

    #[test]
    fn typed_handles_enforce_rights() {
        let mut table = CapabilityTable::<u64, 4>::new().expect("valid capacity");
        let handle = table
            .insert(0xfeed, Rights::READ.union(Rights::WRITE))
            .expect("slot available");

        assert_eq!(*table.get(handle, Rights::READ).expect("read allowed"), 0xfeed);
        assert_eq!(
            table.get(handle, Rights::CONTROL),
            Err(TableError::PermissionDenied)
        );
        *table
            .get_mut(handle, Rights::WRITE)
            .expect("write allowed") = 0xbeef;
        assert_eq!(*table.get(handle, Rights::READ).expect("read allowed"), 0xbeef);
    }

    #[test]
    fn removed_handles_cannot_access_reused_slots() {
        let mut table = CapabilityTable::<u32, 1>::new().expect("valid capacity");
        let stale = table
            .insert(7, Rights::READ)
            .expect("slot available");
        assert_eq!(table.remove(stale), Ok(7));

        let fresh = table
            .insert(9, Rights::READ)
            .expect("slot was safely reused");
        assert_ne!(stale, fresh);
        assert_eq!(table.get(stale, Rights::READ), Err(TableError::InvalidHandle));
        assert_eq!(*table.get(fresh, Rights::READ).expect("fresh handle"), 9);
    }

    #[test]
    fn empty_rights_and_full_tables_are_rejected() {
        let mut table = CapabilityTable::<u8, 1>::new().expect("valid capacity");
        assert_eq!(table.insert(1, Rights::NONE), Err(TableError::EmptyRights));
        table.insert(1, Rights::READ).expect("slot available");
        assert_eq!(table.insert(2, Rights::READ), Err(TableError::Full));
    }
}
