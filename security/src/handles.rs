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

/// A typed, opaque handle. Its generation prevents stale-handle reuse and its
/// table identifier prevents a handle minted by one table from resolving in
/// another table of the same type (cross-task confused-deputy attacks).
pub struct CapabilityHandle<T> {
    table_id: u32,
    slot: u16,
    generation: u32,
    marker: PhantomData<fn() -> T>,
}

impl<T> CapabilityHandle<T> {
    /// Opaque integer form handed to user mode: `generation << 16 | slot`.
    /// The table identifier is deliberately omitted; a raw handle can only be
    /// resolved against the table of the task that presents it.
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }
}

impl<T> Copy for CapabilityHandle<T> {}

impl<T> Clone for CapabilityHandle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> PartialEq for CapabilityHandle<T> {
    fn eq(&self, other: &Self) -> bool {
        self.table_id == other.table_id
            && self.slot == other.slot
            && self.generation == other.generation
    }
}

impl<T> Eq for CapabilityHandle<T> {}

impl<T> core::fmt::Debug for CapabilityHandle<T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CapabilityHandle")
            .field("table_id", &self.table_id)
            .field("slot", &self.slot)
            .field("generation", &self.generation)
            .finish()
    }
}

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
///
/// Every table must receive a unique `table_id` from the kernel object that
/// owns it (for example, the task ID); handles from other tables are rejected.
pub struct CapabilityTable<T, const N: usize> {
    table_id: u32,
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
    pub fn new(table_id: u32) -> Result<Self, TableError> {
        if N > u16::MAX as usize {
            return Err(TableError::CapacityTooLarge);
        }
        Ok(Self {
            table_id,
            slots: core::array::from_fn(|_| Slot::empty()),
        })
    }

    /// Interprets a user-supplied raw handle in this table's namespace. Any
    /// value is accepted here; forged or stale values fail validation later.
    pub const fn handle_from_raw(&self, raw: u64) -> CapabilityHandle<T> {
        CapabilityHandle {
            table_id: self.table_id,
            slot: raw as u16,
            generation: if raw >> 48 != 0 {
                0
            } else {
                (raw >> 16) as u32
            },
            marker: PhantomData,
        }
    }

    pub fn insert(&mut self, value: T, rights: Rights) -> Result<CapabilityHandle<T>, TableError> {
        if rights.is_empty() {
            return Err(TableError::EmptyRights);
        }

        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.value.is_none() && !slot.retired {
                slot.value = Some(value);
                slot.rights = rights;
                return Ok(CapabilityHandle {
                    table_id: self.table_id,
                    slot: index as u16,
                    generation: slot.generation,
                    marker: PhantomData,
                });
            }
        }

        Err(TableError::Full)
    }

    pub fn get(&self, handle: CapabilityHandle<T>, required: Rights) -> Result<&T, TableError> {
        let slot = self.validated_slot(handle)?;
        if required.is_empty() || !slot.rights.contains(required) {
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
        let required = required.union(Rights::WRITE);
        if !slot.rights.contains(required) {
            return Err(TableError::PermissionDenied);
        }
        slot.value.as_mut().ok_or(TableError::InvalidHandle)
    }

    pub fn remove(&mut self, handle: CapabilityHandle<T>) -> Result<T, TableError> {
        let slot = self.validated_slot_mut(handle)?;
        if !slot.rights.contains(Rights::CONTROL) {
            return Err(TableError::PermissionDenied);
        }
        let value = slot.value.take().ok_or(TableError::InvalidHandle)?;
        slot.rights = Rights::NONE;
        match slot.generation.checked_add(1) {
            Some(next) => slot.generation = next,
            None => slot.retired = true,
        }
        Ok(value)
    }

    fn validated_slot(&self, handle: CapabilityHandle<T>) -> Result<&Slot<T>, TableError> {
        if handle.table_id != self.table_id {
            return Err(TableError::InvalidHandle);
        }
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
        if handle.table_id != self.table_id {
            return Err(TableError::InvalidHandle);
        }
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
        let mut table = CapabilityTable::<u64, 4>::new(1).expect("valid capacity");
        let handle = table
            .insert(0xfeed, Rights::READ.union(Rights::WRITE))
            .expect("slot available");

        assert_eq!(
            *table.get(handle, Rights::READ).expect("read allowed"),
            0xfeed
        );
        assert_eq!(
            table.get(handle, Rights::CONTROL),
            Err(TableError::PermissionDenied)
        );
        assert_eq!(
            table.get(handle, Rights::NONE),
            Err(TableError::PermissionDenied)
        );
        assert_eq!(
            table.get_mut(handle, Rights::CONTROL),
            Err(TableError::PermissionDenied)
        );
        *table.get_mut(handle, Rights::WRITE).expect("write allowed") = 0xbeef;
        assert_eq!(
            *table.get(handle, Rights::READ).expect("read allowed"),
            0xbeef
        );
    }

    #[test]
    fn removed_handles_cannot_access_reused_slots() {
        let mut table = CapabilityTable::<u32, 1>::new(1).expect("valid capacity");
        let stale = table
            .insert(7, Rights::READ.union(Rights::CONTROL))
            .expect("slot available");
        assert_eq!(table.remove(stale), Ok(7));

        let fresh = table
            .insert(9, Rights::READ)
            .expect("slot was safely reused");
        assert_ne!(stale, fresh);
        assert_eq!(
            table.get(stale, Rights::READ),
            Err(TableError::InvalidHandle)
        );
        assert_eq!(*table.get(fresh, Rights::READ).expect("fresh handle"), 9);
    }

    #[test]
    fn handles_from_another_table_are_rejected() {
        let mut task_a = CapabilityTable::<u32, 1>::new(1).expect("valid capacity");
        let mut task_b = CapabilityTable::<u32, 1>::new(2).expect("valid capacity");
        let handle_a = task_a
            .insert(1, Rights::READ.union(Rights::CONTROL))
            .expect("slot available");
        task_b.insert(2, Rights::READ).expect("slot available");

        // Same slot and generation, different table: must not resolve.
        assert_eq!(
            task_b.get(handle_a, Rights::READ),
            Err(TableError::InvalidHandle)
        );
        assert_eq!(task_b.remove(handle_a), Err(TableError::InvalidHandle));
    }

    #[test]
    fn raw_handles_round_trip_and_forgeries_fail() {
        let mut table = CapabilityTable::<u32, 4>::new(7).expect("valid capacity");
        let handle = table.insert(5, Rights::READ).expect("slot available");
        let raw = handle.to_raw();
        assert_eq!(table.handle_from_raw(raw), handle);
        assert_eq!(
            *table.get(table.handle_from_raw(raw), Rights::READ).unwrap(),
            5
        );

        for forged in [0, 0xdead_beef, raw + 1, raw | (1 << 60), u64::MAX] {
            assert_eq!(
                table.get(table.handle_from_raw(forged), Rights::READ),
                Err(TableError::InvalidHandle)
            );
        }
    }

    #[test]
    fn empty_rights_and_full_tables_are_rejected() {
        let mut table = CapabilityTable::<u8, 1>::new(1).expect("valid capacity");
        assert_eq!(table.insert(1, Rights::NONE), Err(TableError::EmptyRights));
        table.insert(1, Rights::READ).expect("slot available");
        assert_eq!(table.insert(2, Rights::READ), Err(TableError::Full));
    }
}
