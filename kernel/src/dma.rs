//! DMA-isolation building blocks shared by the PCI, VT-d and AMD-Vi code.
//!
//! Nothing here touches hardware, so all of it runs in host tests: the lock
//! that serialises shared hardware state between CPUs, the ring protocol
//! that queues IOMMU commands and proves they completed, the command
//! encodings, and the rule for reaching a device behind PCI bridges.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// Spin lock for hardware state shared by every CPU (PCI configuration
/// ports, IOMMU command rings, IOMMU device tables).
///
/// Interrupts are disabled on the holding CPU while the lock is held and
/// restored afterwards, so a handler on the same CPU can never re-enter it.
/// The lock is not re-entrant: `f` must not take the same lock again.
pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: Every access to the inner value goes through `with`, which
// provides mutual exclusion with acquire/release ordering.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Runs `f` with exclusive access to the value, interrupts disabled.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let interrupts = disable_interrupts();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: The lock is held: no other reference to the value exists.
        let result = f(unsafe { &mut *self.value.get() });
        self.locked.store(false, Ordering::Release);
        restore_interrupts(interrupts);
        result
    }
}

/// Clears IF and reports whether it was set.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn disable_interrupts() -> bool {
    let flags: u64;
    // SAFETY: On this target the library only runs in the kernel (CPL 0).
    // Reading RFLAGS through the stack and clearing IF touches no other
    // state; the freestanding target has no red zone.
    unsafe {
        core::arch::asm!("pushfq", "pop {flags}", "cli", flags = out(reg) flags,
            options(nomem, preserves_flags));
    }
    flags & (1 << 9) != 0
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn restore_interrupts(enabled: bool) {
    if enabled {
        // SAFETY: CPL 0; restores the interrupt flag found on entry.
        unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)) };
    }
}

/// Host builds run tests in user mode: there is no interrupt flag to manage.
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
fn disable_interrupts() -> bool {
    false
}

#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
fn restore_interrupts(_: bool) {}

/// Entries in an IOMMU command ring: one 4 KiB page of 128-bit entries, on
/// both AMD-Vi (command buffer) and VT-d (invalidation queue).
pub const RING_ENTRIES: u64 = 256;

/// Hardware side of one IOMMU command ring. Indices are entry numbers below
/// [`RING_ENTRIES`].
pub trait CommandRing {
    /// Entry the hardware will fetch next.
    fn head(&mut self) -> u64;
    /// Stores one entry; the hardware does not see it until `publish`.
    fn store(&mut self, index: u64, entry: [u64; 2]);
    /// Orders the stores before the doorbell, then moves the hardware tail.
    fn publish(&mut self, tail: u64);
    /// Clears the completion word and returns the command that makes the
    /// hardware write `token` there once everything queued before it has
    /// completed (AMD-Vi COMPLETION_WAIT, VT-d wait descriptor).
    fn wait_command(&mut self, token: u32) -> [u64; 2];
    /// Current value of the completion word.
    fn completion(&mut self) -> u32;
    /// True while the hardware reports a queue error.
    fn faulted(&mut self) -> bool;
}

/// Software side of a ring; lives inside the unit's [`SpinLock`].
pub struct RingState {
    tail: u64,
    token: u32,
    /// Set by the first unconfirmed batch: later calls fail at once.
    dead: bool,
}

impl RingState {
    pub const fn new() -> Self {
        Self {
            tail: 0,
            token: 0,
            dead: false,
        }
    }

    /// The hardware tail was reset to entry 0 (unit initialisation).
    pub fn reset(&mut self) {
        self.tail = 0;
        self.dead = false;
    }

    /// True once a batch went unconfirmed (see [`submit`]).
    pub const fn is_dead(&self) -> bool {
        self.dead
    }
}

impl Default for RingState {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a batch of commands was not confirmed. In every case the caller must
/// assume the hardware may still use what the commands were meant to retire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingError {
    /// The batch (plus its wait command) can never fit in the ring.
    TooLarge,
    /// The hardware did not fetch enough earlier entries to make room.
    Full,
    /// The hardware reported a queue error.
    Fault,
    /// The wait command did not complete in time.
    Timeout,
    /// An earlier batch went unconfirmed: the unit is no longer trusted and
    /// nothing was queued.
    Dead,
}

/// Free entries of a ring in which `tail == head` means empty, so one entry
/// always stays unused. Out-of-range indices (a misbehaving unit) count as
/// a full ring.
pub const fn ring_free(head: u64, tail: u64) -> u64 {
    if head >= RING_ENTRIES || tail >= RING_ENTRIES {
        return 0;
    }
    (head + RING_ENTRIES - tail - 1) % RING_ENTRIES
}

/// Queues `commands` followed by a wait command and spins (bounded by
/// `poll_limit`) until the hardware confirms the whole batch completed.
///
/// Entries the hardware has not fetched yet (left behind by an earlier,
/// unconfirmed batch) are never overwritten: the call waits for room and
/// fails with [`RingError::Full`] otherwise. The caller must hold the unit's
/// lock so `state` and the ring are not shared with another CPU.
///
/// The first batch the hardware fails to confirm poisons the ring: every
/// later call returns [`RingError::Dead`] immediately, so a dead unit costs
/// its bounded waits once instead of on every operation (the callers hold
/// locks with interrupts disabled). Callers stay fail closed: nothing is
/// confirmed any more, so nothing is freed or granted through this unit.
pub fn submit<R: CommandRing>(
    ring: &mut R,
    state: &mut RingState,
    commands: &[[u64; 2]],
    poll_limit: u32,
) -> Result<(), RingError> {
    if state.dead {
        return Err(RingError::Dead);
    }
    let result = submit_once(ring, state, commands, poll_limit);
    state.dead = matches!(
        result,
        Err(RingError::Full | RingError::Fault | RingError::Timeout)
    );
    result
}

fn submit_once<R: CommandRing>(
    ring: &mut R,
    state: &mut RingState,
    commands: &[[u64; 2]],
    poll_limit: u32,
) -> Result<(), RingError> {
    let needed = commands.len() as u64 + 1;
    if needed > RING_ENTRIES - 1 {
        return Err(RingError::TooLarge);
    }
    let room = (0..poll_limit).any(|_| {
        let room = ring_free(ring.head(), state.tail) >= needed;
        if !room {
            core::hint::spin_loop();
        }
        room
    });
    if !room {
        return Err(RingError::Full);
    }
    // Zero is the cleared completion word, so it is never used as a token.
    state.token = match state.token.wrapping_add(1) {
        0 => 1,
        token => token,
    };
    let token = state.token;
    let wait = ring.wait_command(token);
    for entry in commands.iter().chain(core::iter::once(&wait)) {
        ring.store(state.tail, *entry);
        state.tail = (state.tail + 1) % RING_ENTRIES;
    }
    ring.publish(state.tail);
    for _ in 0..poll_limit {
        if ring.faulted() {
            return Err(RingError::Fault);
        }
        if ring.completion() == token {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(RingError::Timeout)
}

/// AMD-Vi command encodings (128-bit, opcode in bits 63:60 of the first
/// quadword).
pub mod amdvi {
    /// COMPLETION_WAIT with the store bit: the unit writes `data` to the
    /// 8-byte-aligned system physical address `store_address` after every
    /// earlier command has completed.
    pub const fn completion_wait(store_address: u64, data: u64) -> [u64; 2] {
        [
            0x1 << 60 | (store_address & 0x000f_ffff_ffff_fff8) | 1,
            data,
        ]
    }

    /// INVALIDATE_DEVTAB_ENTRY for one device ID.
    pub const fn invalidate_device(device_id: u16) -> [u64; 2] {
        [device_id as u64 | 0x2 << 60, 0]
    }

    /// INVALIDATE_IOMMU_PAGES for every page of a domain: address
    /// 0x7FFF_FFFF_FFFF_F000 with S = 1 and PDE = 1.
    pub const fn invalidate_domain(domain: u16) -> [u64; 2] {
        [
            (domain as u64) << 32 | 0x3 << 60,
            0x7fff_ffff_ffff_f000 | 0b11,
        ]
    }
}

/// VT-d queued-invalidation descriptor encodings.
pub mod vtd {
    /// Wait descriptor (type 5) with status write: the unit stores the
    /// 32-bit `token` at the 4-byte-aligned `status_address` after every
    /// earlier descriptor has completed.
    pub const fn wait(token: u32, status_address: u64) -> [u64; 2] {
        [5 | 1 << 5 | (token as u64) << 32, status_address]
    }
}

/// BIOS-to-OS hand-off of USB host controllers ("legacy USB support"). It
/// must happen before a controller loses Bus Master: firmware that still
/// owns a controller whose DMA stops can loop in SMM (SMI storm, hang).
pub mod usb {
    /// USBLEGSUP (xHCI extended capability 1, EHCI extended capability 1).
    pub const BIOS_OWNED: u32 = 1 << 16;
    pub const OS_OWNED: u32 = 1 << 24;
    /// xHCI USBLEGCTLSTS: bits kept when disabling every SMI source, and
    /// the write-one-to-clear SMI event bits.
    const XHCI_KEEP: u32 = (0x7 << 1) + (0xff << 5) + (0x7 << 17);
    const XHCI_SMI_EVENTS: u32 = 0x7 << 29;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Handoff {
        /// The firmware did not own the controller.
        NotOwned,
        /// The firmware released it after the request.
        Released,
        /// The firmware never released it; ownership was taken regardless.
        TimedOut,
    }

    /// Requests ownership through a USBLEGSUP register (`read`/`write`) and
    /// waits, bounded by `poll_limit` reads, for the firmware to let go.
    pub fn legacy_handoff(
        mut read: impl FnMut() -> u32,
        mut write: impl FnMut(u32),
        poll_limit: u32,
    ) -> Handoff {
        let value = read();
        write(value | OS_OWNED);
        if value & BIOS_OWNED == 0 {
            return Handoff::NotOwned;
        }
        for _ in 0..poll_limit {
            if read() & BIOS_OWNED == 0 {
                return Handoff::Released;
            }
            core::hint::spin_loop();
        }
        write((read() | OS_OWNED) & !BIOS_OWNED);
        Handoff::TimedOut
    }

    /// New xHCI USBLEGCTLSTS value: every SMI enable off, events cleared.
    pub const fn xhci_smi_disabled(control: u32) -> u32 {
        (control & XHCI_KEEP) | XHCI_SMI_EVENTS
    }

    /// Byte offset (from the MMIO base) of the xHCI USB Legacy Support
    /// capability, walking the extended capability list from HCCPARAMS1.
    /// `read` returns the dword at a byte offset, or `None` if unreachable.
    pub fn xhci_legacy_capability(
        hccparams1: u32,
        mut read: impl FnMut(u64) -> Option<u32>,
    ) -> Option<u64> {
        let mut offset = u64::from(hccparams1 >> 16) * 4;
        // The list is bounded: a looping or endless one is abandoned.
        for _ in 0..64 {
            if offset == 0 {
                return None;
            }
            let capability = read(offset)?;
            if capability & 0xff == 1 {
                return Some(offset);
            }
            let next = u64::from((capability >> 8) & 0xff) * 4;
            if next == 0 {
                return None;
            }
            offset += next;
        }
        None
    }

    /// Configuration-space offset of the EHCI USBLEGSUP capability, walking
    /// the EECP list from HCCPARAMS. `read` returns a config-space dword.
    pub fn ehci_legacy_capability(hccparams: u32, mut read: impl FnMut(u8) -> u32) -> Option<u8> {
        let mut offset = ((hccparams >> 8) & 0xff) as u8;
        for _ in 0..16 {
            // Extended capabilities live above the standard header.
            if offset < 0x40 || offset & 3 != 0 || offset > 0xf8 {
                return None;
            }
            let capability = read(offset);
            if capability & 0xff == 1 {
                return Some(offset);
            }
            offset = ((capability >> 8) & 0xff) as u8;
        }
        None
    }
}

/// True if a PCI function with this header type and bus-number registers is
/// a PCI-PCI bridge on the path between `bus` and the root: its Bus Master
/// bit gates every DMA request (and MSI) coming from `bus`.
pub const fn bridge_forwards(header_type: u8, secondary: u8, subordinate: u8, bus: u8) -> bool {
    header_type & 0x7f == 1 && secondary != 0 && secondary <= bus && bus <= subordinate
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn spin_lock_serialises_concurrent_updates() {
        let lock = Arc::new(SpinLock::new((0u64, 0u64)));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let lock = Arc::clone(&lock);
                std::thread::spawn(move || {
                    for _ in 0..20_000 {
                        // An address/data pair like 0xCF8/0xCFC: both halves
                        // must come from the same holder.
                        lock.with(|pair| {
                            pair.0 += 1;
                            std::hint::black_box(&mut *pair);
                            pair.1 += 1;
                            assert_eq!(pair.0, pair.1);
                        });
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(lock.with(|pair| *pair), (80_000, 80_000));
    }

    const WAIT_MARK: u64 = 0xffff_0000_0000_0000;

    /// A unit that consumes the ring on every doorbell, or never (`stalled`).
    struct FakeUnit {
        slots: [[u64; 2]; RING_ENTRIES as usize],
        head: u64,
        tail: u64,
        completion: u32,
        stalled: bool,
        /// Models a unit whose completion word could not be cleared.
        sticky: bool,
        fault: bool,
        executed: Vec<[u64; 2]>,
    }

    impl FakeUnit {
        fn new() -> Self {
            Self {
                slots: [[0; 2]; RING_ENTRIES as usize],
                head: 0,
                tail: 0,
                completion: 0,
                stalled: false,
                sticky: false,
                fault: false,
                executed: Vec::new(),
            }
        }

        fn run(&mut self) {
            while self.head != self.tail {
                let entry = self.slots[self.head as usize];
                if entry[0] == WAIT_MARK {
                    self.completion = entry[1] as u32;
                } else {
                    self.executed.push(entry);
                }
                self.head = (self.head + 1) % RING_ENTRIES;
            }
        }
    }

    impl CommandRing for FakeUnit {
        fn head(&mut self) -> u64 {
            self.head
        }
        fn store(&mut self, index: u64, entry: [u64; 2]) {
            let pending = (self.tail + RING_ENTRIES - self.head) % RING_ENTRIES;
            let offset = (index + RING_ENTRIES - self.head) % RING_ENTRIES;
            assert!(
                offset >= pending,
                "entry {index} overwritten before the unit fetched it"
            );
            self.slots[index as usize] = entry;
        }
        fn publish(&mut self, tail: u64) {
            self.tail = tail;
            if !self.stalled {
                self.run();
            }
        }
        fn wait_command(&mut self, token: u32) -> [u64; 2] {
            if !self.sticky {
                self.completion = 0;
            }
            [WAIT_MARK, u64::from(token)]
        }
        fn completion(&mut self) -> u32 {
            self.completion
        }
        fn faulted(&mut self) -> bool {
            self.fault
        }
    }

    #[test]
    fn ring_free_keeps_one_entry_unused() {
        assert_eq!(ring_free(0, 0), 255);
        assert_eq!(ring_free(10, 9), 0);
        assert_eq!(ring_free(0, 255), 0);
        assert_eq!(ring_free(5, 250), 10);
        // A unit reporting an index outside the ring leaves no room at all.
        assert_eq!(ring_free(256, 0), 0);
        assert_eq!(ring_free(0, 256), 0);
    }

    #[test]
    fn submit_confirms_only_after_the_wait_command_completes() {
        let mut unit = FakeUnit::new();
        let mut state = RingState::new();
        assert_eq!(submit(&mut unit, &mut state, &[[1, 2], [3, 4]], 8), Ok(()));
        assert_eq!(unit.executed, [[1, 2], [3, 4]]);
        assert_eq!((unit.head, unit.tail), (3, 3));
        // Tokens differ between batches, so an old completion never counts.
        assert_eq!(submit(&mut unit, &mut state, &[[5, 6]], 8), Ok(()));
        assert_eq!(unit.completion, 2);
    }

    #[test]
    fn submit_wraps_around_the_ring() {
        let mut unit = FakeUnit::new();
        let mut state = RingState::new();
        for round in 0..400u64 {
            assert_eq!(submit(&mut unit, &mut state, &[[round, 0]], 4), Ok(()));
        }
        assert_eq!(unit.executed.len(), 400);
        assert_eq!(unit.head, 800 % RING_ENTRIES);
    }

    #[test]
    fn submit_times_out_when_the_unit_never_completes() {
        let mut unit = FakeUnit::new();
        unit.stalled = true;
        let mut state = RingState::new();
        assert_eq!(
            submit(&mut unit, &mut state, &[[1, 2]], 16),
            Err(RingError::Timeout)
        );
        assert!(unit.executed.is_empty());
    }

    #[test]
    fn submit_ignores_a_stale_completion_word() {
        let mut unit = FakeUnit::new();
        let mut state = RingState::new();
        assert_eq!(submit(&mut unit, &mut state, &[[1, 2]], 8), Ok(()));
        // The unit stops and the word still holds the previous token: a
        // fresh token per batch keeps it from passing as a confirmation.
        unit.stalled = true;
        unit.sticky = true;
        assert_eq!(unit.completion, 1);
        assert_eq!(
            submit(&mut unit, &mut state, &[[3, 4]], 8),
            Err(RingError::Timeout)
        );
    }

    #[test]
    fn submit_never_overwrites_entries_the_unit_has_not_fetched() {
        // The unit has fetched nothing of a nearly full ring (`store`
        // asserts that no pending entry is overwritten).
        let mut unit = FakeUnit::new();
        unit.stalled = true;
        unit.tail = 254;
        let mut state = RingState::new();
        state.tail = 254;
        assert_eq!(
            submit(&mut unit, &mut state, &[[7, 7]], 4),
            Err(RingError::Full)
        );
        assert_eq!(state.tail, 254);
    }

    #[test]
    fn an_unconfirmed_batch_poisons_the_ring_until_reset() {
        let mut unit = FakeUnit::new();
        unit.stalled = true;
        let mut state = RingState::new();
        assert_eq!(
            submit(&mut unit, &mut state, &[[1, 1]], 16),
            Err(RingError::Timeout)
        );
        assert!(state.is_dead());
        // Later calls fail at once: no polling and nothing queued, even if
        // the unit comes back.
        unit.stalled = false;
        let tail = unit.tail;
        assert_eq!(
            submit(&mut unit, &mut state, &[[2, 2]], u32::MAX),
            Err(RingError::Dead)
        );
        assert_eq!(unit.tail, tail);
        // An oversized batch is a caller error, not a dead unit.
        let mut fresh = RingState::new();
        let batch = [[0u64; 2]; RING_ENTRIES as usize - 1];
        assert_eq!(
            submit(&mut FakeUnit::new(), &mut fresh, &batch, 8),
            Err(RingError::TooLarge)
        );
        assert!(!fresh.is_dead());
        state.reset();
        assert!(!state.is_dead());
    }

    #[test]
    fn usb_handoff_waits_for_the_firmware_and_gives_up_bounded() {
        use core::cell::Cell;
        // Not owned by the firmware: just claim it.
        let register = Cell::new(0u32);
        let outcome = usb::legacy_handoff(|| register.get(), |v| register.set(v), 8);
        assert_eq!(outcome, usb::Handoff::NotOwned);
        assert_eq!(register.get(), usb::OS_OWNED);
        // Firmware releases on the third poll.
        let register = Cell::new(usb::BIOS_OWNED | 1);
        let polls = Cell::new(0);
        let outcome = usb::legacy_handoff(
            || {
                polls.set(polls.get() + 1);
                if polls.get() == 4 {
                    register.set(register.get() & !usb::BIOS_OWNED);
                }
                register.get()
            },
            |v| register.set(v),
            100,
        );
        assert_eq!(outcome, usb::Handoff::Released);
        assert_eq!(register.get(), usb::OS_OWNED | 1);
        // Firmware never releases: bounded, then ownership is forced.
        let register = Cell::new(usb::BIOS_OWNED);
        let outcome = usb::legacy_handoff(|| register.get(), |v| register.set(v), 50);
        assert_eq!(outcome, usb::Handoff::TimedOut);
        assert_eq!(register.get(), usb::OS_OWNED);
    }

    #[test]
    fn usb_legacy_capabilities_are_found_in_bounded_walks() {
        // xHCI: list at 0x500 bytes: protocol cap (2) -> legacy cap (1).
        let read = |offset: u64| match offset {
            0x500 => Some(2 | 4 << 8),
            0x510 => Some(1 | usb::BIOS_OWNED),
            _ => None,
        };
        assert_eq!(usb::xhci_legacy_capability(0x140 << 16, read), Some(0x510));
        assert_eq!(usb::xhci_legacy_capability(0, read), None);
        // A list that loops forever, or leaves the mapped area, is dropped.
        assert_eq!(
            usb::xhci_legacy_capability(1 << 16, |_| Some(2 | 1 << 8)),
            None
        );
        assert_eq!(usb::xhci_legacy_capability(1 << 16, |_| None), None);
        // SMI enables (bits 0, 4, 13-15) go off; events are cleared.
        assert_eq!(usb::xhci_smi_disabled(0xe011), 0x7 << 29);

        // EHCI: EECP 0x68 in configuration space.
        let config = |offset: u8| {
            if offset == 0x68 {
                1 | usb::BIOS_OWNED
            } else {
                0
            }
        };
        assert_eq!(usb::ehci_legacy_capability(0x68 << 8, config), Some(0x68));
        assert_eq!(usb::ehci_legacy_capability(0, config), None);
        assert_eq!(usb::ehci_legacy_capability(0x20 << 8, config), None);
        assert_eq!(
            usb::ehci_legacy_capability(0x40 << 8, |_| 2 | 0x40 << 8),
            None
        );
    }

    #[test]
    fn submit_reports_a_queue_fault_and_an_oversized_batch() {
        let mut unit = FakeUnit::new();
        unit.fault = true;
        let mut state = RingState::new();
        assert_eq!(
            submit(&mut unit, &mut state, &[[1, 2]], 8),
            Err(RingError::Fault)
        );
        let batch = [[0u64; 2]; RING_ENTRIES as usize - 1];
        assert_eq!(
            submit(&mut FakeUnit::new(), &mut RingState::new(), &batch, 8),
            Err(RingError::TooLarge)
        );
    }

    #[test]
    fn amdvi_commands_match_the_specification() {
        let wait = amdvi::completion_wait(0x1_2345_6008, 0xabcd);
        assert_eq!(wait[0] >> 60, 0x1);
        assert_eq!(wait[0] & 1, 1, "store bit");
        assert_eq!(wait[0] & 0b110, 0, "no interrupt, no flush");
        assert_eq!(wait[0] & 0x000f_ffff_ffff_fff8, 0x1_2345_6008);
        assert_eq!((wait[0] >> 52) & 0xff, 0, "reserved bits stay clear");
        assert_eq!(wait[1], 0xabcd);
        // A misaligned or oversized address cannot leak into other fields.
        assert_eq!(amdvi::completion_wait(u64::MAX, 0)[0] >> 52, 0x100);

        assert_eq!(amdvi::invalidate_device(0x1234), [0x2 << 60 | 0x1234, 0]);
        let pages = amdvi::invalidate_domain(7);
        assert_eq!(pages[0], 0x3 << 60 | 7 << 32);
        assert_eq!(pages[1], 0x7fff_ffff_ffff_f003);
    }

    #[test]
    fn vtd_wait_descriptor_matches_the_specification() {
        let wait = vtd::wait(0xdead_beef, 0x7000);
        assert_eq!(wait[0] & 0xf, 5, "descriptor type");
        assert_eq!(wait[0] & (1 << 5), 1 << 5, "status write");
        assert_eq!(wait[0] & 0xffff_ffc0, 0, "no interrupt, reserved clear");
        assert_eq!(wait[0] >> 32, 0xdead_beef);
        assert_eq!(wait[1], 0x7000);
    }

    #[test]
    fn only_bridges_on_the_path_forward_a_bus() {
        // Root port 00:1c.0 with buses 2..=4 behind it.
        assert!(bridge_forwards(0x01, 2, 4, 2));
        assert!(bridge_forwards(0x81, 2, 4, 4), "multi-function bit ignored");
        assert!(!bridge_forwards(0x01, 2, 4, 5));
        assert!(!bridge_forwards(0x01, 2, 4, 1));
        assert!(!bridge_forwards(0x00, 2, 4, 3), "endpoint, not a bridge");
        assert!(!bridge_forwards(0x02, 2, 4, 3), "CardBus header");
        assert!(!bridge_forwards(0x01, 0, 0, 0), "unconfigured bridge");
    }
}
