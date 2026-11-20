//! Synchronous TLB shootdown protocol for address spaces shared by CPUs.
//!
//! This module defines the correctness contract between the VMM and a future
//! APIC/IPI transport. It does not implement APIC discovery, IPI delivery, or
//! an interrupt handler; until those exist, SMP address-space sharing must
//! remain disabled.

use super::vmm::VirtAddr;

/// Transport operations required to invalidate a virtual page on every CPU
/// that can execute the affected address space.
pub trait TlbShootdownTransport {
    type Error;

    /// Returns the logical CPU identifier of the caller (0..64).
    fn current_cpu_id(&self) -> usize;

    /// Bit N is set when logical CPU N is online and may execute this address
    /// space. The caller must provide a stable snapshot for this operation.
    fn online_cpu_mask(&self) -> u64;

    /// Invalidates the page on the calling CPU.
    fn invalidate_local(&mut self, address: VirtAddr) -> Result<(), Self::Error>;

    /// Sends the shootdown IPI to one remote CPU. The handler must invalidate
    /// the requested page and publish completion before acknowledging.
    fn send_shootdown_ipi(
        &mut self,
        cpu_id: usize,
        address: VirtAddr,
    ) -> Result<(), Self::Error>;

    /// Waits for the specified CPU's acknowledgement. Implementations must
    /// use a bounded timeout and must not report success before invalidation
    /// has completed on that CPU.
    fn wait_for_ack(&mut self, cpu_id: usize) -> Result<(), Self::Error>;
}

/// Failure stage. A nonzero pending mask means those CPUs may still hold a
/// stale translation; the caller must not recycle the physical frame.
#[derive(Debug, Eq, PartialEq)]
pub enum ShootdownError<E> {
    InvalidCpuId,
    CurrentCpuNotOnline,
    LocalInvalidation(E),
    SendFailed { cpu_id: usize, pending_mask: u64, source: E },
    AckFailed { cpu_id: usize, pending_mask: u64, source: E },
}

/// Coordinates local invalidation, remote IPIs, and acknowledgements.
///
/// The transport is responsible for APIC delivery and interrupt-side
/// acknowledgement. This routine is synchronous: success means every CPU in
/// the stable online mask has completed the invalidation.
pub struct TlbShootdown;

impl TlbShootdown {
    pub fn invalidate<T: TlbShootdownTransport>(
        transport: &mut T,
        address: VirtAddr,
    ) -> Result<(), ShootdownError<T::Error>> {
        let current = transport.current_cpu_id();
        if current >= u64::BITS as usize {
            return Err(ShootdownError::InvalidCpuId);
        }

        let online = transport.online_cpu_mask();
        let current_bit = 1u64 << current;
        if online & current_bit == 0 {
            return Err(ShootdownError::CurrentCpuNotOnline);
        }

        transport
            .invalidate_local(address)
            .map_err(ShootdownError::LocalInvalidation)?;

        let mut pending = online & !current_bit;
        let mut send_mask = pending;
        while send_mask != 0 {
            let cpu_id = send_mask.trailing_zeros() as usize;
            send_mask &= !(1u64 << cpu_id);
            if let Err(source) = transport.send_shootdown_ipi(cpu_id, address) {
                return Err(ShootdownError::SendFailed {
                    cpu_id,
                    pending_mask: pending,
                    source,
                });
            }
        }

        while pending != 0 {
            let cpu_id = pending.trailing_zeros() as usize;
            if let Err(source) = transport.wait_for_ack(cpu_id) {
                return Err(ShootdownError::AckFailed {
                    cpu_id,
                    pending_mask: pending,
                    source,
                });
            }
            pending &= !(1u64 << cpu_id);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ShootdownError, TlbShootdown, TlbShootdownTransport};
    use crate::memory::vmm::VirtAddr;

    #[derive(Debug, Eq, PartialEq)]
    enum MockError {
        Send,
        Ack,
        Local,
    }

    struct MockTransport {
        current: usize,
        online: u64,
        sent: u64,
        acked: u64,
        fail_send: Option<usize>,
        fail_ack: Option<usize>,
        fail_local: bool,
    }

    impl TlbShootdownTransport for MockTransport {
        type Error = MockError;

        fn current_cpu_id(&self) -> usize { self.current }
        fn online_cpu_mask(&self) -> u64 { self.online }

        fn invalidate_local(&mut self, _: VirtAddr) -> Result<(), Self::Error> {
            if self.fail_local { Err(MockError::Local) } else { Ok(()) }
        }

        fn send_shootdown_ipi(&mut self, cpu_id: usize, _: VirtAddr) -> Result<(), Self::Error> {
            if self.fail_send == Some(cpu_id) { return Err(MockError::Send); }
            self.sent |= 1u64 << cpu_id;
            Ok(())
        }

        fn wait_for_ack(&mut self, cpu_id: usize) -> Result<(), Self::Error> {
            if self.fail_ack == Some(cpu_id) { return Err(MockError::Ack); }
            self.acked |= 1u64 << cpu_id;
            Ok(())
        }
    }

    fn mock() -> MockTransport {
        MockTransport {
            current: 0,
            online: 0b1111,
            sent: 0,
            acked: 0,
            fail_send: None,
            fail_ack: None,
            fail_local: false,
        }
    }

    #[test]
    fn invalidates_local_and_waits_for_every_online_remote_cpu() {
        let mut transport = mock();
        let address = VirtAddr::new(0xffff_8000_0000_1000).unwrap();

        assert_eq!(TlbShootdown::invalidate(&mut transport, address), Ok(()));
        assert_eq!(transport.sent, 0b1110);
        assert_eq!(transport.acked, 0b1110);
    }

    #[test]
    fn reports_all_unconfirmed_cpus_when_ipi_send_fails() {
        let mut transport = mock();
        transport.fail_send = Some(2);
        let address = VirtAddr::new(0xffff_8000_0000_1000).unwrap();

        assert_eq!(
            TlbShootdown::invalidate(&mut transport, address),
            Err(ShootdownError::SendFailed {
                cpu_id: 2,
                pending_mask: 0b1110,
                source: MockError::Send,
            })
        );
    }

    #[test]
    fn reports_pending_cpu_when_acknowledgement_times_out() {
        let mut transport = mock();
        transport.fail_ack = Some(2);
        let address = VirtAddr::new(0xffff_8000_0000_1000).unwrap();

        assert_eq!(
            TlbShootdown::invalidate(&mut transport, address),
            Err(ShootdownError::AckFailed {
                cpu_id: 2,
                pending_mask: 0b1110,
                source: MockError::Ack,
            })
        );
        assert_eq!(transport.acked, 0b0010);
    }

    #[test]
    fn rejects_caller_not_in_online_cpu_snapshot() {
        let mut transport = mock();
        transport.online = 0b1110;
        let address = VirtAddr::new(0xffff_8000_0000_1000).unwrap();

        assert_eq!(
            TlbShootdown::invalidate(&mut transport, address),
            Err(ShootdownError::CurrentCpuNotOnline)
        );
        assert_eq!(transport.sent, 0);
    }

    #[test]
    fn rejects_cpu_ids_outside_mask_width() {
        let mut transport = mock();
        transport.current = 64;
        let address = VirtAddr::new(0xffff_8000_0000_1000).unwrap();

        assert_eq!(
            TlbShootdown::invalidate(&mut transport, address),
            Err(ShootdownError::InvalidCpuId)
        );
    }

    #[test]
    fn local_failure_prevents_remote_ipis() {
        let mut transport = mock();
        transport.fail_local = true;
        let address = VirtAddr::new(0xffff_8000_0000_1000).unwrap();

        assert_eq!(
            TlbShootdown::invalidate(&mut transport, address),
            Err(ShootdownError::LocalInvalidation(MockError::Local))
        );
        assert_eq!(transport.sent, 0);
    }
}
