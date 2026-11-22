//! One disk interface over the NVMe and AHCI drivers, so the storage
//! service and the installer work on either kind of disk.

use crate::Line;
use crate::ahci::Ahci;
use crate::nvme::Nvme;

/// Disk controller kinds, as passed by the kernel in the start argument.
pub const KIND_NVME: u64 = 0;
pub const KIND_AHCI: u64 = 1;

pub enum Drive {
    Nvme(Nvme),
    Ahci(Ahci),
}

impl Drive {
    pub fn bring_up(kind: u64, mmio: u64, line: &mut Line) -> Result<Self, (&'static str, u64)> {
        match kind {
            KIND_NVME => Nvme::bring_up(mmio, line).map(Self::Nvme),
            KIND_AHCI => Ahci::bring_up(mmio, line).map(Self::Ahci),
            _ => Err(("drive: unknown controller kind", 40)),
        }
    }

    pub fn name(&self) -> &'static [u8] {
        match self {
            Self::Nvme(_) => b"NVMe",
            Self::Ahci(_) => b"SATA (AHCI)",
        }
    }

    pub fn blocks(&self) -> u64 {
        match self {
            Self::Nvme(d) => d.blocks,
            Self::Ahci(d) => d.blocks,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::Nvme(d) => d.block_size,
            Self::Ahci(d) => d.block_size,
        }
    }

    pub fn transfer(&mut self, write: bool, lba: u64, count: u16, page: usize) -> bool {
        match self {
            Self::Nvme(d) => d.transfer(write, lba, count, page),
            Self::Ahci(d) => d.transfer(write, lba, count, page),
        }
    }

    pub fn read_page(&self, page: usize, offset: usize, out: &mut [u8]) -> bool {
        match self {
            Self::Nvme(d) => d.read_page(page, offset, out),
            Self::Ahci(d) => d.read_page(page, offset, out),
        }
    }

    pub fn write_page(&self, page: usize, offset: usize, bytes: &[u8]) -> bool {
        match self {
            Self::Nvme(d) => d.write_page(page, offset, bytes),
            Self::Ahci(d) => d.write_page(page, offset, bytes),
        }
    }

    pub fn flush(&mut self) -> bool {
        match self {
            Self::Nvme(d) => d.flush(),
            Self::Ahci(d) => d.flush(),
        }
    }
}
