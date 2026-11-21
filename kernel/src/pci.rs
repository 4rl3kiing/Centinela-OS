//! PCI configuration space (mechanism #1, ports 0xCF8/0xCFC).
//!
//! Configuration space stays kernel-only (the ports are on the deny list for
//! driver grants): a driver can never re-point a BAR, enable bus mastering
//! on another device or reprogram MSI. The kernel enables bus mastering only
//! for a device whose DMA is confined to an IOMMU domain.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Device {
    pub(crate) bus: u8,
    pub(crate) devfn: u8,
}

const COMMAND: u8 = 0x04;
const MEMORY_SPACE: u32 = 1 << 1;
const BUS_MASTER: u32 = 1 << 2;

fn address(device: Device, offset: u8) -> u32 {
    0x8000_0000
        | u32::from(device.bus) << 16
        | u32::from(device.devfn) << 8
        | u32::from(offset & 0xfc)
}

fn read32(device: Device, offset: u8) -> u32 {
    let value: u32;
    // SAFETY: CPL 0, IF=0 (select+access atomic); kernel-owned config ports.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xcf8u16, in("eax") address(device, offset),
            options(nomem, nostack, preserves_flags));
        core::arch::asm!("in eax, dx", in("dx") 0xcfcu16, out("eax") value,
            options(nomem, nostack, preserves_flags));
    }
    value
}

fn write32(device: Device, offset: u8, value: u32) {
    // SAFETY: As in `read32`.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xcf8u16, in("eax") address(device, offset),
            options(nomem, nostack, preserves_flags));
        core::arch::asm!("out dx, eax", in("dx") 0xcfcu16, in("eax") value,
            options(nomem, nostack, preserves_flags));
    }
}

/// Finds the first function on bus 0 with this vendor/device ID.
pub(crate) fn find(vendor: u16, device_id: u16) -> Option<Device> {
    let wanted = u32::from(device_id) << 16 | u32::from(vendor);
    (0u8..=255).find_map(|devfn| {
        let device = Device { bus: 0, devfn };
        (read32(device, 0) == wanted).then_some(device)
    })
}

/// BAR 0 when it is a memory BAR: (physical base, size in bytes).
pub(crate) fn mem_bar0(device: Device) -> Option<(u64, u64)> {
    let original = read32(device, 0x10);
    if original & 1 != 0 {
        return None;
    }
    let is_64 = (original >> 1) & 3 == 2;
    let high = if is_64 { read32(device, 0x14) } else { 0 };
    let command = read32(device, COMMAND);
    write32(device, COMMAND, command & !MEMORY_SPACE);
    write32(device, 0x10, 0xffff_ffff);
    let mask = read32(device, 0x10) & 0xffff_fff0;
    write32(device, 0x10, original);
    write32(device, COMMAND, command);
    let size = u64::from((!mask).wrapping_add(1));
    let base = u64::from(high) << 32 | u64::from(original & 0xffff_fff0);
    (size >= 0x1000 && base != 0 && base & 0xfff == 0).then_some((base, size))
}

/// Enables memory decoding and, if `dma`, bus mastering.
pub(crate) fn enable_memory(device: Device, dma: bool) {
    let command = read32(device, COMMAND) & 0xffff;
    let bits = MEMORY_SPACE | if dma { BUS_MASTER } else { 0 };
    write32(device, COMMAND, command | bits);
}

/// Stops the device from mastering the bus (on driver death).
pub(crate) fn disable_dma(device: Device) {
    let command = read32(device, COMMAND) & 0xffff;
    write32(device, COMMAND, command & !BUS_MASTER);
}
