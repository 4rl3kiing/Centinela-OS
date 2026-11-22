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

/// Finds the first function on bus 0 with this class, subclass and
/// programming interface (for example 01:08:02, an NVMe controller).
pub(crate) fn find_class(class: u8, subclass: u8, interface: u8) -> Option<Device> {
    let wanted = u32::from(class) << 24 | u32::from(subclass) << 16 | u32::from(interface) << 8;
    (0u8..=255).find_map(|devfn| {
        let device = Device { bus: 0, devfn };
        (read32(device, 0) != 0xffff_ffff && read32(device, 0x08) & 0xffff_ff00 == wanted)
            .then_some(device)
    })
}

/// BAR 0 when it is a memory BAR: (physical base, size in bytes).
pub(crate) fn mem_bar0(device: Device) -> Option<(u64, u64)> {
    mem_bar(device, 0)
}

/// Memory BAR `index` (0-5): (physical base, size in bytes), 4 KiB aligned.
pub(crate) fn mem_bar(device: Device, index: u8) -> Option<(u64, u64)> {
    if index > 5 {
        return None;
    }
    let offset = 0x10 + 4 * index;
    let original = read32(device, offset);
    if original & 1 != 0 {
        return None;
    }
    let is_64 = (original >> 1) & 3 == 2;
    let high = if is_64 && index < 5 {
        read32(device, offset + 4)
    } else {
        0
    };
    let command = read32(device, COMMAND);
    write32(device, COMMAND, command & !MEMORY_SPACE);
    write32(device, offset, 0xffff_ffff);
    let mask = read32(device, offset) & 0xffff_fff0;
    write32(device, offset, original);
    write32(device, COMMAND, command);
    let size = u64::from((!mask).wrapping_add(1)).max(0x1000);
    let base = u64::from(high) << 32 | u64::from(original & 0xffff_fff0);
    (base != 0 && base & 0xfff == 0).then_some((base, size))
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

/// Calls `visit(device, vendor, device_id, class, subclass, interface)` for
/// every present function on every bus (configuration mechanism #1).
pub(crate) fn for_each(mut visit: impl FnMut(Device, u16, u16, u8, u8, u8)) {
    for bus in 0u8..=255 {
        for slot in 0u8..32 {
            for function in 0u8..8 {
                let device = Device {
                    bus,
                    devfn: slot << 3 | function,
                };
                let id = read32(device, 0);
                if id & 0xffff == 0xffff {
                    if function == 0 {
                        break;
                    }
                    continue;
                }
                let class = read32(device, 0x08);
                visit(
                    device,
                    id as u16,
                    (id >> 16) as u16,
                    (class >> 24) as u8,
                    (class >> 16) as u8,
                    (class >> 8) as u8,
                );
                // Single-function devices answer on every function number.
                if function == 0 && (read32(device, 0x0c) >> 16) & 0x80 == 0 {
                    break;
                }
            }
        }
    }
}
