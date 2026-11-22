//! PCI configuration space (mechanism #1, ports 0xCF8/0xCFC).
//!
//! Configuration space stays kernel-only (the ports are on the deny list for
//! driver grants): a driver can never re-point a BAR, enable bus mastering
//! on another device or reprogram MSI. The kernel enables bus mastering only
//! for a device whose DMA is confined to an IOMMU domain.
//!
//! DMA policy (fail closed):
//! - At boot, before the IOMMU and any driver start, `quiesce_bus_masters`
//!   clears Bus Master on every function of every bus, bridges included:
//!   whatever the firmware left able to master the bus stops, on machines
//!   with and without an IOMMU.
//! - Bus Master is set again only by `enable_memory(device, true)`, which
//!   the kernel calls only for a device that owns an IOMMU domain (plus the
//!   bridges on its path to the root). Without DMAR/IVRS no domain exists,
//!   so no driver ever gets DMA.
//! - Known cost: firmware services that rely on DMA after hand-off stop
//!   working. The relevant one is BIOS "legacy USB" emulation (a USB
//!   keyboard presented as PS/2 by SMM through the USB host controller): on
//!   real hardware without a native PS/2 port the keyboard is lost. With an
//!   IOMMU that DMA was already blocked by the deny-by-default tables. QEMU
//!   is unaffected (serial, i8042 and the framebuffer never master the bus).
//!
//! - USB legacy hand-off: before a USB host controller loses Bus Master the
//!   kernel takes it from the firmware, because SMM code that still owns a
//!   controller whose DMA stops can loop (SMI storm, hang). xHCI and EHCI:
//!   set OS Owned in USBLEGSUP, wait (bounded) for BIOS Owned to drop, then
//!   disable every SMI source in USBLEGCTLSTS. OHCI: ownership change
//!   request, then all interrupts off. UHCI: legacy register (0xC0) written
//!   with its status bits cleared and every SMI/trap enable off. A hand-off
//!   that times out is logged and ownership is taken anyway.
//! - The AMD IOMMU's own PCI function (class 08.06) is left untouched: the
//!   AMD-Vi specification does not say whether its Bus Master bit gates the
//!   unit's own memory writes (event log, COMPLETION_WAIT store) or its
//!   MSI, so clearing it could make every invalidation go unconfirmed. It
//!   is trusted platform hardware whose accesses are defined by tables the
//!   kernel owns, so skipping it opens no DMA path.
//!
//! Access to the 0xCF8 (address) / 0xCFC (data) pair is serialised by one
//! global lock taken with interrupts disabled, so neither another CPU nor a
//! local handler can re-point 0xCF8 between the two halves of an access.

use core::fmt::Write;

use centinela_hal::serial::SerialWriter;
use centinela_kernel::dma::usb::{self, Handoff};
use centinela_kernel::dma::{SpinLock, bridge_forwards};
use centinela_kernel::memory::hhdm_backend::HhdmFrameMemory;
use centinela_kernel::memory::vmm::{PAGE_SIZE, PageMapping, PageTableMapper, PhysAddr, VirtAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Device {
    pub(crate) bus: u8,
    pub(crate) devfn: u8,
}

const COMMAND: u8 = 0x04;
const MEMORY_SPACE: u32 = 1 << 1;
const BUS_MASTER: u32 = 1 << 2;
/// Header type (bits 23:16) and, for bridges, the bus-number registers.
const HEADER: u8 = 0x0c;
const BRIDGE_BUSES: u8 = 0x18;

/// The configuration port pair. It is reachable only through `CONFIG`, so
/// every address+data sequence (and every read-modify-write built from
/// them) runs under the lock.
struct ConfigPorts(());

static CONFIG: SpinLock<ConfigPorts> = SpinLock::new(ConfigPorts(()));

fn address(device: Device, offset: u8) -> u32 {
    0x8000_0000
        | u32::from(device.bus) << 16
        | u32::from(device.devfn) << 8
        | u32::from(offset & 0xfc)
}

impl ConfigPorts {
    fn read32(&mut self, device: Device, offset: u8) -> u32 {
        let value: u32;
        // SAFETY: CPL 0; kernel-owned config ports. `&mut self` exists only
        // inside `CONFIG.with`: the lock is held and IF=0, so the select and
        // the access cannot be separated by another CPU or a handler.
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") 0xcf8u16, in("eax") address(device, offset),
                options(nomem, nostack, preserves_flags));
            core::arch::asm!("in eax, dx", in("dx") 0xcfcu16, out("eax") value,
                options(nomem, nostack, preserves_flags));
        }
        value
    }

    fn write32(&mut self, device: Device, offset: u8, value: u32) {
        // SAFETY: As in `read32`.
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") 0xcf8u16, in("eax") address(device, offset),
                options(nomem, nostack, preserves_flags));
            core::arch::asm!("out dx, eax", in("dx") 0xcfcu16, in("eax") value,
                options(nomem, nostack, preserves_flags));
        }
    }

    /// Sets and clears bits of the command register (status bits, which are
    /// write-one-to-clear, are written as zero). Returns the old command.
    fn update_command(&mut self, device: Device, set: u32, clear: u32) -> u32 {
        let command = self.read32(device, COMMAND) & 0xffff;
        let updated = (command | set) & !clear;
        if updated != command {
            self.write32(device, COMMAND, updated);
        }
        command
    }
}

fn read32(device: Device, offset: u8) -> u32 {
    CONFIG.with(|ports| ports.read32(device, offset))
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
    // One lock hold: the sizing probe (decoding off, all-ones, restore) must
    // not interleave with another CPU's access to the same device.
    let (original, high, mask) = CONFIG.with(|ports| {
        let original = ports.read32(device, offset);
        if original & 1 != 0 {
            return None;
        }
        let is_64 = (original >> 1) & 3 == 2;
        let high = if is_64 && index < 5 {
            ports.read32(device, offset + 4)
        } else {
            0
        };
        let command = ports.read32(device, COMMAND);
        ports.write32(device, COMMAND, command & !MEMORY_SPACE);
        ports.write32(device, offset, 0xffff_ffff);
        let mask = ports.read32(device, offset) & 0xffff_fff0;
        ports.write32(device, offset, original);
        ports.write32(device, COMMAND, command);
        Some((original, high, mask))
    })?;
    let size = u64::from((!mask).wrapping_add(1)).max(0x1000);
    let base = u64::from(high) << 32 | u64::from(original & 0xffff_fff0);
    (base != 0 && base & 0xfff == 0).then_some((base, size))
}

/// Enables memory decoding and, if `dma`, bus mastering. The caller passes
/// `dma` only for a device that owns an IOMMU domain.
pub(crate) fn enable_memory(device: Device, dma: bool) {
    if dma {
        enable_upstream_bridges(device.bus);
    }
    let bits = MEMORY_SPACE | if dma { BUS_MASTER } else { 0 };
    CONFIG.with(|ports| ports.update_command(device, bits, 0));
}

/// Stops the device from mastering the bus (before its domain is torn down).
pub(crate) fn disable_dma(device: Device) {
    CONFIG.with(|ports| ports.update_command(device, 0, BUS_MASTER));
}

/// Result of the boot-time quiesce.
pub(crate) struct Quiesced {
    /// Functions present.
    pub(crate) functions: u32,
    /// Functions the firmware had left with Bus Master set.
    pub(crate) cleared: u32,
    /// Functions whose Bus Master bit reads back as set (hard-wired).
    pub(crate) stuck: u32,
}

/// Bounds on the wait for the firmware to release a USB controller.
const HANDOFF_CONFIG_POLLS: u32 = 200_000;
const HANDOFF_MMIO_POLLS: u32 = 2_000_000;

/// One kernel page used to reach device registers during the boot quiesce
/// (single CPU), re-pointed on demand and unmapped at the end.
struct Window<'a, 'p, 'b> {
    memory: &'a mut HhdmFrameMemory<'p, 'b>,
    root: PhysAddr,
    address: Option<u64>,
    page: Option<u64>,
}

impl Window<'_, '_, '_> {
    fn unmap(&mut self) {
        if let (Some(address), Some(_)) = (self.address, self.page.take())
            && let Ok(address) = VirtAddr::new(address)
        {
            let _ = PageTableMapper::new(&mut *self.memory, self.root).unmap_4k(address);
        }
    }

    /// Pointer to the 32-bit register at `physical`, mapping its page.
    fn register(&mut self, physical: u64) -> Option<*mut u32> {
        if physical & 3 != 0 {
            return None;
        }
        let page = physical & !(PAGE_SIZE - 1);
        if self.address.is_none() {
            self.address = crate::isolation::free_kernel_slot_address(self.memory, self.root);
        }
        let address = self.address?;
        if self.page != Some(page) {
            self.unmap();
            let mapping = PageMapping::kernel_device(address, page).ok()?;
            PageTableMapper::new(&mut *self.memory, self.root)
                .map_4k(mapping)
                .ok()?;
            self.page = Some(page);
        }
        Some((address + (physical - page)) as *mut u32)
    }

    fn read(&mut self, physical: u64) -> Option<u32> {
        let register = self.register(physical)?;
        // SAFETY: The page was just mapped (UC, kernel only) and holds
        // registers of a controller whose memory decoding is enabled.
        Some(unsafe { register.read_volatile() })
    }

    fn write(&mut self, physical: u64, value: u32) {
        if let Some(register) = self.register(physical) {
            // SAFETY: As in `read`.
            unsafe { register.write_volatile(value) };
        }
    }
}

fn report_handoff(device: Device, kind: &str, outcome: Handoff) {
    if outcome == Handoff::TimedOut {
        let _ = write!(
            SerialWriter,
            "PCI: firmware did not release {kind} controller {:02x}:{:02x}.{} in time; ownership taken anyway.\r\n",
            device.bus,
            device.devfn >> 3,
            device.devfn & 7
        );
    }
}

/// Takes a USB host controller (class 0C.03) from the firmware and silences
/// its SMI sources, before the controller loses Bus Master.
fn usb_handoff(window: &mut Window<'_, '_, '_>, device: Device, interface: u8) {
    if interface == 0x00 {
        // UHCI: clear the status bits, disable every SMI and trap enable.
        CONFIG.with(|ports| {
            let legacy = ports.read32(device, 0xc0);
            ports.write32(device, 0xc0, (legacy & 0xffff_0000) | 0x8f00);
        });
        return;
    }
    // The other controllers are reached through BAR 0; with decoding off
    // the firmware cannot be driving them either.
    let low = read32(device, 0x10);
    if read32(device, COMMAND) & MEMORY_SPACE == 0 || low & 1 != 0 {
        return;
    }
    let high = if (low >> 1) & 3 == 2 {
        read32(device, 0x14)
    } else {
        0
    };
    let base = u64::from(high) << 32 | u64::from(low & 0xffff_fff0);
    if base == 0 {
        return;
    }
    match interface {
        0x10 => {
            // OHCI: HcControl.InterruptRouting set means SMM owns it.
            const CONTROL: u64 = 0x04;
            const ROUTING: u32 = 1 << 8;
            if window
                .read(base + CONTROL)
                .is_some_and(|c| c & ROUTING != 0)
            {
                window.write(base + 0x10, 1 << 30); // enable OwnershipChange
                window.write(base + 0x08, 1 << 3); // OwnershipChangeRequest
                let released = (0..HANDOFF_MMIO_POLLS)
                    .any(|_| window.read(base + CONTROL).is_none_or(|c| c & ROUTING == 0));
                if !released {
                    report_handoff(device, "OHCI", Handoff::TimedOut);
                }
            }
            window.write(base + 0x14, u32::MAX); // HcInterruptDisable: all
        }
        0x20 => {
            let Some(hccparams) = window.read(base + 0x08) else {
                return;
            };
            let Some(offset) = usb::ehci_legacy_capability(hccparams, |o| read32(device, o)) else {
                return;
            };
            let outcome = usb::legacy_handoff(
                || read32(device, offset),
                |value| CONFIG.with(|ports| ports.write32(device, offset, value)),
                HANDOFF_CONFIG_POLLS,
            );
            // USBLEGCTLSTS: every SMI enable off.
            CONFIG.with(|ports| ports.write32(device, offset + 4, 0));
            report_handoff(device, "EHCI", outcome);
        }
        0x30 => {
            let Some(hccparams1) = window.read(base + 0x10) else {
                return;
            };
            let Some(offset) = usb::xhci_legacy_capability(hccparams1, |o| window.read(base + o))
            else {
                return;
            };
            let register = base + offset;
            // Both closures use the window; a cell lets them share it.
            let shared = core::cell::RefCell::new(&mut *window);
            let outcome = usb::legacy_handoff(
                || shared.borrow_mut().read(register).unwrap_or(0),
                |value| shared.borrow_mut().write(register, value),
                HANDOFF_MMIO_POLLS,
            );
            if let Some(control) = window.read(register + 4) {
                window.write(register + 4, usb::xhci_smi_disabled(control));
            }
            report_handoff(device, "xHCI", outcome);
        }
        _ => {}
    }
}

/// Clears Bus Master on every function of every bus, after taking USB host
/// controllers from the firmware. Runs once at boot on the bootstrap CPU,
/// before the IOMMU is programmed and before any driver starts (see the
/// module policy).
pub(crate) fn quiesce_bus_masters(
    memory: &mut HhdmFrameMemory<'_, '_>,
    kernel_root: PhysAddr,
) -> Quiesced {
    let mut result = Quiesced {
        functions: 0,
        cleared: 0,
        stuck: 0,
    };
    let mut window = Window {
        memory,
        root: kernel_root,
        address: None,
        page: None,
    };
    walk(|device, _| {
        let class = read32(device, 0x08);
        result.functions += 1;
        match (class >> 16) as u16 {
            // The AMD IOMMU function keeps its firmware state (module doc).
            0x0806 => return,
            0x0c03 => usb_handoff(&mut window, device, (class >> 8) as u8),
            _ => {}
        }
        let (was_master, still_master) = CONFIG.with(|ports| {
            let before = ports.update_command(device, 0, BUS_MASTER);
            let after = ports.read32(device, COMMAND);
            (before & BUS_MASTER != 0, after & BUS_MASTER != 0)
        });
        result.cleared += u32::from(was_master && !still_master);
        result.stuck += u32::from(still_master);
    });
    window.unmap();
    result
}

/// Sets Bus Master on every PCI-PCI bridge between `bus` and the root (the
/// boot quiesce cleared them), so requests of a device with a DMA domain can
/// travel upstream. Bridges are not turned off again: other devices behind
/// them may hold a domain, and every device without one stays blocked by its
/// own Bus Master bit and by the IOMMU's deny-by-default tables.
fn enable_upstream_bridges(bus: u8) {
    if bus == 0 {
        return;
    }
    walk(|bridge, _| {
        CONFIG.with(|ports| {
            let header = (ports.read32(bridge, HEADER) >> 16) as u8;
            let buses = ports.read32(bridge, BRIDGE_BUSES);
            if bridge_forwards(header, (buses >> 8) as u8, (buses >> 16) as u8, bus) {
                ports.update_command(bridge, BUS_MASTER, 0);
            }
        });
    });
}

/// Calls `visit(device, vendor, device_id, class, subclass, interface)` for
/// every present function on every bus (configuration mechanism #1).
pub(crate) fn for_each(mut visit: impl FnMut(Device, u16, u16, u8, u8, u8)) {
    walk(|device, id| {
        let class = read32(device, 0x08);
        visit(
            device,
            id as u16,
            (id >> 16) as u16,
            (class >> 24) as u8,
            (class >> 16) as u8,
            (class >> 8) as u8,
        );
    });
}

/// Calls `visit(device, id register)` for every present function on every
/// bus. The lock is taken per access, never across `visit`.
fn walk(mut visit: impl FnMut(Device, u32)) {
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
                visit(device, id);
                // Single-function devices answer on every function number.
                if function == 0 && (read32(device, HEADER) >> 16) & 0x80 == 0 {
                    break;
                }
            }
        }
    }
}
