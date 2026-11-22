//! Hardware diagnosis report, printed on every boot (screen and serial).
//!
//! On a real machine this is the first thing to photograph or capture: it
//! lists what the kernel found and which parts Centinela-OS supports, so a
//! single test boot gives enough information to fix what fails.

use core::fmt::Write;

use centinela_hal::serial::SerialWriter;
use centinela_kernel::acpi::{self, PhysicalReader};

fn supported(vendor: u16, device: u16, class: u8, subclass: u8, interface: u8) -> &'static str {
    match (vendor, device, class, subclass, interface) {
        (0x8086, 0x100e, ..) => "driver: e1000",
        (_, _, 0x01, 0x08, 0x02) => "driver: nvme + CFS",
        (_, _, 0x03, ..) => "display: framebuffer console",
        (_, _, 0x06, ..) => "bridge",
        (_, _, 0x0c, 0x03, 0x30) => "USB xHCI: no driver yet",
        (_, _, 0x01, 0x06, 0x01) => "driver: ahci + CFS",
        (_, _, 0x02, ..) => "network: no driver for this model",
        _ => "no driver",
    }
}

/// Prints the report. `rsdp` is the ACPI root (if any).
pub(crate) fn print<R: PhysicalReader>(rsdp: Option<(&R, u64)>) {
    let mut out = SerialWriter;
    let _ = writeln!(out, "HWREPORT begin (photograph or save this block)\r");
    let vendor = core::arch::x86_64::__cpuid(0);
    let mut name = [0u8; 12];
    name[..4].copy_from_slice(&vendor.ebx.to_le_bytes());
    name[4..8].copy_from_slice(&vendor.edx.to_le_bytes());
    name[8..].copy_from_slice(&vendor.ecx.to_le_bytes());
    let mut brand = [0u8; 48];
    if core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0004 {
        for (index, leaf) in (0x8000_0002u32..=0x8000_0004).enumerate() {
            let r = core::arch::x86_64::__cpuid(leaf);
            for (word, value) in [r.eax, r.ebx, r.ecx, r.edx].iter().enumerate() {
                let at = index * 16 + word * 4;
                brand[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
    }
    let printable = |bytes: &[u8]| -> [u8; 48] {
        let mut clean = [b' '; 48];
        for (slot, &byte) in clean.iter_mut().zip(bytes) {
            *slot = if (0x20..0x7f).contains(&byte) {
                byte
            } else {
                b' '
            };
        }
        clean
    };
    let vendor_text = printable(&name);
    let brand_text = printable(&brand);
    let _ = writeln!(
        out,
        "HWREPORT cpu: {} | {}\r",
        core::str::from_utf8(&vendor_text[..12])
            .unwrap_or("?")
            .trim(),
        core::str::from_utf8(&brand_text).unwrap_or("?").trim()
    );
    match rsdp {
        Some((reader, root)) => {
            let mut tables = [[0u8; 4]; 32];
            let count = acpi::list_tables(reader, root, &mut tables);
            let _ = write!(out, "HWREPORT acpi: {count} tables:");
            for signature in &tables[..count] {
                let text = printable(signature);
                let _ = write!(
                    out,
                    " {}",
                    core::str::from_utf8(&text[..4]).unwrap_or("????")
                );
            }
            let _ = writeln!(out, "\r");
        }
        None => {
            let _ = writeln!(out, "HWREPORT acpi: none\r");
        }
    }
    let mut devices = 0;
    crate::pci::for_each(|device, vendor, id, class, subclass, interface| {
        devices += 1;
        let _ = writeln!(
            out,
            "HWREPORT pci {:02x}:{:02x}.{} {vendor:04x}:{id:04x} class {class:02x}.{subclass:02x}.{interface:02x} {}\r",
            device.bus,
            device.devfn >> 3,
            device.devfn & 7,
            supported(vendor, id, class, subclass, interface)
        );
    });
    let _ = writeln!(out, "HWREPORT end ({devices} PCI functions)\r");
}
