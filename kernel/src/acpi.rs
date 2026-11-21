//! Defensive ACPI table discovery (RSDP → XSDT/RSDT → table) and DMAR parsing.
//!
//! Firmware tables are treated as untrusted input: every length is bounded
//! before a slice is formed, every checksum is verified, and structure walks
//! cannot run past their parent table. Physical memory is reached only through
//! a [`PhysicalReader`], which the kernel restricts to ACPI memory regions.

/// Upper bound for any single ACPI table the kernel will read.
pub const MAX_TABLE_LENGTH: usize = 1024 * 1024;
const HEADER_LENGTH: usize = 36;
const MAX_ROOT_ENTRIES: usize = 512;

/// Read-only access to physical memory holding firmware tables.
pub trait PhysicalReader {
    /// Returns `length` bytes at `physical`, or `None` if the range is not
    /// readable firmware memory.
    fn bytes(&self, physical: u64, length: usize) -> Option<&[u8]>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcpiError {
    BadRsdp,
    BadChecksum,
    BadTable,
    Unreadable,
    NotFound,
    TooManyUnits,
}

fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Reads and validates a whole table (header length bound + checksum).
fn read_table<R: PhysicalReader>(reader: &R, physical: u64) -> Result<&[u8], AcpiError> {
    let header = reader
        .bytes(physical, HEADER_LENGTH)
        .ok_or(AcpiError::Unreadable)?;
    let length = u32_at(header, 4).ok_or(AcpiError::BadTable)? as usize;
    if !(HEADER_LENGTH..=MAX_TABLE_LENGTH).contains(&length) {
        return Err(AcpiError::BadTable);
    }
    let table = reader
        .bytes(physical, length)
        .ok_or(AcpiError::Unreadable)?;
    if !checksum_ok(table) {
        return Err(AcpiError::BadChecksum);
    }
    Ok(table)
}

/// Locates the table with `signature`, starting from the RSDP's physical
/// address. Prefers the XSDT (ACPI 2.0+) over the RSDT.
pub fn find_table<'r, R: PhysicalReader>(
    reader: &'r R,
    rsdp: u64,
    signature: &[u8; 4],
) -> Result<&'r [u8], AcpiError> {
    let v1 = reader.bytes(rsdp, 20).ok_or(AcpiError::Unreadable)?;
    if &v1[..8] != b"RSD PTR " || !checksum_ok(v1) {
        return Err(AcpiError::BadRsdp);
    }
    let revision = v1[15];
    let (root, entry_size) = if revision >= 2 {
        let v2 = reader.bytes(rsdp, 36).ok_or(AcpiError::Unreadable)?;
        let length = u32_at(v2, 20).ok_or(AcpiError::BadRsdp)? as usize;
        if !(36..=4096).contains(&length) {
            return Err(AcpiError::BadRsdp);
        }
        let full = reader.bytes(rsdp, length).ok_or(AcpiError::Unreadable)?;
        if !checksum_ok(full) {
            return Err(AcpiError::BadRsdp);
        }
        (u64_at(v2, 24).ok_or(AcpiError::BadRsdp)?, 8)
    } else {
        (u64::from(u32_at(v1, 16).ok_or(AcpiError::BadRsdp)?), 4)
    };
    if root == 0 {
        return Err(AcpiError::BadRsdp);
    }
    let root_table = read_table(reader, root)?;
    let expected: &[u8; 4] = if entry_size == 8 { b"XSDT" } else { b"RSDT" };
    if &root_table[..4] != expected {
        return Err(AcpiError::BadTable);
    }
    let entries = (root_table.len() - HEADER_LENGTH) / entry_size;
    for index in 0..entries.min(MAX_ROOT_ENTRIES) {
        let offset = HEADER_LENGTH + index * entry_size;
        let physical = if entry_size == 8 {
            u64_at(root_table, offset)
        } else {
            u32_at(root_table, offset).map(u64::from)
        }
        .ok_or(AcpiError::BadTable)?;
        if physical == 0 {
            continue;
        }
        let Some(header) = reader.bytes(physical, 4) else {
            continue;
        };
        if header == signature {
            return read_table(reader, physical);
        }
    }
    Err(AcpiError::NotFound)
}

/// How to power the machine off (ACPI S5) and reset it, from the FADT and
/// the DSDT's `\_S5` object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowerControl {
    /// PM1a/PM1b control block I/O ports (0 = absent).
    pub pm1a_control: u16,
    pub pm1b_control: u16,
    /// SLP_TYP values for S5, if the DSDT declares them.
    pub s5: Option<(u8, u8)>,
    /// ACPI reset register when it is an I/O port: (port, value).
    pub reset_port: Option<(u16, u8)>,
}

/// Largest DSDT scanned for `\_S5`.
const MAX_DSDT_SCAN: usize = MAX_TABLE_LENGTH;

/// Reads the FADT ("FACP") and the DSDT it points to.
pub fn parse_power<R: PhysicalReader>(reader: &R, rsdp: u64) -> Result<PowerControl, AcpiError> {
    let fadt = find_table(reader, rsdp, b"FACP")?;
    let port = |offset: usize| -> u16 {
        u32_at(fadt, offset)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(0)
    };
    let mut pm1a_control = port(64);
    let pm1b_control = port(68);
    // ACPI 2.0+: extended PM1a control block (GAS) when the legacy field is 0.
    if pm1a_control == 0 && fadt.get(172) == Some(&1) {
        pm1a_control = u64_at(fadt, 176)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(0);
    }
    let flags = u32_at(fadt, 112).unwrap_or(0);
    let reset_port = if flags & (1 << 10) != 0 && fadt.get(116) == Some(&1) {
        match (u64_at(fadt, 120).map(u16::try_from), fadt.get(128)) {
            (Some(Ok(port)), Some(&value)) if port != 0 => Some((port, value)),
            _ => None,
        }
    } else {
        None
    };
    let x_dsdt = if fadt.len() >= 148 {
        u64_at(fadt, 140).unwrap_or(0)
    } else {
        0
    };
    let dsdt = if x_dsdt != 0 {
        x_dsdt
    } else {
        u64::from(u32_at(fadt, 40).unwrap_or(0))
    };
    let s5 = if dsdt == 0 {
        None
    } else {
        read_table(reader, dsdt)
            .ok()
            .filter(|table| &table[..4] == b"DSDT")
            .and_then(find_s5)
    };
    Ok(PowerControl {
        pm1a_control,
        pm1b_control,
        s5,
        reset_port,
    })
}

/// Finds `Name(\_S5, Package() { a, b, ... })` and returns (SLP_TYPa,
/// SLP_TYPb). Only the AML encodings firmware uses for this object are
/// accepted; anything else returns `None` (no guessing).
pub fn find_s5(dsdt: &[u8]) -> Option<(u8, u8)> {
    let body = dsdt.get(HEADER_LENGTH..dsdt.len().min(MAX_DSDT_SCAN))?;
    let mut start = 0;
    while let Some(position) = body.get(start..)?.windows(4).position(|w| w == b"_S5_") {
        let at = start + position;
        start = at + 1;
        // NameOp (0x08), optionally followed by the root prefix '\'.
        let named = match at {
            0 => false,
            1 => body[0] == 0x08,
            _ => body[at - 1] == 0x08 || (body[at - 1] == b'\\' && body[at - 2] == 0x08),
        };
        if !named || body.get(at + 4) != Some(&0x12) {
            continue;
        }
        let lead = *body.get(at + 5)?;
        let length_bytes = usize::from(lead >> 6);
        let mut cursor = at + 6 + length_bytes;
        let elements = *body.get(cursor)?;
        cursor += 1;
        if elements < 2 {
            continue;
        }
        let mut value = || -> Option<u8> {
            let op = *body.get(cursor)?;
            let (v, used) = match op {
                0x00 => (0, 1),
                0x01 => (1, 1),
                0x0a => (*body.get(cursor + 1)?, 2),
                _ => return None,
            };
            cursor += used;
            (v <= 7).then_some(v)
        };
        if let (Some(a), Some(b)) = (value(), value()) {
            return Some((a, b));
        }
    }
    None
}

/// CMOS index of the RTC century register from the FADT (0 = none).
pub fn rtc_century_register<R: PhysicalReader>(reader: &R, rsdp: u64) -> u8 {
    find_table(reader, rsdp, b"FACP")
        .ok()
        .and_then(|fadt| fadt.get(108).copied())
        // Indexes 0x00-0x0d are the clock itself; anything past 0x7f does
        // not exist in standard CMOS.
        .filter(|&index| (0x0e..0x80).contains(&index))
        .unwrap_or(0)
}

/// Lists the signatures of every table the XSDT/RSDT references (up to
/// `out.len()`), for the hardware report. Returns how many were stored.
pub fn list_tables<R: PhysicalReader>(reader: &R, rsdp: u64, out: &mut [[u8; 4]]) -> usize {
    let Some(v1) = reader.bytes(rsdp, 20) else {
        return 0;
    };
    if &v1[..8] != b"RSD PTR " || !checksum_ok(v1) {
        return 0;
    }
    let (root, entry_size) = if v1[15] >= 2 {
        match reader.bytes(rsdp, 36).and_then(|v2| u64_at(v2, 24)) {
            Some(xsdt) => (xsdt, 8),
            None => return 0,
        }
    } else {
        (u64::from(u32_at(v1, 16).unwrap_or(0)), 4)
    };
    let Ok(root_table) = read_table(reader, root) else {
        return 0;
    };
    let entries = ((root_table.len() - HEADER_LENGTH) / entry_size).min(MAX_ROOT_ENTRIES);
    let mut stored = 0;
    for index in 0..entries {
        if stored == out.len() {
            break;
        }
        let offset = HEADER_LENGTH + index * entry_size;
        let physical = if entry_size == 8 {
            u64_at(root_table, offset)
        } else {
            u32_at(root_table, offset).map(u64::from)
        };
        if let Some(signature) = physical.and_then(|p| reader.bytes(p, 4)) {
            out[stored].copy_from_slice(signature);
            stored += 1;
        }
    }
    stored
}

/// One DMA-remapping hardware unit (DRHD) from the DMAR table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DrhdUnit {
    pub register_base: u64,
    pub segment: u16,
    /// INCLUDE_PCI_ALL: the unit covers every device not claimed by another.
    pub include_all: bool,
}

/// Parsed DMAR summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dmar {
    pub host_address_width: u8,
    pub unit_count: usize,
    /// Firmware requested that DMA remapping stays on (DMA_CTRL_PLATFORM_OPT_IN).
    pub platform_opt_in: bool,
}

/// Parses a checksummed DMAR table into `units`. Fails closed if there are
/// more units than slots: an untracked unit would leave devices unprotected.
pub fn parse_dmar(table: &[u8], units: &mut [DrhdUnit]) -> Result<Dmar, AcpiError> {
    if table.len() < 48 || &table[..4] != b"DMAR" || !checksum_ok(table) {
        return Err(AcpiError::BadTable);
    }
    let host_address_width = table[36].saturating_add(1);
    let platform_opt_in = table[37] & 0b100 != 0;
    let mut offset = 48;
    let mut count = 0;
    while offset < table.len() {
        let kind = u16_at(table, offset).ok_or(AcpiError::BadTable)?;
        let length = usize::from(u16_at(table, offset + 2).ok_or(AcpiError::BadTable)?);
        let end = offset.checked_add(length).ok_or(AcpiError::BadTable)?;
        if length < 4 || end > table.len() {
            return Err(AcpiError::BadTable);
        }
        if kind == 0 {
            if length < 16 {
                return Err(AcpiError::BadTable);
            }
            let register_base = u64_at(table, offset + 8).ok_or(AcpiError::BadTable)?;
            if register_base == 0 || register_base & 0xfff != 0 {
                return Err(AcpiError::BadTable);
            }
            let slot = units.get_mut(count).ok_or(AcpiError::TooManyUnits)?;
            *slot = DrhdUnit {
                register_base,
                segment: u16_at(table, offset + 6).ok_or(AcpiError::BadTable)?,
                include_all: table[offset + 4] & 1 != 0,
            };
            count += 1;
        }
        offset = end;
    }
    Ok(Dmar {
        host_address_width,
        unit_count: count,
        platform_opt_in,
    })
}

/// I/O APIC described by the MADT.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IoApic {
    pub address: u64,
    pub gsi_base: u32,
}

/// ISA interrupt source override (legacy IRQ → GSI, polarity/trigger).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IsaOverride {
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

/// Parsed MADT: the first I/O APIC and up to `MAX_OVERRIDES` ISA overrides.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Madt {
    pub io_apic: Option<IoApic>,
    pub overrides: [IsaOverride; MAX_OVERRIDES],
    pub override_count: usize,
}

pub const MAX_OVERRIDES: usize = 16;

impl Madt {
    /// Resolves a legacy ISA IRQ to (GSI, active_low, level_triggered).
    pub fn route_isa(&self, irq: u8) -> (u32, bool, bool) {
        self.overrides[..self.override_count]
            .iter()
            .find(|entry| entry.source == irq)
            .map_or((u32::from(irq), false, false), |entry| {
                // MPS INTI flags: polarity bits 1:0 (3 = active low),
                // trigger bits 3:2 (3 = level).
                (
                    entry.gsi,
                    entry.flags & 0b11 == 0b11,
                    (entry.flags >> 2) & 0b11 == 0b11,
                )
            })
    }
}

/// Parses a checksummed MADT ("APIC") table defensively.
pub fn parse_madt(table: &[u8]) -> Result<Madt, AcpiError> {
    if table.len() < 44 || &table[..4] != b"APIC" || !checksum_ok(table) {
        return Err(AcpiError::BadTable);
    }
    let mut madt = Madt::default();
    let mut offset = 44;
    while offset < table.len() {
        let kind = *table.get(offset).ok_or(AcpiError::BadTable)?;
        let length = usize::from(*table.get(offset + 1).ok_or(AcpiError::BadTable)?);
        let end = offset.checked_add(length).ok_or(AcpiError::BadTable)?;
        if length < 2 || end > table.len() {
            return Err(AcpiError::BadTable);
        }
        match kind {
            1 if length >= 12 && madt.io_apic.is_none() => {
                let address = u64::from(u32_at(table, offset + 4).ok_or(AcpiError::BadTable)?);
                if address == 0 || address & 0xfff != 0 {
                    return Err(AcpiError::BadTable);
                }
                madt.io_apic = Some(IoApic {
                    address,
                    gsi_base: u32_at(table, offset + 8).ok_or(AcpiError::BadTable)?,
                });
            }
            2 if length >= 10 => {
                let slot = madt
                    .overrides
                    .get_mut(madt.override_count)
                    .ok_or(AcpiError::TooManyUnits)?;
                *slot = IsaOverride {
                    source: table[offset + 3],
                    gsi: u32_at(table, offset + 4).ok_or(AcpiError::BadTable)?,
                    flags: u16_at(table, offset + 8).ok_or(AcpiError::BadTable)?,
                };
                madt.override_count += 1;
            }
            _ => {}
        }
        offset = end;
    }
    Ok(madt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    struct Fake(Vec<(u64, Vec<u8>)>);

    impl PhysicalReader for Fake {
        fn bytes(&self, physical: u64, length: usize) -> Option<&[u8]> {
            self.0.iter().find_map(|(base, data)| {
                let start = physical.checked_sub(*base)? as usize;
                data.get(start..start.checked_add(length)?)
            })
        }
    }

    fn fix_checksum(bytes: &mut [u8], at: usize) {
        bytes[at] = 0;
        let sum = bytes.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        bytes[at] = 0u8.wrapping_sub(sum);
    }

    fn table(signature: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; HEADER_LENGTH];
        t[..4].copy_from_slice(signature);
        t.extend_from_slice(body);
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        fix_checksum(&mut t, 9);
        t
    }

    fn dmar(units: &[u64]) -> Vec<u8> {
        let mut body = vec![47, 0b101];
        body.extend_from_slice(&[0; 10]);
        for base in units {
            let mut drhd = vec![0u8; 16];
            drhd[2..4].copy_from_slice(&16u16.to_le_bytes());
            drhd[4] = 1;
            drhd[8..16].copy_from_slice(&base.to_le_bytes());
            body.extend_from_slice(&drhd);
        }
        table(b"DMAR", &body)
    }

    fn rsdp_v2(xsdt: u64) -> Vec<u8> {
        let mut r = vec![0u8; 36];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[15] = 2;
        r[20..24].copy_from_slice(&36u32.to_le_bytes());
        r[24..32].copy_from_slice(&xsdt.to_le_bytes());
        fix_checksum(&mut r[..20], 8);
        fix_checksum(&mut r, 32);
        r
    }

    fn fadt(dsdt: u32, pm1a: u32, reset: Option<(u16, u8)>) -> Vec<u8> {
        let mut body = vec![0u8; 244 - HEADER_LENGTH];
        let at = |o: usize| o - HEADER_LENGTH;
        body[at(40)..at(44)].copy_from_slice(&dsdt.to_le_bytes());
        body[at(64)..at(68)].copy_from_slice(&pm1a.to_le_bytes());
        if let Some((port, value)) = reset {
            body[at(112)..at(116)].copy_from_slice(&(1u32 << 10).to_le_bytes());
            body[at(116)] = 1;
            body[at(120)..at(128)].copy_from_slice(&u64::from(port).to_le_bytes());
            body[at(128)] = value;
        }
        table(b"FACP", &body)
    }

    fn s5_dsdt(aml: &[u8]) -> Vec<u8> {
        table(b"DSDT", aml)
    }

    #[test]
    fn finds_s5_in_common_encodings() {
        // Name(_S5, Package(4) { 5, 5, 0, 0 }) with byte prefixes (QEMU).
        let qemu = s5_dsdt(&[
            0x10, 0x08, b'_', b'S', b'5', b'_', 0x12, 0x0a, 0x04, 0x0a, 0x05, 0x0a, 0x05, 0x00,
            0x00,
        ]);
        assert_eq!(find_s5(&qemu), Some((5, 5)));
        // Name(\_S5, Package(2) { Zero, One }).
        let rooted = s5_dsdt(&[
            0x08, b'\\', b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x00, 0x01,
        ]);
        assert_eq!(find_s5(&rooted), Some((0, 1)));
    }

    #[test]
    fn refuses_hostile_s5() {
        // Not a Name object, truncated package, out-of-range value, method body.
        for aml in [
            &[0x14, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x00, 0x00][..],
            &[0x08, b'_', b'S', b'5', b'_', 0x12][..],
            &[
                0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x0a, 0xff, 0x00,
            ][..],
            &[
                0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x0b, 0x05, 0x00,
            ][..],
            &[][..],
        ] {
            assert_eq!(find_s5(&s5_dsdt(aml)), None, "{aml:x?}");
        }
    }

    #[test]
    fn parses_power_control_from_fadt_and_dsdt() {
        let dsdt = s5_dsdt(&[
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x0a, 0x05, 0x0a, 0x05,
        ]);
        let mut xsdt_body = Vec::new();
        xsdt_body.extend_from_slice(&0x3000u64.to_le_bytes());
        let xsdt = table(b"XSDT", &xsdt_body);
        let fake = Fake(vec![
            (0x1000, rsdp_v2(0x2000)),
            (0x2000, xsdt),
            (0x3000, fadt(0x4000, 0x604, Some((0xcf9, 0x06)))),
            (0x4000, dsdt),
        ]);
        let power = parse_power(&fake, 0x1000).unwrap();
        assert_eq!(power.pm1a_control, 0x604);
        assert_eq!(power.s5, Some((5, 5)));
        assert_eq!(power.reset_port, Some((0xcf9, 0x06)));
        // A DSDT with a bad checksum yields no S5 rather than garbage.
        let mut broken = s5_dsdt(&[
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x0a, 0x05, 0x0a, 0x05,
        ]);
        broken[9] ^= 0xff;
        let fake = Fake(vec![
            (0x1000, rsdp_v2(0x2000)),
            (0x2000, table(b"XSDT", &xsdt_body)),
            (0x3000, fadt(0x4000, 0x604, None)),
            (0x4000, broken),
        ]);
        let power = parse_power(&fake, 0x1000).unwrap();
        assert_eq!(power.s5, None);
        assert_eq!(power.reset_port, None);
    }

    fn system(dmar_table: Vec<u8>) -> Fake {
        let xsdt = table(b"XSDT", &0x3000u64.to_le_bytes());
        Fake(vec![
            (0x1000, rsdp_v2(0x2000)),
            (0x2000, xsdt),
            (0x3000, dmar_table),
        ])
    }

    #[test]
    fn finds_and_parses_dmar() {
        let fake = system(dmar(&[0xfed9_0000, 0xfed9_1000]));
        let found = find_table(&fake, 0x1000, b"DMAR").unwrap();
        let mut units = [DrhdUnit::default(); 4];
        let dmar = parse_dmar(found, &mut units).unwrap();
        assert_eq!(dmar.unit_count, 2);
        assert_eq!(dmar.host_address_width, 48);
        assert!(dmar.platform_opt_in);
        assert_eq!(units[1].register_base, 0xfed9_1000);
        assert!(units[0].include_all);
    }

    #[test]
    fn rejects_corrupted_checksums() {
        let mut bad = dmar(&[0xfed9_0000]);
        bad[40] ^= 1;
        let fake = system(bad);
        assert_eq!(
            find_table(&fake, 0x1000, b"DMAR"),
            Err(AcpiError::BadChecksum)
        );
        let mut fake = system(dmar(&[0xfed9_0000]));
        fake.0[0].1[0] = b'X';
        assert_eq!(find_table(&fake, 0x1000, b"DMAR"), Err(AcpiError::BadRsdp));
    }

    #[test]
    fn missing_table_is_reported() {
        let fake = system(dmar(&[0xfed9_0000]));
        assert_eq!(find_table(&fake, 0x1000, b"APIC"), Err(AcpiError::NotFound));
    }

    #[test]
    fn hostile_structures_fail_closed() {
        let mut units = [DrhdUnit::default(); 1];
        // More units than slots.
        assert_eq!(
            parse_dmar(&dmar(&[0x1000, 0x2000]), &mut units),
            Err(AcpiError::TooManyUnits)
        );
        // Unaligned register base.
        assert_eq!(
            parse_dmar(&dmar(&[0x1234]), &mut units),
            Err(AcpiError::BadTable)
        );
        // Structure length running past the table.
        let mut t = dmar(&[0x1000]);
        t[48 + 2] = 0xff;
        fix_checksum(&mut t, 9);
        assert_eq!(parse_dmar(&t, &mut units), Err(AcpiError::BadTable));
        // Zero-length structure (infinite-loop attempt).
        let mut t = dmar(&[0x1000]);
        t[48 + 2] = 0;
        t[48 + 3] = 0;
        fix_checksum(&mut t, 9);
        assert_eq!(parse_dmar(&t, &mut units), Err(AcpiError::BadTable));
    }

    fn madt(entries: &[&[u8]]) -> Vec<u8> {
        let mut body = vec![0u8; 8];
        for entry in entries {
            body.extend_from_slice(entry);
        }
        table(b"APIC", &body)
    }

    #[test]
    fn parses_ioapic_and_overrides() {
        let mut ioapic = vec![1u8, 12, 0, 0];
        ioapic.extend_from_slice(&0xfec0_0000u32.to_le_bytes());
        ioapic.extend_from_slice(&0u32.to_le_bytes());
        let mut iso = vec![2u8, 10, 0, 0];
        iso.extend_from_slice(&2u32.to_le_bytes());
        iso.extend_from_slice(&0u16.to_le_bytes());
        let mut level = vec![2u8, 10, 0, 9];
        level.extend_from_slice(&9u32.to_le_bytes());
        level.extend_from_slice(&0b1111u16.to_le_bytes());
        let parsed = parse_madt(&madt(&[&ioapic, &iso, &level])).unwrap();
        assert_eq!(parsed.io_apic.unwrap().address, 0xfec0_0000);
        assert_eq!(parsed.route_isa(0), (2, false, false));
        assert_eq!(parsed.route_isa(9), (9, true, true));
        assert_eq!(parsed.route_isa(3), (3, false, false));
    }

    #[test]
    fn hostile_madt_fails_closed() {
        assert_eq!(parse_madt(&madt(&[&[1, 0]])), Err(AcpiError::BadTable));
        assert_eq!(
            parse_madt(&madt(&[&[1, 200, 0, 0]])),
            Err(AcpiError::BadTable)
        );
        let mut unaligned = vec![1u8, 12, 0, 0];
        unaligned.extend_from_slice(&0xfec0_0010u32.to_le_bytes());
        unaligned.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_madt(&madt(&[&unaligned])), Err(AcpiError::BadTable));
    }

    #[test]
    fn unreadable_memory_is_not_dereferenced() {
        let fake = Fake(vec![]);
        assert_eq!(
            find_table(&fake, 0x1000, b"DMAR"),
            Err(AcpiError::Unreadable)
        );
    }
}
