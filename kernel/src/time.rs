//! Wall-clock time from the CMOS real-time clock (phase 6).
//!
//! Decoding is pure and host-tested; the port reads live in the kernel
//! binary (`clock.rs`). RTC contents are firmware-controlled input, so every
//! field is range-checked and a value that does not decode to a real date is
//! refused rather than clamped.

/// Raw RTC registers as read from the chip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtcRegisters {
    pub seconds: u8,
    pub minutes: u8,
    pub hours: u8,
    pub day: u8,
    pub month: u8,
    pub year: u8,
    /// Century register from the FADT (0 = absent).
    pub century: u8,
    /// Status register B (bit 1: 24-hour mode, bit 2: binary mode).
    pub status_b: u8,
}

/// A validated UTC calendar time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

fn from_bcd(value: u8) -> Option<u8> {
    let (high, low) = (value >> 4, value & 0x0f);
    (high <= 9 && low <= 9).then_some(high * 10 + low)
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => {
            29
        }
        _ => 28,
    }
}

impl RtcRegisters {
    /// Decodes BCD/binary and 12/24-hour formats into a validated date.
    pub fn decode(&self) -> Option<DateTime> {
        let binary = self.status_b & 0x04 != 0;
        let hour24 = self.status_b & 0x02 != 0;
        let field = |value: u8| if binary { Some(value) } else { from_bcd(value) };
        let pm = !hour24 && self.hours & 0x80 != 0;
        let mut hour = field(self.hours & 0x7f)?;
        if !hour24 {
            if !(1..=12).contains(&hour) {
                return None;
            }
            hour = match (hour, pm) {
                (12, false) => 0,
                (12, true) => 12,
                (h, true) => h + 12,
                (h, false) => h,
            };
        }
        let year_low = u16::from(field(self.year)?);
        let century = if self.century != 0 {
            u16::from(field(self.century)?)
        } else {
            // No century register: RTC years 00-69 are 20xx, 70-99 are 19xx.
            if year_low < 70 { 20 } else { 19 }
        };
        let date = DateTime {
            year: century * 100 + year_low,
            month: field(self.month)?,
            day: field(self.day)?,
            hour,
            minute: field(self.minutes)?,
            second: field(self.seconds)?,
        };
        let valid = (1970..=2199).contains(&date.year)
            && (1..=12).contains(&date.month)
            && date.day >= 1
            && date.day <= days_in_month(date.year, date.month)
            && date.hour < 24
            && date.minute < 60
            && date.second < 60;
        valid.then_some(date)
    }
}

impl DateTime {
    /// Seconds since 1970-01-01T00:00:00Z.
    pub fn unix_seconds(&self) -> u64 {
        // Days from civil (Howard Hinnant's algorithm), valid for year >= 1970.
        let (year, month) = if self.month <= 2 {
            (i64::from(self.year) - 1, i64::from(self.month) + 9)
        } else {
            (i64::from(self.year), i64::from(self.month) - 3)
        };
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let day_of_year = (153 * month + 2) / 5 + i64::from(self.day) - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        (days * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bcd(seconds: u8, minutes: u8, hours: u8, day: u8, month: u8, year: u8) -> RtcRegisters {
        RtcRegisters {
            seconds,
            minutes,
            hours,
            day,
            month,
            year,
            century: 0x20,
            status_b: 0x02,
        }
    }

    #[test]
    fn decodes_bcd_24_hour() {
        let t = bcd(0x05, 0x10, 0x22, 0x21, 0x11, 0x26).decode().unwrap();
        assert_eq!(
            t,
            DateTime {
                year: 2026,
                month: 11,
                day: 21,
                hour: 22,
                minute: 10,
                second: 5
            }
        );
        assert_eq!(t.unix_seconds(), 1_795_299_005);
    }

    #[test]
    fn decodes_binary_and_12_hour() {
        let mut r = bcd(5, 10, 0x80 | 12, 1, 1, 30);
        r.status_b = 0x04; // binary, 12-hour
        r.century = 20;
        let t = r.decode().unwrap();
        assert_eq!((t.year, t.hour), (2030, 12));
        r.hours = 12; // 12 AM
        assert_eq!(r.decode().unwrap().hour, 0);
        r.hours = 0x80 | 1; // 1 PM
        assert_eq!(r.decode().unwrap().hour, 13);
    }

    #[test]
    fn refuses_invalid_dates() {
        assert!(bcd(0x60, 0, 0, 1, 1, 0x26).decode().is_none()); // second 60
        assert!(bcd(0, 0, 0x24, 1, 1, 0x26).decode().is_none()); // hour 24
        assert!(bcd(0, 0, 0, 0x31, 0x04, 0x26).decode().is_none()); // April 31
        assert!(bcd(0, 0, 0, 0x29, 0x02, 0x26).decode().is_none()); // 2026 not leap
        assert!(bcd(0, 0, 0, 0x29, 0x02, 0x28).decode().is_some()); // 2028 leap
        assert!(bcd(0, 0, 0, 0x1a, 1, 0x26).decode().is_none()); // invalid BCD
        let mut r = bcd(0, 0, 0, 1, 1, 0x26);
        r.status_b = 0;
        r.hours = 0; // 12-hour mode cannot encode hour 0
        assert!(r.decode().is_none());
    }

    #[test]
    fn epoch_reference_points() {
        let epoch = DateTime {
            year: 1970,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        };
        assert_eq!(epoch.unix_seconds(), 0);
        let leap = DateTime {
            year: 2000,
            month: 2,
            day: 29,
            hour: 12,
            minute: 0,
            second: 0,
        };
        assert_eq!(leap.unix_seconds(), 951_825_600);
    }
}
