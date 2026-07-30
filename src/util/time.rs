//! Civil date and time helpers.
//!
//! The daily log file name needs a calendar date and the log lines need a wall
//! clock time. Both are derived from the Unix epoch without pulling in an
//! external calendar crate.

use std::time::{SystemTime, UNIX_EPOCH};

/// A broken down UTC timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub millis: u32,
}

impl DateTime {
    /// `YYYY-MM-DD`, used for the log file name.
    pub fn date_string(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// `YYYY-MM-DD HH:MM:SS.mmm`, used for log line prefixes.
    pub fn timestamp_string(&self) -> String {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millis
        )
    }
}

/// Convert days since 1970-01-01 to a civil date.
///
/// This is Howard Hinnant's `civil_from_days` algorithm, valid for the whole
/// proleptic Gregorian calendar.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Break a Unix timestamp in milliseconds into a UTC `DateTime`.
pub fn from_unix_millis(millis: i64) -> DateTime {
    let total_secs = millis.div_euclid(1000);
    let ms = millis.rem_euclid(1000) as u32;
    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    DateTime {
        year,
        month,
        day,
        hour: (secs_of_day / 3600) as u32,
        minute: ((secs_of_day % 3600) / 60) as u32,
        second: (secs_of_day % 60) as u32,
        millis: ms,
    }
}

/// Milliseconds since the Unix epoch, or 0 if the clock predates it.
pub fn unix_millis_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

/// Current UTC time broken down.
pub fn now() -> DateTime {
    from_unix_millis(unix_millis_now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_1970_01_01() {
        let dt = from_unix_millis(0);
        assert_eq!((dt.year, dt.month, dt.day), (1970, 1, 1));
        assert_eq!((dt.hour, dt.minute, dt.second, dt.millis), (0, 0, 0, 0));
        assert_eq!(dt.date_string(), "1970-01-01");
    }

    #[test]
    fn known_timestamps() {
        // 2001-09-09T01:46:40Z
        let dt = from_unix_millis(1_000_000_000_000);
        assert_eq!(dt.date_string(), "2001-09-09");
        assert_eq!(dt.timestamp_string(), "2001-09-09 01:46:40.000");

        // 2026-03-12T00:00:00Z, the publication date of the reference specs.
        let dt = from_unix_millis(1_773_273_600_000);
        assert_eq!(dt.date_string(), "2026-03-12");
    }

    #[test]
    fn leap_day_handling() {
        // 2024-02-29T12:34:56.789Z
        let dt = from_unix_millis(1_709_210_096_789);
        assert_eq!(dt.date_string(), "2024-02-29");
        assert_eq!(dt.timestamp_string(), "2024-02-29 12:34:56.789");

        // 2000 is a leap year, 1900 is not.
        assert_eq!(civil_from_days(11016), (2000, 2, 29));
        assert_eq!(civil_from_days(-25508), (1900, 3, 1));
    }

    #[test]
    fn pre_epoch_dates() {
        let dt = from_unix_millis(-1);
        assert_eq!(dt.date_string(), "1969-12-31");
        assert_eq!(dt.timestamp_string(), "1969-12-31 23:59:59.999");
    }

    #[test]
    fn round_trip_day_boundaries() {
        for day in [0i64, 1, 59, 60, 365, 366, 10_000, 20_000, -1, -365] {
            let (y, m, d) = civil_from_days(day);
            let dt = from_unix_millis(day * 86_400_000);
            assert_eq!((dt.year, dt.month, dt.day), (y, m, d));
        }
    }
}
