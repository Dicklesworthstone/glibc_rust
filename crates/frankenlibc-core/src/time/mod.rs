//! Time and date functions.
//!
//! Implements `<time.h>` pure-logic helpers. Actual syscall invocations
//! (`clock_gettime`, etc.) live in the ABI crate; this module provides
//! validators and the `epoch_to_broken_down` converter.

/// Represents a timespec value (seconds + nanoseconds).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0 to 999_999_999).
    pub tv_nsec: i64,
}

/// Clock identifiers for `clock_gettime`.
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;

/// POSIX `CLOCKS_PER_SEC` — microseconds per clock tick.
pub const CLOCKS_PER_SEC: i64 = 1_000_000;

/// Returns `true` if `clock_id` is a known valid clock.
#[inline]
pub fn valid_clock_id(clock_id: i32) -> bool {
    matches!(
        clock_id,
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID
    )
}

/// Broken-down time representation (like `struct tm`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrokenDownTime {
    /// Seconds (0-60, 60 for leap second).
    pub tm_sec: i32,
    /// Minutes (0-59).
    pub tm_min: i32,
    /// Hours (0-23).
    pub tm_hour: i32,
    /// Day of month (1-31).
    pub tm_mday: i32,
    /// Month (0-11).
    pub tm_mon: i32,
    /// Years since 1900.
    pub tm_year: i32,
    /// Day of week (0-6, Sunday = 0).
    pub tm_wday: i32,
    /// Day of year (0-365).
    pub tm_yday: i32,
    /// Daylight saving time flag.
    pub tm_isdst: i32,
}

/// Returns `true` if `year` is a leap year (Gregorian).
#[inline]
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days in each month for a non-leap year.
const DAYS_IN_MONTH: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Convert seconds since Unix epoch to broken-down UTC time.
///
/// Handles negative epochs (pre-1970). UTC only — no timezone/DST.
pub fn epoch_to_broken_down(epoch_secs: i64) -> BrokenDownTime {
    // Seconds within the day
    let mut rem = epoch_secs % 86400;
    let mut days = epoch_secs / 86400;
    if rem < 0 {
        rem += 86400;
        days -= 1;
    }

    let tm_sec = (rem % 60) as i32;
    let tm_min = ((rem / 60) % 60) as i32;
    let tm_hour = (rem / 3600) as i32;

    // Day of week: Jan 1 1970 was Thursday (4)
    let mut wday = (days % 7 + 4) % 7;
    if wday < 0 {
        wday += 7;
    }
    let tm_wday = wday as i32;

    // Walk years from 1970
    let mut year: i64 = 1970;
    let mut remaining_days = days;

    if remaining_days >= 0 {
        loop {
            let days_in_year: i64 = if is_leap_year(year) { 366 } else { 365 };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            year += 1;
        }
    } else {
        loop {
            year -= 1;
            let days_in_year: i64 = if is_leap_year(year) { 366 } else { 365 };
            remaining_days += days_in_year;
            if remaining_days >= 0 {
                break;
            }
        }
    }

    let tm_yday = remaining_days as i32;
    let leap = is_leap_year(year);

    // Walk months
    let mut mon = 0i32;
    let mut day_rem = remaining_days as i32;
    for m in 0..12 {
        let dim = if m == 1 && leap {
            29
        } else {
            DAYS_IN_MONTH[m as usize]
        };
        if day_rem < dim {
            mon = m;
            break;
        }
        day_rem -= dim;
        mon = m + 1;
    }

    BrokenDownTime {
        tm_sec,
        tm_min,
        tm_hour,
        tm_mday: day_rem + 1,
        tm_mon: mon,
        tm_year: (year - 1900) as i32,
        tm_wday,
        tm_yday,
        tm_isdst: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_clock_id() {
        assert!(valid_clock_id(CLOCK_REALTIME));
        assert!(valid_clock_id(CLOCK_MONOTONIC));
        assert!(valid_clock_id(CLOCK_PROCESS_CPUTIME_ID));
        assert!(!valid_clock_id(-1));
        assert!(!valid_clock_id(99));
    }

    #[test]
    fn epoch_zero() {
        let t = epoch_to_broken_down(0);
        assert_eq!(t.tm_year, 70); // 1970
        assert_eq!(t.tm_mon, 0); // January
        assert_eq!(t.tm_mday, 1);
        assert_eq!(t.tm_hour, 0);
        assert_eq!(t.tm_min, 0);
        assert_eq!(t.tm_sec, 0);
        assert_eq!(t.tm_wday, 4); // Thursday
        assert_eq!(t.tm_yday, 0);
    }

    #[test]
    fn known_timestamp() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let t = epoch_to_broken_down(1_704_067_200);
        assert_eq!(t.tm_year, 124); // 2024 - 1900
        assert_eq!(t.tm_mon, 0); // January
        assert_eq!(t.tm_mday, 1);
        assert_eq!(t.tm_hour, 0);
        assert_eq!(t.tm_min, 0);
        assert_eq!(t.tm_sec, 0);
        assert_eq!(t.tm_wday, 1); // Monday
        assert_eq!(t.tm_yday, 0);
    }

    #[test]
    fn leap_year_feb29() {
        // 2024-02-29 12:00:00 UTC = 1709208000
        let t = epoch_to_broken_down(1_709_208_000);
        assert_eq!(t.tm_year, 124);
        assert_eq!(t.tm_mon, 1); // February
        assert_eq!(t.tm_mday, 29);
        assert_eq!(t.tm_hour, 12);
    }

    #[test]
    fn negative_epoch() {
        // 1969-12-31 23:59:59 UTC = -1
        let t = epoch_to_broken_down(-1);
        assert_eq!(t.tm_year, 69); // 1969
        assert_eq!(t.tm_mon, 11); // December
        assert_eq!(t.tm_mday, 31);
        assert_eq!(t.tm_hour, 23);
        assert_eq!(t.tm_min, 59);
        assert_eq!(t.tm_sec, 59);
        assert_eq!(t.tm_wday, 3); // Wednesday
    }

    #[test]
    fn year_2000_boundary() {
        // 2000-01-01 00:00:00 UTC = 946684800
        let t = epoch_to_broken_down(946_684_800);
        assert_eq!(t.tm_year, 100);
        assert_eq!(t.tm_mon, 0);
        assert_eq!(t.tm_mday, 1);
        assert_eq!(t.tm_wday, 6); // Saturday
    }

    #[test]
    fn is_leap_year_check() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
        assert!(is_leap_year(2400));
    }

    #[test]
    fn end_of_year() {
        // 2023-12-31 23:59:59 UTC = 1704067199
        let t = epoch_to_broken_down(1_704_067_199);
        assert_eq!(t.tm_year, 123);
        assert_eq!(t.tm_mon, 11); // December
        assert_eq!(t.tm_mday, 31);
        assert_eq!(t.tm_hour, 23);
        assert_eq!(t.tm_min, 59);
        assert_eq!(t.tm_sec, 59);
        assert_eq!(t.tm_yday, 364);
    }
}
