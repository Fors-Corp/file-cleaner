//! `datetime.isoformat()`, for the two places a date is printed: a backup's
//! `Last Backup Date` and a plan's `created_at`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds and microseconds since the epoch, rounding as `timedelta` does
/// when `plistlib` builds a date from a float (to the nearest microsecond).
pub fn since_epoch(time: SystemTime) -> (i64, u32) {
    let (seconds, nanos) = match time.duration_since(UNIX_EPOCH) {
        Ok(after) => (after.as_secs() as i64, after.subsec_nanos()),
        Err(before) => {
            let before = before.duration();
            match before.subsec_nanos() {
                0 => (-(before.as_secs() as i64), 0),
                nanos => (-(before.as_secs() as i64) - 1, 1_000_000_000 - nanos),
            }
        }
    };
    match (nanos + 500) / 1000 {
        1_000_000 => (seconds + 1, 0),
        micros => (seconds, micros),
    }
}

/// A naive UTC `datetime.isoformat()`: `2024-02-29T12:34:56`, with
/// `.ffffff` only when there are microseconds to show.
pub fn isoformat(seconds: i64, micros: u32) -> String {
    // Days to a civil date, by the usual era arithmetic (proleptic Gregorian,
    // as `datetime` is): years start in March, so a leap day ends one.
    let days = seconds.div_euclid(86400) + 719_468;
    let (era, day_of_era) = (days.div_euclid(146_097), days.rem_euclid(146_097));
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    let clock = seconds.rem_euclid(86400);
    let (hour, minute, second) = (clock / 3600, clock / 60 % 60, clock % 60);
    let fraction = if micros > 0 { format!(".{micros:06}") } else { String::new() };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{fraction}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn dates_are_spelled_as_isoformat_spells_them() {
        // datetime.fromtimestamp(n, UTC).replace(tzinfo=None).isoformat()
        for (seconds, micros, expected) in [
            (0, 0, "1970-01-01T00:00:00"),
            (978_307_200, 0, "2001-01-01T00:00:00"),
            (1_709_210_096, 0, "2024-02-29T12:34:56"),
            (1_709_251_199, 250, "2024-02-29T23:59:59.000250"),
            (1_709_251_200, 0, "2024-03-01T00:00:00"),
            (4_102_444_799, 999_999, "2099-12-31T23:59:59.999999"),
            (-1, 0, "1969-12-31T23:59:59"),
            (-2_208_988_800, 0, "1900-01-01T00:00:00"),
        ] {
            assert_eq!(isoformat(seconds, micros), expected);
        }
    }

    #[test]
    fn times_round_to_the_microsecond_on_both_sides_of_the_epoch() {
        assert_eq!(since_epoch(UNIX_EPOCH + Duration::new(5, 1_499)), (5, 1));
        assert_eq!(since_epoch(UNIX_EPOCH + Duration::new(5, 999_999_600)), (6, 0));
        assert_eq!(since_epoch(UNIX_EPOCH - Duration::new(1, 250_000_000)), (-2, 750_000));
        assert_eq!(since_epoch(UNIX_EPOCH - Duration::new(3, 0)), (-3, 0));
    }
}
