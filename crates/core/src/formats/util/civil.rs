//! Calendar arithmetic shared by dissectors: proleptic Gregorian dates to
//! and from day counts (Howard Hinnant's algorithms).

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
#[allow(clippy::arithmetic_side_effects)] // inputs are range-checked first
pub fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// `(year, month, day)` of a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`), exact for any day of an `i64` count of seconds
/// (larger counts are clamped).
pub fn civil(days: i64) -> (i64, i64, i64) {
    // i64::MAX seconds is 106,751,991,167,300 days; nothing below overflows
    // for days in this range.
    const MAX_DAYS: i64 = 106_751_991_167_301;
    let z = days.clamp(-MAX_DAYS, MAX_DAYS).saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = doe
        .saturating_sub(doe / 1460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365;
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let day = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let month = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let year = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(month <= 2));
    (year, month, day)
}

/// Seconds since the Unix epoch for a proleptic Gregorian date and time.
#[allow(clippy::arithmetic_side_effects)] // i128 cannot overflow for these inputs
pub fn civil_to_unix(year: i64, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> i64 {
    // Howard Hinnant's days_from_civil.
    let y = i128::from(year) - i128::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i128::from(month.clamp(1, 12));
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + i128::from(day.clamp(1, 31)) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + i128::from(hour) * 3600 + i128::from(min) * 60 + i128::from(sec);
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// Seconds from 1970-01-01 to 2001-01-01 (Core Foundation and Cocoa).
pub const CF_EPOCH: i64 = 978_307_200;
/// Seconds from 1970-01-01 to 2000-01-01 (VHD, AppleSingle).
pub const EPOCH_2000: i64 = 946_684_800;
/// Seconds from 1970-01-01 back to 1960-01-01 (SAS), as a negative offset.
pub const SAS_EPOCH: i64 = -315_619_200;
/// The Julian day number of 1970-01-01.
pub const UNIX_JULIAN_DAY: i64 = 2_440_588;
/// Days from 1899-12-30 (OLE automation dates) to 1970-01-01.
const OLE_EPOCH_DAYS: f64 = 25_569.0;

/// Unix seconds of an OLE automation date (`DATE`, Delphi `TDateTime`):
/// days since 1899-12-30, the fraction being the time of day. `None` if it
/// is not finite or out of range.
pub fn ole_date(days: f64) -> Option<i64> {
    let secs = ((days - OLE_EPOCH_DAYS) * 86_400.0).round();
    // 1e16 seconds is far beyond any calendar date and within i64.
    if !secs.is_finite() || secs.abs() > 1e16 {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)] // range-checked above
    Some(secs as i64)
}

/// Unix seconds of a Windows `SYSTEMTIME` (year, month, day of week, day,
/// hour, minute, second, milliseconds; milliseconds dropped), or `None` if
/// the date is out of range.
pub fn systemtime(fields: [u16; 8]) -> Option<i64> {
    let [year, month, _, day, hour, minute, second, _] = fields;
    let days = days_from_civil(i64::from(year), i64::from(month), i64::from(day))?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    days.checked_mul(86_400)?
        .checked_add(i64::from(hour).saturating_mul(3600))?
        .checked_add(i64::from(minute).saturating_mul(60))?
        .checked_add(i64::from(second))
}

/// `YYYY-MM-DD` of a Unix timestamp, for summaries.
pub fn date(unix_seconds: i64) -> String {
    let (year, month, day) = civil(unix_seconds.div_euclid(86_400));
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions() {
        assert_eq!(days_from_civil(2001, 1, 1), Some(CF_EPOCH / 86_400));
        assert_eq!(days_from_civil(2000, 1, 1), Some(EPOCH_2000 / 86_400));
        assert_eq!(days_from_civil(1960, 1, 1), Some(SAS_EPOCH / 86_400));
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(ole_date(25_569.5), Some(43_200));
        assert_eq!(
            systemtime([2000, 1, 6, 1, 0, 0, 1, 500]),
            Some(EPOCH_2000 + 1)
        );
        assert_eq!(civil_to_unix(2000, 1, 1, 0, 0, 0), EPOCH_2000);
        // Exact across the range of an i64 count of seconds.
        assert_eq!(civil(i64::MAX / 86_400), (292_277_026_596, 12, 4));
        assert_eq!(civil(-719_468), (0, 3, 1));
    }
}
