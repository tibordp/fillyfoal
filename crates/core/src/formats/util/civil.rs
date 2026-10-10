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
/// `civil_from_days`).
pub fn civil(days: i64) -> (i64, i64, i64) {
    let z = days
        .clamp(-1_000_000_000, 1_000_000_000)
        .saturating_add(719_468);
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
