//! Plain-text rendering, for the example CLI, tests and debugging.
//!
//! Frontends are expected to do their own presentation; this is one
//! reasonable default.

use std::fmt::Write;

use crate::node::{Count, Node};
use crate::session::{ChildState, NodeId, Session};
use crate::value::{Radix, SizeUnit, Value};

pub fn value(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::UInt { value, radix, .. } => uint(*value, *radix),
        Value::Int { value, .. } => value.to_string(),
        Value::Enum { raw, name, .. } => match name {
            Some(name) => format!("{name} ({raw:#x})"),
            None => format!("{raw:#x} (unknown)"),
        },
        Value::Flags {
            raw, set, unknown, ..
        } => {
            let mut parts: Vec<String> = set.iter().map(|s| (*s).to_owned()).collect();
            if *unknown != 0 {
                parts.push(format!("{unknown:#x}"));
            }
            format!("{raw:#x} [{}]", parts.join(" | "))
        }
        Value::Float { value, bits } => float(*value, *bits),
        Value::Timestamp(t) => t.to_string(),
        Value::Text(s) => format!("{s:?}"),
        Value::Bytes(b) => bytes(b),
        Value::Guid(g) => g.to_string(),
        Value::Checksum(c) => c.to_string(),
        Value::Size { n, unit, .. } => size(*n, *unit),
        Value::Duration { ticks, per_sec } => duration(*ticks, *per_sec),
    }
}

fn bytes(b: &[u8]) -> String {
    const MAX: usize = 16;
    let mut out = String::new();
    for (i, byte) in b.iter().take(MAX).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{byte:02x}");
    }
    if b.len() > MAX {
        out.push_str(" …");
    }
    let ascii: String = b
        .iter()
        .take(MAX)
        .map(|&c| {
            if c.is_ascii_graphic() || c == b' ' {
                char::from(c)
            } else {
                '.'
            }
        })
        .collect();
    let _ = write!(out, "  |{ascii}|");
    out
}

/// One line describing a node: `name: value — summary [span] → target`.
pub fn line(node: &Node) -> String {
    let mut out = node.name.to_string();
    if let Some(v) = &node.value {
        let _ = write!(out, ": {}", value(v));
    }
    if let Some(summary) = &node.summary {
        let _ = write!(out, " — {summary}");
    }
    if let Some(span) = node.span {
        let _ = write!(out, "  [{span}]");
    }
    if let Some(target) = node.target {
        let _ = write!(out, " → {target}");
    }
    out
}

/// Renders the materialised part of the tree under `root`.
pub fn tree<C: crate::formats::Catalog>(session: &Session<C>, root: NodeId) -> String {
    let mut out = String::new();
    render(session, root, 0, &mut out);
    out
}

fn render<C: crate::formats::Catalog>(
    session: &Session<C>,
    id: NodeId,
    depth: usize,
    out: &mut String,
) {
    let Some(node) = session.node(id) else {
        return;
    };
    let Some(children) = session.children(id) else {
        return;
    };
    let indent = "  ".repeat(depth);
    let marker = match children.state {
        ChildState::Leaf => "  ",
        ChildState::NotRequested => "▸ ",
        _ => "▾ ",
    };
    let _ = writeln!(out, "{indent}{marker}{}", line(node));
    for d in &node.diagnostics {
        let _ = writeln!(out, "{indent}    ! {d}");
    }
    for &child in children.ids {
        render(session, child, depth.saturating_add(1), out);
    }
    let inner = "  ".repeat(depth.saturating_add(1));
    match children.state {
        ChildState::More => {
            let total = match children.count {
                Count::Exact(n) => format!(" of {n}"),
                Count::AtLeast(n) => format!(" of at least {n}"),
                Count::Unknown => String::new(),
            };
            let _ = writeln!(out, "{inner}  … ({} shown{total})", children.ids.len());
        }
        ChildState::Running(wait) => {
            let _ = writeln!(out, "{inner}  … (in progress: {wait:?})");
        }
        _ => {}
    }
    if let Some(error) = children.error {
        let _ = writeln!(out, "{inner}  ! {error}");
    }
}

/// An unsigned number in `radix`: `123`, `0x7b`, `0o173` or `0b1111011`.
pub fn uint(value: u64, radix: Radix) -> String {
    match radix {
        Radix::Dec => value.to_string(),
        Radix::Hex => format!("{value:#x}"),
        Radix::Oct => format!("{value:#o}"),
        Radix::Bin => format!("{value:#b}"),
    }
}

/// A size, exact first: `1 byte`, `698 bytes`, `1536 bytes (1.5 KiB)`,
/// `8 × 512 bytes (4 KiB)`, `3 × 128 bytes (384 bytes)`.
pub fn size(n: u64, unit: SizeUnit) -> String {
    use crate::formats::util::fmt;
    match unit {
        SizeUnit::Blocks(block) if block != 1 => match n.checked_mul(u64::from(block)) {
            Some(total) => format!("{n} × {block} bytes ({})", fmt::size(total)),
            None => format!("{n} × {block} bytes"),
        },
        _ if n < 1024 => fmt::size(n),
        _ => format!("{n} bytes ({})", fmt::size(n)),
    }
}

/// `per_sec` as `10^k`, if it is one.
fn power_of_ten(per_sec: u64) -> Option<u32> {
    let k = per_sec.checked_ilog10()?;
    (10u64.checked_pow(k) == Some(per_sec)).then_some(k)
}

/// A duration of `ticks` of `1/per_sec` second, in fillyfoal's one style,
/// computed with integers:
/// - under a second, in the largest of ms, µs and ns that is at least 1:
///   `250 ms`, `26.667 µs`;
/// - under a minute, in seconds: `1.48 s`, `5 s`;
/// - from a minute, as `h:mm:ss`: `0:01:05.500`, `1:02:03`, and from a day
///   `2 days, 3:04:05`.
///
/// Fractions are exact when a tick is a power-of-ten fraction of a second
/// (seconds, ms, µs, 100 ns, ns) and leave out trailing zeros (keeping
/// three digits in `h:mm:ss`). Other ticks (90 kHz, a sample rate) are
/// rounded to three digits past a tick's first, and the ticks follow:
/// `1.48 s (133200/90000 s)`, `22.7 µs (1/44100 s)`.
pub fn duration(ticks: i64, per_sec: u64) -> String {
    duration_text(ticks, per_sec, false)
}

/// [`duration`] for summaries: from a second up rounded to the
/// millisecond, and without the ticks (`0:03:25.017`, not
/// `0:03:25.0170068 (9041250/44100 s)`).
pub fn duration_short(ticks: i64, per_sec: u64) -> String {
    duration_text(ticks, per_sec, true)
}

fn duration_text(ticks: i64, per_sec: u64, short: bool) -> String {
    let per = per_sec.max(1);
    let exact = power_of_ten(per).filter(|&k| k <= 9);
    // Decimal digits of a second shown: exact ones, or three past a
    // tick's first, at most 9.
    let mut digits =
        exact.unwrap_or_else(|| per.checked_ilog10().unwrap_or(0).saturating_add(3).min(9));
    if short && ticks.unsigned_abs() >= per {
        digits = digits.min(3);
    }
    let scale = 10u128.pow(digits);
    let a = u128::from(ticks.unsigned_abs());
    let per128 = u128::from(per);
    // The magnitude in units of 10^-digits s, rounded half up.
    let scaled = a
        .saturating_mul(scale)
        .saturating_add(per128 / 2)
        .checked_div(per128)
        .unwrap_or(0);
    let mut out = String::new();
    if ticks < 0 && scaled != 0 {
        out.push('-');
    }
    let whole = scaled.checked_div(scale).unwrap_or(0);
    let frac = scaled.checked_rem(scale).unwrap_or(0);
    if whole >= 60 {
        let (days, rem) = (whole / 86_400, whole % 86_400);
        if days > 0 {
            let _ = write!(out, "{days} {}, ", if days == 1 { "day" } else { "days" });
        }
        let _ = write!(out, "{}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60);
        let f = fraction(frac, digits);
        if !f.is_empty() {
            let _ = write!(out, ".{f:0<3}");
        }
    } else if whole >= 1 || scaled == 0 {
        let _ = write!(out, "{whole}");
        let f = fraction(frac, digits);
        if !f.is_empty() {
            let _ = write!(out, ".{f}");
        }
        out.push_str(" s");
    } else {
        // Under a second: the largest unit (10^-u s) in which it is >= 1.
        let (u, name) = [(3u32, "ms"), (6, "µs"), (9, "ns")]
            .into_iter()
            .find(|&(u, _)| u >= digits || scaled >= 10u128.pow(digits.saturating_sub(u)))
            .unwrap_or((9, "ns"));
        if u >= digits {
            let _ = write!(
                out,
                "{}",
                scaled.saturating_mul(10u128.pow(u.saturating_sub(digits)))
            );
        } else {
            let div = 10u128.pow(digits.saturating_sub(u));
            let _ = write!(out, "{}", scaled.checked_div(div).unwrap_or(0));
            let f = fraction(
                scaled.checked_rem(div).unwrap_or(0),
                digits.saturating_sub(u),
            );
            if !f.is_empty() {
                let _ = write!(out, ".{f}");
            }
        }
        let _ = write!(out, " {name}");
    }
    if exact.is_none() && !short && ticks != 0 {
        let _ = write!(out, " ({ticks}/{per} s)");
    }
    out
}

/// `frac` as `digits` decimal digits, trailing zeros left out.
fn fraction(frac: u128, digits: u32) -> String {
    if digits == 0 || frac == 0 {
        return String::new();
    }
    let width = usize::try_from(digits).unwrap_or(9);
    format!("{frac:0width$}").trim_end_matches('0').to_owned()
}

/// A float stored `bits` wide, in the shortest decimal that reads back to
/// the same value at that width (so an `f32` 0.8 prints `0.8`), switching
/// to exponent notation for very large or very small magnitudes, which `{}`
/// would spell out with hundreds of digits.
pub fn float(value: f64, bits: u8) -> String {
    let a = value.abs();
    let exp = a != 0.0 && a.is_finite() && !(1e-6..1e21).contains(&a);
    match bits {
        // `as` rounds to nearest; it is exact for a value read as an f32.
        32 => {
            let f = value as f32;
            if exp {
                format!("{f:e}")
            } else {
                format!("{f}")
            }
        }
        16 => half(value, exp),
        _ if exp => format!("{value:e}"),
        _ => format!("{value}"),
    }
}

/// The shortest decimal that rounds to `value` as a half-precision float.
fn half(value: f64, exp: bool) -> String {
    if value.is_finite() && value != 0.0 {
        for digits in 0..5 {
            let s = format!("{value:.digits$e}");
            if s.parse::<f64>().ok().map(to_half) == Some(value) {
                // Re-print the parsed value in the usual style.
                let shortest: f64 = s.parse().unwrap_or(value);
                return if exp {
                    format!("{shortest:e}")
                } else {
                    format!("{shortest}")
                };
            }
        }
    }
    if exp {
        format!("{value:e}")
    } else {
        format!("{value}")
    }
}

/// `x` rounded to the nearest half-precision value (ties to even), as `f64`.
fn to_half(x: f64) -> f64 {
    let a = x.abs();
    let rounded = if !a.is_finite() || a >= 65520.0 {
        f64::INFINITY
    } else if a < 2f64.powi(-14) {
        // Subnormal: multiples of 2^-24.
        (a * 2f64.powi(24)).round_ties_even() * 2f64.powi(-24)
    } else {
        // Normal: 10 fraction bits below the leading one. The exponent of a
        // normal f64 is its biased field less 1023.
        let field = (a.to_bits() >> 52) & 0x7ff;
        let e = i32::try_from(field).unwrap_or(1023).saturating_sub(1023);
        let scale = 2f64.powi(e.saturating_sub(10));
        (a / scale).round_ties_even() * scale
    };
    rounded.copysign(x)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::formats::util::floats::f16;

    #[test]
    fn floats_print_shortest_at_their_stored_width() {
        assert_eq!(value(&Value::f32(0.8)), "0.8");
        assert_eq!(value(&Value::f32(1.83)), "1.83");
        assert_eq!(value(&Value::f32(9.96921e36)), "9.96921e36");
        assert_eq!(value(&Value::f32(f32::NAN)), "NaN");
        assert_eq!(value(&Value::f64(f64::from(0.8f32))), "0.800000011920929");
        assert_eq!(value(&Value::f64(0.1)), "0.1");
        assert_eq!(value(&Value::f64(1e300)), "1e300");
        assert_eq!(value(&Value::f80(44100.0)), "44100");
        // binary16: 0x2e66 is the half nearest 0.1, 0x3c00 is 1.
        assert_eq!(value(&Value::f16(f16(0x2e66))), "0.1");
        assert_eq!(value(&Value::f16(f16(0x3c00))), "1");
        assert_eq!(value(&Value::f16(f16(0x7bff))), "65500");
        assert_eq!(value(&Value::f16(f16(0x0001))), "6e-8");
        assert_eq!(value(&Value::f16(f16(0xc000))), "-2");
        assert_eq!(value(&Value::f16(f16(0x7c00))), "inf");
    }

    #[test]
    fn unsigned_numbers_print_in_their_radix() {
        let v = |radix| Value::UInt {
            value: 0o100644,
            bits: 32,
            radix,
        };
        assert_eq!(value(&v(Radix::Dec)), "33188");
        assert_eq!(value(&v(Radix::Hex)), "0x81a4");
        assert_eq!(value(&v(Radix::Oct)), "0o100644");
        assert_eq!(value(&v(Radix::Bin)), "0b1000000110100100");
    }

    #[test]
    fn enum_names_may_be_computed() {
        assert_eq!(
            value(&Value::named(7, 8, format!("type {}", 7))),
            "type 7 (0x7)"
        );
        let table: crate::value::EnumTable = &[(1, "one")];
        assert_eq!(
            value(&crate::formats::util::val::enumv(1u8, 8, table)),
            "one (0x1)"
        );
    }

    #[test]
    fn timestamps_say_what_the_file_recorded() {
        use crate::value::Time;
        assert_eq!(value(&Value::utc(1_792_119_381)), "2026-10-16 02:56:21 UTC");
        assert_eq!(value(&Value::utc(-1)), "1969-12-31 23:59:59 UTC");
        let t = |t: Time| value(&Value::Timestamp(t));
        assert_eq!(
            t(Time::unix_millis(1_792_119_381_148)),
            "2026-10-16 02:56:21.148 UTC"
        );
        assert_eq!(t(Time::unix_millis(-1)), "1969-12-31 23:59:59.999 UTC");
        // A zero fraction is left out of the text, not out of the value.
        assert_eq!(t(Time::unix_millis(1000)), "1970-01-01 00:00:01 UTC");
        assert_eq!(
            Time::unix_millis(1000).iso8601(),
            "1970-01-01T00:00:01.000Z"
        );
        assert_eq!(
            Time::unix_millis(1000).text_full(),
            "1970-01-01 00:00:01.000 UTC"
        );
        assert_eq!(
            t(Time::unix_micros(1_000_001)),
            "1970-01-01 00:00:01.000001 UTC"
        );
        assert_eq!(t(Time::unix_nanos(5)), "1970-01-01 00:00:00.000000005 UTC");
        // 2024-01-01 00:00:00.1234567 UTC as FILETIME ticks.
        assert_eq!(
            t(Time::filetime(133_485_408_001_234_567)),
            "2024-01-01 00:00:00.1234567 UTC"
        );
        assert_eq!(t(Time::offset(0, 60)), "1970-01-01 01:00:00 UTC+01:00");
        assert_eq!(t(Time::offset(0, -330)), "1969-12-31 18:30:00 UTC-05:30");
        assert_eq!(
            t(Time::offset_wall(3600, 60)),
            "1970-01-01 01:00:00 UTC+01:00"
        );
        assert_eq!(Time::offset_wall(3600, 60).secs, 0);
        assert_eq!(t(Time::local(0)), "1970-01-01 00:00:00 (local time)");
        assert_eq!(t(Time::local(90).minute()), "1970-01-01 00:01 (local time)");
        // 2024-01-01, 12:34:56.
        let (date, time) = ((44 << 9) | (1 << 5) | 1, (12 << 11) | (34 << 5) | 28);
        assert_eq!(
            t(Time::dos(date, time).unwrap()),
            "2024-01-01 12:34:56 (local time)"
        );
        assert_eq!(t(Time::dos_date(date).unwrap()), "2024-01-01");
        assert_eq!(Time::dos_date(0), None);
        assert_eq!(
            Time::filetime(133_485_408_001_234_567).iso8601(),
            "2024-01-01T00:00:00.1234567Z"
        );
        assert_eq!(Time::offset(0, -330).iso8601(), "1969-12-31T18:30:00-05:30");
        assert_eq!(Time::local(0).minute().iso8601(), "1970-01-01T00:00");
        assert_eq!(Time::utc(0).day().iso8601(), "1970-01-01");
    }

    #[test]
    fn checksums_say_their_algorithm_and_verdict() {
        use crate::value::Check;
        let v = |c: Check| value(&c.into());
        assert_eq!(
            v(Check::new("CRC-32", 0xae42_6082u32).verify(0xae42_6082u32)),
            "0xae426082 (CRC-32, valid)"
        );
        let bad = Check::new("CRC-16", 0x1234u16).verify(0x0bu16);
        assert_eq!(v(bad.clone()), "0x1234 (CRC-16, mismatch: computed 0xb)");
        assert_eq!(
            bad.mismatch_text().unwrap(),
            "CRC-16 mismatch: stored 0x1234, computed 0xb"
        );
        // Digests print in full, however long.
        let digest: Vec<u8> = (0..32).collect();
        assert_eq!(
            v(Check::new("SHA-256", digest.clone())),
            format!(
                "{} (SHA-256, not checked)",
                digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        );
        assert_eq!(
            v(Check::new("MD5", [0u8; 16]).skipped("encrypted")),
            "00000000000000000000000000000000 (MD5, skipped: encrypted)"
        );
        // An integer and a byte string compare by their bytes.
        assert!(
            Check::new("CRC-32", 0x0102_0304u32)
                .verify([1u8, 2, 3, 4])
                .is_valid()
        );
        let node = crate::Node::new("CRC").checksum(bad);
        assert_eq!(node.diagnostics.len(), 1);
    }

    #[test]
    fn sizes_show_the_exact_count_first() {
        assert_eq!(value(&Value::size(1)), "1 byte");
        assert_eq!(value(&Value::size(698)), "698 bytes");
        assert_eq!(value(&Value::size(1536)), "1536 bytes (1.5 KiB)");
        assert_eq!(value(&Value::size(4096)), "4096 bytes (4 KiB)");
        assert_eq!(value(&Value::blocks(8, 512u32)), "8 × 512 bytes (4 KiB)");
        assert_eq!(
            value(&Value::blocks(3, 128u32)),
            "3 × 128 bytes (384 bytes)"
        );
        assert_eq!(value(&Value::blocks(3, 1u32)), "3 bytes");
        assert_eq!(
            value(&Value::blocks(u64::MAX, 4096u32)),
            "18446744073709551615 × 4096 bytes"
        );
        assert_eq!(Value::blocks(8, 512u32).size_bytes(), Some(4096));
    }

    #[test]
    fn durations_have_one_style() {
        let d = |t, p| value(&Value::duration(t, p));
        assert_eq!(d(0, 1), "0 s");
        assert_eq!(d(5, 1), "5 s");
        assert_eq!(d(250, 1000), "250 ms");
        assert_eq!(d(1500, 1000), "1.5 s");
        assert_eq!(d(-1, 1000), "-1 ms");
        assert_eq!(d(26_667, 1_000_000_000), "26.667 µs");
        assert_eq!(d(25, 1_000_000_000), "25 ns");
        assert_eq!(d(13_500_000, 1_000_000_000), "13.5 ms");
        assert_eq!(d(4, 100), "40 ms");
        assert_eq!(d(77_070_685, 100), "8 days, 22:05:06.850");
        assert_eq!(d(65_500, 1000), "0:01:05.500");
        assert_eq!(d(3723, 1), "1:02:03");
        assert_eq!(d(86_400, 1), "1 day, 0:00:00");
        assert_eq!(d(1_234_567, 10_000_000), "123.4567 ms");
        assert_eq!(d(1_161_209_263, 10_000_000), "0:01:56.1209263");
        // Ticks that are not decimal fractions of a second keep the ticks.
        assert_eq!(d(133_200, 90_000), "1.48 s (133200/90000 s)");
        assert_eq!(d(3600, 90_000), "40 ms (3600/90000 s)");
        assert_eq!(d(18_900_000, 27_000_000), "700 ms (18900000/27000000 s)");
        assert_eq!(d(1, 44_100), "22.7 µs (1/44100 s)");
        assert_eq!(d(441_000, 44_100), "10 s (441000/44100 s)");
        assert_eq!(d(1, 3), "333 ms (1/3 s)");
        assert_eq!(d(0, 90_000), "0 s");
        assert!(d(i64::MIN, 1).starts_with('-'));
        assert_eq!(d(133_201, 90_000), "1.4800111 s (133201/90000 s)");
        // Summaries round to the millisecond from a second up.
        assert_eq!(duration_short(9_041_250, 44_100), "0:03:25.017");
        assert_eq!(duration_short(1, 44_100), "22.7 µs");
        assert_eq!(duration_short(1_234_567_891, 1_000_000_000), "1.235 s");
    }

    #[test]
    fn value_stays_small() {
        assert!(std::mem::size_of::<Value>() <= 48);
        assert!(std::mem::size_of::<crate::value::Time>() <= 24);
    }
}
