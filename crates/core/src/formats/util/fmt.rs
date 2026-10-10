//! Text formatting for names and summaries: counts, sizes, clipped
//! previews, hex strings and identifiers.

use crate::value::Value;

/// `n` and a noun, with an `s` unless `n` is 1: `"1 file"`, `"3 files"`.
pub fn plural(n: impl Into<u64>, noun: &str) -> String {
    let n = n.into();
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// `n` and the matching form: `"1 entry"`, `"3 entries"`.
pub fn count(n: impl Into<u64>, one: &str, many: &str) -> String {
    let n = n.into();
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// `n` with thousands separators: `"1,234,567"`.
pub fn grouped(n: impl Into<u64>) -> String {
    let digits = n.into().to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len().saturating_sub(i)) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// [`count`] with thousands separators: `"1,234 rows"`.
pub fn grouped_count(n: impl Into<u64>, one: &str, many: &str) -> String {
    let n = n.into();
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{} {many}", grouped(n))
    }
}

/// A byte count: `"1 byte"`, `"512 bytes"`, `"1.2 MiB"`; exact multiples
/// of a unit have no fraction (`"4 KiB"`).
pub fn size(n: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if n < 1024 {
        return if n == 1 {
            "1 byte".to_owned()
        } else {
            format!("{n} bytes")
        };
    }
    let mut value = n as f64 / 1024.0;
    let mut divisor: u64 = 1024;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < 5 {
        value /= 1024.0;
        divisor = divisor.saturating_mul(1024);
        unit = unit.saturating_add(1);
    }
    let name = UNITS.get(unit).copied().unwrap_or("EiB");
    if n.checked_rem(divisor) == Some(0) {
        format!("{} {name}", n.checked_div(divisor).unwrap_or(0))
    } else {
        format!("{value:.1} {name}")
    }
}

/// Text shortened to `max` characters, with an ellipsis if cut.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// A one-line preview: whitespace runs and control characters become
/// single spaces, the ends are trimmed, and the result is [`clip`]ped.
pub fn preview(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() || c.is_control() {
            space = !out.is_empty();
        } else {
            if space {
                out.push(' ');
                space = false;
            }
            out.push(c);
        }
    }
    clip(&out, max)
}

/// The string with its first character uppercased.
pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

pub use crate::text::{hex_lower, hex_upper};

/// An RFC 4122 UUID in its usual lowercase form from 16 bytes in network
/// order (`00112233-4455-6677-8899-aabbccddeeff`). Other lengths get the
/// same grouping as far as they go.
pub fn uuid(b: &[u8]) -> String {
    let mut out = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A four-character code as text, with non-printable bytes escaped.
pub fn fourcc(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}

/// [`fourcc`] as a text value.
pub fn fourcc_value(bytes: &[u8]) -> Value {
    Value::Text(fourcc(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts() {
        assert_eq!(plural(1u8, "file"), "1 file");
        assert_eq!(count(2u8, "entry", "entries"), "2 entries");
        assert_eq!(grouped(1_234_567u32), "1,234,567");
        assert_eq!(grouped(999u32), "999");
        assert_eq!(grouped_count(1000u32, "row", "rows"), "1,000 rows");
    }

    #[test]
    fn text() {
        assert_eq!(size(1), "1 byte");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(4096), "4 KiB");
        assert_eq!(size(256 << 10), "256 KiB");
        assert_eq!(size(3 << 30), "3 GiB");
        assert_eq!(size(1025), "1.0 KiB");
        assert_eq!(clip("abcdef", 3), "abc…");
        assert_eq!(preview("  a\n\tb  c ", 10), "a b c");
        assert_eq!(capitalize("élan"), "Élan");
        assert_eq!(uuid(&[0; 16]), "00000000-0000-0000-0000-000000000000");
        assert_eq!(fourcc(b"ab\0c"), "ab\\x00c");
        // The variants built on it: QuickTime's ©, and trimmed padding.
        assert_eq!(super::super::vidutil::fourcc(b"\xa9nam\x01"), "©nam\\x01");
        assert_eq!(super::super::sound::fourcc(b"ab  "), "ab");
    }
}
