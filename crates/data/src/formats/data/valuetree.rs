//! Shared presentation for the self-describing binary value encodings
//! (MessagePack, BSON, Amazon Ion, Smile, UBJSON): the leaves and container
//! summaries they all build, in the style of the JSON view (keys become
//! node names, scalars typed values, containers lazy nodes with a count),
//! plus number formatting none of them can do with machine integers alone
//! (big integers, decimals) and sub-second timestamps.
//!
//! Each format keeps its own decoder and member walker: their framing
//! (counts, end markers, byte lengths, back-references) has little in
//! common. CBOR predates this module and keeps its own wording.

use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::{clip, grouped_count};
use crate::node::Node;
use crate::value::Value;

/// How deep containers may nest (lazily expanded, so this only bounds
/// what a user can drill into and what scanners keep on their stacks).
pub const MAX_DEPTH: usize = 256;
/// Text shown for a string value; longer strings are cut.
pub const MAX_TEXT: u64 = 0x1000;
/// Bytes shown for a binary value.
pub const MAX_BYTES: u64 = 32;
/// Characters of a key used as a node name.
pub const MAX_KEY: usize = 80;

/// The path for a container at `offset` nested in `path`.
pub fn enter(path: &Path, offset: u64) -> Result<Path> {
    path.enter(offset, MAX_DEPTH)
}

/// `"array, 3 elements"`, or just `"array"` when the count is not known
/// without scanning.
pub fn array_summary(kind: &str, count: Option<u64>) -> String {
    match count {
        Some(n) => format!("{kind}, {}", grouped_count(n, "element", "elements")),
        None => kind.to_owned(),
    }
}

/// `"map, 3 entries"` (or `"object, 3 members"`, with other nouns).
pub fn map_summary(kind: &str, count: Option<u64>, one: &str, many: &str) -> String {
    match count {
        Some(n) => format!("{kind}, {}", grouped_count(n, one, many)),
        None => kind.to_owned(),
    }
}

/// A string leaf from its first bytes (`total` is its full length): lossy
/// UTF-8, with a summary when it was cut and a warning when it is not
/// UTF-8.
pub fn text(node: Node, data: &[u8], total: u64) -> Node {
    let cut = crate::formats::util::datakit::len64(data.len()) < total;
    let valid = match std::str::from_utf8(data) {
        Ok(_) => true,
        // A cut in the middle of a character is not an error.
        Err(e) => cut && e.error_len().is_none(),
    };
    let node = node.value(Value::Text(String::from_utf8_lossy(data).into_owned()));
    let node = if cut {
        node.summary(format!(
            "text, {} (truncated)",
            grouped_count(total, "byte", "bytes")
        ))
    } else {
        node
    };
    if valid {
        node
    } else {
        node.diag(Diagnostic::warning("string is not valid UTF-8"))
    }
}

/// A binary leaf showing the first bytes of `total`.
pub fn bytes(node: Node, kind: &str, data: Vec<u8>, total: u64) -> Node {
    node.value(Value::Bytes(data))
        .summary(format!("{kind}, {}", grouped_count(total, "byte", "bytes")))
}

/// A node name for a map key given as text (empty keys get a placeholder).
pub fn key_name(key: &str, index: u64) -> String {
    if key.is_empty() {
        format!("key #{index}")
    } else {
        clip(key, MAX_KEY)
    }
}

/// Leaf values.
pub use crate::formats::util::val::{int, uint};

/// Decimal digits of a big-endian unsigned magnitude of any length
/// (inputs longer than `MAX_BIG` bytes are described, not converted).
pub fn magnitude_digits(be: &[u8]) -> String {
    const MAX_BIG: usize = 256;
    if be.len() > MAX_BIG {
        return format!("<{}-byte integer>", be.len());
    }
    // Repeated division by 10^9 over base-256 digits.
    let mut num: Vec<u8> = be.iter().copied().skip_while(|&b| b == 0).collect();
    let mut groups: Vec<u32> = Vec::new();
    while !num.is_empty() {
        let mut rem = 0u64;
        let mut next = Vec::with_capacity(num.len());
        for &b in &num {
            let cur = (rem << 8) | u64::from(b);
            let q = cur / 1_000_000_000;
            rem = cur % 1_000_000_000;
            if !(next.is_empty() && q == 0) {
                next.push(u8::try_from(q).unwrap_or(0));
            }
        }
        groups.push(u32::try_from(rem).unwrap_or(0));
        num = next;
    }
    let mut out = match groups.pop() {
        Some(top) => top.to_string(),
        None => return "0".to_owned(),
    };
    for g in groups.iter().rev() {
        out.push_str(&format!("{g:09}"));
    }
    out
}

/// A two's complement big-endian integer of any length, in decimal.
pub fn signed_digits(be: &[u8]) -> String {
    if be.first().is_some_and(|&b| b & 0x80 != 0) {
        // Negate: invert and add one.
        let mut mag: Vec<u8> = be.iter().map(|b| !b).collect();
        for b in mag.iter_mut().rev() {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry {
                break;
            }
        }
        format!("-{}", magnitude_digits(&mag))
    } else {
        magnitude_digits(be)
    }
}

/// A decimal `(-1)^negative × digits × 10^exponent` in the IEEE 754
/// "to-scientific-string" form (as Python's `Decimal` prints it): plain
/// notation for moderate exponents, `1.5E-30` otherwise.
pub fn decimal_string(negative: bool, digits: &str, exponent: i64) -> String {
    let digits = digits.trim_start_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let n = i64::try_from(digits.len()).unwrap_or(i64::MAX);
    let adjusted = exponent.saturating_add(n.saturating_sub(1));
    let sign = if negative { "-" } else { "" };
    if exponent <= 0 && adjusted >= -6 {
        if exponent == 0 {
            return format!("{sign}{digits}");
        }
        let point = n.saturating_add(exponent);
        if point > 0 {
            let at = usize::try_from(point).unwrap_or(0);
            let (int, frac) = digits.split_at(at.min(digits.len()));
            format!("{sign}{int}.{frac}")
        } else {
            let zeros = "0".repeat(usize::try_from(point.saturating_neg()).unwrap_or(0));
            format!("{sign}0.{zeros}{digits}")
        }
    } else {
        let (first, rest) = digits.split_at(1.min(digits.len()));
        let point = if rest.is_empty() { "" } else { "." };
        let esign = if adjusted >= 0 { "+" } else { "" };
        format!("{sign}{first}{point}{rest}E{esign}{adjusted}")
    }
}

/// A UTC date and time with a fraction of a second (`nanos` < 10^9),
/// trimmed to milliseconds or microseconds when the rest is zero.
pub fn datetime(unix_seconds: i64, nanos: u32) -> String {
    let base = crate::render::value(&Value::Timestamp { unix_seconds });
    if nanos == 0 {
        return base;
    }
    let frac = if nanos.is_multiple_of(1_000_000) {
        format!("{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1000) {
        format!("{:06}", nanos / 1000)
    } else {
        format!("{nanos:09}")
    };
    match base.strip_suffix(" UTC") {
        Some(stem) => format!("{stem}.{frac} UTC"),
        None => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_numbers() {
        assert_eq!(magnitude_digits(&[]), "0");
        assert_eq!(magnitude_digits(&[0, 0, 1, 0]), "256");
        let mut two80 = vec![1u8];
        two80.extend([0u8; 10]);
        assert_eq!(magnitude_digits(&two80), "1208925819614629174706176");
        assert_eq!(signed_digits(&[0xff]), "-1");
        assert_eq!(signed_digits(&[0x80, 0]), "-32768");
        assert_eq!(signed_digits(&[0x7f]), "127");
    }

    #[test]
    fn decimals() {
        assert_eq!(decimal_string(false, "12345678", -4), "1234.5678");
        assert_eq!(decimal_string(true, "15", -31), "-1.5E-30");
        assert_eq!(decimal_string(false, "0", -2), "0.00");
        assert_eq!(decimal_string(false, "123", 3), "1.23E+5");
        assert_eq!(decimal_string(false, "5", -7), "5E-7");
        assert_eq!(decimal_string(false, "5", -6), "0.000005");
        assert_eq!(decimal_string(false, "42", 0), "42");
    }

    #[test]
    fn fractions() {
        assert_eq!(datetime(0, 250_000_000), "1970-01-01 00:00:00.250 UTC");
        assert_eq!(
            datetime(0, 123_456_789),
            "1970-01-01 00:00:00.123456789 UTC"
        );
    }
}
