//! Small helpers shared by the executable and bytecode dissectors.

use std::borrow::Cow;

use crate::bytes::to_usize;
use crate::error::Diagnostic;
use crate::fields::{Endian, Prim};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

/// Decodes a `T` at `offset` in `data` with the given byte order.
pub fn get<T: Prim>(data: &[u8], offset: usize, endian: Endian) -> Option<T> {
    let end = offset.checked_add(T::SIZE)?;
    T::decode(data.get(offset..end)?, endian)
}

/// Like [`get`], with a `u64` offset.
pub fn get_at<T: Prim>(data: &[u8], offset: u64, endian: Endian) -> Option<T> {
    get(data, to_usize(offset), endian)
}

/// A hexadecimal unsigned value.
pub fn hex(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Hex,
    }
}

/// A decimal unsigned value.
pub fn dec(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

pub fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// An enumerated value.
pub fn enumerated(table: EnumTable, raw: u64, bits: u8) -> Value {
    Value::Enum {
        raw,
        bits,
        name: lookup(table, raw),
    }
}

/// The table's name for `raw`, or `"<prefix> <raw:#x>"`.
pub fn name_or(table: EnumTable, raw: u64, prefix: &str) -> String {
    lookup(table, raw).map_or_else(|| format!("{prefix} {raw:#x}"), str::to_owned)
}

/// A leaf for raw bytes that were expected to be `wanted` long, with a
/// truncation diagnostic if the region was clamped.
pub fn data_node(name: impl Into<Cow<'static, str>>, span: Span, wanted: u64) -> Node {
    let node = Node::new(name).span(span);
    if span.len < wanted {
        node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, wanted),
            span.len,
        ))
    } else {
        node
    }
}

/// Lower-case hex digits of `bytes`, without separators.
pub fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `"rwx"`-style permission letters.
pub fn perms(read: bool, write: bool, exec: bool) -> String {
    [(read, 'r'), (write, 'w'), (exec, 'x')]
        .iter()
        .map(|&(on, c)| if on { c } else { '-' })
        .collect()
}

/// A short, printable rendering of a string for summaries.
pub fn ellipsize(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Modified UTF-8 (Java class files, DEX): like UTF-8, but NUL is encoded
/// as `C0 80` and supplementary characters as surrogate pairs. Decoded
/// leniently.
pub fn mutf8(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut it = bytes.iter().copied();
    while let Some(a) = it.next() {
        let unit = if a & 0x80 == 0 {
            u16::from(a)
        } else if a & 0xe0 == 0xc0 {
            let b = it.next().unwrap_or(0);
            (u16::from(a & 0x1f) << 6) | u16::from(b & 0x3f)
        } else if a & 0xf0 == 0xe0 {
            let b = it.next().unwrap_or(0);
            let c = it.next().unwrap_or(0);
            (u16::from(a & 0x0f) << 12) | (u16::from(b & 0x3f) << 6) | u16::from(c & 0x3f)
        } else {
            0xfffd
        };
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutf8_decodes_nul_and_surrogates() {
        assert_eq!(mutf8(b"a\xc0\x80b"), "a\0b");
        assert_eq!(mutf8(b"\xed\xa0\xbd\xed\xb8\x80"), "\u{1f600}");
        assert_eq!(hex_string(&[0xde, 0xad]), "dead");
        assert_eq!(ellipsize("abcdef", 3), "abc…");
    }
}
