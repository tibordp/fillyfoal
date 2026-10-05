//! Small helpers shared by the archive and compression dissectors: typed
//! values, sizes, text-encoded numbers (tar, cpio, ar), Unix modes, and the
//! checksums these formats use.

use std::borrow::Cow;
use std::sync::Arc;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Field, Fields};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

pub fn uint(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    }
}

pub fn hex(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Hex,
    }
}

pub fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// A byte count for summaries: `"512 bytes"`, `"1.2 MiB"`.
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if n < 1024 {
        return if n == 1 {
            "1 byte".to_owned()
        } else {
            format!("{n} bytes")
        };
    }
    let mut value = n as f64 / 1024.0;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < 5 {
        value /= 1024.0;
        unit = unit.saturating_add(1);
    }
    let name = UNITS.get(unit).copied().unwrap_or("EiB");
    format!("{value:.1} {name}")
}

/// `"1 entry"`, `"3 entries"`.
pub fn count(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// A leaf for data compressed with a codec we do not decode. It keeps the
/// span, so the bytes stay reachable.
pub fn unsupported(name: impl Into<Cow<'static, str>>, span: Span, codec: &str) -> Node {
    Node::new(name)
        .span(span)
        .summary(human_size(span.len))
        .diag(Diagnostic::unsupported(format!("{codec} compression")))
}

/// Expander that emits pre-built nodes: for small groups decoded together
/// with their parent (e.g. the fields of a varint-encoded record).
pub async fn emit_nodes(cx: Cx, nodes: Arc<Vec<Node>>) -> Result<()> {
    for node in nodes.iter() {
        cx.emit(node.clone());
    }
    Ok(())
}

/// Adds a truncation diagnostic if `span` is shorter than `wanted`.
pub fn check_len(node: Node, span: Span, wanted: u64) -> Node {
    if span.len < wanted {
        node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, wanted),
            span.len,
        ))
    } else {
        node
    }
}

/// Parses an ASCII number in `radix`, ignoring surrounding spaces and NULs.
/// Empty fields are zero.
pub fn parse_ascii(bytes: &[u8], radix: u32) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.trim_matches(|c: char| c == ' ' || c == '\0');
    // Old tar writers terminate with a NUL and then pad with garbage.
    let text = text.split('\0').next().unwrap_or_default().trim();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, radix).ok()
}

/// Tar numbers: octal ASCII, or GNU base-256 (high bit of the first byte).
pub fn parse_tar_number(bytes: &[u8]) -> Option<u64> {
    match bytes.first() {
        Some(&b) if b & 0x80 != 0 => {
            if b & 0x40 != 0 {
                return None; // negative
            }
            let mut v = u64::from(b & 0x3f);
            for &byte in bytes.get(1..).unwrap_or_default() {
                v = v.checked_mul(256)?.checked_add(u64::from(byte))?;
            }
            Some(v)
        }
        _ => parse_ascii(bytes, 8),
    }
}

/// How a text-encoded number is presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Num {
    Dec,
    Hex,
    /// Octal text: shown as a number with the octal form in the summary.
    Oct,
    /// Unix permission bits and file type.
    Mode,
    /// Seconds since the Unix epoch.
    Time,
}

/// A text-encoded number (`radix` 8, 10 or 16; 8 also accepts tar's
/// base-256 form) of `len` bytes. The value is `None` if the text is not a
/// number; the node then shows the raw text and a diagnostic.
pub fn ascii_num<'a>(
    f: &mut Fields<'a>,
    name: &'static str,
    len: u64,
    radix: u32,
    show: Num,
) -> Field<'a, Option<u64>> {
    let parse = move |b: &[u8]| {
        if radix == 8 {
            parse_tar_number(b)
        } else {
            parse_ascii(b, radix)
        }
    };
    f.bytes(name, len)
        .with(move |b, node| match parse(b) {
            Some(v) => present(node, v, show),
            None => node
                .value(text(crate::text::until_nul(b)))
                .diag(Diagnostic::malformed("not a number")),
        })
        .map(move |b| parse(&b))
}

/// Puts `v` on `node` according to `show`.
pub fn present(node: Node, v: u64, show: Num) -> Node {
    match show {
        Num::Dec => node.value(uint(v)),
        Num::Hex => node.value(hex(v)),
        Num::Oct => node.value(uint(v)).summary(format!("0o{v:o}")),
        Num::Mode => node
            .value(uint(v))
            .summary(format!("0o{v:o} {}", unix_mode(v))),
        Num::Time => node.value(Value::Timestamp {
            unix_seconds: i64::try_from(v).unwrap_or(i64::MAX),
        }),
    }
}

/// `ls -l` style rendering of a Unix mode, e.g. `drwxr-xr-x`.
pub fn unix_mode(mode: u64) -> String {
    let kind = match mode & 0o170_000 {
        0o140_000 => 's',
        0o120_000 => 'l',
        0o100_000 => '-',
        0o060_000 => 'b',
        0o040_000 => 'd',
        0o020_000 => 'c',
        0o010_000 => 'p',
        _ => '-',
    };
    let mut out = String::with_capacity(10);
    out.push(kind);
    let bit = |b: u64, c: char| if mode & b != 0 { c } else { '-' };
    let special = |b: u64, x: u64, set: char, unset: char| match (mode & b != 0, mode & x != 0) {
        (true, true) => set,
        (true, false) => unset,
        (false, true) => 'x',
        (false, false) => '-',
    };
    out.push(bit(0o400, 'r'));
    out.push(bit(0o200, 'w'));
    out.push(special(0o4000, 0o100, 's', 'S'));
    out.push(bit(0o040, 'r'));
    out.push(bit(0o020, 'w'));
    out.push(special(0o2000, 0o010, 's', 'S'));
    out.push(bit(0o004, 'r'));
    out.push(bit(0o002, 'w'));
    out.push(special(0o1000, 0o001, 't', 'T'));
    out
}

/// What a Unix mode's file type bits say, for summaries.
pub fn unix_kind(mode: u64) -> &'static str {
    match mode & 0o170_000 {
        0o140_000 => "socket",
        0o120_000 => "symlink",
        0o100_000 => "file",
        0o060_000 => "block device",
        0o040_000 => "directory",
        0o020_000 => "character device",
        0o010_000 => "FIFO",
        _ => "entry",
    }
}

/// CRC-16/ARC (polynomial 0x8005, reflected), used by LHA, ARC, ZOO and
/// StuffIt.
pub fn crc16_arc(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                crc >> 1 ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// CRC-32C (Castagnoli), used by Snappy framing.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                crc >> 1 ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// xxHash32, used by the LZ4 frame format for its header checksum.
pub fn xxh32(data: &[u8], seed: u32) -> u32 {
    const P1: u32 = 2_654_435_761;
    const P2: u32 = 2_246_822_519;
    const P3: u32 = 3_266_489_917;
    const P4: u32 = 668_265_263;
    const P5: u32 = 374_761_393;
    let round = |acc: u32, input: u32| {
        acc.wrapping_add(input.wrapping_mul(P2))
            .rotate_left(13)
            .wrapping_mul(P1)
    };
    let word = |c: &[u8]| {
        let mut b = [0u8; 4];
        b.copy_from_slice(c.get(..4).unwrap_or(&[0; 4]));
        u32::from_le_bytes(b)
    };
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let (stripes, rest) = data.as_chunks::<16>();
    let mut h = if stripes.is_empty() {
        seed.wrapping_add(P5)
    } else {
        let mut v = [
            seed.wrapping_add(P1).wrapping_add(P2),
            seed.wrapping_add(P2),
            seed,
            seed.wrapping_sub(P1),
        ];
        for stripe in stripes {
            for (lane, chunk) in v.iter_mut().zip(stripe.chunks(4)) {
                *lane = round(*lane, word(chunk));
            }
        }
        let [a, b, c, d] = v;
        a.rotate_left(1)
            .wrapping_add(b.rotate_left(7))
            .wrapping_add(c.rotate_left(12))
            .wrapping_add(d.rotate_left(18))
    };
    h = h.wrapping_add(len);
    let (words, bytes) = rest.as_chunks::<4>();
    for w in words {
        h = h
            .wrapping_add(u32::from_le_bytes(*w).wrapping_mul(P3))
            .rotate_left(17)
            .wrapping_mul(P4);
    }
    for &b in bytes {
        h = h
            .wrapping_add(u32::from(b).wrapping_mul(P5))
            .rotate_left(11)
            .wrapping_mul(P1);
    }
    h ^= h >> 15;
    h = h.wrapping_mul(P2);
    h ^= h >> 13;
    h = h.wrapping_mul(P3);
    h ^= h >> 16;
    h
}

/// Decodes fields from bytes already in memory and collects a node (with
/// its span) for each: for variable layouts, such as varint-encoded headers,
/// that [`Fields`] does not cover. Every reader method returns `None` when
/// the data runs out.
pub struct ByteReader<'a> {
    pub data: &'a [u8],
    pub base: Span,
    pub at: usize,
    pub nodes: Vec<Node>,
}

impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8], base: Span) -> Self {
        ByteReader {
            data,
            base,
            at: 0,
            nodes: Vec::new(),
        }
    }

    /// The span from `start` (relative) to the current position.
    pub fn since(&self, start: usize) -> Span {
        self.base.sub(
            crate::bytes::to_u64(start),
            crate::bytes::to_u64(self.at.saturating_sub(start)),
        )
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.at)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let bytes = self.data.get(self.at..end)?;
        self.at = end;
        Some(bytes)
    }

    fn field(&mut self, name: &'static str, start: usize, value: Value) {
        let span = self.since(start);
        self.nodes.push(Node::new(name).span(span).value(value));
    }

    /// Applies `f` to the most recently read field's node.
    pub fn with(&mut self, f: impl FnOnce(Node) -> Node) {
        if let Some(node) = self.nodes.pop() {
            self.nodes.push(f(node));
        }
    }

    pub fn push(&mut self, node: Node) {
        self.nodes.push(node);
    }

    pub fn u8(&mut self, name: &'static str) -> Option<u8> {
        let start = self.at;
        let v = *self.take(1)?.first()?;
        self.field(name, start, uint(v.into()));
        Some(v)
    }

    pub fn u16(&mut self, name: &'static str, endian: Endian) -> Option<u16> {
        let start = self.at;
        let b: [u8; 2] = self.take(2)?.try_into().ok()?;
        let v = match endian {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        };
        self.field(name, start, uint(v.into()));
        Some(v)
    }

    pub fn u32(&mut self, name: &'static str, endian: Endian) -> Option<u32> {
        let start = self.at;
        let b: [u8; 4] = self.take(4)?.try_into().ok()?;
        let v = match endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        };
        self.field(name, start, uint(v.into()));
        Some(v)
    }

    pub fn u64(&mut self, name: &'static str, endian: Endian) -> Option<u64> {
        let start = self.at;
        let b: [u8; 8] = self.take(8)?.try_into().ok()?;
        let v = match endian {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        };
        self.field(name, start, uint(v));
        Some(v)
    }

    /// An unsigned LEB128 value ("vint" in RAR 5, "multibyte integer" in xz).
    pub fn vint(&mut self, name: &'static str) -> Option<u64> {
        let start = self.at;
        let rest = self.data.get(self.at..)?;
        let (v, len) = crate::bytes::uleb128(rest)?;
        self.at = self.at.checked_add(len)?;
        self.field(name, start, uint(v));
        Some(v)
    }

    pub fn bytes(&mut self, name: &'static str, n: u64) -> Option<&'a [u8]> {
        let start = self.at;
        let b = self.take(crate::bytes::to_usize(n))?;
        self.field(name, start, Value::Bytes(b.to_vec()));
        Some(b)
    }

    /// Text of `n` bytes, decoded lossily as UTF-8.
    pub fn text(&mut self, name: &'static str, n: u64) -> Option<String> {
        let start = self.at;
        let b = self.take(crate::bytes::to_usize(n))?;
        let s = String::from_utf8_lossy(b).into_owned();
        self.field(name, start, text(s.clone()));
        Some(s)
    }

    /// Skips `n` bytes without a node.
    pub fn skip(&mut self, n: u64) -> Option<()> {
        self.take(crate::bytes::to_usize(n)).map(|_| ())
    }

    /// The collected nodes, for [`emit_nodes`].
    pub fn into_nodes(self) -> Arc<Vec<Node>> {
        Arc::new(self.nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums() {
        assert_eq!(crc16_arc(b"123456789"), 0xbb3d);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(xxh32(b"", 0), 0x02cc_5d05);
        assert_eq!(
            xxh32(b"Nobody inspects the spammish repetition", 0),
            0xe229_3b2f
        );
    }

    #[test]
    fn numbers() {
        assert_eq!(parse_tar_number(b"0000644\0"), Some(0o644));
        assert_eq!(parse_tar_number(b"      \0 "), Some(0));
        assert_eq!(parse_tar_number(&[0x80, 0, 0, 1, 0]), Some(256));
        assert_eq!(parse_ascii(b"1f", 16), Some(31));
        assert_eq!(unix_mode(0o100_644), "-rw-r--r--");
        assert_eq!(unix_mode(0o041_777), "drwxrwxrwt");
        assert_eq!(human_size(1536), "1.5 KiB");
    }
}
