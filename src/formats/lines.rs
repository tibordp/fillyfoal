//! Line-oriented reading for text formats.
//!
//! [`Lines`] streams a region in chunks and yields one line at a time with
//! its span, so a text dissector can page through a large file without
//! reading it whole. Helpers split lines into fields that keep their spans.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::Head;
use crate::span::Span;

/// Bytes read per refill.
const CHUNK: u64 = 0x4000;
/// Longer lines are cut into pieces of this size.
pub const MAX_LINE: u64 = 0x10000;

/// One line: its bytes (without the terminator) and where it lies.
#[derive(Clone, Debug)]
pub struct Line {
    pub bytes: Vec<u8>,
    /// The line including its terminator.
    pub span: Span,
    /// Offset of the line relative to the region being read.
    pub pos: u64,
}

impl Line {
    /// The line as text (lossily decoded, without `\r\n`).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// The span of the line's content, without the terminator.
    pub fn content(&self) -> Span {
        self.span.sub(0, to_u64(self.bytes.len()))
    }

    /// The span of `len` bytes starting `at` bytes into the line.
    pub fn sub(&self, at: usize, len: usize) -> Span {
        self.content().sub(to_u64(at), to_u64(len))
    }

    /// Fields separated by `sep`, each with its span.
    pub fn split(&self, sep: u8) -> Vec<(String, Span)> {
        let mut out = Vec::new();
        let mut start = 0usize;
        for piece in self.bytes.split(|&b| b == sep) {
            out.push((String::from_utf8_lossy(piece).into_owned(), self.sub(start, piece.len())));
            start = start.saturating_add(piece.len()).saturating_add(1);
        }
        out
    }

    /// Whitespace-separated words, each with its span.
    pub fn words(&self) -> Vec<(String, Span)> {
        let mut out = Vec::new();
        let mut start = None;
        for (i, &b) in self.bytes.iter().enumerate().chain(std::iter::once((self.bytes.len(), &b' '))) {
            let space = b.is_ascii_whitespace();
            match (start, space) {
                (None, false) => start = Some(i),
                (Some(s), true) => {
                    let word = self.bytes.get(s..i).unwrap_or_default();
                    out.push((String::from_utf8_lossy(word).into_owned(), self.sub(s, i.saturating_sub(s))));
                    start = None;
                }
                _ => {}
            }
        }
        out
    }

    /// Fixed columns `[from, to)` (0-based, clamped), trimmed.
    pub fn column(&self, from: usize, to: usize) -> String {
        let end = to.min(self.bytes.len());
        let start = from.min(end);
        String::from_utf8_lossy(self.bytes.get(start..end).unwrap_or_default()).trim().to_owned()
    }
}

/// Streams the lines of a region.
pub struct Lines<'a> {
    cx: &'a Cx,
    region: Span,
    pos: u64,
    buf: Vec<u8>,
    /// Region offset of `buf[0]`.
    buf_at: u64,
}

impl<'a> Lines<'a> {
    pub fn new(cx: &'a Cx, region: Span) -> Self {
        Lines {
            cx,
            region,
            pos: 0,
            buf: Vec::new(),
            buf_at: 0,
        }
    }

    /// Starts reading at `pos` (relative to the region).
    pub fn at(cx: &'a Cx, region: Span, pos: u64) -> Self {
        Lines {
            cx,
            region,
            pos,
            buf: Vec::new(),
            buf_at: pos,
        }
    }

    /// Offset of the next line, relative to the region.
    pub fn pos(&self) -> u64 {
        self.pos
    }

    pub fn region(&self) -> Span {
        self.region
    }

    /// The span from `start` to the current position.
    pub fn since(&self, start: u64) -> Span {
        self.region.sub(start, self.pos.saturating_sub(start))
    }

    /// The next line, or `None` at the end of the region.
    pub async fn next(&mut self) -> Result<Option<Line>> {
        if self.pos >= self.region.len {
            return Ok(None);
        }
        self.cx.checkpoint().await;
        loop {
            let off = to_usize(self.pos.saturating_sub(self.buf_at));
            let avail = self.buf.get(off..).unwrap_or_default();
            if let Some(i) = avail.iter().position(|&b| b == b'\n') {
                return Ok(Some(self.take(off, i, i.saturating_add(1))));
            }
            let buf_end = self.buf_at.saturating_add(to_u64(self.buf.len()));
            if buf_end >= self.region.len || to_u64(avail.len()) >= MAX_LINE {
                let n = avail.len().min(to_usize(MAX_LINE));
                return Ok(Some(self.take(off, n, n)));
            }
            if off > 0 {
                self.buf.drain(..off.min(self.buf.len()));
                self.buf_at = self.pos;
            }
            let data = self.cx.read_avail(self.region.sub(buf_end, CHUNK)).await?;
            if data.is_empty() {
                // The source is shorter than the region claims.
                self.region.len = buf_end;
                if self.pos >= buf_end {
                    return Ok(None);
                }
                continue;
            }
            self.buf.extend_from_slice(&data);
        }
    }

    fn take(&mut self, off: usize, content: usize, consumed: usize) -> Line {
        let mut bytes = self.buf.get(off..off.saturating_add(content)).unwrap_or_default().to_vec();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        let line = Line {
            bytes,
            span: self.region.sub(self.pos, to_u64(consumed)),
            pos: self.pos,
        };
        self.pos = self.pos.saturating_add(to_u64(consumed).max(1));
        line
    }
}

/// The first `n` lines of the probe window, without terminators.
pub fn head_lines<'h>(h: &'h Head<'_>, n: usize) -> Vec<&'h [u8]> {
    let data = h.data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(h.data);
    data.split(|&b| b == b'\n')
        .take(n)
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect()
}

/// Whether the probe window is plain text (no NULs or stray control bytes).
pub fn is_text(h: &Head<'_>) -> bool {
    let sample = h.data.get(..h.data.len().min(4096)).unwrap_or_default();
    !sample.is_empty()
        && sample
            .iter()
            .all(|&b| b >= 0x20 || matches!(b, b'\n' | b'\r' | b'\t' | 0x0c))
}

/// A short, single-line preview of some text.
pub fn preview(s: &str, max: usize) -> String {
    // One line: control characters (newlines, tabs) become spaces.
    let s: String = s.trim().chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let s = s.as_str();
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}

// ---------------------------------------------------------------------------
// Value helpers shared by the science and engineering dissectors.

pub fn text(s: impl Into<String>) -> crate::value::Value {
    crate::value::Value::Text(s.into())
}

pub fn uint(value: u64) -> crate::value::Value {
    crate::value::Value::UInt { value, bits: 64, radix: crate::value::Radix::Dec }
}

pub fn hex(value: u64, bits: u8) -> crate::value::Value {
    crate::value::Value::UInt { value, bits, radix: crate::value::Radix::Hex }
}

pub fn int(value: i64) -> crate::value::Value {
    crate::value::Value::Int { value, bits: 64 }
}

pub fn float(value: f64) -> crate::value::Value {
    crate::value::Value::Float(value)
}

pub fn enumeration(table: crate::value::EnumTable, raw: u64, bits: u8) -> crate::value::Value {
    crate::value::Value::Enum { raw, bits, name: crate::value::lookup(table, raw) }
}

pub fn flags(table: crate::value::FlagTable, raw: u64, bits: u8) -> crate::value::Value {
    let (set, unknown) = crate::value::decode_flags(table, raw);
    crate::value::Value::Flags { raw, bits, set, unknown }
}

/// A number parsed from text: an integer if it is one, else a float, else text.
pub fn number(s: &str) -> crate::value::Value {
    let t = s.trim();
    if let Ok(i) = t.parse::<i64>() {
        int(i)
    } else if let Ok(f) = t.parse::<f64>() {
        float(f)
    } else {
        text(t)
    }
}

/// Counts `key` in a small list of `(key, count)` (at most `cap` keys).
pub fn tally(list: &mut Vec<(String, u64)>, key: &str, cap: usize) {
    if let Some(pos) = list.iter().position(|(k, _)| k == key) {
        if let Some((_, n)) = list.get_mut(pos) {
            *n = n.saturating_add(1);
        }
    } else if list.len() < cap {
        list.push((key.to_owned(), 1));
    }
}

/// Whether `needle` occurs in `hay`.
pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Sets the summary of `node` unless `s` is empty.
pub fn summarize(node: crate::node::Node, s: impl Into<String>) -> crate::node::Node {
    let s = s.into();
    if s.is_empty() { node } else { node.summary(s) }
}

/// A single-precision float, widened without binary noise (0.05, not
/// 0.05000000074505806).
pub fn float32(v: f32) -> crate::value::Value {
    crate::value::Value::Float(v.to_string().parse().unwrap_or(f64::from(v)))
}
