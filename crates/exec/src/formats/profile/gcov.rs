//! GCC coverage files: the notes file written at compile time (`.gcno`:
//! functions, basic blocks, arcs and line tables) and the counts file
//! written when the instrumented program exits (`.gcda`: per-function arc
//! and value-profile counters, run summaries).
//!
//! Both are a header and a flat sequence of tagged records of 32-bit words
//! in the writer's byte order (the magic tells which). GCC 12 changed the
//! layout: record lengths count bytes instead of words, strings are no longer
//! padded to words, headers gained a checksum and an all-zero counter record
//! may be written as a negative length with no body. Older files are read
//! by their version: lengths in words and word-padded strings.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::binutil::{Reader, data_node};
use crate::formats::util::fmt::plural;
use crate::formats::util::lines::flags;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

pub static GCNO: Format = Format {
    name: "gcno",
    title: "GCC coverage notes (gcov)",
    extensions: &["gcno"],
    mime: "application/x-gcov-notes",
    probe: Probe::Custom(|h| probe(h, *b"gcno")),
    dissect: crate::expander!(gcno: Input),
};

pub static GCDA: Format = Format {
    name: "gcda",
    title: "GCC coverage counts (gcov)",
    extensions: &["gcda"],
    mime: "application/x-gcov-data",
    probe: Probe::Custom(|h| probe(h, *b"gcda")),
    dissect: crate::expander!(gcda: Input),
};

const TAG_FUNCTION: u32 = 0x0100_0000;
const TAG_BLOCKS: u32 = 0x0141_0000;
const TAG_ARCS: u32 = 0x0143_0000;
const TAG_LINES: u32 = 0x0145_0000;
const TAG_CONDS: u32 = 0x0147_0000;
const TAG_COUNTER_BASE: u32 = 0x01a1_0000;
const TAG_OBJECT_SUMMARY: u32 = 0xa100_0000;
const TAG_PROGRAM_SUMMARY: u32 = 0xa300_0000;

const TAGS: EnumTable = &[
    (TAG_FUNCTION as u64, "function"),
    (TAG_BLOCKS as u64, "blocks"),
    (TAG_ARCS as u64, "arcs"),
    (TAG_LINES as u64, "lines"),
    (TAG_CONDS as u64, "conditions"),
    (TAG_OBJECT_SUMMARY as u64, "object summary"),
    (TAG_PROGRAM_SUMMARY as u64, "program summary"),
];

/// Counter kinds, in GCC's `gcov-counter.def` order (tag = base + kind << 17).
const COUNTERS: &[&str] = &[
    "arc",
    "interval",
    "power-of-two",
    "top-N",
    "indirect call",
    "average",
    "IOR",
    "time profiler",
];

const ARC_FLAGS: FlagTable = &[
    flag(1, "ON_TREE"),
    flag(2, "FAKE"),
    flag(4, "FALLTHROUGH"),
    flag(8, "TRUE"),
    flag(16, "FALSE"),
];

/// Reads the version word as the four characters GCC writes: `B42*` is
/// GCC 14.2 (the first letter counts tens of the major version from `A`),
/// `407*` GCC 4.7.
fn version(word: u32) -> ([u8; 4], u32, u32) {
    let c = word.to_be_bytes();
    let digit = |b: u8| u32::from(b.wrapping_sub(b'0')).min(9);
    let (major, minor) = match c.first().copied().unwrap_or(0) {
        b @ b'A'..=b'Z' => (
            u32::from(b.wrapping_sub(b'A'))
                .saturating_mul(10)
                .saturating_add(digit(c.get(1).copied().unwrap_or(b'0'))),
            digit(c.get(2).copied().unwrap_or(b'0')),
        ),
        b => (
            digit(b),
            digit(c.get(1).copied().unwrap_or(b'0'))
                .saturating_mul(10)
                .saturating_add(digit(c.get(2).copied().unwrap_or(b'0'))),
        ),
    };
    (c, major, minor)
}

fn probe(h: &Head, magic: [u8; 4]) -> bool {
    let Some(head) = h.data.get(..12) else {
        return false;
    };
    let mut reversed = magic;
    reversed.reverse();
    let endian = if head.starts_with(&magic) {
        Endian::Big
    } else if head.starts_with(&reversed) {
        Endian::Little
    } else {
        return false;
    };
    let Some(word) = crate::formats::util::binutil::get::<u32>(head, 4, endian) else {
        return false;
    };
    let [a, b, c, d] = word.to_be_bytes();
    (a.is_ascii_digit() || a.is_ascii_uppercase())
        && b.is_ascii_digit()
        && c.is_ascii_digit()
        && d.is_ascii_graphic()
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    endian: Endian,
    major: u32,
    notes: bool,
}

impl Layout {
    /// GCC 12 and later: lengths in bytes, unpadded strings, a checksum.
    fn modern(&self) -> bool {
        self.major >= 12
    }

    /// A string: its length (bytes or words) and its bytes. `Some(None)` is
    /// the null string (length 0).
    fn string(&self, r: &mut Reader) -> Option<Option<String>> {
        let len = r.int::<u32>(self.endian)?;
        let n = if self.modern() {
            u64::from(len)
        } else {
            u64::from(len).saturating_mul(4)
        };
        if n == 0 {
            return Some(None);
        }
        let bytes = r.bytes(to_usize(n))?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(Some(
            String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned(),
        ))
    }
}

async fn gcno(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, true).await
}

async fn gcda(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, false).await
}

/// The header: its fields and length.
fn header(data: &[u8], l: &Layout, file: Span) -> (Vec<Node>, u64) {
    let mut r = Reader::new(data);
    let mut nodes = Vec::new();
    let at =
        |r: &Reader, start: usize| file.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
    let start = r.pos();
    if r.bytes(4).is_some() {
        nodes.push(
            Node::new("Magic")
                .span(at(&r, start))
                .value(text(if l.notes { "gcno" } else { "gcda" }))
                .summary(match l.endian {
                    Endian::Little => "little-endian",
                    Endian::Big => "big-endian",
                }),
        );
    }
    let start = r.pos();
    if let Some(v) = r.int::<u32>(l.endian) {
        let (chars, major, minor) = version(v);
        nodes.push(
            Node::new("Version")
                .span(at(&r, start))
                .value(text(String::from_utf8_lossy(&chars).into_owned()))
                .summary(format!("GCC {major}.{minor}")),
        );
    }
    let start = r.pos();
    if let Some(v) = r.int::<u32>(l.endian) {
        nodes.push(
            Node::new("Stamp")
                .span(at(&r, start))
                .value(hex(v, 32))
                .desc("Ties the counts file to the notes file of the same compilation"),
        );
    }
    if l.modern() {
        let start = r.pos();
        if let Some(v) = r.int::<u32>(l.endian) {
            nodes.push(Node::new("Checksum").span(at(&r, start)).value(hex(v, 32)));
        }
    }
    if l.notes && l.major >= 8 {
        let start = r.pos();
        if let Some(cwd) = l.string(&mut r) {
            nodes.push(
                Node::new("Working directory")
                    .span(at(&r, start))
                    .value(text(cwd.unwrap_or_default())),
            );
        }
        let start = r.pos();
        if let Some(v) = r.int::<u32>(l.endian) {
            nodes.push(
                Node::new("Has unexecuted blocks")
                    .span(at(&r, start))
                    .value(crate::value::Value::Bool(v != 0)),
            );
        }
    }
    (nodes, to_u64(r.pos()))
}

async fn header_node(cx: Cx, (l, file): (Layout, Span)) -> Result<()> {
    let data = cx.read_avail(file.sub(0, 0x2000)).await?;
    for node in header(&data, &l, file).0 {
        cx.emit(node);
    }
    Ok(())
}

fn tag_name(tag: u32) -> String {
    if let Some(name) = lookup(TAGS, tag.into()) {
        return name.to_owned();
    }
    if let Some(kind) = counter_kind(tag) {
        return match COUNTERS.get(to_usize(u64::from(kind))) {
            Some(name) => format!("{name} counters"),
            None => format!("counters (kind {kind})"),
        };
    }
    format!("record {tag:#010x}")
}

/// The counter kind of a counts-record tag.
fn counter_kind(tag: u32) -> Option<u32> {
    let off = tag.checked_sub(TAG_COUNTER_BASE)?;
    (off & 0x1_ffff == 0 && off < (32 << 17)).then_some(off >> 17)
}

#[derive(Clone, Debug)]
struct Rec {
    layout: Layout,
    tag: u32,
    span: Span,
    body: Span,
    /// Counters in a record written with a negative length (all zero).
    zeros: Option<u64>,
}

async fn dissect(cx: Cx, input: Input, notes: bool) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x2000)).await?;
    let little = head
        .get(..4)
        .is_some_and(|m| m == if notes { b"oncg" } else { b"adcg" });
    let endian = if little { Endian::Little } else { Endian::Big };
    let word = crate::formats::util::binutil::get::<u32>(&head, 4, endian)
        .ok_or_else(|| Diagnostic::truncated(file.sub(0, 8), to_u64(head.len())))?;
    let (chars, major, minor) = version(word);
    let layout = Layout {
        endian,
        major,
        notes,
    };
    let header_len = header(&head, &layout, file).1;
    cx.annotate(format!(
        "gcov {} (GCC {major}.{minor}, version {})",
        if notes { "notes" } else { "counts" },
        String::from_utf8_lossy(&chars)
    ));
    let mut pos = cx.resume::<u64>().unwrap_or(0);
    if pos == 0 {
        cx.mark(|| 0u64);
        cx.push(
            Node::new("Header")
                .span(file.sub(0, header_len))
                .lazy(header_node, (layout, file)),
        )
        .await;
        pos = header_len;
    }
    while pos < file.len {
        let at = pos;
        cx.mark(move || at);
        let rec = file.sub(pos, 8);
        let bytes = cx.read_avail(rec).await?;
        let mut r = Reader::new(&bytes);
        let (Some(tag), Some(raw_len)) = (r.int::<u32>(endian), r.int::<u32>(endian)) else {
            cx.push(
                Node::new("Trailing bytes")
                    .span(file.tail(pos))
                    .diag(Diagnostic::truncated(rec, to_u64(bytes.len()))),
            )
            .await;
            break;
        };
        let mut zeros = None;
        let signed = i32::from_ne_bytes(raw_len.to_ne_bytes());
        let len = if layout.modern() && counter_kind(tag).is_some() && signed < 0 {
            zeros = Some(u64::from(signed.unsigned_abs()) / 8);
            0
        } else if layout.modern() {
            u64::from(raw_len)
        } else {
            u64::from(raw_len).saturating_mul(4)
        };
        let body = file.sub(pos.saturating_add(8), len);
        let span = file.sub(pos, len.saturating_add(8));
        let mut node = Node::new(tag_name(tag)).span(span);
        if body.len < len {
            let wanted = Span::new(body.source, body.offset, len);
            node = node.diag(Diagnostic::truncated(wanted, body.len));
        }
        let summary = summarize(&cx, &layout, tag, body, zeros).await;
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        let state = Rec {
            layout,
            tag,
            span,
            body,
            zeros,
        };
        cx.push(node.lazy(record, state)).await;
        pos = pos.saturating_add(8).saturating_add(len);
    }
    Ok(())
}

/// A one-line summary of a record, from at most its first 4 KiB.
async fn summarize(cx: &Cx, l: &Layout, tag: u32, body: Span, zeros: Option<u64>) -> String {
    if let Some(n) = zeros {
        return format!("{}, all zero", plural(n, "counter"));
    }
    if counter_kind(tag).is_some() {
        return plural(body.len / 8, "counter");
    }
    let Ok(data) = cx.read_avail(body.sub(0, 4096)).await else {
        return String::new();
    };
    let mut r = Reader::new(&data);
    let e = l.endian;
    match tag {
        TAG_FUNCTION if body.len == 0 => "placeholder (function not emitted)".to_owned(),
        TAG_FUNCTION => {
            let ident = r.int::<u32>(e).unwrap_or(0);
            if !l.notes {
                return format!("ident {ident:#x}");
            }
            r.bytes(8);
            match l.string(&mut r) {
                Some(Some(name)) => {
                    if l.major >= 8 {
                        r.int::<u32>(e);
                    }
                    let file = l.string(&mut r).flatten().unwrap_or_default();
                    let line = r.int::<u32>(e).unwrap_or(0);
                    format!("{name} ({file}:{line}), ident {ident:#x}")
                }
                _ => format!("ident {ident:#x}"),
            }
        }
        TAG_BLOCKS if body.len == 4 && l.major >= 8 => {
            plural(r.int::<u32>(e).unwrap_or(0), "block")
        }
        TAG_BLOCKS => plural(body.len / 4, "block"),
        TAG_ARCS => format!(
            "from block {}, {}",
            r.int::<u32>(e).unwrap_or(0),
            plural(body.len.saturating_sub(4) / 8, "arc")
        ),
        TAG_LINES => {
            let block = r.int::<u32>(e).unwrap_or(0);
            let mut file = String::new();
            let mut lines = Vec::new();
            while let Some(line) = r.int::<u32>(e) {
                if line != 0 {
                    lines.push(line);
                    continue;
                }
                match l.string(&mut r) {
                    Some(Some(name)) if file.is_empty() => file = name,
                    Some(Some(_)) => {}
                    _ => break,
                }
            }
            let range = match (lines.iter().min(), lines.iter().max()) {
                (Some(a), Some(b)) if a == b => format!(":{a}"),
                (Some(a), Some(b)) => format!(":{a}-{b}"),
                _ => String::new(),
            };
            format!("block {block}: {file}{range}")
        }
        TAG_CONDS => plural(body.len / 8, "condition"),
        TAG_OBJECT_SUMMARY if body.len == 8 => {
            let runs = r.int::<u32>(e).unwrap_or(0);
            let max = r.int::<u32>(e).unwrap_or(0);
            format!("{}, largest arc count {max}", plural(runs, "run"))
        }
        _ => String::new(),
    }
}

async fn record(cx: Cx, rec: Rec) -> Result<()> {
    let l = rec.layout;
    let e = l.endian;
    let head = cx.read_avail(rec.span.sub(0, 8)).await?;
    let mut r = Reader::new(&head);
    if let Some(tag) = r.int::<u32>(e) {
        let name = tag_name(tag);
        cx.emit(
            Node::new("Tag")
                .span(rec.span.sub(0, 4))
                .value(hex(tag, 32))
                .summary(name),
        );
    }
    if let Some(len) = r.int::<u32>(e) {
        let mut node = Node::new("Length").span(rec.span.sub(4, 4));
        node = match rec.zeros {
            Some(n) => node
                .value(crate::formats::util::val::int(
                    i32::from_ne_bytes(len.to_ne_bytes()),
                    32,
                ))
                .summary(format!(
                    "negative: {} not written",
                    plural(n, "zero counter")
                )),
            None => node
                .value(uint(len, 32))
                .summary(if l.modern() { "bytes" } else { "words" }),
        };
        cx.emit(node);
    }
    if rec.body.len == 0 {
        return Ok(());
    }
    let body = rec.body;
    let data = cx.read(body).await?;
    let mut r = Reader::new(&data);
    let field =
        |r: &Reader, start: usize| body.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
    if counter_kind(rec.tag).is_some() {
        let mut i = 0u64;
        loop {
            let start = r.pos();
            let (Some(lo), Some(hi)) = (r.int::<u32>(e), r.int::<u32>(e)) else {
                break;
            };
            let v = u64::from(lo) | (u64::from(hi) << 32);
            cx.push(
                Node::new(format!("[{i}]"))
                    .span(field(&r, start))
                    .value(uint(v, 64)),
            )
            .await;
            i = i.saturating_add(1);
        }
        return Ok(());
    }
    match rec.tag {
        TAG_FUNCTION => {
            for name in ["ident", "line number checksum", "CFG checksum"] {
                let start = r.pos();
                let Some(v) = r.int::<u32>(e) else { break };
                cx.emit(Node::new(name).span(field(&r, start)).value(hex(v, 32)));
            }
            if l.notes {
                let start = r.pos();
                if let Some(s) = l.string(&mut r) {
                    cx.emit(
                        Node::new("name")
                            .span(field(&r, start))
                            .value(text(s.unwrap_or_default())),
                    );
                }
                if l.major >= 8 {
                    let start = r.pos();
                    if let Some(v) = r.int::<u32>(e) {
                        cx.emit(
                            Node::new("artificial")
                                .span(field(&r, start))
                                .value(crate::value::Value::Bool(v != 0))
                                .desc("Compiler-generated (a constructor, a thunk)"),
                        );
                    }
                }
                let start = r.pos();
                if let Some(s) = l.string(&mut r) {
                    cx.emit(
                        Node::new("source")
                            .span(field(&r, start))
                            .value(text(s.unwrap_or_default())),
                    );
                }
                for name in ["start line", "start column", "end line", "end column"] {
                    let start = r.pos();
                    let Some(v) = r.int::<u32>(e) else { break };
                    cx.emit(Node::new(name).span(field(&r, start)).value(uint(v, 32)));
                }
            }
        }
        TAG_BLOCKS if data.len() == 4 && l.major >= 8 => {
            if let Some(v) = r.int::<u32>(e) {
                cx.emit(Node::new("blocks").span(body).value(uint(v, 32)));
            }
        }
        TAG_BLOCKS => {
            let mut i = 0u64;
            loop {
                let start = r.pos();
                let Some(v) = r.int::<u32>(e) else { break };
                cx.push(
                    Node::new(format!("block {i}"))
                        .span(field(&r, start))
                        .value(hex(v, 32)),
                )
                .await;
                i = i.saturating_add(1);
            }
        }
        TAG_ARCS => {
            let start = r.pos();
            if let Some(src) = r.int::<u32>(e) {
                cx.emit(
                    Node::new("source block")
                        .span(field(&r, start))
                        .value(uint(src, 32)),
                );
            }
            loop {
                let start = r.pos();
                let (Some(dest), Some(fl)) = (r.int::<u32>(e), r.int::<u32>(e)) else {
                    break;
                };
                cx.push(
                    Node::new(format!("arc to block {dest}"))
                        .span(field(&r, start))
                        .value(flags(ARC_FLAGS, fl.into(), 32)),
                )
                .await;
            }
        }
        TAG_LINES => {
            let start = r.pos();
            if let Some(block) = r.int::<u32>(e) {
                cx.emit(
                    Node::new("block")
                        .span(field(&r, start))
                        .value(uint(block, 32)),
                );
            }
            loop {
                let start = r.pos();
                let Some(line) = r.int::<u32>(e) else { break };
                if line != 0 {
                    cx.push(
                        Node::new("line")
                            .span(field(&r, start))
                            .value(uint(line, 32)),
                    )
                    .await;
                    continue;
                }
                match l.string(&mut r) {
                    Some(Some(name)) => {
                        cx.push(Node::new("file").span(field(&r, start)).value(text(name)))
                            .await;
                    }
                    Some(None) => {
                        cx.push(Node::new("end").span(field(&r, start))).await;
                        break;
                    }
                    None => {
                        cx.push(
                            Node::new("file")
                                .span(field(&r, start))
                                .diag(Diagnostic::malformed("truncated file name")),
                        )
                        .await;
                        break;
                    }
                }
            }
        }
        TAG_CONDS => loop {
            let start = r.pos();
            let (Some(block), Some(terms)) = (r.int::<u32>(e), r.int::<u32>(e)) else {
                break;
            };
            cx.push(
                Node::new(format!("block {block}"))
                    .span(field(&r, start))
                    .value(uint(terms, 32))
                    .summary(plural(terms, "term")),
            )
            .await;
        },
        TAG_OBJECT_SUMMARY if data.len() == 8 => {
            for name in ["runs", "largest arc count"] {
                let start = r.pos();
                let Some(v) = r.int::<u32>(e) else { break };
                cx.emit(Node::new(name).span(field(&r, start)).value(uint(v, 32)));
            }
        }
        _ => cx.emit(data_node("Data", body, body.len)),
    }
    let rest = to_u64(r.pos());
    if rest < body.len && !matches!(rec.tag, TAG_OBJECT_SUMMARY | TAG_PROGRAM_SUMMARY) {
        cx.emit(data_node(
            "Unparsed",
            body.tail(rest),
            body.len.saturating_sub(rest),
        ));
    }
    Ok(())
}
