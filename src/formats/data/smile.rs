//! Smile (`.sml`), the binary JSON of Jackson and Elasticsearch: a `:)\n`
//! header with a version and flags byte, then JSON values as one-byte
//! tokens. Short strings, small integers and short property names fit in
//! the token byte; longer strings end with `0xFC`; integers are
//! zigzag-encoded variable-length ("VInt": 7 bits per byte, the last byte
//! marked and holding 6); floats, big numbers and (unless raw binary is
//! enabled) binary data are spread over 7-bit bytes so no data byte has
//! the high bit set where a marker could be expected. Arrays and objects
//! are delimited by start and end tokens, and keys and values are read in
//! different token "modes".
//!
//! When the header enables them, property names and short string values
//! (up to 64 bytes) are remembered in two tables of up to 1024 entries
//! (cleared when full) and later written as back-references by index.
//! Resolving a reference needs every string before it, so with sharing
//! enabled the first expansion scans the whole stream once and keeps where
//! each table entry and each reference is (cached); nested containers are
//! still listed lazily. The table rules (64-byte limit for both tables,
//! clearing at 1024) follow the Smile specification as Jackson implements
//! it; the fixtures come from smile-js, which agrees.

use std::sync::Arc;

use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::ByteReader;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

use super::valuetree as vt;

pub static FORMAT: Format = Format {
    name: "smile",
    title: "Smile binary JSON",
    extensions: &["sml", "smile"],
    mime: "application/x-jackson-smile",
    // Version 0 in the high nibble; bit 3 is reserved.
    probe: Probe::Custom(|h| {
        h.starts_with(b":)\n") && h.data.get(3).is_some_and(|&b| b & 0xf8 == 0)
    }),
    dissect: crate::expander!(dissect: Input),
};

const FLAGS: FlagTable = &[
    flag(0x01, "shared property names"),
    flag(0x02, "shared string values"),
    flag(0x04, "raw binary"),
];

/// Longest string kept in a shared table, and table size.
const MAX_SHARED_LEN: u64 = 64;
const MAX_SHARED: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tok {
    /// Back-reference to a shared string value.
    SharedValue(u64),
    Empty,
    Null,
    Bool(bool),
    Int(i64, u8),
    BigInt(u64),
    Float32(u32),
    Float64(u64),
    BigDecimal(i64, u64),
    /// A string: ASCII or not, terminated by `0xFC` (long) or not.
    Text {
        long: bool,
    },
    Binary7(u64),
    RawBinary,
    StartArray,
    StartObject,
    EndArray,
    EndObject,
    EndOfContent,
    Header,
    /// Key-mode tokens.
    SharedName(u64),
    Name {
        long: bool,
    },
}

/// A decoded token: `head` bytes before its payload of `payload` bytes,
/// `len` bytes in all (with any terminator).
#[derive(Clone, Copy, Debug)]
struct Token {
    tok: Tok,
    head: u64,
    payload: u64,
    len: u64,
}

fn bad(r: &ByteReader<'_>, at: u64, msg: impl Into<String>) -> Diagnostic {
    Diagnostic::malformed(msg).at(r.span(at, 1))
}

/// A VInt at `at`: `(value, bytes)`.
async fn vint(r: &mut ByteReader<'_>, at: u64) -> Result<(u64, u64)> {
    let mut acc = 0u64;
    for i in 0..10u64 {
        let b = r.byte(at.saturating_add(i)).await?;
        if acc > u64::MAX >> 7 {
            break;
        }
        if b & 0x80 != 0 {
            return Ok(((acc << 6) | u64::from(b & 0x3f), i.saturating_add(1)));
        }
        acc = (acc << 7) | u64::from(b);
    }
    Err(bad(r, at, "variable-length integer too long"))
}

fn zigzag(v: u64) -> i64 {
    let half = i64::try_from(v >> 1).unwrap_or(i64::MAX);
    if v & 1 == 0 {
        half
    } else {
        half.saturating_neg().saturating_sub(1)
    }
}

/// Encoded size of `raw` bytes in 7-bit form.
fn seven_bit_len(raw: u64) -> u64 {
    let rem = raw % 7;
    (raw / 7)
        .saturating_mul(8)
        .saturating_add(if rem == 0 { 0 } else { rem.saturating_add(1) })
}

/// Unpacks 7-bit encoded bytes (whole groups of 8, then a final group of
/// `n + 1` bytes for `n` remaining bytes, the last holding `n` bits).
fn unpack7(enc: &[u8], raw: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw);
    for group in enc.chunks(8) {
        let left = raw.saturating_sub(out.len());
        if left == 0 {
            break;
        }
        let n = left.min(7);
        let (body, last_bits) = if group.len() == 8 && n == 7 {
            (group, 7u32)
        } else {
            (
                group.get(..n.saturating_add(1)).unwrap_or(group),
                u32::try_from(n).unwrap_or(0),
            )
        };
        let mut acc: u64 = 0;
        let count = body.len();
        for (i, &b) in body.iter().enumerate() {
            let bits = if i.saturating_add(1) == count {
                last_bits
            } else {
                7
            };
            acc = (acc << bits) | (u64::from(b) & ((1u64 << bits).saturating_sub(1)));
        }
        let total_bytes = body.len().saturating_sub(1);
        for i in (0..total_bytes).rev() {
            out.push(
                u8::try_from(
                    acc.checked_shr(u32::try_from(i.saturating_mul(8)).unwrap_or(64))
                        .unwrap_or(0)
                        & 0xff,
                )
                .unwrap_or(0),
            );
        }
    }
    out.truncate(raw);
    out
}

/// Folds 7-bit groups into an integer (floats).
fn fold7(b: &[u8]) -> u64 {
    b.iter()
        .fold(0u64, |acc, &x| (acc << 7) | u64::from(x & 0x7f))
}

/// The offset of the `0xFC` ending a long string that starts at `at`.
async fn find_end_marker(r: &mut ByteReader<'_>, at: u64) -> Result<u64> {
    let len = r.region().len;
    let mut pos = at;
    while pos < len {
        let window = r.bytes(pos, len.saturating_sub(pos).min(0x1000)).await?;
        if let Some(i) = window.iter().position(|&b| b == 0xfc) {
            return Ok(pos.saturating_add(vt_len(i)));
        }
        pos = pos.saturating_add(vt_len(window.len()));
        r.cx().checkpoint().await;
    }
    Err(Diagnostic::truncated(
        r.span(at, len.saturating_sub(at).saturating_add(1)),
        len.saturating_sub(at),
    ))
}

fn vt_len(n: usize) -> u64 {
    crate::formats::util::datakit::len64(n)
}

fn token(tok: Tok, head: u64, payload: u64) -> Token {
    Token {
        tok,
        head,
        payload,
        len: head.saturating_add(payload),
    }
}

/// The value-mode token at `at`.
async fn value_token(r: &mut ByteReader<'_>, at: u64) -> Result<Token> {
    let t = r.byte(at).await?;
    let next = at.saturating_add(1);
    Ok(match t {
        0x00 => return Err(bad(r, at, "token 0x00 is not used")),
        0x01..=0x1f => token(Tok::SharedValue(u64::from(t).saturating_sub(1)), 1, 0),
        0x20 => token(Tok::Empty, 1, 0),
        0x21 => token(Tok::Null, 1, 0),
        0x22 | 0x23 => token(Tok::Bool(t == 0x23), 1, 0),
        0x24 | 0x25 => {
            let (v, n) = vint(r, next).await?;
            let bits = if t == 0x24 { 32 } else { 64 };
            token(Tok::Int(zigzag(v), bits), n.saturating_add(1), 0)
        }
        0x26 => {
            let (raw, n) = vint(r, next).await?;
            token(Tok::BigInt(raw), n.saturating_add(1), seven_bit_len(raw))
        }
        0x28 => {
            let b = r.bytes(next, 5).await?;
            token(
                Tok::Float32(u32::try_from(fold7(&b) & 0xffff_ffff).unwrap_or(0)),
                6,
                0,
            )
        }
        0x29 => {
            let b = r.bytes(next, 10).await?;
            token(Tok::Float64(fold7(&b)), 11, 0)
        }
        0x2a => {
            let (scale, n1) = vint(r, next).await?;
            let (raw, n2) = vint(r, next.saturating_add(n1)).await?;
            let scale = zigzag(scale);
            token(
                Tok::BigDecimal(scale, raw),
                n1.saturating_add(n2).saturating_add(1),
                seven_bit_len(raw),
            )
        }
        0x3a => token(Tok::Header, 4, 0),
        0x40..=0x5f => token(
            Tok::Text { long: false },
            1,
            u64::from(t & 0x1f).saturating_add(1),
        ),
        0x60..=0x7f => token(
            Tok::Text { long: false },
            1,
            u64::from(t & 0x1f).saturating_add(33),
        ),
        0x80..=0x9f => token(
            Tok::Text { long: false },
            1,
            u64::from(t & 0x1f).saturating_add(2),
        ),
        0xa0..=0xbf => token(
            Tok::Text { long: false },
            1,
            u64::from(t & 0x1f).saturating_add(34),
        ),
        0xc0..=0xdf => token(Tok::Int(zigzag(u64::from(t & 0x1f)), 5), 1, 0),
        0xe0 | 0xe4 => {
            let end = find_end_marker(r, next).await?;
            let payload = end.saturating_sub(next);
            Token {
                tok: Tok::Text { long: true },
                head: 1,
                payload,
                len: payload.saturating_add(2),
            }
        }
        0xe8 => {
            let (raw, n) = vint(r, next).await?;
            token(Tok::Binary7(raw), n.saturating_add(1), seven_bit_len(raw))
        }
        0xec..=0xef => {
            let low = r.byte(next).await?;
            token(
                Tok::SharedValue((u64::from(t & 3) << 8) | u64::from(low)),
                2,
                0,
            )
        }
        0xf8 => token(Tok::StartArray, 1, 0),
        0xf9 => token(Tok::EndArray, 1, 0),
        0xfa => token(Tok::StartObject, 1, 0),
        0xfb => token(Tok::EndObject, 1, 0),
        0xfd => {
            let (len, n) = vint(r, next).await?;
            token(Tok::RawBinary, n.saturating_add(1), len)
        }
        0xff => token(Tok::EndOfContent, 1, 0),
        _ => return Err(bad(r, at, format!("reserved value token {t:#04x}"))),
    })
}

/// The key-mode token at `at`.
async fn key_token(r: &mut ByteReader<'_>, at: u64) -> Result<Token> {
    let t = r.byte(at).await?;
    let next = at.saturating_add(1);
    Ok(match t {
        0x20 => token(Tok::Empty, 1, 0),
        0x30..=0x33 => {
            let low = r.byte(next).await?;
            token(
                Tok::SharedName((u64::from(t & 3) << 8) | u64::from(low)),
                2,
                0,
            )
        }
        0x34 => {
            let end = find_end_marker(r, next).await?;
            let payload = end.saturating_sub(next);
            Token {
                tok: Tok::Name { long: true },
                head: 1,
                payload,
                len: payload.saturating_add(2),
            }
        }
        0x40..=0x7f => token(Tok::SharedName(u64::from(t & 0x3f)), 1, 0),
        0x80..=0xbf => token(
            Tok::Name { long: false },
            1,
            u64::from(t & 0x3f).saturating_add(1),
        ),
        0xc0..=0xf7 => token(
            Tok::Name { long: false },
            1,
            u64::from(t & 0x3f).saturating_add(2),
        ),
        0xfb => token(Tok::EndObject, 1, 0),
        _ => return Err(bad(r, at, format!("invalid key token {t:#04x}"))),
    })
}

/// Where every shared-table entry and back-reference is, for resolving
/// references anywhere in the stream.
#[derive(Default)]
struct Shared {
    /// `(offset, length)` of each string added to a table.
    entries: Vec<(u64, u64)>,
    /// `(offset of a reference token, index into entries)`, by offset.
    refs: Vec<(u64, u32)>,
    /// Why the scan stopped early, if it did.
    error: Option<Diagnostic>,
}

impl Shared {
    fn lookup(&self, at: u64) -> Option<(u64, u64)> {
        let i = self.refs.binary_search_by_key(&at, |&(o, _)| o).ok()?;
        let &(_, e) = self.refs.get(i)?;
        self.entries.get(usize::try_from(e).ok()?).copied()
    }
}

/// One of the two tables during the scan: indices into `Shared::entries`.
struct Table {
    enabled: bool,
    slots: Vec<u32>,
}

impl Table {
    fn add(&mut self, shared: &mut Shared, at: u64, len: u64) {
        if !self.enabled || len > MAX_SHARED_LEN || len == 0 {
            return;
        }
        if self.slots.len() >= MAX_SHARED {
            self.slots.clear();
        }
        self.slots
            .push(u32::try_from(shared.entries.len()).unwrap_or(u32::MAX));
        shared.entries.push((at, len));
    }
    fn reference(&self, shared: &mut Shared, at: u64, index: u64) {
        if let Some(&e) = usize::try_from(index).ok().and_then(|i| self.slots.get(i)) {
            shared.refs.push((at, e));
        }
    }
}

async fn scan_shared(r: &mut ByteReader<'_>) -> Shared {
    let mut shared = Shared::default();
    if let Err(e) = scan(r, &mut shared).await {
        shared.error = Some(e);
    }
    shared
}

/// Walks every token of the stream, recording table entries and
/// references.
async fn scan(r: &mut ByteReader<'_>, shared: &mut Shared) -> Result<()> {
    let len = r.region().len;
    let mut names = Table {
        enabled: false,
        slots: Vec::new(),
    };
    let mut values = Table {
        enabled: false,
        slots: Vec::new(),
    };
    // Containers open: true for objects.
    let mut stack: Vec<bool> = Vec::new();
    let mut expect_key = false;
    let mut pos = 0u64;
    while pos < len {
        r.cx().checkpoint().await;
        if expect_key {
            let k = key_token(r, pos).await?;
            match k.tok {
                Tok::EndObject => {
                    stack.pop();
                    expect_key = stack.last() == Some(&true);
                }
                Tok::SharedName(i) => {
                    names.reference(shared, pos, i);
                    expect_key = false;
                }
                Tok::Name { .. } => {
                    names.add(shared, pos.saturating_add(k.head), k.payload);
                    expect_key = false;
                }
                _ => expect_key = false,
            }
            pos = pos.saturating_add(k.len);
            continue;
        }
        let v = value_token(r, pos).await?;
        match v.tok {
            Tok::Header if stack.is_empty() => {
                let flags = r.bytes(pos, 4).await?.get(3).copied().unwrap_or(0);
                names = Table {
                    enabled: flags & 1 != 0,
                    slots: Vec::new(),
                };
                values = Table {
                    enabled: flags & 2 != 0,
                    slots: Vec::new(),
                };
            }
            Tok::EndOfContent if stack.is_empty() => {}
            Tok::StartArray | Tok::StartObject => {
                if stack.len() >= vt::MAX_DEPTH {
                    return Err(
                        Diagnostic::limit(format!("nested deeper than {}", vt::MAX_DEPTH))
                            .at(r.span(pos, 1)),
                    );
                }
                stack.push(v.tok == Tok::StartObject);
            }
            Tok::EndArray if stack.last() == Some(&false) => {
                stack.pop();
            }
            Tok::Text { long: false } => values.add(shared, pos.saturating_add(1), v.payload),
            Tok::SharedValue(i) => values.reference(shared, pos, i),
            Tok::Header | Tok::EndOfContent | Tok::EndArray | Tok::EndObject => {
                return Err(bad(r, pos, "unexpected token"));
            }
            _ => {}
        }
        expect_key = stack.last() == Some(&true);
        pos = pos.saturating_add(v.len);
    }
    Ok(())
}

/// The shared tables of the stream in `region` (scanned once, cached).
async fn shared(cx: &Cx, region: Span) -> Arc<Shared> {
    if let Some(s) = cx.cached::<Shared>(region, "smile-shared") {
        return s;
    }
    let mut r = ByteReader::new(cx, region);
    let s = Arc::new(scan_shared(&mut r).await);
    cx.cache(region, "smile-shared", s.clone());
    s
}

/// The end of the value at `at`.
async fn end_of(r: &mut ByteReader<'_>, at: u64) -> Result<u64> {
    let first = value_token(r, at).await?;
    let mut pos = at.saturating_add(first.len);
    let mut stack: Vec<bool> = match first.tok {
        Tok::StartArray => vec![false],
        Tok::StartObject => vec![true],
        Tok::EndArray | Tok::EndObject | Tok::EndOfContent | Tok::Header => {
            return Err(bad(r, at, "unexpected token"));
        }
        _ => return Ok(pos),
    };
    while let Some(&object) = stack.last() {
        r.cx().checkpoint().await;
        if object {
            let k = key_token(r, pos).await?;
            pos = pos.saturating_add(k.len);
            if k.tok == Tok::EndObject {
                stack.pop();
                continue;
            }
        }
        let v = value_token(r, pos).await?;
        pos = pos.saturating_add(v.len);
        match v.tok {
            Tok::StartArray | Tok::StartObject => {
                if stack.len() >= vt::MAX_DEPTH {
                    return Err(
                        Diagnostic::limit(format!("nested deeper than {}", vt::MAX_DEPTH))
                            .at(r.span(pos, 1)),
                    );
                }
                stack.push(v.tok == Tok::StartObject);
            }
            Tok::EndArray if !object => {
                stack.pop();
            }
            Tok::EndArray | Tok::EndObject | Tok::EndOfContent | Tok::Header => {
                return Err(bad(r, pos.saturating_sub(1), "unexpected token"));
            }
            _ => {}
        }
    }
    Ok(pos)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let region = input.span;
    let mut r = ByteReader::new(&cx, region);
    let mut pos = 0u64;
    let mut index = 0u64;
    let mut documents = 0u64;
    while pos < region.len {
        let v = value_token(&mut r, pos).await?;
        match v.tok {
            Tok::Header => {
                let h = r.bytes(pos, 4).await?;
                let flags = h.get(3).copied().unwrap_or(0);
                if documents == 0 {
                    let mut set = Vec::new();
                    for &(f, name) in &[
                        (1u8, "shared names"),
                        (2, "shared values"),
                        (4, "raw binary"),
                    ] {
                        if flags & f != 0 {
                            set.push(name);
                        }
                    }
                    let extra = if set.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", set.join(", "))
                    };
                    cx.annotate(format!("Smile version {}{extra}", flags >> 4));
                }
                documents = documents.saturating_add(1);
                cx.push(header_node(r.span(pos, 4), &h)).await;
                pos = pos.saturating_add(4);
            }
            Tok::EndOfContent => {
                cx.push(
                    Node::new("End of content")
                        .span(r.span(pos, 1))
                        .value(vt::uint(0xff, 8)),
                )
                .await;
                pos = pos.saturating_add(1);
            }
            _ => {
                let name = if index == 0 {
                    "Value".to_owned()
                } else {
                    format!("Value {index}")
                };
                let end = match end_of(&mut r, pos).await {
                    Ok(end) => end,
                    Err(d) => {
                        cx.push(
                            Node::new(name)
                                .span(r.span(pos, region.len.saturating_sub(pos)))
                                .diag(d),
                        )
                        .await;
                        break;
                    }
                };
                let node = item_node(&mut r, pos, end, name, &Path::new()).await?;
                cx.progress(end, region.len);
                cx.push(node).await;
                pos = end;
                index = index.saturating_add(1);
            }
        }
    }
    Ok(())
}

fn header_node(span: Span, h: &[u8]) -> Node {
    let flags = h.get(3).copied().unwrap_or(0);
    Node::new("Header")
        .span(span)
        .value(Value::Text(
            String::from_utf8_lossy(h.get(..2).unwrap_or_default()).into_owned(),
        ))
        .summary(format!("version {}", flags >> 4))
        .lazy(
            crate::expander!(self::header_fields: (Span, u8)),
            (span, flags),
        )
}

async fn header_fields(cx: Cx, (span, flags): (Span, u8)) -> Result<()> {
    cx.emit(
        Node::new("Signature")
            .span(span.sub(0, 3))
            .value(Value::Text(":)\\n".into())),
    );
    cx.emit(
        Node::new("Version")
            .span(span.sub(3, 1))
            .value(vt::uint(u64::from(flags >> 4), 4)),
    );
    let raw = u64::from(flags & 0x0f);
    let (set, unknown) = crate::value::decode_flags(FLAGS, raw);
    cx.emit(Node::new("Flags").span(span.sub(3, 1)).value(Value::Flags {
        raw,
        bits: 4,
        set,
        unknown,
    }));
    Ok(())
}

/// The text of a shared-table entry.
async fn entry_text(r: &mut ByteReader<'_>, entry: Option<(u64, u64)>) -> Result<Option<String>> {
    match entry {
        Some((at, len)) => Ok(Some(
            String::from_utf8_lossy(&r.bytes(at, len).await?).into_owned(),
        )),
        None => Ok(None),
    }
}

/// A node for the value at `start..end`.
async fn item_node(
    r: &mut ByteReader<'_>,
    start: u64,
    end: u64,
    name: String,
    path: &Path,
) -> Result<Node> {
    let v = value_token(r, start).await?;
    let node = Node::new(name).span(r.span(start, end.saturating_sub(start)));
    let body = start.saturating_add(v.head);
    Ok(match v.tok {
        Tok::SharedValue(i) => {
            let table = shared(r.cx(), r.region()).await;
            match entry_text(r, table.lookup(start)).await? {
                Some(text) => node
                    .value(Value::Text(text))
                    .summary(format!("shared value #{i}")),
                None => node
                    .summary(format!("shared value #{i}"))
                    .diag(Diagnostic::malformed(
                        "back-reference to a string not (yet) in the table",
                    )),
            }
        }
        Tok::Empty => node.value(Value::Text(String::new())),
        Tok::Null => node.summary("null"),
        Tok::Bool(b) => node.value(Value::Bool(b)),
        Tok::Int(v, bits) => node.value(vt::int(v, bits.max(8))),
        Tok::BigInt(raw) => {
            let enc = r.bytes(body, v.payload.min(seven_bit_len(256))).await?;
            let bytes = unpack7(&enc, usize::try_from(raw.min(256)).unwrap_or(0));
            let text = if raw > 256 {
                format!("<{raw}-byte integer>")
            } else {
                vt::signed_digits(&bytes)
            };
            node.value(Value::Text(text)).summary("BigInteger")
        }
        Tok::Float32(bits) => node.value(Value::Float(f64::from(f32::from_bits(bits)))),
        Tok::Float64(bits) => node.value(Value::Float(f64::from_bits(bits))),
        Tok::BigDecimal(scale, raw) => {
            let enc = r.bytes(body, v.payload.min(seven_bit_len(256))).await?;
            let bytes = unpack7(&enc, usize::try_from(raw.min(256)).unwrap_or(0));
            let digits = vt::signed_digits(&bytes);
            let (negative, digits) = match digits.strip_prefix('-') {
                Some(d) => (true, d.to_owned()),
                None => (false, digits),
            };
            node.value(Value::Text(vt::decimal_string(
                negative,
                &digits,
                scale.saturating_neg(),
            )))
            .summary(format!("BigDecimal, scale {scale}"))
        }
        Tok::Text { long } => {
            let data = r.bytes(body, v.payload.min(vt::MAX_TEXT)).await?;
            let node = vt::text(node, &data, v.payload);
            if long && v.payload <= vt::MAX_TEXT {
                node.summary("long text")
            } else {
                node
            }
        }
        Tok::Binary7(raw) => {
            let shown = raw.min(vt::MAX_BYTES);
            let enc = r.bytes(body, seven_bit_len(shown).min(v.payload)).await?;
            let bytes = unpack7(&enc, usize::try_from(shown).unwrap_or(0));
            vt::bytes(node, "binary (7-bit encoded)", bytes, raw)
        }
        Tok::RawBinary => {
            let data = r.bytes(body, v.payload.min(vt::MAX_BYTES)).await?;
            vt::bytes(node, "raw binary", data, v.payload)
        }
        Tok::StartArray | Tok::StartObject => {
            let object = v.tok == Tok::StartObject;
            let node = node.summary(if object { "object" } else { "array" });
            if end.saturating_sub(start) <= 2 {
                node.summary(if object {
                    "object, empty"
                } else {
                    "array, empty"
                })
            } else {
                match vt::enter(path, start) {
                    Ok(p) => node.lazy(
                        crate::expander!(self::members: (Span, u64, Path)),
                        (r.region(), start, p),
                    ),
                    Err(d) => node.diag(d),
                }
            }
        }
        _ => node.diag(bad(r, start, "unexpected token")),
    })
}

/// A key's name.
async fn key_name(r: &mut ByteReader<'_>, at: u64, k: &Token, index: u64) -> Result<String> {
    Ok(match k.tok {
        Tok::Empty => String::new(),
        Tok::SharedName(i) => {
            let table = shared(r.cx(), r.region()).await;
            match entry_text(r, table.lookup(at)).await? {
                Some(text) => vt::key_name(&text, index),
                None => format!("<shared name #{i}>"),
            }
        }
        _ => {
            let data = r
                .bytes(at.saturating_add(k.head), k.payload.min(0x200))
                .await?;
            vt::key_name(&String::from_utf8_lossy(&data), index)
        }
    })
}

async fn members(cx: Cx, (region, start, path): (Span, u64, Path)) -> Result<()> {
    let mut r = ByteReader::new(&cx, region);
    let first = value_token(&mut r, start).await?;
    let object = first.tok == Tok::StartObject;
    let (mut pos, mut index) = cx
        .resume::<(u64, u64)>()
        .unwrap_or((start.saturating_add(1), 0));
    loop {
        let at = (pos, index);
        cx.mark(move || at);
        let name = if object {
            let k = key_token(&mut r, pos).await?;
            if k.tok == Tok::EndObject {
                break;
            }
            let name = key_name(&mut r, pos, &k, index).await?;
            pos = pos.saturating_add(k.len);
            name
        } else {
            if r.byte(pos).await? == 0xf9 {
                break;
            }
            format!("[{index}]")
        };
        let end = end_of(&mut r, pos).await?;
        let node = item_node(&mut r, pos, end, name, &path).await?;
        cx.push(node).await;
        pos = end;
        index = index.saturating_add(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{seven_bit_len, unpack7};

    #[test]
    fn seven_bit() {
        // From smile-js: 00 01 02 'binary' ff.
        let enc = [
            0x00, 0x00, 0x20, 0x26, 0x13, 0x25, 0x5c, 0x61, 0x39, 0x1e, 0x3f, 0x07,
        ];
        assert_eq!(seven_bit_len(10), 12);
        assert_eq!(unpack7(&enc, 10), b"\x00\x01\x02binary\xff");
    }
}
