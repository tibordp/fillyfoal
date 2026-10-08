//! AutoCAD DXF: the drawing exchange format, as ASCII text or as binary
//! DXF (`AutoCAD Binary DXF` signature).
//!
//! A DXF file is a sequence of (group code, value) pairs. ASCII DXF puts
//! each code and each value on a line of its own; binary DXF stores the
//! code as one byte (R12 and before, with 255 escaping a 2-byte code) or
//! two bytes (later), and the value by the code's type: NUL-terminated
//! strings, little-endian integers of 1, 2, 4 or 8 bytes, doubles, and
//! length-prefixed binary chunks (the code ranges are those of the DXF
//! reference, as ezdxf implements them). Pairs with code 0 start records;
//! `SECTION`/`ENDSEC` records delimit the sections:
//!
//! - `HEADER`: `$NAME` variables (code 9), each with one or more values;
//! - `CLASSES`: `CLASS` records (application-defined object types);
//! - `TABLES`: `TABLE` ... `ENDTAB` groups of entries (layers, line types,
//!   text styles, views, ...);
//! - `BLOCKS`: `BLOCK` ... `ENDBLK` groups with their entities;
//! - `ENTITIES` and `OBJECTS`: the drawing's entities and non-graphical
//!   objects, counted by type;
//! - `THUMBNAILIMAGE`: a preview bitmap (a DIB, in hex lines), shown as an
//!   embedded BMP.
//!
//! Long sections are walked lazily, page by page, with resume marks.

use std::collections::BTreeMap;

use crate::bytes::{to_u64, u16_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::text::scan::{LINE_CAP, Lines, Scanner};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::Value;

const BINARY_SIGNATURE: &[u8] = b"AutoCAD Binary DXF\r\n\x1a\x00";

fn dxf_probe(h: &Head<'_>) -> bool {
    if h.starts_with(BINARY_SIGNATURE) {
        return true;
    }
    let data = h.data.get(..1024.min(h.data.len())).unwrap_or_default();
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines().map(str::trim);
    // Comments (999) may come first.
    for _ in 0..8 {
        match (lines.next(), lines.next()) {
            (Some("999"), Some(_)) => {}
            (Some("0"), Some("SECTION")) => return true,
            _ => return false,
        }
    }
    false
}

declare_format!(pub DXF = "dxf", "AutoCAD drawing exchange (DXF)", ["dxf"], "image/vnd.dxf",
    Probe::Custom(dxf_probe), dxf);

/// How pairs are encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    Ascii,
    /// Binary DXF; `wide` for 2-byte group codes (R13 and later).
    Binary {
        wide: bool,
    },
}

/// The value type of a group code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Str,
    Bool,
    I16,
    I32,
    I64,
    F64,
    Bin,
}

fn kind(code: i32) -> Kind {
    match code {
        310..=319 | 1004 => Kind::Bin,
        290..=299 => Kind::Bool,
        60..=79 | 170..=179 | 270..=289 | 370..=389 | 400..=409 | 1060..=1070 => Kind::I16,
        90..=99 | 420..=429 | 440..=459 | 1071 => Kind::I32,
        160..=169 => Kind::I64,
        10..=59 | 110..=149 | 210..=239 | 460..=469 | 1010..=1059 => Kind::F64,
        _ => Kind::Str,
    }
}

/// Names of common group codes.
fn code_name(code: i32) -> Option<&'static str> {
    Some(match code {
        0 => "Type",
        2 => "Name",
        5 => "Handle",
        6 => "Line type",
        7 => "Text style",
        8 => "Layer",
        9 => "Variable",
        10 => "X",
        20 => "Y",
        30 => "Z",
        11 => "X2",
        21 => "Y2",
        31 => "Z2",
        39 => "Thickness",
        48 => "Line type scale",
        62 => "Color",
        100 => "Subclass",
        102 => "Group",
        105 => "Handle",
        210 => "Extrusion X",
        220 => "Extrusion Y",
        230 => "Extrusion Z",
        310 => "Binary data",
        330 => "Owner handle",
        340 => "Handle",
        360 => "Owned handle",
        370 => "Line weight",
        390 => "Plot style handle",
        420 => "True color",
        999 => "Comment",
        1001 => "XDATA application",
        _ => return None,
    })
}

#[derive(Clone, Debug)]
enum TagValue {
    Text(String),
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
}

impl TagValue {
    fn text(&self) -> String {
        match self {
            TagValue::Text(s) => s.clone(),
            TagValue::Int(v) => v.to_string(),
            TagValue::Float(v) => float(*v),
            TagValue::Bytes(b) => format!("{} bytes", b.len()),
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            TagValue::Float(v) => Some(*v),
            TagValue::Int(v) => i32::try_from(*v).ok().map(f64::from),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            TagValue::Int(v) => Some(*v),
            _ => None,
        }
    }

    fn value(&self) -> Value {
        match self {
            TagValue::Text(s) => Value::Text(s.clone()),
            TagValue::Int(v) => Value::Int {
                value: *v,
                bits: 64,
            },
            TagValue::Float(v) => Value::Float(*v),
            TagValue::Bytes(b) => Value::Bytes(b.clone()),
        }
    }
}

/// A double as DXF writers print it: plain unless very large or small.
fn float(v: f64) -> String {
    let a = v.abs();
    if a != 0.0 && !(1e-6..1e15).contains(&a) {
        format!("{v:e}")
    } else {
        v.to_string()
    }
}

#[derive(Clone, Debug)]
struct Tag {
    code: i32,
    value: TagValue,
    /// Relative position of the pair, and of what follows it.
    start: u64,
    end: u64,
    /// The span of the value.
    value_span: Span,
}

impl Tag {
    fn is(&self, code: i32, text: &str) -> bool {
        self.code == code && matches!(&self.value, TagValue::Text(t) if t == text)
    }
}

/// Reads pairs from a region.
struct Tagger<'a> {
    region: Span,
    inner: Inner<'a>,
}

enum Inner<'a> {
    Ascii(Lines<'a>),
    Binary {
        scan: Scanner<'a>,
        pos: u64,
        wide: bool,
    },
}

/// Hex digits to bytes (odd or bad digits end it).
fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map_while(|b| {
            char::from(b)
                .to_digit(16)
                .and_then(|d| u8::try_from(d).ok())
        })
        .collect();
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[hi, lo]| hi << 4 | lo)
        .collect()
}

impl<'a> Tagger<'a> {
    fn new(cx: &'a Cx, region: Span, enc: Encoding) -> Self {
        let inner = match enc {
            Encoding::Ascii => Inner::Ascii(Lines::new(cx, region)),
            Encoding::Binary { wide } => Inner::Binary {
                scan: Scanner::new(cx, region),
                pos: 0,
                wide,
            },
        };
        Tagger { region, inner }
    }

    fn pos(&self) -> u64 {
        match &self.inner {
            Inner::Ascii(lines) => lines.pos(),
            Inner::Binary { pos, .. } => *pos,
        }
    }

    fn seek(&mut self, to: u64) {
        match &mut self.inner {
            Inner::Ascii(lines) => lines.seek(to, 0),
            Inner::Binary { pos, .. } => *pos = to,
        }
    }

    fn span(&self, start: u64, end: u64) -> Span {
        self.region.sub(start, end.saturating_sub(start))
    }

    /// The next pair, `None` at the end of the region.
    async fn next(&mut self) -> Result<Option<Tag>> {
        let region = self.region;
        match &mut self.inner {
            Inner::Ascii(lines) => {
                let start = lines.pos();
                let Some(code_line) = lines.next().await? else {
                    return Ok(None);
                };
                let code_text = code_line.text();
                let code_text = code_text.trim();
                if code_text.is_empty() && lines.peek().await?.is_none() {
                    return Ok(None);
                }
                let Ok(code) = code_text.parse::<i32>() else {
                    return Err(Diagnostic::malformed(format!(
                        "bad group code {:?}",
                        code_text.chars().take(32).collect::<String>()
                    ))
                    .at(code_line.span));
                };
                let Some(value_line) = lines.next().await? else {
                    return Err(
                        Diagnostic::malformed(format!("group code {code} has no value"))
                            .at(code_line.span),
                    );
                };
                let raw = value_line.text();
                let value = match kind(code) {
                    Kind::Str => TagValue::Text(raw),
                    Kind::Bin => TagValue::Bytes(unhex(&raw)),
                    Kind::F64 => match raw.trim().parse::<f64>() {
                        Ok(v) => TagValue::Float(v),
                        Err(_) => TagValue::Text(raw),
                    },
                    _ => match raw.trim().parse::<i64>() {
                        Ok(v) => TagValue::Int(v),
                        Err(_) => TagValue::Text(raw),
                    },
                };
                Ok(Some(Tag {
                    code,
                    value,
                    start,
                    end: lines.pos(),
                    value_span: value_line.span,
                }))
            }
            Inner::Binary { scan, pos, wide } => {
                scan.tick().await;
                let start = *pos;
                let Some(first) = scan.byte(start).await? else {
                    return Ok(None);
                };
                let (code, mut at) = if *wide || first == 255 {
                    let from = if *wide {
                        start
                    } else {
                        start.saturating_add(1)
                    };
                    let b = scan.bytes(from, from.saturating_add(2), 2).await?;
                    let Some(code) = u16_le(&b, 0) else {
                        return Err(Diagnostic::truncated(region.sub(start, 3), 1));
                    };
                    (i32::from(code), from.saturating_add(2))
                } else {
                    (i32::from(first), start.saturating_add(1))
                };
                let fixed = |n: u64| (at, at.saturating_add(n));
                let (value, value_start, value_end) = match kind(code) {
                    Kind::Str => {
                        let Some(nul) = scan.find(at, |b| b == 0).await? else {
                            return Err(Diagnostic::malformed("unterminated string")
                                .at(region.sub(at, region.len)));
                        };
                        let bytes = scan.bytes(at, nul, LINE_CAP).await?;
                        let text = crate::formats::text::encoding::decode_8bit(&bytes);
                        let v = (TagValue::Text(text), at, nul);
                        at = nul.saturating_add(1);
                        v
                    }
                    Kind::Bin => {
                        let len = scan
                            .byte(at)
                            .await?
                            .ok_or_else(|| Diagnostic::truncated(region.sub(at, 1), 0))?;
                        let from = at.saturating_add(1);
                        let to = from.saturating_add(u64::from(len));
                        let bytes = scan.bytes(from, to, 256).await?;
                        if to_u64(bytes.len()) < u64::from(len) {
                            return Err(Diagnostic::truncated(
                                region.sub(from, u64::from(len)),
                                to_u64(bytes.len()),
                            ));
                        }
                        at = to;
                        (TagValue::Bytes(bytes), from, to)
                    }
                    k => {
                        let n: u64 = match k {
                            Kind::Bool => 1,
                            Kind::I16 => 2,
                            Kind::I32 => 4,
                            _ => 8,
                        };
                        let (from, to) = fixed(n);
                        let b = scan.bytes(from, to, 8).await?;
                        if to_u64(b.len()) < n {
                            return Err(Diagnostic::truncated(
                                region.sub(from, n),
                                to_u64(b.len()),
                            ));
                        }
                        let mut buf = [0u8; 8];
                        for (d, s) in buf.iter_mut().zip(&b) {
                            *d = *s;
                        }
                        let value = match k {
                            Kind::Bool => TagValue::Int(i64::from(buf[0])),
                            Kind::I16 => {
                                TagValue::Int(i64::from(i16::from_le_bytes([buf[0], buf[1]])))
                            }
                            Kind::I32 => TagValue::Int(i64::from(i32::from_le_bytes([
                                buf[0], buf[1], buf[2], buf[3],
                            ]))),
                            Kind::I64 => TagValue::Int(i64::from_le_bytes(buf)),
                            _ => TagValue::Float(f64::from_le_bytes(buf)),
                        };
                        at = to;
                        (value, from, to)
                    }
                };
                *pos = at;
                Ok(Some(Tag {
                    code,
                    value,
                    start,
                    end: at,
                    value_span: region.sub(value_start, value_end.saturating_sub(value_start)),
                }))
            }
        }
    }

    /// The next pair without consuming it.
    async fn peek(&mut self) -> Result<Option<Tag>> {
        let at = self.pos();
        let tag = self.next().await?;
        self.seek(at);
        Ok(tag)
    }
}

/// What every expander needs.
#[derive(Clone, Copy, Debug)]
struct Doc {
    input: Input,
    enc: Encoding,
}

/// A section found by the top-level scan.
struct Found {
    name: String,
    /// The whole section, `SECTION` to `ENDSEC`.
    span: Span,
    /// Its contents (after the name pair, before `ENDSEC`).
    body: Span,
    records: u64,
    types: BTreeMap<String, u64>,
    vars: u64,
    closed: bool,
}

/// At most this many distinct record types are counted per section.
const MAX_TYPES: usize = 256;

async fn dxf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 24)).await?;
    let (enc, region) = if head.starts_with(BINARY_SIGNATURE) {
        cx.emit(
            Node::new("Signature")
                .span(file.sub(0, 22))
                .value(Value::Text("AutoCAD Binary DXF".to_owned())),
        );
        // The first pair is (0, "SECTION"): a 2-byte code has a zero high
        // byte where a 1-byte code is followed by the string.
        let wide = head.get(23) == Some(&0);
        (Encoding::Binary { wide }, file.tail(22))
    } else {
        (Encoding::Ascii, file)
    };
    let doc = Doc { input, enc };
    let mut tags = Tagger::new(&cx, region, enc);
    let mut current: Option<Found> = None;
    let mut version = None;
    let mut last_var = String::new();
    let mut sections = 0u64;
    let mut entities = None;
    let mut eof = false;
    let mut expect_name = false;
    while let Some(tag) = tags.next().await? {
        cx.progress_in(region, region.offset.saturating_add(tags.pos()));
        if expect_name {
            expect_name = false;
            if let Some(s) = current.as_mut()
                && tag.code == 2
            {
                s.name = tag.value.text();
                s.body = tags.span(tag.end, region.len);
                continue;
            }
        }
        if tag.code == 0 {
            match &tag.value {
                TagValue::Text(t) if t == "SECTION" => {
                    if let Some(open) = current.take() {
                        push_section(&cx, doc, open, &mut sections, &mut entities).await;
                    }
                    current = Some(Found {
                        name: String::new(),
                        span: tags.span(tag.start, region.len),
                        body: tags.span(tag.end, region.len),
                        records: 0,
                        types: BTreeMap::new(),
                        vars: 0,
                        closed: false,
                    });
                    expect_name = true;
                    continue;
                }
                TagValue::Text(t) if t == "ENDSEC" => {
                    if let Some(mut s) = current.take() {
                        s.span = tags.span(s.span.offset.saturating_sub(region.offset), tag.end);
                        s.body = tags.span(s.body.offset.saturating_sub(region.offset), tag.start);
                        s.closed = true;
                        push_section(&cx, doc, s, &mut sections, &mut entities).await;
                    }
                    continue;
                }
                TagValue::Text(t) if t == "EOF" && current.is_none() => {
                    cx.push(Node::new("EOF").span(tags.span(tag.start, tag.end)))
                        .await;
                    eof = true;
                    break;
                }
                _ => {}
            }
            if let Some(s) = current.as_mut() {
                s.records = s.records.saturating_add(1);
                let name = tag.value.text();
                if s.types.len() < MAX_TYPES || s.types.contains_key(&name) {
                    let n = s.types.entry(name).or_insert(0);
                    *n = n.saturating_add(1);
                }
            }
        } else if tag.code == 9 {
            if let Some(s) = current.as_mut() {
                s.vars = s.vars.saturating_add(1);
            }
            last_var = tag.value.text();
        } else if tag.code == 1 && last_var == "$ACADVER" && version.is_none() {
            version = Some(tag.value.text());
        }
    }
    if let Some(mut s) = current.take() {
        s.span = tags.span(s.span.offset.saturating_sub(region.offset), region.len);
        push_section(&cx, doc, s, &mut sections, &mut entities).await;
    }
    if !eof {
        cx.diag(Diagnostic::warning("no EOF record"));
    }
    let release = version.as_deref().and_then(super::release);
    let mut summary = match (&version, release) {
        (Some(v), Some(r)) => format!("{r} drawing ({v})"),
        (Some(v), None) => format!("drawing ({v})"),
        (None, _) => "drawing".to_owned(),
    };
    summary.push_str(match enc {
        Encoding::Ascii => ", ASCII DXF",
        Encoding::Binary { .. } => ", binary DXF",
    });
    if let Some(n) = entities {
        summary.push_str(&format!(", {}", plural(n, "entity", "entities")));
    }
    cx.annotate(summary);
    Ok(())
}

/// "1 entity", "2 entities".
fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// "4 LINE, 1 CIRCLE, ..." (most frequent first).
fn type_summary(types: &BTreeMap<String, u64>, max: usize) -> String {
    let mut sorted: Vec<(&String, &u64)> = types.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let mut parts: Vec<String> = sorted
        .iter()
        .take(max)
        .map(|(name, n)| format!("{n} {name}"))
        .collect();
    if sorted.len() > max {
        parts.push("...".to_owned());
    }
    parts.join(", ")
}

async fn push_section(cx: &Cx, doc: Doc, s: Found, sections: &mut u64, entities: &mut Option<u64>) {
    *sections = sections.saturating_add(1);
    let count = |name: &str| s.types.get(name).copied().unwrap_or(0);
    let summary = match s.name.as_str() {
        "HEADER" => plural(s.vars, "variable", "variables"),
        "CLASSES" => plural(count("CLASS"), "class", "classes"),
        "TABLES" => plural(count("TABLE"), "table", "tables"),
        "BLOCKS" => plural(count("BLOCK"), "block", "blocks"),
        "ENTITIES" => {
            *entities = Some(s.records);
            format!(
                "{}: {}",
                plural(s.records, "entity", "entities"),
                type_summary(&s.types, 6)
            )
        }
        "OBJECTS" => plural(s.records, "object", "objects"),
        "THUMBNAILIMAGE" => "preview image".to_owned(),
        _ => plural(s.records, "record", "records"),
    };
    let name = if s.name.is_empty() {
        "SECTION".to_owned()
    } else {
        s.name.clone()
    };
    let mut node = Node::new(name).span(s.span).summary(summary);
    if !s.closed {
        node = node.diag(Diagnostic::malformed("section has no ENDSEC"));
    }
    let body = s.body;
    node = match s.name.as_str() {
        "HEADER" => node.lazy(header, (doc, body)),
        "TABLES" => node.lazy(tables, (doc, body)),
        "BLOCKS" => node.lazy(blocks, (doc, body)),
        "THUMBNAILIMAGE" => node.lazy(thumbnail, (doc, body)),
        "ENTITIES" | "OBJECTS" => node
            .desc(type_summary(&s.types, usize::MAX))
            .lazy(records, (doc, body)),
        _ => node.lazy(records, (doc, body)),
    };
    cx.push(node).await;
}

/// The pairs of a region, each a node.
async fn pairs(cx: Cx, (doc, region): (Doc, Span)) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let mut tags = Tagger::new(&cx, region, doc.enc);
    tags.seek(pos);
    loop {
        let at = (pos, index);
        cx.mark(move || at);
        cx.progress_in(region, region.offset.saturating_add(pos));
        let Some(tag) = tags.next().await? else {
            break;
        };
        let name = match code_name(tag.code) {
            Some(n) => format!("{} {n}", tag.code),
            None => tag.code.to_string(),
        };
        cx.push(
            Node::new(name)
                .span(tags.span(tag.start, tag.end))
                .value(tag.value.value())
                .target(tag.value_span),
        )
        .await;
        pos = tags.pos();
        index = index.saturating_add(1);
    }
    Ok(())
}

/// One record (a 0 pair and what follows up to the next 0 pair): its pairs.
struct Record {
    kind: String,
    start: u64,
    end: u64,
    tags: Vec<(i32, TagValue)>,
}

/// Pairs kept per record for summaries; the rest is only counted.
const KEEP: usize = 64;

impl Record {
    fn get(&self, code: i32) -> Option<&TagValue> {
        self.tags.iter().find(|(c, _)| *c == code).map(|(_, v)| v)
    }

    fn text(&self, code: i32) -> Option<String> {
        self.get(code).map(TagValue::text)
    }

    fn point(&self, x: i32) -> Option<String> {
        let px = float(self.get(x)?.as_f64()?);
        let py = float(self.get(x.saturating_add(10))?.as_f64()?);
        Some(
            match self.get(x.saturating_add(20)).and_then(TagValue::as_f64) {
                Some(pz) if pz != 0.0 => format!("({px}, {py}, {})", float(pz)),
                _ => format!("({px}, {py})"),
            },
        )
    }

    /// The node's value: a name (code 2) or text (code 1).
    fn value(&self) -> Option<Value> {
        let order = match self.kind.as_str() {
            "CLASS" | "TEXT" | "MTEXT" | "ATTRIB" | "ATTDEF" => [1, 2],
            _ => [2, 1],
        };
        order
            .iter()
            .find_map(|&c| self.text(c).filter(|t| !t.is_empty()))
            .map(Value::Text)
    }

    fn summary(&self) -> String {
        let mut parts = Vec::new();
        match self.kind.as_str() {
            "LINE" => {
                if let (Some(a), Some(b)) = (self.point(10), self.point(11)) {
                    parts.push(format!("{a} to {b}"));
                }
            }
            "CIRCLE" | "ARC" => {
                if let Some(c) = self.point(10) {
                    parts.push(format!("center {c}"));
                }
                if let Some(r) = self.get(40).and_then(TagValue::as_f64) {
                    parts.push(format!("radius {}", float(r)));
                }
                if let (Some(a), Some(b)) = (
                    self.get(50).and_then(TagValue::as_f64),
                    self.get(51).and_then(TagValue::as_f64),
                ) {
                    parts.push(format!("{}° to {}°", float(a), float(b)));
                }
            }
            "POINT" | "TEXT" | "MTEXT" | "INSERT" | "BLOCK" => {
                if let Some(p) = self.point(10) {
                    parts.push(format!("at {p}"));
                }
            }
            "LWPOLYLINE" => {
                if let Some(n) = self.get(90).and_then(TagValue::as_i64) {
                    let closed = self
                        .get(70)
                        .and_then(TagValue::as_i64)
                        .is_some_and(|f| f & 1 != 0);
                    parts.push(format!(
                        "{n} vertices{}",
                        if closed { ", closed" } else { "" }
                    ));
                }
            }
            "LAYER" => {
                if let Some(c) = self.get(62).and_then(TagValue::as_i64) {
                    parts.push(if c < 0 {
                        format!("color {}, off", c.saturating_neg())
                    } else {
                        format!("color {c}")
                    });
                }
                if let Some(lt) = self.text(6) {
                    parts.push(format!("line type {lt}"));
                }
            }
            "LTYPE" => {
                if let Some(d) = self.text(3).filter(|d| !d.is_empty()) {
                    parts.push(d);
                }
            }
            "STYLE" => {
                if let Some(f) = self.text(3).filter(|f| !f.is_empty()) {
                    parts.push(format!("font {f}"));
                }
            }
            "CLASS" => {
                if let Some(c) = self.text(2) {
                    parts.push(c);
                }
                if let Some(a) = self.text(3) {
                    parts.push(a);
                }
            }
            _ => {}
        }
        if let Some(layer) = self.text(8).filter(|l| !l.is_empty()) {
            parts.push(format!("layer {layer}"));
        }
        if let Some(h) = self.text(5).or_else(|| self.text(105)) {
            parts.push(format!("handle {h}"));
        }
        parts.join(", ")
    }

    fn node(&self, doc: Doc, tags: &Tagger<'_>) -> Node {
        let span = tags.span(self.start, self.end);
        let mut node = Node::new(self.kind.clone()).span(span);
        if let Some(v) = self.value() {
            node = node.value(v);
        }
        let summary = self.summary();
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        node.lazy(pairs, (doc, span))
    }
}

/// Reads the record starting at the current position (a 0 pair).
async fn record(tags: &mut Tagger<'_>) -> Result<Option<Record>> {
    let Some(first) = tags.next().await? else {
        return Ok(None);
    };
    let mut rec = Record {
        kind: first.value.text(),
        start: first.start,
        end: first.end,
        tags: Vec::new(),
    };
    if first.code != 0 {
        // Stray pairs before the first record: one pseudo-record.
        rec.kind = format!("(group {})", first.code);
        rec.tags.push((first.code, first.value));
    }
    loop {
        let at = tags.pos();
        let Some(tag) = tags.next().await? else {
            break;
        };
        if tag.code == 0 {
            tags.seek(at);
            break;
        }
        rec.end = tag.end;
        if rec.tags.len() < KEEP {
            rec.tags.push((tag.code, tag.value));
        }
    }
    Ok(Some(rec))
}

/// Records of a region, paged.
async fn records(cx: Cx, (doc, region): (Doc, Span)) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let mut tags = Tagger::new(&cx, region, doc.enc);
    tags.seek(pos);
    loop {
        let at = (pos, index);
        cx.mark(move || at);
        cx.progress_in(region, region.offset.saturating_add(pos));
        let Some(rec) = record(&mut tags).await? else {
            break;
        };
        cx.push(rec.node(doc, &tags)).await;
        pos = tags.pos();
        index = index.saturating_add(1);
    }
    Ok(())
}

/// HEADER: one node per `$VARIABLE`.
async fn header(cx: Cx, (doc, region): (Doc, Span)) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let mut tags = Tagger::new(&cx, region, doc.enc);
    tags.seek(pos);
    loop {
        let at = (pos, index);
        cx.mark(move || at);
        cx.progress_in(region, region.offset.saturating_add(pos));
        let Some(first) = tags.next().await? else {
            break;
        };
        let mut values = Vec::new();
        let mut end = first.end;
        loop {
            let at = tags.pos();
            let Some(tag) = tags.next().await? else {
                break;
            };
            if tag.code == 9 || tag.code == 0 {
                tags.seek(at);
                break;
            }
            end = tag.end;
            if values.len() < KEEP {
                values.push(tag);
            }
        }
        let span = tags.span(first.start, end);
        let mut node = if first.code == 9 {
            Node::new(first.value.text())
        } else {
            Node::new(format!("(group {})", first.code)).value(first.value.value())
        }
        .span(span);
        match values.as_slice() {
            [] => {}
            [one] => {
                node = node.value(one.value.value()).target(one.value_span);
            }
            many => {
                let parts: Vec<String> = many.iter().map(|t| t.value.text()).collect();
                node = node.summary(format!("({})", parts.join(", ")));
            }
        }
        cx.push(node.lazy(pairs, (doc, span))).await;
        pos = tags.pos();
        index = index.saturating_add(1);
    }
    Ok(())
}

/// TABLES: one node per `TABLE` ... `ENDTAB` group.
async fn tables(cx: Cx, (doc, region): (Doc, Span)) -> Result<()> {
    grouped(&cx, doc, region, "TABLE", "ENDTAB").await
}

/// BLOCKS: one node per `BLOCK` ... `ENDBLK` group.
async fn blocks(cx: Cx, (doc, region): (Doc, Span)) -> Result<()> {
    grouped(&cx, doc, region, "BLOCK", "ENDBLK").await
}

async fn grouped(cx: &Cx, doc: Doc, region: Span, open: &str, close: &str) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let mut tags = Tagger::new(cx, region, doc.enc);
    tags.seek(pos);
    loop {
        let at = (pos, index);
        cx.mark(move || at);
        cx.progress_in(region, region.offset.saturating_add(pos));
        let Some(first) = record(&mut tags).await? else {
            break;
        };
        if first.kind != open {
            cx.push(first.node(doc, &tags)).await;
            pos = tags.pos();
            index = index.saturating_add(1);
            continue;
        }
        // Members up to and including the closing record.
        let mut members = 0u64;
        let mut end = first.end;
        let mut closed = false;
        while let Some(peek) = tags.peek().await? {
            if peek.is(0, open) {
                break;
            }
            let Some(rec) = record(&mut tags).await? else {
                break;
            };
            end = rec.end;
            if rec.kind == close {
                closed = true;
                break;
            }
            members = members.saturating_add(1);
        }
        let span = tags.span(first.start, end);
        let (name, what) = if open == "TABLE" {
            (
                first.text(2).unwrap_or_else(|| "TABLE".to_owned()),
                "entries",
            )
        } else {
            ("BLOCK".to_owned(), "entities")
        };
        let unit = match (what, members) {
            ("entries", 1) => "entry",
            ("entities", 1) => "entity",
            _ => what,
        };
        let mut node = Node::new(name)
            .span(span)
            .summary(format!("{members} {unit}"));
        if open == "BLOCK"
            && let Some(v) = first.value()
        {
            node = node.value(v);
        }
        if let Some(h) = first.text(5) {
            node = node.desc(format!("handle {h}"));
        }
        if !closed {
            node = node.diag(Diagnostic::malformed(format!("no {close}")));
        }
        cx.push(node.lazy(records, (doc, span))).await;
        pos = tags.pos();
        index = index.saturating_add(1);
    }
    Ok(())
}

/// THUMBNAILIMAGE: the byte count and the bitmap (code 310 chunks).
async fn thumbnail(cx: Cx, (doc, region): (Doc, Span)) -> Result<()> {
    let mut tags = Tagger::new(&cx, region, doc.enc);
    let mut data = Vec::new();
    let mut first = None;
    let mut last = 0u64;
    let max = cx.limits().max_read;
    while let Some(tag) = tags.next().await? {
        match (tag.code, &tag.value) {
            (90, v) => {
                cx.emit(
                    Node::new("Size")
                        .span(tags.span(tag.start, tag.end))
                        .value(v.value()),
                );
            }
            (310, TagValue::Bytes(b)) => {
                first.get_or_insert(tag.start);
                last = tag.end;
                if to_u64(data.len()) < max {
                    data.extend_from_slice(b);
                }
            }
            _ => cx.emit(
                Node::new(tag.code.to_string())
                    .span(tags.span(tag.start, tag.end))
                    .value(tag.value.value()),
            ),
        }
    }
    let Some(first) = first else {
        return Ok(());
    };
    let parent = tags.span(first, last);
    let decoded = cx.add_derived(
        Origin {
            parent,
            transform: "dxf-thumbnail",
        },
        data,
        parent.len,
        None,
    )?;
    let head = cx.read_avail(decoded.span.sub(0, 2)).await?;
    let node = if head == b"BM" {
        embedded("Image", doc.input.nested(decoded.span))
    } else {
        super::dwg_data::bmp_node(&cx, &doc.input, decoded.span).await?
    };
    cx.emit(node.summary(format!(
        "{:#x} bytes, from code 310 chunks",
        decoded.span.len
    )));
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hex_chunks() {
        assert_eq!(unhex("424D3A00"), vec![0x42, 0x4d, 0x3a, 0]);
        assert_eq!(unhex("4x"), Vec::<u8>::new());
    }
}
