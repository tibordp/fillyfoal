//! Polygon File Format (Stanford PLY).
//!
//! A text header declares elements (`element vertex 8`) and their properties
//! (`property float x`, `property list uchar int vertex_indices`); the body
//! holds the element records in order, as lines of whitespace-separated
//! numbers (`format ascii 1.0`) or packed binary values in either byte order.
//! Records of elements with list properties vary in size, so the start of
//! every later element is only known by walking the records before it: the
//! file node does that for small element counts, and each element's
//! expansion does it for its own start otherwise.

use std::sync::Arc;

use crate::bytes::{array, to_u64, to_usize};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::text::scan::Lines;
use crate::formats::util::{fmt, lines::float32};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::render;
use crate::span::Span;
use crate::value::{Radix, Value};

declare_format!(pub PLY = "ply", "Polygon File Format", ["ply"], "model/ply",
    Probe::Magic(&[(0, b"ply\n"), (0, b"ply\r\n")]), ply);

/// Records the file node walks (over all variable-size elements) to give
/// later elements their spans.
const TOP_WALK_RECORDS: u64 = 4096;
/// List items decoded per list property (for summaries and nodes).
const LIST_SHOWN: u64 = 16;
/// Properties shown in a record's summary.
const SUMMARY_PROPS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    F32,
    F64,
}

impl Ty {
    fn parse(name: &str) -> Option<Ty> {
        Some(match name {
            "char" | "int8" => Ty::I8,
            "uchar" | "uint8" => Ty::U8,
            "short" | "int16" => Ty::I16,
            "ushort" | "uint16" => Ty::U16,
            "int" | "int32" => Ty::I32,
            "uint" | "uint32" => Ty::U32,
            "float" | "float32" => Ty::F32,
            "double" | "float64" => Ty::F64,
            _ => return None,
        })
    }

    fn size(self) -> u64 {
        match self {
            Ty::I8 | Ty::U8 => 1,
            Ty::I16 | Ty::U16 => 2,
            Ty::I32 | Ty::U32 | Ty::F32 => 4,
            Ty::F64 => 8,
        }
    }

    /// Decodes a binary value from the start of `b`.
    fn decode(self, b: &[u8], big: bool) -> Option<Value> {
        macro_rules! get {
            ($t:ty, $n:literal) => {{
                let a = array::<$n>(b, 0)?;
                if big {
                    <$t>::from_be_bytes(a)
                } else {
                    <$t>::from_le_bytes(a)
                }
            }};
        }
        Some(match self {
            Ty::I8 => int(i64::from(get!(i8, 1)), 8),
            Ty::U8 => uint(u64::from(get!(u8, 1)), 8),
            Ty::I16 => int(i64::from(get!(i16, 2)), 16),
            Ty::U16 => uint(u64::from(get!(u16, 2)), 16),
            Ty::I32 => int(i64::from(get!(i32, 4)), 32),
            Ty::U32 => uint(u64::from(get!(u32, 4)), 32),
            Ty::F32 => float32(get!(f32, 4)),
            Ty::F64 => Value::f64(get!(f64, 8)),
        })
    }

    /// Parses an ASCII token; `None` if it is not a number of this type.
    fn parse_token(self, tok: &str) -> Option<Value> {
        Some(match self {
            Ty::I8 => int(i64::from(tok.parse::<i8>().ok()?), 8),
            Ty::U8 => uint(u64::from(tok.parse::<u8>().ok()?), 8),
            Ty::I16 => int(i64::from(tok.parse::<i16>().ok()?), 16),
            Ty::U16 => uint(u64::from(tok.parse::<u16>().ok()?), 16),
            Ty::I32 => int(i64::from(tok.parse::<i32>().ok()?), 32),
            Ty::U32 => uint(u64::from(tok.parse::<u32>().ok()?), 32),
            Ty::F32 | Ty::F64 => Value::f64(tok.parse::<f64>().ok()?),
        })
    }
}

fn int(value: i64, bits: u8) -> Value {
    Value::Int { value, bits }
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

/// A list length: a non-negative integer.
fn list_len(v: &Value) -> Option<u64> {
    match *v {
        Value::UInt { value, .. } => Some(value),
        Value::Int { value, .. } => u64::try_from(value).ok(),
        _ => None,
    }
}

#[derive(Clone, Debug)]
enum Kind {
    Scalar(Ty),
    List(Ty, Ty),
    /// A type name we do not know: one token in ASCII, undecodable in binary.
    Unknown(String),
}

#[derive(Clone, Debug)]
struct Prop {
    name: String,
    kind: Kind,
}

#[derive(Clone, Debug)]
struct Element {
    name: String,
    count: u64,
    props: Vec<Prop>,
}

impl Element {
    /// The record size if every property is a known scalar.
    fn fixed_size(&self) -> Option<u64> {
        self.props.iter().try_fold(0u64, |acc, p| match p.kind {
            Kind::Scalar(t) => Some(acc.saturating_add(t.size())),
            _ => None,
        })
    }

    fn unknown_type(&self) -> Option<&str> {
        self.props.iter().find_map(|p| match &p.kind {
            Kind::Unknown(t) => Some(t.as_str()),
            _ => None,
        })
    }

    fn describe(&self) -> String {
        let props: Vec<String> = self
            .props
            .iter()
            .map(|p| match &p.kind {
                Kind::Scalar(t) => format!("{}: {}", p.name, ty_name(*t)),
                Kind::List(c, t) => format!("{}: list<{}> of {}", p.name, ty_name(*c), ty_name(*t)),
                Kind::Unknown(t) => format!("{}: {t}", p.name),
            })
            .collect();
        format!("{} × [{}]", fmt::grouped(self.count), props.join(", "))
    }
}

fn ty_name(t: Ty) -> &'static str {
    match t {
        Ty::I8 => "int8",
        Ty::U8 => "uint8",
        Ty::I16 => "int16",
        Ty::U16 => "uint16",
        Ty::I32 => "int32",
        Ty::U32 => "uint32",
        Ty::F32 => "float32",
        Ty::F64 => "float64",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    Ascii,
    Binary { big: bool },
}

struct Layout {
    body: Body,
    /// The data after the header.
    data: Span,
    elements: Vec<Element>,
    /// Each element's start in `data`, where the file node worked it out.
    starts: Vec<Option<u64>>,
}

/// One decoded property of a record (positions relative to `data`).
struct PropVal {
    start: u64,
    end: u64,
    /// The scalar, or the first [`LIST_SHOWN`] list items.
    values: Vec<Value>,
    /// The item count of a list property.
    items: Option<u64>,
}

struct Rec {
    start: u64,
    end: u64,
    /// Where the next record starts.
    next: u64,
    props: Vec<PropVal>,
}

/// Walks records of the body, binary or ASCII.
struct Walk<'a> {
    lines: Lines<'a>,
    body: Body,
    pos: u64,
}

impl<'a> Walk<'a> {
    fn new(cx: &'a Cx, data: Span, body: Body) -> Self {
        Walk {
            lines: Lines::new(cx, data),
            body,
            pos: 0,
        }
    }

    fn seek(&mut self, pos: u64) {
        self.pos = pos;
        self.lines.seek(pos, 0);
    }

    /// The next record of `e`, `None` at the end of the data. With
    /// `values` false, only its extent is worked out.
    async fn record(&mut self, e: &Element, values: bool) -> Result<Option<Rec>> {
        match self.body {
            Body::Binary { big } => self.binary(e, big, values).await,
            Body::Ascii => self.ascii(e).await,
        }
    }

    async fn binary(&mut self, e: &Element, big: bool, values: bool) -> Result<Option<Rec>> {
        let scan = self.lines.scanner();
        scan.tick().await;
        let start = self.pos;
        if scan.byte(start).await?.is_none() {
            return Ok(None);
        }
        let mut p = start;
        let mut props = Vec::new();
        for prop in &e.props {
            let begin = p;
            let (vals, items) = match prop.kind {
                Kind::Scalar(t) => {
                    let end = p.saturating_add(t.size());
                    let mut vals = Vec::new();
                    if values {
                        let b = scan.bytes(p, end, 8).await?;
                        vals.push(
                            t.decode(&b, big)
                                .ok_or_else(|| short(scan.span(p, end), &b))?,
                        );
                    } else if scan.byte(end.saturating_sub(1)).await?.is_none() {
                        let have = scan.len().saturating_sub(p);
                        return Err(Diagnostic::truncated(wanted(scan.region(), p, end), have));
                    }
                    p = end;
                    (vals, None)
                }
                Kind::List(c, t) => {
                    let after = p.saturating_add(c.size());
                    let b = scan.bytes(p, after, 8).await?;
                    let count = c
                        .decode(&b, big)
                        .ok_or_else(|| short(scan.span(p, after), &b))?;
                    let n = list_len(&count).ok_or_else(|| {
                        Diagnostic::malformed(format!("negative list length in {}", prop.name))
                            .at(scan.span(p, after))
                    })?;
                    let end = after.saturating_add(n.saturating_mul(t.size()));
                    // Make sure the whole list exists before going on.
                    if n > 0 && scan.byte(end.saturating_sub(1)).await?.is_none() {
                        let have = scan.len().saturating_sub(after);
                        return Err(Diagnostic::truncated(
                            wanted(scan.region(), after, end),
                            have,
                        ));
                    }
                    let mut vals = Vec::new();
                    if values {
                        let shown = n.min(LIST_SHOWN);
                        let len = shown.saturating_mul(t.size());
                        let b = scan
                            .bytes(after, after.saturating_add(len), to_usize(len))
                            .await?;
                        for i in 0..to_usize(shown) {
                            let off = i.saturating_mul(to_usize(t.size()));
                            if let Some(v) = b.get(off..).and_then(|b| t.decode(b, big)) {
                                vals.push(v);
                            }
                        }
                    }
                    p = end;
                    (vals, Some(n))
                }
                Kind::Unknown(ref t) => {
                    return Err(Diagnostic::unsupported(format!(
                        "property type {t:?}: record size unknown"
                    )));
                }
            };
            props.push(PropVal {
                start: begin,
                end: p,
                values: vals,
                items,
            });
        }
        if p == start {
            // An element without properties: nothing to walk.
            return Ok(None);
        }
        self.pos = p;
        Ok(Some(Rec {
            start,
            end: p,
            next: p,
            props,
        }))
    }

    async fn ascii(&mut self, e: &Element) -> Result<Option<Rec>> {
        let line = loop {
            let Some(line) = self.lines.next().await? else {
                return Ok(None);
            };
            if !line.is_blank() {
                break line;
            }
        };
        self.pos = line.next;
        let mut toks = tokens(&line.bytes);
        let mut props = Vec::new();
        let missing = |what: &str| {
            Diagnostic::malformed(format!(
                "{} record ends before {what}{}",
                e.name,
                if line.truncated() {
                    " (line too long)"
                } else {
                    ""
                }
            ))
            .at(line.span)
        };
        for prop in &e.props {
            let (vals, items, begin, end) = match &prop.kind {
                Kind::Scalar(t) => {
                    let (s, en, tok) = toks.next().ok_or_else(|| missing(&prop.name))?;
                    let v = t
                        .parse_token(tok)
                        .unwrap_or_else(|| Value::Text(tok.to_owned()));
                    (vec![v], None, s, en)
                }
                Kind::Unknown(_) => {
                    let (s, en, tok) = toks.next().ok_or_else(|| missing(&prop.name))?;
                    (vec![Value::Text(tok.to_owned())], None, s, en)
                }
                Kind::List(c, t) => {
                    let (s, mut en, tok) = toks.next().ok_or_else(|| missing(&prop.name))?;
                    let n = c
                        .parse_token(tok)
                        .as_ref()
                        .and_then(list_len)
                        .ok_or_else(|| {
                            Diagnostic::malformed(format!(
                                "bad list length {tok:?} in {}",
                                prop.name
                            ))
                            .at(line.span)
                        })?;
                    let mut vals = Vec::new();
                    let mut i = 0u64;
                    while i < n {
                        let (_, e2, tok) = toks.next().ok_or_else(|| missing(&prop.name))?;
                        if i < LIST_SHOWN {
                            vals.push(
                                t.parse_token(tok)
                                    .unwrap_or_else(|| Value::Text(tok.to_owned())),
                            );
                        }
                        en = e2;
                        i = i.saturating_add(1);
                    }
                    (vals, Some(n), s, en)
                }
            };
            props.push(PropVal {
                start: line.start.saturating_add(to_u64(begin)),
                end: line.start.saturating_add(to_u64(end)),
                values: vals,
                items,
            });
        }
        Ok(Some(Rec {
            start: line.start,
            end: line.start.saturating_add(line.span.len),
            next: line.next,
            props,
        }))
    }
}

fn short(want: Span, got: &[u8]) -> Diagnostic {
    Diagnostic::truncated(want, to_u64(got.len()))
}

/// The unclamped span of `start..end` in `region` (for truncation reports).
fn wanted(region: Span, start: u64, end: u64) -> Span {
    Span::new(
        region.source,
        region.offset.saturating_add(start),
        end.saturating_sub(start),
    )
}

/// Whitespace-separated tokens of a line with their byte ranges.
fn tokens(line: &[u8]) -> impl Iterator<Item = (usize, usize, &str)> {
    let mut i = 0usize;
    std::iter::from_fn(move || {
        while line.get(i).is_some_and(u8::is_ascii_whitespace) {
            i = i.saturating_add(1);
        }
        let start = i;
        while line.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
            i = i.saturating_add(1);
        }
        if start == i {
            return None;
        }
        let tok = std::str::from_utf8(line.get(start..i)?).unwrap_or("?");
        Some((start, i, tok))
    })
}

/// Skips `e`'s records from `pos`, returning where the next element starts.
async fn skip_element(walk: &mut Walk<'_>, e: &Element, pos: u64) -> Result<u64> {
    if let (Body::Binary { .. }, Some(size)) = (walk.body, e.fixed_size()) {
        return Ok(pos.saturating_add(size.saturating_mul(e.count)));
    }
    walk.seek(pos);
    let mut at = pos;
    let mut i = 0u64;
    while i < e.count {
        let Some(rec) = walk.record(e, false).await? else {
            return Err(Diagnostic::malformed(format!(
                "{}: only {} of {} records present",
                e.name,
                fmt::grouped(i),
                fmt::grouped(e.count)
            ))
            .at(walk.lines.scanner().span(at, at)));
        };
        at = rec.next;
        i = i.saturating_add(1);
    }
    Ok(at)
}

fn record_summary(e: &Element, rec: &Rec) -> String {
    let parts: Vec<String> = e
        .props
        .iter()
        .zip(&rec.props)
        .take(SUMMARY_PROPS)
        .map(|(p, v)| format!("{}={}", p.name, prop_text(v)))
        .collect();
    let mut s = parts.join(" ");
    if e.props.len() > SUMMARY_PROPS {
        s.push_str(" …");
    }
    fmt::clip(&s, 160)
}

fn value_text(v: &Value) -> String {
    match v {
        Value::Text(t) => t.clone(),
        v => render::value(v),
    }
}

fn prop_text(v: &PropVal) -> String {
    let vals: Vec<String> = v.values.iter().map(value_text).collect();
    match v.items {
        None => vals.join(" "),
        Some(n) => {
            let more = if n > to_u64(vals.len()) { " …" } else { "" };
            format!("[{}{more}]", vals.join(" "))
        }
    }
}

async fn ply(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 65536)).await?;
    let end = head
        .windows(10)
        .position(|w| w == b"end_header")
        .ok_or_else(|| Diagnostic::malformed("no end_header in the first 64 KiB"))?;
    let header_len = head
        .get(end..)
        .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
        .map_or(to_u64(end).saturating_add(10), |nl| {
            to_u64(end.saturating_add(nl).saturating_add(1))
        });
    let text = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
    let mut format = String::new();
    let mut elements: Vec<Element> = Vec::new();
    let mut pos = 0u64;
    let mut header_nodes = Vec::new();
    for line in text.split('\n') {
        let len = to_u64(line.len()).saturating_add(1);
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["format", f, v] => format = format!("{f} {v}"),
            ["element", name, count] => elements.push(Element {
                name: (*name).to_owned(),
                count: count.parse().unwrap_or(0),
                props: Vec::new(),
            }),
            ["property", "list", c, t, name] => {
                if let Some(e) = elements.last_mut() {
                    let kind = match (Ty::parse(c), Ty::parse(t)) {
                        (Some(c), Some(t)) => Kind::List(c, t),
                        _ => Kind::Unknown(format!("list {c} {t}")),
                    };
                    e.props.push(Prop {
                        name: (*name).to_owned(),
                        kind,
                    });
                }
            }
            ["property", kind, name] => {
                if let Some(e) = elements.last_mut() {
                    e.props.push(Prop {
                        name: (*name).to_owned(),
                        kind: Ty::parse(kind)
                            .map_or_else(|| Kind::Unknown((*kind).to_owned()), Kind::Scalar),
                    });
                }
            }
            _ => {}
        }
        if !line.trim().is_empty() {
            header_nodes.push(Node::new(line.trim().to_owned()).span(file.sub(pos, len)));
        }
        pos = pos.saturating_add(len);
    }
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, header_len))
            .summary(format.clone())
            .lazy(
                crate::formats::util::arcutil::push_nodes,
                Arc::new(header_nodes),
            ),
    );
    let body = match format.split_whitespace().next() {
        Some("ascii") => Body::Ascii,
        Some("binary_little_endian") => Body::Binary { big: false },
        Some("binary_big_endian") => Body::Binary { big: true },
        _ => {
            cx.annotate(format!("PLY {format}"));
            return Err(Diagnostic::unsupported(format!(
                "PLY body format {format:?}"
            )));
        }
    };
    let data = file.tail(header_len);
    let summary: Vec<String> = elements
        .iter()
        .map(|e| format!("{} {}", fmt::grouped(e.count), e.name))
        .collect();
    cx.annotate(format!("PLY {format}: {}", summary.join(", ")));

    // Work out where each element starts and ends, walking variable-size
    // elements while that stays cheap.
    let mut walk = Walk::new(&cx, data, body);
    let mut starts = Vec::new();
    let mut ends = Vec::new();
    let mut at = Some(0u64);
    let mut budget = TOP_WALK_RECORDS;
    let mut failure = None;
    for e in &elements {
        starts.push(at);
        let end = match (at, body, e.fixed_size()) {
            (Some(s), Body::Binary { .. }, Some(size)) => {
                Some(s.saturating_add(size.saturating_mul(e.count)))
            }
            (Some(s), _, _) if e.count <= budget && failure.is_none() => {
                budget = budget.saturating_sub(e.count);
                match skip_element(&mut walk, e, s).await {
                    Ok(end) => Some(end),
                    Err(d) => {
                        failure = Some(d);
                        None
                    }
                }
            }
            _ => None,
        };
        ends.push(end);
        at = end;
    }
    let layout = Arc::new(Layout {
        body,
        data,
        elements,
        starts: starts.clone(),
    });
    let last = layout.elements.len().saturating_sub(1);
    for (i, e) in layout.elements.iter().enumerate() {
        let mut node = Node::new(e.name.clone()).summary(e.describe());
        let start = starts.get(i).copied().flatten();
        let end = ends.get(i).copied().flatten();
        match (start, end) {
            (Some(s), Some(en)) => node = node.span(data.sub(s, en.saturating_sub(s))),
            // The last element runs to the end of the file.
            (Some(s), None) if i == last => node = node.span(data.tail(s)),
            _ => {}
        }
        if let (Body::Binary { .. }, Some(t)) = (body, e.unknown_type()) {
            node = node.diag(Diagnostic::unsupported(format!(
                "property type {t:?}: records cannot be walked"
            )));
        } else if e.count > 0 && !e.props.is_empty() {
            node = node.lazy(ply_element, (layout.clone(), i));
        }
        cx.emit(node);
    }
    if let Some(d) = failure {
        cx.diag(d);
    } else if let Some(Some(end)) = ends.last()
        && *end < data.len
    {
        cx.diag(
            Diagnostic::warning(format!(
                "{} bytes after the last element",
                fmt::grouped(data.len.saturating_sub(*end))
            ))
            .at(data.tail(*end)),
        );
    }
    Ok(())
}

/// Lists an element's records.
async fn ply_element(cx: Cx, (layout, idx): (Arc<Layout>, usize)) -> Result<()> {
    let Some(e) = layout.elements.get(idx) else {
        return Ok(());
    };
    let mut walk = Walk::new(&cx, layout.data, layout.body);
    let (mut pos, mut i) = match cx.resume::<(u64, u64)>() {
        Some(state) => state,
        None => {
            // Start from the nearest element whose start is known.
            let known = layout
                .starts
                .get(..=idx)
                .unwrap_or_default()
                .iter()
                .rposition(Option::is_some)
                .unwrap_or(0);
            let mut pos = layout.starts.get(known).copied().flatten().unwrap_or(0);
            for prior in layout.elements.get(known..idx).unwrap_or_default() {
                pos = skip_element(&mut walk, prior, pos).await?;
            }
            (pos, 0)
        }
    };
    walk.seek(pos);
    while i < e.count {
        let at = (pos, i);
        cx.mark(move || at);
        let Some(rec) = walk.record(e, !cx.skipping()).await? else {
            cx.diag(
                Diagnostic::malformed(format!(
                    "only {} of {} records present",
                    fmt::grouped(i),
                    fmt::grouped(e.count)
                ))
                .at(layout.data.sub(pos, 0)),
            );
            break;
        };
        let span = layout
            .data
            .sub(rec.start, rec.end.saturating_sub(rec.start));
        cx.push(
            Node::new(format!("{} {i}", e.name))
                .span(span)
                .summary(record_summary(e, &rec))
                .lazy(ply_record, (layout.clone(), idx, rec.start)),
        )
        .await;
        pos = rec.next;
        i = i.saturating_add(1);
        cx.progress(i, e.count);
    }
    Ok(())
}

/// A record's properties.
async fn ply_record(cx: Cx, (layout, idx, start): (Arc<Layout>, usize, u64)) -> Result<()> {
    let Some(e) = layout.elements.get(idx) else {
        return Ok(());
    };
    let mut walk = Walk::new(&cx, layout.data, layout.body);
    walk.seek(start);
    let Some(rec) = walk.record(e, true).await? else {
        return Ok(());
    };
    for (p, v) in e.props.iter().zip(&rec.props) {
        let span = layout.data.sub(v.start, v.end.saturating_sub(v.start));
        let node = Node::new(p.name.clone()).span(span);
        let node = match (v.items, v.values.first()) {
            (Some(n), _) => node
                .value(uint(n, 32))
                .summary(prop_text(v))
                .desc("list length, then the items"),
            (None, Some(val)) => node.value(val.clone()),
            (None, None) => node,
        };
        cx.emit(node);
    }
    Ok(())
}
