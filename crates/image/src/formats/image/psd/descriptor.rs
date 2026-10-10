//! Photoshop action descriptors and patterns, shared by PSD (layer
//! effects, fills, smart objects, type layers, layer comps) and the preset
//! files (brushes, styles, gradients, actions, shapes).
//!
//! An *action descriptor* is a self-describing tree of typed,
//! four-character-keyed items (numbers with units, strings, enums, lists,
//! nested descriptors, references). Descriptors have no length prefix, so
//! a nested one is measured over its bytes before it is shown as a lazy
//! node; [`descriptor_node`] and [`versioned_descriptor`] do that for
//! callers.

use crate::bytes::{to_u64, u32_be};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt::fourcc;
use crate::formats::util::val::{int, text, uint};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Value, lookup};

const BE: Endian = Endian::Big;

/// Deepest descriptor nesting followed.
const MAX_DEPTH: u32 = 32;
/// Most bytes read into memory to measure descriptors and action lists.
pub const MAX_READ: u64 = 16 << 20;
/// Longest Photoshop Unicode string accepted (code units).
const MAX_STRING: u32 = 0x1_0000;

fn mode_name(mode: u32) -> &'static str {
    lookup(super::COLOR_MODES, mode.into()).unwrap_or("unknown mode")
}

/// A Photoshop Unicode string read through a cursor: u32 code units, UTF-16BE.
pub async fn ustr(cur: &mut Cursor<'_>) -> Result<String> {
    let at = cur.pos();
    let units = cur.u32().await?;
    if units > MAX_STRING {
        return Err(
            Diagnostic::malformed(format!("string of {units} characters")).at(cur.since(at)),
        );
    }
    let b = cur.bytes(u64::from(units).saturating_mul(2)).await?;
    Ok(crate::text::utf16_trimmed(&b, BE))
}

/// Emits `node` when `on`; lets one parser both measure and render.
fn put(cx: &Cx, on: bool, node: Node) {
    if on {
        cx.emit(node);
    }
}

/// A synchronous reader over bytes already in memory, for structures that
/// must be measured before they can be shown lazily (descriptors, action
/// lists). Every read checks bounds and returns `None` past the end.
pub struct Rd<'a> {
    data: &'a [u8],
    pub pos: usize,
    endian: Endian,
}

impl<'a> Rd<'a> {
    pub fn new(data: &'a [u8], endian: Endian) -> Self {
        Rd {
            data,
            pos: 0,
            endian,
        }
    }

    pub fn at(data: &'a [u8], pos: usize, endian: Endian) -> Self {
        Rd { data, pos, endian }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.take(N)?;
        s.try_into().ok()
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    pub fn u16(&mut self) -> Option<u16> {
        let b = self.array::<2>()?;
        Some(match self.endian {
            Endian::Big => u16::from_be_bytes(b),
            Endian::Little => u16::from_le_bytes(b),
        })
    }

    pub fn u32(&mut self) -> Option<u32> {
        let b = self.array::<4>()?;
        Some(match self.endian {
            Endian::Big => u32::from_be_bytes(b),
            Endian::Little => u32::from_le_bytes(b),
        })
    }

    pub fn i32(&mut self) -> Option<i32> {
        self.u32().map(|v| i32::from_ne_bytes(v.to_ne_bytes()))
    }

    pub fn u64(&mut self) -> Option<u64> {
        let b = self.array::<8>()?;
        Some(match self.endian {
            Endian::Big => u64::from_be_bytes(b),
            Endian::Little => u64::from_le_bytes(b),
        })
    }

    pub fn f64(&mut self) -> Option<f64> {
        self.u64().map(f64::from_bits)
    }

    pub fn fourcc(&mut self) -> Option<[u8; 4]> {
        self.array::<4>()
    }

    /// A length-prefixed (u32 count of code units) UTF-16 string, as in
    /// Photoshop files; a trailing NUL is dropped.
    pub fn unicode(&mut self) -> Option<String> {
        let units = usize::try_from(self.u32()?).ok()?;
        let b = self.take(units.checked_mul(2)?)?;
        Some(crate::text::utf16_trimmed(b, self.endian))
    }
}

// ---------------------------------------------------------------------------
// Action descriptors

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Descriptor,
    List,
    Reference,
}

enum Val {
    Leaf(Value, Option<String>),
    Note(String),
    Nested(Kind, String),
}

const TYPE_NAMES: &[(&[u8; 4], &str)] = &[
    (b"Objc", "descriptor"),
    (b"GlbO", "global object"),
    (b"VlLs", "list"),
    (b"obj ", "reference"),
    (b"doub", "double"),
    (b"UntF", "unit float"),
    (b"UnFl", "unit floats"),
    (b"TEXT", "string"),
    (b"enum", "enumerated"),
    (b"long", "integer"),
    (b"comp", "large integer"),
    (b"bool", "boolean"),
    (b"type", "class"),
    (b"GlbC", "class"),
    (b"alis", "alias"),
    (b"tdta", "raw data"),
    (b"Pth ", "path"),
];

fn type_name(t: &[u8; 4]) -> &'static str {
    TYPE_NAMES
        .iter()
        .find(|(k, _)| *k == t)
        .map_or("unknown type", |(_, v)| v)
}

const UNITS: &[(&[u8; 4], &str)] = &[
    (b"#Ang", "°"),
    (b"#Rsl", "dpi"),
    (b"#Rlt", "px (relative)"),
    (b"#Nne", ""),
    (b"#Prc", "%"),
    (b"#Pxl", "px"),
    (b"#Pnt", "pt"),
    (b"#Mlm", "mm"),
];

fn unit_name(u: &[u8; 4]) -> String {
    UNITS
        .iter()
        .find(|(k, _)| *k == u)
        .map_or_else(|| fourcc(u), |(_, v)| (*v).to_owned())
}

/// A class or key ID: a length, or 0 followed by a four-character code.
pub fn key(r: &mut Rd<'_>) -> Option<String> {
    let n = r.u32()?;
    let n = if n == 0 {
        4
    } else {
        usize::try_from(n).ok().filter(|&n| n <= 0x1_0000)?
    };
    Some(crate::text::latin1(r.take(n)?).trim_end().to_owned())
}

fn reference_item(r: &mut Rd<'_>, t: &[u8; 4]) -> Option<String> {
    Some(match t {
        b"prop" => {
            r.unicode()?;
            let class = key(r)?;
            format!("property {} of {class}", key(r)?)
        }
        b"Clss" => {
            r.unicode()?;
            format!("class {}", key(r)?)
        }
        b"Enmr" => {
            r.unicode()?;
            let class = key(r)?;
            let ty = key(r)?;
            format!("{class} {ty}.{}", key(r)?)
        }
        b"rele" => {
            r.unicode()?;
            let class = key(r)?;
            format!("{class} at offset {}", r.i32()?)
        }
        b"Idnt" => format!("identifier {}", r.u32()?),
        b"indx" => format!("index {}", r.u32()?),
        b"name" => {
            r.unicode()?;
            let class = key(r)?;
            format!("{class} named {:?}", r.unicode()?)
        }
        _ => return None,
    })
}

/// A container being skipped: its kind, the items left, and the depth its
/// values are read at.
struct Open {
    kind: Kind,
    left: u32,
    depth: u32,
}

/// The start of a descriptor (at `depth`): its class and item count.
fn descriptor_head(r: &mut Rd<'_>, depth: u32) -> Option<(String, u32)> {
    if depth > MAX_DEPTH {
        return None;
    }
    r.unicode()?;
    let class = key(r)?;
    let n = r.u32()?;
    Some((class, n))
}

/// Reads the head of container value `t` (read at `depth`): the container
/// to skip and its summary. `None` for other types.
fn open(r: &mut Rd<'_>, t: &[u8; 4], depth: u32) -> Option<(Open, Val)> {
    if depth > MAX_DEPTH {
        return None;
    }
    let (kind, left, depth, summary) = match t {
        b"Objc" | b"GlbO" => {
            let inner = depth.saturating_add(1);
            let (class, n) = descriptor_head(r, inner)?;
            (Kind::Descriptor, n, inner, format!("{class}, {n} items"))
        }
        b"VlLs" => {
            let n = r.u32()?;
            (Kind::List, n, depth.saturating_add(1), format!("{n} items"))
        }
        b"obj " => {
            let n = r.u32()?;
            (Kind::Reference, n, depth, format!("{n} items"))
        }
        _ => return None,
    };
    Some((Open { kind, left, depth }, Val::Nested(kind, summary)))
}

fn is_container(t: &[u8; 4]) -> bool {
    matches!(t, b"Objc" | b"GlbO" | b"VlLs" | b"obj ")
}

/// Skips the items left in `container` and everything nested in them, in
/// budgeted steps (a container can hold the whole input).
async fn skip(cx: &Cx, r: &mut Rd<'_>, container: Open) -> Option<()> {
    let mut stack = vec![container];
    let mut steps = 0u32;
    while let Some(top) = stack.last_mut() {
        if top.left == 0 {
            stack.pop();
            continue;
        }
        top.left = top.left.saturating_sub(1);
        let (kind, depth) = (top.kind, top.depth);
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        if kind == Kind::Descriptor {
            key(r)?;
        }
        let t = r.fourcc()?;
        if kind == Kind::Reference {
            reference_item(r, &t)?;
        } else if is_container(&t) {
            stack.push(open(r, &t, depth)?.0);
        } else {
            leaf(r, &t, depth)?;
        }
    }
    Some(())
}

/// Skips a descriptor; returns its class and item count.
pub async fn descriptor(cx: &Cx, r: &mut Rd<'_>, depth: u32) -> Option<(String, u32)> {
    let (class, n) = descriptor_head(r, depth)?;
    let container = Open {
        kind: Kind::Descriptor,
        left: n,
        depth,
    };
    skip(cx, r, container).await?;
    Some((class, n))
}

/// Skips one value of type `t` (read at `depth`).
pub async fn skip_value(cx: &Cx, r: &mut Rd<'_>, t: &[u8; 4], depth: u32) -> Option<()> {
    value(cx, r, t, depth).await.map(drop)
}

/// Reads (or, for containers, skips) one value of type `t`.
async fn value(cx: &Cx, r: &mut Rd<'_>, t: &[u8; 4], depth: u32) -> Option<Val> {
    if !is_container(t) {
        return leaf(r, t, depth);
    }
    let (container, val) = open(r, t, depth)?;
    skip(cx, r, container).await?;
    Some(val)
}

/// Reads one value of a type other than a container.
fn leaf(r: &mut Rd<'_>, t: &[u8; 4], depth: u32) -> Option<Val> {
    if depth > MAX_DEPTH {
        return None;
    }
    Some(match t {
        b"doub" => Val::Leaf(Value::Float(r.f64()?), None),
        b"UntF" => {
            let u = r.fourcc()?;
            Val::Leaf(Value::Float(r.f64()?), Some(unit_name(&u)))
        }
        b"UnFl" => {
            let u = r.fourcc()?;
            let n = r.u32()?;
            r.skip(usize::try_from(n).ok()?.checked_mul(8)?)?;
            Val::Note(format!("{n} values in {}", unit_name(&u)))
        }
        b"TEXT" => Val::Leaf(text(r.unicode()?), None),
        b"enum" => {
            let ty = key(r)?;
            let e = key(r)?;
            Val::Leaf(text(e), Some(ty))
        }
        b"long" => Val::Leaf(int(r.i32()?, 32), None),
        b"comp" => Val::Leaf(int(i64::from_ne_bytes(r.u64()?.to_ne_bytes()), 64), None),
        b"bool" => Val::Leaf(Value::Bool(r.u8()? != 0), None),
        b"type" | b"GlbC" => {
            r.unicode()?;
            Val::Leaf(text(key(r)?), None)
        }
        b"alis" | b"tdta" | b"Pth " => {
            let n = r.u32()?;
            r.skip(usize::try_from(n).ok()?)?;
            Val::Note(format!("{n} bytes"))
        }
        _ => return None,
    })
}

/// The length of the descriptor at the start of `data`.
pub async fn measure_descriptor(cx: &Cx, data: &[u8]) -> Option<usize> {
    let mut r = Rd::new(data, BE);
    descriptor(cx, &mut r, 0).await?;
    Some(r.pos)
}

/// Lists the items of the descriptor at `span` (exactly its bytes): an
/// expander, for nodes named by the caller.
pub async fn descriptor_items(cx: Cx, span: Span) -> Result<()> {
    items(cx, (span, Kind::Descriptor, 0)).await
}

/// A lazy node for the descriptor at `span` (exactly its bytes).
pub fn descriptor_node(name: impl Into<std::borrow::Cow<'static, str>>, span: Span) -> Node {
    Node::new(name)
        .span(span)
        .lazy(items, (span, Kind::Descriptor, 0u32))
}

fn bad(span: Span) -> Diagnostic {
    Diagnostic::malformed("descriptor item is cut off or has an unknown type").at(span)
}

fn item_node(
    name: String,
    t: &[u8; 4],
    val: Option<Val>,
    whole: Span,
    inner: Span,
    depth: u32,
) -> Node {
    let node = Node::new(name).span(whole);
    let ty = type_name(t);
    match val {
        None => node.summary(fourcc(t)).diag(bad(whole)),
        Some(Val::Leaf(v, None)) => node.value(v).summary(ty),
        Some(Val::Leaf(v, Some(s))) => node.value(v).summary(format!("{ty}, {s}")),
        Some(Val::Note(s)) => node.summary(format!("{ty}, {s}")),
        Some(Val::Nested(kind, s)) => node
            .summary(format!("{ty}: {s}"))
            .lazy(items, (inner, kind, depth.saturating_add(1))),
    }
}

async fn items(cx: Cx, (span, kind, depth): (Span, Kind, u32)) -> Result<()> {
    if span.len > MAX_READ {
        return Err(Diagnostic::limit("descriptor larger than 16 MiB").at(span));
    }
    let data = cx.read(span).await?;
    let mut r = Rd::new(&data, BE);
    let sub = |a: usize, b: usize| span.sub(to_u64(a), to_u64(b.saturating_sub(a)));
    let count = match kind {
        Kind::Descriptor => {
            let at = r.pos;
            let name = r.unicode().ok_or_else(|| bad(span))?;
            cx.emit(Node::new("Name").span(sub(at, r.pos)).value(text(name)));
            let at = r.pos;
            let class = key(&mut r).ok_or_else(|| bad(span))?;
            cx.emit(Node::new("Class").span(sub(at, r.pos)).value(text(class)));
            let at = r.pos;
            let n = r.u32().ok_or_else(|| bad(span))?;
            cx.emit(Node::new("Items").span(sub(at, r.pos)).value(uint(n, 32)));
            n
        }
        Kind::List | Kind::Reference => r.u32().ok_or_else(|| bad(span))?,
    };
    for i in 0..count {
        if r.remaining() == 0 {
            cx.emit(Node::new("Missing items").diag(Diagnostic::truncated(span.tail(span.len), 0)));
            break;
        }
        let at = r.pos;
        let name = match kind {
            Kind::Descriptor => key(&mut r),
            _ => Some(format!("[{i}]")),
        };
        let t = r.fourcc();
        let (Some(name), Some(t)) = (name, t) else {
            cx.push(
                Node::new(format!("[{i}]"))
                    .span(sub(at, data.len()))
                    .diag(bad(sub(at, data.len()))),
            )
            .await;
            break;
        };
        let vat = r.pos;
        if kind == Kind::Reference {
            let desc = reference_item(&mut r, &t);
            let node = Node::new(name).span(sub(at, r.pos)).summary(fourcc(&t));
            let ok = desc.is_some();
            cx.push(match desc {
                Some(d) => node.value(text(d)),
                None => node.diag(bad(sub(at, data.len()))),
            })
            .await;
            if !ok {
                break;
            }
            continue;
        }
        let val = value(&cx, &mut r, &t, depth).await;
        let ok = val.is_some();
        let end = if ok { r.pos } else { data.len() };
        cx.push(item_node(name, &t, val, sub(at, end), sub(vat, end), depth))
            .await;
        if !ok {
            break;
        }
    }
    Ok(())
}

/// A versioned descriptor (u32 16, then the descriptor) at `pos` of `data`
/// (which starts at `base` of `region`): its node and end offset.
pub async fn versioned_descriptor(
    cx: &Cx,
    name: &'static str,
    region: Span,
    data: &[u8],
    pos: usize,
) -> (Node, Option<usize>) {
    let mut r = Rd::at(data, pos, BE);
    let version = r.u32();
    let start = r.pos;
    let len = match data.get(start..) {
        Some(rest) => measure_descriptor(cx, rest).await,
        None => None,
    };
    match (version, len) {
        (Some(16), Some(len)) => {
            let span = region.sub(to_u64(start), to_u64(len));
            (
                descriptor_node(name, span).summary("descriptor version 16"),
                start.checked_add(len),
            )
        }
        (v, _) => (
            Node::new(name)
                .span(region.tail(to_u64(pos)))
                .diag(Diagnostic::malformed(format!(
                    "descriptor version {v:?} or contents not understood"
                ))),
            None,
        ),
    }
}

// ---------------------------------------------------------------------------
// Patterns (PSD `Patt` blocks, .pat files, brushes and styles)

struct Pattern {
    name: String,
    mode: u32,
    width: u16,
    height: u16,
}

/// One pattern: header, name, ID, optional colour table and the virtual
/// memory array list holding the pixels (skipped by its length).
async fn pattern(cx: &Cx, cur: &mut Cursor<'_>, on: bool) -> Result<Pattern> {
    let at = cur.pos();
    let version = cur.u32().await?;
    put(
        cx,
        on,
        Node::new("Version")
            .span(cur.since(at))
            .value(uint(version, 32)),
    );
    let at = cur.pos();
    let mode = cur.u32().await?;
    put(
        cx,
        on,
        Node::new("Image mode")
            .span(cur.since(at))
            .value(Value::Enum {
                raw: mode.into(),
                bits: 32,
                name: Some(mode_name(mode)),
            }),
    );
    let at = cur.pos();
    let height = cur.u16().await?;
    let width = cur.u16().await?;
    put(
        cx,
        on,
        Node::new("Size")
            .span(cur.since(at))
            .value(text(format!("{width}×{height}"))),
    );
    let at = cur.pos();
    let name = ustr(cur).await?;
    put(
        cx,
        on,
        Node::new("Name")
            .span(cur.since(at))
            .value(text(name.clone())),
    );
    let at = cur.pos();
    let id_len = cur.u8().await?;
    let id = cur.bytes(id_len.into()).await?;
    put(
        cx,
        on,
        Node::new("ID")
            .span(cur.since(at))
            .value(text(String::from_utf8_lossy(&id))),
    );
    if mode == 2 {
        let at = cur.pos();
        cur.bytes(768).await?;
        put(
            cx,
            on,
            Node::new("Colour table")
                .span(cur.since(at))
                .summary("256 RGB entries"),
        );
    }
    let at = cur.pos();
    let vm_version = cur.u32().await?;
    let len = cur.u32().await?;
    let body = cur.span(u64::from(len));
    if body.len < u64::from(len) {
        return Err(Diagnostic::truncated(
            Span::new(body.source, body.offset, len.into()),
            body.len,
        ));
    }
    cur.skip(len.into());
    if on {
        cx.emit(
            Node::new("Pixel data")
                .span(cur.since(at))
                .summary(format!(
                    "virtual memory array list v{vm_version}, {len} bytes"
                ))
                .lazy(vmal, body),
        );
    }
    Ok(Pattern {
        name,
        mode,
        width,
        height,
    })
}

/// The virtual memory array list body: bounds and channel records.
async fn vmal(cx: Cx, body: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, body, BE);
    let at = cur.pos();
    let (t, l, b, r) = (
        cur.u32().await?,
        cur.u32().await?,
        cur.u32().await?,
        cur.u32().await?,
    );
    cx.emit(
        Node::new("Rectangle")
            .span(cur.since(at))
            .value(text(format!("top {t}, left {l}, bottom {b}, right {r}"))),
    );
    let at = cur.pos();
    let channels = cur.u32().await?;
    cx.emit(
        Node::new("Channels")
            .span(cur.since(at))
            .value(uint(channels, 32))
            .desc("Highest channel index plus two (user and sheet masks)"),
    );
    let mut i = 0u32;
    while cur.remaining() >= 8 && i < channels.saturating_add(2) {
        let at = cur.pos();
        let written = cur.u32().await?;
        if written == 0 {
            cx.push(
                Node::new(format!("Channel {i}"))
                    .span(cur.since(at))
                    .summary("not written"),
            )
            .await;
            i = i.saturating_add(1);
            continue;
        }
        let len = cur.u32().await?;
        let data = cur.span(len.into());
        cur.skip(len.into());
        let mut node = Node::new(format!("Channel {i}")).span(cur.since(at));
        if len >= 23 {
            let h = cx.read(data.sub(0, 23)).await?;
            let depth = u32_be(&h, 0).unwrap_or(0);
            let comp = h.get(22).copied().unwrap_or(0);
            node = node.summary(format!(
                "{depth}-bit, {}, {len} bytes",
                if comp == 1 { "RLE" } else { "raw" }
            ));
        }
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// One pattern at the cursor, as a lazy node named after it.
pub async fn pattern_node(cx: &Cx, cur: &mut Cursor<'_>, index: u32) -> Result<Node> {
    let start = cur.pos();
    let p = pattern(cx, cur, false).await?;
    let span = cur.since(start);
    Ok(Node::new(if p.name.is_empty() {
        format!("Pattern {index}")
    } else {
        p.name
    })
    .span(span)
    .summary(format!("{}×{}, {}", p.width, p.height, mode_name(p.mode)))
    .lazy(pattern_fields, span))
}

async fn pattern_fields(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    pattern(&cx, &mut cur, true).await?;
    Ok(())
}

/// Patterns back to back, each with a u32 length and padded to four bytes
/// (PSD `Patt` blocks, brush and style files).
pub async fn patterns(cx: Cx, body: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, body, BE);
    let mut n = 0u32;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let len = cur.u32().await?;
        let data = cur.span(len.into());
        if data.len < u64::from(len) {
            return Err(Diagnostic::truncated(
                Span::new(data.source, data.offset, len.into()),
                data.len,
            ));
        }
        cur.skip(crate::bytes::align_up(len.into(), 4));
        let mut inner = Cursor::new(&cx, data, BE);
        let node = pattern_node(&cx, &mut inner, n).await?;
        cx.push(node.span(cur.since(start))).await;
        n = n.saturating_add(1);
    }
    Ok(())
}
