//! GVariant serialization, GLib's binary value format (the "normal form"
//! of the GVariant specification), shared by the formats built on it: GVDB
//! files (GResource bundles, dconf databases, GSettings schema caches) and
//! OSTree objects.
//!
//! A serialized value carries no type: the reader brings the type string.
//! Fixed-size values (numbers, booleans, tuples of them) sit at their
//! natural alignment; variable-size ones are delimited by *framing
//! offsets*, little-endian integers stored at the end of their container
//! whose width (1, 2, 4 or 8 bytes) depends on the container's size. A
//! variant stores its child's type string after the child and a zero byte.
//! Numbers are in the writer's byte order, which the container format
//! records (GVDB's byte-swapped signature) or fixes (OSTree swaps its
//! numbers to big-endian itself); framing offsets are always
//! little-endian.
//!
//! [`node`] renders a value of a given type: scalars as typed values,
//! containers as lazy nodes whose members are found through the framing
//! offsets one at a time (an array of a million strings reads two offsets
//! per member shown). Arrays of dictionary entries show each entry under
//! its key. Values that break the framing rules get a diagnostic where the
//! specification would substitute a default.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::datakit::{ByteReader, le_uint};
use crate::formats::util::fmt::{clip, grouped_count};
use crate::formats::util::val;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

/// Longest type string GVariant accepts.
pub const MAX_SIGNATURE: usize = 255;
/// Deepest container nesting in a type (GLib allows 128; a type string of
/// 255 characters cannot nest deeper than this anyway in practice).
const MAX_TYPE_DEPTH: usize = 64;
/// How deep values may nest (variants inside variants) before the view
/// stops descending.
pub const MAX_DEPTH: u32 = 128;
/// How deep [`valid`] follows values (probes: real files nest a few
/// levels; this bounds the work on crafted ones).
const PROBE_DEPTH: u32 = 32;
/// Text shown for a string; longer strings are cut.
const MAX_TEXT: u64 = 0x1000;
/// Bytes shown for a byte array.
const MAX_BYTES: u64 = 64;
/// Characters of a dictionary key used as a node name.
const MAX_KEY: usize = 80;

/// A GVariant type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ty {
    pub kind: Kind,
    align: u64,
    fixed: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One of `b y n q i u x t h d s o g`.
    Basic(u8),
    Variant,
    Maybe(Box<Ty>),
    Array(Box<Ty>),
    /// A tuple (`()` is the unit type).
    Tuple(Vec<Ty>),
    /// A dictionary entry `{kv}`.
    Entry(Box<Ty>, Box<Ty>),
}

/// The size and alignment of a basic type (`None` size: a string).
fn basic(c: u8) -> Option<(u64, Option<u64>)> {
    Some(match c {
        b'b' | b'y' => (1, Some(1)),
        b'n' | b'q' => (2, Some(2)),
        b'i' | b'u' | b'h' => (4, Some(4)),
        b'x' | b't' | b'd' => (8, Some(8)),
        b's' | b'o' | b'g' => (1, None),
        _ => return None,
    })
}

/// `pos` rounded up to a multiple of `align` (a power of two).
pub fn align_up(pos: u64, align: u64) -> u64 {
    let mask = align.saturating_sub(1);
    pos.saturating_add(mask) & !mask
}

/// The width of the framing offsets in a container of `size` bytes.
pub fn offset_size(size: u64) -> u64 {
    match size {
        0 => 0,
        1..=0xff => 1,
        0x100..=0xffff => 2,
        0x1_0000..=0xffff_ffff => 4,
        _ => 8,
    }
}

impl Ty {
    fn new(kind: Kind) -> Ty {
        let (align, fixed) = match &kind {
            Kind::Basic(c) => basic(*c).unwrap_or((1, None)),
            Kind::Variant => (8, None),
            Kind::Maybe(t) | Kind::Array(t) => (t.align, None),
            Kind::Tuple(members) => tuple_layout(members.iter()),
            Kind::Entry(k, v) => tuple_layout([k.as_ref(), v.as_ref()].into_iter()),
        };
        Ty { kind, align, fixed }
    }

    /// The variant type `v`.
    pub fn variant() -> Ty {
        Ty::new(Kind::Variant)
    }

    /// The type a whole type string denotes.
    pub fn parse(sig: &[u8]) -> Option<Ty> {
        if sig.len() > MAX_SIGNATURE {
            return None;
        }
        let (ty, used) = Self::parse_one(sig, 0)?;
        (used == sig.len()).then_some(ty)
    }

    /// The first complete type in `sig` and the bytes it took.
    fn parse_one(sig: &[u8], depth: usize) -> Option<(Ty, usize)> {
        if depth > MAX_TYPE_DEPTH {
            return None;
        }
        let c = *sig.first()?;
        let rest = sig.get(1..)?;
        let deeper = depth.checked_add(1)?;
        let (kind, used) = match c {
            b'v' => (Kind::Variant, 0),
            b'm' => {
                let (t, n) = Self::parse_one(rest, deeper)?;
                (Kind::Maybe(Box::new(t)), n)
            }
            b'a' => {
                let (t, n) = Self::parse_one(rest, deeper)?;
                (Kind::Array(Box::new(t)), n)
            }
            b'(' => {
                let mut members = Vec::new();
                let mut at = 0usize;
                loop {
                    let next = *rest.get(at)?;
                    if next == b')' {
                        break;
                    }
                    let (t, n) = Self::parse_one(rest.get(at..)?, deeper)?;
                    members.push(t);
                    at = at.checked_add(n)?;
                }
                (Kind::Tuple(members), at.checked_add(1)?)
            }
            b'{' => {
                let (k, kn) = Self::parse_one(rest, deeper)?;
                if !matches!(k.kind, Kind::Basic(_)) {
                    return None;
                }
                let (v, vn) = Self::parse_one(rest.get(kn..)?, deeper)?;
                let end = kn.checked_add(vn)?;
                if rest.get(end) != Some(&b'}') {
                    return None;
                }
                (Kind::Entry(Box::new(k), Box::new(v)), end.checked_add(1)?)
            }
            c if basic(c).is_some() => (Kind::Basic(c), 0),
            _ => return None,
        };
        Some((Ty::new(kind), used.checked_add(1)?))
    }

    /// The type string.
    pub fn signature(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match &self.kind {
            Kind::Basic(c) => out.push(char::from(*c)),
            Kind::Variant => out.push('v'),
            Kind::Maybe(t) => {
                out.push('m');
                t.write(out);
            }
            Kind::Array(t) => {
                out.push('a');
                t.write(out);
            }
            Kind::Tuple(members) => {
                out.push('(');
                for m in members {
                    m.write(out);
                }
                out.push(')');
            }
            Kind::Entry(k, v) => {
                out.push('{');
                k.write(out);
                v.write(out);
                out.push('}');
            }
        }
    }

    /// The alignment of the type.
    pub fn align(&self) -> u64 {
        self.align
    }

    /// The size of every value of the type, if it is fixed.
    pub fn fixed(&self) -> Option<u64> {
        self.fixed
    }
}

/// The alignment and fixed size of a tuple of `members`.
fn tuple_layout<'a>(members: impl Iterator<Item = &'a Ty>) -> (u64, Option<u64>) {
    let mut align = 1u64;
    let mut pos = Some(0u64);
    for m in members {
        align = align.max(m.align);
        pos = match (pos, m.fixed) {
            (Some(p), Some(size)) => Some(align_up(p, m.align).saturating_add(size)),
            _ => None,
        };
    }
    let fixed = pos.map(|p| {
        let size = align_up(p, align);
        // The unit type takes one byte.
        if size == 0 { 1 } else { size }
    });
    (align, fixed)
}

/// A serialized value: `start..end` relative to the reader's region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seg {
    pub start: u64,
    pub end: u64,
}

impl Seg {
    pub fn new(start: u64, end: u64) -> Seg {
        Seg { start, end }
    }
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

fn bad(r: &ByteReader<'_>, seg: Seg, msg: impl Into<String>) -> Diagnostic {
    Diagnostic::malformed(msg).at(r.span(seg.start, seg.len()))
}

/// The members of a tuple or dictionary entry.
pub async fn members(r: &mut ByteReader<'_>, seg: Seg, types: &[Ty]) -> Result<Vec<Seg>> {
    let osz = offset_size(seg.len());
    let mut frame_end = seg.len();
    let mut pos = 0u64;
    let mut out = Vec::with_capacity(types.len());
    for (i, t) in types.iter().enumerate() {
        let start = align_up(pos, t.align);
        let end = match t.fixed {
            Some(size) => start.saturating_add(size),
            None if i.saturating_add(1) == types.len() => frame_end,
            None => {
                if frame_end < osz {
                    return Err(bad(r, seg, "framing offsets do not fit in the tuple"));
                }
                frame_end = frame_end.saturating_sub(osz);
                r.le(seg.start.saturating_add(frame_end), osz).await?
            }
        };
        if start > end || end > frame_end {
            return Err(bad(
                r,
                seg,
                format!("member {i} at {start}..{end} does not fit in the tuple"),
            ));
        }
        out.push(Seg::new(
            seg.start.saturating_add(start),
            seg.start.saturating_add(end),
        ));
        pos = end;
    }
    Ok(out)
}

/// An array's framing: its element count and where each element is.
#[derive(Clone, Copy, Debug)]
pub struct Frame {
    pub seg: Seg,
    pub count: u64,
    fixed: Option<u64>,
    align: u64,
    osz: u64,
    /// Where the framing offsets start, relative to `seg.start`.
    table: u64,
}

impl Frame {
    pub async fn open(r: &mut ByteReader<'_>, seg: Seg, elem: &Ty) -> Result<Frame> {
        let n = seg.len();
        let frame = |count, osz, table| Frame {
            seg,
            count,
            fixed: elem.fixed,
            align: elem.align,
            osz,
            table,
        };
        if let Some(size) = elem.fixed {
            if size == 0 || !n.is_multiple_of(size) {
                return Err(bad(
                    r,
                    seg,
                    format!("array of {n} bytes is not a multiple of its {size}-byte elements"),
                ));
            }
            return Ok(frame(n.checked_div(size).unwrap_or(0), 0, n));
        }
        if n == 0 {
            return Ok(frame(0, 0, 0));
        }
        let osz = offset_size(n);
        let last = r
            .le(seg.start.saturating_add(n.saturating_sub(osz)), osz)
            .await?;
        if last > n || !n.saturating_sub(last).is_multiple_of(osz) {
            return Err(bad(
                r,
                seg,
                format!("framing offset {last} does not end the array's elements"),
            ));
        }
        Ok(frame(
            n.saturating_sub(last).checked_div(osz).unwrap_or(0),
            osz,
            last,
        ))
    }

    /// Element `i` (`i < count`).
    pub async fn item(&self, r: &mut ByteReader<'_>, i: u64) -> Result<Seg> {
        let (start, end) = match self.fixed {
            Some(size) => {
                let start = i.saturating_mul(size);
                (start, start.saturating_add(size))
            }
            None => {
                let at = |k: u64| {
                    self.seg
                        .start
                        .saturating_add(self.table)
                        .saturating_add(k.saturating_mul(self.osz))
                };
                let start = match i.checked_sub(1) {
                    Some(prev) => align_up(r.le(at(prev), self.osz).await?, self.align),
                    None => 0,
                };
                (start, r.le(at(i), self.osz).await?)
            }
        };
        if start > end || end > self.table {
            return Err(bad(
                r,
                self.seg,
                format!("element {i} at {start}..{end} does not fit in the array"),
            ));
        }
        Ok(Seg::new(
            self.seg.start.saturating_add(start),
            self.seg.start.saturating_add(end),
        ))
    }
}

/// A variant's child: its type and where it is.
pub async fn variant(r: &mut ByteReader<'_>, seg: Seg) -> Result<(Ty, Seg)> {
    let n = seg.len();
    let take = n.min(crate::bytes::to_u64(MAX_SIGNATURE).saturating_add(1));
    let tail_at = seg.start.saturating_add(n.saturating_sub(take));
    let tail = r.bytes(tail_at, take).await?;
    let Some(zero) = tail.iter().rposition(|&b| b == 0) else {
        return Err(bad(r, seg, "variant has no type string"));
    };
    let sig = tail.get(zero.saturating_add(1)..).unwrap_or_default();
    let Some(ty) = Ty::parse(sig) else {
        return Err(bad(
            r,
            seg,
            format!(
                "variant type {:?} is not a single complete type",
                String::from_utf8_lossy(sig)
            ),
        ));
    };
    let child_end = tail_at.saturating_add(crate::bytes::to_u64(zero));
    Ok((ty, Seg::new(seg.start, child_end)))
}

/// A maybe's child, if it is `Just` one.
pub async fn maybe(r: &mut ByteReader<'_>, seg: Seg, elem: &Ty) -> Result<Option<Seg>> {
    let n = seg.len();
    if n == 0 {
        return Ok(None);
    }
    match elem.fixed {
        Some(size) if size == n => Ok(Some(seg)),
        Some(size) => Err(bad(
            r,
            seg,
            format!("maybe of {n} bytes holds a {size}-byte value"),
        )),
        None => {
            let last = r.byte(seg.end.saturating_sub(1)).await?;
            if last != 0 {
                return Err(bad(r, seg, "maybe does not end in a zero byte"));
            }
            Ok(Some(Seg::new(seg.start, seg.end.saturating_sub(1))))
        }
    }
}

/// A string's text (its first [`MAX_TEXT`] bytes, lossy) and whether it
/// was cut; `Err` if it is not terminated or holds a zero byte.
pub async fn string(r: &mut ByteReader<'_>, seg: Seg, max: u64) -> Result<(String, bool)> {
    let n = seg.len();
    if n == 0 || r.byte(seg.end.saturating_sub(1)).await? != 0 {
        return Err(bad(r, seg, "string is not terminated by a zero byte"));
    }
    let len = n.saturating_sub(1);
    let take = len.min(max);
    let data = r.bytes(seg.start, take).await?;
    if data.contains(&0) {
        return Err(bad(r, seg, "string holds a zero byte"));
    }
    Ok((String::from_utf8_lossy(&data).into_owned(), take < len))
}

fn uint_of(data: &[u8], endian: Endian) -> u64 {
    match endian {
        Endian::Little => le_uint(data),
        Endian::Big => crate::formats::util::datakit::be_uint(data),
    }
}

/// A fixed-size scalar's value.
fn scalar(c: u8, data: &[u8], endian: Endian) -> (Value, Option<&'static str>) {
    let v = uint_of(data, endian);
    match c {
        b'b' => (Value::Bool(v != 0), None),
        b'y' => (val::uint(v, 8), None),
        b'n' => (val::int(v as u16 as i16, 16), None),
        b'q' => (val::uint(v, 16), None),
        b'i' => (val::int(v as u32 as i32, 32), None),
        b'u' => (val::uint(v, 32), None),
        b'h' => (val::int(v as u32 as i32, 32), Some("handle index")),
        b'x' => (val::int(v as i64, 64), None),
        b't' => (val::uint(v, 64), None),
        b'd' => (Value::f64(f64::from_bits(v)), None),
        _ => (val::uint(v, 64), None),
    }
}

/// The summary of a variant's value: its type in angle brackets, then
/// what the value's own summary adds ("as, 2 elements" becomes
/// "<as>, 2 elements").
pub fn typed_summary(sig: &str, summary: Option<&str>) -> String {
    match summary {
        Some(s) => match s.strip_prefix(sig) {
            Some(rest) if rest.is_empty() || rest.starts_with(',') => format!("<{sig}>{rest}"),
            _ => format!("<{sig}> {s}"),
        },
        None => format!("<{sig}>"),
    }
}

/// How values are rendered.
#[derive(Clone, Copy, Debug)]
pub struct Style {
    /// Byte order of numbers.
    pub endian: Endian,
}

/// State of a lazily expanded container.
#[derive(Clone)]
pub struct Lazy {
    pub region: Span,
    pub seg: Seg,
    pub ty: Arc<Ty>,
    pub style: Style,
    pub depth: u32,
}

/// A short description of a container of type `ty`.
fn container_summary(ty: &Ty, count: Option<u64>) -> String {
    let sig = clip(&ty.signature(), 40);
    match count {
        Some(n) => format!("{sig}, {}", grouped_count(n, "element", "elements")),
        None => sig,
    }
}

/// A byte array as a leaf: text when it is a NUL-terminated byte string of
/// printable text, bytes otherwise.
async fn byte_array(r: &mut ByteReader<'_>, node: Node, seg: Seg) -> Result<Node> {
    let n = seg.len();
    if n == 0 {
        return Ok(node.summary("ay, empty"));
    }
    if n <= MAX_TEXT {
        let data = r.bytes(seg.start, n).await?;
        if let Some((&0, text)) = data.split_last()
            && !text.is_empty()
            && let Ok(s) = std::str::from_utf8(text)
            && !s.chars().any(char::is_control)
        {
            return Ok(node
                .value(Value::Text(s.to_owned()))
                .summary(format!("bytestring, {}", grouped_count(n, "byte", "bytes"))));
        }
    }
    let data = r.bytes(seg.start, n.min(MAX_BYTES)).await?;
    Ok(node
        .value(Value::Bytes(data))
        .summary(format!("ay, {}", grouped_count(n, "byte", "bytes"))))
}

type NodeFuture<'a> = Pin<Box<dyn Future<Output = Node> + Send + 'a>>;

fn node_boxed<'a>(
    r: &'a mut ByteReader<'_>,
    name: String,
    seg: Seg,
    ty: &'a Ty,
    style: Style,
    depth: u32,
) -> NodeFuture<'a> {
    Box::pin(async move { node_inner(r, name, seg, ty, style, depth).await })
}

/// The node for the value of type `ty` at `seg`. Problems become
/// diagnostics on the node.
pub async fn node(
    r: &mut ByteReader<'_>,
    name: String,
    seg: Seg,
    ty: &Ty,
    style: Style,
    depth: u32,
) -> Node {
    node_boxed(r, name, seg, ty, style, depth).await
}

async fn node_inner(
    r: &mut ByteReader<'_>,
    name: String,
    seg: Seg,
    ty: &Ty,
    style: Style,
    depth: u32,
) -> Node {
    let base = Node::new(name.clone()).span(r.span(seg.start, seg.len()));
    match build(r, base.clone(), name, seg, ty, style, depth).await {
        Ok(node) => node,
        Err(d) => base.summary(clip(&ty.signature(), 40)).diag(d),
    }
}

async fn build(
    r: &mut ByteReader<'_>,
    node: Node,
    name: String,
    seg: Seg,
    ty: &Ty,
    style: Style,
    depth: u32,
) -> Result<Node> {
    let n = seg.len();
    let lazy = |node: Node, r: &ByteReader<'_>| -> Node {
        if depth >= MAX_DEPTH {
            return node.diag(Diagnostic::limit(format!(
                "values nested deeper than {MAX_DEPTH}"
            )));
        }
        node.lazy(
            crate::expander!(self::expand: Lazy),
            Lazy {
                region: r.region(),
                seg,
                ty: Arc::new(ty.clone()),
                style,
                depth: depth.saturating_add(1),
            },
        )
    };
    Ok(match &ty.kind {
        Kind::Basic(c @ (b's' | b'o' | b'g')) => {
            let (text, cut) = string(r, seg, MAX_TEXT).await?;
            let what = match c {
                b'o' => "object path",
                b'g' => "signature",
                _ => "string",
            };
            let node = node.value(Value::Text(text));
            if cut {
                node.summary(format!(
                    "{what}, {} (truncated)",
                    grouped_count(n.saturating_sub(1), "byte", "bytes")
                ))
            } else if *c == b's' {
                node
            } else {
                node.summary(what)
            }
        }
        Kind::Basic(c) => {
            let size = ty.fixed.unwrap_or(1);
            if n != size {
                return Err(bad(
                    r,
                    seg,
                    format!("{} value takes {n} bytes, not {size}", char::from(*c)),
                ));
            }
            let data = r.bytes(seg.start, size).await?;
            let (value, summary) = scalar(*c, &data, style.endian);
            let node = node.value(value);
            let node = match summary {
                Some(s) => node.summary(s),
                None => node,
            };
            if *c == b'b' && data.first().is_some_and(|&b| b > 1) {
                node.diag(Diagnostic::warning("boolean is neither 0 nor 1"))
            } else {
                node
            }
        }
        Kind::Variant => {
            let (inner, child) = variant(r, seg).await?;
            if depth >= MAX_DEPTH {
                return Ok(node
                    .summary(format!("<{}>", clip(&inner.signature(), 40)))
                    .diag(Diagnostic::limit(format!(
                        "values nested deeper than {MAX_DEPTH}"
                    ))));
            }
            let sig = clip(&inner.signature(), 40);
            let shown = node_boxed(r, name, child, &inner, style, depth.saturating_add(1)).await;
            let summary = typed_summary(&sig, shown.summary.as_deref());
            let mut shown = shown.span(r.span(seg.start, seg.len()));
            shown.summary = Some(summary);
            shown
        }
        Kind::Maybe(elem) => match maybe(r, seg, elem).await? {
            None => node.summary(format!("{}, nothing", clip(&ty.signature(), 40))),
            Some(child) => {
                let shown = node_boxed(r, name, child, elem, style, depth.saturating_add(1)).await;
                let summary = match &shown.summary {
                    Some(s) => format!("just {s}"),
                    None => "just".to_owned(),
                };
                let mut shown = shown.span(r.span(seg.start, seg.len()));
                shown.summary = Some(summary);
                shown
            }
        },
        Kind::Array(elem) if elem.kind == Kind::Basic(b'y') => byte_array(r, node, seg).await?,
        Kind::Array(elem) => {
            let frame = Frame::open(r, seg, elem).await?;
            let node = node.summary(container_summary(ty, Some(frame.count)));
            if frame.count == 0 {
                node
            } else {
                lazy(node, r)
            }
        }
        Kind::Tuple(members) if members.is_empty() => node.summary("()"),
        Kind::Tuple(_) | Kind::Entry(..) => lazy(node.summary(container_summary(ty, None)), r),
    })
}

/// A node name for a dictionary key.
async fn key_name(r: &mut ByteReader<'_>, seg: Seg, key: &Ty, style: Style, index: u64) -> String {
    let shown = node(r, String::new(), seg, key, style, MAX_DEPTH).await;
    let text = match &shown.value {
        Some(Value::Text(s)) => s.clone(),
        Some(v) => crate::render::value(v),
        None => String::new(),
    };
    if text.is_empty() || !shown.diagnostics.is_empty() {
        format!("key #{index}")
    } else {
        clip(&text, MAX_KEY)
    }
}

/// A dictionary entry shown under its key: the value's node, spanning the
/// whole entry.
async fn entry_node(
    r: &mut ByteReader<'_>,
    seg: Seg,
    k: &Ty,
    v: &Ty,
    style: Style,
    depth: u32,
    index: u64,
) -> Node {
    let parts = match members(r, seg, &[k.clone(), v.clone()]).await {
        Ok(p) => p,
        Err(d) => {
            return Node::new(format!("[{index}]"))
                .span(r.span(seg.start, seg.len()))
                .diag(d);
        }
    };
    let (Some(&ks), Some(&vs)) = (parts.first(), parts.get(1)) else {
        return Node::new(format!("[{index}]")).span(r.span(seg.start, seg.len()));
    };
    let name = key_name(r, ks, k, style, index).await;
    node(r, name, vs, v, style, depth)
        .await
        .span(r.span(seg.start, seg.len()))
}

/// The members of a container value.
pub async fn expand(cx: Cx, lazy: Lazy) -> Result<()> {
    let mut r = ByteReader::new(&cx, lazy.region);
    let Lazy {
        seg,
        ty,
        style,
        depth,
        ..
    } = lazy;
    match &ty.kind {
        Kind::Array(elem) => {
            let frame = Frame::open(&mut r, seg, elem).await?;
            cx.set_count(Count::Exact(frame.count));
            let mut i = cx.resume::<u64>().unwrap_or(0);
            while i < frame.count {
                let at = i;
                cx.mark(move || at);
                let item = frame.item(&mut r, i).await?;
                let child = match &elem.kind {
                    Kind::Entry(k, v) => entry_node(&mut r, item, k, v, style, depth, i).await,
                    _ => node(&mut r, format!("[{i}]"), item, elem, style, depth).await,
                };
                cx.push(child).await;
                i = i.saturating_add(1);
            }
        }
        Kind::Tuple(types) => {
            let parts = members(&mut r, seg, types).await?;
            for (i, (part, t)) in parts.iter().zip(types).enumerate() {
                let child = node(&mut r, format!("[{i}]"), *part, t, style, depth).await;
                cx.push(child).await;
            }
        }
        Kind::Entry(k, v) => {
            let parts = members(&mut r, seg, &[k.as_ref().clone(), v.as_ref().clone()]).await?;
            for (name, (part, t)) in ["Key", "Value"]
                .into_iter()
                .zip(parts.iter().zip([k.as_ref(), v.as_ref()]))
            {
                let child = node(&mut r, name.to_owned(), *part, t, style, depth).await;
                cx.push(child).await;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Whether `data` is a well-formed value of type `ty` (for probes: the
/// framing must be consistent all the way down, every string terminated
/// and free of zero bytes). Work is linear in `data` times the type's
/// depth; callers bound `data` (a probe window).
pub fn valid(data: &[u8], ty: &Ty) -> bool {
    valid_at(data, ty, 0)
}

fn sub(data: &[u8], start: u64, end: u64) -> Option<&[u8]> {
    data.get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
}

fn le_at(data: &[u8], at: u64, osz: u64) -> Option<u64> {
    sub(data, at, at.checked_add(osz)?).map(le_uint)
}

fn valid_at(data: &[u8], ty: &Ty, depth: u32) -> bool {
    if depth > PROBE_DEPTH {
        return false;
    }
    let deeper = depth.saturating_add(1);
    let n = crate::bytes::to_u64(data.len());
    if let Some(size) = ty.fixed
        && size != n
    {
        return false;
    }
    match &ty.kind {
        Kind::Basic(b's' | b'o' | b'g') => {
            matches!(data.split_last(), Some((&0, rest)) if !rest.contains(&0))
        }
        Kind::Basic(_) => true,
        Kind::Variant => {
            let Some(zero) = data.iter().rposition(|&b| b == 0) else {
                return false;
            };
            let Some(t) = data.get(zero.saturating_add(1)..).and_then(Ty::parse) else {
                return false;
            };
            data.get(..zero)
                .is_some_and(|child| valid_at(child, &t, deeper))
        }
        Kind::Maybe(elem) => match (n, elem.fixed) {
            (0, _) => true,
            (_, Some(_)) => valid_at(data, elem, deeper),
            _ => matches!(data.split_last(), Some((&0, rest)) if valid_at(rest, elem, deeper)),
        },
        Kind::Array(elem) => {
            if let Some(size) = elem.fixed {
                if size == 0 || !n.is_multiple_of(size) {
                    return false;
                }
                if elem.kind == Kind::Basic(b'y') {
                    return true;
                }
                return data
                    .chunks(usize::try_from(size).unwrap_or(usize::MAX))
                    .all(|c| valid_at(c, elem, deeper));
            }
            if n == 0 {
                return true;
            }
            let osz = offset_size(n);
            let Some(last) = le_at(data, n.saturating_sub(osz), osz) else {
                return false;
            };
            if last > n || !n.saturating_sub(last).is_multiple_of(osz) {
                return false;
            }
            let count = n.saturating_sub(last).checked_div(osz).unwrap_or(0);
            let mut start = 0u64;
            for i in 0..count {
                let Some(end) = le_at(data, last.saturating_add(i.saturating_mul(osz)), osz) else {
                    return false;
                };
                if start > end || end > last {
                    return false;
                }
                if !sub(data, start, end).is_some_and(|e| valid_at(e, elem, deeper)) {
                    return false;
                }
                start = align_up(end, elem.align);
            }
            true
        }
        Kind::Tuple(types) => valid_members(data, types.iter(), types.len(), deeper),
        Kind::Entry(k, v) => valid_members(data, [k.as_ref(), v.as_ref()].into_iter(), 2, deeper),
    }
}

/// The members of a tuple of `types` in `data` (synchronous, for probes
/// over a window they hold), if the framing is consistent. Members are not
/// validated themselves.
pub fn split<'d>(data: &'d [u8], types: &[Ty]) -> Option<Vec<&'d [u8]>> {
    let n = crate::bytes::to_u64(data.len());
    let osz = offset_size(n);
    let mut frame_end = n;
    let mut pos = 0u64;
    let mut out = Vec::with_capacity(types.len());
    for (i, t) in types.iter().enumerate() {
        let start = align_up(pos, t.align);
        let end = match t.fixed {
            Some(size) => start.saturating_add(size),
            None if i.saturating_add(1) == types.len() => frame_end,
            None => {
                frame_end = frame_end.checked_sub(osz)?;
                le_at(data, frame_end, osz)?
            }
        };
        if start > end || end > frame_end {
            return None;
        }
        out.push(sub(data, start, end)?);
        pos = end;
    }
    Some(out)
}

fn valid_members<'a>(
    data: &[u8],
    types: impl Iterator<Item = &'a Ty>,
    count: usize,
    depth: u32,
) -> bool {
    let n = crate::bytes::to_u64(data.len());
    let osz = offset_size(n);
    let mut frame_end = n;
    let mut pos = 0u64;
    for (i, t) in types.enumerate() {
        let start = align_up(pos, t.align);
        let end = match t.fixed {
            Some(size) => start.saturating_add(size),
            None if i.saturating_add(1) == count => frame_end,
            None => {
                let Some(fe) = frame_end.checked_sub(osz) else {
                    return false;
                };
                frame_end = fe;
                match le_at(data, frame_end, osz) {
                    Some(v) => v,
                    None => return false,
                }
            }
        };
        if start > end || end > frame_end {
            return false;
        }
        if !sub(data, start, end).is_some_and(|m| valid_at(m, t, depth)) {
            return false;
        }
        pos = end;
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn types() {
        let t = Ty::parse(b"(a{sv}aya(say)sstayay)").unwrap();
        assert_eq!(t.signature(), "(a{sv}aya(say)sstayay)");
        assert_eq!(t.align(), 8);
        assert_eq!(t.fixed(), None);
        let t = Ty::parse(b"(uuu)").unwrap();
        assert_eq!(t.fixed(), Some(12));
        let t = Ty::parse(b"(yt)").unwrap();
        assert_eq!(t.fixed(), Some(16));
        assert_eq!(Ty::parse(b"()").unwrap().fixed(), Some(1));
        assert!(Ty::parse(b"a").is_none());
        assert!(Ty::parse(b"{vs}").is_none());
        assert!(Ty::parse(b"ss").is_none());
        assert!(Ty::parse(b"(s").is_none());
        let deep = [b'a'; 300];
        assert!(Ty::parse(&deep).is_none());
    }

    #[test]
    fn validation() {
        let t = Ty::parse(b"(uuay)").unwrap();
        // 4 + 4 + "hi" (no framing offset: the last member)
        assert!(valid(&[1, 0, 0, 0, 0, 0, 0, 0, b'h', b'i'], &t));
        let t = Ty::parse(b"as").unwrap();
        // "a\0" "bc\0", offsets 2, 5
        assert!(valid(b"a\0bc\0\x02\x05", &t));
        assert!(!valid(b"a\0bc\0\x02\x09", &t));
        let v = Ty::parse(b"v").unwrap();
        assert!(valid(b"x\0\0s", &v));
        assert!(!valid(b"x\0ss", &v));
    }
}
