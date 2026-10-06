//! A schema-driven protocol buffer walker.
//!
//! Protobuf messages carry no type information, so a dissector supplies a
//! small static schema ([`Msg`]): field numbers, names and types. Unknown
//! fields are still shown, by wire type, with a guess for length-delimited
//! ones (text, nested message or bytes). Nested messages are lazy nodes, and
//! repeated fields are pushed one by one, so a graph with a million nodes
//! costs only the page being looked at.

use crate::bytes::{to_u64, to_usize, uleb128};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

/// Nested messages deeper than this are not expanded.
const MAX_DEPTH: u32 = 48;
/// Messages up to this size are read to compute their title.
const TITLE_MAX: u64 = 16 * 1024;
/// How much of a string field is shown.
const TEXT_MAX: u64 = 256;

/// How a field is decoded.
#[derive(Clone, Copy)]
pub enum Ty {
    /// A varint, shown as signed if the top bit is set (`int32`/`int64`).
    Int,
    /// A zig-zag varint (`sint32`/`sint64`).
    SInt,
    Bool,
    Enum(EnumTable),
    Str,
    Bytes,
    Float,
    Double,
    Msg(&'static Msg),
    /// A packed repeated scalar (or a single unpacked element).
    Packed(Elem),
}

/// Element type of packed repeated fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Elem {
    Varint,
    Float,
    Double,
}

/// One field of a message schema.
pub struct F {
    pub num: u64,
    pub name: &'static str,
    pub ty: Ty,
}

pub const fn f(num: u64, name: &'static str, ty: Ty) -> F {
    F { num, name, ty }
}

/// A message schema.
pub struct Msg {
    pub name: &'static str,
    pub fields: &'static [F],
    /// String fields that, joined, summarise an instance (e.g. a node's
    /// name and operator).
    pub title: &'static [u64],
}

/// A schema that knows no fields: everything is shown by wire type.
pub static UNKNOWN: Msg = Msg {
    name: "message",
    fields: &[],
    title: &[],
};

/// A raw field, as found by [`fields_in`] or [`scan`].
#[derive(Clone, Copy, Debug)]
pub struct Raw {
    pub num: u64,
    pub wire: u8,
    /// The varint or fixed value (0 for length-delimited fields).
    pub value: u64,
    /// Body of a length-delimited field, relative to the scanned data
    /// (or the region, for [`scan`]); empty otherwise.
    pub at: u64,
    pub len: u64,
}

/// Iterates the fields of a message held in memory. Stops at the first
/// malformed or truncated field.
pub fn fields_in(data: &[u8]) -> impl Iterator<Item = Raw> + '_ {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let rest = data.get(pos..)?;
        if rest.is_empty() {
            return None;
        }
        let (key, n) = uleb128(rest)?;
        let mut at = pos.checked_add(n)?;
        let num = key >> 3;
        let wire = u8::try_from(key & 7).ok()?;
        if num == 0 {
            return None;
        }
        let mut raw = Raw {
            num,
            wire,
            value: 0,
            at: 0,
            len: 0,
        };
        match wire {
            0 => {
                let (v, n) = uleb128(data.get(at..)?)?;
                raw.value = v;
                at = at.checked_add(n)?;
            }
            1 => {
                raw.value = crate::bytes::u64_le(data, at)?;
                at = at.checked_add(8)?;
            }
            5 => {
                raw.value = crate::bytes::u32_le(data, at)?.into();
                at = at.checked_add(4)?;
            }
            2 => {
                let (len, n) = uleb128(data.get(at..)?)?;
                at = at.checked_add(n)?;
                let end = at.checked_add(usize::try_from(len).ok()?)?;
                if end > data.len() {
                    return None;
                }
                raw.at = to_u64(at);
                raw.len = len;
                at = end;
            }
            _ => return None,
        }
        pos = at;
        Some(raw)
    })
}

/// Whether `data` parses completely as a message (all fields well formed,
/// ending exactly at the end).
pub fn is_message(data: &[u8]) -> bool {
    let mut pos = 0usize;
    for raw in fields_in(data) {
        match field_end(data, pos, &raw) {
            Some(end) => pos = end,
            None => return false,
        }
    }
    pos > 0 && pos == data.len()
}

/// The end of `raw`, which starts at `pos` in `data`.
fn field_end(data: &[u8], pos: usize, raw: &Raw) -> Option<usize> {
    if raw.wire == 2 {
        return usize::try_from(raw.at.checked_add(raw.len)?).ok();
    }
    let (_, n) = uleb128(data.get(pos..)?)?;
    let at = pos.checked_add(n)?;
    match raw.wire {
        0 => uleb128(data.get(at..)?).and_then(|(_, m)| at.checked_add(m)),
        1 => at.checked_add(8),
        5 => at.checked_add(4),
        _ => None,
    }
}

/// The first string value of field `num` in a message held in memory.
pub fn string_in(data: &[u8], num: u64) -> Option<String> {
    fields_in(data)
        .find(|r| r.num == num && r.wire == 2)
        .and_then(|r| {
            let start = to_usize(r.at);
            let bytes = data.get(start..start.checked_add(to_usize(r.len))?)?;
            Some(String::from_utf8_lossy(bytes).into_owned())
        })
}

/// The first varint value of field `num` in a message held in memory.
pub fn varint_in(data: &[u8], num: u64) -> Option<u64> {
    fields_in(data)
        .find(|r| r.num == num && r.wire == 0)
        .map(|r| r.value)
}

/// Reads the field headers of the message in `span` without reading the
/// bodies of length-delimited fields; at most `max` fields.
pub async fn scan(cx: &Cx, span: Span, max: usize) -> Result<Vec<Raw>> {
    let mut cur = Cursor::new(cx, span, Endian::Little);
    let mut out = Vec::new();
    while !cur.at_end() && out.len() < max {
        let (num, wire) = key(&mut cur).await?;
        let mut raw = Raw {
            num,
            wire,
            value: 0,
            at: 0,
            len: 0,
        };
        match wire {
            0 => raw.value = cur.uleb128().await?,
            1 => raw.value = cur.u64().await?,
            5 => raw.value = cur.u32().await?.into(),
            2 => {
                let len = cur.uleb128().await?;
                raw.at = cur.pos();
                raw.len = len;
                if cur.remaining() < len {
                    return Err(Diagnostic::truncated(
                        Span::new(span.source, span.offset.saturating_add(raw.at), len),
                        cur.remaining(),
                    ));
                }
                cur.skip(len);
            }
            _ => return Err(unsupported_wire(&cur, wire)),
        }
        out.push(raw);
    }
    Ok(out)
}

async fn key(cur: &mut Cursor<'_>) -> Result<(u64, u8)> {
    let start = cur.pos();
    let key = cur.uleb128().await?;
    let num = key >> 3;
    if num == 0 {
        return Err(Diagnostic::malformed("field number 0").at(cur.since(start)));
    }
    Ok((num, u8::try_from(key & 7).unwrap_or(7)))
}

fn unsupported_wire(cur: &Cursor<'_>, wire: u8) -> Diagnostic {
    let d = if matches!(wire, 3 | 4) {
        Diagnostic::unsupported("protobuf groups")
    } else {
        Diagnostic::malformed(format!("wire type {wire}"))
    };
    d.at(cur.span(1))
}

fn uint(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    }
}

fn signed(value: u64) -> Value {
    let v = i64::from_ne_bytes(value.to_ne_bytes());
    if v < 0 {
        Value::Int { value: v, bits: 64 }
    } else {
        uint(value)
    }
}

fn zigzag(value: u64) -> Value {
    let half = i64::from_ne_bytes((value >> 1).to_ne_bytes());
    let v = if value & 1 == 0 { half } else { !half };
    Value::Int { value: v, bits: 64 }
}

fn varint_value(ty: Option<Ty>, v: u64) -> Value {
    match ty {
        Some(Ty::SInt) => zigzag(v),
        Some(Ty::Bool) => Value::Bool(v != 0),
        Some(Ty::Enum(table)) => Value::Enum {
            raw: v,
            bits: 32,
            name: lookup(table, v),
        },
        _ => signed(v),
    }
}

fn f32_of(v: u64) -> f64 {
    widen(f32::from_bits(u32::try_from(v & 0xffff_ffff).unwrap_or(0)))
}

/// An `f32` as the `f64` with the same shortest decimal form (0.1, not
/// 0.10000000149011612).
pub fn widen(x: f32) -> f64 {
    x.to_string().parse().unwrap_or_else(|_| f64::from(x))
}

/// A compact, printable rendition of a string field.
fn short(bytes: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(bytes).into_owned();
    if s.chars().count() > 80 {
        s = s.chars().take(80).collect::<String>() + "…";
    }
    s
}

fn printable(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && std::str::from_utf8(bytes).is_ok_and(|s| {
            s.chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        })
}

/// The title of a message instance from its title fields, if it is small
/// enough to read.
async fn title(cx: &Cx, body: Span, msg: &'static Msg) -> Result<Option<String>> {
    if msg.title.is_empty() || body.len > TITLE_MAX {
        return Ok(None);
    }
    let data = cx.read(body).await?;
    let parts: Vec<String> = msg
        .title
        .iter()
        .filter_map(
            |&n| match msg.fields.iter().find(|f| f.num == n).map(|f| f.ty) {
                Some(Ty::Int | Ty::Enum(_)) => {
                    let v = varint_in(&data, n)?;
                    Some(match msg.fields.iter().find(|f| f.num == n).map(|f| f.ty) {
                        Some(Ty::Enum(t)) => {
                            lookup(t, v).map_or_else(|| v.to_string(), str::to_owned)
                        }
                        _ => v.to_string(),
                    })
                }
                _ => string_in(&data, n)
                    .filter(|s| !s.is_empty())
                    .map(|s| short(s.as_bytes())),
            },
        )
        .collect();
    Ok((!parts.is_empty()).then(|| parts.join(" · ")))
}

/// State of a lazy message node.
pub type State = (Span, &'static Msg, u32);

/// A lazy node for a message of type `msg` at `span`.
pub fn node(name: &'static str, span: Span, msg: &'static Msg) -> Node {
    Node::new(name)
        .span(span)
        .lazy(crate::expander!(self::message: State), (span, msg, 0u32))
}

/// Walks one message, pushing a node per field.
pub async fn message(cx: Cx, (span, msg, depth): State) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Diagnostic::limit("messages nested too deeply").at(span));
    }
    let mut cur = Cursor::new(&cx, span, Endian::Little);
    while !cur.at_end() {
        let start = cur.pos();
        let (num, wire) = key(&mut cur).await?;
        let spec = msg.fields.iter().find(|f| f.num == num);
        let label: std::borrow::Cow<'static, str> = match spec {
            Some(f) => f.name.into(),
            None => format!("field {num}").into(),
        };
        let ty = spec.map(|f| f.ty);
        let node = match wire {
            0 => {
                let v = cur.uleb128().await?;
                Node::new(label).value(varint_value(ty, v))
            }
            1 => {
                let v = cur.u64().await?;
                match ty {
                    Some(Ty::Double | Ty::Packed(Elem::Double)) => {
                        Node::new(label).value(Value::Float(f64::from_bits(v)))
                    }
                    _ => Node::new(label).value(Value::UInt {
                        value: v,
                        bits: 64,
                        radix: Radix::Hex,
                    }),
                }
            }
            5 => {
                let v = u64::from(cur.u32().await?);
                match ty {
                    Some(Ty::Float | Ty::Packed(Elem::Float)) => {
                        Node::new(label).value(Value::Float(f32_of(v)))
                    }
                    _ => Node::new(label).value(Value::UInt {
                        value: v,
                        bits: 32,
                        radix: Radix::Hex,
                    }),
                }
            }
            2 => {
                let len = cur.uleb128().await?;
                let body = cur.span(len);
                if body.len < len {
                    return Err(Diagnostic::truncated(
                        Span::new(body.source, body.offset, len),
                        body.len,
                    ));
                }
                cur.skip(len);
                delimited(&cx, label, body, ty, depth).await?
            }
            _ => return Err(unsupported_wire(&cur, wire)),
        };
        cx.push(node.span(cur.since(start))).await;
    }
    Ok(())
}

async fn delimited(
    cx: &Cx,
    label: std::borrow::Cow<'static, str>,
    body: Span,
    ty: Option<Ty>,
    depth: u32,
) -> Result<Node> {
    let child = depth.saturating_add(1);
    Ok(match ty {
        Some(Ty::Str) => {
            let data = cx.read(body.sub(0, TEXT_MAX)).await?;
            let node =
                Node::new(label).value(Value::Text(String::from_utf8_lossy(&data).into_owned()));
            if body.len > TEXT_MAX {
                node.summary(format!("{} bytes", body.len))
            } else {
                node
            }
        }
        Some(Ty::Msg(m)) => {
            let summary = match title(cx, body, m).await? {
                Some(t) => t,
                None => format!("{}, {} bytes", m.name, body.len),
            };
            Node::new(label)
                .summary(summary)
                .lazy(crate::expander!(self::message: State), (body, m, child))
        }
        Some(Ty::Packed(elem)) => Node::new(label)
            .summary(packed_summary(cx, body, elem).await?)
            .lazy(packed, (body, elem)),
        Some(Ty::Bytes) => Node::new(label).summary(format!("{} bytes", body.len)),
        _ => {
            // Unknown: text, a nested message, or opaque bytes.
            let data = cx.read(body.sub(0, TITLE_MAX)).await?;
            let whole = to_u64(data.len()) == body.len;
            if whole && printable(&data) {
                Node::new(label).value(Value::Text(short(&data)))
            } else if whole && is_message(&data) {
                Node::new(label)
                    .summary(format!("message?, {} bytes", body.len))
                    .lazy(
                        crate::expander!(self::message: State),
                        (body, &UNKNOWN, child),
                    )
            } else {
                Node::new(label).summary(format!("{} bytes", body.len))
            }
        }
    })
}

fn elem_values(data: &[u8], elem: Elem) -> Vec<(Value, usize, usize)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some(rest) = data.get(pos..).filter(|r| !r.is_empty()) {
        let (value, n) = match elem {
            Elem::Varint => match uleb128(rest) {
                Some((v, n)) => (signed(v), n),
                None => break,
            },
            Elem::Float => match crate::bytes::u32_le(rest, 0) {
                Some(v) => (Value::Float(widen(f32::from_bits(v))), 4),
                None => break,
            },
            Elem::Double => match crate::bytes::u64_le(rest, 0) {
                Some(v) => (Value::Float(f64::from_bits(v)), 8),
                None => break,
            },
        };
        out.push((value, pos, n));
        pos = pos.saturating_add(n);
    }
    out
}

fn show(v: &Value) -> String {
    match v {
        Value::UInt { value, .. } => value.to_string(),
        Value::Int { value, .. } => value.to_string(),
        Value::Float(x) => format!("{x}"),
        _ => String::new(),
    }
}

async fn packed_summary(cx: &Cx, body: Span, elem: Elem) -> Result<String> {
    let data = cx.read(body.sub(0, 512)).await?;
    let values = elem_values(&data, elem);
    let shown: Vec<String> = values.iter().take(8).map(|(v, _, _)| show(v)).collect();
    let more = if values.len() > 8 || to_u64(data.len()) < body.len {
        ", …"
    } else {
        ""
    };
    Ok(format!("[{}{more}]", shown.join(", ")))
}

/// Expands a packed field into its elements (the first 4096).
async fn packed(cx: Cx, (body, elem): (Span, Elem)) -> Result<()> {
    let data = cx.read(body.sub(0, 64 * 1024)).await?;
    let values = elem_values(&data, elem);
    let total = values.len();
    for (i, (value, at, n)) in values.into_iter().take(4096).enumerate() {
        cx.push(
            Node::new(format!("[{i}]"))
                .span(body.sub(to_u64(at), to_u64(n)))
                .value(value),
        )
        .await;
    }
    if total > 4096 || to_u64(data.len()) < body.len {
        cx.diag(Diagnostic::limit("only the first elements are shown").at(body));
    }
    Ok(())
}

impl std::fmt::Debug for Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}
