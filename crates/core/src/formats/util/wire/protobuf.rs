//! Protocol Buffers wire format.
//!
//! Low level: [`field`] and [`fields_in`] read fields of a message held in
//! memory (probes, small headers); [`read_field`] and [`scan`] read through
//! a cursor without reading the bodies of length-delimited fields.
//!
//! Schema-driven walker: protobuf messages carry no type information, so a
//! dissector supplies a small static schema ([`Msg`]): field numbers, names and types. Unknown
//! fields are still shown, by wire type, with a guess for length-delimited
//! ones (text, nested message or bytes). Nested messages are lazy nodes, and
//! repeated fields are pushed one by one, so a graph with a million nodes
//! costs only the page being looked at.

use crate::bytes::{to_u64, uleb128};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, decode_flags, lookup};
use std::borrow::Cow;

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
    /// An unsigned varint (`uint32`/`uint64`), shown in decimal.
    UInt,
    /// A zig-zag varint (`sint32`/`sint64`).
    SInt,
    Bool,
    Enum(EnumTable),
    /// An unsigned varint shown in hexadecimal (addresses, masks).
    Hex,
    /// An unsigned varint of seconds since the Unix epoch, UTC.
    Time,
    /// An unsigned varint holding flags.
    Flags(FlagTable),
    /// An unsigned varint some of whose values have names (sentinels such
    /// as `RLIM_INFINITY` or `SIG_DFL`); other values are shown in the
    /// radix.
    Named(EnumTable, Radix),
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
    /// How the elements of a repeated field are labelled.
    pub index: Index,
}

pub const fn f(num: u64, name: &'static str, ty: Ty) -> F {
    F {
        num,
        name,
        ty,
        index: Index::None,
    }
}

impl F {
    /// The field, with its repeated elements labelled by `index`.
    pub const fn indexed(self, index: Index) -> F {
        F { index, ..self }
    }
}

/// How the elements of a repeated field are labelled where their position
/// means something (resource limits by `RLIMIT_*` number, registers by
/// number, key/value pairs).
#[derive(Clone, Copy)]
pub enum Index {
    /// By the field's name.
    None,
    /// By a label computed from the element's position (from 0).
    Label(fn(u64) -> Cow<'static, str>),
    /// Key/value pairs of scalars (an ELF auxiliary vector): even elements
    /// are keys, labelled `key` and named by `keys`; odd ones are values,
    /// labelled by their key's name and shown in decimal for the keys in
    /// `decimal`, in hexadecimal otherwise.
    Pairs {
        key: &'static str,
        keys: EnumTable,
        decimal: &'static [u64],
    },
}

/// The label and value of the element at position `i` of a repeated
/// field (`key`: the element before it, for [`Index::Pairs`]).
fn element(spec: &F, i: u64, key: u64, value: Value) -> (Cow<'static, str>, Value) {
    match spec.index {
        Index::None => (spec.name.into(), value),
        Index::Label(label) => (label(i), value),
        Index::Pairs {
            key: key_label,
            keys,
            decimal,
        } => {
            let Some(raw) = scalar(&value) else {
                return (spec.name.into(), value);
            };
            if i.is_multiple_of(2) {
                let named = Value::Enum {
                    raw,
                    bits: 64,
                    name: lookup(keys, raw).map(Into::into),
                };
                return (key_label.into(), named);
            }
            let label: Cow<'static, str> = match lookup(keys, key) {
                Some(name) => name.into(),
                None => format!("{}[{i}]", spec.name).into(),
            };
            let radix = if decimal.contains(&key) {
                Radix::Dec
            } else {
                Radix::Hex
            };
            let value = Value::UInt {
                value: raw,
                bits: 64,
                radix,
            };
            (label, value)
        }
    }
}

/// The raw bits of a varint's value.
fn scalar(value: &Value) -> Option<u64> {
    match *value {
        Value::UInt { value, .. } => Some(value),
        Value::Int { value, .. } => Some(u64::from_ne_bytes(value.to_ne_bytes())),
        Value::Enum { raw, .. } => Some(raw),
        _ => None,
    }
}

/// A message schema.
pub struct Msg {
    pub name: &'static str,
    pub fields: &'static [F],
    /// Fields that, joined, summarise an instance (e.g. a node's name and
    /// operator); see [`title_of`].
    pub title: &'static [u64],
}

/// A schema that knows no fields: everything is shown by wire type.
pub static UNKNOWN: Msg = Msg {
    name: "message",
    fields: &[],
    title: &[],
};

// ---------------------------------------------------------------------------
// Wire format, in memory

/// Wire types (the low three bits of a field key).
pub const VARINT: u8 = 0;
pub const I64: u8 = 1;
pub const LEN: u8 = 2;
pub const SGROUP: u8 = 3;
pub const EGROUP: u8 = 4;
pub const I32: u8 = 5;

/// Names of the wire types, as in the protobuf encoding guide.
pub const WIRE_TYPES: EnumTable = &[
    (0, "VARINT"),
    (1, "I64"),
    (2, "LEN"),
    (3, "SGROUP"),
    (4, "EGROUP"),
    (5, "I32"),
];

/// The largest valid field number (2^29 - 1).
pub const MAX_FIELD: u64 = (1 << 29) - 1;

/// A varint at `*at`, advancing past it.
pub fn varint(data: &[u8], at: &mut usize) -> Option<u64> {
    let (v, n) = uleb128(data.get(*at..)?)?;
    *at = at.checked_add(n)?;
    Some(v)
}

/// Decodes a zig-zag varint (`sint32`/`sint64`).
pub fn zigzag(v: u64) -> i64 {
    let half = i64::from_ne_bytes((v >> 1).to_ne_bytes());
    if v & 1 == 0 { half } else { !half }
}

/// One field of a message held in memory: number, wire type, and either
/// the scalar or the byte range of a length-delimited payload.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub number: u64,
    pub wire: u8,
    /// The varint or fixed value; the payload length for `LEN` fields.
    pub value: u64,
    /// Start and end of the field (key included).
    pub start: usize,
    pub end: usize,
    /// Start of the value (of the payload, for `LEN` fields).
    pub body: usize,
}

impl Field {
    /// The value's bytes (the payload of a `LEN` field).
    pub fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        data.get(self.body..self.end).unwrap_or_default()
    }

    /// Length of the value's bytes.
    pub fn value_len(&self) -> usize {
        self.end.saturating_sub(self.body)
    }
}

/// The next field of a message at `*at`; `None` at the end or on malformed
/// input (field number 0, groups and unknown wire types, overruns).
pub fn field(data: &[u8], at: &mut usize) -> Option<Field> {
    let start = *at;
    let key = varint(data, at)?;
    let number = key >> 3;
    let wire = u8::try_from(key & 7).ok()?;
    if number == 0 {
        return None;
    }
    let mut body = *at;
    let value = match wire {
        VARINT => varint(data, at)?,
        I64 => {
            let v = crate::bytes::u64_le(data, *at)?;
            *at = at.checked_add(8)?;
            v
        }
        I32 => {
            let v = crate::bytes::u32_le(data, *at)?;
            *at = at.checked_add(4)?;
            u64::from(v)
        }
        LEN => {
            let len = usize::try_from(varint(data, at)?).ok()?;
            body = *at;
            let end = body.checked_add(len)?;
            if end > data.len() {
                return None;
            }
            *at = end;
            to_u64(len)
        }
        _ => return None,
    };
    Some(Field {
        number,
        wire,
        value,
        start,
        end: *at,
        body,
    })
}

/// Iterates the fields of a message held in memory. Stops at the end or at
/// the first malformed or truncated field.
pub fn fields_in(data: &[u8]) -> impl Iterator<Item = Field> + '_ {
    let mut pos = 0usize;
    std::iter::from_fn(move || field(data, &mut pos))
}

/// All fields of a message, or `None` if it does not parse exactly.
pub fn all_fields(data: &[u8]) -> Option<Vec<Field>> {
    let mut at = 0usize;
    let mut out = Vec::new();
    while at < data.len() {
        out.push(field(data, &mut at)?);
    }
    Some(out)
}

/// Whether `data` parses completely as a non-empty message (all fields
/// well formed, ending exactly at the end).
pub fn is_message(data: &[u8]) -> bool {
    let mut at = 0usize;
    while at < data.len() {
        if field(data, &mut at).is_none() {
            return false;
        }
    }
    at > 0
}

/// The first string value of field `num` in a message held in memory.
pub fn string_in(data: &[u8], num: u64) -> Option<String> {
    fields_in(data)
        .find(|r| r.number == num && r.wire == LEN)
        .map(|r| String::from_utf8_lossy(r.payload(data)).into_owned())
}

/// The first varint value of field `num` in a message held in memory.
pub fn varint_in(data: &[u8], num: u64) -> Option<u64> {
    fields_in(data)
        .find(|r| r.number == num && r.wire == VARINT)
        .map(|r| r.value)
}

// ---------------------------------------------------------------------------
// Wire format, through a cursor

/// The value of a field read through a cursor.
#[derive(Clone, Copy, Debug)]
pub enum Payload {
    Varint(u64),
    I64(u64),
    I32(u32),
    /// A length-delimited payload (not read; the cursor is past it).
    Len(Span),
    /// The start or the end of a (deprecated) group; the cursor is past
    /// the key.
    StartGroup,
    EndGroup,
}

/// Reads a field key: field number (never 0) and wire type.
pub async fn read_key(cur: &mut Cursor<'_>) -> Result<(u64, u8)> {
    let start = cur.pos();
    let key = cur.uleb128().await?;
    let num = key >> 3;
    if num == 0 {
        return Err(Diagnostic::malformed("field number 0").at(cur.since(start)));
    }
    Ok((num, u8::try_from(key & 7).unwrap_or(7)))
}

/// Reads one field: its number and value. The body of a length-delimited
/// field is skipped (and must fit in the region); wire types 6 and 7 are
/// errors.
pub async fn read_field(cur: &mut Cursor<'_>) -> Result<(u64, Payload)> {
    let (num, wire) = read_key(cur).await?;
    let payload = match wire {
        VARINT => Payload::Varint(cur.uleb128().await?),
        I64 => Payload::I64(cur.u64().await?),
        I32 => Payload::I32(cur.u32().await?),
        LEN => {
            let len = cur.uleb128().await?;
            let body = cur.span(len);
            if body.len < len {
                return Err(Diagnostic::truncated(
                    Span::new(body.source, body.offset, len),
                    body.len,
                ));
            }
            cur.skip(len);
            Payload::Len(body)
        }
        SGROUP => Payload::StartGroup,
        EGROUP => Payload::EndGroup,
        _ => return Err(Diagnostic::malformed(format!("wire type {wire}")).at(cur.span(1))),
    };
    Ok((num, payload))
}

/// A raw field, as found by [`scan`]: positions are relative to the
/// scanned region.
#[derive(Clone, Copy, Debug)]
pub struct Raw {
    pub num: u64,
    pub wire: u8,
    /// The varint or fixed value (0 for length-delimited fields).
    pub value: u64,
    /// Body of a length-delimited field; empty otherwise.
    pub at: u64,
    pub len: u64,
}

/// Reads the field headers of the message in `span` without reading the
/// bodies of length-delimited fields; at most `max` fields.
pub async fn scan(cx: &Cx, span: Span, max: usize) -> Result<Vec<Raw>> {
    let mut cur = Cursor::new(cx, span, Endian::Little);
    let mut out = Vec::new();
    while !cur.at_end() && out.len() < max {
        let (num, payload) = read_field(&mut cur).await?;
        let mut raw = Raw {
            num,
            wire: VARINT,
            value: 0,
            at: 0,
            len: 0,
        };
        match payload {
            Payload::Varint(v) => raw.value = v,
            Payload::I64(v) => (raw.wire, raw.value) = (I64, v),
            Payload::I32(v) => (raw.wire, raw.value) = (I32, v.into()),
            Payload::Len(body) => {
                raw.wire = LEN;
                raw.at = body.offset.saturating_sub(span.offset);
                raw.len = body.len;
            }
            Payload::StartGroup | Payload::EndGroup => return Err(groups(&cur)),
        }
        out.push(raw);
    }
    Ok(out)
}

/// Groups are not followed by the schema-driven walker.
fn groups(cur: &Cursor<'_>) -> Diagnostic {
    Diagnostic::unsupported("protobuf groups").at(cur.span(1))
}

// ---------------------------------------------------------------------------
// Schema-driven walker

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

fn zigzag_value(value: u64) -> Value {
    Value::Int {
        value: zigzag(value),
        bits: 64,
    }
}

fn varint_value(ty: Option<Ty>, v: u64) -> Value {
    match ty {
        Some(Ty::SInt) => zigzag_value(v),
        Some(Ty::Bool) => Value::Bool(v != 0),
        Some(Ty::Enum(table)) => Value::Enum {
            raw: v,
            bits: 32,
            name: lookup(table, v).map(Into::into),
        },
        Some(Ty::Hex) => Value::UInt {
            value: v,
            bits: 64,
            radix: Radix::Hex,
        },
        Some(Ty::Flags(table)) => {
            let (set, unknown) = decode_flags(table, v);
            Value::Flags {
                raw: v,
                bits: if v > u64::from(u32::MAX) { 64 } else { 32 },
                set,
                unknown,
            }
        }
        Some(Ty::Named(table, radix)) => match lookup(table, v) {
            Some(name) => Value::Enum {
                raw: v,
                bits: 64,
                name: Some(name.into()),
            },
            None => Value::UInt {
                value: v,
                bits: 64,
                radix,
            },
        },
        Some(Ty::UInt) => uint(v),
        Some(Ty::Time) => Value::utc(i64::try_from(v).unwrap_or(i64::MAX)),
        _ => signed(v),
    }
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
    Ok(title_of(&data, msg))
}

/// A summary of a message held in memory (or a prefix of one) from its
/// schema's title fields, joined by " · ": strings, enum names and set
/// flags as they are; hexadecimal numbers ([`Ty::Hex`]) as `name=0x…`;
/// decimal ones as `name=value`, or bare when they are the whole title (a
/// dimension, a count); booleans as their name when true. `None` if no
/// title field is present.
pub fn title_of(data: &[u8], msg: &'static Msg) -> Option<String> {
    // (text, decimal number's field name)
    let mut parts: Vec<(String, Option<&str>)> = Vec::new();
    for &num in msg.title {
        let Some(spec) = msg.fields.iter().find(|f| f.num == num) else {
            continue;
        };
        if let Ty::Int | Ty::UInt | Ty::SInt | Ty::Named(_, Radix::Dec) = spec.ty {
            if let Some(v) = varint_in(data, num) {
                parts.push((show(&varint_value(Some(spec.ty), v)), Some(spec.name)));
            }
            continue;
        }
        let part = match spec.ty {
            Ty::Hex => varint_in(data, num).map(|v| format!("{}={v:#x}", spec.name)),
            Ty::Named(table, _) => varint_in(data, num).map(|v| match lookup(table, v) {
                Some(name) => name.to_owned(),
                None => format!("{}={v:#x}", spec.name),
            }),
            Ty::Bool => varint_in(data, num)
                .filter(|&v| v != 0)
                .map(|_| spec.name.to_owned()),
            Ty::Enum(table) => varint_in(data, num)
                .map(|v| lookup(table, v).map_or_else(|| v.to_string(), str::to_owned)),
            Ty::Flags(table) => varint_in(data, num).map(|v| {
                let (set, unknown) = decode_flags(table, v);
                let mut s = set.join("|");
                if unknown != 0 || s.is_empty() {
                    if !s.is_empty() {
                        s.push('|');
                    }
                    s.push_str(&format!("{unknown:#x}"));
                }
                s
            }),
            _ => string_in(data, num).map(|s| short(s.as_bytes())),
        };
        if let Some(p) = part.filter(|p| !p.is_empty()) {
            parts.push((p, None));
        }
    }
    match parts.as_slice() {
        [] => None,
        [(only, _)] => Some(only.clone()),
        _ => Some(
            parts
                .iter()
                .map(|(text, name)| match name {
                    Some(name) => format!("{name}={text}"),
                    None => text.clone(),
                })
                .collect::<Vec<_>>()
                .join(" · "),
        ),
    }
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
    // Fields labelled by position: number, elements seen, last value.
    let mut seen: Vec<(u64, u64, u64)> = Vec::new();
    while !cur.at_end() {
        let start = cur.pos();
        let (num, payload) = read_field(&mut cur).await?;
        let spec = msg.fields.iter().find(|f| f.num == num);
        let mut label: Cow<'static, str> = match spec {
            Some(f) => f.name.into(),
            None => format!("field {num}").into(),
        };
        let ty = spec.map(|f| f.ty);
        // The element's position and the one before it, if it counts.
        // (A packed run labels its elements itself.)
        let packed_run = matches!((ty, payload), (Some(Ty::Packed(_)), Payload::Len(_)));
        let indexed = spec.filter(|f| !matches!(f.index, Index::None) && !packed_run);
        let raw = match payload {
            Payload::Varint(v) | Payload::I64(v) => v,
            Payload::I32(v) => v.into(),
            _ => 0,
        };
        let at = indexed.map(|f| (f, position(&mut seen, num, raw)));
        if let Some((f, (i, _))) = at
            && !matches!(payload, Payload::Varint(_))
        {
            label = element(f, i, 0, uint(raw)).0;
        }
        let node = match payload {
            Payload::Varint(v) => match at {
                Some((f, (i, key))) => {
                    let (label, value) = element(f, i, key, varint_value(ty, v));
                    Node::new(label).value(value)
                }
                None => Node::new(label).value(varint_value(ty, v)),
            },
            Payload::I64(v) => match ty {
                Some(Ty::Double | Ty::Packed(Elem::Double)) => {
                    Node::new(label).value(Value::f64(f64::from_bits(v)))
                }
                _ => Node::new(label).value(Value::UInt {
                    value: v,
                    bits: 64,
                    radix: Radix::Hex,
                }),
            },
            Payload::I32(v) => match ty {
                Some(Ty::Float | Ty::Packed(Elem::Float)) => {
                    Node::new(label).value(Value::f32(f32::from_bits(v)))
                }
                _ => Node::new(label).value(Value::UInt {
                    value: v.into(),
                    bits: 32,
                    radix: Radix::Hex,
                }),
            },
            Payload::Len(body) => delimited(&cx, label, body, spec, depth).await?,
            Payload::StartGroup | Payload::EndGroup => return Err(groups(&cur)),
        };
        cx.push(node.span(cur.since(start))).await;
    }
    Ok(())
}

/// The position of the next element of field `num` and the value of the
/// one before it, recording `raw` as the last value.
fn position(seen: &mut Vec<(u64, u64, u64)>, num: u64, raw: u64) -> (u64, u64) {
    match seen.iter_mut().find(|e| e.0 == num) {
        Some(e) => {
            let at = (e.1, e.2);
            e.1 = e.1.saturating_add(1);
            e.2 = raw;
            at
        }
        None => {
            seen.push((num, 1, raw));
            (0, 0)
        }
    }
}

async fn delimited(
    cx: &Cx,
    label: std::borrow::Cow<'static, str>,
    body: Span,
    spec: Option<&'static F>,
    depth: u32,
) -> Result<Node> {
    let ty = spec.map(|f| f.ty);
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
            .lazy(packed, (body, elem, spec)),
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
                Some(v) => (Value::f32(f32::from_bits(v)), 4),
                None => break,
            },
            Elem::Double => match crate::bytes::u64_le(rest, 0) {
                Some(v) => (Value::f64(f64::from_bits(v)), 8),
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
        Value::Float { value, bits } => crate::render::float(*value, *bits),
        Value::Enum {
            name: Some(name), ..
        } => name.to_string(),
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
async fn packed(cx: Cx, (body, elem, spec): (Span, Elem, Option<&'static F>)) -> Result<()> {
    let data = cx.read(body.sub(0, 64 * 1024)).await?;
    let values = elem_values(&data, elem);
    let total = values.len();
    let mut key = 0u64;
    for (i, (value, at, n)) in values.into_iter().take(4096).enumerate() {
        let raw = scalar(&value).unwrap_or(0);
        let (label, value) = match spec.filter(|f| !matches!(f.index, Index::None)) {
            Some(f) => element(f, to_u64(i), key, value),
            None => (format!("[{i}]").into(), value),
        };
        key = raw;
        cx.push(
            Node::new(label)
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
