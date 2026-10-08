//! DuckDB's `BinarySerializer` encoding and the catalog objects written
//! with it.
//!
//! The encoding is not self-describing: an object is a run of fields, each
//! a little-endian `u16` field id followed by a value whose encoding
//! depends on the field (LEB128 varints, signed for signed integers; one
//! byte for booleans; raw IEEE floats; varint-length strings and blobs;
//! varint-counted lists; a presence byte before nullable pointers; nested
//! objects), and ends with the id `0xffff`. Fields equal to their default
//! are left out. So every object is read with a grammar of its field ids;
//! an id the grammar does not know stops the parse, because its value
//! cannot be skipped.
//!
//! The grammars below come from memory of DuckDB's generated
//! `serialize_*.cpp` files and were checked against files written by
//! DuckDB 1.5.6 (storage versions 64 and 68). Field names follow DuckDB's.

use std::fmt::Write as _;

use crate::bytes::{sleb128, to_u64, uleb128};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::data::valuetree::datetime;
use crate::formats::util::binutil::Tree;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

/// The id that ends an object.
pub const END: u16 = 0xffff;
/// Nesting depth of types, values and expressions.
const MAX_DEPTH: usize = 48;
/// Elements of a list we are willing to hold for one field.
const MAX_LIST: u64 = 1 << 20;

/// A reader over (a prefix of) a serialized stream.
pub struct Bs<'a> {
    data: &'a [u8],
    pos: usize,
    /// The stream these bytes start; spans are relative to it.
    base: Span,
    /// Whether the stream goes on past `data`.
    more: bool,
    /// Set when a read ran past `data` while the stream goes on: reading a
    /// longer prefix may succeed.
    pub short: bool,
    /// Whether a longer prefix can be read (the stream goes on and the
    /// read limit allows more).
    pub can_grow: bool,
}

impl<'a> Bs<'a> {
    pub fn new(data: &'a [u8], base: Span) -> Self {
        let more = to_u64(data.len()) < base.len;
        Bs {
            data,
            pos: 0,
            base,
            more,
            short: false,
            can_grow: more,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The bytes from `start` to the current position.
    pub fn span(&self, start: usize) -> Span {
        self.base
            .sub(to_u64(start), to_u64(self.pos.saturating_sub(start)))
    }

    fn here(&self, len: usize) -> Span {
        self.base.sub(to_u64(self.pos), to_u64(len))
    }

    fn out_of_data(&mut self) -> Diagnostic {
        if self.more {
            self.short = true;
        }
        Diagnostic::truncated(self.here(1), 0)
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n);
        match end.and_then(|e| self.data.get(self.pos..e)) {
            Some(b) => {
                self.pos = end.unwrap_or(self.pos);
                Ok(b)
            }
            None => Err(self.out_of_data()),
        }
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?.first().copied().unwrap_or(0))
    }

    pub fn id(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([
            b.first().copied().unwrap_or(0),
            b.get(1).copied().unwrap_or(0),
        ]))
    }

    pub fn raw_u64(&mut self) -> Result<u64> {
        let b = self.bytes(8)?;
        Ok(crate::bytes::u64_le(b, 0).unwrap_or(0))
    }

    pub fn uvar(&mut self) -> Result<u64> {
        match uleb128(self.data.get(self.pos..).unwrap_or_default()) {
            Some((v, n)) => {
                self.pos = self.pos.saturating_add(n);
                Ok(v)
            }
            None if self.data.len().saturating_sub(self.pos) >= 10 => {
                Err(Diagnostic::malformed("varint longer than 10 bytes").at(self.here(10)))
            }
            None => Err(self.out_of_data()),
        }
    }

    pub fn svar(&mut self) -> Result<i64> {
        match sleb128(self.data.get(self.pos..).unwrap_or_default()) {
            Some((v, n)) => {
                self.pos = self.pos.saturating_add(n);
                Ok(v)
            }
            None if self.data.len().saturating_sub(self.pos) >= 10 => {
                Err(Diagnostic::malformed("varint longer than 10 bytes").at(self.here(10)))
            }
            None => Err(self.out_of_data()),
        }
    }

    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    /// A varint length and that many bytes.
    pub fn blob(&mut self) -> Result<&'a [u8]> {
        let at = self.pos;
        let len = self.uvar()?;
        if len > to_u64(self.data.len().saturating_sub(self.pos)) && !self.more {
            self.pos = at;
            return Err(Diagnostic::malformed(format!(
                "string of {len} bytes overruns the stream"
            ))
            .at(self.here(1)));
        }
        self.bytes(crate::bytes::to_usize(len))
    }

    pub fn string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.blob()?).into_owned())
    }

    pub fn f32(&mut self) -> Result<f32> {
        let b = self.bytes(4)?;
        Ok(f32::from_le_bytes(
            crate::bytes::array(b, 0).unwrap_or_default(),
        ))
    }

    pub fn f64(&mut self) -> Result<f64> {
        let b = self.bytes(8)?;
        Ok(f64::from_le_bytes(
            crate::bytes::array(b, 0).unwrap_or_default(),
        ))
    }

    /// A list count, sanity-checked against the bytes left (every element
    /// takes at least one byte).
    pub fn count(&mut self) -> Result<u64> {
        let at = self.pos;
        let n = self.uvar()?;
        let left = to_u64(self.data.len().saturating_sub(self.pos));
        if n > MAX_LIST || (n > left && !self.more) {
            self.pos = at;
            return Err(
                Diagnostic::malformed(format!("implausible list length {n}")).at(self.here(1)),
            );
        }
        Ok(n)
    }

    /// A nullable pointer's presence byte.
    pub fn present(&mut self) -> Result<bool> {
        let at = self.pos;
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            b => {
                self.pos = at;
                Err(Diagnostic::malformed(format!("presence byte {b:#x}")).at(self.here(1)))
            }
        }
    }

    pub fn unknown(&self, id: u16, at: usize, what: &str) -> Diagnostic {
        Diagnostic::unsupported(format!("field {id} of {what} is not known"))
            .at(self.base.sub(to_u64(at), 2))
    }

    /// Reads the fields of an object up to its end marker, handing each id
    /// to `field` (which returns `false` for ids it does not know).
    pub fn object(
        &mut self,
        what: &str,
        mut field: impl FnMut(&mut Self, u16, usize) -> Result<bool>,
    ) -> Result<()> {
        loop {
            let at = self.pos;
            let id = self.id()?;
            if id == END {
                return Ok(());
            }
            if !field(self, id, at)? {
                self.pos = at;
                return Err(self.unknown(id, at, what));
            }
        }
    }

    /// Reads a list, calling `item` for each element.
    pub fn list(&mut self, mut item: impl FnMut(&mut Self, u64) -> Result<()>) -> Result<u64> {
        let n = self.count()?;
        for i in 0..n {
            item(self, i)?;
        }
        Ok(n)
    }
}

/// A metadata stream parsed a piece (a catalog entry, a row group) per
/// step, over a prefix that grows (by 4×, from what was read so far) only
/// when a piece runs out of bytes before the stream ends: that piece is
/// then parsed again, and nothing before it.
pub struct Stream {
    span: Span,
    data: Vec<u8>,
    /// The prefix length asked for (the source may hold less).
    want: u64,
    max: u64,
    /// Where the next piece starts.
    pos: usize,
}

impl Stream {
    pub async fn open(cx: &Cx, span: Span, first: u64) -> Result<Stream> {
        let want = span.len.min(first);
        let data = cx.read_avail(span.sub(0, want)).await?;
        Ok(Stream {
            span,
            data,
            want,
            max: cx.limits().max_read,
            pos: 0,
        })
    }

    /// Where the next piece starts.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Parses one piece with `f` from where the last one ended, charging
    /// for the bytes it covered. Nodes `f` added to `t` before running
    /// short are dropped before it runs again, so `f` must add nothing
    /// under nodes that existed before (and must reset its own outputs).
    pub async fn piece<R>(
        &mut self,
        cx: &Cx,
        t: &mut Tree,
        mut f: impl FnMut(&mut Bs<'_>, &mut Tree) -> Result<R>,
    ) -> Result<R> {
        let mark = t.next_index();
        loop {
            let mut bs = Bs::new(&self.data, self.span);
            bs.seek(self.pos);
            bs.can_grow = self.want < self.span.len && self.want < self.max;
            let r = f(&mut bs, t);
            let (end, short) = (bs.pos(), bs.short);
            // A unit per KiB covered.
            for _ in 0..=end.abs_diff(self.pos) >> 10 {
                cx.checkpoint().await;
            }
            if r.is_err() && short && self.want < self.span.len && self.want < self.max {
                let want = self.want.saturating_mul(4).min(self.span.len).min(self.max);
                let have = to_u64(self.data.len());
                let more = cx
                    .read_avail(self.span.sub(have, want.saturating_sub(have)))
                    .await?;
                self.data.extend_from_slice(&more);
                self.want = want;
                t.truncate(mark);
                continue;
            }
            self.pos = end;
            return r;
        }
    }
}

fn deeper(depth: usize, bs: &Bs<'_>) -> Result<usize> {
    if depth >= MAX_DEPTH {
        return Err(Diagnostic::limit("nesting too deep").at(bs.here(1)));
    }
    Ok(depth.saturating_add(1))
}

pub fn uint(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    }
}

pub fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

pub fn enumv(table: EnumTable, raw: u64) -> Value {
    Value::Enum {
        raw,
        bits: 8,
        name: lookup(table, raw),
    }
}

/// Adds a leaf for the field that started at `at` and ends here.
pub fn leaf(t: &mut Tree, p: usize, bs: &Bs<'_>, at: usize, name: &'static str, v: Value) -> usize {
    t.add(Some(p), Node::new(name).span(bs.span(at)).value(v))
}

/// Adds a group node whose span is filled in later with [`close`].
pub fn group(t: &mut Tree, p: Option<usize>, name: impl Into<String>) -> usize {
    t.add(p, Node::new(name.into()))
}

pub fn close(t: &mut Tree, i: usize, bs: &Bs<'_>, at: usize) {
    let span = bs.span(at);
    t.update(i, |n| n.span(span));
}

pub fn summarize(t: &mut Tree, i: usize, s: impl Into<String>) {
    let s = s.into();
    if !s.is_empty() {
        t.update(i, |n| n.summary(s));
    }
}

// ---------------------------------------------------------------------------
// Logical types

pub const TYPE_IDS: EnumTable = &[
    (0, "INVALID"),
    (1, "NULL"),
    (2, "UNKNOWN"),
    (3, "ANY"),
    (4, "USER"),
    (10, "BOOLEAN"),
    (11, "TINYINT"),
    (12, "SMALLINT"),
    (13, "INTEGER"),
    (14, "BIGINT"),
    (15, "DATE"),
    (16, "TIME"),
    (17, "TIMESTAMP_S"),
    (18, "TIMESTAMP_MS"),
    (19, "TIMESTAMP"),
    (20, "TIMESTAMP_NS"),
    (21, "DECIMAL"),
    (22, "FLOAT"),
    (23, "DOUBLE"),
    (24, "CHAR"),
    (25, "VARCHAR"),
    (26, "BLOB"),
    (27, "INTERVAL"),
    (28, "UTINYINT"),
    (29, "USMALLINT"),
    (30, "UINTEGER"),
    (31, "UBIGINT"),
    (32, "TIMESTAMP WITH TIME ZONE"),
    (34, "TIME WITH TIME ZONE"),
    (36, "BIT"),
    (49, "UHUGEINT"),
    (50, "HUGEINT"),
    (54, "UUID"),
    (100, "STRUCT"),
    (101, "LIST"),
    (102, "MAP"),
    (104, "ENUM"),
    (105, "AGGREGATE_STATE"),
    (107, "UNION"),
    (108, "ARRAY"),
];

/// A logical type, as far as the catalog and the statistics need it.
#[derive(Clone, Debug, Default)]
pub struct Ty {
    pub id: u8,
    pub alias: Option<String>,
    pub info: Info,
}

#[derive(Clone, Debug, Default)]
pub enum Info {
    #[default]
    None,
    Decimal(u8, u8),
    /// LIST and MAP element type.
    Child(Box<Ty>),
    /// STRUCT and UNION members.
    Members(Vec<(String, Ty)>),
    Enum(u64, Vec<String>),
    User(String),
    Array(Box<Ty>, u64),
}

impl Ty {
    pub fn sql(&self) -> String {
        if let Some(a) = &self.alias {
            return a.clone();
        }
        let base = lookup(TYPE_IDS, self.id.into())
            .map_or_else(|| format!("TYPE{}", self.id), str::to_owned);
        match &self.info {
            Info::Decimal(w, s) => format!("DECIMAL({w},{s})"),
            Info::Child(c) if self.id == 102 => match &c.info {
                Info::Members(m) if m.len() == 2 => format!(
                    "MAP({}, {})",
                    m.first().map(|(_, t)| t.sql()).unwrap_or_default(),
                    m.get(1).map(|(_, t)| t.sql()).unwrap_or_default()
                ),
                _ => format!("MAP({})", c.sql()),
            },
            Info::Child(c) => format!("{}[]", c.sql()),
            Info::Array(c, n) => format!("{}[{n}]", c.sql()),
            Info::Members(m) => {
                let inner: Vec<String> =
                    m.iter().map(|(n, t)| format!("{n} {}", t.sql())).collect();
                format!("{base}({})", inner.join(", "))
            }
            Info::Enum(n, values) => {
                let mut s = String::from("ENUM(");
                for (i, v) in values.iter().take(8).enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    let _ = write!(s, "'{v}'");
                }
                if *n > 8 {
                    s.push_str(", …");
                }
                s.push(')');
                s
            }
            Info::User(name) => name.clone(),
            Info::None => base,
        }
    }
}

const EXTRA_TYPE_INFO: EnumTable = &[
    (1, "generic"),
    (2, "decimal"),
    (3, "string"),
    (4, "list"),
    (5, "struct"),
    (6, "enum"),
    (7, "user"),
    (8, "aggregate state"),
    (9, "array"),
    (10, "any"),
    (11, "integer literal"),
];

/// A `LogicalType` object.
pub fn logical_type(bs: &mut Bs<'_>, depth: usize) -> Result<Ty> {
    let depth = deeper(depth, bs)?;
    let mut ty = Ty::default();
    bs.object("a logical type", |bs, id, _| {
        match id {
            100 => ty.id = u8::try_from(bs.uvar()?).unwrap_or(u8::MAX),
            101 => {
                if bs.present()? {
                    type_info(bs, depth, &mut ty)?;
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(ty)
}

fn type_info(bs: &mut Bs<'_>, depth: usize, ty: &mut Ty) -> Result<()> {
    let mut kind = 0u64;
    bs.object("type info", |bs, id, _| {
        match (id, kind) {
            (100, _) => kind = bs.uvar()?,
            (101, _) => {
                let a = bs.string()?;
                if !a.is_empty() {
                    ty.alias = Some(a);
                }
            }
            (102, _) => {
                bs.list(|bs, _| value(bs, depth).map(drop))?;
            }
            (103, _) => {
                if bs.present()? {
                    extension_info(bs, depth)?;
                }
            }
            (200, 2) => {
                let w = u8::try_from(bs.uvar()?).unwrap_or(u8::MAX);
                let s = match ty.info {
                    Info::Decimal(_, s) => s,
                    _ => 0,
                };
                ty.info = Info::Decimal(w, s);
            }
            (201, 2) => {
                let s = u8::try_from(bs.uvar()?).unwrap_or(u8::MAX);
                let w = match ty.info {
                    Info::Decimal(w, _) => w,
                    _ => 0,
                };
                ty.info = Info::Decimal(w, s);
            }
            (200, 3) => {
                bs.string()?;
            }
            (200, 4) => ty.info = Info::Child(Box::new(logical_type(bs, depth)?)),
            (200, 5) => {
                let mut members = Vec::new();
                bs.list(|bs, _| {
                    let mut name = String::new();
                    let mut member = Ty::default();
                    bs.object("a struct member", |bs, id, _| {
                        match id {
                            0 => name = bs.string()?,
                            1 => member = logical_type(bs, depth)?,
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })?;
                    members.push((name, member));
                    Ok(())
                })?;
                ty.info = Info::Members(members);
            }
            (200, 6) => ty.info = Info::Enum(bs.uvar()?, Vec::new()),
            (201, 6) => {
                let mut values = Vec::new();
                bs.list(|bs, _| {
                    let s = bs.string()?;
                    if values.len() < 64 {
                        values.push(s);
                    }
                    Ok(())
                })?;
                let n = match ty.info {
                    Info::Enum(n, _) => n,
                    _ => to_u64(values.len()),
                };
                ty.info = Info::Enum(n, values);
            }
            (200, 7) => ty.info = Info::User(bs.string()?),
            (201 | 202, 7) => {
                bs.string()?;
            }
            (203, 7) => {
                bs.list(|bs, _| value(bs, depth).map(drop))?;
            }
            // An unresolved type, as a type expression (1.5).
            (204, 7) => {
                if bs.present()? {
                    ty.info = Info::User(expression(bs, depth)?);
                }
            }
            (200, 8) => {
                bs.string()?;
            }
            (201, 8) => {
                logical_type(bs, depth)?;
            }
            (202, 8) => {
                bs.list(|bs, _| logical_type(bs, depth).map(drop))?;
            }
            (200, 9) => {
                let child = logical_type(bs, depth)?;
                let n = match &ty.info {
                    Info::Array(_, n) => *n,
                    _ => 0,
                };
                ty.info = Info::Array(Box::new(child), n);
            }
            (201, 9) => {
                let n = bs.uvar()?;
                let child = match std::mem::take(&mut ty.info) {
                    Info::Array(c, _) => c,
                    _ => Box::default(),
                };
                ty.info = Info::Array(child, n);
            }
            (200, 10) => {
                logical_type(bs, depth)?;
            }
            (201, 10) => {
                bs.svar()?;
            }
            (200, 11) => {
                value(bs, depth)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    if lookup(EXTRA_TYPE_INFO, kind).is_none() && kind != 0 {
        return Err(Diagnostic::unsupported(format!("type info kind {kind}")));
    }
    Ok(())
}

fn extension_info(bs: &mut Bs<'_>, depth: usize) -> Result<()> {
    bs.object("extension type info", |bs, id, _| {
        match id {
            100 => {
                bs.list(|bs, _| {
                    bs.object("a type modifier", |bs, id, _| {
                        match id {
                            100 => drop(value(bs, depth)?),
                            101 => drop(bs.string()?),
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })
                })?;
            }
            101 => {
                bs.list(|bs, _| {
                    pair(
                        bs,
                        |bs| bs.string().map(drop),
                        |bs| value(bs, depth).map(drop),
                    )
                })?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    })
}

/// A map entry: an object with the key as field 0 and the value as 1.
pub fn pair(
    bs: &mut Bs<'_>,
    mut key: impl FnMut(&mut Bs<'_>) -> Result<()>,
    mut val: impl FnMut(&mut Bs<'_>) -> Result<()>,
) -> Result<()> {
    bs.object("a map entry", |bs, id, _| {
        match id {
            0 => key(bs)?,
            1 => val(bs)?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

// ---------------------------------------------------------------------------
// Values

/// How a type's values (and numeric statistics) are encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phys {
    Bool,
    Signed,
    Unsigned,
    /// `hugeint_t` / `uhugeint_t`: an object of upper and lower halves.
    Huge,
    F32,
    F64,
    Interval,
    Str,
    List,
    Struct,
    Array,
    Other,
}

pub fn phys(ty: &Ty) -> Phys {
    match ty.id {
        10 => Phys::Bool,
        11..=14 | 15..=20 | 32 | 34 => Phys::Signed,
        21 => match ty.info {
            Info::Decimal(w, _) if w > 18 => Phys::Huge,
            _ => Phys::Signed,
        },
        22 => Phys::F32,
        23 => Phys::F64,
        24..=26 => Phys::Str,
        27 => Phys::Interval,
        28..=31 | 104 => Phys::Unsigned,
        49 | 50 | 54 => Phys::Huge,
        101 | 102 => Phys::List,
        100 | 107 => Phys::Struct,
        108 => Phys::Array,
        _ => Phys::Other,
    }
}

/// A 128-bit integer: the upper half as a signed varint (unsigned for
/// `UHUGEINT`), then the lower half.
fn hugeint(bs: &mut Bs<'_>, unsigned: bool) -> Result<i128> {
    let upper = if unsigned {
        i128::from(bs.uvar()?)
    } else {
        i128::from(bs.svar()?)
    };
    let lower = bs.uvar()?;
    Ok(upper.wrapping_shl(64) | i128::from(lower))
}

/// Reads a scalar of physical kind `p` and renders it.
pub fn scalar(bs: &mut Bs<'_>, ty: &Ty, p: Phys) -> Result<(String, Option<Value>)> {
    Ok(match p {
        Phys::Bool => {
            let b = bs.bool()?;
            (
                if b { "true" } else { "false" }.to_owned(),
                Some(Value::Bool(b)),
            )
        }
        Phys::Signed => {
            let v = bs.svar()?;
            // Dates count days, timestamps seconds to nanoseconds.
            let unix = match ty.id {
                15 => Some((v.saturating_mul(86_400), 0)),
                17 => Some((v, 0)),
                18 => Some((
                    v.div_euclid(1000),
                    v.rem_euclid(1000).saturating_mul(1_000_000),
                )),
                19 | 32 => Some((
                    v.div_euclid(1_000_000),
                    v.rem_euclid(1_000_000).saturating_mul(1000),
                )),
                20 => Some((v.div_euclid(1_000_000_000), v.rem_euclid(1_000_000_000))),
                _ => None,
            };
            match (unix, &ty.info) {
                (Some((secs, nanos)), _) => {
                    let mut shown = datetime(secs, u32::try_from(nanos).unwrap_or(0));
                    if ty.id == 15 {
                        shown.truncate(10);
                    }
                    (shown, Some(Value::Timestamp { unix_seconds: secs }))
                }
                (None, Info::Decimal(_, scale)) => (
                    decimal(i128::from(v), *scale),
                    Some(Value::Int { value: v, bits: 64 }),
                ),
                _ => (v.to_string(), Some(Value::Int { value: v, bits: 64 })),
            }
        }
        Phys::Unsigned => {
            let v = bs.uvar()?;
            (v.to_string(), Some(uint(v)))
        }
        Phys::Huge => {
            let v = hugeint(bs, ty.id == 49)?;
            let shown = match ty.info {
                Info::Decimal(_, scale) => decimal(v, scale),
                _ if ty.id == 54 => uuid(v),
                _ if ty.id == 49 => (v as u128).to_string(),
                _ => v.to_string(),
            };
            (shown.clone(), Some(text(shown)))
        }
        Phys::F32 => {
            let v = bs.f32()?;
            (v.to_string(), Some(Value::Float(v.into())))
        }
        Phys::F64 => {
            let v = bs.f64()?;
            (v.to_string(), Some(Value::Float(v)))
        }
        Phys::Interval => {
            let (mut months, mut days, mut micros) = (0i64, 0i64, 0i64);
            bs.object("an interval", |bs, id, _| {
                match id {
                    100 => months = bs.svar()?,
                    101 => days = bs.svar()?,
                    102 => micros = bs.svar()?,
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            let s = format!("{months} months {days} days {micros} µs");
            (s.clone(), Some(text(s)))
        }
        Phys::Str => {
            let b = bs.blob()?;
            if ty.id == 26 {
                let s = crate::formats::util::binutil::hex_string(b.get(..64).unwrap_or(b));
                (
                    format!("'\\x{s}'"),
                    Some(Value::Bytes(b.get(..64).unwrap_or(b).to_vec())),
                )
            } else {
                let s = String::from_utf8_lossy(b).into_owned();
                (format!("'{s}'"), Some(text(s)))
            }
        }
        Phys::List | Phys::Struct | Phys::Array | Phys::Other => {
            return Err(Diagnostic::unsupported(format!(
                "value of type {}",
                ty.sql()
            )));
        }
    })
}

/// `hugeint` as a UUID (DuckDB flips the top bit so UUIDs sort as text).
fn uuid(v: i128) -> String {
    let u = (v as u128) ^ 1u128.wrapping_shl(127);
    let h = format!("{u:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        h.get(0..8).unwrap_or_default(),
        h.get(8..12).unwrap_or_default(),
        h.get(12..16).unwrap_or_default(),
        h.get(16..20).unwrap_or_default(),
        h.get(20..32).unwrap_or_default()
    )
}

fn decimal(v: i128, scale: u8) -> String {
    let digits = v.unsigned_abs().to_string();
    let scale = usize::from(scale);
    let sign = if v < 0 { "-" } else { "" };
    if scale == 0 {
        return format!("{sign}{digits}");
    }
    let padded = format!("{digits:0>width$}", width = scale.saturating_add(1));
    let cut = padded.len().saturating_sub(scale);
    format!(
        "{sign}{}.{}",
        padded.get(..cut).unwrap_or_default(),
        padded.get(cut..).unwrap_or_default()
    )
}

/// A `Value` object, rendered as SQL.
pub fn value(bs: &mut Bs<'_>, depth: usize) -> Result<String> {
    let depth = deeper(depth, bs)?;
    let mut ty = Ty::default();
    let mut null = false;
    let mut shown = String::from("NULL");
    bs.object("a value", |bs, id, _| {
        match id {
            100 => ty = logical_type(bs, depth)?,
            101 => null = bs.bool()?,
            102 => {
                shown = match phys(&ty) {
                    Phys::List | Phys::Struct | Phys::Array => {
                        let mut parts = Vec::new();
                        bs.object("a nested value", |bs, id, _| {
                            if id != 100 {
                                return Ok(false);
                            }
                            bs.list(|bs, _| {
                                let v = value(bs, depth)?;
                                if parts.len() < 16 {
                                    parts.push(v);
                                }
                                Ok(())
                            })?;
                            Ok(true)
                        })?;
                        let (open, close) = if phys(&ty) == Phys::Struct {
                            ("{", "}")
                        } else {
                            ("[", "]")
                        };
                        format!("{open}{}{close}", parts.join(", "))
                    }
                    p => scalar(bs, &ty, p)?.0,
                };
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    if null {
        return Ok(format!("NULL::{}", ty.sql()));
    }
    Ok(match ty.id {
        15 | 17..=20 | 32 => format!("{}::{}", shown, ty.sql()),
        _ => shown,
    })
}

// ---------------------------------------------------------------------------
// Parsed expressions (column defaults, CHECK constraints, macro bodies,
// index keys), rendered as SQL text.

const EXPR_CLASSES: EnumTable = &[
    (1, "aggregate"),
    (2, "case"),
    (3, "cast"),
    (4, "column reference"),
    (5, "comparison"),
    (6, "conjunction"),
    (7, "constant"),
    (8, "default"),
    (9, "function"),
    (10, "operator"),
    (11, "star"),
    (13, "subquery"),
    (14, "window"),
    (15, "parameter"),
    (16, "collate"),
    (17, "lambda"),
    (18, "positional reference"),
    (19, "between"),
    (21, "type"),
];

fn comparison(t: u64) -> &'static str {
    match t {
        25 => "=",
        26 => "<>",
        27 => "<",
        28 => ">",
        29 => "<=",
        30 => ">=",
        37 => "IS DISTINCT FROM",
        38 => "IS NOT DISTINCT FROM",
        _ => "?",
    }
}

/// A `ParsedExpression` (behind its presence byte when `nullable`).
pub fn expression(bs: &mut Bs<'_>, depth: usize) -> Result<String> {
    let depth = deeper(depth, bs)?;
    let mut class = 0u64;
    let mut etype = 0u64;
    let mut alias = String::new();
    let mut name = String::new();
    let mut schema = String::new();
    let mut children: Vec<String> = Vec::new();
    let mut a = String::new();
    let mut b = String::new();
    let mut c = String::new();
    let mut is_operator = false;
    let mut distinct = false;
    let mut try_cast = false;
    let mut cast_type = String::new();
    let start = bs.pos();
    bs.object("an expression", |bs, id, _| {
        match (id, class) {
            (100, _) => {
                class = bs.uvar()?;
                if lookup(EXPR_CLASSES, class).is_none() || matches!(class, 1 | 11 | 13 | 14) {
                    return Err(Diagnostic::unsupported(format!(
                        "{} expressions",
                        lookup(EXPR_CLASSES, class).unwrap_or("unknown")
                    ))
                    .at(bs.span(start)));
                }
            }
            (101, _) => etype = bs.uvar()?,
            (102, _) => alias = bs.string()?,
            (103, _) => drop(bs.uvar()?),
            // constant
            (200, 7) => a = value(bs, depth)?,
            // column reference
            (200, 4) => {
                bs.list(|bs, _| {
                    children.push(bs.string()?);
                    Ok(())
                })?;
            }
            // type expression (1.5): only the type name has been seen
            (202, 21) => name = bs.string()?,
            // function
            (200, 9) => name = bs.string()?,
            (201, 9) => schema = bs.string()?,
            (202, 9) | (200, 6) | (200, 10) => {
                bs.list(|bs, _| {
                    if bs.present()? {
                        children.push(expression(bs, depth)?);
                    }
                    Ok(())
                })?;
            }
            (203, 9) => {
                if bs.present()? {
                    b = expression(bs, depth)?;
                }
            }
            (204, 9) => {
                if bs.present()? {
                    result_modifier(bs, depth)?;
                }
            }
            (205, 9) => distinct = bs.bool()?,
            (206, 9) => is_operator = bs.bool()?,
            (207, 9) => drop(bs.bool()?),
            (208, 9) => drop(bs.string()?),
            // cast, collate
            (200, 3 | 16) | (200 | 201, 5) | (200..=202, 19) | (200 | 201, 17) => {
                let e = if bs.present()? {
                    expression(bs, depth)?
                } else {
                    String::new()
                };
                match id {
                    200 => a = e,
                    201 => b = e,
                    _ => c = e,
                }
            }
            (201, 3) => cast_type = logical_type(bs, depth)?.sql(),
            (202, 3) => try_cast = bs.bool()?,
            (201, 16) => b = bs.string()?,
            // case
            (200, 2) => {
                bs.list(|bs, _| {
                    let (mut when, mut then) = (String::new(), String::new());
                    bs.object("a CASE check", |bs, id, _| {
                        match id {
                            100 => when = present_expression(bs, depth)?,
                            101 => then = present_expression(bs, depth)?,
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })?;
                    children.push(format!("WHEN {when} THEN {then}"));
                    Ok(())
                })?;
            }
            (201, 2) => a = present_expression(bs, depth)?,
            // parameter
            (200, 15) => a = bs.string()?,
            // positional reference
            (200, 18) => a = bs.uvar()?.to_string(),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let sql = match class {
        2 => format!("CASE {} ELSE {a} END", children.join(" ")),
        3 => format!(
            "{}({a} AS {cast_type})",
            if try_cast { "TRY_CAST" } else { "CAST" }
        ),
        4 => children.join("."),
        5 => format!("{a} {} {b}", comparison(etype)),
        6 => children.join(if etype == 51 { " OR " } else { " AND " }),
        7 => a,
        8 => "DEFAULT".to_owned(),
        9 => {
            let qualified = if schema.is_empty() {
                name.clone()
            } else {
                format!("{schema}.{name}")
            };
            match (is_operator, children.as_slice()) {
                (true, [l, r]) => format!("({l} {name} {r})"),
                (true, [x]) => format!("{name}{x}"),
                _ => format!(
                    "{qualified}({}{})",
                    if distinct { "DISTINCT " } else { "" },
                    children.join(", ")
                ),
            }
        }
        10 => match (etype, children.as_slice()) {
            (13, [x]) => format!("NOT {x}"),
            (14, [x]) => format!("{x} IS NULL"),
            (15, [x]) => format!("{x} IS NOT NULL"),
            (35, [x, rest @ ..]) => format!("{x} IN ({})", rest.join(", ")),
            (36, [x, rest @ ..]) => format!("{x} NOT IN ({})", rest.join(", ")),
            _ => format!("operator{etype}({})", children.join(", ")),
        },
        15 => format!("${a}"),
        16 => format!("{a} COLLATE {b}"),
        17 => format!("{a} -> {b}"),
        18 => format!("#{a}"),
        19 => format!("{a} BETWEEN {b} AND {c}"),
        21 => name,
        _ => String::from("?"),
    };
    Ok(if alias.is_empty() {
        sql
    } else {
        format!("{sql} AS {alias}")
    })
}

fn present_expression(bs: &mut Bs<'_>, depth: usize) -> Result<String> {
    if bs.present()? {
        expression(bs, depth)
    } else {
        Ok(String::new())
    }
}

/// A `ResultModifier` (ORDER BY inside an aggregate call); read, not shown.
fn result_modifier(bs: &mut Bs<'_>, depth: usize) -> Result<()> {
    let mut kind = 0;
    bs.object("a result modifier", |bs, id, _| {
        match (id, kind) {
            (100, _) => kind = bs.uvar()?,
            // ORDER BY: a list of order-by nodes
            (200, 2) => {
                bs.list(|bs, _| {
                    bs.object("an ORDER BY term", |bs, id, _| {
                        match id {
                            100 | 101 => drop(bs.uvar()?),
                            102 => drop(present_expression(bs, depth)?),
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })
                })?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    })
}
