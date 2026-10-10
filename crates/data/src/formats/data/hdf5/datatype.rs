//! Datatype messages: decoding (with every field rendered) into [`Ty`],
//! and formatting values of a type.

use crate::bytes::{to_u64, to_usize};
use crate::error::Diagnostic;
use crate::node::Node;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag, lookup};

use super::util::{Rd, limit_enc_size};

/// Datatypes nested inside one another (compound members, array bases).
const MAX_DEPTH: u32 = 16;
/// Members, names and values shown in one-line descriptions.
const SHOWN: usize = 8;

pub const CLASSES: EnumTable = &[
    (0, "fixed-point"),
    (1, "floating-point"),
    (2, "time"),
    (3, "string"),
    (4, "bitfield"),
    (5, "opaque"),
    (6, "compound"),
    (7, "reference"),
    (8, "enumeration"),
    (9, "variable-length"),
    (10, "array"),
    (11, "complex"),
];

const FIXED_BITS: FlagTable = &[
    flag(0x1, "big-endian"),
    flag(0x2, "low padding is 1"),
    flag(0x4, "high padding is 1"),
    flag(0x8, "signed"),
];

const FLOAT_BITS: FlagTable = &[
    flag(0x1, "byte order bit 0 (big-endian)"),
    flag(0x2, "low padding is 1"),
    flag(0x4, "high padding is 1"),
    flag(0x8, "internal padding is 1"),
    flag(0x10, "mantissa MSB always set"),
    flag(0x20, "mantissa MSB implied"),
    flag(0x40, "byte order bit 1 (VAX)"),
];

const PADDING: EnumTable = &[
    (0, "null-terminated"),
    (1, "null-padded"),
    (2, "space-padded"),
];
const CHARSETS: EnumTable = &[(0, "ASCII"), (1, "UTF-8")];
const REFERENCES: EnumTable = &[
    (0, "object reference"),
    (1, "dataset region reference"),
    (2, "object reference (revised)"),
    (3, "dataset region reference (revised)"),
    (4, "attribute reference"),
];

#[derive(Clone, Debug)]
pub struct Member {
    pub name: String,
    pub offset: u32,
    pub ty: Ty,
}

/// A decoded datatype: what values of it look like.
#[derive(Clone, Debug)]
pub enum Ty {
    Int {
        size: u32,
        signed: bool,
        be: bool,
    },
    Float {
        size: u32,
        be: bool,
    },
    Time {
        size: u32,
        be: bool,
    },
    Str {
        size: u32,
        pad: u8,
        utf8: bool,
    },
    Bits {
        size: u32,
    },
    Opaque {
        size: u32,
        tag: String,
    },
    Compound {
        size: u32,
        members: Vec<Member>,
    },
    Ref {
        size: u32,
        kind: u8,
    },
    Enum {
        size: u32,
        base: Box<Ty>,
        names: Vec<(String, Vec<u8>)>,
    },
    Vlen {
        size: u32,
        string: bool,
        utf8: bool,
        base: Box<Ty>,
    },
    Array {
        size: u32,
        dims: Vec<u32>,
        base: Box<Ty>,
    },
    Complex {
        size: u32,
        base: Box<Ty>,
    },
    Other {
        class: u8,
        size: u32,
    },
}

impl Ty {
    pub fn size(&self) -> u32 {
        match self {
            Ty::Int { size, .. }
            | Ty::Float { size, .. }
            | Ty::Time { size, .. }
            | Ty::Str { size, .. }
            | Ty::Bits { size }
            | Ty::Opaque { size, .. }
            | Ty::Compound { size, .. }
            | Ty::Ref { size, .. }
            | Ty::Enum { size, .. }
            | Ty::Vlen { size, .. }
            | Ty::Array { size, .. }
            | Ty::Complex { size, .. }
            | Ty::Other { size, .. } => *size,
        }
    }

    /// Whether values of this type refer to the global heap.
    pub fn has_vlen(&self) -> bool {
        match self {
            Ty::Vlen { .. } => true,
            Ty::Ref {
                kind: 1 | 3 | 4, ..
            } => true,
            Ty::Compound { members, .. } => members.iter().any(|m| m.ty.has_vlen()),
            Ty::Array { base, .. } | Ty::Enum { base, .. } => base.has_vlen(),
            _ => false,
        }
    }

    /// A short description: `int32`, `string[8]`, `compound {x: float32, …}`.
    pub fn describe(&self) -> String {
        let order = |be: bool| if be { " BE" } else { "" };
        match self {
            Ty::Int { size, signed, be } => format!(
                "{}int{}{}",
                if *signed { "" } else { "u" },
                size.saturating_mul(8),
                order(*be)
            ),
            Ty::Float { size, be } => format!("float{}{}", size.saturating_mul(8), order(*be)),
            Ty::Time { size, .. } => format!("time ({size} bytes)"),
            Ty::Str { size, pad, utf8 } => format!(
                "string[{size}]{}, {}",
                if *utf8 { " UTF-8" } else { "" },
                lookup(PADDING, (*pad).into()).unwrap_or("padded")
            ),
            Ty::Bits { size } => format!("bitfield[{size}]"),
            Ty::Opaque { size, tag } if tag.is_empty() => format!("opaque[{size}]"),
            Ty::Opaque { size, tag } => format!("opaque[{size}] \"{tag}\""),
            Ty::Compound { members, .. } => {
                let mut parts: Vec<String> = members
                    .iter()
                    .take(SHOWN)
                    .map(|m| format!("{}: {}", m.name, m.ty.describe()))
                    .collect();
                if members.len() > SHOWN {
                    parts.push("…".to_owned());
                }
                format!("compound {{{}}}", parts.join(", "))
            }
            Ty::Ref { kind, .. } => lookup(REFERENCES, (*kind).into())
                .unwrap_or("reference")
                .to_owned(),
            Ty::Enum { base, names, .. } => {
                let mut parts: Vec<String> = names
                    .iter()
                    .take(SHOWN)
                    .map(|(n, v)| format!("{n}={}", format(base, v)))
                    .collect();
                if names.len() > SHOWN {
                    parts.push("…".to_owned());
                }
                format!("enum {} {{{}}}", base.describe(), parts.join(", "))
            }
            Ty::Vlen {
                string: true, utf8, ..
            } => format!("vlen string{}", if *utf8 { " UTF-8" } else { "" }),
            Ty::Vlen { base, .. } => format!("vlen sequence of {}", base.describe()),
            Ty::Array { dims, base, .. } => {
                let d: Vec<String> = dims.iter().map(u32::to_string).collect();
                format!("{}[{}]", base.describe(), d.join("×"))
            }
            Ty::Complex { base, .. } => format!("complex {}", base.describe()),
            Ty::Other { class, size } => format!("class {class} ({size} bytes)"),
        }
    }
}

fn u32v(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Decodes a datatype at the reader's position, rendering its fields.
pub fn parse(rd: &mut Rd<'_>, depth: u32) -> Option<Ty> {
    if depth > MAX_DEPTH {
        rd.push(
            Node::new("Datatype")
                .span(rd.sp(rd.pos, 0))
                .diag(Diagnostic::limit("datatypes nested too deeply")),
        );
        return None;
    }
    let b0 = rd.peek(1)?;
    let class = u8::try_from(b0 & 0x0f).unwrap_or(0);
    let version = u8::try_from(b0 >> 4).unwrap_or(0);
    let (_, span) = rd.take(1)?;
    rd.push(
        Node::new("Class and version")
            .span(span)
            .value(Value::Enum {
                raw: class.into(),
                bits: 4,
                name: lookup(CLASSES, class.into()),
            })
            .summary(format!("version {version}")),
    );
    let (bits, bspan) = rd.take(3)?;
    let size = u32v(rd.num("Size", 4)?);
    rd.desc("Size of one value, in bytes");
    // The class bit field comes before the size: its node goes there.
    let size_at = rd.out.len().saturating_sub(1);
    let bitfield = |summary: String| {
        let node = Node::new("Class bit field").span(bspan).value(Value::UInt {
            value: bits,
            bits: 24,
            radix: Radix::Hex,
        });
        if summary.is_empty() {
            node
        } else {
            node.summary(summary)
        }
    };
    let flags = |table: FlagTable| {
        let (set, unknown) = crate::value::decode_flags(table, bits & 0xff);
        // Floating-point types keep the sign's bit position in bits 8-15.
        let rest = if class == 1 { 0xff_ffff } else { 0xff };
        Node::new("Class bit field")
            .span(bspan)
            .value(Value::Flags {
                raw: bits,
                bits: 24,
                set,
                unknown: unknown | (bits & !rest),
            })
    };
    Some(match class {
        0 | 4 => {
            let be = bits & 1 != 0;
            let signed = bits & 8 != 0;
            rd.out.insert(size_at, flags(FIXED_BITS));
            rd.num("Bit offset", 2)?;
            rd.num("Bit precision", 2)?;
            if class == 0 {
                Ty::Int { size, signed, be }
            } else {
                Ty::Bits { size }
            }
        }
        1 => {
            let be = bits & 1 != 0;
            let sign = (bits >> 8) & 0xff;
            let mut node = flags(FLOAT_BITS);
            node.summary = Some(format!("sign bit {sign}"));
            rd.out.insert(size_at, node);
            rd.num("Bit offset", 2)?;
            rd.num("Bit precision", 2)?;
            rd.num("Exponent location", 1)?;
            rd.num("Exponent size", 1)?;
            rd.num("Mantissa location", 1)?;
            rd.num("Mantissa size", 1)?;
            rd.num("Exponent bias", 4)?;
            Ty::Float { size, be }
        }
        2 => {
            let be = bits & 1 != 0;
            rd.out.insert(
                size_at,
                bitfield(if be { "big-endian" } else { "little-endian" }.to_owned()),
            );
            rd.num("Bit precision", 2)?;
            Ty::Time { size, be }
        }
        3 => {
            let pad = u8::try_from(bits & 0x0f).unwrap_or(0);
            let cset = (bits >> 4) & 0x0f;
            rd.out.insert(
                size_at,
                bitfield(format!(
                    "{}, {}",
                    lookup(PADDING, pad.into()).unwrap_or("unknown padding"),
                    lookup(CHARSETS, cset).unwrap_or("unknown character set")
                )),
            );
            Ty::Str {
                size,
                pad,
                utf8: cset == 1,
            }
        }
        5 => {
            let len = to_usize(bits & 0xff);
            rd.out
                .insert(size_at, bitfield(format!("tag of {len} bytes")));
            let tag = if len > 0 {
                rd.text("Tag", len)?
            } else {
                String::new()
            };
            Ty::Opaque { size, tag }
        }
        6 => {
            let n = bits & 0xffff;
            rd.out.insert(size_at, bitfield(format!("{n} members")));
            let mut members = Vec::new();
            for _ in 0..n {
                let start = rd.pos;
                let mut sub = rd.fork();
                let member = compound_member(&mut sub, version, size, depth);
                let label = member
                    .as_ref()
                    .map_or_else(|| "Member".to_owned(), |m: &Member| m.name.clone());
                let summary = member
                    .as_ref()
                    .map(|m| format!("{} at offset {}", m.ty.describe(), m.offset));
                rd.join(label, start, sub);
                if let (Some(s), Some(last)) = (summary, rd.last()) {
                    last.summary = Some(s);
                }
                match member {
                    Some(m) => members.push(m),
                    None => break,
                }
            }
            if to_u64(members.len()) < n {
                return None;
            }
            Ty::Compound { size, members }
        }
        7 => {
            let kind = u8::try_from(bits & 0x0f).unwrap_or(0);
            rd.out.insert(
                size_at,
                bitfield(
                    lookup(REFERENCES, kind.into())
                        .unwrap_or("unknown reference type")
                        .to_owned(),
                ),
            );
            Ty::Ref { size, kind }
        }
        8 => {
            let n = bits & 0xffff;
            rd.out.insert(size_at, bitfield(format!("{n} members")));
            let start = rd.pos;
            let mut sub = rd.fork();
            let base = parse(&mut sub, depth.saturating_add(1));
            rd.join("Base type", start, sub);
            let base = base?;
            if let (Some(last), desc) = (rd.last(), base.describe()) {
                last.summary = Some(desc);
            }
            let align = if version >= 3 { 1 } else { 8 };
            let mut names = Vec::new();
            let start = rd.pos;
            let mut sub = rd.fork();
            for _ in 0..n {
                match sub.cstr("Name", align) {
                    Some(s) => names.push(s),
                    None => break,
                }
            }
            let complete = to_u64(names.len()) == n;
            rd.join("Names", start, sub);
            if !complete {
                return None;
            }
            let width = to_usize(base.size().into());
            let start = rd.pos;
            let mut sub = rd.fork();
            let mut pairs = Vec::new();
            for name in names {
                let Some((bytes, span)) = sub.slice(width) else {
                    break;
                };
                sub.push(
                    Node::new(name.clone())
                        .span(span)
                        .value(value(&base, bytes)),
                );
                pairs.push((name, bytes.to_vec()));
            }
            let complete = to_u64(pairs.len()) == n;
            rd.join("Values", start, sub);
            if !complete {
                return None;
            }
            Ty::Enum {
                size,
                base: Box::new(base),
                names: pairs,
            }
        }
        9 => {
            let kind = bits & 0x0f;
            let pad = (bits >> 4) & 0x0f;
            let cset = (bits >> 8) & 0x0f;
            let string = kind == 1;
            rd.out.insert(
                size_at,
                bitfield(if string {
                    format!(
                        "string, {}, {}",
                        lookup(PADDING, pad).unwrap_or("unknown padding"),
                        lookup(CHARSETS, cset).unwrap_or("unknown character set")
                    )
                } else {
                    "sequence".to_owned()
                }),
            );
            let start = rd.pos;
            let mut sub = rd.fork();
            let base = parse(&mut sub, depth.saturating_add(1));
            rd.join("Base type", start, sub);
            let base = base?;
            if let (Some(last), desc) = (rd.last(), base.describe()) {
                last.summary = Some(desc);
            }
            Ty::Vlen {
                size,
                string,
                utf8: cset == 1,
                base: Box::new(base),
            }
        }
        10 => {
            rd.out.insert(size_at, bitfield(String::new()));
            let rank = rd.num("Dimensionality", 1)?;
            if version < 3 {
                rd.reserved(3)?;
            }
            let mut dims = Vec::new();
            for _ in 0..rank {
                dims.push(u32v(rd.num("Dimension size", 4)?));
            }
            if version < 3 {
                for _ in 0..rank {
                    rd.num("Permutation index", 4)?;
                }
            }
            let start = rd.pos;
            let mut sub = rd.fork();
            let base = parse(&mut sub, depth.saturating_add(1));
            rd.join("Base type", start, sub);
            let base = base?;
            if let (Some(last), desc) = (rd.last(), base.describe()) {
                last.summary = Some(desc);
            }
            Ty::Array {
                size,
                dims,
                base: Box::new(base),
            }
        }
        11 => {
            rd.out.insert(
                size_at,
                bitfield(if bits & 1 != 0 {
                    "homogeneous".to_owned()
                } else {
                    String::new()
                }),
            );
            let start = rd.pos;
            let mut sub = rd.fork();
            let base = parse(&mut sub, depth.saturating_add(1));
            rd.join("Base type", start, sub);
            let base = base?;
            Ty::Complex {
                size,
                base: Box::new(base),
            }
        }
        _ => {
            rd.out.insert(size_at, bitfield(String::new()));
            Ty::Other { class, size }
        }
    })
}

/// One member of a compound datatype.
fn compound_member(rd: &mut Rd<'_>, version: u8, size: u32, depth: u32) -> Option<Member> {
    let name = rd.cstr("Name", if version >= 3 { 1 } else { 8 })?;
    let offset = if version >= 3 {
        u32v(rd.num("Byte offset", limit_enc_size(size.into()))?)
    } else {
        u32v(rd.num("Byte offset", 4)?)
    };
    let mut dims = Vec::new();
    if version == 1 {
        let rank = rd.num("Dimensionality", 1)?;
        rd.reserved(3)?;
        rd.num("Dimension permutation", 4)?;
        rd.reserved(4)?;
        for i in 0..4u64 {
            let d = rd.num("Dimension size", 4)?;
            if i < rank {
                dims.push(u32v(d));
            }
        }
    }
    let start = rd.pos;
    let mut sub = rd.fork();
    let ty = parse(&mut sub, depth.saturating_add(1));
    rd.join("Type", start, sub);
    let mut ty = ty?;
    if let (Some(last), desc) = (rd.last(), ty.describe()) {
        last.summary = Some(desc);
    }
    if !dims.is_empty() {
        let count = dims.iter().fold(1u32, |acc, &d| acc.saturating_mul(d));
        ty = Ty::Array {
            size: ty.size().saturating_mul(count),
            dims,
            base: Box::new(ty),
        };
    }
    Some(Member { name, offset, ty })
}

// ---------------------------------------------------------------------------
// Values

/// An integer of up to 8 bytes.
fn int(bytes: &[u8], be: bool, signed: bool) -> Option<Value> {
    let n = bytes.len();
    if n == 0 || n > 8 {
        return None;
    }
    let raw = if be {
        bytes
            .iter()
            .fold(0u64, |acc, &b| acc.wrapping_shl(8) | u64::from(b))
    } else {
        bytes
            .iter()
            .rev()
            .fold(0u64, |acc, &b| acc.wrapping_shl(8) | u64::from(b))
    };
    let bits = u32::try_from(n.saturating_mul(8)).unwrap_or(64);
    Some(if signed {
        let shift = 64u32.saturating_sub(bits);
        let v = raw.wrapping_shl(shift).cast_signed().wrapping_shr(shift);
        Value::Int {
            value: v,
            bits: u8::try_from(bits).unwrap_or(64),
        }
    } else {
        Value::UInt {
            value: raw,
            bits: u8::try_from(bits).unwrap_or(64),
            radix: Radix::Dec,
        }
    })
}

fn half(bits: u16) -> f64 {
    let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = i32::from((bits >> 10) & 0x1f);
    let frac = f64::from(bits & 0x3ff);
    let magnitude = match exp {
        0 => frac * 2f64.powi(-24),
        31 if frac == 0.0 => f64::INFINITY,
        31 => f64::NAN,
        _ => (1.0 + frac / 1024.0) * 2f64.powi(exp.saturating_sub(15)),
    };
    sign * magnitude
}

fn float(bytes: &[u8], be: bool) -> Option<Value> {
    let f = match (bytes.len(), be) {
        (2, false) => half(u16::from_le_bytes(bytes.try_into().ok()?)),
        (2, true) => half(u16::from_be_bytes(bytes.try_into().ok()?)),
        (4, false) => f64::from(f32::from_le_bytes(bytes.try_into().ok()?)),
        (4, true) => f64::from(f32::from_be_bytes(bytes.try_into().ok()?)),
        (8, false) => f64::from_le_bytes(bytes.try_into().ok()?),
        (8, true) => f64::from_be_bytes(bytes.try_into().ok()?),
        _ => return None,
    };
    Some(Value::Float(f))
}

/// Fixed-length string bytes, cut as the padding says.
pub fn fixed_string(bytes: &[u8], pad: u8) -> String {
    let text = if pad == 2 {
        let end = bytes
            .iter()
            .rposition(|&b| b != b' ' && b != 0)
            .map_or(0, |p| p.saturating_add(1));
        bytes.get(..end).unwrap_or_default()
    } else {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        bytes.get(..end).unwrap_or_default()
    };
    String::from_utf8_lossy(text).into_owned()
}

/// The value of one element of `ty` (`bytes` holds exactly its size).
/// Variable-length values (stored in the global heap) are described, not
/// resolved: see `data::element`.
pub fn value(ty: &Ty, bytes: &[u8]) -> Value {
    let raw = || Value::Bytes(bytes.iter().take(256).copied().collect());
    match ty {
        Ty::Int { signed, be, .. } => int(bytes, *be, *signed).unwrap_or_else(raw),
        Ty::Time { be, .. } => int(bytes, *be, true).unwrap_or_else(raw),
        Ty::Float { be, .. } => float(bytes, *be).unwrap_or_else(raw),
        Ty::Str { pad, .. } => Value::Text(fixed_string(bytes, *pad)),
        Ty::Bits { .. } | Ty::Opaque { .. } | Ty::Other { .. } => raw(),
        Ty::Enum { names, .. } => match names.iter().find(|(_, v)| v.as_slice() == bytes) {
            Some((name, _)) => Value::Text(name.clone()),
            None => raw(),
        },
        Ty::Ref { kind: 0, .. } => match super::util::uint(bytes, 0, bytes.len().min(8)) {
            Some(addr) => super::util::hex(addr),
            None => raw(),
        },
        _ => Value::Text(format(ty, bytes)),
    }
}

/// One element of `ty` as text (strings quoted inside structures).
pub fn format(ty: &Ty, bytes: &[u8]) -> String {
    match ty {
        Ty::Str { pad, .. } => format!("{:?}", fixed_string(bytes, *pad)),
        Ty::Enum { .. } => match value(ty, bytes) {
            Value::Text(s) => s,
            other => crate::render::value(&other),
        },
        Ty::Compound { members, .. } => {
            let mut parts = Vec::new();
            for m in members.iter().take(SHOWN.saturating_mul(2)) {
                let at = to_usize(m.offset.into());
                let len = to_usize(m.ty.size().into());
                let field = at
                    .checked_add(len)
                    .and_then(|end| bytes.get(at..end))
                    .map_or_else(|| "?".to_owned(), |b| format(&m.ty, b));
                parts.push(format!("{}: {field}", m.name));
            }
            if members.len() > SHOWN.saturating_mul(2) {
                parts.push("…".to_owned());
            }
            format!("{{{}}}", parts.join(", "))
        }
        Ty::Array { base, .. } => {
            let width = to_usize(base.size().into()).max(1);
            let mut parts: Vec<String> = bytes
                .chunks_exact(width)
                .take(16)
                .map(|c| format(base, c))
                .collect();
            if bytes.len().checked_div(width).unwrap_or(0) > 16 {
                parts.push("…".to_owned());
            }
            format!("[{}]", parts.join(", "))
        }
        Ty::Complex { base, .. } => {
            let half_len = bytes.len() / 2;
            match bytes.split_at_checked(half_len) {
                Some((re, im)) => format!("{} + {}i", format(base, re), format(base, im)),
                None => "?".to_owned(),
            }
        }
        Ty::Vlen { string, .. } => {
            let n = super::util::uint(bytes, 0, 4).unwrap_or(0);
            if *string {
                format!("<string of {n} bytes in the global heap>")
            } else {
                format!("<{n} elements in the global heap>")
            }
        }
        Ty::Ref { kind: 1, .. } => "<region reference>".to_owned(),
        _ => crate::render::value(&value(ty, bytes)),
    }
}
