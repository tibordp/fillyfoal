//! Thrift binary and compact protocols, over bytes held in memory.
//!
//! [`compact`] has the raw compact-protocol primitives (type codes as on
//! the wire), used by Parquet's schema-driven reader. [`Protocol`] reads
//! either protocol with protocol-independent [`Type`]s, for the schemaless
//! dissector.
//!
//! Layouts follow the Thrift protocol specifications
//! (`doc/specs/thrift-binary-protocol.md`, `thrift-compact-protocol.md`);
//! checked against the Python `thrift` package's `TBinaryProtocol` and
//! `TCompactProtocol`.

use crate::bytes::{to_u64, to_usize};

/// Nesting of containers and structures followed when skipping values.
pub const MAX_DEPTH: u32 = 64;

/// The compact protocol, with its own type codes: 1/2 boolean true/false,
/// 3 byte, 4 i16, 5 i32, 6 i64, 7 double, 8 binary, 9 list, 10 set, 11 map,
/// 12 struct, 13 uuid.
pub mod compact {
    use super::*;

    /// A varint at `at`: the value and the position after it.
    pub fn varint(data: &[u8], at: usize) -> Option<(u64, usize)> {
        let (v, n) = crate::bytes::uleb128(data.get(at..)?)?;
        Some((v, at.checked_add(n)?))
    }

    pub fn zigzag(v: u64) -> i64 {
        crate::formats::util::wire::protobuf::zigzag(v)
    }

    /// Skips a value of compact type `t` at `at`; returns where it ends.
    pub fn skip(data: &[u8], at: usize, t: u8, depth: u32) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        match t {
            1 | 2 => Some(at),
            3 => at.checked_add(1).filter(|&e| e <= data.len()),
            4..=6 => varint(data, at).map(|(_, e)| e),
            7 => at.checked_add(8).filter(|&e| e <= data.len()),
            8 => {
                let (len, e) = varint(data, at)?;
                e.checked_add(to_usize(len))
                    .filter(|&end| end <= data.len())
            }
            9 | 10 => {
                let (n, elem, mut pos) = list_header(data, at)?;
                if n > to_u64(data.len()) {
                    return None;
                }
                for _ in 0..n {
                    pos = skip_element(data, pos, elem, depth.saturating_add(1))?;
                }
                Some(pos)
            }
            11 => {
                let (n, kv, mut pos) = map_header(data, at)?;
                if n > to_u64(data.len()) {
                    return None;
                }
                for _ in 0..n {
                    pos = skip_element(data, pos, kv >> 4, depth.saturating_add(1))?;
                    pos = skip_element(data, pos, kv & 0x0f, depth.saturating_add(1))?;
                }
                Some(pos)
            }
            12 => {
                let mut pos = at;
                let mut id = 0i16;
                loop {
                    let (field, t, next) = field_header(data, pos, id)?;
                    if t == 0 {
                        return Some(next);
                    }
                    id = field;
                    pos = skip(data, next, t, depth.saturating_add(1))?;
                }
            }
            13 => at.checked_add(16).filter(|&e| e <= data.len()),
            _ => None,
        }
    }

    /// Inside lists and maps, booleans take a byte of their own.
    pub fn skip_element(data: &[u8], at: usize, t: u8, depth: u32) -> Option<usize> {
        match t {
            1 | 2 => at.checked_add(1).filter(|&e| e <= data.len()),
            _ => skip(data, at, t, depth),
        }
    }

    /// A list/set header: element count, element type, position after.
    pub fn list_header(data: &[u8], at: usize) -> Option<(u64, u8, usize)> {
        let b = *data.get(at)?;
        let elem = b & 0x0f;
        if b >> 4 == 15 {
            let (n, e) = varint(data, at.checked_add(1)?)?;
            Some((n, elem, e))
        } else {
            Some((u64::from(b >> 4), elem, at.checked_add(1)?))
        }
    }

    /// A map header: entry count, key and value types (`key << 4 | value`;
    /// absent for empty maps), position after.
    pub fn map_header(data: &[u8], at: usize) -> Option<(u64, u8, usize)> {
        let (n, pos) = varint(data, at)?;
        if n == 0 {
            return Some((0, 0, pos));
        }
        let kv = *data.get(pos)?;
        Some((n, kv, pos.checked_add(1)?))
    }

    /// A field header: field id, type (0 = stop), position after.
    pub fn field_header(data: &[u8], at: usize, last: i16) -> Option<(i16, u8, usize)> {
        let b = *data.get(at)?;
        let t = b & 0x0f;
        if t == 0 {
            return Some((0, 0, at.checked_add(1)?));
        }
        let delta = b >> 4;
        if delta == 0 {
            let (v, e) = varint(data, at.checked_add(1)?)?;
            Some((i16::try_from(zigzag(v)).ok()?, t, e))
        } else {
            Some((last.checked_add(i16::from(delta))?, t, at.checked_add(1)?))
        }
    }
}

// ---------------------------------------------------------------------------
// Both protocols

/// A Thrift protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// `TBinaryProtocol`: big-endian fixed-width integers, `i32` lengths.
    Binary,
    /// `TCompactProtocol`: varints, zig-zag integers, field id deltas.
    Compact,
}

/// A value type, independent of the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    /// A boolean whose value is in the compact field header.
    BoolIn(bool),
    Bool,
    Byte,
    I16,
    I32,
    I64,
    Double,
    /// `string` or `binary`: a length and bytes.
    Binary,
    Struct,
    Map,
    Set,
    List,
    Uuid,
}

impl Type {
    pub fn name(self) -> &'static str {
        match self {
            Type::BoolIn(_) | Type::Bool => "bool",
            Type::Byte => "byte",
            Type::I16 => "i16",
            Type::I32 => "i32",
            Type::I64 => "i64",
            Type::Double => "double",
            Type::Binary => "binary",
            Type::Struct => "struct",
            Type::Map => "map",
            Type::Set => "set",
            Type::List => "list",
            Type::Uuid => "uuid",
        }
    }
}

/// A decoded scalar.
#[derive(Clone, Debug, PartialEq)]
pub enum Scalar<'a> {
    Bool(bool),
    Int(i64, u8),
    Double(f64),
    Bytes(&'a [u8]),
    Uuid(&'a [u8]),
}

/// A field header: the field id and the type of its value, or the end of
/// the structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Header {
    Field(i16, Type),
    Stop,
}

/// A container header: element count, element type(s) (`None` for an
/// empty compact map, which has no types), position of the first element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Container {
    pub count: u64,
    pub key: Option<Type>,
    pub elem: Option<Type>,
    pub start: usize,
}

fn i32_be(data: &[u8], at: usize) -> Option<i32> {
    crate::bytes::u32_be(data, at).map(u32::cast_signed)
}

impl Protocol {
    /// The type for a type code on the wire, in a field header or as a
    /// container element type.
    pub fn type_of(self, code: u8, element: bool) -> Option<Type> {
        Some(match (self, code) {
            (Protocol::Binary, 2) => Type::Bool,
            (Protocol::Binary, 3) => Type::Byte,
            (Protocol::Binary, 4) => Type::Double,
            (Protocol::Binary, 6) => Type::I16,
            (Protocol::Binary, 8) => Type::I32,
            (Protocol::Binary, 10) => Type::I64,
            (Protocol::Binary, 11) => Type::Binary,
            (Protocol::Binary, 12) => Type::Struct,
            (Protocol::Binary, 13) => Type::Map,
            (Protocol::Binary, 14) => Type::Set,
            (Protocol::Binary, 15) => Type::List,
            (Protocol::Binary, 16) => Type::Uuid,
            (Protocol::Compact, 1 | 2) if element => Type::Bool,
            (Protocol::Compact, 1) => Type::BoolIn(true),
            (Protocol::Compact, 2) => Type::BoolIn(false),
            (Protocol::Compact, 3) => Type::Byte,
            (Protocol::Compact, 4) => Type::I16,
            (Protocol::Compact, 5) => Type::I32,
            (Protocol::Compact, 6) => Type::I64,
            (Protocol::Compact, 7) => Type::Double,
            (Protocol::Compact, 8) => Type::Binary,
            (Protocol::Compact, 9) => Type::List,
            (Protocol::Compact, 10) => Type::Set,
            (Protocol::Compact, 11) => Type::Map,
            (Protocol::Compact, 12) => Type::Struct,
            (Protocol::Compact, 13) => Type::Uuid,
            _ => return None,
        })
    }

    /// The field header at `at` (`last` is the previous field id, for the
    /// compact protocol's deltas) and the position after it.
    pub fn field_header(self, data: &[u8], at: usize, last: i16) -> Option<(Header, usize)> {
        match self {
            Protocol::Binary => {
                let code = *data.get(at)?;
                if code == 0 {
                    return Some((Header::Stop, at.checked_add(1)?));
                }
                let id = crate::bytes::u16_be(data, at.checked_add(1)?)?.cast_signed();
                let t = self.type_of(code, false)?;
                Some((Header::Field(id, t), at.checked_add(3)?))
            }
            Protocol::Compact => {
                let (id, code, next) = compact::field_header(data, at, last)?;
                if code == 0 {
                    return Some((Header::Stop, next));
                }
                Some((Header::Field(id, self.type_of(code, false)?), next))
            }
        }
    }

    /// The header of a list, set or map at `at`.
    pub fn container(self, data: &[u8], at: usize, t: Type) -> Option<Container> {
        match (self, t) {
            (Protocol::Binary, Type::List | Type::Set) => {
                let elem = self.type_of(*data.get(at)?, true)?;
                let n = i32_be(data, at.checked_add(1)?)?;
                Some(Container {
                    count: u64::try_from(n).ok()?,
                    key: None,
                    elem: Some(elem),
                    start: at.checked_add(5)?,
                })
            }
            (Protocol::Binary, Type::Map) => {
                let key = self.type_of(*data.get(at)?, true)?;
                let elem = self.type_of(*data.get(at.checked_add(1)?)?, true)?;
                let n = i32_be(data, at.checked_add(2)?)?;
                Some(Container {
                    count: u64::try_from(n).ok()?,
                    key: Some(key),
                    elem: Some(elem),
                    start: at.checked_add(6)?,
                })
            }
            (Protocol::Compact, Type::List | Type::Set) => {
                let (n, code, start) = compact::list_header(data, at)?;
                Some(Container {
                    count: n,
                    key: None,
                    elem: Some(self.type_of(code, true)?),
                    start,
                })
            }
            (Protocol::Compact, Type::Map) => {
                let (n, kv, start) = compact::map_header(data, at)?;
                if n == 0 {
                    return Some(Container {
                        count: 0,
                        key: None,
                        elem: None,
                        start,
                    });
                }
                Some(Container {
                    count: n,
                    key: Some(self.type_of(kv >> 4, true)?),
                    elem: Some(self.type_of(kv & 0x0f, true)?),
                    start,
                })
            }
            _ => None,
        }
    }

    /// A string/binary at `at`: its bytes' range.
    fn binary(self, data: &[u8], at: usize) -> Option<(usize, usize)> {
        let (len, start) = match self {
            Protocol::Binary => (
                usize::try_from(i32_be(data, at)?).ok()?,
                at.checked_add(4)?,
            ),
            Protocol::Compact => {
                let (len, start) = compact::varint(data, at)?;
                (usize::try_from(len).ok()?, start)
            }
        };
        let end = start.checked_add(len)?;
        (end <= data.len()).then_some((start, end))
    }

    /// The scalar of type `t` at `at` and the position after it.
    pub fn scalar(self, data: &[u8], at: usize, t: Type) -> Option<(Scalar<'_>, usize)> {
        let fixed = |n: usize| at.checked_add(n).filter(|&e| e <= data.len());
        Some(match (self, t) {
            (_, Type::BoolIn(b)) => (Scalar::Bool(b), at),
            (_, Type::Bool) => (Scalar::Bool(*data.get(at)? == 1), fixed(1)?),
            (_, Type::Byte) => (
                Scalar::Int(i64::from(data.get(at)?.cast_signed()), 8),
                fixed(1)?,
            ),
            (Protocol::Binary, Type::I16) => (
                Scalar::Int(i64::from(crate::bytes::u16_be(data, at)?.cast_signed()), 16),
                fixed(2)?,
            ),
            (Protocol::Binary, Type::I32) => (Scalar::Int(i64::from(i32_be(data, at)?), 32), fixed(4)?),
            (Protocol::Binary, Type::I64) => (
                Scalar::Int(crate::bytes::u64_be(data, at)?.cast_signed(), 64),
                fixed(8)?,
            ),
            (Protocol::Binary, Type::Double) => (
                Scalar::Double(f64::from_bits(crate::bytes::u64_be(data, at)?)),
                fixed(8)?,
            ),
            (Protocol::Compact, Type::I16 | Type::I32 | Type::I64) => {
                let (v, end) = compact::varint(data, at)?;
                let bits = match t {
                    Type::I16 => 16,
                    Type::I32 => 32,
                    _ => 64,
                };
                (Scalar::Int(compact::zigzag(v), bits), end)
            }
            (Protocol::Compact, Type::Double) => (
                Scalar::Double(f64::from_bits(crate::bytes::u64_le(data, at)?)),
                fixed(8)?,
            ),
            (_, Type::Binary) => {
                let (start, end) = self.binary(data, at)?;
                (Scalar::Bytes(data.get(start..end)?), end)
            }
            (_, Type::Uuid) => {
                let end = fixed(16)?;
                (Scalar::Uuid(data.get(at..end)?), end)
            }
            _ => return None,
        })
    }

    /// Skips a value of type `t` at `at`; returns where it ends. Bounded by
    /// `depth` (structures and containers nest at most [`MAX_DEPTH`] deep).
    pub fn skip(self, data: &[u8], at: usize, t: Type, depth: u32) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        match t {
            Type::Struct => {
                let mut pos = at;
                let mut last = 0i16;
                loop {
                    match self.field_header(data, pos, last)? {
                        (Header::Stop, next) => return Some(next),
                        (Header::Field(id, t), next) => {
                            last = id;
                            pos = self.skip(data, next, t, depth.saturating_add(1))?;
                        }
                    }
                }
            }
            Type::List | Type::Set | Type::Map => {
                let c = self.container(data, at, t)?;
                // Every element takes at least a byte (except compact
                // booleans in field headers, which are not elements).
                if c.count > to_u64(data.len()) {
                    return None;
                }
                let mut pos = c.start;
                for _ in 0..c.count {
                    if let Some(k) = c.key {
                        pos = self.skip(data, pos, k, depth.saturating_add(1))?;
                    }
                    pos = self.skip(data, pos, c.elem?, depth.saturating_add(1))?;
                }
                Some(pos)
            }
            _ => self.scalar(data, at, t).map(|(_, end)| end),
        }
    }
}

/// A message header (`TMessage`): name, type, sequence id, and where the
/// arguments structure starts. Strict binary headers (`0x8001` version)
/// and compact headers (`0x82`) are recognised; old unversioned binary
/// headers are not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub name: &'a [u8],
    pub kind: u8,
    pub seqid: i32,
    pub start: usize,
}

/// Message types.
pub const MESSAGE_TYPES: crate::value::EnumTable =
    &[(1, "CALL"), (2, "REPLY"), (3, "EXCEPTION"), (4, "ONEWAY")];

impl Protocol {
    pub fn message(self, data: &[u8]) -> Option<Message<'_>> {
        match self {
            Protocol::Binary => {
                let word = crate::bytes::u32_be(data, 0)?;
                if word & 0xffff_0000 != 0x8001_0000 || word & 0xff00 != 0 {
                    return None;
                }
                let kind = u8::try_from(word & 0xff).ok()?;
                let (start, end) = self.binary(data, 4)?;
                let seqid = i32_be(data, end)?;
                Some(Message {
                    name: data.get(start..end)?,
                    kind,
                    seqid,
                    start: end.checked_add(4)?,
                })
            }
            Protocol::Compact => {
                if *data.first()? != 0x82 {
                    return None;
                }
                let b = *data.get(1)?;
                if b & 0x1f != 1 {
                    return None;
                }
                let (seq, at) = compact::varint(data, 2)?;
                let (start, end) = self.binary(data, at)?;
                Some(Message {
                    name: data.get(start..end)?,
                    kind: b >> 5,
                    seqid: u32::try_from(seq).ok()?.cast_signed(),
                    start: end,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_nested_values() {
        // Compact: field 1 i32 = -1, field 2 list<i16> [1, 2], stop.
        let data = [0x15, 0x01, 0x19, 0x24, 0x02, 0x04, 0x00];
        assert_eq!(Protocol::Compact.skip(&data, 0, Type::Struct, 0), Some(7));
        // Binary: field 1 string "ab", stop.
        let data = [11, 0, 1, 0, 0, 0, 2, b'a', b'b', 0];
        assert_eq!(Protocol::Binary.skip(&data, 0, Type::Struct, 0), Some(10));
        assert_eq!(
            Protocol::Binary.field_header(&data, 0, 0),
            Some((Header::Field(1, Type::Binary), 3))
        );
    }
}
