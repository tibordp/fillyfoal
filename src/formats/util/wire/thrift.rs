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

use std::collections::BTreeMap;
use std::task::Poll;

use crate::bytes::to_u64;

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
    /// One synchronous step over the whole value: only for data bounded by
    /// a small constant; use [`Skip::compact`] for anything larger.
    pub fn skip(data: &[u8], at: usize, t: u8, depth: u32) -> Option<usize> {
        Skip::compact(at, t, depth)
            .run(data, None)
            .map(|(end, _)| end)
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
            Protocol::Binary => (usize::try_from(i32_be(data, at)?).ok()?, at.checked_add(4)?),
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
            (Protocol::Binary, Type::I32) => {
                (Scalar::Int(i64::from(i32_be(data, at)?), 32), fixed(4)?)
            }
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
    /// One synchronous step over the whole value: only for data bounded by
    /// a small constant; use [`Skip`] for anything larger.
    pub fn skip(self, data: &[u8], at: usize, t: Type, depth: u32) -> Option<usize> {
        Skip::new(self, at, t, depth)
            .run(data, None)
            .map(|(end, _)| end)
    }
}

// ---------------------------------------------------------------------------
// Skipping values in bounded steps

/// Values at least this long (in bytes) are remembered by a [`Memo`].
pub const MEMO_MIN: usize = 4096;

/// Where structures and containers end (and how many fields or elements
/// they have), remembered across skips over the same bytes so that a value
/// skipped once (to count its fields, say) is not walked again when it is
/// skipped from its parent. Only values of at least [`MEMO_MIN`] bytes are
/// kept: at most `len / MEMO_MIN` per nesting level. With each, how deep
/// its contents nest (relative to it), so that a value remembered at one
/// depth fails at a deeper one exactly as walking it again would.
#[derive(Debug, Default)]
pub struct Memo(BTreeMap<(usize, u8), Remembered>);

#[derive(Clone, Copy, Debug)]
struct Remembered {
    end: usize,
    count: u64,
    nesting: u32,
}

/// The memo key of a composite type.
fn memo_kind(t: Type) -> u8 {
    match t {
        Type::Struct => 0,
        Type::List => 1,
        Type::Set => 2,
        _ => 3,
    }
}

#[derive(Debug)]
enum Frame {
    Struct {
        start: usize,
        last: i16,
        count: u64,
        depth: u32,
        deepest: u32,
    },
    Container {
        start: usize,
        t: Type,
        count: u64,
        remaining: u64,
        key: Option<Type>,
        elem: Option<Type>,
        key_next: bool,
        depth: u32,
        deepest: u32,
    },
}

impl Frame {
    fn deepest(&mut self) -> &mut u32 {
        match self {
            Frame::Struct { deepest, .. } | Frame::Container { deepest, .. } => deepest,
        }
    }
}

/// Skips one value with an explicit stack, a bounded number of values per
/// [`Skip::step`], so that callers can suspend between steps. Yields where
/// the value ends and, for a structure, its number of fields (for a
/// container, its element count; 0 for a scalar).
#[derive(Debug)]
pub struct Skip {
    proto: Protocol,
    /// Parquet's compact reader: an empty list's element type is not
    /// checked.
    lenient: bool,
    stack: Vec<Frame>,
    /// The value to start next: position, type, depth.
    value: Option<(usize, Option<Type>, u32)>,
    pos: usize,
    done: bool,
}

impl Skip {
    pub fn new(proto: Protocol, at: usize, t: Type, depth: u32) -> Skip {
        Skip {
            proto,
            lenient: false,
            stack: Vec::new(),
            value: Some((at, Some(t), depth)),
            pos: at,
            done: false,
        }
    }

    /// A value of compact type code `t` (as in a field header), the way
    /// [`compact::skip`] reads it.
    pub fn compact(at: usize, t: u8, depth: u32) -> Skip {
        Skip {
            proto: Protocol::Compact,
            lenient: true,
            stack: Vec::new(),
            value: Some((at, Protocol::Compact.type_of(t, false), depth)),
            pos: at,
            done: false,
        }
    }

    /// Runs to the end in one step: only for data bounded by a small
    /// constant.
    pub fn run(mut self, data: &[u8], mut memo: Option<&mut Memo>) -> Option<(usize, u64)> {
        loop {
            if let Poll::Ready(r) = self.step(data, memo.as_deref_mut(), u32::MAX) {
                return r;
            }
        }
    }

    /// Advances over at most `budget` values (each a constant amount of
    /// work). `Pending` means call again.
    pub fn step(
        &mut self,
        data: &[u8],
        mut memo: Option<&mut Memo>,
        budget: u32,
    ) -> Poll<Option<(usize, u64)>> {
        if self.done {
            return Poll::Ready(None);
        }
        for _ in 0..budget {
            let r = match self.value.take() {
                Some((at, t, depth)) => self.start(data, memo.as_deref_mut(), at, t, depth),
                None => self.resume(data, memo.as_deref_mut()),
            };
            match r {
                None => {
                    self.done = true;
                    return Poll::Ready(None);
                }
                Some(Some(found)) => {
                    self.done = true;
                    return Poll::Ready(Some(found));
                }
                Some(None) => {}
            }
        }
        Poll::Pending
    }

    /// Starts the value at `at`. `None`: invalid; `Some(Some(_))`: the
    /// outermost value ended; `Some(None)`: carry on.
    #[allow(clippy::option_option)]
    fn start(
        &mut self,
        data: &[u8],
        memo: Option<&mut Memo>,
        at: usize,
        t: Option<Type>,
        depth: u32,
    ) -> Option<Option<(usize, u64)>> {
        if depth > MAX_DEPTH {
            return None;
        }
        let t = t?;
        self.note(depth);
        if matches!(t, Type::Struct | Type::List | Type::Set | Type::Map)
            && let Some(&r) = memo.as_deref().and_then(|m| m.0.get(&(at, memo_kind(t))))
        {
            let deepest = depth.saturating_add(r.nesting);
            if deepest > MAX_DEPTH {
                return None;
            }
            self.note(deepest);
            return Some(self.finish(r.end, r.count));
        }
        match t {
            Type::Struct => {
                self.stack.push(Frame::Struct {
                    start: at,
                    last: 0,
                    count: 0,
                    depth,
                    deepest: depth,
                });
                self.pos = at;
                Some(None)
            }
            Type::List | Type::Set | Type::Map => {
                let c = if self.lenient
                    && matches!(t, Type::List | Type::Set)
                    && let Some((0, _, start)) = compact::list_header(data, at)
                {
                    Container {
                        count: 0,
                        key: None,
                        elem: None,
                        start,
                    }
                } else {
                    self.proto.container(data, at, t)?
                };
                // Every element takes at least a byte (except compact
                // booleans in field headers, which are not elements).
                if c.count > to_u64(data.len()) {
                    return None;
                }
                self.stack.push(Frame::Container {
                    start: at,
                    t,
                    count: c.count,
                    remaining: c.count,
                    key: c.key,
                    elem: c.elem,
                    key_next: true,
                    depth,
                    deepest: depth,
                });
                self.pos = c.start;
                Some(None)
            }
            _ => {
                let (_, end) = self.proto.scalar(data, at, t)?;
                Some(self.finish(end, 0))
            }
        }
    }

    /// Continues the innermost structure or container at `self.pos`.
    #[allow(clippy::option_option)]
    fn resume(&mut self, data: &[u8], memo: Option<&mut Memo>) -> Option<Option<(usize, u64)>> {
        let pos = self.pos;
        let proto = self.proto;
        match self.stack.last_mut()? {
            Frame::Struct {
                last, count, depth, ..
            } => match proto.field_header(data, pos, *last)? {
                (Header::Stop, next) => Some(self.end_frame(memo, Type::Struct, next)),
                (Header::Field(id, t), next) => {
                    *last = id;
                    *count = count.saturating_add(1);
                    self.value = Some((next, Some(t), depth.saturating_add(1)));
                    Some(None)
                }
            },
            Frame::Container {
                t,
                remaining,
                key,
                elem,
                key_next,
                depth,
                ..
            } => {
                if *remaining == 0 {
                    let t = *t;
                    return Some(self.end_frame(memo, t, pos));
                }
                let d = depth.saturating_add(1);
                if let Some(k) = key.filter(|_| *key_next) {
                    *key_next = false;
                    self.value = Some((pos, Some(k), d));
                } else {
                    let e = (*elem)?;
                    *key_next = true;
                    *remaining = remaining.saturating_sub(1);
                    self.value = Some((pos, Some(e), d));
                }
                Some(None)
            }
        }
    }

    /// Notes that a value at `depth` was reached inside the innermost
    /// frame.
    fn note(&mut self, depth: u32) {
        if let Some(f) = self.stack.last_mut() {
            let d = f.deepest();
            *d = (*d).max(depth);
        }
    }

    /// The innermost structure or container (of type `t`) ended at `end`:
    /// pop it, and remember it if large.
    fn end_frame(&mut self, memo: Option<&mut Memo>, t: Type, end: usize) -> Option<(usize, u64)> {
        let (start, count, depth, deepest) = match self.stack.pop()? {
            Frame::Struct {
                start,
                count,
                depth,
                deepest,
                ..
            }
            | Frame::Container {
                start,
                count,
                depth,
                deepest,
                ..
            } => (start, count, depth, deepest),
        };
        if let Some(m) = memo
            && end.saturating_sub(start) >= MEMO_MIN
        {
            let r = Remembered {
                end,
                count,
                nesting: deepest.saturating_sub(depth),
            };
            m.0.insert((start, memo_kind(t)), r);
        }
        self.note(deepest);
        self.finish(end, count)
    }

    /// A value ended at `end`: the result if it was the outermost one.
    fn finish(&mut self, end: usize, count: u64) -> Option<(usize, u64)> {
        self.pos = end;
        self.stack.is_empty().then_some((end, count))
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

    /// Compact: a struct with field 1 = list<i32> of `n` zeros, then stop.
    fn big_struct(n: usize) -> Vec<u8> {
        let mut data = vec![0x19, 0xf5];
        let mut len = n;
        loop {
            let b = u8::try_from(len & 0x7f).unwrap_or(0);
            len >>= 7;
            if len == 0 {
                data.push(b);
                break;
            }
            data.push(b | 0x80);
        }
        data.extend(std::iter::repeat_n(0u8, n));
        data.push(0);
        data
    }

    #[test]
    fn skips_in_bounded_steps() {
        let data = big_struct(10_000);
        let mut skip = Skip::new(Protocol::Compact, 0, Type::Struct, 0);
        let mut memo = Memo::default();
        let mut steps = 0u32;
        let r = loop {
            match skip.step(&data, Some(&mut memo), 100) {
                Poll::Ready(r) => break r,
                Poll::Pending => steps = steps.saturating_add(1),
            }
        };
        assert_eq!(r, Some((data.len(), 1)));
        assert!(steps >= 100, "{steps}");
        // Remembered: skipping again is a single step, from the parent too.
        let mut again = Skip::new(Protocol::Compact, 0, Type::Struct, 0);
        assert_eq!(
            again.step(&data, Some(&mut memo), 1),
            Poll::Ready(Some((data.len(), 1)))
        );
        // The list's elements nest two levels below the struct: from
        // MAX_DEPTH - 1 it fails, remembered or not.
        let deep = Protocol::Compact.skip(&data, 0, Type::Struct, MAX_DEPTH - 1);
        let remembered = Skip::new(Protocol::Compact, 0, Type::Struct, MAX_DEPTH - 1)
            .run(&data, Some(&mut memo));
        assert_eq!((deep, remembered), (None, None));
        assert_eq!(
            Skip::new(Protocol::Compact, 0, Type::Struct, MAX_DEPTH - 2)
                .run(&data, Some(&mut memo)),
            Some((data.len(), 1))
        );
    }

    #[test]
    fn compact_codes_accept_empty_lists_of_any_type() {
        // An empty list whose element type (0) is not a type.
        let data = [0x00];
        assert_eq!(compact::skip(&data, 0, 9, 0), Some(1));
        assert_eq!(Protocol::Compact.skip(&data, 0, Type::List, 0), None);
        assert_eq!(compact::skip(&data, 0, 14, 0), None);
    }
}
