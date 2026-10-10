//! Field decoding: the first layer of the dissector DSL.
//!
//! A [`Fields`] cursor walks a [`Block`]. Each field method decodes a value,
//! records its span, and returns a [`Field`] that can be decorated (radix,
//! enum names, flags, description, target) and then either emitted as a node
//! or just returned. The same layout function therefore serves two purposes:
//! silently extracting values the dissector needs, and rendering the
//! structure when the user expands it.
//!
//! ```ignore
//! fn file_header(f: &mut Fields<'_>, _: &()) -> Result<FileHeader> {
//!     let machine = f.u16("Machine").enumeration(MACHINE).emit()?;
//!     let sections = f.u16("NumberOfSections").emit()?;
//!     f.u32("TimeDateStamp").timestamp().emit()?;
//!     ...
//! }
//! ```

use std::borrow::Cow;

use crate::bytes::{to_u64, to_usize};
use crate::cx::{Block, Cx};
use crate::error::{Diagnostic, Result};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, Radix, Value, decode_flags, lookup};

pub use crate::bytes::Endian;

/// Fixed-size integers that fields can decode.
pub trait Prim: Copy {
    const SIZE: usize;
    fn decode(bytes: &[u8], endian: Endian) -> Option<Self>;
    /// The value's bits, zero-extended.
    fn raw(self) -> u64;
    fn value(self, radix: Radix) -> Value;
}

macro_rules! prim_unsigned {
    ($($t:ty),*) => {$(
        impl Prim for $t {
            const SIZE: usize = std::mem::size_of::<$t>();
            fn decode(bytes: &[u8], endian: Endian) -> Option<Self> {
                let bytes = bytes.try_into().ok()?;
                Some(match endian {
                    Endian::Little => <$t>::from_le_bytes(bytes),
                    Endian::Big => <$t>::from_be_bytes(bytes),
                })
            }
            fn raw(self) -> u64 {
                u64::from(self)
            }
            fn value(self, radix: Radix) -> Value {
                Value::UInt { value: u64::from(self), bits: <$t>::BITS as u8, radix }
            }
        }
    )*};
}

macro_rules! prim_signed {
    ($($t:ty => $u:ty),*) => {$(
        impl Prim for $t {
            const SIZE: usize = std::mem::size_of::<$t>();
            fn decode(bytes: &[u8], endian: Endian) -> Option<Self> {
                let bytes = bytes.try_into().ok()?;
                Some(match endian {
                    Endian::Little => <$t>::from_le_bytes(bytes),
                    Endian::Big => <$t>::from_be_bytes(bytes),
                })
            }
            fn raw(self) -> u64 {
                u64::from(self as $u)
            }
            fn value(self, _radix: Radix) -> Value {
                Value::Int { value: i64::from(self), bits: <$t>::BITS as u8 }
            }
        }
    )*};
}

prim_unsigned!(u8, u16, u32, u64);

macro_rules! prim_float {
    ($($t:ty => $u:ty),*) => {$(
        impl Prim for $t {
            const SIZE: usize = std::mem::size_of::<$t>();
            fn decode(bytes: &[u8], endian: Endian) -> Option<Self> {
                let bytes = bytes.try_into().ok()?;
                Some(match endian {
                    Endian::Little => <$t>::from_le_bytes(bytes),
                    Endian::Big => <$t>::from_be_bytes(bytes),
                })
            }
            fn raw(self) -> u64 {
                u64::from(self.to_bits())
            }
            fn value(self, _radix: Radix) -> Value {
                Value::Float(f64::from(self))
            }
        }
    )*};
}

prim_float!(f32 => u32, f64 => u64);
prim_signed!(i8 => u8, i16 => u16, i32 => u32, i64 => u64);

/// A cursor over a block that decodes fields and, optionally, emits them.
pub struct Fields<'a> {
    cx: Option<&'a Cx>,
    block: &'a Block,
    pos: u64,
    endian: Endian,
}

impl<'a> Fields<'a> {
    /// Decodes without emitting anything.
    pub fn new(block: &'a Block, endian: Endian) -> Self {
        Fields {
            cx: None,
            block,
            pos: 0,
            endian,
        }
    }

    /// Decodes and emits each field as a child of the node being expanded.
    pub fn emitting(cx: &'a Cx, block: &'a Block, endian: Endian) -> Self {
        Fields {
            cx: Some(cx),
            block,
            pos: 0,
            endian,
        }
    }

    pub fn is_emitting(&self) -> bool {
        self.cx.is_some()
    }

    pub fn block(&self) -> &'a Block {
        self.block
    }

    /// Current position, relative to the start of the block.
    pub fn pos(&self) -> u64 {
        self.pos
    }

    pub fn seek(&mut self, pos: u64) {
        self.pos = pos;
    }

    pub fn skip(&mut self, n: u64) {
        self.pos = self.pos.saturating_add(n);
    }

    /// Bytes left in the block's span (not necessarily all present).
    pub fn remaining(&self) -> u64 {
        self.block.span.len.saturating_sub(self.pos)
    }

    /// The span of the next `len` bytes, without consuming them.
    pub fn peek_span(&self, len: u64) -> Span {
        Span::new(
            self.block.span.source,
            self.block.span.offset.saturating_add(self.pos),
            len,
        )
    }

    /// Emits an arbitrary node (e.g. a lazy group) if this cursor is emitting.
    pub fn node(&self, node: Node) {
        if let Some(cx) = self.cx {
            cx.emit(node);
        }
    }

    fn take(&mut self, len: u64) -> (Span, Result<&'a [u8]>) {
        let span = self.peek_span(len);
        let data: &'a [u8] = &self.block.data;
        let start = to_usize(self.pos);
        let bytes = start
            .checked_add(to_usize(len))
            .and_then(|end| data.get(start..end))
            .ok_or_else(|| {
                let available = to_u64(data.len().saturating_sub(start));
                Diagnostic::truncated(span, available)
            });
        self.pos = self.pos.saturating_add(len);
        (span, bytes)
    }

    fn field<T>(&self, name: &'static str, span: Span, value: Result<T>) -> Field<'a, T> {
        Field {
            cx: self.cx,
            node: Node::new(name).span(span),
            value,
            raw: None,
        }
    }

    pub fn int<T: Prim>(&mut self, name: &'static str) -> Field<'a, T> {
        let endian = self.endian;
        let (span, bytes) = self.take(to_u64(T::SIZE));
        let value = bytes.and_then(|b| {
            T::decode(b, endian).ok_or_else(|| Diagnostic::internal("integer decode failed"))
        });
        let mut field = self.field(name, span, value);
        if let Ok(v) = &field.value {
            field.raw = Some((v.raw(), bits_of::<T>()));
            field.node.value = Some(v.value(Radix::Dec));
        }
        field
    }

    pub fn u8(&mut self, name: &'static str) -> Field<'a, u8> {
        self.int(name)
    }

    pub fn u16(&mut self, name: &'static str) -> Field<'a, u16> {
        self.int(name)
    }

    pub fn u32(&mut self, name: &'static str) -> Field<'a, u32> {
        self.int(name)
    }

    pub fn u64(&mut self, name: &'static str) -> Field<'a, u64> {
        self.int(name)
    }

    pub fn i32(&mut self, name: &'static str) -> Field<'a, i32> {
        self.int(name)
    }

    pub fn f32(&mut self, name: &'static str) -> Field<'a, f32> {
        self.int(name)
    }

    pub fn f64(&mut self, name: &'static str) -> Field<'a, f64> {
        self.int(name)
    }

    /// A NUL-terminated UTF-16 string (in the cursor's byte order) within
    /// the rest of the block.
    pub fn utf16z(&mut self, name: &'static str) -> Field<'a, String> {
        let data: &'a [u8] = &self.block.data;
        let start = to_usize(self.pos);
        let rest = data.get(start..).unwrap_or_default();
        let (text, len, terminated) = crate::text::utf16z(rest, self.endian);
        let (span, _) = self.take(to_u64(len));
        let value = if terminated {
            Ok(text)
        } else {
            Err(Diagnostic::malformed("unterminated UTF-16 string").at(span))
        };
        let mut field = self.field(name, span, value);
        if let Ok(v) = &field.value {
            field.node.value = Some(Value::Text(v.clone()));
        }
        field
    }

    /// A fixed-size UTF-16 text field of `units` code units, NUL-padded.
    pub fn utf16(&mut self, name: &'static str, units: u64) -> Field<'a, String> {
        let endian = self.endian;
        let (span, bytes) = self.take(units.saturating_mul(2));
        let text = bytes.map(|b| crate::text::utf16z(b, endian).0);
        let mut field = self.field(name, span, text);
        if let Ok(v) = &field.value {
            field.node.value = Some(Value::Text(v.clone()));
        }
        field
    }

    /// A 32- or 64-bit unsigned field, depending on `wide`.
    pub fn uword(&mut self, name: &'static str, wide: bool) -> Field<'a, u64> {
        if wide {
            self.u64(name)
        } else {
            self.u32(name).map(u64::from)
        }
    }

    pub fn bytes(&mut self, name: &'static str, len: u64) -> Field<'a, Vec<u8>> {
        let (span, bytes) = self.take(len);
        let mut field = self.field(name, span, bytes.map(<[u8]>::to_vec));
        if let Ok(v) = &field.value {
            field.node.value = Some(Value::Bytes(v.clone()));
        }
        field
    }

    /// A fixed-size text field, NUL-padded (decoded lossily as UTF-8).
    pub fn ascii(&mut self, name: &'static str, len: u64) -> Field<'a, String> {
        let (span, bytes) = self.take(len);
        let text = bytes.map(|b| {
            let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            String::from_utf8_lossy(b.get(..end).unwrap_or_default()).into_owned()
        });
        let mut field = self.field(name, span, text);
        if let Ok(v) = &field.value {
            field.node.value = Some(Value::Text(v.clone()));
        }
        field
    }

    /// A NUL-terminated string within the rest of the block.
    pub fn cstr(&mut self, name: &'static str) -> Field<'a, String> {
        let data: &'a [u8] = &self.block.data;
        let start = to_usize(self.pos);
        let rest = data.get(start..).unwrap_or_default();
        let len = match rest.iter().position(|&c| c == 0) {
            Some(n) => to_u64(n).saturating_add(1),
            None => self.remaining().max(1),
        };
        let mut field = self.ascii(name, len);
        if field.value.is_ok() && !rest.contains(&0) {
            field.value = Err(Diagnostic::malformed("unterminated string").at(field.span()));
        }
        field
    }

    /// A GUID in Microsoft mixed-endian layout.
    pub fn guid(&mut self, name: &'static str) -> Field<'a, Guid> {
        let (span, bytes) = self.take(16);
        let guid = bytes.map(|b| {
            let get = |i: usize| b.get(i).copied().unwrap_or(0);
            let u16le = |i: usize| u16::from_le_bytes([get(i), get(i.saturating_add(1))]);
            let mut data4 = [0u8; 8];
            data4.copy_from_slice(b.get(8..16).unwrap_or(&[0; 8]));
            Guid {
                data1: u32::from_le_bytes([get(0), get(1), get(2), get(3)]),
                data2: u16le(4),
                data3: u16le(6),
                data4,
            }
        });
        let mut field = self.field(name, span, guid);
        if let Ok(v) = &field.value {
            field.node.value = Some(Value::Guid(*v));
        }
        field
    }
}

fn bits_of<T: Prim>() -> u8 {
    u8::try_from(T::SIZE.saturating_mul(8)).unwrap_or(u8::MAX)
}

/// A decoded field, not yet emitted.
#[must_use = "a field does nothing until `emit` or `get` is called"]
pub struct Field<'a, T> {
    cx: Option<&'a Cx>,
    node: Node,
    value: Result<T>,
    raw: Option<(u64, u8)>,
}

impl<'a, T> Field<'a, T> {
    pub fn span(&self) -> Span {
        self.node
            .span
            .unwrap_or(Span::new(crate::span::SourceId(0), 0, 0))
    }

    pub fn desc(mut self, description: impl Into<Cow<'static, str>>) -> Self {
        self.node.description = Some(description.into());
        self
    }

    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.node.summary = Some(summary.into());
        self
    }

    pub fn target(mut self, target: Span) -> Self {
        self.node.target = Some(target);
        self
    }

    /// Decorates the node based on the decoded value (skipped if decoding
    /// failed).
    pub fn with(mut self, f: impl FnOnce(&T, Node) -> Node) -> Self {
        if let Ok(v) = &self.value {
            self.node = f(v, self.node);
        }
        self
    }

    /// Attaches a diagnostic when `check` returns one for the value.
    pub fn check(mut self, check: impl FnOnce(&T) -> Option<Diagnostic>) -> Self {
        if let Ok(v) = &self.value
            && let Some(d) = check(v)
        {
            let span = self.span();
            self.node.diagnostics.push(d.at(span));
        }
        self
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Field<'a, U> {
        Field {
            cx: self.cx,
            node: self.node,
            value: self.value.map(f),
            raw: self.raw,
        }
    }

    /// Returns the value without emitting a node.
    pub fn get(self) -> Result<T> {
        self.value
    }

    /// Emits the field (if the cursor is emitting) and returns its value.
    pub fn emit(self) -> Result<T> {
        if let (Some(cx), Ok(_)) = (self.cx, &self.value) {
            cx.emit(self.node);
        }
        self.value
    }
}

impl<T: Prim> Field<'_, T> {
    pub fn hex(mut self) -> Self {
        if let Some(Value::UInt { radix, .. }) = &mut self.node.value {
            *radix = Radix::Hex;
        }
        self
    }

    pub fn enumeration(mut self, table: EnumTable) -> Self {
        if let Some((raw, bits)) = self.raw {
            self.node.value = Some(Value::Enum {
                raw,
                bits,
                name: lookup(table, raw),
            });
        }
        self
    }

    pub fn flags(mut self, table: FlagTable) -> Self {
        if let Some((raw, bits)) = self.raw {
            let (set, unknown) = decode_flags(table, raw);
            self.node.value = Some(Value::Flags {
                raw,
                bits,
                set,
                unknown,
            });
        }
        self
    }

    /// Windows FILETIME (100 ns ticks since 1601).
    pub fn filetime(mut self) -> Self {
        if let Some((raw, _)) = self.raw {
            self.node.value = Some(Value::Timestamp {
                unix_seconds: crate::text::filetime_to_unix(raw),
            });
        }
        self
    }

    /// Seconds since 1904 (HFS, QuickTime, AIFF).
    pub fn mac_time(mut self) -> Self {
        if let Some((raw, _)) = self.raw {
            self.node.value = Some(Value::Timestamp {
                unix_seconds: crate::text::mac_to_unix(raw),
            });
        }
        self
    }

    /// Seconds since the Unix epoch.
    pub fn timestamp(mut self) -> Self {
        if let Some((raw, _)) = self.raw {
            self.node.value = Some(Value::Timestamp {
                unix_seconds: i64::try_from(raw).unwrap_or(i64::MAX),
            });
        }
        self
    }
}

/// A layout function: decodes (and, when emitting, renders) a structure.
pub type Layout<C, R> = fn(&mut Fields<'_>, &C) -> Result<R>;

struct StructState<C, R> {
    span: Span,
    endian: Endian,
    ctx: C,
    layout: Layout<C, R>,
}

impl<C: Clone, R> Clone for StructState<C, R> {
    fn clone(&self) -> Self {
        StructState {
            span: self.span,
            endian: self.endian,
            ctx: self.ctx.clone(),
            layout: self.layout,
        }
    }
}

/// A lazy node whose children are the fields of `layout` applied to `span`.
pub fn struct_node<C, R>(
    name: impl Into<Cow<'static, str>>,
    span: Span,
    endian: Endian,
    ctx: C,
    layout: Layout<C, R>,
) -> Node
where
    C: Clone + Send + Sync + 'static,
    R: 'static,
{
    let state = StructState {
        span,
        endian,
        ctx,
        layout,
    };
    Node::new(name)
        .span(span)
        .lazy(expand_struct::<C, R>, state)
}

async fn expand_struct<C, R>(cx: Cx, st: StructState<C, R>) -> Result<()>
where
    C: Send + Sync,
{
    let block = cx.block(st.span).await?;
    (st.layout)(&mut Fields::emitting(&cx, &block, st.endian), &st.ctx)?;
    Ok(())
}

/// Reads `span` and decodes it with `layout`, without emitting anything.
pub async fn parse<C: Sync, R>(
    cx: &Cx,
    span: Span,
    endian: Endian,
    ctx: &C,
    layout: Layout<C, R>,
) -> Result<R> {
    let block = cx.block(span).await?;
    layout(&mut Fields::new(&block, endian), ctx)
}
