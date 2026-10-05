//! The second layer of the dissector DSL: declarative records and an async
//! cursor for sequential structures.
//!
//! A record declares a fixed-size structure once; the macro generates the Rust
//! struct, a [`Record`] impl that decodes it (emitting fields when the cursor
//! is emitting), and its size:
//!
//! ```ignore
//! record! {
//!     /// BITMAPFILEHEADER
//!     pub struct FileHeader {
//!         magic: ascii[2] "bfType",
//!         size: u32 "bfSize" .hex(),
//!         _reserved: u32 "bfReserved",
//!         offset: u32 "bfOffBits" .hex() .desc("Offset of the pixel array"),
//!     }
//! }
//! ```
//!
//! Field kinds: `u8 u16 u32 u64 i8 i16 i32 i64`, `ascii[N]` (NUL-padded
//! text), `bytes[N]`, `guid`. Anything after the label is a chain of
//! [`crate::Field`] decorators; closures in decorators can refer to fields
//! declared earlier (they are local variables).
//!
//! Variable layouts are written by hand against [`crate::Fields`] or
//! [`Cursor`]: records cover the common case, Rust covers the rest.

use std::borrow::Cow;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Prim, struct_node};
use crate::node::Node;
use crate::span::Span;

/// A fixed-size structure declared with [`record!`](crate::record).
pub trait Record: Sized + Send + 'static {
    const SIZE: u64;
    fn read(f: &mut Fields<'_>) -> Result<Self>;

    /// Adapter for [`struct_node`] and [`crate::fields::parse`].
    fn layout(f: &mut Fields<'_>, _: &()) -> Result<Self> {
        Self::read(f)
    }

    /// A lazy node showing this record's fields at `span`.
    fn node(name: impl Into<Cow<'static, str>>, span: Span, endian: Endian) -> Node {
        struct_node(name, span, endian, (), Self::layout)
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __record_ty {
    (u8) => { u8 };
    (u16) => { u16 };
    (u32) => { u32 };
    (u64) => { u64 };
    (i8) => { i8 };
    (i16) => { i16 };
    (i32) => { i32 };
    (i64) => { i64 };
    (ascii) => { ::std::string::String };
    (bytes) => { ::std::vec::Vec<u8> };
    (guid) => { $crate::value::Guid };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __record_size {
    (u8) => { 1u64 };
    (u16) => { 2u64 };
    (u32) => { 4u64 };
    (u64) => { 8u64 };
    (i8) => { 1u64 };
    (i16) => { 2u64 };
    (i32) => { 4u64 };
    (i64) => { 8u64 };
    (guid) => { 16u64 };
    (ascii [$n:expr]) => { ($n) as u64 };
    (bytes [$n:expr]) => { ($n) as u64 };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __record_read {
    ($f:ident, ascii [$n:expr], $label:literal) => { $f.ascii($label, ($n) as u64) };
    ($f:ident, bytes [$n:expr], $label:literal) => { $f.bytes($label, ($n) as u64) };
    ($f:ident, guid, $label:literal) => { $f.guid($label) };
    ($f:ident, $kind:ident, $label:literal) => { $f.int::<$kind>($label) };
}

/// Declares a fixed-size record. See the [module docs](crate::dsl).
#[macro_export]
macro_rules! record {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $field:ident : $kind:ident $([$len:expr])? $label:literal
                    $(. $method:ident ( $($arg:expr),* ))*
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug)]
        #[allow(dead_code)]
        $vis struct $name {
            $(pub $field: $crate::__record_ty!($kind),)*
        }

        impl $crate::dsl::Record for $name {
            #[allow(clippy::arithmetic_side_effects)]
            const SIZE: u64 = 0 $(+ $crate::__record_size!($kind $([$len])?))*;

            #[allow(unused_variables, clippy::redundant_closure_call)]
            fn read(f: &mut $crate::fields::Fields<'_>) -> $crate::error::Result<Self> {
                $(
                    let $field = $crate::__record_read!(f, $kind $([$len])?, $label)
                        $(. $method ( $($arg),* ))*
                        .emit()?;
                )*
                Ok($name { $($field,)* })
            }
        }
    };
}

/// Sequential, async access to a region: the natural way to walk chunked
/// formats. Positions are relative to the region.
pub struct Cursor<'a> {
    cx: &'a Cx,
    region: Span,
    pos: u64,
    endian: Endian,
}

impl<'a> Cursor<'a> {
    pub fn new(cx: &'a Cx, region: Span, endian: Endian) -> Self {
        Cursor {
            cx,
            region,
            pos: 0,
            endian,
        }
    }

    pub fn region(&self) -> Span {
        self.region
    }

    pub fn pos(&self) -> u64 {
        self.pos
    }

    pub fn seek(&mut self, pos: u64) {
        self.pos = pos;
    }

    pub fn skip(&mut self, n: u64) {
        self.pos = self.pos.saturating_add(n);
    }

    pub fn remaining(&self) -> u64 {
        self.region.len.saturating_sub(self.pos)
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.region.len
    }

    pub fn set_endian(&mut self, endian: Endian) {
        self.endian = endian;
    }

    /// The span of the next `len` bytes (clamped to the region).
    pub fn span(&self, len: u64) -> Span {
        self.region.sub(self.pos, len)
    }

    /// The span from `start` (relative) to the current position.
    pub fn since(&self, start: u64) -> Span {
        self.region.sub(start, self.pos.saturating_sub(start))
    }

    /// Reads and decodes a record silently, advancing past it.
    pub async fn record<R: Record>(&mut self) -> Result<(R, Span)> {
        let span = self.region.sub(self.pos, R::SIZE);
        let block = self.cx.block(span).await?;
        let value = R::read(&mut Fields::new(&block, self.endian))?;
        self.pos = self.pos.saturating_add(R::SIZE);
        Ok((value, span))
    }

    /// Reads exactly `n` bytes, advancing past them.
    pub async fn bytes(&mut self, n: u64) -> Result<Vec<u8>> {
        let span = self.region.sub(self.pos, n);
        if span.len < n {
            return Err(Diagnostic::truncated(
                Span::new(span.source, span.offset, n),
                span.len,
            ));
        }
        let data = self.cx.read(span).await?;
        self.pos = self.pos.saturating_add(n);
        Ok(data)
    }

    /// Reads up to `n` bytes without advancing.
    pub async fn peek(&self, n: u64) -> Result<Vec<u8>> {
        self.cx.read_avail(self.region.sub(self.pos, n)).await
    }

    pub async fn int<T: Prim>(&mut self) -> Result<T> {
        let data = self.bytes(to_u64(T::SIZE)).await?;
        let endian = self.endian;
        T::decode(&data, endian).ok_or_else(|| Diagnostic::internal("integer decode failed"))
    }

    pub async fn u8(&mut self) -> Result<u8> {
        self.int().await
    }

    pub async fn u16(&mut self) -> Result<u16> {
        self.int().await
    }

    pub async fn u32(&mut self) -> Result<u32> {
        self.int().await
    }

    pub async fn u64(&mut self) -> Result<u64> {
        self.int().await
    }

    /// A NUL-terminated string of at most `max` bytes; advances past the NUL.
    pub async fn cstr(&mut self, max: u64) -> Result<(String, Span)> {
        let (text, span) = self.cx.cstr(self.region.sub(self.pos, max)).await?;
        self.pos = self.pos.saturating_add(span.len);
        Ok((text, span))
    }
}
