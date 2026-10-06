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
//! Field kinds: `u8 u16 u32 u64 i8 i16 i32 i64 f32 f64`, `ascii[N]`
//! (NUL-padded text), `utf16[N]` (N code units), `bytes[N]`, `guid`. Anything after the label is a chain of
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
    (f32) => { f32 };
    (f64) => { f64 };
    (utf16) => { ::std::string::String };
    (ascii) => { ::std::string::String };
    (bytes) => { ::std::vec::Vec<u8> };
    (guid) => { $crate::value::Guid };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __record_size {
    (u8) => {
        1u64
    };
    (u16) => {
        2u64
    };
    (u32) => {
        4u64
    };
    (u64) => {
        8u64
    };
    (i8) => {
        1u64
    };
    (i16) => {
        2u64
    };
    (i32) => {
        4u64
    };
    (i64) => {
        8u64
    };
    (f32) => {
        4u64
    };
    (f64) => {
        8u64
    };
    (guid) => {
        16u64
    };
    (utf16 [$n:expr]) => {
        (($n) as u64) * 2
    };
    (ascii [$n:expr]) => {
        ($n) as u64
    };
    (bytes [$n:expr]) => {
        ($n) as u64
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __record_read {
    ($f:ident, ascii [$n:expr], $label:literal) => {
        $f.ascii($label, ($n) as u64)
    };
    ($f:ident, bytes [$n:expr], $label:literal) => {
        $f.bytes($label, ($n) as u64)
    };
    ($f:ident, guid, $label:literal) => {
        $f.guid($label)
    };
    ($f:ident, utf16 [$n:expr], $label:literal) => {
        $f.utf16($label, ($n) as u64)
    };
    ($f:ident, $kind:ident, $label:literal) => {
        $f.int::<$kind>($label)
    };
}

/// Declares a [`Format`](crate::formats::Format) static:
///
/// ```ignore
/// declare_format!(pub NES = "nes", "iNES ROM image", ["nes"], "application/x-nes-rom",
///     Probe::Magic(&[(0, b"NES\x1a")]), dissect);
/// ```
#[macro_export]
macro_rules! declare_format {
    ($vis:vis $id:ident = $name:literal, $title:literal, [$($ext:literal),* $(,)?], $mime:literal, $probe:expr, $dissect:path) => {
        $vis static $id: $crate::formats::Format = $crate::formats::Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: $probe,
            dissect: $crate::expander!($dissect: $crate::formats::Input),
        };
    };
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

/// Reads a record at `span` and emits its fields directly as children of the
/// node being expanded (for formats that are little more than a header).
/// Fields up to a truncation are still emitted.
pub async fn emit_record<R: Record>(cx: &Cx, span: Span, endian: Endian) -> Result<R> {
    let block = cx.block(span).await?;
    R::read(&mut Fields::emitting(cx, &block, endian))
}

/// Reads a record at `span` without emitting anything.
pub async fn read_record<R: Record>(cx: &Cx, span: Span, endian: Endian) -> Result<R> {
    let block = cx.block(span).await?;
    R::read(&mut Fields::new(&block, endian))
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

    /// An unsigned LEB128 value (as in DWARF, WebAssembly, DEX).
    pub async fn uleb128(&mut self) -> Result<u64> {
        let data = self.peek(10).await?;
        let (value, len) = crate::bytes::uleb128(&data)
            .ok_or_else(|| Diagnostic::malformed("invalid LEB128").at(self.span(10)))?;
        self.skip(to_u64(len));
        Ok(value)
    }

    /// A signed LEB128 value.
    pub async fn sleb128(&mut self) -> Result<i64> {
        let data = self.peek(10).await?;
        let (value, len) = crate::bytes::sleb128(&data)
            .ok_or_else(|| Diagnostic::malformed("invalid LEB128").at(self.span(10)))?;
        self.skip(to_u64(len));
        Ok(value)
    }

    /// A NUL-terminated string of at most `max` bytes; advances past the NUL.
    pub async fn cstr(&mut self, max: u64) -> Result<(String, Span)> {
        let (text, span) = self.cx.cstr(self.region.sub(self.pos, max)).await?;
        self.pos = self.pos.saturating_add(span.len);
        Ok((text, span))
    }
}

/// The path from a graph's root to the current node, for cycle and depth
/// checks in graph-shaped formats (object references, directory trees,
/// B-tree pages). Cheap to clone into expander state.
///
/// ```ignore
/// match path.enter(page_number, 64) {
///     Ok(child_path) => node.lazy(expander!(self::page: (Path, u32)), (child_path, page_number)),
///     Err(diagnostic) => node.diag(diagnostic),
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Path(std::sync::Arc<Vec<u64>>);

impl Path {
    pub fn new() -> Self {
        Path::default()
    }

    pub fn depth(&self) -> usize {
        self.0.len()
    }

    pub fn contains(&self, id: u64) -> bool {
        self.0.contains(&id)
    }

    /// The path extended by `id`, or a diagnostic if `id` is already on the
    /// path (a cycle) or the path would exceed `max_depth`.
    pub fn enter(&self, id: u64, max_depth: usize) -> Result<Path> {
        if self.contains(id) {
            return Err(Diagnostic::malformed(format!("cycle: {id:#x} refers back to an ancestor")));
        }
        if self.0.len() >= max_depth {
            return Err(Diagnostic::limit(format!("nested deeper than {max_depth}")));
        }
        let mut ids = Vec::with_capacity(self.0.len().saturating_add(1));
        ids.extend_from_slice(&self.0);
        ids.push(id);
        Ok(Path(std::sync::Arc::new(ids)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::Path;

    #[test]
    fn path_detects_cycles_and_depth() {
        let root = Path::new();
        let a = root.enter(1, 3).unwrap();
        let b = a.enter(2, 3).unwrap();
        assert!(b.enter(1, 3).is_err());
        let c = b.enter(3, 3).unwrap();
        assert!(c.enter(4, 3).is_err());
        assert_eq!(c.depth(), 3);
    }
}
