//! Raster image formats (PNG lives in its own module).
//!
//! Shared helpers for the family live here: palettes, sized regions and a few
//! value constructors.

pub mod bmp;
pub mod farbfeld;
pub mod gif;
pub mod ico;
pub mod jpeg;
pub mod pcx;
pub mod psd;
pub mod qoi;
pub mod sgi;
pub mod sunras;
pub mod tga;
pub mod tiff;
mod tiff_tags;

use std::borrow::Cow;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{Radix, Value};

/// An unsigned decimal value.
pub fn uint(value: impl Into<u64>) -> Value {
    Value::UInt {
        value: value.into(),
        bits: 64,
        radix: Radix::Dec,
    }
}

/// An unsigned hexadecimal value.
pub fn hex(value: impl Into<u64>) -> Value {
    Value::UInt {
        value: value.into(),
        bits: 64,
        radix: Radix::Hex,
    }
}

/// A text value.
pub fn text(value: impl Into<String>) -> Value {
    Value::Text(value.into())
}

/// `len` bytes at `offset` within `parent`, with a truncation diagnostic if
/// the region is cut short.
pub fn region(name: impl Into<Cow<'static, str>>, parent: Span, offset: u64, len: u64) -> Node {
    let span = parent.sub(offset, len);
    let node = Node::new(name).span(span);
    if span.len < len {
        let wanted = Span::new(parent.source, parent.offset.saturating_add(offset), len);
        node.diag(Diagnostic::truncated(wanted, span.len))
    } else {
        node
    }
}

/// How palette entries are laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorOrder {
    Rgb,
    Bgr,
    /// Blue, green, red, reserved (Windows `RGBQUAD`).
    Bgrx,
    Rgba,
}

impl ColorOrder {
    pub fn size(self) -> u64 {
        match self {
            ColorOrder::Rgb | ColorOrder::Bgr => 3,
            ColorOrder::Bgrx | ColorOrder::Rgba => 4,
        }
    }

    fn rgb(self, b: &[u8]) -> (u8, u8, u8, Option<u8>) {
        let at = |i: usize| b.get(i).copied().unwrap_or(0);
        match self {
            ColorOrder::Rgb => (at(0), at(1), at(2), None),
            ColorOrder::Bgr | ColorOrder::Bgrx => (at(2), at(1), at(0), None),
            ColorOrder::Rgba => (at(0), at(1), at(2), Some(at(3))),
        }
    }
}

/// A lazy node listing the colors of a palette, paged.
pub fn palette(name: impl Into<Cow<'static, str>>, span: Span, order: ColorOrder) -> Node {
    let count = span.len.checked_div(order.size()).unwrap_or(0);
    Node::new(name)
        .span(span)
        .summary(format!("{count} colors"))
        .lazy(palette_entries, (span, order))
}

async fn palette_entries(cx: Cx, (span, order): (Span, ColorOrder)) -> Result<()> {
    let size = order.size();
    let count = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for index in 0..count {
        let entry = span.sub(index.saturating_mul(size), size);
        let bytes = cx.read(entry).await?;
        let (r, g, b, a) = order.rgb(&bytes);
        let summary = match a {
            Some(a) => format!("#{r:02x}{g:02x}{b:02x}{a:02x}"),
            None => format!("#{r:02x}{g:02x}{b:02x}"),
        };
        cx.push(
            Node::new(format!("[{index}]"))
                .span(entry)
                .value(Value::Text(summary)),
        )
        .await;
    }
    Ok(())
}

/// `width×height`.
pub fn dims(width: impl std::fmt::Display, height: impl std::fmt::Display) -> String {
    format!("{width}×{height}")
}

/// Registers bytes gathered from `parent` (e.g. segments or sub-blocks
/// joined together) as a derived source, and returns its span.
pub fn reassembled(cx: &Cx, parent: Span, transform: &'static str, data: Vec<u8>) -> Result<Span> {
    let origin = Origin { parent, transform };
    Ok(cx.add_derived(origin, data, parent.len, None)?.span)
}
