//! Raw numeric arrays (NIfTI voxels, HDF4 scientific datasets): elements of
//! one machine type laid out back to back, shown as a paged list of values
//! labelled by their index.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;
use std::sync::Arc;

/// An element type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Elem {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    F32,
    F64,
    /// Complex pair of `f32` (real, imaginary).
    C64,
    /// Complex pair of `f64`.
    C128,
    Rgb24,
    Rgba32,
    /// Text (one byte per element, shown as a string).
    Char,
}

impl Elem {
    pub fn size(self) -> u64 {
        match self {
            Elem::U8 | Elem::I8 | Elem::Char => 1,
            Elem::U16 | Elem::I16 => 2,
            Elem::Rgb24 => 3,
            Elem::U32 | Elem::I32 | Elem::F32 | Elem::Rgba32 => 4,
            Elem::U64 | Elem::I64 | Elem::F64 | Elem::C64 => 8,
            Elem::C128 => 16,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Elem::U8 => "uint8",
            Elem::I8 => "int8",
            Elem::U16 => "uint16",
            Elem::I16 => "int16",
            Elem::U32 => "uint32",
            Elem::I32 => "int32",
            Elem::U64 => "uint64",
            Elem::I64 => "int64",
            Elem::F32 => "float32",
            Elem::F64 => "float64",
            Elem::C64 => "complex64",
            Elem::C128 => "complex128",
            Elem::Rgb24 => "rgb24",
            Elem::Rgba32 => "rgba32",
            Elem::Char => "char",
        }
    }

    fn word<const N: usize>(b: &[u8], endian: Endian) -> Option<[u8; N]> {
        let mut a: [u8; N] = crate::bytes::array(b, 0)?;
        if endian == Endian::Big {
            a.reverse();
        }
        Some(a)
    }

    /// Decodes one element as a number, if it is one.
    pub fn number(self, b: &[u8], endian: Endian) -> Option<f64> {
        Some(match self {
            Elem::U8 | Elem::Char => f64::from(*b.first()?),
            Elem::I8 => f64::from(i8::from_le_bytes(Self::word(b, endian)?)),
            Elem::U16 => f64::from(u16::from_le_bytes(Self::word(b, endian)?)),
            Elem::I16 => f64::from(i16::from_le_bytes(Self::word(b, endian)?)),
            Elem::U32 => f64::from(u32::from_le_bytes(Self::word(b, endian)?)),
            Elem::I32 => f64::from(i32::from_le_bytes(Self::word(b, endian)?)),
            Elem::U64 => u64::from_le_bytes(Self::word(b, endian)?) as f64,
            Elem::I64 => i64::from_le_bytes(Self::word(b, endian)?) as f64,
            Elem::F32 => f64::from(f32::from_le_bytes(Self::word(b, endian)?)),
            Elem::F64 => f64::from_le_bytes(Self::word(b, endian)?),
            Elem::C64 | Elem::C128 | Elem::Rgb24 | Elem::Rgba32 => return None,
        })
    }

    /// Decodes one element as a typed value.
    pub fn value(self, b: &[u8], endian: Endian) -> Option<Value> {
        Some(match self {
            Elem::U8 | Elem::U16 | Elem::U32 => Value::UInt {
                value: self.number(b, endian)? as u64,
                bits: u8::try_from(self.size().saturating_mul(8)).unwrap_or(64),
                radix: crate::value::Radix::Dec,
            },
            Elem::U64 => Value::UInt {
                value: u64::from_le_bytes(Self::word(b, endian)?),
                bits: 64,
                radix: crate::value::Radix::Dec,
            },
            Elem::I8 | Elem::I16 | Elem::I32 => Value::Int {
                value: self.number(b, endian)? as i64,
                bits: u8::try_from(self.size().saturating_mul(8)).unwrap_or(64),
            },
            Elem::I64 => Value::Int {
                value: i64::from_le_bytes(Self::word(b, endian)?),
                bits: 64,
            },
            Elem::F32 | Elem::F64 => Value::Float(self.number(b, endian)?),
            Elem::Char => Value::Text(char::from(*b.first()?).to_string()),
            Elem::C64 => {
                let re = f32::from_le_bytes(Self::word(b, endian)?);
                let im = f32::from_le_bytes(Self::word(b.get(4..)?, endian)?);
                Value::Text(format!("{re}{im:+}i"))
            }
            Elem::C128 => {
                let re = f64::from_le_bytes(Self::word(b, endian)?);
                let im = f64::from_le_bytes(Self::word(b.get(8..)?, endian)?);
                Value::Text(format!("{re}{im:+}i"))
            }
            Elem::Rgb24 | Elem::Rgba32 => Value::Text(format!(
                "#{}",
                crate::formats::util::datakit::hex_string(
                    b.get(..crate::bytes::to_usize(self.size()))?
                )
            )),
        })
    }
}

/// A short human form of a number (integers without decimals).
pub fn num(x: f64) -> String {
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 1e15 {
        format!("{}", x as i64)
    } else if x.is_finite() && x.abs() >= 1e-4 && x.abs() < 1e7 {
        let s = format!("{x:.4}");
        s.trim_end_matches('0').trim_end_matches('.').to_owned()
    } else {
        format!("{x}")
    }
}

/// An array of `count` elements stored contiguously in `span`.
#[derive(Clone)]
pub struct Array {
    pub span: Span,
    pub elem: Elem,
    pub endian: Endian,
    /// Extent of each dimension, fastest-varying first (as NIfTI stores
    /// them); used only to label elements.
    pub dims: Arc<Vec<u64>>,
    /// Whether `dims` lists the slowest-varying dimension first (C order,
    /// HDF4) rather than the fastest first (Fortran order, NIfTI).
    pub row_major: bool,
    /// `value × slope + intercept`, shown next to the stored value.
    pub scale: Option<(f64, f64)>,
}

impl Array {
    pub fn count(&self) -> u64 {
        self.dims.iter().fold(1u64, |acc, &d| acc.saturating_mul(d))
    }

    fn label(&self, mut index: u64) -> String {
        let mut parts = vec![0u64; self.dims.len()];
        let order: Vec<usize> = if self.row_major {
            (0..self.dims.len()).rev().collect()
        } else {
            (0..self.dims.len()).collect()
        };
        for i in order {
            let d = self.dims.get(i).copied().unwrap_or(1).max(1);
            if let Some(p) = parts.get_mut(i) {
                *p = index.checked_rem(d).unwrap_or(0);
            }
            index = index.checked_div(d).unwrap_or(0);
        }
        let parts: Vec<String> = parts.iter().map(u64::to_string).collect();
        format!("[{}]", parts.join(","))
    }

    /// A lazy node listing the elements.
    pub fn node(self, name: &'static str) -> Node {
        let count = self.count();
        let len = count.saturating_mul(self.elem.size());
        let mut node = Node::new(name)
            .span(self.span)
            .summary(format!("{count} × {}", self.elem.name()));
        if self.span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(self.span.source, self.span.offset, len),
                self.span.len,
            ));
        }
        node.lazy(elements, self)
    }
}

const PAGE: u64 = 256;

async fn elements(cx: Cx, array: Array) -> Result<()> {
    let size = array.elem.size();
    let count = array
        .count()
        .min(array.span.len.checked_div(size).unwrap_or(0));
    cx.set_count(Count::Exact(count));
    let mut index = cx.resume::<u64>().unwrap_or(0);
    while index < count {
        let chunk = PAGE.min(count.saturating_sub(index));
        let at = index.saturating_mul(size);
        let bytes = cx
            .read(array.span.sub(at, chunk.saturating_mul(size)))
            .await?;
        for (n, b) in bytes.chunks_exact(crate::bytes::to_usize(size)).enumerate() {
            let i = index.saturating_add(to_u64(n));
            cx.mark(move || i);
            let mut node =
                Node::new(array.label(i)).span(array.span.sub(i.saturating_mul(size), size));
            if let Some(v) = array.elem.value(b, array.endian) {
                node = node.value(v);
            }
            if let (Some((slope, inter)), Some(x)) =
                (array.scale, array.elem.number(b, array.endian))
            {
                node = node.summary(format!("= {}", num(x * slope + inter)));
            }
            cx.push(node).await;
        }
        index = index.saturating_add(chunk);
    }
    Ok(())
}
