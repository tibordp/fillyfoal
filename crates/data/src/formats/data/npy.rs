//! NumPy arrays (`.npy`) and safetensors files.
//!
//! An `.npy` file is a magic string, a version, a header length and a
//! Python dict literal (`descr`, `fortran_order`, `shape`) padded with
//! spaces, followed by the raw array data. A safetensors file is a 64-bit
//! header length, a JSON header mapping tensor names to dtype, shape and
//! byte offsets, and the tensor data.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::{clip, plural, size};
use crate::formats::util::json::{self, Json};
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;
/// Largest header decoded.
const MAX_HEADER: u64 = 100 << 20;
/// Largest structured dtype parsed.
const MAX_DESCR: usize = 64 << 10;
/// Bytes of elements read at once.
const WINDOW: u64 = 64 * 1024;

pub static NPY: Format = Format {
    name: "npy",
    title: "NumPy array",
    extensions: &["npy"],
    mime: "application/x-npy",
    probe: Probe::Magic(&[(0, b"\x93NUMPY")]),
    dissect: crate::expander!(npy: Input),
};

pub static SAFETENSORS: Format = Format {
    name: "safetensors",
    title: "safetensors tensor file",
    extensions: &["safetensors"],
    mime: "application/octet-stream",
    probe: Probe::Custom(probe_safetensors),
    dissect: crate::expander!(safetensors: Input),
};

fn probe_safetensors(h: &Head<'_>) -> bool {
    let Some(n) = u64_le(h.data, 0) else {
        return false;
    };
    n >= 2 && n < h.len && h.at(8, b"{\"")
}

/// The quoted value after `'key':` in a Python dict literal.
fn dict_entry<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let at = text.find(&format!("'{key}'"))?;
    let rest = text.get(at.saturating_add(key.len()).saturating_add(2)..)?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    Some(rest)
}

fn npy_descr(text: &str) -> Option<String> {
    let rest = dict_entry(text, "descr")?;
    let quote = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        // Structured dtype (a list); keep it whole.
        return Some(
            rest.split("'fortran_order'")
                .next()?
                .trim_end_matches([' ', ','])
                .to_owned(),
        );
    }
    rest.get(1..)?.split(quote).next().map(str::to_owned)
}

/// Whether a dtype holds Python objects (`O`, alone or as a field of a
/// structured dtype): numpy then writes the data as a pickle stream
/// (`numpy.lib.format.write_array` calls `pickle.dump`).
fn npy_has_object(descr: &str) -> bool {
    if descr.starts_with('[') {
        ["'O'", "'|O'", "\"O\"", "\"|O\""]
            .iter()
            .any(|t| descr.contains(t))
    } else {
        descr
            .trim_start_matches(['<', '>', '|', '='])
            .starts_with('O')
    }
}

fn npy_shape(text: &str) -> Option<Vec<u64>> {
    let rest = dict_entry(text, "shape")?;
    let inner = rest.strip_prefix('(')?.split(')').next()?;
    inner
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('L').parse().ok())
        .collect()
}

pub async fn npy(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 12)).await?;
    let major = head.get(6).copied().unwrap_or(0);
    let (len_size, header_len) = if major == 1 {
        (2u64, u64::from(u16_le(&head, 8).unwrap_or(0)))
    } else {
        (4u64, u64::from(u32_le(&head, 8).unwrap_or(0)))
    };
    let fixed = file.sub(0, 8u64.saturating_add(len_size));
    let block = cx.block(fixed).await?;
    {
        let mut f = Fields::emitting(&cx, &block, LE);
        f.bytes("Magic", 6).emit()?;
        f.u8("Major version").emit()?;
        f.u8("Minor version").emit()?;
        if major == 1 {
            f.u16("Header length").emit()?;
        } else {
            f.u32("Header length").emit()?;
        }
    }
    let header_span = file.sub_exact(fixed.len, header_len.min(MAX_HEADER))?;
    let bytes = cx.read(header_span).await?;
    let text = String::from_utf8_lossy(&bytes).trim_end().to_owned();
    let descr = npy_descr(&text);
    let shape = npy_shape(&text);
    let fortran = dict_entry(&text, "fortran_order").is_some_and(|v| v.starts_with("True"));
    cx.emit(
        Node::new("Header")
            .span(header_span)
            .value(Value::Text(text.clone())),
    );
    if let Some(d) = &descr {
        cx.emit(Node::new("dtype").value(Value::Text(d.clone())));
    }
    cx.emit(Node::new("Fortran order").value(Value::Bool(fortran)));
    let data = file.tail(fixed.len.saturating_add(header_len));
    let mut summary = format!(
        "NumPy array {}",
        descr.as_deref().map_or("?".to_owned(), |d| clip(d, 40))
    );
    let mut node = Node::new("Data").span(data);
    if let Some(shape) = &shape {
        let dims: Vec<String> = shape.iter().map(u64::to_string).collect();
        let shape_text = if dims.len() == 1 {
            format!("({},)", dims.join(""))
        } else {
            format!("({})", dims.join(", "))
        };
        cx.emit(Node::new("Shape").value(Value::Text(shape_text.clone())));
        summary = format!(
            "{summary}, shape {shape_text}, {} order",
            if fortran { "Fortran" } else { "C" }
        );
        let count = shape.iter().copied().fold(1u64, u64::saturating_mul);
        let dtype = descr.as_deref().and_then(Dtype::parse);
        if let Some(item) = dtype.as_ref().map(Dtype::itemsize) {
            let expected = count.saturating_mul(item);
            node = node.summary(format!(
                "{count_element}, {}",
                size(expected),
                count_element = plural(count, "element")
            ));
            if expected != data.len {
                node = node.diag(Diagnostic::warning(format!(
                    "expected {expected:#x} bytes of data, found {:#x}",
                    data.len
                )));
            }
        }
        if let Some(dtype) = dtype.filter(|d| d.itemsize() > 0) {
            node = node.lazy(
                elements,
                Elements {
                    dtype: Arc::new(dtype),
                    data,
                    shape: Arc::new(shape.clone()),
                    fortran,
                },
            );
        }
    }
    if descr.as_deref().is_some_and(npy_has_object) {
        // Object arrays are pickled: the element count says nothing about
        // the byte length, so no size check either.
        node = embedded_as("Data", input.nested(data), &super::pickle::FORMAT)
            .summary("pickled objects");
    }
    cx.annotate(summary);
    cx.emit(node);
    Ok(())
}

// ---------------------------------------------------------------------------
// Elements

/// A scalar NumPy type: kind character, size in bytes, byte order.
#[derive(Clone, Debug)]
struct Scalar {
    kind: char,
    size: u64,
    big: bool,
}

#[derive(Clone, Debug)]
struct Field {
    name: String,
    ty: Scalar,
    offset: u64,
    /// Elements of a sub-array field.
    count: u64,
}

/// The element type of an array: a scalar or a record of scalar fields.
#[derive(Clone, Debug)]
enum Dtype {
    Scalar(Scalar),
    Record(Vec<Field>, u64),
}

/// A value of the Python literal subset `descr` uses.
enum Lit {
    Str(String),
    Int(u64),
    Seq(Vec<Lit>),
}

fn skip_ws(s: &[u8], pos: &mut usize) {
    while s.get(*pos).is_some_and(u8::is_ascii_whitespace) {
        *pos = pos.saturating_add(1);
    }
}

fn parse_lit(s: &[u8], pos: &mut usize, depth: u32) -> Option<Lit> {
    skip_ws(s, pos);
    let c = *s.get(*pos)?;
    match c {
        b'[' | b'(' => {
            if depth >= 8 {
                return None;
            }
            let close = if c == b'[' { b']' } else { b')' };
            *pos = pos.saturating_add(1);
            let mut items = Vec::new();
            loop {
                skip_ws(s, pos);
                if *s.get(*pos)? == close {
                    *pos = pos.saturating_add(1);
                    return Some(Lit::Seq(items));
                }
                items.push(parse_lit(s, pos, depth.saturating_add(1))?);
                skip_ws(s, pos);
                match *s.get(*pos)? {
                    b',' => *pos = pos.saturating_add(1),
                    x if x == close => {}
                    _ => return None,
                }
            }
        }
        b'\'' | b'"' => {
            let start = pos.saturating_add(1);
            let len = s.get(start..)?.iter().position(|&b| b == c)?;
            let end = start.saturating_add(len);
            *pos = end.saturating_add(1);
            Some(Lit::Str(
                String::from_utf8_lossy(s.get(start..end)?).into_owned(),
            ))
        }
        b'0'..=b'9' => {
            let start = *pos;
            while s.get(*pos).is_some_and(u8::is_ascii_digit) {
                *pos = pos.saturating_add(1);
            }
            let digits = std::str::from_utf8(s.get(start..*pos)?).ok()?;
            if s.get(*pos) == Some(&b'L') {
                *pos = pos.saturating_add(1);
            }
            digits.parse().ok().map(Lit::Int)
        }
        _ => None,
    }
}

impl Scalar {
    /// A type string such as `<f8`, `|S3`, `<U5` or `<M8[ns]`.
    fn parse(t: &str) -> Option<Scalar> {
        let big = t.starts_with('>');
        let rest = t.trim_start_matches(['<', '>', '|', '=']);
        let kind = rest.chars().next()?;
        let digits: String = rest
            .chars()
            .skip(1)
            .take_while(char::is_ascii_digit)
            .collect();
        let n: u64 = digits.parse().ok()?;
        let size = match kind {
            'U' => n.saturating_mul(4),
            'b' | 'i' | 'u' | 'f' | 'c' | 'S' | 'a' | 'V' | 'M' | 'm' => n,
            _ => return None,
        };
        Some(Scalar { kind, size, big })
    }

    fn uint(&self, b: &[u8]) -> u64 {
        if self.big {
            crate::formats::util::datakit::be_uint(b)
        } else {
            crate::formats::util::datakit::le_uint(b)
        }
    }

    fn float(&self, b: &[u8]) -> Option<f64> {
        let r = self.uint(b);
        Some(match b.len() {
            2 => crate::formats::util::floats::f16(u16::try_from(r).ok()?),
            4 => f64::from(f32::from_bits(u32::try_from(r).ok()?)),
            8 => f64::from_bits(r),
            _ => return None,
        })
    }

    fn value(&self, b: &[u8]) -> Value {
        let raw = self.uint(b);
        let v = match (self.kind, b.len()) {
            ('b', 1) => Some(Value::Bool(raw != 0)),
            ('i' | 'M' | 'm', n @ (1 | 2 | 4 | 8)) => {
                let bits = u8::try_from(n.saturating_mul(8)).unwrap_or(64);
                let shift = 64u32.saturating_sub(u32::from(bits));
                let value = raw
                    .checked_shl(shift)
                    .and_then(|v| v.cast_signed().checked_shr(shift))
                    .unwrap_or(0);
                Some(Value::Int { value, bits })
            }
            ('u', n @ (1 | 2 | 4 | 8)) => Some(crate::formats::util::val::uint(
                raw,
                u8::try_from(n.saturating_mul(8)).unwrap_or(64),
            )),
            ('f', n) => self.float(b).map(|value| Value::Float {
                value,
                bits: u8::try_from(n.saturating_mul(8)).unwrap_or(64),
            }),
            ('c', 8 | 16) => {
                let half = b.len() / 2;
                let re = self.float(b.get(..half).unwrap_or_default());
                let im = self.float(b.get(half..).unwrap_or_default());
                match (re, im) {
                    (Some(re), Some(im)) => Some(Value::Text(if im.is_sign_negative() {
                        format!("{re}-{}j", -im)
                    } else {
                        format!("{re}+{im}j")
                    })),
                    _ => None,
                }
            }
            ('S' | 'a', _) => {
                let end = b
                    .iter()
                    .rposition(|&c| c != 0)
                    .map_or(0, |e| e.saturating_add(1));
                let bytes = b.get(..end).unwrap_or_default();
                bytes
                    .iter()
                    .all(|&c| c == b'\t' || (0x20..0x7f).contains(&c))
                    .then(|| Value::Text(crate::text::latin1(bytes)))
            }
            ('U', _) => Some(Value::Text(
                b.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| self.uint(c))
                    .take_while(|&c| c != 0)
                    .map(|c| {
                        u32::try_from(c)
                            .ok()
                            .and_then(char::from_u32)
                            .unwrap_or(char::REPLACEMENT_CHARACTER)
                    })
                    .collect(),
            )),
            _ => None,
        };
        v.unwrap_or_else(|| Value::Bytes(b.iter().take(64).copied().collect()))
    }
}

impl Dtype {
    fn parse(descr: &str) -> Option<Dtype> {
        if !descr.starts_with('[') {
            return Scalar::parse(descr).map(Dtype::Scalar);
        }
        if descr.len() > MAX_DESCR {
            return None;
        }
        let Lit::Seq(items) = parse_lit(descr.as_bytes(), &mut 0, 0)? else {
            return None;
        };
        let mut fields = Vec::new();
        let mut offset = 0u64;
        for item in items {
            let Lit::Seq(parts) = item else {
                return None;
            };
            let mut parts = parts.into_iter();
            let (Some(Lit::Str(name)), Some(Lit::Str(ty))) = (parts.next(), parts.next()) else {
                // Titles and nested records are not listed.
                return None;
            };
            let count = match parts.next() {
                Some(Lit::Seq(dims)) => dims.iter().try_fold(1u64, |a, d| match d {
                    Lit::Int(n) => Some(a.saturating_mul(*n)),
                    _ => None,
                })?,
                Some(Lit::Int(n)) => n,
                Some(Lit::Str(_)) => return None,
                None => 1,
            };
            // Object fields make the data a pickle; Scalar::parse rejects them.
            let ty = Scalar::parse(&ty)?;
            let size = ty.size.saturating_mul(count);
            fields.push(Field {
                name,
                ty,
                offset,
                count,
            });
            offset = offset.saturating_add(size);
        }
        Some(Dtype::Record(fields, offset))
    }

    fn itemsize(&self) -> u64 {
        match self {
            Dtype::Scalar(s) => s.size,
            Dtype::Record(_, n) => *n,
        }
    }
}

#[derive(Clone)]
struct Elements {
    dtype: Arc<Dtype>,
    data: Span,
    shape: Arc<Vec<u64>>,
    fortran: bool,
}

/// The index of storage element `i`: row-major, or column-major in
/// Fortran order.
fn element_name(i: u64, shape: &[u64], fortran: bool) -> String {
    if shape.is_empty() {
        return "Value".to_owned();
    }
    let mut out = vec![0u64; shape.len()];
    let mut i = i;
    let mut step = |slot: &mut u64, d: u64| {
        let d = d.max(1);
        *slot = i.checked_rem(d).unwrap_or(0);
        i = i.checked_div(d).unwrap_or(0);
    };
    if fortran {
        for (slot, &d) in out.iter_mut().zip(shape) {
            step(slot, d);
        }
    } else {
        for (slot, &d) in out.iter_mut().zip(shape).rev() {
            step(slot, d);
        }
    }
    let parts: Vec<String> = out.iter().map(u64::to_string).collect();
    format!("[{}]", parts.join(", "))
}

/// A field of a record: one value, or a sub-array shown as a list.
fn field_value(f: &Field, b: &[u8]) -> Value {
    let size = to_usize(f.ty.size);
    let at = to_usize(f.offset);
    if f.count == 1 {
        return f
            .ty
            .value(b.get(at..at.saturating_add(size)).unwrap_or_default());
    }
    let items: Vec<String> = b
        .get(at..)
        .unwrap_or_default()
        .chunks_exact(size.max(1))
        .take(to_usize(f.count.min(16)))
        .map(|c| crate::render::value(&f.ty.value(c)))
        .collect();
    Value::Text(format!(
        "[{}{}]",
        items.join(", "),
        if f.count > 16 { ", …" } else { "" }
    ))
}

/// The array's elements, in storage order.
async fn elements(cx: Cx, e: Elements) -> Result<()> {
    let size = e.dtype.itemsize();
    let total = e.shape.iter().fold(1u64, |a, &d| a.saturating_mul(d));
    let n = total.min(e.data.len.checked_div(size).unwrap_or(0));
    cx.set_count(Count::Exact(n));
    let per = WINDOW.checked_div(size).unwrap_or(1).max(1);
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < n {
        let w = per.min(n.saturating_sub(i));
        let span = e.data.sub(i.saturating_mul(size), w.saturating_mul(size));
        let data = cx.read(span).await?;
        for (j, b) in data.chunks_exact(to_usize(size)).enumerate() {
            let index = i.saturating_add(to_u64(j));
            let espan = span.sub(to_u64(j).saturating_mul(size), size);
            let node = Node::new(element_name(index, &e.shape, e.fortran)).span(espan);
            let node = match &*e.dtype {
                Dtype::Scalar(t) => node.value(t.value(b)),
                Dtype::Record(fields, _) => {
                    let preview: Vec<String> = fields
                        .iter()
                        .take(8)
                        .map(|f| format!("{}={}", f.name, crate::render::value(&field_value(f, b))))
                        .collect();
                    node.summary(clip(&preview.join(", "), 160))
                        .lazy(record_fields, (e.dtype.clone(), espan))
                }
            };
            cx.mark(move || index);
            cx.push(node).await;
        }
        i = i.saturating_add(w);
    }
    Ok(())
}

async fn record_fields(cx: Cx, (dtype, span): (Arc<Dtype>, Span)) -> Result<()> {
    let Dtype::Record(fields, _) = &*dtype else {
        return Ok(());
    };
    let data = cx.read(span).await?;
    for f in fields {
        cx.push(
            Node::new(clip(&f.name, 120))
                .span(span.sub(f.offset, f.ty.size.saturating_mul(f.count)))
                .value(field_value(f, &data)),
        )
        .await;
    }
    Ok(())
}

/// Bytes per element of a safetensors dtype.
fn st_itemsize(dtype: &str) -> Option<u64> {
    Some(match dtype {
        "BOOL" | "U8" | "I8" | "F8_E5M2" | "F8_E4M3" => 1,
        "I16" | "U16" | "F16" | "BF16" => 2,
        "I32" | "U32" | "F32" => 4,
        "I64" | "U64" | "F64" => 8,
        _ => return None,
    })
}

#[derive(Clone)]
struct Tensor {
    name: String,
    dtype: String,
    shape: Vec<u64>,
    begin: u64,
    end: u64,
}

pub async fn safetensors(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let len_span = file.sub(0, 8);
    let len = u64_le(&cx.read(len_span).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Header size").span(len_span).value(Value::UInt {
        value: len,
        bits: 64,
        radix: crate::value::Radix::Dec,
    }));
    if len > MAX_HEADER {
        return Err(Diagnostic::limit(format!("header of {len:#x} bytes")).at(len_span));
    }
    let header_span = file.sub_exact(8, len)?;
    let bytes = cx.read(header_span).await?;
    // Real headers are small, but the reference implementation accepts up
    // to 100 MB; the parse is charged by the byte and yields as it goes.
    let header = json::parse(&cx, &bytes)
        .await
        .map_err(|e| Diagnostic::malformed(format!("header JSON: {e}")).at(header_span))?;
    let Json::Obj(members) = header else {
        return Err(Diagnostic::malformed("header is not a JSON object").at(header_span));
    };
    let data = file.tail(8u64.saturating_add(len));
    let mut tensors = Vec::new();
    let mut metadata = Vec::new();
    for (i, (name, value)) in members.into_iter().enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        if name == "__metadata__" {
            if let Json::Obj(m) = value {
                metadata = m;
            }
            continue;
        }
        let offsets = value
            .get("data_offsets")
            .and_then(Json::as_array)
            .unwrap_or_default();
        tensors.push(Tensor {
            dtype: value
                .get("dtype")
                .and_then(Json::as_str)
                .unwrap_or("?")
                .to_owned(),
            shape: value
                .get("shape")
                .and_then(Json::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(Json::as_u64)
                .collect(),
            begin: offsets.first().and_then(Json::as_u64).unwrap_or(0),
            end: offsets.get(1).and_then(Json::as_u64).unwrap_or(0),
            name,
        });
    }
    let params: u64 = tensors
        .iter()
        .map(|t| t.shape.iter().copied().fold(1u64, u64::saturating_mul))
        .fold(0, u64::saturating_add);
    cx.annotate(format!(
        "safetensors, {} tensors, {params_parameter}, {}",
        tensors.len(),
        size(data.len),
        params_parameter = plural(params, "parameter")
    ));
    cx.emit(
        embedded_as(
            "Header",
            input.nested(header_span),
            &crate::formats::text::json::FORMAT,
        )
        .summary(format!("{} bytes of JSON", header_span.len)),
    );
    if !metadata.is_empty() {
        cx.emit(
            Node::new("Metadata")
                .summary(plural(metadata.len(), "entry"))
                .lazy(json_members, metadata),
        );
    }
    cx.emit(
        Node::new("Tensors")
            .span(data)
            .summary(format!("{}", tensors.len()))
            .lazy(tensor_list, (data, tensors)),
    );
    Ok(())
}

async fn json_members(cx: Cx, members: Vec<(String, Json)>) -> Result<()> {
    for (k, v) in members {
        let value = match v {
            Json::Str(s) => s,
            other => other.render(),
        };
        cx.push(Node::new(clip(&k, 120)).value(Value::Text(clip(&value, 4000))))
            .await;
    }
    Ok(())
}

async fn tensor_list(cx: Cx, (data, tensors): (Span, Vec<Tensor>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(tensors.len())));
    for t in tensors {
        let span = data.sub(t.begin, t.end.saturating_sub(t.begin));
        let dims: Vec<String> = t.shape.iter().map(u64::to_string).collect();
        let count = t.shape.iter().copied().fold(1u64, u64::saturating_mul);
        let mut node = Node::new(clip(&t.name, 160))
            .span(span)
            .value(Value::Text(t.dtype.clone()))
            .summary(format!("[{}], {}", dims.join(", "), size(span.len)));
        if let Some(item) = st_itemsize(&t.dtype)
            && count.saturating_mul(item) != t.end.saturating_sub(t.begin)
        {
            node = node.diag(Diagnostic::warning("size does not match dtype and shape"));
        }
        if t.end < t.begin || span.len < t.end.saturating_sub(t.begin) {
            node = node.diag(Diagnostic::malformed("data offsets out of range"));
        }
        cx.push(node).await;
    }
    Ok(())
}
