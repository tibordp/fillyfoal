//! GGUF model files (llama.cpp and friends).
//!
//! A header gives the version and the numbers of tensors and metadata
//! pairs. Typed key/value metadata follows (strings, numbers, arrays), then
//! tensor descriptors (name, shape, type, offset into the aligned data
//! section). Metadata and tensors are listed in pages; locating the tensor
//! descriptors means walking the metadata first.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::{ByteReader, clip, le_uint, size};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "gguf",
    title: "GGUF model",
    extensions: &["gguf"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[
        (0, b"GGUF\x01\x00\x00\x00"),
        (0, b"GGUF\x02\x00\x00\x00"),
        (0, b"GGUF\x03\x00\x00\x00"),
    ]),
    dissect: crate::expander!(dissect: Input),
};

const VALUE_TYPES: EnumTable = &[
    (0, "uint8"),
    (1, "int8"),
    (2, "uint16"),
    (3, "int16"),
    (4, "uint32"),
    (5, "int32"),
    (6, "float32"),
    (7, "bool"),
    (8, "string"),
    (9, "array"),
    (10, "uint64"),
    (11, "int64"),
    (12, "float64"),
];

/// ggml tensor types (`enum ggml_type`), shared by GGUF and the older GGML
/// containers.
pub(crate) const TENSOR_TYPES: EnumTable = &[
    (0, "F32"),
    (1, "F16"),
    (2, "Q4_0"),
    (3, "Q4_1"),
    (6, "Q5_0"),
    (7, "Q5_1"),
    (8, "Q8_0"),
    (9, "Q8_1"),
    (10, "Q2_K"),
    (11, "Q3_K"),
    (12, "Q4_K"),
    (13, "Q5_K"),
    (14, "Q6_K"),
    (15, "Q8_K"),
    (16, "IQ2_XXS"),
    (17, "IQ2_XS"),
    (18, "IQ3_XXS"),
    (19, "IQ1_S"),
    (20, "IQ4_NL"),
    (21, "IQ3_S"),
    (22, "IQ2_S"),
    (23, "IQ4_XS"),
    (24, "I8"),
    (25, "I16"),
    (26, "I32"),
    (27, "I64"),
    (28, "F64"),
    (29, "IQ1_M"),
    (30, "BF16"),
    (34, "TQ1_0"),
    (35, "TQ2_0"),
    (39, "MXFP4"),
];

const MAX_STRING: u64 = 1 << 20;
const MAX_DIMS: u64 = 16;

#[derive(Clone, Copy, Debug)]
struct Gguf {
    file: Span,
    /// Version 1 used 32-bit counts and lengths.
    wide: bool,
    tensors: u64,
    kvs: u64,
}

impl Gguf {
    fn len_size(&self) -> u64 {
        if self.wide { 8 } else { 4 }
    }
}

async fn string(r: &mut ByteReader<'_>, g: &Gguf, at: u64) -> Result<(String, u64)> {
    let len = r.le(at, g.len_size()).await?;
    if len > MAX_STRING {
        return Err(
            Diagnostic::limit(format!("string of {len} bytes")).at(r.span(at, g.len_size()))
        );
    }
    let body = at.saturating_add(g.len_size());
    let bytes = r.bytes(body, len).await?;
    Ok((
        String::from_utf8_lossy(&bytes).into_owned(),
        body.saturating_add(len),
    ))
}

fn scalar_size(kind: u32) -> Option<u64> {
    Some(match kind {
        0 | 1 | 7 => 1,
        2 | 3 => 2,
        4..=6 => 4,
        10..=12 => 8,
        _ => return None,
    })
}

fn scalar_value(kind: u32, bytes: &[u8]) -> Value {
    let raw = le_uint(bytes);
    let bits = u8::try_from(bytes.len().saturating_mul(8)).unwrap_or(64);
    match kind {
        0 | 2 | 4 | 10 => Value::UInt {
            value: raw,
            bits,
            radix: crate::value::Radix::Dec,
        },
        1 | 3 | 5 | 11 => Value::Int {
            value: crate::formats::util::sound::sign_extend(raw, bits),
            bits,
        },
        6 => Value::Float(f64::from(f32::from_bits(raw as u32))),
        12 => Value::Float(f64::from_bits(raw)),
        7 => Value::Bool(raw != 0),
        _ => Value::Bytes(bytes.to_vec()),
    }
}

/// Skips (or describes) the value of type `kind` at `at`; returns a short
/// value, a summary, and the end offset.
async fn value(
    r: &mut ByteReader<'_>,
    g: &Gguf,
    kind: u32,
    at: u64,
) -> Result<(Option<Value>, String, u64)> {
    if let Some(n) = scalar_size(kind) {
        let bytes = r.bytes(at, n).await?;
        return Ok((
            Some(scalar_value(kind, &bytes)),
            String::new(),
            at.saturating_add(n),
        ));
    }
    match kind {
        8 => {
            let (s, end) = string(r, g, at).await?;
            Ok((Some(Value::Text(clip(&s, 400))), String::new(), end))
        }
        9 => {
            let elem = u32::try_from(r.le(at, 4).await?).unwrap_or(u32::MAX);
            let count = r.le(at.saturating_add(4), g.len_size()).await?;
            let mut pos = at.saturating_add(4).saturating_add(g.len_size());
            let elem_name = lookup(VALUE_TYPES, elem.into()).unwrap_or("?");
            if let Some(n) = scalar_size(elem) {
                let total = count.saturating_mul(n);
                r.region().sub_exact(pos, total)?;
                pos = pos.saturating_add(total);
            } else if elem == 8 {
                for _ in 0..count {
                    r.cx().checkpoint().await;
                    let len = r.le(pos, g.len_size()).await?;
                    pos = pos.saturating_add(g.len_size()).saturating_add(len);
                    if pos > r.region().len {
                        return Err(Diagnostic::truncated(r.span(at, 1), 0));
                    }
                }
            } else {
                return Err(
                    Diagnostic::unsupported(format!("array of {elem_name}")).at(r.span(at, 4))
                );
            }
            Ok((None, format!("array of {count} {elem_name}"), pos))
        }
        _ => Err(Diagnostic::malformed(format!("value type {kind}")).at(r.span(at, 4))),
    }
}

/// Walks the metadata; returns the offset of the tensor descriptors.
async fn metadata_end(r: &mut ByteReader<'_>, g: &Gguf, start: u64) -> Result<u64> {
    let mut pos = start;
    for _ in 0..g.kvs {
        let (_, after_key) = string(r, g, pos).await?;
        let kind = u32::try_from(r.le(after_key, 4).await?).unwrap_or(u32::MAX);
        pos = value(r, g, kind, after_key.saturating_add(4)).await?.2;
        r.cx().checkpoint().await;
    }
    Ok(pos)
}

fn header_size(g: &Gguf) -> u64 {
    8u64.saturating_add(g.len_size().saturating_mul(2))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut r = ByteReader::new(&cx, file);
    let version = r.le(4, 4).await?;
    let wide = version >= 2;
    let len = if wide { 8 } else { 4 };
    let tensors = r.le(8, len).await?;
    let kvs = r.le(8u64.saturating_add(len), len).await?;
    let g = Gguf {
        file,
        wide,
        tensors,
        kvs,
    };
    let hspan = file.sub(0, header_size(&g));
    let block = cx.block(hspan).await?;
    {
        let mut f = crate::fields::Fields::emitting(&cx, &block, crate::fields::Endian::Little);
        f.ascii("Magic", 4).emit()?;
        f.u32("Version").emit()?;
        f.uword("Tensor count", wide).emit()?;
        f.uword("Metadata count", wide).emit()?;
    }
    // Architecture and name are usually among the first keys.
    let mut pos = header_size(&g);
    let mut found = Vec::new();
    for _ in 0..kvs.min(32) {
        let Ok((key, after)) = string(&mut r, &g, pos).await else {
            break;
        };
        let Ok(kind) = r.le(after, 4).await else {
            break;
        };
        let Ok((v, _, end)) = value(
            &mut r,
            &g,
            u32::try_from(kind).unwrap_or(u32::MAX),
            after.saturating_add(4),
        )
        .await
        else {
            break;
        };
        if matches!(
            key.as_str(),
            "general.architecture" | "general.name" | "general.size_label"
        ) && let Some(Value::Text(t)) = v
        {
            found.push(t);
        }
        pos = end;
    }
    let mut summary = format!("GGUF v{version}, {tensors} tensors, {kvs} metadata entries");
    if !found.is_empty() {
        summary = format!("{}, {summary}", found.join(" "));
    }
    cx.annotate(summary);
    cx.emit(
        Node::new("Metadata")
            .summary(format!("{kvs} entries"))
            .lazy(metadata, g),
    );
    cx.emit(
        Node::new("Tensors")
            .summary(format!("{tensors} tensors"))
            .lazy(tensor_infos, g),
    );
    Ok(())
}

async fn metadata(cx: Cx, g: Gguf) -> Result<()> {
    let mut r = ByteReader::new(&cx, g.file);
    let mut pos = header_size(&g);
    cx.set_count(Count::Exact(g.kvs));
    for _ in 0..g.kvs {
        let (key, after) = string(&mut r, &g, pos).await?;
        let kind = u32::try_from(r.le(after, 4).await?).unwrap_or(u32::MAX);
        let (v, summary, end) = value(&mut r, &g, kind, after.saturating_add(4)).await?;
        let span = g.file.sub(pos, end.saturating_sub(pos));
        let mut node = Node::new(clip(&key, 120)).span(span);
        if let Some(v) = v {
            node = node.value(v);
        }
        let type_name = lookup(VALUE_TYPES, kind.into()).unwrap_or("?");
        node = node.summary(if summary.is_empty() {
            type_name.to_owned()
        } else {
            summary
        });
        if kind == 9 {
            node = node.lazy(array, (g, after.saturating_add(4)));
        }
        cx.push(node).await;
        pos = end;
    }
    Ok(())
}

async fn array(cx: Cx, (g, at): (Gguf, u64)) -> Result<()> {
    let mut r = ByteReader::new(&cx, g.file);
    let elem = u32::try_from(r.le(at, 4).await?).unwrap_or(u32::MAX);
    let count = r.le(at.saturating_add(4), g.len_size()).await?;
    let mut pos = at.saturating_add(4).saturating_add(g.len_size());
    if let Some(n) = scalar_size(elem) {
        g.file.sub_exact(pos, count.saturating_mul(n))?;
    }
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let (v, _, end) = value(&mut r, &g, elem, pos).await?;
        let mut node = Node::new(format!("[{i}]")).span(g.file.sub(pos, end.saturating_sub(pos)));
        if let Some(v) = v {
            node = node.value(v);
        }
        cx.push(node).await;
        pos = end;
    }
    Ok(())
}

async fn tensor_infos(cx: Cx, g: Gguf) -> Result<()> {
    let mut r = ByteReader::new(&cx, g.file);
    let start = metadata_end(&mut r, &g, header_size(&g)).await?;
    // The alignment may be overridden by `general.alignment`.
    let alignment = alignment(&mut r, &g).await.unwrap_or(32).max(1);
    // First pass: find the end of the descriptors (start of the data).
    let mut pos = start;
    for _ in 0..g.tensors {
        let (_, after) = string(&mut r, &g, pos).await?;
        let dims = u64::from(u32::try_from(r.le(after, 4).await?).unwrap_or(u32::MAX));
        if dims > MAX_DIMS {
            return Err(
                Diagnostic::malformed(format!("{dims} dimensions")).at(g.file.sub(after, 4))
            );
        }
        pos = after
            .saturating_add(4)
            .saturating_add(dims.saturating_mul(g.len_size()))
            .saturating_add(4 + 8);
        cx.checkpoint().await;
    }
    let data_start = pos.checked_next_multiple_of(alignment).unwrap_or(u64::MAX);
    let data = g.file.tail(data_start);
    cx.emit(
        Node::new("Tensor data")
            .span(data)
            .summary(format!("{}, aligned to {alignment}", size(data.len))),
    );
    cx.set_count(Count::Exact(g.tensors.saturating_add(1)));
    let mut pos = start;
    for _ in 0..g.tensors {
        let (name, after) = string(&mut r, &g, pos).await?;
        let dims = u32::try_from(r.le(after, 4).await?).unwrap_or(u32::MAX);
        let mut shape = Vec::new();
        let mut at = after.saturating_add(4);
        for _ in 0..dims.min(16) {
            shape.push(r.le(at, g.len_size()).await?);
            at = at.saturating_add(g.len_size());
        }
        let kind = r.le(at, 4).await?;
        let offset = r.le(at.saturating_add(4), 8).await?;
        let end = at.saturating_add(12);
        let dims_text: Vec<String> = shape.iter().map(u64::to_string).collect();
        let type_name =
            lookup(TENSOR_TYPES, kind).map_or_else(|| format!("type {kind}"), str::to_owned);
        cx.push(
            Node::new(clip(&name, 160))
                .span(g.file.sub(pos, end.saturating_sub(pos)))
                .value(Value::Enum {
                    raw: kind,
                    bits: 32,
                    name: lookup(TENSOR_TYPES, kind),
                })
                .summary(format!(
                    "[{}] {type_name}, at data+{offset:#x}",
                    dims_text.join(", ")
                ))
                .target(data.sub(offset, 1)),
        )
        .await;
        pos = end;
    }
    Ok(())
}

/// `general.alignment`, if present.
async fn alignment(r: &mut ByteReader<'_>, g: &Gguf) -> Option<u64> {
    let mut pos = header_size(g);
    for _ in 0..g.kvs {
        let (key, after) = string(r, g, pos).await.ok()?;
        let kind = u32::try_from(r.le(after, 4).await.ok()?).ok()?;
        let (v, _, end) = value(r, g, kind, after.saturating_add(4)).await.ok()?;
        if key == "general.alignment"
            && let Some(Value::UInt { value, .. }) = v
        {
            return Some(value);
        }
        pos = end;
    }
    None
}
