//! NumPy arrays (`.npy`) and safetensors files.
//!
//! An `.npy` file is a magic string, a version, a header length and a
//! Python dict literal (`descr`, `fortran_order`, `shape`) padded with
//! spaces, followed by the raw array data. A safetensors file is a 64-bit
//! header length, a JSON header mapping tensor names to dtype, shape and
//! byte offsets, and the tensor data.

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::datakit::{clip, size};
use crate::formats::json::{self, Json};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;
/// Largest header decoded.
const MAX_HEADER: u64 = 100 << 20;

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

/// Bytes per element of a NumPy type string such as `<f8` or `|u1`.
fn npy_itemsize(descr: &str) -> Option<u64> {
    let kind = descr.trim_start_matches(['<', '>', '|', '=']);
    let digits: String = kind
        .chars()
        .skip(1)
        .take_while(char::is_ascii_digit)
        .collect();
    let n: u64 = digits.parse().ok()?;
    // Unicode strings (`U`) count characters of 4 bytes.
    Some(if kind.starts_with('U') {
        n.saturating_mul(4)
    } else {
        n
    })
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
        let shape_text = format!("({})", dims.join(", "));
        cx.emit(Node::new("Shape").value(Value::Text(shape_text.clone())));
        summary = format!(
            "{summary}, shape {shape_text}, {} order",
            if fortran { "Fortran" } else { "C" }
        );
        let count = shape.iter().copied().fold(1u64, u64::saturating_mul);
        if let Some(item) = descr.as_deref().and_then(npy_itemsize) {
            let expected = count.saturating_mul(item);
            node = node.summary(format!("{count} elements, {}", size(expected)));
            if expected != data.len {
                node = node.diag(Diagnostic::warning(format!(
                    "expected {expected:#x} bytes of data, found {:#x}",
                    data.len
                )));
            }
        }
    }
    cx.annotate(summary);
    cx.emit(node);
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
    let header = json::parse(&bytes)
        .map_err(|e| Diagnostic::malformed(format!("header JSON: {e}")).at(header_span))?;
    let Json::Obj(members) = header else {
        return Err(Diagnostic::malformed("header is not a JSON object").at(header_span));
    };
    let data = file.tail(8u64.saturating_add(len));
    let mut tensors = Vec::new();
    let mut metadata = Vec::new();
    for (name, value) in members {
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
        "safetensors, {} tensors, {params} parameters, {}",
        tensors.len(),
        size(data.len)
    ));
    cx.emit(
        Node::new("Header")
            .span(header_span)
            .summary(format!("{} bytes of JSON", header_span.len)),
    );
    if !metadata.is_empty() {
        cx.emit(
            Node::new("Metadata")
                .summary(format!("{} entries", metadata.len()))
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
