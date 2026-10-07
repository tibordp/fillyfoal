//! Schema-driven binary encodings shown without their schema: Protocol
//! Buffers, FlatBuffers, Thrift (binary and compact protocols) and Cap'n
//! Proto (plain and packed). Field numbers, types and nesting come from
//! the encoding alone; where it does not say (a length-delimited protobuf
//! field, a FlatBuffers slot), the dissectors guess and say so.
//!
//! None of these encodings has a signature, so only Cap'n Proto's stream
//! framing (whose segment table must account for the whole file) is
//! identified by content; the others are reached by extension or "inspect
//! as" (`formats::by_extension`, `Session::open_as`). Formats built on them
//! with their own magic (TFLite, ONNX, Parquet, ...) keep their own
//! dissectors. The shared readers live in `util::wire`.

pub mod capnp;
pub mod flatbuffers;
pub mod protobuf;
pub mod thrift;

use crate::value::{Radix, Value};

pub(crate) fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

pub(crate) fn hex(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Hex,
    }
}

/// An `f32` as the `f64` with the same shortest decimal form.
pub(crate) fn widen(x: f32) -> f64 {
    crate::formats::util::wire::protobuf::widen(x)
}

/// Whether a 32-bit pattern reads as a float a writer would plausibly
/// store (not an integer that happens to be a denormal or a huge value).
pub(crate) fn plausible_f32(bits: u32) -> bool {
    let x = f32::from_bits(bits);
    bits != 0 && x.is_finite() && (1e-6..=1e9).contains(&x.abs())
}

/// Like [`plausible_f32`], for a 64-bit pattern.
pub(crate) fn plausible_f64(bits: u64) -> bool {
    let x = f64::from_bits(bits);
    bits != 0 && x.is_finite() && (1e-9..=1e15).contains(&x.abs())
}

/// Whether `bytes` is non-empty UTF-8 text without control characters
/// (tabs and line breaks allowed). A multi-byte character cut at the end
/// of a prefix is allowed when `cut` is set.
pub(crate) fn printable(bytes: &[u8], cut: bool) -> bool {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) if cut && e.error_len().is_none() => {
            match bytes.get(..e.valid_up_to()).map(std::str::from_utf8) {
                Some(Ok(s)) => s,
                _ => return false,
            }
        }
        Err(_) => return false,
    };
    !text.is_empty()
        && text
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
}

/// Text for display: lossy UTF-8, at most `max` characters.
pub(crate) fn short_text(bytes: &[u8], max: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    if s.chars().count() > max {
        s.chars().take(max).collect::<String>() + "…"
    } else {
        s.into_owned()
    }
}

/// `n` and a noun, pluralised ("1 field", "2 fields", "3 entries").
pub(crate) fn plural(n: u64, noun: &str) -> String {
    match (n, noun.strip_suffix('y')) {
        (1, _) => format!("1 {noun}"),
        (_, Some(stem)) => format!("{n} {stem}ies"),
        _ => format!("{n} {noun}s"),
    }
}

/// The first bytes of a blob, for a `Value::Bytes`.
pub(crate) fn prefix(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.iter().take(32).copied().collect())
}

/// Formats a few values: `[1, 2, 3, …]`.
pub(crate) fn list<T: std::fmt::Display>(values: &[T], more: bool) -> String {
    let shown: Vec<String> = values.iter().take(8).map(T::to_string).collect();
    let more = if more || values.len() > 8 { ", …" } else { "" };
    format!("[{}{more}]", shown.join(", "))
}
