//! Python pickles (protocol 2 and later, which start with `PROTO`).
//!
//! A pickle is a program for a small stack machine. The opcodes are listed
//! in pages with their decoded arguments, up to `STOP`. Nothing is executed.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::{ByteReader, be_uint, clip, le_uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::value::Value;

pub static FORMAT: Format = Format {
    name: "pickle",
    title: "Python pickle",
    extensions: &["pkl", "pickle", "p"],
    mime: "application/x-python-pickle",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// `PROTO n` (2..=5), a plausible next opcode, and `STOP` at the end.
fn probe(h: &Head<'_>) -> bool {
    let (Some(&0x80), Some(&proto), Some(&next)) = (h.data.first(), h.data.get(1), h.data.get(2))
    else {
        return false;
    };
    (2..=5).contains(&proto) && opcode(next).is_some() && h.tail.last() == Some(&b'.')
}

/// How an opcode's argument is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arg {
    None,
    /// Little-endian unsigned integer of this many bytes.
    Uint(u8),
    /// Little-endian signed 32-bit integer.
    Int4,
    /// Length prefix of this many bytes, then that many bytes of text.
    Text(u8),
    /// Length prefix, then raw bytes.
    Bytes(u8),
    /// Length prefix, then a little-endian two's complement integer.
    Long(u8),
    /// Big-endian IEEE double.
    Float,
    /// A newline-terminated line.
    Line,
    /// Two newline-terminated lines (module, name).
    TwoLines,
}

fn opcode(op: u8) -> Option<(&'static str, Arg)> {
    use Arg::*;
    Some(match op {
        b'(' => ("MARK", None),
        b'.' => ("STOP", None),
        b'0' => ("POP", None),
        b'1' => ("POP_MARK", None),
        b'2' => ("DUP", None),
        b'F' => ("FLOAT", Line),
        b'I' => ("INT", Line),
        b'J' => ("BININT", Int4),
        b'K' => ("BININT1", Uint(1)),
        b'L' => ("LONG", Line),
        b'M' => ("BININT2", Uint(2)),
        b'N' => ("NONE", None),
        b'P' => ("PERSID", Line),
        b'Q' => ("BINPERSID", None),
        b'R' => ("REDUCE", None),
        b'S' => ("STRING", Line),
        b'T' => ("BINSTRING", Text(4)),
        b'U' => ("SHORT_BINSTRING", Text(1)),
        b'V' => ("UNICODE", Line),
        b'X' => ("BINUNICODE", Text(4)),
        b'a' => ("APPEND", None),
        b'b' => ("BUILD", None),
        b'c' => ("GLOBAL", TwoLines),
        b'd' => ("DICT", None),
        b'}' => ("EMPTY_DICT", None),
        b'e' => ("APPENDS", None),
        b'g' => ("GET", Line),
        b'h' => ("BINGET", Uint(1)),
        b'i' => ("INST", TwoLines),
        b'j' => ("LONG_BINGET", Uint(4)),
        b'l' => ("LIST", None),
        b']' => ("EMPTY_LIST", None),
        b'o' => ("OBJ", None),
        b'p' => ("PUT", Line),
        b'q' => ("BINPUT", Uint(1)),
        b'r' => ("LONG_BINPUT", Uint(4)),
        b's' => ("SETITEM", None),
        b't' => ("TUPLE", None),
        b')' => ("EMPTY_TUPLE", None),
        b'u' => ("SETITEMS", None),
        b'G' => ("BINFLOAT", Float),
        0x80 => ("PROTO", Uint(1)),
        0x81 => ("NEWOBJ", None),
        0x82 => ("EXT1", Uint(1)),
        0x83 => ("EXT2", Uint(2)),
        0x84 => ("EXT4", Uint(4)),
        0x85 => ("TUPLE1", None),
        0x86 => ("TUPLE2", None),
        0x87 => ("TUPLE3", None),
        0x88 => ("NEWTRUE", None),
        0x89 => ("NEWFALSE", None),
        0x8a => ("LONG1", Long(1)),
        0x8b => ("LONG4", Long(4)),
        b'B' => ("BINBYTES", Bytes(4)),
        b'C' => ("SHORT_BINBYTES", Bytes(1)),
        0x8c => ("SHORT_BINUNICODE", Text(1)),
        0x8d => ("BINUNICODE8", Text(8)),
        0x8e => ("BINBYTES8", Bytes(8)),
        0x8f => ("EMPTY_SET", None),
        0x90 => ("ADDITEMS", None),
        0x91 => ("FROZENSET", None),
        0x92 => ("NEWOBJ_EX", None),
        0x93 => ("STACK_GLOBAL", None),
        0x94 => ("MEMOIZE", None),
        0x95 => ("FRAME", Uint(8)),
        0x96 => ("BYTEARRAY8", Bytes(8)),
        0x97 => ("NEXT_BUFFER", None),
        0x98 => ("READONLY_BUFFER", None),
        _ => return Option::None,
    })
}

/// Longest text or bytes argument decoded into a value.
const MAX_VALUE: u64 = 0x1000;
const MAX_LINE: u64 = 0x1000;

async fn line(r: &mut ByteReader<'_>, at: u64) -> Result<(String, u64)> {
    let mut end = at;
    loop {
        let b = r.byte(end).await?;
        end = end.saturating_add(1);
        if b == b'\n' {
            break;
        }
        if end.saturating_sub(at) > MAX_LINE {
            return Err(Diagnostic::limit("line argument longer than 4 KiB").at(r.span(at, 1)));
        }
    }
    let bytes = r
        .bytes(at, end.saturating_sub(at).saturating_sub(1))
        .await?;
    Ok((String::from_utf8_lossy(&bytes).into_owned(), end))
}

/// The argument of the opcode whose argument starts at `at`; returns its
/// value and the offset after it.
async fn argument(r: &mut ByteReader<'_>, arg: Arg, at: u64) -> Result<(Option<Value>, u64)> {
    Ok(match arg {
        Arg::None => (None, at),
        Arg::Uint(n) => {
            let v = r.le(at, n.into()).await?;
            (
                Some(Value::UInt {
                    value: v,
                    bits: n.saturating_mul(8),
                    radix: crate::value::Radix::Dec,
                }),
                at.saturating_add(n.into()),
            )
        }
        Arg::Int4 => {
            let v = r.le(at, 4).await? as u32 as i32;
            (
                Some(Value::Int {
                    value: v.into(),
                    bits: 32,
                }),
                at.saturating_add(4),
            )
        }
        Arg::Float => {
            let b = r.bytes(at, 8).await?;
            (
                Some(Value::Float(f64::from_bits(be_uint(&b)))),
                at.saturating_add(8),
            )
        }
        Arg::Text(n) | Arg::Bytes(n) | Arg::Long(n) => {
            let len = r.le(at, n.into()).await?;
            let body = at.saturating_add(n.into());
            let end = body.saturating_add(len);
            if end > r.region().len {
                return Err(Diagnostic::truncated(
                    r.span(body, len),
                    r.region().len.saturating_sub(body),
                ));
            }
            let shown = r.bytes(body, len.min(MAX_VALUE)).await?;
            let value = match arg {
                Arg::Text(_) => Value::Text(String::from_utf8_lossy(&shown).into_owned()),
                Arg::Long(_) if len <= 8 => {
                    let raw = le_uint(&shown);
                    let bits = u32::try_from(len.saturating_mul(8)).unwrap_or(64);
                    // Sign-extend from the top byte.
                    let value = if len > 0 && len < 8 && (raw >> bits.saturating_sub(1)) & 1 == 1 {
                        (raw | u64::MAX << bits) as i64
                    } else {
                        raw as i64
                    };
                    Value::Int { value, bits: 64 }
                }
                _ => Value::Bytes(shown.get(..32).unwrap_or(&shown).to_vec()),
            };
            (Some(value), end)
        }
        Arg::Line => {
            let (text, end) = line(r, at).await?;
            (Some(Value::Text(text)), end)
        }
        Arg::TwoLines => {
            let (module, mid) = line(r, at).await?;
            let (name, end) = line(r, mid).await?;
            (Some(Value::Text(format!("{module}.{name}"))), end)
        }
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut r = ByteReader::new(&cx, file);
    let proto = r.byte(1).await?;
    cx.annotate(format!("Python pickle, protocol {proto}"));
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos < file.len {
        let op = r.byte(pos).await?;
        let Some((name, arg)) = opcode(op) else {
            return Err(
                Diagnostic::malformed(format!("unknown opcode {op:#04x}")).at(file.sub(pos, 1))
            );
        };
        let (value, end) = argument(&mut r, arg, pos.saturating_add(1)).await?;
        let mut node = Node::new(name).span(file.sub(pos, end.saturating_sub(pos)));
        if let Some(v) = value {
            if let Value::Text(t) = &v
                && t.len() > 200
            {
                node = node
                    .value(Value::Text(clip(t, 200)))
                    .summary(format!("{} characters", t.chars().count()));
            } else {
                node = node.value(v);
            }
        }
        node = node.desc(format!("opcode {index} at {pos:#x}"));
        cx.push(node).await;
        index = index.saturating_add(1);
        pos = end;
        if op == b'.' {
            break;
        }
    }
    if pos < file.len {
        let rest = file.tail(pos);
        cx.emit(
            Node::new("Trailing data")
                .span(rest)
                .summary(format!("{} bytes", rest.len)),
        );
    }
    Ok(())
}
