//! Protocol Buffers messages without their schema, in the spirit of
//! `protoc --decode_raw`: every field with its number and wire type;
//! varints with their zig-zag and two's-complement readings, fixed-width
//! values as integers or floats (whichever is plausible, the other in the
//! summary), length-delimited fields as text, a nested message (when the
//! payload parses as one completely), a guessed packed array, or bytes.
//! Groups (wire types 3 and 4) are followed.
//!
//! Protobuf has no signature, and short byte strings often parse as
//! messages, so the format is never identified by content: it is chosen by
//! extension (`.pb`, `.protobuf`, `.binpb`) or by hand. Checked against
//! `protoc --encode` output (`tests/data/protobuf`).

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::wire::protobuf::{self as pb, MAX_FIELD, Payload};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::{
    hex, list, plausible_f32, plausible_f64, plural, prefix, printable, short_text, uint, widen,
};

declare_format!(pub FORMAT = "protobuf", "Protocol Buffers message (no schema)",
    ["pb", "protobuf", "binpb"], "application/x-protobuf", Probe::Never, dissect);

/// Nested messages (and groups) followed.
const MAX_DEPTH: u32 = 32;
/// Bytes of a length-delimited field read to classify it.
const SNIFF: u64 = 16 * 1024;
/// Fields scanned to decide whether a large payload is a message.
const MAX_SCAN: u64 = 1 << 16;
/// Groups open at once.
const MAX_GROUPS: usize = 64;
/// Characters of a string field shown.
const TEXT_MAX: usize = 256;

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let count = fields(&cx, input.span, 0).await?;
    cx.annotate(format!(
        "Protocol Buffers message (no schema), {}",
        plural(count, "top-level field")
    ));
    Ok(())
}

/// A nested message or group: its payload and nesting depth.
type State = (Span, u32);

async fn message(cx: Cx, (span, depth): State) -> Result<()> {
    fields(&cx, span, depth).await.map(|_| ())
}

/// Pushes a node per field of the message in `span`; returns the count.
async fn fields(cx: &Cx, span: Span, depth: u32) -> Result<u64> {
    let (pos, mut count) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let mut cur = Cursor::new(cx, span, Endian::Little);
    cur.seek(pos);
    while !cur.at_end() {
        let at = (cur.pos(), count);
        cx.mark(move || at);
        let start = cur.pos();
        let (num, payload) = pb::read_field(&mut cur).await?;
        let mut node = match payload {
            Payload::Varint(v) => varint_node(num, v),
            Payload::I64(v) => i64_node(num, v),
            Payload::I32(v) => i32_node(num, v),
            Payload::Len(body) => len_node(cx, num, body, depth).await?,
            Payload::StartGroup => {
                let inner = cur.pos();
                let end = group_end(&mut cur, num).await?;
                let body = span.sub(inner, end.saturating_sub(inner));
                let node = Node::new(label(num)).summary("SGROUP … EGROUP, group");
                if depth >= MAX_DEPTH {
                    node.diag(Diagnostic::limit("groups nested too deeply"))
                } else {
                    node.lazy(
                        crate::expander!(self::message: State),
                        (body, depth.saturating_add(1)),
                    )
                }
            }
            Payload::EndGroup => {
                return Err(
                    Diagnostic::malformed(format!("end of group {num} without its start"))
                        .at(cur.since(start)),
                );
            }
        };
        if num > MAX_FIELD {
            node = node.diag(Diagnostic::malformed("field number above 2^29 - 1"));
        }
        count = count.saturating_add(1);
        cx.progress(cur.pos(), span.len);
        cx.push(node.span(cur.since(start))).await;
    }
    Ok(count)
}

fn label(num: u64) -> String {
    format!("field {num}")
}

/// Reads up to the end of the group `num` started just before the cursor;
/// returns where its end key starts (the cursor is left after it).
async fn group_end(cur: &mut Cursor<'_>, num: u64) -> Result<u64> {
    let mut open = vec![num];
    loop {
        if cur.at_end() {
            return Err(Diagnostic::new(
                crate::error::DiagKind::Truncated,
                format!("group {num} is not closed"),
            )
            .at(cur.span(0)));
        }
        let at = cur.pos();
        let (n, payload) = pb::read_field(cur).await?;
        match payload {
            Payload::StartGroup => {
                if open.len() >= MAX_GROUPS {
                    return Err(Diagnostic::limit("groups nested too deeply").at(cur.since(at)));
                }
                open.push(n);
            }
            Payload::EndGroup => {
                if open.pop() != Some(n) {
                    return Err(
                        Diagnostic::malformed(format!("end of group {n} does not match"))
                            .at(cur.since(at)),
                    );
                }
                if open.is_empty() {
                    return Ok(at);
                }
            }
            _ => {}
        }
    }
}

fn varint_node(num: u64, v: u64) -> Node {
    let mut summary = String::from("VARINT");
    let signed = v.cast_signed();
    if signed < 0 {
        summary.push_str(&format!(", int64 {signed}"));
    }
    if v != 0 {
        summary.push_str(&format!(", sint64 {}", pb::zigzag(v)));
    }
    Node::new(label(num)).value(uint(v, 64)).summary(summary)
}

fn i64_node(num: u64, v: u64) -> Node {
    let node = Node::new(label(num));
    let signed = v.cast_signed();
    if signed < 0 && signed > -(1 << 48) {
        node.value(Value::Int {
            value: signed,
            bits: 64,
        })
        .summary(format!("I64, sfixed64; fixed64 {v:#x}"))
    } else if plausible_f64(v) {
        node.value(Value::Float(f64::from_bits(v)))
            .summary(format!("I64, double; fixed64 {v:#x}"))
    } else if v < 1 << 53 {
        node.value(uint(v, 64)).summary("I64, fixed64")
    } else {
        let x = f64::from_bits(v);
        let alt = if x.is_finite() {
            format!("; double {x:e}")
        } else {
            String::new()
        };
        node.value(hex(v, 64)).summary(format!("I64, fixed64{alt}"))
    }
}

fn i32_node(num: u64, v: u32) -> Node {
    let node = Node::new(label(num));
    let signed = v.cast_signed();
    if signed < 0 && signed > -(1 << 24) {
        node.value(Value::Int {
            value: signed.into(),
            bits: 32,
        })
        .summary(format!("I32, sfixed32; fixed32 {v:#x}"))
    } else if plausible_f32(v) {
        node.value(Value::Float(widen(f32::from_bits(v))))
            .summary(format!("I32, float; fixed32 {v:#x}"))
    } else if v < 1 << 24 {
        node.value(uint(v, 32)).summary("I32, fixed32")
    } else {
        let x = f32::from_bits(v);
        let alt = if x.is_finite() {
            format!("; float {x:e}")
        } else {
            String::new()
        };
        node.value(hex(v, 32)).summary(format!("I32, fixed32{alt}"))
    }
}

/// How the elements of a payload guessed to be a packed array are read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Packed {
    Varint,
    Float,
    Double,
}

/// Guesses whether `data` (all of a payload, or a prefix of it when `cut`)
/// is a packed array, and its first elements.
fn packed_guess(data: &[u8], cut: bool) -> Option<(Packed, String)> {
    let (words, rest) = data.as_chunks::<4>();
    if rest.is_empty() || cut {
        let bits: Vec<u32> = words.iter().map(|w| u32::from_le_bytes(*w)).collect();
        if bits.iter().any(|&b| b != 0) && bits.iter().all(|&b| b == 0 || plausible_f32(b)) {
            let values: Vec<f64> = bits.iter().map(|&b| widen(f32::from_bits(b))).collect();
            return Some((Packed::Float, list(&values, cut)));
        }
    }
    let (dwords, rest) = data.as_chunks::<8>();
    if rest.is_empty() || cut {
        let bits: Vec<u64> = dwords.iter().map(|w| u64::from_le_bytes(*w)).collect();
        if bits.iter().any(|&b| b != 0) && bits.iter().all(|&b| b == 0 || plausible_f64(b)) {
            let values: Vec<f64> = bits.iter().map(|&b| f64::from_bits(b)).collect();
            return Some((Packed::Double, list(&values, cut)));
        }
    }
    let mut at = 0usize;
    let mut values = Vec::new();
    while at < data.len() {
        match pb::varint(data, &mut at) {
            Some(v) => values.push(v),
            // A varint cut at the end of a prefix.
            None if cut && data.len().saturating_sub(at) < 10 => break,
            None => return None,
        }
    }
    (!values.is_empty()).then(|| (Packed::Varint, list(&values, cut)))
}

/// The number of fields if `data` parses completely as a message (groups
/// balanced, field numbers valid).
fn count_fields(data: &[u8]) -> Option<u64> {
    let mut at = 0usize;
    let mut n = 0u64;
    let mut open: Vec<u64> = Vec::new();
    while at < data.len() {
        let key = pb::varint(data, &mut at)?;
        let num = key >> 3;
        if num == 0 || num > MAX_FIELD {
            return None;
        }
        let fits = |end: usize| (end <= data.len()).then_some(end);
        match u8::try_from(key & 7).ok()? {
            pb::VARINT => {
                pb::varint(data, &mut at)?;
            }
            pb::I64 => at = fits(at.checked_add(8)?)?,
            pb::I32 => at = fits(at.checked_add(4)?)?,
            pb::LEN => {
                let len = usize::try_from(pb::varint(data, &mut at)?).ok()?;
                at = fits(at.checked_add(len)?)?;
            }
            pb::SGROUP => {
                if open.len() >= MAX_GROUPS {
                    return None;
                }
                open.push(num);
            }
            pb::EGROUP => {
                if open.pop()? != num {
                    return None;
                }
            }
            _ => return None,
        }
        if open.is_empty() {
            n = n.saturating_add(1);
        }
    }
    open.is_empty().then_some(n)
}

/// Like [`count_fields`], through the context for payloads too large to
/// read whole; gives up deciding (and says yes) after [`MAX_SCAN`] fields.
async fn scan_fields(cx: &Cx, body: Span) -> Result<Option<u64>> {
    let mut cur = Cursor::new(cx, body, Endian::Little);
    let mut n = 0u64;
    let mut open = 0usize;
    while !cur.at_end() && n < MAX_SCAN {
        let Ok((num, payload)) = pb::read_field(&mut cur).await else {
            return Ok(None);
        };
        if num > MAX_FIELD {
            return Ok(None);
        }
        match payload {
            Payload::StartGroup if open < MAX_GROUPS => open = open.saturating_add(1),
            Payload::StartGroup => return Ok(None),
            Payload::EndGroup if open > 0 => open = open.saturating_sub(1),
            Payload::EndGroup => return Ok(None),
            _ => {}
        }
        if open == 0 {
            n = n.saturating_add(1);
        }
    }
    Ok((open == 0 || n >= MAX_SCAN).then_some(n))
}

async fn len_node(cx: &Cx, num: u64, body: Span, depth: u32) -> Result<Node> {
    let node = Node::new(label(num));
    if body.len == 0 {
        return Ok(node.summary("LEN, empty (string, bytes or message)"));
    }
    let data = cx.read(body.sub(0, SNIFF)).await?;
    let whole = to_u64(data.len()) >= body.len;
    let fields = if depth >= MAX_DEPTH {
        None
    } else if whole {
        count_fields(&data)
    } else {
        scan_fields(cx, body).await?
    };
    let nested = (body, depth.saturating_add(1));
    let size = if whole {
        String::new()
    } else {
        format!(", {} bytes", body.len)
    };
    if printable(&data, !whole) {
        let node = node.value(Value::Text(short_text(&data, TEXT_MAX)));
        return Ok(match fields {
            Some(_) => node
                .summary(format!("LEN{size}; also parses as a message"))
                .lazy(crate::expander!(self::message: State), nested),
            None if whole && data.len() <= TEXT_MAX => node.summary("LEN"),
            None => node.summary(format!("LEN, {} bytes", body.len)),
        });
    }
    if let Some(n) = fields {
        let what = if whole {
            format!("LEN, message, {}", plural(n, "field"))
        } else {
            format!("LEN, message, {} bytes", body.len)
        };
        return Ok(node
            .summary(what)
            .lazy(crate::expander!(self::message: State), nested));
    }
    let node = node.value(prefix(&data));
    Ok(match packed_guess(&data, !whole) {
        Some((kind, values)) => {
            let what = match kind {
                Packed::Varint => "varints",
                Packed::Float => "floats",
                Packed::Double => "doubles",
            };
            node.summary(format!("LEN, {} bytes; packed {what}? {values}", body.len))
                .lazy(packed, (body, kind))
        }
        None => node.summary(format!("LEN, {} bytes", body.len)),
    })
}

/// The elements of a payload guessed to be a packed array.
async fn packed(cx: Cx, (body, kind): (Span, Packed)) -> Result<()> {
    let (pos, mut i) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let mut cur = Cursor::new(&cx, body, Endian::Little);
    cur.seek(pos);
    while !cur.at_end() {
        let at = (cur.pos(), i);
        cx.mark(move || at);
        let start = cur.pos();
        let value = match kind {
            Packed::Varint => uint(cur.uleb128().await?, 64),
            Packed::Float => Value::Float(widen(f32::from_bits(cur.u32().await?))),
            Packed::Double => Value::Float(f64::from_bits(cur.u64().await?)),
        };
        cx.push(
            Node::new(format!("[{i}]"))
                .span(cur.since(start))
                .value(value),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}
