//! Embedded key-value stores built on copy-on-write B+trees: bbolt (etcd's
//! BoltDB) and LMDB. Both keep two meta pages, pick the newer valid one, and
//! hang their trees (buckets, named databases) off it. Shared here: how keys
//! and values are labelled and shown.

pub mod bbolt;
pub mod lmdb;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::Input;
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

/// Bytes of a key read to label its node.
const LABEL_BYTES: u64 = 96;
/// Characters (or bytes, in hex) shown in a label.
const LABEL_CHARS: usize = 48;
/// Bytes of a value read for its preview.
const PREVIEW_BYTES: u64 = 256;
/// Values at least this long are offered to format detection.
const DISSECT_MIN: u64 = 16;

pub(crate) fn uint(name: &'static str, value: u64, span: Span) -> Node {
    Node::new(name).span(span).value(Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    })
}

/// The text of `data` if it is printable UTF-8 (a character cut off at the
/// end of an incomplete read is dropped).
fn printable(data: &[u8], complete: bool) -> Option<&str> {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(e) if !complete && e.error_len().is_none() => {
            std::str::from_utf8(data.get(..e.valid_up_to())?).ok()?
        }
        Err(_) => return None,
    };
    (!text.is_empty() && !text.chars().any(char::is_control)).then_some(text)
}

/// A short label for a key: the text if printable, else hex.
pub(crate) fn label(data: &[u8], total: u64) -> String {
    let complete = to_u64(data.len()) >= total;
    if total == 0 {
        return "(empty key)".to_owned();
    }
    if let Some(text) = printable(data, complete) {
        let mut out: String = text.chars().take(LABEL_CHARS).collect();
        if !complete || text.chars().nth(LABEL_CHARS).is_some() {
            out.push('…');
        }
        return out;
    }
    let shown = LABEL_CHARS / 2;
    let mut out = String::from("0x");
    for b in data.iter().take(shown) {
        out.push_str(&format!("{b:02x}"));
    }
    if data.len() > shown || !complete {
        out.push('…');
    }
    out
}

/// A typed preview of a key or value: text if printable, else the first
/// bytes.
pub(crate) fn preview(data: &[u8], total: u64) -> Value {
    let complete = to_u64(data.len()) >= total;
    match printable(data, complete) {
        Some(text) if complete => Value::Text(text.to_owned()),
        Some(text) => Value::Text(format!("{text}…")),
        None => Value::Bytes(data.iter().take(32).copied().collect()),
    }
}

/// Reads the start of `span` and labels it.
pub(crate) async fn read_label(cx: &Cx, span: Span) -> Result<String> {
    let data = cx.read_avail(span.sub(0, LABEL_BYTES)).await?;
    Ok(label(&data, span.len))
}

/// A node for a stored value: its preview, its size, and (for binary or
/// structured text values) format detection on expansion.
pub(crate) async fn value_node(
    cx: &Cx,
    name: impl Into<std::borrow::Cow<'static, str>>,
    input: &Input,
    span: Span,
) -> Result<Node> {
    let data = cx.read_avail(span.sub(0, PREVIEW_BYTES)).await?;
    let complete = to_u64(data.len()) >= span.len;
    let text = printable(&data, complete);
    let node = Node::new(name)
        .span(span)
        .value(preview(&data, span.len))
        .summary(format!("{} bytes", span.len));
    let structured = text.is_some_and(|t| t.starts_with(['{', '[', '<']));
    if span.len >= DISSECT_MIN && (text.is_none() || structured) {
        Ok(node.lazy(crate::formats::dissect_or_data, input.nested(span)))
    } else {
        Ok(node)
    }
}
