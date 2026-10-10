//! Small helpers shared by the retro dissectors: typed values, variable-length
//! integers, NUL-terminated scans and simple text parsing.

use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Fields;
use crate::formats::util::val::{hex, uint};
use crate::node::Node;
use crate::span::Span;

/// A big-endian unsigned integer of `width` bytes (1..=8), emitted as a hex
/// field. Covers 24-bit offsets and other odd widths.
pub fn uint_be(f: &mut Fields<'_>, name: &'static str, width: u64) -> Result<u64> {
    let span = f.peek_span(width);
    let bytes = f.bytes(name, width).get()?;
    let value = bytes.iter().fold(0u64, |acc, &b| {
        acc.checked_shl(8).unwrap_or(0) | u64::from(b)
    });
    let bits = u8::try_from(width.saturating_mul(8)).unwrap_or(64);
    f.node(Node::new(name).span(span).value(hex(value, bits)));
    Ok(value)
}

/// Variable-length integer flavours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Varint {
    /// byuu's UPS/BPS encoding: little-endian groups of 7 bits, the last
    /// byte has the high bit set, and each continuation adds an offset so that
    /// every value has a single encoding.
    Beat,
    /// VCDIFF (RFC 3284): big-endian groups of 7 bits, continuation bytes have
    /// the high bit set.
    Vcdiff,
}

/// Reads one variable-length integer at the cursor.
pub async fn varint(cur: &mut Cursor<'_>, kind: Varint) -> Result<u64> {
    let start = cur.pos();
    let mut value = 0u64;
    let mut shift = 1u64;
    for _ in 0..10 {
        let byte = cur.u8().await?;
        let low = u64::from(byte & 0x7f);
        let next = match kind {
            Varint::Beat => low.checked_mul(shift).and_then(|v| value.checked_add(v)),
            Varint::Vcdiff => value.checked_mul(128).and_then(|v| v.checked_add(low)),
        };
        value = next.ok_or_else(|| {
            Diagnostic::malformed("variable-length integer overflows").at(cur.since(start))
        })?;
        match kind {
            Varint::Beat if byte & 0x80 != 0 => return Ok(value),
            Varint::Vcdiff if byte & 0x80 == 0 => return Ok(value),
            Varint::Beat => {
                shift = shift.saturating_mul(128);
                value = value
                    .checked_add(shift)
                    .ok_or_else(|| Diagnostic::malformed("variable-length integer overflows"))?;
            }
            Varint::Vcdiff => {}
        }
    }
    Err(Diagnostic::malformed("variable-length integer too long").at(cur.since(start)))
}

/// Reads a variable-length integer and emits it as a field.
pub async fn varint_field(
    cx: &Cx,
    cur: &mut Cursor<'_>,
    kind: Varint,
    name: &'static str,
) -> Result<u64> {
    let start = cur.pos();
    let value = varint(cur, kind).await?;
    cx.emit(
        Node::new(name)
            .span(cur.since(start))
            .value(uint(value, 64)),
    );
    Ok(value)
}

/// Finds the first zero byte in `region` at or after `from` (relative),
/// returning its relative position.
pub async fn find_zero(cx: &Cx, region: Span, from: u64) -> Result<Option<u64>> {
    let mut pos = from;
    while pos < region.len {
        let chunk = cx.read_avail(region.sub(pos, 4096)).await?;
        if chunk.is_empty() {
            break;
        }
        if let Some(i) = chunk.iter().position(|&b| b == 0) {
            return Ok(Some(pos.saturating_add(crate::bytes::to_u64(i))));
        }
        pos = pos.saturating_add(crate::bytes::to_u64(chunk.len()));
    }
    Ok(None)
}

/// CRC-32 of a whole region, if it can be read in one go.
pub async fn crc32_of(cx: &Cx, span: Span) -> Option<u32> {
    if span.len > cx.limits().max_read {
        return None;
    }
    let data = cx.read(span).await.ok()?;
    Some(crate::formats::util::datakit::crc32_paced(cx, &data).await)
}

/// A node for a stored CRC-32, marked valid or mismatched against `computed`.
pub fn crc_node(name: &'static str, span: Span, stored: u32, computed: Option<u32>) -> Node {
    let node = Node::new(name).span(span).value(hex(stored, 32));
    match computed {
        Some(c) if c == stored => node.summary("valid"),
        Some(c) => node.diag(Diagnostic::warning(format!(
            "CRC mismatch: computed {c:#010x}"
        ))),
        None => node.diag(Diagnostic::note(
            "not verified (region too large to read at once)",
        )),
    }
}

/// Lines of a text region: `(line, span)` pairs without line terminators.
pub fn lines(data: &[u8], region: Span) -> Vec<(String, Span)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' {
            let line = data.get(start..i).unwrap_or_default();
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            out.push((
                String::from_utf8_lossy(line).into_owned(),
                region.sub(
                    crate::bytes::to_u64(start),
                    crate::bytes::to_u64(line.len()),
                ),
            ));
            start = i.saturating_add(1);
        }
    }
    if let Some(rest) = data.get(start..)
        && !rest.is_empty()
    {
        let rest = rest.strip_suffix(b"\r").unwrap_or(rest);
        out.push((
            String::from_utf8_lossy(rest).into_owned(),
            region.sub(
                crate::bytes::to_u64(start),
                crate::bytes::to_u64(rest.len()),
            ),
        ));
    }
    out
}

/// Whether `data` is printable ASCII text (tabs and line breaks allowed).
pub fn is_ascii_text(data: &[u8]) -> bool {
    data.iter()
        .all(|&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..0x7f).contains(&b))
}

/// Trims ASCII text read from a fixed-size, space- or NUL-padded field.
pub fn clean(s: &str) -> String {
    s.trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_owned()
}
