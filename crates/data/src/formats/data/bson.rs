//! BSON (`.bson`), MongoDB's document encoding: a document is an int32
//! byte length, typed elements (`type`, a NUL-terminated name, the value)
//! and a terminating zero; arrays are documents keyed `"0"`, `"1"`, ...
//! All numbers are little-endian. A `.bson` file is either one document
//! or, as `mongodump` writes collections, documents back to back.
//!
//! Element values shown: doubles, strings, embedded documents and arrays
//! (lazy), binary with its subtype (UUIDs formatted, MD5 in hex), ObjectId
//! (with its creation time, random value and counter), booleans, UTC
//! datetimes (milliseconds), null, regular expressions, DBPointer,
//! JavaScript code (with scope), symbols, int32/int64, replication
//! timestamps, decimal128 (raw bits and the decoded number), MinKey and
//! MaxKey, and the deprecated undefined.
//!
//! Probe (BSON has no magic): the first document's length must fit the
//! file and its elements must all decode, with known types, UTF-8 names,
//! consistent string and sub-document lengths and the terminating zero,
//! with at least one element; documents that follow must chain to exactly
//! the end of the file (checked as far as the probe window reaches).

use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::{ByteReader, hex, hex_string};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Guid, Value, lookup};

use super::valuetree as vt;

pub static FORMAT: Format = Format {
    name: "bson",
    title: "BSON document",
    extensions: &["bson"],
    mime: "application/bson",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const TYPES: EnumTable = &[
    (0x01, "double"),
    (0x02, "string"),
    (0x03, "document"),
    (0x04, "array"),
    (0x05, "binary"),
    (0x06, "undefined"),
    (0x07, "ObjectId"),
    (0x08, "boolean"),
    (0x09, "UTC datetime"),
    (0x0a, "null"),
    (0x0b, "regular expression"),
    (0x0c, "DBPointer"),
    (0x0d, "JavaScript code"),
    (0x0e, "symbol"),
    (0x0f, "JavaScript code with scope"),
    (0x10, "int32"),
    (0x11, "timestamp"),
    (0x12, "int64"),
    (0x13, "decimal128"),
    (0x7f, "MaxKey"),
    (0xff, "MinKey"),
];

const SUBTYPES: EnumTable = &[
    (0x00, "generic"),
    (0x01, "function"),
    (0x02, "old binary"),
    (0x03, "old UUID"),
    (0x04, "UUID"),
    (0x05, "MD5"),
    (0x06, "encrypted"),
    (0x07, "compressed column"),
    (0x08, "sensitive"),
    (0x09, "vector"),
];

/// The value length of an element of type `t` whose value starts with
/// `b` (`None` if unknown or `b` too short to tell).
fn value_len(t: u8, b: &[u8]) -> Option<u64> {
    let i32_at = |o: usize| -> Option<u64> {
        let v = i32::from_le_bytes(b.get(o..o.checked_add(4)?)?.try_into().ok()?);
        u64::try_from(v).ok()
    };
    let cstr = |o: usize| -> Option<u64> {
        let n = b.get(o..)?.iter().position(|&c| c == 0)?;
        u64::try_from(n).ok()?.checked_add(1)
    };
    Some(match t {
        0x01 | 0x09 | 0x11 | 0x12 => 8,
        0x02 | 0x0d | 0x0e => i32_at(0)?.checked_add(4)?,
        0x03 | 0x04 | 0x0f => i32_at(0)?,
        0x05 => i32_at(0)?.checked_add(5)?,
        0x06 | 0x0a | 0x7f | 0xff => 0,
        0x07 => 12,
        0x08 => 1,
        0x0b => {
            let a = cstr(0)?;
            a.checked_add(cstr(usize::try_from(a).ok()?)?)?
        }
        0x0c => i32_at(0)?.checked_add(16)?,
        0x10 => 4,
        0x13 => 16,
        _ => return None,
    })
}

/// Validates the document at `pos` for the probe: its end, or `None`.
/// `partial` accepts a document cut by the end of `b` if what is there
/// is valid.
fn check_doc(b: &[u8], pos: usize, depth: usize, partial: bool) -> Option<usize> {
    let len = usize::try_from(i32::from_le_bytes(
        b.get(pos..pos.checked_add(4)?)?.try_into().ok()?,
    ))
    .ok()?;
    if len < 5 {
        return None;
    }
    let end = pos.checked_add(len)?;
    if depth > 16 {
        // Deeply nested: trust the length.
        return Some(end);
    }
    let mut p = pos.checked_add(4)?;
    let last = end.checked_sub(1)?;
    while p < last {
        let Some(&t) = b.get(p) else {
            return partial.then_some(end);
        };
        let name_start = p.checked_add(1)?;
        let Some(nul) = b
            .get(name_start..last.min(b.len()))?
            .iter()
            .position(|&c| c == 0)
        else {
            return partial.then_some(end);
        };
        std::str::from_utf8(b.get(name_start..name_start.checked_add(nul)?)?).ok()?;
        let v = name_start.checked_add(nul)?.checked_add(1)?;
        let vb = b.get(v..).unwrap_or_default();
        let Some(n) = value_len(t, vb) else {
            // Unknown type, or not enough bytes to tell.
            return (TYPES.iter().any(|&(k, _)| k == u64::from(t)) && partial && vb.len() < 16)
                .then_some(end);
        };
        let vend = v.checked_add(usize::try_from(n).ok()?)?;
        if vend > last {
            return None;
        }
        if vend > b.len() {
            return partial.then_some(end);
        }
        let body = b.get(v..vend)?;
        let ok = match t {
            0x02 | 0x0d | 0x0e => {
                body.last() == Some(&0)
                    && n >= 5
                    && std::str::from_utf8(body.get(4..body.len().checked_sub(1)?)?).is_ok()
            }
            0x03 | 0x04 => check_doc(b, v, depth.checked_add(1)?, false) == Some(vend),
            0x08 => matches!(body.first(), Some(0 | 1)),
            _ => true,
        };
        if !ok {
            return None;
        }
        p = vend;
    }
    (p == last && b.get(last).is_none_or(|&z| z == 0) && (b.get(last).is_some() || partial))
        .then_some(end)
}

fn probe(h: &Head<'_>) -> bool {
    let whole = u64::try_from(h.data.len()).is_ok_and(|n| n == h.len);
    // At least one element in the first document.
    let first_len = h
        .data
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, i32::from_le_bytes);
    if first_len < 8 || u64::try_from(first_len).is_ok_and(|l| l > h.len) {
        return false;
    }
    // With the input's length unknown, a first document reaching past what
    // the probe sees is unverifiable: any text starts with a "length" that
    // fits under the bound.
    if !h.len_known && usize::try_from(first_len).is_ok_and(|l| l > h.data.len()) {
        return false;
    }
    let mut pos = 0usize;
    let mut docs = 0u32;
    loop {
        if pos == h.data.len() {
            return whole || docs > 0;
        }
        if pos.saturating_add(4) > h.data.len() {
            // A further document starts beyond what the probe can see.
            return !whole && docs > 0;
        }
        let Some(end) = check_doc(h.data, pos, 0, !whole) else {
            return false;
        };
        docs = docs.saturating_add(1);
        if end >= h.data.len() {
            return if whole {
                end == h.data.len()
            } else {
                u64::try_from(end).is_ok_and(|e| e <= h.len)
            };
        }
        pos = end;
    }
}

async fn i32_at(r: &mut ByteReader<'_>, at: u64) -> Result<i32> {
    let v = r.le(at, 4).await?;
    Ok(i32::from_le_bytes(
        u32::try_from(v).unwrap_or(0).to_le_bytes(),
    ))
}

/// The byte length of the document at `at` (checked against the region).
async fn doc_len(r: &mut ByteReader<'_>, at: u64, limit: u64) -> Result<u64> {
    let len = i32_at(r, at).await?;
    match u64::try_from(len) {
        Ok(n) if n >= 5 && n <= limit.saturating_sub(at) => Ok(n),
        _ => Err(
            Diagnostic::malformed(format!("document length {len} does not fit")).at(r.span(at, 4)),
        ),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let total = input.span.len;
    let first = doc_len(&mut r, 0, total).await?;
    if first == total {
        cx.annotate(format!(
            "BSON document, {}",
            crate::formats::util::fmt::grouped_count(total, "byte", "bytes")
        ));
        return elements(cx, (input.span, false, Path::new())).await;
    }
    cx.annotate("BSON documents (collection dump)");
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < total {
        let at = (pos, index);
        cx.mark(move || at);
        let len = doc_len(&mut r, pos, total).await?;
        let span = r.span(pos, len);
        let summary = document_summary(&mut r, pos, len).await;
        cx.progress(pos.saturating_add(len), total);
        cx.push(
            Node::new(format!("Document {index}"))
                .span(span)
                .summary(summary)
                .lazy(
                    crate::expander!(self::elements: (Span, bool, Path)),
                    (span, false, Path::new()),
                ),
        )
        .await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
    }
    Ok(())
}

/// "document, N bytes", with the `_id` when it comes first.
async fn document_summary(r: &mut ByteReader<'_>, at: u64, len: u64) -> String {
    let base = format!(
        "document, {}",
        crate::formats::util::fmt::grouped_count(len, "byte", "bytes")
    );
    let Ok(head) = r
        .bytes(at.saturating_add(4), 5.min(len.saturating_sub(4)))
        .await
    else {
        return base;
    };
    let id = match head.as_slice() {
        [0x07, b'_', b'i', b'd', 0] => r
            .bytes(at.saturating_add(9), 12)
            .await
            .ok()
            .map(|b| hex_string(&b)),
        [0x10, b'_', b'i', b'd', 0] => i32_at(r, at.saturating_add(9))
            .await
            .ok()
            .map(|v| v.to_string()),
        _ => None,
    };
    match id {
        Some(id) => format!("{base}, _id {id}"),
        None => base,
    }
}

/// The elements of the document filling `doc`.
async fn elements(cx: Cx, (doc, array, path): (Span, bool, Path)) -> Result<()> {
    let mut r = ByteReader::new(&cx, doc);
    let len = doc_len(&mut r, 0, doc.len).await?;
    if len != doc.len {
        cx.diag(Diagnostic::malformed(format!(
            "document length {len} disagrees with its {} bytes",
            doc.len
        )));
    }
    let last = len.saturating_sub(1);
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((4, 0));
    while pos < last {
        let at = (pos, index);
        cx.mark(move || at);
        let t = r.byte(pos).await?;
        let name_start = pos.saturating_add(1);
        let window = r
            .bytes(name_start, last.saturating_sub(name_start).min(0x1000))
            .await?;
        let Some(nul) = window.iter().position(|&c| c == 0) else {
            return Err(
                Diagnostic::malformed("element name is not terminated").at(r.span(name_start, 1))
            );
        };
        let name_bytes = window.get(..nul).unwrap_or_default();
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        let value = name_start.saturating_add(vt_len(nul)).saturating_add(1);
        let head = r
            .bytes(value, last.saturating_sub(value).min(0x1000))
            .await?;
        let Some(n) = value_len(t, &head) else {
            return Err(if TYPES.iter().any(|&(k, _)| k == u64::from(t)) {
                Diagnostic::malformed(format!(
                    "{} value does not fit",
                    lookup(TYPES, u64::from(t)).unwrap_or("?")
                ))
                .at(r.span(value, 1))
            } else {
                Diagnostic::malformed(format!("unknown element type {t:#04x}")).at(r.span(pos, 1))
            });
        };
        let end = value.saturating_add(n);
        if end > last {
            return Err(
                Diagnostic::malformed("element runs past the end of its document")
                    .at(r.span(pos, end.saturating_sub(pos))),
            );
        }
        let label = if array {
            format!("[{name}]")
        } else {
            vt::key_name(&name, index)
        };
        let mut node = element(&mut r, t, value, n, label, &path).await?;
        node = node.span(r.span(pos, end.saturating_sub(pos)));
        if array && name != index.to_string() {
            node = node.diag(Diagnostic::warning(format!(
                "array index {name:?} out of sequence"
            )));
        }
        if std::str::from_utf8(name_bytes).is_err() {
            node = node.diag(Diagnostic::warning("element name is not valid UTF-8"));
        }
        cx.progress(end, last);
        cx.push(node).await;
        pos = end;
        index = index.saturating_add(1);
    }
    if pos == last && r.byte(last).await? != 0 {
        cx.diag(
            Diagnostic::malformed("document does not end with a zero byte").at(r.span(last, 1)),
        );
    }
    if array {
        cx.set_count(Count::Exact(index));
    }
    Ok(())
}

fn vt_len(n: usize) -> u64 {
    crate::formats::util::datakit::len64(n)
}

/// A BSON string at `at` (int32 length including the NUL).
async fn string(r: &mut ByteReader<'_>, node: Node, at: u64) -> Result<Node> {
    let len = u64::try_from(i32_at(r, at).await?).unwrap_or(0);
    let text_len = len.saturating_sub(1);
    let data = r
        .bytes(at.saturating_add(4), text_len.min(vt::MAX_TEXT))
        .await?;
    let node = vt::text(node, &data, text_len);
    let nul = r
        .byte(at.saturating_add(4).saturating_add(text_len))
        .await?;
    Ok(if len == 0 || nul != 0 {
        node.diag(Diagnostic::malformed("string is not NUL-terminated"))
    } else {
        node
    })
}

fn sub_document(
    r: &ByteReader<'_>,
    node: Node,
    at: u64,
    len: u64,
    array: bool,
    path: &Path,
) -> Node {
    let span = r.span(at, len);
    let kind = if array { "array" } else { "document" };
    let node = node.summary(format!(
        "{kind}, {}",
        crate::formats::util::fmt::grouped_count(len, "byte", "bytes")
    ));
    if len <= 5 {
        return node;
    }
    match vt::enter(path, span.offset) {
        Ok(p) => node.lazy(
            crate::expander!(self::elements: (Span, bool, Path)),
            (span, array, p),
        ),
        Err(d) => node.diag(d),
    }
}

/// An ObjectId: 4-byte big-endian seconds, 5 random bytes, 3-byte counter.
fn object_id(node: Node, b: &[u8]) -> Node {
    let secs = b.get(..4).map_or(0, crate::formats::util::datakit::be_uint);
    node.value(Value::Text(hex_string(b))).summary(format!(
        "ObjectId, created {}",
        crate::render::value(&Value::Timestamp {
            unix_seconds: i64::try_from(secs).unwrap_or(0)
        })
    ))
}

async fn object_id_fields(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read(span).await?;
    let secs = b.get(..4).map_or(0, crate::formats::util::datakit::be_uint);
    cx.emit(
        Node::new("Timestamp")
            .span(span.sub(0, 4))
            .value(Value::Timestamp {
                unix_seconds: i64::try_from(secs).unwrap_or(0),
            }),
    );
    cx.emit(
        Node::new("Random value")
            .span(span.sub(4, 5))
            .value(Value::Bytes(b.get(4..9).unwrap_or_default().to_vec()))
            .desc("Unique to the machine and process"),
    );
    cx.emit(
        Node::new("Counter").span(span.sub(9, 3)).value(vt::uint(
            b.get(9..12)
                .map_or(0, crate::formats::util::datakit::be_uint),
            24,
        )),
    );
    Ok(())
}

/// A UUID in RFC 4122 (big-endian) byte order.
fn uuid(b: &[u8]) -> Option<Guid> {
    let be = crate::formats::util::datakit::be_uint;
    Some(Guid {
        data1: u32::try_from(be(b.get(0..4)?)).ok()?,
        data2: u16::try_from(be(b.get(4..6)?)).ok()?,
        data3: u16::try_from(be(b.get(6..8)?)).ok()?,
        data4: b.get(8..16)?.try_into().ok()?,
    })
}

/// Decimal128 (IEEE 754-2008, binary integer decimal encoding) as text.
fn decimal128(bits: u128) -> String {
    let negative = bits >> 127 != 0;
    let sign = if negative { "-" } else { "" };
    let combination = (bits >> 122) & 0x1f;
    if combination == 0x1f {
        return "NaN".to_owned();
    }
    if combination == 0x1e {
        return format!("{sign}Infinity");
    }
    let (exponent, coefficient) = if (bits >> 125) & 0b11 == 0b11 {
        // The coefficient would exceed 34 digits: non-canonical, zero.
        ((bits >> 111) & 0x3fff, 0u128)
    } else {
        (
            (bits >> 113) & 0x3fff,
            bits & ((1u128 << 113).saturating_sub(1)),
        )
    };
    let coefficient = if coefficient >= 10u128.pow(34) {
        0
    } else {
        coefficient
    };
    let exponent = i64::try_from(exponent).unwrap_or(0).saturating_sub(6176);
    vt::decimal_string(negative, &coefficient.to_string(), exponent)
}

/// A node for the value of an element of type `t` at `at` (`n` bytes).
async fn element(
    r: &mut ByteReader<'_>,
    t: u8,
    at: u64,
    n: u64,
    name: String,
    path: &Path,
) -> Result<Node> {
    let node = Node::new(name);
    Ok(match t {
        0x01 => node.value(Value::Float(f64::from_bits(r.le(at, 8).await?))),
        0x02 => string(r, node, at).await?,
        0x03 | 0x04 => sub_document(r, node, at, n, t == 0x04, path),
        0x05 => {
            let len = n.saturating_sub(5);
            let subtype = r.byte(at.saturating_add(4)).await?;
            let data_at = at.saturating_add(5);
            let kind = match lookup(SUBTYPES, u64::from(subtype)) {
                Some(s) => format!("binary ({s})"),
                None if subtype >= 0x80 => format!("binary (user-defined {subtype:#04x})"),
                None => format!("binary (subtype {subtype:#04x})"),
            };
            match subtype {
                0x03 | 0x04 if len == 16 => {
                    let b = r.bytes(data_at, 16).await?;
                    let node = node.summary(kind);
                    match uuid(&b) {
                        Some(g) if subtype == 0x04 => node.value(Value::Guid(g)),
                        _ => node.value(Value::Text(hex_string(&b))).desc(
                            "Legacy UUID: the byte order depends on the driver that wrote it (shown as stored)",
                        ),
                    }
                }
                0x05 if len == 16 => {
                    let b = r.bytes(data_at, 16).await?;
                    node.value(Value::Text(hex_string(&b))).summary(kind)
                }
                0x02 if len >= 4 => {
                    let inner = u64::try_from(i32_at(r, data_at).await?).unwrap_or(u64::MAX);
                    let data = r
                        .bytes(
                            data_at.saturating_add(4),
                            len.saturating_sub(4).min(vt::MAX_BYTES),
                        )
                        .await?;
                    let node = vt::bytes(node, &kind, data, len.saturating_sub(4));
                    if inner == len.saturating_sub(4) {
                        node
                    } else {
                        node.diag(Diagnostic::malformed(
                            "old binary subtype: inner length disagrees",
                        ))
                    }
                }
                _ => {
                    let data = r.bytes(data_at, len.min(vt::MAX_BYTES)).await?;
                    vt::bytes(node, &kind, data, len)
                }
            }
        }
        0x06 => node.summary("undefined (deprecated)"),
        0x07 => {
            let b = r.bytes(at, 12).await?;
            object_id(node, &b).lazy(
                crate::expander!(self::object_id_fields: Span),
                r.span(at, 12),
            )
        }
        0x08 => {
            let b = r.byte(at).await?;
            let node = node.value(Value::Bool(b != 0));
            if b > 1 {
                node.diag(Diagnostic::malformed(format!("boolean byte {b:#04x}")))
            } else {
                node
            }
        }
        0x09 => {
            let ms = i64::from_le_bytes(r.le(at, 8).await?.to_le_bytes());
            let secs = ms.div_euclid(1000);
            let nanos = u32::try_from(ms.rem_euclid(1000))
                .unwrap_or(0)
                .saturating_mul(1_000_000);
            node.value(Value::Timestamp { unix_seconds: secs })
                .summary(if nanos == 0 {
                    "UTC datetime".to_owned()
                } else {
                    format!("UTC datetime, {}", vt::datetime(secs, nanos))
                })
        }
        0x0a => node.summary("null"),
        0x0b => {
            let b = r.bytes(at, n.min(vt::MAX_TEXT)).await?;
            let mut parts = b.split(|&c| c == 0);
            let pattern = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
            let options = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
            node.value(Value::Text(format!("/{pattern}/{options}")))
                .summary("regular expression")
        }
        0x0c => {
            let len = u64::try_from(i32_at(r, at).await?).unwrap_or(0);
            let ns = r
                .bytes(
                    at.saturating_add(4),
                    len.saturating_sub(1).min(vt::MAX_TEXT),
                )
                .await?;
            let id = r
                .bytes(at.saturating_add(4).saturating_add(len), 12)
                .await?;
            node.value(Value::Text(String::from_utf8_lossy(&ns).into_owned()))
                .summary(format!(
                    "DBPointer (deprecated) to ObjectId {}",
                    hex_string(&id)
                ))
        }
        0x0d => string(r, node, at).await?.summary("JavaScript code"),
        0x0e => string(r, node, at).await?.summary("symbol (deprecated)"),
        0x0f => {
            let span = r.span(at, n);
            let node = node.summary("JavaScript code with scope");
            match vt::enter(path, span.offset) {
                Ok(p) => node.lazy(
                    crate::expander!(self::code_with_scope: (Span, Path)),
                    (span, p),
                ),
                Err(d) => node.diag(d),
            }
        }
        0x10 => node.value(vt::int(i64::from(i32_at(r, at).await?), 32)),
        0x11 => {
            let v = r.le(at, 8).await?;
            node.value(Value::Timestamp {
                unix_seconds: i64::try_from(v >> 32).unwrap_or(0),
            })
            .summary(format!(
                "replication timestamp, increment {}",
                v & 0xffff_ffff
            ))
        }
        0x12 => node.value(vt::int(
            i64::from_le_bytes(r.le(at, 8).await?.to_le_bytes()),
            64,
        )),
        0x13 => {
            let b = r.bytes(at, 16).await?;
            let bits = u128::from_le_bytes(b.as_slice().try_into().unwrap_or([0; 16]));
            node.value(Value::Text(decimal128(bits)))
                .summary(format!("decimal128, bits {bits:#034x}"))
        }
        0x7f => node.summary("MaxKey"),
        0xff => node.summary("MinKey"),
        _ => node
            .value(hex(t, 8))
            .diag(Diagnostic::malformed("unknown element type")),
    })
}

async fn code_with_scope(cx: Cx, (span, path): (Span, Path)) -> Result<()> {
    let mut r = ByteReader::new(&cx, span);
    let total = u64::try_from(i32_at(&mut r, 0).await?).unwrap_or(0);
    cx.emit(
        Node::new("Length")
            .span(r.span(0, 4))
            .value(vt::uint(total, 32)),
    );
    let code_len = u64::try_from(i32_at(&mut r, 4).await?).unwrap_or(0);
    let code_span = r.span(4, code_len.saturating_add(4));
    let code = string(&mut r, Node::new("Code"), 4).await?.span(code_span);
    cx.emit(code);
    let scope_at = code_len.saturating_add(8);
    let scope_len = doc_len(&mut r, scope_at, span.len).await?;
    cx.emit(
        sub_document(&r, Node::new("Scope"), scope_at, scope_len, false, &path)
            .span(r.span(scope_at, scope_len)),
    );
    if scope_at.saturating_add(scope_len) != total {
        cx.diag(Diagnostic::malformed("code with scope: lengths disagree"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::decimal128;

    #[test]
    fn decimals() {
        // 1234.5678: coefficient 12345678, exponent -4.
        let bits = (u128::from(6176u32 - 4) << 113) | 12_345_678;
        assert_eq!(decimal128(bits), "1234.5678");
        assert_eq!(decimal128(0x7c00u128 << 112), "NaN");
        assert_eq!(decimal128(0xf800u128 << 112), "-Infinity");
        assert_eq!(decimal128(u128::from(6176u32) << 113), "0");
    }
}
