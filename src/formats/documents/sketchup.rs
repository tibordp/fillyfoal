//! SketchUp models (`.skp`, backups `.skb`).
//!
//! A SketchUp model is an MFC `CArchive`: two Unicode `CString`s (the
//! signature "SketchUp Model" and the version, e.g. `{20.0.373}`), a few
//! bytes we do not understand, then serialized objects. MFC writes the
//! first object of each class as a new-class tag (`FFFF`, a schema number,
//! the class name length and the ASCII class name, e.g. `CVersionMap`)
//! before the object's own data; later objects of the class refer back to
//! it by index (`8000 | index`). The objects' own data is SketchUp's
//! private serialization, so the stream cannot be walked object by object.
//!
//! What is shown, all reverse-engineered or from memory and verified only
//! against our own synthetic fixture (SketchUp is not available here):
//!
//! - the header strings, and the unknown bytes before the first object;
//! - the version map, the first object: pairs of a class name (`CString`)
//!   and its version (32-bit), up to the string `End-Of-Version-Map`;
//! - the classes the model uses, found by scanning for new-class tags (so
//!   the list can miss classes or, rarely, contain a false match; per-class
//!   object counts are not knowable without the object layouts);
//! - the preview image, a PNG found by scanning the start of the model.

use crate::bytes::{to_u64, to_usize, u16_le, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Radix, Value};

const LE: Endian = Endian::Little;
/// How far into the model the preview image is looked for.
const PREVIEW_SCAN: u64 = 2 << 20;
/// Window of the class scan (plus overlap for a tag straddling windows).
const WINDOW: u64 = 64 << 10;
/// Longest class name accepted by the scan.
const MAX_CLASS: usize = 64;
/// Version map entries shown at most.
const MAX_VERSIONS: u32 = 4096;
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

declare_format!(pub SKETCHUP = "sketchup", "SketchUp model", ["skp", "skb"], "application/vnd.sketchup.skp",
    Probe::Magic(&[(0, b"\xff\xfe\xff\x0eS\0k\0e\0t\0c\0h\0U\0p\0 \0M\0o\0d\0e\0l\0")]), sketchup);

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

/// An MFC `CString` (`AfxReadStringLength`): a length byte, or `FF` and a
/// 16-bit length, or `FF FFFF` and a 32-bit length; `FF FEFF` before the
/// length marks UTF-16 characters.
async fn cstring(cur: &mut Cursor<'_>) -> Result<(String, Span)> {
    let start = cur.pos();
    let mut wide = false;
    let mut len = u64::from(cur.u8().await?);
    if len == 0xff {
        let mut w = cur.u16().await?;
        if w == 0xfffe {
            wide = true;
            len = u64::from(cur.u8().await?);
            if len == 0xff {
                w = cur.u16().await?;
            }
        }
        if len == 0xff || !wide {
            len = if w == 0xffff {
                u64::from(cur.u32().await?)
            } else {
                u64::from(w)
            };
        }
    }
    let bytes = if wide { len.saturating_mul(2) } else { len };
    if bytes > cur.remaining() {
        return Err(Diagnostic::malformed("string runs past the end").at(cur.since(start)));
    }
    let raw = cur.bytes(bytes).await?;
    let s = if wide {
        crate::text::utf16(&raw, LE)
    } else {
        crate::text::latin1(&raw)
    };
    Ok((s, cur.since(start)))
}

/// A new-class tag at `at` in `data`: `(schema, name, tag length)`.
fn class_tag(data: &[u8], at: usize) -> Option<(u16, String, usize)> {
    if u16_le(data, at)? != 0xffff {
        return None;
    }
    let schema = u16_le(data, at.checked_add(2)?)?;
    let len = usize::from(u16_le(data, at.checked_add(4)?)?);
    if !(2..=MAX_CLASS).contains(&len) {
        return None;
    }
    let start = at.checked_add(6)?;
    let name = data.get(start..start.checked_add(len)?)?;
    let ok =
        name.first() == Some(&b'C') && name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_');
    ok.then(|| (schema, crate::text::latin1(name), len.saturating_add(6)))
}

fn find(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .and_then(|p| p.checked_add(from))
}

/// The length of the PNG starting at `at` in `span`, by walking its chunks
/// up to `IEND`.
async fn png_len(cx: &Cx, span: Span, at: u64) -> Option<u64> {
    let mut pos = at.saturating_add(8);
    for _ in 0..4096 {
        let head = cx.read(span.sub_exact(pos, 8).ok()?).await.ok()?;
        let len = u64::from(u32_be(&head, 0)?);
        let end = pos.saturating_add(12).saturating_add(len);
        if end > span.len {
            return None;
        }
        pos = end;
        if head.get(4..8) == Some(b"IEND") {
            return Some(pos.saturating_sub(at));
        }
    }
    None
}

async fn sketchup(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (magic, span) = cstring(&mut cur).await?;
    cx.emit(Node::new("Signature").span(span).value(text(magic)));
    let (version, span) = cstring(&mut cur).await?;
    cx.emit(Node::new("Version").span(span).value(text(version.clone())));
    let v = version.trim_matches(|c| c == '{' || c == '}').to_owned();
    let body = cur.pos();

    // The first object (the version map) follows a few unknown bytes.
    let head = cx.read_avail(file.sub(body, 256)).await?;
    let first = (0..head.len()).find(|&i| class_tag(&head, i).is_some());
    let mut extras = Vec::new();
    match first {
        Some(skip) => {
            if skip > 0 {
                cx.emit(
                    Node::new("Unknown")
                        .span(file.sub(body, to_u64(skip)))
                        .desc("Bytes before the first object; their meaning is not known"),
                );
            }
            let at = body.saturating_add(to_u64(skip));
            if let Some((schema, name, n)) = class_tag(&head, skip) {
                cur.seek(at.saturating_add(to_u64(n)));
                if name == "CVersionMap" {
                    let start = cur.pos();
                    let mut entries = 0u32;
                    let mut ended = false;
                    // Walk it silently to find its extent; the entries are
                    // emitted on expansion.
                    while entries < MAX_VERSIONS {
                        let Ok((s, _)) = cstring(&mut cur).await else {
                            break;
                        };
                        if s == "End-Of-Version-Map" {
                            ended = true;
                            break;
                        }
                        if cur.u32().await.is_err() {
                            break;
                        }
                        entries = entries.saturating_add(1);
                    }
                    let mut node = Node::new("Version map")
                        .span(file.sub(at, cur.pos().saturating_sub(at)))
                        .summary(format!("{entries} classes, schema {schema}"))
                        .lazy(version_map, (file, at, start));
                    if !ended {
                        node = node.diag(Diagnostic::note(
                            "no End-Of-Version-Map marker where expected",
                        ));
                    }
                    extras.push(format!("{entries} versioned classes"));
                    cx.emit(node);
                }
            }
        }
        None => cx.emit(
            Node::new("Unknown")
                .span(file.sub(body, to_u64(head.len())))
                .diag(Diagnostic::note("no MFC new-class tag near the start")),
        ),
    }
    let objects = file.tail(cur.pos());
    cx.emit(
        Node::new("Classes")
            .span(objects)
            .summary("new-class tags found by scanning")
            .lazy(classes, objects),
    );

    // Preview image.
    let scan = cx
        .read_avail(file.sub(body, PREVIEW_SCAN.min(cx.limits().max_read)))
        .await?;
    if let Some(at) = find(&scan, PNG_MAGIC, 0) {
        let at = body.saturating_add(to_u64(at));
        if let Some(len) = png_len(&cx, file, at).await {
            cx.emit(
                embedded("Preview image", input.nested(file.sub(at, len)))
                    .summary(format!("PNG, {len} bytes")),
            );
            extras.push("preview".into());
        }
    }
    cx.emit(Node::new("Model data").span(objects).diag(Diagnostic::note(
        "SketchUp's object serialization is not documented; objects are not dissected",
    )));
    let extras = if extras.is_empty() {
        String::new()
    } else {
        format!(", {}", extras.join(", "))
    };
    cx.annotate(format!("SketchUp model, version {v}{extras}"));
    Ok(())
}

async fn version_map(cx: Cx, (file, tag, start): (Span, u64, u64)) -> Result<()> {
    let raw = cx.read(file.sub(tag, start.saturating_sub(tag))).await?;
    if let Some((schema, name, _)) = class_tag(&raw, 0) {
        cx.emit(
            Node::new("Class tag")
                .span(file.sub(tag, start.saturating_sub(tag)))
                .value(text(name))
                .summary(format!("new class, schema {schema}")),
        );
    }
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(start);
    let mut entries = 0u32;
    while entries < MAX_VERSIONS {
        let at = cur.pos();
        let (s, _) = cstring(&mut cur).await?;
        if s == "End-Of-Version-Map" {
            cx.push(Node::new("End marker").span(cur.since(at)).value(text(s)))
                .await;
            break;
        }
        let version = cur.u32().await?;
        cx.push(
            Node::new(s)
                .span(cur.since(at))
                .value(uint(version.into(), 32)),
        )
        .await;
        entries = entries.saturating_add(1);
    }
    Ok(())
}

async fn classes(cx: Cx, span: Span) -> Result<()> {
    cx.set_count(Count::Unknown);
    let overlap = to_u64(MAX_CLASS.saturating_add(6));
    let mut pos = cx.resume::<u64>().unwrap_or(0);
    while pos < span.len {
        let data = cx
            .read_avail(span.sub(pos, WINDOW.saturating_add(overlap)))
            .await?;
        let limit = to_usize(WINDOW).min(data.len());
        cx.progress_in(span, span.offset.saturating_add(pos));
        let mut i = 0usize;
        let mut steps = 0u32;
        while i < limit {
            let Some(hit) = find(&data, b"\xff\xff", i).filter(|&h| h < limit) else {
                break;
            };
            match class_tag(&data, hit) {
                Some((schema, name, n)) => {
                    let at = pos.saturating_add(to_u64(hit));
                    cx.mark(move || at);
                    cx.push(
                        Node::new(name)
                            .span(span.sub(at, to_u64(n)))
                            .summary(format!("schema {schema}")),
                    )
                    .await;
                    i = hit.saturating_add(n);
                }
                None => i = hit.saturating_add(1),
            }
            steps = steps.wrapping_add(1);
            if steps.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
        }
        // A tag found in the overlap was already passed: continue after it.
        let next = pos.saturating_add(to_u64(i.max(limit)));
        if limit == 0 || next >= span.len {
            break;
        }
        pos = next;
        cx.checkpoint().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_tags() {
        let data = b"\x00\xff\xff\x01\x00\x05\x00CEdgeX";
        assert_eq!(class_tag(data, 1), Some((1, "CEdge".to_owned(), 11)));
        assert_eq!(class_tag(data, 0), None);
        assert_eq!(class_tag(b"\xff\xff\x01\x00\x05\x00Xedge", 0), None);
    }
}
