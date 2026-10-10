//! Stream data: what a stream holds, its filter chain, and the node that
//! decodes it and hands it on (to the image, font, ICC, XMP or other
//! dissector it belongs to, or to the walkers of PDF's own streams: object
//! streams, cross-reference streams, Type 1 font programs, hint streams).

use std::sync::Arc;

use super::content::{self, Syntax};
use super::objects::{self, Located, ObjStmIndex, SectionKind};
use super::syntax::{Item, Obj};
use super::{DocRef, located_node};
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::plural;
use crate::formats::{content as content_node, dissect_or_data, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Radix, Value};

/// What a stream holds, from its dictionary.
pub(super) fn kind(item: &Item) -> Option<String> {
    let name = |k: &str| item.get(k).and_then(Item::name);
    let int = |k: &str| item.get(k).and_then(Item::int);
    let has = |k: &str| item.get(k).is_some();
    match (name("Type"), name("Subtype")) {
        (_, Some("Image")) => Some(image_summary(item)),
        (_, Some("Form")) => Some("form XObject".to_owned()),
        (Some("Metadata"), _) => Some("XMP metadata".to_owned()),
        (Some("EmbeddedFile"), _) => Some(
            match item
                .get("Params")
                .and_then(|p| p.get("Size"))
                .and_then(Item::int)
            {
                Some(size) => format!("embedded file, {size} bytes"),
                None => "embedded file".to_owned(),
            },
        ),
        (Some("ObjStm"), _) => {
            let n = int("N").unwrap_or(0);
            Some(format!(
                "object stream, {}",
                plural(n.unsigned_abs(), "object")
            ))
        }
        (Some("XRef"), _) => Some("cross-reference stream".to_owned()),
        (Some("CMap"), _) => Some("CMap".to_owned()),
        (_, Some("Type1C")) => Some("CFF font program".to_owned()),
        (_, Some("CIDFontType0C")) => Some("CFF CID-keyed font program".to_owned()),
        (_, Some("OpenType")) => Some("OpenType font program".to_owned()),
        (None, None) if has("Length1") && has("Length2") => Some("Type 1 font program".to_owned()),
        (None, None) if has("Length1") => Some("TrueType font program".to_owned()),
        (None, None) if has("N") && !has("First") => Some(format!(
            "ICC profile, {}",
            plural(int("N").unwrap_or(0).unsigned_abs(), "component")
        )),
        _ => None,
    }
}

/// "image 16×16, /DeviceRGB, 8-bit".
fn image_summary(item: &Item) -> String {
    let dim = |k: &str| {
        item.get(k)
            .and_then(Item::int)
            .map_or("?".to_owned(), |v| v.to_string())
    };
    let mut parts = vec![format!("image {}×{}", dim("Width"), dim("Height"))];
    if matches!(item.get("ImageMask").map(|i| &i.obj), Some(Obj::Bool(true))) {
        parts.push("stencil mask".to_owned());
    } else {
        match item.get("ColorSpace").map(|c| &c.obj) {
            Some(Obj::Name(n)) => parts.push(format!("/{n}")),
            Some(Obj::Array(items)) => {
                if let Some(n) = items.first().and_then(Item::name) {
                    parts.push(format!("/{n}"));
                }
            }
            Some(Obj::Ref(n, g)) => parts.push(format!("colour space {n} {g} R")),
            _ => {}
        }
        if let Some(bits) = item.get("BitsPerComponent").and_then(Item::int) {
            parts.push(format!("{bits}-bit"));
        }
    }
    if item.get("SMask").is_some() {
        parts.push("soft mask".to_owned());
    }
    parts.join(", ")
}

/// The filter chain with its parameters: "/FlateDecode (PNG Up
/// predictor, 4 columns)", "/CCITTFaxDecode (Group 4, 1728 columns)".
pub(super) fn filters_summary(item: &Item) -> Option<String> {
    let names = objects::filters(item);
    if names.is_empty() {
        return None;
    }
    let parts: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let parms = objects::parms(item, i);
            let get = |k: &str| parms.and_then(|p| p.get(k));
            let int = |k: &str| get(k).and_then(Item::int);
            let mut details = Vec::new();
            match name.as_str() {
                "FlateDecode" | "Fl" | "LZWDecode" | "LZW" => {
                    match int("Predictor").unwrap_or(1) {
                        p @ 10..=15 => {
                            let kind = match p {
                                10 => "None",
                                11 => "Sub",
                                12 => "Up",
                                13 => "Average",
                                14 => "Paeth",
                                _ => "optimum",
                            };
                            details.push(format!("PNG {kind} predictor"));
                        }
                        2 => details.push("TIFF predictor".to_owned()),
                        _ => {}
                    }
                    if int("Predictor").unwrap_or(1) > 1 {
                        let columns = int("Columns").unwrap_or(1);
                        details.push(plural(columns.unsigned_abs(), "column"));
                        if let Some(colors) = int("Colors").filter(|&c| c != 1) {
                            details.push(format!("{colors} colours"));
                        }
                        if let Some(bits) = int("BitsPerComponent").filter(|&b| b != 8) {
                            details.push(format!("{bits}-bit"));
                        }
                    }
                    if int("EarlyChange") == Some(0) {
                        details.push("no early change".to_owned());
                    }
                }
                "CCITTFaxDecode" | "CCF" => {
                    let k = int("K").unwrap_or(0);
                    details.push(
                        match k {
                            k if k < 0 => "Group 4",
                            0 => "Group 3, 1-D",
                            _ => "Group 3, 2-D",
                        }
                        .to_owned(),
                    );
                    details.push(format!("{} columns", int("Columns").unwrap_or(1728)));
                    if let Some(rows) = int("Rows") {
                        details.push(format!("{rows} rows"));
                    }
                    if matches!(get("BlackIs1").map(|b| &b.obj), Some(Obj::Bool(true))) {
                        details.push("black is 1".to_owned());
                    }
                    if matches!(
                        get("EncodedByteAlign").map(|b| &b.obj),
                        Some(Obj::Bool(true))
                    ) {
                        details.push("byte-aligned".to_owned());
                    }
                }
                "DCTDecode" | "DCT" => {
                    if let Some(t) = int("ColorTransform") {
                        details.push(format!("colour transform {t}"));
                    }
                }
                "JBIG2Decode" => {
                    if let Some((n, g)) = get("JBIG2Globals").and_then(Item::reference) {
                        details.push(format!("globals in {n} {g} R"));
                    }
                }
                "Crypt" => {
                    let filter = get("Name").and_then(Item::name).unwrap_or("Identity");
                    details.push(format!("/{filter}"));
                }
                _ => {}
            }
            if details.is_empty() {
                format!("/{name}")
            } else {
                format!("/{name} ({})", details.join(", "))
            }
        })
        .collect();
    Some(parts.join(" → "))
}

/// Streams without a type are usually page contents (or CMaps); forms say
/// /Form.
fn looks_like_content(dict: &Item) -> bool {
    let subtype = dict.get("Subtype").and_then(Item::name);
    let typed = dict.get("Type").is_some() || subtype.is_some();
    let other = [
        "Length1",
        "Length2",
        "N",
        "Width",
        "S",
        "FunctionType",
        "ShadingType",
        "PatternType",
    ]
    .iter()
    .any(|k| dict.get(k).is_some());
    (!typed && !other) || subtype == Some("Form")
}

/// Whether `located` is the primary hint stream of a linearized file.
fn is_hint_stream(doc: &DocRef, located: &Located) -> bool {
    let Some(lin) = &doc.linearized else {
        return false;
    };
    lin.item
        .get("H")
        .and_then(Item::array)
        .and_then(|h| h.first())
        .and_then(Item::int)
        .and_then(|h| u64::try_from(h).ok())
        .is_some_and(|h| doc.region.sub(h, 0).offset == located.whole.offset)
}

/// The nodes after a stream's dictionary entries: its data, and the
/// operators of a content stream.
pub(super) fn nodes(doc: &DocRef, located: &Located) -> Vec<Node> {
    let mut out = vec![data_node(doc, located)];
    if looks_like_content(&located.item) && !is_hint_stream(doc, located) {
        out.push(
            Node::new("Operators")
                .desc("The stream read as a content stream or CMap: operands and operators")
                .lazy(
                    crate::expander!(self::operators: (DocRef, Located)),
                    (doc.clone(), located.clone()),
                ),
        );
    }
    out
}

/// The data of a stream, decoded on expansion.
fn data_node(doc: &DocRef, located: &Located) -> Node {
    let name = "Stream data";
    let Some(data) = located.data else {
        return Node::new(name);
    };
    let item = &located.item;
    let mut summary = format!("{} bytes", data.len);
    if let Some(kind) = kind(item) {
        summary = format!("{summary}, {kind}");
    }
    if let Some(filters) = filters_summary(item) {
        summary = format!("{summary}, {filters}");
    }
    let node = Node::new(name).span(data).summary(summary.clone());
    let state = (doc.clone(), located.clone());
    if is_hint_stream(doc, located) {
        return node
            .desc("The primary hint stream: page offset and shared object hint tables")
            .lazy(
                crate::expander!(super::hints::hint_tables: (DocRef, Located)),
                state,
            );
    }
    let has = |k: &str| item.get(k).is_some();
    match item.get("Type").and_then(Item::name) {
        Some("ObjStm") => {
            return node.lazy(
                crate::expander!(self::object_stream: (DocRef, Located)),
                state,
            );
        }
        Some("XRef") => {
            return node.lazy(crate::expander!(self::xref_rows: (DocRef, Located)), state);
        }
        _ => {}
    }
    if has("Length1") && has("Length2") && !has("Subtype") && !has("Type") {
        return node.lazy(crate::expander!(self::type1_font: (DocRef, Located)), state);
    }
    if objects::is_encrypted(located, doc.security.as_ref()) {
        return node
            .summary(format!("{summary}, encrypted"))
            .lazy(crate::expander!(self::encrypted: (DocRef, Located)), state);
    }
    let expected = item
        .get("DL")
        .and_then(Item::int)
        .and_then(|n| u64::try_from(n).ok());
    match objects::codec(item) {
        Ok((codec, _)) => content_node(name, doc.input, data, codec, expected).summary(summary),
        Err(e) => node.diag(Diagnostic::unsupported(e)),
    }
}

/// An encrypted stream: decrypted (asking for the password if needed),
/// then decoded and dissected.
async fn encrypted(cx: Cx, (doc, located): (DocRef, Located)) -> Result<()> {
    let span = objects::decode(&cx, &located, doc.security.as_ref()).await?;
    cx.annotate(format!("{:#x} bytes decrypted and decoded", span.len));
    dissect_or_data(cx, doc.input.nested(span)).await
}

async fn operators(cx: Cx, (doc, located): (DocRef, Located)) -> Result<()> {
    let span = objects::decode(&cx, &located, doc.security.as_ref()).await?;
    let head = cx.read_avail(span.sub(0, 1024)).await?;
    let syntax = if crate::bytes::find(&head, b"begincmap", 0).is_some() {
        cx.annotate("CMap");
        Syntax::CMap
    } else {
        Syntax::Content
    };
    content::operators(&cx, span, syntax).await
}

/// An object stream: the pairs of numbers and offsets, then the objects.
async fn object_stream(cx: Cx, (doc, located): (DocRef, Located)) -> Result<()> {
    let decoded = objects::decode(&cx, &located, doc.security.as_ref()).await?;
    let index = objects::object_stream_index(&cx, &located, decoded).await?;
    let first = located
        .item
        .get("First")
        .and_then(Item::int)
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(0);
    let n = index.entries.len();
    cx.annotate(format!(
        "{}, {:#x} bytes decoded",
        plural(to_u64(n), "object"),
        decoded.len
    ));
    cx.set_count(Count::Exact(to_u64(n).saturating_add(1)));
    cx.push(
        Node::new("Offsets")
            .span(decoded.sub(0, first))
            .summary(format!(
                "{} of object number and offset",
                plural(to_u64(n), "pair")
            ))
            .desc("Each object's number and its offset from /First")
            .lazy(
                crate::expander!(self::object_stream_offsets: (Span, Arc<ObjStmIndex>, u64)),
                (decoded, index.clone(), first),
            ),
    )
    .await;
    for &(num, at) in &index.entries {
        let num = u32::try_from(num).unwrap_or(u32::MAX);
        let node = match objects::object_in(&cx, decoded, at).await {
            Ok(object) => located_node(&doc, format!("Object {num}"), object),
            Err(e) => Node::new(format!("Object {num}"))
                .span(decoded.sub(at, 0))
                .diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn object_stream_offsets(
    cx: Cx,
    (decoded, index, first): (Span, Arc<ObjStmIndex>, u64),
) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(index.entries.len())));
    for (&(num, at), &(start, end)) in index.entries.iter().zip(&index.pairs) {
        cx.push(
            Node::new(format!("Object {num}"))
                .span(decoded.sub(start, end.saturating_sub(start)))
                .value(Value::UInt {
                    value: at.saturating_sub(first),
                    bits: 64,
                    radix: Radix::Dec,
                })
                .summary(format!("at {at:#x} in the decoded stream"))
                .target(decoded.sub(at, 0)),
        )
        .await;
    }
    Ok(())
}

/// A cross-reference stream's rows, by subsection (`/Index`).
async fn xref_rows(cx: Cx, (doc, located): (DocRef, Located)) -> Result<()> {
    for (i, section) in doc.sections.iter().enumerate() {
        for (hybrid, s) in [(false, Some(section)), (true, section.hybrid.as_deref())] {
            let Some(s) = s else { continue };
            if s.kind != SectionKind::Stream
                || s.trailer.as_ref().is_none_or(|t| t.whole != located.whole)
            {
                continue;
            }
            if let Some((rows, [w0, w1, w2])) = s.rows {
                cx.annotate(format!(
                    "{} entr{}, {:#x} bytes decoded in rows of {w0}+{w1}+{w2} bytes (type, field 2, field 3)",
                    s.entries.len(),
                    if s.entries.len() == 1 { "y" } else { "ies" },
                    rows.len
                ));
            }
            return super::subsections_list(cx, (doc.clone(), i, hybrid)).await;
        }
    }
    // A stream no section of the chain uses (an older or orphaned one).
    let span = objects::decode(&cx, &located, None).await?;
    cx.annotate(format!(
        "{:#x} bytes decoded, not in the /Prev chain",
        span.len
    ));
    cx.emit(Node::new("Rows").span(span));
    Ok(())
}

/// A Type 1 font program (`/FontFile`): the clear-text part, the
/// eexec-encrypted private part and the trailer of zeros.
async fn type1_font(cx: Cx, (doc, located): (DocRef, Located)) -> Result<()> {
    let span = objects::decode(&cx, &located, doc.security.as_ref()).await?;
    let l1 = super::int_of(&cx, &doc, located.item.get("Length1"))
        .await
        .and_then(|n| u64::try_from(n).ok());
    let l2 = super::int_of(&cx, &doc, located.item.get("Length2"))
        .await
        .and_then(|n| u64::try_from(n).ok());
    let (Some(l1), Some(l2)) = (l1, l2) else {
        cx.annotate(format!("{:#x} bytes decoded", span.len));
        return dissect_or_data(cx, doc.input.nested(span)).await;
    };
    let clear = span.sub(0, l1);
    let encrypted = span.sub(l1, l2);
    let rest = span.tail(clear.len.saturating_add(encrypted.len));
    cx.annotate(format!(
        "Type 1 font: {} bytes of clear text, {} encrypted, {} after",
        clear.len, encrypted.len, rest.len
    ));
    cx.emit(embedded("Clear-text part", doc.input.nested(clear)));
    if !encrypted.is_empty() {
        let head = cx.read_avail(encrypted.sub(0, 4)).await?;
        let hex = head.len() == 4 && head.iter().all(u8::is_ascii_hexdigit);
        cx.emit(crate::formats::font::type1::private_node(
            doc.input, encrypted, hex,
        ));
    }
    if !rest.is_empty() {
        cx.emit(
            Node::new("Trailer")
                .span(rest)
                .summary(format!("{} bytes", rest.len))
                .desc("512 zeros and cleartomark, or nothing (Length3)"),
        );
    }
    Ok(())
}
