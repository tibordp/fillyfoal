//! Legacy Visio drawings (`.vsd`, `.vss`, `.vst`): the `VisioDocument`
//! stream starts with a text signature and a version byte; Visio 2000 and
//! later then point at the trailer, a stream of pointers to the document's
//! other streams (pages, styles, fonts, colours, names, OLE objects), each
//! of which may hold pointers again. Streams are often compressed with an
//! LZSS (`Codec::Lzh` with `Method::Visio`). Layout as libvisio reads it
//! (`VisioDocument.cpp`, `VSDParser::parseMain`, `readPointer`,
//! `readPointerInfo`, `VSDInternalStream`).

use super::rec::LE;
use crate::bytes::{i32_le, u32_le};
use crate::codec::Codec;
use crate::codec::lzh::{Check, Method, Params};
use crate::cx::Cx;
use crate::dsl::{Path, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::parse;
use crate::formats::Input;
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

const SIGNATURE: &[u8] = b"Visio (TM) Drawing\r\n";
/// Pointer streams followed below the trailer.
const MAX_DEPTH: usize = 6;
/// Pointers listed per stream before assuming corruption.
const MAX_POINTERS: u64 = 65_536;

const VERSIONS: EnumTable = &[
    (1, "Visio 1.0"),
    (2, "Visio 2.0"),
    (3, "Visio 3.0"),
    (4, "Visio 4.0"),
    (5, "Visio 5.0"),
    (6, "Visio 2000"),
    (11, "Visio 2002 and later"),
];

/// Pointer and stream types (libvisio `VSDDocumentStructure.h`).
const TYPES: EnumTable = &[
    (0x0c, "foreign data"),
    (0x0d, "OLE list"),
    (0x0e, "text"),
    (0x14, "trailer"),
    (0x15, "page"),
    (0x16, "colours"),
    (0x18, "font list"),
    (0x19, "font index"),
    (0x1a, "styles"),
    (0x1d, "stencils"),
    (0x1e, "stencil page"),
    (0x1f, "OLE data"),
    (0x27, "pages"),
    (0x2c, "name list"),
    (0x2d, "name"),
    (0x32, "name list 2"),
    (0x33, "name 2"),
    (0x34, "name index"),
];

const FORMAT_DESC: &str = "Bit 1: compressed; bit 0 (pages): foreground page; high nibble: \
    0x4, 0x5 or 0x0 a blob (0x5 also holding pointers), 0x8, 0xc or 0xd a chunk stream";

record! {
    /// The fixed start of the `VisioDocument` stream.
    pub struct Header {
        signature: ascii[21] "Signature" .desc("\"Visio (TM) Drawing\\r\\n\" and a NUL"),
        _unknown: bytes[5] "Unknown",
        version: u8 "Version" .enumeration(VERSIONS),
        _pad: bytes[1] "Unknown",
        length: u32 "Document length"
            .desc("The VisioDocument stream's length (as Visio 2003-2010 write it)"),
        _rest: bytes[4] "Unknown",
    }
}

record! {
    /// A pointer to a stream (Visio 2000 and later).
    pub struct Pointer {
        kind: u32 "Type" .hex() .enumeration(TYPES),
        _unknown: u32 "Unknown",
        offset: u32 "Offset" .hex() .desc("From the start of the VisioDocument stream"),
        length: u32 "Length",
        format: u16 "Format" .hex() .desc(FORMAT_DESC),
    }
}

fn lzss() -> Codec {
    Codec::Lzh(Params::new(Method::Visio, None, Check::None))
}

fn type_name(kind: u32) -> String {
    lookup(TYPES, kind.into()).map_or_else(
        || format!("Stream type {kind:#x}"),
        crate::formats::util::fmt::capitalize,
    )
}

/// The `VisioDocument` stream.
pub async fn document(cx: &Cx, input: Input, span: Span) -> Result<()> {
    let header_span = span.sub(0, Header::SIZE);
    cx.emit(Header::node("Header", header_span, LE));
    let h = parse(cx, header_span, LE, &(), Header::layout).await?;
    if !h.signature.as_bytes().starts_with(SIGNATURE) {
        cx.diag(Diagnostic::malformed("no Visio signature").at(header_span.sub(0, 21)));
        return Ok(());
    }
    let version = lookup(VERSIONS, h.version.into()).unwrap_or("unknown version");
    cx.annotate(format!("Visio drawing ({version})"));
    if h.version != 6 && h.version != 11 {
        cx.emit(
            Node::new("Streams")
                .span(span.tail(Header::SIZE))
                .diag(Diagnostic::unsupported(format!(
                    "pointers of version {} files",
                    h.version
                ))),
        );
        return Ok(());
    }
    if h.version == 11 && h.length != 0 && u64::from(h.length) != span.len {
        cx.diag(Diagnostic::warning(format!(
            "the header gives a document length of {} bytes; the stream has {}",
            h.length, span.len
        )));
    }
    let at = span.sub(Header::SIZE, Pointer::SIZE);
    let p = parse(cx, at, LE, &(), Pointer::layout).await?;
    cx.emit(Pointer::node("Trailer pointer", at, LE));
    cx.emit(stream_node(
        "Trailer".to_owned(),
        input,
        span,
        &p,
        &Path::new(),
    ));
    Ok(())
}

/// One pointer of a pointer stream: its fields, and the stream.
async fn pointer_entry(cx: Cx, (input, doc, at, path): (Input, Span, Span, Path)) -> Result<()> {
    let p = parse(&cx, at, LE, &(), Pointer::layout).await?;
    cx.emit(Pointer::node("Pointer", at, LE));
    cx.emit(stream_node("Stream".to_owned(), input, doc, &p, &path));
    Ok(())
}

/// A node for the stream `p` points at: pointers again, or its data.
fn stream_node(name: String, input: Input, doc: Span, p: &Pointer, path: &Path) -> Node {
    let data = doc.sub(p.offset.into(), p.length.into());
    let compressed = p.format & 2 != 0;
    let mut node = Node::new(name).span(data).summary(format!(
        "{} bytes{}, format {:#06x}",
        p.length,
        if compressed { ", compressed" } else { "" },
        p.format
    ));
    if data.len < u64::from(p.length) {
        node = node.diag(Diagnostic::truncated(data, data.len));
    }
    let holds_pointers = p.format >> 4 == 5 && p.kind != 0x16 || p.kind == 0x14;
    if holds_pointers {
        match path.enter(p.offset.into(), MAX_DEPTH) {
            Ok(path) => node.lazy(
                crate::expander!(self::pointers: (Input, Span, Span, bool, Path)),
                (input, doc, data, compressed, path),
            ),
            Err(d) => node.diag(d),
        }
    } else if compressed {
        node.lazy(crate::formats::expand_content, (input, data, lzss(), None))
    } else {
        node.lazy(crate::formats::dissect_or_data, input.nested(data))
    }
}

/// A stream of pointers: after a 4-byte prefix if compressed, the offset
/// of the list (from 4 bytes before it); there the size of the order list,
/// the pointer count, a reserved word, the pointers and the order list.
async fn pointers(
    cx: Cx,
    (input, doc, data, compressed, path): (Input, Span, Span, bool, Path),
) -> Result<()> {
    let (stream, shift) = if compressed {
        let d = crate::codec::decode_span(&cx, data, &lzss(), None).await?;
        if let Some(e) = d.error {
            cx.diag(e);
        }
        cx.emit(
            Node::new("Decompressed")
                .span(d.span)
                .summary(format!("{} bytes", d.span.len)),
        );
        (d.span, 4u64)
    } else {
        (data, 0)
    };
    let head = cx.read(stream.sub(shift, 4)).await?;
    let offset = u64::from(u32_le(&head, 0).unwrap_or(0));
    cx.emit(
        Node::new("List offset")
            .span(stream.sub(shift, 4))
            .value(crate::formats::util::val::uint(offset, 32))
            .desc("Where the pointer list starts, plus 4"),
    );
    let list = offset.saturating_add(shift).saturating_sub(4);
    let info = cx.read(stream.sub_exact(list, 12)?).await?;
    let order_len = u64::from(u32_le(&info, 0).unwrap_or(0));
    let count = i32_le(&info, 4).unwrap_or(0);
    cx.emit(
        Node::new("Order list size")
            .span(stream.sub(list, 4))
            .value(crate::formats::util::val::uint(order_len, 32)),
    );
    cx.emit(
        Node::new("Pointer count")
            .span(stream.sub(list.saturating_add(4), 4))
            .value(crate::formats::util::val::int(count, 32)),
    );
    let count = u64::try_from(count).unwrap_or(0);
    if count > MAX_POINTERS {
        cx.diag(Diagnostic::limit(format!("{count} pointers")));
        return Ok(());
    }
    let first = list.saturating_add(12);
    let table = stream.sub_exact(first, count.saturating_mul(Pointer::SIZE))?;
    cx.set_count(Count::AtLeast(count));
    for i in 0..count {
        let at = table.sub(i.saturating_mul(Pointer::SIZE), Pointer::SIZE);
        let p = parse(&cx, at, LE, &(), Pointer::layout).await?;
        let node = if p.kind == 0 {
            Pointer::node(format!("Pointer {i}"), at, LE).summary("unused (type 0)")
        } else {
            Node::new(type_name(p.kind))
                .span(at)
                .summary(format!(
                    "{} bytes at {:#x}{}",
                    p.length,
                    p.offset,
                    if p.format & 2 != 0 {
                        ", compressed"
                    } else {
                        ""
                    }
                ))
                .lazy(
                    crate::expander!(self::pointer_entry: (Input, Span, Span, Path)),
                    (input, doc, at, path.clone()),
                )
        };
        cx.push(node).await;
    }
    if order_len > 1 {
        let order = stream.sub(first.saturating_add(table.len), order_len.saturating_mul(4));
        cx.push(
            Node::new("Order")
                .span(order)
                .summary(format!("{order_len} pointer indices"))
                .desc("The order in which the pointers are processed"),
        )
        .await;
    }
    Ok(())
}
