//! gzip (RFC 1952).
//!
//! The top level shows the header and the trailer (read from the end of the
//! file, which gives the original size without decompressing). The content is
//! decompressed only when expanded, then dissected in place (e.g. a tarball).

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Codec, Format, Input, Probe, content_hinted};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "gzip",
    title: "gzip compressed data",
    extensions: &["gz", "tgz", "svgz", "emz", "wmz"],
    mime: "application/gzip",
    probe: Probe::Magic(&[(0, b"\x1f\x8b\x08")]),
    dissect: crate::expander!(dissect: Input),
};

const METHOD: EnumTable = &[(8, "deflate")];

const FLAGS: FlagTable = &[
    flag(0x01, "FTEXT"),
    flag(0x02, "FHCRC"),
    flag(0x04, "FEXTRA"),
    flag(0x08, "FNAME"),
    flag(0x10, "FCOMMENT"),
];

const OS: EnumTable = &[
    (0, "FAT"),
    (1, "Amiga"),
    (2, "VMS"),
    (3, "Unix"),
    (4, "VM/CMS"),
    (5, "Atari TOS"),
    (6, "HPFS"),
    (7, "Macintosh"),
    (8, "Z-System"),
    (9, "CP/M"),
    (10, "TOPS-20"),
    (11, "NTFS"),
    (12, "QDOS"),
    (13, "Acorn RISCOS"),
    (255, "unknown"),
];

const XFL: EnumTable = &[(0, "default"), (2, "best compression"), (4, "fastest")];

record! {
    pub struct Header {
        magic: bytes[2] "ID",
        method: u8 "CM" .enumeration(METHOD),
        flags: u8 "FLG" .flags(FLAGS),
        mtime: u32 "MTIME" .timestamp().desc("Modification time of the original file (0 if unknown)"),
        extra_flags: u8 "XFL" .enumeration(XFL),
        os: u8 "OS" .enumeration(OS),
    }
}

record! {
    pub struct Trailer {
        crc: u32 "CRC32" .hex().desc("CRC-32 of the uncompressed data"),
        size: u32 "ISIZE" .desc("Uncompressed size modulo 2^32"),
    }
}

/// Registered extra subfield ids (SI1 SI2).
const SUBFIELDS: &[(&[u8; 2], &str)] = &[
    (b"AC", "Acorn RISC OS file type"),
    (b"Ap", "Apollo file type"),
    (b"BC", "BGZF block size"),
    (b"cp", "compressed by cpio"),
    (b"GS", "gzsig signature"),
    (b"KN", "KeyNote assertion"),
    (b"Mc", "Macintosh type and creator"),
    (b"RA", "random access index (dictzip)"),
    (b"RO", "Acorn RISC OS file type"),
];

/// The FEXTRA field (XLEN, then subfields of SI1 SI2 LEN data), spanning
/// `span`; `data` is the field's XLEN bytes at `data_span`. Also used by
/// BGZF, whose blocks are gzip members with a `BC` subfield.
pub fn extra_field(span: Span, data: &[u8], data_span: Span) -> Node {
    let mut children = vec![
        Node::new("XLEN")
            .span(span.sub(0, 2))
            .value(uint(data_span.len, 16)),
    ];
    let mut at = 0usize;
    let mut count = 0u64;
    while let (Some(id), Some(len)) = (
        data.get(at..at.saturating_add(2)),
        u16_le(data, at.saturating_add(2)),
    ) {
        let len = usize::from(len);
        let body_at = at.saturating_add(4);
        let sub = data_span.sub(to_u64(at), to_u64(len.saturating_add(4)));
        let body = data_span.sub(to_u64(body_at), to_u64(len));
        let known = SUBFIELDS
            .iter()
            .find(|(k, _)| k.as_slice() == id)
            .map(|(_, v)| *v);
        let id_text = String::from_utf8_lossy(id).into_owned();
        let mut data_node = Node::new("Data").span(body);
        if id == b"BC" && len == 2 {
            let bsize = u16_le(data, body_at).unwrap_or(0);
            data_node = data_node
                .value(uint(bsize, 16))
                .summary(format!("block size {}", u32::from(bsize).saturating_add(1)));
        }
        let mut node = Node::new(format!("Subfield {id_text}"))
            .span(sub)
            .summary(match known {
                Some(what) => format!("{what}, {}", size(to_u64(len))),
                None => size(to_u64(len)),
            });
        if body.len < to_u64(len) {
            node = node.diag(Diagnostic::truncated(body, body.len));
        }
        children.push(node.lazy(
            emit_nodes,
            Arc::new(vec![
                Node::new("SI1 SI2").span(sub.sub(0, 2)).value(text(id_text)),
                Node::new("LEN").span(sub.sub(2, 2)).value(uint(to_u64(len), 16)),
                data_node,
            ]),
        ));
        count = count.saturating_add(1);
        at = body_at.saturating_add(len);
    }
    if at < data.len() {
        children.push(
            Node::new("Trailing bytes")
                .span(data_span.tail(to_u64(at)))
                .diag(Diagnostic::malformed("not a whole subfield")),
        );
    }
    Node::new("Extra field")
        .span(span)
        .summary(format!(
            "{}, {}",
            crate::formats::util::fmt::count(count, "subfield", "subfields"),
            size(data_span.len)
        ))
        .lazy(emit_nodes, Arc::new(children))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (header, header_span) = cur.record::<Header>().await?;
    cx.emit(Header::node("Header", header_span, LE));
    if header.flags & 0x04 != 0 {
        let start = cur.pos();
        let xlen = cur.u16().await?;
        let data_span = cur.span(xlen.into());
        let data = cur.bytes(xlen.into()).await?;
        cx.emit(extra_field(cur.since(start), &data, data_span));
    }
    let mut name = None;
    if header.flags & 0x08 != 0 {
        let (text, span) = cur.cstr(4096).await?;
        cx.emit(
            Node::new("Original name")
                .span(span)
                .value(Value::Text(text.clone())),
        );
        name = Some(text);
    }
    if header.flags & 0x10 != 0 {
        let (text, span) = cur.cstr(65536).await?;
        cx.emit(Node::new("Comment").span(span).value(Value::Text(text)));
    }
    if header.flags & 0x02 != 0 {
        let start = cur.pos();
        let crc = cur.u16().await?;
        cx.emit(
            Node::new("Header CRC16")
                .span(cur.since(start))
                .value(hex(crc, 16)),
        );
    }

    // The trailer of a single-member file is its last 8 bytes; further
    // members, if any, are found by decoding (nothing indexes them).
    let body_len = file.len.saturating_sub(cur.pos()).saturating_sub(8);
    let body = file.sub(cur.pos(), body_len);
    let trailer_span = file.tail(file.len.saturating_sub(8));
    let trailer = cx.read_avail(trailer_span).await?;
    let size = u32_le(&trailer, 4);
    if trailer.len() == 8 {
        cx.emit(Trailer::node("Trailer", trailer_span, LE));
    } else {
        cx.diag(Diagnostic::truncated(trailer_span, to_u64(trailer.len())));
    }
    let mut summary = String::from("gzip");
    if let Some(name) = &name {
        summary = format!("{summary}, originally {name}");
    }
    if let Some(size) = size {
        summary = format!("{summary}, {size} bytes uncompressed");
    }
    cx.annotate(summary);
    // The content is every member, decoded one after another. Nothing
    // records the total: ISIZE is one member's size modulo 2^32, so it only
    // hints whether to decode on demand; the size is found by decoding.
    cx.emit(
        content_hinted(
            "Content",
            input,
            file.tail(cur.pos()),
            Codec::Gzip,
            size.map_or(0, u64::from),
        )
        .summary(format!("{:#x} compressed bytes", body.len)),
    );
    Ok(())
}
