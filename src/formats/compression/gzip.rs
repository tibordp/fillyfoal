//! gzip (RFC 1952).
//!
//! The top level shows the header and the trailer (read from the end of the
//! file, which gives the original size without decompressing). The content is
//! decompressed only when expanded, then dissected in place (e.g. a tarball).

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Codec, Format, Input, Probe, content};
use crate::node::Node;
use crate::record;
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

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (header, header_span) = cur.record::<Header>().await?;
    cx.emit(Header::node("Header", header_span, LE));
    if header.flags & 0x04 != 0 {
        let start = cur.pos();
        let len = cur.u16().await?;
        cur.skip(len.into());
        cx.emit(
            Node::new("Extra field")
                .span(cur.since(start))
                .summary(format!("{len} bytes")),
        );
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
                .value(Value::UInt {
                    value: crc.into(),
                    bits: 16,
                    radix: crate::value::Radix::Hex,
                }),
        );
    }

    // Assume a single member: the trailer is the last 8 bytes. Concatenated
    // members are reported when the content is decompressed.
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
    cx.emit(
        content("Content", input, body, Codec::Deflate, size.map(u64::from))
            .summary(format!("{:#x} compressed bytes", body.len)),
    );
    Ok(())
}
