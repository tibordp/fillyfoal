//! WOFF and WOFF2 web fonts.
//!
//! WOFF 1.0 compresses each sfnt table separately with zlib; a table is
//! decompressed when expanded and then decoded like an sfnt table. WOFF2
//! compresses all tables together into one Brotli stream; its table
//! directory, with variable-length sizes and transforms, is shown in full,
//! and the decompressed tables are decoded unless WOFF2 transformed them.

use crate::bytes::u32_be;
use crate::codec::inflate_span;
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::datakit::{fourcc, size};
use crate::formats::font::tables;
use crate::formats::{Codec, Format, Input, Probe, content};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::Value;

const BE: Endian = Endian::Big;

pub static WOFF: Format = Format {
    name: "woff",
    title: "Web Open Font Format",
    extensions: &["woff"],
    mime: "font/woff",
    probe: Probe::Magic(&[(0, b"wOFF")]),
    dissect: crate::expander!(woff: Input),
};

pub static WOFF2: Format = Format {
    name: "woff2",
    title: "Web Open Font Format 2",
    extensions: &["woff2"],
    mime: "font/woff2",
    probe: Probe::Magic(&[(0, b"wOF2")]),
    dissect: crate::expander!(woff2: Input),
};

record! {
    pub struct WoffHeader {
        signature: ascii[4] "Signature",
        flavor: u32 "Flavor" .hex() .with(|&v, n| n.summary(crate::formats::font::flavor(v))),
        length: u32 "Length",
        tables: u16 "Number of tables",
        _reserved: u16 "Reserved",
        sfnt_size: u32 "Total sfnt size",
        major: u16 "Major version",
        minor: u16 "Minor version",
        meta_offset: u32 "Metadata offset" .hex(),
        meta_length: u32 "Metadata length",
        meta_orig: u32 "Metadata original length",
        priv_offset: u32 "Private data offset" .hex(),
        priv_length: u32 "Private data length",
    }
}

record! {
    pub struct Woff2Header {
        signature: ascii[4] "Signature",
        flavor: u32 "Flavor" .hex() .with(|&v, n| n.summary(crate::formats::font::flavor(v))),
        length: u32 "Length",
        tables: u16 "Number of tables",
        _reserved: u16 "Reserved",
        sfnt_size: u32 "Total sfnt size",
        compressed: u32 "Total compressed size",
        major: u16 "Major version",
        minor: u16 "Minor version",
        meta_offset: u32 "Metadata offset" .hex(),
        meta_length: u32 "Metadata length",
        meta_orig: u32 "Metadata original length",
        priv_offset: u32 "Private data offset" .hex(),
        priv_length: u32 "Private data length",
    }
}

fn metadata_nodes(cx: &Cx, input: Input, file: Span, h: (u32, u32, u32, u32, u32), brotli: bool) {
    let (meta_offset, meta_length, meta_orig, priv_offset, priv_length) = h;
    if meta_length > 0 {
        let span = file.sub(meta_offset.into(), meta_length.into());
        let codec = if brotli { Codec::Brotli } else { Codec::Zlib };
        let node = content("Metadata (XML)", input, span, codec, Some(meta_orig.into()));
        cx.emit(node.summary(format!("{meta_orig} bytes uncompressed")));
    }
    if priv_length > 0 {
        cx.emit(Node::new("Private data").span(file.sub(priv_offset.into(), priv_length.into())));
    }
}

pub async fn woff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, WoffHeader::SIZE);
    let h = parse(&cx, hspan, BE, &(), WoffHeader::layout).await?;
    cx.emit(WoffHeader::node("Header", hspan, BE));
    cx.annotate(format!(
        "WOFF {}.{}, {} tables, {} as sfnt",
        h.major,
        h.minor,
        h.tables,
        size(h.sfnt_size.into())
    ));
    let dir = file.sub_exact(WoffHeader::SIZE, u64::from(h.tables).saturating_mul(20))?;
    cx.emit(
        Node::new("Table directory")
            .span(dir)
            .summary(format!("{} tables", h.tables)),
    );
    metadata_nodes(
        &cx,
        input,
        file,
        (
            h.meta_offset,
            h.meta_length,
            h.meta_orig,
            h.priv_offset,
            h.priv_length,
        ),
        false,
    );
    let data = cx.read(dir).await?;
    for (i, rec) in data.as_chunks::<20>().0.iter().enumerate() {
        let tag = fourcc(rec.get(..4).unwrap_or_default());
        let offset = u32_be(rec, 4).unwrap_or(0);
        let comp = u32_be(rec, 8).unwrap_or(0);
        let orig = u32_be(rec, 12).unwrap_or(0);
        let checksum = u32_be(rec, 16).unwrap_or(0);
        let span = file.sub(offset.into(), comp.into());
        let entry = dir.sub(crate::bytes::to_u64(i).saturating_mul(20), 20);
        let mut summary = if comp < orig {
            format!("zlib, {comp} → {orig} bytes")
        } else {
            format!("{orig} bytes")
        };
        if let Some(name) = tables::table_name(&tag) {
            summary = format!("{name}, {summary}");
        }
        cx.push(
            Node::new(format!("'{tag}'"))
                .span(span)
                .summary(summary)
                .lazy(woff_table, (entry, span, tag, comp < orig, orig, checksum)),
        )
        .await;
    }
    Ok(())
}

async fn woff_table(
    cx: Cx,
    (entry, span, tag, compressed, orig, checksum): (Span, Span, String, bool, u32, u32),
) -> Result<()> {
    cx.emit(crate::fields::struct_node(
        "Directory entry",
        entry,
        BE,
        (),
        |f, _| {
            f.ascii("Tag", 4).emit()?;
            f.u32("Offset").hex().emit()?;
            f.u32("Compressed length").emit()?;
            f.u32("Original length").emit()?;
            f.u32("Original checksum").hex().emit()?;
            Ok(())
        },
    ));
    let table = if compressed {
        let decoded = inflate_span(&cx, span, true, Some(orig.into())).await?;
        if let Some(e) = decoded.error {
            cx.diag(e);
        }
        decoded.span
    } else {
        span
    };
    if table.len <= cx.limits().max_read {
        let data = cx.read_avail(table).await?;
        let computed = tables::checksum(&data, tag == "head");
        let node = Node::new("Checksum").value(crate::formats::datakit::hex(checksum, 32));
        cx.emit(if computed == checksum {
            node.summary("valid")
        } else {
            node.diag(Diagnostic::warning(format!(
                "mismatch: computed {computed:#010x}"
            )))
        });
    }
    tables::decode(&cx, &tag, table).await
}

/// Known tags, indexed by the low 6 bits of a WOFF2 table entry's flags.
const KNOWN_TAGS: [&str; 63] = [
    "cmap", "head", "hhea", "hmtx", "maxp", "name", "OS/2", "post", "cvt ", "fpgm", "glyf", "loca",
    "prep", "CFF ", "VORG", "EBDT", "EBLC", "gasp", "hdmx", "kern", "LTSH", "PCLT", "VDMX", "vhea",
    "vmtx", "BASE", "GDEF", "GPOS", "GSUB", "EBSC", "JSTF", "MATH", "CBDT", "CBLC", "COLR", "CPAL",
    "SVG ", "sbix", "acnt", "avar", "bdat", "bloc", "bsln", "cvar", "fdsc", "feat", "fmtx", "fvar",
    "gvar", "hsty", "just", "lcar", "mort", "morx", "opbd", "prop", "trak", "Zapf", "Silf", "Glat",
    "Gloc", "Feat", "Sill",
];

/// UIntBase128: big-endian base-128 with continuation bits, at most 5 bytes.
async fn base128(cur: &mut Cursor<'_>) -> Result<u32> {
    let mut value = 0u32;
    for i in 0..5 {
        let b = cur.u8().await?;
        if i == 0 && b == 0x80 {
            return Err(Diagnostic::malformed("UIntBase128 with a leading zero"));
        }
        if value & 0xfe00_0000 != 0 {
            return Err(Diagnostic::malformed("UIntBase128 overflows"));
        }
        value = value << 7 | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Diagnostic::malformed("UIntBase128 longer than 5 bytes"))
}

pub async fn woff2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Woff2Header::SIZE);
    let h = parse(&cx, hspan, BE, &(), Woff2Header::layout).await?;
    cx.emit(Woff2Header::node("Header", hspan, BE));
    cx.annotate(format!(
        "WOFF2 {}.{}, {} tables, {} as sfnt, {} compressed",
        h.major,
        h.minor,
        h.tables,
        size(h.sfnt_size.into()),
        size(h.compressed.into())
    ));
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(Woff2Header::SIZE);
    let mut entries = Vec::new();
    for _ in 0..h.tables {
        let start = cur.pos();
        let flags = cur.u8().await?;
        let tag = match KNOWN_TAGS.get(usize::from(flags & 0x3f)) {
            Some(t) => (*t).to_owned(),
            None => fourcc(&cur.bytes(4).await?),
        };
        let orig = base128(&mut cur).await?;
        let version = flags >> 6;
        // glyf/loca are transformed with version 0; others with versions 1-3.
        let transformed = if tag == "glyf" || tag == "loca" {
            version == 0
        } else {
            version != 0
        };
        let transform_len = if transformed {
            Some(base128(&mut cur).await?)
        } else {
            None
        };
        entries.push((cur.since(start), tag, flags, orig, transform_len));
    }
    let dir_end = cur.pos();
    let dir = file.sub(Woff2Header::SIZE, dir_end.saturating_sub(Woff2Header::SIZE));
    cx.emit(
        Node::new("Table directory")
            .span(dir)
            .summary(format!("{} tables", h.tables))
            .lazy(woff2_directory, (entries.clone(),)),
    );
    let mut stream_at = dir_end;
    if h.flavor == u32::from_be_bytes(*b"ttcf") {
        let rest = file.tail(dir_end);
        cx.emit(
            Node::new("Collection directory")
                .span(rest.sub(0, 0))
                .diag(Diagnostic::unsupported("WOFF2 collection directory")),
        );
        stream_at = file.len;
    }
    let stream = file.sub(stream_at, h.compressed.into());
    let total: u64 = entries
        .iter()
        .map(|e| u64::from(e.4.unwrap_or(e.3)))
        .fold(0u64, u64::saturating_add);
    cx.emit(
        Node::new("Compressed font data")
            .span(stream)
            .summary(format!(
                "{} bytes → {total} bytes of table data",
                stream.len
            ))
            .lazy(woff2_tables, (stream, entries, total)),
    );
    metadata_nodes(
        &cx,
        input,
        file,
        (
            h.meta_offset,
            h.meta_length,
            h.meta_orig,
            h.priv_offset,
            h.priv_length,
        ),
        true,
    );
    Ok(())
}

type Woff2Entry = (Span, String, u8, u32, Option<u32>);

/// Decompresses the table data and lists the tables in it, in directory
/// order and without padding (each is its transformed length, if any).
async fn woff2_tables(cx: Cx, (stream, entries, total): (Span, Vec<Woff2Entry>, u64)) -> Result<()> {
    let decoded = crate::codec::decode_span(&cx, stream, &Codec::Brotli, Some(total)).await?;
    cx.annotate(format!("{:#x} bytes decompressed", decoded.span.len));
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    cx.set_count(Count::Exact(crate::bytes::to_u64(entries.len())));
    let mut offset = 0u64;
    for (_, tag, flags, orig, transform) in entries {
        let len = u64::from(transform.unwrap_or(orig));
        let span = decoded.span.sub(offset, len);
        offset = offset.saturating_add(len);
        let mut summary = format!("{len} bytes");
        if let Some(name) = tables::table_name(&tag) {
            summary = format!("{name}, {summary}");
        }
        let node = Node::new(format!("'{tag}'")).span(span);
        cx.push(match transform {
            Some(_) => node.summary(format!(
                "{summary}, transformed (version {}; not decoded)",
                flags >> 6
            )),
            None => node.summary(summary).lazy(woff2_table, (span, tag)),
        })
        .await;
    }
    Ok(())
}

async fn woff2_table(cx: Cx, (span, tag): (Span, String)) -> Result<()> {
    tables::decode(&cx, &tag, span).await
}

async fn woff2_directory(cx: Cx, (entries,): (Vec<Woff2Entry>,)) -> Result<()> {
    cx.set_count(Count::Exact(crate::bytes::to_u64(entries.len())));
    for (span, tag, flags, orig, transform) in entries {
        let mut summary = format!("{orig} bytes");
        if let Some(t) = transform {
            summary = format!(
                "{summary}, transformed (version {}) to {t} bytes",
                flags >> 6
            );
        }
        if let Some(name) = tables::table_name(&tag) {
            summary = format!("{name}, {summary}");
        }
        cx.push(
            Node::new(format!("'{tag}'"))
                .span(span)
                .value(Value::UInt {
                    value: flags.into(),
                    bits: 8,
                    radix: crate::value::Radix::Hex,
                })
                .summary(summary),
        )
        .await;
    }
    Ok(())
}
