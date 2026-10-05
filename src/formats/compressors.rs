//! Single-file compressors: lzop, lrzip, and the MS-DOS `COMPRESS.EXE`
//! formats SZDD and KWAJ.
//!
//! lzop files are a header and blocks with optional checksums; incompressible
//! blocks are stored and dissected as data. The others are a header in front
//! of a single compressed stream (unsupported, see the codec policy) except
//! for KWAJ's stored method.

use std::sync::Arc;

use crate::bytes::u16_le;
use crate::codec::{adler32, crc32};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::arcutil::{count, emit_nodes, hex, human_size, uint, unsupported};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const BE: Endian = Endian::Big;
const LE: Endian = Endian::Little;

pub static LZOP: Format = Format {
    name: "lzop",
    title: "lzop compressed data",
    extensions: &["lzo", "tzo"],
    mime: "application/x-lzop",
    probe: Probe::Magic(&[(0, b"\x89LZO\x00\x0d\x0a\x1a\x0a")]),
    dissect: crate::expander!(dissect_lzop: Input),
};

pub static LRZIP: Format = Format {
    name: "lrzip",
    title: "lrzip compressed data",
    extensions: &["lrz", "tlrz"],
    mime: "application/x-lrzip",
    probe: Probe::Custom(|h| h.starts_with(b"LRZI") && h.data.get(4).is_some_and(|&v| v == 0)),
    dissect: crate::expander!(dissect_lrzip: Input),
};

pub static SZDD: Format = Format {
    name: "szdd",
    title: "MS-DOS COMPRESS (SZDD)",
    extensions: &["ex_", "dl_", "sy_", "tx_", "hl_", "in_", "_"],
    mime: "application/x-ms-compress-szdd",
    probe: Probe::Magic(&[(0, b"SZDD\x88\xf0\x27\x33")]),
    dissect: crate::expander!(dissect_szdd: Input),
};

pub static KWAJ: Format = Format {
    name: "kwaj",
    title: "MS-DOS COMPRESS (KWAJ)",
    extensions: &["ex_", "dl_", "_"],
    mime: "application/x-ms-compress-kwaj",
    probe: Probe::Magic(&[(0, b"KWAJ\x88\xf0\x27\xd1")]),
    dissect: crate::expander!(dissect_kwaj: Input),
};

// ---------------------------------------------------------------------------
// lzop

const LZOP_METHOD: EnumTable = &[(1, "LZO1X-1"), (2, "LZO1X-1(15)"), (3, "LZO1X-999")];

const LZOP_FLAGS: FlagTable = &[
    flag(0x0000_0001, "ADLER32_D"),
    flag(0x0000_0002, "ADLER32_C"),
    flag(0x0000_0004, "STDIN"),
    flag(0x0000_0008, "STDOUT"),
    flag(0x0000_0010, "NAME_DEFAULT"),
    flag(0x0000_0020, "DOSISH"),
    flag(0x0000_0040, "H_EXTRA_FIELD"),
    flag(0x0000_0080, "H_GMTDIFF"),
    flag(0x0000_0100, "CRC32_D"),
    flag(0x0000_0200, "CRC32_C"),
    flag(0x0000_0400, "MULTIPART"),
    flag(0x0000_0800, "H_FILTER"),
    flag(0x0000_1000, "H_CRC32"),
    flag(0x0000_2000, "H_PATH"),
];

/// What the block walk needs from the header.
#[derive(Clone, Copy, Debug, Default)]
struct LzopHeader {
    flags: u32,
    method: u8,
}

fn lzop_header(f: &mut Fields<'_>, _: &()) -> Result<LzopHeader> {
    f.bytes("Magic", 9).emit()?;
    let version = f.u16("Version").hex().emit()?;
    f.u16("Library version").hex().emit()?;
    if version >= 0x0940 {
        f.u16("Version needed").hex().emit()?;
    }
    let method = f.u8("Method").enumeration(LZOP_METHOD).emit()?;
    if version >= 0x0940 {
        f.u8("Level").emit()?;
    }
    let flags = f.u32("Flags").flags(LZOP_FLAGS).emit()?;
    if flags & 0x800 != 0 {
        f.u32("Filter").emit()?;
    }
    f.u32("Mode")
        .with(|&m, n| n.summary(crate::formats::arcutil::unix_mode(m.into())))
        .emit()?;
    f.u32("Modification time").timestamp().emit()?;
    if version >= 0x0940 {
        f.u32("Modification time (high)").emit()?;
    }
    let len = f.u8("Name length").emit()?;
    f.ascii("Name", len.into()).emit()?;
    let covered = f
        .block()
        .data
        .get(9..crate::bytes::to_usize(f.pos()))
        .unwrap_or_default()
        .to_vec();
    let stored = f.u32("Header checksum").hex().get()?;
    let computed = if flags & 0x1000 != 0 {
        crc32(&covered)
    } else {
        adler32(&covered)
    };
    let span = f.peek_span(0);
    let node = Node::new("Header checksum")
        .span(Span::new(span.source, span.offset.saturating_sub(4), 4))
        .value(hex(stored.into()));
    f.node(if computed == stored {
        node.summary("valid")
    } else {
        node.diag(Diagnostic::warning(format!(
            "checksum mismatch: computed {computed:#010x}"
        )))
    });
    if flags & 0x40 != 0 {
        let extra = f.u32("Extra field length").emit()?;
        f.bytes("Extra field", extra.into()).emit()?;
        f.u32("Extra field checksum").hex().emit()?;
    }
    Ok(LzopHeader { flags, method })
}

pub async fn dissect_lzop(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = file.sub(0, 512);
    // Decode once to learn the header's length.
    let block = cx.block(head).await?;
    let mut f = Fields::new(&block, BE);
    let h = lzop_header(&mut f, &())?;
    let header_len = f.pos();
    cx.emit(struct_node(
        "Header",
        file.sub(0, header_len),
        BE,
        (),
        lzop_header,
    ));
    let method = crate::value::lookup(LZOP_METHOD, h.method.into()).unwrap_or("LZO");
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(header_len);
    let mut blocks = 0u64;
    let mut total = 0u64;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let unpacked = cur.u32().await?;
        if unpacked == 0 {
            cx.emit(Node::new("End of stream").span(cur.since(start)));
            break;
        }
        let packed = cur.u32().await?;
        let mut fields = vec![
            Node::new("Uncompressed size")
                .span(file.sub(start, 4))
                .value(uint(unpacked.into())),
            Node::new("Compressed size")
                .span(file.sub(start.saturating_add(4), 4))
                .value(uint(packed.into())),
        ];
        for (bit, name) in [
            (0x001u32, "Uncompressed Adler-32"),
            (0x100, "Uncompressed CRC-32"),
        ] {
            if h.flags & bit != 0 {
                let at = cur.pos();
                let v = cur.u32().await?;
                fields.push(Node::new(name).span(file.sub(at, 4)).value(hex(v.into())));
            }
        }
        if packed < unpacked {
            for (bit, name) in [
                (0x002u32, "Compressed Adler-32"),
                (0x200, "Compressed CRC-32"),
            ] {
                if h.flags & bit != 0 {
                    let at = cur.pos();
                    let v = cur.u32().await?;
                    fields.push(Node::new(name).span(file.sub(at, 4)).value(hex(v.into())));
                }
            }
        }
        let data = cur.span(packed.into());
        cur.skip(packed.into());
        fields.push(if packed >= unpacked {
            Node::new("Stored data").span(data)
        } else {
            unsupported("Compressed data", data, method)
        });
        cx.push(crate::formats::arcutil::check_len(
            Node::new(format!("Block {blocks}"))
                .span(cur.since(start))
                .summary(format!(
                    "{} → {}",
                    human_size(packed.into()),
                    human_size(unpacked.into())
                ))
                .lazy(emit_nodes, Arc::new(fields)),
            data,
            packed.into(),
        ))
        .await;
        blocks = blocks.saturating_add(1);
        total = total.saturating_add(unpacked.into());
    }
    cx.annotate(format!(
        "lzop, {method}, {}, {} uncompressed",
        count(blocks, "block", "blocks"),
        human_size(total)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// lrzip

record! {
    pub struct LrzipHeader {
        magic: ascii[4] "Magic",
        major: u8 "Major version",
        minor: u8 "Minor version",
        size: u64 "Uncompressed size" .with(|&s, n| n.summary(human_size(s))),
        unused: bytes[2] "Reserved",
        lzma: bytes[5] "LZMA properties",
        md5: u8 "MD5 stored",
        encrypted: u8 "Encrypted",
        reserved: u8 "Reserved",
    }
}

pub async fn dissect_lrzip(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, LrzipHeader::SIZE);
    let h = crate::fields::parse(&cx, span, LE, &(), LrzipHeader::layout).await?;
    cx.emit(
        LrzipHeader::node("Header", span, LE).summary(format!("version {}.{}", h.major, h.minor)),
    );
    let mut body = file.tail(LrzipHeader::SIZE);
    if h.md5 != 0 && body.len >= 16 {
        let md5 = file.tail(file.len.saturating_sub(16));
        body = body.sub(0, body.len.saturating_sub(16));
        cx.emit(unsupported(
            "Compressed data",
            body,
            "lrzip (rzip + LZMA/ZPAQ/bzip2)",
        ));
        cx.emit(Node::new("MD5").span(md5));
    } else {
        cx.emit(unsupported(
            "Compressed data",
            body,
            "lrzip (rzip + LZMA/ZPAQ/bzip2)",
        ));
    }
    let enc = if h.encrypted != 0 { ", encrypted" } else { "" };
    cx.annotate(format!(
        "lrzip {}.{}, {} uncompressed{enc}",
        h.major,
        h.minor,
        human_size(h.size)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// SZDD / KWAJ

record! {
    pub struct SzddHeader {
        magic: bytes[8] "Magic",
        mode: ascii[1] "Compression mode" .desc("'A': LZSS with a 4 KiB window"),
        missing: ascii[1] "Missing last character" .desc("Replaces the '_' at the end of the file name"),
        size: u32 "Uncompressed size" .with(|&s, n| n.summary(human_size(s.into()))),
    }
}

pub async fn dissect_szdd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, SzddHeader::SIZE);
    let h = crate::fields::parse(&cx, span, LE, &(), SzddHeader::layout).await?;
    cx.emit(SzddHeader::node("Header", span, LE));
    cx.emit(unsupported(
        "Compressed data",
        file.tail(SzddHeader::SIZE),
        "SZDD LZSS",
    ));
    let missing = if h.missing.trim_matches('\0').is_empty() {
        String::new()
    } else {
        format!(", last character {:?}", h.missing)
    };
    cx.annotate(format!(
        "MS-DOS COMPRESS (SZDD), {} uncompressed{missing}",
        human_size(h.size.into())
    ));
    Ok(())
}

const KWAJ_METHOD: EnumTable = &[
    (0, "stored"),
    (1, "XOR 0xFF"),
    (2, "SZDD LZSS"),
    (3, "LZ + Huffman"),
    (4, "MSZIP"),
];

const KWAJ_FLAGS: FlagTable = &[
    flag(0x01, "LENGTH"),
    flag(0x02, "UNKNOWN"),
    flag(0x04, "EXTRA"),
    flag(0x08, "NAME"),
    flag(0x10, "EXTENSION"),
    flag(0x20, "TEXT"),
];

fn kwaj_header(f: &mut Fields<'_>, _: &()) -> Result<(u16, u16, Option<u32>)> {
    f.bytes("Magic", 8).emit()?;
    let method = f.u16("Method").enumeration(KWAJ_METHOD).emit()?;
    let data = f.u16("Data offset").hex().emit()?;
    let flags = f.u16("Flags").flags(KWAJ_FLAGS).emit()?;
    let mut size = None;
    if flags & 0x01 != 0 {
        size = Some(
            f.u32("Uncompressed size")
                .with(|&s, n| n.summary(human_size(s.into())))
                .emit()?,
        );
    }
    if flags & 0x02 != 0 {
        f.u16("Unknown").emit()?;
    }
    if flags & 0x04 != 0 {
        let len = f.u16("Extra length").emit()?;
        f.bytes("Extra", len.into()).emit()?;
    }
    if flags & 0x08 != 0 {
        f.cstr("File name").emit()?;
    }
    if flags & 0x10 != 0 {
        f.cstr("Extension").emit()?;
    }
    if flags & 0x20 != 0 {
        let len = f.u16("Text length").emit()?;
        f.ascii("Text", len.into()).emit()?;
    }
    Ok((method, data, size))
}

pub async fn dissect_kwaj(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 14)).await?;
    let data_at = u64::from(u16_le(&head, 10).unwrap_or(14));
    let span = file.sub(0, data_at);
    let (method, _, size) = crate::fields::parse(&cx, span, LE, &(), kwaj_header).await?;
    cx.emit(struct_node("Header", span, LE, (), kwaj_header));
    let data = file.tail(data_at);
    let name = crate::value::lookup(KWAJ_METHOD, method.into()).unwrap_or("unknown method");
    cx.emit(match method {
        0 => embedded("Data", input.nested(data)),
        _ => unsupported("Compressed data", data, &format!("KWAJ {name}")),
    });
    let size = size.map_or_else(String::new, |s| {
        format!(", {} uncompressed", human_size(s.into()))
    });
    cx.annotate(format!("MS-DOS COMPRESS (KWAJ), {name}{size}"));
    Ok(())
}
