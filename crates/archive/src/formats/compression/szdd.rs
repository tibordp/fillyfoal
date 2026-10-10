//! The MS-DOS `COMPRESS.EXE` formats SZDD and KWAJ: a header in front of a
//! single compressed stream, decoded and dissected in place (see
//! [`crate::codec::lzh`]): SZDD's LZSS, and KWAJ's stored, XOR, LZSS and
//! MSZIP methods. KWAJ's method 3 (LZ + Huffman) is an unsupported leaf.

use crate::bytes::u16_le;
use crate::codec::{Codec, lzh};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{human_size, unsupported};
use crate::formats::{Format, Input, Probe, embedded};
use crate::record;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;

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
    let codec = Codec::Lzh(lzh::Params::new(
        lzh::Method::Szdd,
        Some(h.size.into()),
        lzh::Check::None,
    ));
    cx.emit(
        crate::formats::content(
            "Content",
            input,
            file.tail(SzddHeader::SIZE),
            codec,
            Some(h.size.into()),
        )
        .summary(human_size(h.size.into())),
    );
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
    let codec_method = match method {
        1 => Some(lzh::Method::KwajXor),
        2 => Some(lzh::Method::Szdd),
        4 => Some(lzh::Method::KwajMszip),
        _ => None,
    };
    let expected = size.map(u64::from);
    cx.emit(match (method, codec_method) {
        (0, _) => embedded("Data", input.nested(data)),
        (_, Some(m)) => {
            let codec = Codec::Lzh(lzh::Params::new(m, expected, lzh::Check::None));
            crate::formats::content("Content", input, data, codec, expected)
        }
        _ => unsupported("Compressed data", data, &format!("KWAJ {name}")),
    });
    let size = size.map_or_else(String::new, |s| {
        format!(", {} uncompressed", human_size(s.into()))
    });
    cx.annotate(format!("MS-DOS COMPRESS (KWAJ), {name}{size}"));
    Ok(())
}
