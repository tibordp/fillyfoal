//! TempleOS compressed files (`.Z`, `CArcCompress` in `Kernel/KernelA.HH`
//! and `Kernel/Compress.HC` of the public-domain TempleOS V5.03 source):
//! almost every file on a TempleOS disk (`Foo.HC.Z`, `Bar.DD.Z`) is one.
//! A 17-byte header gives the compressed size (the whole file, header
//! included), the expanded size and the compression type: stored, or LZW
//! over 7-bit or 8-bit characters (see `codec::templeos`). The expanded
//! data is decoded on demand and dissected in turn: as the format the
//! file's name gives it, if any (see [`format_by_name`]), since HolyC and
//! DolDoc text often has nothing that tells it from plain text.
//!
//! Not Unix `compress`, whose `.Z` starts with `1F 9D`: this one has no
//! magic, so the probe asks for the first 64-bit field to be the file's
//! exact length, a known compression type and a plausible expanded size.

use crate::codec::Codec;
use crate::codec::templeos::{CT_7_BIT, CT_8_BIT, CT_NONE, HEADER};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::util::fmt;
use crate::formats::{Format, Head, Input, Probe, content, content_named};
use crate::node::Node;
use crate::record;
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "templeos-z",
    title: "TempleOS compressed file",
    extensions: &["Z"],
    mime: "application/x-templeos-compressed",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// TempleOS refuses to expand more than this (TOSZ's limit; the kernel's
/// is the mapped address space).
const MAX_EXPANDED: u64 = 0x2000_0000;

/// The format TempleOS gives a file by its name, `.Z` aside: it compiles
/// `.HC`, `.HH`, `.IN` and `.PRJ` files as HolyC (`Load`, `ExeFile`,
/// `#include`) and reads `.DD` and `.MAP` files as DolDoc documents
/// (`DocRead`). `name` may be a path.
pub fn format_by_name(name: &str) -> Option<&'static str> {
    let name = name.rsplit('/').next().unwrap_or(name);
    let name = strip_z(name).unwrap_or(name);
    let (_, ext) = name.rsplit_once('.')?;
    let is = |e: &str| ext.eq_ignore_ascii_case(e);
    if is("HC") || is("HH") || is("IN") || is("PRJ") {
        Some("holyc")
    } else if is("DD") || is("MAP") {
        Some("doldoc")
    } else {
        None
    }
}

/// `name` without its `.Z`, if it has one.
fn strip_z(name: &str) -> Option<&str> {
    name.strip_suffix(".Z").or_else(|| name.strip_suffix(".z"))
}

const TYPES: EnumTable = &[(1, "CT_NONE"), (2, "CT_7_BIT"), (3, "CT_8_BIT")];

fn probe(h: &Head<'_>) -> bool {
    let header = crate::bytes::to_u64(HEADER);
    if !h.len_known || h.len < header {
        return false;
    }
    let (Some(compressed), Some(expanded), Some(&kind)) = (
        crate::bytes::u64_le(h.data, 0),
        crate::bytes::u64_le(h.data, 8),
        h.data.get(16),
    ) else {
        return false;
    };
    if compressed != h.len || expanded >= MAX_EXPANDED {
        return false;
    }
    let body = h.len.saturating_sub(header);
    match kind {
        // `CompressBuf` stores data that does not shrink as it is.
        CT_NONE => expanded == body,
        // Each code (of 8 to 12 bits) stands for 1 to 4096 bytes, and the
        // first is a character: 8 bits below 0x80, or 9 bits below 0x100.
        CT_7_BIT | CT_8_BIT => {
            body > 0
                && expanded >= (body.saturating_mul(8) / 12).saturating_sub(1)
                && expanded <= body.saturating_add(1).saturating_mul(4096)
                && if kind == CT_7_BIT {
                    h.data.get(17).is_some_and(|&c| c < 0x80)
                } else {
                    h.data.get(18).is_none_or(|&c| c & 1 == 0)
                }
        }
        _ => false,
    }
}

record! {
    /// `CArcCompress`.
    pub struct ArcHeader {
        compressed_size: u64 "compressed_size"
            .desc("Size of the whole file, this header included")
            .with(|&v, n| n.summary(fmt::size(v))),
        expanded_size: u64 "expanded_size" .with(|&v, n| n.summary(fmt::size(v))),
        compression_type: u8 "compression_type" .enumeration(TYPES),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, Endian::Little);
    let (header, span) = cur.record::<ArcHeader>().await?;
    cx.emit(ArcHeader::node("Header", span, Endian::Little));
    let body = file.tail(ArcHeader::SIZE);
    let what = match header.compression_type {
        CT_NONE => "stored",
        CT_7_BIT => "LZW, 7-bit characters",
        CT_8_BIT => "LZW, 8-bit characters",
        _ => "unknown compression type",
    };
    let size = header.compressed_size.min(file.len);
    // The file's name says what the expanded data is (`Foo.HC.Z`); a
    // file system passes it on with `Node::known_as`.
    let name = cx.node_name();
    let (span, expected) = (file.sub(0, size), Some(header.expanded_size));
    let mut expanded = match format_by_name(&name) {
        Some(format) => content_named("Expanded", input, span, Codec::TempleOsZ, expected, format),
        None => content("Expanded", input, span, Codec::TempleOsZ, expected),
    };
    if let Some(inner) = strip_z(&name) {
        expanded = expanded.known_as(inner.to_owned());
    }
    cx.emit(expanded.summary(fmt::size(header.expanded_size)));
    cx.emit(
        Node::new(if header.compression_type == CT_NONE {
            "Stored data"
        } else {
            "Compressed data"
        })
        .span(body),
    );
    cx.annotate(format!(
        "TempleOS compressed file ({what}), {} → {}",
        fmt::size(file.len),
        fmt::size(header.expanded_size)
    ));
    Ok(())
}
