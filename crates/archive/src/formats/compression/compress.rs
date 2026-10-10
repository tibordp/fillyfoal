//! Classic Unix compressors: `compress` (`.Z`, LZW; decoded on demand) and
//! `pack` (`.z`, static Huffman; header only).

use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::unsupported;
use crate::formats::util::fmt;
use crate::formats::util::val::uint;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::{FlagTable, field, flag};

pub static COMPRESS: Format = Format {
    name: "compress",
    title: "compress (LZW) data",
    extensions: &["Z", "taz", "tZ"],
    mime: "application/x-compress",
    probe: Probe::Custom(probe_compress),
    dissect: crate::expander!(dissect_compress: Input),
};

pub static PACK: Format = Format {
    name: "pack",
    title: "pack (Huffman) data",
    extensions: &["z"],
    mime: "application/x-pack",
    probe: Probe::Custom(probe_pack),
    dissect: crate::expander!(dissect_pack: Input),
};

fn probe_compress(h: &Head<'_>) -> bool {
    h.starts_with(b"\x1f\x9d")
        && h.data
            .get(2)
            .is_some_and(|&b| (9..=16).contains(&(b & 0x1f)) && b & 0x60 == 0)
}

fn probe_pack(h: &Head<'_>) -> bool {
    h.starts_with(b"\x1f\x1e") && h.data.get(6).is_some_and(|&l| (1..=24).contains(&l))
}

const LZW_FLAGS: FlagTable = &[
    flag(0x80, "BLOCK_MODE"),
    flag(0x20, "RESERVED_20"),
    flag(0x40, "RESERVED_40"),
    field(0x1f, 9, "MAX_BITS_9"),
    field(0x1f, 10, "MAX_BITS_10"),
    field(0x1f, 11, "MAX_BITS_11"),
    field(0x1f, 12, "MAX_BITS_12"),
    field(0x1f, 13, "MAX_BITS_13"),
    field(0x1f, 14, "MAX_BITS_14"),
    field(0x1f, 15, "MAX_BITS_15"),
    field(0x1f, 16, "MAX_BITS_16"),
];

record! {
    pub struct CompressHeader {
        magic: bytes[2] "Magic",
        flags: u8 "Flags"
            .flags(LZW_FLAGS)
            .with(|&f, n| n.summary(format!("up to {}-bit codes", f & 0x1f))),
    }
}

pub async fn dissect_compress(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, Endian::Little);
    let (header, span) = cur.record::<CompressHeader>().await?;
    cx.emit(CompressHeader::node("Header", span, Endian::Little));
    let body = input.span.tail(CompressHeader::SIZE);
    cx.emit(crate::formats::content(
        "Decompressed",
        input,
        input.span,
        crate::codec::Codec::UnixCompress,
        None,
    ));
    cx.emit(Node::new("Compressed data").span(body));
    let mode = if header.flags & 0x80 != 0 {
        ", block mode"
    } else {
        ""
    };
    cx.annotate(format!(
        "compress, {}-bit LZW{mode}, {} compressed",
        header.flags & 0x1f,
        fmt::size(body.len)
    ));
    Ok(())
}

/// pack's header: magic, original size, then the Huffman tree as leaf
/// counts per level followed by the leaf characters.
fn pack_header(f: &mut Fields<'_>, _: &()) -> Result<u64> {
    f.bytes("Magic", 2).emit()?;
    f.u32("Original size")
        .with(|&s, n| n.summary(fmt::size(s.into())))
        .emit()?;
    let levels = f.u8("Tree depth").emit()?;
    let mut leaves = 0u64;
    for level in 1..=levels {
        let start = f.pos();
        let mut n = u64::from(f.u8("Leaves").get()?);
        if level == levels {
            n = n.saturating_add(2); // stored minus two, the EOF leaf included
        }
        let span = f.block().span.sub(start, 1);
        f.node(
            Node::new(format!("Leaves at level {level}"))
                .span(span)
                .value(uint(n, 64)),
        );
        leaves = leaves.saturating_add(n);
    }
    // The EOF leaf is implicit.
    let chars = leaves.saturating_sub(1);
    f.bytes("Leaf characters", chars).emit()?;
    Ok(f.pos())
}

pub async fn dissect_pack(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = file.sub(0, 287); // header, 24 levels, 256 leaves
    let len = crate::fields::parse(&cx, head, Endian::Big, &(), pack_header).await?;
    let size = cx.read(file.sub(2, 4)).await?;
    let size = crate::bytes::u32_be(&size, 0).unwrap_or(0);
    cx.emit(struct_node(
        "Header",
        file.sub(0, len),
        Endian::Big,
        (),
        pack_header,
    ));
    cx.emit(unsupported(
        "Compressed data",
        file.tail(len),
        "pack Huffman",
    ));
    cx.annotate(format!("pack, {} uncompressed", fmt::size(size.into())));
    Ok(())
}
