//! decmpfs: Apple's transparent file compression on HFS+ and APFS.
//!
//! A compressed file (BSD flag `UF_COMPRESSED`) has an empty data fork and
//! a `com.apple.decmpfs` extended attribute: the magic `fpmc`, the
//! compression type and the uncompressed size (all little-endian), then,
//! for the inline types, the compressed data itself. The other types keep
//! the data in the resource fork (`com.apple.ResourceFork` on APFS) as
//! independent 64 KiB chunks behind a table: a classic resource-fork
//! header and a `cmpf` block table for zlib, a bare offset table for LZVN
//! and LZFSE. A chunk (or inline payload) that did not compress is stored
//! as a marker byte followed by the raw bytes. Layouts as in Apple's
//! `decmpfs.c` (xnu) and the AppleFSCompression readers built from it
//! (afsctool, libfsapfs).

use crate::bytes::{to_u64, to_usize, u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::Codec;
use crate::formats::disk::PieceList;
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

/// The attribute's name.
pub const XATTR: &str = "com.apple.decmpfs";
/// `UF_COMPRESSED` in the BSD flags (`st_flags`).
pub const UF_COMPRESSED: u32 = 0x20;
const HEADER: u64 = 16;
const CHUNK: u64 = 0x1_0000;

const TYPES: EnumTable = &[
    (1, "uncompressed, inline"),
    (3, "zlib, inline"),
    (4, "zlib, resource fork"),
    (5, "sparse"),
    (7, "LZVN, inline"),
    (8, "LZVN, resource fork"),
    (9, "uncompressed, inline (type 9)"),
    (10, "uncompressed, resource fork"),
    (11, "LZFSE, inline"),
    (12, "LZFSE, resource fork"),
    (13, "LZBITMAP, inline"),
    (14, "LZBITMAP, resource fork"),
];

/// A chunk's codec and the test for the first byte of a chunk stored raw.
type ChunkCodec = (Codec, fn(u8) -> bool);

/// The attribute's fixed header.
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub kind: u32,
    pub size: u64,
}

impl Header {
    pub fn parse(b: &[u8]) -> Option<Header> {
        (b.get(..4) == Some(b"fpmc")).then(|| Header {
            kind: u32_le(b, 4).unwrap_or(0),
            size: u64_le(b, 8).unwrap_or(0),
        })
    }

    pub fn kind_name(&self) -> &'static str {
        crate::value::lookup(TYPES, self.kind.into()).unwrap_or("unknown type")
    }

    /// Whether the data is in the resource fork.
    pub fn in_resource_fork(&self) -> bool {
        matches!(self.kind, 4 | 8 | 10 | 12 | 14)
    }

    /// The codec of the compressed bytes and the first byte that marks a
    /// chunk stored raw instead.
    fn codec(&self) -> Option<ChunkCodec> {
        match self.kind {
            3 | 4 => Some((Codec::Zlib, |b| b & 0x0f == 0x0f)),
            7 | 8 => Some((Codec::Lzvn, |b| b == 0x06)),
            // LZFSE blocks start with `bvx`.
            11 | 12 => Some((Codec::Lzfse, |b| b != b'b')),
            _ => None,
        }
    }
}

record! {
    /// The attribute's fixed header (`decmpfs_disk_header`).
    pub struct DiskHeader {
        magic: ascii[4] "Magic",
        kind: u32 "Compression type" .enumeration(TYPES),
        size: u64 "Uncompressed size" .with(crate::formats::disk::size_summary),
    }
}

/// The attribute's header as a node.
pub fn header_node(span: Span, h: &Header) -> Node {
    DiskHeader::node("decmpfs header", span.sub(0, HEADER), Endian::Little).summary(format!(
        "{}, {}",
        h.kind_name(),
        super::size(h.size)
    ))
}

/// One compressed unit (`span`) that decodes to `len` bytes, or is a
/// marker byte and `len` raw bytes.
async fn unit(
    cx: &Cx,
    list: &mut PieceList,
    span: Span,
    len: u64,
    (codec, raw): &ChunkCodec,
) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    // Only a unit one byte longer than its output can be stored raw, so
    // compressed ones cost no read here.
    if span.len == len.saturating_add(1) {
        let first = cx.read(span.sub(0, 1)).await?;
        if first.first().is_some_and(|&b| raw(b)) {
            list.data(span.sub(1, len));
            return Ok(());
        }
    }
    list.data(cx.decode_lazy(span, codec, len)?);
    Ok(())
}

/// The file's bytes. `attr` is the attribute's value, `rsrc` the resource
/// fork for the types that use it.
pub async fn content(cx: &Cx, attr: Span, rsrc: Option<Span>) -> Result<(Header, Span)> {
    let head = cx.read(attr.sub_exact(0, HEADER)?).await?;
    let h = Header::parse(&head)
        .ok_or_else(|| Diagnostic::malformed("decmpfs attribute without its fpmc magic"))?;
    let mut list = PieceList::new(attr);
    let payload = attr.tail(HEADER);
    match (h.kind, h.codec()) {
        (1, _) => {
            if payload.len < h.size {
                return Err(Diagnostic::malformed("inline data shorter than the file"));
            }
            list.data(payload.sub(0, h.size));
        }
        (3 | 7 | 11, Some(codec)) => unit(cx, &mut list, payload, h.size, &codec).await?,
        (4, Some(codec)) => {
            let rsrc = rsrc.ok_or_else(|| Diagnostic::malformed("no resource fork"))?;
            zlib_chunks(cx, &mut list, rsrc, h.size, &codec).await?;
        }
        (8 | 12, Some(codec)) => {
            let rsrc = rsrc.ok_or_else(|| Diagnostic::malformed("no resource fork"))?;
            table_chunks(cx, &mut list, rsrc, h.size, &codec).await?;
        }
        _ => {
            return Err(Diagnostic::unsupported(format!(
                "decmpfs compression type {} ({})",
                h.kind,
                h.kind_name()
            )));
        }
    }
    if list.len() < h.size {
        cx.diag(Diagnostic::malformed(format!(
            "the chunks hold {} of {} bytes",
            list.len(),
            h.size
        )));
    }
    Ok((h, list.finish(cx, "decmpfs").await?))
}

/// Chunks expected for `size` bytes.
fn chunks_for(size: u64) -> u64 {
    size.div_ceil(CHUNK)
}

/// The output length of chunk `i`.
fn chunk_len(size: u64, i: u64) -> u64 {
    size.saturating_sub(i.saturating_mul(CHUNK)).min(CHUNK)
}

/// zlib in a resource fork: the resource data (after the fork's 256-byte
/// header and a 4-byte length) is a `cmpf` table of (offset, size) pairs
/// relative to the table, then the chunks.
async fn zlib_chunks(
    cx: &Cx,
    list: &mut PieceList,
    rsrc: Span,
    size: u64,
    codec: &ChunkCodec,
) -> Result<()> {
    let head = cx.read(rsrc.sub_exact(0, 4)?).await?;
    let data = u64::from(u32_be(&head, 0).unwrap_or(0));
    let table = rsrc.tail(data.saturating_add(4));
    let count = u64::from(u32_le(&cx.read(table.sub_exact(0, 4)?).await?, 0).unwrap_or(0));
    let want = chunks_for(size);
    if count != want {
        cx.diag(Diagnostic::malformed(format!(
            "{count} chunks in the table, {want} expected for the size"
        )));
    }
    let entries = cx
        .read(table.sub_exact(4, count.min(want).saturating_mul(8))?)
        .await?;
    for (i, e) in entries.as_chunks::<8>().0.iter().enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let off = u64::from(u32_le(e, 0).unwrap_or(0));
        let len = u64::from(u32_le(e, 4).unwrap_or(0));
        unit(
            cx,
            list,
            table.sub(off, len),
            chunk_len(size, to_u64(i)),
            codec,
        )
        .await?;
    }
    Ok(())
}

/// LZVN or LZFSE in a resource fork: a table of chunk offsets (one more
/// than there are chunks, the first being the table's own length), then
/// the chunks.
async fn table_chunks(
    cx: &Cx,
    list: &mut PieceList,
    rsrc: Span,
    size: u64,
    codec: &ChunkCodec,
) -> Result<()> {
    let first = u64::from(u32_le(&cx.read(rsrc.sub_exact(0, 4)?).await?, 0).unwrap_or(0));
    let count = (first / 4).saturating_sub(1);
    let want = chunks_for(size);
    if count != want || first % 4 != 0 {
        cx.diag(Diagnostic::malformed(format!(
            "{count} chunks in the table, {want} expected for the size"
        )));
    }
    let n = count.min(want);
    let table = cx
        .read(rsrc.sub_exact(0, n.saturating_add(1).saturating_mul(4))?)
        .await?;
    for i in 0..to_usize(n) {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let at = i.saturating_mul(4);
        let start = u64::from(u32_le(&table, at).unwrap_or(0));
        let end = u64::from(u32_le(&table, at.saturating_add(4)).unwrap_or(0));
        if end < start {
            return Err(Diagnostic::malformed(format!(
                "chunk {i} ends before it starts"
            )));
        }
        unit(
            cx,
            list,
            rsrc.sub(start, end.saturating_sub(start)),
            chunk_len(size, to_u64(i)),
            codec,
        )
        .await?;
    }
    Ok(())
}
