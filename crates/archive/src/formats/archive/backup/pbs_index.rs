//! Proxmox Backup Server index files: the dynamic index (`.didx`) of a
//! file archive or other stream cut into variable-sized chunks, and the
//! fixed index (`.fidx`) of a disk image cut into chunks of one size.
//!
//! Both start with a 4096-byte header: an 8-byte magic, the index's UUID,
//! its creation time (seconds since 1970, the snapshot's backup time) and
//! the SHA-256 of all the entries after the header; a fixed index adds the
//! image size and the chunk size. The rest is reserved. A dynamic index
//! then holds 40-byte entries, each a chunk's end offset in the stream
//! (little-endian) and its SHA-256 digest; a fixed index holds only the
//! 32-byte digests, chunk `i` covering `i * chunk_size` onwards. A digest
//! names the chunk's blob in the datastore (`.chunks/<first 4 hex
//! digits>/<digest>`), which is a separate file, so the content itself is
//! not reachable from the index.
//!
//! The layout is from Proxmox Backup's `docs/file-formats.rst` and
//! `pbs-datastore/src/dynamic_index.rs` / `fixed_index.rs` (AGPL-3.0),
//! read for facts only; the checksum (SHA-256 over the raw entries) was
//! confirmed against indexes and their `index.json.blob` manifest written
//! by proxmox-backup-client 3.4.9.

use crate::bytes::{to_u64, u64_le};
use crate::codec::crypto::{Hash, Sha256};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::uuid_value;
use crate::formats::util::fmt::{grouped_count, hex_lower, size};
use crate::formats::util::val::hex;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;

const DYNAMIC: [u8; 8] = [28, 145, 78, 165, 25, 186, 179, 205];
const FIXED: [u8; 8] = [47, 127, 65, 237, 145, 253, 15, 205];
/// The header's size; entries start after it.
const HEADER: u64 = 4096;
/// Indexes whose entries take at most this many bytes have their checksum
/// verified when the file is opened; larger ones when it is expanded.
const EAGER_CSUM: u64 = 1 << 20;
/// Entries read at a time while listing.
const BATCH: u64 = 256;
/// The SHA-256 of 4 MiB of zeros: the digest of every unencrypted
/// all-zero chunk of a disk image with the default chunk size.
const ZERO_CHUNK: [u8; 32] = [
    0xbb, 0x9f, 0x8d, 0xf6, 0x14, 0x74, 0xd2, 0x5e, 0x71, 0xfa, 0x00, 0x72, 0x23, 0x18, 0xcd, 0x38,
    0x73, 0x96, 0xca, 0x17, 0x36, 0x60, 0x5e, 0x12, 0x48, 0x82, 0x1c, 0xc0, 0xde, 0x3d, 0x3a, 0xf8,
];

pub static DIDX: Format = Format {
    name: "pbs-didx",
    title: "Proxmox Backup Server dynamic index",
    extensions: &["didx"],
    mime: "application/x-proxmox-backup-didx",
    probe: Probe::Magic(&[(0, &DYNAMIC)]),
    dissect: crate::expander!(dissect_dynamic: Input),
};

pub static FIDX: Format = Format {
    name: "pbs-fidx",
    title: "Proxmox Backup Server fixed index",
    extensions: &["fidx"],
    mime: "application/x-proxmox-backup-fidx",
    probe: Probe::Magic(&[(0, &FIXED)]),
    dissect: crate::expander!(dissect_fixed: Input),
};

fn time_value(&v: &i64, node: Node) -> Node {
    node.value(Value::Timestamp { unix_seconds: v })
}

#[allow(clippy::ptr_arg)] // used as a `Field::with` decorator
fn digest_value(b: &Vec<u8>, node: Node) -> Node {
    node.value(Value::Text(hex_lower(b)))
}

record! {
    /// `DynamicIndexHeader`, without its reserved tail.
    pub struct DynamicHeader {
        _magic: bytes[8] "Magic",
        _uuid: bytes[16] "UUID" .with(uuid_value),
        _ctime: i64 "Creation time" .with(time_value),
        csum: bytes[32] "Index checksum" .with(digest_value)
            .desc("SHA-256 of all the entries after the header"),
    }
}

record! {
    /// `FixedIndexHeader`, without its reserved tail.
    pub struct FixedHeader {
        _magic: bytes[8] "Magic",
        _uuid: bytes[16] "UUID" .with(uuid_value),
        _ctime: i64 "Creation time" .with(time_value),
        csum: bytes[32] "Index checksum" .with(digest_value)
            .desc("SHA-256 of all the entries after the header"),
        image_size: u64 "Size" .with(|&v, n| n.summary(size(v))) .desc("Size of the image"),
        chunk_size: u64 "Chunk size" .with(|&v, n| n.summary(size(v))),
    }
}

/// What the entry lists need.
#[derive(Clone, Copy)]
struct Index {
    entries: Span,
    /// Entry size: 40 (dynamic) or 32 (fixed).
    entry: u64,
    count: u64,
    /// Fixed index: image size and chunk size.
    image: u64,
    chunk_size: u64,
}

/// The SHA-256 of `entries`, read in pieces.
async fn csum_of(cx: &Cx, entries: Span) -> Result<Vec<u8>> {
    let mut h = Sha256::new();
    let mut off = 0u64;
    while off < entries.len {
        let piece = cx.read(entries.sub(off, 1 << 16)).await?;
        if piece.is_empty() {
            break;
        }
        for part in piece.chunks(crate::formats::util::datakit::HASH_UNIT) {
            h.update(part);
            cx.checkpoint().await;
        }
        off = off.saturating_add(to_u64(piece.len()));
    }
    Ok(h.finish())
}

fn csum_node(span: Span, stored: &[u8], computed: &[u8]) -> Node {
    let node = Node::new("Checksum")
        .span(span)
        .value(Value::Text(hex_lower(computed)))
        .desc("SHA-256 of the entries, computed");
    if stored == computed {
        node.summary("valid")
    } else {
        node.diag(Diagnostic::malformed(
            "index checksum mismatch: the entries do not match the header",
        ))
    }
}

/// Emits the header, the reserved area, the checksum and the chunk list.
async fn common(cx: &Cx, file: Span, header: Node, csum: Vec<u8>, index: Index) -> Result<()> {
    cx.emit(header);
    cx.emit(
        Node::new("Reserved")
            .span(file.sub(
                index.fields_len(),
                HEADER.saturating_sub(index.fields_len()),
            ))
            .summary(size(HEADER.saturating_sub(index.fields_len()))),
    );
    let entries = index.entries;
    if entries.len <= EAGER_CSUM {
        let computed = csum_of(cx, entries).await?;
        cx.emit(csum_node(entries, &csum, &computed));
    } else {
        cx.emit(
            Node::new("Checksum")
                .span(entries)
                .desc("SHA-256 of the entries, computed when expanded")
                .lazy(csum_expand, (entries, csum)),
        );
    }
    let mut chunks =
        Node::new("Chunks")
            .span(entries)
            .summary(grouped_count(index.count, "chunk", "chunks"));
    let rest = entries.len.checked_rem(index.entry).unwrap_or(0);
    if rest != 0 {
        chunks = chunks.diag(Diagnostic::malformed(format!(
            "{rest} trailing bytes after the last whole entry"
        )));
    }
    cx.emit(chunks.lazy(list, index));
    Ok(())
}

impl Index {
    /// Bytes of the header that are fields rather than reserved.
    fn fields_len(&self) -> u64 {
        if self.entry == 40 {
            DynamicHeader::SIZE
        } else {
            FixedHeader::SIZE
        }
    }
}

async fn csum_expand(cx: Cx, (entries, stored): (Span, Vec<u8>)) -> Result<()> {
    let computed = csum_of(&cx, entries).await?;
    cx.emit(csum_node(entries, &stored, &computed).renamed("Computed"));
    Ok(())
}

pub async fn dissect_dynamic(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, DynamicHeader::SIZE);
    let h = parse(&cx, span, LE, &(), DynamicHeader::layout).await?;
    let entries = file.tail(HEADER);
    let count = entries.len / 40;
    let index = Index {
        entries,
        entry: 40,
        count,
        image: 0,
        chunk_size: 0,
    };
    // The stream's size is the last chunk's end.
    let total = if count > 0 {
        let at = count.saturating_sub(1).saturating_mul(40);
        u64_le(&cx.read(entries.sub(at, 8)).await?, 0)
    } else {
        Some(0)
    };
    cx.annotate(format!(
        "Proxmox Backup dynamic index, {}{}",
        grouped_count(count, "chunk", "chunks"),
        total.map(|t| format!(", {}", size(t))).unwrap_or_default(),
    ));
    common(
        &cx,
        file,
        DynamicHeader::node("Header", span, LE),
        h.csum,
        index,
    )
    .await
}

pub async fn dissect_fixed(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, FixedHeader::SIZE);
    let h = parse(&cx, span, LE, &(), FixedHeader::layout).await?;
    let entries = file.tail(HEADER);
    let count = entries.len / 32;
    let mut header = FixedHeader::node("Header", span, LE);
    let expected = h.image_size.div_ceil(h.chunk_size.max(1));
    if h.chunk_size == 0 {
        header = header.diag(Diagnostic::malformed("chunk size is zero"));
    } else if expected != count {
        header = header.diag(Diagnostic::malformed(format!(
            "the image needs {} of {}, the index has {count}",
            grouped_count(expected, "chunk", "chunks"),
            size(h.chunk_size),
        )));
    }
    cx.annotate(format!(
        "Proxmox Backup fixed index, {}, {} of {}",
        size(h.image_size),
        grouped_count(count, "chunk", "chunks"),
        size(h.chunk_size),
    ));
    let index = Index {
        entries,
        entry: 32,
        count,
        image: h.image_size,
        chunk_size: h.chunk_size,
    };
    common(&cx, file, header, h.csum, index).await
}

/// The chunks, in order.
async fn list(cx: Cx, index: Index) -> Result<()> {
    cx.set_count(Count::Exact(index.count));
    let (mut i, mut prev_end) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while i < index.count {
        let n = BATCH.min(index.count.saturating_sub(i));
        let batch_span = index
            .entries
            .sub_exact(i.saturating_mul(index.entry), n.saturating_mul(index.entry))?;
        let batch = cx.read(batch_span).await?;
        for raw in batch.chunks_exact(crate::bytes::to_usize(index.entry)) {
            let span = index
                .entries
                .sub(i.saturating_mul(index.entry), index.entry);
            let mark = (i, prev_end);
            cx.mark(move || mark);
            let node = if index.entry == 40 {
                let end = u64_le(raw, 0).unwrap_or(0);
                let digest = raw.get(8..).unwrap_or_default();
                let node = dynamic_chunk(i, span, prev_end, end, digest);
                prev_end = end.max(prev_end);
                node
            } else {
                fixed_chunk(&index, i, span, raw)
            };
            cx.push(node).await;
            i = i.saturating_add(1);
        }
    }
    Ok(())
}

fn digest_desc() -> &'static str {
    "SHA-256 of the chunk's content; its blob is .chunks/<first 4 hex digits>/<digest> in the datastore"
}

fn dynamic_chunk(i: u64, span: Span, start: u64, end: u64, digest: &[u8]) -> Node {
    let len = end.saturating_sub(start);
    let mut node = Node::new(format!("Chunk {i}"))
        .span(span)
        .value(Value::Text(hex_lower(digest)))
        .summary(format!("{} at {start:#x}", size(len)))
        .desc(digest_desc())
        .lazy(dynamic_fields, span);
    if end < start {
        node = node.diag(Diagnostic::malformed(format!(
            "ends at {end:#x}, before the previous chunk's end {start:#x}"
        )));
    } else if end == start {
        node = node.diag(Diagnostic::warning("empty chunk"));
    }
    node
}

async fn dynamic_fields(cx: Cx, span: Span) -> Result<()> {
    let raw = cx.read(span).await?;
    if let Some(end) = u64_le(&raw, 0) {
        cx.emit(
            Node::new("End offset")
                .span(span.sub(0, 8))
                .value(hex(end, 64)),
        );
    }
    cx.emit(
        Node::new("Digest")
            .span(span.sub(8, 32))
            .value(Value::Text(hex_lower(raw.get(8..).unwrap_or_default()))),
    );
    Ok(())
}

fn fixed_chunk(index: &Index, i: u64, span: Span, digest: &[u8]) -> Node {
    let start = i.saturating_mul(index.chunk_size);
    let len = index.chunk_size.min(index.image.saturating_sub(start));
    let mut summary = format!("{} at {start:#x}", size(len));
    if len == 4 << 20 && digest == ZERO_CHUNK {
        summary.push_str(", zeros");
    }
    let mut node = Node::new(format!("Chunk {i}"))
        .span(span)
        .value(Value::Text(hex_lower(digest)))
        .summary(summary)
        .desc(digest_desc());
    if index.chunk_size > 0 && start >= index.image {
        node = node.diag(Diagnostic::malformed("beyond the end of the image"));
    }
    node
}
