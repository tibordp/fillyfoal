//! LevelDB and RocksDB sorted string tables (`.ldb`, `.sst`): located from
//! the footer at the end, which points at the index block (one entry per
//! data block) and the meta-index block (filters, properties).
//!
//! Blocks hold prefix-compressed entries followed by a restart array; each
//! block has a 5-byte trailer with its compression type and a masked
//! CRC-32C, which is verified. Compressed blocks (Snappy; LevelDB zstd;
//! RocksDB zlib, bzip2, LZ4 and ZSTD) are decompressed into derived sources.
//! RocksDB format version 4 and later index encodings, version 6 footers
//! and XXH3 checksums are not handled.

use crate::bytes::{to_u64, to_usize, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const LEVELDB_MAGIC: u64 = 0xdb47_7524_8b80_fb57;
const ROCKSDB_MAGIC: u64 = 0x88e2_41b7_85f4_cff7;
/// Largest block read.
const MAX_BLOCK: u64 = 64 << 20;

pub static LEVELDB: Format = Format {
    name: "leveldb-sst",
    title: "LevelDB table",
    extensions: &["ldb", "sst"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| magic(h) == Some(LEVELDB_MAGIC)),
    dissect: crate::expander!(dissect: Input),
};

pub static ROCKSDB: Format = Format {
    name: "rocksdb-sst",
    title: "RocksDB table",
    extensions: &["sst"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| magic(h) == Some(ROCKSDB_MAGIC)),
    dissect: crate::expander!(dissect: Input),
};

fn magic(h: &Head<'_>) -> Option<u64> {
    if h.len < 48 {
        return None;
    }
    u64_le(h.tail, h.tail.len().checked_sub(8)?)
}

const COMPRESSION: EnumTable = &[
    (0, "none"),
    (1, "Snappy"),
    (2, "zlib"),
    (3, "BZip2"),
    (4, "LZ4"),
    (5, "LZ4HC"),
    (6, "Xpress"),
    (7, "ZSTD"),
];

const CHECKSUMS: EnumTable = &[
    (0, "none"),
    (1, "CRC-32C"),
    (2, "xxHash"),
    (3, "xxHash64"),
    (4, "XXH3"),
];

fn varint(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let (v, n) = crate::bytes::uleb128(data.get(at..)?)?;
    Some((v, at.checked_add(n)?))
}

/// A block handle (offset, size) at `at`.
fn handle(data: &[u8], at: usize) -> Option<(u64, u64, usize)> {
    let (offset, e) = varint(data, at)?;
    let (size, e) = varint(data, e)?;
    Some((offset, size, e))
}

#[allow(clippy::arithmetic_side_effects)] // CRC arithmetic is modular by design
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn mask(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

/// Which table flavour a block belongs to: compression type numbers and
/// framing differ between LevelDB and RocksDB (and its format versions).
#[derive(Clone, Copy)]
struct Flavor {
    rocks: bool,
    version: u32,
}

#[derive(Clone, Copy)]
enum BlockKind {
    Index,
    Meta,
    Data,
    Properties,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let tail_len = file.len.min(53);
    let tail_span = file.sub(file.len.saturating_sub(tail_len), tail_len);
    let tail = cx.read(tail_span).await?;
    let magic = u64_le(&tail, tail.len().saturating_sub(8)).unwrap_or(0);
    let rocks = magic == ROCKSDB_MAGIC;
    // RocksDB footers: checksum type, handles, padding, format version, magic.
    let footer_len: usize = if rocks { 53 } else { 48 };
    let footer_span = file.sub(
        file.len.saturating_sub(to_u64(footer_len)),
        to_u64(footer_len),
    );
    let footer = tail
        .get(tail.len().saturating_sub(footer_len)..)
        .unwrap_or_default();
    let at = usize::from(rocks);
    let flavor = Flavor {
        rocks,
        version: if rocks { u32_le(footer, 41).unwrap_or(0) } else { 0 },
    };
    let (meta_off, meta_size, e) = handle(footer, at)
        .ok_or_else(|| Diagnostic::malformed("invalid meta-index handle").at(footer_span))?;
    let (index_off, index_size, _) = handle(footer, e)
        .ok_or_else(|| Diagnostic::malformed("invalid index handle").at(footer_span))?;
    let index = block_entries(&cx, file, index_off, index_size, flavor).await;
    let blocks = index.as_ref().map_or(0, Vec::len);
    cx.annotate(format!(
        "{} table, {blocks} data block{}",
        if rocks { "RocksDB" } else { "LevelDB" },
        if blocks == 1 { "" } else { "s" }
    ));
    cx.emit(
        Node::new("Index block")
            .span(file.sub(index_off, index_size.saturating_add(5)))
            .summary(format!("{blocks} entries"))
            .lazy(block, (input, index_off, index_size, BlockKind::Index, flavor)),
    );
    cx.emit(
        Node::new("Meta-index block")
            .span(file.sub(meta_off, meta_size.saturating_add(5)))
            .lazy(block, (input, meta_off, meta_size, BlockKind::Meta, flavor)),
    );
    cx.emit(
        Node::new("Footer")
            .span(footer_span)
            .lazy(footer_fields, (input, rocks)),
    );
    if let Err(e) = index {
        cx.diag(e);
    }
    Ok(())
}

async fn footer_fields(cx: Cx, (input, rocks): (Input, bool)) -> Result<()> {
    let file = input.span;
    let footer_len: u64 = if rocks { 53 } else { 48 };
    let span = file.sub(file.len.saturating_sub(footer_len), footer_len);
    let footer = cx.read(span).await?;
    let mut at = 0usize;
    if rocks {
        let c = footer.first().copied().unwrap_or(0);
        cx.emit(
            Node::new("Checksum type")
                .span(span.sub(0, 1))
                .value(Value::Enum {
                    raw: c.into(),
                    bits: 8,
                    name: lookup(CHECKSUMS, c.into()),
                }),
        );
        at = 1;
    }
    for name in ["Meta-index handle", "Index handle"] {
        let Some((off, size, e)) = handle(&footer, at) else {
            return Err(Diagnostic::malformed("invalid block handle").at(span));
        };
        cx.emit(
            Node::new(name)
                .span(span.sub(to_u64(at), to_u64(e.saturating_sub(at))))
                .value(Value::UInt {
                    value: off,
                    bits: 64,
                    radix: Radix::Hex,
                })
                .summary(format!("{size} bytes"))
                .target(file.sub(off, size)),
        );
        at = e;
    }
    if rocks {
        cx.emit(
            Node::new("Format version")
                .span(span.sub(41, 4))
                .value(Value::UInt {
                    value: u32_le(&footer, 41).unwrap_or(0).into(),
                    bits: 32,
                    radix: Radix::Dec,
                }),
        );
    }
    let magic_at = footer_len.saturating_sub(8);
    cx.emit(
        Node::new("Magic")
            .span(span.sub(magic_at, 8))
            .value(Value::UInt {
                value: u64_le(&footer, to_usize(magic_at)).unwrap_or(0),
                bits: 64,
                radix: Radix::Hex,
            }),
    );
    Ok(())
}

/// One decoded entry: key, value, and the entry's range in the block.
struct Entry {
    key: Vec<u8>,
    value: (usize, usize),
    range: (usize, usize),
}

/// Decodes the entries of a block (without its restart array).
fn entries(data: &[u8]) -> Result<Vec<Entry>> {
    let restarts = to_usize(u64::from(
        u32_le(data, data.len().saturating_sub(4)).unwrap_or(0),
    ));
    let end = data
        .len()
        .checked_sub(4)
        .and_then(|e| e.checked_sub(restarts.checked_mul(4)?))
        .ok_or_else(|| Diagnostic::malformed("restart array does not fit"))?;
    let mut out = Vec::new();
    let mut key: Vec<u8> = Vec::new();
    let mut at = 0usize;
    while at < end {
        let bad = || Diagnostic::malformed(format!("invalid entry at {at:#x}"));
        let (shared, e) = varint(data, at).ok_or_else(bad)?;
        let (unshared, e) = varint(data, e).ok_or_else(bad)?;
        let (value_len, e) = varint(data, e).ok_or_else(bad)?;
        let shared = to_usize(shared);
        if shared > key.len() {
            return Err(bad());
        }
        key.truncate(shared);
        let k_end = e
            .checked_add(to_usize(unshared))
            .filter(|&k| k <= end)
            .ok_or_else(bad)?;
        key.extend_from_slice(data.get(e..k_end).unwrap_or_default());
        let v_end = k_end
            .checked_add(to_usize(value_len))
            .filter(|&v| v <= end)
            .ok_or_else(bad)?;
        out.push(Entry {
            key: key.clone(),
            value: (k_end, v_end),
            range: (at, v_end),
        });
        at = v_end;
    }
    Ok(out)
}

/// Reads a block's contents (uncompressed only) and checks its trailer.
async fn read_block(
    cx: &Cx,
    file: Span,
    offset: u64,
    size: u64,
) -> Result<(Vec<u8>, u8, Option<Diagnostic>)> {
    if size > MAX_BLOCK {
        return Err(Diagnostic::limit("block larger than 64 MiB").at(file.sub(offset, size)));
    }
    let data = cx.read(file.sub_exact(offset, size)?).await?;
    let trailer = cx
        .read(file.sub_exact(offset.saturating_add(size), 5)?)
        .await?;
    let kind = trailer.first().copied().unwrap_or(0);
    let stored = u32_le(&trailer, 1).unwrap_or(0);
    let mut whole = data.clone();
    whole.push(kind);
    let diag = (mask(crc32c(&whole)) != stored)
        .then(|| Diagnostic::warning("block checksum mismatch (CRC-32C)"));
    Ok((data, kind, diag))
}

async fn block_entries(cx: &Cx, file: Span, offset: u64, size: u64, flavor: Flavor) -> Result<Vec<Entry>> {
    let (data, kind, _) = read_block(cx, file, offset, size).await?;
    let (data, _) = decompress(cx, file.sub(offset, size), data, kind, flavor).await?;
    entries(&data)
}

/// The plain bytes of a block and their span (in a derived source when the
/// block is compressed).
async fn decompress(cx: &Cx, span: Span, data: Vec<u8>, kind: u8, flavor: Flavor) -> Result<(Vec<u8>, Span)> {
    use crate::codec::Codec;
    let codec = match (kind, flavor.rocks) {
        (0, _) => return Ok((data, span)),
        (1, _) => Codec::Snappy,
        (2, false) => Codec::Zstd,
        (2, true) => Codec::Deflate,
        (3, true) => Codec::Bzip2,
        (4 | 5, true) => Codec::Lz4Block,
        (7, true) => Codec::Zstd,
        _ => {
            return Err(Diagnostic::unsupported(format!(
                "{} compression",
                lookup(COMPRESSION, kind.into()).unwrap_or("unknown")
            ))
            .at(span));
        }
    };
    // RocksDB (format version 2 and later) prefixes all but Snappy with the
    // decoded size as a varint32; version 1 gave LZ4 an 8-byte size.
    let (skip, expected) = match (kind, flavor.rocks) {
        (2 | 3 | 4 | 5 | 7, true) if flavor.version >= 2 => {
            let (size, end) = varint(&data, 0).ok_or_else(|| Diagnostic::malformed("bad size prefix").at(span))?;
            (end, Some(size))
        }
        (4 | 5, true) => (8, u64_le(&data, 0)),
        _ => (0, None),
    };
    let skip = to_u64(skip);
    let decoded =
        crate::codec::decode_span(cx, span.sub(skip, span.len.saturating_sub(skip)), &codec, expected).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    Ok((crate::codec::read_all(cx, decoded.span).await?, decoded.span))
}

fn text(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(s) if !s.chars().any(char::is_control) => Value::Text(s.to_owned()),
        _ => Value::Bytes(bytes.iter().take(32).copied().collect()),
    }
}

const VALUE_TYPES: EnumTable = &[
    (0, "deletion"),
    (1, "value"),
    (2, "merge"),
    (7, "single deletion"),
    (0xf, "range deletion"),
];

/// A data block key: user key plus (sequence << 8 | type).
fn internal_key(key: &[u8]) -> (Value, String) {
    if key.len() < 8 {
        return (text(key), String::new());
    }
    let (user, trailer) = key.split_at(key.len().saturating_sub(8));
    let t = u64_le(trailer, 0).unwrap_or(0);
    let kind = lookup(VALUE_TYPES, t & 0xff).unwrap_or("unknown type");
    (text(user), format!("seq {}, {kind}", t >> 8))
}

async fn block(cx: Cx, (input, offset, size, kind, flavor): (Input, u64, u64, BlockKind, Flavor)) -> Result<()> {
    let file = input.span;
    let (data, compression, diag) = read_block(&cx, file, offset, size).await?;
    if let Some(d) = diag {
        cx.diag(d);
    }
    let span = file.sub(offset, size);
    match decompress(&cx, span, data, compression, flavor).await {
        Err(e) => cx.emit(Node::new("Contents").span(span).diag(e)),
        Ok((data, span)) => {
            let list = entries(&data)?;
            cx.set_count(Count::AtLeast(to_u64(list.len())));
            for (i, e) in list.iter().enumerate() {
                let range = span.sub(
                    to_u64(e.range.0),
                    to_u64(e.range.1.saturating_sub(e.range.0)),
                );
                let value = data.get(e.value.0..e.value.1).unwrap_or_default();
                let node = match kind {
                    BlockKind::Index | BlockKind::Meta => {
                        let (off, len, _) = handle(value, 0).unwrap_or((0, 0, 0));
                        let name = String::from_utf8_lossy(&e.key).into_owned();
                        let sub = match kind {
                            BlockKind::Meta if name == "rocksdb.properties" => {
                                Some(BlockKind::Properties)
                            }
                            BlockKind::Meta => None,
                            _ => Some(BlockKind::Data),
                        };
                        let label = if matches!(kind, BlockKind::Index) {
                            format!("Data block {i}")
                        } else {
                            name.clone()
                        };
                        let mut node = Node::new(label)
                            .span(range)
                            .value(Value::UInt {
                                value: off,
                                bits: 64,
                                radix: Radix::Hex,
                            })
                            .summary(if matches!(kind, BlockKind::Index) {
                                format!(
                                    "{len} bytes, keys up to {}",
                                    crate::render::value(&internal_key(&e.key).0)
                                )
                            } else {
                                format!("{len} bytes")
                            })
                            .target(file.sub(off, len));
                        if let Some(sub) = sub {
                            node = node.lazy(
                                crate::expander!(self::block: (Input, u64, u64, BlockKind, Flavor)),
                                (input, off, len, sub, flavor),
                            );
                        }
                        node
                    }
                    BlockKind::Data => {
                        let (key, detail) = internal_key(&e.key);
                        let label = crate::render::value(&key);
                        Node::new(label)
                            .span(range)
                            .value(text(value))
                            .summary(detail)
                    }
                    BlockKind::Properties => Node::new(String::from_utf8_lossy(&e.key).into_owned())
                        .span(range)
                        .value(property(value)),
                };
                cx.push(node).await;
            }
        }
    }
    cx.emit(
        Node::new("Trailer")
            .span(file.sub(offset.saturating_add(size), 5))
            .value(Value::Enum {
                raw: compression.into(),
                bits: 8,
                name: lookup(COMPRESSION, compression.into()),
            }),
    );
    Ok(())
}

/// RocksDB properties: numbers are varints, names are text.
fn property(value: &[u8]) -> Value {
    match varint(value, 0) {
        Some((v, e)) if e == value.len() => Value::UInt {
            value: v,
            bits: 64,
            radix: Radix::Dec,
        },
        _ => text(value),
    }
}
