//! LevelDB and RocksDB sorted string tables (`.ldb`, `.sst`): located from
//! the footer at the end, which points at the meta-index block (filters,
//! properties) and the index block (one entry per data block).
//!
//! Blocks hold prefix-compressed entries followed by a restart array; each
//! block has a 5-byte trailer with its compression type and a checksum,
//! which is verified (CRC-32C for LevelDB; for RocksDB the footer's type:
//! CRC-32C, xxHash32, xxHash64 or XXH3, plus the per-block context of
//! format version 6). Compressed blocks (Snappy; LevelDB zstd; RocksDB zlib,
//! bzip2, LZ4 and ZSTD) are decompressed into derived sources.
//!
//! RocksDB footers (table/format.cc): versions 1 to 5 hold the checksum
//! type, both block handles and the format version; version 6 holds the
//! checksum type, an extended magic, a footer checksum, a base context
//! checksum and the meta-index size, with the meta-index right before the
//! footer and the index handle in it (`rocksdb.index`). Index blocks may
//! have user keys (no sequence trailer) and, from version 4, delta-encoded
//! values, as the table properties say. Not handled: data blocks with a hash
//! index, partitioned indexes and indexes with first keys.

mod xxh3;

use crate::bytes::{to_u64, to_usize, u32_le, u64_le};
use crate::codec::crc::crc32c_update;
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
/// Largest block whose xxHash32 is checked (it is computed in one piece).
const MAX_XXH32: usize = 4 << 20;
/// Most entries read from a meta-index or properties block for lookups.
const MAX_META_ENTRIES: usize = 4096;
/// RocksDB footer length (format version 1 and later).
const ROCKS_FOOTER: u64 = 53;
/// LevelDB (and legacy RocksDB) footer length.
const LEVEL_FOOTER: u64 = 48;
/// Block trailer: compression type and checksum.
const TRAILER: u64 = 5;
/// Format version 6's extended magic, after the checksum type.
const EXTENDED_MAGIC: [u8; 4] = [0x3e, 0x00, 0x7a, 0x00];

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

/// Which table flavour a block belongs to: compression type numbers,
/// checksums and index encodings differ between LevelDB and RocksDB (and
/// its format versions).
#[derive(Clone, Copy)]
struct Flavor {
    rocks: bool,
    version: u32,
    /// Checksum type (CRC-32C for LevelDB).
    checksum: u8,
    /// Format version 6's base context checksum (0: none).
    base: u32,
    /// Index keys are user keys, without the 8-byte sequence trailer.
    user_keys: bool,
    /// Index values are delta-encoded.
    delta: bool,
    /// The handle of the ZSTD compression dictionary
    /// (`rocksdb.compression_dict`), if the table has one.
    dict: Option<(u64, u64)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Index,
    Meta,
    Data,
    Properties,
}

/// The decoded footer.
struct Footer {
    span: Span,
    meta: (u64, u64),
    /// The index handle (from the meta-index for format version 6).
    index: Option<(u64, u64)>,
}

fn parse_footer(file: Span, tail: &[u8], flavor: &mut Flavor) -> Result<Footer> {
    let len = if flavor.rocks {
        ROCKS_FOOTER
    } else {
        LEVEL_FOOTER
    };
    let span = file.sub(file.len.saturating_sub(len), len);
    let footer = tail
        .get(tail.len().saturating_sub(to_usize(len))..)
        .unwrap_or_default();
    if flavor.rocks {
        flavor.checksum = footer.first().copied().unwrap_or(0);
        flavor.version = u32_le(footer, 41).unwrap_or(0);
    }
    if flavor.rocks && flavor.version >= 6 {
        if footer.get(1..5) != Some(&EXTENDED_MAGIC[..]) {
            return Err(Diagnostic::malformed("bad extended magic").at(span.sub(1, 4)));
        }
        flavor.base = u32_le(footer, 9).unwrap_or(0);
        let meta_size = u64::from(u32_le(footer, 13).unwrap_or(0));
        let meta_off = span
            .offset
            .saturating_sub(file.offset)
            .checked_sub(meta_size.saturating_add(TRAILER))
            .ok_or_else(|| Diagnostic::malformed("meta-index size too large").at(span))?;
        return Ok(Footer {
            span,
            meta: (meta_off, meta_size),
            index: None,
        });
    }
    let at = usize::from(flavor.rocks);
    let (meta_off, meta_size, e) = handle(footer, at)
        .ok_or_else(|| Diagnostic::malformed("invalid meta-index handle").at(span))?;
    let (index_off, index_size, _) =
        handle(footer, e).ok_or_else(|| Diagnostic::malformed("invalid index handle").at(span))?;
    Ok(Footer {
        span,
        meta: (meta_off, meta_size),
        index: Some((index_off, index_size)),
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let tail_len = file.len.min(ROCKS_FOOTER);
    let tail_span = file.sub(file.len.saturating_sub(tail_len), tail_len);
    let tail = cx.read(tail_span).await?;
    let magic = u64_le(&tail, tail.len().saturating_sub(8)).unwrap_or(0);
    let mut flavor = Flavor {
        rocks: magic == ROCKSDB_MAGIC,
        version: 0,
        checksum: 1,
        base: 0,
        user_keys: false,
        delta: false,
        dict: None,
    };
    let footer = parse_footer(file, &tail, &mut flavor)?;
    let (meta_off, meta_size) = footer.meta;
    // The meta-index names the properties block (and, from version 6, the
    // index block); the properties say how the index is encoded.
    let meta = block_kv(&cx, file, meta_off, meta_size, flavor).await;
    let named = |name: &[u8]| {
        meta.as_ref().ok().and_then(|m| {
            m.iter()
                .find(|(k, _)| k == name)
                .and_then(|(_, v)| handle(v, 0))
                .map(|(o, s, _)| (o, s))
        })
    };
    let index = footer.index.or_else(|| named(b"rocksdb.index"));
    if flavor.rocks {
        flavor.dict = named(b"rocksdb.compression_dict");
    }
    if flavor.rocks
        && let Some((off, size)) = named(b"rocksdb.properties")
        && let Ok(props) = block_kv(&cx, file, off, size, flavor).await
    {
        let flag = |name: &[u8]| {
            props
                .iter()
                .find(|(k, _)| k == name)
                .is_some_and(|(_, v)| varint(v, 0).is_some_and(|(n, _)| n != 0))
        };
        flavor.user_keys = flag(b"rocksdb.index.key.is.user.key");
        flavor.delta = flag(b"rocksdb.index.value.is.delta.encoded");
    }
    let counted = match index {
        Some((off, size)) => block_entries(&cx, file, off, size, BlockKind::Index, flavor).await,
        None => Err(Diagnostic::malformed("no index handle in the meta-index")),
    };
    let blocks = counted.as_ref().map_or(0, |n| *n);
    cx.annotate(format!(
        "{} table{}, {blocks} data block{}",
        if flavor.rocks { "RocksDB" } else { "LevelDB" },
        if flavor.rocks {
            format!(" (format version {})", flavor.version)
        } else {
            String::new()
        },
        if blocks == 1 { "" } else { "s" }
    ));
    if let Some((off, size)) = index {
        cx.emit(
            Node::new("Index block")
                .span(file.sub(off, size.saturating_add(TRAILER)))
                .summary(format!("{blocks} entries"))
                .lazy(block, (input, off, size, BlockKind::Index, flavor)),
        );
    }
    cx.emit(
        Node::new("Meta-index block")
            .span(file.sub(meta_off, meta_size.saturating_add(TRAILER)))
            .lazy(block, (input, meta_off, meta_size, BlockKind::Meta, flavor)),
    );
    cx.emit(
        Node::new("Footer")
            .span(footer.span)
            .lazy(footer_fields, (input, flavor)),
    );
    if let Err(e) = counted {
        cx.diag(e);
    }
    Ok(())
}

fn uint(value: u64, bits: u8, radix: Radix) -> Value {
    Value::UInt { value, bits, radix }
}

async fn footer_fields(cx: Cx, (input, flavor): (Input, Flavor)) -> Result<()> {
    let file = input.span;
    let footer_len = if flavor.rocks {
        ROCKS_FOOTER
    } else {
        LEVEL_FOOTER
    };
    let span = file.sub(file.len.saturating_sub(footer_len), footer_len);
    let footer = cx.read(span).await?;
    let u32_at = |at: usize| u64::from(u32_le(&footer, at).unwrap_or(0));
    let mut at = 0usize;
    if flavor.rocks {
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
    if flavor.rocks && flavor.version >= 6 {
        cx.emit(
            Node::new("Extended magic")
                .span(span.sub(1, 4))
                .value(Value::Bytes(footer.get(1..5).unwrap_or_default().to_vec())),
        );
        // The footer's checksum covers the footer with this field zeroed,
        // plus the context of the footer's offset.
        let stored = u32_le(&footer, 5).unwrap_or(0);
        let mut zeroed = footer.clone();
        if let Some(field) = zeroed.get_mut(5..9) {
            field.fill(0);
        }
        let offset = span.offset.saturating_sub(file.offset);
        let mut node = Node::new("Footer checksum")
            .span(span.sub(5, 4))
            .value(uint(stored.into(), 32, Radix::Hex));
        if let Some(sum) = checksum(&cx, flavor, &zeroed, None, offset).await
            && sum != stored
        {
            node = node.diag(Diagnostic::warning(format!(
                "footer checksum mismatch (computed {sum:#010x})"
            )));
        }
        cx.emit(node);
        cx.emit(
            Node::new("Base context checksum")
                .span(span.sub(9, 4))
                .value(uint(u32_at(9), 32, Radix::Hex))
                .desc("Mixed with each block's offset into its checksum"),
        );
        cx.emit(
            Node::new("Meta-index size")
                .span(span.sub(13, 4))
                .value(uint(u32_at(13), 32, Radix::Dec))
                .desc("The meta-index block ends right before the footer"),
        );
        cx.emit(Node::new("Padding").span(span.sub(17, 24)));
    } else {
        for name in ["Meta-index handle", "Index handle"] {
            let Some((off, size, e)) = handle(&footer, at) else {
                return Err(Diagnostic::malformed("invalid block handle").at(span));
            };
            cx.emit(
                Node::new(name)
                    .span(span.sub(to_u64(at), to_u64(e.saturating_sub(at))))
                    .value(uint(off, 64, Radix::Hex))
                    .summary(format!("{size} bytes"))
                    .target(file.sub(off, size)),
            );
            at = e;
        }
    }
    if flavor.rocks {
        cx.emit(
            Node::new("Format version")
                .span(span.sub(41, 4))
                .value(uint(u32_at(41), 32, Radix::Dec)),
        );
    }
    let magic_at = footer_len.saturating_sub(8);
    cx.emit(Node::new("Magic").span(span.sub(magic_at, 8)).value(uint(
        u64_le(&footer, to_usize(magic_at)).unwrap_or(0),
        64,
        Radix::Hex,
    )));
    Ok(())
}

/// A byte range in a block.
type Range = (usize, usize);

/// One entry: its value's and its own range in the block, and whether the
/// value is a full block handle (false: a delta-encoded index value, the
/// size difference from the previous handle).
struct Step {
    value: Range,
    range: Range,
    full: bool,
}

/// Walks the entries of a block (without its restart array), keeping only
/// the current key: keys share prefixes, so copying each one could take
/// memory quadratic in the block's size.
struct Entries {
    /// Where the restart array starts.
    end: usize,
    at: usize,
    /// Index values are delta-encoded: entries have no value length, and
    /// the value is a block handle after a key with no shared bytes, a
    /// signed size delta otherwise.
    delta: bool,
    /// The current entry's key.
    key: Vec<u8>,
}

impl Entries {
    fn new(data: &[u8], delta: bool) -> Result<Entries> {
        let restarts = to_usize(u64::from(
            u32_le(data, data.len().saturating_sub(4)).unwrap_or(0),
        ));
        let end = data
            .len()
            .checked_sub(4)
            .and_then(|e| e.checked_sub(restarts.checked_mul(4)?))
            .ok_or_else(|| Diagnostic::malformed("restart array does not fit"))?;
        Ok(Entries {
            end,
            at: 0,
            delta,
            key: Vec::new(),
        })
    }

    /// The next entry (its key is in `self.key`).
    fn next(&mut self, data: &[u8]) -> Option<Result<Step>> {
        let (at, end) = (self.at, self.end);
        if at >= end {
            return None;
        }
        let bad = || Diagnostic::malformed(format!("invalid entry at {at:#x}"));
        let step = || {
            let (shared, e) = varint(data, at)?;
            let (unshared, e) = varint(data, e)?;
            let shared = to_usize(shared);
            let (k_start, k_end, v_end) = if self.delta {
                let k_end = e.checked_add(to_usize(unshared)).filter(|&k| k <= end)?;
                let v_end = if shared == 0 {
                    handle(data, k_end)?.2
                } else {
                    varint(data, k_end)?.1
                };
                (e, k_end, v_end)
            } else {
                let (value_len, e) = varint(data, e)?;
                let k_end = e.checked_add(to_usize(unshared)).filter(|&k| k <= end)?;
                let v_end = k_end.checked_add(to_usize(value_len))?;
                (e, k_end, v_end)
            };
            Some((shared, k_start, k_end, v_end)).filter(|&(.., v)| v <= end)
        };
        let Some((shared, e, k_end, v_end)) =
            step().filter(|&(shared, ..)| shared <= self.key.len())
        else {
            self.at = end;
            return Some(Err(bad()));
        };
        self.key.truncate(shared);
        self.key
            .extend_from_slice(data.get(e..k_end).unwrap_or_default());
        self.at = v_end;
        Some(Ok(Step {
            value: (k_end, v_end),
            range: (at, v_end),
            full: !self.delta || shared == 0,
        }))
    }
}

/// The number of entries in a block, or why it does not decode.
async fn count_entries(cx: &Cx, data: &[u8], delta: bool) -> Result<usize> {
    let mut walk = Entries::new(data, delta)?;
    let mut n = 0usize;
    while let Some(entry) = walk.next(data) {
        entry?;
        n = n.saturating_add(1);
        if n.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
    }
    Ok(n)
}

/// What format version 6 adds to a block's checksum for its offset
/// (`ChecksumModifierForContext`): nothing when the base is 0.
fn context(base: u32, offset: u64) -> u32 {
    if base == 0 {
        return 0;
    }
    let (lo, hi) = (offset as u32, (offset >> 32) as u32);
    base ^ lo.wrapping_add(hi)
}

/// RocksDB's built-in checksum (`ComputeBuiltinChecksumWithLastByte`, or
/// `ComputeBuiltinChecksum` without `last`) plus the context for `offset`.
/// None: no checksum, or one not computed.
async fn checksum(
    cx: &Cx,
    flavor: Flavor,
    data: &[u8],
    last: Option<u8>,
    offset: u64,
) -> Option<u32> {
    const PIECE: usize = 64 * 1024;
    let sum = match flavor.checksum {
        1 => {
            let mut crc = !0u32;
            for piece in data.chunks(PIECE) {
                crc = crc32c_update(crc, piece);
                cx.checkpoint().await;
            }
            if let Some(b) = last {
                crc = crc32c_update(crc, &[b]);
            }
            crate::codec::crc::mask_crc32c(!crc)
        }
        2 => {
            if data.len() > MAX_XXH32 {
                return None;
            }
            let mut buf = data.to_vec();
            buf.extend(last);
            cx.checkpoint().await;
            crate::formats::util::arcutil::xxh32(&buf, 0)
        }
        3 => {
            let mut h = crate::codec::zstd::Xxh64::new(0);
            for piece in data.chunks(PIECE) {
                h.update(piece);
                cx.checkpoint().await;
            }
            if let Some(b) = last {
                h.update(&[b]);
            }
            h.finish() as u32
        }
        4 => {
            // XXH3 of all but the last byte, which then modifies it.
            let (body, b) = match last {
                Some(b) => (data, b),
                None => match data.split_last() {
                    Some((&b, body)) => (body, b),
                    None => return Some(0),
                },
            };
            let v = xxh3::xxh3_64(cx, body).await as u32;
            v ^ u32::from(b).wrapping_mul(0x6b90_83d9)
        }
        _ => return None,
    };
    Some(sum.wrapping_add(context(flavor.base, offset)))
}

/// Reads a block's contents (uncompressed only) and checks its trailer.
async fn read_block(
    cx: &Cx,
    file: Span,
    offset: u64,
    size: u64,
    flavor: Flavor,
) -> Result<(Vec<u8>, u8, Option<Diagnostic>)> {
    if size > MAX_BLOCK {
        return Err(Diagnostic::limit("block larger than 64 MiB").at(file.sub(offset, size)));
    }
    let data = cx.read(file.sub_exact(offset, size)?).await?;
    let trailer = cx
        .read(file.sub_exact(offset.saturating_add(size), TRAILER)?)
        .await?;
    let kind = trailer.first().copied().unwrap_or(0);
    let stored = u32_le(&trailer, 1).unwrap_or(0);
    let diag = match checksum(cx, flavor, &data, Some(kind), offset).await {
        Some(sum) if sum != stored => Some(Diagnostic::warning(format!(
            "block checksum mismatch ({})",
            lookup(CHECKSUMS, flavor.checksum.into()).unwrap_or("unknown")
        ))),
        None if flavor.checksum > 4 => Some(Diagnostic::unsupported(format!(
            "checksum type {}",
            flavor.checksum
        ))),
        _ => None,
    };
    Ok((data, kind, diag))
}

/// The number of entries in a block.
async fn block_entries(
    cx: &Cx,
    file: Span,
    offset: u64,
    size: u64,
    kind: BlockKind,
    flavor: Flavor,
) -> Result<usize> {
    let (data, compression, _) = read_block(cx, file, offset, size, flavor).await?;
    let (data, _) = decompress(cx, file, file.sub(offset, size), data, compression, flavor).await?;
    count_entries(cx, &data, kind == BlockKind::Index && flavor.delta).await
}

/// The keys and values of a small block (meta-index, properties), up to
/// `MAX_META_ENTRIES`.
async fn block_kv(
    cx: &Cx,
    file: Span,
    offset: u64,
    size: u64,
    flavor: Flavor,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let (data, compression, _) = read_block(cx, file, offset, size, flavor).await?;
    let (data, _) = decompress(cx, file, file.sub(offset, size), data, compression, flavor).await?;
    let mut walk = Entries::new(&data, false)?;
    let mut out = Vec::new();
    while let Some(entry) = walk.next(&data) {
        let step = entry?;
        let value = data.get(step.value.0..step.value.1).unwrap_or_default();
        out.push((walk.key.clone(), value.to_vec()));
        if out.len() >= MAX_META_ENTRIES {
            break;
        }
        if out.len().is_multiple_of(64) {
            cx.checkpoint().await;
        }
    }
    Ok(out)
}

/// The plain bytes of a block and their span (in a derived source when the
/// block is compressed).
async fn decompress(
    cx: &Cx,
    file: Span,
    span: Span,
    data: Vec<u8>,
    kind: u8,
    flavor: Flavor,
) -> Result<(Vec<u8>, Span)> {
    use crate::codec::Codec;
    let codec = match (kind, flavor.rocks) {
        (0, _) => return Ok((data, span)),
        (1, _) => Codec::Snappy,
        (2, false) => Codec::Zstd,
        (2, true) => Codec::Deflate,
        (3, true) => Codec::Bzip2,
        (4 | 5, true) => Codec::Lz4Block,
        (7, true) => match flavor.dict {
            Some((off, size)) => Codec::ZstdDict(dictionary(cx, file, off, size, flavor).await?),
            None => Codec::Zstd,
        },
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
            let (size, end) = varint(&data, 0)
                .ok_or_else(|| Diagnostic::malformed("bad size prefix").at(span))?;
            (end, Some(size))
        }
        (4 | 5, true) => (8, u64_le(&data, 0)),
        _ => (0, None),
    };
    let skip = to_u64(skip);
    let decoded = crate::codec::decode_span(
        cx,
        span.sub(skip, span.len.saturating_sub(skip)),
        &codec,
        expected,
    )
    .await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    Ok((
        crate::codec::read_all(cx, decoded.span).await?,
        decoded.span,
    ))
}

/// The table's ZSTD compression dictionary (raw samples, or a formatted
/// dictionary from zstd's trainer), parsed once per table.
async fn dictionary(
    cx: &Cx,
    file: Span,
    offset: u64,
    size: u64,
    flavor: Flavor,
) -> Result<crate::codec::zstd::Dict> {
    use crate::codec::zstd::{Dict, Dictionary};
    let span = file.sub(offset, size);
    if let Some(d) = cx.cached::<Dictionary>(span, "sst-zstd-dict") {
        return Ok(Dict(d));
    }
    let (data, kind, _) = read_block(cx, file, offset, size, flavor).await?;
    if kind != 0 {
        return Err(Diagnostic::unsupported("compressed compression dictionary").at(span));
    }
    let d = std::sync::Arc::new(Dictionary::parse(&data).map_err(|e| e.at(span))?);
    cx.cache(span, "sst-zstd-dict", d.clone());
    Ok(Dict(d))
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

/// Decodes a zigzag-encoded signed varint value (`PutVarsignedint64`).
fn zigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ 0i64.wrapping_sub((v & 1) as i64)
}

async fn block(
    cx: Cx,
    (input, offset, size, kind, flavor): (Input, u64, u64, BlockKind, Flavor),
) -> Result<()> {
    let file = input.span;
    let (data, compression, diag) = read_block(&cx, file, offset, size, flavor).await?;
    if let Some(d) = diag {
        cx.diag(d);
    }
    let span = file.sub(offset, size);
    let delta = kind == BlockKind::Index && flavor.delta;
    match decompress(&cx, file, span, data, compression, flavor).await {
        Err(e) => cx.emit(Node::new("Contents").span(span).diag(e)),
        Ok((data, span)) => {
            let n = count_entries(&cx, &data, delta).await?;
            cx.set_count(Count::AtLeast(to_u64(n)));
            let mut walk = Entries::new(&data, delta)?;
            let mut i = 0usize;
            // The previous index entry's handle, for delta-encoded values.
            let mut prev: Option<(u64, u64)> = None;
            while let Some(entry) = walk.next(&data) {
                let step = entry?;
                let key = &walk.key;
                let range = span.sub(
                    to_u64(step.range.0),
                    to_u64(step.range.1.saturating_sub(step.range.0)),
                );
                let value = data.get(step.value.0..step.value.1).unwrap_or_default();
                let node = match kind {
                    BlockKind::Index | BlockKind::Meta => {
                        let (off, len) = if step.full {
                            handle(value, 0).map_or((0, 0), |(o, l, _)| (o, l))
                        } else {
                            // The next block follows the previous one.
                            let d = varint(value, 0).map_or(0, |(v, _)| zigzag(v));
                            let (po, pl) = prev.unwrap_or((0, 0));
                            (
                                po.saturating_add(pl).saturating_add(TRAILER),
                                pl.saturating_add_signed(d),
                            )
                        };
                        prev = Some((off, len));
                        let name = String::from_utf8_lossy(key).into_owned();
                        let sub = match kind {
                            BlockKind::Meta if name == "rocksdb.properties" => {
                                Some(BlockKind::Properties)
                            }
                            BlockKind::Meta if name == "rocksdb.index" => Some(BlockKind::Index),
                            BlockKind::Meta => None,
                            _ => Some(BlockKind::Data),
                        };
                        let label = if kind == BlockKind::Index {
                            format!("Data block {i}")
                        } else {
                            name.clone()
                        };
                        let last_key = if flavor.user_keys {
                            text(key)
                        } else {
                            internal_key(key).0
                        };
                        let mut node = Node::new(label)
                            .span(range)
                            .value(uint(off, 64, Radix::Hex))
                            .summary(if kind == BlockKind::Index {
                                format!(
                                    "{len} bytes, keys up to {}",
                                    crate::render::value(&last_key)
                                )
                            } else {
                                format!("{len} bytes")
                            })
                            .target(file.sub(off, len));
                        if kind == BlockKind::Meta && name == "rocksdb.compression_dict" {
                            // A formatted zstd dictionary, or raw samples.
                            let dict = file.sub(off, len);
                            let magic = cx.read_avail(dict.sub(0, 4)).await?;
                            node = if u32_le(&magic, 0) == Some(crate::codec::zstd::DICT_MAGIC) {
                                crate::formats::embedded(name.clone(), input.nested(dict))
                            } else {
                                Node::new(name.clone())
                                    .span(dict)
                                    .desc("Raw zstd dictionary content (sampled data)")
                            }
                            .summary(format!("{len} bytes"));
                        }
                        if let Some(sub) = sub {
                            node = node.lazy(
                                crate::expander!(self::block: (Input, u64, u64, BlockKind, Flavor)),
                                (input, off, len, sub, flavor),
                            );
                        }
                        node
                    }
                    BlockKind::Data => {
                        let (key, detail) = internal_key(key);
                        let label = crate::render::value(&key);
                        Node::new(label)
                            .span(range)
                            .value(text(value))
                            .summary(detail)
                    }
                    BlockKind::Properties => Node::new(String::from_utf8_lossy(key).into_owned())
                        .span(range)
                        .value(property(value)),
                };
                cx.push(node).await;
                i = i.saturating_add(1);
            }
        }
    }
    cx.emit(
        Node::new("Trailer")
            .span(file.sub(offset.saturating_add(size), TRAILER))
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
        Some((v, e)) if e == value.len() => uint(v, 64, Radix::Dec),
        _ => text(value),
    }
}
