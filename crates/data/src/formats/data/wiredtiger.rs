//! WiredTiger (MongoDB's storage engine) files: B-tree files (`*.wt`,
//! including the `WiredTiger.wt` metadata table) and the
//! `WiredTiger.turtle` bootstrap file. The `WiredTiger` marker file is
//! in `embedded_db`.
//!
//! A B-tree file starts with a descriptor block (magic 120897, major and
//! minor version, CRC-32C) one allocation unit long, followed by blocks.
//! Each block is a 28-byte page header (column-store record number, write
//! generation, in-memory size, entry count or overflow data length, page
//! type, flags, version) and a 12-byte block header (on-disk size,
//! CRC-32C over the first 64 bytes or the whole block, flags), then cells.
//! Cells start with a descriptor byte: short keys and values carry their
//! length in it; other cells have a type (key, prefix-compressed key,
//! value, overflow key or value, address, deleted, copy), an optional
//! second descriptor with a time window, an optional run length, and a
//! length; integers use WiredTiger's packed encoding. Address cells (on
//! internal pages, and for overflow items) hold a block address cookie:
//! the offset and size in allocation units and the block's checksum.
//! Compressed pages keep their first 64 bytes as is; the rest is
//! compressed with the table's compressor (Snappy here, behind
//! WiredTiger's 8-byte length prefix). Blocks are found by walking the
//! file (the tree's roots are named only in the metadata); unused space
//! is shown as such. Row-store pages are listed as records: MongoDB
//! collection keys (packed record ids) are decoded and BSON values are
//! dissected; metadata values are configuration strings, shown as trees,
//! with checkpoint address cookies decoded.
//!
//! Everything here is from memory of WiredTiger's sources (block_desc,
//! page and block headers, `cell.h`, `intpack.i`, `block_addr.c`) and was
//! **not** checked against files written by WiredTiger: the fixtures are
//! synthetic, written by our own generator from the same memory. The
//! allocation size is assumed to be 4 KiB (MongoDB's setting; the real
//! one is in the metadata). Column-store pages are shown as cells only.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::codec::{Codec, crc::crc32c_update};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::util::binutil::{dec, hex, hex_string, text};
use crate::formats::util::fmt::grouped_count;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, decode_flags, flag, lookup};

const MAGIC: u32 = 120_897;
/// The allocation unit assumed for address cookies.
const ALLOC: u64 = 4096;
/// Granularity of the block walk through unused space.
const STEP: u64 = 512;
const HEADER: u64 = 40;
/// Bytes of a compressed page kept uncompressed.
const COMPRESS_SKIP: u64 = 64;
const EXTLIST_MAGIC: u64 = 71_002;
/// Nesting of configuration strings.
const MAX_CONFIG_DEPTH: usize = 16;
/// The longest configuration string shown as a tree.
const MAX_CONFIG_LEN: usize = 64 * 1024;

pub static BTREE: Format = Format {
    name: "wiredtiger-btree",
    title: "WiredTiger B-tree file",
    extensions: &["wt"],
    mime: "application/x-wiredtiger",
    probe: Probe::Custom(btree_probe),
    dissect: crate::expander!(btree: Input),
};

pub static TURTLE: Format = Format {
    name: "wiredtiger-turtle",
    title: "WiredTiger turtle file",
    extensions: &["turtle"],
    mime: "text/x-wiredtiger-turtle",
    probe: Probe::Magic(&[(0, b"WiredTiger version string\n")]),
    dissect: crate::expander!(turtle: Input),
};

fn btree_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(MAGIC)
        && u16_le(h.data, 4) == Some(1)
        && u16_le(h.data, 6).is_some_and(|v| v < 16)
        && h.len >= 512
}

const PAGE_TYPES: EnumTable = &[
    (0, "invalid"),
    (1, "block manager (extent list)"),
    (2, "column-store fixed-length leaf"),
    (3, "column-store internal"),
    (4, "column-store variable-length leaf"),
    (5, "overflow"),
    (6, "row-store internal"),
    (7, "row-store leaf"),
];

const PAGE_FLAGS: FlagTable = &[
    flag(0x01, "compressed"),
    flag(0x02, "all values empty"),
    flag(0x04, "no values empty"),
    flag(0x08, "encrypted"),
    flag(0x20, "fast-truncate update"),
];

const CELL_TYPES: EnumTable = &[
    (0x00, "address (deleted)"),
    (0x10, "address (internal)"),
    (0x20, "address (leaf)"),
    (0x30, "address (leaf, no overflow)"),
    (0x40, "deleted value"),
    (0x50, "key"),
    (0x60, "overflow key"),
    (0x70, "key with prefix"),
    (0x80, "value"),
    (0x90, "value copy"),
    (0xa0, "overflow value"),
    (0xb0, "overflow value (removed)"),
    (0xc0, "overflow key (removed)"),
];

/// Time window fields of a second descriptor byte, in packing order.
const WINDOW: &[(u8, &str)] = &[
    (0x08, "Start timestamp"),
    (0x20, "Start transaction"),
    (0x02, "Durable start timestamp"),
    (0x10, "Stop timestamp"),
    (0x40, "Stop transaction"),
    (0x04, "Durable stop timestamp"),
];

/// A WiredTiger packed unsigned integer at `data[pos..]`: value and length.
fn vuint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let b = *data.get(pos)?;
    match b & 0xf0 {
        0x80..=0xb0 => Some((u64::from(b & 0x3f), 1)),
        0xc0 | 0xd0 => {
            let lo = *data.get(pos.checked_add(1)?)?;
            let v = (u64::from(b & 0x1f) << 8 | u64::from(lo)).checked_add(64)?;
            Some((v, 2))
        }
        0xe0 => {
            let n = usize::from(b & 0x0f);
            if n == 0 || n > 8 {
                return None;
            }
            let bytes = data.get(pos.checked_add(1)?..pos.checked_add(1)?.checked_add(n)?)?;
            let v = bytes.iter().fold(0u64, |acc, &x| acc << 8 | u64::from(x));
            Some((v.checked_add(64 + (1 << 13))?, n.checked_add(1)?))
        }
        _ => None,
    }
}

/// A packed signed integer (record ids are packed this way).
fn vint(data: &[u8], pos: usize) -> Option<(i64, usize)> {
    let b = *data.get(pos)?;
    match b & 0xf0 {
        0x80..=0xf0 => {
            let (v, n) = vuint(data, pos)?;
            Some((i64::try_from(v).ok()?, n))
        }
        0x40 | 0x50 | 0x60 | 0x70 => Some((i64::from(b & 0x3f).saturating_sub(64), 1)),
        0x20 | 0x30 => {
            let lo = *data.get(pos.checked_add(1)?)?;
            let v = i64::from(b & 0x1f) << 8 | i64::from(lo);
            Some((v.saturating_sub((1 << 13) + 64), 2))
        }
        _ => None,
    }
}

async fn crc_with_zeroed(cx: &Cx, block: &[u8], at: usize, len: usize) -> u32 {
    let mut copy = block
        .get(..len.min(block.len()))
        .unwrap_or_default()
        .to_vec();
    if let Some(f) = copy.get_mut(at..at.saturating_add(4)) {
        f.fill(0);
    }
    // Pages can be large: a piece at a time.
    let mut crc = !0u32;
    for piece in copy.chunks(64 * 1024) {
        crc = crc32c_update(crc, piece);
        cx.checkpoint().await;
    }
    !crc
}

pub async fn btree(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let desc = cx.read_avail(file.sub(0, ALLOC)).await?;
    let stored = u32_le(&desc, 8).unwrap_or(0);
    let major = u16_le(&desc, 4).unwrap_or(0);
    let minor = u16_le(&desc, 6).unwrap_or(0);
    let mut sum = Node::new("Checksum")
        .span(file.sub(8, 4))
        .value(hex(stored.into(), 32));
    if crc_with_zeroed(&cx, &desc, 8, desc.len()).await == stored {
        sum = sum.summary("valid (CRC-32C)");
    } else if crc_with_zeroed(&cx, &desc, 8, 512).await == stored {
        sum = sum.summary("valid (CRC-32C over 512 bytes)");
    } else {
        sum = sum.diag(Diagnostic::warning("checksum mismatch"));
    }
    let kids = vec![
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(dec(MAGIC.into(), 32)),
        Node::new("Major version")
            .span(file.sub(4, 2))
            .value(dec(major.into(), 16)),
        Node::new("Minor version")
            .span(file.sub(6, 2))
            .value(dec(minor.into(), 16)),
        sum,
        Node::new("Unused").span(file.sub(12, 4)),
    ];
    cx.emit(
        Node::new("Descriptor block")
            .span(file.sub(0, ALLOC))
            .summary(format!("block manager version {major}.{minor}"))
            .lazy(emit_nodes, Arc::new(kids)),
    );
    cx.emit(
        Node::new("Blocks")
            .span(file.tail(ALLOC))
            .lazy(blocks, (input, file)),
    );
    cx.annotate(format!(
        "WiredTiger B-tree file, block manager {major}.{minor}, {}",
        grouped_count(file.len, "byte", "bytes")
    ));
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct PageHeader {
    mem_size: u32,
    entries: u32,
    kind: u8,
    flags: u8,
    disk_size: u32,
}

fn page_header(h: &[u8]) -> Option<PageHeader> {
    Some(PageHeader {
        mem_size: u32_le(h, 16)?,
        entries: u32_le(h, 20)?,
        kind: *h.get(24)?,
        flags: *h.get(25)?,
        disk_size: u32_le(h, 28)?,
    })
}

fn plausible(h: &PageHeader, at: u64, file: Span) -> bool {
    let size = u64::from(h.disk_size);
    (1..=7).contains(&h.kind)
        && size >= HEADER
        && size % STEP == 0
        && at.checked_add(size).is_some_and(|e| e <= file.len)
        && u64::from(h.mem_size) >= HEADER
}

fn page_summary(h: &PageHeader) -> String {
    let mut s = lookup(PAGE_TYPES, h.kind.into())
        .unwrap_or("page")
        .to_owned();
    if h.kind == 5 {
        s.push_str(&format!(", {}", grouped_count(h.entries, "byte", "bytes")));
    } else if h.kind != 1 {
        s.push_str(&format!(", {}", grouped_count(h.entries, "cell", "cells")));
    }
    if h.flags & 1 != 0 {
        s.push_str(", compressed");
    }
    if h.flags & 8 != 0 {
        s.push_str(", encrypted");
    }
    s
}

/// The blocks of the file, found by walking it: a valid page header is a
/// block; anything else is unused space.
async fn blocks(cx: Cx, (input, file): (Input, Span)) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((ALLOC, 0));
    let mut gap: Option<u64> = None;
    while pos < file.len {
        let head = cx.read_avail(file.sub(pos, HEADER)).await?;
        let h = page_header(&head).filter(|h| plausible(h, pos, file));
        let Some(h) = h else {
            gap.get_or_insert(pos);
            pos = pos.saturating_add(STEP);
            continue;
        };
        if let Some(start) = gap.take() {
            cx.push(
                Node::new("Unused")
                    .span(file.sub(start, pos.saturating_sub(start)))
                    .summary(grouped_count(pos.saturating_sub(start), "byte", "bytes")),
            )
            .await;
        }
        let at = (pos, index);
        cx.mark(move || at);
        let size = u64::from(h.disk_size);
        cx.progress(pos.saturating_add(size), file.len);
        cx.push(
            Node::new(format!("Page {pos:#x}"))
                .span(file.sub(pos, size))
                .summary(page_summary(&h))
                .lazy(crate::expander!(self::page: PageState), (input, file, pos)),
        )
        .await;
        pos = pos.saturating_add(size);
        index = index.saturating_add(1);
    }
    if let Some(start) = gap {
        cx.push(Node::new("Unused").span(file.tail(start))).await;
    }
    Ok(())
}

/// One block: headers, then its cells (or overflow data, or extents).
type PageState = (Input, Span, u64);

async fn page(cx: Cx, (input, file, pos): PageState) -> Result<()> {
    let head = cx.read(file.sub_exact(pos, HEADER)?).await?;
    let h = page_header(&head).ok_or_else(|| Diagnostic::malformed("bad page header"))?;
    let span = file.sub_exact(pos, u64::from(h.disk_size))?;
    let block = cx.read(span).await?;
    let mut ph = vec![
        Node::new("Record number")
            .span(span.sub(0, 8))
            .value(dec(u64_le(&head, 0).unwrap_or(0), 64)),
        Node::new("Write generation")
            .span(span.sub(8, 8))
            .value(dec(u64_le(&head, 8).unwrap_or(0), 64)),
        Node::new("In-memory size")
            .span(span.sub(16, 4))
            .value(dec(h.mem_size.into(), 32)),
        Node::new(if h.kind == 5 {
            "Data length"
        } else {
            "Entries"
        })
        .span(span.sub(20, 4))
        .value(dec(h.entries.into(), 32)),
        Node::new("Type").span(span.sub(24, 1)).value(Value::Enum {
            raw: h.kind.into(),
            bits: 8,
            name: lookup(PAGE_TYPES, h.kind.into()),
        }),
    ];
    let (set, unknown) = decode_flags(PAGE_FLAGS, h.flags.into());
    ph.push(
        Node::new("Flags")
            .span(span.sub(25, 1))
            .value(Value::Flags {
                raw: h.flags.into(),
                bits: 8,
                set,
                unknown,
            }),
    );
    ph.push(
        Node::new("Version")
            .span(span.sub(27, 1))
            .value(dec(head.get(27).copied().unwrap_or(0).into(), 8)),
    );
    cx.emit(
        Node::new("Page header")
            .span(span.sub(0, 28))
            .lazy(emit_nodes, Arc::new(ph)),
    );
    let stored = u32_le(&head, 32).unwrap_or(0);
    let bflags = head.get(36).copied().unwrap_or(0);
    let covered = if bflags & 1 != 0 {
        block.len()
    } else {
        to_usize(COMPRESS_SKIP)
    };
    let mut sum = Node::new("Checksum")
        .span(span.sub(32, 4))
        .value(hex(stored.into(), 32));
    sum = if crc_with_zeroed(&cx, &block, 32, covered).await == stored {
        sum.summary(if bflags & 1 != 0 {
            "valid (CRC-32C of the block)"
        } else {
            "valid (CRC-32C of the first 64 bytes)"
        })
    } else {
        sum.diag(Diagnostic::warning("checksum mismatch"))
    };
    let bh = vec![
        Node::new("On-disk size")
            .span(span.sub(28, 4))
            .value(dec(h.disk_size.into(), 32)),
        sum,
        Node::new("Flags")
            .span(span.sub(36, 1))
            .value(hex(bflags.into(), 8))
            .summary(if bflags & 1 != 0 {
                "checksum covers the data"
            } else {
                "checksum covers the header"
            }),
    ];
    cx.emit(
        Node::new("Block header")
            .span(span.sub(28, 12))
            .lazy(emit_nodes, Arc::new(bh)),
    );
    if h.flags & 8 != 0 {
        cx.emit(
            Node::new("Data")
                .span(span.tail(HEADER))
                .diag(Diagnostic::unsupported("encrypted page")),
        );
        return Ok(());
    }
    // The page image (decompressed if need be).
    let image = if h.flags & 1 != 0 {
        match decompress(&cx, span, &h).await {
            Ok(s) => s,
            Err(e) => {
                cx.emit(
                    Node::new("Compressed data")
                        .span(span.tail(COMPRESS_SKIP))
                        .diag(e),
                );
                return Ok(());
            }
        }
    } else {
        span.sub(HEADER, u64::from(h.mem_size).saturating_sub(HEADER))
    };
    match h.kind {
        5 => {
            let data = image.sub(0, h.entries.into());
            cx.emit(item_node("Data", input, data, &cx.read(data).await?, false));
        }
        1 => extents(&cx, image).await?,
        _ => cells(&cx, input, file, image, h).await?,
    }
    Ok(())
}

/// The page past its header, decompressed: the uncompressed part of the
/// first 64 bytes and the decoded rest, joined as pieces.
async fn decompress(cx: &Cx, span: Span, h: &PageHeader) -> Result<Span> {
    let rest = span.tail(COMPRESS_SKIP);
    let prefix = cx.read(rest.sub_exact(0, 8)?).await?;
    let len = u64_le(&prefix, 0).unwrap_or(0);
    let data = rest
        .sub_exact(8, len)
        .map_err(|_| Diagnostic::unsupported("compressed page without a Snappy length prefix"))?;
    let expected = u64::from(h.mem_size).saturating_sub(COMPRESS_SKIP);
    let codec = if cx.read_avail(data.sub(0, 4)).await? == [0x28, 0xb5, 0x2f, 0xfd] {
        Codec::Zstd
    } else {
        Codec::Snappy
    };
    let decoded = crate::codec::decode_span(cx, data, &codec, Some(expected)).await?;
    if let Some(e) = decoded.error {
        return Err(e);
    }
    cx.add_pieces(
        Origin {
            parent: span,
            transform: "wiredtiger-page",
        },
        vec![
            span.sub(HEADER, COMPRESS_SKIP.saturating_sub(HEADER)),
            decoded.span,
        ],
    )
}

/// An extent list: packed (offset, size) pairs after a magic pair, ended
/// by a zero pair.
async fn extents(cx: &Cx, image: Span) -> Result<()> {
    let data = cx.read_avail(image).await?;
    let mut pos = 0usize;
    let mut first = true;
    while let (Some((off, a)), true) = (vuint(&data, pos), pos < data.len()) {
        let Some((size, b)) = vuint(&data, pos.saturating_add(a)) else {
            break;
        };
        let len = a.saturating_add(b);
        let span = image.sub(to_u64(pos), to_u64(len));
        pos = pos.saturating_add(len);
        if first {
            first = false;
            let mut n = Node::new("Header").span(span).value(dec(off, 64));
            n = if off == EXTLIST_MAGIC {
                n.summary("extent list magic")
            } else {
                n.diag(Diagnostic::malformed("not the extent list magic"))
            };
            cx.emit(n);
            continue;
        }
        if off == 0 && size == 0 {
            cx.emit(Node::new("End").span(span));
            break;
        }
        cx.push(
            Node::new(format!("Extent {off:#x}"))
                .span(span)
                .value(dec(size, 64))
                .summary(format!(
                    "{} at {off:#x}",
                    grouped_count(size, "byte", "bytes")
                )),
        )
        .await;
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct Cell {
    at: usize,
    end: usize,
    desc: u8,
    /// The cell type (short forms mapped to key 0x50 / value 0x80).
    kind: u8,
    prefix: Option<u8>,
    rle: Option<u64>,
    window: Vec<(&'static str, u64)>,
    data: (usize, usize),
}

fn cell(data: &[u8], at: usize) -> Option<Cell> {
    let desc = *data.get(at)?;
    let mut p = at.checked_add(1)?;
    let mut c = Cell {
        at,
        desc,
        ..Cell::default()
    };
    let short = desc & 3;
    let len = if short != 0 {
        c.kind = if short == 3 { 0x80 } else { 0x50 };
        if short == 2 {
            c.prefix = Some(*data.get(p)?);
            p = p.checked_add(1)?;
        }
        u64::from(desc >> 2)
    } else {
        c.kind = desc & 0xf0;
        lookup(CELL_TYPES, c.kind.into())?;
        if desc & 0x08 != 0 {
            let second = *data.get(p)?;
            p = p.checked_add(1)?;
            for &(bit, name) in WINDOW {
                if second & bit != 0 {
                    let (v, n) = vuint(data, p)?;
                    p = p.checked_add(n)?;
                    c.window.push((name, v));
                }
            }
            if second & 0x01 != 0 {
                c.window.push(("Prepared", 1));
            }
        }
        if c.kind == 0x70 {
            c.prefix = Some(*data.get(p)?);
            p = p.checked_add(1)?;
        }
        if desc & 0x04 != 0 {
            let (v, n) = vuint(data, p)?;
            p = p.checked_add(n)?;
            c.rle = Some(v);
        }
        match c.kind {
            0x40 => 0,
            0x90 => {
                // A copy: the offset of the cell it repeats.
                let (_, n) = vuint(data, p)?;
                p = p.checked_add(n)?;
                0
            }
            _ => {
                let (mut v, n) = vuint(data, p)?;
                p = p.checked_add(n)?;
                let adjusted =
                    matches!(c.kind, 0x50 | 0x70) || (c.kind == 0x80 && desc & 0x0c == 0);
                if adjusted {
                    v = v.checked_add(64)?;
                }
                v
            }
        }
    };
    let end = p.checked_add(usize::try_from(len).ok()?)?;
    if end > data.len() {
        return None;
    }
    c.data = (p, end);
    c.end = end;
    Some(c)
}

fn is_key(kind: u8) -> bool {
    matches!(kind, 0x50 | 0x60 | 0x70 | 0xc0)
}

fn is_addr(kind: u8) -> bool {
    kind <= 0x30
}

/// A block address cookie: offset, size and checksum.
fn address(data: &[u8]) -> Option<(u64, u64, u64)> {
    let (off, a) = vuint(data, 0)?;
    let (size, b) = vuint(data, a)?;
    let (sum, _) = vuint(data, a.checked_add(b)?)?;
    if size == 0 {
        return Some((0, 0, sum));
    }
    Some((
        off.checked_add(1)?.checked_mul(ALLOC)?,
        size.checked_mul(ALLOC)?,
        sum,
    ))
}

/// How a key reads: a packed record id (MongoDB collections), a string,
/// or bytes.
fn show_key(key: &[u8]) -> String {
    if let Some((v, n)) = vint(key, 0)
        && n == key.len()
    {
        return format!("record id {v}");
    }
    let text = key.strip_suffix(&[0]).unwrap_or(key);
    if !text.is_empty() && text.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return String::from_utf8_lossy(text).into_owned();
    }
    hex_string(key.get(..32).unwrap_or(key))
}

fn looks_bson(d: &[u8]) -> bool {
    d.len() >= 5
        && u32_le(d, 0).is_some_and(|n| to_u64(d.len()) == u64::from(n))
        && d.last() == Some(&0)
}

/// A key or value item: BSON is dissected, configuration strings become
/// trees, other text is text, the rest bytes.
fn item_node(name: &str, input: Input, span: Span, d: &[u8], key: bool) -> Node {
    let node = Node::new(name.to_owned()).span(span);
    if !key && looks_bson(d) {
        return crate::formats::embedded_as(
            name.to_owned(),
            input.nested(span),
            &super::bson::FORMAT,
        )
        .summary("BSON document");
    }
    let body = d.strip_suffix(&[0]).unwrap_or(d);
    if key {
        return node.value(text(show_key(d)));
    }
    if !body.is_empty()
        && body
            .iter()
            .all(|&b| (0x20..0x7f).contains(&b) || b == b'\n')
    {
        let s = String::from_utf8_lossy(body).into_owned();
        // Configuration strings are short; a page-sized one is not parsed
        // into a tree while its page's cells are listed.
        if s.contains('=') && body.len() <= MAX_CONFIG_LEN {
            let items = config(body, 0, 0, span).0;
            if !items.is_empty() {
                return node.value(text(s)).lazy(emit_nodes, Arc::new(items));
            }
        }
        return node.value(text(s));
    }
    node.value(Value::Bytes(d.get(..64).unwrap_or(d).to_vec()))
        .summary(grouped_count(to_u64(d.len()), "byte", "bytes"))
}

fn cell_fields(c: &Cell, span: Span) -> Vec<Node> {
    let sub =
        |a: usize, b: usize| span.sub(to_u64(a.saturating_sub(c.at)), to_u64(b.saturating_sub(a)));
    let mut kids = vec![
        Node::new("Descriptor")
            .span(sub(c.at, c.at.saturating_add(1)))
            .value(hex(c.desc.into(), 8))
            .summary(
                lookup(CELL_TYPES, c.kind.into()).unwrap_or("?").to_owned()
                    + if c.desc & 3 != 0 { " (short)" } else { "" },
            ),
    ];
    if let Some(p) = c.prefix {
        kids.push(
            Node::new("Prefix length")
                .value(dec(p.into(), 8))
                .desc("Bytes shared with the previous key"),
        );
    }
    for (name, v) in &c.window {
        kids.push(Node::new(*name).value(dec(*v, 64)));
    }
    if let Some(r) = c.rle {
        kids.push(Node::new("Run length").value(dec(r, 64)));
    }
    let len = to_u64(c.data.1.saturating_sub(c.data.0));
    kids.push(
        Node::new("Data")
            .span(sub(c.data.0, c.data.1))
            .summary(grouped_count(len, "byte", "bytes")),
    );
    kids
}

/// The cells of a page, paired into records (row-store leaf), child
/// references (internal pages) or listed one by one.
async fn cells(cx: &Cx, input: Input, file: Span, image: Span, h: PageHeader) -> Result<()> {
    let data = cx.read_avail(image).await?;
    let mut pos = 0usize;
    let mut prev_key: Vec<u8> = Vec::new();
    let mut pending: Option<(Cell, Vec<u8>)> = None;
    let mut n = 0u64;
    cx.set_count(Count::Unknown);
    while pos < data.len() && n < u64::from(h.entries) {
        let Some(c) = cell(&data, pos) else {
            cx.diag(Diagnostic::malformed("bad cell").at(image.sub(to_u64(pos), 1)));
            break;
        };
        pos = c.end;
        n = n.saturating_add(1);
        let raw = data.get(c.data.0..c.data.1).unwrap_or_default();
        if is_key(c.kind) && matches!(h.kind, 6 | 7) {
            // Rebuild prefix-compressed keys from the previous one.
            let mut key = prev_key
                .get(..usize::from(c.prefix.unwrap_or(0)))
                .unwrap_or_default()
                .to_vec();
            key.extend_from_slice(raw);
            prev_key = key.clone();
            if let Some((k, kb)) = pending.take() {
                emit_pair(cx, input, file, image, &data, Some((k, kb)), None).await;
            }
            pending = Some((c, key));
            continue;
        }
        match pending.take() {
            Some(k) => emit_pair(cx, input, file, image, &data, Some(k), Some(c)).await,
            None => emit_pair(cx, input, file, image, &data, None, Some(c)).await,
        }
    }
    if let Some(k) = pending.take() {
        emit_pair(cx, input, file, image, &data, Some(k), None).await;
    }
    Ok(())
}

async fn emit_pair(
    cx: &Cx,
    input: Input,
    file: Span,
    image: Span,
    data: &[u8],
    key: Option<(Cell, Vec<u8>)>,
    value: Option<Cell>,
) {
    let cspan = |c: &Cell| image.sub(to_u64(c.at), to_u64(c.end.saturating_sub(c.at)));
    let dspan = |c: &Cell| image.sub(to_u64(c.data.0), to_u64(c.data.1.saturating_sub(c.data.0)));
    let mut kids = Vec::new();
    let mut name = String::from("Cell");
    let mut summary = String::new();
    let mut start = None;
    let mut end = 0usize;
    if let Some((k, full)) = &key {
        start = Some(k.at);
        end = k.end;
        name = show_key(full);
        let mut fields = cell_fields(k, cspan(k));
        if k.kind == 0x60 {
            fields.push(overflow_node(
                "Overflow key",
                input,
                file,
                data.get(k.data.0..k.data.1).unwrap_or_default(),
            ));
        }
        kids.push(
            Node::new("Key")
                .span(cspan(k))
                .value(text(show_key(full)))
                .lazy(emit_nodes, Arc::new(fields)),
        );
    }
    if let Some(v) = &value {
        start.get_or_insert(v.at);
        end = v.end;
        let raw = data.get(v.data.0..v.data.1).unwrap_or_default();
        let fields = cell_fields(v, cspan(v));
        let label = lookup(CELL_TYPES, v.kind.into()).unwrap_or("cell");
        let node = if is_addr(v.kind) || matches!(v.kind, 0xa0 | 0xb0) {
            let child = if is_addr(v.kind) {
                "Child"
            } else {
                "Overflow value"
            };
            summary = label.to_owned();
            overflow_node(child, input, file, raw)
        } else if v.kind == 0x40 {
            summary = "deleted".to_owned();
            Node::new("Value").value(text("deleted"))
        } else {
            let n = item_node("Value", input, dspan(v), raw, false);
            summary = n
                .summary
                .clone()
                .or_else(|| n.value.as_ref().map(short))
                .unwrap_or_default();
            n
        };
        kids.push(node);
        kids.push(
            Node::new("Value cell")
                .span(cspan(v))
                .summary(label)
                .lazy(emit_nodes, Arc::new(fields)),
        );
        if key.is_none() {
            name = label.to_owned();
        }
    }
    let span = image.sub(
        to_u64(start.unwrap_or(0)),
        to_u64(end.saturating_sub(start.unwrap_or(0))),
    );
    let mut node = Node::new(name).span(span).lazy(emit_nodes, Arc::new(kids));
    if !summary.is_empty() {
        node = node.summary(summary);
    }
    cx.push(node).await;
}

fn short(v: &Value) -> String {
    crate::formats::util::fmt::clip(&crate::render::value(v), 48)
}

/// An address cookie: where the block is, expandable into that page.
fn overflow_node(name: &str, input: Input, file: Span, cookie: &[u8]) -> Node {
    let Some((off, size, sum)) = address(cookie) else {
        return Node::new(name.to_owned()).diag(Diagnostic::malformed("bad address cookie"));
    };
    if size == 0 {
        return Node::new(name.to_owned()).value(text("none"));
    }
    let target = file.sub(off, size);
    let node = Node::new(name.to_owned())
        .value(text(format!(
            "block {off:#x}, {} bytes, checksum {sum:#x}",
            size
        )))
        .target(target);
    if target.len == size && off >= ALLOC {
        node.lazy(crate::expander!(self::page: PageState), (input, file, off))
    } else {
        node.diag(Diagnostic::malformed("address outside the file"))
    }
}

/// Parses a configuration string (`key=value,key=(nested),key="quoted"`)
/// into nodes; returns them and where parsing stopped.
fn config(s: &[u8], mut pos: usize, depth: usize, base: Span) -> (Vec<Node>, usize) {
    let mut out = Vec::new();
    let at = |a: usize, b: usize| base.sub(to_u64(a), to_u64(b.saturating_sub(a)));
    while pos < s.len() && out.len() < 4096 {
        match s.get(pos) {
            Some(b',' | b' ') => {
                pos = pos.saturating_add(1);
                continue;
            }
            Some(b')' | b']') => return (out, pos.saturating_add(1)),
            _ => {}
        }
        let start = pos;
        while pos < s.len() && !matches!(s.get(pos), Some(b'=' | b',' | b')' | b'(' | b']')) {
            pos = pos.saturating_add(1);
        }
        let key = String::from_utf8_lossy(s.get(start..pos).unwrap_or_default()).into_owned();
        if s.get(pos) != Some(&b'=') {
            if s.get(pos) == Some(&b'(') {
                // A bare nested list.
                pos = pos.saturating_add(1);
            }
            out.push(Node::new(key).span(at(start, pos)));
            continue;
        }
        pos = pos.saturating_add(1);
        match s.get(pos) {
            Some(b'(') if depth < MAX_CONFIG_DEPTH => {
                let (kids, end) = config(s, pos.saturating_add(1), depth.saturating_add(1), base);
                let n = to_u64(kids.len());
                let mut node = Node::new(key).span(at(start, end));
                if !kids.is_empty() {
                    node = node
                        .summary(grouped_count(n, "item", "items"))
                        .lazy(emit_nodes, Arc::new(kids));
                } else {
                    node = node.value(text("()"));
                }
                out.push(node);
                pos = end;
            }
            Some(b'"') => {
                let vstart = pos.saturating_add(1);
                let mut e = vstart;
                while e < s.len() && s.get(e) != Some(&b'"') {
                    e = e.saturating_add(if s.get(e) == Some(&b'\\') { 2 } else { 1 });
                }
                let v = String::from_utf8_lossy(s.get(vstart..e.min(s.len())).unwrap_or_default())
                    .into_owned();
                pos = e.saturating_add(1).min(s.len());
                let mut node = Node::new(key.clone())
                    .span(at(start, pos))
                    .value(text(v.clone()));
                if key == "addr" {
                    node = checkpoint_addr(node, &v);
                }
                out.push(node);
            }
            Some(b'[') => {
                let mut e = pos;
                while e < s.len() && s.get(e) != Some(&b']') {
                    e = e.saturating_add(1);
                }
                let v = String::from_utf8_lossy(
                    s.get(pos..e.saturating_add(1).min(s.len()))
                        .unwrap_or_default(),
                )
                .into_owned();
                pos = e.saturating_add(1).min(s.len());
                out.push(Node::new(key).span(at(start, pos)).value(text(v)));
            }
            _ => {
                let vstart = pos;
                while pos < s.len() && !matches!(s.get(pos), Some(b',' | b')')) {
                    pos = pos.saturating_add(1);
                }
                let v =
                    String::from_utf8_lossy(s.get(vstart..pos).unwrap_or_default()).into_owned();
                out.push(Node::new(key).span(at(start, pos)).value(text(v)));
            }
        }
    }
    (out, pos)
}

/// A checkpoint's `addr`: a hex-encoded cookie of a version byte and
/// packed integers (root, extent list addresses, file and checkpoint
/// sizes; the split into fields is from memory, so they are listed in
/// order).
fn checkpoint_addr(node: Node, hexs: &str) -> Node {
    let bytes: Option<Vec<u8>> = (0..hexs.len() / 2)
        .map(|i| {
            u8::from_str_radix(
                hexs.get(i.saturating_mul(2)..i.saturating_mul(2).saturating_add(2))?,
                16,
            )
            .ok()
        })
        .collect();
    let Some(bytes) = bytes else { return node };
    let Some(&version) = bytes.first() else {
        return node;
    };
    let mut kids = vec![Node::new("Version").value(dec(version.into(), 8))];
    let mut pos = 1usize;
    let mut i = 0u64;
    while let Some((v, n)) = vuint(&bytes, pos) {
        kids.push(Node::new(format!("Integer {i}")).value(dec(v, 64)));
        pos = pos.saturating_add(n);
        i = i.saturating_add(1);
    }
    node.summary(format!(
        "checkpoint cookie v{version}, {}",
        grouped_count(i, "integer", "integers")
    ))
    .lazy(emit_nodes, Arc::new(kids))
}

/// The turtle file: alternating key and value lines.
pub async fn turtle(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read(file.sub_exact(0, file.len.min(1 << 20))?).await?;
    let mut lines = Vec::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' {
            lines.push((start, i));
            start = i.saturating_add(1);
        }
    }
    if start < data.len() {
        lines.push((start, data.len()));
    }
    let mut version = String::new();
    for pair in lines.chunks(2) {
        let [(ks, ke), rest @ ..] = pair else {
            continue;
        };
        let key = String::from_utf8_lossy(data.get(*ks..*ke).unwrap_or_default()).into_owned();
        let Some(&(vs, ve)) = rest.first() else {
            cx.push(Node::new(key).span(file.sub(to_u64(*ks), to_u64(ke.saturating_sub(*ks)))))
                .await;
            break;
        };
        let value = data.get(vs..ve).unwrap_or_default();
        let vspan = file.sub(to_u64(vs), to_u64(ve.saturating_sub(vs)));
        let span = file.sub(to_u64(*ks), to_u64(ve.saturating_sub(*ks)));
        if key == "WiredTiger version string" {
            version = String::from_utf8_lossy(value).into_owned();
        }
        let mut node = Node::new(key)
            .span(span)
            .value(text(String::from_utf8_lossy(value).into_owned()));
        if value.contains(&b'=') {
            let (items, _) = config(value, 0, 0, vspan);
            if !items.is_empty() {
                node = node.lazy(emit_nodes, Arc::new(items));
            }
        }
        cx.push(node).await;
    }
    cx.annotate(if version.is_empty() {
        "WiredTiger turtle file".to_owned()
    } else {
        format!("WiredTiger turtle file ({version})")
    });
    Ok(())
}
