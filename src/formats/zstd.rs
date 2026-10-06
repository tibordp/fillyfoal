//! Zstandard (RFC 8878).
//!
//! A file is a sequence of frames: zstd frames (header, blocks, optional
//! checksum) and skippable frames (magic 0x184D2A50..5F, length, data). The
//! seekable format keeps a seek table in a skippable frame at the end, which
//! is decoded too. Blocks are listed from their 3-byte headers; the
//! decompressed content is decoded on demand.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use std::sync::Arc;

use crate::formats::arcutil::{count, emit_nodes, hex, human_size, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag};

const LE: Endian = Endian::Little;
const FRAME_MAGIC: u32 = 0xfd2f_b528;
const SEEKABLE_MAGIC: u32 = 0x8f92_eab1;
const SEEK_TABLE_FRAME: u32 = 0x184d_2a5e;
/// Blocks are at most 128 KiB; a frame with more blocks than this is listed
/// lazily anyway, but walking it to find its end is capped.
const MAX_BLOCK_WALK: u64 = 1 << 24;

pub static FORMAT: Format = Format {
    name: "zstd",
    title: "Zstandard compressed data",
    extensions: &["zst", "tzst", "zstd"],
    mime: "application/zstd",
    probe: Probe::Magic(&[(0, b"\x28\xb5\x2f\xfd")]),
    dissect: crate::expander!(dissect: Input),
};

/// Skippable frames are valid zstd files on their own; the seekable format
/// may even start with one. Require a zstd frame right after it.
pub static SKIPPABLE: Format = Format {
    name: "zstd-skippable",
    title: "Zstandard skippable frame",
    extensions: &["zst"],
    mime: "application/zstd",
    probe: Probe::Custom(|h| {
        let Some(magic) = u32_le(h.data, 0) else {
            return false;
        };
        let Some(len) = u32_le(h.data, 4) else {
            return false;
        };
        let next = usize::try_from(len).ok().and_then(|l| l.checked_add(8));
        magic & 0xffff_fff0 == 0x184d_2a50
            && next.is_some_and(|n| h.at(n, b"\x28\xb5\x2f\xfd") || h.at(n, b"\x04\x22\x4d\x18"))
    }),
    dissect: crate::expander!(dissect: Input),
};

const FHD: FlagTable = &[
    field(0xc0, 0x40, "FCS_2"),
    field(0xc0, 0x80, "FCS_4"),
    field(0xc0, 0xc0, "FCS_8"),
    flag(0x20, "SINGLE_SEGMENT"),
    flag(0x08, "RESERVED"),
    flag(0x04, "CONTENT_CHECKSUM"),
    field(0x03, 0x01, "DICT_ID_1"),
    field(0x03, 0x02, "DICT_ID_2"),
    field(0x03, 0x03, "DICT_ID_4"),
];

const BLOCK_TYPE: EnumTable = &[(0, "raw"), (1, "RLE"), (2, "compressed"), (3, "reserved")];

#[derive(Clone, Copy, Debug, Default)]
pub struct FrameHeader {
    pub checksum: bool,
    pub content_size: Option<u64>,
    pub window: Option<u64>,
}

/// The frame header after the magic: descriptor, window, dictionary ID and
/// content size, all optional but the descriptor.
fn frame_header(f: &mut Fields<'_>, _: &()) -> Result<FrameHeader> {
    let fhd = f
        .u8("Frame header descriptor")
        .flags(FHD)
        .check(|&d| (d & 0x08 != 0).then(|| Diagnostic::malformed("reserved bit set")))
        .emit()?;
    let single = fhd & 0x20 != 0;
    let mut header = FrameHeader {
        checksum: fhd & 0x04 != 0,
        ..FrameHeader::default()
    };
    if !single {
        let wd = f
            .u8("Window descriptor")
            .with(|&w, n| n.summary(human_size(window_size(w))))
            .emit()?;
        header.window = Some(window_size(wd));
    }
    match fhd & 3 {
        1 => {
            f.u8("Dictionary ID").emit()?;
        }
        2 => {
            f.u16("Dictionary ID").emit()?;
        }
        3 => {
            f.u32("Dictionary ID").emit()?;
        }
        _ => {}
    }
    let size = match (fhd >> 6, single) {
        (0, true) => Some(u64::from(f.u8("Frame content size").emit()?)),
        (1, _) => Some(
            u64::from(
                f.u16("Frame content size")
                    .with(|&v, n| {
                        n.summary(format!(
                            "{} (stored minus 256)",
                            u64::from(v).saturating_add(256)
                        ))
                    })
                    .emit()?,
            )
            .saturating_add(256),
        ),
        (2, _) => Some(u64::from(f.u32("Frame content size").emit()?)),
        (3, _) => Some(f.u64("Frame content size").emit()?),
        _ => None,
    };
    header.content_size = size;
    if single {
        header.window = size;
    }
    Ok(header)
}

fn window_size(wd: u8) -> u64 {
    let log = u32::from(wd >> 3).saturating_add(10);
    let base = 1u64.checked_shl(log).unwrap_or(u64::MAX);
    base.saturating_add((base / 8).saturating_mul(u64::from(wd & 7)))
}

fn header_len(fhd: u8) -> u64 {
    let single = fhd & 0x20 != 0;
    let window = u64::from(!single);
    let dict = [0u64, 1, 2, 4]
        .get(usize::from(fhd & 3))
        .copied()
        .unwrap_or(0);
    let fcs = match fhd >> 6 {
        0 => u64::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    1u64.saturating_add(window)
        .saturating_add(dict)
        .saturating_add(fcs)
}

/// What a walk over a frame found.
struct FrameInfo {
    span: Span,
    blocks: u64,
    header: FrameHeader,
}

/// Walks a zstd frame starting at the cursor (after the magic check).
async fn walk_frame(cx: &Cx, cur: &mut Cursor<'_>) -> Result<FrameInfo> {
    let start = cur.pos();
    cur.skip(4);
    let fhd = cur.peek(1).await?.first().copied().unwrap_or(0);
    let hlen = header_len(fhd);
    let header = crate::fields::parse(cx, cur.span(hlen), LE, &(), frame_header).await?;
    cur.skip(hlen);
    let mut blocks = 0u64;
    loop {
        let bh = cur.bytes(3).await?;
        let h = u32::from_le_bytes([
            bh.first().copied().unwrap_or(0),
            bh.get(1).copied().unwrap_or(0),
            bh.get(2).copied().unwrap_or(0),
            0,
        ]);
        let kind = (h >> 1) & 3;
        if kind == 3 {
            return Err(Diagnostic::malformed("reserved block type").at(cur.since(start)));
        }
        let size = if kind == 1 { 1 } else { u64::from(h >> 3) };
        cur.skip(size);
        blocks = blocks.saturating_add(1);
        if h & 1 != 0 {
            break;
        }
        if blocks >= MAX_BLOCK_WALK {
            return Err(Diagnostic::limit("too many blocks").at(cur.since(start)));
        }
        if cur.at_end() {
            return Err(Diagnostic::truncated(
                cur.since(start),
                cur.since(start).len,
            ));
        }
        cx.checkpoint().await;
    }
    if header.checksum {
        cur.skip(4);
    }
    Ok(FrameInfo {
        span: cur.since(start),
        blocks,
        header,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut frames = 0u64;
    let mut total = Some(0u64);
    cx.annotate("Zstandard");
    cx.emit(Node::new("Decompressed").span(file).lazy(decompressed, input));
    while !cur.at_end() {
        let start = cur.pos();
        let magic = cur.peek(4).await?;
        let Some(magic) = u32_le(&magic, 0) else {
            cx.emit(Node::new("Trailing data").span(file.tail(start)));
            break;
        };
        if magic == FRAME_MAGIC {
            let info = match walk_frame(&cx, &mut cur).await {
                Ok(info) => info,
                Err(e) => {
                    let span = file.tail(start);
                    cx.push(
                        Node::new(format!("Frame {frames}"))
                            .span(span)
                            .diag(e)
                            .lazy(frame, (input, span)),
                    )
                    .await;
                    total = None;
                    break;
                }
            };
            total = match (total, info.header.content_size) {
                (Some(t), Some(s)) => Some(t.saturating_add(s)),
                _ => None,
            };
            let content = info
                .header
                .content_size
                .map_or_else(|| "size unknown".to_owned(), human_size);
            cx.push(
                Node::new(format!("Frame {frames}"))
                    .span(info.span)
                    .summary(format!(
                        "{}, {content}",
                        count(info.blocks, "block", "blocks")
                    ))
                    .lazy(frame, (input, info.span)),
            )
            .await;
            frames = frames.saturating_add(1);
        } else if magic & 0xffff_fff0 == 0x184d_2a50 {
            cur.skip(4);
            let len = cur.u32().await?;
            cur.skip(len.into());
            let span = cur.since(start);
            let name = if magic == SEEK_TABLE_FRAME && is_seek_table(&cx, span).await {
                "Seek table".to_owned()
            } else {
                format!("Skippable frame {:#x}", magic & 0xf)
            };
            cx.push(crate::formats::arcutil::check_len(
                Node::new(name)
                    .span(span)
                    .summary(human_size(len.into()))
                    .lazy(skippable, span),
                span,
                u64::from(len).saturating_add(8),
            ))
            .await;
        } else {
            let rest = file.tail(start);
            cx.emit(
                Node::new("Trailing data")
                    .span(rest)
                    .diag(Diagnostic::malformed(format!(
                        "unknown frame magic {magic:#010x}"
                    ))),
            );
            break;
        }
    }
    let mut summary = format!("Zstandard, {}", count(frames, "frame", "frames"));
    if let Some(t) = total {
        summary = format!("{summary}, {} uncompressed", human_size(t));
    }
    cx.annotate(summary);
    Ok(())
}

/// The decompressed content. When every frame records its content size,
/// the total is known up front and a large stream decodes lazily.
async fn decompressed(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut total = Some(0u64);
    while !cur.at_end() && total.is_some() {
        let start = cur.pos();
        let Some(magic) = u32_le(&cur.peek(4).await?, 0) else {
            break;
        };
        if magic == FRAME_MAGIC {
            total = match walk_frame(&cx, &mut cur).await {
                Ok(info) => total.zip(info.header.content_size).map(|(t, s)| t.saturating_add(s)),
                Err(_) => None,
            };
        } else if magic & 0xffff_fff0 == 0x184d_2a50 {
            cur.skip(4);
            let len = cur.u32().await?;
            cur.skip(len.into());
        } else {
            break;
        }
        if cur.pos() == start {
            break;
        }
    }
    crate::formats::expand_content(cx, (input, file, crate::codec::Codec::Zstd, total)).await
}

async fn is_seek_table(cx: &Cx, span: Span) -> bool {
    let tail = span.tail(span.len.saturating_sub(4));
    matches!(cx.read(tail).await, Ok(b) if u32_le(&b, 0) == Some(SEEKABLE_MAGIC))
}

async fn frame(cx: Cx, (_input, span): (Input, Span)) -> Result<()> {
    cx.emit(
        Node::new("Magic")
            .span(span.sub(0, 4))
            .value(hex(FRAME_MAGIC.into())),
    );
    let fhd = cx.read(span.sub(4, 1)).await?.first().copied().unwrap_or(0);
    let hlen = header_len(fhd);
    let header_span = span.sub(4, hlen);
    let header = crate::fields::parse(&cx, header_span, LE, &(), frame_header).await?;
    let mut parts = Vec::new();
    if let Some(s) = header.content_size {
        parts.push(format!("content {}", human_size(s)));
    }
    if let Some(w) = header.window {
        parts.push(format!("window {}", human_size(w)));
    }
    cx.emit(
        struct_node("Frame header", header_span, LE, (), frame_header).summary(parts.join(", ")),
    );
    let blocks_start = 4u64.saturating_add(hlen);
    let check_len = if header.checksum { 4 } else { 0 };
    let blocks_span = span.sub(
        blocks_start,
        span.len
            .saturating_sub(blocks_start)
            .saturating_sub(check_len),
    );
    cx.emit(
        Node::new("Blocks")
            .span(blocks_span)
            .lazy(blocks, blocks_span),
    );
    if header.checksum {
        let at = span.len.saturating_sub(4);
        let bytes = cx.read(span.sub(at, 4)).await?;
        cx.emit(
            Node::new("Content checksum")
                .span(span.sub(at, 4))
                .value(hex(u32_le(&bytes, 0).unwrap_or(0).into()))
                .desc("Low 32 bits of the XXH64 of the content"),
        );
    }
    Ok(())
}

async fn blocks(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let mut index = 0u64;
    while !cur.at_end() {
        let start = cur.pos();
        let bh = cur.bytes(3).await?;
        let h = u32::from_le_bytes([
            bh.first().copied().unwrap_or(0),
            bh.get(1).copied().unwrap_or(0),
            bh.get(2).copied().unwrap_or(0),
            0,
        ]);
        let last = h & 1 != 0;
        let kind = (h >> 1) & 3;
        let size = u64::from(h >> 3);
        let payload = if kind == 1 { 1 } else { size };
        cur.skip(payload);
        let block_span = cur.since(start);
        let kind_name = crate::value::lookup(BLOCK_TYPE, kind.into()).unwrap_or("?");
        let mut summary = format!("{kind_name}, {}", human_size(size));
        if last {
            summary.push_str(", last");
        }
        cx.push(crate::formats::arcutil::check_len(
            Node::new(format!("Block {index}"))
                .span(block_span)
                .summary(summary)
                .lazy(block, block_span),
            block_span,
            payload.saturating_add(3),
        ))
        .await;
        index = index.saturating_add(1);
        if last || kind == 3 {
            break;
        }
    }
    Ok(())
}

async fn block(cx: Cx, span: Span) -> Result<()> {
    let bh = cx.read(span.sub(0, 3)).await?;
    let h = u32::from_le_bytes([
        bh.first().copied().unwrap_or(0),
        bh.get(1).copied().unwrap_or(0),
        bh.get(2).copied().unwrap_or(0),
        0,
    ]);
    let header = span.sub(0, 3);
    cx.emit(
        Node::new("Last block")
            .span(header.sub(0, 1))
            .value(Value::Bool(h & 1 != 0)),
    );
    let kind = (h >> 1) & 3;
    cx.emit(
        Node::new("Block type")
            .span(header.sub(0, 1))
            .value(Value::Enum {
                raw: kind.into(),
                bits: 2,
                name: crate::value::lookup(BLOCK_TYPE, kind.into()),
            }),
    );
    let size = u64::from(h >> 3);
    cx.emit(
        Node::new("Block size")
            .span(header)
            .value(uint(size))
            .summary(if kind == 1 {
                format!("{size} repetitions")
            } else {
                human_size(size)
            }),
    );
    let body = span.tail(3);
    match kind {
        0 => cx.emit(Node::new("Raw data").span(body)),
        1 => {
            let byte = cx.read(body.sub(0, 1)).await?;
            cx.emit(
                Node::new("RLE byte")
                    .span(body.sub(0, 1))
                    .value(Value::Bytes(byte)),
            );
        }
        2 => cx.emit(Node::new("Compressed data").span(body).desc("Decoded as part of the whole stream (see Decompressed)")),
        _ => cx.diag(Diagnostic::malformed("reserved block type")),
    }
    Ok(())
}

async fn skippable(cx: Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub(0, 8)).await?;
    let magic = u32_le(&head, 0).unwrap_or(0);
    let len = u32_le(&head, 4).unwrap_or(0);
    cx.emit(
        Node::new("Magic")
            .span(span.sub(0, 4))
            .value(hex(magic.into())),
    );
    cx.emit(
        Node::new("Frame size")
            .span(span.sub(4, 4))
            .value(uint(len.into())),
    );
    let data = span.tail(8);
    if magic == SEEK_TABLE_FRAME && is_seek_table(&cx, span).await {
        return seek_table(&cx, data).await;
    }
    cx.emit(Node::new("User data").span(data));
    Ok(())
}

/// The seekable format's table: entries, then a 9-byte footer.
async fn seek_table(cx: &Cx, data: Span) -> Result<()> {
    let footer_span = data.sub(data.len.saturating_sub(9), 9);
    let footer = cx.read(footer_span).await?;
    let frames = u32_le(&footer, 0).unwrap_or(0);
    let descriptor = footer.get(4).copied().unwrap_or(0);
    let checksums = descriptor & 0x80 != 0;
    let entry = if checksums { 12u64 } else { 8 };
    let table_len = u64::from(frames).saturating_mul(entry);
    let table = data.sub_exact(0, table_len)?;
    let mut cur = Cursor::new(cx, table, LE);
    let mut compressed_at = 0u64;
    for i in 0..frames {
        let start = cur.pos();
        let compressed = cur.u32().await?;
        let decompressed = cur.u32().await?;
        let mut children = vec![
            Node::new("Compressed size")
                .span(table.sub(start, 4))
                .value(uint(compressed.into())),
            Node::new("Decompressed size")
                .span(table.sub(start.saturating_add(4), 4))
                .value(uint(decompressed.into())),
        ];
        if checksums {
            let c = cur.u32().await?;
            children.push(
                Node::new("Checksum")
                    .span(table.sub(start.saturating_add(8), 4))
                    .value(hex(c.into())),
            );
        }
        cx.push(
            Node::new(format!("Entry {i}"))
                .span(cur.since(start))
                .summary(format!(
                    "at {compressed_at:#x}, {} → {}",
                    human_size(compressed.into()),
                    human_size(decompressed.into())
                ))
                .lazy(emit_nodes, Arc::new(children)),
        )
        .await;
        compressed_at = compressed_at.saturating_add(compressed.into());
    }
    cx.emit(
        Node::new("Seek table footer")
            .span(footer_span)
            .summary(format!(
                "{}, {}",
                count(frames.into(), "frame", "frames"),
                if checksums {
                    "with checksums"
                } else {
                    "no checksums"
                }
            ))
            .lazy(
                emit_nodes,
                Arc::new(vec![
                    Node::new("Number of frames")
                        .span(footer_span.sub(0, 4))
                        .value(uint(frames.into())),
                    Node::new("Descriptor")
                        .span(footer_span.sub(4, 1))
                        .value(hex(descriptor.into())),
                    Node::new("Seekable magic")
                        .span(footer_span.sub(5, 4))
                        .value(hex(SEEKABLE_MAGIC.into())),
                ]),
            ),
    );
    Ok(())
}
