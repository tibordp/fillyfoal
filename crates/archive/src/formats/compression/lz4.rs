//! LZ4 frame format, the legacy LZ4 format, and the Snappy framing format.
//!
//! LZ4 frames: magic, frame descriptor (flags, block size, optional content
//! size and dictionary ID, header checksum), blocks (a 32-bit size whose top
//! bit marks uncompressed data, the data, an optional checksum), an end mark
//! and an optional content checksum. Legacy files are 8 MiB blocks with a
//! size prefix. Snappy framing is a stream of typed chunks.
//!
//! The whole stream is decompressed as a "Decompressed" node; compressed
//! blocks point there, uncompressed blocks are shown as data.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{check_len, emit_nodes, xxh32};
use crate::formats::util::fmt;
use crate::formats::util::fmt::capitalize;
use crate::formats::util::fmt::count;
use crate::formats::util::val::{hex, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, flag};

const LE: Endian = Endian::Little;
const FRAME_MAGIC: u32 = 0x184d_2204;
const LEGACY_MAGIC: u32 = 0x184c_2102;
/// Legacy blocks decompress to at most 8 MiB, so they cannot be larger
/// than this compressed.
const LEGACY_MAX_BLOCK: u32 = 8 * 1024 * 1024 + 8 * 1024 * 1024 / 255 + 16;

pub static FORMAT: Format = Format {
    name: "lz4",
    title: "LZ4 frame",
    extensions: &["lz4", "tlz4"],
    mime: "application/x-lz4",
    probe: Probe::Magic(&[(0, b"\x04\x22\x4d\x18")]),
    dissect: crate::expander!(dissect: Input),
};

pub static LEGACY: Format = Format {
    name: "lz4-legacy",
    title: "LZ4 legacy format",
    extensions: &["lz4"],
    mime: "application/x-lz4",
    probe: Probe::Magic(&[(0, b"\x02\x21\x4c\x18")]),
    dissect: crate::expander!(dissect: Input),
};

pub static SNAPPY: Format = Format {
    name: "snappy",
    title: "Snappy framed data",
    extensions: &["sz", "snappy"],
    mime: "application/x-snappy-framed",
    probe: Probe::Magic(&[(0, b"\xff\x06\x00\x00sNaPpY")]),
    dissect: crate::expander!(dissect_snappy: Input),
};

const FLG: FlagTable = &[
    field(0xc0, 0x40, "VERSION_01"),
    flag(0x20, "BLOCK_INDEPENDENT"),
    flag(0x10, "BLOCK_CHECKSUM"),
    flag(0x08, "CONTENT_SIZE"),
    flag(0x04, "CONTENT_CHECKSUM"),
    flag(0x02, "RESERVED"),
    flag(0x01, "DICT_ID"),
];

const BLOCK_MAX: EnumTable = &[(4, "64 KiB"), (5, "256 KiB"), (6, "1 MiB"), (7, "4 MiB")];

#[derive(Clone, Copy, Debug, Default)]
struct Descriptor {
    block_checksum: bool,
    content_checksum: bool,
    content_size: Option<u64>,
}

fn descriptor_len(flg: u8) -> u64 {
    let mut len = 3u64; // FLG, BD, HC
    if flg & 0x08 != 0 {
        len = len.saturating_add(8);
    }
    if flg & 0x01 != 0 {
        len = len.saturating_add(4);
    }
    len
}

fn descriptor(f: &mut Fields<'_>, _: &()) -> Result<Descriptor> {
    let covered = f.block().data.clone();
    let flg = f
        .u8("FLG")
        .flags(FLG)
        .check(|&v| {
            (v >> 6 != 1).then(|| Diagnostic::malformed(format!("version {} (expected 1)", v >> 6)))
        })
        .emit()?;
    f.u8("BD")
        .with(|&bd, n| {
            let size = crate::value::lookup(BLOCK_MAX, ((bd >> 4) & 7).into()).unwrap_or("invalid");
            n.summary(format!("block maximum {size}"))
        })
        .emit()?;
    let mut d = Descriptor {
        block_checksum: flg & 0x10 != 0,
        content_checksum: flg & 0x04 != 0,
        content_size: None,
    };
    if flg & 0x08 != 0 {
        d.content_size = Some(
            f.u64("Content size")
                .with(|&s, n| n.summary(fmt::size(s)))
                .emit()?,
        );
    }
    if flg & 0x01 != 0 {
        f.u32("Dictionary ID").hex().emit()?;
    }
    let at = crate::bytes::to_usize(f.pos());
    let expected = covered.get(..at).map(|c| ((xxh32(c, 0) >> 8) & 0xff) as u8);
    f.u8("Header checksum")
        .hex()
        .with(|&hc, n| match expected {
            Some(e) if e == hc => n.summary("valid"),
            Some(e) => n.diag(Diagnostic::warning(format!(
                "header checksum mismatch: computed {e:#04x}"
            ))),
            None => n,
        })
        .emit()?;
    Ok(d)
}

struct FrameInfo {
    span: Span,
    blocks: u64,
    content_size: Option<u64>,
}

async fn walk_frame(cx: &Cx, cur: &mut Cursor<'_>) -> Result<FrameInfo> {
    let start = cur.pos();
    cur.skip(4);
    let flg = cur.peek(1).await?.first().copied().unwrap_or(0);
    let dlen = descriptor_len(flg);
    let d = crate::fields::parse(cx, cur.span(dlen), LE, &(), descriptor).await?;
    cur.skip(dlen);
    let mut blocks = 0u64;
    loop {
        let size = cur.u32().await?;
        if size == 0 {
            break;
        }
        cur.skip(u64::from(size & 0x7fff_ffff));
        if d.block_checksum {
            cur.skip(4);
        }
        blocks = blocks.saturating_add(1);
        if cur.at_end() {
            return Err(Diagnostic::malformed("frame has no end mark").at(cur.since(start)));
        }
        cx.checkpoint().await;
    }
    if d.content_checksum {
        cur.skip(4);
    }
    Ok(FrameInfo {
        span: cur.since(start),
        blocks,
        content_size: d.content_size,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut frames = 0u64;
    let mut total = Some(0u64);
    let mut legacy = false;
    cx.annotate("LZ4");
    cx.emit(crate::formats::content(
        "Decompressed",
        input,
        file,
        crate::codec::Codec::Lz4Frame,
        None,
    ));
    while !cur.at_end() {
        let start = cur.pos();
        cx.progress_in(file, cur.span(0).offset);
        let magic = cur.peek(4).await?;
        let Some(magic) = u32_le(&magic, 0) else {
            cx.emit(Node::new("Trailing data").span(file.tail(start)));
            break;
        };
        if magic == FRAME_MAGIC {
            let name = format!("Frame {frames}");
            frames = frames.saturating_add(1);
            match walk_frame(&cx, &mut cur).await {
                Ok(info) => {
                    total = total
                        .zip(info.content_size)
                        .map(|(a, b)| a.saturating_add(b));
                    let size = info
                        .content_size
                        .map_or_else(|| "size unknown".to_owned(), fmt::size);
                    cx.push(
                        Node::new(name)
                            .span(info.span)
                            .summary(format!("{}, {size}", count(info.blocks, "block", "blocks")))
                            .lazy(frame, info.span),
                    )
                    .await;
                }
                Err(e) => {
                    let span = file.tail(start);
                    cx.push(Node::new(name).span(span).diag(e).lazy(frame, span))
                        .await;
                    total = None;
                    break;
                }
            }
        } else if magic == LEGACY_MAGIC {
            legacy = true;
            total = None;
            cur.skip(4);
            legacy_extent(&mut cur).await?;
            let span = cur.since(start);
            frames = frames.saturating_add(1);
            cx.push(
                Node::new("Legacy frame")
                    .span(span)
                    .lazy(legacy_frame, span),
            )
            .await;
        } else if magic & 0xffff_fff0 == 0x184d_2a50 {
            cur.skip(4);
            let len = cur.u32().await?;
            cur.skip(len.into());
            let span = cur.since(start);
            cx.push(check_len(
                Node::new(format!("Skippable frame {:#x}", magic & 0xf))
                    .span(span)
                    .summary(fmt::size(len.into()))
                    .lazy(
                        emit_nodes,
                        Arc::new(vec![
                            Node::new("Magic")
                                .span(span.sub(0, 4))
                                .value(hex(magic, 64)),
                            Node::new("Frame size")
                                .span(span.sub(4, 4))
                                .value(uint(len, 64)),
                            Node::new("User data").span(span.tail(8)),
                        ]),
                    ),
                span,
                u64::from(len).saturating_add(8),
            ))
            .await;
        } else {
            cx.emit(
                Node::new("Trailing data")
                    .span(file.tail(start))
                    .diag(Diagnostic::malformed(format!(
                        "unknown frame magic {magic:#010x}"
                    ))),
            );
            break;
        }
    }
    let kind = if legacy { "LZ4 (legacy)" } else { "LZ4" };
    let mut summary = format!("{kind}, {}", count(frames, "frame", "frames"));
    if let Some(t) = total {
        summary = format!("{summary}, {} uncompressed", fmt::size(t));
    }
    cx.annotate(summary);
    Ok(())
}

/// Legacy blocks run until the end of the input or the next magic number.
async fn legacy_extent(cur: &mut Cursor<'_>) -> Result<()> {
    while cur.remaining() >= 4 {
        let size = u32_le(&cur.peek(4).await?, 0).unwrap_or(0);
        if size == FRAME_MAGIC || size == LEGACY_MAGIC || size & 0xffff_fff0 == 0x184d_2a50 {
            break;
        }
        if size > LEGACY_MAX_BLOCK {
            break;
        }
        cur.skip(4u64.saturating_add(size.into()));
    }
    Ok(())
}

async fn legacy_frame(cx: Cx, span: Span) -> Result<()> {
    cx.emit(
        Node::new("Magic")
            .span(span.sub(0, 4))
            .value(hex(LEGACY_MAGIC, 64)),
    );
    let mut cur = Cursor::new(&cx, span.tail(4), LE);
    let mut index = 0u64;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let size = cur.u32().await?;
        if size > LEGACY_MAX_BLOCK {
            break;
        }
        let data = cur.span(size.into());
        cur.skip(size.into());
        let block_span = cur.since(start);
        cx.progress_in(span, block_span.offset);
        cx.push(check_len(
            Node::new(format!("Block {index}"))
                .span(block_span)
                .summary(fmt::size(size.into()))
                .lazy(
                    emit_nodes,
                    Arc::new(vec![
                        Node::new("Compressed size")
                            .span(block_span.sub(0, 4))
                            .value(uint(size, 64)),
                        Node::new("Compressed data")
                            .span(data)
                            .desc("Decoded as part of the whole stream (see Decompressed)"),
                    ]),
                ),
            data,
            size.into(),
        ))
        .await;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn frame(cx: Cx, span: Span) -> Result<()> {
    cx.emit(
        Node::new("Magic")
            .span(span.sub(0, 4))
            .value(hex(FRAME_MAGIC, 64)),
    );
    let flg = cx.read(span.sub(4, 1)).await?.first().copied().unwrap_or(0);
    let dspan = span.sub(4, descriptor_len(flg));
    let d = crate::fields::parse(&cx, dspan, LE, &(), descriptor).await?;
    let summary = d.content_size.map_or_else(
        || "content size not recorded".to_owned(),
        |s| format!("content {}", fmt::size(s)),
    );
    cx.emit(struct_node("Frame descriptor", dspan, LE, (), descriptor).summary(summary));
    let mut cur = Cursor::new(&cx, span, LE);
    cur.seek(4u64.saturating_add(dspan.len));
    let mut index = 0u64;
    while !cur.at_end() {
        let start = cur.pos();
        let raw = cur.u32().await?;
        if raw == 0 {
            cx.push(
                Node::new("End mark")
                    .span(cur.since(start))
                    .value(hex(0u8, 64)),
            )
            .await;
            break;
        }
        let stored = raw & 0x8000_0000 != 0;
        let size = u64::from(raw & 0x7fff_ffff);
        let data = cur.span(size);
        cur.skip(size);
        let mut children = vec![
            Node::new("Block size")
                .span(span.sub(start, 4))
                .value(hex(raw, 64))
                .summary(format!(
                    "{}, {}",
                    fmt::size(size),
                    if stored { "uncompressed" } else { "compressed" }
                )),
            if stored {
                Node::new("Uncompressed data").span(data)
            } else {
                Node::new("Compressed data")
                    .span(data)
                    .desc("Decoded as part of the whole stream (see Decompressed)")
            },
        ];
        if d.block_checksum {
            let at = cur.pos();
            let c = cx.read_avail(span.sub(at, 4)).await?;
            cur.skip(4);
            children.push(
                Node::new("Block checksum")
                    .span(span.sub(at, 4))
                    .value(hex(u32_le(&c, 0).unwrap_or(0), 64)),
            );
        }
        let block_span = cur.since(start);
        cx.progress_in(span, block_span.offset);
        cx.push(check_len(
            Node::new(format!("Block {index}"))
                .span(block_span)
                .summary(format!(
                    "{}, {}",
                    if stored { "uncompressed" } else { "compressed" },
                    fmt::size(size)
                ))
                .lazy(emit_nodes, Arc::new(children)),
            data,
            size,
        ))
        .await;
        index = index.saturating_add(1);
    }
    if d.content_checksum {
        let at = cur.pos();
        let c = cx.read(span.sub(at, 4)).await?;
        cx.emit(
            Node::new("Content checksum")
                .span(span.sub(at, 4))
                .value(hex(u32_le(&c, 0).unwrap_or(0), 64))
                .desc("XXH32 of the decompressed content"),
        );
    }
    Ok(())
}

const SNAPPY_CHUNK: EnumTable = &[
    (0x00, "compressed data"),
    (0x01, "uncompressed data"),
    (0xfe, "padding"),
    (0xff, "stream identifier"),
];

/// Snappy's masked CRC-32C.
fn mask_crc(crc: u32) -> u32 {
    (crc.rotate_right(15)).wrapping_add(0xa282_ead8)
}

pub async fn dissect_snappy(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut data_chunks = 0u64;
    cx.annotate("Snappy framed");
    cx.emit(crate::formats::content(
        "Decompressed",
        input,
        file,
        crate::codec::Codec::SnappyFramed,
        None,
    ));
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let header = cur.bytes(4).await?;
        let kind = header.first().copied().unwrap_or(0);
        let len = u64::from(u32_le(&header, 0).unwrap_or(0) >> 8);
        let body = cur.span(len);
        cur.skip(len);
        let span = cur.since(start);
        let name = match crate::value::lookup(SNAPPY_CHUNK, kind.into()) {
            Some(n) => n.to_owned(),
            None if kind >= 0x80 => format!("skippable chunk {kind:#04x}"),
            None => format!("reserved chunk {kind:#04x}"),
        };
        let mut node = check_len(
            Node::new(capitalize(&name))
                .span(span)
                .summary(fmt::size(len))
                .lazy(snappy_chunk, (span, kind)),
            body,
            len,
        );
        if (0x02..=0x7f).contains(&kind) {
            node = node.diag(Diagnostic::malformed("reserved unskippable chunk type"));
        }
        if kind <= 1 {
            data_chunks = data_chunks.saturating_add(1);
        }
        cx.progress_in(file, span.offset);
        cx.push(node).await;
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(file.tail(cur.pos())));
    }
    cx.annotate(format!(
        "Snappy framed, {}",
        count(data_chunks, "data chunk", "data chunks")
    ));
    Ok(())
}

async fn snappy_chunk(cx: Cx, (span, kind): (Span, u8)) -> Result<()> {
    cx.emit(
        Node::new("Chunk type")
            .span(span.sub(0, 1))
            .value(crate::value::Value::Enum {
                raw: kind.into(),
                bits: 8,
                name: crate::value::lookup(SNAPPY_CHUNK, kind.into()),
            }),
    );
    cx.emit(
        Node::new("Length")
            .span(span.sub(1, 3))
            .value(uint(span.len.saturating_sub(4), 64)),
    );
    let body = span.tail(4);
    match kind {
        0x00 | 0x01 => {
            let crc = cx.read(body.sub(0, 4)).await?;
            let stored = u32_le(&crc, 0).unwrap_or(0);
            let mut crc_node = Node::new("Masked CRC-32C")
                .span(body.sub(0, 4))
                .value(hex(stored, 64));
            let data = body.tail(4);
            if kind == 0x01 {
                if data.len <= cx.limits().max_read {
                    let bytes = cx.read(data).await?;
                    let computed =
                        mask_crc(crate::formats::util::datakit::crc32c_paced(&cx, &bytes).await);
                    crc_node = if computed == stored {
                        crc_node.summary("valid")
                    } else {
                        crc_node.diag(Diagnostic::warning(format!(
                            "CRC mismatch: computed {computed:#010x}"
                        )))
                    };
                }
                cx.emit(crc_node);
                cx.emit(Node::new("Data").span(data));
            } else {
                cx.emit(crc_node.desc("CRC of the uncompressed data"));
                let head = cx.read_avail(data.sub(0, 5)).await?;
                if let Some((len, n)) = crate::bytes::uleb128(&head) {
                    cx.emit(
                        Node::new("Uncompressed length")
                            .span(data.sub(0, to_u64(n)))
                            .value(uint(len, 64))
                            .summary(fmt::size(len)),
                    );
                }
                cx.emit(
                    Node::new("Compressed data")
                        .span(data)
                        .desc("Decoded as part of the whole stream (see Decompressed)"),
                );
            }
        }
        0xff => {
            let id = cx.read_avail(body).await?;
            cx.emit(Node::new("Stream identifier").span(body).value(
                crate::formats::util::val::text(String::from_utf8_lossy(&id)),
            ));
        }
        _ => cx.emit(Node::new("Data").span(body)),
    }
    Ok(())
}
