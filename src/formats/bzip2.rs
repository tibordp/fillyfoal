//! bzip2 streams.
//!
//! A stream is `BZh` plus a block-size digit, then bit-packed blocks, each
//! starting with the 48-bit magic 0x314159265359 (π), and an end-of-stream
//! marker 0x177245385090 (√π) followed by the combined CRC. Only the first
//! block is byte-aligned; the others are found by a bit-level scan when the
//! block list is expanded. The decompressed content is decoded on demand.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::arcutil::{count, hex, human_size, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

const BE: Endian = Endian::Big;
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const EOS_MAGIC: u64 = 0x1772_4538_5090;
const MASK48: u64 = 0xffff_ffff_ffff;
/// Bytes scanned per step of the block search.
const SCAN_STEP: u64 = 64 * 1024;

pub static FORMAT: Format = Format {
    name: "bzip2",
    title: "bzip2 compressed data",
    extensions: &["bz2", "tbz2", "tbz", "bz"],
    mime: "application/x-bzip2",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"BZh")
        && h.data.get(3).is_some_and(|c| (b'1'..=b'9').contains(c))
        && (h.at(4, b"\x31\x41\x59\x26\x53\x59") || h.at(4, b"\x17\x72\x45\x38\x50\x90"))
}

record! {
    pub struct Header {
        magic: ascii[2] "Signature",
        version: ascii[1] "Version" .desc("'h' = Huffman coding (bzip2)"),
        level: ascii[1] "Block size" .with(|l, n| n.summary(format!("{l}00k"))),
    }
}

/// `n` bits starting at bit `bit` of `data` (MSB first).
fn bits(data: &[u8], bit: u64, n: u32) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..u64::from(n) {
        let at = bit.checked_add(i)?;
        let byte = data.get(to_usize(at / 8))?;
        let b = (byte >> 7u64.saturating_sub(at % 8)) & 1;
        v = v << 1 | u64::from(b);
    }
    Some(v)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let (header, header_span) = cur.record::<Header>().await?;
    cx.emit(Header::node("Header", header_span, BE));
    let block_size = header
        .level
        .parse::<u64>()
        .unwrap_or(0)
        .saturating_mul(100_000);

    let body = file.tail(4);
    let first = cx.read_avail(body.sub(0, 14)).await?;
    let empty = bits(&first, 0, 48) == Some(EOS_MAGIC);
    if !empty {
        cx.emit(
            struct_node("First block header", body.sub(0, 14), BE, (), block_header)
                .summary("byte-aligned"),
        );
    }

    // The end-of-stream marker and combined CRC end the stream, padded to a
    // byte boundary; look for them in the last bytes.
    let tail_len = file.len.min(11).min(body.len);
    let tail_span = file.tail(file.len.saturating_sub(tail_len));
    let tail = cx.read_avail(tail_span).await?;
    let tail_bits = to_u64(tail.len()).saturating_mul(8);
    let eos = (0..8u64).find_map(|pad| {
        let start = tail_bits.checked_sub(80u64.saturating_add(pad))?;
        (bits(&tail, start, 48) == Some(EOS_MAGIC)).then(|| {
            (
                start,
                bits(&tail, start.saturating_add(48), 32).unwrap_or(0),
            )
        })
    });

    cx.emit(
        Node::new("Blocks")
            .span(body)
            .summary(format!(
                "up to {} each, found by a bit-level scan",
                human_size(block_size)
            ))
            .lazy(blocks, body),
    );
    cx.emit(crate::formats::content("Decompressed", input, input.span, crate::codec::Codec::Bzip2, None));
    let mut summary = format!("bzip2, {}k blocks", block_size / 1000);
    match eos {
        Some((bit, crc)) => {
            let bit_offset = tail_span
                .offset
                .saturating_sub(body.offset)
                .saturating_mul(8)
                .saturating_add(bit);
            let byte = bit / 8;
            let span = tail_span.tail(byte);
            cx.emit(
                Node::new("End of stream")
                    .span(span)
                    .summary(format!("at bit {bit_offset:#x} of the compressed data"))
                    .lazy(end_of_stream, (span, bit % 8, crc)),
            );
            if empty {
                summary = "bzip2, empty".to_owned();
            }
        }
        None => cx.diag(Diagnostic::warning(
            "no end-of-stream marker at the end (truncated or concatenated streams)",
        )),
    }
    cx.annotate(summary);
    Ok(())
}

fn block_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.bytes("Block magic", 6)
        .desc("0x314159265359 (BCD π)")
        .emit()?;
    f.u32("Block CRC").hex().emit()?;
    let rest = f.bytes("Randomised / original pointer", 4).get()?;
    let randomised = bits(&rest, 0, 1).unwrap_or(0);
    let orig = bits(&rest, 1, 24).unwrap_or(0);
    let span = f.peek_span(0);
    let at = Span::new(span.source, span.offset.saturating_sub(4), 4);
    f.node(
        Node::new("Randomised")
            .span(at.sub(0, 1))
            .value(Value::Bool(randomised != 0))
            .desc("Deprecated; always 0 in modern streams"),
    );
    f.node(
        Node::new("Original pointer")
            .span(at)
            .value(uint(orig))
            .desc("Position of the original string in the BWT matrix (24 bits)"),
    );
    Ok(())
}

async fn end_of_stream(cx: Cx, (span, shift, crc): (Span, u64, u64)) -> Result<()> {
    cx.emit(
        Node::new("End-of-stream magic")
            .span(span.sub(0, 7))
            .value(hex(EOS_MAGIC))
            .summary(format!("√π (BCD), bit offset {shift} in its first byte")),
    );
    cx.emit(
        Node::new("Combined CRC")
            .span(span.sub(6, 5))
            .value(hex(crc)),
    );
    Ok(())
}

/// Scans the compressed data for block magics, bit by bit.
async fn blocks(cx: Cx, body: Span) -> Result<()> {
    let mut window = 0u64;
    let mut seen = 0u64; // bits shifted into the window
    let mut previous: Option<u64> = None; // bit offset of the last block found
    let mut index = 0u64;
    let mut pos = 0u64;
    let mut end_bit = None;
    'scan: while pos < body.len {
        let chunk = cx.read(body.sub(pos, SCAN_STEP)).await?;
        for (i, &byte) in chunk.iter().enumerate() {
            for b in (0..8).rev() {
                window = window << 1 | u64::from((byte >> b) & 1);
                seen = seen.saturating_add(1);
                if seen < 48 {
                    continue;
                }
                let tag = window & MASK48;
                if tag != BLOCK_MAGIC && tag != EOS_MAGIC {
                    continue;
                }
                let start = seen.saturating_sub(48);
                if let Some(prev) = previous {
                    push_block(&cx, body, index, prev, start).await;
                    index = index.saturating_add(1);
                }
                if tag == EOS_MAGIC {
                    end_bit = Some(start);
                    break 'scan;
                }
                previous = Some(start);
            }
            if i % 4096 == 0 {
                cx.checkpoint().await;
            }
        }
        pos = pos.saturating_add(to_u64(chunk.len()));
    }
    if end_bit.is_none() {
        if let Some(prev) = previous {
            push_block(&cx, body, index, prev, body.len.saturating_mul(8)).await;
            index = index.saturating_add(1);
        }
        cx.diag(Diagnostic::warning("end-of-stream marker not found"));
    }
    cx.annotate(count(index, "block", "blocks"));
    Ok(())
}

async fn push_block(cx: &Cx, body: Span, index: u64, start: u64, end: u64) {
    let first = start / 8;
    let last = end.div_ceil(8);
    let span = body.sub(first, last.saturating_sub(first));
    let crc = match cx.read_avail(body.sub(first, 11)).await {
        Ok(data) => bits(&data, (start % 8).saturating_add(48), 32),
        Err(_) => None,
    };
    let mut node = Node::new(format!("Block {index}"))
        .span(span)
        .summary(format!(
            "bit offset {start:#x}, {} compressed",
            human_size(end.saturating_sub(start) / 8)
        ));
    if let Some(crc) = crc {
        node = node.value(hex(crc));
    }
    cx.push(node).await;
}
