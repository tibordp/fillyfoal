//! InnoDB redo logs: `ib_logfile0`, `ib_logfile1`... (MySQL 5.7 to 8.0.29,
//! MariaDB 10.2 to 10.7) and MySQL 8.0.30's `#innodb_redo/#ib_redoN`.
//!
//! The file is a sequence of 512-byte blocks, each ending in a CRC-32C of
//! the rest. The first four are the file header (format, start LSN, the
//! creator), two checkpoint blocks and a block for encryption information;
//! log blocks follow, each with its number, how many bytes it holds and
//! where its first record group starts. Blocks and checksums are shown;
//! the log records inside (a different set of types for every server
//! version) are not decoded.
//!
//! MariaDB 10.8 replaced this with an unframed log (`Phys` format), whose
//! mini-transactions are walked record by record (`redo108`).

use super::redo108;
use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::codec::crc::crc32c;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::grouped_count;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const BLOCK: u64 = 512;
/// The header blocks before the first log block.
const HEADER: u64 = 4 * BLOCK;
/// MariaDB 10.5's format (`PHYS`).
const MARIADB_10_5: u32 = 0x5048_5953;

pub static FORMAT: Format = Format {
    name: "innodb-redo",
    title: "InnoDB redo log",
    extensions: &[],
    mime: "application/x-innodb-redo-log",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const FORMATS: EnumTable = &[
    (1, "MySQL 5.7.9"),
    (2, "MySQL 8.0.1 (unreleased)"),
    (3, "MySQL 8.0.3"),
    (4, "MySQL 8.0.19"),
    (5, "MySQL 8.0.28"),
    (6, "MySQL 8.0.30"),
    (103, "MariaDB 10.3 (encrypted)"),
    (0x5048_5953, "MariaDB 10.5"),
    (0xd048_5953, "MariaDB 10.5 (encrypted)"),
    (0x5068_7973, "MariaDB 10.8"),
    (0xd068_7973, "MariaDB 10.8 (encrypted)"),
];

/// A header block, a known format, a creator string and a valid checksum.
fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let Some(block) = d.get(..512) else {
        return false;
    };
    let Some(format) = u32_be(block, 0) else {
        return false;
    };
    if lookup(FORMATS, format.into()).is_none() {
        return false;
    }
    let creator = block.get(16..48).unwrap_or_default();
    if !creator.first().is_some_and(u8::is_ascii_alphabetic)
        || !creator.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b))
    {
        return false;
    }
    let body = block.get(..508).unwrap_or_default();
    u32_be(block, 508) == Some(crc32c(body))
}

fn checksum_node(block: &[u8], span: Span) -> Node {
    let stored = u32_be(block, 508).unwrap_or(0);
    let n = Node::new("Checksum")
        .span(span.sub(508, 4))
        .value(hex(stored, 32));
    if block.iter().all(|&b| b == 0) {
        return n.summary("empty block");
    }
    let crc = crc32c(block.get(..508).unwrap_or_default());
    if crc == stored {
        n.summary("CRC-32C, valid")
    } else {
        n.diag(Diagnostic::warning(format!(
            "checksum mismatch (computed {crc:#010x})"
        )))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, HEADER)).await?;
    let format = u32_be(&head, 0).unwrap_or(0);
    if format == redo108::FORMAT_10_8 || format == redo108::FORMAT_10_8_ENCRYPTED {
        return redo108::dissect(cx, file, &head, format).await;
    }
    if to_u64(head.len()) < HEADER {
        return Err(Diagnostic::truncated(file.sub(0, HEADER), file.len));
    }
    let mysql = format <= 6;
    let creator = crate::text::until_nul(head.get(16..48).unwrap_or_default());
    let start_lsn = u64_be(&head, 8).unwrap_or(0);
    cx.emit(
        Node::new("File header")
            .span(file.sub(0, BLOCK))
            .summary(format!("{creator}, start LSN {start_lsn}"))
            .lazy(header_block, (file, format)),
    );
    let mut latest = None;
    for (i, at) in [(1u64, BLOCK), (2, 3 * BLOCK)] {
        let b = head
            .get(to_usize(at)..to_usize(at.saturating_add(BLOCK)))
            .unwrap_or_default();
        let lsn = u64_be(b, 8).unwrap_or(0);
        let empty = b.iter().all(|&x| x == 0);
        if !empty && u32_be(b, 508) == Some(crc32c(b.get(..508).unwrap_or_default())) {
            latest = latest.max(Some(lsn));
        }
        if i == 2 {
            cx.emit(encryption_node(file, &head));
        }
        cx.emit(
            Node::new(format!("Checkpoint {i}"))
                .span(file.sub(at, BLOCK))
                .summary(if empty {
                    "empty".to_owned()
                } else {
                    format!("LSN {lsn}")
                })
                .lazy(checkpoint_block, (file.sub(at, BLOCK), mysql, format)),
        );
    }
    let blocks = file.len.saturating_sub(HEADER) / BLOCK;
    cx.emit(
        Node::new("Log blocks")
            .span(file.sub(HEADER, blocks.saturating_mul(BLOCK)))
            .summary(grouped_count(blocks, "block", "blocks"))
            .lazy(log_blocks, (file, blocks, format)),
    );
    let rest = file
        .len
        .saturating_sub(HEADER)
        .saturating_sub(blocks.saturating_mul(BLOCK));
    if rest != 0 && file.len > HEADER {
        cx.emit(
            Node::new("Trailing bytes")
                .span(file.tail(HEADER.saturating_add(blocks.saturating_mul(BLOCK))))
                .diag(Diagnostic::warning(format!(
                    "{rest} bytes after the last block"
                ))),
        );
    }
    let mut summary = format!(
        "InnoDB redo log ({}) by {creator}, start LSN {start_lsn}",
        lookup(FORMATS, format.into()).unwrap_or("unknown format")
    );
    if let Some(lsn) = latest {
        summary.push_str(&format!(", checkpoint at {lsn}"));
    }
    cx.annotate(summary);
    Ok(())
}

fn encryption_node(file: Span, head: &[u8]) -> Node {
    Node::new("Encryption information")
        .span(file.sub(2 * BLOCK, BLOCK))
        .summary(
            if head.get(1024..1027).is_some_and(|m| m.starts_with(b"lC")) {
                "encrypted log"
            } else {
                "not encrypted"
            },
        )
}

async fn header_block(cx: Cx, (file, format): (Span, u32)) -> Result<()> {
    let span = file.sub(0, BLOCK);
    let b = cx.read(span).await?;
    cx.emit(Node::new("Format").span(span.sub(0, 4)).value(Value::Enum {
        raw: format.into(),
        bits: 32,
        name: lookup(FORMATS, format.into()),
    }));
    let second = u32_be(&b, 4).unwrap_or(0);
    cx.emit(if format == 6 {
        Node::new("Log UUID")
            .span(span.sub(4, 4))
            .value(hex(second, 32))
            .desc("Identifies the server instance; every redo file of it carries the same one")
    } else if format == MARIADB_10_5 {
        Node::new("Subformat")
            .span(span.sub(4, 4))
            .value(uint(second, 32))
    } else {
        Node::new("Unused")
            .span(span.sub(4, 4))
            .value(hex(second, 32))
    });
    cx.emit(
        Node::new("Start LSN")
            .span(span.sub(8, 8))
            .value(uint(u64_be(&b, 8).unwrap_or(0), 64))
            .desc("The LSN of the first log block's start"),
    );
    cx.emit(
        Node::new("Creator")
            .span(span.sub(16, 32))
            .value(text(crate::text::until_nul(
                b.get(16..48).unwrap_or_default(),
            ))),
    );
    if format <= 6 {
        let flags = u32_be(&b, 48).unwrap_or(0);
        let mut set = Vec::new();
        for (bit, name) in [
            (1u32, "logging disabled"),
            (2, "crash unsafe"),
            (3, "not initialised"),
        ] {
            if flags & (1 << bit) != 0 {
                set.push(name);
            }
        }
        cx.emit(
            Node::new("Flags")
                .span(span.sub(48, 4))
                .value(hex(flags, 32))
                .summary(if set.is_empty() {
                    "none".to_owned()
                } else {
                    set.join(", ")
                }),
        );
    }
    cx.emit(checksum_node(&b, span));
    Ok(())
}

async fn checkpoint_block(cx: Cx, (span, mysql, format): (Span, bool, u32)) -> Result<()> {
    let b = cx.read(span).await?;
    let u64_at = |o: usize| u64_be(&b, o).unwrap_or(0);
    if !(mysql && format == 6) {
        cx.emit(
            Node::new("Checkpoint number")
                .span(span.sub(0, 8))
                .value(uint(u64_at(0), 64)),
        );
    }
    cx.emit(
        Node::new("Checkpoint LSN")
            .span(span.sub(8, 8))
            .value(uint(u64_at(8), 64))
            .desc("Recovery starts here: everything before it is in the data files"),
    );
    if !(mysql && format == 6) {
        cx.emit(
            Node::new("Checkpoint offset")
                .span(span.sub(16, 8))
                .value(uint(u64_at(16), 64))
                .desc("Byte offset of the checkpoint LSN in the log files"),
        );
        cx.emit(
            Node::new("Log buffer size")
                .span(span.sub(24, 8))
                .value(uint(u64_at(24), 64)),
        );
    }
    if !mysql {
        cx.emit(
            Node::new("End LSN")
                .span(span.sub(32, 8))
                .value(uint(u64_at(32), 64)),
        );
    }
    cx.emit(checksum_node(&b, span));
    Ok(())
}

fn block_summary(b: &[u8], mysql8_30: bool) -> String {
    if b.iter().all(|&x| x == 0) {
        return "unused".to_owned();
    }
    let no = u32_be(b, 0).unwrap_or(0);
    let len = u16_be(b, 4).unwrap_or(0);
    let first = u16_be(b, 6).unwrap_or(0);
    let mut s = format!("block {}, {len} bytes", no & 0x7fff_ffff);
    if first != 0 {
        s.push_str(&format!(", record group at {first}"));
    }
    if no & 0x8000_0000 != 0 && !mysql8_30 {
        s.push_str(", first of a flush");
    }
    if u32_be(b, 508) != Some(crc32c(b.get(..508).unwrap_or_default())) {
        s.push_str(", bad checksum");
    }
    s
}

async fn log_blocks(cx: Cx, (file, blocks, format): (Span, u64, u32)) -> Result<()> {
    cx.set_count(Count::Exact(blocks));
    let start = cx.resume::<u64>().unwrap_or(0);
    for i in start..blocks {
        cx.mark(move || i);
        let span = file.sub(HEADER.saturating_add(i.saturating_mul(BLOCK)), BLOCK);
        let summary = if cx.skipping() {
            String::new()
        } else {
            let b = cx.read(span).await?;
            block_summary(&b, format == 6)
        };
        cx.push(
            Node::new(format!("Block {i}"))
                .span(span)
                .summary(summary)
                .lazy(log_block, (span, format)),
        )
        .await;
    }
    Ok(())
}

async fn log_block(cx: Cx, (span, format): (Span, u32)) -> Result<()> {
    let b = cx.read(span).await?;
    let no = u32_be(&b, 0).unwrap_or(0);
    let mut n = Node::new("Block number")
        .span(span.sub(0, 4))
        .value(uint(no & 0x7fff_ffff, 31));
    if no & 0x8000_0000 != 0 {
        n = n.summary("flush bit set: the first block of a write");
    }
    cx.emit(n);
    let len = u16_be(&b, 4).unwrap_or(0);
    cx.emit(
        Node::new("Data length")
            .span(span.sub(4, 2))
            .value(uint(len, 16))
            .desc("Bytes used, including this 12-byte header; 512 for a full block"),
    );
    let first = u16_be(&b, 6).unwrap_or(0);
    let mut fr = Node::new("First record group")
        .span(span.sub(6, 2))
        .value(uint(first, 16));
    if first == 0 {
        fr = fr.summary("none starts in this block");
    } else if u64::from(first) < BLOCK {
        fr = fr.target(span.sub(first.into(), 1));
    }
    cx.emit(fr);
    cx.emit(
        Node::new(if format == 6 {
            "Epoch"
        } else {
            "Checkpoint number"
        })
        .span(span.sub(8, 4))
        .value(uint(u32_be(&b, 8).unwrap_or(0), 32)),
    );
    let used = u64::from(len).clamp(12, 508);
    if used > 12 {
        cx.emit(
            Node::new("Log records")
                .span(span.sub(12, used.saturating_sub(12)))
                .summary(format!("{} bytes", used.saturating_sub(12))),
        );
    }
    if used < 508 {
        cx.emit(Node::new("Unused").span(span.sub(used, 508u64.saturating_sub(used))));
    }
    cx.emit(checksum_node(&b, span));
    Ok(())
}
