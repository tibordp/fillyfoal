//! SQLite write-ahead logs (`-wal`) and rollback journals (`-journal`).
//!
//! Both hold page images; frames/records are listed in pages, and each
//! page image is shown with the same B-tree page view as the database
//! (page numbers inside them are not followed, since the other pages live in
//! the database file).

use std::sync::Arc;

use super::btree::{Db, DbRef};
use super::record::Encoding;
use super::{Role, page_node};
use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::value::EnumTable;

const BE: Endian = Endian::Big;

pub static WAL: Format = Format {
    name: "sqlite-wal",
    title: "SQLite write-ahead log",
    extensions: &["db-wal", "sqlite-wal", "wal"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| {
        (h.starts_with(&[0x37, 0x7f, 0x06, 0x82]) || h.starts_with(&[0x37, 0x7f, 0x06, 0x83]))
            && h.at(4, &3_007_000u32.to_be_bytes())
    }),
    dissect: crate::expander!(dissect_wal: Input),
};

pub static JOURNAL: Format = Format {
    name: "sqlite-journal",
    title: "SQLite rollback journal",
    extensions: &["db-journal", "sqlite-journal"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, &[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7])]),
    dissect: crate::expander!(dissect_journal: Input),
};

const WAL_MAGIC: EnumTable = &[
    (0x377f_0682, "little-endian checksums"),
    (0x377f_0683, "big-endian checksums"),
];

record! {
    pub struct WalHeader {
        magic: u32 "Magic" .enumeration(WAL_MAGIC),
        version: u32 "File format version",
        page_size: u32 "Database page size",
        checkpoint: u32 "Checkpoint sequence number",
        salt1: u32 "Salt-1" .hex(),
        salt2: u32 "Salt-2" .hex(),
        checksum1: u32 "Checksum-1" .hex(),
        checksum2: u32 "Checksum-2" .hex(),
    }
}

record! {
    pub struct FrameHeader {
        page: u32 "Page number",
        commit_size: u32 "Database size after commit" .desc("Non-zero for the last frame of a transaction"),
        salt1: u32 "Salt-1" .hex(),
        salt2: u32 "Salt-2" .hex(),
        checksum1: u32 "Checksum-1" .hex(),
        checksum2: u32 "Checksum-2" .hex(),
    }
}

record! {
    pub struct JournalHeader {
        magic: bytes[8] "Magic",
        page_count: u32 "Page count" .desc("Records in this segment; -1 means up to the end of the file"),
        nonce: u32 "Checksum nonce" .hex(),
        initial_size: u32 "Initial database size in pages",
        sector_size: u32 "Sector size",
        page_size: u32 "Page size",
    }
}

fn image_db(input: Input, page_size: u64) -> DbRef {
    Arc::new(Db {
        input,
        page_size,
        usable: page_size,
        page_count: u64::from(u32::MAX),
        encoding: Encoding::Utf8,
        linked: false,
    })
}

fn valid_page_size(size: u32) -> Option<u64> {
    let size = u64::from(size);
    (size.is_power_of_two() && (512..=65536).contains(&size)).then_some(size)
}

async fn dissect_wal(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, WalHeader::SIZE);
    cx.emit(WalHeader::node("WAL Header", header_span, BE));
    let header = crate::fields::parse(&cx, header_span, BE, &(), WalHeader::layout).await?;
    let page_size = valid_page_size(header.page_size).ok_or_else(|| {
        Diagnostic::malformed(format!("invalid page size {}", header.page_size))
            .at(header_span.sub(8, 4))
    })?;
    let frame = FrameHeader::SIZE.saturating_add(page_size);
    let frames = file
        .len
        .saturating_sub(WalHeader::SIZE)
        .checked_div(frame)
        .unwrap_or(0);
    cx.annotate(format!(
        "SQLite WAL, {frames} frames of {page_size}-byte pages, checkpoint {}",
        header.checkpoint
    ));
    cx.emit(
        Node::new("Frames")
            .summary(format!("{frames} frames"))
            .lazy(
                wal_frames,
                (input, page_size, frames, header.salt1, header.salt2),
            ),
    );
    Ok(())
}

async fn wal_frames(
    cx: Cx,
    (input, page_size, frames, salt1, salt2): (Input, u64, u64, u32, u32),
) -> Result<()> {
    cx.set_count(Count::Exact(frames));
    let db = image_db(input, page_size);
    let frame_len = FrameHeader::SIZE.saturating_add(page_size);
    for i in 0..frames {
        let span = input.span.sub(
            WalHeader::SIZE.saturating_add(i.saturating_mul(frame_len)),
            frame_len,
        );
        let head = cx.read(span.sub(0, FrameHeader::SIZE)).await?;
        let page = u32_be(&head, 0).unwrap_or(0);
        let commit = u32_be(&head, 4).unwrap_or(0);
        let current = u32_be(&head, 8) == Some(salt1) && u32_be(&head, 12) == Some(salt2);
        let mut summary = format!("page {page}");
        if commit != 0 {
            summary = format!("{summary}, commit (database is {commit} pages)");
        }
        if !current {
            summary.push_str(", stale (salt mismatch)");
        }
        cx.push(
            Node::new(format!("Frame {i}"))
                .span(span)
                .summary(summary)
                .lazy(frame, (db.clone(), span, page)),
        )
        .await;
    }
    Ok(())
}

async fn frame(cx: Cx, (db, span, page): (DbRef, crate::span::Span, u32)) -> Result<()> {
    cx.emit(FrameHeader::node(
        "Frame header",
        span.sub(0, FrameHeader::SIZE),
        BE,
    ));
    let image = span.tail(FrameHeader::SIZE);
    cx.emit(page_node(
        &db,
        format!("Page {page}"),
        page,
        image,
        Role::Unknown,
    ));
    Ok(())
}

async fn dissect_journal(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, JournalHeader::SIZE);
    cx.emit(JournalHeader::node("Journal Header", header_span, BE));
    let header = crate::fields::parse(&cx, header_span, BE, &(), JournalHeader::layout).await?;
    let page_size = valid_page_size(header.page_size).ok_or_else(|| {
        Diagnostic::malformed(format!("invalid page size {}", header.page_size))
            .at(header_span.sub(24, 4))
    })?;
    let sector = u64::from(header.sector_size).clamp(JournalHeader::SIZE, 65536);
    let record = page_size.saturating_add(8);
    let available = file
        .len
        .saturating_sub(sector)
        .checked_div(record)
        .unwrap_or(0);
    let count = match header.page_count {
        u32::MAX | 0 => available,
        n => u64::from(n).min(available),
    };
    cx.annotate(format!(
        "SQLite rollback journal, {count} pages of {page_size} bytes, database was {} pages",
        header.initial_size
    ));
    if sector > JournalHeader::SIZE {
        cx.emit(Node::new("Header padding").span(file.sub(
            JournalHeader::SIZE,
            sector.saturating_sub(JournalHeader::SIZE),
        )));
    }
    cx.emit(
        Node::new("Page records")
            .summary(format!("{count} records"))
            .lazy(journal_records, (input, page_size, sector, count)),
    );
    Ok(())
}

async fn journal_records(
    cx: Cx,
    (input, page_size, start, count): (Input, u64, u64, u64),
) -> Result<()> {
    cx.set_count(Count::Exact(count));
    let db = image_db(input, page_size);
    let record = page_size.saturating_add(8);
    for i in 0..count {
        let span = input
            .span
            .sub(start.saturating_add(i.saturating_mul(record)), record);
        let head = cx.read(span.sub(0, 4)).await?;
        let page = u32_be(&head, 0).unwrap_or(0);
        cx.push(
            Node::new(format!("Record {i}"))
                .span(span)
                .summary(format!("original content of page {page}"))
                .lazy(journal_record, (db.clone(), span, page)),
        )
        .await;
    }
    Ok(())
}

async fn journal_record(cx: Cx, (db, span, page): (DbRef, crate::span::Span, u32)) -> Result<()> {
    let at = |o: u64, n: u64| span.sub(o, n);
    cx.emit(
        Node::new("Page number")
            .span(at(0, 4))
            .value(crate::value::Value::UInt {
                value: page.into(),
                bits: 32,
                radix: crate::value::Radix::Dec,
            }),
    );
    cx.emit(page_node(
        &db,
        format!("Page {page}"),
        page,
        at(4, db.page_size),
        Role::Unknown,
    ));
    let checksum = at(4u64.saturating_add(db.page_size), 4);
    let data = cx.read_avail(checksum).await?;
    let mut node = Node::new("Checksum").span(checksum);
    if let Some(v) = u32_be(&data, 0) {
        node = node.value(crate::value::Value::UInt {
            value: v.into(),
            bits: 32,
            radix: crate::value::Radix::Hex,
        });
    }
    cx.emit(node);
    Ok(())
}
