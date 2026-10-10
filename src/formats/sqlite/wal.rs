//! SQLite write-ahead logs (`-wal`) and rollback journals (`-journal`).
//!
//! Both hold page images, shown with the same B-tree page view as the
//! database (page numbers inside them are not followed, since the other
//! pages live in the database file).
//!
//! A WAL is valid up to the first frame whose salts differ from the
//! header's or whose cumulative checksum does not match; readers use the
//! frames up to the last commit frame in that prefix. Logs up to
//! `SCAN_BYTES` are verified once when the file is expanded (and the result
//! cached), so every frame can say whether it is committed and whether a
//! later frame supersedes it; larger logs are verified as the frame list is
//! paged through. A rollback journal is a series of segments, each a
//! sector-aligned header followed by page records with a nonce-based
//! checksum.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::btree::{Db, DbRef, Kind};
use super::record::Encoding;
use super::{Role, page_node};
use crate::bytes::{to_u64, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

const BE: Endian = Endian::Big;
/// WAL files up to this size are verified when they are expanded.
const SCAN_BYTES: u64 = 32 << 20;
const WAL_HEADER: u64 = 32;
const FRAME_HEADER: u64 = 24;
const JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];

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
    probe: Probe::Magic(&[(0, &JOURNAL_MAGIC)]),
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

/// The WAL checksum (`walChecksumBytes`): pairs of 32-bit words in the byte
/// order the magic selects, accumulated into `(s1, s2)`.
fn wal_checksum(data: &[u8], big: bool, (mut s1, mut s2): (u32, u32)) -> (u32, u32) {
    for pair in data.as_chunks::<8>().0 {
        let [a0, a1, a2, a3, b0, b1, b2, b3] = *pair;
        let (x0, x1) = if big {
            (
                u32::from_be_bytes([a0, a1, a2, a3]),
                u32::from_be_bytes([b0, b1, b2, b3]),
            )
        } else {
            (
                u32::from_le_bytes([a0, a1, a2, a3]),
                u32::from_le_bytes([b0, b1, b2, b3]),
            )
        };
        s1 = s1.wrapping_add(x0).wrapping_add(s2);
        s2 = s2.wrapping_add(x1).wrapping_add(s1);
    }
    (s1, s2)
}

/// Checks a stored checksum pair against the computed one.
fn checksum_fields(f: &mut Fields<'_>, expected: Option<(u32, u32)>) -> Result<()> {
    let stored1 = f.u32("Checksum-1").hex().emit()?;
    let stored2 = f
        .u32("Checksum-2")
        .hex()
        .desc("With checksum-1: the cumulative checksum, continued from the previous frame (or the header)")
        .emit()?;
    if let Some((e1, e2)) = expected {
        let node = Node::new("Checksum check");
        f.node(if (e1, e2) == (stored1, stored2) {
            node.value(Value::Bool(true)).summary("matches")
        } else {
            node.value(Value::Bool(false))
                .diag(Diagnostic::warning(format!(
                    "computed {e1:#010x} {e2:#010x}"
                )))
        });
    }
    Ok(())
}

fn wal_header_layout(f: &mut Fields<'_>, expected: &Option<(u32, u32)>) -> Result<()> {
    f.u32("Magic")
        .enumeration(WAL_MAGIC)
        .desc("Its lowest bit selects the byte order of the words the checksums add up")
        .emit()?;
    f.u32("File format version")
        .check(|&v| {
            (v != 3_007_000).then(|| Diagnostic::malformed(format!("expected 3007000, not {v}")))
        })
        .desc("3007000 (SQLite 3.7.0)")
        .emit()?;
    f.u32("Database page size").emit()?;
    f.u32("Checkpoint sequence number")
        .desc("Incremented each time the log is reset after a checkpoint")
        .emit()?;
    f.u32("Salt-1")
        .hex()
        .desc("Incremented each time the log restarts; frames with other salts belong to an earlier generation")
        .emit()?;
    f.u32("Salt-2")
        .hex()
        .desc("A new random value each time the log restarts")
        .emit()?;
    checksum_fields(f, *expected)
}

#[derive(Clone, Copy)]
struct FrameCtx {
    salts: (u32, u32),
    /// The checksum this frame should carry, if the log is valid up to it.
    expected: Option<(u32, u32)>,
}

fn frame_header_layout(f: &mut Fields<'_>, ctx: &FrameCtx) -> Result<()> {
    f.u32("Page number")
        .desc("The database page this frame holds a new version of")
        .emit()?;
    f.u32("Database size after commit")
        .with(|&v, n| {
            if v == 0 {
                n.summary("not a commit frame")
            } else {
                n.summary(format!("commit frame: the database is {v} pages"))
            }
        })
        .desc("Non-zero for the last frame of a transaction")
        .emit()?;
    let (salt1, salt2) = ctx.salts;
    let salt_check = move |&v: &u32, n: Node, want: u32| {
        if v == want {
            n.summary("matches the header")
        } else if v == 0 {
            n.summary("not written yet")
        } else {
            n.summary("differs from the header: an earlier generation of the log")
        }
    };
    f.u32("Salt-1")
        .hex()
        .with(|v, n| salt_check(v, n, salt1))
        .emit()?;
    f.u32("Salt-2")
        .hex()
        .with(|v, n| salt_check(v, n, salt2))
        .emit()?;
    checksum_fields(f, ctx.expected)
}

/// Where a frame stands in the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Valid,
    /// Salts of an earlier generation of the log.
    Stale,
    /// Salts and checksums zero: written by an open transaction that
    /// rewrote an earlier frame, to be filled in at commit.
    Unwritten,
    BadChecksum,
    /// Salts match, but an earlier frame ended the valid log.
    AfterEnd,
}

/// The running verification of a log.
#[derive(Clone, Copy)]
struct Chain {
    sums: (u32, u32),
    valid: bool,
}

impl Chain {
    /// Verifies the next frame; returns its status and, while the log is
    /// valid, the checksum it should carry.
    fn step(
        &mut self,
        header: &[u8],
        page: &[u8],
        salts: (u32, u32),
        big: bool,
    ) -> (Status, Option<(u32, u32)>) {
        let salt = (
            u32_be(header, 8).unwrap_or(0),
            u32_be(header, 12).unwrap_or(0),
        );
        let stored = (
            u32_be(header, 16).unwrap_or(0),
            u32_be(header, 20).unwrap_or(0),
        );
        if salt != salts {
            self.valid = false;
            let status = if salt == (0, 0) && stored == (0, 0) {
                Status::Unwritten
            } else {
                Status::Stale
            };
            return (status, None);
        }
        if !self.valid {
            return (Status::AfterEnd, None);
        }
        let sums = wal_checksum(
            page,
            big,
            wal_checksum(header.get(..8).unwrap_or_default(), big, self.sums),
        );
        if sums == stored {
            self.sums = sums;
            (Status::Valid, Some(sums))
        } else {
            self.valid = false;
            (Status::BadChecksum, Some(sums))
        }
    }
}

/// The result of verifying a whole log.
struct Scan {
    statuses: Vec<Status>,
    /// Checksums each frame should carry (while the log is valid).
    expected: Vec<Option<(u32, u32)>>,
    /// Index of the last commit frame of the valid log.
    last_commit: Option<u64>,
    commits: u64,
    /// The latest committed frame of each page.
    latest: BTreeMap<u32, u64>,
}

impl Scan {
    fn valid(&self) -> u64 {
        to_u64(
            self.statuses
                .iter()
                .take_while(|s| **s == Status::Valid)
                .count(),
        )
    }
}

#[derive(Clone, Copy)]
struct Wal {
    input: Input,
    page_size: u64,
    frames: u64,
    salts: (u32, u32),
    big: bool,
    /// The header's checksum, which the first frame continues.
    start: (u32, u32),
}

impl Wal {
    fn frame_len(&self) -> u64 {
        FRAME_HEADER.saturating_add(self.page_size)
    }

    fn frame(&self, i: u64) -> Span {
        self.input.span.sub(
            WAL_HEADER.saturating_add(i.saturating_mul(self.frame_len())),
            self.frame_len(),
        )
    }
}

async fn scan(cx: &Cx, wal: &Wal) -> Result<Scan> {
    let mut out = Scan {
        statuses: Vec::new(),
        expected: Vec::new(),
        last_commit: None,
        commits: 0,
        latest: BTreeMap::new(),
    };
    let mut chain = Chain {
        sums: wal.start,
        valid: true,
    };
    let mut pending: Vec<(u32, u64)> = Vec::new();
    for i in 0..wal.frames {
        let data = cx.read(wal.frame(i)).await?;
        let header = data.get(..24).unwrap_or_default();
        let page = data.get(24..).unwrap_or_default();
        let (status, expected) = chain.step(header, page, wal.salts, wal.big);
        out.statuses.push(status);
        out.expected.push(expected);
        if status == Status::Valid {
            pending.push((u32_be(header, 0).unwrap_or(0), i));
            if u32_be(header, 4).unwrap_or(0) != 0 {
                out.last_commit = Some(i);
                out.commits = out.commits.saturating_add(1);
                out.latest.extend(pending.drain(..));
            }
        }
    }
    Ok(out)
}

/// The reserved bytes per page and the text encoding, from an image of
/// page 1 (whose database header records them) among the first records, if
/// there is one. Records are `stride` bytes from `first`; page images start
/// `skip` bytes in.
async fn page1_info(
    cx: &Cx,
    input: Input,
    first: u64,
    stride: u64,
    count: u64,
    skip: u64,
) -> Result<(u8, Encoding)> {
    for i in 0..count.min(1024) {
        let at = first.saturating_add(i.saturating_mul(stride));
        let head = cx.read_avail(input.span.sub(at, 4)).await?;
        if u32_be(&head, 0) == Some(1) {
            let header = cx
                .read_avail(input.span.sub(at.saturating_add(skip), 100))
                .await?;
            let reserved = header.get(20).copied().unwrap_or(0);
            let encoding = Encoding::from_header(u32_be(&header, 56).unwrap_or(1));
            return Ok((reserved, encoding));
        }
    }
    Ok((0, Encoding::Utf8))
}

fn image_db(input: Input, page_size: u64, (reserved, encoding): (u8, Encoding)) -> DbRef {
    Arc::new(Db {
        input,
        page_size,
        usable: page_size.saturating_sub(reserved.into()).max(480),
        page_count: u64::from(u32::MAX),
        encoding,
        linked: false,
        freelist_trunk: 0,
        largest_root: 0,
    })
}

fn valid_page_size(size: u32) -> Option<u64> {
    let size = u64::from(size);
    (size.is_power_of_two() && (512..=65536).contains(&size)).then_some(size)
}

/// What a page image is, from its first byte (at 100 on page 1).
async fn image_kind(cx: &Cx, image: Span, page: u32) -> Result<String> {
    let at = if page == 1 { 100 } else { 0 };
    let byte = cx.read_avail(image.sub(at, 1)).await?;
    Ok(match byte.first().copied().and_then(Kind::from_byte) {
        Some(kind) => format!("{} B-tree page", kind.name()),
        None => "overflow, freelist or pointer-map page".to_owned(),
    })
}

async fn dissect_wal(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, WalHeader::SIZE);
    let header = crate::fields::parse(&cx, header_span, BE, &(), WalHeader::layout).await;
    let raw = cx.read_avail(header_span).await?;
    let big = header.as_ref().is_ok_and(|h| h.magic & 1 == 1);
    let start = wal_checksum(raw.get(..24).unwrap_or_default(), big, (0, 0));
    let expected = (raw.len() >= 32).then_some(start);
    cx.emit(struct_node(
        "WAL Header",
        header_span,
        BE,
        expected,
        wal_header_layout,
    ));
    let header = header?;
    let page_size = valid_page_size(header.page_size).ok_or_else(|| {
        Diagnostic::malformed(format!("invalid page size {}", header.page_size))
            .at(header_span.sub(8, 4))
    })?;
    let frame_len = FRAME_HEADER.saturating_add(page_size);
    let body = file.len.saturating_sub(WAL_HEADER);
    let frames = body.checked_div(frame_len).unwrap_or(0);
    let header_ok = start == (header.checksum1, header.checksum2);
    let wal = Wal {
        input,
        page_size,
        frames,
        salts: (header.salt1, header.salt2),
        big,
        // A log whose header checksum fails is empty to SQLite.
        start: (header.checksum1, header.checksum2),
    };
    let scanned = if body <= SCAN_BYTES && header_ok {
        let s = Arc::new(scan(&cx, &wal).await?);
        cx.cache(file, "sqlite-wal-scan", s.clone());
        Some(s)
    } else {
        None
    };
    let mut summary = format!(
        "SQLite WAL, {page_size}-byte pages, checkpoint {}, {}",
        header.checkpoint,
        super::plural(frames, "frame", "frames")
    );
    if !header_ok {
        summary.push_str(", header checksum mismatch (the log is ignored)");
    } else if let Some(s) = &scanned {
        let committed = s.last_commit.map_or(0, |c| c.saturating_add(1));
        let valid = s.valid();
        summary = format!(
            "{summary}: {} committed in {}",
            super::thousands(committed),
            super::plural(s.commits, "transaction", "transactions")
        );
        if valid > committed {
            summary = format!("{summary}, {} uncommitted", valid.saturating_sub(committed));
        }
        if frames > valid {
            summary = format!(
                "{summary}, {} past the end of the log",
                frames.saturating_sub(valid)
            );
        }
    }
    cx.annotate(summary);
    let mut frames_node = Node::new("Frames")
        .summary(super::plural(frames, "frame", "frames"))
        .desc("Each frame is a 24-byte header and a new version of one database page")
        .lazy(wal_frames, (wal, header_ok));
    if !header_ok {
        frames_node = frames_node.diag(Diagnostic::warning(
            "the header checksum does not match, so SQLite ignores every frame",
        ));
    }
    cx.emit(frames_node);
    let end = WAL_HEADER.saturating_add(frames.saturating_mul(frame_len));
    if end < file.len {
        cx.emit(
            Node::new("Partial frame")
                .span(file.tail(end))
                .summary(format!("{} bytes", file.len.saturating_sub(end)))
                .desc("An incomplete frame at the end of the log; SQLite ignores it"),
        );
    }
    Ok(())
}

#[derive(Clone)]
struct FrameState {
    db: DbRef,
    span: Span,
    page: u32,
    ctx: FrameCtx,
}

async fn wal_frames(cx: Cx, (wal, header_ok): (Wal, bool)) -> Result<()> {
    cx.set_count(Count::Exact(wal.frames));
    let info = page1_info(
        &cx,
        wal.input,
        WAL_HEADER,
        wal.frame_len(),
        wal.frames,
        FRAME_HEADER,
    )
    .await?;
    let db = image_db(wal.input, wal.page_size, info);
    let scanned = cx.cached::<Scan>(wal.input.span, "sqlite-wal-scan");
    let (start, mut chain) = cx.resume::<(u64, (u32, u32), bool)>().map_or(
        (
            0,
            Chain {
                sums: wal.start,
                valid: header_ok,
            },
        ),
        |(i, sums, valid)| (i, Chain { sums, valid }),
    );
    for i in start..wal.frames {
        let state = (i, chain.sums, chain.valid);
        cx.mark(move || state);
        let span = wal.frame(i);
        let (status, expected, head) = match &scanned {
            Some(s) => {
                let head = cx.read(span.sub(0, FRAME_HEADER)).await?;
                let index = crate::bytes::to_usize(i);
                (
                    s.statuses.get(index).copied().unwrap_or(Status::AfterEnd),
                    s.expected.get(index).copied().flatten(),
                    head,
                )
            }
            None => {
                let data = cx.read(span).await?;
                let head = data.get(..24).unwrap_or_default().to_vec();
                let page = data.get(24..).unwrap_or_default();
                let (status, expected) = chain.step(&head, page, wal.salts, wal.big);
                (status, expected, head)
            }
        };
        let page = u32_be(&head, 0).unwrap_or(0);
        let commit = u32_be(&head, 4).unwrap_or(0);
        let mut summary = format!("page {page}");
        if status == Status::Valid && commit != 0 {
            summary = format!("{summary}, commit (database is {commit} pages)");
        }
        let note = match (status, &scanned) {
            (Status::Valid, Some(s)) if s.last_commit.is_some_and(|c| i <= c) => {
                match s.latest.get(&page) {
                    Some(&latest) if latest == i => "committed, current version".to_owned(),
                    Some(&latest) => format!("committed, superseded by frame {latest}"),
                    None => "committed".to_owned(),
                }
            }
            (Status::Valid, Some(_)) => "uncommitted: no commit frame follows".to_owned(),
            (Status::Valid, None) => "checksum ok".to_owned(),
            (Status::Stale, _) => "stale: salts of an earlier generation of the log".to_owned(),
            (Status::Unwritten, _) => {
                "salts and checksum not written yet (an open transaction)".to_owned()
            }
            (Status::BadChecksum, _) => {
                "checksum mismatch: the valid log ends before this frame".to_owned()
            }
            (Status::AfterEnd, _) => "after the end of the valid log".to_owned(),
        };
        summary = format!("{summary}; {note}");
        cx.push(
            Node::new(format!("Frame {i}"))
                .span(span)
                .summary(summary)
                .lazy(
                    frame,
                    FrameState {
                        db: db.clone(),
                        span,
                        page,
                        ctx: FrameCtx {
                            salts: wal.salts,
                            expected,
                        },
                    },
                ),
        )
        .await;
    }
    Ok(())
}

async fn frame(cx: Cx, state: FrameState) -> Result<()> {
    cx.emit(struct_node(
        "Frame header",
        state.span.sub(0, FRAME_HEADER),
        BE,
        state.ctx,
        frame_header_layout,
    ));
    let image = state.span.tail(FRAME_HEADER);
    let kind = image_kind(&cx, image, state.page).await?;
    cx.emit(
        page_node(
            &state.db,
            format!("Page {}", state.page),
            state.page,
            image,
            Role::Unknown,
        )
        .summary(kind),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Rollback journal

record! {
    pub struct JournalHeader {
        magic: bytes[8] "Magic",
        page_count: u32 "Page count"
            .with(|&v, n| match v {
                0 => n.summary("not yet synced: the records are those that verify"),
                u32::MAX => n.summary("up to the end of the file"),
                _ => n,
            })
            .desc("Page records in this segment, written when the journal is synced; 0xffffffff (no-sync mode) means up to the end of the file"),
        nonce: u32 "Checksum nonce" .hex() .desc("Random; the starting value of every record's checksum in this segment"),
        initial_size: u32 "Initial database size in pages" .desc("A rollback truncates the database back to this size"),
        sector_size: u32 "Sector size" .desc("Segment headers start on multiples of this and are padded to it"),
        page_size: u32 "Page size",
    }
}

/// One segment of a journal: a header and the page records it counts.
#[derive(Clone, Copy, Debug)]
struct Segment {
    at: u64,
    records_at: u64,
    declared: u32,
    nonce: u32,
    /// Records the header vouches for.
    records: u64,
    /// Where the next segment would start (or the end of the journal).
    end: u64,
    last: bool,
}

/// The checksum of a page record: the nonce plus every 200th byte of the
/// page, from the end (`pager_cksum`).
fn journal_checksum(nonce: u32, page: &[u8]) -> u32 {
    let mut sum = nonce;
    let mut i = page.len().saturating_sub(200);
    while i > 0 {
        sum = sum.wrapping_add(page.get(i).copied().unwrap_or(0).into());
        i = i.saturating_sub(200);
    }
    sum
}

/// A super-journal name at the end of the journal (multi-database
/// transactions): page number, name, its length and checksum, magic.
async fn super_journal(cx: &Cx, file: Span) -> Result<Option<Span>> {
    if file.len < 24 {
        return Ok(None);
    }
    let tail = cx.read(file.sub(file.len.saturating_sub(16), 16)).await?;
    if tail.get(8..) != Some(&JOURNAL_MAGIC[..]) {
        return Ok(None);
    }
    let len = u64::from(u32_be(&tail, 0).unwrap_or(0));
    let size = len.saturating_add(16);
    let fits = len != 0 && len <= 65536 && size.saturating_add(4) <= file.len.saturating_sub(28);
    Ok(fits.then(|| {
        file.sub(
            file.len.saturating_sub(size.saturating_add(4)),
            size.saturating_add(4),
        )
    }))
}

async fn dissect_journal(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = crate::fields::parse(
        &cx,
        file.sub(0, JournalHeader::SIZE),
        BE,
        &(),
        JournalHeader::layout,
    )
    .await?;
    let page_size = valid_page_size(header.page_size).ok_or_else(|| {
        Diagnostic::malformed(format!("invalid page size {}", header.page_size)).at(file.sub(24, 4))
    })?;
    let sector = u64::from(header.sector_size).clamp(JournalHeader::SIZE, 65536);
    let record = page_size.saturating_add(8);
    let super_name = super_journal(&cx, file).await?;
    let limit = super_name.map_or(file.len, |s| s.offset.saturating_sub(file.offset));

    // Segments: each header starts on a sector boundary after the records
    // of the one before.
    let mut segments: Vec<Segment> = Vec::new();
    let mut at = 0u64;
    while at.saturating_add(JournalHeader::SIZE) <= limit {
        cx.checkpoint().await;
        let head = cx.read(file.sub(at, JournalHeader::SIZE)).await?;
        if head.get(..8) != Some(&JOURNAL_MAGIC[..]) {
            break;
        }
        let declared = u32_be(&head, 8).unwrap_or(0);
        let nonce = u32_be(&head, 12).unwrap_or(0);
        let records_at = at.saturating_add(sector);
        let available = limit
            .saturating_sub(records_at)
            .checked_div(record)
            .unwrap_or(0);
        let records = match declared {
            u32::MAX => available,
            n => u64::from(n).min(available),
        };
        let next = records_at
            .saturating_add(records.saturating_mul(record))
            .next_multiple_of(sector);
        segments.push(Segment {
            at,
            records_at,
            declared,
            nonce,
            records,
            end: next.min(limit),
            last: false,
        });
        if records == 0 || next <= at {
            break;
        }
        at = next;
    }
    if let Some(last) = segments.last_mut() {
        last.last = true;
        last.end = limit;
    }
    let total = segments
        .iter()
        .fold(0u64, |a, s| a.saturating_add(s.records));
    let mut summary = format!(
        "SQLite rollback journal, {}",
        super::plural(total, "page record", "page records")
    );
    if segments.len() > 1 {
        summary = format!("{summary} in {} segments", segments.len());
    }
    if segments.last().is_some_and(|s| s.declared == 0) {
        summary.push_str(" (the last segment is not yet synced)");
    }
    cx.annotate(format!(
        "{summary}, {page_size}-byte pages, database was {} pages",
        header.initial_size
    ));
    let stored = limit
        .saturating_sub(sector)
        .checked_div(record)
        .unwrap_or(0);
    let info = page1_info(&cx, input, sector, record, stored, 4).await?;
    let db = image_db(input, page_size, info);
    let count = segments.len();
    for (i, seg) in segments.into_iter().enumerate() {
        if count == 1 {
            segment_nodes(&cx, &db, seg).await?;
        } else {
            let mut node = Node::new(format!("Segment {i}"))
                .span(file.sub(seg.at, seg.end.saturating_sub(seg.at)))
                .summary(format!(
                    "{}, nonce {:#010x}",
                    super::plural(seg.records, "record", "records"),
                    seg.nonce
                ))
                .lazy(segment, (db.clone(), seg));
            if seg.declared == 0 {
                node = node.desc("The header's page count is 0: this segment had not been synced");
            }
            cx.emit(node);
        }
    }
    if let Some(span) = super_name {
        cx.emit(
            Node::new("Super-journal name")
                .span(span)
                .desc("Names the journal of a transaction across several attached databases")
                .lazy(super_journal_fields, span),
        );
    }
    Ok(())
}

async fn super_journal_fields(cx: Cx, span: Span) -> Result<()> {
    let name_len = span.len.saturating_sub(20);
    cx.emit(
        Node::new("Lock-byte page number")
            .span(span.sub(0, 4))
            .desc("Marks this record: no page record has this page number"),
    );
    let name = cx.read(span.sub(4, name_len.min(4096))).await?;
    cx.emit(
        Node::new("Name")
            .span(span.sub(4, name_len))
            .value(Value::Text(String::from_utf8_lossy(&name).into_owned())),
    );
    let rest = span.tail(name_len.saturating_add(4));
    let tail = cx.read(rest).await?;
    for (name, at) in [("Name length", 0usize), ("Name checksum", 4)] {
        if let Some(v) = u32_be(&tail, at) {
            cx.emit(
                Node::new(name)
                    .span(rest.sub(to_u64(at), 4))
                    .value(Value::UInt {
                        value: v.into(),
                        bits: 32,
                        radix: if at == 0 { Radix::Dec } else { Radix::Hex },
                    }),
            );
        }
    }
    cx.emit(Node::new("Magic").span(rest.sub(8, 8)));
    Ok(())
}

async fn segment(cx: Cx, (db, seg): (DbRef, Segment)) -> Result<()> {
    segment_nodes(&cx, &db, seg).await
}

async fn segment_nodes(cx: &Cx, db: &DbRef, seg: Segment) -> Result<()> {
    let file = db.input.span;
    cx.emit(JournalHeader::node(
        "Journal Header",
        file.sub(seg.at, JournalHeader::SIZE),
        BE,
    ));
    let header_end = seg.at.saturating_add(JournalHeader::SIZE);
    if seg.records_at > header_end {
        cx.emit(
            Node::new("Header padding")
                .span(file.sub(header_end, seg.records_at.saturating_sub(header_end)))
                .summary("pads the header to a sector"),
        );
    }
    let record = db.page_size.saturating_add(8);
    let mut i = 0u64;
    loop {
        let at = seg.records_at.saturating_add(i.saturating_mul(record));
        if at.saturating_add(record) > seg.end {
            break;
        }
        let counted = i < seg.records;
        if !counted && !seg.last {
            break;
        }
        let span = file.sub(at, record);
        let data = cx.read(span).await?;
        let page = u32_be(&data, 0).unwrap_or(0);
        let image = data
            .get(4..crate::bytes::to_usize(db.page_size.saturating_add(4)))
            .unwrap_or_default();
        let stored = u32_be(
            &data,
            crate::bytes::to_usize(db.page_size.saturating_add(4)),
        );
        let computed = journal_checksum(seg.nonce, image);
        let ok = stored == Some(computed);
        if !counted && (page == 0 || !ok) {
            // Past the counted records, only records that verify are shown.
            break;
        }
        let mut summary = format!("original content of page {page}");
        if !counted {
            summary.push_str(", not counted by the header (written after the last sync)");
        }
        let mut node = Node::new(format!("Record {i}"))
            .span(span)
            .summary(summary)
            .lazy(journal_record, (db.clone(), span, page, computed));
        if !ok {
            node = node.diag(Diagnostic::warning(
                "checksum mismatch: rollback would stop here",
            ));
        }
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    let used = seg
        .records_at
        .saturating_add(i.saturating_mul(record))
        .min(seg.end);
    if used < seg.end {
        cx.push(
            Node::new(if seg.last { "Unused" } else { "Padding" })
                .span(file.sub(used, seg.end.saturating_sub(used)))
                .summary(if seg.last {
                    "after the last record; ignored by rollback"
                } else {
                    "to the next sector boundary"
                }),
        )
        .await;
    }
    Ok(())
}

async fn journal_record(cx: Cx, (db, span, page, computed): (DbRef, Span, u32, u32)) -> Result<()> {
    let at = |o: u64, n: u64| span.sub(o, n);
    cx.emit(
        Node::new("Page number")
            .span(at(0, 4))
            .value(Value::UInt {
                value: page.into(),
                bits: 32,
                radix: Radix::Dec,
            })
            .desc("The database page whose original content follows"),
    );
    let image = at(4, db.page_size);
    let kind = image_kind(&cx, image, page).await?;
    cx.emit(page_node(&db, format!("Page {page}"), page, image, Role::Unknown).summary(kind));
    let checksum = at(4u64.saturating_add(db.page_size), 4);
    let data = cx.read_avail(checksum).await?;
    let mut node = Node::new("Checksum")
        .span(checksum)
        .desc("The segment's nonce plus every 200th byte of the page, counted from the end");
    if let Some(v) = u32_be(&data, 0) {
        node = node.value(Value::UInt {
            value: v.into(),
            bits: 32,
            radix: Radix::Hex,
        });
        node = if v == computed {
            node.summary("matches")
        } else {
            node.diag(Diagnostic::warning(format!("computed {computed:#010x}")))
        };
    }
    cx.emit(node);
    Ok(())
}
