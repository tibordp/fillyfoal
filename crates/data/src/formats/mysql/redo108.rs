//! MariaDB 10.8+ redo logs (`ib_logfile0`, format `Phys`): a 512-byte
//! file header, two 64-byte checkpoint blocks at 4 and 8 KiB, and from
//! 12 KiB a circular log of mini-transactions without block framing.
//!
//! A mini-transaction is a run of log records, then a byte with the
//! sequence bit (1 on the first pass over the circular log, 0 on the
//! second, and so on) and a CRC-32C of the records. A record starts with
//! a byte holding its type and length (a length of 0 means a variable-
//! length integer follows); page records then name the tablespace and
//! page, unless the high bit says "same page as the previous record";
//! before any page record of a mini-transaction, a high bit means a
//! file operation (`FILE_CREATE`, `FILE_MODIFY`, `FILE_CHECKPOINT`...).
//! See `mtr0log.h` and `recv_sys_t::parse` in MariaDB.
//!
//! The mini-transactions are walked from the first byte of the log (or
//! from the latest checkpoint once the log has wrapped around) to the
//! first one whose sequence bit or checksum does not match: the end of
//! the log.

use crate::bytes::{to_u64, to_usize, u32_be, u64_be};
use crate::codec::crc::crc32c;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::{clip, grouped_count, plural, size};
use crate::formats::util::val::{hex, text, uint};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value, lookup};

/// The first checkpoint block, the second, and the log.
const CHECKPOINT_1: u64 = 4096;
const CHECKPOINT_2: u64 = 8192;
const START: u64 = 12288;
const CHECKPOINT_LEN: u64 = 64;
/// Bytes of one mini-transaction read at most.
const MAX_MTR: usize = 4 << 20;

pub const FORMAT_10_8: u32 = 0x5068_7973;
pub const FORMAT_10_8_ENCRYPTED: u32 = 0xd068_7973;

const PAGE_TYPES: EnumTable = &[
    (0x00, "FREE_PAGE"),
    (0x10, "INIT_PAGE"),
    (0x20, "EXTENDED"),
    (0x30, "WRITE"),
    (0x40, "MEMSET"),
    (0x50, "MEMMOVE"),
    (0x60, "RESERVED"),
    (0x70, "OPTION"),
];

const FILE_TYPES: EnumTable = &[
    (0x80, "FILE_CREATE"),
    (0x90, "FILE_DELETE"),
    (0xa0, "FILE_RENAME"),
    (0xb0, "FILE_MODIFY"),
    (0xf0, "FILE_CHECKPOINT"),
];

const EXTENDED: EnumTable = &[
    (0, "INIT_ROW_FORMAT_REDUNDANT"),
    (1, "INIT_ROW_FORMAT_DYNAMIC"),
    (2, "UNDO_INIT"),
    (3, "UNDO_APPEND"),
    (4, "INSERT_HEAP_REDUNDANT"),
    (5, "INSERT_REUSE_REDUNDANT"),
    (6, "INSERT_HEAP_DYNAMIC"),
    (7, "INSERT_REUSE_DYNAMIC"),
    (8, "DELETE_ROW_FORMAT_REDUNDANT"),
    (9, "DELETE_ROW_FORMAT_DYNAMIC"),
    (10, "TRIM_PAGES"),
];

/// The circular log: where it is and how LSNs map onto it.
#[derive(Clone, Copy)]
struct Log {
    file: Span,
    first_lsn: u64,
    capacity: u64,
}

impl Log {
    fn offset(&self, lsn: u64) -> u64 {
        START.saturating_add(
            lsn.saturating_sub(self.first_lsn)
                .checked_rem(self.capacity)
                .unwrap_or(0),
        )
    }

    /// The sequence bit a mini-transaction ending at `lsn` carries.
    fn sequence_bit(&self, lsn: u64) -> u8 {
        let pass = lsn
            .saturating_sub(self.first_lsn)
            .checked_div(self.capacity)
            .unwrap_or(0);
        u8::from(pass & 1 == 0)
    }

    /// The spans of `n` bytes from `lsn` (two if they wrap around).
    fn spans(&self, lsn: u64, n: u64) -> Vec<Span> {
        let at = self.offset(lsn);
        let end = START.saturating_add(self.capacity);
        let first = n.min(end.saturating_sub(at));
        let mut out = vec![self.file.sub(at, first)];
        if first < n {
            out.push(
                self.file
                    .sub(START, n.saturating_sub(first).min(self.capacity)),
            );
        }
        out
    }

    async fn read(&self, cx: &Cx, lsn: u64, n: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for s in self.spans(lsn, n) {
            out.extend(cx.read_avail(s).await?);
        }
        Ok(out)
    }

    /// One span for `n` bytes from `lsn`: the file's, or pieces of it.
    fn span(&self, cx: &Cx, lsn: u64, n: u64) -> Result<Span> {
        let spans = self.spans(lsn, n);
        match spans.as_slice() {
            [one] => Ok(*one),
            _ => cx.add_pieces(
                Origin {
                    parent: self.file,
                    transform: "redo-wrap",
                },
                spans,
            ),
        }
    }
}

/// A variable-length integer (`mlog_decode_varint`): its value and length.
fn varint(b: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *b.get(at)?;
    let byte = |i: usize| b.get(at.checked_add(i)?).map(|&x| u64::from(x));
    Some(match first {
        0..=0x7f => (first.into(), 1),
        0x80..=0xbf => (
            (u64::from(first & 0x3f) << 8 | byte(1)?).checked_add(0x80)?,
            2,
        ),
        0xc0..=0xdf => (
            (u64::from(first & 0x1f) << 16 | byte(1)? << 8 | byte(2)?).checked_add(0x4080)?,
            3,
        ),
        0xe0..=0xef => (
            (u64::from(first & 0x0f) << 24 | byte(1)? << 16 | byte(2)? << 8 | byte(3)?)
                .checked_add(0x20_4080)?,
            4,
        ),
        0xf0..=0xf7 => (
            u64::from(u32_be(b, at.checked_add(1)?)?).checked_add(0x1020_4080)?,
            5,
        ),
        _ => return None,
    })
}

/// One record of a mini-transaction.
#[derive(Clone, Debug)]
struct Rec {
    /// Offset in the mini-transaction, header length, total length.
    at: usize,
    header: usize,
    len: usize,
    /// The first byte.
    kind: u8,
    /// A file operation (before any page record).
    file_op: bool,
    /// The record names the page of the record before.
    same_page: bool,
    /// Tablespace and page, and the bytes they take.
    page: Option<(u64, u64, usize)>,
}

impl Rec {
    fn type_name(&self) -> String {
        let (table, t) = if self.file_op {
            (FILE_TYPES, self.kind & 0xf0)
        } else {
            (PAGE_TYPES, self.kind & 0x70)
        };
        lookup(table, t.into()).map_or_else(|| format!("type {t:#x}"), str::to_owned)
    }
}

/// How a mini-transaction scan ended.
enum Scan {
    /// The records, the end marker's offset and whether the checksum
    /// matched.
    Mtr {
        recs: Vec<Rec>,
        end: usize,
        crc_ok: bool,
    },
    /// More bytes are needed.
    Short,
    /// Not a mini-transaction (the end of the log).
    End(String),
}

/// Scans the mini-transaction at the start of `b`, which should end with
/// sequence bit `bit`.
fn scan(b: &[u8], bit: u8) -> Scan {
    let mut recs = Vec::new();
    let mut at = 0usize;
    let mut got_page = false;
    loop {
        let Some(&first) = b.get(at) else {
            return Scan::Short;
        };
        if first <= 1 {
            if first != bit {
                return Scan::End(if recs.is_empty() {
                    "no mini-transaction follows (sequence bit of an earlier pass)".to_owned()
                } else {
                    "a mini-transaction ends with the wrong sequence bit".to_owned()
                });
            }
            if recs.is_empty() {
                return Scan::End("an empty mini-transaction".to_owned());
            }
            let Some(stored) = u32_be(b, at.saturating_add(1)) else {
                return Scan::Short;
            };
            let crc_ok = crc32c(b.get(..at).unwrap_or_default()) == stored;
            return Scan::Mtr {
                recs,
                end: at,
                crc_ok,
            };
        }
        let mut header = 1usize;
        let mut rlen = usize::from(first & 0x0f);
        if rlen == 0 {
            let Some((add, n)) = varint(b, at.saturating_add(1)) else {
                return if b.len() < at.saturating_add(6) {
                    Scan::Short
                } else {
                    Scan::End(format!("invalid record length at {at:#x}"))
                };
            };
            rlen = to_usize(add).saturating_add(15).saturating_sub(n);
            header = header.saturating_add(n);
        }
        let len = header.saturating_add(rlen);
        if len > MAX_MTR {
            return Scan::End(format!("a record of {len} bytes"));
        }
        let Some(body) = b.get(at.saturating_add(header)..at.saturating_add(len)) else {
            return Scan::Short;
        };
        let high = first & 0x80 != 0;
        let same_page = high && got_page;
        let file_op = high && !got_page;
        if file_op && lookup(FILE_TYPES, (first & 0xf0).into()).is_none() {
            return Scan::End(format!("unknown record type {first:#04x} at {at:#x}"));
        }
        if same_page && first & 0x70 <= 0x10 {
            return Scan::End(format!("invalid same-page record {first:#04x} at {at:#x}"));
        }
        let page = if same_page {
            None
        } else {
            match varint(body, 0).and_then(|(space, n1)| {
                varint(body, n1).map(|(page, n2)| (space, page, n1.saturating_add(n2)))
            }) {
                Some(p) if p.2 <= body.len() => Some(p),
                _ => return Scan::End(format!("record at {at:#x} lacks its page")),
            }
        };
        if !high {
            got_page = true;
        }
        recs.push(Rec {
            at,
            header,
            len,
            kind: first,
            file_op,
            same_page,
            page,
        });
        at = at.saturating_add(len);
    }
}

/// The mini-transaction at `lsn`, read in growing windows.
/// Reads the log ahead in windows, so a walk over many small
/// mini-transactions reads every byte about once.
struct Reader {
    buf: Vec<u8>,
    /// The LSN of the buffer's first byte.
    at: u64,
}

impl Reader {
    /// The mini-transaction at `lsn`: where it starts in the buffer, and
    /// how its scan ended.
    async fn mtr(&mut self, cx: &Cx, log: &Log, lsn: u64) -> Result<(usize, Scan)> {
        let mut window = 64usize << 10;
        loop {
            let off = lsn
                .checked_sub(self.at)
                .map(to_usize)
                .filter(|&o| o <= self.buf.len());
            if let Some(off) = off {
                let b = self.buf.get(off..).unwrap_or_default();
                match scan(b, log.sequence_bit(lsn)) {
                    Scan::Short => {}
                    done => {
                        // Charge the scan over the mini-transaction.
                        if let Scan::Mtr { end, .. } = &done {
                            cx.charge(to_u64(*end) / 64).await;
                        }
                        return Ok((off, done));
                    }
                }
                if off == 0 && self.buf.len() >= window {
                    if window >= MAX_MTR || to_u64(self.buf.len()) >= log.capacity {
                        return Ok((
                            0,
                            Scan::End("the log ends inside a mini-transaction".to_owned()),
                        ));
                    }
                    window = window.saturating_mul(4);
                }
            }
            let n = to_u64(window).min(log.capacity);
            self.buf = log.read(cx, lsn, n).await?;
            self.at = lsn;
            if to_u64(self.buf.len()) < n {
                // Nothing more to read.
                let b = self.buf.as_slice();
                return Ok(match scan(b, log.sequence_bit(lsn)) {
                    Scan::Short => (
                        0,
                        Scan::End("the log ends inside a mini-transaction".to_owned()),
                    ),
                    done => (0, done),
                });
            }
        }
    }
}

pub async fn dissect(cx: Cx, file: Span, head: &[u8], format: u32) -> Result<()> {
    let creator = crate::text::until_nul(head.get(16..48).unwrap_or_default());
    let first_lsn = u64_be(head, 8).unwrap_or(0);
    cx.emit(
        Node::new("File header")
            .span(file.sub(0, 512))
            .summary(format!("{creator}, first LSN {first_lsn}"))
            .lazy(header_block, (file, format)),
    );
    let mut latest: Option<(u64, u64)> = None;
    for (i, at) in [(1u64, CHECKPOINT_1), (2, CHECKPOINT_2)] {
        let span = file.sub(at, CHECKPOINT_LEN);
        let b = cx.read_avail(span).await?;
        let lsn = u64_be(&b, 0).unwrap_or(0);
        let end = u64_be(&b, 8).unwrap_or(0);
        let valid = b.len() == 64
            && b.iter().any(|&x| x != 0)
            && u32_be(&b, 60) == Some(crc32c(b.get(..60).unwrap_or_default()));
        if valid && latest.is_none_or(|(l, _)| lsn > l) {
            latest = Some((lsn, end));
        }
        cx.emit(
            Node::new(format!("Checkpoint {i}"))
                .span(span)
                .summary(if b.iter().all(|&x| x == 0) {
                    "empty".to_owned()
                } else {
                    format!("LSN {lsn}, end LSN {end}")
                })
                .lazy(checkpoint_block, span),
        );
    }
    let capacity = file.len.saturating_sub(START);
    if capacity == 0 {
        return Err(Diagnostic::truncated(file.sub(0, START), file.len));
    }
    let log = Log {
        file,
        first_lsn,
        capacity,
    };
    // Until the log wraps around, it starts at its first byte; after, at
    // the latest checkpoint.
    let from = match latest {
        Some((lsn, _)) if lsn.saturating_sub(first_lsn) >= capacity => lsn,
        _ => first_lsn,
    };
    let encrypted = format == FORMAT_10_8_ENCRYPTED;
    let mut node = Node::new("Mini-transactions")
        .span(file.tail(START))
        .summary(format!(
            "from LSN {from}, in {} of circular log",
            size(capacity)
        ))
        .desc("Each: log records, the sequence bit and a CRC-32C, up to the first that does not match (the end of the log)");
    node = if encrypted {
        node.diag(Diagnostic::unsupported("encrypted redo log"))
    } else {
        node.lazy(mtrs, (log, from))
    };
    cx.emit(node);
    let mut summary = format!(
        "InnoDB redo log (MariaDB 10.8{}) by {creator}, {} capacity",
        if encrypted { ", encrypted" } else { "" },
        size(capacity)
    );
    if let Some((lsn, _)) = latest {
        summary.push_str(&format!(", checkpoint at {lsn}"));
    }
    cx.annotate(summary);
    Ok(())
}

async fn header_block(cx: Cx, (file, format): (Span, u32)) -> Result<()> {
    let span = file.sub(0, 512);
    let b = cx.read(span).await?;
    cx.emit(Node::new("Format").span(span.sub(0, 4)).value(Value::Enum {
        raw: format.into(),
        bits: 32,
        name: Some(if format == FORMAT_10_8 {
            "MariaDB 10.8 (\"Phys\")".into()
        } else {
            "MariaDB 10.8, encrypted".into()
        }),
    }));
    cx.emit(
        Node::new("Unused")
            .span(span.sub(4, 4))
            .value(hex(u32_be(&b, 4).unwrap_or(0), 32)),
    );
    cx.emit(
        Node::new("First LSN")
            .span(span.sub(8, 8))
            .value(uint(u64_be(&b, 8).unwrap_or(0), 64))
            .desc("The LSN of the log's first byte, at offset 12288"),
    );
    cx.emit(
        Node::new("Creator")
            .span(span.sub(16, 32))
            .value(text(crate::text::until_nul(
                b.get(16..48).unwrap_or_default(),
            ))),
    );
    if format == FORMAT_10_8_ENCRYPTED {
        cx.emit(
            Node::new("Encryption information")
                .span(span.sub(48, 64))
                .desc("Key version and nonce of the log's encryption"),
        );
    }
    cx.emit(crc_node(&b, span, 508));
    Ok(())
}

fn crc_node(b: &[u8], span: Span, at: usize) -> Node {
    let stored = u32_be(b, at).unwrap_or(0);
    let n = Node::new("Checksum")
        .span(span.sub(to_u64(at), 4))
        .value(hex(stored, 32));
    let crc = crc32c(b.get(..at).unwrap_or_default());
    if crc == stored {
        n.summary("CRC-32C, valid")
    } else if b.iter().all(|&x| x == 0) {
        n.summary("empty")
    } else {
        n.diag(Diagnostic::warning(format!(
            "checksum mismatch (computed {crc:#010x})"
        )))
    }
}

async fn checkpoint_block(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read(span).await?;
    cx.emit(
        Node::new("Checkpoint LSN")
            .span(span.sub(0, 8))
            .value(uint(u64_be(&b, 0).unwrap_or(0), 64))
            .desc("Recovery starts here: everything before it is in the data files"),
    );
    cx.emit(
        Node::new("End LSN")
            .span(span.sub(8, 8))
            .value(uint(u64_be(&b, 8).unwrap_or(0), 64))
            .desc("The end of the log when the checkpoint was written"),
    );
    cx.emit(Node::new("Reserved").span(span.sub(16, 44)));
    cx.emit(crc_node(&b, span, 60));
    Ok(())
}

/// The mini-transactions from `from` to the end of the log.
async fn mtrs(cx: Cx, (log, from): (Log, u64)) -> Result<()> {
    let (mut lsn, mut index) = cx.resume::<(u64, u64)>().unwrap_or((from, 0));
    let end = from.saturating_add(log.capacity);
    let mut reader = Reader {
        buf: Vec::new(),
        at: lsn,
    };
    while lsn < end {
        let state = (lsn, index);
        cx.mark(move || state);
        let (off, scan) = reader.mtr(&cx, &log, lsn).await?;
        let b = reader.buf.get(off..).unwrap_or_default();
        let (recs, marker, crc_ok) = match scan {
            Scan::Mtr { recs, end, crc_ok } => (recs, end, crc_ok),
            Scan::Short => break,
            Scan::End(why) => {
                let left = end.saturating_sub(lsn);
                cx.push(
                    Node::new("End of the log")
                        .span(
                            log.spans(lsn, left.min(64))
                                .first()
                                .copied()
                                .unwrap_or(log.file),
                        )
                        .summary(format!("at LSN {lsn}: {why}")),
                )
                .await;
                break;
            }
        };
        let len = to_u64(marker).saturating_add(5);
        if !crc_ok {
            cx.push(
                Node::new("End of the log")
                    .span(log.span(&cx, lsn, len)?)
                    .summary(format!(
                        "at LSN {lsn}: a mini-transaction whose checksum does not match"
                    )),
            )
            .await;
            break;
        }
        let span = log.span(&cx, lsn, len)?;
        let first = recs.first().map(|r| describe(r, b)).unwrap_or_default();
        let summary = format!(
            "LSN {lsn}, {}: {}{}",
            plural(recs.len(), "record"),
            first,
            if recs.len() > 1 { ", …" } else { "" }
        );
        cx.push(
            Node::new(format!("Mini-transaction {index}"))
                .span(span)
                .summary(summary)
                .lazy(mtr, (span, lsn)),
        )
        .await;
        cx.progress(lsn.saturating_sub(from), log.capacity);
        lsn = lsn.saturating_add(len);
        index = index.saturating_add(1);
    }
    Ok(())
}

/// A record in a few words.
fn describe(r: &Rec, b: &[u8]) -> String {
    let mut s = r.type_name();
    if let Some((space, page, _)) = r.page {
        if r.file_op {
            s.push_str(&format!(" space {space}"));
        } else {
            s.push_str(&format!(" page {space}:{page}"));
        }
    } else if r.same_page {
        s.push_str(" (same page)");
    }
    let body = b
        .get(r.at.saturating_add(r.header)..r.at.saturating_add(r.len))
        .unwrap_or_default();
    let skip = r.page.map_or(0, |p| p.2);
    let rest = body.get(skip..).unwrap_or_default();
    match r.kind & 0xf0 {
        0x80 | 0x90 | 0xb0 if r.file_op => {
            s.push_str(&format!(" {}", clip(&String::from_utf8_lossy(rest), 60)));
        }
        0xa0 if r.file_op => {
            let names: Vec<String> = rest
                .split(|&x| x == 0)
                .map(|n| clip(&String::from_utf8_lossy(n), 40))
                .collect();
            s.push_str(&format!(" {}", names.join(" to ")));
        }
        0xf0 if r.file_op => match u64_be(rest, 0) {
            Some(lsn) => s.push_str(&format!(" LSN {lsn}")),
            None => s.push_str(" (padding)"),
        },
        _ if !r.file_op && r.kind & 0x70 == 0x20 => {
            if let Some(&sub) = rest.first() {
                s.push_str(&format!(
                    " {}",
                    lookup(EXTENDED, sub.into()).unwrap_or("unknown")
                ));
            }
        }
        _ => {}
    }
    s
}

/// One mini-transaction's records, end marker and checksum.
async fn mtr(cx: Cx, (span, lsn): (Span, u64)) -> Result<()> {
    let b = cx.read(span).await?;
    let bit = b
        .len()
        .checked_sub(5)
        .and_then(|i| b.get(i))
        .copied()
        .unwrap_or(1);
    let Scan::Mtr { recs, end, .. } = scan(&b, bit) else {
        return Err(Diagnostic::malformed("not a mini-transaction"));
    };
    cx.charge(to_u64(b.len()) / 256).await;
    let n = to_u64(recs.len());
    cx.emit(
        Node::new("Records")
            .span(span.sub(0, to_u64(end)))
            .summary(grouped_count(n, "record", "records"))
            .lazy(records, (span, lsn)),
    );
    cx.emit(
        Node::new("Sequence bit")
            .span(span.sub(to_u64(end), 1))
            .value(uint(bit, 8))
            .desc("Flips on every pass over the circular log, so data of the previous pass is told apart"),
    );
    let at = end.saturating_add(1);
    let stored = u32_be(&b, at).unwrap_or(0);
    let crc = crc32c(b.get(..end).unwrap_or_default());
    let node = Node::new("Checksum")
        .span(span.sub(to_u64(at), 4))
        .value(hex(stored, 32))
        .desc("CRC-32C of the records");
    cx.emit(if crc == stored {
        node.summary("CRC-32C, valid")
    } else {
        node.diag(Diagnostic::warning(format!(
            "checksum mismatch (computed {crc:#010x})"
        )))
    });
    Ok(())
}

async fn records(cx: Cx, (span, lsn): (Span, u64)) -> Result<()> {
    let b = cx.read(span).await?;
    let bit = b
        .len()
        .checked_sub(5)
        .and_then(|i| b.get(i))
        .copied()
        .unwrap_or(1);
    let Scan::Mtr { recs, .. } = scan(&b, bit) else {
        return Err(Diagnostic::malformed("not a mini-transaction"));
    };
    cx.set_count(crate::node::Count::Exact(to_u64(recs.len())));
    for (i, r) in recs.iter().enumerate() {
        if i % 256 == 0 {
            cx.checkpoint().await;
        }
        let at = to_u64(r.at);
        cx.push(
            Node::new(format!("Record {i}"))
                .span(span.sub(at, to_u64(r.len)))
                .summary(format!(
                    "LSN {}, {}, {}",
                    lsn.saturating_add(at),
                    describe(r, &b),
                    plural(r.len, "byte")
                ))
                .lazy(
                    record,
                    (span, r.at, r.header, r.len, r.file_op, r.same_page),
                ),
        )
        .await;
    }
    Ok(())
}

async fn record(
    cx: Cx,
    (span, at, header, len, file_op, same_page): (Span, usize, usize, usize, bool, bool),
) -> Result<()> {
    let rspan = span.sub(to_u64(at), to_u64(len));
    let b = cx.read(rspan).await?;
    let first = b.first().copied().unwrap_or(0);
    let (table, t) = if file_op {
        (FILE_TYPES, first & 0xf0)
    } else {
        (PAGE_TYPES, first & 0x70)
    };
    let mut ty = Node::new("Type and length")
        .span(rspan.sub(0, 1))
        .value(hex(first, 8))
        .summary(format!(
            "{}{}, {}",
            lookup(table, t.into()).unwrap_or("unknown"),
            if same_page { ", same page" } else { "" },
            if first & 0x0f == 0 {
                "length follows".to_owned()
            } else {
                plural(first & 0x0f, "more byte")
            }
        ));
    if same_page {
        ty = ty.desc("The high bit: the page of the record before");
    }
    cx.emit(ty);
    if header > 1 {
        cx.emit(
            Node::new("Length")
                .span(rspan.sub(1, to_u64(header.saturating_sub(1))))
                .desc("Variable-length; the record's length less 16"),
        );
    }
    let mut pos = header;
    if !same_page {
        if let Some((space, n1)) = varint(&b, pos) {
            cx.emit(
                Node::new("Tablespace ID")
                    .span(rspan.sub(to_u64(pos), to_u64(n1)))
                    .value(uint(space, 32)),
            );
            pos = pos.saturating_add(n1);
        }
        if let Some((page, n2)) = varint(&b, pos) {
            cx.emit(
                Node::new("Page number")
                    .span(rspan.sub(to_u64(pos), to_u64(n2)))
                    .value(uint(page, 32)),
            );
            pos = pos.saturating_add(n2);
        }
    }
    if pos < len {
        let rest = b.get(pos..).unwrap_or_default();
        let mut payload =
            Node::new("Payload").span(rspan.sub(to_u64(pos), to_u64(len.saturating_sub(pos))));
        if file_op && t != 0xf0 {
            payload = payload.value(text(String::from_utf8_lossy(rest).replace('\0', " → ")));
        } else if file_op {
            payload = payload
                .value(uint(u64_be(rest, 0).unwrap_or(0), 64))
                .summary("checkpoint LSN");
        } else {
            payload = payload.value(Value::Bytes(rest.iter().take(256).copied().collect()));
        }
        cx.emit(payload);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// WRITE to page 1:2 (offset 5, one byte), then WRITE to the same
    /// page, the sequence bit and the CRC-32C.
    fn mtr(bit: u8) -> Vec<u8> {
        let mut b = vec![0x34, 0x01, 0x02, 0x05, 0xaa, 0xb2, 0x01, 0xbb];
        let crc = crc32c(&b);
        b.push(bit);
        b.extend(crc.to_be_bytes());
        b
    }

    #[test]
    fn scans_records_and_trailer() {
        let Scan::Mtr { recs, end, crc_ok } = scan(&mtr(1), 1) else {
            panic!("not a mini-transaction");
        };
        assert!(crc_ok);
        assert_eq!(end, 8);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].page.map(|p| (p.0, p.1)), Some((1, 2)));
        assert!(recs[1].same_page);
        assert_eq!(recs[1].type_name(), "WRITE");
        // The previous pass's sequence bit ends the log.
        assert!(matches!(scan(&mtr(0), 1), Scan::End(_)));
        // Cut short: more bytes are needed.
        assert!(matches!(scan(&mtr(1)[..6], 1), Scan::Short));
    }

    #[test]
    fn varints() {
        assert_eq!(varint(&[0x7f], 0), Some((0x7f, 1)));
        assert_eq!(varint(&[0x80, 0x00], 0), Some((0x80, 2)));
        assert_eq!(varint(&[0xc0, 0x00, 0x00], 0), Some((0x4080, 3)));
        assert_eq!(varint(&[0xf8], 0), None);
    }
}
