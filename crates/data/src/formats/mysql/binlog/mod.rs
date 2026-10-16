//! MySQL and MariaDB binary logs (`mysql-bin.000001`, `binlog.000001`,
//! relay logs), format version 4: the magic `\xfebin`, then events. Every
//! event starts with a 19-byte common header (timestamp, type, server ID,
//! event size, the position after it, flags); the first is the format
//! description event, which gives the server version, the header length,
//! each event type's post-header length and whether events end with a
//! CRC-32 (`binlog_checksum`), verified here for every event.
//!
//! Events decoded: format description, query (with its status variables),
//! rotate, intvar, rand, user variable, XID, stop, table map (with the
//! optional metadata of `binlog_row_metadata=FULL`), rows events v1 and v2
//! (write, update, delete: the rows and their column values for the
//! common types, see `rows`), partial update rows
//! (`binlog_row_value_options=PARTIAL_JSON`: the JSON diffs of the after
//! image), XA prepare (with its XID), rows query, MySQL GTIDs (with logical
//! clocks, commit timestamps and server versions), anonymous GTIDs and
//! previous GTIDs, transaction payloads (zstd-compressed transactions,
//! `binlog_transaction_compression`, whose events are walked in turn),
//! MariaDB's annotate-rows, binlog checkpoint, GTID (with the XID of an
//! XA transaction), GTID list and start encryption events, and
//! MariaDB's compressed query and rows events (`log_bin_compress`, zlib). Other events are shown with their header
//! and raw body. After MariaDB's start encryption event
//! (`encrypt_binlog`), every event is encrypted but for its size (at the
//! usual offset 9): those are listed as encrypted events, unchecked. A
//! replica's relay log (its first event flagged `RELAY_LOG`) has the
//! same layout, but its events carry their positions in the source's
//! binary log.
//!
//! Layouts written from memory of MySQL's binary log documentation
//! (`libbinlogevents`, the internals manual) and MariaDB's knowledge base
//! (no source was consulted while writing this); checked against files
//! written by MySQL 8.0.46 and 9.7.1, MariaDB 10.5.29 and 11.4.13, the
//! decoded rows against the statements that wrote them and, for MariaDB, against
//! `mariadb-binlog -vv` (MariaDB 11.4).

pub(crate) mod rows;

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::crc32_paced;
use crate::formats::util::fmt::{clip, plural, uuid};
use crate::formats::util::val::{enumv, flagsv, hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Check, EnumTable, FlagTable, Value, flag, lookup};

use rows::{Column, TableMap, lenenc};

pub static FORMAT: Format = Format {
    name: "mysql-binlog",
    title: "MySQL/MariaDB binary log",
    extensions: &["binlog"],
    mime: "application/x-mysql-binlog",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const MAGIC: &[u8; 4] = b"\xfebin";
/// The common header of format version 4.
const HEADER: u64 = 19;
/// Events larger than this are listed but not checksummed or decoded.
const MAX_EVENT: u64 = 64 << 20;
/// Text shown at most from a query.
const MAX_QUERY: usize = 64 * 1024;

const EVENT_TYPES: EnumTable = &[
    (0, "Unknown"),
    (1, "Start (v3)"),
    (2, "Query"),
    (3, "Stop"),
    (4, "Rotate"),
    (5, "Intvar"),
    (6, "Load"),
    (7, "Slave"),
    (8, "Create file"),
    (9, "Append block"),
    (10, "Exec load"),
    (11, "Delete file"),
    (12, "New load"),
    (13, "Rand"),
    (14, "User var"),
    (15, "Format description"),
    (16, "Xid"),
    (17, "Begin load query"),
    (18, "Execute load query"),
    (19, "Table map"),
    (20, "Write rows (pre-GA)"),
    (21, "Update rows (pre-GA)"),
    (22, "Delete rows (pre-GA)"),
    (23, "Write rows v1"),
    (24, "Update rows v1"),
    (25, "Delete rows v1"),
    (26, "Incident"),
    (27, "Heartbeat"),
    (28, "Ignorable"),
    (29, "Rows query"),
    (30, "Write rows"),
    (31, "Update rows"),
    (32, "Delete rows"),
    (33, "GTID"),
    (34, "Anonymous GTID"),
    (35, "Previous GTIDs"),
    (36, "Transaction context"),
    (37, "View change"),
    (38, "XA prepare"),
    (39, "Partial update rows"),
    (40, "Transaction payload"),
    (41, "Heartbeat v2"),
    (42, "GTID (tagged)"),
    (160, "Annotate rows"),
    (161, "Binlog checkpoint"),
    (162, "MariaDB GTID"),
    (163, "MariaDB GTID list"),
    (164, "Start encryption"),
    (165, "Query (compressed)"),
    (166, "Write rows v1 (compressed)"),
    (167, "Update rows v1 (compressed)"),
    (168, "Delete rows v1 (compressed)"),
    (169, "Write rows (compressed)"),
    (170, "Update rows (compressed)"),
    (171, "Delete rows (compressed)"),
];

const EVENT_FLAGS: FlagTable = &[
    flag(0x1, "BINLOG_IN_USE"),
    flag(0x2, "FORCED_ROTATE"),
    flag(0x4, "THREAD_SPECIFIC"),
    flag(0x8, "SUPPRESS_USE"),
    flag(0x10, "UPDATE_TABLE_MAP_VERSION"),
    flag(0x20, "ARTIFICIAL"),
    flag(0x40, "RELAY_LOG"),
    flag(0x80, "IGNORABLE"),
    flag(0x100, "NO_FILTER"),
    flag(0x200, "MTS_ISOLATE"),
];

const ROWS_FLAGS: FlagTable = &[
    flag(0x1, "STMT_END"),
    flag(0x2, "NO_FOREIGN_KEY_CHECKS"),
    flag(0x4, "RELAXED_UNIQUE_CHECKS"),
    flag(0x8, "COMPLETE_ROWS"),
    flag(0x80, "NO_CHECK_CONSTRAINT_CHECKS"),
];

const CHECKSUMS: EnumTable = &[(0, "off"), (1, "CRC32"), (255, "undefined")];

const INTVAR_TYPES: EnumTable = &[(1, "LAST_INSERT_ID"), (2, "INSERT_ID")];

const MARIADB_GTID_FLAGS: FlagTable = &[
    flag(0x1, "STANDALONE"),
    flag(0x2, "GROUP_COMMIT_ID"),
    flag(0x4, "TRANSACTIONAL"),
    flag(0x8, "ALLOW_PARALLEL"),
    flag(0x10, "WAITED"),
    flag(0x20, "DDL"),
    flag(0x40, "PREPARED_XA"),
    flag(0x80, "COMPLETED_XA"),
];

/// MariaDB GTID extra flags (from memory of MariaDB's `log_event.h`).
const MARIADB_GTID_EXTRA: FlagTable = &[
    flag(0x1, "MULTI_ENGINE"),
    flag(0x2, "START_ALTER"),
    flag(0x4, "COMMIT_ALTER"),
    flag(0x8, "ROLLBACK_ALTER"),
];

/// A partial update's value options (`binlog_row_value_options`).
const VALUE_OPTIONS: FlagTable = &[flag(0x1, "PARTIAL_JSON_UPDATES")];

const QUERY_FLAGS2: FlagTable = &[
    flag(0x4000, "AUTO_IS_NULL"),
    flag(0x80000, "NOT_AUTOCOMMIT"),
    // MariaDB (10.10+ writes it by default): checked against
    // explicit_defaults_for_timestamp=OFF and ON on MariaDB 11.4.
    flag(0x100_0000, "EXPLICIT_DEFAULTS_FOR_TIMESTAMP"),
    flag(0x400_0000, "NO_FOREIGN_KEY_CHECKS"),
    flag(0x800_0000, "RELAXED_UNIQUE_CHECKS"),
];

/// `sql_mode` bits: the low 32 are common to MySQL and MariaDB (bit 4
/// apart), the higher ones differ. From memory; MySQL 9.7's and MariaDB
/// 10.5's and 11.4's defaults decode to their documented lists.
macro_rules! sql_modes {
    ($($extra:expr),* $(,)?) => {
        &[
            flag(0x1, "REAL_AS_FLOAT"),
            flag(0x2, "PIPES_AS_CONCAT"),
            flag(0x4, "ANSI_QUOTES"),
            flag(0x8, "IGNORE_SPACE"),
            flag(0x20, "ONLY_FULL_GROUP_BY"),
            flag(0x40, "NO_UNSIGNED_SUBTRACTION"),
            flag(0x80, "NO_DIR_IN_CREATE"),
            flag(0x100, "POSTGRESQL"),
            flag(0x200, "ORACLE"),
            flag(0x400, "MSSQL"),
            flag(0x800, "DB2"),
            flag(0x1000, "MAXDB"),
            flag(0x2000, "NO_KEY_OPTIONS"),
            flag(0x4000, "NO_TABLE_OPTIONS"),
            flag(0x8000, "NO_FIELD_OPTIONS"),
            flag(0x1_0000, "MYSQL323"),
            flag(0x2_0000, "MYSQL40"),
            flag(0x4_0000, "ANSI"),
            flag(0x8_0000, "NO_AUTO_VALUE_ON_ZERO"),
            flag(0x10_0000, "NO_BACKSLASH_ESCAPES"),
            flag(0x20_0000, "STRICT_TRANS_TABLES"),
            flag(0x40_0000, "STRICT_ALL_TABLES"),
            flag(0x80_0000, "NO_ZERO_IN_DATE"),
            flag(0x100_0000, "NO_ZERO_DATE"),
            flag(0x200_0000, "ALLOW_INVALID_DATES"),
            flag(0x400_0000, "ERROR_FOR_DIVISION_BY_ZERO"),
            flag(0x800_0000, "TRADITIONAL"),
            flag(0x1000_0000, "NO_AUTO_CREATE_USER"),
            flag(0x2000_0000, "HIGH_NOT_PRECEDENCE"),
            flag(0x4000_0000, "NO_ENGINE_SUBSTITUTION"),
            flag(0x8000_0000, "PAD_CHAR_TO_FULL_LENGTH"),
            $($extra),*
        ]
    };
}

const SQL_MODES_MYSQL: FlagTable = sql_modes![flag(0x1_0000_0000, "TIME_TRUNCATE_FRACTIONAL")];
const SQL_MODES_MARIADB: FlagTable = sql_modes![
    flag(0x10, "IGNORE_BAD_TABLE_OPTIONS"),
    flag(0x1_0000_0000, "EMPTY_STRING_IS_NULL"),
    flag(0x2_0000_0000, "SIMULTANEOUS_ASSIGNMENT"),
    flag(0x4_0000_0000, "TIME_ROUND_FRACTIONAL"),
];

/// Collation IDs: the common ones (MySQL and MariaDB share the low IDs;
/// 2304 is MariaDB's). From memory, the defaults the fixtures' servers
/// write checked against what `mariadb-binlog` prints for them.
const COLLATIONS: EnumTable = &[
    (1, "big5_chinese_ci"),
    (8, "latin1_swedish_ci"),
    (11, "ascii_general_ci"),
    (28, "gbk_chinese_ci"),
    (33, "utf8mb3_general_ci"),
    (45, "utf8mb4_general_ci"),
    (46, "utf8mb4_bin"),
    (47, "latin1_bin"),
    (48, "latin1_general_ci"),
    (63, "binary"),
    (65, "ascii_bin"),
    (83, "utf8mb3_bin"),
    (192, "utf8mb3_unicode_ci"),
    (224, "utf8mb4_unicode_ci"),
    (246, "utf8mb4_unicode_520_ci"),
    (255, "utf8mb4_0900_ai_ci"),
    (309, "utf8mb4_0900_bin"),
    (2304, "utf8mb4_uca1400_ai_ci"),
];

/// A collation ID with its name, if known.
fn collation(id: u64) -> String {
    lookup(COLLATIONS, id).map_or_else(|| id.to_string(), |n| format!("{n} ({id})"))
}

/// The character set a collation ID stands for (by its name's prefix).
fn charset(id: u64) -> String {
    lookup(COLLATIONS, id).map_or_else(
        || id.to_string(),
        |n| format!("{} ({id})", n.split('_').next().unwrap_or(n)),
    )
}

const PAYLOAD_COMPRESSION: EnumTable = &[(0, "zstd"), (255, "none")];

const USER_VAR_TYPES: EnumTable = &[
    (0, "STRING"),
    (1, "REAL"),
    (2, "INT"),
    (3, "ROW"),
    (4, "DECIMAL"),
];

/// How the events of a stream are framed: from the format description.
#[derive(Clone, Debug)]
struct Fmt {
    header_len: u64,
    checksum: bool,
    /// Whether the format description ends with the checksum algorithm and
    /// a CRC field (written even when checksums are off).
    fde_alg: bool,
    /// Post-header lengths, indexed by event type - 1.
    post: Arc<Vec<u8>>,
    server: String,
}

impl Fmt {
    fn post_len(&self, ty: u8, default: u64) -> u64 {
        usize::from(ty)
            .checked_sub(1)
            .and_then(|i| self.post.get(i))
            .map_or(default, |&n| u64::from(n))
    }

    fn mariadb(&self) -> bool {
        self.server.contains("MariaDB")
    }
}

/// A run of events: the region they fill and their framing. Events inside
/// a transaction payload carry no checksums.
#[derive(Clone, Debug)]
struct Stream {
    input: Input,
    region: Span,
    fmt: Fmt,
    /// A replica's relay log (its first event has `RELAY_LOG`): event
    /// positions are the source's.
    relay: bool,
}

/// One event, for its expander.
#[derive(Clone, Debug)]
struct Event {
    stream: Stream,
    span: Span,
    ty: u8,
    /// The table map event of a rows event's table, if seen.
    table: Option<Span>,
}

impl Event {
    fn header_len(&self) -> u64 {
        self.stream.fmt.header_len
    }
    fn crc_len(&self) -> u64 {
        let fmt = &self.stream.fmt;
        if (self.ty == 15 && fmt.fde_alg) || (self.ty != 15 && fmt.checksum) {
            4
        } else {
            0
        }
    }
    /// The body: after the header, before the checksum.
    fn body(&self) -> Span {
        let h = self.header_len();
        self.span.sub(
            h,
            self.span
                .len
                .saturating_sub(h)
                .saturating_sub(self.crc_len()),
        )
    }
}

fn probe(h: &Head<'_>) -> bool {
    if h.data.get(..4) != Some(&MAGIC[..]) {
        return false;
    }
    // The first event: a format description (or a v3 start event) of a
    // plausible size.
    let ty = h.data.get(8).copied();
    let size = u32_le(h.data, 13).map_or(0, u64::from);
    matches!(ty, Some(15 | 1)) && (HEADER..=0x1_0000).contains(&size)
}

/// A dotted server version as numbers.
fn version_triple(s: &str) -> (u32, u32, u32) {
    let mut parts = s.split(|c: char| !c.is_ascii_digit());
    let mut next = || {
        parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0)
    };
    (next(), next(), next())
}

/// The framing a format description event's `body` (after the common
/// header; `event_len` the whole event) describes.
fn parse_fde(body: &[u8], event_len: u64) -> Fmt {
    let server = String::from_utf8_lossy(body.get(2..52).unwrap_or_default())
        .trim_end_matches('\0')
        .to_owned();
    let header_len = u64::from(body.get(56).copied().unwrap_or(19)).max(HEADER);
    // Servers since MySQL 5.6.1 and MariaDB 5.3 end the event with the
    // checksum algorithm and the event's own CRC.
    let since = if server.contains("MariaDB") {
        (5, 3, 0)
    } else {
        (5, 6, 1)
    };
    let has_alg = version_triple(&server) >= since;
    let body_len = event_len.saturating_sub(HEADER);
    let array_end = if has_alg {
        body_len.saturating_sub(5)
    } else {
        body_len
    };
    let post = body
        .get(57..to_usize(array_end))
        .unwrap_or_default()
        .to_vec();
    let checksum = has_alg && body.get(to_usize(array_end)).copied() == Some(1);
    Fmt {
        header_len,
        checksum,
        fde_alg: has_alg,
        post: Arc::new(post),
        server,
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let resumed = cx.resume::<Walk>();
    if resumed.is_none() {
        cx.emit(
            Node::new("Magic")
                .span(file.sub(0, 4))
                .value(Value::Bytes(MAGIC.to_vec())),
        );
    }
    let head = cx.read(file.sub_exact(4, HEADER)?).await?;
    let ty = head.get(4).copied().unwrap_or(0);
    let size = u32_le(&head, 9).map_or(0, u64::from);
    let fmt = if ty == 15 && size <= 0x1_0000 {
        let event = cx.read(file.sub_exact(4, size)?).await?;
        parse_fde(event.get(19..).unwrap_or_default(), size)
    } else {
        Fmt {
            header_len: HEADER,
            checksum: false,
            fde_alg: false,
            post: Arc::new(Vec::new()),
            server: String::new(),
        }
    };
    let relay = u16_le(&head, 17).is_some_and(|f| f & 0x40 != 0);
    cx.annotate(format!(
        "{} {}{}{}",
        if fmt.mariadb() { "MariaDB" } else { "MySQL" },
        if relay { "relay log" } else { "binary log" },
        if fmt.server.is_empty() {
            String::new()
        } else {
            format!(", server {}", fmt.server)
        },
        if fmt.checksum { ", CRC32" } else { "" }
    ));
    let s = Stream {
        input,
        region: file,
        fmt,
        relay,
    };
    walk(&cx, &s, 4, resumed, true).await
}

/// Walk state: position, event index, the table maps of the current
/// statement (table ID, event span, name), and whether a start encryption
/// event has been passed.
type Walk = (u64, u64, Vec<(u64, Span, String)>, bool);

/// Lists the events of `s` from `start`; `top` for the file's own events
/// (checksummed and positioned), not a transaction payload's.
async fn walk(cx: &Cx, s: &Stream, start: u64, resumed: Option<Walk>, top: bool) -> Result<()> {
    let region = s.region;
    let (mut pos, mut index, mut tables, mut encrypted) =
        resumed.unwrap_or((start, 0, Vec::new(), false));
    let h = s.fmt.header_len;
    while pos < region.len {
        let mark: Walk = (pos, index, tables.clone(), encrypted);
        cx.mark(move || mark);
        let head = cx.read(region.sub(pos, h)).await?;
        if to_u64(head.len()) < h {
            cx.push(Node::new("Truncated event").span(region.tail(pos)).diag(
                Diagnostic::truncated(region.sub(pos, h), to_u64(head.len())),
            ))
            .await;
            break;
        }
        let ty = head.get(4).copied().unwrap_or(0);
        let size = u32_le(&head, 9).map_or(0, u64::from);
        let log_pos = u32_le(&head, 13).map_or(0, u64::from);
        let flags = u16_le(&head, 17).unwrap_or(0);
        let crc = if s.fmt.checksum { 4 } else { 0 };
        if encrypted {
            // MariaDB encrypts each event after the start encryption
            // event, all but its size.
            if size < h || size > region.len.saturating_sub(pos) {
                cx.push(Node::new("Encrypted event").span(region.tail(pos)).diag(
                    Diagnostic::malformed(format!(
                        "event size {size} does not fit (at most {} bytes left)",
                        region.len.saturating_sub(pos)
                    )),
                ))
                .await;
                break;
            }
            let span = region.sub(pos, size);
            cx.progress_in(region, pos.saturating_add(size));
            cx.push(
                Node::new("Encrypted event")
                    .span(span)
                    .summary(plural(size, "byte"))
                    .lazy(encrypted_event, span),
            )
            .await;
            pos = pos.saturating_add(size);
            index = index.saturating_add(1);
            continue;
        }
        let name = lookup(EVENT_TYPES, ty.into())
            .map_or_else(|| format!("Event type {ty}"), str::to_owned);
        if size < h.saturating_add(crc) || size > region.len.saturating_sub(pos) {
            cx.push(
                Node::new(name)
                    .span(region.tail(pos))
                    .diag(Diagnostic::malformed(format!(
                        "event size {size} does not fit (at most {} bytes left)",
                        region.len.saturating_sub(pos)
                    ))),
            )
            .await;
            break;
        }
        let span = region.sub(pos, size);
        let stream = s.clone();
        let table_id = if is_rows(ty) || ty == 19 {
            let post = cx.read(span.sub(h, 6)).await?;
            Some(table_id_of(&post, stream.fmt.post_len(ty, 8)))
        } else {
            None
        };
        let table = table_id.and_then(|id| tables.iter().find(|t| t.0 == id).cloned());
        let event = Event {
            stream,
            span,
            ty,
            table: table.as_ref().map(|t| t.1),
        };
        let mut node = Node::new(name).span(span);
        let mut summary = summarize(cx, &event, table.as_ref().map(|t| t.2.as_str())).await;
        if ty == 19
            && let Some(id) = table_id
        {
            let qualified = table_name(cx, &event).await.unwrap_or_default();
            tables.retain(|t| t.0 != id);
            tables.push((id, span, qualified));
        }
        if is_rows(ty) {
            let rows_flags = cx.read(span.sub(h.saturating_add(6), 2)).await?;
            if u16_le(&rows_flags, 0).unwrap_or(0) & 1 != 0 {
                tables.clear();
            }
            if table.is_none() {
                node = node.diag(Diagnostic::warning(
                    "no table map for this table ID before it",
                ));
            }
        }
        if top {
            // A relay log's events carry their positions in the
            // source's binary log.
            if log_pos != 0
                && !s.relay
                && log_pos != region.offset.saturating_add(pos).saturating_add(size)
            {
                summary.push_str(&format!(" (next position {log_pos})"));
            }
            if s.fmt.checksum
                && let Some(message) = check(cx, &event).await?.mismatch_text()
            {
                node = node.diag(Diagnostic::warning(message));
            }
        }
        if flags & 0x80 != 0 && lookup(EVENT_TYPES, ty.into()).is_none() {
            summary.push_str(" (ignorable)");
        }
        cx.progress_in(region, pos.saturating_add(size));
        cx.push(
            node.summary(summary)
                .lazy(crate::expander!(self::event: Event), event),
        )
        .await;
        encrypted |= top && ty == 164;
        pos = pos.saturating_add(size);
        index = index.saturating_add(1);
    }
    Ok(())
}

fn is_rows(ty: u8) -> bool {
    matches!(ty, 20..=25 | 30..=32 | 39 | 166..=171)
}

/// Rows v2 events (and their compressed forms) carry extra data.
fn rows_v2(ty: u8) -> bool {
    matches!(ty, 30..=32 | 39 | 169..=171)
}

/// The kind of rows event: 0 write, 1 update, 2 delete.
fn rows_kind(ty: u8) -> u8 {
    match ty {
        20 | 23 | 30 | 166 | 169 => 0,
        21 | 24 | 31 | 39 | 167 | 170 => 1,
        _ => 2,
    }
}

fn table_id_of(post: &[u8], post_len: u64) -> u64 {
    let n = if post_len == 6 { 4 } else { 6 };
    post.get(..n)
        .unwrap_or_default()
        .iter()
        .rev()
        .fold(0u64, |a, &x| a.wrapping_shl(8) | u64::from(x))
}

/// Checks an event's CRC-32 (skipped when too large). The format
/// description's `BINLOG_IN_USE` flag is cleared first, as the server
/// computed the CRC before setting it.
async fn check(cx: &Cx, e: &Event) -> Result<Check> {
    if e.span.len > MAX_EVENT || e.span.len < 4 {
        let at = e.span.sub(e.span.len.saturating_sub(4), 4);
        let stored = u32_le(&cx.read(at).await?, 0).unwrap_or(0);
        return Ok(Check::new("CRC-32", stored).skipped("event too large"));
    }
    let mut data = cx.read(e.span).await?;
    let n = data.len().saturating_sub(4);
    let stored = u32_le(&data, n).unwrap_or(0);
    data.truncate(n);
    if e.ty == 15
        && let Some(f) = data.get_mut(17)
    {
        *f &= !1;
    }
    Ok(Check::new("CRC-32", stored).verify(crc32_paced(cx, &data).await))
}

/// Reads an event's body (bounded).
async fn body(cx: &Cx, e: &Event) -> Result<Vec<u8>> {
    let b = e.body();
    if b.len > MAX_EVENT {
        return Err(Diagnostic::limit(format!("event body of {} bytes", b.len)).at(b));
    }
    cx.read(b).await
}

async fn table_name(cx: &Cx, e: &Event) -> Option<String> {
    let b = body(cx, e).await.ok()?;
    let t = rows::parse_table_map(&b, to_usize(e.stream.fmt.post_len(19, 8)))?;
    Some(t.qualified())
}

/// The first line of a query, clipped.
fn query_line(q: &[u8]) -> String {
    let s = String::from_utf8_lossy(q.get(..512.min(q.len())).unwrap_or_default()).into_owned();
    let line = s.trim().lines().next().unwrap_or("").trim().to_owned();
    clip(&line, 100)
}

/// The query text of a query event body (`None` if it does not fit).
fn query_parts(b: &[u8], post: usize) -> Option<(usize, usize, usize)> {
    let db_len = usize::from(*b.get(8)?);
    let status_len = usize::from(u16_le(b, 11)?);
    let status = post;
    let db = status.checked_add(status_len)?;
    let query = db.checked_add(db_len)?.checked_add(1)?;
    (query <= b.len()).then_some((status, db, query))
}

/// A GTID's text: `uuid:gno`.
fn gtid_text(sid: &[u8], gno: u64) -> String {
    format!("{}:{gno}", uuid(sid))
}

/// The one-line summary of an event, from its first bytes.
async fn summarize(cx: &Cx, e: &Event, table: Option<&str>) -> String {
    let b = match cx.read(e.body().sub(0, 1024)).await {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let fmt = &e.stream.fmt;
    match e.ty {
        15 => {
            let f = parse_fde(&b, e.span.len);
            format!(
                "binlog v{}, server {}, checksum {}",
                u16_le(&b, 0).unwrap_or(0),
                f.server,
                if fmt.checksum { "CRC32" } else { "off" }
            )
        }
        2 | 165 => {
            let post = to_usize(fmt.post_len(e.ty, 13));
            match query_parts(&b, post) {
                Some((_, db, query)) => {
                    let db_name = String::from_utf8_lossy(
                        b.get(db..query.saturating_sub(1)).unwrap_or_default(),
                    )
                    .into_owned();
                    let text = if e.ty == 165 {
                        compressed_line(cx, e, query).await
                    } else {
                        query_line(b.get(query..).unwrap_or_default())
                    };
                    if db_name.is_empty() {
                        text
                    } else {
                        format!("{db_name}: {text}")
                    }
                }
                None => String::new(),
            }
        }
        4 => {
            let post = to_usize(fmt.post_len(4, 8));
            format!(
                "next file {} at {}",
                String::from_utf8_lossy(b.get(post..).unwrap_or_default()),
                u64_le(&b, 0).unwrap_or(0)
            )
        }
        5 => format!(
            "{} = {}",
            lookup(INTVAR_TYPES, b.first().copied().unwrap_or(0).into()).unwrap_or("?"),
            u64_le(&b, 1).unwrap_or(0)
        ),
        16 => format!("XID {} (commit)", u64_le(&b, 0).unwrap_or(0)),
        19 => {
            let id = table_id_of(&b, fmt.post_len(19, 8));
            match rows::parse_table_map(&b, to_usize(fmt.post_len(19, 8))) {
                Some(t) => format!(
                    "{}, table ID {}, {}",
                    t.qualified(),
                    t.table_id,
                    plural(t.columns.len(), "column")
                ),
                None => format!("table ID {id}"),
            }
        }
        t if is_rows(t) => {
            let id = table_id_of(&b, fmt.post_len(t, 8));
            let what = ["insert", "update", "delete"]
                .get(usize::from(rows_kind(t)))
                .copied()
                .unwrap_or("?");
            format!(
                "{what}, {}, table ID {id}",
                table.unwrap_or("unknown table")
            )
        }
        33 | 34 => {
            let sid = b.get(1..17).unwrap_or_default();
            let gno = u64_le(&b, 17).unwrap_or(0);
            if e.ty == 34 {
                "anonymous".to_owned()
            } else {
                gtid_text(sid, gno)
            }
        }
        35 => {
            let n = u64_le(&b, 0).unwrap_or(0);
            if n >> 56 != 0 {
                "tagged GTID set".to_owned()
            } else {
                plural(n, "server UUID")
            }
        }
        29 => query_line(b.get(1..).unwrap_or_default()),
        160 => query_line(&b),
        161 => String::from_utf8_lossy(b.get(4..).unwrap_or_default()).into_owned(),
        162 => {
            let seq = u64_le(&b, 0).unwrap_or(0);
            let domain = u32_le(&b, 8).unwrap_or(0);
            let flags = b.get(12).copied().unwrap_or(0);
            let server = server_id(cx, e).await;
            let kind = if flags & 0x20 != 0 {
                " ddl"
            } else if flags & 0x1 == 0 {
                " trans"
            } else {
                ""
            };
            let xa = match mariadb_xid(&b, flags) {
                Some(xid) if flags & 0x40 != 0 => format!(", XA START {xid}"),
                Some(xid) => format!(", completes XA {xid}"),
                None => String::new(),
            };
            format!("{domain}-{server}-{seq}{kind}{xa}")
        }
        163 => {
            let count = u32_le(&b, 0).unwrap_or(0) & 0x0fff_ffff;
            let mut parts = Vec::new();
            for i in 0..u64::from(count).min(4) {
                let at = to_usize(i.saturating_mul(16).saturating_add(4));
                parts.push(format!(
                    "{}-{}-{}",
                    u32_le(&b, at).unwrap_or(0),
                    u32_le(&b, at.saturating_add(4)).unwrap_or(0),
                    u64_le(&b, at.saturating_add(8)).unwrap_or(0)
                ));
            }
            if count > 4 {
                parts.push("…".to_owned());
            }
            format!("[{}]", parts.join(", "))
        }
        40 => match payload_header(&b) {
            Some(p) => format!(
                "{}, {} → {} bytes",
                lookup(PAYLOAD_COMPRESSION, p.compression).unwrap_or("?"),
                p.size,
                p.uncompressed
            ),
            None => String::new(),
        },
        164 => format!(
            "scheme {}, key version {}; the events after it are encrypted",
            b.first().copied().unwrap_or(0),
            u32_le(&b, 1).unwrap_or(0)
        ),
        38 => match xa_prepare_xid(&b) {
            Some((one_phase, xid)) if one_phase => format!("XA COMMIT {xid} ONE PHASE"),
            Some((_, xid)) => format!("XA PREPARE {xid}"),
            None => String::new(),
        },
        14 => {
            let n = u32_le(&b, 0).map_or(0, |n| to_usize(n.into()));
            let name =
                String::from_utf8_lossy(b.get(4..4usize.saturating_add(n)).unwrap_or_default())
                    .into_owned();
            let rest = b.get(4usize.saturating_add(n)..).unwrap_or_default();
            format!("@{name}{}", user_var_value(rest))
        }
        13 => format!(
            "seeds {}, {}",
            u64_le(&b, 0).unwrap_or(0),
            u64_le(&b, 8).unwrap_or(0)
        ),
        _ => String::new(),
    }
}

/// ` = value` of a user variable event, from its null flag on (`b`).
fn user_var_value(b: &[u8]) -> String {
    if b.first().copied().unwrap_or(1) != 0 {
        return " = NULL".to_owned();
    }
    let ty = b.get(1).copied().unwrap_or(0);
    let len = u32_le(b, 6).map_or(0, |n| to_usize(n.into()));
    let v = b.get(10..10usize.saturating_add(len)).unwrap_or_default();
    match ty {
        0 => format!(" = '{}'", clip(&String::from_utf8_lossy(v), 60)),
        1 => format!(" = {}", f64::from_bits(u64_le(v, 0).unwrap_or(0))),
        2 => format!(
            " = {}",
            i64::from_le_bytes(u64_le(v, 0).unwrap_or(0).to_le_bytes())
        ),
        _ => String::new(),
    }
}

/// The first line of a compressed query event's query (at `query` in the
/// body), decoding only its start.
async fn compressed_line(cx: &Cx, e: &Event, query: usize) -> String {
    let span = e.body().tail(to_u64(query));
    match decompress_lazy(cx, span).await {
        Ok(decoded) => match cx.read(decoded.sub(0, 512)).await {
            Ok(text) => query_line(&text),
            Err(_) => "(compressed)".to_owned(),
        },
        Err(_) => "(compressed)".to_owned(),
    }
}

async fn server_id(cx: &Cx, e: &Event) -> u32 {
    cx.read(e.span.sub(5, 4))
        .await
        .ok()
        .and_then(|b| u32_le(&b, 0))
        .unwrap_or(0)
}

/// A transaction payload's header fields.
struct Payload {
    compression: u64,
    size: u64,
    uncompressed: u64,
    /// Where the payload starts in the body.
    data: usize,
    /// The fields: type, offset and length of each.
    fields: Vec<(u64, usize, usize)>,
}

fn payload_header(b: &[u8]) -> Option<Payload> {
    let mut p = 0usize;
    let mut out = Payload {
        compression: 255,
        size: 0,
        uncompressed: 0,
        data: 0,
        fields: Vec::new(),
    };
    for _ in 0..16 {
        let start = p;
        let (ty, n) = lenenc(b.get(p..)?)?;
        p = p.checked_add(n)?;
        if ty == 0 {
            out.fields.push((0, start, n));
            out.data = p;
            return Some(out);
        }
        let (len, n) = lenenc(b.get(p..)?)?;
        p = p.checked_add(n)?;
        let value = b.get(p..p.checked_add(to_usize(len))?)?;
        let (v, _) = lenenc(value).unwrap_or((0, 0));
        match ty {
            1 => out.size = v,
            2 => out.compression = v,
            3 => out.uncompressed = v,
            _ => {}
        }
        p = p.checked_add(to_usize(len))?;
        out.fields.push((ty, start, p.saturating_sub(start)));
    }
    None
}

async fn event(cx: Cx, e: Event) -> Result<()> {
    let h = e.header_len();
    let head = cx.read(e.span.sub(0, h)).await?;
    let ts = u32_le(&head, 0).unwrap_or(0);
    cx.emit(
        Node::new("Header")
            .span(e.span.sub(0, h))
            .lazy(header, (e.span.sub(0, h), ts)),
    );
    let b = body(&cx, &e).await?;
    let span = e.body();
    let fmt = &e.stream.fmt;
    let out = Body {
        span,
        data: b.as_slice(),
    };
    match e.ty {
        15 => fde(&cx, &e, &out),
        2 | 165 => query(&cx, &e, &out).await?,
        4 => {
            let post = fmt.post_len(4, 8);
            out.emit(&cx, "Position", 0, 8, uint(out.u64(0), 64));
            out.text(&cx, "Next file", post, out.len().saturating_sub(post));
        }
        5 => {
            out.emit(&cx, "Type", 0, 1, enumv(out.byte(0), 8, INTVAR_TYPES));
            out.emit(&cx, "Value", 1, 8, uint(out.u64(1), 64));
        }
        13 => {
            out.emit(&cx, "Seed 1", 0, 8, uint(out.u64(0), 64));
            out.emit(&cx, "Seed 2", 8, 8, uint(out.u64(8), 64));
        }
        14 => user_var(&cx, &out),
        16 => out.emit(&cx, "XID", 0, 8, uint(out.u64(0), 64)),
        19 => table_map(&cx, &e, &out),
        t if is_rows(t) => rows_event(&cx, &e, &out).await?,
        29 => out.text(&cx, "Query", 1, out.len().saturating_sub(1)),
        33 | 34 => gtid(&cx, &out),
        35 => previous_gtids(&cx, &out),
        40 => payload(&cx, &e, &out).await?,
        160 => out.text(&cx, "Query", 0, out.len()),
        161 => {
            let n = u64::from(u32_le(&b, 0).unwrap_or(0));
            out.emit(&cx, "Name length", 0, 4, uint(n, 32));
            out.text(&cx, "File", 4, n);
        }
        38 => xa_prepare(&cx, &out),
        162 => mariadb_gtid(&cx, &out),
        163 => gtid_list(&cx, &out),
        164 => {
            out.emit(&cx, "Scheme", 0, 1, uint(out.byte(0), 8));
            out.emit(&cx, "Key version", 1, 4, uint(out.u32(1), 32));
            out.raw(&cx, "Nonce", 5, 12);
            cx.emit(
                Node::new("Following events")
                    .desc("Encrypted with the binary log's key: shown as encrypted events"),
            );
        }
        _ => {
            if !b.is_empty() {
                cx.emit(Node::new("Body").span(span));
            }
        }
    }
    if e.crc_len() > 0 {
        let at = e.span.sub(e.span.len.saturating_sub(4), 4);
        let stored = u32_le(&cx.read(at).await?, 0).unwrap_or(0);
        let node = Node::new("Checksum").span(at);
        cx.emit(if !fmt.checksum {
            node.value(hex(stored, 32))
                .summary("unused (checksums off)")
        } else {
            node.checksum(check(&cx, &e).await?)
        });
    }
    Ok(())
}

/// An event after a start encryption event: only its size is in clear.
/// Its CRC-32, if any, is over the encrypted bytes and is not checked.
async fn encrypted_event(cx: Cx, span: Span) -> Result<()> {
    let size = cx.read(span.sub(9, 4)).await?;
    cx.emit(
        Node::new("Encrypted")
            .span(span.sub(0, 9))
            .desc("Timestamp, type and server ID, encrypted"),
    );
    cx.emit(
        Node::new("Event size")
            .span(span.sub(9, 4))
            .value(uint(u32_le(&size, 0).unwrap_or(0), 32)),
    );
    cx.emit(
        Node::new("Encrypted")
            .span(span.tail(13))
            .desc("The rest of the event, encrypted with the binary log's key"),
    );
    Ok(())
}

async fn header(cx: Cx, (span, _ts): (Span, u32)) -> Result<()> {
    let b = cx.read(span).await?;
    let out = Body {
        span,
        data: b.as_slice(),
    };
    out.emit(&cx, "Timestamp", 0, 4, Value::utc(i64::from(out.u32(0))));
    out.emit(&cx, "Type", 4, 1, enumv(out.byte(4), 8, EVENT_TYPES));
    out.emit(&cx, "Server ID", 5, 4, uint(out.u32(5), 32));
    out.emit(&cx, "Event size", 9, 4, uint(out.u32(9), 32));
    out.emit(&cx, "Next position", 13, 4, hex(out.u32(13), 32));
    out.emit(&cx, "Flags", 17, 2, flagsv(out.u16(17), 16, EVENT_FLAGS));
    if span.len > HEADER {
        out.raw(&cx, "Extra header", HEADER, span.len.saturating_sub(HEADER));
    }
    Ok(())
}

/// An event body in memory, for emitting nodes at offsets into it.
struct Body<'a> {
    span: Span,
    data: &'a [u8],
}

impl Body<'_> {
    fn len(&self) -> u64 {
        to_u64(self.data.len())
    }
    fn at(&self, off: u64, len: u64) -> Span {
        self.span.sub(off, len)
    }
    fn byte(&self, off: u64) -> u8 {
        self.data.get(to_usize(off)).copied().unwrap_or(0)
    }
    fn u16(&self, off: u64) -> u16 {
        u16_le(self.data, to_usize(off)).unwrap_or(0)
    }
    fn u32(&self, off: u64) -> u32 {
        u32_le(self.data, to_usize(off)).unwrap_or(0)
    }
    fn u64(&self, off: u64) -> u64 {
        u64_le(self.data, to_usize(off)).unwrap_or(0)
    }
    fn slice(&self, off: u64, len: u64) -> &[u8] {
        let start = to_usize(off).min(self.data.len());
        let end = to_usize(off.saturating_add(len)).min(self.data.len());
        self.data.get(start..end).unwrap_or_default()
    }
    fn node(&self, name: impl Into<String>, off: u64, len: u64) -> Node {
        let mut node = Node::new(name.into()).span(self.at(off, len));
        if off.saturating_add(len) > self.len() {
            node = node.diag(Diagnostic::truncated(
                self.at(off, len),
                self.len().saturating_sub(off),
            ));
        }
        node
    }
    fn emit(&self, cx: &Cx, name: &'static str, off: u64, len: u64, value: Value) {
        cx.emit(self.node(name, off, len).value(value));
    }
    fn raw(&self, cx: &Cx, name: &'static str, off: u64, len: u64) {
        cx.emit(
            self.node(name, off, len)
                .value(Value::Bytes(self.slice(off, len.min(256)).to_vec())),
        );
    }
    fn text(&self, cx: &Cx, name: &'static str, off: u64, len: u64) {
        let s = String::from_utf8_lossy(self.slice(off, len.min(to_u64(MAX_QUERY)))).into_owned();
        cx.emit(self.node(name, off, len).value(Value::Text(s)));
    }
}

fn fde(cx: &Cx, e: &Event, out: &Body<'_>) {
    out.emit(cx, "Binlog version", 0, 2, uint(out.u16(0), 16));
    let server = String::from_utf8_lossy(out.slice(2, 50))
        .trim_end_matches('\0')
        .to_owned();
    cx.emit(out.node("Server version", 2, 50).value(Value::Text(server)));
    out.emit(cx, "Created", 52, 4, Value::utc(i64::from(out.u32(52))));
    out.emit(cx, "Header length", 56, 1, uint(out.byte(56), 8));
    let fmt = &e.stream.fmt;
    let array = to_u64(fmt.post.len());
    cx.emit(
        out.node("Post-header lengths", 57, array)
            .summary(plural(array, "event type"))
            .lazy(post_lengths, out.at(57, array)),
    );
    // The algorithm byte follows the array when the server writes one
    // (the event's CRC is outside the body).
    let alg_at = 57u64.saturating_add(array);
    if alg_at < out.len() {
        out.emit(
            cx,
            "Checksum algorithm",
            alg_at,
            1,
            enumv(out.byte(alg_at), 8, CHECKSUMS),
        );
    }
}

async fn post_lengths(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read(span).await?;
    for (i, &n) in b.iter().enumerate() {
        let ty = i.saturating_add(1);
        let name =
            lookup(EVENT_TYPES, to_u64(ty)).map_or_else(|| format!("Type {ty}"), str::to_owned);
        cx.push(
            Node::new(name)
                .span(span.sub(to_u64(i), 1))
                .value(uint(n, 8)),
        )
        .await;
    }
    Ok(())
}

async fn query(cx: &Cx, e: &Event, out: &Body<'_>) -> Result<()> {
    let post = e.stream.fmt.post_len(e.ty, 13);
    out.emit(cx, "Thread ID", 0, 4, uint(out.u32(0), 32));
    out.emit(cx, "Execution time", 4, 4, uint(out.u32(4), 32));
    let db_len = u64::from(out.byte(8));
    out.emit(cx, "Database name length", 8, 1, uint(out.byte(8), 8));
    out.emit(cx, "Error code", 9, 2, uint(out.u16(9), 16));
    let status_len = u64::from(out.u16(11));
    out.emit(cx, "Status variables length", 11, 2, uint(out.u16(11), 16));
    if post > 13 {
        out.raw(cx, "Extra post-header", 13, post.saturating_sub(13));
    }
    let status = out.at(post, status_len);
    cx.emit(
        out.node("Status variables", post, status_len)
            .lazy(status_vars, (status, e.stream.fmt.mariadb())),
    );
    let db_at = post.saturating_add(status_len);
    out.text(cx, "Database", db_at, db_len);
    let q_at = db_at.saturating_add(db_len).saturating_add(1);
    let q_len = out.len().saturating_sub(q_at);
    if e.ty == 165 {
        let span = out.at(q_at, q_len);
        let node = compressed(cx, span, "Query").await;
        cx.emit(node);
    } else {
        out.text(cx, "Query", q_at, q_len);
    }
    Ok(())
}

/// MariaDB's compressed data (`binlog_buf_uncompress`): a header byte
/// (0x80 | the size of the length), the uncompressed length big-endian,
/// then a zlib stream. Returns the decoded span.
async fn decompress(cx: &Cx, span: Span) -> Result<(Span, u64, u64)> {
    let (data, len, lenlen) = compressed_header(cx, span).await?;
    let decoded = crate::codec::decode_span(cx, data, &Codec::Zlib, Some(len)).await?;
    if let Some(err) = decoded.error {
        return Err(err);
    }
    Ok((decoded.span, len, lenlen))
}

/// The zlib stream of MariaDB's compressed data, its decoded length and
/// the size of that length.
async fn compressed_header(cx: &Cx, span: Span) -> Result<(Span, u64, u64)> {
    let head = cx.read(span.sub(0, 5)).await?;
    let first = head.first().copied().unwrap_or(0);
    let lenlen = u64::from(first & 0x07);
    if first & 0x80 == 0 || !(1..=4).contains(&lenlen) {
        return Err(
            Diagnostic::malformed(format!("compressed header byte {first:#04x}"))
                .at(span.sub(0, 1)),
        );
    }
    let len = head
        .get(1..to_usize(lenlen).saturating_add(1))
        .unwrap_or_default()
        .iter()
        .fold(0u64, |a, &x| a.wrapping_shl(8) | u64::from(x));
    Ok((span.tail(lenlen.saturating_add(1)), len, lenlen))
}

/// MariaDB's compressed data (see `decompress`) as a source decoded on
/// demand.
async fn decompress_lazy(cx: &Cx, span: Span) -> Result<Span> {
    let (data, len, _) = compressed_header(cx, span).await?;
    cx.decode_lazy(data, &Codec::Zlib, len)
}

async fn compressed(cx: &Cx, span: Span, what: &'static str) -> Node {
    match decompress(cx, span).await {
        Ok((decoded, len, _)) => {
            let text = cx
                .read(decoded.sub(0, to_u64(MAX_QUERY)))
                .await
                .unwrap_or_default();
            Node::new(what)
                .span(span)
                .value(Value::Text(String::from_utf8_lossy(&text).into_owned()))
                .summary(format!("zlib, {} → {len} bytes", span.len))
        }
        Err(d) => Node::new(what).span(span).diag(d),
    }
}

/// Query event status variables: a code, then a value whose size the code
/// determines. An unknown code ends what can be decoded.
async fn status_vars(cx: Cx, (span, mariadb): (Span, bool)) -> Result<()> {
    let b = cx.read(span).await?;
    let out = Body {
        span,
        data: b.as_slice(),
    };
    let mut p = 0u64;
    while p < out.len() {
        let code = out.byte(p);
        let v = p.saturating_add(1);
        let str8 = |at: u64| u64::from(out.byte(at)).saturating_add(1);
        let (name, len): (&str, u64) = match code {
            0 => ("Q_FLAGS2", 4),
            1 => ("Q_SQL_MODE", 8),
            2 => ("Q_CATALOG", str8(v).saturating_add(1)),
            3 => ("Q_AUTO_INCREMENT", 4),
            4 => ("Q_CHARSET", 6),
            5 => ("Q_TIME_ZONE", str8(v)),
            6 => ("Q_CATALOG_NZ", str8(v)),
            7 => ("Q_LC_TIME_NAMES", 2),
            8 => ("Q_CHARSET_DATABASE", 2),
            9 => ("Q_TABLE_MAP_FOR_UPDATE", 8),
            10 => ("Q_MASTER_DATA_WRITTEN", 4),
            11 => {
                let user = str8(v);
                (
                    "Q_INVOKER",
                    user.saturating_add(str8(v.saturating_add(user))),
                )
            }
            12 => {
                let count = out.byte(v);
                let mut q = v.saturating_add(1);
                if count != 254 {
                    for _ in 0..count {
                        let rest = out.slice(q, out.len().saturating_sub(q));
                        let n = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
                        q = q.saturating_add(to_u64(n)).saturating_add(1);
                    }
                }
                ("Q_UPDATED_DB_NAMES", q.saturating_sub(v))
            }
            13 => ("Q_MICROSECONDS", 3),
            16 => ("Q_EXPLICIT_DEFAULTS_FOR_TIMESTAMP", 1),
            17 => ("Q_DDL_LOGGED_WITH_XID", 8),
            18 => ("Q_DEFAULT_COLLATION_FOR_UTF8MB4", 2),
            19 => ("Q_SQL_REQUIRE_PRIMARY_KEY", 1),
            20 => ("Q_DEFAULT_TABLE_ENCRYPTION", 1),
            128 => ("Q_HRNOW", 3),
            129 => ("Q_XID", 8),
            130 => ("Q_GTID_FLAGS3", 1),
            // MariaDB 11.2+: a count, then (character set, collation)
            // pairs of 16-bit IDs (checked against `mariadb-binlog`'s
            // `character_set_collations` on MariaDB 11.4).
            131 => (
                "Q_CHARACTER_SET_COLLATIONS",
                u64::from(out.byte(v)).saturating_mul(4).saturating_add(1),
            ),
            _ => {
                cx.emit(
                    out.node(format!("Code {code}"), p, out.len().saturating_sub(p))
                        .value(Value::Bytes(
                            out.slice(p, out.len().saturating_sub(p).min(64)).to_vec(),
                        ))
                        .summary("unknown to this decoder: from here on shown raw"),
                );
                return Ok(());
            }
        };
        let value = match code {
            0 => flagsv(out.u32(v), 32, QUERY_FLAGS2),
            1 => flagsv(
                out.u64(v),
                64,
                if mariadb {
                    SQL_MODES_MARIADB
                } else {
                    SQL_MODES_MYSQL
                },
            ),
            9 | 17 | 129 => hex(out.u64(v), 64),
            3 => Value::Text(format!(
                "increment {}, offset {}",
                out.u16(v),
                out.u16(v.saturating_add(2))
            )),
            4 => Value::Text(format!(
                "client {}, connection {}, server {}",
                collation(out.u16(v).into()),
                collation(out.u16(v.saturating_add(2)).into()),
                collation(out.u16(v.saturating_add(4)).into())
            )),
            131 => {
                let pairs: Vec<String> = (0..u64::from(out.byte(v)))
                    .map(|i| {
                        let at = v.saturating_add(1).saturating_add(i.saturating_mul(4));
                        format!(
                            "{} → {}",
                            charset(out.u16(at).into()),
                            collation(out.u16(at.saturating_add(2)).into())
                        )
                    })
                    .collect();
                Value::Text(pairs.join(", "))
            }
            8 | 18 => Value::Text(collation(out.u16(v).into())),
            2 | 5 | 6 => Value::Text(
                String::from_utf8_lossy(out.slice(v.saturating_add(1), u64::from(out.byte(v))))
                    .into_owned(),
            ),
            11 => {
                let ulen = u64::from(out.byte(v));
                let user = String::from_utf8_lossy(out.slice(v.saturating_add(1), ulen));
                let hat = v.saturating_add(1).saturating_add(ulen);
                let host = String::from_utf8_lossy(
                    out.slice(hat.saturating_add(1), u64::from(out.byte(hat))),
                );
                Value::Text(format!("'{user}'@'{host}'"))
            }
            12 => {
                let names: Vec<String> = out
                    .slice(v.saturating_add(1), len.saturating_sub(1))
                    .split(|&c| c == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                Value::Text(names.join(", "))
            }
            13 | 128 => uint(
                u64::from(out.u16(v)) | (u64::from(out.byte(v.saturating_add(2))) << 16),
                24,
            ),
            7 => uint(out.u16(v), 16),
            10 => uint(out.u32(v), 32),
            _ => uint(out.byte(v), 8),
        };
        cx.push(out.node(name, p, len.saturating_add(1)).value(value))
            .await;
        p = v.saturating_add(len);
    }
    Ok(())
}

fn user_var(cx: &Cx, out: &Body<'_>) {
    let n = u64::from(out.u32(0));
    out.emit(cx, "Name length", 0, 4, uint(n, 32));
    out.text(cx, "Name", 4, n);
    let at = n.saturating_add(4);
    let is_null = out.byte(at);
    out.emit(cx, "Is null", at, 1, Value::Bool(is_null != 0));
    if is_null != 0 {
        return;
    }
    let ty = out.byte(at.saturating_add(1));
    out.emit(
        cx,
        "Type",
        at.saturating_add(1),
        1,
        enumv(ty, 8, USER_VAR_TYPES),
    );
    out.emit(
        cx,
        "Collation",
        at.saturating_add(2),
        4,
        enumv(out.u32(at.saturating_add(2)), 32, COLLATIONS),
    );
    let len = u64::from(out.u32(at.saturating_add(6)));
    out.emit(cx, "Value length", at.saturating_add(6), 4, uint(len, 32));
    let v = at.saturating_add(10);
    match ty {
        0 => out.text(cx, "Value", v, len),
        1 => out.emit(cx, "Value", v, len, Value::f64(f64::from_bits(out.u64(v)))),
        2 => out.emit(
            cx,
            "Value",
            v,
            len,
            Value::Int {
                value: i64::from_le_bytes(out.u64(v).to_le_bytes()),
                bits: 64,
            },
        ),
        _ => out.raw(cx, "Value", v, len),
    }
    let flags_at = v.saturating_add(len);
    if flags_at < out.len() {
        out.emit(cx, "Flags", flags_at, 1, hex(out.byte(flags_at), 8));
    }
}

fn table_map(cx: &Cx, e: &Event, out: &Body<'_>) {
    let post = e.stream.fmt.post_len(19, 8);
    let id_len = if post == 6 { 4 } else { 6 };
    out.emit(
        cx,
        "Table ID",
        0,
        id_len,
        uint(table_id_of(out.data, post), 64),
    );
    out.emit(cx, "Flags", id_len, 2, hex(out.u16(id_len), 16));
    let Some(t) = rows::parse_table_map(out.data, to_usize(post)) else {
        cx.emit(
            out.node("Table", post, out.len().saturating_sub(post))
                .diag(Diagnostic::malformed("table map does not parse")),
        );
        return;
    };
    let db_len = to_u64(t.db.len());
    out.text(cx, "Database", post.saturating_add(1), db_len);
    let t_at = post.saturating_add(db_len).saturating_add(2);
    out.text(cx, "Table", t_at.saturating_add(1), to_u64(t.table.len()));
    let (c_at, c_len) = t.count_at;
    out.emit(
        cx,
        "Column count",
        to_u64(c_at),
        to_u64(c_len),
        uint(to_u64(t.columns.len()), 32),
    );
    let types = out.at(to_u64(t.types_at.0), to_u64(t.types_at.1));
    let meta = out.at(to_u64(t.meta_at.0), to_u64(t.meta_at.1));
    let nulls = out.at(to_u64(t.nulls_at.0), to_u64(t.nulls_at.1));
    let n = t.columns.len();
    let shared = Arc::new(t);
    cx.emit(
        Node::new("Columns")
            .span(types)
            .summary(plural(n, "column"))
            .lazy(columns, (shared.clone(), types)),
    );
    cx.emit(Node::new("Column metadata").span(meta));
    cx.emit(Node::new("NULL bitmap").span(nulls));
    let (o_at, o_len) = shared.optional_at;
    if o_len > 0 {
        let span = out.at(to_u64(o_at), to_u64(o_len));
        cx.emit(
            Node::new("Optional metadata")
                .span(span)
                .lazy(optional_metadata, span),
        );
    }
}

async fn columns(cx: Cx, (t, types): (Arc<TableMap>, Span)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(t.columns.len())));
    for (i, c) in t.columns.iter().enumerate() {
        let name = c
            .name
            .clone()
            .unwrap_or_else(|| format!("@{}", i.saturating_add(1)));
        let mut summary = rows::describe(c);
        if c.unsigned {
            summary.push_str(" UNSIGNED");
        }
        if !c.nullable {
            summary.push_str(" NOT NULL");
        }
        if !c.members.is_empty() {
            summary.push_str(&format!(" ({})", c.members.join(", ")));
        }
        cx.push(
            Node::new(name)
                .span(types.sub(to_u64(i), 1))
                .value(enumv(c.ty, 8, rows::COLUMN_TYPES))
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

async fn optional_metadata(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read(span).await?;
    for (t, start, value, end) in rows::optional_fields(&b) {
        let v = b.get(value..end).unwrap_or_default();
        let mut node = Node::new(
            lookup(rows::OPTIONAL_METADATA, t.into())
                .map_or_else(|| format!("Type {t}"), str::to_owned),
        )
        .span(span.sub(to_u64(start), to_u64(end.saturating_sub(start))));
        node = match t {
            4 => node.value(Value::Text(rows::lenenc_strings(v).join(", "))),
            8 => {
                let cols: Vec<String> = lenenc_ints(v)
                    .iter()
                    .map(|c| c.saturating_add(1).to_string())
                    .collect();
                node.value(Value::Text(cols.join(", ")))
                    .summary("primary key columns (from 1)")
            }
            // The default collation, then (column, collation) pairs for
            // the columns that differ; columns count only the character
            // (or for 10, ENUM and SET) columns, from 0.
            2 | 10 => {
                let ids = lenenc_ints(v);
                let mut parts = Vec::new();
                if let Some(&default) = ids.first() {
                    parts.push(format!("default {}", collation(default)));
                }
                for pair in ids.get(1..).unwrap_or_default().chunks(2) {
                    if let [col, id] = pair {
                        parts.push(format!("column {col}: {}", collation(*id)));
                    }
                }
                node.value(Value::Text(parts.join(", ")))
            }
            // One collation per character (or ENUM and SET) column.
            3 | 11 => {
                let ids: Vec<String> = lenenc_ints(v).into_iter().map(collation).collect();
                node.value(Value::Text(ids.join(", ")))
            }
            // Per ENUM or SET column: a count, then that many strings.
            5 | 6 => node.value(Value::Text(member_lists(v).join("; "))),
            _ => node.value(Value::Bytes(v.iter().take(256).copied().collect())),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// Length-encoded integers filling `b`.
fn lenenc_ints(b: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while let Some((c, n)) = b.get(p..).and_then(lenenc) {
        out.push(c);
        p = p.saturating_add(n);
    }
    out
}

/// The member lists of SET_STR_VALUE and ENUM_STR_VALUE: per column, a
/// length-encoded count, then that many length-encoded strings.
fn member_lists(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while let Some((count, n)) = b.get(p..).and_then(lenenc) {
        p = p.saturating_add(n);
        let mut members = Vec::new();
        for _ in 0..count {
            let Some((len, n)) = b.get(p..).and_then(lenenc) else {
                break;
            };
            let start = p.saturating_add(n);
            let end = start.saturating_add(to_usize(len));
            let Some(s) = b.get(start..end) else {
                break;
            };
            members.push(String::from_utf8_lossy(s).into_owned());
            p = end;
        }
        out.push(members.join(", "));
        if p >= b.len() {
            break;
        }
    }
    out
}

/// What a rows event's listing needs.
#[derive(Clone, Debug)]
struct Rows {
    /// The rows: from the first row to the end of the event's body.
    data: Span,
    table: Option<Arc<TableMap>>,
    present: Vec<u8>,
    present_after: Option<Vec<u8>>,
    kind: u8,
}

async fn rows_event(cx: &Cx, e: &Event, out: &Body<'_>) -> Result<()> {
    let post = e
        .stream
        .fmt
        .post_len(e.ty, if rows_v2(e.ty) { 10 } else { 8 });
    let id_len = if post == 6 { 4 } else { 6 };
    out.emit(
        cx,
        "Table ID",
        0,
        id_len,
        uint(table_id_of(out.data, post), 64),
    );
    out.emit(
        cx,
        "Flags",
        id_len,
        2,
        flagsv(out.u16(id_len), 16, ROWS_FLAGS),
    );
    let mut at = post;
    if rows_v2(e.ty) {
        let extra = u64::from(out.u16(id_len.saturating_add(2)));
        out.emit(
            cx,
            "Extra data length",
            id_len.saturating_add(2),
            2,
            uint(extra, 16),
        );
        if extra > 2 {
            out.raw(cx, "Extra data", at, extra.saturating_sub(2));
        }
        at = at.saturating_add(extra.saturating_sub(2));
    }
    // The column count and bitmaps, then the rows (compressed by MariaDB's
    // log_bin_compress: only the rows are).
    let data = out.at(at, out.len().saturating_sub(at));
    let bytes = cx.read(data.sub(0, 32)).await?;
    let Some((ncols, n)) = lenenc(&bytes) else {
        return Err(Diagnostic::truncated(data, to_u64(bytes.len())));
    };
    let n = to_u64(n);
    cx.emit(
        Node::new("Column count")
            .span(data.sub(0, n))
            .value(uint(ncols, 32)),
    );
    if ncols > rows::MAX_COLUMNS {
        return Err(Diagnostic::limit(format!("{ncols} columns")).at(data.sub(0, n)));
    }
    let blen = rows::bitmap_len(ncols);
    let present = cx.read(data.sub_exact(n, blen)?).await?;
    cx.emit(
        Node::new("Columns present")
            .span(data.sub(n, blen))
            .value(Value::Bytes(present.clone()))
            .summary(plural(rows::bits_set(&present, ncols), "column")),
    );
    let mut p = n.saturating_add(blen);
    let present_after = if rows_kind(e.ty) == 1 {
        let after = cx.read(data.sub_exact(p, blen)?).await?;
        cx.emit(
            Node::new("Columns present (after image)")
                .span(data.sub(p, blen))
                .value(Value::Bytes(after.clone()))
                .summary(plural(rows::bits_set(&after, ncols), "column")),
        );
        p = p.saturating_add(blen);
        Some(after)
    } else {
        None
    };
    let rest = data.tail(p);
    let rows_span = if (166..=171).contains(&e.ty) {
        match decompress(cx, rest).await {
            Ok((span, len, _)) => {
                cx.emit(
                    Node::new("Compressed rows")
                        .span(rest)
                        .summary(format!("zlib, {} → {len} bytes", rest.len)),
                );
                span
            }
            Err(d) => {
                cx.emit(Node::new("Compressed rows").span(rest).diag(d));
                return Ok(());
            }
        }
    } else {
        rest
    };
    let table = match e.table {
        Some(span) => {
            let ev = Event {
                span,
                ty: 19,
                table: None,
                stream: e.stream.clone(),
            };
            let b = body(cx, &ev).await?;
            rows::parse_table_map(&b, to_usize(e.stream.fmt.post_len(19, 8))).map(Arc::new)
        }
        None => None,
    };
    let mut node = Node::new("Rows").span(rows_span);
    if let Some(t) = &table {
        node = node.summary(t.qualified());
        if to_u64(t.columns.len()) != ncols {
            node = node.diag(Diagnostic::malformed(format!(
                "{ncols} columns, the table map has {}",
                t.columns.len()
            )));
        }
    } else {
        node = node.diag(Diagnostic::unsupported(
            "no table map for this table: the values cannot be decoded",
        ));
    }
    if e.ty == 39 {
        node = node.desc("Partial updates: JSON columns of after images may hold diffs");
    }
    cx.emit(node.lazy(
        crate::expander!(self::row_list: Rows),
        Rows {
            data: rows_span,
            table,
            present,
            present_after,
            kind: if e.ty == 39 { 3 } else { rows_kind(e.ty) },
        },
    ));
    Ok(())
}

async fn row_list(cx: Cx, r: Rows) -> Result<()> {
    let Some(t) = r.table.clone() else {
        return Ok(());
    };
    if r.data.len > MAX_EVENT {
        return Err(Diagnostic::limit(format!("{} bytes of rows", r.data.len)).at(r.data));
    }
    let b = cx.read(r.data).await?;
    let (mut p, mut index) = cx.resume::<(usize, u64)>().unwrap_or((0, 0));
    while p < b.len() {
        let mark = (p, index);
        cx.mark(move || mark);
        cx.charge(to_u64(t.columns.len())).await;
        let start = p;
        let before = rows::image(&b, p, &t.columns, &r.present);
        let (cells, end) = match before {
            Ok(x) => x,
            Err(at) => {
                cx.push(
                    Node::new(format!("Row {index}"))
                        .span(r.data.tail(to_u64(start)))
                        .diag(Diagnostic::unsupported(format!(
                            "a value at {:#x} cannot be decoded",
                            r.data.offset.saturating_add(to_u64(at))
                        ))),
                )
                .await;
                return Ok(());
            }
        };
        let mut images = vec![(cells, start, end)];
        p = end;
        if let Some(after) = &r.present_after {
            // Partial JSON updates: the after image starts with the
            // value options and the partial columns.
            let (image_at, partial) = if r.kind == 3 {
                match rows::partial_header(&b, p, &t.columns) {
                    Some((at, _, partial)) => (at, partial),
                    None => {
                        cx.push(
                            Node::new(format!("Row {index}"))
                                .span(r.data.tail(to_u64(start)))
                                .diag(Diagnostic::malformed(
                                    "the partial update header does not decode",
                                )),
                        )
                        .await;
                        return Ok(());
                    }
                }
            } else {
                (p, Vec::new())
            };
            match rows::image_with(&b, image_at, &t.columns, after, &partial) {
                Ok((cells, end)) => {
                    images.push((cells, p, end));
                    p = end;
                }
                Err(at) => {
                    cx.push(
                        Node::new(format!("Row {index}"))
                            .span(r.data.tail(to_u64(start)))
                            .diag(Diagnostic::unsupported(format!(
                                "a value at {:#x} cannot be decoded",
                                r.data.offset.saturating_add(to_u64(at))
                            ))),
                    )
                    .await;
                    return Ok(());
                }
            }
        }
        if p == start {
            // No column present: rows would take no bytes.
            cx.push(
                Node::new(format!("Row {index}"))
                    .span(r.data.tail(to_u64(start)))
                    .diag(Diagnostic::malformed("rows with no columns present")),
            )
            .await;
            return Ok(());
        }
        let span = r.data.sub(to_u64(start), to_u64(p.saturating_sub(start)));
        let summary = images
            .iter()
            .map(|(cells, _, _)| row_summary(&t.columns, &b, cells))
            .collect::<Vec<_>>()
            .join(" → ");
        let image_spans: Vec<(u64, u64)> = images
            .iter()
            .map(|(_, s, e)| (to_u64(*s), to_u64(*e)))
            .collect();
        cx.push(
            Node::new(format!("Row {index}"))
                .span(span)
                .summary(summary)
                .lazy(
                    crate::expander!(self::row: (Rows, Vec<(u64, u64)>)),
                    (r.clone(), image_spans),
                ),
        )
        .await;
        index = index.saturating_add(1);
    }
    Ok(())
}

fn row_summary(columns: &[Column], b: &[u8], cells: &[rows::Cell]) -> String {
    let mut parts = Vec::new();
    for c in cells.iter().take(8) {
        parts.push(match c.at {
            None => "NULL".to_owned(),
            Some((at, n)) => match columns.get(c.column) {
                Some(col) => {
                    let v = b.get(at..at.saturating_add(n)).unwrap_or_default();
                    if c.partial {
                        rows::partial_value(col, v).1
                    } else {
                        rows::value(col, v).1
                    }
                }
                None => "?".to_owned(),
            },
        });
    }
    if cells.len() > 8 {
        parts.push("…".to_owned());
    }
    format!("({})", clip(&parts.join(", "), 200))
}

async fn row(cx: Cx, (r, images): (Rows, Vec<(u64, u64)>)) -> Result<()> {
    let Some(t) = r.table.clone() else {
        return Ok(());
    };
    let names = match (r.kind, images.len()) {
        (1 | 3, 2) => ["Before image", "After image"].as_slice(),
        _ => [""].as_slice(),
    };
    for (k, &(start, end)) in images.iter().enumerate() {
        let span = r.data.sub(start, end.saturating_sub(start));
        let present = if k == 0 {
            r.present.clone()
        } else {
            r.present_after.clone().unwrap_or_default()
        };
        let state = (span, t.clone(), present, r.kind == 3 && k == 1);
        match names.get(k) {
            Some(name) if !name.is_empty() => {
                cx.emit(Node::new(*name).span(span).lazy(
                    crate::expander!(self::cells: (Span, Arc<TableMap>, Vec<u8>, bool)),
                    state,
                ));
            }
            _ => cells(cx.clone(), state).await?,
        }
    }
    Ok(())
}

/// The cells of a row image; `partial` for a partial update's after
/// image, which starts with its value options and partial columns.
async fn cells(
    cx: Cx,
    (span, t, present, partial): (Span, Arc<TableMap>, Vec<u8>, bool),
) -> Result<()> {
    let b = cx.read(span).await?;
    let (start, diffs) = if partial {
        let Some((end, options, diffs)) = rows::partial_header(&b, 0, &t.columns) else {
            return Err(Diagnostic::malformed("partial update header does not decode").at(span));
        };
        let n = lenenc(&b).map_or(1, |(_, n)| n);
        cx.emit(
            Node::new("Value options")
                .span(span.sub(0, to_u64(n)))
                .value(flagsv(options, 64, VALUE_OPTIONS)),
        );
        if end > n {
            let names: Vec<String> = diffs
                .iter()
                .map(|&i| {
                    t.columns
                        .get(i)
                        .and_then(|c| c.name.clone())
                        .unwrap_or_else(|| format!("@{}", i.saturating_add(1)))
                })
                .collect();
            cx.emit(
                Node::new("Partial JSON columns")
                    .span(span.sub(to_u64(n), to_u64(end.saturating_sub(n))))
                    .value(Value::Bytes(b.get(n..end).unwrap_or_default().to_vec()))
                    .summary(if names.is_empty() {
                        "none".to_owned()
                    } else {
                        names.join(", ")
                    })
                    .desc("A bit for each JSON column of the table: set where it holds diffs"),
            );
        }
        (end, diffs)
    } else {
        (0, Vec::new())
    };
    let Ok((cells, _)) = rows::image_with(&b, start, &t.columns, &present, &diffs) else {
        return Err(Diagnostic::malformed("row image does not decode").at(span));
    };
    let null_len = to_u64(cells.len().div_ceil(8));
    cx.emit(Node::new("NULL bitmap").span(span.sub(to_u64(start), null_len)));
    for c in &cells {
        let col = t.columns.get(c.column).cloned().unwrap_or_default();
        let name = col
            .name
            .clone()
            .unwrap_or_else(|| format!("@{}", c.column.saturating_add(1)));
        let node = Node::new(name);
        cx.push(match c.at {
            None => node.summary(format!("NULL, {}", cell_type(&col))),
            Some((at, n)) => {
                let data = b.get(at..at.saturating_add(n)).unwrap_or_default();
                if c.partial {
                    let (v, _) = rows::partial_value(&col, data);
                    node.span(span.sub(to_u64(at), to_u64(n)))
                        .value(v)
                        .summary(format!("{}, JSON diffs", cell_type(&col)))
                } else {
                    let (v, _) = rows::value(&col, data);
                    node.span(span.sub(to_u64(at), to_u64(n)))
                        .value(v)
                        .summary(cell_type(&col))
                }
            }
        })
        .await;
    }
    Ok(())
}

/// A cell's column type, with its signedness.
fn cell_type(c: &Column) -> String {
    let mut s = rows::describe(c);
    if c.unsigned {
        s.push_str(" UNSIGNED");
    }
    s
}

fn gtid(cx: &Cx, out: &Body<'_>) {
    out.emit(cx, "Flags", 0, 1, hex(out.byte(0), 8));
    let sid = out.slice(1, 16);
    cx.emit(out.node("Server UUID", 1, 16).value(Value::uuid(sid)));
    out.emit(cx, "GNO", 17, 8, uint(out.u64(17), 64));
    if out.len() <= 25 {
        return;
    }
    out.emit(cx, "Logical clock type", 25, 1, uint(out.byte(25), 8));
    out.emit(cx, "Last committed", 26, 8, uint(out.u64(26), 64));
    out.emit(cx, "Sequence number", 34, 8, uint(out.u64(34), 64));
    let mut p = 42u64;
    if p.saturating_add(7) > out.len() {
        return;
    }
    let ts = |at: u64| {
        let b = out.slice(at, 7);
        b.iter()
            .rev()
            .fold(0u64, |a, &x| a.wrapping_shl(8) | u64::from(x))
    };
    let immediate = ts(p);
    let has_original = immediate & (1 << 55) != 0;
    let micros = immediate & !(1 << 55);
    cx.emit(
        out.node("Immediate commit timestamp", p, 7)
            .value(Value::utc(i64::try_from(micros / 1_000_000).unwrap_or(0)))
            .summary(format!("{micros} µs")),
    );
    p = p.saturating_add(7);
    if has_original {
        let original = ts(p);
        cx.emit(
            out.node("Original commit timestamp", p, 7)
                .value(Value::utc(i64::try_from(original / 1_000_000).unwrap_or(0)))
                .summary(format!("{original} µs")),
        );
        p = p.saturating_add(7);
    }
    if p >= out.len() {
        return;
    }
    if let Some((len, n)) = lenenc(out.slice(p, 9)) {
        out.emit(cx, "Transaction length", p, to_u64(n), uint(len, 64));
        p = p.saturating_add(to_u64(n));
    }
    if p.saturating_add(4) > out.len() {
        return;
    }
    let immediate = out.u32(p);
    out.emit(
        cx,
        "Immediate server version",
        p,
        4,
        uint(immediate & 0x7fff_ffff, 32),
    );
    p = p.saturating_add(4);
    if immediate & 0x8000_0000 != 0 {
        out.emit(cx, "Original server version", p, 4, uint(out.u32(p), 32));
        p = p.saturating_add(4);
    }
    if p < out.len() {
        out.raw(cx, "More fields", p, out.len().saturating_sub(p));
    }
}

fn previous_gtids(cx: &Cx, out: &Body<'_>) {
    let n = out.u64(0);
    if n >> 56 != 0 {
        out.emit(cx, "Format and count", 0, 8, hex(n, 64));
        out.raw(cx, "Tagged GTID set", 8, out.len().saturating_sub(8));
        return;
    }
    out.emit(cx, "Server UUIDs", 0, 8, uint(n, 64));
    let mut p = 8u64;
    for _ in 0..n.min(4096) {
        if p.saturating_add(24) > out.len() {
            break;
        }
        let sid = uuid(out.slice(p, 16));
        let k = out.u64(p.saturating_add(16));
        let mut q = p.saturating_add(24);
        let mut parts = Vec::new();
        for _ in 0..k.min(4096) {
            if q.saturating_add(16) > out.len() {
                break;
            }
            let start = out.u64(q);
            let end = out.u64(q.saturating_add(8)).saturating_sub(1);
            parts.push(if start == end {
                start.to_string()
            } else {
                format!("{start}-{end}")
            });
            q = q.saturating_add(16);
        }
        cx.emit(
            out.node(sid.clone(), p, q.saturating_sub(p))
                .value(Value::Text(format!("{sid}:{}", parts.join(":"))))
                .summary(plural(k, "interval")),
        );
        p = q;
    }
}

fn mariadb_gtid(cx: &Cx, out: &Body<'_>) {
    out.emit(cx, "Sequence number", 0, 8, uint(out.u64(0), 64));
    out.emit(cx, "Domain ID", 8, 4, uint(out.u32(8), 32));
    let flags = out.byte(12);
    out.emit(cx, "Flags", 12, 1, flagsv(flags, 8, MARIADB_GTID_FLAGS));
    let mut p = 13u64;
    if flags & 0x2 != 0 {
        out.emit(cx, "Commit ID", p, 8, uint(out.u64(p), 64));
        p = p.saturating_add(8);
    }
    if flags & 0xc0 != 0 && p.saturating_add(6) <= out.len() {
        // The XA transaction's XID.
        let gtrid = u64::from(out.byte(p.saturating_add(4)));
        let bqual = u64::from(out.byte(p.saturating_add(5)));
        let len = 6u64.saturating_add(gtrid).saturating_add(bqual);
        let text = mariadb_xid(out.data, flags).unwrap_or_default();
        cx.emit(
            out.node("XID", p, len)
                .value(Value::Text(text))
                .lazy(xid_fields, out.at(p, len)),
        );
        p = p.saturating_add(len);
    }
    if out.byte(p) != 0 {
        // Extra flags, written only when some are set (MariaDB 10.5 and
        // later; layout from memory, the multi-engine count seen in files
        // 11.4 writes).
        let extra = out.byte(p);
        out.emit(
            cx,
            "Extra flags",
            p,
            1,
            flagsv(extra, 8, MARIADB_GTID_EXTRA),
        );
        p = p.saturating_add(1);
        if extra & 0x1 != 0 && p < out.len() {
            cx.emit(
                out.node("Extra engines", p, 1)
                    .value(uint(out.byte(p), 8))
                    .desc("Storage engines in the transaction beyond the first"),
            );
            p = p.saturating_add(1);
        }
    }
    if p < out.len() {
        let rest = out.slice(p, out.len().saturating_sub(p));
        if rest.iter().all(|&b| b == 0) {
            cx.emit(
                out.node("Padding", p, out.len().saturating_sub(p))
                    .desc("Zeros to the event's 19-byte post-header"),
            );
        } else {
            out.raw(cx, "More", p, out.len().saturating_sub(p));
        }
    }
}

/// The XID text of a MariaDB GTID event body `b` with XA flags.
fn mariadb_xid(b: &[u8], flags: u8) -> Option<String> {
    if flags & 0xc0 == 0 {
        return None;
    }
    let p = if flags & 0x2 != 0 { 21usize } else { 13 };
    let format_id = u32_le(b, p)?;
    let gtrid = usize::from(*b.get(p.checked_add(4)?)?);
    let bqual = usize::from(*b.get(p.checked_add(5)?)?);
    let data = p.checked_add(6)?;
    let mid = data.checked_add(gtrid)?;
    let g = b.get(data..mid)?;
    let q = b.get(mid..mid.checked_add(bqual)?)?;
    Some(xid_text(format_id, g, q))
}

/// An XID as XA statements show it: `X'gtrid',X'bqual',formatID`.
fn xid_text(format_id: u32, gtrid: &[u8], bqual: &[u8]) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!("X'{}',X'{}',{format_id}", hex(gtrid), hex(bqual))
}

/// The XID of an XA prepare event body: whether it is a one-phase
/// commit, and the XID's text.
fn xa_prepare_xid(b: &[u8]) -> Option<(bool, String)> {
    let one_phase = *b.first()? != 0;
    let format_id = u32_le(b, 1)?;
    let gtrid = to_usize(u32_le(b, 5)?.into());
    let bqual = to_usize(u32_le(b, 9)?.into());
    let mid = 13usize.checked_add(gtrid)?;
    let g = b.get(13..mid)?;
    let q = b.get(mid..mid.checked_add(bqual)?)?;
    Some((one_phase, xid_text(format_id, g, q)))
}

/// XA prepare (MySQL and MariaDB): whether it commits in one phase, then
/// the XID (format ID, the lengths of its two parts as 32-bit numbers,
/// then the parts).
fn xa_prepare(cx: &Cx, out: &Body<'_>) {
    out.emit(cx, "One phase", 0, 1, Value::Bool(out.byte(0) != 0));
    out.emit(cx, "Format ID", 1, 4, uint(out.u32(1), 32));
    let gtrid = u64::from(out.u32(5));
    let bqual = u64::from(out.u32(9));
    out.emit(cx, "Gtrid length", 5, 4, uint(gtrid, 32));
    out.emit(cx, "Bqual length", 9, 4, uint(bqual, 32));
    out.raw(cx, "Gtrid", 13, gtrid);
    out.raw(cx, "Bqual", 13u64.saturating_add(gtrid), bqual);
}

/// The fields of a MariaDB GTID event's XID: format ID, the lengths of
/// its two parts (one byte each), the parts.
async fn xid_fields(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read(span).await?;
    let out = Body {
        span,
        data: b.as_slice(),
    };
    out.emit(&cx, "Format ID", 0, 4, uint(out.u32(0), 32));
    let gtrid = u64::from(out.byte(4));
    let bqual = u64::from(out.byte(5));
    out.emit(&cx, "Gtrid length", 4, 1, uint(gtrid, 8));
    out.emit(&cx, "Bqual length", 5, 1, uint(bqual, 8));
    out.raw(&cx, "Gtrid", 6, gtrid);
    out.raw(&cx, "Bqual", 6u64.saturating_add(gtrid), bqual);
    Ok(())
}

fn gtid_list(cx: &Cx, out: &Body<'_>) {
    let raw = out.u32(0);
    out.emit(cx, "Count", 0, 4, uint(raw & 0x0fff_ffff, 28));
    if raw >> 28 != 0 {
        out.emit(cx, "Flags", 0, 4, hex(raw >> 28, 8));
    }
    for i in 0..u64::from(raw & 0x0fff_ffff).min(4096) {
        let at = i.saturating_mul(16).saturating_add(4);
        if at.saturating_add(16) > out.len() {
            break;
        }
        cx.emit(
            out.node(format!("[{i}]"), at, 16)
                .value(Value::Text(format!(
                    "{}-{}-{}",
                    out.u32(at),
                    out.u32(at.saturating_add(4)),
                    out.u64(at.saturating_add(8))
                ))),
        );
    }
}

async fn payload(cx: &Cx, e: &Event, out: &Body<'_>) -> Result<()> {
    let Some(p) = payload_header(out.data) else {
        cx.emit(
            Node::new("Payload")
                .span(out.span)
                .diag(Diagnostic::malformed("payload header does not parse")),
        );
        return Ok(());
    };
    for &(ty, start, len) in &p.fields {
        let (name, value) = match ty {
            0 => ("End of header", None),
            1 => ("Payload size", Some(uint(p.size, 64))),
            2 => (
                "Compression",
                Some(enumv(p.compression, 8, PAYLOAD_COMPRESSION)),
            ),
            3 => ("Uncompressed size", Some(uint(p.uncompressed, 64))),
            _ => ("Field", None),
        };
        let mut node = out.node(name, to_u64(start), to_u64(len));
        if let Some(v) = value {
            node = node.value(v);
        }
        cx.emit(node);
    }
    let data = out.at(to_u64(p.data), out.len().saturating_sub(to_u64(p.data)));
    let events = match p.compression {
        0 => {
            let decoded =
                crate::codec::decode_span(cx, data, &Codec::Zstd, Some(p.uncompressed)).await?;
            if let Some(err) = decoded.error {
                cx.emit(Node::new("Payload").span(data).diag(err));
                return Ok(());
            }
            decoded.span
        }
        255 => data,
        c => {
            cx.emit(
                Node::new("Payload")
                    .span(data)
                    .diag(Diagnostic::unsupported(format!("compression type {c}"))),
            );
            return Ok(());
        }
    };
    let inner = Stream {
        input: e.stream.input,
        relay: e.stream.relay,
        region: events,
        fmt: Fmt {
            checksum: false,
            ..e.stream.fmt.clone()
        },
    };
    cx.emit(
        Node::new("Events")
            .span(data)
            .summary(format!("{} decoded", events.len))
            .lazy(crate::expander!(self::inner_events: Stream), inner),
    );
    Ok(())
}

async fn inner_events(cx: Cx, s: Stream) -> Result<()> {
    let resumed = cx.resume::<Walk>();
    walk(&cx, &s, 0, resumed, false).await
}
