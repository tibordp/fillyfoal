//! `global/pg_control`: the cluster's control file, what `pg_controldata`
//! prints. One 8 KiB file holding a C struct (`ControlFileData`) and a
//! CRC-32C of it; the rest is zero. The layouts here are those of control
//! file versions 1002 (PostgreSQL 10), 1100 (11), 1201 (12), 1300 (13 to
//! 16), 1700 (17) and 1800 (18): 11 dropped the prior checkpoint, 12 made
//! the next transaction ID 64 bits and added `max_wal_senders`, 13 dropped
//! `float4ByVal`, 17 put `wal_level` into the checkpoint and 18 added the
//! default char signedness.

use super::relation::lsn;
use crate::bytes::{to_usize, u32_le, u64_le};
use crate::codec::crc::crc32c;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::val::{hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Check, EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "pg-control",
    title: "PostgreSQL control file",
    extensions: &[],
    mime: "application/x-postgresql-control",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// The file is always this long (`PG_CONTROL_FILE_SIZE`).
const FILE_SIZE: u64 = 8192;

/// Where the CRC is, by control file version.
fn crc_at(version: u32) -> Option<usize> {
    match version {
        1002 | 1201 | 1300 | 1700 => Some(288),
        1100 => Some(280),
        1800 => Some(292),
        _ => None,
    }
}

/// The struct's fields, by control file version.
fn fields(version: u32) -> &'static [(&'static str, usize, F)] {
    match version {
        1002 => FIELDS_10,
        1100 => FIELDS_11,
        1201 => FIELDS_12,
        1300 => FIELDS_13,
        _ => FIELDS,
    }
}

fn probe(h: &Head<'_>) -> bool {
    if h.len != FILE_SIZE {
        return false;
    }
    let d = h.data;
    let (Some(version), Some(catalog)) = (u32_le(d, 8), u32_le(d, 12)) else {
        return false;
    };
    let Some(at) = crc_at(version) else {
        return false;
    };
    (200_000_000..300_000_000).contains(&catalog)
        && d.get(..at)
            .is_some_and(|b| u32_le(d, at) == Some(crc32c(b)))
}

const STATES: EnumTable = &[
    (0, "starting up"),
    (1, "shut down"),
    (2, "shut down in recovery"),
    (3, "shutting down"),
    (4, "in crash recovery"),
    (5, "in archive recovery"),
    (6, "in production"),
];

const WAL_LEVELS: EnumTable = &[(0, "minimal"), (1, "replica"), (2, "logical")];

fn release(version: u32) -> &'static str {
    match version {
        1002 => "PostgreSQL 10",
        1100 => "PostgreSQL 11",
        1201 => "PostgreSQL 12",
        1300 => "PostgreSQL 13 to 16",
        1700 => "PostgreSQL 17",
        1800 => "PostgreSQL 18",
        _ => "unknown release",
    }
}

/// One field of the struct: name, offset, kind.
#[derive(Clone, Copy)]
enum F {
    U32,
    I32,
    U64,
    Lsn,
    Time,
    Bool,
    Enum(EnumTable),
    Float,
    Xid64,
    /// A 32-bit epoch, then a 32-bit transaction ID (before PostgreSQL 12).
    XidEpoch,
}

const FIELDS: &[(&str, usize, F)] = &[
    ("System identifier", 0, F::U64),
    ("Control file version", 8, F::U32),
    ("Catalog version", 12, F::U32),
    ("State", 16, F::Enum(STATES)),
    ("Last modified", 24, F::Time),
    ("Latest checkpoint", 32, F::Lsn),
    ("Checkpoint: REDO location", 40, F::Lsn),
    ("Checkpoint: timeline", 48, F::U32),
    ("Checkpoint: previous timeline", 52, F::U32),
    ("Checkpoint: full page writes", 56, F::Bool),
    ("Checkpoint: wal_level", 60, F::Enum(WAL_LEVELS)),
    ("Checkpoint: next XID", 64, F::Xid64),
    ("Checkpoint: next OID", 72, F::U32),
    ("Checkpoint: next MultiXactId", 76, F::U32),
    ("Checkpoint: next MultiXact offset", 80, F::U32),
    ("Checkpoint: oldest XID", 84, F::U32),
    ("Checkpoint: oldest XID's database", 88, F::U32),
    ("Checkpoint: oldest MultiXactId", 92, F::U32),
    ("Checkpoint: oldest MultiXact's database", 96, F::U32),
    ("Checkpoint: time", 104, F::Time),
    ("Checkpoint: oldest commit timestamp XID", 112, F::U32),
    ("Checkpoint: newest commit timestamp XID", 116, F::U32),
    ("Checkpoint: oldest active XID", 120, F::U32),
    ("Fake LSN for unlogged relations", 128, F::Lsn),
    ("Minimum recovery ending location", 136, F::Lsn),
    ("Minimum recovery ending timeline", 144, F::U32),
    ("Backup start location", 152, F::Lsn),
    ("Backup end location", 160, F::Lsn),
    ("End-of-backup record required", 168, F::Bool),
    ("wal_level", 172, F::Enum(WAL_LEVELS)),
    ("wal_log_hints", 176, F::Bool),
    ("max_connections", 180, F::I32),
    ("max_worker_processes", 184, F::I32),
    ("max_wal_senders", 188, F::I32),
    ("max_prepared_transactions", 192, F::I32),
    ("max_locks_per_transaction", 196, F::I32),
    ("track_commit_timestamp", 200, F::Bool),
    ("Maximum data alignment", 204, F::U32),
    ("Float format check", 208, F::Float),
    ("Block size", 216, F::U32),
    ("Blocks per relation segment", 220, F::U32),
    ("WAL block size", 224, F::U32),
    ("WAL segment size", 228, F::U32),
    ("Maximum identifier length", 232, F::U32),
    ("Maximum index columns", 236, F::U32),
    ("Maximum TOAST chunk size", 240, F::U32),
    ("Large object chunk size", 244, F::U32),
    ("float8 passed by value", 248, F::Bool),
    ("Data checksum version", 252, F::U32),
];

/// PostgreSQL 13 to 16: as 17, without the checkpoint's `wal_level`.
const FIELDS_13: &[(&str, usize, F)] = &[
    ("System identifier", 0, F::U64),
    ("Control file version", 8, F::U32),
    ("Catalog version", 12, F::U32),
    ("State", 16, F::Enum(STATES)),
    ("Last modified", 24, F::Time),
    ("Latest checkpoint", 32, F::Lsn),
    ("Checkpoint: REDO location", 40, F::Lsn),
    ("Checkpoint: timeline", 48, F::U32),
    ("Checkpoint: previous timeline", 52, F::U32),
    ("Checkpoint: full page writes", 56, F::Bool),
    ("Checkpoint: next XID", 64, F::Xid64),
    ("Checkpoint: next OID", 72, F::U32),
    ("Checkpoint: next MultiXactId", 76, F::U32),
    ("Checkpoint: next MultiXact offset", 80, F::U32),
    ("Checkpoint: oldest XID", 84, F::U32),
    ("Checkpoint: oldest XID's database", 88, F::U32),
    ("Checkpoint: oldest MultiXactId", 92, F::U32),
    ("Checkpoint: oldest MultiXact's database", 96, F::U32),
    ("Checkpoint: time", 104, F::Time),
    ("Checkpoint: oldest commit timestamp XID", 112, F::U32),
    ("Checkpoint: newest commit timestamp XID", 116, F::U32),
    ("Checkpoint: oldest active XID", 120, F::U32),
    ("Fake LSN for unlogged relations", 128, F::Lsn),
    ("Minimum recovery ending location", 136, F::Lsn),
    ("Minimum recovery ending timeline", 144, F::U32),
    ("Backup start location", 152, F::Lsn),
    ("Backup end location", 160, F::Lsn),
    ("End-of-backup record required", 168, F::Bool),
    ("wal_level", 172, F::Enum(WAL_LEVELS)),
    ("wal_log_hints", 176, F::Bool),
    ("max_connections", 180, F::I32),
    ("max_worker_processes", 184, F::I32),
    ("max_wal_senders", 188, F::I32),
    ("max_prepared_transactions", 192, F::I32),
    ("max_locks_per_transaction", 196, F::I32),
    ("track_commit_timestamp", 200, F::Bool),
    ("Maximum data alignment", 204, F::U32),
    ("Float format check", 208, F::Float),
    ("Block size", 216, F::U32),
    ("Blocks per relation segment", 220, F::U32),
    ("WAL block size", 224, F::U32),
    ("WAL segment size", 228, F::U32),
    ("Maximum identifier length", 232, F::U32),
    ("Maximum index columns", 236, F::U32),
    ("Maximum TOAST chunk size", 240, F::U32),
    ("Large object chunk size", 244, F::U32),
    ("float8 passed by value", 248, F::Bool),
    ("Data checksum version", 252, F::U32),
];

/// PostgreSQL 12: as 13, with `float4ByVal`.
const FIELDS_12: &[(&str, usize, F)] = &[
    ("System identifier", 0, F::U64),
    ("Control file version", 8, F::U32),
    ("Catalog version", 12, F::U32),
    ("State", 16, F::Enum(STATES)),
    ("Last modified", 24, F::Time),
    ("Latest checkpoint", 32, F::Lsn),
    ("Checkpoint: REDO location", 40, F::Lsn),
    ("Checkpoint: timeline", 48, F::U32),
    ("Checkpoint: previous timeline", 52, F::U32),
    ("Checkpoint: full page writes", 56, F::Bool),
    ("Checkpoint: next XID", 64, F::Xid64),
    ("Checkpoint: next OID", 72, F::U32),
    ("Checkpoint: next MultiXactId", 76, F::U32),
    ("Checkpoint: next MultiXact offset", 80, F::U32),
    ("Checkpoint: oldest XID", 84, F::U32),
    ("Checkpoint: oldest XID's database", 88, F::U32),
    ("Checkpoint: oldest MultiXactId", 92, F::U32),
    ("Checkpoint: oldest MultiXact's database", 96, F::U32),
    ("Checkpoint: time", 104, F::Time),
    ("Checkpoint: oldest commit timestamp XID", 112, F::U32),
    ("Checkpoint: newest commit timestamp XID", 116, F::U32),
    ("Checkpoint: oldest active XID", 120, F::U32),
    ("Fake LSN for unlogged relations", 128, F::Lsn),
    ("Minimum recovery ending location", 136, F::Lsn),
    ("Minimum recovery ending timeline", 144, F::U32),
    ("Backup start location", 152, F::Lsn),
    ("Backup end location", 160, F::Lsn),
    ("End-of-backup record required", 168, F::Bool),
    ("wal_level", 172, F::Enum(WAL_LEVELS)),
    ("wal_log_hints", 176, F::Bool),
    ("max_connections", 180, F::I32),
    ("max_worker_processes", 184, F::I32),
    ("max_wal_senders", 188, F::I32),
    ("max_prepared_transactions", 192, F::I32),
    ("max_locks_per_transaction", 196, F::I32),
    ("track_commit_timestamp", 200, F::Bool),
    ("Maximum data alignment", 204, F::U32),
    ("Float format check", 208, F::Float),
    ("Block size", 216, F::U32),
    ("Blocks per relation segment", 220, F::U32),
    ("WAL block size", 224, F::U32),
    ("WAL segment size", 228, F::U32),
    ("Maximum identifier length", 232, F::U32),
    ("Maximum index columns", 236, F::U32),
    ("Maximum TOAST chunk size", 240, F::U32),
    ("Large object chunk size", 244, F::U32),
    ("float4 passed by value", 248, F::Bool),
    ("float8 passed by value", 249, F::Bool),
    ("Data checksum version", 252, F::U32),
];

/// PostgreSQL 11: a 32-bit epoch and XID, no `max_wal_senders`.
const FIELDS_11: &[(&str, usize, F)] = &[
    ("System identifier", 0, F::U64),
    ("Control file version", 8, F::U32),
    ("Catalog version", 12, F::U32),
    ("State", 16, F::Enum(STATES)),
    ("Last modified", 24, F::Time),
    ("Latest checkpoint", 32, F::Lsn),
    ("Checkpoint: REDO location", 40, F::Lsn),
    ("Checkpoint: timeline", 48, F::U32),
    ("Checkpoint: previous timeline", 52, F::U32),
    ("Checkpoint: full page writes", 56, F::Bool),
    ("Checkpoint: next XID", 60, F::XidEpoch),
    ("Checkpoint: next OID", 68, F::U32),
    ("Checkpoint: next MultiXactId", 72, F::U32),
    ("Checkpoint: next MultiXact offset", 76, F::U32),
    ("Checkpoint: oldest XID", 80, F::U32),
    ("Checkpoint: oldest XID's database", 84, F::U32),
    ("Checkpoint: oldest MultiXactId", 88, F::U32),
    ("Checkpoint: oldest MultiXact's database", 92, F::U32),
    ("Checkpoint: time", 96, F::Time),
    ("Checkpoint: oldest commit timestamp XID", 104, F::U32),
    ("Checkpoint: newest commit timestamp XID", 108, F::U32),
    ("Checkpoint: oldest active XID", 112, F::U32),
    ("Fake LSN for unlogged relations", 120, F::Lsn),
    ("Minimum recovery ending location", 128, F::Lsn),
    ("Minimum recovery ending timeline", 136, F::U32),
    ("Backup start location", 144, F::Lsn),
    ("Backup end location", 152, F::Lsn),
    ("End-of-backup record required", 160, F::Bool),
    ("wal_level", 164, F::Enum(WAL_LEVELS)),
    ("wal_log_hints", 168, F::Bool),
    ("max_connections", 172, F::I32),
    ("max_worker_processes", 176, F::I32),
    ("max_prepared_transactions", 180, F::I32),
    ("max_locks_per_transaction", 184, F::I32),
    ("track_commit_timestamp", 188, F::Bool),
    ("Maximum data alignment", 192, F::U32),
    ("Float format check", 200, F::Float),
    ("Block size", 208, F::U32),
    ("Blocks per relation segment", 212, F::U32),
    ("WAL block size", 216, F::U32),
    ("WAL segment size", 220, F::U32),
    ("Maximum identifier length", 224, F::U32),
    ("Maximum index columns", 228, F::U32),
    ("Maximum TOAST chunk size", 232, F::U32),
    ("Large object chunk size", 236, F::U32),
    ("float4 passed by value", 240, F::Bool),
    ("float8 passed by value", 241, F::Bool),
    ("Data checksum version", 244, F::U32),
];

/// PostgreSQL 10: as 11, with the prior checkpoint.
const FIELDS_10: &[(&str, usize, F)] = &[
    ("System identifier", 0, F::U64),
    ("Control file version", 8, F::U32),
    ("Catalog version", 12, F::U32),
    ("State", 16, F::Enum(STATES)),
    ("Last modified", 24, F::Time),
    ("Latest checkpoint", 32, F::Lsn),
    ("Prior checkpoint", 40, F::Lsn),
    ("Checkpoint: REDO location", 48, F::Lsn),
    ("Checkpoint: timeline", 56, F::U32),
    ("Checkpoint: previous timeline", 60, F::U32),
    ("Checkpoint: full page writes", 64, F::Bool),
    ("Checkpoint: next XID", 68, F::XidEpoch),
    ("Checkpoint: next OID", 76, F::U32),
    ("Checkpoint: next MultiXactId", 80, F::U32),
    ("Checkpoint: next MultiXact offset", 84, F::U32),
    ("Checkpoint: oldest XID", 88, F::U32),
    ("Checkpoint: oldest XID's database", 92, F::U32),
    ("Checkpoint: oldest MultiXactId", 96, F::U32),
    ("Checkpoint: oldest MultiXact's database", 100, F::U32),
    ("Checkpoint: time", 104, F::Time),
    ("Checkpoint: oldest commit timestamp XID", 112, F::U32),
    ("Checkpoint: newest commit timestamp XID", 116, F::U32),
    ("Checkpoint: oldest active XID", 120, F::U32),
    ("Fake LSN for unlogged relations", 128, F::Lsn),
    ("Minimum recovery ending location", 136, F::Lsn),
    ("Minimum recovery ending timeline", 144, F::U32),
    ("Backup start location", 152, F::Lsn),
    ("Backup end location", 160, F::Lsn),
    ("End-of-backup record required", 168, F::Bool),
    ("wal_level", 172, F::Enum(WAL_LEVELS)),
    ("wal_log_hints", 176, F::Bool),
    ("max_connections", 180, F::I32),
    ("max_worker_processes", 184, F::I32),
    ("max_prepared_transactions", 188, F::I32),
    ("max_locks_per_transaction", 192, F::I32),
    ("track_commit_timestamp", 196, F::Bool),
    ("Maximum data alignment", 200, F::U32),
    ("Float format check", 208, F::Float),
    ("Block size", 216, F::U32),
    ("Blocks per relation segment", 220, F::U32),
    ("WAL block size", 224, F::U32),
    ("WAL segment size", 228, F::U32),
    ("Maximum identifier length", 232, F::U32),
    ("Maximum index columns", 236, F::U32),
    ("Maximum TOAST chunk size", 240, F::U32),
    ("Large object chunk size", 244, F::U32),
    ("float4 passed by value", 248, F::Bool),
    ("float8 passed by value", 249, F::Bool),
    ("Data checksum version", 252, F::U32),
];

fn size_of(f: F) -> u64 {
    match f {
        F::U32 | F::I32 | F::Enum(_) => 4,
        F::U64 | F::Lsn | F::Time | F::Float | F::Xid64 | F::XidEpoch => 8,
        F::Bool => 1,
    }
}

fn field(b: &[u8], span: Span, name: &'static str, at: usize, f: F) -> Node {
    let n = Node::new(name).span(span.sub(crate::bytes::to_u64(at), size_of(f)));
    let u32_at = u32_le(b, at).unwrap_or(0);
    let u64_at = u64_le(b, at).unwrap_or(0);
    match f {
        F::U32 => n.value(uint(u32_at, 32)),
        F::I32 => n.value(Value::Int {
            value: i64::from(i32::from_le_bytes(u32_at.to_le_bytes())),
            bits: 32,
        }),
        F::U64 => n.value(uint(u64_at, 64)),
        F::Lsn => n.value(hex(u64_at, 64)).summary(lsn(u64_at)),
        F::Time => n.value(Value::utc(i64::from_le_bytes(u64_at.to_le_bytes()))),
        F::Bool => n.value(Value::Bool(b.get(at).copied().unwrap_or(0) != 0)),
        F::Enum(t) => n.value(Value::Enum {
            raw: u32_at.into(),
            bits: 32,
            name: lookup(t, u32_at.into()).map(Into::into),
        }),
        F::Float => {
            let v = f64::from_bits(u64_at);
            let n = n.value(Value::f64(v));
            if v == 1_234_567.0 {
                n.summary("1234567.0: IEEE doubles, this byte order")
            } else {
                n.diag(Diagnostic::warning(
                    "not 1234567.0: written by a machine with another float format",
                ))
            }
        }
        F::Xid64 => {
            n.value(uint(u64_at, 64))
                .summary(format!("{}:{}", u64_at >> 32, u64_at & 0xffff_ffff))
        }
        F::XidEpoch => {
            let xid = u32_le(b, at.saturating_add(4)).unwrap_or(0);
            n.value(uint(xid, 32))
                .summary(format!("{u32_at}:{xid} (epoch:XID)"))
        }
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let b = cx.read(file.sub(0, 512)).await?;
    let version = u32_le(&b, 8).unwrap_or(0);
    let Some(crc) = crc_at(version) else {
        return Err(
            Diagnostic::unsupported(format!("control file version {version}")).at(file.sub(8, 4)),
        );
    };
    for &(name, at, f) in fields(version) {
        cx.emit(field(&b, file, name, at, f));
    }
    let nonce_at = if version == 1100 {
        248u64
    } else if version >= 1800 {
        cx.emit(
            Node::new("Default char signedness")
                .span(file.sub(256, 1))
                .value(Value::Bool(b.get(256).copied().unwrap_or(0) != 0)),
        );
        257u64
    } else {
        256
    };
    cx.emit(
        Node::new("Mock authentication nonce")
            .span(file.sub(nonce_at, 32))
            .value(Value::Bytes(
                b.get(to_usize(nonce_at)..to_usize(nonce_at).saturating_add(32))
                    .unwrap_or_default()
                    .to_vec(),
            )),
    );
    let stored = u32_le(&b, crc).unwrap_or(0);
    let computed = crc32c(b.get(..crc).unwrap_or_default());
    cx.emit(
        Node::new("CRC")
            .span(file.sub(crate::bytes::to_u64(crc), 4))
            .checksum(Check::new("CRC-32C", stored).verify(computed)),
    );
    let end = crate::bytes::to_u64(crc).saturating_add(4);
    cx.emit(
        Node::new("Padding")
            .span(file.tail(end))
            .summary("zero to 8 KiB"),
    );
    let state = u32_le(&b, 16).unwrap_or(0);
    let id = u64_le(&b, 0).unwrap_or(0);
    cx.annotate(format!(
        "PostgreSQL control file ({}, version {version}), system {id}, {}, checkpoint at {}",
        release(version),
        lookup(STATES, state.into()).unwrap_or("unknown state"),
        lsn(u64_le(&b, 32).unwrap_or(0))
    ));
    Ok(())
}
