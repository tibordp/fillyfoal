//! Embedded databases: Tokyo Cabinet, Kyoto Cabinet, GDBM, RRDtool,
//! WiredTiger and Realm.

use crate::bytes::{u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::plural;
use crate::formats::util::val::{text, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::value::Value;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

use crate::formats::text::scan::head_lines as lines;

// ---------------------------------------------------------------------------
// Embedded databases: Tokyo Cabinet, Kyoto Cabinet, GDBM, RRDtool,
// WiredTiger, Realm

declare_format!(pub TOKYO = "tokyo-cabinet", "Tokyo Cabinet database", ["tch", "tcb", "tcf", "tct"], "application/x-tokyo-cabinet",
    Probe::Magic(&[(0, b"ToKyO CaBiNeT\n")]), tokyo);

async fn tokyo(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 64)).await?;
    let version = zstr(head.get(14..32).unwrap_or_default());
    let kind = head.get(32).copied().unwrap_or(0);
    let kind_name = match kind {
        0 => "hash",
        1 => "B+ tree",
        2 => "fixed-length",
        3 => "table",
        _ => "unknown",
    };
    cx.emit(Node::new("Signature").span(file.sub(0, 14)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(14, 18))
            .value(text(version.clone())),
    );
    cx.emit(Node::new("Type").span(file.sub(32, 1)).value(Value::Enum {
        raw: kind.into(),
        bits: 8,
        name: Some(kind_name.into()),
    }));
    let records = u64_le(&head, 48).unwrap_or(0);
    let size = u64_le(&head, 56).unwrap_or(0);
    cx.emit(
        Node::new("Buckets")
            .span(file.sub(40, 8))
            .value(uint(u64_le(&head, 40).unwrap_or(0), 64)),
    );
    cx.emit(
        Node::new("Records")
            .span(file.sub(48, 8))
            .value(uint(records, 64)),
    );
    cx.emit(
        Node::new("File size")
            .span(file.sub(56, 8))
            .value(uint(size, 64)),
    );
    cx.emit(Node::new("Body").span(file.tail(256)));
    cx.annotate(format!(
        "Tokyo Cabinet {kind_name} database {version}, {records_record}",
        records_record = plural(records, "record")
    ));
    Ok(())
}

declare_format!(pub KYOTO = "kyoto-cabinet", "Kyoto Cabinet database", ["kch", "kct"], "application/x-kyoto-cabinet",
    Probe::Magic(&[(0, b"KC\n\0")]), kyoto);

async fn kyoto(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 64)).await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Library version")
            .span(file.sub(4, 1))
            .value(uint(head.get(4).copied().unwrap_or(0), 8)),
    );
    cx.emit(
        Node::new("Library revision")
            .span(file.sub(5, 1))
            .value(uint(head.get(5).copied().unwrap_or(0), 8)),
    );
    cx.emit(
        Node::new("Format version")
            .span(file.sub(6, 1))
            .value(uint(head.get(6).copied().unwrap_or(0), 8)),
    );
    let kind = head.get(8).copied().unwrap_or(0);
    let kind_name = match kind {
        0x31 => "hash",
        0x32 => "B+ tree",
        _ => "unknown",
    };
    cx.emit(Node::new("Type").span(file.sub(8, 1)).value(Value::Enum {
        raw: kind.into(),
        bits: 8,
        name: Some(kind_name.into()),
    }));
    cx.emit(Node::new("Body").span(file.tail(64)));
    cx.annotate(format!("Kyoto Cabinet {kind_name} database"));
    Ok(())
}

/// GDBM header magics (gdbmconst.h): the original format (offsets as wide
/// as the writer's `off_t`), 32- and 64-bit offsets, and the extended
/// ("numsync", gdbm 1.21+) variants of those two.
const GDBM_OMAGIC: u32 = 0x1357_9ace;
const GDBM_MAGIC32: u32 = 0x1357_9acd;
const GDBM_MAGIC64: u32 = 0x1357_9acf;
const GDBM_NUMSYNC32: u32 = 0x1357_9ad0;
const GDBM_NUMSYNC64: u32 = 0x1357_9ad1;

fn gdbm_probe(h: &Head<'_>) -> bool {
    let m = |v: u32| (GDBM_MAGIC32..=GDBM_NUMSYNC64).contains(&v);
    u32_le(h.data, 0).is_some_and(m) || u32_be(h.data, 0).is_some_and(m)
}

declare_format!(pub GDBM = "gdbm", "GNU dbm database", ["gdbm", "db"], "application/x-gdbm",
    Probe::Custom(gdbm_probe), gdbm);

type ReadU32 = fn(&[u8], usize) -> Option<u32>;

/// The directory size implied by `bits` for `off_t` of `width` bytes.
fn gdbm_dir_size(bits: u32, width: u64) -> Option<u64> {
    (bits < 31).then(|| (1u64 << bits).saturating_mul(width))
}

/// Whether the `dir_size`, `dir_bits` pair at `at` is consistent for `off_t`
/// of `width` bytes.
fn gdbm_dir_fits(head: &[u8], at: usize, width: u64, read: ReadU32) -> bool {
    match (read(head, at), read(head, at.saturating_add(4))) {
        (Some(size), Some(bits)) => gdbm_dir_size(bits, width) == Some(size.into()),
        _ => false,
    }
}

/// GDBM file header (gdbmdefs.h `gdbm_file_header`): `int` fields and two
/// `off_t` offsets (`dir`, `next_block`), then for the numsync magics the
/// extended header (`gdbm_ext_header`), then the header's avail block.
async fn gdbm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 32)).await?;
    let little = u32_le(&head, 0).is_some_and(|v| v >> 12 == 0x1_3579);
    let (endian, read): (Endian, ReadU32) = if little { (LE, u32_le) } else { (BE, u32_be) };
    let magic = read(&head, 0).unwrap_or(0);
    let wide = match magic {
        GDBM_MAGIC64 | GDBM_NUMSYNC64 => true,
        GDBM_MAGIC32 | GDBM_NUMSYNC32 => false,
        // The original magic was written with the platform's `off_t`; take
        // the layout whose directory size agrees with its directory bits.
        _ => gdbm_dir_fits(&head, 16, 8, read) && !gdbm_dir_fits(&head, 12, 4, read),
    };
    let numsync = matches!(magic, GDBM_NUMSYNC32 | GDBM_NUMSYNC64);
    let width: u64 = if wide { 8 } else { 4 };
    let block = cx.block(file.sub(0, 96)).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.u32("Magic").hex().emit()?;
    let block_size = f.u32("Block size").emit()?;
    f.uword("Directory offset", wide).hex().emit()?;
    let bits_at = usize::try_from(f.pos().saturating_add(4)).unwrap_or(usize::MAX);
    let bits = read(&head, bits_at).unwrap_or(0);
    f.u32("Directory size")
        .desc("Bytes in the hash directory (2^bits offsets)")
        .check(|&v| {
            (gdbm_dir_size(bits, width) != Some(v.into())).then(|| {
                Diagnostic::warning(format!(
                    "directory size {v} does not match {bits} directory bits"
                ))
            })
        })
        .emit()?;
    f.u32("Directory bits").emit()?;
    f.u32("Bucket size").emit()?;
    let elems = f.u32("Bucket elements").emit()?;
    f.uword("Next block", wide)
        .hex()
        .desc("End of the allocated blocks")
        .emit()?;
    if numsync {
        f.u32("Extension version").emit()?;
        f.u32("Sync count")
            .desc("Number of synchronizations (numsync)")
            .emit()?;
        f.bytes("Padding", 24).emit()?;
    }
    f.u32("Avail table size")
        .desc("Capacity of the header's avail table")
        .emit()?;
    f.u32("Avail count")
        .desc("Free areas listed in the header")
        .emit()?;
    f.uword("Avail next block", wide).hex().emit()?;
    let variant = match magic {
        GDBM_OMAGIC if wide => "original, 64-bit offsets",
        GDBM_OMAGIC => "original, 32-bit offsets",
        GDBM_MAGIC32 => "32-bit offsets",
        GDBM_NUMSYNC32 => "extended, 32-bit offsets",
        GDBM_NUMSYNC64 => "extended, 64-bit offsets",
        _ => "64-bit offsets",
    };
    cx.emit(Node::new("Blocks").span(file.tail(u64::from(block_size).min(file.len))));
    cx.annotate(format!(
        "GDBM ({variant}), {block_size}-byte blocks, {bits} directory bits, {elems} per bucket"
    ));
    Ok(())
}

declare_format!(pub RRD = "rrdtool", "RRDtool round-robin database", ["rrd"], "application/x-rrd",
    Probe::Magic(&[(0, b"RRD\0")]), rrd);

async fn rrd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // The 64-bit layout: cookie[4], version[5], (pad), double float cookie at
    // 16, ds_cnt, rra_cnt, pdp_step as 8-byte longs, 10 × 8-byte params.
    let head = cx.read(file.sub(0, 128)).await?;
    let version = zstr(head.get(4..9).unwrap_or_default());
    let cookie = f64::from_le_bytes(
        head.get(16..24)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 8]),
    );
    if (cookie - 8.642_135e130).abs() > 1e125 {
        return Err(Diagnostic::unsupported(
            "not a little-endian 64-bit RRD (float cookie mismatch)",
        )
        .at(file.sub(16, 8)));
    }
    let ds = u64_le(&head, 24).unwrap_or(0);
    let rra = u64_le(&head, 32).unwrap_or(0);
    let step = u64_le(&head, 40).unwrap_or(0);
    cx.emit(Node::new("Cookie").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 5))
            .value(text(version.clone())),
    );
    cx.emit(
        Node::new("Float cookie")
            .span(file.sub(16, 8))
            .value(Value::f64(cookie)),
    );
    cx.emit(
        Node::new("Data sources")
            .span(file.sub(24, 8))
            .value(uint(ds, 64)),
    );
    cx.emit(
        Node::new("Archives")
            .span(file.sub(32, 8))
            .value(uint(rra, 64)),
    );
    cx.emit(
        Node::new("Step (s)")
            .span(file.sub(40, 8))
            .value(uint(step, 64)),
    );
    let mut pos = 128u64;
    for _ in 0..ds.min(256) {
        let d = cx.read(file.sub_exact(pos, 120)?).await?;
        let name = zstr(d.get(..20).unwrap_or_default());
        let kind = zstr(d.get(20..40).unwrap_or_default());
        cx.push(
            Node::new(format!("DS {name}"))
                .span(file.sub(pos, 120))
                .summary(kind),
        )
        .await;
        pos = pos.saturating_add(120);
    }
    for _ in 0..rra.min(256) {
        let d = cx.read(file.sub_exact(pos, 120)?).await?;
        let cf = zstr(d.get(..20).unwrap_or_default());
        let rows = u64_le(&d, 24).unwrap_or(0);
        let pdp = u64_le(&d, 32).unwrap_or(0);
        cx.push(
            Node::new(format!("RRA {cf}"))
                .span(file.sub(pos, 120))
                .summary(format!(
                    "{rows_row} × {} s",
                    pdp.saturating_mul(step),
                    rows_row = plural(rows, "row")
                )),
        )
        .await;
        pos = pos.saturating_add(120);
    }
    cx.emit(Node::new("Live data and archives").span(file.tail(pos)));
    cx.annotate(format!(
        "RRD v{version}, {ds} data sources, {rra} archives, step {step} s"
    ));
    Ok(())
}

declare_format!(pub WIREDTIGER = "wiredtiger", "WiredTiger database marker", [], "text/x-wiredtiger",
    Probe::Magic(&[(0, b"WiredTiger\nWiredTiger ")]), wiredtiger);

async fn wiredtiger(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 4096).await?;
    let mut version = String::new();
    for (line, span) in all.iter().take(2) {
        if let Some(v) = line.strip_prefix("WiredTiger ") {
            version = v.to_owned();
        }
        cx.emit(Node::new("Line").span(*span).value(text(line.clone())));
    }
    cx.annotate(format!("WiredTiger {version}"));
    Ok(())
}

fn realm_probe(h: &Head<'_>) -> bool {
    h.at(16, b"T-DB")
}

declare_format!(pub REALM = "realm", "Realm database", ["realm"], "application/x-realm",
    Probe::Custom(realm_probe), realm);

async fn realm(cx: Cx, input: Input) -> Result<()> {
    crate::formats::data::realm::dissect(cx, input).await
}
