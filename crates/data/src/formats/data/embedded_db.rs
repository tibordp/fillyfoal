//! Embedded databases: Tokyo Cabinet, Kyoto Cabinet, GDBM, RRDtool,
//! WiredTiger and Realm.

use crate::bytes::{u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::value::{Radix, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

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
        name: Some(kind_name),
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
        "Tokyo Cabinet {kind_name} database {version}, {records} records"
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
            .value(uint(head.get(4).copied().unwrap_or(0).into(), 8)),
    );
    cx.emit(
        Node::new("Library revision")
            .span(file.sub(5, 1))
            .value(uint(head.get(5).copied().unwrap_or(0).into(), 8)),
    );
    cx.emit(
        Node::new("Format version")
            .span(file.sub(6, 1))
            .value(uint(head.get(6).copied().unwrap_or(0).into(), 8)),
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
        name: Some(kind_name),
    }));
    cx.emit(Node::new("Body").span(file.tail(64)));
    cx.annotate(format!("Kyoto Cabinet {kind_name} database"));
    Ok(())
}

fn gdbm_probe(h: &Head<'_>) -> bool {
    let m = |v: u32| (0x1357_9acd..=0x1357_9acf).contains(&v);
    u32_le(h.data, 0).is_some_and(m) || u32_be(h.data, 0).is_some_and(m)
}

declare_format!(pub GDBM = "gdbm", "GNU dbm database", ["gdbm", "db"], "application/x-gdbm",
    Probe::Custom(gdbm_probe), gdbm);

async fn gdbm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 4)).await?;
    let endian = if u32_le(&head, 0).is_some_and(|v| v >> 8 == 0x13_579a) {
        LE
    } else {
        BE
    };
    let block = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    let magic = f.u32("Magic").hex().emit()?;
    let block_size = f.u32("Block size").emit()?;
    f.u32("Directory offset").hex().emit()?;
    f.u32("Directory size").emit()?;
    let bits = f.u32("Directory bits").emit()?;
    f.u32("Bucket size").emit()?;
    let elems = f.u32("Bucket elements").emit()?;
    f.u32("Next block").hex().emit()?;
    let variant = match magic & 0xf {
        0xe => "standard",
        0xd => "32-bit offsets",
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
            .value(Value::Float(cookie)),
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
                .summary(format!("{rows} rows × {} s", pdp.saturating_mul(step))),
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
