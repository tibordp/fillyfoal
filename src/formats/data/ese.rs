//! Extensible Storage Engine (ESE, "JET Blue") databases.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, emit_record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::{EnumTable, Radix, Value, lookup};

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// ESE (JET Blue) databases

fn ese_probe(h: &Head<'_>) -> bool {
    h.at(4, b"\xef\xcd\xab\x89")
}

declare_format!(pub ESE = "ese", "Extensible Storage Engine database", ["edb", "dat", "sdb"], "application/x-ese",
    Probe::Custom(ese_probe), ese);

const ESE_STATES: EnumTable = &[
    (1, "just created"),
    (2, "dirty shutdown"),
    (3, "clean shutdown"),
    (4, "being converted"),
    (5, "force detach"),
];

record! {
    pub struct EseHeader {
        checksum: u32 "Checksum" .hex(),
        signature: u32 "Signature" .hex(),
        version: u32 "Format version" .hex(),
        file_type: u32 "File type" .enumeration(&[(0, "database"), (1, "streaming file")]),
        db_time: u64 "Database time",
        db_signature: bytes[28] "Database signature",
        state: u32 "Database state" .enumeration(ESE_STATES),
    }
}

async fn ese(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: EseHeader = emit_record(&cx, file.sub(0, EseHeader::SIZE), LE).await?;
    let more = cx.read_avail(file.sub(0xe8, 12)).await?;
    let revision = u32_le(&more, 0).unwrap_or(0);
    let page_size = u32_le(&cx.read_avail(file.sub(0xec, 4)).await?, 0).unwrap_or(0);
    cx.emit(
        Node::new("Page size")
            .span(file.sub(0xec, 4))
            .value(Value::UInt {
                value: page_size.into(),
                bits: 32,
                radix: Radix::Dec,
            }),
    );
    cx.emit(Node::new("Pages").span(file.tail(u64::from(page_size).saturating_mul(2))));
    let state = lookup(ESE_STATES, h.state.into()).unwrap_or("unknown state");
    cx.annotate(format!(
        "ESE database v{:#x} rev {revision}, {} KiB pages, {state}",
        h.version,
        page_size / 1024
    ));
    Ok(())
}
