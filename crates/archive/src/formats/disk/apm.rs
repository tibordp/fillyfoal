//! Apple Partition Map: a driver descriptor block (`ER`) followed by one
//! partition map entry (`PM`) per block, as on classic Mac disks and
//! hybrid CDs.

use crate::bytes::u16_be;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{size, volume};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const BE: Endian = Endian::Big;
/// Partition entries followed before assuming corruption.
const MAX_ENTRIES: u32 = 256;

pub static FORMAT: Format = Format {
    name: "apm",
    title: "Apple partition map disk image",
    extensions: &["img", "dmg", "toast", "hfs"],
    mime: "application/x-apple-diskimage",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let block = u16_be(h.data, 2).unwrap_or(0);
    h.starts_with(b"ER")
        && matches!(block, 512 | 1024 | 2048 | 4096)
        && h.at(usize::from(block), b"PM")
}

record! {
    /// Block 0: the driver descriptor map.
    pub struct Ddm {
        signature: ascii[2] "Signature",
        block_size: u16 "Block size",
        block_count: u32 "Block count",
        device_type: u16 "Device type",
        device_id: u16 "Device id",
        data: u32 "Reserved data",
        drivers: u16 "Driver count",
    }
}

const STATUS: FlagTable = &[
    flag(0x001, "VALID"),
    flag(0x002, "ALLOCATED"),
    flag(0x004, "IN_USE"),
    flag(0x008, "BOOTABLE"),
    flag(0x010, "READABLE"),
    flag(0x020, "WRITABLE"),
    flag(0x040, "POSITION_INDEPENDENT"),
    flag(0x100, "CHAIN_COMPATIBLE"),
    flag(0x200, "REAL_DRIVER"),
    flag(0x400, "CHAIN_DRIVER"),
    flag(0x40000000, "AUTO_MOUNT"),
    flag(0x80000000, "STARTUP"),
];

record! {
    /// A partition map entry.
    pub struct Entry {
        signature: ascii[2] "Signature",
        _pad: u16 "Padding",
        map_entries: u32 "Entries in the map",
        start: u32 "First block",
        blocks: u32 "Blocks",
        name: ascii[32] "Name",
        kind: ascii[32] "Type",
        data_start: u32 "First data block",
        data_blocks: u32 "Data blocks",
        status: u32 "Status" .hex() .flags(STATUS),
        boot_start: u32 "Boot code block",
        boot_size: u32 "Boot code size",
        boot_addr: u32 "Boot load address" .hex(),
        _boot_addr2: u32 "Reserved",
        boot_entry: u32 "Boot entry point" .hex(),
        _boot_entry2: u32 "Reserved",
        boot_checksum: u32 "Boot code checksum" .hex(),
        processor: ascii[16] "Processor",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let disk = input.span;
    let ddm = parse(&cx, disk.sub(0, Ddm::SIZE), BE, &(), Ddm::layout).await?;
    let block = u64::from(ddm.block_size);
    cx.emit(Ddm::node("Driver descriptor map", disk.sub(0, block), BE));
    let first = disk.sub(block, Entry::SIZE);
    let head = parse(&cx, first, BE, &(), Entry::layout).await?;
    let count = head.map_entries.min(MAX_ENTRIES);
    cx.annotate(format!(
        "Apple partition map, {count} entries, {}-byte blocks, {}",
        block,
        size(u64::from(ddm.block_count).saturating_mul(block))
    ));
    for i in 1..=u64::from(count) {
        let span = disk.sub(i.saturating_mul(block), Entry::SIZE);
        let e = parse(&cx, span, BE, &(), Entry::layout).await?;
        if e.signature != "PM" {
            cx.diag(Diagnostic::malformed(format!("entry {i} has no PM signature")).at(span));
            break;
        }
        let data = disk.sub(
            u64::from(e.start).saturating_mul(block),
            u64::from(e.blocks).saturating_mul(block),
        );
        let label = if e.name.is_empty() {
            e.kind.clone()
        } else {
            e.name.clone()
        };
        cx.push(
            Node::new(format!("Partition {i}: {label}"))
                .span(span)
                .summary(format!(
                    "{}, {} at block {}",
                    e.kind,
                    size(data.len),
                    e.start
                ))
                .lazy(
                    partition,
                    (
                        input,
                        span,
                        data,
                        e.kind == "Apple_partition_map" || e.kind == "Apple_Free",
                    ),
                ),
        )
        .await;
    }
    Ok(())
}

async fn partition(cx: Cx, (input, entry, data, plain): (Input, Span, Span, bool)) -> Result<()> {
    cx.emit(Entry::node("Entry", entry, BE));
    cx.emit(if plain {
        Node::new("Data").span(data)
    } else {
        volume("Volume", &input, data)
    });
    Ok(())
}
