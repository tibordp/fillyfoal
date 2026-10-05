//! Master Boot Record partition tables, including extended partitions (the
//! EBR chain) and the protective MBR of GPT disks.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::ptypes::{MBR_TYPES, is_extended};
use crate::formats::disk::{size, volume};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const LE: Endian = Endian::Little;
pub const SECTOR: u64 = 512;
/// Offset of the partition table in the sector.
const TABLE: u64 = 446;
/// Longest EBR chain we follow.
const MAX_LOGICAL: usize = 256;

pub static FORMAT: Format = Format {
    name: "mbr",
    title: "MBR partitioned disk image",
    extensions: &["img", "raw", "dd", "bin", "hdd"],
    mime: "application/x-raw-disk-image",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const STATUS: EnumTable = &[(0x00, "inactive"), (0x80, "active (bootable)")];

record! {
    /// A 16-byte partition table entry.
    pub struct Entry {
        status: u8 "Boot indicator" .enumeration(STATUS),
        chs_first: bytes[3] "First sector (CHS)" .with(chs),
        kind: u8 "Partition type" .enumeration(MBR_TYPES),
        chs_last: bytes[3] "Last sector (CHS)" .with(chs),
        lba: u32 "First sector (LBA)",
        sectors: u32 "Sectors" .with(|&n, node| node.summary(size(u64::from(n).saturating_mul(SECTOR)))),
    }
}

#[allow(clippy::ptr_arg)] // used as a `Field::with` decorator
fn chs(b: &Vec<u8>, node: Node) -> Node {
    let get = |i: usize| u16::from(b.get(i).copied().unwrap_or(0));
    let head = get(0);
    let sector = get(1) & 0x3f;
    let cylinder = ((get(1) & 0xc0) << 2) | get(2);
    node.summary(format!("C/H/S {cylinder}/{head}/{sector}"))
}

/// Partition entries of a sector, as raw `(status, type, lba, sectors)`.
fn raw_entries(sector: &[u8]) -> impl Iterator<Item = (u8, u8, u32, u32)> + '_ {
    (0..4usize).filter_map(move |i| {
        let at = 446usize.saturating_add(i.saturating_mul(16));
        let e = sector.get(at..at.saturating_add(16))?;
        Some((*e.first()?, *e.get(4)?, u32_le(e, 8)?, u32_le(e, 12)?))
    })
}

/// A sector looks like a partition table: boot signature, sane status
/// bytes, at least one used entry, and no entry overlapping the MBR itself.
pub fn looks_like_mbr(sector: &[u8]) -> bool {
    if u16_le(sector, 510) != Some(0xaa55) {
        return false;
    }
    let mut used = 0u8;
    for (status, kind, lba, sectors) in raw_entries(sector) {
        if status != 0 && status != 0x80 {
            return false;
        }
        if kind != 0 {
            if lba == 0 || sectors == 0 {
                return false;
            }
            used = 1;
        }
    }
    used > 0
}

fn probe(h: &Head<'_>) -> bool {
    // Hybrid ISO images are better shown as ISO 9660.
    looks_like_mbr(h.data) && !h.at(0x8001, b"CD001")
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let disk = input.span;
    let sector = cx.read(disk.sub(0, SECTOR)).await?;
    let entries: Vec<_> = raw_entries(&sector).collect();
    let used = entries.iter().filter(|e| e.1 != 0).count();
    let protective = entries.iter().any(|e| e.1 == 0xee);
    cx.annotate(if protective {
        "Protective MBR (GPT disk)".to_owned()
    } else {
        format!(
            "MBR partition table, {used} primary partition{}, {}",
            if used == 1 { "" } else { "s" },
            size(disk.len)
        )
    });

    let boot = disk.sub(0, 440);
    let code = Node::new("Bootstrap code").span(boot);
    cx.emit(
        if sector.get(..440).is_some_and(|b| b.iter().all(|&x| x == 0)) {
            code.summary("empty")
        } else {
            code
        },
    );
    if let Some(sig) = u32_le(&sector, 440) {
        cx.emit(
            Node::new("Disk signature")
                .span(disk.sub(440, 4))
                .value(Value::UInt {
                    value: sig.into(),
                    bits: 32,
                    radix: Radix::Hex,
                }),
        );
    }
    for (i, e) in entries.iter().enumerate() {
        let span = disk.sub(TABLE.saturating_add(to_u64(i).saturating_mul(16)), 16);
        let number = i.saturating_add(1);
        if e.1 == 0 {
            continue;
        }
        cx.emit(partition(format!("Partition {number}"), &input, span, 0, 0));
    }
    if protective {
        cx.diag(Diagnostic::note(
            "type 0xEE: this MBR only protects a GPT; the GPT header was not found",
        ));
    }
    cx.emit(
        Node::new("Boot signature")
            .span(disk.sub(510, 2))
            .value(Value::UInt {
                value: u16_le(&sector, 510).unwrap_or(0).into(),
                bits: 16,
                radix: Radix::Hex,
            }),
    );
    Ok(())
}

/// State of a partition node: where its entry is, and the LBA its start is
/// relative to (0 for primary entries, the EBR for logical ones). `ext_base`
/// is the start of the outermost extended partition (EBR links are relative
/// to it).
#[derive(Clone, Copy)]
struct Part {
    input: Input,
    entry: Span,
    base: u64,
    ext_base: u64,
}

fn partition(name: String, input: &Input, entry: Span, base: u64, ext_base: u64) -> Node {
    Node::new(name).span(entry).lazy(
        expand_partition,
        Part {
            input: *input,
            entry,
            base,
            ext_base,
        },
    )
}

/// Summary for a partition entry, e.g. `Linux (0x83), 32 KiB at LBA 64`.
fn describe(e: &Entry, base: u64) -> String {
    let name = lookup(MBR_TYPES, e.kind.into()).unwrap_or("unknown");
    let active = if e.status == 0x80 { ", active" } else { "" };
    format!(
        "{name} ({:#04x}), {} at LBA {}{active}",
        e.kind,
        size(u64::from(e.sectors).saturating_mul(SECTOR)),
        base.saturating_add(e.lba.into())
    )
}

async fn expand_partition(cx: Cx, p: Part) -> Result<()> {
    let e = parse(&cx, p.entry, LE, &(), Entry::layout).await?;
    cx.annotate(describe(&e, p.base));
    cx.emit(Entry::node("Entry", p.entry, LE));
    let disk = p.input.span;
    let start = p.base.saturating_add(e.lba.into()).saturating_mul(SECTOR);
    let len = u64::from(e.sectors).saturating_mul(SECTOR);
    let span = disk.sub(start, len);
    if is_extended(e.kind) && p.ext_base != 0 {
        cx.diag(Diagnostic::malformed(
            "nested extended partition inside an EBR",
        ));
        return Ok(());
    }
    if p.ext_base != 0 && e.lba == 0 {
        cx.diag(Diagnostic::malformed("logical partition overlaps its EBR"));
        return Ok(());
    }
    if is_extended(e.kind) {
        let first = p.base.saturating_add(e.lba.into());
        let ext_base = if p.ext_base == 0 { first } else { p.ext_base };
        cx.emit(
            Node::new("Logical partitions")
                .span(span)
                .lazy(logical_partitions, (p.input, first, ext_base)),
        );
        return Ok(());
    }
    let mut node = volume("Volume", &p.input, span);
    if span.len < len {
        node = node.diag(Diagnostic::truncated(
            Span::new(disk.source, disk.offset.saturating_add(start), len),
            span.len,
        ));
    }
    cx.emit(node);
    Ok(())
}

/// Walks the EBR chain of an extended partition starting at LBA `first`.
async fn logical_partitions(cx: Cx, (input, first, ext_base): (Input, u64, u64)) -> Result<()> {
    let disk = input.span;
    let mut visited: Vec<u64> = Vec::new();
    let mut lba = first;
    let mut number = 5usize;
    loop {
        if visited.contains(&lba) {
            cx.diag(Diagnostic::malformed(format!(
                "EBR chain loops back to LBA {lba}"
            )));
            break;
        }
        if visited.len() >= MAX_LOGICAL {
            cx.diag(Diagnostic::limit(format!(
                "more than {MAX_LOGICAL} logical partitions"
            )));
            break;
        }
        visited.push(lba);
        let at = lba.saturating_mul(SECTOR);
        let ebr = disk.sub(at, SECTOR);
        let sector = cx.read(ebr).await?;
        if u16_le(&sector, 510) != Some(0xaa55) {
            cx.diag(Diagnostic::malformed("EBR without boot signature").at(ebr));
            break;
        }
        let entries: Vec<_> = raw_entries(&sector).collect();
        if let Some(&(_, kind, _, _)) = entries.first()
            && kind != 0
        {
            let entry = ebr.sub(TABLE, 16);
            cx.push(
                partition(format!("Partition {number}"), &input, entry, lba, ext_base).target(ebr),
            )
            .await;
            number = number.saturating_add(1);
        }
        match entries.get(1) {
            Some(&(_, kind, next, _)) if is_extended(kind) && next != 0 => {
                lba = ext_base.saturating_add(next.into());
            }
            _ => break,
        }
    }
    Ok(())
}
