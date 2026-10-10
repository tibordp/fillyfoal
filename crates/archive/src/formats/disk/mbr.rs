//! Master Boot Record partition tables, including extended partitions (the
//! EBR chain) and the protective (or hybrid) MBR of GPT disks.
//!
//! Sector 0 holds 446 bytes of boot code (the last six of which, in modern
//! MBRs, are a disk signature and a copy-protection word), four 16-byte
//! partition entries and the 0x55AA signature. An extended partition holds
//! a chain of extended boot records, each describing one logical partition
//! and linking to the next. A disk layout node accounts for the space
//! between partitions.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::ptypes::{MBR_TYPES, is_extended};
use crate::formats::disk::{size, volume};
use crate::formats::util::fmt::plural;
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
/// Gaps up to this size are read to tell whether they are blank.
const MAX_GAP_CHECK: u64 = 1 << 20;

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

/// Boot code signatures, by a string they contain.
const BOOT_CODES: &[(&[u8], &str)] = &[
    (b"GRUB ", "GRUB"),
    (b"ISOLINUX", "ISOLINUX"),
    (b"SYSLINUX", "SYSLINUX"),
    (b"Invalid partition table", "Microsoft"),
    (b"LILO", "LILO"),
    (b"isolinux.bin missing", "isohybrid"),
];

fn boot_code_node(span: Span, code: &[u8]) -> Node {
    let node = Node::new("Bootstrap code").span(span);
    if code.iter().all(|&x| x == 0) {
        return node.summary("empty");
    }
    match BOOT_CODES
        .iter()
        .find(|(needle, _)| code.windows(needle.len()).any(|w| w == *needle))
    {
        Some((_, name)) => node.summary(format!("{name} boot code")),
        None => node.summary("boot code"),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let disk = input.span;
    let sector = cx.read(disk.sub(0, SECTOR)).await?;
    let entries: Vec<_> = raw_entries(&sector).collect();
    let used = entries.iter().filter(|e| e.1 != 0).count();
    let protective = entries.iter().any(|e| e.1 == 0xee);
    let extended = entries.iter().find(|e| is_extended(e.1)).copied();
    let logical = match extended {
        Some((_, _, lba, _)) => ebr_chain(&cx, disk, lba.into()).await?.0.len(),
        None => 0,
    };
    cx.annotate(if protective {
        "Protective MBR (GPT disk)".to_owned()
    } else {
        format!(
            "MBR partition table, {}{}, {}",
            plural(crate::bytes::to_u64(used), "primary partition"),
            if logical > 0 {
                format!(" and {logical} logical")
            } else {
                String::new()
            },
            size(disk.len)
        )
    });

    cx.emit(boot_code_node(
        disk.sub(0, 440),
        sector.get(..440).unwrap_or_default(),
    ));
    if let Some(sig) = u32_le(&sector, 440) {
        cx.emit(
            Node::new("Disk signature")
                .span(disk.sub(440, 4))
                .value(Value::UInt {
                    value: sig.into(),
                    bits: 32,
                    radix: Radix::Hex,
                })
                .desc("Windows identifies the disk by this number"),
        );
    }
    let protect = u16_le(&sector, 444).unwrap_or(0);
    cx.emit(
        Node::new("Copy protection")
            .span(disk.sub(444, 2))
            .value(Value::UInt {
                value: protect.into(),
                bits: 16,
                radix: Radix::Hex,
            })
            .summary(if protect == 0x5a5a {
                "copy-protected"
            } else {
                "not protected"
            }),
    );
    for (i, e) in entries.iter().enumerate() {
        let span = disk.sub(TABLE.saturating_add(to_u64(i).saturating_mul(16)), 16);
        let number = i.saturating_add(1);
        if e.1 == 0 {
            let at = to_usize(TABLE.saturating_add(to_u64(i).saturating_mul(16)));
            let raw = sector.get(at..at.saturating_add(16)).unwrap_or_default();
            cx.emit(unused_entry(format!("Partition {number}"), span, raw));
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
    cx.emit(
        Node::new("Disk layout")
            .span(disk)
            .summary("partitions and the space between them")
            .lazy(layout, input),
    );
    Ok(())
}

/// An unused partition entry: a leaf when it is all zeros, its fields
/// otherwise (stale data).
fn unused_entry(name: impl Into<std::borrow::Cow<'static, str>>, span: Span, raw: &[u8]) -> Node {
    if raw.iter().all(|&b| b == 0) {
        Node::new(name)
            .span(span)
            .value(Value::Enum {
                raw: 0,
                bits: 8,
                name: Some("unused"),
            })
            .summary("all zeros")
    } else {
        Entry::node(name, span, LE).summary("unused (type 0) but not blank")
    }
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
    if p.ext_base != 0 {
        // A logical partition: its EBR is the sector its entry is in.
        let ebr = Span::new(p.entry.source, p.entry.offset.saturating_sub(TABLE), SECTOR);
        cx.emit(
            Node::new("Extended boot record")
                .span(ebr)
                .summary(format!("at LBA {}", p.base))
                .lazy(ebr_node, (ebr, p.ext_base)),
        );
        if e.lba == 0 {
            cx.diag(Diagnostic::malformed("logical partition overlaps its EBR"));
            return Ok(());
        }
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

/// The fields of an EBR: boot code area, the logical partition entry, the
/// link to the next EBR, the unused entries and the signature.
async fn ebr_node(cx: Cx, (ebr, ext_base): (Span, u64)) -> Result<()> {
    let sector = cx.read(ebr).await?;
    let code = sector.get(..446).unwrap_or_default();
    let mut boot = Node::new("Boot code area").span(ebr.sub(0, 446));
    boot = if code.iter().all(|&b| b == 0) {
        boot.summary("empty (unused in EBRs)")
    } else {
        boot.summary("not empty")
    };
    cx.emit(boot);
    let entries: Vec<_> = raw_entries(&sector).collect();
    for (i, e) in entries.iter().enumerate() {
        let span = ebr.sub(TABLE.saturating_add(to_u64(i).saturating_mul(16)), 16);
        let (name, summary) = match i {
            0 => (
                "Logical partition entry",
                "start relative to this EBR".to_owned(),
            ),
            1 if is_extended(e.1) => (
                "Next EBR link",
                format!("next EBR at LBA {}", ext_base.saturating_add(e.2.into())),
            ),
            1 => ("Next EBR link", "end of chain".to_owned()),
            _ => {
                let at = to_usize(TABLE.saturating_add(to_u64(i).saturating_mul(16)));
                let raw = sector.get(at..at.saturating_add(16)).unwrap_or_default();
                cx.emit(unused_entry("Unused entry", span, raw));
                continue;
            }
        };
        cx.emit(Entry::node(name, span, LE).summary(summary));
    }
    cx.emit(
        Node::new("Boot signature")
            .span(ebr.sub(510, 2))
            .value(Value::UInt {
                value: u16_le(&sector, 510).unwrap_or(0).into(),
                bits: 16,
                radix: Radix::Hex,
            }),
    );
    Ok(())
}

/// One link of an EBR chain: the EBR's LBA and its first entry (the
/// logical partition: type, start relative to the EBR, sectors).
type Link = (u64, u8, u32, u32);

/// Walks the EBR chain of an extended partition starting at LBA `first`.
/// Returns the links and a problem that ended the walk, if any.
async fn ebr_chain(cx: &Cx, disk: Span, first: u64) -> Result<(Vec<Link>, Option<Diagnostic>)> {
    let mut visited: Vec<u64> = Vec::new();
    let mut out = Vec::new();
    let mut lba = first;
    loop {
        if visited.contains(&lba) {
            return Ok((
                out,
                Some(Diagnostic::malformed(format!(
                    "EBR chain loops back to LBA {lba}"
                ))),
            ));
        }
        if visited.len() >= MAX_LOGICAL {
            return Ok((
                out,
                Some(Diagnostic::limit(format!(
                    "more than {MAX_LOGICAL} logical partitions"
                ))),
            ));
        }
        visited.push(lba);
        let ebr = disk.sub(lba.saturating_mul(SECTOR), SECTOR);
        let sector = cx.read_avail(ebr).await?;
        if u16_le(&sector, 510) != Some(0xaa55) {
            return Ok((
                out,
                Some(Diagnostic::malformed("EBR without boot signature").at(ebr)),
            ));
        }
        let entries: Vec<_> = raw_entries(&sector).collect();
        let (_, kind, start, sectors) = entries.first().copied().unwrap_or_default();
        out.push((lba, kind, start, sectors));
        match entries.get(1) {
            Some(&(_, kind, next, _)) if is_extended(kind) && next != 0 => {
                lba = first.saturating_add(next.into());
            }
            _ => return Ok((out, None)),
        }
    }
}

async fn logical_partitions(cx: Cx, (input, first, ext_base): (Input, u64, u64)) -> Result<()> {
    let disk = input.span;
    let (links, problem) = ebr_chain(&cx, disk, first).await?;
    let mut number = 5usize;
    for (lba, kind, _, _) in links {
        let ebr = disk.sub(lba.saturating_mul(SECTOR), SECTOR);
        let entry = ebr.sub(TABLE, 16);
        if kind == 0 {
            cx.push(
                Node::new("Empty EBR")
                    .span(ebr)
                    .lazy(ebr_node, (ebr, ext_base)),
            )
            .await;
            continue;
        }
        cx.push(partition(format!("Partition {number}"), &input, entry, lba, ext_base).target(ebr))
            .await;
        number = number.saturating_add(1);
    }
    if let Some(d) = problem {
        cx.diag(d);
    }
    Ok(())
}

/// A region of the disk in sectors: `[start, end)` and what it is.
type Area = (u64, u64, String);

/// `LBA 5` or `LBA 5–9` for the sectors `[start, end)`.
pub(super) fn lba_range(start: u64, end: u64) -> String {
    let last = end.saturating_sub(1);
    if last <= start {
        format!("LBA {start}")
    } else {
        format!("LBA {start}–{last}")
    }
}

/// Describes unpartitioned sectors `[start, end)` (clipped to the image):
/// blank, or holding data (boot loaders often live right after the MBR).
/// `None` if nothing of them is in the image.
pub(super) async fn gap_node(
    cx: &Cx,
    disk: Span,
    sector: u64,
    (start, end): (u64, u64),
    what: &str,
) -> Result<Option<Node>> {
    let span = disk.sub(
        start.saturating_mul(sector),
        end.saturating_sub(start).saturating_mul(sector),
    );
    if span.is_empty() {
        return Ok(None);
    }
    let mut summary = format!("{}, {what}", size(span.len));
    if span.len <= MAX_GAP_CHECK {
        let data = cx.read_avail(span).await?;
        cx.checkpoint().await;
        summary.push_str(if data.iter().all(|&b| b == 0) {
            ", all zeros"
        } else {
            ", not blank"
        });
    }
    let end = start.saturating_add(span.len.checked_div(sector).unwrap_or(0));
    Ok(Some(
        Node::new("Unpartitioned space")
            .span(span)
            .summary(format!("{}: {summary}", lba_range(start, end))),
    ))
}

/// A partition or structure `[start, end)` in the layout, clipped to the
/// image.
pub(super) fn area_node(disk: Span, sector: u64, (start, end): (u64, u64), name: String) -> Node {
    let want = end.saturating_sub(start).saturating_mul(sector);
    let span = disk.sub(start.saturating_mul(sector), want);
    let mut summary = format!("{}, {}", lba_range(start, end), size(want));
    if span.len < want {
        summary.push_str(&if span.is_empty() {
            "; beyond the end of the image".to_owned()
        } else {
            format!("; only {} in the image", size(span.len))
        });
    }
    Node::new(name).span(span).summary(summary)
}

/// Pushes the gaps in `[a, b)`, telling space inside the extended
/// partition `ext` from the rest.
async fn push_gaps(cx: &Cx, disk: Span, (mut a, b): (u64, u64), ext: (u64, u64)) -> Result<()> {
    while a < b {
        let (stop, what) = if a < ext.0 {
            (
                b.min(ext.0),
                if a == 1 {
                    "between the MBR and the first partition"
                } else {
                    "unallocated"
                },
            )
        } else if a < ext.1 {
            (b.min(ext.1), "free space in the extended partition")
        } else {
            (b, "unallocated")
        };
        if let Some(n) = gap_node(cx, disk, SECTOR, (a, stop), what).await? {
            cx.push(n).await;
        }
        a = stop.max(a.saturating_add(1));
    }
    Ok(())
}

/// The disk in LBA order: MBR, partitions, EBRs and the gaps between them.
async fn layout(cx: Cx, input: Input) -> Result<()> {
    let disk = input.span;
    let total = disk.len / SECTOR;
    let sector = cx.read(disk.sub(0, SECTOR)).await?;
    let mut areas: Vec<Area> = vec![(0, 1, "Master boot record".to_owned())];
    let mut ext = (0u64, 0u64);
    for (i, (_, kind, lba, sectors)) in raw_entries(&sector).enumerate() {
        if kind == 0 {
            continue;
        }
        let start = u64::from(lba);
        let end = start.saturating_add(sectors.into());
        if is_extended(kind) {
            if ext.1 == 0 {
                ext = (start, end);
            }
            let (links, _) = ebr_chain(&cx, disk, start).await?;
            let mut number = 5usize;
            for (ebr, k, rel, n) in links {
                areas.push((
                    ebr,
                    ebr.saturating_add(1),
                    "Extended boot record".to_owned(),
                ));
                if k != 0 {
                    let s = ebr.saturating_add(rel.into());
                    areas.push((
                        s,
                        s.saturating_add(n.into()),
                        format!(
                            "Partition {number}: {}",
                            lookup(MBR_TYPES, k.into()).unwrap_or("unknown")
                        ),
                    ));
                    number = number.saturating_add(1);
                }
            }
            continue;
        }
        areas.push((
            start,
            end,
            format!(
                "Partition {}: {}",
                i.saturating_add(1),
                lookup(MBR_TYPES, kind.into()).unwrap_or("unknown")
            ),
        ));
    }
    areas.sort_by_key(|(s, e, _)| (*s, *e));
    let mut pos = 0u64;
    for (start, end, name) in areas {
        cx.checkpoint().await;
        if start > pos {
            push_gaps(&cx, disk, (pos, start.min(total.max(pos))), ext).await?;
            pos = start;
        }
        if end <= pos {
            continue;
        }
        cx.push(area_node(disk, SECTOR, (pos, end), name)).await;
        pos = end;
    }
    if pos < total {
        push_gaps(&cx, disk, (pos, total), ext).await?;
    }
    Ok(())
}

/// The MBR sector of a GPT disk: its entries, without dissecting the
/// (protective) partitions they describe. Entries other than the 0xEE one
/// make it a hybrid MBR.
pub fn protective_node(name: &'static str, sector: Span) -> Node {
    Node::new(name).span(sector).lazy(protective, sector)
}

async fn protective(cx: Cx, sector: Span) -> Result<()> {
    let data = cx.read(sector).await?;
    cx.emit(boot_code_node(
        sector.sub(0, 440),
        data.get(..440).unwrap_or_default(),
    ));
    cx.emit(
        Node::new("Disk signature")
            .span(sector.sub(440, 4))
            .value(Value::UInt {
                value: u32_le(&data, 440).unwrap_or(0).into(),
                bits: 32,
                radix: Radix::Hex,
            }),
    );
    cx.emit(
        Node::new("Copy protection")
            .span(sector.sub(444, 2))
            .value(Value::UInt {
                value: u16_le(&data, 444).unwrap_or(0).into(),
                bits: 16,
                radix: Radix::Hex,
            }),
    );
    let mut hybrid = false;
    for i in 0..4u64 {
        let span = sector.sub(TABLE.saturating_add(i.saturating_mul(16)), 16);
        let e = parse(&cx, span, LE, &(), Entry::layout).await?;
        let name = format!("Entry {}", i.saturating_add(1));
        let node = Entry::node(name.clone(), span, LE);
        cx.emit(match e.kind {
            0 => {
                let at = to_usize(TABLE.saturating_add(i.saturating_mul(16)));
                unused_entry(
                    name,
                    span,
                    data.get(at..at.saturating_add(16)).unwrap_or_default(),
                )
            }
            0xee => node.summary(format!("protective, {}", describe(&e, 0))),
            _ => {
                hybrid = true;
                node.summary(format!("hybrid: {}", describe(&e, 0)))
            }
        });
    }
    cx.emit(
        Node::new("Boot signature")
            .span(sector.sub(510, 2))
            .value(Value::UInt {
                value: u16_le(&data, 510).unwrap_or(0).into(),
                bits: 16,
                radix: Radix::Hex,
            }),
    );
    if hybrid {
        cx.annotate("hybrid MBR: GPT partitions also listed for legacy systems");
    } else {
        cx.annotate("protective MBR");
    }
    Ok(())
}
