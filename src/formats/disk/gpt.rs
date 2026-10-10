//! GUID Partition Table (UEFI specification, chapter 5).
//!
//! LBA 0 holds a protective (or hybrid) MBR, LBA 1 the header, followed by
//! the partition entry array; a backup header sits in the last LBA, with a
//! backup copy of the array before it. Both headers' CRCs and both arrays'
//! CRCs are verified. A disk layout node accounts for the space between
//! partitions.

use crate::bytes::{to_u64, to_usize};
use crate::codec::crc32;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::ptypes::gpt_type;
use crate::formats::disk::{mbr, size, volume};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Guid, Value, flag};

const LE: Endian = Endian::Little;
const SIGNATURE: &[u8] = b"EFI PART";
/// Entries we list before giving up on a corrupt array.
const MAX_ENTRIES: u64 = 4096;
/// Largest partition array read whole (for CRCs and counts).
const MAX_ARRAY: u64 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "gpt",
    title: "GPT partitioned disk image",
    extensions: &["img", "raw", "dd", "bin"],
    mime: "application/x-raw-disk-image",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.at(512, SIGNATURE) || h.at(4096, SIGNATURE)
}

const ATTRIBUTES: FlagTable = &[
    flag(1 << 0, "PLATFORM_REQUIRED"),
    flag(1 << 1, "NO_BLOCK_IO_PROTOCOL"),
    flag(1 << 2, "LEGACY_BIOS_BOOTABLE"),
    flag(1 << 60, "READ_ONLY (Microsoft)"),
    flag(1 << 61, "SHADOW_COPY (Microsoft)"),
    flag(1 << 62, "HIDDEN (Microsoft)"),
    flag(1 << 63, "NO_DRIVE_LETTER (Microsoft)"),
];

record! {
    pub struct Header {
        signature: ascii[8] "Signature",
        revision: u32 "Revision" .hex() .with(|&r, n| n.summary(format!("{}.{}", r >> 16, r & 0xffff))),
        header_size: u32 "Header size",
        header_crc: u32 "Header CRC32" .hex(),
        _reserved: u32 "Reserved",
        my_lba: u64 "This header's LBA",
        alternate_lba: u64 "Alternate header's LBA",
        first_usable: u64 "First usable LBA",
        last_usable: u64 "Last usable LBA",
        disk_guid: guid "Disk GUID",
        entries_lba: u64 "Partition entries LBA",
        entries: u32 "Number of partition entries",
        entry_size: u32 "Size of a partition entry",
        entries_crc: u32 "Partition entries CRC32" .hex(),
    }
}

fn type_name(g: &Guid, node: crate::node::Node) -> crate::node::Node {
    match gpt_type(&g.to_string()) {
        Some(name) => node.summary(name),
        None => node,
    }
}

record! {
    pub struct Entry {
        kind: guid "Partition type GUID" .with(type_name),
        unique: guid "Unique partition GUID",
        first_lba: u64 "First LBA",
        last_lba: u64 "Last LBA (inclusive)",
        attributes: u64 "Attributes" .hex() .flags(ATTRIBUTES) .desc("Bits 0-2 are defined by UEFI; bits 48-63 by the partition type"),
        name: utf16[36] "Partition name",
    }
}

#[derive(Clone, Copy)]
struct Gpt {
    input: Input,
    sector: u64,
    array: Span,
    entries: u64,
    entry_size: u64,
}

/// A header sector: the header fields, then the reserved rest.
fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let h = Header::read(f)?;
    let size = u64::from(h.header_size).max(Header::SIZE);
    if size > Header::SIZE {
        f.bytes("Extra header bytes", size.saturating_sub(Header::SIZE))
            .emit()?;
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Reserved", rest).emit()?;
    }
    Ok(())
}

/// Checks a header's CRC: computed over `header_size` bytes with the CRC
/// field zeroed.
async fn header_crc(cx: &Cx, span: Span, h: &Header) -> Result<Option<Diagnostic>> {
    let len = u64::from(h.header_size).clamp(92, 4096);
    let mut data = cx.read(span.sub(0, len)).await?;
    if let Some(field) = data.get_mut(16..20) {
        field.fill(0);
    }
    let computed = crc32(&data);
    Ok((computed != h.header_crc).then(|| {
        Diagnostic::warning(format!(
            "header CRC mismatch: computed {computed:#010x}, stored {:#010x}",
            h.header_crc
        ))
        .at(span)
    }))
}

/// Reads a partition array (if small enough) and checks its CRC.
async fn read_array(
    cx: &Cx,
    array: Span,
    crc: u32,
) -> Result<(Option<Vec<u8>>, Option<Diagnostic>)> {
    if array.len > MAX_ARRAY {
        return Ok((None, None));
    }
    let data = cx.read_avail(array).await?;
    if to_u64(data.len()) < array.len {
        let d = Diagnostic::truncated(array, to_u64(data.len()));
        return Ok((Some(data), Some(d)));
    }
    let computed = crate::formats::util::datakit::crc32_paced(cx, &data).await;
    let problem = (computed != crc).then(|| {
        Diagnostic::warning(format!(
            "partition array CRC mismatch: computed {computed:#010x}, stored {crc:#010x}"
        ))
    });
    Ok((Some(data), problem))
}

fn used_entries(data: &[u8], entry_size: u64) -> usize {
    data.chunks(to_usize(entry_size))
        .filter(|e| e.len() >= 16 && e.get(..16).is_some_and(|g| g.iter().any(|&b| b != 0)))
        .count()
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let disk = input.span;
    let head = cx.read_avail(disk.sub(0, 4096 + 8)).await?;
    let sector = if head.get(512..520) == Some(SIGNATURE) {
        512
    } else {
        4096
    };
    cx.emit(mbr::protective_node(
        "Protective MBR",
        disk.sub(0, mbr::SECTOR),
    ));
    if sector > mbr::SECTOR {
        cx.emit(
            Node::new("Rest of LBA 0")
                .span(disk.sub(mbr::SECTOR, sector.saturating_sub(mbr::SECTOR)))
                .summary("unused"),
        );
    }

    let header_sector = disk.sub(sector, sector);
    let header_span = disk.sub(sector, Header::SIZE);
    let header = parse(&cx, header_span, LE, &(), Header::layout).await?;
    let mut header_node =
        struct_node("GPT header", header_sector, LE, (), header_layout).summary(format!(
            "revision {}.{}, {} entries at LBA {}, usable LBA {}–{}",
            header.revision >> 16,
            header.revision & 0xffff,
            header.entries,
            header.entries_lba,
            header.first_usable,
            header.last_usable
        ));
    if let Some(d) = header_crc(&cx, header_span, &header).await? {
        header_node = header_node.diag(d);
    }
    cx.emit(header_node);

    let entry_size = u64::from(header.entry_size);
    let entries = u64::from(header.entries);
    if entry_size < Entry::SIZE {
        return Err(
            Diagnostic::malformed(format!("partition entry size {entry_size} too small"))
                .at(header_span),
        );
    }
    let array = disk.sub(
        header.entries_lba.saturating_mul(sector),
        entries.saturating_mul(entry_size),
    );
    let gpt = Gpt {
        input,
        sector,
        array,
        entries,
        entry_size,
    };

    let (data, problem) = read_array(&cx, array, header.entries_crc).await?;
    let used = data.as_deref().map(|d| used_entries(d, entry_size));
    let mut list = Node::new("Partition entries").span(array);
    if let Some(d) = problem {
        list = list.diag(d);
    }
    cx.annotate(match used {
        Some(n) => format!(
            "GPT disk, {n} partition{}, {sector}-byte sectors, {}, disk GUID {}",
            if n == 1 { "" } else { "s" },
            size(disk.len),
            header.disk_guid
        ),
        None => format!(
            "GPT disk, {sector}-byte sectors, disk GUID {}",
            header.disk_guid
        ),
    });
    cx.emit(
        list.summary(match used {
            Some(n) => format!("{n} used of {entries}, {entry_size} bytes each"),
            None => format!("{entries} entries"),
        })
        .lazy(partitions, gpt),
    );

    let alternate = header.alternate_lba;
    let mut backup_info = None;
    if alternate != 0 && alternate != header.my_lba {
        let backup_sector = disk.sub(alternate.saturating_mul(sector), sector);
        let backup = disk.sub(alternate.saturating_mul(sector), Header::SIZE);
        match parse(&cx, backup, LE, &(), Header::layout).await {
            Ok(b) if b.signature.as_bytes() == SIGNATURE => {
                let mut node =
                    struct_node("Backup GPT header", backup_sector, LE, (), header_layout).summary(
                        format!("at LBA {alternate}, entries at LBA {}", b.entries_lba),
                    );
                if let Some(d) = header_crc(&cx, backup, &b).await? {
                    node = node.diag(d);
                }
                if b.alternate_lba != header.my_lba || b.disk_guid != header.disk_guid {
                    node = node.diag(Diagnostic::warning(
                        "does not mirror the primary header (alternate LBA or disk GUID)",
                    ));
                }
                let barray = disk.sub(
                    b.entries_lba.saturating_mul(sector),
                    u64::from(b.entries).saturating_mul(b.entry_size.into()),
                );
                let (bdata, bproblem) = read_array(&cx, barray, b.entries_crc).await?;
                let mut anode = Node::new("Backup partition entries").span(barray);
                anode = match (&bdata, &data) {
                    (Some(x), Some(y)) if x == y => anode.summary("identical to the primary array"),
                    (Some(_), Some(_)) => {
                        anode.diag(Diagnostic::warning("differs from the primary array"))
                    }
                    _ => anode,
                };
                if let Some(d) = bproblem {
                    anode = anode.diag(d);
                }
                if bdata
                    .as_ref()
                    .zip(data.as_ref())
                    .is_none_or(|(x, y)| x != y)
                {
                    anode = anode.lazy(
                        partitions,
                        Gpt {
                            array: barray,
                            entries: b.entries.into(),
                            entry_size: b.entry_size.into(),
                            ..gpt
                        },
                    );
                }
                cx.emit(anode);
                cx.emit(node);
                backup_info = Some((barray, backup_sector));
            }
            Ok(_) => cx.emit(Node::new("Backup GPT header").span(backup).diag(
                Diagnostic::warning(format!("no backup header at LBA {alternate}")),
            )),
            Err(e) => cx.emit(Node::new("Backup GPT header").span(backup).diag(e)),
        }
    }
    cx.emit(
        Node::new("Disk layout")
            .span(disk)
            .summary("partitions and the space between them")
            .lazy(
                layout,
                (
                    gpt,
                    header_sector,
                    header.first_usable,
                    header.last_usable,
                    backup_info,
                ),
            ),
    );
    Ok(())
}

async fn partitions(cx: Cx, gpt: Gpt) -> Result<()> {
    let count = gpt.entries.min(MAX_ENTRIES);
    if gpt.entries > MAX_ENTRIES {
        cx.diag(Diagnostic::limit(format!(
            "only the first {MAX_ENTRIES} of {} entries are listed",
            gpt.entries
        )));
    }
    let mut unused: Option<u64> = None;
    let flush = |unused: &mut Option<u64>, end: u64| -> Option<Node> {
        let first = unused.take()?;
        let span = gpt.array.sub(
            first.saturating_mul(gpt.entry_size),
            end.saturating_sub(first).saturating_mul(gpt.entry_size),
        );
        let name = if first.saturating_add(1) == end {
            format!("Entry {}", first.saturating_add(1))
        } else {
            format!("Entries {}–{end}", first.saturating_add(1))
        };
        Some(Node::new(name).span(span).value(Value::Enum {
            raw: 0,
            bits: 8,
            name: Some("unused"),
        }))
    };
    for index in 0..count {
        let span = gpt
            .array
            .sub(index.saturating_mul(gpt.entry_size), gpt.entry_size);
        let raw = cx.read_avail(span).await?;
        if to_u64(raw.len()) < Entry::SIZE {
            if let Some(n) = flush(&mut unused, index) {
                cx.push(n).await;
            }
            cx.diag(Diagnostic::truncated(span, to_u64(raw.len())));
            break;
        }
        if raw.get(..16).is_some_and(|g| g.iter().all(|&b| b == 0)) {
            unused.get_or_insert(index);
            cx.checkpoint().await;
            continue;
        }
        if let Some(n) = flush(&mut unused, index) {
            cx.push(n).await;
        }
        let e = parse(&cx, span.sub(0, Entry::SIZE), LE, &(), Entry::layout).await?;
        let kind = gpt_type(&e.kind.to_string()).unwrap_or("unknown type");
        let sectors = e.last_lba.saturating_sub(e.first_lba).saturating_add(1);
        let label = if e.name.is_empty() {
            format!("Partition {}", index.saturating_add(1))
        } else {
            format!("Partition {}: {}", index.saturating_add(1), e.name)
        };
        cx.push(
            Node::new(label)
                .span(span)
                .summary(format!(
                    "{kind}, {} at LBA {}",
                    size(sectors.saturating_mul(gpt.sector)),
                    e.first_lba
                ))
                .lazy(partition, (gpt, span)),
        )
        .await;
    }
    if let Some(n) = flush(&mut unused, count) {
        cx.push(n).await;
    }
    Ok(())
}

async fn partition(cx: Cx, (gpt, span): (Gpt, Span)) -> Result<()> {
    let e = parse(&cx, span.sub(0, Entry::SIZE), LE, &(), Entry::layout).await?;
    cx.emit(Entry::node("Entry", span.sub(0, Entry::SIZE), LE));
    if span.len > Entry::SIZE {
        let extra = span.tail(Entry::SIZE);
        let data = cx.read_avail(extra).await?;
        cx.emit(Node::new("Reserved").span(extra).value(Value::Bytes(data)));
    }
    if e.last_lba < e.first_lba {
        cx.diag(Diagnostic::malformed("last LBA precedes first LBA"));
        return Ok(());
    }
    let disk = gpt.input.span;
    let len = e
        .last_lba
        .saturating_sub(e.first_lba)
        .saturating_add(1)
        .saturating_mul(gpt.sector);
    let data = disk.sub(e.first_lba.saturating_mul(gpt.sector), len);
    let mut node = volume("Volume", &gpt.input, data);
    if data.len < len {
        node = node.diag(Diagnostic::truncated(
            Span::new(
                disk.source,
                disk.offset
                    .saturating_add(e.first_lba.saturating_mul(gpt.sector)),
                len,
            ),
            data.len,
        ));
    }
    cx.emit(node);
    Ok(())
}

/// Pushes the gaps in `[a, b)`, telling the space before the first usable
/// LBA and after the last from free space in between.
async fn push_gaps(cx: &Cx, gpt: &Gpt, (mut a, b): (u64, u64), usable: (u64, u64)) -> Result<()> {
    while a < b {
        let (stop, what) = if a < usable.0 {
            (b.min(usable.0), "reserved, before the first usable LBA")
        } else if a <= usable.1 {
            (b.min(usable.1.saturating_add(1)), "free space")
        } else {
            (b, "after the last usable LBA")
        };
        if let Some(n) = mbr::gap_node(cx, gpt.input.span, gpt.sector, (a, stop), what).await? {
            cx.push(n).await;
        }
        a = stop.max(a.saturating_add(1));
    }
    Ok(())
}

type LayoutState = (Gpt, Span, u64, u64, Option<(Span, Span)>);

/// The disk in LBA order: MBR, headers, arrays, partitions and the gaps.
async fn layout(
    cx: Cx,
    (gpt, header, first_usable, last_usable, backup): LayoutState,
) -> Result<()> {
    let disk = gpt.input.span;
    let sector = gpt.sector;
    let lba = |s: Span| {
        s.offset
            .saturating_sub(disk.offset)
            .checked_div(sector)
            .unwrap_or(0)
    };
    let lba_end = |s: Span| s.end().saturating_sub(disk.offset).div_ceil(sector);
    let mut areas: Vec<(u64, u64, String)> = vec![
        (0, 1, "Protective MBR".to_owned()),
        (lba(header), lba_end(header), "GPT header".to_owned()),
        (
            lba(gpt.array),
            lba_end(gpt.array),
            "Partition entries".to_owned(),
        ),
    ];
    if let Some((array, h)) = backup {
        areas.push((
            lba(array),
            lba_end(array),
            "Backup partition entries".to_owned(),
        ));
        areas.push((lba(h), lba_end(h), "Backup GPT header".to_owned()));
    }
    let (data, _) = read_array(&cx, gpt.array, 0).await?;
    if let Some(data) = data {
        for (i, e) in data.chunks(to_usize(gpt.entry_size)).enumerate() {
            if i.is_multiple_of(256) {
                cx.checkpoint().await;
            }
            if e.get(..16).is_none_or(|g| g.iter().all(|&b| b == 0)) {
                continue;
            }
            let first = crate::bytes::u64_le(e, 32).unwrap_or(0);
            let last = crate::bytes::u64_le(e, 40).unwrap_or(0);
            let kind = crate::formats::disk::guid_le(e.get(..16).unwrap_or_default());
            areas.push((
                first,
                last.saturating_add(1),
                format!(
                    "Partition {}: {}",
                    i.saturating_add(1),
                    gpt_type(&kind.to_string()).unwrap_or("unknown type")
                ),
            ));
        }
    }
    areas.sort_by_key(|(s, e, _)| (*s, *e));
    let total = disk.len.checked_div(sector).unwrap_or(0);
    let usable = (first_usable, last_usable);
    let mut pos = 0u64;
    for (start, end, name) in areas {
        cx.checkpoint().await;
        if start > pos {
            push_gaps(&cx, &gpt, (pos, start.min(total.max(pos))), usable).await?;
            pos = start;
        }
        if end <= pos {
            continue;
        }
        cx.push(mbr::area_node(disk, sector, (pos, end), name))
            .await;
        pos = end;
    }
    if pos < total {
        push_gaps(&cx, &gpt, (pos, total), usable).await?;
    }
    Ok(())
}
