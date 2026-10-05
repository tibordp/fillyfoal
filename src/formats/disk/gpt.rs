//! GUID Partition Table (UEFI specification, chapter 5).
//!
//! LBA 0 holds a protective MBR, LBA 1 the header, followed by the partition
//! entry array; a backup header sits in the last LBA. Both CRCs are verified.

use crate::bytes::{to_u64, to_usize};
use crate::codec::crc32;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::ptypes::gpt_type;
use crate::formats::disk::{mbr, size, volume};
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Guid, flag};

const LE: Endian = Endian::Little;
const SIGNATURE: &[u8] = b"EFI PART";
/// Entries we list before giving up on a corrupt array.
const MAX_ENTRIES: u64 = 4096;

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
        attributes: u64 "Attributes" .hex() .flags(ATTRIBUTES),
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

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let disk = input.span;
    let head = cx.read_avail(disk.sub(0, 4096 + 8)).await?;
    let sector = if head.get(512..520) == Some(SIGNATURE) {
        512
    } else {
        4096
    };
    cx.emit(embedded_as(
        "Protective MBR",
        input.nested(disk.sub(0, mbr::SECTOR)),
        &mbr::FORMAT,
    ));

    let header_span = disk.sub(sector, Header::SIZE);
    let header = parse(&cx, header_span, LE, &(), Header::layout).await?;
    let mut header_node = Header::node("GPT header", header_span, LE).summary(format!(
        "{} entries at LBA {}",
        header.entries, header.entries_lba
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

    // The array is small (16 KiB typically): read it to count partitions and
    // check its CRC, which the summary reports.
    let mut list = Node::new("Partition entries").span(array);
    let mut used = None;
    if array.len <= 1 << 20 {
        let data = cx.read_avail(array).await?;
        if to_u64(data.len()) < entries.saturating_mul(entry_size) {
            list = list.diag(Diagnostic::truncated(array, to_u64(data.len())));
        } else if crc32(&data) != header.entries_crc {
            list = list.diag(Diagnostic::warning(format!(
                "partition array CRC mismatch: computed {:#010x}",
                crc32(&data)
            )));
        }
        let count = data
            .chunks(to_usize(entry_size))
            .filter(|e| e.len() >= 16 && e.get(..16).is_some_and(|g| g.iter().any(|&b| b != 0)))
            .count();
        used = Some(count);
    }
    cx.annotate(match used {
        Some(n) => format!(
            "GPT disk, {n} partitions, {}-byte sectors, {}",
            sector,
            size(disk.len)
        ),
        None => format!("GPT disk, {}-byte sectors", sector),
    });
    cx.emit(
        list.summary(match used {
            Some(n) => format!("{n} used of {entries}"),
            None => format!("{entries} entries"),
        })
        .lazy(partitions, gpt),
    );

    let alternate = header.alternate_lba;
    if alternate != 0 && alternate != header.my_lba {
        let backup = disk.sub(alternate.saturating_mul(sector), Header::SIZE);
        let mut node = Header::node("Backup GPT header", backup, LE);
        match parse(&cx, backup, LE, &(), Header::layout).await {
            Ok(b) if b.signature.as_bytes() == SIGNATURE => {
                if let Some(d) = header_crc(&cx, backup, &b).await? {
                    node = node.diag(d);
                }
                cx.emit(node.summary(format!("at LBA {alternate}")));
            }
            Ok(_) => cx.emit(Node::new("Backup GPT header").span(backup).diag(
                Diagnostic::warning(format!("no backup header at LBA {alternate}")),
            )),
            Err(e) => cx.emit(Node::new("Backup GPT header").span(backup).diag(e)),
        }
    }
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
    for index in 0..count {
        let span = gpt
            .array
            .sub(index.saturating_mul(gpt.entry_size), Entry::SIZE);
        let raw = cx.read_avail(span).await?;
        if to_u64(raw.len()) < Entry::SIZE {
            cx.diag(Diagnostic::truncated(span, to_u64(raw.len())));
            break;
        }
        if raw.get(..16).is_some_and(|g| g.iter().all(|&b| b == 0)) {
            cx.checkpoint().await;
            continue;
        }
        let e = parse(&cx, span, LE, &(), Entry::layout).await?;
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
    Ok(())
}

async fn partition(cx: Cx, (gpt, span): (Gpt, Span)) -> Result<()> {
    let e = parse(&cx, span, LE, &(), Entry::layout).await?;
    cx.emit(Entry::node("Entry", span, LE));
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
