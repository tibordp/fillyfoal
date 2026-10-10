//! Microsoft VHDX virtual disks ([MS-VHDX]).
//!
//! Fixed layout: a file type identifier at 0, two headers at 64 and
//! 128 KiB (the one with the higher sequence number is current), two region
//! tables at 192 and 256 KiB. The region table locates the metadata region
//! (block size, disk size, sector sizes, disk id, parent locator) and the
//! block allocation table, whose entries interleave payload blocks with
//! sector bitmap blocks. The log (a circular buffer of entries replaying
//! metadata writes) is located by the header. The virtual disk is
//! assembled from the BAT.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::qcow::Regions;
use crate::formats::disk::{PieceList, guid_le, size};
use crate::formats::util::datakit::crc32c_paced;
use crate::formats::{Format, Input, Probe, dissect_or_data};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, Value, flag, lookup};

const LE: Endian = Endian::Little;
const KIB64: u64 = 64 * 1024;
const MIB: u64 = 1024 * 1024;
/// Entries listed from a table before assuming corruption.
const MAX_ENTRIES: u64 = 2047;
/// Log entries walked at most.
const MAX_LOG_ENTRIES: u64 = 1 << 16;

pub static FORMAT: Format = Format {
    name: "vhdx",
    title: "Microsoft VHDX virtual disk",
    extensions: &["vhdx", "avhdx"],
    mime: "application/x-vhdx",
    probe: Probe::Magic(&[(0, b"vhdxfile")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    pub struct Header {
        signature: ascii[4] "Signature",
        checksum: u32 "Checksum (CRC-32C)" .hex(),
        sequence: u64 "Sequence number",
        file_write: guid "File write GUID" .desc("Changes whenever the file is opened for writing"),
        data_write: guid "Data write GUID" .desc("Changes whenever the virtual disk's data is written"),
        log_guid: guid "Log GUID" .desc("Identifies the valid log entries; zero if the log is empty"),
        log_version: u16 "Log version",
        version: u16 "Version",
        log_length: u32 "Log length" .with(|&v, n| n.summary(size(v.into()))),
        log_offset: u64 "Log offset" .hex(),
        _reserved: bytes[4016] "Reserved",
    }
}

record! {
    pub struct RegionTable {
        signature: ascii[4] "Signature",
        checksum: u32 "Checksum (CRC-32C)" .hex(),
        entries: u32 "Entry count",
        _reserved: u32 "Reserved",
    }
}

const BAT_GUID: &str = "2dc27766-f623-4200-9d64-115e9bfd4a08";
const METADATA_GUID: &str = "8b7ca206-4790-4b9a-b8fe-575f050f886e";

const REGIONS: &[(&str, &str)] = &[
    (BAT_GUID, "Block allocation table"),
    (METADATA_GUID, "Metadata"),
];

const ITEMS: &[(&str, &str)] = &[
    ("caa16737-fa36-4d43-b3b6-33f0aa44e76b", "File parameters"),
    ("2fa54224-cd1b-4876-b211-5dbed83bf4b8", "Virtual disk size"),
    (
        "beca12ab-b2e6-4523-93ef-c309e000c746",
        "Virtual disk id (page 83 data)",
    ),
    (
        "8141bf1d-a96f-4709-ba47-f233a8faab5f",
        "Logical sector size",
    ),
    (
        "cda348c7-445d-4471-9cc9-e9885251c556",
        "Physical sector size",
    ),
    ("a8d35f2d-b30b-454d-abf7-d3d84834ab0c", "Parent locator"),
];

const LOCATOR_TYPES: &[(&str, &str)] = &[("b04aefb7-d19e-4a81-b789-25b8e9445913", "VHDX parent")];

fn guid_name(table: &[(&str, &'static str)], g: &Guid) -> Option<&'static str> {
    let text = g.to_string();
    let key = text
        .trim_matches(|c| c == '{' || c == '}')
        .to_ascii_lowercase();
    table.iter().find(|(k, _)| *k == key).map(|(_, n)| *n)
}

const REQUIRED: FlagTable = &[flag(1, "REQUIRED")];

record! {
    pub struct RegionEntry {
        id: guid "Region GUID" .with(|g, n| match guid_name(REGIONS, g) { Some(s) => n.summary(s), None => n }),
        offset: u64 "File offset" .hex(),
        length: u32 "Length" .with(|&v, n| n.summary(size(v.into()))),
        required: u32 "Flags" .hex() .flags(REQUIRED),
    }
}

const ITEM_FLAGS: FlagTable = &[
    flag(1, "IS_USER"),
    flag(2, "IS_VIRTUAL_DISK"),
    flag(4, "IS_REQUIRED"),
];

record! {
    pub struct MetadataEntry {
        id: guid "Item GUID" .with(|g, n| match guid_name(ITEMS, g) { Some(s) => n.summary(s), None => n }),
        offset: u32 "Offset" .hex(),
        length: u32 "Length",
        flags: u32 "Flags" .hex() .flags(ITEM_FLAGS),
        _reserved: u32 "Reserved",
    }
}

const FILE_PARAMS: FlagTable = &[flag(1, "LEAVE_BLOCKS_ALLOCATED"), flag(2, "HAS_PARENT")];

record! {
    pub struct LogEntryHeader {
        signature: ascii[4] "Signature",
        checksum: u32 "Checksum (CRC-32C)" .hex(),
        length: u32 "Entry length" .with(|&v, n| n.summary(size(v.into()))),
        tail: u32 "Tail" .hex() .desc("Offset in the log of the oldest entry still needed"),
        sequence: u64 "Sequence number",
        descriptors: u32 "Descriptor count",
        _reserved: u32 "Reserved",
        log_guid: guid "Log GUID",
        flushed: u64 "Flushed file offset" .with(|&v, n| n.summary(format!("file size when flushed: {}", size(v)))),
        last: u64 "Last file offset" .with(|&v, n| n.summary(format!("file size when written: {}", size(v)))),
    }
}

const BAT_STATES: EnumTable = &[
    (0, "not present"),
    (1, "undefined"),
    (2, "zero"),
    (3, "unmapped"),
    (6, "fully present"),
    (7, "partially present"),
];

const BITMAP_STATES: EnumTable = &[(0, "not present"), (6, "present")];

/// Checks the CRC-32C of a structure whose checksum is at offset 4.
async fn verify(cx: &Cx, span: Span, stored: u32) -> Result<Option<Diagnostic>> {
    let mut data = cx.read_avail(span).await?;
    if let Some(f) = data.get_mut(4..8) {
        f.fill(0);
    }
    let computed = crc32c_paced(cx, &data).await;
    Ok((computed != stored).then(|| {
        Diagnostic::warning(format!("checksum mismatch: computed {computed:#010x}")).at(span)
    }))
}

#[derive(Debug, Default)]
struct Params {
    block: u64,
    disk_size: u64,
    logical_sector: u64,
    physical_sector: u64,
    has_parent: bool,
    page83: Option<Guid>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let ident = file.sub(0, KIB64);
    let creator = crate::text::utf16z(&cx.read_avail(ident.sub(8, 512)).await?, LE).0;
    cx.emit(
        struct_node("File type identifier", ident, LE, (), identifier_layout)
            .summary(format!("created by {creator:?}")),
    );

    // Current header: valid signature and checksum, highest sequence.
    let mut current: Option<(usize, Header)> = None;
    let mut nodes = Vec::new();
    for (i, at) in [KIB64, 2 * KIB64].into_iter().enumerate() {
        let span = file.sub(at, 4096);
        let area = file.sub(at, KIB64);
        let name = format!("Header {}", i.saturating_add(1));
        match parse(&cx, span, LE, &(), Header::layout).await {
            Ok(h) if h.signature == "head" => {
                let bad = verify(&cx, span, h.checksum).await?;
                let mut node =
                    Header::node(name, span, LE).summary(format!("sequence {}", h.sequence));
                if let Some(d) = bad {
                    node = node.diag(d);
                } else if current
                    .as_ref()
                    .is_none_or(|(_, c)| h.sequence > c.sequence)
                {
                    current = Some((i, h));
                }
                nodes.push(node);
            }
            Ok(_) => nodes.push(
                Node::new(name)
                    .span(span)
                    .diag(Diagnostic::malformed("bad signature")),
            ),
            Err(e) => nodes.push(Node::new(name).span(span).diag(e)),
        }
        nodes.push(
            Node::new(format!("Header {} padding", i.saturating_add(1)))
                .span(area.tail(4096))
                .summary("rest of the 64 KiB header area"),
        );
    }
    for (i, node) in nodes.into_iter().enumerate() {
        let is_current = current
            .as_ref()
            .is_some_and(|(c, _)| c.saturating_mul(2) == i);
        cx.emit(if is_current {
            let s = node.summary.clone().unwrap_or_default();
            node.summary(format!("{s}, current"))
        } else {
            node
        });
    }
    if current.is_none() {
        cx.diag(Diagnostic::malformed("no valid header"));
    }

    let mut regions = Vec::new();
    for (i, at) in [3 * KIB64, 4 * KIB64].into_iter().enumerate() {
        let span = file.sub(at, KIB64);
        let name = format!("Region table {}", i.saturating_add(1));
        let header = parse(
            &cx,
            span.sub(0, RegionTable::SIZE),
            LE,
            &(),
            RegionTable::layout,
        )
        .await;
        match header {
            Ok(t) if t.signature == "regi" => {
                let mut node = Node::new(name)
                    .span(span)
                    .summary(format!("{} regions", t.entries));
                if let Some(d) = verify(&cx, span, t.checksum).await? {
                    node = node.diag(d);
                }
                let count = u64::from(t.entries).min(MAX_ENTRIES);
                cx.emit(node.lazy(region_table, (span, count)));
                if regions.is_empty() {
                    let data = cx
                        .read_avail(span.sub(16, count.saturating_mul(32)))
                        .await?;
                    for e in data.as_chunks::<32>().0 {
                        let id = guid_le(e.get(..16).unwrap_or_default());
                        regions.push((
                            guid_name(REGIONS, &id),
                            u64_le(e, 16).unwrap_or(0),
                            u32_le(e, 24).unwrap_or(0),
                        ));
                    }
                }
            }
            Ok(_) => cx.emit(
                Node::new(name)
                    .span(span)
                    .diag(Diagnostic::malformed("bad signature")),
            ),
            Err(e) => cx.emit(Node::new(name).span(span).diag(e)),
        }
    }

    let mut log = None;
    if let Some((_, h)) = &current
        && h.log_length > 0
    {
        let span = file.sub(h.log_offset, h.log_length.into());
        log = Some(span);
        let active = h.log_guid != guid_le(&[0; 16]);
        cx.emit(
            Node::new("Log")
                .span(span)
                .summary(if active {
                    "active: entries must be replayed before the disk is used".to_owned()
                } else {
                    format!("{}, empty (log GUID is zero)", size(span.len))
                })
                .lazy(log_entries, span),
        );
    }

    let mut params = Params::default();
    let mut bat = None;
    let mut metadata_span = None;
    for (kind, offset, len) in regions {
        let span = file.sub(offset, len.into());
        match kind {
            Some("Metadata") => {
                params = metadata_params(&cx, span).await?;
                metadata_span = Some(span);
                cx.emit(
                    Node::new("Metadata region")
                        .span(span)
                        .lazy(metadata, (input, span)),
                );
            }
            Some("Block allocation table") => bat = Some(span),
            _ => cx.emit(Node::new("Unknown region").span(span)),
        }
    }
    cx.annotate(format!(
        "VHDX {} disk, {}, {} blocks, {}-byte logical / {}-byte physical sectors{}",
        if params.has_parent {
            "differencing"
        } else {
            "dynamic/fixed"
        },
        size(params.disk_size),
        size(params.block),
        params.logical_sector,
        params.physical_sector,
        match params.page83 {
            Some(g) => format!(", disk id {g}"),
            None => String::new(),
        }
    ));
    let Some(bat) = bat else {
        return Err(Diagnostic::malformed("no block allocation table region"));
    };
    if !params.block.is_power_of_two()
        || params.block < MIB
        || params.block > 256 * MIB
        || !matches!(params.logical_sector, 512 | 4096)
    {
        cx.emit(Node::new("Block allocation table").span(bat));
        return Err(Diagnostic::malformed(format!(
            "block size {:#x}, logical sector size {}",
            params.block, params.logical_sector
        )));
    }
    // One sector bitmap block follows every `chunk_ratio` payload blocks.
    let chunk_ratio = (1u64 << 23)
        .saturating_mul(params.logical_sector)
        .checked_div(params.block)
        .unwrap_or(1)
        .max(1);
    let disk = Arc::new(Disk {
        input,
        bat,
        block: params.block,
        size: params.disk_size,
        chunk_ratio,
        logical_sector: params.logical_sector,
        has_parent: params.has_parent,
        log,
        metadata: metadata_span,
    });
    cx.emit(
        Node::new("Block allocation table")
            .span(bat)
            .summary(format!(
                "{} payload blocks, a sector bitmap block every {chunk_ratio}",
                disk.blocks()
            ))
            .lazy(bat_entries, disk.clone()),
    );
    cx.emit(
        Node::new("File layout")
            .span(file)
            .summary("what each part of the file holds")
            .lazy(layout, disk.clone()),
    );
    let mut vnode = Node::new("Virtual disk")
        .summary(size(params.disk_size))
        .lazy(virtual_disk, disk);
    if params.has_parent {
        vnode = vnode.desc("Sectors absent from this file come from the parent; shown as zeros");
    }
    cx.emit(vnode);
    Ok(())
}

fn identifier_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Signature", 8).emit()?;
    let data = f.block().data.get(8..520).unwrap_or_default().to_vec();
    f.bytes("Creator", 512)
        .with(|_, n| n.value(Value::Text(crate::text::utf16z(&data, LE).0)))
        .emit()?;
    let rest = f.remaining();
    f.bytes("Reserved", rest).emit()?;
    Ok(())
}

async fn region_table(cx: Cx, (span, count): (Span, u64)) -> Result<()> {
    cx.emit(RegionTable::node(
        "Header",
        span.sub(0, RegionTable::SIZE),
        LE,
    ));
    for i in 0..count {
        let e = span.sub(16u64.saturating_add(i.saturating_mul(32)), 32);
        cx.push(RegionEntry::node(format!("Region {i}"), e, LE))
            .await;
    }
    let used = 16u64.saturating_add(count.saturating_mul(32));
    cx.push(
        Node::new("Reserved")
            .span(span.tail(used))
            .summary("rest of the 64 KiB table"),
    )
    .await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Metadata

/// Reads the metadata items the dissector needs.
async fn metadata_params(cx: &Cx, region: Span) -> Result<Params> {
    let mut p = Params::default();
    let head = cx.read_avail(region.sub(0, 32)).await?;
    let count = u64::from(u16_le(&head, 10).unwrap_or(0)).min(MAX_ENTRIES);
    let table = cx
        .read_avail(region.sub(32, count.saturating_mul(32)))
        .await?;
    for e in table.as_chunks::<32>().0 {
        let id = guid_le(e.get(..16).unwrap_or_default());
        let offset = u64::from(u32_le(e, 16).unwrap_or(0));
        let value = cx.read_avail(region.sub(offset, 16)).await?;
        match guid_name(ITEMS, &id) {
            Some("File parameters") => {
                p.block = u32_le(&value, 0).unwrap_or(0).into();
                p.has_parent = u32_le(&value, 4).unwrap_or(0) & 2 != 0;
            }
            Some("Virtual disk size") => p.disk_size = u64_le(&value, 0).unwrap_or(0),
            Some("Logical sector size") => p.logical_sector = u32_le(&value, 0).unwrap_or(0).into(),
            Some("Physical sector size") => {
                p.physical_sector = u32_le(&value, 0).unwrap_or(0).into();
            }
            Some("Virtual disk id (page 83 data)") => p.page83 = Some(guid_le(&value)),
            _ => {}
        }
        cx.checkpoint().await;
    }
    Ok(p)
}

fn metadata_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Signature", 8).emit()?;
    f.u16("Reserved").emit()?;
    f.u16("Entry count").emit()?;
    f.bytes("Reserved", 20).emit()?;
    Ok(())
}

async fn metadata(cx: Cx, (input, region): (Input, Span)) -> Result<()> {
    let head = cx.read_avail(region.sub(0, 32)).await?;
    let count = u64::from(u16_le(&head, 10).unwrap_or(0)).min(MAX_ENTRIES);
    cx.emit(
        struct_node(
            "Table header",
            region.sub(0, 32),
            LE,
            (),
            metadata_header_layout,
        )
        .summary(format!("{count} entries")),
    );
    let mut items = Vec::new();
    for i in 0..count {
        let span = region.sub(32u64.saturating_add(i.saturating_mul(32)), 32);
        let e = parse(&cx, span, LE, &(), MetadataEntry::layout).await?;
        let value = region.sub(e.offset.into(), e.length.into());
        let name = guid_name(ITEMS, &e.id).unwrap_or("Unknown item");
        cx.push(
            MetadataEntry::node(format!("Entry: {name}"), span, LE)
                .summary(format!("{} at {:#x}", size(e.length.into()), e.offset))
                .target(value),
        )
        .await;
        items.push((name, value));
    }
    let used = 32u64.saturating_add(count.saturating_mul(32));
    cx.push(
        Node::new("Table padding")
            .span(region.sub(used, KIB64.saturating_sub(used)))
            .summary("rest of the 64 KiB table"),
    )
    .await;
    for (name, value) in items {
        let data = cx.read_avail(value).await?;
        let node = Node::new(name).span(value);
        let node = match name {
            "File parameters" => struct_node(name, value, LE, (), file_params_layout).summary(
                format!("{} blocks", size(u32_le(&data, 0).unwrap_or(0).into())),
            ),
            "Virtual disk size" => node
                .value(Value::UInt {
                    value: u64_le(&data, 0).unwrap_or(0),
                    bits: 64,
                    radix: crate::value::Radix::Dec,
                })
                .summary(size(u64_le(&data, 0).unwrap_or(0))),
            "Logical sector size" | "Physical sector size" => node.value(Value::UInt {
                value: u32_le(&data, 0).unwrap_or(0).into(),
                bits: 32,
                radix: crate::value::Radix::Dec,
            }),
            "Virtual disk id (page 83 data)" => node.value(Value::Guid(guid_le(&data))),
            "Parent locator" => node
                .summary(format!("{} bytes", data.len()))
                .lazy(parent_locator, (input, value)),
            _ => node.value(Value::Bytes(data.iter().take(256).copied().collect())),
        };
        cx.push(node).await;
    }
    Ok(())
}

fn file_params_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Block size")
        .with(|&v, n| n.summary(size(v.into())))
        .emit()?;
    f.u32("Flags").hex().flags(FILE_PARAMS).emit()?;
    Ok(())
}

/// The parent locator item: a type GUID and key/value pairs (UTF-16).
async fn parent_locator(cx: Cx, (_input, span): (Input, Span)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let block = cx.block(span.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.guid("Locator type")
        .with(|g, n| match guid_name(LOCATOR_TYPES, g) {
            Some(s) => n.summary(s),
            None => n,
        })
        .emit()?;
    f.u16("Reserved").emit()?;
    let count = f.u16("Key-value count").emit()?;
    for i in 0..u64::from(count).min(MAX_ENTRIES) {
        let at = to_usize(20u64.saturating_add(i.saturating_mul(12)));
        let key_at = u32_le(&data, at).unwrap_or(0);
        let value_at = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
        let key_len = u16_le(&data, at.saturating_add(8)).unwrap_or(0);
        let value_len = u16_le(&data, at.saturating_add(10)).unwrap_or(0);
        let text = |o: u32, l: u16| {
            let o = to_usize(o.into());
            data.get(o..o.saturating_add(l.into()))
                .map(|b| crate::text::utf16(b, LE))
                .unwrap_or_default()
        };
        let key = text(key_at, key_len);
        let value = text(value_at, value_len);
        let entry = span.sub(to_u64(at), 12);
        cx.emit(
            struct_node(format!("Entry {i}"), entry, LE, (), locator_entry_layout)
                .summary(key.clone()),
        );
        cx.emit(
            Node::new(format!("Key {i}"))
                .span(span.sub(key_at.into(), key_len.into()))
                .value(Value::Text(key.clone())),
        );
        cx.emit(
            Node::new(key)
                .span(span.sub(value_at.into(), value_len.into()))
                .value(Value::Text(value)),
        );
        cx.checkpoint().await;
    }
    Ok(())
}

fn locator_entry_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Key offset").hex().emit()?;
    f.u32("Value offset").hex().emit()?;
    f.u16("Key length").emit()?;
    f.u16("Value length").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Log

async fn log_entries(cx: Cx, log: Span) -> Result<()> {
    let mut at = 0u64;
    let mut n = 0u64;
    while at < log.len && n < MAX_LOG_ENTRIES {
        let head = cx.read_avail(log.sub(at, LogEntryHeader::SIZE)).await?;
        if head.get(..4) != Some(b"loge".as_slice()) {
            // Not an entry: the rest of the circular buffer is unused (or
            // holds overwritten entries).
            let rest = log.tail(at);
            let zero = cx
                .read_avail(rest.sub(0, 4096))
                .await?
                .iter()
                .all(|&b| b == 0);
            cx.push(Node::new("Unused").span(rest).summary(if zero {
                format!("{}, zeros", size(rest.len))
            } else {
                size(rest.len)
            }))
            .await;
            break;
        }
        let len = u64::from(u32_le(&head, 8).unwrap_or(0));
        if len < 4096 || !len.is_multiple_of(4096) {
            cx.diag(
                Diagnostic::malformed(format!("log entry length {len:#x}")).at(log.sub(at, 12)),
            );
            break;
        }
        let span = log.sub(at, len);
        let seq = u64_le(&head, 16).unwrap_or(0);
        let count = u32_le(&head, 24).unwrap_or(0);
        let mut node = Node::new(format!("Log entry {n}"))
            .span(span)
            .summary(format!(
                "sequence {seq}, {}, {}",
                crate::formats::util::arcutil::count(count.into(), "descriptor", "descriptors"),
                size(len)
            ))
            .lazy(log_entry, span);
        if len <= cx.limits().max_read
            && let Some(d) = verify(&cx, span, u32_le(&head, 4).unwrap_or(0)).await?
        {
            node = node.diag(d);
        }
        cx.push(node).await;
        at = at.saturating_add(len);
        n = n.saturating_add(1);
    }
    Ok(())
}

async fn log_entry(cx: Cx, span: Span) -> Result<()> {
    let h = parse(
        &cx,
        span.sub(0, LogEntryHeader::SIZE),
        LE,
        &(),
        LogEntryHeader::layout,
    )
    .await?;
    cx.emit(LogEntryHeader::node(
        "Header",
        span.sub(0, LogEntryHeader::SIZE),
        LE,
    ));
    let count = u64::from(h.descriptors).min(span.len / 32);
    let descs = span.sub(LogEntryHeader::SIZE, count.saturating_mul(32));
    let data = cx.read_avail(descs).await?;
    // Data sectors follow the header and descriptors, from the next 4 KiB.
    let mut sector = LogEntryHeader::SIZE
        .saturating_add(count.saturating_mul(32))
        .next_multiple_of(4096);
    let pad = span.sub(
        descs.end().saturating_sub(span.offset),
        sector.saturating_sub(descs.end().saturating_sub(span.offset)),
    );
    // Descriptors, then the padding, then the data sectors (file order).
    let mut sectors = Vec::new();
    for i in 0..count {
        let at = to_usize(i.saturating_mul(32));
        let d = descs.sub(to_u64(at), 32);
        let sig = data.get(at..at.saturating_add(4)).unwrap_or_default();
        let file_offset = u64_le(&data, at.saturating_add(16)).unwrap_or(0);
        if sig == b"desc" {
            let sector_span = span.sub(sector, 4096);
            cx.push(
                struct_node(
                    format!("Data descriptor {i}"),
                    d,
                    LE,
                    (),
                    data_descriptor_layout,
                )
                .summary(format!("4 KiB to file offset {file_offset:#x}"))
                .target(sector_span),
            )
            .await;
            sectors.push(
                struct_node(
                    format!("Data sector {i}"),
                    sector_span,
                    LE,
                    (),
                    data_sector_layout,
                )
                .summary(format!("for file offset {file_offset:#x}")),
            );
            sector = sector.saturating_add(4096);
        } else {
            let len = u64_le(&data, at.saturating_add(8)).unwrap_or(0);
            cx.push(
                struct_node(
                    format!("Zero descriptor {i}"),
                    d,
                    LE,
                    (),
                    zero_descriptor_layout,
                )
                .summary(format!(
                    "{} of zeros at file offset {file_offset:#x}",
                    size(len)
                )),
            )
            .await;
        }
    }
    if !pad.is_empty() {
        cx.push(
            Node::new("Padding")
                .span(pad)
                .summary("to the first data sector"),
        )
        .await;
    }
    for node in sectors {
        cx.push(node).await;
    }
    Ok(())
}

fn data_descriptor_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Signature", 4).emit()?;
    f.u32("Trailing bytes")
        .hex()
        .desc("The last 4 bytes of the 4 KiB sector")
        .emit()?;
    f.u64("Leading bytes")
        .hex()
        .desc("The first 8 bytes of the 4 KiB sector")
        .emit()?;
    f.u64("File offset").hex().emit()?;
    f.u64("Sequence number").emit()?;
    Ok(())
}

fn zero_descriptor_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Signature", 4).emit()?;
    f.u32("Reserved").emit()?;
    f.u64("Zero length")
        .with(|&v, n| n.summary(size(v)))
        .emit()?;
    f.u64("File offset").hex().emit()?;
    f.u64("Sequence number").emit()?;
    Ok(())
}

fn data_sector_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Signature", 4).emit()?;
    f.u32("Sequence number (high)").emit()?;
    f.bytes("Data", 4084).emit()?;
    f.u32("Sequence number (low)").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// BAT and virtual disk

struct Disk {
    input: Input,
    bat: Span,
    block: u64,
    size: u64,
    chunk_ratio: u64,
    logical_sector: u64,
    has_parent: bool,
    log: Option<Span>,
    metadata: Option<Span>,
}

impl Disk {
    fn blocks(&self) -> u64 {
        self.size.div_ceil(self.block.max(1))
    }

    /// BAT index of payload block `i` (sector bitmap entries interleave).
    fn index(&self, i: u64) -> u64 {
        i.saturating_add(i.checked_div(self.chunk_ratio).unwrap_or(0))
    }

    /// BAT index of the sector bitmap entry of chunk `c`.
    fn bitmap_index(&self, c: u64) -> u64 {
        c.saturating_mul(self.chunk_ratio.saturating_add(1))
            .saturating_add(self.chunk_ratio)
    }

    /// Payload blocks whose 8-byte entry lies wholly in the BAT: every
    /// chunk of `chunk_ratio + 1` entries holds `chunk_ratio` of them.
    fn listed(&self) -> u64 {
        let entries = self.bat.len / 8;
        let chunk = self.chunk_ratio.saturating_add(1);
        let full = entries.checked_div(chunk).unwrap_or(0);
        let rest = entries.checked_rem(chunk).unwrap_or(0);
        full.saturating_mul(self.chunk_ratio)
            .saturating_add(rest.min(self.chunk_ratio))
    }

    async fn entry_at(&self, cx: &Cx, index: u64) -> Result<(Span, u64)> {
        let span = self.bat.sub(index.saturating_mul(8), 8);
        let raw = cx.read_avail(span).await?;
        Ok((span, u64_le(&raw, 0).unwrap_or(0)))
    }

    fn data(&self, entry: u64) -> Span {
        self.input
            .span
            .sub((entry >> 20).saturating_mul(MIB), self.block)
    }

    /// The sector bitmap block (1 MiB) an entry points at.
    fn bitmap(&self, entry: u64) -> Span {
        self.input.span.sub((entry >> 20).saturating_mul(MIB), MIB)
    }
}

/// What a BAT entry index holds: payload block `n`, the sector bitmap of
/// chunk `n`, or nothing (an entry past the disk size).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Payload(u64),
    Bitmap(u64),
    Padding,
}

impl Disk {
    fn slot(&self, i: u64) -> Slot {
        let chunk = self.chunk_ratio.saturating_add(1);
        let c = i.checked_div(chunk).unwrap_or(0);
        if i.saturating_add(1).is_multiple_of(chunk) {
            // Bitmap entries of chunks past the disk size are padding too.
            let chunks = self.blocks().div_ceil(self.chunk_ratio.max(1));
            return if c < chunks.max(1) {
                Slot::Bitmap(c)
            } else {
                Slot::Padding
            };
        }
        let b = i.saturating_sub(c);
        if b < self.blocks() {
            Slot::Payload(b)
        } else {
            Slot::Padding
        }
    }
}

async fn bat_entries(cx: Cx, d: Arc<Disk>) -> Result<()> {
    let entries = d.bat.len / 8;
    let mut i = 0u64;
    while i < entries {
        cx.progress(i, entries);
        let (span, entry) = d.entry_at(&cx, i).await?;
        let state = entry & 7;
        let offset = (entry >> 20).saturating_mul(MIB);
        match d.slot(i) {
            Slot::Bitmap(c) => {
                let mut n = Node::new(format!("Sector bitmap {c}"))
                    .span(span)
                    .value(Value::Enum {
                        raw: state,
                        bits: 3,
                        name: lookup(BITMAP_STATES, state),
                    })
                    .summary(format!(
                        "for blocks {}–{}{}",
                        c.saturating_mul(d.chunk_ratio),
                        c.saturating_add(1)
                            .saturating_mul(d.chunk_ratio)
                            .saturating_sub(1),
                        if state == 6 {
                            format!(", at {offset:#x}")
                        } else {
                            String::new()
                        }
                    ));
                if state == 6 {
                    n = n.target(d.bitmap(entry));
                }
                cx.push(n).await;
                i = i.saturating_add(1);
            }
            Slot::Padding => {
                // Entries past the disk size, up to the next bitmap entry.
                let start = i;
                while i < entries && d.slot(i) == Slot::Padding {
                    i = i.saturating_add(1);
                    if i.is_multiple_of(4096) {
                        cx.checkpoint().await;
                    }
                }
                let run = d.bat.sub(
                    start.saturating_mul(8),
                    i.saturating_sub(start).saturating_mul(8),
                );
                cx.push(Node::new("Unused entries").span(run).summary(format!(
                    "{} entries beyond the disk size",
                    i.saturating_sub(start)
                )))
                .await;
            }
            Slot::Payload(b) if entry == 0 => {
                // A run of not-present payload blocks.
                let start = i;
                let mut last = b;
                i = i.saturating_add(1);
                while i < entries {
                    let Slot::Payload(nb) = d.slot(i) else { break };
                    let (_, e) = d.entry_at(&cx, i).await?;
                    if e != 0 {
                        break;
                    }
                    last = nb;
                    i = i.saturating_add(1);
                }
                cx.push(
                    Node::new(if b == last {
                        format!("Block {b}")
                    } else {
                        format!("Blocks {b}–{last}")
                    })
                    .span(d.bat.sub(
                        start.saturating_mul(8),
                        i.saturating_sub(start).saturating_mul(8),
                    ))
                    .value(Value::Enum {
                        raw: 0,
                        bits: 3,
                        name: Some("not present"),
                    })
                    .summary(format!(
                        "guest {:#x}–{:#x}: {}",
                        b.saturating_mul(d.block),
                        last.saturating_add(1)
                            .saturating_mul(d.block)
                            .saturating_sub(1),
                        if d.has_parent {
                            "from the parent"
                        } else {
                            "not present (zeros)"
                        }
                    )),
                )
                .await;
            }
            Slot::Payload(b) => {
                let mut n = Node::new(format!("Block {b}"))
                    .span(span)
                    .value(Value::Enum {
                        raw: state,
                        bits: 3,
                        name: lookup(BAT_STATES, state),
                    })
                    .summary(format!(
                        "guest {:#x}: {}{}",
                        b.saturating_mul(d.block),
                        lookup(BAT_STATES, state).unwrap_or("unknown state"),
                        if matches!(state, 6 | 7) {
                            format!(", at {offset:#x}")
                        } else {
                            String::new()
                        }
                    ));
                if matches!(state, 6 | 7) {
                    n = n.target(d.data(entry));
                }
                cx.push(n).await;
                i = i.saturating_add(1);
            }
        }
    }
    Ok(())
}

async fn layout(cx: Cx, d: Arc<Disk>) -> Result<()> {
    let file = d.input.span;
    let mut r = Regions::default();
    r.add(0, KIB64, "File type identifier", None);
    r.add(KIB64, KIB64, "Header 1", None);
    r.add(2 * KIB64, KIB64, "Header 2", None);
    r.add(3 * KIB64, KIB64, "Region table 1", None);
    r.add(4 * KIB64, KIB64, "Region table 2", None);
    if let Some(log) = d.log {
        r.span(file, log, "Log");
    }
    if let Some(m) = d.metadata {
        r.span(file, m, "Metadata region");
    }
    r.span(file, d.bat, "Block allocation table");
    let entries = d.bat.len / 8;
    let chunk = d.chunk_ratio.saturating_add(1);
    let data = cx.read_avail(d.bat).await?;
    for (i, e) in data.as_chunks::<8>().0.iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        let i = to_u64(i);
        if i >= entries {
            break;
        }
        let entry = u64::from_le_bytes(*e);
        let state = entry & 7;
        if (i.saturating_add(1)).is_multiple_of(chunk) {
            if state == 6 {
                r.span(file, d.bitmap(entry), "Sector bitmap block");
            }
        } else if matches!(state, 6 | 7) {
            let b = i.saturating_sub(i.checked_div(chunk).unwrap_or(0));
            let span = d.data(entry);
            r.add(
                span.offset.saturating_sub(file.offset),
                span.len,
                "Payload block",
                Some(b.saturating_mul(d.block)),
            );
        }
    }
    r.emit(&cx, file, "not referenced by the BAT or the region table")
        .await;
    Ok(())
}

async fn virtual_disk(cx: Cx, d: Arc<Disk>) -> Result<()> {
    if d.has_parent {
        cx.diag(Diagnostic::note(
            "sectors absent from this file come from the parent; shown as zeros",
        ));
    }
    let mut list = PieceList::new(d.bat);
    let blocks = d.blocks();
    // Blocks whose entry lies (wholly) in the BAT; a missing entry reads as
    // 0 (not present), so the rest of the disk is one run of zeros. The
    // declared size can imply far more blocks than the file has entries.
    let listed = blocks.min(d.listed());
    let sectors_per_block = d.block.checked_div(d.logical_sector).unwrap_or(0);
    for i in 0..listed {
        cx.progress(i, blocks);
        let want = d.block.min(d.size.saturating_sub(list.len()));
        let (_, entry) = d.entry_at(&cx, d.index(i)).await?;
        match entry & 7 {
            6 => list.data(d.data(entry).sub(0, want)),
            7 if d.has_parent => {
                // Partially present: the chunk's sector bitmap says which
                // sectors are here (least significant bit first).
                let c = i.checked_div(d.chunk_ratio).unwrap_or(0);
                let (_, bentry) = d.entry_at(&cx, d.bitmap_index(c)).await?;
                let first = i
                    .checked_rem(d.chunk_ratio)
                    .unwrap_or(0)
                    .saturating_mul(sectors_per_block);
                let bits = if bentry & 7 == 6 {
                    cx.read_avail(
                        d.bitmap(bentry)
                            .sub(first / 8, sectors_per_block.div_ceil(8)),
                    )
                    .await?
                } else {
                    Vec::new()
                };
                let data = d.data(entry);
                let bit = |s: u64| {
                    bits.get(to_usize(s / 8))
                        .is_some_and(|b| b & (1u8 << (s % 8)) != 0)
                };
                let mut s = 0u64;
                let ss = d.logical_sector;
                while s < sectors_per_block && s.saturating_mul(ss) < want {
                    let present = bit(s);
                    let start = s;
                    while s < sectors_per_block && bit(s) == present {
                        s = s.saturating_add(1);
                    }
                    let a = start.saturating_mul(ss).min(want);
                    let b = s.saturating_mul(ss).min(want);
                    if present {
                        list.data(data.sub(a, b.saturating_sub(a)));
                    } else {
                        list.data(Span::zeros(b.saturating_sub(a)));
                    }
                    cx.checkpoint().await;
                }
            }
            7 => list.data(d.data(entry).sub(0, want)),
            _ => list.data(Span::zeros(want)),
        }
    }
    // What the unlisted blocks would add one by one: a block each, up to
    // the disk size.
    let unlisted = blocks.saturating_sub(listed).saturating_mul(d.block);
    let rest = unlisted.min(d.size.saturating_sub(list.len()));
    list.data(Span::zeros(rest));
    let span = list.finish(&cx, "vhdx-blocks").await?;
    dissect_or_data(cx, d.input.nested(span)).await
}
