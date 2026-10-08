//! Microsoft VHDX virtual disks.
//!
//! Fixed layout: a file type identifier at 0, two headers at 64 and
//! 128 KiB (the one with the higher sequence number is current), two region
//! tables at 192 and 256 KiB. The region table locates the metadata region
//! (block size, disk size, sector sizes, ...) and the block allocation
//! table, from which the virtual disk is assembled.

use std::sync::Arc;

use crate::bytes::{u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{PieceList, crc32c, guid_le, size};
use crate::formats::{Format, Input, Probe, dissect_or_data};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, Value, flag};

const LE: Endian = Endian::Little;
const KIB64: u64 = 64 * 1024;
const MIB: u64 = 1024 * 1024;
/// Entries listed from a table before assuming corruption.
const MAX_ENTRIES: u64 = 2047;

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
        file_write: guid "File write GUID",
        data_write: guid "Data write GUID",
        log_guid: guid "Log GUID",
        log_version: u16 "Log version",
        version: u16 "Version",
        log_length: u32 "Log length" .with(|&v, n| n.summary(size(v.into()))),
        log_offset: u64 "Log offset" .hex(),
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

const REGIONS: &[(&str, &str)] = &[
    (
        "2dc27766-f623-4200-9d64-115e9bfd4a08",
        "Block allocation table",
    ),
    ("8b7ca206-4790-4b9a-b8fe-575f050f886e", "Metadata"),
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

fn guid_name(table: &[(&str, &'static str)], g: &Guid) -> Option<&'static str> {
    let text = g.to_string();
    let key = text.trim_matches(|c| c == '{' || c == '}');
    table.iter().find(|(k, _)| *k == key).map(|(_, n)| *n)
}

record! {
    pub struct RegionEntry {
        id: guid "Region GUID" .with(|g, n| match guid_name(REGIONS, g) { Some(s) => n.summary(s), None => n }),
        offset: u64 "File offset" .hex(),
        length: u32 "Length" .with(|&v, n| n.summary(size(v.into()))),
        required: u32 "Required",
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

const BAT_STATES: EnumTable = &[
    (0, "not present"),
    (1, "undefined"),
    (2, "zero"),
    (3, "unmapped"),
    (6, "fully present"),
    (7, "partially present"),
];

/// Checks the CRC-32C of a structure whose checksum is at offset 4.
async fn verify(cx: &Cx, span: Span, stored: u32) -> Result<Option<Diagnostic>> {
    let mut data = cx.read_avail(span).await?;
    if let Some(f) = data.get_mut(4..8) {
        f.fill(0);
    }
    let computed = crc32c(&data);
    Ok((computed != stored).then(|| {
        Diagnostic::warning(format!("checksum mismatch: computed {computed:#010x}")).at(span)
    }))
}

#[derive(Debug, Default)]
struct Params {
    block: u64,
    disk_size: u64,
    logical_sector: u64,
    has_parent: bool,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let ident = file.sub(0, 8 + 512);
    let creator = crate::text::utf16z(&cx.read_avail(ident.sub(8, 512)).await?, LE).0;
    cx.emit(
        Node::new("File type identifier")
            .span(ident)
            .summary(format!("created by {creator:?}")),
    );

    // Current header: valid signature and checksum, highest sequence.
    let mut current: Option<(u64, Header)> = None;
    for (i, at) in [KIB64, 2 * KIB64].into_iter().enumerate() {
        let span = file.sub(at, 4096);
        let name = format!("Header {}", i.saturating_add(1));
        match parse(&cx, span, LE, &(), Header::layout).await {
            Ok(h) if h.signature == "head" => {
                let bad = verify(&cx, span, h.checksum).await?;
                let mut node =
                    Header::node(name, span, LE).summary(format!("sequence {}", h.sequence));
                if let Some(d) = bad {
                    node = node.diag(d);
                } else if current.as_ref().is_none_or(|(s, _)| h.sequence > *s) {
                    current = Some((h.sequence, h));
                }
                cx.emit(node);
            }
            Ok(_) => cx.emit(
                Node::new(name)
                    .span(span)
                    .diag(Diagnostic::malformed("bad signature")),
            ),
            Err(e) => cx.emit(Node::new(name).span(span).diag(e)),
        }
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

    let mut params = Params::default();
    let mut bat = None;
    for (kind, offset, len) in regions {
        let span = file.sub(offset, len.into());
        match kind {
            Some("Metadata") => {
                params = metadata_params(&cx, span).await?;
                cx.emit(Node::new("Metadata region").span(span).lazy(metadata, span));
            }
            Some("Block allocation table") => bat = Some(span),
            _ => cx.emit(Node::new("Unknown region").span(span)),
        }
    }
    cx.annotate(format!(
        "VHDX {} disk, {}, {} blocks",
        if params.has_parent {
            "differencing"
        } else {
            "dynamic/fixed"
        },
        size(params.disk_size),
        size(params.block)
    ));
    let Some(bat) = bat else {
        return Err(Diagnostic::malformed("no block allocation table region"));
    };
    if !params.block.is_power_of_two() || params.block < MIB || params.logical_sector == 0 {
        cx.emit(Node::new("Block allocation table").span(bat));
        return Err(Diagnostic::malformed(format!(
            "block size {:#x}",
            params.block
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
    });
    cx.emit(
        Node::new("Block allocation table")
            .span(bat)
            .summary(format!("chunk ratio {chunk_ratio}"))
            .lazy(bat_entries, disk.clone()),
    );
    cx.emit(if params.has_parent {
        Node::new("Virtual disk").diag(Diagnostic::unsupported(
            "differencing disk: absent blocks come from the parent",
        ))
    } else {
        Node::new("Virtual disk")
            .summary(size(params.disk_size))
            .lazy(virtual_disk, disk)
    });
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
    Ok(())
}

/// Reads the metadata items the dissector needs.
async fn metadata_params(cx: &Cx, region: Span) -> Result<Params> {
    let mut p = Params::default();
    let head = cx.read_avail(region.sub(0, 32)).await?;
    let count = u64::from(crate::bytes::u16_le(&head, 10).unwrap_or(0)).min(MAX_ENTRIES);
    let table = cx
        .read_avail(region.sub(32, count.saturating_mul(32)))
        .await?;
    for e in table.as_chunks::<32>().0 {
        let id = guid_le(e.get(..16).unwrap_or_default());
        let offset = u64::from(u32_le(e, 16).unwrap_or(0));
        let value = cx.read_avail(region.sub(offset, 8)).await?;
        match guid_name(ITEMS, &id) {
            Some("File parameters") => {
                p.block = u32_le(&value, 0).unwrap_or(0).into();
                p.has_parent = u32_le(&value, 4).unwrap_or(0) & 2 != 0;
            }
            Some("Virtual disk size") => p.disk_size = u64_le(&value, 0).unwrap_or(0),
            Some("Logical sector size") => p.logical_sector = u32_le(&value, 0).unwrap_or(0).into(),
            _ => {}
        }
        cx.checkpoint().await;
    }
    Ok(p)
}

async fn metadata(cx: Cx, region: Span) -> Result<()> {
    let head = cx.read_avail(region.sub(0, 32)).await?;
    let count = u64::from(crate::bytes::u16_le(&head, 10).unwrap_or(0)).min(MAX_ENTRIES);
    cx.emit(
        Node::new("Table header")
            .span(region.sub(0, 32))
            .value(Value::Text(crate::text::until_nul(
                head.get(..8).unwrap_or_default(),
            )))
            .summary(format!("{count} entries")),
    );
    for i in 0..count {
        let span = region.sub(32u64.saturating_add(i.saturating_mul(32)), 32);
        let e = parse(&cx, span, LE, &(), MetadataEntry::layout).await?;
        let value = region.sub(e.offset.into(), e.length.into());
        let data = cx.read_avail(value).await?;
        let shown = match guid_name(ITEMS, &e.id) {
            Some("File parameters") => format!(
                "block size {}, flags {:#x}",
                size(u32_le(&data, 0).unwrap_or(0).into()),
                u32_le(&data, 4).unwrap_or(0)
            ),
            Some("Virtual disk size") => size(u64_le(&data, 0).unwrap_or(0)),
            Some("Logical sector size" | "Physical sector size") => {
                format!("{} bytes", u32_le(&data, 0).unwrap_or(0))
            }
            Some("Virtual disk id (page 83 data)") => guid_le(&data).to_string(),
            _ => format!("{} bytes", data.len()),
        };
        let name = guid_name(ITEMS, &e.id).unwrap_or("Unknown item");
        cx.push(
            MetadataEntry::node(name, span, LE)
                .summary(shown)
                .target(value),
        )
        .await;
    }
    Ok(())
}

struct Disk {
    input: Input,
    bat: Span,
    block: u64,
    size: u64,
    chunk_ratio: u64,
}

impl Disk {
    fn blocks(&self) -> u64 {
        self.size.div_ceil(self.block.max(1))
    }

    /// BAT index of payload block `i` (sector bitmap entries interleave).
    fn index(&self, i: u64) -> u64 {
        i.saturating_add(i.checked_div(self.chunk_ratio).unwrap_or(0))
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

    async fn entry(&self, cx: &Cx, i: u64) -> Result<(Span, u64)> {
        let span = self.bat.sub(self.index(i).saturating_mul(8), 8);
        let raw = cx.read(span).await?;
        Ok((span, u64_le(&raw, 0).unwrap_or(0)))
    }

    fn data(&self, entry: u64) -> Span {
        self.input
            .span
            .sub((entry >> 20).saturating_mul(MIB), self.block)
    }
}

async fn bat_entries(cx: Cx, d: Arc<Disk>) -> Result<()> {
    cx.set_count(Count::Exact(d.blocks()));
    for i in 0..d.blocks() {
        let (span, entry) = d.entry(&cx, i).await?;
        let state = entry & 7;
        let mut node = Node::new(format!("Block {i}"))
            .span(span)
            .value(Value::Enum {
                raw: state,
                bits: 3,
                name: crate::value::lookup(BAT_STATES, state),
            });
        if matches!(state, 6 | 7) {
            node = node.target(d.data(entry));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn virtual_disk(cx: Cx, d: Arc<Disk>) -> Result<()> {
    let mut list = PieceList::new(d.bat);
    let blocks = d.blocks();
    // Blocks whose entry lies (wholly) in the BAT; a missing entry reads as
    // 0 (not present), so the rest of the disk is one run of zeros. The
    // declared size can imply far more blocks than the file has entries.
    let listed = blocks.min(d.listed());
    for i in 0..listed {
        cx.progress(i, blocks);
        let want = d.block.min(d.size.saturating_sub(list.len()));
        let (_, entry) = d.entry(&cx, i).await?;
        let step = match entry & 7 {
            6 | 7 => {
                list.data(d.data(entry).sub(0, want));
                Ok(())
            }
            _ => list.hole(&cx, want),
        };
        if let Err(e) = step {
            cx.diag(e);
            break;
        }
    }
    // What the unlisted blocks would add one by one: a block each, up to
    // the disk size.
    let unlisted = blocks.saturating_sub(listed).saturating_mul(d.block);
    let rest = unlisted.min(d.size.saturating_sub(list.len()));
    if let Err(e) = list.hole(&cx, rest) {
        cx.diag(e);
    }
    let span = list.finish(&cx, "vhdx-blocks").await?;
    dissect_or_data(cx, d.input.nested(span)).await
}
