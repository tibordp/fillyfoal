//! Android platform binaries: dynamic partitions (`super.img` logical
//! partition metadata), vendor boot images, bootloader bundles, MediaTek
//! image headers, Samsung partition tables (PIT), Qualcomm device-tree
//! tables (QCDT), ART profiles, compiled SELinux file contexts, HPROF heap
//! dumps, method traces and binary logcat.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::text::scan::Lines;
use crate::formats::util::datakit::{hex_string, size};
use crate::formats::{Codec, Head, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Radix, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    }
}

fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

fn align_up(v: u64, to: u64) -> u64 {
    if to <= 1 {
        return v;
    }
    v.div_ceil(to).saturating_mul(to)
}

// ---------------------------------------------------------------------------
// Logical partition metadata (super.img)

const LP_GEOMETRY_AT: u64 = 4096;
const LP_GEOMETRY_SIZE: u64 = 4096;
const SECTOR: u64 = 512;

fn super_probe(h: &Head<'_>) -> bool {
    h.at(4096, b"gDla") && u32_le(h.data, 4100) == Some(52)
}

declare_format!(pub SUPER = "android-super", "Android dynamic partitions (super image)", ["img"], "application/x-android-super",
    Probe::Custom(super_probe), lp_super);

fn lp_geometry(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32)> {
    f.ascii("Magic", 4).desc("0x616c4467").emit()?;
    f.u32("Struct size").emit()?;
    f.bytes("Checksum (SHA-256)", 32).emit()?;
    let max = f.u32("Metadata max size").emit()?;
    let slots = f.u32("Metadata slot count").emit()?;
    f.u32("Logical block size").emit()?;
    Ok((max, slots))
}

/// A table descriptor: offset (relative to the tables), count, entry size.
type TableDesc = (u32, u32, u32);

struct LpHeader {
    header_size: u32,
    tables_size: u32,
    partitions: TableDesc,
    extents: TableDesc,
    groups: TableDesc,
    devices: TableDesc,
}

fn lp_header(f: &mut Fields<'_>, _: &()) -> Result<LpHeader> {
    f.ascii("Magic", 4).desc("0x414c5030").emit()?;
    f.u16("Major version").emit()?;
    let minor = f.u16("Minor version").emit()?;
    let header_size = f.u32("Header size").emit()?;
    f.bytes("Header checksum (SHA-256)", 32).emit()?;
    let tables_size = f.u32("Tables size").emit()?;
    f.bytes("Tables checksum (SHA-256)", 32).emit()?;
    let desc = |f: &mut Fields<'_>,
                a: &'static str,
                b: &'static str,
                c: &'static str|
     -> Result<TableDesc> {
        Ok((f.u32(a).hex().emit()?, f.u32(b).emit()?, f.u32(c).emit()?))
    };
    let partitions = desc(
        f,
        "Partitions offset",
        "Partition count",
        "Partition entry size",
    )?;
    let extents = desc(f, "Extents offset", "Extent count", "Extent entry size")?;
    let groups = desc(f, "Groups offset", "Group count", "Group entry size")?;
    let devices = desc(
        f,
        "Block devices offset",
        "Block device count",
        "Block device entry size",
    )?;
    if minor >= 2 && f.remaining() >= 4 {
        f.u32("Flags").flags(LP_HEADER_FLAGS).emit()?;
    }
    Ok(LpHeader {
        header_size,
        tables_size,
        partitions,
        extents,
        groups,
        devices,
    })
}

const SLOT_SUFFIXED: FlagTable = &[flag(1, "SLOT_SUFFIXED")];
const LP_HEADER_FLAGS: FlagTable = &[flag(1, "VIRTUAL_AB_DEVICE"), flag(2, "OVERLAYS_ACTIVE")];
const PIT_ATTRS: FlagTable = &[flag(1, "WRITE"), flag(2, "STL")];
const PIT_UPDATE: FlagTable = &[flag(1, "FOTA"), flag(2, "SECURE")];

const LP_PARTITION_ATTRS: FlagTable = &[
    flag(1, "READONLY"),
    flag(2, "SLOT_SUFFIXED"),
    flag(4, "UPDATED"),
    flag(8, "DISABLED"),
];

async fn lp_super(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Reserved").span(file.sub(0, LP_GEOMETRY_AT)));
    let geo_span = file.sub(LP_GEOMETRY_AT, 52);
    let (max, slots) = crate::fields::parse(&cx, geo_span, LE, &(), lp_geometry).await?;
    cx.emit(struct_node("Geometry", geo_span, LE, (), lp_geometry));
    cx.emit(struct_node(
        "Backup geometry",
        file.sub(LP_GEOMETRY_AT.saturating_add(LP_GEOMETRY_SIZE), 52),
        LE,
        (),
        lp_geometry,
    ));
    let meta_at = LP_GEOMETRY_AT.saturating_add(LP_GEOMETRY_SIZE.saturating_mul(2));
    let head = file.sub(meta_at, 256);
    let h = crate::fields::parse(&cx, head, LE, &(), lp_header).await?;
    cx.emit(struct_node(
        "Metadata header (slot 0)",
        head.sub(0, h.header_size.into()),
        LE,
        (),
        lp_header,
    ));
    let tables = file.sub_exact(
        meta_at.saturating_add(h.header_size.into()),
        h.tables_size.into(),
    )?;
    let table = |d: TableDesc| tables.sub(d.0.into(), u64::from(d.1).saturating_mul(d.2.into()));
    // Block devices and groups (small).
    let devices = cx.read(table(h.devices)).await?;
    let device_names: Vec<String> = devices
        .chunks(chunk_size(h.devices.2))
        .map(|d| zstr(d.get(24..60).unwrap_or_default()))
        .collect();
    let groups = cx.read(table(h.groups)).await?;
    let group_names: Vec<String> = groups
        .chunks(chunk_size(h.groups.2))
        .map(|g| zstr(g.get(..36).unwrap_or_default()))
        .collect();
    cx.emit(
        Node::new("Block devices")
            .span(table(h.devices))
            .summary(device_names.join(", "))
            .lazy(lp_devices, (table(h.devices), h.devices.2)),
    );
    cx.emit(
        Node::new("Groups")
            .span(table(h.groups))
            .summary(group_names.join(", "))
            .lazy(lp_groups, (table(h.groups), h.groups.2)),
    );
    let extents = cx.read(table(h.extents)).await?;
    let parts = cx.read(table(h.partitions)).await?;
    let mut names = Vec::new();
    let pspan = table(h.partitions);
    for (i, p) in parts.chunks(chunk_size(h.partitions.2)).enumerate() {
        if p.len() < 52 {
            break;
        }
        let name = zstr(p.get(..36).unwrap_or_default());
        let attrs = u32_le(p, 36).unwrap_or(0);
        let first = u32_le(p, 40).unwrap_or(0);
        let count = u32_le(p, 44).unwrap_or(0);
        let group = u32_le(p, 48).unwrap_or(0);
        let mut pieces = Vec::new();
        let mut total = 0u64;
        for e in first..first.saturating_add(count.min(4096)) {
            let at = crate::bytes::to_usize(u64::from(e).saturating_mul(h.extents.2.into()));
            let Some(ext) = extents.get(at..at.saturating_add(24)) else {
                break;
            };
            let sectors = u64_le(ext, 0).unwrap_or(0);
            let kind = u32_le(ext, 8).unwrap_or(0);
            let data = u64_le(ext, 12).unwrap_or(0);
            let source = u32_le(ext, 20).unwrap_or(0);
            let len = sectors.saturating_mul(SECTOR);
            total = total.saturating_add(len);
            pieces.push(if kind == 0 && source == 0 {
                file.sub(data.saturating_mul(SECTOR), len)
            } else {
                Span::zeros(len)
            });
        }
        let entry = pspan.sub(
            to_u64(i).saturating_mul(h.partitions.2.into()),
            h.partitions.2.into(),
        );
        let group_name = usize::try_from(group)
            .ok()
            .and_then(|g| group_names.get(g))
            .cloned()
            .unwrap_or_default();
        let (flags, _) = crate::value::decode_flags(LP_PARTITION_ATTRS, attrs.into());
        let summary = format!(
            "{}, {count} extent(s), group {group_name}{}",
            size(total),
            if flags.is_empty() {
                String::new()
            } else {
                format!(", {}", flags.join("|"))
            }
        );
        names.push(name.clone());
        let node = if pieces.is_empty() {
            Node::new(name).span(entry).summary(summary)
        } else {
            let data = cx.add_pieces(
                Origin {
                    parent: entry,
                    transform: "lp-extents",
                },
                pieces,
            )?;
            embedded(name, input.nested(data))
                .summary(summary)
                .target(entry)
        };
        cx.push(node).await;
    }
    cx.annotate(format!(
        "Android super image, {} partitions: {} ({slots} metadata slots of {})",
        names.len(),
        names.join(", "),
        size(max.into())
    ));
    Ok(())
}

/// A table entry size usable with `chunks` (never zero).
fn chunk_size(n: u32) -> usize {
    crate::bytes::to_usize(n.into()).max(1)
}

async fn lp_devices(cx: Cx, (span, entry): (Span, u32)) -> Result<()> {
    let mut at = 0u64;
    while at.saturating_add(64) <= span.len && entry >= 64 {
        let one = span.sub(at, entry.into());
        cx.push(struct_node("Block device", one, LE, (), |f, _| {
            f.u64("First logical sector").emit()?;
            f.u32("Alignment").emit()?;
            f.u32("Alignment offset").emit()?;
            f.u64("Size").with(|&s, n| n.summary(size(s))).emit()?;
            f.ascii("Partition name", 36).emit()?;
            f.u32("Flags").flags(SLOT_SUFFIXED).emit()?;
            Ok(())
        }))
        .await;
        at = at.saturating_add(entry.into());
    }
    Ok(())
}

async fn lp_groups(cx: Cx, (span, entry): (Span, u32)) -> Result<()> {
    let mut at = 0u64;
    while at.saturating_add(48) <= span.len && entry >= 48 {
        let one = span.sub(at, entry.into());
        cx.push(struct_node("Group", one, LE, (), |f, _| {
            f.ascii("Name", 36).emit()?;
            f.u32("Flags").flags(SLOT_SUFFIXED).emit()?;
            f.u64("Maximum size")
                .with(|&s, n| {
                    n.summary(if s == 0 {
                        "unlimited".to_owned()
                    } else {
                        size(s)
                    })
                })
                .emit()?;
            Ok(())
        }))
        .await;
        at = at.saturating_add(entry.into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Vendor boot image (vendor_boot.img)

declare_format!(pub VENDOR_BOOT = "android-vendor-boot", "Android vendor boot image", ["img"], "application/x-android-vendor-boot",
    Probe::Custom(|h| h.starts_with(b"VNDRBOOT") && u32_le(h.data, 8).is_some_and(|v| (3..=4).contains(&v))), vendor_boot);

struct VendorBoot {
    version: u32,
    page: u32,
    ramdisk: u32,
    dtb: u32,
    table: u32,
    entries: u32,
    entry_size: u32,
    bootconfig: u32,
}

fn vendor_layout(f: &mut Fields<'_>, _: &()) -> Result<VendorBoot> {
    f.ascii("Magic", 8).emit()?;
    let version = f.u32("Header version").emit()?;
    let page = f.u32("Page size").emit()?;
    f.u32("Kernel load address").hex().emit()?;
    f.u32("Ramdisk load address").hex().emit()?;
    let ramdisk = f
        .u32("Vendor ramdisk size")
        .with(|&s, n| n.summary(size(s.into())))
        .emit()?;
    f.ascii("Command line", 2048).emit()?;
    f.u32("Tags address").hex().emit()?;
    f.ascii("Product name", 16).emit()?;
    f.u32("Header size").emit()?;
    let dtb = f
        .u32("DTB size")
        .with(|&s, n| n.summary(size(s.into())))
        .emit()?;
    f.u64("DTB load address").hex().emit()?;
    let mut b = VendorBoot {
        version,
        page,
        ramdisk,
        dtb,
        table: 0,
        entries: 0,
        entry_size: 0,
        bootconfig: 0,
    };
    if version >= 4 {
        b.table = f.u32("Ramdisk table size").emit()?;
        b.entries = f.u32("Ramdisk table entries").emit()?;
        b.entry_size = f.u32("Ramdisk table entry size").emit()?;
        b.bootconfig = f.u32("Bootconfig size").emit()?;
    }
    Ok(b)
}

const RAMDISK_TYPE: EnumTable = &[(0, "none"), (1, "platform"), (2, "recovery"), (3, "dlkm")];

async fn vendor_boot(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = file.sub(0, 2128);
    let b = crate::fields::parse(&cx, head, LE, &(), vendor_layout).await?;
    let page = u64::from(b.page);
    if page == 0 || !page.is_power_of_two() || page > 1 << 20 {
        return Err(Diagnostic::malformed(format!("page size {page}")).at(file.sub(12, 4)));
    }
    let header_len = if b.version >= 4 { 2128 } else { 2112 };
    cx.emit(
        struct_node("Header", file.sub(0, header_len), LE, (), vendor_layout)
            .summary(format!("version {}", b.version)),
    );
    let mut at = align_up(header_len, page);
    let ramdisk = file.sub(at, b.ramdisk.into());
    at = align_up(at.saturating_add(b.ramdisk.into()), page);
    let dtb = file.sub(at, b.dtb.into());
    at = align_up(at.saturating_add(b.dtb.into()), page);
    let table = file.sub(at, b.table.into());
    at = align_up(at.saturating_add(b.table.into()), page);
    let bootconfig = file.sub(at, b.bootconfig.into());
    if b.entries > 0 && b.entry_size >= 108 {
        cx.emit(
            Node::new("Vendor ramdisks")
                .span(ramdisk)
                .summary(format!("{} ramdisks, {}", b.entries, size(ramdisk.len)))
                .lazy(
                    vendor_ramdisks,
                    (input, ramdisk, table, b.entries, b.entry_size),
                ),
        );
    } else if !ramdisk.is_empty() {
        cx.emit(embedded("Vendor ramdisk", input.nested(ramdisk)).summary(size(ramdisk.len)));
    }
    if !dtb.is_empty() {
        cx.emit(embedded("DTB", input.nested(dtb)).summary(size(dtb.len)));
    }
    if !table.is_empty() {
        cx.emit(
            Node::new("Ramdisk table")
                .span(table)
                .summary(format!("{} entries", b.entries)),
        );
    }
    if !bootconfig.is_empty() {
        cx.emit(embedded("Bootconfig", input.nested(bootconfig)).summary(size(bootconfig.len)));
    }
    cx.annotate(format!(
        "Android vendor boot image v{}, ramdisk {}, DTB {}",
        b.version,
        size(ramdisk.len),
        size(dtb.len)
    ));
    Ok(())
}

async fn vendor_ramdisks(
    cx: Cx,
    (input, ramdisk, table, entries, entry_size): (Input, Span, Span, u32, u32),
) -> Result<()> {
    for i in 0..entries.min(256) {
        let entry = table.sub_exact(
            u64::from(i).saturating_mul(entry_size.into()),
            entry_size.into(),
        )?;
        let e = cx.read(entry).await?;
        let len = u32_le(&e, 0).unwrap_or(0);
        let offset = u32_le(&e, 4).unwrap_or(0);
        let kind = u32_le(&e, 8).unwrap_or(0);
        let name = zstr(e.get(12..44).unwrap_or_default());
        let label = if name.is_empty() {
            format!("Ramdisk {i}")
        } else {
            name
        };
        cx.push(
            embedded(label, input.nested(ramdisk.sub(offset.into(), len.into())))
                .summary(format!(
                    "{}, {}",
                    lookup(RAMDISK_TYPE, kind.into()).unwrap_or("?"),
                    size(len.into())
                ))
                .target(entry),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bootloader image bundle (BOOTLDR!)

declare_format!(pub BOOTLDR = "android-bootloader", "Android bootloader image bundle", ["img"], "application/x-android-bootloader",
    Probe::Custom(|h| h.starts_with(b"BOOTLDR!") && u32_le(h.data, 8).is_some_and(|n| (1..=256).contains(&n))), bootldr);

async fn bootldr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 20)).await?;
    let count = u32_le(&head, 8).unwrap_or(0);
    let start = u32_le(&head, 12).unwrap_or(0);
    cx.emit(struct_node("Header", file.sub(0, 20), LE, (), |f, _| {
        f.ascii("Magic", 8).emit()?;
        f.u32("Image count").emit()?;
        f.u32("Data offset").hex().emit()?;
        f.u32("Data size").emit()?;
        Ok(())
    }));
    let mut at = u64::from(start);
    let mut names = Vec::new();
    for i in 0..count {
        let entry = file.sub_exact(20u64.saturating_add(u64::from(i).saturating_mul(68)), 68)?;
        let e = cx.read(entry).await?;
        let name = zstr(e.get(..64).unwrap_or_default());
        let len = u64::from(u32_le(&e, 64).unwrap_or(0));
        names.push(name.clone());
        cx.push(
            embedded(name, input.nested(file.sub(at, len)))
                .summary(size(len))
                .target(entry),
        )
        .await;
        at = at.saturating_add(len);
    }
    cx.annotate(format!(
        "Android bootloader bundle, {count} images: {}",
        names.join(", ")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// MediaTek image header

const MTK_MAGIC: &[u8] = b"\x88\x16\x88\x58";

declare_format!(pub MTK = "mtk-image", "MediaTek image (with partition header)", ["img", "bin"], "application/x-mtk-image",
    Probe::Custom(|h| h.starts_with(MTK_MAGIC) && h.data.get(8).is_some_and(u8::is_ascii_graphic)), mtk);

async fn mtk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    let mut names = Vec::new();
    while at < file.len {
        let head = cx.read_avail(file.sub(at, 512)).await?;
        if !head.starts_with(MTK_MAGIC) {
            cx.emit(Node::new("Trailing data").span(file.tail(at)));
            break;
        }
        let len = u64::from(u32_le(&head, 4).unwrap_or(0));
        let name = zstr(head.get(8..40).unwrap_or_default());
        let header = file.sub(at, 512);
        let data = file.sub(at.saturating_add(512), len);
        names.push(name.clone());
        cx.push(
            Node::new(name)
                .span(file.sub(at, len.saturating_add(512)))
                .summary(size(len))
                .lazy(mtk_part, (input, header, data)),
        )
        .await;
        let next = at.saturating_add(512).saturating_add(len);
        // Images are concatenated, sometimes padded to 16 bytes.
        let probe = cx.read_avail(file.sub(next, 4)).await?;
        at = if probe.starts_with(MTK_MAGIC) {
            next
        } else {
            align_up(next, 16)
        };
    }
    cx.annotate(format!("MediaTek image: {}", names.join(", ")));
    Ok(())
}

async fn mtk_part(cx: Cx, (input, header, data): (Input, Span, Span)) -> Result<()> {
    cx.emit(struct_node("Header", header, LE, (), |f, _| {
        f.u32("Magic").hex().emit()?;
        f.u32("Data size").emit()?;
        f.ascii("Name", 32).emit()?;
        f.u32("Load address").hex().emit()?;
        f.u32("Mode").hex().emit()?;
        Ok(())
    }));
    cx.emit(embedded("Data", input.nested(data)).summary(size(data.len)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Samsung partition information table (.pit)

declare_format!(pub PIT = "samsung-pit", "Samsung partition information table", ["pit"], "application/x-samsung-pit",
    Probe::Custom(|h| h.starts_with(b"\x76\x98\x34\x12") && u32_le(h.data, 4).is_some_and(|n| (1..=512).contains(&n) && u64::from(n).saturating_mul(132).saturating_add(28) <= h.len)), pit);

const PIT_DEVICE: EnumTable = &[
    (0, "OneNAND"),
    (1, "File/FAT"),
    (2, "MMC"),
    (3, "All"),
    (8, "UFS"),
];

fn pit_entry(f: &mut Fields<'_>, _: &()) -> Result<String> {
    f.u32("Binary type")
        .enumeration(&[(0, "AP"), (1, "CP")])
        .emit()?;
    f.u32("Device type").enumeration(PIT_DEVICE).emit()?;
    f.u32("Identifier").emit()?;
    f.u32("Attributes").flags(PIT_ATTRS).emit()?;
    f.u32("Update attributes").flags(PIT_UPDATE).emit()?;
    f.u32("Block size or offset").emit()?;
    f.u32("Block count").emit()?;
    f.u32("File offset (obsolete)").emit()?;
    f.u32("File size (obsolete)").emit()?;
    let name = f.ascii("Partition name", 32).emit()?;
    f.ascii("Flash file name", 32).emit()?;
    f.ascii("FOTA file name", 32).emit()?;
    Ok(name)
}

async fn pit(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 28)).await?;
    let count = u32_le(&head, 4).unwrap_or(0);
    cx.emit(struct_node("Header", file.sub(0, 28), LE, (), |f, _| {
        f.u32("Magic").hex().emit()?;
        f.u32("Entry count").emit()?;
        f.ascii("Com/tar tag", 8).emit()?;
        f.ascii("CPU/BL tag", 8).emit()?;
        f.u32("Unknown").emit()?;
        Ok(())
    }));
    cx.set_count(Count::Exact(u64::from(count).saturating_add(1)));
    for i in 0..count {
        let span = file.sub_exact(28u64.saturating_add(u64::from(i).saturating_mul(132)), 132)?;
        let block = cx.block(span).await?;
        let name = pit_entry(&mut Fields::new(&block, LE), &())?;
        let e = &block.data;
        let blocks = u32_le(e, 24).unwrap_or(0);
        let flash = zstr(e.get(68..100).unwrap_or_default());
        cx.push(struct_node(name, span, LE, (), pit_entry).summary(format!(
            "id {}, {blocks} blocks, {flash}",
            u32_le(e, 8).unwrap_or(0)
        )))
        .await;
    }
    cx.annotate(format!("Samsung PIT, {count} partitions"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Qualcomm device-tree table (QCDT)

declare_format!(pub QCDT = "qcdt", "Qualcomm device tree table (dt.img)", ["img"], "application/x-qcdt",
    Probe::Custom(|h| h.starts_with(b"QCDT") && u32_le(h.data, 4).is_some_and(|v| (1..=3).contains(&v))), qcdt);

async fn qcdt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 12)).await?;
    let version = u32_le(&head, 4).unwrap_or(0);
    let count = u32_le(&head, 8).unwrap_or(0);
    cx.emit(struct_node("Header", file.sub(0, 12), LE, (), |f, _| {
        f.ascii("Magic", 4).emit()?;
        f.u32("Version").emit()?;
        f.u32("Entry count").emit()?;
        Ok(())
    }));
    let entry_size: u64 = match version {
        1 => 20,
        2 => 24,
        _ => 40,
    };
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..count.min(4096) {
        let span = file.sub_exact(
            12u64.saturating_add(u64::from(i).saturating_mul(entry_size)),
            entry_size,
        )?;
        let e = cx.read(span).await?;
        let words: Vec<u32> = (0..to_u64(e.len()) / 4)
            .filter_map(|w| u32_le(&e, crate::bytes::to_usize(w.saturating_mul(4))))
            .collect();
        let (platform, variant) = (
            words.first().copied().unwrap_or(0),
            words.get(1).copied().unwrap_or(0),
        );
        let n = words.len();
        let offset = words.get(n.saturating_sub(2)).copied().unwrap_or(0);
        let len = words.get(n.saturating_sub(1)).copied().unwrap_or(0);
        let soc_rev = if version == 1 {
            words.get(2)
        } else {
            words.get(3)
        }
        .copied()
        .unwrap_or(0);
        let summary = format!(
            "platform {platform}, variant {variant:#x}, SoC rev {soc_rev:#x}, DTB at {offset:#x} ({len} bytes)"
        );
        let node = if seen.insert(offset) {
            embedded(
                format!("Entry {i}"),
                input.nested(file.sub(offset.into(), len.into())),
            )
            .target(span)
        } else {
            Node::new(format!("Entry {i}"))
                .span(span)
                .desc("Shares a DTB with an earlier entry")
        };
        cx.push(node.summary(summary)).await;
    }
    cx.annotate(format!(
        "Qualcomm DT table v{version}, {count} entries, {} DTBs",
        seen.len()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// ART profile (.prof, baseline.prof, .profm)

fn art_profile_probe(h: &Head<'_>) -> bool {
    (h.starts_with(b"pro\0") || h.starts_with(b"prm\0"))
        && h.data.get(4..8).is_some_and(|v| {
            v.get(..3).is_some_and(|d| d.iter().all(u8::is_ascii_digit)) && v.get(3) == Some(&0)
        })
}

declare_format!(pub ART_PROFILE = "art-profile", "Android ART profile", ["prof", "profm"], "application/x-art-profile",
    Probe::Custom(art_profile_probe), art_profile);

const ART_SECTIONS: EnumTable = &[
    (0, "DexFiles"),
    (1, "ExtraDescriptors"),
    (2, "Classes"),
    (3, "Methods"),
    (4, "AggregationCounts"),
];

async fn art_profile(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let metadata = head.starts_with(b"prm");
    let version: u32 = String::from_utf8_lossy(head.get(4..7).unwrap_or_default())
        .parse()
        .unwrap_or(0);
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(text(if metadata { "prm" } else { "pro" })),
    );
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 4))
            .value(text(format!("{version:03}"))),
    );
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(8);
    if !metadata && version >= 13 {
        let at = cur.pos();
        let sections = cur.u32().await?;
        cx.emit(
            Node::new("Section count")
                .span(cur.since(at))
                .value(uint(sections.into())),
        );
        for _ in 0..sections.min(64) {
            let at = cur.pos();
            let kind = cur.u32().await?;
            let offset = cur.u32().await?;
            let len = cur.u32().await?;
            let inflated = cur.u32().await?;
            let name = lookup(ART_SECTIONS, kind.into())
                .map_or_else(|| format!("section {kind}"), str::to_owned);
            let body = file.sub(offset.into(), len.into());
            let summary = if inflated != 0 {
                format!("{len} bytes, zlib → {inflated}")
            } else {
                format!("{len} bytes")
            };
            let node = if inflated != 0 {
                content(name, input, body, Codec::Zlib, Some(inflated.into()))
            } else {
                Node::new(name).span(body)
            };
            cx.push(node.summary(summary).target(cur.since(at))).await;
        }
        cx.annotate(format!("ART profile v{version:03}, {sections} sections"));
    } else if !metadata && version >= 9 {
        let at = cur.pos();
        let dex_files = cur.u8().await?;
        let inflated = cur.u32().await?;
        let compressed = cur.u32().await?;
        cx.emit(
            Node::new("Dex file count")
                .span(Span::new(file.source, file.offset.saturating_add(at), 1))
                .value(uint(dex_files.into())),
        );
        cx.emit(
            Node::new("Uncompressed size")
                .span(Span::new(
                    file.source,
                    file.offset.saturating_add(at).saturating_add(1),
                    4,
                ))
                .value(uint(inflated.into())),
        );
        cx.emit(
            Node::new("Compressed size")
                .span(Span::new(
                    file.source,
                    file.offset.saturating_add(at).saturating_add(5),
                    4,
                ))
                .value(uint(compressed.into())),
        );
        let body = file.sub(cur.pos(), compressed.into());
        cx.emit(content(
            "Profile data (zlib)",
            input,
            body,
            Codec::Zlib,
            Some(inflated.into()),
        ));
        cx.annotate(format!(
            "ART profile v{version:03}, {dex_files} dex file(s)"
        ));
    } else {
        cx.emit(Node::new("Data").span(file.tail(8)));
        cx.annotate(
            format!(
                "ART profile {} v{version:03}",
                if metadata { "metadata" } else { "" }
            )
            .replace("  ", " "),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Compiled SELinux file contexts (file_contexts.bin)

declare_format!(pub FCONTEXT = "selinux-fcontext", "Compiled SELinux file contexts", ["bin"], "application/x-selinux-fcontext",
    Probe::Custom(|h| h.starts_with(b"\x8a\xff\x7c\xf9") && u32_le(h.data, 4).is_some_and(|v| (1..=10).contains(&v))), fcontext);

async fn fcontext(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.skip(4);
    cx.emit(Node::new("Magic").span(file.sub(0, 4)).value(Value::UInt {
        value: 0xf97c_ff8a,
        bits: 32,
        radix: Radix::Hex,
    }));
    let at = cur.pos();
    let version = cur.u32().await?;
    cx.emit(
        Node::new("Version")
            .span(cur.since(at))
            .value(uint(version.into())),
    );
    let mut summary = Vec::new();
    for (min, label) in [(2u32, "PCRE version"), (5, "Regex architecture")] {
        if version >= min {
            let at = cur.pos();
            let len = cur.u32().await?;
            if len > 256 {
                return Err(Diagnostic::malformed(format!("{len}-byte {label}")).at(cur.since(at)));
            }
            let s = String::from_utf8_lossy(&cur.bytes(len.into()).await?).into_owned();
            summary.push(format!("{label} {s}"));
            cx.emit(Node::new(label).span(cur.since(at)).value(text(s)));
        }
    }
    let stems_at = cur.pos();
    let stems = cur.u32().await?;
    let mut names = Vec::new();
    for _ in 0..stems.min(100_000) {
        let len = cur.u32().await?;
        let s = cur.bytes(u64::from(len).saturating_add(1)).await?;
        names.push(zstr(&s));
        cx.checkpoint().await;
    }
    cx.emit(
        Node::new("Stems")
            .span(cur.since(stems_at))
            .summary(format!("{stems}: {}", names.join(" "))),
    );
    let at = cur.pos();
    let specs = cur.u32().await?;
    cx.emit(
        Node::new("Specifications")
            .span(file.tail(at))
            .summary(format!("{specs} regular expressions")),
    );
    cx.annotate(format!(
        "Compiled SELinux file contexts v{version}, {stems} stems, {specs} specs, {}",
        summary.join(", ")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// HPROF heap dump

declare_format!(pub HPROF = "hprof", "HPROF heap dump (Java/Android)", ["hprof"], "application/x-hprof",
    Probe::Magic(&[(0, b"JAVA PROFILE 1.0.1\0"), (0, b"JAVA PROFILE 1.0.2\0"), (0, b"JAVA PROFILE 1.0.3\0")]), hprof);

const HPROF_TAGS: EnumTable = &[
    (0x01, "STRING"),
    (0x02, "LOAD CLASS"),
    (0x03, "UNLOAD CLASS"),
    (0x04, "STACK FRAME"),
    (0x05, "STACK TRACE"),
    (0x06, "ALLOC SITES"),
    (0x07, "HEAP SUMMARY"),
    (0x0a, "START THREAD"),
    (0x0b, "END THREAD"),
    (0x0c, "HEAP DUMP"),
    (0x0d, "CPU SAMPLES"),
    (0x0e, "CONTROL SETTINGS"),
    (0x1c, "HEAP DUMP SEGMENT"),
    (0x2c, "HEAP DUMP END"),
];

async fn hprof(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let (version, vspan) = cur.cstr(32).await?;
    cx.emit(Node::new("Format").span(vspan).value(text(version.clone())));
    let at = cur.pos();
    let id_size = cur.u32().await?;
    cx.emit(
        Node::new("Identifier size")
            .span(cur.since(at))
            .value(uint(id_size.into())),
    );
    if !matches!(id_size, 4 | 8) {
        return Err(Diagnostic::malformed(format!("identifier size {id_size}")).at(cur.since(at)));
    }
    let at = cur.pos();
    let millis = cur.u64().await?;
    cx.emit(
        Node::new("Timestamp")
            .span(cur.since(at))
            .value(Value::Timestamp {
                unix_seconds: i64::try_from(millis / 1000).unwrap_or(0),
            }),
    );
    let mut counts = BTreeMap::<u8, u64>::new();
    let mut n = 0u64;
    while !cur.at_end() {
        let start = cur.pos();
        let tag = cur.u8().await?;
        let _time = cur.u32().await?;
        let len = cur.u32().await?;
        let body = cur.span(len.into());
        if body.len < u64::from(len) {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, len.into()),
                body.len,
            ));
        }
        cur.skip(len.into());
        let name =
            lookup(HPROF_TAGS, tag.into()).map_or_else(|| format!("tag {tag:#04x}"), str::to_owned);
        let mut node = Node::new(name).span(cur.since(start));
        let id = u64::from(id_size);
        match tag {
            0x01 => {
                let data = cx.read(body.sub(0, id.saturating_add(256))).await?;
                let s = String::from_utf8_lossy(
                    data.get(crate::bytes::to_usize(id)..).unwrap_or_default(),
                )
                .into_owned();
                node = node.value(text(s));
            }
            0x02 => {
                let data = cx
                    .read(body.sub(0, id.saturating_mul(2).saturating_add(8)))
                    .await?;
                let serial = u32_be(&data, 0).unwrap_or(0);
                node = node.summary(format!("class serial {serial}"));
            }
            _ => node = node.summary(format!("{len} bytes")),
        }
        let c = counts.entry(tag).or_default();
        *c = c.saturating_add(1);
        n = n.saturating_add(1);
        cx.push(node).await;
    }
    let strings = counts.get(&1).copied().unwrap_or(0);
    let classes = counts.get(&2).copied().unwrap_or(0);
    let heap = counts
        .get(&0x1c)
        .copied()
        .unwrap_or(0)
        .saturating_add(counts.get(&0x0c).copied().unwrap_or(0));
    cx.annotate(format!("{} heap dump, {n} records ({strings} strings, {classes} classes, {heap} heap dump segments)", version.trim_end_matches('\0')));
    Ok(())
}

// ---------------------------------------------------------------------------
// Android method trace (.trace)

declare_format!(pub METHOD_TRACE = "android-method-trace", "Android method trace", ["trace"], "application/x-android-trace",
    Probe::Magic(&[(0, b"*version\n")]), method_trace);

async fn method_trace(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut section = String::new();
    let mut section_start = 0u64;
    let mut methods = BTreeMap::<u64, String>::new();
    let mut threads = 0u64;
    let mut binary = None;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if let Some(name) = t.strip_prefix('*') {
            if !section.is_empty() {
                let span = file.sub(section_start, line.start.saturating_sub(section_start));
                cx.push(
                    Node::new(format!("*{section}"))
                        .span(span)
                        .lazy(crate::formats::ml::text::block_lines, span),
                )
                .await;
            }
            if name == "end" {
                cx.push(Node::new("*end").span(line.span)).await;
                binary = Some(line.next);
                break;
            }
            section = name.to_owned();
            section_start = line.start;
            continue;
        }
        match section.as_str() {
            "threads" => threads = threads.saturating_add(1),
            "methods" => {
                let mut parts = t.split('\t');
                if let Some(id) = parts
                    .next()
                    .and_then(|i| u64::from_str_radix(i.trim_start_matches("0x"), 16).ok())
                {
                    let class = parts.next().unwrap_or_default();
                    let method = parts.next().unwrap_or_default();
                    methods.insert(id, format!("{class}.{method}"));
                }
            }
            _ => {}
        }
    }
    let Some(at) = binary else {
        return Err(Diagnostic::malformed("no *end marker").at(file));
    };
    let data = file.tail(at);
    let head = cx.read(data.sub(0, 18)).await?;
    if head.get(..4) != Some(b"SLOW") {
        return Err(Diagnostic::malformed("missing SLOW header").at(data.sub(0, 4)));
    }
    let version = u16_le(&head, 4).unwrap_or(0);
    let offset = u16_le(&head, 6).unwrap_or(0);
    let record = match version {
        1 => 9,
        2 => 10,
        _ => u16_le(&head, 16).unwrap_or(14),
    };
    cx.emit(struct_node(
        "Binary header",
        data.sub(0, offset.into()),
        LE,
        version,
        |f, &v| {
            f.ascii("Magic", 4).emit()?;
            f.u16("Version").emit()?;
            f.u16("Data offset").emit()?;
            f.u64("Start time (µs)").emit()?;
            if v >= 3 {
                f.u16("Record size").emit()?;
            }
            Ok(())
        },
    ));
    let records = data.tail(offset.into());
    let count = records.len.checked_div(u64::from(record)).unwrap_or(0);
    cx.emit(
        Node::new("Records")
            .span(records)
            .summary(format!("{count} records of {record} bytes"))
            .lazy(
                trace_records,
                (records, version, record, Arc::new(methods.clone())),
            ),
    );
    cx.annotate(format!(
        "Android method trace v{version}, {threads} threads, {} methods, {count} events",
        methods.len()
    ));
    Ok(())
}

async fn trace_records(
    cx: Cx,
    (records, version, record, methods): (Span, u16, u16, Arc<BTreeMap<u64, String>>),
) -> Result<()> {
    let size = u64::from(record.max(1));
    let count = records.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = records.sub(i.saturating_mul(size), size);
        let r = cx.read(span).await?;
        let (thread, rest) = if version == 1 {
            (u64::from(r.first().copied().unwrap_or(0)), 1usize)
        } else {
            (u64::from(u16_le(&r, 0).unwrap_or(0)), 2)
        };
        let id = u32_le(&r, rest).unwrap_or(0);
        let time = u32_le(&r, rest.saturating_add(4)).unwrap_or(0);
        let action = match id & 3 {
            0 => "enter",
            1 => "exit",
            2 => "unwind",
            _ => "?",
        };
        let method = methods
            .get(&u64::from(id & !3))
            .cloned()
            .unwrap_or_else(|| format!("{:#x}", id & !3));
        cx.push(
            Node::new(format!("[{i}]"))
                .span(span)
                .value(text(method))
                .summary(format!("thread {thread}, {action}, +{time} µs")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Binary logcat (logcat -B)

const LOG_IDS: EnumTable = &[
    (0, "main"),
    (1, "radio"),
    (2, "events"),
    (3, "system"),
    (4, "crash"),
    (5, "stats"),
    (6, "security"),
    (7, "kernel"),
];

const PRIORITY: &[&str] = &["?", "default", "V", "D", "I", "W", "E", "F", "S"];

/// Checks one entry at `at`; returns where the next one starts.
fn logcat_entry_ok(d: &[u8], at: usize) -> Option<usize> {
    let len = usize::from(u16_le(d, at)?);
    let hdr = usize::from(u16_le(d, at.checked_add(2)?)?);
    let nsec = u32_le(d, at.checked_add(16)?)?;
    let sec = u32_le(d, at.checked_add(12)?)?;
    let hdr = if hdr == 0 { 20 } else { hdr };
    if !matches!(hdr, 20 | 24 | 28)
        || !(1..=5120).contains(&len)
        || nsec >= 1_000_000_000
        || sec < 946_684_800
    {
        return None;
    }
    if hdr >= 24 && u32_le(d, at.checked_add(20)?)? > 7 {
        return None;
    }
    at.checked_add(hdr)?.checked_add(len)
}

fn logcat_probe(h: &Head<'_>) -> bool {
    match logcat_entry_ok(h.data, 0) {
        Some(next) if next >= h.data.len() => to_u64(next) == h.len,
        Some(next) => logcat_entry_ok(h.data, next).is_some(),
        None => false,
    }
}

declare_format!(pub LOGCAT = "logcat-binary", "Android binary logcat", ["bin", "logcat"], "application/x-logcat",
    Probe::Custom(logcat_probe), logcat);

async fn logcat(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut n = 0u64;
    let mut buffers = BTreeMap::<u32, u64>::new();
    while cur.remaining() >= 20 {
        let start = cur.pos();
        let h = cur.bytes(20).await?;
        let len = u16_le(&h, 0).unwrap_or(0);
        let hdr = match u16_le(&h, 2).unwrap_or(0) {
            0 => 20,
            x => x,
        };
        if !(20..=256).contains(&hdr) {
            return Err(Diagnostic::malformed(format!("header size {hdr}")).at(cur.since(start)));
        }
        let pid = i32::from_ne_bytes(u32_le(&h, 4).unwrap_or(0).to_ne_bytes());
        let tid = u32_le(&h, 8).unwrap_or(0);
        let extra = cur.bytes(u64::from(hdr).saturating_sub(20)).await?;
        let lid = if hdr >= 24 {
            u32_le(&extra, 0).unwrap_or(0)
        } else {
            0
        };
        let payload = cur.span(len.into());
        if payload.len < u64::from(len) {
            return Err(Diagnostic::truncated(
                Span::new(payload.source, payload.offset, len.into()),
                payload.len,
            ));
        }
        cur.skip(len.into());
        let data = cx.read(payload.sub(0, 1024)).await?;
        let buffer = lookup(LOG_IDS, lid.into()).unwrap_or("?");
        let node = if lid == 2 || lid == 5 || lid == 6 {
            let tag = u32_le(&data, 0).unwrap_or(0);
            Node::new(format!("{buffer} event"))
                .value(Value::UInt {
                    value: tag.into(),
                    bits: 32,
                    radix: Radix::Dec,
                })
                .summary(format!("pid {pid}, tid {tid}, {len} bytes"))
        } else {
            let prio = data.first().copied().unwrap_or(0);
            let rest = data.get(1..).unwrap_or_default();
            let tag_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            let tag = String::from_utf8_lossy(rest.get(..tag_end).unwrap_or_default()).into_owned();
            let msg = zstr(rest.get(tag_end.saturating_add(1)..).unwrap_or_default());
            let p = PRIORITY.get(usize::from(prio)).copied().unwrap_or("?");
            Node::new(format!("{p}/{tag}"))
                .value(text(msg.trim_end()))
                .summary(format!("{buffer}, pid {pid}, tid {tid}"))
        };
        let c = buffers.entry(lid).or_default();
        *c = c.saturating_add(1);
        cx.push(
            node.span(cur.since(start))
                .lazy(logcat_entry, (cur.since(start), hdr)),
        )
        .await;
        n = n.saturating_add(1);
    }
    let parts: Vec<String> = buffers
        .iter()
        .map(|(b, c)| format!("{} {c}", lookup(LOG_IDS, (*b).into()).unwrap_or("?")))
        .collect();
    cx.annotate(format!(
        "Android binary logcat, {n} entries ({})",
        parts.join(", ")
    ));
    Ok(())
}

async fn logcat_entry(cx: Cx, (span, hdr): (Span, u16)) -> Result<()> {
    let header = span.sub(0, hdr.into());
    let block = cx.block(header).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u16("Payload length").emit()?;
    f.u16("Header size").emit()?;
    f.i32("PID").emit()?;
    f.u32("TID").emit()?;
    f.u32("Seconds").timestamp().emit()?;
    f.u32("Nanoseconds").emit()?;
    if hdr >= 24 {
        f.u32("Log ID").enumeration(LOG_IDS).emit()?;
    }
    if hdr >= 28 {
        f.u32("UID").emit()?;
    }
    let payload = span.tail(hdr.into());
    let data = cx.read(payload.sub(0, 64)).await?;
    cx.emit(
        Node::new("Payload")
            .span(payload)
            .summary(hex_string(data.get(..16).unwrap_or(&data))),
    );
    Ok(())
}
