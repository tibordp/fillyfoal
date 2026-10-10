//! Microsoft Virtual Hard Disk (VHD, "conectix").
//!
//! A 512-byte footer at the end describes the disk. Fixed disks are the raw
//! disk followed by the footer; dynamic and differencing disks have a copy
//! of the footer at the start, a dynamic header (`cxsparse`) with up to
//! eight parent locators, and a block allocation table (BAT). Each
//! allocated block is a sector bitmap (which sectors this file holds; in a
//! differencing disk the others come from the parent) followed by the
//! block's data. The virtual disk is presented as an embedded input.

use std::sync::Arc;

use crate::bytes::{align_up, to_u64, to_usize, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::qcow::Regions;
use crate::formats::disk::{PieceList, size, uuid_value};
use crate::formats::util::civil::EPOCH_2000;
use crate::formats::util::val::{enumv, uint};
use crate::formats::{Format, Head, Input, Probe, dissect_or_data, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const BE: Endian = Endian::Big;
const COOKIE: &[u8] = b"conectix";
const SECTOR: u64 = 512;
const UNUSED: u32 = u32::MAX;

pub static FORMAT: Format = Format {
    name: "vhd",
    title: "Microsoft Virtual Hard Disk",
    extensions: &["vhd"],
    mime: "application/x-vhd",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let tail = h.tail;
    let at = |back: usize| {
        tail.len()
            .checked_sub(back)
            .and_then(|i| tail.get(i..))
            .is_some_and(|t| t.starts_with(COOKIE))
    };
    h.starts_with(COOKIE) || at(512) || at(511)
}

const DISK_TYPES: EnumTable = &[
    (0, "none"),
    (1, "reserved (deprecated)"),
    (2, "fixed"),
    (3, "dynamic"),
    (4, "differencing"),
    (5, "reserved (deprecated)"),
    (6, "reserved (deprecated)"),
];

const FEATURES: FlagTable = &[flag(1, "TEMPORARY"), flag(2, "RESERVED")];

/// Creator applications and host operating systems (four-character codes).
const CREATORS: &[(&str, &str)] = &[
    ("vpc ", "Microsoft Virtual PC"),
    ("vs  ", "Microsoft Virtual Server"),
    ("win ", "Windows (Disk Management)"),
    ("d2v ", "Disk2vhd"),
    ("qemu", "QEMU"),
    ("vbox", "VirtualBox"),
    ("tap\0", "Xen blktap"),
    ("wa\0\0", "Windows Azure"),
    ("Wi2k", "Windows"),
    ("Mac ", "Macintosh"),
];

/// Parent locator platform codes.
const PLATFORMS: EnumTable = &[
    (0, "none"),
    (0x5769_3272, "Wi2r: relative Windows path (deprecated)"),
    (0x5769_326b, "Wi2k: absolute Windows path (deprecated)"),
    (0x5732_7275, "W2ru: relative Windows path (UTF-16)"),
    (0x5732_6b75, "W2ku: absolute Windows path (UTF-16)"),
    (0x4d61_6320, "Mac: Mac OS alias"),
    (0x4d61_6358, "MacX: file URL (UTF-8)"),
];

fn vhd_time(v: &u32, n: Node) -> Node {
    n.value(Value::Timestamp {
        unix_seconds: i64::from(*v).saturating_add(EPOCH_2000),
    })
}

#[allow(clippy::ptr_arg)] // used as a `Field::with` decorator
fn creator(v: &String, n: Node) -> Node {
    match CREATORS
        .iter()
        .find(|(k, _)| k.trim_end_matches('\0') == v.as_str())
    {
        Some((_, name)) => n.summary(*name),
        None => n,
    }
}

fn creator_version(v: &u32, n: Node) -> Node {
    n.summary(format!("{}.{}", v >> 16, v & 0xffff))
}

record! {
    /// The hard disk footer.
    pub struct Footer {
        cookie: ascii[8] "Cookie",
        features: u32 "Features" .hex() .flags(FEATURES),
        version: u32 "File format version" .hex() .with(creator_version),
        data_offset: u64 "Data offset (dynamic header)" .with(|&v, n| if v == u64::MAX { n.summary("none (fixed disk)") } else { n.summary(format!("{v:#x}")) }),
        timestamp: u32 "Created" .with(vhd_time),
        creator_app: ascii[4] "Creator application" .with(creator),
        creator_version: u32 "Creator version" .hex() .with(creator_version),
        creator_os: ascii[4] "Creator host OS" .with(creator),
        original_size: u64 "Original size" .with(|&v, n| n.summary(size(v))),
        current_size: u64 "Current size" .with(|&v, n| n.summary(size(v))),
        cylinders: u16 "Cylinders",
        heads: u8 "Heads",
        sectors: u8 "Sectors per track" .with(|&s, n| n.summary(format!("CHS capacity {}", size(u64::from(cylinders).saturating_mul(heads.into()).saturating_mul(s.into()).saturating_mul(SECTOR))))),
        disk_type: u32 "Disk type" .enumeration(DISK_TYPES),
        checksum: u32 "Checksum" .hex(),
        unique_id: bytes[16] "Unique id" .with(uuid_value),
        saved_state: u8 "Saved state" .with(|&v, n| n.summary(if v == 0 { "no" } else { "yes: the VM was saved with this disk" })),
        _reserved: bytes[427] "Reserved",
    }
}

record! {
    /// The dynamic disk header (before its parent locators).
    pub struct DynamicHeader {
        cookie: ascii[8] "Cookie",
        data_offset: u64 "Data offset (unused)" .hex(),
        table_offset: u64 "BAT offset" .hex(),
        version: u32 "Header version" .hex() .with(creator_version),
        max_entries: u32 "BAT entries",
        block_size: u32 "Block size" .with(|&v, n| n.summary(size(v.into()))),
        checksum: u32 "Checksum" .hex(),
        parent_id: bytes[16] "Parent unique id" .with(uuid_value),
        parent_time: u32 "Parent modified" .with(vhd_time),
        _reserved: u32 "Reserved",
        parent_name: utf16[256] "Parent name",
    }
}

record! {
    /// A parent locator entry.
    pub struct Locator {
        platform: u32 "Platform code" .hex() .enumeration(PLATFORMS),
        space: u32 "Platform data space" .desc("Space reserved for the locator: sectors (in some writers, bytes)"),
        length: u32 "Platform data length",
        _reserved: u32 "Reserved",
        offset: u64 "Platform data offset" .hex(),
    }
}

/// One's complement of the byte sum, skipping the checksum field.
fn checksum(data: &[u8], field: usize) -> u32 {
    let sum = data
        .iter()
        .enumerate()
        .filter(|(i, _)| !(field..field.saturating_add(4)).contains(i))
        .fold(0u32, |s, (_, &b)| s.wrapping_add(b.into()));
    !sum
}

/// A parent locator: platform code and the span of its data.
#[derive(Clone, Copy, Debug)]
struct ParentLocator {
    platform: u32,
    data: Span,
}

struct Dynamic {
    input: Input,
    bat: Span,
    block: u64,
    /// Sector bitmap bytes before each block (padded to a sector).
    bitmap: u64,
    size: u64,
    differencing: bool,
    header: Span,
    footer_copy: Span,
    footer: Option<Span>,
    locators: Vec<ParentLocator>,
}

impl Dynamic {
    fn bitmap_span(&self, entry: u32) -> Span {
        self.input
            .span
            .sub(u64::from(entry).saturating_mul(SECTOR), self.bitmap)
    }

    fn data(&self, entry: u32) -> Span {
        self.input.span.sub(
            u64::from(entry)
                .saturating_mul(SECTOR)
                .saturating_add(self.bitmap),
            self.block,
        )
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // The footer is the last 512 bytes (511 in some old images).
    let tail = cx
        .read_avail(file.tail(file.len.saturating_sub(SECTOR)))
        .await?;
    let footer_at = if tail.starts_with(COOKIE) {
        Some(file.len.saturating_sub(SECTOR))
    } else if tail.get(1..).is_some_and(|t| t.starts_with(COOKIE)) {
        Some(file.len.saturating_sub(511))
    } else {
        None
    };
    let primary = footer_at.unwrap_or(0);
    let footer_span = file.sub(primary, SECTOR);
    let footer = parse(&cx, footer_span, BE, &(), Footer::layout).await?;
    let raw = cx.read_avail(footer_span).await?;
    let mut node = Footer::node(
        if footer_at.is_some() {
            "Footer"
        } else {
            "Footer (copy at start)"
        },
        footer_span,
        BE,
    )
    .summary(format!(
        "{} disk, {}",
        lookup(DISK_TYPES, footer.disk_type.into()).unwrap_or("unknown"),
        size(footer.current_size)
    ));
    if checksum(&raw, 64) != footer.checksum {
        node = node.diag(Diagnostic::warning(format!(
            "footer checksum mismatch: computed {:#010x}",
            checksum(&raw, 64)
        )));
    }
    if footer_at.is_none() {
        node = node.diag(Diagnostic::warning(
            "no footer at the end; using the copy at the start",
        ));
    }
    let kind = lookup(DISK_TYPES, footer.disk_type.into()).unwrap_or("unknown");
    let app = footer.creator_app.trim_end_matches(['\0', ' ']).to_owned();
    let os = footer.creator_os.trim_end_matches(['\0', ' ']).to_owned();

    if footer.disk_type == 2 {
        cx.annotate(format!(
            "VHD {kind} disk, {} (created by {app:?} {}.{} on {os:?})",
            size(footer.current_size),
            footer.creator_version >> 16,
            footer.creator_version & 0xffff,
        ));
        let payload = file.sub(0, primary.min(footer.current_size));
        cx.emit(embedded("Virtual disk", input.nested(payload)).summary(size(payload.len)));
        if primary > footer.current_size {
            cx.emit(
                Node::new("Unused")
                    .span(file.sub(
                        footer.current_size,
                        primary.saturating_sub(footer.current_size),
                    ))
                    .summary("between the disk and the footer"),
            );
        }
        cx.emit(node);
        return Ok(());
    }
    let footer_copy = file.sub(0, SECTOR);
    if footer_at.is_some() {
        let copy = cx.read_avail(footer_copy).await?;
        let mut cnode = Footer::node("Footer copy", footer_copy, BE);
        if copy != raw {
            cnode = cnode.diag(Diagnostic::warning("differs from the footer at the end"));
        }
        cx.emit(cnode);
    }
    let header_span = file.sub(footer.data_offset, 1024);
    let header = parse(&cx, header_span, BE, &(), DynamicHeader::layout).await?;
    let raw = cx.read_avail(header_span).await?;
    if header.cookie != "cxsparse" {
        cx.emit(node);
        return Err(Diagnostic::malformed("bad dynamic header cookie").at(header_span.sub(0, 8)));
    }
    let mut locators = Vec::new();
    for i in 0..8usize {
        let at = 576usize.saturating_add(i.saturating_mul(24));
        let platform = u32_be(&raw, at).unwrap_or(0);
        let len = u32_be(&raw, at.saturating_add(8)).unwrap_or(0);
        let offset = u64_be(&raw, at.saturating_add(16)).unwrap_or(0);
        if platform != 0 {
            locators.push(ParentLocator {
                platform,
                data: file.sub(offset, len.into()),
            });
        }
    }
    let differencing = footer.disk_type == 4;
    let mut parent = String::new();
    if differencing {
        parent = header.parent_name.trim_end_matches('\0').to_owned();
        for l in &locators {
            if matches!(l.platform, 0x5732_7275 | 0x5732_6b75) {
                let d = cx.read_avail(l.data).await?;
                parent = crate::text::utf16z(&d, Endian::Little).0;
                break;
            }
        }
    }
    cx.annotate(format!(
        "VHD {kind} disk, {}, {} blocks (created by {app:?} {}.{} on {os:?}){}",
        size(footer.current_size),
        size(header.block_size.into()),
        footer.creator_version >> 16,
        footer.creator_version & 0xffff,
        if differencing {
            format!(", parent {parent:?}")
        } else {
            String::new()
        }
    ));
    let mut hnode =
        struct_node("Dynamic header", header_span, BE, (), header_layout).summary(format!(
            "{} BAT entries, {} blocks",
            header.max_entries,
            size(header.block_size.into())
        ));
    if checksum(&raw, 36) != header.checksum {
        hnode = hnode.diag(Diagnostic::warning(format!(
            "dynamic header checksum mismatch: computed {:#010x}",
            checksum(&raw, 36)
        )));
    }
    cx.emit(hnode);
    let block = u64::from(header.block_size);
    // Bitmaps are scanned bit by bit: blocks are at most 256 MiB.
    if block < SECTOR || !block.is_power_of_two() || block > 1 << 28 {
        cx.emit(node);
        return Err(Diagnostic::malformed(format!("block size {block}")).at(header_span));
    }
    let entries = u64::from(header.max_entries);
    let bat = file.sub_exact(header.table_offset, entries.saturating_mul(4))?;
    let disk = Arc::new(Dynamic {
        input,
        bat,
        block,
        bitmap: align_up((block / SECTOR).div_ceil(8), SECTOR),
        size: footer.current_size,
        differencing,
        header: header_span,
        footer_copy,
        footer: footer_at.map(|_| footer_span),
        locators: locators.clone(),
    });
    if !locators.is_empty() {
        cx.emit(
            Node::new("Parent locator data")
                .summary(format!("{} locators", locators.len()))
                .lazy(locator_data, Arc::new(locators)),
        );
    }
    let allocated = cx
        .read_avail(bat)
        .await?
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|e| u32::from_be_bytes(**e) != UNUSED)
        .count();
    cx.emit(
        Node::new("Block allocation table")
            .span(bat)
            .summary(format!(
                "{allocated} of {} blocks allocated, {} each",
                header.max_entries,
                size(block)
            ))
            .lazy(bat_entries, disk.clone()),
    );
    let bat_end = bat.end().saturating_sub(file.offset);
    let padded = align_up(bat_end, SECTOR);
    if padded > bat_end {
        cx.emit(
            Node::new("BAT padding")
                .span(file.sub(bat_end, padded.saturating_sub(bat_end)))
                .summary("to the end of the sector"),
        );
    }
    cx.emit(
        Node::new("File layout")
            .span(file)
            .summary("what each part of the file holds")
            .lazy(layout, disk.clone()),
    );
    let mut vnode = Node::new("Virtual disk")
        .summary(size(footer.current_size))
        .lazy(virtual_disk, disk);
    if differencing {
        vnode = vnode.desc("Sectors not present in this file come from the parent; shown as zeros");
    }
    cx.emit(vnode);
    cx.emit(node);
    Ok(())
}

fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    DynamicHeader::read(f)?;
    for i in 0..8u64 {
        let span = f.peek_span(24);
        let block = f.block();
        let at = to_usize(f.pos());
        let platform = u32_be(&block.data, at).unwrap_or(0);
        let name = format!("Parent locator {}", i.saturating_add(1));
        let blank = block
            .data
            .get(at..at.saturating_add(24))
            .is_some_and(|e| e.iter().all(|&b| b == 0));
        f.node(if blank {
            Node::new(name)
                .span(span)
                .value(Value::Enum {
                    raw: 0,
                    bits: 32,
                    name: Some("unused"),
                })
                .summary("all zeros")
        } else {
            Locator::node(name, span, BE).summary(
                lookup(PLATFORMS, platform.into())
                    .map_or_else(|| format!("{platform:#010x}"), str::to_owned),
            )
        });
        f.skip(24);
    }
    f.bytes("Reserved", 256).emit()?;
    Ok(())
}

async fn locator_data(cx: Cx, locators: Arc<Vec<ParentLocator>>) -> Result<()> {
    for l in locators.iter() {
        let data = cx.read_avail(l.data).await?;
        let name = lookup(PLATFORMS, l.platform.into()).unwrap_or("unknown platform");
        let value = match l.platform {
            0x5732_7275 | 0x5732_6b75 => Value::Text(crate::text::utf16z(&data, Endian::Little).0),
            0x4d61_6358 | 0x5769_3272 | 0x5769_326b => Value::Text(crate::text::until_nul(&data)),
            _ => Value::Bytes(data),
        };
        cx.push(Node::new(name).span(l.data).value(value)).await;
    }
    Ok(())
}

async fn bat_entries(cx: Cx, d: Arc<Dynamic>) -> Result<()> {
    let table = cx.read_avail(d.bat).await?;
    let count = to_u64(table.len()) / 4;
    let mut i = 0u64;
    while i < count {
        let entry = u32_be(&table, to_usize(i.saturating_mul(4))).unwrap_or(UNUSED);
        let guest = i.saturating_mul(d.block);
        if entry == UNUSED {
            let start = i;
            while i < count && u32_be(&table, to_usize(i.saturating_mul(4))) == Some(UNUSED) {
                i = i.saturating_add(1);
                if i.is_multiple_of(4096) {
                    cx.checkpoint().await;
                }
            }
            cx.push(
                Node::new(if start.saturating_add(1) == i {
                    format!("Block {start}")
                } else {
                    format!("Blocks {start}–{}", i.saturating_sub(1))
                })
                .span(d.bat.sub(
                    start.saturating_mul(4),
                    i.saturating_sub(start).saturating_mul(4),
                ))
                .value(enumv(UNUSED, 32, &[(0xffff_ffff, "unallocated")]))
                .summary(format!(
                    "guest {guest:#x}–{:#x}: {}",
                    i.saturating_mul(d.block).saturating_sub(1),
                    if d.differencing {
                        "from the parent"
                    } else {
                        "zeros"
                    }
                )),
            )
            .await;
            continue;
        }
        cx.push(
            Node::new(format!("Block {i}"))
                .span(d.bat.sub(i.saturating_mul(4), 4))
                .value(uint(entry, 32))
                .summary(format!(
                    "guest {guest:#x}: sector {entry} (bitmap at {:#x}, data at {:#x})",
                    u64::from(entry).saturating_mul(SECTOR),
                    u64::from(entry)
                        .saturating_mul(SECTOR)
                        .saturating_add(d.bitmap)
                ))
                .target(d.data(entry))
                .lazy(block_node, (d.clone(), entry)),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// Sectors present according to a sector bitmap (most significant bit
/// first), as `[first, end)` runs.
fn present_runs(bitmap: &[u8], sectors: u64) -> Vec<(u64, u64)> {
    let mut runs = Vec::new();
    let bit = |s: u64| {
        bitmap
            .get(to_usize(s / 8))
            .is_some_and(|b| b & (0x80u8 >> (s % 8)) != 0)
    };
    let mut s = 0u64;
    while s < sectors {
        if !bit(s) {
            s = s.saturating_add(1);
            continue;
        }
        let start = s;
        while s < sectors && bit(s) {
            s = s.saturating_add(1);
        }
        runs.push((start, s));
    }
    runs
}

async fn block_node(cx: Cx, (d, entry): (Arc<Dynamic>, u32)) -> Result<()> {
    let bitmap_span = d.bitmap_span(entry);
    let sectors = d.block / SECTOR;
    let bitmap = cx
        .read_avail(bitmap_span.sub(0, sectors.div_ceil(8)))
        .await?;
    cx.checkpoint().await;
    let runs = present_runs(&bitmap, sectors);
    let present = runs
        .iter()
        .fold(0u64, |t, (a, b)| t.saturating_add(b.saturating_sub(*a)));
    cx.emit(
        Node::new("Sector bitmap")
            .span(bitmap_span)
            .value(Value::Bytes(bitmap.iter().take(64).copied().collect()))
            .summary(format!(
                "{present} of {sectors} sectors present{}",
                if d.differencing && present < sectors {
                    "; the others come from the parent"
                } else {
                    ""
                }
            )),
    );
    cx.emit(Node::new("Data").span(d.data(entry)).summary(size(d.block)));
    Ok(())
}

async fn layout(cx: Cx, d: Arc<Dynamic>) -> Result<()> {
    let file = d.input.span;
    let mut r = Regions::default();
    r.span(file, d.footer_copy, "Footer copy");
    r.span(file, d.header, "Dynamic header");
    r.span(
        file,
        Span::new(d.bat.source, d.bat.offset, align_up(d.bat.len, SECTOR)),
        "Block allocation table",
    );
    for l in &d.locators {
        let padded = align_up(l.data.len, SECTOR);
        r.span(
            file,
            Span::new(l.data.source, l.data.offset, padded),
            "Parent locator data",
        );
    }
    let table = cx.read_avail(d.bat).await?;
    for (i, e) in table.as_chunks::<4>().0.iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        let entry = u32::from_be_bytes(*e);
        if entry == UNUSED {
            continue;
        }
        r.span(file, d.bitmap_span(entry), "Sector bitmap");
        let data = d.data(entry);
        r.add(
            data.offset.saturating_sub(file.offset),
            data.len,
            "Block data",
            Some(to_u64(i).saturating_mul(d.block)),
        );
    }
    if let Some(f) = d.footer {
        r.span(file, f, "Footer");
    }
    r.emit(&cx, file, "not referenced by the BAT").await;
    Ok(())
}

async fn virtual_disk(cx: Cx, d: Arc<Dynamic>) -> Result<()> {
    if d.differencing {
        cx.diag(Diagnostic::note(
            "sectors not present in this file come from the parent; shown as zeros",
        ));
    }
    let table = cx.read(d.bat).await?;
    let mut list = PieceList::new(d.bat);
    let sectors = d.block / SECTOR;
    for (i, raw) in table.as_chunks::<4>().0.iter().enumerate() {
        if list.len() >= d.size {
            break;
        }
        let want = d.block.min(d.size.saturating_sub(list.len()));
        if i.is_multiple_of(256) {
            cx.progress(list.len(), d.size);
            cx.checkpoint().await;
        }
        let entry = u32::from_be_bytes(*raw);
        if entry == UNUSED {
            list.data(Span::zeros(want));
            continue;
        }
        let data = d.data(entry);
        if !d.differencing {
            list.data(data.sub(0, want));
            continue;
        }
        // Differencing: only the sectors marked in the bitmap are here.
        let bitmap = cx
            .read_avail(d.bitmap_span(entry).sub(0, sectors.div_ceil(8)))
            .await?;
        let mut pos = 0u64;
        for (a, b) in present_runs(&bitmap, sectors) {
            let a = a.saturating_mul(SECTOR).min(want);
            let b = b.saturating_mul(SECTOR).min(want);
            list.data(Span::zeros(a.saturating_sub(pos)));
            list.data(data.sub(a, b.saturating_sub(a)));
            pos = b;
        }
        list.data(Span::zeros(want.saturating_sub(pos)));
    }
    let span = list.finish(&cx, "vhd-blocks").await?;
    dissect_or_data(cx, d.input.nested(span)).await
}
