//! QEMU copy-on-write images: QCOW (version 1) and QCOW2/QCOW3.
//!
//! The header gives the cluster size and the L1 table; L1 entries point at
//! L2 tables, whose entries map guest clusters to host clusters (possibly
//! deflate- or zstd-compressed, or split into 32 subclusters with extended
//! L2 entries). Header extensions name the backing file format, feature
//! bits, persistent dirty bitmaps, an external data file and the LUKS
//! encryption header. Refcount tables count references to host clusters;
//! internal snapshots keep their own L1 tables.
//!
//! The virtual disk is assembled from the mapping on expansion: allocated
//! clusters in place, compressed clusters decoded, unallocated ones as
//! zeros. A host cluster map accounts for every cluster of the file.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::{PieceList, align, size};
use crate::formats::util::datakit::{enumv, hex, uint};
use crate::formats::{Codec, Format, Head, Input, Probe, dissect_or_data, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const BE: Endian = Endian::Big;
const MAGIC: &[u8] = b"QFI\xfb";
/// Host offset bits of L1, L2 and refcount table entries.
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const COPIED: u64 = 1 << 63;
const COMPRESSED: u64 = 1 << 62;
/// Header extensions, snapshots and bitmaps listed at most.
const MAX_ITEMS: usize = 1024;
/// Regions the host cluster map collects before giving up.
const MAX_REGIONS: usize = 1 << 16;
/// Largest bitmap directory read (the specification's limit).
const MAX_BITMAP_DIRECTORY: u64 = 64 << 20;

pub static FORMAT: Format = Format {
    name: "qcow",
    title: "QEMU copy-on-write disk image (QCOW/QCOW2)",
    extensions: &["qcow", "qcow2", "qcow3", "img"],
    mime: "application/x-qemu-disk",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(MAGIC) && matches!(u32_be(h.data, 4), Some(1..=3))
}

const CRYPT: EnumTable = &[(0, "none"), (1, "AES-CBC"), (2, "LUKS")];

const INCOMPAT: FlagTable = &[
    flag(1, "DIRTY"),
    flag(2, "CORRUPT"),
    flag(4, "EXTERNAL_DATA_FILE"),
    flag(8, "COMPRESSION_TYPE"),
    flag(16, "EXTENDED_L2"),
];

const COMPAT: FlagTable = &[flag(1, "LAZY_REFCOUNTS")];
const AUTOCLEAR: FlagTable = &[flag(1, "BITMAPS"), flag(2, "RAW_EXTERNAL_DATA")];
const COMPRESSION: EnumTable = &[(0, "zlib (raw deflate)"), (1, "zstd")];

const EXT_BACKING_FORMAT: u32 = 0xe279_2aca;
const EXT_FEATURES: u32 = 0x6803_f857;
const EXT_BITMAPS: u32 = 0x2385_2875;
const EXT_CRYPTO: u32 = 0x0537_be77;
const EXT_DATA_FILE: u32 = 0x4441_5441;

const EXTENSIONS: EnumTable = &[
    (0, "end of extensions"),
    (0xe279_2aca, "backing file format name"),
    (0x6803_f857, "feature name table"),
    (0x2385_2875, "bitmaps"),
    (0x0537_be77, "full disk encryption header pointer"),
    (0x4441_5441, "external data file name"),
];

const FEATURE_TYPES: EnumTable = &[(0, "incompatible"), (1, "compatible"), (2, "autoclear")];

const L1_FLAGS: FlagTable = &[flag(COPIED, "COPIED")];
const L2_FLAGS: FlagTable = &[
    flag(COPIED, "COPIED"),
    flag(COMPRESSED, "COMPRESSED"),
    flag(1, "ZERO"),
];
const BITMAP_FLAGS: FlagTable = &[
    flag(1, "IN_USE"),
    flag(2, "AUTO"),
    flag(4, "EXTRA_DATA_COMPATIBLE"),
];
const BITMAP_TYPES: EnumTable = &[(1, "dirty tracking")];

record! {
    /// QCOW2 header (version 2 part).
    pub struct Header2 {
        magic: bytes[4] "Magic",
        version: u32 "Version",
        backing_offset: u64 "Backing file name offset" .hex(),
        backing_size: u32 "Backing file name length",
        cluster_bits: u32 "Cluster bits" .with(|&b, n| n.summary(size(1u64.checked_shl(b).unwrap_or(0)))),
        size: u64 "Virtual disk size" .with(|&v, n| n.summary(size(v))),
        crypt: u32 "Encryption" .enumeration(CRYPT),
        l1_size: u32 "L1 entries",
        l1_offset: u64 "L1 table offset" .hex(),
        refcount_offset: u64 "Refcount table offset" .hex(),
        refcount_clusters: u32 "Refcount table clusters",
        snapshots: u32 "Snapshots",
        snapshots_offset: u64 "Snapshot table offset" .hex(),
    }
}

record! {
    /// QCOW2 version 3 header fields.
    pub struct Header3 {
        incompatible: u64 "Incompatible features" .hex() .flags(INCOMPAT),
        compatible: u64 "Compatible features" .hex() .flags(COMPAT),
        autoclear: u64 "Auto-clear features" .hex() .flags(AUTOCLEAR),
        refcount_order: u32 "Refcount order" .with(|&o, n| n.summary(format!("{}-bit refcounts", 1u64.checked_shl(o).unwrap_or(0)))),
        header_length: u32 "Header length",
    }
}

record! {
    /// QCOW version 1 header.
    pub struct Header1 {
        magic: bytes[4] "Magic",
        version: u32 "Version",
        backing_offset: u64 "Backing file name offset" .hex(),
        backing_size: u32 "Backing file name length",
        mtime: u32 "Modified" .with(crate::formats::disk::unix_time),
        size: u64 "Virtual disk size" .with(|&v, n| n.summary(size(v))),
        cluster_bits: u8 "Cluster bits" .with(|&b, n| n.summary(crate::formats::disk::size(1u64.checked_shl(b.into()).unwrap_or(0)))),
        l2_bits: u8 "L2 bits" .with(|&b, n| n.summary(format!("{} entries per L2 table", 1u64.checked_shl(b.into()).unwrap_or(0)))),
        _padding: u16 "Padding",
        crypt: u32 "Encryption" .enumeration(CRYPT),
        l1_offset: u64 "L1 table offset" .hex(),
    }
}

record! {
    pub struct SnapshotHeader {
        l1_offset: u64 "L1 table offset" .hex(),
        l1_size: u32 "L1 entries",
        id_size: u16 "Id length",
        name_size: u16 "Name length",
        date: u32 "Created" .timestamp(),
        date_ns: u32 "Created (ns)",
        vm_clock_ns: u64 "VM clock (ns)" .with(|&v, n| n.summary(format!("{}.{:09} s", v / 1_000_000_000, v % 1_000_000_000))),
        vm_state_size: u32 "VM state size" .with(|&v, n| n.summary(size(v.into()))),
        extra_size: u32 "Extra data size",
    }
}

record! {
    /// An entry of the bitmap directory (before its extra data and name).
    pub struct BitmapEntry {
        table_offset: u64 "Bitmap table offset" .hex(),
        table_size: u32 "Bitmap table entries",
        flags: u32 "Flags" .hex() .flags(BITMAP_FLAGS),
        kind: u8 "Type" .enumeration(BITMAP_TYPES),
        granularity_bits: u8 "Granularity bits" .with(|&b, n| n.summary(format!("one bit per {}", size(1u64.checked_shl(b.into()).unwrap_or(0))))),
        name_size: u16 "Name length",
        extra_size: u32 "Extra data size",
    }
}

/// A header extension: type, data span.
#[derive(Clone, Copy, Debug)]
struct Ext {
    kind: u32,
    data: Span,
}

/// What the mapping and the cluster map need.
#[derive(Debug)]
struct Image {
    input: Input,
    version: u32,
    cluster_bits: u32,
    /// L2 entries per table.
    l2_entries: u64,
    /// Bytes per L2 entry (16 with extended L2).
    l2_entry_size: u64,
    l1: Span,
    size: u64,
    backing: bool,
    /// Guest data lives in an external data file.
    external: bool,
    /// How compressed clusters are encoded.
    codec: Codec,
    refcount_table: Span,
    refcount_order: u32,
    snapshots: Option<(u64, u32)>,
    /// Bitmap directory (offset, size, count).
    bitmaps: Option<(u64, u64, u32)>,
    /// The LUKS header area of an encrypted image.
    crypto: Option<Span>,
    /// The header, extensions and backing file name.
    header_end: u64,
}

impl Image {
    fn cluster(&self) -> u64 {
        1u64.checked_shl(self.cluster_bits).unwrap_or(0)
    }

    fn extended(&self) -> bool {
        self.l2_entry_size == 16
    }

    /// Guest bytes covered by one L2 table.
    fn l2_covers(&self) -> u64 {
        self.l2_entries.saturating_mul(self.cluster())
    }

    /// The L2 table an L1 entry points at (`None` if unallocated).
    fn l2_table(&self, entry: u64) -> Option<Span> {
        let offset = if self.version == 1 {
            entry
        } else {
            entry & OFFSET_MASK
        };
        (offset != 0).then(|| {
            self.input
                .span
                .sub(offset, self.l2_entries.saturating_mul(self.l2_entry_size))
        })
    }
}

fn ext_name(kind: u32) -> String {
    match lookup(EXTENSIONS, kind.into()) {
        Some(name) => capitalize(name),
        None => format!("Extension {kind:#010x}"),
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let version = u32_be(&head, 4).unwrap_or(0);
    if version == 1 {
        return qcow1(&cx, input).await;
    }
    let span = file.sub(0, Header2::SIZE);
    let h = parse(&cx, span, BE, &(), Header2::layout).await?;
    cx.emit(Header2::node("Header", span, BE));
    if !(9..=21).contains(&h.cluster_bits) {
        return Err(Diagnostic::malformed(format!("cluster bits {}", h.cluster_bits)).at(span));
    }
    let cluster = 1u64 << h.cluster_bits;
    let mut header_len = Header2::SIZE;
    let mut incompatible = 0u64;
    let mut autoclear = 0u64;
    let mut refcount_order = 4u32;
    let mut compression = 0u8;
    if version >= 3 {
        let span3 = file.sub(Header2::SIZE, Header3::SIZE);
        let h3 = parse(&cx, span3, BE, &(), Header3::layout).await?;
        let mut node = Header3::node("Version 3 header", span3, BE);
        if h3.incompatible & 1 != 0 {
            node = node.diag(Diagnostic::note(
                "dirty: refcounts may be inconsistent (lazy refcounts were in use)",
            ));
        }
        if h3.incompatible & 2 != 0 {
            node = node.diag(Diagnostic::warning("marked corrupt by QEMU"));
        }
        cx.emit(node);
        header_len = u64::from(h3.header_length).clamp(Header2::SIZE + Header3::SIZE, cluster);
        incompatible = h3.incompatible;
        autoclear = h3.autoclear;
        refcount_order = h3.refcount_order;
        if header_len > 104 {
            compression = cx
                .read(file.sub(104, 1))
                .await?
                .first()
                .copied()
                .unwrap_or(0);
            cx.emit(
                Node::new("Compression type")
                    .span(file.sub(104, 1))
                    .value(enumv(compression, 8, COMPRESSION)),
            );
            if header_len > 105 {
                let pad = file.sub(105, header_len.saturating_sub(105));
                let bytes = cx.read_avail(pad).await?;
                cx.emit(Node::new("Padding").span(pad).value(Value::Bytes(bytes)));
            }
        }
        if compression != 0 && incompatible & 8 == 0 {
            cx.diag(Diagnostic::warning(
                "compression type set without the COMPRESSION_TYPE feature bit",
            ));
        }
    }
    let extended_l2 = incompatible & 16 != 0;
    let external = incompatible & 4 != 0;

    // Header extensions follow the header, up to the end of the first cluster.
    let ext_area = file.sub(header_len, cluster.saturating_sub(header_len));
    let (exts, ext_len) = read_extensions(&cx, ext_area).await?;
    let ext_span = ext_area.sub(0, ext_len);
    if !ext_span.is_empty() {
        cx.emit(
            Node::new("Header extensions")
                .span(ext_span)
                .summary(
                    exts.iter()
                        .filter(|e| e.kind != 0)
                        .map(|e| lookup(EXTENSIONS, e.kind.into()).unwrap_or("unknown"))
                        .collect::<Vec<_>>()
                        .join(", "),
                )
                .lazy(extensions, (ext_span, Arc::new(exts.clone()))),
        );
    }
    let backing_format = ext_text(&cx, &exts, EXT_BACKING_FORMAT).await?;
    let data_file = ext_text(&cx, &exts, EXT_DATA_FILE).await?;

    let backing = backing_name(&cx, file, h.backing_offset, h.backing_size).await?;
    let mut header_end = ext_span.end().saturating_sub(file.offset).max(header_len);
    if let Some((name, span)) = &backing {
        header_end = header_end.max(span.end().saturating_sub(file.offset));
        cx.emit(
            Node::new("Backing file name")
                .span(*span)
                .value(Value::Text(name.clone())),
        );
    }
    if header_end < cluster {
        cx.emit(
            Node::new("Unused")
                .span(file.sub(header_end, cluster.saturating_sub(header_end)))
                .summary("rest of the header cluster"),
        );
    }

    let bitmaps = match exts.iter().find(|e| e.kind == EXT_BITMAPS) {
        Some(e) => {
            let d = cx.read_avail(e.data).await?;
            let count = u32_be(&d, 0).unwrap_or(0);
            let dir_size = u64_be(&d, 8).unwrap_or(0);
            let dir_offset = u64_be(&d, 16).unwrap_or(0);
            (count > 0 && dir_offset != 0).then_some((dir_offset, dir_size, count))
        }
        None => None,
    };
    let crypto = match exts.iter().find(|e| e.kind == EXT_CRYPTO) {
        Some(e) => {
            let d = cx.read_avail(e.data).await?;
            let offset = u64_be(&d, 0).unwrap_or(0);
            let len = u64_be(&d, 8).unwrap_or(0);
            (offset != 0).then(|| file.sub(offset, len))
        }
        None => None,
    };

    let mut summary = format!(
        "QCOW2 version {version} image, {} virtual, {} clusters",
        size(h.size),
        size(cluster)
    );
    if version >= 3 {
        summary.push_str(&format!(
            ", {}",
            lookup(COMPRESSION, compression.into()).unwrap_or("unknown compression")
        ));
    }
    if extended_l2 {
        summary.push_str(", extended L2 entries");
    }
    if h.crypt != 0 {
        summary.push_str(&format!(
            ", {} encrypted",
            lookup(CRYPT, h.crypt.into()).unwrap_or("unknown")
        ));
    }
    if h.snapshots > 0 {
        summary.push_str(&format!(
            ", {} snapshot{}",
            h.snapshots,
            if h.snapshots == 1 { "" } else { "s" }
        ));
    }
    if let Some((_, _, n)) = bitmaps {
        summary.push_str(&format!(", {n} bitmap{}", if n == 1 { "" } else { "s" }));
    }
    if let Some((name, _)) = &backing {
        summary.push_str(&format!(", backed by {name:?}"));
        if let Some(f) = &backing_format {
            summary.push_str(&format!(" ({f})"));
        }
    }
    if let Some(name) = &data_file {
        summary.push_str(&format!(", data in {name:?}"));
    }
    cx.annotate(summary);

    let entry = if extended_l2 { 16 } else { 8 };
    let image = Arc::new(Image {
        input,
        version,
        cluster_bits: h.cluster_bits,
        l2_entries: cluster.checked_div(entry).unwrap_or(0),
        l2_entry_size: entry,
        l1: file.sub_exact(h.l1_offset, u64::from(h.l1_size).saturating_mul(8))?,
        size: h.size,
        backing: backing.is_some(),
        external,
        codec: if compression == 1 {
            Codec::Zstd
        } else {
            Codec::Deflate
        },
        refcount_table: file.sub(
            h.refcount_offset,
            u64::from(h.refcount_clusters).saturating_mul(cluster),
        ),
        refcount_order: refcount_order.min(6),
        snapshots: (h.snapshots > 0).then_some((h.snapshots_offset, h.snapshots)),
        bitmaps,
        crypto,
        header_end,
    });
    cx.emit(l1_node("L1 table", &image, image.l1));
    if h.refcount_offset != 0 {
        let rt = image.refcount_table;
        cx.emit(
            Node::new("Refcount table")
                .span(rt)
                .summary(format!(
                    "{} entries, {}-bit refcounts",
                    rt.len / 8,
                    1u32 << image.refcount_order
                ))
                .lazy(refcount_table, image.clone()),
        );
    }
    if h.snapshots > 0 {
        cx.emit(
            Node::new("Snapshots")
                .summary(format!("{}", h.snapshots))
                .lazy(snapshots, image.clone()),
        );
    }
    if let Some((offset, dir_size, count)) = bitmaps {
        let mut node = Node::new("Bitmaps")
            .span(file.sub(offset, dir_size))
            .summary(format!("{count} in a {} directory", size(dir_size)))
            .lazy(bitmap_directory, image.clone());
        if autoclear & 1 == 0 {
            node = node.diag(Diagnostic::note(
                "the BITMAPS auto-clear bit is clear: an older QEMU wrote the image, the bitmaps are stale",
            ));
        }
        cx.emit(node);
    }
    if let Some(span) = crypto {
        let node = if h.crypt == 2 {
            embedded_as(
                "Encryption header",
                input.nested(span),
                &super::luks::FORMAT,
            )
        } else {
            Node::new("Encryption header").span(span)
        };
        cx.emit(node.summary(size(span.len)));
    }
    cx.emit(
        Node::new("Host cluster map")
            .span(file)
            .summary("what each cluster of the file holds")
            .lazy(cluster_map, image.clone()),
    );
    if compression > 1 {
        cx.emit(
            Node::new("Virtual disk").diag(Diagnostic::unsupported(format!(
                "compression type {compression}"
            ))),
        );
        return Ok(());
    }
    if external {
        cx.emit(
            Node::new("Virtual disk")
                .summary(size(h.size))
                .diag(Diagnostic::note(format!(
                    "guest data is in the external data file {:?}",
                    data_file.unwrap_or_default()
                ))),
        );
        return Ok(());
    }
    cx.emit(virtual_disk_node(image, h.crypt));
    Ok(())
}

/// The text of a header extension, if present.
async fn ext_text(cx: &Cx, exts: &[Ext], kind: u32) -> Result<Option<String>> {
    match exts.iter().find(|e| e.kind == kind) {
        Some(e) => Ok(Some(crate::text::until_nul(&cx.read_avail(e.data).await?))),
        None => Ok(None),
    }
}

/// Walks the header extensions: their list and the bytes they occupy
/// (through the end marker).
async fn read_extensions(cx: &Cx, area: Span) -> Result<(Vec<Ext>, u64)> {
    let mut out = Vec::new();
    let mut at = 0u64;
    for _ in 0..MAX_ITEMS {
        let head = cx.read_avail(area.sub(at, 8)).await?;
        let (Some(kind), Some(len)) = (u32_be(&head, 0), u32_be(&head, 4)) else {
            break;
        };
        let data = area.sub(at.saturating_add(8), len.into());
        out.push(Ext { kind, data });
        at = at.saturating_add(8u64.saturating_add(align(len.into(), 8)));
        if kind == 0 {
            break;
        }
    }
    Ok((out, at.min(area.len)))
}

async fn extensions(cx: Cx, (area, exts): (Span, Arc<Vec<Ext>>)) -> Result<()> {
    for e in exts.iter() {
        let start = e.data.offset.saturating_sub(8).saturating_sub(area.offset);
        let span = area.sub(start, 8u64.saturating_add(align(e.data.len, 8)));
        let mut node = struct_node(ext_name(e.kind), span, BE, (), ext_layout);
        node = match e.kind {
            EXT_BACKING_FORMAT | EXT_DATA_FILE => node.summary(format!(
                "{:?}",
                crate::text::until_nul(&cx.read_avail(e.data).await?)
            )),
            EXT_FEATURES => node.summary(format!("{} features", e.data.len / 48)),
            0 => node,
            _ => node.summary(size(e.data.len)),
        };
        cx.push(node).await;
    }
    Ok(())
}

fn ext_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let kind = f
        .u32("Type")
        .with(|&v, n| {
            n.value(Value::Enum {
                raw: v.into(),
                bits: 32,
                name: lookup(EXTENSIONS, v.into()),
            })
        })
        .emit()?;
    let len = u64::from(f.u32("Length").emit()?);
    let start = f.pos();
    match kind {
        0 => return Ok(()),
        EXT_BACKING_FORMAT => {
            f.ascii("Backing file format", len).emit()?;
        }
        EXT_DATA_FILE => {
            f.ascii("External data file name", len).emit()?;
        }
        EXT_FEATURES => {
            for _ in 0..(len / 48).min(to_u64(MAX_ITEMS)) {
                let at = to_usize(f.pos());
                let raw = f
                    .block()
                    .data
                    .get(at..at.saturating_add(48))
                    .unwrap_or_default();
                let kind = raw.first().copied().unwrap_or(0);
                let bit = raw.get(1).copied().unwrap_or(0);
                let name = crate::text::until_nul(raw.get(2..).unwrap_or_default());
                f.node(
                    struct_node("Feature", f.peek_span(48), BE, (), feature_layout).summary(
                        format!(
                            "{} bit {bit}: {name}",
                            lookup(FEATURE_TYPES, kind.into()).unwrap_or("unknown")
                        ),
                    ),
                );
                f.skip(48);
            }
        }
        EXT_BITMAPS => {
            f.u32("Bitmaps").emit()?;
            f.u32("Reserved").emit()?;
            f.u64("Bitmap directory size")
                .with(|&v, n| n.summary(size(v)))
                .emit()?;
            f.u64("Bitmap directory offset").hex().emit()?;
        }
        EXT_CRYPTO => {
            f.u64("Encryption header offset").hex().emit()?;
            f.u64("Encryption header length")
                .with(|&v, n| n.summary(size(v)))
                .emit()?;
        }
        _ => {
            f.bytes("Data", len).emit()?;
        }
    }
    // Whatever the known fields left of the declared length, then padding.
    f.seek(start.saturating_add(len));
    let pad = align(len, 8).saturating_sub(len);
    if pad > 0 {
        f.bytes("Padding", pad).emit()?;
    }
    Ok(())
}

fn feature_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Type").enumeration(FEATURE_TYPES).emit()?;
    f.u8("Bit").emit()?;
    f.ascii("Name", 46).emit()?;
    Ok(())
}

fn virtual_disk_node(image: Arc<Image>, crypt: u32) -> Node {
    let node = Node::new("Virtual disk").summary(size(image.size));
    if crypt != 0 {
        return node.diag(Diagnostic::unsupported("encrypted image"));
    }
    node.lazy(virtual_disk, image)
}

async fn backing_name(
    cx: &Cx,
    file: Span,
    offset: u64,
    len: u32,
) -> Result<Option<(String, Span)>> {
    if offset == 0 || len == 0 {
        return Ok(None);
    }
    let span = file.sub(offset, u64::from(len).min(1023));
    let name = String::from_utf8_lossy(&cx.read_avail(span).await?).into_owned();
    Ok(Some((name, span)))
}

async fn qcow1(cx: &Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, Header1::SIZE);
    let h = parse(cx, span, BE, &(), Header1::layout).await?;
    cx.emit(Header1::node("Header", span, BE));
    if !(9..=21).contains(&h.cluster_bits) || !(6..=21).contains(&h.l2_bits) {
        return Err(Diagnostic::malformed("implausible cluster or L2 size").at(span));
    }
    let backing = backing_name(cx, file, h.backing_offset, h.backing_size).await?;
    cx.annotate(format!(
        "QCOW version 1 image, {} virtual, {} clusters{}{}",
        size(h.size),
        size(1u64 << h.cluster_bits),
        if h.crypt != 0 { ", AES encrypted" } else { "" },
        match &backing {
            Some((name, _)) => format!(", backed by {name:?}"),
            None => String::new(),
        }
    ));
    let mut header_end = Header1::SIZE;
    if let Some((name, span)) = &backing {
        header_end = header_end.max(span.end().saturating_sub(file.offset));
        cx.emit(
            Node::new("Backing file name")
                .span(*span)
                .value(Value::Text(name.clone())),
        );
    }
    let l2_entries = 1u64 << h.l2_bits;
    let covered = l2_entries << h.cluster_bits;
    let l1_entries = h.size.div_ceil(covered.max(1));
    let image = Arc::new(Image {
        input,
        version: 1,
        cluster_bits: h.cluster_bits.into(),
        l2_entries,
        l2_entry_size: 8,
        l1: file.sub_exact(h.l1_offset, l1_entries.saturating_mul(8))?,
        size: h.size,
        backing: backing.is_some(),
        external: false,
        codec: Codec::Deflate,
        refcount_table: file.sub(0, 0),
        refcount_order: 4,
        snapshots: None,
        bitmaps: None,
        crypto: None,
        header_end,
    });
    cx.emit(l1_node("L1 table", &image, image.l1));
    cx.emit(
        Node::new("Host cluster map")
            .span(file)
            .summary("what each part of the file holds")
            .lazy(cluster_map, image.clone()),
    );
    cx.emit(virtual_disk_node(image, h.crypt));
    Ok(())
}

// ---------------------------------------------------------------------------
// L1 and L2 tables

fn l1_node(name: &'static str, image: &Arc<Image>, l1: Span) -> Node {
    Node::new(name)
        .span(l1)
        .summary(format!(
            "{}, each covering {} of the guest",
            crate::formats::util::arcutil::count(l1.len / 8, "entry", "entries"),
            size(image.l2_covers())
        ))
        .lazy(l1_table, (image.clone(), l1))
}

/// A run of identical "nothing here" entries `[first, last]`.
fn unallocated_run(prefix: &str, first: u64, last: u64, span: Span, what: &'static str) -> Node {
    let name = if first == last {
        format!("{prefix}[{first}]")
    } else {
        format!("{prefix}[{first}–{last}]")
    };
    Node::new(name).span(span).value(Value::Enum {
        raw: 0,
        bits: 64,
        name: Some(what),
    })
}

async fn l1_table(cx: Cx, (image, l1): (Arc<Image>, Span)) -> Result<()> {
    let count = l1.len / 8;
    let covered = image.l2_covers();
    let mut run: Option<u64> = None;
    let flush = |run: &mut Option<u64>, end: u64| -> Option<Node> {
        let first = run.take()?;
        let last = end.saturating_sub(1);
        Some(
            unallocated_run(
                "L1",
                first,
                last,
                l1.sub(
                    first.saturating_mul(8),
                    end.saturating_sub(first).saturating_mul(8),
                ),
                "unallocated",
            )
            .summary(format!(
                "guest {:#x}–{:#x}: no L2 table",
                first.saturating_mul(covered),
                end.saturating_mul(covered).saturating_sub(1)
            )),
        )
    };
    for i in 0..count {
        cx.progress(i, count);
        let span = l1.sub(i.saturating_mul(8), 8);
        let entry = u64_be(&cx.read(span).await?, 0).unwrap_or(0);
        let Some(table) = image.l2_table(entry) else {
            run.get_or_insert(i);
            cx.checkpoint().await;
            continue;
        };
        if let Some(n) = flush(&mut run, i) {
            cx.push(n).await;
        }
        let guest = i.saturating_mul(covered);
        let value = if image.version == 1 {
            hex(entry, 64)
        } else {
            let (set, unknown) = crate::value::decode_flags(L1_FLAGS, entry & !OFFSET_MASK);
            Value::Flags {
                raw: entry,
                bits: 64,
                set,
                unknown,
            }
        };
        cx.push(
            Node::new(format!("L1[{i}]"))
                .span(span)
                .value(value)
                .summary(format!(
                    "guest {guest:#x}–{:#x}: L2 table at {:#x}{}",
                    guest.saturating_add(covered).saturating_sub(1),
                    table.offset.saturating_sub(image.input.span.offset),
                    if entry & COPIED != 0 && image.version > 1 {
                        ", copied"
                    } else {
                        ""
                    }
                ))
                .target(table)
                .lazy(l2_table, (image.clone(), table, guest)),
        )
        .await;
    }
    if let Some(n) = flush(&mut run, count) {
        cx.push(n).await;
    }
    Ok(())
}

/// A guest cluster's backing, from its L2 entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mapping {
    /// Nothing allocated: zeros, or the backing file.
    Unallocated,
    /// Reads as zeros (v3 zero flag), possibly with a preallocated cluster.
    Zero(Option<u64>),
    /// Host offset (in the data file if external).
    Data(u64),
    /// Compressed: host offset and length.
    Compressed(u64, u64),
}

impl Image {
    fn map(&self, entry: u64) -> Mapping {
        if self.version == 1 {
            if entry == 0 {
                return Mapping::Unallocated;
            }
            if entry >> 63 != 0 {
                let shift = 63u32.saturating_sub(self.cluster_bits);
                let mask = 1u64.checked_shl(shift).map_or(0, |v| v.saturating_sub(1));
                let len = entry.checked_shr(shift).unwrap_or(0) & self.cluster().saturating_sub(1);
                return Mapping::Compressed(entry & mask, len);
            }
            return Mapping::Data(entry);
        }
        if entry & COMPRESSED != 0 {
            // Offset in the low bits, additional 512-byte sectors above.
            let bits = 62u32.saturating_sub(self.cluster_bits.saturating_sub(8));
            let mask = 1u64
                .checked_shl(bits)
                .map_or(u64::MAX, |v| v.saturating_sub(1));
            let offset = entry & mask;
            let sectors = (entry & !(COPIED | COMPRESSED))
                .checked_shr(bits)
                .unwrap_or(0);
            let len = sectors
                .saturating_add(1)
                .saturating_mul(512)
                .saturating_sub(offset & 511);
            return Mapping::Compressed(offset, len);
        }
        let offset = entry & OFFSET_MASK;
        if entry & 1 != 0 && self.version >= 3 && !self.extended() {
            return Mapping::Zero((offset != 0).then_some(offset));
        }
        if offset == 0 {
            Mapping::Unallocated
        } else {
            Mapping::Data(offset)
        }
    }

    /// The exact span of a compressed cluster (a zstd frame is trimmed to
    /// its end; deflate runs to the end of its last sector).
    async fn compressed_span(&self, cx: &Cx, offset: u64, len: u64) -> Result<Span> {
        let span = self.input.span.sub(offset, len);
        if self.codec == Codec::Zstd {
            let head = cx.read_avail(span).await?;
            return Ok(span.sub(0, zstd_frame_len(&head).map_or(span.len, to_u64)));
        }
        Ok(span)
    }
}

/// Subcluster ranges set in a 32-bit bitmap, e.g. `0–3, 7`.
fn bit_ranges(bits: u32) -> String {
    let mut out = Vec::new();
    let mut i = 0u32;
    while i < 32 {
        if (bits >> i) & 1 == 0 {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        while i < 32 && (bits >> i) & 1 != 0 {
            i = i.saturating_add(1);
        }
        let end = i.saturating_sub(1);
        out.push(if start == end {
            format!("{start}")
        } else {
            format!("{start}–{end}")
        });
    }
    if out.is_empty() {
        "none".to_owned()
    } else {
        out.join(", ")
    }
}

async fn l2_table(cx: Cx, (image, table, guest_base): (Arc<Image>, Span, u64)) -> Result<()> {
    let data = cx.read_avail(table).await?;
    if to_u64(data.len()) < table.len {
        cx.diag(Diagnostic::truncated(table, to_u64(data.len())));
    }
    let entry_size = image.l2_entry_size;
    let cluster = image.cluster();
    let file = image.input.span;
    let count = to_u64(data.len()).checked_div(entry_size).unwrap_or(0);
    let mut run: Option<(u64, &'static str)> = None;
    let flush = |run: &mut Option<(u64, &'static str)>, end: u64| -> Option<Node> {
        let (first, what) = run.take()?;
        let last = end.saturating_sub(1);
        let g0 = guest_base.saturating_add(first.saturating_mul(cluster));
        let g1 = guest_base
            .saturating_add(end.saturating_mul(cluster))
            .saturating_sub(1);
        Some(
            unallocated_run(
                "L2",
                first,
                last,
                table.sub(
                    first.saturating_mul(entry_size),
                    end.saturating_sub(first).saturating_mul(entry_size),
                ),
                what,
            )
            .summary(format!("guest {g0:#x}–{g1:#x}: {what}")),
        )
    };
    for j in 0..count {
        if j.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let at = to_usize(j.saturating_mul(entry_size));
        let entry = u64_be(&data, at).unwrap_or(0);
        let bitmap = if image.extended() {
            u64_be(&data, at.saturating_add(8)).unwrap_or(0)
        } else {
            0
        };
        let mapping = image.map(entry);
        let plain = match mapping {
            Mapping::Unallocated if bitmap == 0 => Some("unallocated"),
            Mapping::Zero(None) => Some("zero"),
            _ => None,
        };
        if let Some(what) = plain {
            match run {
                Some((_, w)) if w == what => {}
                _ => {
                    if let Some(n) = flush(&mut run, j) {
                        cx.push(n).await;
                    }
                    run = Some((j, what));
                }
            }
            continue;
        }
        if let Some(n) = flush(&mut run, j) {
            cx.push(n).await;
        }
        let guest = guest_base.saturating_add(j.saturating_mul(cluster));
        let span = table.sub(j.saturating_mul(entry_size), entry_size);
        let copied = if entry & COPIED != 0 && image.version > 1 {
            ", copied"
        } else {
            ""
        };
        let where_ = if image.external {
            " in the data file"
        } else {
            ""
        };
        let mut node = Node::new(format!("L2[{j}]")).span(span);
        node = match mapping {
            Mapping::Data(offset) if image.extended() => {
                let alloc = u32::try_from(bitmap & 0xffff_ffff).unwrap_or(0);
                let zero = u32::try_from(bitmap >> 32).unwrap_or(0);
                node.summary(format!(
                    "guest {guest:#x}: host {offset:#x}{where_}{copied}; subclusters allocated {}, zero {}",
                    bit_ranges(alloc),
                    bit_ranges(zero)
                ))
            }
            Mapping::Data(offset) => node.summary(format!(
                "guest {guest:#x}: host {offset:#x}{where_}{copied}"
            )),
            Mapping::Zero(Some(offset)) => node.summary(format!(
                "guest {guest:#x}: zero, preallocated at {offset:#x}{copied}"
            )),
            Mapping::Compressed(offset, len) => node.summary(format!(
                "guest {guest:#x}: compressed, at most {len} bytes at {offset:#x}"
            )),
            Mapping::Unallocated => {
                let zero = u32::try_from(bitmap >> 32).unwrap_or(0);
                node.summary(format!(
                    "guest {guest:#x}: unallocated; subclusters zero {}",
                    bit_ranges(zero)
                ))
            }
            Mapping::Zero(None) => node,
        };
        // Offsets in an external data file do not point into this file.
        if let Mapping::Data(offset) = mapping
            && !image.external
        {
            node = node.target(file.sub(offset, cluster));
        }
        cx.push(node.lazy(l2_entry, (image.clone(), span))).await;
    }
    if let Some(n) = flush(&mut run, count) {
        cx.push(n).await;
    }
    Ok(())
}

async fn l2_entry(cx: Cx, (image, span): (Arc<Image>, Span)) -> Result<()> {
    let raw = cx.read(span).await?;
    let entry = u64_be(&raw, 0).unwrap_or(0);
    let mapping = image.map(entry);
    let d8 = span.sub(0, 8);
    if image.version == 1 {
        cx.emit(Node::new("Descriptor").span(d8).value(hex(entry, 64)));
    } else {
        let (set, unknown) = crate::value::decode_flags(
            L2_FLAGS,
            match mapping {
                Mapping::Compressed(..) => entry & (COPIED | COMPRESSED),
                _ => entry & !OFFSET_MASK,
            },
        );
        cx.emit(
            Node::new("Descriptor")
                .span(d8)
                .value(Value::Flags {
                    raw: entry,
                    bits: 64,
                    set,
                    unknown,
                })
                .desc("Bit 63: refcount is exactly one; bit 62: compressed; bits 9–55: host offset; bit 0: reads as zeros"),
        );
    }
    match mapping {
        Mapping::Compressed(offset, len) => {
            let span = image.compressed_span(&cx, offset, len).await?;
            cx.emit(
                Node::new("Compressed data offset")
                    .span(d8)
                    .value(hex(offset, 64)),
            );
            cx.emit(
                Node::new("Compressed cluster")
                    .span(span)
                    .summary(format!("{} bytes", span.len))
                    .lazy(decoded_leaf, (span, image.codec.clone(), image.cluster())),
            );
        }
        Mapping::Data(offset) | Mapping::Zero(Some(offset)) => {
            let mut node = Node::new("Host offset").span(d8).value(hex(offset, 64));
            if image.external {
                node = node.desc("An offset in the external data file");
            } else {
                node = node.target(image.input.span.sub(offset, image.cluster()));
            }
            cx.emit(node);
        }
        _ => {}
    }
    if image.extended() {
        let b = span.sub(8, 8);
        let alloc = u32_be(&raw, 12).unwrap_or(0);
        let zero = u32_be(&raw, 8).unwrap_or(0);
        cx.emit(
            Node::new("Subcluster zero bitmap")
                .span(b.sub(0, 4))
                .value(hex(zero, 32))
                .summary(bit_ranges(zero)),
        );
        cx.emit(
            Node::new("Subcluster allocation bitmap")
                .span(b.sub(4, 4))
                .value(hex(alloc, 32))
                .summary(bit_ranges(alloc)),
        );
    }
    Ok(())
}

/// A compressed piece of a virtual disk (a cluster or grain): decoded on
/// expansion and shown as data. It is a fragment of a disk, not a file, so
/// it is not identified as a format; the virtual disk shows it in place.
pub(super) async fn decoded_leaf(
    cx: Cx,
    (span, codec, expected): (Span, Codec, u64),
) -> Result<()> {
    let decoded = crate::codec::decode_span(&cx, span, &codec, Some(expected)).await?;
    let mut node = Node::new("Decompressed")
        .span(decoded.span)
        .summary(size(decoded.span.len));
    if let Some(e) = decoded.error {
        node = node.diag(e);
    }
    cx.emit(node);
    Ok(())
}

// ---------------------------------------------------------------------------
// Refcounts

impl Image {
    fn refcount_bits(&self) -> u64 {
        1u64 << self.refcount_order.min(6)
    }

    /// Clusters described by one refcount block.
    fn refcounts_per_block(&self) -> u64 {
        self.cluster()
            .saturating_mul(8)
            .checked_div(self.refcount_bits())
            .unwrap_or(0)
    }
}

/// Entry `i` of a refcount block (big-endian; sub-byte widths are packed
/// from the least significant bit, as QEMU does).
fn refcount(block: &[u8], i: u64, bits: u64) -> u64 {
    match bits {
        1 | 2 | 4 => {
            let per = 8u64.checked_div(bits).unwrap_or(1);
            let byte = block
                .get(to_usize(i.checked_div(per).unwrap_or(0)))
                .copied()
                .unwrap_or(0);
            let shift = i.checked_rem(per).unwrap_or(0).saturating_mul(bits);
            u64::from(byte >> shift) & ((1u64 << bits).saturating_sub(1))
        }
        8 => block.get(to_usize(i)).copied().unwrap_or(0).into(),
        16 => u16_be(block, to_usize(i.saturating_mul(2)))
            .unwrap_or(0)
            .into(),
        32 => u32_be(block, to_usize(i.saturating_mul(4)))
            .unwrap_or(0)
            .into(),
        _ => u64_be(block, to_usize(i.saturating_mul(8))).unwrap_or(0),
    }
}

async fn refcount_table(cx: Cx, image: Arc<Image>) -> Result<()> {
    let rt = image.refcount_table;
    let data = cx.read_avail(rt).await?;
    let per_block = image.refcounts_per_block();
    let count = to_u64(data.len()) / 8;
    let mut run: Option<u64> = None;
    for i in 0..=count {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let entry = if i < count {
            u64_be(&data, to_usize(i.saturating_mul(8))).unwrap_or(0)
        } else {
            1
        };
        let offset = entry & !0x1ff;
        if offset == 0 && i < count {
            run.get_or_insert(i);
            continue;
        }
        if let Some(first) = run.take() {
            cx.push(
                unallocated_run(
                    "Refcount table",
                    first,
                    i.saturating_sub(1),
                    rt.sub(
                        first.saturating_mul(8),
                        i.saturating_sub(first).saturating_mul(8),
                    ),
                    "unallocated",
                )
                .summary(format!(
                    "clusters {:#x}–{:#x}: no refcount block (all free)",
                    first.saturating_mul(per_block),
                    i.saturating_mul(per_block).saturating_sub(1)
                )),
            )
            .await;
        }
        if i == count {
            break;
        }
        let block = image.input.span.sub(offset, image.cluster());
        let first_cluster = i.saturating_mul(per_block);
        cx.push(
            Node::new(format!("Refcount table[{i}]"))
                .span(rt.sub(i.saturating_mul(8), 8))
                .value(hex(entry, 64))
                .summary(format!(
                    "clusters {first_cluster:#x}–{:#x}: refcount block at {offset:#x}",
                    first_cluster.saturating_add(per_block).saturating_sub(1)
                ))
                .target(block)
                .lazy(refcount_block, (image.clone(), block, first_cluster)),
        )
        .await;
    }
    Ok(())
}

async fn refcount_block(cx: Cx, (image, block, first): (Arc<Image>, Span, u64)) -> Result<()> {
    let data = cx.read_avail(block).await?;
    let bits = image.refcount_bits();
    let entries = to_u64(data.len())
        .saturating_mul(8)
        .checked_div(bits)
        .unwrap_or(0);
    let file_clusters = image.input.span.len.div_ceil(image.cluster().max(1));
    let mut i = 0u64;
    while i < entries {
        let value = refcount(&data, i, bits);
        let start = i;
        while i < entries && refcount(&data, i, bits) == value {
            i = i.saturating_add(1);
            if i.is_multiple_of(4096) {
                cx.checkpoint().await;
            }
        }
        // Byte span of entries [start, i).
        let b0 = start.saturating_mul(bits) / 8;
        let b1 = i.saturating_mul(bits).div_ceil(8);
        let c0 = first.saturating_add(start);
        let c1 = first.saturating_add(i).saturating_sub(1);
        let beyond = c0 >= file_clusters;
        let name = if start.saturating_add(1) == i {
            format!("Cluster {c0:#x}")
        } else {
            format!("Clusters {c0:#x}–{c1:#x}")
        };
        cx.push(
            Node::new(name)
                .span(block.sub(b0, b1.saturating_sub(b0)))
                .value(uint(value, 64))
                .summary(match (value, beyond) {
                    (0, true) => "free (beyond the end of the file)".to_owned(),
                    (0, false) => "free".to_owned(),
                    (1, _) => "refcount 1".to_owned(),
                    (n, _) => format!("refcount {n} (shared with snapshots)"),
                }),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Snapshots

async fn snapshots(cx: Cx, image: Arc<Image>) -> Result<()> {
    let Some((offset, count)) = image.snapshots else {
        return Ok(());
    };
    let file = image.input.span;
    cx.set_count(Count::Exact(count.into()));
    let mut at = offset;
    for i in 0..u64::from(count).min(to_u64(MAX_ITEMS)) {
        let span = file.sub(at, SnapshotHeader::SIZE);
        let s = parse(&cx, span, BE, &(), SnapshotHeader::layout).await?;
        let id_at = at
            .saturating_add(SnapshotHeader::SIZE)
            .saturating_add(s.extra_size.into());
        let id = String::from_utf8_lossy(&cx.read_avail(file.sub(id_at, s.id_size.into())).await?)
            .into_owned();
        let name_at = id_at.saturating_add(s.id_size.into());
        let name =
            String::from_utf8_lossy(&cx.read_avail(file.sub(name_at, s.name_size.into())).await?)
                .into_owned();
        let end = name_at.saturating_add(s.name_size.into());
        let total = align(end.saturating_sub(at), 8);
        cx.push(
            struct_node(
                format!("Snapshot {i}: {name}"),
                file.sub(at, total),
                BE,
                image.clone(),
                snapshot_layout,
            )
            .summary(format!(
                "id {id}, {} L1 entries, VM state {}",
                s.l1_size,
                size(s.vm_state_size.into())
            )),
        )
        .await;
        at = at.saturating_add(total.max(8));
    }
    Ok(())
}

fn snapshot_layout(f: &mut Fields<'_>, image: &Arc<Image>) -> Result<()> {
    let s = SnapshotHeader::read(f)?;
    let extra = u64::from(s.extra_size);
    let extra_start = f.pos();
    if extra >= 8 {
        f.u64("VM state size (64-bit)")
            .with(|&v, n| n.summary(size(v)))
            .emit()?;
    }
    if extra >= 16 {
        f.u64("Virtual disk size")
            .with(|&v, n| n.summary(size(v)))
            .emit()?;
    }
    if extra >= 24 {
        f.u64("Instruction count")
            .with(|&v, n| {
                if v == u64::MAX {
                    n.summary("not recorded")
                } else {
                    n
                }
            })
            .emit()?;
    }
    let used = f.pos().saturating_sub(extra_start);
    if extra > used {
        f.bytes("Extra data (unknown)", extra.saturating_sub(used))
            .emit()?;
    }
    f.seek(extra_start.saturating_add(extra));
    f.ascii("Id", s.id_size.into()).emit()?;
    f.ascii("Name", s.name_size.into()).emit()?;
    let pad = f.remaining();
    if pad > 0 {
        f.bytes("Padding", pad).emit()?;
    }
    if s.l1_offset != 0 {
        let l1 = image
            .input
            .span
            .sub(s.l1_offset, u64::from(s.l1_size).saturating_mul(8));
        f.node(l1_node("L1 table", image, l1));
    }
    Ok(())
}

/// The snapshot table: each snapshot's span and L1 table.
async fn snapshot_table(cx: &Cx, image: &Image) -> Result<Vec<(Span, Span)>> {
    let mut out = Vec::new();
    let Some((offset, count)) = image.snapshots else {
        return Ok(out);
    };
    let file = image.input.span;
    let mut at = offset;
    for _ in 0..u64::from(count).min(to_u64(MAX_ITEMS)) {
        let span = file.sub(at, SnapshotHeader::SIZE);
        let Ok(s) = parse(cx, span, BE, &(), SnapshotHeader::layout).await else {
            break;
        };
        let total = align(
            SnapshotHeader::SIZE
                .saturating_add(s.extra_size.into())
                .saturating_add(s.id_size.into())
                .saturating_add(s.name_size.into()),
            8,
        );
        let l1 = file.sub(s.l1_offset, u64::from(s.l1_size).saturating_mul(8));
        out.push((file.sub(at, total), l1));
        at = at.saturating_add(total);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Bitmaps

/// Bitmap directory entries: span, table offset, table entries, name.
async fn read_bitmaps(cx: &Cx, image: &Image) -> Result<Vec<(Span, u64, u32, String)>> {
    let mut out = Vec::new();
    let Some((offset, dir_size, count)) = image.bitmaps else {
        return Ok(out);
    };
    let dir = image
        .input
        .span
        .sub(offset, dir_size.min(MAX_BITMAP_DIRECTORY));
    let data = cx.read_avail(dir).await?;
    let mut at = 0usize;
    for _ in 0..count.min(u32::try_from(MAX_ITEMS).unwrap_or(u32::MAX)) {
        let (Some(table), Some(entries), Some(name_size), Some(extra)) = (
            u64_be(&data, at),
            u32_be(&data, at.saturating_add(8)),
            u16_be(&data, at.saturating_add(18)),
            u32_be(&data, at.saturating_add(20)),
        ) else {
            break;
        };
        let name_at = at.saturating_add(24).saturating_add(to_usize(extra.into()));
        let name = data
            .get(name_at..name_at.saturating_add(name_size.into()))
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let len = to_usize(align(
            to_u64(name_at.saturating_add(name_size.into()).saturating_sub(at)),
            8,
        ));
        out.push((dir.sub(to_u64(at), to_u64(len)), table, entries, name));
        at = at.saturating_add(len.max(8));
        cx.checkpoint().await;
    }
    Ok(out)
}

async fn bitmap_directory(cx: Cx, image: Arc<Image>) -> Result<()> {
    for (span, _, entries, name) in read_bitmaps(&cx, &image).await? {
        cx.push(
            struct_node(
                format!("Bitmap {name:?}"),
                span,
                BE,
                image.clone(),
                bitmap_layout,
            )
            .summary(format!("{entries} bitmap table entries")),
        )
        .await;
    }
    Ok(())
}

fn bitmap_layout(f: &mut Fields<'_>, image: &Arc<Image>) -> Result<()> {
    let e = BitmapEntry::read(f)?;
    if e.extra_size > 0 {
        f.bytes("Extra data", e.extra_size.into()).emit()?;
    }
    f.ascii("Name", e.name_size.into()).emit()?;
    let pad = f.remaining();
    if pad > 0 {
        f.bytes("Padding", pad).emit()?;
    }
    let table = image
        .input
        .span
        .sub(e.table_offset, u64::from(e.table_size).saturating_mul(8));
    // One bitmap cluster holds cluster_size * 8 bits of `granularity` each.
    let granularity = 1u64.checked_shl(e.granularity_bits.into()).unwrap_or(0);
    let covers = image
        .cluster()
        .saturating_mul(8)
        .saturating_mul(granularity);
    f.node(
        Node::new("Bitmap table")
            .span(table)
            .summary(format!(
                "{} entries, each covering {} of the guest",
                e.table_size,
                size(covers)
            ))
            .lazy(bitmap_table, (image.clone(), table, covers)),
    );
    Ok(())
}

async fn bitmap_table(cx: Cx, (image, table, covers): (Arc<Image>, Span, u64)) -> Result<()> {
    let data = cx.read_avail(table).await?;
    let count = to_u64(data.len()) / 8;
    let mut i = 0u64;
    while i < count {
        let entry = u64_be(&data, to_usize(i.saturating_mul(8))).unwrap_or(0);
        let offset = entry & OFFSET_MASK;
        let guest = i.saturating_mul(covers);
        if offset != 0 {
            let cluster = image.input.span.sub(offset, image.cluster());
            cx.push(
                Node::new(format!("Bitmap table[{i}]"))
                    .span(table.sub(i.saturating_mul(8), 8))
                    .value(hex(entry, 64))
                    .summary(format!(
                        "guest {guest:#x}–{:#x}: bitmap data at {offset:#x}",
                        guest.saturating_add(covers).saturating_sub(1)
                    ))
                    .target(cluster),
            )
            .await;
            i = i.saturating_add(1);
            continue;
        }
        // Runs of "all zeros" / "all ones" entries.
        let start = i;
        while i < count && u64_be(&data, to_usize(i.saturating_mul(8))) == Some(entry) {
            i = i.saturating_add(1);
            if i.is_multiple_of(4096) {
                cx.checkpoint().await;
            }
        }
        let what = if entry & 1 != 0 {
            "all bits set"
        } else {
            "all bits clear"
        };
        cx.push(
            unallocated_run(
                "Bitmap table",
                start,
                i.saturating_sub(1),
                table.sub(
                    start.saturating_mul(8),
                    i.saturating_sub(start).saturating_mul(8),
                ),
                what,
            )
            .summary(format!(
                "guest {guest:#x}–{:#x}: {what}",
                i.saturating_mul(covers).saturating_sub(1)
            )),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Host cluster map

/// A region of a file: offset and length (relative to the file), what it
/// holds and, for guest data, the guest offset.
#[derive(Clone, Copy, Debug)]
pub(super) struct Region {
    start: u64,
    len: u64,
    role: &'static str,
    guest: Option<u64>,
}

/// Whether `next` continues `prev`: same role, contiguous in the file and,
/// for guest data, in the guest.
fn joins(prev: &Region, next: &Region) -> bool {
    prev.role == next.role
        && prev.start.saturating_add(prev.len) == next.start
        && match (prev.guest, next.guest) {
            (Some(a), Some(b)) => a.saturating_add(prev.len) == b,
            (None, None) => true,
            _ => false,
        }
}

/// The regions of a virtual disk file that its metadata accounts for; the
/// rest is shown as unused. Shared by the QCOW, VMDK, VHD and VHDX maps.
#[derive(Clone, Default)]
pub(super) struct Regions {
    list: Vec<Region>,
    full: bool,
}

impl Regions {
    pub(super) fn add(&mut self, start: u64, len: u64, role: &'static str, guest: Option<u64>) {
        if len == 0 {
            return;
        }
        if self.list.len() >= MAX_REGIONS {
            self.full = true;
            return;
        }
        let next = Region {
            start,
            len,
            role,
            guest,
        };
        // Merge with the previous region when contiguous on both sides.
        if let Some(prev) = self.list.last_mut()
            && joins(prev, &next)
        {
            prev.len = prev.len.saturating_add(len);
            return;
        }
        self.list.push(next);
    }

    /// Adds `span` (of the file's source) as a region.
    pub(super) fn span(&mut self, file: Span, span: Span, role: &'static str) {
        if span.source == file.source {
            self.add(
                span.offset.saturating_sub(file.offset),
                span.len,
                role,
                None,
            );
        }
    }

    /// Pushes the regions in file order, with the bytes no region covers
    /// as unused (`why`). Where regions overlap (snapshots sharing clusters
    /// with the active image), the one added first wins.
    pub(super) async fn emit(self, cx: &Cx, file: Span, why: &'static str) {
        self.emit_named(cx, file, "Unused", why).await;
    }

    /// [`Regions::emit`], calling the uncovered bytes `gap_name`.
    pub(super) async fn emit_named(
        self,
        cx: &Cx,
        file: Span,
        gap_name: &'static str,
        why: &'static str,
    ) {
        if self.full {
            cx.diag(Diagnostic::limit(format!(
                "more than {MAX_REGIONS} regions; the map is incomplete"
            )));
        }
        // Bounded by MAX_REGIONS; the sort is stable.
        let mut sorted = self.list;
        sorted.sort_by_key(|x| x.start);
        cx.checkpoint().await;
        let mut list: Vec<Region> = Vec::with_capacity(sorted.len());
        for r in sorted {
            match list.last_mut() {
                Some(prev) if joins(prev, &r) => prev.len = prev.len.saturating_add(r.len),
                _ => list.push(r),
            }
        }
        let gap = |pos: u64, len: u64| {
            Node::new(gap_name)
                .span(file.sub(pos, len))
                .summary(format!("{}, {why}", size(len)))
        };
        let mut pos = 0u64;
        for region in list {
            let end = region.start.saturating_add(region.len).min(file.len);
            if end <= pos {
                continue;
            }
            if region.start > pos {
                let len = region.start.min(file.len).saturating_sub(pos);
                cx.push(gap(pos, len)).await;
                pos = region.start;
            }
            // Clip an overlap with the previous region.
            let skip = pos.saturating_sub(region.start);
            let len = end.saturating_sub(pos);
            let mut summary = size(len);
            if let Some(g) = region.guest {
                let g = g.saturating_add(skip);
                summary = format!(
                    "guest {g:#x}–{:#x}, {summary}",
                    g.saturating_add(len).saturating_sub(1)
                );
            }
            cx.push(
                Node::new(region.role)
                    .span(file.sub(pos, len))
                    .summary(summary),
            )
            .await;
            pos = end;
        }
        if pos < file.len {
            cx.push(gap(pos, file.len.saturating_sub(pos))).await;
        }
    }
}

/// Adds an L1 table's L2 tables and the clusters they map.
async fn map_l1(cx: &Cx, image: &Image, l1: Span, snapshot: bool, out: &mut Regions) -> Result<()> {
    let file = image.input.span;
    let data = cx.read_avail(l1).await?;
    let cluster = image.cluster();
    let covered = image.l2_covers();
    for (i, raw) in data.as_chunks::<8>().0.iter().enumerate() {
        cx.checkpoint().await;
        let entry = u64::from_be_bytes(*raw);
        let Some(table) = image.l2_table(entry) else {
            continue;
        };
        out.span(file, table, "L2 table");
        let entries = cx.read_avail(table).await?;
        let guest_base = to_u64(i).saturating_mul(covered);
        for (j, e) in entries.chunks(to_usize(image.l2_entry_size)).enumerate() {
            if j.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            let guest = guest_base.saturating_add(to_u64(j).saturating_mul(cluster));
            match image.map(u64_be(e, 0).unwrap_or(0)) {
                Mapping::Data(offset) | Mapping::Zero(Some(offset)) if !image.external => {
                    let role = if snapshot { "Snapshot data" } else { "Data" };
                    out.add(offset, cluster, role, Some(guest));
                }
                Mapping::Compressed(offset, len) => {
                    let span = image.compressed_span(cx, offset, len).await?;
                    out.span(
                        file,
                        span,
                        if snapshot {
                            "Snapshot compressed data"
                        } else {
                            "Compressed data"
                        },
                    );
                }
                _ => {}
            }
        }
    }
    Ok(())
}

async fn cluster_map(cx: Cx, image: Arc<Image>) -> Result<()> {
    let file = image.input.span;
    let cluster = image.cluster();
    let mut r = Regions::default();
    r.add(
        0,
        if image.version == 1 {
            image.header_end
        } else {
            cluster
        },
        "Header",
        None,
    );
    // Tables occupy whole clusters (the rest of the last one is slack).
    // (QCOW version 1 packs its L1 table right after the header.)
    let whole = |s: Span| {
        if image.version == 1 {
            s
        } else {
            Span::new(s.source, s.offset, align(s.len, cluster))
        }
    };
    r.span(file, whole(image.l1), "L1 table");
    map_l1(&cx, &image, image.l1, false, &mut r).await?;
    if !image.refcount_table.is_empty() {
        r.span(file, image.refcount_table, "Refcount table");
        let data = cx.read_avail(image.refcount_table).await?;
        for (i, raw) in data.as_chunks::<8>().0.iter().enumerate() {
            if i.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            let offset = u64::from_be_bytes(*raw) & !0x1ff;
            if offset != 0 {
                r.add(offset, cluster, "Refcount block", None);
            }
        }
    }
    for (span, l1) in snapshot_table(&cx, &image).await? {
        r.span(file, span, "Snapshot table");
        r.span(file, whole(l1), "Snapshot L1 table");
        map_l1(&cx, &image, l1, true, &mut r).await?;
    }
    if let Some((offset, dir_size, _)) = image.bitmaps {
        r.add(offset, align(dir_size, cluster), "Bitmap directory", None);
        for (_, table, entries, _) in read_bitmaps(&cx, &image).await? {
            let span = file.sub(table, u64::from(entries).saturating_mul(8));
            r.span(file, whole(span), "Bitmap table");
            let data = cx.read_avail(span).await?;
            for (i, raw) in data.as_chunks::<8>().0.iter().enumerate() {
                if i.is_multiple_of(1024) {
                    cx.checkpoint().await;
                }
                let offset = u64::from_be_bytes(*raw) & OFFSET_MASK;
                if offset != 0 {
                    r.add(offset, cluster, "Bitmap data", None);
                }
            }
        }
    }
    if let Some(span) = image.crypto {
        r.span(file, span, "Encryption header");
    }
    r.emit(&cx, file, "not referenced by any table").await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Virtual disk

/// The length of the zstd frame at the start of `data` (walking its block
/// headers), or `None` if it is not a complete frame.
fn zstd_frame_len(data: &[u8]) -> Option<usize> {
    if data.get(..4)? != [0x28, 0xb5, 0x2f, 0xfd] {
        return None;
    }
    let fhd = *data.get(4)?;
    let single = fhd & 0x20 != 0;
    let dict_len = [0usize, 1, 2, 4].get(usize::from(fhd & 3)).copied()?;
    let fcs_len = match fhd >> 6 {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut pos = 5usize
        .saturating_add(usize::from(!single))
        .saturating_add(dict_len)
        .saturating_add(fcs_len);
    loop {
        let header = data.get(pos..pos.checked_add(3)?)?;
        let h = u32::from(*header.first()?)
            | u32::from(*header.get(1)?) << 8
            | u32::from(*header.get(2)?) << 16;
        let last = h & 1 != 0;
        let size = usize::try_from(h >> 3).ok()?;
        let body = match (h >> 1) & 3 {
            0 | 2 => size,
            1 => 1,
            _ => return None,
        };
        pos = pos.checked_add(3)?.checked_add(body)?;
        if last {
            break;
        }
    }
    if fhd & 0x04 != 0 {
        pos = pos.checked_add(4)?;
    }
    (pos <= data.len()).then_some(pos)
}

async fn virtual_disk(cx: Cx, image: Arc<Image>) -> Result<()> {
    if image.backing {
        cx.diag(Diagnostic::note(
            "unallocated clusters come from the backing file; shown as zeros",
        ));
    }
    let cluster = image.cluster();
    let sub = cluster / 32;
    let covered = image.l2_covers();
    let mut list = PieceList::new(image.l1);
    let l1_count = image.l1.len / 8;
    'outer: for i in 0..l1_count {
        if list.len() >= image.size {
            break;
        }
        cx.progress(list.len(), image.size);
        let entry = u64_be(&cx.read(image.l1.sub(i.saturating_mul(8), 8)).await?, 0).unwrap_or(0);
        let Some(table_span) = image.l2_table(entry) else {
            let want = covered.min(image.size.saturating_sub(list.len()));
            if let Err(e) = list.hole(&cx, want) {
                cx.diag(e);
                break;
            }
            continue;
        };
        let table = cx.read(table_span).await?;
        // An L2 table holds up to 256Ki entries (2 MiB clusters).
        for (j, raw) in table.chunks(to_usize(image.l2_entry_size)).enumerate() {
            let want = cluster.min(image.size.saturating_sub(list.len()));
            if want == 0 {
                break 'outer;
            }
            if j.is_multiple_of(4096) {
                cx.checkpoint().await;
            }
            let entry = u64_be(raw, 0).unwrap_or(0);
            let step = match image.map(entry) {
                Mapping::Unallocated | Mapping::Zero(_) if !image.extended() => {
                    list.hole(&cx, want)
                }
                Mapping::Data(offset) if !image.extended() => {
                    list.data(image.input.span.sub(offset, want));
                    Ok(())
                }
                Mapping::Compressed(offset, len) => {
                    let span = image.compressed_span(&cx, offset, len).await?;
                    match crate::codec::decode_span(&cx, span, &image.codec, Some(cluster)).await {
                        Ok(decoded) => {
                            list.data(decoded.span.sub(0, want));
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
                mapping => {
                    // Extended L2: 32 subclusters, each allocated (data at
                    // its place in the host cluster), zero, or unallocated.
                    let bitmap = u64_be(raw, 8).unwrap_or(0);
                    let host = match mapping {
                        Mapping::Data(offset) => Some(offset),
                        _ => None,
                    };
                    for k in 0..32u64 {
                        let left = want.saturating_sub(k.saturating_mul(sub));
                        if left == 0 {
                            break;
                        }
                        let n = sub.min(left);
                        match host {
                            Some(offset) if (bitmap >> k) & 1 != 0 => list.data(
                                image
                                    .input
                                    .span
                                    .sub(offset.saturating_add(k.saturating_mul(sub)), n),
                            ),
                            _ => list.data(Span::zeros(n)),
                        }
                    }
                    Ok(())
                }
            };
            if let Err(e) = step {
                cx.diag(e);
                break 'outer;
            }
        }
    }
    let span = list.finish(&cx, "qcow-clusters").await?;
    dissect_or_data(cx, image.input.nested(span)).await
}
