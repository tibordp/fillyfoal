//! QEMU copy-on-write images: QCOW (version 1) and QCOW2/QCOW3.
//!
//! The header gives the cluster size and the L1 table; L1 entries point at
//! L2 tables, whose entries map guest clusters to host clusters (possibly
//! deflate- or zstd-compressed). The virtual disk is assembled from that mapping on
//! expansion: allocated clusters in place, compressed clusters decoded,
//! unallocated ones as zeros.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{PieceList, align, size};
use crate::formats::{Codec, Format, Head, Input, Probe, dissect_or_data};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const BE: Endian = Endian::Big;
const MAGIC: &[u8] = b"QFI\xfb";
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
/// Header extensions and snapshots listed at most.
const MAX_ITEMS: usize = 1024;

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
const COMPRESSION: EnumTable = &[(0, "deflate"), (1, "zstd")];

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
        mtime: u32 "Modified" .timestamp(),
        size: u64 "Virtual disk size" .with(|&v, n| n.summary(size(v))),
        cluster_bits: u8 "Cluster bits",
        l2_bits: u8 "L2 bits",
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
        vm_clock_ns: u64 "VM clock (ns)",
        vm_state_size: u32 "VM state size",
        extra_size: u32 "Extra data size",
    }
}

const EXTENSIONS: EnumTable = &[
    (0xe279_2aca, "Backing file format name"),
    (0x6803_f857, "Feature name table"),
    (0x2385_2875, "Bitmaps"),
    (0x0537_be77, "Full disk encryption header"),
    (0x4441_5441, "External data file name"),
];

/// What the virtual disk mapping needs.
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
    /// How compressed clusters are encoded.
    codec: Codec,
}

impl Image {
    fn cluster(&self) -> u64 {
        1u64.checked_shl(self.cluster_bits).unwrap_or(0)
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
    let mut header_len = Header2::SIZE;
    let mut extended_l2 = false;
    let mut compression = 0u8;
    if version >= 3 {
        let span3 = file.sub(Header2::SIZE, Header3::SIZE);
        let h3 = parse(&cx, span3, BE, &(), Header3::layout).await?;
        cx.emit(Header3::node("Version 3 header", span3, BE));
        header_len = u64::from(h3.header_length).max(Header2::SIZE + Header3::SIZE);
        extended_l2 = h3.incompatible & 16 != 0;
        if header_len >= 105 && h3.incompatible & 8 != 0 {
            compression = cx
                .read(file.sub(104, 1))
                .await?
                .first()
                .copied()
                .unwrap_or(0);
            cx.emit(
                Node::new("Compression type")
                    .span(file.sub(104, 1))
                    .value(Value::Enum {
                        raw: compression.into(),
                        bits: 8,
                        name: crate::value::lookup(COMPRESSION, compression.into()),
                    }),
            );
        }
    }
    if !(9..=21).contains(&h.cluster_bits) {
        return Err(Diagnostic::malformed(format!("cluster bits {}", h.cluster_bits)).at(span));
    }
    let backing = backing_name(&cx, file, h.backing_offset, h.backing_size).await?;
    cx.annotate(format!(
        "QCOW{} image, {} virtual, {} clusters{}{}",
        if version >= 3 {
            "3 (qcow2 v3)".to_owned()
        } else {
            "2".to_owned()
        },
        size(h.size),
        size(1u64 << h.cluster_bits),
        if h.snapshots > 0 {
            format!(", {} snapshots", h.snapshots)
        } else {
            String::new()
        },
        match &backing {
            Some((name, _)) => format!(", backed by {name:?}"),
            None => String::new(),
        }
    ));
    if let Some((name, span)) = &backing {
        cx.emit(
            Node::new("Backing file")
                .span(*span)
                .value(Value::Text(name.clone())),
        );
    }
    // Header extensions follow the header, up to the end of the first cluster.
    let ext_area = file.sub(
        header_len,
        (1u64 << h.cluster_bits).saturating_sub(header_len),
    );
    cx.emit(
        Node::new("Header extensions")
            .span(ext_area)
            .lazy(extensions, ext_area),
    );

    let entry = if extended_l2 { 16 } else { 8 };
    let image = Arc::new(Image {
        input,
        version,
        cluster_bits: h.cluster_bits,
        l2_entries: (1u64 << h.cluster_bits).checked_div(entry).unwrap_or(0),
        l2_entry_size: entry,
        l1: file.sub_exact(h.l1_offset, u64::from(h.l1_size).saturating_mul(8))?,
        size: h.size,
        backing: backing.is_some(),
        codec: if compression == 1 {
            Codec::Zstd
        } else {
            Codec::Deflate
        },
    });
    cx.emit(
        Node::new("L1 table")
            .span(image.l1)
            .summary(format!("{} entries", h.l1_size))
            .lazy(l1_table, image.clone()),
    );
    if h.refcount_offset != 0 {
        cx.emit(Node::new("Refcount table").span(file.sub(
            h.refcount_offset,
            u64::from(h.refcount_clusters) << h.cluster_bits,
        )));
    }
    if h.snapshots > 0 {
        cx.emit(
            Node::new("Snapshots")
                .summary(format!("{}", h.snapshots))
                .lazy(snapshots, (file, h.snapshots_offset, h.snapshots)),
        );
    }
    if compression > 1 {
        cx.emit(
            Node::new("Virtual disk").diag(Diagnostic::unsupported(format!(
                "compression type {compression}"
            ))),
        );
        return Ok(());
    }
    cx.emit(virtual_disk_node(image, h.crypt));
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
        "QCOW (version 1) image, {} virtual, {} clusters",
        size(h.size),
        size(1u64 << h.cluster_bits)
    ));
    if let Some((name, span)) = &backing {
        cx.emit(
            Node::new("Backing file")
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
        codec: Codec::Deflate,
    });
    cx.emit(
        Node::new("L1 table")
            .span(image.l1)
            .summary(format!("{l1_entries} entries"))
            .lazy(l1_table, image.clone()),
    );
    cx.emit(virtual_disk_node(image, h.crypt));
    Ok(())
}

async fn extensions(cx: Cx, area: Span) -> Result<()> {
    let mut at = 0u64;
    for _ in 0..MAX_ITEMS {
        let head = cx.read_avail(area.sub(at, 8)).await?;
        let (Some(kind), Some(len)) = (u32_be(&head, 0), u32_be(&head, 4)) else {
            break;
        };
        if kind == 0 {
            cx.push(Node::new("End of extensions").span(area.sub(at, 8)))
                .await;
            break;
        }
        let data = area.sub(at.saturating_add(8), len.into());
        let total = 8u64.saturating_add(u64::from(len).next_multiple_of(8));
        let name = crate::value::lookup(EXTENSIONS, kind.into())
            .map_or_else(|| format!("Extension {kind:#010x}"), str::to_owned);
        let mut node = Node::new(name)
            .span(area.sub(at, total))
            .value(Value::UInt {
                value: kind.into(),
                bits: 32,
                radix: crate::value::Radix::Hex,
            });
        if matches!(kind, 0xe279_2aca | 0x4441_5441) {
            let text = crate::text::until_nul(&cx.read_avail(data).await?);
            node = node.summary(format!("{text:?}"));
        } else if kind == 0x6803_f857 {
            let table = cx.read_avail(data).await?;
            let names: Vec<String> = table
                .as_chunks::<48>()
                .0
                .iter()
                .map(|e| {
                    let kind = match e.first() {
                        Some(0) => "incompatible",
                        Some(1) => "compatible",
                        _ => "autoclear",
                    };
                    format!(
                        "{kind} bit {}: {}",
                        e.get(1).copied().unwrap_or(0),
                        crate::text::until_nul(e.get(2..).unwrap_or_default())
                    )
                })
                .collect();
            node = node.summary(names.join("; "));
        } else {
            node = node.summary(format!("{len} bytes"));
        }
        cx.push(node).await;
        at = at.saturating_add(total);
    }
    Ok(())
}

async fn snapshots(cx: Cx, (file, offset, count): (Span, u64, u32)) -> Result<()> {
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
            SnapshotHeader::node(format!("Snapshot {i}: {name}"), file.sub(at, total), BE).summary(
                format!("id {id}, VM state {}", size(s.vm_state_size.into())),
            ),
        )
        .await;
        at = at.saturating_add(total.max(8));
    }
    Ok(())
}

async fn l1_table(cx: Cx, image: Arc<Image>) -> Result<()> {
    let count = image.l1.len / 8;
    let covered = image.l2_entries.saturating_mul(image.cluster());
    for i in 0..count {
        let span = image.l1.sub(i.saturating_mul(8), 8);
        cx.progress(i, count);
        let entry = u64_be(&cx.read(span).await?, 0).unwrap_or(0);
        let l2 = if image.version == 1 {
            entry
        } else {
            entry & OFFSET_MASK
        };
        if l2 == 0 {
            continue;
        }
        let table = image
            .input
            .span
            .sub(l2, image.l2_entries.saturating_mul(image.l2_entry_size));
        cx.push(
            Node::new(format!("L1[{i}]"))
                .span(span)
                .summary(format!(
                    "guest {:#x}, L2 table at {l2:#x}",
                    i.saturating_mul(covered)
                ))
                .target(table),
        )
        .await;
    }
    Ok(())
}

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

/// A guest cluster's backing, from its L2 entry.
enum Mapping {
    Zero,
    Data(Span),
    Compressed(Span),
}

impl Image {
    fn map(&self, entry: u64) -> Mapping {
        let file = self.input.span;
        let cluster = self.cluster();
        if self.version == 1 {
            return match entry {
                0 => Mapping::Zero,
                e if e >> 63 != 0 => Mapping::Compressed(file.sub(0, 0)),
                e => Mapping::Data(file.sub(e, cluster)),
            };
        }
        if entry & (1 << 62) != 0 {
            // Compressed: offset in the low bits, extra 512-byte sectors above.
            let bits = 62u32.saturating_sub(self.cluster_bits.saturating_sub(8));
            let mask = 1u64
                .checked_shl(bits)
                .map_or(u64::MAX, |v| v.saturating_sub(1));
            let offset = entry & mask;
            let sectors = (entry & !(1u64 << 63) & !(1 << 62))
                .checked_shr(bits)
                .unwrap_or(0);
            let len = sectors
                .saturating_add(1)
                .saturating_mul(512)
                .saturating_sub(offset & 511);
            return Mapping::Compressed(file.sub(offset, len));
        }
        let offset = entry & OFFSET_MASK;
        if offset == 0 || entry & 1 != 0 {
            Mapping::Zero
        } else {
            Mapping::Data(file.sub(offset, cluster))
        }
    }
}

async fn virtual_disk(cx: Cx, image: Arc<Image>) -> Result<()> {
    if image.backing {
        cx.diag(Diagnostic::note(
            "unallocated clusters come from the backing file; shown as zeros",
        ));
    }
    let cluster = image.cluster();
    let covered = image.l2_entries.saturating_mul(cluster);
    let mut list = PieceList::new(image.l1);
    let l1_count = image.l1.len / 8;
    'outer: for i in 0..l1_count {
        if list.len() >= image.size {
            break;
        }
        cx.progress(list.len(), image.size);
        let entry = u64_be(&cx.read(image.l1.sub(i.saturating_mul(8), 8)).await?, 0).unwrap_or(0);
        let l2 = if image.version == 1 {
            entry
        } else {
            entry & OFFSET_MASK
        };
        if l2 == 0 {
            let want = covered.min(image.size.saturating_sub(list.len()));
            if let Err(e) = list.hole(&cx, want) {
                cx.diag(e);
                break;
            }
            continue;
        }
        let table = cx
            .read(
                image
                    .input
                    .span
                    .sub(l2, image.l2_entries.saturating_mul(image.l2_entry_size)),
            )
            .await?;
        // An L2 table holds up to 256Ki entries (2 MiB clusters).
        for (j, raw) in table
            .chunks(crate::bytes::to_usize(image.l2_entry_size))
            .enumerate()
        {
            let want = cluster.min(image.size.saturating_sub(list.len()));
            if want == 0 {
                break 'outer;
            }
            if j.is_multiple_of(4096) {
                cx.checkpoint().await;
            }
            let entry = u64_be(raw, 0).unwrap_or(0);
            let step = match image.map(entry) {
                Mapping::Zero => list.hole(&cx, want),
                Mapping::Data(span) => {
                    list.data(span.sub(0, want));
                    Ok(())
                }
                Mapping::Compressed(span) if image.version >= 2 => {
                    let span = if image.codec == Codec::Zstd {
                        // The span runs to the end of a sector and may hold
                        // the start of the next cluster's frame: keep one.
                        let head = cx.read_avail(span).await?;
                        span.sub(0, zstd_frame_len(&head).map_or(span.len, to_u64))
                    } else {
                        span
                    };
                    match crate::codec::decode_span(&cx, span, &image.codec, Some(cluster)).await {
                        Ok(decoded) => {
                            list.data(decoded.span.sub(0, want));
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
                Mapping::Compressed(_) => Err(Diagnostic::unsupported("QCOW1 compressed cluster")),
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
