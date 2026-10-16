//! Proxmox VE virtual machine archives (`.vma`, written by `vzdump`, usually
//! compressed as `.vma.zst`, `.vma.lzo` or `.vma.gz`).
//!
//! A big-endian header (magic `VMA\0`, version 1, a UUID, the backup time,
//! an MD5 of the header) holds the VM's configuration files and a table of
//! up to 255 devices (disk images, or `vmstate` for saved RAM), both as
//! offsets into a blob buffer of length-prefixed strings. The image data
//! follows in extents: a 512-byte header (magic `VMAE`, the number of 4 KiB
//! blocks that follow, the archive's UUID, an MD5 of the header) with 59
//! block infos, each naming a device, a 64 KiB cluster of it and a 16-bit
//! mask of which of the cluster's 4 KiB blocks are stored (the others are
//! zeros). Then the stored blocks, in block info and bit order.
//!
//! Each device is shown as a disk assembled from its clusters (blocks the
//! archive does not store, and clusters it does not mention, read as
//! zeros) and dissected; the extents are listed with their block infos.
//! Nothing records where a cluster is, so assembling a disk walks every
//! extent header once (charged, and shared by all devices); the data blocks
//! themselves are only read when the disk is.
//!
//! Proxmox VE configuration files (`qemu-server.conf`, `qemu-server.fw`)
//! are listed line by line: `key: value` entries, `#` lines (the VM's
//! description, %-decoded, and vzdump's `#qmdump#map` notes), `[section]`
//! headers with their lines, and other lines (firewall rules) as they are.
//! vzdump itself drops the snapshot sections; `vma create` keeps whatever
//! it is given.
//!
//! The layout is from `vma_spec.txt` in Proxmox's pve-qemu repository (and
//! agrees with `vma create` from pve-qemu-kvm 9.2.0, whose archives were
//! reassembled byte for byte against their source images). Blob sizes in
//! the blob buffer are little-endian, unlike the rest; this is not in the
//! spec but is what `vma` writes.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u16_le, u32_be, u64_be};
use crate::codec::crypto::Md5;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::PieceList;
use crate::formats::util::datakit::digest_paced;
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{self, hex};
use crate::formats::{Format, Head, Input, Probe, content, dissect_or_data};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::Check;

const BE: Endian = Endian::Big;
const CLUSTER: u64 = 65536;
const BLOCK: u64 = 4096;
const EXTENT_HEADER: u64 = 512;
const BLOCK_INFOS: u64 = 59;
/// Fixed part of the header, before the blob buffer.
const FIXED: u64 = 12288;
const MAX_HEADER: u64 = 1 << 25;

pub static FORMAT: Format = Format {
    name: "proxmox-vma",
    title: "Proxmox VE virtual machine archive",
    extensions: &["vma"],
    mime: "application/x-proxmox-vma",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.at(0, b"VMA\0\0\0\0\x01")
}

record! {
    pub struct Header {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        uuid: bytes[16] "UUID" .with(crate::formats::disk::uuid_value),
        ctime: u64 "Backup time" .timestamp(),
        md5: bytes[16] "MD5" .checksum("MD5"),
        blob_offset: u32 "Blob buffer offset" .hex(),
        blob_size: u32 "Blob buffer size",
        header_size: u32 "Header size",
    }
}

record! {
    pub struct ExtentHeader {
        magic: ascii[4] "Magic",
        _reserved: u16 "Reserved",
        blocks: u16 "Block count" .desc("Number of 4 KiB blocks following the header"),
        uuid: bytes[16] "UUID" .with(crate::formats::disk::uuid_value),
        md5: bytes[16] "MD5" .checksum("MD5"),
    }
}

/// The parsed header: what the device and config nodes need.
struct Archive {
    input: Input,
    header_size: u64,
    blob: Span,
}

impl Archive {
    /// The blob at `off` in the blob buffer: (span of its data).
    async fn blob(&self, cx: &Cx, off: u32) -> Result<Span> {
        let at = self.blob.sub(off.into(), 2);
        let b = cx.read(at).await?;
        let len = u16_le(&b, 0).ok_or_else(|| Diagnostic::truncated(at, to_u64(b.len())))?;
        self.blob
            .sub_exact(u64::from(off).saturating_add(2), len.into())
    }

    async fn string(&self, cx: &Cx, off: u32) -> Result<(String, Span)> {
        let span = self.blob(cx, off).await?;
        let b = cx.read(span).await?;
        Ok((crate::text::until_nul(&b), span))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    let h = parse(&cx, hspan, BE, &(), Header::layout).await?;
    let header_size = u64::from(h.header_size);
    // 255 names and 255 configs of at most 64 KiB each fit in 32 MiB.
    if header_size > MAX_HEADER {
        return Err(
            Diagnostic::malformed(format!("header size {header_size} is implausible")).at(hspan),
        );
    }
    let header = file.sub_exact(0, header_size.max(FIXED))?;
    // The MD5 covers the whole header with its own field zeroed.
    let mut raw = cx.read(header).await?;
    if let Some(field) = raw.get_mut(32..48) {
        field.fill(0);
    }
    let check = Check::new("MD5", h.md5.clone()).verify(digest_paced::<Md5>(&cx, &raw).await);
    let mut hnode = Header::checked_node("Header", hspan, BE, check.at(32)).check_diag(&check);
    if h.version != 1 {
        hnode = hnode.diag(Diagnostic::unsupported(format!("version {}", h.version)));
    }
    cx.emit(hnode);
    let archive = Arc::new(Archive {
        input,
        header_size,
        blob: file.sub(h.blob_offset.into(), h.blob_size.into()),
    });
    cx.emit(
        Node::new("Blob buffer")
            .span(archive.blob)
            .summary(size(archive.blob.len)),
    );

    let names = raw.get(2044..3068).unwrap_or_default();
    let datas = raw.get(3068..4092).unwrap_or_default();
    let mut configs = 0u32;
    for i in 0..256usize {
        let off = i.saturating_mul(4);
        let (Some(n), Some(d)) = (u32_be(names, off), u32_be(datas, off)) else {
            break;
        };
        if n == 0 && d == 0 {
            continue;
        }
        configs = configs.saturating_add(1);
        let node = match (archive.string(&cx, n).await, archive.blob(&cx, d).await) {
            (Ok((name, _)), Ok(data)) if pve_config_name(&name) => {
                let what = if name.ends_with(".fw") {
                    "firewall configuration"
                } else {
                    "VM configuration"
                };
                Node::new(name)
                    .span(data)
                    .summary(format!("Proxmox {what}, {}", size(data.len)))
                    .desc("VM configuration file")
                    .lazy(config_lines, (data, false))
            }
            (Ok((name, _)), Ok(data)) => {
                content(name, input, data, crate::formats::Codec::Stored, None)
                    .summary(size(data.len))
                    .desc("VM configuration file")
            }
            (Err(e), _) | (_, Err(e)) => Node::new(format!("Config {i}")).diag(e),
        };
        cx.emit(node);
    }
    cx.emit(
        Node::new("Config table")
            .span(file.sub(2044, 2048))
            .summary(plural(configs, "config file"))
            .desc("Blob buffer offsets of each config file's name (256 slots), then of its data"),
    );

    let mut devices = Vec::new();
    for id in 1..256u64 {
        let at = 4096u64.saturating_add(id.saturating_mul(32));
        let span = file.sub(at, 32);
        let Some(b) = raw.get(usize::try_from(at).unwrap_or(usize::MAX)..) else {
            break;
        };
        let (Some(name), Some(len)) = (u32_be(b, 0), u64_be(b, 8)) else {
            break;
        };
        if name == 0 {
            continue;
        }
        let label = match archive.string(&cx, name).await {
            Ok((s, _)) => s,
            Err(e) => {
                cx.diag(e);
                format!("Device {id}")
            }
        };
        devices.push(label.clone());
        let dev = u8::try_from(id).unwrap_or(0);
        cx.emit(
            Node::new(label.clone())
                .span(span)
                .summary(format!("device {id}, {}", size(len)))
                .desc(if label == "vmstate" {
                    "Saved VM state (RAM)"
                } else {
                    "Disk image, assembled from the extents"
                })
                .lazy(device, (archive.clone(), dev, len)),
        );
    }
    cx.emit(
        Node::new("Device table")
            .span(file.sub(4096, 256 * 32))
            .summary(plural(devices.len(), "device"))
            .desc("256 slots of 32 bytes (slot 0 unused): name offset in the blob buffer, size"),
    );
    let data = file.tail(header_size);
    cx.emit(
        Node::new("Extents")
            .span(data)
            .summary(size(data.len))
            .lazy(extents, archive.clone()),
    );
    cx.annotate(format!(
        "Proxmox VMA archive, {}, {}: {}",
        plural(configs, "config file"),
        plural(devices.len(), "device"),
        devices.join(", ")
    ));
    Ok(())
}

/// Whether a config blob is a Proxmox VE configuration file
/// (`qemu-server.conf`, `qemu-server.fw`): `key: value` lines, `#` lines
/// (the VM's description, %-encoded, and vzdump's `#qmdump#` notes) and
/// `[section]` headers (a snapshot's settings; the firewall's options,
/// rules and IP sets, whose rules are not `key: value`).
fn pve_config_name(name: &str) -> bool {
    name.ends_with(".conf") || name.ends_with(".fw")
}

/// A configuration line's node.
fn config_line(span: Span, line: &[u8]) -> Option<Node> {
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(map) = trimmed.strip_prefix("#qmdump#map:") {
        return Some(
            Node::new("qmdump map")
                .span(span)
                .value(val::text(map))
                .desc(
                    "vzdump's note for restoring a disk: VM drive, archive device, storage, format",
                ),
        );
    }
    if let Some(comment) = trimmed.strip_prefix('#') {
        return Some(
            Node::new("Description")
                .span(span)
                .value(val::text(crate::text::url::percent_decode(comment)))
                .desc("A line of the VM's description (stored %-encoded as a comment)"),
        );
    }
    if let Some((key, value)) = trimmed.split_once(':') {
        let is_key = !key.is_empty()
            && key
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
        if is_key {
            return Some(
                Node::new(key.to_owned())
                    .span(span)
                    .value(val::text(value.trim())),
            );
        }
    }
    Some(Node::new("Line").span(span).value(val::text(trimmed)))
}

/// The lines of a Proxmox VE configuration file, or with `section`, of one
/// `[section]` (its header line first).
async fn config_lines(cx: Cx, (span, section): (Span, bool)) -> Result<()> {
    let b = cx.read(span).await?;
    // (offset, length) of each line, newline excluded.
    let mut lines = Vec::new();
    let mut off = 0u64;
    for line in b.split(|&c| c == b'\n') {
        let len = to_u64(line.len());
        lines.push((off, len));
        off = off.saturating_add(len).saturating_add(1);
    }
    cx.charge(to_u64(lines.len()) / 64).await;
    let is_section = |l: &[u8]| {
        let t = String::from_utf8_lossy(l);
        let t = t.trim();
        t.starts_with('[') && t.ends_with(']')
    };
    let line_at = |&(o, l): &(u64, u64)| {
        let start = usize::try_from(o).unwrap_or(usize::MAX);
        let end = usize::try_from(o.saturating_add(l)).unwrap_or(usize::MAX);
        b.get(start..end).unwrap_or_default()
    };
    let mut i = usize::from(section);
    while let Some(&(o, l)) = lines.get(i) {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let line = line_at(&(o, l));
        if is_section(line) {
            if section {
                break;
            }
            // The section runs to the next one.
            let mut j = i.saturating_add(1);
            while let Some(next) = lines.get(j) {
                if is_section(line_at(next)) {
                    break;
                }
                j = j.saturating_add(1);
            }
            let end = lines.get(j).map_or(span.len, |&(no, _)| no);
            let name = String::from_utf8_lossy(line).trim().to_owned();
            cx.push(
                Node::new(name)
                    .span(span.sub(o, end.saturating_sub(o)))
                    .lazy(
                        crate::expander!(self::config_lines: (Span, bool)),
                        (span.sub(o, end.saturating_sub(o)), true),
                    ),
            )
            .await;
            i = j;
            continue;
        }
        if let Some(node) = config_line(span.sub(o, l), line) {
            cx.push(node).await;
        }
        i = i.saturating_add(1);
    }
    Ok(())
}

/// Where each stored cluster's blocks are: (device, cluster) to (offset of
/// its first stored block in the file, block mask). Clusters stored as all
/// zeros (mask 0, one per zero cluster in `vma create`'s output) are only
/// counted: they read as zeros like clusters the archive does not mention,
/// and a large sparse disk has millions of them.
struct ClusterMap {
    clusters: BTreeMap<(u8, u32), (u64, u16)>,
    /// Per device, the block infos with mask 0.
    zero_clusters: Vec<u64>,
    duplicates: u64,
    error: Option<Diagnostic>,
}

/// Walks every extent header once and records its clusters.
async fn cluster_map(cx: &Cx, archive: &Archive) -> Arc<ClusterMap> {
    let file = archive.input.span;
    if let Some(found) = cx.cached::<ClusterMap>(file, "vma-clusters") {
        return found;
    }
    let mut map = ClusterMap {
        clusters: BTreeMap::new(),
        zero_clusters: vec![0; 256],
        duplicates: 0,
        error: None,
    };
    let mut pos = archive.header_size;
    while pos < file.len {
        cx.progress_in(file, pos);
        let span = file.sub(pos, EXTENT_HEADER);
        let h = match cx.read(span).await {
            Ok(h) => h,
            Err(e) => {
                map.error = Some(e);
                break;
            }
        };
        if h.get(..4) != Some(b"VMAE") || to_u64(h.len()) < EXTENT_HEADER {
            map.error = Some(Diagnostic::malformed("no extent header").at(span));
            break;
        }
        let blocks = u16_be(&h, 6).unwrap_or(0);
        let mut data = pos.saturating_add(EXTENT_HEADER);
        for k in 0..BLOCK_INFOS {
            let info = u64_be(
                &h,
                usize::try_from(40u64.saturating_add(k.saturating_mul(8))).unwrap_or(0),
            )
            .unwrap_or(0);
            if info == 0 {
                continue;
            }
            let mask = u16::try_from(info >> 48).unwrap_or(0);
            let dev = u8::try_from((info >> 32) & 0xff).unwrap_or(0);
            let cluster = u32::try_from(info & 0xffff_ffff).unwrap_or(0);
            let replaced = if mask == 0 {
                if let Some(n) = map.zero_clusters.get_mut(usize::from(dev)) {
                    *n = n.saturating_add(1);
                }
                // A later all-zero copy overrides an earlier stored one.
                map.clusters.remove(&(dev, cluster)).is_some()
            } else {
                map.clusters.insert((dev, cluster), (data, mask)).is_some()
            };
            if replaced {
                map.duplicates = map.duplicates.saturating_add(1);
            }
            data = data.saturating_add(u64::from(mask.count_ones()).saturating_mul(BLOCK));
        }
        let next = pos
            .saturating_add(EXTENT_HEADER)
            .saturating_add(u64::from(blocks).saturating_mul(BLOCK));
        if data != next {
            map.error =
                Some(Diagnostic::malformed("block masks disagree with the block count").at(span));
        }
        pos = next;
        cx.checkpoint().await;
    }
    let map = Arc::new(map);
    cx.cache(file, "vma-clusters", map.clone());
    map
}

async fn device(cx: Cx, (archive, dev, len): (Arc<Archive>, u8, u64)) -> Result<()> {
    let file = archive.input.span;
    let map = cluster_map(&cx, &archive).await;
    if let Some(e) = &map.error {
        cx.diag(e.clone());
    }
    if map.duplicates > 0 {
        cx.diag(Diagnostic::warning(format!(
            "{} clusters stored more than once (the last copy is used)",
            map.duplicates
        )));
    }
    let mut list = PieceList::new(file.sub(
        4096u64.saturating_add(u64::from(dev).saturating_mul(32)),
        32,
    ));
    let mut stored = 0u64;
    let mut missing = 0u64;
    let mut next = 0u64; // next cluster index to place
    for (i, (&(_, cluster), &(data, mask))) in
        map.clusters.range((dev, 0)..=(dev, u32::MAX)).enumerate()
    {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let start = u64::from(cluster).saturating_mul(CLUSTER);
        if start >= len {
            cx.diag(Diagnostic::warning(format!(
                "cluster {cluster} lies past the end of the device"
            )));
            break;
        }
        if u64::from(cluster) > next {
            missing = missing.saturating_add(u64::from(cluster).saturating_sub(next));
            list.hole(&cx, start.saturating_sub(list.len()))?;
        }
        let mut src = data;
        for j in 0..16u32 {
            let off = start.saturating_add(u64::from(j).saturating_mul(BLOCK));
            if off >= len {
                break;
            }
            let want = BLOCK.min(len.saturating_sub(off));
            if mask & (1u16 << j) != 0 {
                list.data(file.sub(src, want));
                src = src.saturating_add(BLOCK);
                stored = stored.saturating_add(1);
            } else {
                list.hole(&cx, want)?;
            }
        }
        next = u64::from(cluster).saturating_add(1);
    }
    let end_cluster = len.div_ceil(CLUSTER);
    if next < end_cluster {
        missing = missing.saturating_add(end_cluster.saturating_sub(next));
    }
    // Clusters stored as zeros are in the archive, if not in the map.
    let zero_clusters = map
        .zero_clusters
        .get(usize::from(dev))
        .copied()
        .unwrap_or(0);
    let missing = missing.saturating_sub(zero_clusters);
    if list.len() < len {
        list.hole(&cx, len.saturating_sub(list.len()))?;
    }
    if missing > 0 {
        cx.diag(Diagnostic::note(format!(
            "{} not in the archive (read as zeros)",
            plural(missing, "cluster")
        )));
    }
    cx.annotate(if stored == 0 {
        format!("{}, all zeros", size(len))
    } else {
        format!("{}, {} stored", size(len), plural(stored, "4 KiB block"))
    });
    let span = list.finish(&cx, "vma-clusters").await?;
    dissect_or_data(cx, archive.input.nested(span)).await
}

async fn extents(cx: Cx, archive: Arc<Archive>) -> Result<()> {
    let file = archive.input.span;
    let (mut pos, mut index) = cx
        .resume::<(u64, u64)>()
        .unwrap_or((archive.header_size, 0));
    while pos < file.len {
        let at = (pos, index);
        cx.mark(move || at);
        cx.progress_in(file, pos);
        let span = file.sub(pos, EXTENT_HEADER);
        let h = cx.read(span).await?;
        if h.get(..4) != Some(b"VMAE") {
            cx.push(
                Node::new(format!("Extent {index}"))
                    .span(file.tail(pos))
                    .diag(Diagnostic::malformed("no extent header")),
            )
            .await;
            break;
        }
        let blocks = u64::from(u16_be(&h, 6).unwrap_or(0));
        let total = EXTENT_HEADER.saturating_add(blocks.saturating_mul(BLOCK));
        let espan = file.sub(pos, total);
        let mut node = Node::new(format!("Extent {index}"))
            .span(espan)
            .summary(plural(blocks, "block"));
        if espan.len < total {
            node = node.diag(Diagnostic::truncated(espan, espan.len));
        }
        cx.push(node.lazy(extent, (archive.input, espan))).await;
        pos = pos.saturating_add(total);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn extent(cx: Cx, (_input, span): (Input, Span)) -> Result<()> {
    let hspan = span.sub(0, EXTENT_HEADER);
    let mut raw = cx.read(hspan).await?;
    let h = parse(&cx, hspan, BE, &(), ExtentHeader::layout).await?;
    if let Some(field) = raw.get_mut(24..40) {
        field.fill(0);
    }
    let check = Check::new("MD5", h.md5.clone()).verify(digest_paced::<Md5>(&cx, &raw).await);
    cx.emit(
        ExtentHeader::checked_node("Header", span.sub(0, ExtentHeader::SIZE), BE, check.at(24))
            .check_diag(&check),
    );
    cx.set_count(Count::AtLeast(1));
    let mut data = span.offset.saturating_add(EXTENT_HEADER);
    for k in 0..BLOCK_INFOS {
        let off = 40u64.saturating_add(k.saturating_mul(8));
        let info = u64_be(&raw, usize::try_from(off).unwrap_or(0)).unwrap_or(0);
        if info == 0 {
            continue;
        }
        let mask = u16::try_from(info >> 48).unwrap_or(0);
        let dev = (info >> 32) & 0xff;
        let cluster = info & 0xffff_ffff;
        let n = u64::from(mask.count_ones()).saturating_mul(BLOCK);
        let target = crate::span::Span::new(span.source, data, n);
        data = data.saturating_add(n);
        let mut b = Node::new(format!("Block info {k}"))
            .span(span.sub(off, 8))
            .value(hex(info, 64))
            .summary(format!(
                "device {dev}, cluster {cluster}, mask {mask:#06x} ({} stored)",
                plural(mask.count_ones(), "block")
            ));
        if n > 0 {
            b = b.target(target);
        }
        cx.push(b).await;
    }
    let stored = span.tail(EXTENT_HEADER);
    if !stored.is_empty() {
        cx.push(Node::new("Data").span(stored).summary(size(stored.len)))
            .await;
    }
    Ok(())
}
