//! FAT12, FAT16 and FAT32 filesystems.
//!
//! The boot sector's BIOS Parameter Block locates everything: reserved
//! sectors, the file allocation tables, the fixed root directory (FAT12/16)
//! and the data region. Directories are listed lazily and paged, with VFAT
//! long names reassembled; a file's content follows its cluster chain and is
//! presented as one piecewise source when fragmented.

use std::collections::HashSet;
use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{
    assemble, content_node, dos_date, dos_stamp, fragments_node, size, size_summary,
};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const ENTRY: u64 = 32;
/// FAT directories hold at most 65536 entries.
const MAX_DIR_BYTES: u64 = 65536 * ENTRY;
/// Directory nesting we follow before assuming corruption.
const MAX_DEPTH: usize = 64;

pub static FORMAT: Format = Format {
    name: "fat",
    title: "FAT12/16/32 filesystem",
    extensions: &["img", "ima", "vfd", "flp", "fat"],
    mime: "application/x-fat-image",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// A boot sector with a plausible BIOS Parameter Block.
pub fn looks_like_fat(d: &[u8]) -> bool {
    let jump = matches!(d.first(), Some(0xeb)) && d.get(2) == Some(&0x90)
        || matches!(d.first(), Some(0xe9));
    let bps = u16_le(d, 11).unwrap_or(0);
    let spc = d.get(13).copied().unwrap_or(0);
    let reserved = u16_le(d, 14).unwrap_or(0);
    let fats = d.get(16).copied().unwrap_or(0);
    let media = d.get(21).copied().unwrap_or(0);
    let total = u32::from(u16_le(d, 19).unwrap_or(0)).max(u32_le(d, 32).unwrap_or(0));
    let fat_size = u32::from(u16_le(d, 22).unwrap_or(0)).max(u32_le(d, 36).unwrap_or(0));
    jump && matches!(bps, 512 | 1024 | 2048 | 4096)
        && spc.is_power_of_two()
        && reserved >= 1
        && (1..=4).contains(&fats)
        && (media >= 0xf8 || media == 0xf0)
        && total > 0
        && fat_size > 0
        && d.get(3..11) != Some(b"NTFS    ")
        && d.get(3..11) != Some(b"EXFAT   ")
}

fn probe(h: &Head<'_>) -> bool {
    looks_like_fat(h.data)
}

const MEDIA: crate::value::EnumTable = &[
    (0xf0, "removable (1.44 MB floppy and others)"),
    (0xf8, "fixed disk"),
    (0xf9, "720 KB / 1.2 MB floppy"),
    (0xfa, "320 KB floppy"),
    (0xfb, "640 KB floppy"),
    (0xfc, "180 KB floppy"),
    (0xfd, "360 KB floppy"),
    (0xfe, "160 KB floppy"),
    (0xff, "320 KB floppy"),
];

record! {
    /// The BIOS Parameter Block common to all FAT variants.
    pub struct Bpb {
        jump: bytes[3] "Jump instruction",
        oem: ascii[8] "OEM name",
        bytes_per_sector: u16 "Bytes per sector",
        sectors_per_cluster: u8 "Sectors per cluster",
        reserved: u16 "Reserved sectors",
        fats: u8 "Number of FATs",
        root_entries: u16 "Root directory entries",
        total16: u16 "Total sectors (16-bit)",
        media: u8 "Media descriptor" .enumeration(MEDIA),
        fat_size16: u16 "Sectors per FAT (FAT12/16)",
        sectors_per_track: u16 "Sectors per track",
        heads: u16 "Heads",
        hidden: u32 "Hidden sectors",
        total32: u32 "Total sectors (32-bit)",
    }
}

record! {
    /// Extended BPB of FAT12/16 volumes (offset 36).
    pub struct Ebpb16 {
        drive: u8 "Drive number" .hex(),
        _reserved: u8 "Reserved",
        signature: u8 "Extended boot signature" .hex(),
        serial: u32 "Volume serial number" .hex(),
        label: ascii[11] "Volume label",
        fs_type: ascii[8] "Filesystem type",
    }
}

const EXT_FLAGS: FlagTable = &[flag(0x80, "MIRRORING_DISABLED")];

record! {
    /// Extended BPB of FAT32 volumes (offset 36).
    pub struct Ebpb32 {
        fat_size32: u32 "Sectors per FAT",
        ext_flags: u16 "Extended flags" .hex() .flags(EXT_FLAGS),
        version: u16 "Filesystem version" .hex(),
        root_cluster: u32 "Root directory cluster",
        fsinfo: u16 "FSInfo sector",
        backup_boot: u16 "Backup boot sector",
        _reserved: bytes[12] "Reserved",
        drive: u8 "Drive number" .hex(),
        _reserved1: u8 "Reserved",
        signature: u8 "Extended boot signature" .hex(),
        serial: u32 "Volume serial number" .hex(),
        label: ascii[11] "Volume label",
        fs_type: ascii[8] "Filesystem type",
    }
}

record! {
    /// FAT32 FSInfo sector.
    pub struct FsInfo {
        lead: u32 "Lead signature" .hex(),
        _reserved: bytes[480] "Reserved",
        signature: u32 "Structure signature" .hex(),
        free: u32 "Free cluster count",
        next_free: u32 "Next free cluster hint",
        _reserved2: bytes[12] "Reserved",
        trail: u32 "Trail signature" .hex(),
    }
}

const ATTRS: FlagTable = &[
    flag(0x01, "READ_ONLY"),
    flag(0x02, "HIDDEN"),
    flag(0x04, "SYSTEM"),
    flag(0x08, "VOLUME_ID"),
    flag(0x10, "DIRECTORY"),
    flag(0x20, "ARCHIVE"),
];

const CASE: FlagTable = &[flag(0x08, "LOWERCASE_BASE"), flag(0x10, "LOWERCASE_EXT")];

record! {
    /// A short (8.3) directory entry.
    pub struct DirEntry {
        name: bytes[11] "Short name" .with(|b, n| n.value(Value::Text(short_name(b, 0)))),
        attr: u8 "Attributes" .flags(ATTRS),
        case: u8 "Case flags (NT)" .flags(CASE),
        created_cs: u8 "Creation time, 10 ms units",
        created: u32 "Created" .with(dos_stamp),
        accessed: u16 "Accessed" .with(dos_date),
        cluster_hi: u16 "First cluster (high word)",
        modified: u32 "Modified" .with(dos_stamp),
        cluster_lo: u16 "First cluster (low word)",
        size: u32 "File size" .with(size_summary),
    }
}

record! {
    /// A VFAT long-name entry: 13 UTF-16 code units of the name.
    pub struct LfnEntry {
        order: u8 "Sequence number" .hex(),
        name1: utf16[5] "Name characters 1-5",
        attr: u8 "Attributes" .hex(),
        kind: u8 "Type",
        checksum: u8 "Short name checksum" .hex(),
        name2: utf16[6] "Name characters 6-11",
        cluster: u16 "First cluster (always 0)",
        name3: utf16[2] "Name characters 12-13",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Fat12,
    Fat16,
    Fat32,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Fat12 => "FAT12",
            Kind::Fat16 => "FAT16",
            Kind::Fat32 => "FAT32",
        }
    }

    /// Smallest end-of-chain marker.
    fn eoc(self) -> u32 {
        match self {
            Kind::Fat12 => 0xff8,
            Kind::Fat16 => 0xfff8,
            Kind::Fat32 => 0x0fff_fff8,
        }
    }
}

/// Volume geometry, shared by every lazy node of the filesystem.
#[derive(Debug)]
struct Fat {
    input: Input,
    kind: Kind,
    cluster: u64,
    /// The first FAT.
    fat: Span,
    /// The fixed root directory (FAT12/16; empty for FAT32).
    root: Span,
    data: Span,
    clusters: u32,
}

type Vol = Arc<Fat>;

impl Fat {
    fn cluster_span(&self, c: u32) -> Option<Span> {
        let index = c.checked_sub(2)?;
        if index >= self.clusters {
            return None;
        }
        Some(
            self.data
                .sub(u64::from(index).saturating_mul(self.cluster), self.cluster),
        )
    }

    /// The bytes of cluster `c`'s FAT entry (FAT12 entries share a byte).
    fn entry_span(&self, c: u32) -> Span {
        let c = u64::from(c);
        match self.kind {
            Kind::Fat12 => self.fat.sub(c.saturating_add(c / 2), 2),
            Kind::Fat16 => self.fat.sub(c.saturating_mul(2), 2),
            Kind::Fat32 => self.fat.sub(c.saturating_mul(4), 4),
        }
    }

    /// The FAT entry of cluster `c`: the next cluster in its chain.
    async fn next(&self, cx: &Cx, c: u32) -> Result<u32> {
        let c64 = u64::from(c);
        Ok(match self.kind {
            Kind::Fat12 => {
                let at = c64.saturating_add(c64 / 2);
                let b = cx.read(self.fat.sub(at, 2)).await?;
                let v = u16_le(&b, 0).unwrap_or(0);
                u32::from(if c & 1 == 1 { v >> 4 } else { v & 0xfff })
            }
            Kind::Fat16 => {
                let b = cx.read(self.fat.sub(c64.saturating_mul(2), 2)).await?;
                u16_le(&b, 0).unwrap_or(0).into()
            }
            Kind::Fat32 => {
                let b = cx.read(self.fat.sub(c64.saturating_mul(4), 4)).await?;
                u32_le(&b, 0).unwrap_or(0) & 0x0fff_ffff
            }
        })
    }

    /// Follows a cluster chain for at most `limit` clusters. Returns the
    /// clusters' spans and a diagnostic if the chain is broken.
    async fn chain(
        &self,
        cx: &Cx,
        start: u32,
        limit: u64,
    ) -> Result<(Vec<Span>, Option<Diagnostic>)> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut c = start;
        while to_u64(out.len()) < limit {
            let Some(span) = self.cluster_span(c) else {
                return Ok((
                    out,
                    Some(Diagnostic::malformed(format!(
                        "cluster {c} is out of range"
                    ))),
                ));
            };
            if !seen.insert(c) {
                return Ok((
                    out,
                    Some(Diagnostic::malformed(format!(
                        "cluster chain loops back to {c}"
                    ))),
                ));
            }
            out.push(span);
            let next = self.next(cx, c).await?;
            if next >= self.kind.eoc() {
                break;
            }
            if next == 0 || next == self.kind.eoc().saturating_sub(1) {
                let what = if next == 0 { "a free" } else { "a bad" };
                return Ok((
                    out,
                    Some(Diagnostic::malformed(format!(
                        "chain runs into {what} cluster after {c}"
                    ))),
                ));
            }
            c = next;
        }
        Ok((out, None))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let bpb_span = vol.sub(0, Bpb::SIZE);
    let bpb = parse(&cx, bpb_span, LE, &(), Bpb::layout).await?;
    cx.emit(
        Bpb::node("Boot sector (BPB)", vol.sub(0, 512), LE).summary(format!("OEM {:?}", bpb.oem)),
    );

    let sector = u64::from(bpb.bytes_per_sector);
    if sector == 0 || bpb.sectors_per_cluster == 0 {
        return Err(Diagnostic::malformed("zero sector or cluster size").at(bpb_span));
    }
    let ext32 = parse(
        &cx,
        vol.sub(Bpb::SIZE, Ebpb32::SIZE),
        LE,
        &(),
        Ebpb32::layout,
    )
    .await;
    let fat_sectors = if bpb.fat_size16 != 0 {
        u64::from(bpb.fat_size16)
    } else {
        ext32.as_ref().map_or(0, |e| u64::from(e.fat_size32))
    };
    let total = if bpb.total16 != 0 {
        u64::from(bpb.total16)
    } else {
        u64::from(bpb.total32)
    };
    let root_bytes = u64::from(bpb.root_entries).saturating_mul(ENTRY);
    let root_sectors = root_bytes.div_ceil(sector);
    let reserved = u64::from(bpb.reserved);
    let fats_len = fat_sectors.saturating_mul(bpb.fats.into());
    let data_sector = reserved
        .saturating_add(fats_len)
        .saturating_add(root_sectors);
    let cluster = sector.saturating_mul(bpb.sectors_per_cluster.into());
    let count = total
        .saturating_sub(data_sector)
        .checked_div(bpb.sectors_per_cluster.into())
        .unwrap_or(0);
    // Linux's rule: a zero 16-bit FAT size means FAT32, whatever the count.
    let kind = if bpb.fat_size16 == 0 {
        Kind::Fat32
    } else if count < 4085 {
        Kind::Fat12
    } else {
        Kind::Fat16
    };
    // Entries the FAT itself can describe.
    let capacity = match kind {
        Kind::Fat12 => fat_sectors.saturating_mul(sector).saturating_mul(2) / 3,
        Kind::Fat16 => fat_sectors.saturating_mul(sector) / 2,
        Kind::Fat32 => fat_sectors.saturating_mul(sector) / 4,
    };
    let clusters = u32::try_from(count.min(capacity.saturating_sub(2))).unwrap_or(u32::MAX);

    let label = match kind {
        Kind::Fat32 => {
            let ext = ext32.clone()?;
            cx.emit(Ebpb32::node(
                "Extended BPB (FAT32)",
                vol.sub(Bpb::SIZE, Ebpb32::SIZE),
                LE,
            ));
            ext.label
        }
        _ => {
            let span = vol.sub(Bpb::SIZE, Ebpb16::SIZE);
            let ext = parse(&cx, span, LE, &(), Ebpb16::layout).await?;
            cx.emit(Ebpb16::node("Extended BPB", span, LE));
            ext.label
        }
    };
    let ext_end = Bpb::SIZE.saturating_add(if kind == Kind::Fat32 {
        Ebpb32::SIZE
    } else {
        Ebpb16::SIZE
    });
    if sector >= 512 {
        cx.emit(
            Node::new("Boot code")
                .span(vol.sub(ext_end, 510u64.saturating_sub(ext_end)))
                .summary(size(510u64.saturating_sub(ext_end))),
        );
        let sig = cx.read_avail(vol.sub(510, 2)).await?;
        let sig_value = u16_le(&sig, 0).unwrap_or(0);
        let mut sig_node = Node::new("Boot signature")
            .span(vol.sub(510, 2))
            .value(Value::UInt {
                value: sig_value.into(),
                bits: 16,
                radix: crate::value::Radix::Hex,
            });
        if sig_value != 0xaa55 {
            sig_node = sig_node.diag(Diagnostic::warning("expected 0xaa55"));
        }
        cx.emit(sig_node);
        if sector > 512 {
            cx.emit(
                Node::new("Unused")
                    .span(vol.sub(512, sector.saturating_sub(512)))
                    .summary("rest of the boot sector"),
            );
        }
    }
    if u64::from(bpb.reserved) > 1 {
        cx.emit(
            Node::new("Reserved sectors")
                .span(
                    vol.sub(
                        sector,
                        u64::from(bpb.reserved)
                            .saturating_sub(1)
                            .saturating_mul(sector),
                    ),
                )
                .summary(format!(
                    "{} sectors after the boot sector",
                    bpb.reserved.saturating_sub(1)
                )),
        );
    }
    let label = label.trim_end().to_owned();
    cx.annotate(format!(
        "{} filesystem{}, {}, {} clusters of {}",
        kind.name(),
        if label.is_empty() || label == "NO NAME" {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(total.saturating_mul(sector)),
        clusters,
        size(cluster),
    ));

    let mut root_cluster = 0;
    if let (Kind::Fat32, Ok(ext)) = (kind, &ext32) {
        root_cluster = ext.root_cluster;
        if ext.fsinfo != 0 && ext.fsinfo != 0xffff {
            let span = vol.sub(u64::from(ext.fsinfo).saturating_mul(sector), FsInfo::SIZE);
            let info = parse(&cx, span, LE, &(), FsInfo::layout).await;
            let mut node = FsInfo::node("FSInfo sector", span, LE);
            match info {
                Ok(i) if i.lead == 0x4161_5252 && i.signature == 0x6141_7272 => {
                    node = node.summary(if i.free == u32::MAX {
                        "free cluster count unknown".to_owned()
                    } else {
                        format!("{} free clusters", i.free)
                    });
                }
                Ok(_) => node = node.diag(Diagnostic::warning("bad FSInfo signatures")),
                Err(e) => node = node.diag(e),
            }
            cx.emit(node);
        }
        if ext.backup_boot != 0 && ext.backup_boot != 0xffff {
            let at = u64::from(ext.backup_boot).saturating_mul(sector);
            cx.emit(Bpb::node("Backup boot sector", vol.sub(at, sector), LE));
            if ext.fsinfo != 0 && ext.fsinfo != 0xffff {
                let copy = vol.sub(
                    at.saturating_add(u64::from(ext.fsinfo).saturating_mul(sector)),
                    FsInfo::SIZE,
                );
                cx.emit(FsInfo::node("FSInfo sector (backup)", copy, LE));
            }
        }
    }

    let fat_len = fat_sectors.saturating_mul(sector);
    let fat_start = reserved.saturating_mul(sector);
    let root = if kind == Kind::Fat32 {
        Span::new(vol.source, vol.offset, 0)
    } else {
        vol.sub(
            fat_start.saturating_add(fats_len.saturating_mul(sector)),
            root_bytes,
        )
    };
    let fs: Vol = Arc::new(Fat {
        input,
        kind,
        cluster,
        fat: vol.sub(fat_start, fat_len),
        root,
        data: vol.tail(data_sector.saturating_mul(sector)),
        clusters,
    });

    for i in 0..u64::from(bpb.fats) {
        let span = vol.sub(fat_start.saturating_add(i.saturating_mul(fat_len)), fat_len);
        let node = Node::new(format!("FAT {}", i.saturating_add(1))).span(span);
        cx.emit(if i == 0 {
            node.summary(format!("{} entries", kind.name()))
                .lazy(fat_entries, fs.clone())
        } else {
            node.summary("copy")
        });
    }
    let root_node = Node::new("Root directory").lazy(
        crate::expander!(self::directory: Dir),
        Dir {
            vol: fs.clone(),
            entry: None,
            first: root_cluster,
            ancestors: Arc::new(Vec::new()),
        },
    );
    cx.emit(if kind == Kind::Fat32 {
        root_node.summary(format!("cluster {root_cluster}"))
    } else {
        root_node.span(root)
    });
    cx.emit(
        Node::new("Data region")
            .span(fs.data)
            .summary(size(fs.data.len)),
    );
    cx.emit(
        Node::new("Free clusters")
            .summary("from the FAT")
            .lazy(free_clusters, fs.clone()),
    );
    Ok(())
}

/// Lists runs of free clusters (FAT entry 0) with their data.
async fn free_clusters(cx: Cx, fs: Vol) -> Result<()> {
    let end = fs.clusters.saturating_add(2);
    let mut from: Option<u32> = None;
    for c in 2..=end {
        if c.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let free = c < end && fs.next(&cx, c).await? == 0;
        match (free, from) {
            (true, None) => from = Some(c),
            (false, Some(f)) => {
                from = None;
                let (Some(a), Some(b)) = (fs.cluster_span(f), fs.cluster_span(c.saturating_sub(1)))
                else {
                    continue;
                };
                let span = Span::new(a.source, a.offset, b.end().saturating_sub(a.offset));
                if span.len == 0 {
                    continue;
                }
                cx.push(
                    Node::new(if f == c.saturating_sub(1) {
                        format!("Cluster {f}")
                    } else {
                        format!("Clusters {f}–{}", c.saturating_sub(1))
                    })
                    .span(span)
                    .summary(format!("free, {}", size(span.len))),
                )
                .await;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Entry 1 holds an end-of-chain marker; on FAT16 and FAT32 its top two
/// bits are the clean-shutdown and no-I/O-error flags (set means clean).
fn entry1_summary(kind: Kind, value: u32) -> String {
    let (clean, healthy) = match kind {
        Kind::Fat12 => return "end of chain marker".to_owned(),
        Kind::Fat16 => (value & 0x8000 != 0, value & 0x4000 != 0),
        Kind::Fat32 => (value & 0x0800_0000 != 0, value & 0x0400_0000 != 0),
    };
    format!(
        "end of chain marker; {}, {}",
        if clean {
            "cleanly unmounted"
        } else {
            "dirty (not cleanly unmounted)"
        },
        if healthy {
            "no I/O errors"
        } else {
            "I/O errors were seen"
        }
    )
}

/// Lists FAT entries; runs of free clusters are shown as one node.
async fn fat_entries(cx: Cx, fs: Vol) -> Result<()> {
    let end = fs.clusters.saturating_add(2);
    for c in 0..2u32 {
        let value = fs.next(&cx, c).await?;
        cx.push(
            Node::new(if c == 0 { "Entry 0" } else { "Entry 1" })
                .span(fs.entry_span(c))
                .value(Value::UInt {
                    value: value.into(),
                    bits: 32,
                    radix: crate::value::Radix::Hex,
                })
                .summary(if c == 0 {
                    "the media descriptor, padded with ones".to_owned()
                } else {
                    entry1_summary(fs.kind, value)
                }),
        )
        .await;
    }
    let mut free_from: Option<u32> = None;
    let flush = |from: u32, to: u32| {
        let name = if from == to {
            format!("Cluster {from}")
        } else {
            format!("Clusters {from}–{to}")
        };
        let a = fs.entry_span(from);
        let b = fs.entry_span(to);
        Node::new(name)
            .span(Span::new(
                a.source,
                a.offset,
                b.end().saturating_sub(a.offset),
            ))
            .value(Value::UInt {
                value: 0,
                bits: 32,
                radix: crate::value::Radix::Dec,
            })
            .summary("free")
    };
    for c in 2..end {
        cx.progress(c.into(), end.into());
        let next = fs.next(&cx, c).await?;
        if next == 0 {
            free_from.get_or_insert(c);
            continue;
        }
        if let Some(from) = free_from.take() {
            cx.push(flush(from, c.saturating_sub(1))).await;
        }
        let summary = if next >= fs.kind.eoc() {
            "end of chain".to_owned()
        } else if next == fs.kind.eoc().saturating_sub(1) {
            "bad cluster".to_owned()
        } else {
            format!("→ {next}")
        };
        let mut node = Node::new(format!("Cluster {c}"))
            .span(fs.entry_span(c))
            .value(Value::UInt {
                value: next.into(),
                bits: 32,
                radix: crate::value::Radix::Hex,
            })
            .summary(summary);
        if let Some(span) = fs.cluster_span(c) {
            node = node.target(span);
        }
        cx.push(node).await;
    }
    if let Some(from) = free_from {
        cx.push(flush(from, end.saturating_sub(1))).await;
    }
    let used = fs
        .entry_span(end.saturating_sub(1))
        .end()
        .saturating_sub(fs.fat.offset);
    if fs.fat.len > used {
        cx.emit(
            Node::new("Unused")
                .span(fs.fat.tail(used))
                .summary("entries beyond the last cluster"),
        );
    }
    Ok(())
}

/// A directory: the fixed root (`first == 0` on FAT12/16) or a cluster chain.
#[derive(Clone)]
struct Dir {
    vol: Vol,
    /// The directory entry describing it (none for the root).
    entry: Option<Span>,
    first: u32,
    /// Clusters of the directories above, to detect cycles.
    ancestors: Arc<Vec<u32>>,
}

/// A long name being collected from LFN entries (which precede their short
/// entry, last part first).
#[derive(Default)]
struct LongName {
    parts: Vec<(u8, Vec<u16>)>,
    checksum: u8,
    start: Option<Span>,
}

impl LongName {
    fn clear(&mut self) {
        self.parts.clear();
        self.start = None;
    }

    /// The assembled name, if the parts are complete and match `short`.
    fn take(&mut self, short: &[u8]) -> Option<String> {
        let ok = !self.parts.is_empty()
            && lfn_checksum(short) == self.checksum
            && self
                .parts
                .iter()
                .rev()
                .enumerate()
                .all(|(i, (order, _))| usize::from(order & 0x1f) == i.saturating_add(1));
        let units: Vec<u16> = self
            .parts
            .iter()
            .rev()
            .flat_map(|(_, u)| u.iter().copied())
            .take_while(|&u| u != 0)
            .collect();
        self.parts.clear();
        ok.then(|| String::from_utf16_lossy(&units))
    }
}

fn lfn_checksum(short: &[u8]) -> u8 {
    short
        .iter()
        .fold(0u8, |sum, &c| sum.rotate_right(1).wrapping_add(c))
}

/// The 8.3 name as displayed, honouring the NT lowercase flags.
fn short_name(b: &[u8], case: u8) -> String {
    let part = |r: std::ops::Range<usize>, lower: bool| -> String {
        let s: String = b
            .get(r)
            .unwrap_or_default()
            .iter()
            .map(|&c| char::from(c))
            .collect::<String>()
            .trim_end()
            .to_owned();
        if lower { s.to_lowercase() } else { s }
    };
    let mut base = part(0..8, case & 0x08 != 0);
    if b.first() == Some(&0x05) {
        base.replace_range(..1, "\u{e5}");
    }
    let ext = part(8..11, case & 0x10 != 0);
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

/// The byte regions holding a directory's entries.
async fn dir_pieces(cx: &Cx, dir: &Dir) -> Result<Vec<Span>> {
    let fs = &dir.vol;
    if dir.first == 0 && fs.kind != Kind::Fat32 {
        return Ok(vec![fs.root]);
    }
    let limit = MAX_DIR_BYTES.div_ceil(fs.cluster.max(1));
    let (pieces, problem) = fs.chain(cx, dir.first, limit).await?;
    if let Some(d) = problem {
        cx.diag(d);
    }
    Ok(pieces)
}

async fn directory(cx: Cx, dir: Dir) -> Result<()> {
    let fs = dir.vol.clone();
    if let Some(entry) = dir.entry {
        cx.emit(DirEntry::node("Directory entry", entry, LE));
    }
    let pieces = Arc::new(dir_pieces(&cx, &dir).await?);
    if dir.first != 0 {
        cx.emit(fragments_node(&cx, "Clusters", pieces.clone()).await);
    }
    let mut ancestors = (*dir.ancestors).clone();
    ancestors.push(dir.first);
    let ancestors = Arc::new(ancestors);

    let mut long = LongName::default();
    for &piece in pieces.iter() {
        let data = cx.read_avail(piece).await?;
        for (i, raw) in data.as_chunks::<32>().0.iter().enumerate() {
            let span = piece.sub(to_u64(i).saturating_mul(ENTRY), ENTRY);
            let first = raw.first().copied().unwrap_or(0);
            let attr = raw.get(11).copied().unwrap_or(0);
            if first == 0 {
                let rest = piece.tail(to_u64(i).saturating_mul(ENTRY));
                cx.push(Node::new("Unused entries").span(rest).summary(format!(
                    "{} free slots (end of directory)",
                    rest.len / ENTRY
                )))
                .await;
                return Ok(());
            }
            if attr & 0x3f == 0x0f {
                if first == 0xe5 {
                    long.clear();
                } else {
                    if first & 0x40 != 0 {
                        long.clear();
                        long.checksum = raw.get(13).copied().unwrap_or(0);
                    }
                    long.start.get_or_insert(span);
                    long.parts.push((first, lfn_units(raw)));
                }
                cx.checkpoint().await;
                continue;
            }
            let short = raw.get(..11).unwrap_or_default();
            let start = long.start.take();
            let long_name = long.take(short);
            let case = raw.get(12).copied().unwrap_or(0);
            let name = long_name.clone().unwrap_or_else(|| short_name(short, case));
            let node_span = match start {
                Some(s)
                    if long_name.is_some() && s.source == span.source && s.offset < span.offset =>
                {
                    Span::new(s.source, s.offset, span.end().saturating_sub(s.offset))
                }
                _ => span,
            };
            if first == 0xe5 {
                let shown = short_name(short, case).chars().skip(1).collect::<String>();
                cx.push(
                    DirEntry::node(format!("(deleted) ?{shown}"), span, LE)
                        .summary("deleted entry"),
                )
                .await;
                continue;
            }
            if attr & 0x08 != 0 {
                cx.push(Node::new("Volume label").span(span).value(Value::Text(
                    crate::text::latin1(short).trim_end().to_owned(),
                )))
                .await;
                continue;
            }
            if short == b".          " || short == b"..         " {
                cx.push(DirEntry::node(name, span, LE).summary("directory link"))
                    .await;
                continue;
            }
            let cluster = u32::from(u16_le(raw, 20).unwrap_or(0)) << 16
                | u32::from(u16_le(raw, 26).unwrap_or(0));
            let file_size = u32_le(raw, 28).unwrap_or(0);
            let modified = u32_le(raw, 22).unwrap_or(0);
            let when = crate::text::dos_datetime(
                u16::try_from(modified >> 16).unwrap_or(0),
                u16::try_from(modified & 0xffff).unwrap_or(0),
            );
            let mut node = Node::new(name).span(node_span);
            if attr & 0x10 != 0 {
                node = node.summary(format!("directory, modified {when}"));
                if cluster == 0 || ancestors.contains(&cluster) || ancestors.len() > MAX_DEPTH {
                    node = node.diag(Diagnostic::malformed(format!(
                        "directory refers back to cluster {cluster}; not followed"
                    )));
                } else {
                    node = node.lazy(
                        crate::expander!(self::directory: Dir),
                        Dir {
                            vol: fs.clone(),
                            entry: Some(span),
                            first: cluster,
                            ancestors: ancestors.clone(),
                        },
                    );
                }
            } else {
                node = node
                    .summary(format!("{}, modified {when}", size(file_size.into())))
                    .lazy(
                        file,
                        (fs.clone(), span, start.filter(|_| long_name.is_some())),
                    );
            }
            cx.push(node).await;
        }
    }
    Ok(())
}

fn lfn_units(raw: &[u8]) -> Vec<u16> {
    [1usize..11, 14..26, 28..32]
        .into_iter()
        .flat_map(|r| raw.get(r).unwrap_or_default().as_chunks::<2>().0.iter())
        .map(|&p| u16::from_le_bytes(p))
        .collect()
}

async fn file(cx: Cx, (fs, entry, long): (Vol, Span, Option<Span>)) -> Result<()> {
    let e = parse(&cx, entry, LE, &(), DirEntry::layout).await?;
    if let Some(start) = long {
        let len = entry.offset.saturating_sub(start.offset);
        cx.emit(
            Node::new("Long name entries")
                .span(Span::new(start.source, start.offset, len))
                .summary(format!("{} entries", len / ENTRY))
                .lazy(lfn_entries, Span::new(start.source, start.offset, len)),
        );
    }
    cx.emit(DirEntry::node("Directory entry", entry, LE));
    let first = u32::from(e.cluster_hi) << 16 | u32::from(e.cluster_lo);
    let size = u64::from(e.size);
    if size == 0 {
        return Ok(());
    }
    let needed = size.div_ceil(fs.cluster.max(1));
    let (pieces, problem) = fs.chain(&cx, first, needed).await?;
    let found = to_u64(pieces.len());
    if let Some(d) = problem {
        cx.diag(d);
    } else if found < needed {
        cx.diag(Diagnostic::malformed(format!(
            "cluster chain has {found} clusters, the file size needs {needed}"
        )));
    }
    let pieces = Arc::new(crate::formats::disk::coalesce_stepped(&cx, pieces, size).await);
    cx.emit(fragments_node(&cx, "Clusters", pieces.clone()).await);
    let content = assemble(&cx, entry, "fat-chain", &pieces).await?;
    cx.emit(content_node(&fs.input, content));
    Ok(())
}

async fn lfn_entries(cx: Cx, span: Span) -> Result<()> {
    let mut at = 0;
    while at < span.len {
        let e = span.sub(at, ENTRY);
        cx.push(LfnEntry::node("Long name entry", e, LE)).await;
        at = at.saturating_add(ENTRY);
    }
    Ok(())
}
