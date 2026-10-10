//! Minix filesystems (versions 1, 2 and 3).
//!
//! The superblock at 1 KiB gives the sizes of the inode and zone bitmaps,
//! which precede the inode table. Files map their content through 7 direct
//! zones and indirect zones; directories are arrays of (inode, name)
//! entries, listed lazily as a tree.

use std::collections::HashSet;
use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{PieceList, content_node, fragments_node, size, unix_mode, unix_time};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;

const LE: Endian = Endian::Little;
const SUPER: u64 = 1024;
const ROOT: u32 = 1;
const MAX_DEPTH: usize = 64;
const MAX_DIR_BYTES: u64 = 16 << 20;
/// Zones mapped per file at most.
const MAX_ZONES: u64 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "minix",
    title: "Minix filesystem",
    extensions: &["img", "minix"],
    mime: "application/x-minix",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// Version and maximum name length, from the magic number.
fn version(head: &[u8]) -> Option<(u8, u64)> {
    match u16_le(head, 16)? {
        0x137f => Some((1, 14)),
        0x138f => Some((1, 30)),
        0x2468 => Some((2, 14)),
        0x2478 => Some((2, 30)),
        _ if u16_le(head, 24) == Some(0x4d5a) => Some((3, 60)),
        _ => None,
    }
}

fn probe(h: &Head<'_>) -> bool {
    let sb = h.data.get(1024..).unwrap_or_default();
    // Plausible bitmap sizes and a nonzero first data zone.
    let (imap, first_zone) = match version(sb) {
        Some((3, _)) => (6, 10),
        Some(_) => (4, 8),
        None => return false,
    };
    u16_le(sb, imap).is_some_and(|n| (1..=1024).contains(&n))
        && u16_le(sb, first_zone).is_some_and(|n| n > 2)
        && h.data.get(510..512) != Some(&[0x55, 0xaa])
}

record! {
    /// Version 1 and 2 superblock.
    pub struct Superblock12 {
        inodes: u16 "Inodes",
        zones_v1: u16 "Zones (v1)",
        imap_blocks: u16 "Inode bitmap blocks",
        zmap_blocks: u16 "Zone bitmap blocks",
        first_data_zone: u16 "First data zone",
        log_zone_size: u16 "Zone size (log2 blocks)",
        max_size: u32 "Maximum file size" .with(|&v, n| n.summary(size(v.into()))),
        magic: u16 "Magic" .hex(),
        state: u16 "State" .hex(),
        zones: u32 "Zones (v2)",
    }
}

record! {
    /// Version 3 superblock.
    pub struct Superblock3 {
        inodes: u32 "Inodes",
        _pad0: u16 "Padding",
        imap_blocks: u16 "Inode bitmap blocks",
        zmap_blocks: u16 "Zone bitmap blocks",
        first_data_zone: u16 "First data zone",
        log_zone_size: u16 "Zone size (log2 blocks)",
        _pad1: u16 "Padding",
        max_size: u32 "Maximum file size" .with(|&v, n| n.summary(size(v.into()))),
        zones: u32 "Zones",
        magic: u16 "Magic" .hex(),
        _pad2: u16 "Padding",
        block_size: u16 "Block size",
        disk_version: u8 "Disk version",
    }
}

record! {
    /// Version 1 inode (32 bytes).
    pub struct Inode1 {
        mode: u16 "Mode" .hex() .with(|&m, n| n.summary(unix_mode(m.into()))),
        uid: u16 "Owner",
        size: u32 "Size",
        mtime: u32 "Modified" .with(unix_time),
        gid: u8 "Group",
        links: u8 "Links",
        zones: bytes[18] "Zones (7 direct, indirect, double indirect)",
    }
}

record! {
    /// Version 2 and 3 inode (64 bytes).
    pub struct Inode2 {
        mode: u16 "Mode" .hex() .with(|&m, n| n.summary(unix_mode(m.into()))),
        links: u16 "Links",
        uid: u16 "Owner",
        gid: u16 "Group",
        size: u32 "Size",
        atime: u32 "Accessed" .with(unix_time),
        mtime: u32 "Modified" .with(unix_time),
        ctime: u32 "Changed" .with(unix_time),
        zones: bytes[40] "Zones (7 direct, indirect, double, triple)",
    }
}

#[derive(Debug)]
struct Fs {
    input: Input,
    vol: Span,
    version: u8,
    block: u64,
    zone_shift: u32,
    inodes: Span,
    inode_size: u64,
    name_len: u64,
}

type FsRef = Arc<Fs>;

impl Fs {
    fn zone(&self) -> u64 {
        self.block
            .checked_shl(self.zone_shift)
            .unwrap_or(self.block)
    }

    fn inode_span(&self, ino: u32) -> Span {
        let index = u64::from(ino.saturating_sub(1));
        self.inodes
            .sub(index.saturating_mul(self.inode_size), self.inode_size)
    }

    /// Zone pointers of an inode: (direct..., indirect, double, triple).
    fn zone_ptrs(&self, inode: &[u8]) -> Vec<u64> {
        if self.version == 1 {
            inode
                .get(14..32)
                .unwrap_or_default()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|z| u64::from(u16::from_le_bytes(*z)))
                .collect()
        } else {
            inode
                .get(24..64)
                .unwrap_or_default()
                .as_chunks::<4>()
                .0
                .iter()
                .map(|z| u64::from(u32::from_le_bytes(*z)))
                .collect()
        }
    }

    fn size_of(&self, inode: &[u8]) -> u64 {
        let at = if self.version == 1 { 4 } else { 8 };
        u32_le(inode, at).unwrap_or(0).into()
    }

    /// The content of an inode, as pieces of the volume (holes as zeros).
    async fn content(&self, cx: &Cx, inode_span: Span, inode: &[u8]) -> Result<(Span, Vec<Span>)> {
        let size = self.size_of(inode);
        let zone = self.zone();
        let needed = size.div_ceil(zone.max(1));
        if needed > MAX_ZONES {
            return Err(Diagnostic::limit(format!("file of {} zones", needed)).at(inode_span));
        }
        let ptr_size: u64 = if self.version == 1 { 2 } else { 4 };
        let per = zone.checked_div(ptr_size).unwrap_or(0);
        let ptrs = self.zone_ptrs(inode);
        // Logical zone -> physical zone, via direct and indirect pointers.
        let mut zones: Vec<u64> = ptrs.iter().take(7).copied().collect();
        let mut seen = HashSet::new();
        for (level, &top) in ptrs.iter().skip(7).enumerate() {
            let mut frontier = vec![top];
            for _ in 0..level {
                let mut next = Vec::new();
                for z in frontier {
                    next.extend(self.pointers(cx, z, per, &mut seen).await?);
                    if to_u64(next.len()) >= needed {
                        break;
                    }
                }
                frontier = next;
            }
            for z in frontier {
                if to_u64(zones.len()) >= needed {
                    break;
                }
                zones.extend(self.pointers(cx, z, per, &mut seen).await?);
            }
        }
        let mut list = PieceList::new(inode_span);
        for (i, &z) in zones
            .iter()
            .take(usize::try_from(needed).unwrap_or(usize::MAX))
            .enumerate()
        {
            if i.is_multiple_of(4096) {
                cx.checkpoint().await;
            }
            let len = zone.min(size.saturating_sub(list.len()));
            if z == 0 {
                list.hole(cx, len)?;
            } else {
                list.data(self.vol.sub(z.saturating_mul(zone), len));
            }
        }
        let span = list.finish(cx, "minix-zones").await?;
        Ok((span, list.into_pieces()))
    }

    /// The pointers in indirect zone `z` (zeros for an absent zone).
    async fn pointers(
        &self,
        cx: &Cx,
        z: u64,
        per: u64,
        seen: &mut HashSet<u64>,
    ) -> Result<Vec<u64>> {
        if z == 0 {
            return Ok(vec![0; crate::bytes::to_usize(per.min(65536))]);
        }
        if !seen.insert(z) {
            return Err(Diagnostic::malformed(format!(
                "zone {z} is used twice as an indirect zone"
            )));
        }
        let data = cx
            .read(self.vol.sub(z.saturating_mul(self.zone()), self.zone()))
            .await?;
        Ok(if self.version == 1 {
            data.as_chunks::<2>()
                .0
                .iter()
                .map(|p| u64::from(u16::from_le_bytes(*p)))
                .collect()
        } else {
            data.as_chunks::<4>()
                .0
                .iter()
                .map(|p| u64::from(u32::from_le_bytes(*p)))
                .collect()
        })
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let head = cx.read_avail(vol.sub(SUPER, 32)).await?;
    let (version, name_len) =
        version(&head).ok_or_else(|| Diagnostic::malformed("no Minix magic"))?;
    let (imap, zmap, log_zone, block, inodes, zones, first_zone) = if version == 3 {
        let sb = parse(
            &cx,
            vol.sub(SUPER, Superblock3::SIZE),
            LE,
            &(),
            Superblock3::layout,
        )
        .await?;
        cx.emit(Superblock3::node(
            "Superblock",
            vol.sub(SUPER, Superblock3::SIZE),
            LE,
        ));
        (
            sb.imap_blocks,
            sb.zmap_blocks,
            sb.log_zone_size,
            u64::from(sb.block_size),
            u64::from(sb.inodes),
            u64::from(sb.zones),
            u64::from(sb.first_data_zone),
        )
    } else {
        let sb = parse(
            &cx,
            vol.sub(SUPER, Superblock12::SIZE),
            LE,
            &(),
            Superblock12::layout,
        )
        .await?;
        cx.emit(Superblock12::node(
            "Superblock",
            vol.sub(SUPER, Superblock12::SIZE),
            LE,
        ));
        let zones = if version == 1 {
            u64::from(sb.zones_v1)
        } else {
            u64::from(sb.zones)
        };
        (
            sb.imap_blocks,
            sb.zmap_blocks,
            sb.log_zone_size,
            1024,
            u64::from(sb.inodes),
            zones,
            u64::from(sb.first_data_zone),
        )
    };
    if !matches!(block, 1024 | 2048 | 4096 | 8192) || log_zone > 8 {
        return Err(Diagnostic::malformed(format!("block size {block}")));
    }
    let inode_size: u64 = if version == 1 { 32 } else { 64 };
    let table_block = 2u64.saturating_add(imap.into()).saturating_add(zmap.into());
    let fs: FsRef = Arc::new(Fs {
        input,
        vol,
        version,
        block,
        zone_shift: log_zone.into(),
        inodes: vol.sub(
            table_block.saturating_mul(block),
            inodes.saturating_mul(inode_size),
        ),
        inode_size,
        name_len,
    });
    cx.annotate(format!(
        "Minix v{version} filesystem, {}, {inodes} inodes, {name_len}-character names",
        size(zones.saturating_mul(fs.zone()))
    ));
    cx.emit(
        Node::new("Boot block")
            .span(vol.sub(0, 1024))
            .summary("left for a boot loader"),
    );
    let sb_len = if version == 3 {
        Superblock3::SIZE
    } else {
        Superblock12::SIZE
    };
    let sb_block_end = 2048u64.max(block.saturating_mul(2));
    cx.emit(
        Node::new("Unused")
            .span(vol.sub(
                SUPER.saturating_add(sb_len),
                sb_block_end.saturating_sub(SUPER).saturating_sub(sb_len),
            ))
            .summary("rest of the superblock's block"),
    );
    let imap_span = vol.sub(
        2u64.saturating_mul(block),
        u64::from(imap).saturating_mul(block),
    );
    let zmap_span = vol.sub(
        2u64.saturating_add(imap.into()).saturating_mul(block),
        u64::from(zmap).saturating_mul(block),
    );
    let imap_raw = cx.read_avail(imap_span).await?;
    let zmap_raw = cx.read_avail(zmap_span).await?;
    // Set bits 1..=n (bit 0 is reserved).
    let used = |raw: &[u8], n: u64| -> u64 {
        let bytes = crate::bytes::to_usize(n.saturating_add(1) / 8);
        let full: u64 = raw
            .get(..bytes)
            .unwrap_or(raw)
            .iter()
            .map(|b| u64::from(b.count_ones()))
            .sum();
        let rest = n.saturating_add(1) % 8;
        let partial = raw.get(bytes).map_or(0, |b| {
            u64::from(
                (b & 0xffu8
                    .checked_shr(u32::try_from(8u64.saturating_sub(rest)).unwrap_or(8))
                    .unwrap_or(0))
                .count_ones(),
            )
        });
        full.saturating_add(partial)
            .saturating_sub(u64::from(raw.first().is_some_and(|b| b & 1 != 0)))
    };
    let data_zones = zones.saturating_sub(first_zone);
    cx.emit(Node::new("Inode bitmap").span(imap_span).summary(format!(
        "{} of {inodes} inodes in use (bit 0 is reserved)",
        used(&imap_raw, inodes.min(1 << 20))
    )));
    cx.emit(Node::new("Zone bitmap").span(zmap_span).summary(format!(
        "{} of {data_zones} data zones in use (bit 0 is reserved)",
        used(&zmap_raw, data_zones.min(1 << 20))
    )));
    cx.emit(
        Node::new("Inode table")
            .span(fs.inodes)
            .summary(format!("{inodes} inodes of {inode_size} bytes"))
            .lazy(inode_table, (fs.clone(), imap_span, inodes)),
    );
    cx.emit(
        Node::new("Free zones")
            .summary("from the zone bitmap")
            .lazy(free_zones, (fs.clone(), zmap_span, first_zone, data_zones)),
    );
    cx.emit(Node::new("Root directory").summary("inode 1").lazy(
        crate::expander!(self::directory: (FsRef, u32, Arc<Vec<u32>>)),
        (fs.clone(), ROOT, Arc::new(Vec::new())),
    ));
    Ok(())
}

/// Whether bit `i` of a bitmap is set.
fn bit(raw: &[u8], i: u64) -> bool {
    raw.get(crate::bytes::to_usize(i / 8)).is_some_and(|b| {
        b.checked_shr(u32::try_from(i % 8).unwrap_or(0))
            .is_some_and(|v| v & 1 != 0)
    })
}

/// The inode table: in-use inodes as records, unused runs as one node.
async fn inode_table(cx: Cx, (fs, imap, count): (FsRef, Span, u64)) -> Result<()> {
    let raw = cx.read_avail(imap).await?;
    let count = count.min(to_u64(raw.len()).saturating_mul(8));
    let mut free: Option<u64> = None;
    for i in 1..=count.saturating_add(1) {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        let used = i <= count && bit(&raw, i);
        if !used && i <= count {
            free.get_or_insert(i);
            continue;
        }
        if let Some(from) = free.take() {
            let a = fs.inode_span(u32::try_from(from).unwrap_or(u32::MAX));
            let n = i.saturating_sub(from);
            cx.push(
                Node::new(format!("Inodes {from}–{}", i.saturating_sub(1)))
                    .span(Span::new(
                        a.source,
                        a.offset,
                        n.saturating_mul(fs.inode_size),
                    ))
                    .summary(format!("{n} unused")),
            )
            .await;
        }
        if used {
            let ino = u32::try_from(i).unwrap_or(u32::MAX);
            cx.push(inode_node(&fs, format!("Inode {ino}"), fs.inode_span(ino)))
                .await;
        }
    }
    Ok(())
}

/// Runs of free data zones from the zone bitmap.
async fn free_zones(cx: Cx, (fs, zmap, first, count): (FsRef, Span, u64, u64)) -> Result<()> {
    let raw = cx.read_avail(zmap).await?;
    let count = count.min(to_u64(raw.len()).saturating_mul(8));
    let zone = fs.zone();
    let mut from: Option<u64> = None;
    for i in 1..=count.saturating_add(1) {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let used = i > count || bit(&raw, i);
        match (used, from) {
            (false, None) => from = Some(i),
            (true, Some(f)) => {
                from = None;
                let z = first.saturating_add(f).saturating_sub(1);
                let n = i.saturating_sub(f);
                cx.push(
                    Node::new(format!(
                        "Zones {z}–{}",
                        z.saturating_add(n).saturating_sub(1)
                    ))
                    .span(fs.vol.sub(z.saturating_mul(zone), n.saturating_mul(zone)))
                    .summary(format!("free, {}", size(n.saturating_mul(zone)))),
                )
                .await;
            }
            _ => {}
        }
    }
    Ok(())
}

fn inode_node(fs: &Fs, name: impl Into<std::borrow::Cow<'static, str>>, span: Span) -> Node {
    if fs.version == 1 {
        Inode1::node(name, span, LE)
    } else {
        Inode2::node(name, span, LE)
    }
}

async fn directory(cx: Cx, (fs, ino, ancestors): (FsRef, u32, Arc<Vec<u32>>)) -> Result<()> {
    let span = fs.inode_span(ino);
    let raw = cx.read(span).await?;
    cx.emit(inode_node(&fs, format!("Inode {ino}"), span));
    if u16_le(&raw, 0).unwrap_or(0) & 0xf000 != 0x4000 {
        return Err(Diagnostic::malformed(format!("inode {ino} is not a directory")).at(span));
    }
    let (data, _) = fs.content(&cx, span, &raw).await?;
    let data = data.sub(0, MAX_DIR_BYTES);
    let ptr: u64 = if fs.version == 3 { 4 } else { 2 };
    let entry = ptr.saturating_add(fs.name_len);
    let mut ancestors = (*ancestors).clone();
    ancestors.push(ino);
    let ancestors = Arc::new(ancestors);
    let bytes = cx.read_avail(data).await?;
    let total = to_u64(bytes.len());
    for (i, e) in bytes.chunks(crate::bytes::to_usize(entry)).enumerate() {
        cx.progress(to_u64(i).saturating_mul(entry), total);
        let child = if ptr == 4 {
            u32_le(e, 0).unwrap_or(0)
        } else {
            u32::from(u16_le(e, 0).unwrap_or(0))
        };
        let name = crate::text::until_nul(e.get(crate::bytes::to_usize(ptr)..).unwrap_or_default());
        if child == 0 || name == "." || name == ".." {
            cx.checkpoint().await;
            continue;
        }
        let entry_span = data.sub(to_u64(i).saturating_mul(entry), entry);
        let child_span = fs.inode_span(child);
        let mode = u16_le(&cx.read_avail(child_span.sub(0, 2)).await?, 0).unwrap_or(0);
        let node = Node::new(name)
            .span(entry_span)
            .summary(format!("{}, inode {child}", unix_mode(mode.into())));
        let node = if mode & 0xf000 == 0x4000 {
            if ancestors.contains(&child) || ancestors.len() > MAX_DEPTH {
                node.diag(Diagnostic::malformed(
                    "directory contains itself; not followed",
                ))
            } else {
                node.lazy(
                    crate::expander!(self::directory: (FsRef, u32, Arc<Vec<u32>>)),
                    (fs.clone(), child, ancestors.clone()),
                )
            }
        } else {
            node.lazy(file, (fs.clone(), child))
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn file(cx: Cx, (fs, ino): (FsRef, u32)) -> Result<()> {
    let span = fs.inode_span(ino);
    let raw = cx.read(span).await?;
    cx.emit(inode_node(&fs, format!("Inode {ino}"), span));
    let (data, pieces) = fs.content(&cx, span, &raw).await?;
    cx.emit(fragments_node(&cx, "Zones", pieces).await);
    cx.emit(content_node(&fs.input, data));
    Ok(())
}
