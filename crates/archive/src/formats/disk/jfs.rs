//! JFS (IBM Journaled File System) aggregates.
//!
//! The primary superblock is at 32 KiB, followed by the aggregate inode
//! map (two pages), the aggregate inode table (32 inodes of 512 bytes:
//! the aggregate inode map's own inode, the block allocation map, the
//! inline log, bad blocks and the fileset's inode map) and the secondary
//! superblock at 60 KiB. Extents are "pxd" descriptors: a 24-bit length and
//! a 40-bit block address; files map their blocks with an extent B+tree
//! ("xtree") whose root lives in the inode.
//!
//! The metadata files are made of 4 KiB pages (`jfs_dmap.h`, `jfs_imap.h`):
//! the block allocation map is a control page, three levels of summary
//! trees (`dmapctl`) and one `dmap` per 8192 blocks holding the working and
//! persistent allocation bitmaps; an inode allocation map is a control page
//! and one allocation group page (IAG) per 4096 inodes, each locating up to
//! 128 extents of 32 inodes. The inline log (`jfs_logmgr.h`) is a
//! superblock followed by log pages.

use crate::bytes::{u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::{PieceList, size, text, unix_mode, uuid_value};
use crate::formats::util::val::uint;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;
const SUPER: u64 = 0x8000;
const AIMAP: u64 = 0x9000;
const AITBL: u64 = 0xb000;
const SUPER2: u64 = 0xf000;
const INODE: u64 = 512;
/// Metadata page size (`PSIZE`).
const PAGE: u64 = 4096;
/// Blocks described by one dmap (`BPERDMAP`).
const BPERDMAP: u64 = 8192;
/// Entries per summary tree page (`LPERCTL`).
const LPERCTL: u64 = 1024;
/// Inode extents per IAG (`EXTSPERIAG`).
const EXTSPERIAG: u64 = 128;
/// Inodes per inode extent (`INOSPEREXT`).
const INOSPEREXT: u64 = 32;
/// xtree page flags.
const BT_LEAF: u8 = 0x02;
const BT_INTERNAL: u8 = 0x04;
/// Limits on the extent trees followed.
const MAX_XT_DEPTH: usize = 8;
const MAX_EXTENTS: usize = 1 << 16;

pub static FORMAT: Format = Format {
    name: "jfs",
    title: "JFS filesystem",
    extensions: &["img", "jfs"],
    mime: "application/x-jfs",
    probe: Probe::Magic(&[(0x8000, b"JFS1")]),
    dissect: crate::expander!(dissect: Input),
};

const STATES: EnumTable = &[
    (0, "clean"),
    (1, "mounted"),
    (2, "dirty"),
    (4, "log redo"),
    (8, "extend"),
    (0x10, "resize"),
];
const FLAGS: FlagTable = &[
    flag(0x1, "COMMIT"),
    flag(0x2, "GROUPCOMMIT"),
    flag(0x4, "LAZYCOMMIT"),
    flag(0x100, "INLINELOG"),
    flag(0x200, "INLINEMOVE"),
    flag(0x400, "BAD_SAIT"),
    flag(0x800, "SPARSE"),
    flag(0x1000, "DASD_ENABLED"),
    flag(0x2000, "DASD_PRIME"),
    flag(0x4000_0000, "UNICODE"),
    flag(0x8000_0000, "OS2"),
    flag(0x1000_0000, "LINUX"),
];
/// B+tree page flags (`jfs_btree.h`).
const BT_FLAGS: FlagTable = &[
    flag(0x01, "ROOT"),
    flag(0x02, "LEAF"),
    flag(0x04, "INTERNAL"),
    flag(0x80, "RIGHTMOST"),
    flag(0x40, "LEFTMOST"),
];
/// Log states (`jfs_logmgr.h`).
const LOG_STATES: EnumTable = &[
    (0, "mounted"),
    (1, "redone"),
    (2, "wrapped"),
    (3, "read error"),
];

/// A `pxd_t`: (length in blocks, block address).
fn pxd(b: &[u8]) -> (u64, u64) {
    let w0 = u32_le(b, 0).unwrap_or(0);
    let w1 = u32_le(b, 4).unwrap_or(0);
    (
        u64::from(w0 & 0x00ff_ffff),
        u64::from(w0 >> 24) << 32 | u64::from(w1),
    )
}

#[allow(clippy::ptr_arg)] // used as a `Field::with` decorator
fn pxd_summary(b: &Vec<u8>, n: Node) -> Node {
    let (len, addr) = pxd(b);
    if len == 0 && addr == 0 {
        n.summary("none")
    } else {
        n.summary(format!("{len} blocks at block {addr}"))
    }
}

record! {
    /// `struct jfs_superblock`.
    pub struct Superblock {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        size: u64 "Size (physical blocks)",
        block_size: u32 "Block size",
        l2_block_size: u16 "Block size (log2)",
        l2_block_factor: u16 "Physical blocks per block (log2)",
        physical_block: u32 "Physical block size",
        l2_physical_block: u16 "Physical block size (log2)",
        _pad: u16 "Padding",
        ag_size: u32 "Allocation group size (blocks)",
        flags: u32 "Flags" .hex() .flags(FLAGS),
        state: u32 "State" .enumeration(STATES),
        compress: u32 "Compression",
        ait2: bytes[8] "Secondary aggregate inode table" .with(pxd_summary),
        aim2: bytes[8] "Secondary aggregate inode map" .with(pxd_summary),
        log_dev: u32 "Log device",
        log_serial: u32 "Log serial number",
        log_pxd: bytes[8] "Inline log" .with(pxd_summary),
        fsck_pxd: bytes[8] "fsck work space" .with(pxd_summary),
        time: u32 "Updated" .timestamp(),
        time_ns: u32 "Updated (ns)",
        fsck_log_len: u32 "fsck log length",
        fsck_log: u8 "fsck log index",
        pack: bytes[11] "Pack name" .with(|b, n| n.value(text(b))),
        extend_size: u64 "Extend size",
        extend_fsck: bytes[8] "Extend fsck work space" .with(pxd_summary),
        extend_log: bytes[8] "Extend log" .with(pxd_summary),
        uuid: bytes[16] "UUID" .with(uuid_value),
        label: bytes[16] "Label" .with(|b, n| n.value(text(b))),
        log_uuid: bytes[16] "Log UUID" .with(uuid_value),
    }
}

/// The aggregate's reserved inodes (`jfs_filsys.h`).
const AGGREGATE_INODES: EnumTable = &[
    (0, "reserved"),
    (1, "aggregate inode map"),
    (2, "block allocation map"),
    (3, "inline log"),
    (4, "bad blocks"),
    (16, "fileset inode map"),
];

/// A fileset's reserved inodes.
const FILESET_INODES: EnumTable = &[
    (0, "reserved"),
    (1, "fileset extension"),
    (2, "root directory"),
    (3, "ACL"),
];

/// Where the aggregate is and how big its blocks are.
#[derive(Clone, Copy, Debug)]
struct Agg {
    vol: Span,
    block: u64,
}

impl Agg {
    fn blocks(&self, addr: u64, len: u64) -> Span {
        self.vol.sub(
            addr.saturating_mul(self.block),
            len.saturating_mul(self.block),
        )
    }
}

/// An `xad_t`: file block offset, length and address of an extent.
#[derive(Clone, Copy, Debug)]
struct Xad {
    offset: u64,
    len: u64,
    addr: u64,
}

fn xad(e: &[u8]) -> Xad {
    let offset =
        u64::from(e.get(3).copied().unwrap_or(0)) << 32 | u64::from(u32_le(e, 4).unwrap_or(0));
    let (len, addr) = pxd(e.get(8..16).unwrap_or_default());
    Xad { offset, len, addr }
}

/// The flag byte and the entries of an xtree page (a 288-byte root in an
/// inode, or a 4 KiB page): a 32-byte header, then 16-byte slots, the
/// first two of which the header takes.
fn xt_entries(page: &[u8], slots: usize) -> (u8, Vec<Xad>) {
    let flag = page.get(16).copied().unwrap_or(0);
    let next = usize::from(u16_le(page, 18).unwrap_or(0)).min(slots);
    let entries = page
        .as_chunks::<16>()
        .0
        .iter()
        .take(next)
        .skip(2)
        .map(|e| xad(e))
        .collect();
    (flag, entries)
}

/// The extents of a file, following its xtree from the root in `inode`.
async fn file_extents(cx: &Cx, agg: Agg, inode: Span) -> Result<Vec<Xad>> {
    let root = cx.read_avail(inode.sub(224, 288)).await?;
    let mut out = Vec::new();
    // Pages still to visit, last first: (entries, depth).
    let mut stack: Vec<(Vec<Xad>, usize)> = Vec::new();
    let (flag, entries) = xt_entries(&root, 18);
    if flag & BT_LEAF != 0 {
        return Ok(entries);
    }
    if flag & BT_INTERNAL != 0 {
        stack.push((entries.into_iter().rev().collect(), 1));
    }
    while let Some((mut pending, depth)) = stack.pop() {
        let Some(child) = pending.pop() else { continue };
        stack.push((pending, depth));
        if depth > MAX_XT_DEPTH {
            return Err(Diagnostic::limit("extent tree too deep").at(inode));
        }
        let span = agg.vol.sub(child.addr.saturating_mul(agg.block), PAGE);
        let page = cx.read_avail(span).await?;
        let (flag, entries) = xt_entries(&page, 256);
        if flag & BT_LEAF != 0 {
            out.extend(entries);
            if out.len() >= MAX_EXTENTS {
                cx.diag(Diagnostic::limit("too many extents").at(inode));
                break;
            }
        } else if flag & BT_INTERNAL != 0 {
            stack.push((entries.into_iter().rev().collect(), depth.saturating_add(1)));
        }
    }
    Ok(out)
}

/// A file's bytes, assembled from its extents (gaps become zeros).
async fn file_span(cx: &Cx, agg: Agg, inode: Span, file_size: u64) -> Result<Span> {
    let extents = file_extents(cx, agg, inode).await?;
    let mut list = PieceList::new(inode);
    for (i, x) in extents.iter().enumerate() {
        if i % 4096 == 4095 {
            cx.checkpoint().await;
        }
        if list.len() >= file_size {
            break;
        }
        let at = x.offset.saturating_mul(agg.block);
        if at < list.len() {
            continue;
        }
        list.hole(cx, at.saturating_sub(list.len()))?;
        let len = x
            .len
            .saturating_mul(agg.block)
            .min(file_size.saturating_sub(list.len()));
        list.data(agg.vol.sub(x.addr.saturating_mul(agg.block), len));
    }
    list.finish(cx, "jfs-extents").await
}

fn time_field(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.u32(name).timestamp().emit()?;
    f.u32("Nanoseconds").emit()?;
    Ok(())
}

fn dxd(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.bytes(name, 16)
        .with(|b, n| {
            let flag = b.first().copied().unwrap_or(0);
            let size = u32_le(b, 4).unwrap_or(0);
            if flag == 0 {
                n.summary("none")
            } else {
                n.summary(format!("flags {flag:#x}, {size} bytes"))
            }
        })
        .emit()?;
    Ok(())
}

/// A `struct dinode`: the common part, then the directory or file area.
fn dinode_layout(f: &mut Fields<'_>, names: &EnumTable) -> Result<()> {
    f.u32("Inode stamp").hex().emit()?;
    f.u32("Fileset").emit()?;
    f.u32("Inode number").enumeration(names).emit()?;
    f.u32("Generation").emit()?;
    f.bytes("Inode extent", 8).with(pxd_summary).emit()?;
    f.u64("Size").with(|&v, n| n.summary(size(v))).emit()?;
    f.u64("Blocks").emit()?;
    f.u32("Links").emit()?;
    f.u32("Owner UID").emit()?;
    f.u32("Group GID").emit()?;
    let mode = f
        .u32("Mode")
        .hex()
        .with(|&m, n| n.summary(unix_mode((m & 0xffff).into())))
        .desc("Unix mode in the low 16 bits; JFS flags above")
        .emit()?;
    time_field(f, "Accessed")?;
    time_field(f, "Changed")?;
    time_field(f, "Modified")?;
    time_field(f, "Created")?;
    dxd(f, "ACL")?;
    dxd(f, "Extended attributes")?;
    f.u32("Next directory index").emit()?;
    f.u32("ACL type").emit()?;
    match mode & 0xf000 {
        0x4000 => dtree_root(f),
        0x2000 | 0x6000 | 0xa000 | 0x1000 | 0xc000 => {
            f.bytes("Unused", 96).emit()?;
            f.bytes("Unused", 16).emit()?;
            dxd(f, "Inline data descriptor")?;
            f.bytes("Inline data", 256)
                .desc("device number, fast symbolic link target or inline extended attributes")
                .emit()?;
            Ok(())
        }
        _ => xtree_root(f),
    }
}

/// A directory's index table and dtree root (`jfs_dtree.h`).
fn dtree_root(f: &mut Fields<'_>) -> Result<()> {
    let table = f.peek_span(96);
    f.node(
        Node::new("Directory index table")
            .span(table)
            .summary("12 inline slots locating entries by readdir cookie")
            .lazy(index_table, table),
    );
    f.skip(96);
    f.bytes("DASD limits", 16).emit()?;
    f.u8("Flags").hex().flags(BT_FLAGS).emit()?;
    let count = f.u8("Entries").emit()?;
    f.int::<i8>("Free slots").emit()?;
    f.int::<i8>("Free list").emit()?;
    f.u32("Parent inode").emit()?;
    f.bytes("Sorted slot table", 8).emit()?;
    f.bytes("Slots", 256)
        .summary(format!("{count} entries in 8 slots of 32 bytes"))
        .emit()?;
    Ok(())
}

async fn index_table(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    for (i, slot) in data.as_chunks::<8>().0.iter().enumerate() {
        let flag = slot.get(1).copied().unwrap_or(0);
        let index = slot.get(2).copied().unwrap_or(0);
        let addr = u64::from(slot.get(3).copied().unwrap_or(0)) << 32
            | u64::from(u32_le(slot, 4).unwrap_or(0));
        let at = crate::bytes::to_u64(i).saturating_mul(8);
        cx.push(
            Node::new(format!("Slot {i}"))
                .span(span.sub(at, 8))
                .value(uint(addr, 40))
                .summary(if flag == 0 {
                    "free".to_owned()
                } else {
                    format!("flags {flag:#x}, slot {index}")
                }),
        )
        .await;
    }
    Ok(())
}

/// A file's xtree root (`jfs_xtree.h`): header and up to 16 extents.
fn xtree_root(f: &mut Fields<'_>) -> Result<()> {
    f.bytes("Unused", 96).emit()?;
    f.u64("Next page").emit()?;
    f.u64("Previous page").emit()?;
    f.u8("Flags").hex().flags(BT_FLAGS).emit()?;
    f.u8("Reserved").emit()?;
    let next = f.u16("Next slot").emit()?;
    f.u16("Maximum slots").emit()?;
    f.u16("Reserved").emit()?;
    f.bytes("Self", 8).with(pxd_summary).emit()?;
    let used = u64::from(next).clamp(2, 18).saturating_sub(2);
    for i in 0..used {
        let span = f.peek_span(16);
        let raw = f.bytes("Extent", 16).get()?;
        let x = xad(&raw);
        f.node(
            Node::new(format!("Extent {i}"))
                .span(span)
                .value(uint(x.addr, 40))
                .summary(format!(
                    "{} blocks at file block {}, flags {:#x}",
                    x.len,
                    x.offset,
                    raw.first().copied().unwrap_or(0)
                )),
        );
    }
    let rest = 16u64.saturating_sub(used).saturating_mul(16);
    if rest > 0 {
        f.bytes("Unused slots", rest).emit()?;
    }
    Ok(())
}

record! {
    /// `struct dbmap_disk`: the block allocation map's control page.
    pub struct DbMap {
        map_size: u64 "Blocks in aggregate",
        free: u64 "Free blocks",
        l2_per_page: u32 "Blocks per page (log2)",
        ags: u32 "Allocation groups",
        max_level: u32 "Top summary level",
        max_ag: u32 "Highest active allocation group",
        ag_pref: u32 "Preferred allocation group",
        ag_level: u32 "Allocation group level",
        ag_height: u32 "Allocation group height",
        ag_width: u32 "Allocation group width",
        ag_start: u32 "Allocation group start index",
        ag_l2_size: u32 "Blocks per allocation group (log2)",
        ag_free: bytes[1024] "Free blocks per allocation group",
        ag_size: u64 "Blocks per allocation group",
        max_free_buddy: u8 "Largest free buddy (log2)",
        _pad: bytes[3007] "Unused",
    }
}

/// The value at the root of a summary tree: the log2 of the largest free
/// run of blocks it describes, or -1.
fn tree_root(b: &[u8]) -> String {
    match b.first().map(|&v| i8::from_le_bytes([v])) {
        Some(v) if v >= 0 => format!("largest free run 2^{v} blocks"),
        _ => "full".to_owned(),
    }
}

/// `struct dmaptree` / `struct dmapctl` header and tree.
fn summary_tree(f: &mut Fields<'_>, nodes: u64) -> Result<()> {
    f.u32("Leaves").emit()?;
    f.u32("Leaves (log2)").emit()?;
    f.u32("First leaf index").emit()?;
    f.u32("Height").emit()?;
    f.int::<i8>("Smallest buddy (log2)").emit()?;
    f.bytes("Tree", nodes)
        .with(|b, n| n.summary(tree_root(b)))
        .desc("buddy-system summary: each node is the log2 of the largest free run below it")
        .emit()?;
    Ok(())
}

fn dmapctl_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    summary_tree(f, 1365)?;
    f.bytes("Unused", 2714).emit()?;
    Ok(())
}

/// Allocated blocks in a bitmap of big-endian bit order in little-endian
/// words, of which the first `n` bits count.
fn allocated(b: &[u8], n: u64) -> u64 {
    let mut total = 0u64;
    for (i, w) in b.as_chunks::<4>().0.iter().enumerate() {
        let first = crate::bytes::to_u64(i).saturating_mul(32);
        if first >= n {
            break;
        }
        let word = u32_le(w, 0).unwrap_or(0);
        let bits = n.saturating_sub(first).min(32);
        let mask = if bits >= 32 {
            u32::MAX
        } else {
            !(u32::MAX
                .checked_shr(u32::try_from(bits).unwrap_or(32))
                .unwrap_or(0))
        };
        total = total.saturating_add(u64::from((word & mask).count_ones()));
    }
    total
}

fn dmap_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let blocks = f.u32("Blocks").emit()?;
    f.u32("Free blocks").emit()?;
    f.u64("First block").emit()?;
    summary_tree(f, 341)?;
    f.bytes("Padding", 2).emit()?;
    f.bytes("Unused", 1672).emit()?;
    let n = u64::from(blocks).min(BPERDMAP);
    f.bytes("Working map", 1024)
        .with(|b, node| node.summary(format!("{} allocated", allocated(b, n))))
        .emit()?;
    f.bytes("Persistent map", 1024)
        .with(|b, node| node.summary(format!("{} allocated", allocated(b, n))))
        .emit()?;
    Ok(())
}

/// What a page of the block allocation map holds: the control page, then
/// one L2 page, and for each L1 group (2^20 dmaps) an L1 page, and for each
/// L0 group (2^10 dmaps) an L0 page followed by its dmaps.
#[derive(Clone, Copy, Debug)]
enum BmapPage {
    Control,
    Ctl { level: u32, index: u64 },
    Dmap(u64),
}

fn bmap_page(p: u64) -> BmapPage {
    match p {
        0 => BmapPage::Control,
        1 => BmapPage::Ctl { level: 2, index: 0 },
        _ => {
            let g0 = LPERCTL.saturating_add(1);
            let g1 = LPERCTL.saturating_mul(g0).saturating_add(1);
            let q = p.saturating_sub(2);
            let (k, r) = (
                q.checked_div(g1).unwrap_or(0),
                q.checked_rem(g1).unwrap_or(0),
            );
            if r == 0 {
                return BmapPage::Ctl { level: 1, index: k };
            }
            let r = r.saturating_sub(1);
            let (j, s) = (
                r.checked_div(g0).unwrap_or(0),
                r.checked_rem(g0).unwrap_or(0),
            );
            let l0 = k.saturating_mul(LPERCTL).saturating_add(j);
            if s == 0 {
                BmapPage::Ctl {
                    level: 0,
                    index: l0,
                }
            } else {
                BmapPage::Dmap(
                    l0.saturating_mul(LPERCTL)
                        .saturating_add(s.saturating_sub(1)),
                )
            }
        }
    }
}

/// The page of dmap `i` (`BLKTODMAP`).
fn dmap_page(i: u64) -> u64 {
    i.saturating_add(i >> 10)
        .saturating_add(i >> 20)
        .saturating_add(4)
}

async fn bmap(cx: Cx, file: Span) -> Result<()> {
    let control = file.sub(0, PAGE);
    let ctl = parse(&cx, control, LE, &(), DbMap::layout).await?;
    let dmaps = ctl.map_size.div_ceil(BPERDMAP);
    let pages = file.len / PAGE;
    cx.set_count(Count::Exact(pages.saturating_add(1)));
    cx.push(
        DbMap::node("Control page", control, LE)
            .summary(format!("{} blocks, {} free", ctl.map_size, ctl.free)),
    )
    .await;
    let per_ag = control.sub(56, 1024);
    cx.push(
        Node::new("Free blocks per allocation group")
            .span(per_ag)
            .summary(format!("{} groups", ctl.ags))
            .lazy(ag_free, (per_ag, ctl.ags)),
    )
    .await;
    for p in 1..pages {
        let span = file.sub(p.saturating_mul(PAGE), PAGE);
        let node = match bmap_page(p) {
            BmapPage::Control => continue,
            BmapPage::Ctl { level, index } => {
                let per = LPERCTL
                    .checked_pow(level.saturating_add(1))
                    .unwrap_or(u64::MAX);
                let name = format!("Level {level} summary {index}");
                if level > ctl.max_level || index.saturating_mul(per) >= dmaps.max(1) {
                    Node::new(name)
                        .span(span)
                        .summary("unused (beyond the map's top level or size)")
                } else {
                    let head = cx.read_avail(span.sub(0, 17)).await?;
                    let root = head.get(16..17).map(tree_root).unwrap_or_default();
                    struct_node(name, span, LE, (), dmapctl_layout).summary(root)
                }
            }
            BmapPage::Dmap(i) if i < dmaps => {
                let head = cx.read_avail(span.sub(0, 16)).await?;
                let blocks = u32_le(&head, 0).unwrap_or(0);
                let free = u32_le(&head, 4).unwrap_or(0);
                let start = u64_le(&head, 8).unwrap_or(0);
                struct_node(format!("Dmap {i}"), span, LE, (), dmap_layout).summary(format!(
                    "blocks {start}–{}, {free} of {blocks} free",
                    start.saturating_add(blocks.into()).saturating_sub(1)
                ))
            }
            BmapPage::Dmap(i) => Node::new(format!("Dmap {i}"))
                .span(span)
                .summary("unused (beyond the map's size)"),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// Runs of free blocks, from the dmaps' persistent maps.
async fn free_blocks(cx: Cx, (agg, file, map_size): (Agg, Span, u64)) -> Result<()> {
    let dmaps = map_size.div_ceil(BPERDMAP);
    let mut run: Option<(u64, u64)> = None;
    let flush = |(from, n): (u64, u64)| {
        Node::new(format!(
            "Blocks {from}–{}",
            from.saturating_add(n).saturating_sub(1)
        ))
        .span(agg.blocks(from, n))
        .summary(format!("free, {}", size(n.saturating_mul(agg.block))))
    };
    for i in 0..dmaps {
        let page = file.sub(dmap_page(i).saturating_mul(PAGE), PAGE);
        if page.len < PAGE {
            break;
        }
        let head = cx.read(page.sub(0, 16)).await?;
        let blocks = u64::from(u32_le(&head, 0).unwrap_or(0)).min(BPERDMAP);
        let start = u64_le(&head, 8).unwrap_or(0);
        let map = cx.read(page.sub(3072, 1024)).await?;
        for b in 0..blocks {
            if b % 4096 == 4095 {
                cx.checkpoint().await;
            }
            let word =
                u32_le(&map, crate::bytes::to_usize(b / 32).saturating_mul(4)).unwrap_or(u32::MAX);
            let used = word
                .checked_shr(31u32.saturating_sub(u32::try_from(b % 32).unwrap_or(0)))
                .is_none_or(|v| v & 1 != 0);
            let block = start.saturating_add(b);
            match (used, run) {
                (false, Some((from, n))) if from.saturating_add(n) == block => {
                    run = Some((from, n.saturating_add(1)));
                }
                (false, prev) => {
                    if let Some(r) = prev {
                        cx.push(flush(r)).await;
                    }
                    run = Some((block, 1));
                }
                (true, Some(r)) => {
                    cx.push(flush(r)).await;
                    run = None;
                }
                (true, None) => {}
            }
        }
    }
    if let Some(r) = run {
        cx.push(flush(r)).await;
    }
    Ok(())
}

record! {
    /// `struct dinomap_disk`: an inode allocation map's control page.
    pub struct DinoMap {
        free_iag: i32 "Free IAG list",
        next_iag: u32 "Next IAG",
        inodes: u32 "Backed inodes",
        free: u32 "Free inodes",
        blocks_per_extent: u32 "Blocks per inode extent",
        l2_blocks_per_extent: u32 "Blocks per inode extent (log2)",
        disk_block: u32 "Disk block (test driver)",
        max_ag: u32 "Highest allocation group (test driver)",
        _pad: bytes[2016] "Unused",
        ag_control: bytes[2048] "Allocation group control",
    }
}

fn agctl_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.i32("Free inode list").emit()?;
    f.i32("Free extent list").emit()?;
    f.u32("Backed inodes").emit()?;
    f.u32("Free inodes").emit()?;
    Ok(())
}

/// A table of fixed-size entries: each in-use entry as its own node, each
/// run of unused ones as one.
async fn entry_list(
    cx: &Cx,
    span: Span,
    width: usize,
    used: fn(usize, &[u8]) -> bool,
    node: fn(usize, Span, &[u8]) -> Node,
) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let w = crate::bytes::to_u64(width);
    let mut idle: Option<usize> = None;
    let flush = |from: usize, to: usize| {
        let at = crate::bytes::to_u64(from).saturating_mul(w);
        let n = crate::bytes::to_u64(to.saturating_sub(from));
        let name = if n == 1 {
            format!("Entry {from}")
        } else {
            format!("Entries {from}–{}", to.saturating_sub(1))
        };
        Node::new(name)
            .span(span.sub(at, n.saturating_mul(w)))
            .summary("unused")
    };
    let entries = data.chunks_exact(width).enumerate();
    let count = data.len().checked_div(width).unwrap_or(0);
    for (i, e) in entries {
        if used(i, e) {
            if let Some(from) = idle.take() {
                cx.push(flush(from, i)).await;
            }
            let at = crate::bytes::to_u64(i).saturating_mul(w);
            cx.push(node(i, span.sub(at, w), e)).await;
        } else if idle.is_none() {
            idle = Some(i);
        }
    }
    if let Some(from) = idle {
        cx.push(flush(from, count)).await;
    }
    Ok(())
}

async fn ag_controls(cx: Cx, span: Span) -> Result<()> {
    entry_list(
        &cx,
        span,
        16,
        // Inactive groups have no inodes and empty (-1 or 0) lists.
        |_, e| {
            u32_le(e, 8).is_some_and(|n| n != 0)
                || u32_le(e, 0).is_some_and(|l| l != 0 && l != u32::MAX)
        },
        |i, span, e| {
            struct_node(format!("AG {i}"), span, LE, (), agctl_layout).summary(format!(
                "{} inodes, {} free",
                u32_le(e, 8).unwrap_or(0),
                u32_le(e, 12).unwrap_or(0)
            ))
        },
    )
    .await
}

async fn ag_free(cx: Cx, (span, groups): (Span, u32)) -> Result<()> {
    let span = span.sub(0, u64::from(groups.min(128)).saturating_mul(8));
    entry_list(
        &cx,
        span,
        8,
        |_, _| true,
        |i, span, e| {
            Node::new(format!("AG {i}"))
                .span(span)
                .value(uint(u64_le(e, 0).unwrap_or(0), 64))
        },
    )
    .await
}

fn iag_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("AG start block").emit()?;
    f.u32("IAG number").emit()?;
    f.i32("Next with free inodes").emit()?;
    f.i32("Previous with free inodes").emit()?;
    f.i32("Next with free extents").emit()?;
    f.i32("Previous with free extents").emit()?;
    f.i32("Next free IAG").emit()?;
    f.bytes("Free inode summary", 16).emit()?;
    f.bytes("Free extent summary", 16).emit()?;
    f.u32("Free inodes").emit()?;
    f.u32("Free extents").emit()?;
    f.bytes("Unused", 1976).emit()?;
    f.bytes("Working map", 512)
        .with(|b, n| n.summary(format!("{} inodes allocated", allocated(b, 4096))))
        .emit()?;
    f.bytes("Persistent map", 512)
        .with(|b, n| n.summary(format!("{} inodes allocated", allocated(b, 4096))))
        .emit()?;
    Ok(())
}

/// An inode allocation map: whose inodes it allocates.
#[derive(Clone, Copy, Debug)]
struct Imap {
    agg: Agg,
    file: Span,
    /// Whether its inode extents are listed (the fileset's; the
    /// aggregate's is the aggregate inode table, shown on its own).
    fileset: bool,
}

async fn imap(cx: Cx, map: Imap) -> Result<()> {
    let control = map.file.sub(0, PAGE);
    let ctl = parse(&cx, control, LE, &(), DinoMap::layout).await?;
    let pages = map.file.len / PAGE;
    cx.set_count(Count::Exact(pages.saturating_add(1)));
    let mut head = DinoMap::node("Control page", control, LE);
    head = head.summary(format!(
        "{} IAGs, {} inodes, {} free",
        ctl.next_iag, ctl.inodes, ctl.free
    ));
    cx.push(head).await;
    cx.push(
        Node::new("Allocation group control")
            .span(control.sub(2048, 2048))
            .summary("128 entries")
            .lazy(ag_controls, control.sub(2048, 2048)),
    )
    .await;
    for p in 1..pages {
        let n = p.saturating_sub(1);
        let span = map.file.sub(p.saturating_mul(PAGE), PAGE);
        if n >= u64::from(ctl.next_iag) {
            cx.push(
                Node::new(format!("IAG {n}"))
                    .span(span)
                    .summary("unused (beyond the next IAG)"),
            )
            .await;
            continue;
        }
        let head = cx.read_avail(span.sub(64, 8)).await?;
        cx.push(
            Node::new(format!("IAG {n}"))
                .span(span)
                .summary(format!(
                    "inodes {}–{}, {} free",
                    n.saturating_mul(EXTSPERIAG * INOSPEREXT),
                    n.saturating_add(1)
                        .saturating_mul(EXTSPERIAG * INOSPEREXT)
                        .saturating_sub(1),
                    u32_le(&head, 0).unwrap_or(0)
                ))
                .lazy(iag, (map, span, n)),
        )
        .await;
    }
    Ok(())
}

async fn iag(cx: Cx, (map, span, n): (Imap, Span, u64)) -> Result<()> {
    let block = cx.block(span).await?;
    iag_layout(&mut Fields::emitting(&cx, &block, LE), &())?;
    let ext = span.sub(3072, 1024);
    let data = cx.read_avail(ext).await?;
    let pmap = cx.read_avail(span.sub(2560, 512)).await?;
    let mut extents = Vec::new();
    for (k, e) in data.as_chunks::<8>().0.iter().enumerate() {
        let (len, addr) = pxd(e);
        if len > 0 {
            extents.push((crate::bytes::to_u64(k), len, addr));
        }
    }
    cx.emit(
        Node::new("Inode extents")
            .span(ext)
            .summary(format!("{} of 128 in use", extents.len()))
            .lazy(pxd_list, ext),
    );
    if !map.fileset {
        return Ok(());
    }
    for (k, len, addr) in extents {
        let first = n
            .saturating_mul(EXTSPERIAG)
            .saturating_add(k)
            .saturating_mul(INOSPEREXT);
        let bits = u32_le(&pmap, crate::bytes::to_usize(k).saturating_mul(4)).unwrap_or(0);
        cx.push(
            Node::new(format!(
                "Inodes {first}–{}",
                first.saturating_add(INOSPEREXT).saturating_sub(1)
            ))
            .span(map.agg.blocks(addr, len))
            .summary(format!("{} allocated", bits.count_ones()))
            .lazy(inode_extent, (map.agg.blocks(addr, len), first, bits)),
        )
        .await;
    }
    Ok(())
}

async fn pxd_list(cx: Cx, span: Span) -> Result<()> {
    entry_list(
        &cx,
        span,
        8,
        |_, e| pxd(e).0 > 0,
        |k, span, e| {
            let (len, addr) = pxd(e);
            Node::new(format!("Extent {k}"))
                .span(span)
                .value(uint(addr, 40))
                .summary(format!("{len} blocks"))
        },
    )
    .await
}

/// The 32 inodes of a fileset inode extent; `bits` is the persistent map
/// word saying which are allocated.
async fn inode_extent(cx: Cx, (span, first, bits): (Span, u64, u32)) -> Result<()> {
    let count = (span.len / INODE).min(INOSPEREXT);
    for i in 0..count {
        let ispan = span.sub(i.saturating_mul(INODE), INODE);
        let number = first.saturating_add(i);
        let name = crate::value::lookup(FILESET_INODES, number).map_or_else(
            || format!("Inode {number}"),
            |n| format!("Inode {number} ({n})"),
        );
        let used = bits
            .checked_shr(31u32.saturating_sub(u32::try_from(i).unwrap_or(0)))
            .is_some_and(|v| v & 1 != 0);
        let node = if used {
            let head = cx.read_avail(ispan.sub(0, 56)).await?;
            let mode = u32_le(&head, 52).unwrap_or(0);
            struct_node(name, ispan, LE, FILESET_INODES, dinode_layout).summary(format!(
                "{}, {}",
                unix_mode((mode & 0xffff).into()),
                size(u64_le(&head, 24).unwrap_or(0))
            ))
        } else {
            Node::new(name).span(ispan).summary("free")
        };
        cx.push(node).await;
    }
    Ok(())
}

record! {
    /// `struct logsuper`: the log's superblock (log page 1).
    pub struct LogSuper {
        magic: u32 "Magic" .hex(),
        version: u32 "Version",
        serial: u32 "Serial number",
        size: u32 "Size (pages)",
        block_size: u32 "Block size",
        l2_block_size: u32 "Block size (log2)",
        flags: u32 "Flags" .hex() .flags(FLAGS),
        state: u32 "State" .enumeration(LOG_STATES),
        end: u32 "End of log",
        uuid: bytes[16] "UUID" .with(uuid_value),
        label: bytes[16] "Label" .with(|b, n| n.value(text(b))),
        active: bytes[2048] "Active file systems" .with(|b, n| {
            let used = b.as_chunks::<16>().0.iter().filter(|u| u.iter().any(|&x| x != 0)).count();
            n.summary(format!("{used} of 128 slots in use"))
        }),
    }
}

/// Log record types (`jfs_logmgr.h`).
const LOG_TYPES: EnumTable = &[
    (0x8000, "commit"),
    (0x4000, "sync point"),
    (0x2000, "mount"),
    (0x0800, "redo page"),
    (0x0080, "no-redo page"),
    (0x0040, "no-redo inode extent"),
    (0x0008, "update map"),
    (0x0001, "no-redo file"),
];

/// Size of a log record descriptor (`struct lrd`).
const LRD: usize = 36;

fn lrd_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Transaction").emit()?;
    f.u32("Back chain").hex().emit()?;
    f.u16("Type").hex().enumeration(LOG_TYPES).emit()?;
    f.u16("Data length").emit()?;
    f.u32("Aggregate").emit()?;
    f.bytes("Type-specific", 20).emit()?;
    Ok(())
}

/// A log page (`struct logpage`). Each record is its data followed by a
/// descriptor giving the data's length, so records are found backwards
/// from the end-of-records offset; a record whose start lies on an earlier
/// page is shown as a continuation.
fn log_page_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Page").emit()?;
    f.u16("Reserved").emit()?;
    let eor = f.u16("End of records").hex().emit()?;
    let data: &[u8] = &f.block().data;
    let eor = usize::from(eor).clamp(8, 4088);
    let mut records = Vec::new();
    let mut end = eor;
    while let Some(lrd) = end.checked_sub(LRD).filter(|&l| l >= 8) {
        let len =
            usize::from(u16_le(data, lrd.saturating_add(10)).unwrap_or(0)).next_multiple_of(4);
        let start = lrd.saturating_sub(len).max(8);
        records.push((start, lrd));
        end = start;
        if start == 8 || records.len() >= 128 {
            break;
        }
    }
    if end > 8 {
        f.bytes(
            "Continued record",
            crate::bytes::to_u64(end.saturating_sub(8)),
        )
        .desc("the tail of a record begun on an earlier page")
        .emit()?;
    }
    for &(start, lrd) in records.iter().rev() {
        f.seek(crate::bytes::to_u64(start));
        if lrd > start {
            f.bytes(
                "Record data",
                crate::bytes::to_u64(lrd.saturating_sub(start)),
            )
            .emit()?;
        }
        let span = f.peek_span(crate::bytes::to_u64(LRD));
        let kind = u16_le(data, lrd.saturating_add(8)).unwrap_or(0);
        let what = match crate::value::lookup(LOG_TYPES, kind.into()) {
            Some(n) => n.to_owned(),
            None => format!("type {kind:#x}"),
        };
        f.node(struct_node("Record", span, LE, (), lrd_layout).summary(what));
        f.skip(crate::bytes::to_u64(LRD));
    }
    f.seek(crate::bytes::to_u64(eor));
    let rest = 4088u64.saturating_sub(crate::bytes::to_u64(eor));
    if rest > 0 {
        f.bytes("Unused", rest).emit()?;
    }
    f.u32("Trailer page").emit()?;
    f.u16("Trailer reserved").emit()?;
    f.u16("Trailer end of records").hex().emit()?;
    Ok(())
}

async fn inline_log(cx: Cx, log: Span) -> Result<()> {
    let pages = log.len / PAGE;
    cx.set_count(Count::Exact(pages));
    for p in 0..pages {
        let span = log.sub(p.saturating_mul(PAGE), PAGE);
        let node = match p {
            0 => Node::new("Page 0").span(span).summary("reserved"),
            1 => {
                let head = cx.read_avail(span.sub(0, 36)).await?;
                if u32_le(&head, 0) != Some(0x8765_4321) {
                    Node::new("Log superblock")
                        .span(span)
                        .diag(Diagnostic::malformed("bad log magic"))
                } else {
                    cx.push(
                        LogSuper::node("Log superblock", span.sub(0, LogSuper::SIZE), LE).summary(
                            format!(
                                "{}, end at {:#x}",
                                crate::value::lookup(
                                    LOG_STATES,
                                    u32_le(&head, 28).unwrap_or(0).into()
                                )
                                .unwrap_or("unknown state"),
                                u32_le(&head, 32).unwrap_or(0)
                            ),
                        ),
                    )
                    .await;
                    Node::new("Unused")
                        .span(span.tail(LogSuper::SIZE))
                        .summary("rest of the log superblock page")
                }
            }
            _ => {
                let head = cx.read_avail(span.sub(0, 8)).await?;
                let page = u32_le(&head, 0).unwrap_or(0);
                let eor = u16_le(&head, 6).unwrap_or(0);
                if p.is_multiple_of(64) {
                    cx.checkpoint().await;
                }
                struct_node(format!("Page {p}"), span, LE, (), log_page_layout).summary(
                    if page == 0 && eor == 0 {
                        "unused".to_owned()
                    } else {
                        format!("log page {page}, records end at {eor:#x}")
                    },
                )
            }
        };
        cx.push(node).await;
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, Superblock::SIZE);
    let sb = parse(&cx, span, LE, &(), Superblock::layout).await?;
    let block = u64::from(sb.block_size).max(512);
    let agg = Agg { vol, block };
    cx.emit(
        Node::new("Reserved")
            .span(vol.sub(0, SUPER))
            .summary("32 KiB left for boot loaders and partition data"),
    );
    cx.emit(Superblock::node("Superblock", span, LE).summary(format!("version {}", sb.version)));
    cx.emit(
        Node::new("Unused")
            .span(vol.sub(
                SUPER.saturating_add(Superblock::SIZE),
                PAGE.saturating_sub(Superblock::SIZE),
            ))
            .summary("rest of the superblock page"),
    );
    cx.emit(imap_node(
        "Aggregate inode map",
        Imap {
            agg,
            file: vol.sub(AIMAP, 0x2000),
            fileset: false,
        },
    ));
    let ait = vol.sub(AITBL, 0x4000);
    cx.emit(
        Node::new("Aggregate inode table")
            .span(ait)
            .summary("32 inodes")
            .lazy(inode_table, (agg, ait)),
    );
    let s2 = vol.sub(SUPER2, Superblock::SIZE);
    if s2.len == Superblock::SIZE {
        cx.emit(Superblock::node("Secondary superblock", s2, LE));
        cx.emit(
            Node::new("Unused")
                .span(vol.sub(
                    SUPER2.saturating_add(Superblock::SIZE),
                    PAGE.saturating_sub(Superblock::SIZE),
                ))
                .summary("rest of the secondary superblock page"),
        );
    }
    let (len, addr) = pxd(&sb.ait2);
    if len > 0 {
        let span = agg.blocks(addr, len);
        cx.emit(
            Node::new("Secondary aggregate inode table")
                .span(span)
                .summary(format!("{len} blocks at block {addr}"))
                .lazy(inode_table, (agg, span.sub(0, 0x4000))),
        );
    }
    let (len, addr) = pxd(&sb.aim2);
    if len > 0 {
        cx.emit(
            imap_node(
                "Secondary aggregate inode map",
                Imap {
                    agg,
                    file: agg.blocks(addr, len),
                    fileset: false,
                },
            )
            .summary(format!("{len} blocks at block {addr}")),
        );
    }
    // The block allocation map and the fileset's inode map are files
    // described by aggregate inodes 2 and 16.
    for (number, name) in [(2u64, "Block allocation map"), (16, "Fileset inode map")] {
        let inode = ait.sub(number.saturating_mul(INODE), INODE);
        let head = cx.read_avail(inode.sub(0, 32)).await?;
        let file_size = u64_le(&head, 24).unwrap_or(0);
        if file_size == 0 {
            continue;
        }
        let file = match file_span(&cx, agg, inode, file_size).await {
            Ok(f) => f,
            Err(e) => {
                cx.diag(e);
                continue;
            }
        };
        let node = Node::new(name).span(file).summary(size(file_size));
        if number == 2 {
            let map_size = u64_le(&cx.read_avail(file.sub(0, 8)).await?, 0).unwrap_or(0);
            cx.emit(node.lazy(bmap, file));
            cx.emit(
                Node::new("Free blocks")
                    .summary("from the block allocation map")
                    .lazy(free_blocks, (agg, file, map_size)),
            );
        } else {
            cx.emit(imap_node(
                name,
                Imap {
                    agg,
                    file,
                    fileset: true,
                },
            ));
        }
    }
    let (log_len, log_addr) = pxd(&sb.log_pxd);
    if log_len > 0 {
        cx.emit(
            Node::new("Inline log")
                .span(agg.blocks(log_addr, log_len))
                .summary(format!("{log_len} blocks at block {log_addr}"))
                .lazy(inline_log, agg.blocks(log_addr, log_len)),
        );
    }
    let (fsck_len, fsck_addr) = pxd(&sb.fsck_pxd);
    if fsck_len > 0 {
        cx.emit(
            Node::new("fsck work space")
                .span(agg.blocks(fsck_addr, fsck_len))
                .summary(format!("{fsck_len} blocks at block {fsck_addr}")),
        );
    }
    let label = crate::text::until_nul(&sb.label);
    cx.annotate(format!(
        "JFS v{} filesystem{}, {}, {}-byte blocks",
        sb.version,
        if label.is_empty() {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(sb.size.saturating_mul(sb.physical_block.into())),
        sb.block_size
    ));
    Ok(())
}

fn imap_node(name: &'static str, map: Imap) -> Node {
    Node::new(name)
        .span(map.file)
        .summary("control page and allocation group pages")
        .lazy(imap, map)
}

async fn inode_table(cx: Cx, (agg, span): (Agg, Span)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    for i in 0..32u64 {
        let at = crate::bytes::to_usize(i.saturating_mul(INODE));
        let used = data
            .get(at..at.saturating_add(512))
            .is_some_and(|b| b.iter().any(|&x| x != 0));
        let name = crate::value::lookup(AGGREGATE_INODES, i)
            .map_or_else(|| format!("Inode {i}"), |n| format!("Inode {i} ({n})"));
        let ispan = span.sub(i.saturating_mul(INODE), INODE);
        cx.push(if used {
            let size = u64::from(u32_le(&data, at.saturating_add(24)).unwrap_or(0));
            struct_node(name, ispan, LE, AGGREGATE_INODES, dinode_layout)
                .summary(crate::formats::disk::size(size))
        } else {
            Node::new(name).span(ispan).summary("unused")
        })
        .await;
        if !used {
            continue;
        }
        let extents = match file_extents(&cx, agg, ispan).await {
            Ok(e) => e,
            Err(e) => {
                cx.diag(e);
                continue;
            }
        };
        for (k, x) in extents.iter().enumerate() {
            cx.push(
                Node::new(format!("Inode {i} extent {k}"))
                    .span(agg.blocks(x.addr, x.len))
                    .summary(format!(
                        "{} blocks at block {}, file block {}",
                        x.len, x.addr, x.offset
                    )),
            )
            .await;
        }
    }
    Ok(())
}
