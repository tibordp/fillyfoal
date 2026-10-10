//! XFS filesystems (v4 and v5).
//!
//! The volume is split into allocation groups (AGs), each starting with a
//! copy of the superblock and three headers: the AGF (free space B+trees),
//! the AGI (inode B+trees) and the AGFL (a small list of reserved blocks).
//! Free space is indexed twice, by block and by size; inodes live in chunks
//! of 64 indexed by the inode B+tree (and, for chunks with free inodes, the
//! free inode B+tree). v5 filesystems add CRC-32C to every metadata block
//! and may keep reverse mapping and reference count B+trees.
//!
//! An inode maps its data (and its extended attributes) through a fork that
//! is inline ("local"), a list of extents, or the root of a B+tree of
//! extents. Directories are short-form (inline), a single block, or data
//! blocks plus leaf, node and free index blocks at fixed logical offsets.
//! The internal log is a sequence of log records whose operations are
//! shown with the cycle stamps restored.
//!
//! Inode numbers, block numbers and AG-relative numbers follow XFS's
//! encoding: an absolute filesystem block is `AG << agblklog | AG block`,
//! and an inode number is `AG block << inopblog | index` within the AG,
//! prefixed by the AG number.

mod ag;
mod attr;
mod btree;
mod dir;
mod inode;
mod log;

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be, u32_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Field, Fields, parse, struct_node};
use crate::formats::disk::{crc32c_update, size, size_summary, text, uuid_value};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{FlagTable, Radix, Value, field, flag};

const BE: Endian = Endian::Big;
/// "No inode" in superblock and directory fields.
const NULLFSINO: u64 = u64::MAX;
/// "No block" in AG-relative fields.
const NULLAGBLOCK: u32 = u32::MAX;
/// Directory nesting followed from the root.
const MAX_DIR_DEPTH: usize = 64;

pub static FORMAT: Format = Format {
    name: "xfs",
    title: "XFS filesystem",
    extensions: &["img", "xfs"],
    mime: "application/x-xfs",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.at(0, b"XFSB")
        && u32_be(h.data, 4).is_some_and(|b| (512..=65536).contains(&b) && b.is_power_of_two())
        && u16_be(h.data, 100).is_some_and(|v| matches!(v & 0xf, 1..=5))
}

const VERSION: FlagTable = &[
    field(0x000f, 1, "V1"),
    field(0x000f, 2, "V2"),
    field(0x000f, 3, "V3"),
    field(0x000f, 4, "V4"),
    field(0x000f, 5, "V5"),
    flag(0x0010, "ATTR"),
    flag(0x0020, "NLINK"),
    flag(0x0040, "QUOTA"),
    flag(0x0080, "ALIGN"),
    flag(0x0100, "DALIGN"),
    flag(0x0200, "SHARED"),
    flag(0x0400, "LOGV2"),
    flag(0x0800, "SECTOR"),
    flag(0x1000, "EXTFLG"),
    flag(0x2000, "DIRV2"),
    flag(0x4000, "BORG"),
    flag(0x8000, "MOREBITS"),
];

const FEATURES2: FlagTable = &[
    flag(0x02, "LAZYSBCOUNT"),
    flag(0x08, "ATTR2"),
    flag(0x10, "PARENT"),
    flag(0x80, "PROJID32BIT"),
    flag(0x100, "CRC"),
    flag(0x200, "FTYPE"),
];

const RO_COMPAT: FlagTable = &[
    flag(0x1, "FINOBT"),
    flag(0x2, "RMAPBT"),
    flag(0x4, "REFLINK"),
    flag(0x8, "INOBTCNT"),
];

const INCOMPAT: FlagTable = &[
    flag(0x01, "FTYPE"),
    flag(0x02, "SPINODES"),
    flag(0x04, "META_UUID"),
    flag(0x08, "BIGTIME"),
    flag(0x10, "NEEDSREPAIR"),
    flag(0x20, "NREXT64"),
    flag(0x40, "EXCHRANGE"),
    flag(0x80, "PARENT"),
    flag(0x100, "METADIR"),
    flag(0x200, "ZONED"),
    flag(0x400, "ZONE_GAPS"),
];

const LOG_INCOMPAT: FlagTable = &[flag(0x1, "XATTRS")];

const QFLAGS: FlagTable = &[
    flag(0x001, "UQUOTA_ACCT"),
    flag(0x002, "UQUOTA_ENFD"),
    flag(0x004, "UQUOTA_CHKD"),
    flag(0x008, "PQUOTA_ACCT"),
    flag(0x010, "OQUOTA_ENFD"),
    flag(0x020, "OQUOTA_CHKD"),
    flag(0x040, "GQUOTA_ACCT"),
    flag(0x080, "GQUOTA_ENFD"),
    flag(0x100, "GQUOTA_CHKD"),
    flag(0x200, "PQUOTA_ENFD"),
    flag(0x400, "PQUOTA_CHKD"),
];

const SB_FLAGS: FlagTable = &[flag(0x1, "READONLY")];

/// What the dissector needs from the superblock.
struct Sb {
    block: u32,
    dblocks: u64,
    log_start: u64,
    root_ino: u64,
    rbm_ino: u64,
    rsum_ino: u64,
    ag_blocks: u32,
    ag_count: u32,
    log_blocks: u32,
    version: u16,
    sect_size: u16,
    inode_size: u16,
    label: Vec<u8>,
    block_log: u8,
    inopb_log: u8,
    ag_blk_log: u8,
    icount: u64,
    ifree: u64,
    fdblocks: u64,
    uquot_ino: u64,
    gquot_ino: u64,
    pquot_ino: u64,
    metadir_ino: u64,
    dir_blk_log: u8,
    features2: u32,
    ro_compat: u32,
    incompat: u32,
}

/// Summary for an inode number field that may be "none".
fn ino_null(v: &u64, node: Node) -> Node {
    if *v == NULLFSINO {
        node.summary("none")
    } else {
        node
    }
}

/// Summary for a log sequence number (cycle in the high half, block in
/// the low half).
fn lsn_summary(v: &u64, node: Node) -> Node {
    node.summary(format!("cycle {}, block {}", v >> 32, v & 0xffff_ffff))
}

/// The CRC-32C XFS stores at `at` in `data`: computed with the field
/// itself taken as zero, and stored little-endian.
fn crc(data: &[u8], at: usize) -> Option<u32> {
    let before = data.get(..at)?;
    let after = data.get(at.checked_add(4)?..)?;
    Some(!crc32c_update(
        crc32c_update(crc32c_update(!0, before), &[0; 4]),
        after,
    ))
}

/// A diagnostic for a CRC mismatch at `at`, if any.
fn crc_diag(data: &[u8], at: usize, what: &str) -> Option<Diagnostic> {
    match (crc(data, at), u32_le(data, at)) {
        (Some(c), Some(s)) if c != s => Some(Diagnostic::warning(format!(
            "{what} CRC mismatch: stored {s:#010x}, computed {c:#010x}"
        ))),
        _ => None,
    }
}

/// A little-endian CRC-32C field read by a big-endian cursor, checked
/// against `computed`.
fn crc_field(f: &mut Fields<'_>, computed: Option<u32>) -> Result<u32> {
    f.u32("CRC-32C")
        .map(u32::swap_bytes)
        .with(|&v, n| {
            let n = n.value(Value::UInt {
                value: v.into(),
                bits: 32,
                radix: Radix::Hex,
            });
            match computed {
                Some(c) if c == v => n.summary("valid"),
                Some(c) => n.diag(Diagnostic::warning(format!("mismatch: computed {c:#010x}"))),
                None => n,
            }
        })
        .emit()
}

/// Context for a header layout: the filesystem version and the CRC
/// computed over the structure (v5).
#[derive(Clone, Copy, Debug)]
struct HdrCtx {
    v5: bool,
    crc: Option<u32>,
}

use crate::formats::disk::uint_node as uint;

/// Emits whatever is left of the cursor's block as an unused region.
fn rest_unused(f: &mut Fields<'_>, name: &'static str) {
    let rest = f.remaining();
    if rest > 0 {
        f.node(Node::new(name).span(f.peek_span(rest)).summary(size(rest)));
    }
}

fn sb_layout(f: &mut Fields<'_>, computed: &Option<u32>) -> Result<Sb> {
    f.ascii("Magic", 4).emit()?;
    let block = f.u32("Block size").with(size_summary).emit()?;
    let dblocks = f
        .u64("Data blocks")
        .with(|&v, n| n.summary(size(v.saturating_mul(block.into()))))
        .emit()?;
    f.u64("Realtime blocks").emit()?;
    f.u64("Realtime extents").emit()?;
    f.bytes("UUID", 16).with(uuid_value).emit()?;
    let log_start = f
        .u64("Log start block")
        .desc("Filesystem block where the internal log starts; 0 when the log is on another device")
        .emit()?;
    let root_ino = f.u64("Root directory inode").emit()?;
    let rbm_ino = f.u64("Realtime bitmap inode").with(ino_null).emit()?;
    let rsum_ino = f.u64("Realtime summary inode").with(ino_null).emit()?;
    f.u32("Realtime extent size (blocks)").emit()?;
    let ag_blocks = f.u32("Blocks per allocation group").emit()?;
    let ag_count = f.u32("Allocation groups").emit()?;
    f.u32("Realtime bitmap blocks").emit()?;
    let log_blocks = f
        .u32("Log blocks")
        .with(|&v, n| n.summary(size(u64::from(v).saturating_mul(block.into()))))
        .emit()?;
    let version = f.u16("Version and features").hex().flags(VERSION).emit()?;
    let sect_size = f.u16("Sector size").emit()?;
    let inode_size = f.u16("Inode size").emit()?;
    f.u16("Inodes per block").emit()?;
    let label = f.bytes("Label", 12).with(|b, n| n.value(text(b))).emit()?;
    let block_log = f.u8("log2(block size)").emit()?;
    f.u8("log2(sector size)").emit()?;
    f.u8("log2(inode size)").emit()?;
    let inopb_log = f.u8("log2(inodes per block)").emit()?;
    let ag_blk_log = f.u8("log2(blocks per AG), rounded up").emit()?;
    f.u8("log2(realtime extents)").emit()?;
    f.u8("mkfs in progress").emit()?;
    f.u8("Maximum inode space (%)").emit()?;
    let icount = f.u64("Allocated inodes").emit()?;
    let ifree = f.u64("Free inodes").emit()?;
    let fdblocks = f
        .u64("Free data blocks")
        .with(|&v, n| n.summary(size(v.saturating_mul(block.into()))))
        .emit()?;
    f.u64("Free realtime extents").emit()?;
    let uquot_ino = f.u64("User quota inode").with(ino_null).emit()?;
    let gquot_ino = f.u64("Group quota inode").with(ino_null).emit()?;
    f.u16("Quota flags").hex().flags(QFLAGS).emit()?;
    f.u8("Flags").hex().flags(SB_FLAGS).emit()?;
    f.u8("Shared version").emit()?;
    f.u32("Inode chunk alignment (blocks)").emit()?;
    f.u32("Stripe unit (blocks)").emit()?;
    f.u32("Stripe width (blocks)").emit()?;
    let dir_blk_log = f.u8("log2(directory block / block)").emit()?;
    f.u8("log2(log sector size)").emit()?;
    f.u16("Log sector size").emit()?;
    f.u32("Log stripe unit (bytes)").emit()?;
    let features2 = f.u32("Features 2").hex().flags(FEATURES2).emit()?;
    f.u32("Features 2 (copy)")
        .hex()
        .flags(FEATURES2)
        .desc("A second copy of Features 2, where a 64-bit padding bug once wrote it")
        .emit()?;
    let (mut ro_compat, mut incompat) = (0, 0);
    let (mut pquot_ino, mut metadir_ino) = (NULLFSINO, NULLFSINO);
    if version & 0xf == 5 {
        f.u32("Compatible features").hex().emit()?;
        ro_compat = f
            .u32("Read-only compatible features")
            .hex()
            .flags(RO_COMPAT)
            .emit()?;
        incompat = f
            .u32("Incompatible features")
            .hex()
            .flags(INCOMPAT)
            .emit()?;
        f.u32("Log incompatible features")
            .hex()
            .flags(LOG_INCOMPAT)
            .emit()?;
        crc_field(f, *computed)?;
        f.u32("Sparse inode chunk alignment (blocks)").emit()?;
        pquot_ino = f.u64("Project quota inode").with(ino_null).emit()?;
        f.u64("Last write LSN").hex().with(lsn_summary).emit()?;
        f.bytes("Metadata UUID", 16)
            .with(uuid_value)
            .desc("The UUID stamped in metadata blocks when it differs from the UUID (META_UUID)")
            .emit()?;
        if incompat & 0x100 != 0 {
            metadir_ino = f.u64("Metadata directory inode").emit()?;
            f.u32("Realtime groups").emit()?;
            f.u32("Realtime extents per group").emit()?;
            f.u8("log2(realtime group blocks)").emit()?;
            f.bytes("Padding", 7).emit()?;
        }
    }
    rest_unused(f, "Unused");
    Ok(Sb {
        block,
        dblocks,
        log_start,
        root_ino,
        rbm_ino,
        rsum_ino,
        ag_blocks,
        ag_count,
        log_blocks,
        version,
        sect_size,
        inode_size,
        label,
        block_log,
        inopb_log,
        ag_blk_log,
        icount,
        ifree,
        fdblocks,
        uquot_ino,
        gquot_ino,
        pquot_ino,
        metadir_ino,
        dir_blk_log,
        features2,
        ro_compat,
        incompat,
    })
}

/// Filesystem geometry and features, shared by every expansion.
#[derive(Debug)]
struct Fs {
    input: Input,
    vol: Span,
    block: u64,
    sect: u64,
    ag_blocks: u64,
    ag_count: u64,
    ag_blk_log: u32,
    inopb_log: u32,
    inode_size: u64,
    /// Directory block size in filesystem blocks.
    dir_fsbs: u64,
    v5: bool,
    ftype: bool,
    sparse_inodes: bool,
    finobt: bool,
    rmap: bool,
    reflink: bool,
}

type FsRef = Arc<Fs>;

/// Whether bit `i` of `v` is set.
fn bit(v: u64, i: u64) -> bool {
    v.checked_shr(u32::try_from(i).unwrap_or(u32::MAX))
        .is_some_and(|x| x & 1 != 0)
}

fn mask(bits: u32) -> u64 {
    1u64.checked_shl(bits)
        .map_or(u64::MAX, |v| v.saturating_sub(1))
}

impl Fs {
    /// Directory block size in bytes.
    fn dir_block(&self) -> u64 {
        self.dir_fsbs.saturating_mul(self.block)
    }

    /// Byte offset of block `agbno` of AG `ag`.
    fn agb_offset(&self, ag: u64, agbno: u64) -> u64 {
        ag.saturating_mul(self.ag_blocks)
            .saturating_add(agbno)
            .saturating_mul(self.block)
    }

    /// `count` blocks from block `agbno` of AG `ag`.
    fn agb_span(&self, ag: u64, agbno: u64, count: u64) -> Span {
        self.vol
            .sub(self.agb_offset(ag, agbno), count.saturating_mul(self.block))
    }

    /// An absolute filesystem block as (AG, AG block).
    fn fsb_split(&self, fsb: u64) -> (u64, u64) {
        (
            fsb.checked_shr(self.ag_blk_log).unwrap_or(0),
            fsb & mask(self.ag_blk_log),
        )
    }

    /// Whether an absolute filesystem block lies inside an AG.
    fn fsb_valid(&self, fsb: u64) -> bool {
        let (ag, agbno) = self.fsb_split(fsb);
        ag < self.ag_count && agbno < self.ag_blocks
    }

    /// `count` blocks from absolute filesystem block `fsb`.
    fn fsb_span(&self, fsb: u64, count: u64) -> Span {
        let (ag, agbno) = self.fsb_split(fsb);
        self.agb_span(ag, agbno, count)
    }

    /// "AG a block b" for an absolute filesystem block.
    fn fsb_text(&self, fsb: u64) -> String {
        let (ag, agbno) = self.fsb_split(fsb);
        format!("AG {ag} block {agbno}")
    }

    /// Bits of an inode number below the AG number.
    fn agino_bits(&self) -> u32 {
        self.ag_blk_log.saturating_add(self.inopb_log)
    }

    /// An inode number as (AG, AG inode).
    fn ino_split(&self, ino: u64) -> (u64, u64) {
        let bits = self.agino_bits();
        (ino.checked_shr(bits).unwrap_or(0), ino & mask(bits))
    }

    /// The inode number of AG inode `agino` in AG `ag`.
    fn ino(&self, ag: u64, agino: u64) -> u64 {
        ag.checked_shl(self.agino_bits()).unwrap_or(0) | (agino & mask(self.agino_bits()))
    }

    /// The bytes of inode `ino`, or why it cannot exist.
    fn ino_span(&self, ino: u64) -> Result<Span> {
        let (ag, agino) = self.ino_split(ino);
        let agbno = agino.checked_shr(self.inopb_log).unwrap_or(0);
        if ag >= self.ag_count || agbno >= self.ag_blocks {
            return Err(Diagnostic::malformed(format!(
                "inode {ino} lies outside the filesystem"
            )));
        }
        let index = agino & mask(self.inopb_log);
        Ok(self.vol.sub(
            self.agb_offset(ag, agbno)
                .saturating_add(index.saturating_mul(self.inode_size)),
            self.inode_size,
        ))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let head = cx.read_avail(vol.sub(0, 512)).await?;
    let sect = u16_be(&head, 102).map_or(512, u64::from).clamp(512, 32768);
    let sb_span = vol.sub(0, sect);
    let raw = cx.read_avail(sb_span).await?;
    let v5 = u16_be(&raw, 100).is_some_and(|v| v & 0xf == 5);
    let computed = if v5 { crc(&raw, 224) } else { None };
    let sb = parse(&cx, sb_span, BE, &computed, sb_layout).await?;
    let label = crate::text::until_nul(&sb.label);
    let block = u64::from(sb.block);
    let mut features = Vec::new();
    for (on, name) in [
        (sb.ro_compat & 0x4 != 0, "reflink"),
        (sb.ro_compat & 0x2 != 0, "rmap"),
        (sb.ro_compat & 0x1 != 0, "finobt"),
        (sb.incompat & 0x8 != 0, "bigtime"),
        (sb.incompat & 0x20 != 0, "nrext64"),
        (sb.incompat & 0x80 != 0, "parent pointers"),
        (sb.incompat & 0x100 != 0, "metadir"),
    ] {
        if on {
            features.push(name);
        }
    }
    let summary = format!(
        "XFS v{}{}, {}, {} × {} allocation groups, {} blocks{}",
        sb.version & 0xf,
        if label.is_empty() {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(sb.dblocks.saturating_mul(block)),
        sb.ag_count,
        size(u64::from(sb.ag_blocks).saturating_mul(block)),
        size(block),
        if features.is_empty() {
            String::new()
        } else {
            format!(" ({})", features.join(", "))
        }
    );
    cx.annotate(summary);
    let mut node = struct_node("Superblock", sb_span, BE, computed, sb_layout).summary(format!(
        "{} inodes ({} free), {} free",
        sb.icount,
        sb.ifree,
        size(sb.fdblocks.saturating_mul(block))
    ));
    if let Some(d) = v5.then(|| crc_diag(&raw, 224, "superblock")).flatten() {
        node = node.diag(d);
    }
    cx.emit(node);
    let inode_size = u64::from(sb.inode_size);
    let block_ok = (512..=65536).contains(&block)
        && block.is_power_of_two()
        && u32::from(sb.block_log) == block.trailing_zeros();
    let inodes_ok = (256..=2048).contains(&inode_size)
        && inode_size.is_power_of_two()
        && inode_size <= block
        && u64::from(sb.inopb_log)
            == block
                .trailing_zeros()
                .saturating_sub(inode_size.trailing_zeros())
                .into();
    let ag_ok = sb.ag_blocks > 0
        && sb.ag_count > 0
        && u64::from(sb.ag_blocks) <= mask(sb.ag_blk_log.into()).saturating_add(1)
        && sb.ag_blk_log < 32;
    if !(block_ok && inodes_ok && ag_ok) {
        return Err(Diagnostic::malformed("implausible block, inode or AG geometry").at(sb_span));
    }
    let fs: FsRef = Arc::new(Fs {
        input,
        vol,
        block,
        sect: u64::from(sb.sect_size).clamp(512, block),
        ag_blocks: sb.ag_blocks.into(),
        ag_count: sb.ag_count.into(),
        ag_blk_log: sb.ag_blk_log.into(),
        inopb_log: sb.inopb_log.into(),
        inode_size,
        dir_fsbs: 1u64.checked_shl(sb.dir_blk_log.min(16).into()).unwrap_or(1),
        v5,
        ftype: if v5 {
            sb.incompat & 0x1 != 0
        } else {
            sb.features2 & 0x200 != 0
        },
        sparse_inodes: v5 && sb.incompat & 0x2 != 0,
        finobt: v5 && sb.ro_compat & 0x1 != 0,
        rmap: v5 && sb.ro_compat & 0x2 != 0,
        reflink: v5 && sb.ro_compat & 0x4 != 0,
    });
    cx.emit(
        Node::new("Allocation groups")
            .summary(format!(
                "{} × {}",
                sb.ag_count,
                size(fs.ag_blocks.saturating_mul(block))
            ))
            .lazy(ag::groups, fs.clone()),
    );
    cx.emit(
        Node::new("Root directory")
            .summary(format!("inode {}", sb.root_ino))
            .lazy(
                crate::expander!(dir::directory: dir::DirState),
                dir::DirState {
                    fs: fs.clone(),
                    ino: sb.root_ino,
                    path: Path::new(),
                },
            ),
    );
    let special: Vec<(&'static str, u64)> = [
        ("Realtime bitmap", sb.rbm_ino),
        ("Realtime summary", sb.rsum_ino),
        ("User quotas", sb.uquot_ino),
        ("Group quotas", sb.gquot_ino),
        ("Project quotas", sb.pquot_ino),
        ("Metadata directory", sb.metadir_ino),
    ]
    .into_iter()
    .filter(|&(_, ino)| ino != NULLFSINO && ino != 0)
    .collect();
    if !special.is_empty() {
        cx.emit(
            Node::new("Metadata inodes")
                .summary(format!("{} inodes", special.len()))
                .lazy(metadata_inodes, (fs.clone(), Arc::new(special))),
        );
    }
    if sb.log_start != 0 {
        if fs.fsb_valid(sb.log_start) {
            let span = fs.fsb_span(sb.log_start, sb.log_blocks.into());
            cx.emit(
                Node::new("Internal log")
                    .span(span)
                    .summary(format!(
                        "{}, at {}",
                        size(span.len),
                        fs.fsb_text(sb.log_start)
                    ))
                    .lazy(log::walk, span),
            );
        } else {
            cx.diag(Diagnostic::malformed(format!(
                "log start block {} lies outside the filesystem",
                sb.log_start
            )));
        }
    }
    Ok(())
}

async fn metadata_inodes(cx: Cx, (fs, list): (FsRef, Arc<Vec<(&'static str, u64)>>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(list.len())));
    for &(name, ino) in list.iter() {
        let node = match fs.ino_span(ino) {
            Ok(span) => Node::new(name)
                .span(span)
                .summary(format!("inode {ino}"))
                .lazy(inode::view, (fs.clone(), ino)),
            Err(d) => Node::new(name).diag(d),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// A typed field helper shared by the submodules: an AG block number,
/// summarised as "none" when null.
fn agbno_field<'a>(f: &mut Fields<'a>, name: &'static str) -> Field<'a, u32> {
    f.u32(name).with(|&v, n| {
        if v == NULLAGBLOCK {
            n.summary("none")
        } else {
            n
        }
    })
}
