//! XFS filesystems: the primary superblock, allocation group headers and
//! the root inode.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{crc32c, size, text, uuid_value};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "xfs",
    title: "XFS filesystem",
    extensions: &["img", "xfs"],
    mime: "application/x-xfs",
    probe: Probe::Magic(&[(0, b"XFSB")]),
    dissect: crate::expander!(dissect: Input),
};

const VERSION: FlagTable = &[
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
    flag(0x80, "PROJID32"),
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
];

record! {
    /// `struct xfs_dsb`, the on-disk superblock.
    pub struct Superblock {
        magic: ascii[4] "Magic",
        block_size: u32 "Block size",
        dblocks: u64 "Data blocks",
        rblocks: u64 "Realtime blocks",
        rextents: u64 "Realtime extents",
        uuid: bytes[16] "UUID" .with(uuid_value),
        log_start: u64 "Log start block",
        root_ino: u64 "Root inode",
        rbm_ino: u64 "Realtime bitmap inode",
        rsum_ino: u64 "Realtime summary inode",
        rext_size: u32 "Realtime extent size (blocks)",
        ag_blocks: u32 "Blocks per allocation group",
        ag_count: u32 "Allocation groups",
        rbm_blocks: u32 "Realtime bitmap blocks",
        log_blocks: u32 "Log blocks",
        version: u16 "Version and features" .hex() .flags(VERSION),
        sect_size: u16 "Sector size",
        inode_size: u16 "Inode size",
        inodes_per_block: u16 "Inodes per block",
        name: bytes[12] "Volume label" .with(|b, n| n.value(text(b))),
        block_log: u8 "log2(block size)",
        sect_log: u8 "log2(sector size)",
        inode_log: u8 "log2(inode size)",
        inopb_log: u8 "log2(inodes per block)",
        ag_blk_log: u8 "log2(AG blocks, rounded up)",
        rext_slog: u8 "log2(realtime extents)",
        in_progress: u8 "mkfs in progress",
        imax_pct: u8 "Max inode space (%)",
        icount: u64 "Allocated inodes",
        ifree: u64 "Free inodes",
        fdblocks: u64 "Free data blocks",
        frextents: u64 "Free realtime extents",
        uquot_ino: u64 "User quota inode",
        gquot_ino: u64 "Group quota inode",
        qflags: u16 "Quota flags" .hex(),
        flags: u8 "Flags" .hex(),
        shared_vn: u8 "Shared version",
        inode_align: u32 "Inode chunk alignment (blocks)",
        unit: u32 "Stripe unit (blocks)",
        width: u32 "Stripe width (blocks)",
        dir_blk_log: u8 "log2(directory block / block)",
        log_sect_log: u8 "log2(log sector size)",
        log_sect_size: u16 "Log sector size",
        log_sunit: u32 "Log stripe unit",
        features2: u32 "Features 2" .hex() .flags(FEATURES2),
        bad_features2: u32 "Features 2 (copy)" .hex(),
        compat: u32 "Compatible features" .hex(),
        ro_compat: u32 "Read-only compatible features" .hex() .flags(RO_COMPAT),
        incompat: u32 "Incompatible features" .hex() .flags(INCOMPAT),
        log_incompat: u32 "Log incompatible features" .hex(),
        crc: u32 "CRC32C" .hex(),
        spino_align: u32 "Sparse inode alignment",
        pquot_ino: u64 "Project quota inode",
        lsn: u64 "Last write LSN" .hex(),
        meta_uuid: bytes[16] "Metadata UUID" .with(uuid_value),
    }
}

record! {
    /// Allocation group free space header.
    pub struct Agf {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        seqno: u32 "AG number",
        length: u32 "Length (blocks)",
        bno_root: u32 "Free space by block B-tree root",
        cnt_root: u32 "Free space by size B-tree root",
        rmap_root: u32 "Reverse mapping B-tree root",
        bno_level: u32 "By-block B-tree levels",
        cnt_level: u32 "By-size B-tree levels",
        rmap_level: u32 "Reverse mapping B-tree levels",
        fl_first: u32 "Free list first",
        fl_last: u32 "Free list last",
        fl_count: u32 "Free list count",
        free_blocks: u32 "Free blocks",
        longest: u32 "Longest free extent",
        btree_blocks: u32 "B-tree blocks",
    }
}

record! {
    /// Allocation group inode header.
    pub struct Agi {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        seqno: u32 "AG number",
        length: u32 "Length (blocks)",
        count: u32 "Allocated inodes",
        root: u32 "Inode B-tree root",
        level: u32 "Inode B-tree levels",
        free_count: u32 "Free inodes",
        new_ino: u32 "Newest inode chunk",
        dir_ino: u32 "Unused (dir_ino)",
    }
}

const FORMATS: EnumTable = &[
    (0, "device"),
    (1, "local (inline)"),
    (2, "extents"),
    (3, "B-tree"),
    (4, "UUID"),
    (5, "reverse mapping"),
];

record! {
    /// `struct xfs_dinode` core (versions 1 and 2; v3 adds 76 bytes).
    pub struct Inode {
        magic: ascii[2] "Magic",
        mode: u16 "Mode" .with(|&m, n| n.summary(crate::formats::disk::unix_mode(m.into()))),
        version: u8 "Version",
        format: u8 "Data fork format" .enumeration(FORMATS),
        onlink: u16 "Link count (v1)",
        uid: u32 "Owner UID",
        gid: u32 "Owner GID",
        nlink: u32 "Link count",
        projid_lo: u16 "Project id (low)",
        projid_hi: u16 "Project id (high)",
        _pad: bytes[6] "Padding",
        flush_iter: u16 "Flush counter",
        atime: u32 "Accessed" .with(crate::formats::disk::unix_time),
        atime_ns: u32 "Accessed (ns)",
        mtime: u32 "Modified" .with(crate::formats::disk::unix_time),
        mtime_ns: u32 "Modified (ns)",
        ctime: u32 "Changed" .with(crate::formats::disk::unix_time),
        ctime_ns: u32 "Changed (ns)",
        size: u64 "Size",
        nblocks: u64 "Blocks",
        extsize: u32 "Extent size hint",
        nextents: u32 "Data extents",
        anextents: u16 "Attribute extents",
        forkoff: u8 "Attribute fork offset (×8)",
        aformat: u8 "Attribute fork format" .enumeration(FORMATS),
        dmevmask: u32 "DMAPI event mask",
        dmstate: u16 "DMAPI state",
        flags: u16 "Flags" .hex(),
        generation: u32 "Generation",
        next_unlinked: u32 "Next unlinked" .hex(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(0, Superblock::SIZE);
    let sb = parse(&cx, span, BE, &(), Superblock::layout).await?;
    let sect = u64::from(sb.sect_size).clamp(512, 32768);
    let mut node = Superblock::node("Superblock", vol.sub(0, sect), BE);
    if sb.version & 0xf == 5 {
        let mut data = cx.read_avail(vol.sub(0, sect)).await?;
        if let Some(f) = data.get_mut(224..228) {
            f.fill(0);
        }
        let computed = crc32c(&data);
        if computed != sb.crc.swap_bytes() {
            node = node.diag(Diagnostic::warning(format!(
                "superblock CRC mismatch: computed {computed:#010x}"
            )));
        }
    }
    cx.emit(node);
    let label = crate::text::until_nul(&sb.name);
    let block = u64::from(sb.block_size);
    cx.annotate(format!(
        "XFS v{} filesystem{}, {}, {} allocation groups, {}-byte blocks",
        sb.version & 0xf,
        if label.is_empty() {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(sb.dblocks.saturating_mul(block)),
        sb.ag_count,
        block
    ));
    if !(512..=65536).contains(&block) || sb.ag_blocks == 0 {
        return Err(Diagnostic::malformed("implausible block or AG size").at(span));
    }
    let geometry = Geometry {
        vol,
        block,
        sect,
        ag_blocks: sb.ag_blocks.into(),
        ag_blk_log: sb.ag_blk_log.into(),
        inopb_log: sb.inopb_log.into(),
        inode_size: sb.inode_size.into(),
    };
    cx.emit(
        Node::new("Allocation groups")
            .summary(format!("{} × {}", sb.ag_count, size(geometry.ag_blocks.saturating_mul(block))))
            .lazy(allocation_groups, (geometry, sb.ag_count)),
    );
    let root = geometry.inode(sb.root_ino);
    cx.emit(
        Node::new("Root inode")
            .span(root)
            .summary(format!("inode {}", sb.root_ino))
            .lazy(inode, root),
    );
    if sb.log_start != 0 {
        let log = vol.sub(geometry.fsblock(sb.log_start), u64::from(sb.log_blocks).saturating_mul(block));
        cx.emit(Node::new("Internal log").span(log).summary(size(log.len)));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Geometry {
    vol: Span,
    block: u64,
    sect: u64,
    ag_blocks: u64,
    ag_blk_log: u64,
    inopb_log: u64,
    inode_size: u64,
}

impl Geometry {
    fn mask(bits: u64) -> u64 {
        1u64.checked_shl(u32::try_from(bits).unwrap_or(64))
            .map_or(u64::MAX, |v| v.saturating_sub(1))
    }

    /// Byte offset of a filesystem block number (AG number in the high bits).
    fn fsblock(&self, fsb: u64) -> u64 {
        let shift = u32::try_from(self.ag_blk_log).unwrap_or(63);
        let ag = fsb.checked_shr(shift).unwrap_or(0);
        let agbno = fsb & Self::mask(self.ag_blk_log);
        ag.saturating_mul(self.ag_blocks)
            .saturating_add(agbno)
            .saturating_mul(self.block)
    }

    /// The span of inode `ino`.
    fn inode(&self, ino: u64) -> Span {
        let shift = u32::try_from(self.inopb_log).unwrap_or(63);
        let fsb = ino.checked_shr(shift).unwrap_or(0);
        let index = ino & Self::mask(self.inopb_log);
        self.vol.sub(
            self.fsblock(fsb)
                .saturating_add(index.saturating_mul(self.inode_size)),
            self.inode_size,
        )
    }
}

async fn allocation_groups(cx: Cx, (g, count): (Geometry, u32)) -> Result<()> {
    cx.set_count(Count::Exact(count.into()));
    for ag in 0..u64::from(count) {
        let start = ag.saturating_mul(g.ag_blocks).saturating_mul(g.block);
        let span = g.vol.sub(start, g.ag_blocks.saturating_mul(g.block));
        if span.is_empty() {
            cx.diag(Diagnostic::truncated(g.vol.tail(start), 0));
            break;
        }
        cx.push(
            Node::new(format!("AG {ag}"))
                .span(span)
                .summary(size(span.len))
                .lazy(allocation_group, (g, start)),
        )
        .await;
    }
    Ok(())
}

async fn allocation_group(cx: Cx, (g, start): (Geometry, u64)) -> Result<()> {
    let sb = g.vol.sub(start, g.sect);
    cx.emit(Superblock::node("Superblock (copy)", sb, BE));
    let agf = g.vol.sub(start.saturating_add(g.sect), Agf::SIZE);
    let mut agf_node = Agf::node("AGF (free space)", agf, BE);
    if let Ok(h) = parse(&cx, agf, BE, &(), Agf::layout).await {
        agf_node = agf_node.summary(format!("{} free blocks", h.free_blocks));
        if h.magic != "XAGF" {
            agf_node = agf_node.diag(Diagnostic::malformed("bad AGF magic"));
        }
    }
    cx.emit(agf_node);
    let agi = g.vol.sub(start.saturating_add(g.sect.saturating_mul(2)), Agi::SIZE);
    let mut agi_node = Agi::node("AGI (inodes)", agi, BE);
    if let Ok(h) = parse(&cx, agi, BE, &(), Agi::layout).await {
        agi_node = agi_node.summary(format!("{} inodes, {} free", h.count, h.free_count));
        if h.magic != "XAGI" {
            agi_node = agi_node.diag(Diagnostic::malformed("bad AGI magic"));
        }
    }
    cx.emit(agi_node);
    cx.emit(Node::new("AGFL (free list)").span(g.vol.sub(start.saturating_add(g.sect.saturating_mul(3)), g.sect)));
    Ok(())
}

async fn inode(cx: Cx, span: Span) -> Result<()> {
    let core = span.sub(0, Inode::SIZE);
    let ino = parse(&cx, core, BE, &(), Inode::layout).await?;
    if ino.magic != "IN" {
        return Err(Diagnostic::malformed("bad inode magic").at(core.sub(0, 2)));
    }
    cx.annotate(format!(
        "{}, {}",
        crate::formats::disk::unix_mode(ino.mode.into()),
        size(ino.size)
    ));
    cx.emit(Inode::node("Inode core", core, BE));
    let fork_start = if ino.version >= 3 { 176 } else { Inode::SIZE };
    let fork_len = if ino.forkoff != 0 {
        u64::from(ino.forkoff).saturating_mul(8)
    } else {
        span.len.saturating_sub(fork_start)
    };
    let fork = span.sub(fork_start, fork_len);
    cx.emit(
        Node::new("Data fork")
            .span(fork)
            .value(Value::Text(crate::value::lookup(FORMATS, ino.format.into()).unwrap_or("unknown").to_owned())),
    );
    Ok(())
}
