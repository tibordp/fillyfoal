//! ext2, ext3 and ext4 filesystems.
//!
//! The superblock at 1 KiB gives the geometry; block group descriptors
//! locate each group's bitmaps and inode table. Inodes map file content
//! through an extent tree (ext4) or direct/indirect block maps (ext2/3);
//! the mapping is assembled into a piecewise source (holes as zeros).
//! Directories, read through that same mapping, are lazy, paged trees
//! (hashed directories are read linearly).

use std::collections::HashSet;
use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{
    PieceList, content_node, crc32c_update, fragments_node, size, text, unix_mode, unix_time,
    uuid_value,
};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const SUPER: u64 = 1024;
const MAGIC: u16 = 0xef53;
const ROOT_INODE: u32 = 2;
/// Extent tree depth, directory nesting and directory size followed.
const MAX_EXTENT_DEPTH: u16 = 5;
const MAX_DIR_DEPTH: usize = 64;
const MAX_DIR_BYTES: u64 = 64 << 20;
/// Block mappings collected for one file before giving up.
const MAX_MAPPINGS: usize = 1 << 20;

pub static FORMAT: Format = Format {
    name: "ext",
    title: "ext2/ext3/ext4 filesystem",
    extensions: &["img", "ext2", "ext3", "ext4"],
    mime: "application/x-ext4",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    u16_le(h.data, 1024 + 56) == Some(MAGIC)
        && u32_le(h.data, 1024 + 24).is_some_and(|l| l <= 6)
        && u32_le(h.data, 1024 + 40).is_some_and(|n| n > 0)
}

const STATES: FlagTable = &[flag(1, "CLEAN"), flag(2, "ERRORS"), flag(4, "ORPHANS")];
const ERRORS: EnumTable = &[(1, "continue"), (2, "remount read-only"), (3, "panic")];
const OS: EnumTable = &[
    (0, "Linux"),
    (1, "Hurd"),
    (2, "Masix"),
    (3, "FreeBSD"),
    (4, "Lites"),
];

const COMPAT: FlagTable = &[
    flag(0x1, "DIR_PREALLOC"),
    flag(0x2, "IMAGIC_INODES"),
    flag(0x4, "HAS_JOURNAL"),
    flag(0x8, "EXT_ATTR"),
    flag(0x10, "RESIZE_INODE"),
    flag(0x20, "DIR_INDEX"),
    flag(0x40, "LAZY_BG"),
    flag(0x80, "EXCLUDE_INODE"),
    flag(0x100, "EXCLUDE_BITMAP"),
    flag(0x200, "SPARSE_SUPER2"),
    flag(0x400, "FAST_COMMIT"),
    flag(0x800, "STABLE_INODES"),
    flag(0x1000, "ORPHAN_FILE"),
];

const INCOMPAT: FlagTable = &[
    flag(0x1, "COMPRESSION"),
    flag(0x2, "FILETYPE"),
    flag(0x4, "RECOVER"),
    flag(0x8, "JOURNAL_DEV"),
    flag(0x10, "META_BG"),
    flag(0x40, "EXTENTS"),
    flag(0x80, "64BIT"),
    flag(0x100, "MMP"),
    flag(0x200, "FLEX_BG"),
    flag(0x400, "EA_INODE"),
    flag(0x1000, "DIRDATA"),
    flag(0x2000, "CSUM_SEED"),
    flag(0x4000, "LARGEDIR"),
    flag(0x8000, "INLINE_DATA"),
    flag(0x10000, "ENCRYPT"),
    flag(0x20000, "CASEFOLD"),
];

const RO_COMPAT: FlagTable = &[
    flag(0x1, "SPARSE_SUPER"),
    flag(0x2, "LARGE_FILE"),
    flag(0x4, "BTREE_DIR"),
    flag(0x8, "HUGE_FILE"),
    flag(0x10, "GDT_CSUM"),
    flag(0x20, "DIR_NLINK"),
    flag(0x40, "EXTRA_ISIZE"),
    flag(0x80, "HAS_SNAPSHOT"),
    flag(0x100, "QUOTA"),
    flag(0x200, "BIGALLOC"),
    flag(0x400, "METADATA_CSUM"),
    flag(0x800, "REPLICA"),
    flag(0x1000, "READONLY"),
    flag(0x2000, "PROJECT"),
    flag(0x4000, "SHARED_BLOCKS"),
    flag(0x8000, "VERITY"),
    flag(0x10000, "ORPHAN_PRESENT"),
];

const HASH: EnumTable = &[
    (0, "legacy"),
    (1, "half MD4"),
    (2, "TEA"),
    (3, "legacy (unsigned)"),
    (4, "half MD4 (unsigned)"),
    (5, "TEA (unsigned)"),
    (6, "SipHash"),
];

record! {
    /// `struct ext4_super_block` (through the encoding fields).
    pub struct Superblock {
        inodes: u32 "Inodes",
        blocks_lo: u32 "Blocks (low)",
        reserved_lo: u32 "Reserved blocks (low)",
        free_blocks_lo: u32 "Free blocks (low)",
        free_inodes: u32 "Free inodes",
        first_data_block: u32 "First data block",
        log_block_size: u32 "Block size (log2 - 10)" .with(|&v, n| n.summary(size(1024u64.checked_shl(v).unwrap_or(0)))),
        log_cluster_size: u32 "Cluster size (log2 - 10)",
        blocks_per_group: u32 "Blocks per group",
        clusters_per_group: u32 "Clusters per group",
        inodes_per_group: u32 "Inodes per group",
        mtime: u32 "Last mounted" .with(unix_time),
        wtime: u32 "Last written" .with(unix_time),
        mount_count: u16 "Mount count",
        max_mount_count: u16 "Maximum mount count",
        magic: u16 "Magic" .hex(),
        state: u16 "State" .hex() .flags(STATES),
        errors: u16 "On errors" .enumeration(ERRORS),
        minor_rev: u16 "Minor revision",
        last_check: u32 "Last checked" .with(unix_time),
        check_interval: u32 "Check interval (s)",
        creator_os: u32 "Creator OS" .enumeration(OS),
        rev_level: u32 "Revision",
        def_resuid: u16 "Reserved blocks user",
        def_resgid: u16 "Reserved blocks group",
        first_ino: u32 "First non-reserved inode",
        inode_size: u16 "Inode size",
        block_group_nr: u16 "This superblock's group",
        compat: u32 "Compatible features" .hex() .flags(COMPAT),
        incompat: u32 "Incompatible features" .hex() .flags(INCOMPAT),
        ro_compat: u32 "Read-only compatible features" .hex() .flags(RO_COMPAT),
        uuid: bytes[16] "UUID" .with(uuid_value),
        volume_name: bytes[16] "Volume name" .with(|b, n| n.value(text(b))),
        last_mounted: bytes[64] "Last mount point" .with(|b, n| n.value(text(b))),
        algorithm_bitmap: u32 "Compression algorithms",
        prealloc_blocks: u8 "Preallocated blocks",
        prealloc_dir_blocks: u8 "Preallocated directory blocks",
        reserved_gdt_blocks: u16 "Reserved GDT blocks",
        journal_uuid: bytes[16] "Journal UUID" .with(uuid_value),
        journal_inode: u32 "Journal inode",
        journal_dev: u32 "Journal device",
        last_orphan: u32 "Orphan list head",
        hash_seed: bytes[16] "Directory hash seed",
        def_hash: u8 "Default hash" .enumeration(HASH),
        journal_backup: u8 "Journal backup type",
        desc_size: u16 "Group descriptor size",
        default_mount_opts: u32 "Default mount options" .hex(),
        first_meta_bg: u32 "First meta block group",
        mkfs_time: u32 "Created" .with(unix_time),
        journal_blocks: bytes[68] "Journal inode backup",
        blocks_hi: u32 "Blocks (high)",
        reserved_hi: u32 "Reserved blocks (high)",
        free_blocks_hi: u32 "Free blocks (high)",
        min_extra_isize: u16 "Minimum extra inode size",
        want_extra_isize: u16 "Wanted extra inode size",
        flags: u32 "Flags" .hex(),
        raid_stride: u16 "RAID stride",
        mmp_interval: u16 "MMP interval",
        mmp_block: u64 "MMP block",
        raid_stripe_width: u32 "RAID stripe width",
        log_groups_per_flex: u8 "Groups per flex group (log2)",
        checksum_type: u8 "Checksum type",
        encryption_level: u8 "Encryption level",
        _pad: u8 "Padding",
        kbytes_written: u64 "Kilobytes written",
        snapshot_inum: u32 "Snapshot inode",
        snapshot_id: u32 "Snapshot id",
        snapshot_reserved: u64 "Snapshot reserved blocks",
        snapshot_list: u32 "Snapshot list head",
        error_count: u32 "Errors",
        first_error_time: u32 "First error" .with(unix_time),
        first_error_ino: u32 "First error inode",
        first_error_block: u64 "First error block",
        first_error_func: ascii[32] "First error function",
        first_error_line: u32 "First error line",
        last_error_time: u32 "Last error" .with(unix_time),
        last_error_ino: u32 "Last error inode",
        last_error_line: u32 "Last error line",
        last_error_block: u64 "Last error block",
        last_error_func: ascii[32] "Last error function",
        mount_opts: ascii[64] "Mount options",
        usr_quota: u32 "User quota inode",
        grp_quota: u32 "Group quota inode",
        overhead: u32 "Overhead clusters",
        backup_bgs: bytes[8] "Backup groups (sparse_super2)",
        encrypt_algos: bytes[4] "Encryption algorithms",
        encrypt_salt: bytes[16] "Encryption salt",
        lpf_ino: u32 "lost+found inode",
        prj_quota: u32 "Project quota inode",
        checksum_seed: u32 "Checksum seed" .hex(),
    }
}

record! {
    /// `struct ext4_group_desc` (32-byte part).
    pub struct GroupDesc {
        block_bitmap: u32 "Block bitmap",
        inode_bitmap: u32 "Inode bitmap",
        inode_table: u32 "Inode table",
        free_blocks: u16 "Free blocks",
        free_inodes: u16 "Free inodes",
        used_dirs: u16 "Directories",
        flags: u16 "Flags" .hex() .flags(BG_FLAGS),
        exclude_bitmap: u32 "Snapshot exclusion bitmap",
        block_bitmap_csum: u16 "Block bitmap checksum" .hex(),
        inode_bitmap_csum: u16 "Inode bitmap checksum" .hex(),
        itable_unused: u16 "Unused inodes",
        checksum: u16 "Checksum" .hex(),
    }
}

const BG_FLAGS: FlagTable = &[
    flag(1, "INODE_UNINIT"),
    flag(2, "BLOCK_UNINIT"),
    flag(4, "INODE_ZEROED"),
];

const INODE_FLAGS: FlagTable = &[
    flag(0x10, "IMMUTABLE"),
    flag(0x20, "APPEND"),
    flag(0x40, "NODUMP"),
    flag(0x80, "NOATIME"),
    flag(0x1000, "INDEX"),
    flag(0x4000, "JOURNAL_DATA"),
    flag(0x40000, "HUGE_FILE"),
    flag(0x80000, "EXTENTS"),
    flag(0x100000, "VERITY"),
    flag(0x200000, "EA_INODE"),
    flag(0x10000000, "INLINE_DATA"),
    flag(0x20000000, "PROJINHERIT"),
    flag(0x40000000, "CASEFOLD"),
];

record! {
    /// `struct ext4_inode` (the 128-byte base).
    pub struct Inode {
        mode: u16 "Mode" .hex() .with(|&m, n| n.summary(unix_mode(m.into()))),
        uid: u16 "Owner (low)",
        size_lo: u32 "Size (low)",
        atime: u32 "Accessed" .with(unix_time),
        ctime: u32 "Changed" .with(unix_time),
        mtime: u32 "Modified" .with(unix_time),
        dtime: u32 "Deleted" .with(unix_time),
        gid: u16 "Group (low)",
        links: u16 "Links",
        blocks_lo: u32 "512-byte blocks (low)",
        flags: u32 "Flags" .hex() .flags(INODE_FLAGS),
        version: u32 "Version",
        block: bytes[60] "Block map / extent tree",
        generation: u32 "Generation",
        file_acl_lo: u32 "Extended attribute block (low)",
        size_hi: u32 "Size (high)",
        _faddr: u32 "Fragment address (obsolete)",
        blocks_hi: u16 "512-byte blocks (high)",
        file_acl_hi: u16 "Extended attribute block (high)",
        uid_hi: u16 "Owner (high)",
        gid_hi: u16 "Group (high)",
        checksum_lo: u16 "Checksum (low)" .hex(),
        _reserved: u16 "Reserved",
    }
}

record! {
    pub struct ExtentHeader {
        magic: u16 "Magic" .hex(),
        entries: u16 "Entries",
        max: u16 "Capacity",
        depth: u16 "Depth",
        generation: u32 "Generation",
    }
}

#[derive(Debug)]
struct Fs {
    input: Input,
    vol: Span,
    block: u64,
    first_data_block: u64,
    inodes_per_group: u64,
    inode_size: u64,
    desc_size: u64,
    gdt: Span,
    groups: u64,
    filetype: bool,
}

type FsRef = Arc<Fs>;

impl Fs {
    fn block_span(&self, n: u64) -> Span {
        self.vol.sub(n.saturating_mul(self.block), self.block)
    }

    /// The span of inode `ino`'s record.
    async fn inode_span(&self, cx: &Cx, ino: u32) -> Result<Span> {
        let index = u64::from(
            ino.checked_sub(1)
                .ok_or_else(|| Diagnostic::malformed("inode 0"))?,
        );
        let group = index.checked_div(self.inodes_per_group).unwrap_or(0);
        if group >= self.groups {
            return Err(Diagnostic::malformed(format!(
                "inode {ino} is beyond the last group"
            )));
        }
        let desc = self
            .gdt
            .sub(group.saturating_mul(self.desc_size), self.desc_size);
        let raw = cx.read(desc).await?;
        let lo = u64::from(u32_le(&raw, 8).unwrap_or(0));
        let hi = if self.desc_size >= 64 {
            u64::from(u32_le(&raw, 40).unwrap_or(0))
        } else {
            0
        };
        let table = hi << 32 | lo;
        let within = index.checked_rem(self.inodes_per_group).unwrap_or(0);
        Ok(self.vol.sub(
            table
                .saturating_mul(self.block)
                .saturating_add(within.saturating_mul(self.inode_size)),
            self.inode_size,
        ))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, 1024);
    let sb = parse(
        &cx,
        span.sub(0, Superblock::SIZE),
        LE,
        &(),
        Superblock::layout,
    )
    .await?;
    let mut node = Superblock::node("Superblock", span, LE);
    if sb.ro_compat & 0x400 != 0 {
        let raw = cx.read_avail(span).await?;
        let computed = crc32c_update(!0, raw.get(..1020).unwrap_or_default());
        if u32_le(&raw, 1020) != Some(computed) {
            node = node.diag(Diagnostic::warning(format!(
                "superblock checksum mismatch: computed {computed:#010x}"
            )));
        }
    }
    cx.emit(node);
    let block = 1024u64
        .checked_shl(sb.log_block_size)
        .filter(|&b| b <= 65536)
        .ok_or_else(|| {
            Diagnostic::malformed(format!(
                "block size 2^{}",
                sb.log_block_size.saturating_add(10)
            ))
            .at(span)
        })?;
    let wide = sb.incompat & 0x80 != 0;
    let blocks = if wide {
        u64::from(sb.blocks_hi) << 32 | u64::from(sb.blocks_lo)
    } else {
        sb.blocks_lo.into()
    };
    let kind = if sb.incompat & 0x2c0 != 0 || sb.ro_compat & 0x448 != 0 {
        "ext4"
    } else if sb.compat & 4 != 0 {
        "ext3"
    } else {
        "ext2"
    };
    let label = crate::text::until_nul(&sb.volume_name);
    cx.annotate(format!(
        "{kind} filesystem{}, {}, {}-byte blocks, {} inodes",
        if label.is_empty() {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(blocks.saturating_mul(block)),
        block,
        sb.inodes
    ));
    if sb.blocks_per_group == 0 || sb.inodes_per_group == 0 {
        return Err(Diagnostic::malformed("zero blocks or inodes per group").at(span));
    }
    let groups = blocks
        .saturating_sub(sb.first_data_block.into())
        .div_ceil(sb.blocks_per_group.into());
    let desc_size = if wide {
        u64::from(sb.desc_size).max(32)
    } else {
        32
    };
    let inode_size = if sb.rev_level == 0 {
        128
    } else {
        u64::from(sb.inode_size).max(128)
    };
    let gdt_block = u64::from(sb.first_data_block).saturating_add(1);
    let fs: FsRef = Arc::new(Fs {
        input,
        vol,
        block,
        first_data_block: sb.first_data_block.into(),
        inodes_per_group: sb.inodes_per_group.into(),
        inode_size,
        desc_size,
        gdt: vol.sub(
            gdt_block.saturating_mul(block),
            groups.saturating_mul(desc_size),
        ),
        groups,
        filetype: sb.incompat & 2 != 0,
    });
    cx.emit(
        Node::new("Block group descriptors")
            .span(fs.gdt)
            .summary(format!("{groups} groups of {} blocks", sb.blocks_per_group))
            .lazy(
                group_descriptors,
                (fs.clone(), u64::from(sb.blocks_per_group)),
            ),
    );
    cx.emit(Node::new("Root directory").summary("inode 2").lazy(
        crate::expander!(self::directory: Dir),
        Dir {
            fs: fs.clone(),
            ino: ROOT_INODE,
            ancestors: Arc::new(Vec::new()),
        },
    ));
    if sb.compat & 4 != 0 && sb.journal_inode != 0 {
        cx.emit(
            Node::new("Journal")
                .summary(format!("inode {}", sb.journal_inode))
                .lazy(inode_node, (fs.clone(), sb.journal_inode)),
        );
    }
    Ok(())
}

async fn group_descriptors(cx: Cx, (fs, per_group): (FsRef, u64)) -> Result<()> {
    cx.set_count(Count::Exact(fs.groups));
    for g in 0..fs.groups {
        let span = fs.gdt.sub(g.saturating_mul(fs.desc_size), fs.desc_size);
        let d = parse(
            &cx,
            span.sub(0, GroupDesc::SIZE),
            LE,
            &(),
            GroupDesc::layout,
        )
        .await?;
        let first = fs
            .first_data_block
            .saturating_add(g.saturating_mul(per_group));
        cx.push(
            GroupDesc::node(format!("Group {g}"), span, LE).summary(format!(
                "blocks {first}–{}, inode table at {}, {} free blocks, {} free inodes",
                first.saturating_add(per_group).saturating_sub(1),
                d.inode_table,
                d.free_blocks,
                d.free_inodes
            )),
        )
        .await;
    }
    Ok(())
}

/// What an inode maps: (logical block, physical block, count, initialized).
type Mapping = (u64, u64, u64, bool);

/// Collects an inode's block mappings, sorted by logical block.
async fn mappings(
    cx: &Cx,
    fs: &Fs,
    inode: &[u8],
    size: u64,
) -> Result<(Vec<Mapping>, Option<Diagnostic>)> {
    let flags = u32_le(inode, 32).unwrap_or(0);
    let i_block = inode.get(40..100).unwrap_or_default();
    let mut out = Vec::new();
    let problem = if flags & 0x80000 != 0 {
        let mut seen = HashSet::new();
        extents(cx, fs, i_block, MAX_EXTENT_DEPTH, &mut seen, &mut out).await?
    } else {
        block_map(cx, fs, i_block, size, &mut out).await?
    };
    out.sort_unstable_by_key(|m| m.0);
    Ok((out, problem))
}

/// Walks an extent tree node (the inode's `i_block` or a tree block).
async fn extents(
    cx: &Cx,
    fs: &Fs,
    node: &[u8],
    depth_limit: u16,
    seen: &mut HashSet<u64>,
    out: &mut Vec<Mapping>,
) -> Result<Option<Diagnostic>> {
    // Iterative depth-first walk to keep the future small.
    let mut stack: Vec<(Vec<u8>, u16)> = vec![(node.to_vec(), depth_limit)];
    while let Some((data, limit)) = stack.pop() {
        if u16_le(&data, 0) != Some(0xf30a) {
            return Ok(Some(Diagnostic::malformed("bad extent header magic")));
        }
        let entries = usize::from(u16_le(&data, 2).unwrap_or(0));
        let depth = u16_le(&data, 6).unwrap_or(0);
        if depth >= limit {
            return Ok(Some(Diagnostic::malformed(
                "extent tree depth does not decrease",
            )));
        }
        for i in 0..entries {
            let at = 12usize.saturating_add(i.saturating_mul(12));
            let Some(e) = data.get(at..at.saturating_add(12)) else {
                break;
            };
            let logical = u64::from(u32_le(e, 0).unwrap_or(0));
            if depth == 0 {
                let raw_len = u16_le(e, 4).unwrap_or(0);
                let (len, init) = if raw_len > 32768 {
                    (raw_len.saturating_sub(32768), false)
                } else {
                    (raw_len, true)
                };
                let start = u64::from(u16_le(e, 6).unwrap_or(0)) << 32
                    | u64::from(u32_le(e, 8).unwrap_or(0));
                out.push((logical, start, len.into(), init));
                if out.len() >= MAX_MAPPINGS {
                    return Ok(Some(Diagnostic::limit("too many extents")));
                }
            } else {
                let child = u64::from(u16_le(e, 8).unwrap_or(0)) << 32
                    | u64::from(u32_le(e, 4).unwrap_or(0));
                if !seen.insert(child) {
                    return Ok(Some(Diagnostic::malformed(format!(
                        "extent tree revisits block {child}"
                    ))));
                }
                let block = cx.read(fs.block_span(child)).await?;
                stack.push((block, depth));
            }
        }
        cx.checkpoint().await;
    }
    Ok(None)
}

/// Walks the classic block map: 12 direct pointers, then single, double
/// and triple indirect blocks.
async fn block_map(
    cx: &Cx,
    fs: &Fs,
    i_block: &[u8],
    size: u64,
    out: &mut Vec<Mapping>,
) -> Result<Option<Diagnostic>> {
    let per = fs.block / 4;
    let needed = size.div_ceil(fs.block);
    let ptr = |i: usize| u64::from(u32_le(i_block, i.saturating_mul(4)).unwrap_or(0));
    for i in 0..12usize {
        if to_u64(i) >= needed {
            return Ok(None);
        }
        if ptr(i) != 0 {
            out.push((to_u64(i), ptr(i), 1, true));
        }
    }
    // (block number, level, first logical block covered)
    let mut stack: Vec<(u64, u32, u64)> = Vec::new();
    let mut first = 12u64;
    for (slot, level) in [(12usize, 1u32), (13, 2), (14, 3)] {
        if ptr(slot) != 0 {
            stack.push((ptr(slot), level, first));
        }
        first = first.saturating_add(per.saturating_pow(level));
    }
    stack.reverse();
    let mut seen = HashSet::new();
    while let Some((block, level, logical)) = stack.pop() {
        if logical >= needed {
            continue;
        }
        if !seen.insert(block) {
            return Ok(Some(Diagnostic::malformed(format!(
                "block map revisits block {block}"
            ))));
        }
        let data = cx.read(fs.block_span(block)).await?;
        let span = per.saturating_pow(level.saturating_sub(1));
        let mut children = Vec::new();
        for (j, p) in data.as_chunks::<4>().0.iter().enumerate() {
            let p = u64::from(u32::from_le_bytes(*p));
            let at = logical.saturating_add(to_u64(j).saturating_mul(span));
            if p == 0 || at >= needed {
                continue;
            }
            if level == 1 {
                out.push((at, p, 1, true));
                if out.len() >= MAX_MAPPINGS {
                    return Ok(Some(Diagnostic::limit("too many blocks")));
                }
            } else {
                children.push((p, level.saturating_sub(1), at));
            }
        }
        children.reverse();
        stack.extend(children);
    }
    Ok(None)
}

/// The inode's content as a span (fragments assembled, holes as zeros).
async fn content(
    cx: &Cx,
    fs: &Fs,
    inode_span: Span,
    inode: &[u8],
    size: u64,
) -> Result<(Span, Vec<Span>)> {
    let flags = u32_le(inode, 32).unwrap_or(0);
    let mode = u16_le(inode, 0).unwrap_or(0);
    // Inline data and fast symlinks live in the inode itself.
    if flags & 0x1000_0000 != 0 || (mode & 0xf000 == 0xa000 && size < 60 && flags & 0x80000 == 0) {
        let span = inode_span.sub(40, size.min(60));
        return Ok((span, vec![span]));
    }
    let (maps, problem) = mappings(cx, fs, inode, size).await?;
    if let Some(d) = problem {
        cx.diag(d);
    }
    let mut list = PieceList::new(inode_span);
    for (i, (logical, physical, count, init)) in maps.into_iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let at = logical.saturating_mul(fs.block);
        if at >= size {
            break;
        }
        if at > list.len() {
            list.hole(cx, at.saturating_sub(list.len()))?;
        } else if at < list.len() {
            cx.diag(Diagnostic::malformed(format!(
                "overlapping mapping at logical block {logical}"
            )));
            continue;
        }
        let len = count.saturating_mul(fs.block).min(size.saturating_sub(at));
        if init {
            list.data(fs.vol.sub(physical.saturating_mul(fs.block), len));
        } else {
            list.hole(cx, len)?;
        }
    }
    if list.len() < size {
        list.hole(cx, size.saturating_sub(list.len()))?;
    }
    let pieces = list.pieces().to_vec();
    let transform = if flags & 0x80000 != 0 {
        "ext4-extents"
    } else {
        "ext2-blocks"
    };
    Ok((list.finish(cx, transform)?, pieces))
}

fn inode_size_of(inode: &[u8]) -> u64 {
    u64::from(u32_le(inode, 108).unwrap_or(0)) << 32 | u64::from(u32_le(inode, 4).unwrap_or(0))
}

/// Shows an inode: its fields, its mapping and its content.
async fn inode_node(cx: Cx, (fs, ino): (FsRef, u32)) -> Result<()> {
    let span = fs.inode_span(&cx, ino).await?;
    let raw = cx.read(span).await?;
    let size = inode_size_of(&raw);
    cx.emit(Inode::node(format!("Inode {ino}"), span, LE));
    let (data, pieces) = content(&cx, &fs, span, &raw, size).await?;
    cx.emit(fragments_node("Blocks", pieces));
    if u16_le(&raw, 0).unwrap_or(0) & 0xf000 == 0xa000 {
        let target = crate::text::until_nul(&cx.read_avail(data.sub(0, 4096)).await?);
        cx.emit(
            Node::new("Symlink target")
                .span(data)
                .value(Value::Text(target)),
        );
    } else {
        cx.emit(content_node(&fs.input, data));
    }
    Ok(())
}

#[derive(Clone)]
struct Dir {
    fs: FsRef,
    ino: u32,
    ancestors: Arc<Vec<u32>>,
}

const FILE_TYPES: EnumTable = &[
    (0, "unknown"),
    (1, "regular file"),
    (2, "directory"),
    (3, "character device"),
    (4, "block device"),
    (5, "FIFO"),
    (6, "socket"),
    (7, "symbolic link"),
];

async fn directory(cx: Cx, dir: Dir) -> Result<()> {
    let fs = dir.fs.clone();
    let span = fs.inode_span(&cx, dir.ino).await?;
    let raw = cx.read(span).await?;
    if u16_le(&raw, 0).unwrap_or(0) & 0xf000 != 0x4000 {
        return Err(
            Diagnostic::malformed(format!("inode {} is not a directory", dir.ino)).at(span),
        );
    }
    cx.emit(Inode::node(format!("Inode {}", dir.ino), span, LE));
    let size = inode_size_of(&raw).min(MAX_DIR_BYTES);
    if u32_le(&raw, 32).unwrap_or(0) & 0x1000_0000 != 0 {
        cx.diag(Diagnostic::unsupported("inline-data directory"));
        return Ok(());
    }
    let (data, _) = content(&cx, &fs, span, &raw, size).await?;
    let mut ancestors = (*dir.ancestors).clone();
    ancestors.push(dir.ino);
    let ancestors = Arc::new(ancestors);
    let mut offset = 0u64;
    while offset < data.len {
        cx.progress(offset, data.len);
        let block = data.sub(offset, fs.block);
        let bytes = cx.read_avail(block).await?;
        let mut at = 0usize;
        while at.saturating_add(8) <= bytes.len() {
            let ino = u32_le(&bytes, at).unwrap_or(0);
            let rec_len = usize::from(u16_le(&bytes, at.saturating_add(4)).unwrap_or(0));
            let name_len = usize::from(bytes.get(at.saturating_add(6)).copied().unwrap_or(0));
            let file_type = bytes.get(at.saturating_add(7)).copied().unwrap_or(0);
            if rec_len < 8 {
                cx.diag(
                    Diagnostic::malformed("directory entry with a record length below 8")
                        .at(block.sub(to_u64(at), 8)),
                );
                break;
            }
            let entry = block.sub(to_u64(at), to_u64(rec_len));
            let name_bytes = bytes
                .get(at.saturating_add(8)..at.saturating_add(8).saturating_add(name_len))
                .unwrap_or_default();
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            at = at.saturating_add(rec_len);
            if ino == 0 || name == "." || name == ".." {
                cx.checkpoint().await;
                continue;
            }
            let kind = if fs.filetype {
                crate::value::lookup(FILE_TYPES, file_type.into()).unwrap_or("unknown")
            } else {
                "entry"
            };
            let node = Node::new(name)
                .span(entry)
                .summary(format!("{kind}, inode {ino}"));
            let node = if fs.filetype && file_type == 2 {
                if ancestors.contains(&ino) || ancestors.len() > MAX_DIR_DEPTH {
                    node.diag(Diagnostic::malformed(format!(
                        "directory inode {ino} contains itself; not followed"
                    )))
                } else {
                    node.lazy(
                        crate::expander!(self::directory: Dir),
                        Dir {
                            fs: fs.clone(),
                            ino,
                            ancestors: ancestors.clone(),
                        },
                    )
                }
            } else {
                node.lazy(inode_node, (fs.clone(), ino))
            };
            cx.push(node).await;
        }
        offset = offset.saturating_add(fs.block);
    }
    Ok(())
}
