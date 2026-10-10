//! ext2, ext3 and ext4 filesystems.
//!
//! The superblock at 1 KiB gives the geometry; block group descriptors
//! locate each group's bitmaps and inode table (with FLEX_BG these may lie
//! in another group). Inodes map file content through an extent tree
//! (ext4) or direct/indirect block maps (ext2/3), or hold it inline; the
//! mapping is assembled into a piecewise source (holes as zeros).
//! Directories are linear blocks of entries, optionally indexed by an
//! htree; extended attributes live after the inode core or in a block of
//! their own. With METADATA_CSUM every structure carries a CRC-32C, which
//! is verified. The journal (JBD2) is described from its superblock.

mod dir;
mod inode;
mod journal;
mod xattr;

use std::sync::Arc;

use crate::bytes::{to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::{Path, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::{crc32c_update, size, text, unix_time, uuid_value};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag};

const LE: Endian = Endian::Little;
const SUPER: u64 = 1024;
const MAGIC: u16 = 0xef53;
const ROOT_INODE: u32 = 2;
/// Directory nesting followed.
const MAX_DIR_DEPTH: usize = 64;

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

const SB_FLAGS: FlagTable = &[
    flag(0x1, "SIGNED_HASH"),
    flag(0x2, "UNSIGNED_HASH"),
    flag(0x4, "TEST_FILESYS"),
];

const MOUNT_OPTS: FlagTable = &[
    flag(0x001, "DEBUG"),
    flag(0x002, "BSDGROUPS"),
    flag(0x004, "XATTR_USER"),
    flag(0x008, "ACL"),
    flag(0x010, "UID16"),
    field_flag(0x060, 0x020, "JMODE_DATA"),
    field_flag(0x060, 0x040, "JMODE_ORDERED"),
    field_flag(0x060, 0x060, "JMODE_WBACK"),
    flag(0x100, "NOBARRIER"),
    flag(0x200, "BLOCK_VALIDITY"),
    flag(0x400, "DISCARD"),
    flag(0x800, "NODELALLOC"),
];

const fn field_flag(mask: u64, value: u64, name: &'static str) -> crate::value::FlagDef {
    crate::value::field(mask, value, name)
}

const CHECKSUM_TYPES: EnumTable = &[(1, "CRC-32C")];

const ENCODINGS: EnumTable = &[(0, "none"), (1, "UTF-8 12.1")];

record! {
    /// `struct ext4_super_block`.
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
        hash_seed: bytes[16] "Directory hash seed" .with(uuid_value),
        def_hash: u8 "Default hash" .enumeration(HASH),
        journal_backup: u8 "Journal backup type" .desc("1: the journal inode's block map is copied into the next field"),
        desc_size: u16 "Group descriptor size",
        default_mount_opts: u32 "Default mount options" .hex() .flags(MOUNT_OPTS),
        first_meta_bg: u32 "First meta block group",
        mkfs_time: u32 "Created" .with(unix_time),
        journal_blocks: bytes[68] "Journal inode backup" .desc("A copy of the journal inode's block map (i_block) and size"),
        blocks_hi: u32 "Blocks (high)",
        reserved_hi: u32 "Reserved blocks (high)",
        free_blocks_hi: u32 "Free blocks (high)",
        min_extra_isize: u16 "Minimum extra inode size",
        want_extra_isize: u16 "Wanted extra inode size",
        flags: u32 "Flags" .hex() .flags(SB_FLAGS),
        raid_stride: u16 "RAID stride",
        mmp_interval: u16 "MMP interval",
        mmp_block: u64 "MMP block",
        raid_stripe_width: u32 "RAID stripe width",
        log_groups_per_flex: u8 "Groups per flex group (log2)",
        checksum_type: u8 "Checksum type" .enumeration(CHECKSUM_TYPES),
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
        wtime_hi: u8 "Last written (high byte)",
        mtime_hi: u8 "Last mounted (high byte)",
        mkfs_time_hi: u8 "Created (high byte)",
        lastcheck_hi: u8 "Last checked (high byte)",
        first_error_time_hi: u8 "First error (high byte)",
        last_error_time_hi: u8 "Last error (high byte)",
        first_error_errcode: u8 "First error code",
        last_error_errcode: u8 "Last error code",
        encoding: u16 "Filename encoding" .enumeration(ENCODINGS),
        encoding_flags: u16 "Encoding flags" .hex(),
        orphan_file_inum: u32 "Orphan file inode",
        _reserved: bytes[376] "Reserved",
        checksum: u32 "Checksum" .hex() .desc("CRC-32C (no final inversion) of the superblock up to this field (METADATA_CSUM)"),
    }
}

const BG_FLAGS: FlagTable = &[
    flag(1, "INODE_UNINIT"),
    flag(2, "BLOCK_UNINIT"),
    flag(4, "INODE_ZEROED"),
];

/// A group descriptor (`struct ext4_group_desc`), 32 or 64 bytes.
#[derive(Clone, Copy, Debug, Default)]
struct Gd {
    block_bitmap: u64,
    inode_bitmap: u64,
    inode_table: u64,
    free_blocks: u64,
    free_inodes: u64,
    flags: u16,
}

fn gd_parse(raw: &[u8], wide: bool) -> Gd {
    let u32_at = |at: usize| u64::from(u32_le(raw, at).unwrap_or(0));
    let u16_at = |at: usize| u64::from(u16_le(raw, at).unwrap_or(0));
    let hi32 = |at: usize| if wide { u32_at(at) << 32 } else { 0 };
    let hi16 = |at: usize| if wide { u16_at(at) << 16 } else { 0 };
    Gd {
        block_bitmap: u32_at(0) | hi32(0x20),
        inode_bitmap: u32_at(4) | hi32(0x24),
        inode_table: u32_at(8) | hi32(0x28),
        free_blocks: u16_at(0xc) | hi16(0x2c),
        free_inodes: u16_at(0xe) | hi16(0x2e),
        flags: u16_le(raw, 0x12).unwrap_or(0),
    }
}

#[derive(Clone, Copy, Debug)]
struct GdCtx {
    wide: bool,
    /// (computed checksum, block bitmap checksum, inode bitmap checksum)
    csum: Option<u16>,
    block_bitmap_csum: Option<u32>,
    inode_bitmap_csum: Option<u32>,
}

fn csum_summary(ok: bool) -> &'static str {
    if ok { "valid" } else { "mismatch" }
}

fn gd_layout(f: &mut Fields<'_>, ctx: &GdCtx) -> Result<()> {
    f.u32("Block bitmap").emit()?;
    f.u32("Inode bitmap").emit()?;
    f.u32("Inode table").emit()?;
    f.u16("Free blocks").emit()?;
    f.u16("Free inodes").emit()?;
    f.u16("Directories").emit()?;
    f.u16("Flags").hex().flags(BG_FLAGS).emit()?;
    f.u32("Snapshot exclusion bitmap").emit()?;
    f.u16("Block bitmap checksum (low)")
        .hex()
        .with(|&v, n| match ctx.block_bitmap_csum {
            Some(c) if !ctx.wide => n.summary(csum_summary(u32::from(v) == c & 0xffff)),
            _ => n,
        })
        .emit()?;
    f.u16("Inode bitmap checksum (low)")
        .hex()
        .with(|&v, n| match ctx.inode_bitmap_csum {
            Some(c) if !ctx.wide => n.summary(csum_summary(u32::from(v) == c & 0xffff)),
            _ => n,
        })
        .emit()?;
    f.u16("Unused inodes").emit()?;
    f.u16("Checksum")
        .hex()
        .with(|&v, n| match ctx.csum {
            Some(c) if c == v => n.summary("valid"),
            Some(c) => n.diag(Diagnostic::warning(format!("mismatch: computed {c:#06x}"))),
            None => n,
        })
        .emit()?;
    if ctx.wide {
        f.u32("Block bitmap (high)").emit()?;
        f.u32("Inode bitmap (high)").emit()?;
        f.u32("Inode table (high)").emit()?;
        f.u16("Free blocks (high)").emit()?;
        f.u16("Free inodes (high)").emit()?;
        f.u16("Directories (high)").emit()?;
        f.u16("Unused inodes (high)").emit()?;
        f.u32("Snapshot exclusion bitmap (high)").emit()?;
        f.u16("Block bitmap checksum (high)").hex().emit()?;
        f.u16("Inode bitmap checksum (high)").hex().emit()?;
        f.u32("Reserved").emit()?;
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Reserved", rest).emit()?;
    }
    Ok(())
}

#[derive(Debug)]
struct Fs {
    input: Input,
    vol: Span,
    block: u64,
    first_data_block: u64,
    blocks: u64,
    blocks_per_group: u64,
    inodes_per_group: u64,
    inode_size: u64,
    desc_size: u64,
    gdt: Span,
    groups: u64,
    wide: bool,
    filetype: bool,
    /// METADATA_CSUM, and its seed.
    csum: Option<u32>,
    gdt_csum: bool,
    uuid: Vec<u8>,
    sparse_super: bool,
    /// SPARSE_SUPER2: the two groups with backups.
    backup_bgs: Option<[u64; 2]>,
    reserved_gdt: u64,
    meta_bg: bool,
}

type FsRef = Arc<Fs>;

impl Fs {
    fn block_span(&self, n: u64) -> Span {
        self.vol.sub(n.saturating_mul(self.block), self.block)
    }

    fn blocks_span(&self, n: u64, count: u64) -> Span {
        self.vol.sub(
            n.saturating_mul(self.block),
            count.saturating_mul(self.block),
        )
    }

    /// Group `g`'s descriptor: its span and fields.
    async fn desc(&self, cx: &Cx, g: u64) -> Result<(Span, Gd, Vec<u8>)> {
        if g >= self.groups {
            return Err(Diagnostic::malformed(format!("group {g} does not exist")));
        }
        let span = self
            .gdt
            .sub(g.saturating_mul(self.desc_size), self.desc_size);
        let raw = cx.read(span).await?;
        Ok((span, gd_parse(&raw, self.wide && self.desc_size >= 64), raw))
    }

    /// The span of inode `ino`'s record.
    async fn inode_span(&self, cx: &Cx, ino: u32) -> Result<Span> {
        let index = u64::from(
            ino.checked_sub(1)
                .ok_or_else(|| Diagnostic::malformed("inode 0"))?,
        );
        let group = index.checked_div(self.inodes_per_group).unwrap_or(0);
        let (_, gd, _) = self
            .desc(cx, group)
            .await
            .map_err(|_| Diagnostic::malformed(format!("inode {ino} is beyond the last group")))?;
        let within = index.checked_rem(self.inodes_per_group).unwrap_or(0);
        Ok(self.vol.sub(
            gd.inode_table
                .saturating_mul(self.block)
                .saturating_add(within.saturating_mul(self.inode_size)),
            self.inode_size,
        ))
    }

    /// Whether group `g` holds a superblock backup.
    fn has_super(&self, g: u64) -> bool {
        if g == 0 {
            return true;
        }
        if let Some(bgs) = self.backup_bgs {
            return bgs.contains(&g);
        }
        if !self.sparse_super || g == 1 {
            return true;
        }
        [3u64, 5, 7].iter().any(|&b| {
            let mut p = b;
            while p < g {
                p = p.saturating_mul(b);
            }
            p == g
        })
    }

    /// The first block of group `g`.
    fn group_start(&self, g: u64) -> u64 {
        self.first_data_block
            .saturating_add(g.saturating_mul(self.blocks_per_group))
    }

    /// Blocks in group `g` (the last may be short).
    fn group_blocks(&self, g: u64) -> u64 {
        self.blocks
            .saturating_sub(self.group_start(g))
            .min(self.blocks_per_group)
    }
}

/// A CRC-32C over several parts, starting from `seed` (no inversions, as
/// ext4's `ext4_chksum`).
fn csum32(seed: u32, parts: &[&[u8]]) -> u32 {
    parts.iter().fold(seed, |c, p| crc32c_update(c, p))
}

/// The checksum of group descriptor `g` (METADATA_CSUM or GDT_CSUM).
fn gd_checksum(fs: &Fs, g: u64, raw: &[u8]) -> Option<u16> {
    let group = u32::try_from(g).unwrap_or(u32::MAX).to_le_bytes();
    let head = raw.get(..0x1e).unwrap_or_default();
    let tail = raw.get(0x20..).unwrap_or_default();
    if let Some(seed) = fs.csum {
        let c = csum32(seed, &[&group, head, &[0, 0], tail]);
        return Some(u16::try_from(c & 0xffff).unwrap_or(0));
    }
    if fs.gdt_csum {
        let crc16 = crate::codec::crc::CRC16_ARC;
        let mut c = crc16.update(0xffff, &fs.uuid);
        c = crc16.update(c, &group);
        c = crc16.update(c, head);
        if fs.wide && raw.len() > 0x20 {
            c = crc16.update(c, tail);
        }
        return Some(u16::try_from(c & 0xffff).unwrap_or(0));
    }
    None
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, 1024);
    let sb = parse(&cx, span, LE, &(), Superblock::layout).await?;
    let raw = cx.read_avail(span).await?;
    let mut node = Superblock::node("Superblock", span, LE);
    if sb.ro_compat & 0x400 != 0 {
        let computed = crc32c_update(!0, raw.get(..1020).unwrap_or_default());
        node = if u32_le(&raw, 1020) == Some(computed) {
            node.summary("checksum valid")
        } else {
            node.diag(Diagnostic::warning(format!(
                "superblock checksum mismatch: computed {computed:#010x}"
            )))
        };
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
        "{kind} filesystem{}, {}, {}-byte blocks, {} inodes ({} free)",
        if label.is_empty() {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(blocks.saturating_mul(block)),
        block,
        sb.inodes,
        sb.free_inodes
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
        u64::from(sb.inode_size).clamp(128, block)
    };
    let gdt_block = u64::from(sb.first_data_block).saturating_add(1);
    let csum = (sb.ro_compat & 0x400 != 0).then(|| {
        if sb.incompat & 0x2000 != 0 {
            sb.checksum_seed
        } else {
            crc32c_update(!0, &sb.uuid)
        }
    });
    let backup_bgs = (sb.compat & 0x200 != 0).then(|| {
        [
            u64::from(u32_le(&sb.backup_bgs, 0).unwrap_or(0)),
            u64::from(u32_le(&sb.backup_bgs, 4).unwrap_or(0)),
        ]
    });
    let fs: FsRef = Arc::new(Fs {
        input,
        vol,
        block,
        first_data_block: sb.first_data_block.into(),
        blocks,
        blocks_per_group: sb.blocks_per_group.into(),
        inodes_per_group: sb.inodes_per_group.into(),
        inode_size,
        desc_size,
        gdt: vol.sub(
            gdt_block.saturating_mul(block),
            groups.saturating_mul(desc_size),
        ),
        groups,
        wide,
        filetype: sb.incompat & 2 != 0,
        csum,
        gdt_csum: sb.ro_compat & 0x10 != 0,
        uuid: sb.uuid.clone(),
        sparse_super: sb.ro_compat & 0x1 != 0,
        backup_bgs,
        reserved_gdt: sb.reserved_gdt_blocks.into(),
        meta_bg: sb.incompat & 0x10 != 0,
    });
    if block > SUPER.saturating_mul(2) || sb.first_data_block == 0 {
        cx.emit(
            Node::new("Boot area")
                .span(vol.sub(0, SUPER))
                .summary("1 KiB before the superblock, left for a boot loader"),
        );
    } else {
        cx.emit(
            Node::new("Boot block")
                .span(vol.sub(0, SUPER))
                .summary("block 0, left for a boot loader"),
        );
    }
    cx.emit(
        Node::new("Block group descriptors")
            .span(fs.gdt)
            .summary(format!("{groups} groups of {} blocks", sb.blocks_per_group))
            .lazy(group_descriptors, fs.clone()),
    );
    cx.emit(
        Node::new("Block groups")
            .summary(format!("{groups} groups"))
            .lazy(block_groups, fs.clone()),
    );
    cx.emit(Node::new("Root directory").summary("inode 2").lazy(
        crate::expander!(dir::directory: dir::Dir),
        dir::Dir {
            fs: fs.clone(),
            ino: ROOT_INODE,
            path: Path::new(),
        },
    ));
    if sb.compat & 4 != 0 && sb.journal_inode != 0 {
        cx.emit(
            Node::new("Journal")
                .summary(format!("inode {}", sb.journal_inode))
                .lazy(journal::journal, (fs.clone(), sb.journal_inode)),
        );
    }
    let mut special: Vec<(&'static str, u32)> = Vec::new();
    for (name, ino) in [
        ("Resize inode", if sb.compat & 0x10 != 0 { 7 } else { 0 }),
        ("User quota", sb.usr_quota),
        ("Group quota", sb.grp_quota),
        ("Project quota", sb.prj_quota),
        ("Orphan file", sb.orphan_file_inum),
        ("Snapshot", sb.snapshot_inum),
    ] {
        if ino != 0 {
            special.push((name, ino));
        }
    }
    if !special.is_empty() {
        cx.emit(
            Node::new("Special inodes")
                .summary(format!("{} inodes", special.len()))
                .lazy(special_inodes, (fs.clone(), Arc::new(special))),
        );
    }
    Ok(())
}

async fn special_inodes(cx: Cx, (fs, list): (FsRef, Arc<Vec<(&'static str, u32)>>)) -> Result<()> {
    for &(name, ino) in list.iter() {
        cx.push(
            Node::new(name)
                .summary(format!("inode {ino}"))
                .lazy(inode::view, (fs.clone(), ino)),
        )
        .await;
    }
    Ok(())
}

async fn group_descriptors(cx: Cx, fs: FsRef) -> Result<()> {
    cx.set_count(Count::Exact(fs.groups));
    for g in 0..fs.groups {
        let (span, d, raw) = fs.desc(&cx, g).await?;
        let first = fs.group_start(g);
        let computed = gd_checksum(&fs, g, &raw);
        let mut node = struct_node(
            format!("Group {g}"),
            span,
            LE,
            GdCtx {
                wide: fs.wide && fs.desc_size >= 64,
                csum: computed,
                block_bitmap_csum: None,
                inode_bitmap_csum: None,
            },
            gd_layout,
        )
        .summary(format!(
            "blocks {first}–{}, inode table at {}, {} free blocks, {} free inodes",
            first.saturating_add(fs.group_blocks(g)).saturating_sub(1),
            d.inode_table,
            d.free_blocks,
            d.free_inodes
        ));
        if let Some(c) = computed
            && u16_le(&raw, 0x1e) != Some(c)
        {
            node = node.diag(Diagnostic::warning("group descriptor checksum mismatch"));
        }
        cx.push(node).await;
    }
    let used = fs.groups.saturating_mul(fs.desc_size);
    let gdt_blocks = used.div_ceil(fs.block);
    let tail = fs.blocks_span(fs.first_data_block.saturating_add(1), gdt_blocks);
    if tail.len > used {
        cx.emit(
            Node::new("Unused")
                .span(tail.tail(used))
                .summary("rest of the descriptor table's last block"),
        );
    }
    Ok(())
}

async fn block_groups(cx: Cx, fs: FsRef) -> Result<()> {
    cx.set_count(Count::Exact(fs.groups));
    for g in 0..fs.groups {
        let first = fs.group_start(g);
        let span = fs.blocks_span(first, fs.group_blocks(g));
        cx.push(
            Node::new(format!("Group {g}"))
                .span(span)
                .summary(format!(
                    "blocks {first}–{}",
                    first.saturating_add(fs.group_blocks(g)).saturating_sub(1)
                ))
                .lazy(group, (fs.clone(), g)),
        )
        .await;
    }
    Ok(())
}

/// One block group: its backups, bitmaps, inode table and free space.
async fn group(cx: Cx, (fs, g): (FsRef, u64)) -> Result<()> {
    let (dspan, gd, raw) = fs.desc(&cx, g).await?;
    let wide = fs.wide && fs.desc_size >= 64;
    let first = fs.group_start(g);
    let gdt_blocks = fs.groups.saturating_mul(fs.desc_size).div_ceil(fs.block);
    if fs.has_super(g) && !fs.meta_bg {
        if g == 0 {
            cx.emit(
                Node::new("Superblock (primary)")
                    .span(fs.vol.sub(SUPER, 1024))
                    .summary("shown at the top level"),
            );
            cx.emit(
                Node::new("Group descriptors (primary)")
                    .span(fs.gdt)
                    .summary("shown at the top level"),
            );
        } else {
            cx.emit(Superblock::node(
                "Superblock (backup)",
                fs.vol.sub(first.saturating_mul(fs.block), 1024),
                LE,
            ));
            cx.emit(
                Node::new("Group descriptors (backup)")
                    .span(fs.blocks_span(first.saturating_add(1), gdt_blocks))
                    .summary(format!("{gdt_blocks} blocks")),
            );
        }
        if fs.reserved_gdt > 0 {
            cx.emit(
                Node::new("Reserved GDT blocks")
                    .span(fs.blocks_span(
                        first.saturating_add(1).saturating_add(gdt_blocks),
                        fs.reserved_gdt,
                    ))
                    .summary(format!("{} blocks for online resizing", fs.reserved_gdt)),
            );
        }
    }
    // Bitmaps, with their checksums.
    let bb_span = fs.block_span(gd.block_bitmap);
    let ib_span = fs.block_span(gd.inode_bitmap);
    let bb = cx.read_avail(bb_span).await?;
    let ib = cx.read_avail(ib_span).await?;
    let bb_csum = fs.csum.map(|seed| {
        csum32(
            seed,
            &[bb.get(..to_usize(fs.blocks_per_group / 8)).unwrap_or(&bb)],
        )
    });
    let ib_csum = fs.csum.map(|seed| {
        csum32(
            seed,
            &[ib.get(..to_usize(fs.inodes_per_group / 8)).unwrap_or(&ib)],
        )
    });
    cx.emit(struct_node(
        "Descriptor",
        dspan,
        LE,
        GdCtx {
            wide,
            csum: gd_checksum(&fs, g, &raw),
            block_bitmap_csum: bb_csum,
            inode_bitmap_csum: ib_csum,
        },
        gd_layout,
    ));
    let stored = |lo: usize, hi: usize| -> u32 {
        let lo = u32::from(u16_le(&raw, lo).unwrap_or(0));
        let hi = if wide {
            u32::from(u16_le(&raw, hi).unwrap_or(0))
        } else {
            0
        };
        hi << 16 | lo
    };
    let check = |computed: Option<u32>, lo: usize, hi: usize| -> Option<Diagnostic> {
        let c = computed?;
        let c = if wide { c } else { c & 0xffff };
        (stored(lo, hi) != c)
            .then(|| Diagnostic::warning(format!("bitmap checksum mismatch: computed {c:#x}")))
    };
    let block_uninit = gd.flags & 2 != 0;
    let mut bnode = Node::new("Block bitmap")
        .span(bb_span)
        .summary(if block_uninit {
            "not initialized (BLOCK_UNINIT)".to_owned()
        } else {
            format!("block {}, {} free", gd.block_bitmap, gd.free_blocks)
        });
    if !block_uninit && let Some(d) = check(bb_csum, 0x18, 0x38) {
        bnode = bnode.diag(d);
    }
    cx.emit(bnode);
    let mut inode_node = Node::new("Inode bitmap").span(ib_span).summary(format!(
        "block {}, {} free",
        gd.inode_bitmap, gd.free_inodes
    ));
    if gd.flags & 1 == 0
        && let Some(d) = check(ib_csum, 0x1a, 0x3a)
    {
        inode_node = inode_node.diag(d);
    }
    cx.emit(inode_node);
    let table = fs.vol.sub(
        gd.inode_table.saturating_mul(fs.block),
        fs.inodes_per_group.saturating_mul(fs.inode_size),
    );
    cx.emit(
        Node::new("Inode table")
            .span(table)
            .summary(format!(
                "blocks {}–{}, {} inodes",
                gd.inode_table,
                gd.inode_table
                    .saturating_add(table.len.div_ceil(fs.block))
                    .saturating_sub(1),
                fs.inodes_per_group
            ))
            .lazy(inode_table, (fs.clone(), g)),
    );
    if !block_uninit {
        cx.emit(
            Node::new("Free blocks")
                .summary(format!("{} blocks", gd.free_blocks))
                .lazy(free_blocks, (fs.clone(), g)),
        );
    }
    Ok(())
}

/// Lists a group's runs of free blocks from its block bitmap.
async fn free_blocks(cx: Cx, (fs, g): (FsRef, u64)) -> Result<()> {
    let (_, gd, _) = fs.desc(&cx, g).await?;
    let bitmap = cx.read(fs.block_span(gd.block_bitmap)).await?;
    let first = fs.group_start(g);
    let n = fs
        .group_blocks(g)
        .min(crate::bytes::to_u64(bitmap.len()).saturating_mul(8));
    let mut run: Option<u64> = None;
    for i in 0..=n {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let used = i == n || bitmap.get(to_usize(i / 8)).is_none() || bit_set(&bitmap, i);
        match (used, run) {
            (false, None) => run = Some(i),
            (true, Some(start)) => {
                run = None;
                let count = i.saturating_sub(start);
                let b = first.saturating_add(start);
                cx.push(
                    Node::new(format!(
                        "Blocks {b}–{}",
                        b.saturating_add(count).saturating_sub(1)
                    ))
                    .span(fs.blocks_span(b, count))
                    .summary(format!("free, {}", size(count.saturating_mul(fs.block)))),
                )
                .await;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Lists a group's inode table: in-use inodes as records, unused runs as
/// single nodes.
async fn inode_table(cx: Cx, (fs, g): (FsRef, u64)) -> Result<()> {
    let (_, gd, _) = fs.desc(&cx, g).await?;
    let table = fs.vol.sub(
        gd.inode_table.saturating_mul(fs.block),
        fs.inodes_per_group.saturating_mul(fs.inode_size),
    );
    let bitmap = if gd.flags & 1 != 0 {
        Vec::new()
    } else {
        cx.read_avail(fs.block_span(gd.inode_bitmap)).await?
    };
    let in_use = |i: u64| bit_set(&bitmap, i);
    let mut unused_from: Option<u64> = None;
    let flush = |from: u64, to: u64| {
        let span = table.sub(
            from.saturating_mul(fs.inode_size),
            to.saturating_sub(from).saturating_mul(fs.inode_size),
        );
        let base = g.saturating_mul(fs.inodes_per_group).saturating_add(1);
        Node::new(format!(
            "Inodes {}–{}",
            base.saturating_add(from),
            base.saturating_add(to).saturating_sub(1)
        ))
        .span(span)
        .summary(format!("{} unused", to.saturating_sub(from)))
        .desc("Free in the inode bitmap")
    };
    for i in 0..fs.inodes_per_group {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        if !in_use(i) {
            unused_from.get_or_insert(i);
            continue;
        }
        if let Some(from) = unused_from.take() {
            cx.push(flush(from, i)).await;
        }
        let ino = u32::try_from(
            g.saturating_mul(fs.inodes_per_group)
                .saturating_add(i)
                .saturating_add(1),
        )
        .unwrap_or(u32::MAX);
        cx.push(inode::record_node(&cx, &fs, ino).await).await;
    }
    if let Some(from) = unused_from {
        cx.push(flush(from, fs.inodes_per_group)).await;
    }
    Ok(())
}

/// A value node with a decimal integer.
fn uint(name: impl Into<std::borrow::Cow<'static, str>>, span: Span, value: u64, bits: u8) -> Node {
    Node::new(name).span(span).value(Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    })
}

/// The first `len` bytes of the next part of a cursor's block.
fn ahead<'a>(f: &Fields<'a>, len: u64) -> &'a [u8] {
    let data: &'a [u8] = &f.block().data;
    let pos = to_usize(f.pos());
    data.get(pos..pos.saturating_add(to_usize(len)))
        .unwrap_or_default()
}

/// Whether bit `i` (least significant first) of a bitmap is set.
fn bit_set(bitmap: &[u8], i: u64) -> bool {
    bitmap.get(to_usize(i / 8)).is_some_and(|b| {
        b.checked_shr(u32::try_from(i % 8).unwrap_or(0))
            .is_some_and(|v| v & 1 != 0)
    })
}
