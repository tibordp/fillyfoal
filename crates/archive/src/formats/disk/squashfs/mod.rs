//! SquashFS (version 4) filesystem images, and CramFS ([`cramfs`]).
//!
//! A 96-byte superblock locates the tables; optional compressor options
//! follow it. File data and fragment blocks come first, then the inode
//! and directory tables (sequences of metadata blocks: a 16-bit header,
//! then up to 8 KiB, compressed or not), then the fragment, export, ID and
//! xattr tables, each a small index of 64-bit pointers to its metadata
//! blocks. Metadata references are (block offset in the table << 16 |
//! offset in the decompressed block). The metadata tables are assembled
//! decompressed, so inodes and directories are read across block
//! boundaries; file content is assembled from its decompressed blocks and
//! its tail in a shared fragment block.

pub mod cramfs;

pub use cramfs::CRAMFS;

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::codec::decode_span;
use crate::cx::Cx;
use crate::dsl::{Path, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::disk::{PieceList, content_node, unix_mode};
use crate::formats::util::arcutil::unsupported;
use crate::formats::util::fmt;
use crate::formats::util::fmt::count;
use crate::formats::util::val::hex;
use crate::formats::{Codec, Format, Input, Probe, content};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag, lookup};

const LE: Endian = Endian::Little;
/// Metadata blocks walked per table before stopping.
const MAX_META_BLOCKS: u64 = 1 << 20;
/// A metadata block's decompressed size (all but a table's last).
const META_SIZE: u64 = 8192;
/// Directory nesting followed.
const MAX_DEPTH: usize = 64;
/// Directory bytes read at most.
const MAX_DIR_BYTES: u64 = 16 << 20;
/// Blocks of one file listed at most.
const MAX_FILE_BLOCKS: u64 = 1 << 20;

pub static SQUASHFS: Format = Format {
    name: "squashfs",
    title: "SquashFS filesystem",
    extensions: &["squashfs", "sqfs", "snap", "sfs"],
    mime: "application/vnd.squashfs",
    probe: Probe::Magic(&[(0, b"hsqs"), (0, b"sqsh")]),
    dissect: crate::expander!(dissect_squashfs: Input),
};

const COMPRESSOR: EnumTable = &[
    (1, "gzip"),
    (2, "LZMA"),
    (3, "LZO"),
    (4, "xz"),
    (5, "LZ4"),
    (6, "zstd"),
];

const SQ_FLAGS: FlagTable = &[
    flag(0x0001, "UNCOMPRESSED_INODES"),
    flag(0x0002, "UNCOMPRESSED_DATA"),
    flag(0x0004, "CHECK"),
    flag(0x0008, "UNCOMPRESSED_FRAGMENTS"),
    flag(0x0010, "NO_FRAGMENTS"),
    flag(0x0020, "ALWAYS_FRAGMENTS"),
    flag(0x0040, "DUPLICATES"),
    flag(0x0080, "EXPORTABLE"),
    flag(0x0100, "UNCOMPRESSED_XATTRS"),
    flag(0x0200, "NO_XATTRS"),
    flag(0x0400, "COMPRESSOR_OPTIONS"),
    flag(0x0800, "UNCOMPRESSED_IDS"),
];

const INODE_TYPES: EnumTable = &[
    (1, "directory"),
    (2, "regular file"),
    (3, "symbolic link"),
    (4, "block device"),
    (5, "character device"),
    (6, "FIFO"),
    (7, "socket"),
    (8, "directory (extended)"),
    (9, "regular file (extended)"),
    (10, "symbolic link (extended)"),
    (11, "block device (extended)"),
    (12, "character device (extended)"),
    (13, "FIFO (extended)"),
    (14, "socket (extended)"),
];

record! {
    pub struct Superblock {
        magic: ascii[4] "Magic",
        inodes: u32 "Inode count",
        mtime: u32 "Modification time" .timestamp(),
        block_size: u32 "Block size" .with(|&b, n| n.summary(fmt::size(b.into()))),
        fragments: u32 "Fragment count",
        compressor: u16 "Compression" .enumeration(COMPRESSOR),
        block_log: u16 "Block size (log2)",
        flags: u16 "Flags" .flags(SQ_FLAGS),
        ids: u16 "ID count",
        major: u16 "Major version",
        minor: u16 "Minor version",
        root: u64 "Root inode reference" .hex()
            .with(|&r, n| n.summary(format!("block {:#x}, offset {:#x}", r >> 16, r & 0xffff))),
        bytes_used: u64 "Bytes used" .with(|&b, n| n.summary(fmt::size(b))),
        id_table: u64 "ID table" .hex(),
        xattr_table: u64 "Xattr ID table" .hex(),
        inode_table: u64 "Inode table" .hex(),
        directory_table: u64 "Directory table" .hex(),
        fragment_table: u64 "Fragment table" .hex(),
        export_table: u64 "Export table" .hex(),
    }
}

const ABSENT: u64 = u64::MAX;

/// The image's parameters, shared by every expansion.
#[derive(Debug)]
struct Fs {
    input: Input,
    file: Span,
    codec: Option<Codec>,
    compressor: &'static str,
    block_size: u64,
    inode_table: u64,
    inode_end: u64,
    dir_table: u64,
    dir_end: u64,
    fragment_table: u64,
    fragments: u64,
    export_table: u64,
    inodes: u64,
    id_table: u64,
    ids: u64,
    xattr_table: u64,
}

type FsRef = Arc<Fs>;

pub async fn dissect_squashfs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    if magic == b"sqsh" {
        cx.emit(
            Node::new("Superblock")
                .span(file.sub(0, 96))
                .diag(Diagnostic::unsupported(
                    "big-endian (version 3 or older) SquashFS",
                )),
        );
        cx.annotate("SquashFS (big-endian, version 3 or older)");
        return Ok(());
    }
    let sb_span = file.sub(0, Superblock::SIZE);
    let sb = crate::fields::parse(&cx, sb_span, LE, &(), Superblock::layout).await?;
    cx.emit(
        Superblock::node("Superblock", sb_span, LE)
            .summary(format!("version {}.{}", sb.major, sb.minor)),
    );
    let codec = match sb.compressor {
        1 => Some(Codec::Zlib),
        // squashfs-tools' legacy LZMA: a 13-byte `.lzma` header per block.
        2 => Some(Codec::LzmaAlone),
        3 => Some(Codec::Lzo1x),
        4 => Some(Codec::Xz),
        5 => Some(Codec::Lz4Block),
        6 => Some(Codec::Zstd),
        _ => None,
    };
    let compressor = lookup(COMPRESSOR, sb.compressor.into()).unwrap_or("unknown");
    cx.annotate(format!(
        "SquashFS {}.{}, {compressor}, {}, {} blocks, {}",
        sb.major,
        sb.minor,
        count(sb.inodes, "inode", "inodes"),
        fmt::size(sb.block_size.into()),
        fmt::size(sb.bytes_used)
    ));
    if sb.major != 4 {
        return Err(Diagnostic::unsupported(format!(
            "SquashFS version {}.{}",
            sb.major, sb.minor
        )));
    }
    let mut data_start = Superblock::SIZE;
    if sb.flags & 0x0400 != 0 {
        let head = cx.read(file.sub(Superblock::SIZE, 2)).await?;
        let len = u64::from(u16_le(&head, 0).unwrap_or(0) & 0x7fff);
        let span = file.sub(Superblock::SIZE, len.saturating_add(2));
        cx.emit(
            struct_node(
                "Compressor options",
                span,
                LE,
                sb.compressor,
                compressor_options,
            )
            .summary(compressor),
        );
        data_start = data_start.saturating_add(span.len);
    }
    // The directory table ends where the first metadata block of a later
    // table starts (each table's index follows its blocks).
    let mut dir_end = sb.bytes_used;
    for (at, entries) in [
        (sb.fragment_table, u64::from(sb.fragments)),
        (sb.export_table, u64::from(sb.inodes)),
        (sb.id_table, u64::from(sb.ids)),
    ] {
        if at == ABSENT || entries == 0 {
            continue;
        }
        let first = cx.read_avail(file.sub(at, 8)).await?;
        if let Some(p) = u64_le(&first, 0) {
            dir_end = dir_end.min(p);
        }
    }
    if sb.xattr_table != ABSENT {
        let head = cx.read_avail(file.sub(sb.xattr_table, 8)).await?;
        if let Some(p) = u64_le(&head, 0) {
            dir_end = dir_end.min(p);
        }
    }
    let fs: FsRef = Arc::new(Fs {
        input,
        file,
        codec,
        compressor,
        block_size: sb.block_size.into(),
        inode_table: sb.inode_table,
        inode_end: sb.directory_table,
        dir_table: sb.directory_table,
        dir_end,
        fragment_table: sb.fragment_table,
        fragments: sb.fragments.into(),
        export_table: sb.export_table,
        inodes: sb.inodes.into(),
        id_table: sb.id_table,
        ids: sb.ids.into(),
        xattr_table: sb.xattr_table,
    });
    let data = file.sub(data_start, sb.inode_table.saturating_sub(data_start));
    cx.emit(
        Node::new("Data and fragment blocks")
            .span(data)
            .summary(format!("{}, {compressor}", fmt::size(data.len))),
    );
    cx.emit(
        Node::new("Inode table")
            .span(file.sub(fs.inode_table, fs.inode_end.saturating_sub(fs.inode_table)))
            .summary(fmt::size(fs.inode_end.saturating_sub(fs.inode_table)))
            .lazy(inode_table, fs.clone()),
    );
    cx.emit(
        Node::new("Directory table")
            .span(file.sub(fs.dir_table, fs.dir_end.saturating_sub(fs.dir_table)))
            .summary(fmt::size(fs.dir_end.saturating_sub(fs.dir_table)))
            .lazy(dir_table, fs.clone()),
    );
    for (name, at, n, kind) in [
        (
            "Fragment table",
            sb.fragment_table,
            fs.fragments,
            Lookup::Fragments,
        ),
        ("Export table", sb.export_table, fs.inodes, Lookup::Export),
        ("ID table", sb.id_table, fs.ids, Lookup::Ids),
    ] {
        if at == ABSENT || at >= sb.bytes_used || n == 0 {
            continue;
        }
        let index_len = n
            .saturating_mul(kind.entry_size())
            .div_ceil(META_SIZE)
            .saturating_mul(8);
        cx.emit(
            Node::new(name)
                .span(file.sub(at, index_len))
                .summary(format!("{n} entries"))
                .lazy(lookup_table, (fs.clone(), kind)),
        );
    }
    if sb.xattr_table != ABSENT && sb.xattr_table < sb.bytes_used {
        cx.emit(
            Node::new("Xattr tables")
                .span(file.sub(sb.xattr_table, 16))
                .lazy(xattr_tables, fs.clone()),
        );
    }
    cx.emit(Node::new("Root directory").lazy(
        crate::expander!(self::directory: DirState),
        DirState {
            fs: fs.clone(),
            iref: sb.root,
            path: Path::new(),
        },
    ));
    if sb.bytes_used < file.len {
        cx.emit(
            Node::new("Padding")
                .span(file.tail(sb.bytes_used))
                .summary("to the device block size"),
        );
    }
    Ok(())
}

fn compressor_options(f: &mut Fields<'_>, compressor: &u16) -> Result<()> {
    f.u16("Metadata header")
        .hex()
        .with(|&h, n| {
            n.summary(format!(
                "{} bytes, {}",
                h & 0x7fff,
                if h & 0x8000 != 0 {
                    "uncompressed"
                } else {
                    "compressed"
                }
            ))
        })
        .emit()?;
    match compressor {
        1 => {
            f.u32("Compression level").emit()?;
            f.u16("Window size").emit()?;
            f.u16("Strategies").hex().emit()?;
        }
        3 => {
            f.u32("Algorithm").emit()?;
            f.u32("Compression level").emit()?;
        }
        4 => {
            f.u32("Dictionary size")
                .with(|&d, n| n.summary(fmt::size(d.into())))
                .emit()?;
            f.u32("Executable filters").hex().emit()?;
        }
        5 => {
            f.u32("Version").emit()?;
            f.u32("Flags").hex().emit()?;
        }
        6 => {
            f.u32("Compression level").emit()?;
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Metadata tables

/// A run of metadata blocks, decompressed and assembled.
#[derive(Debug)]
struct Table {
    /// (offset of the block from the table start, offset in `decoded`).
    blocks: Vec<(u64, u64)>,
    decoded: Span,
}

impl Table {
    /// The position in `decoded` of a metadata reference.
    fn locate(&self, mref: u64) -> Option<u64> {
        let block = mref >> 16;
        let offset = mref & 0xffff;
        let i = self.blocks.partition_point(|&(b, _)| b < block);
        let &(b, at) = self.blocks.get(i)?;
        (b == block).then(|| at.saturating_add(offset))
    }
}

/// One metadata block: its span (header included), payload and decoded
/// bytes.
async fn meta_block(cx: &Cx, fs: &Fs, at: u64, last: bool) -> Result<(Span, Span)> {
    let head = cx.read(fs.file.sub(at, 2)).await?;
    let h = u16_le(&head, 0).unwrap_or(0);
    let len = u64::from(h & 0x7fff);
    let block = fs
        .file
        .sub_exact(at, len.saturating_add(2))
        .map_err(|d| d.at(fs.file.sub(at, 2)))?;
    let payload = block.tail(2);
    if h & 0x8000 != 0 || len == 0 {
        return Ok((block, payload));
    }
    let Some(codec) = &fs.codec else {
        return Err(Diagnostic::unsupported(format!("{} compression", fs.compressor)).at(payload));
    };
    let decoded = if last {
        decode_span(cx, payload, codec, None).await?.span
    } else {
        cx.decode_lazy(payload, codec, META_SIZE)?
    };
    Ok((block, decoded))
}

/// The metadata blocks from `start` to `end`, assembled (cached).
async fn table(cx: &Cx, fs: &Fs, start: u64, end: u64) -> Result<Arc<Table>> {
    let region = fs.file.sub(start, end.saturating_sub(start));
    if let Some(t) = cx.cached::<Table>(region, "squashfs-table") {
        return Ok(t);
    }
    let mut blocks = Vec::new();
    let mut list = PieceList::new(region);
    let mut at = start;
    while at.saturating_add(2) <= end && to_u64(blocks.len()) < MAX_META_BLOCKS {
        let head = cx.read(fs.file.sub(at, 2)).await?;
        let len = u64::from(u16_le(&head, 0).unwrap_or(0) & 0x7fff);
        let next = at.saturating_add(2).saturating_add(len);
        let (_, decoded) = meta_block(cx, fs, at, next.saturating_add(2) > end).await?;
        blocks.push((at.saturating_sub(start), list.len()));
        list.data(decoded);
        if len == 0 {
            break;
        }
        at = next;
    }
    let decoded = list.finish(cx, "squashfs-metadata").await?;
    let t = Arc::new(Table { blocks, decoded });
    cx.cache(region, "squashfs-table", t.clone());
    Ok(t)
}

/// Lists the metadata blocks of a table with their decompressed content.
async fn meta_blocks(cx: &Cx, fs: &FsRef, start: u64, end: u64) -> Result<()> {
    let mut at = start;
    let mut index = 0u64;
    while at.saturating_add(2) <= end && index < MAX_META_BLOCKS {
        let head = cx.read(fs.file.sub(at, 2)).await?;
        let h = u16_le(&head, 0).unwrap_or(0);
        let len = u64::from(h & 0x7fff);
        let stored = h & 0x8000 != 0;
        let block = fs.file.sub(at, len.saturating_add(2));
        let payload = block.tail(2);
        let child = if stored {
            Node::new("Data").span(payload).summary("stored")
        } else if let Some(codec) = &fs.codec {
            content("Data", fs.input, payload, codec.clone(), None)
        } else {
            unsupported("Data", payload, fs.compressor)
        };
        cx.progress_in(fs.file, fs.file.offset.saturating_add(at));
        cx.push(
            Node::new(format!("Metadata block {index}"))
                .span(block)
                .value(hex(h, 64))
                .summary(format!(
                    "{}, {}",
                    fmt::size(len),
                    if stored {
                        "uncompressed"
                    } else {
                        fs.compressor
                    }
                ))
                .lazy(
                    crate::formats::util::arcutil::emit_nodes,
                    Arc::new(vec![child]),
                ),
        )
        .await;
        if len == 0 {
            break;
        }
        at = at.saturating_add(len).saturating_add(2);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn inode_table(cx: Cx, fs: FsRef) -> Result<()> {
    cx.emit(
        Node::new("Metadata blocks")
            .summary(fs.compressor)
            .lazy(table_blocks, (fs.clone(), fs.inode_table, fs.inode_end)),
    );
    cx.emit(
        Node::new("Inodes")
            .summary(count(fs.inodes, "inode", "inodes"))
            .lazy(inode_list, fs.clone()),
    );
    Ok(())
}

async fn dir_table(cx: Cx, fs: FsRef) -> Result<()> {
    meta_blocks(&cx, &fs, fs.dir_table, fs.dir_end).await
}

async fn table_blocks(cx: Cx, (fs, start, end): (FsRef, u64, u64)) -> Result<()> {
    meta_blocks(&cx, &fs, start, end).await
}

// ---------------------------------------------------------------------------
// Inodes

#[derive(Clone, Debug)]
struct Inode {
    kind: u16,
    mode: u16,
    /// The inode's bytes in the decoded inode table.
    span: Span,
    start_block: u64,
    file_size: u64,
    fragment: u32,
    frag_offset: u32,
    /// The block list (in the decoded inode table) and its length.
    block_list: Span,
    blocks: u64,
    xattr: u32,
    /// Directory: offset in its first directory block, parent inode.
    dir_offset: u64,
    nlink: u32,
    target: Vec<u8>,
    rdev: u32,
}

impl Inode {
    fn is_dir(&self) -> bool {
        matches!(self.kind, 1 | 8)
    }

    fn is_file(&self) -> bool {
        matches!(self.kind, 2 | 9)
    }

    fn summary(&self) -> String {
        let what = lookup(INODE_TYPES, self.kind.into()).unwrap_or("unknown type");
        let mut s = if self.is_file() || self.is_dir() {
            format!(
                "{}, {what}, {}",
                unix_mode(self.mode.into()),
                fmt::size(self.file_size)
            )
        } else if matches!(self.kind, 4 | 5 | 11 | 12) {
            format!(
                "{}, {what}, {}",
                unix_mode(self.mode.into()),
                device_summary(self.rdev)
            )
        } else {
            format!("{}, {what}", unix_mode(self.mode.into()))
        };
        if self.nlink > 1 && !self.is_dir() {
            s.push_str(&format!(", {} links", self.nlink));
        }
        s
    }
}

/// Reads the inode at `pos` of the decoded inode table.
async fn read_inode(cx: &Cx, fs: &Fs, t: &Table, pos: u64) -> Result<Inode> {
    let src = t.decoded;
    let head = cx.read_avail(src.sub(pos, 64)).await?;
    if head.len() < 16 {
        return Err(Diagnostic::malformed(format!(
            "inode at {pos:#x} runs past the inode table"
        )));
    }
    let kind = u16_le(&head, 0).unwrap_or(0);
    let mut ino = Inode {
        kind,
        mode: u16_le(&head, 2).unwrap_or(0),
        span: src.sub(pos, 0),
        start_block: 0,
        file_size: 0,
        fragment: u32::MAX,
        frag_offset: 0,
        block_list: src.sub(pos, 0),
        blocks: 0,
        xattr: u32::MAX,
        dir_offset: 0,
        nlink: 0,
        target: Vec::new(),
        rdev: 0,
    };
    let u32_at = |at: usize| u32_le(&head, at).unwrap_or(0);
    let len: u64 = match kind {
        1 => {
            ino.start_block = u32_at(16).into();
            ino.nlink = u32_at(20);
            ino.file_size = u16_le(&head, 24).unwrap_or(0).into();
            ino.dir_offset = u16_le(&head, 26).unwrap_or(0).into();
            32
        }
        8 => {
            ino.nlink = u32_at(16);
            ino.file_size = u32_at(20).into();
            ino.start_block = u32_at(24).into();
            let index_count = u64::from(u16_le(&head, 32).unwrap_or(0));
            ino.dir_offset = u16_le(&head, 34).unwrap_or(0).into();
            ino.xattr = u32_at(36);
            // Directory index entries: 12 bytes and a name each.
            let mut at = pos.saturating_add(40);
            for _ in 0..index_count.min(65536) {
                let e = cx.read(src.sub(at, 12)).await?;
                let name_len = u64::from(u32_le(&e, 8).unwrap_or(0)).saturating_add(1);
                at = at.saturating_add(12).saturating_add(name_len);
            }
            at.saturating_sub(pos)
        }
        2 | 9 => {
            let (start, size, frag, offset, list_at) = if kind == 2 {
                (
                    u64::from(u32_at(16)),
                    u64::from(u32_at(28)),
                    u32_at(20),
                    u32_at(24),
                    32u64,
                )
            } else {
                ino.nlink = u32_at(40);
                ino.xattr = u32_at(52);
                (
                    u64_le(&head, 16).unwrap_or(0),
                    u64_le(&head, 24).unwrap_or(0),
                    u32_at(44),
                    u32_at(48),
                    56u64,
                )
            };
            if kind == 2 {
                ino.nlink = 1;
            }
            ino.start_block = start;
            ino.file_size = size;
            ino.fragment = frag;
            ino.frag_offset = offset;
            let bs = fs.block_size.max(1);
            ino.blocks = if frag == u32::MAX {
                size.div_ceil(bs)
            } else {
                size.checked_div(bs).unwrap_or(0)
            }
            .min(MAX_FILE_BLOCKS);
            ino.block_list = src.sub(pos.saturating_add(list_at), ino.blocks.saturating_mul(4));
            list_at.saturating_add(ino.blocks.saturating_mul(4))
        }
        3 | 10 => {
            ino.nlink = u32_at(16);
            let target_len = u64::from(u32_at(20)).min(65536);
            ino.target = cx.read(src.sub(pos.saturating_add(24), target_len)).await?;
            if kind == 10 {
                let x = cx
                    .read(src.sub(pos.saturating_add(24).saturating_add(target_len), 4))
                    .await?;
                ino.xattr = u32_le(&x, 0).unwrap_or(u32::MAX);
            }
            24u64
                .saturating_add(target_len)
                .saturating_add(if kind == 10 { 4 } else { 0 })
        }
        4 | 5 | 11 | 12 => {
            ino.nlink = u32_at(16);
            ino.rdev = u32_at(20);
            if kind >= 11 {
                ino.xattr = u32_at(24);
                28
            } else {
                24
            }
        }
        6 | 7 | 13 | 14 => {
            ino.nlink = u32_at(16);
            if kind >= 13 {
                ino.xattr = u32_at(20);
                24
            } else {
                20
            }
        }
        other => {
            return Err(Diagnostic::malformed(format!("inode type {other}")).at(src.sub(pos, 2)));
        }
    };
    ino.span = src.sub(pos, len);
    Ok(ino)
}

fn device_summary(v: u32) -> String {
    let major = (v >> 8) & 0xfff;
    let minor = (v & 0xff) | ((v >> 12) & 0xf_ff00);
    format!("major {major}, minor {minor}")
}

#[derive(Clone)]
struct InodeCtx {
    kind: u16,
    block_size: u64,
}

fn inode_layout(f: &mut Fields<'_>, ctx: &InodeCtx) -> Result<()> {
    f.u16("Type").enumeration(INODE_TYPES).emit()?;
    f.u16("Mode")
        .hex()
        .with(|&m, n| n.summary(unix_mode(m.into())))
        .emit()?;
    f.u16("Owner (ID index)").emit()?;
    f.u16("Group (ID index)").emit()?;
    f.u32("Modified").timestamp().emit()?;
    f.u32("Inode number").emit()?;
    match ctx.kind {
        1 => {
            f.u32("Directory block").emit()?;
            f.u32("Links").emit()?;
            f.u16("Size")
                .desc("Bytes of directory listing, plus 3")
                .emit()?;
            f.u16("Offset in directory block").emit()?;
            f.u32("Parent inode").emit()?;
        }
        8 => {
            f.u32("Links").emit()?;
            f.u32("Size")
                .desc("Bytes of directory listing, plus 3")
                .emit()?;
            f.u32("Directory block").emit()?;
            f.u32("Parent inode").emit()?;
            let n = f.u16("Index entries").emit()?;
            f.u16("Offset in directory block").emit()?;
            xattr_field(f)?;
            for _ in 0..n {
                if f.remaining() < 12 {
                    break;
                }
                let name_len = u64::from(
                    u32_le(&f.block().data, to_usize(f.pos()).saturating_add(8)).unwrap_or(0),
                )
                .saturating_add(1);
                f.node(struct_node(
                    "Index entry",
                    f.peek_span(12u64.saturating_add(name_len)),
                    LE,
                    (),
                    dir_index_layout,
                ));
                f.skip(12u64.saturating_add(name_len));
            }
        }
        2 | 9 => {
            let (size, frag) = if ctx.kind == 2 {
                f.u32("First block").hex().emit()?;
                let frag = f
                    .u32("Fragment")
                    .with(|&v, n| if v == u32::MAX { n.summary("none") } else { n })
                    .emit()?;
                f.u32("Offset in fragment").emit()?;
                let size = f
                    .u32("Size")
                    .with(|&v, n| n.summary(fmt::size(v.into())))
                    .emit()?;
                (u64::from(size), frag)
            } else {
                f.u64("First block").hex().emit()?;
                let size = f.u64("Size").with(|&v, n| n.summary(fmt::size(v))).emit()?;
                f.u64("Sparse bytes").emit()?;
                f.u32("Links").emit()?;
                let frag = f
                    .u32("Fragment")
                    .with(|&v, n| if v == u32::MAX { n.summary("none") } else { n })
                    .emit()?;
                f.u32("Offset in fragment").emit()?;
                xattr_field(f)?;
                (size, frag)
            };
            let bs = ctx.block_size.max(1);
            let blocks = if frag == u32::MAX {
                size.div_ceil(bs)
            } else {
                size.checked_div(bs).unwrap_or(0)
            };
            let len = blocks.saturating_mul(4).min(f.remaining());
            if len > 0 {
                f.node(
                    Node::new("Block sizes")
                        .span(f.peek_span(len))
                        .summary(count(blocks, "block", "blocks"))
                        .lazy(block_sizes, f.peek_span(len)),
                );
                f.skip(len);
            }
        }
        3 | 10 => {
            f.u32("Links").emit()?;
            let n = f.u32("Target size").emit()?;
            f.bytes("Target", n.into())
                .with(|b, node| node.value(Value::Text(String::from_utf8_lossy(b).into_owned())))
                .emit()?;
            if ctx.kind == 10 {
                xattr_field(f)?;
            }
        }
        4 | 5 | 11 | 12 => {
            f.u32("Links").emit()?;
            f.u32("Device")
                .hex()
                .with(|&v, n| n.summary(device_summary(v)))
                .emit()?;
            if ctx.kind >= 11 {
                xattr_field(f)?;
            }
        }
        6 | 7 | 13 | 14 => {
            f.u32("Links").emit()?;
            if ctx.kind >= 13 {
                xattr_field(f)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn xattr_field(f: &mut Fields<'_>) -> Result<()> {
    f.u32("Xattr index")
        .with(|&v, n| if v == u32::MAX { n.summary("none") } else { n })
        .emit()?;
    Ok(())
}

fn dir_index_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Listing offset").emit()?;
    f.u32("Directory block").emit()?;
    let n = f.u32("Name size").desc("Name length minus one").emit()?;
    f.bytes("Name", u64::from(n).saturating_add(1))
        .with(|b, node| node.value(Value::Text(String::from_utf8_lossy(b).into_owned())))
        .emit()?;
    Ok(())
}

async fn block_sizes(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, w) in data.as_chunks::<4>().0.iter().enumerate() {
        let v = u32::from_le_bytes(*w);
        let summary = if v == 0 {
            "sparse (a block of zeros)".to_owned()
        } else {
            format!(
                "{}, {}",
                fmt::size((v & 0x00ff_ffff).into()),
                if v & 0x0100_0000 != 0 {
                    "uncompressed"
                } else {
                    "compressed"
                }
            )
        };
        cx.push(
            Node::new(format!("Block {i}"))
                .span(span.sub(to_u64(i).saturating_mul(4), 4))
                .value(Value::UInt {
                    value: v.into(),
                    bits: 32,
                    radix: Radix::Hex,
                })
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

/// Lists the inode table in order.
async fn inode_list(cx: Cx, fs: FsRef) -> Result<()> {
    let t = table(&cx, &fs, fs.inode_table, fs.inode_end).await?;
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < t.decoded.len && index < fs.inodes.max(1).saturating_mul(2) {
        cx.progress(pos, t.decoded.len);
        let ino = match read_inode(&cx, &fs, &t, pos).await {
            Ok(i) => i,
            Err(d) => {
                cx.diag(d);
                break;
            }
        };
        let at = (pos, index);
        cx.mark(move || at);
        cx.push(inode_node(
            &fs,
            &ino,
            format!("Inode {}", index.saturating_add(1)),
        ))
        .await;
        if ino.span.len == 0 {
            break;
        }
        pos = pos.saturating_add(ino.span.len);
        index = index.saturating_add(1);
    }
    Ok(())
}

fn inode_node(fs: &FsRef, ino: &Inode, name: String) -> Node {
    struct_node(
        name,
        ino.span,
        LE,
        InodeCtx {
            kind: ino.kind,
            block_size: fs.block_size,
        },
        inode_layout,
    )
    .summary(ino.summary())
}

// ---------------------------------------------------------------------------
// Directories and files

#[derive(Clone)]
struct DirState {
    fs: FsRef,
    iref: u64,
    path: Path,
}

struct DirEnt {
    name: Vec<u8>,
    iref: u64,
    number: u64,
    kind: u16,
    span: Span,
}

/// The entries of a directory listing.
async fn dir_entries(cx: &Cx, listing: Span) -> Result<(Vec<DirEnt>, Option<Diagnostic>)> {
    let data = cx.read_avail(listing).await?;
    let mut out = Vec::new();
    let mut at = 0usize;
    while at.saturating_add(12) <= data.len() {
        let n = u64::from(u32_le(&data, at).unwrap_or(0)).saturating_add(1);
        let block = u64::from(u32_le(&data, at.saturating_add(4)).unwrap_or(0));
        let base = u64::from(u32_le(&data, at.saturating_add(8)).unwrap_or(0));
        at = at.saturating_add(12);
        if n > 256 {
            return Ok((
                out,
                Some(Diagnostic::malformed(format!(
                    "directory header claims {n} entries"
                ))),
            ));
        }
        for _ in 0..n {
            let Some(e) = data.get(at..at.saturating_add(8)) else {
                return Ok((
                    out,
                    Some(Diagnostic::malformed("directory entry truncated")),
                ));
            };
            let offset = u64::from(u16_le(e, 0).unwrap_or(0));
            let delta = i64::from(i16::from_le_bytes([
                e.get(2).copied().unwrap_or(0),
                e.get(3).copied().unwrap_or(0),
            ]));
            let kind = u16_le(e, 4).unwrap_or(0);
            let name_len = usize::from(u16_le(e, 6).unwrap_or(0)).saturating_add(1);
            let Some(name) =
                data.get(at.saturating_add(8)..at.saturating_add(8).saturating_add(name_len))
            else {
                return Ok((
                    out,
                    Some(Diagnostic::malformed("directory entry name truncated")),
                ));
            };
            let len = 8u64.saturating_add(to_u64(name_len));
            out.push(DirEnt {
                name: name.to_vec(),
                iref: block << 16 | offset,
                number: u64::try_from(i64::try_from(base).unwrap_or(0).saturating_add(delta))
                    .unwrap_or(0),
                kind,
                span: listing.sub(to_u64(at), len),
            });
            at = at.saturating_add(to_usize(len));
        }
    }
    Ok((out, None))
}

/// Lists a directory: its inode, then its entries.
async fn directory(cx: Cx, st: DirState) -> Result<()> {
    let fs = st.fs.clone();
    let it = table(&cx, &fs, fs.inode_table, fs.inode_end).await?;
    let pos = it
        .locate(st.iref)
        .ok_or_else(|| Diagnostic::malformed(format!("bad inode reference {:#x}", st.iref)))?;
    let ino = read_inode(&cx, &fs, &it, pos).await?;
    if !ino.is_dir() {
        return Err(Diagnostic::malformed("not a directory"));
    }
    cx.emit(inode_node(&fs, &ino, "Inode".to_owned()));
    if ino.xattr != u32::MAX {
        cx.emit(
            Node::new("Extended attributes")
                .summary(format!("index {}", ino.xattr))
                .lazy(xattr_list, (fs.clone(), ino.xattr)),
        );
    }
    let dt = table(&cx, &fs, fs.dir_table, fs.dir_end).await?;
    let start = dt
        .locate(ino.start_block << 16 | ino.dir_offset)
        .ok_or_else(|| Diagnostic::malformed("bad directory reference"))?;
    let listing = dt
        .decoded
        .sub(start, ino.file_size.saturating_sub(3).min(MAX_DIR_BYTES));
    let (entries, problem) = dir_entries(&cx, listing).await?;
    for e in entries {
        let what = lookup(INODE_TYPES, e.kind.into()).unwrap_or("unknown");
        let node = Node::new(String::from_utf8_lossy(&e.name).into_owned())
            .span(e.span)
            .value(Value::UInt {
                value: e.number,
                bits: 32,
                radix: Radix::Dec,
            })
            .summary(format!("{what}, inode {}", e.number));
        let node = if matches!(e.kind, 1 | 8) {
            match st.path.enter(e.iref, MAX_DEPTH) {
                Ok(path) => node.lazy(
                    crate::expander!(self::directory: DirState),
                    DirState {
                        fs: fs.clone(),
                        iref: e.iref,
                        path,
                    },
                ),
                Err(d) => node.diag(d),
            }
        } else {
            node.lazy(entry_view, (fs.clone(), e.iref))
        };
        cx.push(node).await;
    }
    if let Some(d) = problem {
        cx.diag(d.at(listing));
    }
    Ok(())
}

/// Shows a non-directory inode: its record and content.
async fn entry_view(cx: Cx, (fs, iref): (FsRef, u64)) -> Result<()> {
    let it = table(&cx, &fs, fs.inode_table, fs.inode_end).await?;
    let pos = it
        .locate(iref)
        .ok_or_else(|| Diagnostic::malformed(format!("bad inode reference {iref:#x}")))?;
    let ino = read_inode(&cx, &fs, &it, pos).await?;
    cx.annotate(ino.summary());
    cx.emit(inode_node(&fs, &ino, "Inode".to_owned()));
    if ino.xattr != u32::MAX {
        cx.emit(
            Node::new("Extended attributes")
                .summary(format!("index {}", ino.xattr))
                .lazy(xattr_list, (fs.clone(), ino.xattr)),
        );
    }
    if ino.is_file() {
        let data = file_content(&cx, &fs, &ino).await?;
        cx.emit(content_node(&fs.input, data));
    } else if matches!(ino.kind, 3 | 10) {
        cx.emit(Node::new("Target").value(Value::Text(
            String::from_utf8_lossy(&ino.target).into_owned(),
        )));
    }
    Ok(())
}

/// A fragment table entry: (start, size word).
async fn fragment_entry(cx: &Cx, fs: &Fs, index: u64) -> Result<(u64, u32)> {
    let (decoded, _) = lookup_decoded(cx, fs, Lookup::Fragments).await?;
    let raw = cx.read(decoded.sub(index.saturating_mul(16), 16)).await?;
    Ok((u64_le(&raw, 0).unwrap_or(0), u32_le(&raw, 8).unwrap_or(0)))
}

/// The decoded bytes of a data or fragment block.
async fn data_block(
    cx: &Cx,
    fs: &Fs,
    span: Span,
    word: u32,
    expected: u64,
    eager: bool,
) -> Result<Span> {
    if word & 0x0100_0000 != 0 {
        return Ok(span);
    }
    let Some(codec) = &fs.codec else {
        return Err(Diagnostic::unsupported(format!("{} compression", fs.compressor)).at(span));
    };
    if eager {
        Ok(decode_span(cx, span, codec, None).await?.span)
    } else {
        cx.decode_lazy(span, codec, expected)
    }
}

/// A file's content: its blocks decompressed, holes as zeros, and its tail
/// from a fragment block.
async fn file_content(cx: &Cx, fs: &Fs, ino: &Inode) -> Result<Span> {
    let words = cx.read(ino.block_list).await?;
    let mut list = PieceList::new(ino.span);
    let mut at = ino.start_block;
    for (i, w) in words.as_chunks::<4>().0.iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        let w = u32::from_le_bytes(*w);
        let expected = fs.block_size.min(
            ino.file_size
                .saturating_sub(to_u64(i).saturating_mul(fs.block_size)),
        );
        if w == 0 {
            list.hole(cx, expected)?;
            continue;
        }
        let len = u64::from(w & 0x00ff_ffff);
        let span = fs.file.sub(at, len);
        at = at.saturating_add(len);
        let decoded = data_block(cx, fs, span, w, expected, false).await?;
        list.data(decoded.sub(0, expected));
    }
    if ino.fragment != u32::MAX && list.len() < ino.file_size {
        let (start, word) = fragment_entry(cx, fs, ino.fragment.into()).await?;
        let span = fs.file.sub(start, u64::from(word & 0x00ff_ffff));
        let decoded = data_block(cx, fs, span, word, fs.block_size, true).await?;
        let tail = ino.file_size.saturating_sub(list.len());
        list.data(decoded.sub(ino.frag_offset.into(), tail));
    }
    if list.len() < ino.file_size {
        list.hole(cx, ino.file_size.saturating_sub(list.len()))?;
    }
    list.finish(cx, "squashfs-file").await
}

// ---------------------------------------------------------------------------
// Lookup tables (fragments, exports, IDs) and xattrs

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lookup {
    Fragments,
    Export,
    Ids,
    XattrIds,
}

impl Lookup {
    fn entry_size(self) -> u64 {
        match self {
            Lookup::Fragments | Lookup::XattrIds => 16,
            Lookup::Export => 8,
            Lookup::Ids => 4,
        }
    }
}

/// A lookup table's index position and entry count.
async fn lookup_place(cx: &Cx, fs: &Fs, kind: Lookup) -> Result<(u64, u64)> {
    Ok(match kind {
        Lookup::Fragments => (fs.fragment_table, fs.fragments),
        Lookup::Export => (fs.export_table, fs.inodes),
        Lookup::Ids => (fs.id_table, fs.ids),
        Lookup::XattrIds => {
            let head = cx.read(fs.file.sub(fs.xattr_table, 16)).await?;
            (
                fs.xattr_table.saturating_add(16),
                u64::from(u32_le(&head, 8).unwrap_or(0)),
            )
        }
    })
}

/// A lookup table's entries, decoded and assembled, and its index entries'
/// pointers.
async fn lookup_decoded(cx: &Cx, fs: &Fs, kind: Lookup) -> Result<(Span, Vec<u64>)> {
    let (index_at, n) = lookup_place(cx, fs, kind).await?;
    let bytes = n.saturating_mul(kind.entry_size());
    let blocks = bytes.div_ceil(META_SIZE);
    let index = fs
        .file
        .sub_exact(index_at, blocks.saturating_mul(8))
        .map_err(|d| d.at(fs.file.sub(index_at, 8)))?;
    if let Some(found) = cx.cached::<(Span, Vec<u64>)>(index, "squashfs-lookup") {
        return Ok((found.0, found.1.clone()));
    }
    let raw = cx.read(index).await?;
    let mut ptrs = Vec::new();
    let mut list = PieceList::new(index);
    for (i, p) in raw.as_chunks::<8>().0.iter().enumerate() {
        let p = u64::from_le_bytes(*p);
        ptrs.push(p);
        let last = to_u64(i).saturating_add(1) == blocks;
        let (_, decoded) = meta_block(cx, fs, p, last).await?;
        list.data(decoded);
    }
    let decoded = list.finish(cx, "squashfs-lookup").await?.sub(0, bytes);
    cx.cache(index, "squashfs-lookup", Arc::new((decoded, ptrs.clone())));
    Ok((decoded, ptrs))
}

fn fragment_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Start").hex().emit()?;
    f.u32("Size")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}, {}",
                fmt::size((v & 0x00ff_ffff).into()),
                if v & 0x0100_0000 != 0 {
                    "uncompressed"
                } else {
                    "compressed"
                }
            ))
        })
        .emit()?;
    f.u32("Unused").emit()?;
    Ok(())
}

fn xattr_id_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Reference")
        .hex()
        .with(|&r, n| n.summary(format!("block {:#x}, offset {:#x}", r >> 16, r & 0xffff)))
        .emit()?;
    f.u32("Count").emit()?;
    f.u32("Size").emit()?;
    Ok(())
}

async fn lookup_table(cx: Cx, (fs, kind): (FsRef, Lookup)) -> Result<()> {
    let (index_at, n) = lookup_place(&cx, &fs, kind).await?;
    let (decoded, ptrs) = lookup_decoded(&cx, &fs, kind).await?;
    for (i, p) in ptrs.iter().enumerate() {
        let span = fs
            .file
            .sub(index_at.saturating_add(to_u64(i).saturating_mul(8)), 8);
        let head = cx.read_avail(fs.file.sub(*p, 2)).await?;
        let len = u64::from(u16_le(&head, 0).unwrap_or(0) & 0x7fff);
        let block = fs.file.sub(*p, len.saturating_add(2));
        let payload = block.tail(2);
        let stored = u16_le(&head, 0).unwrap_or(0) & 0x8000 != 0;
        let child = if stored {
            Node::new("Data").span(payload)
        } else if let Some(codec) = &fs.codec {
            content("Data", fs.input, payload, codec.clone(), None)
        } else {
            unsupported("Data", payload, fs.compressor)
        };
        cx.emit(
            Node::new(format!("Index {i}"))
                .span(span)
                .value(hex(*p, 64))
                .summary(format!("metadata block at {p:#x}"))
                .lazy(
                    crate::formats::util::arcutil::emit_nodes,
                    Arc::new(vec![
                        Node::new("Metadata block")
                            .span(block)
                            .summary(fmt::size(len))
                            .lazy(
                                crate::formats::util::arcutil::emit_nodes,
                                Arc::new(vec![child]),
                            ),
                    ]),
                ),
        );
    }
    cx.emit(
        Node::new("Entries")
            .span(decoded)
            .summary(format!("{n} entries"))
            .lazy(lookup_entries, (fs.clone(), kind, decoded)),
    );
    Ok(())
}

async fn lookup_entries(cx: Cx, (fs, kind, decoded): (FsRef, Lookup, Span)) -> Result<()> {
    let size = kind.entry_size();
    let n = decoded.len.checked_div(size).unwrap_or(0);
    for i in 0..n {
        let span = decoded.sub(i.saturating_mul(size), size);
        let node = match kind {
            Lookup::Fragments => {
                let raw = cx.read(span).await?;
                let start = u64_le(&raw, 0).unwrap_or(0);
                let word = u32_le(&raw, 8).unwrap_or(0);
                let block = fs.file.sub(start, (word & 0x00ff_ffff).into());
                let node = struct_node(format!("Fragment {i}"), span, LE, (), fragment_layout)
                    .summary(format!("{} at {start:#x}", fmt::size(block.len)));
                cx.push(node).await;
                cx.push(if word & 0x0100_0000 != 0 {
                    Node::new(format!("Fragment block {i}"))
                        .span(block)
                        .summary("stored")
                } else if let Some(codec) = &fs.codec {
                    content(
                        format!("Fragment block {i}"),
                        fs.input,
                        block,
                        codec.clone(),
                        None,
                    )
                } else {
                    unsupported(format!("Fragment block {i}"), block, fs.compressor)
                })
                .await;
                continue;
            }
            Lookup::Export => {
                let raw = cx.read(span).await?;
                let r = u64_le(&raw, 0).unwrap_or(0);
                Node::new(format!("Inode {}", i.saturating_add(1)))
                    .span(span)
                    .value(hex(r, 64))
                    .summary(format!("block {:#x}, offset {:#x}", r >> 16, r & 0xffff))
            }
            Lookup::Ids => {
                let raw = cx.read(span).await?;
                Node::new(format!("ID {i}")).span(span).value(Value::UInt {
                    value: u32_le(&raw, 0).unwrap_or(0).into(),
                    bits: 32,
                    radix: Radix::Dec,
                })
            }
            Lookup::XattrIds => struct_node(format!("Xattr ID {i}"), span, LE, (), xattr_id_layout),
        };
        cx.push(node).await;
    }
    Ok(())
}

fn xattr_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Key/value table").hex().emit()?;
    f.u32("Xattr IDs").emit()?;
    f.u32("Unused").emit()?;
    Ok(())
}

async fn xattr_tables(cx: Cx, fs: FsRef) -> Result<()> {
    let head = cx.read(fs.file.sub(fs.xattr_table, 16)).await?;
    let kv = u64_le(&head, 0).unwrap_or(0);
    cx.emit(struct_node(
        "Header",
        fs.file.sub(fs.xattr_table, 16),
        LE,
        (),
        xattr_header_layout,
    ));
    let (_, ptrs) = lookup_decoded(&cx, &fs, Lookup::XattrIds).await?;
    let kv_end = ptrs.first().copied().unwrap_or(fs.xattr_table);
    cx.emit(
        Node::new("Key/value metadata blocks")
            .span(fs.file.sub(kv, kv_end.saturating_sub(kv)))
            .lazy(table_blocks, (fs.clone(), kv, kv_end)),
    );
    cx.emit(Node::new("Xattr ID table").lazy(lookup_table, (fs.clone(), Lookup::XattrIds)));
    Ok(())
}

const XATTR_PREFIX: EnumTable = &[(0, "user."), (1, "trusted."), (2, "security.")];

/// The extended attributes of xattr ID `id`.
async fn xattr_list(cx: Cx, (fs, id): (FsRef, u32)) -> Result<()> {
    let (ids, _) = lookup_decoded(&cx, &fs, Lookup::XattrIds).await?;
    let raw = cx
        .read(ids.sub(u64::from(id).saturating_mul(16), 16))
        .await?;
    let mref = u64_le(&raw, 0).unwrap_or(0);
    let n = u32_le(&raw, 8).unwrap_or(0);
    let head = cx.read(fs.file.sub(fs.xattr_table, 8)).await?;
    let kv = u64_le(&head, 0).unwrap_or(0);
    let (_, ptrs) = lookup_decoded(&cx, &fs, Lookup::XattrIds).await?;
    let kv_end = ptrs.first().copied().unwrap_or(fs.xattr_table);
    let t = table(&cx, &fs, kv, kv_end).await?;
    let mut pos = t
        .locate(mref)
        .ok_or_else(|| Diagnostic::malformed("bad xattr reference"))?;
    for _ in 0..n.min(65536) {
        let kh = cx.read(t.decoded.sub(pos, 4)).await?;
        let ty = u16_le(&kh, 0).unwrap_or(0);
        let name_len = u64::from(u16_le(&kh, 2).unwrap_or(0));
        let name = cx
            .read(t.decoded.sub(pos.saturating_add(4), name_len))
            .await?;
        let vat = pos.saturating_add(4).saturating_add(name_len);
        let vh = cx.read(t.decoded.sub(vat, 4)).await?;
        let vsize = u64::from(u32_le(&vh, 0).unwrap_or(0));
        let full = format!(
            "{}{}",
            lookup(XATTR_PREFIX, (ty & 0xff).into()).unwrap_or("?."),
            String::from_utf8_lossy(&name)
        );
        let mut vspan = t.decoded.sub(vat.saturating_add(4), vsize);
        if ty & 0x100 != 0 {
            // Out of line: the value holds a reference to the real one.
            let r = cx.read(vspan.sub(0, 8)).await?;
            if let Some(p) = t.locate(u64_le(&r, 0).unwrap_or(0)) {
                let len = cx.read(t.decoded.sub(p, 4)).await?;
                vspan = t
                    .decoded
                    .sub(p.saturating_add(4), u32_le(&len, 0).unwrap_or(0).into());
            }
        }
        let value = cx.read_avail(vspan.sub(0, 65536)).await?;
        let node = Node::new(full).span(
            t.decoded.sub(
                pos,
                vat.saturating_add(4)
                    .saturating_add(vsize)
                    .saturating_sub(pos),
            ),
        );
        let trimmed = value.strip_suffix(&[0]).unwrap_or(&value);
        cx.push(if crate::text::looks_like_text(trimmed) {
            node.value(Value::Text(String::from_utf8_lossy(trimmed).into_owned()))
        } else {
            node.value(Value::Bytes(value.clone()))
        })
        .await;
        pos = vat.saturating_add(4).saturating_add(vsize);
    }
    Ok(())
}
