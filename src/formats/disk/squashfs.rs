//! SquashFS (version 4) and CramFS filesystem images.
//!
//! SquashFS: a 96-byte superblock locating the inode, directory, fragment,
//! export, ID and xattr tables; optional compressor options follow it.
//! Tables are sequences of metadata blocks (16-bit header, up to 8 KiB),
//! shown with their payloads, decompressed (gzip, LZMA, xz, LZ4 and zstd;
//! LZO is unsupported).
//!
//! CramFS: a superblock and a tree of 12-byte inodes; directories are
//! walked lazily and file contents (zlib blocks of one page each) are
//! decompressed on expansion.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{
    count, emit_nodes, hex, human_size, uint, unix_mode, unsupported,
};
use crate::formats::{Codec, Format, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;
/// Metadata blocks listed per table before stopping.
const MAX_META_BLOCKS: u64 = 1 << 20;

pub static SQUASHFS: Format = Format {
    name: "squashfs",
    title: "SquashFS filesystem",
    extensions: &["squashfs", "sqfs", "snap", "sfs"],
    mime: "application/vnd.squashfs",
    probe: Probe::Magic(&[(0, b"hsqs"), (0, b"sqsh")]),
    dissect: crate::expander!(dissect_squashfs: Input),
};

pub static CRAMFS: Format = Format {
    name: "cramfs",
    title: "CramFS filesystem",
    extensions: &["cramfs", "cramfs.img"],
    mime: "application/x-cramfs",
    probe: Probe::Custom(|h| {
        (h.starts_with(b"\x45\x3d\xcd\x28") && h.at(16, b"Compressed ROMFS"))
            || (h.at(512, b"\x45\x3d\xcd\x28") && h.at(528, b"Compressed ROMFS"))
    }),
    dissect: crate::expander!(dissect_cramfs: Input),
};

// ---------------------------------------------------------------------------
// SquashFS

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

record! {
    pub struct Superblock {
        magic: ascii[4] "Magic",
        inodes: u32 "Inode count",
        mtime: u32 "Modification time" .timestamp(),
        block_size: u32 "Block size" .with(|&b, n| n.summary(human_size(b.into()))),
        fragments: u32 "Fragment count",
        compressor: u16 "Compression" .enumeration(COMPRESSOR),
        block_log: u16 "Block size (log2)",
        flags: u16 "Flags" .flags(SQ_FLAGS),
        ids: u16 "ID count",
        major: u16 "Major version",
        minor: u16 "Minor version",
        root: u64 "Root inode reference" .hex()
            .with(|&r, n| n.summary(format!("block {:#x}, offset {:#x}", r >> 16, r & 0xffff))),
        bytes_used: u64 "Bytes used" .with(|&b, n| n.summary(human_size(b))),
        id_table: u64 "ID table" .hex(),
        xattr_table: u64 "Xattr ID table" .hex(),
        inode_table: u64 "Inode table" .hex(),
        directory_table: u64 "Directory table" .hex(),
        fragment_table: u64 "Fragment table" .hex(),
        export_table: u64 "Export table" .hex(),
    }
}

const ABSENT: u64 = u64::MAX;

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
        4 => Some(Codec::Xz),
        5 => Some(Codec::Lz4Block),
        6 => Some(Codec::Zstd),
        _ => None,
    };
    let compressor = crate::value::lookup(COMPRESSOR, sb.compressor.into()).unwrap_or("unknown");
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
    // Tables in on-disk order; each ends where the next begins.
    let mut tables: Vec<(&'static str, u64)> = vec![
        ("Inode table", sb.inode_table),
        ("Directory table", sb.directory_table),
        ("Fragment table", sb.fragment_table),
        ("Export table", sb.export_table),
        ("ID table", sb.id_table),
        ("Xattr ID table", sb.xattr_table),
    ];
    tables.retain(|&(_, at)| at != ABSENT && at < sb.bytes_used);
    tables.sort_by_key(|&(_, at)| at);
    let first_table = tables.first().map_or(sb.bytes_used, |&(_, at)| at);
    let data = file.sub(data_start, first_table.saturating_sub(data_start));
    cx.emit(
        Node::new("Data and fragment blocks")
            .span(data)
            .summary(format!("{}, {compressor}", human_size(data.len))),
    );
    for (i, &(name, at)) in tables.iter().enumerate() {
        let end = tables
            .get(i.saturating_add(1))
            .map_or(sb.bytes_used, |&(_, e)| e);
        let span = file.sub(at, end.saturating_sub(at));
        let node = match name {
            "Inode table" | "Directory table" => Node::new(name)
                .span(span)
                .summary(human_size(span.len))
                .lazy(metadata_blocks, (input, span, codec.clone(), compressor)),
            _ => Node::new(name).span(span).summary(human_size(span.len)),
        };
        cx.emit(node);
    }
    if sb.bytes_used < file.len {
        cx.emit(Node::new("Padding").span(file.tail(sb.bytes_used)));
    }
    cx.annotate(format!(
        "SquashFS {}.{}, {compressor}, {}, {} blocks, {}",
        sb.major,
        sb.minor,
        count(sb.inodes.into(), "inode", "inodes"),
        human_size(sb.block_size.into()),
        human_size(sb.bytes_used)
    ));
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
                .with(|&d, n| n.summary(human_size(d.into())))
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

async fn metadata_blocks(
    cx: Cx,
    (input, span, codec, compressor): (Input, Span, Option<Codec>, &'static str),
) -> Result<()> {
    let mut at = 0u64;
    let mut index = 0u64;
    while at.saturating_add(2) <= span.len && index < MAX_META_BLOCKS {
        let head = cx.read(span.sub(at, 2)).await?;
        let h = u16_le(&head, 0).unwrap_or(0);
        let len = u64::from(h & 0x7fff);
        let stored = h & 0x8000 != 0;
        let block = span.sub(at, len.saturating_add(2));
        let payload = block.tail(2);
        let child = if stored {
            Node::new("Data").span(payload)
        } else if let Some(codec) = &codec {
            content("Data", input, payload, codec.clone(), None)
        } else {
            unsupported("Data", payload, compressor)
        };
        cx.progress_in(span, span.offset.saturating_add(at));
        cx.push(
            Node::new(format!("Metadata block {index}"))
                .span(block)
                .value(hex(h.into()))
                .summary(format!(
                    "{}, {}",
                    human_size(len),
                    if stored { "uncompressed" } else { compressor }
                ))
                .lazy(emit_nodes, Arc::new(vec![child])),
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

// ---------------------------------------------------------------------------
// CramFS

const CRAM_FLAGS: FlagTable = &[
    flag(0x0001, "FSID_VERSION_2"),
    flag(0x0002, "SORTED_DIRS"),
    flag(0x0100, "HOLES"),
    flag(0x0400, "WRONG_SIGNATURE"),
    flag(0x0800, "SHIFTED_ROOT_OFFSET"),
    flag(0x1000, "EXT_BLOCK_POINTERS"),
];

const PAGE: u64 = 4096;
const MAX_DEPTH: usize = 64;

record! {
    pub struct CramSuper {
        magic: u32 "Magic" .hex(),
        size: u32 "Size" .with(|&s, n| n.summary(human_size(s.into()))),
        flags: u32 "Flags" .flags(CRAM_FLAGS),
        future: u32 "Reserved",
        signature: ascii[16] "Signature",
        crc: u32 "CRC" .hex(),
        edition: u32 "Edition",
        blocks: u32 "Blocks",
        files: u32 "Files",
        name: ascii[16] "Name",
    }
}

/// A decoded 12-byte inode.
#[derive(Clone, Copy, Debug)]
struct CramInode {
    mode: u16,
    size: u32,
    namelen: u64,
    offset: u64,
}

fn cram_inode(b: &[u8]) -> Option<CramInode> {
    let mode = u16_le(b, 0)?;
    let sg = u32_le(b, 4)?;
    let no = u32_le(b, 8)?;
    Some(CramInode {
        mode,
        size: sg & 0x00ff_ffff,
        namelen: u64::from(no & 0x3f).saturating_mul(4),
        offset: u64::from(no >> 6).saturating_mul(4),
    })
}

fn inode_fields(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Mode")
        .with(|&m, n| n.summary(format!("0o{m:o} {}", unix_mode(m.into()))))
        .emit()?;
    f.u16("UID").emit()?;
    let sg = f.u32("Size and GID").hex().get()?;
    let span = f.peek_span(0);
    let at = Span::new(span.source, span.offset.saturating_sub(4), 4);
    f.node(
        Node::new("Size")
            .span(at.sub(0, 3))
            .value(uint((sg & 0x00ff_ffff).into())),
    );
    f.node(
        Node::new("GID")
            .span(at.sub(3, 1))
            .value(uint((sg >> 24).into())),
    );
    let no = f.u32("Name length and offset").hex().get()?;
    let at = Span::new(span.source, span.offset, 4);
    f.node(
        Node::new("Name length")
            .span(at)
            .value(uint(u64::from(no & 0x3f).saturating_mul(4)))
            .summary("bytes (stored in units of 4)"),
    );
    f.node(
        Node::new("Data offset")
            .span(at)
            .value(hex(u64::from(no >> 6).saturating_mul(4)))
            .summary("stored in units of 4"),
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct CramEntry {
    input: Input,
    /// Where the filesystem starts (0, or 512 with a boot block).
    base: u64,
    inode: Span,
    path: Arc<Vec<u64>>,
}

pub async fn dissect_cramfs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4)).await?;
    let base = if head == b"\x45\x3d\xcd\x28" { 0 } else { 512 };
    if base > 0 {
        cx.emit(embedded("Boot block", input.nested(file.sub(0, base))));
    }
    let sb_span = file.sub(base, CramSuper::SIZE);
    let sb = crate::fields::parse(&cx, sb_span, LE, &(), CramSuper::layout).await?;
    cx.emit(CramSuper::node("Superblock", sb_span, LE).summary(sb.name.clone()));
    let root_span = file.sub(base.saturating_add(CramSuper::SIZE), 12);
    let root = cx.read(root_span).await?;
    let root_inode = cram_inode(&root).ok_or_else(|| Diagnostic::truncated(root_span, 0))?;
    let state = CramEntry {
        input,
        base,
        inode: root_span,
        path: Arc::new(Vec::new()),
    };
    cx.emit(
        Node::new("Root directory")
            .span(root_span)
            .summary(human_size(root_inode.size.into()))
            .lazy(crate::expander!(self::cram_entry: CramEntry), state),
    );
    cx.annotate(format!(
        "CramFS {:?}, {}, {}",
        sb.name,
        count(sb.files.into(), "file", "files"),
        human_size(sb.size.into())
    ));
    Ok(())
}

async fn cram_entry(cx: Cx, e: CramEntry) -> Result<()> {
    let file = e.input.span;
    let raw = cx.read(e.inode).await?;
    let inode = cram_inode(&raw).ok_or_else(|| Diagnostic::truncated(e.inode, 0))?;
    cx.emit(
        struct_node("Inode", e.inode, LE, (), inode_fields).summary(unix_mode(inode.mode.into())),
    );
    let data_at = e.base.saturating_add(inode.offset);
    match u64::from(inode.mode) & 0o170_000 {
        0o040_000 => {
            if e.path.contains(&inode.offset) || e.path.len() >= MAX_DEPTH {
                cx.diag(Diagnostic::limit("directory loop or nesting too deep"));
                return Ok(());
            }
            let mut path = (*e.path).clone();
            path.push(inode.offset);
            let path = Arc::new(path);
            let dir = file.sub(data_at, inode.size.into());
            let data = cx.read(dir).await?;
            let mut at = 0usize;
            while at.saturating_add(12) <= data.len() {
                let Some(child) = data.get(at..).and_then(cram_inode) else {
                    break;
                };
                let name_at = at.saturating_add(12);
                let name_len = to_usize(child.namelen);
                let name = crate::text::until_nul(
                    data.get(name_at..name_at.saturating_add(name_len))
                        .unwrap_or_default(),
                );
                let entry_span = dir.sub(to_u64(at), 12u64.saturating_add(child.namelen));
                let kind = crate::formats::util::arcutil::unix_kind(child.mode.into());
                let summary = if kind == "file" {
                    human_size(child.size.into())
                } else {
                    kind.to_owned()
                };
                cx.push(Node::new(name).span(entry_span).summary(summary).lazy(
                    crate::expander!(self::cram_entry: CramEntry),
                    CramEntry {
                        input: e.input,
                        base: e.base,
                        inode: dir.sub(to_u64(at), 12),
                        path: path.clone(),
                    },
                ))
                .await;
                if child.namelen == 0 {
                    break;
                }
                at = name_at.saturating_add(name_len);
            }
        }
        0o100_000 | 0o120_000 if inode.size > 0 => {
            // Block pointers (end offsets), then zlib blocks of one page each.
            let blocks = u64::from(inode.size).div_ceil(PAGE);
            let ptrs = file.sub(data_at, blocks.saturating_mul(4));
            let raw = cx.read(ptrs).await?;
            cx.emit(Node::new("Block pointers").span(ptrs).value(uint(blocks)));
            let mut start = data_at.saturating_add(ptrs.len);
            let mut nodes = Vec::new();
            for i in 0..blocks {
                let end = u64::from(u32_le(&raw, to_usize(i.saturating_mul(4))).unwrap_or(0))
                    .saturating_add(e.base);
                let span = file.sub(start, end.saturating_sub(start));
                let expected = u64::from(inode.size)
                    .saturating_sub(i.saturating_mul(PAGE))
                    .min(PAGE);
                nodes.push((span, expected));
                start = end;
            }
            if let [(span, expected)] = nodes.as_slice() {
                cx.emit(
                    content("Content", e.input, *span, Codec::Zlib, Some(*expected))
                        .summary(human_size(*expected)),
                );
            } else {
                cx.set_count(Count::AtLeast(blocks));
                for (i, (span, expected)) in nodes.into_iter().enumerate() {
                    cx.push(content(
                        format!("Block {i}"),
                        e.input,
                        span,
                        Codec::Zlib,
                        Some(expected),
                    ))
                    .await;
                }
            }
        }
        _ => {}
    }
    Ok(())
}
