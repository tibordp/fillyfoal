//! CramFS filesystem images: a superblock and a tree of 12-byte inodes;
//! directories are walked lazily and file contents (zlib blocks of one
//! page each) are decompressed on expansion.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{count, hex, human_size, uint, unix_mode};
use crate::formats::{Codec, Format, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const LE: Endian = Endian::Little;

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
