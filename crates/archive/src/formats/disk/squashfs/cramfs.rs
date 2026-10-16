//! CramFS filesystem images: a superblock and a tree of 12-byte inodes;
//! directories are walked lazily and file contents (zlib blocks of one
//! page each) are decompressed on expansion.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::disk::{PieceList, content_node};
use crate::formats::util::arcutil::{push_nodes, unix_mode};
use crate::formats::util::fmt;
use crate::formats::util::fmt::count;
use crate::formats::util::val::{hex, uint};
use crate::formats::{Codec, Format, Input, Probe, content, embedded};
use crate::node::Node;
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
        size: u32 "Size" .size(),
        flags: u32 "Flags" .flags(CRAM_FLAGS),
        future: u32 "Reserved",
        signature: ascii[16] "Signature",
        crc: u32 "CRC" .checksum("CRC-32"),
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
        .oct()
        .with(|&m, n| n.summary(unix_mode(m.into())))
        .emit()?;
    f.u16("UID").emit()?;
    let sg = f.u32("Size and GID").hex().get()?;
    let span = f.peek_span(0);
    let at = Span::new(span.source, span.offset.saturating_sub(4), 4);
    f.node(
        Node::new("Size")
            .span(at.sub(0, 3))
            .value(uint(sg & 0x00ff_ffff, 64)),
    );
    f.node(
        Node::new("GID")
            .span(at.sub(3, 1))
            .value(uint(sg >> 24, 64)),
    );
    let no = f.u32("Name length and offset").hex().get()?;
    let at = Span::new(span.source, span.offset, 4);
    f.node(
        Node::new("Name length")
            .span(at)
            .value(uint(u64::from(no & 0x3f).saturating_mul(4), 64))
            .summary("bytes (stored in units of 4)"),
    );
    f.node(
        Node::new("Data offset")
            .span(at)
            .value(hex(u64::from(no >> 6).saturating_mul(4), 64))
            .summary("stored in units of 4"),
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct CramEntry {
    input: Input,
    inode: Span,
    path: Arc<Vec<u64>>,
}

pub async fn dissect_cramfs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4)).await?;
    let base = if head == b"\x45\x3d\xcd\x28" { 0 } else { 512 };
    if base > 0 {
        let boot = file.sub(0, base);
        if cx.read_avail(boot).await?.iter().all(|&b| b == 0) {
            cx.emit(
                Node::new("Boot block")
                    .span(boot)
                    .summary("zeros (padding)"),
            );
        } else {
            cx.emit(embedded("Boot block", input.nested(boot)));
        }
    }
    let sb_span = file.sub(base, CramSuper::SIZE);
    let sb = crate::fields::parse(&cx, sb_span, LE, &(), CramSuper::layout).await?;
    cx.emit(CramSuper::node("Superblock", sb_span, LE).summary(sb.name.clone()));
    let root_span = file.sub(base.saturating_add(CramSuper::SIZE), 12);
    let root = cx.read(root_span).await?;
    let root_inode = cram_inode(&root).ok_or_else(|| Diagnostic::truncated(root_span, 0))?;
    let state = CramEntry {
        input,
        inode: root_span,
        path: Arc::new(Vec::new()),
    };
    cx.emit(
        Node::new("Root directory")
            .span(root_span)
            .summary(fmt::size(root_inode.size.into()))
            .lazy(crate::expander!(self::cram_entry: CramEntry), state),
    );
    cx.annotate(format!(
        "CramFS {:?}, {}, {}",
        sb.name,
        count(sb.files, "file", "files"),
        fmt::size(sb.size.into())
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
    // Offsets are from the start of the image, also when a 512-byte boot
    // block (mkfs.cramfs -p) moves the superblock.
    let data_at = inode.offset;
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
                    fmt::size(child.size.into())
                } else {
                    kind.to_owned()
                };
                cx.push(Node::new(name).span(entry_span).summary(summary).lazy(
                    crate::expander!(self::cram_entry: CramEntry),
                    CramEntry {
                        input: e.input,
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
            cx.emit(
                Node::new("Block pointers")
                    .span(ptrs)
                    .value(uint(blocks, 64)),
            );
            let mut start = data_at.saturating_add(ptrs.len);
            let mut nodes = Vec::new();
            for i in 0..blocks {
                let end = u64::from(u32_le(&raw, to_usize(i.saturating_mul(4))).unwrap_or(0));
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
                        .summary(fmt::size(*expected)),
                );
            } else {
                // The pages decoded only when a read reaches them, assembled
                // into one stream; the blocks themselves go in a group.
                let mut list = PieceList::new(ptrs);
                for (i, &(span, expected)) in nodes.iter().enumerate() {
                    if i % 256 == 0 {
                        cx.checkpoint().await;
                    }
                    if span.len == 0 {
                        // A hole (the HOLES flag): a page of zeros.
                        list.hole(&cx, expected)?;
                        continue;
                    }
                    match cx.decode_lazy(span, &Codec::Zlib, expected) {
                        Ok(d) => list.data(d),
                        Err(err) => {
                            cx.diag(err);
                            break;
                        }
                    }
                }
                let blocks: Vec<Node> = nodes
                    .into_iter()
                    .enumerate()
                    .map(|(i, (span, expected))| {
                        content(
                            format!("Block {i}"),
                            e.input,
                            span,
                            Codec::Zlib,
                            Some(expected),
                        )
                    })
                    .collect();
                cx.emit(
                    Node::new("Blocks")
                        .summary(fmt::plural(blocks.len(), "page"))
                        .lazy(push_nodes, Arc::new(blocks)),
                );
                let data = list.finish(&cx, "cramfs").await?;
                cx.emit(content_node(&e.input, data));
            }
        }
        _ => {}
    }
    Ok(())
}
