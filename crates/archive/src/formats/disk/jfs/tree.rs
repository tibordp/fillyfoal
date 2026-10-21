//! A JFS fileset's directory tree: inodes found through the fileset inode
//! map (IAG, inode extent, slot), directories read from their dtree (the
//! root in the inode, then 4 KiB pages; `jfs_dtree.h`) in key order, and
//! files' content from their xtree.

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::struct_node;
use crate::formats::disk::{content_node, size, unix_mode};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

use super::{
    Agg, BT_INTERNAL, BT_LEAF, EXTSPERIAG, FILESET_INODES, INODE, INOSPEREXT, LE, PAGE,
    dinode_layout, file_span, pxd,
};

/// Directory nesting followed, dtree pages per directory, and entries.
const MAX_DEPTH: usize = 64;
const MAX_PAGES: usize = 1 << 16;
const MAX_ENTRIES: usize = 1 << 20;
/// A dtree slot, and the characters an entry's first slot and each
/// continuation slot hold.
const SLOT: usize = 32;
const HEAD_CHARS: usize = 11;
const MORE_CHARS: usize = 15;
/// Symbolic link targets shorter than this are kept in the inode
/// (`IDATASIZE`).
const FAST_SYMLINK: u64 = 256;

/// The fileset: the aggregate and the fileset inode map's bytes.
#[derive(Clone, Copy, Debug)]
pub(super) struct Fileset {
    pub agg: Agg,
    pub imap: Span,
}

impl Fileset {
    /// Inode `n`'s 512 bytes: its IAG (a page of the map after the
    /// control page), the extent of 32 inodes it is in, its slot there.
    async fn inode(&self, cx: &Cx, n: u64) -> Result<Span> {
        let per_iag = EXTSPERIAG.saturating_mul(INOSPEREXT);
        let iag = n.checked_div(per_iag).unwrap_or(0);
        let within = n.checked_rem(per_iag).unwrap_or(0);
        let ext = within.checked_div(INOSPEREXT).unwrap_or(0);
        let page = self
            .imap
            .sub(iag.saturating_add(1).saturating_mul(PAGE), PAGE);
        let raw = cx
            .read_avail(page.sub(3072u64.saturating_add(ext.saturating_mul(8)), 8))
            .await?;
        let (len, addr) = pxd(&raw);
        if len == 0 {
            return Err(Diagnostic::malformed(format!(
                "inode {n} is in no inode extent"
            )));
        }
        let slot = within.checked_rem(INOSPEREXT).unwrap_or(0);
        let span = self
            .agg
            .blocks(addr, len)
            .sub(slot.saturating_mul(INODE), INODE);
        if span.len < INODE {
            return Err(Diagnostic::malformed(format!("inode {n} is past the end")));
        }
        Ok(span)
    }
}

/// One directory entry: name and inode number.
struct Entry {
    name: String,
    inode: u64,
}

/// The entries of a dtree page (or the root): the sorted slot table gives
/// their order; internal entries lead to child pages.
fn page_entries(
    page: &[u8],
    leaf: bool,
    stbl: &[u8],
    count: usize,
    out: &mut Vec<Entry>,
    children: &mut Vec<(u64, u64)>,
) {
    let slot = |i: usize| page.get(i.saturating_mul(SLOT)..)?.get(..SLOT);
    for &index in stbl.iter().take(count) {
        let Ok(index) = usize::try_from(i8::from_le_bytes([index])) else {
            continue;
        };
        let Some(e) = slot(index) else { continue };
        let (head, name_at) = if leaf { (4usize, 6usize) } else { (8, 10) };
        let mut next = e.get(head).map_or(-1, |&b| i8::from_le_bytes([b]));
        let namlen = usize::from(e.get(head.saturating_add(1)).copied().unwrap_or(0));
        let mut units: Vec<u16> = Vec::with_capacity(namlen);
        for k in 0..namlen.min(HEAD_CHARS) {
            units.extend(u16_le(e, name_at.saturating_add(k.saturating_mul(2))));
        }
        // Continuation slots: next, count, then 15 characters.
        let mut hops = 0u32;
        while units.len() < namlen && next >= 0 && hops < 32u32 {
            let Some(c) = slot(usize::try_from(next).unwrap_or(0)) else {
                break;
            };
            let take = (namlen.saturating_sub(units.len())).min(MORE_CHARS);
            for k in 0..take {
                units.extend(u16_le(c, 2usize.saturating_add(k.saturating_mul(2))));
            }
            next = c.first().map_or(-1, |&b| i8::from_le_bytes([b]));
            hops = hops.saturating_add(1);
        }
        if leaf {
            out.push(Entry {
                name: String::from_utf16_lossy(&units),
                inode: u32_le(e, 0).unwrap_or(0).into(),
            });
        } else {
            let (len, addr) = pxd(e);
            children.push((addr, len));
        }
    }
}

/// A directory's entries, walking its dtree in key order.
async fn entries(cx: &Cx, fs: &Fileset, inode: Span) -> Result<Vec<Entry>> {
    let raw = cx.read_avail(inode).await?;
    // The root: 32-byte header at 224 (flags, entry count, sorted slot
    // table at +24), slots 1 to 8 after it.
    let root = raw.get(224..512).unwrap_or_default();
    let flag = root.get(16).copied().unwrap_or(0);
    let count = usize::from(root.get(17).copied().unwrap_or(0)).min(8);
    let stbl = root.get(24..32).unwrap_or_default();
    let mut out = Vec::new();
    // Pages still to read, last first.
    let mut pending = Vec::new();
    page_entries(
        root,
        flag & BT_LEAF != 0,
        stbl,
        count,
        &mut out,
        &mut pending,
    );
    pending.reverse();
    let mut pages = 0usize;
    while let Some((addr, _len)) = pending.pop() {
        pages = pages.saturating_add(1);
        if pages > MAX_PAGES || out.len() >= MAX_ENTRIES {
            cx.diag(Diagnostic::limit("directory listed in part").at(inode));
            break;
        }
        let page = cx
            .read_avail(fs.agg.vol.sub(addr.saturating_mul(fs.agg.block), PAGE))
            .await?;
        let flag = page.get(16).copied().unwrap_or(0);
        let count = usize::from(page.get(17).copied().unwrap_or(0));
        let stbl_at = usize::from(page.get(21).copied().unwrap_or(0)).saturating_mul(SLOT);
        let stbl = page.get(stbl_at..).unwrap_or_default();
        if flag & (BT_LEAF | BT_INTERNAL) == 0 {
            cx.diag(
                Diagnostic::malformed(format!(
                    "dtree page at block {addr} is neither leaf nor internal"
                ))
                .at(inode),
            );
            continue;
        }
        let mut children = Vec::new();
        page_entries(
            &page,
            flag & BT_LEAF != 0,
            stbl,
            count,
            &mut out,
            &mut children,
        );
        pending.extend(children.into_iter().rev());
        cx.checkpoint().await;
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Dir {
    pub fs: Fileset,
    pub inode: u64,
}

/// The root directory (fileset inode 2).
pub(super) async fn root_directory(cx: Cx, fs: Fileset) -> Result<()> {
    directory(cx, (Dir { fs, inode: 2 }, Path::new())).await
}

fn inode_node(n: u64, span: Span, raw: &[u8]) -> Node {
    struct_node(
        format!("Inode {n}"),
        span,
        LE,
        FILESET_INODES,
        dinode_layout,
    )
    .summary(format!(
        "{}, {}",
        unix_mode((u32_le(raw, 52).unwrap_or(0) & 0xffff).into()),
        size(u64_le(raw, 24).unwrap_or(0))
    ))
}

/// A directory: its inode, then its entries.
async fn directory(cx: Cx, (dir, path): (Dir, Path)) -> Result<()> {
    let fs = dir.fs;
    let span = fs.inode(&cx, dir.inode).await?;
    let raw = cx.read_avail(span).await?;
    let list = entries(&cx, &fs, span).await?;
    cx.set_count(Count::Exact(to_u64(list.len()).saturating_add(1)));
    cx.push(inode_node(dir.inode, span, &raw)).await;
    for e in list {
        let node = Node::new(e.name);
        let node = match fs.inode(&cx, e.inode).await {
            Err(d) => node.summary(format!("inode {}", e.inode)).diag(d),
            Ok(ispan) => {
                let head = cx.read_avail(ispan.sub(0, 56)).await?;
                let mode = u32_le(&head, 52).unwrap_or(0) & 0xffff;
                let len = u64_le(&head, 24).unwrap_or(0);
                let node = node.span(ispan);
                if mode & 0xf000 == 0x4000 {
                    match path.enter(e.inode, MAX_DEPTH) {
                        Ok(p) => node.summary(format!("directory, inode {}", e.inode)).lazy(
                            crate::expander!(self::directory: (Dir, Path)),
                            (Dir { fs, inode: e.inode }, p),
                        ),
                        Err(d) => node.diag(d),
                    }
                } else {
                    let kind = match mode & 0xf000 {
                        0x8000 => "file",
                        0xa000 => "symbolic link",
                        0x2000 => "character device",
                        0x6000 => "block device",
                        0x1000 => "FIFO",
                        0xc000 => "socket",
                        _ => "inode",
                    };
                    node.summary(format!("{kind}, {}, inode {}", size(len), e.inode))
                        .lazy(file, (fs, e.inode, ispan))
                }
            }
        };
        cx.push(node).await;
    }
    Ok(())
}

/// A file's inode and content, or a symbolic link's target.
async fn file(cx: Cx, (fs, n, span): (Fileset, u64, Span)) -> Result<()> {
    let raw = cx.read_avail(span).await?;
    cx.emit(inode_node(n, span, &raw));
    let mode = u32_le(&raw, 52).unwrap_or(0) & 0xf000;
    let len = u64_le(&raw, 24).unwrap_or(0);
    match mode {
        0x8000 => {
            let data = file_span(&cx, fs.agg, span, len).await?;
            cx.emit(content_node(&fs.agg.input, data));
        }
        0xa000 => {
            let target = if len < FAST_SYMLINK {
                span.sub(256, len)
            } else {
                file_span(&cx, fs.agg, span, len).await?
            };
            let text = cx.read_avail(target.sub(0, 4096)).await?;
            cx.emit(
                Node::new("Target")
                    .span(target)
                    .value(Value::Text(String::from_utf8_lossy(&text).into_owned())),
            );
        }
        _ => {}
    }
    Ok(())
}
