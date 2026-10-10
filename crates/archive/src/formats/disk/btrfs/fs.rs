//! Btrfs filesystem trees: directories (DIR_INDEX items), inodes and file
//! content (EXTENT_DATA items, inline or in extents, possibly compressed).

use crate::bytes::{u16_le, u32_le, u64_le};
use crate::codec::{Codec, decode_span};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::struct_node;
use crate::formats::disk::{PieceList, content_node, size, unix_mode};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value, lookup};

use super::tree::{
    DIR_INDEX, DIR_TYPES, EXTENT_DATA, INODE_ITEM, INODE_REF, ROOT_ITEM, XATTR_ITEM, items,
    key_text, tree_root,
};
use super::{Fs, FsRef, LE};

/// Directory nesting followed.
const MAX_DEPTH: usize = 64;
const FS_TREE: u64 = 5;
const ROOT_DIR: u64 = 256;

#[derive(Clone)]
pub(super) struct DirState {
    fs: FsRef,
    root_tree: u64,
    /// The filesystem (or subvolume) tree's root node.
    tree: u64,
    ino: u64,
    path: Path,
}

pub(super) async fn root_directory(cx: Cx, (fs, root_tree): (FsRef, u64)) -> Result<()> {
    let (tree, _) = tree_root(&cx, &fs, root_tree, FS_TREE)
        .await?
        .ok_or_else(|| Diagnostic::malformed("no filesystem tree in the root tree"))?;
    directory(
        cx,
        DirState {
            fs,
            root_tree,
            tree,
            ino: ROOT_DIR,
            path: Path::new(),
        },
    )
    .await
}

/// An inode's item (the 160-byte INODE_ITEM).
async fn inode_item(cx: &Cx, fs: &Fs, tree: u64, ino: u64) -> Result<(Span, Vec<u8>)> {
    let found = items(cx, fs, tree, ino, INODE_ITEM).await?;
    let (_, span) = found
        .first()
        .copied()
        .ok_or_else(|| Diagnostic::malformed(format!("inode {ino} has no INODE_ITEM")))?;
    let raw = cx.read(span.sub(0, 160)).await?;
    Ok((span, raw))
}

fn inode_summary(raw: &[u8]) -> String {
    format!(
        "{}, {}",
        unix_mode(u32_le(raw, 52).unwrap_or(0).into()),
        size(u64_le(raw, 16).unwrap_or(0))
    )
}

fn item_node(name: String, span: Span, ty: u8) -> Node {
    struct_node(name, span, LE, ty, super::tree::item_layout)
}

/// Lists a directory: its inode, then its entries in index order.
pub(super) async fn directory(cx: Cx, st: DirState) -> Result<()> {
    let fs = st.fs.clone();
    let (ispan, raw) = inode_item(&cx, &fs, st.tree, st.ino).await?;
    cx.emit(item_node(format!("Inode {}", st.ino), ispan, INODE_ITEM).summary(inode_summary(&raw)));
    let entries = items(&cx, &fs, st.tree, st.ino, DIR_INDEX).await?;
    for (index, span) in entries {
        let data = cx.read_avail(span).await?;
        let child = u64_le(&data, 0).unwrap_or(0);
        let loc_type = data.get(8).copied().unwrap_or(0);
        let name_len = usize::from(u16_le(&data, 27).unwrap_or(0));
        let ty = data.get(29).copied().unwrap_or(0);
        let name = String::from_utf8_lossy(
            data.get(30..30usize.saturating_add(name_len))
                .unwrap_or_default(),
        )
        .into_owned();
        let what = lookup(DIR_TYPES, ty.into()).unwrap_or("unknown");
        let node = Node::new(name)
            .span(span)
            .value(Value::UInt {
                value: child,
                bits: 64,
                radix: Radix::Dec,
            })
            .summary(format!("{what}, inode {child}, index {index}"));
        let node = if loc_type == ROOT_ITEM {
            // A subvolume: its own tree, rooted at its directory 256.
            match tree_root(&cx, &fs, st.root_tree, child).await {
                Ok(Some((tree, _))) => match st.path.enter(tree, MAX_DEPTH) {
                    Ok(path) => node.summary(format!("subvolume {child}")).lazy(
                        crate::expander!(self::directory: DirState),
                        DirState {
                            fs: fs.clone(),
                            root_tree: st.root_tree,
                            tree,
                            ino: ROOT_DIR,
                            path,
                        },
                    ),
                    Err(d) => node.diag(d),
                },
                Ok(None) => node.diag(Diagnostic::malformed(format!(
                    "subvolume {child} not found"
                ))),
                Err(d) => node.diag(d),
            }
        } else if ty == 2 {
            match st.path.enter(child, MAX_DEPTH) {
                Ok(path) => node.lazy(
                    crate::expander!(self::directory: DirState),
                    DirState {
                        fs: fs.clone(),
                        root_tree: st.root_tree,
                        tree: st.tree,
                        ino: child,
                        path,
                    },
                ),
                Err(d) => node.diag(d),
            }
        } else {
            node.lazy(inode_view, (fs.clone(), st.tree, child))
        };
        cx.push(node).await;
    }
    Ok(())
}

/// Shows an inode: its item, references, xattrs and content.
async fn inode_view(cx: Cx, (fs, tree, ino): (FsRef, u64, u64)) -> Result<()> {
    let (ispan, raw) = inode_item(&cx, &fs, tree, ino).await?;
    cx.annotate(inode_summary(&raw));
    cx.emit(item_node(format!("Inode {ino}"), ispan, INODE_ITEM).summary(inode_summary(&raw)));
    for (parent, span) in items(&cx, &fs, tree, ino, INODE_REF).await? {
        cx.emit(item_node(key_text(ino, INODE_REF, parent), span, INODE_REF));
    }
    for (hash, span) in items(&cx, &fs, tree, ino, XATTR_ITEM).await? {
        cx.emit(item_node(key_text(ino, XATTR_ITEM, hash), span, XATTR_ITEM));
    }
    let mode = u32_le(&raw, 52).unwrap_or(0) & 0o170_000;
    let size = u64_le(&raw, 16).unwrap_or(0);
    if !matches!(mode, 0o100_000 | 0o120_000) {
        return Ok(());
    }
    let extents = items(&cx, &fs, tree, ino, EXTENT_DATA).await?;
    for (off, span) in &extents {
        cx.emit(item_node(
            key_text(ino, EXTENT_DATA, *off),
            *span,
            EXTENT_DATA,
        ));
    }
    let data = content(&cx, &fs, ispan, &extents, size).await?;
    if mode == 0o120_000 {
        let text = cx.read_avail(data.sub(0, 4096)).await?;
        cx.emit(
            Node::new("Target")
                .span(data)
                .value(Value::Text(String::from_utf8_lossy(&text).into_owned())),
        );
    } else {
        cx.emit(content_node(&fs.input, data));
    }
    Ok(())
}

fn codec_of(compression: u8) -> Option<Codec> {
    match compression {
        1 => Some(Codec::Zlib),
        3 => Some(Codec::Zstd),
        _ => None,
    }
}

/// A file's content from its EXTENT_DATA items (sorted by file offset).
async fn content(
    cx: &Cx,
    fs: &Fs,
    anchor: Span,
    extents: &[(u64, Span)],
    size: u64,
) -> Result<Span> {
    let mut list = PieceList::new(anchor);
    for (i, &(off, span)) in extents.iter().enumerate() {
        if i % 256 == 0 {
            cx.checkpoint().await;
        }
        if off >= size {
            break;
        }
        if off > list.len() {
            list.hole(cx, off.saturating_sub(list.len()))?;
        } else if off < list.len() {
            cx.diag(Diagnostic::malformed(format!(
                "overlapping extent at {off}"
            )));
            continue;
        }
        let head = cx.read(span.sub(0, 53.min(span.len))).await?;
        let ram = u64_le(&head, 8).unwrap_or(0);
        let compression = head.get(16).copied().unwrap_or(0);
        let kind = head.get(20).copied().unwrap_or(0);
        let left = size.saturating_sub(off);
        if kind == 0 {
            let inline = span.tail(21);
            let piece = if compression == 0 {
                inline
            } else {
                let codec = codec_of(compression).ok_or_else(|| {
                    Diagnostic::unsupported(format!("compression type {compression}")).at(inline)
                })?;
                decode_span(cx, inline, &codec, Some(ram)).await?.span
            };
            list.data(piece.sub(0, ram.min(left)));
            continue;
        }
        let disk = u64_le(&head, 21).unwrap_or(0);
        let disk_len = u64_le(&head, 29).unwrap_or(0);
        let offset = u64_le(&head, 37).unwrap_or(0);
        let len = u64_le(&head, 45).unwrap_or(0).min(left);
        if disk == 0 || kind == 2 {
            list.hole(cx, len)?;
            continue;
        }
        let Some(extent) = fs.logical_span(disk, disk_len) else {
            cx.diag(Diagnostic::malformed(format!(
                "extent at logical {disk:#x} is not mapped"
            )));
            list.hole(cx, len)?;
            continue;
        };
        let decoded = if compression == 0 {
            extent
        } else {
            let codec = codec_of(compression).ok_or_else(|| {
                Diagnostic::unsupported(format!("compression type {compression}")).at(extent)
            })?;
            cx.decode_lazy(extent, &codec, ram)?
        };
        list.data(decoded.sub(offset, len));
    }
    if list.len() < size {
        list.hole(cx, size.saturating_sub(list.len()))?;
    }
    list.finish(cx, "btrfs-extents").await
}
