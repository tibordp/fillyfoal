//! ext directories: linear blocks of entries, inline directories, and the
//! htree index (a root and interior nodes disguised as empty entries).

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::disk::size;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

use super::inode::{FL_INDEX, FL_INLINE, Inode, S_IFDIR, content};
use super::{FsRef, HASH, LE, MAX_DIR_DEPTH, csum32};

/// Directory bytes read at most.
const MAX_DIR_BYTES: u64 = 64 << 20;

const FILE_TYPES: EnumTable = &[
    (0, "unknown"),
    (1, "regular file"),
    (2, "directory"),
    (3, "character device"),
    (4, "block device"),
    (5, "FIFO"),
    (6, "socket"),
    (7, "symbolic link"),
    (0xde, "checksum tail"),
];

#[derive(Clone)]
pub(super) struct Dir {
    pub(super) fs: FsRef,
    pub(super) ino: u32,
    pub(super) path: Path,
}

struct Dirent {
    off: u64,
    rec_len: u64,
    ino: u32,
    name: Vec<u8>,
    file_type: u8,
}

/// The entries of a linear directory region. `full` is false for inline
/// regions, whose entries may end before the region does.
fn dirents(data: &[u8]) -> (Vec<Dirent>, Option<Diagnostic>) {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at.saturating_add(8) <= data.len() {
        let ino = u32_le(data, at).unwrap_or(0);
        let raw_len = u64::from(u16_le(data, at.saturating_add(4)).unwrap_or(0));
        // 65536-byte blocks store a whole-block record length as 0.
        let rec_len = if raw_len == 0 && data.len() == 65536 {
            65536
        } else {
            raw_len
        };
        let name_len = usize::from(data.get(at.saturating_add(6)).copied().unwrap_or(0));
        if rec_len < 8 || to_u64(at).saturating_add(rec_len) > to_u64(data.len()) {
            return (
                out,
                Some(Diagnostic::malformed(format!(
                    "directory entry at {at:#x} has a bad record length {rec_len}"
                ))),
            );
        }
        let name = data
            .get(at.saturating_add(8)..at.saturating_add(8).saturating_add(name_len))
            .unwrap_or_default();
        out.push(Dirent {
            off: to_u64(at),
            rec_len,
            ino,
            name: name.to_vec(),
            file_type: data.get(at.saturating_add(7)).copied().unwrap_or(0),
        });
        at = at.saturating_add(to_usize(rec_len));
    }
    (out, None)
}

async fn entry_node(cx: &Cx, dir: &Dir, e: &Dirent, span: Span) -> Node {
    let fs = &dir.fs;
    let (kind, is_dir) = if fs.filetype {
        (
            lookup(FILE_TYPES, e.file_type.into()).unwrap_or("unknown"),
            e.file_type == 2,
        )
    } else {
        match Inode::read(cx, fs, e.ino).await {
            Ok(inode) => ("entry", inode.kind() == S_IFDIR),
            Err(_) => ("entry", false),
        }
    };
    let node = Node::new(String::from_utf8_lossy(&e.name).into_owned())
        .span(span)
        .value(Value::UInt {
            value: e.ino.into(),
            bits: 32,
            radix: Radix::Dec,
        })
        .summary(format!("{kind}, inode {}", e.ino));
    if is_dir {
        match dir.path.enter(e.ino.into(), MAX_DIR_DEPTH) {
            Ok(path) => node.lazy(
                crate::expander!(self::directory: Dir),
                Dir {
                    fs: fs.clone(),
                    ino: e.ino,
                    path,
                },
            ),
            Err(d) => node.diag(d),
        }
    } else {
        node.lazy(super::inode::view, (fs.clone(), e.ino))
    }
}

/// Lists a directory: its inode, then its entries (paged).
pub(super) async fn directory(cx: Cx, dir: Dir) -> Result<()> {
    let fs = dir.fs.clone();
    let inode = Inode::read(&cx, &fs, dir.ino).await?;
    if inode.kind() != S_IFDIR {
        return Err(
            Diagnostic::malformed(format!("inode {} is not a directory", dir.ino)).at(inode.span),
        );
    }
    cx.emit(
        Node::new("Inode")
            .span(inode.span)
            .summary(format!("inode {}, {}", dir.ino, inode.summary()))
            .lazy(super::inode::view, (fs.clone(), dir.ino)),
    );
    let size = inode.size().min(MAX_DIR_BYTES);
    if inode.flags() & FL_INLINE != 0 {
        // The parent's number, then entries, in i_block; more entries in
        // the system.data attribute.
        let mut regions = vec![inode.span.sub(44, 56)];
        if let Some(extra) = super::xattr::inline_data_value(&inode) {
            regions.push(extra);
        }
        for region in regions {
            let data = cx.read_avail(region).await?;
            let (entries, problem) = dirents(&data);
            for e in entries {
                if e.ino == 0 {
                    continue;
                }
                let node = entry_node(&cx, &dir, &e, region.sub(e.off, e.rec_len)).await;
                cx.push(node).await;
            }
            if let Some(d) = problem {
                cx.diag(d.at(region));
            }
        }
        return Ok(());
    }
    let (data, _) = content(&cx, &fs, &inode, size).await?;
    let mut offset = 0u64;
    while offset < data.len {
        cx.progress(offset, data.len);
        let block = data.sub(offset, fs.block);
        let bytes = cx.read_avail(block).await?;
        let (entries, problem) = dirents(&bytes);
        for e in entries {
            if e.ino == 0 || e.name == b"." || e.name == b".." {
                continue;
            }
            let node = entry_node(&cx, &dir, &e, block.sub(e.off, e.rec_len)).await;
            cx.push(node).await;
        }
        if let Some(d) = problem {
            cx.diag(d.at(block));
        }
        offset = offset.saturating_add(fs.block);
    }
    Ok(())
}

fn dirent_layout(f: &mut Fields<'_>, filetype: &bool) -> Result<()> {
    f.u32("Inode").emit()?;
    let rec_len = f.u16("Record length").emit()?;
    let name_len = f.u8("Name length").emit()?;
    if *filetype {
        f.u8("File type").enumeration(FILE_TYPES).emit()?;
    } else {
        f.u8("Name length (high)").emit()?;
    }
    f.bytes("Name", name_len.into())
        .with(|b, n| n.value(Value::Text(String::from_utf8_lossy(b).into_owned())))
        .emit()?;
    let used = 8u64.saturating_add(name_len.into());
    let rest = u64::from(rec_len).saturating_sub(used).min(f.remaining());
    if rest > 0 {
        f.node(
            Node::new("Unused")
                .span(f.peek_span(rest))
                .summary(size(rest)),
        );
        f.skip(rest);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct TailCtx {
    computed: Option<u32>,
}

fn tail_layout(f: &mut Fields<'_>, ctx: &TailCtx) -> Result<()> {
    f.u32("Inode (zero)").emit()?;
    f.u16("Record length").emit()?;
    f.u8("Name length (zero)").emit()?;
    f.u8("File type").hex().enumeration(FILE_TYPES).emit()?;
    f.u32("Checksum")
        .hex()
        .with(|&v, n| match ctx.computed {
            Some(c) if c == v => n.summary("valid"),
            Some(c) => n.diag(Diagnostic::warning(format!("mismatch: computed {c:#010x}"))),
            None => n,
        })
        .emit()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockKind {
    Linear,
    DxRoot,
    DxNode,
}

/// Lists a directory's blocks with their structure.
pub(super) async fn blocks(cx: Cx, (fs, ino): (FsRef, u32)) -> Result<()> {
    let inode = Inode::read(&cx, &fs, ino).await?;
    let size = inode.size().min(MAX_DIR_BYTES);
    let (data, _) = content(&cx, &fs, &inode, size).await?;
    let indexed = inode.flags() & FL_INDEX != 0;
    let seed = inode.csum_seed(&fs);
    let count = data.len.div_ceil(fs.block);
    for b in 0..count {
        let span = data.sub(b.saturating_mul(fs.block), fs.block);
        let head = cx.read_avail(span.sub(0, 8)).await?;
        let rec_len = u64::from(u16_le(&head, 4).unwrap_or(0));
        let kind = if indexed && b == 0 {
            BlockKind::DxRoot
        } else if indexed
            && u32_le(&head, 0) == Some(0)
            && (rec_len == fs.block || (rec_len == 0 && fs.block == 65536))
        {
            BlockKind::DxNode
        } else {
            BlockKind::Linear
        };
        let what = match kind {
            BlockKind::Linear => "entries",
            BlockKind::DxRoot => "htree root",
            BlockKind::DxNode => "htree node",
        };
        cx.push(
            Node::new(format!("Block {b}"))
                .span(span)
                .summary(what)
                .lazy(block_view, (fs.clone(), span, kind, seed)),
        )
        .await;
    }
    Ok(())
}

async fn block_view(
    cx: Cx,
    (fs, span, kind, seed): (FsRef, Span, BlockKind, Option<u32>),
) -> Result<()> {
    let data = cx.read(span).await?;
    match kind {
        BlockKind::Linear => linear(&cx, &fs, span, &data, seed).await,
        BlockKind::DxRoot | BlockKind::DxNode => {
            dx(&cx, span, &data, kind, seed, fs.filetype);
            Ok(())
        }
    }
}

async fn linear(cx: &Cx, fs: &FsRef, span: Span, data: &[u8], seed: Option<u32>) -> Result<()> {
    let (entries, problem) = dirents(data);
    for e in &entries {
        let espan = span.sub(e.off, e.rec_len);
        let is_tail = e.ino == 0 && e.rec_len == 12 && e.name.is_empty() && e.file_type == 0xde;
        let node = if is_tail {
            let computed =
                seed.map(|s| csum32(s, &[data.get(..to_usize(e.off)).unwrap_or_default()]));
            struct_node(
                "Checksum tail",
                espan,
                LE,
                TailCtx { computed },
                tail_layout,
            )
        } else {
            let name = if e.ino == 0 {
                "Unused entry".to_owned()
            } else {
                String::from_utf8_lossy(&e.name).into_owned()
            };
            struct_node(name, espan, LE, fs.filetype, dirent_layout)
                .summary(format!("inode {}", e.ino))
        };
        cx.push(node).await;
    }
    if let Some(d) = problem {
        cx.diag(d.at(span));
    }
    Ok(())
}

fn root_info_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Reserved").emit()?;
    f.u8("Hash version").enumeration(HASH).emit()?;
    f.u8("Info length").emit()?;
    f.u8("Indirect levels").emit()?;
    f.u8("Flags").hex().emit()?;
    Ok(())
}

fn dx_entries_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Limit")
        .desc("Entries that fit in this block")
        .emit()?;
    let count = f.u16("Count").emit()?;
    f.u32("Block (hashes below the next entry)").emit()?;
    for i in 1..u64::from(count) {
        if f.remaining() < 8 {
            break;
        }
        let hash = u32_le(&f.block().data, to_usize(f.pos())).unwrap_or(0);
        let block = u32_le(&f.block().data, to_usize(f.pos()).saturating_add(4)).unwrap_or(0);
        f.node(
            Node::new(format!("Entry {i}"))
                .span(f.peek_span(8))
                .value(Value::UInt {
                    value: hash.into(),
                    bits: 32,
                    radix: Radix::Hex,
                })
                .summary(format!("hashes from {hash:#010x} → block {block}")),
        );
        f.skip(8);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct DxTailCtx {
    computed: Option<u32>,
}

fn dx_tail_layout(f: &mut Fields<'_>, ctx: &DxTailCtx) -> Result<()> {
    f.u32("Reserved").emit()?;
    f.u32("Checksum")
        .hex()
        .with(|&v, n| match ctx.computed {
            Some(c) if c == v => n.summary("valid"),
            Some(c) => n.diag(Diagnostic::warning(format!("mismatch: computed {c:#010x}"))),
            None => n,
        })
        .emit()?;
    Ok(())
}

/// An htree root or node block.
fn dx(cx: &Cx, span: Span, data: &[u8], kind: BlockKind, seed: Option<u32>, filetype: bool) {
    let count_at: u64 = if kind == BlockKind::DxRoot {
        // "." (12 bytes), ".." (12 bytes shown), then the root info.
        cx.emit(struct_node(
            ".",
            span.sub(0, 12),
            LE,
            filetype,
            dirent_layout,
        ));
        cx.emit(
            struct_node("..", span.sub(12, 12), LE, filetype, dirent_layout_fixed)
                .summary("its record length covers the rest of the block"),
        );
        cx.emit(struct_node(
            "Root info",
            span.sub(24, 8),
            LE,
            (),
            root_info_layout,
        ));
        32
    } else {
        cx.emit(
            struct_node(
                "Empty entry",
                span.sub(0, 8),
                LE,
                filetype,
                dirent_layout_fixed,
            )
            .summary("covers the whole block, hiding the index from old readers"),
        );
        8
    };
    let limit = u64::from(u16_le(data, to_usize(count_at)).unwrap_or(0));
    let count = u64::from(u16_le(data, to_usize(count_at).saturating_add(2)).unwrap_or(0));
    let entries = span.sub(count_at, count.saturating_mul(8));
    cx.emit(
        struct_node("Index entries", entries, LE, (), dx_entries_layout)
            .summary(format!("{count} of {limit} entries")),
    );
    let limit_end = count_at.saturating_add(limit.saturating_mul(8));
    let used = count_at.saturating_add(entries.len);
    if limit_end > used {
        cx.emit(
            Node::new("Unused entries")
                .span(span.sub(used, limit_end.saturating_sub(used)))
                .summary(format!("{} slots", limit.saturating_sub(count))),
        );
    }
    if seed.is_some() && limit_end.saturating_add(8) <= span.len {
        let computed = seed.map(|s| {
            csum32(
                s,
                &[
                    data.get(..to_usize(used)).unwrap_or_default(),
                    data.get(to_usize(limit_end)..to_usize(limit_end).saturating_add(4))
                        .unwrap_or_default(),
                    &[0; 4],
                ],
            )
        });
        cx.emit(struct_node(
            "Checksum tail",
            span.sub(limit_end, 8),
            LE,
            DxTailCtx { computed },
            dx_tail_layout,
        ));
        let end = limit_end.saturating_add(8);
        if span.len > end {
            cx.emit(
                Node::new("Unused")
                    .span(span.tail(end))
                    .summary(size(span.len.saturating_sub(end))),
            );
        }
    } else if span.len > limit_end {
        cx.emit(
            Node::new("Unused")
                .span(span.tail(limit_end))
                .summary(size(span.len.saturating_sub(limit_end))),
        );
    }
}

/// A directory entry header and name, without the record's unused space
/// (for the htree's disguised entries).
fn dirent_layout_fixed(f: &mut Fields<'_>, filetype: &bool) -> Result<()> {
    f.u32("Inode").emit()?;
    f.u16("Record length").emit()?;
    let name_len = f.u8("Name length").emit()?;
    if *filetype {
        f.u8("File type").enumeration(FILE_TYPES).emit()?;
    } else {
        f.u8("Name length (high)").emit()?;
    }
    let n = u64::from(name_len).min(f.remaining());
    if n > 0 {
        f.bytes("Name", n)
            .with(|b, n| n.value(Value::Text(String::from_utf8_lossy(b).into_owned())))
            .emit()?;
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Padding", rest).emit()?;
    }
    Ok(())
}
