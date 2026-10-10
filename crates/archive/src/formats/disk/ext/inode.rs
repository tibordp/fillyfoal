//! ext inodes: the record (with the extra fields of large inodes and the
//! in-inode extended attributes), the block mapping (extent tree or block
//! map) and the content it maps.

use std::collections::{BTreeMap, HashSet};

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::disk::{PieceList, content_node, fragments_node, size, unix_mode, unix_time};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

use super::{Fs, FsRef, LE, ahead, csum32, uint};

/// Extent tree depth followed.
const MAX_EXTENT_DEPTH: u16 = 5;
/// Block mappings collected for one file before giving up.
const MAX_MAPPINGS: usize = 1 << 20;

pub(super) const S_IFDIR: u16 = 0x4000;
pub(super) const S_IFREG: u16 = 0x8000;
pub(super) const S_IFLNK: u16 = 0xa000;
pub(super) const FL_INDEX: u32 = 0x1000;
pub(super) const FL_EXTENTS: u32 = 0x80000;
pub(super) const FL_INLINE: u32 = 0x1000_0000;

const INODE_FLAGS: FlagTable = &[
    flag(0x1, "SECRM"),
    flag(0x2, "UNRM"),
    flag(0x4, "COMPR"),
    flag(0x8, "SYNC"),
    flag(0x10, "IMMUTABLE"),
    flag(0x20, "APPEND"),
    flag(0x40, "NODUMP"),
    flag(0x80, "NOATIME"),
    flag(0x100, "DIRTY"),
    flag(0x200, "COMPRBLK"),
    flag(0x400, "NOCOMPR"),
    flag(0x800, "ENCRYPT"),
    flag(0x1000, "INDEX"),
    flag(0x2000, "IMAGIC"),
    flag(0x4000, "JOURNAL_DATA"),
    flag(0x8000, "NOTAIL"),
    flag(0x10000, "DIRSYNC"),
    flag(0x20000, "TOPDIR"),
    flag(0x40000, "HUGE_FILE"),
    flag(0x80000, "EXTENTS"),
    flag(0x100000, "VERITY"),
    flag(0x200000, "EA_INODE"),
    flag(0x2000000, "DAX"),
    flag(0x10000000, "INLINE_DATA"),
    flag(0x20000000, "PROJINHERIT"),
    flag(0x40000000, "CASEFOLD"),
];

/// An inode as read from disk.
pub(super) struct Inode {
    pub(super) ino: u32,
    pub(super) span: Span,
    pub(super) raw: Vec<u8>,
}

impl Inode {
    pub(super) async fn read(cx: &Cx, fs: &Fs, ino: u32) -> Result<Inode> {
        let span = fs.inode_span(cx, ino).await?;
        let raw = cx.read(span).await?;
        Ok(Inode { ino, span, raw })
    }

    pub(super) fn mode(&self) -> u16 {
        u16_le(&self.raw, 0).unwrap_or(0)
    }

    pub(super) fn kind(&self) -> u16 {
        self.mode() & 0xf000
    }

    pub(super) fn flags(&self) -> u32 {
        u32_le(&self.raw, 32).unwrap_or(0)
    }

    pub(super) fn size(&self) -> u64 {
        u64::from(u32_le(&self.raw, 108).unwrap_or(0)) << 32
            | u64::from(u32_le(&self.raw, 4).unwrap_or(0))
    }

    fn generation(&self) -> u32 {
        u32_le(&self.raw, 100).unwrap_or(0)
    }

    pub(super) fn file_acl(&self) -> u64 {
        u64::from(u16_le(&self.raw, 118).unwrap_or(0)) << 32
            | u64::from(u32_le(&self.raw, 104).unwrap_or(0))
    }

    pub(super) fn i_block(&self) -> &[u8] {
        self.raw.get(40..100).unwrap_or_default()
    }

    /// Bytes of extra fields after the 128-byte base.
    pub(super) fn extra_isize(&self) -> u64 {
        if self.raw.len() > 128 {
            u64::from(u16_le(&self.raw, 128).unwrap_or(0))
        } else {
            0
        }
    }

    pub(super) fn is_fast_symlink(&self) -> bool {
        self.kind() == S_IFLNK && self.flags() & (FL_EXTENTS | FL_INLINE) == 0 && self.size() < 60
    }

    /// The seed of this inode's checksums (METADATA_CSUM).
    pub(super) fn csum_seed(&self, fs: &Fs) -> Option<u32> {
        let seed = fs.csum?;
        Some(csum32(
            seed,
            &[&self.ino.to_le_bytes(), &self.generation().to_le_bytes()],
        ))
    }

    /// The computed inode checksum and whether the high half is stored.
    fn checksum(&self, fs: &Fs) -> Option<(u32, bool)> {
        let seed = self.csum_seed(fs)?;
        let raw = &self.raw;
        let base = raw.get(..128)?;
        let mut c = csum32(seed, &[base.get(..0x7c)?, &[0, 0], base.get(0x7e..)?]);
        let mut has_hi = false;
        if raw.len() > 128 {
            has_hi = self.extra_isize() >= 4;
            c = if has_hi {
                csum32(c, &[raw.get(128..0x82)?, &[0, 0], raw.get(0x84..)?])
            } else {
                csum32(c, &[raw.get(128..)?])
            };
        }
        Some((c, has_hi))
    }

    fn stored_checksum(&self, has_hi: bool) -> u32 {
        let lo = u32::from(u16_le(&self.raw, 0x7c).unwrap_or(0));
        let hi = if has_hi {
            u32::from(u16_le(&self.raw, 0x82).unwrap_or(0))
        } else {
            0
        };
        hi << 16 | lo
    }

    /// A diagnostic if the inode checksum does not match.
    pub(super) fn checksum_diag(&self, fs: &Fs) -> Option<Diagnostic> {
        let (c, has_hi) = self.checksum(fs)?;
        let want = if has_hi { c } else { c & 0xffff };
        (self.stored_checksum(has_hi) != want)
            .then(|| Diagnostic::warning(format!("inode checksum mismatch: computed {want:#x}")))
    }

    pub(super) fn summary(&self) -> String {
        let links = u16_le(&self.raw, 26).unwrap_or(0);
        if self.mode() == 0 && links == 0 {
            return "deleted".to_owned();
        }
        format!(
            "{}, {}{}",
            unix_mode(self.mode().into()),
            size(self.size()),
            if links > 1 && self.kind() != S_IFDIR {
                format!(", {links} links")
            } else {
                String::new()
            }
        )
    }
}

#[derive(Clone)]
pub(super) struct InodeCtx {
    pub(super) fs: FsRef,
    pub(super) mode: u16,
    pub(super) flags: u32,
    pub(super) size: u64,
    /// The computed checksum and whether its high half is stored.
    pub(super) csum: Option<(u32, bool)>,
    pub(super) seed: Option<u32>,
}

impl InodeCtx {
    pub(super) fn of(fs: &FsRef, inode: &Inode) -> InodeCtx {
        InodeCtx {
            fs: fs.clone(),
            mode: inode.mode(),
            flags: inode.flags(),
            size: inode.size(),
            csum: inode.checksum(fs),
            seed: inode.csum_seed(fs),
        }
    }
}

/// Extra timestamp bits: two epoch bits and 30 bits of nanoseconds.
fn time_extra(v: &u32, n: Node) -> Node {
    let epoch = v & 3;
    let ns = v >> 2;
    if epoch == 0 && ns == 0 {
        return n;
    }
    n.summary(format!("+{ns} ns, epoch bits {epoch}"))
}

const DIRECT: [&str; 12] = [
    "Direct block 0",
    "Direct block 1",
    "Direct block 2",
    "Direct block 3",
    "Direct block 4",
    "Direct block 5",
    "Direct block 6",
    "Direct block 7",
    "Direct block 8",
    "Direct block 9",
    "Direct block 10",
    "Direct block 11",
];

/// The 60-byte `i_block` area, by what the inode keeps there.
fn i_block_node(ctx: &InodeCtx, span: Span, bytes: &[u8]) -> Node {
    let kind = ctx.mode & 0xf000;
    if ctx.flags & FL_EXTENTS != 0 {
        return struct_node(
            "Extent tree root",
            span,
            LE,
            ExtCtx {
                fs: ctx.fs.clone(),
                seed: ctx.seed,
                root: true,
                path: Path::new(),
            },
            extent_node_layout,
        )
        .summary(format!(
            "depth {}, {} entries",
            u16_le(bytes, 6).unwrap_or(0),
            u16_le(bytes, 2).unwrap_or(0)
        ));
    }
    if ctx.flags & FL_INLINE != 0 {
        let len = ctx.size.min(60);
        return Node::new("Inline data")
            .span(span)
            .summary(format!("{} in the inode", size(len)))
            .desc("The first 60 bytes of the file (a directory's parent and first entries); more follow in the system.data attribute");
    }
    if kind == S_IFLNK && ctx.size < 60 {
        let target = bytes.get(..to_usize(ctx.size)).unwrap_or_default();
        return Node::new("Symlink target")
            .span(span)
            .value(Value::Text(String::from_utf8_lossy(target).into_owned()));
    }
    if matches!(kind, 0x2000 | 0x6000) {
        return struct_node("Device", span, LE, (), device_layout);
    }
    struct_node("Block map", span, LE, ctx.fs.clone(), block_map_layout)
}

fn device_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Device (old encoding)")
        .hex()
        .with(|&v, n| {
            if v == 0 {
                n
            } else {
                n.summary(format!("major {}, minor {}", (v >> 8) & 0xff, v & 0xff))
            }
        })
        .emit()?;
    f.u32("Device (new encoding)")
        .hex()
        .with(|&v, n| {
            if v == 0 {
                n
            } else {
                n.summary(format!(
                    "major {}, minor {}",
                    (v & 0xf_ff00) >> 8,
                    (v & 0xff) | ((v >> 12) & 0xf_ff00)
                ))
            }
        })
        .emit()?;
    let rest = f.remaining();
    f.bytes("Unused", rest).emit()?;
    Ok(())
}

fn block_map_layout(f: &mut Fields<'_>, fs: &FsRef) -> Result<()> {
    for name in DIRECT {
        f.u32(name)
            .with(|&v, n| if v == 0 { n.summary("hole") } else { n })
            .emit()?;
    }
    for (level, name) in [
        (1u32, "Indirect block"),
        (2, "Double indirect block"),
        (3, "Triple indirect block"),
    ] {
        let span = f.peek_span(4);
        let v = u32_le(ahead(f, 4), 0).unwrap_or(0);
        let node = uint(name, span, v.into(), 32);
        f.node(if v == 0 {
            node.summary("none")
        } else {
            node.lazy(
                crate::expander!(self::indirect: Indirect),
                Indirect {
                    fs: fs.clone(),
                    block: v.into(),
                    level,
                    path: Path::new(),
                },
            )
        });
        f.skip(4);
    }
    Ok(())
}

#[derive(Clone)]
struct Indirect {
    fs: FsRef,
    block: u64,
    level: u32,
    path: Path,
}

/// An indirect block: its non-zero pointers (to data or to the next
/// level).
async fn indirect(cx: Cx, st: Indirect) -> Result<()> {
    let fs = &st.fs;
    let span = fs.block_span(st.block);
    let data = cx.read(span).await?;
    let mut zeros: Option<usize> = None;
    let flush = |from: usize, to: usize| {
        Node::new(format!("Pointers {from}–{}", to.saturating_sub(1)))
            .span(span.sub(
                to_u64(from).saturating_mul(4),
                to_u64(to.saturating_sub(from)).saturating_mul(4),
            ))
            .summary("holes")
    };
    let words: Vec<u32> = data
        .as_chunks::<4>()
        .0
        .iter()
        .map(|p| u32::from_le_bytes(*p))
        .collect();
    let mut i = 0usize;
    while i < words.len() {
        let v = words.get(i).copied().unwrap_or(0);
        if v == 0 {
            zeros.get_or_insert(i);
            i = i.saturating_add(1);
            continue;
        }
        if let Some(from) = zeros.take() {
            cx.push(flush(from, i)).await;
        }
        if st.level == 1 {
            // A run of consecutive data blocks.
            let mut end = i.saturating_add(1);
            while words.get(end).is_some_and(|&w| {
                u64::from(w) == u64::from(v).saturating_add(to_u64(end.saturating_sub(i)))
            }) {
                end = end.saturating_add(1);
            }
            let n = end.saturating_sub(i);
            cx.push(
                uint(
                    if n == 1 {
                        format!("Pointer {i}")
                    } else {
                        format!("Pointers {i}–{}", end.saturating_sub(1))
                    },
                    span.sub(to_u64(i).saturating_mul(4), to_u64(n).saturating_mul(4)),
                    v.into(),
                    32,
                )
                .summary(if n == 1 {
                    "data block".to_owned()
                } else {
                    format!(
                        "data blocks {v}–{}",
                        u64::from(v).saturating_add(to_u64(n)).saturating_sub(1)
                    )
                }),
            )
            .await;
            i = end;
            continue;
        }
        let node = uint(
            format!("Pointer {i}"),
            span.sub(to_u64(i).saturating_mul(4), 4),
            v.into(),
            32,
        );
        let node = if st.level > 1 {
            match st.path.enter(v.into(), 4) {
                Ok(path) => node.summary("indirect block").lazy(
                    crate::expander!(self::indirect: Indirect),
                    Indirect {
                        fs: fs.clone(),
                        block: v.into(),
                        level: st.level.saturating_sub(1),
                        path,
                    },
                ),
                Err(d) => node.diag(d),
            }
        } else {
            node.summary("data block")
        };
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    if let Some(from) = zeros {
        cx.push(flush(from, data.len() / 4)).await;
    }
    Ok(())
}

#[derive(Clone)]
pub(super) struct ExtCtx {
    pub(super) fs: FsRef,
    pub(super) seed: Option<u32>,
    pub(super) root: bool,
    pub(super) path: Path,
}

fn extent_header(f: &mut Fields<'_>) -> Result<(u16, u16, u16)> {
    f.u16("Magic").hex().emit()?;
    let entries = f.u16("Entries").emit()?;
    let max = f.u16("Capacity").emit()?;
    let depth = f.u16("Depth").desc("0 for leaves").emit()?;
    f.u32("Generation").emit()?;
    Ok((entries, max, depth))
}

fn leaf_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("File block").emit()?;
    f.u16("Length")
        .with(|&v, n| {
            if v > 32768 {
                n.summary(format!("{} blocks, uninitialized", v.saturating_sub(32768)))
            } else {
                n.summary(format!("{v} blocks"))
            }
        })
        .desc("Above 32768: an uninitialized (preallocated) extent of length − 32768")
        .emit()?;
    f.u16("Start block (high)").emit()?;
    f.u32("Start block (low)").emit()?;
    Ok(())
}

fn index_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("File block").emit()?;
    f.u32("Child block (low)").emit()?;
    f.u16("Child block (high)").emit()?;
    f.u16("Unused").emit()?;
    Ok(())
}

/// An extent tree node: the header, its entries and (in blocks) the
/// checksum tail.
fn extent_node_layout(f: &mut Fields<'_>, ctx: &ExtCtx) -> Result<()> {
    let start = f.pos();
    let (entries, max, depth) = extent_header(f)?;
    let room = f.remaining() / 12;
    let n = u64::from(entries).min(room);
    for i in 0..n {
        let span = f.peek_span(12);
        let e = ahead(f, 12);
        let first = u32_le(e, 0).unwrap_or(0);
        if depth == 0 {
            let raw_len = u16_le(e, 4).unwrap_or(0);
            let len = if raw_len > 32768 {
                raw_len.saturating_sub(32768)
            } else {
                raw_len
            };
            let phys =
                u64::from(u16_le(e, 6).unwrap_or(0)) << 32 | u64::from(u32_le(e, 8).unwrap_or(0));
            f.node(
                struct_node(format!("Extent {i}"), span, LE, (), leaf_layout).summary(format!(
                    "file blocks {first}–{} → block {phys}{}",
                    u64::from(first)
                        .saturating_add(len.into())
                        .saturating_sub(1),
                    if raw_len > 32768 {
                        ", uninitialized"
                    } else {
                        ""
                    }
                )),
            );
        } else {
            let child =
                u64::from(u16_le(e, 8).unwrap_or(0)) << 32 | u64::from(u32_le(e, 4).unwrap_or(0));
            let node = struct_node(format!("Index {i}"), span, LE, (), index_layout)
                .summary(format!("file blocks from {first} → node at block {child}"));
            let child_node = match ctx.path.enter(child, usize::from(MAX_EXTENT_DEPTH)) {
                Ok(path) => Node::new(format!("Node at block {child}"))
                    .span(ctx.fs.block_span(child))
                    .lazy(
                        crate::expander!(self::extent_block: ExtCtx2),
                        ExtCtx2 {
                            ctx: ExtCtx {
                                fs: ctx.fs.clone(),
                                seed: ctx.seed,
                                root: false,
                                path,
                            },
                            block: child,
                        },
                    ),
                Err(d) => Node::new(format!("Node at block {child}")).diag(d),
            };
            f.node(node);
            f.node(child_node);
        }
        f.skip(12);
    }
    if !ctx.root {
        let tail_at = 12u64.saturating_add(u64::from(max).saturating_mul(12));
        let used = f.pos().saturating_sub(start);
        if tail_at > used {
            f.node(
                Node::new("Unused entries")
                    .span(f.peek_span(tail_at.saturating_sub(used)))
                    .summary(format!("{} slots", max.saturating_sub(entries))),
            );
            f.seek(start.saturating_add(tail_at));
        }
        if f.remaining() >= 4 {
            let computed = ctx.seed.map(|seed| {
                csum32(
                    seed,
                    &[f.block().data.get(..to_usize(tail_at)).unwrap_or_default()],
                )
            });
            f.u32("Checksum")
                .hex()
                .with(|&v, n| match computed {
                    Some(c) if c == v => n.summary("valid"),
                    Some(c) => n.diag(Diagnostic::warning(format!("mismatch: computed {c:#010x}"))),
                    None => n,
                })
                .emit()?;
        }
    }
    let rest = f.remaining();
    if rest > 0 {
        f.node(
            Node::new("Unused")
                .span(f.peek_span(rest))
                .summary(size(rest)),
        );
    }
    Ok(())
}

#[derive(Clone)]
struct ExtCtx2 {
    ctx: ExtCtx,
    block: u64,
}

async fn extent_block(cx: Cx, st: ExtCtx2) -> Result<()> {
    let span = st.ctx.fs.block_span(st.block);
    let block = cx.block(span).await?;
    if u16_le(&block.data, 0) != Some(0xf30a) {
        return Err(Diagnostic::malformed("bad extent node magic").at(span.sub(0, 2)));
    }
    extent_node_layout(&mut Fields::emitting(&cx, &block, LE), &st.ctx)?;
    Ok(())
}

/// Extra fields after the 128-byte base of a large inode, then the
/// in-inode extended attributes.
fn inode_layout(f: &mut Fields<'_>, ctx: &InodeCtx) -> Result<()> {
    f.u16("Mode")
        .hex()
        .with(|&m, n| n.summary(unix_mode(m.into())))
        .emit()?;
    f.u16("Owner (low)").emit()?;
    f.u32("Size (low)").emit()?;
    f.u32("Accessed").with(unix_time).emit()?;
    f.u32("Changed").with(unix_time).emit()?;
    f.u32("Modified").with(unix_time).emit()?;
    f.u32("Deleted").with(unix_time).emit()?;
    f.u16("Group (low)").emit()?;
    f.u16("Links").emit()?;
    f.u32("Blocks (low)")
        .desc("In 512-byte units (filesystem blocks with HUGE_FILE)")
        .emit()?;
    f.u32("Flags").hex().flags(INODE_FLAGS).emit()?;
    f.u32("Version").emit()?;
    let span = f.peek_span(60);
    let bytes = ahead(f, 60);
    f.node(i_block_node(ctx, span, bytes));
    f.skip(60);
    f.u32("Generation").emit()?;
    f.u32("Extended attribute block (low)").emit()?;
    f.u32("Size (high)").emit()?;
    f.u32("Fragment address (obsolete)").emit()?;
    f.u16("Blocks (high)").emit()?;
    f.u16("Extended attribute block (high)").emit()?;
    f.u16("Owner (high)").emit()?;
    f.u16("Group (high)").emit()?;
    let csum = ctx.csum;
    f.u16("Checksum (low)")
        .hex()
        .with(|&v, n| match csum {
            Some((c, false)) if u32::from(v) == c & 0xffff => n.summary("valid"),
            Some((c, false)) => n.diag(Diagnostic::warning(format!(
                "mismatch: computed {:#06x}",
                c & 0xffff
            ))),
            _ => n,
        })
        .emit()?;
    f.u16("Reserved").emit()?;
    if f.remaining() == 0 {
        return Ok(());
    }
    let extra = f
        .u16("Extra inode size")
        .desc("Bytes of fields after the 128-byte base")
        .emit()?;
    let extra_end = 128u64.saturating_add(extra.into()).min(f.block().span.len);
    let fits = |f: &Fields<'_>, n: u64| f.pos().saturating_add(n) <= extra_end;
    if fits(f, 2) {
        let lo = u32::from(u16_le(&f.block().data, 0x7c).unwrap_or(0));
        f.u16("Checksum (high)")
            .hex()
            .with(|&v, n| match csum {
                Some((c, true)) if u32::from(v) << 16 | lo == c => n.summary("valid"),
                Some((c, true)) => {
                    n.diag(Diagnostic::warning(format!("mismatch: computed {c:#010x}")))
                }
                _ => n,
            })
            .emit()?;
    }
    for name in ["Changed (extra)", "Modified (extra)", "Accessed (extra)"] {
        if fits(f, 4) {
            f.u32(name).hex().with(time_extra).emit()?;
        }
    }
    if fits(f, 4) {
        f.u32("Created").with(unix_time).emit()?;
    }
    if fits(f, 4) {
        f.u32("Created (extra)").hex().with(time_extra).emit()?;
    }
    if fits(f, 4) {
        f.u32("Version (high)").emit()?;
    }
    if fits(f, 4) {
        f.u32("Project ID").emit()?;
    }
    if f.pos() < extra_end {
        let n = extra_end.saturating_sub(f.pos());
        f.bytes("Reserved", n).emit()?;
    }
    super::xattr::ibody_layout(f)?;
    let rest = f.remaining();
    if rest > 0 {
        f.node(
            Node::new("Unused")
                .span(f.peek_span(rest))
                .summary(size(rest)),
        );
    }
    Ok(())
}

/// The record of an inode, as a lazy node.
pub(super) fn record(fs: &FsRef, inode: &Inode, name: String) -> Node {
    let mut node = struct_node(name, inode.span, LE, InodeCtx::of(fs, inode), inode_layout)
        .summary(inode.summary());
    if let Some(d) = inode.checksum_diag(fs) {
        node = node.diag(d);
    }
    node
}

/// An entry of the inode table listing: the record of a reserved inode,
/// a summary for others (their records are shown from the directory tree).
pub(super) async fn record_node(cx: &Cx, fs: &FsRef, ino: u32) -> Node {
    match Inode::read(cx, fs, ino).await {
        Ok(inode) if ino < FIRST_INO => record(fs, &inode, format!("Inode {ino}")),
        Ok(inode) => {
            let mut node = Node::new(format!("Inode {ino}"))
                .span(inode.span)
                .summary(inode.summary());
            if let Some(d) = inode.checksum_diag(fs) {
                node = node.diag(d);
            }
            node
        }
        Err(d) => Node::new(format!("Inode {ino}")).diag(d),
    }
}

/// Inodes below this are reserved (their records are shown in the table).
const FIRST_INO: u32 = 11;

/// What an inode maps: (logical block, physical block, count, initialized).
type Mapping = (u64, u64, u64, bool);

/// Mappings kept sorted by logical block as they are found (the walks are
/// charged per tree block; sorting a million entries afterwards would be one
/// long step). Equal logical blocks keep the order they were found in.
#[derive(Default)]
struct Mappings {
    sorted: BTreeMap<(u64, usize), (u64, u64, bool)>,
}

impl Mappings {
    fn push(&mut self, (logical, physical, count, init): Mapping) {
        let arrival = self.sorted.len();
        self.sorted
            .insert((logical, arrival), (physical, count, init));
    }

    fn len(&self) -> usize {
        self.sorted.len()
    }

    fn into_sorted(self) -> impl Iterator<Item = Mapping> {
        self.sorted
            .into_iter()
            .map(|((logical, _), (physical, count, init))| (logical, physical, count, init))
    }
}

/// Walks an extent tree from the inode's root (iterative, depth-first).
async fn extents(cx: &Cx, fs: &Fs, root: &[u8], out: &mut Mappings) -> Result<Option<Diagnostic>> {
    let mut seen = HashSet::new();
    let mut stack: Vec<(Vec<u8>, u16)> = vec![(root.to_vec(), MAX_EXTENT_DEPTH)];
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
    out: &mut Mappings,
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

/// The inode's content as a span (fragments assembled, holes as zeros),
/// with the pieces.
pub(super) async fn content(
    cx: &Cx,
    fs: &Fs,
    inode: &Inode,
    size: u64,
) -> Result<(Span, Vec<Span>)> {
    let flags = inode.flags();
    if flags & FL_INLINE != 0 {
        // The first 60 bytes in i_block, the rest in system.data.
        let mut list = PieceList::new(inode.span);
        let head = inode.span.sub(40, size.min(60));
        list.data(head);
        if size > 60
            && let Some(extra) = super::xattr::inline_data_value(inode)
        {
            list.data(extra.sub(0, size.saturating_sub(60)));
        }
        let span = list.finish(cx, "ext4-inline-data").await?;
        return Ok((span, list.into_pieces()));
    }
    if inode.is_fast_symlink() {
        let span = inode.span.sub(40, size.min(60));
        return Ok((span, vec![span]));
    }
    let mut maps = Mappings::default();
    let problem = if flags & FL_EXTENTS != 0 {
        extents(cx, fs, inode.i_block(), &mut maps).await?
    } else {
        block_map(cx, fs, inode.i_block(), size, &mut maps).await?
    };
    if let Some(d) = problem {
        cx.diag(d);
    }
    let mut list = PieceList::new(inode.span);
    for (i, (logical, physical, count, init)) in maps.into_sorted().enumerate() {
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
    let transform = if flags & FL_EXTENTS != 0 {
        "ext4-extents"
    } else {
        "ext2-blocks"
    };
    let span = list.finish(cx, transform).await?;
    Ok((span, list.into_pieces()))
}

/// Shows an inode: its record, its extended attributes and its content.
pub(super) async fn view(cx: Cx, (fs, ino): (FsRef, u32)) -> Result<()> {
    let inode = Inode::read(&cx, &fs, ino).await?;
    cx.annotate(inode.summary());
    view_into(&cx, &fs, &inode).await
}

/// Emits an inode's view into the node being expanded.
pub(super) async fn view_into(cx: &Cx, fs: &FsRef, inode: &Inode) -> Result<()> {
    cx.emit(record(fs, inode, format!("Inode {}", inode.ino)));
    let acl = inode.file_acl();
    if acl != 0 {
        cx.emit(
            Node::new("Extended attribute block")
                .span(fs.block_span(acl))
                .summary(format!("block {acl}"))
                .lazy(super::xattr::block_view, (fs.clone(), acl)),
        );
    }
    let size = inode.size();
    match inode.kind() {
        S_IFDIR => {
            if inode.flags() & FL_INLINE == 0 {
                cx.emit(
                    Node::new("Directory blocks")
                        .summary(crate::formats::disk::size(size))
                        .lazy(super::dir::blocks, (fs.clone(), inode.ino)),
                );
            }
        }
        S_IFLNK => {
            let (data, _) = content(cx, fs, inode, size.min(4096)).await?;
            let target = crate::text::until_nul(&cx.read_avail(data.sub(0, 4096)).await?);
            cx.emit(
                Node::new("Symlink target")
                    .span(data)
                    .value(Value::Text(target)),
            );
        }
        S_IFREG => {
            let (data, pieces) = content(cx, fs, inode, size).await?;
            if inode.flags() & FL_INLINE == 0 {
                cx.emit(fragments_node(cx, "Blocks", pieces).await);
            }
            cx.emit(content_node(&fs.input, data));
        }
        _ => {}
    }
    Ok(())
}
