//! XFS inodes: the core (`xfs_dinode`), the data and attribute forks, and
//! file content mapped through extents.

use std::collections::{BTreeMap, HashSet};

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::disk::{PieceList, content_node, fragments_node, size, unix_mode, uuid_value};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

use super::btree::{bmdr_root, ext_node};
use super::{BE, Fs, FsRef, HdrCtx, crc, crc_field, lsn_summary, rest_unused};

/// Extents collected for one fork before giving up.
const MAX_EXTENTS: usize = 1 << 20;
/// Blocks of a remote symlink target read (targets are at most 1 KiB).
const MAX_SYMLINK_BLOCKS: u64 = 16;

pub(super) const FMT_DEV: u8 = 0;
pub(super) const FMT_LOCAL: u8 = 1;
pub(super) const FMT_EXTENTS: u8 = 2;
pub(super) const FMT_BTREE: u8 = 3;

pub(super) const S_IFDIR: u16 = 0x4000;
pub(super) const S_IFREG: u16 = 0x8000;
pub(super) const S_IFLNK: u16 = 0xa000;

const FORK_FORMATS: EnumTable = &[
    (0, "device"),
    (1, "local (inline)"),
    (2, "extents"),
    (3, "B+tree"),
    (4, "UUID"),
    (5, "metadata B+tree"),
];

const DI_FLAGS: FlagTable = &[
    flag(0x0001, "REALTIME"),
    flag(0x0002, "PREALLOC"),
    flag(0x0004, "NEWRTBM"),
    flag(0x0008, "IMMUTABLE"),
    flag(0x0010, "APPEND"),
    flag(0x0020, "SYNC"),
    flag(0x0040, "NOATIME"),
    flag(0x0080, "NODUMP"),
    flag(0x0100, "RTINHERIT"),
    flag(0x0200, "PROJINHERIT"),
    flag(0x0400, "NOSYMLINKS"),
    flag(0x0800, "EXTSIZE"),
    flag(0x1000, "EXTSZINHERIT"),
    flag(0x2000, "NODEFRAG"),
    flag(0x4000, "FILESTREAM"),
];

const DI_FLAGS2: FlagTable = &[
    flag(0x01, "DAX"),
    flag(0x02, "REFLINK"),
    flag(0x04, "COWEXTSIZE"),
    flag(0x08, "BIGTIME"),
    flag(0x10, "NREXT64"),
    flag(0x20, "METADATA"),
];

/// One mapping of a fork: `count` blocks from logical block `off` at
/// absolute filesystem block `fsb`.
#[derive(Clone, Copy, Debug)]
pub(super) struct Ext {
    pub(super) off: u64,
    pub(super) fsb: u64,
    pub(super) count: u64,
    pub(super) unwritten: bool,
}

/// Decodes a packed 128-bit extent record (`xfs_bmbt_rec`).
pub(super) fn decode_ext(rec: &[u8]) -> Option<Ext> {
    let l0 = u64_be(rec, 0)?;
    let l1 = u64_be(rec, 8)?;
    Some(Ext {
        unwritten: l0 >> 63 != 0,
        off: (l0 & 0x7fff_ffff_ffff_ffff) >> 9,
        fsb: ((l0 & 0x1ff) << 43) | (l1 >> 21),
        count: l1 & 0x1f_ffff,
    })
}

/// An inode as read from disk, with the fields the dissector uses.
pub(super) struct Dinode {
    pub(super) span: Span,
    pub(super) raw: Vec<u8>,
    pub(super) version: u8,
    pub(super) mode: u16,
    pub(super) format: u8,
    pub(super) aformat: u8,
    /// Attribute fork offset in bytes (0: no attribute fork).
    pub(super) forkoff: u64,
    pub(super) size: u64,
    pub(super) nlink: u32,
    pub(super) nextents: u64,
    pub(super) anextents: u64,
    pub(super) flags: u16,
    pub(super) flags2: u64,
}

impl Dinode {
    pub(super) async fn read(cx: &Cx, fs: &Fs, ino: u64) -> Result<Dinode> {
        let span = fs.ino_span(ino)?;
        let raw = cx.read(span).await?;
        if raw.get(..2) != Some(b"IN".as_slice()) {
            return Err(Diagnostic::malformed(format!("inode {ino}: bad magic")).at(span.sub(0, 2)));
        }
        let version = raw.get(4).copied().unwrap_or(0);
        let flags2 = if version >= 3 {
            u64_be(&raw, 120).unwrap_or(0)
        } else {
            0
        };
        let nrext64 = flags2 & 0x10 != 0;
        let (nextents, anextents) = if nrext64 {
            (
                u64_be(&raw, 24).unwrap_or(0),
                u64::from(u32_be(&raw, 76).unwrap_or(0)),
            )
        } else {
            (
                u64::from(u32_be(&raw, 76).unwrap_or(0)),
                u64::from(u16_be(&raw, 80).unwrap_or(0)),
            )
        };
        Ok(Dinode {
            span,
            version,
            mode: u16_be(&raw, 2).unwrap_or(0),
            format: raw.get(5).copied().unwrap_or(0),
            aformat: raw.get(83).copied().unwrap_or(0),
            forkoff: u64::from(raw.get(82).copied().unwrap_or(0)).saturating_mul(8),
            size: u64_be(&raw, 56).unwrap_or(0),
            nlink: if version == 1 {
                u16_be(&raw, 6).unwrap_or(0).into()
            } else {
                u32_be(&raw, 16).unwrap_or(0)
            },
            nextents,
            anextents,
            flags: u16_be(&raw, 90).unwrap_or(0),
            flags2,
            raw,
        })
    }

    pub(super) fn core_len(&self) -> u64 {
        if self.version >= 3 { 176 } else { 100 }
    }

    pub(super) fn kind(&self) -> u16 {
        self.mode & 0xf000
    }

    fn literal_len(&self) -> u64 {
        self.span.len.saturating_sub(self.core_len())
    }

    /// The data fork.
    pub(super) fn dfork(&self) -> (Span, &[u8]) {
        let len = if self.forkoff != 0 {
            self.forkoff.min(self.literal_len())
        } else {
            self.literal_len()
        };
        self.region(self.core_len(), len)
    }

    /// The attribute fork, if the inode has one.
    pub(super) fn afork(&self) -> Option<(Span, &[u8])> {
        if self.forkoff == 0 {
            return None;
        }
        let start = self.core_len().saturating_add(self.forkoff);
        Some(self.region(start, self.span.len.saturating_sub(start)))
    }

    fn region(&self, start: u64, len: u64) -> (Span, &[u8]) {
        let span = self.span.sub(start, len);
        let bytes = self
            .raw
            .get(to_usize(start)..to_usize(start.saturating_add(span.len)))
            .unwrap_or_default();
        (span, bytes)
    }

    pub(super) fn summary(&self) -> String {
        let mut s = format!("{}, {}", unix_mode(self.mode.into()), size(self.size));
        if self.kind() != S_IFDIR && self.nlink > 1 {
            s.push_str(&format!(", {} links", self.nlink));
        }
        s
    }
}

#[derive(Clone, Copy, Debug)]
struct CoreCtx {
    version: u8,
    bigtime: bool,
    nrext64: bool,
    crc: Option<u32>,
    block: u64,
}

/// An inode timestamp: seconds and nanoseconds, or (bigtime) nanoseconds
/// since 1901-12-13 20:45:52 UTC.
fn time_field(f: &mut Fields<'_>, name: &'static str, bigtime: bool) -> Result<()> {
    f.u64(name)
        .with(|&v, n| {
            let (secs, ns) = if bigtime {
                (
                    i64::try_from(v / 1_000_000_000)
                        .unwrap_or(i64::MAX)
                        .saturating_sub(1i64 << 31),
                    v % 1_000_000_000,
                )
            } else {
                (i64::from((v >> 32) as u32 as i32), v & 0xffff_ffff)
            };
            let n = n.value(Value::Timestamp { unix_seconds: secs });
            if ns == 0 {
                n
            } else {
                n.summary(format!("+{ns} ns"))
            }
        })
        .emit()?;
    Ok(())
}

fn core_layout(f: &mut Fields<'_>, ctx: &CoreCtx) -> Result<()> {
    let v3 = ctx.version >= 3;
    f.ascii("Magic", 2).emit()?;
    f.u16("Mode")
        .hex()
        .with(|&m, n| n.summary(unix_mode(m.into())))
        .emit()?;
    f.u8("Version").emit()?;
    f.u8("Data fork format").enumeration(FORK_FORMATS).emit()?;
    if ctx.version == 1 {
        f.u16("Link count").emit()?;
    } else {
        f.u16("Metadata file type")
            .desc("Version 1 kept the link count here; later versions use it only for metadata directory files")
            .emit()?;
    }
    f.u32("Owner UID").emit()?;
    f.u32("Group GID").emit()?;
    f.u32("Link count").emit()?;
    f.u16("Project ID (low)").emit()?;
    f.u16("Project ID (high)").emit()?;
    if ctx.nrext64 {
        f.u64("Data fork extents").emit()?;
    } else if v3 {
        f.bytes("Padding", 8).emit()?;
    } else {
        f.bytes("Padding", 6).emit()?;
        f.u16("Flush counter").emit()?;
    }
    time_field(f, "Accessed", ctx.bigtime)?;
    time_field(f, "Modified", ctx.bigtime)?;
    time_field(f, "Changed", ctx.bigtime)?;
    f.u64("Size").with(|&v, n| n.summary(size(v))).emit()?;
    f.u64("Blocks")
        .with(|&v, n| n.summary(size(v.saturating_mul(ctx.block))))
        .desc("Blocks allocated, including extent map B+tree blocks")
        .emit()?;
    f.u32("Extent size hint (blocks)").emit()?;
    if ctx.nrext64 {
        f.u32("Attribute fork extents").emit()?;
        f.u16("Padding").emit()?;
    } else {
        f.u32("Data fork extents").emit()?;
        f.u16("Attribute fork extents").emit()?;
    }
    f.u8("Attribute fork offset")
        .with(|&v, n| {
            if v == 0 {
                n.summary("no attribute fork")
            } else {
                n.summary(format!(
                    "{} bytes into the literal area",
                    u32::from(v).saturating_mul(8)
                ))
            }
        })
        .desc("In units of 8 bytes from the end of the core")
        .emit()?;
    f.u8("Attribute fork format")
        .enumeration(FORK_FORMATS)
        .emit()?;
    f.u32("DMAPI event mask").emit()?;
    f.u16("DMAPI state").emit()?;
    f.u16("Flags").hex().flags(DI_FLAGS).emit()?;
    f.u32("Generation").emit()?;
    f.u32("Next unlinked inode")
        .with(|&v, n| {
            if v == u32::MAX {
                n.summary("none")
            } else {
                n.summary(format!("AG inode {v}"))
            }
        })
        .emit()?;
    if v3 {
        crc_field(f, ctx.crc)?;
        f.u64("Change count").emit()?;
        f.u64("LSN").hex().with(lsn_summary).emit()?;
        f.u64("Flags 2").hex().flags(DI_FLAGS2).emit()?;
        f.u32("Copy-on-write extent size hint").emit()?;
        f.bytes("Padding", 12).emit()?;
        time_field(f, "Created", ctx.bigtime)?;
        f.u64("Inode number").emit()?;
        f.bytes("UUID", 16).with(uuid_value).emit()?;
    }
    Ok(())
}

#[derive(Clone)]
struct ForkCtx {
    fs: FsRef,
    format: u8,
    kind: u16,
    count: u64,
    attr: bool,
    size: u64,
}

/// A data or attribute fork stored in the inode (device, local, extents).
fn fork_layout(f: &mut Fields<'_>, ctx: &ForkCtx) -> Result<()> {
    match ctx.format {
        FMT_DEV if !ctx.attr => {
            f.u32("Device number")
                .hex()
                .with(|&v, n| {
                    n.summary(format!(
                        "major {}, minor {}",
                        (v >> 18) & 0x3fff,
                        v & 0x3_ffff
                    ))
                })
                .emit()?;
        }
        FMT_LOCAL if ctx.attr => super::attr::sf_layout(f, &ctx.fs)?,
        FMT_LOCAL if ctx.kind == S_IFDIR => super::dir::sf_layout(f, &ctx.fs)?,
        FMT_LOCAL => {
            let len = ctx.size.min(f.remaining());
            let span = f.peek_span(len);
            let bytes = f
                .block()
                .data
                .get(to_usize(f.pos())..to_usize(f.pos().saturating_add(len)))
                .unwrap_or_default();
            let name = if ctx.kind == S_IFLNK {
                "Target"
            } else {
                "Inline data"
            };
            f.node(
                Node::new(name)
                    .span(span)
                    .value(Value::Text(String::from_utf8_lossy(bytes).into_owned())),
            );
            f.skip(len);
        }
        FMT_EXTENTS => {
            let max = f.remaining() / 16;
            let n = ctx.count.min(max);
            for i in 0..n {
                let pos = to_usize(f.pos());
                let rec = f
                    .block()
                    .data
                    .get(pos..pos.saturating_add(16))
                    .unwrap_or_default();
                f.node(ext_node(
                    &ctx.fs,
                    format!("Extent {i}"),
                    f.peek_span(16),
                    rec,
                ));
                f.skip(16);
            }
        }
        _ => {}
    }
    rest_unused(f, "Unused");
    Ok(())
}

fn fork_node(fs: &FsRef, di: &Dinode, attr: bool, span: Span) -> Node {
    let (format, count) = if attr {
        (di.aformat, di.anextents)
    } else {
        (di.format, di.nextents)
    };
    let name = if attr { "Attribute fork" } else { "Data fork" };
    let what = crate::value::lookup(FORK_FORMATS, format.into()).unwrap_or("unknown format");
    let summary = match format {
        FMT_EXTENTS => format!(
            "{what}, {count} extent{}, {}",
            if count == 1 { "" } else { "s" },
            size(span.len)
        ),
        FMT_BTREE => format!("{what}, {count} extents, {}", size(span.len)),
        _ => format!("{what}, {}", size(span.len)),
    };
    if format == FMT_BTREE {
        return Node::new(name)
            .span(span)
            .summary(summary)
            .lazy(bmdr_root, (fs.clone(), span));
    }
    if format > FMT_BTREE || (attr && format == FMT_DEV) {
        return Node::new(name)
            .span(span)
            .summary(summary)
            .diag(Diagnostic::unsupported(format!("fork format {format}")));
    }
    struct_node(
        name,
        span,
        BE,
        ForkCtx {
            fs: fs.clone(),
            format,
            kind: di.kind(),
            count,
            attr,
            size: di.size,
        },
        fork_layout,
    )
    .summary(summary)
}

/// A fork's extents, sorted by logical block, and any problem met.
pub(super) async fn extents(
    cx: &Cx,
    fs: &Fs,
    di: &Dinode,
    attr: bool,
) -> Result<(Vec<Ext>, Option<Diagnostic>)> {
    let (format, count, fork) = if attr {
        match di.afork() {
            Some((_, bytes)) => (di.aformat, di.anextents, bytes),
            None => return Ok((Vec::new(), None)),
        }
    } else {
        (di.format, di.nextents, di.dfork().1)
    };
    // (logical block, arrival) -> extent, so ties keep their order.
    let mut map: BTreeMap<(u64, usize), Ext> = BTreeMap::new();
    let mut problem = None;
    match format {
        FMT_EXTENTS => {
            let n = to_usize(count.min(to_u64(fork.len()) / 16));
            for (i, rec) in fork.as_chunks::<16>().0.iter().take(n).enumerate() {
                if let Some(e) = decode_ext(rec) {
                    map.insert((e.off, i), e);
                }
            }
        }
        FMT_BTREE => {
            let level = u16_be(fork, 0).unwrap_or(0);
            let numrecs = u64::from(u16_be(fork, 2).unwrap_or(0));
            let max = to_u64(fork.len()).saturating_sub(4) / 16;
            let ptrs = 4u64.saturating_add(max.saturating_mul(8));
            let mut stack: Vec<(u64, u32)> = Vec::new();
            for i in 0..numrecs.min(max) {
                let at = to_usize(ptrs.saturating_add(i.saturating_mul(8)));
                if let Some(p) = u64_be(fork, at) {
                    stack.push((p, u32::from(level).saturating_sub(1)));
                }
            }
            let hdr: usize = if fs.v5 { 72 } else { 24 };
            let magic: &[u8] = if fs.v5 { b"BMA3" } else { b"BMAP" };
            let mut seen = HashSet::new();
            while let Some((fsb, want)) = stack.pop() {
                cx.checkpoint().await;
                if !fs.fsb_valid(fsb) || !seen.insert(fsb) {
                    problem = Some(Diagnostic::malformed(format!(
                        "extent map B+tree: bad or repeated block {fsb}"
                    )));
                    break;
                }
                let block = cx.read(fs.fsb_span(fsb, 1)).await?;
                if block.get(..4) != Some(magic) {
                    problem = Some(Diagnostic::malformed(format!(
                        "extent map B+tree: block {fsb} has a bad magic"
                    )));
                    break;
                }
                let lvl = u32::from(u16_be(&block, 4).unwrap_or(0));
                if lvl != want {
                    problem = Some(Diagnostic::malformed(format!(
                        "extent map B+tree: block {fsb} at level {lvl}, expected {want}"
                    )));
                    break;
                }
                let n = u64::from(u16_be(&block, 6).unwrap_or(0));
                let body = block.get(hdr..).unwrap_or_default();
                let max = to_u64(body.len()) / 16;
                let n = n.min(max);
                if lvl == 0 {
                    for rec in body.as_chunks::<16>().0.iter().take(to_usize(n)) {
                        if let Some(e) = decode_ext(rec) {
                            let arrival = map.len();
                            map.insert((e.off, arrival), e);
                        }
                    }
                    if map.len() >= MAX_EXTENTS {
                        problem = Some(Diagnostic::limit("too many extents"));
                        break;
                    }
                } else {
                    let ptrs = max.saturating_mul(8);
                    for i in (0..n).rev() {
                        let at = to_usize(ptrs.saturating_add(i.saturating_mul(8)));
                        if let Some(p) = u64_be(body, at) {
                            stack.push((p, lvl.saturating_sub(1)));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    let mut out = Vec::with_capacity(map.len());
    for (i, e) in map.into_values().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        out.push(e);
    }
    Ok((out, problem))
}

/// The extent mapping logical block `lblk`, if any (`exts` sorted).
pub(super) fn lookup(exts: &[Ext], lblk: u64) -> Option<Ext> {
    let i = exts.partition_point(|e| e.off <= lblk);
    let e = exts.get(i.checked_sub(1)?)?;
    (lblk < e.off.saturating_add(e.count)).then_some(*e)
}

/// The physical span of `count` logical blocks from `lblk` (assembled from
/// pieces if they are not contiguous); `None` if a block is not mapped.
pub(super) async fn logical_span(
    cx: &Cx,
    fs: &Fs,
    exts: &[Ext],
    lblk: u64,
    count: u64,
    transform: &'static str,
) -> Result<Option<Span>> {
    let mut pieces: Vec<Span> = Vec::new();
    let mut b = lblk;
    let end = lblk.saturating_add(count);
    while b < end {
        let Some(e) = lookup(exts, b) else {
            return Ok(None);
        };
        if !fs.fsb_valid(e.fsb) {
            return Ok(None);
        }
        let within = b.saturating_sub(e.off);
        let take = e
            .count
            .saturating_sub(within)
            .min(end.saturating_sub(b))
            .max(1);
        let span = fs.fsb_span(e.fsb.saturating_add(within), take);
        match pieces.last_mut() {
            Some(prev) if prev.source == span.source && prev.end() == span.offset => {
                prev.len = prev.len.saturating_add(span.len);
            }
            _ => pieces.push(span),
        }
        b = b.saturating_add(take);
    }
    match pieces.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(*one)),
        [first, ..] => Ok(Some(
            crate::formats::disk::assemble(cx, *first, transform, &pieces).await?,
        )),
    }
}

/// Shows an inode: its core, its forks and what they hold.
pub(super) async fn view(cx: Cx, (fs, ino): (FsRef, u64)) -> Result<()> {
    let di = Dinode::read(&cx, &fs, ino).await?;
    cx.annotate(di.summary());
    let computed = if di.version >= 3 {
        crc(&di.raw, 100)
    } else {
        None
    };
    let mut core = struct_node(
        "Core",
        di.span.sub(0, di.core_len()),
        BE,
        CoreCtx {
            version: di.version,
            bigtime: di.flags2 & 0x8 != 0,
            nrext64: di.flags2 & 0x10 != 0,
            crc: computed,
            block: fs.block,
        },
        core_layout,
    )
    .summary(format!("inode {ino}, version {}", di.version));
    if let Some(d) = (di.version >= 3)
        .then(|| super::crc_diag(&di.raw, 100, "inode"))
        .flatten()
    {
        core = core.diag(d);
    }
    cx.emit(core);
    let (dspan, _) = di.dfork();
    cx.emit(fork_node(&fs, &di, false, dspan));
    if let Some((aspan, _)) = di.afork() {
        cx.emit(fork_node(&fs, &di, true, aspan));
    }
    let mapped = matches!(di.format, FMT_EXTENTS | FMT_BTREE);
    match di.kind() {
        S_IFREG => file_content(&cx, &fs, &di).await?,
        S_IFDIR if mapped => cx.emit(
            Node::new("Directory blocks")
                .summary(size(di.size))
                .lazy(super::dir::blocks, (fs.clone(), ino)),
        ),
        S_IFLNK if mapped => symlink(&cx, &fs, &di).await?,
        _ => {}
    }
    if matches!(di.aformat, FMT_EXTENTS | FMT_BTREE) && di.anextents > 0 {
        cx.emit(
            Node::new("Attribute blocks")
                .summary(format!("{} extents", di.anextents))
                .lazy(super::attr::blocks, (fs.clone(), ino)),
        );
        cx.emit(Node::new("Attributes").lazy(super::attr::list, (fs.clone(), ino)));
    }
    Ok(())
}

/// A regular file's content: its extents assembled (holes and unwritten
/// extents read as zeros).
async fn file_content(cx: &Cx, fs: &FsRef, di: &Dinode) -> Result<()> {
    if di.size == 0 {
        return Ok(());
    }
    if di.flags & 0x1 != 0 {
        cx.emit(
            Node::new("Content")
                .summary(size(di.size))
                .diag(Diagnostic::unsupported("data on the realtime device")),
        );
        return Ok(());
    }
    match di.format {
        FMT_LOCAL => {
            let (span, _) = di.dfork();
            cx.emit(content_node(&fs.input, span.sub(0, di.size)));
        }
        FMT_EXTENTS | FMT_BTREE => {
            let (exts, problem) = extents(cx, fs, di, false).await?;
            if let Some(d) = problem {
                cx.diag(d);
            }
            let size = di.size;
            let mut list = PieceList::new(di.span);
            for (i, e) in exts.iter().enumerate() {
                if i.is_multiple_of(4096) {
                    cx.checkpoint().await;
                }
                let at = e.off.saturating_mul(fs.block);
                if at >= size {
                    break;
                }
                if at > list.len() {
                    list.hole(cx, at.saturating_sub(list.len()))?;
                } else if at < list.len() {
                    cx.diag(Diagnostic::malformed(format!(
                        "overlapping extent at file block {}",
                        e.off
                    )));
                    continue;
                }
                let len = e
                    .count
                    .saturating_mul(fs.block)
                    .min(size.saturating_sub(at));
                if e.unwritten || !fs.fsb_valid(e.fsb) {
                    if !e.unwritten {
                        cx.diag(Diagnostic::malformed(format!(
                            "extent at file block {} points outside the filesystem",
                            e.off
                        )));
                    }
                    list.hole(cx, len)?;
                } else {
                    list.data(fs.fsb_span(e.fsb, e.count).sub(0, len));
                }
            }
            if list.len() < size {
                list.hole(cx, size.saturating_sub(list.len()))?;
            }
            let span = list.finish(cx, "xfs-extents").await?;
            cx.emit(fragments_node(cx, "Fragments", list.into_pieces()).await);
            cx.emit(content_node(&fs.input, span));
        }
        _ => {}
    }
    Ok(())
}

/// Header of a v5 remote symlink block (`xfs_dsymlink_hdr`) and its part
/// of the target.
fn symlink_block_layout(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    f.u32("Offset in target").emit()?;
    let bytes = f.u32("Bytes in this block").emit()?;
    crc_field(f, ctx.crc)?;
    f.bytes("UUID", 16).with(uuid_value).emit()?;
    f.u64("Owner (inode)").emit()?;
    f.u64("Disk address (512-byte units)").hex().emit()?;
    f.u64("LSN").hex().with(lsn_summary).emit()?;
    let len = u64::from(bytes).min(f.remaining());
    let pos = to_usize(f.pos());
    let text = f
        .block()
        .data
        .get(pos..pos.saturating_add(to_usize(len)))
        .unwrap_or_default();
    f.node(
        Node::new("Target (part)")
            .span(f.peek_span(len))
            .value(Value::Text(String::from_utf8_lossy(text).into_owned())),
    );
    f.skip(len);
    rest_unused(f, "Unused");
    Ok(())
}

/// A symlink whose target is stored in blocks.
async fn symlink(cx: &Cx, fs: &FsRef, di: &Dinode) -> Result<()> {
    let (exts, problem) = extents(cx, fs, di, false).await?;
    if let Some(d) = problem {
        cx.diag(d);
    }
    let mut list = PieceList::new(di.span);
    let mut left = di.size.min(4096);
    let mut lblk = 0u64;
    while left > 0 && lblk < MAX_SYMLINK_BLOCKS {
        let Some(span) = logical_span(cx, fs, &exts, lblk, 1, "xfs-symlink-block").await? else {
            cx.diag(Diagnostic::malformed(format!(
                "symlink block {lblk} is not mapped"
            )));
            break;
        };
        let data = cx.read(span).await?;
        if fs.v5 {
            let bytes = u64::from(u32_be(&data, 8).unwrap_or(0)).min(left);
            let mut node = struct_node(
                format!("Block {lblk}"),
                span,
                BE,
                HdrCtx {
                    v5: true,
                    crc: crc(&data, 12),
                },
                symlink_block_layout,
            )
            .summary(format!("{bytes} bytes of the target"));
            if data.get(..4) != Some(b"XSLM".as_slice()) {
                node = node.diag(Diagnostic::malformed("expected magic XSLM"));
            }
            cx.emit(node);
            list.data(span.sub(56, bytes));
            left = left.saturating_sub(bytes);
            if bytes == 0 {
                break;
            }
        } else {
            let take = left.min(span.len);
            cx.emit(
                Node::new(format!("Block {lblk}"))
                    .span(span.sub(0, take))
                    .summary(format!("{take} bytes of the target")),
            );
            list.data(span.sub(0, take));
            left = left.saturating_sub(take);
            if take == 0 {
                break;
            }
        }
        lblk = lblk.saturating_add(1);
    }
    let target = list.finish(cx, "xfs-symlink").await?;
    let text = cx.read_avail(target).await?;
    cx.emit(
        Node::new("Target")
            .span(target)
            .value(Value::Text(String::from_utf8_lossy(&text).into_owned())),
    );
    Ok(())
}
