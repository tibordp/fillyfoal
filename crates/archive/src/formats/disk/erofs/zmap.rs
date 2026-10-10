//! EROFS compressed files: the map header, the logical cluster ("lcluster")
//! index in its full or compact encoding, and the extents it describes.
//!
//! Each lcluster of the file is either the head of an extent (PLAIN for
//! stored data, HEAD1/HEAD2 for the first/second algorithm), giving the
//! offset in the lcluster where the extent starts and its physical cluster,
//! or a NONHEAD continuing one (whose first entry may hold the physical
//! cluster's block count). The compact encoding packs 2 (4-byte form) or 16
//! (2-byte form) lclusters with a base block address per pack.

use std::sync::Arc;

use crate::bytes::{align_up, to_u64, to_usize, u16_le, u32_le};
use crate::codec::Codec;
use crate::codec::lzma::Props;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::disk::{PieceList, size};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

use super::{ALG_NAMES, Fs, FsRef, Ino, LAYOUT_COMPRESSED_FULL, LE, data_boxed};

const ADVISE: FlagTable = &[
    flag(0x01, "COMPACTED_2B"),
    flag(0x02, "BIG_PCLUSTER_1"),
    flag(0x04, "BIG_PCLUSTER_2"),
    flag(0x08, "INLINE_PCLUSTER"),
    flag(0x10, "INTERLACED_PCLUSTER"),
    flag(0x20, "FRAGMENT_PCLUSTER"),
];

const TYPES: EnumTable = &[(0, "PLAIN"), (1, "HEAD1"), (2, "NONHEAD"), (3, "HEAD2")];
const NONHEAD: u8 = 2;
/// "This NONHEAD holds the physical cluster's block count."
const CBLKCNT: u32 = 0x800;
/// Lclusters indexed at most (1 GiB of data in 4 KiB lclusters).
const MAX_LCLUSTERS: u64 = 1 << 18;
/// MicroLZMA dictionary size when the image records none.
const DEFAULT_DICT: u32 = 8 << 20;

#[derive(Clone, Copy, Debug)]
struct Lcl {
    kind: u8,
    /// Offset in the lcluster where a head's extent starts; for a NONHEAD,
    /// its distance to the head (or the block count).
    lo: u32,
    /// A head's physical cluster start block.
    pblk: u64,
    partial: bool,
    /// A NONHEAD's physical cluster block count.
    cblk: Option<u32>,
    /// The index entry (full) or pack (compact) holding it.
    span: Span,
}

struct Map {
    hpos: u64,
    adv: u16,
    algs: u8,
    cbits: u8,
    frag: u32,
    idata: u16,
    lbits: u32,
    legacy: bool,
    ebase: u64,
    idx_end: u64,
    lcls: Vec<Lcl>,
}

#[derive(Clone, Copy, Debug)]
enum Src {
    /// Physical cluster: start block and length in bytes.
    Blocks(u64, u64),
    /// The tail's physical cluster, packed after the index.
    Inline(Span),
    /// Stored in the packed inode at this offset.
    Fragment(u64),
}

#[derive(Clone, Copy, Debug)]
struct ZExt {
    la: u64,
    llen: u64,
    /// The algorithm; `None` for stored data.
    alg: Option<u8>,
    src: Src,
    partial: bool,
    interlaced: bool,
}

fn compact_layout(ebase: u64, total: u64, adv: u16) -> (u64, u64) {
    let c4i = (32u64.saturating_sub(ebase % 32) / 4) & 7;
    let c2 = if adv & 1 != 0 && c4i < total {
        (total.saturating_sub(c4i) / 16).saturating_mul(16)
    } else {
        0
    };
    (c4i, c2)
}

/// The position of lcluster `lcn`'s entry and its size shift (2: 4-byte
/// form, 1: 2-byte form).
fn compact_pos(ebase: u64, c4i: u64, c2: u64, lcn: u64) -> (u64, u32) {
    let mut pos = ebase;
    let mut l = lcn;
    let mut ash = 2u32;
    if l >= c4i {
        pos = pos.saturating_add(c4i.saturating_mul(4));
        l = l.saturating_sub(c4i);
        if l < c2 {
            ash = 1;
        } else {
            pos = pos.saturating_add(c2.saturating_mul(2));
            l = l.saturating_sub(c2);
        }
    }
    (
        pos.saturating_add(l.checked_shl(ash).unwrap_or(u64::MAX)),
        ash,
    )
}

/// (vcnt, pack size, bits per entry) for an entry size shift.
fn pack_shape(ash: u32) -> (u64, u64, u64) {
    if ash == 2 { (2, 8, 16) } else { (16, 32, 14) }
}

/// Bits `pos..` of a pack: (low bits, type).
fn bits(pack: &[u8], lobits: u32, pos: u64) -> (u32, u8) {
    let at = to_usize(pos / 8);
    let mut w = [0u8; 4];
    for (k, b) in w.iter_mut().enumerate() {
        *b = pack.get(at.saturating_add(k)).copied().unwrap_or(0);
    }
    let v = u32::from_le_bytes(w)
        .checked_shr(u32::try_from(pos % 8).unwrap_or(0))
        .unwrap_or(0);
    let lo = v & 1u32
        .checked_shl(lobits)
        .map_or(u32::MAX, |m| m.saturating_sub(1));
    let ty = u8::try_from(v.checked_shr(lobits).unwrap_or(0) & 3).unwrap_or(0);
    (lo, ty)
}

impl Map {
    async fn read(cx: &Cx, fs: &Fs, ino: &Ino) -> Result<Map> {
        let hpos = align_up(ino.after(), 8);
        let h = cx.read(fs.vol.sub(hpos, 8)).await?;
        let adv = u16_le(&h, 4).unwrap_or(0);
        let cbits = h.get(7).copied().unwrap_or(0);
        let lbits = fs.blkbits.saturating_add(u32::from(cbits & 7));
        let legacy = ino.layout == LAYOUT_COMPRESSED_FULL;
        let ebase = hpos.saturating_add(if legacy { 16 } else { 8 });
        let mut map = Map {
            hpos,
            adv,
            algs: h.get(6).copied().unwrap_or(0),
            cbits,
            frag: u32_le(&h, 0).unwrap_or(0),
            idata: u16_le(&h, 2).unwrap_or(0),
            lbits,
            legacy,
            ebase,
            idx_end: ebase,
            lcls: Vec::new(),
        };
        if cbits & 0x80 != 0 {
            return Ok(map);
        }
        if lbits > 30 {
            return Err(Diagnostic::malformed(format!("lcluster size 2^{lbits}")));
        }
        let lsize = 1u64.checked_shl(lbits).unwrap_or(1);
        let total = ino.size.div_ceil(lsize);
        if total > MAX_LCLUSTERS {
            return Err(Diagnostic::limit(format!(
                "{total} logical clusters; at most {MAX_LCLUSTERS} are indexed"
            )));
        }
        if total == 0 {
            return Ok(map);
        }
        if legacy {
            let span = fs
                .vol
                .sub_exact(ebase, total.saturating_mul(8))
                .map_err(|_| Diagnostic::malformed("cluster index runs past the image"))?;
            let idx = cx.read(span).await?;
            for (i, e) in idx.as_chunks::<8>().0.iter().enumerate() {
                if i.is_multiple_of(4096) {
                    cx.checkpoint().await;
                }
                let advise = u16_le(e, 0).unwrap_or(0);
                let kind = u8::try_from(advise & 3).unwrap_or(0);
                let u = u32_le(e, 4).unwrap_or(0);
                let espan = span.sub(to_u64(i).saturating_mul(8), 8);
                map.lcls.push(if kind == NONHEAD {
                    let d0 = u & 0xffff;
                    Lcl {
                        kind,
                        lo: d0,
                        pblk: 0,
                        partial: false,
                        cblk: (d0 & CBLKCNT != 0).then_some(d0 & 0x7ff),
                        span: espan,
                    }
                } else {
                    Lcl {
                        kind,
                        lo: u16_le(e, 2).unwrap_or(0).into(),
                        pblk: u.into(),
                        partial: advise & 0x8000 != 0,
                        cblk: None,
                        span: espan,
                    }
                });
            }
            map.idx_end = span.end().saturating_sub(fs.vol.offset);
            return Ok(map);
        }
        let (c4i, c2) = compact_layout(ebase, total, adv);
        let (last, ash) = compact_pos(ebase, c4i, c2, total.saturating_sub(1));
        let (_, packsz, _) = pack_shape(ash);
        let end = last
            .saturating_sub(last.checked_rem(packsz).unwrap_or(0))
            .saturating_add(packsz);
        let span = fs
            .vol
            .sub_exact(ebase, end.saturating_sub(ebase))
            .map_err(|_| Diagnostic::malformed("cluster index runs past the image"))?;
        let idx = cx.read(span).await?;
        let lobits = lbits.max(12);
        let big = adv & 0x2 != 0;
        for lcn in 0..total {
            if lcn.is_multiple_of(4096) {
                cx.checkpoint().await;
            }
            let (pos, ash) = compact_pos(ebase, c4i, c2, lcn);
            if (ash == 2 && lbits > 14) || (ash == 1 && lbits > 12) {
                return Err(Diagnostic::unsupported(format!(
                    "compact index with 2^{lbits}-byte lclusters"
                )));
            }
            let (_, packsz, encodebits) = pack_shape(ash);
            let within = pos.checked_rem(packsz).unwrap_or(0);
            let pstart = pos.saturating_sub(within);
            let i = within.checked_shr(ash).unwrap_or(0);
            let rel = to_usize(pstart.saturating_sub(ebase));
            let pack = idx
                .get(rel..rel.saturating_add(to_usize(packsz)))
                .ok_or_else(|| Diagnostic::malformed("cluster index pack out of range"))?;
            let pspan = fs.vol.sub(pstart, packsz);
            let (lo, kind) = bits(pack, lobits, encodebits.saturating_mul(i));
            if kind == NONHEAD {
                map.lcls.push(Lcl {
                    kind,
                    lo,
                    pblk: 0,
                    partial: false,
                    cblk: (lo & CBLKCNT != 0).then_some(lo & 0x7ff),
                    span: pspan,
                });
                continue;
            }
            // Count the physical blocks of the heads before this one in
            // the pack (as the kernel's z_erofs_load_compact_lcluster does).
            let mut nblk: u64 = if big { 0 } else { 1 };
            let mut j = i64::try_from(i).unwrap_or(0);
            let entry = |j: i64| {
                bits(
                    pack,
                    lobits,
                    encodebits.saturating_mul(u64::try_from(j).unwrap_or(0)),
                )
            };
            if big {
                while j > 0 {
                    j = j.saturating_sub(1);
                    let (l2, t2) = entry(j);
                    if t2 == NONHEAD {
                        if l2 & CBLKCNT != 0 {
                            j = j.saturating_sub(1);
                            nblk = nblk.saturating_add((l2 & 0x7ff).into());
                            continue;
                        }
                        if l2 <= 1 {
                            return Err(Diagnostic::malformed(format!(
                                "lcluster {lcn}: bad NONHEAD distance in a big cluster pack"
                            ))
                            .at(pspan));
                        }
                        j = j.saturating_sub(i64::from(l2).saturating_sub(2));
                        continue;
                    }
                    nblk = nblk.saturating_add(1);
                }
            } else {
                while j > 0 {
                    j = j.saturating_sub(1);
                    let (l2, t2) = entry(j);
                    if t2 == NONHEAD {
                        j = j.saturating_sub(l2.into());
                    }
                    if j >= 0 {
                        nblk = nblk.saturating_add(1);
                    }
                }
            }
            let base_at = to_usize(packsz.saturating_sub(4));
            let base = u64::from(u32_le(pack, base_at).unwrap_or(0));
            map.lcls.push(Lcl {
                kind,
                lo,
                pblk: base.saturating_add(nblk),
                partial: false,
                cblk: None,
                span: pspan,
            });
        }
        map.idx_end = end;
        Ok(map)
    }

    fn whole_fragment(&self) -> bool {
        self.cbits & 0x80 != 0
    }

    /// The extents the index describes, and any problem met.
    fn extents(&self, fs: &Fs, size: u64) -> (Vec<ZExt>, Option<Diagnostic>) {
        let interlaced = self.adv & 0x10 != 0;
        if self.whole_fragment() {
            return (
                vec![ZExt {
                    la: 0,
                    llen: size,
                    alg: None,
                    src: Src::Fragment(self.frag.into()),
                    partial: false,
                    interlaced: false,
                }],
                None,
            );
        }
        let lsize = 1u64.checked_shl(self.lbits).unwrap_or(1);
        let heads: Vec<(usize, u64)> = self
            .lcls
            .iter()
            .enumerate()
            .filter(|(_, l)| l.kind != NONHEAD)
            .map(|(lcn, l)| {
                (
                    lcn,
                    to_u64(lcn)
                        .saturating_mul(lsize)
                        .saturating_add(l.lo.into()),
                )
            })
            .collect();
        let mut out = Vec::new();
        let mut problem = None;
        for (k, &(lcn, la)) in heads.iter().enumerate() {
            if la >= size {
                continue;
            }
            let end = heads
                .get(k.saturating_add(1))
                .map_or(size, |&(_, next)| next.min(size));
            if end <= la {
                problem = Some(Diagnostic::malformed(format!(
                    "lcluster {lcn}: extent ends before it starts"
                )));
                continue;
            }
            let Some(head) = self.lcls.get(lcn) else {
                continue;
            };
            let big = if head.kind == 1 {
                self.adv & 0x2 != 0
            } else {
                self.adv & 0x4 != 0
            };
            let bytes = if big {
                let blocks = self
                    .lcls
                    .get(lcn.saturating_add(1))
                    .filter(|n| n.kind == NONHEAD)
                    .and_then(|n| n.cblk)
                    .unwrap_or(1);
                u64::from(blocks).saturating_mul(fs.blk)
            } else {
                lsize
            };
            let alg = match head.kind {
                1 => Some(self.algs & 0xf),
                3 => Some(self.algs >> 4),
                _ => None,
            };
            out.push(ZExt {
                la,
                llen: end.saturating_sub(la),
                alg,
                src: Src::Blocks(head.pblk, bytes),
                partial: head.partial,
                interlaced: interlaced && alg.is_none(),
            });
        }
        if let Some(last) = out.last_mut() {
            if self.adv & 0x8 != 0 {
                last.src = Src::Inline(fs.vol.sub(self.idx_end, self.idata.into()));
            } else if self.adv & 0x20 != 0 {
                last.src = Src::Fragment(self.frag.into());
                last.alg = None;
                last.interlaced = false;
            }
        }
        (out, problem)
    }
}

/// The packed inode's data, for fragments.
async fn packed_data(cx: &Cx, fs: &Fs, depth: u32) -> Result<Span> {
    if depth > 0 {
        return Err(Diagnostic::malformed("a fragment inside the packed inode"));
    }
    let nid = fs
        .packed_nid
        .ok_or_else(|| Diagnostic::malformed("a fragment, but no packed inode"))?;
    let ino = Ino::read(cx, fs, nid).await?;
    data_boxed(cx, fs, &ino, depth.saturating_add(1)).await
}

/// The compressed bytes of a physical cluster without its leading zero
/// padding.
async fn unpadded(cx: &Cx, fs: &Fs, input: Span) -> Result<Span> {
    if !fs.zero_padding {
        return Ok(input);
    }
    let head = cx.read_avail(input.sub(0, fs.blk)).await?;
    let zeros = head.iter().position(|&b| b != 0).unwrap_or(head.len());
    Ok(input.tail(to_u64(zeros)))
}

/// The decoded bytes of a compressed physical cluster (lazily decoded).
async fn decoded(cx: &Cx, fs: &Fs, input: Span, alg: u8, llen: u64) -> Result<Span> {
    let input = unpadded(cx, fs, input).await?;
    let (src, codec) = match alg {
        0 => (input, Codec::Lz4Block),
        2 => (input, Codec::Deflate),
        3 => (input, Codec::Zstd),
        1 => {
            // MicroLZMA: the first byte is the inverted properties byte, in
            // place of the range coder's first byte (always zero).
            let first = cx.read(input.sub(0, 1)).await?;
            let b = first.first().copied().unwrap_or(0);
            let props = Props::from_byte(!b).map_err(|d| d.at(input.sub(0, 1)))?;
            let src = cx.add_pieces(
                Origin {
                    parent: input,
                    transform: "erofs-microlzma",
                },
                vec![Span::zeros(1), input.tail(1)],
            )?;
            (
                src,
                Codec::LzmaRaw {
                    props,
                    size: Some(to_usize(llen)),
                    dict: Some(fs.lzma_dict.unwrap_or(DEFAULT_DICT).max(4096)),
                },
            )
        }
        other => {
            return Err(Diagnostic::unsupported(format!(
                "compression algorithm {other}"
            )));
        }
    };
    cx.decode_lazy(src, &codec, llen)
}

/// The physical span of an extent's cluster (none for fragments).
fn physical(fs: &Fs, e: &ZExt) -> Option<Span> {
    match e.src {
        Src::Blocks(pblk, bytes) => Some(fs.vol.sub(pblk.saturating_mul(fs.blk), bytes)),
        Src::Inline(span) => Some(span),
        Src::Fragment(_) => None,
    }
}

/// The pieces of an extent's data.
async fn extent_pieces(
    cx: &Cx,
    fs: &Fs,
    e: &ZExt,
    packed: &mut Option<Span>,
    depth: u32,
) -> Result<Vec<Span>> {
    if let Src::Fragment(off) = e.src {
        let p = match packed {
            Some(p) => *p,
            None => {
                let p = packed_data(cx, fs, depth).await?;
                *packed = Some(p);
                p
            }
        };
        return Ok(vec![p.sub(off, e.llen)]);
    }
    let Some(input) = physical(fs, e) else {
        return Ok(Vec::new());
    };
    match e.alg {
        None if e.interlaced => {
            // The extent's first bytes (up to the end of its block) are at
            // the end of the cluster, the rest at its start.
            let first = fs
                .blk
                .saturating_sub(e.la.checked_rem(fs.blk).unwrap_or(0))
                .min(e.llen);
            Ok(vec![
                input.sub(input.len.saturating_sub(first), first),
                input.sub(0, e.llen.saturating_sub(first)),
            ])
        }
        None => Ok(vec![input.sub(0, e.llen)]),
        Some(alg) => Ok(vec![
            decoded(cx, fs, input, alg, e.llen).await?.sub(0, e.llen),
        ]),
    }
}

/// A compressed file's content, assembled from its extents.
pub(super) async fn content(cx: &Cx, fs: &Fs, ino: &Ino, depth: u32) -> Result<Span> {
    let map = Map::read(cx, fs, ino).await?;
    let (exts, problem) = map.extents(fs, ino.size);
    if let Some(d) = problem {
        cx.diag(d);
    }
    let mut list = PieceList::new(ino.core_span(fs));
    let mut packed = None;
    for e in &exts {
        cx.checkpoint().await;
        if e.la > list.len() {
            list.hole(cx, e.la.saturating_sub(list.len()))?;
        } else if e.la < list.len() {
            continue;
        }
        for piece in extent_pieces(cx, fs, e, &mut packed, depth).await? {
            list.data(piece);
        }
    }
    if list.len() < ino.size {
        list.hole(cx, ino.size.saturating_sub(list.len()))?;
    }
    list.finish(cx, "erofs-data").await
}

#[derive(Clone, Copy, Debug)]
struct HeaderCtx {
    fragment_off: bool,
    legacy: bool,
}

fn header_layout(f: &mut Fields<'_>, ctx: &HeaderCtx) -> Result<()> {
    if ctx.fragment_off {
        f.u32("Fragment offset")
            .desc("Offset of this file's fragment in the packed inode")
            .emit()?;
    } else {
        f.u16("Reserved").emit()?;
        f.u16("Inline cluster size")
            .desc("Compressed size of the tail cluster packed after the index")
            .emit()?;
    }
    f.u16("Advice").hex().flags(ADVISE).emit()?;
    f.u8("Algorithms")
        .with(|&v, n| {
            n.summary(format!(
                "HEAD1 {}, HEAD2 {}",
                lookup(ALG_NAMES, (v & 0xf).into()).unwrap_or("unknown"),
                lookup(ALG_NAMES, (v >> 4).into()).unwrap_or("unknown")
            ))
        })
        .desc("Low 4 bits: the algorithm of HEAD1 clusters; high 4 bits: of HEAD2 clusters")
        .emit()?;
    f.u8("Cluster bits")
        .with(|&v, n| {
            if v & 0x80 != 0 {
                n.summary("the whole file is a fragment")
            } else {
                n.summary(format!("lclusters of 2^{} blocks", v & 7))
            }
        })
        .desc("Bits 0–2: log2 of the lcluster size in blocks; bit 7: the whole file is in the packed inode")
        .emit()?;
    if ctx.legacy {
        f.bytes("Reserved", 8).emit()?;
    }
    Ok(())
}

fn legacy_entry_layout(f: &mut Fields<'_>, kind: &u8) -> Result<()> {
    f.u16("Advice")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}{}",
                lookup(TYPES, (v & 3).into()).unwrap_or("?"),
                if v & 0x8000 != 0 {
                    ", partial reference"
                } else {
                    ""
                }
            ))
        })
        .desc("Bits 0–1: lcluster type; bit 15: the extent uses part of its cluster's output")
        .emit()?;
    f.u16("Cluster offset").emit()?;
    if *kind == NONHEAD {
        f.u16("Delta 0")
            .with(|&v, n| {
                if u32::from(v) & CBLKCNT != 0 {
                    n.summary(format!("{} compressed blocks", v & 0x7ff))
                } else {
                    n.summary(format!("{v} lclusters after the head"))
                }
            })
            .emit()?;
        f.u16("Delta 1")
            .with(|&v, n| n.summary(format!("{v} lclusters to the next head")))
            .emit()?;
    } else {
        f.u32("Start block").emit()?;
    }
    Ok(())
}

fn lcl_summary(l: &Lcl) -> String {
    let kind = lookup(TYPES, l.kind.into()).unwrap_or("?");
    if l.kind == NONHEAD {
        match l.cblk {
            Some(n) => format!("{kind}, cluster of {n} blocks"),
            None => format!("{kind}, distance {}", l.lo),
        }
    } else {
        format!(
            "{kind} at offset {}, block {}{}",
            l.lo,
            l.pblk,
            if l.partial { ", partial" } else { "" }
        )
    }
}

/// Shows an inode's compression map.
pub(super) async fn view(cx: Cx, (fs, nid): (FsRef, u64)) -> Result<()> {
    let ino = Ino::read(&cx, &fs, nid).await?;
    let map = Map::read(&cx, &fs, &ino).await?;
    let hlen: u64 = if map.legacy { 16 } else { 8 };
    cx.emit(
        struct_node(
            "Map header",
            fs.vol.sub(map.hpos, hlen),
            LE,
            HeaderCtx {
                fragment_off: map.whole_fragment() || map.adv & 0x20 != 0,
                legacy: map.legacy,
            },
            header_layout,
        )
        .summary(format!(
            "{}, lclusters of {}",
            lookup(ALG_NAMES, (map.algs & 0xf).into()).unwrap_or("unknown algorithm"),
            size(1u64.checked_shl(map.lbits).unwrap_or(0))
        )),
    );
    if !map.lcls.is_empty() {
        let index = Span::new(
            fs.vol.source,
            fs.vol.offset.saturating_add(map.ebase),
            map.idx_end.saturating_sub(map.ebase),
        );
        let lcls: Arc<Vec<Lcl>> = Arc::new(map.lcls.clone());
        cx.emit(
            Node::new("Cluster index")
                .span(index)
                .summary(format!(
                    "{} lclusters, {} form",
                    lcls.len(),
                    if map.legacy { "full" } else { "compact" }
                ))
                .lazy(index_view, (lcls, map.legacy)),
        );
    }
    let (exts, problem) = map.extents(&fs, ino.size);
    if let Some(d) = problem {
        cx.diag(d);
    }
    if map.adv & 0x8 != 0
        && let Some(Src::Inline(span)) = exts.last().map(|e| e.src)
    {
        cx.emit(
            Node::new("Inline cluster")
                .span(span)
                .summary(format!("{}, the tail's compressed data", size(span.len))),
        );
    }
    let mut end = if map.lcls.is_empty() {
        map.hpos.saturating_add(hlen)
    } else {
        map.idx_end
    };
    if map.adv & 0x8 != 0 {
        end = end.saturating_add(map.idata.into());
    }
    let aligned = align_up(end, 32);
    cx.emit(
        Node::new("Extents")
            .summary(format!("{} extents", exts.len()))
            .lazy(extents_view, (fs.clone(), Arc::new(exts))),
    );
    if aligned > end {
        cx.emit(
            Node::new("Padding")
                .span(fs.vol.sub(end, aligned.saturating_sub(end)))
                .summary("to the next inode slot"),
        );
    }
    Ok(())
}

async fn index_view(cx: Cx, (lcls, legacy): (Arc<Vec<Lcl>>, bool)) -> Result<()> {
    if legacy {
        for (lcn, l) in lcls.iter().enumerate() {
            cx.push(
                struct_node(
                    format!("Lcluster {lcn}"),
                    l.span,
                    LE,
                    l.kind,
                    legacy_entry_layout,
                )
                .summary(lcl_summary(l)),
            )
            .await;
        }
        return Ok(());
    }
    // Compact: group the lclusters by pack.
    let mut start = 0usize;
    let mut pack_no = 0usize;
    while start < lcls.len() {
        let Some(first) = lcls.get(start) else { break };
        let span = first.span;
        let mut end = start;
        while lcls.get(end).is_some_and(|l| l.span == span) {
            end = end.saturating_add(1);
        }
        let members: Vec<(usize, Lcl)> = (start..end)
            .filter_map(|i| lcls.get(i).map(|l| (i, *l)))
            .collect();
        let base_raw = cx.read(span.sub(span.len.saturating_sub(4), 4)).await?;
        cx.push(
            Node::new(format!("Pack {pack_no}"))
                .span(span)
                .summary(format!(
                    "lclusters {start}–{}, base block {}",
                    end.saturating_sub(1),
                    u32_le(&base_raw, 0).unwrap_or(0)
                ))
                .lazy(pack_view, (span, Arc::new(members))),
        )
        .await;
        start = end;
        pack_no = pack_no.saturating_add(1);
    }
    Ok(())
}

async fn pack_view(cx: Cx, (span, members): (Span, Arc<Vec<(usize, Lcl)>>)) -> Result<()> {
    let n = to_u64(members.len()).max(1);
    let entries = span.sub(0, span.len.saturating_sub(4));
    // Entries are bit-packed; each is shown over its share of the pack.
    let share = entries.len.checked_div(n).unwrap_or(0);
    for (k, (lcn, l)) in members.iter().enumerate() {
        cx.emit(
            Node::new(format!("Lcluster {lcn}"))
                .span(entries.sub(to_u64(k).saturating_mul(share), share))
                .value(Value::Enum {
                    raw: l.kind.into(),
                    bits: 2,
                    name: lookup(TYPES, l.kind.into()),
                })
                .summary(lcl_summary(l)),
        );
    }
    let base = span.sub(span.len.saturating_sub(4), 4);
    let raw = cx.read(base).await?;
    cx.emit(
        Node::new("Base block")
            .span(base)
            .value(Value::UInt {
                value: u32_le(&raw, 0).unwrap_or(0).into(),
                bits: 32,
                radix: crate::value::Radix::Dec,
            })
            .desc("Physical block of the first head cluster in this pack"),
    );
    Ok(())
}

async fn extents_view(cx: Cx, (fs, exts): (FsRef, Arc<Vec<ZExt>>)) -> Result<()> {
    for (i, e) in exts.iter().enumerate() {
        let what = match e.alg {
            Some(a) => lookup(ALG_NAMES, a.into()).unwrap_or("unknown algorithm"),
            None => "stored",
        };
        let place = match e.src {
            Src::Blocks(pblk, bytes) => format!("cluster at block {pblk}, {}", size(bytes)),
            Src::Inline(span) => format!("inline cluster, {}", size(span.len)),
            Src::Fragment(off) => format!("fragment at byte {off} of the packed inode"),
        };
        let mut node = Node::new(format!("Extent {i}")).summary(format!(
            "bytes {}–{} ({}), {what}, {place}{}",
            e.la,
            e.la.saturating_add(e.llen).saturating_sub(1),
            size(e.llen),
            if e.partial { ", partial" } else { "" }
        ));
        if let Some(span) = physical(&fs, e) {
            node = node.span(span);
        }
        cx.push(node.lazy(extent_view, (fs.clone(), *e))).await;
    }
    Ok(())
}

async fn extent_view(cx: Cx, (fs, e): (FsRef, ZExt)) -> Result<()> {
    if let Src::Fragment(_) = e.src {
        let mut packed = None;
        let pieces = extent_pieces(&cx, &fs, &e, &mut packed, 0).await?;
        for p in pieces {
            cx.emit(Node::new("Fragment").span(p).summary(size(p.len)));
        }
        return Ok(());
    }
    let Some(input) = physical(&fs, &e) else {
        return Ok(());
    };
    match e.alg {
        Some(alg) => {
            let data = unpadded(&cx, &fs, input).await?;
            let pad = data.offset.saturating_sub(input.offset);
            if pad > 0 {
                cx.emit(
                    Node::new("Zero padding")
                        .span(input.sub(0, pad))
                        .summary(size(pad))
                        .desc("Compressed data is aligned to the end of its cluster"),
                );
            }
            let out = decoded(&cx, &fs, input, alg, e.llen).await?;
            cx.emit(
                Node::new("Compressed data")
                    .span(data)
                    .summary(size(data.len))
                    .lazy(decoded_view, out.sub(0, e.llen)),
            );
        }
        None => {
            let mut packed = None;
            for p in extent_pieces(&cx, &fs, &e, &mut packed, 0).await? {
                cx.emit(Node::new("Stored data").span(p).summary(size(p.len)));
            }
        }
    }
    Ok(())
}

async fn decoded_view(cx: Cx, out: Span) -> Result<()> {
    cx.emit(Node::new("Decompressed").span(out).summary(size(out.len)));
    Ok(())
}
