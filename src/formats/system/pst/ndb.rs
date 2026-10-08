//! The node database (NDB) layer: pages, the node and block B-trees,
//! blocks, data trees and subnode trees ([MS-PST] 2.2).

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::codec::crc::Crc;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::Input;
use crate::span::{Origin, Span};

/// [MS-PST]'s CRC: CRC-32 (reflected 0x04C11DB7) with no initial or
/// final inversion.
pub const PST_CRC: Crc = Crc::new(32, 0x04c1_1db7, 0, true, 0);

pub const PTYPE_BBT: u8 = 0x80;
pub const PTYPE_NBT: u8 = 0x81;

/// Maximum depth of a B-tree (levels are a byte; real files have 2-4).
const MAX_LEVELS: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ansi,
    Unicode,
    /// Unicode with 4 KiB pages (OST, Outlook 2013 and later).
    Unicode4k,
}

/// Where a page or block lives: its ID and file offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Bref {
    pub bid: u64,
    pub ib: u64,
}

/// What every expander needs to read the file.
#[derive(Clone, Copy, Debug)]
pub struct Pst {
    pub input: Input,
    pub kind: Kind,
    pub crypt: u8,
    pub nbt: Bref,
    pub bbt: Bref,
}

impl Pst {
    pub fn file(&self) -> Span {
        self.input.span
    }
    pub fn wide(&self) -> bool {
        self.kind != Kind::Ansi
    }
    /// Size of a BID, IB or NID slot in on-disk structures.
    pub fn id(&self) -> u64 {
        if self.wide() { 8 } else { 4 }
    }
    pub fn page_size(&self) -> u64 {
        if self.kind == Kind::Unicode4k {
            4096
        } else {
            512
        }
    }
    pub fn block_trailer(&self) -> u64 {
        if self.wide() { 16 } else { 12 }
    }
    /// Largest data block payload (rows of a table matrix never straddle
    /// blocks of this size).
    pub fn max_block_data(&self) -> u64 {
        8192u64.saturating_sub(self.block_trailer())
    }
    pub fn word(&self, data: &[u8], at: usize) -> Option<u64> {
        if self.wide() {
            u64_le(data, at)
        } else {
            u32_le(data, at).map(u64::from)
        }
    }
}

// ---------------------------------------------------------------------------
// Pages

#[derive(Clone, Debug)]
pub enum Entry {
    /// An intermediate entry: the first key under `child`.
    Branch {
        key: u64,
        child: Bref,
    },
    Node(NodeEntry),
    Block(BlockEntry),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NodeEntry {
    pub nid: u32,
    pub data: u64,
    pub sub: u64,
    pub parent: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct BlockEntry {
    pub bref: Bref,
    pub cb: u16,
    pub refs: u16,
}

#[derive(Clone, Debug)]
pub struct Page {
    pub span: Span,
    pub ptype: u8,
    pub level: u8,
    pub cb_ent: u8,
    pub max: u8,
    pub entries: Vec<(Entry, Span)>,
    /// Problems found while reading the page (trailer and checks).
    pub problems: Vec<Diagnostic>,
    pub trailer: Span,
    pub meta: Span,
}

/// Reads and parses a B-tree page (cached).
pub async fn page(cx: &Cx, pst: &Pst, bref: Bref) -> Result<Arc<Page>> {
    if pst.kind == Kind::Unicode4k {
        return Err(Diagnostic::unsupported(
            "B-tree pages of 4 KiB-page files (OST 2013): layout not known well enough",
        ));
    }
    let size = pst.page_size();
    let span = pst.file().sub_exact(bref.ib, size)?;
    if let Some(found) = cx.cached::<Page>(span, "pst-page") {
        return Ok(found);
    }
    let data = cx.read(span).await?;
    let wide = pst.wide();
    // BTPAGE metadata (cEnt, cEntMax, cbEnt, cLevel) then the trailer.
    let (meta_at, trailer_at) = if wide { (488, 496) } else { (496, 500) };
    let get = |at: usize| data.get(at).copied().unwrap_or(0);
    let count = get(meta_at);
    let max = get(meta_at.saturating_add(1));
    let cb_ent = get(meta_at.saturating_add(2));
    let level = get(meta_at.saturating_add(3));
    let ptype = get(trailer_at);
    let repeat = get(trailer_at.saturating_add(1));
    let sig = u16_le(&data, trailer_at.saturating_add(2)).unwrap_or(0);
    let (crc, bid) = if wide {
        (
            u32_le(&data, trailer_at.saturating_add(4)).unwrap_or(0),
            u64_le(&data, trailer_at.saturating_add(8)).unwrap_or(0),
        )
    } else {
        (
            u32_le(&data, trailer_at.saturating_add(8)).unwrap_or(0),
            u32_le(&data, trailer_at.saturating_add(4)).map_or(0, u64::from),
        )
    };
    let mut problems = Vec::new();
    if ptype != repeat {
        problems.push(Diagnostic::malformed(format!(
            "page type {ptype:#04x} and its repeat {repeat:#04x} differ"
        )));
    }
    if !matches!(ptype, PTYPE_BBT | PTYPE_NBT) {
        return Err(Diagnostic::malformed(format!(
            "expected a B-tree page, found page type {ptype:#04x}"
        ))
        .at(span));
    }
    if bid != bref.bid {
        problems.push(Diagnostic::warning(format!(
            "page trailer BID {bid:#x} differs from the reference {:#x}",
            bref.bid
        )));
    }
    // The CRC covers everything before the trailer (entries and metadata).
    let computed_full = PST_CRC.checksum(data.get(..trailer_at).unwrap_or_default());
    if u64::from(crc) != computed_full {
        problems.push(Diagnostic::warning(format!(
            "page CRC {crc:#010x} does not match the computed {computed_full:#010x}"
        )));
    }
    let expected_sig = signature(bref.ib, bref.bid);
    if sig != 0 && sig != expected_sig {
        problems.push(Diagnostic::warning(format!(
            "page signature {sig:#06x} does not match the computed {expected_sig:#06x}"
        )));
    }
    let id = pst.id();
    let want = match (level, ptype) {
        (0, PTYPE_NBT) => id.saturating_mul(4),
        (0, _) => id
            .saturating_mul(2)
            .saturating_add(if wide { 8 } else { 4 }),
        _ => id.saturating_mul(3),
    };
    if u64::from(cb_ent) != want {
        return Err(Diagnostic::malformed(format!(
            "entry size {cb_ent} (expected {want} for this page type and level)"
        ))
        .at(span));
    }
    if level > MAX_LEVELS {
        return Err(Diagnostic::malformed(format!("B-tree level {level}")).at(span));
    }
    let area = to_u64(meta_at);
    let fits = area.checked_div(want).unwrap_or(0);
    let n = u64::from(count).min(fits);
    if u64::from(count) > fits {
        problems.push(Diagnostic::malformed(format!(
            "{count} entries do not fit in the page"
        )));
    }
    let mut entries = Vec::new();
    for i in 0..n {
        let at = i.saturating_mul(want);
        let e = data
            .get(to_usize(at)..to_usize(at.saturating_add(want)))
            .unwrap_or_default();
        let w = |k: u64| pst.word(e, to_usize(k.saturating_mul(id))).unwrap_or(0);
        let entry = if level > 0 {
            Entry::Branch {
                key: w(0),
                child: Bref {
                    bid: w(1),
                    ib: w(2),
                },
            }
        } else if ptype == PTYPE_NBT {
            Entry::Node(NodeEntry {
                nid: w(0) as u32,
                data: w(1),
                sub: w(2),
                parent: u32_le(e, to_usize(id.saturating_mul(3))).unwrap_or(0),
            })
        } else {
            let at = to_usize(id.saturating_mul(2));
            Entry::Block(BlockEntry {
                bref: Bref {
                    bid: w(0),
                    ib: w(1),
                },
                cb: u16_le(e, at).unwrap_or(0),
                refs: u16_le(e, at.saturating_add(2)).unwrap_or(0),
            })
        };
        entries.push((entry, span.sub(at, want)));
    }
    let page = Arc::new(Page {
        span,
        ptype,
        level,
        cb_ent,
        max,
        entries,
        problems,
        trailer: span.sub(to_u64(trailer_at), size.saturating_sub(to_u64(trailer_at))),
        meta: span.sub(area, 4),
    });
    cx.cache(span, "pst-page", page.clone());
    Ok(page)
}

/// [MS-PST] ComputeSig: the 16-bit signature of a page or block.
pub fn signature(ib: u64, bid: u64) -> u16 {
    let x = (ib ^ bid) as u32;
    ((x >> 16) ^ (x & 0xffff)) as u16
}

/// Finds a key in a B-tree: the leaf entry whose key equals `key` (NIDs
/// compare whole; BIDs ignore their lowest bit).
async fn find(cx: &Cx, pst: &Pst, root: Bref, key: u64) -> Result<Option<Entry>> {
    let mut at = root;
    let mut level: Option<u8> = None;
    loop {
        let page = page(cx, pst, at).await?;
        if let Some(parent) = level
            && page.level.saturating_add(1) != parent
        {
            return Err(Diagnostic::malformed("B-tree levels do not decrease").at(page.span));
        }
        level = Some(page.level);
        if page.level == 0 {
            for (entry, _) in &page.entries {
                let found = match entry {
                    Entry::Node(n) => u64::from(n.nid) == key,
                    Entry::Block(b) => b.bref.bid & !1 == key & !1,
                    Entry::Branch { .. } => false,
                };
                if found {
                    return Ok(Some(entry.clone()));
                }
            }
            return Ok(None);
        }
        let mut next = None;
        for (entry, _) in &page.entries {
            if let Entry::Branch { key: k, child } = entry {
                let k = if page.ptype == PTYPE_BBT { k & !1 } else { *k };
                if k <= key {
                    next = Some(*child);
                } else {
                    break;
                }
            }
        }
        match next {
            Some(child) => at = child,
            None => return Ok(None),
        }
    }
}

pub async fn find_node(cx: &Cx, pst: &Pst, nid: u32) -> Result<Option<NodeEntry>> {
    Ok(match find(cx, pst, pst.nbt, nid.into()).await? {
        Some(Entry::Node(n)) => Some(n),
        _ => None,
    })
}

pub async fn find_block(cx: &Cx, pst: &Pst, bid: u64) -> Result<Option<BlockEntry>> {
    Ok(match find(cx, pst, pst.bbt, bid).await? {
        Some(Entry::Block(b)) => Some(b),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Blocks

/// A block found through the block B-tree.
#[derive(Clone, Copy, Debug)]
pub struct Block {
    pub bid: u64,
    /// The block's data (`cb` bytes, before padding and trailer).
    pub raw: Span,
    /// The whole allocation: data, padding and trailer.
    pub alloc: Span,
}

impl Block {
    pub fn internal(&self) -> bool {
        self.bid & 2 != 0
    }
    pub fn trailer(&self, pst: &Pst) -> Span {
        self.alloc.sub(
            self.alloc.len.saturating_sub(pst.block_trailer()),
            pst.block_trailer(),
        )
    }
}

pub async fn block(cx: &Cx, pst: &Pst, bid: u64) -> Result<Block> {
    let entry = find_block(cx, pst, bid).await?.ok_or_else(|| {
        Diagnostic::malformed(format!("block {bid:#x} is not in the block B-tree"))
    })?;
    let cb = u64::from(entry.cb);
    let total = cb.saturating_add(pst.block_trailer()).saturating_add(63) & !63;
    let alloc = pst.file().sub_exact(entry.bref.ib, total)?;
    Ok(Block {
        bid: entry.bref.bid,
        raw: alloc.sub(0, cb),
        alloc,
    })
}

/// The block's data after undoing the file's obfuscation: the raw span
/// itself when there is none (or for internal blocks, which are never
/// encoded), otherwise a derived source.
pub async fn plain(cx: &Cx, pst: &Pst, block: &Block) -> Result<Span> {
    if block.internal() || pst.crypt == 0 {
        return Ok(block.raw);
    }
    let transform = match pst.crypt {
        1 => "pst-permute",
        2 => "pst-cyclic",
        other => {
            return Err(
                Diagnostic::unsupported(format!("block encoding {other:#04x}")).at(block.raw),
            );
        }
    };
    let origin = Origin {
        parent: block.raw,
        transform,
    };
    if let Some(found) = cx.derived(origin) {
        return Ok(found.span);
    }
    let mut data = cx.read(block.raw).await?;
    if pst.crypt == 1 {
        permute_decode(&mut data);
    } else {
        cyclic(&mut data, block.bid as u32);
    }
    let len = to_u64(data.len());
    Ok(cx.add_derived(origin, data, len, None)?.span)
}

/// The data blocks of a node, in order, following XBLOCKs and XXBLOCKs.
/// Their sizes may not add up to more than the root's total (`lcbTotal`),
/// which also bounds how many there are when blocks are repeated.
pub async fn data_tree(cx: &Cx, pst: &Pst, bid: u64) -> Result<Vec<Block>> {
    let root = block(cx, pst, bid).await?;
    if !root.internal() {
        return Ok(vec![root]);
    }
    let root_span = root.raw;
    let mut out = Vec::new();
    let mut total = None;
    let mut used = 0u64;
    let mut pending = vec![(root, 2u8)];
    while let Some((b, allowed)) = pending.pop() {
        let data = cx.read(b.raw).await?;
        let btype = data.first().copied().unwrap_or(0);
        let level = data.get(1).copied().unwrap_or(0);
        if btype != 1 || !(1..=allowed).contains(&level) {
            return Err(Diagnostic::malformed(format!(
                "expected an XBLOCK, found block type {btype:#04x} level {level}"
            ))
            .at(b.raw));
        }
        let count = u16_le(&data, 2).unwrap_or(0);
        let total = *total.get_or_insert_with(|| u64::from(u32_le(&data, 4).unwrap_or(0)));
        let id = to_usize(pst.id());
        let mut children = Vec::new();
        for i in 0..usize::from(count) {
            cx.checkpoint().await;
            let Some(child) = pst.word(&data, i.saturating_mul(id).saturating_add(8)) else {
                break;
            };
            let child = block(cx, pst, child).await?;
            if level == 2 {
                children.push((child, 1));
            } else if child.internal() {
                return Err(
                    Diagnostic::malformed("XBLOCK refers to an internal block").at(child.raw)
                );
            } else {
                used = used.saturating_add(child.raw.len.max(1));
                if used > total {
                    return Err(Diagnostic::malformed(format!(
                        "data blocks hold more than the {total} bytes the data tree declares"
                    ))
                    .at(root_span));
                }
                out.push(child);
            }
        }
        // Depth-first, in order.
        pending.extend(children.into_iter().rev());
    }
    Ok(out)
}

/// A node's data as one span: its block, or its blocks pieced together.
pub async fn stream(cx: &Cx, pst: &Pst, bid: u64) -> Result<Span> {
    if bid == 0 {
        return Ok(Span::zeros(0));
    }
    let blocks = data_tree(cx, pst, bid).await?;
    let mut pieces = Vec::with_capacity(blocks.len());
    for b in &blocks {
        cx.checkpoint().await;
        pieces.push(plain(cx, pst, b).await?);
    }
    match pieces.as_slice() {
        [one] => Ok(*one),
        _ => {
            let root = block(cx, pst, bid).await?;
            cx.add_pieces(
                Origin {
                    parent: root.raw,
                    transform: "pst-data-tree",
                },
                pieces,
            )
        }
    }
}

/// An entry of a subnode tree (SLENTRY).
#[derive(Clone, Copy, Debug)]
pub struct SubEntry {
    pub nid: u32,
    pub data: u64,
    pub sub: u64,
    pub span: Span,
}

/// The subnodes of a node (flattening SIBLOCKs).
pub async fn subnodes(cx: &Cx, pst: &Pst, bid: u64) -> Result<Arc<Vec<SubEntry>>> {
    if bid == 0 {
        return Ok(Arc::new(Vec::new()));
    }
    let root = block(cx, pst, bid).await?;
    if let Some(found) = cx.cached::<Vec<SubEntry>>(root.raw, "pst-subnodes") {
        return Ok(found);
    }
    let mut out = Vec::new();
    let mut pending = vec![(root, 1u8)];
    let id = pst.id();
    while let Some((b, allowed)) = pending.pop() {
        let data = cx.read(b.raw).await?;
        let btype = data.first().copied().unwrap_or(0);
        let level = data.get(1).copied().unwrap_or(0);
        if btype != 2 || level > allowed || !b.internal() {
            return Err(Diagnostic::malformed(format!(
                "expected a subnode block, found block type {btype:#04x} level {level}"
            ))
            .at(b.raw));
        }
        let count = u16_le(&data, 2).unwrap_or(0);
        let start = if pst.wide() { 8u64 } else { 4 };
        let size = id.saturating_mul(if level == 0 { 3 } else { 2 });
        let mut children = Vec::new();
        for i in 0..u64::from(count) {
            cx.checkpoint().await;
            let at = start.saturating_add(i.saturating_mul(size));
            let Some(e) = data.get(to_usize(at)..to_usize(at.saturating_add(size))) else {
                break;
            };
            let w = |k: u64| pst.word(e, to_usize(k.saturating_mul(id))).unwrap_or(0);
            if level == 0 {
                out.push(SubEntry {
                    nid: w(0) as u32,
                    data: w(1),
                    sub: w(2),
                    span: b.raw.sub(at, size),
                });
            } else {
                children.push((block(cx, pst, w(1)).await?, 0));
            }
        }
        pending.extend(children.into_iter().rev());
    }
    let out = Arc::new(out);
    cx.cache(root.raw, "pst-subnodes", out.clone());
    Ok(out)
}

// ---------------------------------------------------------------------------
// Obfuscation ([MS-PST] 5.1 and 5.2)

/// `mpbbCrypt`'s third table (mpbbI): decodes NDB_CRYPT_PERMUTE.
const MPBB_I: [u8; 256] = [
    0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94, 0x53,
    0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab, 0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd,
    0x39, 0x05, 0x96, 0x30, 0xf5, 0x37, 0x60, 0x82, 0x8c, 0xc9, 0x13, 0x4a, 0x6b, 0x1d, 0xf3, 0xfb,
    0x8f, 0x26, 0x97, 0xca, 0x91, 0x17, 0x01, 0xc4, 0x32, 0x2d, 0x6e, 0x31, 0x95, 0xff, 0xd9, 0x23,
    0xd1, 0x00, 0x5e, 0x79, 0xdc, 0x44, 0x3b, 0x1a, 0x28, 0xc5, 0x61, 0x57, 0x20, 0x90, 0x3d, 0x83,
    0xb9, 0x43, 0xbe, 0x67, 0xd2, 0x46, 0x42, 0x76, 0xc0, 0x6d, 0x5b, 0x7e, 0xb2, 0x0f, 0x16, 0x29,
    0x3c, 0xa9, 0x03, 0x54, 0x0d, 0xda, 0x5d, 0xdf, 0xf6, 0xb7, 0xc7, 0x62, 0xcd, 0x8d, 0x06, 0xd3,
    0x69, 0x5c, 0x86, 0xd6, 0x14, 0xf7, 0xa5, 0x66, 0x75, 0xac, 0xb1, 0xe9, 0x45, 0x21, 0x70, 0x0c,
    0x87, 0x9f, 0x74, 0xa4, 0x22, 0x4c, 0x6f, 0xbf, 0x1f, 0x56, 0xaa, 0x2e, 0xb3, 0x78, 0x33, 0x50,
    0xb0, 0xa3, 0x92, 0xbc, 0xcf, 0x19, 0x1c, 0xa7, 0x63, 0xcb, 0x1e, 0x4d, 0x3e, 0x4b, 0x1b, 0x9b,
    0x4f, 0xe7, 0xf0, 0xee, 0xad, 0x3a, 0xb5, 0x59, 0x04, 0xea, 0x40, 0x55, 0x25, 0x51, 0xe5, 0x7a,
    0x89, 0x38, 0x68, 0x52, 0x7b, 0xfc, 0x27, 0xae, 0xd7, 0xbd, 0xfa, 0x07, 0xf4, 0xcc, 0x8e, 0x5f,
    0xef, 0x35, 0x9c, 0x84, 0x2b, 0x15, 0xd5, 0x77, 0x34, 0x49, 0xb6, 0x12, 0x0a, 0x7f, 0x71, 0x88,
    0xfd, 0x9d, 0x18, 0x41, 0x7d, 0x93, 0xd8, 0x58, 0x2c, 0xce, 0xfe, 0x24, 0xaf, 0xde, 0xb8, 0x36,
    0xc8, 0xa1, 0x80, 0xa6, 0x99, 0x98, 0xa8, 0x2f, 0x0e, 0x81, 0x65, 0x73, 0xe4, 0xc2, 0xa2, 0x8a,
    0xd4, 0xe1, 0x11, 0xd0, 0x08, 0x8b, 0x2a, 0xf2, 0xed, 0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec,
];

/// `mpbbCrypt`'s second table (mpbbS), an involution used by the cyclic
/// encoding.
const MPBB_S: [u8; 256] = [
    0x14, 0x53, 0x0f, 0x56, 0xb3, 0xc8, 0x7a, 0x9c, 0xeb, 0x65, 0x48, 0x17, 0x16, 0x15, 0x9f, 0x02,
    0xcc, 0x54, 0x7c, 0x83, 0x00, 0x0d, 0x0c, 0x0b, 0xa2, 0x62, 0xa8, 0x76, 0xdb, 0xd9, 0xed, 0xc7,
    0xc5, 0xa4, 0xdc, 0xac, 0x85, 0x74, 0xd6, 0xd0, 0xa7, 0x9b, 0xae, 0x9a, 0x96, 0x71, 0x66, 0xc3,
    0x63, 0x99, 0xb8, 0xdd, 0x73, 0x92, 0x8e, 0x84, 0x7d, 0xa5, 0x5e, 0xd1, 0x5d, 0x93, 0xb1, 0x57,
    0x51, 0x50, 0x80, 0x89, 0x52, 0x94, 0x4f, 0x4e, 0x0a, 0x6b, 0xbc, 0x8d, 0x7f, 0x6e, 0x47, 0x46,
    0x41, 0x40, 0x44, 0x01, 0x11, 0xcb, 0x03, 0x3f, 0xf7, 0xf4, 0xe1, 0xa9, 0x8f, 0x3c, 0x3a, 0xf9,
    0xfb, 0xf0, 0x19, 0x30, 0x82, 0x09, 0x2e, 0xc9, 0x9d, 0xa0, 0x86, 0x49, 0xee, 0x6f, 0x4d, 0x6d,
    0xc4, 0x2d, 0x81, 0x34, 0x25, 0x87, 0x1b, 0x88, 0xaa, 0xfc, 0x06, 0xa1, 0x12, 0x38, 0xfd, 0x4c,
    0x42, 0x72, 0x64, 0x13, 0x37, 0x24, 0x6a, 0x75, 0x77, 0x43, 0xff, 0xe6, 0xb4, 0x4b, 0x36, 0x5c,
    0xe4, 0xd8, 0x35, 0x3d, 0x45, 0xb9, 0x2c, 0xec, 0xb7, 0x31, 0x2b, 0x29, 0x07, 0x68, 0xa3, 0x0e,
    0x69, 0x7b, 0x18, 0x9e, 0x21, 0x39, 0xbe, 0x28, 0x1a, 0x5b, 0x78, 0xf5, 0x23, 0xca, 0x2a, 0xb0,
    0xaf, 0x3e, 0xfe, 0x04, 0x8c, 0xe7, 0xe5, 0x98, 0x32, 0x95, 0xd3, 0xf6, 0x4a, 0xe8, 0xa6, 0xea,
    0xe9, 0xf3, 0xd5, 0x2f, 0x70, 0x20, 0xf2, 0x1f, 0x05, 0x67, 0xad, 0x55, 0x10, 0xce, 0xcd, 0xe3,
    0x27, 0x3b, 0xda, 0xba, 0xd7, 0xc2, 0x26, 0xd4, 0x91, 0x1d, 0xd2, 0x1c, 0x22, 0x33, 0xf8, 0xfa,
    0xf1, 0x5a, 0xef, 0xcf, 0x90, 0xb6, 0x8b, 0xb5, 0xbd, 0xc0, 0xbf, 0x08, 0x97, 0x1e, 0x6c, 0xe2,
    0x61, 0xe0, 0xc6, 0xc1, 0x59, 0xab, 0xbb, 0x58, 0xde, 0x5f, 0xdf, 0x60, 0x79, 0x7e, 0xb2, 0x8a,
];

/// `mpbbR`, the permute encoding table: the inverse of [`MPBB_I`].
fn mpbb_r() -> [u8; 256] {
    let mut r = [0u8; 256];
    for (i, &v) in MPBB_I.iter().enumerate() {
        if let Some(slot) = r.get_mut(usize::from(v)) {
            *slot = i as u8;
        }
    }
    r
}

fn sub(table: &[u8; 256], b: u8) -> u8 {
    table.get(usize::from(b)).copied().unwrap_or(b)
}

/// Undoes NDB_CRYPT_PERMUTE ("compressible encryption").
pub fn permute_decode(data: &mut [u8]) {
    for b in data {
        *b = sub(&MPBB_I, *b);
    }
}

/// NDB_CRYPT_CYCLIC, keyed by the block's BID; it is its own inverse.
pub fn cyclic(data: &mut [u8], key: u32) {
    let r = mpbb_r();
    let mut w = (key ^ (key >> 16)) as u16;
    for b in data {
        let lo = w as u8;
        let hi = (w >> 8) as u8;
        let mut x = b.wrapping_add(lo);
        x = sub(&r, x);
        x = x.wrapping_add(hi);
        x = sub(&MPBB_S, x);
        x = x.wrapping_sub(hi);
        x = sub(&MPBB_I, x);
        *b = x.wrapping_sub(lo);
        w = w.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::indexing_slicing)]
    fn tables_are_permutations() {
        let mut seen_i = [false; 256];
        for &v in &MPBB_I {
            seen_i[usize::from(v)] = true;
        }
        assert!(seen_i.iter().all(|&s| s));
        // mpbbS is an involution, so the cyclic encoding is its own inverse.
        for (i, &v) in MPBB_S.iter().enumerate() {
            assert_eq!(usize::from(MPBB_S[usize::from(v)]), i);
        }
    }

    #[test]
    fn cyclic_round_trips() {
        let plain: Vec<u8> = (0..=255u8).chain(b"Hello, PST".iter().copied()).collect();
        let mut data = plain.clone();
        cyclic(&mut data, 0x1234_5678);
        assert_ne!(data, plain);
        cyclic(&mut data, 0x1234_5678);
        assert_eq!(data, plain);
    }

    #[test]
    fn signature_folds_halves() {
        assert_eq!(signature(0x4400, 0x4), 0x4404);
        assert_eq!(signature(0x1_0000, 0), 1);
    }
}
