//! ESE pages: the page header (small pages up to 8 KiB, and the extended
//! header of 16/32 KiB pages), checksums (the legacy XOR checksum and the
//! ECC + XOR checksum of newer pages), the tag array at the end of the page
//! and the B-tree nodes the tags point at.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::span::Span;
use crate::value::{FlagTable, flag};

use super::Db;

/// Seed of ESE's XOR checksums.
pub const XOR_SEED: u32 = 0x89ab_cdef;

pub const PAGE_FLAGS: FlagTable = &[
    flag(0x0001, "Root"),
    flag(0x0002, "Leaf"),
    flag(0x0004, "ParentOfLeaf"),
    flag(0x0008, "Empty"),
    flag(0x0010, "Repair"),
    flag(0x0020, "SpaceTree"),
    flag(0x0040, "Index"),
    flag(0x0080, "LongValue"),
    flag(0x0400, "NonUniqueKeys"),
    flag(0x0800, "NewRecordFormat"),
    flag(0x2000, "NewChecksumFormat"),
    flag(0x4000, "Scrubbed"),
    flag(0x8000, "FlushType1"),
    flag(0x1_0000, "FlushType2"),
];

/// Node (tag) flags.
pub const NODE_FLAGS: FlagTable = &[
    flag(0x1, "Version"),
    flag(0x2, "Deleted"),
    flag(0x4, "CompressedKey"),
];

pub const ROOT: u32 = 0x1;
pub const LEAF: u32 = 0x2;
pub const SPACE_TREE: u32 = 0x20;
pub const INDEX: u32 = 0x40;
pub const LONG_VALUE: u32 = 0x80;
pub const NEW_CHECKSUM: u32 = 0x2000;

#[derive(Clone, Copy, Debug)]
pub struct Tag {
    /// Offset within the page (absolute).
    pub at: usize,
    pub size: usize,
    pub flags: u8,
}

/// A parsed page.
pub struct Page {
    pub pgno: u32,
    pub data: Vec<u8>,
    pub small: bool,
    pub checksum: u64,
    pub next: u32,
    pub objid: u32,
    pub cb_free: u16,
    pub mic_free: u16,
    pub flags: u32,
    pub header_len: usize,
    /// Tag 0 is the page's external header; nodes are tags 1 and up.
    pub tags: Vec<Tag>,
}

/// A B-tree node: its key (prefix taken from tag 0 when compressed) and
/// where its data lies in the page.
pub struct NodeRef {
    pub key: Vec<u8>,
    pub prefix_len: usize,
    pub data_at: usize,
    pub data_len: usize,
    pub flags: u8,
}

impl Page {
    pub fn parse(pgno: u32, data: Vec<u8>, small: bool) -> Page {
        let header_len = if small { 40 } else { 80 };
        let itag = u16_le(&data, 0x22).unwrap_or(0);
        let count = usize::from(itag & 0x0fff);
        let mask: u16 = if small { 0x1fff } else { 0x7fff };
        let mut tags = Vec::new();
        let len = data.len();
        for i in 0..count {
            let Some(at) = i
                .checked_add(1)
                .and_then(|n| n.checked_mul(4))
                .and_then(|n| len.checked_sub(n))
            else {
                break;
            };
            if at < header_len {
                break;
            }
            let cb = u16_le(&data, at).unwrap_or(0);
            let ib = u16_le(&data, at.saturating_add(2)).unwrap_or(0);
            let offset = usize::from(ib & mask).saturating_add(header_len);
            let size = usize::from(cb & mask);
            let flags = if small {
                u8::try_from(ib >> 13).unwrap_or(0)
            } else if size >= 2 {
                data.get(offset.saturating_add(1)).map_or(0, |b| b >> 5)
            } else {
                0
            };
            tags.push(Tag {
                at: offset,
                size,
                flags,
            });
        }
        Page {
            pgno,
            small,
            checksum: u64_le(&data, 0).unwrap_or(0),
            next: u32_le(&data, 0x14).unwrap_or(0),
            objid: u32_le(&data, 0x18).unwrap_or(0),
            cb_free: u16_le(&data, 0x1c).unwrap_or(0),
            mic_free: u16_le(&data, 0x20).unwrap_or(0),
            flags: u32_le(&data, 0x24).unwrap_or(0),
            header_len,
            tags,
            data,
        }
    }

    pub fn is_leaf(&self) -> bool {
        self.flags & LEAF != 0
    }

    pub fn is_root(&self) -> bool {
        self.flags & ROOT != 0
    }

    /// The bytes of tag `i` (empty when out of range).
    pub fn tag_bytes(&self, i: usize) -> &[u8] {
        self.tags
            .get(i)
            .and_then(|t| self.data.get(t.at..t.at.saturating_add(t.size)))
            .unwrap_or_default()
    }

    /// Number of nodes (tags after the external header).
    pub fn nodes(&self) -> usize {
        self.tags.len().saturating_sub(1)
    }

    /// Node `i` (1-based tag index).
    pub fn node(&self, i: usize) -> Option<NodeRef> {
        let tag = *self.tags.get(i)?;
        let b = self.tag_bytes(i);
        if b.len() < tag.size || tag.size < 2 {
            return None;
        }
        let mut pos = 0usize;
        let mut key = Vec::new();
        let mut prefix_len = 0usize;
        if tag.flags & 4 != 0 {
            prefix_len = usize::from(u16_le(b, 0)? & 0x1fff);
            let prefix = self.tag_bytes(0);
            key.extend_from_slice(prefix.get(..prefix_len.min(prefix.len()))?);
            pos = 2;
        }
        let suffix_len = usize::from(u16_le(b, pos)? & 0x1fff);
        let suffix_at = pos.checked_add(2)?;
        key.extend_from_slice(b.get(suffix_at..suffix_at.checked_add(suffix_len)?)?);
        let data_rel = suffix_at.checked_add(suffix_len)?;
        Some(NodeRef {
            key,
            prefix_len,
            data_at: tag.at.checked_add(data_rel)?,
            data_len: tag.size.checked_sub(data_rel)?,
            flags: tag.flags,
        })
    }

    pub fn node_data(&self, n: &NodeRef) -> &[u8] {
        self.data
            .get(n.data_at..n.data_at.saturating_add(n.data_len))
            .unwrap_or_default()
    }

    /// The child page of branch node `i`.
    pub fn child(&self, i: usize) -> Option<u32> {
        let n = self.node(i)?;
        u32_le(self.node_data(&n), 0)
    }
}

/// Reads and parses page `pgno` (cached).
pub async fn load(cx: &Cx, db: &Db, pgno: u32) -> Result<Arc<Page>> {
    let span = db.page_span(pgno)?;
    if let Some(p) = cx.cached::<Page>(span, "ese-page") {
        return Ok(p);
    }
    let data = cx.read(span).await?;
    let page = Arc::new(Page::parse(pgno, data, db.small));
    cx.cache(span, "ese-page", page.clone());
    Ok(page)
}

/// XOR of the little-endian dwords of `data`, starting from `seed`.
pub fn xor32(data: &[u8], seed: u32) -> u32 {
    data.as_chunks::<4>()
        .0
        .iter()
        .fold(seed, |acc, c| acc ^ u32::from_le_bytes(*c))
}

/// The ECC checksum of a page from offset 8: the XOR of the bit positions
/// of all set bits, stored with (if the number of set bits is odd) its
/// complement within the page's bit count in the upper half.
pub fn ecc32(page: &[u8]) -> u32 {
    let mut positions = 0u32;
    let mut parity = 0u32;
    for (i, c) in page.as_chunks::<4>().0.iter().enumerate().skip(2) {
        let mut w = u32::from_le_bytes(*c);
        if w == 0 {
            continue;
        }
        let ones = w.count_ones();
        let base = u32::try_from(i).unwrap_or(0).wrapping_shl(5);
        if ones & 1 != 0 {
            positions ^= base;
        }
        parity ^= ones & 1;
        while w != 0 {
            positions ^= w.trailing_zeros();
            w &= w.wrapping_sub(1);
        }
    }
    let bits = u32::try_from(page.len()).unwrap_or(0).wrapping_shl(3);
    let mask = bits.wrapping_sub(1);
    let high = if parity != 0 {
        positions ^ mask
    } else {
        positions
    };
    (high & 0xffff).wrapping_shl(16) | (positions & 0xffff)
}

/// What a page's checksum says.
pub struct Check {
    pub scheme: &'static str,
    pub stored: u64,
    /// `None` when we cannot compute it (large pages).
    pub computed: Option<u64>,
}

pub fn check(page: &Page) -> Check {
    let data = &page.data;
    if page.flags & NEW_CHECKSUM != 0 {
        if !page.small {
            return Check {
                scheme: "ECC + XOR per 8 KiB block (not verified)",
                stored: page.checksum,
                computed: None,
            };
        }
        let xor = xor32(data.get(8..).unwrap_or_default(), 0) ^ page.pgno;
        let ecc = ecc32(data);
        return Check {
            scheme: "ECC + XOR",
            stored: page.checksum,
            computed: Some(u64::from(ecc).wrapping_shl(32) | u64::from(xor)),
        };
    }
    Check {
        scheme: "XOR",
        stored: u64::from(u32_le(data, 0).unwrap_or(0)),
        computed: Some(u64::from(xor32(
            data.get(4..).unwrap_or_default(),
            XOR_SEED,
        ))),
    }
}

/// Leaves of the B-tree rooted at `root`, in key order: descends to the
/// leftmost leaf, then follows the leaf chain. Calls `visit` with each leaf
/// page; stops when it returns false.
pub struct LeafWalk {
    pub next: Option<u32>,
    pub objid: u32,
    pub steps: u64,
}

impl LeafWalk {
    pub async fn start(cx: &Cx, db: &Db, root: u32) -> Result<LeafWalk> {
        let mut pgno = root;
        let top = load(cx, db, root).await?;
        let objid = top.objid;
        for _ in 0..32 {
            let page = load(cx, db, pgno).await?;
            if page.objid != objid {
                return Err(Diagnostic::malformed(format!(
                    "page {pgno} belongs to object {}, not {objid}",
                    page.objid
                )));
            }
            if page.is_leaf() {
                return Ok(LeafWalk {
                    next: Some(pgno),
                    objid,
                    steps: 0,
                });
            }
            pgno = page.child(1).ok_or_else(|| {
                Diagnostic::malformed(format!("branch page {pgno} has no children"))
            })?;
        }
        Err(Diagnostic::limit("B-tree deeper than 32 levels"))
    }

    /// The next leaf page, or `None` at the end of the chain.
    pub async fn next(&mut self, cx: &Cx, db: &Db) -> Result<Option<Arc<Page>>> {
        let Some(pgno) = self.next.take() else {
            return Ok(None);
        };
        self.steps = self.steps.saturating_add(1);
        if self.steps > u64::from(db.pages).saturating_add(1) {
            return Err(Diagnostic::malformed("leaf chain loops"));
        }
        let page = load(cx, db, pgno).await?;
        if page.objid != self.objid || !page.is_leaf() {
            return Err(Diagnostic::malformed(format!(
                "leaf chain reaches page {pgno} of object {}",
                page.objid
            )));
        }
        if page.next != 0 {
            self.next = Some(page.next);
        }
        Ok(Some(page))
    }
}

/// The first leaf entry with a key not less than `key`: (page, tag index).
pub async fn seek(cx: &Cx, db: &Db, root: u32, key: &[u8]) -> Result<Option<(Arc<Page>, usize)>> {
    let mut pgno = root;
    for _ in 0..32 {
        let page = load(cx, db, pgno).await?;
        let count = page.tags.len();
        if page.is_leaf() {
            for i in 1..count {
                if let Some(n) = page.node(i)
                    && n.key.as_slice() >= key
                {
                    return Ok(Some((page, i)));
                }
            }
            if page.next == 0 {
                return Ok(None);
            }
            let next = load(cx, db, page.next).await?;
            return Ok((next.tags.len() > 1).then_some((next, 1)));
        }
        // Separators: child i holds keys below its key (an empty key is
        // the last child, without bound).
        let mut child = None;
        for i in 1..count {
            let Some(n) = page.node(i) else { continue };
            if n.key.is_empty() || key < n.key.as_slice() {
                child = u32_le(page.node_data(&n), 0);
                break;
            }
        }
        pgno = match child.or_else(|| page.child(count.saturating_sub(1))) {
            Some(c) => c,
            None => return Ok(None),
        };
    }
    Err(Diagnostic::limit("B-tree deeper than 32 levels"))
}

/// The span of `len` bytes at `at` in page `page`.
pub fn span_in(db: &Db, page: &Page, at: usize, len: usize) -> Span {
    match db.page_span(page.pgno) {
        Ok(s) => s.sub(to_u64(at), to_u64(len)),
        Err(_) => db.file.sub(0, 0),
    }
}
