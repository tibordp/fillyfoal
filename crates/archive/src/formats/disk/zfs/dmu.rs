//! Reading a pool's objects: block pointers (DVAs, compression, checksums,
//! embedded data), dnodes and their indirect block trees, object sets and
//! ZAPs (micro and fat), as the DMU does (`dmu.c`, `dbuf.c`, `zap_leaf.c`).
//!
//! Only the device at hand is read: blocks on other top-level vdevs, and
//! RAID-Z or dRAID vdevs (whose blocks are spread over all members), are
//! not readable from it; mirrors and single-device vdevs are.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_be, u16_le, u32_be, u32_le, u64_be, u64_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::Input;
use crate::span::{Origin, Span};

/// Labels 0 and 1 and the boot area come before the allocatable space.
const VDEV_START: u64 = 4 * 1024 * 1024;
/// Size of a block pointer, and of the smallest dnode.
pub(super) const BP_SIZE: usize = 128;
pub(super) const DNODE_SIZE: u64 = 512;
/// The most bytes a metadata block may have (16 MiB, `SPA_MAXBLOCKSIZE`).
const MAX_BLOCK: u64 = 16 * 1024 * 1024;

/// A word of `data` at `at`, in the given byte order.
pub(super) fn word(data: &[u8], at: usize, le: bool) -> Option<u64> {
    if le {
        u64_le(data, at)
    } else {
        u64_be(data, at)
    }
}

pub(super) fn word32(data: &[u8], at: usize, le: bool) -> Option<u32> {
    if le {
        u32_le(data, at)
    } else {
        u32_be(data, at)
    }
}

pub(super) fn word16(data: &[u8], at: usize, le: bool) -> Option<u16> {
    if le {
        u16_le(data, at)
    } else {
        u16_be(data, at)
    }
}

/// Bits `shift..shift + len` of `v`.
pub(super) fn bits(v: u64, shift: u32, len: u32) -> u64 {
    v.checked_shr(shift).unwrap_or(0) & 1u64.checked_shl(len).unwrap_or(0).wrapping_sub(1)
}

/// The device a pool is read through.
pub(super) struct Pool {
    pub input: Input,
    /// The top-level vdev this device holds a copy of (its `id`).
    pub top: u64,
}

pub(super) type PoolRef = Arc<Pool>;

/// A block pointer (`blkptr_t`), with where it is stored.
#[derive(Clone, Copy, Debug)]
pub(super) struct Bp {
    pub w: [u64; 16],
    /// Where the pointer itself is stored (anchors derived sources).
    pub at: Span,
}

impl Bp {
    /// The pointer at `off` in `data` (stored in the block's byte order).
    pub fn parse(data: &[u8], off: usize, le: bool, at: Span) -> Option<Bp> {
        let mut w = [0u64; 16];
        for (i, slot) in w.iter_mut().enumerate() {
            *slot = word(data, off.checked_add(i.checked_mul(8)?)?, le)?;
        }
        Some(Bp { w, at })
    }

    fn prop(&self) -> u64 {
        self.w.get(6).copied().unwrap_or(0)
    }

    pub fn is_hole(&self) -> bool {
        self.w.iter().all(|&x| x == 0) || (!self.embedded() && self.birth() == 0)
    }

    pub fn embedded(&self) -> bool {
        bits(self.prop(), 39, 1) == 1
    }

    pub fn birth(&self) -> u64 {
        self.w.get(10).copied().unwrap_or(0)
    }

    /// The block's contents are little-endian.
    pub fn le(&self) -> bool {
        self.prop() >> 63 == 1
    }

    pub fn compression(&self) -> u64 {
        bits(self.prop(), 32, 7)
    }

    pub fn lsize(&self) -> u64 {
        if self.embedded() {
            bits(self.prop(), 0, 25).saturating_add(1)
        } else {
            bits(self.prop(), 0, 16).saturating_add(1) << 9
        }
    }

    pub fn psize(&self) -> u64 {
        if self.embedded() {
            bits(self.prop(), 25, 7).saturating_add(1)
        } else {
            bits(self.prop(), 16, 16).saturating_add(1) << 9
        }
    }

    fn checksum_type(&self) -> u64 {
        bits(self.prop(), 40, 8)
    }

    /// The payload of an embedded block pointer: the words other than the
    /// properties and birth txg, as stored (`BPE_GET_PAYLOAD`).
    fn payload(&self, le: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(112);
        for (i, w) in self.w.iter().enumerate() {
            if i != 6 && i != 10 {
                out.extend(if le { w.to_le_bytes() } else { w.to_be_bytes() });
            }
        }
        out.truncate(to_usize(self.psize()));
        out
    }

    /// The DVAs in use: (vdev, offset, gang).
    fn dvas(&self) -> impl Iterator<Item = (u64, u64, bool)> + '_ {
        self.w.chunks(2).take(3).filter_map(|p| match *p {
            [w0, w1] if w0 != 0 || w1 != 0 => {
                Some((bits(w0, 32, 24), bits(w1, 0, 63) << 9, w1 >> 63 == 1))
            }
            _ => None,
        })
    }
}

/// Fletcher-4 over `data` read as 32-bit words in its byte order.
fn fletcher4(data: &[u8], le: bool) -> [u64; 4] {
    let (mut a, mut b, mut c, mut d) = (0u64, 0u64, 0u64, 0u64);
    for chunk in data.as_chunks::<4>().0 {
        let w = word32(chunk, 0, le).unwrap_or(0);
        a = a.wrapping_add(w.into());
        b = b.wrapping_add(a);
        c = c.wrapping_add(b);
        d = d.wrapping_add(c);
    }
    [a, b, c, d]
}

/// Checksum algorithms (`zio_checksum`) verified here.
const FLETCHER4: u64 = 7;

/// How a block is compressed: bytes of header to skip, and the codec.
fn codec(bp: &Bp) -> Result<Option<(u64, Codec)>> {
    let lsize = bp.lsize();
    Ok(Some(match bp.compression() {
        // inherit / on never reach a block pointer; off and empty.
        0 | 2 | 4 => return Ok(None),
        3 => (0, Codec::Lzjb(lsize)),
        5..=13 => (0, Codec::Zlib),
        14 => (0, Codec::Zle(lsize)),
        // A 4-byte big-endian length, then an LZ4 block.
        15 => (4, Codec::Lz4Block),
        // The compressed length and the version and level, then a frame
        // without its magic number.
        16 => (8, Codec::ZstdMagicless),
        other => {
            return Err(Diagnostic::unsupported(format!("compression type {other}")));
        }
    }))
}

/// The compressed bytes in a physical block (after any header), if the
/// header gives their length.
fn compressed_len(bp: &Bp, head: &[u8]) -> Option<u64> {
    match bp.compression() {
        15 | 16 => u32_be(head, 0).map(u64::from),
        _ => None,
    }
}

impl Pool {
    /// The bytes on this device a DVA points to.
    fn dva_span(&self, vdev: u64, offset: u64, len: u64) -> Option<Span> {
        let dev = self.input.span;
        let at = offset.checked_add(VDEV_START)?;
        (vdev == self.top && at.checked_add(len)? <= dev.len).then(|| dev.sub(at, len))
    }

    /// The physical copies of a block readable from this device.
    fn copies(&self, bp: &Bp) -> Result<Vec<Span>> {
        let psize = bp.psize();
        let mut found = Vec::new();
        let mut why = "on another device";
        for (vdev, offset, gang) in bp.dvas() {
            if gang {
                why = "a gang block";
                continue;
            }
            if let Some(span) = self.dva_span(vdev, offset, psize) {
                found.push(span);
            }
        }
        if found.is_empty() {
            let (vdev, offset, _) = bp.dvas().next().unwrap_or_default();
            return Err(Diagnostic::unsupported(format!(
                "block at <{vdev}:{offset:#x}> is {why}"
            )));
        }
        Ok(found)
    }

    /// The logical contents of the block `bp` points to, decoded lazily and
    /// not verified (file data).
    pub async fn block(&self, cx: &Cx, bp: &Bp) -> Result<Span> {
        if bp.is_hole() {
            return Ok(Span::zeros(bp.lsize()));
        }
        if bp.embedded() {
            return self.embedded(cx, bp).await;
        }
        let raw = *self
            .copies(bp)?
            .first()
            .ok_or_else(|| Diagnostic::malformed("no copy"))?;
        self.decompress(cx, bp, raw).await
    }

    async fn embedded(&self, cx: &Cx, bp: &Bp) -> Result<Span> {
        let origin = Origin {
            parent: bp.at,
            transform: "zfs-embedded",
        };
        let raw = match cx.derived(origin) {
            Some(found) => found.span,
            None => cx.add_derived(origin, bp.payload(bp.le()), 0, None)?.span,
        };
        self.decompress(cx, bp, raw).await
    }

    async fn decompress(&self, cx: &Cx, bp: &Bp, raw: Span) -> Result<Span> {
        let lsize = bp.lsize();
        let head = cx.read_avail(raw.sub(0, 8)).await?;
        match codec(bp)? {
            None => Ok(raw.sub(0, lsize)),
            Some((skip, codec)) => {
                let body = raw.tail(skip);
                let body = match compressed_len(bp, &head) {
                    Some(len) => body.sub(0, len.min(body.len)),
                    None => body,
                };
                cx.decode_lazy(body, &codec, lsize)
            }
        }
    }

    /// A metadata block's logical contents, read and verified: copies whose
    /// checksum fails are skipped.
    pub async fn meta(&self, cx: &Cx, bp: &Bp) -> Result<(Span, Vec<u8>)> {
        if bp.lsize() > MAX_BLOCK {
            return Err(Diagnostic::limit("block larger than 16 MiB"));
        }
        if bp.is_hole() {
            let len = bp.lsize();
            return Ok((Span::zeros(len), vec![0; to_usize(len)]));
        }
        if bp.embedded() {
            let span = self.embedded(cx, bp).await?;
            return Ok((span, cx.read(span).await?));
        }
        let copies = self.copies(bp)?;
        let key = copies.first().copied();
        if let Some(found) = key.and_then(|k| cx.cached::<(Span, Vec<u8>)>(k, "zfs-block")) {
            return Ok((*found).clone());
        }
        let mut last = None;
        for raw in copies {
            if bp.checksum_type() == FLETCHER4 {
                let data = cx.read(raw).await?;
                let sum = fletcher4(&data, bp.le());
                if bp.w.get(12..16) != Some(&sum[..]) {
                    last = Some(Diagnostic::malformed(format!(
                        "fletcher4 checksum mismatch in the block at {:#x}",
                        raw.offset
                    )));
                    continue;
                }
            }
            let span = self.decompress(cx, bp, raw).await?;
            match cx.read(span).await {
                Ok(data) => {
                    if let Some(k) = key {
                        cx.cache(k, "zfs-block", Arc::new((span, data.clone())));
                    }
                    return Ok((span, data));
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| Diagnostic::malformed("no readable copy")))
    }
}

/// A dnode (`dnode_phys_t`).
#[derive(Clone, Debug)]
pub(super) struct Dnode {
    pub obj: u64,
    pub span: Span,
    pub ty: u8,
    pub indblkshift: u8,
    pub nlevels: u8,
    pub bonustype: u8,
    pub flags: u8,
    pub datablksz: u64,
    pub maxblkid: u64,
    pub used: u64,
    pub bps: Vec<Bp>,
    pub bonus: Vec<u8>,
    pub bonus_span: Span,
    pub spill: Option<Bp>,
    pub le: bool,
}

/// `DNODE_FLAG_SPILL_BLKPTR`, `DNODE_FLAG_USED_BYTES`.
const SPILL: u8 = 4;
pub(super) const USED_BYTES: u8 = 1;

impl Dnode {
    /// The dnode at `off` in `data` (a block of dnodes at `block`).
    pub fn parse(obj: u64, data: &[u8], off: usize, block: Span, le: bool) -> Option<Dnode> {
        let d = data.get(off..)?;
        let byte = |at: usize| d.get(at).copied();
        let ty = byte(0)?;
        let nblkptr = usize::from(byte(3)?);
        let extra = u64::from(byte(12)?);
        let size = DNODE_SIZE.saturating_mul(extra.saturating_add(1));
        let span = block.sub(to_u64(off), size);
        let flags = byte(7)?;
        let bonuslen = usize::from(word16(d, 10, le)?);
        let mut bps = Vec::with_capacity(nblkptr);
        for i in 0..nblkptr.min(3usize.saturating_add(to_usize(extra.saturating_mul(4)))) {
            let at = 64usize.saturating_add(i.saturating_mul(BP_SIZE));
            bps.push(Bp::parse(d, at, le, span.sub(to_u64(at), to_u64(BP_SIZE)))?);
        }
        let bonus_at = 64usize.saturating_add(nblkptr.saturating_mul(BP_SIZE));
        let bonus = d
            .get(bonus_at..bonus_at.saturating_add(bonuslen))
            .unwrap_or_default()
            .to_vec();
        let spill = if flags & SPILL != 0 {
            let at = to_usize(size).saturating_sub(BP_SIZE);
            Bp::parse(d, at, le, span.sub(to_u64(at), to_u64(BP_SIZE)))
        } else {
            None
        };
        Some(Dnode {
            obj,
            span,
            ty,
            indblkshift: byte(1)?,
            nlevels: byte(2)?,
            bonustype: byte(4)?,
            flags,
            datablksz: u64::from(word16(d, 8, le)?) << 9,
            maxblkid: word(d, 16, le)?,
            used: word(d, 24, le)?,
            bps,
            bonus_span: span.sub(to_u64(bonus_at), to_u64(bonuslen)),
            bonus,
            spill,
            le,
        })
    }

    /// The pointer to data block `blkid`, through the indirect blocks
    /// (`None` past the end or under a hole).
    pub async fn block_bp(&self, cx: &Cx, pool: &Pool, blkid: u64) -> Result<Option<Bp>> {
        let shift = u32::from(self.indblkshift.saturating_sub(7));
        if shift == 0 && self.nlevels > 1 {
            return Err(Diagnostic::malformed(
                "indirect block shift below 128 bytes",
            ));
        }
        let mut level = u32::from(self.nlevels.saturating_sub(1));
        let top = blkid.checked_shr(shift.saturating_mul(level)).unwrap_or(0);
        let Some(mut bp) = self.bps.get(to_usize(top)).copied() else {
            return Ok(None);
        };
        while level > 0 {
            if bp.is_hole() {
                return Ok(None);
            }
            let (span, data) = pool.meta(cx, &bp).await?;
            level = level.saturating_sub(1);
            let index = bits(
                blkid.checked_shr(shift.saturating_mul(level)).unwrap_or(0),
                0,
                shift,
            );
            let at = to_usize(index).saturating_mul(BP_SIZE);
            bp = Bp::parse(&data, at, bp.le(), span.sub(to_u64(at), to_u64(BP_SIZE)))
                .ok_or_else(|| Diagnostic::malformed("short indirect block"))?;
        }
        Ok(Some(bp))
    }

    /// Bytes `offset..offset + len` of the object, read and verified
    /// (metadata: ZAPs, dnode blocks).
    pub async fn read(&self, cx: &Cx, pool: &Pool, offset: u64, len: u64) -> Result<Vec<u8>> {
        let bs = self.datablksz.max(512);
        let mut out = Vec::with_capacity(to_usize(len.min(MAX_BLOCK)));
        let mut at = offset;
        let end = offset.saturating_add(len);
        while at < end {
            let blkid = at.checked_div(bs).unwrap_or(0);
            let within = at.checked_rem(bs).unwrap_or(0);
            let n = (bs.saturating_sub(within)).min(end.saturating_sub(at));
            match self.block_bp(cx, pool, blkid).await? {
                Some(bp) if !bp.is_hole() => {
                    let (_, data) = pool.meta(cx, &bp).await?;
                    let piece = data
                        .get(to_usize(within)..to_usize(within.saturating_add(n)))
                        .ok_or_else(|| Diagnostic::malformed("short block"))?;
                    out.extend_from_slice(piece);
                }
                _ => out.resize(out.len().saturating_add(to_usize(n)), 0),
            }
            at = at.saturating_add(n);
            cx.checkpoint().await;
        }
        Ok(out)
    }

    /// Data block `blkid` with the span it decodes to (`None` for a hole).
    pub async fn data_block(
        &self,
        cx: &Cx,
        pool: &Pool,
        blkid: u64,
    ) -> Result<Option<(Span, Vec<u8>)>> {
        match self.block_bp(cx, pool, blkid).await? {
            Some(bp) if !bp.is_hole() => Ok(Some(pool.meta(cx, &bp).await?)),
            _ => Ok(None),
        }
    }
}

/// An object set (`objset_phys_t`): its meta-dnode, which holds the
/// set's dnodes, and its type.
#[derive(Clone, Debug)]
pub(super) struct Objset {
    pub meta: Dnode,
    pub ty: u64,
}

pub(super) const OS_ZPL: u64 = 2;
pub(super) const OS_ZVOL: u64 = 3;

impl Objset {
    pub async fn read(cx: &Cx, pool: &Pool, bp: &Bp) -> Result<Objset> {
        let (span, data) = pool.meta(cx, bp).await?;
        let le = bp.le();
        let meta = Dnode::parse(0, &data, 0, span, le)
            .ok_or_else(|| Diagnostic::malformed("short object set"))?;
        Ok(Objset {
            meta,
            ty: word(&data, 704, le).unwrap_or(0),
        })
    }

    /// Object `obj`'s dnode.
    pub async fn dnode(&self, cx: &Cx, pool: &Pool, obj: u64) -> Result<Dnode> {
        let bs = self.meta.datablksz.max(DNODE_SIZE);
        let at = obj.saturating_mul(DNODE_SIZE);
        let Some((span, data)) = self
            .meta
            .data_block(cx, pool, at.checked_div(bs).unwrap_or(0))
            .await?
        else {
            return Err(Diagnostic::malformed(format!("object {obj} is in a hole")));
        };
        let dn = Dnode::parse(
            obj,
            &data,
            to_usize(at.checked_rem(bs).unwrap_or(0)),
            span,
            self.meta.le,
        )
        .ok_or_else(|| Diagnostic::malformed(format!("object {obj}: short dnode")))?;
        if dn.ty == 0 {
            return Err(Diagnostic::malformed(format!("object {obj} is free")));
        }
        Ok(dn)
    }
}

/// A ZAP entry's value: integers (of 1, 2, 4 or 8 bytes).
#[derive(Clone, Debug)]
pub(super) struct ZapValue {
    pub ints: Vec<u64>,
}

impl ZapValue {
    pub fn first(&self) -> Option<u64> {
        self.ints.first().copied()
    }
}

/// Entries read from one ZAP, at most.
pub(super) const MAX_ZAP: usize = 1 << 20;

const ZBT_LEAF: u64 = 1 << 63;
const ZBT_HEADER: u64 = (1 << 63) | 1;
const ZBT_MICRO: u64 = (1 << 63) | 3;
const ZAP_MAGIC: u64 = 0x2_f52a_b2ab;
const LEAF_MAGIC: u32 = 0x02ab_1eaf;
const CHUNK: usize = 24;

/// A ZAP object's entries (name, value), in storage order.
pub(super) async fn zap(cx: &Cx, pool: &Pool, dn: &Dnode) -> Result<Vec<(String, ZapValue)>> {
    let Some((_, block0)) = dn.data_block(cx, pool, 0).await? else {
        return Ok(Vec::new());
    };
    let le = dn.le;
    match word(&block0, 0, le) {
        Some(ZBT_MICRO) => Ok(micro(&block0, le)),
        Some(ZBT_HEADER) => fat(cx, pool, dn, &block0).await,
        Some(other) => Err(Diagnostic::malformed(format!(
            "not a ZAP (block type {other:#x})"
        ))),
        None => Err(Diagnostic::malformed("empty ZAP")),
    }
}

/// A micro ZAP: 64-byte entries of a value, a collision differentiator
/// and a name of up to 49 bytes.
fn micro(block: &[u8], le: bool) -> Vec<(String, ZapValue)> {
    block
        .get(64..)
        .unwrap_or_default()
        .as_chunks::<64>()
        .0
        .iter()
        .filter_map(|e| {
            let name = e.get(14..)?;
            let name = name.get(..name.iter().position(|&b| b == 0)?)?;
            if name.is_empty() {
                return None;
            }
            Some((
                String::from_utf8_lossy(name).into_owned(),
                ZapValue {
                    ints: vec![word(e, 0, le)?],
                },
            ))
        })
        .collect()
}

/// A fat ZAP: the header block, then leaves. Every leaf is read in block
/// order (the pointer table only matters for lookups).
async fn fat(cx: &Cx, pool: &Pool, dn: &Dnode, header: &[u8]) -> Result<Vec<(String, ZapValue)>> {
    let le = dn.le;
    if word(header, 8, le) != Some(ZAP_MAGIC) {
        return Err(Diagnostic::malformed("bad fat ZAP magic"));
    }
    let tbl_blk = word(header, 16, le).unwrap_or(0);
    let tbl_len = word(header, 24, le).unwrap_or(0);
    let freeblk = word(header, 56, le)
        .unwrap_or(0)
        .min(dn.maxblkid.saturating_add(1));
    let mut out = Vec::new();
    for blkid in 1..freeblk {
        if tbl_len > 0 && (tbl_blk..tbl_blk.saturating_add(tbl_len)).contains(&blkid) {
            continue;
        }
        let Some((_, leaf)) = dn.data_block(cx, pool, blkid).await? else {
            continue;
        };
        if word(&leaf, 0, le) != Some(ZBT_LEAF) || word32(&leaf, 24, le) != Some(LEAF_MAGIC) {
            continue;
        }
        leaf_entries(&leaf, le, &mut out);
        if out.len() >= MAX_ZAP {
            cx.diag(Diagnostic::limit(format!(
                "ZAP listed to {MAX_ZAP} entries"
            )));
            break;
        }
        cx.checkpoint().await;
    }
    Ok(out)
}

/// The entries of one fat ZAP leaf (`zap_leaf_phys_t`): a 48-byte header,
/// a hash table of 16-bit chunk numbers, then 24-byte chunks holding
/// entries and the arrays of their names and values.
fn leaf_entries(leaf: &[u8], le: bool, out: &mut Vec<(String, ZapValue)>) {
    let hash_entries = leaf.len() / 32;
    let base = 48usize.saturating_add(hash_entries.saturating_mul(2));
    let chunks = leaf.get(base..).unwrap_or_default();
    let chunk = |i: u16| {
        chunks
            .get(usize::from(i).saturating_mul(CHUNK)..)?
            .get(..CHUNK)
    };
    // An array of `n` bytes, from chunk `first` on.
    let array = |first: u16, n: usize| -> Option<Vec<u8>> {
        let mut data = Vec::with_capacity(n);
        let mut at = first;
        let mut hops = 0usize;
        while data.len() < n {
            let c = chunk(at)?;
            if c.first() != Some(&251) {
                return None;
            }
            let take = (n.saturating_sub(data.len())).min(21);
            data.extend_from_slice(c.get(1..1usize.saturating_add(take))?);
            at = word16(c, 22, le)?;
            hops = hops.saturating_add(1);
            if hops > chunks.len() / CHUNK {
                return None;
            }
        }
        Some(data)
    };
    for c in chunks.as_chunks::<CHUNK>().0 {
        if c.first() != Some(&252) {
            continue;
        }
        let entry = || -> Option<(String, ZapValue)> {
            let intlen = *c.get(1)?;
            let name_chunk = word16(c, 4, le)?;
            let name_len = usize::from(word16(c, 6, le)?);
            let value_chunk = word16(c, 8, le)?;
            let value_n = usize::from(word16(c, 10, le)?);
            let mut name = array(name_chunk, name_len)?;
            while name.last() == Some(&0) {
                name.pop();
            }
            let size = usize::from(intlen);
            if !matches!(size, 1 | 2 | 4 | 8) {
                return None;
            }
            let raw = array(value_chunk, value_n.saturating_mul(size))?;
            // Values are stored big-endian whatever the pool's byte order.
            let ints = raw
                .chunks_exact(size)
                .map(|b| b.iter().fold(0u64, |v, &x| (v << 8) | u64::from(x)))
                .collect();
            Some((
                String::from_utf8_lossy(&name).into_owned(),
                ZapValue { ints },
            ))
        };
        if let Some(e) = entry() {
            out.push(e);
        }
    }
}

/// The value of `key` in a ZAP's entries.
pub(super) fn lookup(entries: &[(String, ZapValue)], key: &str) -> Option<u64> {
    entries
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.first())
}
