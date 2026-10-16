//! The block area of a Partclone image (`partclone.<fs> -c`), turned back
//! into the volume it was saved from.
//!
//! A Partclone image is a header, a bitmap of the volume's blocks (which are
//! in use), and then the blocks in use, in order, each `block_size` bytes,
//! with check values between them. The container dissector reads the header
//! and the bitmap; this decoder gets the bitmap as a parameter and the area
//! after it as input, and writes every block of the volume: the next stored
//! block for a block in use, zeros for the others (as `partclone.restore`
//! leaves them, after zeroing the device).
//!
//! The check values differ between the two image formats:
//!
//! - **0002** (partclone 0.2.89 and later): after every
//!   `blocks_per_checksum` stored blocks, and after the last one, a
//!   `checksum_size`-byte check value. With CRC32 (mode `0x20`, 4 bytes) it
//!   is the raw CRC-32 register (initial value `0xffffffff`, no final
//!   inversion) over the blocks since the previous one, or with
//!   `--no-reseed` over every block so far. Mode 0 stores none.
//! - **0001** (partclone 0.2.x): after every stored block, 4 bytes: the
//!   same register carried on over the whole image, but updated with the
//!   block's *first byte* repeated `block_size` times (a bug of those
//!   versions, kept by later ones to read their images).
//!
//! Written from memory of partclone's image layout and checked against
//! images written by partclone 0.3.36 (format 0002, every checksum layout)
//! and 0.2.73 (format 0001): the check value algorithms above (including
//! format 0001's first-byte CRC) were worked out from those images and
//! `partclone.restore`'s output. No partclone code was read or copied.
//!
//! Runs of free blocks are zero runs a caller can skip (see "Zero runs" in
//! the pipeline docs). The decoder's state is a few counters and a shared
//! reference to the bitmap, so it checkpoints for almost nothing, and a container can start
//! it at any block (see [`Partclone::at`]): the bitmap says where each
//! block is stored. Checks that depend on what came before (a CRC carried
//! on from the start) are skipped by a decoder started that way.

use std::sync::Arc;

use crate::codec::crc::crc32_update;
use crate::codec::pipeline::{Decode, Step, Streaming};
use crate::error::{DiagKind, Diagnostic, Result};

/// The largest block size decoded.
pub const MAX_BLOCK: u32 = 16 << 20;
/// Free blocks looked at per step, at most, before producing their zeros.
const SCAN: u64 = 1 << 16;

/// How stored blocks are checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// No check values (format 0002, mode 0).
    None,
    /// Format 0002 CRC32: a 4-byte value after every `every` blocks and
    /// after the last; `reseed` restarts the register after each.
    Crc32 { every: u32, reseed: bool },
    /// A check value of an unknown mode, `size` bytes after every `every`
    /// blocks and after the last: skipped, unchecked.
    Other { size: u32, every: u32 },
    /// Format 0001: 4 bytes after every block, over its first byte.
    V1,
}

impl Check {
    /// Bytes of a check value and stored blocks per check value.
    pub fn layout(&self) -> (u64, u64) {
        match *self {
            Check::None => (0, 1),
            Check::Crc32 { every, .. } => (4, u64::from(every.max(1))),
            Check::Other { size, every } => (u64::from(size), u64::from(every.max(1))),
            Check::V1 => (4, 1),
        }
    }

    /// Where stored block `n` (counting stored blocks only) starts in the
    /// block area.
    pub fn offset(&self, block_size: u32, n: u64) -> u64 {
        let (size, every) = self.layout();
        n.saturating_mul(u64::from(block_size))
            .saturating_add(n.checked_div(every).unwrap_or(0).saturating_mul(size))
    }
}

/// What the decoder needs from the image header and bitmap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub block_size: u32,
    /// Blocks in the volume.
    pub blocks: u64,
    /// One bit per block, least significant first: set for blocks stored.
    /// Missing bytes read as free blocks.
    pub bitmap: Arc<[u8]>,
    /// Blocks the bitmap marks (within `blocks`): the last check value
    /// follows the last of them.
    pub stored: u64,
    pub check: Check,
    /// Check values are in the byte order of the machine that wrote the
    /// image (format 0002 records it); little-endian otherwise.
    pub big_endian: bool,
}

impl Params {
    /// Bytes the image restores.
    pub fn volume_len(&self) -> u64 {
        self.blocks.saturating_mul(u64::from(self.block_size))
    }

    /// Whether block `b` is stored.
    pub fn used(&self, b: u64) -> bool {
        let byte = usize::try_from(b / 8).ok().and_then(|i| self.bitmap.get(i));
        byte.is_some_and(|&v| v >> (b % 8) & 1 == 1)
    }

    /// Free blocks from `b`, looking at most `max` blocks ahead (and never
    /// past the volume).
    fn free_run(&self, b: u64, max: u64) -> u64 {
        let end = self.blocks.min(b.saturating_add(max));
        let mut at = b;
        while at < end {
            if at.is_multiple_of(8) && at.saturating_add(8) <= end {
                let byte = usize::try_from(at / 8)
                    .ok()
                    .and_then(|i| self.bitmap.get(i))
                    .copied()
                    .unwrap_or(0);
                if byte == 0 {
                    at = at.saturating_add(8);
                    continue;
                }
            }
            if self.used(at) {
                break;
            }
            at = at.saturating_add(1);
        }
        at.saturating_sub(b)
    }
}

/// A shortage of input (see [`Decode::truncation_is_exact`]).
fn truncated(message: String) -> Diagnostic {
    Diagnostic::new(DiagKind::Truncated, message)
}

/// The resumable decoder; positions are relative to the buffers as they are
/// now (see "Releasing" in the pipeline docs).
#[derive(Clone, Debug)]
pub struct Partclone {
    p: Arc<Params>,
    /// Input position.
    at: usize,
    /// Input released before `at` (for positions in messages).
    released: u64,
    /// The next block of the volume to produce.
    block: u64,
    /// Stored blocks consumed so far (from the image's start, also when
    /// started at a later block).
    stored: u64,
    /// Zero bytes of free blocks still to produce.
    zeros: u64,
    /// Bytes of the current stored block still to copy.
    copy: u64,
    /// A check value is due before the next block.
    due: bool,
    /// The CRC register.
    crc: u32,
    /// Whether the register covers what the next check value covers (not
    /// so for a decoder started at a later block, until a reseed).
    verify: bool,
    /// Check values that did not match, and the stored block the first
    /// such one follows.
    bad: u64,
    first_bad: Option<u64>,
    done: bool,
}

impl Partclone {
    pub fn new(p: Arc<Params>) -> Self {
        Self::at(p, 0, 0)
    }

    /// A decoder starting at volume block `block`, with `stored` stored
    /// blocks before it, given the block area from where its next stored
    /// block starts (`Check::offset`).
    pub fn at(p: Arc<Params>, block: u64, stored: u64) -> Self {
        Partclone {
            p,
            at: 0,
            released: 0,
            block,
            stored,
            zeros: 0,
            copy: 0,
            due: false,
            crc: 0xffff_ffff,
            verify: block == 0,
            bad: 0,
            first_bad: None,
            done: false,
        }
    }

    /// [`Partclone::at`] as a pipeline decoder (for seeds).
    pub fn seed(p: Arc<Params>, block: u64, stored: u64) -> Streaming<Self> {
        Streaming(Self::at(p, block, stored))
    }

    fn offset(&self, at: usize) -> u64 {
        self.released.saturating_add(crate::bytes::to_u64(at))
    }

    /// Reads the check value due at `self.at`.
    fn check(&mut self, input: &[u8]) -> Result<()> {
        let (size, _) = self.p.check.layout();
        let size = crate::bytes::to_usize(size);
        let end = self.at.saturating_add(size);
        let Some(raw) = input.get(self.at..end) else {
            return Err(truncated(format!(
                "Partclone image ends inside the check value after stored block {}",
                self.stored
            )));
        };
        let stored = raw
            .get(..4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(|b| {
                if self.p.big_endian {
                    u32::from_be_bytes(b)
                } else {
                    u32::from_le_bytes(b)
                }
            });
        let (compare, reseed) = match self.p.check {
            Check::Crc32 { reseed, .. } => (true, reseed),
            Check::V1 => (true, false),
            Check::None | Check::Other { .. } => (false, false),
        };
        if compare && self.verify && stored != Some(self.crc) {
            self.bad = self.bad.saturating_add(1);
            self.first_bad.get_or_insert(self.stored.saturating_sub(1));
        }
        if reseed {
            self.crc = 0xffff_ffff;
            self.verify = true;
        }
        self.at = end;
        self.due = false;
        Ok(())
    }

    /// Sets up the next block (or run of free blocks); `false` at the end.
    fn next(&mut self) -> Result<bool> {
        let p = &self.p;
        if self.block >= p.blocks {
            return Ok(false);
        }
        if p.used(self.block) {
            self.copy = u64::from(p.block_size);
            self.block = self.block.saturating_add(1);
            self.stored = self.stored.saturating_add(1);
            return Ok(true);
        }
        let n = p.free_run(self.block, SCAN).max(1);
        self.zeros = n.saturating_mul(u64::from(p.block_size));
        self.block = self.block.saturating_add(n);
        Ok(true)
    }

    /// Whether a check value follows the stored block just copied.
    fn check_due(&self) -> bool {
        let (size, every) = self.p.check.layout();
        if size == 0 {
            return false;
        }
        // And after the last stored block, whatever the count.
        self.stored.is_multiple_of(every) || self.stored == self.p.stored
    }
}

impl Decode for Partclone {
    fn step(
        &mut self,
        input: &[u8],
        _eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let bs = self.p.block_size;
        if bs == 0 || bs > MAX_BLOCK {
            return Err(Diagnostic::unsupported(format!("block size {bs:#x}")));
        }
        let start = out.len();
        let goal = start.saturating_add(step.max(1));
        // A run of free blocks found in this step: stop before writing its
        // zeros, so a caller that skips zero runs can (see "Zero runs" in
        // the pipeline docs); one that does not calls again and gets them.
        let mut found_free = false;
        loop {
            if self.done {
                return Ok(Step::Done);
            }
            let room = goal.saturating_sub(out.len());
            if room == 0 {
                return Ok(Step::More);
            }
            let grow = |out: &Vec<u8>, n: usize| -> Result<()> {
                if out.len().saturating_add(n) > limit {
                    return Err(Diagnostic::limit("Partclone volume exceeds the limit"));
                }
                Ok(())
            };
            if self.zeros > 0 {
                if found_free {
                    return Ok(Step::More);
                }
                let n = crate::bytes::to_usize(self.zeros).min(room);
                grow(out, n)?;
                out.resize(out.len().saturating_add(n), 0);
                self.zeros = self.zeros.saturating_sub(crate::bytes::to_u64(n));
                continue;
            }
            if self.copy > 0 {
                let avail = input.get(self.at..).unwrap_or_default();
                let Some(&first) = avail.first() else {
                    if out.len() > start {
                        return Ok(Step::More);
                    }
                    return Err(truncated(format!(
                        "Partclone image ends inside volume block {} (stored block {})",
                        self.block.saturating_sub(1),
                        self.stored.saturating_sub(1)
                    )));
                };
                if self.p.check == Check::V1 && self.copy == u64::from(bs) {
                    // The whole block's check value, from its first byte.
                    let fill = [first; 256];
                    let mut left = crate::bytes::to_usize(self.copy);
                    while left > 0 {
                        let n = left.min(fill.len());
                        self.crc = crc32_update(self.crc, fill.get(..n).unwrap_or_default());
                        left = left.saturating_sub(n);
                    }
                }
                let n = crate::bytes::to_usize(self.copy).min(room).min(avail.len());
                grow(out, n)?;
                let data = avail.get(..n).unwrap_or_default();
                if matches!(self.p.check, Check::Crc32 { .. }) {
                    self.crc = crc32_update(self.crc, data);
                }
                out.extend_from_slice(data);
                self.at = self.at.saturating_add(n);
                self.copy = self.copy.saturating_sub(crate::bytes::to_u64(n));
                if self.copy == 0 {
                    self.due = self.check_due();
                }
                continue;
            }
            if self.due {
                match self.check(input) {
                    Ok(()) => {}
                    Err(e) if out.len() > start => {
                        let _ = e;
                        return Ok(Step::More);
                    }
                    Err(e) => return Err(e),
                }
                continue;
            }
            if !self.next()? {
                self.done = true;
            }
            found_free = self.zeros > 0;
        }
    }

    fn consumed(&self) -> usize {
        self.at
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        let first = self.first_bad?;
        Some(Diagnostic::warning(format!(
            "{} check value{} of the Partclone image do{} not match, the first after stored block {first}",
            self.bad,
            if self.bad == 1 { "" } else { "s" },
            if self.bad == 1 { "es" } else { "" },
        )))
    }

    fn releasable_input(&self) -> usize {
        self.at
    }

    fn release_input(&mut self, n: usize) {
        let n = n.min(self.at);
        self.at = self.at.saturating_sub(n);
        self.released = self.released.saturating_add(crate::bytes::to_u64(n));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Nothing decoded is read again.
        out_len
    }

    fn heap_size(&self) -> Option<usize> {
        // The bitmap is shared, not copied.
        Some(0)
    }

    fn truncation_is_exact(&self) -> bool {
        true
    }

    fn window_free(&self) -> bool {
        true
    }

    fn zero_run(&self) -> u64 {
        self.zeros
    }

    fn skip_zeros(&mut self, n: u64) {
        self.zeros = self.zeros.saturating_sub(n);
    }
}

impl Partclone {
    /// Stream offset of the next input byte (for messages and tests).
    pub fn position(&self) -> u64 {
        self.offset(self.at)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::codec::Codec;
    use crate::codec::pipeline::{
        Decoder, Status, decode_all, decode_all_skipping, verify_checkpoints,
    };

    const BS: u32 = 16;

    /// Blocks 0-2 and 5 and 9 of 12 in use.
    fn bitmap() -> Arc<[u8]> {
        Arc::from(vec![0b0010_0111u8, 0b0000_0010])
    }

    fn params(check: Check) -> Arc<Params> {
        Arc::new(Params {
            block_size: BS,
            blocks: 12,
            bitmap: bitmap(),
            stored: 5,
            check,
            big_endian: false,
        })
    }

    /// The block area for `check`, block `b` filled with `b + 1` (and its
    /// first byte `0x80 | b`).
    fn area(check: Check) -> Vec<u8> {
        let used = [0u8, 1, 2, 5, 9];
        let mut s = Vec::new();
        let mut crc = 0xffff_ffffu32;
        for (i, &b) in used.iter().enumerate() {
            let mut block = vec![b + 1; BS as usize];
            block[0] = 0x80 | b;
            match check {
                Check::V1 => crc = crc32_update(crc, &[block[0]; BS as usize]),
                _ => crc = crc32_update(crc, &block),
            }
            s.extend_from_slice(&block);
            let n = i as u64 + 1;
            let last = i + 1 == used.len();
            match check {
                Check::None => {}
                Check::V1 => s.extend_from_slice(&crc.to_le_bytes()),
                Check::Crc32 { every, reseed } => {
                    if n.is_multiple_of(u64::from(every)) || last {
                        s.extend_from_slice(&crc.to_le_bytes());
                        if reseed {
                            crc = 0xffff_ffff;
                        }
                    }
                }
                Check::Other { size, every } => {
                    if n.is_multiple_of(u64::from(every)) || last {
                        s.extend(std::iter::repeat_n(0xee, size as usize));
                    }
                }
            }
        }
        s
    }

    fn expected() -> Vec<u8> {
        let mut v = vec![0u8; 12 * BS as usize];
        for b in [0usize, 1, 2, 5, 9] {
            let block = &mut v[b * BS as usize..(b + 1) * BS as usize];
            block.fill(b as u8 + 1);
            block[0] = 0x80 | b as u8;
        }
        v
    }

    fn decoder(check: Check) -> Box<dyn Decoder> {
        Codec::Partclone(params(check)).decoder().unwrap()
    }

    const CHECKS: [Check; 6] = [
        Check::None,
        Check::V1,
        Check::Crc32 {
            every: 2,
            reseed: true,
        },
        Check::Crc32 {
            every: 2,
            reseed: false,
        },
        Check::Crc32 {
            every: 100,
            reseed: true,
        },
        Check::Other { size: 2, every: 3 },
    ];

    #[test]
    fn restores_the_volume_in_every_layout() {
        for check in CHECKS {
            let s = area(check);
            let mut d = decoder(check);
            let out = decode_all(d.as_mut(), &s, 1 << 20).unwrap();
            assert_eq!(out, expected(), "{check:?}");
            assert_eq!(d.consumed(), s.len(), "{check:?}");
            assert_eq!(d.warning(&out), None, "{check:?}");
        }
    }

    #[test]
    fn offsets_follow_the_layout() {
        for check in CHECKS {
            let s = area(check);
            // Stored block 3 (volume block 5) starts with 0x85.
            let at = check.offset(BS, 3) as usize;
            assert_eq!(s[at], 0x85, "{check:?}");
        }
    }

    #[test]
    fn mismatches_are_warned() {
        for check in [
            Check::V1,
            Check::Crc32 {
                every: 2,
                reseed: true,
            },
        ] {
            let mut s = area(check);
            // The first byte of stored block 1: covered by every check.
            s[BS as usize + if check == Check::V1 { 4 } else { 0 }] ^= 1;
            let mut d = decoder(check);
            let out = decode_all(d.as_mut(), &s, 1 << 20).unwrap();
            let w = d.warning(&out).unwrap();
            assert_eq!(w.kind, DiagKind::Warning);
            assert!(w.message.contains("after stored block"), "{}", w.message);
        }
    }

    /// A big-endian writer stores its check values big-endian: they match
    /// when the image says so, and only then.
    #[test]
    fn check_values_follow_the_writers_byte_order() {
        let check = Check::Crc32 {
            every: 2,
            reseed: true,
        };
        let le = area(check);
        let mut be = le.clone();
        // The check values follow stored blocks 1, 3 and 4.
        for n in [2u64, 4, 5] {
            let at = (check.offset(BS, n) - if n % 2 == 0 { 4 } else { 0 }) as usize;
            be[at..at + 4].reverse();
        }
        let mut p = (*params(check)).clone();
        p.big_endian = true;
        let p = Arc::new(p);
        let mut d = Codec::Partclone(p.clone()).decoder().unwrap();
        let out = decode_all(d.as_mut(), &be, 1 << 20).unwrap();
        assert_eq!(out, expected());
        assert_eq!(d.warning(&out), None);
        let mut d = Codec::Partclone(p).decoder().unwrap();
        let out = decode_all(d.as_mut(), &le, 1 << 20).unwrap();
        assert!(d.warning(&out).is_some());
    }

    /// A decoder started at a later block, from where its block is stored,
    /// produces the rest of the volume.
    #[test]
    fn starts_at_any_block() {
        for check in CHECKS {
            let s = area(check);
            let p = params(check);
            let mut stored = 0;
            for b in 0..12u64 {
                let at = check.offset(BS, stored) as usize;
                let mut d = Partclone::seed(p.clone(), b, stored);
                let out = decode_all(&mut d, &s[at..], 1 << 20).unwrap();
                assert_eq!(
                    out,
                    expected()[(b * u64::from(BS)) as usize..],
                    "{check:?} {b}"
                );
                assert_eq!(d.warning(&out), None, "{check:?} {b}");
                if p.used(b) {
                    stored += 1;
                }
            }
        }
    }

    #[test]
    fn checkpoints_resume_exactly() {
        for check in CHECKS {
            let s = area(check);
            let (checked, largest) = verify_checkpoints(|| decoder(check), &s, 7, 1).unwrap();
            assert!(checked > 10, "{checked}");
            assert!(largest < 512, "{largest}");
        }
    }

    #[test]
    fn decodes_incrementally() {
        for check in CHECKS {
            let s = area(check);
            let mut d = decoder(check);
            let mut out = Vec::new();
            let mut fed = 0;
            loop {
                let eof = fed == s.len();
                match d.decode(&s[..fed], eof, &mut out, 5, 1 << 20).unwrap() {
                    Status::Done => break,
                    Status::More => {}
                    Status::NeedInput => fed += 1,
                }
            }
            assert_eq!(out, expected(), "{check:?}");
        }
    }

    #[test]
    fn truncation_is_reported() {
        for check in CHECKS {
            let s = area(check);
            for cut in [0, 5, BS as usize, s.len() - 1] {
                let e = decode_all(decoder(check).as_mut(), &s[..cut], 1 << 20).unwrap_err();
                assert_eq!(e.kind, DiagKind::Truncated, "{check:?} {cut}");
            }
        }
    }

    /// A billion free blocks cost nothing to store; they are produced a
    /// step at a time, and a limit is reported, not exceeded.
    #[test]
    fn free_space_is_produced_in_bounded_steps() {
        let p = Arc::new(Params {
            block_size: 4096,
            blocks: 1 << 30,
            bitmap: Arc::from(vec![0u8; 1 << 10]),
            stored: 0,
            check: Check::None,
            big_endian: false,
        });
        let mut d = Codec::Partclone(p.clone()).decoder().unwrap();
        let mut out = Vec::new();
        for _ in 0..10 {
            out.clear();
            assert_eq!(
                d.decode(&[], true, &mut out, 4096, 1 << 30),
                Ok(Status::More)
            );
            assert!(out.len() < 2 * 4096 && out.iter().all(|&b| b == 0));
        }
        // The first step stops after finding the free run, before its zeros.
        let mut d = Codec::Partclone(p).decoder().unwrap();
        assert_eq!(
            d.decode(&[], true, &mut Vec::new(), 1 << 20, 1000),
            Ok(Status::More)
        );
        let e = d
            .decode(&[], true, &mut Vec::new(), 1 << 20, 1000)
            .unwrap_err();
        assert_eq!(e.kind, DiagKind::Limit);
    }

    /// A caller that skips zero runs gets the same volume, in every layout,
    /// without the free blocks being written.
    #[test]
    fn free_blocks_can_be_skipped() {
        for check in CHECKS {
            let s = area(check);
            let mut d = decoder(check);
            assert!(d.window_free());
            let (out, skipped) = decode_all_skipping(d.as_mut(), &s, 1 << 20).unwrap();
            assert_eq!(out, expected(), "{check:?}");
            assert_eq!(skipped, 7 * u64::from(BS), "{check:?}");
            assert_eq!(d.warning(&out), None, "{check:?}");
        }
        // A billion free blocks: a free run per bounded scan, each skipped
        // at once.
        let p = Arc::new(Params {
            block_size: 4096,
            blocks: 1 << 30,
            bitmap: Arc::from(vec![0u8; 1 << 10]),
            stored: 0,
            check: Check::None,
            big_endian: false,
        });
        let mut d = Codec::Partclone(p).decoder().unwrap();
        let mut out = Vec::new();
        assert_eq!(
            d.decode(&[], true, &mut out, 4096, 1 << 20),
            Ok(Status::More)
        );
        assert!(out.is_empty());
        assert_eq!(d.zero_run(), SCAN * 4096);
        d.skip_zeros(SCAN * 4096);
        assert_eq!(
            d.decode(&[], true, &mut out, 4096, 1 << 20),
            Ok(Status::More)
        );
        assert!(out.is_empty());
        assert_eq!(d.zero_run(), SCAN * 4096);
    }
}
