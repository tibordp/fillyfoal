//! ZFS's own block compressors: LZJB (its original LZRW-style compressor)
//! and ZLE (zero-length encoding). Neither records where its data ends: a
//! block's compressed data is padded to whole sectors, so both stop after
//! the block's logical size.

use crate::codec::lz::{Units, run_units};
use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// The farthest an LZJB back reference reaches (10-bit offsets).
const LZJB_WINDOW: usize = 1 << 10;

/// LZJB (`lzjb.c`): a copy-map byte announces eight items, each a literal
/// byte or a two-byte match (6-bit length + 3, 10-bit offset). Decoded an
/// item at a time; stops after `len` bytes.
#[derive(Clone)]
pub struct Lzjb {
    len: u64,
    produced: u64,
    pos: usize,
    map: u8,
    /// Items left under the current copy map.
    left: u8,
    /// Where the window starts in `out`.
    base: usize,
}

impl Lzjb {
    pub fn new(len: u64) -> Self {
        Lzjb {
            len,
            produced: 0,
            pos: 0,
            map: 0,
            left: 0,
            base: 0,
        }
    }
}

fn truncated(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("{what}: truncated data"))
}

impl Units for Lzjb {
    fn unit(
        &mut self,
        input: &[u8],
        _eof: bool,
        out: &mut Vec<u8>,
        _room: usize,
        limit: usize,
    ) -> Result<usize> {
        let (mut pos, mut map, mut left) = (self.pos, self.map, self.left);
        if left == 0 {
            map = *input.get(pos).ok_or_else(|| truncated("LZJB"))?;
            pos = pos.saturating_add(1);
            left = 8;
        }
        let rest = usize::try_from(self.len.saturating_sub(self.produced)).unwrap_or(usize::MAX);
        let made = if map & 1 != 0 {
            let hi = *input.get(pos).ok_or_else(|| truncated("LZJB"))?;
            let lo = *input
                .get(pos.saturating_add(1))
                .ok_or_else(|| truncated("LZJB"))?;
            pos = pos.saturating_add(2);
            let len = usize::from(hi >> 2).saturating_add(3).min(rest);
            let dist = (usize::from(hi & 3) << 8) | usize::from(lo);
            if dist == 0 || dist > out.len().saturating_sub(self.base) {
                return Err(Diagnostic::malformed(
                    "LZJB: match offset before the start of the output",
                ));
            }
            if out.len().saturating_add(len) > limit {
                return Err(Diagnostic::output_limit(limit));
            }
            crate::codec::lz::copy_back(out, dist, len)?;
            len
        } else {
            let b = *input.get(pos).ok_or_else(|| truncated("LZJB"))?;
            pos = pos.saturating_add(1);
            if out.len() >= limit {
                return Err(Diagnostic::output_limit(limit));
            }
            out.push(b);
            1
        };
        self.pos = pos;
        self.map = map >> 1;
        self.left = left.saturating_sub(1);
        self.produced = self.produced.saturating_add(crate::bytes::to_u64(made));
        Ok(made)
    }

    fn finished(&self) -> bool {
        self.produced >= self.len
    }

    fn progress(&self) -> usize {
        self.pos
    }
}

/// Implements [`Decode`] for a [`Units`] decoder with fields `pos` (input
/// consumed) and `base` (window start in the output), keeping `window`
/// bytes of output.
macro_rules! units_decode {
    ($ty:ty, $window:expr) => {
        impl Decode for $ty {
            fn step(
                &mut self,
                input: &[u8],
                eof: bool,
                out: &mut Vec<u8>,
                step: usize,
                limit: usize,
            ) -> Result<Step> {
                run_units(self, input, eof, out, step, limit)
            }

            fn consumed(&self) -> usize {
                self.pos
            }

            fn releasable_input(&self) -> usize {
                self.pos
            }

            fn release_input(&mut self, n: usize) {
                self.pos = self.pos.saturating_sub(n);
            }

            fn releasable_output(&self, out_len: usize) -> usize {
                out_len.saturating_sub($window).max(self.base).min(out_len)
            }

            fn release_output(&mut self, n: usize) {
                self.base = self.base.saturating_sub(n);
            }

            fn heap_size(&self) -> Option<usize> {
                // The window is in `out`.
                Some(0)
            }
        }
    };
}

units_decode!(Lzjb, LZJB_WINDOW);

/// ZLE (`zle.c`, with ZFS's level of 64): a length byte `n` is followed by
/// `n + 1` literal bytes if `n < 64`, otherwise stands for `n - 63` zeros.
/// Stops after `len` bytes.
#[derive(Clone)]
pub struct Zle {
    len: u64,
    produced: u64,
    pos: usize,
    base: usize,
}

impl Zle {
    pub fn new(len: u64) -> Self {
        Zle {
            len,
            produced: 0,
            pos: 0,
            base: 0,
        }
    }
}

/// Runs shorter than this many bytes are literals (ZFS's ZLE level).
const ZLE_LEVEL: usize = 64;

impl Units for Zle {
    fn unit(
        &mut self,
        input: &[u8],
        _eof: bool,
        out: &mut Vec<u8>,
        _room: usize,
        limit: usize,
    ) -> Result<usize> {
        let n =
            usize::from(*input.get(self.pos).ok_or_else(|| truncated("ZLE"))?).saturating_add(1);
        let rest = usize::try_from(self.len.saturating_sub(self.produced)).unwrap_or(usize::MAX);
        let start = self.pos.saturating_add(1);
        let (made, next) = if n <= ZLE_LEVEL {
            let lit = input
                .get(start..start.saturating_add(n))
                .ok_or_else(|| truncated("ZLE"))?;
            let lit = lit.get(..n.min(rest)).unwrap_or(lit);
            if out.len().saturating_add(lit.len()) > limit {
                return Err(Diagnostic::output_limit(limit));
            }
            out.extend_from_slice(lit);
            (lit.len(), start.saturating_add(n))
        } else {
            let zeros = n.saturating_sub(ZLE_LEVEL).min(rest);
            if out.len().saturating_add(zeros) > limit {
                return Err(Diagnostic::output_limit(limit));
            }
            out.resize(out.len().saturating_add(zeros), 0);
            (zeros, start)
        };
        self.pos = next;
        self.produced = self.produced.saturating_add(crate::bytes::to_u64(made));
        Ok(made)
    }

    fn finished(&self) -> bool {
        self.produced >= self.len
    }

    fn progress(&self) -> usize {
        self.pos
    }
}

units_decode!(Zle, 0);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn run(d: &mut impl Decode, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        while d.step(input, true, &mut out, usize::MAX, 1 << 20).unwrap() == Step::More {}
        out
    }

    #[test]
    fn lzjb_literals_and_matches() {
        // Map 0b0000_0100: two literals "ab", then a match of 6 bytes at
        // distance 2 (length 6 - 3 = 3, so hi = 3 << 2), then padding.
        let input = [0b100, b'a', b'b', 3 << 2, 2, 0xee, 0xee];
        assert_eq!(run(&mut Lzjb::new(8), &input), b"abababab");
    }

    #[test]
    fn zle_literals_and_zeros() {
        // "xyz", then 10 zeros (63 + 10 = 73), then "!" and padding.
        let input = [2, b'x', b'y', b'z', 73, 0, b'!', 0xff];
        let mut want = b"xyz".to_vec();
        want.extend([0; 10]);
        want.push(b'!');
        assert_eq!(run(&mut Zle::new(14), &input), want);
    }
}
