//! BZZ, DjVu's general-purpose compressor (DjVuLibre's `BSByteStream`):
//! blocks of a Burrows-Wheeler transform whose output is ranked by a
//! frequency-sorted move-to-front list and coded with the ZP adaptive
//! binary arithmetic coder. DjVu uses it for the multi-page directory
//! (`DIRM`), bookmarks (`NAVM`), hidden text (`TXTz`), annotations
//! (`ANTz`) and foreground color indices (`FGbz`).
//!
//! The stream is one ZP-coded bit sequence (most significant bit first,
//! the coder reading `0xff` past the end of its input) holding blocks:
//!
//! - the block size `n + 1` as 24 raw (equiprobable) bits; zero ends the
//!   stream. Blocks are at most 4 MiB.
//! - the frequency-estimation speed (0 to 2) as up to two raw bits.
//! - `n + 1` symbols: the BWT of the block with an end marker that sorts
//!   before every byte. Each symbol is the rank of the byte in the
//!   move-to-front list, coded with adaptive contexts by magnitude (0, 1,
//!   2-3, 4-7, ... 128-255; contexts for 0 and 1 also depend on the
//!   previous rank); a rank of 256 (every test failing) is the marker.
//!   After each byte the list is reordered by decaying frequencies of its
//!   first four entries.
//!
//! The contexts carry over from one block to the next; the list does not.
//!
//! Written from memory of DjVuLibre's `ZPCodec.cpp` (including its state
//! table and the ZP interval-reversion fix) and `BSByteStream.cpp`, not
//! from a fetched copy, and not checked against files written by
//! DjVuLibre (whose tools were not available): the test vectors come from
//! `tests/data/djvu/bzz.py`, an encoder written from the same recollection.

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

const P: [u16; 256] = [
    0x8000, 0x8000, 0x8000, 0x6bbd, 0x6bbd, 0x5d45, 0x5d45, 0x51b9, 0x51b9, 0x4813, 0x4813, 0x3fd5,
    0x3fd5, 0x38b1, 0x38b1, 0x3275, 0x3275, 0x2cfd, 0x2cfd, 0x2825, 0x2825, 0x23ab, 0x23ab, 0x1f87,
    0x1f87, 0x1bbb, 0x1bbb, 0x1845, 0x1845, 0x1523, 0x1523, 0x1253, 0x1253, 0x0fcf, 0x0fcf, 0x0d95,
    0x0d95, 0x0b9d, 0x0b9d, 0x09e3, 0x09e3, 0x0861, 0x0861, 0x0711, 0x0711, 0x05f1, 0x05f1, 0x04f9,
    0x04f9, 0x0425, 0x0425, 0x0371, 0x0371, 0x02d9, 0x02d9, 0x0259, 0x0259, 0x01ed, 0x01ed, 0x0193,
    0x0193, 0x0149, 0x0149, 0x010b, 0x010b, 0x00d5, 0x00d5, 0x00a5, 0x00a5, 0x007b, 0x007b, 0x0057,
    0x0057, 0x003b, 0x003b, 0x0023, 0x0023, 0x0013, 0x0013, 0x0007, 0x0007, 0x0001, 0x0001, 0x5695,
    0x24ee, 0x8000, 0x0d30, 0x481a, 0x0481, 0x3579, 0x017a, 0x24ef, 0x007b, 0x1978, 0x0028, 0x10ca,
    0x000d, 0x0b5d, 0x0034, 0x078a, 0x00a0, 0x050f, 0x0117, 0x0358, 0x01ea, 0x0234, 0x0144, 0x0173,
    0x0234, 0x00f5, 0x0353, 0x00a1, 0x05c5, 0x011a, 0x03cf, 0x01aa, 0x0285, 0x0286, 0x01ab, 0x03d3,
    0x011a, 0x05c5, 0x00ba, 0x08ad, 0x007a, 0x0ccc, 0x01eb, 0x1302, 0x02e6, 0x1b81, 0x045e, 0x24ef,
    0x0690, 0x2865, 0x09de, 0x3987, 0x0dc8, 0x2c99, 0x10ca, 0x3b5f, 0x0b5d, 0x5695, 0x078a, 0x8000,
    0x050f, 0x24ee, 0x0358, 0x0d30, 0x0234, 0x0481, 0x0173, 0x017a, 0x00f5, 0x007b, 0x00a1, 0x0028,
    0x011a, 0x000d, 0x01aa, 0x0034, 0x0286, 0x00a0, 0x03d3, 0x0117, 0x05c5, 0x01ea, 0x08ad, 0x0144,
    0x0ccc, 0x0234, 0x1302, 0x0353, 0x1b81, 0x05c5, 0x24ef, 0x03cf, 0x2b74, 0x0285, 0x201d, 0x01ab,
    0x1715, 0x011a, 0x0fb7, 0x00ba, 0x0a67, 0x01eb, 0x06e7, 0x02e6, 0x0496, 0x045e, 0x030d, 0x0690,
    0x0206, 0x09de, 0x0155, 0x0dc8, 0x00e1, 0x2b74, 0x0094, 0x201d, 0x0188, 0x1715, 0x0252, 0x0fb7,
    0x0383, 0x0a67, 0x0547, 0x06e7, 0x07e2, 0x0496, 0x0bc0, 0x030d, 0x1178, 0x0206, 0x19da, 0x0155,
    0x24ef, 0x00e1, 0x320e, 0x0094, 0x432a, 0x0188, 0x447d, 0x0252, 0x5ece, 0x0383, 0x8000, 0x0547,
    0x481a, 0x07e2, 0x3579, 0x0bc0, 0x24ef, 0x1178, 0x1978, 0x19da, 0x2865, 0x24ef, 0x3987, 0x320e,
    0x2c99, 0x432a, 0x3b5f, 0x447d, 0x5695, 0x5ece, 0x8000, 0x8000, 0x5695, 0x481a, 0x481a, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000,
];
const M: [u16; 256] = [
    0x0000, 0x0000, 0x0000, 0x10a5, 0x10a5, 0x1f28, 0x1f28, 0x2bd3, 0x2bd3, 0x36e3, 0x36e3, 0x408c,
    0x408c, 0x48fd, 0x48fd, 0x505d, 0x505d, 0x56d0, 0x56d0, 0x5c71, 0x5c71, 0x615b, 0x615b, 0x65a5,
    0x65a5, 0x6962, 0x6962, 0x6ca2, 0x6ca2, 0x6f74, 0x6f74, 0x71e6, 0x71e6, 0x7404, 0x7404, 0x75d6,
    0x75d6, 0x7768, 0x7768, 0x78c2, 0x78c2, 0x79ea, 0x79ea, 0x7ae7, 0x7ae7, 0x7bbe, 0x7bbe, 0x7c75,
    0x7c75, 0x7d0f, 0x7d0f, 0x7d91, 0x7d91, 0x7dfe, 0x7dfe, 0x7e5a, 0x7e5a, 0x7ea6, 0x7ea6, 0x7ee6,
    0x7ee6, 0x7f1a, 0x7f1a, 0x7f45, 0x7f45, 0x7f6b, 0x7f6b, 0x7f8d, 0x7f8d, 0x7faa, 0x7faa, 0x7fc3,
    0x7fc3, 0x7fd7, 0x7fd7, 0x7fe7, 0x7fe7, 0x7ff2, 0x7ff2, 0x7ffa, 0x7ffa, 0x7fff, 0x7fff, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000,
];
const UP: [u8; 256] = [
    84, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
    75, 76, 77, 78, 79, 80, 81, 82, 81, 82, 9, 86, 5, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 82,
    99, 76, 101, 70, 103, 66, 105, 106, 107, 66, 109, 60, 111, 56, 69, 114, 65, 116, 61, 118, 57,
    120, 53, 122, 49, 124, 43, 72, 39, 60, 33, 56, 29, 52, 23, 48, 23, 42, 137, 38, 21, 140, 15,
    142, 9, 144, 141, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 70, 157, 66, 81, 62, 75,
    58, 69, 54, 65, 50, 167, 44, 65, 40, 59, 34, 55, 30, 175, 24, 177, 178, 179, 180, 181, 182,
    183, 184, 69, 186, 59, 188, 55, 190, 51, 192, 47, 194, 41, 196, 37, 198, 199, 72, 201, 62, 203,
    58, 205, 54, 207, 50, 209, 46, 211, 40, 213, 36, 215, 30, 217, 26, 219, 20, 71, 14, 61, 14, 57,
    8, 53, 228, 49, 230, 45, 232, 39, 234, 35, 138, 29, 24, 25, 240, 19, 22, 13, 16, 13, 10, 7,
    244, 249, 10, 89, 230, 0, 0, 0, 0, 0,
];
const DN: [u8; 256] = [
    145, 4, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
    72, 73, 74, 75, 76, 77, 78, 79, 80, 85, 226, 6, 176, 143, 138, 141, 112, 135, 104, 133, 100,
    129, 98, 127, 72, 125, 102, 123, 60, 121, 110, 119, 108, 117, 54, 115, 48, 113, 134, 59, 132,
    55, 130, 51, 128, 47, 126, 41, 62, 37, 66, 31, 54, 25, 50, 131, 46, 17, 40, 15, 136, 7, 32,
    139, 172, 9, 170, 85, 168, 248, 166, 247, 164, 197, 162, 95, 160, 173, 158, 165, 156, 161, 60,
    159, 56, 71, 52, 163, 48, 59, 42, 171, 38, 169, 32, 53, 26, 47, 174, 193, 18, 191, 222, 189,
    218, 187, 216, 185, 214, 61, 212, 53, 210, 49, 208, 45, 206, 39, 204, 195, 202, 31, 200, 243,
    64, 239, 56, 237, 52, 235, 48, 233, 44, 231, 38, 229, 34, 227, 28, 225, 22, 223, 16, 221, 220,
    63, 8, 55, 224, 51, 2, 47, 87, 43, 246, 37, 244, 33, 238, 27, 236, 21, 16, 15, 8, 241, 242, 7,
    10, 245, 2, 1, 83, 250, 2, 143, 246, 0, 0, 0, 0, 0,
];

/// The largest block DjVuLibre accepts (4096 KiB).
const MAX_BLOCK: u32 = 4096 * 1024;
/// Contexts used by the symbol coder.
const CONTEXTS: usize = 300;
/// Move-to-front entries whose position follows their frequency.
const FREQMAX: usize = 4;
/// Contexts per position for ranks 0 and 1 (by the previous rank).
const CTXIDS: usize = 3;

fn bad(msg: &str) -> Diagnostic {
    Diagnostic::malformed(format!("bzz: {msg}"))
}

/// The ZP decoder's state.
#[derive(Clone, Debug, Default)]
struct Zp {
    a: u32,
    code: u32,
    fence: u32,
    buffer: u32,
    /// Bits left in `buffer`.
    scount: u32,
    /// `0xff` bytes the coder may still read past the end.
    delay: u32,
    /// Input position (relative to the buffer as it is now).
    pos: usize,
}

impl Zp {
    fn next_byte(&mut self, input: &[u8], eof: bool, padded: bool) -> Result<u32> {
        if let Some(&b) = input.get(self.pos) {
            self.pos = self.pos.saturating_add(1);
            return Ok(b.into());
        }
        if !eof {
            return Err(bad("stream ended early"));
        }
        if padded {
            self.delay = self.delay.saturating_sub(1);
            if self.delay < 1 {
                return Err(bad("unexpected end of data"));
            }
        }
        Ok(0xff)
    }

    fn start(&mut self, input: &[u8], eof: bool) -> Result<()> {
        let hi = self.next_byte(input, eof, false)?;
        let lo = self.next_byte(input, eof, false)?;
        self.code = hi << 8 | lo;
        self.a = 0;
        self.delay = 25;
        self.scount = 0;
        self.buffer = 0;
        self.preload(input, eof)?;
        self.set_fence();
        Ok(())
    }

    fn preload(&mut self, input: &[u8], eof: bool) -> Result<()> {
        while self.scount <= 24 {
            let byte = self.next_byte(input, eof, true)?;
            self.buffer = self.buffer.wrapping_shl(8) | byte;
            self.scount = self.scount.saturating_add(8);
        }
        Ok(())
    }

    fn set_fence(&mut self) {
        self.fence = self.code.min(0x7fff);
    }

    /// The low `n` bits of the buffer below the read position.
    fn take(&mut self, n: u32) -> u32 {
        self.scount = self.scount.saturating_sub(n);
        let mask = 1u32.wrapping_shl(n).wrapping_sub(1);
        self.buffer.wrapping_shr(self.scount) & mask
    }

    fn mps(&mut self, z: u32, input: &[u8], eof: bool) -> Result<()> {
        self.a = z.wrapping_shl(1) & 0xffff;
        let bit = self.take(1);
        self.code = (self.code.wrapping_shl(1) & 0xffff) | bit;
        if self.scount < 16 {
            self.preload(input, eof)?;
        }
        self.set_fence();
        Ok(())
    }

    fn lps(&mut self, z: u32, input: &[u8], eof: bool) -> Result<()> {
        let z = 0x10000u32.saturating_sub(z);
        self.a = self.a.saturating_add(z);
        self.code = self.code.saturating_add(z);
        // Leading one bits of the 16-bit interval (at least one).
        let a16 = u16::try_from(self.a & 0xffff).unwrap_or(u16::MAX);
        let shift = (!a16).leading_zeros().min(16);
        self.a = self.a.wrapping_shl(shift) & 0xffff;
        let bits = self.take(shift);
        self.code = (self.code.wrapping_shl(shift) & 0xffff) | bits;
        if self.scount < 16 {
            self.preload(input, eof)?;
        }
        self.set_fence();
        Ok(())
    }

    /// Decodes a bit with an adaptive context.
    fn bit(&mut self, ctx: &mut u8, input: &[u8], eof: bool) -> Result<u32> {
        let state = usize::from(*ctx);
        let mps = u32::from(*ctx & 1);
        let z = self
            .a
            .saturating_add(P.get(state).copied().unwrap_or(0).into());
        if z <= self.fence {
            self.a = z;
            return Ok(mps);
        }
        // The ZP interval-reversion fix.
        let d = 0x6000u32.saturating_add(z.saturating_add(self.a) >> 2);
        let z = z.min(d);
        if z > self.code {
            *ctx = DN.get(state).copied().unwrap_or(0);
            self.lps(z, input, eof)?;
            Ok(mps ^ 1)
        } else {
            if self.a >= u32::from(M.get(state).copied().unwrap_or(0)) {
                *ctx = UP.get(state).copied().unwrap_or(0);
            }
            self.mps(z, input, eof)?;
            Ok(mps)
        }
    }

    /// Decodes an equiprobable bit (no context).
    fn raw_bit(&mut self, input: &[u8], eof: bool) -> Result<u32> {
        let z = 0x8000u32.saturating_add(self.a >> 1);
        if z > self.code {
            self.lps(z, input, eof)?;
            Ok(1)
        } else {
            self.mps(z, input, eof)?;
            Ok(0)
        }
    }

    fn raw(&mut self, bits: u32, input: &[u8], eof: bool) -> Result<u32> {
        let mut n = 0u32;
        for _ in 0..bits {
            n = n.wrapping_shl(1) | self.raw_bit(input, eof)?;
        }
        Ok(n)
    }
}

/// Incremental BZZ decoder: each step decodes whole blocks.
#[derive(Clone, Debug)]
pub struct Bzz {
    zp: Zp,
    ctx: [u8; CONTEXTS],
    started: bool,
    done: bool,
}

impl Default for Bzz {
    fn default() -> Self {
        Bzz {
            zp: Zp::default(),
            ctx: [0; CONTEXTS],
            started: false,
            done: false,
        }
    }
}

impl Bzz {
    /// `bits`-bit number coded with the binary tree of contexts at `base`.
    fn binary(&mut self, base: usize, bits: u32, input: &[u8], eof: bool) -> Result<usize> {
        let mut n = 1usize;
        let m = 1usize.wrapping_shl(bits);
        while n < m {
            let at = base.saturating_add(n).saturating_sub(1);
            let Some(ctx) = self.ctx.get_mut(at) else {
                return Err(bad("context out of range"));
            };
            let b = self.zp.bit(ctx, input, eof)?;
            n = n.wrapping_shl(1) | usize::try_from(b).unwrap_or(0);
        }
        Ok(n.saturating_sub(m))
    }

    fn ctx_bit(&mut self, at: usize, input: &[u8], eof: bool) -> Result<bool> {
        let Some(ctx) = self.ctx.get_mut(at) else {
            return Err(bad("context out of range"));
        };
        Ok(self.zp.bit(ctx, input, eof)? == 1)
    }

    /// The next move-to-front rank (256 for the end marker).
    fn rank(&mut self, prev: usize, input: &[u8], eof: bool) -> Result<usize> {
        let ctxid = prev.min(CTXIDS - 1);
        if self.ctx_bit(ctxid, input, eof)? {
            return Ok(0);
        }
        if self.ctx_bit(CTXIDS.saturating_add(ctxid), input, eof)? {
            return Ok(1);
        }
        let mut base = 2 * CTXIDS;
        let mut low = 2usize;
        for bits in 1..=7u32 {
            if self.ctx_bit(base, input, eof)? {
                let v = self.binary(base.saturating_add(1), bits, input, eof)?;
                return Ok(low.saturating_add(v));
            }
            base = base.saturating_add(1usize.wrapping_shl(bits));
            low = low.saturating_mul(2);
        }
        Ok(256)
    }

    /// Decodes one block onto `out`; false at the end of the stream.
    fn block(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, limit: usize) -> Result<bool> {
        let size = self.zp.raw(24, input, eof)?;
        if size == 0 {
            return Ok(false);
        }
        if size > MAX_BLOCK {
            return Err(bad("block too large"));
        }
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        if out.len().saturating_add(size).saturating_sub(1) > limit {
            return Err(Diagnostic::output_limit(limit));
        }
        let mut fshift = 0u32;
        if self.zp.raw_bit(input, eof)? == 1 {
            fshift = 1;
            if self.zp.raw_bit(input, eof)? == 1 {
                fshift = 2;
            }
        }
        let mut mtf: [u8; 256] = core::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
        let mut freq = [0u32; FREQMAX];
        let mut fadd = 4u32;
        let mut prev = 3usize;
        let mut marker = None;
        let mut data = Vec::new();
        for i in 0..size {
            let rank = self.rank(prev, input, eof)?;
            prev = rank;
            if rank >= 256 {
                data.push(0);
                marker = Some(i);
                continue;
            }
            let c = mtf.get(rank).copied().unwrap_or(0);
            data.push(c);
            fadd = fadd.saturating_add(fadd >> fshift);
            if fadd > 0x1000_0000 {
                fadd >>= 24;
                for f in &mut freq {
                    *f >>= 24;
                }
            }
            let mut fc = fadd;
            if let Some(f) = freq.get(rank) {
                fc = fc.saturating_add(*f);
            }
            let mut k = rank;
            while k >= FREQMAX {
                let v = mtf.get(k.saturating_sub(1)).copied().unwrap_or(0);
                if let Some(slot) = mtf.get_mut(k) {
                    *slot = v;
                }
                k = k.saturating_sub(1);
            }
            while k > 0 {
                let before = freq.get(k.saturating_sub(1)).copied().unwrap_or(0);
                if fc < before {
                    break;
                }
                let v = mtf.get(k.saturating_sub(1)).copied().unwrap_or(0);
                if let Some(slot) = mtf.get_mut(k) {
                    *slot = v;
                }
                if let Some(slot) = freq.get_mut(k) {
                    *slot = before;
                }
                k = k.saturating_sub(1);
            }
            if let Some(slot) = mtf.get_mut(k) {
                *slot = c;
            }
            if let Some(slot) = freq.get_mut(k) {
                *slot = fc;
            }
        }
        let marker = match marker {
            Some(m) if m >= 1 && m < size => m,
            _ => return Err(bad("missing block marker")),
        };
        unsort(&data, marker, out)?;
        Ok(true)
    }
}

/// Inverts the Burrows-Wheeler transform of `data` (whose end marker is at
/// `marker`) onto `out`.
fn unsort(data: &[u8], marker: usize, out: &mut Vec<u8>) -> Result<()> {
    let size = data.len();
    let mut count = [0u32; 256];
    let mut posn = Vec::with_capacity(size);
    for (i, &c) in data.iter().enumerate() {
        if i == marker {
            posn.push(0);
            continue;
        }
        let slot = count.get_mut(usize::from(c)).ok_or_else(|| bad("symbol"))?;
        posn.push(u32::from(c) << 24 | (*slot & 0x00ff_ffff));
        *slot = slot.saturating_add(1);
    }
    let mut last = 1u32;
    for slot in &mut count {
        let n = *slot;
        *slot = last;
        last = last.saturating_add(n);
    }
    let start = out.len();
    out.resize(start.saturating_add(size.saturating_sub(1)), 0);
    let mut i = 0usize;
    let mut left = size.saturating_sub(1);
    while left > 0 {
        let n = posn.get(i).copied().ok_or_else(|| bad("corrupt block"))?;
        let c = n >> 24;
        left = left.saturating_sub(1);
        if let Some(slot) = out.get_mut(start.saturating_add(left)) {
            *slot = u8::try_from(c).unwrap_or(0);
        }
        let base = count
            .get(usize::try_from(c).unwrap_or(0))
            .copied()
            .unwrap_or(0);
        i = usize::try_from(base.saturating_add(n & 0x00ff_ffff)).unwrap_or(usize::MAX);
    }
    if i != marker {
        out.truncate(start);
        return Err(bad("corrupt block"));
    }
    Ok(())
}

impl Decode for Bzz {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        if !self.started {
            self.zp.start(input, eof)?;
            self.started = true;
        }
        let goal = out.len().saturating_add(step.max(1));
        loop {
            if self.done {
                return Ok(Step::Done);
            }
            if out.len() >= goal {
                return Ok(Step::More);
            }
            if !self.block(input, eof, out, limit)? {
                self.done = true;
            }
        }
    }

    fn consumed(&self) -> usize {
        self.zp.pos
    }

    fn releasable_input(&self) -> usize {
        self.zp.pos
    }

    fn release_input(&mut self, n: usize) {
        self.zp.pos = self.zp.pos.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Blocks are independent of earlier output.
        out_len
    }

    fn heap_size(&self) -> Option<usize> {
        // Steps end between blocks, which are independent: no window,
        // and the context models are inline.
        Some(0)
    }
}

/// Decodes a whole BZZ stream (for callers holding all of it).
pub fn decode(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut d = crate::codec::pipeline::Streaming(Bzz::default());
    crate::codec::pipeline::decode_all(&mut d, input, limit)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{Decoder, Status, Streaming};

    // Vectors written by `tests/data/djvu/bzz.py` (see the module docs):
    // `encode(words[:4096])`, the same with 1000-byte blocks, and `encode(b"")`.
    #[test]
    fn checkpoints_between_blocks_are_free() {
        let (checked, largest) = crate::codec::pipeline::verify_checkpoints(
            || Box::new(Streaming(Bzz::default())),
            include_bytes!("testdata/words-blocks.bzz"),
            1,
            1,
        )
        .unwrap();
        // Four blocks of 1000 bytes and one of 96.
        assert!(checked >= 3, "{checked}");
        assert_eq!(largest, std::mem::size_of::<Bzz>());
    }

    #[test]
    fn decodes_reference_vectors() {
        let words = &include_bytes!("testdata/words.txt")[..4096];
        assert_eq!(
            decode(include_bytes!("testdata/words.bzz"), 1 << 20).unwrap(),
            words
        );
        assert_eq!(
            decode(include_bytes!("testdata/words-blocks.bzz"), 1 << 20).unwrap(),
            words
        );
        assert_eq!(
            decode(include_bytes!("testdata/empty.bzz"), 1 << 20).unwrap(),
            b""
        );
    }

    #[test]
    fn incremental_with_release() {
        let words = &include_bytes!("testdata/words.txt")[..4096];
        let data = include_bytes!("testdata/words-blocks.bzz");
        let mut d = Streaming(Bzz::default());
        let mut out = Vec::new();
        let mut kept = Vec::new();
        let mut fed = 0usize;
        let mut input: Vec<u8> = Vec::new();
        loop {
            let eof = fed >= data.len();
            match d.decode(&input, eof, &mut out, 100, 1 << 20).unwrap() {
                Status::Done => break,
                Status::More => {}
                Status::NeedInput => {
                    let n = 7.min(data.len() - fed);
                    input.extend_from_slice(&data[fed..fed + n]);
                    fed += n;
                }
            }
            let n = d.releasable_input();
            d.release_input(n);
            input.drain(..n);
            let m = d.releasable_output(out.len());
            d.release_output(m);
            kept.extend(out.drain(..m));
        }
        kept.extend(out);
        assert_eq!(kept, words);
    }

    #[test]
    fn limits_and_garbage() {
        let data = include_bytes!("testdata/words.bzz");
        assert!(decode(data, 1000).is_err());
        assert!(decode(&data[..data.len() / 2], 1 << 20).is_err());
        for seed in 0..64u32 {
            let junk: Vec<u8> = (0..64u32)
                .map(|i| (i.wrapping_mul(2_654_435_761).wrapping_add(seed * 977) >> 13) as u8)
                .collect();
            let _ = decode(&junk, 1 << 16);
        }
    }
}
