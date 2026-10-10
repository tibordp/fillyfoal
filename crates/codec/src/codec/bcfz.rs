//! The bit-level LZ77 of Guitar Pro 6 `BCFZ` files.
//!
//! After the 4-byte `BCFZ` magic and a little-endian 32-bit decoded size
//! comes a stream of bits, most significant bit of each byte first. Each
//! token starts with one flag bit:
//!
//! - `1`: a back-reference. A 4-bit word size `n` (read MSB first), then an
//!   `n`-bit offset and an `n`-bit length, both read *least* significant
//!   bit first. `min(offset, length)` bytes are copied from `offset` bytes
//!   back; copies never overlap the bytes they produce.
//! - `0`: literals. A 2-bit count (LSB first), then that many bytes of 8
//!   bits each (MSB first, not byte-aligned).
//!
//! Decoding stops once the decoded size is reached, which may be in the
//! middle of a token (the writer's last literal run can claim more bytes
//! than it carries). The layout is that of the open GPX readers (alphaTab,
//! TuxGuitar) and was checked against a real Guitar Pro 6 file: every bit
//! is consumed and the size matches exactly.
//!
//! The codec here takes the stream *after* the 8-byte header; the container
//! dissector passes the decoded size.

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// Offsets have at most 15 bits.
const WINDOW: usize = 1 << 15;

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("BCFZ: {what}"))
}

/// Incremental decoder state: everything is a position in the input and
/// output buffers as they are now (see "Releasing" in the pipeline docs).
#[derive(Clone, Debug)]
pub struct Bcfz {
    /// Decoded size from the header.
    size: u64,
    /// Bytes produced so far, including released ones.
    produced: u64,
    /// Bit position in the (current) input buffer.
    bit: usize,
}

impl Bcfz {
    pub fn new(size: u64) -> Self {
        Bcfz {
            size,
            produced: 0,
            bit: 0,
        }
    }
}

/// An MSB-first bit reader over a slice, starting at a bit position.
struct Bits<'a> {
    data: &'a [u8],
    bit: usize,
}

impl Bits<'_> {
    fn one(&mut self) -> Result<u32> {
        let byte = self
            .data
            .get(self.bit >> 3)
            .copied()
            .ok_or_else(|| bad("stream ended early"))?;
        let shift = 7u32.saturating_sub(u32::try_from(self.bit & 7).unwrap_or(0));
        self.bit = self.bit.saturating_add(1);
        Ok(u32::from(byte >> shift & 1))
    }

    /// `n` bits, the first read being the most significant.
    fn msb(&mut self, n: u32) -> Result<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = v << 1 | self.one()?;
        }
        Ok(v)
    }

    /// `n` bits, the first read being the least significant.
    fn lsb(&mut self, n: u32) -> Result<u32> {
        let mut v = 0u32;
        for i in 0..n {
            v |= self.one()? << i;
        }
        Ok(v)
    }
}

impl Decode for Bcfz {
    fn step(
        &mut self,
        input: &[u8],
        _eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        if self.size > crate::bytes::to_u64(limit) {
            return Err(Diagnostic::output_limit(limit));
        }
        let goal = out.len().saturating_add(step);
        let mut bits = Bits {
            data: input,
            bit: self.bit,
        };
        while self.produced < self.size {
            if out.len() >= goal {
                self.bit = bits.bit;
                return Ok(Step::More);
            }
            let left =
                usize::try_from(self.size.saturating_sub(self.produced)).unwrap_or(usize::MAX);
            let before = out.len();
            if bits.one()? == 1 {
                let n = bits.msb(4)?;
                let offset = usize::try_from(bits.lsb(n)?).unwrap_or(usize::MAX);
                let len = usize::try_from(bits.lsb(n)?).unwrap_or(usize::MAX);
                let start = out
                    .len()
                    .checked_sub(offset)
                    .ok_or_else(|| bad("back-reference before the start of the output"))?;
                let count = offset.min(len).min(left);
                let end = start.saturating_add(count);
                let copy = out
                    .get(start..end)
                    .ok_or_else(|| bad("bad back-reference"))?
                    .to_vec();
                out.extend_from_slice(&copy);
            } else {
                let count = usize::try_from(bits.lsb(2)?).unwrap_or(0);
                for _ in 0..count.min(left) {
                    let byte = u8::try_from(bits.msb(8)?).unwrap_or(0);
                    out.push(byte);
                }
            }
            self.produced = self
                .produced
                .saturating_add(crate::bytes::to_u64(out.len().saturating_sub(before)));
        }
        self.bit = bits.bit;
        Ok(Step::Done)
    }

    fn consumed(&self) -> usize {
        self.bit.div_ceil(8)
    }

    fn releasable_input(&self) -> usize {
        self.bit >> 3
    }

    fn release_input(&mut self, n: usize) {
        self.bit = self.bit.saturating_sub(n.saturating_mul(8));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len.saturating_sub(WINDOW)
    }

    fn heap_size(&self) -> Option<usize> {
        // The window is in `out`.
        Some(0)
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
    use crate::codec::pipeline::{Streaming, decode_all};

    /// An MSB-first bit writer, the inverse of [`Bits`].
    #[derive(Default)]
    struct Writer {
        bytes: Vec<u8>,
        bits: usize,
    }

    impl Writer {
        fn bit(&mut self, b: u32) {
            if self.bits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if b != 0 {
                *self.bytes.last_mut().unwrap() |= 0x80 >> (self.bits % 8);
            }
            self.bits += 1;
        }
        fn msb(&mut self, v: u32, n: u32) {
            for i in (0..n).rev() {
                self.bit(v >> i & 1);
            }
        }
        fn lsb(&mut self, v: u32, n: u32) {
            for i in 0..n {
                self.bit(v >> i & 1);
            }
        }
        fn literals(&mut self, data: &[u8]) {
            for chunk in data.chunks(3) {
                self.bit(0);
                self.lsb(chunk.len() as u32, 2);
                for &b in chunk {
                    self.msb(u32::from(b), 8);
                }
            }
        }
        fn copy(&mut self, offset: u32, len: u32, n: u32) {
            self.bit(1);
            self.msb(n, 4);
            self.lsb(offset, n);
            self.lsb(len, n);
        }
    }

    #[test]
    fn checkpoints_resume_mid_stream() {
        let words = include_bytes!("testdata/words.txt");
        let mut w = Writer::default();
        w.literals(&words[..5000]);
        let mut size = 5000u64;
        for i in 0..1000u32 {
            let (offset, len) = (1000 + i * 37 % 4000, 20 + i % 300);
            w.copy(offset, len, 13);
            w.literals(&words[i as usize..i as usize + 7]);
            size += u64::from(offset.min(len)) + 7;
        }
        let (checked, largest) = crate::codec::pipeline::verify_checkpoints(
            || Box::new(Streaming(Bcfz::new(size))),
            &w.bytes,
            2000,
            3,
        )
        .unwrap();
        assert!(checked > 10, "{checked}");
        assert_eq!(largest, std::mem::size_of::<Bcfz>());
    }

    #[test]
    fn literals_and_copies() {
        let mut w = Writer::default();
        w.literals(b"abcd");
        w.copy(4, 4, 3); // abcd
        w.copy(8, 6, 4); // abcdab
        w.literals(b"!");
        let expected = b"abcdabcdabcdab!";
        let mut d = Streaming(Bcfz::new(expected.len() as u64));
        assert_eq!(decode_all(&mut d, &w.bytes, 1 << 20).unwrap(), expected);
        // Releasing the input and output windows keeps decoding correct.
        let mut tiny = Streaming(Bcfz::new(expected.len() as u64));
        let mut out = Vec::new();
        let mut input = w.bytes.clone();
        loop {
            match crate::codec::pipeline::Decoder::decode(
                &mut tiny,
                &input,
                true,
                &mut out,
                1,
                1 << 20,
            )
            .unwrap()
            {
                crate::codec::pipeline::Status::Done => break,
                _ => {
                    let n = crate::codec::pipeline::Decoder::releasable_input(&tiny);
                    crate::codec::pipeline::Decoder::release_input(&mut tiny, n);
                    input.drain(..n);
                }
            }
        }
        assert_eq!(out, expected);
    }

    #[test]
    fn stops_at_the_size_inside_a_token() {
        let mut w = Writer::default();
        w.literals(b"xyz");
        // A literal run claiming three bytes with only one left to produce
        // and the stream ending after its first byte.
        w.bit(0);
        w.lsb(3, 2);
        w.msb(u32::from(b'!'), 8);
        let mut d = Streaming(Bcfz::new(4));
        assert_eq!(decode_all(&mut d, &w.bytes, 1 << 20).unwrap(), b"xyz!");
    }

    #[test]
    fn errors() {
        let mut w = Writer::default();
        w.literals(b"a");
        w.copy(5, 5, 3);
        let mut d = Streaming(Bcfz::new(10));
        assert!(decode_all(&mut d, &w.bytes, 1 << 20).is_err());
        let mut short = Streaming(Bcfz::new(100));
        assert!(decode_all(&mut short, &[0x30, 0x80], 1 << 20).is_err());
        let mut big = Streaming(Bcfz::new(1 << 30));
        assert!(decode_all(&mut big, &[0x30], 1 << 20).is_err());
    }
}
