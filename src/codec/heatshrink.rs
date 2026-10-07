//! Heatshrink (Atomic Object's LZSS for embedded systems), as used by Prusa
//! binary G-code blocks.
//!
//! The stream is a sequence of bits, most significant bit of each byte
//! first, with no header and no end marker. Each token starts with a tag
//! bit:
//!
//! - `1`: a literal, the next 8 bits.
//! - `0`: a back-reference: a `window`-bit index and a `lookahead`-bit
//!   count, both MSB first; `count + 1` bytes are copied from `index + 1`
//!   bytes back (copies may overlap the bytes they produce).
//!
//! The parameters (window and lookahead sizes as powers of two) are not
//! stored in the stream; the container names them. The stream ends when the
//! input runs out: the encoder pads its last byte with zero bits, which can
//! never complete a back-reference, so leftover bits are padding. Like the
//! reference decoder, references reaching before the start of the output
//! read zeros (its window starts zero-filled).
//!
//! Checked byte-exact against the reference C implementation through the
//! `heatshrink2` Python bindings (see the tests).

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// Incremental decoder state; positions are relative to the buffers as they
/// are now (see "Releasing" in the pipeline docs).
#[derive(Clone, Debug)]
pub struct Heatshrink {
    window: u8,
    lookahead: u8,
    /// Bit position in the (current) input buffer.
    bit: usize,
    /// Bytes produced so far, including released ones.
    produced: usize,
}

impl Heatshrink {
    /// A decoder for a stream with `window` and `lookahead` bits (4 to 15
    /// and 3 to `window - 1` in the reference implementation).
    pub fn new(window: u8, lookahead: u8) -> Self {
        Heatshrink {
            window,
            lookahead,
            bit: 0,
            produced: 0,
        }
    }
}

fn bits_at(data: &[u8], bit: usize, n: u32) -> u32 {
    let mut v = 0u32;
    for i in 0..n {
        let at = bit.saturating_add(usize::try_from(i).unwrap_or(0));
        let byte = data.get(at >> 3).copied().unwrap_or(0);
        let shift = 7u32.saturating_sub(u32::try_from(at & 7).unwrap_or(0));
        v = v << 1 | u32::from(byte >> shift & 1);
    }
    v
}

impl Decode for Heatshrink {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        if !(4..=15).contains(&self.window) || self.lookahead < 1 || self.lookahead >= self.window {
            return Err(Diagnostic::malformed(format!(
                "heatshrink: invalid parameters (window {}, lookahead {})",
                self.window, self.lookahead
            )));
        }
        let total = input.len().saturating_mul(8);
        let goal = out.len().saturating_add(step);
        let reference = 1usize
            .saturating_add(usize::from(self.window))
            .saturating_add(usize::from(self.lookahead));
        loop {
            if out.len() >= goal {
                return Ok(Step::More);
            }
            let left = total.saturating_sub(self.bit);
            let literal = left >= 9 && bits_at(input, self.bit, 1) == 1;
            let need = if literal { 9 } else { reference };
            if left < need {
                // Fewer bits than a token: padding at the end of the stream.
                if eof {
                    return Ok(Step::Done);
                }
                return Err(Diagnostic::malformed("heatshrink: stream ended early"));
            }
            let body = self.bit.saturating_add(1);
            let before = out.len();
            if literal {
                out.push(u8::try_from(bits_at(input, body, 8)).unwrap_or(0));
            } else {
                let index = usize::try_from(bits_at(input, body, self.window.into())).unwrap_or(0);
                let count = usize::try_from(bits_at(
                    input,
                    body.saturating_add(self.window.into()),
                    self.lookahead.into(),
                ))
                .unwrap_or(0);
                let dist = index.saturating_add(1);
                for _ in 0..=count {
                    let byte = out
                        .len()
                        .checked_sub(dist)
                        .and_then(|at| out.get(at))
                        .copied()
                        .unwrap_or(0);
                    out.push(byte);
                }
            }
            self.produced = self
                .produced
                .saturating_add(out.len().saturating_sub(before));
            if self.produced > limit {
                return Err(Diagnostic::limit(format!(
                    "decompressed data exceeds {limit:#x} bytes"
                )));
            }
            self.bit = self.bit.saturating_add(need);
        }
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
        // References reach at most 2^window bytes back; before the first
        // window the zero fill depends on the output length, so keep it all.
        let window = 1usize << self.window.min(15);
        if self.produced < window {
            return 0;
        }
        out_len.saturating_sub(window)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{Decoder, Status, Streaming, decode_all};

    /// The first 16 KiB of `words.txt`, compressed by heatshrink 0.4.1
    /// through the `heatshrink2` 0.14.0 Python bindings:
    /// `heatshrink2.compress(data, window_sz2=W, lookahead_sz2=L)`.
    #[test]
    fn matches_the_reference_encoder() {
        let words = &include_bytes!("testdata/words.txt")[..16384];
        for (w, l, data) in [
            (11, 4, &include_bytes!("testdata/words.hs11-4")[..]),
            (12, 4, &include_bytes!("testdata/words.hs12-4")[..]),
            (8, 4, &include_bytes!("testdata/words.hs8-4")[..]),
        ] {
            let mut d = Streaming(Heatshrink::new(w, l));
            assert_eq!(decode_all(&mut d, data, 1 << 20).unwrap(), words, "{w}/{l}");
        }
    }

    #[test]
    fn incremental_with_release() {
        let words = &include_bytes!("testdata/words.txt")[..16384];
        let data = include_bytes!("testdata/words.hs11-4");
        let mut d = Streaming(Heatshrink::new(11, 4));
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
        let data = include_bytes!("testdata/words.hs12-4");
        let mut d = Streaming(Heatshrink::new(12, 4));
        assert!(decode_all(&mut d, data, 1000).is_err());
        // Invalid parameters.
        let mut bad = Streaming(Heatshrink::new(20, 4));
        assert!(decode_all(&mut bad, data, 1 << 20).is_err());
        // Anything decodes to something (zeros before the start).
        let mut z = Streaming(Heatshrink::new(8, 4));
        assert_eq!(
            decode_all(&mut z, &[0x00, 0x30], 1 << 20).unwrap(),
            [0u8; 7]
        );
    }
}
