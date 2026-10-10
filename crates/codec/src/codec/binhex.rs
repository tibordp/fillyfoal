//! BinHex 4.0's encoding: 6-bit text (64 printable characters, others
//! such as line breaks ignored) carrying bytes in which `0x90` starts a run
//! (`0x90 n` repeats the byte before it until there are `n` in all; `0x90
//! 0` is a literal `0x90`). The input is the text between the colons; a
//! `:` ends it too.

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

const ALPHABET: &[u8; 64] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

/// Each character's 6-bit value, or 0xff.
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
const VALUES: [u8; 256] = {
    let mut t = [0xffu8; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
};

/// Incremental decoder state; positions are relative to the buffers as they
/// are now (see "Releasing" in the pipeline docs).
#[derive(Clone, Debug, Default)]
pub struct BinHex {
    /// Input position.
    at: usize,
    /// Bits not yet forming a byte, and how many.
    acc: u32,
    bits: u32,
    /// A `0x90` waits for its count.
    escape: bool,
    /// The last byte output (what a run repeats).
    last: u8,
    /// Bytes produced so far, including released ones.
    produced: u64,
    done: bool,
}

impl BinHex {
    /// Handles one decoded byte.
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) {
        if self.escape {
            self.escape = false;
            if b == 0 {
                self.emit(0x90, out);
            } else {
                for _ in 1..b {
                    self.emit(self.last, out);
                }
            }
        } else if b == 0x90 {
            self.escape = true;
        } else {
            self.emit(b, out);
        }
    }

    fn emit(&mut self, b: u8, out: &mut Vec<u8>) {
        out.push(b);
        self.last = b;
        self.produced = self.produced.saturating_add(1);
    }
}

impl Decode for BinHex {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        if self.done {
            return Ok(Step::Done);
        }
        let start = self.at;
        let goal = self
            .produced
            .saturating_add(crate::bytes::to_u64(step.max(1)));
        // Bound the text scanned per step too (it may hold no data at all).
        let scan = step.max(1).saturating_mul(2).saturating_add(64);
        let limit = crate::bytes::to_u64(limit);
        loop {
            if self.produced >= goal || self.at.saturating_sub(start) >= scan {
                return Ok(Step::More);
            }
            let Some(&c) = input.get(self.at) else {
                if eof {
                    // A partial byte, or a 0x90 without a count, is dropped.
                    self.done = true;
                    return Ok(Step::Done);
                }
                if self.at > start {
                    return Ok(Step::More);
                }
                return Err(Diagnostic::malformed("BinHex text ends early"));
            };
            if c == b':' {
                self.done = true;
                return Ok(Step::Done);
            }
            self.at = self.at.saturating_add(1);
            let v = VALUES.get(usize::from(c)).copied().unwrap_or(0xff);
            if v == 0xff {
                continue;
            }
            self.acc = (self.acc << 6 | u32::from(v)) & 0x00ff_ffff;
            self.bits = self.bits.saturating_add(6);
            if self.bits >= 8 {
                self.bits = self.bits.saturating_sub(8);
                let b = u8::try_from(self.acc >> self.bits & 0xff).unwrap_or(0);
                self.byte(b, out);
                if self.produced > limit {
                    return Err(Diagnostic::limit("decoded BinHex data too large"));
                }
            }
        }
    }

    fn consumed(&self) -> usize {
        self.at
    }

    fn releasable_input(&self) -> usize {
        self.at
    }

    fn release_input(&mut self, n: usize) {
        self.at = self.at.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }

    fn heap_size(&self) -> Option<usize> {
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
    use crate::codec::Codec;
    use crate::codec::pipeline::decode_all;

    /// Encodes bytes as BinHex 6-bit text (no run-length encoding).
    fn encode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in data.chunks(3) {
            let mut w = [0u8; 3];
            w[..chunk.len()].copy_from_slice(chunk);
            let v = u32::from(w[0]) << 16 | u32::from(w[1]) << 8 | u32::from(w[2]);
            let chars = chunk.len() + 1;
            for i in 0..chars {
                out.push(super::ALPHABET[(v >> (18 - 6 * i) & 63) as usize]);
            }
        }
        out
    }

    #[test]
    fn runs_and_escapes() {
        // "a", a run to 5 "a"s, an escaped 0x90, "b".
        let text = encode(&[b'a', 0x90, 5, 0x90, 0, b'b']);
        let mut with_breaks = text.clone();
        with_breaks.insert(3, b'\n');
        with_breaks.extend(b":trailing");
        for input in [&text, &with_breaks] {
            let out = decode_all(Codec::BinHex.decoder().unwrap().as_mut(), input, 99).unwrap();
            assert_eq!(out, b"aaaaa\x90b");
        }
        assert!(decode_all(Codec::BinHex.decoder().unwrap().as_mut(), &text, 3).is_err());
    }

    #[test]
    fn checkpoints_resume_mid_stream() {
        // Text with runs and escaped 0x90 bytes, in lines of 64 characters.
        let words = &include_bytes!("testdata/words.txt")[..30_000];
        let mut raw = Vec::new();
        for (i, chunk) in words.chunks(100).enumerate() {
            raw.extend_from_slice(chunk);
            raw.extend_from_slice(if i % 2 == 0 {
                &[b'x', 0x90, 200]
            } else {
                &[0x90, 0]
            });
        }
        let mut text = Vec::new();
        for line in encode(&raw).chunks(64) {
            text.extend_from_slice(line);
            text.push(b'\n');
        }
        let (checked, largest) = crate::codec::pipeline::verify_checkpoints(
            || Codec::BinHex.decoder().unwrap(),
            &text,
            1000,
            3,
        )
        .unwrap();
        assert!(checked > 10, "{checked}");
        assert!(largest < 256, "{largest}");
    }
}
