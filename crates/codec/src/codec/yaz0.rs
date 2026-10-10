//! Nintendo Yaz0, a simple LZ77: after the 16-byte header (`Yaz0`, the
//! big-endian decoded size, reserved words), each group byte's bits, most
//! significant first, say whether the next item is a literal byte (1) or a
//! back-reference (0) of two bytes `NR RR` (distance `RRR + 1`, length
//! `N + 2`), or three bytes `0R RR NN` (length `NN + 0x12`). Decoding stops
//! once the decoded size is reached (a last copy may overshoot it).

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// The farthest a back-reference reaches.
const WINDOW: usize = 0x1000;

fn ends_early() -> Diagnostic {
    Diagnostic::malformed("Yaz0 stream ends early")
}

/// Incremental decoder state; positions are relative to the buffers as they
/// are now (see "Releasing" in the pipeline docs).
#[derive(Clone, Debug)]
pub struct Yaz0 {
    /// The decoded size.
    size: u64,
    /// Input position (at a group byte between steps).
    at: usize,
    /// Bytes produced so far, including released ones.
    produced: u64,
    done: bool,
}

impl Yaz0 {
    /// A decoder for the body of a stream decoding to `size` bytes.
    pub fn new(size: u64) -> Self {
        Yaz0 {
            size,
            at: 0,
            produced: 0,
            done: false,
        }
    }
}

impl Decode for Yaz0 {
    fn step(
        &mut self,
        input: &[u8],
        _eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let byte = |at: usize| input.get(at).copied().ok_or_else(ends_early);
        let limit = crate::bytes::to_u64(limit);
        let goal = self
            .produced
            .saturating_add(crate::bytes::to_u64(step.max(1)));
        while !self.done && self.produced < self.size {
            if self.produced >= goal {
                return Ok(Step::More);
            }
            let group = byte(self.at)?;
            self.at = self.at.saturating_add(1);
            for bit in (0..8).rev() {
                if self.produced >= self.size {
                    break;
                }
                if self.produced >= limit {
                    return Err(Diagnostic::limit("Yaz0 output exceeds the limit"));
                }
                if group >> bit & 1 == 1 {
                    out.push(byte(self.at)?);
                    self.at = self.at.saturating_add(1);
                    self.produced = self.produced.saturating_add(1);
                } else {
                    let b1 = usize::from(byte(self.at)?);
                    let b2 = usize::from(byte(self.at.saturating_add(1))?);
                    self.at = self.at.saturating_add(2);
                    let distance = ((b1 & 0x0f) << 8 | b2).saturating_add(1);
                    let len = if b1 >> 4 == 0 {
                        let b3 = usize::from(byte(self.at)?);
                        self.at = self.at.saturating_add(1);
                        b3.saturating_add(0x12)
                    } else {
                        (b1 >> 4).saturating_add(2)
                    };
                    if crate::bytes::to_u64(distance) > self.produced {
                        return Err(Diagnostic::malformed("Yaz0 back-reference before start"));
                    }
                    let from = out.len().saturating_sub(distance);
                    for i in 0..len {
                        let b = out.get(from.saturating_add(i)).copied().unwrap_or(0);
                        out.push(b);
                    }
                    self.produced = self.produced.saturating_add(crate::bytes::to_u64(len));
                }
            }
        }
        if self.produced > self.size {
            // The last copy overshot the decoded size.
            let over = crate::bytes::to_usize(self.produced.saturating_sub(self.size));
            out.truncate(out.len().saturating_sub(over));
            self.produced = self.size;
        }
        self.done = true;
        Ok(Step::Done)
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
        out_len.saturating_sub(WINDOW)
    }

    fn heap_size(&self) -> Option<usize> {
        // The window is in `out`.
        Some(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::codec::Codec;
    use crate::codec::pipeline::decode_all;

    /// A Yaz0 body for `data`, from greedy matches (for this test only).
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    fn encode(data: &[u8]) -> Vec<u8> {
        use crate::codec::xpress::tests::{Token, parse};
        let mut out = Vec::new();
        let mut group = 0;
        for (i, token) in parse(data, super::WINDOW, 0x111, usize::MAX)
            .into_iter()
            .enumerate()
        {
            if i % 8 == 0 {
                group = out.len();
                out.push(0);
            }
            match token {
                Token::Literal(b) => {
                    out[group] |= 0x80 >> (i % 8);
                    out.push(b);
                }
                Token::Match { offset, len } => {
                    let r = offset - 1;
                    if len <= 17 {
                        out.extend_from_slice(&[((len - 2) << 4 | r >> 8) as u8, r as u8]);
                    } else {
                        out.extend_from_slice(&[(r >> 8) as u8, r as u8, (len - 0x12) as u8]);
                    }
                }
            }
        }
        out
    }

    #[test]
    fn checkpoints_resume_mid_stream() {
        let words = include_bytes!("testdata/words.txt");
        let data = [&words[..], &[7u8; 3000], &words[..20_000]].concat();
        let body = encode(&data);
        let codec = Codec::Yaz0 {
            size: data.len() as u64,
        };
        assert!(decode_all(codec.decoder().unwrap().as_mut(), &body, 1 << 24).unwrap() == data);
        let (checked, largest) =
            crate::codec::pipeline::verify_checkpoints(|| codec.decoder().unwrap(), &body, 2000, 3)
                .unwrap();
        assert!(checked > 10, "{checked}");
        assert!(largest < 256, "{largest}");
    }

    #[test]
    fn literals_and_copies() {
        // "abc", then a 2-byte copy of length 6 at distance 3, then a
        // 3-byte copy of 0x12 bytes at distance 1.
        let body = [0xe0, b'a', b'b', b'c', 0x40, 0x02, 0x00, 0x00, 0x00];
        let codec = Codec::Yaz0 { size: 9 + 0x12 };
        let out = decode_all(codec.decoder().unwrap().as_mut(), &body, 1 << 20).unwrap();
        let mut expected = b"abcabcabc".to_vec();
        expected.extend([b'c'; 0x12]);
        assert_eq!(out, expected);
        // The size cuts the last copy short.
        let codec = Codec::Yaz0 { size: 7 };
        let out = decode_all(codec.decoder().unwrap().as_mut(), &body, 1 << 20).unwrap();
        assert_eq!(out, b"abcabca");
        // A reference before the start, and truncation, are errors.
        let codec = Codec::Yaz0 { size: 4 };
        assert!(decode_all(codec.decoder().unwrap().as_mut(), &[0x00, 0x10, 0x00], 99).is_err());
        assert!(decode_all(codec.decoder().unwrap().as_mut(), &body[..3], 99).is_err());
    }
}
