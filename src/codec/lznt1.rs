//! LZNT1 ([MS-XCA] section 2.5): chunks of up to 4 KiB of output, each
//! with a 16-bit header (compressed flag, signature 3, size minus 3), stored
//! or as flag groups of literals and 16-bit words whose displacement/length
//! split widens with the position in the chunk. A zero header ends the
//! data. NTFS compresses files this way, one compression unit at a time.
//!
//! Back-references stay inside their chunk, so the decoder works a chunk at
//! a time and keeps nothing it has passed: all input before the next chunk
//! and all output can be released.

use crate::codec::pipeline::{Decode, Step};
use crate::codec::xpress::copy_back;
use crate::error::{Diagnostic, Result};

const CHUNK: usize = 4096;

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("LZNT1: {what}"))
}

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
}

/// Ends a step that ran out of input: keep what it produced, or ask for
/// more (the caller rolls the step back).
fn need(progress: bool) -> Result<Step> {
    if progress {
        Ok(Step::More)
    } else {
        Err(bad("needs more input"))
    }
}

/// LZNT1, decoded to the end of the input (or the end-of-data header). With
/// a `size` (an NTFS compression unit), the output is cut or zero-filled to
/// exactly that many bytes.
///
/// Positions are relative to the buffers as they are now (see "Releasing"
/// in the pipeline docs).
#[derive(Clone, Debug)]
pub struct Lznt1 {
    size: Option<usize>,
    /// Input position of the next chunk header.
    pos: usize,
    /// Output produced so far, released bytes included.
    produced: usize,
    /// The end of the data was reached (only zero fill follows).
    ended: bool,
    /// Once done, the input consumed: all of it, as before (the container
    /// decides where the data ends).
    finished: Option<usize>,
}

impl Lznt1 {
    pub fn new(size: Option<u64>) -> Self {
        Lznt1 {
            size: size.map(|s| usize::try_from(s).unwrap_or(usize::MAX)),
            pos: 0,
            produced: 0,
            ended: false,
            finished: None,
        }
    }
}

/// Decodes one compressed chunk's flag groups onto `out`.
fn chunk(data: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let start = out.len();
    let mut pos = 0usize;
    while let Some(&flags) = data.get(pos) {
        pos = pos.saturating_add(1);
        for bit in 0..8 {
            if pos >= data.len() {
                break;
            }
            let written = out.len().saturating_sub(start);
            if flags >> bit & 1 == 0 {
                out.push(data.get(pos).copied().unwrap_or(0));
                pos = pos.saturating_add(1);
            } else {
                let (Some(&lo), Some(&hi)) = (data.get(pos), data.get(pos.saturating_add(1)))
                else {
                    return Err(bad("chunk ends inside a compressed word"));
                };
                pos = pos.saturating_add(2);
                let word = usize::from(u16::from_le_bytes([lo, hi]));
                // The displacement takes the high M bits, M being the
                // largest value in 4..=12 with 2^(M-1) < (bytes written in
                // this chunk); the length takes the rest.
                let mut shift = 12u32;
                let mut p = written.saturating_sub(1);
                while p >= 0x10 {
                    shift = shift.saturating_sub(1);
                    p >>= 1;
                }
                let len = (word & ((1usize << shift).saturating_sub(1))).saturating_add(3);
                let disp = (word >> shift).saturating_add(1);
                if disp > written {
                    return Err(bad("displacement before the start of the chunk"));
                }
                copy_back(out, disp, len, start.saturating_add(CHUNK))?;
            }
            if out.len().saturating_sub(start) >= CHUNK && pos < data.len() {
                return Err(bad("chunk decodes to more than 4 KiB"));
            }
        }
    }
    Ok(())
}

impl Decode for Lznt1 {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        if let Some(size) = self.size
            && size.saturating_sub(self.produced) > limit.saturating_sub(out.len())
        {
            return Err(too_big(limit));
        }
        let goal = out.len().saturating_add(step);
        let (from, first) = (self.pos, out.len());
        loop {
            let progress = out.len() > first || self.pos > from;
            if self.ended {
                if let Some(size) = self.size {
                    // Zero fill, a step at a time.
                    let n = size
                        .saturating_sub(self.produced)
                        .min(goal.saturating_sub(out.len()));
                    out.resize(out.len().saturating_add(n), 0);
                    self.produced = self.produced.saturating_add(n);
                    if self.produced < size {
                        return Ok(Step::More);
                    }
                }
                if !eof {
                    return if out.len() > first {
                        Ok(Step::More)
                    } else {
                        Err(bad("waiting for the end of the input"))
                    };
                }
                self.finished = Some(input.len());
                return Ok(Step::Done);
            }
            // At most a step of output, or of input (chunks may be empty).
            if out.len() >= goal || self.pos.saturating_sub(from) >= step {
                return Ok(Step::More);
            }
            if self.size.is_some_and(|s| self.produced >= s) {
                self.ended = true;
                continue;
            }
            let (Some(&lo), Some(&hi)) =
                (input.get(self.pos), input.get(self.pos.saturating_add(1)))
            else {
                if eof {
                    self.ended = true;
                    continue;
                }
                return need(progress);
            };
            let header = u16::from_le_bytes([lo, hi]);
            if header == 0 {
                self.ended = true;
                continue;
            }
            let total = usize::from(header & 0x0fff).saturating_add(3);
            let Some(data) = input.get(self.pos.saturating_add(2)..self.pos.saturating_add(total))
            else {
                if eof {
                    return Err(bad("truncated chunk"));
                }
                return need(progress);
            };
            let before = out.len();
            // Every chunk but the last decodes to 4 KiB; a short one is
            // padded with zeros (as NTFS does).
            let rem = self.produced % CHUNK;
            if rem != 0 {
                out.resize(out.len().saturating_add(CHUNK.saturating_sub(rem)), 0);
            }
            if header & 0x8000 != 0 {
                chunk(data, out)?;
            } else {
                if data.len() > CHUNK {
                    return Err(bad("stored chunk larger than 4 KiB"));
                }
                out.extend_from_slice(data);
            }
            self.pos = self.pos.saturating_add(total);
            self.produced = self
                .produced
                .saturating_add(out.len().saturating_sub(before));
            if out.len() > limit {
                return Err(too_big(limit));
            }
            // A compression unit is cut to its size.
            if let Some(size) = self.size
                && self.produced > size
            {
                let over = self.produced.saturating_sub(size);
                out.truncate(out.len().saturating_sub(over));
                self.produced = size;
            }
        }
    }

    fn consumed(&self) -> usize {
        self.finished.unwrap_or(self.pos)
    }

    fn releasable_input(&self) -> usize {
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        self.finished = self.finished.map(|f| f.saturating_sub(n));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Steps end between chunks, and chunks do not refer to each other.
        out_len
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{Streaming, decode_all};

    fn decode(size: Option<u64>, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        decode_all(&mut Streaming(Lznt1::new(size)), input, limit)
    }

    /// [MS-XCA] section 3.3: a 142-byte string (with its NUL) in one
    /// 59-byte compressed chunk.
    #[test]
    fn spec_example() {
        let compressed = [
            0x38, 0xb0, 0x88, 0x46, 0x23, 0x20, 0x00, 0x20, 0x47, 0x20, 0x41, 0x00, 0x10, 0xa2,
            0x47, 0x01, 0xa0, 0x45, 0x20, 0x44, 0x00, 0x08, 0x45, 0x01, 0x50, 0x79, 0x00, 0xc0,
            0x45, 0x20, 0x05, 0x24, 0x13, 0x88, 0x05, 0xb4, 0x02, 0x4a, 0x44, 0xef, 0x03, 0x58,
            0x02, 0x8c, 0x09, 0x16, 0x01, 0x48, 0x45, 0x00, 0xbe, 0x00, 0x9e, 0x00, 0x04, 0x01,
            0x18, 0x90, 0x00,
        ];
        let mut expected = b"F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D E E F# D E F# G F# D E \
F# G F# E D E A F# F# G A A G F# E D D E F# E D D"
            .to_vec();
        expected.push(0);
        assert_eq!(expected.len(), 142);
        assert_eq!(decode(None, &compressed, 1 << 20).unwrap(), expected);
        // A compression unit: zero-filled to its size.
        let unit = decode(Some(8192), &compressed, 1 << 20).unwrap();
        assert_eq!(unit.len(), 8192);
        assert_eq!(&unit[..142], &expected[..]);
        assert!(unit[142..].iter().all(|&b| b == 0));
        assert!(decode(None, &compressed[..30], 1 << 20).is_err());
        assert!(decode(None, &compressed, 100).is_err());
    }
}
