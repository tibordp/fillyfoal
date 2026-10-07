//! Cap'n Proto's packed encoding (capnproto.org/encoding.html, "Packing"):
//! each 8-byte word becomes a tag byte, whose bit `i` says byte `i` is
//! nonzero, followed by the nonzero bytes. Tag `0x00` is followed by a
//! count of further all-zero words; tag `0xff` by the 8 bytes, a count, and
//! that many words copied unpacked.
//!
//! Checked against pycapnp's `to_bytes_packed` (see the `capnp-packed`
//! fixtures) and the examples in the specification.

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// The packed-encoding decoder; resumable at word boundaries.
#[derive(Clone, Default)]
pub struct Packed {
    pos: usize,
}

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("unpacked data exceeds {limit:#x} bytes"))
}

impl Packed {
    /// Decodes the unit (one tag and what it governs) at `self.pos`; `None`
    /// if the input does not hold all of it yet.
    fn unit(&mut self, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<Option<()>> {
        let Some(&tag) = input.get(self.pos) else {
            return Ok(None);
        };
        let mut at = self.pos.saturating_add(1);
        let mut word = [0u8; 8];
        for (i, slot) in word.iter_mut().enumerate() {
            if tag & (1 << i) != 0 {
                let Some(&b) = input.get(at) else {
                    return Ok(None);
                };
                *slot = b;
                at = at.saturating_add(1);
            }
        }
        let extra = match tag {
            0x00 | 0xff => {
                let Some(&n) = input.get(at) else {
                    return Ok(None);
                };
                at = at.saturating_add(1);
                usize::from(n).saturating_mul(8)
            }
            _ => 0,
        };
        let raw = if tag == 0xff {
            let end = at.saturating_add(extra);
            let Some(raw) = input.get(at..end) else {
                return Ok(None);
            };
            at = end;
            Some(raw)
        } else {
            None
        };
        if out.len().saturating_add(8).saturating_add(extra) > limit {
            return Err(too_big(limit));
        }
        out.extend_from_slice(&word);
        match raw {
            Some(raw) => out.extend_from_slice(raw),
            None => out.resize(out.len().saturating_add(extra), 0),
        }
        self.pos = at;
        Ok(Some(()))
    }
}

impl Decode for Packed {
    fn step(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Step> {
        let target = out.len().saturating_add(step.max(1));
        while out.len() < target {
            if self.pos >= input.len() && eof {
                return Ok(Step::Done);
            }
            if self.unit(input, out, limit)?.is_none() {
                if eof {
                    return Err(Diagnostic::malformed("packed word truncated"));
                }
                return Err(Diagnostic::malformed("waiting for input"));
            }
        }
        if self.pos >= input.len() && eof {
            return Ok(Step::Done);
        }
        Ok(Step::More)
    }

    fn consumed(&self) -> usize {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unpack(data: &[u8]) -> Result<Vec<u8>> {
        let mut d = Packed::default();
        let mut out = Vec::new();
        while d.step(data, true, &mut out, 1 << 20, 1 << 20)? != Step::Done {}
        Ok(out)
    }

    #[test]
    fn specification_examples() {
        // From the encoding specification.
        assert_eq!(
            unpack(&[0x51, 0x08, 0x03, 0x02]).ok(),
            Some(vec![0x08, 0, 0, 0, 0x03, 0, 0x02, 0])
        );
        assert_eq!(
            unpack(&[0x31, 0x01, 0x0b, 0x0c]).ok(),
            Some(vec![0x01, 0, 0, 0, 0x0b, 0x0c, 0, 0])
        );
        // A zero word and two more.
        assert_eq!(unpack(&[0x00, 0x02]).ok(), Some(vec![0; 24]));
        // A full word and one raw word after it.
        let mut packed = vec![0xff, 1, 2, 3, 4, 5, 6, 7, 8, 1];
        packed.extend_from_slice(&[0, 9, 0, 9, 0, 9, 0, 9]);
        let out = unpack(&packed).unwrap_or_default();
        assert_eq!(out.len(), 16);
        assert_eq!(out.get(9), Some(&9));
        assert!(unpack(&[0x03, 0x01]).is_err());
    }
}
