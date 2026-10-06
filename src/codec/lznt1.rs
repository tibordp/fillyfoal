//! LZNT1 ([MS-XCA] section 2.5): chunks of up to 4 KiB of output, each
//! with a 16-bit header (compressed flag, signature 3, size minus 3), stored
//! or as flag groups of literals and 16-bit words whose displacement/length
//! split widens with the position in the chunk. A zero header ends the
//! data. NTFS compresses files this way, one compression unit at a time.

use crate::codec::filters::Filter;
use crate::codec::xpress::copy_back;
use crate::error::{Diagnostic, Result};

const CHUNK: usize = 4096;

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("LZNT1: {what}"))
}

/// LZNT1, decoded to the end of the input (or the end-of-data header). With
/// a `size` (an NTFS compression unit), the output is cut or zero-filled to
/// exactly that many bytes.
#[derive(Clone, Copy, Debug)]
pub struct Lznt1 {
    pub size: Option<u64>,
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
                let (Some(&lo), Some(&hi)) = (data.get(pos), data.get(pos.saturating_add(1))) else {
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

impl Filter for Lznt1 {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let size = self.size.map(|s| usize::try_from(s).unwrap_or(usize::MAX));
        if size.is_some_and(|s| s > limit) {
            return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
        }
        let end = size.unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(size.unwrap_or(input.len().saturating_mul(2)).min(1 << 24));
        let mut pos = 0usize;
        while out.len() < end {
            let (Some(&lo), Some(&hi)) = (input.get(pos), input.get(pos.saturating_add(1))) else {
                break;
            };
            let header = u16::from_le_bytes([lo, hi]);
            if header == 0 {
                break;
            }
            let total = usize::from(header & 0x0fff).saturating_add(3);
            let data = input
                .get(pos.saturating_add(2)..pos.saturating_add(total))
                .ok_or_else(|| bad("truncated chunk"))?;
            pos = pos.saturating_add(total);
            // Every chunk but the last decodes to 4 KiB; a short one is
            // padded with zeros (as NTFS does).
            let rem = out.len() % CHUNK;
            if rem != 0 {
                out.resize(out.len().saturating_add(CHUNK.saturating_sub(rem)), 0);
            }
            if header & 0x8000 != 0 {
                chunk(data, &mut out)?;
            } else {
                if data.len() > CHUNK {
                    return Err(bad("stored chunk larger than 4 KiB"));
                }
                out.extend_from_slice(data);
            }
            if out.len() > limit {
                return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
            }
        }
        if let Some(size) = size {
            out.resize(size, 0);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// [MS-XCA] section 3.3: a 142-byte string (with its NUL) in one
    /// 59-byte compressed chunk.
    #[test]
    fn spec_example() {
        let compressed = [
            0x38, 0xb0, 0x88, 0x46, 0x23, 0x20, 0x00, 0x20, 0x47, 0x20, 0x41, 0x00, 0x10, 0xa2, 0x47, 0x01, 0xa0, 0x45, 0x20,
            0x44, 0x00, 0x08, 0x45, 0x01, 0x50, 0x79, 0x00, 0xc0, 0x45, 0x20, 0x05, 0x24, 0x13, 0x88, 0x05, 0xb4, 0x02, 0x4a,
            0x44, 0xef, 0x03, 0x58, 0x02, 0x8c, 0x09, 0x16, 0x01, 0x48, 0x45, 0x00, 0xbe, 0x00, 0x9e, 0x00, 0x04, 0x01, 0x18,
            0x90, 0x00,
        ];
        let mut expected = b"F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D E E F# D E F# G F# D E \
F# G F# E D E A F# F# G A A G F# E D D E F# E D D"
            .to_vec();
        expected.push(0);
        assert_eq!(expected.len(), 142);
        assert_eq!(Lznt1 { size: None }.apply(&compressed, 1 << 20).unwrap(), expected);
        // A compression unit: zero-filled to its size.
        let unit = Lznt1 { size: Some(8192) }.apply(&compressed, 1 << 20).unwrap();
        assert_eq!(unit.len(), 8192);
        assert_eq!(&unit[..142], &expected[..]);
        assert!(unit[142..].iter().all(|&b| b == 0));
        assert!(Lznt1 { size: None }.apply(&compressed[..30], 1 << 20).is_err());
        assert!(Lznt1 { size: None }.apply(&compressed, 100).is_err());
    }
}
