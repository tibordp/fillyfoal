//! PKWARE's two "implode" formats:
//!
//! - ZIP method 6 (PKZIP 1.x): LZ77 with a 4 KiB or 8 KiB window and two or
//!   three Shannon-Fano trees (literals optional, lengths, distances)
//!   stored at the start of the data. The stream has no end marker; it
//!   ends at the uncompressed size the container records.
//! - The Data Compression Library's implode ("blast"; ZIP method 10, old
//!   installers, MPQ): fixed codes, a 1-4 KiB window and an end code.
//!
//! Both read bits LSB-first and store codes bit-inverted relative to
//! canonical Huffman codes, most significant bit first.

use crate::codec::filters::Filter;
use crate::error::{Diagnostic, Result};

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
}

struct Bits<'a> {
    data: &'a [u8],
    /// Position in bits.
    pos: usize,
    what: &'static str,
}

impl Bits<'_> {
    fn available(&self) -> usize {
        self.data.len().saturating_mul(8).saturating_sub(self.pos)
    }

    fn bit(&mut self) -> Result<u32> {
        let b = self
            .data
            .get(self.pos / 8)
            .ok_or_else(|| Diagnostic::malformed(format!("{}: truncated data", self.what)))?;
        let v = u32::from(b >> (self.pos % 8) & 1);
        self.pos = self.pos.saturating_add(1);
        Ok(v)
    }

    fn bits(&mut self, n: u32) -> Result<u32> {
        let mut v = 0u32;
        for i in 0..n {
            v |= self.bit()? << i;
        }
        Ok(v)
    }

    fn bytes_used(&self) -> usize {
        self.pos.div_ceil(8)
    }
}

/// A canonical prefix code over bit-inverted input.
struct Code {
    /// Codes per length, 1..=16.
    count: [u16; 17],
    /// Symbols ordered by (length, value).
    symbol: Vec<u16>,
}

impl Code {
    /// Builds the code for `lengths` (0 = unused). Over-subscribed lengths
    /// are an error; incomplete codes are allowed (missing codes fail when
    /// met).
    fn new(lengths: &[u8], what: &str) -> Result<Self> {
        let mut count = [0u16; 17];
        for &l in lengths {
            if let Some(c) = count.get_mut(usize::from(l)) {
                *c = c.saturating_add(1);
            }
        }
        let mut left = 1i32;
        for c in count.iter().skip(1) {
            left = left.saturating_mul(2).saturating_sub(i32::from(*c));
            if left < 0 {
                return Err(Diagnostic::malformed(format!("{what}: over-subscribed code")));
            }
        }
        let mut symbol = Vec::with_capacity(lengths.len());
        for len in 1..=16u8 {
            for (s, &l) in lengths.iter().enumerate() {
                if l == len {
                    symbol.push(u16::try_from(s).unwrap_or(0));
                }
            }
        }
        Ok(Code { count, symbol })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<usize> {
        let (mut code, mut first, mut index) = (0usize, 0usize, 0usize);
        for &count in self.count.iter().skip(1) {
            code |= usize::try_from(bits.bit()? ^ 1).unwrap_or(0);
            let count = usize::from(count);
            if let Some(off) = code.checked_sub(first)
                && off < count
            {
                return self
                    .symbol
                    .get(index.saturating_add(off))
                    .map(|&s| usize::from(s))
                    .ok_or_else(|| Diagnostic::malformed(format!("{}: bad code", bits.what)));
            }
            index = index.saturating_add(count);
            first = first.saturating_add(count) << 1;
            code <<= 1;
        }
        Err(Diagnostic::malformed(format!("{}: invalid code", bits.what)))
    }
}

/// Expands run-length coded bit lengths: each byte holds the length (minus
/// `bias`) in its low nibble and the repeat count minus one in its high
/// nibble.
fn expand_lengths(packed: &[u8], bias: u8, n: usize, what: &str) -> Result<Vec<u8>> {
    let mut lengths = Vec::with_capacity(n);
    for &b in packed {
        for _ in 0..=(b >> 4) {
            lengths.push((b & 0x0f).saturating_add(bias));
        }
    }
    if lengths.len() != n {
        return Err(Diagnostic::malformed(format!("{what}: tree has the wrong number of codes")));
    }
    Ok(lengths)
}

/// Copies `len` bytes from `dist` back; bytes before the start of the
/// output read as zeros (as PKZIP and Info-ZIP do).
fn copy_back(out: &mut Vec<u8>, dist: usize, len: usize) {
    for _ in 0..len {
        let b = out
            .len()
            .checked_sub(dist)
            .and_then(|i| out.get(i).copied())
            .unwrap_or(0);
        out.push(b);
    }
}

/// ZIP method 6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Implode {
    /// General purpose bit 1: an 8 KiB window (else 4 KiB).
    pub large_window: bool,
    /// General purpose bit 2: a literal tree (else literals are raw bytes).
    pub literal_tree: bool,
    /// The uncompressed size; without it decoding stops when the input
    /// runs out.
    pub size: Option<u64>,
}

impl Filter for Implode {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        const WHAT: &str = "implode";
        let mut pos = 0usize;
        let mut tree = |n: usize| -> Result<Code> {
            let count = input
                .get(pos)
                .map(|&b| usize::from(b).saturating_add(1))
                .ok_or_else(|| Diagnostic::malformed("implode: truncated tree"))?;
            let packed = input
                .get(pos.saturating_add(1)..pos.saturating_add(1).saturating_add(count))
                .ok_or_else(|| Diagnostic::malformed("implode: truncated tree"))?;
            pos = pos.saturating_add(1).saturating_add(count);
            Code::new(&expand_lengths(packed, 1, n, WHAT)?, WHAT)
        };
        let literals = if self.literal_tree { Some(tree(256)?) } else { None };
        let lengths = tree(64)?;
        let distances = tree(64)?;
        let mut bits = Bits {
            data: input.get(pos..).unwrap_or_default(),
            pos: 0,
            what: WHAT,
        };
        let size = match self.size {
            Some(s) => {
                let s = usize::try_from(s).unwrap_or(usize::MAX);
                if s > limit {
                    return Err(too_big(limit));
                }
                Some(s)
            }
            None => None,
        };
        let (low_bits, min_len) = (if self.large_window { 7 } else { 6 }, if self.literal_tree { 3 } else { 2 });
        let mut out = Vec::with_capacity(size.unwrap_or(0).min(1 << 24));
        loop {
            match size {
                Some(s) if out.len() >= s => break,
                // Without a size, stop when no complete symbol can follow.
                None if bits.available() < 8 => break,
                _ => {}
            }
            if bits.bit()? == 1 {
                let b = match &literals {
                    Some(code) => code.decode(&mut bits)?,
                    None => usize::try_from(bits.bits(8)?).unwrap_or(0),
                };
                out.push(u8::try_from(b).unwrap_or(0));
            } else {
                let low = usize::try_from(bits.bits(low_bits)?).unwrap_or(0);
                let high = distances.decode(&mut bits)?;
                let dist = (high << low_bits | low).saturating_add(1);
                let mut len = lengths.decode(&mut bits)?;
                if len == 63 {
                    len = len.saturating_add(usize::try_from(bits.bits(8)?).unwrap_or(0));
                }
                len = len.saturating_add(min_len);
                if let Some(s) = size {
                    len = len.min(s.saturating_sub(out.len()));
                }
                if out.len().saturating_add(len) > limit {
                    return Err(too_big(limit));
                }
                copy_back(&mut out, dist, len);
            }
            if out.len() > limit {
                return Err(too_big(limit));
            }
        }
        Ok(out)
    }
}

/// Packed bit lengths of the DCL codes, in the format of
/// [`expand_lengths`] with no bias (from zlib's `contrib/blast/blast.c`).
const DCL_LITERALS: [u8; 98] = [
    11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8, 9, 7, 6, 7, 8, 7, 6, 55, 8, 23, 24, 12, 11,
    7, 9, 11, 12, 6, 7, 22, 5, 7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8, 25, 11, 8, 11, 9, 12, 8, 12, 5, 38, 5,
    38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27, 44, 253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61,
    12, 45, 44, 173,
];
const DCL_LENGTHS: [u8; 6] = [2, 35, 36, 53, 38, 23];
const DCL_DISTANCES: [u8; 7] = [2, 20, 53, 230, 247, 151, 248];
const DCL_BASE: [u16; 16] = [3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264];
const DCL_EXTRA: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];

/// Decodes a DCL implode stream; returns the output and the bytes used.
pub fn blast(input: &[u8], limit: usize) -> Result<(Vec<u8>, usize)> {
    const WHAT: &str = "DCL implode";
    let bad = |what: &str| Diagnostic::malformed(format!("DCL implode: {what}"));
    let coded = match input.first() {
        Some(0) => false,
        Some(1) => true,
        Some(_) => return Err(bad("bad literal mode")),
        None => return Err(bad("truncated header")),
    };
    let dict_bits = match input.get(1) {
        Some(&b @ 4..=6) => u32::from(b),
        Some(_) => return Err(bad("bad dictionary size")),
        None => return Err(bad("truncated header")),
    };
    let literals = Code::new(&expand_lengths(&DCL_LITERALS, 0, 256, WHAT)?, WHAT)?;
    let lengths = Code::new(&expand_lengths(&DCL_LENGTHS, 0, 16, WHAT)?, WHAT)?;
    let distances = Code::new(&expand_lengths(&DCL_DISTANCES, 0, 64, WHAT)?, WHAT)?;
    let mut bits = Bits {
        data: input.get(2..).unwrap_or_default(),
        pos: 0,
        what: WHAT,
    };
    let mut out = Vec::new();
    loop {
        if bits.bit()? == 1 {
            let sym = lengths.decode(&mut bits)?;
            let base = DCL_BASE.get(sym).copied().unwrap_or(0);
            let extra = DCL_EXTRA.get(sym).copied().unwrap_or(0);
            let len = usize::from(base).saturating_add(usize::try_from(bits.bits(u32::from(extra))?).unwrap_or(0));
            if len == 519 {
                break; // end code
            }
            let low_bits = if len == 2 { 2 } else { dict_bits };
            let high = distances.decode(&mut bits)?;
            let low = usize::try_from(bits.bits(low_bits)?).unwrap_or(0);
            let dist = (high << low_bits | low).saturating_add(1);
            if dist > out.len() {
                return Err(bad("distance before the start of the output"));
            }
            if out.len().saturating_add(len) > limit {
                return Err(too_big(limit));
            }
            copy_back(&mut out, dist, len);
        } else {
            let b = if coded {
                literals.decode(&mut bits)?
            } else {
                usize::try_from(bits.bits(8)?).unwrap_or(0)
            };
            out.push(u8::try_from(b).unwrap_or(0));
            if out.len() > limit {
                return Err(too_big(limit));
            }
        }
    }
    Ok((out, bits.bytes_used().saturating_add(2)))
}

/// A DCL implode stream.
#[derive(Clone, Copy)]
pub struct DclImplode;

impl Filter for DclImplode {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        blast(input, limit).map(|(out, _)| out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn blast_reference_vector() {
        // From the comments of zlib's contrib/blast/blast.c.
        let data = [0x00, 0x04, 0x82, 0x24, 0x25, 0x8f, 0x80, 0x7f];
        let (out, used) = blast(&data, 100).unwrap();
        assert_eq!(out, b"AIAIAIAIAIAIA");
        assert_eq!(used, data.len());
    }
}
