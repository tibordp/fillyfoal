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
//!
//! The method-10 decoder and its code tables are an altered Rust version of
//! Mark Adler's `blast` (zlib `contrib/blast`, zlib license; see
//! `THIRD-PARTY.md`).

use std::sync::Arc;

use crate::codec::pipeline::{Decode, Step, Streaming, decode_all};
use crate::error::{Diagnostic, Result};

struct Bits<'a> {
    data: &'a [u8],
    /// Position in bits.
    pos: usize,
    what: &'static str,
}

impl Bits<'_> {
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
                return Err(Diagnostic::malformed(format!(
                    "{what}: over-subscribed code"
                )));
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
        Err(Diagnostic::malformed(format!(
            "{}: invalid code",
            bits.what
        )))
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
        return Err(Diagnostic::malformed(format!(
            "{what}: tree has the wrong number of codes"
        )));
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

/// Ends a step that ran out of input: keep what it produced, or ask for
/// more (the caller rolls the step back).
fn need(progress: bool, what: &str) -> Result<Step> {
    if progress {
        Ok(Step::More)
    } else {
        Err(Diagnostic::malformed(format!("{what}: needs more input")))
    }
}

/// The trees of a method-6 stream.
struct Trees {
    literals: Option<Code>,
    lengths: Code,
    distances: Code,
}

/// An incremental ZIP method-6 decoder: a symbol at a time, a step of
/// output per call, keeping its window (4 or 8 KiB) of output. Positions
/// are relative to the buffers as they are now (see "Releasing" in the
/// pipeline docs).
#[derive(Clone)]
pub struct Explode {
    params: Implode,
    trees: Option<Arc<Trees>>,
    /// Bit position in the input (after the trees).
    bit: usize,
    /// Output produced so far, released bytes included.
    produced: usize,
    /// Once done, the input consumed: all of it, as before.
    finished: Option<usize>,
}

impl Explode {
    pub fn new(params: Implode) -> Self {
        Explode {
            params,
            trees: None,
            bit: 0,
            produced: 0,
            finished: None,
        }
    }

    fn window(&self) -> usize {
        if self.params.large_window { 8192 } else { 4096 }
    }

    /// Reads the trees at the start of the input; returns them and the
    /// bytes they take.
    fn read_trees(&self, input: &[u8]) -> Result<(Trees, usize)> {
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
        let literals = if self.params.literal_tree {
            Some(tree(256)?)
        } else {
            None
        };
        let lengths = tree(64)?;
        let distances = tree(64)?;
        Ok((
            Trees {
                literals,
                lengths,
                distances,
            },
            pos,
        ))
    }
}

impl Decode for Explode {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        const WHAT: &str = "implode";
        let trees = match &self.trees {
            Some(trees) => Arc::clone(trees),
            None => {
                let (trees, pos) = self.read_trees(input)?;
                let trees = Arc::new(trees);
                self.trees = Some(Arc::clone(&trees));
                self.bit = pos.saturating_mul(8);
                trees
            }
        };
        let size = self
            .params
            .size
            .map(|s| usize::try_from(s).unwrap_or(usize::MAX));
        if let Some(s) = size
            && s.saturating_sub(self.produced) > limit.saturating_sub(out.len())
        {
            return Err(Diagnostic::output_limit(limit));
        }
        let (low_bits, min_len) = (
            if self.params.large_window { 7 } else { 6 },
            if self.params.literal_tree { 3 } else { 2 },
        );
        let goal = out.len().saturating_add(step);
        let first = out.len();
        loop {
            let progress = out.len() > first;
            let available = input.len().saturating_mul(8).saturating_sub(self.bit);
            let end = match size {
                Some(s) => self.produced >= s,
                // Without a size, stop when no complete symbol can follow.
                None => available < 8,
            };
            if end {
                if !eof {
                    return need(progress, WHAT);
                }
                self.finished = Some(input.len());
                return Ok(Step::Done);
            }
            if out.len() >= goal {
                return Ok(Step::More);
            }
            // A shortage of input inside a symbol fails the step (rolled
            // back until more input arrives).
            let mut bits = Bits {
                data: input,
                pos: self.bit,
                what: WHAT,
            };
            let before = out.len();
            if bits.bit()? == 1 {
                let b = match &trees.literals {
                    Some(code) => code.decode(&mut bits)?,
                    None => usize::try_from(bits.bits(8)?).unwrap_or(0),
                };
                out.push(u8::try_from(b).unwrap_or(0));
            } else {
                let low = usize::try_from(bits.bits(low_bits)?).unwrap_or(0);
                let high = trees.distances.decode(&mut bits)?;
                let dist = (high << low_bits | low).saturating_add(1);
                let mut len = trees.lengths.decode(&mut bits)?;
                if len == 63 {
                    len = len.saturating_add(usize::try_from(bits.bits(8)?).unwrap_or(0));
                }
                len = len.saturating_add(min_len);
                if let Some(s) = size {
                    len = len.min(s.saturating_sub(self.produced));
                }
                if out.len().saturating_add(len) > limit {
                    return Err(Diagnostic::output_limit(limit));
                }
                copy_back(out, dist, len);
            }
            if out.len() > limit {
                return Err(Diagnostic::output_limit(limit));
            }
            self.bit = bits.pos;
            self.produced = self
                .produced
                .saturating_add(out.len().saturating_sub(before));
        }
    }

    fn consumed(&self) -> usize {
        self.finished.unwrap_or_else(|| self.bit.div_ceil(8))
    }

    fn releasable_input(&self) -> usize {
        self.bit / 8
    }

    fn release_input(&mut self, n: usize) {
        self.bit = self.bit.saturating_sub(n.saturating_mul(8));
        self.finished = self.finished.map(|f| f.saturating_sub(n));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Distances reach a window back; before a full window, references
        // before the start read zeros, so keep everything.
        if self.produced < self.window() {
            0
        } else {
            out_len.saturating_sub(self.window())
        }
    }
}

/// Packed bit lengths of the DCL codes, in the format of
/// [`expand_lengths`] with no bias (from zlib's `contrib/blast/blast.c`).
const DCL_LITERALS: [u8; 98] = [
    11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8, 9, 7, 6, 7, 8, 7, 6, 55,
    8, 23, 24, 12, 11, 7, 9, 11, 12, 6, 7, 22, 5, 7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8,
    25, 11, 8, 11, 9, 12, 8, 12, 5, 38, 5, 38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27, 44,
    253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61, 12, 45, 44, 173,
];
const DCL_LENGTHS: [u8; 6] = [2, 35, 36, 53, 38, 23];
const DCL_DISTANCES: [u8; 7] = [2, 20, 53, 230, 247, 151, 248];
const DCL_BASE: [u16; 16] = [3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264];
const DCL_EXTRA: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];

/// The header and codes of a DCL stream.
struct DclSetup {
    coded: bool,
    dict_bits: u32,
    literals: Code,
    lengths: Code,
    distances: Code,
}

/// DCL distances reach at most 4 KiB back.
const DCL_WINDOW: usize = 4096;

/// An incremental DCL implode decoder: a symbol at a time, a step of
/// output per call, keeping its window of output. Positions are relative
/// to the buffers as they are now (see "Releasing" in the pipeline docs).
#[derive(Clone, Default)]
pub struct DclExplode {
    setup: Option<Arc<DclSetup>>,
    /// Bit position in the input (from the start of the header).
    bit: usize,
    /// Output produced so far, released bytes included.
    produced: usize,
    /// Bytes used, once the end code has been read.
    end: Option<usize>,
    /// Once done, the input consumed: all of it, as before.
    finished: Option<usize>,
}

impl DclExplode {
    /// The bytes the stream used up to its end code (header included),
    /// once it has been read.
    pub fn used(&self) -> Option<usize> {
        self.end
    }

    fn read_setup(input: &[u8]) -> Result<DclSetup> {
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
        Ok(DclSetup {
            coded,
            dict_bits,
            literals: Code::new(&expand_lengths(&DCL_LITERALS, 0, 256, WHAT)?, WHAT)?,
            lengths: Code::new(&expand_lengths(&DCL_LENGTHS, 0, 16, WHAT)?, WHAT)?,
            distances: Code::new(&expand_lengths(&DCL_DISTANCES, 0, 64, WHAT)?, WHAT)?,
        })
    }
}

impl Decode for DclExplode {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        const WHAT: &str = "DCL implode";
        let bad = |what: &str| Diagnostic::malformed(format!("DCL implode: {what}"));
        let setup = match &self.setup {
            Some(setup) => Arc::clone(setup),
            None => {
                let setup = Arc::new(Self::read_setup(input)?);
                self.setup = Some(Arc::clone(&setup));
                self.bit = 16;
                setup
            }
        };
        let goal = out.len().saturating_add(step);
        let first = out.len();
        loop {
            if self.end.is_some() {
                if !eof {
                    return need(out.len() > first, WHAT);
                }
                self.finished = Some(input.len());
                return Ok(Step::Done);
            }
            if out.len() >= goal {
                return Ok(Step::More);
            }
            // A shortage of input inside a symbol fails the step (rolled
            // back until more input arrives).
            let mut bits = Bits {
                data: input,
                pos: self.bit,
                what: WHAT,
            };
            let before = out.len();
            if bits.bit()? == 1 {
                let sym = setup.lengths.decode(&mut bits)?;
                let base = DCL_BASE.get(sym).copied().unwrap_or(0);
                let extra = DCL_EXTRA.get(sym).copied().unwrap_or(0);
                let len = usize::from(base)
                    .saturating_add(usize::try_from(bits.bits(u32::from(extra))?).unwrap_or(0));
                if len == 519 {
                    // The end code.
                    self.bit = bits.pos;
                    self.end = Some(bits.pos.div_ceil(8));
                    continue;
                }
                let low_bits = if len == 2 { 2 } else { setup.dict_bits };
                let high = setup.distances.decode(&mut bits)?;
                let low = usize::try_from(bits.bits(low_bits)?).unwrap_or(0);
                let dist = (high << low_bits | low).saturating_add(1);
                if dist > self.produced {
                    return Err(bad("distance before the start of the output"));
                }
                if out.len().saturating_add(len) > limit {
                    return Err(Diagnostic::output_limit(limit));
                }
                copy_back(out, dist, len);
            } else {
                let b = if setup.coded {
                    setup.literals.decode(&mut bits)?
                } else {
                    usize::try_from(bits.bits(8)?).unwrap_or(0)
                };
                out.push(u8::try_from(b).unwrap_or(0));
                if out.len() > limit {
                    return Err(Diagnostic::output_limit(limit));
                }
            }
            self.bit = bits.pos;
            self.produced = self
                .produced
                .saturating_add(out.len().saturating_sub(before));
        }
    }

    fn consumed(&self) -> usize {
        self.finished.unwrap_or_else(|| self.bit.div_ceil(8))
    }

    fn releasable_input(&self) -> usize {
        self.bit / 8
    }

    fn release_input(&mut self, n: usize) {
        self.bit = self.bit.saturating_sub(n.saturating_mul(8));
        self.end = self.end.map(|e| e.saturating_sub(n));
        self.finished = self.finished.map(|f| f.saturating_sub(n));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len.saturating_sub(DCL_WINDOW)
    }
}

/// Decodes a DCL implode stream; returns the output and the bytes used.
pub fn blast(input: &[u8], limit: usize) -> Result<(Vec<u8>, usize)> {
    let mut decoder = Streaming(DclExplode::default());
    let out = decode_all(&mut decoder, input, limit)?;
    Ok((out, decoder.0.used().unwrap_or(input.len())))
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
