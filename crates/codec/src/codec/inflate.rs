//! DEFLATE (RFC 1951) decoder.
//!
//! An altered Rust version of Mark Adler's `puff` (zlib `contrib/puff`, zlib
//! license; see `THIRD-PARTY.md`): canonical Huffman decoding one bit at a
//! time. Slow, small and easy to audit. The decoder works on input
//! that is fully in memory and can stop at any symbol boundary, so callers
//! decode in bounded steps and yield to the budget in between.

use crate::error::{Diagnostic, Result};

const MAX_BITS: usize = 15;

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// A canonical Huffman code: how many codes of each length, and the symbols
/// in code order.
#[derive(Clone, Debug)]
struct Huffman {
    counts: [u16; MAX_BITS + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    /// Builds a code from per-symbol lengths. Incomplete codes are allowed
    /// (as in zlib) as long as they are not over-subscribed.
    fn new(lengths: &[u8]) -> Result<Self> {
        let mut counts = [0u16; MAX_BITS + 1];
        for &len in lengths {
            let slot = counts
                .get_mut(usize::from(len))
                .ok_or_else(|| bad("code length above 15"))?;
            *slot = slot.saturating_add(1);
        }
        let mut left: i32 = 1;
        for len in 1..=MAX_BITS {
            left = left.saturating_mul(2);
            left = left.saturating_sub(i32::from(counts.get(len).copied().unwrap_or(0)));
            if left < 0 {
                return Err(bad("over-subscribed Huffman code"));
            }
        }
        let mut offsets = [0u16; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            let next = offsets
                .get(len)
                .copied()
                .unwrap_or(0)
                .saturating_add(counts.get(len).copied().unwrap_or(0));
            if let Some(o) = offsets.get_mut(len.saturating_add(1)) {
                *o = next;
            }
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            if let Some(o) = offsets.get_mut(usize::from(len)) {
                if let Some(slot) = symbols.get_mut(usize::from(*o)) {
                    *slot = u16::try_from(symbol).unwrap_or(u16::MAX);
                }
                *o = o.saturating_add(1);
            }
        }
        Ok(Huffman { counts, symbols })
    }
}

/// How far back a DEFLATE match can reach.
pub const WINDOW: usize = 32 * 1024;

fn bad(message: &str) -> Diagnostic {
    Diagnostic::malformed(format!("deflate: {message}"))
}

#[derive(Clone, Debug)]
enum State {
    Header,
    Stored { remaining: usize },
    Codes { lit: Huffman, dist: Huffman },
    Done,
}

pub use super::pipeline::Step;

/// A resumable inflater over an in-memory compressed buffer.
#[derive(Clone, Debug)]
pub struct Inflate {
    /// Position in the input, in bits.
    bit: usize,
    state: State,
    last: bool,
}

impl Default for Inflate {
    fn default() -> Self {
        Self::new()
    }
}

impl Inflate {
    pub fn new() -> Self {
        Inflate {
            bit: 0,
            state: State::Header,
            last: false,
        }
    }

    /// Bytes of input consumed so far (rounded up to whole bytes).
    pub fn consumed(&self) -> usize {
        self.bit.div_ceil(8)
    }

    /// Whole input bytes already read (a partly read byte is kept).
    pub fn releasable_input(&self) -> usize {
        self.bit / 8
    }

    /// The first `n` (at most [`Inflate::releasable_input`]) input bytes
    /// were dropped.
    pub fn release_input(&mut self, n: usize) {
        self.bit = self.bit.saturating_sub(n.saturating_mul(8));
    }

    /// Decodes until at least `step` more bytes have been produced, the stream
    /// ends, or `limit` total output bytes would be exceeded (an error).
    pub fn step(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let target = out.len().saturating_add(step);
        loop {
            if out.len() >= target {
                return Ok(Step::More);
            }
            match std::mem::replace(&mut self.state, State::Done) {
                State::Done => return Ok(Step::Done),
                State::Header => {
                    if self.last {
                        self.state = State::Done;
                        continue;
                    }
                    self.last = self.bits(input, 1)? == 1;
                    self.state = match self.bits(input, 2)? {
                        0 => {
                            self.bit = self.bit.div_ceil(8).saturating_mul(8);
                            let len = self.bits(input, 16)?;
                            let nlen = self.bits(input, 16)?;
                            if len != !nlen & 0xffff {
                                return Err(bad("stored block length check failed"));
                            }
                            State::Stored {
                                remaining: usize::try_from(len).unwrap_or(0),
                            }
                        }
                        1 => fixed()?,
                        2 => self.dynamic(input)?,
                        _ => return Err(bad("invalid block type 3")),
                    };
                }
                State::Stored { remaining } => {
                    let start = self.bit / 8;
                    let room = target.saturating_sub(out.len()).max(1);
                    let n = remaining.min(room);
                    let bytes = start
                        .checked_add(n)
                        .and_then(|end| input.get(start..end))
                        .ok_or_else(|| bad("input ends inside a stored block"))?;
                    if out.len().saturating_add(n) > limit {
                        return Err(Diagnostic::output_limit(limit));
                    }
                    out.extend_from_slice(bytes);
                    self.bit = self.bit.saturating_add(n.saturating_mul(8));
                    let remaining = remaining.saturating_sub(n);
                    self.state = if remaining == 0 {
                        State::Header
                    } else {
                        State::Stored { remaining }
                    };
                }
                State::Codes { lit, dist } => {
                    let done = self.codes(input, out, &lit, &dist, target, limit)?;
                    self.state = if done {
                        State::Header
                    } else {
                        State::Codes { lit, dist }
                    };
                }
            }
        }
    }

    fn bits(&mut self, input: &[u8], n: u32) -> Result<u32> {
        let mut value = 0u32;
        for i in 0..n {
            let byte = input
                .get(self.bit / 8)
                .copied()
                .ok_or_else(|| bad("input ends unexpectedly"))?;
            let bit = u32::from(byte >> (self.bit % 8)) & 1;
            value |= bit << i;
            self.bit = self.bit.saturating_add(1);
        }
        Ok(value)
    }

    fn decode(&mut self, input: &[u8], h: &Huffman) -> Result<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAX_BITS {
            code |= i32::try_from(self.bits(input, 1)?).unwrap_or(0);
            let count = i32::from(h.counts.get(len).copied().unwrap_or(0));
            if code.saturating_sub(first) < count {
                let at = index.saturating_add(code).saturating_sub(first);
                return usize::try_from(at)
                    .ok()
                    .and_then(|at| h.symbols.get(at).copied())
                    .ok_or_else(|| bad("invalid Huffman code"));
            }
            index = index.saturating_add(count);
            first = first.saturating_add(count).saturating_mul(2);
            code = code.saturating_mul(2);
        }
        Err(bad("invalid Huffman code"))
    }

    /// Decodes symbols until end-of-block (`true`) or `target` output bytes.
    fn codes(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        lit: &Huffman,
        dist: &Huffman,
        target: usize,
        limit: usize,
    ) -> Result<bool> {
        while out.len() < target {
            let symbol = usize::from(self.decode(input, lit)?);
            if symbol < 256 {
                if out.len() >= limit {
                    return Err(Diagnostic::output_limit(limit));
                }
                out.push(u8::try_from(symbol).unwrap_or(0));
                continue;
            }
            if symbol == 256 {
                return Ok(true);
            }
            let index = symbol.saturating_sub(257);
            let base = LENGTH_BASE
                .get(index)
                .ok_or_else(|| bad("invalid length symbol"))?;
            let extra = LENGTH_EXTRA.get(index).copied().unwrap_or(0);
            let len = usize::from(*base)
                .saturating_add(usize::try_from(self.bits(input, extra.into())?).unwrap_or(0));
            let d = usize::from(self.decode(input, dist)?);
            let base = DIST_BASE
                .get(d)
                .ok_or_else(|| bad("invalid distance symbol"))?;
            let extra = DIST_EXTRA.get(d).copied().unwrap_or(0);
            let distance = usize::from(*base)
                .saturating_add(usize::try_from(self.bits(input, extra.into())?).unwrap_or(0));
            if distance > out.len() {
                return Err(bad("distance reaches before the start of the output"));
            }
            if out.len().saturating_add(len) > limit {
                return Err(Diagnostic::output_limit(limit));
            }
            let from = out.len().saturating_sub(distance);
            for i in 0..len {
                let byte = out.get(from.saturating_add(i)).copied().unwrap_or(0);
                out.push(byte);
            }
        }
        Ok(false)
    }

    fn dynamic(&mut self, input: &[u8]) -> Result<State> {
        let nlen = usize::try_from(self.bits(input, 5)?)
            .unwrap_or(0)
            .saturating_add(257);
        let ndist = usize::try_from(self.bits(input, 5)?)
            .unwrap_or(0)
            .saturating_add(1);
        let ncode = usize::try_from(self.bits(input, 4)?)
            .unwrap_or(0)
            .saturating_add(4);
        if nlen > 286 || ndist > 30 {
            return Err(bad("too many length or distance codes"));
        }
        let mut lengths = [0u8; 19];
        for &index in CODE_LENGTH_ORDER.iter().take(ncode) {
            if let Some(slot) = lengths.get_mut(index) {
                *slot = u8::try_from(self.bits(input, 3)?).unwrap_or(0);
            }
        }
        let code_lengths = Huffman::new(&lengths)?;
        let mut all = vec![0u8; nlen.saturating_add(ndist)];
        let mut i = 0usize;
        while i < all.len() {
            let symbol = self.decode(input, &code_lengths)?;
            let (value, repeat) = match symbol {
                0..=15 => (u8::try_from(symbol).unwrap_or(0), 1usize),
                16 => {
                    let previous = i
                        .checked_sub(1)
                        .and_then(|p| all.get(p).copied())
                        .ok_or_else(|| bad("repeat with no previous length"))?;
                    (
                        previous,
                        3usize.saturating_add(self.bits(input, 2)? as usize),
                    )
                }
                17 => (0, 3usize.saturating_add(self.bits(input, 3)? as usize)),
                _ => (0, 11usize.saturating_add(self.bits(input, 7)? as usize)),
            };
            if i.saturating_add(repeat) > all.len() {
                return Err(bad("code lengths overflow the table"));
            }
            for _ in 0..repeat {
                if let Some(slot) = all.get_mut(i) {
                    *slot = value;
                }
                i = i.saturating_add(1);
            }
        }
        if all.get(256).copied().unwrap_or(0) == 0 {
            return Err(bad("no end-of-block code"));
        }
        let (lit, dist) = all.split_at(nlen);
        Ok(State::Codes {
            lit: Huffman::new(lit)?,
            dist: Huffman::new(dist)?,
        })
    }
}

fn fixed() -> Result<State> {
    let mut lit = [0u8; 288];
    for (i, slot) in lit.iter_mut().enumerate() {
        *slot = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    Ok(State::Codes {
        lit: Huffman::new(&lit)?,
        dist: Huffman::new(&[5u8; 30])?,
    })
}

/// Inflates a whole buffer (for tests and small inputs).
pub fn inflate(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut inflater = Inflate::new();
    while inflater.step(input, &mut out, usize::MAX, limit)? == Step::More {}
    Ok(out)
}

/// Inflates a whole raw DEFLATE stream whose distances may reach back into
/// `dictionary` (a preset dictionary: zlib's FDICT, or MSZIP's previous
/// block). Returns the output (without the dictionary) and the input bytes
/// consumed. `limit` bounds the output alone.
pub fn inflate_with_dictionary(
    input: &[u8],
    dictionary: &[u8],
    limit: usize,
) -> Result<(Vec<u8>, usize)> {
    let mut out = dictionary.to_vec();
    let mut inflater = Inflate::new();
    let total = limit.saturating_add(dictionary.len());
    while inflater.step(input, &mut out, usize::MAX, total)? == Step::More {}
    out.drain(..dictionary.len());
    Ok((out, inflater.consumed()))
}
