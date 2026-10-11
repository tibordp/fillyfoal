//! LZMS, Microsoft's LZ77 format with range-coded decisions and adaptive
//! Huffman codes, as in WIM and ESD images (one block per WIM chunk).
//!
//! Written from wimlib's description of the format (`lzms_decompress.c`,
//! wimlib 1.13), which reverse-engineered it:
//!
//! - A block is read in little-endian 16-bit units from both ends: a binary
//!   range decoder reads forwards from the start, and a bitstream of
//!   Huffman codewords and verbatim extra bits reads backwards from the end
//!   (each unit MSB first). Past the start the bitstream reads zeros; past
//!   the end the range decoder shifts in zeros.
//! - The range decoder (range from `0xffffffff`, code from the first 32
//!   bits, renormalised by 16 bits once the range drops below 2^16) decodes
//!   each decision bit with a probability n/64 (clamped to 1..=63), where n
//!   is the number of zeros among the last 64 bits decoded with the same
//!   entry (initially `0x0000000055555555`). The entry is chosen by the last
//!   4, 5 or 6 bits decoded in that decision's context.
//! - Items are literals, LZ matches and delta matches, each with an
//!   explicit offset or one of three repeat offsets (pairs, for delta
//!   matches). The repeat queues take a used offset out and insert the
//!   new one at the front one item late.
//! - Five Huffman codes (literal, LZ offset slot, length slot, delta offset
//!   slot, delta power) start from all frequencies 1 and are rebuilt every
//!   1024 or 512 symbols from the frequencies, which are then halved
//!   (`f / 2 + 1`). The code is the one a priority-queue construction
//!   builds when ties favour leaves, made canonical, limited to 15 bits.
//! - The decoded block then goes through an x86 filter that turns absolute
//!   addresses in CALL, RIP-relative LEA/MOV and similar instructions back
//!   into relative ones, where the data looks like x86 code.
//!
//! [`Block`] decodes one block a bounded amount at a time into a window it
//! does not own (the block's decoded bytes so far), and [`X86`] filters
//! that window into the output as it grows, so a large block (solid WIM
//! chunks are commonly 64 MiB) never needs one long step.

use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("LZMS: {what}"))
}

/// The largest block (decoded size) the format allows.
pub const MAX_BLOCK: usize = 1 << 30;

const MAX_CODEWORD: usize = 15;
const LITERAL_SYMS: usize = 256;
const LENGTH_SYMS: usize = 54;
const POWER_SYMS: usize = 8;
const OFFSET_SLOTS: usize = 799;

/// Slot bases and extra-bit counts: each slot's base is the previous one
/// plus a power of two, used for a run of slots; the last base is one past
/// the largest value.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn slots<const N: usize, const B: usize>(runs: &[u16], last: u32) -> ([u32; B], [u8; N]) {
    let mut base = [0u32; B];
    let mut extra = [0u8; N];
    let mut slot = 0;
    let mut value = 0u32;
    let mut order = 0;
    while order < runs.len() {
        let mut run = runs[order];
        while run > 0 {
            value += 1 << order;
            if slot > 0 {
                extra[slot - 1] = order as u8;
            }
            base[slot] = value;
            slot += 1;
            run -= 1;
        }
        order += 1;
    }
    base[slot] = last;
    extra[slot - 1] = (31 - (last - base[slot - 1]).leading_zeros()) as u8;
    (base, extra)
}

const OFFSETS: ([u32; OFFSET_SLOTS + 1], [u8; OFFSET_SLOTS]) = slots(
    &[
        9, 0, 9, 7, 10, 15, 15, 20, 20, 30, 33, 40, 42, 45, 60, 73, 80, 85, 95, 105, 6,
    ],
    0x465b_e4a5,
);
const LENGTHS: ([u32; LENGTH_SYMS + 1], [u8; LENGTH_SYMS]) = slots(
    &[27, 4, 6, 4, 5, 2, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1],
    0x4001_08ab,
);

/// Offset slots used for a block of `size` bytes: enough for an offset of
/// `size - 1`.
fn offset_slots(size: usize) -> usize {
    if size < 2 {
        return 0;
    }
    let max = u32::try_from(size.saturating_sub(1)).unwrap_or(u32::MAX);
    OFFSETS.0.partition_point(|&b| b <= max).min(OFFSET_SLOTS)
}

/// A probability entry: the last 64 bits decoded with it.
#[derive(Clone, Copy, Debug)]
struct Prob {
    zeros: u8,
    recent: u64,
}

impl Prob {
    const INIT: Prob = Prob {
        zeros: 48,
        recent: 0x5555_5555,
    };

    /// Out of 64, the chance of a 0; never 0 or 64.
    fn p0(self) -> u32 {
        u32::from(self.zeros).clamp(1, 63)
    }

    fn update(&mut self, bit: bool) {
        let out = u8::from(self.recent >> 63 != 0);
        self.zeros = self.zeros.wrapping_add(out).wrapping_sub(u8::from(bit));
        self.recent = self.recent << 1 | u64::from(bit);
    }
}

/// A decision context: its recent bits select the probability entry.
#[derive(Clone, Debug)]
struct Context<const N: usize> {
    state: usize,
    probs: [Prob; N],
}

impl<const N: usize> Context<N> {
    fn new() -> Self {
        Context {
            state: 0,
            probs: [Prob::INIT; N],
        }
    }
}

/// The forwards range decoder.
#[derive(Clone, Debug)]
struct Range {
    range: u32,
    code: u32,
    /// The next 16-bit unit.
    next: usize,
}

fn le16(input: &[u8], at: usize) -> u16 {
    match input.get(at..at.saturating_add(2)) {
        Some(&[a, b]) => u16::from_le_bytes([a, b]),
        _ => 0,
    }
}

impl Range {
    fn new(input: &[u8]) -> Self {
        Range {
            range: u32::MAX,
            code: u32::from(le16(input, 0)) << 16 | u32::from(le16(input, 2)),
            next: 4,
        }
    }

    fn bit<const N: usize>(&mut self, input: &[u8], cx: &mut Context<N>) -> bool {
        let state = cx.state;
        let Some(prob) = cx.probs.get_mut(state) else {
            return false;
        };
        if self.range & 0xffff_0000 == 0 {
            self.range <<= 16;
            self.code <<= 16;
            if self.next.saturating_add(2) <= input.len() {
                self.code |= u32::from(le16(input, self.next));
                self.next = self.next.saturating_add(2);
            }
        }
        let bound = (self.range >> 6).wrapping_mul(prob.p0());
        let bit = if self.code < bound {
            self.range = bound;
            false
        } else {
            self.range = self.range.wrapping_sub(bound);
            self.code = self.code.wrapping_sub(bound);
            true
        };
        prob.update(bit);
        cx.state = (state << 1 | usize::from(bit)) & N.wrapping_sub(1);
        bit
    }
}

/// The backwards bitstream (Huffman codewords and extra bits).
#[derive(Clone, Debug)]
struct Bits {
    buf: u64,
    left: u32,
    /// One past the next 16-bit unit.
    next: usize,
}

impl Bits {
    fn fill(&mut self, input: &[u8]) {
        while self.left <= 48 {
            let word = match self.next.checked_sub(2) {
                Some(at) => {
                    self.next = at;
                    le16(input, at)
                }
                None => 0,
            };
            self.buf |= u64::from(word) << (48u32.wrapping_sub(self.left) & 63);
            self.left = self.left.wrapping_add(16);
        }
    }

    /// The next `n` (at most 32) bits, without consuming them.
    fn peek(&self, n: u32) -> u64 {
        self.buf.checked_shr(64u32.wrapping_sub(n)).unwrap_or(0)
    }

    fn skip(&mut self, n: u32) {
        self.buf = self.buf.checked_shl(n).unwrap_or(0);
        self.left = self.left.saturating_sub(n);
    }

    fn read(&mut self, input: &[u8], n: u32) -> u32 {
        if self.left < n {
            self.fill(input);
        }
        let v = self.peek(n);
        self.skip(n);
        u32::try_from(v).unwrap_or(0)
    }
}

/// An adaptive canonical Huffman code.
#[derive(Clone, Debug)]
struct Code {
    freqs: Vec<u32>,
    rebuild: u32,
    until_rebuild: u32,
    /// Codewords per length.
    counts: [u32; MAX_CODEWORD + 1],
    /// Symbols ordered by codeword length, then value.
    symbols: Vec<u16>,
}

impl Code {
    fn new(syms: usize, rebuild: u32) -> Self {
        let mut code = Code {
            freqs: vec![1; syms],
            rebuild,
            until_rebuild: rebuild,
            counts: [0; MAX_CODEWORD + 1],
            symbols: Vec::with_capacity(syms.saturating_add(1)),
        };
        code.build();
        code
    }

    fn heap_size(&self) -> usize {
        self.freqs
            .capacity()
            .saturating_mul(4)
            .saturating_add(self.symbols.capacity().saturating_mul(2))
    }

    /// Builds the code from the frequencies.
    fn build(&mut self) {
        self.counts = [0; MAX_CODEWORD + 1];
        self.symbols.clear();
        let n = self.freqs.len();
        if n < 2 {
            if n == 1 {
                // Two codewords, the second for a symbol that does not
                // exist (wimlib does the same).
                self.counts[1] = 2;
                self.symbols.extend([0, 1]);
            }
            return;
        }
        let lens = code_lengths(&self.freqs);
        for &len in &lens {
            if let Some(c) = self.counts.get_mut(usize::from(len)) {
                *c = c.saturating_add(1);
            }
        }
        // Counting sort by length (symbols in order within a length).
        let mut next = [0usize; MAX_CODEWORD + 2];
        for len in 1..=MAX_CODEWORD {
            let prev = next.get(len).copied().unwrap_or(0);
            let count = self.counts.get(len).copied().unwrap_or(0);
            if let Some(n) = next.get_mut(len.saturating_add(1)) {
                *n = prev.saturating_add(count as usize);
            }
        }
        self.symbols.resize(n, 0);
        for (sym, &len) in lens.iter().enumerate() {
            if let Some(at) = next.get_mut(usize::from(len))
                && let Some(slot) = self.symbols.get_mut(*at)
            {
                *slot = u16::try_from(sym).unwrap_or(0);
                *at = at.saturating_add(1);
            }
        }
    }

    fn decode(&mut self, input: &[u8], bits: &mut Bits) -> Result<usize> {
        if bits.left < MAX_CODEWORD as u32 {
            bits.fill(input);
        }
        let window = bits.peek(MAX_CODEWORD as u32);
        let mut first = 0u64;
        let mut index = 0usize;
        for len in 1..=MAX_CODEWORD {
            let code = window >> (MAX_CODEWORD.wrapping_sub(len) & 63);
            let count = u64::from(self.counts.get(len).copied().unwrap_or(0));
            let delta = code.wrapping_sub(first);
            if delta < count {
                bits.skip(len as u32);
                let sym = self
                    .symbols
                    .get(index.saturating_add(usize::try_from(delta).unwrap_or(usize::MAX)))
                    .copied()
                    .map(usize::from)
                    .filter(|&s| s < self.freqs.len())
                    .ok_or_else(|| bad("invalid symbol"))?;
                self.count(sym);
                return Ok(sym);
            }
            index = index.saturating_add(usize::try_from(count).unwrap_or(0));
            first = first.saturating_add(count) << 1;
        }
        Err(bad("invalid Huffman code"))
    }

    fn count(&mut self, sym: usize) {
        if let Some(f) = self.freqs.get_mut(sym) {
            *f = f.saturating_add(1);
        }
        self.until_rebuild = self.until_rebuild.saturating_sub(1);
        if self.until_rebuild == 0 {
            self.build();
            for f in &mut self.freqs {
                *f = (*f >> 1).saturating_add(1);
            }
            self.until_rebuild = self.rebuild;
        }
    }
}

/// Codeword lengths for `freqs` (at least two, all nonzero): the leaves
/// sorted by frequency then symbol, merged with the internal nodes in the
/// order they are made (two queues; ties take leaves first), the lengths
/// counted from the internal nodes' depths with any beyond 15 moved up,
/// and handed out longest first in leaf order. This is the construction
/// wimlib's compressor and decompressor share.
fn code_lengths(freqs: &[u32]) -> Vec<u8> {
    let n = freqs.len();
    let mut lens = vec![0u8; n];
    let mut order: Vec<u16> = (0..n).map(|s| u16::try_from(s).unwrap_or(0)).collect();
    let freq = |s: u16| freqs.get(usize::from(s)).copied().unwrap_or(0);
    order.sort_unstable_by_key(|&s| (freq(s), s));
    let leaf = |i: usize| order.get(i).map_or(u64::MAX, |&s| u64::from(freq(s)));
    let internals = n.saturating_sub(1);
    // Internal nodes: frequency, then parent once it has one.
    let mut weight: Vec<u64> = Vec::with_capacity(internals);
    let mut parent: Vec<usize> = vec![0; internals];
    let (mut i, mut b) = (0usize, 0usize);
    let node = |w: &Vec<u64>, k: usize| w.get(k).copied().unwrap_or(u64::MAX);
    while weight.len() < internals {
        let e = weight.len();
        let w = if i.saturating_add(1) < n
            && (b == e || leaf(i.saturating_add(1)) <= node(&weight, b))
        {
            let w = leaf(i).saturating_add(leaf(i.saturating_add(1)));
            i = i.saturating_add(2);
            w
        } else if b.saturating_add(2) <= e
            && (i >= n || node(&weight, b.saturating_add(1)) < leaf(i))
        {
            let w = node(&weight, b).saturating_add(node(&weight, b.saturating_add(1)));
            for k in [b, b.saturating_add(1)] {
                if let Some(p) = parent.get_mut(k) {
                    *p = e;
                }
            }
            b = b.saturating_add(2);
            w
        } else {
            let w = leaf(i).saturating_add(node(&weight, b));
            if let Some(p) = parent.get_mut(b) {
                *p = e;
            }
            i = i.saturating_add(1);
            b = b.saturating_add(1);
            w
        };
        weight.push(w);
    }
    // Leaf counts per length: the root's two children at length 1, and each
    // internal node (parents before children, so in reverse order) turns
    // one leaf at its depth into two below it.
    let mut len_counts = [0u32; MAX_CODEWORD + 2];
    len_counts[1] = 2;
    let mut depth = vec![0usize; internals];
    for k in (0..internals.saturating_sub(1)).rev() {
        let p = parent.get(k).copied().unwrap_or(0);
        let d = depth.get(p).copied().unwrap_or(0).saturating_add(1);
        if let Some(slot) = depth.get_mut(k) {
            *slot = d;
        }
        let mut len = d;
        if len >= MAX_CODEWORD {
            len = MAX_CODEWORD;
            loop {
                len = len.saturating_sub(1);
                if len == 0 || len_counts.get(len).is_some_and(|&c| c != 0) {
                    break;
                }
            }
        }
        if let Some(c) = len_counts.get_mut(len) {
            *c = c.saturating_sub(1);
        }
        if let Some(c) = len_counts.get_mut(len.saturating_add(1)) {
            *c = c.saturating_add(2);
        }
    }
    let mut at = 0usize;
    for len in (1..=MAX_CODEWORD).rev() {
        for _ in 0..len_counts.get(len).copied().unwrap_or(0) {
            if let Some(&s) = order.get(at)
                && let Some(l) = lens.get_mut(usize::from(s))
            {
                *l = len as u8;
            }
            at = at.saturating_add(1);
        }
    }
    lens
}

/// The rest of a match still to be copied (a step ends in the middle of
/// a long one).
#[derive(Clone, Copy, Debug)]
enum Pending {
    None,
    Lz {
        offset: usize,
        left: usize,
    },
    Delta {
        offset: usize,
        span: usize,
        left: usize,
    },
}

/// One LZMS block being decoded (before the x86 filter).
#[derive(Clone, Debug)]
pub struct Block {
    size: usize,
    range: Range,
    bits: Bits,
    main: Context<16>,
    is_delta: Context<32>,
    lz: Context<64>,
    lz_rep: [Context<64>; 2],
    delta: Context<64>,
    delta_rep: [Context<64>; 2],
    literal: Code,
    lz_offset: Code,
    length: Code,
    delta_offset: Code,
    delta_power: Code,
    recent_lz: [u32; 4],
    /// `power << 32 | raw offset`.
    recent_delta: [u64; 4],
    /// The previous item: 0 literal, 1 LZ match, 2 delta match (the queue
    /// update that is still due).
    prev: u8,
    pending: Pending,
}

impl Block {
    /// A decoder for a block of `input.len()` bytes that decodes to `size`
    /// bytes. The same `input` must be passed to every [`Block::decode`].
    pub fn new(input: &[u8], size: usize) -> Result<Self> {
        if input.len() < 4 || !input.len().is_multiple_of(2) {
            return Err(bad("block size not an even number of at least 4 bytes"));
        }
        if size > MAX_BLOCK {
            return Err(Diagnostic::unsupported(format!(
                "LZMS block of {size:#x} bytes"
            )));
        }
        let slots = offset_slots(size);
        Ok(Block {
            size,
            range: Range::new(input),
            bits: Bits {
                buf: 0,
                left: 0,
                next: input.len(),
            },
            main: Context::new(),
            is_delta: Context::new(),
            lz: Context::new(),
            lz_rep: [Context::new(), Context::new()],
            delta: Context::new(),
            delta_rep: [Context::new(), Context::new()],
            literal: Code::new(LITERAL_SYMS, 1024),
            lz_offset: Code::new(slots, 1024),
            length: Code::new(LENGTH_SYMS, 512),
            delta_offset: Code::new(slots, 1024),
            delta_power: Code::new(POWER_SYMS, 512),
            recent_lz: [1, 2, 3, 4],
            recent_delta: [1, 2, 3, 4],
            prev: 0,
            pending: Pending::None,
        })
    }

    /// The decoded size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Heap bytes a clone copies.
    pub fn heap_size(&self) -> usize {
        [
            &self.literal,
            &self.lz_offset,
            &self.length,
            &self.delta_offset,
            &self.delta_power,
        ]
        .iter()
        .map(|c| c.heap_size())
        .fold(0, usize::saturating_add)
    }

    fn offset(&mut self, input: &[u8], delta: bool) -> Result<u32> {
        let code = if delta {
            &mut self.delta_offset
        } else {
            &mut self.lz_offset
        };
        let slot = code.decode(input, &mut self.bits)?;
        let base = OFFSETS.0.get(slot).copied().unwrap_or(0);
        let extra = OFFSETS.1.get(slot).copied().unwrap_or(0);
        Ok(base.wrapping_add(self.bits.read(input, u32::from(extra))))
    }

    fn length(&mut self, input: &[u8]) -> Result<usize> {
        let slot = self.length.decode(input, &mut self.bits)?;
        let base = LENGTHS.0.get(slot).copied().unwrap_or(0);
        let extra = LENGTHS.1.get(slot).copied().unwrap_or(0);
        let len = if extra == 0 {
            base
        } else {
            base.wrapping_add(self.bits.read(input, u32::from(extra)))
        };
        Ok(usize::try_from(len).unwrap_or(usize::MAX))
    }

    /// Decodes into `win` (the block's output so far, before filtering)
    /// until it holds at least `until` bytes or the block is complete.
    /// Returns whether it is.
    pub fn decode(&mut self, input: &[u8], win: &mut Vec<u8>, until: usize) -> Result<bool> {
        let until = until.min(self.size);
        loop {
            match self.pending {
                Pending::None => {}
                Pending::Lz { offset, left } => {
                    let n = left.min(until.saturating_sub(win.len()).max(1));
                    copy_lz(win, offset, n)?;
                    self.pending = match left.saturating_sub(n) {
                        0 => Pending::None,
                        left => Pending::Lz { offset, left },
                    };
                }
                Pending::Delta { offset, span, left } => {
                    let n = left.min(until.saturating_sub(win.len()).max(1));
                    copy_delta(win, offset, span, n)?;
                    self.pending = match left.saturating_sub(n) {
                        0 => Pending::None,
                        left => Pending::Delta { offset, span, left },
                    };
                }
            }
            if win.len() >= self.size {
                return Ok(true);
            }
            if win.len() >= until {
                return Ok(false);
            }
            self.item(input, win)?;
        }
    }

    /// Decodes one item; a match is left pending, to be copied.
    fn item(&mut self, input: &[u8], win: &mut Vec<u8>) -> Result<()> {
        if !self.range.bit(input, &mut self.main) {
            let sym = self.literal.decode(input, &mut self.bits)?;
            win.push(u8::try_from(sym).unwrap_or(0));
            self.prev = 0;
            return Ok(());
        }
        let left = self.size.saturating_sub(win.len());
        if !self.range.bit(input, &mut self.is_delta) {
            // LZ match. A repeat offset comes from one slot further along
            // when the previous item was an LZ match, whose offset is not
            // yet at the front of the queue.
            let offset = if !self.range.bit(input, &mut self.lz) {
                let offset = self.offset(input, false)?;
                self.recent_lz.copy_within(0..3, 1);
                offset
            } else {
                let rep = self.rep(input, false);
                take_repeat(&mut self.recent_lz, rep, usize::from(self.prev & 1))
            };
            if let Some(front) = self.recent_lz.first_mut() {
                *front = offset;
            }
            self.prev = 1;
            let len = self.length(input)?;
            let offset = usize::try_from(offset).unwrap_or(usize::MAX);
            if offset == 0 || offset > win.len() {
                return Err(bad("match offset before the start of the block"));
            }
            if len > left {
                return Err(bad("match runs past the end of the block"));
            }
            self.pending = Pending::Lz { offset, left: len };
        } else {
            // Delta match: a (power, raw offset) pair.
            let pair = if !self.range.bit(input, &mut self.delta) {
                let power = self.delta_power.decode(input, &mut self.bits)?;
                let raw = self.offset(input, true)?;
                self.recent_delta.copy_within(0..3, 1);
                u64::try_from(power).unwrap_or(0) << 32 | u64::from(raw)
            } else {
                let rep = self.rep(input, true);
                take_repeat(&mut self.recent_delta, rep, usize::from(self.prev >> 1))
            };
            if let Some(front) = self.recent_delta.first_mut() {
                *front = pair;
            }
            self.prev = 2;
            let len = self.length(input)?;
            let power = u32::try_from(pair >> 32).unwrap_or(u32::MAX);
            let raw = pair & 0xffff_ffff;
            let span = 1u64.checked_shl(power).filter(|_| power < 32);
            let offset = span
                .and_then(|s| raw.checked_mul(s))
                .filter(|&o| o <= u64::from(u32::MAX));
            let (Some(span), Some(offset)) = (span, offset) else {
                return Err(bad("delta match offset overflows"));
            };
            let reach = usize::try_from(offset.saturating_add(span)).unwrap_or(usize::MAX);
            if reach > win.len() {
                return Err(bad("delta match before the start of the block"));
            }
            if len > left {
                return Err(bad("match runs past the end of the block"));
            }
            self.pending = Pending::Delta {
                offset: usize::try_from(offset).unwrap_or(usize::MAX),
                span: usize::try_from(span).unwrap_or(usize::MAX),
                left: len,
            };
        }
        Ok(())
    }

    /// Which repeat offset (0..=2) an LZ or delta match uses.
    fn rep(&mut self, input: &[u8], delta: bool) -> usize {
        let [first, second] = if delta {
            &mut self.delta_rep
        } else {
            &mut self.lz_rep
        };
        if !self.range.bit(input, first) {
            0
        } else if !self.range.bit(input, second) {
            1
        } else {
            2
        }
    }
}

/// Takes repeat entry `rep` out of `queue`, `late` (0 or 1) slots further
/// along when the previous match's entry is still to be pushed: the entries
/// before it move one slot along (the front is then overwritten).
fn take_repeat<T: Copy + Default>(queue: &mut [T; 4], rep: usize, late: usize) -> T {
    let at = rep.saturating_add(late);
    let value = queue.get(at).copied().unwrap_or_default();
    if let Some(v) = queue.get(rep).copied()
        && let Some(slot) = queue.get_mut(at)
    {
        *slot = v;
    }
    queue.copy_within(0..rep, 1);
    value
}

/// Appends `n` bytes copied from `offset` back (possibly overlapping).
fn copy_lz(win: &mut Vec<u8>, offset: usize, n: usize) -> Result<()> {
    let mut left = n;
    while left > 0 {
        let from = win
            .len()
            .checked_sub(offset)
            .ok_or_else(|| bad("match offset before the start of the block"))?;
        let take = left.min(offset);
        win.extend_from_within(from..from.saturating_add(take));
        left = left.saturating_sub(take);
    }
    Ok(())
}

/// Appends `n` bytes of a delta match: each is the byte `offset` back plus
/// the difference between the bytes `span` before each of the two.
fn copy_delta(win: &mut Vec<u8>, offset: usize, span: usize, n: usize) -> Result<()> {
    for _ in 0..n {
        let at = win.len();
        let get = |back: usize| at.checked_sub(back).and_then(|i| win.get(i)).copied();
        let (Some(a), Some(b), Some(c)) =
            (get(offset), get(span), get(offset.saturating_add(span)))
        else {
            return Err(bad("delta match before the start of the block"));
        };
        win.push(a.wrapping_add(b).wrapping_sub(c));
    }
    Ok(())
}

/// Translations stop this many bytes before the end of the block.
const X86_TAIL: usize = 16;
/// How far back a likely instruction keeps translation on.
const X86_MAX_TRANSLATION_OFFSET: i64 = 1023;
/// Two references to the same address this close mark likely x86 code.
const X86_ID_WINDOW: i64 = 65535;
/// "Never referenced": just out of the window from position 0.
const X86_NEVER: i32 = -65536;

/// The x86 filter of an LZMS block, undone a step at a time as the block
/// is decoded. Positions are within the block.
#[derive(Clone, Debug)]
pub struct X86 {
    size: usize,
    /// The next position to look at for an opcode.
    scan: usize,
    /// Bytes written to the output.
    emitted: usize,
    /// The end of the last likely instruction.
    last_x86: i64,
    /// Per low 16 bits of a target address, where it was last referenced.
    last_target: Vec<i32>,
}

impl X86 {
    pub fn new(size: usize) -> Self {
        X86 {
            size,
            scan: 1,
            emitted: 0,
            // Just out of reach of position 0.
            last_x86: -1024,
            last_target: if size > X86_TAIL.saturating_add(1) {
                vec![X86_NEVER; 1 << 16]
            } else {
                Vec::new()
            },
        }
    }

    /// Heap bytes a clone copies.
    pub fn heap_size(&self) -> usize {
        self.last_target.capacity().saturating_mul(4)
    }

    /// Whether the whole block has been written out.
    pub fn done(&self) -> bool {
        self.emitted >= self.size
    }

    /// Appends to `out` the filtered bytes of `win` (the block decoded so
    /// far) that no later translation can change.
    pub fn run(&mut self, win: &[u8], out: &mut Vec<u8>) {
        let have = win.len();
        let limit = if self.size > X86_TAIL.saturating_add(1) {
            self.size.saturating_sub(X86_TAIL)
        } else {
            0
        };
        let byte = |i: usize| win.get(i).copied().unwrap_or(0);
        // An opcode needs the 7 bytes after it.
        while self.scan < limit && (self.scan.saturating_add(8) <= have || have >= self.size) {
            let p = self.scan;
            let (op, p1, p2) = (
                byte(p),
                byte(p.saturating_add(1)),
                byte(p.saturating_add(2)),
            );
            let mut max = X86_MAX_TRANSLATION_OFFSET;
            let opcode_len = match op {
                // Call indirect relative.
                0xff if p1 == 0x15 => 2,
                // Lock add relative.
                0xf0 if p1 == 0x83 && p2 == 0x05 => 3,
                // REX.W LEA or MOV with what may be RIP-relative addressing
                // (only the R/M field is tested).
                0x48 | 0x4c
                    if p2 & 0x07 == 0x05
                        && (p1 == 0x8d || p1 == 0x8b && op & 0x04 == 0 && p2 & 0xf0 == 0) =>
                {
                    3
                }
                // Call relative, with less tolerance.
                0xe8 => {
                    max >>= 1;
                    1
                }
                // Jump relative: skipped, never translated.
                0xe9 => {
                    self.scan = p.saturating_add(5);
                    continue;
                }
                _ => {
                    self.scan = p.saturating_add(1);
                    continue;
                }
            };
            let at = p.saturating_add(opcode_len);
            let operand = win.get(at..at.saturating_add(4)).unwrap_or_default();
            let mut n = match *operand {
                [a, b, c, d] => u32::from_le_bytes([a, b, c, d]),
                _ => 0,
            };
            let i = i64::try_from(p).unwrap_or(i64::MAX);
            if i.saturating_sub(self.last_x86) <= max {
                n = n.wrapping_sub(p as u32);
                out.extend_from_slice(win.get(self.emitted..at).unwrap_or_default());
                out.extend_from_slice(&n.to_le_bytes());
                self.emitted = at.saturating_add(4);
            }
            let target = usize::from((p as u16).wrapping_add(n as u16));
            let end = at.saturating_add(3);
            let e = i64::try_from(end).unwrap_or(i64::MAX);
            if let Some(last) = self.last_target.get_mut(target) {
                if e.saturating_sub(i64::from(*last)) <= X86_ID_WINDOW {
                    self.last_x86 = e;
                }
                *last = i32::try_from(end).unwrap_or(i32::MAX);
            }
            self.scan = end.saturating_add(1);
        }
        let frontier = if self.scan >= limit {
            have
        } else {
            self.scan.min(have)
        };
        if frontier > self.emitted {
            out.extend_from_slice(win.get(self.emitted..frontier).unwrap_or_default());
            self.emitted = frontier;
        }
    }
}

/// Decodes a whole block (for tests and small inputs).
pub fn decode_block(input: &[u8], size: usize) -> Result<Vec<u8>> {
    let mut block = Block::new(input, size)?;
    let mut filter = X86::new(size);
    let mut win = Vec::new();
    let mut out = Vec::new();
    loop {
        let until = win.len().saturating_add(1 << 16);
        let done = block.decode(input, &mut win, until)?;
        filter.run(&win, &mut out);
        if done {
            return Ok(out);
        }
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

    #[test]
    fn slot_tables_match_wimlib() {
        // Spot checks against wimlib's `lzms_offset_slot_base` and
        // `lzms_length_slot_base` tables and their extra-bit counts.
        let (ob, oe) = OFFSETS;
        assert_eq!(&ob[..12], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 0xd, 0x11, 0x15]);
        assert_eq!(ob[100], 0x20a5);
        assert_eq!(ob[400], 0x3064a5);
        assert_eq!(ob[797], 0x064b_e4a5);
        assert_eq!(ob[798], 0x065b_e4a5);
        assert_eq!(ob[799], 0x465b_e4a5);
        assert_eq!(
            &oe[..18],
            &[0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3]
        );
        assert_eq!(&oe[790..], &[19, 19, 20, 20, 20, 20, 20, 20, 30]);
        let (lb, le) = LENGTHS;
        assert_eq!(&lb[25..32], &[0x1a, 0x1b, 0x1d, 0x1f, 0x21, 0x23, 0x27]);
        assert_eq!(&lb[50..], &[0x2ab, 0x4ab, 0x8ab, 0x108ab, 0x4001_08ab]);
        assert_eq!(&le[44..], &[4, 5, 5, 6, 7, 8, 9, 10, 16, 30]);
        assert_eq!(offset_slots(1), 0);
        assert_eq!(offset_slots(2), 1);
        assert_eq!(offset_slots(10), 9);
        assert_eq!(offset_slots(32768), offset_slots(32769));
    }

    #[test]
    fn code_lengths_favour_leaves_on_ties() {
        // Four equal frequencies: a balanced tree.
        assert_eq!(code_lengths(&[1, 1, 1, 1]), [2, 2, 2, 2]);
        // 1,1,2: the tie between the leaf of weight 2 and the node of
        // weight 2 takes the leaf first, so both 1s are at depth 2.
        assert_eq!(code_lengths(&[1, 1, 2]), [2, 2, 1]);
        // Kraft equality for an initial 799-symbol code.
        let lens = code_lengths(&[1; 799]);
        let kraft: u64 = lens.iter().map(|&l| 1u64 << (15 - l)).sum();
        assert_eq!(kraft, 1 << 15);
        // Skewed frequencies stay within 15 bits.
        let freqs: Vec<u32> = (0..40).map(|i| 1u32 << (i % 21)).collect();
        let lens = code_lengths(&freqs);
        assert!(lens.iter().all(|&l| (1..=15).contains(&l)));
        let kraft: u64 = lens.iter().map(|&l| 1u64 << (15 - l)).sum();
        assert_eq!(kraft, 1 << 15);
    }

    #[test]
    fn rejects_odd_and_tiny_blocks() {
        assert!(Block::new(&[0; 3], 10).is_err());
        assert!(Block::new(&[0; 5], 10).is_err());
        assert!(Block::new(&[0; 4], 10).is_ok());
    }
}
