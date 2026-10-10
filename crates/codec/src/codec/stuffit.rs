//! StuffIt fork compression methods.
//!
//! StuffIt's formats were never documented by Aladdin; these decoders are
//! written from memory of The Unarchiver's (XADMaster) implementations,
//! and no StuffIt producer or independent decoder was available to check
//! them against: the tests only show that they invert the encoders in
//! `tests/data/stuffit/`, which share the same understanding.
//!
//! - **1, RLE90**: `0x90 n` repeats the previous byte `n - 1` more times;
//!   `0x90 0` is a literal `0x90`.
//! - **2, LZW**: Unix `compress` without its header, 14-bit codes, block
//!   mode (see [`crate::codec::unixz`]).
//! - **3, Huffman**: a tree sent depth-first (1 = leaf + 8-bit value,
//!   0 = branch), then codes MSB-first.
//! - **5, LZAH**: Okumura's LZHUF (4 KiB window, adaptive Huffman, the
//!   top six position bits through a static code) as in LHA's `-lh1-`.
//! - **13**: LZSS over a 64 KiB window with three Huffman codes (two for
//!   literals/lengths, alternating after a match, and one for distance
//!   widths), LSB-first. Only the dynamic variant, whose code lengths are
//!   sent through a fixed meta-code, is supported; the five built-in code
//!   sets are not.
//! - **15, Arsenic**: an adaptive arithmetic coder over a
//!   move-to-front/zero-run coded Burrows-Wheeler transform, with a final
//!   run-length stage (four equal bytes and a count) and a CRC-32.
//!   Randomized blocks are not supported.
//!
//! Outputs are cut at the fork's recorded length; the fork's CRC-16 (ARC)
//! is checked where the archive gives one. [`Decoder`] works a bounded run
//! at a time (about `step` bytes of output, or a slice of a block's
//! symbols or transform) and releases its input as it goes.

use std::sync::Arc;

use crate::bytes::to_usize;
use crate::codec::pipeline::{self, Decode, Decoder as _, Status, Step, Streaming};
use crate::codec::unixz::UnixCompress;
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("StuffIt: {what}"))
}

/// A compressed fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// The method number (without the encryption flag).
    pub method: u8,
    /// The uncompressed length.
    pub size: u64,
    /// The CRC-16 (ARC) of the uncompressed fork, if it should be checked.
    pub crc: Option<u16>,
}

/// Whether [`Decoder`] handles `method`.
pub fn supported(method: u8) -> bool {
    matches!(method, 0 | 1 | 2 | 3 | 5 | 13 | 15)
}

// ---------------------------------------------------------------------------
// Bit readers

/// MSB-first bits.
#[derive(Clone)]
struct MsbBits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MsbBits<'a> {
    fn bit(&mut self) -> Result<u32> {
        let byte = self
            .data
            .get(self.pos / 8)
            .copied()
            .ok_or_else(|| bad("compressed data ends early"))?;
        let b = (byte >> (7usize.saturating_sub(self.pos % 8))) & 1;
        self.pos = self.pos.saturating_add(1);
        Ok(u32::from(b))
    }

    /// A bit, or 0 past the end (the arithmetic decoder reads ahead).
    fn bit_or_zero(&mut self) -> u32 {
        self.bit().unwrap_or(0)
    }

    fn bits(&mut self, n: u32) -> Result<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = v << 1 | self.bit()?;
        }
        Ok(v)
    }
}

/// LSB-first bits.
#[derive(Clone)]
struct LsbBits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> LsbBits<'a> {
    fn bit(&mut self) -> Result<u32> {
        let byte = self
            .data
            .get(self.pos / 8)
            .copied()
            .ok_or_else(|| bad("compressed data ends early"))?;
        let b = (byte >> (self.pos % 8)) & 1;
        self.pos = self.pos.saturating_add(1);
        Ok(u32::from(b))
    }

    fn bits(&mut self, n: u32) -> Result<u32> {
        let mut v = 0u32;
        for i in 0..n {
            v |= self.bit()? << i;
        }
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// 3: Huffman

#[derive(Clone)]
enum HuffNode {
    Leaf(u8),
    Branch(usize, usize),
}

/// Most nodes a tree over 256 values can have (with some slack for
/// duplicate leaves).
const MAX_NODES: usize = 1024;

fn parse_tree(bs: &mut MsbBits<'_>, nodes: &mut Vec<HuffNode>, depth: usize) -> Result<usize> {
    if nodes.len() >= MAX_NODES || depth > 256 {
        return Err(bad("Huffman tree too large"));
    }
    let index = nodes.len();
    if bs.bit()? == 1 {
        nodes.push(HuffNode::Leaf(u8::try_from(bs.bits(8)?).unwrap_or(0)));
        return Ok(index);
    }
    nodes.push(HuffNode::Branch(0, 0));
    let zero = parse_tree(bs, nodes, depth.saturating_add(1))?;
    let one = parse_tree(bs, nodes, depth.saturating_add(1))?;
    if let Some(n) = nodes.get_mut(index) {
        *n = HuffNode::Branch(zero, one);
    }
    Ok(index)
}

// ---------------------------------------------------------------------------
// 5: LZAH (LZHUF)

const LZAH_N: usize = 4096;
const LZAH_F: usize = 60;
const LZAH_THRESHOLD: usize = 2;
const LZAH_CHARS: usize = 256 - LZAH_THRESHOLD + LZAH_F;
const LZAH_T: usize = LZAH_CHARS * 2 - 1;
const LZAH_ROOT: usize = LZAH_T - 1;
const LZAH_MAX_FREQ: u32 = 0x8000;

/// Okumura's adaptive Huffman tree (`lzhuf.c`): `son[i] >= T` marks a leaf.
#[derive(Clone)]
struct Adaptive {
    freq: Vec<u32>,
    prnt: Vec<usize>,
    son: Vec<usize>,
}

impl Adaptive {
    fn new() -> Self {
        let mut freq = vec![0u32; LZAH_T.saturating_add(1)];
        let mut prnt = vec![0usize; LZAH_T.saturating_add(LZAH_CHARS)];
        let mut son = vec![0usize; LZAH_T];
        for i in 0..LZAH_CHARS {
            if let Some(f) = freq.get_mut(i) {
                *f = 1;
            }
            if let Some(s) = son.get_mut(i) {
                *s = i.saturating_add(LZAH_T);
            }
            if let Some(p) = prnt.get_mut(i.saturating_add(LZAH_T)) {
                *p = i;
            }
        }
        let mut i = 0usize;
        let mut j = LZAH_CHARS;
        while j <= LZAH_ROOT {
            let f = freq
                .get(i)
                .copied()
                .unwrap_or(0)
                .saturating_add(freq.get(i.saturating_add(1)).copied().unwrap_or(0));
            if let Some(slot) = freq.get_mut(j) {
                *slot = f;
            }
            if let Some(s) = son.get_mut(j) {
                *s = i;
            }
            if let Some(p) = prnt.get_mut(i) {
                *p = j;
            }
            if let Some(p) = prnt.get_mut(i.saturating_add(1)) {
                *p = j;
            }
            i = i.saturating_add(2);
            j = j.saturating_add(1);
        }
        if let Some(f) = freq.get_mut(LZAH_T) {
            *f = 0xffff;
        }
        if let Some(p) = prnt.get_mut(LZAH_ROOT) {
            *p = 0;
        }
        Adaptive { freq, prnt, son }
    }

    fn f(&self, i: usize) -> u32 {
        self.freq.get(i).copied().unwrap_or(0)
    }

    fn s(&self, i: usize) -> usize {
        self.son.get(i).copied().unwrap_or(0)
    }

    fn reconstruct(&mut self) {
        // Collect the leaves in the first half, halving their frequencies.
        let mut j = 0usize;
        for i in 0..LZAH_T {
            if self.s(i) >= LZAH_T {
                let f = self.f(i).saturating_add(1) / 2;
                let s = self.s(i);
                if let Some(slot) = self.freq.get_mut(j) {
                    *slot = f;
                }
                if let Some(slot) = self.son.get_mut(j) {
                    *slot = s;
                }
                j = j.saturating_add(1);
            }
        }
        // Rebuild the tree by connecting sons.
        let mut i = 0usize;
        let mut j = LZAH_CHARS;
        while j < LZAH_T {
            let f = self.f(i).saturating_add(self.f(i.saturating_add(1)));
            if let Some(slot) = self.freq.get_mut(j) {
                *slot = f;
            }
            let mut k = j.saturating_sub(1);
            while k > 0 && f < self.f(k) {
                k = k.saturating_sub(1);
            }
            if f >= self.f(k) {
                k = k.saturating_add(1);
            }
            // Insert node j's frequency and son at k.
            if k < j {
                self.freq.copy_within(k..j, k.saturating_add(1));
                self.son.copy_within(k..j, k.saturating_add(1));
            }
            if let Some(slot) = self.freq.get_mut(k) {
                *slot = f;
            }
            if let Some(slot) = self.son.get_mut(k) {
                *slot = i;
            }
            i = i.saturating_add(2);
            j = j.saturating_add(1);
        }
        // Connect parents.
        for i in 0..LZAH_T {
            let k = self.s(i);
            if let Some(p) = self.prnt.get_mut(k) {
                *p = i;
            }
            if k < LZAH_T
                && let Some(p) = self.prnt.get_mut(k.saturating_add(1))
            {
                *p = i;
            }
        }
    }

    fn update(&mut self, c: usize) {
        if self.f(LZAH_ROOT) == LZAH_MAX_FREQ {
            self.reconstruct();
        }
        let mut c = self
            .prnt
            .get(c.saturating_add(LZAH_T))
            .copied()
            .unwrap_or(0);
        let mut guard = 0usize;
        loop {
            guard = guard.saturating_add(1);
            if guard > LZAH_T.saturating_mul(2) {
                return;
            }
            let k = self.f(c).saturating_add(1);
            if let Some(slot) = self.freq.get_mut(c) {
                *slot = k;
            }
            // If the order is disturbed, exchange nodes.
            let mut l = c.saturating_add(1);
            if k > self.f(l) {
                while k > self.f(l.saturating_add(1)) {
                    l = l.saturating_add(1);
                }
                let fl = self.f(l);
                if let Some(slot) = self.freq.get_mut(c) {
                    *slot = fl;
                }
                if let Some(slot) = self.freq.get_mut(l) {
                    *slot = k;
                }
                let i = self.s(c);
                if let Some(p) = self.prnt.get_mut(i) {
                    *p = l;
                }
                if i < LZAH_T
                    && let Some(p) = self.prnt.get_mut(i.saturating_add(1))
                {
                    *p = l;
                }
                let j = self.s(l);
                if let Some(slot) = self.son.get_mut(l) {
                    *slot = i;
                }
                if let Some(p) = self.prnt.get_mut(j) {
                    *p = c;
                }
                if j < LZAH_T
                    && let Some(p) = self.prnt.get_mut(j.saturating_add(1))
                {
                    *p = c;
                }
                if let Some(slot) = self.son.get_mut(c) {
                    *slot = j;
                }
                c = l;
            }
            c = self.prnt.get(c).copied().unwrap_or(0);
            if c == 0 {
                break;
            }
        }
    }

    fn decode_char(&mut self, bs: &mut MsbBits<'_>) -> Result<usize> {
        let mut c = self.s(LZAH_ROOT);
        let mut guard = 0usize;
        while c < LZAH_T {
            guard = guard.saturating_add(1);
            if guard > LZAH_T {
                return Err(bad("LZAH tree loop"));
            }
            c = self.s(c.saturating_add(to_usize(u64::from(bs.bit()?))));
        }
        let c = c.saturating_sub(LZAH_T);
        self.update(c);
        Ok(c)
    }
}

/// The upper six position bits' code lengths (`lzhuf.c`'s `d_len`, by the
/// number of codes of each length: 1 of 3 bits, 3 of 4, 8 of 5, 12 of 6,
/// 24 of 7, 16 of 8).
fn lzah_position(bs: &mut MsbBits<'_>) -> Result<usize> {
    // Read 8 bits, find the code (canonical in 8-bit space), then read the
    // remaining low bits.
    let i = bs.bits(8)?;
    // (first byte value, first upper value, code length) per group.
    let (base, first, len) = match i {
        0x00..=0x1f => (0x00, 0, 3),
        0x20..=0x4f => (0x20, 1, 4),
        0x50..=0x8f => (0x50, 4, 5),
        0x90..=0xbf => (0x90, 12, 6),
        0xc0..=0xef => (0xc0, 24, 7),
        _ => (0xf0, 48, 8),
    };
    let upper = (i.saturating_sub(base) >> (8u32.saturating_sub(len))).saturating_add(first);
    // `len` bits identify the upper part; 8 - len of the bits read already
    // belong to the low six bits, and the rest follow.
    let have = 8u32.saturating_sub(len);
    let mut low = i & ((1u32 << have).saturating_sub(1));
    low = low << (6u32.saturating_sub(have)) | bs.bits(6u32.saturating_sub(have))?;
    Ok(to_usize(u64::from(upper << 6 | (low & 0x3f))))
}

// ---------------------------------------------------------------------------
// 13

/// A canonical prefix code (shortest codes are all zeros), decoded a bit at
/// a time with the first bit read as the code's most significant.
#[derive(Clone)]
struct Canonical {
    /// Symbols ordered by (length, symbol).
    symbols: Vec<u16>,
    /// Number of codes of each length.
    counts: Vec<u32>,
}

impl Canonical {
    fn new(lengths: &[i32]) -> Result<Canonical> {
        let mut counts = vec![0u32; 33];
        for &l in lengths {
            if l > 32 {
                return Err(bad("code length out of range"));
            }
            if l > 0
                && let Some(c) = counts.get_mut(to_usize(u64::from(l.unsigned_abs())))
            {
                *c = c.saturating_add(1);
            }
        }
        let mut symbols = Vec::new();
        for len in 1..=32 {
            for (s, &l) in lengths.iter().enumerate() {
                if l == len {
                    symbols.push(u16::try_from(s).unwrap_or(u16::MAX));
                }
            }
        }
        Ok(Canonical { symbols, counts })
    }

    fn read(&self, bs: &mut LsbBits<'_>) -> Result<u16> {
        let mut code = 0u64;
        let mut first = 0u64;
        let mut index = 0u64;
        for len in 1..=32usize {
            code |= u64::from(bs.bit()?);
            let count = u64::from(self.counts.get(len).copied().unwrap_or(0));
            if code.wrapping_sub(first) < count && code >= first {
                let at = index.saturating_add(code.saturating_sub(first));
                return self
                    .symbols
                    .get(to_usize(at))
                    .copied()
                    .ok_or_else(|| bad("invalid code"));
            }
            index = index.saturating_add(count);
            first = first.saturating_add(count) << 1;
            code <<= 1;
        }
        Err(bad("invalid code"))
    }
}

/// The meta-code for code lengths: (code, length), first bit read in the
/// code's lowest bit.
const META_CODES: [(u32, u32); 37] = [
    (0x5d8, 11),
    (0x058, 8),
    (0x040, 8),
    (0x0c0, 8),
    (0x000, 8),
    (0x078, 7),
    (0x02b, 6),
    (0x014, 5),
    (0x00c, 5),
    (0x01c, 5),
    (0x01b, 5),
    (0x00b, 6),
    (0x010, 5),
    (0x020, 6),
    (0x038, 7),
    (0x018, 7),
    (0x0d8, 9),
    (0xbd8, 12),
    (0x180, 10),
    (0x680, 11),
    (0x380, 11),
    (0xf80, 12),
    (0x780, 12),
    (0x480, 11),
    (0x080, 11),
    (0x280, 11),
    (0x3d8, 12),
    (0xfd8, 12),
    (0x7d8, 12),
    (0x9d8, 12),
    (0x1d8, 12),
    (0x004, 5),
    (0x001, 2),
    (0x002, 2),
    (0x007, 3),
    (0x003, 4),
    (0x008, 5),
];

fn meta_symbol(bs: &mut LsbBits<'_>) -> Result<usize> {
    let mut v = 0u32;
    for n in 1..=12u32 {
        v |= bs.bit()? << n.saturating_sub(1);
        if let Some(i) = META_CODES.iter().position(|&(c, l)| l == n && c == v) {
            return Ok(i);
        }
    }
    Err(bad("invalid meta-code"))
}

fn sit13_code(bs: &mut LsbBits<'_>, num: usize) -> Result<Canonical> {
    let mut lengths = vec![0i32; num];
    let mut length = 0i32;
    let mut i = 0usize;
    let set = |lengths: &mut Vec<i32>, i: usize, v: i32| -> Result<()> {
        *lengths
            .get_mut(i)
            .ok_or_else(|| bad("too many code lengths"))? = v;
        Ok(())
    };
    while i < num {
        match meta_symbol(bs)? {
            31 => length = -1,
            32 => length = length.saturating_add(1),
            33 => length = length.saturating_sub(1),
            34 => {
                if bs.bit()? == 1 {
                    set(&mut lengths, i, length)?;
                    i = i.saturating_add(1);
                }
            }
            35 => {
                let n = bs.bits(3)?.saturating_add(2);
                for _ in 0..n {
                    set(&mut lengths, i, length)?;
                    i = i.saturating_add(1);
                }
            }
            36 => {
                let n = bs.bits(6)?.saturating_add(10);
                for _ in 0..n {
                    set(&mut lengths, i, length)?;
                    i = i.saturating_add(1);
                }
            }
            v => length = i32::try_from(v).unwrap_or(0).saturating_add(1),
        }
        set(&mut lengths, i, length)?;
        i = i.saturating_add(1);
    }
    Canonical::new(&lengths)
}

const SIT13_WINDOW: usize = 1 << 16;

// ---------------------------------------------------------------------------
// 15: Arsenic

const ARITH_BITS: u32 = 26;
const ARITH_ONE: u32 = 1 << (ARITH_BITS - 1);
const ARITH_HALF: u32 = 1 << (ARITH_BITS - 2);

struct Model {
    symbols: Vec<(u32, u32)>,
    increment: u32,
    limit: u32,
    total: u32,
}

impl Model {
    fn new(first: u32, last: u32, increment: u32, limit: u32) -> Model {
        let mut m = Model {
            symbols: (first..=last).map(|s| (s, increment)).collect(),
            increment,
            limit,
            total: 0,
        };
        m.reset();
        m
    }

    fn reset(&mut self) {
        for s in &mut self.symbols {
            s.1 = self.increment;
        }
        self.total = self
            .increment
            .saturating_mul(u32::try_from(self.symbols.len()).unwrap_or(0));
    }

    fn increase(&mut self, index: usize) {
        if let Some(s) = self.symbols.get_mut(index) {
            s.1 = s.1.saturating_add(self.increment);
        }
        self.total = self.total.saturating_add(self.increment);
        if self.total > self.limit {
            self.total = 0;
            for s in &mut self.symbols {
                s.1 = s.1.saturating_add(1) >> 1;
                self.total = self.total.saturating_add(s.1);
            }
        }
    }
}

struct Arith<'a> {
    bs: MsbBits<'a>,
    range: u32,
    code: u32,
}

impl<'a> Arith<'a> {
    fn symbol(&mut self, model: &mut Model) -> Result<u32> {
        let factor = self.range.checked_div(model.total).unwrap_or(0);
        if factor == 0 {
            return Err(bad("arithmetic coder out of range"));
        }
        let frequency = self.code.checked_div(factor).unwrap_or(0);
        let mut cumulative = 0u32;
        let last = model.symbols.len().saturating_sub(1);
        let mut n = 0usize;
        while n < last {
            let f = model.symbols.get(n).map_or(0, |s| s.1);
            if cumulative.saturating_add(f) > frequency {
                break;
            }
            cumulative = cumulative.saturating_add(f);
            n = n.saturating_add(1);
        }
        let (symbol, size) = model.symbols.get(n).copied().unwrap_or((0, 0));
        let low = factor.saturating_mul(cumulative);
        self.code = self.code.wrapping_sub(low);
        if cumulative.saturating_add(size) == model.total {
            self.range = self.range.saturating_sub(low);
        } else {
            self.range = size.saturating_mul(factor);
        }
        let mut guard = 0u32;
        while self.range <= ARITH_HALF {
            guard = guard.saturating_add(1);
            if guard > 64 || self.range == 0 {
                return Err(bad("arithmetic coder out of range"));
            }
            self.range <<= 1;
            self.code = self.code << 1 | self.bs.bit_or_zero();
        }
        if self.bs.pos > self.bs.data.len().saturating_mul(8).saturating_add(64) {
            return Err(bad("compressed data ends early"));
        }
        model.increase(n);
        Ok(symbol)
    }

    fn bit_string(&mut self, model: &mut Model, bits: u32) -> Result<u32> {
        let mut v = 0u32;
        for i in 0..bits {
            if self.symbol(model)? != 0 {
                v |= 1 << i;
            }
        }
        Ok(v)
    }
}

/// Moves entry `i` of the move-to-front list to the front and returns it.
fn mtf_take(mtf: &mut [u8], i: usize) -> u8 {
    let i = i.min(mtf.len().saturating_sub(1));
    let b = mtf.get(i).copied().unwrap_or(0);
    mtf.copy_within(0..i, 1);
    if let Some(f) = mtf.first_mut() {
        *f = b;
    }
    b
}

// ---------------------------------------------------------------------------
// The small-state methods (rolled back by `Streaming`)

/// Decoder state of a method whose state is cheap to copy (all but LZW and
/// Arsenic).
#[derive(Clone)]
enum Kind {
    Stored {
        pos: usize,
    },
    Rle90 {
        pos: usize,
        last: u8,
    },
    Huffman {
        /// Bits read.
        pos: usize,
        nodes: Option<Arc<[HuffNode]>>,
    },
    Lzah(Box<Lzah>),
    Sit13(Box<Sit13>),
}

#[derive(Clone)]
struct Lzah {
    pos: usize,
    tree: Adaptive,
    window: Vec<u8>,
    r: usize,
}

#[derive(Clone)]
struct Codes {
    first: Canonical,
    second: Option<Canonical>,
    offsets: Canonical,
}

#[derive(Clone)]
struct Sit13 {
    /// Bits read, counting the first byte.
    pos: usize,
    codes: Option<Arc<Codes>>,
    use_second: bool,
}

/// Methods 0, 1, 3, 5 and 13: decode until `size` bytes are out, a bounded
/// run at a time, straight into the output (method 13 reads its window
/// back from there).
#[derive(Clone)]
struct Simple {
    kind: Kind,
    size: usize,
    produced: usize,
    done: bool,
}

impl Simple {
    fn new(method: u8, size: usize) -> Option<Simple> {
        let kind = match method {
            0 => Kind::Stored { pos: 0 },
            1 => Kind::Rle90 { pos: 0, last: 0 },
            3 => Kind::Huffman {
                pos: 0,
                nodes: None,
            },
            5 => Kind::Lzah(Box::new(Lzah {
                pos: 0,
                tree: Adaptive::new(),
                window: vec![b' '; LZAH_N],
                r: LZAH_N.saturating_sub(LZAH_F),
            })),
            13 => Kind::Sit13(Box::new(Sit13 {
                pos: 8,
                codes: None,
                use_second: false,
            })),
            _ => return None,
        };
        Some(Simple {
            kind,
            size,
            produced: 0,
            done: false,
        })
    }

    fn push(&mut self, out: &mut Vec<u8>, b: u8) {
        out.push(b);
        self.produced = self.produced.saturating_add(1);
    }

    /// Decodes one symbol (or run, or match); true once the stream has
    /// ended before `size`.
    fn unit(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>) -> Result<bool> {
        let want = self.size;
        let left = want.saturating_sub(self.produced);
        match &mut self.kind {
            Kind::Stored { pos } => {
                let data = input.get(*pos..).unwrap_or_default();
                let n = left.min(data.len()).min(1 << 16);
                if n == 0 {
                    return if eof {
                        Ok(true)
                    } else {
                        Err(bad("compressed data ends early"))
                    };
                }
                out.extend_from_slice(data.get(..n).unwrap_or_default());
                *pos = pos.saturating_add(n);
                self.produced = self.produced.saturating_add(n);
            }
            Kind::Rle90 { pos, last } => {
                let Some(&b) = input.get(*pos) else {
                    return if eof {
                        Ok(true)
                    } else {
                        Err(bad("compressed data ends early"))
                    };
                };
                *pos = pos.saturating_add(1);
                if b != 0x90 {
                    *last = b;
                    self.push(out, b);
                    return Ok(false);
                }
                let n = *input
                    .get(*pos)
                    .ok_or_else(|| bad("RLE escape at the end"))?;
                *pos = pos.saturating_add(1);
                if n == 0 {
                    *last = 0x90;
                    self.push(out, 0x90);
                } else {
                    let more = usize::from(n.saturating_sub(1)).min(left);
                    out.extend(std::iter::repeat_n(*last, more));
                    self.produced = self.produced.saturating_add(more);
                }
            }
            Kind::Huffman { pos, nodes } => {
                let mut bs = MsbBits {
                    data: input,
                    pos: *pos,
                };
                let tree = match nodes {
                    Some(tree) => tree.clone(),
                    None => {
                        let mut parsed = Vec::new();
                        parse_tree(&mut bs, &mut parsed, 0)?;
                        let tree: Arc<[HuffNode]> = parsed.into();
                        *nodes = Some(tree.clone());
                        *pos = bs.pos;
                        return Ok(false);
                    }
                };
                let mut at = 0usize;
                let b = loop {
                    match tree.get(at) {
                        Some(HuffNode::Leaf(v)) => break *v,
                        Some(HuffNode::Branch(z, o)) => at = if bs.bit()? == 0 { *z } else { *o },
                        None => return Err(bad("bad Huffman tree")),
                    }
                };
                *pos = bs.pos;
                self.push(out, b);
            }
            Kind::Lzah(st) => {
                let mut bs = MsbBits {
                    data: input,
                    pos: st.pos,
                };
                let c = st.tree.decode_char(&mut bs)?;
                if c < 256 {
                    let b = u8::try_from(c).unwrap_or(0);
                    out.push(b);
                    self.produced = self.produced.saturating_add(1);
                    if let Some(slot) = st.window.get_mut(st.r) {
                        *slot = b;
                    }
                    st.r = st.r.saturating_add(1) & (LZAH_N - 1);
                } else {
                    let pos = lzah_position(&mut bs)?;
                    let start = st.r.wrapping_sub(pos).wrapping_sub(1) & (LZAH_N - 1);
                    let len = c.saturating_sub(255).saturating_add(LZAH_THRESHOLD);
                    for k in 0..len.min(left) {
                        let b = st
                            .window
                            .get(start.saturating_add(k) & (LZAH_N - 1))
                            .copied()
                            .unwrap_or(0);
                        out.push(b);
                        if let Some(slot) = st.window.get_mut(st.r) {
                            *slot = b;
                        }
                        st.r = st.r.saturating_add(1) & (LZAH_N - 1);
                    }
                    self.produced = self.produced.saturating_add(len.min(left));
                }
                st.pos = bs.pos;
            }
            Kind::Sit13(st) => {
                let mut bs = LsbBits {
                    data: input,
                    pos: st.pos,
                };
                let codes = match &st.codes {
                    Some(codes) => codes.clone(),
                    None => {
                        st.codes = Some(Arc::new(sit13_codes(input, &mut bs)?));
                        st.pos = bs.pos;
                        return Ok(false);
                    }
                };
                let code = match (&codes.second, st.use_second) {
                    (Some(s), true) => s,
                    _ => &codes.first,
                };
                let val = code.read(&mut bs)?;
                if val < 0x100 {
                    st.use_second = false;
                    st.pos = bs.pos;
                    self.push(out, u8::try_from(val).unwrap_or(0));
                    return Ok(false);
                }
                st.use_second = true;
                let len = match val {
                    0x100..=0x13d => usize::from(val).saturating_sub(0x100).saturating_add(3),
                    0x13e => to_usize(u64::from(bs.bits(10)?)).saturating_add(65),
                    0x13f => to_usize(u64::from(bs.bits(15)?)).saturating_add(65),
                    _ => {
                        st.pos = bs.pos;
                        return Ok(true);
                    }
                };
                let bitlength = u32::from(codes.offsets.read(&mut bs)?);
                let offset = match bitlength {
                    0 => 1usize,
                    1 => 2,
                    b => {
                        let b = b.saturating_sub(1);
                        (1usize << b)
                            .saturating_add(to_usize(u64::from(bs.bits(b)?)))
                            .saturating_add(1)
                    }
                };
                if offset > self.produced || offset > SIT13_WINDOW || offset > out.len() {
                    return Err(bad("match distance before the start of the data"));
                }
                let start = out.len().saturating_sub(offset);
                let n = len.min(left);
                for k in 0..n {
                    let b = out.get(start.saturating_add(k)).copied().unwrap_or(0);
                    out.push(b);
                }
                self.produced = self.produced.saturating_add(n);
                st.pos = bs.pos;
            }
        }
        Ok(false)
    }

    /// Heap bytes a copy holds: the trees and codes (shared ones counted
    /// too: a copy may outlive the decoder), and method 5's own window.
    fn held_bytes(&self) -> usize {
        let word = std::mem::size_of::<usize>();
        let canonical = |c: &Canonical| {
            c.symbols
                .capacity()
                .saturating_mul(2)
                .saturating_add(c.counts.capacity().saturating_mul(4))
        };
        match &self.kind {
            Kind::Stored { .. } | Kind::Rle90 { .. } => 0,
            Kind::Huffman { nodes, .. } => nodes.as_ref().map_or(0, |n| {
                n.len().saturating_mul(std::mem::size_of::<HuffNode>())
            }),
            Kind::Lzah(st) => std::mem::size_of::<Lzah>()
                .saturating_add(st.tree.freq.capacity().saturating_mul(4))
                .saturating_add(st.tree.prnt.capacity().saturating_mul(word))
                .saturating_add(st.tree.son.capacity().saturating_mul(word))
                .saturating_add(st.window.capacity()),
            Kind::Sit13(st) => {
                std::mem::size_of::<Sit13>().saturating_add(st.codes.as_ref().map_or(0, |c| {
                    std::mem::size_of::<Codes>()
                        .saturating_add(canonical(&c.first))
                        .saturating_add(c.second.as_ref().map_or(0, canonical))
                        .saturating_add(canonical(&c.offsets))
                }))
            }
        }
    }

    /// Bits read so far.
    fn bit_pos(&self) -> usize {
        match &self.kind {
            Kind::Stored { pos } | Kind::Rle90 { pos, .. } => pos.saturating_mul(8),
            Kind::Huffman { pos, .. } => *pos,
            Kind::Lzah(st) => st.pos,
            Kind::Sit13(st) => st.pos,
        }
    }
}

/// Method 13's header: the code set byte and the codes.
fn sit13_codes(input: &[u8], bs: &mut LsbBits<'_>) -> Result<Codes> {
    let first_byte = *input.first().ok_or_else(|| bad("empty method 13 stream"))?;
    if first_byte >> 4 != 0 {
        return Err(Diagnostic::unsupported(format!(
            "StuffIt method 13 built-in code set {}",
            first_byte >> 4
        )));
    }
    let first = sit13_code(bs, 321)?;
    let second = if first_byte & 0x08 != 0 {
        None
    } else {
        Some(sit13_code(bs, 321)?)
    };
    let offsets = sit13_code(bs, usize::from(first_byte & 7).saturating_add(10))?;
    Ok(Codes {
        first,
        second,
        offsets,
    })
}

impl Decode for Simple {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        _limit: usize,
    ) -> Result<Step> {
        let start = self.produced;
        // Units that produce nothing (a tree, a code set) are bounded too.
        let mut units = 0usize;
        loop {
            if self.done || self.produced >= self.size {
                self.done = true;
                return Ok(Step::Done);
            }
            if self.produced.saturating_sub(start) >= step || units >= STEP_UNITS {
                return Ok(Step::More);
            }
            units = units.saturating_add(1);
            if self.unit(input, eof, out)? {
                self.done = true;
                return Ok(Step::Done);
            }
        }
    }

    fn consumed(&self) -> usize {
        self.bit_pos() / 8
    }

    fn releasable_input(&self) -> usize {
        self.bit_pos() / 8
    }

    fn release_input(&mut self, n: usize) {
        let bits = n.saturating_mul(8);
        match &mut self.kind {
            Kind::Stored { pos } | Kind::Rle90 { pos, .. } => *pos = pos.saturating_sub(n),
            Kind::Huffman { pos, .. } => *pos = pos.saturating_sub(bits),
            Kind::Lzah(st) => st.pos = st.pos.saturating_sub(bits),
            Kind::Sit13(st) => st.pos = st.pos.saturating_sub(bits),
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        match self.kind {
            Kind::Sit13(_) => out_len.saturating_sub(SIT13_WINDOW),
            _ => out_len,
        }
    }
}

/// Units (symbols, runs, matches) per step at most, for steps that
/// produce little.
const STEP_UNITS: usize = 1 << 16;

// ---------------------------------------------------------------------------
// Arsenic, resumable

/// Input an Arsenic unit (a block's start or end, one selector with its
/// zero run and symbol) may read at most: 61 symbols of at most 64 bits.
const ARSENIC_UNIT_BITS: usize = 8192;

enum Phase {
    /// The code register and the stream header.
    Start,
    /// A block's flags and BWT index.
    Block,
    /// The block's symbols (and, after the last, the block's end).
    Symbols,
    /// A zero run: `left` more `byte`s, then the symbol that ended it
    /// (`None`: the block's end).
    Fill {
        byte: u8,
        left: usize,
        then: Option<u32>,
    },
    /// The block's end, after a zero run.
    EndBlock,
    /// Counting the block's bytes, from this index.
    Count(usize),
    /// Building the inverse transform, from this index.
    Transform(usize),
    /// Walking the transform, this many bytes done.
    Walk(usize),
    Finished,
}

/// What an Arsenic step ended with.
enum Progress {
    More,
    NeedInput,
    Done,
}

/// Arsenic, decoded a bounded amount at a time with its blocks (up to
/// 16 MiB, and their transform) kept, never copied: before reading, a unit
/// waits until [`ARSENIC_UNIT_BITS`] are buffered (or the input has ended),
/// so it never runs out of input midway and nothing is rolled back.
struct Arsenic {
    pos: usize,
    range: u32,
    code: u32,
    initial: Model,
    selector: Model,
    mtf_models: [Model; 7],
    phase: Phase,
    block_bits: u32,
    block_size: usize,
    end: bool,
    mtf: Vec<u8>,
    randomized: bool,
    primary: usize,
    block: Vec<u8>,
    counts: [usize; 256],
    cumulative: [usize; 256],
    transform: Vec<u32>,
    index: usize,
    run: u32,
    last: u8,
    repeat_next: bool,
    stored_crc: Option<u32>,
    /// Running CRC-32 register of all the output.
    crc: u32,
    crc_ok: bool,
    /// Bytes written to the output (at most the fork's size; the rest is
    /// decoded and checked, not kept).
    written: usize,
    size: usize,
}

impl Arsenic {
    fn new(size: usize) -> Arsenic {
        Arsenic {
            pos: 0,
            range: ARITH_ONE,
            code: 0,
            initial: Model::new(0, 1, 1, 256),
            selector: Model::new(0, 10, 8, 1024),
            mtf_models: [
                Model::new(2, 3, 8, 1024),
                Model::new(4, 7, 4, 1024),
                Model::new(8, 15, 4, 1024),
                Model::new(16, 31, 4, 1024),
                Model::new(32, 63, 2, 1024),
                Model::new(64, 127, 2, 1024),
                Model::new(128, 255, 1, 1024),
            ],
            phase: Phase::Start,
            block_bits: 0,
            block_size: 0,
            end: false,
            mtf: Vec::new(),
            randomized: false,
            primary: 0,
            block: Vec::new(),
            counts: [0; 256],
            cumulative: [0; 256],
            transform: Vec::new(),
            index: 0,
            run: 0,
            last: 0,
            repeat_next: false,
            stored_crc: None,
            crc: 0xffff_ffff,
            crc_ok: true,
            written: 0,
            size,
        }
    }

    fn emit(&mut self, out: &mut Vec<u8>, b: u8, n: usize) {
        let keep = n.min(self.size.saturating_sub(self.written));
        out.extend(std::iter::repeat_n(b, keep));
        self.written = self.written.saturating_add(keep);
        let run = [b; 256];
        let mut left = n;
        while left > 0 {
            let k = left.min(run.len());
            self.crc = crate::codec::crc::crc32_update(self.crc, run.get(..k).unwrap_or_default());
            left = left.saturating_sub(k);
        }
    }

    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
    ) -> Result<Progress> {
        let mut ac = Arith {
            bs: MsbBits {
                data: input,
                pos: self.pos,
            },
            range: self.range,
            code: self.code,
        };
        let result = self.run(&mut ac, eof, out, step);
        self.pos = ac.bs.pos;
        self.range = ac.range;
        self.code = ac.code;
        result
    }

    fn run(
        &mut self,
        ac: &mut Arith<'_>,
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
    ) -> Result<Progress> {
        // Work units: an output byte or a transform entry 1, a symbol 16.
        let budget = step.max(256).saturating_mul(4);
        let mut work = 0usize;
        loop {
            if work >= budget {
                return Ok(Progress::More);
            }
            let reads = matches!(
                self.phase,
                Phase::Start | Phase::Block | Phase::Symbols | Phase::EndBlock
            );
            if reads
                && !eof
                && ac.bs.data.len().saturating_mul(8) < ac.bs.pos.saturating_add(ARSENIC_UNIT_BITS)
            {
                return Ok(Progress::NeedInput);
            }
            match self.phase {
                Phase::Start => {
                    for _ in 0..ARITH_BITS {
                        ac.code = ac.code << 1 | ac.bs.bit_or_zero();
                    }
                    if ac.bit_string(&mut self.initial, 8)? != u32::from(b'A')
                        || ac.bit_string(&mut self.initial, 8)? != u32::from(b's')
                    {
                        return Err(bad("not an Arsenic stream"));
                    }
                    self.block_bits = ac.bit_string(&mut self.initial, 4)?.saturating_add(9);
                    self.block_size = 1usize << self.block_bits;
                    self.end = ac.symbol(&mut self.initial)? != 0;
                    self.phase = if self.end {
                        Phase::Finished
                    } else {
                        Phase::Block
                    };
                    work = work.saturating_add(64);
                }
                Phase::Block => {
                    self.mtf = (0..=255u8).collect();
                    self.randomized = ac.symbol(&mut self.initial)? != 0;
                    self.primary = to_usize(u64::from(
                        ac.bit_string(&mut self.initial, self.block_bits)?,
                    ));
                    self.block.clear();
                    self.phase = Phase::Symbols;
                    work = work.saturating_add(64);
                }
                Phase::Symbols => {
                    work = work.saturating_add(16);
                    let mut sel = ac.symbol(&mut self.selector)?;
                    let mut zeros = 0usize;
                    if sel < 2 {
                        let mut state = 1usize;
                        while sel < 2 {
                            zeros = zeros.saturating_add(if sel == 0 { state } else { state << 1 });
                            if zeros > self.block_size {
                                return Err(bad("zero run beyond the block"));
                            }
                            state = state.saturating_mul(2);
                            sel = ac.symbol(&mut self.selector)?;
                        }
                        if self.block.len().saturating_add(zeros) > self.block_size {
                            return Err(bad("zero run beyond the block"));
                        }
                    }
                    // The symbol that ends the run, read now so the run can
                    // be filled across steps without reading.
                    let symbol = match sel {
                        10 => None,
                        2 => Some(1),
                        s => {
                            let model = self
                                .mtf_models
                                .get_mut(to_usize(u64::from(s.saturating_sub(3))))
                                .ok_or_else(|| bad("bad selector"))?;
                            Some(ac.symbol(model)?)
                        }
                    };
                    if zeros > 0 {
                        let byte = mtf_take(&mut self.mtf, 0);
                        self.phase = Phase::Fill {
                            byte,
                            left: zeros,
                            then: symbol,
                        };
                        continue;
                    }
                    match symbol {
                        None => self.end_block(ac)?,
                        Some(s) => self.push_symbol(s)?,
                    }
                }
                Phase::Fill { byte, left, then } => {
                    // A byte filled is an eighth of a unit.
                    let room = budget.saturating_sub(work).saturating_mul(8).max(1);
                    let n = left.min(room);
                    self.block.extend(std::iter::repeat_n(byte, n));
                    work = work.saturating_add(n / 8).saturating_add(1);
                    let left = left.saturating_sub(n);
                    if left > 0 {
                        self.phase = Phase::Fill { byte, left, then };
                    } else if let Some(s) = then {
                        self.phase = Phase::Symbols;
                        self.push_symbol(s)?;
                    } else {
                        self.phase = Phase::EndBlock;
                    }
                }
                Phase::EndBlock => self.end_block(ac)?,
                Phase::Count(from) => {
                    let to = from
                        .saturating_add(budget.saturating_sub(work))
                        .min(self.block.len());
                    for &b in self.block.get(from..to).unwrap_or_default() {
                        if let Some(c) = self.counts.get_mut(usize::from(b)) {
                            *c = c.saturating_add(1);
                        }
                    }
                    // The transform grows alongside (zeroed a piece at a
                    // time; every entry is set when it is built).
                    self.transform.resize(to, 0);
                    work = work
                        .saturating_add(to.saturating_sub(from).saturating_mul(2))
                        .saturating_add(1);
                    if to < self.block.len() {
                        self.phase = Phase::Count(to);
                        continue;
                    }
                    let mut total = 0usize;
                    for (c, n) in self.cumulative.iter_mut().zip(self.counts.iter_mut()) {
                        *c = total;
                        total = total.saturating_add(*n);
                        *n = 0;
                    }
                    self.phase = Phase::Transform(0);
                }
                Phase::Transform(from) => {
                    let to = from
                        .saturating_add(budget.saturating_sub(work))
                        .min(self.block.len());
                    for i in from..to {
                        let k = usize::from(self.block.get(i).copied().unwrap_or(0));
                        let at = self
                            .cumulative
                            .get(k)
                            .copied()
                            .unwrap_or(0)
                            .saturating_add(self.counts.get(k).copied().unwrap_or(0));
                        if let Some(slot) = self.transform.get_mut(at) {
                            *slot = u32::try_from(i).unwrap_or(u32::MAX);
                        }
                        if let Some(c) = self.counts.get_mut(k) {
                            *c = c.saturating_add(1);
                        }
                    }
                    work = work
                        .saturating_add(to.saturating_sub(from))
                        .saturating_add(1);
                    self.phase = if to < self.block.len() {
                        Phase::Transform(to)
                    } else {
                        self.index = self.primary;
                        self.run = 0;
                        self.last = 0;
                        self.repeat_next = false;
                        Phase::Walk(0)
                    };
                }
                Phase::Walk(from) => {
                    // Walk it, undoing the final run-length stage.
                    let mut i = from;
                    while i < self.block.len() && work < budget {
                        self.index = self
                            .transform
                            .get(self.index)
                            .map_or(0, |&i| to_usize(u64::from(i)));
                        let b = self.block.get(self.index).copied().unwrap_or(0);
                        let n = if self.repeat_next {
                            self.repeat_next = false;
                            self.run = 0;
                            self.emit(out, self.last, usize::from(b));
                            usize::from(b)
                        } else {
                            if self.run > 0 && b == self.last {
                                self.run = self.run.saturating_add(1);
                            } else {
                                self.run = 1;
                                self.last = b;
                            }
                            self.emit(out, b, 1);
                            if self.run == 4 {
                                self.repeat_next = true;
                            }
                            1
                        };
                        work = work.saturating_add(n).saturating_add(2);
                        i = i.saturating_add(1);
                    }
                    let to = i;
                    self.phase = if to < self.block.len() {
                        Phase::Walk(to)
                    } else if self.end {
                        self.crc_ok = self.stored_crc.is_none_or(|crc| crc == !self.crc);
                        Phase::Finished
                    } else {
                        Phase::Block
                    };
                }
                Phase::Finished => return Ok(Progress::Done),
            }
        }
    }

    /// The end of a block's symbols: checks, model resets, the end flag
    /// and CRC.
    fn end_block(&mut self, ac: &mut Arith<'_>) -> Result<()> {
        if self.primary >= self.block.len() {
            return Err(bad("BWT index out of range"));
        }
        self.selector.reset();
        for m in &mut self.mtf_models {
            m.reset();
        }
        if ac.symbol(&mut self.initial)? != 0 {
            self.stored_crc = Some(ac.bit_string(&mut self.initial, 32)?);
            self.end = true;
        }
        if self.randomized {
            return Err(Diagnostic::unsupported("randomized Arsenic blocks"));
        }
        self.counts = [0; 256];
        self.transform.clear();
        self.phase = Phase::Count(0);
        Ok(())
    }

    /// Appends the byte of move-to-front `symbol` to the block.
    fn push_symbol(&mut self, symbol: u32) -> Result<()> {
        if self.block.len() >= self.block_size {
            return Err(bad("block overflow"));
        }
        let b = mtf_take(&mut self.mtf, to_usize(u64::from(symbol)));
        self.block.push(b);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The decoder

enum Method {
    Simple(Streaming<Simple>),
    /// LZW decodes to the end of its input, past the fork's length: its
    /// output goes through `scratch`, cut at the length.
    Lzw {
        lzw: UnixCompress,
        scratch: Vec<u8>,
        written: usize,
    },
    Arsenic(Box<Arsenic>),
    Unsupported,
}

/// The decoder for [`Params`]: the fork, a bounded run at a time, input
/// released as it is read.
pub struct Decoder {
    params: Params,
    method: Method,
    /// Running CRC-16 (ARC) of the output.
    crc16: u64,
    warning: Option<Diagnostic>,
    consumed: usize,
    done: bool,
}

impl Decoder {
    pub fn new(params: Params) -> Self {
        let size = to_usize(params.size);
        let method = match params.method {
            2 => match UnixCompress::raw(0x8e) {
                Ok(lzw) => Method::Lzw {
                    lzw,
                    scratch: Vec::new(),
                    written: 0,
                },
                Err(_) => Method::Unsupported,
            },
            15 => Method::Arsenic(Box::new(Arsenic::new(size))),
            m => Simple::new(m, size).map_or(Method::Unsupported, |s| Method::Simple(Streaming(s))),
        };
        Decoder {
            params,
            method,
            crc16: 0,
            warning: None,
            consumed: 0,
            done: false,
        }
    }

    /// One step of the method; `Done` once its stream has ended.
    fn inner(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let size = to_usize(self.params.size);
        match &mut self.method {
            Method::Simple(s) => {
                let status = s.decode(input, eof, out, step, limit)?;
                self.consumed = s.consumed();
                Ok(status)
            }
            Method::Lzw {
                lzw,
                scratch,
                written,
            } => {
                let status = lzw.decode(input, eof, scratch, step, usize::MAX)?;
                let keep = scratch.len().min(size.saturating_sub(*written));
                out.extend_from_slice(scratch.get(..keep).unwrap_or_default());
                *written = written.saturating_add(keep);
                scratch.clear();
                self.consumed = lzw.consumed();
                Ok(status)
            }
            Method::Arsenic(a) => {
                let progress = a.decode(input, eof, out, step)?;
                self.consumed = a.pos / 8;
                Ok(match progress {
                    Progress::More => Status::More,
                    Progress::NeedInput => Status::NeedInput,
                    Progress::Done => {
                        if !a.crc_ok {
                            self.warning = Some(Diagnostic::warning("Arsenic CRC-32 mismatch"));
                        }
                        Status::Done
                    }
                })
            }
            Method::Unsupported => Err(Diagnostic::unsupported(format!(
                "StuffIt method {}",
                self.params.method
            ))),
        }
    }
}

impl pipeline::Decoder for Decoder {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        if self.done {
            return Ok(Status::Done);
        }
        let mark = out.len();
        let status = self.inner(input, eof, out, step, limit)?;
        let fresh = out.get(mark..).unwrap_or_default();
        self.crc16 = crate::codec::crc::CRC16_ARC.update(self.crc16, fresh);
        if out.len() > limit {
            return Err(Diagnostic::output_limit(limit));
        }
        match status {
            // The stream has ended; the rest of the input is padding,
            // consumed with it once it is all in.
            Status::Done if eof => {
                self.consumed = input.len();
                self.done = true;
                if let Some(crc) = self.params.crc
                    && u64::from(crc) != self.crc16
                {
                    self.warning = Some(Diagnostic::warning("StuffIt fork CRC-16 mismatch"));
                }
                Ok(Status::Done)
            }
            Status::Done if out.len() > mark => Ok(Status::More),
            Status::Done => Ok(Status::NeedInput),
            status => Ok(status),
        }
    }

    fn consumed(&self) -> usize {
        self.consumed
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        self.warning.clone()
    }

    fn releasable_input(&self) -> usize {
        match &self.method {
            _ if self.done => self.consumed,
            Method::Simple(s) => s.releasable_input(),
            Method::Lzw { lzw, .. } => lzw.releasable_input(),
            Method::Arsenic(a) => a.pos / 8,
            Method::Unsupported => 0,
        }
    }

    fn release_input(&mut self, n: usize) {
        self.consumed = self.consumed.saturating_sub(n);
        if self.done {
            return;
        }
        match &mut self.method {
            Method::Simple(s) => s.release_input(n),
            Method::Lzw { lzw, .. } => lzw.release_input(n),
            Method::Arsenic(a) => a.pos = a.pos.saturating_sub(n.saturating_mul(8)),
            Method::Unsupported => {}
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        match &self.method {
            Method::Simple(s) => s.releasable_output(out_len),
            _ => out_len,
        }
    }

    /// The methods but Arsenic (whose models and BWT block, up to 16 MiB,
    /// are not counted here): their tables and, for method 13, the 64 KiB
    /// window in `out`; method 2 is `compress` with its string table.
    fn checkpoint(&self) -> Option<Box<dyn pipeline::Decoder>> {
        let method = match &self.method {
            Method::Simple(s) => Method::Simple(s.clone()),
            Method::Lzw {
                lzw,
                scratch,
                written,
            } => Method::Lzw {
                lzw: lzw.clone(),
                scratch: scratch.clone(),
                written: *written,
            },
            Method::Arsenic(_) | Method::Unsupported => return None,
        };
        Some(Box::new(Decoder {
            params: self.params,
            method,
            crc16: self.crc16,
            warning: self.warning.clone(),
            consumed: self.consumed,
            done: self.done,
        }))
    }

    fn state_size(&self) -> usize {
        let method = match &self.method {
            Method::Simple(s) => s.0.held_bytes(),
            Method::Lzw { lzw, scratch, .. } => pipeline::Decoder::state_size(lzw)
                .saturating_sub(std::mem::size_of::<UnixCompress>())
                .saturating_add(scratch.len()),
            Method::Arsenic(_) | Method::Unsupported => 0,
        };
        let warning = self.warning.as_ref().map_or(0, |w| w.message.capacity());
        std::mem::size_of::<Self>()
            .saturating_add(method)
            .saturating_add(warning)
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
    use crate::bytes::{u16_be, u32_be};
    use crate::codec::crc::crc16_arc;

    /// Decodes a whole fork; the warning is a failed internal check
    /// (Arsenic's CRC-32).
    fn decode(
        method: u8,
        input: &[u8],
        size: usize,
        limit: usize,
    ) -> Result<(Vec<u8>, Option<Diagnostic>)> {
        let mut d = Decoder::new(Params {
            method,
            size: size as u64,
            crc: None,
        });
        let out = pipeline::decode_all(&mut d, input, limit)?;
        let warning = pipeline::Decoder::warning(&d, &out);
        Ok((out, warning))
    }

    // The fixtures were written by tests/data/stuffit/make_sit.py, whose
    // encoders share this module's understanding of the formats (except
    // method 2, which is `compress -b 14`).

    #[test]
    fn classic_forks() {
        let archive = include_bytes!("../../../../tests/fixtures/synthetic/stuffit/methods.sit");
        let mut at = 22usize;
        let mut methods = Vec::new();
        while at + 112 <= archive.len() {
            let h = &archive[at..at + 112];
            at += 112;
            if h[0] >= 32 {
                continue;
            }
            let len = |o| u32_be(h, o).unwrap() as usize;
            let (rlen, dlen, rpack, dpack) = (len(84), len(88), len(92), len(96));
            for (method, size, packed, crc) in [
                (h[0], rlen, rpack, u16_be(h, 100).unwrap()),
                (h[1], dlen, dpack, u16_be(h, 102).unwrap()),
            ] {
                if packed > 0 {
                    let (out, warning) =
                        decode(method, &archive[at..at + packed], size, 1 << 20).unwrap();
                    assert!(warning.is_none(), "method {method}");
                    assert_eq!(out.len(), size, "method {method}");
                    assert_eq!(crc16_arc(&out), crc, "method {method}");
                    methods.push(method);
                }
                at += packed;
            }
        }
        methods.sort_unstable();
        methods.dedup();
        assert_eq!(methods, [0, 1, 2, 3, 5, 13, 15]);
    }

    /// Every fork of `methods.sit` but Arsenic's (not checkpointed).
    #[test]
    fn checkpoints_resume_mid_fork() {
        let archive = include_bytes!("../../../../tests/fixtures/synthetic/stuffit/methods.sit");
        let mut at = 22usize;
        let mut methods = Vec::new();
        while at + 112 <= archive.len() {
            let h = &archive[at..at + 112];
            at += 112;
            if h[0] >= 32 {
                continue;
            }
            let len = |o| u32_be(h, o).unwrap() as u64;
            for (method, size, packed, crc) in [
                (h[0], len(84), len(92), u16_be(h, 100).unwrap()),
                (h[1], len(88), len(96), u16_be(h, 102).unwrap()),
            ] {
                let input = &archive[at..at + packed as usize];
                at += packed as usize;
                if packed == 0 {
                    continue;
                }
                let params = Params {
                    method,
                    size,
                    crc: Some(crc),
                };
                let (checked, largest) =
                    pipeline::verify_checkpoints(|| Box::new(Decoder::new(params)), input, 200, 1)
                        .unwrap();
                if method == 15 {
                    assert_eq!(checked, 0);
                } else {
                    // (Stored forks are copied 64 KiB at a time.)
                    assert!(checked > 0 || size < 1000 || method == 0, "method {method}");
                    assert!(largest < 256 * 1024, "method {method}: {largest}");
                    methods.push(method);
                }
            }
        }
        methods.sort_unstable();
        methods.dedup();
        assert_eq!(methods, [0, 1, 2, 3, 5, 13]);
    }

    #[test]
    fn rle90_escapes() {
        let (out, _) = decode(1, &[b'a', 0x90, 4, 0x90, 0, b'b'], 6, 100).unwrap();
        assert_eq!(out, b"aaaa\x90b");
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for method in [1u8, 2, 3, 5, 13, 15] {
            for seed in 0..48u8 {
                let data: Vec<u8> = (0..96u8)
                    .map(|i| i.wrapping_mul(seed | 1).wrapping_add(seed).rotate_left(3))
                    .collect();
                let _ = decode(method, &data, 4000, 1 << 16);
            }
        }
    }
}
