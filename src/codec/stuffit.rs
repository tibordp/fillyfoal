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
//! is checked where the archive gives one.

use crate::bytes::to_usize;
use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("StuffIt: {what}"))
}

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
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

/// Whether [`decode`] handles `method`.
pub fn supported(method: u8) -> bool {
    matches!(method, 0 | 1 | 2 | 3 | 5 | 13 | 15)
}

/// Decodes a whole fork; the warning is a failed internal check (Arsenic's
/// CRC-32).
pub fn decode(
    method: u8,
    input: &[u8],
    size: usize,
    limit: usize,
) -> Result<(Vec<u8>, Option<Diagnostic>)> {
    let want = size.min(limit);
    let mut warning = None;
    let mut out = match method {
        0 => input
            .get(..size.min(input.len()))
            .unwrap_or_default()
            .to_vec(),
        1 => rle90(input, want)?,
        2 => crate::codec::unixz::decode_raw(0x8e, input, limit)?,
        3 => huffman(input, want)?,
        5 => lzah(input, want)?,
        13 => sit13(input, want)?,
        15 => {
            let (out, ok) = arsenic(input, limit)?;
            if !ok {
                warning = Some(Diagnostic::warning("Arsenic CRC-32 mismatch"));
            }
            out
        }
        _ => return Err(Diagnostic::unsupported(format!("StuffIt method {method}"))),
    };
    if size > limit && out.len() >= limit {
        return Err(too_big(limit));
    }
    out.truncate(size);
    Ok((out, warning))
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
    fn new(data: &'a [u8]) -> Self {
        MsbBits { data, pos: 0 }
    }

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
    fn new(data: &'a [u8]) -> Self {
        LsbBits { data, pos: 0 }
    }

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
// 1: RLE90

fn rle90(input: &[u8], want: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut last = 0u8;
    let mut i = 0usize;
    while out.len() < want {
        let Some(&b) = input.get(i) else { break };
        i = i.saturating_add(1);
        if b != 0x90 {
            last = b;
            out.push(b);
            continue;
        }
        let n = *input.get(i).ok_or_else(|| bad("RLE escape at the end"))?;
        i = i.saturating_add(1);
        if n == 0 {
            last = 0x90;
            out.push(0x90);
        } else {
            let more = usize::from(n.saturating_sub(1)).min(want.saturating_sub(out.len()));
            out.extend(std::iter::repeat_n(last, more));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 3: Huffman

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

fn huffman(input: &[u8], want: usize) -> Result<Vec<u8>> {
    let mut bs = MsbBits::new(input);
    let mut nodes = Vec::new();
    parse_tree(&mut bs, &mut nodes, 0)?;
    let mut out = Vec::new();
    while out.len() < want {
        let mut at = 0usize;
        loop {
            match nodes.get(at) {
                Some(HuffNode::Leaf(v)) => {
                    out.push(*v);
                    break;
                }
                Some(HuffNode::Branch(z, o)) => at = if bs.bit()? == 0 { *z } else { *o },
                None => return Err(bad("bad Huffman tree")),
            }
        }
    }
    Ok(out)
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

fn lzah(input: &[u8], want: usize) -> Result<Vec<u8>> {
    let mut bs = MsbBits::new(input);
    let mut tree = Adaptive::new();
    let mut window = vec![b' '; LZAH_N];
    let mut r = LZAH_N.saturating_sub(LZAH_F);
    let mut out = Vec::new();
    while out.len() < want {
        let c = tree.decode_char(&mut bs)?;
        if c < 256 {
            let b = u8::try_from(c).unwrap_or(0);
            out.push(b);
            if let Some(slot) = window.get_mut(r) {
                *slot = b;
            }
            r = r.saturating_add(1) & (LZAH_N - 1);
        } else {
            let pos = lzah_position(&mut bs)?;
            let start = r.wrapping_sub(pos).wrapping_sub(1) & (LZAH_N - 1);
            let len = c.saturating_sub(255).saturating_add(LZAH_THRESHOLD);
            for k in 0..len {
                if out.len() >= want {
                    break;
                }
                let b = window
                    .get(start.saturating_add(k) & (LZAH_N - 1))
                    .copied()
                    .unwrap_or(0);
                out.push(b);
                if let Some(slot) = window.get_mut(r) {
                    *slot = b;
                }
                r = r.saturating_add(1) & (LZAH_N - 1);
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 13

/// A canonical prefix code (shortest codes are all zeros), decoded a bit at
/// a time with the first bit read as the code's most significant.
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

fn sit13(input: &[u8], want: usize) -> Result<Vec<u8>> {
    let first_byte = *input.first().ok_or_else(|| bad("empty method 13 stream"))?;
    let mut bs = LsbBits::new(input.get(1..).unwrap_or_default());
    if first_byte >> 4 != 0 {
        return Err(Diagnostic::unsupported(format!(
            "StuffIt method 13 built-in code set {}",
            first_byte >> 4
        )));
    }
    let first = sit13_code(&mut bs, 321)?;
    let second = if first_byte & 0x08 != 0 {
        None
    } else {
        Some(sit13_code(&mut bs, 321)?)
    };
    let offsets = sit13_code(&mut bs, usize::from(first_byte & 7).saturating_add(10))?;
    let mut out: Vec<u8> = Vec::new();
    let mut use_second = false;
    while out.len() < want {
        let code = match (&second, use_second) {
            (Some(s), true) => s,
            _ => &first,
        };
        let val = code.read(&mut bs)?;
        if val < 0x100 {
            use_second = false;
            out.push(u8::try_from(val).unwrap_or(0));
            continue;
        }
        use_second = true;
        let len = match val {
            0x100..=0x13d => usize::from(val).saturating_sub(0x100).saturating_add(3),
            0x13e => to_usize(u64::from(bs.bits(10)?)).saturating_add(65),
            0x13f => to_usize(u64::from(bs.bits(15)?)).saturating_add(65),
            _ => break,
        };
        let bitlength = u32::from(offsets.read(&mut bs)?);
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
        if offset > out.len() || offset > SIT13_WINDOW {
            return Err(bad("match distance before the start of the data"));
        }
        let start = out.len().saturating_sub(offset);
        for k in 0..len.min(want.saturating_sub(out.len())) {
            let b = out.get(start.saturating_add(k)).copied().unwrap_or(0);
            out.push(b);
        }
    }
    Ok(out)
}

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
    fn new(data: &'a [u8]) -> Self {
        let mut bs = MsbBits::new(data);
        let mut code = 0u32;
        for _ in 0..ARITH_BITS {
            code = code << 1 | bs.bit_or_zero();
        }
        Arith {
            bs,
            range: ARITH_ONE,
            code,
        }
    }

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

/// Decodes an Arsenic stream; the flag says whether its CRC-32 matched.
fn arsenic(input: &[u8], limit: usize) -> Result<(Vec<u8>, bool)> {
    let mut ac = Arith::new(input);
    let mut initial = Model::new(0, 1, 1, 256);
    let mut selector = Model::new(0, 10, 8, 1024);
    let mut mtf_models = [
        Model::new(2, 3, 8, 1024),
        Model::new(4, 7, 4, 1024),
        Model::new(8, 15, 4, 1024),
        Model::new(16, 31, 4, 1024),
        Model::new(32, 63, 2, 1024),
        Model::new(64, 127, 2, 1024),
        Model::new(128, 255, 1, 1024),
    ];
    if ac.bit_string(&mut initial, 8)? != u32::from(b'A')
        || ac.bit_string(&mut initial, 8)? != u32::from(b's')
    {
        return Err(bad("not an Arsenic stream"));
    }
    let block_bits = ac.bit_string(&mut initial, 4)?.saturating_add(9);
    let block_size = 1usize << block_bits;
    let mut end = ac.symbol(&mut initial)? != 0;
    let mut out: Vec<u8> = Vec::new();
    let mut stored_crc = None;
    while !end {
        // One block.
        let mut mtf: Vec<u8> = (0..=255u8).collect();
        let randomized = ac.symbol(&mut initial)? != 0;
        let primary = to_usize(u64::from(ac.bit_string(&mut initial, block_bits)?));
        let mut block: Vec<u8> = Vec::new();
        loop {
            let mut sel = ac.symbol(&mut selector)?;
            if sel < 2 {
                let mut state = 1usize;
                let mut zeros = 0usize;
                while sel < 2 {
                    zeros = zeros.saturating_add(if sel == 0 { state } else { state << 1 });
                    if zeros > block_size {
                        return Err(bad("zero run beyond the block"));
                    }
                    state = state.saturating_mul(2);
                    sel = ac.symbol(&mut selector)?;
                }
                if block.len().saturating_add(zeros) > block_size {
                    return Err(bad("zero run beyond the block"));
                }
                let b = mtf_take(&mut mtf, 0);
                block.extend(std::iter::repeat_n(b, zeros));
            }
            let symbol = match sel {
                10 => break,
                2 => 1,
                s => {
                    let model = mtf_models
                        .get_mut(to_usize(u64::from(s.saturating_sub(3))))
                        .ok_or_else(|| bad("bad selector"))?;
                    ac.symbol(model)?
                }
            };
            if block.len() >= block_size {
                return Err(bad("block overflow"));
            }
            let b = mtf_take(&mut mtf, to_usize(u64::from(symbol)));
            block.push(b);
        }
        if primary >= block.len() {
            return Err(bad("BWT index out of range"));
        }
        selector.reset();
        for m in &mut mtf_models {
            m.reset();
        }
        if ac.symbol(&mut initial)? != 0 {
            stored_crc = Some(ac.bit_string(&mut initial, 32)?);
            end = true;
        }
        if randomized {
            return Err(Diagnostic::unsupported("randomized Arsenic blocks"));
        }
        // Inverse BWT.
        let mut counts = [0usize; 256];
        for &b in &block {
            if let Some(c) = counts.get_mut(usize::from(b)) {
                *c = c.saturating_add(1);
            }
        }
        let mut cumulative = [0usize; 256];
        let mut total = 0usize;
        for (c, n) in cumulative.iter_mut().zip(counts.iter_mut()) {
            *c = total;
            total = total.saturating_add(*n);
            *n = 0;
        }
        let mut transform = vec![0usize; block.len()];
        for (i, &b) in block.iter().enumerate() {
            let k = usize::from(b);
            let at = cumulative
                .get(k)
                .copied()
                .unwrap_or(0)
                .saturating_add(counts.get(k).copied().unwrap_or(0));
            if let Some(slot) = transform.get_mut(at) {
                *slot = i;
            }
            if let Some(c) = counts.get_mut(k) {
                *c = c.saturating_add(1);
            }
        }
        // Walk it, undoing the final run-length stage.
        let mut index = primary;
        let mut count = 0u32;
        let mut last = 0u8;
        let mut repeat_next = false;
        for _ in 0..block.len() {
            index = transform.get(index).copied().unwrap_or(0);
            let b = block.get(index).copied().unwrap_or(0);
            if repeat_next {
                repeat_next = false;
                count = 0;
                out.extend(std::iter::repeat_n(last, usize::from(b)));
            } else {
                if count > 0 && b == last {
                    count = count.saturating_add(1);
                } else {
                    count = 1;
                    last = b;
                }
                out.push(b);
                if count == 4 {
                    repeat_next = true;
                }
            }
            if out.len() > limit {
                return Err(too_big(limit));
            }
        }
    }
    let ok = stored_crc.is_none_or(|crc| crc == crate::codec::crc32(&out));
    Ok((out, ok))
}

/// The decoder for [`Params`] (decodes once all input is in).
#[derive(Clone)]
pub struct Decoder {
    params: Params,
    consumed: usize,
    done: bool,
    warning: Option<Diagnostic>,
}

impl Decoder {
    pub fn new(params: Params) -> Self {
        Decoder {
            params,
            consumed: 0,
            done: false,
            warning: None,
        }
    }
}

impl Decode for Decoder {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        _step: usize,
        limit: usize,
    ) -> Result<Step> {
        if !eof {
            return Err(Diagnostic::malformed("waiting for the whole input"));
        }
        if !self.done {
            let (data, warning) = decode(
                self.params.method,
                input,
                to_usize(self.params.size),
                limit.saturating_sub(out.len()),
            )?;
            self.warning = warning;
            if let Some(crc) = self.params.crc
                && crate::codec::crc::crc16_arc(&data) != crc
            {
                self.warning = Some(Diagnostic::warning("StuffIt fork CRC-16 mismatch"));
            }
            out.extend_from_slice(&data);
            self.consumed = input.len();
            self.done = true;
        }
        Ok(Step::Done)
    }

    fn consumed(&self) -> usize {
        self.consumed
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        self.warning.clone()
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

    // The fixtures were written by tests/data/stuffit/make_sit.py, whose
    // encoders share this module's understanding of the formats (except
    // method 2, which is `compress -b 14`).

    #[test]
    fn classic_forks() {
        let archive = include_bytes!("../../tests/fixtures/synthetic/stuffit/methods.sit");
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
