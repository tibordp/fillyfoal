//! Zstandard decompression (RFC 8878): frames of raw, RLE and compressed
//! blocks; Huffman-coded literals; FSE-coded sequences with repeat offsets;
//! XXH64 content checksums. Dictionaries are not supported.

use crate::codec::filters::Filter;
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("zstd: {what}"))
}

fn le(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0u64, |a, &b| a << 8 | u64::from(b))
}

// ---------------------------------------------------------------------------
// Bit readers

/// Forward little-endian bit reader (FSE table descriptions).
struct Forward<'a> {
    data: &'a [u8],
    bit: usize,
}

impl Forward<'_> {
    fn peek(&self, n: u32) -> u32 {
        let byte = self.bit / 8;
        let window = le(self.data.get(byte..byte.saturating_add(8).min(self.data.len())).unwrap_or_default());
        u32::try_from((window >> (self.bit % 8)) & (1u64 << n).wrapping_sub(1)).unwrap_or(0)
    }

    fn skip(&mut self, n: u32) {
        self.bit = self.bit.saturating_add(usize::try_from(n).unwrap_or(0));
    }
}

/// Backward bit reader: starts at the highest set bit of the last byte
/// (a padding marker) and reads towards the start.
struct Backward<'a> {
    data: &'a [u8],
    /// Bits left above position 0 (may go negative: an overflow).
    pos: i64,
}

impl<'a> Backward<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        let last = *data.last().ok_or_else(|| bad("empty bitstream"))?;
        if last == 0 {
            return Err(bad("bitstream without its end marker"));
        }
        let len = i64::try_from(data.len()).unwrap_or(i64::MAX);
        let pos = len.saturating_mul(8).saturating_sub(i64::from(last.leading_zeros())).saturating_sub(1);
        Ok(Backward { data, pos })
    }

    /// The `n` bits below the current position (zeros past the start).
    fn peek(&self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        let start = self.pos.saturating_sub(i64::from(n));
        let mut v = 0u64;
        for i in 0..i64::from(n) {
            let p = start.saturating_add(i);
            if p >= 0 {
                let p = usize::try_from(p).unwrap_or(usize::MAX);
                let byte = self.data.get(p / 8).copied().unwrap_or(0);
                v |= u64::from(byte >> (p % 8) & 1) << i;
            }
        }
        v
    }

    fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.pos = self.pos.saturating_sub(i64::from(n));
        v
    }

    fn overflowed(&self) -> bool {
        self.pos < 0
    }
}

// ---------------------------------------------------------------------------
// FSE

#[derive(Clone, Copy, Default)]
struct Cell {
    symbol: u8,
    bits: u8,
    base: u16,
}

#[derive(Clone)]
struct Fse {
    log: u32,
    cells: Vec<Cell>,
}

impl Fse {
    fn build(counts: &[i16], log: u32) -> Result<Self> {
        let size = 1usize << log;
        let mut cells = vec![Cell::default(); size];
        let mut high = size.saturating_sub(1);
        let mut next = vec![0u32; counts.len()];
        for (s, (&c, slot)) in counts.iter().zip(next.iter_mut()).enumerate() {
            if c == -1 {
                cells.get_mut(high).ok_or_else(|| bad("FSE table overflow"))?.symbol = u8::try_from(s).unwrap_or(0);
                high = high.saturating_sub(1);
                *slot = 1;
            } else {
                *slot = u32::try_from(c.max(0)).unwrap_or(0);
            }
        }
        let step = (size >> 1).saturating_add(size >> 3).saturating_add(3);
        let mask = size.saturating_sub(1);
        let mut position = 0usize;
        for (s, &c) in counts.iter().enumerate() {
            for _ in 0..c.max(0) {
                cells.get_mut(position).ok_or_else(|| bad("FSE table overflow"))?.symbol = u8::try_from(s).unwrap_or(0);
                loop {
                    position = position.wrapping_add(step) & mask;
                    if position <= high {
                        break;
                    }
                }
            }
        }
        if position != 0 {
            return Err(bad("FSE table not filled"));
        }
        for cell in &mut cells {
            let n = next.get_mut(usize::from(cell.symbol)).ok_or_else(|| bad("FSE symbol"))?;
            let state = *n;
            *n = n.saturating_add(1);
            let high_bit = 31u32.saturating_sub(state.max(1).leading_zeros());
            let bits = log.saturating_sub(high_bit);
            cell.bits = u8::try_from(bits).unwrap_or(0);
            cell.base = u16::try_from((state << bits).saturating_sub(u32::try_from(size).unwrap_or(0))).unwrap_or(0);
        }
        Ok(Fse { log, cells })
    }

    fn rle(symbol: u8) -> Self {
        Fse { log: 0, cells: vec![Cell { symbol, bits: 0, base: 0 }] }
    }

    /// Reads a table description; returns the table and bytes consumed.
    fn read(data: &[u8], max_symbol: usize, max_log: u32) -> Result<(Self, usize)> {
        let mut r = Forward { data, bit: 0 };
        let log = r.peek(4).saturating_add(5);
        r.skip(4);
        if log > max_log {
            return Err(bad("FSE accuracy log too large"));
        }
        let mut remaining = (1i32 << log).saturating_add(1);
        let mut threshold = 1i32 << log;
        let mut bits = log.saturating_add(1);
        let mut counts: Vec<i16> = Vec::new();
        while remaining > 1 && counts.len() <= max_symbol {
            let max = threshold.saturating_mul(2).saturating_sub(1).saturating_sub(remaining);
            let low = i32::try_from(r.peek(bits.saturating_sub(1))).unwrap_or(0);
            let mut count;
            if low < max {
                count = low;
                r.skip(bits.saturating_sub(1));
            } else {
                count = i32::try_from(r.peek(bits)).unwrap_or(0);
                if count >= threshold {
                    count = count.saturating_sub(max);
                }
                r.skip(bits);
            }
            count = count.saturating_sub(1);
            remaining = remaining.saturating_sub(count.abs());
            counts.push(i16::try_from(count).map_err(|_| bad("FSE count"))?);
            if count == 0 {
                // Repeat flags: runs of zero-probability symbols.
                loop {
                    let repeat = r.peek(2);
                    r.skip(2);
                    counts.resize(counts.len().saturating_add(usize::try_from(repeat).unwrap_or(0)), 0);
                    if repeat != 3 || counts.len() > max_symbol {
                        break;
                    }
                }
            }
            while remaining < threshold && threshold > 1 {
                bits = bits.saturating_sub(1);
                threshold >>= 1;
            }
        }
        if remaining != 1 || counts.len() > max_symbol.saturating_add(1) {
            return Err(bad("invalid FSE table description"));
        }
        Ok((Fse::build(&counts, log)?, r.bit.div_ceil(8)))
    }

    fn init(&self, r: &mut Backward<'_>) -> usize {
        usize::try_from(r.read(self.log)).unwrap_or(0)
    }

    fn symbol(&self, state: usize) -> u8 {
        self.cells.get(state).map_or(0, |c| c.symbol)
    }

    fn update(&self, state: &mut usize, r: &mut Backward<'_>) {
        let cell = self.cells.get(*state).copied().unwrap_or_default();
        *state = usize::from(cell.base).wrapping_add(usize::try_from(r.read(cell.bits.into())).unwrap_or(0));
    }
}

const LL_DEFAULT: [i16; 36] = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1];
const ML_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT: [i16; 29] = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1];

const LL_BASE: [(u32, u32); 36] = [
    (0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0), (7, 0), (8, 0), (9, 0), (10, 0), (11, 0), (12, 0), (13, 0), (14, 0), (15, 0),
    (16, 1), (18, 1), (20, 1), (22, 1), (24, 2), (28, 2), (32, 3), (40, 3), (48, 4), (64, 6), (128, 7), (256, 8), (512, 9),
    (1024, 10), (2048, 11), (4096, 12), (8192, 13), (16384, 14), (32768, 15), (65536, 16),
];
const ML_BASE: [(u32, u32); 53] = [
    (3, 0), (4, 0), (5, 0), (6, 0), (7, 0), (8, 0), (9, 0), (10, 0), (11, 0), (12, 0), (13, 0), (14, 0), (15, 0), (16, 0), (17, 0),
    (18, 0), (19, 0), (20, 0), (21, 0), (22, 0), (23, 0), (24, 0), (25, 0), (26, 0), (27, 0), (28, 0), (29, 0), (30, 0), (31, 0),
    (32, 0), (33, 0), (34, 0), (35, 1), (37, 1), (39, 1), (41, 1), (43, 2), (47, 2), (51, 3), (59, 3), (67, 4), (83, 4), (99, 5),
    (131, 7), (259, 8), (515, 9), (1027, 10), (2051, 11), (4099, 12), (8195, 13), (16387, 14), (32771, 15), (65539, 16),
];

// ---------------------------------------------------------------------------
// Huffman (literals)

#[derive(Clone)]
struct Huffman {
    max_bits: u32,
    /// (symbol, bits) for every `max_bits`-bit prefix.
    table: Vec<(u8, u8)>,
}

impl Huffman {
    fn from_weights(mut weights: Vec<u8>) -> Result<Self> {
        let total: u32 = weights.iter().filter(|&&w| w > 0).map(|&w| 1u32 << (w.saturating_sub(1))).sum();
        if total == 0 {
            return Err(bad("empty Huffman weights"));
        }
        let max_bits = 32u32.saturating_sub(total.leading_zeros());
        if max_bits > 11 {
            return Err(bad("Huffman code too long"));
        }
        let left = (1u32 << max_bits).saturating_sub(total);
        if !left.is_power_of_two() {
            return Err(bad("Huffman weights do not complete a tree"));
        }
        weights.push(u8::try_from(32u32.saturating_sub(left.leading_zeros())).unwrap_or(0));
        let size = 1usize << max_bits;
        let mut table = vec![(0u8, 0u8); size];
        // Lowest weights (longest codes) first.
        let mut next = 0usize;
        for w in 1..=u8::try_from(max_bits).unwrap_or(11) {
            for (s, &sw) in weights.iter().enumerate() {
                if sw != w {
                    continue;
                }
                let len = 1usize << (w.saturating_sub(1));
                let bits = u8::try_from(max_bits.saturating_add(1).saturating_sub(u32::from(w))).unwrap_or(0);
                for slot in table.get_mut(next..next.saturating_add(len)).ok_or_else(|| bad("Huffman table overflow"))? {
                    *slot = (u8::try_from(s).unwrap_or(0), bits);
                }
                next = next.saturating_add(len);
            }
        }
        Ok(Huffman { max_bits, table })
    }

    /// Reads a tree description; returns the tree and bytes consumed.
    fn read(data: &[u8]) -> Result<(Self, usize)> {
        let header = usize::from(*data.first().ok_or_else(|| bad("missing Huffman tree"))?);
        if header >= 128 {
            let n = header.saturating_sub(127);
            let bytes = data.get(1..1usize.saturating_add(n.div_ceil(2))).ok_or_else(|| bad("truncated Huffman weights"))?;
            let weights: Vec<u8> = bytes.iter().flat_map(|&b| [b >> 4, b & 0x0f]).take(n).collect();
            return Ok((Huffman::from_weights(weights)?, 1usize.saturating_add(n.div_ceil(2))));
        }
        let body = data.get(1..1usize.saturating_add(header)).ok_or_else(|| bad("truncated Huffman weights"))?;
        let (fse, used) = Fse::read(body, 255, 6)?;
        let mut r = Backward::new(body.get(used..).unwrap_or_default())?;
        let mut s1 = fse.init(&mut r);
        let mut s2 = fse.init(&mut r);
        let mut weights = Vec::new();
        loop {
            if weights.len() >= 255 {
                return Err(bad("too many Huffman weights"));
            }
            weights.push(fse.symbol(s1));
            fse.update(&mut s1, &mut r);
            if r.overflowed() {
                weights.push(fse.symbol(s2));
                break;
            }
            weights.push(fse.symbol(s2));
            fse.update(&mut s2, &mut r);
            if r.overflowed() {
                weights.push(fse.symbol(s1));
                break;
            }
        }
        Ok((Huffman::from_weights(weights)?, 1usize.saturating_add(header)))
    }

    fn decode_stream(&self, data: &[u8], count: usize, out: &mut Vec<u8>) -> Result<()> {
        let mut r = Backward::new(data)?;
        for _ in 0..count {
            let idx = usize::try_from(r.peek(self.max_bits)).unwrap_or(0);
            let &(symbol, bits) = self.table.get(idx).ok_or_else(|| bad("Huffman index"))?;
            out.push(symbol);
            r.pos = r.pos.saturating_sub(i64::from(bits));
        }
        if r.pos != 0 {
            return Err(bad("Huffman stream not fully consumed"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Frames and blocks

/// State that persists between the blocks of a frame.
struct FrameState {
    huffman: Option<Huffman>,
    ll: Option<Fse>,
    of: Option<Fse>,
    ml: Option<Fse>,
    reps: [usize; 3],
}

fn literals(block: &[u8], st: &mut FrameState) -> Result<(Vec<u8>, usize)> {
    let b0 = *block.first().ok_or_else(|| bad("empty block"))?;
    let kind = b0 & 3;
    let format = (b0 >> 2) & 3;
    let byte = |i: usize| usize::from(block.get(i).copied().unwrap_or(0));
    if kind < 2 {
        let (size, header) = match format {
            0 | 2 => (usize::from(b0 >> 3), 1usize),
            1 => (usize::from(b0 >> 4) | byte(1) << 4, 2),
            _ => (usize::from(b0 >> 4) | byte(1) << 4 | byte(2) << 12, 3),
        };
        if kind == 0 {
            let lit = block.get(header..header.saturating_add(size)).ok_or_else(|| bad("truncated literals"))?;
            return Ok((lit.to_vec(), header.saturating_add(size)));
        }
        let b = *block.get(header).ok_or_else(|| bad("truncated literals"))?;
        return Ok((vec![b; size], header.saturating_add(1)));
    }
    let (header, regen, compressed, streams) = match format {
        0 | 1 => {
            let h = le(block.get(..3).unwrap_or_default());
            (3usize, (h >> 4) & 0x3ff, (h >> 14) & 0x3ff, if format == 0 { 1 } else { 4 })
        }
        2 => {
            let h = le(block.get(..4).unwrap_or_default());
            (4, (h >> 4) & 0x3fff, (h >> 18) & 0x3fff, 4)
        }
        _ => {
            let h = le(block.get(..5).unwrap_or_default());
            (5, (h >> 4) & 0x3_ffff, (h >> 22) & 0x3_ffff, 4)
        }
    };
    let regen = usize::try_from(regen).unwrap_or(0);
    let compressed = usize::try_from(compressed).unwrap_or(0);
    let mut data = block.get(header..header.saturating_add(compressed)).ok_or_else(|| bad("truncated literals"))?;
    if kind == 2 {
        let (tree, used) = Huffman::read(data)?;
        st.huffman = Some(tree);
        data = data.get(used..).unwrap_or_default();
    }
    let tree = st.huffman.as_ref().ok_or_else(|| bad("treeless literals without a previous tree"))?;
    let mut out = Vec::with_capacity(regen);
    if streams == 1 {
        tree.decode_stream(data, regen, &mut out)?;
    } else {
        let jump = data.get(..6).ok_or_else(|| bad("truncated jump table"))?;
        let sizes = [le(jump.get(0..2).unwrap_or_default()), le(jump.get(2..4).unwrap_or_default()), le(jump.get(4..6).unwrap_or_default())];
        let each = regen.div_ceil(4);
        let mut pos = 6usize;
        for (i, &size) in sizes.iter().enumerate() {
            let size = usize::try_from(size).unwrap_or(0);
            let s = data.get(pos..pos.saturating_add(size)).ok_or_else(|| bad("truncated literal stream"))?;
            tree.decode_stream(s, each, &mut out)?;
            pos = pos.saturating_add(size);
            let _ = i;
        }
        let last = regen.saturating_sub(each.saturating_mul(3));
        tree.decode_stream(data.get(pos..).unwrap_or_default(), last, &mut out)?;
    }
    Ok((out, header.saturating_add(compressed)))
}

/// A sequence table per its compression mode.
fn table(mode: u8, data: &[u8], prev: Option<Fse>, default: &[i16], default_log: u32, max_symbol: usize, max_log: u32) -> Result<(Fse, usize)> {
    match mode {
        0 => Ok((Fse::build(default, default_log)?, 0)),
        1 => Ok((Fse::rle(*data.first().ok_or_else(|| bad("missing RLE symbol"))?), 1)),
        2 => Fse::read(data, max_symbol, max_log),
        _ => Ok((prev.ok_or_else(|| bad("repeat mode without a previous table"))?, 0)),
    }
}

fn compressed_block(block: &[u8], st: &mut FrameState, out: &mut Vec<u8>, frame_start: usize, limit: usize) -> Result<()> {
    let (lits, mut pos) = literals(block, st)?;
    let b0 = usize::from(*block.get(pos).ok_or_else(|| bad("missing sequence count"))?);
    let byte = |i: usize| usize::from(block.get(i).copied().unwrap_or(0));
    let count = match b0 {
        0 => {
            out.extend_from_slice(&lits);
            return Ok(());
        }
        1..=127 => {
            pos = pos.saturating_add(1);
            b0
        }
        128..=254 => {
            let n = (b0.saturating_sub(128) << 8) | byte(pos.saturating_add(1));
            pos = pos.saturating_add(2);
            n
        }
        _ => {
            let n = byte(pos.saturating_add(1)) | byte(pos.saturating_add(2)) << 8;
            pos = pos.saturating_add(3);
            n.saturating_add(0x7f00)
        }
    };
    let modes = *block.get(pos).ok_or_else(|| bad("missing modes"))?;
    pos = pos.saturating_add(1);
    let (ll, used) = table(modes >> 6, block.get(pos..).unwrap_or_default(), st.ll.take(), &LL_DEFAULT, 6, 35, 9)?;
    pos = pos.saturating_add(used);
    let (of, used) = table(modes >> 4 & 3, block.get(pos..).unwrap_or_default(), st.of.take(), &OF_DEFAULT, 5, 31, 8)?;
    pos = pos.saturating_add(used);
    let (ml, used) = table(modes >> 2 & 3, block.get(pos..).unwrap_or_default(), st.ml.take(), &ML_DEFAULT, 6, 52, 9)?;
    pos = pos.saturating_add(used);
    let mut r = Backward::new(block.get(pos..).unwrap_or_default())?;
    let mut ll_state = ll.init(&mut r);
    let mut of_state = of.init(&mut r);
    let mut ml_state = ml.init(&mut r);
    let mut lit_pos = 0usize;
    for i in 0..count {
        let of_code = u32::from(of.symbol(of_state));
        let ml_code = usize::from(ml.symbol(ml_state));
        let ll_code = usize::from(ll.symbol(ll_state));
        if of_code > 31 {
            return Err(bad("offset code too large"));
        }
        let offset_value = usize::try_from((1u64 << of_code).wrapping_add(r.read(of_code))).unwrap_or(usize::MAX);
        let &(ml_base, ml_bits) = ML_BASE.get(ml_code).ok_or_else(|| bad("match length code"))?;
        let match_len = usize::try_from(u64::from(ml_base).wrapping_add(r.read(ml_bits))).unwrap_or(0);
        let &(ll_base, ll_bits) = LL_BASE.get(ll_code).ok_or_else(|| bad("literal length code"))?;
        let lit_len = usize::try_from(u64::from(ll_base).wrapping_add(r.read(ll_bits))).unwrap_or(0);
        if i.saturating_add(1) < count {
            ll.update(&mut ll_state, &mut r);
            ml.update(&mut ml_state, &mut r);
            of.update(&mut of_state, &mut r);
        }
        // Repeat offsets.
        let [r1, r2, r3] = st.reps;
        let offset = if offset_value > 3 {
            let o = offset_value.saturating_sub(3);
            st.reps = [o, r1, r2];
            o
        } else {
            let index = if lit_len == 0 { offset_value.saturating_add(1) } else { offset_value };
            match index {
                1 => r1,
                2 => {
                    st.reps = [r2, r1, r3];
                    r2
                }
                3 => {
                    st.reps = [r3, r1, r2];
                    r3
                }
                _ => {
                    let o = r1.saturating_sub(1);
                    st.reps = [o, r1, r2];
                    o
                }
            }
        };
        let lit = lits.get(lit_pos..lit_pos.saturating_add(lit_len)).ok_or_else(|| bad("literals overrun"))?;
        out.extend_from_slice(lit);
        lit_pos = lit_pos.saturating_add(lit_len);
        if offset == 0 || offset > out.len().saturating_sub(frame_start) {
            return Err(bad("match offset beyond the window"));
        }
        if out.len().saturating_add(match_len) > limit {
            return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
        }
        let from = out.len().saturating_sub(offset);
        for k in 0..match_len {
            let b = out.get(from.saturating_add(k)).copied().unwrap_or(0);
            out.push(b);
        }
    }
    out.extend_from_slice(lits.get(lit_pos..).unwrap_or_default());
    st.ll = Some(ll);
    st.of = Some(of);
    st.ml = Some(ml);
    Ok(())
}

/// XXH64 (for content checksums).
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    const P1: u64 = 0x9e37_79b1_85eb_ca87;
    const P2: u64 = 0xc2b2_ae3d_27d4_eb4f;
    const P3: u64 = 0x1656_67b1_9e37_79f9;
    const P4: u64 = 0x85eb_ca77_c2b2_ae63;
    const P5: u64 = 0x27d4_eb2f_1656_67c5;
    let round = |acc: u64, v: u64| acc.wrapping_add(v.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1);
    let merge = |acc: u64, v: u64| (acc ^ round(0, v)).wrapping_mul(P1).wrapping_add(P4);
    let mut h;
    let (stripes, rest) = data.as_chunks::<32>();
    if stripes.is_empty() {
        h = seed.wrapping_add(P5);
    } else {
        let mut v = [seed.wrapping_add(P1).wrapping_add(P2), seed.wrapping_add(P2), seed, seed.wrapping_sub(P1)];
        for stripe in stripes {
            for (acc, lane) in v.iter_mut().zip(stripe.as_chunks::<8>().0) {
                *acc = round(*acc, u64::from_le_bytes(*lane));
            }
        }
        h = v[0].rotate_left(1).wrapping_add(v[1].rotate_left(7)).wrapping_add(v[2].rotate_left(12)).wrapping_add(v[3].rotate_left(18));
        for lane in v {
            h = merge(h, lane);
        }
    }
    h = h.wrapping_add(u64::try_from(data.len()).unwrap_or(0));
    let (words, rest) = rest.as_chunks::<8>();
    for w in words {
        h = (h ^ round(0, u64::from_le_bytes(*w))).rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
    }
    let (quads, bytes) = rest.as_chunks::<4>();
    for q in quads {
        h = (h ^ u64::from(u32::from_le_bytes(*q)).wrapping_mul(P1)).rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
    }
    for &b in bytes {
        h = (h ^ u64::from(b).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^ (h >> 32)
}

/// Zstandard frames (and skippable frames), concatenated.
#[derive(Clone, Copy)]
pub struct Zstd;

impl Filter for Zstd {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        let mut frames = 0u32;
        while let Some(magic) = input.get(pos..pos.saturating_add(4)).map(le) {
            if magic & 0xffff_fff0 == 0x184d_2a50 {
                let len = usize::try_from(le(input.get(pos.saturating_add(4)..pos.saturating_add(8)).unwrap_or_default())).unwrap_or(usize::MAX);
                pos = pos.saturating_add(8).saturating_add(len);
                continue;
            }
            if magic != 0xfd2f_b528 {
                if frames == 0 {
                    return Err(bad("not a zstd frame"));
                }
                break;
            }
            frames = frames.saturating_add(1);
            pos = pos.saturating_add(4);
            let fhd = *input.get(pos).ok_or_else(|| bad("truncated frame header"))?;
            pos = pos.saturating_add(1);
            let single = fhd & 0x20 != 0;
            let checksum = fhd & 0x04 != 0;
            let dict_len = match fhd & 3 {
                0 => 0usize,
                1 => 1,
                2 => 2,
                _ => 4,
            };
            let fcs_len = match fhd >> 6 {
                0 => usize::from(single),
                1 => 2,
                2 => 4,
                _ => 8,
            };
            if !single {
                pos = pos.saturating_add(1); // window descriptor
            }
            let dict = le(input.get(pos..pos.saturating_add(dict_len)).unwrap_or_default());
            if dict != 0 {
                return Err(Diagnostic::unsupported("zstd frame using a dictionary"));
            }
            pos = pos.saturating_add(dict_len).saturating_add(fcs_len);
            let frame_start = out.len();
            let mut st = FrameState { huffman: None, ll: None, of: None, ml: None, reps: [1, 4, 8] };
            loop {
                let h = le(input.get(pos..pos.saturating_add(3)).ok_or_else(|| bad("truncated block header"))?);
                pos = pos.saturating_add(3);
                let last = h & 1 != 0;
                let kind = (h >> 1) & 3;
                let size = usize::try_from(h >> 3).unwrap_or(0);
                match kind {
                    0 => out.extend_from_slice(input.get(pos..pos.saturating_add(size)).ok_or_else(|| bad("truncated raw block"))?),
                    1 => {
                        let b = *input.get(pos).ok_or_else(|| bad("truncated RLE block"))?;
                        out.resize(out.len().saturating_add(size), b);
                    }
                    2 => {
                        let block = input.get(pos..pos.saturating_add(size)).ok_or_else(|| bad("truncated compressed block"))?;
                        compressed_block(block, &mut st, &mut out, frame_start, limit)?;
                    }
                    _ => return Err(bad("reserved block type")),
                }
                if out.len() > limit {
                    return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
                }
                pos = pos.saturating_add(if kind == 1 { 1 } else { size });
                if last {
                    break;
                }
            }
            if checksum {
                let stored = le(input.get(pos..pos.saturating_add(4)).ok_or_else(|| bad("truncated checksum"))?);
                let content = out.get(frame_start..).unwrap_or_default();
                if xxh64(content, 0) & 0xffff_ffff != stored {
                    return Err(bad("content checksum mismatch"));
                }
                pos = pos.saturating_add(4);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn xxh64_vectors() {
        assert_eq!(xxh64(b"", 0), 0xef46_db37_51d8_e999);
        assert_eq!(xxh64(b"abc", 0), 0x44bc_2cf5_ad77_0999);
    }
}
