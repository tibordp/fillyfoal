//! Apple LZFSE: blocks of `bvx2` (FSE-coded literals and L/M/D triples),
//! `bvxn` (LZVN), `bvx-` (stored) up to `bvx$`. Version-1 (`bvx1`) blocks
//! are not supported.
//!
//! The FSE table construction and the code tables follow Apple's reference
//! implementation (<https://github.com/lzfse/lzfse>, BSD-3-Clause; see
//! `THIRD-PARTY.md`), the format's only specification.

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("LZFSE: {what}"))
}

fn le(b: &[u8]) -> u64 {
    b.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x))
}

fn field(v: u64, offset: u32, bits: u32) -> u64 {
    (v >> offset) & ((1u64 << bits).wrapping_sub(1))
}

const L_EXTRA: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
const L_BASE: [u32; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60,
];
const M_EXTRA: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];
const M_BASE: [u32; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312,
];
const D_EXTRA: [u8; 64] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14,
    14, 14, 15, 15, 15, 15,
];
const D_BASE: [u32; 64] = [
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156, 188, 220,
    252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092,
    5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956, 49148,
    57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
];

/// The backward bit stream: refilled 64 bits at a time from the end of a
/// payload towards its start.
struct In<'a> {
    data: &'a [u8],
    /// Bytes not yet loaded (the next refill reads just below this).
    pos: usize,
    accum: u64,
    nbits: u32,
}

impl<'a> In<'a> {
    /// A stream ending at `end` in `data`; refills may read back into the
    /// bytes before the payload (they only supply padding bits).
    fn new(data: &'a [u8], end: usize, extra: i64) -> Result<Self> {
        let mut s = In {
            data,
            pos: end.min(data.len()),
            accum: 0,
            nbits: 0,
        };
        let take = if extra != 0 { 8 } else { 7 };
        s.pos = s
            .pos
            .checked_sub(take)
            .ok_or_else(|| bad("payload too short"))?;
        let mut v = le(data
            .get(s.pos..s.pos.saturating_add(take))
            .unwrap_or_default());
        if take == 7 {
            v &= 0x00ff_ffff_ffff_ffff;
        }
        let bits = i64::try_from(take.saturating_mul(8))
            .unwrap_or(64)
            .saturating_add(extra);
        s.nbits = u32::try_from(bits).map_err(|_| bad("bad bit count"))?;
        if !(56..64).contains(&s.nbits) || (s.nbits < 64 && v >> s.nbits != 0) {
            return Err(bad("bad stream start"));
        }
        s.accum = v;
        Ok(s)
    }

    fn flush(&mut self) -> Result<()> {
        let n = 63u32.saturating_sub(self.nbits) & !7;
        if n == 0 {
            return Ok(());
        }
        let bytes = usize::try_from(n / 8).unwrap_or(0);
        self.pos = self
            .pos
            .checked_sub(bytes)
            .ok_or_else(|| bad("stream overrun"))?;
        let incoming = le(self
            .data
            .get(self.pos..self.pos.saturating_add(bytes))
            .unwrap_or_default());
        self.accum = self.accum << n | incoming;
        self.nbits = self.nbits.saturating_add(n);
        Ok(())
    }

    fn pull(&mut self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        self.nbits = self.nbits.saturating_sub(n);
        let v = self.accum >> self.nbits;
        self.accum &= (1u64 << self.nbits).wrapping_sub(1);
        v
    }
}

/// A literal decoder entry: symbol, bits to pull, state delta.
#[derive(Clone, Copy, Default)]
struct Entry {
    k: u32,
    delta: i32,
    symbol: u8,
}

/// A value decoder entry (L, M, D).
#[derive(Clone, Copy, Default)]
struct VEntry {
    total: u32,
    value_bits: u32,
    delta: i32,
    base: u32,
}

/// The LZFSE spread: each symbol's states, with `k` and `delta` per state.
fn spread(nstates: u32, freq: &[u16], mut each: impl FnMut(usize, u32, i32)) -> Result<()> {
    let n_clz = nstates.leading_zeros();
    let mut sum = 0u32;
    for (i, &f) in freq.iter().enumerate() {
        let f = u32::from(f);
        if f == 0 {
            continue;
        }
        sum = sum.saturating_add(f);
        if sum > nstates {
            return Err(bad("frequencies exceed the table size"));
        }
        let k = f.leading_zeros().saturating_sub(n_clz);
        let j0 = (nstates.saturating_mul(2) >> k).saturating_sub(f);
        for j in 0..f {
            if j < j0 {
                let delta = i64::from(f.saturating_add(j)) << k;
                each(
                    i,
                    k,
                    i32::try_from(delta.saturating_sub(i64::from(nstates))).unwrap_or(0),
                );
            } else {
                let delta = i64::from(j.saturating_sub(j0)) << k.saturating_sub(1);
                each(i, k.saturating_sub(1), i32::try_from(delta).unwrap_or(0));
            }
        }
    }
    Ok(())
}

fn literal_table(freq: &[u16]) -> Result<Vec<Entry>> {
    let mut t = Vec::with_capacity(1024);
    spread(1024, freq, |sym, k, delta| {
        t.push(Entry {
            k,
            delta,
            symbol: u8::try_from(sym).unwrap_or(0),
        })
    })?;
    t.resize(1024, Entry::default());
    Ok(t)
}

fn value_table(nstates: u32, freq: &[u16], extra: &[u8], base: &[u32]) -> Result<Vec<VEntry>> {
    let mut t = Vec::with_capacity(usize::try_from(nstates).unwrap_or(0));
    spread(nstates, freq, |sym, k, delta| {
        let vb = u32::from(extra.get(sym).copied().unwrap_or(0));
        t.push(VEntry {
            total: k.saturating_add(vb),
            value_bits: vb,
            delta,
            base: base.get(sym).copied().unwrap_or(0),
        });
    })?;
    t.resize(usize::try_from(nstates).unwrap_or(0), VEntry::default());
    Ok(t)
}

fn decode_literal(state: &mut u32, table: &[Entry], s: &mut In<'_>) -> Result<u8> {
    let e = table
        .get(usize::try_from(*state).unwrap_or(usize::MAX))
        .ok_or_else(|| bad("literal state"))?;
    let v = s.pull(e.k);
    *state = u32::try_from(i64::from(e.delta).saturating_add(i64::try_from(v).unwrap_or(0)))
        .map_err(|_| bad("state"))?;
    Ok(e.symbol)
}

fn decode_value(state: &mut u32, table: &[VEntry], s: &mut In<'_>) -> Result<u32> {
    let e = table
        .get(usize::try_from(*state).unwrap_or(usize::MAX))
        .ok_or_else(|| bad("value state"))?;
    let bits = s.pull(e.total);
    let next = i64::from(e.delta).saturating_add(i64::try_from(bits >> e.value_bits).unwrap_or(0));
    *state = u32::try_from(next).map_err(|_| bad("state"))?;
    let value = bits & ((1u64 << e.value_bits).wrapping_sub(1));
    Ok(e.base.saturating_add(u32::try_from(value).unwrap_or(0)))
}

const FREQ_NBITS: [u32; 32] = [
    2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2,
    14,
];
const FREQ_VALUE: [u16; 32] = [
    0, 2, 1, 4, 0, 3, 1, 0, 0, 2, 1, 5, 0, 3, 1, 0, 0, 2, 1, 6, 0, 3, 1, 0, 0, 2, 1, 7, 0, 3, 1, 0,
];

/// Decodes a `bvx2` block (starting at its magic) into `out`; returns the
/// block's length.
fn block_v2(block: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<usize> {
    let n_raw = usize::try_from(le(block
        .get(4..8)
        .ok_or_else(|| bad("truncated header"))?))
    .unwrap_or(0);
    let v0 = le(block.get(8..16).ok_or_else(|| bad("truncated header"))?);
    let v1 = le(block.get(16..24).ok_or_else(|| bad("truncated header"))?);
    let v2 = le(block.get(24..32).ok_or_else(|| bad("truncated header"))?);
    let n_literals = usize::try_from(field(v0, 0, 20)).unwrap_or(0);
    let n_lit_bytes = usize::try_from(field(v0, 20, 20)).unwrap_or(0);
    let n_matches = field(v0, 40, 20);
    let literal_bits = i64::try_from(field(v0, 60, 3))
        .unwrap_or(0)
        .saturating_sub(7);
    let mut lit_state = [
        field(v1, 0, 10),
        field(v1, 10, 10),
        field(v1, 20, 10),
        field(v1, 30, 10),
    ]
    .map(|v| u32::try_from(v).unwrap_or(0));
    let n_lmd_bytes = usize::try_from(field(v1, 40, 20)).unwrap_or(0);
    let lmd_bits = i64::try_from(field(v1, 60, 3))
        .unwrap_or(0)
        .saturating_sub(7);
    let header_size = usize::try_from(field(v2, 0, 32)).unwrap_or(0);
    let mut l_state = u32::try_from(field(v2, 32, 10)).unwrap_or(0);
    let mut m_state = u32::try_from(field(v2, 42, 10)).unwrap_or(0);
    let mut d_state = u32::try_from(field(v2, 52, 10)).unwrap_or(0);
    // Frequency tables: L (20), M (20), D (64), literals (256).
    let tables = block
        .get(32..header_size)
        .ok_or_else(|| bad("truncated frequency tables"))?;
    let mut freq = [0u16; 360];
    let mut accum = 0u32;
    let mut accum_bits = 0u32;
    let mut src = tables.iter();
    for slot in &mut freq {
        while accum_bits.saturating_add(8) <= 32 {
            let Some(&b) = src.next() else { break };
            accum |= u32::from(b) << accum_bits;
            accum_bits = accum_bits.saturating_add(8);
        }
        let b = usize::try_from(accum & 31).unwrap_or(0);
        let n = FREQ_NBITS.get(b).copied().unwrap_or(2);
        *slot = match n {
            8 => u16::try_from(((accum >> 4) & 0xf).wrapping_add(8)).unwrap_or(0),
            14 => u16::try_from(((accum >> 4) & 0x3ff).wrapping_add(24)).unwrap_or(0),
            _ => FREQ_VALUE.get(b).copied().unwrap_or(0),
        };
        if n > accum_bits {
            return Err(bad("truncated frequency tables"));
        }
        accum >>= n;
        accum_bits = accum_bits.saturating_sub(n);
    }
    let (l_freq, rest) = freq.split_at(20);
    let (m_freq, rest) = rest.split_at(20);
    let (d_freq, lit_freq) = rest.split_at(64);
    let lit_table = literal_table(lit_freq)?;
    let l_table = value_table(64, l_freq, &L_EXTRA, &L_BASE)?;
    let m_table = value_table(64, m_freq, &M_EXTRA, &M_BASE)?;
    let d_table = value_table(256, d_freq, &D_EXTRA, &D_BASE)?;
    // Literals: four interleaved states.
    let lit_end = header_size.saturating_add(n_lit_bytes);
    if lit_end > block.len() {
        return Err(bad("truncated literals"));
    }
    let mut s = In::new(block, lit_end, literal_bits)?;
    let mut literals = Vec::with_capacity(n_literals.saturating_add(4));
    while literals.len() < n_literals {
        s.flush()?;
        for st in &mut lit_state {
            literals.push(decode_literal(st, &lit_table, &mut s)?);
        }
    }
    literals.truncate(n_literals);
    // L, M, D triples.
    let lmd_start = header_size.saturating_add(n_lit_bytes);
    let lmd_end = lmd_start.saturating_add(n_lmd_bytes);
    if lmd_end > block.len() {
        return Err(bad("truncated matches"));
    }
    let mut s = In::new(block, lmd_end, lmd_bits)?;
    let start = out.len();
    let mut lit_pos = 0usize;
    let mut d = 0usize;
    for _ in 0..n_matches {
        s.flush()?;
        let l = usize::try_from(decode_value(&mut l_state, &l_table, &mut s)?).unwrap_or(0);
        let m = usize::try_from(decode_value(&mut m_state, &m_table, &mut s)?).unwrap_or(0);
        s.flush()?;
        let new_d = usize::try_from(decode_value(&mut d_state, &d_table, &mut s)?).unwrap_or(0);
        if new_d != 0 {
            d = new_d;
        }
        out.extend_from_slice(
            literals
                .get(lit_pos..lit_pos.saturating_add(l))
                .ok_or_else(|| bad("literals overrun"))?,
        );
        lit_pos = lit_pos.saturating_add(l);
        if m > 0 {
            if d == 0 || d > out.len() {
                return Err(bad("match distance outside the output"));
            }
            let from = out.len().saturating_sub(d);
            for i in 0..m {
                let b = out.get(from.saturating_add(i)).copied().unwrap_or(0);
                out.push(b);
            }
        }
        if out.len() > limit {
            return Err(Diagnostic::output_limit(limit));
        }
    }
    if out.len().saturating_sub(start) != n_raw {
        return Err(bad("block produced the wrong number of bytes"));
    }
    Ok(lmd_start.saturating_add(n_lmd_bytes))
}

/// Decodes an LZVN stream of `payload` bytes into `out` (`n_raw` bytes).
fn lzvn(payload: &[u8], n_raw: usize, out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let start = out.len();
    let mut pos = 0usize;
    let mut d = 0usize;
    let byte = |pos: usize| -> Result<usize> {
        payload
            .get(pos)
            .map(|&b| usize::from(b))
            .ok_or_else(|| bad("truncated LZVN stream"))
    };
    loop {
        let opc = byte(pos)?;
        // (literal count, match length, new distance, opcode length)
        let (l, m, nd, len): (usize, usize, Option<usize>, usize) = match opc {
            0x06 => break,
            0x0e | 0x16 => (0, 0, None, 1),
            0xa0..=0xbf => {
                let (b1, b2) = (byte(pos.saturating_add(1))?, byte(pos.saturating_add(2))?);
                (
                    (opc >> 3) & 3,
                    ((opc & 7) << 2 | (b1 & 3)).saturating_add(3),
                    Some(b2 << 6 | b1 >> 2),
                    3,
                )
            }
            0xe0 => (byte(pos.saturating_add(1))?.saturating_add(16), 0, None, 2),
            0xe1..=0xef => (opc & 0x0f, 0, None, 1),
            0xf0 => (0, byte(pos.saturating_add(1))?.saturating_add(16), None, 2),
            0xf1..=0xff => (0, opc & 0x0f, None, 1),
            0x70..=0x7f | 0xd0..=0xdf | 0x1e | 0x26 | 0x2e | 0x36 | 0x3e => {
                return Err(bad("undefined LZVN opcode"));
            }
            _ if opc & 7 == 6 => (opc >> 6, ((opc >> 3) & 7).saturating_add(3), None, 1),
            _ if opc & 7 == 7 => {
                let dist = byte(pos.saturating_add(1))? | byte(pos.saturating_add(2))? << 8;
                (opc >> 6, ((opc >> 3) & 7).saturating_add(3), Some(dist), 3)
            }
            _ => (
                (opc >> 6),
                ((opc >> 3) & 7).saturating_add(3),
                Some((opc & 7) << 8 | byte(pos.saturating_add(1))?),
                2,
            ),
        };
        pos = pos.saturating_add(len);
        let lits = payload
            .get(pos..pos.saturating_add(l))
            .ok_or_else(|| bad("truncated LZVN literals"))?;
        out.extend_from_slice(lits);
        pos = pos.saturating_add(l);
        if let Some(nd) = nd {
            d = nd;
        }
        if m > 0 {
            if d == 0 || d > out.len() {
                return Err(bad("LZVN distance outside the output"));
            }
            let from = out.len().saturating_sub(d);
            for i in 0..m {
                let b = out.get(from.saturating_add(i)).copied().unwrap_or(0);
                out.push(b);
            }
        }
        if out.len() > limit || out.len().saturating_sub(start) > n_raw {
            return Err(bad("LZVN output exceeds the block size"));
        }
    }
    if out.len().saturating_sub(start) != n_raw {
        return Err(bad("LZVN block produced the wrong number of bytes"));
    }
    Ok(())
}

/// The farthest a match reaches back: `bvx2` distances are at most
/// `D_BASE[63]` plus 15 extra bits (262 139), LZVN ones 16 bits.
pub const WINDOW: usize = 229_372 + (1 << 15);

/// An LZFSE stream, decoded a block per step. Matches reach back into
/// earlier blocks' output (`out` is the window, [`WINDOW`] bytes of it),
/// so the state is just the input position.
#[derive(Clone, Default)]
pub struct Lzfse {
    pos: usize,
    done: bool,
}

impl Lzfse {
    /// Decodes the block at `self.pos`; false at the end of the stream.
    fn block(&mut self, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<bool> {
        let block = input
            .get(self.pos..)
            .ok_or_else(|| bad("missing end of stream"))?;
        let len = match block.get(..4) {
            Some(b"bvx$") => {
                self.pos = self.pos.saturating_add(4);
                return Ok(false);
            }
            Some(b"bvx-") => {
                let n = usize::try_from(le(block
                    .get(4..8)
                    .ok_or_else(|| bad("truncated header"))?))
                .unwrap_or(0);
                out.extend_from_slice(
                    block
                        .get(8..8usize.saturating_add(n))
                        .ok_or_else(|| bad("truncated stored block"))?,
                );
                8usize.saturating_add(n)
            }
            Some(b"bvxn") => {
                let n_raw = usize::try_from(le(block
                    .get(4..8)
                    .ok_or_else(|| bad("truncated header"))?))
                .unwrap_or(0);
                let n_payload = usize::try_from(le(block
                    .get(8..12)
                    .ok_or_else(|| bad("truncated header"))?))
                .unwrap_or(0);
                let payload = block
                    .get(12..12usize.saturating_add(n_payload))
                    .ok_or_else(|| bad("truncated LZVN block"))?;
                lzvn(payload, n_raw, out, limit)?;
                12usize.saturating_add(n_payload)
            }
            Some(b"bvx2") => block_v2(block, out, limit)?,
            Some(b"bvx1") => return Err(Diagnostic::unsupported("LZFSE version-1 blocks")),
            _ => return Err(bad("bad block magic")),
        };
        if out.len() > limit {
            return Err(Diagnostic::output_limit(limit));
        }
        self.pos = self.pos.saturating_add(len);
        Ok(true)
    }
}

impl Decode for Lzfse {
    fn step(
        &mut self,
        input: &[u8],
        _eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let mark = out.len();
        while !self.done {
            if !self.block(input, out, limit)? {
                self.done = true;
            } else if out.len().saturating_sub(mark) >= step {
                return Ok(Step::More);
            }
        }
        Ok(Step::Done)
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        // Blocks are decoded whole from their start.
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len.saturating_sub(WINDOW)
    }
}
