//! bzip2 decompression: Huffman-coded MTF/RLE symbols, the inverse
//! Burrows–Wheeler transform, and the final run-length step. Concatenated
//! streams are decoded in sequence; block CRCs are checked.

use crate::codec::filters::Filter;
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("bzip2: {what}"))
}

/// MSB-first bit reader.
struct Bits<'a> {
    data: &'a [u8],
    bit: usize,
}

impl Bits<'_> {
    fn bit(&mut self) -> Result<u32> {
        let byte = self.data.get(self.bit / 8).copied().ok_or_else(|| bad("unexpected end of data"))?;
        let v = (byte << (self.bit & 7)) >> 7;
        self.bit = self.bit.saturating_add(1);
        Ok(u32::from(v))
    }

    fn bits(&mut self, n: u32) -> Result<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = v << 1 | self.bit()?;
        }
        Ok(v)
    }

    fn align(&mut self) {
        self.bit = self.bit.next_multiple_of(8);
    }
}

/// CRC-32 as bzip2 computes it (MSB-first, polynomial 0x04c11db7).
fn crc_update(crc: u32, b: u8) -> u32 {
    let mut c = crc ^ u32::from(b) << 24;
    for _ in 0..8 {
        c = if c & 0x8000_0000 != 0 { c << 1 ^ 0x04c1_1db7 } else { c << 1 };
    }
    c
}

/// A canonical Huffman code: (length, symbol) sorted, decoded bit by bit.
struct Huffman {
    /// For each length: the first code, the index of its first symbol, the count.
    limits: Vec<(u32, usize, u32)>,
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self> {
        let mut symbols = Vec::with_capacity(lengths.len());
        let mut limits = Vec::new();
        let mut code = 0u32;
        for len in 1..=20u8 {
            let first_index = symbols.len();
            for (sym, &l) in lengths.iter().enumerate() {
                if l == len {
                    symbols.push(u16::try_from(sym).map_err(|_| bad("too many symbols"))?);
                }
            }
            let count = u32::try_from(symbols.len().saturating_sub(first_index)).unwrap_or(0);
            limits.push((code, first_index, count));
            code = code.saturating_add(count) << 1;
        }
        Ok(Huffman { limits, symbols })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16> {
        let mut code = 0u32;
        for &(first, index, count) in &self.limits {
            code = code << 1 | bits.bit()?;
            if count > 0 && code >= first && code < first.saturating_add(count) {
                let i = index.saturating_add(usize::try_from(code.saturating_sub(first)).unwrap_or(0));
                return self.symbols.get(i).copied().ok_or_else(|| bad("bad Huffman code"));
            }
        }
        Err(bad("bad Huffman code"))
    }
}

/// Decodes one block, appending to `out`; returns its stored CRC.
fn block(bits: &mut Bits<'_>, max: usize, out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let stored_crc = bits.bits(32)?;
    if bits.bit()? != 0 {
        return Err(Diagnostic::unsupported("bzip2: randomised blocks"));
    }
    let orig_ptr = usize::try_from(bits.bits(24)?).unwrap_or(usize::MAX);
    // Symbols in use.
    let used_groups = bits.bits(16)?;
    let mut alphabet = Vec::new();
    for g in 0..16u8 {
        if used_groups & (0x8000 >> g) != 0 {
            let row = bits.bits(16)?;
            for b in 0..16u8 {
                if row & (0x8000 >> b) != 0 {
                    alphabet.push(g.wrapping_mul(16).wrapping_add(b));
                }
            }
        }
    }
    if alphabet.is_empty() {
        return Err(bad("no symbols in use"));
    }
    let alpha = alphabet.len().saturating_add(2);
    let groups = usize::try_from(bits.bits(3)?).unwrap_or(0);
    if !(2..=6).contains(&groups) {
        return Err(bad("bad number of Huffman groups"));
    }
    let selectors_n = usize::try_from(bits.bits(15)?).unwrap_or(0);
    if selectors_n == 0 {
        return Err(bad("no selectors"));
    }
    let mut mtf_groups: Vec<u8> = (0..u8::try_from(groups).unwrap_or(6)).collect();
    let mut selectors = Vec::with_capacity(selectors_n);
    for _ in 0..selectors_n {
        let mut j = 0usize;
        while bits.bit()? == 1 {
            j = j.saturating_add(1);
            if j >= groups {
                return Err(bad("bad selector"));
            }
        }
        let g = mtf_groups.remove(j);
        mtf_groups.insert(0, g);
        selectors.push(g);
    }
    let mut tables = Vec::with_capacity(groups);
    for _ in 0..groups {
        let mut len = i32::try_from(bits.bits(5)?).unwrap_or(0);
        let mut lengths = Vec::with_capacity(alpha);
        for _ in 0..alpha {
            loop {
                if !(1..=20).contains(&len) {
                    return Err(bad("bad code length"));
                }
                if bits.bit()? == 0 {
                    break;
                }
                len = if bits.bit()? == 0 { len.saturating_add(1) } else { len.saturating_sub(1) };
            }
            lengths.push(u8::try_from(len).unwrap_or(0));
        }
        tables.push(Huffman::new(&lengths)?);
    }
    // Symbols: MTF indices with RUNA/RUNB zero runs, until end of block.
    let eob = u16::try_from(alpha.saturating_sub(1)).unwrap_or(u16::MAX);
    let mut mtf: Vec<u8> = alphabet.clone();
    let mut tt: Vec<u8> = Vec::new();
    let mut run = 0usize;
    let mut run_weight = 1usize;
    let mut decoded = 0usize;
    loop {
        let selector = selectors.get(decoded / 50).copied().ok_or_else(|| bad("ran out of selectors"))?;
        let table = tables.get(usize::from(selector)).ok_or_else(|| bad("bad selector"))?;
        let sym = table.decode(bits)?;
        decoded = decoded.saturating_add(1);
        if sym <= 1 {
            run = run.saturating_add(run_weight.saturating_mul(usize::from(sym).saturating_add(1)));
            run_weight = run_weight.saturating_mul(2);
            if run > max {
                return Err(bad("run exceeds the block size"));
            }
            continue;
        }
        if run > 0 {
            let b = *mtf.first().ok_or_else(|| bad("empty alphabet"))?;
            tt.resize(tt.len().saturating_add(run), b);
            run = 0;
            run_weight = 1;
        }
        if sym == eob {
            break;
        }
        let index = usize::from(sym.saturating_sub(1));
        if index >= mtf.len() {
            return Err(bad("MTF index out of range"));
        }
        let b = mtf.remove(index);
        mtf.insert(0, b);
        tt.push(b);
        if tt.len() > max {
            return Err(bad("block exceeds its declared size"));
        }
    }
    if orig_ptr >= tt.len() {
        return Err(bad("origin pointer outside the block"));
    }
    // Inverse BWT.
    let mut counts = [0usize; 256];
    for &b in &tt {
        if let Some(c) = counts.get_mut(usize::from(b)) {
            *c = c.saturating_add(1);
        }
    }
    let mut start = [0usize; 256];
    let mut sum = 0usize;
    for (s, c) in start.iter_mut().zip(counts) {
        *s = sum;
        sum = sum.saturating_add(c);
    }
    let mut next = vec![0usize; tt.len()];
    for (i, &b) in tt.iter().enumerate() {
        if let Some(s) = start.get_mut(usize::from(b)) {
            if let Some(slot) = next.get_mut(*s) {
                *slot = i;
            }
            *s = s.saturating_add(1);
        }
    }
    // Final run-length decoding (four equal bytes, then a repeat count).
    let mut crc = !0u32;
    let mut pos = next.get(orig_ptr).copied().unwrap_or(0);
    let mut last: Option<u8> = None;
    let mut same = 0u32;
    for _ in 0..tt.len() {
        let b = tt.get(pos).copied().unwrap_or(0);
        pos = next.get(pos).copied().unwrap_or(0);
        if same == 4 {
            for _ in 0..b {
                if let Some(l) = last {
                    out.push(l);
                    crc = crc_update(crc, l);
                }
            }
            same = 0;
            last = None;
            if out.len() > limit {
                return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
            }
            continue;
        }
        if Some(b) == last {
            same = same.saturating_add(1);
        } else {
            same = 1;
            last = Some(b);
        }
        out.push(b);
        crc = crc_update(crc, b);
    }
    if out.len() > limit {
        return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
    }
    if !crc != stored_crc {
        return Err(bad("block CRC mismatch"));
    }
    Ok(())
}

/// bzip2 streams, concatenated.
#[derive(Clone, Copy)]
pub struct Bzip2;

impl Filter for Bzip2 {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut bits = Bits { data: input, bit: 0 };
        let mut streams = 0u32;
        loop {
            let at = bits.bit / 8;
            match input.get(at..at.saturating_add(4)) {
                Some([b'B', b'Z', b'h', level @ b'1'..=b'9']) => {
                    bits.bit = bits.bit.saturating_add(32);
                    streams = streams.saturating_add(1);
                    let max = usize::from(level.saturating_sub(b'0')).saturating_mul(100_000);
                    loop {
                        let magic = u64::from(bits.bits(24)?) << 24 | u64::from(bits.bits(24)?);
                        match magic {
                            0x3141_5926_5359 => block(&mut bits, max, &mut out, limit)?,
                            0x1772_4538_5090 => {
                                bits.bits(32)?; // combined CRC
                                bits.align();
                                break;
                            }
                            _ => return Err(bad("bad block magic")),
                        }
                    }
                }
                _ if streams == 0 => return Err(bad("not a bzip2 stream")),
                _ => return Ok(out),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decodes_python_bz2_output() {
        // bz2.compress(b"hello hello hello hello, bzip2!\n" * 3)
        let data = [
            0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x20, 0x8a, 0xda, 0xa8, 0x00, 0x00,
            0x14, 0xd9, 0x80, 0x00, 0x10, 0x60, 0x04, 0x10, 0x00, 0x12, 0x64, 0xc0, 0x10, 0x20, 0x00, 0x31,
            0x00, 0xd0, 0x00, 0x8a, 0x9a, 0x01, 0xa6, 0x90, 0xdd, 0x94, 0x32, 0xd9, 0xf3, 0xa7, 0xa0, 0xed,
            0x84, 0x29, 0x90, 0x68, 0x06, 0x9a, 0x7e, 0x2e, 0xe4, 0x8a, 0x70, 0xa1, 0x20, 0x41, 0x15, 0xb5,
            0x50,
        ];
        let out = Bzip2.apply(&data, 1 << 20);
        assert_eq!(out.unwrap(), b"hello hello hello hello, bzip2!\n".repeat(3));
    }
}
