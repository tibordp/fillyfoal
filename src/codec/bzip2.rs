//! bzip2 decompression: Huffman-coded MTF/RLE symbols, the inverse
//! Burrows–Wheeler transform, and the final run-length step. Concatenated
//! streams are decoded in sequence; block CRCs are checked.
//!
//! NSIS installers use a variant ([`Bzip2::nsis`]): no stream header, a
//! single byte instead of each 48-bit block (`0x31`) and end (`0x17`)
//! magic, no randomised bit and no CRCs, 900 kB blocks. (From memory of
//! NSIS's modified `decompress.c` and 7-Zip's NSIS decoder; our test
//! streams are real bzip2 output rewritten that way.)

use crate::codec::pipeline::{Decode, Step};
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
        let byte = self
            .data
            .get(self.bit / 8)
            .copied()
            .ok_or_else(|| bad("unexpected end of data"))?;
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
    u32::try_from(crate::codec::crc::CRC32_BZIP2.update_byte(crc.into(), b)).unwrap_or(0)
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
                let i =
                    index.saturating_add(usize::try_from(code.saturating_sub(first)).unwrap_or(0));
                return self
                    .symbols
                    .get(i)
                    .copied()
                    .ok_or_else(|| bad("bad Huffman code"));
            }
        }
        Err(bad("bad Huffman code"))
    }
}

/// Decodes one block, appending to `out`; returns its (checked) CRC. NSIS
/// blocks have neither a CRC nor the randomised bit.
fn block(
    bits: &mut Bits<'_>,
    max: usize,
    out: &mut Vec<u8>,
    limit: usize,
    nsis: bool,
) -> Result<u32> {
    let stored_crc = if nsis { 0 } else { bits.bits(32)? };
    if !nsis && bits.bit()? != 0 {
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
                len = if bits.bit()? == 0 {
                    len.saturating_add(1)
                } else {
                    len.saturating_sub(1)
                };
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
        let selector = selectors
            .get(decoded / 50)
            .copied()
            .ok_or_else(|| bad("ran out of selectors"))?;
        let table = tables
            .get(usize::from(selector))
            .ok_or_else(|| bad("bad selector"))?;
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
                return Err(Diagnostic::limit(format!(
                    "decompressed data exceeds {limit:#x} bytes"
                )));
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
        return Err(Diagnostic::limit(format!(
            "decompressed data exceeds {limit:#x} bytes"
        )));
    }
    if !nsis && !crc != stored_crc {
        return Err(bad("block CRC mismatch"));
    }
    Ok(stored_crc)
}

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_MAGIC: u64 = 0x1772_4538_5090;

/// Whether a block or end-of-stream magic (which follows every block)
/// starts somewhere after the magic at bit `at`. Without one, the block
/// at `at` cannot be complete yet.
fn next_magic(input: &[u8], at: usize) -> bool {
    let mut window = 0u64;
    let mut have = 0u32;
    for &b in input.get((at / 8).saturating_add(6)..).unwrap_or_default() {
        window = window << 8 | u64::from(b);
        have = have.saturating_add(8);
        if have < 48 {
            continue;
        }
        for shift in 0..8u32.min(have.saturating_sub(47)) {
            let candidate = (window >> shift) & 0xffff_ffff_ffff;
            if candidate == BLOCK_MAGIC || candidate == END_MAGIC {
                return true;
            }
        }
    }
    false
}

/// The stream being decoded.
#[derive(Clone, Copy)]
struct Stream {
    /// The block size limit (from the level digit).
    max: usize,
    /// The combined CRC of the blocks so far.
    combined: u32,
}

/// bzip2 streams, concatenated; decoded a block at a time.
#[derive(Clone, Default)]
pub struct Bzip2 {
    /// Bit position in the input (byte-aligned between streams).
    bit: usize,
    streams: u32,
    stream: Option<Stream>,
    done: bool,
    /// The NSIS variant (see the module docs).
    nsis: bool,
}

/// Input an NSIS block may need before it can be decoded: its markers do
/// not let us find where it ends, so short of the end of the input, decode
/// only with this much at hand (more than a 900 kB block compresses to).
const NSIS_LOOKAHEAD: usize = 1 << 20;

impl Bzip2 {
    /// The NSIS variant: one headerless stream of CRC-less blocks.
    pub fn nsis() -> Self {
        Bzip2 {
            nsis: true,
            ..Bzip2::default()
        }
    }

    /// Starts a stream at the current (byte-aligned) position, or ends.
    fn start_stream(&mut self, input: &[u8], eof: bool) -> Result<()> {
        if self.nsis {
            if self.streams > 0 {
                self.done = true;
            } else {
                self.streams = 1;
                self.stream = Some(Stream {
                    max: 900_000,
                    combined: 0,
                });
            }
            return Ok(());
        }
        let at = self.bit / 8;
        match input.get(at..at.saturating_add(4)) {
            Some([b'B', b'Z', b'h', level @ b'1'..=b'9']) => {
                self.bit = self.bit.saturating_add(32);
                self.streams = self.streams.saturating_add(1);
                let max = usize::from(level.saturating_sub(b'0')).saturating_mul(100_000);
                self.stream = Some(Stream { max, combined: 0 });
                Ok(())
            }
            None if !eof => Err(bad("unexpected end of data")),
            _ if self.streams == 0 => Err(bad("not a bzip2 stream")),
            _ => {
                self.done = true;
                Ok(())
            }
        }
    }

    /// Decodes the stream's next block, or its end.
    fn block(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, limit: usize) -> Result<()> {
        let Some(stream) = self.stream.as_mut() else {
            return Ok(());
        };
        let mut bits = Bits {
            data: input,
            bit: self.bit,
        };
        if self.nsis {
            if !eof && input.len().saturating_sub(self.bit / 8) < NSIS_LOOKAHEAD {
                return Err(bad("unexpected end of data"));
            }
            match bits.bits(8)? {
                0x31 => {
                    block(&mut bits, stream.max, out, limit, true)?;
                }
                0x17 => self.stream = None,
                _ => return Err(bad("bad block marker")),
            }
            self.bit = bits.bit;
            return Ok(());
        }
        let magic = u64::from(bits.bits(24)?) << 24 | u64::from(bits.bits(24)?);
        match magic {
            BLOCK_MAGIC if !eof && !next_magic(input, self.bit) => {
                // The block cannot be complete: fail fast instead of
                // decoding it up to the end of the input.
                return Err(bad("unexpected end of data"));
            }
            BLOCK_MAGIC => {
                let crc = block(&mut bits, stream.max, out, limit, false)?;
                stream.combined = stream.combined.rotate_left(1) ^ crc;
            }
            END_MAGIC => {
                let stored = bits.bits(32)?;
                if stored != stream.combined {
                    return Err(bad("stream CRC mismatch"));
                }
                bits.align();
                self.stream = None;
            }
            _ => return Err(bad("bad block magic")),
        }
        self.bit = bits.bit;
        Ok(())
    }
}

impl Decode for Bzip2 {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let target = out.len().saturating_add(step.max(1));
        loop {
            if self.done {
                return Ok(Step::Done);
            }
            if out.len() >= target {
                return Ok(Step::More);
            }
            if self.stream.is_some() {
                self.block(input, eof, out, limit)?;
            } else {
                self.start_stream(input, eof)?;
            }
        }
    }

    fn consumed(&self) -> usize {
        self.bit.div_ceil(8)
    }

    fn releasable_input(&self) -> usize {
        // A partly read byte is kept.
        self.bit / 8
    }

    fn release_input(&mut self, n: usize) {
        self.bit = self.bit.saturating_sub(n.saturating_mul(8));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Blocks never refer to earlier output, and CRCs are computed as
        // each block is produced.
        out_len
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
            0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x20, 0x8a, 0xda, 0xa8,
            0x00, 0x00, 0x14, 0xd9, 0x80, 0x00, 0x10, 0x60, 0x04, 0x10, 0x00, 0x12, 0x64, 0xc0,
            0x10, 0x20, 0x00, 0x31, 0x00, 0xd0, 0x00, 0x8a, 0x9a, 0x01, 0xa6, 0x90, 0xdd, 0x94,
            0x32, 0xd9, 0xf3, 0xa7, 0xa0, 0xed, 0x84, 0x29, 0x90, 0x68, 0x06, 0x9a, 0x7e, 0x2e,
            0xe4, 0x8a, 0x70, 0xa1, 0x20, 0x41, 0x15, 0xb5, 0x50,
        ];
        let out = crate::codec::pipeline::decode_all(
            &mut crate::codec::pipeline::Streaming(Bzip2::default()),
            &data,
            1 << 20,
        );
        assert_eq!(out.unwrap(), b"hello hello hello hello, bzip2!\n".repeat(3));
    }

    #[test]
    fn decodes_nsis_variant() {
        // tests/data/installer/nsisbz.py: Python's bz2 output rewritten bit for
        // bit into NSIS's variant (no header, 1-byte markers, no CRCs).
        let data = [
            0x31, 0x00, 0x00, 0x2c, 0xb3, 0x00, 0x00, 0x20, 0xc0, 0x08, 0x20, 0x00, 0x24, 0xcb,
            0x90, 0x20, 0x40, 0x00, 0xa1, 0x4c, 0x00, 0x00, 0x8a, 0x9a, 0x09, 0xa6, 0x8f, 0x24,
            0x32, 0xfe, 0x86, 0x5d, 0x30, 0xcb, 0xe3, 0xc0, 0x76, 0xc2, 0x14, 0xed, 0xf8, 0x19,
            0x07, 0x0d, 0x81, 0x91, 0xa6, 0x9e, 0x8b, 0x80,
        ];
        let out = crate::codec::pipeline::decode_all(
            &mut crate::codec::pipeline::Streaming(Bzip2::nsis()),
            &data,
            1 << 20,
        );
        assert_eq!(
            out.unwrap(),
            b"hello hello hello hello, nsis bzip2!\n".repeat(3)
        );
        // Standard streams are not NSIS streams.
        assert!(
            crate::codec::pipeline::decode_all(
                &mut crate::codec::pipeline::Streaming(Bzip2::default()),
                &data,
                1 << 20,
            )
            .is_err()
        );
    }
}
