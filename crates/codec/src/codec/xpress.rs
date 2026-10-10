//! Microsoft Xpress ([MS-XCA]): Plain LZ77 (sections 2.3/2.4) and
//! LZ77+Huffman (sections 2.1/2.2).
//!
//! Plain LZ77 interleaves 32-bit flag words with literals and 16-bit match
//! words (13-bit offset, 3-bit length, longer lengths in a shared nibble,
//! then a byte, 16 or 32 bits). LZ77+Huffman codes each 64 KiB of output as
//! a block: a 256-byte table of 4-bit code lengths for 512 symbols, then a
//! bit stream read in little-endian 16-bit words, with the extra bytes of
//! long match lengths interleaved where the decoder reads its next word.
//! The stream carries no size, so it is decoded up to a size the container
//! records (the end-of-data symbol 256 is also an ordinary match symbol).
//!
//! Both decoders work a step of output at a time (long matches are copied
//! across steps), keep only their window of output (8 KiB and 64 KiB) and
//! release the input they have passed. Positions are relative to the
//! buffers as they are now (see "Releasing" in the pipeline docs).

use std::sync::Arc;

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("Xpress: {what}"))
}

/// Ends a step that ran out of input: keep what it produced, or ask for
/// more (the caller rolls the step back).
fn need(progress: bool) -> Result<Step> {
    if progress {
        Ok(Step::More)
    } else {
        Err(bad("needs more input"))
    }
}

/// Copies `len` bytes from `offset` back in `out`, byte by byte (the source
/// may overlap what is being written), stopping at `end` bytes of output.
pub(crate) fn copy_back(out: &mut Vec<u8>, offset: usize, len: usize, end: usize) -> Result<()> {
    if offset == 0 || offset > out.len() {
        return Err(Diagnostic::malformed("match offset outside the output"));
    }
    let len = len.min(end.saturating_sub(out.len()));
    copy_match(out, offset, len);
    Ok(())
}

/// Copies `len` bytes from `offset` (checked by the caller) back in `out`.
fn copy_match(out: &mut Vec<u8>, offset: usize, len: usize) {
    let start = out.len().saturating_sub(offset);
    for i in 0..len {
        let b = out.get(start.saturating_add(i)).copied().unwrap_or(0);
        out.push(b);
    }
}

/// Continues a pending match by up to `goal - out.len()` bytes; returns
/// what is left of it.
fn continue_match(
    pending: &mut Option<(usize, usize)>,
    out: &mut Vec<u8>,
    produced: &mut usize,
    goal: usize,
) -> Option<(usize, usize)> {
    let (offset, left) = (*pending)?;
    let n = left.min(goal.saturating_sub(out.len()));
    copy_match(out, offset, n);
    *produced = produced.saturating_add(n);
    let left = left.saturating_sub(n);
    *pending = (left > 0).then_some((offset, left));
    *pending
}

fn u16_at(data: &[u8], at: usize) -> Option<usize> {
    crate::bytes::u16_le(data, at).map(usize::from)
}

/// Plain LZ77, decoded to the end of the input or `size` bytes.
#[derive(Clone, Debug)]
pub struct Xpress {
    size: Option<usize>,
    /// Input position.
    pos: usize,
    flags: u32,
    flag_count: u32,
    /// Input position of the shared length nibble, if one is half used.
    half_byte: Option<usize>,
    /// Output produced so far, released bytes included.
    produced: usize,
    /// A match being copied: its offset and the bytes left.
    pending: Option<(usize, usize)>,
    /// Once done, the input consumed: all of it, as before.
    finished: Option<usize>,
}

/// Plain LZ77 offsets reach 8 KiB back.
const PLAIN_WINDOW: usize = 1 << 13;

impl Xpress {
    pub fn new(size: Option<u64>) -> Self {
        Xpress {
            size: size.map(|s| usize::try_from(s).unwrap_or(usize::MAX)),
            pos: 0,
            flags: 0,
            flag_count: 0,
            half_byte: None,
            produced: 0,
            pending: None,
            finished: None,
        }
    }

    /// The end of the stream: done once all input is in.
    fn finish(&mut self, input: &[u8], eof: bool, progress: bool) -> Result<Step> {
        if !eof {
            return need(progress);
        }
        self.finished = Some(input.len());
        Ok(Step::Done)
    }
}

impl Decode for Xpress {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        if let Some(size) = self.size
            && size.saturating_sub(self.produced) > limit.saturating_sub(out.len())
        {
            return Err(Diagnostic::output_limit(limit));
        }
        let goal = out.len().saturating_add(step);
        let first = out.len();
        let byte = |pos: &mut usize| -> Result<usize> {
            let b = input
                .get(*pos)
                .copied()
                .ok_or_else(|| bad("truncated match length"))?;
            *pos = pos.saturating_add(1);
            Ok(usize::from(b))
        };
        loop {
            if continue_match(&mut self.pending, out, &mut self.produced, goal).is_some() {
                return Ok(Step::More);
            }
            let progress = out.len() > first;
            match self.size {
                Some(s) if self.produced >= s => return self.finish(input, eof, progress),
                None if out.len() > limit => return Err(Diagnostic::output_limit(limit)),
                _ => {}
            }
            if out.len() >= goal {
                return Ok(Step::More);
            }
            if self.flag_count == 0 {
                if self.pos >= input.len() {
                    return self.finish(input, eof, progress);
                }
                let Some(flags) = crate::bytes::u32_le(input, self.pos) else {
                    if eof {
                        return Err(bad("truncated flags"));
                    }
                    return need(progress);
                };
                self.flags = flags;
                self.pos = self.pos.saturating_add(4);
                self.flag_count = 32;
            }
            let bit = self.flag_count.saturating_sub(1);
            if self.flags >> bit & 1 == 0 {
                let Some(&b) = input.get(self.pos) else {
                    if !eof {
                        return need(progress);
                    }
                    if self.size.is_some() {
                        return Err(bad("truncated literal"));
                    }
                    return self.finish(input, eof, progress);
                };
                self.flag_count = bit;
                out.push(b);
                self.pos = self.pos.saturating_add(1);
                self.produced = self.produced.saturating_add(1);
                continue;
            }
            if self.pos == input.len() {
                return self.finish(input, eof, progress);
            }
            self.flag_count = bit;
            // From here on a shortage of input fails the step (rolled back
            // until more input arrives).
            let mut pos = self.pos;
            let word = u16_at(input, pos).ok_or_else(|| bad("truncated match"))?;
            pos = pos.saturating_add(2);
            let offset = (word >> 3).saturating_add(1);
            let mut len = word & 7;
            if len == 7 {
                len = match self.half_byte.take() {
                    None => {
                        self.half_byte = Some(pos);
                        byte(&mut pos)? & 0x0f
                    }
                    Some(at) => usize::from(input.get(at).copied().unwrap_or(0) >> 4),
                };
                if len == 15 {
                    len = byte(&mut pos)?;
                    if len == 255 {
                        len = u16_at(input, pos).ok_or_else(|| bad("truncated match length"))?;
                        pos = pos.saturating_add(2);
                        if len == 0 {
                            len = usize::try_from(
                                crate::bytes::u32_le(input, pos)
                                    .ok_or_else(|| bad("truncated match length"))?,
                            )
                            .unwrap_or(usize::MAX);
                            pos = pos.saturating_add(4);
                        }
                        len = len
                            .checked_sub(15 + 7)
                            .ok_or_else(|| bad("bad match length"))?;
                    }
                    len = len.saturating_add(15);
                }
                len = len.saturating_add(7);
            }
            self.pos = pos;
            len = len.saturating_add(3);
            if self.size.is_none() && out.len().saturating_add(len) > limit {
                return Err(Diagnostic::output_limit(limit));
            }
            if offset > self.produced {
                return Err(Diagnostic::malformed("match offset outside the output"));
            }
            if let Some(size) = self.size {
                len = len.min(size.saturating_sub(self.produced));
            }
            self.pending = (len > 0).then_some((offset, len));
        }
    }

    fn consumed(&self) -> usize {
        self.finished.unwrap_or(self.pos)
    }

    fn releasable_input(&self) -> usize {
        self.half_byte.map_or(self.pos, |at| at.min(self.pos))
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        self.half_byte = self.half_byte.map(|at| at.saturating_sub(n));
        self.finished = self.finished.map(|f| f.saturating_sub(n));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len.saturating_sub(PLAIN_WINDOW)
    }
}

/// LZ77+Huffman offsets reach 64 KiB back.
const HUFFMAN_WINDOW: usize = 1 << 16;

/// LZ77+Huffman, decoded to exactly `size` bytes.
#[derive(Clone, Debug)]
pub struct XpressHuffman {
    size: usize,
    /// Input position of the next block (outside a block).
    pos: usize,
    block: Option<Block>,
    /// Output produced so far, released bytes included.
    produced: usize,
    /// A match being copied: its offset and the bytes left.
    pending: Option<(usize, usize)>,
    /// Input held at the last step (bounds what can be released).
    held: usize,
    /// Once done, the input consumed: all of it, as before.
    finished: Option<usize>,
}

/// The block being decoded.
#[derive(Clone, Debug)]
struct Block {
    code: Arc<Code>,
    bits: Bits,
    /// Where the block's output ends (counted like `produced`).
    end: usize,
}

/// A block's code lengths and decoding table.
#[derive(Debug)]
struct Code {
    lengths: [u8; 512],
    table: Vec<u16>,
}

/// The 16-bit-word bit reader of section 2.2.4.
#[derive(Clone, Copy, Debug)]
struct Bits {
    pos: usize,
    next: u32,
    extra: i32,
    /// Words read past the end of the input (as zeros).
    overrun: u32,
}

impl Bits {
    fn word(&mut self, data: &[u8], eof: bool) -> Result<u32> {
        match u16_at(data, self.pos) {
            Some(w) => {
                self.pos = self.pos.saturating_add(2);
                Ok(u32::try_from(w).unwrap_or(0))
            }
            None if !eof => Err(bad("truncated bit stream")),
            None => {
                // The last word may be a lone byte; beyond that, the
                // register only prefetches.
                let w = data.get(self.pos).copied().map_or(0, u32::from);
                self.pos = self.pos.saturating_add(2);
                self.overrun = self.overrun.saturating_add(1);
                if self.overrun > 2 {
                    return Err(bad("truncated bit stream"));
                }
                Ok(w)
            }
        }
    }

    fn start(data: &[u8], eof: bool, pos: usize) -> Result<Self> {
        let mut bits = Bits {
            pos,
            next: 0,
            extra: 0,
            overrun: 0,
        };
        let hi = bits.word(data, eof)?;
        let lo = bits.word(data, eof)?;
        bits.next = hi << 16 | lo;
        bits.extra = 16;
        Ok(bits)
    }

    fn peek(&self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            self.next >> (32u32.saturating_sub(n))
        }
    }

    fn skip(&mut self, n: u32, data: &[u8], eof: bool) -> Result<()> {
        if n == 0 {
            return Ok(());
        }
        self.next = self.next.checked_shl(n).unwrap_or(0);
        self.extra = self.extra.saturating_sub(i32::try_from(n).unwrap_or(32));
        if self.extra < 0 {
            let w = self.word(data, eof)?;
            let shift = u32::try_from(self.extra.saturating_neg()).unwrap_or(0);
            self.next |= w.checked_shl(shift).unwrap_or(0);
            self.extra = self.extra.saturating_add(16);
        }
        Ok(())
    }

    fn byte(&mut self, data: &[u8]) -> Result<usize> {
        let b = data
            .get(self.pos)
            .copied()
            .ok_or_else(|| bad("truncated match length"))?;
        self.pos = self.pos.saturating_add(1);
        Ok(usize::from(b))
    }

    fn u16(&mut self, data: &[u8]) -> Result<usize> {
        let v = u16_at(data, self.pos).ok_or_else(|| bad("truncated match length"))?;
        self.pos = self.pos.saturating_add(2);
        Ok(v)
    }

    fn u32(&mut self, data: &[u8]) -> Result<usize> {
        let v =
            crate::bytes::u32_le(data, self.pos).ok_or_else(|| bad("truncated match length"))?;
        self.pos = self.pos.saturating_add(4);
        Ok(usize::try_from(v).unwrap_or(usize::MAX))
    }
}

const TABLE_BITS: u32 = 15;

/// The canonical decoding table of section 2.2.4: `2^(15 - len)` entries
/// per symbol, ordered by (length, symbol).
fn decoding_table(lengths: &[u8; 512], table: &mut [u16]) -> Result<()> {
    let mut at = 0usize;
    for len in 1..=TABLE_BITS {
        let count = 1usize << (TABLE_BITS.saturating_sub(len));
        for (symbol, &l) in lengths.iter().enumerate() {
            if u32::from(l) == len {
                let slots = table
                    .get_mut(at..at.saturating_add(count))
                    .ok_or_else(|| bad("oversubscribed Huffman code"))?;
                slots.fill(u16::try_from(symbol).unwrap_or(0));
                at = at.saturating_add(count);
            }
        }
    }
    if at != table.len() {
        return Err(bad("incomplete Huffman code"));
    }
    Ok(())
}

impl XpressHuffman {
    pub fn new(size: u64) -> Self {
        XpressHuffman {
            size: usize::try_from(size).unwrap_or(usize::MAX),
            pos: 0,
            block: None,
            produced: 0,
            pending: None,
            held: 0,
            finished: None,
        }
    }

    /// The input position the decoder has reached.
    fn at(&self) -> usize {
        self.block.as_ref().map_or(self.pos, |b| b.bits.pos)
    }

    /// Reads the next block's table and starts its bit stream.
    fn open_block(&mut self, input: &[u8], eof: bool) -> Result<Block> {
        let raw = input
            .get(self.pos..self.pos.saturating_add(256))
            .ok_or_else(|| bad("truncated: no Huffman table for the next block"))?;
        let mut lengths = [0u8; 512];
        for (i, &b) in raw.iter().enumerate() {
            if let Some(slot) = lengths.get_mut(i.saturating_mul(2)) {
                *slot = b & 0x0f;
            }
            if let Some(slot) = lengths.get_mut(i.saturating_mul(2).saturating_add(1)) {
                *slot = b >> 4;
            }
        }
        let mut table = vec![0u16; 1 << TABLE_BITS];
        decoding_table(&lengths, &mut table)?;
        let bits = Bits::start(input, eof, self.pos.saturating_add(256))?;
        Ok(Block {
            code: Arc::new(Code { lengths, table }),
            bits,
            end: self.produced.saturating_add(1 << 16).min(self.size),
        })
    }
}

impl Decode for XpressHuffman {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        if self.size.saturating_sub(self.produced) > limit.saturating_sub(out.len()) {
            return Err(Diagnostic::output_limit(limit));
        }
        self.held = input.len();
        let goal = out.len().saturating_add(step);
        let first = out.len();
        loop {
            if continue_match(&mut self.pending, out, &mut self.produced, goal).is_some() {
                return Ok(Step::More);
            }
            let progress = out.len() > first;
            if let Some(block) = &self.block
                && self.produced >= block.end
            {
                self.pos = block.bits.pos;
                self.block = None;
            }
            if self.produced >= self.size {
                if !eof {
                    return need(progress);
                }
                self.finished = Some(input.len());
                return Ok(Step::Done);
            }
            if out.len() >= goal {
                return Ok(Step::More);
            }
            let Some(block) = &mut self.block else {
                if !eof && input.len() < self.pos.saturating_add(260) {
                    return need(progress);
                }
                self.block = Some(self.open_block(input, eof)?);
                continue;
            };
            // A shortage of input inside a symbol fails the step (rolled
            // back until more input arrives).
            let bits = &mut block.bits;
            let code = &block.code;
            let symbol = usize::from(
                code.table
                    .get(usize::try_from(bits.peek(TABLE_BITS)).unwrap_or(0))
                    .copied()
                    .unwrap_or(0),
            );
            bits.skip(
                u32::from(code.lengths.get(symbol).copied().unwrap_or(0)),
                input,
                eof,
            )?;
            if let Ok(literal) = u8::try_from(symbol) {
                out.push(literal);
                self.produced = self.produced.saturating_add(1);
                continue;
            }
            let symbol = symbol.saturating_sub(256);
            let mut len = symbol & 15;
            let offset_bits = u32::try_from(symbol >> 4).unwrap_or(0);
            if len == 15 {
                len = bits.byte(input)?;
                if len == 255 {
                    len = bits.u16(input)?;
                    if len == 0 {
                        len = bits.u32(input)?;
                    }
                    len = len.checked_sub(15).ok_or_else(|| bad("bad match length"))?;
                }
                len = len.saturating_add(15);
            }
            len = len.saturating_add(3);
            let offset = usize::try_from(bits.peek(offset_bits))
                .unwrap_or(0)
                .saturating_add(1usize << offset_bits);
            bits.skip(offset_bits, input, eof)?;
            if offset > self.produced {
                return Err(Diagnostic::malformed("match offset outside the output"));
            }
            let len = len.min(self.size.saturating_sub(self.produced));
            self.pending = (len > 0).then_some((offset, len));
        }
    }

    fn consumed(&self) -> usize {
        self.finished.unwrap_or_else(|| self.at())
    }

    fn releasable_input(&self) -> usize {
        self.at().min(self.held)
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        if let Some(block) = &mut self.block {
            block.bits.pos = block.bits.pos.saturating_sub(n);
        }
        self.held = self.held.saturating_sub(n);
        self.finished = self.finished.map(|f| f.saturating_sub(n));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len.saturating_sub(HUFFMAN_WINDOW)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{Streaming, decode_all};

    fn plain(size: Option<u64>, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        decode_all(&mut Streaming(Xpress::new(size)), input, limit)
    }

    fn huffman(size: u64, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        decode_all(&mut Streaming(XpressHuffman::new(size)), input, limit)
    }

    fn hex(s: &str) -> Vec<u8> {
        crate::text::unhex(s).unwrap()
    }

    fn abc300() -> Vec<u8> {
        b"abc".iter().copied().cycle().take(300).collect()
    }

    /// [MS-XCA] section 3.1 (Plain LZ77 examples).
    #[test]
    fn plain_spec_examples() {
        let alphabet = hex(
            "3f 00 00 00 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a",
        );
        assert_eq!(
            plain(None, &alphabet, 1 << 20).unwrap(),
            b"abcdefghijklmnopqrstuvwxyz"
        );
        let abc = hex("ff ff ff 1f 61 62 63 17 00 0f ff 26 01");
        assert_eq!(plain(None, &abc, 1 << 20).unwrap(), abc300());
        assert_eq!(plain(Some(300), &abc, 1 << 20).unwrap(), abc300());
        assert_eq!(plain(Some(10), &abc, 1 << 20).unwrap(), &abc300()[..10]);
        assert!(plain(None, &abc, 100).is_err());
        assert!(plain(Some(300), &abc[..9], 1 << 20).is_err());
    }

    /// The 256-byte length table of [MS-XCA] section 3.2's examples, as
    /// (offset, byte) pairs; all other bytes are zero.
    fn table(nonzero: &[(usize, u8)]) -> Vec<u8> {
        let mut t = vec![0u8; 256];
        for &(at, b) in nonzero {
            t[at] = b;
        }
        t
    }

    /// [MS-XCA] section 3.2 (LZ77+Huffman examples).
    #[test]
    fn huffman_spec_examples() {
        let mut alphabet = table(&[
            (0x30, 0x50),
            (0x31, 0x55),
            (0x32, 0x55),
            (0x33, 0x55),
            (0x34, 0x55),
            (0x35, 0x55),
            (0x36, 0x55),
            (0x37, 0x55),
            (0x38, 0x55),
            (0x39, 0x55),
            (0x3a, 0x55),
            (0x3b, 0x45),
            (0x3c, 0x44),
            (0x3d, 0x04),
            (0x80, 0x04),
        ]);
        alphabet.extend(hex(
            "d8 52 3e d7 94 11 5b e9 19 5f f9 d6 7c df 8d 04 00 00 00 00",
        ));
        assert_eq!(
            huffman(26, &alphabet, 1 << 20).unwrap(),
            b"abcdefghijklmnopqrstuvwxyz"
        );
        let mut abc = table(&[(0x30, 0x30), (0x31, 0x23), (0x80, 0x02), (0x8f, 0x20)]);
        abc.extend(hex("a8 dc 00 00 ff 26 01"));
        assert_eq!(huffman(300, &abc, 1 << 20).unwrap(), abc300());
        assert!(huffman(300, &abc, 299).is_err());
        assert!(huffman(300, &abc[..260], 1 << 20).is_err());
        // An incomplete code is rejected.
        let mut broken = abc.clone();
        broken[0x30] = 0x31;
        assert!(huffman(300, &broken, 1 << 20).is_err());
    }
}
