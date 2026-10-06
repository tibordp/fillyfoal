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

use crate::codec::filters::Filter;
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("Xpress: {what}"))
}

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
}

/// Copies `len` bytes from `offset` back in `out`, byte by byte (the source
/// may overlap what is being written), stopping at `end` bytes of output.
pub(crate) fn copy_back(out: &mut Vec<u8>, offset: usize, len: usize, end: usize) -> Result<()> {
    if offset == 0 || offset > out.len() {
        return Err(Diagnostic::malformed("match offset outside the output"));
    }
    let len = len.min(end.saturating_sub(out.len()));
    let start = out.len().saturating_sub(offset);
    for i in 0..len {
        let b = out.get(start.saturating_add(i)).copied().unwrap_or(0);
        out.push(b);
    }
    Ok(())
}

fn u16_at(data: &[u8], at: usize) -> Option<usize> {
    let b = data.get(at..at.checked_add(2)?)?;
    Some(usize::from(u16::from_le_bytes([*b.first()?, *b.get(1)?])))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at.checked_add(4)?)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

/// Plain LZ77, decoded to the end of the input or `size` bytes.
#[derive(Clone, Copy, Debug)]
pub struct Xpress {
    pub size: Option<u64>,
}

impl Filter for Xpress {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let end = match self.size {
            Some(s) => {
                let s = usize::try_from(s).unwrap_or(usize::MAX);
                if s > limit {
                    return Err(too_big(limit));
                }
                s
            }
            None => limit.saturating_add(1),
        };
        let mut out = Vec::with_capacity(end.min(input.len().saturating_mul(4)).min(1 << 24));
        let mut pos = 0usize;
        let mut flags = 0u32;
        let mut flag_count = 0u32;
        let mut half_byte: Option<usize> = None;
        let byte = |pos: &mut usize| -> Result<usize> {
            let b = input.get(*pos).copied().ok_or_else(|| bad("truncated match length"))?;
            *pos = pos.saturating_add(1);
            Ok(usize::from(b))
        };
        while out.len() < end {
            if flag_count == 0 {
                if pos >= input.len() {
                    break;
                }
                flags = u32_at(input, pos).ok_or_else(|| bad("truncated flags"))?;
                pos = pos.saturating_add(4);
                flag_count = 32;
            }
            flag_count = flag_count.saturating_sub(1);
            if flags >> flag_count & 1 == 0 {
                let Some(&b) = input.get(pos) else {
                    if self.size.is_some() {
                        return Err(bad("truncated literal"));
                    }
                    break;
                };
                out.push(b);
                pos = pos.saturating_add(1);
                continue;
            }
            if pos == input.len() {
                break;
            }
            let word = u16_at(input, pos).ok_or_else(|| bad("truncated match"))?;
            pos = pos.saturating_add(2);
            let offset = (word >> 3).saturating_add(1);
            let mut len = word & 7;
            if len == 7 {
                len = match half_byte.take() {
                    None => {
                        half_byte = Some(pos);
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
                            len = usize::try_from(u32_at(input, pos).ok_or_else(|| bad("truncated match length"))?)
                                .unwrap_or(usize::MAX);
                            pos = pos.saturating_add(4);
                        }
                        len = len.checked_sub(15 + 7).ok_or_else(|| bad("bad match length"))?;
                    }
                    len = len.saturating_add(15);
                }
                len = len.saturating_add(7);
            }
            len = len.saturating_add(3);
            if self.size.is_none() && out.len().saturating_add(len) > limit {
                return Err(too_big(limit));
            }
            copy_back(&mut out, offset, len, end)?;
        }
        if out.len() > limit {
            return Err(too_big(limit));
        }
        Ok(out)
    }
}

/// LZ77+Huffman, decoded to exactly `size` bytes.
#[derive(Clone, Copy, Debug)]
pub struct XpressHuffman {
    pub size: u64,
}

/// The 16-bit-word bit reader of section 2.2.4.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    next: u32,
    extra: i32,
    /// Words read past the end of the input (as zeros).
    overrun: u32,
}

impl Bits<'_> {
    fn word(&mut self) -> Result<u32> {
        match u16_at(self.data, self.pos) {
            Some(w) => {
                self.pos = self.pos.saturating_add(2);
                Ok(u32::try_from(w).unwrap_or(0))
            }
            None => {
                // The last word may be a lone byte; beyond that, the
                // register only prefetches.
                let w = self.data.get(self.pos).copied().map_or(0, u32::from);
                self.pos = self.pos.saturating_add(2);
                self.overrun = self.overrun.saturating_add(1);
                if self.overrun > 2 {
                    return Err(bad("truncated bit stream"));
                }
                Ok(w)
            }
        }
    }

    fn start(&mut self) -> Result<()> {
        let hi = self.word()?;
        let lo = self.word()?;
        self.next = hi << 16 | lo;
        self.extra = 16;
        Ok(())
    }

    fn peek(&self, n: u32) -> u32 {
        if n == 0 { 0 } else { self.next >> (32u32.saturating_sub(n)) }
    }

    fn skip(&mut self, n: u32) -> Result<()> {
        if n == 0 {
            return Ok(());
        }
        self.next = self.next.checked_shl(n).unwrap_or(0);
        self.extra = self.extra.saturating_sub(i32::try_from(n).unwrap_or(32));
        if self.extra < 0 {
            let w = self.word()?;
            let shift = u32::try_from(self.extra.saturating_neg()).unwrap_or(0);
            self.next |= w.checked_shl(shift).unwrap_or(0);
            self.extra = self.extra.saturating_add(16);
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<usize> {
        let b = self.data.get(self.pos).copied().ok_or_else(|| bad("truncated match length"))?;
        self.pos = self.pos.saturating_add(1);
        Ok(usize::from(b))
    }

    fn u16(&mut self) -> Result<usize> {
        let v = u16_at(self.data, self.pos).ok_or_else(|| bad("truncated match length"))?;
        self.pos = self.pos.saturating_add(2);
        Ok(v)
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
                let slots = table.get_mut(at..at.saturating_add(count)).ok_or_else(|| bad("oversubscribed Huffman code"))?;
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

impl Filter for XpressHuffman {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let end = usize::try_from(self.size).unwrap_or(usize::MAX);
        if end > limit {
            return Err(too_big(limit));
        }
        let mut out = Vec::with_capacity(end.min(input.len().saturating_mul(16)).min(1 << 24));
        let mut table = vec![0u16; 1 << TABLE_BITS];
        let mut lengths = [0u8; 512];
        let mut pos = 0usize;
        while out.len() < end {
            let raw = input
                .get(pos..pos.saturating_add(256))
                .ok_or_else(|| bad("truncated: no Huffman table for the next block"))?;
            for (i, &b) in raw.iter().enumerate() {
                if let Some(slot) = lengths.get_mut(i.saturating_mul(2)) {
                    *slot = b & 0x0f;
                }
                if let Some(slot) = lengths.get_mut(i.saturating_mul(2).saturating_add(1)) {
                    *slot = b >> 4;
                }
            }
            decoding_table(&lengths, &mut table)?;
            let mut bits = Bits {
                data: input,
                pos: pos.saturating_add(256),
                next: 0,
                extra: 0,
                overrun: 0,
            };
            bits.start()?;
            let block_end = out.len().saturating_add(1 << 16).min(end);
            while out.len() < block_end {
                let symbol = usize::from(table.get(usize::try_from(bits.peek(TABLE_BITS)).unwrap_or(0)).copied().unwrap_or(0));
                bits.skip(u32::from(lengths.get(symbol).copied().unwrap_or(0)))?;
                if let Ok(literal) = u8::try_from(symbol) {
                    out.push(literal);
                    continue;
                }
                let symbol = symbol.saturating_sub(256);
                let mut len = symbol & 15;
                let offset_bits = u32::try_from(symbol >> 4).unwrap_or(0);
                if len == 15 {
                    len = bits.byte()?;
                    if len == 255 {
                        len = bits.u16()?;
                        if len == 0 {
                            len = usize::try_from(u32_at(input, bits.pos).ok_or_else(|| bad("truncated match length"))?)
                                .unwrap_or(usize::MAX);
                            bits.pos = bits.pos.saturating_add(4);
                        }
                        len = len.checked_sub(15).ok_or_else(|| bad("bad match length"))?;
                    }
                    len = len.saturating_add(15);
                }
                len = len.saturating_add(3);
                let offset = usize::try_from(bits.peek(offset_bits)).unwrap_or(0).saturating_add(1usize << offset_bits);
                bits.skip(offset_bits)?;
                copy_back(&mut out, offset, len, end)?;
            }
            pos = bits.pos;
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|h| u8::from_str_radix(h, 16).unwrap()).collect()
    }

    fn abc300() -> Vec<u8> {
        b"abc".iter().copied().cycle().take(300).collect()
    }

    /// [MS-XCA] section 3.1 (Plain LZ77 examples).
    #[test]
    fn plain_spec_examples() {
        let alphabet = hex("3f 00 00 00 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a");
        assert_eq!(Xpress { size: None }.apply(&alphabet, 1 << 20).unwrap(), b"abcdefghijklmnopqrstuvwxyz");
        let abc = hex("ff ff ff 1f 61 62 63 17 00 0f ff 26 01");
        assert_eq!(Xpress { size: None }.apply(&abc, 1 << 20).unwrap(), abc300());
        assert_eq!(Xpress { size: Some(300) }.apply(&abc, 1 << 20).unwrap(), abc300());
        assert_eq!(Xpress { size: Some(10) }.apply(&abc, 1 << 20).unwrap(), &abc300()[..10]);
        assert!(Xpress { size: None }.apply(&abc, 100).is_err());
        assert!(Xpress { size: Some(300) }.apply(&abc[..9], 1 << 20).is_err());
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
        alphabet.extend(hex("d8 52 3e d7 94 11 5b e9 19 5f f9 d6 7c df 8d 04 00 00 00 00"));
        assert_eq!(
            XpressHuffman { size: 26 }.apply(&alphabet, 1 << 20).unwrap(),
            b"abcdefghijklmnopqrstuvwxyz"
        );
        let mut abc = table(&[(0x30, 0x30), (0x31, 0x23), (0x80, 0x02), (0x8f, 0x20)]);
        abc.extend(hex("a8 dc 00 00 ff 26 01"));
        assert_eq!(XpressHuffman { size: 300 }.apply(&abc, 1 << 20).unwrap(), abc300());
        assert!(XpressHuffman { size: 300 }.apply(&abc, 299).is_err());
        assert!(XpressHuffman { size: 300 }.apply(&abc[..260], 1 << 20).is_err());
        // An incomplete code is rejected.
        let mut broken = abc.clone();
        broken[0x30] = 0x31;
        assert!(XpressHuffman { size: 300 }.apply(&broken, 1 << 20).is_err());
    }
}
