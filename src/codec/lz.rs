//! LZ77-family decompressors without entropy coding: LZ4 (blocks, frames
//! and the legacy format) and Snappy (raw and framed).

use crate::codec::filters::Filter;
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(what.to_owned())
}

fn limit_check(out: &[u8], limit: usize) -> Result<()> {
    if out.len() > limit {
        Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")))
    } else {
        Ok(())
    }
}

/// Copies `len` bytes from `offset` back in `out` (overlap allowed).
fn copy_back(out: &mut Vec<u8>, offset: usize, len: usize, limit: usize) -> Result<()> {
    if offset == 0 || offset > out.len() {
        return Err(bad("match offset outside the output"));
    }
    if out.len().saturating_add(len) > limit {
        return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
    }
    let start = out.len().saturating_sub(offset);
    for i in 0..len {
        let b = out.get(start.saturating_add(i)).copied().unwrap_or(0);
        out.push(b);
    }
    Ok(())
}

/// Decodes one LZ4 block from `input` onto `out` (whose existing contents
/// are the dictionary for linked blocks).
pub fn lz4_block(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let mut pos = 0usize;
    let byte = |pos: &mut usize| -> Result<u8> {
        let b = input.get(*pos).copied().ok_or_else(|| bad("truncated LZ4 block"))?;
        *pos = pos.saturating_add(1);
        Ok(b)
    };
    let length = |pos: &mut usize, base: usize| -> Result<usize> {
        let mut len = base;
        if base == 15 {
            loop {
                let b = byte(pos)?;
                len = len.saturating_add(usize::from(b));
                if b != 255 {
                    break;
                }
            }
        }
        Ok(len)
    };
    while pos < input.len() {
        let token = byte(&mut pos)?;
        let literals = length(&mut pos, usize::from(token >> 4))?;
        let end = pos.saturating_add(literals);
        let lit = input.get(pos..end).ok_or_else(|| bad("truncated LZ4 literals"))?;
        out.extend_from_slice(lit);
        limit_check(out, limit)?;
        pos = end;
        if pos >= input.len() {
            break; // the last sequence has literals only
        }
        let lo = byte(&mut pos)?;
        let hi = byte(&mut pos)?;
        let offset = usize::from(u16::from_le_bytes([lo, hi]));
        let len = length(&mut pos, usize::from(token & 0x0f))?.saturating_add(4);
        copy_back(out, offset, len, limit)?;
    }
    Ok(())
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at.checked_add(4)?).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes)
}

/// LZ4 frames (and legacy frames, and skippable frames), concatenated.
#[derive(Clone, Copy)]
pub struct Lz4Frame;

impl Filter for Lz4Frame {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while let Some(magic) = u32_at(input, pos) {
            pos = pos.saturating_add(4);
            match magic {
                0x184d_2204 => {
                    let flg = *input.get(pos).ok_or_else(|| bad("truncated frame descriptor"))?;
                    let block_checksum = flg & 0x10 != 0;
                    let content_size = flg & 0x08 != 0;
                    let content_checksum = flg & 0x04 != 0;
                    let dict = flg & 0x01 != 0;
                    if dict {
                        return Err(Diagnostic::unsupported("LZ4 frame with an external dictionary"));
                    }
                    // FLG, BD, optional content size and dictionary ID, HC.
                    pos = pos.saturating_add(2).saturating_add(if content_size { 8 } else { 0 }).saturating_add(1);
                    let frame_start = out.len();
                    loop {
                        let size = u32_at(input, pos).ok_or_else(|| bad("truncated LZ4 block size"))?;
                        pos = pos.saturating_add(4);
                        if size == 0 {
                            break;
                        }
                        let raw = size & 0x8000_0000 != 0;
                        let len = crate::bytes::to_usize((size & 0x7fff_ffff).into());
                        let block = input.get(pos..pos.saturating_add(len)).ok_or_else(|| bad("truncated LZ4 block"))?;
                        if raw {
                            out.extend_from_slice(block);
                            limit_check(&out, limit)?;
                        } else {
                            // Linked blocks refer back into earlier output of
                            // the same frame; earlier frames are not part of
                            // the window, which an offset check enforces.
                            let mut frame_out = out.split_off(frame_start);
                            lz4_block(block, &mut frame_out, limit.saturating_sub(frame_start))?;
                            out.extend_from_slice(&frame_out);
                        }
                        pos = pos.saturating_add(len).saturating_add(if block_checksum { 4 } else { 0 });
                    }
                    if content_checksum {
                        pos = pos.saturating_add(4);
                    }
                }
                0x184c_2102 => {
                    // Legacy: independent blocks of up to 8 MiB until the next
                    // magic number or the end.
                    while let Some(len) = u32_at(input, pos) {
                        if len == 0x184c_2102 || len & 0xffff_fff0 == 0x184d_2a50 || len == 0x184d_2204 {
                            break;
                        }
                        let len = crate::bytes::to_usize(len.into());
                        let block = input.get(pos.saturating_add(4)..pos.saturating_add(4).saturating_add(len)).ok_or_else(|| bad("truncated legacy LZ4 block"))?;
                        let mut part = Vec::new();
                        lz4_block(block, &mut part, limit.saturating_sub(out.len()))?;
                        out.extend_from_slice(&part);
                        pos = pos.saturating_add(4).saturating_add(len);
                    }
                }
                m if m & 0xffff_fff0 == 0x184d_2a50 => {
                    let len = u32_at(input, pos).ok_or_else(|| bad("truncated skippable frame"))?;
                    pos = pos.saturating_add(4).saturating_add(crate::bytes::to_usize(len.into()));
                }
                _ => break,
            }
        }
        Ok(out)
    }
}

/// One raw LZ4 block (as embedded in other containers).
#[derive(Clone, Copy)]
pub struct Lz4Block;

impl Filter for Lz4Block {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        lz4_block(input, &mut out, limit)?;
        Ok(out)
    }
}

/// Raw Snappy: a varint length, then literals and copies.
pub fn snappy_raw(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut pos = 0usize;
    let mut expected = 0u64;
    for shift in (0..35).step_by(7) {
        let b = *input.get(pos).ok_or_else(|| bad("truncated Snappy length"))?;
        pos = pos.saturating_add(1);
        expected |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
    }
    let expected = crate::bytes::to_usize(expected);
    if expected > limit {
        return Err(Diagnostic::limit(format!("Snappy data claims {expected:#x} bytes")));
    }
    let mut out = Vec::with_capacity(expected.min(1 << 24));
    let le = |bytes: &[u8]| bytes.iter().rev().fold(0usize, |a, &b| a.wrapping_shl(8) | usize::from(b));
    while pos < input.len() {
        let tag = *input.get(pos).unwrap_or(&0);
        pos = pos.saturating_add(1);
        match tag & 3 {
            0 => {
                let mut len = usize::from(tag >> 2);
                if len >= 60 {
                    let n = len.saturating_sub(59);
                    len = le(input.get(pos..pos.saturating_add(n)).ok_or_else(|| bad("truncated literal length"))?);
                    pos = pos.saturating_add(n);
                }
                let len = len.saturating_add(1);
                let lit = input.get(pos..pos.saturating_add(len)).ok_or_else(|| bad("truncated literal"))?;
                out.extend_from_slice(lit);
                pos = pos.saturating_add(len);
            }
            1 => {
                let len = usize::from((tag >> 2) & 7).saturating_add(4);
                let lo = usize::from(*input.get(pos).ok_or_else(|| bad("truncated copy"))?);
                pos = pos.saturating_add(1);
                copy_back(&mut out, usize::from(tag >> 5) << 8 | lo, len, limit)?;
            }
            2 => {
                let len = usize::from(tag >> 2).saturating_add(1);
                let off = le(input.get(pos..pos.saturating_add(2)).ok_or_else(|| bad("truncated copy"))?);
                pos = pos.saturating_add(2);
                copy_back(&mut out, off, len, limit)?;
            }
            _ => {
                let len = usize::from(tag >> 2).saturating_add(1);
                let off = le(input.get(pos..pos.saturating_add(4)).ok_or_else(|| bad("truncated copy"))?);
                pos = pos.saturating_add(4);
                copy_back(&mut out, off, len, limit)?;
            }
        }
        limit_check(&out, limit)?;
    }
    if out.len() != expected {
        return Err(bad("Snappy output length differs from the header"));
    }
    Ok(out)
}

/// Raw Snappy as a filter.
#[derive(Clone, Copy)]
pub struct Snappy;

impl Filter for Snappy {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        snappy_raw(input, limit)
    }
}

/// The Snappy framing format: chunks of compressed or uncompressed data
/// (each with a masked CRC-32C, not checked here).
#[derive(Clone, Copy)]
pub struct SnappyFramed;

impl Filter for SnappyFramed {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while let (Some(&kind), Some(len)) = (input.get(pos), input.get(pos.saturating_add(1)..pos.saturating_add(4))) {
            let len = len.iter().rev().fold(0usize, |a, &b| a << 8 | usize::from(b));
            let body = input.get(pos.saturating_add(4)..pos.saturating_add(4).saturating_add(len)).ok_or_else(|| bad("truncated Snappy chunk"))?;
            match kind {
                0x00 => out.extend(snappy_raw(body.get(4..).unwrap_or_default(), limit.saturating_sub(out.len()))?),
                0x01 => out.extend_from_slice(body.get(4..).unwrap_or_default()),
                0x02..=0x7f => return Err(Diagnostic::unsupported(format!("reserved Snappy chunk {kind:#04x}"))),
                _ => {}
            }
            limit_check(&out, limit)?;
            pos = pos.saturating_add(4).saturating_add(len);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn lz4_block_with_overlapping_match() {
        // "abcabcabcabcabc!" : literals "abc", match offset 3 len 12, literal "!".
        let block = [0x38, b'a', b'b', b'c', 3, 0, 0x10, b'!'];
        let mut out = Vec::new();
        lz4_block(&block, &mut out, 100).unwrap();
        assert_eq!(out, b"abcabcabcabcabc!");
    }

    #[test]
    fn snappy() {
        // Length 10: literal "ab", copy1 len 8 offset 2.
        let data = [10, 0x04, b'a', b'b', 0x11, 2];
        assert_eq!(snappy_raw(&data, 100).unwrap(), b"ababababab");
    }
}
