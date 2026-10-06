//! Small byte-oriented LZ77 decompressors: LZF (liblzf; raw, and the `ZV`
//! block framing of the `lzf` tool) and Apple Data Compression (ADC, used
//! by old disk images).

use crate::codec::filters::Filter;
use crate::error::{Diagnostic, Result};

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
}

/// Copies `len` bytes from `dist` back (overlap allowed); the window starts
/// at `base`.
fn copy_back(out: &mut Vec<u8>, base: usize, dist: usize, len: usize, limit: usize, what: &str) -> Result<()> {
    if dist == 0 || dist > out.len().saturating_sub(base) {
        return Err(Diagnostic::malformed(format!("{what}: match distance before the start of the output")));
    }
    if out.len().saturating_sub(base).saturating_add(len) > limit {
        return Err(too_big(limit));
    }
    let start = out.len().saturating_sub(dist);
    for i in 0..len {
        let b = out.get(start.saturating_add(i)).copied().unwrap_or(0);
        out.push(b);
    }
    Ok(())
}

fn literals(input: &[u8], pos: usize, n: usize, out: &mut Vec<u8>, base: usize, limit: usize, what: &str) -> Result<usize> {
    let end = pos.saturating_add(n);
    let lit = input
        .get(pos..end)
        .ok_or_else(|| Diagnostic::malformed(format!("{what}: truncated literal run")))?;
    if out.len().saturating_sub(base).saturating_add(n) > limit {
        return Err(too_big(limit));
    }
    out.extend_from_slice(lit);
    Ok(end)
}

/// Decodes raw LZF data (all of `input`) onto `out`.
pub fn lzf(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let base = out.len();
    let mut pos = 0usize;
    let byte = |pos: usize| -> Result<usize> {
        input
            .get(pos)
            .map(|&b| usize::from(b))
            .ok_or_else(|| Diagnostic::malformed("LZF: truncated back reference"))
    };
    while pos < input.len() {
        let ctrl = byte(pos)?;
        pos = pos.saturating_add(1);
        if ctrl < 32 {
            pos = literals(input, pos, ctrl.saturating_add(1), out, base, limit, "LZF")?;
            continue;
        }
        let mut len = ctrl >> 5;
        if len == 7 {
            len = len.saturating_add(byte(pos)?);
            pos = pos.saturating_add(1);
        }
        let dist = ((ctrl & 0x1f) << 8).saturating_add(byte(pos)?).saturating_add(1);
        pos = pos.saturating_add(1);
        copy_back(out, base, dist, len.saturating_add(2), limit, "LZF")?;
    }
    Ok(())
}

/// Raw LZF data.
#[derive(Clone, Copy)]
pub struct Lzf;

impl Filter for Lzf {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        lzf(input, &mut out, limit)?;
        Ok(out)
    }
}

/// One `ZV` block header: `(header length, data length, uncompressed
/// length, compressed?)`; the lengths are equal for stored blocks.
pub fn zv_block(head: &[u8]) -> Option<(usize, usize, usize, bool)> {
    let be16 = |at: usize| crate::bytes::u16_be(head, at).map(usize::from);
    match head.get(..3)? {
        b"ZV\0" => {
            let n = be16(3)?;
            Some((5, n, n, false))
        }
        b"ZV\x01" => Some((7, be16(3)?, be16(5)?, true)),
        _ => None,
    }
}

/// The `lzf` tool's framing: blocks of `ZV`, a type byte (0 stored, 1
/// compressed) and big-endian 16-bit sizes. Each block is compressed alone.
#[derive(Clone, Copy)]
pub struct LzfFramed;

impl Filter for LzfFramed {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        // The tool stops quietly at a zero byte or the end of input.
        while let Some(&b) = input.get(pos)
            && b != 0
        {
            let head = input.get(pos..).unwrap_or_default();
            let (hlen, clen, ulen, compressed) =
                zv_block(head).ok_or_else(|| Diagnostic::malformed("LZF: bad ZV block header"))?;
            let start = pos.saturating_add(hlen);
            let data = input
                .get(start..start.saturating_add(clen))
                .ok_or_else(|| Diagnostic::malformed("LZF: truncated ZV block"))?;
            if out.len().saturating_add(ulen) > limit {
                return Err(too_big(limit));
            }
            let before = out.len();
            if compressed {
                lzf(data, &mut out, ulen)?;
            } else {
                out.extend_from_slice(data);
            }
            if out.len().saturating_sub(before) != ulen {
                return Err(Diagnostic::malformed("LZF: ZV block decoded to the wrong size"));
            }
            pos = start.saturating_add(clen);
        }
        Ok(out)
    }
}

/// Apple Data Compression: a byte with the top bit set starts a literal run
/// of up to 128 bytes; otherwise a 3-byte (bit 6 set; 4-67 bytes, 16-bit
/// distance) or 2-byte (3-18 bytes, 10-bit distance) match. Distances count
/// from the byte before the current one.
pub fn adc(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let base = out.len();
    let mut pos = 0usize;
    let byte = |pos: usize| -> Result<usize> {
        input
            .get(pos)
            .map(|&b| usize::from(b))
            .ok_or_else(|| Diagnostic::malformed("ADC: truncated match"))
    };
    while pos < input.len() {
        let b = byte(pos)?;
        if b & 0x80 != 0 {
            pos = literals(input, pos.saturating_add(1), (b & 0x7f).saturating_add(1), out, base, limit, "ADC")?;
        } else if b & 0x40 != 0 {
            let len = (b & 0x3f).saturating_add(4);
            let dist = (byte(pos.saturating_add(1))? << 8 | byte(pos.saturating_add(2))?).saturating_add(1);
            pos = pos.saturating_add(3);
            copy_back(out, base, dist, len, limit, "ADC")?;
        } else {
            let len = ((b & 0x3c) >> 2).saturating_add(3);
            let dist = ((b & 3) << 8 | byte(pos.saturating_add(1))?).saturating_add(1);
            pos = pos.saturating_add(2);
            copy_back(out, base, dist, len, limit, "ADC")?;
        }
    }
    Ok(())
}

/// One ADC chunk.
#[derive(Clone, Copy)]
pub struct Adc;

impl Filter for Adc {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        adc(input, &mut out, limit)?;
        Ok(out)
    }
}
