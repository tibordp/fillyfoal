//! Small byte-oriented LZ77 decompressors: LZF (liblzf; raw, and the `ZV`
//! block framing of the `lzf` tool) and Apple Data Compression (ADC, used
//! by old disk images). Each is decoded a token (or a `ZV` block) at a
//! time, with its window in its own output.

use crate::codec::lz::{Units, run_units};
use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
}

/// Copies `len` bytes from `dist` back (overlap allowed); the window starts
/// at `base`.
fn copy_back(
    out: &mut Vec<u8>,
    base: usize,
    dist: usize,
    len: usize,
    limit: usize,
    what: &str,
) -> Result<()> {
    if dist == 0 || dist > out.len().saturating_sub(base) {
        return Err(Diagnostic::malformed(format!(
            "{what}: match distance before the start of the output"
        )));
    }
    if out.len().saturating_sub(base).saturating_add(len) > limit {
        return Err(too_big(limit));
    }
    crate::codec::lz::copy_back(out, dist, len)
}

fn literals(
    input: &[u8],
    pos: usize,
    n: usize,
    out: &mut Vec<u8>,
    base: usize,
    limit: usize,
    what: &str,
) -> Result<usize> {
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
    let mut d = Lzf {
        base: out.len(),
        ..Lzf::default()
    };
    while d.step(input, true, out, usize::MAX, limit)? == Step::More {}
    Ok(())
}

/// The farthest an LZF back reference reaches (13-bit distances).
const LZF_WINDOW: usize = 1 << 13;

/// Raw LZF data, decoded a token at a time.
#[derive(Clone, Default)]
pub struct Lzf {
    pos: usize,
    /// Where the window starts in `out` (the limit counts from there too).
    base: usize,
    done: bool,
}

impl Units for Lzf {
    fn unit(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        _room: usize,
        limit: usize,
    ) -> Result<usize> {
        let (base, mut pos) = (self.base, self.pos);
        let byte = |pos: usize| -> Result<usize> {
            input
                .get(pos)
                .map(|&b| usize::from(b))
                .ok_or_else(|| Diagnostic::malformed("LZF: truncated back reference"))
        };
        if pos >= input.len() {
            if !eof {
                return Err(Diagnostic::malformed("LZF: truncated data"));
            }
            self.done = true;
            return Ok(1);
        }
        let mark = out.len();
        let ctrl = byte(pos)?;
        pos = pos.saturating_add(1);
        if ctrl < 32 {
            pos = literals(input, pos, ctrl.saturating_add(1), out, base, limit, "LZF")?;
        } else {
            let mut len = ctrl >> 5;
            if len == 7 {
                len = len.saturating_add(byte(pos)?);
                pos = pos.saturating_add(1);
            }
            let dist = ((ctrl & 0x1f) << 8)
                .saturating_add(byte(pos)?)
                .saturating_add(1);
            pos = pos.saturating_add(1);
            copy_back(out, base, dist, len.saturating_add(2), limit, "LZF")?;
        }
        self.pos = pos;
        Ok(out.len().saturating_sub(mark))
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn progress(&self) -> usize {
        self.pos
    }
}

impl Decode for Lzf {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        run_units(self, input, eof, out, step, limit)
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
            .saturating_sub(LZF_WINDOW)
            .max(self.base)
            .min(out_len)
    }

    fn release_output(&mut self, n: usize) {
        self.base = self.base.saturating_sub(n);
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
/// compressed) and big-endian 16-bit sizes. Each block is compressed alone
/// (and decoded whole: at most 64 KiB).
#[derive(Clone, Default)]
pub struct LzfFramed {
    pos: usize,
    /// A zero byte ended the blocks; the rest of the input is ignored.
    ended: bool,
    done: bool,
}

impl Units for LzfFramed {
    fn unit(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        _room: usize,
        limit: usize,
    ) -> Result<usize> {
        let pos = self.pos;
        // The tool stops quietly at a zero byte or the end of input.
        let b = input.get(pos).copied();
        if self.ended || b.is_none() {
            if eof {
                self.pos = input.len().max(pos);
                self.done = true;
                return Ok(1);
            }
            if self.ended && pos < input.len() {
                self.pos = input.len();
                return Ok(1);
            }
            return Err(Diagnostic::malformed("LZF: truncated ZV block"));
        }
        if b == Some(0) {
            self.ended = true;
            return Ok(1);
        }
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
        let decoded = if compressed {
            lzf(data, out, ulen)
        } else {
            out.extend_from_slice(data);
            Ok(())
        };
        if decoded.is_ok() && out.len().saturating_sub(before) != ulen {
            out.truncate(before);
            return Err(Diagnostic::malformed(
                "LZF: ZV block decoded to the wrong size",
            ));
        }
        if let Err(e) = decoded {
            out.truncate(before);
            return Err(e);
        }
        self.pos = start.saturating_add(clen);
        Ok(ulen)
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn progress(&self) -> usize {
        self.pos.wrapping_add(usize::from(self.ended))
    }
}

impl Decode for LzfFramed {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        run_units(self, input, eof, out, step, limit)
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Blocks are independent and decoded whole.
        out_len
    }
}

/// Decodes one ADC chunk (all of `input`) onto `out`.
pub fn adc(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let mut d = Adc {
        base: out.len(),
        ..Adc::default()
    };
    while d.step(input, true, out, usize::MAX, limit)? == Step::More {}
    Ok(())
}

/// The farthest an ADC match reaches (16-bit distances, plus one).
const ADC_WINDOW: usize = 1 << 16;

/// Apple Data Compression: a byte with the top bit set starts a literal run
/// of up to 128 bytes; otherwise a 3-byte (bit 6 set; 4-67 bytes, 16-bit
/// distance) or 2-byte (3-18 bytes, 10-bit distance) match. Distances count
/// from the byte before the current one. Decoded a token at a time.
#[derive(Clone, Default)]
pub struct Adc {
    pos: usize,
    /// Where the window starts in `out` (the limit counts from there too).
    base: usize,
    done: bool,
}

impl Units for Adc {
    fn unit(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        _room: usize,
        limit: usize,
    ) -> Result<usize> {
        let (base, mut pos) = (self.base, self.pos);
        let byte = |pos: usize| -> Result<usize> {
            input
                .get(pos)
                .map(|&b| usize::from(b))
                .ok_or_else(|| Diagnostic::malformed("ADC: truncated match"))
        };
        if pos >= input.len() {
            if !eof {
                return Err(Diagnostic::malformed("ADC: truncated data"));
            }
            self.done = true;
            return Ok(1);
        }
        let mark = out.len();
        let b = byte(pos)?;
        if b & 0x80 != 0 {
            pos = literals(
                input,
                pos.saturating_add(1),
                (b & 0x7f).saturating_add(1),
                out,
                base,
                limit,
                "ADC",
            )?;
        } else if b & 0x40 != 0 {
            let len = (b & 0x3f).saturating_add(4);
            let dist = (byte(pos.saturating_add(1))? << 8 | byte(pos.saturating_add(2))?)
                .saturating_add(1);
            pos = pos.saturating_add(3);
            copy_back(out, base, dist, len, limit, "ADC")?;
        } else {
            let len = ((b & 0x3c) >> 2).saturating_add(3);
            let dist = ((b & 3) << 8 | byte(pos.saturating_add(1))?).saturating_add(1);
            pos = pos.saturating_add(2);
            copy_back(out, base, dist, len, limit, "ADC")?;
        }
        self.pos = pos;
        Ok(out.len().saturating_sub(mark))
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn progress(&self) -> usize {
        self.pos
    }
}

impl Decode for Adc {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        run_units(self, input, eof, out, step, limit)
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
            .saturating_sub(ADC_WINDOW)
            .max(self.base)
            .min(out_len)
    }

    fn release_output(&mut self, n: usize) {
        self.base = self.base.saturating_sub(n);
    }
}
