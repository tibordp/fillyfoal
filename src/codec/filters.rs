//! Byte filters (PDF/PostScript/TIFF): ASCIIHex, ASCII85, RunLength, LZW
//! (MSB-first, with early change), and the PNG and TIFF predictors.
//!
//! Each is written over the whole input; [`Whole`] makes it a [`Decode`]
//! that waits for the end of its input, then decodes in one go.

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// A filter over complete input.
pub trait Filter: Clone + Send + 'static {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>>;
}

/// Adapts a [`Filter`] into a [`Decode`] that decodes once all input is in.
#[derive(Clone)]
pub struct Whole<F> {
    filter: F,
    consumed: usize,
    done: bool,
}

impl<F> Whole<F> {
    pub fn new(filter: F) -> Self {
        Whole { filter, consumed: 0, done: false }
    }
}

impl<F: Filter> Decode for Whole<F> {
    fn step(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, _step: usize, limit: usize) -> Result<Step> {
        if !eof {
            return Err(Diagnostic::malformed("waiting for the whole input"));
        }
        if !self.done {
            let decoded = self.filter.apply(input, limit.saturating_sub(out.len()))?;
            out.extend_from_slice(&decoded);
            self.consumed = input.len();
            self.done = true;
        }
        Ok(Step::Done)
    }

    fn consumed(&self) -> usize {
        self.consumed
    }
}

fn check_limit(out: &[u8], limit: usize) -> Result<()> {
    if out.len() > limit {
        Err(Diagnostic::limit(format!("decoded data exceeds {limit:#x} bytes")))
    } else {
        Ok(())
    }
}

fn is_white(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0)
}

/// ASCIIHexDecode: hex digit pairs, whitespace ignored, `>` ends the data
/// (an odd final digit is followed by an implicit 0).
#[derive(Clone, Copy)]
pub struct AsciiHex;

impl Filter for AsciiHex {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(input.len() / 2);
        let mut high: Option<u8> = None;
        for &b in input {
            if b == b'>' {
                break;
            }
            if is_white(b) {
                continue;
            }
            let v = char::from(b)
                .to_digit(16)
                .and_then(|d| u8::try_from(d).ok())
                .ok_or_else(|| Diagnostic::malformed(format!("invalid hex digit {:?}", char::from(b))))?;
            match high.take() {
                Some(h) => out.push(h << 4 | v),
                None => high = Some(v),
            }
            check_limit(&out, limit)?;
        }
        if let Some(h) = high {
            out.push(h << 4);
        }
        Ok(out)
    }
}

/// ASCII85Decode: base-85 groups of five characters, `z` for four zero
/// bytes, whitespace ignored, `~>` ends the data.
#[derive(Clone, Copy)]
pub struct Ascii85;

impl Filter for Ascii85 {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(input.len().saturating_mul(4) / 5);
        let mut group = [0u8; 5];
        let mut n = 0usize;
        let body = input.strip_prefix(b"<~").unwrap_or(input);
        let flush = |group: &[u8; 5], n: usize, out: &mut Vec<u8>| {
            let mut padded = *group;
            for slot in padded.iter_mut().skip(n) {
                *slot = 84;
            }
            let v = padded.iter().fold(0u64, |acc, &d| acc.wrapping_mul(85).wrapping_add(u64::from(d)));
            let bytes = u32::try_from(v & 0xffff_ffff).unwrap_or(0).to_be_bytes();
            out.extend_from_slice(bytes.get(..n.saturating_sub(1)).unwrap_or_default());
        };
        for &b in body {
            match b {
                b'~' => break,
                b'z' if n == 0 => out.extend_from_slice(&[0; 4]),
                b'!'..=b'u' => {
                    if let Some(slot) = group.get_mut(n) {
                        *slot = b.wrapping_sub(b'!');
                    }
                    n = n.saturating_add(1);
                    if n == 5 {
                        flush(&group, 5, &mut out);
                        n = 0;
                    }
                }
                _ if is_white(b) => {}
                _ => return Err(Diagnostic::malformed(format!("invalid ASCII85 character {:?}", char::from(b)))),
            }
            check_limit(&out, limit)?;
        }
        if n == 1 {
            return Err(Diagnostic::malformed("ASCII85 data ends with a single character"));
        }
        if n > 1 {
            flush(&group, n, &mut out);
        }
        Ok(out)
    }
}

/// RunLengthDecode: a length byte `n` copies `n + 1` literal bytes (n < 128)
/// or repeats the next byte `257 - n` times (n > 128); 128 ends the data.
#[derive(Clone, Copy)]
pub struct RunLength;

impl Filter for RunLength {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut it = input.iter().copied();
        while let Some(n) = it.next() {
            match n {
                128 => break,
                0..=127 => {
                    for _ in 0..=n {
                        out.push(it.next().ok_or_else(|| Diagnostic::malformed("truncated literal run"))?);
                    }
                }
                _ => {
                    let b = it.next().ok_or_else(|| Diagnostic::malformed("truncated repeat run"))?;
                    let count = 257usize.saturating_sub(usize::from(n));
                    out.resize(out.len().saturating_add(count), b);
                }
            }
            check_limit(&out, limit)?;
        }
        Ok(out)
    }
}

/// PackBits (TIFF, Mac): like RunLength, but 128 is a no-op.
#[derive(Clone, Copy)]
pub struct PackBits;

impl Filter for PackBits {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut it = input.iter().copied();
        while let Some(n) = it.next() {
            match n {
                128 => {}
                0..=127 => {
                    for _ in 0..=n {
                        out.push(it.next().ok_or_else(|| Diagnostic::malformed("truncated literal run"))?);
                    }
                }
                _ => {
                    let b = it.next().ok_or_else(|| Diagnostic::malformed("truncated repeat run"))?;
                    let count = 257usize.saturating_sub(usize::from(n));
                    out.resize(out.len().saturating_add(count), b);
                }
            }
            check_limit(&out, limit)?;
        }
        Ok(out)
    }
}

/// LZWDecode (PDF, TIFF): MSB-first codes of 9 to 12 bits, 256 clears the
/// table, 257 ends the data. With `early_change` the code width grows one
/// code early (PDF's default, and TIFF's behaviour).
#[derive(Clone, Copy)]
pub struct Lzw {
    pub early_change: bool,
}

impl Filter for Lzw {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        // Each entry: (prefix code, last byte, length). Strings are rebuilt
        // by walking prefixes.
        let mut table: Vec<(u16, u8, u32)> = (0..=255u8).map(|b| (u16::MAX, b, 1)).collect();
        table.push((u16::MAX, 0, 0)); // 256: clear
        table.push((u16::MAX, 0, 0)); // 257: end
        let mut out: Vec<u8> = Vec::new();
        let mut width = 9u32;
        let mut prev: Option<u16> = None;
        let mut acc = 0u32;
        let mut bits = 0u32;
        let early = u32::from(self.early_change);
        let string = |table: &[(u16, u8, u32)], code: u16, buf: &mut Vec<u8>| -> Option<u8> {
            let start = buf.len();
            let mut c = code;
            let mut guard = 0u32;
            loop {
                let &(p, b, _) = table.get(usize::from(c))?;
                buf.push(b);
                guard = guard.saturating_add(1);
                if p == u16::MAX || guard > 4096 {
                    break;
                }
                c = p;
            }
            buf.get_mut(start..)?.reverse();
            buf.get(start).copied()
        };
        for &byte in input {
            acc = (acc << 8) | u32::from(byte);
            bits = bits.saturating_add(8);
            while bits >= width {
                let shift = bits.saturating_sub(width);
                let code = u16::try_from((acc >> shift) & (1u32 << width).wrapping_sub(1)).unwrap_or(0);
                bits = shift;
                acc &= (1u32 << bits).wrapping_sub(1);
                match code {
                    256 => {
                        table.truncate(258);
                        width = 9;
                        prev = None;
                        continue;
                    }
                    257 => return Ok(out),
                    _ => {}
                }
                let next = u16::try_from(table.len()).unwrap_or(u16::MAX);
                match prev {
                    None => {
                        string(&table, code, &mut out).ok_or_else(|| Diagnostic::malformed("invalid LZW code"))?;
                    }
                    Some(p) => {
                        let first = if code < next {
                            string(&table, code, &mut out).ok_or_else(|| Diagnostic::malformed("invalid LZW code"))?
                        } else if code == next {
                            // KwKwK: the previous string plus its first byte.
                            let f = string(&table, p, &mut out).ok_or_else(|| Diagnostic::malformed("invalid LZW code"))?;
                            out.push(f);
                            f
                        } else {
                            return Err(Diagnostic::malformed("LZW code beyond the table"));
                        };
                        if table.len() < 4096 {
                            let len = table.get(usize::from(p)).map_or(1, |e| e.2.saturating_add(1));
                            table.push((p, first, len));
                        }
                    }
                }
                prev = Some(code);
                let size = u32::try_from(table.len()).unwrap_or(4096).saturating_add(early);
                width = if size >= 2048 { 12 } else if size >= 1024 { 11 } else if size >= 512 { 10 } else { 9 };
                check_limit(&out, limit)?;
            }
        }
        Ok(out)
    }
}

/// PNG row predictors (PDF `/Predictor` 10–15): every row starts with its
/// filter type. `bpp` is bytes per pixel (at least 1), `row` bytes per row.
#[derive(Clone, Copy)]
pub struct PngPredictor {
    pub bpp: usize,
    pub row: usize,
}

impl Filter for PngPredictor {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let row = self.row.max(1);
        let bpp = self.bpp.max(1);
        let mut out = Vec::with_capacity(input.len());
        let mut prev = vec![0u8; row];
        for chunk in input.chunks(row.saturating_add(1)) {
            let Some((&kind, body)) = chunk.split_first() else { break };
            let mut cur = vec![0u8; row];
            for (i, &b) in body.iter().enumerate() {
                let left = i.checked_sub(bpp).and_then(|j| cur.get(j)).copied().unwrap_or(0);
                let up = prev.get(i).copied().unwrap_or(0);
                let up_left = i.checked_sub(bpp).and_then(|j| prev.get(j)).copied().unwrap_or(0);
                let value = match kind {
                    1 => b.wrapping_add(left),
                    2 => b.wrapping_add(up),
                    3 => b.wrapping_add(u8::try_from((u16::from(left).saturating_add(u16::from(up))) / 2).unwrap_or(0)),
                    4 => b.wrapping_add(paeth(left, up, up_left)),
                    _ => b,
                };
                if let Some(slot) = cur.get_mut(i) {
                    *slot = value;
                }
            }
            out.extend_from_slice(cur.get(..body.len()).unwrap_or_default());
            prev = cur;
            check_limit(&out, limit)?;
        }
        Ok(out)
    }
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (ia, ib, ic) = (i16::from(a), i16::from(b), i16::from(c));
    let p = ia.saturating_add(ib).saturating_sub(ic);
    let (pa, pb, pc) = (p.saturating_sub(ia).abs(), p.saturating_sub(ib).abs(), p.saturating_sub(ic).abs());
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// TIFF predictor 2 (horizontal differencing) for 8-bit components.
#[derive(Clone, Copy)]
pub struct TiffPredictor {
    pub bpp: usize,
    pub row: usize,
}

impl Filter for TiffPredictor {
    fn apply(&self, input: &[u8], _limit: usize) -> Result<Vec<u8>> {
        let bpp = self.bpp.max(1);
        let mut out = input.to_vec();
        for row in out.chunks_mut(self.row.max(1)) {
            for i in bpp..row.len() {
                let left = row.get(i.wrapping_sub(bpp)).copied().unwrap_or(0);
                if let Some(slot) = row.get_mut(i) {
                    *slot = slot.wrapping_add(left);
                }
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
    fn ascii_filters() {
        assert_eq!(AsciiHex.apply(b"48 65 6C6c6F 2>", 100).unwrap(), b"Hello ");
        assert_eq!(AsciiHex.apply(b"4>", 100).unwrap(), b"@");
        assert_eq!(Ascii85.apply(b"87cURD]i,\"Ebo80~>", 100).unwrap(), b"Hello World!");
        assert_eq!(Ascii85.apply(b"<~z~>", 100).unwrap(), [0, 0, 0, 0]);
        assert_eq!(Ascii85.apply(b"9jqo^~>", 100).unwrap(), b"Man ");
        assert_eq!(Ascii85.apply(b"9jqo~>", 100).unwrap(), b"Man");
    }

    #[test]
    fn run_length() {
        assert_eq!(RunLength.apply(&[2, b'a', b'b', b'c', 254, b'x', 128, b'?'], 100).unwrap(), b"abcxxx");
        assert_eq!(PackBits.apply(&[128, 0, b'q', 255, b'z'], 100).unwrap(), b"qzz");
    }

    #[test]
    fn lzw_pdf_reference_example() {
        // PDF 1.7 reference, 7.4.4.2: "-----A---B" encoded with early change.
        let input = [0x80, 0x0b, 0x60, 0x50, 0x22, 0x0c, 0x0c, 0x85, 0x01];
        assert_eq!(Lzw { early_change: true }.apply(&input, 100).unwrap(), b"-----A---B");
    }

    #[test]
    fn predictors() {
        // Two rows of 3 one-byte pixels: Sub and Up.
        let data = [1, 1, 1, 1, 2, 5, 5, 5];
        assert_eq!(PngPredictor { bpp: 1, row: 3 }.apply(&data, 100).unwrap(), [1, 2, 3, 6, 7, 8]);
        assert_eq!(TiffPredictor { bpp: 1, row: 3 }.apply(&[1, 1, 1, 5, 0, 0], 100).unwrap(), [1, 2, 3, 5, 5, 5]);
    }
}
