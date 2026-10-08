//! Byte filters (PDF/PostScript/TIFF/Type 1): ASCIIHex, ASCII85, RunLength,
//! PackBits, LZW (MSB-first, with early change), the PNG and TIFF
//! predictors, and eexec.
//!
//! Each is a [`ByteFilter`], fed a byte at a time; [`Bytes`] makes it an
//! incremental [`Decode`]. [`Filter`] and [`Whole`] remain for codecs
//! written over their whole input, decoded in one go once it is all in.

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
        Whole {
            filter,
            consumed: 0,
            done: false,
        }
    }
}

impl<F: Filter> Decode for Whole<F> {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        _step: usize,
        limit: usize,
    ) -> Result<Step> {
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
        Err(Diagnostic::limit(format!(
            "decoded data exceeds {limit:#x} bytes"
        )))
    } else {
        Ok(())
    }
}

fn is_white(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0)
}

/// A filter fed one input byte at a time, keeping its state between bytes
/// (so it can stop anywhere and resume). [`Bytes`] makes it a [`Decode`].
pub trait ByteFilter: Clone + Send + 'static {
    /// Decodes one input byte into `out` (all output so far). Returns
    /// `false` at the end-of-data marker: the rest of the input is ignored.
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool>;

    /// Ends the data (at the marker or the end of the input).
    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }

    /// Output bytes at the front the filter will never read again.
    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }

    /// Rebases output positions after the first `n` bytes were dropped.
    fn release_output(&mut self, _n: usize) {}
}

/// Adapts a [`ByteFilter`] into a [`Decode`]: each step decodes about
/// `step` bytes of output, or a bounded amount of input, then returns.
/// Input after the end-of-data marker is consumed and ignored, and the
/// stream ends with the input (so `consumed` is the whole input, as it was
/// when these filters decoded the whole buffer at once).
#[derive(Clone)]
pub struct Bytes<F> {
    filter: F,
    pos: usize,
    ended: bool,
}

impl<F> Bytes<F> {
    pub fn new(filter: F) -> Self {
        Bytes {
            filter,
            pos: 0,
            ended: false,
        }
    }
}

/// Input bytes a step may scan, whatever it produces (whitespace, codes
/// that only clear a table).
fn input_budget(step: usize) -> usize {
    step.saturating_mul(4).max(4096)
}

impl<F: ByteFilter> Decode for Bytes<F> {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        if self.ended {
            // Skip what follows the end-of-data marker.
            return if eof {
                self.pos = input.len();
                Ok(Step::Done)
            } else if self.pos < input.len() {
                self.pos = input.len();
                Ok(Step::More)
            } else {
                Err(Diagnostic::malformed("out of input"))
            };
        }
        let mark = out.len();
        let start = self.pos;
        let budget = input_budget(step);
        while let Some(&b) = input.get(self.pos) {
            self.pos = self.pos.saturating_add(1);
            let go_on = self.filter.byte(b, out)?;
            if !go_on {
                self.filter.finish(out)?;
                check_limit(out, limit)?;
                self.ended = true;
                return Ok(Step::More);
            }
            check_limit(out, limit)?;
            if out.len().saturating_sub(mark) >= step || self.pos.saturating_sub(start) >= budget {
                return Ok(Step::More);
            }
        }
        if eof {
            self.filter.finish(out)?;
            check_limit(out, limit)?;
            self.ended = true;
            Ok(Step::Done)
        } else if self.pos > start {
            Ok(Step::More)
        } else {
            Err(Diagnostic::malformed("out of input"))
        }
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
        self.filter.releasable_output(out_len)
    }

    fn release_output(&mut self, n: usize) {
        self.filter.release_output(n);
    }
}

fn hex_value(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// ASCIIHexDecode: hex digit pairs, whitespace ignored, `>` ends the data
/// (an odd final digit is followed by an implicit 0).
#[derive(Clone, Copy, Default)]
pub struct AsciiHex {
    high: Option<u8>,
}

impl ByteFilter for AsciiHex {
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool> {
        if b == b'>' {
            return Ok(false);
        }
        if is_white(b) {
            return Ok(true);
        }
        let v = hex_value(b).ok_or_else(|| {
            Diagnostic::malformed(format!("invalid hex digit {:?}", char::from(b)))
        })?;
        match self.high.take() {
            Some(h) => out.push(h << 4 | v),
            None => self.high = Some(v),
        }
        Ok(true)
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if let Some(h) = self.high.take() {
            out.push(h << 4);
        }
        Ok(())
    }
}

/// ASCII85Decode: base-85 groups of five characters, `z` for four zero
/// bytes, whitespace ignored, `~>` ends the data. A leading `<~` is
/// skipped.
#[derive(Clone, Copy, Default)]
pub struct Ascii85 {
    group: [u8; 5],
    n: usize,
    /// Input bytes seen, up to 2 (for the `<~` prefix).
    seen: u8,
    /// A leading `<`, held until the next byte shows whether it starts
    /// the prefix.
    lt: bool,
}

impl Ascii85 {
    fn flush(&self, n: usize, out: &mut Vec<u8>) {
        let mut padded = self.group;
        for slot in padded.iter_mut().skip(n) {
            *slot = 84;
        }
        let v = padded.iter().fold(0u64, |acc, &d| {
            acc.wrapping_mul(85).wrapping_add(u64::from(d))
        });
        let bytes = u32::try_from(v & 0xffff_ffff).unwrap_or(0).to_be_bytes();
        out.extend_from_slice(bytes.get(..n.saturating_sub(1)).unwrap_or_default());
    }

    fn char(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool> {
        match b {
            b'~' => return Ok(false),
            b'z' if self.n == 0 => out.extend_from_slice(&[0; 4]),
            b'!'..=b'u' => {
                if let Some(slot) = self.group.get_mut(self.n) {
                    *slot = b.wrapping_sub(b'!');
                }
                self.n = self.n.saturating_add(1);
                if self.n == 5 {
                    self.flush(5, out);
                    self.n = 0;
                }
            }
            _ if is_white(b) => {}
            _ => {
                return Err(Diagnostic::malformed(format!(
                    "invalid ASCII85 character {:?}",
                    char::from(b)
                )));
            }
        }
        Ok(true)
    }
}

impl ByteFilter for Ascii85 {
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool> {
        let first = self.seen;
        self.seen = self.seen.saturating_add(1).min(2);
        match first {
            0 if b == b'<' => {
                self.lt = true;
                Ok(true)
            }
            1 if self.lt => {
                self.lt = false;
                if b == b'~' {
                    Ok(true)
                } else {
                    // Not the prefix: the `<` was a digit.
                    self.char(b'<', out)?;
                    self.char(b, out)
                }
            }
            _ => self.char(b, out),
        }
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if std::mem::take(&mut self.lt) {
            self.char(b'<', out)?;
        }
        if self.n == 1 {
            return Err(Diagnostic::malformed(
                "ASCII85 data ends with a single character",
            ));
        }
        if self.n > 1 {
            self.flush(self.n, out);
        }
        Ok(())
    }
}

/// State of a RunLength or PackBits decoder.
#[derive(Clone, Copy, Default)]
enum Run {
    /// Expecting a length byte.
    #[default]
    Length,
    /// This many literal bytes to copy.
    Literal(u8),
    /// The next byte repeats this many times.
    Repeat(usize),
}

/// One byte of RunLength or PackBits data; `stop` is whether 128 ends the
/// data (RunLength) or does nothing (PackBits).
fn run_byte(run: &mut Run, b: u8, out: &mut Vec<u8>, stop: bool) -> bool {
    *run = match *run {
        Run::Length => match b {
            128 if stop => return false,
            128 => Run::Length,
            0..=127 => Run::Literal(b.saturating_add(1)),
            _ => Run::Repeat(257usize.saturating_sub(usize::from(b))),
        },
        Run::Literal(n) => {
            out.push(b);
            match n.saturating_sub(1) {
                0 => Run::Length,
                n => Run::Literal(n),
            }
        }
        Run::Repeat(count) => {
            out.resize(out.len().saturating_add(count), b);
            Run::Length
        }
    };
    true
}

fn run_finish(run: Run) -> Result<()> {
    match run {
        Run::Length => Ok(()),
        Run::Literal(_) => Err(Diagnostic::malformed("truncated literal run")),
        Run::Repeat(_) => Err(Diagnostic::malformed("truncated repeat run")),
    }
}

/// RunLengthDecode: a length byte `n` copies `n + 1` literal bytes (n < 128)
/// or repeats the next byte `257 - n` times (n > 128); 128 ends the data.
#[derive(Clone, Copy, Default)]
pub struct RunLength(Run);

impl ByteFilter for RunLength {
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool> {
        Ok(run_byte(&mut self.0, b, out, true))
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<()> {
        run_finish(self.0)
    }
}

/// PackBits (TIFF, Mac): like RunLength, but 128 is a no-op.
#[derive(Clone, Copy, Default)]
pub struct PackBits(Run);

impl ByteFilter for PackBits {
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool> {
        Ok(run_byte(&mut self.0, b, out, false))
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<()> {
        run_finish(self.0)
    }
}

/// LZWDecode (PDF, TIFF): MSB-first codes of 9 to 12 bits, 256 clears the
/// table, 257 ends the data. With `early_change` the code width grows one
/// code early (PDF's default, and TIFF's behaviour).
#[derive(Clone)]
pub struct Lzw {
    early: u32,
    /// Entries past the 258 fixed codes: (prefix code, last byte). Strings
    /// are rebuilt by walking prefixes.
    table: Vec<(u16, u8)>,
    width: u32,
    prev: Option<u16>,
    acc: u32,
    bits: u32,
}

impl Lzw {
    pub fn new(early_change: bool) -> Self {
        Lzw {
            early: u32::from(early_change),
            table: Vec::new(),
            width: 9,
            prev: None,
            acc: 0,
            bits: 0,
        }
    }

    /// Entries in the table, including the 258 fixed codes.
    fn size(&self) -> usize {
        self.table.len().saturating_add(258)
    }

    /// The entry for `code`: (prefix or `u16::MAX`, byte); `None` beyond
    /// the table.
    fn entry(&self, code: u16) -> Option<(u16, u8)> {
        match code {
            0..=255 => Some((u16::MAX, u8::try_from(code).unwrap_or(0))),
            256 | 257 => Some((u16::MAX, 0)),
            _ => self
                .table
                .get(usize::from(code).saturating_sub(258))
                .copied(),
        }
    }

    /// Appends the string for `code` and returns its first byte.
    fn string(&self, code: u16, out: &mut Vec<u8>) -> Result<u8> {
        let start = out.len();
        let mut c = code;
        let mut guard = 0u32;
        loop {
            let (p, b) = self
                .entry(c)
                .ok_or_else(|| Diagnostic::malformed("invalid LZW code"))?;
            out.push(b);
            guard = guard.saturating_add(1);
            if p == u16::MAX || guard > 4096 {
                break;
            }
            c = p;
        }
        if let Some(s) = out.get_mut(start..) {
            s.reverse();
        }
        out.get(start)
            .copied()
            .ok_or_else(|| Diagnostic::malformed("invalid LZW code"))
    }

    /// Decodes one code; `false` at the end-of-data code.
    fn code(&mut self, code: u16, out: &mut Vec<u8>) -> Result<bool> {
        match code {
            256 => {
                self.table.clear();
                self.width = 9;
                self.prev = None;
                return Ok(true);
            }
            257 => return Ok(false),
            _ => {}
        }
        let next = u16::try_from(self.size()).unwrap_or(u16::MAX);
        match self.prev {
            None => {
                self.string(code, out)?;
            }
            Some(p) => {
                let first = if code < next {
                    self.string(code, out)?
                } else if code == next {
                    // KwKwK: the previous string plus its first byte.
                    let f = self.string(p, out)?;
                    out.push(f);
                    f
                } else {
                    return Err(Diagnostic::malformed("LZW code beyond the table"));
                };
                if self.size() < 4096 {
                    self.table.push((p, first));
                }
            }
        }
        self.prev = Some(code);
        let size = u32::try_from(self.size())
            .unwrap_or(4096)
            .saturating_add(self.early);
        self.width = if size >= 2048 {
            12
        } else if size >= 1024 {
            11
        } else if size >= 512 {
            10
        } else {
            9
        };
        Ok(true)
    }
}

impl ByteFilter for Lzw {
    fn byte(&mut self, byte: u8, out: &mut Vec<u8>) -> Result<bool> {
        self.acc = (self.acc << 8) | u32::from(byte);
        self.bits = self.bits.saturating_add(8);
        while self.bits >= self.width {
            let shift = self.bits.saturating_sub(self.width);
            let code = u16::try_from((self.acc >> shift) & (1u32 << self.width).wrapping_sub(1))
                .unwrap_or(0);
            self.bits = shift;
            self.acc &= (1u32 << self.bits).wrapping_sub(1);
            if !self.code(code, out)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// PNG row predictors (PDF `/Predictor` 10–15): every row starts with its
/// filter type. The previous row is read back from the output.
#[derive(Clone, Copy)]
pub struct PngPredictor {
    bpp: usize,
    row: usize,
    /// The current row's filter type (`None` before its first byte).
    kind: Option<u8>,
    /// Bytes of the current row decoded so far.
    col: usize,
    /// Where the current row starts in the output (once one has started).
    row_start: Option<usize>,
    /// Where the previous row starts (`None` in the first row).
    prev_start: Option<usize>,
}

impl PngPredictor {
    /// `bpp` is bytes per pixel, `row` bytes per row (each at least 1).
    pub fn new(bpp: usize, row: usize) -> Self {
        PngPredictor {
            bpp: bpp.max(1),
            row: row.max(1),
            kind: None,
            col: 0,
            row_start: None,
            prev_start: None,
        }
    }
}

impl ByteFilter for PngPredictor {
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool> {
        let Some(kind) = self.kind else {
            self.kind = Some(b);
            self.col = 0;
            if self.row_start.is_some() {
                self.prev_start = self.row_start;
            }
            self.row_start = Some(out.len());
            return Ok(true);
        };
        let col = self.col;
        let at = |base: Option<usize>, back: usize| -> u8 {
            base.and_then(|s| out.get(s.checked_add(col.checked_sub(back)?)?).copied())
                .unwrap_or(0)
        };
        let left = at(self.row_start, self.bpp);
        let up = at(self.prev_start, 0);
        let up_left = at(self.prev_start, self.bpp);
        let value = match kind {
            1 => b.wrapping_add(left),
            2 => b.wrapping_add(up),
            3 => b.wrapping_add(
                u8::try_from((u16::from(left).saturating_add(u16::from(up))) / 2).unwrap_or(0),
            ),
            4 => b.wrapping_add(paeth(left, up, up_left)),
            _ => b,
        };
        out.push(value);
        self.col = col.saturating_add(1);
        if self.col >= self.row {
            self.kind = None;
        }
        Ok(true)
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // The next row reads the current one; a row in progress reads the
        // one before.
        let keep = if self.kind.is_none() {
            self.row_start
        } else {
            self.prev_start.or(self.row_start)
        };
        keep.unwrap_or(out_len).min(out_len)
    }

    fn release_output(&mut self, n: usize) {
        self.row_start = self.row_start.map(|s| s.saturating_sub(n));
        self.prev_start = self.prev_start.map(|s| s.saturating_sub(n));
    }
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (ia, ib, ic) = (i16::from(a), i16::from(b), i16::from(c));
    let p = ia.saturating_add(ib).saturating_sub(ic);
    let (pa, pb, pc) = (
        p.saturating_sub(ia).abs(),
        p.saturating_sub(ib).abs(),
        p.saturating_sub(ic).abs(),
    );
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
    bpp: usize,
    row: usize,
    /// Bytes of the current row decoded so far.
    col: usize,
}

impl TiffPredictor {
    /// `bpp` is bytes per pixel, `row` bytes per row (each at least 1).
    pub fn new(bpp: usize, row: usize) -> Self {
        TiffPredictor {
            bpp: bpp.max(1),
            row: row.max(1),
            col: 0,
        }
    }
}

impl ByteFilter for TiffPredictor {
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool> {
        let left = if self.col >= self.bpp {
            out.len()
                .checked_sub(self.bpp)
                .and_then(|i| out.get(i))
                .copied()
                .unwrap_or(0)
        } else {
            0
        };
        out.push(b.wrapping_add(left));
        self.col = self.col.saturating_add(1);
        if self.col >= self.row {
            self.col = 0;
        }
        Ok(true)
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len.saturating_sub(self.col.min(self.bpp))
    }
}

/// Adobe Type 1 `eexec` decryption (key 55665), from binary or hex text;
/// the first four (random) plaintext bytes are dropped. Hex text ends at
/// the first character that is neither a hex digit nor whitespace.
#[derive(Clone, Copy)]
pub struct Eexec {
    hex: bool,
    high: Option<u8>,
    r: u16,
    skip: u8,
}

impl Eexec {
    pub fn new(hex: bool) -> Self {
        Eexec {
            hex,
            high: None,
            r: 55665,
            skip: 4,
        }
    }

    fn decrypt(&mut self, c: u8, out: &mut Vec<u8>) {
        let p = c ^ self.r.to_be_bytes()[0];
        self.r = u16::from(c)
            .wrapping_add(self.r)
            .wrapping_mul(52845)
            .wrapping_add(22719);
        if self.skip > 0 {
            self.skip = self.skip.saturating_sub(1);
        } else {
            out.push(p);
        }
    }
}

impl ByteFilter for Eexec {
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool> {
        if !self.hex {
            self.decrypt(b, out);
            return Ok(true);
        }
        if is_white(b) {
            return Ok(true);
        }
        let Some(v) = hex_value(b) else {
            return Ok(false);
        };
        match self.high.take() {
            Some(h) => self.decrypt(h << 4 | v, out),
            None => self.high = Some(v),
        }
        Ok(true)
    }
}

/// Type 1 decryption with seed `r`, dropping `skip` leading bytes (eexec:
/// 55665 and 4; charstrings: 4330 and lenIV).
pub fn type1_decrypt(data: &[u8], mut r: u16, skip: usize) -> Vec<u8> {
    let out: Vec<u8> = data
        .iter()
        .map(|&c| {
            let p = c ^ r.to_be_bytes()[0];
            r = u16::from(c)
                .wrapping_add(r)
                .wrapping_mul(52845)
                .wrapping_add(22719);
            p
        })
        .collect();
    out.get(skip..).unwrap_or_default().to_vec()
}

/// Decodes a whole in-memory buffer with a [`ByteFilter`] (tests and
/// inputs bounded by a small constant).
pub fn apply<F: ByteFilter>(filter: F, input: &[u8], limit: usize) -> Result<Vec<u8>> {
    crate::codec::pipeline::decode_all(
        &mut crate::codec::pipeline::Streaming(Bytes::new(filter)),
        input,
        limit,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ascii_filters() {
        let hex = |s: &[u8]| apply(AsciiHex::default(), s, 100).unwrap();
        let a85 = |s: &[u8]| apply(Ascii85::default(), s, 100).unwrap();
        assert_eq!(hex(b"48 65 6C6c6F 2>"), b"Hello ");
        assert_eq!(hex(b"4>"), b"@");
        assert_eq!(hex(b"4142>zz"), b"AB");
        assert_eq!(a85(b"87cURD]i,\"Ebo80~>"), b"Hello World!");
        assert_eq!(a85(b"<~z~>"), [0, 0, 0, 0]);
        assert_eq!(a85(b"9jqo^~>"), b"Man ");
        assert_eq!(a85(b"9jqo~>"), b"Man");
        // A leading `<` that does not start `<~` is a digit.
        assert_eq!(a85(b"<<<<<~>"), a85(b"<~<<<<<~>"));
        assert!(apply(Ascii85::default(), b"<", 100).is_err());
        assert!(apply(AsciiHex::default(), b"4g", 100).is_err());
    }

    #[test]
    fn run_length() {
        assert_eq!(
            apply(
                RunLength::default(),
                &[2, b'a', b'b', b'c', 254, b'x', 128, b'?'],
                100
            )
            .unwrap(),
            b"abcxxx"
        );
        assert_eq!(
            apply(PackBits::default(), &[128, 0, b'q', 255, b'z'], 100).unwrap(),
            b"qzz"
        );
        assert!(apply(RunLength::default(), &[2, b'a'], 100).is_err());
        assert!(apply(PackBits::default(), &[255], 100).is_err());
    }

    #[test]
    fn lzw_pdf_reference_example() {
        // PDF 1.7 reference, 7.4.4.2: "-----A---B" encoded with early change.
        let input = [0x80, 0x0b, 0x60, 0x50, 0x22, 0x0c, 0x0c, 0x85, 0x01];
        assert_eq!(apply(Lzw::new(true), &input, 100).unwrap(), b"-----A---B");
    }

    #[test]
    fn eexec_round_trip() {
        // Encrypt with the inverse transform, then decrypt.
        let plain = b"\0\0\0\0dup /Private 8 dict";
        let mut r = 55665u16;
        let enc: Vec<u8> = plain
            .iter()
            .map(|&p| {
                let c = p ^ r.to_be_bytes()[0];
                r = u16::from(c)
                    .wrapping_add(r)
                    .wrapping_mul(52845)
                    .wrapping_add(22719);
                c
            })
            .collect();
        assert_eq!(
            apply(Eexec::new(false), &enc, 100).unwrap(),
            b"dup /Private 8 dict"
        );
        let hex: String = enc.iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(
            apply(Eexec::new(true), hex.as_bytes(), 100).unwrap(),
            b"dup /Private 8 dict"
        );
        assert_eq!(type1_decrypt(&enc, 55665, 4), b"dup /Private 8 dict");
    }

    #[test]
    fn predictors() {
        // Two rows of 3 one-byte pixels: Sub and Up.
        let data = [1, 1, 1, 1, 2, 5, 5, 5];
        assert_eq!(
            apply(PngPredictor::new(1, 3), &data, 100).unwrap(),
            [1, 2, 3, 6, 7, 8]
        );
        assert_eq!(
            apply(TiffPredictor::new(1, 3), &[1, 1, 1, 5, 0, 0], 100).unwrap(),
            [1, 2, 3, 5, 5, 5]
        );
    }

    #[test]
    fn limits() {
        assert!(apply(RunLength::default(), &[129, b'x'], 100).is_err());
        assert!(apply(RunLength::default(), &[129, b'x'], 128).is_ok());
    }
}
