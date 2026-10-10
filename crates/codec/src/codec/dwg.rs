//! The LZ77 variant of AutoCAD R2004+ DWG files (also R2010, R2013 and
//! R2018), which compresses the system pages (section page map, section
//! map) and the pages of the named sections (`AcDb:Header`,
//! `AcDb:AcDbObjects`, ...), each on its own.
//!
//! The layout is the one in the Open Design Alliance's "Open Design
//! Specification for .dwg files" (section "Compression"), as remembered;
//! no real AutoCAD output was available to check it against, so the tests
//! are spec-derived vectors and round trips through a test encoder.
//!
//! The stream starts with a literal length (see `literal_length`) and that
//! many literal bytes. Then opcodes follow, each a back-reference that also
//! says how many literals come after it:
//!
//! | opcode | length | offset | literals |
//! |---|---|---|---|
//! | `0x40..=0xff` | `(op >> 4) - 1` | `next << 2 \| (op >> 2) & 3` | `op & 3`, or a literal length |
//! | `0x21..=0x3f` | `op - 0x1e` | two-byte offset | in the offset, or a literal length |
//! | `0x20` | long length `+ 0x21` | two-byte offset | in the offset, or a literal length |
//! | `0x12..=0x1f` | `(op & 0xf) + 2` | two-byte offset `+ 0x3fff` | in the offset, or a literal length |
//! | `0x10` | long length `+ 9` | two-byte offset `+ 0x3fff` | in the offset, or a literal length |
//! | `0x11` | end of the stream | | |
//!
//! A back-reference copies `length` bytes from `offset + 1` bytes back
//! (overlapping copies repeat). A two-byte offset is `b0 >> 2 | b1 << 6`,
//! with the literal count in the low two bits of `b0`. A literal length is
//! `b + 3` for a byte `b` in `1..=15`; `0x00` starts an extended length
//! (`0x0f`, plus `0xff` per further zero byte, plus the first nonzero byte,
//! plus 3); a byte of `0x10` or more is the next opcode (no literals). A
//! long length is a byte `b` if nonzero, else `0xff` plus `0xff` per further
//! zero byte plus the first nonzero byte.

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// The longest back-reference distance: offset `0x3fff + 0x3fff`, plus one.
const WINDOW: usize = 0x8000;

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("DWG LZ77: {what}"))
}

/// Incremental decoder of one compressed page. Positions are relative to
/// the buffers as they are now (see "Releasing" in the pipeline docs).
#[derive(Clone, Debug)]
pub struct Lz77 {
    /// Decompressed size of the page (from its header): decoding stops
    /// there even without an end opcode, and more output is an error.
    size: u64,
    produced: u64,
    pos: usize,
    started: bool,
    /// An opcode read while looking for a literal length.
    pending: Option<u8>,
}

impl Lz77 {
    pub fn new(size: u64) -> Self {
        Lz77 {
            size,
            produced: 0,
            pos: 0,
            started: false,
            pending: None,
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8> {
        let b = self
            .data
            .get(self.pos)
            .copied()
            .ok_or_else(|| bad("stream ended early"))?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    /// A literal length, or the opcode that follows when there are none.
    fn literal_length(&mut self) -> Result<(usize, Option<u8>)> {
        let b = self.byte()?;
        match b {
            0x01..=0x0f => Ok((usize::from(b).saturating_add(3), None)),
            0x00 => {
                let mut total = 0x0fusize;
                loop {
                    let next = self.byte()?;
                    if next != 0 {
                        return Ok((
                            total.saturating_add(usize::from(next)).saturating_add(3),
                            None,
                        ));
                    }
                    total = total.saturating_add(0xff);
                }
            }
            op => Ok((0, Some(op))),
        }
    }

    fn long_length(&mut self) -> Result<usize> {
        let b = self.byte()?;
        if b != 0 {
            return Ok(usize::from(b));
        }
        let mut total = 0xffusize;
        loop {
            let next = self.byte()?;
            if next != 0 {
                return Ok(total.saturating_add(usize::from(next)));
            }
            total = total.saturating_add(0xff);
        }
    }

    /// A two-byte offset and the literal count in its low bits.
    fn two_byte_offset(&mut self) -> Result<(usize, usize)> {
        let b0 = self.byte()?;
        let b1 = self.byte()?;
        Ok((
            usize::from(b0 >> 2) | usize::from(b1) << 6,
            usize::from(b0 & 3),
        ))
    }

    /// Literals after a back-reference: `lits` if nonzero, else a literal
    /// length (which may be the next opcode instead).
    fn trailing(&mut self, lits: usize) -> Result<(usize, Option<u8>)> {
        if lits != 0 {
            Ok((lits, None))
        } else {
            self.literal_length()
        }
    }
}

impl Lz77 {
    fn copy_literals(
        &mut self,
        r: &mut Reader<'_>,
        out: &mut Vec<u8>,
        n: usize,
        limit: usize,
    ) -> Result<()> {
        let end = r.pos.saturating_add(n);
        let lits = r
            .data
            .get(r.pos..end)
            .ok_or_else(|| bad("stream ended inside literals"))?;
        self.grow(out.len(), n, limit)?;
        out.extend_from_slice(lits);
        r.pos = end;
        Ok(())
    }

    /// Checks that `n` more bytes fit the page and the limit.
    fn grow(&mut self, out_len: usize, n: usize, limit: usize) -> Result<()> {
        let n64 = crate::bytes::to_u64(n);
        let produced = self.produced.saturating_add(n64);
        if produced > self.size {
            return Err(bad("page decodes to more than its size"));
        }
        if out_len.saturating_add(n) > limit {
            return Err(Diagnostic::output_limit(limit));
        }
        self.produced = produced;
        Ok(())
    }
}

impl Decode for Lz77 {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let goal = out.len().saturating_add(step);
        let mut r = Reader {
            data: input,
            pos: self.pos,
        };
        if !self.started {
            let (n, op) = r.literal_length()?;
            self.copy_literals(&mut r, out, n, limit)?;
            self.started = true;
            self.pending = op;
            self.pos = r.pos;
        }
        loop {
            if self.produced >= self.size {
                return Ok(Step::Done);
            }
            if out.len() >= goal {
                return Ok(Step::More);
            }
            let op = match self.pending.take() {
                Some(op) => op,
                None if eof && r.pos >= input.len() => return Ok(Step::Done),
                None => r.byte()?,
            };
            let (length, offset, lits) = match op {
                0x40..=0xff => {
                    let next = r.byte()?;
                    let length = usize::from(op >> 4).saturating_sub(1);
                    let offset = usize::from(next) << 2 | usize::from(op >> 2 & 3);
                    (length, offset, usize::from(op & 3))
                }
                0x21..=0x3f => {
                    let (offset, lits) = r.two_byte_offset()?;
                    (usize::from(op).saturating_sub(0x1e), offset, lits)
                }
                0x20 => {
                    let length = r.long_length()?.saturating_add(0x21);
                    let (offset, lits) = r.two_byte_offset()?;
                    (length, offset, lits)
                }
                0x12..=0x1f => {
                    let (offset, lits) = r.two_byte_offset()?;
                    (
                        usize::from(op & 0x0f).saturating_add(2),
                        offset.saturating_add(0x3fff),
                        lits,
                    )
                }
                0x10 => {
                    let length = r.long_length()?.saturating_add(9);
                    let (offset, lits) = r.two_byte_offset()?;
                    (length, offset.saturating_add(0x3fff), lits)
                }
                0x11 => {
                    self.pos = r.pos;
                    return Ok(Step::Done);
                }
                _ => return Err(bad(&format!("invalid opcode {op:#04x}"))),
            };
            let (lits, next) = r.trailing(lits)?;
            // The back-reference.
            let distance = offset.saturating_add(1);
            let start = out
                .len()
                .checked_sub(distance)
                .ok_or_else(|| bad("back-reference before the start of the page"))?;
            self.grow(out.len(), length, limit)?;
            out.reserve(length);
            for i in 0..length {
                let b = out
                    .get(start.saturating_add(i))
                    .copied()
                    .ok_or_else(|| bad("bad back-reference"))?;
                out.push(b);
            }
            self.copy_literals(&mut r, out, lits, limit)?;
            self.pending = next;
            self.pos = r.pos;
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
        out_len.saturating_sub(WINDOW)
    }

    fn heap_size(&self) -> Option<usize> {
        // The window is in `out`.
        Some(0)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
pub(crate) mod tests {
    use super::*;
    use crate::codec::pipeline::{Decoder, Streaming, decode_all};
    use std::collections::HashMap;

    fn literal_length(out: &mut Vec<u8>, n: usize) {
        assert!(n >= 4);
        if n <= 0x12 {
            out.push((n - 3) as u8);
        } else {
            out.push(0);
            let mut r = n - 0x12;
            while r > 0xff {
                out.push(0);
                r -= 0xff;
            }
            out.push(r as u8);
        }
    }

    fn long_length(out: &mut Vec<u8>, v: usize) {
        assert!(v >= 1);
        if v <= 0xff {
            out.push(v as u8);
        } else {
            out.push(0);
            let mut r = v - 0xff;
            while r > 0xff {
                out.push(0);
                r -= 0xff;
            }
            out.push(r as u8);
        }
    }

    /// The opcode bytes of a back-reference, and the index of the byte
    /// that takes the literal count (all but the `0x40` form put it in the
    /// first offset byte).
    fn opcode(len: usize, offset: usize) -> Option<(Vec<u8>, usize)> {
        if (3..=14).contains(&len) && offset <= 0x3ff {
            return Some((
                vec![
                    ((len + 1) << 4 | (offset & 3) << 2) as u8,
                    (offset >> 2) as u8,
                ],
                0,
            ));
        }
        let (mut v, o) = if offset <= 0x3fff && len >= 3 {
            if len <= 0x21 {
                (vec![(len + 0x1e) as u8], offset)
            } else {
                let mut v = vec![0x20];
                long_length(&mut v, len - 0x21);
                (v, offset)
            }
        } else if offset > 0x3fff && offset <= 0x7ffe && len >= 4 {
            if len <= 17 {
                (vec![(0x10 | (len - 2)) as u8], offset - 0x3fff)
            } else {
                let mut v = vec![0x10];
                long_length(&mut v, len - 9);
                (v, offset - 0x3fff)
            }
        } else {
            return None;
        };
        let at = v.len();
        v.push(((o & 0x3f) << 2) as u8);
        v.push((o >> 6) as u8);
        Some((v, at))
    }

    /// Writes a back-reference opcode followed by `lits`.
    fn token(out: &mut Vec<u8>, op: Option<(Vec<u8>, usize)>, lits: &[u8]) {
        match op {
            None => literal_length(out, lits.len()),
            Some((mut op, at)) => {
                let k = lits.len();
                if (1..=3).contains(&k) {
                    op[at] |= k as u8;
                    out.extend_from_slice(&op);
                } else {
                    out.extend_from_slice(&op);
                    if k > 0 {
                        literal_length(out, k);
                    }
                }
            }
        }
        out.extend_from_slice(lits);
    }

    /// A greedy encoder of the format in the module docs (the inverse of
    /// the decoder, written from the same description). Needs at least 4
    /// bytes: the first literal run cannot be shorter.
    pub(crate) fn compress(data: &[u8]) -> Vec<u8> {
        assert!(data.len() >= 4);
        let n = data.len();
        let mut out = Vec::new();
        let mut chains: HashMap<[u8; 3], Vec<usize>> = HashMap::new();
        let mut pending: Option<(Vec<u8>, usize)> = None;
        let mut lit_start = 0;
        let mut pos = 0;
        let index = |chains: &mut HashMap<[u8; 3], Vec<usize>>, at: usize| {
            if at + 3 <= n {
                chains
                    .entry([data[at], data[at + 1], data[at + 2]])
                    .or_default()
                    .push(at);
            }
        };
        while pos < n {
            let mut best: Option<(usize, usize)> = None;
            if pos >= 4 && pos + 3 <= n {
                let key = [data[pos], data[pos + 1], data[pos + 2]];
                for &cand in chains
                    .get(&key)
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .rev()
                    .take(64)
                {
                    let dist = pos - cand;
                    if dist > 0x7fff {
                        break;
                    }
                    let mut l = 0;
                    while pos + l < n && data[cand + l] == data[pos + l] && l < 0x300 {
                        l += 1;
                    }
                    if opcode(l, dist - 1).is_some() && best.is_none_or(|(bl, _)| l > bl) {
                        best = Some((l, dist));
                    }
                }
            }
            let Some((len, dist)) = best else {
                index(&mut chains, pos);
                pos += 1;
                continue;
            };
            token(&mut out, pending.take(), &data[lit_start..pos]);
            pending = opcode(len, dist - 1);
            for at in pos..pos + len {
                index(&mut chains, at);
            }
            pos += len;
            lit_start = pos;
        }
        if pending.is_some() || lit_start < n {
            token(&mut out, pending.take(), &data[lit_start..n]);
        }
        out.push(0x11);
        out
    }

    fn run(data: &[u8], size: u64) -> Result<Vec<u8>> {
        decode_all(&mut Streaming(Lz77::new(size)), data, 1 << 20)
    }

    /// One token of every kind, written by hand from the opcode table in
    /// the module docs.
    #[test]
    fn every_opcode() {
        let mut s = Vec::new();
        let mut want: Vec<u8> = Vec::new();
        let copy = |want: &mut Vec<u8>, dist: usize, len: usize| {
            for _ in 0..len {
                want.push(want[want.len() - dist]);
            }
        };
        // A 4-byte literal run (length byte 1).
        s.extend_from_slice(&[0x01, b'a', b'b', b'c', b'd']);
        want.extend_from_slice(b"abcd");
        // 0x40 form: length 3 (high nibble 4), offset 3, one inline literal.
        s.extend_from_slice(&[0x40 | 3 << 2 | 1, 0, b'e']);
        copy(&mut want, 4, 3);
        want.push(b'e');
        // 0x21..0x3f: length 5 (0x23), offset 7, literal count 0 and a
        // literal length byte of 1 (4 literals).
        s.extend_from_slice(&[0x23, 7 << 2, 0, 0x01, b'w', b'x', b'y', b'z']);
        copy(&mut want, 8, 5);
        want.extend_from_slice(b"wxyz");
        // 0x20: long length 2 (+0x21), offset 0 (repeat the last byte),
        // then an extended literal length of 0x4000 (a far copy needs that
        // much history): 0x00, 0x3f zero bytes, then 0x13.
        s.extend_from_slice(&[0x20, 2, 0, 0, 0x00]);
        copy(&mut want, 1, 0x23);
        let mut r = 0x4000 - 0x12;
        while r > 0xff {
            s.push(0);
            r -= 0xff;
        }
        s.push(r as u8);
        let filler: Vec<u8> = (0..0x4000u32).map(|i| (i * 7 % 251) as u8).collect();
        s.extend_from_slice(&filler);
        want.extend_from_slice(&filler);
        // 0x12..0x1f: length 17 (0x1f), offset 0x3fff + 1, two literals.
        s.extend_from_slice(&[0x1f, 1 << 2 | 2, 0, b'p', b'q']);
        copy(&mut want, 0x4001, 17);
        want.extend_from_slice(b"pq");
        // 0x10: long length 1 (+9), offset 0x3fff + 0x40, one literal.
        s.extend_from_slice(&[0x10, 1, 1, 1, b'!']);
        copy(&mut want, 0x4040, 10);
        want.push(b'!');
        // The end opcode; what follows is not consumed.
        s.extend_from_slice(&[0x11, 0xaa, 0xbb]);
        let mut d = Streaming(Lz77::new(1 << 20));
        assert_eq!(decode_all(&mut d, &s, 1 << 20).unwrap(), want);
        assert_eq!(d.consumed(), s.len() - 2);
        // Without the end opcode, decoding stops at the page size.
        s.truncate(s.len() - 3);
        assert_eq!(run(&s, want.len() as u64).unwrap(), want);
    }

    #[test]
    fn round_trip() {
        let mut data = Vec::new();
        for i in 0..40_000u32 {
            data.push((i % 13) as u8);
            if i % 97 == 0 {
                data.extend_from_slice(b"AcDb:AcDbObjects");
            }
            if i % 1000 == 0 {
                data.extend((0..300).map(|j| (j * i) as u8));
            }
        }
        // Far repeats (beyond 0x3fff).
        let copy = data[100..600].to_vec();
        data.extend_from_slice(&copy);
        let packed = compress(&data);
        assert!(packed.len() < data.len() / 4);
        assert!(
            packed
                .iter()
                .any(|&b| b == 0x10 || (0x12..=0x1f).contains(&b))
        );
        assert_eq!(run(&packed, data.len() as u64).unwrap(), data);
        // Literals only.
        let text = b"no repeats here: 0123456789".to_vec();
        assert_eq!(run(&compress(&text), 1000).unwrap(), text);
        // Long runs (0x20 and 0x10 long lengths).
        let zeros = vec![0u8; 3000];
        assert_eq!(run(&compress(&zeros), 3000).unwrap(), zeros);
    }

    #[test]
    fn checkpoints_resume_mid_stream() {
        let mut data = include_bytes!("testdata/words.txt").to_vec();
        data.extend((0..20_000u32).map(|i| (i % 13) as u8));
        // Far repeats (beyond 0x3fff).
        let copy = data[100..9000].to_vec();
        data.extend_from_slice(&copy);
        let packed = compress(&data);
        let size = data.len() as u64;
        let (checked, largest) = crate::codec::pipeline::verify_checkpoints(
            || Box::new(Streaming(Lz77::new(size))),
            &packed,
            2000,
            3,
        )
        .unwrap();
        assert!(checked > 10, "{checked}");
        assert_eq!(largest, std::mem::size_of::<Lz77>());
    }

    #[test]
    fn errors() {
        // A copy before the start.
        assert!(run(&[0x01, 1, 2, 3, 4, 0x41, 9, 0x11], 100).is_err());
        // Output beyond the page size.
        assert!(run(&compress(&[7; 100]), 50).is_err());
        // Truncated literals.
        assert!(run(&[0x05, 1, 2, 3], 100).is_err());
        // An invalid opcode.
        assert!(run(&[0x01, 1, 2, 3, 4, 0x0f, 0x11], 100).is_err());
        // Over the limit.
        assert!(
            decode_all(
                &mut Streaming(Lz77::new(1 << 30)),
                &compress(&[0; 5000]),
                1000
            )
            .is_err()
        );
    }
}
