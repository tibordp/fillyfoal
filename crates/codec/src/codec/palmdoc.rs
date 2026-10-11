//! The text records of a PalmDOC or Mobipocket book, decoded into one
//! stream: each record loses its trailing entries (the extra data the MOBI
//! header's flags announce: index data, and the bytes of a character that
//! continues into the next record) and is decompressed on its own with
//! PalmDOC's LZ77, or taken as it is.
//!
//! PalmDOC LZ77 (as calibre's `ebooks/compression/palmdoc` and the
//! MobileRead wiki describe it): a byte 0x01..=0x08 is followed by that
//! many literal bytes, 0x00 and 0x09..=0x7F are literals, 0xC0..=0xFF stand
//! for a space and the byte XOR 0x80, and 0x80..=0xBF start a two-byte
//! back-reference: 11 bits of distance, 3 bits of length (plus 3), into
//! the record's output.

use std::sync::Arc;

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// The most a text record may hold, encoded or decoded (records are 4 KiB
/// of text plus a few bytes of trailing entries).
pub const MAX_RECORD: usize = 64 * 1024;

fn ends_early() -> Diagnostic {
    Diagnostic::malformed("PalmDOC text record ends early")
}

/// The text records of a book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Book {
    /// The length of each record, in order (they follow each other).
    pub records: Arc<[u32]>,
    /// The MOBI header's extra data flags (0 for PalmDOC).
    pub trailing: u16,
    /// PalmDOC LZ77 (compression 2), or stored (1).
    pub compressed: bool,
}

/// The size of the trailing entries at the end of `record` (calibre's
/// `sizeof_trailing_entries`): one backward-encoded size per flag bit 1..15,
/// last entry first, then for bit 0 the overlapping bytes of a multi-byte
/// character, counted in the low two bits of the last byte left.
pub fn trailing_size(record: &[u8], flags: u16) -> usize {
    let mut num = 0usize;
    let mut bits = flags >> 1;
    while bits != 0 {
        if bits & 1 != 0 {
            let end = record.len().saturating_sub(num);
            // A backward varint: 7 bits per byte from the end, the first
            // (most significant) byte marked by its high bit.
            let mut size = 0usize;
            let mut shift = 0u32;
            let mut at = end;
            while at > 0 {
                at = at.saturating_sub(1);
                let v = record.get(at).copied().unwrap_or(0);
                size |= usize::from(v & 0x7f) << shift;
                shift = shift.saturating_add(7);
                if v & 0x80 != 0 || shift >= 28 {
                    break;
                }
            }
            num = num.saturating_add(size);
        }
        bits >>= 1;
    }
    if flags & 1 != 0 {
        let last = record
            .len()
            .checked_sub(num.saturating_add(1))
            .and_then(|i| record.get(i))
            .copied()
            .unwrap_or(0);
        num = num.saturating_add(usize::from(last & 3).saturating_add(1));
    }
    num
}

/// Decompresses one record's PalmDOC LZ77 data, appending to `out`.
pub fn lz77(data: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let start = out.len();
    let mut i = 0usize;
    while let Some(&c) = data.get(i) {
        i = i.saturating_add(1);
        match c {
            0x01..=0x08 => {
                let n = usize::from(c);
                let lit = data.get(i..i.saturating_add(n)).ok_or_else(ends_early)?;
                out.extend_from_slice(lit);
                i = i.saturating_add(n);
            }
            0x00 | 0x09..=0x7f => out.push(c),
            0x80..=0xbf => {
                let next = *data.get(i).ok_or_else(ends_early)?;
                i = i.saturating_add(1);
                let pair = u16::from(c) << 8 | u16::from(next);
                let distance = usize::from(pair >> 3 & 0x7ff);
                let len = usize::from(pair & 7).saturating_add(3);
                if distance == 0 || distance > out.len().saturating_sub(start) {
                    return Err(Diagnostic::malformed(
                        "PalmDOC back-reference before the record's start",
                    ));
                }
                let from = out.len().saturating_sub(distance);
                for k in 0..len {
                    let b = out.get(from.saturating_add(k)).copied().unwrap_or(0);
                    out.push(b);
                }
            }
            _ => {
                out.push(b' ');
                out.push(c ^ 0x80);
            }
        }
        if out.len().saturating_sub(start) > MAX_RECORD {
            return Err(Diagnostic::malformed(
                "PalmDOC text record decodes to over 64 KiB",
            ));
        }
    }
    Ok(())
}

/// Incremental decoder over the records; positions are relative to the
/// buffers as they are now. Between steps it is at a record boundary, and
/// no record reaches back into another.
#[derive(Clone, Debug)]
pub struct Records {
    book: Book,
    /// The next record.
    index: usize,
    /// Input position (where the next record starts).
    at: usize,
}

impl Records {
    pub fn new(book: Book) -> Self {
        Records {
            book,
            index: 0,
            at: 0,
        }
    }
}

impl Decode for Records {
    fn step(
        &mut self,
        input: &[u8],
        _eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let goal = out.len().saturating_add(step.max(1));
        while let Some(&len) = self.book.records.get(self.index) {
            if out.len() >= goal {
                return Ok(Step::More);
            }
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            if len > MAX_RECORD {
                return Err(Diagnostic::malformed("PalmDOC text record over 64 KiB"));
            }
            let record = input
                .get(self.at..self.at.saturating_add(len))
                .ok_or_else(ends_early)?;
            let trail = trailing_size(record, self.book.trailing);
            let text = record
                .get(
                    ..len.checked_sub(trail).ok_or_else(|| {
                        Diagnostic::malformed("trailing entries larger than the text record")
                    })?,
                )
                .unwrap_or_default();
            if self.book.compressed {
                lz77(text, out)?;
            } else {
                out.extend_from_slice(text);
            }
            if out.len() > limit {
                return Err(Diagnostic::output_limit(limit));
            }
            self.at = self.at.saturating_add(len);
            self.index = self.index.saturating_add(1);
        }
        Ok(Step::Done)
    }

    fn consumed(&self) -> usize {
        self.at
    }

    fn releasable_input(&self) -> usize {
        self.at
    }

    fn release_input(&mut self, n: usize) {
        self.at = self.at.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Records do not reach back into each other.
        out_len
    }

    fn heap_size(&self) -> Option<usize> {
        // The record lengths are shared.
        Some(0)
    }

    fn boundary(&self) -> Option<usize> {
        (self.index < self.book.records.len()).then_some(self.at)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{Streaming, decode_all, verify_checkpoints};

    #[test]
    fn lz77_tokens() {
        let mut out = Vec::new();
        // Literal, literal run, space pair, back-reference (distance 2,
        // length 3+2).
        lz77(b"ab\x02\x01\x02\xe3d\x80\x12", &mut out).unwrap();
        assert_eq!(out, b"ab\x01\x02 cdcdcdc");
        assert!(lz77(b"a\x80\x12", &mut Vec::new()).is_err());
    }

    #[test]
    fn trailing_entries_are_trimmed() {
        // One size entry (flag bit 1: 3 bytes, the varint included) and a
        // multi-byte overlap of 2 bytes (flag bit 0).
        let record = b"text\xe3\x81\x01\x00\x83";
        assert_eq!(trailing_size(record, 0b11), 3 + 2);
        assert_eq!(trailing_size(b"text\x82", 0b10), 2);
        assert_eq!(trailing_size(b"text", 0), 0);
    }

    #[test]
    fn records_decode_in_order_and_resume() {
        // Three records: stored text with a one-byte trailing entry each.
        let parts: [&[u8]; 3] = [b"first \x81", b"second \x81", b"third\x81"];
        let input: Vec<u8> = parts.concat();
        let book = Book {
            records: parts.iter().map(|p| p.len() as u32).collect(),
            trailing: 0b10,
            compressed: false,
        };
        let out = decode_all(&mut Streaming(Records::new(book.clone())), &input, 1 << 20).unwrap();
        assert_eq!(out, b"first second third");
        let (checked, _) = verify_checkpoints(
            || Box::new(Streaming(Records::new(book.clone()))),
            &input,
            1,
            1,
        )
        .unwrap();
        assert!(checked >= 2, "{checked}");
    }
}
