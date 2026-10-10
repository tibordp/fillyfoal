//! Cap'n Proto encoding: the stream framing's segment table and pointers.
//!
//! From the encoding specification (capnproto.org/encoding.html): a message
//! is a segment table (`u32` segment count minus one, a `u32` size in
//! 8-byte words per segment, padding to a word) followed by the segments.
//! Every pointer is one little-endian word whose low two bits say what it
//! is; offsets count words from the end of the pointer.

use crate::value::EnumTable;

/// Bytes per word.
pub const WORD: u64 = 8;

/// The most segments accepted (the reference implementation's limit).
pub const MAX_SEGMENTS: u32 = 512;

/// List element sizes.
pub const ELEMENT_SIZES: EnumTable = &[
    (0, "VOID"),
    (1, "BIT"),
    (2, "BYTE"),
    (3, "TWO_BYTES"),
    (4, "FOUR_BYTES"),
    (5, "EIGHT_BYTES"),
    (6, "POINTER"),
    (7, "INLINE_COMPOSITE"),
];

/// Bits per element of a list with element size code `elem` (composite
/// lists: 0, the size comes from their tag).
pub fn element_bits(elem: u8) -> u64 {
    match elem {
        1 => 1,
        2 => 8,
        3 => 16,
        4 => 32,
        5 | 6 => 64,
        _ => 0,
    }
}

/// A decoded pointer word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pointer {
    /// All zero.
    Null,
    /// A struct: offset to its data section and the section sizes in words.
    Struct { offset: i32, data: u16, ptrs: u16 },
    /// A list: offset to its first element, element size code, and the
    /// element count (the word count for composite lists).
    List { offset: i32, elem: u8, count: u32 },
    /// A far pointer: to a landing pad in another segment, which is a
    /// single pointer or (`double`) a far pointer and a tag.
    Far {
        double: bool,
        offset: u32,
        segment: u32,
    },
    /// A capability: an index into the message's capability table.
    Capability { index: u32 },
    /// Type 3 with a nonzero reserved part.
    Reserved(u64),
}

/// The 30-bit signed offset in bits 2..32 of a struct or list pointer.
fn offset30(word: u64) -> i32 {
    let low = u32::try_from(word & 0xffff_ffff).unwrap_or(0);
    low.cast_signed() >> 2
}

fn hi(word: u64) -> u32 {
    u32::try_from(word >> 32).unwrap_or(0)
}

/// Decodes a pointer word.
pub fn pointer(word: u64) -> Pointer {
    if word == 0 {
        return Pointer::Null;
    }
    match word & 3 {
        0 => Pointer::Struct {
            offset: offset30(word),
            data: u16::try_from((word >> 32) & 0xffff).unwrap_or(0),
            ptrs: u16::try_from(word >> 48).unwrap_or(0),
        },
        1 => Pointer::List {
            offset: offset30(word),
            elem: u8::try_from((word >> 32) & 7).unwrap_or(0),
            count: hi(word) >> 3,
        },
        2 => Pointer::Far {
            double: word & 4 != 0,
            offset: u32::try_from((word >> 3) & 0x1fff_ffff).unwrap_or(0),
            segment: hi(word),
        },
        _ if word & 0xffff_fffc == 0 => Pointer::Capability { index: hi(word) },
        _ => Pointer::Reserved(word),
    }
}

/// The word a struct or list pointer at word `at` points to.
pub fn target(at: u64, offset: i32) -> Option<u64> {
    let next = at.checked_add(1)?;
    if offset >= 0 {
        next.checked_add(u64::from(offset.unsigned_abs()))
    } else {
        next.checked_sub(u64::from(offset.unsigned_abs()))
    }
}

/// The stream framing's segment table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentTable {
    /// Size of the table, padding included, in bytes.
    pub len: u64,
    /// Each segment's start (relative to the message) and size in words.
    pub segments: Vec<(u64, u64)>,
}

impl SegmentTable {
    /// The size of the whole message in bytes.
    pub fn message_len(&self) -> u64 {
        self.segments.last().map_or(self.len, |&(start, words)| {
            start.saturating_add(words.saturating_mul(WORD))
        })
    }
}

/// Bytes needed to read the segment table whose first word is `head`.
pub fn table_len(segment_count_minus_one: u32) -> Option<u64> {
    let n = u64::from(segment_count_minus_one).checked_add(1)?;
    // 4 bytes of count plus 4 per segment, rounded up to a word.
    let raw = n.checked_mul(4)?.checked_add(4)?;
    Some(raw.checked_add(7)? & !7)
}

/// Parses a segment table from the start of `data`; `None` if it is
/// truncated or has more than [`MAX_SEGMENTS`] segments.
pub fn segment_table(data: &[u8]) -> Option<SegmentTable> {
    let minus_one = crate::bytes::u32_le(data, 0)?;
    if minus_one >= MAX_SEGMENTS {
        return None;
    }
    let len = table_len(minus_one)?;
    let mut segments = Vec::new();
    let mut start = len;
    for i in 0..=minus_one {
        let at = usize::try_from(i).ok()?.checked_mul(4)?.checked_add(4)?;
        let words = u64::from(crate::bytes::u32_le(data, at)?);
        segments.push((start, words));
        start = start.checked_add(words.checked_mul(WORD)?)?;
    }
    Some(SegmentTable { len, segments })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_pointers() {
        // Struct, offset 0, 1 data word, 2 pointers.
        assert_eq!(
            pointer(0x0002_0001_0000_0000),
            Pointer::Struct {
                offset: 0,
                data: 1,
                ptrs: 2
            }
        );
        // List of bytes, offset -2, 5 elements.
        let word = ((5u64 << 3 | 2) << 32) | (u64::from((-2i32).cast_unsigned() << 2) | 1);
        assert_eq!(
            pointer(word),
            Pointer::List {
                offset: -2,
                elem: 2,
                count: 5
            }
        );
        assert_eq!(target(10, -2), Some(9));
        assert_eq!(pointer(3 | (7 << 32)), Pointer::Capability { index: 7 });
        assert_eq!(
            pointer(2 | 4 | (3 << 3) | (1 << 32)),
            Pointer::Far {
                double: true,
                offset: 3,
                segment: 1
            }
        );
    }

    #[test]
    fn reads_segment_tables() {
        let t = segment_table(&[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]).unwrap_or(
            SegmentTable {
                len: 0,
                segments: Vec::new(),
            },
        );
        assert_eq!(t.len, 16);
        assert_eq!(t.segments, vec![(16, 2), (32, 3)]);
        assert_eq!(t.message_len(), 56);
    }
}
