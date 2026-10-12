//! Bounds-checked integer decoding from byte slices.

pub fn array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    data.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

pub fn u16_le(data: &[u8], offset: usize) -> Option<u16> {
    array(data, offset).map(u16::from_le_bytes)
}

pub fn u32_le(data: &[u8], offset: usize) -> Option<u32> {
    array(data, offset).map(u32::from_le_bytes)
}

pub fn u64_le(data: &[u8], offset: usize) -> Option<u64> {
    array(data, offset).map(u64::from_le_bytes)
}

pub fn u16_be(data: &[u8], offset: usize) -> Option<u16> {
    array(data, offset).map(u16::from_be_bytes)
}

pub fn u32_be(data: &[u8], offset: usize) -> Option<u32> {
    array(data, offset).map(u32::from_be_bytes)
}

pub fn u64_be(data: &[u8], offset: usize) -> Option<u64> {
    array(data, offset).map(u64::from_be_bytes)
}

/// Converts a byte count or offset to `usize`, saturating on 32-bit hosts.
pub fn to_usize(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

pub fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

pub fn u24_le(data: &[u8], offset: usize) -> Option<u32> {
    let b: [u8; 3] = array(data, offset)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], 0]))
}

pub fn u24_be(data: &[u8], offset: usize) -> Option<u32> {
    let b: [u8; 3] = array(data, offset)?;
    Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
}

pub fn i16_le(data: &[u8], offset: usize) -> Option<i16> {
    array(data, offset).map(i16::from_le_bytes)
}

pub fn i32_le(data: &[u8], offset: usize) -> Option<i32> {
    array(data, offset).map(i32::from_le_bytes)
}

pub fn i32_be(data: &[u8], offset: usize) -> Option<i32> {
    array(data, offset).map(i32::from_be_bytes)
}

/// Unsigned LEB128: the value and the number of bytes it occupies.
pub fn uleb128(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &byte) in data.iter().enumerate().take(10) {
        let shift = u32::try_from(i).ok()?.checked_mul(7)?;
        let bits = u64::from(byte & 0x7f).checked_shl(shift)?;
        value |= bits;
        if byte & 0x80 == 0 {
            return Some((value, i.checked_add(1)?));
        }
    }
    None
}

/// Signed LEB128: the value and the number of bytes it occupies.
pub fn sleb128(data: &[u8]) -> Option<(i64, usize)> {
    let mut value = 0i64;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate().take(10) {
        value |= i64::from(byte & 0x7f).checked_shl(shift)?;
        shift = shift.checked_add(7)?;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= (-1i64).checked_shl(shift)?;
            }
            return Some((value, i.checked_add(1)?));
        }
    }
    None
}

/// Byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// The first position at or after `from` where `needle` occurs in
/// `haystack`. An empty needle matches at `from` (if it is in range).
pub fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let rest = haystack.get(from..)?;
    let Some((&first, tail)) = needle.split_first() else {
        return Some(from);
    };
    // Candidates are found a word at a time: probes search whole heads
    // (66 KiB) for strings that are usually absent.
    let mut at = 0usize;
    loop {
        let p = at.checked_add(find_byte(rest.get(at..)?, first)?)?;
        let next = p.checked_add(1)?;
        if rest
            .get(next..next.checked_add(tail.len())?)
            .is_some_and(|w| w == tail)
        {
            return p.checked_add(from);
        }
        at = next;
    }
}

/// The first position of `byte` in `haystack`, examining eight bytes at a
/// time.
pub fn find_byte(haystack: &[u8], byte: u8) -> Option<usize> {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    let pattern = LO.wrapping_mul(u64::from(byte));
    let (chunks, remainder) = haystack.as_chunks::<8>();
    let mut base = 0usize;
    for &chunk in chunks {
        let word = u64::from_le_bytes(chunk) ^ pattern;
        // A zero byte of `word` is a match; the lowest flagged byte is
        // exact (false positives only appear above a true one).
        let zero = word.wrapping_sub(LO) & !word & HI;
        if zero != 0 {
            let lane = usize::try_from(zero.trailing_zeros().wrapping_div(8)).ok()?;
            return base.checked_add(lane);
        }
        base = base.checked_add(8)?;
    }
    remainder
        .iter()
        .position(|&b| b == byte)
        .and_then(|p| base.checked_add(p))
}

/// The last position where `needle` occurs in `haystack`.
pub fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(haystack.len());
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Whether `needle` occurs in `haystack`.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle, 0).is_some()
}

/// A big-endian base-128 integer (MIDI, MPEG-4 descriptors, WBMP, BPG): 7
/// bits per byte, most significant group first, high bit set on every byte
/// but the last. At most `max_len` bytes are read. Returns the value and the
/// number of bytes, or `None` if it is truncated, longer than `max_len`, or
/// overflows 64 bits.
pub fn vlq_be(data: &[u8], max_len: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &b) in data.iter().take(max_len).enumerate() {
        if value > u64::MAX >> 7 {
            return None;
        }
        value = value << 7 | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((value, i.saturating_add(1)));
        }
    }
    None
}

pub fn i16_be(data: &[u8], offset: usize) -> Option<i16> {
    array(data, offset).map(i16::from_be_bytes)
}

pub fn i64_le(data: &[u8], offset: usize) -> Option<i64> {
    array(data, offset).map(i64::from_le_bytes)
}

pub fn i64_be(data: &[u8], offset: usize) -> Option<i64> {
    array(data, offset).map(i64::from_be_bytes)
}

pub fn f32_le(data: &[u8], offset: usize) -> Option<f32> {
    array(data, offset).map(f32::from_le_bytes)
}

pub fn f32_be(data: &[u8], offset: usize) -> Option<f32> {
    array(data, offset).map(f32::from_be_bytes)
}

pub fn f64_le(data: &[u8], offset: usize) -> Option<f64> {
    array(data, offset).map(f64::from_le_bytes)
}

pub fn f64_be(data: &[u8], offset: usize) -> Option<f64> {
    array(data, offset).map(f64::from_be_bytes)
}

/// `v` rounded up to a multiple of `a` (`v` itself if `a` is 0), saturating
/// at `u64::MAX`.
pub fn align_up(v: u64, a: u64) -> u64 {
    if a == 0 {
        return v;
    }
    v.checked_next_multiple_of(a).unwrap_or(u64::MAX)
}

/// The padding that takes `v` to the next multiple of `a`.
pub fn padding(v: u64, a: u64) -> u64 {
    align_up(v, a).saturating_sub(v)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn search() {
        assert_eq!(find(b"abcabc", b"bc", 0), Some(1));
        assert_eq!(find(b"abcabc", b"bc", 2), Some(4));
        assert_eq!(find(b"abc", b"", 1), Some(1));
        assert_eq!(find(b"abc", b"x", 5), None);
        assert_eq!(rfind(b"abcabc", b"bc"), Some(4));
        assert!(contains(b"abc", b"c"));
        assert_eq!(find(b"abc", b"", 3), Some(3));
        assert_eq!(find(b"abc", b"", 4), None);
        assert_eq!(find(b"abc", b"abcd", 0), None);
    }

    /// The word-at-a-time search agrees with a naive one at every length,
    /// alignment and byte value (including 0x80 and 0x01 neighbours, which
    /// the zero-byte trick is sensitive to).
    #[test]
    fn word_search_matches_naive_search() {
        let naive = |h: &[u8], n: &[u8], from: usize| -> Option<usize> {
            let rest = h.get(from..)?;
            if n.is_empty() {
                return Some(from);
            }
            rest.windows(n.len()).position(|w| w == n).map(|p| p + from)
        };
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut data = Vec::new();
        for _ in 0..600 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.push([0u8, 1, 0x80, 0x81, 0xff, b'\n', b'a', b'b'][(x % 8) as usize]);
        }
        for len in 0..data.len() {
            let h = &data[..len];
            for byte in [0u8, 1, 0x80, 0x81, 0xff, b'\n', b'a', b'b', b'z'] {
                assert_eq!(
                    find_byte(h, byte),
                    h.iter().position(|&b| b == byte),
                    "{len} {byte}"
                );
            }
            if len % 7 == 0 {
                for needle in [&b"ab"[..], b"\n\x80", b"\x01\x00\x01", b"bb a"] {
                    for from in [0, 1, 5, len] {
                        assert_eq!(find(h, needle, from), naive(h, needle, from));
                    }
                }
            }
        }
    }

    #[test]
    fn vlq() {
        assert_eq!(vlq_be(&[0x00], 4), Some((0, 1)));
        assert_eq!(vlq_be(&[0x81, 0x00], 4), Some((0x80, 2)));
        assert_eq!(vlq_be(&[0xff, 0xff, 0xff, 0x7f], 4), Some((0x0fff_ffff, 4)));
        assert_eq!(vlq_be(&[0x80, 0x80, 0x80, 0x80, 0x00], 4), None);
        assert_eq!(vlq_be(&[0x80], 4), None);
    }

    #[test]
    fn alignment() {
        assert_eq!(align_up(5, 4), 8);
        assert_eq!(align_up(8, 4), 8);
        assert_eq!(align_up(5, 0), 5);
        assert_eq!(padding(5, 4), 3);
        assert_eq!(align_up(u64::MAX, 4), u64::MAX);
    }
}
