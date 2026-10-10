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
    if needle.is_empty() {
        return Some(from);
    }
    rest.windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p.saturating_add(from))
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
