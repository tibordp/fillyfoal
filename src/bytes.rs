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
