//! Bounds-checked integer decoding from byte slices.

fn array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
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
