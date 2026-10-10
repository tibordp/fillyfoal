//! Text decoding helpers.

use crate::bytes::Endian;
use crate::bytes::to_usize;

pub mod url;

/// Decodes NUL-terminated UTF-16 from `data`. Returns the text, the number
/// of bytes consumed (including the terminator, if found) and whether a
/// terminator was found.
pub fn utf16z(data: &[u8], endian: Endian) -> (String, usize, bool) {
    let mut units = Vec::new();
    let mut at = 0usize;
    while let Some(pair) = data.get(at..at.saturating_add(2)) {
        let bytes = [
            pair.first().copied().unwrap_or(0),
            pair.get(1).copied().unwrap_or(0),
        ];
        let unit = match endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        };
        at = at.saturating_add(2);
        if unit == 0 {
            return (String::from_utf16_lossy(&units), at, true);
        }
        units.push(unit);
    }
    (String::from_utf16_lossy(&units), at, false)
}

/// Decodes UTF-16 of a known length (no terminator handling).
pub fn utf16(data: &[u8], endian: Endian) -> String {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&b| match endian {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// UTF-16 of a known length with trailing NULs removed (fixed-size name
/// fields).
pub fn utf16_trimmed(data: &[u8], endian: Endian) -> String {
    let mut s = utf16(data, endian);
    s.truncate(s.trim_end_matches('\0').len());
    s
}

/// The value of an ASCII hex digit.
pub fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Bytes from hex digits, ignoring ASCII whitespace; `None` on any other
/// character or an odd number of digits.
pub fn unhex(s: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let digits: Vec<u8> = s
        .as_ref()
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .map(hex_digit)
        .collect::<Option<_>>()?;
    let (pairs, rest) = digits.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    Some(pairs.iter().map(|&[h, l]| h << 4 | l).collect())
}

/// Lowercase hex of `bytes` (hashes, IDs).
pub fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Uppercase hex of `bytes`.
pub fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// ISO 8859-1: every byte is a code point.
pub fn latin1(data: &[u8]) -> String {
    data.iter().map(|&b| char::from(b)).collect()
}

/// Text up to the first NUL, decoded lossily as UTF-8.
pub fn until_nul(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(data.get(..end).unwrap_or_default()).into_owned()
}

/// Whether `data` looks like text: valid UTF-8 (allowing a cut-off final
/// character) with few control characters.
pub fn looks_like_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let valid = match std::str::from_utf8(data) {
        Ok(_) => data.len(),
        Err(e) if e.error_len().is_none() => e.valid_up_to(),
        Err(_) => return false,
    };
    let text = data.get(..valid).unwrap_or_default();
    let control = text
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c))
        .count();
    control.saturating_mul(100) <= to_usize(text.len() as u64)
}

/// Seconds between 1601-01-01 (Windows FILETIME epoch) and 1970-01-01.
const FILETIME_EPOCH: i64 = 11_644_473_600;
/// Seconds between 1904-01-01 (classic Mac / HFS epoch) and 1970-01-01.
pub const MAC_EPOCH: i64 = 2_082_844_800;

/// Windows FILETIME (100 ns ticks since 1601) to Unix seconds.
pub fn filetime_to_unix(ticks: u64) -> i64 {
    i64::try_from(ticks / 10_000_000)
        .unwrap_or(i64::MAX)
        .saturating_sub(FILETIME_EPOCH)
}

/// Seconds since 1904 (HFS, QuickTime/MP4, AIFF) to Unix seconds.
pub fn mac_to_unix(seconds: u64) -> i64 {
    i64::try_from(seconds)
        .unwrap_or(i64::MAX)
        .saturating_sub(MAC_EPOCH)
}

/// MS-DOS date and time fields as `YYYY-MM-DD hh:mm:ss`.
pub fn dos_datetime(date: u16, time: u16) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        1980u16.saturating_add(date >> 9),
        (date >> 5) & 0x0f,
        date & 0x1f,
        time >> 11,
        (time >> 5) & 0x3f,
        (time & 0x1f).saturating_mul(2)
    )
}
