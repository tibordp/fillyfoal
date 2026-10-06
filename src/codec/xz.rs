//! The `.xz` container: streams of blocks, each decoded through its filter
//! chain (LZMA2, optionally preceded by BCJ or Delta), with integrity
//! checks.

use crate::codec::crypto::{Hash, Sha256};
use crate::codec::filters::Filter;
use crate::codec::lzma::{Post, lzma2};
use crate::error::{Diagnostic, Result};
pub use crate::codec::crc::crc64;

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("xz: {what}"))
}

const MAGIC: &[u8; 6] = b"\xfd7zXZ\0";

/// A multibyte integer (7 bits per byte, little-endian groups).
fn varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut v = 0u64;
    for i in 0..9u32 {
        let b = *data.get(*pos).ok_or_else(|| bad("truncated integer"))?;
        *pos = pos.saturating_add(1);
        v |= u64::from(b & 0x7f) << i.wrapping_mul(7);
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(bad("integer too long"))
}

#[derive(Clone, Copy)]
pub struct Xz;

impl Filter for Xz {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        let mut streams = 0u32;
        loop {
            // Stream padding (multiples of four zero bytes) between streams.
            while streams > 0 && input.get(pos..pos.saturating_add(4)) == Some(&[0, 0, 0, 0][..]) {
                pos = pos.saturating_add(4);
            }
            match input.get(pos..pos.saturating_add(6)) {
                Some(m) if m == MAGIC => {}
                _ if streams == 0 => return Err(bad("not an xz stream")),
                _ => return Ok(out),
            }
            streams = streams.saturating_add(1);
            let check = input.get(pos.saturating_add(7)).copied().unwrap_or(0) & 0x0f;
            let check_len: usize = match check {
                0 => 0,
                1 => 4,
                4 => 8,
                10 => 32,
                c => 4usize << ((usize::from(c).saturating_sub(1)) / 3),
            };
            pos = pos.saturating_add(12);
            // Blocks until the index (a zero header-size byte).
            loop {
                let size_byte = *input.get(pos).ok_or_else(|| bad("truncated block"))?;
                if size_byte == 0 {
                    break;
                }
                let header_len = (usize::from(size_byte).saturating_add(1)).saturating_mul(4);
                let header = input.get(pos..pos.saturating_add(header_len)).ok_or_else(|| bad("truncated block header"))?;
                let flags = header.get(1).copied().unwrap_or(0);
                let mut hp = 2usize;
                let packed = if flags & 0x40 != 0 { Some(varint(header, &mut hp)?) } else { None };
                if flags & 0x80 != 0 {
                    varint(header, &mut hp)?;
                }
                let filters = usize::from(flags & 3).saturating_add(1);
                let mut posts = Vec::new();
                let mut have_lzma2 = false;
                for _ in 0..filters {
                    let id = varint(header, &mut hp)?;
                    let props_len = usize::try_from(varint(header, &mut hp)?).unwrap_or(usize::MAX);
                    let props = header.get(hp..hp.saturating_add(props_len)).ok_or_else(|| bad("truncated filter properties"))?;
                    hp = hp.saturating_add(props_len);
                    match id {
                        0x21 => have_lzma2 = true,
                        0x03 => posts.push(Post::Delta(usize::from(props.first().copied().unwrap_or(0)).saturating_add(1))),
                        0x04 => posts.push(Post::X86),
                        0x07 => posts.push(Post::Arm),
                        0x0a => posts.push(Post::Arm64),
                        other => return Err(Diagnostic::unsupported(format!("xz filter {other:#x}"))),
                    }
                }
                if !have_lzma2 {
                    return Err(Diagnostic::unsupported("xz block without LZMA2"));
                }
                let data_start = pos.saturating_add(header_len);
                let data = match packed {
                    Some(n) => input.get(data_start..data_start.saturating_add(usize::try_from(n).unwrap_or(usize::MAX))).ok_or_else(|| bad("truncated block data"))?,
                    None => input.get(data_start..).unwrap_or_default(),
                };
                let mut block = lzma2(data, limit.saturating_sub(out.len()))?;
                // Filters listed before LZMA2 are applied after it, last first.
                for post in posts.iter().rev() {
                    post.apply(&mut block);
                }
                // Find the end of the compressed data: re-run to learn the
                // consumed size when it was not recorded.
                let consumed = match packed {
                    Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
                    None => lzma2_len(data)?,
                };
                let mut end = data_start.saturating_add(consumed);
                end = end.next_multiple_of(4);
                let stored = input.get(end..end.saturating_add(check_len)).ok_or_else(|| bad("truncated check"))?;
                let ok = match check {
                    1 => crate::codec::crc32(&block).to_le_bytes().as_slice() == stored,
                    4 => crc64(&block).to_le_bytes().as_slice() == stored,
                    10 => Sha256::digest(&block).as_slice() == stored,
                    _ => true,
                };
                if !ok {
                    return Err(bad("block check mismatch"));
                }
                out.extend_from_slice(&block);
                pos = end.saturating_add(check_len);
            }
            // Index: records, padding, CRC32; then the 12-byte footer.
            let mut ip = pos.saturating_add(1);
            let records = varint(input, &mut ip)?;
            for _ in 0..records.min(1 << 24) {
                varint(input, &mut ip)?;
                varint(input, &mut ip)?;
            }
            ip = ip.next_multiple_of(4).saturating_add(4);
            pos = ip.saturating_add(12);
        }
    }
}

/// The length of an LZMA2 stream (its chunks up to the end marker).
fn lzma2_len(data: &[u8]) -> Result<usize> {
    let mut pos = 0usize;
    loop {
        let control = *data.get(pos).ok_or_else(|| bad("truncated LZMA2 data"))?;
        let h = |i: usize| usize::from(data.get(pos.saturating_add(i)).copied().unwrap_or(0));
        pos = pos.saturating_add(match control {
            0 => return Ok(pos.saturating_add(1)),
            1 | 2 => 3usize.saturating_add((h(1) << 8 | h(2)).saturating_add(1)),
            0x80..=0xff => {
                let packed = (h(3) << 8 | h(4)).saturating_add(1);
                let props = usize::from((control >> 5) & 3 >= 2);
                5usize.saturating_add(props).saturating_add(packed)
            }
            _ => return Err(bad("invalid LZMA2 control byte")),
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn crc64_check_value() {
        assert_eq!(crc64(b"123456789"), 0x995d_c9bb_df19_39fa);
    }
}
