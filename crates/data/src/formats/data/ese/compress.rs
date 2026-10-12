//! Compressed column values and long-value chunks (tagged value flag 0x02,
//! Windows 7 and later). The top five bits of the first byte name the
//! scheme, as libesedb reads them: 1 is 7-bit ASCII and 2 7-bit Unicode
//! (seven-bit characters packed least significant bit first after that
//! byte, Unicode ones widened to UTF-16LE), 3 Xpress (Plain LZ77, after the
//! byte and a 16-bit decompressed size). Later schemes (Xpress9, Xpress10,
//! LZ4) are reported as unsupported.
//!
//! Not yet checked against a database written by esent.dll with
//! compression on: the layout follows libesedb_compression.c.

use crate::bytes::u16_le;
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::span::{Origin, Span};

/// The largest separated long value decompressed chunk by chunk.
pub const MAX_LONG: u64 = 16 << 20;

pub fn scheme_name(b: &[u8]) -> Option<&'static str> {
    match b.first()? >> 3 {
        1 => Some("7-bit ASCII"),
        2 => Some("7-bit Unicode"),
        3 => Some("Xpress"),
        _ => None,
    }
}

/// Unpacks 7-bit characters (after the scheme byte), widening each to two
/// bytes for Unicode. The last byte's padding bits may make a NUL
/// character, which is dropped.
pub fn seven_bit(b: &[u8], wide: bool) -> Vec<u8> {
    let payload = b.get(1..).unwrap_or_default();
    let chars = payload.len().saturating_mul(8) / 7;
    let mut out = Vec::with_capacity(chars.saturating_mul(if wide { 2 } else { 1 }));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &x in payload {
        acc |= u32::from(x).wrapping_shl(bits);
        bits = bits.saturating_add(8);
        while bits >= 7 {
            out.push(u8::try_from(acc & 0x7f).unwrap_or(0));
            if wide {
                out.push(0);
            }
            acc = acc.wrapping_shr(7);
            bits = bits.saturating_sub(7);
        }
    }
    let width = if wide { 2 } else { 1 };
    while out.len() >= width && out.iter().rev().take(width).all(|&c| c == 0) {
        out.truncate(out.len().saturating_sub(width));
    }
    out
}

/// Decompresses the value in `span` (whose bytes are `b`) into a derived
/// source; returns the scheme's name and the source's span.
pub async fn value(cx: &Cx, span: Span, b: &[u8]) -> Result<(&'static str, Span)> {
    let scheme = b.first().map_or(0, |x| x >> 3);
    match scheme {
        1 | 2 => {
            let wide = scheme == 2;
            let out = seven_bit(b, wide);
            let d = cx.add_derived(
                Origin {
                    parent: span,
                    transform: if wide {
                        "ese-7bit-unicode"
                    } else {
                        "ese-7bit-ascii"
                    },
                },
                out,
                span.len,
                None,
            )?;
            Ok((if wide { "7-bit Unicode" } else { "7-bit ASCII" }, d.span))
        }
        3 => {
            let size = u16_le(b, 1)
                .ok_or_else(|| Diagnostic::malformed("Xpress value lacks its size").at(span))?;
            let d = crate::codec::decode_span(
                cx,
                span.tail(3),
                &Codec::Xpress {
                    size: Some(size.into()),
                },
                Some(size.into()),
            )
            .await?;
            if let Some(e) = d.error {
                return Err(e);
            }
            Ok(("Xpress", d.span))
        }
        s => Err(Diagnostic::unsupported(format!("compression scheme {s}")).at(span)),
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    /// Packs ASCII as ESE's 7-bit scheme does (scheme byte 0x08 | unused).
    fn pack(s: &[u8], scheme: u8) -> Vec<u8> {
        let mut out = vec![scheme << 3];
        let (mut acc, mut bits) = (0u32, 0u32);
        for &c in s {
            acc |= u32::from(c) << bits;
            bits += 7;
            while bits >= 8 {
                out.push((acc & 0xff) as u8);
                acc >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            out.push(acc as u8);
        }
        out
    }

    #[test]
    fn seven_bit_round_trips() {
        for s in [&b"a"[..], b"fillyfoal", b"12345678", b"exactly sixteen!"] {
            assert_eq!(seven_bit(&pack(s, 1), false), s, "{s:?}");
            let wide: Vec<u8> = s.iter().flat_map(|&c| [c, 0]).collect();
            assert_eq!(seven_bit(&pack(s, 2), true), wide, "{s:?}");
        }
        assert_eq!(scheme_name(&pack(b"x", 1)), Some("7-bit ASCII"));
        assert_eq!(scheme_name(&[0x18, 0, 0]), Some("Xpress"));
        assert_eq!(scheme_name(&[0x28]), None);
    }
}
