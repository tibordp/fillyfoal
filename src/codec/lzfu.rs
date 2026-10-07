//! Compressed RTF ([MS-OXRTFCP]): the `LZFu` LZ77 variant Outlook uses for
//! `PidTagRtfCompressed`, and its uncompressed `MELA` form.
//!
//! A 16-byte header (compressed size, raw size, type, CRC) precedes the
//! data. Each control byte announces eight items, least significant bit
//! first: a literal byte (0) or a big-endian 16-bit reference (1) of a
//! 12-bit position in a 4 KiB circular dictionary and a 4-bit length (+2).
//! The dictionary starts with a fixed RTF prologue; a reference to the
//! current write position ends the stream. Written from memory of the
//! specification; the CRC is not checked.

use crate::codec::filters::Filter;
use crate::error::{Diagnostic, Result};

/// The dictionary's initial contents (207 bytes).
const PROLOGUE: &[u8] = b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx";

const LZFU: u32 = 0x7546_5a4c;
const MELA: u32 = 0x414c_454d;

#[derive(Clone, Copy)]
pub struct Lzfu;

impl Filter for Lzfu {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let word = |at: usize| crate::bytes::u32_le(input, at);
        let (Some(comp_size), Some(raw_size), Some(kind)) = (word(0), word(4), word(8)) else {
            return Err(Diagnostic::malformed("compressed RTF: header truncated"));
        };
        let raw_size = usize::try_from(raw_size).unwrap_or(usize::MAX);
        if raw_size > limit {
            return Err(Diagnostic::limit(format!(
                "compressed RTF: {raw_size:#x} bytes exceed {limit:#x}"
            )));
        }
        // COMPSIZE counts everything after its own field.
        let end = usize::try_from(comp_size)
            .unwrap_or(usize::MAX)
            .saturating_add(4)
            .min(input.len());
        let data = input.get(16..end).unwrap_or_default();
        match kind {
            MELA => Ok(data
                .get(..raw_size.min(data.len()))
                .unwrap_or_default()
                .to_vec()),
            LZFU => decode(data, raw_size),
            other => Err(Diagnostic::malformed(format!(
                "compressed RTF: unknown type {other:#010x}"
            ))),
        }
    }
}

fn decode(data: &[u8], raw_size: usize) -> Result<Vec<u8>> {
    let mut dict = [0u8; 4096];
    for (slot, &b) in dict.iter_mut().zip(PROLOGUE) {
        *slot = b;
    }
    let mut write = PROLOGUE.len();
    let mut out = Vec::with_capacity(raw_size.min(data.len().saturating_mul(8)));
    let mut pos = 0usize;
    while let Some(&control) = data.get(pos) {
        pos = pos.saturating_add(1);
        for bit in 0..8 {
            if out.len() >= raw_size {
                return Ok(out);
            }
            if control & (1 << bit) == 0 {
                let Some(&b) = data.get(pos) else {
                    return Ok(out);
                };
                pos = pos.saturating_add(1);
                out.push(b);
                if let Some(slot) = dict.get_mut(write) {
                    *slot = b;
                }
                write = (write.saturating_add(1)) & 0xfff;
            } else {
                let (Some(&hi), Some(&lo)) = (data.get(pos), data.get(pos.saturating_add(1)))
                else {
                    return Err(Diagnostic::malformed("compressed RTF: reference truncated"));
                };
                pos = pos.saturating_add(2);
                let reference = u16::from_be_bytes([hi, lo]);
                let mut offset = usize::from(reference >> 4);
                let len = usize::from(reference & 0xf).saturating_add(2);
                if offset == write {
                    return Ok(out);
                }
                for _ in 0..len {
                    if out.len() >= raw_size {
                        return Ok(out);
                    }
                    let b = dict.get(offset).copied().unwrap_or(0);
                    out.push(b);
                    if let Some(slot) = dict.get_mut(write) {
                        *slot = b;
                    }
                    write = (write.saturating_add(1)) & 0xfff;
                    offset = (offset.saturating_add(1)) & 0xfff;
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn prologue_is_207_bytes() {
        assert_eq!(PROLOGUE.len(), 207);
    }

    #[allow(clippy::indexing_slicing)]
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i.saturating_add(2)], 16).unwrap())
            .collect()
    }

    /// Written by the `compressed-rtf` Python package 1.0.7
    /// (`compressed_rtf.compress(data, compressed=True)`); the first is
    /// also the example of [MS-OXRTFCP].
    #[test]
    #[allow(clippy::indexing_slicing)]
    fn decodes_real_compressor_output() {
        let cases: [(&str, &[u8]); 2] = [
            (
                "2d0000002b0000004c5a4675f1c5c7a703000a007263706731323542320af32068656c090020627705b06c647d0a800fa0",
                b"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n",
            ),
            (
                "3c000000690000004c5a467521b4805afb000a01032001f70e020df0076d0280c27d0aea2068656c090010ef0511307705b06c642c2050285354210aa37d1380",
                b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Times New Roman;}} \\pard\\plain hello hello hello hello world, PST!\\par }",
            ),
        ];
        for (compressed, plain) in cases {
            assert_eq!(Lzfu.apply(&hex(compressed), 1 << 20).unwrap(), plain);
        }
    }

    /// A reference into the prologue (`{\rtf1\ansi`), literals, and the
    /// end marker (a reference to the write position).
    #[test]
    fn decodes_literals_and_prologue_references() {
        let mut body = Vec::new();
        // Control 0b0000_0001: one reference then 7 literals.
        body.push(0b0000_0001);
        // Offset 0, length 11 (stored as 9).
        body.extend_from_slice(&9u16.to_be_bytes());
        body.extend_from_slice(b"cpg1252");
        // Control: a reference to the write position ends the stream.
        let write = (207 + 11 + 7) as u16;
        body.push(0b0000_0001);
        body.extend_from_slice(&(write << 4).to_be_bytes());
        let mut input = Vec::new();
        input.extend_from_slice(&u32::try_from(body.len() + 12).unwrap().to_le_bytes());
        input.extend_from_slice(&18u32.to_le_bytes());
        input.extend_from_slice(&LZFU.to_le_bytes());
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(&body);
        let out = Lzfu.apply(&input, 1 << 20).unwrap();
        assert_eq!(out, b"{\\rtf1\\ansicpg1252");
    }

    #[test]
    fn copies_overlapping_references() {
        // "ab" then a reference to the "ab" just written, length 6.
        let mut body = vec![0b0000_0100, b'a', b'b'];
        body.extend_from_slice(&((207u16 << 4) | 4).to_be_bytes());
        let mut input = Vec::new();
        input.extend_from_slice(&u32::try_from(body.len() + 12).unwrap().to_le_bytes());
        input.extend_from_slice(&8u32.to_le_bytes());
        input.extend_from_slice(&LZFU.to_le_bytes());
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(&body);
        assert_eq!(Lzfu.apply(&input, 1 << 20).unwrap(), b"abababab");
    }
}
