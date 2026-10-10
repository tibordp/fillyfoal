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

use crate::codec::lz::{Units, run_units};
use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// The dictionary's initial contents (207 bytes).
const PROLOGUE: &[u8] = b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx";

const LZFU: u32 = 0x7546_5a4c;
const MELA: u32 = 0x414c_454d;

/// Compressed RTF, decoded an item at a time. The window is the 4 KiB
/// dictionary, kept here, so all output can be released.
#[derive(Clone)]
pub struct Lzfu {
    /// `(raw size, compressed?)`, once the header has been read.
    header: Option<(usize, bool)>,
    pos: usize,
    /// Where the data ends (it may extend past the input).
    end: usize,
    /// Output bytes produced so far.
    produced: usize,
    /// The current control byte, and the next of its bits (8: none).
    control: u8,
    bit: u8,
    dict: [u8; 4096],
    write: usize,
    /// The data has ended; the rest of the input is ignored.
    ended: bool,
    done: bool,
}

impl Default for Lzfu {
    fn default() -> Self {
        let mut dict = [0u8; 4096];
        for (slot, &b) in dict.iter_mut().zip(PROLOGUE) {
            *slot = b;
        }
        Lzfu {
            header: None,
            pos: 0,
            end: 0,
            produced: 0,
            control: 0,
            bit: 8,
            dict,
            write: PROLOGUE.len(),
            ended: false,
            done: false,
        }
    }
}

impl Lzfu {
    /// Reads the header.
    fn header(&mut self, input: &[u8], limit: usize) -> Result<usize> {
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
        let compressed = match kind {
            MELA => false,
            LZFU => true,
            other => {
                return Err(Diagnostic::malformed(format!(
                    "compressed RTF: unknown type {other:#010x}"
                )));
            }
        };
        // COMPSIZE counts everything after its own field.
        self.end = usize::try_from(comp_size)
            .unwrap_or(usize::MAX)
            .saturating_add(4);
        self.pos = 16;
        self.header = Some((raw_size, compressed));
        Ok(16)
    }

    /// Writes `b` to the output and the dictionary.
    fn put(&mut self, out: &mut Vec<u8>, b: u8) {
        out.push(b);
        if let Some(slot) = self.dict.get_mut(self.write) {
            *slot = b;
        }
        self.write = (self.write.saturating_add(1)) & 0xfff;
        self.produced = self.produced.saturating_add(1);
    }
}

impl Units for Lzfu {
    fn unit(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        room: usize,
        limit: usize,
    ) -> Result<usize> {
        if self.ended {
            if eof {
                self.pos = input.len().max(self.pos);
                self.done = true;
                return Ok(1);
            }
            if self.pos < input.len() {
                self.pos = input.len();
                return Ok(1);
            }
            return Err(Diagnostic::malformed("compressed RTF: waiting for input"));
        }
        let Some((raw_size, compressed)) = self.header else {
            return self.header(input, limit);
        };
        // The data runs to `end`, or to the end of the input.
        let data_end = self.end.min(input.len());
        let complete = eof || input.len() >= self.end;
        let short = || Diagnostic::malformed("compressed RTF: data truncated");
        let left = raw_size.saturating_sub(self.produced);
        if left == 0 {
            self.ended = true;
            return Ok(1);
        }
        let pos = self.pos;
        if !compressed {
            let avail = data_end.saturating_sub(pos);
            if avail == 0 {
                if !complete {
                    return Err(short());
                }
                self.ended = true;
                return Ok(1);
            }
            let n = left.min(avail).min(room.max(1));
            let to = pos.saturating_add(n);
            out.extend_from_slice(input.get(pos..to).unwrap_or_default());
            self.pos = to;
            self.produced = self.produced.saturating_add(n);
            return Ok(n);
        }
        let byte = |at: usize| input.get(at).copied().filter(|_| at < data_end);
        if self.bit >= 8 {
            let Some(control) = byte(pos) else {
                if !complete {
                    return Err(short());
                }
                self.ended = true;
                return Ok(1);
            };
            self.control = control;
            self.bit = 0;
            self.pos = pos.saturating_add(1);
            return Ok(1);
        }
        if self.control & (1 << self.bit) == 0 {
            let Some(b) = byte(pos) else {
                if !complete {
                    return Err(short());
                }
                self.ended = true;
                return Ok(1);
            };
            self.put(out, b);
            self.pos = pos.saturating_add(1);
            self.bit = self.bit.saturating_add(1);
            return Ok(1);
        }
        let (Some(hi), Some(lo)) = (byte(pos), byte(pos.saturating_add(1))) else {
            if !complete {
                return Err(short());
            }
            return Err(Diagnostic::malformed("compressed RTF: reference truncated"));
        };
        let reference = u16::from_be_bytes([hi, lo]);
        let mut offset = usize::from(reference >> 4);
        let len = usize::from(reference & 0xf).saturating_add(2);
        if offset == self.write {
            self.ended = true;
            return Ok(1);
        }
        for _ in 0..len.min(left) {
            let b = self.dict.get(offset).copied().unwrap_or(0);
            self.put(out, b);
            offset = (offset.saturating_add(1)) & 0xfff;
        }
        self.pos = pos.saturating_add(2);
        self.bit = self.bit.saturating_add(1);
        Ok(len)
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn progress(&self) -> usize {
        self.pos
    }
}

impl Decode for Lzfu {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        run_units(self, input, eof, out, step, limit)
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        // Before the header is read, `pos` is 0.
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        self.end = self.end.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }

    fn heap_size(&self) -> Option<usize> {
        // The 4 KiB dictionary is inline.
        Some(0)
    }
}

/// Decodes a whole compressed RTF stream (for tests).
#[cfg(test)]
fn decode(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut d = crate::codec::pipeline::Streaming(Lzfu::default());
    crate::codec::pipeline::decode_all(&mut d, input, limit)
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
        crate::text::unhex(s).unwrap()
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
            assert_eq!(decode(&hex(compressed), 1 << 20).unwrap(), plain);
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
        let out = decode(&input, 1 << 20).unwrap();
        assert_eq!(out, b"{\\rtf1\\ansicpg1252");
    }

    /// Literals and references (to text 100 and 1000 bytes back), then the
    /// end marker.
    #[test]
    #[allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation
    )]
    fn checkpoints_resume_mid_stream() {
        let words = include_bytes!("testdata/words.txt");
        let (mut body, mut write, mut raw) = (Vec::new(), PROLOGUE.len(), 0usize);
        let mut control = 0;
        let mut items = 0;
        let mut item = |body: &mut Vec<u8>, reference: Option<u16>, literal: u8| {
            if items % 8 == 0 {
                control = body.len();
                body.push(0);
            }
            match reference {
                Some(r) => {
                    body[control] |= 1 << (items % 8);
                    body.extend_from_slice(&r.to_be_bytes());
                }
                None => body.push(literal),
            }
            items += 1;
        };
        for (i, &literal) in words.iter().enumerate().take(20_000) {
            if i > 1000 && i % 3 == 0 {
                let back = if i % 2 == 0 { 100 } else { 1000 };
                let len = 2 + i % 16;
                let at = (write + 4096 - back) % 4096;
                item(&mut body, Some((at << 4 | (len - 2)) as u16), 0);
                write = (write + len) % 4096;
                raw += len;
            } else {
                item(&mut body, None, literal);
                write = (write + 1) % 4096;
                raw += 1;
            }
        }
        item(&mut body, Some((write << 4) as u16), 0);
        let mut input = Vec::new();
        input.extend_from_slice(&u32::try_from(body.len() + 12).unwrap().to_le_bytes());
        input.extend_from_slice(&u32::try_from(raw).unwrap().to_le_bytes());
        input.extend_from_slice(&LZFU.to_le_bytes());
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(&body);
        assert_eq!(decode(&input, 1 << 24).unwrap().len(), raw);
        let (checked, largest) = crate::codec::pipeline::verify_checkpoints(
            || Box::new(crate::codec::pipeline::Streaming(Lzfu::default())),
            &input,
            1000,
            3,
        )
        .unwrap();
        assert!(checked > 10, "{checked}");
        // The dictionary is inline.
        assert_eq!(largest, std::mem::size_of::<Lzfu>());
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
        assert_eq!(decode(&input, 1 << 20).unwrap(), b"abababab");
    }
}
