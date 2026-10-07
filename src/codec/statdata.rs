//! Row compression in statistics data files: SPSS bytecode (`.sav` with
//! compression code 1, and inside `.zsav` zlib blocks), and SAS7BDAT's two
//! row compressions, `SASYZCRL` (run-length) and `SASYZCR2` (Ross Data
//! Compression).
//!
//! SPSS bytecode is checked byte-exact against ReadStat: the bytecode data
//! of `survey-bytecode.sav` decodes to the uncompressed data of
//! `survey.sav` (both written by pyreadstat). No free SAS writer exists, so
//! the SAS decoders follow the open readers (ReadStat, pandas) as
//! remembered; the test vectors were encoded by
//! `tests/data/sas7bdat/make.py` and decode to the same rows in pandas and
//! ReadStat.

use crate::codec::filters::Filter;
use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// SPSS bytecode: blocks of 8 command bytes, each standing for one 8-byte
/// value: 0 is padding, 1..=251 the number `code - bias`, 252 the end of
/// the data, 253 a value stored uncompressed after the command block, 254
/// eight spaces, 255 the system-missing value. Resumable at block
/// boundaries; keeps no history, so everything consumed or produced can be
/// released.
#[derive(Clone)]
pub struct SpssBytecode {
    bias: f64,
    big_endian: bool,
    pos: usize,
    done: bool,
}

impl SpssBytecode {
    pub fn new(bias_bits: u64, big_endian: bool) -> Self {
        SpssBytecode {
            bias: f64::from_bits(bias_bits),
            big_endian,
            pos: 0,
            done: false,
        }
    }

    fn number(&self, v: f64) -> [u8; 8] {
        if self.big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    /// Decodes the block at `self.pos`; `None` if its input is not all
    /// there yet.
    fn block(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>) -> Result<Option<()>> {
        let rest = input.get(self.pos..).unwrap_or_default();
        let codes = match rest.get(..8) {
            Some(c) => c,
            // A final, short command block (the stream simply ends).
            None if eof => rest,
            None => return Ok(None),
        };
        let mut data = self.pos.saturating_add(codes.len());
        let mark = out.len();
        for &code in codes {
            match code {
                0 => {}
                252 => {
                    self.done = true;
                    break;
                }
                253 => {
                    let Some(raw) = input.get(data..data.saturating_add(8)) else {
                        out.truncate(mark);
                        if eof {
                            return Err(Diagnostic::malformed("bytecode data truncated"));
                        }
                        return Ok(None);
                    };
                    out.extend_from_slice(raw);
                    data = data.saturating_add(8);
                }
                254 => out.extend_from_slice(b"        "),
                255 => out.extend_from_slice(&self.number(-f64::MAX)),
                n => out.extend_from_slice(&self.number(f64::from(n) - self.bias)),
            }
        }
        self.pos = data;
        Ok(Some(()))
    }
}

impl Decode for SpssBytecode {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let target = out.len().saturating_add(step.max(1));
        while out.len() < target {
            if self.done || (eof && self.pos >= input.len()) {
                return Ok(Step::Done);
            }
            if out.len().saturating_add(64) > limit {
                return Err(Diagnostic::limit(format!(
                    "decompressed data exceeds {limit:#x} bytes"
                )));
            }
            if self.block(input, eof, out)?.is_none() {
                return Err(Diagnostic::malformed("waiting for input"));
            }
        }
        if self.done || (eof && self.pos >= input.len()) {
            return Ok(Step::Done);
        }
        Ok(Step::More)
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }
}

/// A 12-bit length (`low` nibble, then a byte) plus `base`.
fn long(byte: u8, base: usize, low: usize) -> usize {
    usize::from(byte)
        .saturating_add(base)
        .saturating_add(low.saturating_mul(256))
}

/// `low` plus a byte shifted left by four bits (RDC counts and offsets).
fn nibbles(byte: u8, low: usize) -> usize {
    low.saturating_add(usize::from(byte).saturating_mul(16))
}

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed row exceeds {limit:#x} bytes"))
}

fn take(input: &[u8], at: &mut usize) -> Result<u8> {
    let b = input
        .get(*at)
        .copied()
        .ok_or_else(|| Diagnostic::malformed("compressed row truncated"))?;
    *at = at.saturating_add(1);
    Ok(b)
}

fn fill(out: &mut Vec<u8>, byte: u8, n: usize, limit: usize) -> Result<()> {
    if out.len().saturating_add(n) > limit {
        return Err(too_big(limit));
    }
    out.resize(out.len().saturating_add(n), byte);
    Ok(())
}

fn copy(out: &mut Vec<u8>, input: &[u8], at: &mut usize, n: usize, limit: usize) -> Result<()> {
    let end = at.saturating_add(n);
    let bytes = input
        .get(*at..end)
        .ok_or_else(|| Diagnostic::malformed("compressed row truncated"))?;
    if out.len().saturating_add(n) > limit {
        return Err(too_big(limit));
    }
    out.extend_from_slice(bytes);
    *at = end;
    Ok(())
}

/// `SASYZCRL`: a command nibble and a length nibble per control byte,
/// copying literals or inserting runs of a byte, a blank, `@` or zero.
#[derive(Clone, Copy)]
pub struct SasRle;

impl Filter for SasRle {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < input.len() {
            let control = take(input, &mut at)?;
            let low = usize::from(control & 0x0f);
            match control >> 4 {
                0x0 => {
                    let n = long(take(input, &mut at)?, 64, low);
                    copy(&mut out, input, &mut at, n, limit)?;
                }
                0x1 => {
                    let n = long(take(input, &mut at)?, 64 + 4096, low);
                    copy(&mut out, input, &mut at, n, limit)?;
                }
                0x2 => copy(&mut out, input, &mut at, low.saturating_add(96), limit)?,
                0x4 => {
                    let n = long(take(input, &mut at)?, 18, low);
                    let byte = take(input, &mut at)?;
                    fill(&mut out, byte, n, limit)?;
                }
                0x5 => {
                    let n = long(take(input, &mut at)?, 17, low);
                    fill(&mut out, b'@', n, limit)?;
                }
                0x6 => {
                    let n = long(take(input, &mut at)?, 17, low);
                    fill(&mut out, b' ', n, limit)?;
                }
                0x7 => {
                    let n = long(take(input, &mut at)?, 17, low);
                    fill(&mut out, 0, n, limit)?;
                }
                0x8 => copy(&mut out, input, &mut at, low.saturating_add(1), limit)?,
                0x9 => copy(&mut out, input, &mut at, low.saturating_add(17), limit)?,
                0xa => copy(&mut out, input, &mut at, low.saturating_add(33), limit)?,
                0xb => copy(&mut out, input, &mut at, low.saturating_add(49), limit)?,
                0xc => {
                    let byte = take(input, &mut at)?;
                    fill(&mut out, byte, low.saturating_add(3), limit)?;
                }
                0xd => fill(&mut out, b'@', low.saturating_add(2), limit)?,
                0xe => fill(&mut out, b' ', low.saturating_add(2), limit)?,
                0xf => fill(&mut out, 0, low.saturating_add(2), limit)?,
                _ => {
                    return Err(Diagnostic::malformed(format!(
                        "unknown RLE command {control:#04x}"
                    )));
                }
            }
        }
        Ok(out)
    }
}

/// `SASYZCR2`, Ross Data Compression: a big-endian 16-bit control word
/// before every 16 items says which are literals (0) and which commands
/// (1): short and long runs, and short and long back-references.
#[derive(Clone, Copy)]
pub struct SasRdc;

impl Filter for SasRdc {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        let mut at = 0usize;
        let mut bits = 0u16;
        let mut mask = 0u16;
        while at < input.len() {
            mask >>= 1;
            if mask == 0 {
                let hi = take(input, &mut at)?;
                let lo = take(input, &mut at)?;
                bits = u16::from_be_bytes([hi, lo]);
                mask = 0x8000;
                if at >= input.len() {
                    break;
                }
            }
            if bits & mask == 0 {
                let b = take(input, &mut at)?;
                fill(&mut out, b, 1, limit)?;
                continue;
            }
            let control = take(input, &mut at)?;
            let cmd = control >> 4;
            let low = usize::from(control & 0x0f);
            match cmd {
                0 => {
                    let byte = take(input, &mut at)?;
                    fill(&mut out, byte, low.saturating_add(3), limit)?;
                }
                1 => {
                    let n = nibbles(take(input, &mut at)?, low).saturating_add(19);
                    let byte = take(input, &mut at)?;
                    fill(&mut out, byte, n, limit)?;
                }
                _ => {
                    let offset = nibbles(take(input, &mut at)?, low).saturating_add(3);
                    let n = if cmd == 2 {
                        usize::from(take(input, &mut at)?).saturating_add(16)
                    } else {
                        usize::from(cmd)
                    };
                    let start = out.len().checked_sub(offset).ok_or_else(|| {
                        Diagnostic::malformed("back-reference before the start of the row")
                    })?;
                    if out.len().saturating_add(n) > limit {
                        return Err(too_big(limit));
                    }
                    for i in 0..n {
                        let b = out.get(start.saturating_add(i)).copied().unwrap_or(0);
                        out.push(b);
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
            .collect()
    }

    /// Data records of a `.sav`: everything after the dictionary
    /// terminator (record type 999 and its filler).
    fn sav_data(file: &[u8]) -> &[u8] {
        let at = file
            .windows(8)
            .position(|w| w == [0xe7, 3, 0, 0, 0, 0, 0, 0])
            .unwrap_or(0);
        file.get(at + 8..).unwrap_or_default()
    }

    #[test]
    fn spss_bytecode_matches_readstat() {
        let plain = include_bytes!("../../tests/fixtures/external/spss-sav/survey.sav");
        let packed = include_bytes!("../../tests/fixtures/external/spss-sav/survey-bytecode.sav");
        let mut d = SpssBytecode::new(100f64.to_bits(), false);
        let input = sav_data(packed);
        let mut out = Vec::new();
        // One byte at a time first: the decoder must ask for more input.
        for n in 0..input.len() {
            let mut probe = d.clone();
            let mut tmp = out.clone();
            let _ = probe.step(
                input.get(..n).unwrap_or_default(),
                false,
                &mut tmp,
                1,
                1 << 20,
            );
        }
        while d.step(input, true, &mut out, 7, 1 << 20).ok() == Some(Step::More) {}
        assert_eq!(out, sav_data(plain));
    }

    #[test]
    fn spss_bytecode_codes() {
        let mut d = SpssBytecode::new(100f64.to_bits(), true);
        let mut out = Vec::new();
        let input = [
            101, 254, 255, 253, 0, 0, 0, 252, b'A', b'B', b'C', b'D', 1, 2, 3, 4,
        ];
        while d.step(&input, true, &mut out, 64, 1 << 20).ok() == Some(Step::More) {}
        let mut want = 1f64.to_be_bytes().to_vec();
        want.extend_from_slice(b"        ");
        want.extend_from_slice(&(-f64::MAX).to_be_bytes());
        want.extend_from_slice(b"ABCD\x01\x02\x03\x04");
        assert_eq!(out, want);
        assert_eq!(d.consumed(), 16);
    }

    // Rows of tests/data/sas7bdat/make.py (32-bit little-endian), encoded
    // by its compressors; pandas and ReadStat read them back as the rows.
    const ROW_2: &str =
        "0000000000000040c5a06b6f646120202020202000000000c08dd240000000008088cc40001840";
    const ROW_3: &str =
        "00000000000008402020202020202020202020200000000000feffff0000000000000000beffff";

    #[test]
    fn sas_rle_rows() {
        for (packed, row) in [
            ("f58640c5a06b6f6461e4f283c08dd240f2868088cc40001840", ROW_2),
            ("f4810840eaf382fefffff682beffff", ROW_3),
        ] {
            assert_eq!(SasRle.apply(&hex(packed), 1 << 16).ok(), Some(hex(row)));
        }
    }

    #[test]
    fn sas_rdc_rows() {
        for (packed, row) in [
            (
                "80c2040040c5a06b6f646103200100c08dd240010080000088cc40001840",
                ROW_2,
            ),
            ("98800300084009200200feffff0500beffff", ROW_3),
        ] {
            assert_eq!(SasRdc.apply(&hex(packed), 1 << 16).ok(), Some(hex(row)));
        }
    }

    /// A longer vector exercising long literals, long runs and
    /// back-references (decoded identically by pandas; ReadStat agrees up
    /// to the first NUL, where its C strings end).
    fn long() -> Vec<u8> {
        let mut v = b"ABCDEFGH".repeat(6);
        v.extend_from_slice(&[b' '; 40]);
        v.extend_from_slice(&[0; 100]);
        v.extend(0u8..70);
        v.extend_from_slice(&[b'x'; 30]);
        v
    }

    #[test]
    fn sas_long_vectors() {
        let rle = "af4142434445464748414243444546474841424344454647484142434445464748414243444546474841424344454647486017705400050102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445400c78";
        assert_eq!(SasRle.apply(&hex(rle), 1 << 16).ok(), Some(long()));
        let rdc = "00e741424344454647488500fd00fd0047480f200f200120fc000f000f000f000f000f0008000102030405060708090a00000b0c0d0e0f101112131415161718191a00001b1c1d1e1f202122232425262728292a00002b2c2d2e2f303132333435363738393a03803b3c3d3e3f40520d0f780978";
        assert_eq!(SasRdc.apply(&hex(rdc), 1 << 16).ok(), Some(long()));
        // Limits and truncation.
        assert!(SasRle.apply(&hex(rle), 100).is_err());
        assert!(SasRdc.apply(&hex(rdc), 100).is_err());
        assert!(SasRle.apply(&[0x00], 1 << 16).is_err());
        assert!(SasRdc.apply(&[0x80, 0x00, 0x30], 1 << 16).is_err());
    }
}
