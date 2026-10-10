//! MeatPack: Scott Mudge's 4-bit packing of G-code text, used for the
//! G-code blocks of Prusa binary G-code (bgcode).
//!
//! # Provenance
//!
//! Written from OctoPrint-MeatPack (BSD-3-Clause, "Copyright (c) 2025 Scott
//! Mudge"; see `THIRD-PARTY.md`): the decoder is derived as the inverse of
//! its packer, `OctoPrint_MeatPack/meatpack.py`, and the format description
//! in its README. How MeatPack is used inside bgcode blocks (the block's
//! encoding parameter: 1 = MeatPack, 2 = MeatPack keeping comment lines)
//! comes from Prusa's bgcode specification (`doc/specifications.md` in
//! libbgcode). This file replaces an earlier version that was transliterated
//! from libbgcode's (AGPL-3.0) decoder. It was written by an AI that has
//! seen that decoder (in this project, and possibly in training) and did
//! not consult it while writing this version.
//!
//! # Format
//!
//! Each character of the 15 most common in G-code gets a 4-bit code:
//! `0`-`9` are 0-9, then `.` (10), space (11), newline (12), `G` (13) and
//! `X` (14). Code 15 is a flag meaning "a full byte follows". In packed mode
//! the stream is a sequence of groups, each standing for two characters:
//!
//! - a byte whose two nibbles are both codes: the low nibble's character,
//!   then the high nibble's;
//! - low nibble 15: the next byte is the first character, the high
//!   nibble's the second;
//! - high nibble 15: the low nibble's character, then the next byte;
//! - `0xFF` (both 15): the next two bytes are the two characters.
//!
//! The packer pads a line of odd length with a newline, so a line may be
//! followed by an empty one.
//!
//! Two `0xFF` bytes in a row never occur in packed text (a full byte
//! following `0xFF` is a text character, never `0xFF`), so `0xFF 0xFF`
//! introduces a command byte: 251 enables packing, 250 disables it, 249
//! resets everything (packing and no-spaces off), 247 enables and 246
//! disables no-spaces mode, and others (248, a configuration query) do
//! nothing here. Commands are recognized whether or not packing is on;
//! with packing off every other byte is a character. A stream starts with
//! packing off: the packer's files (and bgcode blocks) begin with the
//! enable command (the bgcode blocks in our fixtures then also enable
//! no-spaces mode).
//!
//! In no-spaces mode code 11 stands for `E` instead of a space (spaces are
//! then sent as full bytes). In either mode the packer removes the spaces
//! from every line containing a `G` followed by a digit, and other lines
//! keep theirs.
//!
//! # Output formatting (our choice)
//!
//! The removed spaces are not recoverable. This decoder, by its own
//! convention (not any other implementation's), writes:
//!
//! - a space before an uppercase letter that directly follows a digit or
//!   `.`, on a line that so far has no space and no `;` (so a stripped
//!   `G1X10.5E.2` reads `G1 X10.5 E.2`, while lines that kept their spaces,
//!   quoted strings in them and comments are left alone; words without a
//!   value, as in `G28XY`, stay joined, which G-code allows);
//! - no empty lines: a newline right after another newline, or at the very
//!   start, is dropped (this removes the packer's padding).
//!
//! Everything else is written as decoded.

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// The signal byte; two in a row introduce a command.
const SIGNAL: u8 = 0xFF;
/// The nibble flagging a full byte.
const FULL: u8 = 0x0F;

const ENABLE_PACKING: u8 = 251;
const DISABLE_PACKING: u8 = 250;
const RESET_ALL: u8 = 249;
const ENABLE_NO_SPACES: u8 = 247;
const DISABLE_NO_SPACES: u8 = 246;

/// Incremental decoder state; positions are relative to the buffers as they
/// are now (see "Releasing" in the pipeline docs).
#[derive(Clone, Debug)]
pub struct MeatPack {
    /// Next unread input byte.
    pos: usize,
    packing: bool,
    no_spaces: bool,
    /// Last character written on the current line (`\n` at a line start).
    last: u8,
    /// The current line has had a space or a `;`.
    spaced: bool,
    /// Bytes written so far, including released ones.
    produced: usize,
}

impl Default for MeatPack {
    fn default() -> Self {
        MeatPack {
            pos: 0,
            packing: false,
            no_spaces: false,
            last: b'\n',
            spaced: false,
            produced: 0,
        }
    }
}

impl MeatPack {
    /// The character a 4-bit code (other than [`FULL`]) stands for.
    fn character(&self, code: u8) -> u8 {
        match code {
            0..=9 => b'0'.saturating_add(code),
            10 => b'.',
            11 if self.no_spaces => b'E',
            11 => b' ',
            12 => b'\n',
            13 => b'G',
            _ => b'X',
        }
    }

    /// Writes one decoded character, applying the output formatting rules.
    fn emit(&mut self, c: u8, out: &mut Vec<u8>) {
        let before = out.len();
        if c == b'\n' {
            if self.last != b'\n' {
                out.push(c);
            }
            self.last = b'\n';
            self.spaced = false;
        } else {
            if !self.spaced
                && c.is_ascii_uppercase()
                && (self.last.is_ascii_digit() || self.last == b'.')
            {
                out.push(b' ');
            }
            if c == b' ' || c == b';' {
                self.spaced = true;
            }
            out.push(c);
            self.last = c;
        }
        self.produced = self
            .produced
            .saturating_add(out.len().saturating_sub(before));
    }

    fn command(&mut self, command: u8) {
        match command {
            ENABLE_PACKING => self.packing = true,
            DISABLE_PACKING => self.packing = false,
            RESET_ALL => {
                self.packing = false;
                self.no_spaces = false;
            }
            ENABLE_NO_SPACES => self.no_spaces = true,
            DISABLE_NO_SPACES => self.no_spaces = false,
            _ => {}
        }
    }

    /// Decodes the group at `pos`, returning its length, or `None` if the
    /// input ends inside it.
    fn group(&mut self, input: &[u8], out: &mut Vec<u8>) -> Option<usize> {
        let pos = self.pos;
        let at = |i: usize| input.get(pos.checked_add(i)?).copied();
        let first = at(0)?;
        if first == SIGNAL && at(1)? == SIGNAL {
            self.command(at(2)?);
            return Some(3);
        }
        if !self.packing {
            self.emit(first, out);
            return Some(1);
        }
        let (low, high) = (first & 0x0F, first >> 4);
        // Check the whole group is there before writing any of it.
        let full = usize::from(low == FULL).saturating_add(usize::from(high == FULL));
        at(full)?;
        let mut next = 1usize;
        for code in [low, high] {
            let c = if code == FULL {
                let c = at(next)?;
                next = next.saturating_add(1);
                c
            } else {
                self.character(code)
            };
            self.emit(c, out);
        }
        Some(next)
    }
}

impl Decode for MeatPack {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let goal = out.len().saturating_add(step);
        loop {
            if out.len() >= goal {
                return Ok(Step::More);
            }
            if self.pos >= input.len() {
                if eof {
                    return Ok(Step::Done);
                }
                return Err(Diagnostic::malformed("MeatPack: more input needed"));
            }
            let Some(n) = self.group(input, out) else {
                return Err(Diagnostic::malformed(
                    "MeatPack: input ends inside a packed group or command",
                ));
            };
            self.pos = self.pos.saturating_add(n);
            if self.produced > limit {
                return Err(Diagnostic::limit(format!(
                    "decompressed data exceeds {limit:#x} bytes"
                )));
            }
        }
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
        // Output is never read back: the formatting state is kept here.
        out_len
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{Decoder, Status, Streaming, decode_all};

    fn decode(data: &[u8]) -> Result<Vec<u8>> {
        decode_all(&mut Streaming(MeatPack::default()), data, 1 << 20)
    }

    /// The packing of `G1 X113.214 Y91.45 E1.3154` from the
    /// OctoPrint-MeatPack README, with spaces and without.
    const WITH_SPACES: &[u8] = &[
        0xFF, 0xFF, 251, 0x1D, 0xEB, 0x11, 0xA3, 0x12, 0xB4, 0x9F, b'Y', 0xA1, 0x54, 0xFB, b'E',
        0xA1, 0x13, 0x45, 0xCC, 0xFF, 0xFF, 249,
    ];
    const NO_SPACES: &[u8] = &[
        0xFF, 0xFF, 251, 0xFF, 0xFF, 247, 0x1D, 0x1E, 0x31, 0x2A, 0x41, 0x9F, b'Y', 0xA1, 0x54,
        0x1B, 0x3A, 0x51, 0xC4, 0xFF, 0xFF, 249,
    ];
    const LINE: &[u8] = b"G1 X113.214 Y91.45 E1.3154\n";

    #[test]
    fn readme_example() {
        assert_eq!(decode(WITH_SPACES).unwrap(), LINE);
        assert_eq!(decode(NO_SPACES).unwrap(), LINE);
    }

    #[test]
    fn modes_and_formatting() {
        // Packing off: bytes pass through; blank lines are dropped.
        assert_eq!(decode(b"\nM73 P0\n\n\nM107\n").unwrap(), b"M73 P0\nM107\n");
        // Kept spaces, quotes and comments are left alone.
        assert_eq!(
            decode(b"M862.3 P \"MK4S\"\nG28XY\nG1X.5;A1B\n").unwrap(),
            b"M862.3 P \"MK4S\"\nG28 XY\nG1 X.5;A1B\n"
        );
        // Unknown commands are ignored; a lone 0xFF with packing off is text.
        assert_eq!(
            decode(&[0xFF, 0xFF, 248, b'A', 0xFF, b'B']).unwrap(),
            b"A\xFFB"
        );
    }

    #[test]
    fn truncation_and_limit() {
        assert!(decode(&WITH_SPACES[..7]).is_ok());
        // Inside a group with a full byte, and inside a command.
        assert!(decode(&WITH_SPACES[..10]).is_err());
        assert!(decode(&[0xFF, 0xFF]).is_err());
        let mut d = Streaming(MeatPack::default());
        assert!(decode_all(&mut d, WITH_SPACES, 10).is_err());
    }

    #[test]
    fn incremental_with_release() {
        let data: Vec<u8> = NO_SPACES.repeat(50);
        let expected = LINE.repeat(50);
        let mut d = Streaming(MeatPack::default());
        let mut out = Vec::new();
        let mut kept = Vec::new();
        let mut fed = 0usize;
        let mut input: Vec<u8> = Vec::new();
        loop {
            let eof = fed >= data.len();
            match d.decode(&input, eof, &mut out, 5, 1 << 20).unwrap() {
                Status::Done => break,
                Status::More => {}
                Status::NeedInput => {
                    let n = 3.min(data.len() - fed);
                    input.extend_from_slice(&data[fed..fed + n]);
                    fed += n;
                }
            }
            let n = d.releasable_input();
            d.release_input(n);
            input.drain(..n);
            let m = d.releasable_output(out.len());
            d.release_output(m);
            kept.extend(out.drain(..m));
        }
        kept.extend(out);
        assert_eq!(kept, expected);
    }
}
