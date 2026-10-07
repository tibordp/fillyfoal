//! MeatPack: the 4-bit packing of G-code text by Scott Mudge, used in
//! Prusa binary G-code blocks (encodings 1 and 2).
//!
//! The 15 most common G-code characters (`0`-`9`, `.`, space, newline, `G`,
//! `X`) pack two to a byte, low nibble first; a nibble of `0xF` means that
//! character follows as a full byte instead. Two `0xFF` bytes introduce a
//! command byte: 251 enables packing, 250 disables it (comment lines are
//! stored verbatim between them), 249 resets, 247/246 switch "no spaces"
//! mode on and off (nibble `0xB` then means `E`, since spaces are dropped).
//! The encoder removes spaces from `G` lines and collapses blank lines.
//!
//! The decoder reproduces libbgcode's `MeatPack::unbinarize` exactly,
//! including its output conventions: a space is put back before each
//! parameter letter of a `G` line, and repeated newlines are collapsed. It
//! is checked against `from_binary_to_ascii` of libbgcode (pybgcode) on the
//! `bgcode` fixtures (see `tests/formats.rs`).

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

const SIGNAL: u8 = 0xff;
const ENABLE_PACKING: u8 = 251;
const DISABLE_PACKING: u8 = 250;
const RESET_ALL: u8 = 249;
const ENABLE_NO_SPACES: u8 = 247;
const DISABLE_NO_SPACES: u8 = 246;

/// Parameter letters that get a space before them on `G` lines.
const G_PARAMETERS: &[u8] = b"XYZEFIJRSGPWHCA";

#[derive(Clone, Debug, Default)]
pub struct MeatPack {
    /// Input bytes consumed (relative to the current input buffer).
    pos: usize,
    produced: usize,
    unpacking: bool,
    no_spaces: bool,
    command: bool,
    signals: u8,
    /// A packed character waiting for the full-width one before it.
    held: u8,
    /// Full-width characters still to come.
    queue: u8,
    /// Inside a `G` line: parameters get spaces.
    add_space: bool,
    last: Option<u8>,
}

impl MeatPack {
    fn nibble(&self, n: u8) -> u8 {
        match n {
            0..=9 => b'0'.saturating_add(n),
            10 => b'.',
            11 if self.no_spaces => b'E',
            11 => b' ',
            12 => b'\n',
            13 => b'G',
            14 => b'X',
            _ => 0,
        }
    }

    /// The characters one received byte stands for (at most two).
    fn receive(&mut self, c: u8, chars: &mut Vec<u8>) {
        if !self.unpacking {
            chars.push(c);
            return;
        }
        if self.queue > 0 {
            chars.push(c);
            if self.held > 0 {
                chars.push(self.held);
                self.held = 0;
            }
            self.queue = self.queue.saturating_sub(1);
            return;
        }
        let first_full = c & 0x0f == 0x0f;
        let second_full = c & 0xf0 == 0xf0;
        let low = self.nibble(c & 0x0f);
        let high = self.nibble(c >> 4);
        if first_full {
            self.queue = self.queue.saturating_add(1);
            if second_full {
                self.queue = self.queue.saturating_add(1);
            } else {
                self.held = high;
            }
        } else {
            chars.push(low);
            if low != b'\n' {
                if second_full {
                    self.queue = self.queue.saturating_add(1);
                } else {
                    chars.push(high);
                }
            }
        }
    }

    fn put(&mut self, c: u8, out: &mut Vec<u8>) {
        let mut new_line = false;
        if c == b'G' && (self.produced == 0 || self.last == Some(b'\n')) {
            self.add_space = true;
            new_line = true;
        } else if c == b'\n' {
            self.add_space = false;
        }
        if !new_line
            && self.add_space
            && (self.produced == 0 || self.last != Some(b' '))
            && G_PARAMETERS.contains(&c)
        {
            self.emit(b' ', out);
        }
        if c != b'\n' || self.produced == 0 || self.last != Some(b'\n') {
            self.emit(c, out);
        }
    }

    fn emit(&mut self, c: u8, out: &mut Vec<u8>) {
        out.push(c);
        self.produced = self.produced.saturating_add(1);
        self.last = Some(c);
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
        let mut chars = Vec::with_capacity(2);
        loop {
            if out.len() >= goal {
                return Ok(Step::More);
            }
            let Some(&c) = input.get(self.pos) else {
                if eof {
                    return Ok(Step::Done);
                }
                return Err(Diagnostic::malformed("MeatPack: more input needed"));
            };
            self.pos = self.pos.saturating_add(1);
            chars.clear();
            if c == SIGNAL {
                if self.signals > 0 {
                    self.command = true;
                    self.signals = 0;
                } else {
                    self.signals = 1;
                }
            } else if self.command {
                match c {
                    ENABLE_PACKING => self.unpacking = true,
                    DISABLE_PACKING | RESET_ALL => self.unpacking = false,
                    ENABLE_NO_SPACES => self.no_spaces = true,
                    DISABLE_NO_SPACES => self.no_spaces = false,
                    _ => {}
                }
                self.command = false;
            } else {
                if self.signals > 0 {
                    self.receive(SIGNAL, &mut chars);
                    self.signals = 0;
                }
                self.receive(c, &mut chars);
            }
            for &ch in &chars {
                self.put(ch, out);
            }
            if self.produced > limit {
                return Err(Diagnostic::limit(format!(
                    "decoded data exceeds {limit:#x} bytes"
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
        // Only the last character matters, and it is kept in the state.
        out_len
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{Streaming, decode_all};

    fn decode(data: &[u8]) -> String {
        let mut d = Streaming(MeatPack::default());
        String::from_utf8(decode_all(&mut d, data, 1 << 20).unwrap()).unwrap()
    }

    #[test]
    fn packed_lines_and_comments() {
        // Enable packing; "G1X10.5\n" packed: 'G''1' = 0x1d, 'X''1' = 0x1e,
        // '0''.' = 0xa0, '5''\n' = 0xc5.
        let mut data = vec![0xff, 0xff, ENABLE_PACKING, 0x1d, 0x1e, 0xa0, 0xc5];
        // "M" is not packable: low nibble full, high nibble '1' packed;
        // then "04 S" ... keep it short: "M1\n" = 0x1f 'M', '\n' + pad.
        data.extend_from_slice(&[0x1f, b'M', 0x0c]);
        // A comment line, stored verbatim with packing off.
        data.extend_from_slice(&[0xff, 0xff, DISABLE_PACKING]);
        data.extend_from_slice(b";hello\n");
        assert_eq!(decode(&data), "G1 X10.5\nM1\n;hello\n");
    }

    #[test]
    fn no_spaces_mode_and_full_bytes() {
        // No-spaces mode: nibble 0xB is 'E'. "G1E2\n": 0x1d, 0x2b, 0x0c.
        let data = [
            0xff,
            0xff,
            ENABLE_PACKING,
            0xff,
            0xff,
            ENABLE_NO_SPACES,
            0x1d,
            0x2b,
            0x0c,
        ];
        assert_eq!(decode(&data), "G1 E2\n");
        // Both characters full width: 0xff then two bytes ("Y" and "Z" are
        // not packable). A single 0xff followed by data is data.
        let data = [0xff, 0xff, ENABLE_PACKING, 0x1d, 0xff, b'Y', b'Z', 0xcc];
        assert_eq!(decode(&data), "G1 Y Z\n");
    }
}
