//! Unix `compress` (`.Z`): LZW with LSB-first codes of 9 up to 16 bits and,
//! in block mode, a CLEAR code. Codes come in groups of `bits` bytes; when
//! the code width changes or the table is cleared, the rest of the group is
//! skipped (the original implementation's buffering, now part of the
//! format).
//!
//! The string table has up to 64K entries (192 KiB), too much to snapshot
//! before every step, so [`UnixCompress`] is a [`Decoder`] of its own that
//! never needs rolling back: it checks that a whole code is in the input
//! before it changes any state, and otherwise waits for more.

use crate::codec::pipeline::{Decoder, Status};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!(".Z: {what}"))
}

/// The LZW state once the header has been read.
#[derive(Clone)]
struct Lzw {
    max_bits: u32,
    block_mode: bool,
    max_max_code: usize,
    /// The next code's position, in bits from the start of the code data.
    pos: usize,
    bits: u32,
    max_code: usize,
    free: usize,
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    old: Option<usize>,
    fin: u8,
    /// Where the codes of the current width began (groups count from here).
    mark: usize,
    stack: Vec<u8>,
}

impl Lzw {
    fn new(flags: u8) -> Result<Self> {
        let max_bits = u32::from(flags & 0x1f);
        if !(9..=16).contains(&max_bits) {
            return Err(bad("maximum code width out of range"));
        }
        let block_mode = flags & 0x80 != 0;
        let max_max_code = 1usize << max_bits;
        Ok(Lzw {
            max_bits,
            block_mode,
            max_max_code,
            pos: 0,
            bits: 9,
            max_code: (1usize << 9).saturating_sub(1),
            free: if block_mode { 257 } else { 256 },
            prefix: vec![0u16; max_max_code],
            suffix: (0..max_max_code)
                .map(|i| u8::try_from(i & 0xff).unwrap_or(0))
                .collect(),
            old: None,
            fin: 0,
            mark: 0,
            stack: Vec::new(),
        })
    }

    /// Skips to the end of the current group of `bits` codes, counted from
    /// where the codes of this width began.
    fn align(&mut self) {
        let group = usize::try_from(self.bits).unwrap_or(9).saturating_mul(8);
        self.pos = self.mark.saturating_add(
            self.pos
                .saturating_sub(self.mark)
                .div_ceil(group)
                .saturating_mul(group),
        );
        self.mark = self.pos;
    }

    /// Decodes codes from `data` onto `out` until `step` bytes have been
    /// produced (true) or no whole code is left (false).
    fn run(&mut self, data: &[u8], out: &mut Vec<u8>, step: usize, limit: usize) -> Result<bool> {
        let total_bits = data.len().saturating_mul(8);
        let start = out.len();
        loop {
            if self.free > self.max_code && self.bits < self.max_bits {
                self.align();
                self.bits = self.bits.saturating_add(1);
                self.max_code = if self.bits == self.max_bits {
                    self.max_max_code
                } else {
                    (1usize << self.bits).saturating_sub(1)
                };
            }
            let width = usize::try_from(self.bits).unwrap_or(16);
            if self.pos.saturating_add(width) > total_bits {
                return Ok(false);
            }
            let mut code = 0usize;
            for i in 0..width {
                let p = self.pos.saturating_add(i);
                let b = data.get(p / 8).copied().unwrap_or(0) >> (p % 8) & 1;
                code |= usize::from(b) << i;
            }
            self.pos = self.pos.saturating_add(width);
            let Some(prev) = self.old else {
                if code > 255 {
                    return Err(bad("first code is not a literal"));
                }
                self.fin = u8::try_from(code).unwrap_or(0);
                out.push(self.fin);
                self.old = Some(code);
                continue;
            };
            if code == 256 && self.block_mode {
                self.free = 256;
                self.align();
                self.bits = 9;
                self.max_code = (1usize << self.bits).saturating_sub(1);
                continue;
            }
            let incode = code;
            self.stack.clear();
            if code >= self.free {
                if code > self.free {
                    return Err(bad("code beyond the table"));
                }
                self.stack.push(self.fin);
                code = prev;
            }
            while code >= 256 {
                self.stack.push(
                    self.suffix
                        .get(code)
                        .copied()
                        .ok_or_else(|| bad("code beyond the table"))?,
                );
                code = usize::from(
                    self.prefix
                        .get(code)
                        .copied()
                        .ok_or_else(|| bad("code beyond the table"))?,
                );
                if self.stack.len() > self.max_max_code {
                    return Err(bad("string loop"));
                }
            }
            self.fin = u8::try_from(code).unwrap_or(0);
            self.stack.push(self.fin);
            out.extend(self.stack.iter().rev());
            if out.len() > limit {
                return Err(Diagnostic::output_limit(limit));
            }
            if self.free < self.max_max_code {
                if let Some(p) = self.prefix.get_mut(self.free) {
                    *p = u16::try_from(prev).unwrap_or(0);
                }
                if let Some(s) = self.suffix.get_mut(self.free) {
                    *s = self.fin;
                }
                self.free = self.free.saturating_add(1);
            }
            self.old = Some(incode);
            if out.len().saturating_sub(start) >= step {
                return Ok(true);
            }
        }
    }
}

impl Lzw {
    /// Code data bits that may be dropped: up to the next code, or to the
    /// latest group boundary at or before it, which [`Lzw::align`] can
    /// count from instead of `mark`.
    fn releasable_bits(&self) -> usize {
        let group = usize::try_from(self.bits).unwrap_or(9).saturating_mul(8);
        let into_group = self
            .pos
            .saturating_sub(self.mark)
            .checked_rem(group)
            .unwrap_or(0);
        self.pos.saturating_sub(into_group)
    }

    /// Drops `n` bits (whole bytes, at most [`Lzw::releasable_bits`]) from
    /// the front of the code data.
    fn release(&mut self, n: usize) {
        let group = usize::try_from(self.bits).unwrap_or(9).saturating_mul(8);
        let into_group = self
            .pos
            .saturating_sub(self.mark)
            .checked_rem(group)
            .unwrap_or(0);
        // A group boundary as good as `mark` for aligning, kept in range.
        self.mark = self.pos.saturating_sub(into_group).saturating_sub(n);
        self.pos = self.pos.saturating_sub(n);
    }
}

/// A `.Z` stream, decoded as far as the input reaches. Output is never
/// read back (the string table holds the strings), so all of it can be
/// released, and input up to the current code.
#[derive(Clone)]
pub struct UnixCompress {
    lzw: Option<Lzw>,
    /// Header bytes still at the front of the input (3, until released).
    header: usize,
    consumed: usize,
    done: bool,
}

impl Default for UnixCompress {
    fn default() -> Self {
        UnixCompress {
            lzw: None,
            header: 3,
            consumed: 0,
            done: false,
        }
    }
}

impl UnixCompress {
    /// Headerless `compress` code data with the given flags byte (`0x80`
    /// block mode, low bits the maximum code width), as StuffIt's method 2
    /// stores it, up to the end of the input.
    pub fn raw(flags: u8) -> Result<Self> {
        Ok(UnixCompress {
            lzw: Some(Lzw::new(flags)?),
            header: 0,
            consumed: 0,
            done: false,
        })
    }
}

impl Decoder for UnixCompress {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        if self.done {
            return Ok(Status::Done);
        }
        let lzw = match &mut self.lzw {
            Some(lzw) => lzw,
            None => {
                if input.len() < 3 && !eof {
                    return Ok(Status::NeedInput);
                }
                if input.get(..2) != Some(&[0x1f, 0x9d]) {
                    return Err(bad("missing magic"));
                }
                let flags = *input.get(2).ok_or_else(|| bad("truncated header"))?;
                self.consumed = 3;
                self.lzw.insert(Lzw::new(flags)?)
            }
        };
        let data = input.get(self.header..).unwrap_or_default();
        let mark = out.len();
        if lzw.run(data, out, step, limit)? {
            self.consumed = lzw.pos.div_ceil(8).saturating_add(self.header);
            return Ok(Status::More);
        }
        if eof {
            // The stream ends with the input (the last bits are padding).
            self.consumed = input.len();
            self.done = true;
            return Ok(Status::Done);
        }
        self.consumed = (lzw.pos / 8).saturating_add(self.header);
        Ok(if out.len() > mark {
            Status::More
        } else {
            Status::NeedInput
        })
    }

    fn consumed(&self) -> usize {
        self.consumed
    }

    fn releasable_input(&self) -> usize {
        match &self.lzw {
            Some(_) if self.done => self.consumed,
            Some(lzw) => self.header.saturating_add(lzw.releasable_bits() / 8),
            None => 0,
        }
    }

    fn release_input(&mut self, n: usize) {
        self.consumed = self.consumed.saturating_sub(n);
        if self.done {
            return;
        }
        let from_header = n.min(self.header);
        self.header = self.header.saturating_sub(from_header);
        if let Some(lzw) = &mut self.lzw {
            lzw.release(n.saturating_sub(from_header).saturating_mul(8));
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    /// The string table (allocated whole for the maximum code width, so a
    /// CLEAR code does not make it smaller: 3 bytes per code, 192 KiB at 16
    /// bits) and the string being expanded; no window.
    fn checkpoint(&self) -> Option<Box<dyn Decoder>> {
        Some(Box::new(self.clone()))
    }

    fn state_size(&self) -> usize {
        let table = self.lzw.as_ref().map_or(0, |lzw| {
            lzw.prefix
                .capacity()
                .saturating_mul(2)
                .saturating_add(lzw.suffix.capacity())
                .saturating_add(lzw.stack.capacity())
        });
        std::mem::size_of::<Self>().saturating_add(table)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::codec::pipeline::verify_checkpoints;

    /// `/usr/bin/compress` output (`tests/data/compress`): 16-bit codes,
    /// 12-bit codes (`-b12`), incompressible data, and a megabyte of words
    /// whose table fills up and is cleared.
    #[test]
    fn checkpoints_resume_mid_stream() {
        for (name, step, every, bits) in [
            ("text.Z", 1024, 3, 16),
            ("text12.Z", 1024, 3, 12),
            ("rnd.Z", 1024, 3, 16),
            ("words.Z", 1 << 16, 7, 16),
        ] {
            let input = std::fs::read(format!(
                "{}/../../tests/data/compress/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            let (checked, largest) =
                verify_checkpoints(|| Box::new(UnixCompress::default()), &input, step, every)
                    .unwrap();
            assert!(checked > 3, "{name}: {checked}");
            let table = 3usize << bits;
            assert!(
                (table..table + 8192).contains(&largest),
                "{name}: {largest}"
            );
        }
    }
}
