//! TempleOS `.Z` compression (`CArcCompress`): a 17-byte header (64-bit
//! compressed and expanded sizes, a compression type), then either the
//! bytes as they are (`CT_NONE`) or LZW codes, LSB-first, of 8 (`CT_7_BIT`,
//! for text with no byte above 0x7f) or 9 (`CT_8_BIT`) bits growing to 12.
//!
//! Unlike Unix `compress`, there is no CLEAR code: once all 4096 codes are
//! in use, each new string takes the slot of an earlier one that no other
//! string extends (a leaf of the string tree), searched for cyclically from
//! the last slot taken. The decoder has to reproduce that search exactly,
//! so this is a port of `ArcExpandBuf` and `ArcEntryGet` in
//! `Kernel/Compress.HC` of the public-domain TempleOS V5.03 source
//! (cross-checked with Terry Davis's own Linux tool, `Linux/TOSZ.CPP`),
//! with the hash chains as slot indices. Two quirks carried over: when the
//! code width reaches 12 bits the slot at 2048 is skipped until the search
//! wraps, and a string's characters are pushed on a stack of at most 4096
//! bytes (longer chains, possible only in damaged data, are an error here
//! where TempleOS would overrun).
//!
//! [`TempleOsZ`] is a [`Decoder`] of its own that never rolls back: it
//! checks that a whole code is in the input before it changes any state.

use crate::bytes::{to_u64, to_usize, u64_le};
use crate::codec::pipeline::{Decoder, Status};
use crate::error::{DiagKind, Diagnostic, Result};

/// Header size: `compressed_size`, `expanded_size` (both `I64`) and
/// `compression_type` (`U8`).
pub const HEADER: usize = 17;
/// `CT_NONE`: the body is the expanded data.
pub const CT_NONE: u8 = 1;
/// `CT_7_BIT`: LZW over 7-bit characters (codes start at 8 bits).
pub const CT_7_BIT: u8 = 2;
/// `CT_8_BIT`: LZW over bytes (codes start at 9 bits).
pub const CT_8_BIT: u8 = 3;

const BITS_MAX: u32 = 12;
const SLOTS: usize = 1 << BITS_MAX;
const NONE: u16 = u16::MAX;

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("TempleOS .Z: {what}"))
}

/// `CArcEntry`: a string as (prefix code, last character), chained with
/// the other strings of the same prefix.
#[derive(Clone, Copy)]
struct Entry {
    next: u16,
    basecode: u16,
    ch: u8,
}

/// `CArcCtrl`, for expanding.
#[derive(Clone)]
struct Lzw {
    min_table_entry: usize,
    compress: Vec<Entry>,
    /// Heads of the chains of strings by prefix code.
    hash: Vec<u16>,
    cur_entry: usize,
    next_entry: usize,
    next_bits: u32,
    free_idx: usize,
    free_limit: usize,
    saved_basecode: Option<usize>,
    entry_used: bool,
    last_ch: u8,
    /// Characters still to be output, last first.
    stack: Vec<u8>,
}

impl Lzw {
    /// `ArcCtrlNew`.
    fn new(seven_bit: bool) -> Result<Self> {
        let min_bits: u32 = if seven_bit { 7 } else { 8 };
        let mut c = Lzw {
            min_table_entry: 1 << min_bits,
            compress: vec![
                Entry {
                    next: NONE,
                    basecode: 0,
                    ch: 0,
                };
                SLOTS
            ],
            hash: vec![NONE; SLOTS],
            cur_entry: 0,
            next_entry: 0,
            next_bits: min_bits.saturating_add(1),
            free_idx: 1 << min_bits,
            free_limit: 1 << min_bits.saturating_add(1),
            saved_basecode: None,
            entry_used: true,
            last_ch: 0,
            stack: Vec::with_capacity(SLOTS),
        };
        c.entry_get()?;
        c.entry_used = true;
        Ok(c)
    }

    fn entry(&self, i: usize) -> Entry {
        self.compress.get(i).copied().unwrap_or(Entry {
            next: NONE,
            basecode: 0,
            ch: 0,
        })
    }

    fn head(&self, code: usize) -> u16 {
        self.hash.get(code).copied().unwrap_or(NONE)
    }

    /// `ArcEntryGet`: makes the next free slot current and picks the one
    /// after it, growing the code width or, at 12 bits, recycling a leaf.
    fn entry_get(&mut self) -> Result<()> {
        if !self.entry_used {
            return Ok(());
        }
        let mut i = self.free_idx;
        self.entry_used = false;
        self.cur_entry = self.next_entry;
        if self.next_bits < BITS_MAX {
            self.next_entry = i;
            i = i.saturating_add(1);
            if i == self.free_limit {
                self.next_bits = self.next_bits.saturating_add(1);
                self.free_limit = 1 << self.next_bits;
            }
        } else {
            let mut tries = 0usize;
            loop {
                i = i.saturating_add(1);
                if i == self.free_limit {
                    i = self.min_table_entry;
                }
                if self.head(i) == NONE {
                    break;
                }
                tries = tries.saturating_add(1);
                if tries > SLOTS {
                    return Err(bad("no free string slot"));
                }
            }
            self.next_entry = i;
            self.unlink(i)?;
        }
        self.free_idx = i;
        Ok(())
    }

    /// Takes slot `t` out of the chain of its old prefix.
    fn unlink(&mut self, t: usize) -> Result<()> {
        let tag = u16::try_from(t).unwrap_or(NONE);
        let entry = self.entry(t);
        let base = usize::from(entry.basecode);
        if self.head(base) == tag {
            if let Some(h) = self.hash.get_mut(base) {
                *h = entry.next;
            }
            return Ok(());
        }
        let mut p = self.head(base);
        for _ in 0..SLOTS {
            if p == NONE {
                return Ok(());
            }
            let e = self.entry(p.into());
            if e.next == tag {
                if let Some(slot) = self.compress.get_mut(usize::from(p)) {
                    slot.next = entry.next;
                }
                return Ok(());
            }
            p = e.next;
        }
        Err(bad("string chain loops"))
    }

    /// Expands `basecode` onto the stack and adds the string the previous
    /// code and this one's first character make (the loop body of
    /// `ArcExpandBuf`).
    fn expand(&mut self, lastcode: usize, basecode: usize) -> Result<()> {
        let mut code = if self.cur_entry == basecode {
            self.stack.push(self.last_ch);
            lastcode
        } else {
            basecode
        };
        while code >= self.min_table_entry {
            if self.stack.len() >= SLOTS {
                return Err(bad("string longer than the stack"));
            }
            let e = self.entry(code);
            self.stack.push(e.ch);
            code = e.basecode.into();
        }
        // `code` is a literal here, below 256.
        self.last_ch = u8::try_from(code).unwrap_or(0);
        self.stack.push(self.last_ch);
        self.entry_used = true;
        let cur = self.cur_entry;
        let head = self.head(lastcode);
        if let Some(e) = self.compress.get_mut(cur) {
            e.basecode = u16::try_from(lastcode).unwrap_or(0);
            e.ch = self.last_ch;
            e.next = head;
        }
        if let Some(h) = self.hash.get_mut(lastcode) {
            *h = u16::try_from(cur).unwrap_or(NONE);
        }
        self.entry_get()
    }
}

/// Reads `bits` bits LSB-first at bit `pos` of `data` (`BFieldExtU32`).
fn bits_at(data: &[u8], pos: u64, bits: u32) -> usize {
    let mut v = 0usize;
    for i in 0..bits {
        let p = pos.saturating_add(i.into());
        let byte = usize::try_from(p / 8).unwrap_or(usize::MAX);
        let b = data.get(byte).copied().unwrap_or(0) >> (p % 8) & 1;
        v |= usize::from(b) << i;
    }
    v
}

fn short(what: &str) -> Diagnostic {
    Diagnostic::new(DiagKind::Truncated, format!("TempleOS .Z: {what}"))
}

/// A whole `CArcCompress` (header included), expanded as far as the input
/// reaches, up to its expanded size.
#[derive(Clone, Default)]
pub struct TempleOsZ {
    /// Compressed size (bits), expanded size, type; once the header is in.
    header: Option<(u64, u64, u8)>,
    lzw: Option<Box<Lzw>>,
    /// The next code's position, in bits from the start of the header.
    pos: u64,
    /// Input bytes dropped from the front.
    released: u64,
    produced: u64,
    /// Where the stream ended (bytes from its start), once it has.
    end: Option<u64>,
}

impl TempleOsZ {
    fn finish(&mut self, input_len: usize) -> Status {
        let have = self.released.saturating_add(to_u64(input_len));
        let size = self.header.map_or(0, |(bits, _, _)| bits / 8);
        self.end = Some(size.min(have));
        Status::Done
    }

    /// `CT_NONE`: the body is copied, `expanded_size` bytes of it.
    fn stored(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let expanded = self.header.map_or(0, |(_, e, _)| e);
        let from = to_usize((self.pos / 8).saturating_sub(self.released));
        let want = expanded.saturating_sub(self.produced);
        let avail = to_u64(input.len().saturating_sub(from));
        let n = want.min(avail).min(to_u64(step.max(1)));
        let chunk = input
            .get(from..from.saturating_add(to_usize(n)))
            .unwrap_or_default();
        if out.len().saturating_add(chunk.len()) > limit {
            return Err(Diagnostic::output_limit(limit));
        }
        out.extend_from_slice(chunk);
        self.produced = self.produced.saturating_add(n);
        self.pos = self.pos.saturating_add(n.saturating_mul(8));
        if self.produced >= expanded {
            return Ok(self.finish(input.len()));
        }
        if n > 0 {
            Ok(Status::More)
        } else if eof {
            Err(short("stored data ends before its expanded size"))
        } else {
            Ok(Status::NeedInput)
        }
    }
}

impl Decoder for TempleOsZ {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        if self.end.is_some() {
            return Ok(Status::Done);
        }
        let (compressed_bits, expanded, kind) = match self.header {
            Some(h) => h,
            None => {
                if input.len() < HEADER {
                    if eof {
                        return Err(short("header cut short"));
                    }
                    return Ok(Status::NeedInput);
                }
                let compressed = u64_le(input, 0).unwrap_or(0);
                let expanded = u64_le(input, 8).unwrap_or(0);
                let kind = input.get(16).copied().unwrap_or(0);
                if !(CT_NONE..=CT_8_BIT).contains(&kind) {
                    return Err(bad(&format!("unknown compression type {kind}")));
                }
                if compressed < to_u64(HEADER) {
                    return Err(bad("compressed size smaller than the header"));
                }
                let h = (compressed.saturating_mul(8), expanded, kind);
                self.header = Some(h);
                self.pos = to_u64(HEADER).saturating_mul(8);
                if kind != CT_NONE {
                    self.lzw = Some(Box::new(Lzw::new(kind == CT_7_BIT)?));
                }
                h
            }
        };
        if kind == CT_NONE {
            return self.stored(input, eof, out, step, limit);
        }
        let start = out.len();
        let released_bits = self.released.saturating_mul(8);
        let avail_bits = released_bits
            .saturating_add(to_u64(input.len()).saturating_mul(8))
            .min(compressed_bits);
        loop {
            let Some(lzw) = self.lzw.as_deref_mut() else {
                return Err(Diagnostic::internal("TempleOS .Z: no decoder state"));
            };
            while self.produced < expanded {
                let Some(b) = lzw.stack.pop() else { break };
                if out.len() >= limit {
                    return Err(Diagnostic::output_limit(limit));
                }
                out.push(b);
                self.produced = self.produced.saturating_add(1);
            }
            if self.produced >= expanded {
                return Ok(self.finish(input.len()));
            }
            if out.len().saturating_sub(start) >= step {
                return Ok(Status::More);
            }
            let bits = lzw.next_bits;
            let end = self.pos.saturating_add(bits.into());
            if end > avail_bits {
                if end > compressed_bits {
                    return Err(bad(&format!(
                        "codes end {} bytes short of the expanded size",
                        expanded.saturating_sub(self.produced)
                    )));
                }
                if eof {
                    return Err(short("code data cut short"));
                }
                return Ok(if out.len() > start {
                    Status::More
                } else {
                    Status::NeedInput
                });
            }
            let code = bits_at(input, self.pos.saturating_sub(released_bits), bits);
            self.pos = end;
            match lzw.saved_basecode {
                None => {
                    // The first code is a character of its own.
                    if code >= lzw.min_table_entry {
                        return Err(bad("first code is not a character"));
                    }
                    lzw.last_ch = u8::try_from(code).unwrap_or(0);
                    lzw.stack.push(lzw.last_ch);
                    lzw.entry_get()?;
                }
                Some(lastcode) => lzw.expand(lastcode, code)?,
            }
            lzw.saved_basecode = Some(code);
        }
    }

    fn consumed(&self) -> usize {
        let bytes = self.end.unwrap_or_else(|| self.pos.div_ceil(8));
        to_usize(bytes.saturating_sub(self.released))
    }

    fn releasable_input(&self) -> usize {
        if self.header.is_none() {
            return 0;
        }
        let at = self.end.unwrap_or(self.pos / 8);
        to_usize(at.saturating_sub(self.released))
    }

    fn release_input(&mut self, n: usize) {
        self.released = self.released.saturating_add(to_u64(n));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    fn checkpoint(&self) -> Option<Box<dyn Decoder>> {
        Some(Box::new(self.clone()))
    }

    /// The string table (4096 slots of 6 bytes), the chain heads (8 KiB)
    /// and the stack (4 KiB).
    fn state_size(&self) -> usize {
        let table = self.lzw.as_ref().map_or(0, |l| {
            l.compress
                .capacity()
                .saturating_mul(std::mem::size_of::<Entry>())
                .saturating_add(l.hash.capacity().saturating_mul(2))
                .saturating_add(l.stack.capacity())
                .saturating_add(std::mem::size_of::<Lzw>())
        });
        std::mem::size_of::<Self>().saturating_add(table)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{decode_all, verify_checkpoints};

    fn read(rel: &str) -> Vec<u8> {
        std::fs::read(format!("{}/../../tests/{rel}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn decode(input: &[u8]) -> Result<Vec<u8>> {
        decode_all(&mut TempleOsZ::default(), input, 1 << 26)
    }

    /// Real `.Z` files from the TempleOS V5.03 ISO (7-bit, 8-bit with
    /// sprites, long enough to recycle string slots, stored) decode to
    /// exactly what TOSZ (`Linux/TOSZ.CPP` from the same tree) writes for
    /// them, kept in `tests/data/templeos-z`.
    #[test]
    fn matches_tosz() {
        for name in [
            "DateTime.HC",
            "FileLowLevel.DD",
            "FileSysRedSea.HC",
            "StadiumBG.GR",
        ] {
            let z = read(&format!("fixtures/external/templeos-z/{name}.Z"));
            let want = read(&format!("data/templeos-z/{name}"));
            assert_eq!(decode(&z).unwrap(), want, "{name}");
        }
    }

    /// With `TEMPLEOS_Z_DIRS=<files>:<tosz outputs>` (the ISO's files as
    /// `tests/data/redsea/extract.py` writes them, and TOSZ's expansion of
    /// each `.Z` at the same path without `.Z`), checks every one.
    #[test]
    fn matches_tosz_everywhere() {
        let Ok(dirs) = std::env::var("TEMPLEOS_Z_DIRS") else {
            return;
        };
        let (src, want) = dirs.split_once(':').unwrap();
        let mut stack = vec![std::path::PathBuf::from(src)];
        let mut n = 0;
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "Z") {
                    let rel = p.strip_prefix(src).unwrap().with_extension("");
                    let expected = std::fs::read(std::path::Path::new(want).join(&rel)).unwrap();
                    let got = decode(&std::fs::read(&p).unwrap()).unwrap();
                    assert!(got == expected, "{}", rel.display());
                    n += 1;
                }
            }
        }
        eprintln!("{n} files match TOSZ");
    }

    #[test]
    fn stored_and_damaged() {
        let mut z = vec![0u8; HEADER];
        z[0] = 20;
        z[8] = 3;
        z[16] = CT_NONE;
        z.extend_from_slice(b"abc");
        assert_eq!(decode(&z).unwrap(), b"abc");
        z[16] = 9;
        assert!(decode(&z).is_err());
        // All-ones codes: each refers to the slot about to be filled, so
        // strings grow by one character per code until the stack limit.
        let mut lz = vec![0u8; HEADER];
        lz[0] = 120;
        lz[8] = 0xff;
        lz[9] = 0xff;
        lz[16] = CT_8_BIT;
        lz.extend(std::iter::repeat_n(0x01u8, 1));
        lz.extend(std::iter::repeat_n(0xffu8, 102));
        let e = decode(&lz).unwrap_err();
        assert_eq!(e.kind, DiagKind::Malformed, "{e}");
        // Cut short: truncated, not malformed.
        let full = read("fixtures/external/templeos-z/DateTime.HC.Z");
        let e = decode(&full[..100]).unwrap_err();
        assert_eq!(e.kind, DiagKind::Truncated, "{e}");
    }

    #[test]
    fn checkpoints_resume_mid_stream() {
        let z = read("fixtures/external/templeos-z/FileSysRedSea.HC.Z");
        let (checked, largest) =
            verify_checkpoints(|| Box::new(TempleOsZ::default()), &z, 512, 3).unwrap();
        assert!(checked > 3, "{checked}");
        assert!(largest < 64 << 10, "{largest}");
    }
}
