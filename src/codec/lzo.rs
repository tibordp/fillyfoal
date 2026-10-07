//! LZO1X (the bitstream of `lzo1x_1`, `lzo1x_1_15` and `lzo1x_999`, decoded
//! like `lzo1x_decompress_safe`) and the lzop (`.lzo`) container: a header,
//! then independently compressed blocks with optional Adler-32/CRC-32 checks
//! of the compressed and uncompressed bytes.

use crate::codec::filters::Filter;
use crate::codec::pipeline::{Decode, Step};
use crate::codec::{adler32, crc32};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("LZO: {what}"))
}

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
}

/// The LZO1X input cursor.
struct In<'a> {
    data: &'a [u8],
    pos: usize,
}

impl In<'_> {
    fn byte(&mut self) -> Result<usize> {
        let b = self
            .data
            .get(self.pos)
            .copied()
            .ok_or_else(|| bad("input overrun"))?;
        self.pos = self.pos.saturating_add(1);
        Ok(usize::from(b))
    }

    /// A length continued by zero bytes (each worth 255) and a final byte.
    fn extended(&mut self, base: usize) -> Result<usize> {
        let mut t = 0usize;
        loop {
            let b = self.byte()?;
            if b != 0 {
                return Ok(t.saturating_add(base).saturating_add(b));
            }
            t = t.saturating_add(255);
        }
    }

    fn literals(&mut self, n: usize, out: &mut Vec<u8>, base: usize, limit: usize) -> Result<()> {
        let end = self.pos.saturating_add(n);
        let lit = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| bad("input overrun in literals"))?;
        if out.len().saturating_sub(base).saturating_add(n) > limit {
            return Err(too_big(limit));
        }
        out.extend_from_slice(lit);
        self.pos = end;
        Ok(())
    }
}

/// Copies `len` bytes from `dist` back (overlap allowed); the window starts
/// at `base`.
fn copy_match(out: &mut Vec<u8>, base: usize, dist: usize, len: usize, limit: usize) -> Result<()> {
    if dist == 0 || dist > out.len().saturating_sub(base) {
        return Err(bad("match distance before the start of the output"));
    }
    if out.len().saturating_sub(base).saturating_add(len) > limit {
        return Err(too_big(limit));
    }
    let start = out.len().saturating_sub(dist);
    for i in 0..len {
        let b = out.get(start.saturating_add(i)).copied().unwrap_or(0);
        out.push(b);
    }
    Ok(())
}

/// Decodes one LZO1X stream (up to and including its end marker) onto `out`;
/// returns the number of input bytes consumed. At most `limit` bytes are
/// produced.
pub fn lzo1x(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<usize> {
    #[derive(Clone, Copy)]
    enum State {
        /// Expecting an instruction after a literal run of 0 (a match) or of
        /// 4+ bytes: a byte below 16 is then a 3-byte match ("M1" far).
        AfterLongRun,
        /// Expecting an instruction after a match: a byte below 16 starts a
        /// literal run.
        Top,
        /// After 1-3 literals: a byte below 16 is a 2-byte match.
        AfterShortRun,
    }
    let base = out.len();
    let mut ip = In {
        data: input,
        pos: 0,
    };
    let mut state = State::Top;
    if let Some(&first) = input.first()
        && first > 17
    {
        ip.pos = 1;
        let t = usize::from(first).saturating_sub(17);
        ip.literals(t, out, base, limit)?;
        state = if t < 4 {
            State::AfterShortRun
        } else {
            State::AfterLongRun
        };
    }
    loop {
        let t = ip.byte()?;
        // `state_bits` is the 2-bit trailing literal count of a match.
        let state_bits = if t < 16 {
            match state {
                State::Top => {
                    let n = if t == 0 { ip.extended(15)? } else { t };
                    ip.literals(n.saturating_add(3), out, base, limit)?;
                    state = State::AfterLongRun;
                    continue;
                }
                State::AfterLongRun => {
                    let b = ip.byte()?;
                    let dist = (t >> 2).saturating_add(b << 2).saturating_add(0x801);
                    copy_match(out, base, dist, 3, limit)?;
                }
                State::AfterShortRun => {
                    let b = ip.byte()?;
                    let dist = (t >> 2).saturating_add(b << 2).saturating_add(1);
                    copy_match(out, base, dist, 2, limit)?;
                }
            }
            t & 3
        } else if t >= 64 {
            let b = ip.byte()?;
            let dist = (t >> 2 & 7).saturating_add(b << 3).saturating_add(1);
            let len = (t >> 5).saturating_add(1);
            copy_match(out, base, dist, len, limit)?;
            t & 3
        } else if t >= 32 {
            let len = if t & 31 == 0 {
                ip.extended(31)?
            } else {
                t & 31
            };
            let lo = ip.byte()?;
            let hi = ip.byte()?;
            let dist = (lo >> 2).saturating_add(hi << 6).saturating_add(1);
            copy_match(out, base, dist, len.saturating_add(2), limit)?;
            lo & 3
        } else {
            let len = if t & 7 == 0 { ip.extended(7)? } else { t & 7 };
            let lo = ip.byte()?;
            let hi = ip.byte()?;
            let dist = ((t & 8) << 11)
                .saturating_add(lo >> 2)
                .saturating_add(hi << 6);
            if dist == 0 {
                return Ok(ip.pos); // end of stream
            }
            copy_match(
                out,
                base,
                dist.saturating_add(0x4000),
                len.saturating_add(2),
                limit,
            )?;
            lo & 3
        };
        if state_bits == 0 {
            state = State::Top;
        } else {
            ip.literals(state_bits, out, base, limit)?;
            state = State::AfterShortRun;
        }
    }
}

/// One raw LZO1X stream.
#[derive(Clone, Copy)]
pub struct Lzo1x;

impl Filter for Lzo1x {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        lzo1x(input, &mut out, limit)?;
        Ok(out)
    }
}

pub const LZOP_MAGIC: &[u8; 9] = b"\x89LZO\0\r\n\x1a\n";

/// lzop header flags.
pub const F_ADLER32_D: u32 = 0x1;
pub const F_ADLER32_C: u32 = 0x2;
pub const F_H_EXTRA_FIELD: u32 = 0x40;
pub const F_CRC32_D: u32 = 0x100;
pub const F_CRC32_C: u32 = 0x200;
pub const F_H_FILTER: u32 = 0x800;
pub const F_H_CRC32: u32 = 0x1000;

/// lzop's largest block (`MAX_BLOCK_SIZE`).
pub const LZOP_MAX_BLOCK: u32 = 64 * 1024 * 1024;

fn be32(data: &[u8], at: usize) -> Result<u32> {
    crate::bytes::u32_be(data, at).ok_or_else(|| bad("truncated lzop file"))
}

fn be16(data: &[u8], at: usize) -> Result<u16> {
    crate::bytes::u16_be(data, at).ok_or_else(|| bad("truncated lzop header"))
}

/// A parsed lzop header.
pub struct LzopHeader {
    pub version: u16,
    pub method: u8,
    pub flags: u32,
    /// Where the header checksum is stored.
    pub checksum_at: usize,
    /// Whether the header checksum matches.
    pub checksum_ok: bool,
    /// The size of the header, the checksum and any extra field included.
    pub len: usize,
}

/// Parses an lzop header at the start of `data`.
pub fn lzop_header(data: &[u8]) -> Result<LzopHeader> {
    if data.get(..9) != Some(LZOP_MAGIC.as_slice()) {
        return Err(bad("missing lzop magic"));
    }
    let version = be16(data, 9)?;
    if version < 0x0900 {
        return Err(bad("lzop version too old"));
    }
    let mut pos = 13usize; // magic, version, library version
    if version >= 0x0940 {
        pos = pos.saturating_add(2); // version needed to extract
    }
    let method = *data.get(pos).ok_or_else(|| bad("truncated lzop header"))?;
    pos = pos.saturating_add(if version >= 0x0940 { 2 } else { 1 });
    let flags = be32(data, pos)?;
    pos = pos.saturating_add(4);
    if flags & F_H_FILTER != 0 {
        pos = pos.saturating_add(4);
    }
    pos = pos.saturating_add(8); // mode, low modification time
    if version >= 0x0940 {
        pos = pos.saturating_add(4);
    }
    let name_len = *data.get(pos).ok_or_else(|| bad("truncated lzop header"))?;
    pos = pos.saturating_add(1).saturating_add(usize::from(name_len));
    let checksum_at = pos;
    let stored = be32(data, checksum_at)?;
    let covered = data
        .get(9..checksum_at)
        .ok_or_else(|| bad("truncated lzop header"))?;
    let computed = if flags & F_H_CRC32 != 0 {
        crc32(covered)
    } else {
        adler32(covered)
    };
    pos = checksum_at.saturating_add(4);
    if flags & F_H_EXTRA_FIELD != 0 {
        let len = be32(data, pos)?;
        pos = pos
            .saturating_add(8)
            .saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
    }
    Ok(LzopHeader {
        version,
        method,
        flags,
        checksum_at,
        checksum_ok: stored == computed,
        len: pos,
    })
}

/// The size of a block header (sizes and checksums) given the flags and
/// whether the block is compressed.
pub fn lzop_block_header_len(flags: u32, compressed: bool) -> usize {
    let mut len = 8usize;
    for (flag, data_check) in [
        (F_ADLER32_D, true),
        (F_CRC32_D, true),
        (F_ADLER32_C, false),
        (F_CRC32_C, false),
    ] {
        if flags & flag != 0 && (data_check || compressed) {
            len = len.saturating_add(4);
        }
    }
    len
}

/// The lzop container: one or more concatenated members, decoded a block
/// (with its checks) at a time.
#[derive(Clone, Default)]
pub struct Lzop {
    pos: usize,
    /// The current member's flags, once its header has been read.
    member: Option<u32>,
    /// A member has ended: another may follow.
    between: bool,
    done: bool,
}

impl Lzop {
    /// Reads a member header at `self.pos`.
    fn header(&mut self, input: &[u8]) -> Result<()> {
        let rest = input.get(self.pos..).unwrap_or_default();
        let header = lzop_header(rest)?;
        if !header.checksum_ok {
            return Err(bad("lzop header checksum mismatch"));
        }
        if !matches!(header.method, 1..=3) {
            return Err(Diagnostic::unsupported(format!(
                "lzop method {}",
                header.method
            )));
        }
        if header.flags & F_H_FILTER != 0 {
            return Err(Diagnostic::unsupported("lzop filters"));
        }
        self.pos = self.pos.saturating_add(header.len);
        self.member = Some(header.flags);
        Ok(())
    }

    /// Decodes the block at `self.pos` of a member with `flags`.
    fn block(&mut self, flags: u32, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
        let pos = self.pos;
        let raw = be32(input, pos)?;
        if raw == 0 {
            self.pos = pos.saturating_add(4);
            self.member = None;
            self.between = true;
            return Ok(());
        }
        let packed = be32(input, pos.saturating_add(4))?;
        if raw > LZOP_MAX_BLOCK || packed > raw {
            return Err(bad("bad lzop block size"));
        }
        let compressed = packed < raw;
        let mut at = pos.saturating_add(8);
        let mut check = |flag: u32, data_check: bool| -> Result<Option<(u32, bool, bool)>> {
            if flags & flag == 0 || !(data_check || compressed) {
                return Ok(None);
            }
            let v = be32(input, at)?;
            at = at.saturating_add(4);
            Ok(Some((v, data_check, flag & (F_CRC32_C | F_CRC32_D) != 0)))
        };
        let checks = [
            check(F_ADLER32_D, true)?,
            check(F_CRC32_D, true)?,
            check(F_ADLER32_C, false)?,
            check(F_CRC32_C, false)?,
        ];
        let (raw, packed) = (
            usize::try_from(raw).unwrap_or(usize::MAX),
            usize::try_from(packed).unwrap_or(usize::MAX),
        );
        let data = input
            .get(at..at.saturating_add(packed))
            .ok_or_else(|| bad("truncated lzop block"))?;
        if out.len().saturating_add(raw) > limit {
            return Err(too_big(limit));
        }
        let start = out.len();
        if compressed {
            let used = lzo1x(data, out, raw)?;
            if used != packed {
                return Err(bad("lzop block has trailing bytes"));
            }
        } else {
            out.extend_from_slice(data);
        }
        let block = out.get(start..).unwrap_or_default();
        if block.len() != raw {
            return Err(bad("lzop block decoded to the wrong size"));
        }
        for (stored, data_check, crc) in checks.into_iter().flatten() {
            let subject = if data_check { block } else { data };
            let computed = if crc {
                crc32(subject)
            } else {
                adler32(subject)
            };
            if computed != stored {
                return Err(bad("lzop block checksum mismatch"));
            }
        }
        self.pos = at.saturating_add(packed);
        Ok(())
    }
}

impl Decode for Lzop {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let mark = out.len();
        while !self.done {
            match self.member {
                Some(flags) => self.block(flags, input, out, limit)?,
                None if self.between => {
                    // Another member follows if the magic does.
                    let rest = input.get(self.pos..).unwrap_or_default();
                    let n = rest.len().min(LZOP_MAGIC.len());
                    if rest.get(..n) != LZOP_MAGIC.get(..n) {
                        self.done = true;
                    } else if n < LZOP_MAGIC.len() {
                        if !eof {
                            return Err(bad("truncated lzop file"));
                        }
                        self.done = true;
                    } else {
                        self.header(input)?;
                    }
                }
                None => self.header(input)?,
            }
            if out.len().saturating_sub(mark) >= step {
                return Ok(Step::More);
            }
        }
        Ok(Step::Done)
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        // Headers and blocks (with their checks) are read whole from `pos`.
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Blocks are independent, and checked as they are decoded.
        out_len
    }
}
