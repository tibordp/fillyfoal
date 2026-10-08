//! LZO1X (the bitstream of `lzo1x_1`, `lzo1x_1_15` and `lzo1x_999`, decoded
//! like `lzo1x_decompress_safe`) and the lzop (`.lzo`) container: a header,
//! then independently compressed blocks with optional Adler-32/CRC-32 checks
//! of the compressed and uncompressed bytes.

use crate::codec::lz::{
    Run, RunMemo, SCAN, Units, literal_chunk, match_chunk, read_run, run_units,
};
use crate::codec::pipeline::{Decode, Step};
use crate::codec::{adler32, crc32};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("LZO: {what}"))
}

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
}

/// Decodes one LZO1X stream (up to and including its end marker) onto `out`;
/// returns the number of input bytes consumed. At most `limit` bytes are
/// produced.
pub fn lzo1x(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<usize> {
    let mut d = Lzo1x {
        base: out.len(),
        ..Lzo1x::default()
    };
    while !matches!(d.at, LzoAt::End) {
        d.unit(input, true, out, usize::MAX, limit)?;
    }
    Ok(d.pos)
}

/// The farthest an LZO1X match reaches back (an M4 match: 0xbfff).
const LZO_WINDOW: usize = 0xc000;

/// What the instruction after a literal run or a match may be.
#[derive(Clone, Copy, Default)]
enum LzoState {
    /// After a literal run of 0 (a match) or of 4+ bytes: a byte below 16
    /// is then a 3-byte match ("M1" far).
    AfterLongRun,
    /// After a match: a byte below 16 starts a literal run.
    #[default]
    Top,
    /// After 1-3 literals: a byte below 16 is a 2-byte match.
    AfterShortRun,
}

/// Where an [`Lzo1x`] decoder is.
#[derive(Clone, Copy, Default)]
enum LzoAt {
    /// Before the first byte (which may start with a literal run).
    #[default]
    Start,
    /// At an instruction.
    Instruction,
    /// Copying a match, then `trailing` (0-3) literals.
    Match {
        dist: usize,
        left: usize,
        trailing: usize,
    },
    /// Copying literals, then expecting an instruction in state `then`.
    Literals { left: usize, then: LzoState },
    /// After the end marker.
    End,
}

/// One raw LZO1X stream, decoded an instruction (or a bounded piece of a
/// long literal run or match) at a time. Input after the end marker is
/// ignored.
#[derive(Clone, Default)]
pub struct Lzo1x {
    pos: usize,
    /// Where the window starts in `out` (the limit counts from there too).
    base: usize,
    at: LzoAt,
    state: LzoState,
    memo: RunMemo,
    done: bool,
}

impl Lzo1x {
    /// A length: `low` if nonzero, else `base` continued by zero bytes (each
    /// worth 255) and a final byte at `at`. `None` when suspended.
    fn length(
        &mut self,
        input: &[u8],
        at: usize,
        low: usize,
        base: usize,
    ) -> Result<Option<(usize, usize)>> {
        if low != 0 {
            return Ok(Some((low, at)));
        }
        match read_run(input, at, 0, &mut self.memo) {
            Run::Done(extra, next) => Ok(Some((extra.saturating_add(base), next))),
            Run::Suspended => Ok(None),
            Run::Short => Err(bad("input overrun")),
        }
    }

    /// Starts a match after checking it against the window and the limit.
    fn start_match(
        &mut self,
        out: &[u8],
        dist: usize,
        len: usize,
        trailing: usize,
        next: usize,
        limit: usize,
    ) -> Result<usize> {
        let held = out.len().saturating_sub(self.base);
        if dist == 0 || dist > held {
            return Err(bad("match distance before the start of the output"));
        }
        if held.saturating_add(len) > limit {
            return Err(too_big(limit));
        }
        self.pos = next;
        self.at = LzoAt::Match {
            dist,
            left: len,
            trailing,
        };
        Ok(1)
    }

    /// Decodes the instruction at `pos`.
    fn instruction(&mut self, input: &[u8], out: &[u8], limit: usize) -> Result<usize> {
        let byte = |at: usize| -> Result<usize> {
            input
                .get(at)
                .map(|&b| usize::from(b))
                .ok_or_else(|| bad("input overrun"))
        };
        let t = byte(self.pos)?;
        let p = self.pos.saturating_add(1);
        if t < 16 {
            return match self.state {
                LzoState::Top => {
                    let Some((n, next)) = self.length(input, p, t, 15)? else {
                        return Ok(SCAN);
                    };
                    self.pos = next;
                    self.at = LzoAt::Literals {
                        left: n.saturating_add(3),
                        then: LzoState::AfterLongRun,
                    };
                    Ok(1)
                }
                LzoState::AfterLongRun => {
                    let b = byte(p)?;
                    let dist = (t >> 2).saturating_add(b << 2).saturating_add(0x801);
                    self.start_match(out, dist, 3, t & 3, p.saturating_add(1), limit)
                }
                LzoState::AfterShortRun => {
                    let b = byte(p)?;
                    let dist = (t >> 2).saturating_add(b << 2).saturating_add(1);
                    self.start_match(out, dist, 2, t & 3, p.saturating_add(1), limit)
                }
            };
        }
        if t >= 64 {
            let b = byte(p)?;
            let dist = (t >> 2 & 7).saturating_add(b << 3).saturating_add(1);
            let len = (t >> 5).saturating_add(1);
            return self.start_match(out, dist, len, t & 3, p.saturating_add(1), limit);
        }
        if t >= 32 {
            let Some((len, at)) = self.length(input, p, t & 31, 31)? else {
                return Ok(SCAN);
            };
            let lo = byte(at)?;
            let hi = byte(at.saturating_add(1))?;
            let dist = (lo >> 2).saturating_add(hi << 6).saturating_add(1);
            let next = at.saturating_add(2);
            return self.start_match(out, dist, len.saturating_add(2), lo & 3, next, limit);
        }
        let Some((len, at)) = self.length(input, p, t & 7, 7)? else {
            return Ok(SCAN);
        };
        let lo = byte(at)?;
        let hi = byte(at.saturating_add(1))?;
        let next = at.saturating_add(2);
        let dist = ((t & 8) << 11)
            .saturating_add(lo >> 2)
            .saturating_add(hi << 6);
        if dist == 0 {
            self.pos = next;
            self.at = LzoAt::End;
            return Ok(1);
        }
        self.start_match(
            out,
            dist.saturating_add(0x4000),
            len.saturating_add(2),
            lo & 3,
            next,
            limit,
        )
    }
}

impl Units for Lzo1x {
    fn unit(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        room: usize,
        limit: usize,
    ) -> Result<usize> {
        let budget = limit.saturating_sub(out.len().saturating_sub(self.base));
        match self.at {
            LzoAt::Start => {
                let Some(&first) = input.first() else {
                    if !eof {
                        return Err(bad("input overrun"));
                    }
                    self.at = LzoAt::Instruction;
                    return Ok(1);
                };
                if first > 17 {
                    let t = usize::from(first).saturating_sub(17);
                    self.pos = 1;
                    self.at = LzoAt::Literals {
                        left: t,
                        then: if t < 4 {
                            LzoState::AfterShortRun
                        } else {
                            LzoState::AfterLongRun
                        },
                    };
                } else {
                    self.at = LzoAt::Instruction;
                }
                Ok(1)
            }
            LzoAt::Instruction => self.instruction(input, out, limit),
            LzoAt::Literals { left, then } => {
                let mut left = left;
                let n = if left > 0 {
                    literal_chunk(
                        input,
                        eof,
                        &mut self.pos,
                        &mut left,
                        out,
                        room,
                        budget,
                        limit,
                        &|| bad("input overrun in literals"),
                    )?
                } else {
                    0
                };
                if left == 0 {
                    self.state = then;
                    self.at = LzoAt::Instruction;
                } else {
                    self.at = LzoAt::Literals { left, then };
                }
                Ok(n)
            }
            LzoAt::Match {
                dist,
                left,
                trailing,
            } => {
                let mut left = left;
                let n = match_chunk(out, dist, &mut left, room, budget, limit)?;
                self.at = match (left, trailing) {
                    (0, 0) => {
                        self.state = LzoState::Top;
                        LzoAt::Instruction
                    }
                    (0, t) => LzoAt::Literals {
                        left: t,
                        then: LzoState::AfterShortRun,
                    },
                    _ => LzoAt::Match {
                        dist,
                        left,
                        trailing,
                    },
                };
                Ok(n)
            }
            LzoAt::End => {
                // Input after the end marker is ignored, once it has all
                // been seen.
                if eof {
                    self.pos = input.len().max(self.pos);
                    self.done = true;
                    return Ok(1);
                }
                if self.pos < input.len() {
                    self.pos = input.len();
                    return Ok(1);
                }
                Err(bad("waiting for the end of the input"))
            }
        }
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn progress(&self) -> usize {
        self.pos.wrapping_add(self.memo.mark())
    }
}

impl Decode for Lzo1x {
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
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        self.memo.rebase(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
            .saturating_sub(LZO_WINDOW)
            .max(self.base)
            .min(out_len)
    }

    fn release_output(&mut self, n: usize) {
        self.base = self.base.saturating_sub(n);
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
