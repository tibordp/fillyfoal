//! LZO1X (the bitstream of `lzo1x_1`, `lzo1x_1_15` and `lzo1x_999`, decoded
//! like `lzo1x_decompress_safe`) and the lzop (`.lzo`) container: a header,
//! then independently compressed blocks with optional Adler-32/CRC-32 checks
//! of the compressed and uncompressed bytes.

use crate::codec::crc::crc32_update;
use crate::codec::lz::{
    Run, RunMemo, SCAN, Sub, Units, literal_chunk, match_chunk, read_run, run_units,
};
use crate::codec::pipeline::{Decode, Step};
use crate::codec::{Adler32, adler32, crc32};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("LZO: {what}"))
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
            return Err(Diagnostic::output_limit(limit));
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

/// An [`Lzo1x`] run up to its end marker (input after it is the caller's).
struct ToEnd<'a>(&'a mut Lzo1x);

impl Units for ToEnd<'_> {
    fn unit(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        room: usize,
        limit: usize,
    ) -> Result<usize> {
        self.0.unit(input, eof, out, room, limit)
    }

    fn finished(&self) -> bool {
        matches!(self.0.at, LzoAt::End)
    }

    fn progress(&self) -> usize {
        self.0.progress()
    }
}

/// Running Adler-32 and CRC-32 of a block's bytes (those asked for).
#[derive(Clone, Copy)]
struct Sums {
    adler: Option<Adler32>,
    /// The CRC-32 register (before the final inversion).
    crc: Option<u32>,
}

impl Sums {
    fn new(adler: bool, crc: bool) -> Self {
        Sums {
            adler: adler.then(Adler32::new),
            crc: crc.then_some(u32::MAX),
        }
    }

    fn update(&mut self, data: &[u8]) {
        if let Some(a) = self.adler.as_mut() {
            a.update(data);
        }
        if let Some(c) = self.crc.as_mut() {
            *c = crc32_update(*c, data);
        }
    }

    fn value(&self, crc: bool) -> u32 {
        if crc {
            !self.crc.unwrap_or(u32::MAX)
        } else {
            self.adler.unwrap_or_default().value()
        }
    }
}

/// A stored check: its value, whether it covers the decoded bytes (else
/// the compressed ones), and whether it is a CRC-32 (else an Adler-32).
type Check = (u32, bool, bool);

/// The lzop block being decoded: copied (stored) or run through an
/// [`Lzo1x`] a bounded step at a time, its checks computed as it goes.
#[derive(Clone)]
struct LzopBlock {
    sub: Sub,
    raw: usize,
    produced: usize,
    lzo: Option<Lzo1x>,
    checks: [Option<Check>; 4],
    /// Of the decoded bytes.
    data: Sums,
    /// Of the compressed bytes.
    packed: Sums,
}

impl LzopBlock {
    /// Runs one step of the block, producing about `room` bytes; returns
    /// whether it has ended (and passed its checks).
    fn step(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, room: usize) -> Result<bool> {
        let (slice, whole) = self.sub.slice(input);
        if !whole && eof {
            return Err(bad("truncated lzop block"));
        }
        let mark = out.len();
        match self.lzo.as_mut() {
            Some(d) => {
                let before = d.pos;
                let status = run_units(&mut ToEnd(d), slice, whole, out, room, self.raw)?;
                self.packed
                    .update(slice.get(before..d.pos).unwrap_or_default());
                self.data.update(out.get(mark..).unwrap_or_default());
                self.produced = self.produced.saturating_add(out.len().saturating_sub(mark));
                if status == Step::More {
                    return Ok(false);
                }
                if d.pos != self.sub.end.saturating_sub(self.sub.from) {
                    return Err(bad("lzop block has trailing bytes"));
                }
            }
            None => {
                let n = self.sub.copy(input, out, room);
                self.data.update(out.get(mark..).unwrap_or_default());
                self.produced = self.produced.saturating_add(n);
                if !self.sub.copied() {
                    if n == 0 {
                        return Err(bad("truncated lzop block"));
                    }
                    return Ok(false);
                }
            }
        }
        if self.produced != self.raw {
            return Err(bad("lzop block decoded to the wrong size"));
        }
        for (stored, data_check, crc) in self.checks.into_iter().flatten() {
            let sums = if data_check { self.data } else { self.packed };
            if sums.value(crc) != stored {
                return Err(bad("lzop block checksum mismatch"));
            }
        }
        Ok(true)
    }
}

/// The lzop container: one or more concatenated members, decoded a header
/// at a time and blocks (with their checks) a bounded step at a time.
#[derive(Clone, Default)]
pub struct Lzop {
    /// The next header's position (the current block's, while one is being
    /// decoded).
    pos: usize,
    /// The current member's flags, once its header has been read.
    member: Option<u32>,
    /// A member has ended: another may follow.
    between: bool,
    block: Option<LzopBlock>,
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

    /// Reads the block header at `self.pos` of a member with `flags`, and
    /// starts the block.
    fn block_header(
        &mut self,
        flags: u32,
        input: &[u8],
        eof: bool,
        out: &[u8],
        limit: usize,
    ) -> Result<()> {
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
        let mut check = |flag: u32, data_check: bool| -> Result<Option<Check>> {
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
        let sub = Sub::new(at, packed);
        if eof && input.len() < sub.end {
            return Err(bad("truncated lzop block"));
        }
        if out.len().saturating_add(raw) > limit {
            return Err(Diagnostic::output_limit(limit));
        }
        let wants = |flag: u32| flags & flag != 0;
        self.block = Some(LzopBlock {
            sub,
            raw,
            produced: 0,
            lzo: compressed.then(|| Lzo1x {
                base: out.len(),
                ..Lzo1x::default()
            }),
            checks,
            data: Sums::new(wants(F_ADLER32_D), wants(F_CRC32_D)),
            packed: Sums::new(
                compressed && wants(F_ADLER32_C),
                compressed && wants(F_CRC32_C),
            ),
        });
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
        // Headers (each a bounded read) count as work alongside output.
        let mut headers = 0usize;
        loop {
            let work = out
                .len()
                .saturating_sub(mark)
                .saturating_add(headers.saturating_mul(64));
            if work >= step.max(1) {
                return Ok(Step::More);
            }
            if let Some(block) = self.block.as_mut() {
                if !block.step(input, eof, out, step.saturating_sub(work))? {
                    return Ok(Step::More);
                }
                self.pos = block.sub.end;
                self.block = None;
                continue;
            }
            if self.done {
                return Ok(Step::Done);
            }
            headers = headers.saturating_add(1);
            match self.member {
                Some(flags) => self.block_header(flags, input, eof, out, limit)?,
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
        }
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        match &self.block {
            // Checked as it is consumed.
            Some(b) => b
                .sub
                .from
                .saturating_add(b.lzo.as_ref().map_or(0, |d| d.releasable_input())),
            // Headers are read whole from `pos`.
            None => self.pos,
        }
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        if let Some(b) = self.block.as_mut() {
            let inner = b.sub.release(n);
            if let Some(d) = b.lzo.as_mut() {
                d.release_input(inner);
            }
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        match self.block.as_ref().and_then(|b| b.lzo.as_ref()) {
            // A compressed block refers back into its own output.
            Some(d) => d.releasable_output(out_len),
            // Blocks are independent, and checked as they are decoded.
            None => out_len,
        }
    }

    fn release_output(&mut self, n: usize) {
        if let Some(d) = self.block.as_mut().and_then(|b| b.lzo.as_mut()) {
            d.release_output(n);
        }
    }
}
