//! LZ77-family decompressors without entropy coding: LZ4 (blocks, frames
//! and the legacy format) and Snappy (raw and framed), and the step
//! machinery the byte-oriented LZ77 decoders share ([`Units`]).

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(what.to_owned())
}

fn limit_check(out: &[u8], limit: usize) -> Result<()> {
    if out.len() > limit {
        Err(Diagnostic::output_limit(limit))
    } else {
        Ok(())
    }
}

/// Most input bytes one unit scans without producing output (a length
/// continuation, zero padding) before it suspends.
pub(crate) const SCAN: usize = 64 * 1024;

/// A decoder that advances a unit at a time: a whole token, or a bounded
/// piece of a long literal run or match. Its window is its own output.
pub(crate) trait Units {
    /// Decodes one unit, producing at most about `room` bytes, and returns
    /// the work done (bytes produced or scanned). An error leaves the
    /// decoder as it was, apart from memoized progress (see `progress`).
    fn unit(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        room: usize,
        limit: usize,
    ) -> Result<usize>;

    /// The stream has ended (and all input has been seen).
    fn finished(&self) -> bool;

    /// A value that grows whenever the decoder consumes input or memoizes
    /// a scan, so a step that runs out of input after some progress keeps
    /// it instead of rolling back.
    fn progress(&self) -> usize;
}

/// Runs units until about `step` bytes of work are done or the stream
/// ends. Running out of input after some progress ends the step early
/// (the caller calls again, and the shortage then rolls back an empty
/// step and asks for more input).
pub(crate) fn run_units<U: Units>(
    u: &mut U,
    input: &[u8],
    eof: bool,
    out: &mut Vec<u8>,
    step: usize,
    limit: usize,
) -> Result<Step> {
    let mark = out.len();
    let before = u.progress();
    let target = step.max(1);
    let mut work = 0usize;
    while !u.finished() {
        if work >= target {
            return Ok(Step::More);
        }
        match u.unit(input, eof, out, target.saturating_sub(work), limit) {
            Ok(w) => work = work.saturating_add(w.max(1)),
            Err(e) => {
                return if !eof && (out.len() > mark || u.progress() != before) {
                    Ok(Step::More)
                } else {
                    Err(e)
                };
            }
        }
    }
    Ok(Step::Done)
}

/// How far a length continuation run (bytes that each add 255 and go on,
/// then a final byte that adds its value) has been read, so a run cut
/// short by the end of the input, or suspended, is not rescanned.
#[derive(Clone, Copy, Default)]
pub(crate) struct RunMemo {
    at: usize,
    end: usize,
    sum: usize,
}

impl RunMemo {
    /// Rebases the memo after the first `n` input bytes are dropped (a memo
    /// of a run among them is stale and is forgotten).
    pub(crate) fn rebase(&mut self, n: usize) {
        *self = match (self.at.checked_sub(n), self.end.checked_sub(n)) {
            (Some(at), Some(end)) => RunMemo {
                at,
                end,
                sum: self.sum,
            },
            _ => RunMemo::default(),
        };
    }

    /// Grows with every byte memoized (for [`Units::progress`]).
    pub(crate) fn mark(&self) -> usize {
        self.end
    }
}

/// The outcome of [`read_run`].
pub(crate) enum Run {
    /// The run's value (255 per continuation byte plus the final byte) and
    /// the position after it.
    Done(usize, usize),
    /// [`SCAN`] bytes were read; call again.
    Suspended,
    /// The input ended inside the run.
    Short,
}

/// Reads a length continuation run at `at` whose continuation byte is
/// `cont`, resuming from `memo`.
pub(crate) fn read_run(input: &[u8], at: usize, cont: u8, memo: &mut RunMemo) -> Run {
    let (mut p, mut sum) = if memo.at == at && memo.end > at {
        (memo.end, memo.sum)
    } else {
        (at, 0)
    };
    let stop = p.saturating_add(SCAN);
    loop {
        let Some(&b) = input.get(p) else {
            *memo = RunMemo { at, end: p, sum };
            return Run::Short;
        };
        if p >= stop {
            *memo = RunMemo { at, end: p, sum };
            return Run::Suspended;
        }
        p = p.saturating_add(1);
        if b != cont {
            return Run::Done(sum.saturating_add(usize::from(b)), p);
        }
        sum = sum.saturating_add(255);
    }
}

/// Copies up to `room` of the `*left` literal bytes at `input[*pos..]`,
/// with at most `budget` more bytes allowed before `limit`; returns the
/// number copied. At the end of the input a run cut short fails (`trunc`)
/// before anything is copied; before it, what is there is copied.
#[allow(clippy::too_many_arguments)]
pub(crate) fn literal_chunk(
    input: &[u8],
    eof: bool,
    pos: &mut usize,
    left: &mut usize,
    out: &mut Vec<u8>,
    room: usize,
    budget: usize,
    limit: usize,
    trunc: &dyn Fn() -> Diagnostic,
) -> Result<usize> {
    let avail = input.len().saturating_sub(*pos);
    if eof && avail < *left {
        return Err(trunc());
    }
    let n = (*left).min(room.max(1)).min(avail);
    if n == 0 {
        return Err(trunc());
    }
    if n > budget {
        return Err(Diagnostic::output_limit(limit));
    }
    let end = pos.saturating_add(n);
    out.extend_from_slice(input.get(*pos..end).unwrap_or_default());
    *pos = end;
    *left = left.saturating_sub(n);
    Ok(n)
}

/// Copies up to `room` of the `*left` bytes of a match `dist` back in
/// `out` (overlap allowed; `dist` already checked against the window),
/// with at most `budget` more bytes allowed before `limit`.
pub(crate) fn match_chunk(
    out: &mut Vec<u8>,
    dist: usize,
    left: &mut usize,
    room: usize,
    budget: usize,
    limit: usize,
) -> Result<usize> {
    let n = (*left).min(room.max(1));
    if n > budget {
        return Err(Diagnostic::output_limit(limit));
    }
    copy_back(out, dist, n)?;
    *left = left.saturating_sub(n);
    Ok(n)
}

/// Appends `len` bytes from `dist` back in `out` (overlap allowed).
pub(crate) fn copy_back(out: &mut Vec<u8>, dist: usize, len: usize) -> Result<()> {
    if dist == 0 || dist > out.len() {
        return Err(bad("match offset outside the output"));
    }
    let mut from = out.len().saturating_sub(dist);
    let mut left = len;
    while left > 0 {
        // Each piece lies within what is already there.
        let k = left.min(dist);
        let to = from.saturating_add(k);
        if to > out.len() {
            return Err(bad("match offset outside the output"));
        }
        out.extend_from_within(from..to);
        from = to;
        left = left.saturating_sub(k);
    }
    Ok(())
}

/// Decodes one LZ4 block from `input` onto `out` (whose existing contents
/// are the dictionary for linked blocks).
pub fn lz4_block(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
    lz4_block_from(input, out, 0, false, limit)
}

/// [`lz4_block`] with the dictionary starting at `out[base..]`; see
/// [`Lz4Block`] for `zero_padding`.
fn lz4_block_from(
    input: &[u8],
    out: &mut Vec<u8>,
    base: usize,
    zero_padding: bool,
    limit: usize,
) -> Result<()> {
    let mut d = Lz4Block {
        base,
        zero_padding,
        ..Lz4Block::default()
    };
    while d.step(input, true, out, usize::MAX, limit)? == Step::More {}
    Ok(())
}

/// Where an [`Lz4Block`] is within a sequence.
#[derive(Clone, Copy, Default)]
enum Lz4Seq {
    /// At a token.
    #[default]
    Token,
    /// Copying literals; `nibble` is the token's match length nibble.
    Literals { left: usize, nibble: u8 },
    /// Copying a match.
    Match { dist: usize, left: usize },
}

/// The farthest an LZ4 match reaches back (16-bit offsets).
const LZ4_WINDOW: usize = 1 << 16;

/// One raw LZ4 block (as embedded in other containers), decoded a sequence
/// (or a bounded piece of a long one) at a time. With `zero_padding`,
/// zeros from the end of a sequence's literals to the end of the input end
/// the block when the sequence's match length nibble is 0, as in a final
/// sequence (the zeros could only be an invalid offset): zero padding
/// after the block is ignored.
#[derive(Clone, Default)]
pub struct Lz4Block {
    pos: usize,
    /// Where the window starts in `out`.
    base: usize,
    zero_padding: bool,
    seq: Lz4Seq,
    memo: RunMemo,
    /// At the end of the input, `input[pos..zeros]` are known to be zeros.
    zeros: usize,
    done: bool,
}

impl Lz4Block {
    /// A block that may be followed by zero padding.
    pub fn new() -> Self {
        Lz4Block {
            zero_padding: true,
            ..Lz4Block::default()
        }
    }

    fn finish(&mut self, input: &[u8]) -> usize {
        self.pos = input.len();
        self.done = true;
        1
    }

    /// A length: `nibble`, continued by bytes at `at` when it is 15.
    /// `None` when the read was suspended.
    fn length(&mut self, input: &[u8], at: usize, nibble: u8) -> Result<Option<(usize, usize)>> {
        if nibble != 15 {
            return Ok(Some((usize::from(nibble), at)));
        }
        match read_run(input, at, 255, &mut self.memo) {
            Run::Done(extra, next) => Ok(Some((extra.saturating_add(15), next))),
            Run::Suspended => Ok(None),
            Run::Short => Err(bad("truncated LZ4 block")),
        }
    }
}

impl Units for Lz4Block {
    fn unit(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        room: usize,
        limit: usize,
    ) -> Result<usize> {
        let pos = self.pos;
        match self.seq {
            Lz4Seq::Token => {
                let Some(&token) = input.get(pos) else {
                    if !eof {
                        return Err(bad("truncated LZ4 block"));
                    }
                    return Ok(self.finish(input));
                };
                let Some((left, next)) = self.length(input, pos.saturating_add(1), token >> 4)?
                else {
                    return Ok(SCAN);
                };
                self.pos = next;
                self.seq = Lz4Seq::Literals {
                    left,
                    nibble: token & 0x0f,
                };
                Ok(1)
            }
            Lz4Seq::Literals { left, nibble } if left > 0 => {
                let mut left = left;
                let n = literal_chunk(
                    input,
                    eof,
                    &mut self.pos,
                    &mut left,
                    out,
                    room,
                    limit.saturating_sub(out.len()),
                    limit,
                    &|| bad("truncated LZ4 literals"),
                )?;
                self.seq = Lz4Seq::Literals { left, nibble };
                Ok(n)
            }
            Lz4Seq::Literals { nibble, .. } => {
                if pos >= input.len() {
                    // The last sequence has literals only.
                    if !eof {
                        return Err(bad("truncated LZ4 block"));
                    }
                    return Ok(self.finish(input));
                }
                let head = input
                    .get(pos..pos.saturating_add(2).min(input.len()))
                    .unwrap_or_default();
                if self.zero_padding && nibble == 0 && head.iter().all(|&b| b == 0) {
                    // Padding if only zeros follow, else an invalid offset.
                    if !eof {
                        return Err(bad("truncated LZ4 block"));
                    }
                    let from = self.zeros.max(pos);
                    let to = from.saturating_add(SCAN).min(input.len());
                    let rest = input.get(from..to).unwrap_or_default();
                    if rest.iter().any(|&b| b != 0) {
                        return Err(bad("match offset outside the output"));
                    }
                    self.zeros = to;
                    if to >= input.len() {
                        self.finish(input);
                    }
                    return Ok(rest.len());
                }
                let (Some(&lo), Some(&hi)) = (input.get(pos), input.get(pos.saturating_add(1)))
                else {
                    return Err(bad("truncated LZ4 block"));
                };
                let dist = usize::from(u16::from_le_bytes([lo, hi]));
                let Some((len, next)) = self.length(input, pos.saturating_add(2), nibble)? else {
                    return Ok(SCAN);
                };
                if dist == 0 || dist > out.len().saturating_sub(self.base) {
                    return Err(bad("match offset outside the output"));
                }
                self.pos = next;
                self.seq = Lz4Seq::Match {
                    dist,
                    left: len.saturating_add(4),
                };
                Ok(1)
            }
            Lz4Seq::Match { dist, left } => {
                let mut left = left;
                let n = match_chunk(
                    out,
                    dist,
                    &mut left,
                    room,
                    limit.saturating_sub(out.len()),
                    limit,
                )?;
                self.seq = if left == 0 {
                    Lz4Seq::Token
                } else {
                    Lz4Seq::Match { dist, left }
                };
                Ok(n)
            }
        }
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn progress(&self) -> usize {
        self.pos
            .wrapping_add(self.memo.mark())
            .wrapping_add(self.zeros)
    }
}

impl Decode for Lz4Block {
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
        self.zeros = self.zeros.saturating_sub(n);
        self.memo.rebase(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
            .saturating_sub(LZ4_WINDOW)
            .max(self.base)
            .min(out_len)
    }

    fn release_output(&mut self, n: usize) {
        self.base = self.base.saturating_sub(n);
    }
}

/// A stretch `[from, end)` of the input (a block, a chunk) that a
/// container decodes a step at a time, through an inner decoder whose
/// input positions are relative to `from`, or by copying (advancing
/// `from`). Positions are kept in the caller's current input buffer, so
/// releasing input rebases them.
#[derive(Clone, Copy)]
pub(crate) struct Sub {
    pub(crate) from: usize,
    pub(crate) end: usize,
}

impl Sub {
    pub(crate) fn new(from: usize, len: usize) -> Self {
        Sub {
            from,
            end: from.saturating_add(len),
        }
    }

    /// The part of the stretch present in `input`, and whether all of it is.
    pub(crate) fn slice<'a>(&self, input: &'a [u8]) -> (&'a [u8], bool) {
        let to = self.end.min(input.len());
        (
            input.get(self.from.min(to)..to).unwrap_or_default(),
            input.len() >= self.end,
        )
    }

    /// Copies up to `room` (at least 1) of the bytes present onto `out`,
    /// advancing `from`; returns the number copied.
    pub(crate) fn copy(&mut self, input: &[u8], out: &mut Vec<u8>, room: usize) -> usize {
        let (slice, _) = self.slice(input);
        let n = slice.len().min(room.max(1));
        out.extend_from_slice(slice.get(..n).unwrap_or_default());
        self.from = self.from.saturating_add(n);
        n
    }

    /// Whether `from` has reached the end (all of it copied).
    pub(crate) fn copied(&self) -> bool {
        self.from >= self.end
    }

    /// Rebases after the caller drops the first `n` input bytes; returns
    /// how many of them lay inside the stretch (to release from the inner
    /// decoder).
    pub(crate) fn release(&mut self, n: usize) -> usize {
        let k = n.min(self.from);
        self.from = self.from.saturating_sub(k);
        self.end = self.end.saturating_sub(n);
        n.saturating_sub(k)
    }
}

/// Where an [`Lz4Frame`] decoder is.
#[derive(Clone, Copy)]
enum Lz4At {
    /// Before a frame's magic number.
    Magic,
    /// Inside a frame whose output starts at `start` (the window of its
    /// linked blocks; independent blocks see only their own output).
    Frame {
        start: usize,
        independent: bool,
        block_checksum: bool,
        content_checksum: bool,
    },
    /// Inside a legacy frame.
    Legacy,
    Done,
}

/// The block an [`Lz4Frame`] is decoding: stored (copied a step at a
/// time) or compressed (an [`Lz4Block`] over the block's bytes).
#[derive(Clone)]
struct Lz4Body {
    sub: Sub,
    block: Option<Lz4Block>,
    /// Bytes after the block (its checksum).
    trailer: usize,
    legacy: bool,
}

impl Lz4Body {
    /// Runs one step of the block; returns whether it has ended.
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<bool> {
        let (slice, whole) = self.sub.slice(input);
        if !whole && eof {
            return Err(bad(if self.legacy {
                "truncated legacy LZ4 block"
            } else {
                "truncated LZ4 block"
            }));
        }
        match &mut self.block {
            Some(d) => Ok(d.step(slice, whole, out, step, limit)? == Step::Done),
            None => {
                let n = self.sub.copy(input, out, step);
                limit_check(out, limit)?;
                if n == 0 && !self.sub.copied() {
                    return Err(bad("truncated LZ4 block"));
                }
                Ok(self.sub.copied())
            }
        }
    }
}

/// LZ4 frames (and legacy frames, and skippable frames), concatenated;
/// decoded a header at a time, and blocks a bounded step at a time. The
/// content checksum is not verified.
#[derive(Clone)]
pub struct Lz4Frame {
    /// The next header's position (the current block's header, while one
    /// is being decoded).
    pos: usize,
    at: Lz4At,
    body: Option<Lz4Body>,
}

impl Default for Lz4Frame {
    fn default() -> Self {
        Lz4Frame {
            pos: 0,
            at: Lz4At::Magic,
            body: None,
        }
    }
}

impl Lz4Frame {
    /// Reads one header: a frame header, a block header (starting the
    /// block's body), or an end mark.
    fn header(&mut self, input: &[u8], eof: bool, out: &[u8]) -> Result<()> {
        let pos = self.pos;
        match self.at {
            Lz4At::Done => {}
            Lz4At::Magic => {
                let Some(magic) = crate::bytes::u32_le(input, pos) else {
                    // The end, unless more input is coming.
                    if !eof {
                        return Err(bad("truncated LZ4 frame magic"));
                    }
                    self.pos = pos.min(input.len());
                    self.at = Lz4At::Done;
                    return Ok(());
                };
                let pos = pos.saturating_add(4);
                match magic {
                    0x184d_2204 => {
                        let flg = *input
                            .get(pos)
                            .ok_or_else(|| bad("truncated frame descriptor"))?;
                        let content_size = flg & 0x08 != 0;
                        if flg & 0x01 != 0 {
                            return Err(Diagnostic::unsupported(
                                "LZ4 frame with an external dictionary",
                            ));
                        }
                        // FLG, BD, optional content size and dictionary ID, HC.
                        self.pos = pos
                            .saturating_add(2)
                            .saturating_add(if content_size { 8 } else { 0 })
                            .saturating_add(1);
                        self.at = Lz4At::Frame {
                            start: out.len(),
                            independent: flg & 0x20 != 0,
                            block_checksum: flg & 0x10 != 0,
                            content_checksum: flg & 0x04 != 0,
                        };
                    }
                    0x184c_2102 => {
                        self.pos = pos;
                        self.at = Lz4At::Legacy;
                    }
                    m if m & 0xffff_fff0 == 0x184d_2a50 => {
                        let len = crate::bytes::u32_le(input, pos)
                            .ok_or_else(|| bad("truncated skippable frame"))?;
                        self.pos = pos
                            .saturating_add(4)
                            .saturating_add(crate::bytes::to_usize(len.into()));
                    }
                    _ => self.at = Lz4At::Done,
                }
            }
            Lz4At::Frame {
                start,
                independent,
                block_checksum,
                content_checksum,
            } => {
                let size = crate::bytes::u32_le(input, pos)
                    .ok_or_else(|| bad("truncated LZ4 block size"))?;
                let pos = pos.saturating_add(4);
                if size == 0 {
                    self.pos = pos.saturating_add(if content_checksum { 4 } else { 0 });
                    self.at = Lz4At::Magic;
                    return Ok(());
                }
                let raw = size & 0x8000_0000 != 0;
                let len = crate::bytes::to_usize((size & 0x7fff_ffff).into());
                // Linked blocks refer back into earlier output of the
                // same frame; earlier frames are not part of the window.
                let base = if independent { out.len() } else { start };
                self.body = Some(Lz4Body {
                    sub: Sub::new(pos, len),
                    block: (!raw).then(|| Lz4Block {
                        base,
                        ..Lz4Block::default()
                    }),
                    trailer: if block_checksum { 4 } else { 0 },
                    legacy: false,
                });
            }
            Lz4At::Legacy => {
                // Independent blocks of up to 8 MiB until the next magic
                // number or the end.
                let Some(len) = crate::bytes::u32_le(input, pos) else {
                    if !eof {
                        return Err(bad("truncated legacy LZ4 block size"));
                    }
                    self.at = Lz4At::Magic;
                    return Ok(());
                };
                if len == 0x184c_2102 || len & 0xffff_fff0 == 0x184d_2a50 || len == 0x184d_2204 {
                    self.at = Lz4At::Magic;
                    return Ok(());
                }
                let len = crate::bytes::to_usize(len.into());
                self.body = Some(Lz4Body {
                    sub: Sub::new(pos.saturating_add(4), len),
                    block: Some(Lz4Block {
                        base: out.len(),
                        ..Lz4Block::default()
                    }),
                    trailer: 0,
                    legacy: true,
                });
            }
        }
        Ok(())
    }
}

impl Decode for Lz4Frame {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let mark = out.len();
        // Header bytes read count as work alongside output.
        let mut read = 0usize;
        loop {
            let work = out.len().saturating_sub(mark).saturating_add(read);
            if work >= step.max(1) {
                return Ok(Step::More);
            }
            if let Some(body) = self.body.as_mut() {
                let room = step.saturating_sub(work);
                if !body.step(input, eof, out, room, limit)? {
                    return Ok(Step::More);
                }
                self.pos = body.sub.end.saturating_add(body.trailer);
                self.body = None;
                if self.pos > input.len() && !eof {
                    return Err(bad("truncated LZ4 block checksum"));
                }
                continue;
            }
            if matches!(self.at, Lz4At::Done) {
                return Ok(Step::Done);
            }
            let before = self.pos;
            self.header(input, eof, out)?;
            read = read
                .saturating_add(self.pos.saturating_sub(before).min(SCAN))
                .saturating_add(1);
        }
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        match &self.body {
            Some(body) => body
                .sub
                .from
                .saturating_add(body.block.as_ref().map_or(0, |d| d.releasable_input())),
            // Headers are read whole from `pos`.
            None => self.pos,
        }
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        if let Some(body) = self.body.as_mut() {
            let inner = body.sub.release(n);
            if let Some(d) = body.block.as_mut() {
                d.release_input(inner);
            }
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        if let Some(d) = self.body.as_ref().and_then(|b| b.block.as_ref()) {
            return d.releasable_output(out_len);
        }
        match self.at {
            // Linked blocks see the frame's last 64 KiB.
            Lz4At::Frame {
                start,
                independent: false,
                ..
            } => out_len.saturating_sub(LZ4_WINDOW).max(start).min(out_len),
            // Independent blocks (and legacy ones) see only their own output.
            _ => out_len,
        }
    }

    fn release_output(&mut self, n: usize) {
        if let Lz4At::Frame { start, .. } = &mut self.at {
            *start = start.saturating_sub(n);
        }
        if let Some(d) = self.body.as_mut().and_then(|b| b.block.as_mut()) {
            d.release_output(n);
        }
    }
}

/// Raw Snappy: a varint length, then literals and copies.
pub fn snappy_raw(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut d = Snappy::default();
    while d.step(input, true, &mut out, usize::MAX, limit)? == Step::More {}
    Ok(out)
}

/// The farthest a Snappy copy reaches back (32-bit offsets).
const SNAPPY_WINDOW: u64 = 0x1_0000_0000;

/// Raw Snappy, decoded an element (or a bounded piece of a long literal)
/// at a time.
#[derive(Clone, Default)]
pub struct Snappy {
    pos: usize,
    /// The length from the header, once read.
    expected: Option<usize>,
    /// Literal bytes still to copy.
    literal: usize,
    /// Where the stream's output starts in `out` (its window).
    base: usize,
    /// Output bytes of the stream released so far.
    released: usize,
    done: bool,
}

impl Snappy {
    /// Bytes of the stream produced so far, given `out_len` bytes held.
    fn produced(&self, out_len: usize) -> usize {
        self.released
            .saturating_add(out_len.saturating_sub(self.base))
    }
}

impl Units for Snappy {
    fn unit(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        room: usize,
        limit: usize,
    ) -> Result<usize> {
        let Some(expected) = self.expected else {
            // A varint of at most five bytes (32 bits).
            let (expected, pos) = crate::bytes::uleb128(input.get(..5).unwrap_or(input))
                .ok_or_else(|| {
                    bad(if input.len() < 5 {
                        "truncated Snappy length"
                    } else {
                        "Snappy length too long"
                    })
                })?;
            let expected = crate::bytes::to_usize(expected);
            if expected > limit.saturating_sub(out.len()) {
                return Err(Diagnostic::limit(format!(
                    "Snappy data claims {expected:#x} bytes"
                )));
            }
            self.pos = pos;
            self.expected = Some(expected);
            return Ok(pos);
        };
        if self.literal > 0 {
            return literal_chunk(
                input,
                eof,
                &mut self.pos,
                &mut self.literal,
                out,
                room,
                limit.saturating_sub(out.len()),
                limit,
                &|| bad("truncated literal"),
            );
        }
        let mut pos = self.pos;
        let Some(&tag) = input.get(pos) else {
            if !eof {
                return Err(bad("truncated Snappy data"));
            }
            if self.produced(out.len()) != expected {
                return Err(bad("Snappy output length differs from the header"));
            }
            self.done = true;
            return Ok(1);
        };
        pos = pos.saturating_add(1);
        let le = |bytes: &[u8]| {
            bytes
                .iter()
                .rev()
                .fold(0usize, |a, &b| a.wrapping_shl(8) | usize::from(b))
        };
        let (dist, len) = match tag & 3 {
            0 => {
                let mut len = usize::from(tag >> 2);
                if len >= 60 {
                    let n = len.saturating_sub(59);
                    len = le(input
                        .get(pos..pos.saturating_add(n))
                        .ok_or_else(|| bad("truncated literal length"))?);
                    pos = pos.saturating_add(n);
                }
                self.pos = pos;
                self.literal = len.saturating_add(1);
                return Ok(1);
            }
            1 => {
                let lo = usize::from(*input.get(pos).ok_or_else(|| bad("truncated copy"))?);
                pos = pos.saturating_add(1);
                (
                    usize::from(tag >> 5) << 8 | lo,
                    usize::from((tag >> 2) & 7).saturating_add(4),
                )
            }
            kind => {
                let n = if kind == 2 { 2 } else { 4 };
                let dist = le(input
                    .get(pos..pos.saturating_add(n))
                    .ok_or_else(|| bad("truncated copy"))?);
                pos = pos.saturating_add(n);
                (dist, usize::from(tag >> 2).saturating_add(1))
            }
        };
        if dist == 0 || dist > out.len().saturating_sub(self.base) {
            return Err(bad("match offset outside the output"));
        }
        if out.len().saturating_add(len) > limit {
            return Err(Diagnostic::output_limit(limit));
        }
        copy_back(out, dist, len)?;
        self.pos = pos;
        Ok(len)
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn progress(&self) -> usize {
        self.pos
    }
}

impl Decode for Snappy {
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
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
            .saturating_sub(usize::try_from(SNAPPY_WINDOW).unwrap_or(usize::MAX))
            .max(self.base)
            .min(out_len)
    }

    fn release_output(&mut self, n: usize) {
        let before = n.min(self.base);
        self.base = self.base.saturating_sub(before);
        self.released = self.released.saturating_add(n.saturating_sub(before));
    }
}

/// What a Snappy framing chunk's body is decoded as.
#[derive(Clone)]
enum SnappyBody {
    /// Compressed: raw Snappy after the CRC.
    Compressed(Snappy),
    /// Uncompressed: copied after the CRC.
    Stored,
    /// Padding or a skippable chunk: skipped.
    Skipped,
}

/// The Snappy framing format: chunks of compressed or uncompressed data
/// (each with a masked CRC-32C, not checked here). Decoded a chunk header
/// at a time, and chunk bodies a bounded step at a time.
#[derive(Clone, Default)]
pub struct SnappyFramed {
    /// The next chunk header's position (the current chunk's, while one is
    /// being decoded).
    pos: usize,
    /// The chunk being decoded: its body (after the CRC, for data chunks).
    chunk: Option<(Sub, SnappyBody)>,
    done: bool,
}

impl Decode for SnappyFramed {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let mark = out.len();
        // Chunk headers count as work alongside output.
        let mut headers = 0usize;
        loop {
            let work = out
                .len()
                .saturating_sub(mark)
                .saturating_add(headers.saturating_mul(4));
            if work >= step.max(1) {
                return Ok(Step::More);
            }
            if let Some((sub, body)) = self.chunk.as_mut() {
                let (slice, whole) = sub.slice(input);
                if !whole && eof {
                    return Err(bad("truncated Snappy chunk"));
                }
                let room = step.saturating_sub(work);
                let ended = match body {
                    SnappyBody::Compressed(d) => {
                        d.step(slice, whole, out, room, limit)? == Step::Done
                    }
                    SnappyBody::Stored => {
                        let n = sub.copy(input, out, room);
                        limit_check(out, limit)?;
                        if n == 0 && !sub.copied() {
                            return Err(bad("truncated Snappy chunk"));
                        }
                        sub.copied()
                    }
                    SnappyBody::Skipped => {
                        let n = slice.len().min(SCAN);
                        sub.from = sub.from.saturating_add(n);
                        headers = headers.saturating_add(n / 4);
                        if n == 0 && !sub.copied() {
                            return Err(bad("truncated Snappy chunk"));
                        }
                        sub.copied()
                    }
                };
                if !ended {
                    return Ok(Step::More);
                }
                self.pos = sub.end;
                self.chunk = None;
                continue;
            }
            if self.done {
                return Ok(Step::Done);
            }
            let pos = self.pos;
            let (Some(&kind), Some(len)) = (
                input.get(pos),
                input.get(pos.saturating_add(1)..pos.saturating_add(4)),
            ) else {
                if !eof {
                    return Err(bad("truncated Snappy chunk header"));
                }
                self.done = true;
                continue;
            };
            let len = len
                .iter()
                .rev()
                .fold(0usize, |a, &b| a << 8 | usize::from(b));
            let chunk = Sub::new(pos.saturating_add(4), len);
            // Data chunks start with a CRC.
            let data = Sub {
                from: chunk.from.saturating_add(4).min(chunk.end),
                end: chunk.end,
            };
            let body = match kind {
                0x00 => SnappyBody::Compressed(Snappy {
                    base: out.len(),
                    ..Snappy::default()
                }),
                0x01 => SnappyBody::Stored,
                0x02..=0x7f => {
                    if eof && input.len() < chunk.end {
                        return Err(bad("truncated Snappy chunk"));
                    }
                    return Err(Diagnostic::unsupported(format!(
                        "reserved Snappy chunk {kind:#04x}"
                    )));
                }
                _ => SnappyBody::Skipped,
            };
            let sub = if matches!(body, SnappyBody::Skipped) {
                chunk
            } else {
                data
            };
            self.chunk = Some((sub, body));
            headers = headers.saturating_add(1);
        }
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        match &self.chunk {
            Some((sub, SnappyBody::Compressed(d))) => sub.from.saturating_add(d.releasable_input()),
            Some((sub, _)) => sub.from,
            None => self.pos,
        }
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        if let Some((sub, body)) = self.chunk.as_mut() {
            let inner = sub.release(n);
            if let SnappyBody::Compressed(d) = body {
                d.release_input(inner);
            }
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        match &self.chunk {
            // A compressed chunk refers back into its own output.
            Some((_, SnappyBody::Compressed(d))) => d.releasable_output(out_len),
            // Chunks are independent: other output is never read back.
            _ => out_len,
        }
    }

    fn release_output(&mut self, n: usize) {
        if let Some((_, SnappyBody::Compressed(d))) = self.chunk.as_mut() {
            d.release_output(n);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn lz4_block_with_overlapping_match() {
        // "abcabcabcabcabc!" : literals "abc", match offset 3 len 12, literal "!".
        let block = [0x38, b'a', b'b', b'c', 3, 0, 0x10, b'!'];
        let mut out = Vec::new();
        lz4_block(&block, &mut out, 100).unwrap();
        assert_eq!(out, b"abcabcabcabcabc!");
    }

    #[test]
    fn snappy() {
        // Length 10: literal "ab", copy1 len 8 offset 2.
        let data = [10, 0x04, b'a', b'b', 0x11, 2];
        assert_eq!(snappy_raw(&data, 100).unwrap(), b"ababababab");
    }

    #[test]
    fn long_runs_are_read_in_pieces() {
        // A literal length continued by 200,000 bytes of 255: the run is
        // scanned in suspended pieces, then fails at the end of the input.
        let mut block = vec![0xf0];
        block.resize(200_001, 255);
        let mut d = Lz4Block::new();
        let mut out = Vec::new();
        let mut calls = 0;
        let result = loop {
            calls += 1;
            match d.step(&block, true, &mut out, 1024, 1 << 30) {
                Ok(Step::More) => {}
                other => break other,
            }
        };
        assert!(result.is_err() && calls > 3 && out.is_empty());
    }
}
