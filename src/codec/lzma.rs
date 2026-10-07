//! LZMA and LZMA2 decompression (the range-coded LZ77 of 7-Zip and xz),
//! the `.lzma` ("LZMA alone") container, and the xz BCJ and Delta filters.
//!
//! # Decoding on demand
//!
//! The decoders here implement [`Decoder`] directly rather than going
//! through [`Streaming`](crate::codec::pipeline::Streaming), and never roll
//! back: a unit of work only starts once all the input it can need is
//! there, so it never runs out of input half-way, and nothing has to be
//! snapshotted (no per-step clone of the ~14 KiB of probabilities, or the
//! 6 MiB that `.lzma` allows with lc + lp = 12).
//!
//! - Raw LZMA ([`LzmaStream`]: `.lzma` and raw LZMA with known properties)
//!   has no internal boundaries. It decodes symbol by symbol (a literal or
//!   a match) and pauses after `step` bytes, or when fewer than
//!   [`MARGIN`] bytes of input remain unread before the end of what has
//!   been fed: a symbol reads at most 48 bits through the range coder, and
//!   each bit at most one input byte, so a symbol started with `MARGIN`
//!   bytes in hand always completes. At the end of the input the margin is
//!   dropped and a shortage is an error.
//! - LZMA2 ([`Lzma2Stream`], and the [`Lzma2`] core that xz blocks use)
//!   copies an uncompressed chunk (at most 64 KiB) once all of it has
//!   arrived, and decodes an LZMA chunk (up to 2 MiB of output, so too
//!   coarse a unit on its own) symbol by symbol like raw LZMA, with the
//!   same margin until the whole chunk is in. LZMA state carries across
//!   chunks that do not reset it.
//!
//! The dictionary is the output: `out` itself, addressed through a
//! [`View`] (where this stream's position 0 is in the buffer). xz blocks
//! with BCJ or Delta filters instead decode into a window of their own (see
//! [`crate::codec::xz`]), since `out` then holds filtered bytes. The
//! filters ([`PostState`]) run incrementally too: each keeps the few bytes
//! it cannot settle yet (x86 BCJ looks four bytes ahead, ARM filters work
//! on whole words) until more arrive or the stream ends.

use crate::codec::pipeline::{Decoder, Status};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("LZMA: {what}"))
}

fn too_large(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
}

const PROB_INIT: u16 = 1024;

/// Input bytes a raw LZMA decoder keeps in hand before starting a symbol
/// (see the module docs): a match reads at most 2 + 10 + 6 + 26 + 4 = 48
/// range-coder bits, each normalising at most once.
pub const MARGIN: usize = 64;

/// The range decoder's registers, kept between steps.
#[derive(Clone, Copy)]
struct Registers {
    pos: usize,
    range: u32,
    code: u32,
}

/// The range decoder.
struct Range<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> Range<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        if data.first() != Some(&0) {
            return Err(bad("range coder does not start with 0"));
        }
        let code = data
            .get(1..5)
            .ok_or_else(|| bad("truncated range coder"))?
            .iter()
            .fold(0u32, |a, &b| a << 8 | u32::from(b));
        Ok(Range {
            data,
            pos: 5,
            range: 0xffff_ffff,
            code,
        })
    }

    fn resume(data: &'a [u8], r: Registers) -> Self {
        Range {
            data,
            pos: r.pos,
            range: r.range,
            code: r.code,
        }
    }

    fn registers(&self) -> Registers {
        Registers {
            pos: self.pos,
            range: self.range,
            code: self.code,
        }
    }

    fn normalize(&mut self) -> Result<()> {
        if self.range < 1 << 24 {
            let b = *self
                .data
                .get(self.pos)
                .ok_or_else(|| bad("unexpected end of data"))?;
            self.pos = self.pos.saturating_add(1);
            self.range <<= 8;
            self.code = self.code << 8 | u32::from(b);
        }
        Ok(())
    }

    fn bit(&mut self, prob: &mut u16) -> Result<u32> {
        let bound = (self.range >> 11).wrapping_mul(u32::from(*prob));
        let bit = if self.code < bound {
            self.range = bound;
            *prob = prob.wrapping_add((2048u16.wrapping_sub(*prob)) >> 5);
            0
        } else {
            self.code = self.code.wrapping_sub(bound);
            self.range = self.range.wrapping_sub(bound);
            *prob = prob.wrapping_sub(*prob >> 5);
            1
        };
        self.normalize()?;
        Ok(bit)
    }

    fn direct(&mut self, count: u32) -> Result<u32> {
        let mut result = 0u32;
        for _ in 0..count {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & t);
            result = (result << 1).wrapping_add(t.wrapping_add(1));
            self.normalize()?;
        }
        Ok(result)
    }

    fn tree(&mut self, probs: &mut [u16], bits: u32) -> Result<u32> {
        let mut m = 1usize;
        for _ in 0..bits {
            let p = probs.get_mut(m).ok_or_else(|| bad("bit tree index"))?;
            m = m << 1 | usize::try_from(self.bit(p)?).unwrap_or(0);
        }
        Ok(u32::try_from(m).unwrap_or(0).wrapping_sub(1 << bits))
    }

    fn reverse(&mut self, probs: &mut [u16], bits: u32) -> Result<u32> {
        let mut m = 1usize;
        let mut sym = 0u32;
        for i in 0..bits {
            let p = probs.get_mut(m).ok_or_else(|| bad("bit tree index"))?;
            let b = self.bit(p)?;
            m = m << 1 | usize::try_from(b).unwrap_or(0);
            sym |= b << i;
        }
        Ok(sym)
    }
}

/// Length decoder probabilities.
#[derive(Clone)]
struct Len {
    choice: u16,
    choice2: u16,
    low: Vec<[u16; 8]>,
    mid: Vec<[u16; 8]>,
    high: [u16; 256],
}

impl Len {
    fn new() -> Self {
        Len {
            choice: PROB_INIT,
            choice2: PROB_INIT,
            low: vec![[PROB_INIT; 8]; 16],
            mid: vec![[PROB_INIT; 8]; 16],
            high: [PROB_INIT; 256],
        }
    }

    fn decode(&mut self, rc: &mut Range<'_>, pos_state: usize) -> Result<u32> {
        if rc.bit(&mut self.choice)? == 0 {
            let t = self
                .low
                .get_mut(pos_state)
                .ok_or_else(|| bad("position state"))?;
            return rc.tree(t, 3);
        }
        if rc.bit(&mut self.choice2)? == 0 {
            let t = self
                .mid
                .get_mut(pos_state)
                .ok_or_else(|| bad("position state"))?;
            return Ok(8u32.wrapping_add(rc.tree(t, 3)?));
        }
        Ok(16u32.wrapping_add(rc.tree(&mut self.high, 8)?))
    }
}

/// LZMA properties: literal context bits, literal position bits, position bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Props {
    pub lc: u32,
    pub lp: u32,
    pub pb: u32,
}

impl Props {
    pub fn from_byte(b: u8) -> Result<Self> {
        if b >= 9 * 5 * 5 {
            return Err(bad("invalid properties byte"));
        }
        let b = u32::from(b);
        Ok(Props {
            lc: b % 9,
            lp: (b / 9) % 5,
            pb: b / 45,
        })
    }
}

/// Where a stream's output lives in a buffer: stream position `p` is at
/// index `p + start - dropped` (`start` when the buffer is shared `out`
/// that held other data first, `dropped` when a private window has
/// discarded its oldest bytes).
#[derive(Clone, Copy, Debug, Default)]
pub struct View {
    pub start: usize,
    pub dropped: usize,
}

impl View {
    /// The buffer index of stream position `p` (0 if it was dropped).
    fn index(self, p: usize) -> usize {
        p.saturating_add(self.start).saturating_sub(self.dropped)
    }

    /// The stream position of buffer index `i`.
    fn position(self, i: usize) -> usize {
        i.saturating_add(self.dropped).saturating_sub(self.start)
    }
}

/// Where [`State::run`] may read and must stop, in buffer indices.
#[derive(Clone, Copy)]
struct Bounds {
    view: View,
    /// The start of the dictionary (back-references stay at or after it).
    dict: usize,
    /// The end of the stream or chunk, if known.
    end: Option<usize>,
    /// Pause (between symbols) once the buffer reaches this length.
    stop: usize,
    /// Pause before a symbol once the range coder is past this input
    /// position.
    avail: usize,
    limit: usize,
}

/// The LZMA decoder state (persisting across LZMA2 chunks).
#[derive(Clone)]
struct State {
    props: Props,
    literal: Vec<u16>,
    is_match: [u16; 192],
    is_rep: [u16; 12],
    is_rep0: [u16; 12],
    is_rep1: [u16; 12],
    is_rep2: [u16; 12],
    is_rep0_long: [u16; 192],
    pos_slot: [[u16; 64]; 4],
    special: [u16; 115],
    align: [u16; 16],
    len: Len,
    rep_len: Len,
    state: usize,
    reps: [u32; 4],
}

impl State {
    fn new(props: Props) -> Self {
        let lit = 0x300usize << (props.lc.saturating_add(props.lp)).min(16);
        State {
            props,
            literal: vec![PROB_INIT; lit],
            is_match: [PROB_INIT; 192],
            is_rep: [PROB_INIT; 12],
            is_rep0: [PROB_INIT; 12],
            is_rep1: [PROB_INIT; 12],
            is_rep2: [PROB_INIT; 12],
            is_rep0_long: [PROB_INIT; 192],
            pos_slot: [[PROB_INIT; 64]; 4],
            special: [PROB_INIT; 115],
            align: [PROB_INIT; 16],
            len: Len::new(),
            rep_len: Len::new(),
            state: 0,
            reps: [0; 4],
        }
    }

    /// A match distance (minus one), for a match of length `len` (minus 2).
    fn distance(&mut self, rc: &mut Range<'_>, len: u32) -> Result<u32> {
        let len_state = usize::try_from(len.min(3)).unwrap_or(3);
        let slot = rc.tree(
            self.pos_slot
                .get_mut(len_state)
                .ok_or_else(|| bad("length state"))?,
            6,
        )?;
        if slot < 4 {
            return Ok(slot);
        }
        let direct = (slot >> 1).wrapping_sub(1);
        let base = (2 | (slot & 1)) << direct;
        Ok(if slot < 14 {
            let start = usize::try_from(base.wrapping_sub(slot)).unwrap_or(0);
            let probs = self
                .special
                .get_mut(start..)
                .ok_or_else(|| bad("distance"))?;
            base.wrapping_add(rc.reverse(probs, direct)?)
        } else {
            let high = rc.direct(direct.wrapping_sub(4))? << 4;
            base.wrapping_add(high)
                .wrapping_add(rc.reverse(&mut self.align, 4)?)
        })
    }

    /// Whether `rc` holds an end marker at stream position `position`
    /// (after a stream of known size: encoders may write both).
    fn end_marker(&mut self, rc: &mut Range<'_>, position: usize) -> bool {
        let pos_state = position & (1usize << self.props.pb).wrapping_sub(1);
        let idx = self.state.wrapping_mul(16).wrapping_add(pos_state);
        let mut probe = || -> Result<bool> {
            let is_match = self.is_match.get_mut(idx).ok_or_else(|| bad("state"))?;
            if rc.bit(is_match)? == 0 {
                return Ok(false);
            }
            if rc.bit(
                self.is_rep
                    .get_mut(self.state)
                    .ok_or_else(|| bad("state"))?,
            )? == 1
            {
                return Ok(false);
            }
            let len = self.len.decode(rc, pos_state)?;
            Ok(self.distance(rc, len)? == 0xffff_ffff)
        };
        probe().unwrap_or(false)
    }

    /// Decodes `rc` into `out`, a symbol at a time, until the end of the
    /// stream or chunk (`Ok(true)`: `b.end` reached or the end marker) or a
    /// pause (`Ok(false)`: `b.stop` or `b.avail` reached).
    fn run(&mut self, rc: &mut Range<'_>, out: &mut Vec<u8>, b: Bounds) -> Result<bool> {
        let pb_mask = (1usize << self.props.pb).wrapping_sub(1);
        let lp_mask = (1usize << self.props.lp).wrapping_sub(1);
        let lc = self.props.lc;
        // Bytes before the stream's start are not its own.
        let first = b.view.index(0);
        loop {
            if b.end.is_some_and(|e| out.len() >= e) {
                return Ok(true);
            }
            if out.len() > b.limit {
                return Err(too_large(b.limit));
            }
            if out.len() >= b.stop || rc.pos > b.avail {
                return Ok(false);
            }
            let position = b.view.position(out.len());
            let pos_state = position & pb_mask;
            let s = self.state;
            let idx = s.wrapping_mul(16).wrapping_add(pos_state);
            let mut bit = rc.bit(self.is_match.get_mut(idx).ok_or_else(|| bad("state"))?)?;
            if bit == 0 {
                // Literal.
                let prev = if out.len() > first {
                    out.last().copied().unwrap_or(0)
                } else {
                    0
                };
                let base = 0x300usize.wrapping_mul(
                    ((position & lp_mask) << lc)
                        .wrapping_add(usize::from(prev) >> (8u32.saturating_sub(lc))),
                );
                let probs = self
                    .literal
                    .get_mut(base..base.wrapping_add(0x300))
                    .ok_or_else(|| bad("literal state"))?;
                let mut sym = 1usize;
                if s >= 7 {
                    let dist = usize::try_from(self.reps[0]).unwrap_or(0).wrapping_add(1);
                    let mut match_byte = out
                        .len()
                        .checked_sub(dist)
                        .filter(|&i| i >= first)
                        .and_then(|i| out.get(i))
                        .copied()
                        .ok_or_else(|| bad("match distance"))?;
                    loop {
                        let match_bit = usize::from(match_byte >> 7 & 1);
                        match_byte <<= 1;
                        let i = 0x100usize.wrapping_add(match_bit << 8).wrapping_add(sym);
                        let b = usize::try_from(
                            rc.bit(probs.get_mut(i).ok_or_else(|| bad("literal"))?)?,
                        )
                        .unwrap_or(0);
                        sym = sym << 1 | b;
                        if match_bit != b || sym >= 0x100 {
                            break;
                        }
                    }
                }
                while sym < 0x100 {
                    let b =
                        usize::try_from(rc.bit(probs.get_mut(sym).ok_or_else(|| bad("literal"))?)?)
                            .unwrap_or(0);
                    sym = sym << 1 | b;
                }
                out.push(u8::try_from(sym & 0xff).unwrap_or(0));
                self.state = if s < 4 {
                    0
                } else if s < 10 {
                    s.wrapping_sub(3)
                } else {
                    s.wrapping_sub(6)
                };
                continue;
            }
            let len;
            bit = rc.bit(self.is_rep.get_mut(s).ok_or_else(|| bad("state"))?)?;
            if bit == 1 {
                if out.len() <= b.dict {
                    return Err(bad("repeated match before any data"));
                }
                if rc.bit(self.is_rep0.get_mut(s).ok_or_else(|| bad("state"))?)? == 0 {
                    if rc.bit(self.is_rep0_long.get_mut(idx).ok_or_else(|| bad("state"))?)? == 0 {
                        // Short rep: one byte at rep0.
                        self.state = if s < 7 { 9 } else { 11 };
                        let dist = usize::try_from(self.reps[0]).unwrap_or(0).wrapping_add(1);
                        let b = out
                            .len()
                            .checked_sub(dist)
                            .filter(|&i| i >= first)
                            .and_then(|i| out.get(i))
                            .copied()
                            .ok_or_else(|| bad("match distance"))?;
                        out.push(b);
                        continue;
                    }
                } else {
                    let dist;
                    if rc.bit(self.is_rep1.get_mut(s).ok_or_else(|| bad("state"))?)? == 0 {
                        dist = self.reps[1];
                    } else {
                        if rc.bit(self.is_rep2.get_mut(s).ok_or_else(|| bad("state"))?)? == 0 {
                            dist = self.reps[2];
                        } else {
                            dist = self.reps[3];
                            self.reps[3] = self.reps[2];
                        }
                        self.reps[2] = self.reps[1];
                    }
                    self.reps[1] = self.reps[0];
                    self.reps[0] = dist;
                }
                len = self.rep_len.decode(rc, pos_state)?;
                self.state = if s < 7 { 8 } else { 11 };
            } else {
                self.reps[3] = self.reps[2];
                self.reps[2] = self.reps[1];
                self.reps[1] = self.reps[0];
                len = self.len.decode(rc, pos_state)?;
                self.state = if s < 7 { 7 } else { 10 };
                let dist = self.distance(rc, len)?;
                if dist == 0xffff_ffff {
                    return Ok(true); // end marker
                }
                self.reps[0] = dist;
            }
            let len = usize::try_from(len).unwrap_or(0).wrapping_add(2);
            let dist = usize::try_from(self.reps[0])
                .unwrap_or(usize::MAX)
                .wrapping_add(1);
            if dist > out.len().saturating_sub(b.dict) {
                return Err(bad("match distance beyond the dictionary"));
            }
            let mut len = len;
            if let Some(e) = b.end {
                len = len.min(e.saturating_sub(out.len()));
            }
            let from = out.len().wrapping_sub(dist);
            for i in 0..len {
                let b = out.get(from.wrapping_add(i)).copied().unwrap_or(0);
                out.push(b);
            }
        }
    }
}

/// The decoder in progress: probabilities and range coder.
struct Running {
    state: State,
    rc: Registers,
    view: View,
    /// The decoded size, as a buffer index, when known.
    end: Option<usize>,
}

/// A raw LZMA stream: `.lzma` ("LZMA alone": properties, dictionary size,
/// uncompressed size, all ones when unknown and the stream ends with a
/// marker; then the range-coded data), or raw LZMA with known properties
/// and possibly a known decoded size (7-Zip, ZIP method 14).
pub struct LzmaStream {
    /// The header length: 13 for `.lzma`, 0 for raw data.
    header: usize,
    /// Where the range-coded data starts in the input (the header length
    /// until input is released).
    data_at: usize,
    props: Props,
    size: Option<usize>,
    /// The dictionary size, when known (from the `.lzma` header): the
    /// furthest a match reaches back.
    dict: Option<usize>,
    running: Option<Box<Running>>,
    consumed: usize,
    done: bool,
}

impl LzmaStream {
    /// A `.lzma` stream.
    pub fn alone() -> Self {
        LzmaStream {
            header: 13,
            data_at: 13,
            props: Props {
                lc: 0,
                lp: 0,
                pb: 0,
            },
            size: None,
            dict: None,
            running: None,
            consumed: 0,
            done: false,
        }
    }

    /// Raw LZMA with known properties; `size` is the decoded size and
    /// `dict` the dictionary size, when known (with it, output before the
    /// dictionary can be released).
    pub fn raw(props: Props, size: Option<usize>, dict: Option<u32>) -> Self {
        let dict = dict.map(|d| usize::try_from(d).unwrap_or(usize::MAX).max(4096));
        LzmaStream {
            header: 0,
            data_at: 0,
            props,
            size,
            dict,
            running: None,
            consumed: 0,
            done: false,
        }
    }

    fn start(&mut self, input: &[u8], out: &[u8], limit: usize) -> Result<Running> {
        if self.header > 0 {
            self.props = Props::from_byte(*input.first().ok_or_else(|| bad("truncated header"))?)?;
            let size = input
                .get(5..13)
                .and_then(|s| s.try_into().ok())
                .map(u64::from_le_bytes)
                .ok_or_else(|| bad("truncated header"))?;
            self.size = (size != u64::MAX).then(|| usize::try_from(size).unwrap_or(usize::MAX));
            let dict = input
                .get(1..5)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or_else(|| bad("truncated header"))?;
            // Smaller dictionaries decode as 4 KiB ones (as in xz).
            self.dict = Some(usize::try_from(dict).unwrap_or(usize::MAX).max(4096));
            if self
                .size
                .is_some_and(|e| e > limit.saturating_sub(out.len()))
            {
                return Err(Diagnostic::limit(format!(
                    "LZMA data claims {size:#x} bytes"
                )));
            }
        }
        let rc = Range::new(input.get(self.header..).unwrap_or_default())?.registers();
        let view = View {
            start: out.len(),
            dropped: 0,
        };
        let end = self.size.map(|s| s.saturating_add(out.len()));
        Ok(Running {
            state: State::new(self.props),
            rc,
            view,
            end,
        })
    }
}

impl Decoder for LzmaStream {
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
        if self.running.is_none() {
            if !eof && input.len() < self.header.saturating_add(5) {
                return Ok(Status::NeedInput);
            }
            self.running = Some(Box::new(self.start(input, out, limit)?));
        }
        let Some(r) = self.running.as_mut() else {
            return Err(bad("decoder not started"));
        };
        let data = input.get(self.data_at..).unwrap_or_default();
        let mark = out.len();
        let bounds = Bounds {
            view: r.view,
            dict: r.view.index(0),
            end: r.end,
            stop: out.len().saturating_add(step.max(1)),
            avail: if eof {
                usize::MAX
            } else {
                data.len().saturating_sub(MARGIN)
            },
            limit,
        };
        let mut rc = Range::resume(data, r.rc);
        let ended = r.state.run(&mut rc, out, bounds)?;
        r.rc = rc.registers();
        self.consumed = self.data_at.saturating_add(r.rc.pos);
        if ended && r.end.is_some_and(|e| out.len() >= e) {
            // The known size reached: an end marker may follow (the
            // encoder's choice). Consume it if so.
            if !eof && data.len() < r.rc.pos.saturating_add(MARGIN) {
                return Ok(if out.len() > mark {
                    Status::More
                } else {
                    Status::NeedInput
                });
            }
            if r.state.end_marker(&mut rc, r.view.position(out.len())) {
                self.consumed = self.data_at.saturating_add(rc.pos);
            }
        }
        if ended {
            self.done = true;
            self.running = None;
            Ok(Status::Done)
        } else if out.len() > mark {
            Ok(Status::More)
        } else {
            Ok(Status::NeedInput)
        }
    }

    fn consumed(&self) -> usize {
        self.consumed
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    /// Everything consumed, once decoding has started (the header is read
    /// once, when it does).
    fn releasable_input(&self) -> usize {
        if self.running.is_some() || self.done {
            self.consumed
        } else {
            0
        }
    }

    fn release_input(&mut self, n: usize) {
        self.consumed = self.consumed.saturating_sub(n);
        let from_header = n.min(self.data_at);
        self.data_at = self.data_at.saturating_sub(from_header);
        if let Some(r) = self.running.as_mut() {
            r.rc.pos = r.rc.pos.saturating_sub(n.saturating_sub(from_header));
        }
    }

    /// Output before the dictionary (all of it once done); nothing for raw
    /// LZMA, whose dictionary size is not known.
    fn releasable_output(&self, out_len: usize) -> usize {
        if self.done {
            return out_len;
        }
        match (self.running.as_ref(), self.dict) {
            (Some(r), Some(dict)) => out_len
                .saturating_sub(dict)
                .max(r.view.index(0))
                .min(out_len),
            _ => 0,
        }
    }

    fn release_output(&mut self, n: usize) {
        if let Some(r) = self.running.as_mut() {
            r.view.dropped = r.view.dropped.saturating_add(n);
            r.end = r.end.map(|e| e.saturating_sub(n));
        }
    }
}

/// What [`Lzma2::step`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chunk {
    /// Nothing: more input is needed first (only before the end of input).
    NeedInput,
    /// Some progress: output, or a chunk header.
    Decoded,
    /// The end marker: the stream is complete.
    End,
}

/// An LZMA chunk being decoded.
#[derive(Clone, Copy)]
struct Open {
    /// Where its compressed data starts in the input, and its size.
    data_at: usize,
    packed: usize,
    /// The stream position where its output ends.
    end: usize,
    rc: Registers,
}

/// An LZMA2 stream decoded incrementally (raw LZMA2, and xz blocks):
/// uncompressed chunks whole, LZMA chunks a symbol at a time like
/// [`LzmaStream`].
#[derive(Clone, Default)]
pub struct Lzma2 {
    /// Input consumed (from the start of the LZMA2 data), up to the chunk
    /// being decoded.
    pos: usize,
    state: Option<State>,
    /// The stream position of the last dictionary reset.
    dict: usize,
    open: Option<Open>,
    done: bool,
}

/// `Ok(NeedInput)` before the end of the input, else the error.
fn short(eof: bool, what: &str) -> Result<Chunk> {
    if eof {
        Err(bad(what))
    } else {
        Ok(Chunk::NeedInput)
    }
}

impl Lzma2 {
    /// Input bytes consumed so far.
    pub fn consumed(&self) -> usize {
        self.open
            .map_or(self.pos, |o| o.data_at.saturating_add(o.rc.pos))
    }

    /// Whether the end marker has been decoded.
    pub fn done(&self) -> bool {
        self.done
    }

    /// Rebases the input positions after the first `n` bytes (at most
    /// [`consumed`](Self::consumed)) of the LZMA2 data were dropped.
    pub fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        if let Some(o) = self.open.as_mut() {
            let before = n.min(o.data_at);
            let within = n.saturating_sub(before);
            o.data_at = o.data_at.saturating_sub(before);
            o.rc.pos = o.rc.pos.saturating_sub(within);
            o.packed = o.packed.saturating_sub(within);
        }
    }

    /// Where the dictionary starts in the buffer `view` locates: output
    /// before the last dictionary reset is never read again.
    pub fn dict_start(&self, view: View) -> usize {
        view.index(self.dict)
    }

    /// Decodes more of `input` (the LZMA2 data so far) into `out`, pausing
    /// between symbols once `out` reaches `stop` bytes. `view` locates this
    /// stream in `out`; `limit` bounds `out`'s length.
    pub fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        view: View,
        stop: usize,
        limit: usize,
    ) -> Result<Chunk> {
        if self.done {
            return Ok(Chunk::End);
        }
        if self.open.is_none() {
            let begun = self.begin(input, eof, out, view, limit)?;
            if self.open.is_none() {
                return Ok(begun);
            }
        }
        let Some(open) = self.open else {
            return Err(bad("no chunk"));
        };
        let chunk_end = open.data_at.saturating_add(open.packed);
        let complete = input.len() >= chunk_end;
        if !complete && eof {
            return Err(bad("truncated chunk"));
        }
        let data = input
            .get(open.data_at..chunk_end.min(input.len()))
            .unwrap_or_default();
        let st = self
            .state
            .as_mut()
            .ok_or_else(|| bad("LZMA chunk before properties"))?;
        let bounds = Bounds {
            view,
            dict: view.index(self.dict),
            end: Some(view.index(open.end)),
            stop,
            avail: if complete {
                usize::MAX
            } else {
                data.len().saturating_sub(MARGIN)
            },
            limit,
        };
        let mark = out.len();
        let mut rc = Range::resume(data, open.rc);
        if st.run(&mut rc, out, bounds)? {
            self.pos = chunk_end;
            self.open = None;
            return Ok(Chunk::Decoded);
        }
        self.open = Some(Open {
            rc: rc.registers(),
            ..open
        });
        Ok(if out.len() > mark {
            Chunk::Decoded
        } else {
            Chunk::NeedInput
        })
    }

    /// Starts the next chunk once its header (and, for an LZMA chunk, the
    /// range coder's first bytes) has arrived: copies an uncompressed chunk
    /// whole, or opens an LZMA chunk for [`step`](Self::step) to decode.
    fn begin(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        view: View,
        limit: usize,
    ) -> Result<Chunk> {
        let pos = self.pos;
        let Some(&control) = input.get(pos) else {
            return short(eof, "truncated LZMA2 data");
        };
        let at = |i: usize| usize::from(input.get(pos.saturating_add(i)).copied().unwrap_or(0));
        match control {
            0x00 => {
                self.pos = pos.saturating_add(1);
                self.done = true;
                Ok(Chunk::End)
            }
            0x01 | 0x02 => {
                if input.len() < pos.saturating_add(3) {
                    return short(eof, "truncated chunk");
                }
                let size = (at(1) << 8 | at(2)).saturating_add(1);
                let Some(data) =
                    input.get(pos.saturating_add(3)..pos.saturating_add(3).saturating_add(size))
                else {
                    return short(eof, "truncated chunk");
                };
                if control == 0x01 {
                    self.dict = view.position(out.len());
                }
                out.extend_from_slice(data);
                self.pos = pos.saturating_add(3).saturating_add(size);
                if out.len() > limit {
                    return Err(too_large(limit));
                }
                Ok(Chunk::Decoded)
            }
            0x80..=0xff => {
                if input.len() < pos.saturating_add(5) {
                    return short(eof, "truncated chunk header");
                }
                let unpacked =
                    (usize::from(control & 0x1f) << 16 | at(1) << 8 | at(2)).saturating_add(1);
                let packed = (at(3) << 8 | at(4)).saturating_add(1);
                let reset = (control >> 5) & 3;
                let data_at = pos
                    .saturating_add(5)
                    .saturating_add(usize::from(reset >= 2));
                if input.len() < data_at {
                    return short(eof, "truncated properties");
                }
                let chunk_end = data_at.saturating_add(packed);
                if input.len() < chunk_end
                    && (eof || input.len() < data_at.saturating_add(packed.min(5)))
                {
                    return short(eof, "truncated chunk");
                }
                if reset == 3 {
                    self.dict = view.position(out.len());
                }
                if reset >= 2 {
                    let props = Props::from_byte(u8::try_from(at(5)).unwrap_or(0xff))?;
                    if props.lc.saturating_add(props.lp) > 4 {
                        return Err(bad("lc + lp exceeds 4"));
                    }
                    self.state = Some(State::new(props));
                } else if reset == 1 {
                    let props = self
                        .state
                        .as_ref()
                        .map(|s| s.props)
                        .ok_or_else(|| bad("state reset before properties"))?;
                    self.state = Some(State::new(props));
                }
                if self.state.is_none() {
                    return Err(bad("LZMA chunk before properties"));
                }
                let rc = Range::new(
                    input
                        .get(data_at..chunk_end.min(input.len()))
                        .unwrap_or_default(),
                )?
                .registers();
                if out.len().saturating_add(unpacked) > limit {
                    return Err(too_large(limit));
                }
                let end = view.position(out.len()).saturating_add(unpacked);
                self.open = Some(Open {
                    data_at,
                    packed,
                    end,
                    rc,
                });
                Ok(Chunk::Decoded)
            }
            _ => Err(bad("invalid LZMA2 control byte")),
        }
    }
}

/// Raw LZMA2 (7-Zip) as a [`Decoder`].
#[derive(Default)]
pub struct Lzma2Stream {
    core: Lzma2,
    view: Option<View>,
    /// The dictionary size, when known (7-Zip's coder property).
    window: Option<usize>,
}

impl Lzma2Stream {
    /// Raw LZMA2 whose dictionary size is `dict`, if known.
    pub fn new(dict: Option<u32>) -> Self {
        Lzma2Stream {
            window: dict.map(|d| usize::try_from(d).unwrap_or(usize::MAX).max(4096)),
            ..Self::default()
        }
    }
}

/// The dictionary size an LZMA2 property byte (7-Zip, xz) encodes.
pub fn lzma2_dict(prop: u8) -> Option<u32> {
    match prop {
        40 => Some(u32::MAX),
        0..=39 => (2u32 | u32::from(prop & 1)).checked_shl(u32::from(prop / 2).saturating_add(11)),
        _ => None,
    }
}

impl Decoder for Lzma2Stream {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let view = *self.view.get_or_insert(View {
            start: out.len(),
            dropped: 0,
        });
        let mark = out.len();
        let target = mark.saturating_add(step.max(1));
        loop {
            if out.len() >= target {
                return Ok(Status::More);
            }
            match self.core.step(input, eof, out, view, target, limit)? {
                Chunk::End => return Ok(Status::Done),
                Chunk::Decoded => {}
                Chunk::NeedInput if out.len() > mark => return Ok(Status::More),
                Chunk::NeedInput => return Ok(Status::NeedInput),
            }
        }
    }

    fn consumed(&self) -> usize {
        self.core.consumed()
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    fn releasable_input(&self) -> usize {
        self.core.consumed()
    }

    fn release_input(&mut self, n: usize) {
        self.core.release_input(n);
    }

    /// Output before the dictionary (when its size is known) or before the
    /// last dictionary reset; all of it once done.
    fn releasable_output(&self, out_len: usize) -> usize {
        match self.view {
            _ if self.core.done() => out_len,
            Some(view) => {
                let beyond = self.window.map_or(0, |w| out_len.saturating_sub(w));
                self.core.dict_start(view).max(beyond).min(out_len)
            }
            None => 0,
        }
    }

    fn release_output(&mut self, n: usize) {
        if let Some(v) = self.view.as_mut() {
            v.dropped = v.dropped.saturating_add(n);
        }
    }
}

// ---------------------------------------------------------------------------
// Branch converters (BCJ) and Delta, decoding direction.

fn test_ms(b: u8) -> bool {
    b == 0 || b == 0xff
}

/// An xz/7-Zip filter after the decompressor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Post {
    X86,
    Arm,
    Arm64,
    Delta(usize),
}

impl Post {
    /// Filters a whole buffer (a stream from position 0).
    pub fn apply(self, buf: &mut [u8]) {
        PostState::new(self).run(buf, true);
    }
}

/// A [`Post`] filter applied incrementally: [`run`](Self::run) filters the
/// stream a piece at a time and says how much of each piece is final.
#[derive(Clone)]
pub struct PostState {
    kind: Post,
    /// The stream position of the next byte to filter.
    pos: u64,
    /// x86: the position of the last E8/E9 byte seen, and the mask of
    /// recent ones.
    prev_pos: u64,
    prev_mask: u32,
    /// Delta: the last 256 output bytes, by position.
    history: [u8; 256],
}

impl PostState {
    pub fn new(kind: Post) -> Self {
        PostState {
            kind,
            pos: 0,
            prev_pos: u64::MAX,
            prev_mask: 0,
            history: [0; 256],
        }
    }

    /// Filters `buf`, the stream from this filter's position on, in place,
    /// and returns how many of its leading bytes are final; the rest must be
    /// passed again, with more after them, next time. At `eof` all are
    /// final.
    pub fn run(&mut self, buf: &mut [u8], eof: bool) -> usize {
        let done = match self.kind {
            Post::X86 => self.x86(buf),
            Post::Arm => {
                arm(buf, self.pos);
                buf.len() & !3
            }
            Post::Arm64 => {
                arm64(buf, self.pos);
                buf.len() & !3
            }
            Post::Delta(d) => {
                self.delta(buf, d);
                buf.len()
            }
        };
        let done = if eof { buf.len() } else { done.min(buf.len()) };
        self.pos = self.pos.wrapping_add(u64::try_from(done).unwrap_or(0));
        done
    }

    /// x86 BCJ (E8 CALL, E9 JMP); returns where it stopped (it reads four
    /// bytes past each position).
    fn x86(&mut self, buf: &mut [u8]) -> usize {
        const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
        const BIT_NUM: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
        let size = buf.len().saturating_sub(4);
        let mut i = 0usize;
        let byte = |buf: &[u8], i: usize| buf.get(i).copied().unwrap_or(0);
        let at = |i: usize| self.pos.wrapping_add(u64::try_from(i).unwrap_or(0));
        while i < size {
            if byte(buf, i) & 0xfe != 0xe8 {
                i = i.saturating_add(1);
                continue;
            }
            let gap = at(i).wrapping_sub(self.prev_pos);
            if gap > 3 {
                self.prev_mask = 0;
            } else {
                self.prev_mask = (self.prev_mask << (gap.wrapping_sub(1) & 31)) & 7;
                if self.prev_mask != 0 {
                    let m = usize::try_from(self.prev_mask).unwrap_or(0);
                    let b = byte(
                        buf,
                        i.wrapping_add(4).wrapping_sub(
                            usize::try_from(BIT_NUM.get(m).copied().unwrap_or(0)).unwrap_or(0),
                        ),
                    );
                    if !ALLOWED.get(m).copied().unwrap_or(false) || test_ms(b) {
                        self.prev_pos = at(i);
                        self.prev_mask = self.prev_mask << 1 | 1;
                        i = i.saturating_add(1);
                        continue;
                    }
                }
            }
            self.prev_pos = at(i);
            if test_ms(byte(buf, i.saturating_add(4))) {
                let src_bytes: [u8; 4] = buf
                    .get(i.saturating_add(1)..i.saturating_add(5))
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 4]);
                let mut src = u32::from_le_bytes(src_bytes);
                // The position after the instruction, modulo 2^32.
                let pos = u32::try_from(at(i) & 0xffff_ffff)
                    .unwrap_or(0)
                    .wrapping_add(5);
                let mut dest;
                loop {
                    dest = src.wrapping_sub(pos);
                    if self.prev_mask == 0 {
                        break;
                    }
                    let j = BIT_NUM
                        .get(usize::try_from(self.prev_mask).unwrap_or(0))
                        .copied()
                        .unwrap_or(0)
                        .wrapping_mul(8);
                    let b =
                        u8::try_from((dest >> (24u32.wrapping_sub(j) & 31)) & 0xff).unwrap_or(0);
                    if !test_ms(b) {
                        break;
                    }
                    src = dest ^ ((1u32 << (32u32.wrapping_sub(j) & 31)).wrapping_sub(1));
                }
                dest &= 0x01ff_ffff;
                dest |= 0u32.wrapping_sub(dest & 0x0100_0000);
                if let Some(slot) = buf.get_mut(i.saturating_add(1)..i.saturating_add(5)) {
                    slot.copy_from_slice(&dest.to_le_bytes());
                }
                i = i.saturating_add(5);
            } else {
                self.prev_mask = self.prev_mask << 1 | 1;
                i = i.saturating_add(1);
            }
        }
        i
    }

    /// Delta decoding with byte distance `distance` (1 to 256).
    fn delta(&mut self, buf: &mut [u8], distance: usize) {
        let d = u64::try_from(distance).unwrap_or(0);
        let slot = |p: u64| usize::try_from(p & 0xff).unwrap_or(0);
        let mut p = self.pos;
        for b in buf.iter_mut() {
            if p >= d {
                *b = b.wrapping_add(
                    self.history
                        .get(slot(p.wrapping_sub(d)))
                        .copied()
                        .unwrap_or(0),
                );
            }
            if let Some(h) = self.history.get_mut(slot(p)) {
                *h = *b;
            }
            p = p.wrapping_add(1);
        }
    }
}

/// The program counter (modulo 2^32) of the word at index `i` of a buffer
/// starting at stream position `pos`.
fn pc(pos: u64, i: usize) -> u32 {
    u32::try_from(pos & 0xffff_ffff)
        .unwrap_or(0)
        .wrapping_add(u32::try_from(i).unwrap_or(0).wrapping_mul(4))
}

/// ARM (32-bit) BCJ: BL instructions, over the whole words of `buf`.
fn arm(buf: &mut [u8], pos: u64) {
    for (i, w) in buf.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        if w[3] == 0xeb {
            let src = (u32::from(w[2]) << 16 | u32::from(w[1]) << 8 | u32::from(w[0])) << 2;
            let dest = src.wrapping_sub(pc(pos, i).wrapping_add(8)) >> 2;
            let d = dest.to_le_bytes();
            w[0] = d[0];
            w[1] = d[1];
            w[2] = d[2];
        }
    }
}

/// ARM64 BCJ: BL and ADRP instructions, over the whole words of `buf`.
fn arm64(buf: &mut [u8], pos: u64) {
    for (i, w) in buf.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let pc = pc(pos, i);
        let mut instr = u32::from_le_bytes(*w);
        if instr >> 26 == 0x25 {
            instr = 0x9400_0000 | (instr.wrapping_sub(pc >> 2) & 0x03ff_ffff);
            *w = instr.to_le_bytes();
        } else if instr & 0x9f00_0000 == 0x9000_0000 {
            let src = (instr >> 29 & 3) | (instr >> 3 & 0x001f_fffc);
            if src.wrapping_add(0x0002_0000) & 0x001c_0000 != 0 {
                continue;
            }
            let dest = src.wrapping_sub(pc >> 12);
            instr &= 0x9000_001f;
            instr |= (dest & 3) << 29;
            instr |= (dest & 0x0003_fffc) << 3;
            instr |= 0u32.wrapping_sub(dest & 0x0002_0000) & 0x00e0_0000;
            *w = instr.to_le_bytes();
        }
    }
}
