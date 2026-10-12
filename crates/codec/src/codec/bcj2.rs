//! 7-Zip's BCJ2 x86 branch converter (coder `03 03 01 1B`), decoding
//! direction.
//!
//! BCJ2 splits x86 code into four streams: the main stream (the code with
//! the targets of converted CALL/JMP/Jcc instructions removed), the CALL
//! targets and the JMP/Jcc targets (absolute, big-endian 32-bit), and a
//! range-coded stream of one bit per candidate opcode saying whether it was
//! converted. Each stream has its own coder in the 7z folder (usually LZMA2
//! for the main stream, LZMA for the targets, none for the bits).
//!
//! The decoder reads the four streams side by side, so its single input
//! holds their packed bytes interleaved in pieces of at most [`PIECE`]
//! bytes, in the order [`Schedule`] gives: each stream advances in
//! proportion to its packed length, so the input arrives roughly as fast as
//! the streams use it. The decoder routes each piece to its stream as it
//! arrives and releases the input it has routed; each stream releases what
//! its own decoder has consumed. So a large folder is held only as far as
//! the streams run ahead of each other, not in full.
//!
//! The format follows the LZMA SDK's `Bcj2.c` (Igor Pavlov, public domain):
//! an 11-bit adaptive bit model per previous byte for E8, one for E9 and one
//! for Jcc, and an LZMA-style range decoder whose 5 first bytes start the
//! code.

use std::sync::Arc;

use super::Codec;
use super::pipeline::{Decoder, Status};
use crate::error::{Diagnostic, Result};

/// One of the four input streams: its packed length, how it is coded, and
/// its decoded size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub len: u64,
    /// [`Codec::Stored`] for a stream packed as is (the bit stream).
    pub codec: Codec,
    pub size: u64,
}

/// A BCJ2 folder: main, CALL, JMP and range coder streams, and the size of
/// the output. The decoder's input is their packed bytes interleaved as
/// [`Schedule`] says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub streams: [Stream; 4],
    pub size: u64,
}

/// Largest piece of one stream in the interleaved input. Small in tests,
/// so the fixture exercises interleaving.
pub const PIECE: u64 = if cfg!(test) { 64 } else { 256 * 1024 };

/// The order of the pieces of the decoder's input: each item is (stream,
/// offset in its packed bytes, length). The next piece always comes from
/// the stream that has had the smallest fraction of its packed bytes so
/// far (ties: the shorter stream, then the lower index), so short streams
/// come first and long ones advance together.
#[derive(Clone, Debug)]
pub struct Schedule {
    lens: [u64; 4],
    taken: [u64; 4],
}

impl Schedule {
    pub fn new(lens: [u64; 4]) -> Self {
        Schedule {
            lens,
            taken: [0; 4],
        }
    }

    /// Whether every byte of stream `k` has been scheduled.
    fn exhausted(&self, k: usize) -> bool {
        self.taken.get(k) >= self.lens.get(k)
    }
}

impl Iterator for Schedule {
    type Item = (usize, u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let mut best: Option<usize> = None;
        for k in 0..4 {
            let (Some(&len), Some(&taken)) = (self.lens.get(k), self.taken.get(k)) else {
                continue;
            };
            if taken >= len {
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => {
                    let (bl, bt) = (
                        self.lens.get(b).copied().unwrap_or(0),
                        self.taken.get(b).copied().unwrap_or(0),
                    );
                    // taken/len < bt/bl, cross-multiplied.
                    let lhs = u128::from(taken).saturating_mul(u128::from(bl));
                    let rhs = u128::from(bt).saturating_mul(u128::from(len));
                    lhs < rhs || (lhs == rhs && len < bl)
                }
            };
            if better {
                best = Some(k);
            }
        }
        let k = best?;
        let len = self.lens.get(k).copied().unwrap_or(0);
        let slot = self.taken.get_mut(k)?;
        let offset = *slot;
        let n = len.saturating_sub(offset).min(PIECE);
        *slot = offset.saturating_add(n);
        Some((k, offset, n))
    }
}

const MAIN: usize = 0;
const CALL: usize = 1;
const JUMP: usize = 2;
const RC: usize = 3;

const TOP: u32 = 1 << 24;
const MODEL_BITS: u32 = 11;
const MODEL_TOTAL: u16 = 1 << MODEL_BITS;
const MOVE_BITS: u32 = 5;
/// Output a stream's decoder produces per call (and the used output or
/// input kept before it is dropped). Small in tests, so the fixture
/// exercises both.
const CHUNK: usize = if cfg!(test) { 256 } else { 64 * 1024 };
/// Input bytes routed to the streams per round, and rounds per call.
const ROUTE: usize = if cfg!(test) { 128 } else { 1024 * 1024 };
const ROUNDS: u32 = 8;

/// A stream being decoded: its packed bytes not yet released, its decoder
/// (none if stored) and the decoded bytes not yet used.
struct Sub {
    size: usize,
    decoder: Option<Box<dyn Decoder>>,
    /// Packed bytes received; those its decoder released are dropped.
    input: Vec<u8>,
    /// All of its packed bytes have been received (or the input ended).
    complete: bool,
    /// Decoded bytes; those before `pos` have been used.
    buf: Vec<u8>,
    pos: usize,
    /// Stored streams: input bytes copied to `buf` so far.
    fed: usize,
    /// Decoded bytes dropped from the front of `buf`.
    released: usize,
    done: bool,
}

impl Sub {
    fn new(s: &Stream) -> Self {
        Sub {
            size: usize::try_from(s.size).unwrap_or(usize::MAX),
            decoder: s.codec.decoder(),
            input: Vec::new(),
            complete: s.len == 0,
            buf: Vec::new(),
            pos: 0,
            fed: 0,
            released: 0,
            done: false,
        }
    }

    fn avail(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Drops used output and consumed input the stream no longer needs.
    fn trim(&mut self) {
        let drop = match &self.decoder {
            Some(d) => d.releasable_output(self.buf.len()).min(self.pos),
            None => self.pos,
        };
        if drop >= CHUNK {
            self.buf.drain(..drop);
            self.pos = self.pos.saturating_sub(drop);
            self.released = self.released.saturating_add(drop);
            if let Some(d) = self.decoder.as_mut() {
                d.release_output(drop);
            }
        }
        let used = match &self.decoder {
            Some(d) => d.releasable_input(),
            None => self.fed,
        }
        .min(self.input.len());
        if used >= CHUNK {
            self.input.drain(..used);
            match self.decoder.as_mut() {
                Some(d) => d.release_input(used),
                None => self.fed = self.fed.saturating_sub(used),
            }
        }
    }

    /// Decodes some more of the stream from the packed bytes it has.
    fn pump(&mut self) -> Result<Pumped> {
        if self.done {
            return Ok(Pumped::Stalled);
        }
        self.trim();
        let before = self.buf.len();
        let mut busy = false;
        match self.decoder.as_mut() {
            None => {
                let fresh = self.input.get(self.fed..).unwrap_or_default();
                let n = fresh.len().min(CHUNK);
                self.buf
                    .extend_from_slice(fresh.get(..n).unwrap_or_default());
                self.fed = self.fed.saturating_add(n);
                if self.complete && self.fed >= self.input.len() {
                    self.done = true;
                }
            }
            Some(d) => {
                // The decoder's limit counts the output it still holds.
                let limit = self.size.saturating_sub(self.released);
                match d.decode(&self.input, self.complete, &mut self.buf, CHUNK, limit)? {
                    Status::Done => self.done = true,
                    Status::More => busy = true,
                    Status::NeedInput => {}
                }
            }
        }
        Ok(if self.buf.len() > before {
            Pumped::Grew
        } else if busy {
            Pumped::Busy
        } else {
            Pumped::Stalled
        })
    }

    /// A copy to resume from, if its decoder can be checkpointed.
    fn checkpoint(&self) -> Option<Self> {
        let decoder = match &self.decoder {
            Some(d) => Some(d.checkpoint()?),
            None => None,
        };
        Some(Sub {
            size: self.size,
            decoder,
            input: self.input.clone(),
            complete: self.complete,
            buf: self.buf.clone(),
            pos: self.pos,
            fed: self.fed,
            released: self.released,
            done: self.done,
        })
    }

    fn state_size(&self) -> usize {
        self.input
            .len()
            .saturating_add(self.buf.len())
            .saturating_add(self.decoder.as_ref().map_or(0, |d| d.state_size()))
    }
}

/// What a [`Sub::pump`] achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pumped {
    /// More decoded bytes.
    Grew,
    /// The decoder worked (read a header) but produced nothing yet.
    Busy,
    /// Nothing: the stream ended, or it needs more packed bytes.
    Stalled,
}

/// Whether a stream's bytes are available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Avail {
    Ready,
    NeedInput,
    /// Not yet, but work was done: yield and come back.
    Later,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Copying bytes of the main stream.
    Literal,
    /// A candidate opcode was output; its bit is next.
    Bit(u8),
    /// A converted instruction: its target is next (from the CALL stream
    /// if `true`).
    Target(bool),
}

/// The BCJ2 decoder (see the module docs).
pub struct Bcj2 {
    subs: [Sub; 4],
    /// Where the pieces of the input go.
    schedule: Schedule,
    /// The stream the current piece belongs to, and its bytes not yet
    /// routed.
    piece: (usize, u64),
    /// Input bytes routed to the streams (relative to the input as it is
    /// now: routed input may be released).
    routed: usize,
    probs: [u16; 258],
    code: u32,
    range: u32,
    started: bool,
    prev: u8,
    stage: Stage,
    /// Output produced so far (instruction addresses count from 0).
    produced: u64,
    size: u64,
}

impl Bcj2 {
    pub fn new(params: &Arc<Params>) -> Self {
        Bcj2 {
            subs: params.streams.each_ref().map(Sub::new),
            schedule: Schedule::new(params.streams.each_ref().map(|s| s.len)),
            piece: (0, 0),
            routed: 0,
            probs: [MODEL_TOTAL >> 1; 258],
            code: 0,
            range: u32::MAX,
            started: false,
            prev: 0,
            stage: Stage::Literal,
            produced: 0,
            size: params.size,
        }
    }

    /// Routes up to [`ROUTE`] more bytes of the input to their streams and
    /// marks the streams whose packed bytes have all arrived. Returns the
    /// number of bytes routed.
    fn route(&mut self, input: &[u8], eof: bool) -> usize {
        let mut moved = 0usize;
        while moved < ROUTE {
            if self.piece.1 == 0 {
                match self.schedule.next() {
                    Some((k, _, n)) => self.piece = (k, n),
                    None => break,
                }
            }
            let fresh = input.get(self.routed..).unwrap_or_default();
            let room = ROUTE.saturating_sub(moved);
            let n = usize::try_from(self.piece.1)
                .unwrap_or(usize::MAX)
                .min(fresh.len())
                .min(room);
            if n == 0 {
                break;
            }
            if let Some(sub) = self.subs.get_mut(self.piece.0) {
                sub.input
                    .extend_from_slice(fresh.get(..n).unwrap_or_default());
            }
            self.routed = self.routed.saturating_add(n);
            self.piece.1 = self.piece.1.saturating_sub(u64::try_from(n).unwrap_or(0));
            moved = moved.saturating_add(n);
        }
        let ended = eof && self.routed >= input.len();
        for (k, sub) in self.subs.iter_mut().enumerate() {
            let pending = self.piece.0 == k && self.piece.1 > 0;
            if ended || (self.schedule.exhausted(k) && !pending) {
                sub.complete = true;
            }
        }
        moved
    }

    /// Makes `n` decoded bytes of stream `k` available, if it can within
    /// a bounded amount of work. At the end of the input a stream that
    /// runs short is an error.
    fn need(&mut self, k: usize, n: usize, input: &[u8], eof: bool) -> Result<Avail> {
        let mut busy = 0u32;
        let mut rounds = 0u32;
        loop {
            let sub = self
                .subs
                .get_mut(k)
                .ok_or_else(|| Diagnostic::internal("BCJ2 stream index"))?;
            if sub.avail() >= n {
                return Ok(Avail::Ready);
            }
            match sub.pump()? {
                Pumped::Grew => {}
                Pumped::Busy => {
                    busy = busy.saturating_add(1);
                    if busy >= 16 {
                        return Ok(Avail::Later);
                    }
                }
                Pumped::Stalled => {
                    if sub.done || sub.complete {
                        return Err(Diagnostic::malformed(format!(
                            "BCJ2: {} stream ends early",
                            ["main", "CALL", "JMP", "range coder"]
                                .get(k)
                                .copied()
                                .unwrap_or("?")
                        )));
                    }
                    // Its packed bytes come later in the input: route more.
                    if self.route(input, eof) == 0 && !self.subs.get(k).is_some_and(|s| s.complete)
                    {
                        return Ok(Avail::NeedInput);
                    }
                    rounds = rounds.saturating_add(1);
                    if rounds >= ROUNDS {
                        return Ok(Avail::Later);
                    }
                }
            }
        }
    }

    fn take(&mut self, k: usize) -> u8 {
        let Some(sub) = self.subs.get_mut(k) else {
            return 0;
        };
        let b = sub.buf.get(sub.pos).copied().unwrap_or(0);
        sub.pos = sub.pos.saturating_add(1);
        b
    }

    fn emit(&mut self, out: &mut Vec<u8>, b: u8, limit: usize) -> Result<()> {
        if out.len() >= limit {
            return Err(Diagnostic::output_limit(limit));
        }
        out.push(b);
        self.produced = self.produced.saturating_add(1);
        Ok(())
    }
}

/// Whether `b` (after `prev`) is an instruction BCJ2 may have converted:
/// E8 CALL, E9 JMP, or 0F 8x Jcc.
fn is_jump(prev: u8, b: u8) -> bool {
    b & 0xfe == 0xe8 || (prev == 0x0f && b & 0xf0 == 0x80)
}

impl Decoder for Bcj2 {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let target = out.len().saturating_add(step.max(1));
        loop {
            if self.produced >= self.size {
                return Ok(Status::Done);
            }
            if out.len() >= target {
                return Ok(Status::More);
            }
            match self.stage {
                Stage::Literal => {
                    match self.need(MAIN, 1, input, eof)? {
                        Avail::Ready => {}
                        Avail::NeedInput => return Ok(Status::NeedInput),
                        Avail::Later => return Ok(Status::More),
                    }
                    let room = target.saturating_sub(out.len());
                    let mut n = self.subs.get(MAIN).map_or(0, Sub::avail).min(room);
                    while n > 0 && self.produced < self.size {
                        let b = self.take(MAIN);
                        self.emit(out, b, limit)?;
                        n = n.saturating_sub(1);
                        if is_jump(self.prev, b) {
                            self.stage = Stage::Bit(b);
                            break;
                        }
                        self.prev = b;
                    }
                }
                Stage::Bit(b) => {
                    let want = if !self.started {
                        5
                    } else if self.range < TOP {
                        1
                    } else {
                        0
                    };
                    if want > 0 {
                        match self.need(RC, want, input, eof)? {
                            Avail::Ready => {}
                            Avail::NeedInput => return Ok(Status::NeedInput),
                            Avail::Later => return Ok(Status::More),
                        }
                    }
                    if !self.started {
                        for _ in 0..5 {
                            self.code = self.code << 8 | u32::from(self.take(RC));
                        }
                        self.started = true;
                    } else if self.range < TOP {
                        self.range <<= 8;
                        self.code = self.code << 8 | u32::from(self.take(RC));
                    }
                    let index = match b {
                        0xe8 => usize::from(self.prev),
                        0xe9 => 256,
                        _ => 257,
                    };
                    let p = self.probs.get(index).copied().unwrap_or(MODEL_TOTAL >> 1);
                    let bound = (self.range >> MODEL_BITS).wrapping_mul(u32::from(p));
                    let converted = self.code >= bound;
                    let p = if converted {
                        self.range = self.range.wrapping_sub(bound);
                        self.code = self.code.wrapping_sub(bound);
                        p.wrapping_sub(p >> MOVE_BITS)
                    } else {
                        self.range = bound;
                        p.wrapping_add(MODEL_TOTAL.wrapping_sub(p) >> MOVE_BITS)
                    };
                    if let Some(slot) = self.probs.get_mut(index) {
                        *slot = p;
                    }
                    if converted {
                        self.stage = Stage::Target(b == 0xe8);
                    } else {
                        self.prev = b;
                        self.stage = Stage::Literal;
                    }
                }
                Stage::Target(call) => {
                    let k = if call { CALL } else { JUMP };
                    match self.need(k, 4, input, eof)? {
                        Avail::Ready => {}
                        Avail::NeedInput => return Ok(Status::NeedInput),
                        Avail::Later => return Ok(Status::More),
                    }
                    let mut v = 0u32;
                    for _ in 0..4 {
                        v = v << 8 | u32::from(self.take(k));
                    }
                    let at = u32::try_from(self.produced & 0xffff_ffff).unwrap_or(0);
                    let dest = v.wrapping_sub(at.wrapping_add(4));
                    for byte in dest.to_le_bytes() {
                        if self.produced >= self.size {
                            break;
                        }
                        self.emit(out, byte, limit)?;
                    }
                    self.prev = dest.to_le_bytes()[3];
                    self.stage = Stage::Literal;
                }
            }
        }
    }

    fn consumed(&self) -> usize {
        self.routed
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    /// Everything routed: the streams hold what they still need.
    fn releasable_input(&self) -> usize {
        self.routed
    }

    fn release_input(&mut self, n: usize) {
        self.routed = self.routed.saturating_sub(n);
    }

    /// All of it: the output is never read back.
    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }

    /// Each stream checkpointed with what it holds: its unreleased packed
    /// bytes, and its decoder's window of decoded bytes (as large as its
    /// dictionary, as for a plain LZMA stream).
    fn checkpoint(&self) -> Option<Box<dyn Decoder>> {
        let [a, b, c, d] = &self.subs;
        Some(Box::new(Bcj2 {
            subs: [
                a.checkpoint()?,
                b.checkpoint()?,
                c.checkpoint()?,
                d.checkpoint()?,
            ],
            schedule: self.schedule.clone(),
            piece: self.piece,
            routed: self.routed,
            probs: self.probs,
            code: self.code,
            range: self.range,
            started: self.started,
            prev: self.prev,
            stage: self.stage,
            produced: self.produced,
            size: self.size,
        }))
    }

    fn state_size(&self) -> usize {
        self.subs
            .iter()
            .map(Sub::state_size)
            .fold(std::mem::size_of::<Self>(), usize::saturating_add)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::codec::lzma::{Props, lzma2_dict};
    use crate::codec::pipeline::{decode_all, verify_checkpoints};

    /// The decoder's input: the packed streams (given in stream order)
    /// interleaved as [`Schedule`] says.
    fn interleave(packed: [&[u8]; 4]) -> Vec<u8> {
        let lens = packed.map(|p| p.len() as u64);
        let mut input = Vec::new();
        for (k, offset, len) in Schedule::new(lens) {
            input.extend_from_slice(&packed[k][offset as usize..(offset + len) as usize]);
        }
        input
    }

    /// Decodes `input` the way a lazily decoded source does: fed `feed`
    /// bytes at a time, dropping the input the decoder releases. Returns
    /// the output and the most input bytes the caller and the decoder held
    /// at once.
    fn decode_lazily(d: &mut dyn Decoder, input: &[u8], feed: usize) -> (Vec<u8>, usize) {
        let mut out = Vec::new();
        let mut start = 0; // input released so far
        let mut have = 0; // input fed so far
        let mut most = 0;
        loop {
            let eof = have >= input.len();
            match d
                .decode(&input[start..have], eof, &mut out, 100, 1 << 24)
                .unwrap()
            {
                Status::Done => break,
                Status::More => {}
                Status::NeedInput => have = (have + feed).min(input.len()),
            }
            let n = d.releasable_input().min(have - start);
            d.release_input(n);
            start += n;
            most = most.max(have - start + d.state_size());
        }
        (out, most)
    }

    /// 7-Zip 26.03's `7zz a -mf=BCJ2 -m0=LZMA2` of an x86-64 Mach-O
    /// (`tests/data/7z/make_bcj2.sh`): packed streams main (LZMA2), range
    /// coder, CALL and JMP (LZMA) at 0x20, decoding to the executable
    /// (CRC-32 as recorded in the archive).
    #[test]
    fn bcj2_from_7zip() {
        let archive = include_bytes!("../../../../tests/fixtures/external/7z/bcj2.7z");
        let packed = &archive[0x20..0x20 + 0x741 + 0x0e + 0xf8 + 0x08];
        let input = interleave([
            &packed[..0x741],
            &packed[0x74f..0x847],
            &packed[0x847..],
            &packed[0x741..0x74f],
        ]);
        let lzma = |size| Codec::LzmaRaw {
            props: Props::from_byte(0x6c).unwrap(),
            size: Some(size),
            dict: Some(0x8000),
        };
        let params = Arc::new(Params {
            streams: [
                Stream {
                    len: 0x741,
                    codec: Codec::Lzma2 {
                        dict: lzma2_dict(6),
                    },
                    size: 22196,
                },
                Stream {
                    len: 0xf8,
                    codec: lzma(3208),
                    size: 3208,
                },
                Stream {
                    len: 8,
                    codec: lzma(4),
                    size: 4,
                },
                Stream {
                    len: 0x0e,
                    codec: Codec::Stored,
                    size: 0x0e,
                },
            ],
            size: 25408,
        });
        let codec = Codec::Bcj2(params);
        let out = decode_all(codec.decoder().unwrap().as_mut(), &input, 1 << 20).unwrap();
        assert_eq!(out.len(), 25408);
        assert_eq!(crate::codec::crc32(&out), 0xfa7d_6965);

        // Fed a few bytes at a time, in small steps, releasing input: the
        // same output.
        let (got, _) = decode_lazily(codec.decoder().unwrap().as_mut(), &input, 37);
        assert_eq!(got, out);

        // Checkpoints resume to the same output.
        let (checked, _) = verify_checkpoints(|| codec.decoder().unwrap(), &input, 500, 3).unwrap();
        assert!(checked > 10, "{checked}");

        // A truncated input is an error at its end.
        assert!(decode_all(codec.decoder().unwrap().as_mut(), &input[..0x700], 1 << 20).is_err());
    }

    /// Short streams come first; long ones advance in proportion.
    #[test]
    fn schedule_interleaves_in_proportion() {
        let pieces: Vec<_> = Schedule::new([1000, 100, 0, 5]).collect();
        assert_eq!(pieces[0], (3, 0, 5));
        assert_eq!(pieces[1], (1, 0, 64));
        assert_eq!(pieces[2], (0, 0, 64));
        let total: u64 = pieces.iter().map(|p| p.2).sum();
        assert_eq!(total, 1105);
        // Stream 1 ends about when stream 0 is halfway or more, not after it.
        let last1 = pieces.iter().rposition(|p| p.0 == 1).unwrap();
        let before: u64 = pieces[..last1]
            .iter()
            .filter(|p| p.0 == 0)
            .map(|p| p.2)
            .sum();
        assert!((500..1000).contains(&before), "{before}");
    }

    /// Stored streams far larger than a piece: the input held at once stays
    /// a small multiple of the pieces and chunks, not the whole folder.
    #[test]
    fn input_is_released_as_streams_advance() {
        const N: usize = 200_000;
        // Every 50th byte an E8 CALL. A range coder stream of 0xff bytes
        // keeps the code at the top of the range, so every candidate is
        // converted and the CALL stream is read as the main stream is.
        let main: Vec<u8> = (0..N)
            .map(|i| if i % 50 == 0 { 0xe8 } else { (i % 0xe0) as u8 })
            .collect();
        let calls = N / 50;
        let call: Vec<u8> = (0..calls * 4).map(|i| (i * 7) as u8).collect();
        let rc = vec![0xffu8; 2000];
        let stored = |len: usize| Stream {
            len: len as u64,
            codec: Codec::Stored,
            size: len as u64,
        };
        let size = N + calls * 4;
        let params = Arc::new(Params {
            streams: [stored(N), stored(call.len()), stored(0), stored(rc.len())],
            size: size as u64,
        });
        let input = interleave([&main, &call, &[], &rc]);
        let codec = Codec::Bcj2(params);
        let whole = decode_all(codec.decoder().unwrap().as_mut(), &input, 1 << 24).unwrap();
        assert_eq!(whole.len(), size);
        assert_eq!(whole[5..54], main[1..50]);
        let (out, most) = decode_lazily(codec.decoder().unwrap().as_mut(), &input, 1000);
        assert_eq!(out, whole);
        assert!(most < 8 * 1024, "held {most} bytes of {}", input.len());
    }
}
