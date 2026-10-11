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
//! The decoder's single input holds the four packed streams back to back
//! at the positions [`Params`] gives; it runs each stream's decoder on its
//! part and interleaves their output. The format follows the LZMA SDK's
//! `Bcj2.c` (Igor Pavlov, public domain): an 11-bit adaptive bit model per
//! previous byte for E8, one for E9 and one for Jcc, and an LZMA-style range
//! decoder whose 5 first bytes start the code.

use std::sync::Arc;

use super::Codec;
use super::pipeline::{Decoder, Status};
use crate::error::{Diagnostic, Result};

/// One of the four input streams: where its packed bytes lie in the
/// decoder's input, how they are coded, and its decoded size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub offset: u64,
    pub len: u64,
    /// [`Codec::Stored`] for a stream packed as is (the bit stream).
    pub codec: Codec,
    pub size: u64,
}

/// A BCJ2 folder: main, CALL, JMP and range coder streams, and the size of
/// the output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub streams: [Stream; 4],
    pub size: u64,
}

const MAIN: usize = 0;
const CALL: usize = 1;
const JUMP: usize = 2;
const RC: usize = 3;

const TOP: u32 = 1 << 24;
const MODEL_BITS: u32 = 11;
const MODEL_TOTAL: u16 = 1 << MODEL_BITS;
const MOVE_BITS: u32 = 5;
/// Output a stream's decoder produces per call (and the used output kept
/// before it is dropped). Small in tests, so the fixture exercises both.
const CHUNK: usize = if cfg!(test) { 256 } else { 64 * 1024 };

/// A stream being decoded: its decoder (none if stored) and the decoded
/// bytes not yet used.
struct Sub {
    offset: usize,
    len: usize,
    size: usize,
    decoder: Option<Box<dyn Decoder>>,
    /// Decoded bytes; those before `pos` have been used.
    buf: Vec<u8>,
    pos: usize,
    /// Stored streams: input bytes copied so far.
    fed: usize,
    /// Decoded bytes dropped from the front of `buf`.
    released: usize,
    done: bool,
}

impl Sub {
    fn new(s: &Stream) -> Self {
        Sub {
            offset: usize::try_from(s.offset).unwrap_or(usize::MAX),
            len: usize::try_from(s.len).unwrap_or(usize::MAX),
            size: usize::try_from(s.size).unwrap_or(usize::MAX),
            decoder: s.codec.decoder(),
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

    /// Decodes some more of the stream.
    fn pump(&mut self, input: &[u8], eof: bool) -> Result<Pumped> {
        if self.done {
            return Ok(Pumped::Stalled);
        }
        let end = self.offset.saturating_add(self.len);
        let have = input.len().min(end);
        let part = input.get(self.offset..have).unwrap_or_default();
        let complete = eof || input.len() >= end;
        // Drop used output the decoder no longer needs.
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
        let before = self.buf.len();
        let mut busy = false;
        match self.decoder.as_mut() {
            None => {
                let fresh = part.get(self.fed..).unwrap_or_default();
                let n = fresh.len().min(CHUNK);
                self.buf
                    .extend_from_slice(fresh.get(..n).unwrap_or_default());
                self.fed = self.fed.saturating_add(n);
                if complete && self.fed >= part.len() {
                    self.done = true;
                }
            }
            Some(d) => {
                // The decoder's limit counts the output it still holds.
                let limit = self.size.saturating_sub(self.released);
                match d.decode(part, complete, &mut self.buf, CHUNK, limit)? {
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
}

/// What a [`Sub::pump`] achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pumped {
    /// More decoded bytes.
    Grew,
    /// The decoder worked (read a header) but produced nothing yet.
    Busy,
    /// Nothing: the stream ended, or its input has not arrived yet.
    Stalled,
}

/// Whether a stream's bytes are available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Avail {
    Ready,
    NeedInput,
    /// Not yet, but its decoder is busy: yield and come back.
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

/// The BCJ2 decoder (see the module docs). It keeps all of its input, as
/// the four streams are read side by side.
pub struct Bcj2 {
    subs: [Sub; 4],
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

    fn sub(&mut self, k: usize) -> Result<&mut Sub> {
        self.subs
            .get_mut(k)
            .ok_or_else(|| Diagnostic::internal("BCJ2 stream index"))
    }

    /// Makes `n` decoded bytes of stream `k` available, if it can within
    /// a bounded number of decoder steps. At the end of the input a stream
    /// that runs short is an error.
    fn need(&mut self, k: usize, n: usize, input: &[u8], eof: bool) -> Result<Avail> {
        let sub = self.sub(k)?;
        let mut busy = 0u32;
        while sub.avail() < n {
            let pumped = sub.pump(input, eof)?;
            if pumped == Pumped::Busy {
                busy = busy.saturating_add(1);
                if busy >= 16 {
                    return Ok(Avail::Later);
                }
            }
            if pumped == Pumped::Stalled {
                if sub.done || eof {
                    return Err(Diagnostic::malformed(format!(
                        "BCJ2: {} stream ends early",
                        ["main", "CALL", "JMP", "range coder"]
                            .get(k)
                            .copied()
                            .unwrap_or("?")
                    )));
                }
                return Ok(Avail::NeedInput);
            }
        }
        Ok(Avail::Ready)
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
        self.subs
            .iter()
            .map(|s| s.offset.saturating_add(s.len))
            .max()
            .unwrap_or(0)
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    /// All of it: the output is never read back.
    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::codec::lzma::{Props, lzma2_dict};
    use crate::codec::pipeline::decode_all;

    /// 7-Zip 26.03's `7zz a -mf=BCJ2 -m0=LZMA2` of an x86-64 Mach-O
    /// (`tests/data/7z/make_bcj2.sh`): packed streams main (LZMA2), range
    /// coder, CALL and JMP (LZMA) at 0x20, decoding to the executable
    /// (CRC-32 as recorded in the archive).
    #[test]
    fn bcj2_from_7zip() {
        let archive = include_bytes!("../../../../tests/fixtures/external/7z/bcj2.7z");
        let packed = &archive[0x20..0x20 + 0x741 + 0x0e + 0xf8 + 0x08];
        let lzma = |size| Codec::LzmaRaw {
            props: Props::from_byte(0x6c).unwrap(),
            size: Some(size),
            dict: Some(0x8000),
        };
        let params = Arc::new(Params {
            streams: [
                Stream {
                    offset: 0,
                    len: 0x741,
                    codec: Codec::Lzma2 {
                        dict: lzma2_dict(6),
                    },
                    size: 22196,
                },
                Stream {
                    offset: 0x74f,
                    len: 0xf8,
                    codec: lzma(3208),
                    size: 3208,
                },
                Stream {
                    offset: 0x847,
                    len: 8,
                    codec: lzma(4),
                    size: 4,
                },
                Stream {
                    offset: 0x741,
                    len: 0x0e,
                    codec: Codec::Stored,
                    size: 0x0e,
                },
            ],
            size: 25408,
        });
        let codec = Codec::Bcj2(params);
        let out = decode_all(codec.decoder().unwrap().as_mut(), packed, 1 << 20).unwrap();
        assert_eq!(out.len(), 25408);
        assert_eq!(crate::codec::crc32(&out), 0xfa7d_6965);

        // Fed a few bytes at a time, in small steps: the same output.
        let mut d = codec.decoder().unwrap();
        let mut got = Vec::new();
        let mut have = 0;
        loop {
            let eof = have >= packed.len();
            match d
                .decode(&packed[..have], eof, &mut got, 100, 1 << 20)
                .unwrap()
            {
                Status::Done => break,
                Status::More => {}
                Status::NeedInput => have = (have + 37).min(packed.len()),
            }
        }
        assert_eq!(got, out);

        // Stored streams, the main one longer than a chunk and with no
        // branch candidates: copied through, used bytes dropped on the way.
        let main: Vec<u8> = (0..3000u32).map(|i| (i % 0xe0) as u8).collect();
        let stored = |offset: u64, len: u64| Stream {
            offset,
            len,
            codec: Codec::Stored,
            size: len,
        };
        let params = Arc::new(Params {
            streams: [
                stored(0, 3000),
                stored(3000, 0),
                stored(3000, 0),
                stored(3000, 5),
            ],
            size: 3000,
        });
        let mut input = main.clone();
        input.extend_from_slice(&[0; 5]);
        let mut d = Codec::Bcj2(params).decoder().unwrap();
        assert_eq!(decode_all(d.as_mut(), &input, 1 << 20).unwrap(), main);

        // A truncated main stream is an error at the end of the input.
        assert!(decode_all(codec.decoder().unwrap().as_mut(), &packed[..0x700], 1 << 20).is_err());
    }
}
