//! RAR decompression: the LZ + Huffman scheme of RAR 2.9/3.x (unrar's
//! `Unpack29`, with PPMd variant H blocks and the standard RarVM filters)
//! and of RAR 5.0/7.0 (`Unpack5`, with its DELTA, E8, E8E9 and ARM
//! filters).
//!
//! Written from knowledge of the unrar sources (no public specification
//! exists, and no RAR compressor was available). Verification:
//!
//! - The PPMd model decodes 7-Zip's own PPMd encoder output byte for byte
//!   (pyppmd, with the 7z range coder; including runs that exhaust the
//!   model's memory).
//! - Everything else is checked on streams written by our test encoder
//!   (`tests/data/rar/rarenc.py`), which libarchive (`bsdtar`, an
//!   independent RAR decoder) also decodes to the same bytes: RAR 5 LZ with
//!   all four filters and solid runs; RAR 2.9 LZ (all symbol kinds,
//!   repeated and delta-coded tables), PPMd blocks and the E8, E8E9,
//!   DELTA, RGB and AUDIO filters (their byte code forged to the standard
//!   programs' length and CRC32, which is all decoders look at).
//! - Not checked against another decoder: RAR 2.9 solid runs and
//!   low-distance repeats across table changes (libarchive supports
//!   neither the way unrar does), the ITANIUM filter, RAR 7.0's larger
//!   distance table. These follow unrar as remembered.
//!
//! A solid group of files is one [`Codec::Rar`](crate::codec::Codec::Rar)
//! stream: its input is the files' packed data concatenated (each file's
//! bit stream starts on its own), its output the files' contents
//! concatenated, each cut to the size its header records. The dictionary,
//! the tables and the repeated distances carry over between files, as in
//! unrar.

mod bits;
mod filters;
mod ppmd;
mod v3;
mod v5;

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::codec::pipeline::{Decoder, Status};
use crate::error::{Diagnostic, Result};

/// The decompression algorithm of a member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// RAR 2.9/3.x (unpack version 29).
    V29,
    /// RAR 5.0 (unpack version 50).
    V50,
    /// RAR 7.0 (larger dictionaries, 80 distance slots).
    V70,
}

/// One file of a (solid) group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub packed: u64,
    pub unpacked: u64,
    pub algorithm: Algorithm,
}

/// A group of files decoded as one stream (one file unless the archive is
/// solid).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// Dictionary size: history kept for back-references.
    pub dict: u64,
    pub members: Arc<[Member]>,
}

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("RAR: {what}"))
}

/// Input bytes kept ahead of the decoder before it decodes a symbol of a
/// member whose data is not all available yet: more than any unit it
/// decodes at once (tables, a filter's byte code, a PPMd escape sequence).
const MARGIN: u64 = 256 * 1024;
/// How far past its recorded size a member may decode looking for its end
/// marker.
const SLACK: u64 = 1 << 20;

/// Unfiltered history: positions count from the start of the group.
#[derive(Default)]
pub(super) struct Window {
    base: u64,
    data: Vec<u8>,
}

impl Window {
    pub fn pos(&self) -> u64 {
        self.base.saturating_add(to_u64(self.data.len()))
    }

    pub fn put(&mut self, b: u8) {
        self.data.push(b);
    }

    /// Copies `len` bytes from `dist` back. Distances before the start of
    /// the stream read zeros (unrar's fresh window); before what is kept
    /// (beyond the dictionary) they are errors.
    pub fn copy(&mut self, dist: u64, len: u64) -> Result<()> {
        let pos = self.pos();
        if dist == 0 {
            return Err(bad("zero match distance"));
        }
        let len_us = to_usize(len);
        if dist > pos {
            // Reads before the stream start.
            for _ in 0..len {
                let at = self.pos().checked_sub(dist);
                let b = match at {
                    Some(a) if a >= self.base => self
                        .data
                        .get(to_usize(a.saturating_sub(self.base)))
                        .copied()
                        .unwrap_or(0),
                    _ => 0,
                };
                self.data.push(b);
            }
            return Ok(());
        }
        let src = pos.saturating_sub(dist);
        if src < self.base {
            return Err(bad("match distance beyond the dictionary"));
        }
        let from = to_usize(src.saturating_sub(self.base));
        if dist >= len {
            let end = from.saturating_add(len_us);
            if end <= self.data.len() {
                self.data.extend_from_within(from..end);
                return Ok(());
            }
        }
        self.data.reserve(len_us);
        for i in 0..len_us {
            let b = self.data.get(from.saturating_add(i)).copied().unwrap_or(0);
            self.data.push(b);
        }
        Ok(())
    }

    /// The bytes at `[start, start + len)` (within what is kept).
    pub fn slice(&self, start: u64, len: u64) -> &[u8] {
        let from = to_usize(start.saturating_sub(self.base));
        self.data
            .get(from..from.saturating_add(to_usize(len)))
            .unwrap_or_default()
    }

    /// Drops history before `keep_from` once that frees enough.
    fn trim(&mut self, keep_from: u64) {
        let n = keep_from.saturating_sub(self.base);
        if n >= (1 << 20) && n >= to_u64(self.data.len()) / 4 {
            self.data.drain(..to_usize(n).min(self.data.len()));
            self.base = keep_from.min(self.pos());
        }
    }
}

/// A filter waiting for its block to be decoded.
#[derive(Clone, Debug)]
pub(super) struct Pending {
    start: u64,
    len: u64,
    kind: filters::Kind,
}

/// The decoder of a [`Params`] group.
pub struct Stream {
    params: Params,
    /// Absolute input offset of `input[0]` (bytes released before it).
    in_base: u64,
    member: usize,
    /// Absolute input offset of the current member's packed data.
    member_in: u64,
    /// Bit position within the current member's packed data.
    bitpos: u64,
    started: bool,
    win: Window,
    /// Window position where the current member's output starts.
    member_start: u64,
    /// Bytes of the current member output so far.
    emitted: u64,
    /// Window position up to which data was output (or skipped).
    written: u64,
    pending: Vec<Pending>,
    v5: v5::State,
    v3: v3::State,
    done: bool,
}

impl Stream {
    pub fn new(params: Params) -> Self {
        Stream {
            params,
            in_base: 0,
            member: 0,
            member_in: 0,
            bitpos: 0,
            started: false,
            win: Window::default(),
            member_start: 0,
            emitted: 0,
            written: 0,
            pending: Vec::new(),
            v5: v5::State::default(),
            v3: v3::State::default(),
            done: false,
        }
    }

    fn current(&self) -> Option<Member> {
        self.params.members.get(self.member).copied()
    }

    /// History to keep: the dictionary, at least 4 MiB.
    fn keep(&self) -> u64 {
        self.params.dict.max(4 << 20)
    }

    /// Outputs what is decoded up to the first pending filter whose block
    /// is incomplete. At the end of a member (`end`), incomplete filters
    /// are dropped and their data output unfiltered.
    fn flush(&mut self, out: &mut Vec<u8>, end: bool, limit: usize) -> Result<()> {
        let pos = self.win.pos();
        while let Some(f) = self.pending.first().cloned() {
            if f.start < self.written {
                // Overlaps what was already output: corrupt, ignored.
                self.pending.remove(0);
                continue;
            }
            if f.start >= pos {
                break;
            }
            self.emit_raw(out, f.start, limit)?;
            let end_at = f.start.saturating_add(f.len);
            if end_at > pos {
                if end {
                    self.pending.clear();
                    break;
                }
                return Ok(());
            }
            let mut data = self.win.slice(f.start, f.len).to_vec();
            let offset = f.start.saturating_sub(self.member_start);
            self.pending.remove(0);
            filters::apply(&f.kind, &mut data, offset)?;
            // RAR 3 applies further filters on the same block to the
            // filtered data.
            while let Some(next) = self.pending.first() {
                if next.start != f.start || next.len != f.len || !next.kind.chains() {
                    break;
                }
                let kind = next.kind.clone();
                self.pending.remove(0);
                filters::apply(&kind, &mut data, offset)?;
            }
            self.emit_bytes(out, &data, limit)?;
            self.written = end_at;
        }
        self.emit_raw(out, pos, limit)?;
        let keep_from = self.written.min(self.win.pos().saturating_sub(self.keep()));
        self.win.trim(keep_from);
        Ok(())
    }

    /// Outputs the window from `written` to `to` unchanged.
    fn emit_raw(&mut self, out: &mut Vec<u8>, to: u64, limit: usize) -> Result<()> {
        if to <= self.written {
            return Ok(());
        }
        let len = to.saturating_sub(self.written);
        let room = self.room(len);
        if room > 0 {
            let data = self.win.slice(self.written, room);
            out.extend_from_slice(data);
            self.emitted = self.emitted.saturating_add(to_u64(data.len()));
        }
        self.written = to;
        check_limit(out, limit)
    }

    fn emit_bytes(&mut self, out: &mut Vec<u8>, data: &[u8], limit: usize) -> Result<()> {
        let room = to_usize(self.room(to_u64(data.len())));
        out.extend_from_slice(data.get(..room).unwrap_or(data));
        self.emitted = self.emitted.saturating_add(to_u64(room));
        check_limit(out, limit)
    }

    /// How many of `len` more bytes still belong to the current member.
    fn room(&self, len: u64) -> u64 {
        let size = self.current().map_or(0, |m| m.unpacked);
        size.saturating_sub(self.emitted).min(len)
    }

    /// Ends the current member and moves to the next.
    fn finish_member(&mut self, out: &mut Vec<u8>, limit: usize) -> Result<()> {
        self.flush(out, true, limit)?;
        self.written = self.win.pos();
        self.pending.clear();
        let m = self.current().ok_or_else(|| bad("no member"))?;
        if self.emitted < m.unpacked {
            return Err(bad(&format!(
                "file {} decoded to {:#x} bytes, expected {:#x}",
                self.member, self.emitted, m.unpacked
            )));
        }
        self.member_in = self.member_in.saturating_add(m.packed);
        self.member = self.member.saturating_add(1);
        self.bitpos = 0;
        self.started = false;
        self.emitted = 0;
        self.member_start = self.win.pos();
        if self.member >= self.params.members.len() {
            self.done = true;
        }
        Ok(())
    }
}

fn check_limit(out: &[u8], limit: usize) -> Result<()> {
    if out.len() > limit {
        Err(Diagnostic::limit(format!(
            "decoded data exceeds {limit:#x} bytes"
        )))
    } else {
        Ok(())
    }
}

/// What a decoding unit reports.
pub(super) enum Unit {
    /// Continue.
    More,
    /// The member's data ended (end marker, last block, or input).
    End,
}

impl Decoder for Stream {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let target = out.len().saturating_add(step);
        let mut work = 0u32;
        let start_len = out.len();
        loop {
            if self.done {
                return Ok(Status::Done);
            }
            let Some(m) = self.current() else {
                self.done = true;
                return Ok(Status::Done);
            };
            if m.unpacked == 0 && m.packed == 0 {
                self.finish_member(out, limit)?;
                continue;
            }
            let avail = self.in_base.saturating_add(to_u64(input.len()));
            let member_end = self.member_in.saturating_add(m.packed);
            let here = self.member_in.saturating_add(self.bitpos >> 3);
            if avail < member_end && !eof && here.saturating_add(MARGIN) > avail {
                return Ok(if out.len() > start_len {
                    Status::More
                } else {
                    Status::NeedInput
                });
            }
            let from = self.member_in.max(self.in_base);
            let skipped = from.saturating_sub(self.member_in);
            let from = to_usize(from.saturating_sub(self.in_base));
            let to = to_usize(member_end.min(avail).saturating_sub(self.in_base));
            let data = input.get(from..to).unwrap_or_default();
            let data = bits::Bits {
                data,
                base: skipped,
                pos: self.bitpos,
            };
            // Decode a batch of symbols, then output what is final.
            let batch_end = if avail >= member_end || eof {
                u64::MAX
            } else {
                avail.saturating_sub(MARGIN)
            };
            let stop = batch_end.saturating_sub(self.member_in);
            let unit = match m.algorithm {
                Algorithm::V50 | Algorithm::V70 => self.run5(data, m, stop)?,
                Algorithm::V29 => self.run3(data, stop)?,
            };
            match unit {
                Unit::End => {
                    if avail < member_end
                        && eof
                        && self.bitpos
                            >= member_end
                                .min(avail)
                                .saturating_sub(self.member_in)
                                .saturating_mul(8)
                    {
                        self.flush(out, true, limit)?;
                        return Err(bad("packed data ends early"));
                    }
                    self.finish_member(out, limit)?;
                }
                Unit::More => {
                    self.flush(out, false, limit)?;
                    if self.win.pos().saturating_sub(self.member_start)
                        > m.unpacked.saturating_add(SLACK)
                    {
                        return Err(bad("file data runs past its recorded size"));
                    }
                }
            }
            work = work.saturating_add(1);
            if out.len() >= target || work >= 64 {
                return Ok(Status::More);
            }
        }
    }

    fn consumed(&self) -> usize {
        to_usize(
            self.member_in
                .saturating_add(self.bitpos.saturating_add(7) >> 3),
        )
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    fn releasable_input(&self) -> usize {
        let here = self.member_in.saturating_add(self.bitpos >> 3);
        to_usize(here.saturating_sub(self.in_base))
    }

    fn release_input(&mut self, n: usize) {
        self.in_base = self.in_base.saturating_add(to_u64(n));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Matches read the decoder's own window, never `out`.
        out_len
    }
}

/// Symbols per batch between output flushes.
pub(super) const BATCH: u32 = 32 * 1024;

#[cfg(test)]
mod tests;
