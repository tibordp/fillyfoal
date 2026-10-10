//! The `.xz` container: streams of blocks, each decoded through its filter
//! chain (LZMA2, optionally preceded by BCJ or Delta), with integrity
//! checks.
//!
//! [`XzStream`] decodes on demand, a unit at a time: a stream header, a
//! block header, some of a block's LZMA2 data (a block is usually the whole
//! file, and an LZMA2 chunk can hold 2 MiB, so it decodes symbol by symbol
//! as [`Lzma2`] does), a block's check, an index with the stream footer, or
//! stream padding. Each unit starts only once all the input it can need has
//! arrived, so nothing is ever rolled back and the decoder is never
//! cloned. Block checks (CRC-32, CRC-64, SHA-256) are
//! computed as the output appears and compared at the end of each block.
//!
//! A block without BCJ or Delta filters decodes straight into `out`, which
//! is then also the LZMA2 dictionary. A block with them needs the
//! *unfiltered* bytes as its dictionary while `out` must only ever show
//! filtered ones, so it decodes into a private window that keeps the last
//! dictionary-size bytes (compacted once it holds twice that, or the
//! dictionary plus 32 KiB), and passes each chunk's new bytes through the
//! filters, which hold back the few bytes they cannot settle yet (see
//! [`PostState`]). Memory for such blocks is up to twice the dictionary
//! size on top of the output.

pub use crate::codec::crc::crc64;
use crate::codec::crc::{CRC32, CRC64_XZ};
use crate::codec::crypto::{Hash, Sha256};
use crate::codec::filters::Filter;
use crate::codec::lzma::{Chunk, Lzma2, Post, PostState, View};
use crate::codec::pipeline::{Decoder, Status};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("xz: {what}"))
}

/// `Ok(pending)` before the end of the input, else the error.
fn wait<T>(eof: bool, what: &str, pending: T) -> Result<T> {
    if eof { Err(bad(what)) } else { Ok(pending) }
}

const MAGIC: &[u8; 6] = b"\xfd7zXZ\0";

/// A multibyte integer (7 bits per byte, little-endian groups).
fn varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    // At most nine bytes (63 bits).
    let rest = data.get(*pos..).unwrap_or_default();
    let (v, n) = crate::bytes::uleb128(rest.get(..9).unwrap_or(rest)).ok_or_else(|| {
        bad(if rest.len() < 9 {
            "truncated integer"
        } else {
            "integer too long"
        })
    })?;
    *pos = pos.saturating_add(n);
    Ok(v)
}

/// Rounds input position `pos` up to a multiple of four in the file, whose
/// first `phase` (modulo 4) bytes were released.
fn align4(pos: usize, phase: usize) -> usize {
    let r = pos.wrapping_add(phase) & 3;
    pos.saturating_add(4usize.wrapping_sub(r) & 3)
}

/// The LZMA2 dictionary size from its property byte.
fn dict_size(b: u8) -> usize {
    if b >= 40 {
        usize::try_from(u32::MAX).unwrap_or(usize::MAX)
    } else {
        usize::from(2 | (b & 1)) << (b / 2).wrapping_add(11)
    }
}

/// A block check being computed.
#[derive(Clone)]
enum Check {
    /// None, or a kind that is not verified.
    None,
    Crc32(u64),
    Crc64(u64),
    Sha256(Sha256),
}

impl Check {
    fn new(id: u8) -> Self {
        match id {
            1 => Check::Crc32(CRC32.init()),
            4 => Check::Crc64(CRC64_XZ.init()),
            10 => Check::Sha256(Sha256::new()),
            _ => Check::None,
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Check::None => {}
            Check::Crc32(c) => *c = CRC32.update(*c, data),
            Check::Crc64(c) => *c = CRC64_XZ.update(*c, data),
            Check::Sha256(h) => h.update(data),
        }
    }

    fn matches(&self, stored: &[u8]) -> bool {
        match self {
            Check::None => true,
            Check::Crc32(c) => {
                u32::try_from(CRC32.finish(*c))
                    .unwrap_or(0)
                    .to_le_bytes()
                    .as_slice()
                    == stored
            }
            Check::Crc64(c) => CRC64_XZ.finish(*c).to_le_bytes().as_slice() == stored,
            Check::Sha256(h) => h.clone().finish().as_slice() == stored,
        }
    }
}

/// The unfiltered side of a block with BCJ or Delta filters.
struct Filtered {
    /// The latest unfiltered output: the LZMA2 dictionary.
    window: Vec<u8>,
    /// Bytes dropped from the front of `window`.
    dropped: usize,
    /// Bytes of history to keep: the dictionary size.
    keep: usize,
    /// The filters in the order they apply, each with the bytes it holds
    /// back.
    stages: Vec<(PostState, Vec<u8>)>,
}

impl Filtered {
    /// Runs fresh unfiltered bytes through the filters; returns those now
    /// final.
    fn feed(&mut self, mut data: Vec<u8>, eof: bool) -> Vec<u8> {
        for (filter, pending) in &mut self.stages {
            pending.extend_from_slice(&data);
            let n = filter.run(pending, eof);
            data = pending.drain(..n).collect();
        }
        data
    }

    fn compact(&mut self) {
        if self.window.len() > self.keep.saturating_add(self.keep.max(1 << 15)) {
            let cut = self.window.len().saturating_sub(self.keep);
            self.window.drain(..cut);
            self.dropped = self.dropped.saturating_add(cut);
        }
    }
}

/// A block being decoded.
struct Block {
    /// Where its compressed data starts in the input.
    data_start: usize,
    /// The compressed size, if the header records it.
    packed: Option<usize>,
    lzma2: Lzma2,
    /// Where its output is in `out` (its start, and output released since).
    view: View,
    /// The LZMA2 dictionary size: how far back unfiltered output is read.
    dict: usize,
    check: Check,
    check_len: usize,
    filtered: Option<Box<Filtered>>,
}

enum Unit {
    Progress,
    NeedInput,
    Done,
}

enum BlockStep {
    Progress,
    NeedInput,
    /// The block (and its check) ends at this input position.
    End(usize),
}

impl Block {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        stop: usize,
        limit: usize,
        phase: usize,
    ) -> Result<BlockStep> {
        let data_end = self.packed.map(|n| self.data_start.saturating_add(n));
        if !self.lzma2.done() {
            let avail = data_end.map_or(input.len(), |e| e.min(input.len()));
            let data = input.get(self.data_start..avail).unwrap_or_default();
            let data_eof = eof || data_end.is_some_and(|e| e <= input.len());
            let chunk = match self.filtered.as_mut() {
                None => {
                    let mark = out.len();
                    let chunk = self
                        .lzma2
                        .step(data, data_eof, out, self.view, stop, limit)?;
                    self.check.update(out.get(mark..).unwrap_or_default());
                    chunk
                }
                Some(f) => {
                    let mark = f.window.len();
                    let view = View {
                        start: 0,
                        dropped: f.dropped,
                    };
                    // `limit` bounds `out`, which has released
                    // `view.dropped` bytes of this block.
                    let room = limit
                        .saturating_add(self.view.dropped)
                        .saturating_sub(self.view.start)
                        .saturating_sub(f.dropped);
                    let wstop = mark.saturating_add(stop.saturating_sub(out.len()));
                    let chunk =
                        self.lzma2
                            .step(data, data_eof, &mut f.window, view, wstop, room)?;
                    let fresh = f.window.get(mark..).unwrap_or_default().to_vec();
                    let filtered = f.feed(fresh, chunk == Chunk::End);
                    self.check.update(&filtered);
                    out.extend_from_slice(&filtered);
                    f.compact();
                    chunk
                }
            };
            return Ok(if chunk == Chunk::NeedInput {
                BlockStep::NeedInput
            } else {
                BlockStep::Progress
            });
        }
        // Block padding to a multiple of four, then the check.
        let end = data_end.unwrap_or(self.data_start.saturating_add(self.lzma2.consumed()));
        if input.len() < end {
            return wait(eof, "truncated block data", BlockStep::NeedInput);
        }
        let end = align4(end, phase);
        let Some(stored) = input.get(end..end.saturating_add(self.check_len)) else {
            return wait(eof, "truncated check", BlockStep::NeedInput);
        };
        if !self.check.matches(stored) {
            return Err(bad("block check mismatch"));
        }
        Ok(BlockStep::End(end.saturating_add(self.check_len)))
    }
}

/// An `.xz` file (one or more streams, with stream padding between them) as
/// a [`Decoder`].
#[derive(Default)]
pub struct XzStream {
    /// Input consumed (up to the current block's data).
    pos: usize,
    /// The input length last seen.
    seen: usize,
    streams: u32,
    /// Inside a stream (after its header, before its index).
    in_stream: bool,
    check_id: u8,
    check_len: usize,
    block: Option<Box<Block>>,
    done: bool,
    /// Input released so far, modulo 4 (padding aligns to file offsets).
    phase: usize,
}

impl XzStream {
    fn unit(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        stop: usize,
        limit: usize,
    ) -> Result<Unit> {
        if self.done {
            return Ok(Unit::Done);
        }
        if !self.in_stream {
            return self.stream_header(input, eof);
        }
        if let Some(block) = self.block.as_mut() {
            return Ok(
                match block.step(input, eof, out, stop, limit, self.phase)? {
                    BlockStep::Progress => Unit::Progress,
                    BlockStep::NeedInput => Unit::NeedInput,
                    BlockStep::End(end) => {
                        self.pos = end;
                        self.block = None;
                        Unit::Progress
                    }
                },
            );
        }
        let Some(&size_byte) = input.get(self.pos) else {
            return wait(eof, "truncated block", Unit::NeedInput);
        };
        if size_byte == 0 {
            return self.index(input, eof);
        }
        let header_len = (usize::from(size_byte).saturating_add(1)).saturating_mul(4);
        let Some(header) = input.get(self.pos..self.pos.saturating_add(header_len)) else {
            return wait(eof, "truncated block header", Unit::NeedInput);
        };
        let flags = header.get(1).copied().unwrap_or(0);
        let mut hp = 2usize;
        let packed = if flags & 0x40 != 0 {
            Some(varint(header, &mut hp)?)
        } else {
            None
        };
        if flags & 0x80 != 0 {
            varint(header, &mut hp)?;
        }
        let filters = usize::from(flags & 3).saturating_add(1);
        let mut posts = Vec::new();
        let mut dict = None;
        for _ in 0..filters {
            let id = varint(header, &mut hp)?;
            let props_len = usize::try_from(varint(header, &mut hp)?).unwrap_or(usize::MAX);
            let props = header
                .get(hp..hp.saturating_add(props_len))
                .ok_or_else(|| bad("truncated filter properties"))?;
            hp = hp.saturating_add(props_len);
            match id {
                0x21 => dict = Some(dict_size(props.first().copied().unwrap_or(0))),
                0x03 => posts.push(Post::Delta(
                    usize::from(props.first().copied().unwrap_or(0)).saturating_add(1),
                )),
                0x04 => posts.push(Post::X86),
                0x07 => posts.push(Post::Arm),
                0x0a => posts.push(Post::Arm64),
                other => return Err(Diagnostic::unsupported(format!("xz filter {other:#x}"))),
            }
        }
        let Some(dict) = dict else {
            return Err(Diagnostic::unsupported("xz block without LZMA2"));
        };
        // Filters listed before LZMA2 apply after it, last first.
        let filtered = (!posts.is_empty()).then(|| {
            Box::new(Filtered {
                window: Vec::new(),
                dropped: 0,
                keep: dict.max(4096),
                stages: posts
                    .iter()
                    .rev()
                    .map(|&p| (PostState::new(p), Vec::new()))
                    .collect(),
            })
        });
        self.pos = self.pos.saturating_add(header_len);
        self.block = Some(Box::new(Block {
            data_start: self.pos,
            packed: packed.map(|n| usize::try_from(n).unwrap_or(usize::MAX)),
            lzma2: Lzma2::default(),
            view: View {
                start: out.len(),
                dropped: 0,
            },
            dict,
            check: Check::new(self.check_id),
            check_len: self.check_len,
            filtered,
        }));
        Ok(Unit::Progress)
    }

    /// Stream padding (between streams), then a stream header, or the end.
    fn stream_header(&mut self, input: &[u8], eof: bool) -> Result<Unit> {
        if self.streams > 0 {
            loop {
                let rest = input.get(self.pos..).unwrap_or_default();
                if rest.get(..4) == Some(&[0, 0, 0, 0][..]) {
                    self.pos = self.pos.saturating_add(4);
                } else if !eof && rest.len() < 4 && rest.iter().all(|&b| b == 0) {
                    return Ok(Unit::NeedInput);
                } else {
                    break;
                }
            }
        }
        let rest = input.get(self.pos..).unwrap_or_default();
        let head = rest.get(..6).unwrap_or(rest);
        if !eof && head.len() < 6 && MAGIC.starts_with(head) {
            return Ok(Unit::NeedInput);
        }
        if head != MAGIC {
            if self.streams == 0 {
                return Err(bad("not an xz stream"));
            }
            self.done = true;
            return Ok(Unit::Done);
        }
        if !eof && rest.len() < 12 {
            return Ok(Unit::NeedInput);
        }
        self.check_id = rest.get(7).copied().unwrap_or(0) & 0x0f;
        self.check_len = match self.check_id {
            0 => 0,
            1 => 4,
            4 => 8,
            10 => 32,
            c => 4usize << ((usize::from(c).saturating_sub(1)) / 3),
        };
        self.pos = self.pos.saturating_add(12);
        self.streams = self.streams.saturating_add(1);
        self.in_stream = true;
        Ok(Unit::Progress)
    }

    /// The index (records, padding, CRC-32) and the 12-byte stream footer.
    fn index(&mut self, input: &[u8], eof: bool) -> Result<Unit> {
        let mut ip = self.pos.saturating_add(1);
        let phase = self.phase;
        let parsed = (|| {
            let records = varint(input, &mut ip)?;
            for _ in 0..records.min(1 << 24) {
                varint(input, &mut ip)?;
                varint(input, &mut ip)?;
            }
            Ok::<_, Diagnostic>(align4(ip, phase).saturating_add(4).saturating_add(12))
        })();
        let end = match parsed {
            Ok(end) => end,
            Err(_) if !eof => return Ok(Unit::NeedInput),
            Err(e) => return Err(e),
        };
        if !eof && input.len() < end {
            return Ok(Unit::NeedInput);
        }
        self.pos = end;
        self.in_stream = false;
        Ok(Unit::Progress)
    }
}

impl Decoder for XzStream {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        self.seen = input.len();
        let mark = out.len();
        let target = mark.saturating_add(step.max(1));
        loop {
            if out.len() >= target {
                return Ok(Status::More);
            }
            match self.unit(input, eof, out, target, limit)? {
                Unit::Progress => {}
                Unit::NeedInput if out.len() > mark => return Ok(Status::More),
                Unit::NeedInput => return Ok(Status::NeedInput),
                Unit::Done => return Ok(Status::Done),
            }
        }
    }

    fn consumed(&self) -> usize {
        let pos = match &self.block {
            Some(b) => b.data_start.saturating_add(b.lzma2.consumed()),
            None => self.pos,
        };
        pos.min(self.seen)
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    /// Everything consumed: headers and indexes are parsed once whole, and
    /// a block reads only past its LZMA2 data.
    fn releasable_input(&self) -> usize {
        self.consumed()
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        self.seen = self.seen.saturating_sub(n);
        self.phase = self.phase.wrapping_add(n) & 3;
        if let Some(b) = self.block.as_mut() {
            let before = n.min(b.data_start);
            let within = n.saturating_sub(before);
            b.data_start = b.data_start.saturating_sub(before);
            b.lzma2.release_input(within);
            b.packed = b.packed.map(|p| p.saturating_sub(within));
        }
    }

    /// Output before the current block's dictionary. Each block starts a
    /// new dictionary, and a filtered block's dictionary is a private
    /// window, so everything else can go.
    fn releasable_output(&self, out_len: usize) -> usize {
        match self.block.as_deref() {
            Some(b) if b.filtered.is_none() && !b.lzma2.done() => out_len
                .saturating_sub(b.dict)
                .max(b.lzma2.dict_start(b.view))
                .min(out_len),
            _ => out_len,
        }
    }

    fn release_output(&mut self, n: usize) {
        if let Some(b) = self.block.as_mut() {
            b.view.dropped = b.view.dropped.saturating_add(n);
        }
    }
}

/// A whole `.xz` file in memory (for containers that hold small ones).
#[derive(Clone, Copy)]
pub struct Xz;

impl Filter for Xz {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        crate::codec::pipeline::decode_all(&mut XzStream::default(), input, limit)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn crc64_check_value() {
        assert_eq!(crc64(b"123456789"), 0x995d_c9bb_df19_39fa);
    }
}
