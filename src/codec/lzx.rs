//! LZX, as in Microsoft cabinets, Compiled HTML Help and WIM images.
//!
//! LZ77 over a window of 2^15..2^21 bytes with canonical Huffman codes,
//! modelled on libmspack's `lzxd.c` (and, for the WIM variant, wimlib).
//! The bitstream is a sequence of little-endian 16-bit words read MSB
//! first. Output comes in frames of 32 KiB; the input is realigned to a
//! word boundary after every frame, and frames are where the CHM variant
//! resets its state and where Intel E8 call translation is undone.
//!
//! Blocks are verbatim (main and length trees), aligned (plus an aligned
//! offset tree for the low three offset bits) or uncompressed (realigned,
//! the three repeated offsets as 32-bit integers, raw bytes, a pad byte
//! after an odd length). Tree lengths are sent as deltas against the
//! previous block's, through a 20-symbol pretree.
//!
//! Parameters ([`Params`]):
//! - `window_bits`: log2 of the window (15..=21). CAB: bits 8..12 of the
//!   folder's compression type. CHM: from the LZXC control data. WIM: 15.
//! - `reset_interval`: frames (32 KiB each) between resets of the Huffman
//!   lengths, repeated offsets and E8 header, 0 for none. CHM: the LZXC
//!   reset interval divided by 32 KiB. CAB: 0. E8 positions count from the
//!   last reset (as 7-Zip decodes CHM; libmspack counts from the start of
//!   the stream, which only differs for CHM files that use E8 translation).
//! - `variant`: [`Variant::Cab`] (CAB and CHM: 24-bit block sizes; after
//!   each reset a header bit, and if set a 32-bit translation size,
//!   enables E8 translation) or [`Variant::Wim`] (block sizes are a
//!   "32 KiB" bit or 16 bits (24 for windows of 64 KiB and more); no
//!   header, translation always on with the given size, 12 000 000 for
//!   WIM). A WIM resource is decoded chunk by chunk, each chunk (32 KiB of
//!   output) being its own stream.
//! - `len`: the decoded size if known (it sizes the last frame);
//!   otherwise the stream ends where the input does.

use crate::codec::pipeline::{Decoder, Status};
use crate::error::{Diagnostic, Result};

/// Output bytes per frame.
pub const FRAME: usize = 32 * 1024;
const MAX_BITS: usize = 16;
const PRETREE: usize = 20;
const LENGTHS: usize = 249;
const MAIN_MAX: usize = 256 + 50 * 8;
/// E8 translation only applies to the first 1 GiB.
const E8_LIMIT: u64 = 1 << 30;

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("LZX: {what}"))
}

/// How blocks and E8 translation are signalled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Variant {
    /// CAB and CHM: 24-bit block sizes; an E8 header after each reset.
    Cab,
    /// WIM: short block sizes; no header, E8 translation always on with
    /// this translation size (12 000 000 in WIM).
    Wim { e8_size: u32 },
}

/// Parameters of an LZX stream (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Params {
    pub window_bits: u8,
    pub reset_interval: u32,
    pub variant: Variant,
    pub len: Option<u64>,
}

impl Params {
    /// CAB folders: no resets, E8 header at the start.
    pub fn cab(window_bits: u8) -> Self {
        Params {
            window_bits,
            reset_interval: 0,
            variant: Variant::Cab,
            len: None,
        }
    }

    /// One WIM chunk (window 2^15, E8 size 12 000 000) of `len` bytes.
    pub fn wim_chunk(len: u64) -> Self {
        Params {
            window_bits: 15,
            reset_interval: 0,
            variant: Variant::Wim {
                e8_size: 12_000_000,
            },
            len: Some(len),
        }
    }
}

/// Number of position slots for a window size.
fn position_slots(window_bits: u8) -> Option<usize> {
    Some(match window_bits {
        15 => 30,
        16 => 32,
        17 => 34,
        18 => 36,
        19 => 38,
        20 => 42,
        21 => 50,
        _ => return None,
    })
}

/// `(extra bits, position base)` per position slot (libmspack's tables).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn slot_tables() -> ([u8; 51], [u32; 51]) {
    let mut extra = [0u8; 51];
    let mut base = [0u32; 51];
    let mut i = 0;
    let mut j = 0u8;
    while i < 50 {
        extra[i] = j;
        extra[i + 1] = j;
        if i != 0 && j < 17 {
            j += 1;
        }
        i += 2;
    }
    let mut i = 0;
    let mut b = 0u32;
    while i < 51 {
        base[i] = b;
        b += 1 << extra[i];
        i += 1;
    }
    (extra, base)
}

const SLOTS: ([u8; 51], [u32; 51]) = slot_tables();

/// A canonical Huffman code, decoded MSB first one bit at a time.
#[derive(Clone, Debug, Default)]
struct Huffman {
    counts: [u16; MAX_BITS + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self> {
        let mut counts = [0u16; MAX_BITS + 1];
        for &len in lengths {
            let slot = counts
                .get_mut(usize::from(len))
                .ok_or_else(|| bad("code length above 16"))?;
            *slot = slot.saturating_add(1);
        }
        let mut left: i32 = 1;
        for len in 1..=MAX_BITS {
            left = left.saturating_mul(2);
            left = left.saturating_sub(i32::from(counts.get(len).copied().unwrap_or(0)));
            if left < 0 {
                return Err(bad("over-subscribed Huffman code"));
            }
        }
        let mut offsets = [0u16; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            let next = offsets
                .get(len)
                .copied()
                .unwrap_or(0)
                .saturating_add(counts.get(len).copied().unwrap_or(0));
            if let Some(o) = offsets.get_mut(len.saturating_add(1)) {
                *o = next;
            }
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            if let Some(o) = offsets.get_mut(usize::from(len)) {
                if let Some(slot) = symbols.get_mut(usize::from(*o)) {
                    *slot = u16::try_from(symbol).unwrap_or(u16::MAX);
                }
                *o = o.saturating_add(1);
            }
        }
        Ok(Huffman { counts, symbols })
    }
}

/// The LZX bit reader: little-endian 16-bit words, MSB first. At the end
/// of the input (once it is known to be the end) two zero bytes may be
/// read, as libmspack allows.
#[derive(Clone, Debug, Default)]
struct Bits {
    /// Next input byte.
    pos: usize,
    buf: u64,
    left: u32,
}

impl Bits {
    fn need(&mut self, input: &[u8], eof: bool, n: u32) -> Result<()> {
        while self.left < n {
            let word = match (input.get(self.pos), input.get(self.pos.saturating_add(1))) {
                (Some(&lo), Some(&hi)) => u16::from_le_bytes([lo, hi]),
                (lo, _) if eof && self.pos < input.len().saturating_add(2) => {
                    u16::from(lo.copied().unwrap_or(0))
                }
                _ => return Err(bad("input ends unexpectedly")),
            };
            self.buf |= u64::from(word) << 48u32.saturating_sub(self.left);
            self.left = self.left.saturating_add(16);
            self.pos = self.pos.saturating_add(2);
        }
        Ok(())
    }

    fn read(&mut self, input: &[u8], eof: bool, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        self.need(input, eof, n)?;
        let v = u32::try_from(self.buf >> 64u32.saturating_sub(n)).unwrap_or(0);
        self.buf = self.buf.checked_shl(n).unwrap_or(0);
        self.left = self.left.saturating_sub(n);
        Ok(v)
    }

    fn decode(&mut self, input: &[u8], eof: bool, h: &Huffman) -> Result<usize> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAX_BITS {
            code |= i32::try_from(self.read(input, eof, 1)?).unwrap_or(0);
            let count = i32::from(h.counts.get(len).copied().unwrap_or(0));
            if code.saturating_sub(first) < count {
                let at = index.saturating_add(code).saturating_sub(first);
                return usize::try_from(at)
                    .ok()
                    .and_then(|at| h.symbols.get(at).copied())
                    .map(usize::from)
                    .ok_or_else(|| bad("invalid Huffman code"));
            }
            index = index.saturating_add(count);
            first = first.saturating_add(count).saturating_mul(2);
            code = code.saturating_mul(2);
        }
        Err(bad("invalid Huffman code"))
    }

    /// Drops the bits left of the current word (aligns to 16 bits).
    fn align(&mut self) {
        self.buf = 0;
        self.left = 0;
    }

    /// Bits not yet read, counting the input as ending here.
    fn remaining(&self, input: &[u8]) -> usize {
        input
            .len()
            .saturating_sub(self.pos)
            .saturating_mul(8)
            .saturating_add(usize::try_from(self.left).unwrap_or(0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Block {
    None,
    Verbatim,
    Aligned,
    Uncompressed,
}

/// Decoder state small enough to snapshot per frame (the history lives in
/// [`Lzx::hist`]).
#[derive(Clone, Debug)]
struct State {
    bits: Bits,
    main_len: Vec<u8>,
    length_len: Vec<u8>,
    main: Huffman,
    length: Huffman,
    aligned: Huffman,
    r: [u32; 3],
    block: Block,
    block_len: u32,
    block_remaining: u32,
    header_read: bool,
    e8_size: u32,
    /// Where the last reset happened (E8 positions count from there).
    reset_offset: u64,
    /// Frames decoded.
    frame: u64,
    /// Bytes decoded.
    offset: u64,
    done: bool,
}

/// Decoder state saved before a frame.
#[derive(Clone, Debug)]
pub struct Snapshot {
    st: State,
    hist: usize,
}

/// An LZX decoder core: decodes one frame at a time from a buffer holding
/// the whole stream so far.
#[derive(Clone, Debug)]
pub struct Lzx {
    params: Params,
    main_symbols: usize,
    st: State,
    /// Untranslated output; at least the last window's worth.
    hist: Vec<u8>,
}

impl Lzx {
    pub fn new(params: Params) -> Result<Self> {
        let slots =
            position_slots(params.window_bits).ok_or_else(|| bad("window size out of range"))?;
        let main_symbols = 256usize.saturating_add(slots.saturating_mul(8));
        Ok(Lzx {
            params,
            main_symbols,
            st: State {
                bits: Bits::default(),
                main_len: vec![0; MAIN_MAX],
                length_len: vec![0; LENGTHS],
                main: Huffman::default(),
                length: Huffman::default(),
                aligned: Huffman::default(),
                r: [1; 3],
                block: Block::None,
                block_len: 0,
                block_remaining: 0,
                header_read: false,
                e8_size: 0,
                reset_offset: 0,
                frame: 0,
                offset: 0,
                done: false,
            },
            hist: Vec::new(),
        })
    }

    fn window(&self) -> usize {
        1usize << self.params.window_bits.min(21)
    }

    /// Bytes of input consumed.
    pub fn consumed(&self) -> usize {
        self.st.bits.pos
    }

    /// The first `n` (at most [`Lzx::consumed`]) input bytes were dropped
    /// (between frames). Bits already read stay buffered.
    pub fn release_input(&mut self, n: usize) {
        self.st.bits.pos = self.st.bits.pos.saturating_sub(n);
    }

    /// Whether the stream has ended (only when its length is unknown).
    pub fn done(&self) -> bool {
        self.st.done
    }

    /// Bytes decoded so far.
    pub fn offset(&self) -> u64 {
        self.st.offset
    }

    /// Saves the state before a frame (see [`Lzx::restore`]).
    pub fn snapshot(&mut self) -> Snapshot {
        let window = self.window();
        if self.hist.len() > window.saturating_mul(2) {
            let drop = self.hist.len().saturating_sub(window);
            self.hist.drain(..drop);
        }
        Snapshot {
            st: self.st.clone(),
            hist: self.hist.len(),
        }
    }

    /// Rolls back to a snapshot (after a frame failed for lack of input).
    pub fn restore(&mut self, snapshot: Snapshot) {
        self.st = snapshot.st;
        self.hist.truncate(snapshot.hist);
    }

    fn reset(&mut self) -> Result<()> {
        if self.st.block_remaining != 0 {
            return Err(bad("block continues across a reset"));
        }
        self.st.r = [1; 3];
        self.st.reset_offset = self.st.offset;
        self.st.header_read = false;
        self.st.block = Block::None;
        self.st.main_len.iter_mut().for_each(|l| *l = 0);
        self.st.length_len.iter_mut().for_each(|l| *l = 0);
        Ok(())
    }

    /// Reads tree lengths `first..last` of `lens` as deltas, through a
    /// pretree.
    fn read_lengths(
        st: &mut State,
        input: &[u8],
        eof: bool,
        which: bool,
        first: usize,
        last: usize,
    ) -> Result<()> {
        let mut pre = [0u8; PRETREE];
        for p in &mut pre {
            *p = u8::try_from(st.bits.read(input, eof, 4)?).unwrap_or(0);
        }
        let pretree = Huffman::new(&pre)?;
        let lens = if which {
            &mut st.main_len
        } else {
            &mut st.length_len
        };
        let mut x = first;
        let delta = |old: u8, z: usize| -> u8 {
            let z = u8::try_from(z).unwrap_or(0);
            if old >= z {
                old.saturating_sub(z)
            } else {
                old.saturating_add(17).saturating_sub(z)
            }
        };
        while x < last {
            let z = st.bits.decode(input, eof, &pretree)?;
            let (value, run) = match z {
                17 => (Some(0), st.bits.read(input, eof, 4)?.saturating_add(4)),
                18 => (Some(0), st.bits.read(input, eof, 5)?.saturating_add(20)),
                19 => {
                    let run = st.bits.read(input, eof, 1)?.saturating_add(4);
                    let z = st.bits.decode(input, eof, &pretree)?;
                    if z > 16 {
                        return Err(bad("invalid pretree run"));
                    }
                    (Some(delta(lens.get(x).copied().unwrap_or(0), z)), run)
                }
                _ => (None, 1),
            };
            for _ in 0..run {
                // Runs may spill past `last` (into the next range), as in
                // libmspack; they stop at the end of the table.
                if let Some(slot) = lens.get_mut(x) {
                    *slot = value.unwrap_or_else(|| delta(*slot, z));
                }
                x = x.saturating_add(1);
            }
        }
        Ok(())
    }

    fn block_header(&mut self, input: &[u8], eof: bool) -> Result<()> {
        let st = &mut self.st;
        if st.block == Block::Uncompressed && st.block_len & 1 != 0 {
            // The pad byte after an odd-sized uncompressed block.
            st.bits.pos = st.bits.pos.saturating_add(1);
        }
        let kind = st.bits.read(input, eof, 3)?;
        let size = match self.params.variant {
            Variant::Cab => {
                let hi = st.bits.read(input, eof, 16)?;
                let lo = st.bits.read(input, eof, 8)?;
                hi << 8 | lo
            }
            Variant::Wim { .. } => {
                if st.bits.read(input, eof, 1)? == 1 {
                    32768
                } else {
                    let mut s = st.bits.read(input, eof, 16)?;
                    if self.params.window_bits >= 16 {
                        s = s << 8 | st.bits.read(input, eof, 8)?;
                    }
                    s
                }
            }
        };
        st.block_len = size;
        st.block_remaining = size;
        st.block = match kind {
            1 => Block::Verbatim,
            2 => Block::Aligned,
            3 => Block::Uncompressed,
            _ => return Err(bad("invalid block type")),
        };
        match st.block {
            Block::Aligned | Block::Verbatim => {
                if st.block == Block::Aligned {
                    let mut lens = [0u8; 8];
                    for l in &mut lens {
                        *l = u8::try_from(st.bits.read(input, eof, 3)?).unwrap_or(0);
                    }
                    st.aligned = Huffman::new(&lens)?;
                }
                Self::read_lengths(st, input, eof, true, 0, 256)?;
                Self::read_lengths(st, input, eof, true, 256, self.main_symbols)?;
                st.main = Huffman::new(st.main_len.get(..self.main_symbols).unwrap_or_default())?;
                Self::read_lengths(st, input, eof, false, 0, LENGTHS)?;
                st.length = Huffman::new(&st.length_len)?;
            }
            Block::Uncompressed => {
                // Realign: 1..16 bits (a whole word if already aligned).
                if st.bits.left == 0 {
                    st.bits.need(input, eof, 16)?;
                }
                st.bits.align();
                for r in &mut st.r {
                    *r = crate::bytes::u32_le(input, st.bits.pos)
                        .ok_or_else(|| bad("input ends unexpectedly"))?;
                    st.bits.pos = st.bits.pos.saturating_add(4);
                }
            }
            Block::None => {}
        }
        Ok(())
    }

    /// Decodes up to `todo` bytes of the current block into `hist`.
    /// `frame_start`: where the current frame starts in `hist`.
    fn run(&mut self, input: &[u8], eof: bool, todo: usize, frame_start: usize) -> Result<()> {
        let window = self.window();
        let st = &mut self.st;
        if st.block == Block::Uncompressed {
            let start = st.bits.pos;
            let bytes = start
                .checked_add(todo)
                .and_then(|end| input.get(start..end))
                .ok_or_else(|| bad("input ends inside an uncompressed block"))?;
            self.hist.extend_from_slice(bytes);
            st.bits.pos = start.saturating_add(todo);
            return Ok(());
        }
        let aligned = st.block == Block::Aligned;
        let (extra_bits, base) = (&SLOTS.0, &SLOTS.1);
        let mut left = todo;
        let start_offset = st.offset;
        while left > 0 {
            let sym = st.bits.decode(input, eof, &st.main)?;
            if sym < 256 {
                self.hist.push(u8::try_from(sym).unwrap_or(0));
                left = left.saturating_sub(1);
                continue;
            }
            let element = sym.saturating_sub(256);
            let mut length = element & 7;
            if length == 7 {
                length = length.saturating_add(st.bits.decode(input, eof, &st.length)?);
            }
            length = length.saturating_add(2);
            let slot = element >> 3;
            let offset = match slot {
                0 => st.r[0],
                1 => {
                    st.r.swap(0, 1);
                    st.r[0]
                }
                2 => {
                    st.r.swap(0, 2);
                    st.r[0]
                }
                _ => {
                    let extra = u32::from(extra_bits.get(slot).copied().unwrap_or(17));
                    let mut off = base.get(slot).copied().unwrap_or(0).saturating_sub(2);
                    if aligned && extra >= 3 {
                        let verbatim = st.bits.read(input, eof, extra.saturating_sub(3))?;
                        off = off.saturating_add(verbatim << 3);
                        let low = st.bits.decode(input, eof, &st.aligned)?;
                        off = off.saturating_add(u32::try_from(low).unwrap_or(0));
                    } else {
                        off = off.saturating_add(st.bits.read(input, eof, extra)?);
                    }
                    st.r = [off, st.r[0], st.r[1]];
                    off
                }
            };
            if length > left {
                return Err(bad("match crosses a block or frame boundary"));
            }
            let distance = usize::try_from(offset).unwrap_or(usize::MAX);
            let produced = self.hist.len().saturating_sub(frame_start);
            let available = usize::try_from(start_offset)
                .unwrap_or(usize::MAX)
                .saturating_add(produced);
            if distance == 0
                || distance > available
                || distance > window
                || distance > self.hist.len()
            {
                return Err(bad("match offset reaches before the start of the window"));
            }
            let from = self.hist.len().saturating_sub(distance);
            for i in 0..length {
                let byte = self.hist.get(from.saturating_add(i)).copied().unwrap_or(0);
                self.hist.push(byte);
            }
            left = left.saturating_sub(length);
        }
        Ok(())
    }

    /// Decodes the next frame of `frame_len` bytes (or less, if the input
    /// ends first and the length is unknown) and appends it, translated,
    /// to `out`. On error, the state is unspecified (callers snapshot).
    /// `may_end`: the stream may end (at a block boundary) where the input
    /// does.
    pub fn frame(
        &mut self,
        input: &[u8],
        eof: bool,
        may_end: bool,
        frame_len: usize,
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<()> {
        let interval = u64::from(self.params.reset_interval);
        if interval != 0 && self.st.frame.is_multiple_of(interval) {
            self.reset()?;
        }
        if !self.st.header_read {
            self.st.e8_size = match self.params.variant {
                Variant::Cab => {
                    if self.st.bits.read(input, eof, 1)? == 1 {
                        let hi = self.st.bits.read(input, eof, 16)?;
                        let lo = self.st.bits.read(input, eof, 16)?;
                        hi << 16 | lo
                    } else {
                        0
                    }
                }
                Variant::Wim { e8_size } => e8_size,
            };
            self.st.header_read = true;
        }
        let start = self.hist.len();
        let mut produced = 0usize;
        while produced < frame_len {
            if self.st.block_remaining == 0 {
                if may_end && eof && self.st.bits.remaining(input) < 32 {
                    // The input ends at a block boundary.
                    self.st.done = true;
                    break;
                }
                self.block_header(input, eof)?;
                continue;
            }
            let todo = usize::try_from(self.st.block_remaining)
                .unwrap_or(usize::MAX)
                .min(frame_len.saturating_sub(produced));
            if out.len().saturating_add(produced).saturating_add(todo) > limit {
                return Err(Diagnostic::limit(format!(
                    "decompressed data exceeds {limit:#x} bytes"
                )));
            }
            self.run(input, eof, todo, start)?;
            produced = produced.saturating_add(todo);
            self.st.block_remaining = self
                .st
                .block_remaining
                .saturating_sub(u32::try_from(todo).unwrap_or(u32::MAX));
        }
        // Frames end on a word boundary (not inside uncompressed blocks,
        // which are byte-aligned already).
        self.st.bits.align();
        let data = self.hist.get(start..).unwrap_or_default();
        let at = out.len();
        out.extend_from_slice(data);
        let position = self.st.offset.saturating_sub(self.st.reset_offset);
        if self.st.e8_size != 0 && position < E8_LIMIT && produced > 10 {
            translate(
                out.get_mut(at..).unwrap_or_default(),
                position,
                self.st.e8_size,
            );
        }
        self.st.frame = self.st.frame.saturating_add(1);
        self.st.offset = self
            .st
            .offset
            .saturating_add(crate::bytes::to_u64(produced));
        Ok(())
    }
}

/// Undoes E8 call translation on one frame starting at stream offset
/// `offset`: the operands of `E8` bytes (not within the last 10 bytes) that
/// were turned from relative into absolute addresses are turned back.
pub fn translate(frame: &mut [u8], offset: u64, size: u32) {
    let size = i64::from(size);
    let end = frame.len().saturating_sub(10);
    let mut i = 0usize;
    let mut pos = i64::try_from(offset).unwrap_or(i64::MAX);
    while i < end {
        if frame.get(i) != Some(&0xe8) {
            i = i.saturating_add(1);
            pos = pos.saturating_add(1);
            continue;
        }
        let at = i.saturating_add(1);
        if let Some(abs) = crate::bytes::i32_le(frame, at) {
            let abs = i64::from(abs);
            if abs >= pos.saturating_neg() && abs < size {
                let rel = if abs >= 0 {
                    abs.saturating_sub(pos)
                } else {
                    abs.saturating_add(size)
                };
                let rel = (rel as i32).to_le_bytes();
                if let Some(slot) = frame.get_mut(at..at.saturating_add(4)) {
                    slot.copy_from_slice(&rel);
                }
            }
        }
        i = i.saturating_add(5);
        pos = pos.saturating_add(5);
    }
}

/// A raw LZX stream as a [`Decoder`] (CHM content, WIM chunks).
pub struct LzxStream {
    core: Result<Lzx>,
    params: Params,
}

impl LzxStream {
    pub fn new(params: Params) -> Self {
        LzxStream {
            core: Lzx::new(params),
            params,
        }
    }
}

impl Decoder for LzxStream {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let core = self.core.as_mut().map_err(|e| e.clone())?;
        let target = out.len().saturating_add(step);
        let mut decoded = 0u64;
        loop {
            let remaining = match self.params.len {
                Some(len) => len.saturating_sub(core.offset()),
                None if core.done() => 0,
                None => u64::MAX,
            };
            if remaining == 0 {
                return Ok(Status::Done);
            }
            if out.len() >= target {
                return Ok(Status::More);
            }
            let frame_len =
                usize::try_from(remaining.min(crate::bytes::to_u64(FRAME))).unwrap_or(FRAME);
            let saved = core.snapshot();
            let out_mark = out.len();
            match core.frame(input, eof, self.params.len.is_none(), frame_len, out, limit) {
                Ok(()) => decoded = decoded.saturating_add(1),
                Err(_) if !eof => {
                    core.restore(saved);
                    out.truncate(out_mark);
                    return Ok(if decoded > 0 {
                        Status::More
                    } else {
                        Status::NeedInput
                    });
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn consumed(&self) -> usize {
        self.core.as_ref().map_or(0, Lzx::consumed)
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    fn releasable_input(&self) -> usize {
        // Bits read ahead are buffered in the reader.
        self.consumed()
    }

    fn release_input(&mut self, n: usize) {
        if let Ok(core) = self.core.as_mut() {
            core.release_input(n);
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Matches read the decoder's own history (untranslated), never
        // `out`, and E8 positions count from its running offset.
        out_len
    }
}
