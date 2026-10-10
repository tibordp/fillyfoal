//! ACE 1.0 and 2.0 decompression (`unace`'s LZ77 and "blocked" methods).
//!
//! Nothing about ACE's compression was ever published as a specification;
//! this follows the behaviour of `acefile` (a pure-Python reimplementation
//! of `unace` 2.5 by Daniel Roethlisberger), which the tests use as an
//! oracle on archives our generator writes.
//!
//! The bitstream is a sequence of little-endian 32-bit words read
//! MSB-first. Huffman trees are sent as code widths (themselves
//! Huffman-coded, delta-coded modulo the largest width, with zero runs),
//! and codes are assigned in the order a particular unstable quicksort
//! leaves the symbols in, which [`quicksort`] reproduces.
//!
//! - **LZ77** (method 1, ACE 1.0): blocks of symbols, each block starting
//!   with a main tree (literals, four "repeat the n-th last distance"
//!   symbols, 23 distance-width symbols) and a length tree.
//! - **Blocked** (method 2, ACE 2.0): the same LZ77, plus a type code that
//!   switches mode: plain LZ77, LZ77 over delta-coded byte planes
//!   (`DELTA`), LZ77 over x86 code with `E8`/`E9` targets made absolute
//!   (`EXE`), an adaptive linear predictor for 8/16/32-bit sound
//!   (`SOUND`, after RAR 2's audio filter), and a context-modelled 2D
//!   predictor with Golomb-Rice residuals for pictures (`PIC`).
//!
//! In solid archives the LZ77 dictionary carries over from one file to the
//! next; [`Params`] lists the files from the first one, and the output is
//! theirs, one after another (a solid archive is decoded once, its files
//! being spans of the output). Each file's stored CRC-32 (the standard
//! polynomial without the final inversion) is checked.
//!
//! [`Decoder`] works a bounded run at a time (about `step` bytes, cut
//! between LZ77 matches, SOUND samples or PIC rows) and releases its input
//! as it goes.

use std::sync::Arc;

use crate::bytes::to_usize;
use crate::codec::pipeline::{self, Status};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("ACE: {what}"))
}

fn too_big(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
}

/// One file of a (solid) stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    /// Compressed bytes (the file's packed data in the input).
    pub packed: u64,
    /// Decompressed size.
    pub size: u64,
    /// 0 stored, 1 LZ77, 2 blocked.
    pub method: u8,
    /// The stored ACE CRC-32 of the decompressed data.
    pub crc: u32,
}

/// What to decode: the packed data of `members`, one after another; the
/// output is all of theirs, in order (a solid archive's files share the
/// dictionary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub members: Arc<[Member]>,
}

/// ACE's CRC-32: the standard CRC-32 without its final inversion.
pub fn ace_crc32(data: &[u8]) -> u32 {
    !crate::codec::crc32(data)
}

// ---------------------------------------------------------------------------
// Bits

/// Little-endian 32-bit words, each read MSB-first. Peeking up to 31 bits
/// past the end reads zeros; consuming them is an error.
#[derive(Clone)]
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Bits {
            data,
            pos: 0,
            end: data.len().div_ceil(4).saturating_mul(32),
        }
    }

    fn word(&self, i: usize) -> u64 {
        let at = i.saturating_mul(4);
        let mut w = 0u64;
        for k in 0..4usize {
            let b = self.data.get(at.saturating_add(k)).copied().unwrap_or(0);
            w |= u64::from(b) << (k.saturating_mul(8));
        }
        w
    }

    fn peek(&self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        let n = n.min(32);
        let width = to_usize(u64::from(n));
        if self.pos.saturating_add(width) > self.end.saturating_add(31) {
            return Err(bad("compressed data ends early"));
        }
        let w = self.pos / 32;
        let off = u32::try_from(self.pos % 32).unwrap_or(0);
        let v = (self.word(w) << 32 | self.word(w.saturating_add(1)))
            .checked_shl(off)
            .unwrap_or(0);
        Ok(u32::try_from(v >> (64u32.saturating_sub(n))).unwrap_or(0))
    }

    fn skip(&mut self, n: u32) -> Result<()> {
        let next = self.pos.saturating_add(to_usize(u64::from(n)));
        if next > self.end {
            return Err(bad("compressed data ends early"));
        }
        self.pos = next;
        Ok(())
    }

    fn read(&mut self, n: u32) -> Result<u32> {
        let v = self.peek(n)?;
        self.skip(n)?;
        Ok(v)
    }

    fn bit(&mut self) -> Result<bool> {
        Ok(self.read(1)? == 1)
    }

    /// A Golomb-Rice code: `r` remainder bits, then a unary quotient (ones
    /// ended by a zero). Signed values keep the sign in the lowest bit.
    fn golomb(&mut self, r: u32, signed: bool) -> Result<i64> {
        let mut value = i64::from(self.read(r)?);
        let step = 1i64.checked_shl(r).unwrap_or(i64::MAX);
        while self.bit()? {
            value = value.saturating_add(step);
        }
        if !signed {
            return Ok(value);
        }
        Ok(if value & 1 != 0 {
            (value >> 1).saturating_neg().saturating_sub(1)
        } else {
            value >> 1
        })
    }

    /// An unsigned integer of known width whose top bit (always set) is
    /// not stored.
    fn known_width(&mut self, bits: u32) -> Result<u32> {
        if bits < 2 {
            return Ok(bits);
        }
        let low = bits.saturating_sub(1);
        Ok(self.read(low)?.saturating_add(1u32 << low))
    }
}

// ---------------------------------------------------------------------------
// Huffman

/// `unace`'s quicksort, descending by key: the order it leaves equal keys
/// in decides which codes the symbols get, so it is reproduced exactly.
fn quicksort(keys: &mut [u8], values: &mut [u16]) {
    if let Some(last) = keys.len().checked_sub(1) {
        sort_range(keys, values, 0, last as isize);
    }
}

fn key(keys: &[u8], i: isize, default: u8) -> u8 {
    usize::try_from(i)
        .ok()
        .and_then(|i| keys.get(i))
        .copied()
        .unwrap_or(default)
}

fn swap(keys: &mut [u8], values: &mut [u16], a: isize, b: isize) {
    if let (Ok(a), Ok(b)) = (usize::try_from(a), usize::try_from(b))
        && a < keys.len()
        && b < keys.len()
        && a < values.len()
        && b < values.len()
    {
        keys.swap(a, b);
        values.swap(a, b);
    }
}

fn sort_range(keys: &mut [u8], values: &mut [u16], left: isize, right: isize) {
    let m = key(keys, right, 0);
    let mut nl = left;
    let mut nr = right;
    loop {
        while key(keys, nl, m) > m {
            nl = nl.saturating_add(1);
        }
        while key(keys, nr, m) < m {
            nr = nr.saturating_sub(1);
        }
        if nl <= nr {
            swap(keys, values, nl, nr);
            nl = nl.saturating_add(1);
            nr = nr.saturating_sub(1);
        }
        if nl >= nr {
            break;
        }
    }
    if left < nr {
        if left < nr.saturating_sub(1) {
            sort_range(keys, values, left, nr);
        } else if key(keys, left, 0) < key(keys, nr, 0) {
            swap(keys, values, left, nr);
        }
    }
    if right > nl {
        if nl < right.saturating_sub(1) {
            sort_range(keys, values, nl, right);
        } else if key(keys, nl, 0) < key(keys, right, 0) {
            swap(keys, values, nl, right);
        }
    }
}

/// A Huffman code as a lookup table indexed by the next `max` bits.
#[derive(Clone)]
struct Tree {
    // Shared: trees never change once built, and decoder states that hold
    // them are cloned before every step.
    codes: Arc<[u16]>,
    widths: Arc<[u8]>,
    max: u32,
}

impl Tree {
    fn new(mut widths: Vec<u8>, max: u32) -> Result<Tree> {
        let mut sorted_widths = widths.clone();
        let mut symbols: Vec<u16> = (0..widths.len())
            .map(|i| u16::try_from(i).unwrap_or(u16::MAX))
            .collect();
        quicksort(&mut sorted_widths, &mut symbols);
        let mut used = sorted_widths.iter().take_while(|&&w| w != 0).count();
        if used < 2 {
            let first = symbols.first().copied().ok_or_else(|| bad("empty tree"))?;
            if let Some(w) = widths.get_mut(usize::from(first)) {
                *w = 1;
            }
            used = used.max(1);
        }
        let max_codes = 1usize << max;
        let mut codes = Vec::with_capacity(max_codes);
        for (&sym, &width) in symbols.iter().zip(&sorted_widths).take(used).rev() {
            // The sorted width, even where a lone symbol's width was just
            // raised to 1 (its code then fills the table, as in `unace`).
            let width = u32::from(width);
            if width > max {
                return Err(bad("Huffman code too long"));
            }
            let repeat = 1usize << max.saturating_sub(width);
            if codes.len().saturating_add(repeat) > max_codes {
                return Err(bad("oversubscribed Huffman code"));
            }
            codes.extend(std::iter::repeat_n(sym, repeat));
        }
        Ok(Tree {
            codes: codes.into(),
            widths: widths.into(),
            max,
        })
    }

    fn read(&self, bs: &mut Bits<'_>) -> Result<u16> {
        let v = to_usize(u64::from(bs.peek(self.max)?));
        let sym = *self
            .codes
            .get(v)
            .ok_or_else(|| bad("invalid Huffman code"))?;
        let width = self.widths.get(usize::from(sym)).copied().unwrap_or(0);
        bs.skip(u32::from(width))?;
        Ok(sym)
    }

    /// Reads a tree of up to `num` symbols with codes of at most `max` bits.
    fn read_from(bs: &mut Bits<'_>, max: u32, num: usize) -> Result<Tree> {
        let num_widths = to_usize(u64::from(bs.read(9)?))
            .saturating_add(1)
            .min(num.saturating_add(1));
        let lower = u8::try_from(bs.read(4)?).unwrap_or(0);
        let upper = u8::try_from(bs.read(4)?).unwrap_or(0);
        let mut width_widths = Vec::with_capacity(usize::from(upper).saturating_add(1));
        for _ in 0..=upper {
            width_widths.push(u8::try_from(bs.read(3)?).unwrap_or(0));
        }
        let width_tree = Tree::new(width_widths, 7)?;
        let mut widths: Vec<u8> = Vec::with_capacity(num_widths);
        while widths.len() < num_widths {
            let sym = width_tree.read(bs)?;
            if sym < u16::from(upper) {
                widths.push(u8::try_from(sym).unwrap_or(0));
            } else {
                let n = to_usize(u64::from(bs.read(4)?))
                    .saturating_add(4)
                    .min(num_widths.saturating_sub(widths.len()));
                widths.extend(std::iter::repeat_n(0, n));
            }
        }
        if upper > 0 {
            let mut prev = 0u8;
            for (i, w) in widths.iter_mut().enumerate() {
                if i > 0 {
                    let sum = u16::from(*w).saturating_add(u16::from(prev));
                    *w = u8::try_from(sum.checked_rem(u16::from(upper)).unwrap_or(0)).unwrap_or(0);
                }
                prev = *w;
            }
        }
        for w in &mut widths {
            if *w > 0 {
                *w = w.saturating_add(lower);
            }
        }
        Tree::new(widths, max)
    }
}

// ---------------------------------------------------------------------------
// Modes

const MODE_LZ77: u8 = 0;
const MODE_DELTA: u8 = 1;
const MODE_EXE: u8 = 2;
const MODE_SOUND_8: u8 = 3;
const MODE_SOUND_32B: u8 = 6;
const MODE_PIC: u8 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mode {
    mode: u8,
    delta_dist: u32,
    delta_len: u32,
    exe_mode: u32,
}

impl Mode {
    fn plain(mode: u8) -> Self {
        Mode {
            mode,
            delta_dist: 0,
            delta_len: 0,
            exe_mode: 0,
        }
    }

    fn read(bs: &mut Bits<'_>) -> Result<Mode> {
        let mut m = Mode::plain(u8::try_from(bs.read(8)?).unwrap_or(0xff));
        if m.mode == MODE_DELTA {
            m.delta_dist = bs.read(8)?;
            m.delta_len = bs.read(17)?;
        } else if m.mode == MODE_EXE {
            m.exe_mode = bs.read(8)?;
        }
        Ok(m)
    }
}

// ---------------------------------------------------------------------------
// LZ77

const MAX_DIC_BITS: u32 = 22;
const TYPECODE: u16 = 260 + MAX_DIC_BITS as u16 + 1;
const NUM_MAIN: usize = 260 + MAX_DIC_BITS as usize + 2;
const NUM_LEN: usize = 255;
const LZ_MAX_WIDTH: u32 = 11;
/// History kept for back-references: the largest ACE dictionary (4 MiB).
const DICT_KEEP: usize = 1 << MAX_DIC_BITS;

/// The LZ77 dictionary: everything LZ77 (or a non-LZ mode) produced,
/// trimmed to the last 4 MiB now and then (only between decoder steps, so
/// that a step can be undone by truncating it). With filters (DELTA, EXE)
/// it holds the bytes before filtering.
#[derive(Clone, Default)]
struct Dict {
    data: Vec<u8>,
}

impl Dict {
    fn trim(&mut self) {
        if self.data.len() > DICT_KEEP.saturating_mul(2) {
            let cut = self.data.len().saturating_sub(DICT_KEEP);
            self.data.drain(..cut);
        }
    }

    fn register(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }
}

#[derive(Clone, Default)]
struct Lz77 {
    main: Option<Tree>,
    lens: Option<Tree>,
    left: u32,
    /// The last four distances, oldest first.
    hist: [u32; 4],
}

impl Lz77 {
    fn main_symbol(&mut self, bs: &mut Bits<'_>) -> Result<u16> {
        if self.left == 0 {
            self.main = Some(Tree::read_from(bs, LZ_MAX_WIDTH, NUM_MAIN)?);
            self.lens = Some(Tree::read_from(bs, LZ_MAX_WIDTH, NUM_LEN)?);
            self.left = bs.read(15)?;
        }
        self.left = self.left.saturating_sub(1);
        self.main.as_ref().ok_or_else(|| bad("no tree"))?.read(bs)
    }

    fn len_symbol(&self, bs: &mut Bits<'_>) -> Result<u32> {
        Ok(u32::from(
            self.lens.as_ref().ok_or_else(|| bad("no tree"))?.read(bs)?,
        ))
    }

    /// Decodes until at least `soft` bytes have been added to `dict` or a
    /// type code announces another mode; returns the number of bytes added.
    /// A match may run past `soft`, but not past `want`.
    fn read(
        &mut self,
        bs: &mut Bits<'_>,
        dict: &mut Dict,
        soft: usize,
        want: usize,
    ) -> Result<(usize, Option<Mode>)> {
        let mut have = 0usize;
        while have < soft.min(want) {
            let sym = self.main_symbol(bs)?;
            if sym <= 255 {
                dict.data.push(u8::try_from(sym).unwrap_or(0));
                have = have.saturating_add(1);
                continue;
            }
            if sym == TYPECODE {
                let mode = Mode::read(bs)?;
                return Ok((have, Some(mode)));
            }
            if sym > TYPECODE {
                return Err(bad("invalid LZ77 symbol"));
            }
            let (dist, len) = if sym <= 259 {
                let len = self.len_symbol(bs)?;
                let offset = usize::from(sym & 3);
                let idx = 3usize.saturating_sub(offset);
                let dist = self.hist.get(idx).copied().unwrap_or(0);
                // Move it to the most recent place.
                let mut v: Vec<u32> = self.hist.to_vec();
                if idx < v.len() {
                    v.remove(idx);
                }
                v.push(dist);
                for (slot, d) in self.hist.iter_mut().zip(v) {
                    *slot = d;
                }
                (dist, len.saturating_add(if offset > 1 { 3 } else { 2 }))
            } else {
                let dist = bs.known_width(u32::from(sym.saturating_sub(260)))?;
                let len = self.len_symbol(bs)?;
                self.hist.rotate_left(1);
                if let Some(last) = self.hist.last_mut() {
                    *last = dist;
                }
                let extra = if dist <= 255 {
                    2
                } else if dist <= 8191 {
                    3
                } else {
                    4
                };
                (dist, len.saturating_add(extra))
            };
            let dist = to_usize(u64::from(dist)).saturating_add(1);
            let len = to_usize(u64::from(len));
            if have.saturating_add(len) > want {
                return Err(bad("match runs past the end of the data"));
            }
            if dist > dict.data.len() {
                return Err(bad("match distance before the start of the data"));
            }
            let start = dict.data.len().saturating_sub(dist);
            for i in 0..len {
                let b = dict.data.get(start.saturating_add(i)).copied().unwrap_or(0);
                dict.data.push(b);
            }
            have = have.saturating_add(len);
        }
        Ok((have, None))
    }
}

// ---------------------------------------------------------------------------
// SOUND

const SOUND_RUNLEN: i32 = 32;
const SOUND_TYPECODE: u16 = 256 + 32;
const SOUND_NUM: usize = 256 + 32 + 1;
const SOUND_MAX_WIDTH: u32 = 10;
const SOUND_CHANNELS: [usize; 4] = [1, 2, 3, 3];
const SOUND_USE: [[usize; 4]; 4] = [[0, 0, 0, 0], [0, 1, 0, 1], [0, 1, 0, 2], [1, 0, 2, 0]];

fn schar(x: i32) -> i32 {
    i32::from((x & 0xff) as u8 as i8)
}

fn uchar(x: i32) -> i32 {
    x & 0xff
}

/// Bits needed for `v` (Python's `int.bit_length` for v >= 0).
fn bit_length(v: i64) -> u32 {
    64u32.saturating_sub(v.unsigned_abs().leading_zeros())
}

fn sound_quantizer(i: i32) -> i32 {
    // q[i] = q[256 - i] = bit_length(i) for i in 1..=128.
    let i = i & 0xff;
    let v = if i > 128 { 256i32.saturating_sub(i) } else { i };
    i32::try_from(bit_length(i64::from(v))).unwrap_or(0)
}

#[derive(Clone, Default)]
struct SoundTrees {
    trees: Vec<Option<Tree>>,
    left: u32,
}

impl SoundTrees {
    fn symbol(&mut self, bs: &mut Bits<'_>, model: usize) -> Result<u16> {
        if self.left == 0 {
            for t in &mut self.trees {
                *t = Some(Tree::read_from(bs, SOUND_MAX_WIDTH, SOUND_NUM)?);
            }
            self.left = bs.read(15)?;
        }
        self.left = self.left.saturating_sub(1);
        self.trees
            .get(model)
            .and_then(Option::as_ref)
            .ok_or_else(|| bad("no sound tree"))?
            .read(bs)
    }
}

#[derive(Clone, Default)]
struct Channel {
    base: usize,
    pred_dif_cnt: [i32; 2],
    last_pred_dif_cnt: [i32; 2],
    rar_dif_cnt: [i32; 4],
    rar_coeff: [i32; 4],
    rar_dif: [i32; 9],
    byte_count: u32,
    last_sample: i32,
    last_delta: i32,
    adapt_model_cnt: i32,
    adapt_model_use: usize,
    get_state: u8,
    get_code: i32,
}

enum Sample {
    Value(i32),
    Mode(Mode),
}

impl Channel {
    fn get(&mut self, bs: &mut Bits<'_>, trees: &mut SoundTrees) -> Result<Sample> {
        if self.get_state != 2 {
            let mut model = usize::from(self.get_state) << 1;
            if model == 0 {
                model = model.saturating_add(self.adapt_model_use);
            }
            let code = trees.symbol(bs, model.saturating_add(self.base))?;
            if code == SOUND_TYPECODE {
                return Ok(Sample::Mode(Mode::read(bs)?));
            }
            self.get_code = i32::from(code);
        }
        let mut value = 0i32;
        if self.get_state == 0 {
            if self.get_code >= SOUND_RUNLEN {
                value = self.get_code.saturating_sub(SOUND_RUNLEN);
                self.adapt_model_cnt =
                    (self.adapt_model_cnt.saturating_mul(7) >> 3).saturating_add(value);
                self.adapt_model_use = usize::from(self.adapt_model_cnt > 40);
            } else {
                self.get_state = 2;
            }
        } else if self.get_state == 1 {
            value = self.get_code;
            self.get_state = 0;
        }
        if self.get_state == 2 {
            if self.get_code == 0 {
                self.get_state = 1;
            } else {
                self.get_code = self.get_code.saturating_sub(1);
            }
            value = 0;
        }
        Ok(Sample::Value(if value & 1 != 0 {
            255i32.saturating_sub(value >> 1)
        } else {
            value >> 1
        }))
    }

    fn predicted(&self) -> i32 {
        let mut sum = self.last_sample.saturating_mul(8);
        for (c, d) in self.rar_coeff.iter().zip(&self.rar_dif_cnt) {
            sum = sum.saturating_add(c.saturating_mul(*d));
        }
        uchar(sum >> 3)
    }

    fn predict(&self) -> i32 {
        if self.pred_dif_cnt[0] > self.pred_dif_cnt[1] {
            self.last_sample
        } else {
            self.predicted()
        }
    }

    fn adjust(&mut self, sample: i32) {
        self.byte_count = self.byte_count.wrapping_add(1);
        let pred_dif = schar(self.predicted().saturating_sub(sample)) << 3;
        let cnt = self.rar_dif_cnt;
        for (k, c) in cnt.iter().enumerate() {
            let i = k.saturating_mul(2);
            if let Some(d) = self.rar_dif.get_mut(i) {
                *d = d.saturating_add(pred_dif.saturating_sub(*c).saturating_abs());
            }
            if let Some(d) = self.rar_dif.get_mut(i.saturating_add(1)) {
                *d = d.saturating_add(pred_dif.saturating_add(*c).saturating_abs());
            }
        }
        self.rar_dif[8] = self.rar_dif[8].saturating_add(pred_dif.saturating_abs());
        self.last_delta = schar(sample.saturating_sub(self.last_sample));
        self.pred_dif_cnt[0] = self.pred_dif_cnt[0].saturating_add(sound_quantizer(pred_dif >> 3));
        self.pred_dif_cnt[1] = self.pred_dif_cnt[1]
            .saturating_add(sound_quantizer(self.last_sample.saturating_sub(sample)));
        self.last_sample = sample;
        if self.byte_count & 0x1f == 0 {
            let mut min_dif = 0xffff;
            let mut min_pos = 8usize;
            for i in (0..9usize).rev() {
                if let Some(d) = self.rar_dif.get_mut(i) {
                    if *d <= min_dif {
                        min_dif = *d;
                        min_pos = i;
                    }
                    *d = 0;
                }
            }
            if min_pos != 8 {
                let i = min_pos >> 1;
                if let Some(c) = self.rar_coeff.get_mut(i) {
                    if min_pos & 1 == 0 {
                        if *c >= -16 {
                            *c = c.saturating_sub(1);
                        }
                    } else if *c <= 16 {
                        *c = c.saturating_add(1);
                    }
                }
            }
            if self.byte_count & 0xff == 0 {
                for (cnt, last) in self
                    .pred_dif_cnt
                    .iter_mut()
                    .zip(self.last_pred_dif_cnt.iter_mut())
                {
                    *cnt = cnt.saturating_sub(*last);
                    *last = *cnt;
                }
            }
        }
        self.rar_dif_cnt[3] = self.rar_dif_cnt[2];
        self.rar_dif_cnt[2] = self.rar_dif_cnt[1];
        self.rar_dif_cnt[1] = self.last_delta.saturating_sub(self.rar_dif_cnt[0]);
        self.rar_dif_cnt[0] = self.last_delta;
    }
}

#[derive(Clone, Default)]
struct Sound {
    mode: usize,
    trees: SoundTrees,
    channels: Vec<Channel>,
}

impl Sound {
    fn reinit(&mut self, mode: u8) {
        self.mode = usize::from(mode.saturating_sub(MODE_SOUND_8)).min(3);
        let n = SOUND_CHANNELS.get(self.mode).copied().unwrap_or(1);
        self.trees = SoundTrees {
            trees: vec![None; n.saturating_mul(3)],
            left: 0,
        };
        self.channels = (0..n)
            .map(|i| Channel {
                base: i.saturating_mul(3),
                ..Channel::default()
            })
            .collect();
    }

    fn read(&mut self, bs: &mut Bits<'_>, want: usize, out: &mut Vec<u8>) -> Result<Option<Mode>> {
        let uses = SOUND_USE.get(self.mode).copied().unwrap_or([0; 4]);
        for i in 0..(want & !3) {
            let c = uses.get(i % 4).copied().unwrap_or(0);
            let ch = self
                .channels
                .get_mut(c)
                .ok_or_else(|| bad("no sound channel"))?;
            let value = match ch.get(bs, &mut self.trees)? {
                Sample::Mode(m) => return Ok(Some(m)),
                Sample::Value(v) => v,
            };
            let sample = uchar(value.saturating_add(ch.predict()));
            out.push(u8::try_from(sample).unwrap_or(0));
            ch.adjust(schar(sample));
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// PIC

const PIC_CONTEXTS: usize = 365;
const PIC_MAX_WIDTH: i64 = 1 << 20;
/// Input bits after which [`Pic::read`] ends early (between rows).
const PIC_STEP_BITS: usize = 1 << 19;

#[derive(Clone, Copy)]
struct ErrContext {
    used: i32,
    predictor: usize,
    average: i32,
    errors: [i32; 4],
}

impl Default for ErrContext {
    fn default() -> Self {
        ErrContext {
            used: 0,
            predictor: 0,
            average: 4,
            errors: [0; 4],
        }
    }
}

fn pic_quantizer(d: i32) -> i32 {
    match d {
        i32::MIN..=-21 => -4,
        -20..=-7 => -3,
        -6..=-3 => -2,
        -2..=-1 => -1,
        0 => 0,
        1..=2 => 1,
        3..=6 => 2,
        7..=20 => 3,
        _ => 4,
    }
}

fn dif_bit_width(d: i32) -> i32 {
    // Indexed by the difference modulo 256, as a signed byte.
    let s = schar(d);
    let v = if s >= 0 {
        s.saturating_mul(2)
    } else {
        s.saturating_mul(-2).saturating_sub(1)
    };
    i32::try_from(bit_length(i64::from(v))).unwrap_or(0)
}

#[derive(Clone, Copy, Default)]
struct Pixels {
    /// 0: plain, 1: difference to the plane before, 2: weighted difference.
    kind: u8,
    a: i32,
    b: i32,
    c: i32,
    d: i32,
    x: i32,
}

impl Pixels {
    fn new(kind: u8) -> Self {
        let v = if kind == 0 { 0 } else { 128 };
        Pixels {
            kind,
            a: v,
            b: v,
            c: v,
            d: 0,
            x: v,
        }
    }

    fn shift(&mut self) {
        self.c = self.a;
        self.a = self.d;
        self.b = self.x;
    }

    fn set_d(&mut self, this: i32, reference: i32) {
        self.d = match self.kind {
            0 => this,
            1 => uchar(128i32.saturating_add(this).saturating_sub(reference)),
            _ => uchar(
                128i32
                    .saturating_add(this)
                    .saturating_sub(reference.saturating_mul(11) >> 4),
            ),
        };
    }

    fn produce(&self, reference: i32) -> i32 {
        match self.kind {
            0 => self.x,
            1 => uchar(self.x.saturating_add(reference).saturating_sub(128)),
            _ => uchar(
                self.x
                    .saturating_add(reference.saturating_mul(11) >> 4)
                    .saturating_sub(128),
            ),
        }
    }

    fn context(&self) -> usize {
        let ctx = pic_quantizer(self.d.saturating_sub(self.a))
            .saturating_mul(81)
            .saturating_add(pic_quantizer(self.a.saturating_sub(self.c)).saturating_mul(9))
            .saturating_add(pic_quantizer(self.c.saturating_sub(self.b)));
        to_usize(u64::from(ctx.unsigned_abs()))
    }

    fn predict(&self, which: usize) -> i32 {
        match which {
            0 => self.a,
            1 => self.b,
            2 => self.a.saturating_add(self.b) >> 1,
            _ => uchar(self.a.saturating_add(self.b).saturating_sub(self.c)),
        }
    }

    fn update_x(&mut self, bs: &mut Bits<'_>, ctx: &mut ErrContext) -> Result<()> {
        ctx.used = ctx.used.saturating_add(1);
        let r = ctx.average.checked_div(ctx.used).unwrap_or(0);
        let eps = bs.golomb(bit_length(i64::from(r)), true)?;
        let eps = i32::try_from(eps.clamp(-(1 << 30), 1 << 30)).unwrap_or(0);
        self.x = uchar(self.predict(ctx.predictor).saturating_add(eps));
        ctx.average = ctx.average.saturating_add(eps.saturating_abs());
        if ctx.used == 128 {
            ctx.used >>= 1;
            ctx.average >>= 1;
        }
        let mut best = 0usize;
        for i in 0..4usize {
            let e = dif_bit_width(self.x.saturating_sub(self.predict(i)));
            if let Some(c) = ctx.errors.get_mut(i) {
                *c = c.saturating_add(e);
            }
            if i == 0 || ctx.errors.get(i) < ctx.errors.get(best) {
                best = i;
            }
        }
        ctx.predictor = best;
        if ctx.errors.iter().any(|&e| e > 0x7f) {
            for e in &mut ctx.errors {
                *e >>= 1;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Pic {
    width: usize,
    planes: usize,
    plane0: Vec<ErrContext>,
    planes1: Vec<ErrContext>,
    /// The previous row (shared: replaced, never changed, per row).
    prev: Arc<[i32]>,
}

impl Pic {
    fn reinit(&mut self, bs: &mut Bits<'_>) -> Result<()> {
        let width = bs.golomb(12, false)?;
        let planes = bs.golomb(2, false)?;
        if width > PIC_MAX_WIDTH || planes > PIC_MAX_WIDTH {
            return Err(bad("picture too wide"));
        }
        self.width = to_usize(u64::try_from(width).unwrap_or(0));
        self.planes = to_usize(u64::try_from(planes).unwrap_or(0));
        self.plane0 = vec![ErrContext::default(); PIC_CONTEXTS];
        self.planes1 = vec![ErrContext::default(); PIC_CONTEXTS];
        self.prev = vec![0; self.width.saturating_add(self.planes)].into();
        Ok(())
    }

    /// `v[i]`, with -1 meaning the last element (as the reference does).
    fn at(v: &[i32], i: isize) -> i32 {
        let i = if i < 0 {
            v.len().checked_sub(i.unsigned_abs())
        } else {
            usize::try_from(i).ok()
        };
        i.and_then(|i| v.get(i)).copied().unwrap_or(0)
    }

    fn row(&mut self, bs: &mut Bits<'_>) -> Result<Vec<i32>> {
        let len = self.width.saturating_add(self.planes);
        let mut row = vec![0i32; len];
        for plane in 0..self.planes {
            let kind = if plane == 0 {
                0
            } else {
                let k = bs.read(2)?;
                if k > 2 {
                    return Err(bad("unknown picture plane predictor"));
                }
                u8::try_from(k).unwrap_or(0)
            };
            let mut px = Pixels::new(kind);
            let p = plane as isize;
            px.set_d(
                Pic::at(&self.prev, p),
                Pic::at(&self.prev, p.saturating_sub(1)),
            );
            let mut col = plane;
            while col < self.width {
                px.shift();
                let next = col.saturating_add(self.planes) as isize;
                px.set_d(
                    Pic::at(&self.prev, next),
                    Pic::at(&self.prev, next.saturating_sub(1)),
                );
                let ctx_index = px.context();
                let model = if plane == 0 {
                    &mut self.plane0
                } else {
                    &mut self.planes1
                };
                let ctx = model
                    .get_mut(ctx_index)
                    .ok_or_else(|| bad("picture context out of range"))?;
                px.update_x(bs, ctx)?;
                let left = Pic::at(&row, (col as isize).saturating_sub(1));
                if let Some(slot) = row.get_mut(col) {
                    *slot = px.produce(left);
                }
                col = col.saturating_add(self.planes);
            }
        }
        let full: Arc<[i32]> = row.into();
        let row = full.get(..self.width).unwrap_or_default().to_vec();
        self.prev = full;
        Ok(row)
    }

    /// Decodes rows until at least `soft` bytes are out (rows are never
    /// cut short of `want`), a type code announces another mode, or the
    /// rows read so far took more than [`PIC_STEP_BITS`] (rows can be
    /// empty).
    fn read(
        &mut self,
        bs: &mut Bits<'_>,
        soft: usize,
        want: usize,
        out: &mut Vec<u8>,
    ) -> Result<Option<Mode>> {
        let mut have = 0usize;
        let start = bs.pos;
        while have < soft.min(want) && bs.pos.saturating_sub(start) <= PIC_STEP_BITS {
            if !bs.bit()? {
                return Ok(Some(Mode::read(bs)?));
            }
            let row = self.row(bs)?;
            for &v in row.iter().take(want.saturating_sub(have)) {
                out.push(u8::try_from(uchar(v)).unwrap_or(0));
                have = have.saturating_add(1);
            }
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Members

/// Output an LZ77 or SOUND run produces before the decoder looks at its
/// budget again (a match may run a little past it; a PIC row and a DELTA
/// block are never cut).
const CHUNK: usize = 4096;
/// With less buffered input than this ahead, a step that has produced
/// output ends at the next clean point rather than risk running out (and
/// being undone).
const MARGIN: usize = 16 * 1024;
/// Iterations (runs between mode switches) per step: switches can
/// produce nothing.
const MAX_ITERATIONS: usize = 256;

/// The member being decoded.
#[derive(Clone)]
struct Cur {
    /// Input index the bit position counts from: the member's start, moved
    /// on by whole 32-bit words (stored members: by bytes) as it is read.
    in_pos: usize,
    /// Input index of the member's end.
    end: usize,
    /// Bits read since `in_pos`.
    bit: usize,
    size: usize,
    produced: usize,
    method: u8,
    lz: Lz77,
    exe_leftover: Vec<u8>,
    last_delta: u8,
    mode: Mode,
    next: Option<Mode>,
    /// Running ACE CRC-32 of the output.
    crc: u32,
}

/// What a member's step works with besides its own state.
struct Shared<'a> {
    dict: &'a mut Dict,
    sound: &'a mut Sound,
    pic: &'a mut Pic,
    out: &'a mut Vec<u8>,
}

impl Cur {
    fn new(start: usize, m: &Member) -> Cur {
        let packed = to_usize(m.packed);
        Cur {
            in_pos: start,
            end: start.saturating_add(packed),
            bit: 0,
            size: to_usize(m.size),
            produced: 0,
            method: m.method,
            lz: Lz77::default(),
            exe_leftover: Vec::new(),
            last_delta: 0,
            mode: Mode::plain(MODE_LZ77),
            next: None,
            crc: 0xffff_ffff,
        }
    }

    fn emit(&mut self, out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(bytes);
        self.crc = crate::codec::crc::crc32_update(self.crc, bytes);
        self.produced = self.produced.saturating_add(bytes.len());
    }

    /// Decodes about `budget` more bytes of this member; true once it is
    /// complete.
    fn run(
        &mut self,
        input: &[u8],
        eof: bool,
        sh: &mut Shared<'_>,
        budget: usize,
        iterations: &mut usize,
    ) -> Result<bool> {
        let data = input
            .get(self.in_pos..self.end.min(input.len()))
            .unwrap_or_default();
        // Everything of the member there is to have (with less, only whole
        // words count as read, so that no zero padding is consumed).
        let complete = eof || input.len() >= self.end;
        if self.method == 0 {
            return self.stored(data, complete, sh, budget);
        }
        let end = if complete {
            data.len().div_ceil(4).saturating_mul(32)
        } else {
            (data.len() / 4).saturating_mul(32)
        };
        let mut bs = Bits {
            data,
            pos: self.bit,
            end,
        };
        let mut here = 0usize;
        let finished = loop {
            if self.produced >= self.size {
                break true;
            }
            if here >= budget || *iterations >= MAX_ITERATIONS {
                break false;
            }
            if !complete && here > 0 && data.len().saturating_sub(bs.pos / 8) < MARGIN {
                break false;
            }
            *iterations = iterations.saturating_add(1);
            let before = self.produced;
            match self.method {
                1 => self.lz77(&mut bs, sh)?,
                2 => self.blocked(&mut bs, sh)?,
                _ => return Err(Diagnostic::unsupported("ACE compression method")),
            }
            here = here.saturating_add(self.produced.saturating_sub(before));
        };
        let words = (bs.pos / 32).min(data.len() / 4);
        self.in_pos = self.in_pos.saturating_add(words.saturating_mul(4));
        self.bit = bs.pos.saturating_sub(words.saturating_mul(32));
        Ok(finished)
    }

    fn stored(
        &mut self,
        data: &[u8],
        complete: bool,
        sh: &mut Shared<'_>,
        budget: usize,
    ) -> Result<bool> {
        let left = self.size.saturating_sub(self.produced);
        if complete && data.len() < left {
            return Err(bad("stored data ends early"));
        }
        let n = left.min(data.len()).min(budget.max(1));
        if n == 0 && left > 0 {
            return Err(bad("stored data ends early"));
        }
        let bytes = data.get(..n).unwrap_or_default();
        self.emit(sh.out, bytes);
        sh.dict.register(bytes);
        self.in_pos = self.in_pos.saturating_add(n);
        Ok(self.produced >= self.size)
    }

    /// One run of ACE 1.0 LZ77.
    fn lz77(&mut self, bs: &mut Bits<'_>, sh: &mut Shared<'_>) -> Result<()> {
        let want = self.size.saturating_sub(self.produced);
        let (n, mode) = self.lz.read(bs, sh.dict, CHUNK, want)?;
        if mode.is_some() {
            return Err(bad("type code in an ACE 1.0 LZ77 stream"));
        }
        let start = sh.dict.data.len().saturating_sub(n);
        let bytes = sh.dict.data.get(start..).unwrap_or_default();
        sh.out.extend_from_slice(bytes);
        self.crc = crate::codec::crc::crc32_update(self.crc, bytes);
        self.produced = self.produced.saturating_add(n);
        Ok(())
    }

    /// One run of blocked data: up to a mode switch, or about [`CHUNK`]
    /// bytes.
    fn blocked(&mut self, bs: &mut Bits<'_>, sh: &mut Shared<'_>) -> Result<()> {
        let size = self.size;
        if let Some(n) = self.next.take() {
            if n.mode != self.mode.mode {
                if (MODE_SOUND_8..=MODE_SOUND_32B).contains(&n.mode) {
                    sh.sound.reinit(n.mode);
                } else if n.mode == MODE_PIC {
                    sh.pic.reinit(bs)?;
                }
            }
            self.mode = n;
        }
        let before = (self.produced, bs.pos);
        let left = size.saturating_sub(self.produced);
        match self.mode.mode {
            MODE_DELTA => {
                let delta_len = to_usize(u64::from(self.mode.delta_len));
                let mut delta: Vec<u8> = Vec::new();
                while delta.len() < delta_len {
                    let more = delta_len.saturating_sub(delta.len());
                    let (n, nm) = self.lz.read(bs, sh.dict, more, more)?;
                    let start = sh.dict.data.len().saturating_sub(n);
                    delta.extend_from_slice(sh.dict.data.get(start..).unwrap_or_default());
                    if let Some(nm) = nm {
                        if self.next.is_some() {
                            return Err(bad("DELTA block interrupted twice"));
                        }
                        self.next = Some(nm);
                        if delta.is_empty() {
                            break;
                        }
                    }
                }
                if delta.is_empty() && self.next.is_some() {
                    return Ok(());
                }
                for b in &mut delta {
                    *b = b.wrapping_add(self.last_delta);
                    self.last_delta = *b;
                }
                let dist = to_usize(u64::from(self.mode.delta_dist));
                let plane_size = delta_len
                    .checked_div(dist)
                    .ok_or_else(|| bad("DELTA distance 0"))?;
                let mut planes = Vec::with_capacity(left.min(delta.len()));
                'planes: for pos in 0..plane_size {
                    let mut plane = 0usize;
                    while plane < delta_len {
                        let b = delta
                            .get(plane.saturating_add(pos))
                            .copied()
                            .ok_or_else(|| bad("DELTA block ends early"))?;
                        if planes.len() >= left {
                            break 'planes;
                        }
                        planes.push(b);
                        plane = plane.saturating_add(plane_size);
                    }
                }
                self.emit(sh.out, &planes);
            }
            MODE_LZ77 | MODE_EXE => {
                let mut chunk = std::mem::take(&mut self.exe_leftover);
                let want = left.saturating_sub(chunk.len());
                let (n, nm) = self.lz.read(bs, sh.dict, CHUNK, want)?;
                let start = sh.dict.data.len().saturating_sub(n);
                chunk.extend_from_slice(sh.dict.data.get(start..).unwrap_or_default());
                self.next = nm;
                if self.mode.mode == MODE_EXE {
                    let at = self.produced;
                    let last = at.saturating_add(chunk.len()) >= size;
                    self.exe_leftover = exe_filter(&mut chunk, at, self.mode.exe_mode, last);
                }
                self.emit(sh.out, &chunk);
            }
            MODE_SOUND_8..=MODE_SOUND_32B => {
                // Runs stay multiples of four (the channel pattern restarts
                // with each).
                let mut buf = Vec::new();
                self.next = sh.sound.read(bs, left.min(CHUNK), &mut buf)?;
                sh.dict.register(&buf);
                self.emit(sh.out, &buf);
            }
            MODE_PIC => {
                let mut buf = Vec::new();
                self.next = sh.pic.read(bs, CHUNK, left, &mut buf)?;
                sh.dict.register(&buf);
                self.emit(sh.out, &buf);
            }
            _ => return Err(bad("unknown compression mode")),
        }
        if (self.produced, bs.pos) == before && self.next.is_none() {
            return Err(bad("no progress"));
        }
        Ok(())
    }
}

/// Decoder state, apart from the dictionary (cloned before each step).
#[derive(Clone, Default)]
struct State {
    /// The member being decoded or next.
    k: usize,
    /// Input index of member `k`'s packed data.
    start: usize,
    cur: Option<Cur>,
    /// SOUND and PIC models carry over from one member to the next.
    sound: Sound,
    pic: Pic,
    /// The first member whose CRC did not match.
    bad_crc: Option<usize>,
    consumed: usize,
    done: bool,
}

/// The decoder for [`Params`]: the members' outputs one after another, a
/// bounded run at a time, input released as it is read.
///
/// The 4 MiB dictionary is too large to copy before every step, so this is
/// a [`pipeline::Decoder`] of its own: a step that runs out of input is
/// undone by restoring the small state and truncating the dictionary and
/// the output (the dictionary is only trimmed between steps).
pub struct Decoder {
    params: Params,
    st: State,
    dict: Dict,
}

impl Decoder {
    pub fn new(params: Params) -> Self {
        Decoder {
            params,
            st: State::default(),
            dict: Dict::default(),
        }
    }

    fn run(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let first = out.len();
        let mut iterations = 0usize;
        loop {
            let here = out.len().saturating_sub(first);
            if here >= step || iterations >= MAX_ITERATIONS {
                return Ok(Status::More);
            }
            let st = &mut self.st;
            let Some(cur) = st.cur.as_mut() else {
                let Some(m) = self.params.members.get(st.k) else {
                    if eof {
                        st.consumed = input.len();
                        st.done = true;
                        return Ok(Status::Done);
                    }
                    st.consumed = st.start.min(input.len());
                    return Ok(if here > 0 {
                        Status::More
                    } else {
                        Status::NeedInput
                    });
                };
                let size = to_usize(m.size);
                if size > limit.saturating_sub(out.len()) {
                    return Err(too_big(limit));
                }
                if size > 0 && m.method > 2 {
                    return Err(Diagnostic::unsupported("ACE compression method"));
                }
                st.cur = Some(Cur::new(st.start, m));
                continue;
            };
            let mut sh = Shared {
                dict: &mut self.dict,
                sound: &mut st.sound,
                pic: &mut st.pic,
                out,
            };
            let budget = step.saturating_sub(here);
            if !cur.run(input, eof, &mut sh, budget, &mut iterations)? {
                st.consumed = cur.in_pos.min(input.len());
                return Ok(Status::More);
            }
            let (crc, next) = (cur.crc, cur.end);
            if self.params.members.get(st.k).is_some_and(|m| m.crc != crc) && st.bad_crc.is_none() {
                st.bad_crc = Some(st.k);
            }
            st.cur = None;
            st.k = st.k.saturating_add(1);
            st.start = next;
            st.consumed = next.min(input.len());
        }
    }
}

impl pipeline::Decoder for Decoder {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        if self.st.done {
            return Ok(Status::Done);
        }
        self.dict.trim();
        let saved = self.st.clone();
        let dict_mark = self.dict.data.len();
        let mark = out.len();
        match self.run(input, eof, out, step, limit) {
            Err(_) if !eof => {
                // Most likely a shortage of input; retry once more arrives.
                // A genuine error recurs at the end of the input.
                self.st = saved;
                self.dict.data.truncate(dict_mark);
                out.truncate(mark);
                Ok(Status::NeedInput)
            }
            result => result,
        }
    }

    fn consumed(&self) -> usize {
        self.st.consumed
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        let k = self.st.bad_crc?;
        Some(Diagnostic::warning(if self.params.members.len() > 1 {
            format!(
                "ACE CRC-32 mismatch (file {} of the solid stream)",
                k.saturating_add(1)
            )
        } else {
            "ACE CRC-32 mismatch".to_owned()
        }))
    }

    fn releasable_input(&self) -> usize {
        self.st.consumed
    }

    fn release_input(&mut self, n: usize) {
        let st = &mut self.st;
        st.consumed = st.consumed.saturating_sub(n);
        st.start = st.start.saturating_sub(n);
        if let Some(cur) = &mut st.cur {
            cur.in_pos = cur.in_pos.saturating_sub(n);
            cur.end = cur.end.saturating_sub(n);
        }
    }

    /// The dictionary is kept apart, so no output is read again.
    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }
}

/// Undoes the EXE filter on `chunk` (which starts at output position `at`):
/// `E8` (CALL) targets are 16-bit or 32-bit (`exe_mode` 0 or not), `E9`
/// (JMP) targets 16-bit, stored relative-to-absolute. Returns the tail that
/// may hold an instruction completed by the next chunk (none for the last).
fn exe_filter(chunk: &mut Vec<u8>, at: usize, exe_mode: u32, last: bool) -> Vec<u8> {
    let len = chunk.len();
    let mut i = 0usize;
    while i.saturating_add(4) < len {
        let op = chunk.get(i).copied().unwrap_or(0);
        let pos = at.saturating_add(i);
        let wide = op == 0xe8 && exe_mode != 0;
        if op == 0xe8 || op == 0xe9 {
            let n = if wide { 4usize } else { 2 };
            let mut v = 0u32;
            for k in 0..n {
                let b = chunk
                    .get(i.saturating_add(1).saturating_add(k))
                    .copied()
                    .unwrap_or(0);
                v |= u32::from(b) << (k.saturating_mul(8));
            }
            let p = u32::try_from(pos & 0xffff_ffff).unwrap_or(0);
            let v = if wide {
                v.wrapping_sub(p)
            } else {
                v.wrapping_sub(p) & 0xffff
            };
            for k in 0..n {
                if let Some(slot) = chunk.get_mut(i.saturating_add(1).saturating_add(k)) {
                    *slot = (v >> (k.saturating_mul(8))) as u8;
                }
            }
            i = i.saturating_add(n).saturating_add(1);
        } else {
            i = i.saturating_add(1);
        }
    }
    if last {
        return Vec::new();
    }
    let hold = (i..len).find(|&j| matches!(chunk.get(j), Some(0xe8 | 0xe9)));
    match hold {
        Some(j) => chunk.split_off(j),
        None => Vec::new(),
    }
}

/// Decodes an archive or file comment (a length, a Huffman tree, and
/// literals or copies from the last place the same two-byte sum occurred).
pub fn comment(buf: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut bs = Bits::new(buf);
    let want = to_usize(u64::from(bs.read(15)?));
    let tree = Tree::read_from(&mut bs, LZ_MAX_WIDTH, NUM_MAIN)?;
    let mut out: Vec<u8> = Vec::new();
    let mut table = vec![0usize; 511];
    while out.len() < want {
        if out.len() > limit {
            return Err(too_big(limit));
        }
        let n = out.len();
        let source = if n > 1 {
            let h = usize::from(out.get(n.saturating_sub(1)).copied().unwrap_or(0)).saturating_add(
                usize::from(out.get(n.saturating_sub(2)).copied().unwrap_or(0)),
            );
            let s = table.get(h).copied().unwrap_or(0);
            if let Some(slot) = table.get_mut(h) {
                *slot = n;
            }
            s
        } else {
            0
        };
        let code = tree.read(&mut bs)?;
        if code < 256 {
            out.push(u8::try_from(code).unwrap_or(0));
        } else {
            let len = usize::from(code.saturating_sub(256)).saturating_add(2);
            for i in 0..len {
                let b = out
                    .get(source.saturating_add(i))
                    .copied()
                    .ok_or_else(|| bad("comment copy out of range"))?;
                out.push(b);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::bytes::{u16_le, u32_le};

    /// Whether the archive is solid, and each file with its packed data.
    fn members(archive: &[u8]) -> (bool, Vec<(Member, std::ops::Range<usize>)>) {
        let mut at = 0usize;
        let mut solid = false;
        let mut out = Vec::new();
        while at + 7 <= archive.len() {
            let size = usize::from(u16_le(archive, at + 2).unwrap());
            let kind = archive[at + 4];
            let flags = u16_le(archive, at + 5).unwrap();
            let end = at + 4 + size;
            if kind == 0 {
                solid = flags & 0x8000 != 0;
                at = end;
                continue;
            }
            let packed = u32_le(archive, at + 7).unwrap();
            let member = Member {
                packed: packed.into(),
                size: u32_le(archive, at + 11).unwrap().into(),
                crc: u32_le(archive, at + 23).unwrap(),
                method: archive[at + 27],
            };
            out.push((member, end..end + packed as usize));
            at = end + packed as usize;
        }
        (solid, out)
    }

    /// Decodes `members` from `input` in one go.
    fn decode(members: Vec<Member>, input: &[u8], limit: usize) -> Result<(Vec<u8>, bool)> {
        let mut d = Decoder::new(Params {
            members: members.into(),
        });
        let out = pipeline::decode_all(&mut d, input, limit)?;
        let ok = pipeline::Decoder::warning(&d, &out).is_none();
        Ok((out, ok))
    }

    fn check(archive: &[u8], count: usize) {
        let (solid, files) = members(archive);
        assert_eq!(files.len(), count);
        if solid {
            // The whole stream at once, and every prefix of it.
            let all: Vec<Member> = files.iter().map(|(m, _)| *m).collect();
            let input: Vec<u8> = files
                .iter()
                .flat_map(|(_, r)| archive[r.clone()].to_vec())
                .collect();
            let (out, ok) = decode(all.clone(), &input, 1 << 20).unwrap();
            assert!(ok, "CRC mismatch");
            let mut at = 0usize;
            for (i, (m, _)) in files.iter().enumerate() {
                let size = m.size as usize;
                assert_eq!(ace_crc32(&out[at..at + size]), m.crc, "member {i}");
                at += size;
                let packed: usize = files[..=i].iter().map(|(_, r)| r.len()).sum();
                let (prefix, ok) = decode(all[..=i].to_vec(), &input[..packed], 1 << 20).unwrap();
                assert!(ok);
                assert_eq!(prefix, out[..at]);
            }
            assert_eq!(at, out.len());
        } else {
            for (i, (m, range)) in files.iter().enumerate() {
                let (out, ok) = decode(vec![*m], &archive[range.clone()], 1 << 20).unwrap();
                assert_eq!(out.len() as u64, m.size, "member {i}");
                assert!(ok, "member {i}: CRC mismatch");
            }
        }
    }

    // The fixtures were written by tests/data/ace/make_ace.py and decoded
    // by acefile; the stored CRCs are of acefile's output.
    #[test]
    fn lz77_v1() {
        check(
            include_bytes!("../../../../tests/fixtures/synthetic/ace/lz77.ace"),
            2,
        );
    }

    #[test]
    fn blocked_modes() {
        check(
            include_bytes!("../../../../tests/fixtures/synthetic/ace/blocked.ace"),
            7,
        );
    }

    #[test]
    fn solid() {
        check(
            include_bytes!("../../../../tests/fixtures/synthetic/ace/solid.ace"),
            3,
        );
    }

    #[test]
    fn comment_and_crc() {
        assert_eq!(ace_crc32(b"123456789"), 873_187_033);
        let archive = include_bytes!("../../../../tests/fixtures/synthetic/ace/lz77.ace");
        let len = usize::from(u16_le(archive, 30).unwrap());
        let text = comment(&archive[32..32 + len], 1 << 16).unwrap();
        assert_eq!(text, b"Made by the fillyfoal test generator.");
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for method in [1u8, 2] {
            let params = Params {
                members: vec![Member {
                    packed: 64,
                    size: 1000,
                    method,
                    crc: 0,
                }]
                .into(),
            };
            for seed in 0..64u8 {
                let data: Vec<u8> = (0..64u8)
                    .map(|i| i.wrapping_mul(seed).wrapping_add(seed))
                    .collect();
                let mut d = Decoder::new(params.clone());
                let _ = pipeline::decode_all(&mut d, &data, 1 << 16);
            }
        }
    }
}
