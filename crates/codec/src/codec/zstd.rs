//! Zstandard decompression (RFC 8878): frames of raw, RLE and compressed
//! blocks; Huffman-coded literals; FSE-coded sequences with repeat offsets;
//! XXH64 content checksums; dictionaries (raw content, or the formatted
//! kind with entropy tables and repeat offsets) when the container has one.

use std::sync::Arc;

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("zstd: {what}"))
}

/// The input ends inside a frame: the decoder reports every shortage this
/// way, and only shortages (see [`Decode::truncation_is_exact`]).
fn short(what: &str) -> Diagnostic {
    Diagnostic::new(
        crate::error::DiagKind::Truncated,
        format!("zstd: truncated {what}"),
    )
}

fn le(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0u64, |a, &b| a << 8 | u64::from(b))
}

// ---------------------------------------------------------------------------
// Bit readers

/// Forward little-endian bit reader (FSE table descriptions).
struct Forward<'a> {
    data: &'a [u8],
    bit: usize,
}

impl Forward<'_> {
    fn peek(&self, n: u32) -> u32 {
        let byte = self.bit / 8;
        let window = le(self
            .data
            .get(byte..byte.saturating_add(8).min(self.data.len()))
            .unwrap_or_default());
        u32::try_from((window >> (self.bit % 8)) & (1u64 << n).wrapping_sub(1)).unwrap_or(0)
    }

    fn skip(&mut self, n: u32) {
        self.bit = self.bit.saturating_add(usize::try_from(n).unwrap_or(0));
    }
}

/// Backward bit reader: starts at the highest set bit of the last byte
/// (a padding marker) and reads towards the start.
struct Backward<'a> {
    data: &'a [u8],
    /// Bits left above position 0 (may go negative: an overflow).
    pos: i64,
}

impl<'a> Backward<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        let last = *data.last().ok_or_else(|| bad("empty bitstream"))?;
        if last == 0 {
            return Err(bad("bitstream without its end marker"));
        }
        let len = i64::try_from(data.len()).unwrap_or(i64::MAX);
        let pos = len
            .saturating_mul(8)
            .saturating_sub(i64::from(last.leading_zeros()))
            .saturating_sub(1);
        Ok(Backward { data, pos })
    }

    /// The `n` bits below the current position (zeros past the start), as
    /// one 8-byte window shifted into place. Callers read at most 31 bits;
    /// `n` is capped at 57, what a window holds from any bit offset.
    fn peek(&self, n: u32) -> u64 {
        let n = n.min(57);
        let start = self.pos.saturating_sub(i64::from(n));
        // Bits below position 0 read as zeros: take those from 0 up, then
        // shift them to where they belong.
        let missing = if start < 0 {
            u32::try_from(start.unsigned_abs()).unwrap_or(u32::MAX)
        } else {
            0
        };
        if missing >= n {
            return 0;
        }
        let avail = n.saturating_sub(missing);
        let from = usize::try_from(start.max(0)).unwrap_or(usize::MAX);
        let byte = from / 8;
        let window = match self
            .data
            .get(byte..byte.saturating_add(8))
            .and_then(|w| <[u8; 8]>::try_from(w).ok())
        {
            Some(w) => u64::from_le_bytes(w),
            None => le(self.data.get(byte..).unwrap_or_default()),
        };
        ((window >> (from % 8)) & (1u64 << avail).wrapping_sub(1)) << missing
    }

    fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.pos = self.pos.saturating_sub(i64::from(n));
        v
    }

    fn overflowed(&self) -> bool {
        self.pos < 0
    }
}

// ---------------------------------------------------------------------------
// FSE

#[derive(Clone, Copy, Default)]
struct Cell {
    symbol: u8,
    bits: u8,
    base: u16,
}

#[derive(Clone)]
struct Fse {
    log: u32,
    cells: Vec<Cell>,
}

impl Fse {
    fn build(counts: &[i16], log: u32) -> Result<Self> {
        let size = 1usize << log;
        let mut cells = vec![Cell::default(); size];
        let mut high = size.saturating_sub(1);
        let mut next = vec![0u32; counts.len()];
        for (s, (&c, slot)) in counts.iter().zip(next.iter_mut()).enumerate() {
            if c == -1 {
                cells
                    .get_mut(high)
                    .ok_or_else(|| bad("FSE table overflow"))?
                    .symbol = u8::try_from(s).unwrap_or(0);
                high = high.saturating_sub(1);
                *slot = 1;
            } else {
                *slot = u32::try_from(c.max(0)).unwrap_or(0);
            }
        }
        let step = (size >> 1).saturating_add(size >> 3).saturating_add(3);
        let mask = size.saturating_sub(1);
        let mut position = 0usize;
        for (s, &c) in counts.iter().enumerate() {
            for _ in 0..c.max(0) {
                cells
                    .get_mut(position)
                    .ok_or_else(|| bad("FSE table overflow"))?
                    .symbol = u8::try_from(s).unwrap_or(0);
                loop {
                    position = position.wrapping_add(step) & mask;
                    if position <= high {
                        break;
                    }
                }
            }
        }
        if position != 0 {
            return Err(bad("FSE table not filled"));
        }
        for cell in &mut cells {
            let n = next
                .get_mut(usize::from(cell.symbol))
                .ok_or_else(|| bad("FSE symbol"))?;
            let state = *n;
            *n = n.saturating_add(1);
            let high_bit = 31u32.saturating_sub(state.max(1).leading_zeros());
            let bits = log.saturating_sub(high_bit);
            cell.bits = u8::try_from(bits).unwrap_or(0);
            cell.base =
                u16::try_from((state << bits).saturating_sub(u32::try_from(size).unwrap_or(0)))
                    .unwrap_or(0);
        }
        Ok(Fse { log, cells })
    }

    fn rle(symbol: u8) -> Self {
        Fse {
            log: 0,
            cells: vec![Cell {
                symbol,
                bits: 0,
                base: 0,
            }],
        }
    }

    /// Reads a table description; returns the table and bytes consumed.
    fn read(data: &[u8], max_symbol: usize, max_log: u32) -> Result<(Self, usize)> {
        let mut r = Forward { data, bit: 0 };
        let log = r.peek(4).saturating_add(5);
        r.skip(4);
        if log > max_log {
            return Err(bad("FSE accuracy log too large"));
        }
        let mut remaining = (1i32 << log).saturating_add(1);
        let mut threshold = 1i32 << log;
        let mut bits = log.saturating_add(1);
        let mut counts: Vec<i16> = Vec::new();
        while remaining > 1 && counts.len() <= max_symbol {
            let max = threshold
                .saturating_mul(2)
                .saturating_sub(1)
                .saturating_sub(remaining);
            let low = i32::try_from(r.peek(bits.saturating_sub(1))).unwrap_or(0);
            let mut count;
            if low < max {
                count = low;
                r.skip(bits.saturating_sub(1));
            } else {
                count = i32::try_from(r.peek(bits)).unwrap_or(0);
                if count >= threshold {
                    count = count.saturating_sub(max);
                }
                r.skip(bits);
            }
            count = count.saturating_sub(1);
            remaining = remaining.saturating_sub(count.abs());
            counts.push(i16::try_from(count).map_err(|_| bad("FSE count"))?);
            if count == 0 {
                // Repeat flags: runs of zero-probability symbols.
                loop {
                    let repeat = r.peek(2);
                    r.skip(2);
                    counts.resize(
                        counts
                            .len()
                            .saturating_add(usize::try_from(repeat).unwrap_or(0)),
                        0,
                    );
                    if repeat != 3 || counts.len() > max_symbol {
                        break;
                    }
                }
            }
            while remaining < threshold && threshold > 1 {
                bits = bits.saturating_sub(1);
                threshold >>= 1;
            }
        }
        if remaining != 1 || counts.len() > max_symbol.saturating_add(1) {
            return Err(bad("invalid FSE table description"));
        }
        Ok((Fse::build(&counts, log)?, r.bit.div_ceil(8)))
    }

    fn init(&self, r: &mut Backward<'_>) -> usize {
        usize::try_from(r.read(self.log)).unwrap_or(0)
    }

    fn symbol(&self, state: usize) -> u8 {
        self.cells.get(state).map_or(0, |c| c.symbol)
    }

    fn update(&self, state: &mut usize, r: &mut Backward<'_>) {
        let cell = self.cells.get(*state).copied().unwrap_or_default();
        *state = usize::from(cell.base)
            .wrapping_add(usize::try_from(r.read(cell.bits.into())).unwrap_or(0));
    }
}

const LL_DEFAULT: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const ML_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

const LL_BASE: [(u32, u32); 36] = [
    (0, 0),
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 1),
    (18, 1),
    (20, 1),
    (22, 1),
    (24, 2),
    (28, 2),
    (32, 3),
    (40, 3),
    (48, 4),
    (64, 6),
    (128, 7),
    (256, 8),
    (512, 9),
    (1024, 10),
    (2048, 11),
    (4096, 12),
    (8192, 13),
    (16384, 14),
    (32768, 15),
    (65536, 16),
];
const ML_BASE: [(u32, u32); 53] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 0),
    (17, 0),
    (18, 0),
    (19, 0),
    (20, 0),
    (21, 0),
    (22, 0),
    (23, 0),
    (24, 0),
    (25, 0),
    (26, 0),
    (27, 0),
    (28, 0),
    (29, 0),
    (30, 0),
    (31, 0),
    (32, 0),
    (33, 0),
    (34, 0),
    (35, 1),
    (37, 1),
    (39, 1),
    (41, 1),
    (43, 2),
    (47, 2),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 5),
    (131, 7),
    (259, 8),
    (515, 9),
    (1027, 10),
    (2051, 11),
    (4099, 12),
    (8195, 13),
    (16387, 14),
    (32771, 15),
    (65539, 16),
];

// ---------------------------------------------------------------------------
// Huffman (literals)

#[derive(Clone)]
struct Huffman {
    max_bits: u32,
    /// (symbol, bits) for every `max_bits`-bit prefix.
    table: Vec<(u8, u8)>,
}

impl Huffman {
    fn from_weights(mut weights: Vec<u8>) -> Result<Self> {
        let total: u32 = weights
            .iter()
            .filter(|&&w| w > 0)
            .map(|&w| 1u32 << (w.saturating_sub(1)))
            .sum();
        if total == 0 {
            return Err(bad("empty Huffman weights"));
        }
        let max_bits = 32u32.saturating_sub(total.leading_zeros());
        if max_bits > 11 {
            return Err(bad("Huffman code too long"));
        }
        let left = (1u32 << max_bits).saturating_sub(total);
        if !left.is_power_of_two() {
            return Err(bad("Huffman weights do not complete a tree"));
        }
        weights.push(u8::try_from(32u32.saturating_sub(left.leading_zeros())).unwrap_or(0));
        let size = 1usize << max_bits;
        let mut table = vec![(0u8, 0u8); size];
        // Lowest weights (longest codes) first.
        let mut next = 0usize;
        for w in 1..=u8::try_from(max_bits).unwrap_or(11) {
            for (s, &sw) in weights.iter().enumerate() {
                if sw != w {
                    continue;
                }
                let len = 1usize << (w.saturating_sub(1));
                let bits = u8::try_from(max_bits.saturating_add(1).saturating_sub(u32::from(w)))
                    .unwrap_or(0);
                for slot in table
                    .get_mut(next..next.saturating_add(len))
                    .ok_or_else(|| bad("Huffman table overflow"))?
                {
                    *slot = (u8::try_from(s).unwrap_or(0), bits);
                }
                next = next.saturating_add(len);
            }
        }
        Ok(Huffman { max_bits, table })
    }

    /// Reads a tree description; returns the tree and bytes consumed.
    fn read(data: &[u8]) -> Result<(Self, usize)> {
        let header = usize::from(*data.first().ok_or_else(|| bad("missing Huffman tree"))?);
        if header >= 128 {
            let n = header.saturating_sub(127);
            let bytes = data
                .get(1..1usize.saturating_add(n.div_ceil(2)))
                .ok_or_else(|| bad("truncated Huffman weights"))?;
            let weights: Vec<u8> = bytes
                .iter()
                .flat_map(|&b| [b >> 4, b & 0x0f])
                .take(n)
                .collect();
            return Ok((
                Huffman::from_weights(weights)?,
                1usize.saturating_add(n.div_ceil(2)),
            ));
        }
        let body = data
            .get(1..1usize.saturating_add(header))
            .ok_or_else(|| bad("truncated Huffman weights"))?;
        let (fse, used) = Fse::read(body, 255, 6)?;
        let mut r = Backward::new(body.get(used..).unwrap_or_default())?;
        let mut s1 = fse.init(&mut r);
        let mut s2 = fse.init(&mut r);
        let mut weights = Vec::new();
        loop {
            if weights.len() >= 255 {
                return Err(bad("too many Huffman weights"));
            }
            weights.push(fse.symbol(s1));
            fse.update(&mut s1, &mut r);
            if r.overflowed() {
                weights.push(fse.symbol(s2));
                break;
            }
            weights.push(fse.symbol(s2));
            fse.update(&mut s2, &mut r);
            if r.overflowed() {
                weights.push(fse.symbol(s1));
                break;
            }
        }
        Ok((
            Huffman::from_weights(weights)?,
            1usize.saturating_add(header),
        ))
    }

    fn decode_stream(&self, data: &[u8], count: usize, out: &mut Vec<u8>) -> Result<()> {
        // One window of the 57 bits below the position serves several
        // symbols (codes are at most 11 bits): each symbol's prefix is the
        // window's top `max_bits` bits below those already used, exactly
        // what peeking at the moved position would return.
        const WINDOW: u32 = 57;
        let mut r = Backward::new(data)?;
        let mask = (1u64 << self.max_bits).wrapping_sub(1);
        out.reserve(count);
        let mut left = count;
        while left > 0 {
            let window = r.peek(WINDOW);
            let mut used = 0u32;
            while left > 0 && used.saturating_add(self.max_bits) <= WINDOW {
                let shift = WINDOW.saturating_sub(used).saturating_sub(self.max_bits);
                let idx = usize::try_from((window >> shift) & mask).unwrap_or(0);
                let &(symbol, bits) = self.table.get(idx).ok_or_else(|| bad("Huffman index"))?;
                out.push(symbol);
                used = used.saturating_add(u32::from(bits));
                left = left.saturating_sub(1);
            }
            r.pos = r.pos.saturating_sub(i64::from(used));
        }
        if r.pos != 0 {
            return Err(bad("Huffman stream not fully consumed"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Frames and blocks

/// State that persists between the blocks of a frame.
#[derive(Clone)]
struct FrameState {
    huffman: Option<Huffman>,
    ll: Option<Fse>,
    of: Option<Fse>,
    ml: Option<Fse>,
    reps: [usize; 3],
}

impl FrameState {
    /// The state a frame starts with: no tables, the default repeat
    /// offsets.
    fn fresh() -> Self {
        FrameState {
            huffman: None,
            ll: None,
            of: None,
            ml: None,
            reps: [1, 4, 8],
        }
    }
}

// ---------------------------------------------------------------------------
// Dictionaries

/// The magic number of a formatted dictionary.
pub const DICT_MAGIC: u32 = 0xec30_a437;

/// A zstd dictionary (RFC 8878 §5): content that frames may reach back
/// into as if it preceded them and, in a formatted dictionary, the entropy
/// tables and repeat offsets frames start with.
pub struct Dictionary {
    /// The Dictionary_ID (0 for raw content).
    pub id: u32,
    /// Where the parts of a formatted dictionary lie in its bytes.
    pub layout: Option<DictLayout>,
    content: Vec<u8>,
    st: FrameState,
}

/// The parts of a formatted dictionary, as offsets into its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DictLayout {
    /// Huffman tree description of the literals.
    pub huffman: (usize, usize),
    /// FSE table descriptions: offsets, match lengths, literal lengths.
    pub offsets: (usize, usize),
    pub match_lengths: (usize, usize),
    pub literal_lengths: (usize, usize),
    /// The three repeat offsets (12 bytes).
    pub reps_at: usize,
    /// Where the content starts (it runs to the end).
    pub content_at: usize,
}

impl Dictionary {
    /// A dictionary from its bytes: a formatted one if they start with
    /// [`DICT_MAGIC`], otherwise raw content. Bounded work: the tables are
    /// small and the content is only copied.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.get(..4).map(le) != Some(u64::from(DICT_MAGIC)) {
            return Ok(Dictionary {
                id: 0,
                layout: None,
                content: bytes.to_vec(),
                st: FrameState::fresh(),
            });
        }
        let (id, layout, st) = formatted(bytes, bytes.len())?;
        Ok(Dictionary {
            id,
            layout: Some(layout),
            content: bytes.get(layout.content_at..).unwrap_or_default().to_vec(),
            st,
        })
    }

    /// The ID, layout and repeat offsets of a formatted dictionary of
    /// `total` bytes, from its first bytes (the tables and repeat offsets
    /// fit in [`DICT_HEADER_MAX`]).
    pub fn header(head: &[u8], total: usize) -> Result<(u32, DictLayout, [usize; 3])> {
        if head.get(..4).map(le) != Some(u64::from(DICT_MAGIC)) {
            return Err(bad("not a formatted dictionary"));
        }
        let (id, layout, st) = formatted(head, total)?;
        Ok((id, layout, st.reps))
    }

    /// The content frames reach back into.
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// The repeat offsets frames start with.
    pub fn reps(&self) -> [usize; 3] {
        self.st.reps
    }
}

/// The most bytes a formatted dictionary's header (magic, ID, entropy
/// tables, repeat offsets) can take.
pub const DICT_HEADER_MAX: usize = 1024;

/// Parses a formatted dictionary's header from `bytes` (at least its
/// header), the whole dictionary being `total` bytes long.
fn formatted(bytes: &[u8], total: usize) -> Result<(u32, DictLayout, FrameState)> {
    let id = u32::try_from(le(bytes
        .get(4..8)
        .ok_or_else(|| bad("truncated dictionary"))?))
    .unwrap_or(0);
    let rest = |at: usize| bytes.get(at..).unwrap_or_default();
    let mut at = 8usize;
    let (huffman, used) = Huffman::read(rest(at))?;
    let huffman_at = (at, at.saturating_add(used));
    at = huffman_at.1;
    let mut fse = |max_symbol: usize, max_log: u32| -> Result<(Fse, (usize, usize))> {
        let (t, used) = Fse::read(rest(at), max_symbol, max_log)?;
        let span = (at, at.saturating_add(used));
        at = span.1;
        Ok((t, span))
    };
    let (of, of_at) = fse(31, 8)?;
    let (ml, ml_at) = fse(52, 9)?;
    let (ll, ll_at) = fse(35, 9)?;
    let reps_at = at;
    let reps_bytes = bytes
        .get(at..at.saturating_add(12))
        .ok_or_else(|| bad("truncated dictionary"))?;
    let content_at = at.saturating_add(12);
    let content_len = total.saturating_sub(content_at);
    let mut reps = [0usize; 3];
    for (r, b) in reps.iter_mut().zip(reps_bytes.chunks(4)) {
        *r = usize::try_from(le(b)).unwrap_or(usize::MAX);
        if *r == 0 || *r > content_len {
            return Err(bad("dictionary repeat offset outside its content"));
        }
    }
    let layout = DictLayout {
        huffman: huffman_at,
        offsets: of_at,
        match_lengths: ml_at,
        literal_lengths: ll_at,
        reps_at,
        content_at,
    };
    let st = FrameState {
        huffman: Some(huffman),
        ll: Some(ll),
        of: Some(of),
        ml: Some(ml),
        reps,
    };
    Ok((id, layout, st))
}

/// A shared [`Dictionary`] as a codec parameter; equal when it is the same
/// dictionary (same ID and content).
#[derive(Clone)]
pub struct Dict(pub Arc<Dictionary>);

impl PartialEq for Dict {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
            || (self.0.id == other.0.id
                && self.0.layout == other.0.layout
                && self.0.content == other.0.content)
    }
}

impl Eq for Dict {}

impl std::fmt::Debug for Dict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Dict(id {}, {} bytes of content)",
            self.0.id,
            self.0.content.len()
        )
    }
}

fn literals(block: &[u8], st: &mut FrameState) -> Result<(Vec<u8>, usize)> {
    let b0 = *block.first().ok_or_else(|| bad("empty block"))?;
    let kind = b0 & 3;
    let format = (b0 >> 2) & 3;
    let byte = |i: usize| usize::from(block.get(i).copied().unwrap_or(0));
    if kind < 2 {
        let (size, header) = match format {
            0 | 2 => (usize::from(b0 >> 3), 1usize),
            1 => (usize::from(b0 >> 4) | byte(1) << 4, 2),
            _ => (usize::from(b0 >> 4) | byte(1) << 4 | byte(2) << 12, 3),
        };
        if kind == 0 {
            let lit = block
                .get(header..header.saturating_add(size))
                .ok_or_else(|| bad("truncated literals"))?;
            return Ok((lit.to_vec(), header.saturating_add(size)));
        }
        let b = *block.get(header).ok_or_else(|| bad("truncated literals"))?;
        return Ok((vec![b; size], header.saturating_add(1)));
    }
    let (header, regen, compressed, streams) = match format {
        0 | 1 => {
            let h = le(block.get(..3).unwrap_or_default());
            (
                3usize,
                (h >> 4) & 0x3ff,
                (h >> 14) & 0x3ff,
                if format == 0 { 1 } else { 4 },
            )
        }
        2 => {
            let h = le(block.get(..4).unwrap_or_default());
            (4, (h >> 4) & 0x3fff, (h >> 18) & 0x3fff, 4)
        }
        _ => {
            let h = le(block.get(..5).unwrap_or_default());
            (5, (h >> 4) & 0x3_ffff, (h >> 22) & 0x3_ffff, 4)
        }
    };
    let regen = usize::try_from(regen).unwrap_or(0);
    let compressed = usize::try_from(compressed).unwrap_or(0);
    let mut data = block
        .get(header..header.saturating_add(compressed))
        .ok_or_else(|| bad("truncated literals"))?;
    if kind == 2 {
        let (tree, used) = Huffman::read(data)?;
        st.huffman = Some(tree);
        data = data.get(used..).unwrap_or_default();
    }
    let tree = st
        .huffman
        .as_ref()
        .ok_or_else(|| bad("treeless literals without a previous tree"))?;
    let mut out = Vec::with_capacity(regen);
    if streams == 1 {
        tree.decode_stream(data, regen, &mut out)?;
    } else {
        let jump = data.get(..6).ok_or_else(|| bad("truncated jump table"))?;
        let sizes = [
            le(jump.get(0..2).unwrap_or_default()),
            le(jump.get(2..4).unwrap_or_default()),
            le(jump.get(4..6).unwrap_or_default()),
        ];
        let each = regen.div_ceil(4);
        let mut pos = 6usize;
        for (i, &size) in sizes.iter().enumerate() {
            let size = usize::try_from(size).unwrap_or(0);
            let s = data
                .get(pos..pos.saturating_add(size))
                .ok_or_else(|| bad("truncated literal stream"))?;
            tree.decode_stream(s, each, &mut out)?;
            pos = pos.saturating_add(size);
            let _ = i;
        }
        let last = regen.saturating_sub(each.saturating_mul(3));
        tree.decode_stream(data.get(pos..).unwrap_or_default(), last, &mut out)?;
    }
    Ok((out, header.saturating_add(compressed)))
}

/// A sequence table per its compression mode.
fn table(
    mode: u8,
    data: &[u8],
    prev: Option<Fse>,
    default: &[i16],
    default_log: u32,
    max_symbol: usize,
    max_log: u32,
) -> Result<(Fse, usize)> {
    match mode {
        0 => Ok((Fse::build(default, default_log)?, 0)),
        1 => Ok((
            Fse::rle(*data.first().ok_or_else(|| bad("missing RLE symbol"))?),
            1,
        )),
        2 => Fse::read(data, max_symbol, max_log),
        _ => Ok((
            prev.ok_or_else(|| bad("repeat mode without a previous table"))?,
            0,
        )),
    }
}

fn compressed_block(
    block: &[u8],
    st: &mut FrameState,
    out: &mut Vec<u8>,
    frame_start: usize,
    window: usize,
    limit: usize,
    dict: &[u8],
) -> Result<()> {
    let (lits, mut pos) = literals(block, st)?;
    let b0 = usize::from(
        *block
            .get(pos)
            .ok_or_else(|| bad("missing sequence count"))?,
    );
    let byte = |i: usize| usize::from(block.get(i).copied().unwrap_or(0));
    let count = match b0 {
        0 => {
            out.extend_from_slice(&lits);
            return Ok(());
        }
        1..=127 => {
            pos = pos.saturating_add(1);
            b0
        }
        128..=254 => {
            let n = (b0.saturating_sub(128) << 8) | byte(pos.saturating_add(1));
            pos = pos.saturating_add(2);
            n
        }
        _ => {
            let n = byte(pos.saturating_add(1)) | byte(pos.saturating_add(2)) << 8;
            pos = pos.saturating_add(3);
            n.saturating_add(0x7f00)
        }
    };
    let modes = *block.get(pos).ok_or_else(|| bad("missing modes"))?;
    pos = pos.saturating_add(1);
    let (ll, used) = table(
        modes >> 6,
        block.get(pos..).unwrap_or_default(),
        st.ll.take(),
        &LL_DEFAULT,
        6,
        35,
        9,
    )?;
    pos = pos.saturating_add(used);
    let (of, used) = table(
        modes >> 4 & 3,
        block.get(pos..).unwrap_or_default(),
        st.of.take(),
        &OF_DEFAULT,
        5,
        31,
        8,
    )?;
    pos = pos.saturating_add(used);
    let (ml, used) = table(
        modes >> 2 & 3,
        block.get(pos..).unwrap_or_default(),
        st.ml.take(),
        &ML_DEFAULT,
        6,
        52,
        9,
    )?;
    pos = pos.saturating_add(used);
    let mut r = Backward::new(block.get(pos..).unwrap_or_default())?;
    let mut ll_state = ll.init(&mut r);
    let mut of_state = of.init(&mut r);
    let mut ml_state = ml.init(&mut r);
    let mut lit_pos = 0usize;
    for i in 0..count {
        let of_code = u32::from(of.symbol(of_state));
        let ml_code = usize::from(ml.symbol(ml_state));
        let ll_code = usize::from(ll.symbol(ll_state));
        if of_code > 31 {
            return Err(bad("offset code too large"));
        }
        let offset_value =
            usize::try_from((1u64 << of_code).wrapping_add(r.read(of_code))).unwrap_or(usize::MAX);
        let &(ml_base, ml_bits) = ML_BASE
            .get(ml_code)
            .ok_or_else(|| bad("match length code"))?;
        let match_len =
            usize::try_from(u64::from(ml_base).wrapping_add(r.read(ml_bits))).unwrap_or(0);
        let &(ll_base, ll_bits) = LL_BASE
            .get(ll_code)
            .ok_or_else(|| bad("literal length code"))?;
        let lit_len =
            usize::try_from(u64::from(ll_base).wrapping_add(r.read(ll_bits))).unwrap_or(0);
        if i.saturating_add(1) < count {
            ll.update(&mut ll_state, &mut r);
            ml.update(&mut ml_state, &mut r);
            of.update(&mut of_state, &mut r);
        }
        // Repeat offsets.
        let [r1, r2, r3] = st.reps;
        let offset = if offset_value > 3 {
            let o = offset_value.saturating_sub(3);
            st.reps = [o, r1, r2];
            o
        } else {
            let index = if lit_len == 0 {
                offset_value.saturating_add(1)
            } else {
                offset_value
            };
            match index {
                1 => r1,
                2 => {
                    st.reps = [r2, r1, r3];
                    r2
                }
                3 => {
                    st.reps = [r3, r1, r2];
                    r3
                }
                _ => {
                    let o = r1.saturating_sub(1);
                    st.reps = [o, r1, r2];
                    o
                }
            }
        };
        let lit = lits
            .get(lit_pos..lit_pos.saturating_add(lit_len))
            .ok_or_else(|| bad("literals overrun"))?;
        out.extend_from_slice(lit);
        lit_pos = lit_pos.saturating_add(lit_len);
        // The frame's output so far (or, once released, at least its
        // window); a match reaching further back continues into the
        // dictionary's content, as if it preceded the frame.
        let avail = out.len().saturating_sub(frame_start);
        let before = offset.saturating_sub(avail);
        if offset == 0
            || (before == 0 && offset > window)
            || before > dict.len()
            || (before > 0 && dict.is_empty())
        {
            return Err(bad("match offset beyond the window"));
        }
        if out.len().saturating_add(match_len) > limit {
            return Err(Diagnostic::output_limit(limit));
        }
        let from_dict = before.min(match_len);
        let start = dict.len().saturating_sub(before);
        out.extend_from_slice(
            dict.get(start..start.saturating_add(from_dict))
                .unwrap_or_default(),
        );
        // The rest repeats the output from `offset` back. Copying what is
        // there, doubling as it grows, gives the same bytes as copying one
        // at a time (an overlapping match is periodic with that offset).
        let from = out.len().saturating_sub(offset);
        let mut left = match_len.saturating_sub(from_dict);
        while left > 0 {
            let n = left.min(out.len().saturating_sub(from));
            if n == 0 {
                return Err(bad("match offset beyond the output"));
            }
            out.extend_from_within(from..from.saturating_add(n));
            left = left.saturating_sub(n);
        }
    }
    out.extend_from_slice(lits.get(lit_pos..).unwrap_or_default());
    st.ll = Some(ll);
    st.of = Some(of);
    st.ml = Some(ml);
    Ok(())
}

const P1: u64 = 0x9e37_79b1_85eb_ca87;
const P2: u64 = 0xc2b2_ae3d_27d4_eb4f;
const P3: u64 = 0x1656_67b1_9e37_79f9;
const P4: u64 = 0x85eb_ca77_c2b2_ae63;
const P5: u64 = 0x27d4_eb2f_1656_67c5;

fn xxh_round(acc: u64, v: u64) -> u64 {
    acc.wrapping_add(v.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

/// Incremental XXH64 (for content checksums).
#[derive(Clone)]
pub struct Xxh64 {
    seed: u64,
    lanes: [u64; 4],
    /// A partial 32-byte stripe.
    buf: [u8; 32],
    buffered: usize,
    total: u64,
}

impl Xxh64 {
    pub fn new(seed: u64) -> Self {
        Xxh64 {
            seed,
            lanes: [
                seed.wrapping_add(P1).wrapping_add(P2),
                seed.wrapping_add(P2),
                seed,
                seed.wrapping_sub(P1),
            ],
            buf: [0; 32],
            buffered: 0,
            total: 0,
        }
    }

    fn stripe(&mut self, stripe: &[u8; 32]) {
        for (acc, lane) in self.lanes.iter_mut().zip(stripe.as_chunks::<8>().0) {
            *acc = xxh_round(*acc, u64::from_le_bytes(*lane));
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self
            .total
            .wrapping_add(u64::try_from(data.len()).unwrap_or(0));
        if self.buffered > 0 {
            let take = 32usize.saturating_sub(self.buffered).min(data.len());
            if let (Some(dst), Some(src)) = (
                self.buf
                    .get_mut(self.buffered..self.buffered.saturating_add(take)),
                data.get(..take),
            ) {
                dst.copy_from_slice(src);
            }
            self.buffered = self.buffered.saturating_add(take);
            data = data.get(take..).unwrap_or_default();
            if self.buffered < 32 {
                return;
            }
            let full = self.buf;
            self.stripe(&full);
            self.buffered = 0;
        }
        let (stripes, rest) = data.as_chunks::<32>();
        for stripe in stripes {
            self.stripe(stripe);
        }
        if let Some(dst) = self.buf.get_mut(..rest.len()) {
            dst.copy_from_slice(rest);
        }
        self.buffered = rest.len();
    }

    pub fn finish(&self) -> u64 {
        let merge = |acc: u64, v: u64| (acc ^ xxh_round(0, v)).wrapping_mul(P1).wrapping_add(P4);
        let mut h;
        if self.total >= 32 {
            let [a, b, c, d] = self.lanes;
            h = a
                .rotate_left(1)
                .wrapping_add(b.rotate_left(7))
                .wrapping_add(c.rotate_left(12))
                .wrapping_add(d.rotate_left(18));
            for lane in self.lanes {
                h = merge(h, lane);
            }
        } else {
            h = self.seed.wrapping_add(P5);
        }
        h = h.wrapping_add(self.total);
        let rest = self.buf.get(..self.buffered).unwrap_or_default();
        let (words, rest) = rest.as_chunks::<8>();
        for w in words {
            h = (h ^ xxh_round(0, u64::from_le_bytes(*w)))
                .rotate_left(27)
                .wrapping_mul(P1)
                .wrapping_add(P4);
        }
        let (quads, bytes) = rest.as_chunks::<4>();
        for q in quads {
            h = (h ^ u64::from(u32::from_le_bytes(*q)).wrapping_mul(P1))
                .rotate_left(23)
                .wrapping_mul(P2)
                .wrapping_add(P3);
        }
        for &b in bytes {
            h = (h ^ u64::from(b).wrapping_mul(P5))
                .rotate_left(11)
                .wrapping_mul(P1);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(P2);
        h ^= h >> 29;
        h = h.wrapping_mul(P3);
        h ^ (h >> 32)
    }
}

/// XXH64 of a whole buffer.
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let mut h = Xxh64::new(seed);
    h.update(data);
    h.finish()
}

/// The frame being decoded.
#[derive(Clone)]
struct Frame {
    /// Where the frame's output starts in `out` (its window starts there);
    /// 0 once output from the frame's start has been released.
    start: usize,
    /// The window size: how far back matches may reach.
    window: usize,
    /// Bytes the frame has produced so far.
    produced: u64,
    /// The content checksum, if the frame has one.
    hash: Option<Xxh64>,
    /// The declared content size.
    size: Option<u64>,
    st: FrameState,
}

/// Zstandard frames (and skippable frames), concatenated; or, in
/// single-frame mode, exactly one frame (after any skippable frames).
/// Decoded a block at a time.
#[derive(Clone)]
pub struct Zstd {
    /// Input consumed (always at a frame or block boundary).
    pos: usize,
    /// Zstandard (not skippable) frames started.
    frames: u32,
    frame: Option<Frame>,
    single: bool,
    done: bool,
    dict: Option<Dict>,
}

impl Zstd {
    /// Concatenated frames, until the input ends or something else follows.
    pub fn new() -> Self {
        Zstd {
            pos: 0,
            frames: 0,
            frame: None,
            single: false,
            done: false,
            dict: None,
        }
    }

    /// Concatenated frames that may use `dict`: frames naming no
    /// dictionary, or naming its ID, start from it.
    pub fn with_dictionary(dict: Dict) -> Self {
        Zstd {
            dict: Some(dict),
            ..Zstd::new()
        }
    }

    /// One frame; whatever follows it is left unconsumed.
    pub fn single_frame() -> Self {
        Zstd {
            single: true,
            ..Zstd::new()
        }
    }

    /// Starts a frame (or skips a skippable one) at `self.pos`.
    fn start_frame(&mut self, input: &[u8], eof: bool, out: &[u8]) -> Result<()> {
        let pos = self.pos;
        let Some(magic) = input.get(pos..pos.saturating_add(4)).map(le) else {
            if !eof {
                return Err(short("frame magic"));
            }
            if self.single && self.frames == 0 {
                return Err(bad("missing frame"));
            }
            // Fewer than four bytes left: not another frame.
            self.done = true;
            return Ok(());
        };
        if magic & 0xffff_fff0 == 0x184d_2a50 {
            let len = input
                .get(pos.saturating_add(4)..pos.saturating_add(8))
                .map(le);
            let end = len.map(|len| {
                pos.saturating_add(8)
                    .saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
            });
            match end {
                Some(end) if end <= input.len() => self.pos = end,
                _ if !eof => return Err(short("skippable frame")),
                _ => {
                    self.pos = input.len();
                    if self.single && self.frames == 0 {
                        return Err(bad("missing frame"));
                    }
                    self.done = true;
                }
            }
            return Ok(());
        }
        if magic != 0xfd2f_b528 {
            if self.frames == 0 {
                return Err(bad("not a zstd frame"));
            }
            self.done = true;
            return Ok(());
        }
        let mut at = pos.saturating_add(4);
        let fhd = *input.get(at).ok_or_else(|| short("frame header"))?;
        at = at.saturating_add(1);
        let single = fhd & 0x20 != 0;
        let dict_len = match fhd & 3 {
            0 => 0usize,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        let fcs_len = match fhd >> 6 {
            0 => usize::from(single),
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let mut window = None;
        if !single {
            let wd = *input.get(at).ok_or_else(|| short("frame header"))?;
            let base = 1u64 << (10u32.saturating_add(u32::from(wd >> 3)));
            let add = (base / 8).saturating_mul(u64::from(wd & 7));
            window = Some(base.saturating_add(add));
            at = at.saturating_add(1);
        }
        let dict = le(input
            .get(at..at.saturating_add(dict_len))
            .ok_or_else(|| short("frame header"))?);
        let dict = u32::try_from(dict).unwrap_or(u32::MAX);
        let st = match &self.dict {
            Some(d) if dict == 0 || dict == d.0.id => d.0.st.clone(),
            _ if dict != 0 => {
                return Err(Diagnostic::unsupported(format!(
                    "zstd frame using a dictionary (ID {dict}) that is not available"
                )));
            }
            _ => FrameState::fresh(),
        };
        at = at.saturating_add(dict_len);
        let fcs = le(input
            .get(at..at.saturating_add(fcs_len))
            .ok_or_else(|| short("frame header"))?);
        at = at.saturating_add(fcs_len);
        let size = match fcs_len {
            0 => None,
            2 => Some(fcs.saturating_add(256)),
            _ => Some(fcs),
        };
        // A single-segment frame's window is its content size.
        let window = window
            .or(size)
            .map_or(usize::MAX, |w| usize::try_from(w).unwrap_or(usize::MAX));
        self.frames = self.frames.saturating_add(1);
        self.pos = at;
        self.frame = Some(Frame {
            start: out.len(),
            window,
            produced: 0,
            hash: (fhd & 0x04 != 0).then(|| Xxh64::new(0)),
            size,
            st,
        });
        Ok(())
    }

    /// Decodes the frame's next block (and its end, after the last one).
    fn block(&mut self, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
        let Some(frame) = self.frame.as_mut() else {
            return Ok(());
        };
        let mut pos = self.pos;
        let h = le(input
            .get(pos..pos.saturating_add(3))
            .ok_or_else(|| short("block header"))?);
        pos = pos.saturating_add(3);
        let last = h & 1 != 0;
        let kind = (h >> 1) & 3;
        let size = usize::try_from(h >> 3).unwrap_or(0);
        let before = out.len();
        match kind {
            0 => {
                let body = input
                    .get(pos..pos.saturating_add(size))
                    .ok_or_else(|| short("raw block"))?;
                if before.saturating_add(size) > limit {
                    return Err(Diagnostic::output_limit(limit));
                }
                out.extend_from_slice(body);
            }
            1 => {
                let b = *input.get(pos).ok_or_else(|| short("RLE block"))?;
                if before.saturating_add(size) > limit {
                    return Err(Diagnostic::output_limit(limit));
                }
                out.resize(before.saturating_add(size), b);
            }
            2 => {
                let block = input
                    .get(pos..pos.saturating_add(size))
                    .ok_or_else(|| short("compressed block"))?;
                // The dictionary is valid until the frame has produced a
                // window's worth (and until then none of the frame's output
                // has been released, so it directly precedes the frame).
                let window = u64::try_from(frame.window).unwrap_or(u64::MAX);
                let dict = match &self.dict {
                    Some(d) if frame.produced <= window => d.0.content(),
                    _ => &[],
                };
                compressed_block(
                    block,
                    &mut frame.st,
                    out,
                    frame.start,
                    frame.window,
                    limit,
                    dict,
                )?;
            }
            _ => return Err(bad("reserved block type")),
        }
        if out.len() > limit {
            return Err(Diagnostic::output_limit(limit));
        }
        let block_out = out.get(before..).unwrap_or_default();
        frame.produced = frame
            .produced
            .saturating_add(u64::try_from(block_out.len()).unwrap_or(u64::MAX));
        if let Some(hash) = frame.hash.as_mut() {
            hash.update(block_out);
        }
        pos = pos.saturating_add(if kind == 1 { 1 } else { size });
        if last {
            if frame.size.is_some_and(|size| frame.produced != size) {
                return Err(bad("frame content size mismatch"));
            }
            if let Some(hash) = &frame.hash {
                let stored = le(input
                    .get(pos..pos.saturating_add(4))
                    .ok_or_else(|| short("checksum"))?);
                if hash.finish() & 0xffff_ffff != stored {
                    return Err(bad("content checksum mismatch"));
                }
                pos = pos.saturating_add(4);
            }
            self.frame = None;
            if self.single {
                self.done = true;
            }
        }
        self.pos = pos;
        Ok(())
    }
}

impl Default for Zstd {
    fn default() -> Self {
        Zstd::new()
    }
}

impl Decode for Zstd {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let target = out.len().saturating_add(step.max(1));
        loop {
            if self.done {
                return Ok(Step::Done);
            }
            if out.len() >= target {
                return Ok(Step::More);
            }
            if self.frame.is_some() {
                self.block(input, out, limit)?;
            } else {
                self.start_frame(input, eof, out)?;
            }
        }
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn releasable_input(&self) -> usize {
        // Always at a frame or block boundary.
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Earlier frames are done with; the current one reaches back at
        // most its window.
        match &self.frame {
            None => out_len,
            Some(frame) => out_len
                .saturating_sub(frame.window)
                .max(frame.start)
                .min(out_len),
        }
    }

    fn release_output(&mut self, n: usize) {
        if let Some(frame) = self.frame.as_mut() {
            frame.start = frame.start.saturating_sub(n);
        }
    }

    /// The frame's tables (the Huffman tree and the three FSE tables kept
    /// for treeless literals and repeat modes); the window is the caller's
    /// output, and nothing at all is kept between frames.
    fn heap_size(&self) -> Option<usize> {
        let Some(frame) = &self.frame else {
            return Some(0);
        };
        let st = &frame.st;
        let fse = |t: &Option<Fse>| {
            t.as_ref().map_or(0, |t| {
                t.cells
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Cell>())
            })
        };
        let huffman = st.huffman.as_ref().map_or(0, |h| {
            h.table
                .capacity()
                .saturating_mul(std::mem::size_of::<(u8, u8)>())
        });
        Some(
            huffman
                .saturating_add(fse(&st.ll))
                .saturating_add(fse(&st.of))
                .saturating_add(fse(&st.ml)),
        )
    }

    fn boundary(&self) -> Option<usize> {
        // Between frames.
        (self.frame.is_none() && !self.done).then_some(self.pos)
    }

    /// Headers, blocks and checksums are checked to be whole before they
    /// are decoded, so whatever goes wrong inside one is damage.
    fn truncation_is_exact(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{Streaming, verify_checkpoints};

    /// `words8.zst` (see `testdata/words8.py`): a 320 KB frame with a
    /// 128 KiB window and a content checksum, a skippable frame, a small
    /// frame with a raw block, and a frame with a 4 KiB window and no
    /// content size.
    const WORDS8: &[u8] = include_bytes!("testdata/words8.zst");

    #[test]
    fn checkpoints_resume_inside_and_between_frames() {
        for (step, at_least) in [(4096, 8), (50_000, 2)] {
            let (checked, largest) =
                verify_checkpoints(|| Box::new(Streaming(Zstd::new())), WORDS8, step, 1).unwrap();
            assert!(checked >= at_least, "{checked}");
            // Tables only: the window is the caller's output.
            assert!(largest < 16 * 1024, "{largest}");
        }
        let (checked, _) = verify_checkpoints(
            || Box::new(Streaming(Zstd::single_frame())),
            WORDS8,
            4096,
            1,
        )
        .unwrap();
        assert!(checked >= 2, "{checked}");
    }

    #[test]
    fn windows_are_released_mid_frame_and_whole_between_frames() {
        let mut d = Zstd::new();
        let mut out = Vec::new();
        let mut seen_mid = false;
        let mut seen_between = false;
        loop {
            let step = d.step(WORDS8, true, &mut out, 4096, 1 << 30).unwrap();
            let keep = out.len() - d.releasable_output(out.len());
            match &d.frame {
                Some(frame) if frame.window == 1 << 17 && out.len() > 1 << 17 => {
                    assert_eq!(keep, 1 << 17);
                    seen_mid = true;
                }
                Some(frame) => assert!(keep <= frame.window),
                None => {
                    assert_eq!(keep, 0);
                    seen_between = true;
                }
            }
            if step == Step::Done {
                break;
            }
        }
        assert!(seen_mid && seen_between);
        assert_eq!(out.len(), 320_000 + 1000 + 8192 + 30_000);
    }

    /// Feeds `input` to a streaming decoder 4 KiB more at a time, as a lazy
    /// read does; returns the error and how much input had been fed.
    fn stream_until_error(input: &[u8]) -> (Diagnostic, usize) {
        use crate::codec::pipeline::{Decoder, Status};
        let mut d = Streaming(Zstd::new());
        let mut out = Vec::new();
        let mut fed = 0;
        loop {
            fed = (fed + 4096).min(input.len());
            loop {
                match d.decode(
                    &input[..fed],
                    fed == input.len(),
                    &mut out,
                    1 << 16,
                    1 << 30,
                ) {
                    Ok(Status::More) => {}
                    Ok(Status::NeedInput) => break,
                    Ok(Status::Done) => panic!("decoded without an error"),
                    Err(e) => return (e, fed),
                }
            }
        }
    }

    /// Where the first block header of the frame at the start of `data` is.
    fn first_block(data: &[u8]) -> usize {
        let fhd = data[4];
        let single = fhd & 0x20 != 0;
        let dict = [0, 1, 2, 4][usize::from(fhd & 3)];
        let fcs = [usize::from(single), 2, 4, 8][usize::from(fhd >> 6)];
        5 + usize::from(!single) + dict + fcs
    }

    /// Every shortage is reported as truncated, so damage in a large
    /// stream is reported once the damaged block is in, not after the
    /// whole stream has been fed (retrying every step on the way).
    #[test]
    fn damage_is_reported_once_its_block_is_in() {
        // 40 copies of words8.zst: about 1 MB of input, 14 MB of output.
        let whole: Vec<u8> = WORDS8.repeat(40);
        let block = first_block(&whole);

        // A reserved block type in the first block header.
        let mut data = whole.clone();
        data[block] |= 0b110;
        let (e, fed) = stream_until_error(&data);
        assert_eq!(e.kind, crate::error::DiagKind::Malformed, "{e}");
        assert!(e.message.contains("reserved block type"), "{e}");
        assert_eq!(fed, 4096);

        // Damage inside the first compressed block: the first byte of its
        // body whose corruption the decoder detects.
        let header = u32::from(whole[block])
            | u32::from(whole[block + 1]) << 8
            | u32::from(whole[block + 2]) << 16;
        assert_eq!((header >> 1) & 3, 2, "a compressed block");
        let size = (header >> 3) as usize;
        let body = block + 3;
        let found = (body..body + size).find_map(|at| {
            let mut data = whole.clone();
            data[at] ^= 0xff;
            let (e, fed) = stream_until_error(&data);
            (e.kind == crate::error::DiagKind::Malformed).then_some(fed)
        });
        let fed = found.expect("some damage is detected");
        assert!(fed <= body + size + 4096, "{fed}");

        // A stream that is merely cut short still waits for input, and
        // is reported as truncated at its end.
        let cut = &whole[..whole.len() - 100];
        let (e, fed) = stream_until_error(cut);
        assert_eq!(e.kind, crate::error::DiagKind::Truncated, "{e}");
        assert_eq!(fed, cut.len());
    }

    #[test]
    fn a_fresh_decoder_at_a_frame_start_decodes_the_rest() {
        // Frames are independent: what a container's seek table needs.
        use crate::codec::pipeline::{Decoder, decode_all};
        let all = decode_all(&mut Streaming(Zstd::new()), WORDS8, 1 << 30).unwrap();
        let mut first = Streaming(Zstd::single_frame());
        let head = decode_all(&mut first, WORDS8, 1 << 30).unwrap();
        let at = first.consumed();
        assert_eq!(head.len(), 320_000);
        let mut d = crate::codec::Codec::Zstd.decoder().unwrap();
        let rest = decode_all(d.as_mut(), &WORDS8[at..], 1 << 30).unwrap();
        assert_eq!(rest, &all[head.len()..]);
        assert_eq!(rest.len(), 1000 + 8192 + 30_000);
    }

    /// `words.zdict`, `words-dict.zst`, `words-raw.zst`: see
    /// `testdata/words-dict.sh` (the zstd CLI).
    const WORDS: &[u8] = include_bytes!("testdata/words.txt");
    const ZDICT: &[u8] = include_bytes!("testdata/words.zdict");
    const WITH_DICT: &[u8] = include_bytes!("testdata/words-dict.zst");
    const WITH_RAW: &[u8] = include_bytes!("testdata/words-raw.zst");

    fn dict(bytes: &[u8]) -> Dict {
        Dict(Arc::new(Dictionary::parse(bytes).unwrap()))
    }

    #[test]
    fn formatted_dictionary_primes_tables_reps_and_window() {
        use crate::codec::pipeline::decode_all;
        let d = dict(ZDICT);
        assert_eq!(d.0.id, 4242);
        let layout = d.0.layout.unwrap();
        assert_eq!(layout.huffman.0, 8);
        assert_eq!(layout.content_at + d.0.content().len(), ZDICT.len());
        let expected = [
            &WORDS[..2000],
            &WORDS[50_000..110_000],
            &WORDS[20_000..20_300],
        ]
        .concat();
        let out = decode_all(
            &mut Streaming(Zstd::with_dictionary(d.clone())),
            WITH_DICT,
            1 << 30,
        )
        .unwrap();
        assert_eq!(out, expected);
        let (checked, largest) = verify_checkpoints(
            || Box::new(Streaming(Zstd::with_dictionary(d.clone()))),
            WITH_DICT,
            1024,
            1,
        )
        .unwrap();
        assert!(checked >= 8, "{checked}");
        // Tables only: the dictionary is shared, not copied.
        assert!(largest < 16 * 1024, "{largest}");
        // Without it, or with another one, the frames are refused.
        let e = decode_all(&mut Streaming(Zstd::new()), WITH_DICT, 1 << 30).unwrap_err();
        assert!(e.message.contains("dictionary (ID 4242)"), "{}", e.message);
        let other = dict(&WORDS[..100]); // raw content, ID 0
        let e = decode_all(
            &mut Streaming(Zstd::with_dictionary(other)),
            WITH_DICT,
            1 << 30,
        )
        .unwrap_err();
        assert!(e.message.contains("dictionary (ID 4242)"), "{}", e.message);
    }

    #[test]
    fn raw_content_dictionary_precedes_the_frame() {
        use crate::codec::pipeline::decode_all;
        let d = dict(&WORDS[..8192]);
        assert_eq!((d.0.id, d.0.layout), (0, None));
        let out = decode_all(
            &mut Streaming(Zstd::with_dictionary(d.clone())),
            WITH_RAW,
            1 << 30,
        )
        .unwrap();
        assert_eq!(out, &WORDS[30_000..40_000]);
        verify_checkpoints(
            || Box::new(Streaming(Zstd::with_dictionary(d.clone()))),
            WITH_RAW,
            1024,
            1,
        )
        .unwrap();
        // The frame names no dictionary: without one, its first match
        // reaching back before the frame fails.
        let e = decode_all(&mut Streaming(Zstd::new()), WITH_RAW, 1 << 30).unwrap_err();
        assert!(e.message.contains("beyond the window"), "{}", e.message);
    }

    #[test]
    fn bad_dictionaries_are_rejected() {
        assert!(Dictionary::parse(&ZDICT[..20]).is_err());
        let mut bad_reps = ZDICT.to_vec();
        let at = dict(ZDICT).0.layout.unwrap().reps_at;
        bad_reps[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(Dictionary::parse(&bad_reps).is_err());
    }

    /// The bit-at-a-time reading `Backward::peek` replaced: bit `i` of
    /// the result is bit `pos - n + i` of the data, zero below bit 0.
    fn peek_bitwise(data: &[u8], pos: i64, n: u32) -> u64 {
        let mut v = 0u64;
        for i in 0..i64::from(n) {
            let p = pos - i64::from(n) + i;
            if p >= 0 {
                let byte = data.get((p / 8) as usize).copied().unwrap_or(0);
                v |= u64::from(byte >> (p % 8) & 1) << i;
            }
        }
        v
    }

    #[test]
    fn windowed_peek_matches_bitwise_reading() {
        let data: Vec<u8> = (0u32..37)
            .map(|i| (i.wrapping_mul(0x9d) ^ 0x5a) as u8)
            .collect();
        let end = (data.len() * 8) as i64;
        for pos in -70..=end {
            for n in 0..=57 {
                let r = Backward { data: &data, pos };
                assert_eq!(r.peek(n), peek_bitwise(&data, pos, n), "pos {pos}, n {n}");
            }
        }
    }

    #[test]
    fn xxh64_vectors() {
        assert_eq!(xxh64(b"", 0), 0xef46_db37_51d8_e999);
        assert_eq!(xxh64(b"abc", 0), 0x44bc_2cf5_ad77_0999);
    }
}
