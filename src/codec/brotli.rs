//! Brotli (RFC 7932): meta-blocks (compressed, uncompressed, metadata),
//! simple and complex prefix codes, block switching, context modeling,
//! distance codes with NPOSTFIX/NDIRECT and the last-distance ring, and the
//! static dictionary with its 121 word transforms. The output buffer serves
//! as the sliding window (distances never reach past `2^WBITS - 16`
//! bytes; longer ones are dictionary words), so output before the window
//! can be released. Decoded a meta-block at a time. The non-standard
//! large-window extension is not supported.

use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("Brotli: {what}"))
}

/// The static dictionary (RFC 7932 Appendix A; MIT-licensed, as embedded in
/// the reference implementation). SHA-256
/// 20e42eb1b511c21806d4d227d07e5dd06877d8ce7b3a817f378f313653f35c70.
static DICTIONARY: &[u8; 122_784] = include_bytes!("brotli_dictionary.bin");

/// log2 of the number of dictionary words of each length (4 to 24).
const NDBITS: [u32; 25] = [0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5];

/// Offset of the words of each length in the dictionary.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn dict_offsets() -> [usize; 25] {
    let mut off = [0usize; 25];
    let mut len = 4;
    while len < 24 {
        off[len + 1] = off[len] + (len << NDBITS[len]);
        len += 1;
    }
    off
}
const DOFFSET: [usize; 25] = dict_offsets();

/// A Brotli stream decoded a meta-block at a time; reports where the
/// stream ended, so trailing bytes show up.
#[derive(Clone, Default)]
pub struct Stream {
    /// Position in the input, in bits.
    bit: usize,
    /// The window size (`2^WBITS - 16`), once the stream header is read.
    window: Option<usize>,
    ring: Option<Ring>,
    /// Where the stream's output starts in `out` (0 once released).
    start: Option<usize>,
    /// Output bytes released from the front of the stream's output.
    released: usize,
    done: bool,
}

impl Stream {
    /// Decodes the stream header, or the next meta-block (setting `done`
    /// after the last one).
    fn next(&mut self, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
        let mut b = Bits { data: input, pos: self.bit };
        let Some(window) = self.window else {
            self.window = Some((1usize << window_bits(&mut b)?).saturating_sub(16));
            self.bit = b.pos;
            return Ok(());
        };
        let mut ring = self.ring.unwrap_or([4, 11, 15, 16]);
        let last = b.bit()?;
        if last && b.bit()? {
            self.bit = b.pos;
            self.done = true;
            return Ok(());
        }
        let nibbles = match b.read(2)? {
            3 => 0,
            n => n.saturating_add(4),
        };
        if nibbles == 0 {
            // Metadata, skipped.
            if last {
                return Err(bad("metadata in the last meta-block"));
            }
            if b.bit()? {
                return Err(bad("reserved bit set"));
            }
            let nbytes = b.read(2)?;
            let mut skip = 0usize;
            for i in 0..nbytes {
                let v = b.read_usize(8)?;
                if i.saturating_add(1) == nbytes && nbytes > 1 && v == 0 {
                    return Err(bad("metadata length has a zero last byte"));
                }
                skip |= v << i.saturating_mul(8);
            }
            if nbytes > 0 {
                skip = skip.saturating_add(1);
            }
            b.align()?;
            b.skip(skip.saturating_mul(8))?;
            self.bit = b.pos;
            return Ok(());
        }
        let mut mlen = 0usize;
        for i in 0..nibbles {
            let v = b.read_usize(4)?;
            if i.saturating_add(1) == nibbles && nibbles > 4 && v == 0 {
                return Err(bad("meta-block length has a zero last nibble"));
            }
            mlen |= v << i.saturating_mul(4);
        }
        let mlen = mlen.saturating_add(1);
        if out.len().saturating_add(mlen) > limit {
            return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
        }
        if !last && b.bit()? {
            b.align()?;
            let start = b.pos >> 3;
            let data = input
                .get(start..start.saturating_add(mlen))
                .ok_or_else(|| bad("truncated uncompressed meta-block"))?;
            out.extend_from_slice(data);
            b.skip(mlen.saturating_mul(8))?;
            self.bit = b.pos;
            return Ok(());
        }
        let (origin, released) = (self.start.unwrap_or(0), self.released);
        let history = |len: usize| len.saturating_sub(origin).saturating_add(released);
        meta_block(&mut b, out, mlen, window, &mut ring, history)?;
        self.ring = Some(ring);
        self.bit = b.pos;
        self.done = last;
        Ok(())
    }
}

impl Decode for Stream {
    fn step(&mut self, input: &[u8], _eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Step> {
        if self.start.is_none() {
            self.start = Some(out.len());
        }
        let target = out.len().saturating_add(step.max(1));
        loop {
            if self.done {
                return Ok(Step::Done);
            }
            if out.len() >= target {
                return Ok(Step::More);
            }
            self.next(input, out, limit)?;
        }
    }

    fn consumed(&self) -> usize {
        self.bit.div_ceil(8)
    }

    fn releasable_input(&self) -> usize {
        // A partly read byte is kept.
        self.bit / 8
    }

    fn release_input(&mut self, n: usize) {
        self.bit = self.bit.saturating_sub(n.saturating_mul(8));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Distances beyond the window are dictionary words, which do not
        // read the output; literal contexts need the last two bytes.
        match self.window {
            Some(window) => out_len.saturating_sub(window.max(2)),
            None => 0,
        }
    }

    fn release_output(&mut self, n: usize) {
        let start = self.start.unwrap_or(0);
        self.released = self.released.saturating_add(n.saturating_sub(start));
        self.start = Some(start.saturating_sub(n));
    }
}

/// Whether `data` is exactly one complete Brotli stream with some content
/// and zero padding bits at its end. Brotli has no magic; this is the
/// (expensive, but strict) way to recognise a stream.
pub fn is_complete_stream(data: &[u8], limit: usize) -> bool {
    match decode(data, limit) {
        Ok((out, bits)) => {
            let pad = u32::try_from(bits.wrapping_neg() & 7).unwrap_or(0);
            let rest = Bits { data, pos: bits }.peek(pad);
            !out.is_empty() && bits.div_ceil(8) == data.len() && rest == 0
        }
        Err(_) => false,
    }
}

/// The window size (log2) from a stream's first bits.
pub fn window_bits_of(data: &[u8]) -> Option<u32> {
    window_bits(&mut Bits { data, pos: 0 }).ok()
}

/// LSB-first bit reader.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn peek(&self, n: u32) -> u32 {
        let byte = self.pos >> 3;
        let bytes = match self.data.get(byte..byte.saturating_add(8)) {
            Some(w) => w,
            None => self.data.get(byte..).unwrap_or_default(),
        };
        let word = bytes.iter().rev().fold(0u64, |a, &b| a << 8 | u64::from(b));
        let v = word >> (self.pos & 7);
        u32::try_from(v & (1u64 << n).wrapping_sub(1)).unwrap_or(0)
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        self.pos = self.pos.saturating_add(n);
        if self.pos > self.data.len().saturating_mul(8) {
            return Err(bad("truncated stream"));
        }
        Ok(())
    }

    /// Reads `n` (at most 32) bits.
    fn read(&mut self, n: u32) -> Result<u32> {
        let v = self.peek(n);
        self.skip(usize::try_from(n).unwrap_or(usize::MAX))?;
        Ok(v)
    }

    fn read_usize(&mut self, n: u32) -> Result<usize> {
        Ok(usize::try_from(self.read(n)?).unwrap_or(usize::MAX))
    }

    fn bit(&mut self) -> Result<bool> {
        Ok(self.read(1)? != 0)
    }

    /// Skips to the next byte boundary; the padding bits must be zero.
    fn align(&mut self) -> Result<()> {
        let pad = u32::try_from(self.pos.wrapping_neg() & 7).unwrap_or(0);
        if self.read(pad)? != 0 {
            return Err(bad("non-zero padding bits"));
        }
        Ok(())
    }
}

/// A canonical prefix code.
struct Huff {
    /// Set for a code with one symbol (decoded from zero bits).
    single: Option<u16>,
    count: [u16; 16],
    /// Symbols by code length, then value.
    sorted: Vec<u16>,
    /// Codes up to 8 bits, indexed by the next 8 input bits:
    /// `len << 10 | symbol`, or 0.
    fast: Vec<u16>,
}

impl Huff {
    fn new(lengths: &[u8]) -> Huff {
        let mut count = [0u16; 16];
        for &l in lengths.iter().filter(|&&l| l != 0) {
            if let Some(c) = count.get_mut(usize::from(l)) {
                *c = c.saturating_add(1);
            }
        }
        let mut used = (0u16..).zip(lengths).filter(|&(_, &l)| l != 0).map(|(s, _)| s);
        if let (Some(only), None) = (used.next(), used.next()) {
            return Huff { single: Some(only), count, sorted: Vec::new(), fast: Vec::new() };
        }
        let mut sorted = Vec::new();
        for len in 1..16u8 {
            sorted.extend((0u16..).zip(lengths).filter(|&(_, &l)| l == len).map(|(s, _)| s));
        }
        let mut fast = vec![0u16; 256];
        let mut next = 0u32;
        let mut it = sorted.iter();
        for len in 1..=8u32 {
            let n = count.get(usize::try_from(len).unwrap_or(0)).copied().unwrap_or(0);
            for _ in 0..n {
                let Some(&sym) = it.next() else { break };
                let rev = next.reverse_bits() >> 32u32.saturating_sub(len);
                let entry = u16::try_from(len << 10).unwrap_or(0) | sym;
                let mut fill = usize::try_from(rev).unwrap_or(usize::MAX);
                while let Some(e) = fast.get_mut(fill) {
                    *e = entry;
                    fill = fill.saturating_add(1 << len);
                }
                next = next.wrapping_add(1);
            }
            next <<= 1;
        }
        Huff { single: None, count, sorted, fast }
    }

    fn decode(&self, b: &mut Bits<'_>) -> Result<u16> {
        if let Some(s) = self.single {
            return Ok(s);
        }
        let e = self.fast.get(usize::try_from(b.peek(8)).unwrap_or(0)).copied().unwrap_or(0);
        if e != 0 {
            b.skip(usize::from(e >> 10))?;
            return Ok(e & 0x3ff);
        }
        let (mut code, mut first, mut index) = (0u32, 0u32, 0u32);
        for &n in self.count.get(1..).unwrap_or_default() {
            code |= b.read(1)?;
            let n = u32::from(n);
            if code.wrapping_sub(first) < n {
                let i = usize::try_from(index.saturating_add(code.wrapping_sub(first))).unwrap_or(usize::MAX);
                return self.sorted.get(i).copied().ok_or_else(|| bad("invalid prefix code"));
            }
            index = index.saturating_add(n);
            first = first.saturating_add(n) << 1;
            code <<= 1;
        }
        Err(bad("invalid prefix code"))
    }
}

const CODE_LENGTH_ORDER: [usize; 18] = [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// The fixed code for code length code lengths, indexed by the next 4
/// bits: bits used and value.
const CL_PREFIX_LEN: [usize; 16] = [2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4];
const CL_PREFIX_VAL: [u8; 16] = [0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5];

/// Reads a prefix code over `alphabet` symbols.
fn read_prefix_code(b: &mut Bits<'_>, alphabet: usize) -> Result<Huff> {
    let hskip = b.read_usize(2)?;
    let mut lengths = vec![0u8; alphabet];
    if hskip == 1 {
        // Simple code: up to four listed symbols.
        let bits = usize::BITS.saturating_sub(alphabet.saturating_sub(1).leading_zeros());
        let nsym = b.read_usize(2)?.saturating_add(1);
        let mut syms = [0usize; 4];
        for i in 0..nsym {
            let s = b.read_usize(bits)?;
            if s >= alphabet {
                return Err(bad("prefix code symbol out of range"));
            }
            if syms.get(..i).unwrap_or_default().contains(&s) {
                return Err(bad("duplicate symbol in a simple prefix code"));
            }
            if let Some(x) = syms.get_mut(i) {
                *x = s;
            }
        }
        let lens: &[u8] = match nsym {
            1 => &[1],
            2 => &[1, 1],
            3 => &[1, 2, 2],
            _ if b.bit()? => &[1, 2, 3, 3],
            _ => &[2, 2, 2, 2],
        };
        for (&s, &l) in syms.iter().zip(lens) {
            if let Some(x) = lengths.get_mut(s) {
                *x = l;
            }
        }
        return Ok(Huff::new(&lengths));
    }
    // Complex code: symbol code lengths coded with a code length code.
    let mut cl = [0u8; 18];
    let mut space = 32u32;
    let mut nonzero = 0u32;
    for &idx in CODE_LENGTH_ORDER.iter().skip(hskip) {
        let p = usize::try_from(b.peek(4)).unwrap_or(0);
        b.skip(CL_PREFIX_LEN.get(p).copied().unwrap_or(2))?;
        let val = CL_PREFIX_VAL.get(p).copied().unwrap_or(0);
        if let Some(x) = cl.get_mut(idx) {
            *x = val;
        }
        if val != 0 {
            space = space.saturating_sub(32 >> val);
            nonzero = nonzero.saturating_add(1);
            if space == 0 {
                break;
            }
        }
    }
    if nonzero != 1 && space != 0 {
        return Err(bad("invalid code length code"));
    }
    let clcode = Huff::new(&cl);
    let mut space = 32768usize;
    let (mut prev, mut repeat, mut repeat_len) = (8u8, 0usize, 0u8);
    let mut sym = 0usize;
    while sym < alphabet && space > 0 {
        let c = clcode.decode(b)?;
        if c < 16 {
            repeat = 0;
            let c = u8::try_from(c).unwrap_or(0);
            if let Some(x) = lengths.get_mut(sym) {
                *x = c;
            }
            if c != 0 {
                prev = c;
                space = space.checked_sub(32768 >> c).ok_or_else(|| bad("oversubscribed prefix code"))?;
            }
            sym = sym.saturating_add(1);
        } else {
            let (extra, new_len) = if c == 16 { (2, prev) } else { (3, 0) };
            if repeat_len != new_len {
                repeat = 0;
                repeat_len = new_len;
            }
            let old = repeat;
            if repeat > 0 {
                repeat = repeat.saturating_sub(2) << extra;
            }
            repeat = repeat.saturating_add(b.read_usize(extra)?).saturating_add(3);
            let delta = repeat.saturating_sub(old);
            if sym.saturating_add(delta) > alphabet {
                return Err(bad("code length run past the alphabet"));
            }
            for x in lengths.get_mut(sym..sym.saturating_add(delta)).unwrap_or_default() {
                *x = repeat_len;
            }
            sym = sym.saturating_add(delta);
            if repeat_len != 0 {
                space = space
                    .checked_sub(delta.saturating_mul(32768 >> repeat_len))
                    .ok_or_else(|| bad("oversubscribed prefix code"))?;
            }
        }
    }
    if space != 0 {
        return Err(bad("incomplete prefix code"));
    }
    Ok(Huff::new(&lengths))
}

/// A variable-length number from 0 to 255.
fn var_u8(b: &mut Bits<'_>) -> Result<usize> {
    if !b.bit()? {
        return Ok(0);
    }
    let n = b.read(3)?;
    if n == 0 {
        return Ok(1);
    }
    Ok((1usize << n).saturating_add(b.read_usize(n)?))
}

const BLOCK_LEN: [(usize, u32); 26] = [
    (1, 2), (5, 2), (9, 2), (13, 2), (17, 3), (25, 3), (33, 3), (41, 3), (49, 4), (65, 4), (81, 4), (97, 4), (113, 5),
    (145, 5), (177, 5), (209, 5), (241, 6), (305, 6), (369, 7), (497, 8), (753, 9), (1265, 10), (2289, 11), (4337, 12),
    (8433, 13), (16625, 24),
];

fn block_len(b: &mut Bits<'_>, code: &Huff) -> Result<usize> {
    let s = code.decode(b)?;
    let &(base, extra) = BLOCK_LEN.get(usize::from(s)).ok_or_else(|| bad("bad block length code"))?;
    Ok(base.saturating_add(b.read_usize(extra)?))
}

/// Block switching state of one category (literals, commands, distances).
struct Blocks {
    ntypes: usize,
    /// Block type and block count codes (if there are several types).
    codes: Option<(Huff, Huff)>,
    current: usize,
    previous: usize,
    left: usize,
}

impl Blocks {
    fn read(b: &mut Bits<'_>) -> Result<Blocks> {
        let ntypes = var_u8(b)?.saturating_add(1);
        let mut blocks = Blocks { ntypes, codes: None, current: 0, previous: 1, left: 1 << 24 };
        if ntypes >= 2 {
            let types = read_prefix_code(b, ntypes.saturating_add(2))?;
            let lens = read_prefix_code(b, 26)?;
            blocks.left = block_len(b, &lens)?;
            blocks.codes = Some((types, lens));
        }
        Ok(blocks)
    }

    /// Counts one symbol, switching blocks first if the current one is
    /// used up.
    fn next(&mut self, b: &mut Bits<'_>) -> Result<()> {
        if self.left == 0 {
            let Some((types, lens)) = &self.codes else {
                return Err(bad("block count exceeded"));
            };
            let t = match types.decode(b)? {
                0 => self.previous,
                1 => self.current.saturating_add(1).checked_rem(self.ntypes).unwrap_or(0),
                s => usize::from(s).saturating_sub(2),
            };
            self.previous = self.current;
            self.current = t;
            self.left = block_len(b, lens)?;
        }
        self.left = self.left.saturating_sub(1);
        Ok(())
    }
}

fn read_context_map(b: &mut Bits<'_>, size: usize, ntrees: usize) -> Result<Vec<u8>> {
    let mut map = vec![0u8; size];
    if ntrees < 2 {
        return Ok(map);
    }
    let rlemax = if b.bit()? { b.read_usize(4)?.saturating_add(1) } else { 0 };
    let code = read_prefix_code(b, ntrees.saturating_add(rlemax))?;
    let mut i = 0usize;
    while i < size {
        let s = usize::from(code.decode(b)?);
        if s == 0 {
            i = i.saturating_add(1);
        } else if s <= rlemax {
            let bits = u32::try_from(s).unwrap_or(0);
            i = i.saturating_add(1 << s).saturating_add(b.read_usize(bits)?);
            if i > size {
                return Err(bad("context map run too long"));
            }
        } else {
            if let Some(x) = map.get_mut(i) {
                *x = u8::try_from(s.saturating_sub(rlemax)).map_err(|_| bad("bad context map entry"))?;
            }
            i = i.saturating_add(1);
        }
    }
    if b.bit()? {
        // Inverse move-to-front.
        let mut mtf: Vec<u8> = (0..=255).collect();
        for x in &mut map {
            let idx = usize::from(*x);
            let v = mtf.get(idx).copied().unwrap_or(0);
            *x = v;
            if idx > 0 {
                mtf.copy_within(0..idx, 1);
                if let Some(f) = mtf.first_mut() {
                    *f = v;
                }
            }
        }
    }
    Ok(map)
}

/// UTF-8 context lookup tables (RFC 7932 section 7.1), for the last and the
/// second-to-last byte.
const UTF8_P1: [u8; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    8, 12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
    12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
    12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
];
const UTF8_P2: [u8; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
];

/// The signed context class of a byte.
fn signed_class(b: u8) -> u8 {
    match b {
        0 => 0,
        1..=15 => 1,
        16..=63 => 2,
        64..=127 => 3,
        128..=191 => 4,
        192..=239 => 5,
        240..=254 => 6,
        255 => 7,
    }
}

fn literal_context(mode: u8, p1: u8, p2: u8) -> usize {
    usize::from(match mode {
        0 => p1 & 0x3f,
        1 => p1 >> 2,
        2 => UTF8_P1.get(usize::from(p1)).copied().unwrap_or(0) | UTF8_P2.get(usize::from(p2)).copied().unwrap_or(0),
        _ => signed_class(p1) << 3 | signed_class(p2),
    })
}

/// Insert length codes: base and extra bits.
const INSERT: [(usize, u32); 24] = [
    (0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 1), (8, 1), (10, 2), (14, 2), (18, 3), (26, 3), (34, 4), (50, 4),
    (66, 5), (98, 5), (130, 6), (194, 7), (322, 8), (578, 9), (1090, 10), (2114, 12), (6210, 14), (22594, 24),
];
/// Copy length codes: base and extra bits.
const COPY: [(usize, u32); 24] = [
    (2, 0), (3, 0), (4, 0), (5, 0), (6, 0), (7, 0), (8, 0), (9, 0), (10, 1), (12, 1), (14, 2), (18, 2), (22, 3), (30, 3),
    (38, 4), (54, 4), (70, 5), (102, 5), (134, 6), (198, 7), (326, 8), (582, 9), (1094, 10), (2118, 24),
];
/// Insert and copy length code bases of each 64-symbol cell of the
/// command alphabet (cells 0 and 1 imply distance code 0).
const CELLS: [(usize, usize); 11] = [(0, 0), (0, 8), (0, 0), (0, 8), (8, 0), (8, 8), (0, 16), (16, 0), (8, 16), (16, 8), (16, 16)];

/// The word transforms (RFC 7932 Appendix B): prefix, type, suffix. Types:
/// 0 identity, 1-9 omit the last 1-9 bytes, 10 uppercase the first
/// character, 11 uppercase all, 12-20 omit the first 1-9 bytes.
const TRANSFORMS: [(&[u8], u8, &[u8]); 121] = [
    (b"", 0, b""), (b"", 0, b" "), (b" ", 0, b" "),
    (b"", 12, b""), (b"", 10, b" "), (b"", 0, b" the "),
    (b" ", 0, b""), (b"s ", 0, b" "), (b"", 0, b" of "),
    (b"", 10, b""), (b"", 0, b" and "), (b"", 13, b""),
    (b"", 1, b""), (b", ", 0, b" "), (b"", 0, b", "),
    (b" ", 10, b" "), (b"", 0, b" in "), (b"", 0, b" to "),
    (b"e ", 0, b" "), (b"", 0, b"\""), (b"", 0, b"."),
    (b"", 0, b"\">"), (b"", 0, b"\n"), (b"", 3, b""),
    (b"", 0, b"]"), (b"", 0, b" for "), (b"", 14, b""),
    (b"", 2, b""), (b"", 0, b" a "), (b"", 0, b" that "),
    (b" ", 10, b""), (b"", 0, b". "), (b".", 0, b""),
    (b" ", 0, b", "), (b"", 15, b""), (b"", 0, b" with "),
    (b"", 0, b"'"), (b"", 0, b" from "), (b"", 0, b" by "),
    (b"", 16, b""), (b"", 17, b""), (b" the ", 0, b""),
    (b"", 4, b""), (b"", 0, b". The "), (b"", 11, b""),
    (b"", 0, b" on "), (b"", 0, b" as "), (b"", 0, b" is "),
    (b"", 7, b""), (b"", 1, b"ing "), (b"", 0, b"\n\t"),
    (b"", 0, b":"), (b" ", 0, b". "), (b"", 0, b"ed "),
    (b"", 20, b""), (b"", 18, b""), (b"", 6, b""),
    (b"", 0, b"("), (b"", 10, b", "), (b"", 8, b""),
    (b"", 0, b" at "), (b"", 0, b"ly "), (b" the ", 0, b" of "),
    (b"", 5, b""), (b"", 9, b""), (b" ", 10, b", "),
    (b"", 10, b"\""), (b".", 0, b"("), (b"", 11, b" "),
    (b"", 10, b"\">"), (b"", 0, b"=\""), (b" ", 0, b"."),
    (b".com/", 0, b""), (b" the ", 0, b" of the "), (b"", 10, b"'"),
    (b"", 0, b". This "), (b"", 0, b","), (b".", 0, b" "),
    (b"", 10, b"("), (b"", 10, b"."), (b"", 0, b" not "),
    (b" ", 0, b"=\""), (b"", 0, b"er "), (b" ", 11, b" "),
    (b"", 0, b"al "), (b" ", 11, b""), (b"", 0, b"='"),
    (b"", 11, b"\""), (b"", 10, b". "), (b" ", 0, b"("),
    (b"", 0, b"ful "), (b" ", 10, b". "), (b"", 0, b"ive "),
    (b"", 0, b"less "), (b"", 11, b"'"), (b"", 0, b"est "),
    (b" ", 10, b"."), (b"", 11, b"\">"), (b" ", 0, b"='"),
    (b"", 10, b","), (b"", 0, b"ize "), (b"", 11, b"."),
    (b"\xc2\xa0", 0, b""), (b" ", 0, b","), (b"", 10, b"=\""),
    (b"", 11, b"=\""), (b"", 0, b"ous "), (b"", 11, b", "),
    (b"", 10, b"='"), (b" ", 10, b","), (b" ", 11, b"=\""),
    (b" ", 11, b", "), (b"", 11, b","), (b"", 11, b"("),
    (b"", 11, b". "), (b" ", 11, b"."), (b"", 11, b"='"),
    (b" ", 11, b". "), (b" ", 10, b"=\""), (b" ", 11, b"='"),
    (b" ", 10, b"='"),
];

/// Uppercases the first character of `w` (or all of them), the way RFC
/// 7932 does it: ASCII letters, and a fixed bit flip in the second or third
/// byte of other UTF-8 sequences.
fn uppercase(w: &mut [u8], all: bool) {
    let mut i = 0usize;
    while let Some(&c) = w.get(i) {
        let step = if c < 0xc0 {
            if let Some(x) = w.get_mut(i).filter(|x| x.is_ascii_lowercase()) {
                *x ^= 32;
            }
            1
        } else if c < 0xe0 {
            if let Some(x) = w.get_mut(i.saturating_add(1)) {
                *x ^= 32;
            }
            2
        } else {
            if let Some(x) = w.get_mut(i.saturating_add(2)) {
                *x ^= 5;
            }
            3
        };
        if !all {
            break;
        }
        i = i.saturating_add(step);
    }
}

/// Appends dictionary word `id` of length `len`, transformed.
fn dictionary(out: &mut Vec<u8>, id: usize, len: usize, end: usize) -> Result<()> {
    let (Some(&nbits), Some(&offset)) = (NDBITS.get(len), DOFFSET.get(len)) else {
        return Err(bad("dictionary reference with a bad length"));
    };
    if nbits == 0 {
        return Err(bad("dictionary reference with a bad length"));
    }
    let index = id & ((1usize << nbits).saturating_sub(1));
    let &(prefix, kind, suffix) = TRANSFORMS
        .get(id >> nbits)
        .ok_or_else(|| bad("distance beyond the dictionary"))?;
    let start = offset.saturating_add(index.saturating_mul(len));
    let word = DICTIONARY
        .get(start..start.saturating_add(len))
        .ok_or_else(|| bad("distance beyond the dictionary"))?;
    let word = match kind {
        1..=9 => word.get(..len.saturating_sub(usize::from(kind))).unwrap_or_default(),
        12..=20 => word.get(usize::from(kind.saturating_sub(11))..).unwrap_or_default(),
        _ => word,
    };
    let total = prefix.len().saturating_add(word.len()).saturating_add(suffix.len());
    if out.len().saturating_add(total) > end {
        return Err(bad("dictionary word past the end of the meta-block"));
    }
    out.extend_from_slice(prefix);
    let at = out.len();
    out.extend_from_slice(word);
    if kind == 10 || kind == 11 {
        uppercase(out.get_mut(at..).unwrap_or_default(), kind == 11);
    }
    out.extend_from_slice(suffix);
    Ok(())
}

/// Copies `len` bytes from `dist` back (overlap allowed); the caller has
/// checked `dist <= out.len()`.
fn copy_back(out: &mut Vec<u8>, dist: usize, len: usize) {
    let mut left = len;
    while left > 0 && dist > 0 {
        let start = out.len().saturating_sub(dist);
        let n = left.min(dist);
        if start.saturating_add(n) > out.len() {
            return;
        }
        out.extend_from_within(start..start.saturating_add(n));
        left = left.saturating_sub(n);
    }
}

/// The last four distances, most recent first.
type Ring = [usize; 4];

/// Decodes a distance code: the distance and whether it enters the ring.
fn distance(b: &mut Bits<'_>, code: usize, ndirect: usize, npostfix: u32, ring: &Ring) -> Result<(usize, bool)> {
    const DELTA: [i64; 6] = [-1, 1, -2, 2, -3, 3];
    if code < 16 {
        let (slot, delta) = match code {
            0..=3 => (code, 0),
            4..=9 => (0, DELTA.get(code.saturating_sub(4)).copied().unwrap_or(0)),
            _ => (1, DELTA.get(code.saturating_sub(10)).copied().unwrap_or(0)),
        };
        let base = i64::try_from(ring.get(slot).copied().unwrap_or(0)).unwrap_or(0);
        let d = usize::try_from(base.saturating_add(delta))
            .ok()
            .filter(|&d| d > 0)
            .ok_or_else(|| bad("non-positive distance"))?;
        return Ok((d, code != 0));
    }
    if code < 16usize.saturating_add(ndirect) {
        return Ok((code.saturating_sub(15), true));
    }
    let x = code.saturating_sub(ndirect).saturating_sub(16);
    let nbits = u32::try_from(x >> npostfix.saturating_add(1)).unwrap_or(0).saturating_add(1);
    let extra = b.read_usize(nbits)?;
    let hcode = x >> npostfix;
    let lcode = x & ((1usize << npostfix).saturating_sub(1));
    let offset = (2usize.saturating_add(hcode & 1) << nbits).saturating_sub(4);
    let d = (offset.saturating_add(extra) << npostfix)
        .saturating_add(lcode)
        .saturating_add(ndirect)
        .saturating_add(1);
    Ok((d, true))
}

fn tree<'a>(codes: &'a [Huff], map: &[u8], index: usize) -> Result<&'a Huff> {
    map.get(index)
        .and_then(|&t| codes.get(usize::from(t)))
        .ok_or_else(|| bad("context map refers to a missing prefix code"))
}

/// Decodes one compressed meta-block of `mlen` bytes onto `out`.
/// `history(out.len())` is the length of the stream's output so far,
/// counting what was released (and not what precedes the stream in `out`).
fn meta_block(
    b: &mut Bits<'_>,
    out: &mut Vec<u8>,
    mlen: usize,
    window: usize,
    ring: &mut Ring,
    history: impl Fn(usize) -> usize,
) -> Result<()> {
    let mut lit = Blocks::read(b)?;
    let mut cmd = Blocks::read(b)?;
    let mut dst = Blocks::read(b)?;
    let npostfix = b.read(2)?;
    let ndirect = b.read_usize(4)? << npostfix;
    let modes = (0..lit.ntypes)
        .map(|_| Ok(u8::try_from(b.read(2)?).unwrap_or(0)))
        .collect::<Result<Vec<u8>>>()?;
    let ntrees_l = var_u8(b)?.saturating_add(1);
    let cmap_l = read_context_map(b, lit.ntypes.saturating_mul(64), ntrees_l)?;
    let ntrees_d = var_u8(b)?.saturating_add(1);
    let cmap_d = read_context_map(b, dst.ntypes.saturating_mul(4), ntrees_d)?;
    let lit_codes = (0..ntrees_l).map(|_| read_prefix_code(b, 256)).collect::<Result<Vec<_>>>()?;
    let cmd_codes = (0..cmd.ntypes).map(|_| read_prefix_code(b, 704)).collect::<Result<Vec<_>>>()?;
    let dist_alphabet = 16usize.saturating_add(ndirect).saturating_add(48 << npostfix);
    let dist_codes = (0..ntrees_d).map(|_| read_prefix_code(b, dist_alphabet)).collect::<Result<Vec<_>>>()?;

    let end = out.len().saturating_add(mlen);
    while out.len() < end {
        cmd.next(b)?;
        let code = usize::from(cmd_codes.get(cmd.current).ok_or_else(|| bad("bad block type"))?.decode(b)?);
        let &(ibase, cbase) = CELLS.get(code >> 6).ok_or_else(|| bad("bad command code"))?;
        let &(ilen, ibits) = INSERT.get(ibase.saturating_add(code >> 3 & 7)).ok_or_else(|| bad("bad insert code"))?;
        let &(clen, cbits) = COPY.get(cbase.saturating_add(code & 7)).ok_or_else(|| bad("bad copy code"))?;
        let ilen = ilen.saturating_add(b.read_usize(ibits)?);
        let clen = clen.saturating_add(b.read_usize(cbits)?);
        if out.len().saturating_add(ilen) > end {
            return Err(bad("insert past the end of the meta-block"));
        }
        for _ in 0..ilen {
            lit.next(b)?;
            let n = out.len();
            let h = history(n);
            let p1 = if h >= 1 { n.checked_sub(1).and_then(|i| out.get(i)).copied().unwrap_or(0) } else { 0 };
            let p2 = if h >= 2 { n.checked_sub(2).and_then(|i| out.get(i)).copied().unwrap_or(0) } else { 0 };
            let mode = modes.get(lit.current).copied().unwrap_or(0);
            let ctx = lit.current.saturating_mul(64).saturating_add(literal_context(mode, p1, p2));
            let byte = tree(&lit_codes, &cmap_l, ctx)?.decode(b)?;
            out.push(u8::try_from(byte).unwrap_or(0));
        }
        if out.len() >= end {
            break;
        }
        let (dist, push) = if code < 128 {
            (ring[0], false)
        } else {
            dst.next(b)?;
            let ctx = dst.current.saturating_mul(4).saturating_add(clen.min(5).saturating_sub(2));
            let dcode = usize::from(tree(&dist_codes, &cmap_d, ctx)?.decode(b)?);
            distance(b, dcode, ndirect, npostfix, ring)?
        };
        let max_distance = window.min(history(out.len()));
        if dist > max_distance {
            dictionary(out, dist.saturating_sub(max_distance).saturating_sub(1), clen, end)?;
            continue;
        }
        if push {
            *ring = [dist, ring[0], ring[1], ring[2]];
        }
        if out.len().saturating_add(clen) > end {
            return Err(bad("copy past the end of the meta-block"));
        }
        copy_back(out, dist, clen);
    }
    Ok(())
}

fn window_bits(b: &mut Bits<'_>) -> Result<u32> {
    if !b.bit()? {
        return Ok(16);
    }
    let n = b.read(3)?;
    if n != 0 {
        return Ok(n.saturating_add(17));
    }
    match b.read(3)? {
        0 => Ok(17),
        1 => Err(Diagnostic::unsupported("Brotli large windows")),
        m => Ok(m.saturating_add(8)),
    }
}

/// Decodes a stream; also returns the bit position where it ended.
fn decode(input: &[u8], limit: usize) -> Result<(Vec<u8>, usize)> {
    let mut stream = Stream::default();
    let mut out = Vec::new();
    stream.step(input, true, &mut out, usize::MAX, limit)?;
    Ok((out, stream.bit))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_layout() {
        assert_eq!(DOFFSET[24] + 24 * 32, DICTIONARY.len());
        assert!(DICTIONARY.starts_with(b"timedownlifeleftback"));
    }

    #[test]
    fn uppercasing() {
        let mut w = *b"hello world";
        uppercase(&mut w, false);
        assert_eq!(&w, b"Hello world");
        uppercase(&mut w, true);
        assert_eq!(&w, b"HELLO WORLD");
    }
}
