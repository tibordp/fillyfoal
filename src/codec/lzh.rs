//! The codecs of the DOS-era archivers: LHA (`-lh1-`, `-lh4-` to `-lh7-`,
//! LArc's `-lzs-` and `-lz5-`), ARJ (methods 1 to 4), ZOO (LZW and `-lh5-`)
//! and `COMPRESS.EXE` (SZDD's LZSS, KWAJ's MSZIP).
//!
//! Written from memory of the reference decoders (LHa for UNIX's
//! `slide.c`/`huf.c`/`dhuf.c`/`larc.c`, Okumura's `lzhuf.c`, `unarj`'s
//! `decode.c`, ZOO's `lzd.c`, libmspack's `lzss.c` and `mszipd.c`); the
//! tests and `tests/data/lzh/make.py` say which methods 7-Zip, libarchive
//! and `lhafile` decode to the same bytes and which are only checked
//! against our own test encoders.
//!
//! - **Static Huffman** (`-lh4-` to `-lh7-`, ARJ 1 to 3, ZOO 2): LZSS with
//!   a window of 2^`dict_bits` bytes (ARJ: 26 KiB), in blocks. Each block
//!   starts with a 16-bit token count and three code-length tables: a
//!   19-symbol table that codes the literal/length table's lengths, the
//!   510-symbol literal/length table (0 to 255 literals, 256 + n a match of
//!   n + 3 bytes), and the position table, whose symbol is the bit length
//!   of the match distance minus one (followed by the bits below the top
//!   one). Codes are canonical, bits are read most significant first.
//! - **`-lh1-`**: LHarc's LZHUF: 4 KiB window, matches of up to 60 bytes,
//!   literals and lengths with an adaptive Huffman code (314 symbols,
//!   rebuilt when the root reaches 0x8000), and distances as a fixed code
//!   for the upper 6 bits plus 6 plain bits.
//! - **ARJ 4** ("fastest"): no Huffman: lengths and distances in an
//!   Elias-gamma-like code (unary width, then that many bits).
//! - **`-lzs-`**, **`-lz5-`** (LArc) and **SZDD** (also KWAJ 2): LZSS over a
//!   ring buffer with absolute positions. `-lzs-` is bit-oriented (a flag
//!   bit, an 8-bit literal or an 11-bit position and a 4-bit length); the
//!   others take a flag byte for every eight items (least significant bit
//!   first, 1 for a literal) and 12-bit positions with 4-bit lengths. They
//!   differ in the ring's initial contents and write position.
//! - **ZOO LZW** (method 1): 9- to 13-bit codes packed least significant
//!   bit first, 256 clears the table, 257 ends the stream.
//! - **KWAJ XOR** (method 1): every byte inverted.
//! - **KWAJ MSZIP** (method 4): blocks of a 16-bit length, `CK` and a
//!   DEFLATE stream reaching back into the previous 32 KiB of output; a
//!   zero length ends them.
//!
//! LHA's decoder starts with a window full of spaces (LZHUF's encoder
//! matches against them); so do SZDD's and LArc's rings. Elsewhere a
//! reference before the start of the output reads zeros. The containers
//! record the decoded size (the Huffman streams have no end marker), and
//! the CRC of the output, which [`Check`] verifies as it is produced.

use crate::codec::crc::{CRC16_ARC, CRC32};
use crate::codec::inflate;
use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

fn bad(what: impl std::fmt::Display) -> Diagnostic {
    Diagnostic::malformed(format!("LZH: {what}"))
}

/// The coding method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// LHA `-lh1-` (LZHUF).
    Lh1,
    /// LHA `-lh4-` (12 bits) to `-lh7-` (16 bits), ZOO method 2 (13).
    Lh { dict_bits: u8 },
    /// ARJ methods 1 to 3 (static Huffman, 26 KiB window).
    Arj,
    /// ARJ method 4.
    ArjFastest,
    /// LArc `-lzs-` (2 KiB ring).
    Lzs,
    /// LArc `-lz5-` (4 KiB ring with a preset dictionary).
    Lz5,
    /// SZDD and KWAJ method 2 (4 KiB ring of spaces).
    Szdd,
    /// ZOO method 1.
    ZooLzw,
    /// KWAJ method 4.
    KwajMszip,
    /// KWAJ method 1: every byte inverted.
    KwajXor,
}

/// A check value of the decoded data, verified once the stream ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Check {
    None,
    /// CRC-16/ARC (LHA, ZOO).
    Crc16(u16),
    /// CRC-32 (ARJ).
    Crc32(u32),
}

/// What a stream needs to be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Params {
    pub method: Method,
    /// The decoded size, if known; decoding stops there. The Huffman and
    /// ARJ methods need it (their streams have no end marker); without
    /// it they end when the input does.
    pub size: Option<u64>,
    pub check: Check,
}

impl Params {
    pub fn new(method: Method, size: Option<u64>, check: Check) -> Self {
        Params {
            method,
            size,
            check,
        }
    }

    /// The largest plausible ratio of decoded to encoded size.
    pub fn max_ratio(&self) -> u64 {
        match self.method {
            // A 256-byte match in a few bits.
            Method::Lh { .. } | Method::Arj | Method::Lh1 => 2_048,
            Method::ArjFastest => 128,
            // 18 bytes per 2 bytes (and a flag bit).
            Method::Lz5 | Method::Szdd | Method::Lzs => 16,
            Method::ZooLzw => 4_096,
            Method::KwajMszip => 1_032,
            Method::KwajXor => 1,
        }
    }

    /// How far back the output is read (`None`: not at all).
    fn window(&self) -> Option<usize> {
        match self.method {
            Method::Lh { .. } | Method::Arj => Some(1 << 16),
            Method::Lh1 => Some(1 << 12),
            Method::ArjFastest => Some(1 << 15),
            _ => None,
        }
    }

    /// What a reference before the start of the output reads.
    fn fill(&self) -> u8 {
        match self.method {
            Method::Lh { .. } | Method::Lh1 => b' ',
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------- bits

/// Reads bits most significant first from `data`, starting at bit `pos`.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn bit(&mut self) -> Result<u32> {
        let byte = self
            .data
            .get(self.pos >> 3)
            .copied()
            .ok_or_else(|| bad("stream ended early"))?;
        let shift = 7usize.saturating_sub(self.pos & 7);
        self.pos = self.pos.saturating_add(1);
        Ok(u32::from(byte >> shift & 1))
    }

    /// `n` (at most 24) bits.
    fn bits(&mut self, n: u32) -> Result<u32> {
        let mut v = 0u32;
        for _ in 0..n.min(24) {
            v = v << 1 | self.bit()?;
        }
        Ok(v)
    }

    fn total(&self) -> usize {
        self.data.len().saturating_mul(8)
    }
}

// ---------------------------------------------------------------- Huffman

const MAX_LEN: usize = 16;

/// A canonical Huffman code, or a single symbol coded with no bits.
#[derive(Clone, Debug)]
enum Code {
    Single(u16),
    Huffman {
        counts: [u16; MAX_LEN + 1],
        symbols: Vec<u16>,
    },
}

impl Code {
    /// Codes are assigned shortest first, then in symbol order. Incomplete
    /// codes are accepted (an unused code is an error when read).
    fn new(lengths: &[u8]) -> Result<Code> {
        let mut counts = [0u16; MAX_LEN + 1];
        for &len in lengths {
            let slot = counts
                .get_mut(usize::from(len))
                .ok_or_else(|| bad("code length above 16"))?;
            *slot = slot.saturating_add(1);
        }
        if let Some(c) = counts.get_mut(0) {
            *c = 0;
        }
        let mut left: i64 = 1;
        for len in 1..=MAX_LEN {
            left = left.saturating_mul(2);
            left = left.saturating_sub(i64::from(counts.get(len).copied().unwrap_or(0)));
            if left < 0 {
                return Err(bad("over-subscribed Huffman code"));
            }
        }
        let mut offsets = [0usize; MAX_LEN + 2];
        for len in 1..=MAX_LEN {
            let next = offsets
                .get(len)
                .copied()
                .unwrap_or(0)
                .saturating_add(usize::from(counts.get(len).copied().unwrap_or(0)));
            if let Some(o) = offsets.get_mut(len.saturating_add(1)) {
                *o = next;
            }
        }
        let used = offsets.get(MAX_LEN + 1).copied().unwrap_or(0);
        let mut symbols = vec![0u16; used];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            if let Some(o) = offsets.get_mut(usize::from(len)) {
                if let Some(slot) = symbols.get_mut(*o) {
                    *slot = u16::try_from(symbol).unwrap_or(u16::MAX);
                }
                *o = o.saturating_add(1);
            }
        }
        Ok(Code::Huffman { counts, symbols })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16> {
        let (counts, symbols) = match self {
            Code::Single(s) => return Ok(*s),
            Code::Huffman { counts, symbols } => (counts, symbols),
        };
        let mut code: i64 = 0;
        let mut first: i64 = 0;
        let mut index: i64 = 0;
        for len in 1..=MAX_LEN {
            code |= i64::from(bits.bit()?);
            let count = i64::from(counts.get(len).copied().unwrap_or(0));
            if code.saturating_sub(first) < count {
                let at = index.saturating_add(code.saturating_sub(first));
                return usize::try_from(at)
                    .ok()
                    .and_then(|at| symbols.get(at))
                    .copied()
                    .ok_or_else(|| bad("bad Huffman code"));
            }
            index = index.saturating_add(count);
            first = first.saturating_add(count) << 1;
            code <<= 1;
        }
        Err(bad("unused Huffman code"))
    }
}

/// Literal/length symbols of the static methods.
const NC: usize = 510;
/// Symbols of the table that codes the literal/length lengths.
const NT: usize = 19;

/// LHA's `read_pt_len`: `n` lengths of 3 bits, 7 and above continued in
/// unary; after `special` lengths a 2-bit count of zeros.
fn read_pt_len(bits: &mut Bits<'_>, nn: usize, nbit: u32, special: Option<usize>) -> Result<Code> {
    let n = usize::try_from(bits.bits(nbit)?).unwrap_or(usize::MAX);
    if n == 0 {
        let c = bits.bits(nbit)?;
        if usize::try_from(c).unwrap_or(usize::MAX) >= nn {
            return Err(bad(format!("single code {c} out of range")));
        }
        return Ok(Code::Single(u16::try_from(c).unwrap_or(0)));
    }
    if n > nn {
        return Err(bad(format!("{n} code lengths for {nn} symbols")));
    }
    let mut lengths = vec![0u8; nn];
    let mut i = 0usize;
    while i < n {
        let mut c = bits.bits(3)?;
        if c == 7 {
            while bits.bit()? == 1 {
                c = c.saturating_add(1);
                if c > 16 {
                    return Err(bad("code length above 16"));
                }
            }
        }
        if let Some(slot) = lengths.get_mut(i) {
            *slot = u8::try_from(c).unwrap_or(0);
        }
        i = i.saturating_add(1);
        if Some(i) == special {
            let zeros = bits.bits(2)?;
            i = i.saturating_add(usize::try_from(zeros).unwrap_or(0));
        }
    }
    if i > nn {
        return Err(bad("too many code lengths"));
    }
    Code::new(&lengths)
}

/// LHA's `read_c_len`: the literal/length lengths, coded with `t`.
fn read_c_len(bits: &mut Bits<'_>, t: &Code) -> Result<Code> {
    let n = usize::try_from(bits.bits(9)?).unwrap_or(usize::MAX);
    if n == 0 {
        let c = bits.bits(9)?;
        if usize::try_from(c).unwrap_or(usize::MAX) >= NC {
            return Err(bad(format!("single code {c} out of range")));
        }
        return Ok(Code::Single(u16::try_from(c).unwrap_or(0)));
    }
    if n > NC {
        return Err(bad(format!("{n} code lengths for {NC} symbols")));
    }
    let mut lengths = vec![0u8; NC];
    let mut i = 0usize;
    while i < n {
        let c = t.decode(bits)?;
        let zeros = match c {
            0 => 1,
            1 => bits.bits(4)?.saturating_add(3),
            2 => bits.bits(9)?.saturating_add(20),
            _ => {
                let slot = lengths
                    .get_mut(i)
                    .ok_or_else(|| bad("too many code lengths"))?;
                *slot = u8::try_from(c.saturating_sub(2)).unwrap_or(u8::MAX);
                i = i.saturating_add(1);
                continue;
            }
        };
        i = i.saturating_add(usize::try_from(zeros).unwrap_or(usize::MAX));
    }
    if i > NC {
        return Err(bad("too many code lengths"));
    }
    Code::new(&lengths)
}

// ---------------------------------------------------------------- LZHUF

/// LZHUF's literal/length symbols: 256 literals, matches of 3 to 60.
const N_CHAR: usize = 256 - 3 + 60;
const T: usize = N_CHAR * 2 - 1;
const ROOT: usize = T - 1;
const MAX_FREQ: u32 = 0x8000;

/// Okumura's adaptive Huffman tree (`lzhuf.c`): nodes ordered by
/// frequency; `son` is a node's left child (the right one follows it) or
/// `T + symbol` for a leaf; `prnt` maps nodes and `T + symbol` to parents.
#[derive(Clone, Debug)]
struct Adaptive {
    freq: Vec<u32>,
    prnt: Vec<usize>,
    son: Vec<usize>,
}

fn at(v: &[usize], i: usize) -> usize {
    v.get(i).copied().unwrap_or(0)
}

fn put<V: Copy>(v: &mut [V], i: usize, x: V) {
    if let Some(slot) = v.get_mut(i) {
        *slot = x;
    }
}

impl Adaptive {
    fn new() -> Self {
        let mut a = Adaptive {
            freq: vec![0; T + 1],
            prnt: vec![0; T + N_CHAR],
            son: vec![0; T],
        };
        for i in 0..N_CHAR {
            put(&mut a.freq, i, 1);
            put(&mut a.son, i, i.saturating_add(T));
            put(&mut a.prnt, i.saturating_add(T), i);
        }
        let mut i = 0usize;
        for j in N_CHAR..=ROOT {
            let f = a.f(i).saturating_add(a.f(i.saturating_add(1)));
            put(&mut a.freq, j, f);
            put(&mut a.son, j, i);
            put(&mut a.prnt, i, j);
            put(&mut a.prnt, i.saturating_add(1), j);
            i = i.saturating_add(2);
        }
        put(&mut a.freq, T, 0xffff);
        put(&mut a.prnt, ROOT, 0);
        a
    }

    fn f(&self, i: usize) -> u32 {
        self.freq.get(i).copied().unwrap_or(u32::MAX)
    }

    fn decode(&mut self, bits: &mut Bits<'_>) -> Result<usize> {
        let mut c = at(&self.son, ROOT);
        let mut depth = 0u32;
        while c < T {
            c = at(
                &self.son,
                c.saturating_add(usize::try_from(bits.bit()?).unwrap_or(0)),
            );
            depth = depth.saturating_add(1);
            if depth > 64 {
                return Err(bad("adaptive Huffman tree too deep"));
            }
        }
        let symbol = c.saturating_sub(T);
        self.update(symbol);
        Ok(symbol)
    }

    /// Halves the frequencies and rebuilds the tree.
    fn reconst(&mut self) {
        let mut j = 0usize;
        for i in 0..T {
            if at(&self.son, i) >= T {
                let half = self.f(i).saturating_add(1) / 2;
                put(&mut self.freq, j, half);
                let s = at(&self.son, i);
                put(&mut self.son, j, s);
                j = j.saturating_add(1);
            }
        }
        let mut i = 0usize;
        for j in N_CHAR..T {
            let f = self.f(i).saturating_add(self.f(i.saturating_add(1)));
            put(&mut self.freq, j, f);
            let mut k = j.saturating_sub(1);
            while k > 0 && f < self.f(k) {
                k = k.saturating_sub(1);
            }
            if f >= self.f(k) {
                k = k.saturating_add(1);
            }
            // Insert at k, shifting k..j up by one.
            if let Some(slice) = self.freq.get_mut(k..=j) {
                slice.rotate_right(1);
            }
            put(&mut self.freq, k, f);
            if let Some(slice) = self.son.get_mut(k..=j) {
                slice.rotate_right(1);
            }
            put(&mut self.son, k, i);
            i = i.saturating_add(2);
        }
        for i in 0..T {
            let k = at(&self.son, i);
            put(&mut self.prnt, k, i);
            if k < T {
                put(&mut self.prnt, k.saturating_add(1), i);
            }
        }
    }

    fn update(&mut self, symbol: usize) {
        if self.f(ROOT) >= MAX_FREQ {
            self.reconst();
        }
        let mut c = at(&self.prnt, symbol.saturating_add(T));
        for _ in 0..=T {
            let k = self.f(c).saturating_add(1);
            put(&mut self.freq, c, k);
            let mut l = c.saturating_add(1);
            if k > self.f(l) {
                while l < T && k > self.f(l.saturating_add(1)) {
                    l = l.saturating_add(1);
                }
                let fl = self.f(l);
                put(&mut self.freq, c, fl);
                put(&mut self.freq, l, k);
                let i = at(&self.son, c);
                put(&mut self.prnt, i, l);
                if i < T {
                    put(&mut self.prnt, i.saturating_add(1), l);
                }
                let j = at(&self.son, l);
                put(&mut self.son, l, i);
                put(&mut self.prnt, j, c);
                if j < T {
                    put(&mut self.prnt, j.saturating_add(1), c);
                }
                put(&mut self.son, c, j);
                c = l;
            }
            c = at(&self.prnt, c);
            if c == 0 {
                break;
            }
        }
    }
}

/// LZHUF's fixed code for the upper 6 bits of a position: 1 code of 3
/// bits, 3 of 4, 8 of 5, 12 of 6, 24 of 7 and 16 of 8.
fn lh1_position_code() -> Result<Code> {
    let mut lengths = Vec::with_capacity(64);
    for (len, n) in [(3u8, 1usize), (4, 3), (5, 8), (6, 12), (7, 24), (8, 16)] {
        lengths.extend(std::iter::repeat_n(len, n));
    }
    Code::new(&lengths)
}

// ---------------------------------------------------------------- rings

/// LArc `-lz5-`'s preset ring: runs of 13 copies of each byte, the bytes
/// up and down, 128 zeros and spaces.
fn lz5_ring() -> Vec<u8> {
    let mut ring = Vec::with_capacity(4096);
    for i in 0..=255u8 {
        ring.extend(std::iter::repeat_n(i, 13));
    }
    ring.extend(0..=255u8);
    ring.extend((0..=255u8).rev());
    ring.extend(std::iter::repeat_n(0, 128));
    ring.resize(4096, b' ');
    ring
}

// ---------------------------------------------------------------- decoder

#[derive(Clone, Debug)]
enum State {
    Static {
        /// Tokens left in the current block.
        block: u32,
        c: Code,
        p: Code,
    },
    Lh1 {
        tree: Box<Adaptive>,
        p: Code,
    },
    Fastest,
    Ring {
        ring: Vec<u8>,
        pos: usize,
        /// The current flag byte, with a marker bit above the unused flags.
        flags: u32,
    },
    Lzw {
        /// `(prefix code, last byte)` of codes 258 and up.
        table: Vec<(u16, u8)>,
        bits: u32,
        old: Option<u16>,
        first: u8,
    },
    Mszip {
        dict: Vec<u8>,
    },
}

/// A stream decoder (see the module documentation).
#[derive(Clone, Debug)]
pub struct Lzh {
    params: Params,
    state: State,
    /// Position in the input, in bits.
    bit: usize,
    /// Bytes produced so far, including released ones.
    produced: u64,
    crc: u64,
    done: bool,
}

impl Lzh {
    pub fn new(params: Params) -> Self {
        let state = match params.method {
            Method::Lh { .. } | Method::Arj => State::Static {
                block: 0,
                c: Code::Single(0),
                p: Code::Single(0),
            },
            Method::Lh1 => State::Lh1 {
                tree: Box::new(Adaptive::new()),
                p: lh1_position_code().unwrap_or(Code::Single(0)),
            },
            Method::ArjFastest => State::Fastest,
            Method::Lzs => State::Ring {
                ring: vec![b' '; 2048],
                pos: 2048 - 17,
                flags: 1,
            },
            Method::Lz5 => State::Ring {
                ring: lz5_ring(),
                pos: 4096 - 18,
                flags: 1,
            },
            Method::Szdd => State::Ring {
                ring: vec![b' '; 4096],
                pos: 4096 - 16,
                flags: 1,
            },
            Method::ZooLzw => State::Lzw {
                table: Vec::new(),
                bits: 9,
                old: None,
                first: 0,
            },
            Method::KwajMszip => State::Mszip { dict: Vec::new() },
            Method::KwajXor => State::Fastest,
        };
        let crc = match params.check {
            Check::Crc16(_) => CRC16_ARC.init(),
            _ => CRC32.init(),
        };
        Lzh {
            params,
            state,
            bit: 0,
            produced: 0,
            crc,
            done: false,
        }
    }

    /// Bytes still wanted (`u64::MAX` without a known size).
    fn wanted(&self) -> u64 {
        self.params
            .size
            .map_or(u64::MAX, |s| s.saturating_sub(self.produced))
    }

    fn finished(&self) -> bool {
        self.wanted() == 0
    }

    /// Copies `len` bytes from `dist` bytes back in `out`.
    fn copy(&mut self, out: &mut Vec<u8>, dist: usize, len: usize) -> Result<()> {
        let len = usize::try_from(self.wanted())
            .unwrap_or(usize::MAX)
            .min(len);
        let fill = self.params.fill();
        let produced = usize::try_from(self.produced).unwrap_or(usize::MAX);
        for k in 0..len {
            let back = dist;
            let byte = if back > produced.saturating_add(k) {
                fill
            } else {
                let at = out
                    .len()
                    .checked_sub(back)
                    .ok_or_else(|| bad("reference beyond the window"))?;
                out.get(at).copied().unwrap_or(fill)
            };
            out.push(byte);
        }
        self.produced = self.produced.saturating_add(crate::bytes::to_u64(len));
        Ok(())
    }

    fn literal(&mut self, out: &mut Vec<u8>, byte: u8) {
        if !self.finished() {
            out.push(byte);
            self.produced = self.produced.saturating_add(1);
        }
    }

    /// One token of the static Huffman methods.
    fn static_token(&mut self, bits: &mut Bits<'_>, out: &mut Vec<u8>) -> Result<()> {
        let (np, pbit) = match self.params.method {
            Method::Lh { dict_bits } => {
                let np = usize::from(dict_bits.clamp(13, 16)).saturating_add(1);
                (np, if np <= 14 { 4 } else { 5 })
            }
            _ => (17, 5),
        };
        let State::Static { block, c, p } = &mut self.state else {
            return Err(bad("wrong state"));
        };
        if *block == 0 {
            let n = bits.bits(16)?;
            *block = if n == 0 { 0x1_0000 } else { n };
            let t = read_pt_len(bits, NT, 5, Some(3))?;
            *c = read_c_len(bits, &t)?;
            *p = read_pt_len(bits, np, pbit, None)?;
        }
        *block = block.saturating_sub(1);
        let sym = c.decode(bits)?;
        if sym < 256 {
            self.literal(out, u8::try_from(sym).unwrap_or(0));
            return Ok(());
        }
        let len = usize::from(sym).saturating_sub(253);
        let pcode = u32::from(p.decode(bits)?);
        if pcode > 16 {
            return Err(bad(format!("position code {pcode}")));
        }
        let dist = if pcode == 0 {
            0
        } else {
            (1u32 << pcode.saturating_sub(1)).saturating_add(bits.bits(pcode.saturating_sub(1))?)
        };
        self.copy(
            out,
            usize::try_from(dist)
                .unwrap_or(usize::MAX)
                .saturating_add(1),
            len,
        )
    }

    fn lh1_token(&mut self, bits: &mut Bits<'_>, out: &mut Vec<u8>) -> Result<()> {
        let State::Lh1 { tree, p } = &mut self.state else {
            return Err(bad("wrong state"));
        };
        let sym = tree.decode(bits)?;
        if sym < 256 {
            self.literal(out, u8::try_from(sym).unwrap_or(0));
            return Ok(());
        }
        let len = sym.saturating_sub(253);
        let upper = usize::from(p.decode(bits)?);
        let lower = usize::try_from(bits.bits(6)?).unwrap_or(0);
        self.copy(out, (upper << 6 | lower).saturating_add(1), len)
    }

    /// ARJ's unary-width numbers: up to `stop - start` one bits, each
    /// adding the next power of two from 2^`start`, then `width` bits.
    fn arj_number(bits: &mut Bits<'_>, start: u32, stop: u32) -> Result<u32> {
        let mut plus = 0u32;
        let mut pwr = 1u32 << start;
        let mut width = start;
        while width < stop {
            if bits.bit()? == 0 {
                break;
            }
            plus = plus.saturating_add(pwr);
            pwr <<= 1;
            width = width.saturating_add(1);
        }
        let v = if width != 0 { bits.bits(width)? } else { 0 };
        Ok(v.saturating_add(plus))
    }

    fn fastest_token(&mut self, bits: &mut Bits<'_>, out: &mut Vec<u8>) -> Result<()> {
        let c = Self::arj_number(bits, 0, 7)?;
        if c == 0 {
            let b = bits.bits(8)?;
            self.literal(out, u8::try_from(b).unwrap_or(0));
            return Ok(());
        }
        let len = usize::try_from(c).unwrap_or(0).saturating_add(2);
        let pos = Self::arj_number(bits, 9, 13)?;
        self.copy(
            out,
            usize::try_from(pos).unwrap_or(usize::MAX).saturating_add(1),
            len,
        )
    }

    /// One item of the ring methods; `Ok(false)` if the input ended
    /// cleanly before it.
    fn ring_token(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        let method = self.params.method;
        let mut bits = Bits {
            data: input,
            pos: self.bit,
        };
        if bits.pos >= bits.total() {
            return Ok(false);
        }
        let wanted = usize::try_from(self.wanted()).unwrap_or(usize::MAX);
        let State::Ring { ring, pos, flags } = &mut self.state else {
            return Err(bad("wrong state"));
        };
        let mask = ring.len().saturating_sub(1);
        let (literal, item) = if method == Method::Lzs {
            if bits.bit()? == 1 {
                (true, bits.bits(8)?)
            } else {
                (false, bits.bits(15)?)
            }
        } else {
            if *flags == 1 {
                *flags = bits.bits(8)? | 0x100;
            }
            let literal = *flags & 1 == 1;
            *flags >>= 1;
            if literal {
                (true, bits.bits(8)?)
            } else {
                (false, bits.bits(16)?)
            }
        };
        let (from, len) = if literal {
            (None, 1usize)
        } else if method == Method::Lzs {
            // 11-bit position, 4-bit length (2 to 17).
            (
                Some(usize::try_from(item >> 4).unwrap_or(0)),
                usize::try_from(item & 0xf).unwrap_or(0).saturating_add(2),
            )
        } else {
            // Low position byte, then high nibble of position and length.
            let lo = item >> 8;
            let hi = item & 0xff;
            (
                Some(usize::try_from(lo | (hi & 0xf0) << 4).unwrap_or(0)),
                usize::try_from(hi & 0x0f).unwrap_or(0).saturating_add(3),
            )
        };
        let len = wanted.min(len);
        for k in 0..len {
            let byte = match from {
                None => u8::try_from(item).unwrap_or(0),
                Some(f) => ring.get(f.saturating_add(k) & mask).copied().unwrap_or(0),
            };
            put(ring, *pos & mask, byte);
            *pos = pos.saturating_add(1) & mask;
            out.push(byte);
        }
        self.produced = self.produced.saturating_add(crate::bytes::to_u64(len));
        self.bit = bits.pos;
        Ok(true)
    }

    /// One code of ZOO's LZW; `Ok(false)` at the end code.
    fn lzw_token(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        let State::Lzw {
            table,
            bits,
            old,
            first,
        } = &mut self.state
        else {
            return Err(bad("wrong state"));
        };
        // Codes are packed least significant bit first.
        let mut code = 0u32;
        for i in 0..*bits {
            let at = self.bit.saturating_add(usize::try_from(i).unwrap_or(0));
            let byte = input
                .get(at >> 3)
                .copied()
                .ok_or_else(|| bad("LZW stream ended early"))?;
            code |= u32::from(byte >> (at & 7) & 1) << i;
        }
        self.bit = self.bit.saturating_add(usize::try_from(*bits).unwrap_or(0));
        let free = table.len().saturating_add(258);
        match code {
            257 => return Ok(false),
            256 => {
                table.clear();
                *bits = 9;
                *old = None;
                return Ok(true);
            }
            _ => {}
        }
        let code_us = usize::try_from(code).unwrap_or(usize::MAX);
        let Some(prev) = *old else {
            if code > 255 {
                return Err(bad(format!("LZW code {code} after a clear")));
            }
            *first = u8::try_from(code).unwrap_or(0);
            *old = Some(u16::try_from(code).unwrap_or(0));
            let b = *first;
            self.literal(out, b);
            return Ok(true);
        };
        if code_us > free {
            return Err(bad(format!("LZW code {code} beyond the table")));
        }
        // Expand the code (or, for the next free code, the previous one
        // and its first byte).
        let mut stack = Vec::new();
        let mut cur = if code_us == free {
            stack.push(*first);
            usize::from(prev)
        } else {
            code_us
        };
        while cur > 255 {
            let &(prefix, ch) = table
                .get(cur.saturating_sub(258))
                .ok_or_else(|| bad("LZW code not in the table"))?;
            stack.push(ch);
            cur = usize::from(prefix);
            if stack.len() > 8192 {
                return Err(bad("LZW chain too long"));
            }
        }
        *first = u8::try_from(cur).unwrap_or(0);
        stack.push(*first);
        if table.len() < 8192 - 258 {
            table.push((prev, *first));
            if table.len().saturating_add(258) >= 1usize << *bits && *bits < 13 {
                *bits = bits.saturating_add(1);
            }
        }
        *old = Some(u16::try_from(code).unwrap_or(0));
        let wanted = usize::try_from(self.wanted()).unwrap_or(usize::MAX);
        let n = stack.len().min(wanted);
        out.extend(stack.iter().rev().take(n));
        self.produced = self.produced.saturating_add(crate::bytes::to_u64(n));
        Ok(true)
    }

    /// One MSZIP block; `Ok(false)` at the end.
    fn mszip_block(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>) -> Result<bool> {
        let State::Mszip { dict } = &mut self.state else {
            return Err(bad("wrong state"));
        };
        let at = self.bit >> 3;
        if at >= input.len() && eof {
            return Ok(false);
        }
        let len = crate::bytes::u16_le(input, at).ok_or_else(|| bad("truncated MSZIP block"))?;
        if len == 0 {
            self.bit = self.bit.saturating_add(16);
            return Ok(false);
        }
        let body = input.get(at.saturating_add(2)..).unwrap_or_default();
        let Some(data) = body.strip_prefix(b"CK") else {
            return Err(bad("MSZIP block without 'CK' signature"));
        };
        let (block, used) = inflate::inflate_with_dictionary(data, dict, inflate::WINDOW)?;
        dict.extend_from_slice(&block);
        let excess = dict.len().saturating_sub(inflate::WINDOW);
        dict.drain(..excess);
        let n = block
            .len()
            .min(usize::try_from(self.wanted()).unwrap_or(usize::MAX));
        out.extend_from_slice(block.get(..n).unwrap_or_default());
        self.produced = self.produced.saturating_add(crate::bytes::to_u64(n));
        let next = at.saturating_add(4).saturating_add(used);
        self.bit = next.saturating_mul(8);
        Ok(true)
    }

    fn run(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        goal: usize,
        limit: usize,
    ) -> Result<Step> {
        loop {
            // ZOO's LZW goes on to its end code (so it is consumed).
            if self.finished() && self.params.method != Method::ZooLzw {
                return Ok(Step::Done);
            }
            if out.len() >= goal {
                return Ok(Step::More);
            }
            if self.produced > crate::bytes::to_u64(limit) {
                return Err(Diagnostic::limit(format!(
                    "decompressed data exceeds {limit:#x} bytes"
                )));
            }
            let method = self.params.method;
            let more = match method {
                Method::Lh { .. } | Method::Arj | Method::Lh1 | Method::ArjFastest => {
                    let mut bits = Bits {
                        data: input,
                        pos: self.bit,
                    };
                    if eof && self.params.size.is_none() && bits.pos >= bits.total() {
                        return Ok(Step::Done);
                    }
                    match method {
                        Method::Lh1 => self.lh1_token(&mut bits, out),
                        Method::ArjFastest => self.fastest_token(&mut bits, out),
                        _ => self.static_token(&mut bits, out),
                    }
                    .or_else(|e| {
                        // Without a size, the stream ends with the input.
                        if eof && self.params.size.is_none() {
                            bits.pos = bits.total();
                            Ok(())
                        } else {
                            Err(e)
                        }
                    })?;
                    self.bit = bits.pos;
                    true
                }
                Method::Lzs | Method::Lz5 | Method::Szdd => {
                    match self.ring_token(input, out) {
                        Ok(more) => more,
                        // A partial item at the end is padding.
                        Err(_) if eof => false,
                        Err(e) => return Err(e),
                    }
                }
                Method::ZooLzw => self.lzw_token(input, out)?,
                Method::KwajMszip => self.mszip_block(input, eof, out)?,
                Method::KwajXor => match input.get(self.bit >> 3) {
                    Some(&b) => {
                        self.literal(out, !b);
                        self.bit = self.bit.saturating_add(8);
                        true
                    }
                    None => false,
                },
            };
            if !more {
                if !eof && !matches!(method, Method::ZooLzw | Method::KwajMszip) {
                    return Err(bad("waiting for input"));
                }
                return Ok(Step::Done);
            }
        }
    }
}

impl Decode for Lzh {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        if self.done {
            return Ok(Step::Done);
        }
        let mark = out.len();
        let goal = mark.saturating_add(step);
        let result = self.run(input, eof, out, goal, limit);
        let new = out.get(mark..).unwrap_or_default();
        self.crc = match self.params.check {
            Check::Crc16(_) => CRC16_ARC.update(self.crc, new),
            _ => CRC32.update(self.crc, new),
        };
        if self.produced > crate::bytes::to_u64(limit) {
            return Err(Diagnostic::limit(format!(
                "decompressed data exceeds {limit:#x} bytes"
            )));
        }
        let step = result?;
        if step == Step::Done {
            self.done = true;
        }
        Ok(step)
    }

    fn consumed(&self) -> usize {
        self.bit.div_ceil(8)
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        if let Some(size) = self.params.size
            && self.produced < size
        {
            return Some(Diagnostic::warning(format!(
                "decoded {:#x} of {size:#x} bytes",
                self.produced
            )));
        }
        match self.params.check {
            Check::None => None,
            Check::Crc16(want) => {
                let got = CRC16_ARC.finish(self.crc);
                (got != u64::from(want)).then(|| {
                    Diagnostic::warning(format!(
                        "CRC-16 mismatch: computed {got:#06x}, stored {want:#06x}"
                    ))
                })
            }
            Check::Crc32(want) => {
                let got = CRC32.finish(self.crc);
                (got != u64::from(want)).then(|| {
                    Diagnostic::warning(format!(
                        "CRC-32 mismatch: computed {got:#010x}, stored {want:#010x}"
                    ))
                })
            }
        }
    }

    fn releasable_input(&self) -> usize {
        self.bit >> 3
    }

    fn release_input(&mut self, n: usize) {
        self.bit = self.bit.saturating_sub(n.saturating_mul(8));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        match self.params.window() {
            // Before a whole window, references before the start read the
            // fill byte, which depends on the output length: keep it all.
            Some(w) if self.produced < crate::bytes::to_u64(w) => 0,
            Some(w) => out_len.saturating_sub(w),
            None => out_len,
        }
    }
}
