//! Quantum (CAB compression type 2): LZ77 with an adaptive arithmetic
//! coder, as described by libmspack's `qtmd.c` (after Matthew Russotto's
//! description of the format).
//!
//! Eight adaptive models: a selector (7 symbols: four literal ranges of
//! 64 bytes, matches of length 3, of length 4, and of a coded length), the
//! four literal models, two position-slot models for the fixed-length
//! matches, and a position-slot and a length-slot model for the rest.
//! Extra bits for positions and lengths are read straight from the same
//! MSB-first bitstream that feeds the arithmetic decoder. Output comes in
//! 32 KiB frames: the arithmetic decoder restarts at every frame (one CAB
//! data block), while the models and the window carry over.

use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("Quantum: {what}"))
}

const POSITION_BASE: [u32; 42] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 393216, 524288, 786432, 1048576, 1572864,
];
const EXTRA_BITS: [u8; 42] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19,
];
const LENGTH_BASE: [u8; 27] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 18, 22, 26, 30, 38, 46, 54, 62, 78, 94, 110, 126, 158, 190,
    222, 254,
];
const LENGTH_EXTRA: [u8; 27] = [
    0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// An adaptive frequency model: symbols sorted by decreasing frequency,
/// with cumulative frequencies (`cum[entries]` is 0).
#[derive(Clone, Debug)]
struct Model {
    shifts_left: u32,
    syms: Vec<u16>,
    cum: Vec<u32>,
}

impl Model {
    pub fn new(start: u16, len: u16) -> Self {
        Model {
            shifts_left: 4,
            syms: (0..=len).map(|i| start.saturating_add(i)).collect(),
            cum: (0..=len)
                .map(|i| u32::from(len.saturating_sub(i)))
                .collect(),
        }
    }

    pub fn entries(&self) -> usize {
        self.syms.len().saturating_sub(1)
    }

    pub fn total(&self) -> u32 {
        self.cum.first().copied().unwrap_or(0)
    }

    /// Credits symbol index `index` (and everything ranked above it), and
    /// rescales when the total grows too large.
    pub fn bump(&mut self, index: usize) {
        for c in self.cum.iter_mut().take(index.saturating_add(1)) {
            *c = c.saturating_add(8);
        }
        if self.total() > 3800 {
            self.update();
        }
    }

    fn update(&mut self) {
        let n = self.entries();
        self.shifts_left = self.shifts_left.saturating_sub(1);
        if self.shifts_left != 0 {
            for i in (0..n).rev() {
                let next = self.cum.get(i.saturating_add(1)).copied().unwrap_or(0);
                if let Some(c) = self.cum.get_mut(i) {
                    *c >>= 1;
                    if *c <= next {
                        *c = next.saturating_add(1);
                    }
                }
            }
            return;
        }
        self.shifts_left = 50;
        for i in 0..n {
            let next = self.cum.get(i.saturating_add(1)).copied().unwrap_or(0);
            if let Some(c) = self.cum.get_mut(i) {
                *c = c.saturating_sub(next).saturating_add(1) >> 1;
            }
        }
        // An in-place selection sort by decreasing frequency (its
        // stability matters).
        for i in 0..n.saturating_sub(1) {
            for j in i.saturating_add(1)..n {
                let (a, b) = (
                    self.cum.get(i).copied().unwrap_or(0),
                    self.cum.get(j).copied().unwrap_or(0),
                );
                if a < b {
                    self.cum.swap(i, j);
                    self.syms.swap(i, j);
                }
            }
        }
        for i in (0..n).rev() {
            let next = self.cum.get(i.saturating_add(1)).copied().unwrap_or(0);
            if let Some(c) = self.cum.get_mut(i) {
                *c = c.saturating_add(next);
            }
        }
    }
}

/// The models, in a fixed order: selector, literals ×4, length-3 and
/// length-4 positions, coded-length positions, length slots.
#[derive(Clone, Debug)]
struct Models {
    pub selector: Model,
    pub literal: [Model; 4],
    pub pos3: Model,
    pub pos4: Model,
    pub pos: Model,
    pub len: Model,
}

impl Models {
    pub fn new(window_bits: u8) -> Self {
        let slots = u16::from(window_bits).saturating_mul(2);
        Models {
            selector: Model::new(0, 7),
            literal: [
                Model::new(0, 64),
                Model::new(64, 64),
                Model::new(128, 64),
                Model::new(192, 64),
            ],
            pos3: Model::new(0, slots.min(24)),
            pos4: Model::new(0, slots.min(36)),
            pos: Model::new(0, slots),
            len: Model::new(0, 27),
        }
    }
}

/// MSB-first bits of one frame's data; past its end come the 0xFF trailer
/// CAB extraction appends, then zeros.
struct Bits<'a> {
    data: &'a [u8],
    bit: usize,
}

impl Bits<'_> {
    fn bit(&mut self) -> Result<u32> {
        let at = self.bit / 8;
        let byte = match self.data.get(at) {
            Some(&b) => b,
            None if at == self.data.len() => 0xff,
            None if at < self.data.len().saturating_add(4) => 0,
            None => return Err(bad("input ends unexpectedly")),
        };
        let v = u32::from(byte.rotate_left(u32::try_from(self.bit % 8).unwrap_or(0)) >> 7);
        self.bit = self.bit.saturating_add(1);
        Ok(v)
    }

    fn read(&mut self, n: u8) -> Result<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = v << 1 | self.bit()?;
        }
        Ok(v)
    }
}

/// The arithmetic decoder (16-bit registers).
struct Coder {
    h: u32,
    l: u32,
    c: u32,
}

impl Coder {
    fn symbol(&mut self, bits: &mut Bits<'_>, model: &mut Model) -> Result<u16> {
        let total = model.total();
        let range = (self.h.wrapping_sub(self.l) & 0xffff).saturating_add(1);
        let offset = i64::from(self.c)
            .saturating_sub(i64::from(self.l))
            .saturating_add(1);
        let symf = offset
            .saturating_mul(i64::from(total))
            .saturating_sub(1)
            .checked_div(i64::from(range))
            .unwrap_or(0)
            & 0xffff;
        let n = model.entries();
        let mut i = 1usize;
        while i < n {
            if i64::from(model.cum.get(i).copied().unwrap_or(0)) <= symf {
                break;
            }
            i = i.saturating_add(1);
        }
        let index = i.saturating_sub(1);
        let sym = model
            .syms
            .get(index)
            .copied()
            .ok_or_else(|| bad("bad model"))?;
        let range = u64::from(self.h.wrapping_sub(self.l).wrapping_add(1));
        let total = u64::from(total.max(1));
        let hi = u64::from(model.cum.get(index).copied().unwrap_or(0));
        let lo = u64::from(model.cum.get(i).copied().unwrap_or(0));
        let l = u64::from(self.l);
        self.h = u32::try_from(
            l.saturating_add(hi.saturating_mul(range).checked_div(total).unwrap_or(0))
                .wrapping_sub(1)
                & 0xffff,
        )
        .unwrap_or(0);
        self.l = u32::try_from(
            l.saturating_add(lo.saturating_mul(range).checked_div(total).unwrap_or(0)) & 0xffff,
        )
        .unwrap_or(0);
        model.bump(index);
        loop {
            if self.l & 0x8000 != self.h & 0x8000 {
                if self.l & 0x4000 != 0 && self.h & 0x4000 == 0 {
                    // Underflow.
                    self.c ^= 0x4000;
                    self.l &= 0x3fff;
                    self.h |= 0x4000;
                } else {
                    break;
                }
            }
            self.l = self.l << 1 & 0xffff;
            self.h = (self.h << 1 | 1) & 0xffff;
            self.c = (self.c << 1 | bits.bit()?) & 0xffff;
        }
        Ok(sym)
    }
}

/// A Quantum decoder: models and window carried across frames.
#[derive(Clone, Debug)]
pub struct Quantum {
    window_bits: u8,
    models: Models,
    hist: Vec<u8>,
    offset: u64,
}

impl Quantum {
    pub fn new(window_bits: u8) -> Result<Self> {
        if !(10..=21).contains(&window_bits) {
            return Err(bad("window size out of range"));
        }
        Ok(Quantum {
            window_bits,
            models: Models::new(window_bits),
            hist: Vec::new(),
            offset: 0,
        })
    }

    /// Decodes one frame of `frame_len` bytes from `data` (one CAB data
    /// block) and appends it to `out`.
    pub fn frame(
        &mut self,
        data: &[u8],
        frame_len: usize,
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<()> {
        if out.len().saturating_add(frame_len) > limit {
            return Err(Diagnostic::limit(format!(
                "decompressed data exceeds {limit:#x} bytes"
            )));
        }
        let window = 1usize << self.window_bits;
        if self.hist.len() > window.saturating_mul(2) {
            let drop = self.hist.len().saturating_sub(window);
            self.hist.drain(..drop);
        }
        let start = self.hist.len();
        let mut bits = Bits { data, bit: 0 };
        let mut coder = Coder {
            h: 0xffff,
            l: 0,
            c: bits.read(16)?,
        };
        let m = &mut self.models;
        let mut produced = 0usize;
        while produced < frame_len {
            let selector = coder.symbol(&mut bits, &mut m.selector)?;
            if let Some(model) = m.literal.get_mut(usize::from(selector)) {
                let sym = coder.symbol(&mut bits, model)?;
                self.hist.push(u8::try_from(sym).unwrap_or(0));
                produced = produced.saturating_add(1);
                continue;
            }
            let (slot, length) = match selector {
                4 => (coder.symbol(&mut bits, &mut m.pos3)?, 3usize),
                5 => (coder.symbol(&mut bits, &mut m.pos4)?, 4),
                6 => {
                    let ls = usize::from(coder.symbol(&mut bits, &mut m.len)?);
                    let extra = bits.read(LENGTH_EXTRA.get(ls).copied().unwrap_or(0))?;
                    let base = usize::from(LENGTH_BASE.get(ls).copied().unwrap_or(0));
                    let len = base
                        .saturating_add(usize::try_from(extra).unwrap_or(0))
                        .saturating_add(5);
                    (coder.symbol(&mut bits, &mut m.pos)?, len)
                }
                _ => return Err(bad("invalid selector")),
            };
            let slot = usize::from(slot);
            let extra = bits.read(EXTRA_BITS.get(slot).copied().unwrap_or(0))?;
            let distance = usize::try_from(
                POSITION_BASE
                    .get(slot)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(extra)
                    .saturating_add(1),
            )
            .unwrap_or(usize::MAX);
            let available = usize::try_from(self.offset)
                .unwrap_or(usize::MAX)
                .saturating_add(produced);
            if distance > available || distance > window || distance > self.hist.len() {
                return Err(bad("match offset reaches before the start of the window"));
            }
            if produced.saturating_add(length) > frame_len {
                return Err(bad("match crosses the end of the frame"));
            }
            let from = self.hist.len().saturating_sub(distance);
            for i in 0..length {
                let byte = self.hist.get(from.saturating_add(i)).copied().unwrap_or(0);
                self.hist.push(byte);
            }
            produced = produced.saturating_add(length);
        }
        out.extend_from_slice(self.hist.get(start..).unwrap_or_default());
        self.offset = self.offset.saturating_add(crate::bytes::to_u64(produced));
        Ok(())
    }
}
