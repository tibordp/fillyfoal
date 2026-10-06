//! LZMA and LZMA2 decompression (the range-coded LZ77 of 7-Zip and xz),
//! the `.lzma` ("LZMA alone") container, and the xz BCJ and Delta filters.

use crate::codec::filters::Filter;
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("LZMA: {what}"))
}

const PROB_INIT: u16 = 1024;

/// The range decoder.
struct Range<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> Range<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        if data.first() != Some(&0) {
            return Err(bad("range coder does not start with 0"));
        }
        let code = data.get(1..5).ok_or_else(|| bad("truncated range coder"))?.iter().fold(0u32, |a, &b| a << 8 | u32::from(b));
        Ok(Range { data, pos: 5, range: 0xffff_ffff, code })
    }

    fn normalize(&mut self) -> Result<()> {
        if self.range < 1 << 24 {
            let b = *self.data.get(self.pos).ok_or_else(|| bad("unexpected end of data"))?;
            self.pos = self.pos.saturating_add(1);
            self.range <<= 8;
            self.code = self.code << 8 | u32::from(b);
        }
        Ok(())
    }

    fn bit(&mut self, prob: &mut u16) -> Result<u32> {
        let bound = (self.range >> 11).wrapping_mul(u32::from(*prob));
        let bit = if self.code < bound {
            self.range = bound;
            *prob = prob.wrapping_add((2048u16.wrapping_sub(*prob)) >> 5);
            0
        } else {
            self.code = self.code.wrapping_sub(bound);
            self.range = self.range.wrapping_sub(bound);
            *prob = prob.wrapping_sub(*prob >> 5);
            1
        };
        self.normalize()?;
        Ok(bit)
    }

    fn direct(&mut self, count: u32) -> Result<u32> {
        let mut result = 0u32;
        for _ in 0..count {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & t);
            result = (result << 1).wrapping_add(t.wrapping_add(1));
            self.normalize()?;
        }
        Ok(result)
    }

    fn tree(&mut self, probs: &mut [u16], bits: u32) -> Result<u32> {
        let mut m = 1usize;
        for _ in 0..bits {
            let p = probs.get_mut(m).ok_or_else(|| bad("bit tree index"))?;
            m = m << 1 | usize::try_from(self.bit(p)?).unwrap_or(0);
        }
        Ok(u32::try_from(m).unwrap_or(0).wrapping_sub(1 << bits))
    }

    fn reverse(&mut self, probs: &mut [u16], bits: u32) -> Result<u32> {
        let mut m = 1usize;
        let mut sym = 0u32;
        for i in 0..bits {
            let p = probs.get_mut(m).ok_or_else(|| bad("bit tree index"))?;
            let b = self.bit(p)?;
            m = m << 1 | usize::try_from(b).unwrap_or(0);
            sym |= b << i;
        }
        Ok(sym)
    }
}

/// Length decoder probabilities.
#[derive(Clone)]
struct Len {
    choice: u16,
    choice2: u16,
    low: Vec<[u16; 8]>,
    mid: Vec<[u16; 8]>,
    high: [u16; 256],
}

impl Len {
    fn new() -> Self {
        Len { choice: PROB_INIT, choice2: PROB_INIT, low: vec![[PROB_INIT; 8]; 16], mid: vec![[PROB_INIT; 8]; 16], high: [PROB_INIT; 256] }
    }

    fn decode(&mut self, rc: &mut Range<'_>, pos_state: usize) -> Result<u32> {
        if rc.bit(&mut self.choice)? == 0 {
            let t = self.low.get_mut(pos_state).ok_or_else(|| bad("position state"))?;
            return rc.tree(t, 3);
        }
        if rc.bit(&mut self.choice2)? == 0 {
            let t = self.mid.get_mut(pos_state).ok_or_else(|| bad("position state"))?;
            return Ok(8u32.wrapping_add(rc.tree(t, 3)?));
        }
        Ok(16u32.wrapping_add(rc.tree(&mut self.high, 8)?))
    }
}

/// LZMA properties: literal context bits, literal position bits, position bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Props {
    pub lc: u32,
    pub lp: u32,
    pub pb: u32,
}

impl Props {
    pub fn from_byte(b: u8) -> Result<Self> {
        if b >= 9 * 5 * 5 {
            return Err(bad("invalid properties byte"));
        }
        let b = u32::from(b);
        Ok(Props { lc: b % 9, lp: (b / 9) % 5, pb: b / 45 })
    }
}

/// The LZMA decoder state (persisting across LZMA2 chunks).
#[derive(Clone)]
struct State {
    props: Props,
    literal: Vec<u16>,
    is_match: [u16; 192],
    is_rep: [u16; 12],
    is_rep0: [u16; 12],
    is_rep1: [u16; 12],
    is_rep2: [u16; 12],
    is_rep0_long: [u16; 192],
    pos_slot: [[u16; 64]; 4],
    special: [u16; 115],
    align: [u16; 16],
    len: Len,
    rep_len: Len,
    state: usize,
    reps: [u32; 4],
}

impl State {
    fn new(props: Props) -> Self {
        let lit = 0x300usize << (props.lc.saturating_add(props.lp)).min(16);
        State {
            props,
            literal: vec![PROB_INIT; lit],
            is_match: [PROB_INIT; 192],
            is_rep: [PROB_INIT; 12],
            is_rep0: [PROB_INIT; 12],
            is_rep1: [PROB_INIT; 12],
            is_rep2: [PROB_INIT; 12],
            is_rep0_long: [PROB_INIT; 192],
            pos_slot: [[PROB_INIT; 64]; 4],
            special: [PROB_INIT; 115],
            align: [PROB_INIT; 16],
            len: Len::new(),
            rep_len: Len::new(),
            state: 0,
            reps: [0; 4],
        }
    }

    /// Decodes `rc` into `out` until `end` bytes of output exist (if known),
    /// or the end marker. `dict_start` bounds back-references.
    fn run(&mut self, rc: &mut Range<'_>, out: &mut Vec<u8>, dict_start: usize, end: Option<usize>, limit: usize) -> Result<()> {
        let pb_mask = (1usize << self.props.pb).wrapping_sub(1);
        let lp_mask = (1usize << self.props.lp).wrapping_sub(1);
        let lc = self.props.lc;
        loop {
            if end.is_some_and(|e| out.len() >= e) {
                return Ok(());
            }
            if out.len() > limit {
                return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
            }
            let pos_state = out.len() & pb_mask;
            let s = self.state;
            let idx = s.wrapping_mul(16).wrapping_add(pos_state);
            let mut bit = rc.bit(self.is_match.get_mut(idx).ok_or_else(|| bad("state"))?)?;
            if bit == 0 {
                // Literal.
                let prev = out.last().copied().unwrap_or(0);
                let base = 0x300usize.wrapping_mul(((out.len() & lp_mask) << lc).wrapping_add(usize::from(prev) >> (8u32.saturating_sub(lc))));
                let probs = self.literal.get_mut(base..base.wrapping_add(0x300)).ok_or_else(|| bad("literal state"))?;
                let mut sym = 1usize;
                if s >= 7 {
                    let dist = usize::try_from(self.reps[0]).unwrap_or(0).wrapping_add(1);
                    let mut match_byte = out.len().checked_sub(dist).and_then(|i| out.get(i)).copied().ok_or_else(|| bad("match distance"))?;
                    loop {
                        let match_bit = usize::from(match_byte >> 7 & 1);
                        match_byte <<= 1;
                        let i = 0x100usize.wrapping_add(match_bit << 8).wrapping_add(sym);
                        let b = usize::try_from(rc.bit(probs.get_mut(i).ok_or_else(|| bad("literal"))?)?).unwrap_or(0);
                        sym = sym << 1 | b;
                        if match_bit != b || sym >= 0x100 {
                            break;
                        }
                    }
                }
                while sym < 0x100 {
                    let b = usize::try_from(rc.bit(probs.get_mut(sym).ok_or_else(|| bad("literal"))?)?).unwrap_or(0);
                    sym = sym << 1 | b;
                }
                out.push(u8::try_from(sym & 0xff).unwrap_or(0));
                self.state = if s < 4 { 0 } else if s < 10 { s.wrapping_sub(3) } else { s.wrapping_sub(6) };
                continue;
            }
            let len;
            bit = rc.bit(self.is_rep.get_mut(s).ok_or_else(|| bad("state"))?)?;
            if bit == 1 {
                if out.len() <= dict_start {
                    return Err(bad("repeated match before any data"));
                }
                if rc.bit(self.is_rep0.get_mut(s).ok_or_else(|| bad("state"))?)? == 0 {
                    if rc.bit(self.is_rep0_long.get_mut(idx).ok_or_else(|| bad("state"))?)? == 0 {
                        // Short rep: one byte at rep0.
                        self.state = if s < 7 { 9 } else { 11 };
                        let dist = usize::try_from(self.reps[0]).unwrap_or(0).wrapping_add(1);
                        let b = out.len().checked_sub(dist).and_then(|i| out.get(i)).copied().ok_or_else(|| bad("match distance"))?;
                        out.push(b);
                        continue;
                    }
                } else {
                    let dist;
                    if rc.bit(self.is_rep1.get_mut(s).ok_or_else(|| bad("state"))?)? == 0 {
                        dist = self.reps[1];
                    } else {
                        if rc.bit(self.is_rep2.get_mut(s).ok_or_else(|| bad("state"))?)? == 0 {
                            dist = self.reps[2];
                        } else {
                            dist = self.reps[3];
                            self.reps[3] = self.reps[2];
                        }
                        self.reps[2] = self.reps[1];
                    }
                    self.reps[1] = self.reps[0];
                    self.reps[0] = dist;
                }
                len = self.rep_len.decode(rc, pos_state)?;
                self.state = if s < 7 { 8 } else { 11 };
            } else {
                self.reps[3] = self.reps[2];
                self.reps[2] = self.reps[1];
                self.reps[1] = self.reps[0];
                len = self.len.decode(rc, pos_state)?;
                self.state = if s < 7 { 7 } else { 10 };
                let len_state = usize::try_from(len.min(3)).unwrap_or(3);
                let slot = rc.tree(self.pos_slot.get_mut(len_state).ok_or_else(|| bad("length state"))?, 6)?;
                let dist = if slot < 4 {
                    slot
                } else {
                    let direct = (slot >> 1).wrapping_sub(1);
                    let base = (2 | (slot & 1)) << direct;
                    if slot < 14 {
                        let start = usize::try_from(base.wrapping_sub(slot)).unwrap_or(0);
                        let probs = self.special.get_mut(start..).ok_or_else(|| bad("distance"))?;
                        base.wrapping_add(rc.reverse(probs, direct)?)
                    } else {
                        let high = rc.direct(direct.wrapping_sub(4))? << 4;
                        base.wrapping_add(high).wrapping_add(rc.reverse(&mut self.align, 4)?)
                    }
                };
                if dist == 0xffff_ffff {
                    return Ok(()); // end marker
                }
                self.reps[0] = dist;
            }
            let len = usize::try_from(len).unwrap_or(0).wrapping_add(2);
            let dist = usize::try_from(self.reps[0]).unwrap_or(usize::MAX).wrapping_add(1);
            if dist > out.len().saturating_sub(dict_start) {
                return Err(bad("match distance beyond the dictionary"));
            }
            let mut len = len;
            if let Some(e) = end {
                len = len.min(e.saturating_sub(out.len()));
            }
            let from = out.len().wrapping_sub(dist);
            for i in 0..len {
                let b = out.get(from.wrapping_add(i)).copied().unwrap_or(0);
                out.push(b);
            }
        }
    }
}

/// `.lzma` ("LZMA alone"): properties, dictionary size, uncompressed size
/// (all ones: unknown, ended by a marker), then the range-coded data.
#[derive(Clone, Copy)]
pub struct LzmaAlone;

impl Filter for LzmaAlone {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let props = Props::from_byte(*input.first().ok_or_else(|| bad("truncated header"))?)?;
        let size = input.get(5..13).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes).ok_or_else(|| bad("truncated header"))?;
        let end = (size != u64::MAX).then(|| usize::try_from(size).unwrap_or(usize::MAX));
        if end.is_some_and(|e| e > limit) {
            return Err(Diagnostic::limit(format!("LZMA data claims {size:#x} bytes")));
        }
        let mut rc = Range::new(input.get(13..).unwrap_or_default())?;
        let mut out = Vec::with_capacity(end.unwrap_or(0).min(1 << 24));
        State::new(props).run(&mut rc, &mut out, 0, end, limit)?;
        Ok(out)
    }
}

/// Raw LZMA with known properties (7-Zip, ZIP method 14): `end` is the
/// decoded size when known.
#[derive(Clone, Copy)]
pub struct LzmaRaw {
    pub props: Props,
    pub end: Option<usize>,
}

impl Filter for LzmaRaw {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut rc = Range::new(input)?;
        let mut out = Vec::new();
        State::new(self.props).run(&mut rc, &mut out, 0, self.end, limit)?;
        Ok(out)
    }
}

/// Raw LZMA2 (xz blocks, 7-Zip): a sequence of chunks.
#[derive(Clone, Copy)]
pub struct Lzma2;

pub fn lzma2(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut state: Option<State> = None;
    let mut dict_start = 0usize;
    loop {
        let control = *input.get(pos).ok_or_else(|| bad("truncated LZMA2 data"))?;
        pos = pos.saturating_add(1);
        match control {
            0x00 => return Ok(out),
            0x01 | 0x02 => {
                let size = input.get(pos..pos.saturating_add(2)).ok_or_else(|| bad("truncated chunk"))?;
                let size = usize::from(u16::from_be_bytes([size.first().copied().unwrap_or(0), size.get(1).copied().unwrap_or(0)])).saturating_add(1);
                let data = input.get(pos.saturating_add(2)..pos.saturating_add(2).saturating_add(size)).ok_or_else(|| bad("truncated chunk"))?;
                if control == 0x01 {
                    dict_start = out.len();
                }
                out.extend_from_slice(data);
                pos = pos.saturating_add(2).saturating_add(size);
            }
            0x80..=0xff => {
                let h = input.get(pos..pos.saturating_add(4)).ok_or_else(|| bad("truncated chunk header"))?;
                let unpacked = (usize::from(control & 0x1f) << 16 | usize::from(h.first().copied().unwrap_or(0)) << 8 | usize::from(h.get(1).copied().unwrap_or(0))).saturating_add(1);
                let packed = (usize::from(h.get(2).copied().unwrap_or(0)) << 8 | usize::from(h.get(3).copied().unwrap_or(0))).saturating_add(1);
                pos = pos.saturating_add(4);
                let reset = (control >> 5) & 3;
                if reset == 3 {
                    dict_start = out.len();
                }
                if reset >= 2 {
                    let props = Props::from_byte(*input.get(pos).ok_or_else(|| bad("truncated properties"))?)?;
                    if props.lc.saturating_add(props.lp) > 4 {
                        return Err(bad("lc + lp exceeds 4"));
                    }
                    pos = pos.saturating_add(1);
                    state = Some(State::new(props));
                } else if reset == 1 {
                    let props = state.as_ref().map(|s| s.props).ok_or_else(|| bad("state reset before properties"))?;
                    state = Some(State::new(props));
                }
                let st = state.as_mut().ok_or_else(|| bad("LZMA chunk before properties"))?;
                let data = input.get(pos..pos.saturating_add(packed)).ok_or_else(|| bad("truncated chunk"))?;
                let mut rc = Range::new(data)?;
                let end = out.len().saturating_add(unpacked);
                if end > limit {
                    return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
                }
                st.run(&mut rc, &mut out, dict_start, Some(end), limit)?;
                pos = pos.saturating_add(packed);
            }
            _ => return Err(bad("invalid LZMA2 control byte")),
        }
        if out.len() > limit {
            return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
        }
    }
}

impl Filter for Lzma2 {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        lzma2(input, limit)
    }
}

// ---------------------------------------------------------------------------
// Branch converters (BCJ) and Delta, decoding direction.

fn test_ms(b: u8) -> bool {
    b == 0 || b == 0xff
}

/// x86 BCJ over a whole buffer starting at stream position 0.
pub fn bcj_x86(buf: &mut [u8]) {
    const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
    const BIT_NUM: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
    if buf.len() <= 4 {
        return;
    }
    let size = buf.len().saturating_sub(4);
    let mut prev_pos: usize = usize::MAX;
    let mut prev_mask: u32 = 0;
    let mut i = 0usize;
    let byte = |buf: &[u8], i: usize| buf.get(i).copied().unwrap_or(0);
    while i < size {
        if byte(buf, i) & 0xfe != 0xe8 {
            i = i.saturating_add(1);
            continue;
        }
        let gap = i.wrapping_sub(prev_pos);
        if gap > 3 {
            prev_mask = 0;
        } else {
            prev_mask = (prev_mask << (gap.wrapping_sub(1) & 31)) & 7;
            if prev_mask != 0 {
                let m = usize::try_from(prev_mask).unwrap_or(0);
                let b = byte(buf, i.wrapping_add(4).wrapping_sub(usize::try_from(BIT_NUM.get(m).copied().unwrap_or(0)).unwrap_or(0)));
                if !ALLOWED.get(m).copied().unwrap_or(false) || test_ms(b) {
                    prev_pos = i;
                    prev_mask = prev_mask << 1 | 1;
                    i = i.saturating_add(1);
                    continue;
                }
            }
        }
        prev_pos = i;
        if test_ms(byte(buf, i.saturating_add(4))) {
            let src_bytes: [u8; 4] = buf.get(i.saturating_add(1)..i.saturating_add(5)).and_then(|s| s.try_into().ok()).unwrap_or([0; 4]);
            let mut src = u32::from_le_bytes(src_bytes);
            let pos = u32::try_from(i).unwrap_or(0).wrapping_add(5);
            let mut dest;
            loop {
                dest = src.wrapping_sub(pos);
                if prev_mask == 0 {
                    break;
                }
                let j = BIT_NUM.get(usize::try_from(prev_mask).unwrap_or(0)).copied().unwrap_or(0).wrapping_mul(8);
                let b = u8::try_from((dest >> (24u32.wrapping_sub(j) & 31)) & 0xff).unwrap_or(0);
                if !test_ms(b) {
                    break;
                }
                src = dest ^ ((1u32 << (32u32.wrapping_sub(j) & 31)).wrapping_sub(1));
            }
            dest &= 0x01ff_ffff;
            dest |= 0u32.wrapping_sub(dest & 0x0100_0000);
            if let Some(slot) = buf.get_mut(i.saturating_add(1)..i.saturating_add(5)) {
                slot.copy_from_slice(&dest.to_le_bytes());
            }
            i = i.saturating_add(5);
        } else {
            prev_mask = prev_mask << 1 | 1;
            i = i.saturating_add(1);
        }
    }
}

/// ARM (32-bit) BCJ: BL instructions.
pub fn bcj_arm(buf: &mut [u8]) {
    for (i, w) in buf.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        if w[3] == 0xeb {
            let src = (u32::from(w[2]) << 16 | u32::from(w[1]) << 8 | u32::from(w[0])) << 2;
            let pc = u32::try_from(i).unwrap_or(0).wrapping_mul(4).wrapping_add(8);
            let dest = src.wrapping_sub(pc) >> 2;
            let d = dest.to_le_bytes();
            w[0] = d[0];
            w[1] = d[1];
            w[2] = d[2];
        }
    }
}

/// ARM64 BCJ: BL and ADRP instructions.
pub fn bcj_arm64(buf: &mut [u8]) {
    for (i, w) in buf.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let pc = u32::try_from(i).unwrap_or(0).wrapping_mul(4);
        let mut instr = u32::from_le_bytes(*w);
        if instr >> 26 == 0x25 {
            instr = 0x9400_0000 | (instr.wrapping_sub(pc >> 2) & 0x03ff_ffff);
            *w = instr.to_le_bytes();
        } else if instr & 0x9f00_0000 == 0x9000_0000 {
            let src = (instr >> 29 & 3) | (instr >> 3 & 0x001f_fffc);
            if src.wrapping_add(0x0002_0000) & 0x001c_0000 != 0 {
                continue;
            }
            let dest = src.wrapping_sub(pc >> 12);
            instr &= 0x9000_001f;
            instr |= (dest & 3) << 29;
            instr |= (dest & 0x0003_fffc) << 3;
            instr |= 0u32.wrapping_sub(dest & 0x0002_0000) & 0x00e0_0000;
            *w = instr.to_le_bytes();
        }
    }
}

/// Delta decoding with byte distance `distance`.
pub fn delta(buf: &mut [u8], distance: usize) {
    for i in distance..buf.len() {
        let prev = buf.get(i.wrapping_sub(distance)).copied().unwrap_or(0);
        if let Some(b) = buf.get_mut(i) {
            *b = b.wrapping_add(prev);
        }
    }
}

/// An xz/7-Zip filter after the decompressor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Post {
    X86,
    Arm,
    Arm64,
    Delta(usize),
}

impl Post {
    pub fn apply(self, buf: &mut [u8]) {
        match self {
            Post::X86 => bcj_x86(buf),
            Post::Arm => bcj_arm(buf),
            Post::Arm64 => bcj_arm64(buf),
            Post::Delta(d) => delta(buf, d),
        }
    }
}
