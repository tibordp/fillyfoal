//! Canonical prefix codes as RAR uses them, and the code-length tables
//! that describe them.
//!
//! Codes are assigned in order of (length, symbol), most significant bit
//! first, lengths 1 to 15; a zero length leaves a symbol out. This is the
//! assignment libarchive's `create_code` (RAR 1.5–4.x reader) and
//! `create_decode_tables` (RAR 5 reader) both make. Like them, an
//! over-subscribed set of lengths is rejected; reading a code that an
//! incomplete set leaves unassigned is an error here (libarchive's RAR 4
//! reader errors too, its RAR 5 reader substitutes a symbol).
//!
//! The decoder is a small table indexed by the next `QUICK` bits for the
//! short codes, and a per-length search (counts and first codes) for the
//! rest. See [`super`] for provenance.

use super::bad;
use super::bits::Bits;
use crate::error::Result;

const MAX_LEN: usize = 15;
const QUICK: u32 = 10;
const QUICK_SHIFT: u32 = MAX_LEN as u32 - QUICK;

/// A decoder for one prefix code.
#[derive(Clone, Default)]
pub struct Code {
    /// Number of codes of each length.
    count: [u16; MAX_LEN + 1],
    /// The first (smallest) code of each length.
    first: [u32; MAX_LEN + 1],
    /// Index into `sorted` of the first symbol of each length.
    start: [u16; MAX_LEN + 1],
    /// Symbols in code order.
    sorted: Vec<u16>,
    /// For each `QUICK`-bit prefix: (length, symbol) of the code it starts
    /// with, length 0 when the code is longer (or unassigned).
    quick: Vec<(u8, u16)>,
}

impl Code {
    /// Heap bytes a clone copies.
    pub fn heap_size(&self) -> usize {
        self.sorted
            .capacity()
            .saturating_mul(std::mem::size_of::<u16>())
            .saturating_add(
                self.quick
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(u8, u16)>()),
            )
    }

    /// Builds the code for `lengths` (one per symbol, 0 = unused).
    pub fn new(lengths: &[u8]) -> Result<Code> {
        let mut c = Code::default();
        for &l in lengths {
            let l = usize::from(l);
            if l > MAX_LEN {
                return Err(bad("code length above 15"));
            }
            if let Some(n) = c.count.get_mut(l) {
                *n = n.saturating_add(1);
            }
        }
        if let Some(n) = c.count.first_mut() {
            *n = 0;
        }
        // Kraft sum in units of 2^-15: at most 1 for a prefix code.
        let mut kraft = 0u32;
        let mut code = 0u32;
        let mut index = 0u16;
        for l in 1..=MAX_LEN {
            let n = c.count.get(l).copied().unwrap_or(0);
            kraft = kraft.saturating_add(u32::from(n) << MAX_LEN.saturating_sub(l));
            code <<= 1;
            if let Some(f) = c.first.get_mut(l) {
                *f = code;
            }
            if let Some(s) = c.start.get_mut(l) {
                *s = index;
            }
            code = code.saturating_add(u32::from(n));
            index = index.saturating_add(n);
        }
        if kraft > 1 << MAX_LEN {
            return Err(bad("over-subscribed prefix code"));
        }
        for l in 1..=MAX_LEN {
            for (sym, &len) in lengths.iter().enumerate() {
                if usize::from(len) == l {
                    c.sorted.push(sym as u16);
                }
            }
        }
        c.quick = vec![(0, 0); 1 << QUICK];
        for l in 1..=(QUICK as usize) {
            let first = c.first.get(l).copied().unwrap_or(0);
            let start = usize::from(c.start.get(l).copied().unwrap_or(0));
            let n = u32::from(c.count.get(l).copied().unwrap_or(0));
            for k in 0..n {
                let sym = c
                    .sorted
                    .get(start.saturating_add(k as usize))
                    .copied()
                    .unwrap_or(0);
                // Every QUICK-bit value beginning with this code.
                let shift = (QUICK as usize).saturating_sub(l);
                let lo = (first.saturating_add(k) as usize) << shift;
                let hi = lo.saturating_add(1 << shift);
                for e in c.quick.get_mut(lo..hi).unwrap_or_default() {
                    *e = (l as u8, sym);
                }
            }
        }
        Ok(c)
    }

    /// Reads one symbol.
    pub fn decode(&self, bits: &mut Bits<'_>) -> Result<u16> {
        let v = bits.peek(MAX_LEN as u32);
        if let Some(&(l, sym)) = self.quick.get((v >> QUICK_SHIFT) as usize)
            && l != 0
        {
            bits.skip(u32::from(l));
            return Ok(sym);
        }
        for l in 1..=MAX_LEN {
            let code = v >> MAX_LEN.saturating_sub(l);
            let first = self.first.get(l).copied().unwrap_or(0);
            let n = u32::from(self.count.get(l).copied().unwrap_or(0));
            if let Some(k) = code.checked_sub(first)
                && k < n
            {
                let at = usize::from(self.start.get(l).copied().unwrap_or(0));
                let sym = self
                    .sorted
                    .get(at.saturating_add(k as usize))
                    .copied()
                    .ok_or_else(|| bad("invalid prefix code"))?;
                bits.skip(l as u32);
                return Ok(sym);
            }
        }
        Err(bad("invalid prefix code in the bit stream"))
    }
}

/// Reads the code lengths of a block's codes into `lengths`: first the 20
/// lengths (4 bits each) of a pre-code, 15 being an escape (15 followed by
/// 0 is a length of 15, by n > 0 a run of n + 2 zeros); then pre-code
/// symbols 0–15 (a length, or with `delta` a value added modulo 16 to the
/// length already there), 16/17 (repeat the previous length 3 + 3 bits /
/// 11 + 7 bits times), 18/19 (as many zeros). As libarchive's `parse_codes`
/// and `parse_tables`.
pub fn read_lengths(bits: &mut Bits<'_>, lengths: &mut [u8], delta: bool) -> Result<()> {
    let mut pre = [0u8; 20];
    let mut i = 0usize;
    while i < pre.len() {
        let l = bits.read(4) as u8;
        if l == 15 {
            let zeros = bits.read(4) as usize;
            if zeros != 0 {
                let end = i.saturating_add(zeros).saturating_add(2).min(pre.len());
                for p in pre.get_mut(i..end).unwrap_or_default() {
                    *p = 0;
                }
                i = end;
                continue;
            }
        }
        if let Some(p) = pre.get_mut(i) {
            *p = l;
        }
        i = i.saturating_add(1);
    }
    let pre = Code::new(&pre)?;
    let mut i = 0usize;
    while i < lengths.len() {
        let sym = pre.decode(bits)?;
        match sym {
            0..=15 => {
                if let Some(l) = lengths.get_mut(i) {
                    *l = if delta {
                        l.wrapping_add(sym as u8) & 15
                    } else {
                        sym as u8
                    };
                }
                i = i.saturating_add(1);
            }
            _ => {
                let n = if sym & 1 == 0 {
                    bits.read(3).saturating_add(3)
                } else {
                    bits.read(7).saturating_add(11)
                };
                let value = if sym < 18 {
                    let prev = i
                        .checked_sub(1)
                        .ok_or_else(|| bad("length repeat at the start"))?;
                    lengths.get(prev).copied().unwrap_or(0)
                } else {
                    0
                };
                let end = i.saturating_add(n as usize).min(lengths.len());
                for l in lengths.get_mut(i..end).unwrap_or_default() {
                    *l = value;
                }
                i = end;
            }
        }
    }
    Ok(())
}
