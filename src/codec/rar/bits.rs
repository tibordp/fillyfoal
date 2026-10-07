//! The RAR bit reader (bytes read most significant bit first) and the
//! canonical Huffman tables of unrar's `MakeDecodeTables`/`DecodeNumber`,
//! including their behaviour on incomplete codes.

/// A bit position over one member's packed data. Reads past the end yield
/// zero bits; [`Bits::overrun`] tells when that happened.
pub(super) struct Bits<'a> {
    pub data: &'a [u8],
    /// Byte offset of `data[0]` in the member (bytes released before it).
    pub base: u64,
    /// Position in bits from the start of `data`.
    pub pos: u64,
}

impl Bits<'_> {
    fn byte(&self, i: u64) -> u32 {
        i.checked_sub(self.base)
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| self.data.get(i))
            .copied()
            .map_or(0, u32::from)
    }

    /// The next 16 bits, without consuming them (unrar's `getbits`).
    pub fn peek16(&self) -> u32 {
        let at = self.pos >> 3;
        let word = self.byte(at) << 16
            | self.byte(at.saturating_add(1)) << 8
            | self.byte(at.saturating_add(2));
        (word >> (8u64.wrapping_sub(self.pos & 7))) & 0xffff
    }

    /// The next 32 bits, without consuming them (unrar's `getbits32`).
    pub fn peek32(&self) -> u32 {
        let at = self.pos >> 3;
        let word = u64::from(self.byte(at)) << 32
            | u64::from(self.byte(at.saturating_add(1))) << 24
            | u64::from(self.byte(at.saturating_add(2))) << 16
            | u64::from(self.byte(at.saturating_add(3))) << 8
            | u64::from(self.byte(at.saturating_add(4)));
        u32::try_from((word >> (8u64.wrapping_sub(self.pos & 7))) & 0xffff_ffff).unwrap_or(0)
    }

    pub fn skip(&mut self, n: u32) {
        self.pos = self.pos.saturating_add(u64::from(n));
    }

    /// Reads `n` (at most 32) bits.
    pub fn read(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let n = n.min(32);
        let v = self.peek32() >> 32u32.wrapping_sub(n);
        self.skip(n);
        v
    }

    /// Reads `n` (up to 64) bits.
    pub fn read_long(&mut self, n: u32) -> u64 {
        if n > 32 {
            let hi = u64::from(self.read(n.saturating_sub(32)));
            hi << 32 | u64::from(self.read(32))
        } else {
            u64::from(self.read(n))
        }
    }

    pub fn align(&mut self) {
        self.pos = self.pos.saturating_add(7) & !7;
    }

    /// The byte holding the next bit.
    pub fn byte_pos(&self) -> u64 {
        self.pos >> 3
    }

    /// Reads a whole byte at a byte boundary (unrar's `GetChar`).
    pub fn get_byte(&mut self) -> u8 {
        let b = self.byte(self.pos >> 3);
        self.pos = (self.pos | 7).saturating_add(1);
        u8::try_from(b).unwrap_or(0)
    }

    /// Whether reading went past the end of the data.
    pub fn overrun(&self) -> bool {
        self.pos > self.end_bits()
    }

    /// Whether all bits of the data have been read.
    pub fn exhausted(&self) -> bool {
        self.pos >= self.end_bits()
    }

    fn end_bits(&self) -> u64 {
        self.base
            .saturating_add(crate::bytes::to_u64(self.data.len()))
            .saturating_mul(8)
    }
}

/// A decoding table built like unrar's `MakeDecodeTables`.
#[derive(Clone, Debug)]
pub(super) struct Huff {
    /// Left-aligned (16-bit) upper limit of the codes of each length.
    limit: [u32; 16],
    /// Index in `symbols` of the first code of each length.
    first: [u32; 16],
    symbols: Vec<u16>,
    quick_bits: u32,
    quick_len: Vec<u8>,
    quick_sym: Vec<u16>,
}

impl Huff {
    /// A table for code `lengths` (low 4 bits used); `quick_bits` is 10
    /// for the main (literal/length) tables and 7 for the others, as in
    /// unrar (it only matters for incomplete codes).
    pub fn new(lengths: &[u8], quick_bits: u32) -> Self {
        let size = lengths.len();
        let mut count = [0u32; 16];
        for &l in lengths {
            if let Some(c) = count.get_mut(usize::from(l & 0xf)) {
                *c = c.saturating_add(1);
            }
        }
        count[0] = 0;
        let mut limit = [0u32; 16];
        let mut first = [0u32; 16];
        let mut upper = 0u32;
        for i in 1..16usize {
            upper = upper.saturating_add(count.get(i).copied().unwrap_or(0));
            let aligned = upper
                .checked_shl(16u32.saturating_sub(i as u32))
                .unwrap_or(u32::MAX);
            upper = upper.saturating_mul(2);
            if let Some(l) = limit.get_mut(i) {
                *l = aligned;
            }
            let prev = first
                .get(i.saturating_sub(1))
                .copied()
                .unwrap_or(0)
                .saturating_add(count.get(i.saturating_sub(1)).copied().unwrap_or(0));
            if let Some(f) = first.get_mut(i) {
                *f = prev;
            }
        }
        let mut symbols = vec![0u16; size];
        let mut next = first;
        for (sym, &l) in lengths.iter().enumerate() {
            let l = usize::from(l & 0xf);
            if l == 0 {
                continue;
            }
            if let Some(n) = next.get_mut(l) {
                if let Some(slot) = usize::try_from(*n).ok().and_then(|n| symbols.get_mut(n)) {
                    *slot = u16::try_from(sym).unwrap_or(0);
                }
                *n = n.saturating_add(1);
            }
        }
        let quick_size = 1usize << quick_bits;
        let mut quick_len = vec![0u8; quick_size];
        let mut quick_sym = vec![0u16; quick_size];
        let mut cur = 1usize;
        for code in 0..quick_size {
            let field = u32::try_from(code).unwrap_or(0) << 16u32.saturating_sub(quick_bits);
            while cur < 16 && field >= limit.get(cur).copied().unwrap_or(0) {
                cur = cur.saturating_add(1);
            }
            if let Some(q) = quick_len.get_mut(code) {
                *q = u8::try_from(cur).unwrap_or(16);
            }
            let dist = field.wrapping_sub(limit.get(cur.saturating_sub(1)).copied().unwrap_or(0))
                >> (16usize.saturating_sub(cur));
            let sym = if cur < 16 {
                let pos = first.get(cur).copied().unwrap_or(0).wrapping_add(dist);
                usize::try_from(pos)
                    .ok()
                    .filter(|&p| p < size)
                    .and_then(|p| symbols.get(p))
                    .copied()
                    .unwrap_or(0)
            } else {
                0
            };
            if let Some(q) = quick_sym.get_mut(code) {
                *q = sym;
            }
        }
        Huff {
            limit,
            first,
            symbols,
            quick_bits,
            quick_len,
            quick_sym,
        }
    }

    /// unrar's `DecodeNumber`.
    pub fn decode(&self, bits: &mut Bits<'_>) -> u32 {
        let field = bits.peek16() & 0xfffe;
        if field
            < self
                .limit
                .get(self.quick_bits as usize)
                .copied()
                .unwrap_or(0)
        {
            let code = (field >> 16u32.saturating_sub(self.quick_bits)) as usize;
            bits.skip(u32::from(self.quick_len.get(code).copied().unwrap_or(16)));
            return u32::from(self.quick_sym.get(code).copied().unwrap_or(0));
        }
        let mut n = 15usize;
        for i in (self.quick_bits as usize).saturating_add(1)..15 {
            if field < self.limit.get(i).copied().unwrap_or(0) {
                n = i;
                break;
            }
        }
        bits.skip(n as u32);
        let dist = field.wrapping_sub(self.limit.get(n.saturating_sub(1)).copied().unwrap_or(0))
            >> (16usize.saturating_sub(n));
        let pos = self.first.get(n).copied().unwrap_or(0).wrapping_add(dist);
        let pos = usize::try_from(pos)
            .ok()
            .filter(|&p| p < self.symbols.len())
            .unwrap_or(0);
        u32::from(self.symbols.get(pos).copied().unwrap_or(0))
    }
}

/// Reads the 20 bit lengths of the pre-code (shared by RAR 3 and RAR 5):
/// 4 bits each, 15 escaping either a length of 15 or a run of zeros.
pub(super) fn read_bit_lengths(bits: &mut Bits<'_>) -> [u8; 20] {
    let mut out = [0u8; 20];
    let mut i = 0usize;
    while i < out.len() {
        let len = bits.read(4);
        if len == 15 {
            let zeros = bits.read(4);
            if zeros == 0 {
                if let Some(o) = out.get_mut(i) {
                    *o = 15;
                }
                i = i.saturating_add(1);
            } else {
                for _ in 0..zeros.saturating_add(2) {
                    if i >= out.len() {
                        break;
                    }
                    if let Some(o) = out.get_mut(i) {
                        *o = 0;
                    }
                    i = i.saturating_add(1);
                }
            }
        } else {
            if let Some(o) = out.get_mut(i) {
                *o = u8::try_from(len).unwrap_or(0);
            }
            i = i.saturating_add(1);
        }
    }
    out
}

/// Reads `table.len()` code lengths with the pre-code `bc`: 0–15 literal
/// (added to `old` modulo 16 if given, RAR 3), 16/17 repeat the previous
/// length, 18/19 runs of zeros. `None` if the first code repeats.
pub(super) fn read_lengths(
    bits: &mut Bits<'_>,
    bc: &Huff,
    table: &mut [u8],
    old: Option<&[u8]>,
) -> Option<()> {
    let size = table.len();
    let mut i = 0usize;
    while i < size {
        if bits.overrun() {
            return None;
        }
        let n = bc.decode(bits);
        if n < 16 {
            let base = old.and_then(|o| o.get(i)).copied().unwrap_or(0);
            if let Some(t) = table.get_mut(i) {
                *t = (u8::try_from(n).unwrap_or(0).wrapping_add(base)) & 0xf;
            }
            i = i.saturating_add(1);
        } else {
            let count = if n == 16 || n == 18 {
                bits.read(3).saturating_add(3)
            } else {
                bits.read(7).saturating_add(11)
            };
            let value = if n < 18 {
                if i == 0 {
                    return None;
                }
                table.get(i.saturating_sub(1)).copied().unwrap_or(0)
            } else {
                0
            };
            for _ in 0..count {
                if i >= size {
                    break;
                }
                if let Some(t) = table.get_mut(i) {
                    *t = value;
                }
                i = i.saturating_add(1);
            }
        }
    }
    Some(())
}
