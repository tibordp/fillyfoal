//! The bit reader of the RAR decoders: most significant bit first, as
//! libarchive's RAR readers consume their input (`rar_br_bits` in
//! `archive_read_support_format_rar.c`, `read_bits_16`/`read_bits_32` in
//! `archive_read_support_format_rar5.c`). See [`super`] for provenance.

use crate::bytes::{to_u64, to_usize};

/// A window on a member's packed data. Positions count bits from the start
/// of the member; `data[0]` is the member's byte `base`. Bytes outside
/// `data` read as zeros (the decoders check where the data ends).
#[derive(Clone, Copy)]
pub struct Bits<'a> {
    pub data: &'a [u8],
    pub base: u64,
    pub pos: u64,
}

impl Bits<'_> {
    fn byte(&self, at: u64) -> u8 {
        match at.checked_sub(self.base) {
            Some(i) => self.data.get(to_usize(i)).copied().unwrap_or(0),
            None => 0,
        }
    }

    /// The next `n` (at most 32) bits, not consumed.
    pub fn peek(&self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let first = self.pos >> 3;
        let mut window = 0u64;
        for k in 0..5u64 {
            window = window << 8 | u64::from(self.byte(first.saturating_add(k)));
        }
        // 40 bits loaded; skip the bits already consumed of the first byte.
        let used = (self.pos & 7) as u32;
        let shifted = window << (24u32.saturating_add(used));
        (shifted >> (64u32.saturating_sub(n.min(32)))) as u32
    }

    pub fn skip(&mut self, n: u32) {
        self.pos = self.pos.saturating_add(u64::from(n));
    }

    /// Reads `n` (at most 32) bits.
    pub fn read(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.skip(n);
        v
    }

    /// Reads one bit as a flag.
    pub fn flag(&mut self) -> bool {
        self.read(1) != 0
    }

    pub fn get_byte(&mut self) -> u8 {
        self.read(8) as u8
    }

    /// Moves to the next byte boundary.
    pub fn align(&mut self) {
        self.pos = self.pos.saturating_add(7) & !7;
    }

    /// The bit position where `data` ends.
    pub fn end(&self) -> u64 {
        self.base
            .saturating_add(to_u64(self.data.len()))
            .saturating_mul(8)
    }
}
