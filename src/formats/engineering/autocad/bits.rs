//! The bit-coded values of DWG files (R13 and later), as described in the
//! ODA's "Open Design Specification for .dwg files" ("Bit codes and data
//! definitions"): bits are read most significant first, and multi-byte raw
//! values (`RS`, `RL`, `RD`) are their bytes in little-endian order, each
//! byte read as eight bits from wherever the stream happens to be.
//!
//! Every reader returns `None` once the data runs out.

/// A bit cursor over an in-memory buffer.
#[derive(Clone, Debug)]
pub struct Bits<'a> {
    data: &'a [u8],
    /// Position in bits.
    pub pos: u64,
}

impl<'a> Bits<'a> {
    pub fn new(data: &'a [u8], pos: u64) -> Self {
        Bits { data, pos }
    }

    /// Bits left.
    pub fn remaining(&self) -> u64 {
        crate::bytes::to_u64(self.data.len())
            .saturating_mul(8)
            .saturating_sub(self.pos)
    }

    /// `B`: one bit.
    pub fn b(&mut self) -> Option<bool> {
        let byte = self
            .data
            .get(usize::try_from(self.pos >> 3).ok()?)
            .copied()?;
        let shift = 7u64.saturating_sub(self.pos & 7);
        self.pos = self.pos.saturating_add(1);
        Some(byte >> shift & 1 == 1)
    }

    /// `n` bits (at most 32), most significant first.
    pub fn bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n.min(32) {
            v = v << 1 | u32::from(self.b()?);
        }
        Some(v)
    }

    /// `BB`: two bits.
    pub fn bb(&mut self) -> Option<u8> {
        u8::try_from(self.bits(2)?).ok()
    }

    /// `RC`: a raw byte.
    pub fn rc(&mut self) -> Option<u8> {
        if self.pos & 7 == 0 {
            let byte = self
                .data
                .get(usize::try_from(self.pos >> 3).ok()?)
                .copied()?;
            self.pos = self.pos.saturating_add(8);
            return Some(byte);
        }
        u8::try_from(self.bits(8)?).ok()
    }

    /// `RS`: a raw little-endian short.
    pub fn rs(&mut self) -> Option<u16> {
        let lo = self.rc()?;
        let hi = self.rc()?;
        Some(u16::from_le_bytes([lo, hi]))
    }

    /// `RL`: a raw little-endian long.
    pub fn rl(&mut self) -> Option<u32> {
        let lo = self.rs()?;
        let hi = self.rs()?;
        Some(u32::from(lo) | u32::from(hi) << 16)
    }

    /// `RD`: a raw little-endian double.
    pub fn rd(&mut self) -> Option<f64> {
        let mut b = [0u8; 8];
        for byte in &mut b {
            *byte = self.rc()?;
        }
        Some(f64::from_le_bytes(b))
    }

    /// `BS`: a bit short (`00` a raw short, `01` a byte, `10` 0, `11` 256).
    pub fn bs(&mut self) -> Option<u16> {
        match self.bb()? {
            0 => self.rs(),
            1 => self.rc().map(u16::from),
            2 => Some(0),
            _ => Some(256),
        }
    }

    /// `BL`: a bit long (`00` a raw long, `01` a byte, `10` 0).
    pub fn bl(&mut self) -> Option<u32> {
        match self.bb()? {
            0 => self.rl(),
            1 => self.rc().map(u32::from),
            2 => Some(0),
            _ => None,
        }
    }

    /// `BD`: a bit double (`00` a raw double, `01` 1.0, `10` 0.0).
    pub fn bd(&mut self) -> Option<f64> {
        match self.bb()? {
            0 => self.rd(),
            1 => Some(1.0),
            2 => Some(0.0),
            _ => None,
        }
    }

    /// `TV`: a `BS` length and that many 8-bit characters (code page text,
    /// shown as Latin-1; a trailing NUL is dropped).
    pub fn tv(&mut self) -> Option<String> {
        let len = self.bs()?;
        // Each character needs eight bits: a bogus length fails here before
        // anything is allocated.
        if u64::from(len).saturating_mul(8) > self.remaining() {
            return None;
        }
        let mut bytes = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            bytes.push(self.rc()?);
        }
        Some(crate::text::until_nul(&bytes))
    }

    /// `TU`: a `BS` length and that many UTF-16LE code units (R2007+).
    pub fn tu(&mut self) -> Option<String> {
        let len = self.bs()?;
        if u64::from(len).saturating_mul(16) > self.remaining() {
            return None;
        }
        let mut units = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            units.push(self.rs()?);
        }
        while units.last() == Some(&0) {
            units.pop();
        }
        Some(String::from_utf16_lossy(&units))
    }

    /// `H`: a handle reference: a 4-bit code, a 4-bit byte count and that
    /// many bytes, most significant first. Returns (code, value).
    pub fn h(&mut self) -> Option<(u8, u64)> {
        let code = u8::try_from(self.bits(4)?).ok()?;
        let count = self.bits(4)?;
        let mut value = 0u64;
        for _ in 0..count {
            value = value << 8 | u64::from(self.rc()?);
        }
        Some((code, value))
    }

    /// `OT`: an object type (R2010+): `00` a byte, `01` a byte plus
    /// `0x1f0`, otherwise a raw short.
    pub fn ot(&mut self) -> Option<u16> {
        match self.bb()? {
            0 => self.rc().map(u16::from),
            1 => self.rc().map(|b| u16::from(b).saturating_add(0x1f0)),
            _ => self.rs(),
        }
    }
}

/// `MC`/`UMC` at a byte offset: little-endian groups of 7 bits, the high
/// bit of each byte saying another follows. For a signed `MC`, bit 6 of
/// the last byte is the sign. Returns (value, bytes used).
pub fn modular_char(data: &[u8], signed: bool) -> Option<(i64, usize)> {
    let mut value = 0u64;
    for (i, &b) in data.iter().enumerate().take(9) {
        let shift = u32::try_from(i).ok()?.saturating_mul(7);
        if b & 0x80 == 0 {
            let used = i.saturating_add(1);
            if signed {
                let magnitude = value | u64::from(b & 0x3f) << shift;
                let magnitude = i64::try_from(magnitude).ok()?;
                return Some((
                    if b & 0x40 != 0 {
                        magnitude.saturating_neg()
                    } else {
                        magnitude
                    },
                    used,
                ));
            }
            let v = value | u64::from(b) << shift;
            return Some((i64::try_from(v).ok()?, used));
        }
        value |= u64::from(b & 0x7f) << shift;
    }
    None
}

/// `MS` at a byte offset: little-endian 16-bit words carrying 15 bits each,
/// bit 15 saying another follows. Returns (value, bytes used).
pub fn modular_short(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for i in 0..4usize {
        let at = i.checked_mul(2)?;
        let word = crate::bytes::u16_le(data, at)?;
        let shift = u32::try_from(i).ok()?.saturating_mul(15);
        value |= u64::from(word & 0x7fff) << shift;
        if word & 0x8000 == 0 {
            return Some((value, at.saturating_add(2)));
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bit_codes() {
        // BS 10 (0), BS 11 (256), BS 01 + 0x41, then B 1 and RS 0x1234
        // straddling bytes.
        // bits: 10 11 01 01000001 1 00110100 00010010
        let bits = "10110101000001100110100000100100";
        let bytes: Vec<u8> = bits
            .as_bytes()
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |v, &b| v << 1 | (b - b'0')))
            .collect();
        let mut r = Bits::new(&bytes, 0);
        assert_eq!(r.bs(), Some(0));
        assert_eq!(r.bs(), Some(256));
        assert_eq!(r.bs(), Some(0x41));
        assert_eq!(r.b(), Some(true));
        assert_eq!(r.rs(), Some(0x1234));
        assert_eq!(r.b(), Some(false));
        assert_eq!(r.b(), None);
    }

    #[test]
    fn modular() {
        // The ODA spec's examples: 0x82 0x24 is 4610; 0xE9 0x97 0xE6 0x00 is
        // 112823273; 0x85 0x4B is -1413 (signed).
        assert_eq!(modular_char(&[0x82, 0x24], false), Some((4610, 2)));
        assert_eq!(
            modular_char(&[0xe9, 0x97, 0xe6, 0x35], false),
            Some((112_823_273, 4))
        );
        assert_eq!(modular_char(&[0x85, 0x4b], true), Some((-1413, 2)));
        assert_eq!(modular_short(&[0x31, 0xf4, 0x8d, 0x00]), Some((4650033, 4)));
    }
}
