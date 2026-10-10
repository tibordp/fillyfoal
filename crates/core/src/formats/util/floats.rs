//! Floating-point encodings other than IEEE single and double: half
//! precision, x87 extended precision and IBM System/360 hexadecimal.

/// An IEEE 754 half-precision float.
pub fn f16(bits: u16) -> f64 {
    let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from(bits >> 10 & 0x1f);
    let mantissa = f64::from(bits & 0x3ff);
    sign * match exponent {
        0 => mantissa * 2f64.powi(-24),
        0x1f if mantissa == 0.0 => f64::INFINITY,
        0x1f => f64::NAN,
        e => (1.0 + mantissa / 1024.0) * 2f64.powi(e.saturating_sub(15)),
    }
}

/// An x87 80-bit extended float from its exponent word and mantissa.
fn f80(se: u16, mantissa: u64) -> f64 {
    let sign = if se & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from(se & 0x7fff);
    if exponent == 0 && mantissa == 0 {
        return 0.0;
    }
    if exponent == 0x7fff {
        return if mantissa << 1 == 0 {
            sign * f64::INFINITY
        } else {
            f64::NAN
        };
    }
    // value = mantissa * 2^(exponent - 16383 - 63)
    sign * mantissa as f64 * 2f64.powi(exponent.saturating_sub(16383 + 63))
}

/// An 80-bit extended float stored big-endian (AIFF sample rates).
pub fn f80_be(b: &[u8]) -> Option<f64> {
    let b: [u8; 10] = crate::bytes::array(b, 0)?;
    let [e0, e1, m @ ..] = b;
    Some(f80(u16::from_be_bytes([e0, e1]), u64::from_be_bytes(m)))
}

/// An 80-bit extended float stored little-endian (x86 memory, Delphi
/// `Extended`).
pub fn f80_le(b: &[u8]) -> Option<f64> {
    let b: [u8; 10] = crate::bytes::array(b, 0)?;
    let [m @ .., e0, e1] = b;
    Some(f80(u16::from_le_bytes([e0, e1]), u64::from_le_bytes(m)))
}

/// An IBM System/360 hexadecimal float of 1 to 8 big-endian bytes (SAS
/// transport files use truncated ones): sign bit, a base-16 exponent
/// biased by 64, then a fraction.
pub fn ibm(b: &[u8]) -> Option<f64> {
    let (&first, rest) = b.split_first()?;
    if rest.len() > 7 {
        return None;
    }
    let mut fraction = 0u64;
    for &byte in rest {
        fraction = fraction << 8 | u64::from(byte);
    }
    if fraction == 0 {
        return Some(0.0);
    }
    let bits = i32::try_from(rest.len().saturating_mul(8)).ok()?;
    let sign = if first & 0x80 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from(first & 0x7f).saturating_sub(64);
    Some(sign * fraction as f64 * 2f64.powi(exponent.saturating_mul(4).saturating_sub(bits)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half() {
        assert_eq!(f16(0x3c00), 1.0);
        assert_eq!(f16(0xc000), -2.0);
        assert_eq!(f16(0x0001), 2f64.powi(-24));
        assert!(f16(0x7c00).is_infinite());
    }

    #[test]
    fn extended() {
        let b = [0x40, 0x0e, 0xac, 0x44, 0, 0, 0, 0, 0, 0];
        assert_eq!(f80_be(&b), Some(44100.0));
        let mut l = b;
        l.reverse();
        assert_eq!(f80_le(&l), Some(44100.0));
    }

    #[test]
    fn hexadecimal() {
        assert_eq!(ibm(&[0x41, 0x10, 0, 0]), Some(1.0));
        assert_eq!(ibm(&[0xc2, 0x76, 0xa0, 0, 0, 0, 0, 0]), Some(-118.625));
        assert_eq!(ibm(&[0x41, 0x10]), Some(1.0));
        assert_eq!(ibm(&[0, 0, 0, 0]), Some(0.0));
    }
}
