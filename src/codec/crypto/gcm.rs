//! AES-GCM decryption with tag verification (NIST SP 800-38D), for
//! `aes256-gcm@openssh.com` key files. 96-bit IVs only. Checked against the
//! GCM specification's test cases 1 and 2 (tests below).

use super::cipher::Aes;

/// Multiplication in GF(2^128) with GCM's bit order.
fn gmul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe1 << 120;
    let mut z = 0u128;
    let mut v = y;
    for i in (0..128).rev() {
        if (x >> i) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ R } else { v >> 1 };
    }
    z
}

fn ghash(h: u128, aad: &[u8], data: &[u8]) -> u128 {
    let mut y = 0u128;
    for part in [aad, data] {
        for chunk in part.chunks(16) {
            let mut block = [0u8; 16];
            block
                .get_mut(..chunk.len())
                .unwrap_or_default()
                .copy_from_slice(chunk);
            y = gmul(y ^ u128::from_be_bytes(block), h);
        }
    }
    let bits = |n: usize| u128::try_from(n).unwrap_or(0).wrapping_mul(8);
    gmul(y ^ (bits(aad.len()) << 64) ^ bits(data.len()), h)
}

/// Decrypts `data` and checks `tag`; returns the plaintext and whether the
/// tag verified.
pub fn aes_gcm_open(
    aes: &Aes,
    iv: &[u8; 12],
    aad: &[u8],
    data: &[u8],
    tag: &[u8],
) -> (Vec<u8>, bool) {
    let mut h = [0u8; 16];
    aes.encrypt_block(&mut h);
    let mut j0 = [0u8; 16];
    j0.get_mut(..12).unwrap_or_default().copy_from_slice(iv);
    j0[15] = 1;
    let mut out = Vec::with_capacity(data.len());
    let mut counter = 1u32;
    for chunk in data.chunks(16) {
        counter = counter.wrapping_add(1);
        let mut ks = j0;
        ks.get_mut(12..)
            .unwrap_or_default()
            .copy_from_slice(&counter.to_be_bytes());
        aes.encrypt_block(&mut ks);
        out.extend(chunk.iter().zip(ks).map(|(a, b)| a ^ b));
    }
    let mut ek = j0;
    aes.encrypt_block(&mut ek);
    let expected =
        (ghash(u128::from_be_bytes(h), aad, data) ^ u128::from_be_bytes(ek)).to_be_bytes();
    (out, expected.as_slice() == tag)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn gcm_spec_test_cases() {
        let aes = Aes::new(&[0; 16]).unwrap();
        // Test case 1: empty plaintext.
        let (p, ok) = aes_gcm_open(
            &aes,
            &[0; 12],
            &[],
            &[],
            &unhex("58e2fccefa7e3061367f1d57a4e7455a"),
        );
        assert!(ok && p.is_empty());
        // Test case 2: one zero block.
        let c = unhex("0388dace60b6a392f328c2b971b2fe78");
        let (p, ok) = aes_gcm_open(
            &aes,
            &[0; 12],
            &[],
            &c,
            &unhex("ab6e47d42cec13bdf53a67b21257bddf"),
        );
        assert!(ok);
        assert_eq!(hex(&p), "00000000000000000000000000000000");
        let (_, ok) = aes_gcm_open(&aes, &[0; 12], &[], &c, &[0; 16]);
        assert!(!ok);
    }
}
