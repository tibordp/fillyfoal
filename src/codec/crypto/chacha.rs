//! ChaCha20 and Poly1305 (RFC 8439), and OpenSSH's
//! `chacha20-poly1305@openssh.com` as used for private key files.
//!
//! Checked against the RFC 8439 test vectors (tests below) and end to end
//! against `ssh-keygen -Z chacha20-poly1305@openssh.com` keys.

/// One 64-byte ChaCha20 block. `input` is the last four state words as
/// bytes: counter and nonce (RFC 8439: 32-bit counter + 96-bit nonce; the
/// original variant OpenSSH uses: 64-bit counter + 64-bit nonce).
pub fn chacha20_block(key: &[u8; 32], input: &[u8; 16]) -> [u8; 64] {
    let word = |b: &[u8], i: usize| -> u32 {
        let at = i.saturating_mul(4);
        b.get(at..at.saturating_add(4))
            .and_then(|w| <[u8; 4]>::try_from(w).ok())
            .map_or(0, u32::from_le_bytes)
    };
    let mut init = [0u32; 16];
    let constants = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    for (i, s) in init.iter_mut().enumerate() {
        *s = match i {
            0..4 => constants.get(i).copied().unwrap_or(0),
            4..12 => word(key, i.saturating_sub(4)),
            _ => word(input, i.saturating_sub(12)),
        };
    }
    let mut x = init;
    fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        let g = |x: &[u32; 16], i: usize| x.get(i).copied().unwrap_or(0);
        let set = |x: &mut [u32; 16], i: usize, v: u32| {
            if let Some(s) = x.get_mut(i) {
                *s = v;
            }
        };
        set(x, a, g(x, a).wrapping_add(g(x, b)));
        set(x, d, (g(x, d) ^ g(x, a)).rotate_left(16));
        set(x, c, g(x, c).wrapping_add(g(x, d)));
        set(x, b, (g(x, b) ^ g(x, c)).rotate_left(12));
        set(x, a, g(x, a).wrapping_add(g(x, b)));
        set(x, d, (g(x, d) ^ g(x, a)).rotate_left(8));
        set(x, c, g(x, c).wrapping_add(g(x, d)));
        set(x, b, (g(x, b) ^ g(x, c)).rotate_left(7));
    }
    for _ in 0..10 {
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 1, 5, 9, 13);
        qr(&mut x, 2, 6, 10, 14);
        qr(&mut x, 3, 7, 11, 15);
        qr(&mut x, 0, 5, 10, 15);
        qr(&mut x, 1, 6, 11, 12);
        qr(&mut x, 2, 7, 8, 13);
        qr(&mut x, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for ((o, a), b) in out.as_chunks_mut::<4>().0.iter_mut().zip(x).zip(init) {
        *o = a.wrapping_add(b).to_le_bytes();
    }
    out
}

/// XORs `data` with the original ChaCha20 keystream (64-bit nonce, 64-bit
/// block counter starting at `counter`).
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 8], counter: u64, data: &mut [u8]) {
    let mut counter = counter;
    for chunk in data.chunks_mut(64) {
        let mut input = [0u8; 16];
        input
            .get_mut(..8)
            .unwrap_or_default()
            .copy_from_slice(&counter.to_le_bytes());
        input
            .get_mut(8..)
            .unwrap_or_default()
            .copy_from_slice(nonce);
        let ks = chacha20_block(key, &input);
        for (d, k) in chunk.iter_mut().zip(ks) {
            *d ^= k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// The Poly1305 one-time authenticator of `msg` under `key` (r || s).
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let le = |b: &[u8], at: usize| -> u32 {
        b.get(at..at.saturating_add(4))
            .and_then(|w| <[u8; 4]>::try_from(w).ok())
            .map_or(0, u32::from_le_bytes)
    };
    const M: u32 = 0x3ff_ffff;
    let r0 = le(key, 0) & M;
    let r1 = (le(key, 3) >> 2) & 0x3ff_ff03;
    let r2 = (le(key, 6) >> 4) & 0x3ff_c0ff;
    let r3 = (le(key, 9) >> 6) & 0x3f0_3fff;
    let r4 = (le(key, 12) >> 8) & 0x00f_ffff;
    let (r0, r1, r2, r3, r4) = (
        u64::from(r0),
        u64::from(r1),
        u64::from(r2),
        u64::from(r3),
        u64::from(r4),
    );
    let (s1, s2, s3, s4) = (
        r1.wrapping_mul(5),
        r2.wrapping_mul(5),
        r3.wrapping_mul(5),
        r4.wrapping_mul(5),
    );
    let mut h = [0u32; 5];
    for chunk in msg.chunks(16) {
        let mut block = [0u8; 17];
        block
            .get_mut(..chunk.len())
            .unwrap_or_default()
            .copy_from_slice(chunk);
        let hibit = if chunk.len() == 16 {
            1u32 << 24
        } else {
            if let Some(b) = block.get_mut(chunk.len()) {
                *b = 1;
            }
            0
        };
        let [h0, h1, h2, h3, h4] = h;
        let h0 = u64::from(h0.wrapping_add(le(&block, 0) & M));
        let h1 = u64::from(h1.wrapping_add((le(&block, 3) >> 2) & M));
        let h2 = u64::from(h2.wrapping_add((le(&block, 6) >> 4) & M));
        let h3 = u64::from(h3.wrapping_add((le(&block, 9) >> 6) & M));
        let h4 = u64::from(h4.wrapping_add((le(&block, 12) >> 8) | hibit));
        let dot = |terms: [(u64, u64); 5]| {
            terms
                .iter()
                .fold(0u64, |acc, &(a, b)| acc.wrapping_add(a.wrapping_mul(b)))
        };
        let d0 = dot([(h0, r0), (h1, s4), (h2, s3), (h3, s2), (h4, s1)]);
        let mut d1 = dot([(h0, r1), (h1, r0), (h2, s4), (h3, s3), (h4, s2)]);
        let mut d2 = dot([(h0, r2), (h1, r1), (h2, r0), (h3, s4), (h4, s3)]);
        let mut d3 = dot([(h0, r3), (h1, r2), (h2, r1), (h3, r0), (h4, s4)]);
        let mut d4 = dot([(h0, r4), (h1, r3), (h2, r2), (h3, r1), (h4, r0)]);
        let mask = u64::from(M);
        let mut c = d0 >> 26;
        let mut n0 = d0 & mask;
        d1 = d1.wrapping_add(c);
        c = d1 >> 26;
        let mut n1 = d1 & mask;
        d2 = d2.wrapping_add(c);
        c = d2 >> 26;
        let n2 = d2 & mask;
        d3 = d3.wrapping_add(c);
        c = d3 >> 26;
        let n3 = d3 & mask;
        d4 = d4.wrapping_add(c);
        c = d4 >> 26;
        let n4 = d4 & mask;
        n0 = n0.wrapping_add(c.wrapping_mul(5));
        c = n0 >> 26;
        n0 &= mask;
        n1 = n1.wrapping_add(c);
        let t = |v: u64| u32::try_from(v).unwrap_or(0);
        h = [t(n0), t(n1), t(n2), t(n3), t(n4)];
    }
    // Full carry, then reduce modulo 2^130 - 5.
    let [mut h0, mut h1, mut h2, mut h3, mut h4] = h;
    let mut c = h1 >> 26;
    h1 &= M;
    h2 = h2.wrapping_add(c);
    c = h2 >> 26;
    h2 &= M;
    h3 = h3.wrapping_add(c);
    c = h3 >> 26;
    h3 &= M;
    h4 = h4.wrapping_add(c);
    c = h4 >> 26;
    h4 &= M;
    h0 = h0.wrapping_add(c.wrapping_mul(5));
    c = h0 >> 26;
    h0 &= M;
    h1 = h1.wrapping_add(c);

    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= M;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= M;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= M;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= M;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
    // h >= p exactly when g4 did not underflow.
    if g4 >> 31 == 0 {
        (h0, h1, h2, h3, h4) = (g0, g1, g2, g3, g4);
    }
    let w0 = h0 | (h1 << 26);
    let w1 = (h1 >> 6) | (h2 << 20);
    let w2 = (h2 >> 12) | (h3 << 14);
    let w3 = (h3 >> 18) | (h4 << 8);
    let mut out = [0u8; 16];
    let mut carry = 0u64;
    for (i, w) in [w0, w1, w2, w3].into_iter().enumerate() {
        let pad = u64::from(le(key, i.saturating_mul(4).saturating_add(16)));
        let f = u64::from(w).wrapping_add(pad).wrapping_add(carry);
        carry = f >> 32;
        if let Some(o) = out.get_mut(i.saturating_mul(4)..i.saturating_mul(4).saturating_add(4)) {
            o.copy_from_slice(&u32::try_from(f & 0xffff_ffff).unwrap_or(0).to_le_bytes());
        }
    }
    out
}

/// Decrypts `data` with OpenSSH's `chacha20-poly1305@openssh.com` without
/// associated data, as for key files: `key` is 64 bytes (the second half
/// keys only the packet-length cipher, unused here), the nonce is the
/// sequence number. Returns the plaintext and whether `tag` verified.
pub fn openssh_chachapoly_open(key: &[u8], seq: u64, data: &[u8], tag: &[u8]) -> (Vec<u8>, bool) {
    let Some(main) = key.get(..32).and_then(|k| <[u8; 32]>::try_from(k).ok()) else {
        return (Vec::new(), false);
    };
    let nonce = seq.to_be_bytes();
    let mut poly_key = [0u8; 32];
    chacha20_xor(&main, &nonce, 0, &mut poly_key);
    let ok = poly1305(&poly_key, data).as_slice() == tag;
    let mut out = data.to_vec();
    chacha20_xor(&main, &nonce, 1, &mut out);
    (out, ok)
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
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn chacha20_rfc8439_block() {
        // RFC 8439 2.3.2.
        let key: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let input: [u8; 16] = unhex("01000000 000000090000004a00000000")
            .try_into()
            .unwrap();
        assert_eq!(
            hex(&chacha20_block(&key, &input)),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn poly1305_rfc8439() {
        // RFC 8439 2.5.2.
        let key: [u8; 32] =
            unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .try_into()
                .unwrap();
        assert_eq!(
            hex(&poly1305(&key, b"Cryptographic Forum Research Group")),
            "a8061dc1305136c6c22b8baf0c0127a9"
        );
        // RFC 8439 A.3 vector #1 (all zero) and #2 (s only).
        assert_eq!(
            hex(&poly1305(&[0; 32], &[0; 64])),
            "00000000000000000000000000000000"
        );
        let mut k = [0u8; 32];
        k[16..].copy_from_slice(&unhex("36e5f6b5c5e06070f0efca96227a863e"));
        let text = b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
        assert_eq!(hex(&poly1305(&k, text)), "36e5f6b5c5e06070f0efca96227a863e");
        // A.3 #5: exercises the final reduction (h + s wraps).
        let k: [u8; 32] = unhex("0200000000000000000000000000000000000000000000000000000000000000")
            .try_into()
            .unwrap();
        assert_eq!(
            hex(&poly1305(&k, &unhex("ffffffffffffffffffffffffffffffff"))),
            "03000000000000000000000000000000"
        );
    }
}
