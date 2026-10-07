//! ChaCha20 (RFC 8439): 256-bit key, 96-bit nonce, 32-bit block counter.

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let g = |s: &[u32; 16], i: usize| s.get(i).copied().unwrap_or(0);
    let (mut va, mut vb, mut vc, mut vd) = (g(s, a), g(s, b), g(s, c), g(s, d));
    va = va.wrapping_add(vb);
    vd = (vd ^ va).rotate_left(16);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_left(12);
    va = va.wrapping_add(vb);
    vd = (vd ^ va).rotate_left(8);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_left(7);
    for (i, x) in [(a, va), (b, vb), (c, vc), (d, vd)] {
        if let Some(slot) = s.get_mut(i) {
            *slot = x;
        }
    }
}

fn words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut out = [0u32; N];
    for (w, c) in out.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *w = u32::from_le_bytes(*c);
    }
    out
}

/// One 64-byte keystream block.
fn block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    init[4..12].copy_from_slice(key);
    init[12] = counter;
    init[13..].copy_from_slice(nonce);
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for ((chunk, x), y) in out.as_chunks_mut::<4>().0.iter_mut().zip(s).zip(init) {
        chunk.copy_from_slice(&x.wrapping_add(y).to_le_bytes());
    }
    out
}

/// XORs `data` with the keystream for `key` (32 bytes) and `nonce` (12
/// bytes), starting at block `counter`. `None` for wrong key or nonce sizes.
pub fn chacha20(key: &[u8], nonce: &[u8], counter: u32, data: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 32 || nonce.len() != 12 {
        return None;
    }
    let key: [u32; 8] = words(key);
    let nonce: [u32; 3] = words(nonce);
    let mut out = Vec::with_capacity(data.len());
    let mut ctr = counter;
    for chunk in data.chunks(64) {
        let ks = block(&key, ctr, &nonce);
        out.extend(chunk.iter().zip(ks).map(|(a, b)| a ^ b));
        ctr = ctr.wrapping_add(1);
    }
    Some(out)
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

    #[test]
    fn reference_library() {
        // pycryptodome ChaCha20 with the RFC 8439 section 2.4.2 key and
        // nonce: the keystream from block 0, and 150 patterned bytes
        // encrypted from block 1.
        let key: Vec<u8> = (0..32u8).collect();
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        assert_eq!(
            hex(&chacha20(&key, &nonce, 0, &[0; 64]).unwrap()),
            "af051e40bba0354981329a806a140eafd258a22a6dcb4bb9f6569cb3efe2deaf\
             837bd87ca20b5ba12081a306af0eb35c41a239d20dfc74c81771560d9c9c1e4b"
        );
        let text: Vec<u8> = (0..150u32).map(|i| (i * 7 % 256) as u8).collect();
        let ct = chacha20(&key, &nonce, 1, &text).unwrap();
        assert_eq!(
            hex(&ct[..32]),
            "22485fe65c38f3d017e16122ec387f84fc646107b1bf9c43d6e07c515a381da1"
        );
        assert_eq!(hex(&ct[ct.len() - 4..]), "7543cd5e");
        assert_eq!(chacha20(&key, &nonce, 1, &ct).unwrap(), text);
    }
}
