//! BLAKE2b (RFC 7693), unkeyed, with any digest length from 1 to 64 bytes.
//! Argon2 is built on it.

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// An incremental BLAKE2b hash.
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    buf: [u8; 128],
    used: usize,
    total: u128,
    out: usize,
}

fn get(v: &[u64; 16], i: usize) -> u64 {
    v.get(i).copied().unwrap_or(0)
}

fn set(v: &mut [u64; 16], i: usize, x: u64) {
    if let Some(slot) = v.get_mut(i) {
        *slot = x;
    }
}

#[allow(clippy::too_many_arguments)]
fn mix(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    let mut va = get(v, a);
    let mut vb = get(v, b);
    let mut vc = get(v, c);
    let mut vd = get(v, d);
    va = va.wrapping_add(vb).wrapping_add(x);
    vd = (vd ^ va).rotate_right(32);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_right(24);
    va = va.wrapping_add(vb).wrapping_add(y);
    vd = (vd ^ va).rotate_right(16);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_right(63);
    set(v, a, va);
    set(v, b, vb);
    set(v, c, vc);
    set(v, d, vd);
}

impl Blake2b {
    /// A hash producing `out` bytes (clamped to 1..=64).
    pub fn new(out: usize) -> Self {
        let out = out.clamp(1, 64);
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ crate::bytes::to_u64(out);
        Blake2b {
            h,
            buf: [0; 128],
            used: 0,
            total: 0,
            out,
        }
    }

    fn compress(&mut self, last: bool) {
        let mut m = [0u64; 16];
        for (word, chunk) in m.iter_mut().zip(self.buf.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        let t = self.total.to_le_bytes();
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&t[..8]);
        hi.copy_from_slice(&t[8..]);
        v[12] ^= u64::from_le_bytes(lo);
        v[13] ^= u64::from_le_bytes(hi);
        if last {
            v[14] = !v[14];
        }
        for s in &SIGMA {
            let w = |i: usize| m.get(s.get(i).copied().unwrap_or(0)).copied().unwrap_or(0);
            mix(&mut v, 0, 4, 8, 12, w(0), w(1));
            mix(&mut v, 1, 5, 9, 13, w(2), w(3));
            mix(&mut v, 2, 6, 10, 14, w(4), w(5));
            mix(&mut v, 3, 7, 11, 15, w(6), w(7));
            mix(&mut v, 0, 5, 10, 15, w(8), w(9));
            mix(&mut v, 1, 6, 11, 12, w(10), w(11));
            mix(&mut v, 2, 7, 8, 13, w(12), w(13));
            mix(&mut v, 3, 4, 9, 14, w(14), w(15));
        }
        for (i, h) in self.h.iter_mut().enumerate() {
            *h ^= get(&v, i) ^ get(&v, i.saturating_add(8));
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.used == 128 {
                self.total = self.total.wrapping_add(128);
                self.compress(false);
                self.used = 0;
            }
            let take = (128usize.saturating_sub(self.used)).min(data.len());
            let (head, rest) = data.split_at(take);
            if let Some(dst) = self.buf.get_mut(self.used..self.used.saturating_add(take)) {
                dst.copy_from_slice(head);
            }
            self.used = self.used.saturating_add(take);
            data = rest;
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.total = self.total.wrapping_add(self.used as u128);
        if let Some(rest) = self.buf.get_mut(self.used..) {
            rest.fill(0);
        }
        self.compress(true);
        let mut out: Vec<u8> = self.h.iter().flat_map(|w| w.to_le_bytes()).collect();
        out.truncate(self.out);
        out
    }

    /// The `out`-byte digest of `data`.
    pub fn digest(out: usize, data: &[u8]) -> Vec<u8> {
        let mut h = Blake2b::new(out);
        h.update(data);
        h.finish()
    }
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
    fn vectors() {
        // RFC 7693 appendix A.
        assert_eq!(
            hex(&Blake2b::digest(64, b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            hex(&Blake2b::digest(64, b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
        // Python hashlib.blake2b(bytes(range(256)) * 3, digest_size=32).
        let long: Vec<u8> = (0..768u32).map(|i| i as u8).collect();
        let mut h = Blake2b::new(32);
        for chunk in long.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(
            hex(&h.finish()),
            "b8007121274217790e2923e0ad7027986e5a99d5531ef6ae7d294140fc81615d"
        );
        assert_eq!(
            hex(&Blake2b::digest(32, &long)),
            "b8007121274217790e2923e0ad7027986e5a99d5531ef6ae7d294140fc81615d"
        );
    }
}
