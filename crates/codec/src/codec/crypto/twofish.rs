//! Twofish (Schneier et al., 1998) with 128-, 192- or 256-bit keys, as
//! KeePass uses it (CBC through [`super::cbc_decrypt`]). A direct
//! implementation of the specification: the key-dependent S-boxes are
//! precomputed per key, nothing else is table-driven.

use super::cipher::BlockCipher;

/// The 4-bit permutations `t0..t3` of `q0` and `q1`.
const QT: [[[u8; 16]; 4]; 2] = [
    [
        [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
        [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
        [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
        [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
    ],
    [
        [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5],
        [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8],
        [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15],
        [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10],
    ],
];

const MDS: [[u8; 4]; 4] = [
    [0x01, 0xef, 0x5b, 0x5b],
    [0x5b, 0xef, 0xef, 0x01],
    [0xef, 0x5b, 0x01, 0xef],
    [0xef, 0x01, 0xef, 0x5b],
];

const RS: [[u8; 8]; 4] = [
    [0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e],
    [0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5],
    [0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19],
    [0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03],
];

fn nib(t: &[u8; 16], x: u8) -> u8 {
    t.get(usize::from(x & 15)).copied().unwrap_or(0)
}

fn ror4(x: u8) -> u8 {
    ((x >> 1) | (x << 3)) & 15
}

/// `q0` (`n == 0`) or `q1`.
fn q(n: usize, x: u8) -> u8 {
    let Some(t) = QT.get(n) else { return 0 };
    let (a0, b0) = (x >> 4, x & 15);
    let a1 = a0 ^ b0;
    let b1 = a0 ^ ror4(b0) ^ ((a0 << 3) & 15);
    let (a2, b2) = (nib(&t[0], a1), nib(&t[1], b1));
    let a3 = a2 ^ b2;
    let b3 = a2 ^ ror4(b2) ^ ((a2 << 3) & 15);
    let (a4, b4) = (nib(&t[2], a3), nib(&t[3], b3));
    (b4 << 4) | a4
}

/// Multiplication in GF(2^8) modulo `poly`.
fn gf(mut a: u8, mut b: u8, poly: u16) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= poly.to_le_bytes()[0];
        }
        b >>= 1;
    }
    r
}

fn mds(y: [u8; 4]) -> u32 {
    let mut z = [0u8; 4];
    for (zi, row) in z.iter_mut().zip(&MDS) {
        for (m, yj) in row.iter().zip(&y) {
            *zi ^= gf(*m, *yj, 0x169);
        }
    }
    u32::from_le_bytes(z)
}

/// Which `q` each byte position goes through, outermost (applied first)
/// first: the 4th key word's layer, the 3rd's, then the two always there,
/// and the final one before the MDS.
const ORDER: [[usize; 5]; 4] = [
    [1, 1, 0, 0, 1],
    [0, 1, 1, 0, 0],
    [0, 0, 0, 1, 1],
    [1, 0, 1, 1, 0],
];

/// The S-box chain of `h` for byte position `pos` with key words `l`
/// (`l[0]` applied last).
fn chain(pos: usize, x: u8, l: &[u32]) -> u8 {
    let Some(order) = ORDER.get(pos) else {
        return 0;
    };
    let byte = |i: usize| {
        l.get(i)
            .map_or(0, |w| w.to_le_bytes().get(pos).copied().unwrap_or(0))
    };
    let mut y = x;
    // Layers for the key words beyond the first two (k = 3, 4).
    for (layer, word) in [(0usize, 3usize), (1, 2)] {
        if l.len() > word {
            y = q(order.get(layer).copied().unwrap_or(0), y) ^ byte(word);
        }
    }
    y = q(order.get(2).copied().unwrap_or(0), y) ^ byte(1);
    y = q(order.get(3).copied().unwrap_or(0), y) ^ byte(0);
    q(order.get(4).copied().unwrap_or(0), y)
}

/// The `h` function.
fn h(x: u32, l: &[u32]) -> u32 {
    let b = x.to_le_bytes();
    let mut y = [0u8; 4];
    for (pos, (yi, bi)) in y.iter_mut().zip(b).enumerate() {
        *yi = chain(pos, bi, l);
    }
    mds(y)
}

pub struct Twofish {
    k: [u32; 40],
    /// `g` per input byte position: `g(x) = sbox[0][x0] ^ ... ^ sbox[3][x3]`.
    sbox: Vec<[u32; 256]>,
}

impl Twofish {
    /// A cipher for a 16-, 24- or 32-byte key.
    pub fn new(key: &[u8]) -> Option<Self> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return None;
        }
        let words: Vec<u32> = key
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        let me: Vec<u32> = words.iter().step_by(2).copied().collect();
        let mo: Vec<u32> = words.iter().skip(1).step_by(2).copied().collect();
        // S in reverse order: S[0] is computed from the last 8 key bytes.
        let mut s: Vec<u32> = key
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| {
                let mut out = [0u8; 4];
                for (o, row) in out.iter_mut().zip(&RS) {
                    for (r, m) in row.iter().zip(chunk) {
                        *o ^= gf(*r, *m, 0x14d);
                    }
                }
                u32::from_le_bytes(out)
            })
            .collect();
        s.reverse();
        let mut k = [0u32; 40];
        for i in 0..20u32 {
            let a = h(i.wrapping_mul(2).wrapping_mul(0x0101_0101), &me);
            let b = h(
                i.wrapping_mul(2).wrapping_add(1).wrapping_mul(0x0101_0101),
                &mo,
            )
            .rotate_left(8);
            let at = usize::try_from(i).unwrap_or(0).saturating_mul(2);
            if let Some(slot) = k.get_mut(at) {
                *slot = a.wrapping_add(b);
            }
            if let Some(slot) = k.get_mut(at.saturating_add(1)) {
                *slot = a.wrapping_add(b.wrapping_mul(2)).rotate_left(9);
            }
        }
        // The MDS step is linear, so g splits per input byte.
        let mut sbox = vec![[0u32; 256]; 4];
        for (pos, table) in sbox.iter_mut().enumerate() {
            for (x, slot) in (0..=255u8).zip(table.iter_mut()) {
                let mut y = [0u8; 4];
                if let Some(yi) = y.get_mut(pos) {
                    *yi = chain(pos, x, &s);
                }
                *slot = mds(y);
            }
        }
        Some(Twofish { k, sbox })
    }

    fn g(&self, x: u32) -> u32 {
        x.to_le_bytes()
            .iter()
            .zip(&self.sbox)
            .fold(0, |acc, (b, t)| {
                acc ^ t.get(usize::from(*b)).copied().unwrap_or(0)
            })
    }

    fn key(&self, i: usize) -> u32 {
        self.k.get(i).copied().unwrap_or(0)
    }

    fn load(block: &[u8; 16]) -> [u32; 4] {
        std::array::from_fn(|i| {
            let at = i.saturating_mul(4);
            let b = |j: usize| block.get(at.saturating_add(j)).copied().unwrap_or(0);
            u32::from_le_bytes([b(0), b(1), b(2), b(3)])
        })
    }

    fn store(words: [u32; 4], block: &mut [u8; 16]) {
        for (chunk, w) in block.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let p = Self::load(block);
        let mut r = [
            p[0] ^ self.key(0),
            p[1] ^ self.key(1),
            p[2] ^ self.key(2),
            p[3] ^ self.key(3),
        ];
        for round in 0..16usize {
            let t0 = self.g(r[0]);
            let t1 = self.g(r[1].rotate_left(8));
            let f0 = t0
                .wrapping_add(t1)
                .wrapping_add(self.key(round.wrapping_mul(2).wrapping_add(8)));
            let f1 = t0
                .wrapping_add(t1.wrapping_mul(2))
                .wrapping_add(self.key(round.wrapping_mul(2).wrapping_add(9)));
            let n2 = (r[2] ^ f0).rotate_right(1);
            let n3 = r[3].rotate_left(1) ^ f1;
            r = [n2, n3, r[0], r[1]];
        }
        let c = [
            r[2] ^ self.key(4),
            r[3] ^ self.key(5),
            r[0] ^ self.key(6),
            r[1] ^ self.key(7),
        ];
        Self::store(c, block);
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let c = Self::load(block);
        // Undo the output whitening and the final swap.
        let mut r = [
            c[2] ^ self.key(6),
            c[3] ^ self.key(7),
            c[0] ^ self.key(4),
            c[1] ^ self.key(5),
        ];
        for round in (0..16usize).rev() {
            // r is the state after this round: [n2, n3, old0, old1].
            let (o0, o1) = (r[2], r[3]);
            let t0 = self.g(o0);
            let t1 = self.g(o1.rotate_left(8));
            let f0 = t0
                .wrapping_add(t1)
                .wrapping_add(self.key(round.wrapping_mul(2).wrapping_add(8)));
            let f1 = t0
                .wrapping_add(t1.wrapping_mul(2))
                .wrapping_add(self.key(round.wrapping_mul(2).wrapping_add(9)));
            let o2 = r[0].rotate_left(1) ^ f0;
            let o3 = (r[1] ^ f1).rotate_right(1);
            r = [o0, o1, o2, o3];
        }
        let p = [
            r[0] ^ self.key(0),
            r[1] ^ self.key(1),
            r[2] ^ self.key(2),
            r[3] ^ self.key(3),
        ];
        Self::store(p, block);
    }
}

impl BlockCipher for Twofish {
    const BLOCK: usize = 16;
    fn decrypt(&self, block: &mut [u8]) {
        if let Ok(b) = <&mut [u8; 16]>::try_from(block) {
            self.decrypt_block(b);
        }
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

    fn unhex(s: &str) -> Vec<u8> {
        crate::text::unhex(s).unwrap()
    }

    #[test]
    fn vectors() {
        // The Twofish paper's ecb_tbl.txt: zero keys and plaintexts, and
        // the 256-bit entry at the end of the chained table.
        for (key, pt, ct) in [
            (
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "9f589f5cf6122c32b6bfec2f2ae8c35a",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "57ff739d4dc92c1bd7fc01700cc8216f",
            ),
            (
                "d43bb7556ea32e46f2a282b7d45b4e0d57ff739d4dc92c1bd7fc01700cc8216f",
                "90afe91bb288544f2c32dc239b2635e6",
                "6cb4561c40bf0a9705931cb6d408e7fa",
            ),
        ] {
            let tf = Twofish::new(&unhex(key)).unwrap();
            let mut b: [u8; 16] = unhex(pt).try_into().unwrap();
            tf.encrypt_block(&mut b);
            assert_eq!(b.to_vec(), unhex(ct));
            tf.decrypt_block(&mut b);
            assert_eq!(b.to_vec(), unhex(pt));
        }
    }
}
