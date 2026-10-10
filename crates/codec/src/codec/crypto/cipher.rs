//! Block and stream ciphers for decrypting the user's own files: AES, RC4,
//! DES/3DES and RC2. Straightforward table-based implementations, not
//! hardened against side channels.

// ---------------------------------------------------------------------------
// AES (FIPS 197)

// Evaluated at compile time: an out-of-range index is a compile error.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const SBOX: [u8; 256] = {
    // Generated at compile time from the multiplicative inverse in GF(2^8)
    // and the affine transform.
    let mut sbox = [0u8; 256];
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    loop {
        // p *= 3
        p = p ^ (p << 1) ^ (if p & 0x80 != 0 { 0x1b } else { 0 });
        // q /= 3
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        sbox[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    sbox[0] = 0x63;
    sbox
};

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const INV_SBOX: [u8; 256] = {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
};

fn sb(x: u8) -> u8 {
    SBOX.get(usize::from(x)).copied().unwrap_or(0)
}

fn isb(x: u8) -> u8 {
    INV_SBOX.get(usize::from(x)).copied().unwrap_or(0)
}

fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

/// Multiplication by `k` in GF(2^8), as a table built at compile time.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn mul_table(k: u8) -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let (mut a, mut b, mut p) = (i as u8, k, 0u8);
        while b != 0 {
            if b & 1 != 0 {
                p ^= a;
            }
            a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
            b >>= 1;
        }
        t[i] = p;
        i += 1;
    }
    t
}

const MUL: [[u8; 256]; 6] = [
    mul_table(2),
    mul_table(3),
    mul_table(9),
    mul_table(11),
    mul_table(13),
    mul_table(14),
];

fn gmul(a: u8, k: u8) -> u8 {
    let table = match k {
        2 => 0,
        3 => 1,
        9 => 2,
        11 => 3,
        13 => 4,
        14 => 5,
        _ => return a,
    };
    MUL.get(table)
        .and_then(|t| t.get(usize::from(a)))
        .copied()
        .unwrap_or(0)
}

/// An expanded AES key (128, 192 or 256 bits).
#[derive(Clone)]
pub struct Aes {
    round_keys: Vec<[u8; 16]>,
}

impl Aes {
    /// `None` unless `key` is 16, 24 or 32 bytes.
    pub fn new(key: &[u8]) -> Option<Self> {
        let nk = match key.len() {
            16 => 4usize,
            24 => 6,
            32 => 8,
            _ => return None,
        };
        let total = 4usize.saturating_mul(nk.saturating_add(7));
        let mut w: Vec<[u8; 4]> = key.as_chunks::<4>().0.to_vec();
        let mut rcon = 1u8;
        while w.len() < total {
            let i = w.len();
            let mut t = w.last().copied().unwrap_or([0; 4]);
            if i.is_multiple_of(nk) {
                t = [sb(t[1]) ^ rcon, sb(t[2]), sb(t[3]), sb(t[0])];
                rcon = xtime(rcon);
            } else if nk > 6 && i.checked_rem(nk) == Some(4) {
                t = t.map(sb);
            }
            let prev = w.get(i.wrapping_sub(nk)).copied().unwrap_or([0; 4]);
            w.push([
                prev[0] ^ t[0],
                prev[1] ^ t[1],
                prev[2] ^ t[2],
                prev[3] ^ t[3],
            ]);
        }
        let round_keys = w
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| {
                let mut k = [0u8; 16];
                for (dst, src) in k.as_chunks_mut::<4>().0.iter_mut().zip(c) {
                    *dst = *src;
                }
                k
            })
            .collect();
        Some(Aes { round_keys })
    }

    fn add(state: &mut [u8; 16], key: &[u8; 16]) {
        for (s, k) in state.iter_mut().zip(key) {
            *s ^= k;
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let last = self.round_keys.len().saturating_sub(1);
        for (round, key) in self.round_keys.iter().enumerate() {
            if round > 0 {
                for b in block.iter_mut() {
                    *b = sb(*b);
                }
                shift_rows(block);
                if round < last {
                    mix_columns(block);
                }
            }
            Aes::add(block, key);
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let last = self.round_keys.len().saturating_sub(1);
        for (round, key) in self.round_keys.iter().enumerate().rev() {
            Aes::add(block, key);
            if round > 0 {
                if round < last {
                    inv_mix_columns(block);
                }
                inv_shift_rows(block);
                for b in block.iter_mut() {
                    *b = isb(*b);
                }
            }
        }
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    let c = *s;
    for col in 0..4usize {
        for row in 0..4usize {
            let from = (col.wrapping_add(row) & 3)
                .wrapping_mul(4)
                .wrapping_add(row);
            if let (Some(d), Some(v)) = (
                s.get_mut(col.wrapping_mul(4).wrapping_add(row)),
                c.get(from),
            ) {
                *d = *v;
            }
        }
    }
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    let c = *s;
    for col in 0..4usize {
        for row in 0..4usize {
            let to = (col.wrapping_add(row) & 3)
                .wrapping_mul(4)
                .wrapping_add(row);
            if let (Some(d), Some(v)) =
                (s.get_mut(to), c.get(col.wrapping_mul(4).wrapping_add(row)))
            {
                *d = *v;
            }
        }
    }
}

fn mix_columns(s: &mut [u8; 16]) {
    for c in s.as_chunks_mut::<4>().0 {
        let [a, b, d, e] = *c;
        *c = [
            gmul(a, 2) ^ gmul(b, 3) ^ d ^ e,
            a ^ gmul(b, 2) ^ gmul(d, 3) ^ e,
            a ^ b ^ gmul(d, 2) ^ gmul(e, 3),
            gmul(a, 3) ^ b ^ d ^ gmul(e, 2),
        ];
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in s.as_chunks_mut::<4>().0 {
        let [a, b, d, e] = *c;
        *c = [
            gmul(a, 14) ^ gmul(b, 11) ^ gmul(d, 13) ^ gmul(e, 9),
            gmul(a, 9) ^ gmul(b, 14) ^ gmul(d, 11) ^ gmul(e, 13),
            gmul(a, 13) ^ gmul(b, 9) ^ gmul(d, 14) ^ gmul(e, 11),
            gmul(a, 11) ^ gmul(b, 13) ^ gmul(d, 9) ^ gmul(e, 14),
        ];
    }
}

/// A block cipher for the CBC helpers.
pub trait BlockCipher {
    const BLOCK: usize;
    fn decrypt(&self, block: &mut [u8]);
}

impl BlockCipher for Aes {
    const BLOCK: usize = 16;
    fn decrypt(&self, block: &mut [u8]) {
        if let Ok(b) = <&mut [u8; 16]>::try_from(block) {
            self.decrypt_block(b);
        }
    }
}

/// CBC decryption of whole blocks (a trailing partial block is dropped).
pub fn cbc_decrypt<C: BlockCipher>(cipher: &C, iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut prev = iv.to_vec();
    prev.resize(C::BLOCK, 0);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(C::BLOCK).filter(|c| c.len() == C::BLOCK) {
        let mut block = chunk.to_vec();
        cipher.decrypt(&mut block);
        for (b, p) in block.iter_mut().zip(&prev) {
            *b ^= p;
        }
        out.extend_from_slice(&block);
        prev = chunk.to_vec();
    }
    out
}

/// Removes PKCS#7 padding; `None` if it is invalid (often: a wrong key).
pub fn unpad_pkcs7(data: &[u8], block: usize) -> Option<&[u8]> {
    let n = usize::from(*data.last()?);
    if n == 0 || n > block || n > data.len() {
        return None;
    }
    let (body, pad) = data.split_at(data.len().saturating_sub(n));
    pad.iter().all(|&b| usize::from(b) == n).then_some(body)
}

/// AES in CTR mode with a little-endian counter starting at 1, as WinZip AES
/// uses (the counter occupies the whole block).
pub fn aes_ctr_le(aes: &Aes, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = 1u128;
    for chunk in data.chunks(16) {
        let mut ks = counter.to_le_bytes();
        aes.encrypt_block(&mut ks);
        out.extend(chunk.iter().zip(ks).map(|(a, b)| a ^ b));
        counter = counter.wrapping_add(1);
    }
    out
}

// ---------------------------------------------------------------------------
// RC4

/// An RC4 keystream (an empty key leaves the identity permutation).
#[derive(Clone)]
pub struct Rc4State {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    /// The key schedule.
    pub fn new(key: &[u8]) -> Self {
        let mut s: [u8; 256] = std::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
        if !key.is_empty() {
            let mut j = 0u8;
            for i in 0..256usize {
                let k = key
                    .get(i.checked_rem(key.len()).unwrap_or(0))
                    .copied()
                    .unwrap_or(0);
                j = j
                    .wrapping_add(s.get(i).copied().unwrap_or(0))
                    .wrapping_add(k);
                s.swap(i, usize::from(j));
            }
        }
        Rc4State { s, i: 0, j: 0 }
    }

    /// `b` XORed with the next keystream byte.
    pub fn apply(&mut self, b: u8) -> u8 {
        let get = |s: &[u8; 256], x: u8| s.get(usize::from(x)).copied().unwrap_or(0);
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(get(&self.s, self.i));
        self.s.swap(usize::from(self.i), usize::from(self.j));
        let t = get(&self.s, self.i).wrapping_add(get(&self.s, self.j));
        b ^ get(&self.s, t)
    }
}

pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state = Rc4State::new(key);
    data.iter().map(|&b| state.apply(b)).collect()
}

// ---------------------------------------------------------------------------
// DES and triple DES (FIPS 46-3)

const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];
const S: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
        14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
        9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Permutes the `width`-bit value `v` by `table` (1-based positions,
/// counted from the most significant bit) into `table.len()` bits.
fn permute(v: u64, width: u32, table: &[u8]) -> u64 {
    let n = u32::try_from(table.len()).unwrap_or(0);
    table.iter().enumerate().fold(0u64, |acc, (i, &pos)| {
        let bit = (v >> width.saturating_sub(u32::from(pos))) & 1;
        let shift = n
            .saturating_sub(1)
            .saturating_sub(u32::try_from(i).unwrap_or(0));
        acc | (bit << shift)
    })
}

/// One DES key schedule.
#[derive(Clone)]
pub struct Des {
    subkeys: [u64; 16],
}

impl Des {
    pub fn new(key: &[u8; 8]) -> Self {
        let k = permute(u64::from_be_bytes(*key), 64, &PC1);
        let (mut c, mut d) = ((k >> 28) & 0x0fff_ffff, k & 0x0fff_ffff);
        let mut subkeys = [0u64; 16];
        for (slot, &s) in subkeys.iter_mut().zip(&SHIFTS) {
            c = ((c << s) | (c >> 28u32.saturating_sub(s))) & 0x0fff_ffff;
            d = ((d << s) | (d >> 28u32.saturating_sub(s))) & 0x0fff_ffff;
            *slot = permute((c << 28) | d, 56, &PC2);
        }
        Des { subkeys }
    }

    fn feistel(r: u32, k: u64) -> u32 {
        let x = permute(u64::from(r), 32, &E) ^ k;
        let mut out = 0u32;
        for (i, sbox) in S.iter().enumerate() {
            let shift = 42u32.saturating_sub(u32::try_from(i).unwrap_or(0).saturating_mul(6));
            let six = usize::try_from((x >> shift) & 0x3f).unwrap_or(0);
            let row = ((six & 0x20) >> 4) | (six & 1);
            let col = (six >> 1) & 0x0f;
            let v = sbox
                .get(row.saturating_mul(16).saturating_add(col))
                .copied()
                .unwrap_or(0);
            out = (out << 4) | u32::from(v);
        }
        u32::try_from(permute(u64::from(out), 32, &P)).unwrap_or(0)
    }

    fn crypt(&self, block: u64, decrypt: bool) -> u64 {
        let ip = permute(block, 64, &IP);
        let (mut l, mut r) = (
            u32::try_from(ip >> 32).unwrap_or(0),
            u32::try_from(ip & 0xffff_ffff).unwrap_or(0),
        );
        for i in 0..16usize {
            let k = if decrypt {
                self.subkeys.get(15usize.saturating_sub(i))
            } else {
                self.subkeys.get(i)
            }
            .copied()
            .unwrap_or(0);
            let next = l ^ Des::feistel(r, k);
            l = r;
            r = next;
        }
        permute((u64::from(r) << 32) | u64::from(l), 64, &FP)
    }
}

/// Triple DES (EDE): 16 or 24-byte keys.
#[derive(Clone)]
pub struct TripleDes([Des; 3]);

impl TripleDes {
    pub fn new(key: &[u8]) -> Option<Self> {
        let k = |i: usize| -> Option<[u8; 8]> {
            let at = i.saturating_mul(8);
            key.get(at..at.saturating_add(8))?.try_into().ok()
        };
        let (a, b) = (k(0)?, k(1)?);
        let c = if key.len() >= 24 { k(2)? } else { a };
        Some(TripleDes([Des::new(&a), Des::new(&b), Des::new(&c)]))
    }
}

impl BlockCipher for TripleDes {
    const BLOCK: usize = 8;
    fn decrypt(&self, block: &mut [u8]) {
        let Ok(b) = <&mut [u8; 8]>::try_from(block) else {
            return;
        };
        let [a, m, c] = &self.0;
        let v = a.crypt(m.crypt(c.crypt(u64::from_be_bytes(*b), true), false), true);
        *b = v.to_be_bytes();
    }
}

impl BlockCipher for Des {
    const BLOCK: usize = 8;
    fn decrypt(&self, block: &mut [u8]) {
        let Ok(b) = <&mut [u8; 8]>::try_from(block) else {
            return;
        };
        *b = self.crypt(u64::from_be_bytes(*b), true).to_be_bytes();
    }
}

// ---------------------------------------------------------------------------
// RC2 (RFC 2268)

const PITABLE: [u8; 256] = [
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];

/// RC2 with an effective key length in bits (40 for "export" PKCS#12).
#[derive(Clone)]
pub struct Rc2 {
    k: [u16; 64],
}

impl Rc2 {
    pub fn new(key: &[u8], effective_bits: usize) -> Self {
        let pi = |x: u8| PITABLE.get(usize::from(x)).copied().unwrap_or(0);
        let mut l = [0u8; 128];
        let t = key.len().min(128);
        if let Some(dst) = l.get_mut(..t) {
            dst.copy_from_slice(key.get(..t).unwrap_or_default());
        }
        for i in t..128 {
            let a = l.get(i.wrapping_sub(1)).copied().unwrap_or(0);
            let b = l.get(i.wrapping_sub(t)).copied().unwrap_or(0);
            if let Some(slot) = l.get_mut(i) {
                *slot = pi(a.wrapping_add(b));
            }
        }
        let t8 = effective_bits.div_ceil(8).clamp(1, 128);
        let bits = t8.saturating_mul(8);
        let tm = 0xffu8 >> bits.saturating_sub(effective_bits.min(bits)).min(7);
        let idx = 128usize.saturating_sub(t8);
        if let Some(slot) = l.get_mut(idx) {
            *slot = pi(*slot & tm);
        }
        for i in (0..idx).rev() {
            let a = l.get(i.saturating_add(1)).copied().unwrap_or(0);
            let b = l.get(i.saturating_add(t8)).copied().unwrap_or(0);
            if let Some(slot) = l.get_mut(i) {
                *slot = pi(a ^ b);
            }
        }
        let mut k = [0u16; 64];
        for (slot, pair) in k.iter_mut().zip(l.as_chunks::<2>().0) {
            *slot = u16::from_le_bytes(*pair);
        }
        Rc2 { k }
    }
}

impl BlockCipher for Rc2 {
    const BLOCK: usize = 8;
    fn decrypt(&self, block: &mut [u8]) {
        let Ok(b) = <&mut [u8; 8]>::try_from(block) else {
            return;
        };
        let mut r = [0u16; 4];
        for (slot, pair) in r.iter_mut().zip(b.as_chunks::<2>().0) {
            *slot = u16::from_le_bytes(*pair);
        }
        let key = |i: usize| self.k.get(i).copied().unwrap_or(0);
        let rr = |r: &[u16; 4], i: usize| r.get(i & 3).copied().unwrap_or(0);
        let mut j = 63usize;
        let rounds = |r: &mut [u16; 4], j: &mut usize| {
            for i in (0..4usize).rev() {
                let s = [1u32, 2, 3, 5].get(i).copied().unwrap_or(1);
                let v = rr(r, i).rotate_right(s);
                let v = v
                    .wrapping_sub(key(*j))
                    .wrapping_sub(rr(r, i.wrapping_add(3)) & rr(r, i.wrapping_add(2)))
                    .wrapping_sub(!rr(r, i.wrapping_add(3)) & rr(r, i.wrapping_add(1)));
                if let Some(slot) = r.get_mut(i) {
                    *slot = v;
                }
                *j = j.saturating_sub(1);
            }
        };
        let mash = |r: &mut [u16; 4]| {
            for i in (0..4usize).rev() {
                let v = rr(r, i).wrapping_sub(key(usize::from(rr(r, i.wrapping_add(3)) & 63)));
                if let Some(slot) = r.get_mut(i) {
                    *slot = v;
                }
            }
        };
        for round in (0..16).rev() {
            rounds(&mut r, &mut j);
            if round == 11 || round == 5 {
                mash(&mut r);
            }
        }
        for (dst, w) in b.as_chunks_mut::<2>().0.iter_mut().zip(r) {
            *dst = w.to_le_bytes();
        }
    }
}
