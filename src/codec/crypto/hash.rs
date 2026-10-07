//! Hash functions: MD5, SHA-1, SHA-256, SHA-384 and SHA-512.
//!
//! For decryption and integrity checks of the user's own files; these are
//! straightforward implementations, not hardened against side channels.

/// An incremental hash function.
pub trait Hash: Clone {
    /// Input block size in bytes (for HMAC).
    const BLOCK: usize;
    /// Digest size in bytes.
    const OUT: usize;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finish(self) -> Vec<u8>;

    /// The digest of `data`.
    fn digest(data: &[u8]) -> Vec<u8> {
        let mut h = Self::new();
        h.update(data);
        h.finish()
    }
}

/// Buffers input into fixed-size blocks for a Merkle–Damgård hash.
#[derive(Clone)]
struct Blocks<const N: usize> {
    buf: [u8; N],
    used: usize,
    total: u128,
}

impl<const N: usize> Blocks<N> {
    fn new() -> Self {
        Blocks {
            buf: [0; N],
            used: 0,
            total: 0,
        }
    }

    /// Feeds `data`, calling `compress` for each full block.
    fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8; N])) {
        self.total = self.total.wrapping_add(data.len() as u128);
        while !data.is_empty() {
            let take = N.saturating_sub(self.used).min(data.len());
            let (head, rest) = data.split_at(take);
            if let Some(dst) = self.buf.get_mut(self.used..self.used.saturating_add(take)) {
                dst.copy_from_slice(head);
            }
            self.used = self.used.saturating_add(take);
            data = rest;
            if self.used == N {
                compress(&self.buf);
                self.used = 0;
            }
        }
    }

    /// Pads with 0x80, zeros and the bit length (`len_bytes` wide, big- or
    /// little-endian), compressing the final block(s).
    fn finish(mut self, len_bytes: usize, little: bool, mut compress: impl FnMut(&[u8; N])) {
        let bits = self.total.wrapping_mul(8);
        let mut tail = vec![0x80u8];
        let rem = self.used.saturating_add(1).checked_rem(N).unwrap_or(0);
        let pad = N
            .saturating_sub(len_bytes)
            .saturating_add(N)
            .saturating_sub(rem)
            .checked_rem(N)
            .unwrap_or(0);
        tail.resize(pad.saturating_add(1), 0);
        let len = if little {
            bits.to_le_bytes()
        } else {
            bits.to_be_bytes()
        };
        if little {
            tail.extend_from_slice(len.get(..len_bytes).unwrap_or_default());
        } else {
            tail.extend_from_slice(
                len.get(16usize.saturating_sub(len_bytes)..)
                    .unwrap_or_default(),
            );
        }
        self.update(&tail, &mut compress);
    }
}

fn word(block: &[u8], i: usize, little: bool) -> u32 {
    let b: [u8; 4] = block
        .get(i.saturating_mul(4)..i.saturating_mul(4).saturating_add(4))
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0; 4]);
    if little {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    blocks: Blocks<64>,
}

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

fn md5_compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let [mut a, mut b, mut c, mut d] = *state;
    for (i, (&s, &k)) in MD5_S.iter().zip(MD5_K.iter()).enumerate() {
        let (f, g) = match i / 16 {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), i.wrapping_mul(5).wrapping_add(1) % 16),
            2 => (b ^ c ^ d, i.wrapping_mul(3).wrapping_add(5) % 16),
            _ => (c ^ (b | !d), i.wrapping_mul(7) % 16),
        };
        let f = f
            .wrapping_add(a)
            .wrapping_add(k)
            .wrapping_add(word(block, g, true));
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(f.rotate_left(s));
    }
    for (x, y) in state.iter_mut().zip([a, b, c, d]) {
        *x = x.wrapping_add(y);
    }
}

impl Hash for Md5 {
    const BLOCK: usize = 64;
    const OUT: usize = 16;

    fn new() -> Self {
        Md5 {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            blocks: Blocks::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.blocks.update(data, |b| md5_compress(state, b));
    }

    fn finish(self) -> Vec<u8> {
        let mut state = self.state;
        self.blocks.finish(8, true, |b| md5_compress(&mut state, b));
        state.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
}

// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    blocks: Blocks<64>,
}

fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (i, slot) in w.iter_mut().enumerate().take(16) {
        *slot = word(block, i, false);
    }
    for i in 16..80usize {
        let x = |k: usize| w.get(i.wrapping_sub(k)).copied().unwrap_or(0);
        let v = (x(3) ^ x(8) ^ x(14) ^ x(16)).rotate_left(1);
        if let Some(slot) = w.get_mut(i) {
            *slot = v;
        }
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6u32),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for (x, y) in state.iter_mut().zip([a, b, c, d, e]) {
        *x = x.wrapping_add(y);
    }
}

impl Hash for Sha1 {
    const BLOCK: usize = 64;
    const OUT: usize = 20;

    fn new() -> Self {
        Sha1 {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            blocks: Blocks::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.blocks.update(data, |b| sha1_compress(state, b));
    }

    fn finish(self) -> Vec<u8> {
        let mut state = self.state;
        self.blocks
            .finish(8, false, |b| sha1_compress(&mut state, b));
        state.iter().flat_map(|w| w.to_be_bytes()).collect()
    }
}

// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    blocks: Blocks<64>,
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, slot) in w.iter_mut().enumerate().take(16) {
        *slot = word(block, i, false);
    }
    for i in 16..64usize {
        let x = |k: usize| w.get(i.wrapping_sub(k)).copied().unwrap_or(0);
        let s0 = x(15).rotate_right(7) ^ x(15).rotate_right(18) ^ (x(15) >> 3);
        let s1 = x(2).rotate_right(17) ^ x(2).rotate_right(19) ^ (x(2) >> 10);
        let v = x(16).wrapping_add(s0).wrapping_add(x(7)).wrapping_add(s1);
        if let Some(slot) = w.get_mut(i) {
            *slot = v;
        }
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (&k, &wi) in SHA256_K.iter().zip(w.iter()) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, y) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *x = x.wrapping_add(y);
    }
}

impl Hash for Sha256 {
    const BLOCK: usize = 64;
    const OUT: usize = 32;

    fn new() -> Self {
        Sha256 {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            blocks: Blocks::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.blocks.update(data, |b| sha256_compress(state, b));
    }

    fn finish(self) -> Vec<u8> {
        let mut state = self.state;
        self.blocks
            .finish(8, false, |b| sha256_compress(&mut state, b));
        state.iter().flat_map(|w| w.to_be_bytes()).collect()
    }
}

// ---------------------------------------------------------------------------

const SHA512_K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for (i, slot) in w.iter_mut().enumerate().take(16) {
        let b: [u8; 8] = block
            .get(i.saturating_mul(8)..i.saturating_mul(8).saturating_add(8))
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 8]);
        *slot = u64::from_be_bytes(b);
    }
    for i in 16..80usize {
        let x = |k: usize| w.get(i.wrapping_sub(k)).copied().unwrap_or(0);
        let s0 = x(15).rotate_right(1) ^ x(15).rotate_right(8) ^ (x(15) >> 7);
        let s1 = x(2).rotate_right(19) ^ x(2).rotate_right(61) ^ (x(2) >> 6);
        let v = x(16).wrapping_add(s0).wrapping_add(x(7)).wrapping_add(s1);
        if let Some(slot) = w.get_mut(i) {
            *slot = v;
        }
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (&k, &wi) in SHA512_K.iter().zip(w.iter()) {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(wi);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, y) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *x = x.wrapping_add(y);
    }
}

#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    blocks: Blocks<128>,
    out: usize,
}

impl Sha512 {
    fn with(state: [u64; 8], out: usize) -> Self {
        Sha512 {
            state,
            blocks: Blocks::new(),
            out,
        }
    }
}

impl Hash for Sha512 {
    const BLOCK: usize = 128;
    const OUT: usize = 64;

    fn new() -> Self {
        Sha512::with(
            [
                0x6a09_e667_f3bc_c908,
                0xbb67_ae85_84ca_a73b,
                0x3c6e_f372_fe94_f82b,
                0xa54f_f53a_5f1d_36f1,
                0x510e_527f_ade6_82d1,
                0x9b05_688c_2b3e_6c1f,
                0x1f83_d9ab_fb41_bd6b,
                0x5be0_cd19_137e_2179,
            ],
            64,
        )
    }

    fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.blocks.update(data, |b| sha512_compress(state, b));
    }

    fn finish(self) -> Vec<u8> {
        let mut state = self.state;
        let out = self.out;
        self.blocks
            .finish(16, false, |b| sha512_compress(&mut state, b));
        let mut d: Vec<u8> = state.iter().flat_map(|w| w.to_be_bytes()).collect();
        d.truncate(out);
        d
    }
}

/// SHA-384: SHA-512 with other initial values, truncated.
#[derive(Clone)]
pub struct Sha384(Sha512);

impl Hash for Sha384 {
    const BLOCK: usize = 128;
    const OUT: usize = 48;

    fn new() -> Self {
        Sha384(Sha512::with(
            [
                0xcbbb_9d5d_c105_9ed8,
                0x629a_292a_367c_d507,
                0x9159_015a_3070_dd17,
                0x152f_ecd8_f70e_5939,
                0x6733_2667_ffc0_0b31,
                0x8eb4_4a87_6858_1511,
                0xdb0c_2e0d_64f9_8fa7,
                0x47b5_481d_befa_4fa4,
            ],
            48,
        ))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finish(self) -> Vec<u8> {
        self.0.finish()
    }
}

/// HMAC with hash `H`.
pub fn hmac<H: Hash>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<H>::new(key);
    mac.update(message);
    mac.finish()
}

/// An incremental HMAC.
#[derive(Clone)]
pub struct Hmac<H: Hash> {
    inner: H,
    outer: H,
}

impl<H: Hash> Hmac<H> {
    pub fn new(key: &[u8]) -> Self {
        let mut k = if key.len() > H::BLOCK {
            H::digest(key)
        } else {
            key.to_vec()
        };
        k.resize(H::BLOCK, 0);
        let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
        let mut inner = H::new();
        inner.update(&ipad);
        let mut outer = H::new();
        outer.update(&opad);
        Hmac { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finish(self) -> Vec<u8> {
        let mut outer = self.outer;
        outer.update(&self.inner.finish());
        outer.finish()
    }
}

/// PBKDF2 (RFC 8018) with HMAC-`H`, producing `len` bytes. Cost grows with
/// `iterations`; callers in dissectors should cap or budget it.
pub fn pbkdf2<H: Hash>(password: &[u8], salt: &[u8], iterations: u32, len: usize) -> Vec<u8> {
    let prf = Hmac::<H>::new(password);
    let mut out = Vec::with_capacity(len);
    let mut block = 1u32;
    while out.len() < len {
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u = mac.finish();
        let mut t = u.clone();
        for _ in 1..iterations {
            let mut mac = prf.clone();
            mac.update(&u);
            u = mac.finish();
            for (x, y) in t.iter_mut().zip(&u) {
                *x ^= y;
            }
        }
        out.extend_from_slice(&t);
        block = block.wrapping_add(1);
    }
    out.truncate(len);
    out
}
