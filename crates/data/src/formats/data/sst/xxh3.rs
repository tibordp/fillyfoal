//! XXH3-64 with seed 0 and the default secret (xxHash 0.8), which RocksDB
//! uses for its default block checksum. Checked against the `xxhash`
//! reference library at every length up to 2100 bytes and on larger inputs.

use crate::cx::Cx;

const SECRET: [u8; 192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

const P32_1: u64 = 0x9e37_79b1;
const P32_2: u64 = 0x85eb_ca77;
const P32_3: u64 = 0xc2b2_ae3d;
const P64_1: u64 = 0x9e37_79b1_85eb_ca87;
const P64_2: u64 = 0xc2b2_ae3d_27d4_eb4f;
const P64_3: u64 = 0x1656_67b1_9e37_79f9;
const P64_4: u64 = 0x85eb_ca77_c2b2_ae63;
const P64_5: u64 = 0x27d4_eb2f_1656_67c5;

/// Bytes per block of the long hash: 16 stripes of 64 bytes.
const BLOCK: usize = 1024;
const STRIPES: usize = 16;

fn r64(d: &[u8], at: usize) -> u64 {
    d.get(at..at.saturating_add(8))
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

fn r32(d: &[u8], at: usize) -> u64 {
    d.get(at..at.saturating_add(4))
        .and_then(|b| b.try_into().ok())
        .map_or(0, |b| u32::from_le_bytes(b).into())
}

fn byte(d: &[u8], at: usize) -> u64 {
    d.get(at).copied().map_or(0, u64::from)
}

fn fold(a: u64, b: u64) -> u64 {
    let p = u128::from(a).wrapping_mul(u128::from(b));
    (p as u64) ^ ((p >> 64) as u64)
}

fn avalanche64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(P64_2);
    h ^= h >> 29;
    h = h.wrapping_mul(P64_3);
    h ^ (h >> 32)
}

fn avalanche(mut h: u64) -> u64 {
    h ^= h >> 37;
    h = h.wrapping_mul(0x1656_6791_9e37_79f9);
    h ^ (h >> 32)
}

fn rrmxmx(mut h: u64, len: u64) -> u64 {
    h ^= h.rotate_left(49) ^ h.rotate_left(24);
    h = h.wrapping_mul(0x9fb2_1c65_1e98_df25);
    h ^= (h >> 35).wrapping_add(len);
    h = h.wrapping_mul(0x9fb2_1c65_1e98_df25);
    h ^ (h >> 28)
}

fn mix16(d: &[u8], at: usize, s: usize) -> u64 {
    fold(
        r64(d, at) ^ r64(&SECRET, s),
        r64(d, at.saturating_add(8)) ^ r64(&SECRET, s.saturating_add(8)),
    )
}

fn short(d: &[u8]) -> u64 {
    let n = d.len();
    let len = n as u64;
    let end = |k: usize| n.saturating_sub(k);
    match n {
        0 => avalanche64(r64(&SECRET, 56) ^ r64(&SECRET, 64)),
        1..=3 => {
            let c = (byte(d, 0) << 16) | (byte(d, n >> 1) << 24) | byte(d, end(1)) | (len << 8);
            avalanche64(c ^ (r32(&SECRET, 0) ^ r32(&SECRET, 4)))
        }
        4..=8 => {
            let x = r32(d, end(4)).wrapping_add(r32(d, 0) << 32);
            rrmxmx(x ^ (r64(&SECRET, 8) ^ r64(&SECRET, 16)), len)
        }
        9..=16 => {
            let lo = r64(d, 0) ^ (r64(&SECRET, 24) ^ r64(&SECRET, 32));
            let hi = r64(d, end(8)) ^ (r64(&SECRET, 40) ^ r64(&SECRET, 48));
            avalanche(
                len.wrapping_add(lo.swap_bytes())
                    .wrapping_add(hi)
                    .wrapping_add(fold(lo, hi)),
            )
        }
        17..=128 => {
            let mut acc = len.wrapping_mul(P64_1);
            let mut add = |at: usize, s: usize| acc = acc.wrapping_add(mix16(d, at, s));
            if n > 32 {
                if n > 64 {
                    if n > 96 {
                        add(48, 96);
                        add(end(64), 112);
                    }
                    add(32, 64);
                    add(end(48), 80);
                }
                add(16, 32);
                add(end(32), 48);
            }
            add(0, 0);
            add(end(16), 16);
            avalanche(acc)
        }
        _ => {
            let mut acc = len.wrapping_mul(P64_1);
            for i in 0..8usize {
                acc = acc.wrapping_add(mix16(d, i.saturating_mul(16), i.saturating_mul(16)));
            }
            acc = avalanche(acc);
            for i in 8..n / 16 {
                let s = i.saturating_sub(8).saturating_mul(16).saturating_add(3);
                acc = acc.wrapping_add(mix16(d, i.saturating_mul(16), s));
            }
            acc = acc.wrapping_add(mix16(d, end(16), 136 - 17));
            avalanche(acc)
        }
    }
}

fn stripe(acc: &mut [u64; 8], d: &[u8], at: usize, s: usize) {
    for i in 0..8usize {
        let v = r64(d, at.saturating_add(i.saturating_mul(8)));
        let k = v ^ r64(&SECRET, s.saturating_add(i.saturating_mul(8)));
        if let Some(a) = acc.get_mut(i ^ 1) {
            *a = a.wrapping_add(v);
        }
        if let Some(a) = acc.get_mut(i) {
            *a = a.wrapping_add((k & 0xffff_ffff).wrapping_mul(k >> 32));
        }
    }
}

fn scramble(acc: &mut [u64; 8]) {
    for (i, a) in acc.iter_mut().enumerate() {
        let mut v = *a;
        v ^= v >> 47;
        v ^= r64(&SECRET, 128usize.saturating_add(i.saturating_mul(8)));
        *a = v.wrapping_mul(P32_1);
    }
}

/// XXH3-64 of `d`, charging the long-input loop to `cx` every 64 KiB.
pub async fn xxh3_64(cx: &Cx, d: &[u8]) -> u64 {
    let n = d.len();
    if n <= 240 {
        return short(d);
    }
    let mut acc = [P32_3, P64_1, P64_2, P64_3, P64_4, P32_2, P64_5, P32_1];
    let blocks = n.saturating_sub(1) / BLOCK;
    for b in 0..blocks {
        let base = b.saturating_mul(BLOCK);
        for s in 0..STRIPES {
            stripe(
                &mut acc,
                d,
                base.saturating_add(s.saturating_mul(64)),
                s.saturating_mul(8),
            );
        }
        scramble(&mut acc);
        if b % 64 == 63 {
            cx.checkpoint().await;
        }
    }
    let base = blocks.saturating_mul(BLOCK);
    let last = n.saturating_sub(1).saturating_sub(base) / 64;
    for s in 0..last {
        stripe(
            &mut acc,
            d,
            base.saturating_add(s.saturating_mul(64)),
            s.saturating_mul(8),
        );
    }
    stripe(&mut acc, d, n.saturating_sub(64), 192 - 64 - 7);
    let mut h = (n as u64).wrapping_mul(P64_1);
    for i in 0..4usize {
        let s = 11usize.saturating_add(i.saturating_mul(16));
        let a = acc.get(i.saturating_mul(2)).copied().unwrap_or(0);
        let b = acc
            .get(i.saturating_mul(2).saturating_add(1))
            .copied()
            .unwrap_or(0);
        h = h.wrapping_add(fold(
            a ^ r64(&SECRET, s),
            b ^ r64(&SECRET, s.saturating_add(8)),
        ));
    }
    avalanche(h)
}

#[cfg(test)]
mod tests {
    use super::short;

    /// Reference values from the `xxhash` library (`xxh3_64_intdigest`).
    #[test]
    fn short_vectors() {
        assert_eq!(short(b""), 0x2d06_8005_38d3_94c2);
        assert_eq!(short(b"a"), 0xe6c6_32b6_1e96_4e1f);
        assert_eq!(short(b"abc"), 0x78af_5f94_892f_3950);
        assert_eq!(short(b"abcde"), 0x55c6_5158_ee9e_652d);
        assert_eq!(short(b"abcdefghijkl"), 0x52be_ba20_86c3_f6d7);
        assert_eq!(short(&b"0123456789".repeat(5)), 0x0967_3f25_dfd6_9709);
        assert_eq!(short(&[b'x'; 100]), 0xc909_84ff_df50_ce42);
        assert_eq!(short(&[b'y'; 200]), 0x78c5_ae5c_f7b1_237e);
    }
}
