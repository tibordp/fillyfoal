//! Argon2d, Argon2i and Argon2id (RFC 9106), versions 0x10 and 0x13.
//!
//! The memory filling runs in caller-sized steps ([`Argon2::step`]) so a
//! dissector can interleave it with `cx.checkpoint()`: KeePass databases
//! routinely ask for tens of megabytes and many passes. Lanes are filled one
//! after another in each slice, which gives the same result as the parallel
//! reference implementation.

use super::blake2b::Blake2b;
use crate::bytes::to_u64;

/// Words in a 1 KiB block.
const WORDS: usize = 128;
const SYNC_POINTS: u32 = 4;

type Block = [u64; WORDS];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    D = 0,
    I = 1,
    Id = 2,
}

/// Argon2 parameters (memory in KiB).
#[derive(Clone, Debug)]
pub struct Params {
    pub variant: Variant,
    pub version: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
    pub out_len: u32,
}

impl Params {
    /// Blocks actually used (memory rounded down to whole segments, at
    /// least two per slice and lane).
    pub fn blocks(&self) -> u64 {
        let lanes = u64::from(self.lanes.max(1));
        let sync = u64::from(SYNC_POINTS);
        let m = u64::from(self.memory_kib).max(lanes.saturating_mul(2 * sync));
        let segment = m.checked_div(lanes.saturating_mul(sync)).unwrap_or(0);
        segment.saturating_mul(lanes).saturating_mul(sync)
    }

    /// Block compressions the whole derivation performs.
    pub fn cost(&self) -> u64 {
        self.blocks().saturating_mul(u64::from(self.iterations))
    }
}

/// `H'`: BLAKE2b with arbitrary output length (RFC 9106 section 3.3).
fn h_prime(out_len: usize, parts: &[&[u8]]) -> Vec<u8> {
    let len32 = u32::try_from(out_len).unwrap_or(u32::MAX).to_le_bytes();
    if out_len <= 64 {
        let mut h = Blake2b::new(out_len);
        h.update(&len32);
        for p in parts {
            h.update(p);
        }
        return h.finish();
    }
    let mut h = Blake2b::new(64);
    h.update(&len32);
    for p in parts {
        h.update(p);
    }
    let mut v = h.finish();
    let mut out = Vec::with_capacity(out_len);
    while out_len.saturating_sub(out.len()) > 64 {
        out.extend_from_slice(v.get(..32).unwrap_or_default());
        v = Blake2b::digest(64, &v);
    }
    let rest = out_len.saturating_sub(out.len());
    if rest == 64 {
        out.extend_from_slice(&v);
    } else {
        out.extend_from_slice(&Blake2b::digest(rest, &v));
    }
    out
}

#[inline]
fn bla(a: u64, b: u64) -> u64 {
    let lo = (a & 0xffff_ffff).wrapping_mul(b & 0xffff_ffff);
    a.wrapping_add(b).wrapping_add(lo.wrapping_mul(2))
}

#[inline]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    let (mut va, mut vb, mut vc, mut vd) = (
        v.get(a).copied().unwrap_or(0),
        v.get(b).copied().unwrap_or(0),
        v.get(c).copied().unwrap_or(0),
        v.get(d).copied().unwrap_or(0),
    );
    va = bla(va, vb);
    vd = (vd ^ va).rotate_right(32);
    vc = bla(vc, vd);
    vb = (vb ^ vc).rotate_right(24);
    va = bla(va, vb);
    vd = (vd ^ va).rotate_right(16);
    vc = bla(vc, vd);
    vb = (vb ^ vc).rotate_right(63);
    for (i, x) in [(a, va), (b, vb), (c, vc), (d, vd)] {
        if let Some(slot) = v.get_mut(i) {
            *slot = x;
        }
    }
}

fn permute(v: &mut [u64; 16]) {
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

/// Applies the permutation to the 16 words of `r` at `idx`.
fn round(r: &mut Block, idx: [usize; 16]) {
    let mut v = [0u64; 16];
    for (x, &i) in v.iter_mut().zip(&idx) {
        *x = r.get(i).copied().unwrap_or(0);
    }
    permute(&mut v);
    for (x, &i) in v.iter().zip(&idx) {
        if let Some(slot) = r.get_mut(i) {
            *slot = *x;
        }
    }
}

/// The compression function `G(x, y)`, XORed into `out` if `xor`.
fn compress(x: &Block, y: &Block, out: &mut Block, xor: bool) {
    let mut r = [0u64; WORDS];
    for ((r, a), b) in r.iter_mut().zip(x).zip(y) {
        *r = a ^ b;
    }
    let mut tmp = r;
    if xor {
        for (t, o) in tmp.iter_mut().zip(out.iter()) {
            *t ^= o;
        }
    }
    for i in 0..8usize {
        let base = i.saturating_mul(16);
        let idx: [usize; 16] = std::array::from_fn(|k| base.saturating_add(k));
        round(&mut r, idx);
    }
    for i in 0..8usize {
        let base = i.saturating_mul(2);
        let idx: [usize; 16] = std::array::from_fn(|k| {
            base.saturating_add((k / 2).saturating_mul(16))
                .saturating_add(k % 2)
        });
        round(&mut r, idx);
    }
    for ((o, t), r) in out.iter_mut().zip(&tmp).zip(&r) {
        *o = t ^ r;
    }
}

fn block_from(bytes: &[u8]) -> Block {
    let mut b = [0u64; WORDS];
    for (w, c) in b.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *w = u64::from_le_bytes(*c);
    }
    b
}

/// An Argon2 computation in progress.
pub struct Argon2 {
    params: Params,
    memory: Vec<Block>,
    lane_len: u32,
    segment_len: u32,
    // Position of the next block.
    pass: u32,
    slice: u32,
    lane: u32,
    index: u32,
    // Data-independent addressing state for the current segment.
    input: Block,
    address: Block,
    done: bool,
}

impl Argon2 {
    /// Sets up the memory and its first blocks. `None` if the parameters are
    /// unusable or the memory cannot be allocated.
    pub fn new(
        params: Params,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        associated: &[u8],
    ) -> Option<Self> {
        if params.lanes == 0
            || params.lanes > 0x00ff_ffff
            || params.iterations == 0
            || params.out_len < 4
            || !matches!(params.version, 0x10 | 0x13)
        {
            return None;
        }
        let blocks = usize::try_from(params.blocks()).ok()?;
        let lane_len = u32::try_from(params.blocks().checked_div(params.lanes.into())?).ok()?;
        let segment_len = lane_len / SYNC_POINTS;
        let mut memory: Vec<Block> = Vec::new();
        memory.try_reserve_exact(blocks).ok()?;
        memory.resize(blocks, [0; WORDS]);

        let le = |x: u32| x.to_le_bytes();
        let len = |b: &[u8]| u32::try_from(b.len()).unwrap_or(u32::MAX).to_le_bytes();
        let mut h = Blake2b::new(64);
        for part in [
            le(params.lanes),
            le(params.out_len),
            le(params.memory_kib),
            le(params.iterations),
            le(params.version),
            le(params.variant as u32),
        ] {
            h.update(&part);
        }
        for field in [password, salt, secret, associated] {
            h.update(&len(field));
            h.update(field);
        }
        let h0 = h.finish();
        for lane in 0..params.lanes {
            for i in 0..2u32 {
                let b = h_prime(1024, &[&h0, &le(i), &le(lane)]);
                let at = usize::try_from(
                    u64::from(lane)
                        .saturating_mul(u64::from(lane_len))
                        .saturating_add(u64::from(i)),
                )
                .ok()?;
                *memory.get_mut(at)? = block_from(&b);
            }
        }
        let mut a = Argon2 {
            params,
            memory,
            lane_len,
            segment_len,
            pass: 0,
            slice: 0,
            lane: 0,
            index: 2,
            input: [0; WORDS],
            address: [0; WORDS],
            done: false,
        };
        a.start_segment();
        Some(a)
    }

    fn independent(&self) -> bool {
        match self.params.variant {
            Variant::I => true,
            Variant::D => false,
            Variant::Id => self.pass == 0 && self.slice < SYNC_POINTS / 2,
        }
    }

    fn next_addresses(&mut self) {
        self.input[6] = self.input[6].wrapping_add(1);
        let zero = [0u64; WORDS];
        let mut addr = [0u64; WORDS];
        compress(&zero, &self.input, &mut addr, false);
        let first = addr;
        compress(&zero, &first, &mut addr, false);
        self.address = addr;
    }

    fn start_segment(&mut self) {
        if self.independent() {
            self.input = [0; WORDS];
            self.input[0] = self.pass.into();
            self.input[1] = self.lane.into();
            self.input[2] = self.slice.into();
            self.input[3] = to_u64(self.memory.len());
            self.input[4] = self.params.iterations.into();
            self.input[5] = self.params.variant as u64;
            if self.pass == 0 && self.slice == 0 {
                self.next_addresses();
            }
        }
    }

    fn at(&self, lane: u32, index: u32) -> usize {
        usize::try_from(
            u64::from(lane)
                .saturating_mul(u64::from(self.lane_len))
                .saturating_add(u64::from(index)),
        )
        .unwrap_or(usize::MAX)
    }

    /// Fills the next block.
    fn fill_one(&mut self) {
        let i = self.index;
        let col = self
            .slice
            .saturating_mul(self.segment_len)
            .saturating_add(i);
        let prev_col = if col == 0 {
            self.lane_len.saturating_sub(1)
        } else {
            col.saturating_sub(1)
        };
        let prev = self.at(self.lane, prev_col);
        let rand = if self.independent() {
            let k = usize::try_from(i).unwrap_or(0) % WORDS;
            if k == 0 {
                self.next_addresses();
            }
            self.address.get(k).copied().unwrap_or(0)
        } else {
            self.memory.get(prev).map_or(0, |b| b[0])
        };
        let ref_lane = if self.pass == 0 && self.slice == 0 {
            self.lane
        } else {
            u32::try_from(
                (rand >> 32)
                    .checked_rem(self.params.lanes.into())
                    .unwrap_or(0),
            )
            .unwrap_or(0)
        };
        let same = ref_lane == self.lane;
        let seg = u64::from(self.segment_len);
        let lane_len = u64::from(self.lane_len);
        let idx = u64::from(i);
        let area = if self.pass == 0 {
            if self.slice == 0 {
                idx.saturating_sub(1)
            } else if same {
                u64::from(self.slice)
                    .saturating_mul(seg)
                    .saturating_add(idx)
                    .saturating_sub(1)
            } else {
                u64::from(self.slice)
                    .saturating_mul(seg)
                    .saturating_sub(u64::from(i == 0))
            }
        } else if same {
            lane_len
                .saturating_sub(seg)
                .saturating_add(idx)
                .saturating_sub(1)
        } else {
            lane_len
                .saturating_sub(seg)
                .saturating_sub(u64::from(i == 0))
        };
        let j1 = rand & 0xffff_ffff;
        let x = j1.saturating_mul(j1) >> 32;
        let rel = area
            .saturating_sub(1)
            .saturating_sub(area.saturating_mul(x) >> 32);
        let start = if self.pass != 0 && self.slice != SYNC_POINTS - 1 {
            u64::from(self.slice.saturating_add(1)).saturating_mul(seg)
        } else {
            0
        };
        let ref_col = u32::try_from(start.saturating_add(rel).checked_rem(lane_len).unwrap_or(0))
            .unwrap_or(0);
        let reference = self.at(ref_lane, ref_col);
        let cur = self.at(self.lane, col);
        let xor = self.pass != 0 && self.params.version == 0x13;
        let p = self.memory.get(prev).copied().unwrap_or([0; WORDS]);
        let r = self.memory.get(reference).copied().unwrap_or([0; WORDS]);
        if let Some(out) = self.memory.get_mut(cur) {
            compress(&p, &r, out, xor);
        }
    }

    /// Fills up to `blocks` more blocks; true once all passes are done.
    pub fn step(&mut self, blocks: u32) -> bool {
        for _ in 0..blocks {
            if self.done {
                break;
            }
            if self.index >= self.segment_len {
                self.lane = self.lane.saturating_add(1);
                if self.lane >= self.params.lanes {
                    self.lane = 0;
                    self.slice = self.slice.saturating_add(1);
                    if self.slice >= SYNC_POINTS {
                        self.slice = 0;
                        self.pass = self.pass.saturating_add(1);
                        if self.pass >= self.params.iterations {
                            self.done = true;
                            break;
                        }
                    }
                }
                self.index = if self.pass == 0 && self.slice == 0 {
                    2
                } else {
                    0
                };
                self.start_segment();
                continue;
            }
            self.fill_one();
            self.index = self.index.saturating_add(1);
        }
        self.done
    }

    /// The tag, once [`Argon2::step`] has returned true.
    pub fn finish(&self) -> Vec<u8> {
        let mut c = [0u64; WORDS];
        let last = self.lane_len.saturating_sub(1);
        for lane in 0..self.params.lanes {
            if let Some(b) = self.memory.get(self.at(lane, last)) {
                for (x, y) in c.iter_mut().zip(b) {
                    *x ^= y;
                }
            }
        }
        let bytes: Vec<u8> = c.iter().flat_map(|w| w.to_le_bytes()).collect();
        h_prime(
            usize::try_from(self.params.out_len).unwrap_or(32),
            &[&bytes],
        )
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

    fn run(variant: Variant, version: u32) -> String {
        // RFC 9106 section 5 test vectors.
        let params = Params {
            variant,
            version,
            memory_kib: 32,
            iterations: 3,
            lanes: 4,
            out_len: 32,
        };
        let mut a = Argon2::new(params, &[1; 32], &[2; 16], &[3; 8], &[4; 12]).unwrap();
        while !a.step(7) {}
        hex(&a.finish())
    }

    #[test]
    fn rfc9106_vectors() {
        assert_eq!(
            run(Variant::D, 0x13),
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
        );
        assert_eq!(
            run(Variant::I, 0x13),
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
        );
        assert_eq!(
            run(Variant::Id, 0x13),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn reference_library() {
        // argon2-cffi (libargon2) `hash_secret_raw(b"password",
        // b"somesaltsomesalt", time_cost=2, memory_cost=72, parallelism=3,
        // hash_len=40, ...)`, both versions.
        let cases = [
            (
                Variant::D,
                0x10,
                "52f1a648346dd2408fcbeee4169a527f5a07ab5b9e3b908764857f9ac929eeda9507239f6d8d6394",
            ),
            (
                Variant::D,
                0x13,
                "d0f0acfca1587f4b465620c4b817e6ad13611f9d761aa05e8ad22f3310a34433c312fef5733e1cb0",
            ),
            (
                Variant::I,
                0x10,
                "94e5ad94178e3878a661df3eba5d71e91d9102abaabed0e57e0a00bc5b53077edd0e72c4a4243aa3",
            ),
            (
                Variant::I,
                0x13,
                "c44a847956967d5f2c8b988551712c61ebfdced302e3ddcf369d3a4b4ebd79c48b938ba166589d70",
            ),
            (
                Variant::Id,
                0x10,
                "4e6961887de3b654ea5be3551682bb7ba166837ef97c21ace4d3be48225c60e1ebbcdb9001e68876",
            ),
            (
                Variant::Id,
                0x13,
                "be20f5a08f8fd62c95989cd34e6881bf5c87144927eb0a4174a0434a8163c5a5efb66654864c3eb9",
            ),
        ];
        for (variant, version, want) in cases {
            let params = Params {
                variant,
                version,
                memory_kib: 72,
                iterations: 2,
                lanes: 3,
                out_len: 40,
            };
            let mut a = Argon2::new(params, b"password", b"somesaltsomesalt", b"", b"").unwrap();
            while !a.step(1000) {}
            assert_eq!(hex(&a.finish()), want, "{variant:?} {version:#x}");
        }
    }
}
