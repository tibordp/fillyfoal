//! PostgreSQL's on-disk files: relation files (`base/<db>/<relfilenode>`,
//! heap tables, indexes, free space and visibility maps: `relation`),
//! the cluster control file (`global/pg_control`: `control`) and
//! write-ahead log segments (`pg_wal/<timeline><segment>`: `wal`). Custom
//! format dumps (`pg_dump -Fc`) are in `data::dumps`.

pub mod control;
pub mod relation;
pub mod wal;

/// PostgreSQL's page size; every build ships with 8 KiB pages.
pub(crate) const BLCKSZ: u64 = 8192;

/// The data checksum of a page (`pg_checksum_page`): FNV-1a style mixing
/// over 32 parallel lanes of 32-bit words, folded, mixed with the block
/// number and reduced to 1..=65535.
pub(crate) fn page_checksum(page: &[u8], block: u32) -> Option<u16> {
    const N_SUMS: usize = 32;
    const FNV_PRIME: u32 = 16_777_619;
    const BASE: [u32; N_SUMS] = [
        0x5B1F_36E9,
        0xB852_5960,
        0x02AB_50AA,
        0x1DE6_6D2A,
        0x79FF_467A,
        0x9BB9_F8A3,
        0x217E_7CD2,
        0x83E1_3D2C,
        0xF8D4_474F,
        0xE39E_B970,
        0x42C6_AE16,
        0x9932_16FA,
        0x7B09_3B5D,
        0x98DA_FF3C,
        0xF718_902A,
        0x0B1C_9CDB,
        0xE58F_764B,
        0x1876_36BC,
        0x5D7B_3BB1,
        0xE73D_E7DE,
        0x92BE_C979,
        0xCCA6_C0B2,
        0x304A_0979,
        0x85AA_43D4,
        0x7831_25BB,
        0x6CA8_EAA2,
        0xE407_EAC6,
        0x4B5C_FC3E,
        0x9FBF_8C76,
        0x15CA_20BE,
        0xF2CA_9FD3,
        0x959B_D756,
    ];
    if page.len() != crate::bytes::to_usize(BLCKSZ) {
        return None;
    }
    let comp = |sum: u32, value: u32| {
        let tmp = sum ^ value;
        tmp.wrapping_mul(FNV_PRIME) ^ (tmp >> 17)
    };
    let mut sums = BASE;
    for (i, chunk) in page.as_chunks::<4>().0.iter().enumerate() {
        let mut word = u32::from_le_bytes(*chunk);
        // The checksum field itself counts as zero.
        if i == 2 {
            word &= 0xffff_0000;
        }
        let lane = sums.get_mut(i % N_SUMS)?;
        *lane = comp(*lane, word);
    }
    for _ in 0..2 {
        for lane in &mut sums {
            *lane = comp(*lane, 0);
        }
    }
    let folded = sums.iter().fold(0u32, |a, &s| a ^ s) ^ block;
    u16::try_from(folded % 65535).ok()?.checked_add(1)
}
