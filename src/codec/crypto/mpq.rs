//! The MPQ "encryption": a fixed table-driven cipher whose keys are hashes
//! of well-known strings (table names, file names).

/// The crypt table (0x500 entries), built at compile time.
// Evaluated at compile time: an out-of-range index is a compile error.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const TABLE: [u32; 0x500] = {
    let mut t = [0u32; 0x500];
    let mut seed: u32 = 0x0010_0001;
    let mut i = 0;
    while i < 0x100 {
        let mut j = i;
        let mut k = 0;
        while k < 5 {
            seed = (seed * 125 + 3) % 0x2a_aaab;
            let hi = (seed & 0xffff) << 16;
            seed = (seed * 125 + 3) % 0x2a_aaab;
            let lo = seed & 0xffff;
            t[j] = hi | lo;
            j += 0x100;
            k += 1;
        }
        i += 1;
    }
    t
};

fn table(i: u32) -> u32 {
    TABLE.get(usize::try_from(i).unwrap_or(0)).copied().unwrap_or(0)
}

/// Hash kinds for [`hash_string`].
pub const HASH_OFFSET: u32 = 0;
pub const HASH_NAME_A: u32 = 1;
pub const HASH_NAME_B: u32 = 2;
pub const HASH_FILE_KEY: u32 = 3;

/// The MPQ string hash (case-insensitive, `/` and `\` equivalent).
pub fn hash_string(s: &str, kind: u32) -> u32 {
    let (mut seed1, mut seed2) = (0x7fed_7fedu32, 0xeeee_eeeeu32);
    for b in s.bytes() {
        let c = u32::from(if b == b'/' { b'\\' } else { b.to_ascii_uppercase() });
        seed1 = table(kind.wrapping_mul(0x100).wrapping_add(c)) ^ seed1.wrapping_add(seed2);
        seed2 = c.wrapping_add(seed1).wrapping_add(seed2).wrapping_add(seed2 << 5).wrapping_add(3);
    }
    seed1
}

/// Decrypts little-endian 32-bit words in place (a trailing partial word is
/// left as is).
pub fn decrypt(data: &mut [u8], mut key: u32) {
    let mut seed = 0xeeee_eeeeu32;
    for word in data.as_chunks_mut::<4>().0 {
        seed = seed.wrapping_add(table(0x400u32.wrapping_add(key & 0xff)));
        let ch = u32::from_le_bytes(*word) ^ key.wrapping_add(seed);
        key = (!key << 0x15).wrapping_add(0x1111_1111) | (key >> 0x0b);
        seed = ch.wrapping_add(seed).wrapping_add(seed << 5).wrapping_add(3);
        *word = ch.to_le_bytes();
    }
}

/// The key of a file: the hash of its base name, adjusted by its offset and
/// size when the archive says so.
pub fn file_key(name: &str, offset: u32, size: u32, adjusted: bool) -> u32 {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let key = hash_string(base, HASH_FILE_KEY);
    if adjusted { key.wrapping_add(offset) ^ size } else { key }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_keys() {
        // The table keys every MPQ implementation hard-codes.
        assert_eq!(hash_string("(hash table)", HASH_FILE_KEY), 0xc3af_3770);
        assert_eq!(hash_string("(block table)", HASH_FILE_KEY), 0xec83_b3a3);
    }
}
