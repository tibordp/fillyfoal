//! 7-Zip's AES-256 key derivation (the 7zAES coder, method `06 F1 07 01`).
//!
//! The key is the SHA-256 of 2^`cycles` rounds of salt ‖ password ‖ round
//! counter, the password as UTF-16LE and the counter as 8 little-endian
//! bytes, all fed to one hash. `cycles` 0x3f is a special case with no
//! hashing: the key is salt ‖ password, cut or zero-padded to 32 bytes.
//! Written from the format's description (7-Zip's `7zAes` documentation
//! and behaviour, checked against archives made by 7-Zip 25.01), not from
//! its source.

use super::{Hash, Sha256, Stepped};

/// The `cycles` value that means "no hashing".
pub const RAW_KEY: u8 = 0x3f;

/// A password as 7-Zip feeds it to the key derivation: UTF-16LE, no
/// terminator (invalid UTF-8 is replaced first).
pub fn utf16le(password: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(password)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// An incremental 7zAES key derivation. One unit of work is one round
/// per 64 bytes it hashes (a round of a short password hashes fewer than
/// 64 bytes, so a unit is a fraction of a SHA-256 block).
#[derive(Clone)]
pub struct SevenZipKdf {
    /// Salt ‖ password ‖ counter: what each round hashes.
    round: Vec<u8>,
    /// Where the counter starts in `round`.
    counter_at: usize,
    rounds: u64,
    done: u64,
    sha: Sha256,
    key: Option<[u8; 32]>,
}

impl SevenZipKdf {
    /// `password` is UTF-16LE (see [`utf16le`]). `cycles` above 62 other
    /// than [`RAW_KEY`] is taken as 62 (callers refuse those anyway).
    pub fn new(password: &[u8], salt: &[u8], cycles: u8) -> Self {
        let mut round = salt.to_vec();
        round.extend_from_slice(password);
        let counter_at = round.len();
        if cycles == RAW_KEY {
            let mut key = [0u8; 32];
            for (k, b) in key.iter_mut().zip(&round) {
                *k = *b;
            }
            return SevenZipKdf {
                round,
                counter_at,
                rounds: 0,
                done: 0,
                sha: Sha256::new(),
                key: Some(key),
            };
        }
        round.extend_from_slice(&[0; 8]);
        SevenZipKdf {
            round,
            counter_at,
            rounds: 1u64 << cycles.min(62),
            done: 0,
            sha: Sha256::new(),
            key: None,
        }
    }

    /// The units of work one round takes.
    fn cost(&self) -> u32 {
        u32::try_from(self.round.len().div_ceil(64))
            .unwrap_or(u32::MAX)
            .max(1)
    }

    /// The derived key (all zeros if the derivation was not run to the end).
    pub fn key(&self) -> [u8; 32] {
        self.key.unwrap_or([0; 32])
    }
}

impl Stepped for SevenZipKdf {
    fn advance(&mut self, units: u32) -> u32 {
        let cost = self.cost();
        let mut used = 0u32;
        while used < units.max(1) && self.key.is_none() {
            self.sha.update(&self.round);
            // The counter: 8 little-endian bytes, incremented with carry.
            for b in self.round.iter_mut().skip(self.counter_at) {
                *b = b.wrapping_add(1);
                if *b != 0 {
                    break;
                }
            }
            self.done = self.done.saturating_add(1);
            used = used.saturating_add(cost);
            if self.done >= self.rounds {
                let digest = std::mem::replace(&mut self.sha, Sha256::new()).finish();
                let mut key = [0u8; 32];
                for (k, b) in key.iter_mut().zip(&digest) {
                    *k = *b;
                }
                self.key = Some(key);
            }
        }
        used
    }

    fn done(&self) -> bool {
        self.key.is_some()
    }

    fn units(&self) -> u64 {
        self.rounds.saturating_mul(self.cost().into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn derive(password: &str, salt: &[u8], cycles: u8) -> [u8; 32] {
        let mut kdf = SevenZipKdf::new(&utf16le(password.as_bytes()), salt, cycles);
        while kdf.advance(7) > 0 {}
        kdf.key()
    }

    #[test]
    fn rounds_hash_salt_password_and_counter() {
        // The definition, spelt out for 2^3 rounds.
        let pw = utf16le("fillyfoal".as_bytes());
        let salt = [1u8, 2, 3];
        let mut all = Vec::new();
        for i in 0u64..8 {
            all.extend_from_slice(&salt);
            all.extend_from_slice(&pw);
            all.extend_from_slice(&i.to_le_bytes());
        }
        assert_eq!(derive("fillyfoal", &salt, 3).to_vec(), Sha256::digest(&all));
        // The counter carries into its next byte.
        let mut all = Vec::new();
        for i in 0u64..512 {
            all.extend_from_slice(&pw);
            all.extend_from_slice(&i.to_le_bytes());
        }
        assert_eq!(derive("fillyfoal", &[], 9).to_vec(), Sha256::digest(&all));
    }

    #[test]
    fn raw_key_is_salt_and_password() {
        let key = derive("ab", &[9], RAW_KEY);
        assert_eq!(&key[..5], &[9, b'a', 0, b'b', 0]);
        assert!(key[5..].iter().all(|&b| b == 0));
        let long = derive("0123456789abcdefghij", &[], RAW_KEY);
        assert_eq!(long.to_vec(), utf16le(b"0123456789abcdef"));
    }

    #[test]
    fn units_and_steps() {
        let mut kdf = SevenZipKdf::new(&utf16le(b"fillyfoal"), &[], 10);
        // 18 password bytes and 8 counter bytes: one unit a round.
        assert_eq!(kdf.units(), 1024);
        assert_eq!(kdf.advance(100), 100);
        assert!(!kdf.done());
        let mut total = 100;
        loop {
            let used = kdf.advance(100);
            if used == 0 {
                break;
            }
            total += used;
        }
        assert_eq!(total, 1024);
        assert!(kdf.done());
    }
}
