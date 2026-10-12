//! RC4 encryption of Office binary documents (MS-OFFCRYPTO 2.3.6, "RC4",
//! and 2.3.5, "RC4 CryptoAPI"): the keystream is restarted with a new key
//! every 1024 bytes of the stream, the key of block `n` being a hash of the
//! password-derived key and `n`. In an Excel workbook stream (MS-XLS
//! 2.2.10) the keystream runs by stream position, but record headers and
//! the bodies of a few records stay in the clear.

use super::cipher::Rc4State;
use super::hash::{Hash, Md5, Sha1};
use super::stream::Key;
use crate::codec::filters::ByteFilter;
use crate::error::Result;

/// Bytes encrypted with one block key.
pub const BLOCK: u64 = 1024;

/// The password-derived key and how block keys are made from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rc4Key {
    /// RC4: the 5-byte truncated intermediate hash. CryptoAPI: H0, the
    /// SHA-1 of the salt and the password.
    pub base: Key,
    /// CryptoAPI (SHA-1) rather than RC4 1.1 (MD5).
    pub cryptoapi: bool,
    /// CryptoAPI: the key size in bytes (5 for 40-bit keys, which are
    /// padded with zeros to 128 bits).
    pub key_bytes: usize,
}

impl Rc4Key {
    /// RC4 1.1 (MS-OFFCRYPTO 2.3.6.2): `password` is UTF-16LE.
    pub fn rc4(password: &[u8], salt: &[u8]) -> Self {
        let h0 = Md5::digest(password);
        let truncated = h0.get(..5).unwrap_or_default();
        let mut h = Md5::new();
        for _ in 0..16 {
            h.update(truncated);
            h.update(salt);
        }
        let h1 = h.finish();
        Rc4Key {
            base: Key::new(h1.get(..5).unwrap_or_default().to_vec()),
            cryptoapi: false,
            key_bytes: 16,
        }
    }

    /// RC4 CryptoAPI (MS-OFFCRYPTO 2.3.5.2): `password` is UTF-16LE, `bits`
    /// the header's KeySize (0 means 40).
    pub fn cryptoapi(password: &[u8], salt: &[u8], bits: u32) -> Self {
        let mut h = Sha1::new();
        h.update(salt);
        h.update(password);
        let bits = if bits == 0 { 40 } else { bits.min(160) };
        Rc4Key {
            base: Key::new(h.finish()),
            cryptoapi: true,
            key_bytes: usize::try_from(bits / 8).unwrap_or(16).max(5),
        }
    }

    /// The RC4 key of block `block`.
    pub fn block_key(&self, block: u32) -> Vec<u8> {
        let base = self.base.expose();
        if self.cryptoapi {
            let mut h = Sha1::new();
            h.update(base);
            h.update(&block.to_le_bytes());
            let mut key = h.finish();
            key.truncate(self.key_bytes);
            if self.key_bytes == 5 {
                key.resize(16, 0);
            }
            key
        } else {
            let mut h = Md5::new();
            h.update(base);
            h.update(&block.to_le_bytes());
            h.finish()
        }
    }

    /// Whether the password is right: the verifier and its hash (MD5 for
    /// RC4, SHA-1 for CryptoAPI) decrypt, as one keystream with block 0's
    /// key, to a verifier that hashes to the hash.
    pub fn verify(&self, verifier: &[u8], verifier_hash: &[u8]) -> bool {
        let mut rc4 = Rc4State::new(&self.block_key(0));
        let plain: Vec<u8> = verifier.iter().map(|&b| rc4.apply(b)).collect();
        let hash: Vec<u8> = verifier_hash.iter().map(|&b| rc4.apply(b)).collect();
        let expected = if self.cryptoapi {
            Sha1::digest(&plain)
        } else {
            Md5::digest(&plain)
        };
        let n = expected.len().min(hash.len());
        n >= 16 && hash.get(..n) == expected.get(..n)
    }
}

/// Where the filter is in the record structure.
#[derive(Clone, Copy, Debug)]
enum Part {
    /// Reading the 4-byte header; `have` bytes so far.
    Header { have: u8 },
    /// In the body: `left` bytes to go, `at` bytes done.
    Body { left: u16, at: u16 },
}

/// Decrypts an Excel BIFF8 workbook stream: record headers, everything up
/// to and including FILEPASS, the bodies of the records MS-XLS 2.2.10
/// leaves in the clear (BOF, FILEPASS, UsrExcl, FileLock, InterfaceHdr,
/// RRDInfo, RRDHead) and BoundSheet8's lbPlyPos are copied; everything else
/// is decrypted with the keystream byte of its stream position.
#[derive(Clone)]
pub struct XlsRc4 {
    key: Rc4Key,
    rc4: Rc4State,
    pos: u64,
    header: [u8; 4],
    part: Part,
    encrypting: bool,
}

impl XlsRc4 {
    pub fn new(key: &Rc4Key) -> Self {
        XlsRc4 {
            rc4: Rc4State::new(&key.block_key(0)),
            key: key.clone(),
            pos: 0,
            header: [0; 4],
            part: Part::Header { have: 0 },
            encrypting: false,
        }
    }

    fn kind(&self) -> u16 {
        u16::from_le_bytes([self.header[0], self.header[1]])
    }
}

/// Records whose bodies stay unencrypted after FILEPASS.
pub fn xls_clear_record(kind: u16) -> bool {
    matches!(
        kind,
        0x0809
            | 0x0409
            | 0x0209
            | 0x0009
            | 0x002f
            | 0x0194
            | 0x0195
            | 0x00e1
            | 0x0196
            | 0x0138
            | 0x000a
    )
}

impl ByteFilter for XlsRc4 {
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool> {
        if self.pos > 0 && self.pos.is_multiple_of(BLOCK) {
            let block = u32::try_from(self.pos / BLOCK).unwrap_or(u32::MAX);
            self.rc4 = Rc4State::new(&self.key.block_key(block));
        }
        let decrypted = self.rc4.apply(b);
        self.pos = self.pos.saturating_add(1);
        match self.part {
            Part::Header { have } => {
                if let Some(slot) = self.header.get_mut(usize::from(have)) {
                    *slot = b;
                }
                out.push(b);
                let have = have.saturating_add(1);
                self.part = if have < 4 {
                    Part::Header { have }
                } else {
                    let len = u16::from_le_bytes([self.header[2], self.header[3]]);
                    if len == 0 {
                        self.after_record();
                        Part::Header { have: 0 }
                    } else {
                        Part::Body { left: len, at: 0 }
                    }
                };
            }
            Part::Body { left, at } => {
                let kind = self.kind();
                let clear =
                    !self.encrypting || xls_clear_record(kind) || (kind == 0x0085 && at < 4);
                out.push(if clear { b } else { decrypted });
                let left = left.saturating_sub(1);
                self.part = if left == 0 {
                    self.after_record();
                    Part::Header { have: 0 }
                } else {
                    Part::Body {
                        left,
                        at: at.saturating_add(1),
                    }
                };
            }
        }
        Ok(true)
    }

    fn heap_size(&self) -> Option<usize> {
        // The permutation is inline; the key is shared.
        Some(0)
    }
}

impl XlsRc4 {
    fn after_record(&mut self) {
        if self.kind() == 0x002f {
            self.encrypting = true;
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

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn rc4_verifier_round_trip() {
        // Encrypt a verifier the way a writer does, then check it.
        let salt = [7u8; 16];
        let key = Rc4Key::rc4(&utf16("fillyfoal"), &salt);
        let verifier = [0x42u8; 16];
        let hash = Md5::digest(&verifier);
        let mut rc4 = Rc4State::new(&key.block_key(0));
        let enc_v: Vec<u8> = verifier.iter().map(|&b| rc4.apply(b)).collect();
        let enc_h: Vec<u8> = hash.iter().map(|&b| rc4.apply(b)).collect();
        assert!(key.verify(&enc_v, &enc_h));
        let wrong = Rc4Key::rc4(&utf16("nope"), &salt);
        assert!(!wrong.verify(&enc_v, &enc_h));
    }

    #[test]
    fn xls_headers_and_clear_records_pass_through() {
        let key = Rc4Key::cryptoapi(&utf16("fillyfoal"), &[1; 16], 128);
        // FILEPASS (empty body for the test), then a record that is
        // encrypted, then a BOF whose body stays clear.
        let stream = [
            0x2f, 0x00, 0x00, 0x00, // FILEPASS
            0x3d, 0x00, 0x02, 0x00, 0xaa, 0xbb, // WINDOW1-ish, encrypted
            0x09, 0x08, 0x02, 0x00, 0x00, 0x06, // BOF, clear
        ];
        let mut f = XlsRc4::new(&key);
        let mut out = Vec::new();
        for &b in &stream {
            f.byte(b, &mut out).unwrap();
        }
        assert_eq!(out.get(..8), stream.get(..8));
        assert_ne!(out.get(8..10), stream.get(8..10));
        assert_eq!(out.get(10..), stream.get(10..));
        // Decrypting is position-keyed RC4 over the body bytes.
        let mut rc4 = Rc4State::new(&key.block_key(0));
        let ks: Vec<u8> = (0..10).map(|_| rc4.apply(0)).collect();
        assert_eq!(out.get(8), Some(&(0xaa ^ ks[8])));
    }
}
