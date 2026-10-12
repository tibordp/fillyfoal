//! RC4 encryption of Office binary documents (MS-OFFCRYPTO 2.3.6, "RC4",
//! and 2.3.5, "RC4 CryptoAPI"), and the XOR obfuscation of Excel workbooks
//! (2.3.7, method 1). RC4: the keystream is restarted with a new key
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

/// The keystream of an encrypted workbook stream (one per stream, so the
/// inline RC4 permutation costs nothing worth boxing).
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum Cipher {
    /// RC4 or RC4 CryptoAPI, rekeyed every [`BLOCK`] bytes.
    Rc4 { key: Rc4Key, rc4: Rc4State },
    /// XOR obfuscation (MS-OFFCRYPTO 2.3.7.4, method 1) with this 16-byte
    /// XOR array (see [`xor_array`]).
    Xor(Key),
}

/// Decrypts an Excel workbook stream (RC4 and RC4 CryptoAPI in BIFF8, XOR
/// obfuscation in BIFF5 and BIFF8): record headers, everything up to and
/// including FILEPASS, the bodies of the records MS-XLS 2.2.10 leaves in
/// the clear (BOF, FILEPASS, UsrExcl, FileLock, InterfaceHdr, RRDInfo,
/// RRDHead) and BoundSheet8's lbPlyPos are copied; everything else is
/// decrypted by its stream position: with the RC4 keystream byte of that
/// position or, for XOR obfuscation, XORed with the XOR array byte at that
/// position plus the record's size (modulo 16) and rotated right by 5 bits
/// (as msoffcrypto-tool decrypts it).
#[derive(Clone)]
pub struct XlsRc4 {
    cipher: Cipher,
    pos: u64,
    header: [u8; 4],
    part: Part,
    encrypting: bool,
}

impl XlsRc4 {
    pub fn new(key: &Rc4Key) -> Self {
        Self::with(Cipher::Rc4 {
            rc4: Rc4State::new(&key.block_key(0)),
            key: key.clone(),
        })
    }

    /// XOR obfuscation with the 16-byte XOR array `array` (see
    /// [`xor_array`]).
    pub fn xor(array: &Key) -> Self {
        Self::with(Cipher::Xor(array.clone()))
    }

    fn with(cipher: Cipher) -> Self {
        XlsRc4 {
            cipher,
            pos: 0,
            header: [0; 4],
            part: Part::Header { have: 0 },
            encrypting: false,
        }
    }

    fn kind(&self) -> u16 {
        u16::from_le_bytes([self.header[0], self.header[1]])
    }

    fn len(&self) -> u16 {
        u16::from_le_bytes([self.header[2], self.header[3]])
    }

    /// The byte at the current position decrypted (the RC4 keystream runs
    /// over every byte, clear or not).
    fn decrypt(&mut self, b: u8) -> u8 {
        let pos = self.pos;
        let len = self.len();
        match &mut self.cipher {
            Cipher::Rc4 { key, rc4 } => {
                if pos > 0 && pos.is_multiple_of(BLOCK) {
                    let block = u32::try_from(pos / BLOCK).unwrap_or(u32::MAX);
                    *rc4 = Rc4State::new(&key.block_key(block));
                }
                rc4.apply(b)
            }
            Cipher::Xor(array) => {
                let index = pos.wrapping_add(len.into()) % 16;
                let x = usize::try_from(index)
                    .ok()
                    .and_then(|i| array.expose().get(i))
                    .copied()
                    .unwrap_or(0);
                (b ^ x).rotate_right(5)
            }
        }
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
        let decrypted = self.decrypt(b);
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
                    let len = self.len();
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

/// The single-byte password XOR obfuscation works on (MS-OFFCRYPTO
/// 2.3.7.4): each character's low byte, or its high byte when the low one
/// is zero; `None` unless it has 1 to 15 characters.
pub fn xor_password(password: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = password
        .encode_utf16()
        .map(|c| {
            let [lo, hi] = c.to_le_bytes();
            if lo == 0 { hi } else { lo }
        })
        .collect();
    (1..=15).contains(&bytes.len()).then_some(bytes)
}

/// The password verifier of XOR obfuscation (MS-OFFCRYPTO 2.3.7.1,
/// CreatePasswordVerifier_Method1), as FILEPASS stores it.
pub fn xor_verifier(password: &[u8]) -> u16 {
    let len = u8::try_from(password.len()).unwrap_or(u8::MAX);
    let mut verifier = 0u16;
    for &b in password.iter().rev().chain(std::iter::once(&len)) {
        let high = u16::from(verifier & 0x4000 != 0);
        verifier = (high | (verifier.wrapping_shl(1) & 0x7fff)) ^ u16::from(b);
    }
    verifier ^ 0xce4b
}

const XOR_INITIAL: [u16; 15] = [
    0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C, 0x0E10, 0xF1CE, 0x313E, 0x1872, 0xE139, 0xD40F, 0x84F9,
    0x280C, 0xA96A, 0x4EC3,
];

const XOR_MATRIX: [u16; 105] = [
    0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09, 0x7B61, 0xF6C2, 0xFDA5, 0xEB6B, 0xC6F7,
    0x9DCF, 0x2BBF, 0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0, 0x0375, 0x06EA, 0x0DD4,
    0x1BA8, 0x3750, 0x6EA0, 0xDD40, 0xD849, 0xA0B3, 0x5147, 0xA28E, 0x553D, 0xAA7A, 0x44D5, 0x6F45,
    0xDE8A, 0xAD35, 0x4A4B, 0x9496, 0x390D, 0x721A, 0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC,
    0x5FD9, 0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0, 0xB861, 0x60E3, 0xC1C6, 0x93AD,
    0x377B, 0x6EF6, 0xDDEC, 0x45A0, 0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10, 0xAA51, 0x4483,
    0x8906, 0x022D, 0x045A, 0x08B4, 0x1168, 0x76B4, 0xED68, 0xCAF1, 0x85C3, 0x1BA7, 0x374E, 0x6E9C,
    0x3730, 0x6E60, 0xDCC0, 0xA9A1, 0x4363, 0x86C6, 0x1DAD, 0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373,
    0x06E6, 0x0DCC, 0x1021, 0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48C4,
];

/// The XOR obfuscation key (MS-OFFCRYPTO 2.3.7.2, CreateXorKey_Method1)
/// of a password of 1 to 15 bytes.
pub fn xor_key(password: &[u8]) -> u16 {
    let mut key = password
        .len()
        .checked_sub(1)
        .and_then(|i| XOR_INITIAL.get(i))
        .copied()
        .unwrap_or(0);
    let mut element = XOR_MATRIX.len();
    for &c in password.iter().rev() {
        let mut c = c;
        for _ in 0..7 {
            element = element.saturating_sub(1);
            if c & 0x40 != 0 {
                key ^= XOR_MATRIX.get(element).copied().unwrap_or(0);
            }
            c = c.wrapping_shl(1);
        }
    }
    key
}

/// The 16-byte XOR array of XOR obfuscation (MS-OFFCRYPTO 2.3.7.2,
/// CreateXorArray_Method1) for a password of 1 to 15 bytes: the password
/// followed by the pad array, each byte XORed with the key's low byte
/// (even positions) or high byte (odd positions) and rotated right by 1.
pub fn xor_array(password: &[u8]) -> [u8; 16] {
    const PAD: [u8; 15] = [
        0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80, 0x00, 0xBE, 0x0F, 0x00, 0xBF, 0x0F, 0x00,
    ];
    let [lo, hi] = xor_key(password).to_le_bytes();
    let n = password.len().min(15);
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let src = if i < n {
            password.get(i).copied()
        } else {
            i.checked_sub(n).and_then(|j| PAD.get(j)).copied()
        }
        .unwrap_or(0);
        let half = if i.is_multiple_of(2) { lo } else { hi };
        *slot = (src ^ half).rotate_right(1);
    }
    out
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

    #[test]
    fn xor_obfuscation_matches_msoffcrypto() {
        // Keys and arrays computed with msoffcrypto-tool 6.0.0's
        // DocumentXOR; the VelvetSweatshop verifier is its doctest's.
        let cases: [(&str, u16, &str); 3] = [
            ("fillyfoal", 0x323e, "2cad292fa32aa8a929c4e0e642e6e0c5"),
            (
                "VelvetSweatshop",
                0xb359,
                "876b9ae21ee305621e699660986e9404",
            ),
            ("abc", 0x514a, "95999475da577857da7465a87a2f2577"),
        ];
        for (password, key, array) in cases {
            let p = xor_password(password).unwrap();
            assert_eq!(xor_key(&p), key, "{password}");
            let hex: String = xor_array(&p).iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, array, "{password}");
        }
        assert_eq!(xor_verifier(b"VelvetSweatshop"), 0x9a0a);
        assert_eq!(xor_verifier(b"fillyfoal"), 0xd2ab);
        assert_eq!(xor_password(""), None);
        assert_eq!(xor_password("0123456789abcdef"), None);
    }

    #[test]
    fn xls_xor_decrypts_by_position_and_record_size() {
        let array = xor_array(b"fillyfoal");
        let mut f = XlsRc4::xor(&Key::new(array.to_vec()));
        // FILEPASS at 0 (6-byte body), then a 2-byte record whose body sits
        // at stream offsets 14 and 15: indices (14 + 2) % 16 and 15 + 2.
        let plain = [0x12u8, 0x34];
        let enc: Vec<u8> = plain
            .iter()
            .zip([0usize, 1])
            .map(|(&b, i)| b.rotate_left(5) ^ array[i])
            .collect();
        let mut stream = vec![0x2f, 0x00, 0x06, 0x00, 0, 0, 0, 0, 0, 0];
        stream.extend_from_slice(&[0x3d, 0x00, 0x02, 0x00]);
        stream.extend_from_slice(&enc);
        let mut out = Vec::new();
        for &b in &stream {
            f.byte(b, &mut out).unwrap();
        }
        assert_eq!(out.get(..14), stream.get(..14));
        assert_eq!(out.get(14..), Some(&plain[..]));
    }
}
