//! Decryption stages for codec chains.

use std::fmt;
use std::sync::Arc;

use super::cipher::Aes;
use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// Key material held by a codec. `Debug` does not print it.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(Arc<[u8]>);

impl Key {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Key(bytes.into().into())
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// One byte of the raw CRC-32 register update ZipCrypto keys use.
fn crc_byte(crc: u32, b: u8) -> u32 {
    u32::try_from(crate::codec::crc::CRC32.update_byte(crc.into(), b)).unwrap_or(0)
}

/// The traditional PKWARE ("ZipCrypto") cipher state.
#[derive(Clone, Copy)]
pub struct ZipCryptoKeys([u32; 3]);

impl ZipCryptoKeys {
    pub fn new(password: &[u8]) -> Self {
        let mut k = ZipCryptoKeys([0x1234_5678, 0x2345_6789, 0x3456_7890]);
        for &b in password {
            k.update(b);
        }
        k
    }

    fn update(&mut self, plain: u8) {
        let [k0, k1, k2] = &mut self.0;
        *k0 = crc_byte(*k0, plain);
        *k1 = k1
            .wrapping_add(*k0 & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        *k2 = crc_byte(*k2, k1.to_be_bytes()[0]);
    }

    pub fn decrypt(&mut self, c: u8) -> u8 {
        let temp = (self.0[2] | 2) & 0xffff;
        let t = (temp.wrapping_mul(temp ^ 1) >> 8).to_le_bytes()[0];
        let p = c ^ t;
        self.update(p);
        p
    }
}

/// ZipCrypto decryption; the 12-byte encryption header is consumed but not
/// output.
#[derive(Clone)]
pub struct ZipCrypto {
    keys: ZipCryptoKeys,
    pos: usize,
}

impl ZipCrypto {
    pub fn new(password: &Key) -> Self {
        ZipCrypto {
            keys: ZipCryptoKeys::new(password.expose()),
            pos: 0,
        }
    }
}

impl Decode for ZipCrypto {
    fn step(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Step> {
        let available = input.get(self.pos..).unwrap_or_default();
        if available.is_empty() {
            return if eof { Ok(Step::Done) } else { Err(Diagnostic::malformed("out of input")) };
        }
        let take = available.len().min(step.max(1));
        for &c in available.get(..take).unwrap_or_default() {
            let p = self.keys.decrypt(c);
            if self.pos >= 12 {
                if out.len() >= limit {
                    return Err(Diagnostic::limit("decrypted data exceeds the limit"));
                }
                out.push(p);
            }
            self.pos = self.pos.saturating_add(1);
        }
        Ok(Step::More)
    }

    fn consumed(&self) -> usize {
        self.pos
    }
}

/// AES in CTR mode with a little-endian block counter starting at 1
/// (WinZip AE-1/AE-2).
#[derive(Clone)]
pub struct AesCtrLe {
    aes: Aes,
    pos: usize,
}

impl AesCtrLe {
    pub fn new(key: &Key) -> Option<Self> {
        Some(AesCtrLe {
            aes: Aes::new(key.expose())?,
            pos: 0,
        })
    }
}

impl Decode for AesCtrLe {
    fn step(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Step> {
        let available = input.get(self.pos..).unwrap_or_default();
        // Whole blocks, or the final partial block at the end.
        let usable = if eof { available.len() } else { available.len() & !15 };
        if usable == 0 {
            return if eof { Ok(Step::Done) } else { Err(Diagnostic::malformed("out of input")) };
        }
        let take = usable.min(step.max(16).next_multiple_of(16));
        if out.len().saturating_add(take) > limit {
            return Err(Diagnostic::limit("decrypted data exceeds the limit"));
        }
        let mut counter = u128::try_from(self.pos / 16).unwrap_or(0).wrapping_add(1);
        for chunk in available.get(..take).unwrap_or_default().chunks(16) {
            let mut ks = counter.to_le_bytes();
            self.aes.encrypt_block(&mut ks);
            out.extend(chunk.iter().zip(ks).map(|(a, b)| a ^ b));
            counter = counter.wrapping_add(1);
        }
        self.pos = self.pos.saturating_add(take);
        Ok(Step::More)
    }

    fn consumed(&self) -> usize {
        self.pos
    }
}

/// RC4 as a streaming stage.
#[derive(Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
    pos: usize,
}

impl Rc4 {
    pub fn new(key: &Key) -> Self {
        let mut s: [u8; 256] = std::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
        let key = key.expose();
        if !key.is_empty() {
            let mut j = 0u8;
            for i in 0..256usize {
                let k = key.get(i.checked_rem(key.len()).unwrap_or(0)).copied().unwrap_or(0);
                j = j.wrapping_add(s.get(i).copied().unwrap_or(0)).wrapping_add(k);
                s.swap(i, usize::from(j));
            }
        }
        Rc4 { s, i: 0, j: 0, pos: 0 }
    }
}

impl Decode for Rc4 {
    fn step(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Step> {
        let available = input.get(self.pos..).unwrap_or_default();
        if available.is_empty() {
            return if eof { Ok(Step::Done) } else { Err(Diagnostic::malformed("out of input")) };
        }
        let take = available.len().min(step.max(1));
        if out.len().saturating_add(take) > limit {
            return Err(Diagnostic::limit("decrypted data exceeds the limit"));
        }
        let get = |s: &[u8; 256], x: u8| s.get(usize::from(x)).copied().unwrap_or(0);
        for &b in available.get(..take).unwrap_or_default() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(get(&self.s, self.i));
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let t = get(&self.s, self.i).wrapping_add(get(&self.s, self.j));
            out.push(b ^ get(&self.s, t));
        }
        self.pos = self.pos.saturating_add(take);
        Ok(Step::More)
    }

    fn consumed(&self) -> usize {
        self.pos
    }
}

/// AES-CBC with the IV in the first 16 bytes and PKCS#7 padding (PDF
/// AESV2/AESV3).
#[derive(Clone)]
pub struct AesCbcIvPrefixed(pub Key);

impl crate::codec::filters::Filter for AesCbcIvPrefixed {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let out = aes_cbc_iv_prefixed(self.0.expose(), input)
            .ok_or_else(|| Diagnostic::malformed("AES-CBC data is not a whole number of blocks, or its padding is bad"))?;
        if out.len() > limit {
            return Err(Diagnostic::limit("decrypted data exceeds the limit"));
        }
        Ok(out)
    }
}

/// Decrypts `data` (IV, then AES-CBC ciphertext with PKCS#7 padding).
pub fn aes_cbc_iv_prefixed(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return Some(Vec::new());
    }
    let aes = Aes::new(key)?;
    let (iv, body) = (data.get(..16)?, data.get(16..)?);
    if body.len() % 16 != 0 {
        return None;
    }
    let plain = super::cipher::cbc_decrypt(&aes, iv, body);
    super::cipher::unpad_pkcs7(&plain, 16).map(<[u8]>::to_vec)
}
