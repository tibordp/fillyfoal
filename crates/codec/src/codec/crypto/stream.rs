//! Decryption stages for codec chains.

use std::fmt;
use std::sync::Arc;

use super::cipher::{Aes, Rc4State};
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
    /// Header bytes still to decrypt (and drop).
    header: u8,
}

impl ZipCrypto {
    pub fn new(password: &Key) -> Self {
        ZipCrypto {
            keys: ZipCryptoKeys::new(password.expose()),
            pos: 0,
            header: 12,
        }
    }
}

impl Decode for ZipCrypto {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let available = input.get(self.pos..).unwrap_or_default();
        if available.is_empty() {
            return if eof {
                Ok(Step::Done)
            } else {
                Err(Diagnostic::malformed("out of input"))
            };
        }
        let take = available.len().min(step.max(1));
        for &c in available.get(..take).unwrap_or_default() {
            let p = self.keys.decrypt(c);
            if self.header > 0 {
                self.header = self.header.saturating_sub(1);
            } else {
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
    fn releasable_input(&self) -> usize {
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }

    fn heap_size(&self) -> Option<usize> {
        // Three 32-bit keys.
        Some(0)
    }
}

/// Heap bytes of an AES key schedule, at most: 15 round keys of 16 bytes
/// (AES-256).
const AES_ROUND_KEYS: usize = 15 * 16;

/// AES in CTR mode with a little-endian block counter starting at 1
/// (WinZip AE-1/AE-2).
#[derive(Clone)]
pub struct AesCtrLe {
    aes: Aes,
    pos: usize,
    /// Input bytes dropped from the front (a multiple of 16 until the
    /// end), for the counter.
    released: usize,
}

impl AesCtrLe {
    pub fn new(key: &Key) -> Option<Self> {
        Some(AesCtrLe {
            aes: Aes::new(key.expose())?,
            pos: 0,
            released: 0,
        })
    }
}

impl Decode for AesCtrLe {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let available = input.get(self.pos..).unwrap_or_default();
        // Whole blocks, or the final partial block at the end.
        let usable = if eof {
            available.len()
        } else {
            available.len() & !15
        };
        if usable == 0 {
            return if eof {
                Ok(Step::Done)
            } else {
                Err(Diagnostic::malformed("out of input"))
            };
        }
        let take = usable.min(
            step.max(16)
                .checked_next_multiple_of(16)
                .unwrap_or(usize::MAX),
        );
        if out.len().saturating_add(take) > limit {
            return Err(Diagnostic::limit("decrypted data exceeds the limit"));
        }
        let block = self.released.saturating_add(self.pos) / 16;
        let mut counter = u128::try_from(block).unwrap_or(0).wrapping_add(1);
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
    fn releasable_input(&self) -> usize {
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        self.released = self.released.saturating_add(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }

    fn heap_size(&self) -> Option<usize> {
        Some(AES_ROUND_KEYS)
    }
}

/// RC4 as a streaming stage.
#[derive(Clone)]
pub struct Rc4 {
    state: Rc4State,
    pos: usize,
}

impl Rc4 {
    pub fn new(key: &Key) -> Self {
        Rc4 {
            state: Rc4State::new(key.expose()),
            pos: 0,
        }
    }
}

impl Decode for Rc4 {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let available = input.get(self.pos..).unwrap_or_default();
        if available.is_empty() {
            return if eof {
                Ok(Step::Done)
            } else {
                Err(Diagnostic::malformed("out of input"))
            };
        }
        let take = available.len().min(step.max(1));
        if out.len().saturating_add(take) > limit {
            return Err(Diagnostic::limit("decrypted data exceeds the limit"));
        }
        let state = &mut self.state;
        out.extend(
            available
                .get(..take)
                .unwrap_or_default()
                .iter()
                .map(|&b| state.apply(b)),
        );
        self.pos = self.pos.saturating_add(take);
        Ok(Step::More)
    }

    fn consumed(&self) -> usize {
        self.pos
    }
    fn releasable_input(&self) -> usize {
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }

    fn heap_size(&self) -> Option<usize> {
        // The 256-byte permutation is inline.
        Some(0)
    }
}

/// AES-CBC with the IV in the first 16 bytes and PKCS#7 padding (PDF
/// AESV2/AESV3), decrypted block by block. The last block is held back
/// until the input ends, when its padding is checked and removed.
#[derive(Clone)]
pub struct AesCbcIvPrefixed {
    /// `None` for a key of the wrong length (an error unless the data is
    /// empty).
    aes: Option<Aes>,
    /// The previous ciphertext block (the IV at first).
    iv: [u8; 16],
    have_iv: bool,
    /// A partial block.
    buf: [u8; 16],
    filled: usize,
    /// The last decrypted block, held for its padding.
    held: Option<[u8; 16]>,
    seen: bool,
}

impl AesCbcIvPrefixed {
    pub fn new(key: &Key) -> Self {
        AesCbcIvPrefixed {
            aes: Aes::new(key.expose()),
            iv: [0; 16],
            have_iv: false,
            buf: [0; 16],
            filled: 0,
            held: None,
            seen: false,
        }
    }
}

fn bad_aes_cbc() -> Diagnostic {
    Diagnostic::malformed("AES-CBC data is not a whole number of blocks, or its padding is bad")
}

impl crate::codec::filters::ByteFilter for AesCbcIvPrefixed {
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool> {
        self.seen = true;
        let Some(aes) = &self.aes else {
            return Err(bad_aes_cbc());
        };
        if let Some(slot) = self.buf.get_mut(self.filled) {
            *slot = b;
        }
        self.filled = self.filled.saturating_add(1);
        if self.filled < 16 {
            return Ok(true);
        }
        self.filled = 0;
        let cipher = self.buf;
        if !self.have_iv {
            self.iv = cipher;
            self.have_iv = true;
            return Ok(true);
        }
        let mut block = cipher;
        aes.decrypt_block(&mut block);
        for (p, v) in block.iter_mut().zip(&self.iv) {
            *p ^= v;
        }
        self.iv = cipher;
        if let Some(prev) = self.held.replace(block) {
            out.extend_from_slice(&prev);
        }
        Ok(true)
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if !self.seen {
            return Ok(());
        }
        let last = match self.held.take() {
            Some(last) if self.filled == 0 => last,
            _ => return Err(bad_aes_cbc()),
        };
        let body = super::cipher::unpad_pkcs7(&last, 16).ok_or_else(bad_aes_cbc)?;
        out.extend_from_slice(body);
        Ok(())
    }

    fn heap_size(&self) -> Option<usize> {
        Some(self.aes.as_ref().map_or(0, |_| AES_ROUND_KEYS))
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::codec::Codec;
    use crate::codec::pipeline::verify_checkpoints;

    /// Every cipher resumes from a checkpoint anywhere: the stream ciphers
    /// on any input (decrypting is a bijection), CBC on data encrypted here.
    #[test]
    fn checkpoints_resume_anywhere() {
        let data: Vec<u8> = (0..50_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let key = Key::new(b"0123456789abcdef0123456789abcdef".to_vec());
        let mut iv = [7u8; 16];
        let mut cbc = iv.to_vec();
        let aes = Aes::new(key.expose()).unwrap();
        let pad = 16 - data.len() % 16;
        let padded = [data.clone(), vec![pad as u8; pad]].concat();
        for block in padded.chunks(16) {
            let mut b: [u8; 16] = block.try_into().unwrap();
            for (x, v) in b.iter_mut().zip(&iv) {
                *x ^= v;
            }
            aes.encrypt_block(&mut b);
            cbc.extend_from_slice(&b);
            iv = b;
        }
        let cases = [
            (Codec::ZipCrypto(key.clone()), data.clone(), 0),
            (Codec::AesCtrLe(key.clone()), data.clone(), AES_ROUND_KEYS),
            (Codec::Rc4(key.clone()), data.clone(), 0),
            (Codec::AesCbc(key.clone()), cbc, AES_ROUND_KEYS),
        ];
        for (codec, input, heap) in cases {
            let decoded = crate::codec::pipeline::decode_all(
                codec.decoder().unwrap().as_mut(),
                &input,
                1 << 20,
            )
            .unwrap();
            match codec {
                Codec::AesCbc(_) => assert!(decoded == data),
                Codec::ZipCrypto(_) => assert_eq!(decoded.len(), data.len() - 12),
                _ => assert_eq!(decoded.len(), data.len()),
            }
            // Steps of a block and a half: checkpoints mid-block too.
            let (checked, largest) =
                verify_checkpoints(|| codec.decoder().unwrap(), &input, 24, 97).unwrap();
            assert!(checked > 15, "{checked}");
            assert!(
                (heap..heap + 512).contains(&largest),
                "{}: {largest}",
                codec.name()
            );
        }
    }
}
