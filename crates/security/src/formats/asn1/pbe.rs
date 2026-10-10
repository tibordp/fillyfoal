//! Password-based encryption as used by PKCS#12 and PKCS#8: the PKCS#12
//! PBE algorithms (RFC 7292 appendix C) and PBES2 with PBKDF2 (RFC 8018).

use super::der;
use crate::codec::crypto::stream::Rc4;
use crate::codec::crypto::{
    self, Aes, BlockCipher, Des, Hash, Hmac, Key, Pbkdf2, Pkcs12Kdf, Rc2, Sha1, Sha256, Sha384,
    Sha512, TripleDes, bmp_password, cbc_decrypt, unpad_pkcs7,
};
use crate::codec::pipeline::{Decode, Step};
use crate::cx::Cx;
use crate::formats::util::datakit::feed_paced;

/// Bytes deciphered per unit of work (a multiple of every block size).
const PIECE: usize = 256;

/// CBC decryption of whole blocks, a piece at a time with a checkpoint
/// after each (the same result as [`cbc_decrypt`]).
async fn cbc_paced<C: BlockCipher + Sync>(cx: &Cx, c: &C, iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev = iv;
    for piece in data.chunks(PIECE) {
        out.extend_from_slice(&cbc_decrypt(c, prev, piece));
        // The next piece chains from this one's last ciphertext block.
        prev = piece
            .get(piece.len().saturating_sub(C::BLOCK)..)
            .unwrap_or_default();
        cx.checkpoint().await;
    }
    out
}

/// RC4, a piece at a time with a checkpoint after each.
async fn rc4_paced(cx: &Cx, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut rc4 = Rc4::new(&Key::new(key));
    let mut out = Vec::with_capacity(data.len());
    while let Ok(Step::More) = rc4.step(data, true, &mut out, PIECE, usize::MAX) {
        cx.checkpoint().await;
    }
    out
}

/// Key derivations beyond this many iterations are refused (hostile input
/// could otherwise make one expansion run for hours). The derivations run
/// in budgeted steps either way.
pub const MAX_ITERATIONS: u64 = 10_000_000;

/// The longest PBES2 key we derive (the ciphers take at most 32 bytes; the
/// length comes from the file and multiplies the work).
const MAX_KEY_LEN: usize = 64;

/// PBKDF2 with HMAC-`H`, run in budgeted steps.
async fn pbkdf2<H: Hash>(
    cx: &Cx,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    len: usize,
) -> Vec<u8> {
    let mut kdf = Pbkdf2::<H>::new(password, salt, iterations, len);
    crypto::run(cx, &mut kdf).await;
    kdf.finish()
}

/// The PKCS#12 key derivation with hash `H`, run in budgeted steps.
async fn pkcs12_kdf<H: Hash>(
    cx: &Cx,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    id: u8,
    len: usize,
) -> Vec<u8> {
    let mut kdf = Pkcs12Kdf::<H>::new(password, salt, iterations, id, len);
    crypto::run(cx, &mut kdf).await;
    kdf.finish()
}

/// Why decryption did not happen.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// An algorithm or parameter we do not implement.
    Unsupported(String),
    /// Decryption ran but the result is not valid (usually a wrong password).
    Wrong,
}

fn oid_of(content: &[u8]) -> Option<String> {
    let (tlv, c) = der::first(content)?;
    (tlv.tag == 6).then(|| der::oid(c)).flatten()
}

/// The algorithm OID and parameter bytes of an AlgorithmIdentifier's content.
fn algorithm(content: &[u8]) -> Option<(String, &[u8])> {
    let mut it = der::elements(content);
    let (tlv, oid) = it.next()?;
    if tlv.tag != 6 {
        return None;
    }
    let params = it.next().map_or(&[][..], |(_, c)| c);
    Some((der::oid(oid)?, params))
}

/// The name of an encryption algorithm, for display.
pub fn describe(alg: &[u8]) -> String {
    let Some((oid, params)) = algorithm(alg) else {
        return "unknown algorithm".into();
    };
    if oid == "1.2.840.113549.1.5.13" {
        let mut it = der::elements(params);
        let kdf = it.next().and_then(|(_, k)| algorithm(k));
        let enc = it.next().and_then(|(_, e)| oid_of(e));
        let prf = kdf
            .as_ref()
            .and_then(|(_, p)| {
                der::elements(p)
                    .find(|(t, _)| t.tag == 16)
                    .and_then(|(_, a)| oid_of(a))
            })
            .map_or("HMAC-SHA1", |o| prf_name(&o));
        return format!(
            "PBES2 (PBKDF2 {prf}, {})",
            enc.map_or("unknown cipher", |e| cipher_name(&e))
        );
    }
    pkcs12_pbe(&oid).map_or_else(
        || super::oids::name(&oid).map_or_else(|| format!("algorithm {oid}"), str::to_owned),
        |(name, ..)| name.to_owned(),
    )
}

fn prf_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.2.7" => "HMAC-SHA1",
        "1.2.840.113549.2.9" => "HMAC-SHA256",
        "1.2.840.113549.2.10" => "HMAC-SHA384",
        "1.2.840.113549.2.11" => "HMAC-SHA512",
        _ => "unknown PRF",
    }
}

fn cipher_name(oid: &str) -> &'static str {
    match oid {
        "2.16.840.1.101.3.4.1.2" => "AES-128-CBC",
        "2.16.840.1.101.3.4.1.22" => "AES-192-CBC",
        "2.16.840.1.101.3.4.1.42" => "AES-256-CBC",
        "1.2.840.113549.3.7" => "3DES-CBC",
        "1.3.14.3.2.7" => "DES-CBC",
        _ => "unknown cipher",
    }
}

#[derive(Clone, Copy)]
enum Pkcs12Cipher {
    Rc4,
    TripleDes,
    Rc2,
}

/// PKCS#12 PBE algorithms: name, cipher, key length (bytes), IV length.
fn pkcs12_pbe(oid: &str) -> Option<(&'static str, Pkcs12Cipher, usize, usize)> {
    Some(match oid {
        "1.2.840.113549.1.12.1.1" => ("pbeWithSHAAnd128BitRC4", Pkcs12Cipher::Rc4, 16, 0),
        "1.2.840.113549.1.12.1.2" => ("pbeWithSHAAnd40BitRC4", Pkcs12Cipher::Rc4, 5, 0),
        "1.2.840.113549.1.12.1.3" => (
            "pbeWithSHAAnd3-KeyTripleDES-CBC",
            Pkcs12Cipher::TripleDes,
            24,
            8,
        ),
        "1.2.840.113549.1.12.1.4" => (
            "pbeWithSHAAnd2-KeyTripleDES-CBC",
            Pkcs12Cipher::TripleDes,
            16,
            8,
        ),
        "1.2.840.113549.1.12.1.5" => ("pbeWithSHAAnd128BitRC2-CBC", Pkcs12Cipher::Rc2, 16, 8),
        "1.2.840.113549.1.12.1.6" => ("pbeWithSHAAnd40BitRC2-CBC", Pkcs12Cipher::Rc2, 5, 8),
        _ => return None,
    })
}

fn salt_and_iterations(params: &[u8]) -> Option<(&[u8], u64)> {
    let mut it = der::elements(params);
    let (_, salt) = it.next()?;
    let (_, iter) = it.next()?;
    Some((salt, u64::try_from(der::integer(iter)?).ok()?))
}

fn check_iterations(n: u64) -> Result<u32, Failure> {
    if n == 0 || n > MAX_ITERATIONS {
        return Err(Failure::Unsupported(format!(
            "{n} key-derivation iterations"
        )));
    }
    u32::try_from(n).map_err(|_| Failure::Unsupported("iteration count".into()))
}

/// A password candidate. PKCS#12 encodes passwords as BMPStrings; an
/// absent password (`null`) is no bytes at all, unlike the empty string.
#[derive(Clone, Copy, Debug)]
pub struct Password<'a> {
    pub text: &'a [u8],
    pub null: bool,
}

impl Password<'_> {
    /// The candidates tried before asking: absent, then empty.
    pub const FREE: [Password<'static>; 2] = [
        Password {
            text: b"",
            null: true,
        },
        Password {
            text: b"",
            null: false,
        },
    ];

    fn bmp(&self) -> Vec<u8> {
        if self.null {
            Vec::new()
        } else {
            bmp_password(self.text)
        }
    }
}

/// Decrypts `ciphertext` encrypted with algorithm `alg` (an
/// AlgorithmIdentifier's content) under `password`. The result is unpadded
/// and checked to start like DER. The key derivation runs in budgeted steps.
pub async fn decrypt(
    cx: &Cx,
    alg: &[u8],
    password: Password<'_>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Failure> {
    let (oid, params) =
        algorithm(alg).ok_or_else(|| Failure::Unsupported("malformed algorithm".into()))?;
    let plain = if let Some((_, cipher, key_len, iv_len)) = pkcs12_pbe(&oid) {
        let (salt, iterations) = salt_and_iterations(params)
            .ok_or_else(|| Failure::Unsupported("malformed PBE parameters".into()))?;
        let iterations = check_iterations(iterations)?;
        let pw = password.bmp();
        let key = pkcs12_kdf::<Sha1>(cx, &pw, salt, iterations, 1, key_len).await;
        let iv = pkcs12_kdf::<Sha1>(cx, &pw, salt, iterations, 2, iv_len).await;
        match cipher {
            Pkcs12Cipher::Rc4 => return Ok(rc4_paced(cx, &key, ciphertext).await),
            Pkcs12Cipher::TripleDes => {
                let c =
                    TripleDes::new(&key).ok_or_else(|| Failure::Unsupported("3DES key".into()))?;
                unpad(cbc_paced(cx, &c, &iv, ciphertext).await, 8)?
            }
            Pkcs12Cipher::Rc2 => {
                let c = Rc2::new(&key, key_len.saturating_mul(8));
                unpad(cbc_paced(cx, &c, &iv, ciphertext).await, 8)?
            }
        }
    } else if oid == "1.2.840.113549.1.5.13" {
        pbes2(cx, params, password.text, ciphertext).await?
    } else if oid == JKS_KEY_PROTECTOR {
        jks_key_protector(cx, password.text, ciphertext).await?
    } else if oid == JCE_PBE_MD5_3DES {
        jce_pbe_md5_3des(cx, params, password.text, ciphertext).await?
    } else {
        return Err(Failure::Unsupported(format!("encryption algorithm {oid}")));
    };
    if plain.first() != Some(&0x30) {
        return Err(Failure::Wrong);
    }
    Ok(plain)
}

/// Sun's JKS key protector (`sun.security.provider.KeyProtector`).
const JKS_KEY_PROTECTOR: &str = "1.3.6.1.4.1.42.2.17.1.1";
/// Sun JCE's PBEWithMD5AndTripleDES (`com.sun.crypto.provider.KeyProtector`).
const JCE_PBE_MD5_3DES: &str = "1.3.6.1.4.1.42.2.19.1";

/// A password as Java's UTF-16 code units, big-endian, without a
/// terminator (how the JKS key protector hashes it).
fn utf16_be(password: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(password)
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect()
}

/// The JKS key protector: a 20-byte salt, the key XORed with a SHA-1
/// keystream (each block the SHA-1 of the password and the previous block,
/// starting from the salt), and the SHA-1 of the password and the
/// plaintext as a check.
async fn jks_key_protector(cx: &Cx, password: &[u8], data: &[u8]) -> Result<Vec<u8>, Failure> {
    let len = data.len().checked_sub(40).ok_or(Failure::Wrong)?;
    let salt = data.get(..20).ok_or(Failure::Wrong)?;
    let encrypted = data
        .get(20..20usize.saturating_add(len))
        .ok_or(Failure::Wrong)?;
    let check = data
        .get(20usize.saturating_add(len)..)
        .ok_or(Failure::Wrong)?;
    let pw = utf16_be(password);
    let mut block = salt.to_vec();
    let mut plain = Vec::with_capacity(len);
    for (i, chunk) in encrypted.chunks(20).enumerate() {
        let mut h = Sha1::new();
        h.update(&pw);
        h.update(&block);
        block = h.finish();
        plain.extend(chunk.iter().zip(&block).map(|(c, k)| c ^ k));
        if i.is_multiple_of(64) {
            cx.checkpoint().await;
        }
    }
    let mut h = Sha1::new();
    h.update(&pw);
    h.update(&plain);
    if h.finish() != check {
        return Err(Failure::Wrong);
    }
    Ok(plain)
}

/// Sun JCE's PBEWithMD5AndTripleDES: each salt half (the first reversed
/// when both are equal) hashed with the password `iterations` times by MD5
/// gives 16 bytes of the 3DES key and IV.
async fn jce_pbe_md5_3des(
    cx: &Cx,
    params: &[u8],
    password: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Failure> {
    let (salt, iterations) = salt_and_iterations(params)
        .ok_or_else(|| Failure::Unsupported("malformed PBE parameters".into()))?;
    let iterations = check_iterations(iterations)?;
    let mut salt = salt.to_vec();
    if salt.len() != 8 {
        return Err(Failure::Unsupported(format!("{}-byte salt", salt.len())));
    }
    if salt.get(..4) == salt.get(4..)
        && let Some(first) = salt.get_mut(..4)
    {
        first.reverse();
    }
    // Java hands the password over as its chars' low seven bits.
    let pw: Vec<u8> = String::from_utf8_lossy(password)
        .chars()
        .map(|c| u8::try_from(u32::from(c) & 0x7f).unwrap_or(0))
        .collect();
    let mut derived = Vec::with_capacity(32);
    for half in salt.chunks(4) {
        let mut state = half.to_vec();
        for i in 0..iterations {
            let mut h = crypto::Md5::new();
            h.update(&state);
            h.update(&pw);
            state = h.finish();
            if i.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
        }
        derived.extend(state);
    }
    let (key, iv) = derived.split_at(24);
    let c = TripleDes::new(key).ok_or_else(|| Failure::Unsupported("3DES key".into()))?;
    unpad(cbc_paced(cx, &c, iv, ciphertext).await, 8)
}

fn unpad(mut data: Vec<u8>, block: usize) -> Result<Vec<u8>, Failure> {
    let len = unpad_pkcs7(&data, block).ok_or(Failure::Wrong)?.len();
    data.truncate(len);
    Ok(data)
}

async fn pbes2(
    cx: &Cx,
    params: &[u8],
    password: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Failure> {
    let bad = || Failure::Unsupported("malformed PBES2 parameters".into());
    let mut it = der::elements(params);
    let (_, kdf) = it.next().ok_or_else(bad)?;
    let (_, enc) = it.next().ok_or_else(bad)?;
    let (kdf_oid, kdf_params) = algorithm(kdf).ok_or_else(bad)?;
    if kdf_oid != "1.2.840.113549.1.5.12" {
        return Err(Failure::Unsupported(format!("key derivation {kdf_oid}")));
    }
    let mut k = der::elements(kdf_params);
    let (_, salt) = k.next().ok_or_else(bad)?;
    let (_, iter) = k.next().ok_or_else(bad)?;
    let iterations = check_iterations(
        der::integer(iter)
            .and_then(|i| u64::try_from(i).ok())
            .ok_or_else(bad)?,
    )?;
    let mut key_len = None;
    let mut prf = "1.2.840.113549.2.7".to_owned();
    for (tlv, c) in k {
        match tlv.tag {
            2 => key_len = der::integer(c).and_then(|i| usize::try_from(i).ok()),
            16 => prf = oid_of(c).unwrap_or(prf),
            _ => {}
        }
    }
    let (enc_oid, iv) = algorithm(enc).ok_or_else(bad)?;
    let len = match enc_oid.as_str() {
        "2.16.840.1.101.3.4.1.2" => 16,
        "2.16.840.1.101.3.4.1.22" => 24,
        "2.16.840.1.101.3.4.1.42" => 32,
        "1.2.840.113549.3.7" => 24,
        "1.3.14.3.2.7" => 8,
        other => return Err(Failure::Unsupported(format!("cipher {other}"))),
    };
    let len = key_len.unwrap_or(len);
    if len > MAX_KEY_LEN {
        return Err(Failure::Unsupported(format!("{len}-byte key")));
    }
    let key = match prf.as_str() {
        "1.2.840.113549.2.7" => pbkdf2::<Sha1>(cx, password, salt, iterations, len).await,
        "1.2.840.113549.2.9" => pbkdf2::<Sha256>(cx, password, salt, iterations, len).await,
        "1.2.840.113549.2.10" => pbkdf2::<Sha384>(cx, password, salt, iterations, len).await,
        "1.2.840.113549.2.11" => pbkdf2::<Sha512>(cx, password, salt, iterations, len).await,
        other => return Err(Failure::Unsupported(format!("PRF {other}"))),
    };
    match enc_oid.as_str() {
        "1.2.840.113549.3.7" => {
            let c = TripleDes::new(&key).ok_or_else(bad)?;
            unpad(cbc_paced(cx, &c, iv, ciphertext).await, 8)
        }
        "1.3.14.3.2.7" => {
            let k: [u8; 8] = key
                .get(..8)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(bad)?;
            unpad(cbc_paced(cx, &Des::new(&k), iv, ciphertext).await, 8)
        }
        _ => {
            let c = Aes::new(&key).ok_or_else(bad)?;
            unpad(cbc_paced(cx, &c, iv, ciphertext).await, 16)
        }
    }
}

/// Checks a PKCS#12 MAC (`mac_data` is MacData's content) over
/// `auth_safe` (the bytes of the authenticated safe) with `password`.
pub async fn verify_mac(
    cx: &Cx,
    mac_data: &[u8],
    password: Password<'_>,
    auth_safe: &[u8],
) -> Option<bool> {
    let mut it = der::elements(mac_data);
    let (_, digest_info) = it.next()?;
    let (_, salt) = it.next()?;
    let iterations = it.next().and_then(|(_, i)| der::integer(i)).unwrap_or(1);
    let iterations = check_iterations(u64::try_from(iterations).ok()?).ok()?;
    let mut d = der::elements(digest_info);
    let (_, alg) = d.next()?;
    let (_, digest) = d.next()?;
    let (oid, _) = algorithm(alg)?;
    let pw = password.bmp();
    let mac = match oid.as_str() {
        "1.3.14.3.2.26" => mac::<Sha1>(cx, &pw, salt, iterations, auth_safe).await,
        "2.16.840.1.101.3.4.2.1" => mac::<Sha256>(cx, &pw, salt, iterations, auth_safe).await,
        "2.16.840.1.101.3.4.2.2" => mac::<Sha384>(cx, &pw, salt, iterations, auth_safe).await,
        "2.16.840.1.101.3.4.2.3" => mac::<Sha512>(cx, &pw, salt, iterations, auth_safe).await,
        _ => return None,
    };
    Some(mac == digest)
}

async fn mac<H: Hash>(
    cx: &Cx,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    data: &[u8],
) -> Vec<u8> {
    let key = pkcs12_kdf::<H>(cx, password, salt, iterations, 3, H::OUT).await;
    let mut h = Hmac::<H>::new(&key);
    feed_paced(cx, data, |piece| h.update(piece)).await;
    h.finish()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn describes() {
        // AlgorithmIdentifier content for pbeWithSHAAnd3-KeyTripleDES-CBC.
        let alg = [
            0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30, 0x00,
        ];
        assert_eq!(super::describe(&alg), "pbeWithSHAAnd3-KeyTripleDES-CBC");
    }
}
