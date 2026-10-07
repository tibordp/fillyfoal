//! Cryptographic primitives for reading encrypted files the user has the
//! password for: hashes, HMAC, PBKDF2, the PKCS#12 key derivation, and the
//! ciphers those formats use. In-house and dependency-free like the other
//! codecs; correct, but not hardened against side channels (they decrypt
//! local files for display, not secrets in transit).

pub mod argon2;
pub mod bcrypt;
pub mod blake2b;
pub mod chacha20;
pub mod cipher;
pub mod gcm;
pub mod hash;
pub mod mpq;
pub mod poly1305;
pub mod stream;
pub mod twofish;

pub use cipher::{
    Aes, BlockCipher, Des, Rc2, TripleDes, aes_ctr_le, cbc_decrypt, rc4, unpad_pkcs7,
};
pub use hash::{Hash, Hmac, Md5, Sha1, Sha256, Sha384, Sha512, hmac, pbkdf2};
pub use stream::{Key, ZipCryptoKeys, aes_cbc_iv_prefixed};

/// The PKCS#12 key derivation (RFC 7292 appendix B) with hash `H`. `id` is
/// 1 for keys, 2 for IVs and 3 for MAC keys; `password` is the raw
/// BMPString (UTF-16BE with a terminating NUL), see [`bmp_password`].
pub fn pkcs12_kdf<H: Hash>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    id: u8,
    len: usize,
) -> Vec<u8> {
    let v = H::BLOCK;
    let fill = |src: &[u8]| -> Vec<u8> {
        if src.is_empty() {
            return Vec::new();
        }
        let n = v.saturating_mul(src.len().div_ceil(v));
        src.iter().copied().cycle().take(n).collect()
    };
    let mut i_block = fill(salt);
    i_block.extend(fill(password));
    let d = vec![id; v];
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let mut h = H::new();
        h.update(&d);
        h.update(&i_block);
        let mut a = h.finish();
        for _ in 1..iterations {
            a = H::digest(&a);
        }
        out.extend_from_slice(&a);
        if out.len() >= len {
            break;
        }
        // I_j = (I_j + B + 1) mod 2^(8v) for each v-byte block of I.
        let b: Vec<u8> = a.iter().copied().cycle().take(v).collect();
        for chunk in i_block.chunks_mut(v) {
            let mut carry = 1u16;
            for (x, y) in chunk.iter_mut().rev().zip(b.iter().rev()) {
                let sum = u16::from(*x)
                    .wrapping_add(u16::from(*y))
                    .wrapping_add(carry);
                *x = sum.to_le_bytes()[0];
                carry = sum >> 8;
            }
        }
    }
    out.truncate(len);
    out
}

/// A password as a PKCS#12 BMPString: UTF-16BE plus a 2-byte NUL (empty
/// for an absent password).
pub fn bmp_password(password: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(password);
    let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    out.extend_from_slice(&[0, 0]);
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

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hashes() {
        assert_eq!(hex(&Md5::digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex(&Md5::digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(&Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&Sha384::digest(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex(&Sha512::digest(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        // Multi-block input exercises buffering and padding.
        let long = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&Sha1::digest(&long)),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
        assert_eq!(
            hex(&Sha256::digest(&long)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        let mut h = Sha256::new();
        for chunk in long.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(hex(&h.finish()), hex(&Sha256::digest(&long)));
    }

    #[test]
    fn hmac_and_pbkdf2() {
        // RFC 4231 test case 2.
        assert_eq!(
            hex(&hmac::<Sha256>(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // RFC 6070.
        assert_eq!(
            hex(&pbkdf2::<Sha1>(b"password", b"salt", 2, 20)),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        );
        assert_eq!(
            hex(&pbkdf2::<Sha1>(b"password", b"salt", 4096, 20)),
            "4b007901b765489abead49d926f721d065a429c1"
        );
    }

    #[test]
    fn aes_vectors() {
        // FIPS 197 appendix C.
        let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        for (key, ct) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "dda97ca4864cdfe06eaf70a0ec0d7191",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            let aes = Aes::new(&unhex(key)).unwrap();
            let mut b = pt;
            aes.encrypt_block(&mut b);
            assert_eq!(hex(&b), ct);
            aes.decrypt_block(&mut b);
            assert_eq!(b, pt);
        }
    }

    #[test]
    fn rc4_des_rc2_vectors() {
        assert_eq!(hex(&rc4(b"Key", b"Plaintext")), "bbf316e8d940af0ad3");
        // DES: FIPS 81 / classic vector.
        let des = Des::new(&unhex("133457799bbcdff1").try_into().unwrap());
        let mut b = unhex("85e813540f0ab405");
        des.decrypt(&mut b);
        assert_eq!(hex(&b), "0123456789abcdef");
        // 3DES with K1 = K2 = K3 is single DES.
        let tdes =
            TripleDes::new(&unhex("133457799bbcdff1133457799bbcdff1133457799bbcdff1")).unwrap();
        let mut b = unhex("85e813540f0ab405");
        tdes.decrypt(&mut b);
        assert_eq!(hex(&b), "0123456789abcdef");
        // RFC 2268: key 0x00 x8, effective 63 bits.
        let rc2 = Rc2::new(&unhex("0000000000000000"), 63);
        let mut b = unhex("ebb773f993278eff");
        rc2.decrypt(&mut b);
        assert_eq!(hex(&b), "0000000000000000");
        let rc2 = Rc2::new(&unhex("88bca90e90875a7f0f79c384627bafb2"), 128);
        let mut b = unhex("2269552ab0f85ca6");
        rc2.decrypt(&mut b);
        assert_eq!(hex(&b), "0000000000000000");
    }

    #[test]
    fn pkcs12_kdf_vector() {
        // OpenSSL test vector: password "smeg", SHA-1, 1 iteration, ID 1.
        let key = pkcs12_kdf::<Sha1>(&bmp_password(b"smeg"), &unhex("0a58cf64530d823f"), 1, 1, 24);
        assert_eq!(
            hex(&key),
            "8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3"
        );
    }
}
