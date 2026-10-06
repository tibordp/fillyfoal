//! The PDF standard security handler (ISO 32000-2, 7.6.4): revisions 2–4
//! (RC4 and AES-128 with MD5-derived keys) and 5–6 (AES-256).
//!
//! The empty user password is tried first, without asking; a real password
//! is requested only when encrypted content is needed.

use std::sync::Arc;

use super::syntax::{Item, Obj};
use crate::codec::Codec;
use crate::codec::crypto::{Aes, Hash, Key, Md5, Sha256, Sha384, Sha512, rc4};
use crate::cx::Cx;
use crate::span::Span;

/// The padding string of algorithm 2.
const PAD: [u8; 32] = [
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08, 0x2e, 0x2e, 0x00, 0xb6,
    0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Identity,
    Rc4,
    AesV2,
    AesV3,
}

/// A parsed `/Encrypt` dictionary.
#[derive(Debug)]
pub struct Security {
    revision: i64,
    key_len: usize,
    o: Vec<u8>,
    u: Vec<u8>,
    ue: Vec<u8>,
    p: i32,
    id0: Vec<u8>,
    pub encrypt_metadata: bool,
    pub streams: Method,
    pub strings: Method,
    /// Where the password applies (for the secret request).
    pub realm: Span,
}

fn string(item: &Item, key: &str) -> Vec<u8> {
    match item.get(key).map(|i| &i.obj) {
        Some(Obj::Str { bytes, .. }) => bytes.clone(),
        _ => Vec::new(),
    }
}

/// The crypt filter method named by `/StmF` or `/StrF`.
fn method(dict: &Item, which: &str, v: i64) -> Method {
    if v < 4 {
        return Method::Rc4;
    }
    let Some(name) = dict.get(which).and_then(Item::name) else {
        return Method::Identity;
    };
    if name == "Identity" {
        return Method::Identity;
    }
    let cfm = dict
        .get("CF")
        .and_then(|cf| cf.get(name))
        .and_then(|f| f.get("CFM"))
        .and_then(Item::name);
    match cfm {
        Some("AESV2") => Method::AesV2,
        Some("AESV3") => Method::AesV3,
        Some("None") => Method::Identity,
        _ => Method::Rc4,
    }
}

impl Security {
    /// Parses `/Encrypt`; `Err` names what is unsupported.
    pub fn parse(dict: &Item, id0: Vec<u8>, realm: Span) -> Result<Self, String> {
        let filter = dict.get("Filter").and_then(Item::name).unwrap_or("Standard");
        if filter != "Standard" {
            return Err(format!("security handler /{filter}"));
        }
        let v = dict.get("V").and_then(Item::int).unwrap_or(0);
        let revision = dict.get("R").and_then(Item::int).unwrap_or(0);
        if !(2..=6).contains(&revision) {
            return Err(format!("standard security handler revision {revision}"));
        }
        let bits = dict.get("Length").and_then(Item::int).unwrap_or(40);
        let key_len = match revision {
            2 => 5,
            5 | 6 => 32,
            _ => usize::try_from(bits / 8).unwrap_or(5).clamp(5, 16),
        };
        let p = dict.get("P").and_then(Item::int).unwrap_or(0);
        let p = i32::try_from(p).unwrap_or_else(|_| i32::from_le_bytes(u32::try_from(p & 0xffff_ffff).unwrap_or(0).to_le_bytes()));
        Ok(Security {
            revision,
            key_len,
            o: string(dict, "O"),
            u: string(dict, "U"),
            ue: string(dict, "UE"),
            p,
            id0,
            encrypt_metadata: !matches!(dict.get("EncryptMetadata").map(|i| &i.obj), Some(Obj::Bool(false))),
            streams: method(dict, "StmF", v),
            strings: method(dict, "StrF", v),
            realm,
        })
    }

    /// The file key for user password `password`, if it is the right one.
    pub fn file_key(&self, password: &[u8]) -> Option<Vec<u8>> {
        if self.revision >= 5 {
            return self.file_key_aes256(password);
        }
        // Algorithm 2.
        let mut padded: Vec<u8> = password.iter().copied().take(32).collect();
        padded.extend(PAD.iter().take(32usize.saturating_sub(padded.len())));
        let mut h = Md5::new();
        h.update(&padded);
        h.update(self.o.get(..32).unwrap_or(&self.o));
        h.update(&self.p.to_le_bytes());
        h.update(&self.id0);
        if self.revision >= 4 && !self.encrypt_metadata {
            h.update(&[0xff; 4]);
        }
        let mut key = h.finish();
        if self.revision >= 3 {
            for _ in 0..50 {
                key = Md5::digest(key.get(..self.key_len).unwrap_or(&key));
            }
        }
        key.truncate(self.key_len);
        // Algorithms 4 and 5: check /U.
        let ok = if self.revision == 2 {
            rc4(&key, &PAD) == self.u.get(..32).unwrap_or(&self.u)
        } else {
            let mut h = Md5::new();
            h.update(&PAD);
            h.update(&self.id0);
            let mut x = rc4(&key, &h.finish());
            for i in 1..=19u8 {
                let k: Vec<u8> = key.iter().map(|b| b ^ i).collect();
                x = rc4(&k, &x);
            }
            self.u.get(..16) == Some(x.as_slice())
        };
        ok.then_some(key)
    }

    fn file_key_aes256(&self, password: &[u8]) -> Option<Vec<u8>> {
        let password = password.get(..127).unwrap_or(password);
        let (hash, rest) = (self.u.get(..32)?, self.u.get(32..48)?);
        let (validation, key_salt) = rest.split_at(8);
        if self.hash_r6(password, validation, &[]) != hash {
            return None;
        }
        let intermediate = self.hash_r6(password, key_salt, &[]);
        let aes = Aes::new(&intermediate)?;
        // /UE is the file key, AES-256-CBC-encrypted with a zero IV and no
        // padding.
        let mut prev = [0u8; 16];
        let mut key = Vec::with_capacity(32);
        for chunk in self.ue.get(..32)?.chunks(16) {
            let mut block: [u8; 16] = chunk.try_into().ok()?;
            let saved = block;
            aes.decrypt_block(&mut block);
            key.extend(block.iter().zip(prev).map(|(a, b)| a ^ b));
            prev = saved;
        }
        Some(key)
    }

    /// Algorithm 2.A's hash: SHA-256 (revision 5), or algorithm 2.B's
    /// iterated hash (revision 6).
    fn hash_r6(&self, password: &[u8], salt: &[u8], udata: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(password);
        h.update(salt);
        h.update(udata);
        let mut k = h.finish();
        if self.revision == 5 {
            return k;
        }
        let mut round = 0u32;
        loop {
            let mut k1 = Vec::new();
            for _ in 0..64 {
                k1.extend_from_slice(password);
                k1.extend_from_slice(&k);
                k1.extend_from_slice(udata);
            }
            let Some(aes) = k.get(..16).and_then(Aes::new) else {
                return k;
            };
            // AES-128-CBC encryption with IV k[16..32], no padding.
            let mut prev: [u8; 16] = k.get(16..32).and_then(|s| s.try_into().ok()).unwrap_or([0; 16]);
            let mut e = Vec::with_capacity(k1.len());
            for chunk in k1.chunks(16) {
                let mut block: [u8; 16] = chunk.try_into().unwrap_or([0; 16]);
                for (b, p) in block.iter_mut().zip(prev) {
                    *b ^= p;
                }
                aes.encrypt_block(&mut block);
                e.extend_from_slice(&block);
                prev = block;
            }
            let sum = e.iter().take(16).fold(0u32, |a, &b| a.wrapping_add(u32::from(b)));
            k = match sum % 3 {
                0 => Sha256::digest(&e),
                1 => Sha384::digest(&e),
                _ => Sha512::digest(&e),
            };
            let last = u32::from(e.last().copied().unwrap_or(0));
            round = round.saturating_add(1);
            if round >= 64 && last <= round.saturating_sub(32) {
                break;
            }
            if round > 1000 {
                break;
            }
        }
        k.truncate(32);
        k
    }

    /// The key for object `num` `generation` (algorithm 1).
    fn object_key(&self, file_key: &[u8], num: u32, generation: u16, method: Method) -> Vec<u8> {
        if method == Method::AesV3 {
            return file_key.to_vec();
        }
        let mut h = Md5::new();
        h.update(file_key);
        h.update(num.to_le_bytes().get(..3).unwrap_or_default());
        h.update(&generation.to_le_bytes());
        if method == Method::AesV2 {
            h.update(b"sAlT");
        }
        let mut key = h.finish();
        key.truncate(file_key.len().saturating_add(5).min(16));
        key
    }

    /// The codec that decrypts a stream of object `id`.
    pub fn stream_codec(&self, file_key: &[u8], (num, generation): (u32, u16)) -> Option<Codec> {
        let key = Key::new(self.object_key(file_key, num, generation, self.streams));
        match self.streams {
            Method::Identity => None,
            Method::Rc4 => Some(Codec::Rc4(key)),
            Method::AesV2 | Method::AesV3 => Some(Codec::AesCbc(key)),
        }
    }

    /// Decrypts a string of object `id`.
    pub fn decrypt_string(&self, file_key: &[u8], (num, generation): (u32, u16), data: &[u8]) -> Vec<u8> {
        let key = self.object_key(file_key, num, generation, self.strings);
        match self.strings {
            Method::Identity => data.to_vec(),
            Method::Rc4 => rc4(&key, data),
            Method::AesV2 | Method::AesV3 => crate::codec::crypto::aes_cbc_iv_prefixed(&key, data).unwrap_or_default(),
        }
    }
}

/// The file key: the empty password if it works, otherwise (when `ask`)
/// the password from the host. Both outcomes are cached per document, so
/// expensive key derivations (revision 6) run once.
pub async fn file_key(cx: &Cx, security: &Arc<Security>, ask: bool) -> Option<Arc<Vec<u8>>> {
    const FREE: &str = "pdf-free-key";
    const ASKED: &str = "pdf-asked-key";
    let free = match cx.cached::<Option<Arc<Vec<u8>>>>(security.realm, FREE) {
        Some(found) => (*found).clone(),
        None => {
            let key = security.file_key(b"").map(Arc::new);
            cx.cache(security.realm, FREE, Arc::new(key.clone()));
            key
        }
    };
    if free.is_some() || !ask {
        return free.or_else(|| cx.cached::<Option<Arc<Vec<u8>>>>(security.realm, ASKED).and_then(|k| (*k).clone()));
    }
    if let Some(found) = cx.cached::<Option<Arc<Vec<u8>>>>(security.realm, ASKED) {
        return (*found).clone();
    }
    let mut key = None;
    for attempt in 0..crate::secret::MAX_ATTEMPTS {
        let request = crate::secret::SecretRequest::password(security.realm, "Password to open the PDF", attempt);
        let Some(secret) = cx.secret(request).await else { break };
        if let Some(k) = security.file_key(secret.expose()) {
            key = Some(Arc::new(k));
            break;
        }
    }
    cx.cache(security.realm, ASKED, Arc::new(key.clone()));
    key
}
