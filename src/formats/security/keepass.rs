//! KeePass databases: KDBX 3.1 and 4.x (KeePass 2, KeePassXC, KeeWeb, ...)
//! and KDB (KeePass 1.x, KeePassX 0.4).
//!
//! The outer header is shown without a password. Expanding the payload asks
//! for the master password (key files and Windows user accounts are not
//! supported) and then shows the whole chain: the KDF (AES-KDF or Argon2,
//! run in budgeted steps), the integrity layer (KDBX 4 HMAC block stream,
//! KDBX 3 hashed block stream, KDB contents hash), decryption (AES-256,
//! ChaCha20, Twofish), gzip, the KDBX 4 inner header with its attachments,
//! the XML document and a summary of groups and entries.
//!
//! Protected values (passwords, protected custom fields) are never decoded:
//! in KDBX they stay encrypted with the inner random stream, and the KDB
//! password field is shown only as "protected".
//!
//! Layouts follow KeePassLib (`KdbxFile`), KeePassXC and pykeepass as
//! remembered; KDBX 3.1/4.0 are checked against files written by pykeepass.
//! The KDB 1.x layout (field types, packed times) is from memory of
//! KeePass 1.x `PwManager` and checked only against our own generator.

use std::collections::HashMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::codec::crypto;
use crate::codec::crypto::argon2::{self, Argon2};
use crate::codec::crypto::chacha20::chacha20;
use crate::codec::crypto::twofish::Twofish;
use crate::codec::crypto::{Aes, Hash, Hmac, Sha256, Sha512, cbc_decrypt, unpad_pkcs7};
use crate::codec::{Codec, decode_span, read_all};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::record;
use crate::secret::{MAX_ATTEMPTS, SecretRequest};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Radix, Value, decode_flags, flag, lookup};

const LE: Endian = Endian::Little;

declare_format!(pub KDBX = "kdbx", "KeePass 2 database", ["kdbx"], "application/x-keepass2",
    Probe::Magic(&[(0, b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5")]), kdbx);
declare_format!(pub KDB = "kdb", "KeePass 1 database", ["kdb"], "application/x-keepass",
    Probe::Magic(&[(0, b"\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5")]), kdb);

// ---------------------------------------------------------------------------
// Key derivation

/// Work units charged per AES-KDF round batch and per Argon2 block: the
/// session's work limit doubles as a cap on how long a KDF may run, so a
/// corrupt round count is refused up front instead of spinning.
const AES_ROUNDS_PER_UNIT: u64 = 8;

#[derive(Clone, Debug)]
enum Kdf {
    Aes {
        seed: Vec<u8>,
        rounds: u64,
    },
    Argon2 {
        params: argon2::Params,
        salt: Vec<u8>,
        secret: Vec<u8>,
        associated: Vec<u8>,
    },
}

impl Kdf {
    fn units(&self) -> u64 {
        match self {
            Kdf::Aes { rounds, .. } => rounds / AES_ROUNDS_PER_UNIT,
            Kdf::Argon2 { params, .. } => params.cost(),
        }
    }

    fn describe(&self) -> String {
        match self {
            Kdf::Aes { rounds, .. } => format!("AES-KDF, {rounds} rounds"),
            Kdf::Argon2 { params, .. } => format!(
                "{}, {}, {}, {}",
                match params.variant {
                    argon2::Variant::D => "Argon2d",
                    argon2::Variant::I => "Argon2i",
                    argon2::Variant::Id => "Argon2id",
                },
                plural(params.iterations.into(), "pass", "passes"),
                kib(params.memory_kib.into()),
                plural(params.lanes.into(), "lane", "lanes")
            ),
        }
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn kib(n: u64) -> String {
    if n >= 1024 && n.is_multiple_of(1024) {
        format!("{} MiB", n / 1024)
    } else {
        format!("{n} KiB")
    }
}

/// Runs the KDF on `key` in budgeted steps; the 32-byte transformed key.
async fn derive(cx: &Cx, kdf: &Kdf, key: &[u8], at: Span) -> Result<Vec<u8>> {
    let limit = cx.limits().max_work.saturating_mul(2) / 5;
    if kdf.units() > limit {
        return Err(Diagnostic::limit(format!(
            "key derivation too expensive ({}) for the work limit",
            kdf.describe()
        ))
        .at(at));
    }
    match kdf {
        Kdf::Aes { seed, rounds } => {
            let aes = Aes::new(seed)
                .filter(|_| seed.len() == 32)
                .ok_or_else(|| Diagnostic::malformed("AES-KDF seed is not 32 bytes").at(at))?;
            let mut a = [0u8; 16];
            let mut b = [0u8; 16];
            a.copy_from_slice(key.get(..16).unwrap_or(&[0; 16]));
            b.copy_from_slice(key.get(16..32).unwrap_or(&[0; 16]));
            let mut left = *rounds;
            while left > 0 {
                let n = left.min(AES_ROUNDS_PER_UNIT);
                for _ in 0..n {
                    aes.encrypt_block(&mut a);
                    aes.encrypt_block(&mut b);
                }
                left = left.saturating_sub(n);
                cx.checkpoint().await;
            }
            let mut h = Sha256::new();
            h.update(&a);
            h.update(&b);
            Ok(h.finish())
        }
        Kdf::Argon2 {
            params,
            salt,
            secret,
            associated,
        } => {
            let limits = cx.limits();
            if params.blocks().saturating_mul(1024) > limits.max_derived {
                return Err(Diagnostic::limit(format!(
                    "Argon2 memory ({}) exceeds the memory limit",
                    kib(params.blocks())
                ))
                .at(at));
            }
            let mut state = Argon2::new(params.clone(), key, salt, secret, associated)
                .ok_or_else(|| Diagnostic::malformed("unusable Argon2 parameters").at(at))?;
            crypto::run(cx, &mut state).await;
            Ok(state.finish())
        }
    }
}

/// Asks for password number `attempt` and derives the transformed key from
/// it; `None` if the host declined.
async fn attempt_key(
    cx: &Cx,
    realm: Span,
    prompt: &str,
    attempt: u32,
    composite: impl Fn(&[u8]) -> Vec<u8>,
    kdf: &Kdf,
) -> Result<Option<Vec<u8>>> {
    let Some(secret) = cx
        .secret(SecretRequest::password(realm, prompt, attempt))
        .await
    else {
        return Ok(None);
    };
    Ok(Some(
        derive(cx, kdf, &composite(secret.expose()), realm).await?,
    ))
}

/// Asks for the password until `check` (cheap: a few blocks) accepts the
/// key derived from it. `None` if the host declined or every attempt
/// failed.
async fn unlock<T>(
    cx: &Cx,
    realm: Span,
    prompt: &str,
    composite: impl Fn(&[u8]) -> Vec<u8>,
    kdf: &Kdf,
    check: impl Fn(&[u8]) -> Option<T>,
) -> Result<Option<T>> {
    for attempt in 0..MAX_ATTEMPTS {
        let Some(transformed) = attempt_key(cx, realm, prompt, attempt, &composite, kdf).await?
        else {
            return Ok(None);
        };
        if let Some(keys) = check(&transformed) {
            return Ok(Some(keys));
        }
    }
    Ok(None)
}

/// Bytes decrypted or hashed per unit of work.
const CRYPT_UNIT: usize = 256;
/// Bytes decrypted or hashed between checkpoints (whole cipher blocks and
/// ChaCha20 blocks).
const CRYPT_CHUNK: usize = 16 << 10;

async fn charge(cx: &Cx, bytes: usize) {
    for _ in 0..bytes.div_ceil(CRYPT_UNIT) {
        cx.checkpoint().await;
    }
}

/// Feeds `data` to `update` a chunk at a time, charging for it.
async fn feed(cx: &Cx, data: &[u8], mut update: impl FnMut(&[u8])) {
    for chunk in data.chunks(CRYPT_CHUNK) {
        update(chunk);
        charge(cx, chunk.len()).await;
    }
}

/// [`sha256`] of `data`, in budgeted steps.
async fn sha256_stepped(cx: &Cx, data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    feed(cx, data, |c| h.update(c)).await;
    h.finish()
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

fn sha512(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cipher {
    Aes,
    ChaCha20,
    Twofish,
}

impl Cipher {
    fn name(self) -> &'static str {
        match self {
            Cipher::Aes => "AES-256-CBC",
            Cipher::ChaCha20 => "ChaCha20",
            Cipher::Twofish => "Twofish-CBC",
        }
    }

    /// Decrypts the first bytes of `data` (whole blocks), for checking a
    /// password without decrypting everything.
    fn decrypt_head(self, key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Cipher::Aes => Some(cbc_decrypt(&Aes::new(key)?, iv, data)),
            Cipher::Twofish => Some(cbc_decrypt(&Twofish::new(key)?, iv, data)),
            Cipher::ChaCha20 => chacha20(key, iv, 0, data),
        }
    }

    /// Decrypts `data` (and removes CBC padding); `None` for a bad key size
    /// or padding. In budgeted steps: CBC a chunk at a time, carrying the
    /// IV (the chunk's last cipher block); ChaCha20 carrying the block
    /// counter.
    async fn decrypt_stepped(self, cx: &Cx, key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        enum Keyed {
            Aes(Aes),
            Twofish(Twofish),
            ChaCha20,
        }
        /// ChaCha20 blocks in a chunk.
        const CHACHA_BLOCKS: u32 = 1 << 8;
        const _: () = assert!(CRYPT_CHUNK == 64 << 8);
        let keyed = match self {
            Cipher::Aes => Keyed::Aes(Aes::new(key)?),
            Cipher::Twofish => Keyed::Twofish(Twofish::new(key)?),
            Cipher::ChaCha20 => Keyed::ChaCha20,
        };
        let mut out = Vec::with_capacity(data.len());
        let mut prev = iv;
        let mut counter = 0u32;
        for chunk in data.chunks(CRYPT_CHUNK) {
            match &keyed {
                Keyed::Aes(c) => out.extend(cbc_decrypt(c, prev, chunk)),
                Keyed::Twofish(c) => out.extend(cbc_decrypt(c, prev, chunk)),
                Keyed::ChaCha20 => out.extend(chacha20(key, iv, counter, chunk)?),
            }
            prev = chunk
                .get(chunk.len().saturating_sub(16)..)
                .unwrap_or_default();
            counter = counter.wrapping_add(CHACHA_BLOCKS);
            charge(cx, chunk.len()).await;
        }
        match keyed {
            Keyed::ChaCha20 => {
                // Wrong key or nonce sizes fail even with no data.
                chacha20(key, iv, 0, &[])?;
                Some(out)
            }
            _ => {
                let n = unpad_pkcs7(&out, 16)?.len();
                out.truncate(n);
                Some(out)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// KDBX outer header

const KDBX_FIELDS: EnumTable = &[
    (0, "End of header"),
    (1, "Comment"),
    (2, "Cipher ID"),
    (3, "Compression flags"),
    (4, "Master seed"),
    (5, "Transform seed"),
    (6, "Transform rounds"),
    (7, "Encryption IV"),
    (8, "Protected stream key"),
    (9, "Stream start bytes"),
    (10, "Inner random stream ID"),
    (11, "KDF parameters"),
    (12, "Public custom data"),
];

const KDBX_CIPHERS: &[(&str, Cipher)] = &[
    ("31c1f2e6bf714350be5805216afc5aff", Cipher::Aes),
    ("d6038a2b8b6f4cb5a524339a31dbb59a", Cipher::ChaCha20),
    ("ad68f29f576f4bb9a36ad47af965346c", Cipher::Twofish),
];

const KDFS: &[(&str, &str)] = &[
    ("c9d9f39a628a4460bf740d08c18a4fea", "AES-KDF"),
    ("ef636ddf8c29444b91f7a9a403e30a0c", "Argon2d"),
    ("9e298b1956db4773b23dfc3ec6f0a1e6", "Argon2id"),
];

const STREAMS: EnumTable = &[
    (0, "none"),
    (1, "ArcFour variant"),
    (2, "Salsa20"),
    (3, "ChaCha20"),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What the payload needs from the outer header.
#[derive(Clone, Debug, Default)]
struct Header {
    major: u16,
    cipher: Option<Cipher>,
    compressed: bool,
    master_seed: Vec<u8>,
    iv: Vec<u8>,
    stream_start: Vec<u8>,
    kdf: Option<Kdf>,
    /// Header length (offset of the end of the "End of header" field).
    end: u64,
    /// Where the payload starts (after the v4 hash and HMAC).
    payload: u64,
}

/// One item of a KDBX 4 VariantDictionary.
struct VdItem {
    key: String,
    kind: u8,
    value: Vec<u8>,
    /// Offsets of the item within the dictionary.
    start: usize,
    len: usize,
}

/// Parses a VariantDictionary: version, then typed items up to a 0 type.
fn variant_dict(data: &[u8]) -> std::result::Result<(u16, Vec<VdItem>), String> {
    let version = u16_le(data, 0).ok_or("truncated version")?;
    if version >> 8 != 1 {
        return Err(format!("unsupported version {version:#06x}"));
    }
    let mut items = Vec::new();
    let mut pos = 2usize;
    loop {
        let start = pos;
        let kind = *data.get(pos).ok_or("missing terminator")?;
        if kind == 0 {
            return Ok((version, items));
        }
        let key_len = to_usize(
            u32_le(data, pos.saturating_add(1))
                .ok_or("truncated item")?
                .into(),
        );
        let key_at = pos.saturating_add(5);
        let key = data
            .get(key_at..key_at.saturating_add(key_len))
            .ok_or("truncated key")?;
        let val_len_at = key_at.saturating_add(key_len);
        let val_len = to_usize(u32_le(data, val_len_at).ok_or("truncated item")?.into());
        let val_at = val_len_at.saturating_add(4);
        let value = data
            .get(val_at..val_at.saturating_add(val_len))
            .ok_or("truncated value")?;
        pos = val_at.saturating_add(val_len);
        items.push(VdItem {
            key: String::from_utf8_lossy(key).into_owned(),
            kind,
            value: value.to_vec(),
            start,
            len: pos.saturating_sub(start),
        });
    }
}

const VD_TYPES: EnumTable = &[
    (0x04, "UInt32"),
    (0x05, "UInt64"),
    (0x08, "Bool"),
    (0x0c, "Int32"),
    (0x0d, "Int64"),
    (0x18, "String"),
    (0x42, "Bytes"),
];

fn vd_uint(item: &VdItem) -> Option<u64> {
    match (item.kind, item.value.len()) {
        (0x04, 4) => u32_le(&item.value, 0).map(u64::from),
        (0x05, 8) => u64_le(&item.value, 0),
        _ => None,
    }
}

/// The KDF a KDBX 4 parameter dictionary describes.
fn kdf_from(items: &[VdItem]) -> std::result::Result<Kdf, String> {
    let get = |k: &str| items.iter().find(|i| i.key == k);
    let uuid = get("$UUID").map(|i| hex(&i.value)).ok_or("no KDF UUID")?;
    let name = KDFS
        .iter()
        .find(|(u, _)| *u == uuid)
        .map(|(_, n)| *n)
        .ok_or_else(|| format!("unknown KDF {uuid}"))?;
    let bytes = |k: &str| get(k).map(|i| i.value.clone()).unwrap_or_default();
    let uint = |k: &str| get(k).and_then(vd_uint);
    if name == "AES-KDF" {
        return Ok(Kdf::Aes {
            seed: bytes("S"),
            rounds: uint("R").ok_or("no round count")?,
        });
    }
    let small = |k: &str| {
        uint(k)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| format!("missing or bad Argon2 parameter {k}"))
    };
    let memory = uint("M").ok_or("no Argon2 memory size")? / 1024;
    Ok(Kdf::Argon2 {
        params: argon2::Params {
            variant: if name == "Argon2id" {
                argon2::Variant::Id
            } else {
                argon2::Variant::D
            },
            version: small("V")?,
            memory_kib: u32::try_from(memory).map_err(|_| "Argon2 memory size too large")?,
            iterations: small("I")?,
            lanes: small("P")?,
            out_len: 32,
        },
        salt: bytes("S"),
        secret: bytes("K"),
        associated: bytes("A"),
    })
}

/// A node per dictionary item, with the KDF parameters named.
async fn variant_dict_node(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let (version, items) = variant_dict(&data).map_err(|e| Diagnostic::malformed(e).at(span))?;
    cx.emit(
        Node::new("Version")
            .span(span.sub(0, 2))
            .value(Value::UInt {
                value: version.into(),
                bits: 16,
                radix: Radix::Hex,
            }),
    );
    for item in &items {
        cx.checkpoint().await;
        let at = span.sub(to_u64(item.start), to_u64(item.len));
        let desc = match item.key.as_str() {
            "$UUID" => "KDF algorithm",
            "R" => "AES-KDF rounds",
            "S" => "Salt (seed)",
            "I" => "Argon2 iterations (passes)",
            "M" => "Argon2 memory in bytes",
            "P" => "Argon2 parallelism (lanes)",
            "V" => "Argon2 version",
            "K" => "Argon2 secret key",
            "A" => "Argon2 associated data",
            _ => "",
        };
        let mut node = Node::new(item.key.clone()).span(at);
        if !desc.is_empty() {
            node = node.desc(desc);
        }
        node = match item.kind {
            0x42 if item.key == "$UUID" => {
                let uuid = hex(&item.value);
                let name = KDFS.iter().find(|(u, _)| *u == uuid).map(|(_, n)| *n);
                node.value(Value::Text(name.map_or(uuid, str::to_owned)))
            }
            0x04 | 0x05 => match vd_uint(item) {
                Some(v) => {
                    let n = node.value(Value::UInt {
                        value: v,
                        bits: if item.kind == 4 { 32 } else { 64 },
                        radix: if item.key == "V" {
                            Radix::Hex
                        } else {
                            Radix::Dec
                        },
                    });
                    if item.key == "M" {
                        n.summary(kib(v / 1024))
                    } else {
                        n
                    }
                }
                None => node.diag(Diagnostic::malformed("bad integer size")),
            },
            0x08 => node.value(Value::Bool(item.value.first().is_some_and(|&b| b != 0))),
            0x0c | 0x0d => {
                let v = match item.value.len() {
                    4 => u32_le(&item.value, 0).map(|v| i64::from(v as i32)),
                    8 => u64_le(&item.value, 0).map(|v| v as i64),
                    _ => None,
                };
                match v {
                    Some(value) => node.value(Value::Int {
                        value,
                        bits: if item.kind == 0x0c { 32 } else { 64 },
                    }),
                    None => node.diag(Diagnostic::malformed("bad integer size")),
                }
            }
            0x18 => node.value(Value::Text(
                String::from_utf8_lossy(&item.value).into_owned(),
            )),
            _ => node.summary(format!(
                "{}, {} bytes",
                lookup(VD_TYPES, item.kind.into()).unwrap_or("unknown type"),
                item.value.len()
            )),
        };
        cx.emit(node);
    }
    Ok(())
}

async fn kdbx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &head, LE);
    f.u32("Signature 1").hex().emit()?;
    f.u32("Signature 2").hex().emit()?;
    let minor = f.u16("Minor version").emit()?;
    let major = f.u16("Major version").emit()?;
    let mut h = Header {
        major,
        ..Header::default()
    };
    let mut cipher_name = "unknown cipher".to_owned();
    let mut v3_seed = Vec::new();
    let mut v3_rounds = None;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(12);
    loop {
        let start = cur.pos();
        let id = cur.u8().await?;
        let len = if major >= 4 {
            cur.u32().await?
        } else {
            u32::from(cur.u16().await?)
        };
        let data = file.sub_exact(cur.pos(), len.into())?;
        let bytes = cur.bytes(len.into()).await?;
        let name =
            lookup(KDBX_FIELDS, id.into()).map_or_else(|| format!("Field {id}"), str::to_owned);
        let mut node = Node::new(name).span(cur.since(start)).target(data);
        match id {
            2 => {
                let uuid = hex(&bytes);
                h.cipher = KDBX_CIPHERS
                    .iter()
                    .find(|(g, _)| *g == uuid)
                    .map(|(_, c)| *c);
                cipher_name = h.cipher.map_or(uuid, |c| c.name().to_owned());
                node = node.value(Value::Text(cipher_name.clone()));
            }
            3 => {
                let v = u32_le(&bytes, 0).unwrap_or(0);
                h.compressed = v == 1;
                node = node.value(Value::Enum {
                    raw: v.into(),
                    bits: 32,
                    name: lookup(&[(0, "none"), (1, "gzip")], v.into()),
                });
            }
            4 => {
                h.master_seed = bytes;
                node = node.summary(format!("{len} bytes"));
            }
            5 => {
                v3_seed = bytes;
                node = node.summary(format!("{len} bytes"));
            }
            6 => {
                let rounds = u64_le(&bytes, 0).unwrap_or(0);
                v3_rounds = Some(rounds);
                node = node.value(Value::UInt {
                    value: rounds,
                    bits: 64,
                    radix: Radix::Dec,
                });
            }
            7 => {
                h.iv = bytes;
                node = node.summary(format!("{len} bytes"));
            }
            9 => {
                h.stream_start = bytes;
                node = node.summary(format!("{len} bytes"));
            }
            10 => {
                let v = u32_le(&bytes, 0).unwrap_or(0);
                node = node.value(Value::Enum {
                    raw: v.into(),
                    bits: 32,
                    name: lookup(STREAMS, v.into()),
                });
            }
            11 | 12 => {
                let parsed = variant_dict(&bytes);
                if id == 11 {
                    match parsed
                        .as_ref()
                        .map_err(String::clone)
                        .and_then(|(_, i)| kdf_from(i))
                    {
                        Ok(kdf) => {
                            node = node.summary(kdf.describe());
                            h.kdf = Some(kdf);
                        }
                        Err(e) => node = node.diag(Diagnostic::malformed(e)),
                    }
                } else {
                    node = node.summary(format!(
                        "{} items",
                        parsed.as_ref().map_or(0, |(_, i)| i.len())
                    ));
                }
                node = node.lazy(variant_dict_node, data);
            }
            1 => {
                node = node.value(Value::Text(String::from_utf8_lossy(&bytes).into_owned()));
            }
            _ => node = node.summary(format!("{len} bytes")),
        }
        cx.push(node).await;
        if id == 0 {
            break;
        }
    }
    h.end = cur.pos();
    if major < 4
        && let Some(rounds) = v3_rounds
    {
        h.kdf = Some(Kdf::Aes {
            seed: v3_seed,
            rounds,
        });
    }
    if major >= 4 {
        let stored = cx.read_avail(file.sub(h.end, 32)).await?;
        let header = cx.read(file.sub_exact(0, h.end)?).await?;
        let mut node = Node::new("Header SHA-256").span(file.sub(h.end, 32));
        node = if stored == sha256(&[&header]) {
            node.summary("matches")
        } else {
            node.diag(Diagnostic::warning("header hash mismatch"))
        };
        cx.emit(node);
        cx.emit(
            Node::new("Header HMAC-SHA-256")
                .span(file.sub(h.end.saturating_add(32), 32))
                .summary("checked with the key when unlocked"),
        );
        h.payload = h.end.saturating_add(64);
    } else {
        h.payload = h.end;
    }
    let kdf = h
        .kdf
        .as_ref()
        .map_or("unknown KDF".to_owned(), Kdf::describe);
    cx.emit(
        Node::new("Payload")
            .span(file.tail(h.payload))
            .desc("Encrypted with the master key; expanding asks for the password")
            .lazy(kdbx_payload, (input, Arc::new(h))),
    );
    cx.annotate(format!(
        "KeePass KDBX {major}.{minor}, {cipher_name}, {kdf}"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// KDBX payload

/// Keys derived from a verified password.
struct KdbxKeys {
    cipher: Vec<u8>,
    hmac_base: Vec<u8>,
}

impl KdbxKeys {
    fn new(seed: &[u8], transformed: &[u8]) -> Self {
        KdbxKeys {
            cipher: sha256(&[seed, transformed]),
            hmac_base: sha512(&[seed, transformed, &[1]]),
        }
    }

    /// The HMAC of block `index` over `head` then `data`, in budgeted
    /// steps.
    async fn block_mac_stepped(&self, cx: &Cx, index: u64, head: &[&[u8]], data: &[u8]) -> Vec<u8> {
        let key = sha512(&[&index.to_le_bytes(), &self.hmac_base]);
        let mut mac = Hmac::<Sha256>::new(&key);
        for p in head {
            mac.update(p);
        }
        feed(cx, data, |c| mac.update(c)).await;
        mac.finish()
    }
}

#[derive(Clone, Debug)]
struct BlockInfo {
    span: Span,
    data: Span,
    ok: bool,
}

async fn kdbx_payload(cx: Cx, (input, h): (Input, Arc<Header>)) -> Result<()> {
    let file = input.span;
    let payload = file.tail(h.payload);
    let locked = |m: &str| Diagnostic::unsupported(m.to_owned()).at(payload);
    let cipher = h.cipher.ok_or_else(|| locked("unknown cipher"))?;
    let kdf = h
        .kdf
        .as_ref()
        .ok_or_else(|| locked("unknown key derivation"))?;
    if h.major >= 4 {
        // KDBX 4 authenticates the header with a key derived from the
        // password, which is the password check.
        let header = cx.read(file.sub_exact(0, h.end)?).await?;
        let stored = cx
            .read(file.sub_exact(h.end.saturating_add(32), 32)?)
            .await?;
        let keys = match cx.cached::<KdbxKeys>(file, "kdbx-keys") {
            Some(k) => k,
            None => {
                let mut found = None;
                for attempt in 0..MAX_ATTEMPTS {
                    let Some(t) = attempt_key(&cx, file, PROMPT, attempt, composite2, kdf).await?
                    else {
                        break;
                    };
                    let keys = KdbxKeys::new(&h.master_seed, &t);
                    if keys.block_mac_stepped(&cx, u64::MAX, &[], &header).await == stored {
                        found = Some(keys);
                        break;
                    }
                }
                let Some(keys) = found else {
                    return Err(locked("encrypted (no password, or a wrong one)"));
                };
                let keys = Arc::new(keys);
                cx.cache(file, "kdbx-keys", keys.clone());
                keys
            }
        };
        kdbx4_payload(&cx, input, &h, cipher, &keys).await
    } else {
        let head = cx.read_avail(payload.sub(0, 32)).await?;
        let check = |t: &[u8]| {
            let keys = KdbxKeys::new(&h.master_seed, t);
            let plain = cipher.decrypt_head(&keys.cipher, &h.iv, &head)?;
            (plain.get(..32) == Some(h.stream_start.as_slice())).then_some(keys)
        };
        let keys = match cx.cached::<KdbxKeys>(file, "kdbx-keys") {
            Some(k) => k,
            None => {
                let Some(keys) = unlock(&cx, file, PROMPT, composite2, kdf, check).await? else {
                    return Err(locked("encrypted (no password, or a wrong one)"));
                };
                let keys = Arc::new(keys);
                cx.cache(file, "kdbx-keys", keys.clone());
                keys
            }
        };
        kdbx3_payload(&cx, input, &h, cipher, &keys).await
    }
}

const PROMPT: &str = "Master password for the KeePass database";

/// The KDBX composite key for a password alone.
fn composite2(password: &[u8]) -> Vec<u8> {
    sha256(&[&sha256(&[password])])
}

async fn decrypt(cx: &Cx, cipher: Cipher, keys: &KdbxKeys, iv: &[u8], span: Span) -> Result<Span> {
    let origin = Origin {
        parent: span,
        transform: "kdbx-decrypt",
    };
    if let Some(found) = cx.derived(origin) {
        return Ok(found.span);
    }
    let data = read_all(cx, span).await?;
    let plain = cipher
        .decrypt_stepped(cx, &keys.cipher, iv, &data)
        .await
        .ok_or_else(|| Diagnostic::malformed("decryption failed (bad padding)").at(span))?;
    Ok(cx.add_derived(origin, plain, span.len, None)?.span)
}

fn blocks_node(name: &'static str, blocks: Vec<BlockInfo>, what: &'static str) -> Node {
    let bad = blocks.iter().filter(|b| !b.ok).count();
    let mut node = Node::new(name).summary(format!(
        "{} blocks{}",
        blocks.len(),
        if bad == 0 {
            format!(", {what} verified")
        } else {
            format!(", {bad} bad")
        }
    ));
    if let (Some(first), Some(last)) = (blocks.first(), blocks.last())
        && first.span.source == last.span.source
    {
        node = node.span(Span::new(
            first.span.source,
            first.span.offset,
            last.span.end().saturating_sub(first.span.offset),
        ));
    }
    if bad > 0 {
        node = node.diag(Diagnostic::warning(format!(
            "{bad} block(s) fail their {what}"
        )));
    }
    node.lazy(block_list, (Arc::new(blocks), what))
}

async fn block_list(cx: Cx, (blocks, what): (Arc<Vec<BlockInfo>>, &'static str)) -> Result<()> {
    for (i, b) in blocks.iter().enumerate() {
        let mut node = Node::new(format!("Block {i}")).span(b.span).target(b.data);
        node = if b.data.len == 0 {
            node.summary("end")
        } else {
            node.summary(format!("{} bytes", b.data.len))
        };
        if !b.ok {
            node = node.diag(Diagnostic::warning(format!("{what} mismatch")));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The gzip layer (if any) around `span`: the decompressed span.
async fn gunzip(cx: &Cx, span: Span) -> Result<Span> {
    let head = cx.read_avail(span.sub(0, 4096)).await?;
    let bad = || Diagnostic::malformed("not a gzip stream").at(span);
    if head.get(..3) != Some(&[0x1f, 0x8b, 8][..]) {
        return Err(bad());
    }
    let flags = *head.get(3).ok_or_else(bad)?;
    let mut pos = 10usize;
    if flags & 4 != 0 {
        let n = usize::from(u16_le(&head, pos).ok_or_else(bad)?);
        pos = pos.saturating_add(2).saturating_add(n);
    }
    for bit in [8u8, 16] {
        if flags & bit != 0 {
            let n = head
                .get(pos..)
                .and_then(|r| r.iter().position(|&b| b == 0))
                .ok_or_else(bad)?;
            pos = pos.saturating_add(n).saturating_add(1);
        }
    }
    if flags & 2 != 0 {
        pos = pos.saturating_add(2);
    }
    let body = span.tail(to_u64(pos));
    let decoded = decode_span(cx, body, &Codec::Deflate, None).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    Ok(decoded.span)
}

async fn kdbx3_payload(
    cx: &Cx,
    input: Input,
    h: &Header,
    cipher: Cipher,
    keys: &KdbxKeys,
) -> Result<()> {
    let file = input.span;
    let plain = decrypt(cx, cipher, keys, &h.iv, file.tail(h.payload)).await?;
    cx.emit(Node::new("Decrypted").span(plain).summary(format!(
        "{}, {} bytes",
        cipher.name(),
        plain.len
    )));
    cx.emit(
        Node::new("Stream start bytes")
            .span(plain.sub(0, 32))
            .summary("match the header (password verified)"),
    );
    // The hashed block stream: index, SHA-256, size, data; a zero-size
    // block with a zero hash ends it.
    let data = read_all(cx, plain.tail(32)).await?;
    let mut blocks = Vec::new();
    let mut pieces = Vec::new();
    let mut pos = 0usize;
    while let (Some(_), Some(hash), Some(size)) = (
        u32_le(&data, pos),
        data.get(pos.saturating_add(4)..pos.saturating_add(36)),
        u32_le(&data, pos.saturating_add(36)),
    ) {
        cx.checkpoint().await;
        let at = pos.saturating_add(40);
        let size = to_usize(size.into());
        let Some(body) = data.get(at..at.saturating_add(size)) else {
            cx.diag(
                Diagnostic::malformed("block overruns the data")
                    .at(plain.tail(to_u64(pos).saturating_add(32))),
            );
            break;
        };
        let span = plain.sub(
            to_u64(pos).saturating_add(32),
            to_u64(size).saturating_add(40),
        );
        let data_span = plain.sub(to_u64(at).saturating_add(32), to_u64(size));
        let ok = if size == 0 {
            hash.iter().all(|&b| b == 0)
        } else {
            sha256_stepped(cx, body).await == hash
        };
        blocks.push(BlockInfo {
            span,
            data: data_span,
            ok,
        });
        if size == 0 {
            break;
        }
        pieces.push(data_span);
        pos = at.saturating_add(size);
    }
    cx.emit(blocks_node("Hashed block stream", blocks, "SHA-256"));
    let content = cx.add_pieces(
        Origin {
            parent: plain,
            transform: "kdbx-hashed-blocks",
        },
        pieces,
    )?;
    let xml = if h.compressed {
        let out = gunzip(cx, content).await?;
        cx.emit(
            Node::new("Decompressed")
                .span(out)
                .summary(format!("gzip, {} bytes", out.len)),
        );
        out
    } else {
        content
    };
    emit_document(cx, input, xml, None).await
}

async fn kdbx4_payload(
    cx: &Cx,
    input: Input,
    h: &Header,
    cipher: Cipher,
    keys: &KdbxKeys,
) -> Result<()> {
    let file = input.span;
    let payload = file.tail(h.payload);
    // The HMAC block stream: HMAC-SHA-256, size, data; ends with an empty
    // block. The MAC covers the block index, size and data.
    let mut blocks = Vec::new();
    let mut pieces = Vec::new();
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos < payload.len {
        let head = cx.read(payload.sub_exact(pos, 36)?).await?;
        let size = u32_le(&head, 32).unwrap_or(0);
        let data_span = payload.sub_exact(pos.saturating_add(36), size.into())?;
        let data = cx.read(data_span).await?;
        let mac = keys
            .block_mac_stepped(
                cx,
                index,
                &[&index.to_le_bytes(), &size.to_le_bytes()],
                &data,
            )
            .await;
        blocks.push(BlockInfo {
            span: payload.sub(pos, u64::from(size).saturating_add(36)),
            data: data_span,
            ok: head.get(..32) == Some(mac.as_slice()),
        });
        pos = pos.saturating_add(36).saturating_add(size.into());
        index = index.saturating_add(1);
        if size == 0 {
            break;
        }
        pieces.push(data_span);
    }
    cx.emit(blocks_node("HMAC block stream", blocks, "HMAC"));
    let cipher_text = cx.add_pieces(
        Origin {
            parent: payload,
            transform: "kdbx-hmac-blocks",
        },
        pieces,
    )?;
    let plain = decrypt(cx, cipher, keys, &h.iv, cipher_text).await?;
    cx.emit(Node::new("Decrypted").span(plain).summary(format!(
        "{}, {} bytes",
        cipher.name(),
        plain.len
    )));
    let content = if h.compressed {
        let out = gunzip(cx, plain).await?;
        cx.emit(
            Node::new("Decompressed")
                .span(out)
                .summary(format!("gzip, {} bytes", out.len)),
        );
        out
    } else {
        plain
    };
    // The inner header: type, size, data; type 0 ends it.
    let mut cur = Cursor::new(cx, content, LE);
    let mut binaries = 0u32;
    while !cur.at_end() {
        let id = cur.u8().await?;
        let len = cur.u32().await?;
        cur.skip(len.into());
        if id == 3 {
            binaries = binaries.saturating_add(1);
        }
        if id == 0 {
            break;
        }
    }
    let inner = content.sub(0, cur.pos());
    cx.emit(
        Node::new("Inner header")
            .span(inner)
            .summary(plural(binaries.into(), "attachment", "attachments"))
            .lazy(inner_header, (input, inner)),
    );
    emit_document(cx, input, content.tail(cur.pos()), Some(binaries)).await
}

const INNER_FIELDS: EnumTable = &[
    (0, "End of header"),
    (1, "Inner random stream ID"),
    (2, "Inner random stream key"),
    (3, "Binary"),
];

async fn inner_header(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let mut binary = 0u32;
    while !cur.at_end() {
        let start = cur.pos();
        let id = cur.u8().await?;
        let len = cur.u32().await?;
        let data = span.sub_exact(cur.pos(), len.into())?;
        let name = lookup(INNER_FIELDS, id.into()).unwrap_or("Unknown field");
        let mut node = Node::new(if id == 3 {
            format!("Binary {binary}")
        } else {
            name.to_owned()
        });
        match id {
            1 => {
                let v = u32_le(&cur.bytes(len.into()).await?, 0).unwrap_or(0);
                node = node.value(Value::Enum {
                    raw: v.into(),
                    bits: 32,
                    name: lookup(STREAMS, v.into()),
                });
            }
            3 => {
                let flags = cur.u8().await?;
                cur.skip(u64::from(len).saturating_sub(1));
                let body = data.tail(1);
                node = node
                    .summary(format!(
                        "{} bytes{}",
                        body.len,
                        if flags & 1 != 0 { ", protected" } else { "" }
                    ))
                    .lazy(binary_node, (input, data));
                binary = binary.saturating_add(1);
            }
            _ => {
                cur.skip(len.into());
                node = node.summary(format!("{len} bytes"));
            }
        }
        cx.push(node.span(cur.since(start)).target(data)).await;
        if id == 0 {
            break;
        }
    }
    Ok(())
}

const BINARY_FLAGS: FlagTable = &[flag(1, "PROTECTED")];

async fn binary_node(cx: Cx, (input, data): (Input, Span)) -> Result<()> {
    let flags = cx.read(data.sub_exact(0, 1)?).await?;
    let raw = flags.first().copied().unwrap_or(0);
    cx.emit(Node::new("Flags").span(data.sub(0, 1)).value({
        let (set, unknown) = decode_flags(BINARY_FLAGS, raw.into());
        Value::Flags {
            raw: raw.into(),
            bits: 8,
            set,
            unknown,
        }
    }));
    cx.emit(embedded("Content", input.nested(data.tail(1))));
    Ok(())
}

/// The XML document and the database summary.
async fn emit_document(cx: &Cx, input: Input, xml: Span, binaries: Option<u32>) -> Result<()> {
    cx.emit(embedded_as(
        "XML",
        input.nested(xml),
        &crate::formats::text::xml::FORMAT,
    ));
    cx.emit(
        Node::new("Database")
            .span(xml)
            .desc("Groups and entries from the XML; protected values are not shown")
            .lazy(database, (input, xml)),
    );
    let _ = binaries;
    cx.annotate("unlocked");
    Ok(())
}

// ---------------------------------------------------------------------------
// The KeePass XML document

#[derive(Debug, Default)]
struct Field {
    key: String,
    /// `None` for protected values.
    value: Option<String>,
    span: (usize, usize),
}

#[derive(Debug, Default)]
struct Attachment {
    name: String,
    reference: String,
    span: (usize, usize),
}

#[derive(Debug, Default)]
struct Entry {
    span: (usize, usize),
    fields: Vec<Field>,
    attachments: Vec<Attachment>,
    history: Vec<usize>,
}

impl Entry {
    fn get(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.key == key)
    }

    fn text(&self, key: &str) -> &str {
        self.get(key)
            .and_then(|f| f.value.as_deref())
            .unwrap_or_default()
    }
}

#[derive(Debug, Default)]
struct Group {
    name: String,
    span: (usize, usize),
    groups: Vec<usize>,
    entries: Vec<usize>,
}

#[derive(Debug, Default)]
struct Doc {
    meta: Vec<(String, String, (usize, usize))>,
    meta_span: Option<(usize, usize)>,
    roots: Vec<usize>,
    groups: Vec<Group>,
    entries: Vec<Entry>,
    deleted: u32,
    error: Option<String>,
}

const META_KEYS: &[&str] = &[
    "Generator",
    "DatabaseName",
    "DatabaseDescription",
    "DefaultUserName",
    "MaintenanceHistoryDays",
    "RecycleBinEnabled",
    "HistoryMaxItems",
    "HistoryMaxSize",
    "HeaderHash",
];

/// Element nesting deeper than this is not followed.
const MAX_DEPTH: usize = 96;
/// Text kept per value.
const MAX_TEXT: usize = 4096;

enum Tok<'a> {
    Start {
        name: &'a [u8],
        attrs: &'a [u8],
        empty: bool,
    },
    End {
        name: &'a [u8],
    },
    Text(&'a [u8], bool),
}

/// A minimal XML tokenizer for KeePass documents: tags, text, CDATA;
/// comments, declarations and doctypes are skipped. Returns the token and
/// the position after it.
fn next_token(data: &[u8], pos: usize) -> Option<(Tok<'_>, usize, usize)> {
    let mut pos = pos;
    loop {
        let rest = data.get(pos..)?;
        if rest.is_empty() {
            return None;
        }
        let find = |pat: &[u8], from: usize| {
            rest.get(from..)
                .and_then(|r| r.windows(pat.len()).position(|w| w == pat))
                .map(|i| i.saturating_add(from))
        };
        if rest.first() != Some(&b'<') {
            let n = rest.iter().position(|&b| b == b'<').unwrap_or(rest.len());
            return Some((Tok::Text(rest.get(..n)?, false), pos, pos.saturating_add(n)));
        }
        if rest.starts_with(b"<![CDATA[") {
            let end = find(b"]]>", 9).unwrap_or(rest.len());
            let text = rest.get(9..end).unwrap_or_default();
            return Some((
                Tok::Text(text, true),
                pos,
                pos.saturating_add(end).saturating_add(3),
            ));
        }
        let skip_to = |pat: &[u8], from: usize| {
            find(pat, from).map_or(data.len(), |i| {
                pos.saturating_add(i).saturating_add(pat.len())
            })
        };
        if rest.starts_with(b"<!--") {
            pos = skip_to(b"-->", 4);
            continue;
        }
        if rest.starts_with(b"<?") {
            pos = skip_to(b"?>", 2);
            continue;
        }
        if rest.starts_with(b"<!") {
            pos = skip_to(b">", 2);
            continue;
        }
        if rest.starts_with(b"</") {
            let end = find(b">", 2).unwrap_or(rest.len());
            let name = rest.get(2..end).unwrap_or_default().trim_ascii();
            return Some((
                Tok::End { name },
                pos,
                pos.saturating_add(end).saturating_add(1),
            ));
        }
        // A start tag; '>' inside quoted attribute values does not end it.
        let mut quote = None;
        let mut end = rest.len();
        for (i, &b) in rest.iter().enumerate().skip(1) {
            match (quote, b) {
                (Some(q), _) if b == q => quote = None,
                (Some(_), _) => {}
                (None, b'"' | b'\'') => quote = Some(b),
                (None, b'>') => {
                    end = i;
                    break;
                }
                _ => {}
            }
        }
        let inner = rest.get(1..end).unwrap_or_default();
        let empty = inner.last() == Some(&b'/');
        let inner = if empty {
            inner
                .get(..inner.len().saturating_sub(1))
                .unwrap_or_default()
        } else {
            inner
        };
        let n = inner
            .iter()
            .position(|b| b.is_ascii_whitespace())
            .unwrap_or(inner.len());
        let (name, attrs) = inner.split_at(n);
        return Some((
            Tok::Start { name, attrs, empty },
            pos,
            pos.saturating_add(end).saturating_add(1),
        ));
    }
}

/// The value of attribute `name` in `attrs`.
fn attr(attrs: &[u8], name: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(attrs);
    let name = String::from_utf8_lossy(name);
    let mut rest = text.as_ref();
    while let Some(i) = rest.find(name.as_ref()) {
        let after = rest.get(i.saturating_add(name.len())..).unwrap_or_default();
        let boundary = i == 0
            || rest
                .get(..i)
                .and_then(|s| s.chars().last())
                .is_some_and(char::is_whitespace);
        let value = after.trim_start().strip_prefix('=').map(str::trim_start);
        if boundary && let Some(v) = value {
            let q = v.chars().next()?;
            if q == '"' || q == '\'' {
                let body = v.get(1..)?;
                let end = body.find(q)?;
                return Some(body.get(..end)?.to_owned());
            }
        }
        rest = after;
    }
    None
}

/// A KeePass document parser's state, fed one token at a time.
#[derive(Default)]
struct DocParser {
    doc: Doc,
    stack: Vec<Vec<u8>>,
    groups: Vec<(usize, usize)>,  // (group index, depth)
    entries: Vec<(usize, usize)>, // (entry index, depth)
    text: String,
    protected: bool,
    reference: String,
    pending_key: String,
    leaf_start: usize,
    pos: usize,
}

impl DocParser {
    /// Handles the next token; `false` at the end or on an error.
    fn step(&mut self, data: &[u8]) -> bool {
        let Some((tok, start, next)) = next_token(data, self.pos) else {
            return false;
        };
        self.pos = next.max(self.pos.saturating_add(1));
        match tok {
            Tok::Start { name, attrs, empty } => {
                let parent = self.stack.last().map(Vec::as_slice);
                let depth = self.stack.len();
                self.text.clear();
                self.leaf_start = start;
                match name {
                    b"Group" if matches!(parent, Some(b"Root" | b"Group")) => {
                        let id = self.doc.groups.len();
                        self.doc.groups.push(Group {
                            span: (start, start),
                            ..Group::default()
                        });
                        match self.groups.last() {
                            Some(&(g, _)) => {
                                if let Some(p) = self.doc.groups.get_mut(g) {
                                    p.groups.push(id);
                                }
                            }
                            None => self.doc.roots.push(id),
                        }
                        if !empty {
                            self.groups.push((id, depth));
                        }
                    }
                    b"Entry" if matches!(parent, Some(b"Group" | b"History")) => {
                        let id = self.doc.entries.len();
                        self.doc.entries.push(Entry {
                            span: (start, start),
                            ..Entry::default()
                        });
                        if parent == Some(b"History") {
                            if let Some(e) = self
                                .entries
                                .last()
                                .and_then(|&(e, _)| self.doc.entries.get_mut(e))
                            {
                                e.history.push(id);
                            }
                        } else if let Some(g) = self
                            .groups
                            .last()
                            .and_then(|&(g, _)| self.doc.groups.get_mut(g))
                        {
                            g.entries.push(id);
                        }
                        if !empty {
                            self.entries.push((id, depth));
                        }
                    }
                    b"Meta" if depth == 1 => self.doc.meta_span = Some((start, start)),
                    b"DeletedObject" => self.doc.deleted = self.doc.deleted.saturating_add(1),
                    b"String" | b"Binary" if parent == Some(b"Entry") => {
                        self.pending_key.clear();
                        self.reference.clear();
                    }
                    b"Value" => {
                        self.protected = attr(attrs, b"Protected")
                            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
                        self.reference = attr(attrs, b"Ref").unwrap_or_default();
                        if empty {
                            close_value(
                                &mut self.doc,
                                &self.entries,
                                &self.stack,
                                &self.pending_key,
                                "",
                                self.protected,
                                &self.reference,
                                (start, next),
                            );
                        }
                    }
                    _ => {}
                }
                if !empty {
                    if self.stack.len() >= MAX_DEPTH {
                        self.doc.error = Some("elements nested too deeply".to_owned());
                        return false;
                    }
                    self.stack.push(name.to_vec());
                }
            }
            Tok::Text(t, cdata) => {
                if self.text.len() < MAX_TEXT {
                    let s = String::from_utf8_lossy(t);
                    if cdata {
                        self.text.push_str(&s);
                    } else {
                        self.text
                            .push_str(&crate::formats::text::xml::decode_entities(&s, false));
                    }
                }
            }
            Tok::End { name } => {
                if self.stack.last().map(Vec::as_slice) != Some(name) {
                    self.doc.error = Some(format!(
                        "mismatched end tag </{}>",
                        String::from_utf8_lossy(name)
                    ));
                    return false;
                }
                self.stack.pop();
                let parent = self.stack.last().map(Vec::as_slice);
                let depth = self.stack.len();
                let value: String = self.text.chars().take(MAX_TEXT).collect();
                match name {
                    b"Group" => {
                        if let Some(&(g, d)) = self.groups.last()
                            && d == depth
                        {
                            if let Some(group) = self.doc.groups.get_mut(g) {
                                group.span.1 = next;
                            }
                            self.groups.pop();
                        }
                    }
                    b"Entry" => {
                        if let Some(&(e, d)) = self.entries.last()
                            && d == depth
                        {
                            if let Some(entry) = self.doc.entries.get_mut(e) {
                                entry.span.1 = next;
                            }
                            self.entries.pop();
                        }
                    }
                    b"Name" if parent == Some(b"Group") => {
                        if let Some(g) = self
                            .groups
                            .last()
                            .and_then(|&(g, d)| (d.saturating_add(1) == depth).then_some(g))
                            .and_then(|g| self.doc.groups.get_mut(g))
                        {
                            g.name = value;
                        }
                    }
                    b"Key" if matches!(parent, Some(b"String" | b"Binary")) => {
                        self.pending_key = value
                    }
                    b"Value" if matches!(parent, Some(b"String" | b"Binary")) => {
                        close_value(
                            &mut self.doc,
                            &self.entries,
                            &self.stack,
                            &self.pending_key,
                            &value,
                            self.protected,
                            &self.reference,
                            (self.leaf_start, next),
                        );
                    }
                    b"Meta" if depth == 1 => {
                        if let Some(m) = self.doc.meta_span.as_mut() {
                            m.1 = next;
                        }
                    }
                    _ if parent == Some(b"Meta") => {
                        let key = String::from_utf8_lossy(name).into_owned();
                        if META_KEYS.contains(&key.as_str()) {
                            self.doc.meta.push((key, value, (self.leaf_start, next)));
                        }
                    }
                    _ => {}
                }
                self.text.clear();
            }
        }
        true
    }
}

#[cfg(test)]
fn parse_doc(data: &[u8]) -> Doc {
    let mut p = DocParser::default();
    while p.step(data) {}
    p.doc
}

/// Parses the document, checkpointing between tokens.
async fn parse_doc_stepped(cx: &Cx, data: &[u8]) -> Doc {
    let mut p = DocParser::default();
    let mut n = 0u32;
    while p.step(data) {
        n = n.wrapping_add(1);
        if n.is_multiple_of(256) {
            cx.checkpoint().await;
        }
    }
    p.doc
}

/// Records a `<Value>` of an entry's `<String>` or `<Binary>`.
#[allow(clippy::too_many_arguments)]
fn close_value(
    doc: &mut Doc,
    entries: &[(usize, usize)],
    stack: &[Vec<u8>],
    key: &str,
    value: &str,
    protected: bool,
    reference: &str,
    span: (usize, usize),
) {
    // The stack holds ... Entry, String|Binary (and Value, if not empty).
    let container = stack
        .iter()
        .rev()
        .find(|n| n.as_slice() == b"String" || n.as_slice() == b"Binary");
    let Some(entry) = entries.last().and_then(|&(e, _)| doc.entries.get_mut(e)) else {
        return;
    };
    if container.map(Vec::as_slice) == Some(b"Binary") {
        entry.attachments.push(Attachment {
            name: key.to_owned(),
            reference: reference.to_owned(),
            span,
        });
    } else {
        entry.fields.push(Field {
            key: key.to_owned(),
            value: (!protected).then(|| value.to_owned()),
            span,
        });
    }
}

type DocState = (Arc<Doc>, Span, usize);

fn sub(xml: Span, (a, b): (usize, usize)) -> Span {
    xml.sub(to_u64(a), to_u64(b.saturating_sub(a)))
}

async fn database(cx: Cx, (_input, xml): (Input, Span)) -> Result<()> {
    let doc = match cx.cached::<Doc>(xml, "keepass-doc") {
        Some(d) => d,
        None => {
            let data = read_all(&cx, xml).await?;
            let d = Arc::new(parse_doc_stepped(&cx, &data).await);
            cx.cache(xml, "keepass-doc", d.clone());
            d
        }
    };
    if let Some(e) = &doc.error {
        cx.diag(Diagnostic::malformed(e.clone()).at(xml));
    }
    if let Some(m) = doc.meta_span {
        cx.emit(
            Node::new("Meta")
                .span(sub(xml, m))
                .lazy(meta, (doc.clone(), xml, 0usize)),
        );
    }
    for &g in &doc.roots {
        cx.checkpoint().await;
        cx.emit(group_node(&doc, xml, g, 0));
    }
    if doc.deleted > 0 {
        cx.emit(Node::new("Deleted objects").value(Value::UInt {
            value: doc.deleted.into(),
            bits: 32,
            radix: Radix::Dec,
        }));
    }
    let history: usize = doc.entries.iter().map(|e| e.history.len()).sum();
    cx.annotate(format!(
        "{}, {}",
        plural(to_u64(doc.groups.len()), "group", "groups"),
        plural(
            to_u64(doc.entries.len().saturating_sub(history)),
            "entry",
            "entries"
        )
    ));
    Ok(())
}

async fn meta(cx: Cx, (doc, xml, _): DocState) -> Result<()> {
    for (key, value, span) in &doc.meta {
        cx.checkpoint().await;
        cx.emit(
            Node::new(key.clone())
                .span(sub(xml, *span))
                .value(Value::Text(value.clone())),
        );
    }
    Ok(())
}

fn group_node(doc: &Arc<Doc>, xml: Span, g: usize, depth: usize) -> Node {
    let Some(group) = doc.groups.get(g) else {
        return Node::new("Group");
    };
    let name = if group.name.is_empty() {
        "(unnamed group)".to_owned()
    } else {
        group.name.clone()
    };
    let node = Node::new(name).span(sub(xml, group.span)).summary(format!(
        "{}, {}",
        plural(to_u64(group.groups.len()), "group", "groups"),
        plural(to_u64(group.entries.len()), "entry", "entries")
    ));
    if depth >= MAX_DEPTH {
        return node.diag(Diagnostic::limit("groups nested too deeply"));
    }
    node.lazy(
        crate::expander!(self::group_children: (DocState, usize)),
        ((doc.clone(), xml, g), depth),
    )
}

async fn group_children(cx: Cx, ((doc, xml, g), depth): (DocState, usize)) -> Result<()> {
    let Some(group) = doc.groups.get(g) else {
        return Ok(());
    };
    for &child in &group.groups {
        cx.push(group_node(&doc, xml, child, depth.saturating_add(1)))
            .await;
    }
    for &e in &group.entries {
        cx.push(entry_node(&doc, xml, e)).await;
    }
    Ok(())
}

fn entry_node(doc: &Arc<Doc>, xml: Span, e: usize) -> Node {
    let Some(entry) = doc.entries.get(e) else {
        return Node::new("Entry");
    };
    let title = entry.text("Title");
    let user = entry.text("UserName");
    let url = entry.text("URL");
    let summary = match (user.is_empty(), url.is_empty()) {
        (false, false) => format!("{user} — {url}"),
        (false, true) => user.to_owned(),
        (true, false) => url.to_owned(),
        (true, true) => String::new(),
    };
    let mut node = Node::new(if title.is_empty() {
        "(untitled entry)".to_owned()
    } else {
        title.to_owned()
    })
    .span(sub(xml, entry.span))
    .lazy(entry_children, (doc.clone(), xml, e));
    if !summary.is_empty() {
        node = node.summary(summary);
    }
    node
}

async fn entry_children(cx: Cx, (doc, xml, e): DocState) -> Result<()> {
    let Some(entry) = doc.entries.get(e) else {
        return Ok(());
    };
    for f in &entry.fields {
        cx.checkpoint().await;
        let mut node = Node::new(f.key.clone()).span(sub(xml, f.span));
        node = match &f.value {
            Some(v) => node.value(Value::Text(v.clone())),
            None => node.summary("protected"),
        };
        cx.emit(node);
    }
    for a in &entry.attachments {
        cx.checkpoint().await;
        cx.emit(
            Node::new(format!("Attachment {}", a.name))
                .span(sub(xml, a.span))
                .summary(format!("binary #{}", a.reference)),
        );
    }
    if !entry.history.is_empty() {
        cx.emit(
            Node::new("History")
                .summary(plural(to_u64(entry.history.len()), "revision", "revisions"))
                .lazy(history, (doc.clone(), xml, e)),
        );
    }
    Ok(())
}

async fn history(cx: Cx, (doc, xml, e): DocState) -> Result<()> {
    let Some(entry) = doc.entries.get(e) else {
        return Ok(());
    };
    for &h in &entry.history {
        // History entries have no history of their own.
        let mut node = entry_node(&doc, xml, h);
        node.name = format!("Revision: {}", node.name).into();
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// KDB (KeePass 1.x)

const KDB_FLAGS: FlagTable = &[
    flag(1, "SHA2"),
    flag(2, "RIJNDAEL"),
    flag(4, "ARCFOUR"),
    flag(8, "TWOFISH"),
];

record! {
    pub struct KdbHeader {
        signature1: u32 "Signature 1" .hex(),
        signature2: u32 "Signature 2" .hex(),
        flags: u32 "Flags" .flags(KDB_FLAGS),
        version: u32 "Version" .hex(),
        master_seed: bytes[16] "Master seed",
        iv: bytes[16] "Encryption IV",
        groups: u32 "Groups",
        entries: u32 "Entries",
        contents_hash: bytes[32] "Contents hash" .desc("SHA-256 of the decrypted groups and entries"),
        transform_seed: bytes[32] "Transform seed",
        rounds: u32 "Key transform rounds",
    }
}

async fn kdb(cx: Cx, input: Input) -> Result<()> {
    let h: KdbHeader = emit_record(&cx, input.span.sub(0, KdbHeader::SIZE), LE).await?;
    let cipher = kdb_cipher(h.flags);
    cx.emit(
        Node::new("Payload")
            .span(input.span.tail(KdbHeader::SIZE))
            .desc("Encrypted groups and entries; expanding asks for the password")
            .lazy(kdb_payload, (input, Arc::new(h.clone()))),
    );
    cx.annotate(format!(
        "KeePass 1, {} groups, {} entries, {}, {} rounds",
        h.groups,
        h.entries,
        cipher.map_or("unknown cipher", Cipher::name),
        h.rounds
    ));
    Ok(())
}

fn kdb_cipher(flags: u32) -> Option<Cipher> {
    if flags & 2 != 0 {
        Some(Cipher::Aes)
    } else if flags & 8 != 0 {
        Some(Cipher::Twofish)
    } else {
        None
    }
}

async fn kdb_payload(cx: Cx, (input, h): (Input, Arc<KdbHeader>)) -> Result<()> {
    let file = input.span;
    let payload = file.tail(KdbHeader::SIZE);
    let locked = |m: &str| Diagnostic::unsupported(m.to_owned()).at(payload);
    let cipher = kdb_cipher(h.flags).ok_or_else(|| locked("unsupported cipher (ARCFOUR?)"))?;
    let origin = Origin {
        parent: payload,
        transform: "kdb-decrypt",
    };
    let plain = match cx.derived(origin) {
        Some(found) => found.span,
        None => {
            let data = read_all(&cx, payload).await?;
            let kdf = Kdf::Aes {
                seed: h.transform_seed.to_vec(),
                rounds: h.rounds.into(),
            };
            let composite = |p: &[u8]| sha256(&[p]);
            // Each attempt decrypts and hashes the whole payload, in
            // budgeted steps.
            let mut found = None;
            for attempt in 0..MAX_ATTEMPTS {
                let Some(t) = attempt_key(&cx, file, PROMPT_KDB, attempt, composite, &kdf).await?
                else {
                    break;
                };
                let key = sha256(&[&h.master_seed, &t]);
                let Some(plain) = cipher.decrypt_stepped(&cx, &key, &h.iv, &data).await else {
                    continue;
                };
                if sha256_stepped(&cx, &plain).await == h.contents_hash {
                    found = Some(plain);
                    break;
                }
            }
            let Some(plain) = found else {
                return Err(locked("encrypted (no password, or a wrong one)"));
            };
            cx.add_derived(origin, plain, payload.len, None)?.span
        }
    };
    cx.emit(Node::new("Decrypted").span(plain).summary(format!(
        "{}, {} bytes, contents hash verified",
        cipher.name(),
        plain.len
    )));
    let data = read_all(&cx, plain).await?;
    let doc = Arc::new(kdb_parse(&cx, &data, h.groups, h.entries).await);
    if let Some(e) = &doc.error {
        cx.diag(Diagnostic::malformed(e.clone()).at(plain));
    }
    cx.emit(
        Node::new("Groups")
            .summary(format!("{}", doc.groups.len()))
            .lazy(kdb_records, (input, plain, doc.clone(), true)),
    );
    cx.emit(
        Node::new("Entries")
            .summary(format!("{}", doc.entries.len()))
            .lazy(kdb_records, (input, plain, doc.clone(), false)),
    );
    cx.annotate("unlocked");
    Ok(())
}

const PROMPT_KDB: &str = "Master password for the KeePass 1 database";

#[derive(Debug, Default)]
struct KdbRecord {
    span: (usize, usize),
    /// (type, data offset, data length)
    fields: Vec<(u16, usize, usize)>,
}

#[derive(Debug, Default)]
struct KdbDoc {
    groups: Vec<KdbRecord>,
    entries: Vec<KdbRecord>,
    error: Option<String>,
}

async fn kdb_parse(cx: &Cx, data: &[u8], groups: u32, entries: u32) -> KdbDoc {
    let mut doc = KdbDoc::default();
    let mut pos = 0usize;
    for (count, is_group) in [(groups, true), (entries, false)] {
        for _ in 0..count {
            cx.checkpoint().await;
            if pos >= data.len() {
                doc.error = Some("fewer records than the header says".to_owned());
                return doc;
            }
            let start = pos;
            let mut rec = KdbRecord::default();
            loop {
                let (Some(kind), Some(len)) =
                    (u16_le(data, pos), u32_le(data, pos.saturating_add(2)))
                else {
                    doc.error = Some("truncated field".to_owned());
                    return doc;
                };
                let at = pos.saturating_add(6);
                let len = to_usize(len.into());
                if data.get(at..at.saturating_add(len)).is_none() {
                    doc.error = Some("field overruns the data".to_owned());
                    return doc;
                }
                rec.fields.push((kind, at, len));
                pos = at.saturating_add(len);
                if kind == 0xffff {
                    break;
                }
                if rec.fields.len().is_multiple_of(256) {
                    cx.checkpoint().await;
                }
            }
            rec.span = (start, pos);
            if is_group {
                doc.groups.push(rec);
            } else {
                doc.entries.push(rec);
            }
        }
    }
    doc
}

const KDB_GROUP_FIELDS: EnumTable = &[
    (0, "Extra data"),
    (1, "Group ID"),
    (2, "Name"),
    (3, "Created"),
    (4, "Modified"),
    (5, "Accessed"),
    (6, "Expires"),
    (7, "Image ID"),
    (8, "Level"),
    (9, "Flags"),
    (0xffff, "End"),
];

const KDB_ENTRY_FIELDS: EnumTable = &[
    (0, "Extra data"),
    (1, "UUID"),
    (2, "Group ID"),
    (3, "Image ID"),
    (4, "Title"),
    (5, "URL"),
    (6, "User name"),
    (7, "Password"),
    (8, "Notes"),
    (9, "Created"),
    (10, "Modified"),
    (11, "Accessed"),
    (12, "Expires"),
    (13, "Attachment name"),
    (14, "Attachment data"),
    (0xffff, "End"),
];

fn kdb_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned()
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y.saturating_sub(1) } else { y };
    let era = y.div_euclid(400);
    let yoe = y.saturating_sub(era.saturating_mul(400));
    let mp = (m.saturating_add(9)).rem_euclid(12);
    let doy = (153i64.saturating_mul(mp).saturating_add(2) / 5)
        .saturating_add(d)
        .saturating_sub(1);
    let doe = yoe
        .saturating_mul(365)
        .saturating_add(yoe / 4)
        .saturating_sub(yoe / 100)
        .saturating_add(doy);
    era.saturating_mul(146_097)
        .saturating_add(doe)
        .saturating_sub(719_468)
}

/// A KeePass 1 packed time (year 14 bits, month 4, day 5, hour 5, minute
/// 6, second 6, big-endian bit order); `None` for "never" (2999-12-28).
fn kdb_time(b: &[u8]) -> Option<Option<i64>> {
    let [b0, b1, b2, b3, b4] = <[u8; 5]>::try_from(b.get(..5)?).ok()?;
    let (b0, b1, b2, b3, b4) = (
        i64::from(b0),
        i64::from(b1),
        i64::from(b2),
        i64::from(b3),
        i64::from(b4),
    );
    let year = (b0 << 6) | (b1 >> 2);
    let month = ((b1 & 3) << 2) | (b2 >> 6);
    let day = (b2 >> 1) & 0x1f;
    let hour = ((b2 & 1) << 4) | (b3 >> 4);
    let minute = ((b3 & 0x0f) << 2) | (b4 >> 6);
    let second = b4 & 0x3f;
    if year == 2999 {
        return Some(None);
    }
    let days = days_from_civil(year, month, day);
    Some(Some(
        days.saturating_mul(86_400)
            .saturating_add(hour.saturating_mul(3600))
            .saturating_add(minute.saturating_mul(60))
            .saturating_add(second),
    ))
}

async fn kdb_records(
    cx: Cx,
    (input, plain, doc, groups): (Input, Span, Arc<KdbDoc>, bool),
) -> Result<()> {
    let records = if groups { &doc.groups } else { &doc.entries };
    let data = read_all(&cx, plain).await?;
    let field = |rec: &KdbRecord, kind: u16| {
        rec.fields
            .iter()
            .find(|f| f.0 == kind)
            .and_then(|&(_, at, len)| data.get(at..at.saturating_add(len)))
            .map(kdb_text)
            .unwrap_or_default()
    };
    // Group names by ID (the first group with an ID wins), for the entries.
    let mut names: HashMap<u32, String> = HashMap::new();
    for g in &doc.groups {
        cx.checkpoint().await;
        if let Some(&(_, at, _)) = g.fields.iter().find(|f| f.0 == 1)
            && let Some(id) = u32_le(&data, at)
        {
            names.entry(id).or_insert_with(|| field(g, 2));
        }
    }
    for (i, rec) in records.iter().enumerate() {
        let span = sub(plain, rec.span);
        let node = if groups {
            let level = rec
                .fields
                .iter()
                .find(|f| f.0 == 8)
                .and_then(|&(_, at, _)| u16_le(&data, at))
                .unwrap_or(0);
            Node::new(field(rec, 2)).summary(format!("level {level}"))
        } else {
            let title = field(rec, 4);
            let user = field(rec, 6);
            let url = field(rec, 5);
            let group = rec
                .fields
                .iter()
                .find(|f| f.0 == 2)
                .and_then(|&(_, at, _)| u32_le(&data, at))
                .and_then(|id| names.get(&id))
                .cloned()
                .unwrap_or_default();
            let summary = if title == "Meta-Info" && user == "SYSTEM" && url == "$" {
                format!("meta stream: {}", field(rec, 8))
            } else {
                let mut parts = vec![];
                for p in [user, url] {
                    if !p.is_empty() {
                        parts.push(p);
                    }
                }
                if !group.is_empty() {
                    parts.push(format!("in {group}"));
                }
                parts.join(", ")
            };
            Node::new(if title.is_empty() {
                format!("Entry {i}")
            } else {
                title
            })
            .summary(summary)
        };
        cx.push(
            node.span(span)
                .lazy(kdb_fields, (input, plain, doc.clone(), groups, i)),
        )
        .await;
    }
    Ok(())
}

async fn kdb_fields(
    cx: Cx,
    (input, plain, doc, groups, i): (Input, Span, Arc<KdbDoc>, bool, usize),
) -> Result<()> {
    let records = if groups { &doc.groups } else { &doc.entries };
    let Some(rec) = records.get(i) else {
        return Ok(());
    };
    let table = if groups {
        KDB_GROUP_FIELDS
    } else {
        KDB_ENTRY_FIELDS
    };
    for &(kind, at, len) in &rec.fields {
        let span = plain.sub(to_u64(at), to_u64(len));
        let whole = plain.sub(to_u64(at).saturating_sub(6), to_u64(len).saturating_add(6));
        let name =
            lookup(table, kind.into()).map_or_else(|| format!("Field {kind:#06x}"), str::to_owned);
        let mut node = Node::new(name).span(whole).target(span);
        let password = !groups && kind == 7;
        if password {
            // Plaintext in the decrypted data; never put it in a value.
            cx.emit(node.summary("protected"));
            continue;
        }
        let bytes = cx.read(span).await?;
        let int = |n: usize| match n {
            2 => u16_le(&bytes, 0).map(u64::from),
            _ => u32_le(&bytes, 0).map(u64::from),
        };
        node = match (groups, kind) {
            (_, 0xffff) => node,
            (true, 2) | (false, 4 | 5 | 6 | 8 | 13) => node.value(Value::Text(kdb_text(&bytes))),
            (true, 3..=6) | (false, 9..=12) => match kdb_time(&bytes) {
                Some(Some(t)) => node.value(Value::Timestamp { unix_seconds: t }),
                Some(None) => node.summary("never"),
                None => node.diag(Diagnostic::malformed("bad time")),
            },
            (true, 1 | 7 | 9) | (false, 2 | 3) => match int(4) {
                Some(v) => node.value(Value::UInt {
                    value: v,
                    bits: 32,
                    radix: if kind == 9 { Radix::Hex } else { Radix::Dec },
                }),
                None => node.diag(Diagnostic::malformed("bad integer")),
            },
            (true, 8) => match int(2) {
                Some(v) => node.value(Value::UInt {
                    value: v,
                    bits: 16,
                    radix: Radix::Dec,
                }),
                None => node.diag(Diagnostic::malformed("bad integer")),
            },
            (false, 1) => node.value(Value::Text(hex(&bytes))),
            (false, 14) if !bytes.is_empty() => {
                cx.emit(node.summary(format!("{len} bytes")));
                cx.emit(embedded("Attachment", input.nested(span)));
                continue;
            }
            _ => node.summary(format!("{len} bytes")),
        };
        cx.emit(node);
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn packed_time() {
        // 2024-05-06 07:08:09 packed by hand.
        let (y, mo, d, h, mi, s) = (2024u64, 5u64, 6u64, 7u64, 8u64, 9u64);
        let v = (y << 26) | (mo << 22) | (d << 17) | (h << 12) | (mi << 6) | s;
        let b = &v.to_be_bytes()[3..];
        assert_eq!(kdb_time(b), Some(Some(1_714_979_289)));
    }

    #[test]
    fn xml_summary() {
        let xml = br#"<?xml version="1.0"?><KeePassFile><Meta><Generator>x &amp; y</Generator></Meta>
<Root><Group><Name>Root</Name><Entry><String><Key>Title</Key><Value>T</Value></String>
<String><Key>Password</Key><Value Protected="True">c2VjcmV0</Value></String>
<History><Entry><String><Key>Title</Key><Value>Old</Value></String></Entry></History></Entry>
<Group><Name>Sub</Name></Group></Group><DeletedObjects><DeletedObject/></DeletedObjects></Root></KeePassFile>"#;
        let doc = parse_doc(xml);
        assert!(doc.error.is_none(), "{:?}", doc.error);
        assert_eq!(doc.meta[0].1, "x & y");
        assert_eq!(doc.groups.len(), 2);
        assert_eq!(doc.groups[0].name, "Root");
        assert_eq!(doc.groups[1].name, "Sub");
        assert_eq!(doc.entries.len(), 2);
        assert_eq!(doc.entries[0].text("Title"), "T");
        assert!(doc.entries[0].get("Password").unwrap().value.is_none());
        assert_eq!(doc.entries[0].history, vec![1]);
        assert_eq!(doc.deleted, 1);
    }
}
