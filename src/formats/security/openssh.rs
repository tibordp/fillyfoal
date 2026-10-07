//! OpenSSH private keys: the binary `openssh-key-v1` format (inside the
//! `-----BEGIN OPENSSH PRIVATE KEY-----` armor), as described in OpenSSH's
//! `PROTOCOL.key` and written by `sshkey_private_to_blob2`.
//!
//! ```text
//! "openssh-key-v1\0"
//! string ciphername, string kdfname, string kdfoptions
//! u32 number of keys N, N × string public key blob
//! string private section (encrypted unless the cipher is "none")
//! [authentication tag, for AEAD ciphers, after the string]
//!
//! private section: u32 check1, u32 check2 (equal), N × (key type,
//! private key fields, string comment), padding 1, 2, 3, … to the block size
//! ```
//!
//! Encrypted keys use `bcrypt_pbkdf` over the passphrase and the salt and
//! rounds from the KDF options; the derived bytes are the cipher key and IV.
//! A passphrase is checked by the check values (and the AEAD tag). The
//! private key fields per type follow `sshkey_private_serialize`; the
//! layouts of the FIDO (`sk-*`) types and of certificates are from memory
//! of OpenSSH's sources, not checked against real keys. Key material is
//! never shown: secret fields show only their size.

use crate::codec::crypto::bcrypt::BcryptPbkdf;
use crate::codec::crypto::chacha::openssh_chachapoly_open;
use crate::codec::crypto::gcm::aes_gcm_open;
use crate::codec::crypto::{Aes, TripleDes, cbc_decrypt};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::decode::preview;
use crate::formats::text::ssh::{BLOB, key_bits, mpint_node, ssh_string, string_node};
use crate::formats::text::{plural, text_node};
use crate::formats::{Input, Probe, embedded_as};
use crate::node::Node;
use crate::secret::{MAX_ATTEMPTS, SecretRequest};
use crate::span::{Origin, Span};
use crate::value::{FlagTable, Radix, Value, decode_flags, flag};

declare_format!(pub OPENSSH_KEY = "openssh-key", "OpenSSH private key", [], "application/octet-stream",
    Probe::Magic(&[(0, b"openssh-key-v1\0")]), dissect);

const BE: Endian = Endian::Big;

/// Highest bcrypt round count we derive keys for. `ssh-keygen` defaults
/// to 16 and users raise it to a few hundred; each round is one bcrypt
/// hash per 32 bytes of key material.
const MAX_ROUNDS: u32 = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    None,
    Cbc,
    Ctr,
    Gcm,
    ChaChaPoly,
    TripleDesCbc,
}

/// A cipher of OpenSSH's `cipher.c` table.
#[derive(Debug)]
struct CipherSpec {
    name: &'static str,
    key: usize,
    iv: usize,
    block: usize,
    tag: usize,
    mode: Mode,
}

const fn spec(
    name: &'static str,
    key: usize,
    iv: usize,
    block: usize,
    tag: usize,
    mode: Mode,
) -> CipherSpec {
    CipherSpec {
        name,
        key,
        iv,
        block,
        tag,
        mode,
    }
}

static CIPHERS: &[CipherSpec] = &[
    spec("none", 0, 0, 8, 0, Mode::None),
    spec("aes128-cbc", 16, 16, 16, 0, Mode::Cbc),
    spec("aes192-cbc", 24, 16, 16, 0, Mode::Cbc),
    spec("aes256-cbc", 32, 16, 16, 0, Mode::Cbc),
    spec("rijndael-cbc@lysator.liu.se", 32, 16, 16, 0, Mode::Cbc),
    spec("aes128-ctr", 16, 16, 16, 0, Mode::Ctr),
    spec("aes192-ctr", 24, 16, 16, 0, Mode::Ctr),
    spec("aes256-ctr", 32, 16, 16, 0, Mode::Ctr),
    spec("aes128-gcm@openssh.com", 16, 12, 16, 16, Mode::Gcm),
    spec("aes256-gcm@openssh.com", 32, 12, 16, 16, Mode::Gcm),
    spec(
        "chacha20-poly1305@openssh.com",
        64,
        0,
        8,
        16,
        Mode::ChaChaPoly,
    ),
    spec("3des-cbc", 24, 8, 8, 0, Mode::TripleDesCbc),
];

fn cipher_desc(mode: Mode) -> &'static str {
    match mode {
        Mode::None => "not encrypted",
        Mode::Cbc => "AES in CBC mode",
        Mode::Ctr => "AES in counter mode",
        Mode::Gcm => "AES-GCM (authenticated)",
        Mode::ChaChaPoly => "ChaCha20 with a Poly1305 tag (authenticated)",
        Mode::TripleDesCbc => "Triple DES in CBC mode",
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// How a private key field is shown.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A public string (text or bytes).
    Public,
    /// A public multiple-precision integer.
    PublicInt,
    /// Key material: shown by size only.
    Secret,
    /// A single byte (FIDO flags).
    Byte,
    /// An embedded certificate blob.
    Certificate,
}

/// FIDO key flags (`SSH_SK_*` in OpenSSH's `sk-api.h`).
const SK_FLAGS: FlagTable = &[
    flag(0x01, "user presence required"),
    flag(0x04, "user verification required"),
    flag(0x10, "force operation"),
    flag(0x20, "resident key"),
];

type Fields = &'static [(&'static str, Kind)];

const RSA_PUB: Fields = &[
    ("Modulus (n)", Kind::PublicInt),
    ("Public exponent (e)", Kind::PublicInt),
];
const RSA_PRIV: Fields = &[
    ("Private exponent (d)", Kind::Secret),
    ("CRT coefficient (iqmp)", Kind::Secret),
    ("Prime p", Kind::Secret),
    ("Prime q", Kind::Secret),
];
const DSA_PUB: Fields = &[
    ("p", Kind::PublicInt),
    ("q", Kind::PublicInt),
    ("g", Kind::PublicInt),
    ("y", Kind::PublicInt),
];
const DSA_PRIV: Fields = &[("Private key (x)", Kind::Secret)];
const ECDSA_PUB: Fields = &[("Curve", Kind::Public), ("Public point (Q)", Kind::Public)];
const ECDSA_PRIV: Fields = &[("Private scalar (d)", Kind::Secret)];
const ED25519: Fields = &[
    ("Public key", Kind::Public),
    ("Private key (seed ‖ public key)", Kind::Secret),
];
const SK_PRIV: Fields = &[
    ("Flags", Kind::Byte),
    ("Key handle", Kind::Secret),
    ("Reserved", Kind::Public),
];

/// The private section's fields after the key type, per type.
fn private_fields(kind: &[u8]) -> Option<Vec<(&'static str, Kind)>> {
    let cert = kind.ends_with(b"-cert-v01@openssh.com");
    let base = kind.strip_suffix(b"-cert-v01@openssh.com").unwrap_or(kind);
    let mut out: Vec<(&'static str, Kind)> = Vec::new();
    if cert {
        out.push(("Certificate", Kind::Certificate));
    }
    let public = |out: &mut Vec<_>, f: Fields| {
        if !cert {
            out.extend_from_slice(f);
        }
    };
    match base {
        b"ssh-rsa" => {
            public(&mut out, RSA_PUB);
            out.extend_from_slice(RSA_PRIV);
        }
        b"ssh-dss" => {
            public(&mut out, DSA_PUB);
            out.extend_from_slice(DSA_PRIV);
        }
        b"ssh-ed25519" => out.extend_from_slice(ED25519),
        b"sk-ssh-ed25519@openssh.com" => {
            if !cert {
                out.push(("Public key", Kind::Public));
                out.push(("Application", Kind::Public));
            }
            out.extend_from_slice(SK_PRIV);
        }
        b"sk-ecdsa-sha2-nistp256@openssh.com" => {
            if !cert {
                out.extend_from_slice(ECDSA_PUB);
                out.push(("Application", Kind::Public));
            }
            out.extend_from_slice(SK_PRIV);
        }
        _ if base.starts_with(b"ecdsa-sha2-") => {
            public(&mut out, ECDSA_PUB);
            out.extend_from_slice(ECDSA_PRIV);
        }
        _ => return None,
    }
    Some(out)
}

/// Salt and rounds from bcrypt KDF options.
fn bcrypt_options(options: &[u8]) -> Option<(Vec<u8>, u32)> {
    let salt_len = crate::bytes::to_usize(crate::bytes::u32_be(options, 0)?.into());
    let salt = options.get(4..4usize.checked_add(salt_len)?)?.to_vec();
    let rounds = crate::bytes::u32_be(options, 4usize.saturating_add(salt_len))?;
    Some((salt, rounds))
}

/// Everything the private section needs once found.
#[derive(Clone, Copy)]
struct Section {
    input: Input,
    /// The (possibly encrypted) private section, without its length.
    data: Span,
    /// Number of keys.
    count: u32,
}

#[derive(Clone, Copy)]
struct Encrypted {
    section: Section,
    cipher: &'static CipherSpec,
    kdf_options: Span,
    tag: Span,
}

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, BE);
    cx.emit(
        Node::new("Magic")
            .span(cur.span(15))
            .value(Value::Text("openssh-key-v1".to_owned())),
    );
    cur.skip(15);
    let (cipher_name, span) = ssh_string(&mut cur).await?;
    let cipher = CIPHERS.iter().find(|c| c.name.as_bytes() == cipher_name);
    let mut node = string_node("Cipher", &cipher_name, span);
    match cipher {
        Some(c) => node = node.desc(cipher_desc(c.mode)),
        None => node = node.diag(Diagnostic::unsupported("unknown cipher")),
    }
    cx.emit(node);
    let (kdf, span) = ssh_string(&mut cur).await?;
    cx.emit(string_node("KDF", &kdf, span).desc(match kdf.as_slice() {
        b"none" => "no key derivation (unencrypted key)",
        b"bcrypt" => "bcrypt_pbkdf: the passphrase is stretched with bcrypt and SHA-512",
        _ => "unknown key derivation",
    }));
    let (options, options_span) = ssh_string(&mut cur).await?;
    let options_body = options_span.sub(4, options_span.len.saturating_sub(4));
    let bcrypt = (kdf == b"bcrypt")
        .then(|| bcrypt_options(&options))
        .flatten();
    let mut node = Node::new("KDF options").span(options_span);
    if let Some((salt, rounds)) = &bcrypt {
        node = node
            .summary(format!("{}-byte salt, {rounds} rounds", salt.len()))
            .lazy(kdf_options, options_body);
    } else if options.is_empty() {
        node = node.summary("empty");
    } else {
        node = node.summary(format!("{} bytes", options.len()));
    }
    cx.emit(node);
    let start = cur.pos();
    let count = cur.u32().await?;
    cx.emit(
        Node::new("Number of keys")
            .span(cur.since(start))
            .value(Value::UInt {
                value: count.into(),
                bits: 32,
                radix: Radix::Dec,
            }),
    );
    let mut summary = String::from("OpenSSH private key");
    for i in 0..count.min(64) {
        let (blob, span) = ssh_string(&mut cur).await?;
        let key = span.sub(4, span.len.saturating_sub(4));
        let kind_len = crate::bytes::u32_be(&blob, 0).unwrap_or(0);
        let kind = blob
            .get(4..4usize.saturating_add(crate::bytes::to_usize(kind_len.into())))
            .unwrap_or_default();
        let mut what = text(kind);
        if let Some(bits) = key_bits(kind, &blob) {
            what = format!("{what}, {bits} bits");
        }
        if i == 0 {
            summary = format!("{summary}, {what}");
        }
        cx.emit(
            embedded_as(
                format!("Public key {}", i.saturating_add(1)),
                input.nested(key),
                &BLOB,
            )
            .summary(what),
        );
    }
    if count > 64 {
        cx.diag(Diagnostic::limit(format!(
            "only the first 64 of {count} keys are shown"
        )));
        cx.annotate(summary);
        return Ok(());
    }
    let start = cur.pos();
    let len = cur.u32().await?;
    let data = cur.span(len.into());
    if data.len < u64::from(len) {
        cx.emit(
            Node::new("Private section")
                .span(cur.since(start))
                .diag(Diagnostic::truncated(
                    input.span.sub(cur.pos(), len.into()),
                    data.len,
                )),
        );
        cx.annotate(summary);
        return Ok(());
    }
    cur.skip(len.into());
    let section = Section { input, data, count };
    let encrypted = cipher_name != b"none";
    if encrypted {
        let tag_len = cipher.map_or(0, |c| c.tag);
        let tag = cur.span(crate::bytes::to_u64(tag_len));
        cur.skip(tag.len);
        let mut node = Node::new("Private section (encrypted)")
            .span(cur.since(start))
            .summary(format!("{len} bytes, {}", text(&cipher_name)));
        node = match (cipher, &bcrypt) {
            (Some(_), Some((_, rounds))) if *rounds > MAX_ROUNDS => node.diag(
                Diagnostic::unsupported(format!("{rounds} bcrypt rounds (more than {MAX_ROUNDS})")),
            ),
            (Some(c), Some(_)) => node.lazy(
                decrypt,
                Encrypted {
                    section,
                    cipher: c,
                    kdf_options: options_body,
                    tag,
                },
            ),
            (None, _) => node.diag(Diagnostic::unsupported(format!(
                "cipher {}",
                text(&cipher_name)
            ))),
            (Some(_), None) => node.diag(Diagnostic::unsupported(format!(
                "key derivation {}",
                text(&kdf)
            ))),
        };
        cx.emit(node);
        summary = format!(
            "{summary}, encrypted ({}{})",
            text(&cipher_name),
            bcrypt
                .as_ref()
                .map(|(_, r)| format!(", {r} bcrypt rounds"))
                .unwrap_or_default()
        );
    } else {
        cx.emit(
            Node::new("Private section")
                .span(cur.since(start))
                .summary(plural(count.into(), "key", "keys"))
                .lazy(private_section, section),
        );
        summary = format!("{summary}, unencrypted");
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(cur.span(cur.remaining())));
    }
    cx.annotate(summary);
    Ok(())
}

async fn kdf_options(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    let (salt, s) = ssh_string(&mut cur).await?;
    cx.emit(
        Node::new("Salt")
            .span(s)
            .value(Value::Bytes(salt.clone()))
            .summary(format!("{} bytes", salt.len())),
    );
    let start = cur.pos();
    let rounds = cur.u32().await?;
    cx.emit(
        Node::new("Rounds")
            .span(cur.since(start))
            .value(Value::UInt {
                value: rounds.into(),
                bits: 32,
                radix: Radix::Dec,
            })
            .desc("bcrypt hashes per 32 bytes of derived key"),
    );
    Ok(())
}

async fn private_section(cx: Cx, section: Section) -> Result<()> {
    private_contents(&cx, section, 8).await
}

/// Emits the check values, keys and padding of a plaintext private section.
async fn private_contents(cx: &Cx, section: Section, block: usize) -> Result<()> {
    let Section { input, data, count } = section;
    let mut cur = Cursor::new(cx, data, BE);
    let mut checks = [0u32; 2];
    for (name, check) in ["Check 1", "Check 2"].into_iter().zip(&mut checks) {
        let start = cur.pos();
        *check = cur.u32().await?;
        cx.emit(Node::new(name).span(cur.since(start)).value(Value::UInt {
            value: (*check).into(),
            bits: 32,
            radix: Radix::Hex,
        }));
    }
    if checks[0] != checks[1] {
        cx.diag(
            Diagnostic::malformed("the check values differ (wrong passphrase or corrupt key)")
                .at(data.sub(0, 8)),
        );
    }
    for _ in 0..count.min(64) {
        let start = cur.pos();
        let (kind, _) = ssh_string(&mut cur).await?;
        let Some(fields) = private_fields(&kind) else {
            cx.emit(
                Node::new(text(&kind))
                    .span(cur.span(cur.remaining()))
                    .diag(Diagnostic::unsupported("unknown key type")),
            );
            return Ok(());
        };
        for &(_, k) in &fields {
            if k == Kind::Byte {
                cur.u8().await?;
            } else {
                ssh_string(&mut cur).await?;
            }
        }
        let (comment, _) = ssh_string(&mut cur).await?;
        let kind_text = text(&kind);
        let span = cur.since(start);
        cx.emit(
            Node::new(if comment.is_empty() {
                kind_text.clone()
            } else {
                text(&comment)
            })
            .span(span)
            .summary(kind_text)
            .lazy(private_key, (input, span)),
        );
    }
    if !cur.at_end() {
        let pad_span = cur.span(cur.remaining());
        let pad = cx.read_avail(pad_span).await?;
        let mut node = Node::new("Padding")
            .span(pad_span)
            .summary(format!("{} bytes", pad.len()));
        let expected = pad.iter().zip(1u8..).all(|(&b, i)| b == i);
        if !expected || pad.len() >= block.max(8) {
            node = node.diag(Diagnostic::warning(
                "padding is not 1, 2, 3, … up to the block size",
            ));
        }
        cx.emit(node);
    }
    Ok(())
}

async fn private_key(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    let (kind, s) = ssh_string(&mut cur).await?;
    cx.emit(string_node("Key type", &kind, s));
    for (name, k) in private_fields(&kind).unwrap_or_default() {
        let start = cur.pos();
        if k == Kind::Byte {
            let flags = cur.u8().await?;
            cx.emit(Node::new(name).span(cur.since(start)).value({
                let (set, unknown) = decode_flags(SK_FLAGS, flags.into());
                Value::Flags {
                    raw: flags.into(),
                    bits: 8,
                    set,
                    unknown,
                }
            }));
            continue;
        }
        let (data, s) = ssh_string(&mut cur).await?;
        cx.emit(match k {
            Kind::Secret => Node::new(name)
                .span(s)
                .summary(format!("present, {} bytes", data.len()))
                .desc("private key material (not shown)"),
            Kind::PublicInt => mpint_node(name, &data, s),
            Kind::Certificate => {
                embedded_as(name, input.nested(s.sub(4, s.len.saturating_sub(4))), &BLOB)
            }
            _ => string_node(name, &data, s),
        });
    }
    let (comment, s) = ssh_string(&mut cur).await?;
    cx.emit(text_node("Comment", s, &preview(&text(&comment), 200)));
    Ok(())
}

/// Decrypts `data` with derived key material; returns the plaintext and
/// whether the AEAD tag (if any) verified.
fn decrypt_with(
    c: &CipherSpec,
    material: &[u8],
    data: &[u8],
    tag: &[u8],
) -> Option<(Vec<u8>, bool)> {
    let key = material.get(..c.key)?;
    let iv = material.get(c.key..c.key.saturating_add(c.iv))?;
    Some(match c.mode {
        Mode::None => (data.to_vec(), true),
        Mode::Cbc => (cbc_decrypt(&Aes::new(key)?, iv, data), true),
        Mode::TripleDesCbc => (cbc_decrypt(&TripleDes::new(key)?, iv, data), true),
        Mode::Ctr => {
            let aes = Aes::new(key)?;
            let mut counter = u128::from_be_bytes(iv.try_into().ok()?);
            let mut out = Vec::with_capacity(data.len());
            for chunk in data.chunks(16) {
                let mut ks = counter.to_be_bytes();
                aes.encrypt_block(&mut ks);
                out.extend(chunk.iter().zip(ks).map(|(a, b)| a ^ b));
                counter = counter.wrapping_add(1);
            }
            (out, true)
        }
        Mode::Gcm => aes_gcm_open(&Aes::new(key)?, iv.try_into().ok()?, &[], data, tag),
        Mode::ChaChaPoly => openssh_chachapoly_open(key, 0, data, tag),
    })
}

const PROMPT: &str = "Passphrase for the OpenSSH private key";

async fn decrypt(cx: Cx, e: Encrypted) -> Result<()> {
    let Encrypted {
        section,
        cipher,
        kdf_options,
        tag,
    } = e;
    let options = cx.read(kdf_options).await?;
    let (salt, rounds) = bcrypt_options(&options)
        .ok_or_else(|| Diagnostic::malformed("malformed bcrypt options").at(kdf_options))?;
    let data = cx.read(section.data).await?;
    let tag_bytes = cx.read(tag).await?;
    if data.len().checked_rem(cipher.block).is_some_and(|r| r != 0) {
        return Err(Diagnostic::malformed(format!(
            "encrypted length is not a multiple of the {}-byte block",
            cipher.block
        ))
        .at(section.data));
    }
    let mut plain = None;
    for attempt in 0..MAX_ATTEMPTS {
        let request = SecretRequest::password(section.input.span, PROMPT, attempt);
        let Some(secret) = cx.secret(request).await else {
            break;
        };
        let Some(mut kdf) = BcryptPbkdf::new(
            secret.expose(),
            &salt,
            rounds,
            cipher.key.saturating_add(cipher.iv),
        ) else {
            continue;
        };
        while !kdf.done() {
            kdf.step();
            cx.checkpoint().await;
        }
        let material = kdf.finish();
        let Some((out, tag_ok)) = decrypt_with(cipher, &material, &data, &tag_bytes) else {
            continue;
        };
        let checks_match = out.len() >= 8 && out.get(..4) == out.get(4..8);
        if checks_match && tag_ok {
            plain = Some(out);
            break;
        }
    }
    let Some(plain) = plain else {
        cx.emit(
            Node::new("Encrypted data")
                .span(section.data)
                .diag(Diagnostic::unsupported(
                    "encrypted (no or wrong passphrase)",
                )),
        );
        return Ok(());
    };
    if cipher.tag > 0 {
        cx.emit(
            Node::new("Authentication tag")
                .span(tag)
                .summary("verified")
                .desc(cipher_desc(cipher.mode)),
        );
    }
    let decrypted = cx.add_derived(
        Origin {
            parent: section.data,
            transform: "openssh-key-decrypt",
        },
        plain,
        section.data.len,
        None,
    )?;
    private_contents(
        &cx,
        Section {
            data: decrypted.span,
            ..section
        },
        cipher.block,
    )
    .await
}
