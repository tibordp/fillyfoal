//! PuTTY private keys (`.ppk`), versions 2 and 3, as written by PuTTYgen
//! (`ppk_save_sb` in PuTTY's `sshpubk.c`; layout from memory of PuTTY's
//! sources and its documentation's PPK appendix, fixtures synthetic).
//!
//! ```text
//! PuTTY-User-Key-File-<version>: <algorithm>
//! Encryption: none | aes256-cbc
//! Comment: <text>
//! Public-Lines: <n>, then n lines of base64 (the SSH public key blob)
//! [v3, encrypted: Key-Derivation, Argon2-Memory/-Passes/-Parallelism/-Salt]
//! Private-Lines: <n>, then n lines of base64 (private fields, padded)
//! Private-MAC: <hex>
//! ```
//!
//! The MAC covers the algorithm, encryption, comment and both blobs (each
//! as an SSH string, the private one decrypted and padded). Version 2:
//! HMAC-SHA-1 keyed with SHA-1("putty-private-key-file-mac-key" ‖
//! passphrase); AES-256-CBC with a zero IV and the key SHA-1(0 ‖
//! passphrase) ‖ SHA-1(1 ‖ passphrase) (each counter a 32-bit big-endian
//! prefix). Version 3: HMAC-SHA-256, with an empty key when unencrypted;
//! encrypted keys take cipher key, IV and MAC key (32 + 16 + 32 bytes) from
//! Argon2 over the passphrase and `Argon2-Salt`. Private key material is
//! shown by size only.

use crate::codec::crypto;
use crate::codec::crypto::argon2::{Argon2, Params, Variant};
use crate::codec::crypto::{Aes, Hash, Hmac, Sha1, Sha256, cbc_decrypt};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::decode::{Transform, decoded_node, derive_with};
use crate::formats::text::ssh::key_bits;
use crate::formats::util::val::{text, uint};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::secret::{MAX_ATTEMPTS, SecretRequest};
use crate::span::{Origin, Span};
use crate::text::unhex;
use crate::value::Value;

use crate::formats::text::scan::head_lines as header_lines;

declare_format!(pub PPK = "putty-key", "PuTTY private key (PPK)", ["ppk"], "application/x-putty-private-key",
    Probe::Magic(&[(0, b"PuTTY-User-Key-File-")]), ppk);

/// What the private key expansion needs.
#[derive(Clone)]
struct Private {
    input: Input,
    version: u32,
    algorithm: String,
    encryption: String,
    comment: String,
    public: Option<Span>,
    private: Span,
    mac: Option<(String, Span)>,
    /// Version 3 key derivation: variant, memory (KiB), passes,
    /// parallelism, salt.
    argon: Option<(String, u32, u32, u32, Vec<u8>)>,
}

/// The version 3 key derivation lines as read (variant, memory, passes,
/// parallelism, salt).
type ArgonHeader = (
    String,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<Vec<u8>>,
);

async fn ppk(cx: Cx, input: Input) -> Result<()> {
    let all = header_lines(&cx, input.span, 1 << 16).await?;
    let mut version = String::new();
    let mut algorithm = String::new();
    let mut encryption = String::new();
    let mut comment = String::new();
    let mut public = None;
    let mut mac = None;
    let mut argon: ArgonHeader = (String::new(), None, None, None, None);
    // The header values the private key's expansion needs (the MAC comes
    // after the private lines).
    for (line, span) in &all {
        match line.split_once(": ") {
            Some((k, v)) if k.starts_with("PuTTY-User-Key-File-") => {
                version = k.trim_start_matches("PuTTY-User-Key-File-").to_owned();
                algorithm = v.to_owned();
            }
            Some(("Encryption", v)) => encryption = v.to_owned(),
            Some(("Comment", v)) => comment = v.to_owned(),
            Some(("Private-MAC" | "Private-Hash", v)) => mac = Some((v.to_owned(), *span)),
            Some(("Key-Derivation", v)) => argon.0 = v.to_owned(),
            Some(("Argon2-Memory", v)) => argon.1 = v.trim().parse().ok(),
            Some(("Argon2-Passes", v)) => argon.2 = v.trim().parse().ok(),
            Some(("Argon2-Parallelism", v)) => argon.3 = v.trim().parse().ok(),
            Some(("Argon2-Salt", v)) => argon.4 = unhex(v),
            _ => {}
        }
    }
    let argon = match argon {
        (variant, Some(m), Some(p), Some(l), Some(salt)) => Some((variant, m, p, l, salt)),
        _ => None,
    };
    let encrypted = encryption != "none";
    let mut public_blob = Vec::new();
    let mut i = 0usize;
    while let Some((line, span)) = all.get(i) {
        i = i.saturating_add(1);
        let Some((key, value)) = line.split_once(": ") else {
            continue;
        };
        if let Some(n) = key.strip_suffix("-Lines").map(str::to_owned) {
            let count: usize = value.trim().parse().unwrap_or(0);
            let (Some((_, first)), Some((_, last))) = (
                all.get(i),
                all.get(
                    i.saturating_add(count)
                        .saturating_sub(1)
                        .min(all.len().saturating_sub(1)),
                ),
            ) else {
                continue;
            };
            let body = Span::new(
                first.source,
                first.offset,
                last.end().saturating_sub(first.offset),
            );
            i = i.saturating_add(count);
            if n == "Public" {
                let blob_text: String = all
                    .iter()
                    .skip(i.saturating_sub(count))
                    .take(count)
                    .map(|(l, _)| l.as_str())
                    .collect();
                public_blob = crate::formats::text::decode::base64(blob_text.as_bytes()).bytes;
                public = Some(body);
                let kind = public_blob
                    .get(4..)
                    .and_then(|rest| {
                        let len = crate::bytes::u32_be(&public_blob, 0)?;
                        rest.get(..crate::bytes::to_usize(len.into()))
                    })
                    .unwrap_or_default()
                    .to_vec();
                let mut node = decoded_node("Public key", input, body, Transform::Base64);
                let mut what = String::from_utf8_lossy(&kind).into_owned();
                if let Some(bits) = key_bits(&kind, &public_blob) {
                    what = format!("{what}, {bits} bits");
                }
                node = node.summary(what);
                cx.emit(node);
            } else if n == "Private" {
                let state = Private {
                    input,
                    version: version.trim().parse().unwrap_or(0),
                    algorithm: algorithm.clone(),
                    encryption: encryption.clone(),
                    comment: comment.clone(),
                    public,
                    private: body,
                    mac: mac.clone(),
                    argon: argon.clone(),
                };
                cx.emit(
                    Node::new("Private key")
                        .span(body)
                        .summary(if encrypted {
                            format!("encrypted ({encryption}), base64")
                        } else {
                            "base64".to_owned()
                        })
                        .lazy(private_key, state),
                );
            } else {
                cx.emit(Node::new(format!("{n} lines")).span(body));
            }
            continue;
        }
        let mut node = Node::new(key.to_owned()).span(*span).value(text(value));
        if let Some(v) = key.strip_prefix("PuTTY-User-Key-File-") {
            node = node.desc(format!("PPK version {v}; the key algorithm"));
        }
        match key {
            "Encryption" => {
                node = node.desc(match value {
                    "none" => "the private key is not encrypted",
                    "aes256-cbc" => "AES-256-CBC with a key derived from the passphrase",
                    _ => "unknown encryption",
                });
            }
            "Private-MAC" | "Private-Hash" => {
                node = node.desc(if version == "3" {
                    "HMAC-SHA-256 of the key file's contents"
                } else if key == "Private-MAC" {
                    "HMAC-SHA-1 of the key file's contents"
                } else {
                    "SHA-1 hash (version 1)"
                });
            }
            "Argon2-Memory" | "Argon2-Passes" | "Argon2-Parallelism" => {
                if let Ok(v) = value.trim().parse::<u64>() {
                    node = node.value(uint(v, 32));
                    if key == "Argon2-Memory" {
                        node = node.summary("KiB");
                    }
                }
            }
            "Argon2-Salt" => {
                if let Some(salt) = unhex(value) {
                    node = node
                        .value(Value::Bytes(salt.clone()))
                        .summary(format!("{} bytes", salt.len()));
                }
            }
            _ => {}
        }
        cx.emit(node);
    }
    let mut summary = format!("PuTTY v{version} {algorithm} key");
    if let Some(bits) = key_bits(algorithm.as_bytes(), &public_blob) {
        summary = format!("{summary} ({bits} bits)");
    }
    cx.annotate(format!(
        "{summary} {comment:?}, {}",
        if encrypted {
            format!("encrypted ({encryption})")
        } else {
            "unencrypted".to_owned()
        }
    ));
    Ok(())
}

/// The data the MAC covers.
fn mac_data(p: &Private, public: &[u8], private: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in [
        p.algorithm.as_bytes(),
        p.encryption.as_bytes(),
        p.comment.as_bytes(),
        public,
        private,
    ] {
        out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn hmac_with<H: Hash>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<H>::new(key);
    m.update(data);
    m.finish()
}

/// Version 2: the AES key from the passphrase.
fn v2_cipher_key(passphrase: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(40);
    for n in 0u32..2 {
        let mut h = Sha1::new();
        h.update(&n.to_be_bytes());
        h.update(passphrase);
        key.extend(h.finish());
    }
    key.truncate(32);
    key
}

/// Version 2: the MAC key from the passphrase (empty if unencrypted).
fn v2_mac_key(passphrase: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(b"putty-private-key-file-mac-key");
    h.update(passphrase);
    h.finish()
}

/// Version 2 decryption and MAC check with a passphrase: the plaintext and
/// whether the MAC matched.
fn v2_open(
    p: &Private,
    passphrase: &[u8],
    public: &[u8],
    blob: &[u8],
    mac: &[u8],
) -> Option<(Vec<u8>, bool)> {
    let plain = if passphrase.is_empty() {
        blob.to_vec()
    } else {
        cbc_decrypt(&Aes::new(&v2_cipher_key(passphrase))?, &[0; 16], blob)
    };
    let ok = hmac_with::<Sha1>(&v2_mac_key(passphrase), &mac_data(p, public, &plain)) == mac;
    Some((plain, ok))
}

const PROMPT: &str = "Passphrase for the PuTTY private key";

/// Most Argon2 block compressions run for a key (PuTTYgen's defaults are
/// far below: 8 MiB and a pass count tuned to about 100 ms).
const MAX_ARGON2_COST: u64 = 1 << 22;

fn argon_params(p: &Private) -> Option<Params> {
    let (variant, memory, passes, lanes, _) = p.argon.as_ref()?;
    let variant = match variant.as_str() {
        "Argon2d" => Variant::D,
        "Argon2i" => Variant::I,
        "Argon2id" => Variant::Id,
        _ => return None,
    };
    Some(Params {
        variant,
        version: 0x13,
        memory_kib: *memory,
        iterations: *passes,
        lanes: *lanes,
        out_len: 80,
    })
}

async fn private_key(cx: Cx, p: Private) -> Result<()> {
    let (decoded, error) = derive_with(&cx, p.private, Transform::Base64).await?;
    if let Some(e) = error {
        cx.diag(e);
    }
    let blob = cx.read(decoded).await?;
    let public = match p.public {
        Some(span) => {
            let (span, _) = derive_with(&cx, span, Transform::Base64).await?;
            cx.read(span).await?
        }
        None => Vec::new(),
    };
    let mac = p.mac.as_ref().and_then(|(hex, _)| unhex(hex));
    let mac_span = p.mac.as_ref().map(|(_, s)| *s);
    let encrypted = p.encryption != "none";
    let (plain, mac_ok, what) = match (p.version, encrypted) {
        (3, true) if p.encryption == "aes256-cbc" => {
            let Some(mac) = mac else {
                return Err(Diagnostic::malformed("missing or malformed Private-MAC").at(p.private));
            };
            if blob.len().checked_rem(16) != Some(0) {
                return Err(
                    Diagnostic::malformed("encrypted length is not a multiple of 16").at(decoded),
                );
            }
            let Some(params) = argon_params(&p) else {
                return Err(
                    Diagnostic::malformed("missing or malformed Argon2 parameters").at(p.private),
                );
            };
            if params.blocks().saturating_mul(1024) > cx.limits().max_derived
                || params.cost() > MAX_ARGON2_COST
            {
                cx.emit(
                    Node::new("Encrypted data")
                        .span(decoded)
                        .diag(Diagnostic::limit(format!(
                            "Argon2 with {} KiB and {} passes exceeds the limits",
                            params.memory_kib, params.iterations
                        ))),
                );
                return Ok(());
            }
            let salt = p.argon.as_ref().map(|a| a.4.clone()).unwrap_or_default();
            let mut opened = None;
            for attempt in 0..MAX_ATTEMPTS {
                let request = SecretRequest::password(p.input.span, PROMPT, attempt);
                let Some(secret) = cx.secret(request).await else {
                    break;
                };
                let Some(mut state) = Argon2::new(params.clone(), secret.expose(), &salt, &[], &[])
                else {
                    break;
                };
                crypto::run(&cx, &mut state).await;
                let keys = state.finish();
                let (Some(key), Some(iv), Some(mac_key)) =
                    (keys.get(..32), keys.get(32..48), keys.get(48..80))
                else {
                    break;
                };
                let Some(aes) = Aes::new(key) else {
                    break;
                };
                let plain = cbc_decrypt(&aes, iv, &blob);
                if hmac_with::<Sha256>(mac_key, &mac_data(&p, &public, &plain)) == mac {
                    opened = Some(plain);
                    break;
                }
            }
            let Some(plain) = opened else {
                cx.emit(
                    Node::new("Encrypted data")
                        .span(decoded)
                        .diag(Diagnostic::unsupported(
                            "encrypted (no or wrong passphrase)",
                        )),
                );
                return Ok(());
            };
            (plain, Some(true), "HMAC-SHA-256")
        }
        (3, false) => {
            let ok = mac
                .as_ref()
                .map(|m| hmac_with::<Sha256>(&[], &mac_data(&p, &public, &blob)) == *m);
            (blob, ok, "HMAC-SHA-256")
        }
        (2, _) if p.encryption == "none" || p.encryption == "aes256-cbc" => {
            let Some(mac) = mac else {
                return Err(Diagnostic::malformed("missing or malformed Private-MAC").at(p.private));
            };
            if !encrypted {
                let (plain, ok) = v2_open(&p, b"", &public, &blob, &mac).unwrap_or_default();
                (plain, Some(ok), "HMAC-SHA-1")
            } else {
                if blob.len().checked_rem(16) != Some(0) {
                    return Err(
                        Diagnostic::malformed("encrypted length is not a multiple of 16")
                            .at(decoded),
                    );
                }
                let verify = |s: &crate::secret::Secret| {
                    !s.expose().is_empty()
                        && v2_open(&p, s.expose(), &public, &blob, &mac).is_some_and(|(_, ok)| ok)
                };
                let Some(secret) = cx.unlock(p.input.span, PROMPT, verify).await else {
                    cx.emit(Node::new("Encrypted data").span(decoded).diag(
                        Diagnostic::unsupported("encrypted (no or wrong passphrase)"),
                    ));
                    return Ok(());
                };
                let (plain, ok) =
                    v2_open(&p, secret.expose(), &public, &blob, &mac).unwrap_or_default();
                (plain, Some(ok), "HMAC-SHA-1")
            }
        }
        _ if encrypted => {
            cx.emit(
                Node::new("Encrypted data")
                    .span(decoded)
                    .diag(Diagnostic::unsupported(format!(
                        "{} in PPK version {}",
                        p.encryption, p.version
                    ))),
            );
            return Ok(());
        }
        _ => (blob, None, "unverified"),
    };
    let mut node = Node::new("MAC check").summary(match mac_ok {
        Some(true) => format!("{what}, verified"),
        Some(false) => format!("{what}, mismatch"),
        None => what.to_owned(),
    });
    if let Some(s) = mac_span {
        node = node.span(s);
    }
    if mac_ok == Some(false) {
        node = node.diag(Diagnostic::malformed(
            "the MAC does not match (corrupt or edited key file)",
        ));
    }
    cx.emit(node);
    let span = if encrypted {
        cx.add_derived(
            Origin {
                parent: decoded,
                transform: "ppk-aes256-cbc",
            },
            plain,
            decoded.len,
            None,
        )?
        .span
    } else {
        decoded
    };
    private_fields(&cx, &p.algorithm, span).await
}

/// Field names of PuTTY's private blob, per algorithm.
fn field_names(algorithm: &str) -> &'static [&'static str] {
    match algorithm {
        "ssh-rsa" => &[
            "Private exponent (d)",
            "Prime p",
            "Prime q",
            "CRT coefficient (iqmp)",
        ],
        "ssh-dss" => &["Private key (x)"],
        "ssh-ed25519" | "ssh-ed448" => &["Secret key"],
        a if a.starts_with("ecdsa-sha2-") => &["Private scalar (d)"],
        _ => &[],
    }
}

async fn private_fields(cx: &Cx, algorithm: &str, span: Span) -> Result<()> {
    let mut cur = Cursor::new(cx, span, Endian::Big);
    let names = field_names(algorithm);
    let mut n = 0usize;
    while cur.remaining() >= 4 && n < 16 {
        let start = cur.pos();
        let len = cur.u32().await?;
        if u64::from(len) > cur.remaining() || (names.is_empty() && len == 0) {
            cur.seek(start);
            break;
        }
        cur.skip(len.into());
        let name = names.get(n).map_or_else(
            || format!("Field {}", n.saturating_add(1)),
            |s| (*s).to_owned(),
        );
        cx.emit(
            Node::new(name)
                .span(cur.since(start))
                .summary(format!("present, {len} bytes"))
                .desc("private key material (not shown)"),
        );
        n = n.saturating_add(1);
        if !names.is_empty() && n == names.len() {
            break;
        }
    }
    if !cur.at_end() {
        cx.emit(
            Node::new("Padding")
                .span(cur.span(cur.remaining()))
                .summary(format!("{} bytes", cur.remaining())),
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::text::hex_lower;

    #[test]
    fn argon2_80_byte_output_matches_argon2_cffi() {
        // `argon2.low_level.hash_secret_raw(b"fillyfoal", bytes(range(16)),
        // 1, 64, 1, 80, Type.ID)`: the PPK v3 key material length.
        let params = Params {
            variant: Variant::Id,
            version: 0x13,
            memory_kib: 64,
            iterations: 1,
            lanes: 1,
            out_len: 80,
        };
        let salt: Vec<u8> = (0..16).collect();
        let mut a = Argon2::new(params, b"fillyfoal", &salt, &[], &[]).unwrap();
        while !a.step(64) {}
        let hex = hex_lower(&a.finish());
        assert_eq!(
            hex,
            "6ebd0e3db8f0afbf7762bb78e8dfefec15a49b9ceea97d8b5e9b95a204d551563b984f20592a4504f52b67891c63f39359cb4885aee38a971ddef308c72388656015a7e02ff1e026973ed690c3994852"
        );
    }
}
