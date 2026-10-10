//! Desktop password stores: GNOME Keyring files (`.keyring`) and KDE
//! KWallet files (`.kwl`). Both keep a cleartext index (item attributes or
//! name hashes) in front of the encrypted secrets.

use crate::codec::crypto::{Aes, Hash, Md5, Sha256, cbc_decrypt};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::secret::{MAX_ATTEMPTS, SecretRequest};
use crate::span::{Origin, Span};
use crate::text::hex_lower;
use crate::value::{EnumTable, FlagTable, Value, decode_flags, flag, lookup};

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// GNOME Keyring (gnome-keyring's gkm-secret-binary.c): a cleartext header and
// item index (attribute names with MD5-hashed values), then the items'
// secrets, display names, times, attribute values and ACLs, AES-128-CBC
// encrypted under a key and IV from the password and salt by iterated
// SHA-256 (egg_symkey_generate_simple), starting with an MD5 of the rest.

declare_format!(pub GNOME_KEYRING = "gnome-keyring", "GNOME Keyring file", ["keyring"], "application/x-gnome-keyring",
    Probe::Magic(&[(0, b"GnomeKeyring\n\r\0\n")]), gnome_keyring);

const ITEM_TYPES: EnumTable = &[
    (0, "generic secret"),
    (1, "network password"),
    (2, "note"),
    (3, "chained keyring password"),
    (4, "encryption key password"),
    (0x100, "public key storage"),
];

const ATTRIBUTE_TYPES: EnumTable = &[(0, "string"), (1, "uint32")];

const ACCESS_TYPES: FlagTable = &[flag(1, "read"), flag(2, "write"), flag(4, "remove")];

/// Most items and attributes per item read.
const MAX_ITEMS: u32 = 100_000;
const MAX_ATTRIBUTES: u32 = 1024;
/// Largest encrypted part decrypted.
const MAX_ENCRYPTED: u64 = 16 << 20;
/// Most key-derivation rounds run (gnome-keyring picks 1000 to 4095).
const MAX_ITERATIONS: u32 = 1 << 20;

/// A keyring string: u32 length (0xffffffff for none), then UTF-8.
async fn kr_string(cur: &mut Cursor<'_>) -> Result<(Option<String>, Span)> {
    let start = cur.pos();
    let len = cur.u32().await?;
    if len == u32::MAX {
        return Ok((None, cur.since(start)));
    }
    if u64::from(len) > cur.remaining() {
        return Err(Diagnostic::malformed("string longer than the file").at(cur.since(start)));
    }
    let raw = cur.bytes(len.into()).await?;
    Ok((
        Some(String::from_utf8_lossy(&raw).into_owned()),
        cur.since(start),
    ))
}

fn string_node(
    name: impl Into<std::borrow::Cow<'static, str>>,
    value: Option<String>,
    span: Span,
) -> Node {
    let node = Node::new(name).span(span);
    match value {
        Some(v) => node.value(text(v)),
        None => node.summary("none"),
    }
}

/// Header fields the decryption needs.
#[derive(Clone)]
struct KeyringHeader {
    iterations: u32,
    salt: Vec<u8>,
    /// The IDs of the items, in order.
    ids: Vec<u32>,
}

async fn gnome_keyring(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    cx.emit(
        Node::new("Signature")
            .span(cur.span(16))
            .value(Value::Bytes(cx.read(file.sub(0, 16)).await?)),
    );
    cur.skip(16);
    let vspan = cur.span(4);
    let v = cur.bytes(4).await?;
    let get = |i: usize| v.get(i).copied().unwrap_or(0);
    cx.emit(
        Node::new("Version")
            .span(vspan)
            .value(text(format!("{}.{}", get(0), get(1))))
            .summary(format!(
                "{}, {}",
                if get(2) == 0 {
                    "AES-128-CBC"
                } else {
                    "unknown cipher"
                },
                if get(3) == 0 {
                    "iterated SHA-256 key derivation"
                } else {
                    "unknown key derivation"
                }
            )),
    );
    let (name, span) = kr_string(&mut cur).await?;
    let name = name.unwrap_or_default();
    cx.emit(
        Node::new("Keyring name")
            .span(span)
            .value(text(name.clone())),
    );
    let fixed = cur.span(52);
    let block = cx.block(fixed).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u64("Created").timestamp().emit()?;
    f.u64("Modified").timestamp().emit()?;
    f.u32("Flags")
        .hex()
        .desc("1: lock on idle, 2: lock after a timeout")
        .emit()?;
    f.u32("Lock timeout (s)").emit()?;
    let iterations = f.u32("Hash iterations").emit()?;
    let salt = f.bytes("Salt", 8).emit()?;
    f.bytes("Reserved", 16).emit()?;
    cur.skip(52);
    let count_span = cur.span(4);
    let count = cur.u32().await?;
    cx.emit(
        Node::new("Number of items")
            .span(count_span)
            .value(uint(count, 32)),
    );
    let list_start = cur.pos();
    let mut kinds = Vec::new();
    for _ in 0..count.min(MAX_ITEMS) {
        let start = cur.pos();
        let id = cur.u32().await?;
        let kind = cur.u32().await?;
        let attrs = cur.u32().await?;
        let mut names = Vec::new();
        for _ in 0..attrs.min(MAX_ATTRIBUTES) {
            let (n, _) = kr_string(&mut cur).await?;
            let t = cur.u32().await?;
            if t == 0 {
                kr_string(&mut cur).await?;
            } else {
                cur.skip(4);
            }
            names.push(n.unwrap_or_default());
        }
        kinds.push(id);
        let span = cur.since(start);
        cx.push(
            Node::new(format!("Item {id}"))
                .span(span)
                .value(Value::Enum {
                    raw: kind.into(),
                    bits: 32,
                    name: lookup(ITEM_TYPES, kind.into()),
                })
                .summary(format!("hashed attributes: {}", names.join(", ")))
                .lazy(crate::expander!(self::gk_item: Span), span),
        )
        .await;
    }
    let _ = list_start;
    let len_span = cur.span(4);
    let enc = u64::from(cur.u32().await?);
    cx.emit(
        Node::new("Encrypted size")
            .span(len_span)
            .value(uint(enc, 32)),
    );
    let encrypted = cur.span(enc);
    let header = KeyringHeader {
        iterations,
        salt,
        ids: kinds,
    };
    cx.emit(
        Node::new("Encrypted data")
            .span(encrypted)
            .summary(format!("{}, AES-128-CBC", size(enc)))
            .lazy(
                crate::expander!(self::gk_encrypted: (Input, Span, KeyringHeader)),
                (input, encrypted, header),
            ),
    );
    cx.annotate(format!(
        "GNOME Keyring {name:?}, {count} items, {} encrypted",
        size(enc)
    ));
    Ok(())
}

/// A cleartext item: its ID, type and hashed attributes.
async fn gk_item(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    let at = cur.pos();
    let id = cur.u32().await?;
    cx.emit(Node::new("ID").span(cur.since(at)).value(uint(id, 32)));
    let at = cur.pos();
    let kind = cur.u32().await?;
    cx.emit(Node::new("Type").span(cur.since(at)).value(Value::Enum {
        raw: kind.into(),
        bits: 32,
        name: lookup(ITEM_TYPES, kind.into()),
    }));
    let at = cur.pos();
    let n = cur.u32().await?;
    cx.emit(
        Node::new("Attribute count")
            .span(cur.since(at))
            .value(uint(n, 32)),
    );
    for _ in 0..n.min(MAX_ATTRIBUTES) {
        let start = cur.pos();
        let (name, _) = kr_string(&mut cur).await?;
        let t = cur.u32().await?;
        let node = Node::new(name.unwrap_or_default());
        let node = if t == 0 {
            let (hash, _) = kr_string(&mut cur).await?;
            node.value(text(hash.unwrap_or_default()))
                .summary("MD5 of the string value")
        } else {
            let h = cur.u32().await?;
            node.value(hex(h, 32)).summary("hashed integer value")
        };
        cx.emit(node.span(cur.since(start)).desc(format!(
            "{} attribute",
            lookup(ATTRIBUTE_TYPES, t.into()).unwrap_or("unknown")
        )));
    }
    Ok(())
}

/// Key and IV from the password: SHA-256 of (previous digest, password,
/// salt), re-hashed `iterations - 1` times; one digest gives both.
async fn gk_derive(cx: &Cx, password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(password);
    h.update(salt);
    let mut digest = h.finish();
    for i in 1..iterations {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        digest = Sha256::digest(&digest);
    }
    digest
}

/// AES-128-CBC decryption a chunk at a time, charging for it.
async fn gk_decrypt(cx: &Cx, key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let aes = Aes::new(key)?;
    let mut out = Vec::with_capacity(data.len());
    let mut prev = iv.to_vec();
    for chunk in data.chunks(16 << 10) {
        out.extend(cbc_decrypt(&aes, &prev, chunk));
        prev = chunk.get(chunk.len().saturating_sub(16)..)?.to_vec();
        for _ in 0..chunk.len().div_ceil(256) {
            cx.checkpoint().await;
        }
    }
    Some(out)
}

const GK_PROMPT: &str = "Password for the GNOME keyring";

async fn gk_encrypted(cx: Cx, (input, span, header): (Input, Span, KeyringHeader)) -> Result<()> {
    if span.len > MAX_ENCRYPTED || span.len % 16 != 0 {
        return Err(
            Diagnostic::unsupported("encrypted part not a whole number of AES blocks").at(span),
        );
    }
    if header.iterations > MAX_ITERATIONS {
        return Err(Diagnostic::limit(format!(
            "{} key-derivation rounds (more than {MAX_ITERATIONS})",
            header.iterations
        ))
        .at(span));
    }
    let origin = Origin {
        parent: span,
        transform: "gnome-keyring-decrypt",
    };
    let plain = match cx.derived(origin) {
        Some(found) => found.span,
        None => {
            let data = cx.read(span).await?;
            let mut found = None;
            for attempt in 0..MAX_ATTEMPTS {
                let Some(secret) = cx
                    .secret(SecretRequest::password(input.span, GK_PROMPT, attempt))
                    .await
                else {
                    break;
                };
                let derived =
                    gk_derive(&cx, secret.expose(), &header.salt, header.iterations.max(1)).await;
                let (key, iv) = derived.split_at(16.min(derived.len()));
                let Some(plain) = gk_decrypt(&cx, key, iv, &data).await else {
                    break;
                };
                // The first 16 bytes are the MD5 of the rest.
                let (hash, rest) = plain.split_at(16.min(plain.len()));
                if Md5::digest(rest) == hash {
                    found = Some(plain);
                    break;
                }
            }
            let Some(plain) = found else {
                cx.emit(
                    Node::new("Ciphertext")
                        .span(span)
                        .diag(Diagnostic::note("needs the keyring password")),
                );
                return Ok(());
            };
            cx.add_derived(origin, plain, span.len, None)?.span
        }
    };
    cx.emit(
        Node::new("MD5 of the items")
            .span(plain.sub(0, 16))
            .value(Value::Bytes(cx.read(plain.sub(0, 16)).await?)),
    );
    let mut cur = Cursor::new(&cx, plain, BE);
    cur.seek(16);
    for id in &header.ids {
        let start = cur.pos();
        let (name, _) = kr_string(&mut cur).await?;
        skip_item(&mut cur).await?;
        let span = cur.since(start);
        cx.push(
            Node::new(format!("Item {id}: {}", name.unwrap_or_default()))
                .span(span)
                .lazy(crate::expander!(self::gk_secret_item: Span), span),
        )
        .await;
    }
    if cur.remaining() > 0 {
        cx.emit(Node::new("Padding").span(cur.span(cur.remaining())));
    }
    cx.annotate("unlocked");
    Ok(())
}

/// Skips an encrypted item after its display name.
async fn skip_item(cur: &mut Cursor<'_>) -> Result<()> {
    kr_string(cur).await?; // secret
    cur.skip(16); // times
    kr_string(cur).await?; // reserved
    cur.skip(16);
    let attrs = cur.u32().await?;
    for _ in 0..attrs.min(MAX_ATTRIBUTES) {
        kr_string(cur).await?;
        if cur.u32().await? == 0 {
            kr_string(cur).await?;
        } else {
            cur.skip(4);
        }
    }
    let acls = cur.u32().await?;
    for _ in 0..acls.min(MAX_ATTRIBUTES) {
        cur.skip(4);
        for _ in 0..3 {
            kr_string(cur).await?;
        }
        cur.skip(4);
    }
    Ok(())
}

/// An item's encrypted part, decrypted.
async fn gk_secret_item(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    let (name, s) = kr_string(&mut cur).await?;
    cx.emit(string_node("Display name", name, s));
    let (secret, s) = kr_string(&mut cur).await?;
    cx.emit(string_node("Secret", secret, s));
    for name in ["Created", "Modified"] {
        let at = cur.pos();
        let t = cur.u64().await?;
        cx.emit(Node::new(name).span(cur.since(at)).value(Value::Timestamp {
            unix_seconds: i64::try_from(t).unwrap_or(0),
        }));
    }
    let (reserved, s) = kr_string(&mut cur).await?;
    cx.emit(string_node("Reserved string", reserved, s));
    cx.emit(
        Node::new("Reserved")
            .span(cur.span(16))
            .value(Value::Bytes(cur.bytes(16).await?)),
    );
    let at = cur.pos();
    let n = cur.u32().await?;
    cx.emit(
        Node::new("Attribute count")
            .span(cur.since(at))
            .value(uint(n, 32)),
    );
    for _ in 0..n.min(MAX_ATTRIBUTES) {
        let start = cur.pos();
        let (name, _) = kr_string(&mut cur).await?;
        let node = Node::new(name.unwrap_or_default());
        let node = if cur.u32().await? == 0 {
            let (value, _) = kr_string(&mut cur).await?;
            node.value(text(value.unwrap_or_default()))
        } else {
            node.value(uint(cur.u32().await?, 32))
        };
        cx.emit(node.span(cur.since(start)));
    }
    let at = cur.pos();
    let acls = cur.u32().await?;
    cx.emit(
        Node::new("ACL entries")
            .span(cur.since(at))
            .value(uint(acls, 32)),
    );
    for i in 0..acls.min(MAX_ATTRIBUTES) {
        let start = cur.pos();
        let types = cur.u32().await?;
        let (app, _) = kr_string(&mut cur).await?;
        let (path, _) = kr_string(&mut cur).await?;
        kr_string(&mut cur).await?;
        cur.skip(4);
        let (set, unknown) = decode_flags(ACCESS_TYPES, types.into());
        cx.emit(
            Node::new(format!("ACL {i}"))
                .span(cur.since(start))
                .value(Value::Flags {
                    raw: types.into(),
                    bits: 32,
                    set,
                    unknown,
                })
                .summary(format!(
                    "{} ({})",
                    app.unwrap_or_default(),
                    path.unwrap_or_default()
                )),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// KWallet

declare_format!(pub KWALLET = "kwallet", "KDE KWallet file", ["kwl"], "application/x-kwallet",
    Probe::Magic(&[(0, b"KWALLET\n\r\0\r\n")]), kwallet);

const KW_CIPHERS: EnumTable = &[(0, "Blowfish"), (1, "Blowfish (CBC)"), (2, "GPG")];
const KW_HASHES: EnumTable = &[(0, "SHA-1"), (1, "MD5"), (2, "PBKDF2-SHA512")];

async fn kwallet(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.bytes("Signature", 12).emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    let cipher = f.u8("Cipher").enumeration(KW_CIPHERS).emit()?;
    let hash = f.u8("Hash").enumeration(KW_HASHES).emit()?;
    let folders = f.u32("Number of folders").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(20);
    let mut entries_total = 0u64;
    for i in 0..folders.min(65_536) {
        let start = cur.pos();
        let folder_hash = cur.bytes(16).await?;
        let entries = cur.u32().await?;
        let list = cur.span(u64::from(entries).saturating_mul(16));
        cur.skip(list.len);
        entries_total = entries_total.saturating_add(entries.into());
        cx.push(
            Node::new(format!("Folder {i}"))
                .span(cur.since(start))
                .value(text(hex_lower(&folder_hash)))
                .desc("MD5 of the folder name")
                .summary(format!("{entries} entries"))
                .lazy(kw_entries, list),
        )
        .await;
    }
    cx.emit(
        Node::new("Encrypted data")
            .span(file.tail(cur.pos()))
            .diag(Diagnostic::note("requires the wallet password")),
    );
    cx.annotate(format!(
        "KWallet {major}.{minor}, {}, {}, {folders} folders, {entries_total} entries",
        lookup(KW_CIPHERS, cipher.into()).unwrap_or("unknown cipher"),
        lookup(KW_HASHES, hash.into()).unwrap_or("unknown hash")
    ));
    Ok(())
}

async fn kw_entries(cx: Cx, list: Span) -> Result<()> {
    let raw = cx.read(list).await?;
    for (i, h) in raw.as_chunks::<16>().0.iter().enumerate() {
        cx.push(
            Node::new(format!("Entry {i}"))
                .span(list.sub(crate::bytes::to_u64(i).saturating_mul(16), 16))
                .value(text(hex_lower(h)))
                .desc("MD5 of the entry key"),
        )
        .await;
    }
    Ok(())
}
