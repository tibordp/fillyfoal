//! Credential stores, key files and backups.

use crate::bytes::{u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Codec, Input, Probe, content};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// KeePass

declare_format!(pub KDBX = "kdbx", "KeePass 2 database", ["kdbx"], "application/x-keepass2",
    Probe::Magic(&[(0, b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5")]), kdbx);
declare_format!(pub KDB = "kdb", "KeePass 1 database", ["kdb"], "application/x-keepass",
    Probe::Magic(&[(0, b"\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5")]), kdb);

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

const KDBX_CIPHERS: &[(&str, &str)] = &[
    ("31c1f2e6bf714350be5805216afc5aff", "AES-256-CBC"),
    ("d6038a2b8b6f4cb5a524339a31dbb59a", "ChaCha20"),
    ("ad68f29f576f4bb9a36ad47af965346c", "Twofish-CBC"),
];

async fn kdbx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &head, LE);
    f.u32("Signature 1").hex().emit()?;
    f.u32("Signature 2").hex().emit()?;
    let minor = f.u16("Minor version").emit()?;
    let major = f.u16("Major version").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(12);
    let mut cipher = "unknown cipher".to_owned();
    loop {
        let start = cur.pos();
        let id = cur.u8().await?;
        let len = if major >= 4 {
            cur.u32().await?
        } else {
            u32::from(cur.u16().await?)
        };
        let data = cur.span(len.into());
        let bytes = cur.bytes(len.into()).await?;
        let name =
            lookup(KDBX_FIELDS, id.into()).map_or_else(|| format!("Field {id}"), str::to_owned);
        let mut node = Node::new(name).span(cur.since(start)).target(data);
        match id {
            2 => {
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                cipher = KDBX_CIPHERS
                    .iter()
                    .find(|(g, _)| *g == hex)
                    .map_or(hex, |(_, n)| (*n).to_owned());
                node = node.value(Value::Text(cipher.clone()));
            }
            3 => {
                let v = u32_le(&bytes, 0).unwrap_or(0);
                node = node.value(Value::Enum {
                    raw: v.into(),
                    bits: 32,
                    name: lookup(&[(0, "none"), (1, "gzip")], v.into()),
                });
            }
            6 => {
                node = node.value(Value::UInt {
                    value: crate::bytes::u64_le(&bytes, 0).unwrap_or(0),
                    bits: 64,
                    radix: Radix::Dec,
                })
            }
            _ => node = node.summary(format!("{len} bytes")),
        }
        cx.push(node).await;
        if id == 0 {
            break;
        }
    }
    if major >= 4 {
        cx.emit(Node::new("Header SHA-256").span(cur.span(32)));
        cx.emit(Node::new("Header HMAC-SHA-256").span(file.sub(cur.pos().saturating_add(32), 32)));
        cur.skip(64);
    }
    cx.emit(
        Node::new("Encrypted payload")
            .span(file.tail(cur.pos()))
            .diag(Diagnostic::note("encrypted; requires the master key")),
    );
    cx.annotate(format!("KeePass KDBX {major}.{minor}, {cipher}"));
    Ok(())
}

record! {
    pub struct KdbHeader {
        signature1: u32 "Signature 1" .hex(),
        signature2: u32 "Signature 2" .hex(),
        flags: u32 "Flags" .hex(),
        version: u32 "Version" .hex(),
        master_seed: bytes[16] "Master seed",
        iv: bytes[16] "Encryption IV",
        groups: u32 "Groups",
        entries: u32 "Entries",
        contents_hash: bytes[32] "Contents hash",
        transform_seed: bytes[32] "Transform seed",
        rounds: u32 "Key transform rounds",
    }
}

async fn kdb(cx: Cx, input: Input) -> Result<()> {
    let h: KdbHeader = emit_record(&cx, input.span.sub(0, KdbHeader::SIZE), LE).await?;
    cx.emit(Node::new("Encrypted payload").span(input.span.tail(KdbHeader::SIZE)));
    cx.annotate(format!(
        "KeePass 1, {} groups, {} entries",
        h.groups, h.entries
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenSSH private keys (the binary inside the PEM armour)

declare_format!(pub OPENSSH_KEY = "openssh-key", "OpenSSH private key (binary)", [], "application/octet-stream",
    Probe::Magic(&[(0, b"openssh-key-v1\0")]), openssh_key);

/// Reads an SSH wire-format string (u32 BE length + bytes).
async fn ssh_string(cur: &mut Cursor<'_>) -> Result<(Vec<u8>, Span)> {
    let start = cur.pos();
    let len = cur.u32().await?;
    if u64::from(len) > cur.remaining() {
        return Err(Diagnostic::malformed("string length exceeds the data").at(cur.since(start)));
    }
    let bytes = cur.bytes(len.into()).await?;
    Ok((bytes, cur.since(start)))
}

async fn openssh_key(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, BE);
    cx.emit(Node::new("Magic").span(cur.span(15)));
    cur.skip(15);
    let text = |name: &'static str, bytes: &[u8], span: Span| {
        Node::new(name)
            .span(span)
            .value(Value::Text(String::from_utf8_lossy(bytes).into_owned()))
    };
    let (cipher, span) = ssh_string(&mut cur).await?;
    cx.emit(text("Cipher", &cipher, span));
    let (kdf, span) = ssh_string(&mut cur).await?;
    cx.emit(text("KDF", &kdf, span));
    let (_, span) = ssh_string(&mut cur).await?;
    cx.emit(Node::new("KDF options").span(span));
    let count = cur.u32().await?;
    let mut algorithms = Vec::new();
    for i in 0..count.min(16) {
        let (blob, span) = ssh_string(&mut cur).await?;
        let algo_len = usize::try_from(u32_be(&blob, 0).unwrap_or(0)).unwrap_or(0);
        let algo = String::from_utf8_lossy(
            blob.get(4..4usize.saturating_add(algo_len))
                .unwrap_or_default(),
        )
        .into_owned();
        algorithms.push(algo.clone());
        cx.emit(
            Node::new(format!("Public key {i}"))
                .span(span)
                .value(Value::Text(algo)),
        );
    }
    let (_, span) = ssh_string(&mut cur).await?;
    let encrypted = cipher != b"none";
    let mut private = Node::new("Private section").span(span);
    if encrypted {
        private = private.diag(Diagnostic::note("encrypted with a passphrase"));
    }
    cx.emit(private);
    cx.annotate(format!(
        "{} key(s): {}{}",
        count,
        algorithms.join(", "),
        if encrypted {
            ", passphrase-protected"
        } else {
            ", unencrypted"
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GnuPG keybox

fn keybox_probe(h: &crate::formats::Head<'_>) -> bool {
    h.at(8, b"KBXf")
}

declare_format!(pub KEYBOX = "keybox", "GnuPG keybox", ["kbx"], "application/x-gnupg-keybox",
    Probe::Custom(keybox_probe), keybox);

const KEYBOX_TYPES: EnumTable = &[(0, "empty"), (1, "header"), (2, "OpenPGP"), (3, "X.509")];

async fn keybox(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, BE);
    let mut counts = [0u32; 4];
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let len = cur.u32().await?;
        let kind = cur.u8().await?;
        if len < 5 {
            cx.diag(Diagnostic::malformed("blob shorter than its header").at(cur.since(start)));
            break;
        }
        cur.seek(start.saturating_add(len.into()));
        if let Some(c) = counts.get_mut(usize::from(kind)) {
            *c = c.saturating_add(1);
        }
        let name = lookup(KEYBOX_TYPES, kind.into()).unwrap_or("unknown");
        cx.push(
            Node::new(format!("{name} blob"))
                .span(cur.since(start))
                .summary(format!("{len} bytes")),
        )
        .await;
    }
    cx.annotate(format!(
        "{} OpenPGP and {} X.509 blob(s)",
        counts[2], counts[3]
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS keychain (legacy .keychain)

declare_format!(pub KEYCHAIN = "keychain", "macOS keychain", ["keychain", "keychain-db"], "application/x-apple-keychain",
    Probe::Magic(&[(0, b"kych")]), keychain);

record! {
    pub struct KeychainHeader {
        magic: ascii[4] "Magic",
        version: u32 "Version" .hex(),
        auth_offset: u32 "Auth offset" .hex(),
        schema_offset: u32 "Schema offset" .hex(),
    }
}

async fn keychain(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: KeychainHeader = read_record(&cx, file.sub(0, KeychainHeader::SIZE), BE).await?;
    cx.emit(KeychainHeader::node(
        "Header",
        file.sub(0, KeychainHeader::SIZE),
        BE,
    ));
    let schema = file.tail(h.schema_offset.into());
    let head = cx.read_avail(schema.sub(0, 8)).await?;
    let tables = u32_be(&head, 4).unwrap_or(0);
    cx.emit(
        Node::new("Schema")
            .span(schema)
            .summary(format!("{tables} tables")),
    );
    cx.annotate(format!("keychain, {tables} tables"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Android backup (adb backup)

declare_format!(pub ANDROID_BACKUP = "android-backup", "Android backup", ["ab"], "application/x-android-backup",
    Probe::Magic(&[(0, b"ANDROID BACKUP\n")]), android_backup);

async fn android_backup(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1024)).await?;
    let mut pos = 0u64;
    let mut lines = Vec::new();
    for (i, line) in head.split(|&b| b == b'\n').take(4).enumerate() {
        let len = crate::bytes::to_u64(line.len()).saturating_add(1);
        let label = ["Magic", "Version", "Compressed", "Encryption"]
            .get(i)
            .copied()
            .unwrap_or("Line");
        let text = String::from_utf8_lossy(line).into_owned();
        cx.emit(
            Node::new(label)
                .span(file.sub(pos, len))
                .value(Value::Text(text.clone())),
        );
        lines.push(text);
        pos = pos.saturating_add(len);
    }
    let compressed = lines.get(2).is_some_and(|l| l == "1");
    let encryption = lines.get(3).cloned().unwrap_or_default();
    let body = file.tail(pos);
    if encryption == "none" {
        // The payload is a (zlib-compressed) tar archive.
        let codec = if compressed {
            Codec::Zlib
        } else {
            Codec::Stored
        };
        cx.emit(content("Payload (tar)", input, body, codec, None));
    } else {
        cx.emit(
            Node::new("Payload")
                .span(body)
                .diag(Diagnostic::note(format!("encrypted ({encryption})"))),
        );
    }
    cx.annotate(format!(
        "Android backup v{}, {}{}",
        lines.get(1).cloned().unwrap_or_default(),
        if compressed {
            "compressed"
        } else {
            "uncompressed"
        },
        if encryption == "none" {
            String::new()
        } else {
            format!(", {encryption}")
        }
    ));
    Ok(())
}
