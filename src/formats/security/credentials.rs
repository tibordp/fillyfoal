//! Credential stores, key files and backups.

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Codec, Input, Probe, content};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const BE: Endian = Endian::Big;

// KeePass lives in its own module; re-exported for the format table.
pub use super::keepass::{KDB, KDBX};

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
