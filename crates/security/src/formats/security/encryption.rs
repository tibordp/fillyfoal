//! Encrypted and signed files: Password Safe, OpenSSL `enc`, AES Crypt,
//! AxCrypt, and minisign/signify keys and signatures.

use crate::bytes::{u16_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::text::decode::base64;
use crate::formats::text::scan::head_lines;
use crate::formats::util::val::{text, uint};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Encrypted files: Password Safe, OpenSSL enc, AES Crypt, AxCrypt

declare_format!(pub PWSAFE = "password-safe", "Password Safe v3 database", ["psafe3"], "application/x-password-safe",
    Probe::Magic(&[(0, b"PWS3")]), pwsafe);

async fn pwsafe(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 152)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    f.bytes("Salt", 32).emit()?;
    let iterations = f.u32("Key stretch iterations").emit()?;
    f.bytes("Stretched key hash (SHA-256)", 32).emit()?;
    f.bytes("Encrypted K (B1, B2)", 32).emit()?;
    f.bytes("Encrypted L (B3, B4)", 32).emit()?;
    f.bytes("CBC IV", 16).emit()?;
    let tail = cx
        .read_avail(file.sub(file.len.saturating_sub(48), 48))
        .await?;
    let eof = if tail.starts_with(b"PWS3-EOFPWS3-EOF") {
        file.len.saturating_sub(48)
    } else {
        file.len
    };
    cx.emit(
        Node::new("Encrypted records (Twofish-CBC)").span(file.sub(152, eof.saturating_sub(152))),
    );
    if eof < file.len {
        cx.emit(Node::new("EOF marker").span(file.sub(eof, 16)));
        cx.emit(Node::new("HMAC-SHA256").span(file.sub(eof.saturating_add(16), 32)));
    }
    cx.annotate(format!("Password Safe v3, {iterations} iterations"));
    Ok(())
}

declare_format!(pub OPENSSL_ENC = "openssl-enc", "OpenSSL encrypted file", ["enc", "aes"], "application/x-openssl-enc",
    Probe::Magic(&[(0, b"Salted__")]), openssl_enc);

async fn openssl_enc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 8)));
    let salt = cx.read(file.sub(8, 8)).await?;
    cx.emit(
        Node::new("Salt")
            .span(file.sub(8, 8))
            .value(Value::Bytes(salt)),
    );
    cx.emit(Node::new("Ciphertext").span(file.tail(16)).summary(
        if file.len.saturating_sub(16).is_multiple_of(16) {
            "block-aligned (CBC/ECB)"
        } else {
            "stream mode"
        },
    ));
    cx.annotate("OpenSSL `enc` encrypted data (salted)");
    Ok(())
}

declare_format!(pub AESCRYPT = "aes-crypt", "AES Crypt file", ["aes"], "application/x-aescrypt",
    Probe::Magic(&[(0, b"AES\x02"), (0, b"AES\x01"), (0, b"AES\x00")]), aescrypt);

async fn aescrypt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 5)).await?;
    let version = head.get(3).copied().unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 3)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(3, 1))
            .value(uint(version, 8)),
    );
    let mut pos = 5u64;
    let mut created_by = String::new();
    if version >= 2 {
        loop {
            let l = u64::from(u16_be(&cx.read(file.sub_exact(pos, 2)?).await?, 0).unwrap_or(0));
            if l == 0 {
                cx.emit(Node::new("End of extensions").span(file.sub(pos, 2)));
                pos = pos.saturating_add(2);
                break;
            }
            let data = cx.read(file.sub_exact(pos.saturating_add(2), l)?).await?;
            let (k, v) = data.split_at(data.iter().position(|&b| b == 0).unwrap_or(data.len()));
            let key = String::from_utf8_lossy(k).into_owned();
            let value = String::from_utf8_lossy(v.get(1..).unwrap_or_default())
                .trim_end_matches('\0')
                .to_owned();
            if key == "CREATED_BY" {
                created_by = value.clone();
            }
            let node = Node::new(if key.is_empty() {
                "Padding".to_owned()
            } else {
                key
            })
            .span(file.sub(pos, l.saturating_add(2)));
            cx.emit(if value.is_empty() {
                node
            } else {
                node.value(text(value))
            });
            pos = pos.saturating_add(2).saturating_add(l);
        }
    }
    if version >= 1 {
        cx.emit(Node::new("IV").span(file.sub(pos, 16)));
        cx.emit(Node::new("Encrypted IV and key").span(file.sub(pos.saturating_add(16), 48)));
        cx.emit(Node::new("HMAC (IV and key)").span(file.sub(pos.saturating_add(64), 32)));
        pos = pos.saturating_add(96);
    } else {
        cx.emit(Node::new("IV").span(file.sub(pos, 16)));
        pos = pos.saturating_add(16);
    }
    let body = file.len.saturating_sub(pos).saturating_sub(33);
    cx.emit(Node::new("Ciphertext (AES-256-CBC)").span(file.sub(pos, body)));
    cx.emit(Node::new("Last block size").span(file.sub(pos.saturating_add(body), 1)));
    cx.emit(Node::new("HMAC").span(file.sub(pos.saturating_add(body).saturating_add(1), 32)));
    cx.annotate(format!(
        "AES Crypt v{version}{}",
        if created_by.is_empty() {
            String::new()
        } else {
            format!(", created by {created_by}")
        }
    ));
    Ok(())
}

declare_format!(pub AXCRYPT = "axcrypt", "AxCrypt encrypted file", ["axx"], "application/x-axcrypt",
    Probe::Magic(&[(0, b"\xc0\xb9\x07\x2e\x4f\x93\xf1\x46\xa0\x15\x79\x2c\xa1\xd9\xe8\x21")]), axcrypt);

const AX_BLOCKS: EnumTable = &[
    (1, "Preamble"),
    (2, "Version"),
    (3, "Key wrap 1"),
    (4, "Key wrap 2"),
    (13, "ID tag"),
    (14, "Data"),
    (15, "File name info"),
    (16, "Encryption info"),
    (17, "Compression info"),
    (18, "File info"),
    (19, "Compression"),
    (20, "Unicode file name info"),
    (63, "Data"),
];

async fn axcrypt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // Blocks: GUID, i32 length (including the 5-byte header), u8 type.
    let mut pos = 16u64;
    let mut n = 0u32;
    cx.emit(Node::new("GUID").span(file.sub(0, 16)));
    while pos.saturating_add(5) <= file.len {
        let h = cx.read(file.sub(pos, 5)).await?;
        let len = u64::from(u32_le(&h, 0).unwrap_or(0));
        let kind = h.get(4).copied().unwrap_or(0);
        if len < 5 {
            return Err(
                Diagnostic::malformed("header block shorter than 5 bytes").at(file.sub(pos, 5))
            );
        }
        let name = AX_BLOCKS
            .iter()
            .find(|(k, _)| *k == u64::from(kind))
            .map_or("Unknown block", |(_, v)| v);
        cx.push(
            Node::new(name)
                .span(file.sub(pos, len))
                .summary(format!("type {kind}, {} bytes", len.saturating_sub(5))),
        )
        .await;
        n = n.saturating_add(1);
        pos = pos.saturating_add(len);
        if kind == 63 {
            cx.emit(Node::new("Encrypted data").span(file.tail(pos)));
            break;
        }
        // Each further block is preceded by the GUID again.
        if cx.read_avail(file.sub(pos, 16)).await?.len() == 16 {
            pos = pos.saturating_add(16);
        }
    }
    cx.annotate(format!("AxCrypt 1.x file, {n} header blocks"));
    Ok(())
}

// ---------------------------------------------------------------------------
// minisign / signify

declare_format!(pub MINISIGN = "minisign", "minisign/signify key or signature", ["minisig", "sig", "pub", "sec"], "text/x-minisign",
    Probe::Magic(&[(0, b"untrusted comment: ")]), minisign);

async fn minisign(cx: Cx, input: Input) -> Result<()> {
    let all = head_lines(&cx, input.span, 4096).await?;
    let mut kind = "file";
    let mut key_id = String::new();
    for (i, (line, span)) in all.iter().enumerate() {
        if let Some(c) = line.strip_prefix("untrusted comment: ") {
            cx.emit(Node::new("Untrusted comment").span(*span).value(text(c)));
        } else if let Some(c) = line.strip_prefix("trusted comment: ") {
            cx.emit(Node::new("Trusted comment").span(*span).value(text(c)));
        } else if !line.trim().is_empty() {
            let decoded = base64(line.trim().as_bytes()).bytes;
            let alg = String::from_utf8_lossy(decoded.get(..2).unwrap_or_default()).into_owned();
            let id: String = decoded
                .get(2..10)
                .unwrap_or_default()
                .iter()
                .rev()
                .map(|b| format!("{b:02X}"))
                .collect();
            let label = match (i, decoded.len()) {
                (_, 42) => {
                    kind = "public key";
                    "Public key"
                }
                (_, 74) if i <= 1 => {
                    kind = "signature";
                    "Signature"
                }
                (_, 64) => "Global signature",
                (_, 104 | 158) => {
                    kind = "secret key";
                    "Secret key"
                }
                _ => "Data",
            };
            if key_id.is_empty() && decoded.len() >= 10 {
                key_id = id.clone();
            }
            let node = Node::new(label).span(*span);
            cx.emit(if decoded.len() >= 10 && label != "Global signature" {
                node.summary(format!(
                    "algorithm {alg}, key ID {id}, {} bytes",
                    decoded.len()
                ))
            } else {
                node.summary(format!("{} bytes", decoded.len()))
            });
        }
    }
    cx.annotate(format!("minisign/signify {kind}, key ID {key_id}"));
    Ok(())
}
