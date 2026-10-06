//! Security artifacts (Kerberos keytabs and credential caches, Password
//! Safe, OpenSSL/AES Crypt/AxCrypt encrypted files, minisign/signify),
//! backup and database dumps (MTF/BKF, Oracle export, PostgreSQL custom
//! dumps, MySQL FRM, MyISAM, H2, FileMaker), R and ASDF data, Windows
//! Address Book, compiled AppleScript, and packaging (AppImage, Solaris
//! datastreams, Haiku packages, Electron ASAR).

use crate::bytes::{to_u64, u16_be, u16_le, u32_be, u32_le, u64_be, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::text::decode::base64;
use crate::formats::text::scan::head_lines;
use crate::formats::{Head, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt { value, bits, radix: Radix::Dec }
}

fn hex(value: u64, bits: u8) -> Value {
    Value::UInt { value, bits, radix: Radix::Hex }
}

fn time(secs: u32) -> Value {
    Value::Timestamp { unix_seconds: secs.into() }
}

fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

/// Kerberos encryption types (RFC 3961 and successors).
const ENCTYPES: EnumTable = &[
    (1, "des-cbc-crc"),
    (3, "des-cbc-md5"),
    (16, "des3-cbc-sha1"),
    (17, "aes128-cts-hmac-sha1-96"),
    (18, "aes256-cts-hmac-sha1-96"),
    (19, "aes128-cts-hmac-sha256-128"),
    (20, "aes256-cts-hmac-sha384-192"),
    (23, "rc4-hmac"),
    (24, "rc4-hmac-exp"),
    (25, "camellia128-cts-cmac"),
    (26, "camellia256-cts-cmac"),
];

fn enctype(e: u16) -> &'static str {
    ENCTYPES.iter().find(|(k, _)| *k == u64::from(e)).map_or("unknown", |(_, v)| v)
}

// ---------------------------------------------------------------------------
// Kerberos keytab

fn keytab_probe(h: &Head<'_>) -> bool {
    // Version 0x0502 (big-endian) or 0x0501 (native), then the first entry's
    // length: a plausible, non-zero size.
    let size = if h.at(1, b"\x02") { u32_be(h.data, 2) } else { u32_le(h.data, 2) };
    h.data.first() == Some(&5)
        && matches!(h.data.get(1), Some(1 | 2))
        && size.is_some_and(|s| {
            let s = i32::from_ne_bytes(s.to_ne_bytes()).unsigned_abs();
            (16..=0x10000).contains(&s)
        })
}

declare_format!(pub KEYTAB = "krb5-keytab", "Kerberos keytab", ["keytab", "kt"], "application/x-krb5-keytab",
    Probe::Custom(keytab_probe), keytab);

async fn keytab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let v = cx.read(file.sub(0, 2)).await?;
    let endian = if v.get(1) == Some(&2) { BE } else { LE };
    cx.emit(Node::new("Version").span(file.sub(0, 2)).value(hex(u16_be(&v, 0).unwrap_or(0).into(), 16)));
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(2);
    let mut n = 0u32;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let size = cur.u32().await?;
        let signed = i32::from_ne_bytes(size.to_ne_bytes());
        let len = u64::from(signed.unsigned_abs());
        let entry = cur.span(len);
        if entry.len < len {
            return Err(Diagnostic::truncated(Span::new(entry.source, entry.offset, len), entry.len));
        }
        cur.skip(len);
        if signed < 0 {
            cx.push(Node::new("Hole").span(cur.since(start)).summary(format!("{len} bytes free"))).await;
            continue;
        }
        if len == 0 {
            break;
        }
        // Parse the entry for its summary; the node expands to its fields.
        let mut e = Cursor::new(&cx, entry, endian);
        let mut count = u64::from(e.u16().await?);
        if endian == LE {
            count = count.saturating_sub(1);
        }
        let realm_len = u64::from(e.u16().await?);
        let realm = String::from_utf8_lossy(&e.bytes(realm_len).await?).into_owned();
        let mut parts = Vec::new();
        for _ in 0..count.min(16) {
            let l = u64::from(e.u16().await?);
            parts.push(String::from_utf8_lossy(&e.bytes(l).await?).into_owned());
        }
        e.skip(8);
        let kvno = e.u8().await?;
        let etype = e.u16().await?;
        let principal = format!("{}@{realm}", parts.join("/"));
        cx.push(
            Node::new(principal)
                .span(cur.since(start))
                .summary(format!("kvno {kvno}, {}", enctype(etype)))
                .lazy(keytab_entry, (entry, endian)),
        )
        .await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!("Kerberos keytab, {n} keys"));
    Ok(())
}

async fn keytab_entry(cx: Cx, (entry, endian): (Span, Endian)) -> Result<()> {
    let mut e = Cursor::new(&cx, entry, endian);
    let at = e.pos();
    let count = e.u16().await?;
    cx.emit(Node::new("Components").span(e.since(at)).value(uint(count.into(), 16)));
    let mut n = u64::from(count);
    if endian == LE {
        n = n.saturating_sub(1);
    }
    for i in 0..=n.min(16) {
        let at = e.pos();
        let l = u64::from(e.u16().await?);
        let s = String::from_utf8_lossy(&e.bytes(l).await?).into_owned();
        cx.emit(Node::new(if i == 0 { "Realm".to_owned() } else { format!("Component {i}") }).span(e.since(at)).value(text(s)));
    }
    let at = e.pos();
    let kind = e.u32().await?;
    cx.emit(Node::new("Name type").span(e.since(at)).value(uint(kind.into(), 32)));
    let at = e.pos();
    let stamp = e.u32().await?;
    cx.emit(Node::new("Timestamp").span(e.since(at)).value(time(stamp)));
    let at = e.pos();
    let kvno = e.u8().await?;
    cx.emit(Node::new("Key version (8-bit)").span(e.since(at)).value(uint(kvno.into(), 8)));
    let at = e.pos();
    let etype = e.u16().await?;
    cx.emit(Node::new("Encryption type").span(e.since(at)).value(Value::Enum { raw: etype.into(), bits: 16, name: Some(enctype(etype)) }));
    let at = e.pos();
    let klen = u64::from(e.u16().await?);
    e.skip(klen);
    cx.emit(Node::new("Key").span(e.since(at)).summary(format!("{klen} bytes")));
    if e.remaining() >= 4 {
        let at = e.pos();
        let v = e.u32().await?;
        cx.emit(Node::new("Key version (32-bit)").span(e.since(at)).value(uint(v.into(), 32)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Kerberos credential cache

declare_format!(pub CCACHE = "krb5-ccache", "Kerberos credential cache", ["ccache"], "application/x-krb5-ccache",
    Probe::Custom(ccache_probe), ccache);

fn ccache_probe(h: &Head<'_>) -> bool {
    // v4 has a header-tag length (usually 12); v3 starts with a principal.
    (h.starts_with(b"\x05\x04") && u16_be(h.data, 2).is_some_and(|l| l <= 64 && l % 4 == 0))
        || (h.starts_with(b"\x05\x03") && u32_be(h.data, 2).is_some_and(|t| t <= 10))
}

/// A principal: name type, component count, realm, components.
async fn principal(cur: &mut Cursor<'_>, v3: bool) -> Result<String> {
    let _kind = cur.u32().await?;
    let mut count = u64::from(cur.u32().await?);
    if !v3 {
        count = count.min(64);
    }
    let l = u64::from(cur.u32().await?);
    let realm = String::from_utf8_lossy(&cur.bytes(l).await?).into_owned();
    let mut parts = Vec::new();
    for _ in 0..count.min(64) {
        let l = u64::from(cur.u32().await?);
        parts.push(String::from_utf8_lossy(&cur.bytes(l).await?).into_owned());
    }
    Ok(format!("{}@{realm}", parts.join("/")))
}

async fn counted(cur: &mut Cursor<'_>) -> Result<Span> {
    let l = u64::from(cur.u32().await?);
    let span = cur.span(l);
    if span.len < l {
        return Err(Diagnostic::truncated(Span::new(span.source, span.offset, l), span.len));
    }
    cur.skip(l);
    Ok(span)
}

async fn ccache(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let version = cur.u16().await?;
    cx.emit(Node::new("Version").span(file.sub(0, 2)).value(hex(version.into(), 16)));
    if version == 0x0504 {
        let at = cur.pos();
        let len = u64::from(cur.u16().await?);
        cur.skip(len);
        cx.emit(Node::new("Header tags").span(cur.since(at)).summary(format!("{len} bytes")));
    }
    let at = cur.pos();
    let default = principal(&mut cur, false).await?;
    cx.emit(Node::new("Default principal").span(cur.since(at)).value(text(default.clone())));
    let mut n = 0u32;
    while cur.remaining() > 0 {
        let start = cur.pos();
        let client = principal(&mut cur, false).await?;
        let server = principal(&mut cur, false).await?;
        let etype = cur.u16().await?;
        let key = counted(&mut cur).await?;
        let auth = cur.u32().await?;
        let _start_time = cur.u32().await?;
        let end = cur.u32().await?;
        let _renew = cur.u32().await?;
        let _skey = cur.u8().await?;
        let flags = cur.u32().await?;
        let addresses = cur.u32().await?;
        for _ in 0..addresses.min(64) {
            cur.skip(2);
            counted(&mut cur).await?;
        }
        let authdata = cur.u32().await?;
        for _ in 0..authdata.min(64) {
            cur.skip(2);
            counted(&mut cur).await?;
        }
        let ticket = counted(&mut cur).await?;
        let second = counted(&mut cur).await?;
        let span = cur.since(start);
        cx.push(
            Node::new(server.clone())
                .span(span)
                .summary(format!("for {client}, {}, flags {flags:#x}", enctype(etype)))
                .lazy(ccache_cred, (input, auth, end, etype, key, ticket, second)),
        )
        .await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!("Kerberos credential cache v{}, {default}, {n} credentials", version & 0xff));
    Ok(())
}

async fn ccache_cred(cx: Cx, (input, auth, end, etype, key, ticket, second): (Input, u32, u32, u16, Span, Span, Span)) -> Result<()> {
    cx.emit(Node::new("Authenticated").value(time(auth)));
    cx.emit(Node::new("Expires").value(time(end)));
    cx.emit(Node::new("Session key").span(key).summary(format!("{}, {} bytes", enctype(etype), key.len)));
    // Tickets are DER (ASN.1 application tag 1).
    cx.emit(embedded("Ticket", input.nested(ticket)));
    if second.len > 0 {
        cx.emit(embedded("Second ticket", input.nested(second)));
    }
    Ok(())
}

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
    let tail = cx.read_avail(file.sub(file.len.saturating_sub(48), 48)).await?;
    let eof = if tail.starts_with(b"PWS3-EOFPWS3-EOF") { file.len.saturating_sub(48) } else { file.len };
    cx.emit(Node::new("Encrypted records (Twofish-CBC)").span(file.sub(152, eof.saturating_sub(152))));
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
    cx.emit(Node::new("Salt").span(file.sub(8, 8)).value(Value::Bytes(salt)));
    cx.emit(Node::new("Ciphertext").span(file.tail(16)).summary(if file.len.saturating_sub(16).is_multiple_of(16) { "block-aligned (CBC/ECB)" } else { "stream mode" }));
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
    cx.emit(Node::new("Version").span(file.sub(3, 1)).value(uint(version.into(), 8)));
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
            let value = String::from_utf8_lossy(v.get(1..).unwrap_or_default()).trim_end_matches('\0').to_owned();
            if key == "CREATED_BY" {
                created_by = value.clone();
            }
            let node = Node::new(if key.is_empty() { "Padding".to_owned() } else { key }).span(file.sub(pos, l.saturating_add(2)));
            cx.emit(if value.is_empty() { node } else { node.value(text(value)) });
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
    cx.annotate(format!("AES Crypt v{version}{}", if created_by.is_empty() { String::new() } else { format!(", created by {created_by}") }));
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
            return Err(Diagnostic::malformed("header block shorter than 5 bytes").at(file.sub(pos, 5)));
        }
        let name = AX_BLOCKS.iter().find(|(k, _)| *k == u64::from(kind)).map_or("Unknown block", |(_, v)| v);
        cx.push(Node::new(name).span(file.sub(pos, len)).summary(format!("type {kind}, {} bytes", len.saturating_sub(5)))).await;
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
            let id: String = decoded.get(2..10).unwrap_or_default().iter().rev().map(|b| format!("{b:02X}")).collect();
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
                node.summary(format!("algorithm {alg}, key ID {id}, {} bytes", decoded.len()))
            } else {
                node.summary(format!("{} bytes", decoded.len()))
            });
        }
    }
    cx.annotate(format!("minisign/signify {kind}, key ID {key_id}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Backups and database dumps

declare_format!(pub MTF = "mtf", "Microsoft Tape Format (BKF / SQL Server backup)", ["bkf", "bak"], "application/x-mtf",
    Probe::Magic(&[(0, b"TAPE")]), mtf);

const MTF_DBLKS: &[&[u8; 4]] = &[b"TAPE", b"SSET", b"VOLB", b"DIRB", b"FILE", b"CFIL", b"ESPB", b"ESET", b"EOTM", b"SFMB", b"MSCI", b"MSDA", b"MQDA"];

async fn mtf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x80)).await?;
    // After the 52-byte common header: media family ID, attributes,
    // sequence, password encryption, soft filemark size, catalog type, then
    // (size, offset) pairs for the tape name, description, password and
    // software name, the logical block size, vendor, date and MTF version.
    let block_size = u64::from(u16_le(&head, 0x54).unwrap_or(1024)).max(512);
    let name_size = u64::from(u16_le(&head, 0x44).unwrap_or(0));
    let name_at = u64::from(u16_le(&head, 0x46).unwrap_or(0));
    let string_type = head.get(0x2e).copied().unwrap_or(1);
    let raw_name = cx.read_avail(file.sub(name_at, name_size.min(512))).await?;
    let name = if string_type == 2 { crate::text::utf16z(&raw_name, LE).0 } else { zstr(&raw_name) };
    let major = head.get(0x5d).copied().unwrap_or(0);
    let mut pos = 0u64;
    let mut counts: Vec<(String, u32)> = Vec::new();
    while pos.saturating_add(4) <= file.len {
        let id = cx.read(file.sub(pos, 4)).await?;
        let id_arr: [u8; 4] = id.get(..4).and_then(|s| s.try_into().ok()).unwrap_or([0; 4]);
        if MTF_DBLKS.contains(&&id_arr) {
            // A descriptor block: common header (52 bytes) + type-specific.
            let h = cx.read(file.sub_exact(pos, 52)?).await?;
            let first = u64::from(u16_le(&h, 8).unwrap_or(0)).max(52);
            let kind = String::from_utf8_lossy(&id).into_owned();
            match counts.iter_mut().find(|(k, _)| *k == kind) {
                Some((_, n)) => *n = n.saturating_add(1),
                None => counts.push((kind.clone(), 1)),
            }
            cx.push(Node::new(kind).span(file.sub(pos, first)).summary(format!("descriptor block, streams at +{first:#x}"))).await;
            pos = pos.saturating_add(first);
            if id_arr == *b"SFMB" || id_arr == *b"EOTM" {
                pos = pos.saturating_add(1).checked_next_multiple_of(block_size).unwrap_or(u64::MAX);
            }
        } else {
            // A stream: id, attributes, u64 length, encryption,
            // compression, checksum (22 bytes), data, 4-byte aligned.
            let h = cx.read(file.sub_exact(pos, 22)?).await?;
            let len = u64_le(&h, 8).unwrap_or(0);
            let kind = String::from_utf8_lossy(&id).into_owned();
            if !id.iter().all(|b| b.is_ascii_alphanumeric()) {
                cx.push(Node::new("Unparsed data").span(file.tail(pos)).diag(Diagnostic::malformed("expected a descriptor block or stream header"))).await;
                break;
            }
            let total = 22u64.saturating_add(len);
            cx.push(Node::new(format!("Stream {kind}")).span(file.sub(pos, total)).summary(format!("{len} bytes"))).await;
            pos = pos.saturating_add(total);
            pos = pos.checked_next_multiple_of(4).unwrap_or(u64::MAX);
        }
    }
    let list: Vec<String> = counts.iter().map(|(k, n)| format!("{n}× {k}")).collect();
    cx.annotate(format!("MTF {major}.x media {name:?}, {block_size}-byte blocks: {}", list.join(", ")));
    Ok(())
}

fn oracle_probe(h: &Head<'_>) -> bool {
    h.at(2, b"EXPORT:V")
}

declare_format!(pub ORACLE_EXP = "oracle-exp", "Oracle export dump (exp)", ["dmp"], "application/x-oracle-dump",
    Probe::Custom(oracle_probe), oracle_exp);

async fn oracle_exp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = head_lines(&cx, file.tail(2), 512).await?;
    let labels = ["Export version", "User", "Mode", "Buffer"];
    let mut version = String::new();
    let mut user = String::new();
    for (i, (line, span)) in all.iter().take(4).enumerate() {
        let value = if i == 0 { line.trim_start_matches("EXPORT:").to_owned() } else { line.get(1..).unwrap_or_default().to_owned() };
        if i == 0 {
            version = value.clone();
        } else if i == 1 {
            user = value.clone();
        }
        cx.emit(Node::new(labels.get(i).copied().unwrap_or("Line")).span(*span).value(text(value)));
    }
    cx.emit(Node::new("Dump body").span(file.tail(512)));
    cx.annotate(format!("Oracle export {version}, user {user}"));
    Ok(())
}

declare_format!(pub PG_DUMP = "pg-dump", "PostgreSQL custom-format dump", ["dump", "backup", "pgdump"], "application/x-pg-dump",
    Probe::Magic(&[(0, b"PGDMP")]), pg_dump);

async fn pg_dump(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 11)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 5).emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    let rev = f.u8("Revision").emit()?;
    let int_size = f.u8("Integer size").emit()?;
    f.u8("Offset size").emit()?;
    let format = f.u8("Format").enumeration(&[(1, "custom"), (2, "files"), (3, "tar"), (4, "null"), (5, "directory")]).emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(11);
    let int_size = u64::from(int_size).clamp(1, 8);
    // Integers: a sign byte, then `int_size` little-endian bytes.
    async fn int(cur: &mut Cursor<'_>, size: u64) -> Result<i64> {
        let sign = cur.u8().await?;
        let b = cur.bytes(size).await?;
        let v = b.iter().rev().fold(0i64, |a, &x| a.wrapping_shl(8) | i64::from(x));
        Ok(if sign != 0 { v.wrapping_neg() } else { v })
    }
    async fn string(cur: &mut Cursor<'_>, size: u64) -> Result<(String, Span)> {
        let len = int(cur, size).await?;
        if len < 0 {
            return Ok((String::new(), cur.span(0)));
        }
        let len = u64::try_from(len).unwrap_or(0);
        let span = cur.span(len);
        let s = String::from_utf8_lossy(&cur.bytes(len).await?).into_owned();
        Ok((s, span))
    }
    let at = cur.pos();
    let compression = if (major, minor) >= (1, 15) {
        i64::from(cur.u8().await?)
    } else {
        int(&mut cur, int_size).await?
    };
    cx.emit(Node::new("Compression").span(cur.since(at)).value(Value::Int { value: compression, bits: 32 }));
    let at = cur.pos();
    let mut t = [0i64; 7];
    for v in &mut t {
        *v = int(&mut cur, int_size).await?;
    }
    let [sec, min, hour, mday, mon, year, _] = t;
    cx.emit(Node::new("Created").span(cur.since(at)).value(text(format!(
        "{:04}-{:02}-{:02} {hour:02}:{min:02}:{sec:02}",
        year.saturating_add(1900),
        mon.saturating_add(1),
        mday
    ))));
    let (db, span) = string(&mut cur, int_size).await?;
    cx.emit(Node::new("Database").span(span).value(text(db.clone())));
    let (server, span) = string(&mut cur, int_size).await?;
    cx.emit(Node::new("Server version").span(span).value(text(server.clone())));
    let (tool, span) = string(&mut cur, int_size).await?;
    cx.emit(Node::new("pg_dump version").span(span).value(text(tool)));
    let at = cur.pos();
    let entries = int(&mut cur, int_size).await?;
    cx.emit(Node::new("TOC entries").span(cur.since(at)).value(Value::Int { value: entries, bits: 32 }));
    cx.emit(Node::new("Table of contents and data").span(file.tail(cur.pos())));
    let _ = format;
    cx.annotate(format!("PostgreSQL dump v{major}.{minor}.{rev} of {db:?} (server {server}), {entries} TOC entries"));
    Ok(())
}

const MYSQL_ENGINES: EnumTable = &[
    (6, "HEAP"),
    (9, "MyISAM"),
    (10, "MRG_MyISAM"),
    (11, "BerkeleyDB"),
    (12, "InnoDB"),
    (14, "NDB Cluster"),
    (16, "ARCHIVE"),
    (17, "CSV"),
    (18, "FEDERATED"),
    (19, "BLACKHOLE"),
    (20, "partitioned"),
    (27, "Aria"),
    (28, "PERFORMANCE_SCHEMA"),
    (42, "dynamic"),
];

declare_format!(pub MYSQL_FRM = "mysql-frm", "MySQL table definition (FRM)", ["frm"], "application/x-mysql-frm",
    Probe::Magic(&[(0, b"\xfe\x01\x09"), (0, b"\xfe\x01\x0a"), (0, b"\xfe\x01\x0b"), (0, b"\xfe\x01\x0c")]), mysql_frm);

async fn mysql_frm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x40)).await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 2)));
    cx.emit(Node::new("FRM version").span(file.sub(2, 1)).value(uint(head.get(2).copied().unwrap_or(0).into(), 8)));
    let engine = head.get(3).copied().unwrap_or(0);
    let name = MYSQL_ENGINES.iter().find(|(k, _)| *k == u64::from(engine)).map(|(_, v)| *v);
    cx.emit(Node::new("Engine").span(file.sub(3, 1)).value(Value::Enum { raw: engine.into(), bits: 8, name }));
    cx.emit(Node::new("I/O size").span(file.sub(4, 2)).value(uint(u16_le(&head, 4).unwrap_or(0).into(), 16)));
    cx.emit(Node::new("Record length").span(file.sub(0x10, 2)).value(uint(u16_le(&head, 0x10).unwrap_or(0).into(), 16)));
    let version = u32_le(&head, 0x33).unwrap_or(0);
    cx.emit(Node::new("MySQL version").span(file.sub(0x33, 4)).value(text(format!("{}.{}.{}", version / 10000, version / 100 % 100, version % 100))));
    cx.emit(Node::new("Key and column definitions").span(file.tail(0x40)));
    cx.annotate(format!("MySQL table definition, {} engine, written by {}.{}.{}", name.unwrap_or("unknown"), version / 10000, version / 100 % 100, version % 100));
    Ok(())
}

declare_format!(pub MYISAM = "myisam-index", "MyISAM index (MYI)", ["myi"], "application/x-myisam",
    Probe::Magic(&[(0, b"\xfe\xfe\x07\x01"), (0, b"\xfe\xfe\x0b\x01")]), myisam);

async fn myisam(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 36)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.bytes("Signature", 4).emit()?;
    f.u16("Options").hex().emit()?;
    f.u16("Header length").emit()?;
    f.u16("State info length").emit()?;
    f.u16("Base info length").emit()?;
    f.u16("Base position").emit()?;
    f.u16("Key parts").emit()?;
    f.u16("Unique key parts").emit()?;
    let keys = f.u8("Keys").emit()?;
    f.u8("Uniques").emit()?;
    f.u8("Language").emit()?;
    f.u8("Max block size index").emit()?;
    f.u8("Full-text keys").emit()?;
    f.u8("Unused").emit()?;
    f.u16("Open count").emit()?;
    f.u8("Changed").emit()?;
    f.u8("Sort key").emit()?;
    let records = f.u64("Records").emit()?;
    cx.emit(Node::new("State, base and key definitions").span(file.tail(36)));
    cx.annotate(format!("MyISAM index, {keys} keys, {records} records"));
    Ok(())
}

declare_format!(pub H2 = "h2-mvstore", "H2 database (MVStore)", ["db", "mv.db"], "application/x-h2",
    Probe::Magic(&[(0, b"H:2,")]), h2);

async fn h2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4096)).await?;
    let end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let header = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
    let mut pos = 0u64;
    let mut pairs = Vec::new();
    for pair in header.split(',') {
        let len = to_u64(pair.len());
        if let Some((k, v)) = pair.split_once(':') {
            let decoded = u64::from_str_radix(v, 16).ok();
            let node = Node::new(k.to_owned()).span(file.sub(pos, len));
            cx.emit(match (k, decoded) {
                ("created" | "blockSize" | "version" | "format" | "block" | "chunk", Some(d)) => node.value(uint(d, 64)).summary(format!("hex {v}")),
                _ => node.value(text(v)),
            });
            pairs.push((k.to_owned(), v.to_owned()));
        }
        pos = pos.saturating_add(len).saturating_add(1);
    }
    cx.emit(Node::new("Second store header").span(file.sub(4096, 4096)));
    cx.emit(Node::new("Chunks").span(file.tail(8192)));
    let get = |k: &str| pairs.iter().find(|(a, _)| a == k).map_or("?", |(_, v)| v.as_str());
    cx.annotate(format!("H2 MVStore, format {}, version {}", get("format"), get("version")));
    Ok(())
}

fn filemaker_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x00\x01\x00\x00\x00\x02\x00\x01\x00\x05\x00\x02\x00\x02\xc0") && h.at(15, b"HBAM")
}

declare_format!(pub FILEMAKER = "filemaker", "FileMaker Pro database", ["fp7", "fmp12", "fp5"], "application/x-filemaker",
    Probe::Custom(filemaker_probe), filemaker);

async fn filemaker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1024)).await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 15)));
    let kind = String::from_utf8_lossy(head.get(15..20).unwrap_or_default()).into_owned();
    cx.emit(Node::new("Format").span(file.sub(15, 5)).value(text(kind.clone())));
    // A Pascal-string application version sits in the first block.
    let version = head
        .windows(4)
        .position(|w| w == b"Pro " || w == b"Fil ")
        .and_then(|p| head.get(p..).map(|r| zstr(r.get(..32).unwrap_or_default())))
        .unwrap_or_default();
    if !version.is_empty() {
        cx.emit(Node::new("Application").value(text(version.clone())));
    }
    cx.emit(Node::new("Blocks").span(file.tail(1024)).summary("4 KiB blocks"));
    cx.annotate(format!("FileMaker {kind} database{}", if version.is_empty() { String::new() } else { format!(" ({version})") }));
    Ok(())
}

// ---------------------------------------------------------------------------
// Data: R serialization (RDS/RData), ASDF

fn r_probe(h: &Head<'_>) -> bool {
    (h.starts_with(b"X\n\0\0\0\x02") || h.starts_with(b"X\n\0\0\0\x03"))
        || ((h.starts_with(b"RDX2\n") || h.starts_with(b"RDX3\n")) && h.at(5, b"X\n"))
}

declare_format!(pub R_DATA = "r-serialized", "R serialized data (RDS/RData)", ["rds", "rdata", "rda"], "application/x-r-data",
    Probe::Custom(r_probe), r_data);

const SEXP_TYPES: EnumTable = &[
    (0, "NULL"),
    (1, "symbol"),
    (2, "pairlist"),
    (3, "closure"),
    (4, "environment"),
    (6, "language"),
    (10, "logical vector"),
    (13, "integer vector"),
    (14, "double vector"),
    (15, "complex vector"),
    (16, "character vector"),
    (19, "list"),
    (20, "expression vector"),
    (24, "raw vector"),
    (25, "S4 object"),
];

async fn r_data(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let rdata = cx.read(file.sub(0, 4)).await? == b"RDX2" || cx.read(file.sub(0, 4)).await? == b"RDX3";
    let mut at = 0u64;
    if rdata {
        cx.emit(Node::new("RData signature").span(file.sub(0, 5)));
        at = 5;
    }
    let body = file.tail(at);
    let head = cx.block(body.sub(0, 14)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Format (XDR)", 2).emit()?;
    let version = f.u32("Serialization version").emit()?;
    let writer = f.u32("Written by R").emit()?;
    f.u32("Minimum reader R").emit()?;
    let mut pos = 14u64;
    if version == 3 {
        let l = u64::from(u32_be(&cx.read(body.sub(pos, 4)).await?, 0).unwrap_or(0));
        let enc = String::from_utf8_lossy(&cx.read(body.sub(pos.saturating_add(4), l.min(64))).await?).into_owned();
        cx.emit(Node::new("Native encoding").span(body.sub(pos, l.saturating_add(4))).value(text(enc)));
        pos = pos.saturating_add(4).saturating_add(l);
    }
    let flags = u32_be(&cx.read(body.sub(pos, 4)).await?, 0).unwrap_or(0);
    let kind = flags & 0xff;
    let name = SEXP_TYPES.iter().find(|(k, _)| *k == u64::from(kind)).map(|(_, v)| *v);
    cx.emit(Node::new("Top-level object").span(body.tail(pos)).value(Value::Enum { raw: kind.into(), bits: 8, name }).summary(format!("flags {flags:#x}")));
    cx.annotate(format!(
        "R {} (serialization v{version}, R {}.{}.{}), top level {}",
        if rdata { "workspace (RData)" } else { "object (RDS)" },
        writer >> 16,
        (writer >> 8) & 0xff,
        writer & 0xff,
        name.unwrap_or("unknown type")
    ));
    Ok(())
}

declare_format!(pub ASDF = "asdf", "Advanced Scientific Data Format", ["asdf"], "application/x-asdf",
    Probe::Magic(&[(0, b"#ASDF ")]), asdf);

async fn asdf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1 << 20)).await?;
    let first = head.iter().position(|&b| b == b'\n').unwrap_or(0);
    let version = String::from_utf8_lossy(head.get(6..first).unwrap_or_default()).into_owned();
    // The YAML tree ends with "...\n"; binary blocks follow (magic \xd3BLK).
    let tree_end = head.windows(5).position(|w| w == b"\n...\n").map_or(to_u64(head.len()), |p| to_u64(p).saturating_add(5));
    cx.emit(Node::new("Header").span(file.sub(0, to_u64(first))).value(text(version.clone())));
    let yaml_at = head.windows(5).position(|w| w == b"%YAML").map_or(0, to_u64);
    cx.emit(embedded("Tree (YAML)", input.nested(file.sub(yaml_at, tree_end.saturating_sub(yaml_at)))));
    let mut pos = tree_end;
    let mut blocks = 0u32;
    while pos.saturating_add(6) <= file.len {
        let h = cx.read(file.sub(pos, 6)).await?;
        if !h.starts_with(b"\xd3BLK") {
            break;
        }
        let header_len = u64::from(u16_be(&h, 4).unwrap_or(0));
        let b = cx.read(file.sub_exact(pos.saturating_add(6), header_len.min(48))?).await?;
        let compression = String::from_utf8_lossy(b.get(4..8).unwrap_or_default()).trim_end_matches('\0').to_owned();
        let allocated = u64_be(&b, 8).unwrap_or(0);
        let used = u64_be(&b, 16).unwrap_or(0);
        let data = file.sub(pos.saturating_add(6).saturating_add(header_len), used);
        let node = Node::new(format!("Block {blocks}"))
            .span(file.sub(pos, 6u64.saturating_add(header_len).saturating_add(allocated)))
            .summary(format!("{used} bytes{}", if compression.is_empty() { String::new() } else { format!(", {compression}") }));
        cx.push(if compression.is_empty() { node } else { node.diag(Diagnostic::note(format!("{compression}-compressed: {data:?}"))) }).await;
        blocks = blocks.saturating_add(1);
        pos = pos.saturating_add(6).saturating_add(header_len).saturating_add(allocated);
    }
    cx.annotate(format!("ASDF {version}, {blocks} binary blocks"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows Address Book, compiled AppleScript

declare_format!(pub WAB = "wab", "Windows Address Book", ["wab"], "application/x-wab",
    Probe::Magic(&[(0, b"\x9c\xcb\xcb\x8d\x13\x75\xd2\x11\x91\x58\x00\xc0\x4f\x79\x56\xa4")]), wab);

async fn wab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x34)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.guid("Signature").emit()?;
    f.u32("Next entry ID").emit()?;
    // Index descriptors: type, maximum, offset, count.
    let mut total = 0u32;
    for name in ["Text index", "Name index"] {
        f.u32(name).hex().emit()?;
        f.u32("Maximum entries").emit()?;
        f.u32("Offset").hex().emit()?;
        total = total.saturating_add(f.u32("Entries").emit()?);
    }
    cx.emit(Node::new("Indexes and records").span(file.tail(0x34)));
    cx.annotate(format!("Windows Address Book, {total} index entries"));
    Ok(())
}

declare_format!(pub APPLESCRIPT = "applescript", "Compiled AppleScript", ["scpt"], "application/x-applescript",
    Probe::Magic(&[(0, b"FasdUAS ")]), applescript);

async fn applescript(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let version = String::from_utf8_lossy(head.get(8..16).unwrap_or_default()).trim_end().to_owned();
    cx.emit(Node::new("Signature").span(file.sub(0, 8)).value(text("FasdUAS")));
    cx.emit(Node::new("Version").span(file.sub(8, 8)).value(text(version.clone())));
    cx.emit(Node::new("Serialized script").span(file.tail(16)));
    let tail = cx.read_avail(file.sub(file.len.saturating_sub(16), 16)).await?;
    if tail.windows(4).any(|w| w == b"ascr") {
        cx.emit(Node::new("Trailer").span(file.sub(file.len.saturating_sub(16), 16)).summary("ascr marker"));
    }
    cx.annotate(format!("compiled AppleScript (FasdUAS {version})"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Packaging: AppImage, Solaris datastream, Haiku packages, Electron ASAR

fn appimage_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x7fELF") && (h.at(8, b"AI\x02") || h.at(8, b"AI\x01"))
}

declare_format!(pub APPIMAGE = "appimage", "AppImage", ["appimage"], "application/vnd.appimage",
    Probe::Custom(appimage_probe), appimage);

async fn appimage(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = cx.read(file.sub(0, 64)).await?;
    let kind = h.get(10).copied().unwrap_or(0);
    let is64 = h.get(4) == Some(&2);
    let little = h.get(5) != Some(&2);
    let u16_at = |at: usize| if little { u16_le(&h, at) } else { u16_be(&h, at) }.unwrap_or(0);
    let (shoff, entsize, count) = if is64 {
        (if little { u64_le(&h, 0x28) } else { u64_be(&h, 0x28) }.unwrap_or(0), u16_at(0x3a), u16_at(0x3c))
    } else {
        (u64::from(if little { u32_le(&h, 0x20) } else { u32_be(&h, 0x20) }.unwrap_or(0)), u16_at(0x2e), u16_at(0x30))
    };
    // The runtime ends with its section header table; the image follows.
    let end = shoff.saturating_add(u64::from(entsize).saturating_mul(count.into()));
    if end == 0 || end >= file.len {
        return Err(Diagnostic::malformed("cannot locate the end of the ELF runtime").at(file.sub(0, 64)));
    }
    cx.emit(Node::new("AppImage type").span(file.sub(8, 3)).value(uint(kind.into(), 8)));
    cx.emit(embedded_as("Runtime (ELF)", input.nested(file.sub(0, end)), &crate::formats::elf::FORMAT));
    cx.emit(embedded(if kind == 1 { "Filesystem image (ISO 9660)" } else { "Filesystem image (SquashFS)" }, input.nested(file.tail(end))));
    cx.annotate(format!("AppImage type {kind}, payload at {end:#x}"));
    Ok(())
}

declare_format!(pub SOLARIS_PKG = "solaris-pkg", "SVR4 package datastream", ["pkg"], "application/x-svr4-package",
    Probe::Magic(&[(0, b"# PaCkAgE DaTaStReAm\n")]), solaris_pkg);

async fn solaris_pkg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = head_lines(&cx, file, 8192).await?;
    let mut end = 0u64;
    let mut packages = Vec::new();
    for (line, span) in all.iter().skip(1) {
        if line.starts_with("# end of header") {
            end = span.end().saturating_sub(file.offset);
            break;
        }
        let mut parts = line.split_whitespace();
        if let (Some(name), Some(parts_n), Some(size)) = (parts.next(), parts.next(), parts.next()) {
            packages.push(name.to_owned());
            cx.emit(Node::new(name.to_owned()).span(*span).summary(format!("{parts_n} part(s), up to {size} blocks")));
        }
    }
    cx.emit(Node::new("Header").span(file.sub(0, end)));
    let body = end.checked_next_multiple_of(512).unwrap_or(u64::MAX);
    cx.emit(embedded("Package archives (cpio)", input.nested(file.tail(body))));
    cx.annotate(format!("SVR4 package datastream: {}", packages.join(", ")));
    Ok(())
}

declare_format!(pub HPKG = "haiku-package", "Haiku package", ["hpkg", "hpkr"], "application/x-haiku-package",
    Probe::Magic(&[(0, b"hpkg"), (0, b"hpkr")]), hpkg);

async fn hpkg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let repo = cx.read(file.sub(0, 4)).await? == b"hpkr";
    let head = cx.block(file.sub(0, 40)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    let header = f.u16("Header size").emit()?;
    let version = f.u16("Version").emit()?;
    let total = f.u64("Total size").emit()?;
    f.u16("Minor version").emit()?;
    let compression = f.u16("Heap compression").enumeration(&[(0, "none"), (1, "zlib"), (2, "zstd")]).emit()?;
    let chunk = f.u32("Heap chunk size").emit()?;
    let compressed = f.u64("Heap size (compressed)").emit()?;
    let uncompressed = f.u64("Heap size (uncompressed)").emit()?;
    let heap = file.sub(header.into(), compressed);
    cx.emit(Node::new("Heap").span(heap).summary(format!("{uncompressed} bytes uncompressed in {chunk}-byte chunks")));
    let _ = compression;
    cx.annotate(format!("Haiku {} v{version}, {total} bytes", if repo { "repository" } else { "package" }));
    Ok(())
}

fn asar_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(4) && h.at(16, b"{\"files\":")
}

declare_format!(pub ASAR = "asar", "Electron archive (ASAR)", ["asar"], "application/x-asar",
    Probe::Custom(asar_probe), asar);

async fn asar(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Size field length").emit()?;
    let header = f.u32("Header size").emit()?;
    f.u32("Header pickle payload").emit()?;
    let json = f.u32("Header JSON length").emit()?;
    cx.emit(embedded("Header (JSON)", input.nested(file.sub(16, json.into()))));
    let data = 8u64.saturating_add(header.into());
    cx.emit(Node::new("File data").span(file.tail(data)).summary("offsets in the header are relative to here"));
    cx.annotate(format!("Electron ASAR, {json}-byte index"));
    Ok(())
}
