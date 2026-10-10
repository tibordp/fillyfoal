//! Desktop password stores: GNOME Keyring files (`.keyring`) and KDE
//! KWallet files (`.kwl`). Both keep a cleartext index (item attributes or
//! name hashes) in front of the encrypted secrets.

use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::size;
use crate::formats::util::val::text;
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::text::hex_lower;
use crate::value::{EnumTable, Value, lookup};

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// GNOME Keyring

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

async fn gnome_keyring(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    cx.emit(Node::new("Signature").span(cur.span(16)));
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
                    "AES-128"
                } else {
                    "unknown cipher"
                },
                if get(3) == 0 {
                    "MD5 key derivation"
                } else {
                    "unknown hash"
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
    f.u32("Flags").hex().emit()?;
    f.u32("Lock timeout (s)").emit()?;
    f.u32("Hash iterations").emit()?;
    f.bytes("Salt", 8).emit()?;
    f.bytes("Reserved", 16).emit()?;
    cur.skip(52);
    let count_span = cur.span(4);
    let count = cur.u32().await?;
    cx.emit(
        Node::new("Number of items")
            .span(count_span)
            .value(Value::UInt {
                value: count.into(),
                bits: 32,
                radix: crate::value::Radix::Dec,
            }),
    );
    for i in 0..count.min(100_000) {
        let start = cur.pos();
        let id = cur.u32().await?;
        let kind = cur.u32().await?;
        let attrs = cur.u32().await?;
        let mut names = Vec::new();
        for _ in 0..attrs.min(1024) {
            let (n, _) = kr_string(&mut cur).await?;
            let t = cur.u32().await?;
            if t == 0 {
                kr_string(&mut cur).await?;
            } else {
                cur.skip(4);
            }
            names.push(n.unwrap_or_default());
        }
        cx.push(
            Node::new(format!("Item {id}"))
                .span(cur.since(start))
                .value(Value::Enum {
                    raw: kind.into(),
                    bits: 32,
                    name: lookup(ITEM_TYPES, kind.into()),
                })
                .summary(format!("hashed attributes: {}", names.join(", ")))
                .desc(format!("Item index {i}")),
        )
        .await;
    }
    let len_span = cur.span(4);
    let enc = u64::from(cur.u32().await?);
    cx.emit(
        Node::new("Encrypted size")
            .span(len_span)
            .value(Value::UInt {
                value: enc,
                bits: 32,
                radix: crate::value::Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("Encrypted data")
            .span(cur.span(enc))
            .diag(Diagnostic::note(
                "AES-128-CBC; requires the keyring password",
            )),
    );
    cx.annotate(format!(
        "GNOME Keyring {name:?}, {count} items, {} encrypted",
        size(enc)
    ));
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
