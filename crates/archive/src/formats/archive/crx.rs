//! Chrome extensions (`.crx`, versions 2 and 3) and Mozilla `mozlz4`
//! files.
//!
//! A CRX is a small header (`Cr24`) carrying the publisher's key and
//! signature, followed by a ZIP archive. Version 3 stores them in a
//! protocol buffer (`CrxFileHeader`), read with `util::wire::protobuf`. `mozlz4` (Firefox session and search files) is a magic,
//! the decompressed size and an LZ4 block, decompressed on expansion.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt::{hex_lower, size};
use crate::formats::util::val::{hex, uint};
use crate::formats::util::wire::protobuf as pb;
use crate::formats::{Format, Input, Probe, archive::zip, embedded_as, embedded_named};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;
const MAX_DEPTH: u32 = 8;

pub static CRX: Format = Format {
    name: "crx",
    title: "Chrome extension package",
    extensions: &["crx"],
    mime: "application/x-chrome-extension",
    probe: Probe::Magic(&[(0, b"Cr24\x02\x00\x00\x00"), (0, b"Cr24\x03\x00\x00\x00")]),
    dissect: crate::expander!(crx: Input),
};

pub static MOZLZ4: Format = Format {
    name: "mozlz4",
    title: "Mozilla LZ4-compressed file",
    extensions: &["mozlz4", "jsonlz4", "baklz4"],
    mime: "application/x-mozlz4",
    probe: Probe::Magic(&[(0, b"mozLz40\0")]),
    dissect: crate::expander!(mozlz4: Input),
};

record! {
    pub struct Crx2Header {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        key_len: u32 "Public key length",
        sig_len: u32 "Signature length",
    }
}

pub async fn crx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub_exact(0, 12)?).await?;
    let version = u32_le(&head, 4).unwrap_or(0);
    let zip_at = if version == 2 {
        let mut cur = Cursor::new(&cx, file, LE);
        let (h, span) = cur.record::<Crx2Header>().await?;
        cx.emit(Crx2Header::node("Header", span, LE));
        let key = file.sub(Crx2Header::SIZE, h.key_len.into());
        let sig = file.sub(key.end().saturating_sub(file.offset), h.sig_len.into());
        // A SubjectPublicKeyInfo; the signature is a bare RSA value.
        cx.emit(embedded_named("Public key", input.nested(key), "der").summary(size(key.len)));
        cx.emit(Node::new("Signature").span(sig).summary(size(sig.len)));
        sig.end().saturating_sub(file.offset)
    } else {
        let header_len = u64::from(u32_le(&head, 8).unwrap_or(0));
        cx.emit(crate::fields::struct_node(
            "Header",
            file.sub(0, 12),
            LE,
            (),
            |f, _| {
                f.ascii("Magic", 4).emit()?;
                f.u32("Version").emit()?;
                f.u32("Header size").emit()?;
                Ok(())
            },
        ));
        let proto = file.sub(12, header_len);
        cx.emit(
            Node::new("CrxFileHeader")
                .span(proto)
                .summary(format!("{} (protocol buffer)", size(proto.len)))
                .lazy(message, (input, proto, Kind::FileHeader, 0u32)),
        );
        12u64.saturating_add(header_len)
    };
    let archive = file.tail(zip_at);
    cx.annotate(format!(
        "Chrome extension (CRX{version}), {} ZIP payload",
        size(archive.len)
    ));
    cx.emit(embedded_as("Archive", input.nested(archive), &zip::FORMAT));
    Ok(())
}

/// The message types of `crx3.proto` this decoder names fields for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    FileHeader,
    RsaProof,
    EcdsaProof,
    SignedData,
    Unknown,
}

fn field_name(kind: Kind, number: u64) -> (&'static str, Kind) {
    match (kind, number) {
        (Kind::FileHeader, 2) => ("sha256_with_rsa", Kind::RsaProof),
        (Kind::FileHeader, 3) => ("sha256_with_ecdsa", Kind::EcdsaProof),
        (Kind::FileHeader, 4) => ("verified_contents", Kind::Unknown),
        (Kind::FileHeader, 10000) => ("signed_header_data", Kind::SignedData),
        (Kind::RsaProof | Kind::EcdsaProof, 1) => ("public_key", Kind::Unknown),
        (Kind::RsaProof | Kind::EcdsaProof, 2) => ("signature", Kind::Unknown),
        (Kind::SignedData, 1) => ("crx_id", Kind::Unknown),
        _ => ("field", Kind::Unknown),
    }
}

/// Walks one protocol buffer message.
async fn message(cx: Cx, (input, span, kind, depth): (Input, Span, Kind, u32)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while !cur.at_end() {
        let start = cur.pos();
        let (number, payload) = pb::read_field(&mut cur).await?;
        let (name, sub) = field_name(kind, number);
        let label = if name == "field" {
            format!("field {number}")
        } else {
            name.to_owned()
        };
        let node = match payload {
            pb::Payload::Varint(v) => Node::new(label).value(uint(v, 64)),
            pb::Payload::I64(v) => Node::new(label).value(hex(v, 64)),
            pb::Payload::I32(v) => Node::new(label).value(hex(v, 32)),
            pb::Payload::Len(body) => {
                let bytes = cx.read_avail(body.sub(0, 32)).await?;
                let mut node = Node::new(label.clone()).summary(size(body.len));
                // The key is a SubjectPublicKeyInfo; an ECDSA signature is a DER
                // Ecdsa-Sig-Value, an RSA one a bare value. Both DER forms are a
                // SEQUENCE.
                let der = bytes.first() == Some(&0x30)
                    && matches!(
                        (kind, name),
                        (Kind::RsaProof | Kind::EcdsaProof, "public_key")
                            | (Kind::EcdsaProof, "signature")
                    );
                if der {
                    node = embedded_named(label, input.nested(body), "der").summary(size(body.len));
                } else if sub != Kind::Unknown && depth < MAX_DEPTH {
                    node = node.lazy(
                        crate::expander!(self::message: (Input, Span, Kind, u32)),
                        (input, body, sub, depth.saturating_add(1)),
                    );
                } else if name == "crx_id" {
                    node = node.value(Value::Text(crx_id(&bytes)));
                } else {
                    node = node.value(Value::Bytes(bytes));
                }
                node
            }
            pb::Payload::StartGroup | pb::Payload::EndGroup => {
                return Err(Diagnostic::unsupported("protobuf groups").at(span.sub(start, 1)));
            }
        };
        cx.push(node.span(cur.since(start))).await;
    }
    Ok(())
}

/// The extension ID: the first 16 bytes of the key hash in letters `a`–`p`.
fn crx_id(bytes: &[u8]) -> String {
    let hex = hex_lower(bytes.get(..16).unwrap_or(bytes));
    hex.chars()
        .map(|c| {
            let v = c.to_digit(16).unwrap_or(0);
            char::from(b'a'.saturating_add(u8::try_from(v).unwrap_or(0)))
        })
        .collect()
}

pub async fn mozlz4(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 8).emit()?;
    let size_out = f.u32("Decompressed size").emit()?;
    cx.annotate(format!(
        "Mozilla LZ4 file, {} uncompressed",
        size(size_out.into())
    ));
    cx.emit(crate::formats::content(
        "LZ4 block",
        input,
        file.tail(12),
        crate::codec::Codec::Lz4Block,
        Some(size_out.into()),
    ));
    Ok(())
}
