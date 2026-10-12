//! Office document encryption headers (MS-OFFCRYPTO): the RC4 and
//! CryptoAPI headers of binary documents (Excel's FILEPASS, the start of
//! Word's table stream, PowerPoint's CryptSession10Container), and the
//! `EncryptionInfo` and `EncryptedPackage` streams that wrap an encrypted
//! Office Open XML package in a compound file.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::codec::crypto::office::Rc4Key;
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Fields;
use crate::formats::Input;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

use super::rec::LE;

pub const ALG_IDS: EnumTable = &[
    (0x6801, "RC4"),
    (0x660e, "AES-128"),
    (0x660f, "AES-192"),
    (0x6610, "AES-256"),
];
const HASH_IDS: EnumTable = &[(0x8004, "SHA-1")];
const CRYPTO_FLAGS: FlagTable = &[
    flag(0x04, "fCryptoAPI"),
    flag(0x08, "fDocProps"),
    flag(0x10, "fExternal"),
    flag(0x20, "fAES"),
];

/// Largest EncryptionInfo stream read (an agile descriptor is a few KiB).
const MAX_INFO: u64 = 0x10000;

/// The scheme an `EncryptionVersionInfo` names, in a few words.
pub fn version_name(major: u16, minor: u16) -> String {
    match (major, minor) {
        (1, 1) => "RC4, version 1.1".to_owned(),
        (2..=4, 2) => format!("CryptoAPI, version {major}.2"),
        (3 | 4, 3) => format!("extensible, version {major}.3"),
        (4, 4) => "agile, version 4.4".to_owned(),
        _ => format!("unknown version {major}.{minor}"),
    }
}

/// The scheme of an encryption header that starts with its version, with
/// the cipher where the header names one ("CryptoAPI, version 4.2,
/// AES-128"). `span` is where `data` was read from.
pub fn summary(data: &[u8], span: Span) -> String {
    let (Some(major), Some(minor)) = (u16_le(data, 0), u16_le(data, 2)) else {
        return "encrypted".to_owned();
    };
    let mut s = version_name(major, minor);
    if (3 | 4, 2) == (major, minor) && u32_le(data, 4).is_some_and(|f| f & 0x20 != 0) {
        // fAES: ECMA-376 standard encryption of an OOXML package.
        s = format!("standard, version {major}.2");
    }
    if (2..=4).contains(&major) && minor == 2 {
        // Version, flags, header size, then the header: flags, SizeExtra,
        // AlgID.
        if let Some(alg) = u32_le(data, 20)
            && let Some(name) = lookup(ALG_IDS, alg.into())
        {
            s = format!("{s}, {name}");
        }
    } else if (major, minor) == (4, 4) {
        let xml = data.get(8..).unwrap_or_default();
        let at = span.sub(8, to_u64(xml.len()));
        let attr = |name| crate::formats::publishing::tag_attr(xml, at, b"<keyData", name);
        if let (Some(cipher), Some(bits)) = (attr("cipherAlgorithm"), attr("keyBits")) {
            s = format!("{s}, {cipher}-{bits}");
        }
        if let Some(hash) = attr("hashAlgorithm") {
            s = format!("{s}, {hash}");
        }
    }
    s
}

/// An `EncryptionVersionInfo` and what follows it in a binary document:
/// RC4 (MS-OFFCRYPTO 2.3.6.1: salt, verifier and its MD5 hash) or
/// CryptoAPI (2.3.5.1: EncryptionHeader and EncryptionVerifier).
pub fn header(f: &mut Fields<'_>) -> Result<()> {
    let major = f.u16("vMajor").emit()?;
    let minor = f.u16("vMinor").emit()?;
    if major == 1 && minor == 1 {
        f.bytes("Salt", 16).emit()?;
        f.bytes("EncryptedVerifier", 16).emit()?;
        f.bytes("EncryptedVerifierHash", 16).desc("MD5").emit()?;
        return Ok(());
    }
    if (2..=4).contains(&major) && minor == 2 {
        standard(f)?;
    }
    Ok(())
}

/// The RC4 CryptoAPI key of an encryption header that starts with its
/// version (MS-OFFCRYPTO 2.3.5.1: version 2.2, 3.2 or 4.2, flags, header
/// size, EncryptionHeader, EncryptionVerifier) for `password`, and whether
/// the verifier accepts it; `None` for another scheme or a short header.
pub fn cryptoapi_key(info: &[u8], password: &str) -> Option<(Rc4Key, bool)> {
    if !matches!((u16_le(info, 0)?, u16_le(info, 2)?), (2..=4, 2)) {
        return None;
    }
    // Flags, header size, then the header: KeySize at offset 16.
    let header = to_usize(u32_le(info, 8)?.into());
    let bits = u32_le(info, 12usize.saturating_add(16))?;
    let verifier = 12usize.checked_add(header)?;
    let salt_len = to_usize(u32_le(info, verifier)?.into());
    let salt_at = verifier.saturating_add(4);
    let salt = info.get(salt_at..salt_at.checked_add(salt_len)?)?;
    let v_at = salt_at.saturating_add(salt_len);
    let encrypted_verifier = info.get(v_at..v_at.saturating_add(16))?;
    let hash_len = to_usize(u32_le(info, v_at.saturating_add(16))?.into());
    let h_at = v_at.saturating_add(20);
    let hash = info.get(h_at..h_at.checked_add(hash_len)?)?;
    let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let key = Rc4Key::cryptoapi(&utf16, salt, bits);
    let ok = key.verify(encrypted_verifier, hash);
    Some((key, ok))
}

/// [`header`] as a layout, for a lazy node.
pub fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    header(f)
}

/// After the version: flags, the EncryptionHeader (with its CSP name) and
/// the EncryptionVerifier. Shared by CryptoAPI RC4 and ECMA-376 standard
/// encryption.
fn standard(f: &mut Fields<'_>) -> Result<()> {
    f.u32("Flags").flags(CRYPTO_FLAGS).emit()?;
    let size = f.u32("EncryptionHeaderSize").emit()?;
    let header_end = f.pos().saturating_add(u64::from(size));
    f.u32("Flags (header)").flags(CRYPTO_FLAGS).emit()?;
    f.u32("SizeExtra").emit()?;
    f.u32("AlgID").hex().enumeration(ALG_IDS).emit()?;
    f.u32("AlgIDHash").hex().enumeration(HASH_IDS).emit()?;
    f.u32("KeySize").desc("Bits; 0 means 40").emit()?;
    f.u32("ProviderType").hex().emit()?;
    f.u32("Reserved1").emit()?;
    f.u32("Reserved2").emit()?;
    let csp = header_end.saturating_sub(f.pos()).min(f.remaining()) / 2;
    if csp > 0 {
        f.utf16("CSPName", csp).emit()?;
    }
    if f.remaining() >= 4 {
        let salt = f.u32("SaltSize").emit()?;
        let n = u64::from(salt).min(f.remaining());
        f.bytes("Salt", n).emit()?;
        let n = f.remaining().min(16);
        f.bytes("EncryptedVerifier", n).emit()?;
        if f.remaining() >= 4 {
            f.u32("VerifierHashSize")
                .desc("Bytes of the verifier's hash (20 for SHA-1)")
                .emit()?;
            let n = f.remaining();
            f.bytes("EncryptedVerifierHash", n)
                .desc("Padded to the cipher's block size")
                .emit()?;
        }
    }
    Ok(())
}

/// The `EncryptionInfo` stream of an encrypted Office Open XML document:
/// the version, then standard encryption's binary header and verifier, or
/// agile encryption's XML descriptor.
pub async fn encryption_info(cx: &Cx, input: Input, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, MAX_INFO)).await?;
    let mut f = Fields::emitting(cx, &block, LE);
    let major = u16_le(&block.data, 0).unwrap_or(0);
    let minor = u16_le(&block.data, 2).unwrap_or(0);
    cx.annotate(summary(&block.data, block.span));
    f.u16("vMajor").emit()?;
    f.u16("vMinor").emit()?;
    match (major, minor) {
        (2..=4, 2) => standard(&mut f)?,
        (4, 4) => {
            f.u32("Reserved").hex().desc("0x40").emit()?;
            let xml = span.tail(8);
            cx.emit(
                crate::formats::embedded("XmlEncryptionDescriptor", input.nested(xml))
                    .span(xml)
                    .desc("Key data, data integrity HMAC and the password key encryptor"),
            );
            let text = block.data.get(8..).unwrap_or_default();
            let at = block.span.sub(8, to_u64(text.len()));
            let attr = |tag, name| crate::formats::publishing::tag_attr(text, at, tag, name);
            let spin = attr(b"<p:encryptedKey", "spinCount")
                .or_else(|| attr(b"<encryptedKey", "spinCount"));
            if let Some(spin) = spin {
                cx.emit(
                    Node::new("Password hash rounds")
                        .value(crate::value::Value::Text(spin))
                        .desc("The password key encryptor's spinCount"),
                );
            }
        }
        _ => {
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("Remaining data", rest).emit()?;
            }
        }
    }
    Ok(())
}

/// The `EncryptedPackage` stream: the package's size, then the encrypted
/// ZIP package.
pub async fn encrypted_package(cx: &Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(cx, &block, LE);
    let size = f
        .u64("StreamSize")
        .desc("Bytes of the decrypted package (a ZIP file)")
        .emit()?;
    cx.emit(
        Node::new("Encrypted data")
            .span(span.tail(8))
            .summary(format!(
                "{} bytes, {size} when decrypted",
                span.len.saturating_sub(8)
            ))
            .desc("The package, encrypted in 4096-byte segments"),
    );
    Ok(())
}
