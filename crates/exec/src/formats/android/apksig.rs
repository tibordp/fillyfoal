//! APK signatures: the APK Signing Block (`APK Sig Block 42`) that sits
//! between an APK's last local entry and its central directory, APK
//! Signature Scheme v4 files (`.idsig`) and signing certificate lineage
//! files written by `apksigner rotate`.
//!
//! The signing block is a list of ID-value pairs: the v2, v3 and v3.1
//! signature scheme blocks (signers with their signed data: content
//! digests, X.509 certificates, SDK ranges and additional attributes such
//! as the key rotation lineage; signatures and the public key), the source
//! stamp, and padding that aligns the central directory to 4 KiB. Every
//! structure inside is a sequence of `u32`-length-prefixed elements
//! (little-endian). The layout follows `apksig` (the library behind
//! `apksigner`) and Android's `ApkSignatureSchemeV{2,3,4}Verifier`.

use crate::bytes::{to_u64, to_usize, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::asn1::der;
use crate::formats::util::binutil::data_node;
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::name_or;
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;

/// The magic that ends the signing block, right before the central
/// directory.
pub const MAGIC: &[u8; 16] = b"APK Sig Block 42";

pub static SIGNING_BLOCK: Format = Format {
    name: "apk-signing-block",
    title: "APK Signing Block",
    extensions: &[],
    mime: "application/octet-stream",
    probe: Probe::Never,
    dissect: crate::expander!(dissect: Input),
};

pub static IDSIG: Format = Format {
    name: "apk-idsig",
    title: "APK Signature Scheme v4 signature",
    extensions: &["idsig"],
    mime: "application/octet-stream",
    probe: Probe::Custom(idsig_probe),
    dissect: crate::expander!(idsig: Input),
};

pub static LINEAGE: Format = Format {
    name: "apk-lineage",
    title: "APK signing certificate lineage",
    extensions: &["lineage"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"\xd1\x39\xff\x3e\x01\0\0\0")]),
    dissect: crate::expander!(lineage_file: Input),
};

const V2: u32 = 0x7109_871a;
const V3: u32 = 0xf053_68c0;
const V31: u32 = 0x1b93_ad61;
const STAMP_V2: u32 = 0x6dff_800d;
const VERITY_PADDING: u32 = 0x4272_6577;

/// Block IDs of the ID-value pairs (apksig's constants, and the IDs other
/// tools are known to write).
const BLOCK_IDS: EnumTable = &[
    (0x7109_871a, "APK Signature Scheme v2"),
    (0xf053_68c0, "APK Signature Scheme v3"),
    (0x1b93_ad61, "APK Signature Scheme v3.1"),
    (0x6dff_800d, "Source stamp v2"),
    (0x2b09_189e, "Source stamp v1"),
    (0x4272_6577, "Verity padding"),
    (0x504b_4453, "Dependency info (Android Gradle plugin)"),
    (0x2146_444e, "Google Play frosting"),
    (0x7177_7777, "Walle channel info"),
];

const ALGORITHMS: EnumTable = &[
    (0x0101, "RSA_PSS_WITH_SHA256"),
    (0x0102, "RSA_PSS_WITH_SHA512"),
    (0x0103, "RSA_PKCS1_V1_5_WITH_SHA256"),
    (0x0104, "RSA_PKCS1_V1_5_WITH_SHA512"),
    (0x0201, "ECDSA_WITH_SHA256"),
    (0x0202, "ECDSA_WITH_SHA512"),
    (0x0301, "DSA_WITH_SHA256"),
    (0x0421, "VERITY_RSA_PKCS1_V1_5_WITH_SHA256"),
    (0x0423, "VERITY_ECDSA_WITH_SHA256"),
    (0x0425, "VERITY_DSA_WITH_SHA256"),
];

/// Additional attributes of signed data (v2/v3) and of a source stamp.
const ATTRIBUTES: EnumTable = &[
    (0xbeef_f00d, "Stripping protection"),
    (0x3ba0_6f8c, "Proof of rotation"),
    (0x559f_8b02, "Rotation min SDK version"),
    (0xc2a6_b3ba, "Rotation on dev release"),
    (0xe43c_5946, "Stamp time"),
    (0x9d63_03f7, "Stamp proof of rotation"),
];

/// Signature schemes, as named by stripping protection and source stamps.
const SCHEMES: EnumTable = &[
    (1, "JAR signing (v1)"),
    (2, "APK Signature Scheme v2"),
    (3, "APK Signature Scheme v3"),
    (4, "APK Signature Scheme v4"),
    (31, "APK Signature Scheme v3.1"),
];

/// Capabilities a past signing certificate keeps in a lineage.
const LINEAGE_FLAGS: FlagTable = &[
    flag(1, "INSTALLED_DATA"),
    flag(2, "SHARED_USER_ID"),
    flag(4, "PERMISSION"),
    flag(8, "ROLLBACK"),
    flag(16, "AUTH"),
];

const V4_HASH: EnumTable = &[(1, "SHA-256")];

/// Certificates up to this size get their subject in summaries.
const SUMMARY_CERT: usize = 64 * 1024;

/// What a structure or a sequence element holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A v2 (`v3 == false`) or v3/v3.1 signer.
    Signer {
        v3: bool,
    },
    SignedData {
        v3: bool,
    },
    /// A `{u32 algorithm, length-prefixed bytes}` pair.
    Digest,
    Signature,
    Certificate,
    Attribute,
    /// A proof-of-rotation lineage: a version, then nodes.
    Lineage,
    LineageNode,
    LineageSigned,
    /// The source stamp signer (v2).
    Stamp,
    StampDigest,
    /// v4 hashing info and signing info.
    HashingInfo,
    SigningInfo,
    SigningInfos,
}

type State = (Input, Span, Kind);

/// A lazy node over a sequence of length-prefixed elements of `kind`.
fn seq_node(name: &'static str, input: Input, span: Span, kind: Kind) -> Node {
    Node::new(name)
        .span(span)
        .lazy(crate::expander!(self::seq: State), (input, span, kind))
}

/// A lazy node over a structure of `kind` that fills `span`.
fn struct_node(name: &'static str, input: Input, span: Span, kind: Kind) -> Node {
    Node::new(name).span(span).lazy(
        crate::expander!(self::structure: State),
        (input, span, kind),
    )
}

/// A `u32` length field, then the span of the content it measures.
fn lp(f: &mut Fields<'_>, name: &'static str) -> Result<Span> {
    let n = u64::from(f.u32(name).emit()?);
    let left = f.remaining();
    let span = f.peek_span(n);
    if n > left {
        return Err(Diagnostic::truncated(span, left));
    }
    f.skip(n);
    Ok(span)
}

/// Silent reader over in-memory bytes for summaries.
struct Rd<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    fn new(data: &'a [u8]) -> Self {
        Rd { data, pos: 0 }
    }
    fn u32(&mut self) -> Option<u32> {
        let v = u32_le(self.data, self.pos)?;
        self.pos = self.pos.checked_add(4)?;
        Some(v)
    }
    fn lp(&mut self) -> Option<&'a [u8]> {
        let n = to_usize(self.u32()?.into());
        let end = self.pos.checked_add(n)?;
        let v = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(v)
    }
}

/// The subject of a DER certificate (`CN=..., O=...`).
fn subject(cert: &[u8]) -> Option<String> {
    if cert.len() > SUMMARY_CERT {
        return None;
    }
    let (_, body) = der::first(cert)?;
    let (_, tbs) = der::first(body)?;
    let mut fields = der::elements(tbs);
    let (first, _) = fields.next()?;
    // An explicit [0] version comes before the serial number.
    let skip = if first.class == 2 && first.tag == 0 {
        4
    } else {
        3
    };
    let (_, name) = fields.nth(skip)?;
    Some(der::name(name))
}

/// First certificate's subject in v2/v3 signed data.
fn signed_data_subject(signed: &[u8]) -> Option<String> {
    let mut r = Rd::new(signed);
    r.lp()?;
    let certs = r.lp()?;
    subject(Rd::new(certs).lp()?)
}

fn sdk_range(min: u32, max: u32) -> String {
    if max == i32::MAX.unsigned_abs() {
        format!("SDK {min}+")
    } else {
        format!("SDK {min}–{max}")
    }
}

/// Name, summary and value for sequence element `index` holding `content`.
fn describe(kind: Kind, index: u64, content: &[u8]) -> (String, Option<String>, Option<Value>) {
    let mut r = Rd::new(content);
    match kind {
        Kind::Signer { v3 } => {
            let signed = r.lp();
            let mut parts = Vec::new();
            if v3 && let (Some(min), Some(max)) = (r.u32(), r.u32()) {
                parts.push(sdk_range(min, max));
            }
            if let Some(s) = signed.and_then(signed_data_subject) {
                parts.push(s);
            }
            (format!("Signer {index}"), Some(parts.join(", ")), None)
        }
        Kind::Digest | Kind::Signature => {
            let alg = r.u32().unwrap_or(0);
            let bytes = r.lp().map(<[u8]>::to_vec);
            let what = if kind == Kind::Digest {
                "Digest"
            } else {
                "Signature"
            };
            (
                format!("{what} {index}"),
                Some(name_or(ALGORITHMS, alg.into(), "algorithm")),
                bytes.map(Value::Bytes),
            )
        }
        Kind::Certificate => (format!("Certificate {index}"), subject(content), None),
        Kind::Attribute => {
            let id = r.u32().unwrap_or(0);
            let rest = content.get(4..).unwrap_or_default();
            let value = match id {
                0xbeef_f00d | 0x559f_8b02 => u32_le(rest, 0).map(|v| match id {
                    0xbeef_f00d => crate::formats::util::val::enumv(v, 32, SCHEMES),
                    _ => crate::formats::util::val::uint(v, 32),
                }),
                0xe43c_5946 => u64_le(rest, 0).map(|t| Value::Timestamp {
                    unix_seconds: i64::try_from(t).unwrap_or(i64::MAX),
                }),
                _ => None,
            };
            (name_or(ATTRIBUTES, id.into(), "Attribute"), None, value)
        }
        Kind::LineageNode => {
            let signed = r.lp().unwrap_or_default();
            let cert = Rd::new(signed).lp().and_then(subject);
            (format!("Certificate {index}"), cert, None)
        }
        Kind::StampDigest => {
            let scheme = r.u32().unwrap_or(0);
            (
                format!("Digest {index}"),
                Some(name_or(SCHEMES, scheme.into(), "scheme")),
                None,
            )
        }
        _ => (format!("Element {index}"), None, None),
    }
}

/// A sequence of length-prefixed elements.
async fn seq(cx: Cx, (input, span, kind): State) -> Result<()> {
    let block = cx.block(span).await?;
    let data = &block.data;
    let mut pos = 0usize;
    let mut index = 0u64;
    while pos < data.len() {
        let at = span.sub(to_u64(pos), span.len);
        let Some(n) = u32_le(data, pos).map(|n| to_usize(n.into())) else {
            cx.push(data_node("Trailing bytes", at, at.len)).await;
            break;
        };
        let start = pos.saturating_add(4);
        let Some(content) = start.checked_add(n).and_then(|end| data.get(start..end)) else {
            let wanted = span.sub(to_u64(pos), to_u64(n).saturating_add(4));
            cx.push(
                Node::new(format!("Element {index}"))
                    .span(at)
                    .diag(Diagnostic::malformed("length runs past the sequence").at(wanted)),
            )
            .await;
            break;
        };
        let whole = span.sub(to_u64(pos), to_u64(n).saturating_add(4));
        let (name, summary, value) = describe(kind, index, content);
        let mut node = Node::new(name)
            .span(whole)
            .lazy(crate::expander!(self::element: State), (input, whole, kind));
        if let Some(s) = summary.filter(|s| !s.is_empty()) {
            node = node.summary(s);
        }
        if let Some(v) = value {
            node = node.value(v);
        }
        cx.push(node).await;
        pos = start.saturating_add(n);
        index = index.saturating_add(1);
    }
    Ok(())
}

/// One element: its length, then its content.
async fn element(cx: Cx, (input, span, kind): State) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Length").emit()?;
    let content = f.peek_span(f.remaining());
    match kind {
        Kind::Certificate => {
            f.node(embedded_as(
                "Certificate",
                input.nested(content),
                &crate::formats::asn1::X509,
            ));
            Ok(())
        }
        Kind::Signer { .. } | Kind::SignedData { .. } | Kind::LineageNode => {
            fields(&mut f, input, kind)
        }
        Kind::Digest | Kind::Signature => {
            f.u32("Signature algorithm")
                .enumeration(ALGORITHMS)
                .emit()?;
            let what = if kind == Kind::Digest {
                "Digest"
            } else {
                "Signature"
            };
            let len = f
                .u32(if kind == Kind::Digest {
                    "Digest length"
                } else {
                    "Signature length"
                })
                .emit()?;
            f.bytes(what, len.into()).emit()?;
            Ok(())
        }
        Kind::Attribute => {
            let id = f
                .u32("ID")
                .hex()
                .with(|&v, n| match lookup(ATTRIBUTES, v.into()) {
                    Some(name) => n.summary(name),
                    None => n,
                })
                .emit()?;
            attribute_value(&mut f, input, id)
        }
        Kind::StampDigest => {
            f.u32("Scheme").enumeration(SCHEMES).emit()?;
            let sigs = lp(&mut f, "Signatures length")?;
            f.node(seq_node("Signatures", input, sigs, Kind::Signature));
            Ok(())
        }
        _ => Ok(()),
    }
}

fn attribute_value(f: &mut Fields<'_>, input: Input, id: u32) -> Result<()> {
    let rest = f.remaining();
    match id {
        0xbeef_f00d => {
            f.u32("Scheme")
                .enumeration(SCHEMES)
                .desc("Highest signature scheme the APK is also signed with: verifiers that see this attribute reject the APK if that scheme's block was stripped")
                .emit()?;
        }
        0x559f_8b02 => {
            f.u32("Min SDK version")
                .desc("Lowest platform version the rotated key (the v3.1 block) targets")
                .emit()?;
        }
        0xe43c_5946 => {
            f.u64("Time").timestamp().emit()?;
        }
        0x3ba0_6f8c | 0x9d63_03f7 => {
            let span = f.peek_span(rest);
            f.skip(rest);
            f.node(struct_node("Lineage", input, span, Kind::Lineage));
        }
        _ if rest > 0 => {
            f.bytes("Value", rest).emit()?;
        }
        _ => {}
    }
    Ok(())
}

/// A structure that fills its span.
async fn structure(cx: Cx, (input, span, kind): State) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    fields(&mut f, input, kind)
}

fn fields(f: &mut Fields<'_>, input: Input, kind: Kind) -> Result<()> {
    match kind {
        Kind::Signer { v3 } => {
            let signed = lp(f, "Signed data length")?;
            f.node(struct_node(
                "Signed data",
                input,
                signed,
                Kind::SignedData { v3 },
            ));
            if v3 {
                f.u32("Min SDK version").emit()?;
                f.u32("Max SDK version").emit()?;
            }
            let sigs = lp(f, "Signatures length")?;
            f.node(seq_node("Signatures", input, sigs, Kind::Signature));
            let key = lp(f, "Public key length")?;
            f.node(
                embedded_as("Public key", input.nested(key), &crate::formats::asn1::DER)
                    .desc("SubjectPublicKeyInfo"),
            );
        }
        Kind::SignedData { v3 } => {
            let digests = lp(f, "Digests length")?;
            f.node(seq_node("Digests", input, digests, Kind::Digest));
            let certs = lp(f, "Certificates length")?;
            f.node(seq_node("Certificates", input, certs, Kind::Certificate));
            if v3 {
                f.u32("Min SDK version").emit()?;
                f.u32("Max SDK version").emit()?;
            }
            let attrs = lp(f, "Additional attributes length")?;
            f.node(seq_node(
                "Additional attributes",
                input,
                attrs,
                Kind::Attribute,
            ));
            // apksig appends an empty element to v2 signed data.
            while f.remaining() >= 4 {
                let span = lp(f, "Reserved length")?;
                if span.len > 0 {
                    f.node(data_node("Reserved", span, span.len));
                }
            }
        }
        Kind::Lineage => {
            f.u32("Version").emit()?;
            let nodes = f.peek_span(f.remaining());
            f.skip(nodes.len);
            f.node(seq_node("Certificates", input, nodes, Kind::LineageNode));
        }
        Kind::LineageNode => {
            let signed = lp(f, "Signed data length")?;
            f.node(struct_node(
                "Signed data",
                input,
                signed,
                Kind::LineageSigned,
            ));
            f.u32("Flags")
                .flags(LINEAGE_FLAGS)
                .desc("Capabilities this certificate keeps after the rotation")
                .emit()?;
            f.u32("Signature algorithm")
                .enumeration(ALGORITHMS)
                .desc("Algorithm this certificate's key uses to sign the next node (0 in the last node)")
                .emit()?;
            let len = f.u32("Signature length").emit()?;
            if len > 0 {
                f.bytes("Signature", len.into())
                    .desc("The previous certificate's signature over this node's signed data")
                    .emit()?;
            }
        }
        Kind::LineageSigned => {
            let cert = lp(f, "Certificate length")?;
            f.node(embedded_as(
                "Certificate",
                input.nested(cert),
                &crate::formats::asn1::X509,
            ));
            f.u32("Parent signature algorithm")
                .enumeration(ALGORITHMS)
                .desc("Algorithm the previous certificate's key signed this node with (0 in the first node)")
                .emit()?;
        }
        Kind::Stamp => {
            let cert = lp(f, "Certificate length")?;
            f.node(embedded_as(
                "Certificate",
                input.nested(cert),
                &crate::formats::asn1::X509,
            ));
            let digests = lp(f, "Signed digests length")?;
            f.node(
                seq_node("Signed digests", input, digests, Kind::StampDigest)
                    .desc("The stamp key's signatures over each scheme's digest"),
            );
            if f.remaining() >= 8 {
                // The attribute list is wrapped in one more length prefix.
                let outer = lp(f, "Attributes length")?;
                let block = f.block();
                let inner_at = outer.offset.saturating_sub(block.span.offset);
                let mut g = Fields::new(block, LE);
                g.seek(inner_at);
                let inner = u64::from(g.u32("").get()?);
                f.seek(inner_at);
                let attrs = lp(f, "Attribute list length")?;
                f.node(seq_node("Attributes", input, attrs, Kind::Attribute));
                let used = inner.saturating_add(4);
                if outer.len > used {
                    let rest = outer.len.saturating_sub(used);
                    f.node(data_node("Unused", f.peek_span(rest), rest));
                    f.skip(rest);
                }
            }
            if f.remaining() >= 4 {
                let sigs = lp(f, "Attribute signatures length")?;
                f.node(seq_node(
                    "Attribute signatures",
                    input,
                    sigs,
                    Kind::Signature,
                ));
            }
            let rest = f.remaining();
            if rest > 0 {
                f.node(data_node("Trailing data", f.peek_span(rest), rest));
            }
        }
        Kind::HashingInfo => {
            f.u32("Hash algorithm").enumeration(V4_HASH).emit()?;
            f.u8("Log2 block size")
                .with(|&v, n| match 1u64.checked_shl(v.into()) {
                    Some(b) => n.summary(format!("{b}-byte blocks")),
                    None => n,
                })
                .emit()?;
            let salt = lp(f, "Salt length")?;
            if salt.len > 0 {
                f.node(data_node("Salt", salt, salt.len));
            }
            let len = f.u32("Root hash length").emit()?;
            f.bytes("Root hash", len.into())
                .desc("Root of the fs-verity Merkle tree over the APK")
                .emit()?;
        }
        Kind::SigningInfo => v4_signing_info(f, input)?,
        Kind::SigningInfos => {
            v4_signing_info(f, input)?;
            while f.remaining() >= 8 {
                f.u32("Block ID").hex().enumeration(BLOCK_IDS).emit()?;
                let span = lp(f, "Signing info length")?;
                f.node(struct_node(
                    "Signing info (rotated key)",
                    input,
                    span,
                    Kind::SigningInfo,
                ));
            }
        }
        Kind::Digest
        | Kind::Signature
        | Kind::Certificate
        | Kind::Attribute
        | Kind::StampDigest => {}
    }
    Ok(())
}

fn v4_signing_info(f: &mut Fields<'_>, input: Input) -> Result<()> {
    let len = f.u32("APK digest length").emit()?;
    f.bytes("APK digest", len.into())
        .desc("The v3 (or v2) content digest of the APK")
        .emit()?;
    let cert = lp(f, "Certificate length")?;
    f.node(embedded_as(
        "Certificate",
        input.nested(cert),
        &crate::formats::asn1::X509,
    ));
    let extra = lp(f, "Additional data length")?;
    if extra.len > 0 {
        f.node(data_node("Additional data", extra, extra.len));
    }
    let key = lp(f, "Public key length")?;
    f.node(
        embedded_as("Public key", input.nested(key), &crate::formats::asn1::DER)
            .desc("SubjectPublicKeyInfo"),
    );
    f.u32("Signature algorithm")
        .enumeration(ALGORITHMS)
        .emit()?;
    let len = f.u32("Signature length").emit()?;
    f.bytes("Signature", len.into()).emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The signing block

/// Where the signing block before a central directory at `cd` lies, given
/// the 24 bytes before `cd` (size field and magic).
pub fn locate(footer: &[u8], cd: u64) -> Option<(u64, u64)> {
    if footer.get(8..24)? != MAGIC {
        return None;
    }
    let size = u64_le(footer, 0)?;
    let total = size.checked_add(8)?;
    let start = cd.checked_sub(total)?;
    (size >= 24).then_some((start, total))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let declared = f
        .u64("Block size")
        .desc("Bytes after this field, up to the end of the magic")
        .emit()?;
    let end = file.len.saturating_sub(24);
    let mut pos = 8u64;
    let mut names = Vec::new();
    while pos < end {
        let at = file.sub(pos, 12);
        let h = cx.read(at).await?;
        let (Some(len), Some(id)) = (u64_le(&h, 0), u32_le(&h, 8)) else {
            break;
        };
        let pair = file.sub(pos, len.saturating_add(8));
        if len < 4 || pos.saturating_add(8).saturating_add(len) > end {
            cx.emit(
                Node::new("Pair")
                    .span(file.sub(pos, end.saturating_sub(pos)))
                    .diag(Diagnostic::malformed("pair length runs past the block").at(pair)),
            );
            pos = end;
            break;
        }
        let name =
            lookup(BLOCK_IDS, id.into()).map_or_else(|| format!("Block {id:#010x}"), str::to_owned);
        if id != VERITY_PADDING {
            names.push(name.clone());
        }
        cx.push(
            Node::new(name)
                .span(pair)
                .summary(size_or_signers(&cx, pair, id).await)
                .lazy(pair_node, (input, pair, id)),
        )
        .await;
        pos = pos.saturating_add(8).saturating_add(len);
    }
    if pos < end {
        let rest = file.sub(pos, end.saturating_sub(pos));
        cx.emit(data_node("Unused", rest, rest.len));
    }
    let tail = cx.block(file.sub(end, 24)).await?;
    let mut f = Fields::emitting(&cx, &tail, LE);
    f.u64("Block size (repeated)")
        .check(|&v| (v != declared).then(|| Diagnostic::malformed("differs from the leading size")))
        .emit()?;
    f.ascii("Magic", 16).emit()?;
    let schemes = if names.is_empty() {
        "no blocks".to_owned()
    } else {
        names.join(", ")
    };
    cx.annotate(format!("APK Signing Block, {}: {schemes}", size(file.len)));
    Ok(())
}

async fn size_or_signers(cx: &Cx, pair: Span, id: u32) -> String {
    if matches!(id, V2 | V3 | V31)
        && let Ok(h) = cx.read(pair.sub(12, 4)).await
        && let Some(n) = u32_le(&h, 0)
    {
        // Count signers without reading them: walk the length prefixes.
        let signers = pair.sub(16, n.into());
        let mut count = 0u64;
        let mut at = 0u64;
        while at.saturating_add(4) <= signers.len && count < 64 {
            let Ok(b) = cx.read(signers.sub(at, 4)).await else {
                break;
            };
            let Some(len) = u32_le(&b, 0) else { break };
            at = at.saturating_add(4).saturating_add(len.into());
            count = count.saturating_add(1);
        }
        return plural(count, "signer");
    }
    size(pair.len.saturating_sub(12))
}

async fn pair_node(cx: Cx, (input, pair, id): (Input, Span, u32)) -> Result<()> {
    let block = cx.block(pair.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u64("Length").emit()?;
    f.u32("ID").hex().enumeration(BLOCK_IDS).emit()?;
    let value = pair.tail(12);
    match id {
        V2 | V3 | V31 => {
            let block = cx.block(value).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            let signers = lp(&mut f, "Signers length")?;
            cx.emit(seq_node(
                "Signers",
                input,
                signers,
                Kind::Signer { v3: id != V2 },
            ));
        }
        STAMP_V2 => {
            let block = cx.block(value).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            let signer = lp(&mut f, "Signer length")?;
            cx.emit(struct_node(
                "Source stamp signer",
                input,
                signer,
                Kind::Stamp,
            ));
        }
        VERITY_PADDING => cx.emit(
            data_node("Padding", value, value.len)
                .desc("Zeros that align the central directory to 4 KiB for fs-verity"),
        ),
        _ => cx.emit(data_node("Value", value, value.len)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// v4 signature files

fn idsig_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let ok = || -> Option<bool> {
        let version = u32_le(d, 0)?;
        let hashing = u32_le(d, 4)?;
        let salt = u32_le(d, 13)?;
        let root_at = 17usize.checked_add(to_usize(salt.into()))?;
        let root = u32_le(d, root_at)?;
        Some(
            (2..=3).contains(&version)
                && u32_le(d, 8)? == 1
                && *d.get(12)? == 12
                && salt <= 32
                && root == 32
                && u64::from(hashing) == to_u64(root_at).checked_add(36)?.checked_sub(8)?,
        )
    };
    ok().unwrap_or(false)
}

async fn idsig(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let version = f.u32("Version").emit()?;
    let hashing_len = f.u32("Hashing info length").emit()?;
    let hashing = file.sub_exact(8, hashing_len.into())?;
    cx.emit(struct_node(
        "Hashing info",
        input,
        hashing,
        Kind::HashingInfo,
    ));
    let at = hashing
        .offset
        .saturating_sub(file.offset)
        .saturating_add(hashing.len);
    let b = cx.block(file.sub(at, 4)).await?;
    let mut f = Fields::emitting(&cx, &b, LE);
    let signing_len = f.u32("Signing info length").emit()?;
    let signing = file.sub_exact(at.saturating_add(4), signing_len.into())?;
    cx.emit(struct_node(
        "Signing info",
        input,
        signing,
        Kind::SigningInfos,
    ));
    let at = at.saturating_add(4).saturating_add(signing.len);
    let mut tree_len = 0;
    if at < file.len {
        let b = cx.block(file.sub(at, 4)).await?;
        let mut f = Fields::emitting(&cx, &b, LE);
        tree_len = f.u32("Merkle tree size").emit()?;
        let tree = file.sub(at.saturating_add(4), tree_len.into());
        cx.emit(
            data_node("Merkle tree", tree, tree_len.into()).desc(
                "SHA-256 hashes of the APK's 4 KiB blocks, level by level (root level first)",
            ),
        );
        let end = tree
            .offset
            .saturating_sub(file.offset)
            .saturating_add(tree.len);
        if end < file.len {
            let rest = file.tail(end);
            cx.emit(data_node("Trailing data", rest, rest.len));
        }
    }
    cx.annotate(format!(
        "APK Signature Scheme v4 signature v{version}, Merkle tree {}",
        size(tree_len.into())
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Lineage files (`apksigner rotate --out`)

async fn lineage_file(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Magic").hex().emit()?;
    f.u32("Version").emit()?;
    let len = f.u32("Lineage length").emit()?;
    let lineage = file.sub(12, len.into());
    cx.emit(struct_node("Lineage", input, lineage, Kind::Lineage));
    let end = 12u64.saturating_add(lineage.len);
    if end < file.len {
        let rest = file.tail(end);
        cx.emit(data_node("Trailing data", rest, rest.len));
    }
    // Count the certificates for the summary.
    let data = cx.read(lineage).await?;
    let mut r = Rd::new(&data);
    r.u32();
    let mut n = 0u64;
    let mut last = None;
    while let Some(node) = r.lp() {
        n = n.saturating_add(1);
        last = Rd::new(node)
            .lp()
            .and_then(|s| Rd::new(s).lp())
            .and_then(subject);
        if n.is_multiple_of(256) {
            cx.checkpoint().await;
        }
    }
    let mut s = format!(
        "APK signing certificate lineage, {}",
        plural(n, "certificate")
    );
    if let Some(last) = last {
        s = format!("{s}, current {last}");
    }
    cx.annotate(s);
    Ok(())
}
