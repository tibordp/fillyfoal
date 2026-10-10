//! Apple code signatures: the embedded-signature SuperBlob referenced by
//! `LC_CODE_SIGNATURE` (always big-endian), with its CodeDirectory (fields
//! by version, special and code slot hashes), requirements (decoded into
//! expression trees), entitlements (XML and DER, dissected as property list
//! and DER) and CMS signature (dissected as PKCS#7).

use std::sync::Arc;

use super::tables::grouped_count;

use crate::bytes::{to_u64, to_usize, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::Tree;
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, name_or, text, uint};
use crate::formats::{Input, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::text::hex_lower;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const BE: Endian = Endian::Big;

pub const CSMAGIC_REQUIREMENT: u32 = 0xfade_0c00;
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade_0c01;
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade_0cc1;
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade_7172;
pub const CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT: u32 = 0xfade_8181;

const MAGIC: EnumTable = &[
    (0xfade_0c00, "CSMAGIC_REQUIREMENT"),
    (0xfade_0c01, "CSMAGIC_REQUIREMENTS"),
    (0xfade_0c02, "CSMAGIC_CODEDIRECTORY"),
    (0xfade_0cc0, "CSMAGIC_EMBEDDED_SIGNATURE"),
    (0xfade_0cc1, "CSMAGIC_DETACHED_SIGNATURE"),
    (0xfade_0b01, "CSMAGIC_BLOBWRAPPER"),
    (0xfade_7171, "CSMAGIC_EMBEDDED_ENTITLEMENTS"),
    (0xfade_7172, "CSMAGIC_EMBEDDED_DER_ENTITLEMENTS"),
    (0xfade_8181, "CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT"),
];

const SLOT: EnumTable = &[
    (0, "CodeDirectory"),
    (1, "Info.plist"),
    (2, "Requirements"),
    (3, "Resource Directory"),
    (4, "Application"),
    (5, "Entitlements"),
    (6, "Rep Specific"),
    (7, "DER Entitlements"),
    (8, "Launch Constraint (self)"),
    (9, "Launch Constraint (parent)"),
    (10, "Launch Constraint (responsible)"),
    (11, "Library Constraint"),
    (0x1000, "Alternate CodeDirectory 0"),
    (0x1001, "Alternate CodeDirectory 1"),
    (0x1002, "Alternate CodeDirectory 2"),
    (0x1003, "Alternate CodeDirectory 3"),
    (0x1004, "Alternate CodeDirectory 4"),
    (0x10000, "CMS Signature"),
    (0x10001, "Identification"),
    (0x10002, "Ticket"),
];

const REQUIREMENT_TYPE: EnumTable = &[
    (1, "Host"),
    (2, "Guest"),
    (3, "Designated"),
    (4, "Library"),
    (5, "Plugin"),
];

const REQUIREMENT_KIND: EnumTable = &[(1, "expression"), (2, "launch constraint (DER)")];

const HASH_TYPE: EnumTable = &[
    (0, "none"),
    (1, "SHA-1"),
    (2, "SHA-256"),
    (3, "SHA-256 (truncated)"),
    (4, "SHA-384"),
    (5, "SHA-512"),
];

const CD_FLAGS: FlagTable = &[
    flag(0x1, "HOST"),
    flag(0x2, "ADHOC"),
    flag(0x4, "GET_TASK_ALLOW"),
    flag(0x8, "INSTALLER"),
    flag(0x10, "FORCED_LV"),
    flag(0x20, "INVALID_ALLOWED"),
    flag(0x100, "HARD"),
    flag(0x200, "KILL"),
    flag(0x400, "CHECK_EXPIRATION"),
    flag(0x800, "RESTRICT"),
    flag(0x1000, "ENFORCEMENT"),
    flag(0x2000, "REQUIRE_LV"),
    flag(0x4000, "ENTITLEMENTS_VALIDATED"),
    flag(0x8000, "NVRAM_UNRESTRICTED"),
    flag(0x1_0000, "RUNTIME"),
    flag(0x2_0000, "LINKER_SIGNED"),
];

const EXEC_SEG_FLAGS: FlagTable = &[
    flag(0x1, "MAIN_BINARY"),
    flag(0x10, "ALLOW_UNSIGNED"),
    flag(0x20, "DEBUGGER"),
    flag(0x40, "JIT"),
    flag(0x80, "SKIP_LV"),
    flag(0x100, "CAN_LOAD_CDHASH"),
    flag(0x200, "CAN_EXEC_CDHASH"),
];

const SPECIAL_SLOTS: &[&str] = &[
    "Info.plist",
    "Requirements",
    "Resource Directory",
    "Application",
    "Entitlements",
    "Rep Specific",
    "DER Entitlements",
    "Launch Constraint (self)",
    "Launch Constraint (parent)",
    "Launch Constraint (responsible)",
    "Library Constraint",
];

/// Longest identifier or team ID we read.
const MAX_STRING: u64 = 1024;
/// Most index entries in a SuperBlob we look at.
const MAX_BLOBS: u32 = 64;
/// Largest requirement blob decoded.
const MAX_REQUIREMENT: u64 = 0x1_0000;

/// The blobs listed in a SuperBlob's index: `(slot type, span)`.
async fn index(cx: &Cx, span: Span) -> Result<Vec<(u32, Span)>> {
    let head = cx.read(span.sub(0, 12)).await?;
    let count = u32_be(&head, 8).unwrap_or(0).min(MAX_BLOBS);
    let table = cx
        .read(span.sub_exact(12, u64::from(count).saturating_mul(8))?)
        .await?;
    let mut out = Vec::new();
    for i in 0..count {
        let at = to_usize(u64::from(i).saturating_mul(8));
        let kind = u32_be(&table, at).unwrap_or(0);
        let offset = u32_be(&table, at.saturating_add(4)).unwrap_or(0);
        let len_bytes = cx.read_avail(span.sub(offset.into(), 8)).await?;
        let len = u32_be(&len_bytes, 4).unwrap_or(0);
        out.push((kind, span.sub(offset.into(), len.into())));
    }
    Ok(out)
}

/// What the CodeDirectory says about the signer.
#[derive(Default)]
struct Signer {
    identifier: Option<String>,
    team: Option<String>,
    flags: u32,
    hash: u8,
    version: u32,
}

async fn signer(cx: &Cx, span: Span) -> Result<Signer> {
    let head = cx.read(span.sub(0, 4)).await?;
    if !matches!(
        u32_be(&head, 0),
        Some(CSMAGIC_EMBEDDED_SIGNATURE | CSMAGIC_DETACHED_SIGNATURE)
    ) {
        return Err(Diagnostic::malformed("not an embedded signature"));
    }
    let blobs = index(cx, span).await?;
    let mut s = Signer::default();
    if let Some((_, cd)) = blobs.iter().find(|(k, _)| *k == 0) {
        let data = cx.read_avail(cd.sub(0, 0x58)).await?;
        s.version = u32_be(&data, 8).unwrap_or(0);
        s.flags = u32_be(&data, 12).unwrap_or(0);
        let ident = u32_be(&data, 20).unwrap_or(0);
        s.hash = data.get(37).copied().unwrap_or(0);
        if let Ok((id, _)) = cx.cstr(cd.tail(ident.into()).sub(0, MAX_STRING)).await {
            s.identifier = Some(id);
        }
        let team = if s.version >= 0x20200 {
            u32_be(&data, 48).unwrap_or(0)
        } else {
            0
        };
        if team != 0
            && let Ok((t, _)) = cx.cstr(cd.tail(team.into()).sub(0, MAX_STRING)).await
        {
            s.team = Some(t);
        }
    }
    Ok(s)
}

/// A one-line description of a signature: the identifier, the team (or
/// "ad-hoc"), whether it is linker-signed and the hash.
pub async fn summary(cx: &Cx, span: Span) -> Result<String> {
    let s = signer(cx, span).await?;
    let mut parts = Vec::new();
    parts.extend(s.identifier);
    if let Some(t) = s.team {
        parts.push(format!("team {t}"));
    }
    if s.flags & 0x2 != 0 {
        parts.push("ad-hoc".to_owned());
    }
    if s.flags & 0x2_0000 != 0 {
        parts.push("linker-signed".to_owned());
    }
    if s.version != 0 {
        parts.push(name_or(HASH_TYPE, s.hash.into(), "hash"));
    }
    Ok(parts.join(", "))
}

/// The kind of signature, for a file summary: `ad-hoc`, `ad-hoc,
/// linker-signed`, `team ABCDE12345`.
pub async fn brief(cx: &Cx, span: Span) -> Result<String> {
    let s = signer(cx, span).await?;
    let mut parts = Vec::new();
    if let Some(t) = s.team {
        parts.push(format!("team {t}"));
    }
    if s.flags & 0x2 != 0 {
        parts.push("ad-hoc".to_owned());
    }
    if s.flags & 0x2_0000 != 0 {
        parts.push("linker-signed".to_owned());
    }
    if parts.is_empty() {
        parts.push("identity unknown".to_owned());
    }
    Ok(parts.join(", "))
}

/// Expander for a SuperBlob (embedded signature or requirement set) that is
/// a file of its own.
pub async fn superblob(cx: Cx, span: Span) -> Result<()> {
    superblob_in(cx, Input::root(span)).await
}

/// Expander for a SuperBlob embedded in `input`'s parent.
pub async fn superblob_in(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let head = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let magic = f.u32("magic").enumeration(MAGIC).emit()?;
    let length = f.u32("length").hex().emit()?;
    let count = f.u32("count").emit()?;
    let requirements = magic == CSMAGIC_REQUIREMENTS;
    let blobs = index(&cx, span).await?;
    if count > MAX_BLOBS {
        cx.diag(Diagnostic::limit(format!(
            "only the first {MAX_BLOBS} of {count} blobs are shown"
        )));
    }
    let label = |kind: u32| {
        if requirements {
            name_or(REQUIREMENT_TYPE, kind.into(), "requirement type")
        } else {
            lookup(SLOT, kind.into()).map_or_else(|| format!("Slot {kind:#x}"), str::to_owned)
        }
    };
    let table = span.sub(12, to_u64(blobs.len()).saturating_mul(8));
    let mut entries = Vec::new();
    for (i, (kind, blob)) in blobs.iter().enumerate() {
        let at = table.sub(to_u64(i).saturating_mul(8), 8);
        let offset = blob.offset.saturating_sub(span.offset);
        entries.push(
            Node::new(label(*kind))
                .span(at)
                .value(hex(offset, 32))
                .summary(format!("type {kind:#x}"))
                .target(*blob),
        );
    }
    cx.emit(
        super::group("Index", table, entries)
            .summary(grouped_count(count, "blob", "blobs"))
            .desc("Blob types and their offsets"),
    );
    let mut end = table.end().saturating_sub(span.offset);
    for (kind, blob) in blobs {
        let node = blob_node(&cx, label(kind), blob, input).await;
        cx.emit(node);
        end = end.max(blob.end().saturating_sub(span.offset));
    }
    // An embedded signature's space is usually larger than the SuperBlob.
    let used = u64::from(length).max(end);
    if used < span.len {
        let rest = span.tail(used);
        let data = cx.read_avail(rest.sub(0, 0x1_0000)).await?;
        let zeros = data.iter().all(|&b| b == 0);
        cx.emit(
            Node::new(if zeros { "Padding" } else { "Trailing Data" })
                .span(rest)
                .summary(size(rest.len))
                .desc("Space reserved for the signature beyond the SuperBlob"),
        );
    }
    Ok(())
}

async fn blob_node(cx: &Cx, label: String, blob: Span, input: Input) -> Node {
    let head = cx.read_avail(blob.sub(0, 12)).await.unwrap_or_default();
    let magic = u32_be(&head, 0).unwrap_or(0);
    let node = Node::new(label).span(blob);
    let inner = input.nested(blob);
    match magic {
        CSMAGIC_CODEDIRECTORY => {
            let summary = cd_summary(cx, blob).await.unwrap_or_default();
            node.summary(summary).lazy(code_directory, blob)
        }
        CSMAGIC_REQUIREMENTS => node
            .summary(grouped_count(
                u32_be(&head, 8).unwrap_or(0),
                "requirement",
                "requirements",
            ))
            .lazy(crate::expander!(self::superblob_in: Input), inner),
        CSMAGIC_REQUIREMENT => {
            let summary = match requirement_tree(cx, blob).await {
                Ok((_, text)) => text,
                Err(_) => "requirement".to_owned(),
            };
            node.summary(summary).lazy(requirement, blob)
        }
        CSMAGIC_EMBEDDED_ENTITLEMENTS => node
            .summary(format!(
                "XML property list, {}",
                size(blob.len.saturating_sub(8))
            ))
            .lazy(wrapper, (blob, input)),
        CSMAGIC_EMBEDDED_DER_ENTITLEMENTS | CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT => node
            .summary(format!("DER, {}", size(blob.len.saturating_sub(8))))
            .lazy(wrapper, (blob, input)),
        CSMAGIC_BLOBWRAPPER => {
            let summary = if blob.len <= 8 {
                "empty (ad-hoc signature)".to_owned()
            } else {
                format!("CMS SignedData, {}", size(blob.len.saturating_sub(8)))
            };
            node.summary(summary).lazy(wrapper, (blob, input))
        }
        _ => node
            .summary(name_or(MAGIC, magic.into(), "magic"))
            .lazy(wrapper, (blob, input)),
    }
}

/// A blob with a magic, a length and a payload, the payload dissected by
/// what the magic says it is.
async fn wrapper(cx: Cx, (blob, input): (Span, Input)) -> Result<()> {
    let head = cx.block(blob.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let magic = f.u32("magic").enumeration(MAGIC).emit()?;
    f.u32("length").hex().emit()?;
    let payload = blob.tail(8);
    if payload.len == 0 {
        return Ok(());
    }
    let inner = input.nested(payload);
    cx.emit(match magic {
        CSMAGIC_BLOBWRAPPER => embedded_as("CMS Signature", inner, &crate::formats::asn1::PKCS7),
        CSMAGIC_EMBEDDED_ENTITLEMENTS => {
            embedded_as("Entitlements", inner, &crate::formats::text::plist::FORMAT)
        }
        CSMAGIC_EMBEDDED_DER_ENTITLEMENTS => {
            embedded_as("DER Entitlements", inner, &crate::formats::asn1::DER)
        }
        CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT => {
            embedded_as("Launch Constraint", inner, &crate::formats::asn1::DER)
        }
        _ => Node::new("Data").span(payload).summary(size(payload.len)),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// CodeDirectory

#[derive(Clone, Copy, Debug)]
struct CodeDirectory {
    hash_offset: u32,
    ident_offset: u32,
    special_slots: u32,
    code_slots: u32,
    code_limit: u32,
    hash_size: u8,
    page_size: u8,
    team_offset: u32,
}

async fn cd_summary(cx: &Cx, blob: Span) -> Result<String> {
    let data = cx.read_avail(blob.sub(0, 0x40)).await?;
    let version = u32_be(&data, 8).unwrap_or(0);
    let flags = u32_be(&data, 12).unwrap_or(0);
    let special = u32_be(&data, 24).unwrap_or(0);
    let code = u32_be(&data, 28).unwrap_or(0);
    let hash = data.get(37).copied().unwrap_or(0);
    let mut s = format!(
        "v{:x}, {}, {}+{} hashes",
        version,
        name_or(HASH_TYPE, hash.into(), "hash"),
        special,
        code
    );
    let (set, _) = crate::value::decode_flags(CD_FLAGS, flags.into());
    if !set.is_empty() {
        s.push_str(&format!(", {}", set.join(" | ").to_ascii_lowercase()));
    }
    Ok(s)
}

fn code_directory_layout(f: &mut Fields<'_>, _: &()) -> Result<CodeDirectory> {
    f.u32("magic").enumeration(MAGIC).emit()?;
    f.u32("length").hex().emit()?;
    let version = f
        .u32("version")
        .hex()
        .with(|&v, n| n.summary(format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)))
        .desc("Fields after spare2 depend on it")
        .emit()?;
    f.u32("flags").flags(CD_FLAGS).emit()?;
    let hash_offset = f
        .u32("hashOffset")
        .hex()
        .desc("Offset of code slot 0 (special slots precede it)")
        .emit()?;
    let ident_offset = f.u32("identOffset").hex().emit()?;
    let special_slots = f.u32("nSpecialSlots").emit()?;
    let code_slots = f.u32("nCodeSlots").emit()?;
    let code_limit = f
        .u32("codeLimit")
        .hex()
        .desc("Bytes of the file covered by code slots")
        .emit()?;
    let hash_size = f.u8("hashSize").emit()?;
    f.u8("hashType").enumeration(HASH_TYPE).emit()?;
    f.u8("platform")
        .desc("Platform identifier (0: not a platform binary)")
        .emit()?;
    let page_size = f
        .u8("pageSize")
        .with(|&v, n| {
            if v == 0 {
                n.summary("one page covers everything")
            } else {
                n.summary(format!("2^{v} = {:#x} bytes", 1u64 << v.min(63)))
            }
        })
        .emit()?;
    f.u32("spare2").emit()?;
    let mut team_offset = 0;
    if version >= 0x20100 {
        f.u32("scatterOffset").hex().emit()?;
    }
    if version >= 0x20200 {
        team_offset = f.u32("teamOffset").hex().emit()?;
    }
    if version >= 0x20300 {
        f.u32("spare3").emit()?;
        f.u64("codeLimit64").hex().emit()?;
    }
    if version >= 0x20400 {
        f.u64("execSegBase")
            .hex()
            .desc("File offset of the executable segment")
            .emit()?;
        f.u64("execSegLimit").hex().emit()?;
        f.u64("execSegFlags").flags(EXEC_SEG_FLAGS).emit()?;
    }
    if version >= 0x20500 {
        f.u32("runtime")
            .hex()
            .with(|&v, n| n.summary(super::tables::version(v)))
            .emit()?;
        f.u32("preEncryptOffset").hex().emit()?;
    }
    if version >= 0x20600 {
        f.u8("linkageHashType").enumeration(HASH_TYPE).emit()?;
        f.u8("linkageApplicationType").emit()?;
        f.u16("linkageApplicationSubType").emit()?;
        f.u32("linkageOffset").hex().emit()?;
        f.u32("linkageSize").hex().emit()?;
    }
    Ok(CodeDirectory {
        hash_offset,
        ident_offset,
        special_slots,
        code_slots,
        code_limit,
        hash_size,
        page_size,
        team_offset,
    })
}

async fn code_directory(cx: Cx, blob: Span) -> Result<()> {
    let block = cx.block(blob.sub(0, 0x80)).await?;
    let cd = code_directory_layout(&mut Fields::emitting(&cx, &block, BE), &())?;
    for (name, offset) in [("Identifier", cd.ident_offset), ("Team ID", cd.team_offset)] {
        if offset == 0 {
            continue;
        }
        match cx.cstr(blob.tail(offset.into()).sub(0, MAX_STRING)).await {
            Ok((s, at)) => cx.emit(Node::new(name).span(at).value(text(s))),
            Err(e) => cx.emit(Node::new(name).diag(e)),
        }
    }
    let size = u64::from(cd.hash_size);
    let special = u64::from(cd.special_slots).saturating_mul(size);
    let start = u64::from(cd.hash_offset).saturating_sub(special);
    if cd.special_slots > 0 {
        let span = blob.sub(start, special);
        cx.emit(
            Node::new("Special Slots")
                .span(span)
                .summary(format!("{} hashes", cd.special_slots))
                .desc("Hashes of the other blobs and of files outside the binary, slot -1 last")
                .lazy(special_slots, (span, cd.special_slots, cd.hash_size)),
        );
    }
    let span = blob.sub(
        cd.hash_offset.into(),
        u64::from(cd.code_slots).saturating_mul(size),
    );
    cx.emit(
        Node::new("Code Slots")
            .span(span)
            .summary(format!(
                "{} hashes covering {:#x} bytes",
                cd.code_slots, cd.code_limit
            ))
            .lazy(code_slots, (span, cd)),
    );
    Ok(())
}

async fn special_slots(cx: Cx, (span, count, size): (Span, u32, u8)) -> Result<()> {
    let size = u64::from(size);
    let count = count.min(u32::try_from(span.len.checked_div(size).unwrap_or(0)).unwrap_or(0));
    // Stored in reverse: slot -count first, slot -1 last.
    for i in 0..count {
        let at = span.sub(u64::from(i).saturating_mul(size), size);
        let hash = cx.read(at).await?;
        let slot = count.saturating_sub(i);
        let label = SPECIAL_SLOTS
            .get(to_usize(slot.into()).saturating_sub(1))
            .map_or_else(|| format!("Slot -{slot}"), |s| format!("-{slot} {s}"));
        let empty = hash.iter().all(|&b| b == 0);
        let mut node = Node::new(label).span(at).value(text(hex_lower(&hash)));
        if empty {
            node = node.summary("not present");
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn code_slots(cx: Cx, (span, cd): (Span, CodeDirectory)) -> Result<()> {
    let size = u64::from(cd.hash_size);
    let page = if cd.page_size == 0 || cd.page_size >= 64 {
        u64::from(cd.code_limit)
    } else {
        1u64 << cd.page_size
    };
    let count = u64::from(cd.code_slots).min(span.len.checked_div(size).unwrap_or(0));
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(size), size);
        let hash = cx.read(at).await?;
        let start = i.saturating_mul(page);
        let end = start.saturating_add(page).min(cd.code_limit.into());
        cx.push(
            Node::new(format!("Page {i}"))
                .span(at)
                .value(text(hex_lower(&hash)))
                .summary(format!("file {start:#x}..{end:#x}")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Requirements

const EXPR_OP: EnumTable = &[
    (0, "opFalse"),
    (1, "opTrue"),
    (2, "opIdent"),
    (3, "opAppleAnchor"),
    (4, "opAnchorHash"),
    (5, "opInfoKeyValue"),
    (6, "opAnd"),
    (7, "opOr"),
    (8, "opCDHash"),
    (9, "opNot"),
    (10, "opInfoKeyField"),
    (11, "opCertField"),
    (12, "opTrustedCert"),
    (13, "opTrustedCerts"),
    (14, "opCertGeneric"),
    (15, "opAppleGenericAnchor"),
    (16, "opEntitlementField"),
    (17, "opCertPolicy"),
    (18, "opNamedAnchor"),
    (19, "opNamedCode"),
    (20, "opPlatform"),
    (21, "opNotarized"),
    (22, "opCertFieldDate"),
    (23, "opLegacyDevID"),
];

const MATCH_OP: EnumTable = &[
    (0, "matchExists"),
    (1, "matchEqual"),
    (2, "matchContains"),
    (3, "matchBeginsWith"),
    (4, "matchEndsWith"),
    (5, "matchLessThan"),
    (6, "matchGreaterThan"),
    (7, "matchLessEqual"),
    (8, "matchGreaterEqual"),
    (9, "matchOn"),
    (10, "matchBefore"),
    (11, "matchAfter"),
    (12, "matchOnOrBefore"),
    (13, "matchOnOrAfter"),
    (14, "matchAbsent"),
];

/// Deepest expression nesting decoded.
const MAX_DEPTH: u32 = 64;
/// Seconds between the Unix epoch and the Core Foundation epoch (2001).
const CF_EPOCH: i64 = 978_307_200;

/// A decoder for the binary requirement language (Security framework
/// `Requirement::Reader`), building a tree of operator nodes.
struct ReqParser<'a> {
    data: &'a [u8],
    pos: usize,
    span: Span,
    tree: Tree,
}

impl<'a> ReqParser<'a> {
    fn at(&self, start: usize) -> Span {
        self.span
            .sub(to_u64(start), to_u64(self.pos.saturating_sub(start)))
    }

    fn bad(&self) -> Diagnostic {
        Diagnostic::malformed("truncated requirement expression").at(self.at(self.pos))
    }

    fn u32(&mut self) -> Result<u32> {
        let v = u32_be(self.data, self.pos).ok_or_else(|| self.bad())?;
        self.pos = self.pos.saturating_add(4);
        Ok(v)
    }

    /// A length-prefixed byte string, padded to 4 bytes.
    fn bytes(&mut self) -> Result<(&'a [u8], Span)> {
        let start = self.pos;
        let len = to_usize(self.u32()?.into());
        let end = self.pos.checked_add(len).ok_or_else(|| self.bad())?;
        let b = self.data.get(self.pos..end).ok_or_else(|| self.bad())?;
        self.pos = end.saturating_add(3) & !3;
        Ok((b, self.at(start)))
    }

    fn string(&mut self, parent: usize, name: &'static str) -> Result<String> {
        let (b, span) = self.bytes()?;
        let s = String::from_utf8_lossy(b).into_owned();
        self.tree.add(
            Some(parent),
            Node::new(name).span(span).value(text(s.clone())),
        );
        Ok(s)
    }

    fn hash(&mut self, parent: usize, name: &'static str) -> Result<String> {
        let (b, span) = self.bytes()?;
        let s = hex_lower(b);
        self.tree.add(
            Some(parent),
            Node::new(name).span(span).value(text(s.clone())),
        );
        Ok(s)
    }

    fn slot(&mut self, parent: usize) -> Result<String> {
        let start = self.pos;
        let v = i32::from_be_bytes(self.u32()?.to_be_bytes());
        let s = match v {
            0 => "leaf".to_owned(),
            -1 => "root".to_owned(),
            n => n.to_string(),
        };
        self.tree.add(
            Some(parent),
            Node::new("slot")
                .span(self.at(start))
                .value(Value::Int {
                    value: v.into(),
                    bits: 32,
                })
                .summary(format!("certificate {s}")),
        );
        Ok(s)
    }

    /// A match suffix: `= "value"`, `exists`, ...
    fn matching(&mut self, parent: usize) -> Result<String> {
        let start = self.pos;
        let op = self.u32()?;
        self.tree.add(
            Some(parent),
            Node::new("match").span(self.at(start)).value(Value::Enum {
                raw: op.into(),
                bits: 32,
                name: lookup(MATCH_OP, op.into()),
            }),
        );
        Ok(match op {
            0 => "/* exists */".to_owned(),
            14 => "absent".to_owned(),
            1..=8 => {
                let v = self.string(parent, "value")?;
                match op {
                    1 => format!("= \"{v}\""),
                    2 => format!("~ \"{v}\""),
                    3 => format!("= \"{v}*\""),
                    4 => format!("= \"*{v}\""),
                    5 => format!("< \"{v}\""),
                    6 => format!("> \"{v}\""),
                    7 => format!("<= \"{v}\""),
                    _ => format!(">= \"{v}\""),
                }
            }
            9..=13 => {
                let start = self.pos;
                let hi = self.u32()?;
                let lo = self.u32()?;
                let t = i64::from_be_bytes((u64::from(hi) << 32 | u64::from(lo)).to_be_bytes());
                self.tree.add(
                    Some(parent),
                    Node::new("timestamp")
                        .span(self.at(start))
                        .value(Value::Timestamp {
                            unix_seconds: t.saturating_add(CF_EPOCH),
                        }),
                );
                let rel = match op {
                    9 => "=",
                    10 => "<",
                    11 => ">",
                    12 => "<=",
                    _ => ">=",
                };
                format!("{rel} timestamp {t}")
            }
            _ => return Err(Diagnostic::unsupported(format!("match operation {op}"))),
        })
    }

    /// One expression; returns its text and whether it is an `or`.
    fn expr(&mut self, parent: Option<usize>, depth: u32) -> Result<(String, bool)> {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit(
                "requirement expression nested too deeply",
            ));
        }
        let start = self.pos;
        let raw = self.u32()?;
        let op = raw & 0x00ff_ffff;
        let index = self.tree.add(
            parent,
            Node::new(lookup(EXPR_OP, op.into()).unwrap_or("op?")),
        );
        self.tree.add(
            Some(index),
            Node::new("op").span(self.at(start)).value(Value::Enum {
                raw: raw.into(),
                bits: 32,
                name: lookup(EXPR_OP, op.into()),
            }),
        );
        let mut or = false;
        let text = match op {
            0 => "never".to_owned(),
            1 => "always".to_owned(),
            2 => format!("identifier \"{}\"", self.string(index, "identifier")?),
            3 => "anchor apple".to_owned(),
            4 => {
                let slot = self.slot(index)?;
                format!("certificate {slot} = H\"{}\"", self.hash(index, "hash")?)
            }
            5 => {
                let key = self.string(index, "key")?;
                format!("info[{key}] = \"{}\"", self.string(index, "value")?)
            }
            6 | 7 => {
                let (a, a_or) = self.expr(Some(index), depth.saturating_add(1))?;
                let (b, b_or) = self.expr(Some(index), depth.saturating_add(1))?;
                if op == 6 {
                    let wrap = |s: String, or: bool| if or { format!("({s})") } else { s };
                    format!("{} and {}", wrap(a, a_or), wrap(b, b_or))
                } else {
                    or = true;
                    format!("{a} or {b}")
                }
            }
            8 => format!("cdhash H\"{}\"", self.hash(index, "hash")?),
            9 => {
                let (a, a_or) = self.expr(Some(index), depth.saturating_add(1))?;
                if a_or {
                    format!("! ({a})")
                } else {
                    format!("! {a}")
                }
            }
            10 => {
                let key = self.string(index, "key")?;
                format!("info[{key}] {}", self.matching(index)?)
            }
            11 | 22 => {
                let slot = self.slot(index)?;
                let field = self.string(index, "field")?;
                let field = if op == 22 {
                    format!("timestamp.{field}")
                } else {
                    field
                };
                format!("certificate {slot}[{field}] {}", self.matching(index)?)
            }
            12 => format!("certificate {} trusted", self.slot(index)?),
            13 => "anchor trusted".to_owned(),
            14 | 17 => {
                let slot = self.slot(index)?;
                let oid = self.hash(index, "oid")?;
                let kind = if op == 14 { "field" } else { "policy" };
                format!("certificate {slot}[{kind}.{oid}] {}", self.matching(index)?)
            }
            15 => "anchor apple generic".to_owned(),
            16 => {
                let key = self.string(index, "key")?;
                format!("entitlement[\"{key}\"] {}", self.matching(index)?)
            }
            18 => format!("anchor apple {}", self.string(index, "name")?),
            19 => format!("({})", self.string(index, "name")?),
            20 => {
                let start = self.pos;
                let platform = self.u32()?;
                self.tree.add(
                    Some(index),
                    Node::new("platform")
                        .span(self.at(start))
                        .value(uint(platform, 32)),
                );
                format!("platform = {platform}")
            }
            21 => "notarized".to_owned(),
            23 => "legacy".to_owned(),
            _ if raw & 0x4000_0000 != 0 => {
                // opGenericSkip: an unknown operator with one data operand.
                self.hash(index, "data")?;
                format!("/* unknown operator {op:#x} */")
            }
            _ => {
                return Err(
                    Diagnostic::unsupported(format!("requirement operator {raw:#x}"))
                        .at(self.at(start)),
                );
            }
        };
        let span = self.at(start);
        let summary = text.clone();
        self.tree.update(index, |n| n.span(span).summary(summary));
        Ok((text, or))
    }
}

/// Decodes a requirement blob's expression into a tree (root index 0) and
/// its text in the requirement language.
async fn requirement_tree(cx: &Cx, blob: Span) -> Result<(Tree, String)> {
    if blob.len > MAX_REQUIREMENT {
        return Err(Diagnostic::limit("requirement is too large").at(blob));
    }
    let data = cx.read_avail(blob).await?;
    let kind = u32_be(&data, 8).unwrap_or(0);
    if kind != 1 {
        return Err(Diagnostic::unsupported(format!("requirement kind {kind}")));
    }
    let mut p = ReqParser {
        data: &data,
        pos: 12,
        span: blob,
        tree: Tree::default(),
    };
    let (text, _) = p.expr(None, 0)?;
    Ok((p.tree, text))
}

async fn requirement(cx: Cx, blob: Span) -> Result<()> {
    let head = cx.block(blob.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("magic").enumeration(MAGIC).emit()?;
    f.u32("length").hex().emit()?;
    let kind = f.u32("kind").enumeration(REQUIREMENT_KIND).emit()?;
    if kind == 2 {
        cx.emit(embedded_as(
            "Launch Constraint",
            Input::root(blob.tail(12)),
            &crate::formats::asn1::DER,
        ));
        return Ok(());
    }
    let (tree, _) = requirement_tree(&cx, blob).await?;
    let tree = Arc::new(tree);
    cx.emit(
        Tree::node(&tree, 0)
            .desc("The requirement as an operator tree; the summary is its source text"),
    );
    Ok(())
}
