//! Apple code signatures: the embedded-signature SuperBlob referenced by
//! `LC_CODE_SIGNATURE` (always big-endian), with its CodeDirectory,
//! requirements, entitlements and CMS signature.

use crate::bytes::{to_u64, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::{data_node, hex_string, name_or, text};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const BE: Endian = Endian::Big;

pub const CSMAGIC_REQUIREMENT: u32 = 0xfade_0c00;
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade_0c01;
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade_0cc1;
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade_7172;

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

/// The blobs listed in a SuperBlob's index: `(slot type, span)`.
async fn index(cx: &Cx, span: Span) -> Result<Vec<(u32, Span)>> {
    let head = cx.read(span.sub(0, 12)).await?;
    let count = u32_be(&head, 8).unwrap_or(0).min(MAX_BLOBS);
    let table = cx
        .read(span.sub_exact(12, u64::from(count).saturating_mul(8))?)
        .await?;
    let mut out = Vec::new();
    for i in 0..count {
        let at = crate::bytes::to_usize(u64::from(i).saturating_mul(8));
        let kind = u32_be(&table, at).unwrap_or(0);
        let offset = u32_be(&table, at.saturating_add(4)).unwrap_or(0);
        let len_bytes = cx.read_avail(span.sub(offset.into(), 8)).await?;
        let len = u32_be(&len_bytes, 4).unwrap_or(0);
        out.push((kind, span.sub(offset.into(), len.into())));
    }
    Ok(out)
}

/// A one-line description of a signature for the file summary: the
/// identifier, the team (or "ad-hoc"), and whether it is linker-signed.
pub async fn summary(cx: &Cx, span: Span) -> Result<String> {
    let head = cx.read(span.sub(0, 4)).await?;
    if u32_be(&head, 0) != Some(CSMAGIC_EMBEDDED_SIGNATURE) {
        return Err(Diagnostic::malformed("not an embedded signature"));
    }
    let blobs = index(cx, span).await?;
    let mut parts = Vec::new();
    if let Some((_, cd)) = blobs.iter().find(|(k, _)| *k == 0) {
        let data = cx.read_avail(cd.sub(0, 0x58)).await?;
        let version = u32_be(&data, 8).unwrap_or(0);
        let flags = u32_be(&data, 12).unwrap_or(0);
        let ident = u32_be(&data, 20).unwrap_or(0);
        let hash = data.get(37).copied().unwrap_or(0);
        if let Ok((id, _)) = cx.cstr(cd.tail(ident.into()).sub(0, MAX_STRING)).await {
            parts.push(id);
        }
        let team = if version >= 0x20200 {
            u32_be(&data, 48).unwrap_or(0)
        } else {
            0
        };
        if team != 0
            && let Ok((t, _)) = cx.cstr(cd.tail(team.into()).sub(0, MAX_STRING)).await
        {
            parts.push(format!("team {t}"));
        }
        if flags & 0x2 != 0 {
            parts.push("ad-hoc".to_owned());
        }
        if flags & 0x2_0000 != 0 {
            parts.push("linker-signed".to_owned());
        }
        parts.push(name_or(HASH_TYPE, hash.into(), "hash"));
    }
    Ok(parts.join(", "))
}

/// Expander for a SuperBlob (embedded signature or requirement set).
pub async fn superblob(cx: Cx, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let magic = f.u32("magic").enumeration(MAGIC).emit()?;
    f.u32("length").hex().emit()?;
    let count = f.u32("count").emit()?;
    let requirements = magic == CSMAGIC_REQUIREMENTS;
    let blobs = index(&cx, span).await?;
    if count > MAX_BLOBS {
        cx.diag(Diagnostic::limit(format!(
            "only the first {MAX_BLOBS} of {count} blobs are shown"
        )));
    }
    for (i, (kind, blob)) in blobs.into_iter().enumerate() {
        let entry = span.sub(12u64.saturating_add(to_u64(i).saturating_mul(8)), 8);
        let label = if requirements {
            name_or(REQUIREMENT_TYPE, kind.into(), "requirement type")
        } else {
            lookup(SLOT, kind.into()).map_or_else(|| format!("Slot {kind:#x}"), str::to_owned)
        };
        let node = blob_node(&cx, label, blob).await;
        cx.emit(node.target(entry));
    }
    Ok(())
}

async fn blob_node(cx: &Cx, label: String, blob: Span) -> Node {
    let head = cx.read_avail(blob.sub(0, 8)).await.unwrap_or_default();
    let magic = u32_be(&head, 0).unwrap_or(0);
    let node = Node::new(label).span(blob);
    match magic {
        CSMAGIC_CODEDIRECTORY => node.lazy(code_directory, blob),
        CSMAGIC_REQUIREMENTS => node.lazy(crate::expander!(self::superblob: Span), blob),
        CSMAGIC_EMBEDDED_ENTITLEMENTS => node.lazy(entitlements, blob),
        CSMAGIC_BLOBWRAPPER => {
            let summary = if blob.len <= 8 {
                "empty (ad-hoc signature)".to_owned()
            } else {
                format!("PKCS#7 SignedData, {:#x} bytes", blob.len.saturating_sub(8))
            };
            node.summary(summary).lazy(wrapper, blob)
        }
        CSMAGIC_REQUIREMENT => node.summary("requirement expression").lazy(wrapper, blob),
        _ => node
            .summary(name_or(MAGIC, magic.into(), "magic"))
            .lazy(wrapper, blob),
    }
}

/// Generic blob: magic, length and the payload.
async fn wrapper(cx: Cx, blob: Span) -> Result<()> {
    let head = cx.block(blob.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let magic = f.u32("magic").enumeration(MAGIC).emit()?;
    f.u32("length").hex().emit()?;
    let payload = blob.tail(8);
    if payload.len > 0 {
        let name = match magic {
            CSMAGIC_BLOBWRAPPER => "CMS Signature",
            CSMAGIC_REQUIREMENT => "Expression",
            CSMAGIC_EMBEDDED_DER_ENTITLEMENTS => "DER Entitlements",
            _ => "Data",
        };
        cx.emit(data_node(name, payload, payload.len));
    }
    Ok(())
}

async fn entitlements(cx: Cx, blob: Span) -> Result<()> {
    let head = cx.block(blob.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("magic").enumeration(MAGIC).emit()?;
    f.u32("length").hex().emit()?;
    let payload = blob.tail(8);
    let xml = cx.read_avail(payload.sub(0, 0x10_0000)).await?;
    cx.emit(
        Node::new("Entitlements")
            .span(payload)
            .value(text(String::from_utf8_lossy(&xml).into_owned()))
            .desc("XML property list"),
    );
    Ok(())
}

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

fn code_directory_layout(f: &mut Fields<'_>, _: &()) -> Result<CodeDirectory> {
    f.u32("magic").enumeration(MAGIC).emit()?;
    f.u32("length").hex().emit()?;
    let version = f
        .u32("version")
        .hex()
        .with(|&v, n| n.summary(format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)))
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
    f.u8("platform").emit()?;
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
        f.u64("execSegBase").hex().emit()?;
        f.u64("execSegLimit").hex().emit()?;
        f.u64("execSegFlags").flags(EXEC_SEG_FLAGS).emit()?;
    }
    if version >= 0x20500 {
        f.u32("runtime")
            .hex()
            .with(|&v, n| n.summary(crate::formats::macho::tables::version(v)))
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
            .get(crate::bytes::to_usize(slot.into()).saturating_sub(1))
            .map_or_else(|| format!("Slot -{slot}"), |s| format!("-{slot} {s}"));
        let empty = hash.iter().all(|&b| b == 0);
        let mut node = Node::new(label).span(at).value(text(hex_string(&hash)));
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
                .value(text(hex_string(&hash)))
                .summary(format!("file {start:#x}..{end:#x}")),
        )
        .await;
    }
    Ok(())
}
