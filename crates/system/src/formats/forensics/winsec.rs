//! Windows security identifiers (SIDs) and self-relative security
//! descriptors (`SECURITY_DESCRIPTOR_RELATIVE`, MS-DTYP 2.4.6) with their
//! ACLs and ACEs, as stored in registry hives (`sk` cells), event logs,
//! NTFS `$Secure`, minidump token streams and elsewhere.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::plural;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;

/// A binary SID: its `S-R-A-S1-S2...` form and its length in bytes.
pub fn parse_sid(b: &[u8]) -> Option<(String, usize)> {
    let revision = *b.first()?;
    let count = usize::from(*b.get(1)?);
    let authority = b.get(2..8)?;
    let authority = authority
        .iter()
        .fold(0u64, |acc, &x| acc.wrapping_shl(8) | u64::from(x));
    let len = count.checked_mul(4)?.checked_add(8)?;
    if b.len() < len {
        return None;
    }
    let mut out = if authority >= 1 << 32 {
        format!("S-{revision}-{authority:#x}")
    } else {
        format!("S-{revision}-{authority}")
    };
    for i in 0..count {
        let v = u32_le(b, i.checked_mul(4)?.checked_add(8)?)?;
        out.push_str(&format!("-{v}"));
    }
    Some((out, len))
}

/// The conventional name of a well-known SID, if it is one.
pub fn sid_name(sid: &str) -> Option<&'static str> {
    const WELL_KNOWN: &[(&str, &str)] = &[
        ("S-1-0-0", "Nobody"),
        ("S-1-1-0", "Everyone"),
        ("S-1-2-0", "LOCAL"),
        ("S-1-2-1", "CONSOLE LOGON"),
        ("S-1-3-0", "CREATOR OWNER"),
        ("S-1-3-1", "CREATOR GROUP"),
        ("S-1-3-4", "OWNER RIGHTS"),
        ("S-1-5-1", "DIALUP"),
        ("S-1-5-2", "NETWORK"),
        ("S-1-5-3", "BATCH"),
        ("S-1-5-4", "INTERACTIVE"),
        ("S-1-5-6", "SERVICE"),
        ("S-1-5-7", "ANONYMOUS LOGON"),
        ("S-1-5-9", "ENTERPRISE DOMAIN CONTROLLERS"),
        ("S-1-5-10", "SELF"),
        ("S-1-5-11", "Authenticated Users"),
        ("S-1-5-12", "RESTRICTED"),
        ("S-1-5-13", "TERMINAL SERVER USER"),
        ("S-1-5-14", "REMOTE INTERACTIVE LOGON"),
        ("S-1-5-15", "This Organization"),
        ("S-1-5-17", "IUSR"),
        ("S-1-5-18", "SYSTEM"),
        ("S-1-5-19", "LOCAL SERVICE"),
        ("S-1-5-20", "NETWORK SERVICE"),
        ("S-1-5-32-544", "Administrators"),
        ("S-1-5-32-545", "Users"),
        ("S-1-5-32-546", "Guests"),
        ("S-1-5-32-547", "Power Users"),
        ("S-1-5-32-548", "Account Operators"),
        ("S-1-5-32-549", "Server Operators"),
        ("S-1-5-32-550", "Print Operators"),
        ("S-1-5-32-551", "Backup Operators"),
        ("S-1-5-32-552", "Replicators"),
        ("S-1-5-32-555", "Remote Desktop Users"),
        ("S-1-5-32-556", "Network Configuration Operators"),
        ("S-1-5-32-558", "Performance Monitor Users"),
        ("S-1-5-32-559", "Performance Log Users"),
        ("S-1-5-32-562", "Distributed COM Users"),
        ("S-1-5-32-568", "IIS_IUSRS"),
        ("S-1-5-32-573", "Event Log Readers"),
        ("S-1-5-32-578", "Hyper-V Administrators"),
        ("S-1-5-32-580", "Remote Management Users"),
        ("S-1-5-64-10", "NTLM Authentication"),
        ("S-1-5-80-0", "ALL SERVICES"),
        ("S-1-5-113", "Local account"),
        (
            "S-1-5-114",
            "Local account and member of Administrators group",
        ),
        ("S-1-15-2-1", "ALL APPLICATION PACKAGES"),
        ("S-1-15-2-2", "ALL RESTRICTED APPLICATION PACKAGES"),
        ("S-1-16-0", "Untrusted Mandatory Level"),
        ("S-1-16-4096", "Low Mandatory Level"),
        ("S-1-16-8192", "Medium Mandatory Level"),
        ("S-1-16-8448", "Medium Plus Mandatory Level"),
        ("S-1-16-12288", "High Mandatory Level"),
        ("S-1-16-16384", "System Mandatory Level"),
        ("S-1-16-20480", "Protected Process Mandatory Level"),
    ];
    if let Some((_, name)) = WELL_KNOWN.iter().find(|(s, _)| *s == sid) {
        return Some(name);
    }
    // Domain-relative accounts and groups: S-1-5-21-a-b-c-RID.
    let rid = sid.strip_prefix("S-1-5-21-")?.rsplit('-').next()?;
    match rid {
        "500" => Some("Administrator (domain account)"),
        "501" => Some("Guest (domain account)"),
        "502" => Some("krbtgt"),
        "512" => Some("Domain Admins"),
        "513" => Some("Domain Users"),
        "514" => Some("Domain Guests"),
        "515" => Some("Domain Computers"),
        "516" => Some("Domain Controllers"),
        "519" => Some("Enterprise Admins"),
        _ => None,
    }
}

/// `S-...` with its well-known name, for summaries.
pub fn sid_label(sid: &str) -> String {
    match sid_name(sid) {
        Some(name) => format!("{name} ({sid})"),
        None => sid.to_owned(),
    }
}

/// A leaf for the SID stored in `span` (whose bytes are `b`).
pub fn sid_node(name: &'static str, span: Span, b: &[u8]) -> Node {
    match parse_sid(b) {
        Some((sid, len)) => {
            let node = Node::new(name)
                .span(span.sub(0, to_u64(len)))
                .value(Value::Text(sid.clone()));
            match sid_name(&sid) {
                Some(n) => node.summary(n),
                None => node,
            }
        }
        None => Node::new(name)
            .span(span)
            .diag(Diagnostic::malformed("truncated SID")),
    }
}

/// `SECURITY_DESCRIPTOR_CONTROL`.
const SD_CONTROL: FlagTable = &[
    flag(0x0001, "SE_OWNER_DEFAULTED"),
    flag(0x0002, "SE_GROUP_DEFAULTED"),
    flag(0x0004, "SE_DACL_PRESENT"),
    flag(0x0008, "SE_DACL_DEFAULTED"),
    flag(0x0010, "SE_SACL_PRESENT"),
    flag(0x0020, "SE_SACL_DEFAULTED"),
    flag(0x0040, "SE_DACL_TRUSTED"),
    flag(0x0080, "SE_SERVER_SECURITY"),
    flag(0x0100, "SE_DACL_AUTO_INHERIT_REQ"),
    flag(0x0200, "SE_SACL_AUTO_INHERIT_REQ"),
    flag(0x0400, "SE_DACL_AUTO_INHERITED"),
    flag(0x0800, "SE_SACL_AUTO_INHERITED"),
    flag(0x1000, "SE_DACL_PROTECTED"),
    flag(0x2000, "SE_SACL_PROTECTED"),
    flag(0x4000, "SE_RM_CONTROL_VALID"),
    flag(0x8000, "SE_SELF_RELATIVE"),
];

const ACE_TYPES: EnumTable = &[
    (0x00, "ACCESS_ALLOWED"),
    (0x01, "ACCESS_DENIED"),
    (0x02, "SYSTEM_AUDIT"),
    (0x03, "SYSTEM_ALARM"),
    (0x04, "ACCESS_ALLOWED_COMPOUND"),
    (0x05, "ACCESS_ALLOWED_OBJECT"),
    (0x06, "ACCESS_DENIED_OBJECT"),
    (0x07, "SYSTEM_AUDIT_OBJECT"),
    (0x08, "SYSTEM_ALARM_OBJECT"),
    (0x09, "ACCESS_ALLOWED_CALLBACK"),
    (0x0a, "ACCESS_DENIED_CALLBACK"),
    (0x0b, "ACCESS_ALLOWED_CALLBACK_OBJECT"),
    (0x0c, "ACCESS_DENIED_CALLBACK_OBJECT"),
    (0x0d, "SYSTEM_AUDIT_CALLBACK"),
    (0x0e, "SYSTEM_ALARM_CALLBACK"),
    (0x0f, "SYSTEM_AUDIT_CALLBACK_OBJECT"),
    (0x10, "SYSTEM_ALARM_CALLBACK_OBJECT"),
    (0x11, "SYSTEM_MANDATORY_LABEL"),
    (0x12, "SYSTEM_RESOURCE_ATTRIBUTE"),
    (0x13, "SYSTEM_SCOPED_POLICY_ID"),
    (0x14, "SYSTEM_PROCESS_TRUST_LABEL"),
    (0x15, "SYSTEM_ACCESS_FILTER"),
];

const ACE_FLAGS: FlagTable = &[
    flag(0x01, "OBJECT_INHERIT"),
    flag(0x02, "CONTAINER_INHERIT"),
    flag(0x04, "NO_PROPAGATE_INHERIT"),
    flag(0x08, "INHERIT_ONLY"),
    flag(0x10, "INHERITED"),
    flag(0x40, "SUCCESSFUL_ACCESS"),
    flag(0x80, "FAILED_ACCESS"),
];

const OBJECT_ACE_FLAGS: FlagTable = &[
    flag(0x1, "ACE_OBJECT_TYPE_PRESENT"),
    flag(0x2, "ACE_INHERITED_OBJECT_TYPE_PRESENT"),
];

/// Standard and generic access rights, shared by every object type.
macro_rules! standard_rights {
    ($($specific:expr),* $(,)?) => {
        &[
            $($specific,)*
            flag(0x0001_0000, "DELETE"),
            flag(0x0002_0000, "READ_CONTROL"),
            flag(0x0004_0000, "WRITE_DAC"),
            flag(0x0008_0000, "WRITE_OWNER"),
            flag(0x0010_0000, "SYNCHRONIZE"),
            flag(0x0100_0000, "ACCESS_SYSTEM_SECURITY"),
            flag(0x0200_0000, "MAXIMUM_ALLOWED"),
            flag(0x1000_0000, "GENERIC_ALL"),
            flag(0x2000_0000, "GENERIC_EXECUTE"),
            flag(0x4000_0000, "GENERIC_WRITE"),
            flag(0x8000_0000, "GENERIC_READ"),
        ]
    };
}

/// Access rights of registry keys.
pub const KEY_RIGHTS: FlagTable = standard_rights![
    flag(0x0001, "KEY_QUERY_VALUE"),
    flag(0x0002, "KEY_SET_VALUE"),
    flag(0x0004, "KEY_CREATE_SUB_KEY"),
    flag(0x0008, "KEY_ENUMERATE_SUB_KEYS"),
    flag(0x0010, "KEY_NOTIFY"),
    flag(0x0020, "KEY_CREATE_LINK"),
    flag(0x0100, "KEY_WOW64_64KEY"),
    flag(0x0200, "KEY_WOW64_32KEY"),
];

/// Access rights without object-specific names.
pub const GENERIC_RIGHTS: FlagTable = standard_rights![];

/// Mandatory label policy bits (in the mask of a mandatory label ACE).
const LABEL_POLICY: FlagTable = &[
    flag(0x1, "NO_WRITE_UP"),
    flag(0x2, "NO_READ_UP"),
    flag(0x4, "NO_EXECUTE_UP"),
];

/// What a security descriptor amounts to: "owner Administrators, DACL 3 ACEs".
pub fn sd_summary(b: &[u8]) -> String {
    let mut parts = Vec::new();
    let sid_at = |off: usize, what: &str| -> Option<String> {
        if off == 0 {
            return None;
        }
        let (sid, _) = parse_sid(b.get(off..)?)?;
        Some(format!(
            "{what} {}",
            sid_name(&sid).map_or_else(|| sid.clone(), str::to_owned)
        ))
    };
    let at = |o: usize| u32_le(b, o).map_or(0, |v| usize::try_from(v).unwrap_or(0));
    parts.extend(sid_at(at(4), "owner"));
    parts.extend(sid_at(at(8), "group"));
    let control = u16_le(b, 2).unwrap_or(0);
    let acl = |off: usize, present: bool, what: &str| -> Option<String> {
        if !present {
            return None;
        }
        if off == 0 {
            return Some(format!("null {what}"));
        }
        let count = u16_le(b, off.checked_add(4)?)?;
        Some(format!("{what} {}", plural(count, "ACE")))
    };
    parts.extend(acl(at(16), control & 0x4 != 0, "DACL"));
    parts.extend(acl(at(12), control & 0x10 != 0, "SACL"));
    parts.join(", ")
}

/// Expander: the fields of a self-relative security descriptor in `span`,
/// with access masks named by `rights`.
pub async fn security_descriptor(cx: Cx, (span, rights): (Span, FlagTable)) -> Result<()> {
    let block = cx.block(span).await?;
    let b = &block.data;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("Revision").emit()?;
    f.u8("Sbz1")
        .desc("Resource manager control bits when SE_RM_CONTROL_VALID is set")
        .emit()?;
    let control = f.u16("Control").flags(SD_CONTROL).emit()?;
    let owner = f.u32("Owner offset").hex().emit()?;
    let group = f.u32("Group offset").hex().emit()?;
    let sacl = f.u32("SACL offset").hex().emit()?;
    let dacl = f.u32("DACL offset").hex().emit()?;
    if control & 0x8000 == 0 {
        cx.diag(Diagnostic::unsupported(
            "absolute security descriptor (offsets are pointers)",
        ));
        return Ok(());
    }
    if let Some((s, bytes)) = part(span, b, owner) {
        cx.emit(sid_node("Owner", s, bytes));
    }
    if let Some((s, bytes)) = part(span, b, group) {
        cx.emit(sid_node("Group", s, bytes));
    }
    for (name, off, present) in [
        ("SACL", sacl, control & 0x10 != 0),
        ("DACL", dacl, control & 0x4 != 0),
    ] {
        if let Some((s, bytes)) = part(span, b, off) {
            let size = u16_le(bytes, 2).unwrap_or(0);
            let count = u16_le(bytes, 4).unwrap_or(0);
            let acl = s.sub(0, size.into());
            let mut node = Node::new(name).span(acl).summary(plural(count, "ACE"));
            if !present {
                node = node.desc("Offset set, but the control flags say it is absent");
            }
            cx.emit(node.lazy(acl_fields, (acl, rights)));
        } else if present {
            cx.emit(
                Node::new(name)
                    .summary("null")
                    .desc("Present but null: no restrictions (DACL) or no auditing (SACL)"),
            );
        }
    }
    Ok(())
}

/// The part of a descriptor at `offset` (none for offset 0).
fn part(span: Span, b: &[u8], offset: u32) -> Option<(Span, &[u8])> {
    let o64 = u64::from(offset);
    if offset == 0 || o64 >= span.len {
        return None;
    }
    Some((span.tail(o64), b.get(usize::try_from(offset).ok()?..)?))
}

async fn acl_fields(cx: Cx, (span, rights): (Span, FlagTable)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("AclRevision").emit()?;
    f.u8("Sbz1").emit()?;
    f.u16("AclSize").emit()?;
    let count = f.u16("AceCount").emit()?;
    f.u16("Sbz2").emit()?;
    let mut pos = 8u64;
    for i in 0..count {
        cx.checkpoint().await;
        let at = usize::try_from(pos).unwrap_or(usize::MAX);
        let (Some(kind), Some(flags), Some(size)) = (
            block.data.get(at).copied(),
            block.data.get(at.saturating_add(1)).copied(),
            u16_le(&block.data, at.saturating_add(2)),
        ) else {
            cx.diag(Diagnostic::truncated(span.tail(pos), 0));
            break;
        };
        if size < 8 {
            cx.diag(Diagnostic::malformed(format!("ACE {i} has size {size}")).at(span.sub(pos, 4)));
            break;
        }
        let ace = span.sub(pos, size.into());
        let body = block
            .data
            .get(at..at.saturating_add(usize::from(size)))
            .unwrap_or_default();
        let sid = ace_sid(kind, body)
            .and_then(|o| parse_sid(body.get(o..)?))
            .map(|(s, _)| sid_name(&s).map_or(s.clone(), str::to_owned));
        let type_name = lookup(ACE_TYPES, kind.into()).unwrap_or("unknown ACE");
        let mut summary = type_name.to_owned();
        if let Some(sid) = sid {
            summary = format!("{summary} {sid}");
        }
        if flags & 0x10 != 0 {
            summary.push_str(", inherited");
        }
        cx.emit(
            Node::new(format!("ACE {i}"))
                .span(ace)
                .summary(summary)
                .lazy(ace_fields, (ace, rights)),
        );
        pos = pos.saturating_add(size.into());
    }
    Ok(())
}

/// Offset of the SID within an ACE of type `kind`, if it has one.
fn ace_sid(kind: u8, b: &[u8]) -> Option<usize> {
    match kind {
        // Object ACEs: mask, flags, optional GUIDs, then the SID.
        0x05..=0x08 | 0x0b | 0x0c | 0x0f | 0x10 => {
            let flags = u32_le(b, 8)?;
            let mut at = 12usize;
            if flags & 1 != 0 {
                at = at.checked_add(16)?;
            }
            if flags & 2 != 0 {
                at = at.checked_add(16)?;
            }
            Some(at)
        }
        0x04 => None,
        _ => Some(8),
    }
}

async fn ace_fields(cx: Cx, (span, rights): (Span, FlagTable)) -> Result<()> {
    let block = cx.block(span).await?;
    let b = &block.data;
    let mut f = Fields::emitting(&cx, &block, LE);
    let kind = f.u8("AceType").enumeration(ACE_TYPES).emit()?;
    f.u8("AceFlags").flags(ACE_FLAGS).emit()?;
    let size = f.u16("AceSize").emit()?;
    let mask_table = if kind == 0x11 { LABEL_POLICY } else { rights };
    f.u32("Mask").flags(mask_table).emit()?;
    if kind == 0x04 {
        // Compound ACE: compound type, reserved, server SID, client SID.
        f.u16("CompoundAceType").emit()?;
        f.u16("Reserved").emit()?;
        let at = usize::try_from(f.pos()).unwrap_or(usize::MAX);
        if let Some((_, len)) = b.get(at..).and_then(parse_sid) {
            cx.emit(sid_node(
                "Server SID",
                f.peek_span(to_u64(len)),
                b.get(at..).unwrap_or_default(),
            ));
            f.skip(to_u64(len));
        }
    } else if matches!(kind, 0x05..=0x08 | 0x0b | 0x0c | 0x0f | 0x10) {
        let flags = f.u32("Flags").flags(OBJECT_ACE_FLAGS).emit()?;
        if flags & 1 != 0 {
            f.guid("ObjectType").emit()?;
        }
        if flags & 2 != 0 {
            f.guid("InheritedObjectType").emit()?;
        }
    }
    let at = usize::try_from(f.pos()).unwrap_or(usize::MAX);
    let rest = b.get(at..).unwrap_or_default();
    let sid_len = match parse_sid(rest) {
        Some((_, len)) => {
            cx.emit(sid_node("SID", f.peek_span(to_u64(len)), rest));
            to_u64(len)
        }
        None => 0,
    };
    f.skip(sid_len);
    let left = u64::from(size).saturating_sub(f.pos());
    if left > 0 {
        let name = match kind {
            0x09..=0x10 => "Application data",
            0x12 => "Attribute data",
            _ => "Padding",
        };
        f.bytes(name, left).emit()?;
    }
    Ok(())
}
