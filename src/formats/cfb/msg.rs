//! Outlook messages ([MS-OXMSG]): the `__properties_version1.0` streams of
//! the message, its recipients and attachments (fixed-size values inline,
//! sizes of the others), the `__substg1.0_` value streams decoded by
//! property type, compressed RTF bodies, and the named property mapping in
//! `__nameid_version1.0` that gives properties 0x8000 and above their names.

use std::sync::Arc;

use super::CfbRef;
use super::rec::{LE, enumv, hex, uint};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::Input;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, Value, flag, lookup};

/// Tagged property names ([MS-OXPROPS]), without the `PidTag` prefix.
pub const MAPI_NAMES: EnumTable = &[
    (0x0001, "NameidBucketCount"),
    (0x0002, "NameidStreamGuid"),
    (0x0003, "NameidStreamEntry"),
    (0x0004, "NameidStreamString"),
    (0x0017, "Importance"),
    (0x001a, "MessageClass"),
    (0x0023, "OriginatorDeliveryReportRequested"),
    (0x0026, "Priority"),
    (0x0029, "ReadReceiptRequested"),
    (0x002b, "RecipientReassignmentProhibited"),
    (0x002e, "OriginalSensitivity"),
    (0x0036, "Sensitivity"),
    (0x0037, "Subject"),
    (0x0039, "ClientSubmitTime"),
    (0x003b, "SentRepresentingSearchKey"),
    (0x003d, "SubjectPrefix"),
    (0x003f, "ReceivedByEntryId"),
    (0x0040, "ReceivedByName"),
    (0x0041, "SentRepresentingEntryId"),
    (0x0042, "SentRepresentingName"),
    (0x0043, "ReceivedRepresentingEntryId"),
    (0x0044, "ReceivedRepresentingName"),
    (0x004f, "ReplyRecipientEntries"),
    (0x0050, "ReplyRecipientNames"),
    (0x0051, "ReceivedBySearchKey"),
    (0x0052, "ReceivedRepresentingSearchKey"),
    (0x0057, "MessageToMe"),
    (0x0058, "MessageCcMe"),
    (0x0064, "SentRepresentingAddressType"),
    (0x0065, "SentRepresentingEmailAddress"),
    (0x0070, "ConversationTopic"),
    (0x0071, "ConversationIndex"),
    (0x0075, "ReceivedByAddressType"),
    (0x0076, "ReceivedByEmailAddress"),
    (0x0077, "ReceivedRepresentingAddressType"),
    (0x0078, "ReceivedRepresentingEmailAddress"),
    (0x007d, "TransportMessageHeaders"),
    (0x0c15, "RecipientType"),
    (0x0c17, "ReplyRequested"),
    (0x0c19, "SenderEntryId"),
    (0x0c1a, "SenderName"),
    (0x0c1d, "SenderSearchKey"),
    (0x0c1e, "SenderAddressType"),
    (0x0c1f, "SenderEmailAddress"),
    (0x0e01, "DeleteAfterSubmit"),
    (0x0e02, "DisplayBcc"),
    (0x0e03, "DisplayCc"),
    (0x0e04, "DisplayTo"),
    (0x0e06, "MessageDeliveryTime"),
    (0x0e07, "MessageFlags"),
    (0x0e08, "MessageSize"),
    (0x0e0f, "Responsibility"),
    (0x0e17, "MessageStatus"),
    (0x0e1b, "HasAttachments"),
    (0x0e1d, "NormalizedSubject"),
    (0x0e1f, "RtfInSync"),
    (0x0e20, "AttachSize"),
    (0x0e21, "AttachNumber"),
    (0x0e23, "InternetArticleNumber"),
    (0x0e27, "SecurityDescriptor"),
    (0x0e30, "ReplItemid"),
    (0x0e33, "ReplChangenum"),
    (0x0e34, "ReplVersionhistory"),
    (0x0e38, "ReplFlags"),
    (0x0e79, "TrustSender"),
    (0x0ff4, "Access"),
    (0x0ff6, "InstanceKey"),
    (0x0ff7, "AccessLevel"),
    (0x0ff9, "RecordKey"),
    (0x0ffe, "ObjectType"),
    (0x0fff, "EntryId"),
    (0x1000, "Body"),
    (0x1009, "RtfCompressed"),
    (0x1013, "Html"),
    (0x1035, "InternetMessageId"),
    (0x1039, "InternetReferences"),
    (0x1042, "InReplyToId"),
    (0x1080, "IconIndex"),
    (0x1081, "LastVerbExecuted"),
    (0x1082, "LastVerbExecutionTime"),
    (0x1090, "FlagStatus"),
    (0x1096, "BlockStatus"),
    (0x10f4, "AttributeHidden"),
    (0x3001, "DisplayName"),
    (0x3002, "AddressType"),
    (0x3003, "EmailAddress"),
    (0x3004, "Comment"),
    (0x3007, "CreationTime"),
    (0x3008, "LastModificationTime"),
    (0x300b, "SearchKey"),
    (0x3010, "TargetEntryId"),
    (0x3013, "ConversationId"),
    (0x3016, "ConversationIndexTracking"),
    (0x35df, "ValidFolderMask"),
    (0x35e0, "IpmSubTreeEntryId"),
    (0x35e2, "IpmOutboxEntryId"),
    (0x35e3, "IpmWastebasketEntryId"),
    (0x35e4, "IpmSentMailEntryId"),
    (0x35e5, "ViewsEntryId"),
    (0x35e6, "CommonViewsEntryId"),
    (0x35e7, "FinderEntryId"),
    (0x3602, "ContentCount"),
    (0x3603, "ContentUnreadCount"),
    (0x3613, "ContainerClass"),
    (0x360a, "Subfolders"),
    (0x3701, "AttachDataBinary"),
    (0x3702, "AttachEncoding"),
    (0x3703, "AttachExtension"),
    (0x3704, "AttachFilename"),
    (0x3705, "AttachMethod"),
    (0x3707, "AttachLongFilename"),
    (0x3708, "AttachPathname"),
    (0x3709, "AttachRendering"),
    (0x370a, "AttachTag"),
    (0x370b, "RenderingPosition"),
    (0x370e, "AttachMimeTag"),
    (0x3712, "AttachContentId"),
    (0x3713, "AttachContentLocation"),
    (0x3714, "AttachFlags"),
    (0x3900, "DisplayType"),
    (0x3905, "DisplayTypeEx"),
    (0x39fe, "SmtpAddress"),
    (0x39ff, "AddressBookDisplayNamePrintable"),
    (0x3a00, "Account"),
    (0x3a20, "TransmittableDisplayName"),
    (0x3a40, "SendRichInfo"),
    (0x3fde, "InternetCodepage"),
    (0x3ff1, "MessageLocaleId"),
    (0x3ff8, "CreatorName"),
    (0x3ff9, "CreatorEntryId"),
    (0x3ffa, "LastModifierName"),
    (0x3ffb, "LastModifierEntryId"),
    (0x3ffd, "MessageCodepage"),
    (0x5902, "InternetMailOverrideFormat"),
    (0x5909, "MessageEditorFormat"),
    (0x5d01, "SenderSmtpAddress"),
    (0x5d02, "SentRepresentingSmtpAddress"),
    (0x5fde, "RecipientResourceState"),
    (0x5fdf, "RecipientOrder"),
    (0x5fe5, "RecipientSipUri"),
    (0x5ff6, "RecipientDisplayName"),
    (0x5ff7, "RecipientEntryId"),
    (0x5ffb, "RecipientTrackStatusTime"),
    (0x5ffd, "RecipientFlags"),
    (0x5fff, "RecipientTrackStatus"),
    (0x6633, "PstLrNoRestrictions"),
    (0x6635, "PstHiddenCount"),
    (0x6636, "PstHiddenUnread"),
    (0x66fa, "LatestPstEnsure"),
    (0x6705, "SortLocaleId"),
    (0x67f2, "LtpRowId"),
    (0x67f3, "LtpRowVer"),
    (0x67ff, "PstPassword"),
    (0x7ffd, "AttachmentFlags"),
    (0x7ffe, "AttachmentHidden"),
    (0x7fff, "AttachmentContactPhoto"),
    (0x6772, "PstIpmSubTreeDescendant"),
    (0x6773, "PstSubTreeContainer"),
    (0x0e05, "ParentDisplay"),
    (0x0e09, "ParentEntryId"),
    (0x0e0a, "SentMailEntryId"),
    (0x0e12, "MessageRecipients"),
    (0x0e13, "MessageAttachments"),
    (0x0e2b, "ToDoItemFlags"),
    (0x3005, "Depth"),
    (0x3a0c, "Language"),
    (0x7ffa, "AttachmentLinkId"),
];

/// Property types ([MS-OXCDATA] 2.11.1).
pub const TYPES: EnumTable = &[
    (0x0002, "PtypInteger16"),
    (0x0003, "PtypInteger32"),
    (0x0004, "PtypFloating32"),
    (0x0005, "PtypFloating64"),
    (0x0006, "PtypCurrency"),
    (0x0007, "PtypFloatingTime"),
    (0x000a, "PtypErrorCode"),
    (0x000b, "PtypBoolean"),
    (0x000d, "PtypObject"),
    (0x0014, "PtypInteger64"),
    (0x001e, "PtypString8"),
    (0x001f, "PtypString"),
    (0x0040, "PtypTime"),
    (0x0048, "PtypGuid"),
    (0x00fb, "PtypServerId"),
    (0x00fd, "PtypRestriction"),
    (0x00fe, "PtypRuleAction"),
    (0x0102, "PtypBinary"),
    (0x1002, "PtypMultipleInteger16"),
    (0x1003, "PtypMultipleInteger32"),
    (0x1004, "PtypMultipleFloating32"),
    (0x1005, "PtypMultipleFloating64"),
    (0x1006, "PtypMultipleCurrency"),
    (0x1007, "PtypMultipleFloatingTime"),
    (0x1014, "PtypMultipleInteger64"),
    (0x101e, "PtypMultipleString8"),
    (0x101f, "PtypMultipleString"),
    (0x1040, "PtypMultipleTime"),
    (0x1048, "PtypMultipleGuid"),
    (0x1102, "PtypMultipleBinary"),
];

const IMPORTANCE: EnumTable = &[(0, "Low"), (1, "Normal"), (2, "High")];
const SENSITIVITY: EnumTable = &[
    (0, "Normal"),
    (1, "Personal"),
    (2, "Private"),
    (3, "Confidential"),
];
const RECIPIENT_TYPE: EnumTable = &[(0, "Originator"), (1, "To"), (2, "Cc"), (3, "Bcc")];
const ATTACH_METHOD: EnumTable = &[
    (0, "None"),
    (1, "By value"),
    (2, "By reference"),
    (4, "By reference only"),
    (5, "Embedded message"),
    (6, "OLE storage"),
    (7, "By web reference"),
];
const OBJECT_TYPE: EnumTable = &[
    (1, "Store"),
    (2, "Address book"),
    (3, "Folder"),
    (4, "Address book container"),
    (5, "Message"),
    (6, "Mail user"),
    (7, "Attachment"),
    (8, "Distribution list"),
];
const MESSAGE_FLAGS: FlagTable = &[
    flag(0x1, "mfRead"),
    flag(0x2, "mfUnmodified"),
    flag(0x4, "mfSubmitted"),
    flag(0x8, "mfUnsent"),
    flag(0x10, "mfHasAttach"),
    flag(0x20, "mfFromMe"),
    flag(0x40, "mfFAI"),
    flag(0x80, "mfResend"),
    flag(0x100, "mfNotifyRead"),
    flag(0x200, "mfNotifyUnread"),
    flag(0x400, "mfEverRead"),
    flag(0x2000, "mfInternet"),
    flag(0x8000, "mfUntrusted"),
];
const PROP_FLAGS: FlagTable = &[
    flag(0x1, "PROPATTR_MANDATORY"),
    flag(0x2, "PROPATTR_READABLE"),
    flag(0x4, "PROPATTR_WRITABLE"),
];
const EDITOR_FORMAT: EnumTable = &[(0, "unknown"), (1, "plain text"), (2, "HTML"), (3, "RTF")];

/// Well-known property set GUIDs.
const PROPERTY_SETS: &[(&str, &str)] = &[
    ("{00020328-0000-0000-c000-000000000046}", "PS_MAPI"),
    (
        "{00020329-0000-0000-c000-000000000046}",
        "PS_PUBLIC_STRINGS",
    ),
    ("{00062008-0000-0000-c000-000000000046}", "PSETID_Common"),
    ("{00062004-0000-0000-c000-000000000046}", "PSETID_Address"),
    (
        "{00062002-0000-0000-c000-000000000046}",
        "PSETID_Appointment",
    ),
    ("{00062003-0000-0000-c000-000000000046}", "PSETID_Task"),
    ("{0006200a-0000-0000-c000-000000000046}", "PSETID_Log"),
    ("{0006200e-0000-0000-c000-000000000046}", "PSETID_Note"),
    (
        "{00020386-0000-0000-c000-000000000046}",
        "PS_INTERNET_HEADERS",
    ),
    ("{6ed8da90-450b-101b-98da-00aa003f1305}", "PSETID_Meeting"),
    ("{41f28f13-83f4-4114-a584-eedb5a6b0bff}", "PSETID_Messaging"),
    (
        "{71035549-0739-4dcb-9163-00f0580dbbdf}",
        "PSETID_UnifiedMessaging",
    ),
    ("{96357f7f-59e1-47d0-99a7-46515c183b54}", "PSETID_Sharing"),
    ("{00062040-0000-0000-c000-000000000046}", "PSETID_AirSync"),
    (
        "{23239608-685d-4732-9c55-4c95cb4e8e33}",
        "PSETID_XmlExtractedEntities",
    ),
    (
        "{33eba41f-7aa8-422e-be7b-79e1a98e54b3}",
        "PSETID_CalendarAssistant",
    ),
];

fn set_name(g: &Guid) -> String {
    let s = g.to_string();
    PROPERTY_SETS
        .iter()
        .find(|(k, _)| *k == s)
        .map_or(s, |(_, n)| (*n).to_owned())
}

fn guid(data: &[u8], at: usize) -> Option<Guid> {
    Some(Guid {
        data1: u32_le(data, at)?,
        data2: u16_le(data, at.checked_add(4)?)?,
        data3: u16_le(data, at.checked_add(6)?)?,
        data4: crate::bytes::array(data, at.checked_add(8)?)?,
    })
}

/// A named property's identity: its property set and number or name.
#[derive(Clone, Debug)]
pub struct Named {
    pub set: String,
    pub id: Result<u32, String>,
}

/// The named property map, indexed by `prop_id - 0x8000`.
#[derive(Default, Debug)]
pub struct NameMap {
    pub names: Vec<Option<Named>>,
}

/// The display name of a property ID.
pub fn property_name(id: u16, names: &NameMap) -> String {
    if id >= 0x8000 {
        return match names
            .names
            .get(usize::from(id.saturating_sub(0x8000)))
            .cloned()
            .flatten()
        {
            Some(Named { set, id: Ok(n) }) => format!("{set}:{n:#06x}"),
            Some(Named { set, id: Err(s) }) => format!("{set}:{s}"),
            None => format!("Named property {id:#06x}"),
        };
    }
    lookup(MAPI_NAMES, id.into())
        .map_or_else(|| format!("Property {id:#06x}"), |n| format!("PidTag{n}"))
}

/// `__substg1.0_XXXXYYYY[-NNNNNNNN]`: property ID, type, and value index.
pub fn tag(raw: &str) -> Option<(u16, u16, Option<u32>)> {
    let hex = raw.strip_prefix("__substg1.0_")?;
    let (tag, index) = match hex.split_once('-') {
        Some((t, i)) => (t, Some(u32::from_str_radix(i, 16).ok()?)),
        None => (hex, None),
    };
    if tag.len() != 8 {
        return None;
    }
    let tag = u32::from_str_radix(tag, 16).ok()?;
    Some(((tag >> 16) as u16, (tag & 0xffff) as u16, index))
}

/// Loads the named property map from the root's `__nameid_version1.0`.
pub async fn name_map(cx: &Cx, cfb: &CfbRef) -> Arc<NameMap> {
    let key = cfb.input.span.sub(0, 0);
    if let Some(found) = cx.cached::<NameMap>(key, "msg-nameid") {
        return found;
    }
    let map = Arc::new(load_name_map(cx, cfb).await.unwrap_or_default());
    cx.cache(key, "msg-nameid", map.clone());
    map
}

async fn load_name_map(cx: &Cx, cfb: &CfbRef) -> Option<NameMap> {
    let (storage, _) = super::find_child(cx, cfb, 0, "__nameid_version1.0").await?;
    let guids = super::child_stream(cx, cfb, storage, "__substg1.0_00020102").await;
    let entries = super::child_stream(cx, cfb, storage, "__substg1.0_00030102").await?;
    let strings = super::child_stream(cx, cfb, storage, "__substg1.0_00040102").await;
    let guids = match guids {
        Some(s) => cx.read_avail(s.sub(0, 0x10000)).await.ok()?,
        None => Vec::new(),
    };
    let strings = match strings {
        Some(s) => cx.read_avail(s.sub(0, 0x100000)).await.ok()?,
        None => Vec::new(),
    };
    let entries = cx.read_avail(entries.sub(0, 0x80000)).await.ok()?;
    let mut map = NameMap::default();
    for (i, e) in entries.as_chunks::<8>().0.iter().enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let a = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let b = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
        let (set, index, string) = entry_parts(b);
        let set = set_label(set, &guids);
        let id = if string {
            Err(name_string(&strings, a).unwrap_or_else(|| format!("string at {a:#x}")))
        } else {
            Ok(a)
        };
        let slot = usize::from(index);
        if map.names.len() <= slot {
            map.names.resize(slot.saturating_add(1), None);
        }
        if let Some(s) = map.names.get_mut(slot) {
            *s = Some(Named { set, id });
        }
        if map.names.len() > 0x8000 {
            break;
        }
    }
    Some(map)
}

/// Index and kind information: (GUID index, property index, string name).
fn entry_parts(b: u32) -> (u16, u16, bool) {
    (((b >> 1) & 0x7fff) as u16, (b >> 16) as u16, b & 1 != 0)
}

fn set_label(index: u16, guids: &[u8]) -> String {
    match index {
        1 => "PS_MAPI".to_owned(),
        2 => "PS_PUBLIC_STRINGS".to_owned(),
        n => guid(guids, usize::from(n.saturating_sub(3)).saturating_mul(16))
            .map_or_else(|| format!("GUID {n}"), |g| set_name(&g)),
    }
}

fn name_string(strings: &[u8], at: u32) -> Option<String> {
    let at = to_usize(at.into());
    let len = to_usize(u32_le(strings, at)?.into());
    let raw = strings.get(at.checked_add(4)?..at.checked_add(4)?.checked_add(len)?)?;
    Some(crate::text::utf16(raw, LE))
}

/// The typed value of a fixed-size property (`raw` holds its 8 bytes or
/// more), and a summary.
fn scalar(id: u16, ty: u16, raw: &[u8]) -> (Option<Value>, Option<String>) {
    let low = u32_le(raw, 0).map(u64::from).unwrap_or(0);
    let wide = u64_le(raw, 0).unwrap_or(0);
    let value = match ty {
        0x0002 => Value::Int {
            value: i64::from(u16_le(raw, 0).unwrap_or(0).cast_signed()),
            bits: 16,
        },
        0x0003 => match id {
            0x0017 => enumv(low, 32, IMPORTANCE),
            0x0036 | 0x002e => enumv(low, 32, SENSITIVITY),
            0x0c15 => enumv(low, 32, RECIPIENT_TYPE),
            0x3705 => enumv(low, 32, ATTACH_METHOD),
            0x0ffe => enumv(low, 32, OBJECT_TYPE),
            0x5909 => enumv(low, 32, EDITOR_FORMAT),
            0x0e07 => super::rec::flagsv(low, 32, MESSAGE_FLAGS),
            0x3fde | 0x3ffd | 0x3fd9 => {
                return (Some(uint(low, 32)), Some("code page".to_owned()));
            }
            0x3ff1 | 0x3a0c => {
                return (
                    Some(hex(low, 32)),
                    Some(crate::formats::util::lcid::describe(
                        u32::try_from(low).unwrap_or(0),
                    )),
                );
            }
            _ => Value::Int {
                value: i64::from((low as u32).cast_signed()),
                bits: 32,
            },
        },
        0x0004 => Value::Float(f64::from(f32::from_bits(low as u32))),
        0x0005 | 0x0007 => Value::Float(f64::from_bits(wide)),
        0x0006 => {
            let v = wide.cast_signed();
            return (
                Some(Value::Int { value: v, bits: 64 }),
                Some(format!("{}.{:04}", v / 10_000, (v % 10_000).unsigned_abs())),
            );
        }
        0x000a => hex(low, 32),
        0x000b => Value::Bool(raw.first().is_some_and(|&b| b != 0)),
        0x0014 => Value::Int {
            value: wide.cast_signed(),
            bits: 64,
        },
        0x0040 => {
            if wide == 0 || wide == 0x7fff_ffff_ffff_ffff {
                return (Some(hex(wide, 64)), Some("not set".to_owned()));
            }
            Value::Timestamp {
                unix_seconds: crate::text::filetime_to_unix(wide),
            }
        }
        _ => return (None, None),
    };
    (Some(value), None)
}

/// How many header bytes precede the property entries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    /// The top-level message: 32 bytes.
    Top,
    /// A message embedded in an attachment: 24 bytes.
    Embedded,
    /// A recipient or attachment: 8 bytes.
    Child,
}

/// `__properties_version1.0`: a header, then 16-byte property entries.
pub async fn properties(cx: &Cx, cfb: &CfbRef, span: Span, level: Level) -> Result<()> {
    let names = name_map(cx, cfb).await;
    let header = match level {
        Level::Top => 32,
        Level::Embedded => 24,
        Level::Child => 8,
    };
    let head = struct_node("Header", span.sub(0, header), LE, level, header_layout);
    cx.emit(head);
    let mut at = header;
    while at.saturating_add(16) <= span.len {
        let entry = span.sub(at, 16);
        let data = cx.read(entry).await?;
        let tag = u32_le(&data, 0).unwrap_or(0);
        let (id, ty) = ((tag >> 16) as u16, (tag & 0xffff) as u16);
        let name = property_name(id, &names);
        let type_name = lookup(TYPES, ty.into()).unwrap_or("unknown type");
        let raw = data.get(8..).unwrap_or_default();
        let fixed = matches!(ty, 0x0002..=0x0007 | 0x000a | 0x000b | 0x0014 | 0x0040);
        let mut node = Node::new(name).span(entry);
        if fixed {
            let (value, detail) = scalar(id, ty, raw);
            if let Some(v) = value {
                node = node.value(v);
            }
            node = node.summary(match detail {
                Some(d) => format!("{type_name}, {d}"),
                None => type_name.to_owned(),
            });
        } else {
            let size = u32_le(raw, 0).unwrap_or(0);
            node = node.value(uint(size, 32)).summary(format!(
                "{type_name}: {size}-byte value in stream __substg1.0_{tag:08X}"
            ));
        }
        cx.progress_in(span, entry.offset);
        cx.push(node.lazy(entry_node, (entry, fixed))).await;
        at = at.saturating_add(16);
    }
    if at < span.len {
        cx.push(
            Node::new("Trailing data")
                .span(span.tail(at))
                .diag(Diagnostic::malformed("a partial property entry")),
        )
        .await;
    }
    Ok(())
}

fn header_layout(f: &mut Fields<'_>, level: &Level) -> Result<()> {
    f.bytes("Reserved", 8).emit()?;
    if *level == Level::Child {
        return Ok(());
    }
    f.u32("Next Recipient ID").emit()?;
    f.u32("Next Attachment ID").emit()?;
    f.u32("Recipient Count").emit()?;
    f.u32("Attachment Count").emit()?;
    if *level == Level::Top {
        f.bytes("Reserved", 8).emit()?;
    }
    Ok(())
}

async fn entry_node(cx: Cx, (entry, fixed): (Span, bool)) -> Result<()> {
    let block = cx.block(entry).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u16("Property type").enumeration(TYPES).emit()?;
    f.u16("Property ID").hex().emit()?;
    f.u32("Flags").flags(PROP_FLAGS).emit()?;
    if fixed {
        f.bytes("Value", 8).emit()?;
    } else {
        f.u32("Size")
            .desc("Bytes in the value stream (strings include the terminator)")
            .emit()?;
        f.u32("Reserved").emit()?;
    }
    Ok(())
}

/// A `__substg1.0_` value stream.
pub async fn value_stream(
    cx: &Cx,
    cfb: &CfbRef,
    input: Input,
    raw: &str,
    span: Span,
) -> Result<()> {
    let Some((id, ty, index)) = tag(raw) else {
        return Ok(());
    };
    let names = name_map(cx, cfb).await;
    cx.emit(
        Node::new("Property")
            .value(Value::Text(property_name(id, &names)))
            .summary(format!(
                "{}{}",
                lookup(TYPES, ty.into()).unwrap_or("unknown type"),
                match index {
                    Some(i) => format!(", value {i}"),
                    None => String::new(),
                }
            )),
    );
    let base = ty & 0x0fff;
    let multi = ty & 0x1000 != 0;
    match (base, multi, index) {
        (0x001e | 0x001f, false, _) | (0x001e | 0x001f, true, Some(_)) => {
            let data = cx.read_avail(span.sub(0, 0x10000)).await?;
            let text = if base == 0x001f {
                crate::text::utf16(&data, LE)
            } else {
                crate::text::latin1(&data)
            };
            let text = text.trim_end_matches('\0').to_owned();
            let mut node = Node::new("Value").span(span).value(Value::Text(text));
            if span.len > 0x10000 {
                node = node.summary(format!("first 64 KiB of {} bytes", span.len));
            }
            if id == 0x007d || id == 0x1013 {
                node = node.lazy(crate::formats::dissect_or_data, input.nested(span));
            }
            cx.emit(node);
        }
        (0x001e | 0x001f | 0x0102, true, None) => {
            // The lengths of the values, each in its own stream.
            let data = cx.read_avail(span.sub(0, 0x10000)).await?;
            let step = if base == 0x0102 { 8usize } else { 4 };
            for (i, c) in data.chunks_exact(step).enumerate() {
                let len = u32_le(c, 0).unwrap_or(0);
                cx.push(
                    Node::new(format!("Length {i}"))
                        .span(span.sub(to_u64(i.saturating_mul(step)), to_u64(step)))
                        .value(uint(len, 32)),
                )
                .await;
            }
        }
        (_, true, None) => {
            let size = match base {
                0x0002 => 2usize,
                0x0003 | 0x0004 => 4,
                0x0048 => 16,
                _ => 8,
            };
            let data = cx.read_avail(span.sub(0, 0x10000)).await?;
            for (i, c) in data.chunks_exact(size).enumerate() {
                if i.is_multiple_of(256) {
                    cx.checkpoint().await;
                }
                let mut node = Node::new(format!("Value {i}"))
                    .span(span.sub(to_u64(i.saturating_mul(size)), to_u64(size)));
                node = if base == 0x0048 {
                    match guid(c, 0) {
                        Some(g) => node.value(Value::Guid(g)),
                        None => node,
                    }
                } else {
                    match scalar(id, base, c).0 {
                        Some(v) => node.value(v),
                        None => node.value(Value::Bytes(c.to_vec())),
                    }
                };
                cx.push(node).await;
            }
        }
        (0x0048, false, _) => {
            let data = cx.read_avail(span.sub(0, 16)).await?;
            let mut node = Node::new("Value").span(span);
            if let Some(g) = guid(&data, 0) {
                node = node.value(Value::Guid(g));
            }
            cx.emit(node);
        }
        (0x0102, _, _) if id == 0x1009 => {
            let head = cx.read_avail(span.sub(0, 16)).await?;
            let raw_size = u32_le(&head, 4).map(u64::from);
            cx.emit(struct_node(
                "Compressed RTF header",
                span.sub(0, 16),
                LE,
                (),
                rtf_header,
            ));
            cx.emit(
                crate::formats::content(
                    "Decompressed RTF",
                    input,
                    span,
                    crate::codec::Codec::Lzfu,
                    raw_size,
                )
                .summary(format!("{} bytes", raw_size.unwrap_or(0))),
            );
        }
        (0x0102, _, _) if id == 0x0002 || id == 0x0003 || id == 0x0004 => {
            // Named property mapping streams.
            nameid_stream(cx, id, span).await?;
        }
        (0x0102, _, _) if span.len <= 64 => {
            let data = cx.read_avail(span).await?;
            let mut node = Node::new("Value")
                .span(span)
                .value(Value::Bytes(data.clone()));
            if matches!(
                id,
                0x0fff | 0x0ff9 | 0x300b | 0x0c19 | 0x0041 | 0x003b | 0x0071
            ) {
                node = node.summary(entry_id_summary(&data));
            }
            cx.emit(node);
        }
        _ => cx.emit(
            Node::new("Value")
                .span(span)
                .summary(format!("{} bytes", span.len))
                .lazy(crate::formats::dissect_or_data, input.nested(span)),
        ),
    }
    Ok(())
}

fn entry_id_summary(data: &[u8]) -> String {
    match guid(data, 4) {
        Some(g) => format!("provider {g}"),
        None => format!("{} bytes", data.len()),
    }
}

const RTF_TYPES: EnumTable = &[
    (0x7546_5a4c, "LZFu (compressed)"),
    (0x414c_454d, "MELA (uncompressed)"),
];

fn rtf_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("compSize").desc("Bytes after this field").emit()?;
    f.u32("rawSize").emit()?;
    f.u32("compType").hex().enumeration(RTF_TYPES).emit()?;
    f.u32("crc").hex().emit()?;
    Ok(())
}

/// The GUID, entry and string streams of the named property mapping.
async fn nameid_stream(cx: &Cx, id: u16, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 0x100000)).await?;
    match id {
        0x0002 => {
            for (i, c) in data.as_chunks::<16>().0.iter().enumerate() {
                let g = guid(c, 0);
                let mut node = Node::new(format!("GUID {}", i.saturating_add(3)))
                    .span(span.sub(to_u64(i.saturating_mul(16)), 16));
                if let Some(g) = g {
                    node = node.summary(set_name(&g)).value(Value::Guid(g));
                }
                cx.push(node).await;
            }
        }
        0x0003 => {
            for (i, e) in data.as_chunks::<8>().0.iter().enumerate() {
                if i.is_multiple_of(256) {
                    cx.checkpoint().await;
                }
                let a = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
                let b = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
                let (set, index, string) = entry_parts(b);
                cx.push(
                    Node::new(format!(
                        "Property {:#06x}",
                        0x8000u32.saturating_add(index.into())
                    ))
                    .span(span.sub(to_u64(i.saturating_mul(8)), 8))
                    .value(hex(a, 32))
                    .summary(format!(
                        "{} {} in set index {set}",
                        if string {
                            "name at string offset"
                        } else {
                            "number"
                        },
                        if string {
                            format!("{a:#x}")
                        } else {
                            format!("{a:#06x}")
                        }
                    )),
                )
                .await;
            }
        }
        _ => {
            let mut at = 0usize;
            while at.saturating_add(4) <= data.len() {
                cx.checkpoint().await;
                let len = to_usize(u32_le(&data, at).unwrap_or(0).into());
                let end = at.saturating_add(4).saturating_add(len);
                let text =
                    crate::text::utf16(data.get(at.saturating_add(4)..end).unwrap_or_default(), LE);
                let padded = end.saturating_add(3) & !3;
                cx.push(
                    Node::new(format!("Name at {at:#x}"))
                        .span(span.sub(to_u64(at), to_u64(padded.saturating_sub(at))))
                        .value(Value::Text(text)),
                )
                .await;
                at = padded;
            }
        }
    }
    Ok(())
}

/// A label for an entry of an Outlook message storage, and a description.
pub fn label(raw: &str, names: Option<&NameMap>, nameid: bool) -> Option<(String, String)> {
    for (prefix, label) in [
        ("__recip_version1.0_#", "Recipient"),
        ("__attach_version1.0_#", "Attachment"),
    ] {
        if let Some(n) = raw.strip_prefix(prefix) {
            let index = u32::from_str_radix(n, 16).unwrap_or(0);
            return Some((
                format!("{label} {index}"),
                format!("{} storage", label.to_lowercase()),
            ));
        }
    }
    let fixed = match raw {
        "__nameid_version1.0" => Some(("Named property mapping", "storage")),
        "__properties_version1.0" => Some(("Properties", "fixed-size property values")),
        "__substg1.0_00020102" => Some(("GUID stream", "named property sets")),
        "__substg1.0_00030102" => Some(("Entry stream", "named property entries")),
        "__substg1.0_00040102" => Some(("String stream", "named property names")),
        "__substg1.0_3701000D" => Some(("Embedded message", "attachment data storage")),
        _ => None,
    };
    if let Some((a, b)) = fixed {
        return Some((a.to_owned(), b.to_owned()));
    }
    let (id, ty, index) = tag(raw)?;
    if nameid && (0x1000..=0x10ff).contains(&id) && ty == 0x0102 && raw.len() == 20 {
        return Some((
            format!("Hash bucket {:#06x}", id),
            "named property hash stream".to_owned(),
        ));
    }
    let empty = NameMap::default();
    let name = property_name(id, names.unwrap_or(&empty));
    let ty_name = lookup(TYPES, ty.into()).map_or_else(|| format!("type {ty:#06x}"), str::to_owned);
    Some(match index {
        Some(i) => (
            format!("{name} [{i}]"),
            format!("property {id:#06x}, {ty_name}"),
        ),
        None => (name, format!("property {id:#06x}, {ty_name}")),
    })
}
