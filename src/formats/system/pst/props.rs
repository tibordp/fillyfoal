//! MAPI property names, types and values.

use std::sync::Arc;

use super::ltp::{self, NodeRef, Raw};
use super::ndb::{self, Pst};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Endian;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, Radix, Value, flag, lookup};

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
    (0x0102, "PtypBinary"),
    (0x1002, "PtypMultipleInteger16"),
    (0x1003, "PtypMultipleInteger32"),
    (0x1005, "PtypMultipleFloating64"),
    (0x1014, "PtypMultipleInteger64"),
    (0x101e, "PtypMultipleString8"),
    (0x101f, "PtypMultipleString"),
    (0x1040, "PtypMultipleTime"),
    (0x1048, "PtypMultipleGuid"),
    (0x1102, "PtypMultipleBinary"),
];

/// Tagged property names ([MS-OXPROPS]), without the `PidTag` prefix.
pub const NAMES: EnumTable = &[
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
];

const IMPORTANCE: EnumTable = &[(0, "Low"), (1, "Normal"), (2, "High")];
const SENSITIVITY: EnumTable = &[
    (0, "Normal"),
    (1, "Personal"),
    (2, "Private"),
    (3, "Confidential"),
];
const RECIPIENT_TYPE: EnumTable = &[(0, "Originator"), (1, "To"), (2, "Cc"), (3, "Bcc")];
pub const ATTACH_METHOD: EnumTable = &[
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
    flag(0x1, "READ"),
    flag(0x2, "UNMODIFIED"),
    flag(0x4, "SUBMITTED"),
    flag(0x8, "UNSENT"),
    flag(0x10, "HASATTACH"),
    flag(0x20, "FROMME"),
    flag(0x40, "ASSOCIATED"),
    flag(0x80, "RESEND"),
    flag(0x100, "NOTIFYREAD"),
    flag(0x200, "NOTIFYUNREAD"),
    flag(0x400, "EVERREAD"),
    flag(0x2000, "INTERNET"),
    flag(0x8000, "UNTRUSTED"),
];

/// Well-known property set GUIDs, in the on-disk (little-endian) order.
const PROPERTY_SETS: &[(&str, &str)] = &[
    ("{00020328-0000-0000-c000-000000000046}", "PS_MAPI"),
    ("{00020329-0000-0000-c000-000000000046}", "PS_PUBLIC_STRINGS"),
    ("{00062008-0000-0000-c000-000000000046}", "PSETID_Common"),
    ("{00062004-0000-0000-c000-000000000046}", "PSETID_Address"),
    ("{00062002-0000-0000-c000-000000000046}", "PSETID_Appointment"),
    ("{00062003-0000-0000-c000-000000000046}", "PSETID_Task"),
    ("{0006200a-0000-0000-c000-000000000046}", "PSETID_Log"),
    ("{0006200e-0000-0000-c000-000000000046}", "PSETID_Note"),
    ("{00020386-0000-0000-c000-000000000046}", "PS_INTERNET_HEADERS"),
    ("{6ed8da90-450b-101b-98da-00aa003f1305}", "PSETID_Meeting"),
    ("{41f28f13-83f4-4114-a584-eedb5a6b0bff}", "PSETID_Messaging"),
    ("{71035549-0739-4dcb-9163-00f0580dbbdf}", "PSETID_UnifiedMessaging"),
    ("{96357f7f-59e1-47d0-99a7-46515c183b54}", "PSETID_Sharing"),
    ("{00062040-0000-0000-c000-000000000046}", "PSETID_AirSync"),
    ("{23239608-685d-4732-9c55-4c95cb4e8e33}", "PSETID_XmlExtractedEntities"),
    ("{33eba41f-7aa8-422e-be7b-79e1a98e54b3}", "PSETID_CalendarAssistant"),
];

pub fn guid(data: &[u8]) -> Option<Guid> {
    Some(Guid {
        data1: u32_le(data, 0)?,
        data2: u16_le(data, 4)?,
        data3: u16_le(data, 6)?,
        data4: crate::bytes::array(data, 8)?,
    })
}

fn set_name(g: &Guid) -> String {
    let s = g.to_string();
    PROPERTY_SETS
        .iter()
        .find(|(k, _)| *k == s)
        .map_or(s, |(_, n)| (*n).to_owned())
}

/// A named property's identity, from the name-to-ID map.
#[derive(Clone, Debug)]
pub enum Named {
    Id(String, u32),
    Name(String, String),
}

/// The name-to-ID map ([MS-PST] 2.4.7), indexed by `prop_id - 0x8000`.
pub type NameMap = Vec<Option<Named>>;

/// Most named properties resolved (the map can be large).
const MAX_NAMED: usize = 0x8000;

pub async fn name_map(cx: &Cx, pst: &Pst) -> Arc<NameMap> {
    let key = pst.file().sub(0, 0);
    if let Some(found) = cx.cached::<NameMap>(key, "pst-nameid") {
        return found;
    }
    let map = Arc::new(load_name_map(cx, pst).await.unwrap_or_default());
    cx.cache(key, "pst-nameid", map.clone());
    map
}

async fn load_name_map(cx: &Cx, pst: &Pst) -> Result<NameMap> {
    let Some(entry) = ndb::find_node(cx, pst, 0x61).await? else {
        return Ok(Vec::new());
    };
    let node = NodeRef {
        nid: entry.nid,
        data: entry.data,
        sub: entry.sub,
    };
    let pc = ltp::pc(cx, pst, node).await?;
    let mut streams: [Option<Span>; 3] = [None, None, None];
    for p in &pc.props {
        let slot = match p.id {
            0x0002 => 0,
            0x0003 => 1,
            0x0004 => 2,
            _ => continue,
        };
        if let Raw::Data(span) = ltp::prop_value(cx, pst, &pc.heap, p).await?
            && let Some(s) = streams.get_mut(slot)
        {
            *s = Some(span);
        }
    }
    let [Some(guids), Some(entries), strings] = streams else {
        return Ok(Vec::new());
    };
    let guids = cx.read(guids.sub(0, 0x10000)).await?;
    let entries = cx.read(entries.sub(0, to_u64(MAX_NAMED).saturating_mul(8))).await?;
    let strings = match strings {
        Some(s) => cx.read(s.sub(0, 0x100000)).await?,
        None => Vec::new(),
    };
    let mut map: NameMap = Vec::new();
    for e in entries.as_chunks::<8>().0 {
        let value = u32_le(e, 0).unwrap_or(0);
        let flags = u16_le(e, 4).unwrap_or(0);
        let index = usize::from(u16_le(e, 6).unwrap_or(0));
        let set = match flags >> 1 {
            1 => "PS_MAPI".to_owned(),
            2 => "PS_PUBLIC_STRINGS".to_owned(),
            n => {
                let at = usize::from(n).saturating_sub(3).saturating_mul(16);
                guids
                    .get(at..at.saturating_add(16))
                    .and_then(guid)
                    .map_or_else(|| format!("GUID #{n}"), |g| set_name(&g))
            }
        };
        let named = if flags & 1 == 0 {
            Named::Id(set, value)
        } else {
            let at = to_usize(value.into());
            let len = to_usize(u32_le(&strings, at).unwrap_or(0).into());
            let s = strings
                .get(at.saturating_add(4)..at.saturating_add(4).saturating_add(len))
                .map(|b| crate::text::utf16(b, Endian::Little))
                .unwrap_or_default();
            Named::Name(set, s)
        };
        if index < MAX_NAMED {
            if map.len() <= index {
                map.resize(index.saturating_add(1), None);
            }
            if let Some(slot) = map.get_mut(index) {
                *slot = Some(named);
            }
        }
    }
    Ok(map)
}

/// The display name of a property ID.
pub fn name(id: u16, names: &NameMap) -> String {
    if id >= 0x8000 {
        let named = names.get(usize::from(id.saturating_sub(0x8000))).cloned().flatten();
        return match named {
            Some(Named::Id(set, n)) => format!("{set}:{n:#06x}"),
            Some(Named::Name(set, s)) => format!("{set}:{s}"),
            None => format!("Named property {id:#06x}"),
        };
    }
    lookup(NAMES, id.into()).map_or_else(|| format!("Property {id:#06x}"), |n| format!("PidTag{n}"))
}

/// Text values are shown up to this many bytes.
pub const MAX_TEXT: u64 = 0x1000;
/// Binary values are shown inline up to this many bytes.
const MAX_INLINE_BINARY: u64 = 64;

/// Decodes a string property's bytes.
pub fn text(ty: u16, data: &[u8]) -> String {
    let s = if ty & 0x0fff == 0x001f {
        crate::text::utf16(data, Endian::Little)
    } else {
        crate::text::latin1(data)
    };
    s.trim_end_matches('\0').to_owned()
}

/// A property value as a node (named by the caller), with typed value and
/// span; large text and binary values get a child to dissect them.
pub fn value_node(
    pst: &Pst,
    mut node: Node,
    id: u16,
    ty: u16,
    raw: &[u8],
    span: Span,
) -> Node {
    node = node.span(span);
    let (value, summary) = scalar(id, ty, raw);
    if let Some(v) = value {
        node = node.value(v);
    }
    if let Some(s) = summary {
        node = node.summary(s);
    }
    match ty {
        0x001e | 0x001f => {
            if span.len > MAX_TEXT {
                node = node.summary(format!("first 4 KiB of {} bytes", span.len));
            }
        }
        0x0102 | 0x000d if span.len > MAX_INLINE_BINARY => {
            node = node
                .summary(format!("{} bytes", span.len))
                .lazy(crate::formats::dissect_or_data, pst.input.nested(span));
        }
        _ => {}
    }
    node
}

/// Typed value and summary of a scalar property (`raw` holds its bytes,
/// at most [`MAX_TEXT`] of them for variable-size types).
pub fn scalar(id: u16, ty: u16, raw: &[u8]) -> (Option<Value>, Option<String>) {
    let low = u32_le(raw, 0).map(u64::from).unwrap_or(0);
    let wide = u64_le(raw, 0).unwrap_or(0);
    let enumerated = |table: EnumTable, raw: u64| Value::Enum {
        raw,
        bits: 32,
        name: lookup(table, raw),
    };
    let value = match ty {
        0x0002 => Value::Int {
            value: i64::from(u16_le(raw, 0).unwrap_or(0).cast_signed()),
            bits: 16,
        },
        0x0003 => match id {
            0x0017 => enumerated(IMPORTANCE, low),
            0x0036 | 0x002e => enumerated(SENSITIVITY, low),
            0x0c15 => enumerated(RECIPIENT_TYPE, low),
            0x3705 => enumerated(ATTACH_METHOD, low),
            0x0ffe => enumerated(OBJECT_TYPE, low),
            0x0e07 => {
                let (set, unknown) = crate::value::decode_flags(MESSAGE_FLAGS, low);
                Value::Flags {
                    raw: low,
                    bits: 32,
                    set,
                    unknown,
                }
            }
            0x67f2 | 0x67ff => Value::UInt {
                value: low,
                bits: 32,
                radix: Radix::Hex,
            },
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
        0x000a => Value::UInt {
            value: low,
            bits: 32,
            radix: Radix::Hex,
        },
        0x000b => Value::Bool(raw.first().is_some_and(|&b| b != 0)),
        0x0014 => Value::Int {
            value: wide.cast_signed(),
            bits: 64,
        },
        0x0040 => {
            if wide == 0 || wide == 0x7fff_ffff_ffff_ffff {
                return (None, Some("not set".to_owned()));
            }
            Value::Timestamp {
                unix_seconds: crate::text::filetime_to_unix(wide),
            }
        }
        0x0048 => match guid(raw) {
            Some(g) => Value::Guid(g),
            None => return (None, None),
        },
        0x001e | 0x001f => Value::Text(text(ty, raw)),
        0x0102 | 0x000d => {
            if to_u64(raw.len()) <= MAX_INLINE_BINARY {
                Value::Bytes(raw.to_vec())
            } else {
                return (None, None);
            }
        }
        t if t & 0x1000 != 0 => return (None, Some(multi(t, raw))),
        _ => return (None, Some(format!("{} bytes", raw.len()))),
    };
    (Some(value), None)
}

/// A multi-valued property, as a one-line summary.
fn multi(ty: u16, raw: &[u8]) -> String {
    let count = to_usize(u32_le(raw, 0).unwrap_or(0).into());
    let base = ty & 0x0fff;
    if let Some(size) = ltp::fixed_size(base) {
        // Fixed-size elements are stored back to back, without a count.
        let size = to_usize(size).max(1);
        let n = raw.len().checked_div(size).unwrap_or(0);
        let shown: Vec<String> = raw
            .chunks_exact(size)
            .take(16)
            .map(|c| {
                scalar(0, base, c)
                    .0
                    .map_or_else(String::new, |v| crate::render::value(&v))
            })
            .collect();
        return format!("{n} values: {}", shown.join(", "));
    }
    let mut items = Vec::new();
    for i in 0..count.min(16) {
        let at = |k: usize| u32_le(raw, 4usize.saturating_add(k.saturating_mul(4)));
        let Some(start) = at(i) else { break };
        let end = if i.saturating_add(1) < count {
            at(i.saturating_add(1)).unwrap_or(0)
        } else {
            raw.len() as u32
        };
        let item = raw
            .get(to_usize(start.into())..to_usize(end.into()))
            .unwrap_or_default();
        items.push(match base {
            0x001e | 0x001f => format!("{:?}", text(base, item)),
            _ => format!("{} bytes", item.len()),
        });
    }
    format!("{count} values: {}", items.join(", "))
}

/// Reads a property's bytes (inline or from the heap or a subnode), up
/// to [`MAX_TEXT`].
pub async fn read_raw(cx: &Cx, raw: &Raw) -> Result<(Vec<u8>, Span)> {
    match *raw {
        Raw::Inline(v, span) => Ok((v.to_le_bytes().to_vec(), span)),
        Raw::Data(span) => Ok((cx.read_avail(span.sub(0, MAX_TEXT)).await?, span)),
    }
}
