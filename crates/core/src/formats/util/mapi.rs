//! MAPI property tags shared by Outlook message files (`.msg`, in
//! compound files) and Personal Storage Tables (`.pst`): tagged property
//! names ([MS-OXPROPS]), property types ([MS-OXCDATA] 2.11.1), the
//! enumerations and flags of common properties, the well-known named
//! property sets, and the decoding of fixed-size property values.

use crate::bytes::{to_usize, u16_le, u32_le, u64_le};
use crate::formats::util::datakit::{enumv, hex, uint};
use crate::value::{EnumTable, FlagTable, Guid, Value, decode_flags, flag, lookup};

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

pub const IMPORTANCE: EnumTable = &[(0, "Low"), (1, "Normal"), (2, "High")];
pub const SENSITIVITY: EnumTable = &[
    (0, "Normal"),
    (1, "Personal"),
    (2, "Private"),
    (3, "Confidential"),
];
pub const RECIPIENT_TYPE: EnumTable = &[(0, "Originator"), (1, "To"), (2, "Cc"), (3, "Bcc")];
pub const ATTACH_METHOD: EnumTable = &[
    (0, "None"),
    (1, "By value"),
    (2, "By reference"),
    (4, "By reference only"),
    (5, "Embedded message"),
    (6, "OLE storage"),
    (7, "By web reference"),
];
pub const OBJECT_TYPE: EnumTable = &[
    (1, "Store"),
    (2, "Address book"),
    (3, "Folder"),
    (4, "Address book container"),
    (5, "Message"),
    (6, "Mail user"),
    (7, "Attachment"),
    (8, "Distribution list"),
];
/// `PidTagMessageFlags` ([MS-OXCMSG] 2.2.1.6).
pub const MESSAGE_FLAGS: FlagTable = &[
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
/// `PidTagMessageEditorFormat`.
pub const EDITOR_FORMAT: EnumTable = &[(0, "unknown"), (1, "plain text"), (2, "HTML"), (3, "RTF")];

/// Well-known property set GUIDs ([MS-OXPROPS] 1.3.2).
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

/// A GUID stored in its on-disk (little-endian) layout at `at`.
pub fn guid(data: &[u8], at: usize) -> Option<Guid> {
    Some(Guid {
        data1: u32_le(data, at)?,
        data2: u16_le(data, at.checked_add(4)?)?,
        data3: u16_le(data, at.checked_add(6)?)?,
        data4: crate::bytes::array(data, at.checked_add(8)?)?,
    })
}

/// The name of a well-known property set, or the GUID itself.
pub fn set_name(g: &Guid) -> String {
    let s = g.to_string();
    PROPERTY_SETS
        .iter()
        .find(|(k, _)| *k == s)
        .map_or(s, |(_, n)| (*n).to_owned())
}

/// The property set of a name-to-ID map entry: index 1 is PS_MAPI, 2 is
/// PS_PUBLIC_STRINGS, and 3 onwards index the GUID stream
/// ([MS-OXMSG] 2.2.3.1.2, [MS-PST] 2.4.7.1).
pub fn set_label(index: u16, guids: &[u8]) -> String {
    match index {
        1 => "PS_MAPI".to_owned(),
        2 => "PS_PUBLIC_STRINGS".to_owned(),
        n => guid(guids, usize::from(n.saturating_sub(3)).saturating_mul(16))
            .map_or_else(|| format!("GUID #{n}"), |g| set_name(&g)),
    }
}

/// A property name in a name-to-ID map's string stream: a 32-bit byte
/// count, then UTF-16LE.
pub fn name_string(strings: &[u8], at: u32) -> Option<String> {
    let at = to_usize(at.into());
    let len = to_usize(u32_le(strings, at)?.into());
    let start = at.checked_add(4)?;
    let raw = strings.get(start..start.checked_add(len)?)?;
    Some(crate::text::utf16(raw, crate::fields::Endian::Little))
}

/// A named property's identity: its property set, and its number (`Ok`)
/// or string name (`Err`).
#[derive(Clone, Debug)]
pub struct Named {
    pub set: String,
    pub id: Result<u32, String>,
}

/// The display name of a property ID; IDs 0x8000 and above are looked up
/// in `named`, indexed by `id - 0x8000`.
pub fn property_name(id: u16, named: &[Option<Named>]) -> String {
    if id >= 0x8000 {
        return match named.get(usize::from(id.saturating_sub(0x8000))) {
            Some(Some(Named { set, id: Ok(n) })) => format!("{set}:{n:#06x}"),
            Some(Some(Named { set, id: Err(s) })) => format!("{set}:{s}"),
            _ => format!("Named property {id:#06x}"),
        };
    }
    lookup(NAMES, id.into()).map_or_else(|| format!("Property {id:#06x}"), |n| format!("PidTag{n}"))
}

/// Whether a property type is stored inline in 8 bytes or fewer.
pub fn is_fixed(ty: u16) -> bool {
    matches!(ty, 0x0002..=0x0007 | 0x000a | 0x000b | 0x0014 | 0x0040)
}

/// The typed value of a fixed-size property ([`is_fixed`]; `raw` holds
/// its bytes), and a detail for the summary. Other types give nothing.
pub fn fixed_scalar(id: u16, ty: u16, raw: &[u8]) -> (Option<Value>, Option<String>) {
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
            0x0e07 => {
                let (set, unknown) = decode_flags(MESSAGE_FLAGS, low);
                Value::Flags {
                    raw: low,
                    bits: 32,
                    set,
                    unknown,
                }
            }
            0x3fde | 0x3ffd | 0x3fd9 => {
                return (Some(uint(low, 32)), Some("code page".to_owned()));
            }
            0x3ff1 | 0x3a0c | 0x6705 => {
                return (
                    Some(hex(low, 32)),
                    Some(crate::formats::util::lcid::describe(
                        u32::try_from(low).unwrap_or(0),
                    )),
                );
            }
            0x67f2 | 0x67ff => hex(low, 32),
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
