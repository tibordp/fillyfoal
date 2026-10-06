//! What the compound file is used for: recognising the application,
//! naming entries (MSI's encoded stream names, Outlook's property streams),
//! and choosing a decoder for each stream.

use super::{
    Cfb, DirEntry, StreamState, TreeWalk, display_name, entry_name, office, propset, read_entry,
};
use crate::bytes::{u32_le, u64_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::Input;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Guid, Radix, Value, lookup};

/// What kind of storage a stream lives in, which decides how entries are
/// named and decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    Plain,
    Msi,
    /// The top level of an Outlook message.
    MsgRoot,
    /// A recipient, attachment or embedded message storage.
    Msg,
    Thumbs,
}

impl Context {
    pub fn child(parent: Context, _name: &str) -> Context {
        match parent {
            Context::MsgRoot | Context::Msg => Context::Msg,
            other => other,
        }
    }
}

/// The Windows Installer CLSIDs of the root storage.
pub fn installer_kind(clsid: &[u8; 16]) -> Option<&'static str> {
    const TAIL: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    if clsid.get(4..) != Some(&TAIL[..]) {
        return None;
    }
    match u32_le(clsid, 0)? {
        0x000c_1084 => Some("Windows Installer package"),
        0x000c_1086 => Some("Windows Installer patch"),
        0x000c_1082 => Some("Windows Installer transform"),
        _ => None,
    }
}

fn guid_bytes(g: &Guid) -> [u8; 16] {
    let mut out = [0u8; 16];
    let d1 = g.data1.to_le_bytes();
    let d2 = g.data2.to_le_bytes();
    let d3 = g.data3.to_le_bytes();
    for (slot, b) in out
        .iter_mut()
        .zip(d1.iter().chain(&d2).chain(&d3).chain(&g.data4))
    {
        *slot = *b;
    }
    out
}

/// Recognises the application from the root storage, and finds a title.
pub async fn application(cx: &Cx, cfb: &Cfb, root: &DirEntry) -> (Option<String>, Context) {
    if let Some(kind) = installer_kind(&guid_bytes(&root.clsid)) {
        let title = summary_title(cx, cfb, root).await;
        return (Some(with_title(kind, title)), Context::Msi);
    }
    let mut names = Vec::new();
    let mut walk = TreeWalk::new(root.child);
    while let Some((id, entry)) = walk.next(cx, cfb).await {
        names.push((entry_name(&entry), id));
        if names.len() >= super::MAX_ROOT_SCAN {
            break;
        }
    }
    let has = |n: &str| names.iter().any(|(name, _)| name == n);
    let (kind, context) = if has("WordDocument") {
        ("Word 97-2003 document", Context::Plain)
    } else if has("Workbook") {
        ("Excel 97-2003 workbook", Context::Plain)
    } else if has("Book") {
        ("Excel 5.0/95 workbook", Context::Plain)
    } else if has("PowerPoint Document") {
        ("PowerPoint 97-2003 presentation", Context::Plain)
    } else if has("__properties_version1.0") || has("__nameid_version1.0") {
        ("Outlook message", Context::MsgRoot)
    } else if has("Catalog") {
        ("Thumbs.db thumbnail cache", Context::Thumbs)
    } else if has("VisioDocument") {
        ("Visio drawing", Context::Plain)
    } else if has("Quill") {
        ("Publisher document", Context::Plain)
    } else if has("\u{1}Ole10Native") {
        ("OLE 1.0 embedded object", Context::Plain)
    } else {
        return (None, Context::Plain);
    };
    let title = if context == Context::MsgRoot {
        let subject = names.iter().find(|(n, _)| n == "__substg1.0_0037001F");
        match subject {
            Some(&(_, id)) => stream_text(cx, cfb, id).await,
            None => None,
        }
    } else {
        summary_title(cx, cfb, root).await
    };
    (Some(with_title(kind, title)), context)
}

fn with_title(kind: &str, title: Option<String>) -> String {
    match title {
        Some(t) if !t.is_empty() => format!("{kind} {t:?}"),
        _ => kind.to_owned(),
    }
}

/// The title from the root's `\x05SummaryInformation`, if any.
async fn summary_title(cx: &Cx, cfb: &Cfb, root: &DirEntry) -> Option<String> {
    let mut walk = TreeWalk::new(root.child);
    let mut scanned = 0usize;
    while let Some((id, entry)) = walk.next(cx, cfb).await {
        scanned = scanned.saturating_add(1);
        if scanned > super::MAX_ROOT_SCAN {
            return None;
        }
        if entry_name(&entry) == "\u{5}SummaryInformation" {
            let (span, _) = super::stream(cx, cfb, id, &entry).await.ok()?;
            return propset::title(cx, span).await;
        }
    }
    None
}

async fn stream_text(cx: &Cx, cfb: &Cfb, id: u32) -> Option<String> {
    let entry = read_entry(cx, cfb, id).await.ok()?;
    let (span, _) = super::stream(cx, cfb, id, &entry).await.ok()?;
    let data = cx.read_avail(span.sub(0, 1024)).await.ok()?;
    Some(crate::text::utf16z(&data, Endian::Little).0)
}

/// MSI stream names pack two base-64 characters into one code point
/// (U+3800..U+47FF), one into U+4800..U+483F, and mark tables with U+4840.
pub fn msi_name(raw: &str) -> Option<String> {
    const ALPHABET: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
    let b64 = |v: u32| {
        usize::try_from(v & 0x3f)
            .ok()
            .and_then(|i| ALPHABET.get(i))
            .map_or('?', |&c| char::from(c))
    };
    if !raw.chars().any(|c| ('\u{3800}'..='\u{4840}').contains(&c)) {
        return None;
    }
    let mut out = String::new();
    for c in raw.chars() {
        let u = u32::from(c);
        match u {
            0x3800..0x4800 => {
                let v = u.saturating_sub(0x3800);
                out.push(b64(v));
                out.push(b64(v >> 6));
            }
            0x4800..0x4840 => out.push(b64(u.saturating_sub(0x4800))),
            0x4840 => out.push('!'),
            _ => out.push(c),
        }
    }
    Some(out)
}

/// A display label for an entry, and a short description.
pub fn label(raw: &str, context: Context) -> (String, Option<String>) {
    if context == Context::Msi
        && let Some(name) = msi_name(raw)
    {
        return match name.strip_prefix('!') {
            Some(table) => (table.to_owned(), Some("MSI table".to_owned())),
            None => (name, None),
        };
    }
    if matches!(context, Context::MsgRoot | Context::Msg) {
        for (prefix, label) in [
            ("__recip_version1.0_#", "Recipient"),
            ("__attach_version1.0_#", "Attachment"),
        ] {
            if let Some(n) = raw.strip_prefix(prefix) {
                let index = u32::from_str_radix(n, 16).unwrap_or(0);
                return (
                    format!("{label} {index}"),
                    Some(format!("{} storage", label.to_lowercase())),
                );
            }
        }
        match raw {
            "__substg1.0_00020102" => {
                return (
                    "GUID stream".to_owned(),
                    Some("named property GUIDs".to_owned()),
                );
            }
            "__substg1.0_00030102" => {
                return (
                    "Entry stream".to_owned(),
                    Some("named property entries".to_owned()),
                );
            }
            "__substg1.0_00040102" => {
                return (
                    "String stream".to_owned(),
                    Some("named property names".to_owned()),
                );
            }
            "__nameid_version1.0" => {
                return (
                    "Named property mapping".to_owned(),
                    Some("storage".to_owned()),
                );
            }
            "__properties_version1.0" => {
                return (
                    "Properties".to_owned(),
                    Some("fixed-size property values".to_owned()),
                );
            }
            "__substg1.0_3701000D" => {
                return ("Embedded message".to_owned(), Some("storage".to_owned()));
            }
            _ => {}
        }
        if let Some((id, kind)) = msg_tag(raw) {
            let name = lookup(MSG_PROPERTIES, id.into())
                .map_or_else(|| format!("Property {id:#06x}"), |n| format!("PidTag{n}"));
            let kind = lookup(MSG_TYPES, kind.into())
                .map_or_else(|| format!("type {kind:#06x}"), str::to_owned);
            return (name, Some(format!("property {id:#06x}, {kind}")));
        }
    }
    let detail = match raw {
        "\u{5}SummaryInformation" => Some("summary information property set"),
        "\u{5}DocumentSummaryInformation" => Some("document summary property set"),
        "WordDocument" => Some("Word document stream"),
        "0Table" | "1Table" => Some("Word table stream"),
        "Workbook" => Some("Excel BIFF8 workbook stream"),
        "Book" => Some("Excel BIFF5 workbook stream"),
        "PowerPoint Document" => Some("PowerPoint document stream"),
        "Current User" => Some("PowerPoint current user"),
        "Pictures" => Some("embedded pictures"),
        "\u{1}CompObj" => Some("OLE class information"),
        "\u{1}Ole" => Some("OLE object information"),
        "\u{1}Ole10Native" => Some("OLE 1.0 native data"),
        "Macros" | "_VBA_PROJECT_CUR" | "VBA" => Some("VBA project"),
        "ObjectPool" => Some("embedded objects"),
        "Catalog" => Some("thumbnail catalog"),
        _ => None,
    };
    (display_name(raw), detail.map(str::to_owned))
}

/// `__substg1.0_XXXXYYYY`: property id and type.
fn msg_tag(raw: &str) -> Option<(u16, u16)> {
    let hex = raw.strip_prefix("__substg1.0_")?;
    if hex.len() != 8 {
        return None;
    }
    let tag = u32::from_str_radix(hex, 16).ok()?;
    Some(((tag >> 16) as u16, (tag & 0xffff) as u16))
}

const MSG_TYPES: EnumTable = &[
    (0x0002, "PT_SHORT"),
    (0x0003, "PT_LONG"),
    (0x0004, "PT_FLOAT"),
    (0x0005, "PT_DOUBLE"),
    (0x0006, "PT_CURRENCY"),
    (0x0007, "PT_APPTIME"),
    (0x000a, "PT_ERROR"),
    (0x000b, "PT_BOOLEAN"),
    (0x000d, "PT_OBJECT"),
    (0x0014, "PT_I8"),
    (0x001e, "PT_STRING8"),
    (0x001f, "PT_UNICODE"),
    (0x0040, "PT_SYSTIME"),
    (0x0048, "PT_CLSID"),
    (0x0102, "PT_BINARY"),
    (0x1003, "PT_MV_LONG"),
    (0x101e, "PT_MV_STRING8"),
    (0x101f, "PT_MV_UNICODE"),
    (0x1102, "PT_MV_BINARY"),
];

const MSG_PROPERTIES: EnumTable = &[
    (0x0017, "Importance"),
    (0x001a, "MessageClass"),
    (0x0026, "Priority"),
    (0x0036, "Sensitivity"),
    (0x0037, "Subject"),
    (0x0039, "ClientSubmitTime"),
    (0x003d, "SubjectPrefix"),
    (0x0042, "SentRepresentingName"),
    (0x0064, "SentRepresentingAddressType"),
    (0x0065, "SentRepresentingEmailAddress"),
    (0x0070, "ConversationTopic"),
    (0x0071, "ConversationIndex"),
    (0x007d, "TransportMessageHeaders"),
    (0x0c15, "RecipientType"),
    (0x0c1a, "SenderName"),
    (0x0c1e, "SenderAddressType"),
    (0x0c1f, "SenderEmailAddress"),
    (0x0e02, "DisplayBcc"),
    (0x0e03, "DisplayCc"),
    (0x0e04, "DisplayTo"),
    (0x0e06, "MessageDeliveryTime"),
    (0x0e07, "MessageFlags"),
    (0x0e08, "MessageSize"),
    (0x0e17, "MessageStatus"),
    (0x0e1b, "HasAttachments"),
    (0x0e1d, "NormalizedSubject"),
    (0x0ff9, "RecordKey"),
    (0x0fff, "EntryId"),
    (0x1000, "Body"),
    (0x1009, "RtfCompressed"),
    (0x1013, "BodyHtml"),
    (0x1035, "InternetMessageId"),
    (0x3001, "DisplayName"),
    (0x3002, "AddressType"),
    (0x3003, "EmailAddress"),
    (0x3007, "CreationTime"),
    (0x3008, "LastModificationTime"),
    (0x300b, "SearchKey"),
    (0x3701, "AttachDataBinary"),
    (0x3703, "AttachExtension"),
    (0x3704, "AttachFilename"),
    (0x3705, "AttachMethod"),
    (0x3707, "AttachLongFilename"),
    (0x370e, "AttachMimeTag"),
    (0x3712, "AttachContentId"),
    (0x39fe, "SmtpAddress"),
    (0x3a00, "Account"),
    (0x3fde, "InternetCodepage"),
    (0x3ff1, "MessageLocaleId"),
    (0x3ffa, "LastModifierName"),
    (0x5d01, "SenderSmtpAddress"),
    (0x5d02, "SentRepresentingSmtpAddress"),
];

/// Emits the decoded content of a stream.
pub async fn content(cx: &Cx, state: &StreamState, span: Span) -> Result<()> {
    let input = state.cfb.input;
    let name = state.name.as_str();
    match (state.context, name) {
        (_, n) if n.starts_with('\u{5}') => propset::emit(cx, span).await,
        (Context::Plain, "WordDocument") => office::word(cx, span).await,
        (Context::Plain, "Workbook" | "Book") => office::biff(cx, span).await,
        (Context::Plain, "PowerPoint Document" | "Current User") => office::ppt(cx, span).await,
        (Context::MsgRoot | Context::Msg, "__properties_version1.0") => {
            msg_properties(cx, span, state.context == Context::MsgRoot).await
        }
        (Context::MsgRoot | Context::Msg, n) if msg_tag(n).is_some() => {
            msg_value(cx, input, n, span).await
        }
        (Context::Thumbs, "Catalog") => thumbs_catalog(cx, span).await,
        (Context::Thumbs, n) if n.chars().all(|c| c.is_ascii_digit()) => {
            thumbnail(cx, input, span).await
        }
        _ => {
            cx.emit(raw_content(input, span));
            Ok(())
        }
    }
}

/// The stream's bytes, identified and dissected on expansion.
fn raw_content(input: Input, span: Span) -> Node {
    Node::new("Content")
        .span(span)
        .summary(format!("{} bytes", span.len))
        .lazy(crate::formats::dissect_or_data, input.nested(span))
}

async fn msg_value(cx: &Cx, input: Input, name: &str, span: Span) -> Result<()> {
    let Some((_, kind)) = msg_tag(name) else {
        return Ok(());
    };
    match kind {
        0x001f | 0x001e => {
            let data = cx.read_avail(span.sub(0, 0x10000)).await?;
            let text = if kind == 0x001f {
                crate::text::utf16(&data, Endian::Little)
            } else {
                String::from_utf8_lossy(&data).into_owned()
            };
            let text = text.trim_end_matches('\0').to_owned();
            let mut node = Node::new("Value").span(span).value(Value::Text(text));
            if span.len > 0x10000 {
                node = node.summary(format!("first 64 KiB of {} bytes", span.len));
            }
            cx.emit(node);
        }
        _ => cx.emit(raw_content(input, span)),
    }
    Ok(())
}

/// The fixed-size property records of `__properties_version1.0`.
async fn msg_properties(cx: &Cx, span: Span, top: bool) -> Result<()> {
    let header = if top { 32 } else { 8 };
    cx.emit(Node::new("Header").span(span.sub(0, header)));
    let mut at = header;
    while at.saturating_add(16) <= span.len {
        let record = span.sub(at, 16);
        let data = cx.read(record).await?;
        let tag = u32_le(&data, 0).unwrap_or(0);
        let (id, kind) = ((tag >> 16) as u16, (tag & 0xffff) as u16);
        let raw = u64_le(&data, 8).unwrap_or(0);
        let name = lookup(MSG_PROPERTIES, id.into())
            .map_or_else(|| format!("Property {id:#06x}"), |n| format!("PidTag{n}"));
        let type_name = lookup(MSG_TYPES, kind.into()).unwrap_or("unknown type");
        let low = raw & 0xffff_ffff;
        let (value, detail) = match kind {
            0x0002 => (
                Value::Int {
                    value: i64::from(low as u16 as i16),
                    bits: 16,
                },
                None,
            ),
            0x0003 => (
                Value::Int {
                    value: i64::from(low as u32 as i32),
                    bits: 32,
                },
                None,
            ),
            0x000b => (Value::Bool(low & 0xffff != 0), None),
            0x0014 => (
                Value::Int {
                    value: raw.cast_signed(),
                    bits: 64,
                },
                None,
            ),
            0x0040 => (
                Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(raw),
                },
                None,
            ),
            0x0005 => (Value::Float(f64::from_bits(raw)), None),
            _ => (
                Value::UInt {
                    value: low,
                    bits: 32,
                    radix: Radix::Dec,
                },
                Some("size of the value stream"),
            ),
        };
        let summary = match detail {
            Some(d) => format!("{type_name}, {d}"),
            None => type_name.to_owned(),
        };
        cx.push(Node::new(name).span(record).value(value).summary(summary))
            .await;
        at = at.saturating_add(16);
    }
    Ok(())
}

async fn thumbs_catalog(cx: &Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub(0, 16)).await?;
    let header_len = u64::from(crate::bytes::u16_le(&head, 0).unwrap_or(16)).max(16);
    let count = u32_le(&head, 4).unwrap_or(0);
    let width = u32_le(&head, 8).unwrap_or(0);
    let height = u32_le(&head, 12).unwrap_or(0);
    cx.emit(
        Node::new("Catalog header")
            .span(span.sub(0, header_len))
            .summary(format!("{count} thumbnails, {width}×{height}")),
    );
    let mut at = header_len;
    let mut seen = 0u32;
    while at.saturating_add(16) <= span.len && seen < count {
        let head = cx.read(span.sub(at, 16)).await?;
        let len = u64::from(u32_le(&head, 0).unwrap_or(0));
        if len < 16 {
            break;
        }
        let index = u32_le(&head, 4).unwrap_or(0);
        let time = u64_le(&head, 8).unwrap_or(0);
        let entry = span.sub(at, len);
        let name = cx.read_avail(entry.sub(16, len.saturating_sub(16))).await?;
        let name = crate::text::utf16z(&name, Endian::Little).0;
        let stream: String = index.to_string().chars().rev().collect();
        cx.push(
            Node::new(name)
                .span(entry)
                .value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(time),
                })
                .summary(format!("thumbnail {index} (stream \"{stream}\")")),
        )
        .await;
        at = at.saturating_add(len);
        seen = seen.saturating_add(1);
    }
    Ok(())
}

async fn thumbnail(cx: &Cx, input: Input, span: Span) -> Result<()> {
    let head = cx.read_avail(span.sub(0, 12)).await?;
    let header = u64::from(u32_le(&head, 0).unwrap_or(0));
    if !(12..=64).contains(&header) {
        cx.emit(raw_content(input, span));
        return Ok(());
    }
    cx.emit(Node::new("Thumbnail header").span(span.sub(0, header)));
    let image = span.tail(header);
    cx.emit(raw_content(input, image).summary(format!("image, {} bytes", image.len)));
    Ok(())
}
