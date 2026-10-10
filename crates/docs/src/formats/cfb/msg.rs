//! Outlook messages ([MS-OXMSG]): the `__properties_version1.0` streams of
//! the message, its recipients and attachments (fixed-size values inline,
//! sizes of the others), the `__substg1.0_` value streams decoded by
//! property type, compressed RTF bodies, and the named property mapping in
//! `__nameid_version1.0` that gives properties 0x8000 and above their names.

use std::sync::Arc;

use super::CfbRef;
use super::rec::LE;
use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::Input;
use crate::formats::util::mapi::{self, Named, TYPES, guid, set_label, set_name};
use crate::formats::util::val::{hex, uint};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const PROP_FLAGS: FlagTable = &[
    flag(0x1, "PROPATTR_MANDATORY"),
    flag(0x2, "PROPATTR_READABLE"),
    flag(0x4, "PROPATTR_WRITABLE"),
];

/// The named property map, indexed by `prop_id - 0x8000`.
#[derive(Default, Debug)]
pub struct NameMap {
    pub names: Vec<Option<Named>>,
}

/// The display name of a property ID.
pub fn property_name(id: u16, names: &NameMap) -> String {
    mapi::property_name(id, &names.names)
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
            Err(mapi::name_string(&strings, a).unwrap_or_else(|| format!("string at {a:#x}")))
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
        let fixed = mapi::is_fixed(ty);
        let mut node = Node::new(name).span(entry);
        if fixed {
            let (value, detail) = mapi::fixed_scalar(id, ty, raw);
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
                    match mapi::fixed_scalar(id, base, c).0 {
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
                let padded = to_usize(crate::bytes::align_up(to_u64(end), 4));
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
