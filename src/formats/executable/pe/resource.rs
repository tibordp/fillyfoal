//! Typed Win32 resource data, shared by PE resource directories and
//! compiled resource files (`.res`).
//!
//! Each `RT_*` type has its own layout (from the Windows SDK documentation of
//! `GRPICONDIR`, `ACCELTABLEENTRY`, `MESSAGE_RESOURCE_DATA`, string table
//! blocks and menu templates): icons and cursors are bare DIBs (or PNG
//! streams) without a file header, groups list them by resource ID, string
//! tables hold 16 counted UTF-16 strings, and so on. Types without a layout
//! of their own (`RT_RCDATA`, `RT_HTML`, `RT_MANIFEST`, custom types) are
//! handed to format detection, which also finds Delphi forms (`TPF0`) in
//! `RT_RCDATA`.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::image::{bmp, dims};
use crate::formats::util::lines::flags as flag_value;
use crate::formats::{Input, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

use super::version;

const LE: Endian = Endian::Little;
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";

pub const RT_CURSOR: u32 = 1;
pub const RT_BITMAP: u32 = 2;
pub const RT_ICON: u32 = 3;
pub const RT_MENU: u32 = 4;
pub const RT_DIALOG: u32 = 5;
pub const RT_STRING: u32 = 6;
pub const RT_RCDATA: u32 = 10;
pub const RT_ACCELERATOR: u32 = 9;
pub const RT_MESSAGETABLE: u32 = 11;
pub const RT_GROUP_CURSOR: u32 = 12;
pub const RT_GROUP_ICON: u32 = 14;
pub const RT_VERSION: u32 = 16;

/// A node for the data of one resource of type `kind` (an `RT_*` ordinal,
/// `None` for a named type) and ordinal name `name`, found at `span` in
/// `input`. Reads at most a few bytes, for the summary.
pub async fn content(
    cx: &Cx,
    input: Input,
    span: Span,
    kind: Option<u32>,
    name: Option<u32>,
) -> Node {
    match node(cx, input, span, kind, name).await {
        Ok(node) => node,
        Err(e) => embedded("Content", input.nested(span))
            .summary(format!("{:#x} bytes", span.len))
            .diag(e),
    }
}

async fn node(
    cx: &Cx,
    input: Input,
    span: Span,
    kind: Option<u32>,
    name: Option<u32>,
) -> Result<Node> {
    Ok(match kind {
        Some(RT_ICON) => image_node(cx, input, span, false).await?,
        Some(RT_CURSOR) => image_node(cx, input, span, true).await?,
        Some(RT_BITMAP) => {
            let head = cx.read_avail(span.sub(0, 16)).await?;
            let mut node = Node::new("Bitmap (DIB)")
                .span(span)
                .lazy(bitmap, (input, span));
            if let Some(s) = dib_summary(&head, false) {
                node = node.summary(s);
            }
            node
        }
        Some(RT_GROUP_ICON | RT_GROUP_CURSOR) => {
            let cursor = kind == Some(RT_GROUP_CURSOR);
            let head = cx.read_avail(span.sub(0, 6)).await?;
            let count = u16_le(&head, 4).unwrap_or(0);
            let what = if cursor { "Cursor group" } else { "Icon group" };
            Node::new(what)
                .span(span)
                .summary(format!(
                    "{count} image{}",
                    if count == 1 { "" } else { "s" }
                ))
                .lazy(group, (span, cursor))
        }
        Some(RT_VERSION) => {
            let node = Node::new("Version Info")
                .span(span)
                .lazy(version::block, span);
            match version::summary(cx, span).await {
                Ok(summary) => node.summary(summary),
                Err(e) => node.diag(e),
            }
        }
        Some(RT_STRING) => {
            let mut node = Node::new("String table")
                .span(span)
                .lazy(strings, (span, name));
            if let Some(block) = name {
                let first = block.saturating_sub(1).saturating_mul(16);
                node = node.summary(format!("strings {first}–{}", first.saturating_add(15)));
            }
            node
        }
        Some(RT_ACCELERATOR) => Node::new("Accelerator table")
            .span(span)
            .summary(format!("{} entries", span.len / 8))
            .lazy(accelerators, span),
        Some(RT_MESSAGETABLE) => {
            let head = cx.read_avail(span.sub(0, 4)).await?;
            let blocks = u32_le(&head, 0).unwrap_or(0);
            Node::new("Message table")
                .span(span)
                .summary(format!("{blocks} blocks"))
                .lazy(messages, span)
        }
        Some(RT_DIALOG) => {
            let head = cx.read_avail(span.sub(0, 18)).await?;
            let ex = u16_le(&head, 2) == Some(0xffff);
            let count = if ex {
                u16_le(&head, 16)
            } else {
                u16_le(&head, 8)
            }
            .unwrap_or(0);
            Node::new(if ex {
                "Dialog template (DLGTEMPLATEEX)"
            } else {
                "Dialog template"
            })
            .span(span)
            .summary(format!("{count} controls"))
            .lazy(dialog, (span, ex))
        }
        Some(RT_MENU) => {
            let head = cx.read_avail(span.sub(0, 4)).await?;
            if u16_le(&head, 0) == Some(0) {
                Node::new("Menu template").span(span).lazy(menu, span)
            } else {
                Node::new("Menu template (MENUEX)")
                    .span(span)
                    .lazy(menu_ex, span)
            }
        }
        Some(RT_RCDATA) if cx.read_avail(span.sub(0, 4)).await? == b"TPF0" => embedded_as(
            "Delphi form",
            input.nested(span),
            &crate::formats::system::delphi::DFM,
        )
        .summary(format!("TPF0 stream, {:#x} bytes", span.len)),
        _ => embedded("Content", input.nested(span)).summary(format!("{:#x} bytes", span.len)),
    })
}

/// "16×16, 32-bit" from the start of a `BITMAPINFOHEADER` (`icon`: the
/// height counts the XOR image and the AND mask).
fn dib_summary(head: &[u8], icon: bool) -> Option<String> {
    let size = u32_le(head, 0)?;
    if size == 12 {
        let w = u16_le(head, 4)?;
        let h = u16_le(head, 6)?;
        let bits = u16_le(head, 10)?;
        let h = if icon { h / 2 } else { h };
        return Some(format!("{}, {bits}-bit", dims(w, h)));
    }
    if !(16..=124).contains(&size) {
        return None;
    }
    let w = i32::from_le_bytes(head.get(4..8)?.try_into().ok()?);
    let h = i32::from_le_bytes(head.get(8..12)?.try_into().ok()?);
    let bits = u16_le(head, 14)?;
    let h = h.unsigned_abs();
    let h = if icon { h / 2 } else { h };
    Some(format!("{}, {bits}-bit", dims(w.unsigned_abs(), h)))
}

async fn image_node(cx: &Cx, input: Input, span: Span, cursor: bool) -> Result<Node> {
    let skip: u64 = if cursor { 4 } else { 0 };
    let head = cx.read_avail(span.sub(0, skip.saturating_add(16))).await?;
    let pixels = head
        .get(usize::from(cursor).saturating_mul(4)..)
        .unwrap_or_default();
    let what = if cursor { "Cursor image" } else { "Icon image" };
    let mut summary = if pixels.starts_with(PNG) {
        "PNG".to_owned()
    } else {
        dib_summary(pixels, true).unwrap_or_else(|| "DIB".to_owned())
    };
    if cursor && let (Some(x), Some(y)) = (u16_le(&head, 0), u16_le(&head, 2)) {
        summary = format!("{summary}, hotspot ({x}, {y})");
    }
    Ok(Node::new(what)
        .span(span)
        .summary(summary)
        .lazy(image, (input, span, cursor)))
}

async fn image(cx: Cx, (input, span, cursor): (Input, Span, bool)) -> Result<()> {
    let body = if cursor {
        let block = cx.block(span.sub(0, 4)).await?;
        let mut f = Fields::emitting(&cx, &block, LE);
        f.u16("Hotspot x").emit()?;
        f.u16("Hotspot y").emit()?;
        span.tail(4)
    } else {
        span
    };
    let magic = cx.read_avail(body.sub(0, 8)).await?;
    if magic == PNG {
        cx.emit(embedded("PNG image", input.nested(body)));
    } else {
        bmp::dib(&cx, input, body, None, true).await?;
    }
    Ok(())
}

async fn bitmap(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    bmp::dib(&cx, input, span, None, false).await?;
    Ok(())
}

/// `GRPICONDIR` / cursor directory: header, then 14-byte entries naming
/// the `RT_ICON` / `RT_CURSOR` resources by ID.
async fn group(cx: Cx, (span, cursor): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u16("idReserved").emit()?;
    f.u16("idType").desc("1 = icon, 2 = cursor").emit()?;
    let count = f.u16("idCount").emit()?;
    cx.set_count(Count::Exact(u64::from(count).saturating_add(3)));
    for index in 0..count {
        let at = 6u64.saturating_add(u64::from(index).saturating_mul(14));
        let entry = span.sub(at, 14);
        let data = block
            .data
            .get(crate::bytes::to_usize(at)..)
            .unwrap_or_default();
        let mut node = Node::new(format!("Entry {index}"))
            .span(entry)
            .lazy(group_entry, (entry, cursor));
        if data.len() >= 14 {
            let (w, h, bits) = if cursor {
                (
                    u32::from(u16_le(data, 0).unwrap_or(0)),
                    u32::from(u16_le(data, 2).unwrap_or(0) / 2),
                    u16_le(data, 6).unwrap_or(0),
                )
            } else {
                let side = |v: u8| if v == 0 { 256u32 } else { v.into() };
                (
                    side(data.first().copied().unwrap_or(0)),
                    side(data.get(1).copied().unwrap_or(0)),
                    u16_le(data, 6).unwrap_or(0),
                )
            };
            let size = u32_le(data, 8).unwrap_or(0);
            let id = u16_le(data, 12).unwrap_or(0);
            node = node.summary(format!(
                "{}, {bits}-bit, {size:#x} bytes, resource #{id}",
                dims(w, h)
            ));
        } else {
            node = node.diag(Diagnostic::truncated(entry, to_u64(data.len())));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn group_entry(cx: Cx, (span, cursor): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    if cursor {
        f.u16("wWidth").emit()?;
        f.u16("wHeight")
            .desc("Twice the height (image and mask)")
            .emit()?;
    } else {
        f.u8("bWidth").desc("0 means 256").emit()?;
        f.u8("bHeight").desc("0 means 256").emit()?;
        f.u8("bColorCount").emit()?;
        f.u8("bReserved").emit()?;
    }
    f.u16("wPlanes").emit()?;
    f.u16("wBitCount").emit()?;
    f.u32("dwBytesInRes").hex().emit()?;
    f.u16("nId").desc("ID of the image resource").emit()?;
    Ok(())
}

/// A string table block: 16 counted UTF-16 strings; block `n` holds the
/// strings with IDs `(n - 1) * 16` to `(n - 1) * 16 + 15`.
async fn strings(cx: Cx, (span, name): (Span, Option<u32>)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let first = name.map(|n| n.saturating_sub(1).saturating_mul(16));
    let mut at = 0usize;
    for index in 0..16u32 {
        let Some(len) = u16_le(&data, at) else {
            break;
        };
        let bytes = usize::from(len).saturating_mul(2);
        let text_at = at.saturating_add(2);
        let entry = span.sub(to_u64(at), to_u64(bytes.saturating_add(2)));
        if len > 0 {
            let label = match first {
                Some(f) => format!("String {}", f.saturating_add(index)),
                None => format!("String [{index}]"),
            };
            let mut node = Node::new(label).span(entry);
            match data.get(text_at..text_at.saturating_add(bytes)) {
                Some(raw) => {
                    node = node.value(Value::Text(crate::text::utf16(raw, LE)));
                }
                None => {
                    node = node.diag(Diagnostic::truncated(
                        entry,
                        to_u64(data.len().saturating_sub(at)),
                    ));
                }
            }
            cx.push(node).await;
        }
        at = text_at.saturating_add(bytes);
    }
    Ok(())
}

const ACCEL_FLAGS: FlagTable = &[
    flag(0x01, "FVIRTKEY"),
    flag(0x02, "FNOINVERT"),
    flag(0x04, "FSHIFT"),
    flag(0x08, "FCONTROL"),
    flag(0x10, "FALT"),
    flag(0x80, "last entry"),
];

/// `ACCELTABLEENTRY` records of 8 bytes, the last flagged 0x80.
async fn accelerators(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let count = data.len() / 8;
    for index in 0..count {
        let at = index.saturating_mul(8);
        let flags = u16_le(&data, at).unwrap_or(0);
        let key = u16_le(&data, at.saturating_add(2)).unwrap_or(0);
        let id = u16_le(&data, at.saturating_add(4)).unwrap_or(0);
        let entry = span.sub(to_u64(at), 8);
        let mut keys = Vec::new();
        if flags & 0x08 != 0 {
            keys.push("Ctrl".to_owned());
        }
        if flags & 0x10 != 0 {
            keys.push("Alt".to_owned());
        }
        if flags & 0x04 != 0 {
            keys.push("Shift".to_owned());
        }
        keys.push(if flags & 0x01 != 0 {
            format!("VK {key:#04x}")
        } else {
            match char::from_u32(key.into()) {
                Some(c) if !c.is_control() => format!("'{c}'"),
                _ if (1..0x20).contains(&key) => format!(
                    "^{}",
                    char::from(u8::try_from(key).unwrap_or(0).saturating_add(0x40))
                ),
                _ => format!("char {key:#04x}"),
            }
        });
        cx.push(
            Node::new(format!("Entry {index}"))
                .span(entry)
                .summary(format!("{} → command {id}", keys.join("+")))
                .lazy(accelerator, entry),
        )
        .await;
        if flags & 0x80 != 0 {
            break;
        }
    }
    Ok(())
}

async fn accelerator(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u16("fFlags").flags(ACCEL_FLAGS).emit()?;
    f.u16("wAnsi")
        .hex()
        .desc("Character code or virtual-key code")
        .emit()?;
    f.u16("wId").desc("Command ID").emit()?;
    f.u16("padding").emit()?;
    Ok(())
}

/// `MESSAGE_RESOURCE_DATA`: block count, then `(LowId, HighId,
/// OffsetToEntries)` blocks; each block's entries are `Length, Flags, Text`
/// (Flags 1 = UTF-16, 0 = ANSI).
async fn messages(cx: Cx, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 4)).await?;
    let blocks = Fields::emitting(&cx, &head, LE)
        .u32("NumberOfBlocks")
        .emit()?;
    let table = span.sub_exact(4, u64::from(blocks).saturating_mul(12))?;
    let data = cx.read(table).await?;
    for index in 0..blocks {
        let at = crate::bytes::to_usize(index.into()).saturating_mul(12);
        let low = u32_le(&data, at).unwrap_or(0);
        let high = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
        let offset = u32_le(&data, at.saturating_add(8)).unwrap_or(0);
        cx.push(
            Node::new(format!("Block {index}"))
                .span(table.sub(to_u64(at), 12))
                .summary(format!("IDs {low:#x}–{high:#x}"))
                .lazy(
                    message_block,
                    (span, table.sub(to_u64(at), 12), low, high, offset),
                ),
        )
        .await;
    }
    Ok(())
}

fn message_block_fields(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("LowId").hex().emit()?;
    f.u32("HighId").hex().emit()?;
    f.u32("OffsetToEntries")
        .hex()
        .desc("From the start of the message table")
        .emit()?;
    Ok(())
}

async fn message_block(
    cx: Cx,
    (span, descriptor, low, high, offset): (Span, Span, u32, u32, u32),
) -> Result<()> {
    let block = cx.block(descriptor).await?;
    message_block_fields(&mut Fields::emitting(&cx, &block, LE), &())?;
    let mut at = u64::from(offset);
    let mut id = low;
    loop {
        let head = cx.read(span.sub_exact(at, 4)?).await?;
        let len = u16_le(&head, 0).unwrap_or(0);
        let flags = u16_le(&head, 2).unwrap_or(0);
        if len < 4 {
            cx.diag(
                Diagnostic::malformed(format!("message entry length {len}")).at(span.sub(at, 4)),
            );
            break;
        }
        let entry = span.sub(at, len.into());
        let raw = cx.read_avail(entry.tail(4)).await?;
        let text = match flags {
            1 => crate::text::utf16z(&raw, LE).0,
            _ => crate::text::until_nul(&raw),
        };
        let text = text.trim_end_matches(['\r', '\n']).to_owned();
        let encoding = match flags {
            0 => "ANSI",
            1 => "UTF-16",
            2 => "UTF-8",
            _ => "unknown encoding",
        };
        cx.push(
            Node::new(format!("Message {id:#x}"))
                .span(entry)
                .value(Value::Text(text))
                .summary(format!("{encoding}, {len} bytes")),
        )
        .await;
        if id >= high {
            break;
        }
        id = id.saturating_add(1);
        at = at.saturating_add(len.into());
    }
    Ok(())
}

const DIALOG_STYLES: FlagTable = &[
    flag(0x0000_0001, "DS_ABSALIGN"),
    flag(0x0000_0002, "DS_SYSMODAL"),
    flag(0x0000_0020, "DS_LOCALEDIT"),
    flag(0x0000_0040, "DS_SETFONT"),
    flag(0x0000_0080, "DS_MODALFRAME"),
    flag(0x0000_0100, "DS_NOIDLEMSG"),
    flag(0x0000_0200, "DS_SETFOREGROUND"),
    flag(0x0000_0400, "DS_3DLOOK"),
    flag(0x0000_0800, "DS_FIXEDSYS"),
    flag(0x0000_1000, "DS_NOFAILCREATE"),
    flag(0x0000_2000, "DS_CONTROL"),
    flag(0x0000_4000, "DS_CENTER"),
    flag(0x0000_8000, "DS_CENTERMOUSE"),
    flag(0x0001_0000, "WS_MAXIMIZEBOX"),
    flag(0x0002_0000, "WS_MINIMIZEBOX"),
    flag(0x0004_0000, "WS_THICKFRAME"),
    flag(0x0008_0000, "WS_SYSMENU"),
    flag(0x0010_0000, "WS_HSCROLL"),
    flag(0x0020_0000, "WS_VSCROLL"),
    flag(0x0040_0000, "WS_DLGFRAME"),
    flag(0x0080_0000, "WS_BORDER"),
    flag(0x0400_0000, "WS_CLIPSIBLINGS"),
    flag(0x0800_0000, "WS_DISABLED"),
    flag(0x1000_0000, "WS_VISIBLE"),
    flag(0x2000_0000, "WS_MINIMIZE"),
    flag(0x4000_0000, "WS_CHILD"),
    flag(0x8000_0000, "WS_POPUP"),
];

/// Predefined control classes, by atom.
fn control_class(atom: u16) -> Option<&'static str> {
    Some(match atom {
        0x80 => "Button",
        0x81 => "Edit",
        0x82 => "Static",
        0x83 => "ListBox",
        0x84 => "ScrollBar",
        0x85 => "ComboBox",
        _ => return None,
    })
}

/// An `sz_Or_Ord` field: 0 (none), 0xFFFF + ordinal, or a UTF-16 string.
/// Emits it and returns its text.
fn sz_or_ord(f: &mut Fields<'_>, name: &'static str, class: bool) -> Result<String> {
    let data = &f.block().data;
    let at = crate::bytes::to_usize(f.pos());
    match u16_le(data, at) {
        Some(0) => {
            f.u16(name).summary("none").emit()?;
            Ok(String::new())
        }
        Some(0xffff) => {
            let span = f.peek_span(4);
            let ordinal =
                u16_le(data, at.saturating_add(2)).ok_or_else(|| Diagnostic::truncated(span, 2))?;
            let label = if class {
                control_class(ordinal).map_or_else(|| format!("#{ordinal:#x}"), str::to_owned)
            } else {
                format!("#{ordinal}")
            };
            f.node(
                Node::new(name)
                    .span(span)
                    .value(crate::formats::util::lines::hex(ordinal.into(), 16))
                    .summary(label.clone()),
            );
            f.skip(4);
            Ok(label)
        }
        _ => f.utf16z(name).emit(),
    }
}

fn align4(f: &mut Fields<'_>) {
    let aligned = f.pos().next_multiple_of(4);
    f.seek(aligned);
}

/// `DLGTEMPLATE` / `DLGTEMPLATEEX` header fields; returns the control count.
fn dialog_header(f: &mut Fields<'_>, ex: bool) -> Result<u16> {
    let style = if ex {
        f.u16("dlgVer").emit()?;
        f.u16("signature").hex().emit()?;
        f.u32("helpID").emit()?;
        f.u32("exStyle").hex().emit()?;
        f.u32("style").flags(DIALOG_STYLES).emit()?
    } else {
        let style = f.u32("style").flags(DIALOG_STYLES).emit()?;
        f.u32("dwExtendedStyle").hex().emit()?;
        style
    };
    let count = f.u16(if ex { "cDlgItems" } else { "cdit" }).emit()?;
    f.int::<i16>("x").emit()?;
    f.int::<i16>("y").emit()?;
    f.int::<i16>("cx").emit()?;
    f.int::<i16>("cy").emit()?;
    sz_or_ord(f, "menu", false)?;
    sz_or_ord(f, "windowClass", false)?;
    f.utf16z("title").emit()?;
    if style & 0x40 != 0 {
        f.u16("pointsize").emit()?;
        if ex {
            f.u16("weight").emit()?;
            f.u8("italic").emit()?;
            f.u8("charset").emit()?;
        }
        f.utf16z("typeface").emit()?;
    }
    Ok(count)
}

/// One `DLGITEMTEMPLATE(EX)`; returns its summary.
fn dialog_item(f: &mut Fields<'_>, ex: bool) -> Result<String> {
    if ex {
        f.u32("helpID").emit()?;
        f.u32("exStyle").hex().emit()?;
        f.u32("style").hex().emit()?;
    } else {
        f.u32("style").hex().emit()?;
        f.u32("dwExtendedStyle").hex().emit()?;
    }
    let x = f.int::<i16>("x").emit()?;
    let y = f.int::<i16>("y").emit()?;
    let w = f.int::<i16>("cx").emit()?;
    let h = f.int::<i16>("cy").emit()?;
    let id = if ex {
        f.u32("id").emit()?
    } else {
        u32::from(f.u16("id").emit()?)
    };
    let class = sz_or_ord(f, "windowClass", true)?;
    let title = sz_or_ord(f, "title", false)?;
    let extra = f.u16("extraCount").emit()?;
    if extra > 0 {
        f.bytes("Creation data", extra.into()).emit()?;
    }
    Ok(format!("{class} {title:?}, ID {id}, at ({x}, {y}) {w}×{h}"))
}

async fn dialog(cx: Cx, (span, ex): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let count = dialog_header(&mut f, ex)?;
    align4(&mut f);
    let mut at = f.pos();
    for index in 0..count {
        let mut g = Fields::new(&block, LE);
        g.seek(at);
        let summary = dialog_item(&mut g, ex)?;
        let item = span.sub(at, g.pos().saturating_sub(at));
        cx.push(
            Node::new(format!("Control {index}"))
                .span(item)
                .summary(summary)
                .lazy(dialog_control, (item, ex)),
        )
        .await;
        align4(&mut g);
        at = g.pos();
    }
    Ok(())
}

async fn dialog_control(cx: Cx, (span, ex): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    dialog_item(&mut Fields::emitting(&cx, &block, LE), ex)?;
    Ok(())
}

const MF_FLAGS: FlagTable = &[
    flag(0x0001, "MF_GRAYED"),
    flag(0x0002, "MF_DISABLED"),
    flag(0x0004, "MF_BITMAP"),
    flag(0x0008, "MF_CHECKED"),
    flag(0x0010, "MF_POPUP"),
    flag(0x0020, "MF_MENUBARBREAK"),
    flag(0x0040, "MF_MENUBREAK"),
    flag(0x0080, "MF_END"),
    flag(0x0100, "MF_OWNERDRAW"),
    flag(0x0800, "MF_SEPARATOR"),
    flag(0x4000, "MF_HELP"),
];

/// A standard menu template: `MENUITEMTEMPLATEHEADER`, then items; a popup
/// (`MF_POPUP`) has no ID and is followed by its own items, each level ending
/// with an `MF_END` item. Shown flat, with the nesting in the item names.
async fn menu(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let header = cx.block(span.sub(0, 4)).await?;
    {
        let mut f = Fields::emitting(&cx, &header, LE);
        f.u16("versionNumber").emit()?;
        f.u16("offset").emit()?;
    }
    let offset = u16_le(&data, 2).unwrap_or(0);
    let mut at = 4usize.saturating_add(offset.into());
    // Open popups: their names, and whether each popup item was itself the
    // last (MF_END) of its level.
    let mut stack: Vec<(String, bool)> = Vec::new();
    'items: while at < data.len() {
        cx.checkpoint().await;
        let start = at;
        let Some(flags) = u16_le(&data, at) else {
            break;
        };
        at = at.saturating_add(2);
        let popup = flags & 0x10 != 0;
        let id = if popup {
            None
        } else {
            let id = u16_le(&data, at);
            at = at.saturating_add(2);
            id
        };
        let (text, used, _) = crate::text::utf16z(data.get(at..).unwrap_or_default(), LE);
        at = at.saturating_add(used);
        let entry = span.sub(to_u64(start), to_u64(at.saturating_sub(start)));
        let label = if text.is_empty() && !popup {
            "(separator)".to_owned()
        } else {
            text.replace('&', "")
        };
        let mut path: Vec<&str> = stack.iter().map(|(n, _)| n.as_str()).collect();
        path.push(&label);
        let mut node =
            Node::new(path.join(" › "))
                .span(entry)
                .value(flag_value(MF_FLAGS, flags.into(), 16));
        if let Some(id) = id.filter(|_| !(text.is_empty() && flags & 0x10 == 0)) {
            node = node.summary(format!("command {id}"));
        }
        cx.push(node).await;
        if popup {
            stack.push((label, flags & 0x80 != 0));
            if stack.len() > 32 {
                cx.diag(Diagnostic::limit("menu nested deeper than 32 levels"));
                break;
            }
            continue;
        }
        if flags & 0x80 != 0 {
            // This level ends; so does every enclosing level whose popup
            // was the last item of its own level.
            let mut ended = true;
            while ended {
                match stack.pop() {
                    Some((_, last)) => ended = last,
                    None => break 'items,
                }
            }
        }
    }
    Ok(())
}

const MFT_FLAGS: FlagTable = &[
    flag(0x0000_0004, "MFT_BITMAP"),
    flag(0x0000_0020, "MFT_MENUBARBREAK"),
    flag(0x0000_0040, "MFT_MENUBREAK"),
    flag(0x0000_0100, "MFT_OWNERDRAW"),
    flag(0x0000_0200, "MFT_RADIOCHECK"),
    flag(0x0000_0800, "MFT_SEPARATOR"),
    flag(0x0000_2000, "MFT_RIGHTORDER"),
    flag(0x0000_4000, "MFT_RIGHTJUSTIFY"),
];

/// An extended menu template: `MENUEX_TEMPLATE_HEADER` (version 1, offset
/// of the items, help ID), then `MENUEX_TEMPLATE_ITEM`s (type, state, ID,
/// `bResInfo`, text, DWORD alignment; a popup, `bResInfo & 1`, adds a help
/// ID and is followed by its items; `bResInfo & 0x80` ends a level). Shown
/// flat, with the nesting in the item names.
async fn menu_ex(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let header = cx.block(span.sub(0, 8)).await?;
    {
        let mut f = Fields::emitting(&cx, &header, LE);
        f.u16("wVersion").desc("1 for MENUEX").emit()?;
        f.u16("wOffset")
            .desc("Offset of the first item from the end of this field")
            .emit()?;
        f.u32("dwHelpId").emit()?;
    }
    let offset = u16_le(&data, 2).unwrap_or(4);
    let mut at = 4usize.saturating_add(offset.into());
    let mut stack: Vec<(String, bool)> = Vec::new();
    'items: while at < data.len() {
        cx.checkpoint().await;
        let start = at;
        let (Some(kind), Some(state), Some(id), Some(info)) = (
            u32_le(&data, at),
            u32_le(&data, at.saturating_add(4)),
            u32_le(&data, at.saturating_add(8)),
            u16_le(&data, at.saturating_add(12)),
        ) else {
            break;
        };
        at = at.saturating_add(14);
        let (text, used, _) = crate::text::utf16z(data.get(at..).unwrap_or_default(), LE);
        at = at.saturating_add(used).next_multiple_of(4);
        let popup = info & 0x01 != 0;
        if popup {
            at = at.saturating_add(4);
        }
        let entry = span.sub(to_u64(start), to_u64(at.saturating_sub(start)));
        let label = if kind & 0x800 != 0 {
            "(separator)".to_owned()
        } else {
            text.replace('&', "")
        };
        let mut path: Vec<&str> = stack.iter().map(|(n, _)| n.as_str()).collect();
        path.push(&label);
        let mut summary = if popup {
            "popup".to_owned()
        } else {
            format!("command {id}")
        };
        if state != 0 {
            summary.push_str(&format!(", state {state:#x}"));
        }
        cx.push(
            Node::new(path.join(" › "))
                .span(entry)
                .value(flag_value(MFT_FLAGS, kind.into(), 32))
                .summary(summary),
        )
        .await;
        if popup {
            stack.push((label, info & 0x80 != 0));
            if stack.len() > 32 {
                cx.diag(Diagnostic::limit("menu nested deeper than 32 levels"));
                break;
            }
            continue;
        }
        if info & 0x80 != 0 {
            let mut ended = true;
            while ended {
                match stack.pop() {
                    Some((_, last)) => ended = last,
                    None => break 'items,
                }
            }
        }
    }
    Ok(())
}
