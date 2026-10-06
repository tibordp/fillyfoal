//! Version resources (`VS_VERSIONINFO`).
//!
//! A version resource is a tree of blocks, each `wLength, wValueLength,
//! wType, szKey (UTF-16), padding, Value, padding, Children`. The root's
//! value is a `VS_FIXEDFILEINFO`; `StringFileInfo` holds per-language string
//! tables and `VarFileInfo` the list of translations.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const VS_FF: FlagTable = &[
    flag(0x01, "DEBUG"),
    flag(0x02, "PRERELEASE"),
    flag(0x04, "PATCHED"),
    flag(0x08, "PRIVATEBUILD"),
    flag(0x10, "INFOINFERRED"),
    flag(0x20, "SPECIALBUILD"),
];

const VOS: EnumTable = &[
    (0x0000_0000, "UNKNOWN"),
    (0x0000_0001, "WINDOWS16"),
    (0x0000_0004, "WINDOWS32"),
    (0x0001_0000, "DOS"),
    (0x0001_0001, "DOS_WINDOWS16"),
    (0x0001_0004, "DOS_WINDOWS32"),
    (0x0004_0000, "NT"),
    (0x0004_0004, "NT_WINDOWS32"),
];

const VFT: EnumTable = &[
    (0, "UNKNOWN"),
    (1, "APP"),
    (2, "DLL"),
    (3, "DRV"),
    (4, "FONT"),
    (5, "VXD"),
    (7, "STATIC_LIB"),
];

record! {
    /// VS_FIXEDFILEINFO
    pub struct FixedFileInfo {
        signature: u32 "dwSignature" .hex() .desc("0xfeef04bd"),
        struct_version: u32 "dwStrucVersion" .hex(),
        file_ms: u32 "dwFileVersionMS" .hex(),
        file_ls: u32 "dwFileVersionLS" .hex(),
        product_ms: u32 "dwProductVersionMS" .hex(),
        product_ls: u32 "dwProductVersionLS" .hex(),
        flags_mask: u32 "dwFileFlagsMask" .hex(),
        flags: u32 "dwFileFlags" .flags(VS_FF),
        os: u32 "dwFileOS" .enumeration(VOS),
        file_type: u32 "dwFileType" .enumeration(VFT),
        subtype: u32 "dwFileSubtype" .hex(),
        date_ms: u32 "dwFileDateMS" .hex(),
        date_ls: u32 "dwFileDateLS" .hex(),
    }
}

impl FixedFileInfo {
    pub fn file_version(&self) -> String {
        dotted(self.file_ms, self.file_ls)
    }

    pub fn product_version(&self) -> String {
        dotted(self.product_ms, self.product_ls)
    }
}

fn dotted(ms: u32, ls: u32) -> String {
    format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff)
}

/// One block, decoded from bytes in memory. Offsets are relative to the
/// block's start.
struct Block {
    len: usize,
    value_len: usize,
    text: bool,
    key: String,
    key_end: usize,
    value_start: usize,
    value_end: usize,
}

fn align4(n: usize) -> usize {
    n.checked_next_multiple_of(4).unwrap_or(usize::MAX)
}

/// Reads a NUL-terminated UTF-16LE string at `start`; returns it and the
/// offset after the terminator.
fn utf16z(data: &[u8], start: usize) -> (String, usize) {
    let mut units = Vec::new();
    let mut at = start;
    while let Some(unit) = u16_le(data, at) {
        at = at.saturating_add(2);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    (String::from_utf16_lossy(&units), at)
}

fn parse_block(data: &[u8]) -> Result<Block> {
    let len = usize::from(u16_le(data, 0).ok_or_else(short)?);
    let value_len = usize::from(u16_le(data, 2).ok_or_else(short)?);
    let text = u16_le(data, 4).ok_or_else(short)? == 1;
    if len < 6 || len > data.len() {
        return Err(Diagnostic::malformed(format!(
            "block length {len:#x} does not fit (have {:#x})",
            data.len()
        )));
    }
    let block = data.get(..len).unwrap_or_default();
    let (key, key_end) = utf16z(block, 6);
    let value_start = align4(key_end).min(len);
    // Text values count UTF-16 units, binary values count bytes.
    let value_bytes = if text {
        value_len.saturating_mul(2)
    } else {
        value_len
    };
    let value_end = value_start.saturating_add(value_bytes).min(len);
    Ok(Block {
        len,
        value_len,
        text,
        key,
        key_end,
        value_start,
        value_end,
    })
}

fn short() -> Diagnostic {
    Diagnostic::malformed("version block header is truncated")
}

/// The text value of a block, without its terminator.
fn text_value(data: &[u8], block: &Block) -> String {
    let bytes = data
        .get(block.value_start..block.value_end)
        .unwrap_or_default();
    utf16z(bytes, 0).0
}

/// Summary of `VS_VERSIONINFO` at `span` (for the top-level node).
pub async fn summary(cx: &Cx, span: Span) -> Result<String> {
    let data = cx.read(span.sub(0, 0xffff)).await?;
    let block = parse_block(&data)?;
    let fixed = data
        .get(block.value_start..block.value_end)
        .filter(|v| to_u64(v.len()) >= FixedFileInfo::SIZE);
    match fixed {
        Some(_) => {
            let span = span.sub(to_u64(block.value_start), FixedFileInfo::SIZE);
            let bytes = data
                .get(block.value_start..block.value_end)
                .unwrap_or_default()
                .to_vec();
            let info = FixedFileInfo::read(&mut Fields::new(
                &crate::cx::Block { span, data: bytes },
                Endian::Little,
            ))?;
            Ok(format!(
                "file {}, product {}",
                info.file_version(),
                info.product_version()
            ))
        }
        None => Ok(block.key),
    }
}

/// Expands one block: its header fields, its value and its child blocks.
pub async fn block(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let b = parse_block(&data)?;
    let span = span.sub(0, to_u64(b.len));
    let block = crate::cx::Block {
        span,
        data: data.get(..b.len).unwrap_or_default().to_vec(),
    };
    {
        let mut f = Fields::emitting(&cx, &block, Endian::Little);
        f.u16("wLength").hex().emit()?;
        f.u16("wValueLength").emit()?;
        f.u16("wType").desc("1 = text, 0 = binary").emit()?;
    }
    cx.emit(
        Node::new("szKey")
            .value(Value::Text(b.key.clone()))
            .span(span.sub(6, to_u64(b.key_end.saturating_sub(6)))),
    );

    let value_span = span.sub(
        to_u64(b.value_start),
        to_u64(b.value_end.saturating_sub(b.value_start)),
    );
    if b.value_len > 0 {
        if b.key == "VS_VERSION_INFO" && value_span.len >= FixedFileInfo::SIZE {
            cx.emit(FixedFileInfo::node(
                "VS_FIXEDFILEINFO",
                value_span.sub(0, FixedFileInfo::SIZE),
                Endian::Little,
            ));
        } else if b.text {
            cx.emit(
                Node::new("Value")
                    .value(Value::Text(text_value(&block.data, &b)))
                    .span(value_span),
            );
        } else if b.key == "Translation" {
            let value = block
                .data
                .get(b.value_start..b.value_end)
                .unwrap_or_default();
            let pairs: Vec<String> = (0..value.len() / 4)
                .filter_map(|i| u32_le(value, i.saturating_mul(4)))
                .map(|v| format!("{:04x}{:04x}", v & 0xffff, v >> 16))
                .collect();
            cx.emit(
                Node::new("Value")
                    .value(Value::Text(pairs.join(", ")))
                    .summary("language and code page")
                    .span(value_span),
            );
        } else {
            cx.emit(Node::new("Value").span(value_span));
        }
    }

    let mut at = align4(b.value_end);
    while at < b.len {
        cx.checkpoint().await;
        let rest = block.data.get(at..).unwrap_or_default();
        let child = match parse_block(rest) {
            Ok(child) => child,
            Err(e) => {
                cx.diag(e.at(span.tail(to_u64(at))));
                break;
            }
        };
        let child_span = span.sub(to_u64(at), to_u64(child.len));
        let mut node = Node::new(child.key.clone()).span(child_span);
        if child.text && child.value_len > 0 {
            node = node.summary(text_value(rest, &child));
        }
        cx.push(node.lazy(crate::expander!(self::block: Span), child_span))
            .await;
        if child.len == 0 {
            break;
        }
        at = align4(at.saturating_add(child.len));
    }
    Ok(())
}
