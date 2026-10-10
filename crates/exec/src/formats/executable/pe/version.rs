//! Version resources (`VS_VERSIONINFO`).
//!
//! A version resource is a tree of blocks, each `wLength, wValueLength,
//! wType, szKey (UTF-16), padding, Value, padding, Children`. The root's
//! value is a `VS_FIXEDFILEINFO`; `StringFileInfo` holds per-language string
//! tables and `VarFileInfo` the list of translations.
//!
//! 16-bit Windows (NE) resources have the same tree with an older block
//! header: `wLength, wValueLength, szKey (ANSI)`, no `wType`, and text
//! values counted in bytes. Their strings are text, the root's and
//! `Translation`'s values binary.

use super::resource::Layout;
use crate::bytes::{align_up, to_u64, to_usize, u16_le, u32_le};
use crate::codec::charset::Charset;
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
    to_usize(align_up(to_u64(n), 4))
}

impl Layout {
    /// Bytes of block header before `szKey`.
    fn header_len(self) -> usize {
        match self {
            Layout::Win32 => 6,
            Layout::Win16 => 4,
        }
    }

    /// A NUL-terminated string at the start of `data`, and the bytes it
    /// takes with the terminator.
    fn string(self, data: &[u8]) -> (String, usize) {
        match self {
            Layout::Win32 => {
                let (s, len, _) = crate::text::utf16z(data, Endian::Little);
                (s, len)
            }
            Layout::Win16 => {
                let end = data.iter().position(|&b| b == 0);
                let text = data.get(..end.unwrap_or(data.len())).unwrap_or_default();
                let len = end.map_or(data.len(), |e| e.saturating_add(1));
                (Charset::Windows1252.decode(text), len)
            }
        }
    }
}

fn parse_block(data: &[u8], layout: Layout) -> Result<Block> {
    let header = layout.header_len();
    let len = usize::from(u16_le(data, 0).ok_or_else(short)?);
    let value_len = usize::from(u16_le(data, 2).ok_or_else(short)?);
    if len < header || len > data.len() {
        return Err(Diagnostic::malformed(format!(
            "block length {len:#x} does not fit (have {:#x})",
            data.len()
        )));
    }
    let block = data.get(..len).unwrap_or_default();
    let (key, key_len) = layout.string(block.get(header..).unwrap_or_default());
    let key_end = header.saturating_add(key_len);
    let text = match layout {
        Layout::Win32 => u16_le(data, 4) == Some(1),
        Layout::Win16 => key != "VS_VERSION_INFO" && key != "Translation",
    };
    let value_start = align4(key_end).min(len);
    // Win32 text values count UTF-16 units; everything else counts bytes.
    let value_bytes = if text && layout == Layout::Win32 {
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
fn text_value(data: &[u8], block: &Block, layout: Layout) -> String {
    let bytes = data
        .get(block.value_start..block.value_end)
        .unwrap_or_default();
    layout.string(bytes).0
}

/// Summary of `VS_VERSIONINFO` at `span` (for the top-level node).
pub async fn summary(cx: &Cx, span: Span, layout: Layout) -> Result<String> {
    let data = cx.read(span.sub(0, 0xffff)).await?;
    let block = parse_block(&data, layout)?;
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
pub async fn block(cx: Cx, (span, layout): (Span, Layout)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let b = parse_block(&data, layout)?;
    let span = span.sub(0, to_u64(b.len));
    let block = crate::cx::Block {
        span,
        data: data.get(..b.len).unwrap_or_default().to_vec(),
    };
    {
        let mut f = Fields::emitting(&cx, &block, Endian::Little);
        f.u16("wLength").hex().emit()?;
        f.u16("wValueLength").emit()?;
        if layout == Layout::Win32 {
            f.u16("wType").desc("1 = text, 0 = binary").emit()?;
        }
    }
    let header = layout.header_len();
    cx.emit(
        Node::new("szKey")
            .value(Value::Text(b.key.clone()))
            .span(span.sub(to_u64(header), to_u64(b.key_end.saturating_sub(header)))),
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
                    .value(Value::Text(text_value(&block.data, &b, layout)))
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
        let child = match parse_block(rest, layout) {
            Ok(child) => child,
            Err(e) => {
                cx.diag(e.at(span.tail(to_u64(at))));
                break;
            }
        };
        let child_span = span.sub(to_u64(at), to_u64(child.len));
        let mut node = Node::new(child.key.clone()).span(child_span);
        if child.text && child.value_len > 0 {
            node = node.summary(text_value(rest, &child, layout));
        }
        cx.push(node.lazy(
            crate::expander!(self::block: (Span, Layout)),
            (child_span, layout),
        ))
        .await;
        if child.len == 0 {
            break;
        }
        at = align4(at.saturating_add(child.len));
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    /// A 16-bit block: header, ANSI key, value and children, DWORD-aligned.
    fn block16(key: &str, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0, 0];
        b.extend((value.len() as u16).to_le_bytes());
        b.extend(key.as_bytes());
        b.push(0);
        b.resize(b.len().next_multiple_of(4), 0);
        b.extend(value);
        for c in children {
            b.resize(b.len().next_multiple_of(4), 0);
            b.extend(c);
        }
        let len = (b.len() as u16).to_le_bytes();
        b[..2].copy_from_slice(&len);
        b
    }

    #[test]
    fn win16_blocks() {
        let string = block16("CompanyName", b"Acme\0", &[]);
        let table = block16("040904E4", &[], &[string]);
        let info = block16("StringFileInfo", &[], &[table]);
        let root = block16("VS_VERSION_INFO", &[0; 52], &[info]);

        let b = parse_block(&root, Layout::Win16).unwrap();
        assert_eq!((b.key.as_str(), b.text), ("VS_VERSION_INFO", false));
        assert_eq!((b.value_start, b.value_end), (20, 72));
        let info = parse_block(&root[72..], Layout::Win16).unwrap();
        assert_eq!(info.key, "StringFileInfo");
        let table = &root[72 + align4(info.value_end)..];
        let t = parse_block(table, Layout::Win16).unwrap();
        assert_eq!(t.key, "040904E4");
        let string = &table[align4(t.value_end)..];
        let s = parse_block(string, Layout::Win16).unwrap();
        assert!(s.text);
        assert_eq!(text_value(string, &s, Layout::Win16), "Acme");
    }
}
