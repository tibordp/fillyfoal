//! Compiled Win32 resource files (`.res`, from `rc`/`llvm-rc`/`windres`):
//! a sequence of resource entries, each a header (sizes, type, name,
//! language, flags) followed by its data. An empty entry comes first.
//!
//! Version resources are decoded with the PE dissector's `VS_VERSIONINFO`
//! reader; other data is identified and dissected when expanded.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::binutil::{ellipsize, name_or};
use crate::formats::pe::tables::RESOURCE_TYPE;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const LE: Endian = Endian::Little;
const RT_VERSION: u64 = 16;

pub static FORMAT: Format = Format {
    name: "win32-res",
    title: "Win32 compiled resources",
    extensions: &["res"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(
        0,
        b"\0\0\0\0\x20\0\0\0\xff\xff\0\0\xff\xff\0\0",
    )]),
    dissect: crate::expander!(dissect: Input),
};

const MEMORY_FLAGS: FlagTable = &[
    flag(0x10, "MOVEABLE"),
    flag(0x20, "PURE"),
    flag(0x40, "PRELOAD"),
    flag(0x1000, "DISCARDABLE"),
];

/// A resource type or name: `FFFF` and an ID, or a NUL-terminated UTF-16
/// string. Returns the label and its length in bytes.
fn ident(data: &[u8], at: usize, types: bool) -> (String, usize) {
    if u16_le(data, at) == Some(0xffff) {
        let id = u16_le(data, at.saturating_add(2)).unwrap_or(0);
        let label = if types {
            name_or(RESOURCE_TYPE, id.into(), "type")
        } else {
            format!("#{id}")
        };
        (label, 4)
    } else {
        let (s, len, _) = crate::text::utf16z(data.get(at..).unwrap_or_default(), LE);
        (format!("{s:?}"), len)
    }
}

#[derive(Clone, Debug)]
struct Entry {
    kind: String,
    kind_id: Option<u16>,
    name: String,
    header: Span,
    data: Span,
    language: u16,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut offset = 0u64;
    let mut entries = Vec::new();
    while offset.saturating_add(32) <= file.len {
        cx.checkpoint().await;
        let head = cx.read_avail(file.sub(offset, 0x400)).await?;
        let (Some(data_size), Some(header_size)) = (u32_le(&head, 0), u32_le(&head, 4)) else {
            break;
        };
        if header_size < 32 {
            cx.diag(Diagnostic::malformed(format!("header size {header_size}")).at(file.sub(offset, 8)));
            break;
        }
        let (kind, n1) = ident(&head, 8, true);
        let kind_id = (u16_le(&head, 8) == Some(0xffff)).then(|| u16_le(&head, 10).unwrap_or(0));
        let (name, _) = ident(&head, 8usize.saturating_add(n1), false);
        let fixed = to_usize(header_size.into()).saturating_sub(16);
        let language = u16_le(&head, fixed.saturating_add(6)).unwrap_or(0);
        let header = file.sub(offset, header_size.into());
        let data = file.sub(offset.saturating_add(header_size.into()), data_size.into());
        entries.push(Entry {
            kind,
            kind_id,
            name,
            header,
            data,
            language,
        });
        offset = offset
            .saturating_add(header_size.into())
            .saturating_add(data_size.into())
            .checked_next_multiple_of(4)
            .unwrap_or(u64::MAX);
    }
    let kinds: Vec<&str> = entries
        .iter()
        .filter(|e| e.data.len > 0)
        .map(|e| e.kind.as_str())
        .collect();
    cx.annotate(format!(
        "Win32 resources, {} entries: {}",
        kinds.len(),
        ellipsize(&kinds.join(", "), 120)
    ));
    for e in entries {
        let label = if e.data.len == 0 && e.kind_id == Some(0) {
            "(empty entry)".to_owned()
        } else {
            format!("{} {}", e.kind, e.name)
        };
        cx.push(
            Node::new(label)
                .span(e.header.sub(0, 0).span_to(e.data))
                .summary(format!("{:#x} bytes, language {:#06x}", e.data.len, e.language))
                .lazy(entry, (input, e)),
        )
        .await;
    }
    Ok(())
}

/// `RT_STRING` blocks hold 16 length-prefixed UTF-16 strings; block `n`
/// holds string IDs `(n - 1) * 16 ..`.
async fn string_table(cx: Cx, (span, name): (Span, String)) -> Result<()> {
    let data = cx.read(span).await?;
    let block: u32 = name.trim_start_matches('#').parse().unwrap_or(1);
    let base = block.saturating_sub(1).saturating_mul(16);
    let mut at = 0usize;
    for i in 0..16u32 {
        let Some(len) = u16_le(&data, at) else { break };
        let bytes = usize::from(len).saturating_mul(2);
        let start = at;
        at = at.saturating_add(2).saturating_add(bytes);
        if len == 0 {
            continue;
        }
        let s = crate::text::utf16(
            data.get(start.saturating_add(2)..at).unwrap_or_default(),
            LE,
        );
        cx.emit(
            Node::new(format!("{}", base.saturating_add(i)))
                .span(span.sub(to_u64(start), to_u64(at.saturating_sub(start))))
                .value(crate::formats::binutil::text(s)),
        );
    }
    Ok(())
}

trait SpanTo {
    fn span_to(self, end: Span) -> Span;
}

impl SpanTo for Span {
    /// From the start of `self` to the end of `end`.
    fn span_to(self, end: Span) -> Span {
        Span::new(self.source, self.offset, end.end().saturating_sub(self.offset))
    }
}

async fn entry(cx: Cx, (input, e): (Input, Entry)) -> Result<()> {
    let block = cx.block(e.header).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("DataSize").hex().emit()?;
    f.u32("HeaderSize").hex().emit()?;
    let data = block.data.clone();
    let (_, n1) = ident(&data, 8, true);
    let (_, n2) = ident(&data, 8usize.saturating_add(n1), false);
    f.node(Node::new("Type").span(e.header.sub(8, to_u64(n1))).value(crate::formats::binutil::text(e.kind.clone())));
    f.node(
        Node::new("Name")
            .span(e.header.sub(8u64.saturating_add(to_u64(n1)), to_u64(n2)))
            .value(crate::formats::binutil::text(e.name.clone())),
    );
    f.seek(e.header.len.saturating_sub(16));
    f.u32("DataVersion").emit()?;
    f.u16("MemoryFlags").flags(MEMORY_FLAGS).emit()?;
    f.u16("LanguageId").hex().emit()?;
    f.u32("Version").emit()?;
    f.u32("Characteristics").hex().emit()?;
    if e.data.len > 0 {
        let node = if e.kind_id.map(u64::from) == Some(RT_VERSION) {
            let node = Node::new("Version Info")
                .span(e.data)
                .lazy(crate::formats::pe::version::block, e.data);
            match crate::formats::pe::version::summary(&cx, e.data).await {
                Ok(s) => node.summary(s),
                Err(d) => node.diag(d),
            }
        } else if e.kind_id == Some(6) {
            Node::new("String Table")
                .span(e.data)
                .lazy(string_table, (e.data, e.name.clone()))
        } else {
            Node::new("Data")
                .span(e.data)
                .lazy(crate::formats::dissect_or_data, input.nested(e.data))
        };
        cx.emit(node);
    }
    Ok(())
}
