//! APEv1/APEv2 tags, found at the end of Monkey's Audio, WavPack, Musepack
//! and some MP3 files (before an ID3v1 tag, if there is one).

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::Input;
use crate::formats::sound::{clip, decode_text, leaf, text};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, flag};

const LE: Endian = Endian::Little;
const MAGIC: &[u8] = b"APETAGEX";

const FLAGS: FlagTable = &[
    flag(0x8000_0000, "HAS_HEADER"),
    flag(0x4000_0000, "NO_FOOTER"),
    flag(0x2000_0000, "IS_HEADER"),
    flag(0x1, "READ_ONLY"),
    field(0x6, 0x2, "BINARY"),
    field(0x6, 0x4, "LOCATOR"),
];

const ITEM_KIND: EnumTable = &[(0, "UTF-8 text"), (1, "binary"), (2, "external locator")];

record! {
    pub struct Footer {
        magic: ascii[8] "Preamble",
        version: u32 "Version" .desc("1000 = APEv1, 2000 = APEv2"),
        size: u32 "Tag size" .desc("Items and footer, excluding the header"),
        items: u32 "Items",
        flags: u32 "Flags" .flags(FLAGS),
        _reserved: bytes[8] "Reserved",
    }
}

/// The APE tag ending at `end` (relative to `span`), if any: its whole
/// span including the optional header.
pub async fn find(cx: &Cx, span: Span, end: u64) -> Result<Option<Span>> {
    let Some(at) = end.checked_sub(Footer::SIZE) else {
        return Ok(None);
    };
    let footer = cx.read_avail(span.sub(at, Footer::SIZE)).await?;
    if !footer.starts_with(MAGIC) {
        return Ok(None);
    }
    let size = u64::from(u32_le(&footer, 12).unwrap_or(0));
    let flags = u32_le(&footer, 20).unwrap_or(0);
    let header = if flags & 0x8000_0000 != 0 {
        Footer::SIZE
    } else {
        0
    };
    let total = size.saturating_add(header);
    let Some(start) = end.checked_sub(total) else {
        return Ok(None);
    };
    Ok(Some(span.sub(start, total)))
}

/// A lazy node for the APE tag at `span`.
pub async fn node(cx: &Cx, input: Input, span: Span) -> Node {
    let mut node = Node::new("APE tag").span(span);
    let footer = cx
        .read_avail(span.sub(span.len.saturating_sub(Footer::SIZE), Footer::SIZE))
        .await
        .unwrap_or_default();
    let version = u32_le(&footer, 8).unwrap_or(0);
    let items = u32_le(&footer, 16).unwrap_or(0);
    let mut summary = format!("APEv{}, {items} items", version / 1000);
    if let Ok(Some(title)) = title(cx, span).await {
        summary.push_str(&format!(": {title}"));
    }
    node = node.summary(summary);
    node.lazy(expand, (input, span))
}

async fn expand(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let footer_span = span.sub(span.len.saturating_sub(Footer::SIZE), Footer::SIZE);
    let footer = crate::fields::parse(&cx, footer_span, LE, &(), Footer::layout).await?;
    let has_header = footer.flags & 0x8000_0000 != 0;
    if has_header {
        cx.emit(Footer::node("Header", span.sub(0, Footer::SIZE), LE));
    }
    let start = if has_header { Footer::SIZE } else { 0 };
    let items = span.sub(
        start,
        span.len.saturating_sub(start).saturating_sub(Footer::SIZE),
    );
    cx.emit(
        Node::new("Items")
            .span(items)
            .summary(format!("{} items", footer.items))
            .lazy(expand_items, (input, items, footer.items)),
    );
    cx.emit(Footer::node("Footer", footer_span, LE));
    Ok(())
}

/// One item: value size, flags, key (NUL-terminated), value.
struct Item {
    key: String,
    flags: u32,
    span: Span,
    value: Span,
}

async fn read_item(cur: &mut Cursor<'_>) -> Result<Item> {
    let start = cur.pos();
    let size = cur.u32().await?;
    let flags = cur.u32().await?;
    let (key, _) = cur.cstr(256).await?;
    let value = cur.span(size.into());
    cur.skip(size.into());
    Ok(Item {
        key,
        flags,
        span: cur.since(start),
        value,
    })
}

async fn expand_items(cx: Cx, (input, region, count): (Input, Span, u32)) -> Result<()> {
    cx.set_count(Count::Exact(count.into()));
    let mut cur = Cursor::new(&cx, region, LE);
    for _ in 0..count {
        if cur.at_end() {
            break;
        }
        let item = read_item(&mut cur).await?;
        let kind = (item.flags >> 1) & 3;
        let mut node = Node::new(item.key.clone()).span(item.span);
        if kind == 1 {
            node = node.summary(format!("{} bytes", item.value.len));
        } else {
            let data = cx.read_avail(item.value.sub(0, 256)).await?;
            node = node.summary(clip(&decode_text(&data), 60));
        }
        cx.push(node.lazy(item_fields, (input, item.span, item.value, kind)))
            .await;
    }
    Ok(())
}

async fn item_fields(cx: Cx, (input, span, value, kind): (Input, Span, Span, u32)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &block, LE);
    f.u32("Value size").emit()?;
    f.u32("Flags")
        .flags(FLAGS)
        .with(|&v, n| {
            n.summary(crate::value::lookup(ITEM_KIND, ((v >> 1) & 3).into()).unwrap_or("reserved"))
        })
        .emit()?;
    let key_len = value.offset.saturating_sub(span.offset).saturating_sub(8);
    let key = cx.read(span.sub(8, key_len)).await?;
    cx.emit(leaf(
        "Key",
        span.sub(8, key_len),
        text(crate::text::until_nul(&key)),
    ));
    if kind == 1 {
        // Cover art: "file name\0" then the image.
        let data = cx.read_avail(value.sub(0, 256)).await?;
        let name_len = data.iter().position(|&b| b == 0).map(to_u64);
        match name_len {
            Some(n) => {
                cx.emit(leaf(
                    "File name",
                    value.sub(0, n.saturating_add(1)),
                    text(crate::text::latin1(
                        data.get(..crate::bytes::to_usize(n)).unwrap_or_default(),
                    )),
                ));
                cx.emit(crate::formats::embedded(
                    "Data",
                    input.nested(value.tail(n.saturating_add(1))),
                ));
            }
            None => cx.emit(Node::new("Data").span(value)),
        }
    } else {
        let data = cx.read(value.sub(0, value.len.min(1 << 16))).await?;
        cx.emit(leaf("Value", value, text(decode_text(&data))));
    }
    Ok(())
}

/// "Artist – Title" from the tag's items.
pub async fn title(cx: &Cx, span: Span) -> Result<Option<String>> {
    let items = span.sub(0, span.len.saturating_sub(Footer::SIZE));
    let mut cur = Cursor::new(cx, items, LE);
    if cur.peek(8).await? == MAGIC {
        cur.skip(Footer::SIZE);
    }
    let (mut artist, mut title) = (None, None);
    let mut n = 0u32;
    while !cur.at_end() && n < 64 {
        let item = read_item(&mut cur).await?;
        let slot = match item.key.to_ascii_lowercase().as_str() {
            "artist" => &mut artist,
            "title" => &mut title,
            _ => {
                n = n.saturating_add(1);
                continue;
            }
        };
        let data = cx.read_avail(item.value.sub(0, 256)).await?;
        *slot = Some(decode_text(&data));
        n = n.saturating_add(1);
    }
    Ok(match (artist, title) {
        (Some(a), Some(t)) => Some(format!("{a} – {t}")),
        (a, t) => a.or(t),
    })
}
