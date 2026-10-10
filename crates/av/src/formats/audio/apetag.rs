//! APEv1/APEv2 tags, found at the end of Monkey's Audio, WavPack, Musepack
//! and some MP3 files (before an ID3v1 tag, if there is one).
//!
//! A tag is an optional 32-byte header, items (value size, flags, a
//! NUL-terminated key, the value) and a 32-byte footer that repeats the
//! header. Values are UTF-8 text (several values separated by NULs),
//! binary data (cover art: a file name, a NUL, the image) or locators.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::Input;
use crate::formats::util::arcutil::human_size;
use crate::formats::util::sound::{clip, decode_text, image_info, leaf, text};
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

const ITEM_FLAGS: FlagTable = &[
    flag(0x1, "READ_ONLY"),
    field(0x6, 0x2, "BINARY"),
    field(0x6, 0x4, "LOCATOR"),
];

const ITEM_KIND: EnumTable = &[
    (0, "UTF-8 text"),
    (1, "binary"),
    (2, "external locator"),
    (3, "reserved"),
];

record! {
    pub struct Footer {
        magic: ascii[8] "Preamble",
        version: u32 "Version" .with(|&v, n| n.summary(match v { 1000 => "APEv1", 2000 => "APEv2", _ => "unknown version" })),
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
    let version = u32_le(&footer, 8).unwrap_or(0);
    // APEv1 has no header (and its flags field is zero).
    let header = if version >= 2000 && flags & 0x8000_0000 != 0 {
        Footer::SIZE
    } else {
        0
    };
    if size < Footer::SIZE {
        return Ok(None);
    }
    let total = size.saturating_add(header);
    let Some(start) = end.checked_sub(total) else {
        return Ok(None);
    };
    Ok(Some(span.sub(start, total)))
}

/// A lazy node for the APE tag at `span`.
pub async fn node(cx: &Cx, input: Input, span: Span) -> Node {
    let footer = cx
        .read_avail(span.sub(span.len.saturating_sub(Footer::SIZE), Footer::SIZE))
        .await
        .unwrap_or_default();
    let version = u32_le(&footer, 8).unwrap_or(0);
    let items = u32_le(&footer, 16).unwrap_or(0);
    let mut summary = format!(
        "APEv{}, {}, {}",
        version / 1000,
        crate::formats::util::arcutil::count(items.into(), "item", "items"),
        human_size(span.len)
    );
    match scan(cx, span).await {
        Ok(s) => {
            let mut parts = Vec::new();
            if let Some(t) = s.title() {
                let extra: Vec<String> = [s.album, s.year].into_iter().flatten().collect();
                if extra.is_empty() {
                    parts.push(t);
                } else {
                    parts.push(format!("{t} ({})", extra.join(", ")));
                }
            }
            if let Some(t) = s.track {
                parts.push(format!("track {t}"));
            }
            if let Some(c) = s.cover {
                parts.push(format!("cover {c}"));
            }
            if !parts.is_empty() {
                summary.push_str(&format!(": {}", parts.join(", ")));
            }
        }
        Err(e) => return Node::new("APE tag").span(span).summary(summary).diag(e),
    }
    Node::new("APE tag")
        .span(span)
        .summary(summary)
        .lazy(expand, (input, span))
}

async fn expand(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let footer_span = span.sub(span.len.saturating_sub(Footer::SIZE), Footer::SIZE);
    let footer = crate::fields::parse(&cx, footer_span, LE, &(), Footer::layout).await?;
    let has_header = footer.version >= 2000 && footer.flags & 0x8000_0000 != 0;
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
            .lazy(expand_items, (input, items, footer.items, footer.version)),
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
    if u64::from(size) > cur.remaining() {
        return Err(Diagnostic::malformed(format!(
            "item {key:?} claims {size} bytes, more than the tag holds"
        )));
    }
    let value = cur.span(size.into());
    cur.skip(size.into());
    Ok(Item {
        key,
        flags,
        span: cur.since(start),
        value,
    })
}

/// The kind of an item's value (APEv1 items are all text).
fn kind(flags: u32, version: u32) -> u32 {
    if version < 2000 { 0 } else { (flags >> 1) & 3 }
}

async fn expand_items(
    cx: Cx,
    (input, region, count, version): (Input, Span, u32, u32),
) -> Result<()> {
    cx.set_count(Count::Exact(count.into()));
    let mut cur = Cursor::new(&cx, region, LE);
    for _ in 0..count {
        if cur.at_end() {
            break;
        }
        let at = cur.pos();
        let item = match read_item(&mut cur).await {
            Ok(item) => item,
            Err(e) => {
                cx.push(Node::new("Unparsed data").span(region.tail(at)).diag(e))
                    .await;
                return Ok(());
            }
        };
        let kind = kind(item.flags, version);
        let mut node = Node::new(item.key.clone()).span(item.span);
        if kind == 1 {
            let data = cx.read_avail(item.value.sub(0, 0x10000)).await?;
            let name_len = data.iter().position(|&b| b == 0);
            let image = name_len.and_then(|n| data.get(n.saturating_add(1)..));
            node = node.summary(match image.and_then(image_info) {
                Some(info) => format!("{info}, {}", human_size(item.value.len)),
                None => format!("binary, {}", human_size(item.value.len)),
            });
        } else {
            let data = cx.read_avail(item.value.sub(0, 256)).await?;
            let values: Vec<String> = data
                .split(|&b| b == 0)
                .map(decode_text)
                .filter(|s| !s.is_empty())
                .collect();
            node = node.summary(clip(&values.join(" / "), 60));
        }
        cx.push(node.lazy(item_fields, (input, item.span, item.value, kind)))
            .await;
    }
    if !cur.at_end() {
        cx.push(
            Node::new("Unparsed data")
                .span(region.tail(cur.pos()))
                .diag(Diagnostic::warning("bytes after the last item")),
        )
        .await;
    }
    Ok(())
}

async fn item_fields(cx: Cx, (input, span, value, kind): (Input, Span, Span, u32)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &block, LE);
    f.u32("Value size").emit()?;
    f.u32("Flags")
        .flags(ITEM_FLAGS)
        .with(|_, n| n.summary(crate::value::lookup(ITEM_KIND, kind.into()).unwrap_or("reserved")))
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
        let data = cx.read_avail(value.sub(0, 0x10000)).await?;
        let name_len = data.iter().position(|&b| b == 0).map(to_u64);
        match name_len {
            Some(n) => {
                cx.emit(leaf(
                    "File name",
                    value.sub(0, n.saturating_add(1)),
                    text(decode_text(data.get(..to_usize(n)).unwrap_or_default())),
                ));
                let image = value.tail(n.saturating_add(1));
                let info = data
                    .get(to_usize(n).saturating_add(1)..)
                    .and_then(image_info);
                cx.emit(
                    crate::formats::embedded("Data", input.nested(image)).summary(match info {
                        Some(i) => format!("{i}, {}", human_size(image.len)),
                        None => human_size(image.len),
                    }),
                );
            }
            None => cx.emit(Node::new("Data").span(value).summary(human_size(value.len))),
        }
        return Ok(());
    }
    let data = cx.read(value.sub(0, value.len.min(1 << 16))).await?;
    let name = if kind == 2 { "Locator" } else { "Value" };
    // APEv2 lists several values separated by NULs.
    let parts: Vec<&[u8]> = data.split(|&b| b == 0).collect();
    if parts.len() <= 1 {
        cx.emit(leaf(name, value, text(decode_text(&data))));
        return Ok(());
    }
    let mut at = 0u64;
    for (i, part) in parts.into_iter().enumerate() {
        let len = to_u64(part.len());
        cx.emit(leaf(
            format!("{name} {}", i.saturating_add(1)),
            value.sub(at, len),
            text(decode_text(part)),
        ));
        at = at.saturating_add(len).saturating_add(1);
    }
    Ok(())
}

/// What the tag's summary shows.
#[derive(Default)]
struct Scan {
    artist: Option<String>,
    title: Option<String>,
    album: Option<String>,
    year: Option<String>,
    track: Option<String>,
    cover: Option<String>,
}

impl Scan {
    fn title(&self) -> Option<String> {
        match (&self.artist, &self.title) {
            (Some(a), Some(t)) => Some(format!("{a} – {t}")),
            (a, t) => a.clone().or_else(|| t.clone()),
        }
    }
}

async fn scan(cx: &Cx, span: Span) -> Result<Scan> {
    let footer = cx
        .read_avail(span.sub(span.len.saturating_sub(Footer::SIZE), Footer::SIZE))
        .await?;
    let version = u32_le(&footer, 8).unwrap_or(0);
    let items = span.sub(0, span.len.saturating_sub(Footer::SIZE));
    let mut cur = Cursor::new(cx, items, LE);
    if cur.peek(8).await? == MAGIC {
        cur.skip(Footer::SIZE);
    }
    let mut s = Scan::default();
    let mut n = 0u32;
    while !cur.at_end() && n < 64 {
        n = n.saturating_add(1);
        let item = read_item(&mut cur).await?;
        let key = item.key.to_ascii_lowercase();
        if key.starts_with("cover art") && kind(item.flags, version) == 1 {
            if s.cover.is_none() || key == "cover art (front)" {
                let data = cx.read_avail(item.value.sub(0, 0x10000)).await?;
                let image = data
                    .iter()
                    .position(|&b| b == 0)
                    .and_then(|p| data.get(p.saturating_add(1)..));
                s.cover = image.and_then(image_info).or(s.cover);
            }
            continue;
        }
        let slot = match key.as_str() {
            "artist" => &mut s.artist,
            "title" => &mut s.title,
            "album" => &mut s.album,
            "year" => &mut s.year,
            "track" => &mut s.track,
            _ => continue,
        };
        let data = cx.read_avail(item.value.sub(0, 256)).await?;
        let first = data.split(|&b| b == 0).next().unwrap_or_default();
        *slot = Some(decode_text(first));
    }
    Ok(s)
}

/// "Artist – Title" from the tag's items.
pub async fn title(cx: &Cx, span: Span) -> Result<Option<String>> {
    Ok(scan(cx, span).await?.title())
}
