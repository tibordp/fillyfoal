//! macOS bookmark data (`book`): the format behind `NSURL` bookmarks, Finder
//! aliases since 10.6, and many plist-embedded file references.
//!
//! A header is followed by a data area of typed items (strings, numbers,
//! dates, arrays, dictionaries, URLs) and one or more tables of contents
//! mapping well-known keys (path components, volume name, creation date,
//! ...) to items. Offsets are relative to the data area.

use crate::bytes::{to_u64, u32_le, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::datakit::{cf_time, clip, hex_string};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const MAX_DEPTH: u32 = 16;
const MAX_TOCS: u32 = 64;

pub static FORMAT: Format = Format {
    name: "bookmark",
    title: "macOS bookmark data",
    extensions: &["bookmark"],
    mime: "application/octet-stream",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// `book`, the total length, and a sane header size.
fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"book")
        && u32_le(h.data, 4).is_some_and(|n| u64::from(n) == h.len)
        && u32_le(h.data, 12).is_some_and(|n| (16..=0x100).contains(&n))
}

const KEYS: EnumTable = &[
    (0x1003, "Target flags"),
    (0x1004, "Path"),
    (0x1005, "File IDs"),
    (0x1010, "Resource properties"),
    (0x1020, "File name"),
    (0x1040, "Creation date"),
    (0x1054, "Unknown (0x1054)"),
    (0x1055, "Unknown (0x1055)"),
    (0x1056, "Unknown (0x1056)"),
    (0x1101, "Unknown (0x1101)"),
    (0x1102, "Unknown (0x1102)"),
    (0x2000, "Volume info"),
    (0x2002, "Volume path"),
    (0x2005, "Volume URL"),
    (0x2010, "Volume name"),
    (0x2011, "Volume UUID"),
    (0x2012, "Volume size"),
    (0x2013, "Volume creation date"),
    (0x2020, "Volume properties"),
    (0x2030, "Volume was boot"),
    (0x2040, "Volume bookmark"),
    (0x2050, "Volume mount point"),
    (0xc001, "Containing folder index"),
    (0xc011, "Creator user name"),
    (0xc012, "Creator UID"),
    (0xd001, "Was file reference"),
    (0xd010, "Creation options"),
    (0xe003, "URL length array"),
    (0xf017, "Display name"),
    (0xf020, "Effective icon data"),
    (0xf022, "Type bindings"),
    (0xf030, "Unknown (0xf030)"),
    (0xf080, "Security extension (read-write)"),
    (0xf081, "Security extension (read-only)"),
];

const TYPES: EnumTable = &[
    (0x0101, "string"),
    (0x0201, "data"),
    (0x0301, "int8"),
    (0x0302, "int16"),
    (0x0303, "int32"),
    (0x0304, "int64"),
    (0x0305, "float32"),
    (0x0306, "float64"),
    (0x0400, "date"),
    (0x0500, "false"),
    (0x0501, "true"),
    (0x0601, "array"),
    (0x0701, "dictionary"),
    (0x0801, "UUID"),
    (0x0901, "URL"),
    (0x0902, "relative URL"),
];

#[derive(Clone, Copy, Debug)]
struct Book {
    data: Span,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let header_size = {
        let mut f = Fields::emitting(&cx, &head, LE);
        f.ascii("Magic", 4).emit()?;
        f.u32("Total length").emit()?;
        f.u32("Version").hex().emit()?;
        f.u32("Header size").hex().emit()?
    };
    let data = file.tail(header_size.into());
    let book = Book { data };
    let first = cx.read(data.sub_exact(0, 4)?).await?;
    let mut toc = u32_le(&first, 0).unwrap_or(0);
    cx.emit(
        Node::new("First TOC offset")
            .span(data.sub(0, 4))
            .value(crate::formats::util::datakit::hex(toc, 32)),
    );
    let mut path = Vec::new();
    let mut volume = None;
    let mut seen = 0u32;
    while toc != 0 && seen < MAX_TOCS {
        seen = seen.saturating_add(1);
        let span = data.sub_exact(toc.into(), 20)?;
        let h = cx.read(span).await?;
        if u32_le(&h, 4) != Some(0xffff_fffe) {
            return Err(Diagnostic::malformed("bad table of contents").at(span));
        }
        let id = u32_le(&h, 8).unwrap_or(0);
        let next = u32_le(&h, 12).unwrap_or(0);
        let count = u32_le(&h, 16).unwrap_or(0);
        let entries = data.sub_exact(
            u64::from(toc).saturating_add(20),
            u64::from(count).saturating_mul(12),
        )?;
        if seen == 1 {
            let table = cx.read(entries).await?;
            for (i, e) in table.as_chunks::<12>().0.iter().enumerate() {
                if i.is_multiple_of(256) {
                    cx.checkpoint().await;
                }
                let key = u32_le(e, 0).unwrap_or(0);
                let off = u32_le(e, 4).unwrap_or(0);
                match key {
                    0x1004 => path = string_array(&cx, &book, off).await.unwrap_or_default(),
                    0x2010 => volume = string_at(&cx, &book, off).await.ok().flatten(),
                    _ => {}
                }
            }
        }
        cx.emit(
            Node::new(format!("Table of contents {id}"))
                .span(data.sub(toc.into(), 20u64.saturating_add(entries.len)))
                .summary(format!("{count} entries"))
                .lazy(toc_entries, (book, entries)),
        );
        if next == toc {
            break;
        }
        toc = next;
    }
    let mut summary = String::from("macOS bookmark");
    if !path.is_empty() {
        summary = format!("{summary} → /{}", path.join("/"));
    }
    if let Some(v) = volume {
        summary = format!("{summary} on {v:?}");
    }
    cx.annotate(summary);
    Ok(())
}

/// The item header at `offset`: length, type and the item's data span.
async fn item(cx: &Cx, book: &Book, offset: u32) -> Result<(u32, Span, Span)> {
    let head = book.data.sub_exact(offset.into(), 8)?;
    let h = cx.read(head).await?;
    let len = u32_le(&h, 0).unwrap_or(0);
    let kind = u32_le(&h, 4).unwrap_or(0);
    let body = book
        .data
        .sub_exact(u64::from(offset).saturating_add(8), len.into())?;
    Ok((
        kind,
        body,
        book.data
            .sub(offset.into(), u64::from(len).saturating_add(8)),
    ))
}

async fn string_at(cx: &Cx, book: &Book, offset: u32) -> Result<Option<String>> {
    let (kind, body, _) = item(cx, book, offset).await?;
    if kind != 0x0101 {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&cx.read(body.sub(0, 0x1000)).await?).into_owned(),
    ))
}

async fn string_array(cx: &Cx, book: &Book, offset: u32) -> Result<Vec<String>> {
    let (kind, body, _) = item(cx, book, offset).await?;
    if kind != 0x0601 {
        return Ok(Vec::new());
    }
    let offsets = cx.read(body.sub(0, 0x1000)).await?;
    let mut out = Vec::new();
    for o in offsets.as_chunks::<4>().0 {
        if let Some(s) = string_at(cx, book, u32::from_le_bytes(*o)).await? {
            out.push(s);
        }
    }
    Ok(out)
}

async fn toc_entries(cx: Cx, (book, entries): (Book, Span)) -> Result<()> {
    let table = cx.read(entries).await?;
    for (i, e) in table.as_chunks::<12>().0.iter().enumerate() {
        let key = u32_le(e, 0).unwrap_or(0);
        let off = u32_le(e, 4).unwrap_or(0);
        let name =
            lookup(KEYS, key.into()).map_or_else(|| format!("Key {key:#06x}"), str::to_owned);
        let node = item_node(&cx, &book, name, off, 0)
            .await
            .unwrap_or_else(|e| Node::new(format!("Key {key:#06x}")).diag(e));
        cx.push(node.target(entries.sub(to_u64(i).saturating_mul(12), 12)))
            .await;
    }
    Ok(())
}

/// A node for the item at `offset`, with containers expandable.
async fn item_node(cx: &Cx, book: &Book, name: String, offset: u32, depth: u32) -> Result<Node> {
    let (kind, body, span) = item(cx, book, offset).await?;
    let bytes = cx.read(body.sub(0, 0x1000)).await?;
    let node = Node::new(name).span(span);
    let type_name =
        lookup(TYPES, kind.into()).map_or_else(|| format!("type {kind:#06x}"), str::to_owned);
    let num = |n: usize| crate::formats::util::datakit::le_uint(bytes.get(..n).unwrap_or_default());
    let value = match kind {
        0x0101 | 0x0901 => Some(Value::Text(String::from_utf8_lossy(&bytes).into_owned())),
        0x0201 => Some(Value::Bytes(bytes.get(..32).unwrap_or(&bytes).to_vec())),
        0x0301 => Some(Value::Int {
            value: i64::from(num(1) as u8 as i8),
            bits: 8,
        }),
        0x0302 => Some(Value::Int {
            value: i64::from(num(2) as u16 as i16),
            bits: 16,
        }),
        0x0303 => Some(Value::Int {
            value: i64::from(num(4) as u32 as i32),
            bits: 32,
        }),
        0x0304 => Some(Value::Int {
            value: num(8) as i64,
            bits: 64,
        }),
        0x0305 => Some(Value::Float(f64::from(f32::from_bits(num(4) as u32)))),
        0x0306 => Some(Value::Float(f64::from_bits(num(8)))),
        0x0400 => Some(cf_time(f64::from_bits(u64_be(&bytes, 0).unwrap_or(0)))),
        0x0500 => Some(Value::Bool(false)),
        0x0501 => Some(Value::Bool(true)),
        0x0801 => Some(Value::Text(hex_string(&bytes))),
        _ => None,
    };
    let mut node = match value {
        Some(Value::Text(t)) => node.value(Value::Text(clip(&t, 400))),
        Some(v) => node.value(v),
        None => node,
    };
    node = node.summary(format!("{type_name}, {} bytes", body.len));
    if matches!(kind, 0x0601 | 0x0701 | 0x0902) {
        if depth >= MAX_DEPTH {
            return Ok(node.diag(Diagnostic::limit("items nested too deeply")));
        }
        node = node.lazy(
            crate::expander!(self::container: (Book, u32, Span, u32)),
            (*book, kind, body, depth.saturating_add(1)),
        );
    }
    Ok(node)
}

async fn container(cx: Cx, (book, kind, body, depth): (Book, u32, Span, u32)) -> Result<()> {
    let data = cx.read(body.sub(0, 0x10000)).await?;
    let offsets: Vec<u32> = data
        .as_chunks::<4>()
        .0
        .iter()
        .map(|o| u32::from_le_bytes(*o))
        .collect();
    match kind {
        0x0701 => {
            for pair in offsets.chunks(2) {
                let (Some(&k), Some(&v)) = (pair.first(), pair.get(1)) else {
                    break;
                };
                let key = string_at(&cx, &book, k)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| format!("key at {k:#x}"));
                let node = (item_node(&cx, &book, clip(&key, 120), v, depth)).await;
                cx.push(node.unwrap_or_else(|e| Node::new(key).diag(e)))
                    .await;
            }
        }
        0x0902 => {
            for (name, &o) in ["Base", "Relative"].into_iter().zip(&offsets) {
                let node = (item_node(&cx, &book, name.to_owned(), o, depth)).await;
                cx.push(node.unwrap_or_else(|e| Node::new(name).diag(e)))
                    .await;
            }
        }
        _ => {
            for (i, &o) in offsets.iter().enumerate() {
                let node = (item_node(&cx, &book, format!("[{i}]"), o, depth)).await;
                cx.push(node.unwrap_or_else(|e| Node::new(format!("[{i}]")).diag(e)))
                    .await;
            }
        }
    }
    Ok(())
}
