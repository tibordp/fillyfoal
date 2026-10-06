//! xar archives (macOS installer packages, Safari extensions).
//!
//! A big-endian header, a zlib-compressed XML table of contents, and a heap.
//! The TOC lists files with their heap offsets, sizes and encodings; it is
//! decompressed when the file list is expanded and scanned for `<file>`
//! elements. Member data is decompressed (zlib, bzip2, xz, LZMA) or
//! dissected in place.

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::codec::inflate_span;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::arcutil::{count, emit_nodes, human_size, text, uint, unsupported};
use crate::formats::{Codec, Format, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "xar",
    title: "xar archive",
    extensions: &["xar", "pkg", "xip", "safariextz"],
    mime: "application/x-xar",
    probe: Probe::Magic(&[(0, b"xar!\x00\x1c"), (0, b"xar!\x00\x40")]),
    dissect: crate::expander!(dissect: Input),
};

const CHECKSUM: EnumTable = &[(0, "none"), (1, "SHA-1"), (2, "MD5"), (3, "other (named)")];

record! {
    pub struct Header {
        magic: ascii[4] "Magic",
        size: u16 "Header size",
        version: u16 "Version",
        toc_compressed: u64 "TOC compressed size" .with(|&s, n| n.summary(human_size(s))),
        toc_uncompressed: u64 "TOC uncompressed size" .with(|&s, n| n.summary(human_size(s))),
        checksum: u32 "Checksum algorithm" .enumeration(CHECKSUM),
    }
}

fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let h = Header::read(f)?;
    if h.checksum == 3 && h.size > 28 {
        f.cstr("Checksum name").emit()?;
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = crate::fields::parse(&cx, file.sub(0, Header::SIZE), BE, &(), Header::layout).await?;
    let header_span = file.sub(0, h.size.into());
    cx.emit(struct_node("Header", header_span, BE, (), header_layout));
    let toc = file.sub(h.size.into(), h.toc_compressed);
    let heap = file.tail(u64::from(h.size).saturating_add(h.toc_compressed));
    cx.emit(
        Node::new("Files")
            .span(toc)
            .lazy(files, (input, toc, h.toc_uncompressed, heap)),
    );
    cx.emit(
        content(
            "Table of contents",
            input,
            toc,
            Codec::Zlib,
            Some(h.toc_uncompressed),
        )
        .summary(format!("XML, {} compressed", human_size(toc.len))),
    );
    cx.emit(Node::new("Heap").span(heap).summary(human_size(heap.len)));
    cx.annotate(format!(
        "xar archive, TOC {} ({} compressed)",
        human_size(h.toc_uncompressed),
        human_size(h.toc_compressed)
    ));
    Ok(())
}

/// A `<file>` element of the TOC.
#[derive(Clone, Debug, Default)]
struct Entry {
    parent: Option<usize>,
    name: String,
    kind: String,
    offset: Option<u64>,
    length: Option<u64>,
    size: Option<u64>,
    encoding: String,
    mode: String,
    mtime: String,
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The value of attribute `name` in a start tag's text.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let key = format!("{name}=\"");
    let start = tag.find(&key)?.checked_add(key.len())?;
    let rest = tag.get(start..)?;
    let end = rest.find('"')?;
    Some(unescape(rest.get(..end)?))
}

/// A minimal scan of the TOC: elements, their nesting and leaf text.
fn scan(xml: &str) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut open: Vec<usize> = Vec::new(); // indices of open <file> elements
    let mut path: Vec<String> = Vec::new(); // element names
    let mut rest = xml;
    let mut text_start: Option<&str> = None;
    while let Some(lt) = rest.find('<') {
        let before = rest.get(..lt).unwrap_or_default();
        let Some(gt) = rest.get(lt..).and_then(|r| r.find('>')) else {
            break;
        };
        let tag = rest
            .get(lt.saturating_add(1)..lt.saturating_add(gt))
            .unwrap_or_default();
        rest = rest
            .get(lt.saturating_add(gt).saturating_add(1)..)
            .unwrap_or_default();
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        if let Some(end) = tag.strip_prefix('/') {
            let name = end.trim();
            let value = text_start.take().map(|_| unescape(before.trim()));
            if let (Some(v), Some(&i)) = (value, open.last()) {
                let in_data = path.iter().rev().nth(1).is_some_and(|p| p == "data");
                let parent_is_file = path.iter().rev().nth(1).is_some_and(|p| p == "file");
                if let Some(e) = entries.get_mut(i) {
                    match name {
                        "name" if parent_is_file => e.name = v,
                        "type" if parent_is_file => e.kind = v,
                        "mode" if parent_is_file => e.mode = v,
                        "mtime" if parent_is_file => e.mtime = v,
                        "offset" if in_data => e.offset = v.parse().ok(),
                        "length" if in_data => e.length = v.parse().ok(),
                        "size" if in_data => e.size = v.parse().ok(),
                        _ => {}
                    }
                }
            }
            if name == "file" {
                open.pop();
            }
            path.pop();
            continue;
        }
        let self_closing = tag.ends_with('/');
        let name = tag
            .trim_end_matches('/')
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        if name == "encoding"
            && path.last().is_some_and(|p| p == "data")
            && let (Some(style), Some(&i)) = (attribute(tag, "style"), open.last())
            && let Some(e) = entries.get_mut(i)
        {
            e.encoding = style;
        }
        if self_closing {
            continue;
        }
        if name == "file" {
            entries.push(Entry {
                parent: open.last().copied(),
                ..Entry::default()
            });
            open.push(entries.len().saturating_sub(1));
        }
        path.push(name);
        text_start = Some(rest);
    }
    entries
}

fn full_path(entries: &[Entry], i: usize) -> String {
    let mut parts = Vec::new();
    let mut cur = Some(i);
    while let Some(c) = cur {
        let Some(e) = entries.get(c) else {
            break;
        };
        parts.push(e.name.as_str());
        cur = e.parent.filter(|&p| p < c);
        if parts.len() > 256 {
            break;
        }
    }
    parts.reverse();
    parts.join("/")
}

async fn files(cx: Cx, (input, toc, expected, heap): (Input, Span, u64, Span)) -> Result<()> {
    let decoded = inflate_span(&cx, toc, true, Some(expected)).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    let xml = cx.read(decoded.span).await?;
    let xml = String::from_utf8_lossy(&xml);
    let entries = scan(&xml);
    cx.set_count(Count::Exact(to_u64(entries.len())));
    cx.annotate(count(to_u64(entries.len()), "entry", "entries"));
    for (i, e) in entries.iter().enumerate() {
        let path = full_path(&entries, i);
        let mut children = vec![Node::new("Type").value(text(e.kind.clone()))];
        if !e.mode.is_empty() {
            let mode = u64::from_str_radix(&e.mode, 8).unwrap_or(0);
            children.push(
                Node::new("Mode")
                    .value(text(e.mode.clone()))
                    .summary(crate::formats::arcutil::unix_mode(mode)),
            );
        }
        if !e.mtime.is_empty() {
            children.push(Node::new("Modification time").value(text(e.mtime.clone())));
        }
        let mut node = Node::new(path);
        if let (Some(offset), Some(length)) = (e.offset, e.length) {
            let data = heap.sub(offset, length);
            let size = e.size.unwrap_or(length);
            children.push(Node::new("Heap offset").value(uint(offset)).target(data));
            children.push(Node::new("Encoding").value(text(e.encoding.clone())));
            let c = match e.encoding.as_str() {
                "application/x-gzip" => content("Content", input, data, Codec::Zlib, Some(size)),
                "application/octet-stream" => embedded("Content", input.nested(data)),
                "application/x-bzip2" => content("Content", input, data, Codec::Bzip2, Some(size)),
                "application/x-xz" => content("Content", input, data, Codec::Xz, Some(size)),
                // xar's "lzma" is written by liblzma's easy encoder (an .xz
                // stream); older writers used `.lzma`.
                "application/x-lzma" => Node::new("Content")
                    .span(data)
                    .lazy(lzma_content, (input, data, size)),
                other => unsupported("Content", data, other),
            };
            children.push(c.summary(human_size(size)));
            node = node.span(data).summary(human_size(size));
        } else {
            node = node.summary(e.kind.clone());
        }
        cx.push(node.lazy(emit_nodes, Arc::new(children))).await;
    }
    Ok(())
}

/// Expander for `application/x-lzma` members: an `.xz` stream or, from
/// older writers, `.lzma`.
async fn lzma_content(cx: Cx, (input, data, size): (Input, Span, u64)) -> Result<()> {
    let magic = cx.read_avail(data.sub(0, 6)).await?;
    let codec = if magic == b"\xfd7zXZ\x00" { Codec::Xz } else { Codec::LzmaAlone };
    let decoded = crate::codec::decode_span(&cx, data, &codec, Some(size)).await?;
    cx.annotate(format!("{:#x} bytes {}", decoded.span.len, codec.verb()));
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    crate::formats::dissect_or_data(cx, input.nested(decoded.span)).await
}
