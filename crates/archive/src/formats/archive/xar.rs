//! xar archives (macOS installer packages, Safari extensions).
//!
//! A big-endian header, a zlib-compressed XML table of contents, and a heap.
//! The TOC lists files with their heap offsets, sizes and encodings; it is
//! decompressed when the file list is expanded and scanned for `<file>`
//! elements. Member data is decompressed (zlib, `.lzma`) or dissected in
//! place (raw, and bzip2/xz streams, whose dissectors decompress them).

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::codec::inflate_span;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::text::decode::base64;
use crate::formats::text::scan::Owned;
use crate::formats::text::xml::{self, Kind, Lexer, Mode, Tok};
use crate::formats::util::arcutil::{emit_nodes, unsupported};
use crate::formats::util::fmt;
use crate::formats::util::fmt::count;
use crate::formats::util::val::{text, uint};
use crate::formats::{Codec, Format, Input, Probe, content, embedded, embedded_named};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
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
        toc_compressed: u64 "TOC compressed size" .with(|&s, n| n.summary(fmt::size(s))),
        toc_uncompressed: u64 "TOC uncompressed size" .with(|&s, n| n.summary(fmt::size(s))),
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
        .summary(format!("XML, {} compressed", fmt::size(toc.len))),
    );
    cx.emit(
        Node::new("Heap")
            .span(heap)
            .summary(fmt::size(heap.len))
            .lazy(heap_regions, (input, toc, h.toc_uncompressed, heap)),
    );
    cx.annotate(format!(
        "xar archive, TOC {} ({} compressed)",
        fmt::size(h.toc_uncompressed),
        fmt::size(h.toc_compressed)
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

/// A heap region the TOC describes outside the files: the TOC checksum or
/// a signature (`<checksum>`, `<signature>`, `<x-signature>`).
#[derive(Debug, Default)]
struct Region {
    /// The element: `checksum`, `signature` or `x-signature`.
    element: String,
    style: String,
    offset: Option<u64>,
    size: Option<u64>,
    /// Base64 `<X509Certificate>` texts of a signature's `<KeyInfo>`.
    certs: Vec<Owned>,
}

/// What the TOC says: files, and the TOC checksum and signatures.
#[derive(Debug, Default)]
struct Toc {
    entries: Vec<Entry>,
    regions: Vec<Region>,
}

/// The value of attribute `name` of start tag `t`, entities decoded.
async fn attribute(lex: &mut Lexer<'_>, t: &Tok, name: &[u8]) -> Result<Option<String>> {
    let tag = lex.owned(t, 4096).await?;
    Ok(xml::attributes(tag.piece())
        .into_iter()
        .find(|a| a.name.bytes() == name)
        .and_then(|a| a.value)
        .map(|v| xml::decode_entities(&v.text(), false)))
}

/// Walks the decompressed TOC (`xml`): `<file>` elements, their nesting and
/// leaf values, and the checksum and signature regions.
async fn parse_toc(cx: &Cx, xml: Span) -> Result<Toc> {
    let mut lex = Lexer::new(cx, xml, Mode::Xml);
    let mut toc = Toc::default();
    let mut open: Vec<usize> = Vec::new(); // indices of open <file> elements
    let mut path: Vec<Vec<u8>> = Vec::new(); // element names
    let mut region: Option<Region> = None;
    let mut value = String::new();
    let mut cert: Option<Owned> = None;
    loop {
        let t = lex.next().await?;
        match t.kind {
            Kind::Eof => break,
            Kind::Start => {
                let name = lex.name(&t).await?;
                let parent = path.last().map(Vec::as_slice);
                if name == b"encoding"
                    && parent == Some(b"data")
                    && let Some(&i) = open.last()
                    && let Some(style) = attribute(&mut lex, &t, b"style").await?
                    && let Some(e) = toc.entries.get_mut(i)
                {
                    e.encoding = style;
                }
                let starts_region = parent == Some(b"toc")
                    && matches!(name.as_slice(), b"checksum" | b"signature" | b"x-signature");
                if starts_region {
                    region = Some(Region {
                        element: String::from_utf8_lossy(&name).into_owned(),
                        style: attribute(&mut lex, &t, b"style").await?.unwrap_or_default(),
                        ..Region::default()
                    });
                }
                if t.empty {
                    if starts_region {
                        toc.regions.extend(region.take());
                    }
                    continue;
                }
                if name == b"file" {
                    toc.entries.push(Entry {
                        parent: open.last().copied(),
                        ..Entry::default()
                    });
                    open.push(toc.entries.len().saturating_sub(1));
                }
                path.push(name);
                value.clear();
                cert = None;
            }
            Kind::Text | Kind::Cdata => {
                if path.last().is_some_and(|n| n == b"X509Certificate") {
                    let len = to_usize(t.end.saturating_sub(t.start));
                    cert = Some(lex.owned(&t, len).await?);
                } else {
                    value.push_str(&xml::token_text(&mut lex, &t).await?);
                }
            }
            Kind::End => {
                let Some(name) = path.pop() else {
                    continue;
                };
                let parent = path.last().map(Vec::as_slice);
                let v = value.trim();
                if let Some(r) = region.as_mut() {
                    match name.as_slice() {
                        b"offset" if parent == Some(r.element.as_bytes()) => {
                            r.offset = v.parse().ok()
                        }
                        b"size" if parent == Some(r.element.as_bytes()) => r.size = v.parse().ok(),
                        b"X509Certificate" => r.certs.extend(cert.take()),
                        _ => {}
                    }
                    if parent == Some(b"toc") && name == r.element.as_bytes() {
                        toc.regions.extend(region.take());
                    }
                } else if let Some(e) = open.last().and_then(|&i| toc.entries.get_mut(i)) {
                    match (name.as_slice(), parent) {
                        (b"name", Some(b"file")) => e.name = v.to_owned(),
                        (b"type", Some(b"file")) => e.kind = v.to_owned(),
                        (b"mode", Some(b"file")) => e.mode = v.to_owned(),
                        (b"mtime", Some(b"file")) => e.mtime = v.to_owned(),
                        (b"offset", Some(b"data")) => e.offset = v.parse().ok(),
                        (b"length", Some(b"data")) => e.length = v.parse().ok(),
                        (b"size", Some(b"data")) => e.size = v.parse().ok(),
                        _ => {}
                    }
                }
                if name == b"file" {
                    open.pop();
                }
                value.clear();
            }
            _ => {}
        }
    }
    Ok(toc)
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

/// Decompresses and walks the TOC.
async fn read_toc(cx: &Cx, toc: Span, expected: u64) -> Result<Toc> {
    let decoded = inflate_span(cx, toc, true, Some(expected)).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    parse_toc(cx, decoded.span).await
}

/// Expander for the heap: the TOC checksum and the signatures the TOC
/// places there, with the signing certificates from its `<KeyInfo>`.
async fn heap_regions(
    cx: Cx,
    (input, toc, expected, heap): (Input, Span, u64, Span),
) -> Result<()> {
    let toc = read_toc(&cx, toc, expected).await?;
    for r in toc.regions {
        let title = match r.element.as_str() {
            "checksum" => "TOC checksum",
            "x-signature" => "Extra signature",
            _ => "Signature",
        };
        let mut node = Node::new(title).value(text(r.style.clone()));
        let mut cms = false;
        if let (Some(offset), Some(size)) = (r.offset, r.size) {
            let data = heap.sub(offset, size);
            // A CMS signature is a PKCS #7 SignedData; an RSA one is a bare
            // signature value.
            cms = r.style.eq_ignore_ascii_case("CMS");
            if cms {
                node = embedded_named(title, input.nested(data), "pkcs7");
            }
            node = node
                .span(data)
                .summary(format!("{}, {}", r.style, fmt::size(size)));
        }
        let mut certs = Vec::new();
        for (i, c) in r.certs.iter().enumerate() {
            let decoded = base64(&c.bytes);
            let name = format!("Certificate {i}");
            let origin = Origin {
                parent: c.span,
                transform: "base64",
            };
            let mut cert = match decoded.error {
                None => {
                    let der = cx.add_derived(origin, decoded.bytes, c.span.len, None)?;
                    embedded_named(name, input.nested(der.span), "x509")
                }
                Some(e) => Node::new(name).span(c.span).diag(Diagnostic::malformed(e)),
            };
            cert = cert.desc("X509Certificate from the TOC's KeyInfo (base64)");
            certs.push(cert);
        }
        if cms || certs.is_empty() {
            cx.push(node).await;
            for cert in certs {
                cx.push(cert).await;
            }
        } else {
            cx.push(node.lazy(emit_nodes, Arc::new(certs))).await;
        }
    }
    Ok(())
}

async fn files(cx: Cx, (input, toc, expected, heap): (Input, Span, u64, Span)) -> Result<()> {
    let entries = read_toc(&cx, toc, expected).await?.entries;
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
                    .summary(crate::formats::util::arcutil::unix_mode(mode)),
            );
        }
        if !e.mtime.is_empty() {
            children.push(Node::new("Modification time").value(text(e.mtime.clone())));
        }
        let mut node = Node::new(path);
        if let (Some(offset), Some(length)) = (e.offset, e.length) {
            let data = heap.sub(offset, length);
            let size = e.size.unwrap_or(length);
            children.push(
                Node::new("Heap offset")
                    .value(uint(offset, 64))
                    .target(data),
            );
            children.push(Node::new("Encoding").value(text(e.encoding.clone())));
            let c = match e.encoding.as_str() {
                "application/x-gzip" => content("Content", input, data, Codec::Zlib, Some(size)),
                // The bzip2 and xz dissectors show the stream and its content.
                "application/octet-stream" | "application/x-bzip2" | "application/x-xz" => {
                    embedded("Content", input.nested(data))
                }
                // xar's "lzma" is written by liblzma's easy encoder (an .xz
                // stream); older writers used `.lzma`.
                "application/x-lzma" => Node::new("Content")
                    .span(data)
                    .lazy(lzma_content, (input, data, size)),
                other => unsupported("Content", data, other),
            };
            children.push(c.summary(fmt::size(size)));
            node = node.span(data).summary(fmt::size(size));
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
    if magic == b"\xfd7zXZ\x00" {
        return crate::formats::dissect_or_data(cx, input.nested(data)).await;
    }
    let codec = Codec::LzmaAlone;
    let decoded = crate::codec::decode_span(&cx, data, &codec, Some(size)).await?;
    cx.annotate(format!("{:#x} bytes {}", decoded.span.len, codec.verb()));
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    crate::formats::dissect_or_data(cx, input.nested(decoded.span)).await
}
