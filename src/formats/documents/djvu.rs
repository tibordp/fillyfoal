//! DjVu documents: an IFF-style chunk tree after an `AT&T` prefix.
//!
//! - `FORM:DJVU` is a page: `INFO` (size, resolution, gamma, rotation),
//!   image layers (`Sjbz` JB2 or `Smmr` G4 masks, `BG44`/`FG44` IW44
//!   wavelets, `BGjp`/`FGjp` JPEG, `FGbz` foreground palette), `INCL`
//!   references to shared files, the hidden text layer (`TXTa`, or `TXTz`
//!   compressed) and annotations (`ANTa`/`ANTz`).
//! - `FORM:DJVM` is a multi-page document: a `DIRM` directory (component
//!   offsets for a bundled document, then BZZ-compressed sizes, types, ids,
//!   names and titles), an optional `NAVM` outline, and the component files
//!   (`FORM:DJVU` pages, `FORM:DJVI` shared data, `FORM:THUM` thumbnails).
//!   An *indirect* document has a directory only; its pages are separate
//!   files.
//!
//! Chunks start at even offsets of the file (a pad byte precedes a chunk
//! that would start odd). `INFO` stores width and height big-endian but the
//! resolution little-endian.
//!
//! Layouts follow DjVuLibre (`IFFByteStream`, `DjVuInfo`, `DjVmDir`,
//! `DjVmNav`, `DjVuText`, `DjVuAnno`, `DjVuPalette`, `IW44Image`) as
//! remembered, not a fetched specification; JB2, MMR and IW44 image data are
//! not decoded (their headers are shown). BZZ is [`crate::codec::bzz`].

use std::sync::Arc;

use crate::bytes::{u16_be, u16_le, u24_be, u32_be};
use crate::codec::{Codec, decode_span};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::{Input, Probe, content, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

declare_format!(pub DJVU = "djvu", "DjVu document", ["djvu", "djv"], "image/vnd.djvu",
    Probe::Magic(&[(0, b"AT&TFORM")]), djvu);

/// FORMs nested deeper than this are not expanded.
const MAX_FORM_DEPTH: u32 = 8;
/// Nesting limit for text zones, bookmarks and annotation lists.
const MAX_TREE_DEPTH: usize = 32;
/// Input bytes a parser scans between checkpoints.
const CHECK_BYTES: usize = 4096;

fn uint(value: impl Into<u64>, bits: u8) -> Value {
    Value::UInt {
        value: value.into(),
        bits,
        radix: Radix::Dec,
    }
}

fn hex(value: impl Into<u64>, bits: u8) -> Value {
    Value::UInt {
        value: value.into(),
        bits,
        radix: Radix::Hex,
    }
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn to_usize(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

fn lossy(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

/// `s` shortened to `max` characters for a summary, on one line.
fn snippet(s: &str, max: usize) -> String {
    let flat: String = s
        .trim_end()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() > max {
        let cut: String = flat.chars().take(max).collect();
        format!("{cut}…")
    } else {
        flat
    }
}

// ---------------------------------------------------------------------------
// Top level

async fn djvu(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)).desc("AT&T prefix"));
    let head = cx.read_avail(file.sub(4, 12)).await?;
    let kind = lossy(head.get(8..12).unwrap_or_default());
    let summary = match kind.as_str() {
        "DJVU" => {
            let info = cx.read_avail(file.sub(16, 18)).await?;
            match info.get(..4) {
                Some(b"INFO") => format!(
                    "single-page DjVu, {}",
                    info_summary(info.get(8..).unwrap_or_default())
                ),
                _ => "single-page DjVu".to_owned(),
            }
        }
        "DJVM" => match load_dir(&cx, file.sub(16, 0), file).await {
            Ok(Some(dir)) => {
                let pages = dir.files.iter().filter(|f| f.kind() == PAGE).count();
                let how = if dir.bundled { "bundled" } else { "indirect" };
                format!(
                    "{how} multi-page DjVu, {pages} page{}, {} file{}",
                    if pages == 1 { "" } else { "s" },
                    dir.files.len(),
                    if dir.files.len() == 1 { "" } else { "s" }
                )
            }
            _ => "multi-page DjVu".to_owned(),
        },
        "DJVI" => "shared DjVu data".to_owned(),
        "THUM" => "DjVu thumbnails".to_owned(),
        _ => "DjVu".to_owned(),
    };
    cx.annotate(summary);
    chunks(cx, (input, file.tail(4), None, 0)).await
}

/// State of a chunk walker: the file, the region, the multi-page directory
/// (if inside a `FORM:DJVM`) and the FORM depth.
type Walk = (Input, Span, Option<Arc<Dir>>, u32);

async fn chunks(cx: Cx, (input, span, dir, depth): Walk) -> Result<()> {
    let mut pos = cx.resume::<u64>().unwrap_or(0);
    while span.len.saturating_sub(pos) >= 8 {
        let at = pos;
        cx.mark(move || at);
        let head = cx.read(span.sub(pos, 8)).await?;
        let id = lossy(head.get(..4).unwrap_or_default());
        let len = u32_be(&head, 4).unwrap_or(0);
        let body = span.sub(pos.saturating_add(8), len.into());
        let mut next = pos.saturating_add(8).saturating_add(len.into());
        let whole = span.sub(pos, next.saturating_sub(pos));
        let mut node = chunk_node(&cx, input, &id, whole, body, dir.as_ref(), depth).await;
        if body.len < u64::from(len) {
            node = node.diag(Diagnostic::truncated(
                span.sub(pos.saturating_add(8), len.into()),
                body.len,
            ));
            next = span.len;
        }
        // The next chunk starts at an even offset of the file.
        let absolute = span
            .offset
            .saturating_add(next)
            .saturating_sub(input.span.offset);
        if absolute % 2 == 1 && next < span.len {
            next = next.saturating_add(1);
        }
        cx.progress_in(span, span.offset.saturating_add(next));
        cx.push(node).await;
        pos = next.max(pos.saturating_add(8));
    }
    if pos < span.len {
        cx.push(
            Node::new("Trailing data")
                .span(span.tail(pos))
                .summary(format!("{} bytes", span.len.saturating_sub(pos))),
        )
        .await;
    }
    Ok(())
}

const CHUNK_NAMES: &[(&str, &str)] = &[
    ("DIRM", "Multi-page directory"),
    ("NAVM", "Outline"),
    ("INFO", "Page information"),
    ("INCL", "Included file"),
    ("Sjbz", "JB2 bitonal mask"),
    ("Smmr", "G4 (MMR) bitonal mask"),
    ("BG44", "IW44 background"),
    ("FG44", "IW44 foreground"),
    ("BGjp", "JPEG background"),
    ("FGjp", "JPEG foreground"),
    ("FGbz", "Foreground colors"),
    ("TXTa", "Hidden text"),
    ("TXTz", "Hidden text (BZZ)"),
    ("ANTa", "Annotations"),
    ("ANTz", "Annotations (BZZ)"),
    ("Djbz", "Shared JB2 shapes"),
    ("TH44", "IW44 thumbnail"),
    ("CIDa", "Document identifier"),
];

async fn chunk_node(
    cx: &Cx,
    input: Input,
    id: &str,
    whole: Span,
    body: Span,
    dir: Option<&Arc<Dir>>,
    depth: u32,
) -> Node {
    let label = CHUNK_NAMES
        .iter()
        .find(|(k, _)| *k == id)
        .map_or("", |(_, n)| *n);
    let node = Node::new(id.to_owned()).span(whole);
    let size = format!("{} bytes", body.len);
    let plain = node.clone().summary(if label.is_empty() {
        size.clone()
    } else {
        format!("{label}, {size}")
    });
    match id {
        "FORM" => form_node(cx, input, whole, body, dir, depth).await,
        "INFO" => match cx.read_avail(body.sub(0, 10)).await {
            Ok(data) => node
                .summary(info_summary(&data))
                .lazy(info_fields, (body, data)),
            Err(e) => node.diag(e),
        },
        "DIRM" => plain.lazy(
            dirm_fields,
            (input, body, whole.offset.saturating_sub(input.span.offset)),
        ),
        "NAVM" => plain.lazy(outline, body),
        "INCL" => {
            let data = cx.read_avail(body.sub(0, 1024)).await.unwrap_or_default();
            let name = lossy(&data);
            let mut node = node
                .summary(format!("includes \"{}\"", snippet(&name, 80)))
                .value(Value::Text(name.clone()));
            if let Some(file) = dir.and_then(|d| d.files.iter().find(|f| f.id == name))
                && let Some(span) = file.chunk(input)
            {
                node = node.target(span);
            }
            node
        }
        "TXTa" | "TXTz" => plain.lazy(text_layer, (body, id == "TXTz")),
        "ANTa" | "ANTz" => plain.lazy(annotations, (body, id == "ANTz")),
        "BG44" | "FG44" | "TH44" => {
            let data = cx.read_avail(body.sub(0, 9)).await.unwrap_or_default();
            node.summary(format!("{label}, {}", iw44_summary(&data, body.len)))
                .lazy(iw44_fields, (body, data))
        }
        "BGjp" | "FGjp" => embedded(id.to_owned(), input.nested(body))
            .span(whole)
            .summary(format!("{label}, {size}")),
        "FGbz" => plain.lazy(palette, (input, body)),
        "Smmr" => {
            let data = cx.read_avail(body.sub(0, 8)).await.unwrap_or_default();
            if data.get(..3) == Some(b"MMR") {
                node.summary(format!(
                    "{label}, {}×{}, {size}",
                    u16_be(&data, 4).unwrap_or(0),
                    u16_be(&data, 6).unwrap_or(0)
                ))
                .lazy(mmr_fields, (body, data))
            } else {
                plain.diag(Diagnostic::malformed("no MMR signature").at(body.sub(0, 3)))
            }
        }
        _ => plain,
    }
}

// ---------------------------------------------------------------------------
// FORMs

async fn form_node(
    cx: &Cx,
    input: Input,
    whole: Span,
    body: Span,
    dir: Option<&Arc<Dir>>,
    depth: u32,
) -> Node {
    let kind = lossy(&cx.read_avail(body.sub(0, 4)).await.unwrap_or_default());
    let offset = whole.offset.saturating_sub(input.span.offset);
    let entry = dir.and_then(|d| d.files.iter().find(|f| f.offset == Some(offset)));
    let mut summary = match kind.as_str() {
        "DJVU" => "page".to_owned(),
        "DJVM" => "multi-page document".to_owned(),
        "DJVI" => "shared data".to_owned(),
        "THUM" => "thumbnails".to_owned(),
        _ => format!("FORM:{kind}"),
    };
    if let Some(file) = entry {
        summary = match file.page {
            Some(n) => format!("page {n}, \"{}\"", file.id),
            None => format!("{summary}, \"{}\"", file.id),
        };
        if let Some(title) = &file.title {
            summary = format!("{summary} ({title})");
        }
    }
    if kind == "DJVU" {
        let info = cx.read_avail(body.sub(4, 18)).await.unwrap_or_default();
        if info.get(..4) == Some(b"INFO") {
            summary = format!(
                "{summary}, {}",
                info_summary(info.get(8..).unwrap_or_default())
            );
        }
    }
    let node = Node::new(format!("FORM:{kind}"))
        .span(whole)
        .summary(format!("{summary}, {} bytes", body.len));
    if depth >= MAX_FORM_DEPTH {
        return node.diag(Diagnostic::limit("FORMs nested too deeply"));
    }
    let inner = body.tail(4);
    if kind == "DJVM" {
        node.lazy(
            crate::expander!(self::document: Walk),
            (input, inner, None, depth.saturating_add(1)),
        )
    } else {
        node.lazy(
            crate::expander!(self::chunks: Walk),
            (input, inner, dir.cloned(), depth.saturating_add(1)),
        )
    }
}

/// A `FORM:DJVM`: reads the directory, then walks the components.
async fn document(cx: Cx, (input, span, _, depth): Walk) -> Result<()> {
    let dir = match load_dir(&cx, span, input.span).await {
        Ok(dir) => dir,
        Err(e) => {
            cx.diag(e);
            None
        }
    };
    chunks(cx, (input, span, dir, depth)).await
}

// ---------------------------------------------------------------------------
// INFO

const ROTATIONS: &[(u8, &str)] = &[
    (1, "0°"),
    (6, "90° counter-clockwise"),
    (2, "180°"),
    (5, "90° clockwise"),
];

fn info_summary(data: &[u8]) -> String {
    let mut s = format!(
        "{}×{}",
        u16_be(data, 0).unwrap_or(0),
        u16_be(data, 2).unwrap_or(0)
    );
    if let Some(dpi) = u16_le(data, 6) {
        s = format!("{s}, {dpi} dpi");
    }
    if let Some(flags) = data.get(9)
        && let Some((_, r)) = ROTATIONS.iter().find(|(k, _)| *k == flags & 7)
        && *r != "0°"
    {
        s = format!("{s}, rotated {r}");
    }
    s
}

async fn info_fields(cx: Cx, (body, data): (Span, Vec<u8>)) -> Result<()> {
    if let Some(w) = u16_be(&data, 0) {
        cx.emit(Node::new("Width").span(body.sub(0, 2)).value(uint(w, 16)));
    }
    if let Some(h) = u16_be(&data, 2) {
        cx.emit(Node::new("Height").span(body.sub(2, 2)).value(uint(h, 16)));
    }
    if let (Some(&minor), Some(&major)) = (data.get(4), data.get(5)) {
        cx.emit(
            Node::new("Version")
                .span(body.sub(4, 2))
                .value(uint(u16::from(major) << 8 | u16::from(minor), 16))
                .desc("Minor byte, then major byte"),
        );
    }
    if let Some(dpi) = u16_le(&data, 6) {
        cx.emit(
            Node::new("Resolution")
                .span(body.sub(6, 2))
                .value(uint(dpi, 16))
                .summary(format!("{dpi} dpi"))
                .desc("Little-endian, unlike the other fields"),
        );
    }
    if let Some(&gamma) = data.get(8) {
        cx.emit(
            Node::new("Gamma")
                .span(body.sub(8, 1))
                .value(uint(gamma, 8))
                .summary(format!("{}.{}", gamma / 10, gamma % 10)),
        );
    }
    if let Some(&flags) = data.get(9) {
        let rotation = ROTATIONS
            .iter()
            .find(|(k, _)| *k == flags & 7)
            .map(|(_, r)| *r);
        cx.emit(
            Node::new("Flags")
                .span(body.sub(9, 1))
                .value(hex(flags, 8))
                .summary(format!("rotation {}", rotation.unwrap_or("0° (unset)"))),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Image chunk headers

fn iw44_summary(data: &[u8], len: u64) -> String {
    let serial = data.first().copied().unwrap_or(0);
    let slices = data.get(1).copied().unwrap_or(0);
    if serial == 0 && data.len() >= 8 {
        let major = data.get(2).copied().unwrap_or(0);
        format!(
            "{}, {}×{}, {slices} slices, {len} bytes",
            if major & 0x80 != 0 {
                "grayscale"
            } else {
                "color"
            },
            u16_be(data, 4).unwrap_or(0),
            u16_be(data, 6).unwrap_or(0)
        )
    } else {
        format!("part {serial}, {slices} slices, {len} bytes")
    }
}

async fn iw44_fields(cx: Cx, (body, data): (Span, Vec<u8>)) -> Result<()> {
    let serial = data.first().copied().unwrap_or(0);
    cx.emit(
        Node::new("Serial")
            .span(body.sub(0, 1))
            .value(uint(serial, 8)),
    );
    if let Some(&slices) = data.get(1) {
        cx.emit(
            Node::new("Slices")
                .span(body.sub(1, 1))
                .value(uint(slices, 8)),
        );
    }
    let mut at = 2u64;
    if serial == 0 && data.len() >= 8 {
        let major = data.get(2).copied().unwrap_or(0);
        cx.emit(
            Node::new("Major version")
                .span(body.sub(2, 1))
                .value(hex(major, 8))
                .summary(format!(
                    "{}, version {}",
                    if major & 0x80 != 0 {
                        "grayscale"
                    } else {
                        "color"
                    },
                    major & 0x7f
                )),
        );
        cx.emit(
            Node::new("Minor version")
                .span(body.sub(3, 1))
                .value(uint(data.get(3).copied().unwrap_or(0), 8)),
        );
        cx.emit(
            Node::new("Width")
                .span(body.sub(4, 2))
                .value(uint(u16_be(&data, 4).unwrap_or(0), 16)),
        );
        cx.emit(
            Node::new("Height")
                .span(body.sub(6, 2))
                .value(uint(u16_be(&data, 6).unwrap_or(0), 16)),
        );
        at = 8;
        if let Some(&delay) = data.get(8) {
            cx.emit(
                Node::new("Chroma delay")
                    .span(body.sub(8, 1))
                    .value(hex(delay, 8))
                    .desc("Low 7 bits: slices before chroma; bit 7: half-resolution chroma"),
            );
            at = 9;
        }
    }
    cx.emit(
        Node::new("Wavelet data")
            .span(body.tail(at))
            .summary(format!(
                "{} bytes (not decoded)",
                body.len.saturating_sub(at)
            )),
    );
    Ok(())
}

async fn mmr_fields(cx: Cx, (body, data): (Span, Vec<u8>)) -> Result<()> {
    cx.emit(
        Node::new("Signature")
            .span(body.sub(0, 3))
            .value(Value::Text("MMR".into())),
    );
    if let Some(&flags) = data.get(3) {
        let mut set = Vec::new();
        if flags & 1 != 0 {
            set.push("inverted");
        }
        if flags & 2 != 0 {
            set.push("striped");
        }
        cx.emit(
            Node::new("Flags")
                .span(body.sub(3, 1))
                .value(hex(flags, 8))
                .summary(if set.is_empty() {
                    "none".to_owned()
                } else {
                    set.join(", ")
                }),
        );
    }
    cx.emit(
        Node::new("Width")
            .span(body.sub(4, 2))
            .value(uint(u16_be(&data, 4).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("Height")
            .span(body.sub(6, 2))
            .value(uint(u16_be(&data, 6).unwrap_or(0), 16)),
    );
    cx.emit(Node::new("G4 data").span(body.tail(8)).summary(format!(
        "{} bytes (not decoded)",
        body.len.saturating_sub(8)
    )));
    Ok(())
}

/// `FGbz`: a palette (BGR triples) and optionally BZZ-compressed 16-bit
/// color indices, one per JB2 blit.
async fn palette(cx: Cx, (input, body): (Input, Span)) -> Result<()> {
    let head = cx.read(body.sub(0, 3)).await?;
    let version = head.first().copied().unwrap_or(0);
    let count = u16_be(&head, 1).unwrap_or(0);
    cx.emit(
        Node::new("Version")
            .span(body.sub(0, 1))
            .value(hex(version, 8))
            .summary(format!(
                "version {}{}",
                version & 0x7f,
                if version & 0x80 != 0 {
                    ", with color indices"
                } else {
                    ""
                }
            )),
    );
    cx.emit(
        Node::new("Palette size")
            .span(body.sub(1, 2))
            .value(uint(count, 16)),
    );
    let table = body.sub_exact(3, u64::from(count).saturating_mul(3))?;
    let colors = cx.read(table).await?;
    for (i, &[b, g, r]) in colors.as_chunks::<3>().0.iter().enumerate() {
        cx.push(
            Node::new(format!("Color {i}"))
                .span(table.sub(to_u64(i).saturating_mul(3), 3))
                .value(Value::Text(format!("#{r:02x}{g:02x}{b:02x}")))
                .desc("Stored blue, green, red"),
        )
        .await;
    }
    if version & 0x80 != 0 {
        let at = table.len.saturating_add(3);
        let n = cx.read(body.sub(at, 3)).await?;
        let indices = u24_be(&n, 0).unwrap_or(0);
        cx.push(
            Node::new("Index count")
                .span(body.sub(at, 3))
                .value(uint(indices, 24)),
        )
        .await;
        let data = body.tail(at.saturating_add(3));
        cx.push(
            content(
                "Color indices",
                input,
                data,
                Codec::Bzz,
                Some(u64::from(indices).saturating_mul(2)),
            )
            .summary(format!("{indices} big-endian 16-bit indices (BZZ)")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Directory

const INCLUDE: u8 = 0;
const PAGE: u8 = 1;
const FILE_TYPES: &[(u8, &str)] = &[
    (INCLUDE, "shared data"),
    (PAGE, "page"),
    (2, "thumbnails"),
    (3, "shared annotations"),
];
const HAS_NAME: u8 = 0x80;
const HAS_TITLE: u8 = 0x40;

/// One component of a multi-page document.
#[derive(Debug)]
struct DirFile {
    id: String,
    name: Option<String>,
    title: Option<String>,
    flags: u8,
    size: u32,
    /// Offset of the component's FORM in the file (bundled documents).
    offset: Option<u64>,
    /// Page number (from 1) for pages.
    page: Option<u32>,
    /// Span of the offset in the (uncompressed) offset table.
    offset_span: Option<Span>,
    /// Spans of the size, flags and strings in the decoded directory.
    size_span: Span,
    flags_span: Span,
    id_span: Span,
    name_span: Option<Span>,
    title_span: Option<Span>,
}

impl DirFile {
    fn kind(&self) -> u8 {
        self.flags & 0x3f
    }

    /// The component's chunk in a bundled file.
    fn chunk(&self, input: Input) -> Option<Span> {
        let offset = self.offset?;
        Some(input.span.sub(offset, self.size.into()))
    }
}

#[derive(Debug)]
struct Dir {
    bundled: bool,
    version: u8,
    count: u16,
    files: Vec<DirFile>,
    /// The decoded part, or why it could not be decoded.
    decoded: Option<Span>,
    error: Option<Diagnostic>,
}

/// Finds the `DIRM` chunk at the start of a `FORM:DJVM` body (after the
/// `DJVM` kind, `span` starts there) and parses it, once per file.
async fn load_dir(cx: &Cx, span: Span, file: Span) -> Result<Option<Arc<Dir>>> {
    let region = Span::new(
        span.source,
        span.offset,
        file.end().saturating_sub(span.offset),
    );
    let head = cx.read_avail(region.sub(0, 8)).await?;
    if head.get(..4) != Some(b"DIRM") {
        return Ok(None);
    }
    let len = u32_be(&head, 4).unwrap_or(0);
    let body = region.sub(8, len.into());
    if let Some(dir) = cx.cached::<Dir>(body, "djvu-dirm") {
        return Ok(Some(dir));
    }
    let dir = Arc::new(parse_dir(cx, body).await?);
    cx.cache(body, "djvu-dirm", dir.clone());
    Ok(Some(dir))
}

async fn parse_dir(cx: &Cx, body: Span) -> Result<Dir> {
    let head = cx.read(body.sub(0, 3)).await?;
    let flags = head.first().copied().unwrap_or(0);
    let count = u16_be(&head, 1).ok_or_else(|| Diagnostic::truncated(body.sub(0, 3), 1))?;
    let bundled = flags & 0x80 != 0;
    let mut offsets = Vec::new();
    let mut table = None;
    let mut at = 3u64;
    if bundled {
        let t = body.sub_exact(3, u64::from(count).saturating_mul(4))?;
        table = Some(t);
        let raw = cx.read(t).await?;
        offsets = raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&c| u32::from_be_bytes(c))
            .collect();
        at = at.saturating_add(t.len);
    }
    let mut dir = Dir {
        bundled,
        version: flags & 0x7f,
        count,
        files: Vec::new(),
        decoded: None,
        error: None,
    };
    let decoded = match decode_span(cx, body.tail(at), &Codec::Bzz, None).await {
        Ok(d) => d,
        Err(e) => {
            dir.error = Some(e);
            return Ok(dir);
        }
    };
    dir.decoded = Some(decoded.span);
    dir.error = decoded.error.clone();
    let data = cx.read(decoded.span).await?;
    let n = usize::from(count);
    let d = decoded.span;
    let flags_at = n.saturating_mul(3);
    let mut pos = flags_at.saturating_add(n);
    let mut page = 0u32;
    let cstr = |pos: &mut usize| -> Option<(String, Span)> {
        let rest = data.get(*pos..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        let s = lossy(rest.get(..end)?);
        let span = d.sub(to_u64(*pos), to_u64(end));
        *pos = pos.saturating_add(end).saturating_add(1);
        Some((s, span))
    };
    for i in 0..n {
        let size_at = i.saturating_mul(3);
        let (Some(size), Some(&fl)) =
            (u24_be(&data, size_at), data.get(flags_at.saturating_add(i)))
        else {
            dir.error = Some(Diagnostic::truncated(d, to_u64(data.len())));
            break;
        };
        let Some((id, id_span)) = cstr(&mut pos) else {
            dir.error = Some(Diagnostic::malformed("directory entry ids end early").at(d));
            break;
        };
        let (mut name, mut name_span, mut title, mut title_span) = (None, None, None, None);
        if fl & HAS_NAME != 0
            && let Some((s, sp)) = cstr(&mut pos)
        {
            name = Some(s);
            name_span = Some(sp);
        }
        if fl & HAS_TITLE != 0
            && let Some((s, sp)) = cstr(&mut pos)
        {
            title = Some(s);
            title_span = Some(sp);
        }
        let is_page = fl & 0x3f == PAGE;
        if is_page {
            page = page.saturating_add(1);
        }
        dir.files.push(DirFile {
            id,
            name,
            title,
            flags: fl,
            size,
            offset: offsets.get(i).map(|&o| u64::from(o)),
            page: is_page.then_some(page),
            offset_span: table.map(|t| t.sub(to_u64(i).saturating_mul(4), 4)),
            size_span: d.sub(to_u64(size_at), 3),
            flags_span: d.sub(to_u64(flags_at.saturating_add(i)), 1),
            id_span,
            name_span,
            title_span,
        });
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
    }
    Ok(dir)
}

async fn dirm_fields(cx: Cx, (input, body, offset): (Input, Span, u64)) -> Result<()> {
    let Some(dir) = load_dir(&cx, input.span.tail(offset), input.span).await? else {
        return Err(Diagnostic::malformed("not a DIRM chunk"));
    };
    cx.emit(
        Node::new("Flags")
            .span(body.sub(0, 1))
            .value(hex(u8::from(dir.bundled) << 7 | dir.version, 8))
            .summary(format!(
                "{}, version {}",
                if dir.bundled { "bundled" } else { "indirect" },
                dir.version
            )),
    );
    cx.emit(
        Node::new("File count")
            .span(body.sub(1, 2))
            .value(uint(dir.count, 16)),
    );
    let mut at = 3u64;
    if dir.bundled {
        let len = u64::from(dir.count).saturating_mul(4);
        cx.emit(
            Node::new("Offsets")
                .span(body.sub(3, len))
                .summary(format!("{} big-endian 32-bit file offsets", dir.count)),
        );
        at = at.saturating_add(len);
    }
    let mut node = Node::new("Entries (BZZ)")
        .span(body.tail(at))
        .summary(format!(
            "{} files, {} bytes compressed",
            dir.files.len(),
            body.len.saturating_sub(at)
        ));
    if let Some(e) = &dir.error {
        node = node.diag(e.clone());
    }
    cx.emit(node.lazy(dir_entries, (input, dir.clone())));
    Ok(())
}

async fn dir_entries(cx: Cx, (input, dir): (Input, Arc<Dir>)) -> Result<()> {
    for file in &dir.files {
        let kind = FILE_TYPES
            .iter()
            .find(|(k, _)| *k == file.kind())
            .map_or("unknown type", |(_, n)| *n);
        let mut summary = match file.page {
            Some(n) => format!("page {n}"),
            None => kind.to_owned(),
        };
        if let Some(title) = &file.title {
            summary = format!("{summary}, \"{title}\"");
        }
        summary = format!("{summary}, {} bytes", file.size);
        if let Some(o) = file.offset {
            summary = format!("{summary} at {o:#x}");
        }
        let mut node = Node::new(file.id.clone())
            .span(file.id_span)
            .summary(summary)
            .lazy(dir_entry, (dir.clone(), file.id_span));
        if let Some(span) = file.chunk(input) {
            node = node.target(span);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn dir_entry(cx: Cx, (dir, id_span): (Arc<Dir>, Span)) -> Result<()> {
    let Some(file) = dir.files.iter().find(|f| f.id_span == id_span) else {
        return Ok(());
    };
    cx.emit(
        Node::new("ID")
            .span(file.id_span)
            .value(Value::Text(file.id.clone())),
    );
    if let (Some(name), Some(span)) = (&file.name, file.name_span) {
        cx.emit(
            Node::new("Name")
                .span(span)
                .value(Value::Text(name.clone())),
        );
    }
    if let (Some(title), Some(span)) = (&file.title, file.title_span) {
        cx.emit(
            Node::new("Title")
                .span(span)
                .value(Value::Text(title.clone())),
        );
    }
    let kind = FILE_TYPES
        .iter()
        .find(|(k, _)| *k == file.kind())
        .map(|(_, n)| *n);
    let mut extra = Vec::new();
    if file.flags & HAS_NAME != 0 {
        extra.push("has name");
    }
    if file.flags & HAS_TITLE != 0 {
        extra.push("has title");
    }
    let mut flags = kind.unwrap_or("unknown type").to_owned();
    if !extra.is_empty() {
        flags = format!("{flags}, {}", extra.join(", "));
    }
    cx.emit(
        Node::new("Flags")
            .span(file.flags_span)
            .value(hex(file.flags, 8))
            .summary(flags),
    );
    cx.emit(
        Node::new("Size")
            .span(file.size_span)
            .value(uint(file.size, 24)),
    );
    if let (Some(o), Some(span)) = (file.offset, file.offset_span) {
        cx.emit(Node::new("Offset").span(span).value(hex(o, 32)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Outline (NAVM)

struct Bookmark {
    title: String,
    url: String,
    span: Span,
    children: Vec<usize>,
}

struct Outline {
    marks: Vec<Bookmark>,
    roots: Vec<usize>,
}

async fn outline(cx: Cx, body: Span) -> Result<()> {
    let decoded = decode_span(&cx, body, &Codec::Bzz, None).await?;
    if let Some(e) = decoded.error.clone() {
        cx.diag(e);
    }
    let d = decoded.span;
    let data = cx.read(d).await?;
    let count = u16_be(&data, 0).ok_or_else(|| Diagnostic::truncated(d.sub(0, 2), 0))?;
    cx.emit(
        Node::new("Bookmark count")
            .span(d.sub(0, 2))
            .value(uint(count, 16)),
    );
    let mut out = Outline {
        marks: Vec::new(),
        roots: Vec::new(),
    };
    let mut stack: Vec<(usize, u8)> = Vec::new();
    let mut pos = 2usize;
    let mut problem = None;
    for i in 0..count {
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
        let start = pos;
        let Some(&children) = data.get(pos) else {
            problem = Some(Diagnostic::truncated(d.sub(to_u64(pos), 1), 0));
            break;
        };
        let read = |at: usize| -> Option<(String, usize)> {
            let len = to_usize(u24_be(&data, at)?.into());
            let s = data.get(at.saturating_add(3)..at.saturating_add(3).saturating_add(len))?;
            Some((lossy(s), at.saturating_add(3).saturating_add(len)))
        };
        let Some((title, after)) = read(pos.saturating_add(1)) else {
            problem = Some(Diagnostic::malformed("bookmark title runs past the end").at(d));
            break;
        };
        let Some((url, end)) = read(after) else {
            problem = Some(Diagnostic::malformed("bookmark URL runs past the end").at(d));
            break;
        };
        pos = end;
        let idx = out.marks.len();
        out.marks.push(Bookmark {
            title,
            url,
            span: d.sub(to_u64(start), to_u64(end.saturating_sub(start))),
            children: Vec::new(),
        });
        while stack.last().is_some_and(|&(_, left)| left == 0) {
            stack.pop();
        }
        if let Some((parent, left)) = stack.last_mut() {
            *left = left.saturating_sub(1);
            if let Some(p) = out.marks.get_mut(*parent) {
                p.children.push(idx);
            }
        } else {
            out.roots.push(idx);
        }
        if children > 0 {
            if stack.len() >= MAX_TREE_DEPTH {
                problem = Some(Diagnostic::limit("bookmarks nested too deeply"));
                break;
            }
            stack.push((idx, children));
        }
    }
    if let Some(p) = problem {
        cx.diag(p);
    }
    let out = Arc::new(out);
    let roots = out.roots.clone();
    for idx in roots {
        cx.push(bookmark_node(&out, idx)).await;
    }
    Ok(())
}

fn bookmark_node(outline: &Arc<Outline>, idx: usize) -> Node {
    let Some(mark) = outline.marks.get(idx) else {
        return Node::new("?");
    };
    let mut node = Node::new(mark.title.clone())
        .span(mark.span)
        .value(Value::Text(mark.url.clone()));
    if !mark.children.is_empty() {
        node = node.lazy(bookmark_children, (outline.clone(), idx));
    }
    node
}

async fn bookmark_children(cx: Cx, (outline, idx): (Arc<Outline>, usize)) -> Result<()> {
    let children = outline
        .marks
        .get(idx)
        .map(|m| m.children.clone())
        .unwrap_or_default();
    for child in children {
        cx.push(bookmark_node(&outline, child)).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hidden text

const ZONE_TYPES: &[(u8, &str)] = &[
    (1, "Page"),
    (2, "Column"),
    (3, "Region"),
    (4, "Paragraph"),
    (5, "Line"),
    (6, "Word"),
    (7, "Character"),
];
/// Bytes of a zone record before its children.
const ZONE_LEN: usize = 17;

#[derive(Clone, Copy, Debug)]
struct Rect {
    xmin: i64,
    ymin: i64,
    xmax: i64,
    ymax: i64,
}

struct Zone {
    kind: u8,
    rect: Rect,
    start: i64,
    len: u32,
    span: Span,
    children: Vec<usize>,
}

struct TextLayer {
    text: Vec<u8>,
    zones: Vec<Zone>,
}

impl TextLayer {
    fn text_of(&self, zone: &Zone) -> String {
        let start = usize::try_from(zone.start).unwrap_or(usize::MAX);
        let end = start.saturating_add(to_usize(zone.len.into()));
        lossy(
            self.text
                .get(start..end.min(self.text.len()))
                .unwrap_or_default(),
        )
    }
}

fn read_zone(
    data: &[u8],
    at: usize,
    parent: Option<&Zone>,
    prev: Option<&Zone>,
    d: Span,
) -> Option<(Zone, u32)> {
    let kind = *data.get(at)?;
    let field = |i: usize| -> Option<i64> {
        let raw = u16_be(
            data,
            at.saturating_add(1).saturating_add(i.saturating_mul(2)),
        )?;
        Some(i64::from(raw).saturating_sub(0x8000))
    };
    let (mut x, mut y, w, h, mut start) = (field(0)?, field(1)?, field(2)?, field(3)?, field(4)?);
    let len = u24_be(data, at.saturating_add(11))?;
    let children = u24_be(data, at.saturating_add(14))?;
    if let Some(prev) = prev {
        if matches!(kind, 1 | 4 | 5) {
            x = x.saturating_add(prev.rect.xmin);
            y = prev.rect.ymin.saturating_sub(y.saturating_add(h));
        } else {
            x = x.saturating_add(prev.rect.xmax);
            y = y.saturating_add(prev.rect.ymin);
        }
        start = start
            .saturating_add(prev.start)
            .saturating_add(prev.len.into());
    } else if let Some(parent) = parent {
        x = x.saturating_add(parent.rect.xmin);
        y = parent.rect.ymax.saturating_sub(y.saturating_add(h));
        start = start.saturating_add(parent.start);
    }
    let zone = Zone {
        kind,
        rect: Rect {
            xmin: x,
            ymin: y,
            xmax: x.saturating_add(w),
            ymax: y.saturating_add(h),
        },
        start,
        len,
        span: d.sub(to_u64(at), to_u64(ZONE_LEN)),
        children: Vec::new(),
    };
    Some((zone, children))
}

/// Parses the zone tree at `at` (depth-first, children after their
/// parent's record) into a flat list; the root is zone 0.
async fn parse_zones(cx: &Cx, data: &[u8], at: usize, d: Span) -> (Vec<Zone>, Option<Diagnostic>) {
    let mut zones: Vec<Zone> = Vec::new();
    let Some((root, n)) = read_zone(data, at, None, None, d) else {
        return (zones, Some(Diagnostic::truncated(d.sub(to_u64(at), 17), 0)));
    };
    zones.push(root);
    let mut pos = at.saturating_add(ZONE_LEN);
    // (zone, children left, previous child)
    let mut stack: Vec<(usize, u32, Option<usize>)> = Vec::new();
    if n > 0 {
        stack.push((0, n, None));
    }
    while let Some(&(parent, left, prev)) = stack.last() {
        if left == 0 {
            stack.pop();
            continue;
        }
        let read = read_zone(
            data,
            pos,
            zones.get(parent),
            prev.and_then(|p| zones.get(p)),
            d,
        );
        let Some((zone, n)) = read else {
            return (
                zones,
                Some(Diagnostic::malformed("text zones end early").at(d.sub(to_u64(pos), 17))),
            );
        };
        pos = pos.saturating_add(ZONE_LEN);
        let idx = zones.len();
        if idx % 256 == 255 {
            cx.checkpoint().await;
        }
        zones.push(zone);
        if let Some(p) = zones.get_mut(parent) {
            p.children.push(idx);
        }
        if let Some(top) = stack.last_mut() {
            *top = (parent, left.saturating_sub(1), Some(idx));
        }
        if n > 0 {
            if stack.len() >= MAX_TREE_DEPTH {
                return (
                    zones,
                    Some(Diagnostic::limit("text zones nested too deeply")),
                );
            }
            stack.push((idx, n, None));
        }
    }
    let rest = data.len().saturating_sub(pos);
    let diag = (rest > 0).then(|| {
        Diagnostic::warning(format!("{rest} bytes after the zones")).at(d.tail(to_u64(pos)))
    });
    (zones, diag)
}

async fn text_layer(cx: Cx, (body, compressed): (Span, bool)) -> Result<()> {
    let d = if compressed {
        let decoded = decode_span(&cx, body, &Codec::Bzz, None).await?;
        if let Some(e) = decoded.error.clone() {
            cx.diag(e);
        }
        decoded.span
    } else {
        body
    };
    let data = cx.read(d).await?;
    let len = u24_be(&data, 0).ok_or_else(|| Diagnostic::truncated(d.sub(0, 3), 0))?;
    cx.emit(
        Node::new("Text length")
            .span(d.sub(0, 3))
            .value(uint(len, 24)),
    );
    let text_span = d.sub(3, len.into());
    let text = data
        .get(3..3usize.saturating_add(to_usize(len.into())))
        .unwrap_or_else(|| data.get(3..).unwrap_or_default())
        .to_vec();
    let full = lossy(&text);
    let words = full.split_whitespace().count();
    cx.emit(
        Node::new("Text")
            .span(text_span)
            .summary(format!("{words} words"))
            .value(Value::Text(full)),
    );
    let at = 3usize.saturating_add(to_usize(len.into()));
    let Some(&version) = data.get(at) else {
        return Ok(());
    };
    cx.emit(
        Node::new("Version")
            .span(d.sub(to_u64(at), 1))
            .value(uint(version, 8)),
    );
    let (zones, diag) = parse_zones(&cx, &data, at.saturating_add(1), d).await;
    if let Some(e) = diag {
        cx.diag(e);
    }
    let layer = Arc::new(TextLayer { text, zones });
    if !layer.zones.is_empty() {
        cx.emit(zone_node(&layer, 0));
    }
    Ok(())
}

fn zone_node(layer: &Arc<TextLayer>, idx: usize) -> Node {
    let Some(zone) = layer.zones.get(idx) else {
        return Node::new("?");
    };
    let name = ZONE_TYPES
        .iter()
        .find(|(k, _)| *k == zone.kind)
        .map_or_else(
            || format!("Zone type {}", zone.kind),
            |(_, n)| (*n).to_owned(),
        );
    let text = layer.text_of(zone);
    let r = zone.rect;
    let mut node = Node::new(name)
        .span(zone.span)
        .summary(format!("({}, {})–({}, {})", r.xmin, r.ymin, r.xmax, r.ymax))
        .value(Value::Text(text));
    if !zone.children.is_empty() {
        node = node.lazy(zone_children, (layer.clone(), idx));
    }
    node
}

async fn zone_children(cx: Cx, (layer, idx): (Arc<TextLayer>, usize)) -> Result<()> {
    let children = layer
        .zones
        .get(idx)
        .map(|z| z.children.clone())
        .unwrap_or_default();
    for child in children {
        cx.push(zone_node(&layer, child)).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Annotations

#[derive(Debug)]
enum SxKind {
    Atom,
    Str,
    List,
}

#[derive(Debug)]
struct Sx {
    kind: SxKind,
    text: String,
    start: usize,
    end: usize,
    children: Vec<usize>,
}

struct Sexprs {
    items: Vec<Sx>,
    roots: Vec<usize>,
    source: Span,
}

/// Parses the annotation s-expressions: lists, quoted strings (C escapes)
/// and atoms.
async fn parse_sexprs(cx: &Cx, data: &[u8], source: Span) -> (Sexprs, Option<Diagnostic>) {
    let mut out = Sexprs {
        items: Vec::new(),
        roots: Vec::new(),
        source,
    };
    let mut stack: Vec<usize> = Vec::new();
    let mut pos = 0usize;
    let attach = |out: &mut Sexprs, stack: &[usize], idx: usize| {
        if let Some(&parent) = stack.last() {
            if let Some(p) = out.items.get_mut(parent) {
                p.children.push(idx);
            }
        } else {
            out.roots.push(idx);
        }
    };
    // Input offset of the next checkpoint.
    let mut check = 0usize;
    while let Some(&c) = data.get(pos) {
        if pos >= check {
            check = pos.saturating_add(CHECK_BYTES);
            cx.checkpoint().await;
        }
        match c {
            b'(' => {
                if stack.len() >= MAX_TREE_DEPTH {
                    return (
                        out,
                        Some(Diagnostic::limit("annotations nested too deeply")),
                    );
                }
                let idx = out.items.len();
                out.items.push(Sx {
                    kind: SxKind::List,
                    text: String::new(),
                    start: pos,
                    end: pos,
                    children: Vec::new(),
                });
                attach(&mut out, &stack, idx);
                stack.push(idx);
                pos = pos.saturating_add(1);
            }
            b')' => {
                pos = pos.saturating_add(1);
                match stack.pop() {
                    Some(idx) => {
                        if let Some(item) = out.items.get_mut(idx) {
                            item.end = pos;
                        }
                    }
                    None => {
                        return (
                            out,
                            Some(
                                Diagnostic::malformed("unbalanced ')'")
                                    .at(source.sub(to_u64(pos), 1)),
                            ),
                        );
                    }
                }
            }
            b'"' => {
                let start = pos;
                pos = pos.saturating_add(1);
                let mut s = Vec::new();
                let mut closed = false;
                while let Some(&b) = data.get(pos) {
                    if pos >= check {
                        check = pos.saturating_add(CHECK_BYTES);
                        cx.checkpoint().await;
                    }
                    pos = pos.saturating_add(1);
                    match b {
                        b'"' => {
                            closed = true;
                            break;
                        }
                        b'\\' => {
                            let Some(&e) = data.get(pos) else { break };
                            pos = pos.saturating_add(1);
                            match e {
                                b'n' => s.push(b'\n'),
                                b't' => s.push(b'\t'),
                                b'r' => s.push(b'\r'),
                                b'0'..=b'7' => {
                                    let mut v = u32::from(e.saturating_sub(b'0'));
                                    for _ in 0..2 {
                                        match data.get(pos) {
                                            Some(&o @ b'0'..=b'7') => {
                                                v = v.saturating_mul(8).saturating_add(u32::from(
                                                    o.saturating_sub(b'0'),
                                                ));
                                                pos = pos.saturating_add(1);
                                            }
                                            _ => break,
                                        }
                                    }
                                    s.push(u8::try_from(v & 0xff).unwrap_or(0));
                                }
                                other => s.push(other),
                            }
                        }
                        other => s.push(other),
                    }
                }
                if !closed {
                    return (
                        out,
                        Some(
                            Diagnostic::malformed("unterminated string")
                                .at(source.tail(to_u64(start))),
                        ),
                    );
                }
                let idx = out.items.len();
                out.items.push(Sx {
                    kind: SxKind::Str,
                    text: lossy(&s),
                    start,
                    end: pos,
                    children: Vec::new(),
                });
                attach(&mut out, &stack, idx);
            }
            c if c.is_ascii_whitespace() || c == 0 => pos = pos.saturating_add(1),
            _ => {
                let start = pos;
                while let Some(&b) = data.get(pos) {
                    if b.is_ascii_whitespace() || b == b'(' || b == b')' || b == b'"' || b == 0 {
                        break;
                    }
                    pos = pos.saturating_add(1);
                }
                let idx = out.items.len();
                out.items.push(Sx {
                    kind: SxKind::Atom,
                    text: lossy(data.get(start..pos).unwrap_or_default()),
                    start,
                    end: pos,
                    children: Vec::new(),
                });
                attach(&mut out, &stack, idx);
            }
        }
    }
    let diag = (!stack.is_empty()).then(|| Diagnostic::malformed("unclosed '('").at(source));
    (out, diag)
}

impl Sexprs {
    /// Compact rendering of item `idx`, at most `max` characters.
    fn render(&self, idx: usize, max: usize) -> String {
        let mut out = String::new();
        self.render_into(idx, &mut out, max, 0);
        snippet(&out, max)
    }

    fn render_into(&self, idx: usize, out: &mut String, max: usize, depth: usize) {
        let Some(item) = self.items.get(idx) else {
            return;
        };
        if out.len() > max || depth > MAX_TREE_DEPTH {
            return;
        }
        match item.kind {
            SxKind::Atom => out.push_str(&item.text),
            SxKind::Str => {
                out.push('"');
                out.push_str(&item.text);
                out.push('"');
            }
            SxKind::List => {
                out.push('(');
                for (i, &c) in item.children.iter().enumerate() {
                    if i > 0 {
                        out.push(' ');
                    }
                    self.render_into(c, out, max, depth.saturating_add(1));
                }
                out.push(')');
            }
        }
    }
}

fn sx_node(sx: &Arc<Sexprs>, idx: usize) -> Node {
    let Some(item) = sx.items.get(idx) else {
        return Node::new("?");
    };
    let span = sx.source.sub(
        to_u64(item.start),
        to_u64(item.end.saturating_sub(item.start)),
    );
    match item.kind {
        SxKind::Atom => Node::new("Atom")
            .span(span)
            .value(Value::Text(item.text.clone())),
        SxKind::Str => Node::new("String")
            .span(span)
            .value(Value::Text(item.text.clone())),
        SxKind::List => {
            let head = item
                .children
                .first()
                .and_then(|&h| sx.items.get(h))
                .filter(|h| matches!(h.kind, SxKind::Atom))
                .map(|h| h.text.clone());
            let args: Vec<usize> = item
                .children
                .iter()
                .skip(usize::from(head.is_some()))
                .copied()
                .collect();
            let rest = args
                .iter()
                .map(|&a| sx.render(a, 60))
                .collect::<Vec<_>>()
                .join(" ");
            let mut node = Node::new(head.unwrap_or_else(|| "List".to_owned())).span(span);
            if !rest.is_empty() {
                node = node.summary(snippet(&rest, 80));
            }
            // A list of only atoms and strings is shown by its summary alone
            // unless it has several arguments.
            if args.len() > 1
                || args.iter().any(|&a| {
                    sx.items
                        .get(a)
                        .is_some_and(|i| matches!(i.kind, SxKind::List))
                })
            {
                node = node.lazy(sx_children, (sx.clone(), idx));
            }
            node
        }
    }
}

async fn sx_children(cx: Cx, (sx, idx): (Arc<Sexprs>, usize)) -> Result<()> {
    let Some(item) = sx.items.get(idx) else {
        return Ok(());
    };
    let skip = usize::from(
        item.children
            .first()
            .and_then(|&h| sx.items.get(h))
            .is_some_and(|h| matches!(h.kind, SxKind::Atom)),
    );
    for &c in item.children.iter().skip(skip) {
        cx.push(sx_node(&sx, c)).await;
    }
    Ok(())
}

async fn annotations(cx: Cx, (body, compressed): (Span, bool)) -> Result<()> {
    let d = if compressed {
        let decoded = decode_span(&cx, body, &Codec::Bzz, None).await?;
        if let Some(e) = decoded.error.clone() {
            cx.diag(e);
        }
        decoded.span
    } else {
        body
    };
    let data = cx.read(d).await?;
    let (sx, diag) = parse_sexprs(&cx, &data, d).await;
    if let Some(e) = diag {
        cx.diag(e);
    }
    let sx = Arc::new(sx);
    let roots = sx.roots.clone();
    for idx in roots {
        cx.push(sx_node(&sx, idx)).await;
    }
    Ok(())
}
