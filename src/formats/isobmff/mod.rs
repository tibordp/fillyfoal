//! ISO base media file format and its relatives: MP4, M4A/M4V, QuickTime
//! MOV, 3GP/3G2, HEIF/HEIC, AVIF, Canon CR3 and JPEG 2000 (JP2/JPX/MJ2).
//!
//! Everything is a box: `size, type[, largesize][, usertype], body`. One
//! generic walker lists boxes (paged) and recurses into containers; decoders
//! for individual box types live in the submodules. Large sample tables are
//! listed in pages and never read whole.

mod boxes;
mod canon;
mod heif;
mod jp2;
mod meta;
mod sample;
mod summary;
mod tables;

use crate::bytes::{to_u64, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::vidutil::{fourcc, hex, text, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

pub(crate) const BE: Endian = Endian::Big;

/// Which member of the family a file is, from its brands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Brand {
    Mp4,
    M4a,
    M4v,
    Mov,
    ThreeGp,
    ThreeG2,
    Heif,
    Avif,
    Cr3,
    Jp2,
    Jpx,
    Mj2,
}

impl Brand {
    fn label(self) -> &'static str {
        match self {
            Brand::Mp4 => "MP4",
            Brand::M4a => "MPEG-4 audio",
            Brand::M4v => "MPEG-4 video (Apple)",
            Brand::Mov => "QuickTime movie",
            Brand::ThreeGp => "3GPP",
            Brand::ThreeG2 => "3GPP2",
            Brand::Heif => "HEIF",
            Brand::Avif => "AVIF",
            Brand::Cr3 => "Canon CR3",
            Brand::Jp2 => "JPEG 2000",
            Brand::Jpx => "JPEG 2000 (JPX)",
            Brand::Mj2 => "Motion JPEG 2000",
        }
    }

    fn is_jp2(self) -> bool {
        matches!(self, Brand::Jp2 | Brand::Jpx | Brand::Mj2)
    }
}

macro_rules! bmff_format {
    ($id:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $brand:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom(|h| classify(h) == Some($brand)),
            dissect: crate::expander!(dissect: Input),
        };
    };
}

bmff_format!(CR3, "cr3", "Canon RAW 3", ["cr3", "crm"], "image/x-canon-cr3", Brand::Cr3);
bmff_format!(HEIF, "heif", "High Efficiency Image File", ["heic", "heif", "heics", "heifs", "hif"], "image/heic", Brand::Heif);
bmff_format!(AVIF, "avif", "AV1 Image File", ["avif", "avifs"], "image/avif", Brand::Avif);
bmff_format!(JP2, "jp2", "JPEG 2000 image", ["jp2"], "image/jp2", Brand::Jp2);
bmff_format!(JPX, "jpx", "JPEG 2000 extended image", ["jpx", "jpf"], "image/jpx", Brand::Jpx);
bmff_format!(MJ2, "mj2", "Motion JPEG 2000", ["mj2", "mjp2"], "video/mj2", Brand::Mj2);
bmff_format!(THREE_GP, "3gp", "3GPP multimedia", ["3gp", "3gpp"], "video/3gpp", Brand::ThreeGp);
bmff_format!(THREE_G2, "3g2", "3GPP2 multimedia", ["3g2", "3gp2"], "video/3gpp2", Brand::ThreeG2);
bmff_format!(M4A, "m4a", "MPEG-4 audio", ["m4a", "m4b", "m4p", "m4r"], "audio/mp4", Brand::M4a);
bmff_format!(M4V, "m4v", "MPEG-4 video (Apple)", ["m4v"], "video/x-m4v", Brand::M4v);
bmff_format!(MOV, "mov", "QuickTime movie", ["mov", "qt"], "video/quicktime", Brand::Mov);
bmff_format!(MP4, "mp4", "MPEG-4 Part 14", ["mp4", "m4s", "mp4v", "f4v", "ismv", "cmfv", "cmfa"], "video/mp4", Brand::Mp4);

const JP2_SIGNATURE: &[u8] = b"\0\0\0\x0cjP  \r\n\x87\n";

/// Identifies the family member from the file's first bytes.
pub fn classify(h: &Head<'_>) -> Option<Brand> {
    if h.starts_with(JP2_SIGNATURE) {
        if !h.at(16, b"ftyp") {
            return Some(Brand::Jp2);
        }
        return Some(match h.data.get(20..24) {
            Some(b"jpx ") | Some(b"jpm ") => Brand::Jpx,
            Some(b"mjp2") | Some(b"mj2s") => Brand::Mj2,
            _ => Brand::Jp2,
        });
    }
    if h.at(4, b"ftyp") {
        let size = usize::try_from(u32_be(h.data, 0)?).ok()?;
        if !(16..=4096).contains(&size) || size % 4 != 0 {
            return None;
        }
        let major: [u8; 4] = crate::bytes::array(h.data, 8)?;
        if !major.iter().all(|b| b.is_ascii_graphic() || *b == b' ' || *b == 0) {
            return None;
        }
        let end = size.min(h.data.len());
        let compat = h.data.get(16..end).unwrap_or_default();
        return Some(from_brands(&major, compat));
    }
    legacy_quicktime(h).then_some(Brand::Mov)
}

fn from_brands(major: &[u8; 4], compat: &[u8]) -> Brand {
    let has = |b: &[u8]| compat.as_chunks::<4>().0.iter().any(|c| c.as_slice() == b);
    match major {
        b"crx " => Brand::Cr3,
        b"avif" | b"avis" => Brand::Avif,
        b"heic" | b"heix" | b"hevc" | b"hevx" | b"heim" | b"heis" | b"hevm" | b"hevs" => {
            Brand::Heif
        }
        b"mif1" | b"msf1" | b"mif2" | b"miaf" => {
            if has(b"avif") || has(b"avis") {
                Brand::Avif
            } else {
                Brand::Heif
            }
        }
        b"qt  " => Brand::Mov,
        b"M4A " | b"M4B " | b"M4P " => Brand::M4a,
        b"M4V " | b"M4VH" | b"M4VP" => Brand::M4v,
        b"mjp2" | b"mj2s" => Brand::Mj2,
        b"jp2 " => Brand::Jp2,
        b"jpx " => Brand::Jpx,
        [b'3', b'g', b'2', _] => Brand::ThreeG2,
        [b'3', b'g', _, _] => Brand::ThreeGp,
        _ if has(b"heic") || has(b"heix") => Brand::Heif,
        _ if has(b"avif") => Brand::Avif,
        _ => Brand::Mp4,
    }
}

/// Top-level box types of QuickTime files written before `ftyp` existed.
const QT_TOP: &[&[u8; 4]] = &[b"moov", b"mdat", b"wide", b"free", b"skip", b"pnot"];
const QT_MOOV_FIRST: &[&[u8; 4]] = &[b"mvhd", b"cmov", b"prfl", b"udta", b"trak", b"iods"];

fn legacy_quicktime(h: &Head<'_>) -> bool {
    let kind_at = |at: usize| crate::bytes::array::<4>(h.data, at.saturating_add(4));
    let Some(first) = kind_at(0) else {
        return false;
    };
    let Some(size) = u32_be(h.data, 0) else {
        return false;
    };
    if !QT_TOP.contains(&&first) || size < 8 || u64::from(size) > h.len {
        return false;
    }
    if &first == b"moov" {
        return kind_at(8).is_some_and(|k| QT_MOOV_FIRST.contains(&&k));
    }
    let next = usize::try_from(size).unwrap_or(usize::MAX);
    match kind_at(next) {
        Some(k) => QT_TOP.contains(&&k) && u32_be(h.data, next).is_some_and(|s| s >= 8 || s == 0),
        None => {
            u64::from(size) < h.len
                && h.tail.windows(4).any(|w| w == b"moov" || w == b"mvhd")
        }
    }
}

// ---------------------------------------------------------------------------
// Box headers

/// A decoded box header. `size` is the full size of the box (resolved for
/// `largesize` and size 0).
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub kind: [u8; 4],
    pub size: u64,
    pub header_len: u64,
    pub uuid: Option<[u8; 16]>,
    /// The size field was 0: the box extends to the end of its container.
    pub to_end: bool,
}

impl Header {
    pub fn name(&self) -> String {
        fourcc(&self.kind)
    }
}

/// Reads the header of the box at `pos` within `region`. `Ok(None)` when
/// fewer than 8 bytes remain.
pub async fn read_header(cx: &Cx, region: Span, pos: u64) -> Result<Option<Header>> {
    let remaining = region.len.saturating_sub(pos);
    if remaining < 8 {
        return Ok(None);
    }
    let data = cx.read_avail(region.sub(pos, 32)).await?;
    let size32 = u32_be(&data, 0).unwrap_or(0);
    let kind: [u8; 4] = crate::bytes::array(&data, 4).unwrap_or_default();
    let (mut size, mut header_len, mut to_end) = (u64::from(size32), 8u64, false);
    if size32 == 1 {
        size = u64_be(&data, 8)
            .ok_or_else(|| Diagnostic::truncated(region.sub(pos, 16), remaining))?;
        header_len = 16;
    } else if size32 == 0 {
        size = remaining;
        to_end = true;
    }
    let mut uuid = None;
    if &kind == b"uuid" {
        uuid = crate::bytes::array::<16>(&data, crate::bytes::to_usize(header_len));
        if uuid.is_none() {
            return Err(Diagnostic::truncated(region.sub(pos, header_len.saturating_add(16)), remaining));
        }
        header_len = header_len.saturating_add(16);
    }
    if size < header_len {
        return Err(Diagnostic::malformed(format!(
            "box '{}' declares size {size}, smaller than its header",
            fourcc(&kind)
        ))
        .at(region.sub(pos, header_len)));
    }
    Ok(Some(Header {
        kind,
        size,
        header_len,
        uuid,
        to_end,
    }))
}

/// Finds the first child of type `kind` in a region of boxes.
pub async fn find_child(cx: &Cx, region: Span, kind: &[u8; 4]) -> Result<Option<(Header, Span)>> {
    let mut pos = 0u64;
    let mut guard = 0u32;
    while let Some(h) = read_header(cx, region, pos).await? {
        if &h.kind == kind {
            return Ok(Some((h, region.sub(pos, h.size))));
        }
        pos = pos.saturating_add(h.size);
        guard = guard.saturating_add(1);
        if guard > 1024 {
            break;
        }
    }
    Ok(None)
}

/// Follows a path of box types down from `region`; returns the body of the
/// last box.
pub async fn find_path(cx: &Cx, region: Span, path: &[&[u8; 4]]) -> Result<Option<Span>> {
    let mut current = region;
    for kind in path {
        let Some((h, span)) = find_child(cx, current, kind).await? else {
            return Ok(None);
        };
        current = span.tail(h.header_len).tail(container_skip(&h.kind));
    }
    Ok(Some(current))
}

// ---------------------------------------------------------------------------
// Walking

/// Where a box sits: what dissector-wide facts apply to it.
#[derive(Clone, Copy, Debug)]
pub struct Ctx {
    pub brand: Brand,
    /// Type of the enclosing box (`\0\0\0\0` at the top level).
    pub parent: [u8; 4],
    /// Handler type of the enclosing track or meta box, if known.
    pub handler: [u8; 4],
    pub depth: u32,
    /// The region of boxes this box is part of (for sibling lookups).
    pub siblings: Span,
}

impl Ctx {
    fn child(self, parent: [u8; 4], siblings: Span) -> Ctx {
        Ctx {
            parent,
            depth: self.depth.saturating_add(1),
            siblings,
            ..self
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BoxState {
    pub input: Input,
    pub span: Span,
    pub header: Header,
    pub ctx: Ctx,
}

impl BoxState {
    pub fn body(&self) -> Span {
        self.span.tail(self.header.header_len)
    }
}

const MAX_DEPTH: u32 = 40;

/// Plain containers: the body is a sequence of boxes.
const CONTAINERS: &[&[u8; 4]] = &[
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts", b"udta", b"mvex", b"moof",
    b"traf", b"mfra", b"tref", b"sinf", b"schi", b"iprp", b"ipco", b"gmhd", b"tapt", b"clip",
    b"matt", b"rinf", b"strk", b"strd", b"wave", b"meco", b"trgr", b"jp2h", b"res ", b"uinf",
    b"jpch", b"jplh", b"cgrp", b"ftab", b"ilst", b"grpl", b"hnti", b"hinf", b"tmcd",
    b"imap", b"rmra", b"rmda", b"cmov", b"fiin", b"paen", b"ludt", b"vttc",
];

/// Containers whose children start after a fixed prefix (FullBox header,
/// entry count ...).
pub fn container_skip(kind: &[u8; 4]) -> u64 {
    match kind {
        b"meta" => 4,
        b"dref" | b"stsd" => 8,
        _ => 0,
    }
}

fn is_container(h: &Header, ctx: &Ctx) -> bool {
    // Items in an 'ilst' are containers of 'data' boxes.
    CONTAINERS.contains(&&h.kind) || &ctx.parent == b"ilst"
}

/// Lists the boxes in `region` (relative to nothing: it is a span).
pub async fn children(cx: &Cx, input: Input, region: Span, ctx: Ctx) -> Result<()> {
    if ctx.depth > MAX_DEPTH {
        return Err(Diagnostic::limit(format!("boxes nested deeper than {MAX_DEPTH}")).at(region));
    }
    let top = ctx.depth == 0;
    let mut pos = 0u64;
    let mut annotation = summary::Annotation::default();
    while pos < region.len {
        let header = match read_header(cx, region, pos).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                let rest = region.tail(pos);
                let zero = cx.read_avail(rest).await?.iter().all(|&b| b == 0);
                cx.emit(
                    Node::new(if zero { "Padding" } else { "Trailing bytes" })
                        .span(rest)
                        .summary(format!("{} bytes", rest.len)),
                );
                break;
            }
            Err(e) => {
                cx.emit(Node::new("Invalid box").span(region.tail(pos)).diag(e));
                break;
            }
        };
        let span = region.sub(pos, header.size);
        let st = BoxState {
            input,
            span,
            header,
            ctx,
        };
        let mut node = Node::new(header.name()).span(span);
        if span.len < header.size {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, header.size),
                span.len,
            ));
        }
        if let Some(s) = describe(cx, &st).await {
            node = node.summary(s);
        }
        if top {
            annotation.observe(cx, &st).await;
        }
        cx.push(node.lazy(crate::expander!(self::expand_box: BoxState), st))
            .await;
        if header.to_end {
            break;
        }
        pos = pos.saturating_add(header.size);
    }
    Ok(())
}

/// Expands one box: its header fields, then its decoded body.
async fn expand_box(cx: Cx, st: BoxState) -> Result<()> {
    let h = st.header;
    let block = cx.block(st.span.sub(0, h.header_len)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Size")
        .with(|&s, n| if s == 0 { n.summary("to end of container") } else { n })
        .emit()?;
    f.ascii("Type", 4).emit()?;
    if h.header_len >= 16 && u32_be(&block.data, 0) == Some(1) {
        f.u64("Large size").emit()?;
    }
    if let Some(u) = h.uuid {
        let at = f.peek_span(16);
        let mut node = text("User type", at, crate::formats::vidutil::uuid(&u));
        if let Some(name) = canon::uuid_name(&u) {
            node = node.summary(name);
        }
        cx.emit(node);
    }
    decode(&cx, &st).await
}

/// Decodes a box body according to its type.
async fn decode(cx: &Cx, st: &BoxState) -> Result<()> {
    let h = &st.header;
    let body = st.body();
    let ctx = st.ctx;
    if ctx.parent == *b"stsd" {
        return sample::entry(cx, st).await;
    }
    if is_container(h, &ctx) {
        let handler = match &h.kind {
            b"mdia" | b"trak" => summary::handler_of(cx, &h.kind, body).await.unwrap_or(ctx.handler),
            _ => ctx.handler,
        };
        let child = Ctx {
            handler,
            ..ctx.child(h.kind, body)
        };
        return children(cx, st.input, body, child).await;
    }
    if boxes::decode(cx, st).await? {
        return Ok(());
    }
    if tables::decode(cx, st).await? {
        return Ok(());
    }
    if meta::decode(cx, st).await? {
        return Ok(());
    }
    if heif::decode_item_box(cx, st).await? {
        return Ok(());
    }
    if ctx.brand.is_jp2() && jp2::decode(cx, st).await? {
        return Ok(());
    }
    if canon::decode(cx, st).await? {
        return Ok(());
    }
    if sample::decode_config(cx, st).await? {
        return Ok(());
    }
    if !body.is_empty() {
        cx.emit(Node::new("Data").span(body));
    }
    Ok(())
}

/// A one-line summary for the box list, from a small read.
async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let h = &st.header;
    if let Some(u) = h.uuid {
        return canon::uuid_name(&u).map(str::to_owned);
    }
    if st.ctx.parent == *b"stsd" {
        return sample::describe(cx, st).await;
    }
    match &h.kind {
        b"mdat" | b"free" | b"skip" | b"wide" | b"idat" => {
            Some(format!("{} bytes", st.body().len))
        }
        b"trak" => summary::track(cx, st.body()).await.ok().map(|t| t.describe()),
        _ => {
            if let Some(s) = boxes::describe(cx, st).await {
                return Some(s);
            }
            if let Some(s) = tables::describe(cx, st).await {
                return Some(s);
            }
            if let Some(s) = meta::describe(cx, st).await {
                return Some(s);
            }
            if let Some(s) = heif::describe(cx, st).await {
                return Some(s);
            }
            if st.ctx.brand.is_jp2()
                && let Some(s) = jp2::describe(cx, st).await
            {
                return Some(s);
            }
            sample::describe_config(cx, st).await
        }
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 4096)).await?;
    let probe = Head {
        data: &head,
        tail: &head,
        len: input.span.len,
    };
    let brand = classify(&probe).unwrap_or(Brand::Mp4);
    cx.annotate(brand.label());
    let ctx = Ctx {
        brand,
        parent: [0; 4],
        handler: [0; 4],
        depth: 0,
        siblings: input.span,
    };
    children(&cx, input, input.span, ctx).await
}

// ---------------------------------------------------------------------------
// Shared field helpers

/// Emits (or silently reads) a FullBox version and flags.
pub fn full_box(f: &mut Fields<'_>) -> Result<(u8, u32)> {
    let version = f.u8("Version").emit()?;
    let field = f.bytes("Flags", 3);
    let span = field.span();
    let raw = field.get()?;
    let flags = raw
        .iter()
        .fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
    f.node(hex("Flags", span, flags.into(), 24));
    Ok((version, flags))
}

/// Reads the FullBox version and flags at the start of `body`.
pub async fn version_flags(cx: &Cx, body: Span) -> Result<(u8, u32)> {
    let data = cx.read(body.sub(0, 4)).await?;
    let word = u32_be(&data, 0).unwrap_or(0);
    Ok((u8::try_from(word >> 24).unwrap_or(0), word & 0x00ff_ffff))
}

/// Reads a small box body for in-memory parsing.
pub async fn small(cx: &Cx, body: Span) -> Result<Vec<u8>> {
    crate::formats::vidutil::read_small(cx, body, 0x10000).await
}

/// A count node with the number of bytes the span holds.
pub fn bytes_node(name: &'static str, span: Span) -> Node {
    Node::new(name)
        .span(span)
        .summary(format!("{} bytes", span.len))
}

pub fn count(name: &'static str, span: Span, n: u64) -> Node {
    uint(name, span, n, 32)
}

pub fn len_u64(n: usize) -> u64 {
    to_u64(n)
}
