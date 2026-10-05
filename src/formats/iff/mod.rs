//! Chunked containers: Microsoft RIFF (little-endian, also RIFX, RF64 and
//! BW64) and Electronic Arts IFF 85 (big-endian).
//!
//! Both are a tree of chunks `id[4], size, data, pad-to-even`, where the
//! container chunks (`RIFF`/`LIST`, `FORM`/`LIST`/`CAT `/`PROP`) start their
//! data with a four-character type and hold further chunks. One walker serves
//! both families; each form type (WAVE, AVI, WEBP, AIFF, ILBM, ...) registers
//! its own [`Format`] and contributes chunk decoders, chunk summaries and a
//! one-line description of the file.

pub mod aiff;
pub mod amiga;
pub mod avi;
pub mod misc;
pub mod wav;
pub mod webp;

use std::sync::Arc;

use crate::bytes::{u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::sound::{fourcc, peek_text, text};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;

pub type FourCc = [u8; 4];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Riff,
    Iff,
}

/// What every chunk of one file shares.
#[derive(Clone, Debug)]
pub struct Ctx {
    pub input: Input,
    pub family: Family,
    pub endian: Endian,
    /// The form type of the outermost container (`WAVE`, `AIFF`, ...).
    pub form: FourCc,
    /// RF64 `ds64` sizes for chunks whose 32-bit size is `0xffffffff`.
    pub sizes: Arc<[(FourCc, u64)]>,
}

/// One chunk, as handed to the per-form decoders.
#[derive(Clone, Debug)]
pub struct Chunk {
    pub ctx: Ctx,
    pub id: FourCc,
    /// Header, data and padding (clamped to the input).
    pub span: Span,
    /// The data (clamped to the input).
    pub data: Span,
    /// The declared data size.
    pub size: u64,
    /// The type of the enclosing container (`INFO`, `strl`, the form type).
    pub list: FourCc,
    /// The data of the enclosing container, after its type.
    pub parent: Span,
}

impl Chunk {
    pub fn endian(&self) -> Endian {
        self.ctx.endian
    }

    pub fn input(&self) -> Input {
        self.ctx.input
    }
}

/// A top-level chunk found by [`scan`].
#[derive(Clone, Debug)]
pub struct Entry {
    pub id: FourCc,
    pub data: Span,
    pub size: u64,
}

// ---------------------------------------------------------------------------
// Registration

macro_rules! form {
    ($id:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $probe:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom($probe),
            dissect: crate::expander!(dissect: Input),
        };
    };
}

fn riff(h: &Head<'_>, form: &[u8]) -> bool {
    (h.starts_with(b"RIFF") || h.starts_with(b"RIFX")) && h.at(8, form)
}

fn iff(h: &Head<'_>, form: &[u8]) -> bool {
    h.starts_with(b"FORM") && h.at(8, form)
}

form!(
    WAV,
    "wav",
    "Waveform audio (WAVE, RF64, BW64)",
    ["wav", "wave", "bwf", "rf64"],
    "audio/wav",
    |h| riff(h, b"WAVE")
        || ((h.starts_with(b"RF64") || h.starts_with(b"BW64")) && h.at(8, b"WAVE"))
);
form!(
    AVI,
    "avi",
    "Audio Video Interleave",
    ["avi", "divx"],
    "video/x-msvideo",
    |h| riff(h, b"AVI ") || riff(h, b"AVIX")
);
form!(
    WEBP,
    "webp",
    "WebP image",
    ["webp"],
    "image/webp",
    |h| riff(h, b"WEBP")
);
form!(
    ANI,
    "ani",
    "Windows animated cursor",
    ["ani"],
    "application/x-navi-animation",
    |h| riff(h, b"ACON")
);
form!(
    RMI,
    "rmi",
    "RIFF MIDI",
    ["rmi"],
    "audio/mid",
    |h| riff(h, b"RMID")
);
form!(
    DLS,
    "dls",
    "Downloadable Sounds",
    ["dls"],
    "audio/dls",
    |h| riff(h, b"DLS ")
);
form!(
    SF2,
    "sf2",
    "SoundFont 2",
    ["sf2", "sf3", "sbk"],
    "audio/x-soundfont",
    |h| riff(h, b"sfbk")
);
form!(
    XWMA,
    "xwma",
    "XAudio2 WMA",
    ["xwma"],
    "audio/x-xwma",
    |h| riff(h, b"XWMA")
);
form!(
    CDXA,
    "cdxa",
    "Video CD MPEG (RIFF CDXA)",
    ["dat"],
    "video/mpeg",
    |h| riff(h, b"CDXA")
);
form!(
    RIFF_PALETTE,
    "riff-palette",
    "RIFF palette",
    ["pal"],
    "application/octet-stream",
    |h| riff(h, b"PAL ")
);
form!(
    RDIB,
    "rdib",
    "RIFF device-independent bitmap",
    ["rdi"],
    "image/bmp",
    |h| riff(h, b"RDIB")
);
form!(
    RMMP,
    "rmmp",
    "RIFF multimedia movie",
    ["mmm"],
    "application/octet-stream",
    |h| riff(h, b"RMMP")
);
form!(
    QCP,
    "qcp",
    "Qualcomm PureVoice",
    ["qcp"],
    "audio/qcelp",
    |h| riff(h, b"QLCM")
);
form!(
    CDR,
    "cdr",
    "CorelDRAW drawing",
    ["cdr", "cdt"],
    "application/vnd.corel-draw",
    |h| riff(h, b"CDR")
);
form!(
    FOURXM,
    "4xm",
    "4X Technologies movie",
    ["4xm"],
    "video/x-4xm",
    |h| riff(h, b"4XMV")
);
form!(
    AMV,
    "amv",
    "AMV video",
    ["amv"],
    "video/x-amv",
    |h| riff(h, b"AMV ")
);
form!(
    AIFF,
    "aiff",
    "Audio Interchange File Format",
    ["aiff", "aif"],
    "audio/aiff",
    |h| iff(h, b"AIFF")
);
form!(
    AIFC,
    "aifc",
    "Audio Interchange File Format, compressed",
    ["aifc", "aiff", "aif"],
    "audio/aiff",
    |h| iff(h, b"AIFC")
);
form!(
    SVX8,
    "8svx",
    "Amiga 8-bit sampled voice",
    ["8svx", "iff", "svx"],
    "audio/x-8svx",
    |h| iff(h, b"8SVX")
);
form!(
    SVX16,
    "16sv",
    "Amiga 16-bit sampled voice",
    ["16sv", "iff", "svx"],
    "audio/x-16sv",
    |h| iff(h, b"16SV")
);
form!(
    ILBM,
    "ilbm",
    "Amiga interleaved bitmap",
    ["ilbm", "iff", "lbm"],
    "image/x-ilbm",
    |h| iff(h, b"ILBM") || iff(h, b"PBM ") || iff(h, b"ACBM")
);
form!(
    ANIM,
    "anim",
    "Amiga IFF animation",
    ["anim", "iff"],
    "video/x-anim",
    |h| iff(h, b"ANIM")
);
form!(
    SMUS,
    "smus",
    "Amiga simple musical score",
    ["smus", "iff"],
    "audio/x-smus",
    |h| iff(h, b"SMUS")
);
form!(
    FTXT,
    "ftxt",
    "Amiga formatted text",
    ["ftxt", "iff"],
    "text/x-iff",
    |h| iff(h, b"FTXT")
);
form!(
    MAUD,
    "maud",
    "MacroSystem audio",
    ["maud", "iff"],
    "audio/x-maud",
    |h| iff(h, b"MAUD")
);

/// Any other RIFF form.
pub static RIFF: Format = Format {
    name: "riff",
    title: "Resource Interchange File Format",
    extensions: &["riff"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| {
        (h.starts_with(b"RIFF") || h.starts_with(b"RIFX") || h.starts_with(b"RF64"))
            && h.data.get(8..12).is_some_and(is_fourcc)
    }),
    dissect: crate::expander!(dissect: Input),
};

/// Any other EA IFF 85 file.
pub static IFF: Format = Format {
    name: "iff",
    title: "Interchange File Format (EA IFF 85)",
    extensions: &["iff"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| {
        (h.starts_with(b"FORM") || h.starts_with(b"CAT ") || h.starts_with(b"LIST"))
            && h.data.get(8..12).is_some_and(is_fourcc)
    }),
    dissect: crate::expander!(dissect: Input),
};

fn is_fourcc(b: &[u8]) -> bool {
    b.len() == 4 && b.iter().all(|&c| (0x20..0x7f).contains(&c))
}

// ---------------------------------------------------------------------------
// Walking

const RIFF_CONTAINERS: &[&FourCc] = &[b"RIFF", b"LIST", b"RIFX"];
const IFF_CONTAINERS: &[&FourCc] = &[b"FORM", b"LIST", b"CAT ", b"PROP"];

/// Whether `id` holds further chunks after a four-character type.
pub fn is_container(family: Family, id: &FourCc) -> bool {
    match family {
        Family::Riff => RIFF_CONTAINERS.contains(&id),
        Family::Iff => IFF_CONTAINERS.contains(&id),
    }
}

fn word(endian: Endian, data: &[u8], at: usize) -> Option<u32> {
    match endian {
        Endian::Little => u32_le(data, at),
        Endian::Big => u32_be(data, at),
    }
}

/// Reads the chunk header at `pos` of `region`: id, declared size, and the
/// whole chunk's length (header, data, pad), resolving RF64 sizes.
async fn header(cx: &Cx, ctx: &Ctx, region: Span, pos: u64) -> Result<(FourCc, u64, u64)> {
    let h = cx.read(region.sub(pos, 8)).await?;
    let id = crate::bytes::array::<4>(&h, 0).unwrap_or_default();
    let raw = word(ctx.endian, &h, 4).unwrap_or(0);
    let size = if raw == u32::MAX && ctx.family == Family::Riff {
        ctx.sizes
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, s)| *s)
            .unwrap_or_else(|| region.len.saturating_sub(pos).saturating_sub(8))
    } else {
        u64::from(raw)
    };
    let total = size.saturating_add(8).saturating_add(size & 1);
    Ok((id, size, total))
}

/// The top-level chunks of `region` (at most `max`), for describing a file
/// before its chunks are listed.
pub async fn scan(cx: &Cx, ctx: &Ctx, region: Span, max: usize) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    let mut pos = 0u64;
    while pos.saturating_add(8) <= region.len && out.len() < max {
        let (id, size, total) = header(cx, ctx, region, pos).await?;
        out.push(Entry {
            id,
            data: region.sub(pos.saturating_add(8), size),
            size,
        });
        pos = pos.saturating_add(total);
    }
    Ok(out)
}

/// The chunks directly inside a container, by id (searching at most 64).
pub async fn find(cx: &Cx, ctx: &Ctx, region: Span, id: &FourCc) -> Result<Option<Entry>> {
    Ok(scan(cx, ctx, region, 64)
        .await?
        .into_iter()
        .find(|e| &e.id == id))
}

/// Pushes one node per chunk in `region`, paged.
pub async fn walk(cx: &Cx, ctx: &Ctx, region: Span, list: FourCc) -> Result<()> {
    let mut pos = 0u64;
    while pos < region.len {
        if region.len.saturating_sub(pos) < 8 {
            cx.emit(Node::new("Trailing bytes").span(region.tail(pos)));
            break;
        }
        let (id, size, total) = header(cx, ctx, region, pos).await?;
        if id == [0; 4] && size == 0 {
            cx.emit(
                Node::new("Zero padding")
                    .span(region.tail(pos))
                    .summary(format!("{} bytes", region.len.saturating_sub(pos))),
            );
            break;
        }
        let span = region.sub(pos, total);
        let data = region.sub(pos.saturating_add(8), size);
        let chunk = Chunk {
            ctx: ctx.clone(),
            id,
            span,
            data,
            size,
            list,
            parent: region,
        };
        let node = chunk_node(cx, chunk).await;
        cx.push(node).await;
        pos = pos.saturating_add(total);
    }
    Ok(())
}

/// The collapsed node for a chunk: name, summary, diagnostics, and its
/// lazy expansion.
async fn chunk_node(cx: &Cx, chunk: Chunk) -> Node {
    let id = fourcc(&chunk.id);
    let container = is_container(chunk.ctx.family, &chunk.id);
    let mut name = id.clone();
    let mut summary = None;
    if container {
        let kind = cx.read_avail(chunk.data.sub(0, 4)).await.unwrap_or_default();
        name = format!("{id} {}", fourcc(&kind));
        summary = Some(format!("{} bytes", chunk.size.saturating_sub(4)));
    } else {
        match summarize(cx, &chunk).await {
            Ok(Some(s)) => summary = Some(s),
            Ok(None) => {}
            Err(_) => summary = Some(format!("{} bytes", chunk.size)),
        }
    }
    let mut node = Node::new(name)
        .span(chunk.span)
        .summary(summary.unwrap_or_else(|| format!("{} bytes", chunk.size)));
    if let Some(d) = describe_id(&chunk) {
        node = node.desc(d);
    }
    if chunk.data.len < chunk.size {
        node = node.diag(Diagnostic::truncated(
            Span::new(chunk.data.source, chunk.data.offset, chunk.size),
            chunk.data.len,
        ));
    }
    node.lazy(crate::expander!(self::expand: Chunk), chunk)
}

/// Expands a chunk: its header fields, then its decoded data.
async fn expand(cx: Cx, chunk: Chunk) -> Result<()> {
    let endian = chunk.endian();
    let head = cx.block(chunk.span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, endian);
    f.ascii("Chunk ID", 4).emit()?;
    let raw = f
        .u32("Chunk size")
        .with(|&v, n| {
            if v == u32::MAX && chunk.ctx.family == Family::Riff {
                n.summary(format!("see ds64: {} bytes", chunk.size))
            } else {
                n
            }
        })
        .emit()?;
    let _ = raw;
    if is_container(chunk.ctx.family, &chunk.id) {
        let block = cx.block(chunk.data.sub(0, 4)).await?;
        let kind = Fields::emitting(&cx, &block, endian)
            .bytes("Type", 4)
            .with(|b, n| n.value(text(fourcc(b))))
            .emit()?;
        let kind = crate::bytes::array::<4>(&kind, 0).unwrap_or_default();
        walk(&cx, &chunk.ctx, chunk.data.tail(4), kind).await?;
    } else if !common(&cx, &chunk).await? && !body(&cx, &chunk).await? {
        cx.emit(Node::new("Data").span(chunk.data));
    }
    if chunk.size & 1 == 1 && chunk.span.len > chunk.size.saturating_add(8) {
        cx.emit(
            Node::new("Pad byte")
                .span(chunk.span.tail(chunk.size.saturating_add(8)))
                .desc("Chunks are padded to an even length"),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dispatch to the form decoders

/// Decoders shared by all forms. Returns whether the chunk was handled.
async fn common(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let input = chunk.input();
    match (&chunk.id, &chunk.list) {
        (_, b"INFO") => {
            let text = peek_text(cx, chunk.data, chunk.data.len).await?;
            cx.emit(
                Node::new("Text")
                    .span(chunk.data)
                    .value(crate::value::Value::Text(text)),
            );
        }
        (b"JUNK" | b"junk" | b"PAD " | b"FLLR" | b"free", _) => {
            cx.emit(Node::new("Padding").span(chunk.data));
        }
        (b"id3 " | b"ID3 " | b"ID32", _) => {
            cx.emit(embedded("ID3 tag", input.nested(chunk.data)));
        }
        (b"XMP " | b"_PMX" | b"iXML" | b"axml", _) => {
            let text = peek_text(cx, chunk.data, chunk.data.len.min(1 << 20)).await?;
            cx.emit(
                Node::new("XML")
                    .span(chunk.data)
                    .value(crate::value::Value::Text(text)),
            );
        }
        _ => return Ok(false),
    }
    Ok(true)
}

async fn body(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    match (chunk.ctx.family, &chunk.ctx.form) {
        (Family::Riff, b"WAVE") => wav::chunk(cx, chunk).await,
        (Family::Riff, b"AVI " | b"AVIX") => avi::chunk(cx, chunk).await,
        (Family::Riff, b"WEBP") => webp::chunk(cx, chunk).await,
        (Family::Riff, _) => misc::chunk(cx, chunk).await,
        (Family::Iff, b"AIFF" | b"AIFC") => aiff::chunk(cx, chunk).await,
        (Family::Iff, _) => amiga::chunk(cx, chunk).await,
    }
}

/// A summary for a chunk's collapsed line, if the form has one.
async fn summarize(cx: &Cx, chunk: &Chunk) -> Result<Option<String>> {
    if &chunk.list == b"INFO" || is_text_chunk(chunk) {
        let text = peek_text(cx, chunk.data, 120).await?;
        return Ok(Some(crate::formats::sound::clip(&text, 60)));
    }
    match (chunk.ctx.family, &chunk.ctx.form) {
        (Family::Riff, b"WAVE") => wav::summary(cx, chunk).await,
        (Family::Riff, b"AVI " | b"AVIX") => avi::summary(cx, chunk).await,
        (Family::Riff, b"WEBP") => webp::summary(cx, chunk).await,
        (Family::Riff, _) => misc::summary(cx, chunk).await,
        (Family::Iff, b"AIFF" | b"AIFC") => aiff::summary(cx, chunk).await,
        (Family::Iff, _) => amiga::summary(cx, chunk).await,
    }
}

/// IFF's generic text chunks.
fn is_text_chunk(chunk: &Chunk) -> bool {
    chunk.ctx.family == Family::Iff
        && matches!(&chunk.id, b"NAME" | b"AUTH" | b"(c) " | b"ANNO" | b"CHRS")
}

fn describe_id(chunk: &Chunk) -> Option<&'static str> {
    let table: &[(&FourCc, &str)] = match chunk.ctx.family {
        Family::Riff => &[
            (b"JUNK", "Filler, ignored"),
            (b"LIST", "List of chunks"),
            (b"INAM", "Title"),
            (b"IART", "Artist"),
            (b"ICMT", "Comment"),
            (b"ICOP", "Copyright"),
            (b"ICRD", "Creation date"),
            (b"IGNR", "Genre"),
            (b"ISFT", "Software"),
            (b"IPRD", "Product (album)"),
            (b"IENG", "Engineer"),
            (b"ITRK", "Track number"),
            (b"IPRT", "Track number"),
            (b"ISBJ", "Subject"),
            (b"IKEY", "Keywords"),
            (b"ISRC", "Source"),
            (b"ITCH", "Technician"),
            (b"ILNG", "Language"),
            (b"id3 ", "ID3 tag"),
        ],
        Family::Iff => &[
            (b"NAME", "Name"),
            (b"AUTH", "Author"),
            (b"(c) ", "Copyright"),
            (b"ANNO", "Annotation"),
            (b"CHRS", "Character string"),
            (b"FORM", "Form: a typed group of chunks"),
            (b"CAT ", "Concatenation of forms"),
            (b"PROP", "Shared properties for a LIST"),
        ],
    };
    table
        .iter()
        .find(|(id, _)| *id == &chunk.id)
        .map(|(_, d)| *d)
        .or_else(|| match (chunk.ctx.family, &chunk.ctx.form) {
            (Family::Riff, b"WAVE") => wav::describe_id(&chunk.id),
            (Family::Riff, b"AVI " | b"AVIX") => avi::describe_id(&chunk.id),
            (Family::Riff, b"WEBP") => webp::describe_id(&chunk.id),
            (Family::Iff, b"AIFF" | b"AIFC") => aiff::describe_id(&chunk.id),
            _ => None,
        })
}

/// One line about the whole file.
async fn describe(cx: &Cx, ctx: &Ctx, region: Span) -> Result<Option<String>> {
    match (ctx.family, &ctx.form) {
        (Family::Riff, b"WAVE") => wav::describe(cx, ctx, region).await,
        (Family::Riff, b"AVI ") => avi::describe(cx, ctx, region).await,
        (Family::Riff, b"WEBP") => webp::describe(cx, ctx, region).await,
        (Family::Riff, _) => misc::describe(cx, ctx, region).await,
        (Family::Iff, b"AIFF" | b"AIFC") => aiff::describe(cx, ctx, region).await,
        (Family::Iff, _) => amiga::describe(cx, ctx, region).await,
    }
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 12)).await?;
    let magic = crate::bytes::array::<4>(&head, 0).unwrap_or_default();
    let form = crate::bytes::array::<4>(&head, 8).unwrap_or_default();
    let (family, endian) = match &magic {
        b"RIFF" | b"RF64" | b"BW64" => (Family::Riff, Endian::Little),
        b"RIFX" => (Family::Riff, Endian::Big),
        b"FORM" | b"LIST" | b"CAT " => (Family::Iff, Endian::Big),
        _ => {
            return Err(Diagnostic::malformed("not a RIFF or IFF file").at(file.sub(0, 4)));
        }
    };
    let raw = word(endian, &head, 4).unwrap_or(0);

    let mut sizes: Vec<(FourCc, u64)> = Vec::new();
    let mut size = u64::from(raw);
    let header_node = crate::fields::struct_node(
        "Header",
        file.sub(0, 12),
        endian,
        (),
        |f: &mut Fields<'_>, _: &()| {
            f.ascii("Chunk ID", 4).emit()?;
            f.u32("Size").emit()?;
            f.ascii("Form type", 4).emit()?;
            Ok(())
        },
    );
    cx.emit(header_node);
    if matches!(&magic, b"RF64" | b"BW64") {
        match ds64(&cx, file).await {
            Ok((riff, table)) => {
                if raw == u32::MAX {
                    size = riff;
                }
                sizes = table;
            }
            Err(e) => cx.diag(e),
        }
    }
    let ctx = Ctx {
        input,
        family,
        endian,
        form,
        sizes: sizes.into(),
    };
    let region = file.sub(12, size.saturating_sub(4));
    if file.len < size.saturating_add(8) {
        cx.diag(Diagnostic::truncated(
            Span::new(file.source, file.offset, size.saturating_add(8)),
            file.len,
        ));
    }
    let kind = match family {
        Family::Riff => "RIFF",
        Family::Iff => "IFF",
    };
    cx.annotate(format!("{kind} {}", fourcc(&form)));
    match describe(&cx, &ctx, region).await {
        Ok(Some(line)) => cx.annotate(line),
        Ok(None) => {}
        Err(e) => cx.diag(e),
    }
    walk(&cx, &ctx, region, form).await?;

    let end = size.saturating_add(8).saturating_add(size & 1);
    if end < file.len {
        let rest = file.tail(end);
        let next = cx.read_avail(rest.sub(0, 4)).await?;
        if next == magic {
            // OpenDML AVI: further RIFF chunks follow the first.
            walk(&cx, &ctx, rest, form).await?;
        } else {
            cx.emit(
                embedded("Trailing data", input.nested(rest))
                    .summary(format!("{} bytes after the last chunk", rest.len)),
            );
        }
    }
    Ok(())
}

/// The RF64/BW64 `ds64` chunk: 64-bit sizes for the RIFF and data chunks,
/// plus a table for any other oversized chunk.
async fn ds64(cx: &Cx, file: Span) -> Result<(u64, Vec<(FourCc, u64)>)> {
    let head = cx.read(file.sub(12, 36)).await?;
    if head.get(..4) != Some(b"ds64") {
        return Err(Diagnostic::malformed("RF64 file without a ds64 chunk").at(file.sub(12, 4)));
    }
    let riff = u64_le(&head, 8).unwrap_or(0);
    let data = u64_le(&head, 16).unwrap_or(0);
    let mut table = vec![(*b"data", data)];
    let count = u32_le(&head, 32).unwrap_or(0);
    let entries = file.sub(48, u64::from(count).saturating_mul(12));
    let raw = cx.read_avail(entries).await?;
    for entry in raw.as_chunks::<12>().0 {
        let id = crate::bytes::array::<4>(entry, 0).unwrap_or_default();
        table.push((id, u64_le(entry, 4).unwrap_or(0)));
    }
    Ok((riff, table))
}
