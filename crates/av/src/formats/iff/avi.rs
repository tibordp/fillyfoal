//! AVI chunks: `avih`, `strh`, `strf` (BITMAPINFOHEADER or WAVEFORMATEX by
//! stream type), `strn`, `strd`, `vprp`, OpenDML `indx`/`ix##`/`dmlh`,
//! `idx1`, and the stream data chunks of `movi`. Index entries point at the
//! chunks they index; OpenDML files continue in further `AVIX` RIFF chunks,
//! which the RIFF walker lists after the first.

use crate::bytes::{u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::embedded;
use crate::formats::iff::{Chunk, Ctx, Entry, FourCc, find, scan, wav};
use crate::formats::util::sound::{fourcc, peek_text, text};
use crate::formats::util::vidutil;
use crate::formats::video::asf;
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag};

const AVIF: FlagTable = &[
    flag(0x10, "HASINDEX"),
    flag(0x20, "MUSTUSEINDEX"),
    flag(0x100, "ISINTERLEAVED"),
    flag(0x800, "TRUSTCKTYPE"),
    flag(0x10000, "WASCAPTUREFILE"),
    flag(0x20000, "COPYRIGHTED"),
];

const STREAM_FLAGS: FlagTable = &[flag(0x1, "DISABLED"), flag(0x10000, "VIDEO_PALCHANGES")];

const INDEX_FLAGS: FlagTable = &[
    flag(0x1, "LIST"),
    flag(0x10, "KEYFRAME"),
    flag(0x100, "NO_TIME"),
];

fn fps_summary(usec: u32, n: Node) -> Node {
    if usec == 0 {
        n
    } else {
        n.summary(format!("{} fps", vidutil::num(1e6 / f64::from(usec))))
    }
}

record! {
    /// MainAVIHeader
    pub struct MainHeader {
        usec_per_frame: u32 "Microseconds per frame" .with(|&v, n| fps_summary(v, n)),
        max_bytes_per_sec: u32 "Max bytes per second" .desc("Approximate maximum data rate"),
        padding: u32 "Padding granularity" .desc("Data is padded to a multiple of this many bytes"),
        flags: u32 "Flags" .flags(AVIF),
        total_frames: u32 "Total frames" .desc("Frames in the first RIFF chunk (OpenDML files count all frames in dmlh)"),
        initial_frames: u32 "Initial frames" .desc("Frames before the first video frame in interleaved files"),
        streams: u32 "Streams",
        buffer: u32 "Suggested buffer size",
        width: u32 "Width",
        height: u32 "Height",
        _reserved: bytes[16] "Reserved",
    }
}

impl MainHeader {
    fn fps(&self) -> f64 {
        if self.usec_per_frame == 0 {
            0.0
        } else {
            1e6 / f64::from(self.usec_per_frame)
        }
    }
}

const STREAM_TYPE: &[(&FourCc, &str)] = &[
    (b"vids", "video"),
    (b"auds", "audio"),
    (b"txts", "text"),
    (b"mids", "MIDI"),
    (b"iavs", "DV (interleaved)"),
];

fn stream_type(t: &[u8]) -> &'static str {
    STREAM_TYPE
        .iter()
        .find(|(k, _)| k.as_slice() == t)
        .map_or("stream", |(_, n)| n)
}

/// A FourCC field whose value may also be a small number (a stream
/// handler of 0 or 1 for audio).
fn handler_node(b: &[u8], n: Node) -> Node {
    let v = u32_le(b, 0).unwrap_or(0);
    if b.iter().all(|&c| c.is_ascii_graphic() || c == b' ') {
        let n = n.value(text(fourcc(b)));
        match vidutil::codec_name(b) {
            Some(c) => n.summary(c),
            None => n,
        }
    } else {
        n.value(Value::UInt {
            value: v.into(),
            bits: 32,
            radix: Radix::Hex,
        })
    }
}

fn language_node(l: u16, n: Node) -> Node {
    match crate::formats::util::lcid::name(l.into()) {
        Some(name) if l != 0 => n.summary(name),
        _ => n,
    }
}

fn length_summary(length: u32, scale: u32, rate: u32) -> Option<String> {
    (rate > 0).then(|| vidutil::seconds_f64(f64::from(length) * f64::from(scale) / f64::from(rate)))
}

record! {
    /// AVISTREAMHEADER
    pub struct StreamHeader {
        kind: bytes[4] "Type" .with(|b, n| n.value(text(fourcc(b))).summary(stream_type(b))),
        handler: bytes[4] "Handler" .with(|b, n| handler_node(b, n)) .desc("Preferred codec (a FourCC for video)"),
        flags: u32 "Flags" .flags(STREAM_FLAGS),
        priority: u16 "Priority",
        language: u16 "Language" .with(|&l, n| language_node(l, n)),
        initial_frames: u32 "Initial frames" .desc("How far audio is skewed ahead of video in interleaved files"),
        scale: u32 "Scale" .desc("Time base: rate / scale units per second"),
        rate: u32 "Rate" .with(|&r, n| if scale > 0 { n.summary(format!("{} per second", vidutil::num(f64::from(r) / f64::from(scale)))) } else { n }),
        start: u32 "Start" .desc("Start time, in rate/scale units"),
        length: u32 "Length" .desc("In rate/scale units (frames or samples)") .with(|&l, n| match length_summary(l, scale, rate) { Some(s) => n.summary(s), None => n }),
        buffer: u32 "Suggested buffer size",
        quality: u32 "Quality" .desc("0 to 10000; 0xffffffff = default") .with(|&q, n| if q == u32::MAX { n.summary("default") } else { n }),
        sample_size: u32 "Sample size" .desc("Bytes per sample; 0 = samples vary in size (one chunk each)"),
        left: i16 "Frame left",
        top: i16 "Frame top",
        right: i16 "Frame right",
        bottom: i16 "Frame bottom",
    }
}

impl StreamHeader {
    fn rate(&self) -> f64 {
        if self.scale == 0 {
            0.0
        } else {
            f64::from(self.rate) / f64::from(self.scale)
        }
    }

    fn seconds(&self) -> Option<f64> {
        (self.rate > 0)
            .then(|| f64::from(self.length) * f64::from(self.scale) / f64::from(self.rate))
    }
}

record! {
    pub struct IndexEntry {
        id: bytes[4] "Chunk ID" .with(|b, n| n.value(text(fourcc(b)))),
        flags: u32 "Flags" .flags(INDEX_FLAGS),
        offset: u32 "Offset" .hex() .desc("Of the chunk header, relative to the movi list's type (or to the file, in some old files)"),
        size: u32 "Size",
    }
}

const INDEX_TYPE: EnumTable = &[
    (0, "index of indexes"),
    (1, "index of chunks"),
    (0x80, "data"),
];
const INDEX_SUBTYPE: EnumTable = &[(0, "frames"), (1, "fields")];

const VIDEO_FORMATS: EnumTable = &[
    (0, "unknown"),
    (1, "PAL square pixels"),
    (2, "PAL CCIR 601"),
    (3, "NTSC square pixels"),
    (4, "NTSC CCIR 601"),
];
const VIDEO_STANDARDS: EnumTable = &[(0, "unknown"), (1, "PAL"), (2, "NTSC"), (3, "SECAM")];

pub fn describe_id(id: &FourCc) -> Option<&'static str> {
    Some(match id {
        b"avih" => "Main AVI header",
        b"strh" => "Stream header",
        b"strf" => "Stream format",
        b"strn" => "Stream name",
        b"strd" => "Stream codec data",
        b"indx" => "OpenDML index (usually a super index of ix## chunks)",
        b"idx1" => "Legacy index of the first movi list",
        b"dmlh" => "OpenDML extended header",
        b"vprp" => "Video properties",
        [b'i', b'x', _, _] => "OpenDML standard index",
        _ => match stream_chunk(id) {
            Some((_, "dc")) => "Compressed video frame",
            Some((_, "db")) => "Uncompressed video frame",
            Some((_, "wb")) => "Audio data",
            Some((_, "tx")) => "Subtitle or text",
            Some((_, "pc")) => "Palette change",
            _ => return None,
        },
    })
}

/// `##dc`, `##wb`, ...: stream number and kind.
fn stream_chunk(id: &FourCc) -> Option<(u32, &str)> {
    let [a, b, _, _] = *id;
    if !a.is_ascii_digit() || !b.is_ascii_digit() {
        return None;
    }
    let n = u32::from(a.saturating_sub(b'0'))
        .saturating_mul(10)
        .saturating_add(u32::from(b.saturating_sub(b'0')));
    let kind = std::str::from_utf8(id.get(2..4)?).ok()?;
    Some((n, kind))
}

/// The `strh` of the stream list a chunk belongs to.
async fn stream_header(cx: &Cx, chunk: &Chunk) -> Option<StreamHeader> {
    let strh = find(cx, &chunk.ctx, chunk.parent, b"strh").await.ok()??;
    parse(cx, strh.data, chunk.endian(), &(), StreamHeader::layout)
        .await
        .ok()
}

/// (width, height, bits per pixel, compression) from a BITMAPINFOHEADER.
fn bitmap_info(d: &[u8]) -> Option<(i32, i32, u16, [u8; 4])> {
    Some((
        i32::from_le_bytes(crate::bytes::array(d, 4)?),
        i32::from_le_bytes(crate::bytes::array(d, 8)?),
        u16_le(d, 14)?,
        crate::bytes::array(d, 16)?,
    ))
}

/// "Motion JPEG 16×16, 24-bit".
fn video_format(d: &[u8]) -> Option<String> {
    let (w, h, bits, c) = bitmap_info(d)?;
    Some(format!(
        "{} {w}×{}, {bits}-bit",
        asf::compression_name(&c),
        h.unsigned_abs()
    ))
}

/// The codec of a video format, for the file summary.
fn video_codec(d: &[u8]) -> Option<String> {
    let (w, h, _, c) = bitmap_info(d)?;
    Some(format!(
        "{} {w}×{}",
        asf::compression_name(&c),
        h.unsigned_abs()
    ))
}

pub async fn summary(cx: &Cx, chunk: &Chunk) -> Result<Option<String>> {
    let e = chunk.endian();
    Ok(match &chunk.id {
        b"avih" => {
            let h = parse(cx, chunk.data, e, &(), MainHeader::layout).await?;
            let mut s = format!(
                "{}×{}, {} fps, {}, {}",
                h.width,
                h.height,
                vidutil::num(h.fps()),
                vidutil::plural(h.total_frames, "frame"),
                vidutil::plural(h.streams, "stream")
            );
            if h.flags & 0x100 != 0 {
                s.push_str(", interleaved");
            }
            Some(s)
        }
        b"strh" => {
            let h = parse(cx, chunk.data, e, &(), StreamHeader::layout).await?;
            let mut s = stream_type(&h.kind).to_owned();
            if h.handler.iter().all(|&c| c.is_ascii_graphic() || c == b' ') {
                s.push_str(&format!(" {}", fourcc(&h.handler)));
            }
            if &h.kind == b"vids" {
                s.push_str(&format!(
                    ", {} fps, {}",
                    vidutil::num(h.rate()),
                    vidutil::plural(h.length, "frame")
                ));
            } else {
                let unit = if &h.kind == b"auds" {
                    "samples"
                } else {
                    "units"
                };
                s.push_str(&format!(
                    ", {} {unit}/s, length {}",
                    vidutil::num(h.rate()),
                    h.length
                ));
            }
            if let Some(secs) = h.seconds() {
                s.push_str(&format!(" ({})", vidutil::seconds_f64(secs)));
            }
            Some(s)
        }
        b"strf" => match stream_header(cx, chunk).await {
            Some(h) if &h.kind == b"vids" => {
                let d = cx.read_avail(chunk.data.sub(0, 40)).await?;
                video_format(&d)
            }
            Some(h) if &h.kind == b"auds" => Some(
                parse(cx, chunk.data, e, &(), wav::wave_format)
                    .await?
                    .summary(),
            ),
            _ => None,
        },
        b"strn" => Some(peek_text(cx, chunk.data, 120).await?),
        b"strd" => Some(format!("{} bytes", chunk.size)),
        b"idx1" => Some(entry_count(chunk.size / 16)),
        b"JUNK" => reserved_kind(cx, chunk).await?.map(|k| match k {
            Reserved::SuperIndex => "space reserved for an OpenDML super index (unused)".to_owned(),
            Reserved::Odml => "space reserved for the OpenDML header list (unused)".to_owned(),
        }),
        b"dmlh" => {
            let d = cx.read_avail(chunk.data.sub(0, 4)).await?;
            u32_le(&d, 0).map(|n| format!("{} in all", vidutil::plural(n, "frame")))
        }
        b"vprp" => {
            let d = cx.read_avail(chunk.data.sub(0, 36)).await?;
            vprp_summary(&d)
        }
        b"indx" | [b'i', b'x', _, _] => {
            let d = cx.read_avail(chunk.data.sub(0, 12)).await?;
            index_summary(&d)
        }
        id => stream_chunk(id).map(|(n, kind)| {
            let what = match kind {
                "dc" => "video",
                "db" => "uncompressed video",
                "wb" => "audio",
                "tx" => "text",
                "pc" => "palette change",
                _ => "data",
            };
            format!("stream {n} {what}, {} bytes", chunk.size)
        }),
    })
}

/// What FFmpeg reserves as `JUNK` in the headers, to be renamed `indx` and
/// `LIST odml` if the file grows into OpenDML (past one RIFF chunk).
#[derive(Clone, Copy)]
enum Reserved {
    /// In `strl`: a super index header (4 longs per entry, index of
    /// indexes) and room for its entries.
    SuperIndex,
    /// In `hdrl`: `odml`, then a `dmlh` chunk header and its zeroed body.
    Odml,
}

async fn reserved_kind(cx: &Cx, chunk: &Chunk) -> Result<Option<Reserved>> {
    let d = cx.read_avail(chunk.data.sub(0, 24)).await?;
    Ok(match &chunk.list {
        b"strl"
            if d.len() == 24
                && u16_le(&d, 0) == Some(4)
                && d.get(2) == Some(&0)
                && d.get(3) == Some(&0) =>
        {
            Some(Reserved::SuperIndex)
        }
        b"hdrl" if d.starts_with(b"odmldmlh") => Some(Reserved::Odml),
        _ => None,
    })
}

/// A `JUNK` chunk in the headers that holds reserved OpenDML structures.
async fn reserved(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let data = chunk.data;
    let e = chunk.endian();
    match reserved_kind(cx, chunk).await? {
        Some(Reserved::SuperIndex) => {
            let block = cx.block(data.sub(0, 24)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u16("Longs per entry").emit()?;
            f.u8("Index subtype").emit()?;
            f.u8("Index type").desc("0: index of indexes").emit()?;
            f.u32("Entries in use").emit()?;
            f.bytes("Indexed chunk ID", 4)
                .with(|b, n| n.value(text(fourcc(b))))
                .emit()?;
            f.bytes("Reserved", 12).emit()?;
            cx.emit(
                Node::new("Entry space")
                    .span(data.tail(24))
                    .summary(format!(
                        "room for {} entries",
                        data.len.saturating_sub(24) / 16
                    )),
            );
        }
        Some(Reserved::Odml) => {
            let block = cx.block(data.sub(0, 12)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.bytes("List type", 4)
                .with(|b, n| n.value(text(fourcc(b))))
                .emit()?;
            f.bytes("Inner chunk ID", 4)
                .with(|b, n| n.value(text(fourcc(b))))
                .emit()?;
            f.u32("Inner chunk size").emit()?;
            cx.emit(Node::new("Reserved").span(data.tail(12)));
        }
        None => return Ok(false),
    }
    Ok(true)
}

/// "1 entry", "3 entries".
fn entry_count(n: u64) -> String {
    if n == 1 {
        "1 entry".to_owned()
    } else {
        format!("{n} entries")
    }
}

/// "super index of 00dc, 2 entries".
fn index_summary(d: &[u8]) -> Option<String> {
    let kind = *d.get(3)?;
    let entries = u32_le(d, 4)?;
    let id = fourcc(d.get(8..12)?);
    let what = match kind {
        0 => "super index",
        1 => "standard index",
        _ => "index",
    };
    Some(format!("{what} of {id}, {}", entry_count(entries.into())))
}

/// "PAL, 4:3, 720×576, 2 fields".
fn vprp_summary(d: &[u8]) -> Option<String> {
    let standard = u32_le(d, 4)?;
    let refresh = u32_le(d, 8)?;
    let aspect = u32_le(d, 20)?;
    let w = u32_le(d, 24)?;
    let h = u32_le(d, 28)?;
    let fields = u32_le(d, 32)?;
    let mut parts = Vec::new();
    if standard != 0 {
        parts.push(vidutil::lookup_or(VIDEO_STANDARDS, standard.into()));
    }
    if refresh != 0 {
        parts.push(format!("{refresh} Hz"));
    }
    parts.push(format!("{}:{}", aspect >> 16, aspect & 0xffff));
    parts.push(format!("{w}×{h}"));
    parts.push(vidutil::plural(fields, "field"));
    Some(parts.join(", "))
}

pub async fn chunk(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let e = chunk.endian();
    let data = chunk.data;
    match &chunk.id {
        b"avih" => cx.emit(MainHeader::node("Main header", data, e)),
        b"strh" => cx.emit(StreamHeader::node("Stream header", data, e)),
        b"strf" => match stream_header(cx, chunk).await {
            Some(h) if &h.kind == b"vids" => {
                let block = cx.block(data).await?;
                let mut f = Fields::emitting(cx, &block, e);
                asf::bitmapinfoheader(&mut f)?;
                let rest = f.remaining();
                if rest > 0 {
                    f.bytes("Codec data", rest).emit()?;
                }
            }
            Some(h) if &h.kind == b"auds" => {
                let block = cx.block(data).await?;
                let mut f = Fields::emitting(cx, &block, e);
                asf::waveformatex(&mut f)?;
                let rest = f.remaining();
                if rest > 0 {
                    f.bytes("Extra data", rest).emit()?;
                }
            }
            _ => cx.emit(Node::new("Format data").span(data)),
        },
        b"strn" => {
            let t = peek_text(cx, data, data.len).await?;
            cx.emit(Node::new("Name").span(data).value(text(t)));
        }
        b"strd" => cx.emit(
            Node::new("Codec data")
                .span(data)
                .summary(format!("{} bytes", data.len)),
        ),
        b"dmlh" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(cx, &block, e)
                .u32("Total frames")
                .desc("Frames in all RIFF chunks")
                .emit()?;
            if data.len > 4 {
                cx.emit(Node::new("Reserved").span(data.tail(4)));
            }
        }
        b"vprp" => {
            let block = cx.block(data.sub(0, 0x1000)).await?;
            vprp(&mut Fields::emitting(cx, &block, e))?;
        }
        b"idx1" => idx1(cx, chunk).await?,
        b"JUNK" => return reserved(cx, chunk).await,
        b"indx" | [b'i', b'x', _, _] => index(cx, chunk).await?,
        id if stream_chunk(id).is_some() => {
            let head = cx.read_avail(data.sub(0, 4)).await?;
            if head.starts_with(&[0xff, 0xd8, 0xff]) {
                cx.emit(embedded("JPEG frame", chunk.input().nested(data)));
            } else if head.starts_with(&[0, 0, 1]) || head == [0, 0, 0, 1] {
                // MPEG-1/2/4 or H.264/HEVC elementary stream data.
                cx.emit(
                    embedded("Frame", chunk.input().nested(data))
                        .summary(format!("{} bytes", data.len)),
                );
            } else {
                cx.emit(
                    Node::new("Data")
                        .span(data)
                        .summary(format!("{} bytes", data.len)),
                );
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// VideoPropHeader and its field descriptions.
fn vprp(f: &mut Fields<'_>) -> Result<()> {
    f.u32("Video format").enumeration(VIDEO_FORMATS).emit()?;
    f.u32("Video standard")
        .enumeration(VIDEO_STANDARDS)
        .emit()?;
    f.u32("Vertical refresh rate").desc("Hz").emit()?;
    f.u32("Horizontal total").desc("In pixels").emit()?;
    f.u32("Vertical total").desc("In lines").emit()?;
    f.u32("Frame aspect ratio")
        .hex()
        .with(|&v, n| n.summary(format!("{}:{}", v >> 16, v & 0xffff)))
        .emit()?;
    f.u32("Frame width").emit()?;
    f.u32("Frame height").emit()?;
    let fields = f.u32("Fields per frame").emit()?;
    for _ in 0..fields.min(2) {
        if f.remaining() < 32 {
            break;
        }
        f.u32("Compressed bitmap height").emit()?;
        f.u32("Compressed bitmap width").emit()?;
        f.u32("Valid bitmap height").emit()?;
        f.u32("Valid bitmap width").emit()?;
        f.u32("Valid bitmap X offset").emit()?;
        f.u32("Valid bitmap Y offset").emit()?;
        f.u32("Video X offset").emit()?;
        f.u32("Video Y valid start line").emit()?;
    }
    Ok(())
}

/// Entries are read and pushed in pages of this many.
const PAGE: u64 = 256;

/// The legacy index: one entry per chunk of the first `movi` list.
async fn idx1(cx: &Cx, chunk: &Chunk) -> Result<()> {
    let data = chunk.data;
    let count = data.len / 16;
    cx.set_count(Count::Exact(count));
    let file = chunk.input().span;
    // Offsets count from the movi list's type, or (in some old files) from
    // the start of the file. Check which one the first entry fits.
    let top = scan(cx, &chunk.ctx, chunk.parent, 64).await?;
    let movi = list(cx, &top, b"movi")
        .await?
        .map(|s| s.offset.saturating_sub(4));
    let first = cx.read_avail(data.sub(0, 16)).await?;
    let base = match (movi, u32_le(&first, 8)) {
        (Some(m), Some(off)) => {
            let rel = m.saturating_add(off.into());
            let at = cx
                .read_avail(Span::new(file.source, rel, 4))
                .await
                .unwrap_or_default();
            if first.get(..4) == Some(at.as_slice()) {
                m
            } else {
                file.offset
            }
        }
        _ => file.offset,
    };
    let mut index = 0u64;
    while index < count {
        let n = count.saturating_sub(index).min(PAGE);
        let page = data.sub(index.saturating_mul(16), n.saturating_mul(16));
        let d = cx.read_avail(page).await?;
        for j in 0..n {
            let at = vidutil::us(j.saturating_mul(16));
            let Some(e) = d.get(at..at.saturating_add(16)) else {
                break;
            };
            let id = crate::bytes::array::<4>(e, 0).unwrap_or_default();
            let flags = u32_le(e, 4).unwrap_or(0);
            let offset = u32_le(e, 8).unwrap_or(0);
            let size = u32_le(e, 12).unwrap_or(0);
            let span = page.sub(j.saturating_mul(16), 16);
            let target = Span::new(
                file.source,
                base.saturating_add(offset.into()),
                u64::from(size).saturating_add(8),
            );
            let key = if flags & 0x10 != 0 { ", keyframe" } else { "" };
            let what = stream_chunk(&id).map_or_else(
                || fourcc(&id),
                |(s, _)| format!("{} (stream {s})", fourcc(&id)),
            );
            cx.push(
                IndexEntry::node(
                    format!("Entry {}", index.saturating_add(j)),
                    span,
                    chunk.endian(),
                )
                .target(target)
                .summary(format!(
                    "{what} at {:#x}, {size} bytes{key}",
                    target.offset.saturating_sub(file.offset)
                )),
            )
            .await;
        }
        index = index.saturating_add(n);
    }
    Ok(())
}

/// OpenDML indexes: `indx` (usually a super index of `ix##` chunks) and
/// `ix##` standard indexes.
async fn index(cx: &Cx, chunk: &Chunk) -> Result<()> {
    let data = chunk.data;
    let e = chunk.endian();
    let head = cx.read_avail(data.sub(0, 24)).await?;
    let longs = u16_le(&head, 0).unwrap_or(0);
    let kind = head.get(3).copied().unwrap_or(0);
    let entries = u32_le(&head, 4).unwrap_or(0);
    let block = cx.block(data.sub(0, 24)).await?;
    let mut f = Fields::emitting(cx, &block, e);
    f.u16("Longs per entry")
        .desc("Size of an entry, in 4-byte units")
        .emit()?;
    f.u8("Index subtype").enumeration(INDEX_SUBTYPE).emit()?;
    f.u8("Index type").enumeration(INDEX_TYPE).emit()?;
    f.u32("Entries in use").emit()?;
    f.bytes("Chunk ID", 4)
        .with(|b, n| n.value(text(fourcc(b))).summary("the chunks indexed"))
        .emit()?;
    let base = if kind == 1 {
        let base = f
            .u64("Base offset")
            .hex()
            .desc("Entry offsets count from here")
            .emit()?;
        f.u32("Reserved").emit()?;
        base
    } else {
        f.bytes("Reserved", 12).emit()?;
        0
    };
    let stride = u64::from(longs).saturating_mul(4);
    let table = data.tail(24);
    if stride == 0 {
        if entries > 0 {
            cx.diag(Diagnostic::malformed("index entry size is zero").at(data.sub(0, 2)));
        }
        return Ok(());
    }
    let used = u64::from(entries).saturating_mul(stride);
    let span = table.sub(0, used);
    let mut node = Node::new("Entries")
        .span(span)
        .summary(entry_count(entries.into()))
        .lazy(
            index_entries,
            IndexTable {
                input: chunk.input(),
                span,
                stride,
                kind,
                base,
            },
        );
    if span.len < used {
        node = node.diag(Diagnostic::truncated(
            Span::new(table.source, table.offset, used),
            span.len,
        ));
    }
    cx.emit(node);
    if table.len > used {
        cx.emit(
            Node::new("Unused entries")
                .span(table.tail(used))
                .summary(format!("{} bytes", table.len.saturating_sub(used)))
                .desc("Space reserved for more entries"),
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct IndexTable {
    input: crate::formats::Input,
    span: Span,
    stride: u64,
    /// 0 = super index, 1 = standard index.
    kind: u8,
    base: u64,
}

async fn index_entries(cx: Cx, t: IndexTable) -> Result<()> {
    let count = t.span.len.checked_div(t.stride).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    let file = t.input.span;
    let mut index = 0u64;
    while index < count {
        let n = count.saturating_sub(index).min(PAGE);
        let page = t
            .span
            .sub(index.saturating_mul(t.stride), n.saturating_mul(t.stride));
        let d = cx.read_avail(page).await?;
        for j in 0..n {
            let at = vidutil::us(j.saturating_mul(t.stride));
            let span = page.sub(j.saturating_mul(t.stride), t.stride);
            let e = d.get(at..).unwrap_or_default();
            let name = format!("Entry {}", index.saturating_add(j));
            let node = if t.kind == 0 {
                let offset = u64_le(e, 0).unwrap_or(0);
                let size = u32_le(e, 8).unwrap_or(0);
                let duration = u32_le(e, 12).unwrap_or(0);
                Node::new(name)
                    .span(span)
                    .target(file.sub(offset, size.into()))
                    .summary(format!(
                        "index chunk at {offset:#x}, {size} bytes, duration {duration}"
                    ))
                    .lazy(super_entry, span)
            } else {
                let offset = u32_le(e, 0).unwrap_or(0);
                let raw = u32_le(e, 4).unwrap_or(0);
                let size = raw & 0x7fff_ffff;
                let key = if raw & 0x8000_0000 == 0 {
                    ", keyframe"
                } else {
                    ""
                };
                let at = t.base.saturating_add(offset.into());
                Node::new(name)
                    .span(span)
                    .target(file.sub(at, size.into()))
                    .summary(format!("data at {at:#x}, {size} bytes{key}"))
                    .lazy(std_entry, (span, t.stride))
            };
            cx.push(node).await;
        }
        index = index.saturating_add(n);
    }
    Ok(())
}

async fn super_entry(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, Endian::Little);
    f.u64("Offset")
        .hex()
        .desc("Of the ix## chunk, from the start of the file")
        .emit()?;
    f.u32("Size")
        .desc("Of the ix## chunk, header included")
        .emit()?;
    f.u32("Duration")
        .desc("Frames or samples it indexes")
        .emit()?;
    Ok(())
}

async fn std_entry(cx: Cx, (span, stride): (Span, u64)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, Endian::Little);
    f.u32("Offset")
        .hex()
        .desc("Of the chunk's data, relative to the base offset")
        .emit()?;
    f.u32("Size")
        .with(|&v, n| {
            n.summary(format!(
                "{} bytes{}",
                v & 0x7fff_ffff,
                if v & 0x8000_0000 != 0 {
                    ", not a keyframe"
                } else {
                    ", keyframe"
                }
            ))
        })
        .desc("Bit 31 set: not a keyframe")
        .emit()?;
    if stride >= 12 {
        f.u32("Second field offset").hex().emit()?;
    }
    Ok(())
}

/// Finds `LIST <kind>` among `entries`.
async fn list(cx: &Cx, entries: &[Entry], kind: &FourCc) -> Result<Option<Span>> {
    for e in entries.iter().filter(|e| &e.id == b"LIST") {
        let t = cx.read_avail(e.data.sub(0, 4)).await?;
        if t == kind {
            return Ok(Some(e.data.tail(4)));
        }
    }
    Ok(None)
}

/// "AVI, 00:01:23.000, MPEG-4 Visual 640×480 25 fps + MP3 stereo 44100 Hz".
pub async fn describe(cx: &Cx, ctx: &Ctx, region: Span) -> Result<Option<String>> {
    let top = scan(cx, ctx, region, 64).await?;
    let Some(hdrl) = list(cx, &top, b"hdrl").await? else {
        return Ok(None);
    };
    let entries = scan(cx, ctx, hdrl, 64).await?;
    let Some(avih) = entries.iter().find(|e| &e.id == b"avih") else {
        return Ok(None);
    };
    let main = parse(cx, avih.data, ctx.endian, &(), MainHeader::layout).await?;
    let mut streams = Vec::new();
    let mut seconds = None;
    for e in entries.iter().filter(|e| &e.id == b"LIST") {
        let t = cx.read_avail(e.data.sub(0, 4)).await?;
        if t != b"strl" {
            continue;
        }
        let inner = scan(cx, ctx, e.data.tail(4), 16).await?;
        let Some(strh) = inner.iter().find(|c| &c.id == b"strh") else {
            continue;
        };
        let h = parse(cx, strh.data, ctx.endian, &(), StreamHeader::layout).await?;
        let strf = inner.iter().find(|c| &c.id == b"strf");
        let format = match strf {
            Some(f) => cx.read_avail(f.data.sub(0, 40)).await?,
            None => Vec::new(),
        };
        let line = match h.kind.as_slice() {
            b"vids" => {
                if seconds.is_none() {
                    seconds = h.seconds();
                }
                let codec = video_codec(&format).unwrap_or_else(|| fourcc(&h.handler));
                format!("{codec} {} fps", vidutil::num(h.rate()))
            }
            b"auds" => {
                let tag = u16_le(&format, 0).unwrap_or(0);
                let tag = if tag == 0xfffe {
                    u16_le(&format, 24).unwrap_or(tag)
                } else {
                    tag
                };
                let channels = u16_le(&format, 2).unwrap_or(0);
                let rate = u32_le(&format, 4).unwrap_or(0);
                format!(
                    "{} {} {rate} Hz",
                    vidutil::lookup_or(wav::FORMAT_TAG, tag.into()),
                    match channels {
                        1 => "mono".to_owned(),
                        2 => "stereo".to_owned(),
                        n => format!("{n} ch"),
                    }
                )
            }
            kind => format!("{} stream", stream_type(kind)),
        };
        streams.push(line);
    }
    let odml = list(cx, &entries, b"odml").await?.is_some();
    let seconds = seconds
        .unwrap_or_else(|| f64::from(main.total_frames) * f64::from(main.usec_per_frame) / 1e6);
    let mut parts = vec![
        if odml { "AVI (OpenDML)" } else { "AVI" }.to_owned(),
        vidutil::seconds_f64(seconds),
    ];
    if !streams.is_empty() {
        parts.push(streams.join(" + "));
    }
    if let Some(info) = list(cx, &top, b"INFO").await?
        && let Some(inam) = scan(cx, ctx, info, 32)
            .await?
            .into_iter()
            .find(|e| &e.id == b"INAM")
    {
        let t = peek_text(cx, inam.data, 120).await?;
        if !t.is_empty() {
            parts.push(format!("\"{t}\""));
        }
    }
    Ok(Some(parts.join(", ")))
}
