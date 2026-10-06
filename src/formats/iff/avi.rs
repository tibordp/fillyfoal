//! AVI chunks: `avih`, `strh`, `strf` (BITMAPINFOHEADER or WAVEFORMATEX by
//! stream type), `strn`, OpenDML `indx`/`ix##`/`dmlh`, `idx1`, and the
//! stream data chunks of `movi`.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Fields, parse};
use crate::formats::embedded;
use crate::formats::iff::{Chunk, Ctx, Entry, FourCc, find, scan, wav};
use crate::formats::util::sound::{duration, fourcc, peek_text, table, text};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

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

const COMPRESSION: EnumTable = &[
    (0, "BI_RGB"),
    (1, "BI_RLE8"),
    (2, "BI_RLE4"),
    (3, "BI_BITFIELDS"),
    (4, "BI_JPEG"),
    (5, "BI_PNG"),
];

record! {
    /// MainAVIHeader
    pub struct MainHeader {
        usec_per_frame: u32 "Microseconds per frame",
        max_bytes_per_sec: u32 "Max bytes per second",
        padding: u32 "Padding granularity",
        flags: u32 "Flags" .flags(AVIF),
        total_frames: u32 "Total frames",
        initial_frames: u32 "Initial frames",
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

record! {
    /// AVISTREAMHEADER
    pub struct StreamHeader {
        kind: bytes[4] "Type" .with(|b, n| n.value(text(fourcc(b))).summary(stream_type(b))),
        handler: bytes[4] "Handler" .with(|b, n| n.value(text(fourcc(b)))),
        flags: u32 "Flags" .flags(STREAM_FLAGS),
        priority: u16 "Priority",
        language: u16 "Language",
        initial_frames: u32 "Initial frames",
        scale: u32 "Scale",
        rate: u32 "Rate" .with(|&r, n| if scale > 0 { n.summary(format!("{:.3} per second", f64::from(r) / f64::from(scale))) } else { n }),
        start: u32 "Start",
        length: u32 "Length" .desc("In units of rate/scale"),
        buffer: u32 "Suggested buffer size",
        quality: u32 "Quality",
        sample_size: u32 "Sample size",
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
}

record! {
    /// BITMAPINFOHEADER
    pub struct BitmapInfo {
        size: u32 "Header size",
        width: i32 "Width",
        height: i32 "Height" .desc("Negative for top-down bitmaps"),
        planes: u16 "Planes",
        bit_count: u16 "Bits per pixel",
        compression: u32 "Compression" .with(|&c, n| match crate::value::lookup(COMPRESSION, c.into()) {
            Some(name) => n.summary(name),
            None => n.summary(fourcc(&c.to_le_bytes())),
        }),
        image_size: u32 "Image size",
        x_ppm: i32 "Horizontal resolution (px/m)",
        y_ppm: i32 "Vertical resolution (px/m)",
        colors_used: u32 "Colors used",
        colors_important: u32 "Important colors",
    }
}

impl BitmapInfo {
    fn codec(&self) -> String {
        match crate::value::lookup(COMPRESSION, self.compression.into()) {
            Some("BI_RGB") => "RGB".to_owned(),
            Some(name) => name.to_owned(),
            None => fourcc(&self.compression.to_le_bytes()),
        }
    }
}

record! {
    pub struct IndexEntry {
        id: bytes[4] "Chunk ID" .with(|b, n| n.value(text(fourcc(b)))),
        flags: u32 "Flags" .flags(INDEX_FLAGS),
        offset: u32 "Offset" .hex() .desc("Relative to the movi list (or the file, in old files)"),
        size: u32 "Size",
    }
}

record! {
    /// OpenDML index header (`indx` and `ix##`).
    pub struct IndexHeader {
        longs_per_entry: u16 "Longs per entry",
        sub_type: u8 "Index subtype",
        kind: u8 "Index type" .enumeration(INDEX_TYPE),
        entries: u32 "Entries in use",
        chunk_id: bytes[4] "Chunk ID" .with(|b, n| n.value(text(fourcc(b)))),
    }
}

const INDEX_TYPE: EnumTable = &[(0, "super index"), (1, "standard index"), (0x80, "data")];

record! {
    pub struct SuperIndexEntry {
        offset: u64 "Offset" .hex(),
        size: u32 "Size",
        duration: u32 "Duration",
    }
}

record! {
    pub struct StdIndexEntry {
        offset: u32 "Offset" .hex() .desc("Relative to the base offset"),
        size: u32 "Size" .desc("Bit 31 set: not a key frame"),
    }
}

pub fn describe_id(id: &FourCc) -> Option<&'static str> {
    Some(match id {
        b"avih" => "Main AVI header",
        b"strh" => "Stream header",
        b"strf" => "Stream format",
        b"strn" => "Stream name",
        b"strd" => "Stream codec data",
        b"indx" => "OpenDML super index",
        b"idx1" => "Legacy index",
        b"dmlh" => "OpenDML extended header",
        b"vprp" => "Video properties",
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
    let [a, b, c, d] = *id;
    if !a.is_ascii_digit() || !b.is_ascii_digit() {
        return None;
    }
    let n = u32::from(a.saturating_sub(b'0'))
        .saturating_mul(10)
        .saturating_add(u32::from(b.saturating_sub(b'0')));
    let kind = std::str::from_utf8(id.get(2..4)?).ok()?;
    let _ = (c, d);
    Some((n, kind))
}

/// The `strh` of the stream list a chunk belongs to.
async fn stream_header(cx: &Cx, chunk: &Chunk) -> Option<StreamHeader> {
    let strh = find(cx, &chunk.ctx, chunk.parent, b"strh").await.ok()??;
    parse(cx, strh.data, chunk.endian(), &(), StreamHeader::layout)
        .await
        .ok()
}

pub async fn summary(cx: &Cx, chunk: &Chunk) -> Result<Option<String>> {
    let e = chunk.endian();
    Ok(match &chunk.id {
        b"avih" => {
            let h = parse(cx, chunk.data, e, &(), MainHeader::layout).await?;
            Some(format!(
                "{}×{}, {:.2} fps, {} frames, {} streams",
                h.width,
                h.height,
                h.fps(),
                h.total_frames,
                h.streams
            ))
        }
        b"strh" => {
            let h = parse(cx, chunk.data, e, &(), StreamHeader::layout).await?;
            Some(format!(
                "{} {}, {:.3}/s, length {}",
                stream_type(&h.kind),
                fourcc(&h.handler),
                h.rate(),
                h.length
            ))
        }
        b"strf" => match stream_header(cx, chunk).await {
            Some(h) if &h.kind == b"vids" => {
                let b = parse(cx, chunk.data, e, &(), BitmapInfo::layout).await?;
                Some(format!(
                    "{} {}×{}, {}-bit",
                    b.codec(),
                    b.width,
                    b.height.unsigned_abs(),
                    b.bit_count
                ))
            }
            Some(h) if &h.kind == b"auds" => Some(
                parse(cx, chunk.data, e, &(), wav::wave_format)
                    .await?
                    .summary(),
            ),
            _ => None,
        },
        b"strn" => Some(peek_text(cx, chunk.data, 120).await?),
        b"idx1" => Some(format!("{} entries", chunk.size / IndexEntry::SIZE)),
        id => stream_chunk(id).map(|(n, kind)| {
            let what = match kind {
                "dc" | "db" => "video",
                "wb" => "audio",
                "tx" => "text",
                "pc" => "palette",
                _ => "data",
            };
            format!("stream {n} {what}, {} bytes", chunk.size)
        }),
    })
}

pub async fn chunk(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let e = chunk.endian();
    let data = chunk.data;
    match &chunk.id {
        b"avih" => cx.emit(MainHeader::node("Main header", data, e)),
        b"strh" => cx.emit(StreamHeader::node("Stream header", data, e)),
        b"strf" => match stream_header(cx, chunk).await {
            Some(h) if &h.kind == b"vids" => {
                cx.emit(BitmapInfo::node(
                    "Bitmap info",
                    data.sub(0, BitmapInfo::SIZE),
                    e,
                ));
                let extra = data.tail(BitmapInfo::SIZE);
                if !extra.is_empty() {
                    cx.emit(Node::new("Codec data").span(extra));
                }
            }
            Some(h) if &h.kind == b"auds" => {
                let block = cx.block(data).await?;
                wav::wave_format(&mut Fields::emitting(cx, &block, e), &())?;
            }
            _ => cx.emit(Node::new("Format data").span(data)),
        },
        b"strn" => {
            let t = peek_text(cx, data, data.len).await?;
            cx.emit(Node::new("Name").span(data).value(text(t)));
        }
        b"dmlh" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(cx, &block, e).u32("Total frames").emit()?;
        }
        b"idx1" => {
            cx.set_count(crate::node::Count::Exact(data.len / IndexEntry::SIZE));
            let mut cur = crate::dsl::Cursor::new(cx, data, e);
            let mut i = 0u64;
            while cur.remaining() >= IndexEntry::SIZE {
                let (entry, span) = cur.record::<IndexEntry>().await?;
                let key = if entry.flags & 0x10 != 0 { ", key" } else { "" };
                cx.push(
                    IndexEntry::node(format!("Entry {i}"), span, e).summary(format!(
                        "{} at {:#x}, {} bytes{key}",
                        fourcc(&entry.id),
                        entry.offset,
                        entry.size
                    )),
                )
                .await;
                i = i.saturating_add(1);
            }
        }
        b"indx" => {
            let header = data.sub(0, IndexHeader::SIZE);
            cx.emit(IndexHeader::node("Index header", header, e));
            let entries = data.tail(24);
            cx.emit(table::<SuperIndexEntry>(
                "Entries",
                entries,
                e,
                "Index",
                Some(|s| format!("{:#x}, {} bytes, duration {}", s.offset, s.size, s.duration)),
            ));
        }
        [b'i', b'x', _, _] => {
            let header = data.sub(0, IndexHeader::SIZE);
            cx.emit(IndexHeader::node("Index header", header, e));
            let base = cx.read_avail(data.sub(12, 8)).await?;
            let base = crate::bytes::u64_le(&base, 0).unwrap_or(0);
            cx.emit(
                Node::new("Base offset")
                    .span(data.sub(12, 8))
                    .value(crate::formats::util::sound::hex(base, 64)),
            );
            cx.emit(table::<StdIndexEntry>(
                "Entries",
                data.tail(24),
                e,
                "Index",
                Some(|s| {
                    let key = if s.size & 0x8000_0000 == 0 {
                        ", key"
                    } else {
                        ""
                    };
                    format!("{:#x}, {} bytes{key}", s.offset, s.size & 0x7fff_ffff)
                }),
            ));
        }
        id if stream_chunk(id).is_some() => {
            let head = cx.read_avail(data.sub(0, 3)).await?;
            if head == [0xff, 0xd8, 0xff] {
                cx.emit(embedded("JPEG frame", chunk.input().nested(data)));
            } else {
                cx.emit(Node::new("Data").span(data));
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
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
        let codec = match (h.kind.as_slice(), strf) {
            (b"vids", Some(f)) => {
                let raw = cx.read_avail(f.data.sub(16, 4)).await?;
                let c = u32_le(&raw, 0).unwrap_or(0);
                match crate::value::lookup(COMPRESSION, c.into()) {
                    Some("BI_RGB") => "RGB".to_owned(),
                    Some(n) => n.to_owned(),
                    None => fourcc(&c.to_le_bytes()),
                }
            }
            (b"auds", Some(f)) => {
                let raw = cx.read_avail(f.data.sub(0, 2)).await?;
                let tag = u16_le(&raw, 0).unwrap_or(0);
                crate::value::lookup(wav::FORMAT_TAG, tag.into())
                    .map_or_else(|| format!("format {tag:#x}"), str::to_owned)
            }
            _ => fourcc(&h.handler),
        };
        streams.push(format!("{codec} {}", stream_type(&h.kind)));
    }
    let seconds = f64::from(main.total_frames) * f64::from(main.usec_per_frame) / 1e6;
    let mut line = format!(
        "AVI, {}×{}, {:.2} fps, {} streams",
        main.width,
        main.height,
        main.fps(),
        main.streams
    );
    if !streams.is_empty() {
        line.push_str(&format!(" ({})", streams.join(", ")));
    }
    line.push_str(&format!(", {}", duration(seconds)));
    Ok(Some(line))
}
