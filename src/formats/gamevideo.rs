//! Simple game and multimedia video containers: id RoQ, Sega FILM (CPK),
//! Loki SMJPEG and Autodesk FLIC. Each is a header plus a chunk list,
//! listed in pages.

use crate::bytes::{u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::vidutil::{self, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

// ---------------------------------------------------------------------------
// id RoQ

pub static ROQ: Format = Format {
    name: "roq",
    title: "id RoQ video",
    extensions: &["roq"],
    mime: "video/x-roq",
    probe: Probe::Magic(&[(0, b"\x84\x10\xff\xff\xff\xff")]),
    dissect: crate::expander!(dissect_roq: Input),
};

const ROQ_CHUNKS: EnumTable = &[
    (0x1084, "Signature"),
    (0x1001, "Info"),
    (0x1002, "Quad codebook"),
    (0x1011, "Quad VQ"),
    (0x1012, "JPEG"),
    (0x1013, "Quad hang"),
    (0x1020, "Sound (mono)"),
    (0x1021, "Sound (stereo)"),
    (0x1030, "Packet"),
];

pub async fn dissect_roq(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 24)).await?;
    let fps = u16_le(&head, 6).unwrap_or(0);
    let mut summary = format!("RoQ, {fps} fps");
    if u16_le(&head, 8) == Some(0x1001) {
        summary = format!(
            "RoQ, {}×{}, {fps} fps",
            u16_le(&head, 16).unwrap_or(0),
            u16_le(&head, 18).unwrap_or(0)
        );
    }
    cx.annotate(summary);
    let mut pos = 0u64;
    let mut frame = 0u32;
    while pos < file.len {
        let d = cx.read_avail(file.sub(pos, 16)).await?;
        let (Some(id), Some(size), Some(arg)) = (u16_le(&d, 0), u32_le(&d, 2), u16_le(&d, 6)) else {
            cx.emit(Node::new("Trailing bytes").span(file.tail(pos)));
            break;
        };
        // Some encoders pad odd-sized chunks with one byte.
        if id >> 8 != 0x10 && u16_le(&d, 1).is_some_and(|next| next >> 8 == 0x10) {
            cx.push(Node::new("Padding").span(file.sub(pos, 1))).await;
            pos = pos.saturating_add(1);
            continue;
        }
        let len = if id == 0x1084 { 0 } else { u64::from(size) };
        let total = len.saturating_add(8);
        let span = file.sub(pos, total);
        let mut summary = match id {
            0x1084 => format!("{arg} fps"),
            0x1001 => format!(
                "{}×{}",
                u16_le(&d, 8).unwrap_or(0),
                u16_le(&d, 10).unwrap_or(0)
            ),
            0x1002 => format!("{len} bytes, {} 4×4 cells", match arg & 0xff {
                0 => 256,
                n => n,
            }),
            0x1011 | 0x1012 => {
                frame = frame.saturating_add(1);
                format!("frame {}, {len} bytes", frame.saturating_sub(1))
            }
            _ => format!("{len} bytes"),
        };
        if id == 0x1020 || id == 0x1021 {
            summary = format!("{len} bytes, initial sample {:#06x}", arg);
        }
        let name = vidutil::lookup_or(ROQ_CHUNKS, id.into());
        let mut node = Node::new(name).span(span).summary(summary).lazy(roq_chunk, span);
        if span.len < total {
            node = node.diag(Diagnostic::truncated(Span::new(file.source, span.offset, total), span.len));
        }
        cx.push(node).await;
        pos = pos.saturating_add(total);
    }
    Ok(())
}

async fn roq_chunk(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, Endian::Little);
    let id = f.u16("Chunk ID").enumeration(ROQ_CHUNKS).emit()?;
    f.u32("Size").emit()?;
    f.u16("Argument").hex().emit()?;
    if id == 0x1001 {
        f.u16("Width").emit()?;
        f.u16("Height").emit()?;
        f.u16("Block dimension").emit()?;
        f.u16("Sub-block dimension").emit()?;
    } else if id != 0x1084 && span.len > 8 {
        cx.emit(Node::new("Data").span(span.tail(8)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sega FILM

pub static FILM: Format = Format {
    name: "film",
    title: "Sega FILM",
    extensions: &["cpk", "cak", "film"],
    mime: "video/x-sega-film",
    probe: Probe::Custom(|h| h.starts_with(b"FILM") && h.at(16, b"FDSC")),
    dissect: crate::expander!(dissect_film: Input),
};

record! {
    pub struct FilmHeader {
        signature: ascii[4] "Signature",
        header_len: u32 "Header length",
        version: ascii[4] "Version",
        reserved: u32 "Reserved",
    }
}

record! {
    pub struct FilmDescription {
        signature: ascii[4] "Signature",
        size: u32 "Chunk size",
        fourcc: ascii[4] "Video codec",
        height: u32 "Height",
        width: u32 "Width",
        bpp: u8 "Bits per pixel",
        channels: u8 "Audio channels",
        bits: u8 "Audio bits",
        compression: u8 "Audio compression",
        rate: u16 "Audio sample rate",
    }
}

record! {
    pub struct FilmSample {
        offset: u32 "Offset" .hex(),
        length: u32 "Length",
        info1: u32 "Info 1" .hex(),
        info2: u32 "Info 2" .hex(),
    }
}

impl vidutil::Entry for FilmSample {
    fn label(index: u64) -> String {
        format!("Sample {index}")
    }
    fn summary(&self) -> Option<String> {
        Some(if self.info1 == 0xffff_ffff {
            format!("audio, {} bytes", self.length)
        } else {
            format!(
                "video at {} ticks, {} bytes{}",
                self.info1 & 0x7fff_ffff,
                self.length,
                if self.info1 & 0x8000_0000 == 0 { ", keyframe" } else { "" }
            )
        })
    }
}

pub async fn dissect_film(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, Endian::Big);
    let (h, hspan) = cur.record::<FilmHeader>().await?;
    cx.emit(FilmHeader::node("Header", hspan, Endian::Big));
    let (d, _) = cur.record::<FilmDescription>().await?;
    cx.emit(FilmDescription::node(
        "Description (FDSC)",
        file.sub(16, u64::from(d.size).max(FilmDescription::SIZE)),
        Endian::Big,
    ));
    cur.seek(16u64.saturating_add(d.size.into()));
    let stab = cur.pos();
    let s = cx.read_avail(file.sub(stab, 16)).await?;
    let clock = u32_be(&s, 8).unwrap_or(0);
    let count = u32_be(&s, 12).unwrap_or(0);
    cx.annotate(format!(
        "Sega FILM {}, {} {}×{}{}, {}",
        h.version,
        d.fourcc,
        d.width,
        d.height,
        if d.channels > 0 {
            format!(" + {}-bit PCM {} Hz {} ch", d.bits, d.rate, d.channels)
        } else {
            String::new()
        },
        vidutil::plural(count, "sample")
    ));
    let stab_span = file.sub(stab, u32_be(&s, 4).map_or(16, u64::from));
    cx.emit(
        Node::new("Sample table (STAB)")
            .span(stab_span)
            .summary(format!("base clock {clock} Hz, {}", vidutil::plural(count, "sample")))
            .lazy(film_table, (stab_span, count)),
    );
    let data = file.tail(h.header_len.into());
    cx.emit(Node::new("Sample data").span(data).summary(format!("{} bytes", data.len)));
    Ok(())
}

async fn film_table(cx: Cx, (span, count): (Span, u32)) -> Result<()> {
    let block = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, Endian::Big);
    f.ascii("Signature", 4).emit()?;
    f.u32("Chunk size").emit()?;
    f.u32("Base clock").emit()?;
    f.u32("Sample count").emit()?;
    cx.emit(vidutil::table::<FilmSample>("Samples", span.tail(16), count.into(), Endian::Big));
    Ok(())
}

// ---------------------------------------------------------------------------
// SMJPEG

pub static SMJPEG: Format = Format {
    name: "smjpeg",
    title: "Loki SMJPEG",
    extensions: &["mjpg", "smjpeg"],
    mime: "video/x-smjpeg",
    probe: Probe::Magic(&[(0, b"\x00\x0aSMJPEG")]),
    dissect: crate::expander!(dissect_smjpeg: Input),
};

pub async fn dissect_smjpeg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 16)).await?;
    let h = file.sub(0, 16);
    cx.emit(vidutil::text("Signature", h.sub(0, 8), "\\0\\nSMJPEG"));
    cx.emit(uint("Version", h.sub(8, 4), u32_be(&head, 8).unwrap_or(0).into(), 32));
    let length = u32_be(&head, 12).unwrap_or(0);
    cx.emit(uint("Length", h.sub(12, 4), length.into(), 32).summary(vidutil::seconds_ms(length.into())));
    let mut parts = vec!["SMJPEG".to_owned()];
    let mut pos = 16u64;
    let mut in_header = true;
    let mut index = 0u32;
    while pos < file.len {
        let d = cx.read_avail(file.sub(pos, 24)).await?;
        let Some(tag) = d.get(..4) else {
            cx.emit(Node::new("Trailing bytes").span(file.tail(pos)));
            break;
        };
        let tag: [u8; 4] = tag.try_into().unwrap_or_default();
        let (name, len, summary) = match &tag {
            b"HEND" | b"DONE" => {
                let name = if &tag == b"HEND" { "Header end" } else { "Done" };
                (name.to_owned(), 0u64, None)
            }
            b"_TXT" => (
                "Text".to_owned(),
                u64::from(u32_be(&d, 4).unwrap_or(0)),
                Some(String::from_utf8_lossy(d.get(8..).unwrap_or_default()).into_owned()),
            ),
            b"_SND" => {
                let s = format!(
                    "{} Hz, {}-bit, {} ch, {}",
                    u16_be(&d, 8).unwrap_or(0),
                    d.get(10).copied().unwrap_or(0),
                    d.get(11).copied().unwrap_or(0),
                    vidutil::fourcc(d.get(12..16).unwrap_or_default())
                );
                parts.push(format!("audio {s}"));
                ("Audio header".to_owned(), u64::from(u32_be(&d, 4).unwrap_or(0)), Some(s))
            }
            b"_VID" => {
                let s = format!(
                    "{} frames, {}×{}, {}",
                    u32_be(&d, 8).unwrap_or(0),
                    u16_be(&d, 12).unwrap_or(0),
                    u16_be(&d, 14).unwrap_or(0),
                    vidutil::fourcc(d.get(16..20).unwrap_or_default())
                );
                parts.push(format!("video {s}"));
                ("Video header".to_owned(), u64::from(u32_be(&d, 4).unwrap_or(0)), Some(s))
            }
            b"sndD" | b"vidD" => {
                let ts = u32_be(&d, 4).unwrap_or(0);
                let len = u64::from(u32_be(&d, 8).unwrap_or(0)).saturating_add(4);
                let kind = if &tag == b"sndD" { "Audio" } else { "Video" };
                (
                    format!("{kind} chunk {index}"),
                    len,
                    Some(format!("{}, {} bytes", vidutil::seconds_ms(ts.into()), len.saturating_sub(4))),
                )
            }
            _ => {
                cx.emit(
                    Node::new("Unknown data")
                        .span(file.tail(pos))
                        .diag(Diagnostic::malformed(format!("unknown chunk {}", vidutil::fourcc(&tag)))),
                );
                break;
            }
        };
        let total = len.saturating_add(if len == 0 { 4 } else { 8 });
        let span = file.sub(pos, total);
        let mut node = Node::new(name).span(span);
        if let Some(s) = summary {
            node = node.summary(s);
        }
        if &tag == b"vidD" {
            node = node.lazy(smjpeg_chunk, (input, span));
        }
        if in_header {
            cx.emit(node);
        } else {
            cx.push(node).await;
            index = index.saturating_add(1);
        }
        if &tag == b"HEND" {
            in_header = false;
            cx.annotate(parts.join(", "));
        }
        pos = pos.saturating_add(total);
        if &tag == b"DONE" {
            break;
        }
    }
    if in_header {
        cx.annotate(parts.join(", "));
    }
    Ok(())
}

async fn smjpeg_chunk(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 12)).await?;
    cx.emit(uint("Timestamp", span.sub(4, 4), u32_be(&d, 4).unwrap_or(0).into(), 32));
    cx.emit(uint("Length", span.sub(8, 4), u32_be(&d, 8).unwrap_or(0).into(), 32));
    cx.emit(crate::formats::embedded("JPEG frame", input.nested(span.tail(12))));
    Ok(())
}

// ---------------------------------------------------------------------------
// Autodesk FLIC

pub static FLIC: Format = Format {
    name: "flic",
    title: "Autodesk FLIC animation",
    extensions: &["fli", "flc", "flx"],
    mime: "video/x-flic",
    probe: Probe::Custom(|h| {
        matches!(u16_le(h.data, 4), Some(0xaf11 | 0xaf12 | 0xaf44 | 0xaf30 | 0xaf31))
            && u32_le(h.data, 0).is_some_and(|s| u64::from(s) <= h.len.saturating_add(16) && s >= 128)
            && u16_le(h.data, 8).is_some_and(|w| w > 0)
            && u16_le(h.data, 10).is_some_and(|w| w > 0)
            && u16_le(h.data, 12).is_some_and(|d| matches!(d, 1 | 8 | 15 | 16 | 24 | 32))
    }),
    dissect: crate::expander!(dissect_flic: Input),
};

record! {
    pub struct FlicHeader {
        size: u32 "File size",
        magic: u16 "Magic" .hex(),
        frames: u16 "Frames",
        width: u16 "Width",
        height: u16 "Height",
        depth: u16 "Depth",
        flags: u16 "Flags" .hex(),
        speed: u32 "Speed" .desc("Milliseconds per frame (jiffies for FLI)"),
        reserved1: u16 "Reserved",
        created: u32 "Created" .timestamp(),
        creator: u32 "Creator" .hex(),
        updated: u32 "Updated" .timestamp(),
        updater: u32 "Updater" .hex(),
        aspect_x: u16 "Aspect X",
        aspect_y: u16 "Aspect Y",
        ext_flags: u16 "EGI flags" .hex(),
        keyframes: u16 "Keyframes",
        total_frames: u16 "Total frames",
        req_memory: u32 "Required memory",
        max_regions: u16 "Max regions",
        transp_num: u16 "Transparency count",
        reserved2: bytes[24] "Reserved",
        oframe1: u32 "Offset of frame 1" .hex(),
        oframe2: u32 "Offset of frame 2" .hex(),
        reserved3: bytes[40] "Reserved",
    }
}

const FLIC_CHUNKS: EnumTable = &[
    (4, "COLOR_256"),
    (7, "DELTA_FLC"),
    (11, "COLOR_64"),
    (12, "DELTA_FLI"),
    (13, "BLACK"),
    (15, "BYTE_RUN"),
    (16, "FLI_COPY"),
    (18, "PSTAMP"),
    (25, "DTA_BRUN"),
    (26, "DTA_COPY"),
    (27, "DTA_LC"),
    (31, "LABEL"),
    (32, "BMP_MASK"),
    (33, "MLEV_MASK"),
    (34, "SEGMENT"),
    (35, "KEY_IMAGE"),
    (36, "KEY_PAL"),
    (37, "REGION"),
    (38, "WAVE"),
    (39, "USERSTRING"),
    (40, "RGN_MASK"),
    (41, "LABELEX"),
    (42, "SHIFT"),
    (43, "PATHMAP"),
    (0xf100, "PREFIX"),
    (0xf1e0, "SCRIPT"),
    (0xf1fa, "FRAME"),
    (0xf1fb, "SEGMENT_TABLE"),
    (0xf1fc, "HUFFMAN_TABLE"),
];

pub async fn dissect_flic(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (h, span) = Cursor::new(&cx, file, Endian::Little).record::<FlicHeader>().await?;
    cx.emit(FlicHeader::node("Header", span, Endian::Little));
    let fli = h.magic == 0xaf11;
    let ms = if fli { u64::from(h.speed).saturating_mul(1000) / 70 } else { h.speed.into() };
    cx.annotate(format!(
        "FLIC ({}), {}×{}, {}-bit, {}, {} ms/frame",
        if fli { "FLI" } else { "FLC" },
        h.width,
        h.height,
        h.depth,
        vidutil::plural(h.frames, "frame"),
        ms
    ));
    flic_chunks(&cx, file.tail(FlicHeader::SIZE), 0).await
}

async fn flic_chunks(cx: &Cx, region: Span, depth: u32) -> Result<()> {
    let mut pos = 0u64;
    let mut frame = 0u32;
    while pos.saturating_add(6) <= region.len {
        let d = cx.read_avail(region.sub(pos, 16)).await?;
        let size = u64::from(u32_le(&d, 0).unwrap_or(0));
        let kind = u16_le(&d, 4).unwrap_or(0);
        if size < 6 {
            cx.emit(Node::new("Invalid chunk").span(region.tail(pos)).diag(Diagnostic::malformed("chunk smaller than its header")));
            break;
        }
        let span = region.sub(pos, size);
        let name = vidutil::lookup_or(FLIC_CHUNKS, kind.into());
        let mut node = Node::new(name).span(span);
        if kind == 0xf1fa {
            let sub = u16_le(&d, 6).unwrap_or(0);
            node = node.summary(format!("frame {frame}, {}", vidutil::plural(sub, "chunk")));
            frame = frame.saturating_add(1);
            if depth == 0 {
                node = node.lazy(crate::expander!(self::flic_frame: Span), span);
            }
        } else {
            node = node.summary(format!("{size} bytes"));
        }
        if span.len < size {
            node = node.diag(Diagnostic::truncated(Span::new(span.source, span.offset, size), span.len));
        }
        cx.push(node).await;
        pos = pos.saturating_add(size);
    }
    Ok(())
}

async fn flic_frame(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, Endian::Little);
    f.u32("Size").emit()?;
    f.u16("Type").enumeration(FLIC_CHUNKS).emit()?;
    f.u16("Chunks").emit()?;
    f.u16("Delay").emit()?;
    f.u16("Reserved").emit()?;
    f.u16("Width override").emit()?;
    f.u16("Height override").emit()?;
    flic_chunks(&cx, span.tail(16), 1).await
}
