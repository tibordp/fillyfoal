//! RealMedia (`.rm`, `.rmvb`): big-endian chunks `id, size, version`.
//! The `.RMF` file header is followed by properties (`PROP`), media stream
//! headers (`MDPR`), content description (`CONT`), the data chunk (`DATA`,
//! packets listed in pages) and indexes (`INDX`).

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::vidutil::{self, fixed16, num};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{FlagTable, flag};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "rm",
    title: "RealMedia",
    extensions: &["rm", "rmvb", "rv"],
    mime: "application/vnd.rn-realmedia",
    probe: Probe::Custom(|h| {
        h.starts_with(b".RMF") && u32_be(h.data, 4).is_some_and(|s| (10..=0x100).contains(&s))
    }),
    dissect: crate::expander!(dissect: Input),
};

const PROP_FLAGS: FlagTable = &[
    flag(0x1, "SAVE_ENABLED"),
    flag(0x2, "PERFECT_PLAY"),
    flag(0x4, "LIVE_BROADCAST"),
    flag(0x8, "DOWNLOAD_ENABLED"),
];

#[derive(Clone, Copy, Debug)]
struct Chunk {
    span: Span,
    id: [u8; 4],
}

fn chunk_name(id: &[u8; 4]) -> &'static str {
    match id {
        b".RMF" => "File header",
        b"PROP" => "Properties",
        b"MDPR" => "Media properties",
        b"CONT" => "Content description",
        b"DATA" => "Data",
        b"INDX" => "Index",
        b"RMMD" => "Metadata",
        b"RMJE" => "Metadata end",
        _ => "Chunk",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut info = Info::default();
    while pos < file.len {
        let d = cx.read_avail(file.sub(pos, 10)).await?;
        let (Some(id), Some(size)) = (crate::bytes::array::<4>(&d, 0), u32_be(&d, 4)) else {
            cx.emit(Node::new("Trailing bytes").span(file.tail(pos)));
            break;
        };
        // Some writers leave the DATA size at 0: it then runs to the index
        // or the end of the file.
        let size = if size == 0 && &id == b"DATA" {
            file.len.saturating_sub(pos)
        } else {
            u64::from(size)
        };
        if size < 8 {
            cx.emit(
                Node::new("Invalid chunk")
                    .span(file.tail(pos))
                    .diag(Diagnostic::malformed(format!(
                        "chunk size {size} is too small"
                    ))),
            );
            break;
        }
        let chunk = Chunk {
            span: file.sub(pos, size),
            id,
        };
        let body = cx.read_avail(chunk.span.sub(0, 0x400)).await?;
        info.observe(&id, &body);
        let mut node = Node::new(chunk_name(&id))
            .span(chunk.span)
            .value(crate::value::Value::Text(vidutil::fourcc(&id)))
            .lazy(expand_chunk, chunk);
        if let Some(s) = chunk_summary(&id, &body) {
            node = node.summary(s);
        }
        if chunk.span.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(file.source, chunk.span.offset, size),
                chunk.span.len,
            ));
        }
        cx.progress_in(file, file.offset.saturating_add(pos));
        cx.push(node).await;
        pos = pos.saturating_add(size);
    }
    cx.annotate(info.describe());
    Ok(())
}

fn chunk_summary(id: &[u8; 4], d: &[u8]) -> Option<String> {
    match id {
        b"PROP" => Some(format!(
            "{} streams, {}",
            u16_be(d, 46)?,
            vidutil::seconds_ms(u32_be(d, 30)?.into())
        )),
        b"MDPR" => {
            let (name, mime) = stream_names(d)?;
            Some(format!("stream {}: {mime} \"{name}\"", u16_be(d, 10)?))
        }
        b"DATA" => Some(format!("{} packets", u32_be(d, 10)?)),
        b"INDX" => Some(format!(
            "{} entries for stream {}",
            u32_be(d, 10)?,
            u16_be(d, 14)?
        )),
        b"CONT" => {
            let len = usize::from(u16_be(d, 10)?);
            let title = d.get(12..12usize.saturating_add(len))?;
            (!title.is_empty()).then(|| format!("\"{}\"", String::from_utf8_lossy(title)))
        }
        _ => None,
    }
}

/// Stream name and MIME type of an MDPR chunk.
fn stream_names(d: &[u8]) -> Option<(String, String)> {
    let name_len = usize::from(*d.get(40)?);
    let name = d.get(41..41usize.saturating_add(name_len))?;
    let at = 41usize.saturating_add(name_len);
    let mime_len = usize::from(*d.get(at)?);
    let mime = d.get(at.saturating_add(1)..at.saturating_add(1).saturating_add(mime_len))?;
    Some((
        String::from_utf8_lossy(name).into_owned(),
        String::from_utf8_lossy(mime).into_owned(),
    ))
}

/// Type-specific data of an MDPR chunk.
fn type_specific(d: &[u8]) -> Option<&[u8]> {
    let name_len = usize::from(*d.get(40)?);
    let at = 41usize.saturating_add(name_len);
    let mime_len = usize::from(*d.get(at)?);
    let at = at.saturating_add(1).saturating_add(mime_len);
    let len = usize::try_from(u32_be(d, at)?).ok()?;
    d.get(at.saturating_add(4)..at.saturating_add(4).saturating_add(len))
}

#[derive(Default)]
struct Info {
    duration: Option<u32>,
    streams: Vec<String>,
    title: Option<String>,
}

impl Info {
    fn observe(&mut self, id: &[u8; 4], d: &[u8]) {
        match id {
            b"PROP" => self.duration = u32_be(d, 30),
            b"MDPR" => {
                if let Some(ts) = type_specific(d) {
                    if ts.get(4..8) == Some(b"VIDO") {
                        let fourcc = vidutil::fourcc(ts.get(8..12).unwrap_or_default());
                        let w = u16_be(ts, 12).unwrap_or(0);
                        let h = u16_be(ts, 14).unwrap_or(0);
                        self.streams.push(format!("{w}×{h} {fourcc}"));
                        return;
                    }
                    if ts.starts_with(b".ra\xfd") {
                        self.streams.push(format!(
                            "RealAudio{}",
                            audio_codec(ts)
                                .map(|c| format!(" ({c})"))
                                .unwrap_or_default()
                        ));
                        return;
                    }
                }
                if let Some((_, mime)) = stream_names(d)
                    && mime != "logical-fileinfo"
                {
                    self.streams.push(mime);
                }
            }
            b"CONT" => {
                let len = usize::from(u16_be(d, 10).unwrap_or(0));
                let title = d.get(12..12usize.saturating_add(len)).unwrap_or_default();
                if !title.is_empty() {
                    self.title = Some(String::from_utf8_lossy(title).into_owned());
                }
            }
            _ => {}
        }
    }

    fn describe(&self) -> String {
        let mut parts = vec!["RealMedia".to_owned()];
        if !self.streams.is_empty() {
            parts.push(self.streams.join(" + "));
        }
        if let Some(d) = self.duration {
            parts.push(vidutil::seconds_ms(d.into()));
        }
        if let Some(t) = &self.title {
            parts.push(format!("\"{t}\""));
        }
        parts.join(", ")
    }
}

/// The FourCC of a RealAudio stream header (`.ra\xfd` version 3, 4 or 5).
fn audio_codec(ts: &[u8]) -> Option<String> {
    match u16_be(ts, 4)? {
        3 => Some("lpcJ".to_owned()),
        4 => {
            // Version 4: interleaver and codec are Pascal strings after
            // the fixed fields.
            let at = 0x38usize;
            let len = usize::from(*ts.get(at)?);
            let at = at.saturating_add(1).saturating_add(len);
            let len = usize::from(*ts.get(at)?);
            ts.get(at.saturating_add(1)..at.saturating_add(1).saturating_add(len))
                .map(vidutil::fourcc)
        }
        5 => ts.get(0x42..0x46).map(vidutil::fourcc),
        _ => None,
    }
}

async fn expand_chunk(cx: Cx, chunk: Chunk) -> Result<()> {
    let block = cx.block(chunk.span.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.ascii("Object ID", 4).emit()?;
    f.u32("Size").emit()?;
    f.u16("Version").emit()?;
    match &chunk.id {
        b".RMF" => {
            if f.remaining() >= 8 {
                f.u32("File version").emit()?;
                f.u32("Number of headers").emit()?;
            }
        }
        b"PROP" => {
            f.u32("Max bit rate").emit()?;
            f.u32("Average bit rate").emit()?;
            f.u32("Max packet size").emit()?;
            f.u32("Average packet size").emit()?;
            f.u32("Number of packets").emit()?;
            f.u32("Duration")
                .with(|&d, n| n.summary(vidutil::seconds_ms(d.into())))
                .emit()?;
            f.u32("Preroll").desc("Milliseconds").emit()?;
            f.u32("Index offset").hex().emit()?;
            f.u32("Data offset").hex().emit()?;
            f.u16("Number of streams").emit()?;
            f.u16("Flags").flags(PROP_FLAGS).emit()?;
        }
        b"MDPR" => {
            f.u16("Stream number").emit()?;
            f.u32("Max bit rate").emit()?;
            f.u32("Average bit rate").emit()?;
            f.u32("Max packet size").emit()?;
            f.u32("Average packet size").emit()?;
            f.u32("Start time").emit()?;
            f.u32("Preroll").emit()?;
            f.u32("Duration")
                .with(|&d, n| n.summary(vidutil::seconds_ms(d.into())))
                .emit()?;
            let n = f.u8("Stream name size").emit()?;
            f.ascii("Stream name", n.into()).emit()?;
            let n = f.u8("MIME type size").emit()?;
            f.ascii("MIME type", n.into()).emit()?;
            let len = f.u32("Type-specific length").emit()?;
            let at = f.pos();
            type_specific_fields(&mut f, len.into())?;
            f.seek(at.saturating_add(len.into()));
        }
        b"CONT" => {
            for name in ["Title", "Author", "Copyright", "Comment"] {
                let n = f.u16("Length").get()?;
                f.ascii(name, n.into()).emit()?;
            }
        }
        b"DATA" => {
            let n = f.u32("Number of packets").emit()?;
            f.u32("Next data header").hex().emit()?;
            let packets = chunk.span.tail(18);
            cx.emit(
                Node::new("Packets")
                    .span(packets)
                    .summary(format!("{n} packets"))
                    .lazy(expand_packets, (packets, n)),
            );
        }
        b"INDX" => {
            let n = f.u32("Number of indices").emit()?;
            f.u16("Stream number").emit()?;
            f.u32("Next index header").hex().emit()?;
            let entries = chunk.span.tail(20);
            cx.emit(vidutil::table::<IndexEntry>(
                "Entries",
                entries,
                n.into(),
                BE,
            ));
        }
        _ => {
            let rest = chunk.span.tail(10);
            if !rest.is_empty() {
                cx.emit(Node::new("Data").span(rest));
            }
        }
    }
    Ok(())
}

/// Video (`VIDO`) and audio (`.ra\xfd`) stream headers.
fn type_specific_fields(f: &mut Fields<'_>, len: u64) -> Result<()> {
    let d = f
        .block()
        .data
        .get(vidutil::us(f.pos())..)
        .unwrap_or_default();
    if d.get(4..8) == Some(b"VIDO") {
        f.u32("Header size").emit()?;
        f.ascii("Type", 4).emit()?;
        f.ascii("Codec", 4).emit()?;
        f.u16("Width").emit()?;
        f.u16("Height").emit()?;
        f.u16("Bits per pixel").emit()?;
        f.u16("Padding width").emit()?;
        f.u16("Padding height").emit()?;
        f.u32("Frame rate")
            .with(|&v, n| n.summary(format!("{} fps", num(fixed16(v)))))
            .emit()?;
    } else if d.starts_with(b".ra\xfd") {
        f.bytes("Signature", 4).emit()?;
        f.u16("Version").emit()?;
        let at = f.pos();
        let rest = len.saturating_sub(6);
        f.node(Node::new("Audio header").span(f.peek_span(rest)));
        f.seek(at.saturating_add(rest));
    } else if len > 0 {
        f.bytes("Type-specific data", len).emit()?;
    }
    Ok(())
}

crate::record! {
    pub struct IndexEntry {
        version: u16 "Version",
        timestamp: u32 "Timestamp",
        offset: u32 "Packet offset" .hex(),
        packet: u32 "Packet number",
    }
}

impl vidutil::Entry for IndexEntry {
    fn summary(&self) -> Option<String> {
        Some(format!(
            "{} → packet {} at {:#x}",
            vidutil::seconds_ms(self.timestamp.into()),
            self.packet,
            self.offset
        ))
    }
}

async fn expand_packets(cx: Cx, (span, declared): (Span, u32)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u32;
    while pos < span.len && index < declared {
        let d = cx.read_avail(span.sub(pos, 12)).await?;
        let (Some(version), Some(len)) = (u16_be(&d, 0), u16_be(&d, 2)) else {
            break;
        };
        if len < 12 {
            cx.emit(
                Node::new("Invalid packet")
                    .span(span.tail(pos))
                    .diag(Diagnostic::malformed("packet shorter than its header")),
            );
            break;
        }
        let pspan = span.sub(pos, len.into());
        let stream = u16_be(&d, 4).unwrap_or(0);
        let ts = u32_be(&d, 6).unwrap_or(0);
        let key = version == 0 && d.get(11).is_some_and(|f| f & 2 != 0);
        cx.progress_in(span, span.offset.saturating_add(pos));
        cx.push(
            Node::new(format!("Packet {index}"))
                .span(pspan)
                .summary(format!(
                    "stream {stream}, {}{}, {len} bytes",
                    vidutil::seconds_ms(ts.into()),
                    if key { ", keyframe" } else { "" }
                ))
                .lazy(expand_packet, pspan),
        )
        .await;
        pos = pos.saturating_add(len.into());
        index = index.saturating_add(1);
    }
    cx.set_count(Count::Exact(index.into()));
    Ok(())
}

async fn expand_packet(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 13)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    let version = f.u16("Version").emit()?;
    f.u16("Length").emit()?;
    f.u16("Stream number").emit()?;
    f.u32("Timestamp")
        .with(|&t, n| n.summary(vidutil::seconds_ms(t.into())))
        .emit()?;
    let header = if version == 0 {
        f.u8("Packet group").emit()?;
        f.u8("Flags")
            .hex()
            .with(|&v, n| if v & 2 != 0 { n.summary("keyframe") } else { n })
            .emit()?;
        12
    } else {
        f.u16("ASM rule").emit()?;
        f.u8("ASM flags").hex().emit()?;
        13
    };
    cx.emit(Node::new("Payload").span(span.tail(header)));
    Ok(())
}
