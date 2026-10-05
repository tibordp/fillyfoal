//! Apple Core Audio Format: `caff`, version and flags, then chunks with a
//! four-character type and a 64-bit big-endian size (-1 for a final `data`
//! chunk that runs to the end of the file).

use crate::bytes::{to_u64, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::sound::{channels, duration_of, fourcc, hz, leaf, text};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "caf",
    title: "Core Audio Format",
    extensions: &["caf"],
    mime: "audio/x-caf",
    probe: Probe::Magic(&[(0, b"caff\x00\x01")]),
    dissect: crate::expander!(dissect: Input),
};

const FORMATS: &[(&[u8; 4], &str)] = &[
    (b"lpcm", "Linear PCM"),
    (b"ima4", "IMA 4:1 ADPCM"),
    (b"aac ", "AAC"),
    (b"MAC3", "MACE 3:1"),
    (b"MAC6", "MACE 6:1"),
    (b"ulaw", "µ-law"),
    (b"alaw", "A-law"),
    (b".mp1", "MPEG Layer I"),
    (b".mp2", "MPEG Layer II"),
    (b".mp3", "MPEG Layer III"),
    (b"alac", "Apple Lossless"),
    (b"flac", "FLAC"),
    (b"opus", "Opus"),
    (b"ac-3", "AC-3"),
    (b"ec-3", "E-AC-3"),
    (b"samr", "AMR-NB"),
    (b"sawb", "AMR-WB"),
    (b"Qclp", "QCELP"),
    (b"QDM2", "QDesign Music 2"),
    (b"ilbc", "iLBC"),
];

fn format_name(id: &[u8]) -> String {
    FORMATS
        .iter()
        .find(|(k, _)| k.as_slice() == id)
        .map_or_else(|| fourcc(id), |(_, n)| (*n).to_owned())
}

const PCM_FLAGS: FlagTable = &[flag(0x1, "FLOAT"), flag(0x2, "LITTLE_ENDIAN")];

#[derive(Clone, Debug, Default)]
struct Description {
    rate: f64,
    format: Vec<u8>,
    bytes_per_packet: u32,
    frames_per_packet: u32,
    channels: u32,
    bits: u32,
}

fn desc(f: &mut Fields<'_>, _: &()) -> Result<Description> {
    let rate = f.f64("Sample rate").emit()?;
    let format = f
        .bytes("Format ID", 4)
        .with(|b, n| n.value(text(fourcc(b))).summary(format_name(b)))
        .emit()?;
    if format == b"lpcm" {
        f.u32("Format flags").flags(PCM_FLAGS).emit()?;
    } else {
        f.u32("Format flags").hex().emit()?;
    }
    Ok(Description {
        rate,
        format,
        bytes_per_packet: f.u32("Bytes per packet").desc("0 = variable").emit()?,
        frames_per_packet: f.u32("Frames per packet").desc("0 = variable").emit()?,
        channels: f.u32("Channels per frame").emit()?,
        bits: f.u32("Bits per channel").emit()?,
    })
}

const CHUNKS: &[(&[u8; 4], &str)] = &[
    (b"desc", "Audio description"),
    (b"data", "Audio data"),
    (b"pakt", "Packet table"),
    (b"chan", "Channel layout"),
    (b"kuki", "Magic cookie (codec configuration)"),
    (b"info", "Information strings"),
    (b"strg", "Strings"),
    (b"mark", "Markers"),
    (b"regn", "Regions"),
    (b"inst", "Instrument"),
    (b"midi", "MIDI data"),
    (b"umid", "Unique material identifier"),
    (b"ovvw", "Overview"),
    (b"peak", "Peak values"),
    (b"edct", "Edit comments"),
    (b"uuid", "User-defined"),
    (b"free", "Free space"),
];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("File type", 4).emit()?;
    f.u16("Version").emit()?;
    f.u16("Flags").emit()?;

    let mut pos = 8u64;
    let mut description = None;
    let mut data_len = None;
    let mut valid_frames = None;
    let mut chunks = Vec::new();
    while file.len.saturating_sub(pos) >= 12 && chunks.len() < 4096 {
        let h = cx.read(file.sub(pos, 12)).await?;
        let id: [u8; 4] = crate::bytes::array(&h, 0).unwrap_or_default();
        let raw = u64_be(&h, 4).unwrap_or(0);
        let size = if raw == u64::MAX {
            file.len.saturating_sub(pos).saturating_sub(12)
        } else {
            raw
        };
        let span = file.sub(pos, size.saturating_add(12));
        let data = span.tail(12);
        match &id {
            b"desc" => description = parse(&cx, data, BE, &(), desc).await.ok(),
            b"data" => data_len = Some(data.len.saturating_sub(4)),
            b"pakt" => {
                let p = cx.read_avail(data.sub(8, 8)).await?;
                valid_frames = u64_be(&p, 0);
            }
            _ => {}
        }
        chunks.push((id, span, raw));
        pos = pos.saturating_add(size).saturating_add(12);
    }
    if let Some(d) = &description {
        let mut line = format!("CAF, {}, {}, {}", format_name(&d.format), hz(d.rate), channels(d.channels));
        if d.bits > 0 {
            line.push_str(&format!(", {}-bit", d.bits));
        }
        let frames = match (valid_frames, data_len) {
            (Some(n), _) => Some(n),
            (None, Some(len)) if d.bytes_per_packet > 0 => Some(
                len.checked_div(d.bytes_per_packet.into())
                    .unwrap_or(0)
                    .saturating_mul(d.frames_per_packet.max(1).into()),
            ),
            _ => None,
        };
        if let Some(d) = frames.and_then(|n| duration_of(n, d.rate as u64)) {
            line.push_str(&format!(", {d}"));
        }
        cx.annotate(line);
    }
    for (id, span, raw) in chunks {
        let mut node = Node::new(fourcc(&id)).span(span);
        if let Some((_, d)) = CHUNKS.iter().find(|(k, _)| *k == &id) {
            node = node.desc(*d);
        }
        node = node.summary(match &id {
            b"desc" => description.as_ref().map_or_else(String::new, |d| {
                format!("{}, {}, {}", format_name(&d.format), hz(d.rate), channels(d.channels))
            }),
            _ => format!("{} bytes", span.len.saturating_sub(12)),
        });
        let declared = raw.saturating_add(12);
        if raw != u64::MAX && span.len < declared {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, declared),
                span.len,
            ));
        }
        cx.push(node.lazy(chunk, (input, id, span))).await;
    }
    if pos < file.len {
        cx.emit(Node::new("Trailing data").span(file.tail(pos)));
    }
    Ok(())
}

async fn chunk(cx: Cx, (input, id, span): (Input, [u8; 4], Span)) -> Result<()> {
    let head = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Chunk type", 4).emit()?;
    f.u64("Chunk size")
        .with(|&s, n| if s == u64::MAX { n.summary("-1: to the end of the file") } else { n })
        .emit()?;
    let data = span.tail(12);
    match &id {
        b"desc" => cx.emit(struct_node("Description", data, BE, (), desc)),
        b"data" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(&cx, &block, BE)
                .u32("Edit count")
                .emit()?;
            cx.emit(Node::new("Audio data").span(data.tail(4)));
        }
        b"pakt" => {
            let block = cx.block(data.sub(0, 24)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            f.int::<i64>("Packets").emit()?;
            f.int::<i64>("Valid frames").emit()?;
            f.i32("Priming frames").emit()?;
            f.i32("Remainder frames").emit()?;
            cx.emit(
                Node::new("Packet sizes")
                    .span(data.tail(24))
                    .desc("Variable-length integers, one (or two) per packet"),
            );
        }
        b"chan" => {
            let block = cx.block(data.sub(0, 12)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            f.u32("Layout tag")
                .hex()
                .with(|&t, n| n.summary(format!("layout {}, {} channels", t >> 16, t & 0xffff)))
                .emit()?;
            f.u32("Channel bitmap").hex().emit()?;
            f.u32("Channel descriptions").emit()?;
            if data.len > 12 {
                cx.emit(Node::new("Descriptions").span(data.tail(12)));
            }
        }
        b"info" => {
            let block = cx.block(data.sub(0, data.len.min(1 << 16))).await?;
            let count = u32_be(&block.data, 0).unwrap_or(0);
            cx.emit(leaf("Entries", data.sub(0, 4), crate::formats::sound::uint(count, 32)));
            let mut at = 4usize;
            for _ in 0..count {
                let rest = block.data.get(at..).unwrap_or_default();
                let Some(k) = rest.iter().position(|&b| b == 0) else {
                    break;
                };
                let after = rest.get(k.saturating_add(1)..).unwrap_or_default();
                let Some(v) = after.iter().position(|&b| b == 0) else {
                    break;
                };
                let key = String::from_utf8_lossy(rest.get(..k).unwrap_or_default()).into_owned();
                let value = String::from_utf8_lossy(after.get(..v).unwrap_or_default()).into_owned();
                let len = k.saturating_add(v).saturating_add(2);
                cx.emit(leaf(key, data.sub(to_u64(at), to_u64(len)), text(value)));
                at = at.saturating_add(len);
            }
        }
        b"midi" => cx.emit(embedded("MIDI file", input.nested(data))),
        b"free" => cx.emit(Node::new("Padding").span(data)),
        b"uuid" => {
            let block = cx.block(data.sub(0, 16)).await?;
            Fields::emitting(&cx, &block, BE).bytes("UUID", 16).emit()?;
            cx.emit(Node::new("Data").span(data.tail(16)));
        }
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}
