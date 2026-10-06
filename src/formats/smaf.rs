//! Yamaha SMAF (`.mmf`, mobile ringtones): an `MMMD` file chunk holding a
//! contents-info chunk, optional data, score tracks (`MTR*`) and audio
//! tracks (`ATR*`) with their own sub-chunks, and a final CRC-16.

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::sound::{decode_text, fourcc, hex, leaf, text};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "smaf",
    title: "Yamaha SMAF",
    extensions: &["mmf", "smaf"],
    mime: "application/vnd.smaf",
    probe: Probe::Custom(|h| h.starts_with(b"MMMD") && h.at(8, b"CNTI")),
    dissect: crate::expander!(dissect: Input),
};

const CLASS: EnumTable = &[(0, "YAMAHA"), (0x10, "unknown")];
const KIND: EnumTable = &[
    (0x00, "ringtone"),
    (0x10, "ringtone (MA-2)"),
    (0x20, "ringtone (MA-3)"),
    (0x30, "ringtone (MA-5)"),
];

fn describe(id: &[u8]) -> Option<&'static str> {
    Some(match id {
        b"CNTI" => "Contents information",
        b"OPDA" => "Optional data",
        [b'M', b'T', b'R', _] => "Score track",
        [b'A', b'T', b'R', _] => "Audio track",
        [b'G', b'T', b'R', _] => "Graphics track",
        b"MspI" | b"AspI" => "Seek and phrase information",
        b"Mtsu" => "Setup data",
        b"Mtsq" | b"Atsq" => "Sequence data",
        b"Mtsp" => "Stream PCM wave data",
        [b'M', b'w', b'a', _] | [b'A', b'w', b'a', _] => "Wave data",
        _ => return None,
    })
}

/// Bytes between a track chunk's header and its first sub-chunk.
fn track_header(id: &[u8], first: u8) -> u64 {
    match id {
        [b'A', b'T', b'R', _] => 6,
        [b'M', b'T', b'R', _] => {
            if first == 0 {
                8
            } else {
                20
            }
        }
        _ => 0,
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let size = u64::from(u32_be(&head, 4).unwrap_or(0));
    cx.emit(leaf("Magic", file.sub(0, 4), text("MMMD")));
    cx.emit(leaf(
        "Size",
        file.sub(4, 4),
        crate::formats::sound::uint(size, 32),
    ));
    // The file chunk ends with a CRC-16 (which some writers omit).
    let body = file.sub(8, size);
    let mut tracks = Vec::new();
    let end = walk(&cx, body, &mut tracks).await?;
    let rest = body.tail(end);
    if rest.len == 2 {
        let raw = cx.read(rest).await?;
        cx.emit(leaf("CRC", rest, hex(u16_be(&raw, 0).unwrap_or(0), 16)));
    } else if !rest.is_empty() {
        cx.emit(Node::new("Trailing bytes").span(rest));
    }
    cx.annotate(format!(
        "SMAF{}",
        if tracks.is_empty() {
            String::new()
        } else {
            format!(", tracks: {}", tracks.join(", "))
        }
    ));
    Ok(())
}

/// Lists the chunks of `region`; returns where the last one ends.
async fn walk(cx: &Cx, region: Span, tracks: &mut Vec<String>) -> Result<u64> {
    let mut pos = 0u64;
    while region.len.saturating_sub(pos) >= 8 {
        let head = cx.read(region.sub(pos, 9)).await?;
        let id = head.get(..4).unwrap_or_default().to_vec();
        let len = u64::from(u32_be(&head, 4).unwrap_or(0));
        let span = region.sub(pos, len.saturating_add(8));
        let name = fourcc(&id);
        if matches!(id.get(..3), Some(b"MTR" | b"ATR" | b"GTR")) {
            tracks.push(name.clone());
        }
        let mut node = Node::new(name).span(span).summary(format!("{len} bytes"));
        if let Some(d) = describe(&id) {
            node = node.desc(d);
        }
        let first = head.get(8).copied().unwrap_or(0);
        cx.push(node.lazy(
            crate::expander!(self::chunk: (Vec<u8>, Span, u8)),
            (id, span, first),
        ))
        .await;
        pos = pos.saturating_add(len).saturating_add(8);
    }
    Ok(pos.min(region.len))
}

async fn chunk(cx: Cx, (id, span, first): (Vec<u8>, Span, u8)) -> Result<()> {
    let data = span.tail(8);
    match id.as_slice() {
        b"CNTI" => {
            let block = cx.block(data.sub(0, 5)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            f.u8("Class").enumeration(CLASS).emit()?;
            f.u8("Type").enumeration(KIND).emit()?;
            f.u8("Code type").hex().emit()?;
            f.u8("Copy status").hex().emit()?;
            f.u8("Copy counts").emit()?;
            if data.len > 5 {
                let t = cx.read(data.tail(5)).await?;
                cx.emit(leaf("Options", data.tail(5), text(decode_text(&t))));
            }
        }
        b"OPDA" => {
            let t = cx.read_avail(data.sub(0, 4096)).await?;
            cx.emit(leaf("Data", data, text(decode_text(&t))));
        }
        [b'A', b'T', b'R', _] => {
            let block = cx.block(data.sub(0, 6)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            f.u8("Format type").emit()?;
            f.u8("Sequence type").emit()?;
            f.u16("Wave type")
                .hex()
                .with(|&w, n| {
                    let rate = match (w >> 8) & 0xf {
                        0 => "4000 Hz",
                        1 => "8000 Hz",
                        2 => "11025 Hz",
                        3 => "22050 Hz",
                        4 => "44100 Hz",
                        _ => "unknown rate",
                    };
                    n.summary(format!(
                        "{}, {rate}",
                        if w & 0x8000 != 0 { "stereo" } else { "mono" }
                    ))
                })
                .emit()?;
            f.u8("Timebase (duration)").emit()?;
            f.u8("Timebase (gate)").emit()?;
            walk(&cx, data.tail(6), &mut Vec::new()).await?;
        }
        [b'M', b'T', b'R', _] => {
            let skip = track_header(&id, first);
            let block = cx.block(data.sub(0, 4)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            f.u8("Format type").emit()?;
            f.u8("Sequence type").emit()?;
            f.u8("Timebase (duration)").emit()?;
            f.u8("Timebase (gate)").emit()?;
            cx.emit(Node::new("Channel status").span(data.sub(4, skip.saturating_sub(4))));
            walk(&cx, data.tail(skip), &mut Vec::new()).await?;
        }
        b"Mtsp" => {
            walk(&cx, data, &mut Vec::new()).await?;
        }
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}
