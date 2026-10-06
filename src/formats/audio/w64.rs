//! Sony Wave64: like WAVE, but chunks are named by GUIDs, sizes are 64-bit
//! (and include the 24-byte chunk header), and chunks are 8-byte aligned.

use crate::bytes::u64_le;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::iff::wav;
use crate::formats::util::sound::fourcc;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;

const LE: Endian = Endian::Little;

const RIFF: [u8; 16] = [
    0x72, 0x69, 0x66, 0x66, 0x2e, 0x91, 0xcf, 0x11, 0xa5, 0xd6, 0x28, 0xdb, 0x04, 0xc1, 0x00, 0x00,
];
/// The tail shared by the WAVE-specific GUIDs (`fmt `, `data`, `wave`, ...).
const WAVE_TAIL: [u8; 12] = [
    0xf3, 0xac, 0xd3, 0x11, 0x8c, 0xd1, 0x00, 0xc0, 0x4f, 0x8e, 0xdb, 0x8a,
];

pub static FORMAT: Format = Format {
    name: "w64",
    title: "Sony Wave64",
    extensions: &["w64"],
    mime: "audio/x-w64",
    probe: Probe::Custom(|h| h.starts_with(&RIFF) && h.at(24, b"wave") && h.at(28, &WAVE_TAIL)),
    dissect: crate::expander!(dissect: Input),
};

/// A readable name for a chunk GUID: its first four bytes, which spell the
/// chunk's RIFF name for the standard GUIDs.
fn name(guid: &[u8]) -> String {
    match guid.get(..4) {
        Some(head) if head.iter().all(|c| c.is_ascii_graphic() || *c == b' ') => fourcc(head),
        _ => "GUID chunk".to_owned(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 40)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.guid("RIFF GUID").emit()?;
    let size = f.u64("Size").desc("Including this header").emit()?;
    f.guid("WAVE GUID").emit()?;
    let region = file.sub(40, size.saturating_sub(40));
    let mut pos = 0u64;
    let mut fmt = None;
    let mut data_len = None;
    let mut chunks = Vec::new();
    while region.len.saturating_sub(pos) >= 24 && chunks.len() < 4096 {
        let h = cx.read(region.sub(pos, 24)).await?;
        let len = u64_le(&h, 16).unwrap_or(0).max(24);
        let span = region.sub(pos, len);
        let kind = name(h.get(..16).unwrap_or_default());
        match kind.as_str() {
            "fmt" => {
                fmt = parse(&cx, span.tail(24), LE, &(), wav::wave_format)
                    .await
                    .ok()
            }
            "data" => data_len = Some(len.saturating_sub(24)),
            _ => {}
        }
        chunks.push((kind, span, len));
        pos = pos.saturating_add(len.saturating_add(7) & !7);
    }
    if let Some(fmt) = &fmt {
        let mut line = format!("Wave64 {}", fmt.summary());
        if let Some(d) = data_len.and_then(|n| fmt.duration(n, None)) {
            line.push_str(&format!(", {d}"));
        }
        cx.annotate(line);
    }
    for (kind, span, len) in chunks {
        let mut node = Node::new(kind.clone()).span(span);
        node = node.summary(match (kind.as_str(), &fmt) {
            ("fmt", Some(f)) => f.summary(),
            _ => format!("{} bytes", len.saturating_sub(24)),
        });
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        cx.push(node.lazy(chunk, (kind, span))).await;
    }
    if pos < region.len {
        cx.emit(Node::new("Trailing bytes").span(region.tail(pos)));
    }
    Ok(())
}

async fn chunk(cx: Cx, (kind, span): (String, Span)) -> Result<()> {
    let head = cx.block(span.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.guid("Chunk GUID").emit()?;
    f.u64("Size").desc("Including the 24-byte header").emit()?;
    let data = span.tail(24);
    match kind.as_str() {
        "fmt" => {
            let block = cx.block(data).await?;
            wav::wave_format(&mut Fields::emitting(&cx, &block, LE), &())?;
        }
        "data" => cx.emit(Node::new("Samples").span(data)),
        "junk" => cx.emit(Node::new("Padding").span(data)),
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}
