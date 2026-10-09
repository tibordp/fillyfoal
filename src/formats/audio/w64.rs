//! Sony Wave64: like WAVE, but chunks are named by GUIDs, sizes are 64-bit
//! (and include the 24-byte chunk header), and chunks are 8-byte aligned.
//! The WAVE chunks keep their meaning: `fmt `, `data`, `fact` (a 64-bit
//! frame count here), `bext`, `junk`, plus Sony's `marker` and
//! `summarylist` GUIDs.

use crate::bytes::u64_le;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::iff::wav;
use crate::formats::util::sound::{fourcc, peek_text, text};
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
/// `{ABF76256-392D-11D2-86C7-00C04F8EDB8A}`
const MARKER: [u8; 16] = [
    0x56, 0x62, 0xf7, 0xab, 0x2d, 0x39, 0xd2, 0x11, 0x86, 0xc7, 0x00, 0xc0, 0x4f, 0x8e, 0xdb, 0x8a,
];
/// `{925F94BC-525A-11D2-86DC-00C04F8EDB8A}`
const SUMMARY_LIST: [u8; 16] = [
    0xbc, 0x94, 0x5f, 0x92, 0x5a, 0x52, 0xd2, 0x11, 0x86, 0xdc, 0x00, 0xc0, 0x4f, 0x8e, 0xdb, 0x8a,
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
    if guid == MARKER.as_slice() {
        return "marker".to_owned();
    }
    if guid == SUMMARY_LIST.as_slice() {
        return "summarylist".to_owned();
    }
    match guid.get(..4) {
        Some(head) if head.iter().all(|c| c.is_ascii_graphic() || *c == b' ') => fourcc(head),
        _ => "GUID chunk".to_owned(),
    }
}

fn describe_id(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "fmt" => "Sample format",
        "data" => "Sample data",
        "fact" => "Sample frames (for compressed formats)",
        "bext" => "Broadcast Wave extension (EBU Tech 3285)",
        "junk" => "Filler, ignored",
        "list" => "List of chunks",
        "levl" => "Peak envelope",
        "marker" => "Sony markers",
        "summarylist" => "Sony summary list",
        _ => return None,
    })
}

/// Chunks listed (a guard against hostile files of empty chunks).
const MAX_CHUNKS: usize = 4096;

#[derive(Clone, Debug)]
struct State {
    kind: String,
    span: Span,
    fmt: Option<wav::WaveFormat>,
    frames: Option<u64>,
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
    let mut fact = None;
    let mut chunks = Vec::new();
    while region.len.saturating_sub(pos) >= 24 && chunks.len() < MAX_CHUNKS {
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
            "fact" => fact = u64_le(&cx.read_avail(span.sub(24, 8)).await?, 0),
            _ => {}
        }
        chunks.push((kind, span, len));
        pos = pos.saturating_add(len.saturating_add(7) & !7);
    }
    if let Some(fmt) = &fmt {
        let mut line = format!("Wave64 {}", fmt.line());
        if let Some(d) = data_len.and_then(|n| fmt.duration(n, fact)) {
            line.push_str(&format!(", {d}"));
        }
        cx.annotate(line);
    }
    for (kind, span, len) in chunks {
        let mut node = Node::new(kind.clone()).span(span);
        let body = len.saturating_sub(24);
        node = node.summary(match (kind.as_str(), &fmt) {
            ("fmt", Some(f)) => f.line(),
            ("data", Some(f)) => match f.duration(body, fact) {
                Some(d) => format!("{body} bytes, {d}"),
                None => format!("{body} bytes"),
            },
            ("fact", _) => fact.map_or_else(|| format!("{body} bytes"), |n| format!("{n} frames")),
            ("bext", _) => {
                let t = peek_text(&cx, span.sub(24, 256), 256).await?;
                if t.is_empty() {
                    format!("{body} bytes")
                } else {
                    crate::formats::util::sound::clip(&t, 60)
                }
            }
            _ => format!("{body} bytes"),
        });
        if let Some(d) = describe_id(&kind) {
            node = node.desc(d);
        }
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        let state = State {
            kind,
            span,
            fmt: fmt.clone(),
            frames: fact,
        };
        cx.push(node.lazy(chunk, state)).await;
    }
    if pos < region.len {
        cx.emit(Node::new("Trailing bytes").span(region.tail(pos)));
    }
    Ok(())
}

async fn chunk(cx: Cx, st: State) -> Result<()> {
    let span = st.span;
    let head = cx.block(span.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.guid("Chunk GUID").emit()?;
    f.u64("Size").desc("Including the 24-byte header").emit()?;
    let data = span.tail(24);
    match st.kind.as_str() {
        "fmt" => {
            let block = cx.block(data).await?;
            wav::wave_format(&mut Fields::emitting(&cx, &block, LE), &())?;
        }
        "data" => {
            let mut node = Node::new("Samples").span(data);
            if let Some(fmt) = &st.fmt {
                let mut parts = Vec::new();
                if let Some(n) = fmt.frames(data.len, st.frames) {
                    parts.push(format!("{n} frames"));
                }
                if let Some(d) = fmt.duration(data.len, st.frames) {
                    parts.push(d);
                }
                if !parts.is_empty() {
                    node = node.summary(parts.join(", "));
                }
            }
            cx.emit(node);
        }
        "fact" => {
            let block = cx.block(data.sub(0, 8)).await?;
            Fields::emitting(&cx, &block, LE)
                .u64("Sample frames")
                .emit()?;
        }
        "bext" => {
            let rate = st.fmt.as_ref().map_or(0, |f| f.rate);
            let block = cx.block(data.sub(0, 602)).await?;
            wav::bext(&mut Fields::emitting(&cx, &block, LE), rate)?;
            let history = data.tail(602);
            if !history.is_empty() {
                let t = peek_text(&cx, history, history.len.min(1 << 16)).await?;
                cx.emit(Node::new("Coding history").span(history).value(text(t)));
            }
        }
        "junk" => cx.emit(Node::new("Padding").span(data)),
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}
