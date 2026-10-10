//! Audio codecs and production files: TwinVQ, Logic EXS24 instruments,
//! ReCycle loops and Power Tab tablature.

use crate::bytes::{u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::util::val::text;
use crate::formats::video::containers::chunks;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::text::until_nul;
use crate::value::Value;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// TwinVQ, Logic EXS24, ReCycle, Power Tab

declare_format!(pub TWINVQ = "twinvq", "TwinVQ audio (VQF)", ["vqf", "vql", "vqe"], "audio/x-twinvq",
    Probe::Magic(&[(0, b"TWIN")]), twinvq);

async fn twinvq(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let version = String::from_utf8_lossy(head.get(4..12).unwrap_or_default()).into_owned();
    let size = u64::from(u32_be(&head, 12).unwrap_or(0));
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 8))
            .value(text(version.clone())),
    );
    let header = file.sub(16, size);
    let mut summary = String::new();
    let mut pos = 0u64;
    while pos.saturating_add(8) <= header.len {
        let h = cx.read(header.sub(pos, 8)).await?;
        let id = String::from_utf8_lossy(h.get(..4).unwrap_or_default()).into_owned();
        let len = u64::from(u32_be(&h, 4).unwrap_or(0));
        let body = header.sub(pos.saturating_add(8), len);
        let mut node = Node::new(id.clone()).span(header.sub(pos, len.saturating_add(8)));
        if id == "COMM" {
            let b = cx.read_avail(body.sub(0, 12)).await?;
            summary = format!(
                "{} channel(s), {} kbps, {} kHz",
                u32_be(&b, 0).unwrap_or(0).saturating_add(1),
                u32_be(&b, 4).unwrap_or(0),
                u32_be(&b, 8).unwrap_or(0)
            );
            node = node.summary(summary.clone());
        } else if matches!(id.as_str(), "NAME" | "AUTH" | "(c) " | "FILE" | "COMT") {
            let t = cx.read_avail(body.sub(0, 256)).await?;
            node = node.value(text(String::from_utf8_lossy(&t).into_owned()));
        }
        cx.emit(node);
        pos = pos.saturating_add(8).saturating_add(len);
    }
    cx.emit(Node::new("Audio data").span(file.tail(16u64.saturating_add(size))));
    cx.annotate(format!("TwinVQ {version}, {summary}"));
    Ok(())
}

fn exs_probe(h: &Head<'_>) -> bool {
    h.at(16, b"TBOS") || h.at(16, b"SOBT") || h.at(16, b"JBOS")
}

declare_format!(pub EXS = "exs24", "Logic EXS24 sampler instrument", ["exs"], "application/x-exs24",
    Probe::Custom(exs_probe), exs);

async fn exs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let big = cx.read(file.sub(16, 4)).await? == b"SOBT";
    let mut pos = 0u64;
    let mut counts = [0u32; 6];
    let mut name = String::new();
    while pos.saturating_add(84) <= file.len {
        let h = cx.read(file.sub(pos, 84)).await?;
        let kind = if big { u32_be(&h, 0) } else { u32_le(&h, 0) }.unwrap_or(0);
        let size = u64::from(if big { u32_be(&h, 4) } else { u32_le(&h, 4) }.unwrap_or(0));
        let label = match kind & 0x0f00_0000 {
            0 => "Header",
            0x0100_0000 => "Zone",
            0x0200_0000 => "Group",
            0x0300_0000 => "Sample",
            0x0400_0000 => "Parameters",
            _ => "Chunk",
        };
        let index = usize::try_from((kind >> 24) & 0x0f).unwrap_or(5).min(5);
        if let Some(c) = counts.get_mut(index) {
            *c = c.saturating_add(1);
        }
        let chunk_name = until_nul(h.get(20..84).unwrap_or_default());
        if index == 0 {
            name = chunk_name.clone();
        }
        cx.push(
            Node::new(label)
                .span(file.sub(pos, size.saturating_add(84)))
                .summary(chunk_name),
        )
        .await;
        pos = pos.saturating_add(84).saturating_add(size);
    }
    let [_, zones, groups, samples, ..] = counts;
    cx.annotate(format!(
        "EXS24 instrument {name:?}: {zones} zones, {groups} groups, {samples} samples"
    ));
    Ok(())
}

fn rex_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"CAT ") && h.at(8, b"REX2")
}

declare_format!(pub REX2 = "rex2", "Propellerhead ReCycle loop (REX2)", ["rx2", "rex"], "audio/x-rex2",
    Probe::Custom(rex_probe), rex2);

async fn rex2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Container")
            .span(file.sub(0, 12))
            .summary("CAT REX2"),
    );
    let found = chunks(&cx, file, 12, ChunkLayout::IFF).await?;
    let slices = found.iter().filter(|c| c.id == b"SLCE").count();
    cx.annotate(format!(
        "REX2 loop, {} chunks, {slices} slices",
        found.len()
    ));
    Ok(())
}

declare_format!(pub PTAB = "power-tab", "Power Tab document", ["ptb"], "application/x-power-tab",
    Probe::Magic(&[(0, b"ptab")]), power_tab);

/// An MFC `CString`: a length byte (0xff: a u16 follows), then the text.
async fn mfc_string(cur: &mut Cursor<'_>) -> Result<(String, Span)> {
    let mut len = u64::from(cur.u8().await?);
    if len == 0xff {
        len = u64::from(cur.u16().await?);
    }
    let span = cur.span(len);
    let text = String::from_utf8_lossy(&cur.bytes(len).await?).into_owned();
    Ok((text, span))
}

async fn power_tab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.skip(4);
    let version = cur.u16().await?;
    let kind = cur.u8().await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 2))
            .value(text(format!("{}.{}", version >> 8, version & 0xff))),
    );
    cx.emit(
        Node::new("File type")
            .span(file.sub(6, 1))
            .value(Value::Enum {
                raw: kind.into(),
                bits: 8,
                name: match kind {
                    0 => Some("song"),
                    1 => Some("lesson"),
                    _ => None,
                },
            }),
    );
    let mut title = String::new();
    if kind == 0 {
        let content = cur.u8().await?;
        cx.emit(
            Node::new("Content type")
                .span(cur.since(cur.pos().saturating_sub(1)))
                .value(Value::UInt {
                    value: content.into(),
                    bits: 8,
                    radix: crate::value::Radix::Hex,
                }),
        );
        let (t, span) = mfc_string(&mut cur).await?;
        cx.emit(Node::new("Title").span(span).value(text(t.clone())));
        title = t;
        let (artist, span) = mfc_string(&mut cur).await?;
        cx.emit(Node::new("Artist").span(span).value(text(artist.clone())));
        if !artist.is_empty() {
            title = format!("{title} by {artist}");
        }
    }
    cx.emit(Node::new("Body").span(file.tail(cur.pos())));
    cx.annotate(format!(
        "Power Tab {} {title:?}",
        if kind == 0 { "song" } else { "lesson" }
    ));
    Ok(())
}
