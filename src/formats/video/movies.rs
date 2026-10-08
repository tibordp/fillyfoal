//! Game and workstation movies: LucasArts SMUSH, DXA, Acorn Replay and SGI
//! movies.

use crate::bytes::{u16_be, u16_le, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::text::scan::head_lines;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::value::{Radix, Value};

const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

// ---------------------------------------------------------------------------
// Video: LucasArts SMUSH, DXA, Acorn Replay, SGI movies

fn smush_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"ANIM") && h.at(8, b"AHDR")
}

declare_format!(pub SMUSH = "smush", "LucasArts SMUSH animation (SAN/ANM)", ["san", "anm", "snm"], "video/x-smush",
    Probe::Custom(smush_probe), smush);

async fn smush(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let size = u64::from(u32_be(&cx.read(file.sub(4, 4)).await?, 0).unwrap_or(0));
    cx.emit(
        Node::new("ANIM")
            .span(file.sub(0, 8))
            .summary(format!("{size} bytes")),
    );
    let mut cur = Cursor::new(&cx, file.sub(8, size), BE);
    let mut frames = 0u32;
    let mut version = 0u16;
    let mut declared = 0u16;
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, BE).align(2)).await? {
        if chunk.id == b"AHDR" {
            let b = cx.read(chunk.body.sub(0, 4)).await?;
            version = u16_le(&b, 0).unwrap_or(0);
            declared = u16_le(&b, 2).unwrap_or(0);
        } else if chunk.id == b"FRME" {
            frames = frames.saturating_add(1);
        }
        cx.progress_in(cur.region(), cur.region().offset.saturating_add(cur.pos()));
        cx.push(chunk.node()).await;
    }
    cx.annotate(format!(
        "SMUSH animation v{version}, {declared} frames declared, {frames} present"
    ));
    Ok(())
}

declare_format!(pub DXA = "dxa", "DXA video (ScummVM)", ["dxa"], "video/x-dxa",
    Probe::Magic(&[(0, b"DEXA")]), dxa);

async fn dxa(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 15)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    f.u8("Flags").hex().emit()?;
    let frames = f.u16("Frames").emit()?;
    let rate = f.u32("Frame rate").emit()?;
    let w = f.u16("Width").emit()?;
    let h = f.u16("Height").emit()?;
    let signed = i32::from_ne_bytes(rate.to_ne_bytes());
    let fps = match signed {
        r if r > 0 => 1000.0 / f64::from(r),
        r if r < 0 => 100_000.0 / f64::from(r.unsigned_abs()),
        _ => 10.0,
    };
    let mut pos = 15u64;
    let tag = cx.read_avail(file.sub(pos, 4)).await?;
    if tag == b"WAVE" {
        let size =
            u64::from(u32_be(&cx.read(file.sub(pos.saturating_add(4), 4)).await?, 0).unwrap_or(0));
        cx.emit(embedded(
            "Sound (WAV)",
            input.nested(file.sub(pos.saturating_add(8), size)),
        ));
        pos = pos.saturating_add(8).saturating_add(size);
    }
    cx.emit(
        Node::new("Frames")
            .span(file.tail(pos))
            .summary(format!("{frames} FRAM/NULL records")),
    );
    cx.annotate(format!(
        "DXA video, {w}×{h}, {frames} frames at {fps:.2} fps"
    ));
    Ok(())
}

declare_format!(pub ARMOVIE = "armovie", "Acorn Replay movie (ARMovie)", ["rpl"], "video/x-armovie",
    Probe::Magic(&[(0, b"ARMovie\n")]), armovie);

async fn armovie(cx: Cx, input: Input) -> Result<()> {
    let lines = head_lines(&cx, input.span, 1024).await?;
    const LABELS: [&str; 15] = [
        "Signature",
        "Name",
        "Date and copyright",
        "Author",
        "Video format",
        "Width",
        "Height",
        "Pixel depth",
        "Frames per second",
        "Sound format",
        "Sound rate",
        "Sound channels",
        "Sound precision",
        "Frames per chunk",
        "Chunks",
    ];
    let mut values = Vec::new();
    for ((line, span), label) in lines.iter().zip(LABELS) {
        let value = line.split(" ;").next().unwrap_or(line).trim().to_owned();
        values.push(value.clone());
        cx.emit(Node::new(label).span(*span).value(text(value)));
    }
    let get = |i: usize| values.get(i).cloned().unwrap_or_default();
    cx.annotate(format!(
        "Acorn Replay movie {:?}: {}×{}, {} fps",
        get(1),
        get(5),
        get(6),
        get(8)
    ));
    Ok(())
}

declare_format!(pub SGI_MOVIE = "sgi-movie", "SGI movie", ["mv", "movie", "sgi"], "video/x-sgi-movie",
    Probe::Magic(&[(0, b"MOVI")]), sgi_movie);

async fn sgi_movie(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let version = u16_be(&head, 4).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 2))
            .value(uint(version.into(), 16)),
    );
    cx.emit(Node::new("Movie").span(file.tail(8)));
    cx.annotate(format!("SGI movie, version {version}"));
    Ok(())
}
