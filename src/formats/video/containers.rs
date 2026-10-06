//! Smaller video containers: Nullsoft Streaming Video, NuppelVideo, RED R3D
//! and Deluxe Paint animations.

use crate::bytes::u16_le;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Chunk, ChunkLayout, Cursor, Record, emit_record};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// Pushes a node for every chunk of `region` from `start`; returns the chunks.
async fn chunks(cx: &Cx, region: Span, start: u64, layout: ChunkLayout) -> Result<Vec<Chunk>> {
    let mut cur = Cursor::new(cx, region, layout.endian);
    cur.seek(start);
    let mut out = Vec::new();
    while let Some(chunk) = cur.chunk(layout).await? {
        cx.push(chunk.node()).await;
        out.push(chunk);
    }
    Ok(out)
}

/// "3× A, 1× B" for chunk kinds in order of first appearance.
fn tally(found: &[Chunk]) -> String {
    let mut counts: Vec<(String, u32)> = Vec::new();
    for c in found {
        let id = c.name();
        match counts.iter_mut().find(|(k, _)| *k == id) {
            Some((_, n)) => *n = n.saturating_add(1),
            None => counts.push((id, 1)),
        }
    }
    counts
        .iter()
        .map(|(k, n)| format!("{n}× {k}"))
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Video: Nullsoft Streaming Video, NuppelVideo, RED, Deluxe Paint Animation

declare_format!(pub NSV = "nsv", "Nullsoft Streaming Video", ["nsv"], "video/x-nsv",
    Probe::Magic(&[(0, b"NSVf"), (0, b"NSVs")]), nsv);

async fn nsv(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    if cx.read(file.sub(0, 4)).await? == b"NSVf" {
        let head = cx.block(file.sub(0, 28)).await?;
        let mut f = Fields::emitting(&cx, &head, LE);
        f.ascii("Signature", 4).emit()?;
        let size = f.u32("Header size").emit()?;
        f.u32("File size").emit()?;
        f.u32("Length (ms)").emit()?;
        let meta = f.u32("Metadata length").emit()?;
        f.u32("TOC allocated").emit()?;
        f.u32("TOC entries").emit()?;
        if meta > 0 {
            let m = cx
                .read_avail(file.sub(28, u64::from(meta).min(4096)))
                .await?;
            cx.emit(
                Node::new("Metadata")
                    .span(file.sub(28, meta.into()))
                    .value(text(String::from_utf8_lossy(&m).into_owned())),
            );
        }
        at = size.into();
    }
    let s = cx.read_avail(file.sub(at, 19)).await?;
    if s.starts_with(b"NSVs") {
        let video = String::from_utf8_lossy(s.get(4..8).unwrap_or_default()).into_owned();
        let audio = String::from_utf8_lossy(s.get(8..12).unwrap_or_default()).into_owned();
        let w = u16_le(&s, 12).unwrap_or(0);
        let h = u16_le(&s, 14).unwrap_or(0);
        cx.emit(
            Node::new("First sync frame")
                .span(file.sub(at, 19))
                .summary(format!("video {video}, audio {audio}, {w}×{h}")),
        );
        cx.emit(Node::new("Stream").span(file.tail(at)));
        cx.annotate(format!(
            "NSV, video {}, audio {}, {w}×{h}",
            video.trim(),
            audio.trim()
        ));
    } else {
        cx.emit(Node::new("Stream").span(file.tail(at)));
        cx.annotate("NSV");
    }
    Ok(())
}

declare_format!(pub NUV = "nuppelvideo", "NuppelVideo / MythTV recording", ["nuv"], "video/x-nuv",
    Probe::Magic(&[(0, b"NuppelVideo\0"), (0, b"MythTVVideo\0")]), nuv);

record! {
    pub struct NuvHeader {
        magic: ascii[12] "Signature",
        version: ascii[5] "Version",
        pad: bytes[3] "Padding",
        width: i32 "Width",
        height: i32 "Height",
        desired_width: i32 "Desired width",
        desired_height: i32 "Desired height",
        pimode: u8 "Picture mode",
        pad2: bytes[3] "Padding",
        aspect: f64 "Aspect ratio",
        fps: f64 "Frames per second",
        video_blocks: i32 "Video blocks",
        audio_blocks: i32 "Audio blocks",
        text_blocks: i32 "Text blocks",
        keyframe_distance: i32 "Keyframe distance",
    }
}

async fn nuv(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: NuvHeader = emit_record(&cx, file.sub(0, NuvHeader::SIZE), LE).await?;
    cx.emit(Node::new("Frames").span(file.tail(NuvHeader::SIZE)));
    cx.annotate(format!(
        "{} {} recording, {}×{} at {:.2} fps",
        h.magic, h.version, h.width, h.height, h.fps
    ));
    Ok(())
}

fn r3d_probe(h: &Head<'_>) -> bool {
    h.at(4, b"RED1") || h.at(4, b"RED2")
}

declare_format!(pub R3D = "r3d", "RED camera raw video (R3D)", ["r3d"], "video/x-r3d",
    Probe::Custom(r3d_probe), r3d);

async fn r3d(cx: Cx, input: Input) -> Result<()> {
    let found = chunks(
        &cx,
        input.span,
        0,
        ChunkLayout::new(4, 4, BE).size_first().inclusive(),
    )
    .await?;
    cx.annotate(format!("RED R3D clip: {}", tally(&found)));
    Ok(())
}

declare_format!(pub DPAINT_ANM = "dpaint-anm", "Deluxe Paint Animation (ANM)", ["anm"], "video/x-dpaint-anm",
    Probe::Magic(&[(0, b"LPF ")]), dpaint_anm);

async fn dpaint_anm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x80)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    f.u16("Maximum large pages").emit()?;
    let pages = f.u16("Large pages").emit()?;
    let records = f.u32("Records").emit()?;
    f.u16("Maximum records per page").emit()?;
    f.u16("Page table offset").hex().emit()?;
    f.ascii("Content type", 4).emit()?;
    let w = f.u16("Width").emit()?;
    let h = f.u16("Height").emit()?;
    f.u8("Variant").emit()?;
    f.u8("Version").emit()?;
    f.u8("Has last delta").emit()?;
    f.u8("Last delta valid").emit()?;
    f.u8("Pixel type").emit()?;
    f.u8("Compression").emit()?;
    f.u8("Other records per frame").emit()?;
    f.u8("Bitmap type").emit()?;
    f.bytes("Record types", 32).emit()?;
    let frames = f.u32("Frames").emit()?;
    let fps = f.u16("Frames per second").emit()?;
    cx.emit(Node::new("Palette").span(file.sub(0x80, 0x400)));
    cx.emit(Node::new("Large page table").span(file.sub(0x500, 0x600)));
    cx.emit(
        Node::new("Large pages")
            .span(file.tail(0xb00))
            .summary(format!("{pages} × 64 KiB")),
    );
    cx.annotate(format!(
        "Deluxe Paint animation, {w}×{h}, {frames} frames at {fps} fps, {records} records"
    ));
    Ok(())
}
