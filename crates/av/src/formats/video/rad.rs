//! RAD Game Tools video: Bink (`BIK`, `KB2`) and Smacker (`SMK2`, `SMK4`).
//! The headers are decoded; frames are listed in pages from the frame index
//! (Bink) or the frame size table (Smacker).

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::plural;
use crate::formats::util::vidutil::{self, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const LE: Endian = Endian::Little;

pub static BINK: Format = Format {
    name: "bink",
    title: "Bink video",
    extensions: &["bik", "bk2"],
    mime: "video/vnd.radgamettools.bink",
    probe: Probe::Custom(|h| {
        (h.starts_with(b"BIK") || h.starts_with(b"KB2"))
            && h.data.get(3).is_some_and(u8::is_ascii_lowercase)
            && u32_le(h.data, 8).is_some_and(|n| n > 0 && n < 1_000_000)
            && u32_le(h.data, 20).is_some_and(|w| w > 0 && w <= 16384)
            && u32_le(h.data, 24).is_some_and(|w| w > 0 && w <= 16384)
    }),
    dissect: crate::expander!(dissect_bink: Input),
};

pub static SMACKER: Format = Format {
    name: "smacker",
    title: "Smacker video",
    extensions: &["smk"],
    mime: "video/vnd.radgamettools.smacker",
    probe: Probe::Custom(|h| {
        (h.starts_with(b"SMK2") || h.starts_with(b"SMK4"))
            && u32_le(h.data, 4).is_some_and(|w| w > 0 && w <= 16384)
            && u32_le(h.data, 8).is_some_and(|w| w > 0 && w <= 16384)
    }),
    dissect: crate::expander!(dissect_smacker: Input),
};

record! {
    pub struct BinkHeader {
        signature: ascii[4] "Signature",
        file_size: u32 "File size − 8",
        frames: u32 "Frame count",
        largest: u32 "Largest frame size",
        frames2: u32 "Frame count (repeated)",
        width: u32 "Width",
        height: u32 "Height",
        fps_num: u32 "Frame rate dividend",
        fps_den: u32 "Frame rate divider",
        flags: u32 "Video flags" .flags(BINK_FLAGS),
        tracks: u32 "Audio tracks",
    }
}

const BINK_FLAGS: FlagTable = &[flag(0x0010_0000, "ALPHA"), flag(0x0002_0000, "GRAYSCALE")];

const AUDIO_FLAGS: FlagTable = &[
    flag(0x1000, "USE_DCT"),
    flag(0x2000, "STEREO"),
    flag(0x4000, "16_BIT"),
];

const MAX_TRACKS: u32 = 256;

#[derive(Clone, Copy, Debug)]
struct Frames {
    /// The frame offset table.
    index: Span,
    count: u64,
    file: Span,
}

pub async fn dissect_bink(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (h, span) = crate::dsl::Cursor::new(&cx, file, LE)
        .record::<BinkHeader>()
        .await?;
    cx.emit(BinkHeader::node("Header", span, LE));
    let fps = if h.fps_den > 0 {
        format!(
            ", {} fps",
            vidutil::num(f64::from(h.fps_num) / f64::from(h.fps_den))
        )
    } else {
        String::new()
    };
    let version = h.signature.get(3..).unwrap_or("").to_owned();
    cx.annotate(format!(
        "Bink {}{version}, {}×{}, {}{fps}, {}",
        if h.signature.starts_with("KB2") {
            "2 "
        } else {
            ""
        },
        h.width,
        h.height,
        plural(h.frames, "frame"),
        plural(h.tracks, "audio track")
    ));
    let tracks = u64::from(h.tracks.min(MAX_TRACKS));
    if h.tracks > MAX_TRACKS {
        cx.diag(Diagnostic::limit(format!("{} audio tracks", h.tracks)));
    }
    let mut pos = BinkHeader::SIZE;
    if tracks > 0 {
        let len = tracks.saturating_mul(12);
        let s = file.sub(pos, len);
        cx.emit(
            Node::new("Audio tracks")
                .span(s)
                .summary(plural(tracks, "track"))
                .lazy(bink_tracks, (s, tracks)),
        );
        pos = pos.saturating_add(len);
    }
    let count = u64::from(h.frames);
    let index = file.sub(pos, count.saturating_add(1).saturating_mul(4));
    cx.emit(
        Node::new("Frames")
            .span(index)
            .summary(plural(count, "frame"))
            .desc("From the frame index; bit 0 of an offset marks a keyframe")
            .lazy(bink_frames, Frames { index, count, file }),
    );
    Ok(())
}

async fn bink_tracks(cx: Cx, (span, tracks): (Span, u64)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    for _ in 0..tracks {
        f.u32("Max decoded size").emit()?;
    }
    for _ in 0..tracks {
        f.u16("Sample rate").emit()?;
        f.u16("Audio flags").flags(AUDIO_FLAGS).emit()?;
    }
    for _ in 0..tracks {
        f.u32("Track ID").emit()?;
    }
    Ok(())
}

const PAGE: u64 = 256;

async fn bink_frames(cx: Cx, fr: Frames) -> Result<()> {
    let fits = fr.index.len.checked_div(4).unwrap_or(0).saturating_sub(1);
    let count = fr.count.min(fits);
    if count < fr.count {
        cx.diag(Diagnostic::truncated(
            Span::new(
                fr.index.source,
                fr.index.offset,
                fr.count.saturating_add(1).saturating_mul(4),
            ),
            fr.index.len,
        ));
    }
    cx.set_count(Count::Exact(count));
    let mut i = 0u64;
    while i < count {
        let n = count.saturating_sub(i).min(PAGE);
        let d = cx
            .read(
                fr.index
                    .sub(i.saturating_mul(4), n.saturating_add(1).saturating_mul(4)),
            )
            .await?;
        for j in 0..n {
            let at = vidutil::us(j.saturating_mul(4));
            let start = u32_le(&d, at).unwrap_or(0);
            let end = u32_le(&d, at.saturating_add(4)).unwrap_or(0) & !1;
            let key = start & 1 != 0;
            let start = u64::from(start & !1);
            let len = u64::from(end).saturating_sub(start);
            let entry = fr.index.sub(i.saturating_add(j).saturating_mul(4), 4);
            let mut node = uint(format!("Frame {}", i.saturating_add(j)), entry, start, 32)
                .summary(format!(
                    "{len} bytes{}",
                    if key { ", keyframe" } else { "" }
                ))
                .target(fr.file.sub(start, len));
            if start > fr.file.len {
                node = node.diag(Diagnostic::malformed(
                    "frame offset beyond the end of the file",
                ));
            }
            cx.push(node).await;
        }
        i = i.saturating_add(n);
    }
    Ok(())
}

record! {
    pub struct SmackerHeader {
        signature: ascii[4] "Signature",
        width: u32 "Width",
        height: u32 "Height",
        frames: u32 "Frame count",
        rate: i32 "Frame rate" .desc("> 0: ms per frame; < 0: 1/100 ms per frame; 0: 10 fps"),
        flags: u32 "Flags" .flags(SMK_FLAGS),
        audio0: u32 "Audio size 0",
        audio1: u32 "Audio size 1",
        audio2: u32 "Audio size 2",
        audio3: u32 "Audio size 3",
        audio4: u32 "Audio size 4",
        audio5: u32 "Audio size 5",
        audio6: u32 "Audio size 6",
        trees: u32 "Trees size",
        mmap: u32 "MMap size",
        mclr: u32 "MClr size",
        full: u32 "Full size",
        types: u32 "Type size",
        rate0: u32 "Audio rate 0" .hex() .with(|&v, n| n.summary(audio_rate(v))),
        rate1: u32 "Audio rate 1" .hex() .with(|&v, n| n.summary(audio_rate(v))),
        rate2: u32 "Audio rate 2" .hex() .with(|&v, n| n.summary(audio_rate(v))),
        rate3: u32 "Audio rate 3" .hex() .with(|&v, n| n.summary(audio_rate(v))),
        rate4: u32 "Audio rate 4" .hex() .with(|&v, n| n.summary(audio_rate(v))),
        rate5: u32 "Audio rate 5" .hex() .with(|&v, n| n.summary(audio_rate(v))),
        rate6: u32 "Audio rate 6" .hex() .with(|&v, n| n.summary(audio_rate(v))),
        dummy: u32 "Dummy",
    }
}

const SMK_FLAGS: FlagTable = &[
    flag(1, "RING_FRAME"),
    flag(2, "Y_INTERLACED"),
    flag(4, "Y_DOUBLED"),
];

fn audio_rate(v: u32) -> String {
    if v & 0x4000_0000 == 0 {
        return "no audio".to_owned();
    }
    format!(
        "{} Hz, {}-bit, {}{}",
        v & 0x00ff_ffff,
        if v & 0x2000_0000 != 0 { 16 } else { 8 },
        if v & 0x1000_0000 != 0 {
            "stereo"
        } else {
            "mono"
        },
        if v & 0x8000_0000 != 0 {
            ", compressed"
        } else {
            ""
        }
    )
}

#[derive(Clone, Copy, Debug)]
struct SmkFrames {
    sizes: Span,
    types: Span,
    data: Span,
    count: u64,
}

pub async fn dissect_smacker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (h, span) = crate::dsl::Cursor::new(&cx, file, LE)
        .record::<SmackerHeader>()
        .await?;
    cx.emit(SmackerHeader::node("Header", span, LE));
    let fps = match h.rate {
        r if r > 0 => 1000.0 / f64::from(r),
        r if r < 0 => 100_000.0 / -f64::from(r),
        _ => 10.0,
    };
    let audio = [
        h.rate0, h.rate1, h.rate2, h.rate3, h.rate4, h.rate5, h.rate6,
    ]
    .iter()
    .filter(|&&r| r & 0x4000_0000 != 0)
    .count();
    cx.annotate(format!(
        "Smacker {}, {}×{}, {}, {} fps, {}",
        h.signature.get(3..).unwrap_or(""),
        h.width,
        h.height,
        plural(h.frames, "frame"),
        vidutil::num(fps),
        plural(crate::bytes::to_u64(audio), "audio track")
    ));
    let count = u64::from(h.frames).saturating_add(u64::from(h.flags & 1));
    let mut pos = SmackerHeader::SIZE;
    let sizes = file.sub(pos, count.saturating_mul(4));
    pos = pos.saturating_add(count.saturating_mul(4));
    let types = file.sub(pos, count);
    pos = pos.saturating_add(count);
    let trees = file.sub(pos, h.trees.into());
    pos = pos.saturating_add(h.trees.into());
    cx.emit(
        Node::new("Frame sizes")
            .span(sizes)
            .summary(format!("{count} entries")),
    );
    cx.emit(Node::new("Frame types").span(types));
    cx.emit(
        Node::new("Huffman trees")
            .span(trees)
            .summary(format!("{} bytes", h.trees)),
    );
    let data = file.tail(pos);
    cx.emit(
        Node::new("Frames")
            .span(data)
            .summary(plural(count, "frame"))
            .lazy(
                smacker_frames,
                SmkFrames {
                    sizes,
                    types,
                    data,
                    count,
                },
            ),
    );
    Ok(())
}

async fn smacker_frames(cx: Cx, fr: SmkFrames) -> Result<()> {
    let count = fr.count.min(fr.sizes.len / 4).min(fr.types.len);
    cx.set_count(Count::Exact(count));
    let mut pos = 0u64;
    let mut i = 0u64;
    while i < count {
        let n = count.saturating_sub(i).min(PAGE);
        let sizes = cx
            .read(fr.sizes.sub(i.saturating_mul(4), n.saturating_mul(4)))
            .await?;
        let types = cx.read(fr.types.sub(i, n)).await?;
        for j in 0..n {
            let raw = u32_le(&sizes, vidutil::us(j.saturating_mul(4))).unwrap_or(0);
            let t = types.get(vidutil::us(j)).copied().unwrap_or(0);
            let len = u64::from(raw & !3);
            let span = fr.data.sub(pos, len);
            let mut parts = vec![format!("{len} bytes")];
            if raw & 1 != 0 {
                parts.push("keyframe".to_owned());
            }
            if t & 1 != 0 {
                parts.push("palette".to_owned());
            }
            let tracks = (t >> 1).count_ones();
            if tracks > 0 {
                parts.push(plural(tracks, "audio chunk"));
            }
            let mut node = Node::new(format!("Frame {}", i.saturating_add(j)))
                .span(span)
                .summary(parts.join(", "));
            if span.len < len {
                node = node.diag(Diagnostic::truncated(
                    Span::new(span.source, span.offset, len),
                    span.len,
                ));
            }
            cx.push(node).await;
            pos = pos.saturating_add(len);
        }
        i = i.saturating_add(n);
    }
    Ok(())
}
