//! AAC in ADTS framing (`.aac`): each frame starts with a 7-byte header
//! (9 with CRC) giving the profile, sample rate, channel configuration and
//! frame length. An ID3v2 tag may precede the stream.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::util::sound::{Bits, FrameSyntax, count_frames, duration, frames_node};
use crate::formats::{Format, Head, Input, Probe, audio::id3};
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "aac",
    title: "AAC audio (ADTS)",
    extensions: &["aac", "adts"],
    mime: "audio/aac",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let start = id3::v2_len(h.data).map_or(0, to_usize);
    let Some(data) = h.data.get(start..) else {
        return false;
    };
    match parse(data) {
        Some((len, _)) => match data.get(to_usize(len)..) {
            Some(next) if next.len() >= 7 => parse(next).is_some(),
            _ => true,
        },
        None => false,
    }
}

const RATES: [u32; 13] = [
    96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
];

const PROFILE: EnumTable = &[(0, "Main"), (1, "LC"), (2, "SSR"), (3, "LTP")];

const CHANNELS: EnumTable = &[
    (0, "defined in the stream"),
    (1, "mono"),
    (2, "stereo"),
    (3, "3 channels"),
    (4, "4 channels"),
    (5, "5 channels"),
    (6, "5.1"),
    (7, "7.1"),
];

/// Frame length and description of the ADTS header at the start of `d`.
fn parse(d: &[u8]) -> Option<(u64, String)> {
    let h = d.get(..7)?;
    let b = |i: usize| h.get(i).copied().unwrap_or(0);
    if b(0) != 0xff || b(1) & 0xf6 != 0xf0 {
        return None;
    }
    let profile = b(2) >> 6;
    let rate = *RATES.get(usize::from((b(2) >> 2) & 0xf))?;
    let channels = ((b(2) & 1) << 2) | (b(3) >> 6);
    let len = (u64::from(b(3) & 3) << 11) | (u64::from(b(4)) << 3) | u64::from(b(5) >> 5);
    let header = if b(1) & 1 == 0 { 9 } else { 7 };
    if len < header {
        return None;
    }
    Some((
        len,
        format!(
            "AAC {}, {rate} Hz, {}",
            crate::value::lookup(PROFILE, profile.into()).unwrap_or("?"),
            crate::value::lookup(CHANNELS, channels.into()).unwrap_or("?")
        ),
    ))
}

fn header(d: &[u8]) -> u64 {
    if d.get(1).is_some_and(|b| b & 1 == 0) {
        9
    } else {
        7
    }
}

fn layout(b: &mut Bits<'_>) -> Result<()> {
    b.field("Sync word", 12).hex().emit()?;
    b.field("MPEG version", 1)
        .with(|v, n| n.summary(if v == 0 { "MPEG-4" } else { "MPEG-2" }))
        .emit()?;
    b.field("Layer", 2).emit()?;
    let absent = b
        .field("Protection absent", 1)
        .with(|v, n| n.summary(if v == 0 { "CRC follows" } else { "no CRC" }))
        .emit()?;
    b.field("Profile", 2).enumeration(PROFILE).emit()?;
    b.field("Sample rate index", 4)
        .with(|v, n| match RATES.get(to_usize(v)) {
            Some(r) => n.summary(format!("{r} Hz")),
            None => n,
        })
        .emit()?;
    b.field("Private", 1).emit()?;
    b.field("Channel configuration", 3)
        .enumeration(CHANNELS)
        .emit()?;
    b.field("Original/copy", 1).emit()?;
    b.field("Home", 1).emit()?;
    b.field("Copyright ID bit", 1).emit()?;
    b.field("Copyright ID start", 1).emit()?;
    b.field("Frame length", 13)
        .desc("Including the header")
        .emit()?;
    b.field("Buffer fullness", 11)
        .with(|v, n| if v == 0x7ff { n.summary("VBR") } else { n })
        .emit()?;
    b.field("Raw data blocks − 1", 2).emit()?;
    if absent == 0 {
        b.field("CRC", 16).hex().emit()?;
    }
    Ok(())
}

static SYNTAX: FrameSyntax = FrameSyntax {
    peek: 9,
    parse,
    header,
    layout,
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 10)).await?;
    let mut start = 0u64;
    if let Some(len) = id3::v2_len(&head) {
        cx.emit(id3::tag_node(&cx, input, file.sub(0, len)).await);
        start = len;
    }
    let mut end = file.len;
    let mut trailing = None;
    if let Some(v1) = id3::find_v1(&cx, file).await? {
        trailing = Some(id3::v1_node(&cx, v1).await?);
        end = end.saturating_sub(128);
    }
    let stream = file.sub(start, end.saturating_sub(start));
    let window = cx.read_avail(stream.sub(0, 0x10000)).await?;
    if let Some((_, describe)) = parse(&window) {
        let (count, covered) = count_frames(&window, &SYNTAX);
        let rate = window
            .get(2)
            .and_then(|b| RATES.get(usize::from((b >> 2) & 0xf)))
            .copied()
            .unwrap_or(0);
        // Frames hold 1024 samples per raw data block.
        let frames = if covered == to_u64(window.len()) || covered == 0 {
            count as f64
        } else {
            count as f64 * stream.len as f64 / covered as f64
        };
        let seconds = if rate > 0 {
            frames * 1024.0 / f64::from(rate)
        } else {
            0.0
        };
        let kbps = if seconds > 0.0 {
            stream.len as f64 * 8.0 / seconds / 1000.0
        } else {
            0.0
        };
        cx.annotate(format!(
            "{describe} (ADTS), {kbps:.0} kbps, {}",
            duration(seconds)
        ));
    }
    cx.emit(frames_node(stream, &SYNTAX));
    if let Some(node) = trailing {
        cx.emit(node);
    }
    Ok(())
}
