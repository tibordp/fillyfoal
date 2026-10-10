//! FLAC: the `fLaC` signature, metadata blocks (STREAMINFO, PADDING,
//! APPLICATION, SEEKTABLE, VORBIS_COMMENT, CUESHEET, PICTURE), then audio
//! frames. Frames have no length field: a frame ends where the next frame
//! header starts, which is found by scanning for a header whose CRC-8
//! checks out at a position where the CRC-16 of the bytes before it does
//! too.
//!
//! The metadata block decoders are shared with FLAC-in-Ogg.

use crate::bytes::{to_u64, to_usize, u32_be};
use crate::codec::crc::crc8;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::sound::{
    Bits, CRC16_BUYPASS, bits_node, channels, duration_of, image_info, leaf, parse_bits, table,
};
use crate::formats::util::val::{enumv, hex, text, uint};
use crate::formats::{Format, Input, Probe, audio::id3, audio::vorbis, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "flac",
    title: "Free Lossless Audio Codec",
    extensions: &["flac", "fla"],
    mime: "audio/flac",
    probe: Probe::Custom(|h| {
        h.starts_with(b"fLaC")
            || id3::v2_len(h.data)
                .and_then(|len| h.data.get(to_usize(len)..))
                .is_some_and(|rest| rest.starts_with(b"fLaC"))
    }),
    dissect: crate::expander!(dissect: Input),
};

pub const BLOCK_TYPE: EnumTable = &[
    (0, "STREAMINFO"),
    (1, "PADDING"),
    (2, "APPLICATION"),
    (3, "SEEKTABLE"),
    (4, "VORBIS_COMMENT"),
    (5, "CUESHEET"),
    (6, "PICTURE"),
    (127, "invalid"),
];

/// Registered APPLICATION block IDs.
const APPLICATIONS: &[(&[u8; 4], &str)] = &[
    (b"ATCH", "FlacFile"),
    (b"BSOL", "beSolo"),
    (b"BUGS", "Bugs Player"),
    (b"Cues", "GoldWave cue points"),
    (b"Fica", "CUE Splitter"),
    (b"Ftol", "flac-tools"),
    (b"MOTB", "MOTB MetaCzar"),
    (b"MPSE", "MP3 Stream Editor"),
    (b"MuML", "MusicML"),
    (b"RIFF", "Sound Devices RIFF chunk storage"),
    (b"SFFL", "Sound Font FLAC"),
    (b"SONY", "Sony Creative Software"),
    (b"SQEZ", "flacsqueeze"),
    (b"TtWv", "TwistedWave"),
    (b"UITS", "UITS embedding tools"),
    (b"aiff", "FLAC AIFF chunk storage"),
    (b"imag", "flac-image"),
    (b"peem", "Parseable Embedded Extensible Metadata"),
    (b"qfst", "QFLAC Studio"),
    (b"riff", "FLAC RIFF chunk storage"),
    (b"tune", "TagTuner"),
    (b"w64 ", "FLAC Wave64 chunk storage"),
    (b"xbat", "XBAT"),
    (b"xmcd", "xmcd"),
];

fn application(id: &[u8]) -> Option<&'static str> {
    APPLICATIONS
        .iter()
        .find(|(k, _)| k.as_slice() == id)
        .map(|(_, v)| *v)
}

/// STREAMINFO, the values the file summary needs.
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamInfo {
    pub rate: u64,
    pub channels: u64,
    pub bits: u64,
    pub samples: u64,
    pub min_frame: u64,
    pub max_frame: u64,
}

impl StreamInfo {
    /// "44100 Hz, 2 ch, 16-bit, 0:05".
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{} Hz, {}, {}-bit",
            self.rate,
            channels(self.channels),
            self.bits
        );
        if self.samples > 0
            && let Some(d) = duration_of(self.samples, self.rate)
        {
            s.push_str(&format!(", {d}"));
        }
        s
    }
}

pub fn streaminfo(b: &mut Bits<'_>) -> Result<StreamInfo> {
    let min_block = b.field("Minimum block size", 16).emit()?;
    b.field("Maximum block size", 16)
        .with(|v, n| {
            if v == min_block {
                n.summary("fixed block size")
            } else {
                n
            }
        })
        .emit()?;
    let min_frame = b
        .field("Minimum frame size", 24)
        .with(|v, n| if v == 0 { n.summary("unknown") } else { n })
        .emit()?;
    let max_frame = b
        .field("Maximum frame size", 24)
        .with(|v, n| if v == 0 { n.summary("unknown") } else { n })
        .emit()?;
    let rate = b
        .field("Sample rate", 20)
        .with(|v, n| n.summary(format!("{v} Hz")))
        .emit()?;
    let channels = b
        .field("Channels − 1", 3)
        .with(|v, n| n.summary(channels(v.saturating_add(1))))
        .emit()?
        .saturating_add(1);
    let bits = b
        .field("Bits per sample − 1", 5)
        .with(|v, n| n.summary(format!("{}-bit", v.saturating_add(1))))
        .emit()?
        .saturating_add(1);
    let samples = b
        .field("Total samples", 36)
        .with(|v, n| match duration_of(v, rate) {
            Some(d) if v > 0 => n.summary(d),
            _ => n.summary("unknown"),
        })
        .emit()?;
    b.bytes("MD5 signature", 16)
        .desc("MD5 of the unencoded audio samples; all zeros if not computed")
        .emit()?;
    Ok(StreamInfo {
        rate,
        channels,
        bits,
        samples,
        min_frame,
        max_frame,
    })
}

record! {
    pub struct SeekPoint {
        sample: u64 "Sample number" .desc("0xffffffffffffffff = placeholder"),
        offset: u64 "Offset" .hex() .desc("From the first frame header"),
        samples: u16 "Samples in target frame",
    }
}

/// One metadata block: its type and where it is.
#[derive(Clone, Copy, Debug)]
pub struct Block {
    pub input: Input,
    pub kind: u8,
    /// Header and data.
    pub span: Span,
}

/// A lazy node for the metadata block at `span` (header included).
pub async fn block_node(cx: &Cx, input: Input, span: Span) -> Result<Node> {
    let head = cx.read(span.sub(0, 4)).await?;
    let kind = head.first().copied().unwrap_or(0) & 0x7f;
    let name =
        lookup(BLOCK_TYPE, kind.into()).map_or_else(|| format!("Block type {kind}"), str::to_owned);
    let data = span.tail(4);
    let summary = match kind {
        0 => parse_bits(cx, data.sub(0, 34), streaminfo, false)
            .await
            .map(|s| s.summary())
            .ok(),
        1 => Some(format!("{} of padding", human_size(data.len))),
        3 => Some(format!("{} seek points", data.len / SeekPoint::SIZE)),
        4 => {
            let vendor = vendor(cx, data).await;
            match (vorbis::title(cx, data).await, vendor) {
                (Some(t), _) => Some(t),
                (None, Some(v)) => Some(format!("vendor {v}")),
                _ => None,
            }
        }
        5 => cuesheet_summary(cx, data).await.ok(),
        6 => picture_summary(cx, data).await.ok(),
        2 => {
            let id = cx.read_avail(data.sub(0, 4)).await?;
            let fourcc = crate::formats::util::sound::fourcc(&id);
            Some(match application(&id) {
                Some(name) => format!(
                    "{fourcc} ({name}), {}",
                    human_size(data.len.saturating_sub(4))
                ),
                None => format!("{fourcc}, {}", human_size(data.len.saturating_sub(4))),
            })
        }
        _ => None,
    };
    let node = Node::new(name)
        .span(span)
        .summary(summary.unwrap_or_else(|| human_size(data.len)));
    Ok(node.lazy(
        crate::expander!(self::block: Block),
        Block { input, kind, span },
    ))
}

/// STREAMINFO decoded from its 34-byte body at the start of `d`, for
/// summaries.
pub fn peek_streaminfo(d: &[u8]) -> Option<StreamInfo> {
    let d = d.get(..34)?;
    streaminfo(&mut Bits::new(
        d,
        crate::formats::util::vidutil::detached(d.len()),
    ))
    .ok()
}

/// Emits a lazy node for each metadata block of `region` from `pos` up to
/// the one flagged last, then any bytes after it: FLAC codec
/// configuration in other containers (ISOBMFF `dfLa`, Matroska, FLV, CAF).
pub async fn metadata_blocks(cx: &Cx, input: Input, region: Span, mut pos: u64) -> Result<()> {
    while pos.saturating_add(4) <= region.len {
        let h = cx.read_avail(region.sub(pos, 4)).await?;
        let Some(len) = crate::bytes::u24_be(&h, 1) else {
            break;
        };
        let last = h.first().is_some_and(|b| b & 0x80 != 0);
        let span = region.sub(pos, 4u64.saturating_add(len.into()));
        cx.emit(block_node(cx, input, span).await?);
        pos = pos.saturating_add(span.len.max(1));
        if last {
            break;
        }
    }
    if pos < region.len {
        cx.emit(Node::new("Trailing data").span(region.tail(pos)));
    }
    Ok(())
}

/// `fLaC` followed by metadata blocks: FLAC codec configuration as
/// Matroska, FLV and CAF store it.
pub async fn codec_config(cx: &Cx, input: Input, data: Span) -> Result<()> {
    let magic = cx.read_avail(data.sub(0, 4)).await?;
    if magic != b"fLaC" {
        cx.emit(Node::new("Data").span(data).diag(Diagnostic::malformed(
            "FLAC codec data without the fLaC signature",
        )));
        return Ok(());
    }
    cx.emit(
        Node::new("Signature")
            .span(data.sub(0, 4))
            .value(text("fLaC")),
    );
    metadata_blocks(cx, input, data, 4).await
}

/// "44100 Hz, 2 ch, 16-bit, 0:05" for the STREAMINFO at the start of a
/// metadata block sequence that may begin with `fLaC`.
pub fn config_summary(d: &[u8]) -> Option<String> {
    let blocks = d.strip_prefix(b"fLaC").unwrap_or(d);
    // The first block must be STREAMINFO.
    (blocks.first()? & 0x7f == 0)
        .then(|| peek_streaminfo(blocks.get(4..)?))
        .flatten()
        .map(|s| s.summary())
}

/// The vendor string of a comment block.
async fn vendor(cx: &Cx, data: Span) -> Option<String> {
    let head = cx.read_avail(data.sub(0, 4)).await.ok()?;
    let len = crate::bytes::u32_le(&head, 0)?;
    let v = cx
        .read_avail(data.sub(4, u64::from(len).min(256)))
        .await
        .ok()?;
    Some(String::from_utf8_lossy(&v).into_owned())
}

pub async fn block(cx: Cx, b: Block) -> Result<()> {
    let head = cx.block(b.span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u8("Header")
        .with(|&v, n| {
            n.value(enumv(v & 0x7f, 7, BLOCK_TYPE))
                .summary(if v & 0x80 != 0 {
                    "last metadata block"
                } else {
                    "more blocks follow"
                })
        })
        .emit()?;
    crate::formats::util::sound::u24(&mut f, "Length", BE).emit()?;
    let data = b.span.tail(4);
    match b.kind {
        0 => cx.emit(bits_node(
            "Stream info",
            data,
            |b| streaminfo(b).map(|_| ()),
            false,
        )),
        1 => {
            let head = cx.read_avail(data.sub(0, 4096)).await?;
            let mut node = Node::new("Padding")
                .span(data)
                .summary(human_size(data.len));
            if head.iter().any(|&b| b != 0) {
                node = node.diag(Diagnostic::warning("padding is not all zeros"));
            }
            cx.emit(node);
        }
        2 => {
            let id = cx.read_avail(data.sub(0, 4)).await?;
            let mut node = leaf(
                "Application ID",
                data.sub(0, 4),
                text(crate::formats::util::sound::fourcc(&id)),
            );
            if let Some(name) = application(&id) {
                node = node.summary(name);
            }
            cx.emit(node);
            let rest = data.tail(4);
            if matches!(id.as_slice(), b"riff" | b"aiff" | b"w64 ") {
                // flac --keep-foreign-metadata: one chunk of the original
                // file per block.
                let chunk = cx.read_avail(rest.sub(0, 4)).await?;
                cx.emit(
                    Node::new("Foreign chunk")
                        .span(rest)
                        .summary(format!(
                            "{}, {}",
                            crate::formats::util::sound::fourcc(&chunk),
                            human_size(rest.len)
                        ))
                        .desc(
                            "A chunk of the original WAV/AIFF/Wave64 file, kept for restoring it",
                        ),
                );
            } else if !rest.is_empty() {
                cx.emit(Node::new("Data").span(rest).summary(human_size(rest.len)));
            }
        }
        3 => cx.emit(table::<SeekPoint>(
            "Seek points",
            data,
            BE,
            "Point",
            Some(|p| {
                if p.sample == u64::MAX {
                    "placeholder".to_owned()
                } else {
                    format!(
                        "sample {} at byte {} ({} samples)",
                        p.sample, p.offset, p.samples
                    )
                }
            }),
        )),
        4 => {
            vorbis::emit(&cx, b.input, data).await?;
        }
        5 => cuesheet(&cx, data).await?,
        6 => picture(&cx, b.input, data).await?,
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CUESHEET

async fn cuesheet_summary(cx: &Cx, data: Span) -> Result<String> {
    let head = cx.read(data.sub(0, 396)).await?;
    let catalog = crate::formats::util::sound::latin1_z(head.get(..128).unwrap_or_default());
    let cd = head.get(136).is_some_and(|b| b & 0x80 != 0);
    let tracks = head.get(395).copied().unwrap_or(0);
    let mut s = format!("{tracks} tracks");
    if cd {
        s.push_str(", CD-DA");
    }
    if !catalog.is_empty() {
        s.push_str(&format!(", catalog {catalog}"));
    }
    Ok(s)
}

async fn cuesheet(cx: &Cx, data: Span) -> Result<()> {
    let block = cx.block(data.sub(0, 396)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    crate::formats::util::sound::latin1_field(&mut f, "Media catalog number", 128).emit()?;
    f.u64("Lead-in samples")
        .desc("CD-DA: samples before the first track (at least two seconds)")
        .emit()?;
    let cd = f
        .u8("Flags")
        .with(|&v, n| n.summary(if v & 0x80 != 0 { "CD-DA" } else { "not CD-DA" }))
        .emit()?
        & 0x80
        != 0;
    f.bytes("Reserved", 258).emit()?;
    let tracks = f.u8("Tracks").emit()?;
    let region = data.tail(396);
    cx.emit(
        Node::new("Tracks")
            .span(region)
            .summary(format!("{tracks} tracks"))
            .lazy(expand_tracks, (region, tracks, cd)),
    );
    Ok(())
}

/// A sample offset as a CD position (75 sectors per second at 44.1 kHz).
fn cd_time(samples: u64) -> String {
    let frames = samples / 588;
    format!(
        "{:02}:{:02}:{:02}",
        frames / 4500,
        frames / 75 % 60,
        frames % 75
    )
}

async fn expand_tracks(cx: Cx, (region, tracks, cd): (Span, u8, bool)) -> Result<()> {
    cx.set_count(Count::Exact(tracks.into()));
    let mut at = 0u64;
    for _ in 0..tracks {
        let head = cx.read(region.sub(at, 36)).await?;
        let offset = crate::bytes::u64_be(&head, 0).unwrap_or(0);
        let number = head.get(8).copied().unwrap_or(0);
        let isrc = crate::formats::util::sound::latin1_z(head.get(9..21).unwrap_or_default());
        let flags = head.get(21).copied().unwrap_or(0);
        let indices = head.get(35).copied().unwrap_or(0);
        let len = 36u64.saturating_add(u64::from(indices).saturating_mul(12));
        let span = region.sub(at, len);
        let name = if number == 170 || (number == 255 && !cd) {
            "Lead-out".to_owned()
        } else {
            format!("Track {number}")
        };
        let mut summary = format!("at sample {offset}");
        if cd {
            summary.push_str(&format!(" ({})", cd_time(offset)));
        }
        if flags & 0x80 != 0 {
            summary.push_str(", data");
        }
        if !isrc.is_empty() {
            summary.push_str(&format!(", ISRC {isrc}"));
        }
        if indices > 0 {
            summary.push_str(&format!(
                ", {}",
                crate::formats::util::arcutil::count(indices.into(), "index", "indices")
            ));
        }
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(expand_track, (span, cd)),
        )
        .await;
        at = at.saturating_add(len);
    }
    Ok(())
}

async fn expand_track(cx: Cx, (span, cd): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u64("Offset")
        .desc("In samples, from the start of the audio")
        .with(|&v, n| if cd { n.summary(cd_time(v)) } else { n })
        .emit()?;
    f.u8("Number")
        .with(|&v, n| {
            if v == 170 {
                n.summary("lead-out (CD-DA)")
            } else {
                n
            }
        })
        .emit()?;
    crate::formats::util::sound::latin1_field(&mut f, "ISRC", 12).emit()?;
    f.u8("Flags")
        .with(|&v, n| {
            let mut parts = vec![if v & 0x80 != 0 { "non-audio" } else { "audio" }];
            if v & 0x40 != 0 {
                parts.push("pre-emphasis");
            }
            n.summary(parts.join(", "))
        })
        .emit()?;
    f.bytes("Reserved", 13).emit()?;
    let count = f.u8("Index points").emit()?;
    for _ in 0..count {
        let span = f.peek_span(12);
        let offset = f.u64("Offset").get()?;
        let number = f.u8("Number").get()?;
        f.skip(3);
        let mut summary = format!("at sample {offset} relative to the track");
        if cd {
            summary.push_str(&format!(" ({})", cd_time(offset)));
        }
        f.node(
            Node::new(format!("Index {number}"))
                .span(span)
                .value(uint(offset, 64))
                .summary(summary),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PICTURE

/// The fields of a PICTURE block (also used inside Ogg comments).
pub async fn picture(cx: &Cx, input: Input, data: Span) -> Result<()> {
    let block = cx.block(data.sub(0, data.len.min(1 << 16))).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.u32("Picture type")
        .with(|&v, n| n.value(enumv(v, 32, id3::PICTURE_TYPE)))
        .emit()?;
    let len = f.u32("MIME type length").emit()?;
    crate::formats::util::sound::latin1_field(&mut f, "MIME type", len.into()).emit()?;
    let len = f.u32("Description length").emit()?;
    f.bytes("Description", len.into())
        .with(|b, n| n.value(text(String::from_utf8_lossy(b).into_owned())))
        .emit()?;
    f.u32("Width").emit()?;
    f.u32("Height").emit()?;
    f.u32("Color depth")
        .with(|&v, n| n.summary(format!("{v} bits per pixel")))
        .emit()?;
    f.u32("Colors used")
        .desc("For indexed images; 0 otherwise")
        .emit()?;
    let len = f.u32("Data length").emit()?;
    let image = data.sub(f.pos(), len.into());
    let info = block.data.get(to_usize(f.pos())..).and_then(image_info);
    let summary = match info {
        Some(i) => format!("{i}, {}", human_size(image.len)),
        None => human_size(image.len),
    };
    cx.emit(embedded("Picture data", input.nested(image)).summary(summary));
    Ok(())
}

async fn picture_summary(cx: &Cx, data: Span) -> Result<String> {
    let head = cx.read_avail(data.sub(0, 4096)).await?;
    let kind = u32_be(&head, 0).unwrap_or(0);
    let mime_len = to_usize(u32_be(&head, 4).unwrap_or(0).into());
    let mime = head
        .get(8..8usize.saturating_add(mime_len))
        .map(crate::text::latin1)
        .unwrap_or_default();
    let at = 8usize.saturating_add(mime_len);
    let desc_len = to_usize(u32_be(&head, at).unwrap_or(0).into());
    let fields = at.saturating_add(4).saturating_add(desc_len);
    let (w, h) = (
        u32_be(&head, fields).unwrap_or(0),
        u32_be(&head, fields.saturating_add(4)).unwrap_or(0),
    );
    let image = head.get(fields.saturating_add(20)..).unwrap_or_default();
    let kind = lookup(id3::PICTURE_TYPE, kind.into()).unwrap_or("picture");
    let what = image_info(image).unwrap_or_else(|| {
        if w > 0 && h > 0 {
            format!("{w}×{h} {mime}")
        } else {
            mime
        }
    });
    Ok(format!("{kind}, {what}"))
}

// ---------------------------------------------------------------------------
// File

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 10)).await?;
    let mut pos = 0u64;
    let mut titles = Vec::new();
    if let Some(len) = id3::v2_len(&head) {
        let span = file.sub(0, len);
        cx.emit(id3::tag_node(&cx, input, span).await);
        titles.extend(id3::title(&cx, span).await);
        pos = len;
    }
    cx.emit(
        Node::new("Signature")
            .span(file.sub(pos, 4))
            .value(text("fLaC")),
    );
    pos = pos.saturating_add(4);
    let mut info = None;
    let mut cover = None;
    loop {
        let head = cx.read(file.sub(pos, 4)).await?;
        let flags = head.first().copied().unwrap_or(0);
        let len = u64::from(crate::bytes::u24_be(&head, 1).unwrap_or(0));
        let span = file.sub(pos, len.saturating_add(4));
        let data = span.tail(4);
        match flags & 0x7f {
            0 if info.is_none() => {
                info = parse_bits(&cx, data.sub(0, 34), streaminfo, false)
                    .await
                    .ok();
            }
            4 => titles.extend(vorbis::title(&cx, data).await),
            6 if cover.is_none() => cover = picture_summary(&cx, data).await.ok(),
            _ => {}
        }
        let mut node = block_node(&cx, input, span).await?;
        if span.len < len.saturating_add(4) {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len.saturating_add(4)),
                span.len,
            ));
        }
        cx.push(node).await;
        pos = pos.saturating_add(4).saturating_add(len);
        if flags & 0x80 != 0 || pos >= file.len {
            break;
        }
    }
    let trailing = id3::trailing_tags(&cx, input, file, pos).await?;
    titles.extend(trailing.titles.iter().cloned());
    let frames = file.sub(pos, trailing.end.saturating_sub(pos));
    let mut line = match &info {
        Some(i) => {
            let mut s = format!("FLAC, {}", i.summary());
            if i.samples > 0 && i.rate > 0 {
                let seconds = i.samples as f64 / i.rate as f64;
                s.push_str(&format!(
                    ", {:.0} kbps",
                    frames.len as f64 * 8.0 / seconds / 1000.0
                ));
            }
            s
        }
        None => "FLAC".to_owned(),
    };
    if let Some(c) = cover.and_then(|c| c.split_once(", ").map(|(_, w)| w.to_owned())) {
        line.push_str(&format!(", cover {c}"));
    }
    if let Some(t) = titles.first() {
        line.push_str(&format!(" — {t}"));
    }
    cx.annotate(line);
    if !frames.is_empty() {
        cx.push(
            Node::new("Frames")
                .span(frames)
                .summary(human_size(frames.len))
                .lazy(list_frames, (frames, info.unwrap_or_default())),
        )
        .await;
    }
    for node in trailing.nodes {
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Frames

const CHANNELS: EnumTable = &[
    (0, "mono"),
    (1, "left, right"),
    (2, "left, right, centre"),
    (3, "front L/R, back L/R"),
    (4, "5 channels"),
    (5, "5.1"),
    (6, "6.1"),
    (7, "7.1"),
    (8, "left/side stereo"),
    (9, "side/right stereo"),
    (10, "mid/side stereo"),
];

const SAMPLE_SIZE: EnumTable = &[
    (0, "from STREAMINFO"),
    (1, "8-bit"),
    (2, "12-bit"),
    (3, "reserved"),
    (4, "16-bit"),
    (5, "20-bit"),
    (6, "24-bit"),
    (7, "32-bit"),
];

const RATE_CODE: EnumTable = &[
    (0, "from STREAMINFO"),
    (1, "88.2 kHz"),
    (2, "176.4 kHz"),
    (3, "192 kHz"),
    (4, "8 kHz"),
    (5, "16 kHz"),
    (6, "22.05 kHz"),
    (7, "24 kHz"),
    (8, "32 kHz"),
    (9, "44.1 kHz"),
    (10, "48 kHz"),
    (11, "96 kHz"),
    (12, "8-bit kHz follows"),
    (13, "16-bit Hz follows"),
    (14, "16-bit tens of Hz follows"),
    (15, "invalid"),
];

/// A decoded frame header.
#[derive(Clone, Copy, Debug)]
struct FrameHeader {
    len: usize,
    variable: bool,
    number: u64,
    block_size: u64,
    channels: u8,
}

/// Parses (and CRC-checks) the frame header at the start of `d`.
fn frame_header(d: &[u8]) -> Option<FrameHeader> {
    if *d.first()? != 0xff || d.get(1)? & 0xfe != 0xf8 {
        return None;
    }
    let size_code = d.get(2)? >> 4;
    let rate_code = d.get(2)? & 0xf;
    let chan = d.get(3)? >> 4;
    if size_code == 0
        || rate_code == 15
        || chan > 10
        || d.get(3)? & 1 != 0
        || (d.get(3)? >> 1) & 7 == 3
    {
        return None;
    }
    // UTF-8-style coded frame or sample number.
    let first = *d.get(4)?;
    let extra = first.leading_ones() as usize;
    let (mut number, extra) = match extra {
        0 => (u64::from(first), 0),
        2..=7 => (u64::from(first & (0x7f >> extra)), extra.saturating_sub(1)),
        _ => return None,
    };
    for i in 0..extra {
        let b = *d.get(5usize.saturating_add(i))?;
        if b & 0xc0 != 0x80 {
            return None;
        }
        number = (number << 6) | u64::from(b & 0x3f);
    }
    let mut at = 5usize.saturating_add(extra);
    let block_size = match size_code {
        1 => 192,
        2..=5 => 576u64 << size_code.saturating_sub(2),
        6 => {
            at = at.saturating_add(1);
            u64::from(*d.get(at.saturating_sub(1))?).saturating_add(1)
        }
        7 => {
            at = at.saturating_add(2);
            u64::from(crate::bytes::u16_be(d, at.saturating_sub(2))?).saturating_add(1)
        }
        _ => 256u64 << size_code.saturating_sub(8),
    };
    at = at.saturating_add(match rate_code {
        12 => 1,
        13 | 14 => 2,
        _ => 0,
    });
    let crc = *d.get(at)?;
    if crc8(d.get(..at)?) != crc {
        return None;
    }
    Some(FrameHeader {
        len: at.saturating_add(1),
        variable: d.get(1)? & 1 != 0,
        number,
        block_size,
        channels: chan,
    })
}

/// "frame 12, 4096 samples, mid/side stereo" for the frame header at the
/// start of `d` (FLAC-in-Ogg audio packets).
pub fn frame_summary(d: &[u8]) -> Option<String> {
    let h = frame_header(d)?;
    Some(format!(
        "{} {}, {} samples, {}",
        if h.variable { "sample" } else { "frame" },
        h.number,
        h.block_size,
        lookup(CHANNELS, h.channels.into()).unwrap_or("?")
    ))
}

/// A lazy node for the FLAC frame in `span` (whose first bytes are `d`):
/// FLAC-in-Ogg audio packets.
pub fn frame_node(d: &[u8], span: Span) -> Option<Node> {
    let h = frame_header(d)?;
    Some(
        Node::new("FLAC frame")
            .span(span)
            .summary(frame_summary(d).unwrap_or_default())
            .lazy(frame, (span, h.len)),
    )
}

/// How far ahead to look for the next frame in one read.
const WINDOW: u64 = 0x10000;

/// Where the frame starting at `pos` (relative to `region`) ends: the next
/// frame header after at least `min_len` bytes, numbered at least `number`,
/// where the CRC-16 of the frame so far checks out. If no such header turns
/// up within `limit` bytes (a damaged frame), the first header with a valid
/// CRC-8 is taken instead.
async fn next_frame(
    cx: &Cx,
    region: Span,
    pos: u64,
    min_len: u64,
    number: u64,
    limit: u64,
) -> Result<Option<u64>> {
    let mut at = pos;
    let mut crc = CRC16_BUYPASS.init();
    let mut fallback = None;
    while at < region.len {
        let window = cx
            .read_avail(region.sub(at, WINDOW.saturating_add(16)))
            .await?;
        let scan = window.len().min(to_usize(WINDOW));
        for (i, &b) in window.iter().take(scan).enumerate() {
            if i % 4096 == 0 {
                cx.checkpoint().await;
            }
            let abs = at.saturating_add(to_u64(i));
            if abs.saturating_sub(pos) >= min_len
                && b == 0xff
                && let Some(h) = window.get(i..).and_then(frame_header)
                && h.number >= number
            {
                if crc == 0 {
                    return Ok(Some(abs));
                }
                if fallback.is_none() {
                    fallback = Some(abs);
                }
            }
            if abs.saturating_sub(pos) > limit && fallback.is_some() {
                return Ok(fallback);
            }
            crc = CRC16_BUYPASS.update_byte(crc, b);
        }
        if to_u64(window.len()) <= 16 {
            break;
        }
        at = at.saturating_add(to_u64(scan).max(1));
    }
    Ok(fallback)
}

async fn list_frames(cx: Cx, (region, info): (Span, StreamInfo)) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let limit = if info.max_frame > 0 {
        info.max_frame.saturating_mul(2)
    } else {
        1 << 20
    };
    while pos < region.len {
        let mark = (pos, index);
        let head = cx.read_avail(region.sub(pos, 16)).await?;
        let Some(h) = frame_header(&head) else {
            let rest = region.tail(pos);
            cx.mark(move || mark);
            cx.push(
                Node::new("Unparsed data")
                    .span(rest)
                    .summary(human_size(rest.len))
                    .diag(Diagnostic::malformed("no valid frame header")),
            )
            .await;
            return Ok(());
        };
        let min = to_u64(h.len).saturating_add(2).max(info.min_frame);
        let next_number = if h.variable {
            h.number.saturating_add(h.block_size)
        } else {
            h.number.saturating_add(1)
        };
        let next = next_frame(&cx, region, pos, min, next_number, limit)
            .await?
            .unwrap_or(region.len);
        let span = region.sub(pos, next.saturating_sub(pos));
        cx.progress_in(region, region.offset.saturating_add(pos));
        let chans = lookup(CHANNELS, h.channels.into()).unwrap_or("?");
        let what = if h.variable { "sample" } else { "frame" };
        cx.mark(move || mark);
        cx.push(
            Node::new(format!("Frame {index}"))
                .span(span)
                .summary(format!(
                    "{what} {}, {} samples, {chans}, {}",
                    h.number,
                    h.block_size,
                    human_size(span.len)
                ))
                .lazy(frame, (span, h.len)),
        )
        .await;
        pos = next;
        index = index.saturating_add(1);
    }
    Ok(())
}

/// "LPC, order 8".
fn subframe_type(t: u64) -> String {
    match t {
        0 => "constant".to_owned(),
        1 => "verbatim".to_owned(),
        8..=12 => format!("fixed predictor, order {}", t.saturating_sub(8)),
        32..=63 => format!("LPC, order {}", t.saturating_sub(31)),
        _ => "reserved".to_owned(),
    }
}

async fn frame(cx: Cx, (span, header_len): (Span, usize)) -> Result<()> {
    let header = span.sub(0, to_u64(header_len));
    cx.emit(bits_node("Header", header, frame_fields, false));
    let crc_at = span.len.saturating_sub(2);
    let subframes = span.sub(
        to_u64(header_len),
        crc_at.saturating_sub(to_u64(header_len)),
    );
    let first = cx.read_avail(subframes.sub(0, 1)).await?;
    let mut node = Node::new("Subframes").span(subframes).desc(
        "One encoded subframe per channel; only the first one's start is known without decoding",
    );
    if let Some(&b) = first.first() {
        let kind = u64::from((b >> 1) & 0x3f);
        node = node
            .summary(format!(
                "first: {}{}",
                subframe_type(kind),
                if b & 1 != 0 { ", wasted bits" } else { "" }
            ))
            .lazy(expand_subframe, subframes.sub(0, 1));
    }
    cx.emit(node);
    // The CRC-16 covers the whole frame; with the CRC itself the remainder
    // is zero.
    let crc = cx.read(span.sub(crc_at, 2)).await?;
    let mut crc_node = leaf(
        "CRC-16",
        span.sub(crc_at, 2),
        hex(crate::bytes::u16_be(&crc, 0).unwrap_or(0), 16),
    );
    if span.len <= cx.limits().max_read {
        let data = cx.read_avail(span).await?;
        if to_u64(data.len()) == span.len {
            let mut reg = CRC16_BUYPASS.init();
            for chunk in data.chunks(0x10000) {
                reg = CRC16_BUYPASS.update(reg, chunk);
                cx.checkpoint().await;
            }
            crc_node = if reg == 0 {
                crc_node.summary("valid")
            } else {
                crc_node.diag(Diagnostic::warning("CRC mismatch"))
            };
        }
    }
    cx.emit(crc_node);
    Ok(())
}

async fn expand_subframe(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let mut b = Bits::emitting(&cx, &data, span);
    b.field("Zero bit", 1).emit()?;
    b.field("Subframe type", 6)
        .hex()
        .with(|v, n| n.summary(subframe_type(v)))
        .emit()?;
    b.field("Wasted bits flag", 1).flag().emit()?;
    Ok(())
}

fn frame_fields(b: &mut Bits<'_>) -> Result<()> {
    b.field("Sync code", 14).hex().emit()?;
    b.field("Reserved", 1).emit()?;
    let variable = b
        .field("Blocking strategy", 1)
        .with(|v, n| n.summary(if v == 0 { "fixed" } else { "variable" }))
        .emit()?;
    let size_code = b
        .field("Block size code", 4)
        .with(|v, n| match v {
            1 => n.summary("192 samples"),
            2..=5 => n.summary(format!("{} samples", 576u64 << v.saturating_sub(2))),
            6 => n.summary("8-bit value follows"),
            7 => n.summary("16-bit value follows"),
            8..=15 => n.summary(format!("{} samples", 256u64 << v.saturating_sub(8))),
            _ => n.diag(Diagnostic::malformed("reserved block size code")),
        })
        .emit()?;
    let rate_code = b
        .field("Sample rate code", 4)
        .enumeration(RATE_CODE)
        .emit()?;
    b.field("Channel assignment", 4)
        .enumeration(CHANNELS)
        .emit()?;
    b.field("Sample size", 3).enumeration(SAMPLE_SIZE).emit()?;
    b.field("Reserved", 1).emit()?;
    // The frame or sample number, UTF-8 style: the first byte's leading
    // ones count the bytes.
    let start = b.pos();
    let first = b.read(8).unwrap_or(0);
    let extra = u8::try_from(first).unwrap_or(0).leading_ones();
    let (mut number, extra) = if extra >= 2 {
        (first & (0x7f >> extra), extra.saturating_sub(1))
    } else {
        (first, 0)
    };
    for _ in 0..extra {
        number = (number << 6) | (b.read(8).unwrap_or(0) & 0x3f);
    }
    b.node(
        Node::new(if variable == 0 {
            "Frame number"
        } else {
            "Sample number"
        })
        .span(b.span_of(start, b.pos()))
        .value(uint(number, 64))
        .desc("Coded like UTF-8: frame number (fixed blocking) or first sample number (variable)"),
    );
    match size_code {
        6 => {
            b.field("Block size − 1", 8)
                .with(|v, n| n.summary(format!("{} samples", v.saturating_add(1))))
                .emit()?;
        }
        7 => {
            b.field("Block size − 1", 16)
                .with(|v, n| n.summary(format!("{} samples", v.saturating_add(1))))
                .emit()?;
        }
        _ => {}
    }
    match rate_code {
        12 => {
            b.field("Sample rate (kHz)", 8).emit()?;
        }
        13 => {
            b.field("Sample rate (Hz)", 16).emit()?;
        }
        14 => {
            b.field("Sample rate (10 Hz)", 16).emit()?;
        }
        _ => {}
    }
    b.field("CRC-8", 8)
        .hex()
        .with(|_, n| n.summary("valid"))
        .emit()?;
    Ok(())
}
