//! Raw AAC streams: ADTS (`.aac`: each frame starts with a 7-byte header,
//! 9 with CRC, giving the profile, sample rate, channel configuration and
//! frame length), ADIF (one header for the whole stream, then unframed raw
//! data blocks) and LOAS/LATM (frames with an 11-bit sync word whose
//! payload starts with a StreamMuxConfig carrying an AudioSpecificConfig).
//! An ID3v2 tag may precede the stream.
//!
//! The AudioSpecificConfig and program config element decoders here are
//! usable wherever MPEG-4 audio is configured (MP4 `esds`, FLV, Matroska).

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::sound::{
    Bits, FrameRef, FrameSyntax, bits_node, duration, estimate_frames, frames_node,
};
use crate::formats::{Format, Head, Input, Probe, audio::id3};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

pub static FORMAT: Format = Format {
    name: "aac",
    title: "AAC audio (ADTS, ADIF, LOAS)",
    extensions: &["aac", "adts", "adif", "loas", "latm"],
    mime: "audio/aac",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let start = id3::v2_len(h.data).map_or(0, to_usize);
    let Some(data) = h.data.get(start..) else {
        return false;
    };
    if data.starts_with(b"ADIF") {
        return true;
    }
    for syntax in [&ADTS, &LOAS] {
        if let Some((len, _)) = (syntax.parse)(data) {
            return match data.get(to_usize(len)..) {
                Some(next) if to_u64(next.len()) >= syntax.peek => (syntax.parse)(next).is_some(),
                _ => true,
            };
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Shared tables and configuration structures

pub const RATES: [u32; 13] = [
    96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
];

/// ADTS profiles: the audio object type minus one.
const PROFILE: EnumTable = &[(0, "Main"), (1, "LC"), (2, "SSR"), (3, "LTP")];

pub const OBJECT_TYPE: EnumTable = &[
    (0, "null"),
    (1, "AAC Main"),
    (2, "AAC LC"),
    (3, "AAC SSR"),
    (4, "AAC LTP"),
    (5, "SBR (HE-AAC)"),
    (6, "AAC Scalable"),
    (7, "TwinVQ"),
    (8, "CELP"),
    (9, "HVXC"),
    (12, "TTSI"),
    (13, "Main synthetic"),
    (14, "Wavetable synthesis"),
    (15, "General MIDI"),
    (16, "Algorithmic synthesis"),
    (17, "ER AAC LC"),
    (19, "ER AAC LTP"),
    (20, "ER AAC Scalable"),
    (21, "ER TwinVQ"),
    (22, "ER BSAC"),
    (23, "ER AAC LD"),
    (24, "ER CELP"),
    (25, "ER HVXC"),
    (26, "ER HILN"),
    (27, "ER Parametric"),
    (28, "SSC"),
    (29, "PS (HE-AAC v2)"),
    (30, "MPEG Surround"),
    (32, "MPEG-1/2 Layer I"),
    (33, "MPEG-1/2 Layer II"),
    (34, "MPEG-1/2 Layer III"),
    (35, "DST"),
    (36, "ALS"),
    (37, "SLS"),
    (38, "SLS non-core"),
    (39, "ER AAC ELD"),
    (40, "SMR Simple"),
    (41, "SMR Main"),
    (42, "USAC (no SBR)"),
    (43, "SAOC"),
    (44, "LD MPEG Surround"),
    (45, "USAC"),
];

pub const CHANNEL_CONFIG: EnumTable = &[
    (0, "defined by a program config element"),
    (1, "mono"),
    (2, "stereo"),
    (3, "3.0 (C, L, R)"),
    (4, "4.0 (C, L, R, Cs)"),
    (5, "5.0"),
    (6, "5.1"),
    (7, "7.1 (front wide)"),
    (11, "6.1"),
    (12, "7.1 (rear)"),
    (13, "22.2"),
    (14, "7.1 (front height)"),
];

const ELEMENT: EnumTable = &[
    (0, "SCE (single channel)"),
    (1, "CPE (channel pair)"),
    (2, "CCE (coupling channel)"),
    (3, "LFE"),
    (4, "DSE (data stream)"),
    (5, "PCE (program config)"),
    (6, "FIL (fill)"),
    (7, "END"),
];

fn rate_name(index: u64) -> Option<String> {
    RATES.get(to_usize(index)).map(|r| format!("{r} Hz"))
}

fn channel_name(config: u64) -> &'static str {
    lookup(CHANNEL_CONFIG, config).unwrap_or("reserved")
}

/// The fields of an AudioSpecificConfig the summary needs.
#[derive(Clone, Copy, Debug, Default)]
pub struct Asc {
    pub object_type: u64,
    pub rate: Option<u32>,
    pub channels: u64,
    /// SBR or PS signalled explicitly, with the output rate.
    pub sbr_rate: Option<u32>,
    pub ps: bool,
    /// 960 instead of 1024 samples per frame.
    pub short_frames: bool,
}

impl Asc {
    /// "HE-AAC (AAC LC + SBR), 44100 Hz, stereo".
    pub fn summary(&self) -> String {
        let base = lookup(OBJECT_TYPE, self.object_type).unwrap_or("audio object type");
        let codec = match (self.sbr_rate.is_some(), self.ps) {
            (_, true) => format!("HE-AAC v2 ({base} + SBR + PS)"),
            (true, false) => format!("HE-AAC ({base} + SBR)"),
            _ => base.to_owned(),
        };
        let mut s = codec;
        if let Some(r) = self.sbr_rate.or(self.rate) {
            s.push_str(&format!(", {r} Hz"));
        }
        s.push_str(&format!(", {}", channel_name(self.channels)));
        s
    }
}

/// An audio object type: 5 bits, or 31 and 6 more.
fn object_type(b: &mut Bits<'_>, name: &'static str) -> Result<u64> {
    let start = b.pos();
    let first = b
        .read(5)
        .ok_or_else(|| Diagnostic::malformed("truncated audio object type"))?;
    let value = if first == 31 {
        b.read(6)
            .ok_or_else(|| Diagnostic::malformed("truncated audio object type"))?
            .saturating_add(32)
    } else {
        first
    };
    b.node(Node::new(name).span(b.span_of(start, b.pos())).value(
        crate::formats::util::sound::enumerated(value, 8, OBJECT_TYPE),
    ));
    Ok(value)
}

/// A sampling frequency: a 4-bit index, or 15 and a 24-bit rate.
fn sampling_rate(b: &mut Bits<'_>, name: &'static str) -> Result<Option<u32>> {
    let index = b
        .field(name, 4)
        .with(|v, n| match rate_name(v) {
            Some(r) => n.summary(r),
            None if v == 15 => n.summary("explicit"),
            None => n.diag(Diagnostic::malformed("reserved sampling frequency index")),
        })
        .emit()?;
    if index == 15 {
        let rate = b
            .field("Sampling frequency", 24)
            .with(|v, n| n.summary(format!("{v} Hz")))
            .emit()?;
        return Ok(u32::try_from(rate).ok());
    }
    Ok(RATES.get(to_usize(index)).copied())
}

/// AudioSpecificConfig (ISO/IEC 14496-3, 1.6.2.1), as far as the
/// GASpecificConfig of AAC object types.
pub fn audio_specific_config(b: &mut Bits<'_>) -> Result<Asc> {
    let mut asc = Asc {
        object_type: object_type(b, "Audio object type")?,
        ..Asc::default()
    };
    asc.rate = sampling_rate(b, "Sampling frequency index")?;
    asc.channels = b
        .field("Channel configuration", 4)
        .enumeration(CHANNEL_CONFIG)
        .emit()?;
    let mut core = asc.object_type;
    if matches!(asc.object_type, 5 | 29) {
        asc.ps = asc.object_type == 29;
        asc.sbr_rate = sampling_rate(b, "Extension sampling frequency index")?;
        core = object_type(b, "Core audio object type")?;
        if core == 22 {
            b.field("Extension channel configuration", 4)
                .enumeration(CHANNEL_CONFIG)
                .emit()?;
        }
        asc.object_type = core;
    }
    if matches!(core, 1..=4 | 6 | 7 | 17 | 19..=23) {
        asc.short_frames = b
            .field("Frame length flag", 1)
            .with(|v, n| {
                n.summary(if v == 0 {
                    "1024 samples"
                } else {
                    "960 samples"
                })
            })
            .emit()?
            != 0;
        if b.field("Depends on core coder", 1).flag().emit()? != 0 {
            b.field("Core coder delay", 14).emit()?;
        }
        let extension = b.field("Extension flag", 1).flag().emit()?;
        if asc.channels == 0 {
            program_config(b)?;
        }
        if matches!(core, 6 | 20) {
            b.field("Layer number", 3).emit()?;
        }
        if extension != 0 {
            if core == 22 {
                b.field("Number of sub-frames", 5).emit()?;
                b.field("Layer length", 11).emit()?;
            }
            if matches!(core, 17 | 19 | 20 | 23) {
                b.field("Section data resilience", 1).flag().emit()?;
                b.field("Scale factor data resilience", 1).flag().emit()?;
                b.field("Spectral data resilience", 1).flag().emit()?;
            }
            b.field("Extension flag 3", 1).emit()?;
        }
    }
    Ok(asc)
}

/// What a program config element says.
#[derive(Clone, Copy, Debug, Default)]
pub struct Pce {
    /// The profile (audio object type minus one).
    pub profile: u64,
    pub rate: Option<u32>,
    /// Full-bandwidth channels.
    pub channels: u64,
    pub lfe: u64,
}

/// A program config element (after its element ID).
pub fn program_config(b: &mut Bits<'_>) -> Result<Pce> {
    b.field("Element instance tag", 4).emit()?;
    let profile = b.field("Object type", 2).enumeration(PROFILE).emit()?;
    let rate = b
        .field("Sampling frequency index", 4)
        .with(|v, n| match rate_name(v) {
            Some(r) => n.summary(r),
            None => n,
        })
        .emit()?;
    let front = b.field("Front channel elements", 4).emit()?;
    let side = b.field("Side channel elements", 4).emit()?;
    let back = b.field("Back channel elements", 4).emit()?;
    let lfe = b.field("LFE channel elements", 2).emit()?;
    let assoc = b.field("Associated data elements", 3).emit()?;
    let cc = b.field("Coupling channel elements", 4).emit()?;
    if b.field("Mono mixdown present", 1).flag().emit()? != 0 {
        b.field("Mono mixdown element", 4).emit()?;
    }
    if b.field("Stereo mixdown present", 1).flag().emit()? != 0 {
        b.field("Stereo mixdown element", 4).emit()?;
    }
    if b.field("Matrix mixdown present", 1).flag().emit()? != 0 {
        b.field("Matrix mixdown index", 2).emit()?;
        b.field("Pseudo surround", 1).flag().emit()?;
    }
    let mut pce = Pce {
        profile,
        rate: RATES.get(to_usize(rate)).copied(),
        channels: 0,
        lfe,
    };
    for (count, name) in [
        (front, "Front element"),
        (side, "Side element"),
        (back, "Back element"),
    ] {
        for _ in 0..count {
            let start = b.pos();
            let cpe = b.read(1).unwrap_or(0);
            let tag = b.read(4).unwrap_or(0);
            pce.channels = pce.channels.saturating_add(cpe.saturating_add(1));
            b.node(
                Node::new(name)
                    .span(b.span_of(start, b.pos()))
                    .summary(format!(
                        "{} #{tag}",
                        if cpe != 0 {
                            "channel pair"
                        } else {
                            "single channel"
                        }
                    )),
            );
        }
    }
    for _ in 0..lfe {
        b.field("LFE element tag", 4).emit()?;
    }
    for _ in 0..assoc {
        b.field("Associated data element tag", 4).emit()?;
    }
    for _ in 0..cc {
        b.field("Coupling element independently switched", 1)
            .flag()
            .emit()?;
        b.field("Coupling element tag", 4).emit()?;
    }
    // Byte alignment, then the comment.
    let aligned = b.pos().div_ceil(8).saturating_mul(8);
    b.skip(aligned.saturating_sub(b.pos()));
    let len = b.field("Comment length", 8).emit()?;
    if len > 0 {
        b.bytes("Comment", len).emit()?;
    }
    Ok(pce)
}

/// The first syntactic element of a raw data block: "CPE (channel pair)
/// #0".
fn first_element(d: &[u8]) -> Option<String> {
    let b = *d.first()?;
    let id = b >> 5;
    let name = lookup(ELEMENT, id.into())?;
    // FIL has a count where the others have an instance tag.
    Some(if id >= 6 {
        name.to_owned()
    } else {
        format!("{name} #{}", (b >> 1) & 0xf)
    })
}

/// A raw data block node; a program config element in it is decoded.
fn raw_block(span: Span, head: &[u8]) -> Node {
    let mut node = Node::new("Raw data block")
        .span(span)
        .desc("Syntactic elements (channel elements, fill, end); the first is named");
    if let Some(first) = first_element(head) {
        node = node.summary(format!("starts with {first}, {}", human_size(span.len)));
    }
    if head.first().is_some_and(|b| b >> 5 == 5) {
        node = node.lazy(expand_pce, span);
    }
    node
}

async fn expand_pce(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 512)).await?;
    let mut b = Bits::emitting(&cx, &data, span);
    b.field("Element ID", 3).enumeration(ELEMENT).emit()?;
    program_config(&mut b)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ADTS

/// Frame length and description of the ADTS header at the start of `d`.
fn parse_adts(d: &[u8]) -> Option<(u64, String)> {
    let h = d.get(..7)?;
    let b = |i: usize| h.get(i).copied().unwrap_or(0);
    if b(0) != 0xff || b(1) & 0xf6 != 0xf0 {
        return None;
    }
    let profile = b(2) >> 6;
    let rate = *RATES.get(usize::from((b(2) >> 2) & 0xf))?;
    let channels = ((b(2) & 1) << 2) | (b(3) >> 6);
    let len = (u64::from(b(3) & 3) << 11) | (u64::from(b(4)) << 3) | u64::from(b(5) >> 5);
    let header = adts_header(d);
    if len < header {
        return None;
    }
    let blocks = (b(6) & 3).saturating_add(1);
    let mut s = format!(
        "AAC {}, {rate} Hz, {}",
        lookup(PROFILE, profile.into()).unwrap_or("?"),
        channel_name(channels.into())
    );
    if blocks > 1 {
        s.push_str(&format!(", {blocks} raw data blocks"));
    }
    Some((len, s))
}

/// The header length: 7 bytes, plus the CRC and raw data block positions.
fn adts_header(d: &[u8]) -> u64 {
    if d.get(1).is_some_and(|b| b & 1 == 0) {
        let blocks = d.get(6).map_or(0, |b| u64::from(b & 3));
        9u64.saturating_add(blocks.saturating_mul(2))
    } else {
        7
    }
}

fn adts_layout(b: &mut Bits<'_>) -> Result<()> {
    b.field("Sync word", 12).hex().emit()?;
    b.field("MPEG version", 1)
        .with(|v, n| n.summary(if v == 0 { "MPEG-4" } else { "MPEG-2" }))
        .emit()?;
    b.field("Layer", 2)
        .with(|v, n| {
            if v == 0 {
                n
            } else {
                n.diag(Diagnostic::malformed("layer must be 0"))
            }
        })
        .emit()?;
    let absent = b
        .field("Protection absent", 1)
        .with(|v, n| n.summary(if v == 0 { "CRC follows" } else { "no CRC" }))
        .emit()?;
    b.field("Profile", 2)
        .enumeration(PROFILE)
        .desc("The audio object type minus one")
        .emit()?;
    b.field("Sampling frequency index", 4)
        .with(|v, n| match rate_name(v) {
            Some(r) => n.summary(r),
            None => n.diag(Diagnostic::malformed("reserved sampling frequency index")),
        })
        .emit()?;
    b.field("Private", 1).flag().emit()?;
    b.field("Channel configuration", 3)
        .enumeration(CHANNEL_CONFIG)
        .emit()?;
    b.field("Original/copy", 1).flag().emit()?;
    b.field("Home", 1).flag().emit()?;
    b.field("Copyright ID bit", 1).emit()?;
    b.field("Copyright ID start", 1).flag().emit()?;
    b.field("Frame length", 13)
        .desc("Including the header")
        .emit()?;
    b.field("Buffer fullness", 11)
        .with(|v, n| {
            if v == 0x7ff {
                n.summary("variable bitrate")
            } else {
                n.summary(format!("{} bytes", v.saturating_mul(4)))
            }
        })
        .desc("Bit reservoir state, in 32-bit words")
        .emit()?;
    let blocks = b
        .field("Raw data blocks − 1", 2)
        .with(|v, n| {
            n.summary(format!(
                "{} of 1024 samples",
                crate::formats::util::arcutil::count(v.saturating_add(1), "block", "blocks")
            ))
        })
        .emit()?;
    if absent == 0 {
        for i in 0..blocks {
            b.field("Raw data block position", 16)
                .with(|v, n| n.summary(format!("block {}: byte {v}", i.saturating_add(1))))
                .emit()?;
        }
        b.field("CRC", 16).hex().emit()?;
    }
    Ok(())
}

static ADTS: FrameSyntax = FrameSyntax {
    peek: 16,
    sync: &[0xff],
    parse: parse_adts,
    header: adts_header,
    layout: adts_layout,
    expand: Some(crate::expander!(adts_frame: FrameRef)),
};

async fn adts_frame(cx: Cx, f: FrameRef) -> Result<()> {
    cx.emit(bits_node("Header", f.header, adts_layout, false));
    let payload = f.span.tail(f.header.len);
    let head = cx.read_avail(payload.sub(0, 1)).await?;
    let blocks = cx
        .read_avail(f.span.sub(6, 1))
        .await?
        .first()
        .map_or(1, |b| (b & 3).saturating_add(1));
    if blocks == 1 {
        cx.emit(raw_block(payload, &head));
    } else {
        cx.emit(
            Node::new("Raw data blocks")
                .span(payload)
                .summary(format!("{blocks} blocks, {}", human_size(payload.len))),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LOAS / LATM

/// Frame length and description of the LOAS AudioSyncStream header at the
/// start of `d`.
fn parse_loas(d: &[u8]) -> Option<(u64, String)> {
    let w = (u32::from(*d.first()?) << 16) | (u32::from(*d.get(1)?) << 8) | u32::from(*d.get(2)?);
    if w >> 13 != 0x2b7 {
        return None;
    }
    let len = u64::from(w & 0x1fff);
    if len == 0 {
        return None;
    }
    // useSameStreamMux: the configuration is in an earlier frame.
    let same = d.get(3).is_some_and(|b| b & 0x80 != 0);
    let what = if same {
        "LATM, same configuration".to_owned()
    } else {
        latm_config(d.get(3..).unwrap_or_default()).map_or_else(
            || "LATM, new configuration".to_owned(),
            |a| format!("LATM: {}", a.summary()),
        )
    };
    Some((len.saturating_add(3), what))
}

fn loas_header(_: &[u8]) -> u64 {
    3
}

fn loas_layout(b: &mut Bits<'_>) -> Result<()> {
    b.field("Sync word", 11).hex().emit()?;
    b.field("Mux element length", 13)
        .desc("Bytes of AudioMuxElement after this header")
        .emit()?;
    Ok(())
}

/// The AudioSpecificConfig in the StreamMuxConfig of an AudioMuxElement
/// (`d` starts at the element), silently.
fn latm_config(d: &[u8]) -> Option<Asc> {
    let span = Span::new(crate::span::SourceId::ZEROS, 0, to_u64(d.len()));
    let mut b = Bits::new(d, span);
    if b.read(1)? != 0 {
        return None;
    }
    stream_mux_config(&mut b).ok().flatten()
}

/// StreamMuxConfig (ISO/IEC 14496-3, 1.7.3.1) up to the first layer's
/// AudioSpecificConfig. `None` for versions whose ASC is length-prefixed in
/// a form not decoded here.
fn stream_mux_config(b: &mut Bits<'_>) -> Result<Option<Asc>> {
    let version = b.field("Audio mux version", 1).emit()?;
    if version != 0 {
        let a = b.field("Audio mux version A", 1).emit()?;
        if a != 0 {
            return Ok(None);
        }
        latm_value(b, "Tara buffer fullness")?;
    }
    b.field("All streams same time framing", 1).flag().emit()?;
    b.field("Sub-frames − 1", 6).emit()?;
    b.field("Programs − 1", 4).emit()?;
    b.field("Layers − 1", 3).emit()?;
    if version != 0 {
        latm_value(b, "ASC length")?;
    }
    // Decode the AudioSpecificConfig ahead; it is shown as a group.
    let start = b.pos();
    let mut ahead = b.silent();
    let asc = audio_specific_config(&mut ahead)?;
    let end = ahead.pos();
    b.node(
        Node::new("Audio specific config")
            .span(b.span_of(start, end))
            .summary(asc.summary())
            .lazy(expand_asc, (b.span(), start)),
    );
    b.seek(end);
    let frame_type = b
        .field("Frame length type", 3)
        .with(|v, n| {
            n.summary(match v {
                0 => "variable (payload length info)",
                1 => "fixed",
                _ => "CELP/HVXC",
            })
        })
        .emit()?;
    match frame_type {
        0 => {
            b.field("LATM buffer fullness", 8).emit()?;
        }
        1 => {
            b.field("Frame length", 9).emit()?;
        }
        _ => {}
    }
    Ok(Some(asc))
}

async fn expand_asc(cx: Cx, (span, start): (Span, u64)) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 256)).await?;
    let mut b = Bits::emitting(&cx, &data, span.sub(0, 256));
    b.seek(start);
    audio_specific_config(&mut b)?;
    Ok(())
}

/// LatmGetValue: 2 bits of byte count, then that many bytes plus one.
fn latm_value(b: &mut Bits<'_>, name: &'static str) -> Result<u64> {
    let bytes = b.read(2).unwrap_or(0).saturating_add(1);
    let start = b.pos();
    let v = b
        .read(u32::try_from(bytes.saturating_mul(8)).unwrap_or(8))
        .ok_or_else(|| Diagnostic::malformed("truncated LATM value"))?;
    b.node(
        Node::new(name)
            .span(b.span_of(start, b.pos()))
            .value(crate::formats::util::sound::uint(v, 32)),
    );
    Ok(v)
}

static LOAS: FrameSyntax = FrameSyntax {
    peek: 32,
    sync: &[0x56],
    parse: parse_loas,
    header: loas_header,
    layout: loas_layout,
    expand: Some(crate::expander!(loas_frame: FrameRef)),
};

async fn loas_frame(cx: Cx, f: FrameRef) -> Result<()> {
    cx.emit(bits_node("Header", f.header, loas_layout, false));
    let element = f.span.tail(3);
    let head = cx.read_avail(element.sub(0, 1)).await?;
    let same = head.first().is_some_and(|b| b & 0x80 != 0);
    let mut node = Node::new("Audio mux element").span(element);
    if same {
        node = node.summary("same stream mux configuration as before, payload");
    } else {
        node = node
            .summary("new stream mux configuration, payload")
            .lazy(expand_mux, element);
    }
    cx.emit(node);
    Ok(())
}

async fn expand_mux(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 256)).await?;
    let mut b = Bits::emitting(&cx, &data, span);
    b.field("Use same stream mux", 1).flag().emit()?;
    stream_mux_config(&mut b)?;
    let end = b.pos();
    cx.emit(
        Node::new("Payload")
            .span(span.tail(end.div_ceil(8)))
            .desc("PayloadLengthInfo and the raw data blocks (not byte-aligned)"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// ADIF

/// What the summary needs from an ADIF header.
#[derive(Default)]
struct Adif {
    vbr: bool,
    bitrate: u64,
    /// The first program's configuration.
    pce: Pce,
    /// Bits in the header.
    bits: u64,
}

fn adif_header(b: &mut Bits<'_>) -> Result<Adif> {
    b.bytes("ID", 4)
        .with(|_, n| n.value(crate::formats::util::sound::text("ADIF")))
        .emit()?;
    if b.field("Copyright ID present", 1).flag().emit()? != 0 {
        b.field("Copyright ID", 64).hex().emit()?;
        b.field("Copyright ID (continued)", 8).hex().emit()?;
    }
    b.field("Original/copy", 1).flag().emit()?;
    b.field("Home", 1).flag().emit()?;
    let mut a = Adif {
        vbr: b
            .field("Bitstream type", 1)
            .with(|v, n| {
                n.summary(if v == 0 {
                    "constant rate"
                } else {
                    "variable rate"
                })
            })
            .emit()?
            != 0,
        ..Adif::default()
    };
    a.bitrate = b
        .field("Bitrate", 23)
        .with(|v, n| n.summary(format!("{v} bit/s")))
        .desc("Constant rate: the bitrate; variable rate: the peak")
        .emit()?;
    let count = b.field("Program config elements − 1", 4).emit()?;
    for i in 0..=count {
        if !a.vbr {
            b.field("ADIF buffer fullness", 20).emit()?;
        }
        let pce = program_config(b)?;
        if i == 0 {
            a.pce = pce;
        }
    }
    a.bits = b.pos();
    Ok(a)
}

async fn dissect_adif(cx: &Cx, stream: Span, title: &str) -> Result<()> {
    let data = cx.read_avail(stream.sub(0, 4096)).await?;
    let mut silent = Bits::new(&data, stream.sub(0, to_u64(data.len())));
    let header = adif_header(&mut silent);
    let header_len = header.as_ref().map_or(4, |a| a.bits.div_ceil(8));
    let header_span = stream.sub(0, header_len);
    let node = Node::new("ADIF header")
        .span(header_span)
        .lazy(expand_adif, header_span);
    let a = match header {
        Ok(a) => a,
        Err(e) => {
            cx.emit(node.diag(e));
            return Ok(());
        }
    };
    let channels = if a.pce.lfe > 0 {
        format!("{}.{} ch", a.pce.channels, a.pce.lfe)
    } else {
        format!("{} ch", a.pce.channels)
    };
    let mut line = format!(
        "AAC {} (ADIF), {}{channels}",
        lookup(PROFILE, a.pce.profile).unwrap_or("?"),
        a.pce.rate.map(|r| format!("{r} Hz, ")).unwrap_or_default()
    );
    if a.vbr {
        line.push_str(&format!(", VBR (peak {} kbps)", a.bitrate / 1000));
    } else if a.bitrate > 0 {
        let seconds = stream.len as f64 * 8.0 / a.bitrate as f64;
        line.push_str(&format!(
            ", {} kbps, {}",
            a.bitrate / 1000,
            duration(seconds)
        ));
    }
    cx.annotate(format!("{line}{title}"));
    cx.emit(node.summary(format!(
        "{}, {} bit/s{}, {channels}",
        if a.vbr {
            "variable rate"
        } else {
            "constant rate"
        },
        a.bitrate,
        if a.vbr { " peak" } else { "" }
    )));
    let raw = stream.tail(header_len);
    let head = cx.read_avail(raw.sub(0, 1)).await?;
    let mut blocks = Node::new("Raw data blocks")
        .span(raw)
        .summary(human_size(raw.len))
        .desc("Unframed: block boundaries are only found by decoding");
    if let Some(first) = first_element(&head) {
        blocks = blocks.summary(format!("{}, starting with {first}", human_size(raw.len)));
    }
    cx.emit(blocks);
    Ok(())
}

async fn expand_adif(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let mut b = Bits::emitting(&cx, &data, span);
    adif_header(&mut b)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// File

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 10)).await?;
    let mut start = 0u64;
    let mut titles = Vec::new();
    if let Some(len) = id3::v2_len(&head) {
        let span = file.sub(0, len);
        cx.emit(id3::tag_node(&cx, input, span).await);
        titles.extend(id3::title(&cx, span).await);
        start = len;
    }
    let trailing = id3::trailing_tags(&cx, input, file, start).await?;
    titles.extend(trailing.titles.iter().cloned());
    let stream = file.sub(start, trailing.end.saturating_sub(start));
    let window = cx.read_avail(stream.sub(0, 0x10000)).await?;
    let title = titles
        .first()
        .map(|t| format!(" — {t}"))
        .unwrap_or_default();
    if window.starts_with(b"ADIF") {
        dissect_adif(&cx, stream, &title).await?;
    } else if let Some((_, describe)) = parse_adts(&window) {
        let frames = estimate_frames(&window, stream.len, &ADTS);
        let b2 = window.get(2).copied().unwrap_or(0);
        let rate = RATES
            .get(usize::from((b2 >> 2) & 0xf))
            .copied()
            .unwrap_or(0);
        let blocks = window
            .get(6)
            .map_or(1.0, |b| f64::from((b & 3).saturating_add(1)));
        let seconds = if rate > 0 {
            frames * blocks * 1024.0 / f64::from(rate)
        } else {
            0.0
        };
        let kbps = if seconds > 0.0 {
            stream.len as f64 * 8.0 / seconds / 1000.0
        } else {
            0.0
        };
        cx.annotate(format!(
            "{describe} (ADTS), {kbps:.0} kbps, {}{title}",
            duration(seconds)
        ));
        cx.emit(frames_node(stream, &ADTS));
    } else if let Some((_, describe)) = parse_loas(&window) {
        let frames = estimate_frames(&window, stream.len, &LOAS);
        let asc = latm_config(window.get(3..).unwrap_or_default());
        let rate = asc.and_then(|a| a.rate).unwrap_or(0);
        let samples = if asc.is_some_and(|a| a.short_frames) {
            960.0
        } else {
            1024.0
        };
        let seconds = if rate > 0 {
            frames * samples / f64::from(rate)
        } else {
            0.0
        };
        let kbps = if seconds > 0.0 {
            stream.len as f64 * 8.0 / seconds / 1000.0
        } else {
            0.0
        };
        let what = asc.map_or(describe, |a| format!("{} (LOAS/LATM)", a.summary()));
        cx.annotate(format!(
            "{what}, {kbps:.0} kbps, {}{title}",
            duration(seconds)
        ));
        cx.emit(frames_node(stream, &LOAS));
    } else {
        cx.emit(frames_node(stream, &ADTS));
    }
    for node in trailing.nodes {
        cx.emit(node);
    }
    Ok(())
}
