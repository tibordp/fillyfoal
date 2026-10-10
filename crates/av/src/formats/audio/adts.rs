//! Raw AAC streams: ADTS (`.aac`: each frame starts with a 7-byte header,
//! 9 with CRC, giving the profile, sample rate, channel configuration and
//! frame length), ADIF (one header for the whole stream, then unframed raw
//! data blocks) and LOAS/LATM (frames with an 11-bit sync word whose
//! payload starts with a StreamMuxConfig carrying an AudioSpecificConfig).
//! An ID3v2 tag may precede the stream.
//!
//! The AudioSpecificConfig and program config element are decoded by
//! `vidutil::audio`, as wherever else MPEG-4 audio is configured (MP4
//! `esds`, FLV, Matroska, CAF).

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::sound::{
    Bits, FrameRef, FrameSyntax, bits_node, duration, estimate_frames, frames_node,
};
use crate::formats::util::vidutil::audio::{
    self as aac, AAC_PROFILES, AAC_SAMPLE_RATES, AscInfo, CHANNEL_CONFIGS, PceInfo,
};
use crate::formats::util::vidutil::bitwalk::Walker;
use crate::formats::util::vidutil::detached;
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
    AAC_SAMPLE_RATES
        .get(to_usize(index))
        .map(|r| format!("{r} Hz"))
}

fn channel_name(config: u64) -> &'static str {
    lookup(CHANNEL_CONFIGS, config).unwrap_or("reserved")
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
    let rate = *AAC_SAMPLE_RATES.get(usize::from((b(2) >> 2) & 0xf))?;
    let channels = ((b(2) & 1) << 2) | (b(3) >> 6);
    let len = (u64::from(b(3) & 3) << 11) | (u64::from(b(4)) << 3) | u64::from(b(5) >> 5);
    let header = adts_header(d);
    if len < header {
        return None;
    }
    let blocks = (b(6) & 3).saturating_add(1);
    let mut s = format!(
        "AAC {}, {rate} Hz, {}",
        lookup(AAC_PROFILES, profile.into()).unwrap_or("?"),
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
        .enumeration(AAC_PROFILES)
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
        .enumeration(CHANNEL_CONFIGS)
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
            |a| format!("LATM: {}", a.describe()),
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

// ---------------------------------------------------------------------------
// ADIF

async fn dissect_adif(cx: &Cx, stream: Span, title: &str) -> Result<()> {
    let data = cx.read_avail(stream.sub(0, 4096)).await?;
    let mut silent = Walker::new(&data, stream.sub(0, to_u64(data.len())), false, false);
    let header = adif_header(&mut silent);
    let header_len = header.as_ref().map_or(4, |a| a.bits.div_ceil(8));
    let header_span = stream.sub(0, header_len);
    let node = Node::new("ADIF header")
        .span(header_span)
        .lazy(expand_adif, header_span);
    let Some(a) = header else {
        cx.emit(node.diag(Diagnostic::malformed(
            "the ADIF header ends early or holds a value out of range",
        )));
        return Ok(());
    };
    let channels = if a.pce.lfe > 0 {
        format!("{}.{} ch", a.pce.channels, a.pce.lfe)
    } else {
        format!("{} ch", a.pce.channels)
    };
    let mut line = format!(
        "AAC {} (ADIF), {}{channels}",
        lookup(AAC_PROFILES, a.pce.profile).unwrap_or("?"),
        a.pce
            .sample_rate
            .map(|r| format!("{r} Hz, "))
            .unwrap_or_default()
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
        let rate = AAC_SAMPLE_RATES
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
        let rate = asc.map_or(0, |a| a.sample_rate);
        // Samples per frame at the core rate (1024 unless signalled).
        let samples = asc
            .map(|a| a.frame_length)
            .filter(|&n| n > 0)
            .map_or(1024.0, |n| n as f64);
        let seconds = if rate > 0 {
            frames * samples / rate as f64
        } else {
            0.0
        };
        let kbps = if seconds > 0.0 {
            stream.len as f64 * 8.0 / seconds / 1000.0
        } else {
            0.0
        };
        let what = asc.map_or(describe, |a| format!("{} (LOAS/LATM)", a.describe()));
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

/// A raw data block that starts with a program config element, decoded.
async fn expand_pce(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 512)).await?;
    let mut w = Walker::new(&data, span.sub(0, to_u64(data.len())), false, true);
    let ok = (|| {
        w.en("Element ID", 3, ELEMENT)?;
        aac::program_config_element(&mut w, 0)
    })()
    .is_some();
    for node in w.finish(ok) {
        cx.emit(node);
    }
    Ok(())
}

/// The AudioSpecificConfig in the StreamMuxConfig of an AudioMuxElement
/// (`d` starts at the element), silently.
fn latm_config(d: &[u8]) -> Option<AscInfo> {
    let d = d.get(..512).unwrap_or(d);
    let mut w = Walker::new(d, detached(d.len()), false, false);
    if w.read(1)? != 0 {
        return None;
    }
    stream_mux_config(&mut w).flatten()
}

/// StreamMuxConfig (ISO/IEC 14496-3, 1.7.3.1) up to the first layer's
/// AudioSpecificConfig and frame length type. `Some(None)` for versions
/// whose configuration is not decoded here; `None` if it ends early.
fn stream_mux_config(w: &mut Walker) -> Option<Option<AscInfo>> {
    let version = w.u("Audio mux version", 1)?;
    if version != 0 {
        let a = w.u("Audio mux version A", 1)?;
        if a != 0 {
            return Some(None);
        }
        latm_value(w, "Tara buffer fullness")?;
    }
    w.flag("All streams same time framing")?;
    w.u("Sub-frames − 1", 6)?;
    w.u("Programs − 1", 4)?;
    w.u("Layers − 1", 3)?;
    if version != 0 {
        latm_value(w, "ASC length")?;
    }
    w.begin("AudioSpecificConfig");
    let asc = aac::audio_specific_config(w)?;
    w.end_summary(|| asc.describe());
    let frame_type = w.u("Frame length type", 3)?;
    w.summary(|| {
        (match frame_type {
            0 => "variable (payload length info)",
            1 => "fixed",
            _ => "CELP/HVXC",
        })
        .to_owned()
    });
    match frame_type {
        0 => {
            w.u("LATM buffer fullness", 8)?;
        }
        1 => {
            w.u("Frame length", 9)?;
        }
        _ => {}
    }
    Some(Some(asc))
}

/// LatmGetValue: 2 bits of byte count, then that many bytes plus one.
fn latm_value(w: &mut Walker, name: &'static str) -> Option<u64> {
    let bytes = w.read(2)?.saturating_add(1);
    w.u(name, u32::try_from(bytes.saturating_mul(8)).ok()?)
}

async fn expand_mux(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 512)).await?;
    let mut w = Walker::new(&data, span.sub(0, to_u64(data.len())), false, true);
    let ok = (|| {
        w.flag("Use same stream mux")?;
        stream_mux_config(&mut w)
    })()
    .is_some();
    let end = to_u64(w.pos());
    for node in w.finish(ok) {
        cx.emit(node);
    }
    cx.emit(
        Node::new("Payload")
            .span(span.tail(end.div_ceil(8)))
            .desc("PayloadLengthInfo and the raw data blocks (not byte-aligned)"),
    );
    Ok(())
}

/// What the summary needs from an ADIF header.
#[derive(Default)]
struct Adif {
    vbr: bool,
    bitrate: u64,
    /// The first program's configuration.
    pce: PceInfo,
    /// Bits in the header.
    bits: u64,
}

fn adif_header(w: &mut Walker) -> Option<Adif> {
    let start = w.pos();
    let id = w.read_bytes(4)?;
    w.text("ID", start, String::from_utf8_lossy(&id).into_owned());
    if w.flag("Copyright ID present")? {
        w.x("Copyright ID", 64)?;
        w.x("Copyright ID (continued)", 8)?;
    }
    w.flag("Original/copy")?;
    w.flag("Home")?;
    let vbr = w.u("Bitstream type", 1)? != 0;
    w.summary(|| {
        (if vbr {
            "variable rate"
        } else {
            "constant rate"
        })
        .to_owned()
    });
    let bitrate = w.u("Bitrate", 23)?;
    w.summary(|| format!("{bitrate} bit/s"));
    w.desc("Constant rate: the bitrate; variable rate: the peak");
    let count = w.u("Program config elements − 1", 4)?;
    let mut a = Adif {
        vbr,
        bitrate,
        ..Adif::default()
    };
    for i in 0..=count {
        if !vbr {
            w.u("ADIF buffer fullness", 20)?;
        }
        let pce = aac::program_config_element(w, 0)?;
        if i == 0 {
            a.pce = pce;
        }
    }
    a.bits = to_u64(w.pos());
    Some(a)
}

async fn expand_adif(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let mut w = Walker::new(&data, span.sub(0, to_u64(data.len())), false, true);
    let ok = adif_header(&mut w).is_some();
    for node in w.finish(ok) {
        cx.emit(node);
    }
    Ok(())
}
