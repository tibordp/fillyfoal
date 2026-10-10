//! Flash Video (FLV), including Enhanced RTMP/FLV (FourCC codecs).
//!
//! A 9-byte header, then tags `type, size (24), timestamp (24+8), stream
//! id (24), data, previous tag size`. Tags are listed in pages.
//!
//! - Audio tags: format, rate, size, channels; AAC packets with their
//!   AudioSpecificConfig; enhanced audio (Opus, FLAC, AC-3, E-AC-3, MP3,
//!   AAC by FourCC) with sequence headers and multichannel configs.
//! - Video tags: frame type and codec; AVC/HEVC packets with composition
//!   time, the decoder configuration record (parameter sets decoded) and
//!   the NAL units of each frame (slice headers decoded with the parameter
//!   sets seen before); Sorenson H.263 picture headers, VP6 adjustments;
//!   enhanced video (`avc1`, `hvc1`, `av01`, `vp09`) with their
//!   configuration records, AV1 OBUs and VP9 frame headers.
//! - Script tags: AMF0 values (and AMF3 inside them), usually `onMetaData`
//!   with duration, size, frame rate and the keyframe index.
//! - Previous-tag-size fields are checked.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::util::fmt::plural;
use crate::formats::util::vidutil::bitwalk::Walker;
use crate::formats::util::vidutil::nal::{self, NalCodec, group};
use crate::formats::util::vidutil::{self, ParamSets, enumerated, seconds_ms, text, uint, vp9};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "flv",
    title: "Flash Video",
    extensions: &["flv", "f4v_"],
    mime: "video/x-flv",
    probe: Probe::Custom(|h| {
        h.starts_with(b"FLV\x01") && u32_be(h.data, 5).is_some_and(|o| (9..=1024).contains(&o))
    }),
    dissect: crate::expander!(dissect: Input),
};

const HEADER_FLAGS: FlagTable = &[flag(0x04, "AUDIO"), flag(0x01, "VIDEO")];

const TAG_TYPES: EnumTable = &[(8, "audio"), (9, "video"), (18, "script data")];

const SOUND_FORMATS: EnumTable = &[
    (0, "PCM (platform endian)"),
    (1, "ADPCM"),
    (2, "MP3"),
    (3, "PCM (little endian)"),
    (4, "Nellymoser 16 kHz mono"),
    (5, "Nellymoser 8 kHz mono"),
    (6, "Nellymoser"),
    (7, "G.711 A-law"),
    (8, "G.711 µ-law"),
    (9, "enhanced (FourCC)"),
    (10, "AAC"),
    (11, "Speex"),
    (14, "MP3 8 kHz"),
    (15, "device-specific"),
];

const VIDEO_CODECS: EnumTable = &[
    (1, "JPEG"),
    (2, "Sorenson H.263"),
    (3, "Screen video"),
    (4, "On2 VP6"),
    (5, "On2 VP6 with alpha"),
    (6, "Screen video v2"),
    (7, "H.264"),
    (12, "HEVC"),
    (13, "AV1"),
];

const FRAME_TYPES: EnumTable = &[
    (1, "keyframe"),
    (2, "inter frame"),
    (3, "disposable inter frame"),
    (4, "generated keyframe"),
    (5, "video info/command"),
];

const AVC_PACKET: EnumTable = &[(0, "sequence header"), (1, "NALU"), (2, "end of sequence")];
const AAC_PACKET: EnumTable = &[(0, "sequence header"), (1, "raw")];
const SOUND_RATES: [&str; 4] = ["5.5 kHz", "11 kHz", "22 kHz", "44 kHz"];

const VIDEO_PACKET_TYPES: EnumTable = &[
    (0, "sequence start"),
    (1, "coded frames"),
    (2, "sequence end"),
    (3, "coded frames (no composition time)"),
    (4, "metadata"),
    (5, "MPEG-2 TS sequence start"),
    (6, "multitrack"),
    (7, "modifier extension"),
];

const AUDIO_PACKET_TYPES: EnumTable = &[
    (0, "sequence start"),
    (1, "coded frames"),
    (2, "sequence end"),
    (4, "multichannel config"),
    (5, "multitrack"),
    (7, "modifier extension"),
];

const H263_SIZES: [(u64, u64); 7] = [
    (0, 0),
    (0, 0),
    (352, 288),
    (176, 144),
    (128, 96),
    (320, 240),
    (160, 120),
];

record! {
    pub struct Header {
        signature: ascii[3] "Signature",
        version: u8 "Version",
        flags: u8 "Flags" .flags(HEADER_FLAGS),
        offset: u32 "Data offset",
    }
}

/// Decoder state carried from the configuration record to later frames.
#[derive(Clone, Debug, Default)]
struct Codec {
    ps: Arc<ParamSets>,
    hevc: bool,
    length_size: u64,
    seq: Option<vidutil::av1::SeqInfo>,
}

#[derive(Clone, Debug)]
struct Tag {
    input: Input,
    span: Span,
    kind: u8,
    size: u64,
    codec: Arc<Codec>,
}

impl Tag {
    fn data(&self) -> Span {
        self.span.sub(11, self.size)
    }
}

#[derive(Clone, Debug)]
struct Walk {
    pos: u64,
    codec: Arc<Codec>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = crate::fields::parse(&cx, file.sub(0, 9), BE, &(), Header::layout).await?;
    let start = u64::from(header.offset);
    let summary = Summary::scan(&cx, file, start).await?;
    cx.annotate(summary.describe());
    let mut walk = match cx.resume::<Walk>() {
        Some(w) => w,
        None => {
            cx.emit(Header::node("Header", file.sub(0, 9), BE));
            if start > 9 {
                cx.emit(Node::new("Header padding").span(file.sub(9, start.saturating_sub(9))));
            }
            let d = cx.read_avail(file.sub(start, 4)).await?;
            let mut node = uint(
                "Previous tag size",
                file.sub(start, 4),
                u32_be(&d, 0).unwrap_or(0).into(),
                32,
            );
            if u32_be(&d, 0).is_some_and(|v| v != 0) {
                node = node.diag(Diagnostic::warning("should be 0"));
            }
            cx.emit(node);
            Walk {
                pos: start.saturating_add(4),
                codec: Arc::new(Codec {
                    length_size: 4,
                    ..Codec::default()
                }),
            }
        }
    };
    while walk.pos < file.len {
        let state = walk.clone();
        cx.mark(move || state);
        let pos = walk.pos;
        let head = cx.read_avail(file.sub(pos, 16)).await?;
        if head.len() < 11 {
            cx.push(Node::new("Trailing bytes").span(file.tail(pos)))
                .await;
            break;
        }
        let kind = head.first().copied().unwrap_or(0) & 0x1f;
        let size = u64::from(crate::bytes::u24_be(&head, 1).unwrap_or(0));
        let ts = crate::bytes::u24_be(&head, 4).unwrap_or(0)
            | (u32::from(head.get(7).copied().unwrap_or(0)) << 24);
        let total = size.saturating_add(15);
        let tag = Tag {
            input,
            span: file.sub(pos, total),
            kind,
            size,
            codec: walk.codec.clone(),
        };
        let body = cx.read_avail(tag.data().sub(0, 16)).await?;
        if kind == 9
            && let Some(next) = update_codec(&cx, &tag, &body).await?
        {
            walk.codec = Arc::new(next);
        }
        let name = crate::value::lookup(TAG_TYPES, kind.into())
            .map_or_else(|| format!("Tag type {kind}"), capitalise);
        let mut node = Node::new(name)
            .span(tag.span)
            .summary(tag_summary(kind, ts, size, &body))
            .lazy(expand_tag, tag.clone());
        if tag.span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(file.source, tag.span.offset, total),
                tag.span.len,
            ));
        }
        cx.progress_in(file, file.offset.saturating_add(pos));
        cx.push(node).await;
        walk.pos = pos.saturating_add(total);
    }
    Ok(())
}

/// The codec state after a video tag that carries a configuration record.
async fn update_codec(cx: &Cx, tag: &Tag, body: &[u8]) -> Result<Option<Codec>> {
    let b = body.first().copied().unwrap_or(0);
    let (config_at, kind) = if b & 0x80 != 0 {
        if b & 15 != 0 {
            return Ok(None);
        }
        (5u64, body.get(1..5).unwrap_or_default().to_vec())
    } else if matches!(b & 15, 7 | 12) && body.get(1) == Some(&0) {
        (
            5u64,
            if b & 15 == 7 {
                b"avc1".to_vec()
            } else {
                b"hvc1".to_vec()
            },
        )
    } else {
        return Ok(None);
    };
    let config = tag.data().tail(config_at);
    let d = vidutil::read_small(cx, config, 0x4000).await?;
    let mut next = (*tag.codec).clone();
    match kind.as_slice() {
        b"avc1" | b"hvc1" => {
            let hevc = kind == b"hvc1";
            let mut ps = ParamSets::default();
            collect_param_sets(&d, hevc, &mut ps);
            next.ps = Arc::new(ps);
            next.hevc = hevc;
            next.length_size = if hevc {
                u64::from(d.get(21).copied().unwrap_or(3) & 3).saturating_add(1)
            } else {
                u64::from(d.get(4).copied().unwrap_or(3) & 3).saturating_add(1)
            };
        }
        b"av01" => {
            let mut w = Walker::new(d.get(4..).unwrap_or_default(), config, false, false);
            let mut seq = None;
            let _ = nal::obus(&mut w, &mut seq);
            next.seq = seq;
        }
        _ => return Ok(None),
    }
    Ok(Some(next))
}

/// The SPS and PPS of an `avcC`/`hvcC` record.
fn collect_param_sets(d: &[u8], hevc: bool, ps: &mut ParamSets) {
    let codec = if hevc { NalCodec::Hevc } else { NalCodec::Avc };
    let detached = Span::new(crate::span::SourceId::default_host(), 0, 0);
    let mut units: Vec<&[u8]> = Vec::new();
    if hevc {
        let arrays = d.get(22).copied().unwrap_or(0);
        let mut at = 23usize;
        for _ in 0..arrays {
            let n = u16_be(d, at.saturating_add(1)).unwrap_or(0);
            at = at.saturating_add(3);
            for _ in 0..n {
                let len = usize::from(u16_be(d, at).unwrap_or(0));
                let start = at.saturating_add(2);
                if let Some(u) = d.get(start..start.saturating_add(len)) {
                    units.push(u);
                }
                at = start.saturating_add(len);
            }
        }
    } else {
        let mut at = 5usize;
        for count_mask in [0x1fu8, 0xff] {
            let n = d.get(at).copied().unwrap_or(0) & count_mask;
            at = at.saturating_add(1);
            for _ in 0..n {
                let len = usize::from(u16_be(d, at).unwrap_or(0));
                let start = at.saturating_add(2);
                if let Some(u) = d.get(start..start.saturating_add(len)) {
                    units.push(u);
                }
                at = start.saturating_add(len);
            }
        }
    }
    for u in units {
        let (info, _) = nal::parse_nal(codec, u, detached, ps, false);
        ps.update(info.sps.as_ref(), info.pps.as_ref());
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

fn tag_summary(kind: u8, ts: u32, size: u64, body: &[u8]) -> String {
    let mut parts = vec![seconds_ms(ts.into())];
    let b = body.first().copied().unwrap_or(0);
    match kind {
        8 => {
            if b >> 4 == 9 {
                parts.push(format!(
                    "{}, {}",
                    vidutil::fourcc(body.get(1..5).unwrap_or_default()),
                    vidutil::lookup_or(AUDIO_PACKET_TYPES, (b & 15).into())
                ));
            } else {
                parts.push(vidutil::lookup_or(SOUND_FORMATS, (b >> 4).into()));
                if b >> 4 == 10 && body.get(1) == Some(&0) {
                    parts.push("sequence header".to_owned());
                }
            }
        }
        9 => {
            if b & 0x80 != 0 {
                parts.push(format!(
                    "{}, {}, {}",
                    vidutil::fourcc(body.get(1..5).unwrap_or_default()),
                    vidutil::lookup_or(FRAME_TYPES, ((b >> 4) & 7).into()),
                    vidutil::lookup_or(VIDEO_PACKET_TYPES, (b & 15).into())
                ));
            } else {
                parts.push(vidutil::lookup_or(VIDEO_CODECS, (b & 15).into()));
                parts.push(vidutil::lookup_or(FRAME_TYPES, (b >> 4).into()));
                if matches!(b & 15, 7 | 12 | 13) && body.get(1) == Some(&0) {
                    parts.push("sequence header".to_owned());
                }
            }
        }
        18 => parts.push("metadata".to_owned()),
        _ => {}
    }
    parts.push(format!("{size} bytes"));
    parts.join(", ")
}

async fn expand_tag(cx: Cx, tag: Tag) -> Result<()> {
    let block = cx.block(tag.span.sub(0, 11)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u8("Tag type")
        .with(|&t, n| {
            let n = n.value(Value::Enum {
                raw: (t & 0x1f).into(),
                bits: 5,
                name: crate::value::lookup(TAG_TYPES, (t & 0x1f).into()),
            });
            if t & 0x20 != 0 {
                n.summary("filtered (encrypted)")
            } else {
                n
            }
        })
        .emit()?;
    let at = |o: u64, n: u64| tag.span.sub(o, n);
    cx.emit(uint("Data size", at(1, 3), tag.size, 24));
    let ts = u32_be(&block.data, 4).unwrap_or(0);
    let ts = (ts >> 8) | ((ts & 0xff) << 24);
    cx.emit(
        uint("Timestamp", at(4, 4), ts.into(), 32)
            .summary(seconds_ms(ts.into()))
            .desc("Milliseconds; 24 bits plus an 8-bit extension holding the high byte"),
    );
    let stream_id = crate::bytes::u24_be(&block.data, 8).unwrap_or(0);
    let mut sid = uint("Stream ID", at(8, 3), stream_id.into(), 24);
    if stream_id != 0 {
        sid = sid.diag(Diagnostic::warning("should be 0"));
    }
    cx.emit(sid);
    let data = tag.data();
    match tag.kind {
        8 => audio(&cx, tag.input, data).await?,
        9 => video(&cx, data, &tag.codec).await?,
        18 => {
            amf_values(
                cx.clone(),
                AmfList {
                    span: data,
                    kind: ListKind::Values,
                    depth: 0,
                },
            )
            .await?
        }
        _ => cx.emit(Node::new("Data").span(data)),
    }
    let prev = tag.span.sub(tag.size.saturating_add(11), 4);
    let d = cx.read_avail(prev).await?;
    if let Some(v) = u32_be(&d, 0) {
        let mut node = uint("Previous tag size", prev, v.into(), 32);
        if u64::from(v) != tag.size.saturating_add(11) {
            node = node.diag(Diagnostic::warning(format!(
                "does not match the tag size ({})",
                tag.size.saturating_add(11)
            )));
        }
        cx.emit(node);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Audio

async fn audio(cx: &Cx, input: Input, data: Span) -> Result<()> {
    let d = cx.read_avail(data.sub(0, 64)).await?;
    let Some(&b) = d.first() else {
        return Ok(());
    };
    let s = data.sub(0, 1);
    cx.emit(enumerated(
        "Sound format",
        s,
        (b >> 4).into(),
        4,
        SOUND_FORMATS,
    ));
    if b >> 4 == 9 {
        return enhanced_audio(cx, input, data, &d).await;
    }
    cx.emit(
        uint("Sound rate", s, ((b >> 2) & 3).into(), 2).summary(
            SOUND_RATES
                .get(usize::from((b >> 2) & 3))
                .copied()
                .unwrap_or(""),
        ),
    );
    cx.emit(
        uint("Sound size", s, ((b >> 1) & 1).into(), 1).summary(if b & 2 != 0 {
            "16-bit"
        } else {
            "8-bit"
        }),
    );
    cx.emit(
        uint("Sound type", s, (b & 1).into(), 1).summary(if b & 1 != 0 {
            "stereo"
        } else {
            "mono"
        }),
    );
    let mut at = 1u64;
    if b >> 4 == 10 {
        let p = d.get(1).copied().unwrap_or(0);
        cx.emit(enumerated(
            "AAC packet type",
            data.sub(1, 1),
            p.into(),
            8,
            AAC_PACKET,
        ));
        at = 2;
        if p == 0 {
            cx.emit(asc_node(cx, data.tail(2)).await?);
            return Ok(());
        }
    }
    let payload = data.tail(at);
    let mut node = bytes_node("Audio data", payload);
    if matches!(b >> 4, 2 | 14)
        && let Some(s) = d
            .get(vidutil::us(at)..)
            .and_then(vidutil::audio::es_summary)
    {
        node = node.summary(format!("{s}, {} bytes", payload.len));
    }
    cx.emit(node);
    Ok(())
}

/// An AudioSpecificConfig at `span`, decoded.
async fn asc_node(cx: &Cx, span: Span) -> Result<Node> {
    let bytes = cx.read_avail(span.sub(0, 64)).await?;
    let (a, nodes) = nal::asc(&bytes, span, true);
    let mut node = group("AudioSpecificConfig", span, nodes);
    if let Some(a) = a {
        node = node.summary(a.describe());
    }
    Ok(node)
}

async fn enhanced_audio(cx: &Cx, input: Input, data: Span, d: &[u8]) -> Result<()> {
    let b = d.first().copied().unwrap_or(0);
    let packet = b & 15;
    cx.emit(enumerated(
        "Audio packet type",
        data.sub(0, 1),
        packet.into(),
        4,
        AUDIO_PACKET_TYPES,
    ));
    if packet == 5 || packet == 7 {
        cx.emit(bytes_node("Data", data.tail(1)));
        return Ok(());
    }
    let fourcc = d.get(1..5).unwrap_or_default();
    cx.emit(
        text("FourCC", data.sub(1, 4), vidutil::fourcc(fourcc))
            .summary(vidutil::codec_name(fourcc).unwrap_or("unknown codec")),
    );
    let body = data.tail(5);
    let bytes = d.get(5..).unwrap_or_default();
    match (packet, fourcc) {
        (0, b"mp4a") => cx.emit(asc_node(cx, body).await?),
        (0, b"Opus") => {
            let (o, nodes) = nal::opus(bytes, body, true, false);
            let mut node = group("Opus ID header", body, nodes);
            if let Some(o) = o {
                node = node.summary(o.describe());
            }
            cx.emit(node);
        }
        // The metadata blocks, STREAMINFO first, with or without `fLaC`.
        (0, b"fLaC") if bytes.starts_with(b"fLaC") => {
            crate::formats::audio::flac::codec_config(cx, input, body).await?;
        }
        (0, b"fLaC") => crate::formats::audio::flac::metadata_blocks(cx, input, body, 0).await?,
        (4, _) => {
            let mut w = Walker::new(bytes, body, false, true);
            let ok = (|| -> Option<()> {
                let order = w.en(
                    "AudioChannelOrder",
                    8,
                    &[(0, "unspecified"), (1, "native"), (2, "custom")],
                )?;
                let n = w.u("channelCount", 8)?;
                if order == 1 {
                    w.x("audioChannelFlags", 32)?;
                } else if order == 2 {
                    for i in 0..n {
                        w.u(format!("audioChannelMapping[{i}]"), 8)?;
                    }
                }
                Some(())
            })()
            .is_some();
            for node in w.finish(ok) {
                cx.emit(node);
            }
        }
        _ => {
            let mut node = bytes_node("Audio data", body);
            if let Some(s) = vidutil::audio::es_summary(bytes) {
                node = node.summary(format!("{s}, {} bytes", body.len));
            }
            cx.emit(node);
        }
    }
    Ok(())
}

fn bytes_node(name: &'static str, span: Span) -> Node {
    Node::new(name)
        .span(span)
        .summary(format!("{} bytes", span.len))
}

// ---------------------------------------------------------------------------
// Video

async fn video(cx: &Cx, data: Span, codec: &Codec) -> Result<()> {
    let d = cx.read_avail(data.sub(0, 32)).await?;
    let Some(&b) = d.first() else {
        return Ok(());
    };
    let s = data.sub(0, 1);
    if b & 0x80 != 0 {
        return enhanced_video(cx, data, &d, codec).await;
    }
    cx.emit(enumerated("Frame type", s, (b >> 4).into(), 4, FRAME_TYPES));
    let id = b & 15;
    cx.emit(enumerated("Codec ID", s, id.into(), 4, VIDEO_CODECS));
    if b >> 4 == 5 {
        let cmd = d.get(1).copied().unwrap_or(0);
        cx.emit(enumerated(
            "Video command",
            data.sub(1, 1),
            cmd.into(),
            8,
            &[
                (0, "start of client-side seeking"),
                (1, "end of client-side seeking"),
            ],
        ));
        return Ok(());
    }
    match id {
        7 | 12 | 13 => {
            let p = d.get(1).copied().unwrap_or(0);
            cx.emit(enumerated(
                "Packet type",
                data.sub(1, 1),
                p.into(),
                8,
                AVC_PACKET,
            ));
            cx.emit(composition_time(data.sub(2, 3), &d, 2));
            let payload = data.tail(5);
            let kind: &[u8; 4] = match id {
                7 => b"avc1",
                12 => b"hvc1",
                _ => b"av01",
            };
            if p == 0 {
                cx.emit(config_node(cx, kind, payload).await?);
            } else if p == 1 {
                frames(cx, kind, payload, codec).await?;
            }
        }
        2 => {
            let bytes = cx.read_avail(data.sub(1, 16)).await?;
            let mut w = Walker::new(&bytes, data.tail(1), false, true);
            let r = h263_header(&mut w);
            let mut node = group("Picture header", data.sub(1, 8), w.finish(r.is_some()));
            if let Some(s) = r {
                node = node.summary(s);
            }
            cx.emit(node);
            cx.emit(bytes_node("Video data", data.tail(1)));
        }
        4 | 5 => {
            let mut at = 1u64;
            if id == 5 {
                let off = crate::bytes::u24_be(&d, 1).unwrap_or(0);
                cx.emit(
                    uint("Alpha offset", data.sub(1, 3), off.into(), 24)
                        .desc("Offset of the alpha channel data"),
                );
                at = 4;
            }
            let adj = d.get(vidutil::us(at)).copied().unwrap_or(0);
            cx.emit(
                uint("Size adjustment", data.sub(at, 1), adj.into(), 8).summary(format!(
                    "width −{}, height −{}",
                    adj >> 4,
                    adj & 15
                )),
            );
            cx.emit(bytes_node("Video data", data.tail(at.saturating_add(1))));
        }
        _ => cx.emit(bytes_node("Video data", data.tail(1))),
    }
    Ok(())
}

fn composition_time(span: Span, d: &[u8], at: usize) -> Node {
    let ct = crate::bytes::u24_be(d, at).unwrap_or(0);
    let ct = i32::from_ne_bytes((ct << 8).to_ne_bytes()) >> 8;
    Node::new("Composition time")
        .span(span)
        .value(Value::Int {
            value: ct.into(),
            bits: 24,
        })
        .summary(format!("{ct} ms"))
}

async fn enhanced_video(cx: &Cx, data: Span, d: &[u8], codec: &Codec) -> Result<()> {
    let b = d.first().copied().unwrap_or(0);
    let s = data.sub(0, 1);
    cx.emit(enumerated(
        "Frame type",
        s,
        ((b >> 4) & 7).into(),
        3,
        FRAME_TYPES,
    ));
    let packet = b & 15;
    cx.emit(enumerated(
        "Packet type",
        s,
        packet.into(),
        4,
        VIDEO_PACKET_TYPES,
    ));
    if packet == 6 || packet == 7 {
        cx.emit(bytes_node("Data", data.tail(1)));
        return Ok(());
    }
    let fourcc: [u8; 4] = d
        .get(1..5)
        .and_then(|f| f.try_into().ok())
        .unwrap_or([0; 4]);
    cx.emit(
        text("FourCC", data.sub(1, 4), vidutil::fourcc(&fourcc))
            .summary(vidutil::codec_name(&fourcc).unwrap_or("unknown codec")),
    );
    let mut payload = data.tail(5);
    match packet {
        0 => cx.emit(config_node(cx, &fourcc, payload).await?),
        1 | 3 => {
            if packet == 1 && matches!(&fourcc, b"avc1" | b"hvc1") {
                cx.emit(composition_time(data.sub(5, 3), d, 5));
                payload = data.tail(8);
            }
            frames(cx, &fourcc, payload, codec).await?;
        }
        4 => {
            amf_values(
                cx.clone(),
                AmfList {
                    span: payload,
                    kind: ListKind::Values,
                    depth: 0,
                },
            )
            .await?;
        }
        _ => cx.emit(bytes_node("Data", payload)),
    }
    Ok(())
}

/// The decoder configuration record of `fourcc` at `span`, decoded.
async fn config_node(cx: &Cx, fourcc: &[u8; 4], span: Span) -> Result<Node> {
    let d = vidutil::read_small(cx, span, 0x4000).await?;
    let (name, summary, nodes) = match fourcc {
        b"avc1" => {
            let (s, n) = nal::avcc(&d, span, true);
            ("AVCDecoderConfigurationRecord", s.map(|s| s.describe()), n)
        }
        b"hvc1" => {
            let (s, n) = nal::hvcc(&d, span, true);
            ("HEVCDecoderConfigurationRecord", s.map(|s| s.describe()), n)
        }
        b"av01" => {
            let (s, n) = nal::av1c(&d, span, true);
            ("AV1CodecConfigurationRecord", s, n)
        }
        b"vp09" => {
            let (s, n) = nal::vpcc(&d, span, true);
            ("VPCodecConfigurationRecord", s, n)
        }
        _ => ("Decoder configuration record", None, Vec::new()),
    };
    let mut node = group(name, span, nodes);
    node = node.summary(match summary {
        Some(s) => s,
        None => format!("{} bytes", span.len),
    });
    Ok(node)
}

/// The coded data of a video frame: NAL units, OBUs or a VP9 frame.
async fn frames(cx: &Cx, fourcc: &[u8; 4], payload: Span, codec: &Codec) -> Result<()> {
    match fourcc {
        b"avc1" | b"hvc1" => {
            let nal_codec = if fourcc == b"hvc1" {
                NalCodec::Hevc
            } else {
                NalCodec::Avc
            };
            let size = codec.length_size.clamp(1, 4);
            let mut pos = 0u64;
            let mut ps = (*codec.ps).clone();
            while pos < payload.len {
                let head = cx.read_avail(payload.sub(pos, size)).await?;
                let len = head.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
                let span = payload.sub(pos, size.saturating_add(len));
                let unit = span.tail(size);
                let d = vidutil::read_small(cx, unit, 0x1000).await?;
                let (node, info) = nal::nal_node(nal_codec, &d, unit, &ps);
                ps.update(info.sps.as_ref(), info.pps.as_ref());
                let mut node = node.span(span);
                if unit.len < len {
                    node = node.diag(Diagnostic::truncated(
                        Span::new(unit.source, unit.offset, len),
                        unit.len,
                    ));
                }
                cx.push(node).await;
                pos = pos.saturating_add(size).saturating_add(len);
            }
        }
        b"av01" => {
            let d = vidutil::read_small(cx, payload, 0x10000).await?;
            let mut w = Walker::new(&d, payload, false, true);
            let mut seq = codec.seq;
            let ok = nal::obus(&mut w, &mut seq).is_some();
            for node in w.finish(ok) {
                cx.emit(node);
            }
        }
        b"vp09" => {
            let d = cx.read_avail(payload.sub(0, 64)).await?;
            let mut w = Walker::new(&d, payload, false, true);
            let r = vp9::vp9_header(&mut w);
            let mut node = group("VP9 frame header", payload, w.finish(r.is_some()));
            if let Some(f) = r {
                node = node.summary(f.describe());
            }
            cx.emit(node);
            cx.emit(bytes_node("Frame data", payload));
        }
        _ => cx.emit(bytes_node("Video data", payload)),
    }
    Ok(())
}

/// The Sorenson H.263 picture header.
fn h263_header(w: &mut Walker) -> Option<String> {
    w.x("PictureStartCode", 17)?;
    w.u("Version", 5)?;
    w.u("TemporalReference", 8)?;
    let size = w.en(
        "PictureSize",
        3,
        &[
            (0, "custom, 8-bit"),
            (1, "custom, 16-bit"),
            (2, "CIF (352×288)"),
            (3, "QCIF (176×144)"),
            (4, "SQCIF (128×96)"),
            (5, "320×240"),
            (6, "160×120"),
        ],
    )?;
    let (width, height) = match size {
        0 => (w.u("Width", 8)?, w.u("Height", 8)?),
        1 => (w.u("Width", 16)?, w.u("Height", 16)?),
        n => H263_SIZES.get(vidutil::us(n)).copied().unwrap_or((0, 0)),
    };
    let t = w.en(
        "PictureType",
        2,
        &[(0, "intra"), (1, "inter"), (2, "disposable inter")],
    )?;
    w.flag("DeblockingFlag")?;
    w.u("Quantizer", 5)?;
    Some(format!(
        "{} picture, {width}×{height}",
        match t {
            0 => "intra",
            1 => "inter",
            _ => "disposable inter",
        }
    ))
}

// ---------------------------------------------------------------------------
// AMF0

const AMF_TYPES: EnumTable = &[
    (0, "Number"),
    (1, "Boolean"),
    (2, "String"),
    (3, "Object"),
    (4, "MovieClip"),
    (5, "Null"),
    (6, "Undefined"),
    (7, "Reference"),
    (8, "ECMA array"),
    (9, "Object end"),
    (10, "Strict array"),
    (11, "Date"),
    (12, "Long string"),
    (13, "Unsupported"),
    (15, "XML document"),
    (16, "Typed object"),
    (17, "AMF3 value"),
];

const MAX_AMF_DEPTH: u32 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListKind {
    /// A sequence of values (script tag body).
    Values,
    /// Object properties up to the end marker.
    Properties,
    /// `n` values of a strict array.
    Items(u32),
}

#[derive(Clone, Copy, Debug)]
struct AmfList {
    span: Span,
    kind: ListKind,
    depth: u32,
}

/// The end of the AMF0 value at `at` (exclusive), without decoding it.
fn amf_skip(d: &[u8], at: usize, depth: u32) -> Option<usize> {
    if depth > MAX_AMF_DEPTH {
        return None;
    }
    let t = *d.get(at)?;
    let body = at.checked_add(1)?;
    match t {
        0 => body.checked_add(8),
        1 => body.checked_add(1),
        2 => body
            .checked_add(2)?
            .checked_add(usize::from(u16_be(d, body)?)),
        3 => props_end(d, body, depth),
        5 | 6 | 9 | 13 => Some(body),
        7 => body.checked_add(2),
        8 => props_end(d, body.checked_add(4)?, depth),
        10 => {
            let n = u32_be(d, body)?;
            let mut pos = body.checked_add(4)?;
            for _ in 0..n {
                pos = amf_skip(d, pos, depth.checked_add(1)?)?;
            }
            Some(pos)
        }
        11 => body.checked_add(10),
        12 | 15 => body
            .checked_add(4)?
            .checked_add(usize::try_from(u32_be(d, body)?).ok()?),
        16 => {
            let name = usize::from(u16_be(d, body)?);
            props_end(d, body.checked_add(2)?.checked_add(name)?, depth)
        }
        17 => {
            let mut a = Amf3::new(d, body);
            a.skip_value(depth.checked_add(1)?)?;
            Some(a.at)
        }
        _ => None,
    }
}

/// The end of an object's properties, including the `00 00 09` marker.
fn props_end(d: &[u8], mut pos: usize, depth: u32) -> Option<usize> {
    loop {
        let len = usize::from(u16_be(d, pos)?);
        if len == 0 && d.get(pos.checked_add(2)?) == Some(&9) {
            return pos.checked_add(3);
        }
        pos = pos.checked_add(2)?.checked_add(len)?;
        pos = amf_skip(d, pos, depth.checked_add(1)?)?;
    }
}

async fn amf_values(cx: Cx, list: AmfList) -> Result<()> {
    if list.depth > MAX_AMF_DEPTH {
        return Err(Diagnostic::limit("AMF values nested too deeply").at(list.span));
    }
    let d = vidutil::read_small(&cx, list.span, 0x100000).await?;
    let mut pos = 0usize;
    let mut index = 0u32;
    loop {
        if pos >= d.len() {
            break;
        }
        if let ListKind::Items(n) = list.kind
            && index >= n
        {
            break;
        }
        let mut name = match list.kind {
            ListKind::Values => format!("Value {}", index.saturating_add(1)),
            ListKind::Items(_) => format!("[{index}]"),
            ListKind::Properties => {
                let len = usize::from(u16_be(&d, pos).unwrap_or(0));
                if len == 0 && d.get(pos.saturating_add(2)) == Some(&9) {
                    cx.emit(Node::new("Object end").span(vidutil::at(list.span, pos, 3)));
                    break;
                }
                let start = pos.saturating_add(2);
                let key = d.get(start..start.saturating_add(len)).unwrap_or_default();
                pos = start.saturating_add(len);
                String::from_utf8_lossy(key).into_owned()
            }
        };
        let Some(end) = amf_skip(&d, pos, list.depth) else {
            cx.emit(
                Node::new(name)
                    .span(list.span.tail(to_u64(pos)))
                    .diag(Diagnostic::malformed("invalid AMF0 value")),
            );
            break;
        };
        let span = vidutil::at(list.span, pos, end.saturating_sub(pos));
        let t = d.get(pos).copied().unwrap_or(0);
        if list.kind == ListKind::Values && index < 2 {
            name = if index == 0 && t == 2 {
                "Name"
            } else {
                "Value"
            }
            .to_owned();
        }
        let node = amf_node(name.clone(), &d, pos, span, list.depth);
        cx.push(annotate_property(&name, node, &d, pos)).await;
        pos = end;
        index = index.saturating_add(1);
        cx.checkpoint().await;
    }
    Ok(())
}

/// Adds units and names to well-known `onMetaData` properties.
fn annotate_property(name: &str, node: Node, d: &[u8], pos: usize) -> Node {
    let number = (d.get(pos) == Some(&0))
        .then(|| crate::bytes::array::<8>(d, pos.saturating_add(1)).map(f64::from_be_bytes))
        .flatten();
    let Some(n) = number else {
        return match name {
            "keyframes" => node.desc("Keyframe index: file positions and times of keyframes"),
            _ => node,
        };
    };
    match name {
        "duration" | "lasttimestamp" | "lastkeyframetimestamp" => {
            node.summary(vidutil::seconds_f64(n))
        }
        "width" | "height" => node.summary("pixels"),
        "framerate" => node.summary("fps"),
        "videodatarate" | "audiodatarate" => node.summary("kb/s"),
        "audiosamplerate" => node.summary("Hz"),
        "audiosamplesize" => node.summary("bits"),
        "filesize" | "datasize" | "videosize" | "audiosize" => {
            node.summary(crate::formats::util::arcutil::human_size(count(n)))
        }
        "videocodecid" => node.summary(codec_id_name(n, VIDEO_CODECS)),
        "audiocodecid" => node.summary(codec_id_name(n, SOUND_FORMATS)),
        _ => node,
    }
}

/// A non-negative metadata number as an integer (saturating).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn count(n: f64) -> u64 {
    n as u64
}

/// A codec ID from metadata: a legacy number or an enhanced FourCC.
fn codec_id_name(n: f64, table: EnumTable) -> String {
    let v = count(n);
    if v > 255 {
        let b = u32::try_from(v).unwrap_or(0).to_be_bytes();
        let fourcc = vidutil::fourcc(&b);
        match vidutil::codec_name(&b) {
            Some(c) => format!("{fourcc} ({c})"),
            None => fourcc,
        }
    } else {
        vidutil::lookup_or(table, v)
    }
}

/// A codec ID from metadata as a codec name.
fn codec_id_short(n: f64, table: EnumTable) -> String {
    let v = count(n);
    if v > 255 {
        let b = u32::try_from(v).unwrap_or(0).to_be_bytes();
        vidutil::codec_name(&b).map_or_else(|| vidutil::fourcc(&b), str::to_owned)
    } else {
        vidutil::lookup_or(table, v)
    }
}

/// A node for the AMF0 value at `pos` (occupying `span`).
fn amf_node(name: String, d: &[u8], pos: usize, span: Span, depth: u32) -> Node {
    let t = d.get(pos).copied().unwrap_or(0);
    let body = pos.saturating_add(1);
    let node = Node::new(name).span(span);
    let inner = |skip: usize| span.tail(to_u64(skip));
    let child = |kind, skip| AmfList {
        span: inner(skip),
        kind,
        depth: depth.saturating_add(1),
    };
    match t {
        0 => {
            let v = crate::bytes::array::<8>(d, body).map_or(0.0, f64::from_be_bytes);
            node.value(Value::Float(v))
        }
        1 => node.value(Value::Bool(d.get(body).is_some_and(|&b| b != 0))),
        2 | 12 => {
            let (len, skip) = if t == 2 {
                (u16_be(d, body).map(usize::from), 3)
            } else {
                (u32_be(d, body).and_then(|n| usize::try_from(n).ok()), 5)
            };
            let start = pos.saturating_add(skip);
            let s = d
                .get(start..start.saturating_add(len.unwrap_or(0)))
                .unwrap_or_default();
            node.value(Value::Text(String::from_utf8_lossy(s).into_owned()))
        }
        3 => node.summary("object").lazy(
            crate::expander!(self::amf_values: AmfList),
            child(ListKind::Properties, 1),
        ),
        16 => {
            let len = u16_be(d, body).map_or(0, usize::from);
            let start = body.saturating_add(2);
            let class = d.get(start..start.saturating_add(len)).unwrap_or_default();
            node.summary(format!(
                "object of class {}",
                String::from_utf8_lossy(class)
            ))
            .lazy(
                crate::expander!(self::amf_values: AmfList),
                child(ListKind::Properties, 3usize.saturating_add(len)),
            )
        }
        8 => node
            .summary(format!(
                "ECMA array, {} entries",
                u32_be(d, body).unwrap_or(0)
            ))
            .lazy(
                crate::expander!(self::amf_values: AmfList),
                child(ListKind::Properties, 5),
            ),
        10 => {
            let n = u32_be(d, body).unwrap_or(0);
            node.summary(format!("strict array, {n} items")).lazy(
                crate::expander!(self::amf_values: AmfList),
                child(ListKind::Items(n), 5),
            )
        }
        11 => {
            let ms = crate::bytes::array::<8>(d, body).map_or(0.0, f64::from_be_bytes);
            #[allow(clippy::cast_possible_truncation)]
            let secs = (ms / 1000.0) as i64;
            node.value(Value::Timestamp { unix_seconds: secs })
        }
        7 => node.value(Value::UInt {
            value: u16_be(d, body).unwrap_or(0).into(),
            bits: 16,
            radix: crate::value::Radix::Dec,
        }),
        17 => {
            let mut a = Amf3::new(d, body);
            let start = a.at;
            match a.value(depth.saturating_add(1), span.tail(1), start) {
                Some((value, children)) => {
                    let mut n = node.summary("AMF3");
                    if let Some(v) = value {
                        n = n.value(v);
                    }
                    if !children.is_empty() {
                        n = n.lazy(emit_nodes, Arc::new(children));
                    }
                    n
                }
                None => node.diag(Diagnostic::malformed("invalid AMF3 value")),
            }
        }
        _ => node.value(Value::Enum {
            raw: t.into(),
            bits: 8,
            name: crate::value::lookup(AMF_TYPES, t.into()),
        }),
    }
}

// ---------------------------------------------------------------------------
// AMF3 (inside an AMF0 `avmplus` value)

/// Nodes an AMF3 value may produce at most (the decoding is eager).
const AMF3_NODES: u32 = 4096;

/// An AMF3 decoder over `d` from `at`, keeping the reference tables.
struct Amf3<'a> {
    d: &'a [u8],
    at: usize,
    strings: Vec<String>,
    traits: Vec<(bool, Vec<String>)>,
    budget: u32,
}

impl<'a> Amf3<'a> {
    fn new(d: &'a [u8], at: usize) -> Self {
        Amf3 {
            d,
            at,
            strings: Vec::new(),
            traits: Vec::new(),
            budget: AMF3_NODES,
        }
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.d.get(self.at)?;
        self.at = self.at.checked_add(1)?;
        Some(b)
    }

    /// U29: up to four bytes, seven bits each (eight in the last).
    fn u29(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for i in 0..4 {
            let b = self.byte()?;
            if i == 3 {
                return Some((v << 8) | u32::from(b));
            }
            v = (v << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        Some(v)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let b = self.d.get(self.at..end)?;
        self.at = end;
        Some(b)
    }

    fn string(&mut self) -> Option<String> {
        let h = self.u29()?;
        if h & 1 == 0 {
            return self.strings.get(usize::try_from(h >> 1).ok()?).cloned();
        }
        let n = usize::try_from(h >> 1).ok()?;
        let s = String::from_utf8_lossy(self.bytes(n)?).into_owned();
        if !s.is_empty() && self.strings.len() < 65536 {
            self.strings.push(s.clone());
        }
        Some(s)
    }

    fn skip_value(&mut self, depth: u32) -> Option<()> {
        let mut quiet = Amf3 {
            d: self.d,
            at: self.at,
            strings: std::mem::take(&mut self.strings),
            traits: std::mem::take(&mut self.traits),
            budget: AMF3_NODES.saturating_mul(16),
        };
        let span = Span::new(crate::span::SourceId::default_host(), 0, 0);
        quiet.value(depth, span, quiet.at)?;
        self.at = quiet.at;
        Some(())
    }

    /// Decodes a value: its scalar value (if any) and child nodes.
    /// `base` is the span of `d` from `origin`.
    fn value(
        &mut self,
        depth: u32,
        base: Span,
        origin: usize,
    ) -> Option<(Option<Value>, Vec<Node>)> {
        if depth > MAX_AMF_DEPTH {
            return None;
        }
        self.budget = self.budget.checked_sub(1)?;
        let t = self.byte()?;
        Some(match t {
            0 | 1 => (
                Some(Value::Text(
                    if t == 0 { "undefined" } else { "null" }.to_owned(),
                )),
                Vec::new(),
            ),
            2 | 3 => (Some(Value::Bool(t == 3)), Vec::new()),
            4 => {
                let v = self.u29()?;
                // Sign-extend 29 bits.
                let v = i64::from(i32::from_ne_bytes((v << 3).to_ne_bytes()) >> 3);
                (Some(Value::Int { value: v, bits: 29 }), Vec::new())
            }
            5 => {
                let b = self.bytes(8)?;
                let v = f64::from_be_bytes(b.try_into().ok()?);
                (Some(Value::Float(v)), Vec::new())
            }
            6 | 7 | 11 => (Some(Value::Text(self.string()?)), Vec::new()),
            8 => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return Some((Some(Value::Text("(reference)".to_owned())), Vec::new()));
                }
                let b = self.bytes(8)?;
                let ms = f64::from_be_bytes(b.try_into().ok()?);
                #[allow(clippy::cast_possible_truncation)]
                let secs = (ms / 1000.0) as i64;
                (Some(Value::Timestamp { unix_seconds: secs }), Vec::new())
            }
            9 => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return Some((Some(Value::Text("(reference)".to_owned())), Vec::new()));
                }
                let dense = h >> 1;
                let mut out = Vec::new();
                loop {
                    let key = self.string()?;
                    if key.is_empty() {
                        break;
                    }
                    out.push(self.child(key, depth, base, origin)?);
                }
                for i in 0..dense {
                    out.push(self.child(format!("[{i}]"), depth, base, origin)?);
                }
                (None, out)
            }
            10 => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return Some((Some(Value::Text("(reference)".to_owned())), Vec::new()));
                }
                let (dynamic, names) = if h & 2 == 0 {
                    self.traits.get(usize::try_from(h >> 2).ok()?).cloned()?
                } else if h & 4 != 0 {
                    // Externalizable: opaque.
                    let class = self.string()?;
                    return Some((
                        Some(Value::Text(format!("externalizable {class}"))),
                        Vec::new(),
                    ));
                } else {
                    let dynamic = h & 8 != 0;
                    let count = h >> 4;
                    let _class = self.string()?;
                    let mut names = Vec::new();
                    for _ in 0..count.min(4096) {
                        names.push(self.string()?);
                    }
                    if self.traits.len() < 4096 {
                        self.traits.push((dynamic, names.clone()));
                    }
                    (dynamic, names)
                };
                let mut out = Vec::new();
                for n in names {
                    out.push(self.child(n, depth, base, origin)?);
                }
                if dynamic {
                    loop {
                        let key = self.string()?;
                        if key.is_empty() {
                            break;
                        }
                        out.push(self.child(key, depth, base, origin)?);
                    }
                }
                (None, out)
            }
            12 => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return Some((Some(Value::Text("(reference)".to_owned())), Vec::new()));
                }
                let b = self.bytes(usize::try_from(h >> 1).ok()?)?;
                (Some(Value::Bytes(b.to_vec())), Vec::new())
            }
            13..=16 => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return Some((Some(Value::Text("(reference)".to_owned())), Vec::new()));
                }
                let n = h >> 1;
                self.byte()?;
                let mut out = Vec::new();
                if t == 16 {
                    self.string()?;
                }
                for i in 0..n {
                    let start = self.at;
                    let value = match t {
                        13 => Value::Int {
                            value: i64::from(i32::from_be_bytes(self.bytes(4)?.try_into().ok()?)),
                            bits: 32,
                        },
                        14 => Value::UInt {
                            value: u64::from(u32::from_be_bytes(self.bytes(4)?.try_into().ok()?)),
                            bits: 32,
                            radix: crate::value::Radix::Dec,
                        },
                        15 => Value::Float(f64::from_be_bytes(self.bytes(8)?.try_into().ok()?)),
                        _ => {
                            out.push(self.child(format!("[{i}]"), depth, base, origin)?);
                            continue;
                        }
                    };
                    self.budget = self.budget.checked_sub(1)?;
                    out.push(
                        Node::new(format!("[{i}]"))
                            .span(self.span(base, origin, start))
                            .value(value),
                    );
                }
                (None, out)
            }
            17 => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return Some((Some(Value::Text("(reference)".to_owned())), Vec::new()));
                }
                self.byte()?;
                let mut out = Vec::new();
                for i in 0..h >> 1 {
                    out.push(self.child(format!("key {i}"), depth, base, origin)?);
                    out.push(self.child(format!("value {i}"), depth, base, origin)?);
                }
                (None, out)
            }
            _ => return None,
        })
    }

    fn span(&self, base: Span, origin: usize, start: usize) -> Span {
        base.sub(
            to_u64(start.saturating_sub(origin)),
            to_u64(self.at.saturating_sub(start)),
        )
    }

    /// A named child value as a node.
    fn child(&mut self, name: String, depth: u32, base: Span, origin: usize) -> Option<Node> {
        let start = self.at;
        let (value, children) = self.value(depth.checked_add(1)?, base, origin)?;
        let mut node = Node::new(name).span(self.span(base, origin, start));
        if let Some(v) = value {
            node = node.value(v);
        }
        if !children.is_empty() {
            node = node
                .summary(plural(to_u64(children.len()), "entry"))
                .lazy(emit_nodes, Arc::new(children));
        }
        Some(node)
    }
}

// ---------------------------------------------------------------------------
// File summary

#[derive(Default)]
struct Summary {
    width: Option<f64>,
    height: Option<f64>,
    framerate: Option<f64>,
    video: Option<String>,
    video_detail: Option<String>,
    audio: Option<String>,
    audio_detail: Option<String>,
    duration: Option<f64>,
    keyframes: Option<u64>,
}

impl Summary {
    /// Looks at the first tags: metadata and the codec configurations.
    async fn scan(cx: &Cx, file: Span, start: u64) -> Result<Summary> {
        let mut s = Summary::default();
        let mut pos = start.saturating_add(4);
        for _ in 0..32 {
            if pos >= file.len {
                break;
            }
            let head = cx.read_avail(file.sub(pos, 16)).await?;
            if head.len() < 11 {
                break;
            }
            let kind = head.first().copied().unwrap_or(0) & 0x1f;
            let size = u64::from(crate::bytes::u24_be(&head, 1).unwrap_or(0));
            let data = file.sub(pos.saturating_add(11), size);
            let body = cx.read_avail(data.sub(0, 16)).await?;
            s.observe(cx, kind, data, &body).await?;
            if s.video_detail.is_some() && s.audio_detail.is_some() && s.duration.is_some() {
                break;
            }
            pos = pos.saturating_add(size).saturating_add(15);
        }
        Ok(s)
    }

    async fn observe(&mut self, cx: &Cx, kind: u8, data: Span, body: &[u8]) -> Result<()> {
        let b = body.first().copied().unwrap_or(0);
        match kind {
            8 => {
                if self.audio.is_none() {
                    self.audio = if b >> 4 == 9 {
                        body.get(1..5).map(|f| {
                            vidutil::codec_name(f).map_or_else(|| vidutil::fourcc(f), str::to_owned)
                        })
                    } else {
                        crate::value::lookup(SOUND_FORMATS, (b >> 4).into()).map(str::to_owned)
                    };
                }
                let asc = if b >> 4 == 10 && body.get(1) == Some(&0) {
                    Some(2u64)
                } else if b & 0xf0 == 0x90 && b & 15 == 0 && body.get(1..5) == Some(b"mp4a") {
                    Some(5)
                } else {
                    None
                };
                if self.audio_detail.is_none()
                    && let Some(at) = asc
                {
                    let d = cx.read_avail(data.tail(at).sub(0, 64)).await?;
                    self.audio_detail = nal::asc(&d, data, false).0.map(|a| a.describe());
                } else if self.audio_detail.is_none() && matches!(b >> 4, 2 | 14) {
                    self.audio_detail =
                        vidutil::audio::es_summary(body.get(1..).unwrap_or_default());
                }
            }
            9 => {
                if self.video.is_none() {
                    self.video = if b & 0x80 != 0 {
                        body.get(1..5).map(|f| {
                            vidutil::codec_name(f).map_or_else(|| vidutil::fourcc(f), str::to_owned)
                        })
                    } else {
                        crate::value::lookup(VIDEO_CODECS, (b & 15).into()).map(str::to_owned)
                    };
                }
                let config: Option<&[u8]> = if b & 0x80 != 0 && b & 15 == 0 {
                    body.get(1..5)
                } else if b & 0x80 == 0 && body.get(1) == Some(&0) {
                    match b & 15 {
                        7 => Some(b"avc1"),
                        12 => Some(b"hvc1"),
                        _ => None,
                    }
                } else {
                    None
                };
                if self.video_detail.is_none()
                    && let Some(f) = config
                {
                    let span = data.tail(5);
                    let d = vidutil::read_small(cx, span, 0x4000).await?;
                    self.video_detail = match f {
                        b"avc1" => nal::avcc(&d, span, false).0.map(|s| s.describe()),
                        b"hvc1" => nal::hvcc(&d, span, false).0.map(|s| s.describe()),
                        b"av01" => nal::av1c(&d, span, false).0,
                        b"vp09" => nal::vpcc(&d, span, false).0,
                        _ => None,
                    };
                }
            }
            18 => {
                let d = vidutil::read_small(cx, data, 0x10000).await?;
                self.metadata(&d);
            }
            _ => {}
        }
        Ok(())
    }

    /// Reads `onMetaData` properties.
    fn metadata(&mut self, d: &[u8]) {
        // Skip the name string, then expect an ECMA array or object.
        let Some(start) = amf_skip(d, 0, 0) else {
            return;
        };
        let mut pos = match d.get(start) {
            Some(8) => start.saturating_add(5),
            Some(3) => start.saturating_add(1),
            _ => return,
        };
        for _ in 0..256 {
            let Some(len) = u16_be(d, pos).map(usize::from) else {
                return;
            };
            if len == 0 {
                return;
            }
            let key_start = pos.saturating_add(2);
            let key = d
                .get(key_start..key_start.saturating_add(len))
                .unwrap_or_default();
            let at = key_start.saturating_add(len);
            let number = (d.get(at) == Some(&0))
                .then(|| crate::bytes::array::<8>(d, at.saturating_add(1)).map(f64::from_be_bytes))
                .flatten();
            match (key, number) {
                (b"width", Some(n)) => self.width = Some(n),
                (b"height", Some(n)) => self.height = Some(n),
                (b"duration", Some(n)) => self.duration = Some(n),
                (b"framerate", Some(n)) => self.framerate = Some(n),
                (b"videocodecid", Some(n)) if self.video.is_none() => {
                    self.video = Some(codec_id_short(n, VIDEO_CODECS));
                }
                (b"audiocodecid", Some(n)) if self.audio.is_none() => {
                    self.audio = Some(codec_id_short(n, SOUND_FORMATS));
                }
                (b"keyframes", None) => {
                    // An object with "times" and "filepositions" arrays.
                    if let Some(i) =
                        vidutil::find(d.get(at..).unwrap_or_default(), b"\x00\x05times\x0a")
                        && let Some(n) = u32_be(d, at.saturating_add(i).saturating_add(8))
                    {
                        self.keyframes = Some(n.into());
                    }
                }
                _ => {}
            }
            let Some(end) = amf_skip(d, at, 1) else {
                return;
            };
            pos = end;
        }
    }

    fn describe(&self) -> String {
        let mut parts = vec!["FLV".to_owned()];
        let mut streams = Vec::new();
        if let Some(v) = &self.video {
            streams.push(match (&self.video_detail, self.width, self.height) {
                (Some(d), _, _) => format!("{v} {d}"),
                (None, Some(w), Some(h)) if w > 0.0 => {
                    let mut s = format!("{}×{} {v}", vidutil::num(w), vidutil::num(h));
                    if let Some(f) = self.framerate.filter(|f| *f > 0.0) {
                        s = format!("{s}, {} fps", vidutil::num(f));
                    }
                    s
                }
                _ => v.clone(),
            });
        }
        if let Some(a) = &self.audio {
            streams.push(match &self.audio_detail {
                Some(d) => d.clone(),
                None => a.clone(),
            });
        }
        if !streams.is_empty() {
            parts.push(streams.join(" + "));
        }
        if let Some(d) = self.duration {
            parts.push(vidutil::seconds_f64(d));
        }
        if let Some(k) = self.keyframes {
            parts.push(format!("keyframe index of {k}"));
        }
        parts.join(", ")
    }
}
