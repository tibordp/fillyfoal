//! Flash Video (FLV).
//!
//! A 9-byte header, then tags `type, size (24), timestamp (24+8), stream
//! id (24), data, previous tag size`. Tags are listed in pages. Audio and
//! video tags start with a codec header byte; script tags carry AMF0
//! values (usually `onMetaData`), which are decoded into a tree.

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::vidutil::{self, enumerated, seconds_ms, text, uint};
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
    (9, "extended"),
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

record! {
    pub struct Header {
        signature: ascii[3] "Signature",
        version: u8 "Version",
        flags: u8 "Flags" .flags(HEADER_FLAGS),
        offset: u32 "Data offset",
    }
}

#[derive(Clone, Copy, Debug)]
struct Tag {
    span: Span,
    kind: u8,
    size: u64,
}

impl Tag {
    fn data(&self) -> Span {
        self.span.sub(11, self.size)
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = crate::fields::parse(&cx, file.sub(0, 9), BE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", file.sub(0, 9), BE));
    let mut pos = u64::from(header.offset);
    if pos > 9 {
        cx.emit(Node::new("Header padding").span(file.sub(9, pos.saturating_sub(9))));
    }
    cx.emit(uint("Previous tag size", file.sub(pos, 4), 0, 32));
    pos = pos.saturating_add(4);
    let mut summary = Summary::default();
    let mut index = 0u32;
    while pos < file.len {
        let head = cx.read_avail(file.sub(pos, 16)).await?;
        if head.len() < 11 {
            cx.emit(Node::new("Trailing bytes").span(file.tail(pos)));
            break;
        }
        let kind = head.first().copied().unwrap_or(0) & 0x1f;
        let size = u64::from(crate::bytes::u24_be(&head, 1).unwrap_or(0));
        let ts = crate::bytes::u24_be(&head, 4).unwrap_or(0)
            | (u32::from(head.get(7).copied().unwrap_or(0)) << 24);
        let total = size.saturating_add(15);
        let tag = Tag {
            span: file.sub(pos, total),
            kind,
            size,
        };
        let body = cx.read_avail(tag.data().sub(0, 8)).await?;
        if index < 16 {
            summary.observe(&cx, &tag, &body).await;
            cx.annotate(summary.describe());
        }
        let name = crate::value::lookup(TAG_TYPES, kind.into())
            .map_or_else(|| format!("Tag type {kind}"), capitalise);
        let mut node = Node::new(name)
            .span(tag.span)
            .summary(tag_summary(kind, ts, size, &body))
            .lazy(expand_tag, tag);
        if tag.span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(file.source, tag.span.offset, total),
                tag.span.len,
            ));
        }
        cx.push(node).await;
        pos = pos.saturating_add(total);
        index = index.saturating_add(1);
    }
    Ok(())
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
            parts.push(vidutil::lookup_or(SOUND_FORMATS, (b >> 4).into()));
            if b >> 4 == 10 && body.get(1) == Some(&0) {
                parts.push("sequence header".to_owned());
            }
        }
        9 => {
            if b & 0x80 != 0 {
                parts.push(format!(
                    "{}, {}",
                    vidutil::fourcc(body.get(1..5).unwrap_or_default()),
                    vidutil::lookup_or(FRAME_TYPES, ((b >> 4) & 7).into())
                ));
            } else {
                parts.push(vidutil::lookup_or(VIDEO_CODECS, (b & 15).into()));
                parts.push(vidutil::lookup_or(FRAME_TYPES, (b >> 4).into()));
                if matches!(b & 15, 7 | 12) && body.get(1) == Some(&0) {
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
    cx.emit(uint("Timestamp", at(4, 4), ts.into(), 32).summary(seconds_ms(ts.into())));
    cx.emit(uint(
        "Stream ID",
        at(8, 3),
        crate::bytes::u24_be(&block.data, 8).unwrap_or(0).into(),
        24,
    ));
    let data = tag.data();
    match tag.kind {
        8 => audio(&cx, data).await?,
        9 => video(&cx, data).await?,
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
            node = node.diag(Diagnostic::warning("does not match the tag size"));
        }
        cx.emit(node);
    }
    Ok(())
}

async fn audio(cx: &Cx, data: Span) -> Result<()> {
    let d = cx.read_avail(data.sub(0, 16)).await?;
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
            let config = data.tail(2);
            let bytes = cx.read_avail(config.sub(0, 64)).await?;
            let mut node = Node::new("AudioSpecificConfig").span(config);
            if let Some(s) = vidutil::asc_summary(&bytes) {
                node = node.summary(s);
            }
            cx.emit(node);
            return Ok(());
        }
    }
    cx.emit(vidutil_bytes("Audio data", data.tail(at)));
    Ok(())
}

fn vidutil_bytes(name: &'static str, span: Span) -> Node {
    Node::new(name)
        .span(span)
        .summary(format!("{} bytes", span.len))
}

async fn video(cx: &Cx, data: Span) -> Result<()> {
    let d = cx.read_avail(data.sub(0, 16)).await?;
    let Some(&b) = d.first() else {
        return Ok(());
    };
    let s = data.sub(0, 1);
    if b & 0x80 != 0 {
        // Enhanced RTMP: frame type, packet type and a FourCC.
        cx.emit(enumerated(
            "Frame type",
            s,
            ((b >> 4) & 7).into(),
            3,
            FRAME_TYPES,
        ));
        cx.emit(
            uint("Packet type", s, (b & 15).into(), 4).summary(match b & 15 {
                0 => "sequence start",
                1 => "coded frames",
                2 => "sequence end",
                3 => "coded frames (no composition time)",
                4 => "metadata",
                _ => "other",
            }),
        );
        cx.emit(text(
            "FourCC",
            data.sub(1, 4),
            vidutil::fourcc(d.get(1..5).unwrap_or_default()),
        ));
        cx.emit(vidutil_bytes("Video data", data.tail(5)));
        return Ok(());
    }
    cx.emit(enumerated("Frame type", s, (b >> 4).into(), 4, FRAME_TYPES));
    cx.emit(enumerated("Codec ID", s, (b & 15).into(), 4, VIDEO_CODECS));
    if matches!(b & 15, 7 | 12) {
        let p = d.get(1).copied().unwrap_or(0);
        cx.emit(enumerated(
            "Packet type",
            data.sub(1, 1),
            p.into(),
            8,
            AVC_PACKET,
        ));
        let ct = crate::bytes::u24_be(&d, 2).unwrap_or(0);
        let ct = i32::from_ne_bytes((ct << 8).to_ne_bytes()) >> 8;
        cx.emit(
            Node::new("Composition time")
                .span(data.sub(2, 3))
                .value(Value::Int {
                    value: ct.into(),
                    bits: 24,
                }),
        );
        let payload = data.tail(5);
        if p == 0 {
            let bytes = cx.read_avail(payload.sub(0, 1024)).await?;
            let summary = if b & 15 == 7 {
                vidutil::avcc_summary(&bytes)
            } else {
                vidutil::hvcc_summary(&bytes)
            };
            let mut node = Node::new("Decoder configuration record").span(payload);
            if let Some(s) = summary {
                node = node.summary(s);
            }
            cx.emit(node);
        } else {
            cx.emit(vidutil_bytes("NAL units", payload));
        }
        return Ok(());
    }
    cx.emit(vidutil_bytes("Video data", data.tail(1)));
    Ok(())
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
        cx.push(amf_node(name, &d, pos, span, list.depth)).await;
        pos = end;
        index = index.saturating_add(1);
    }
    Ok(())
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
        _ => node.value(Value::Enum {
            raw: t.into(),
            bits: 8,
            name: crate::value::lookup(AMF_TYPES, t.into()),
        }),
    }
}

// ---------------------------------------------------------------------------
// File summary

#[derive(Default)]
struct Summary {
    width: Option<f64>,
    height: Option<f64>,
    video: Option<String>,
    audio: Option<String>,
    duration: Option<f64>,
}

impl Summary {
    async fn observe(&mut self, cx: &Cx, tag: &Tag, body: &[u8]) {
        let b = body.first().copied().unwrap_or(0);
        match tag.kind {
            8 if self.audio.is_none() => {
                self.audio =
                    crate::value::lookup(SOUND_FORMATS, (b >> 4).into()).map(str::to_owned);
            }
            9 if self.video.is_none() => {
                self.video = if b & 0x80 != 0 {
                    body.get(1..5).map(vidutil::fourcc)
                } else {
                    crate::value::lookup(VIDEO_CODECS, (b & 15).into()).map(str::to_owned)
                };
            }
            18 => {
                let Ok(d) = vidutil::read_small(cx, tag.data(), 0x10000).await else {
                    return;
                };
                self.metadata(&d);
            }
            _ => {}
        }
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
                (b"videocodecid", Some(n)) if self.video.is_none() => {
                    self.video = crate::value::lookup(VIDEO_CODECS, n as u64).map(str::to_owned);
                }
                (b"audiocodecid", Some(n)) if self.audio.is_none() => {
                    self.audio = crate::value::lookup(SOUND_FORMATS, n as u64).map(str::to_owned);
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
            streams.push(match (self.width, self.height) {
                (Some(w), Some(h)) if w > 0.0 => {
                    format!("{}×{} {v}", vidutil::num(w), vidutil::num(h))
                }
                _ => v.clone(),
            });
        }
        if let Some(a) = &self.audio {
            streams.push(a.clone());
        }
        if !streams.is_empty() {
            parts.push(streams.join(" + "));
        }
        if let Some(d) = self.duration {
            parts.push(vidutil::seconds_f64(d));
        }
        parts.join(", ")
    }
}
