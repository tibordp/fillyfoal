//! Coded video frames shared by the containers that carry them unframed:
//! FLV, ISO BMFF samples and Matroska blocks.
//!
//! A container hands over the frame's bytes and the decoder configuration
//! record of its track (`avcC`, `hvcC`, `av1C`); the frame is split into
//! length-prefixed NAL units (slice headers decoded with the parameter sets
//! of the record), AV1 OBUs, or a VP9 frame header.

use std::sync::Arc;

use crate::bytes::u16_be;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::vidutil::bitwalk::Walker;
use crate::formats::util::vidutil::nal::{self, NalCodec, group};
use crate::formats::util::vidutil::{self, ParamSets, av1::SeqInfo, detached, vp9};
use crate::node::Node;
use crate::span::Span;

/// How a track's frames are coded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    #[default]
    Other,
    /// H.264 with length-prefixed NAL units (`avc1`/`avc3`).
    Avc,
    /// HEVC with length-prefixed NAL units (`hvc1`/`hev1`).
    Hevc,
    /// AV1 OBUs in the low-overhead format.
    Av1,
    Vp9,
}

impl Kind {
    /// The kind for an ISO BMFF / FLV FourCC.
    pub fn from_fourcc(fourcc: &[u8; 4]) -> Kind {
        match fourcc {
            b"avc1" | b"avc2" | b"avc3" | b"avc4" => Kind::Avc,
            b"hvc1" | b"hev1" => Kind::Hevc,
            b"av01" => Kind::Av1,
            b"vp09" => Kind::Vp9,
            _ => Kind::Other,
        }
    }
}

/// Decoder state carried from a track's configuration record to its frames.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub kind: Kind,
    /// Parameter sets from the configuration record.
    pub ps: Arc<ParamSets>,
    /// Bytes in each NAL unit's length prefix (1, 2 or 4).
    pub length_size: u64,
    /// The AV1 sequence header from the configuration record.
    pub seq: Option<SeqInfo>,
}

impl Config {
    /// A configuration with no record: 4-byte NAL lengths, no parameter
    /// sets.
    pub fn bare(kind: Kind) -> Config {
        Config {
            kind,
            length_size: 4,
            ..Config::default()
        }
    }

    /// The configuration from a decoder configuration record (`avcC`,
    /// `hvcC` or `av1C` bytes, read whole; they are small).
    pub fn from_record(kind: Kind, d: &[u8]) -> Config {
        let mut c = Config::bare(kind);
        match kind {
            Kind::Avc | Kind::Hevc => {
                let hevc = kind == Kind::Hevc;
                let mut ps = ParamSets::default();
                collect_param_sets(d, hevc, &mut ps);
                c.ps = Arc::new(ps);
                let at = if hevc { 21 } else { 4 };
                c.length_size = u64::from(d.get(at).copied().unwrap_or(3) & 3).saturating_add(1);
            }
            Kind::Av1 => {
                let (_, seq, _) = nal::av1c_config(d, detached(0), false);
                c.seq = seq;
            }
            Kind::Vp9 | Kind::Other => {}
        }
        c
    }

    /// Whether [`frames`] decodes anything for this track.
    pub fn splits(&self) -> bool {
        self.kind != Kind::Other
    }
}

/// The SPS and PPS of an `avcC`/`hvcC` record.
fn collect_param_sets(d: &[u8], hevc: bool, ps: &mut ParamSets) {
    let codec = if hevc { NalCodec::Hevc } else { NalCodec::Avc };
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
        let (info, _) = nal::parse_nal(codec, u, detached(0), ps, false);
        ps.update(info.sps.as_ref(), info.pps.as_ref());
    }
}

/// Emits the coded data of one frame at `payload`: NAL units (pushed, one
/// per unit), OBUs, or a VP9 frame header and the frame data.
pub async fn frames(cx: &Cx, payload: Span, c: &Config) -> Result<()> {
    match c.kind {
        Kind::Avc | Kind::Hevc => {
            let nal_codec = if c.kind == Kind::Hevc {
                NalCodec::Hevc
            } else {
                NalCodec::Avc
            };
            let size = c.length_size.clamp(1, 4);
            let mut pos = 0u64;
            let mut ps = (*c.ps).clone();
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
        Kind::Av1 => {
            let d = vidutil::read_small(cx, payload, 0x10000).await?;
            let mut w = Walker::new(&d, payload, false, true);
            let mut seq = c.seq;
            let ok = nal::obus(&mut w, &mut seq).is_some();
            for node in w.finish(ok) {
                cx.emit(node);
            }
        }
        Kind::Vp9 => {
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
        Kind::Other => cx.emit(bytes_node("Video data", payload)),
    }
    Ok(())
}

/// The state of a lazily split frame: [`expand`].
#[derive(Clone, Debug)]
pub struct Frame {
    pub span: Span,
    pub config: Arc<Config>,
}

/// Expander for a frame node: `node.lazy(coded::expand, Frame { .. })`.
pub async fn expand(cx: Cx, f: Frame) -> Result<()> {
    frames(&cx, f.span, &f.config).await
}

fn bytes_node(name: &'static str, span: Span) -> Node {
    Node::new(name)
        .span(span)
        .summary(format!("{} bytes", span.len))
}
