//! Entry points over whole NAL units and codec configuration records:
//! decode a unit for its summary, or decode it into nodes for display.

use std::sync::Arc;

use super::av1::{self, SeqInfo};
use super::bitwalk::Walker;
use super::params::{ParamSets, PpsInfo, SliceInfo, SpsInfo};
use super::{audio, h264, hevc, sei, vp9};
use crate::formats::util::arcutil::emit_nodes;
use crate::node::Node;
use crate::span::Span;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NalCodec {
    Avc,
    Hevc,
}

impl NalCodec {
    /// The NAL unit type from the first header byte.
    pub fn nal_type(self, b0: u8) -> u8 {
        match self {
            NalCodec::Avc => b0 & 0x1f,
            NalCodec::Hevc => (b0 >> 1) & 0x3f,
        }
    }

    pub fn types(self) -> crate::value::EnumTable {
        match self {
            NalCodec::Avc => super::tables::H264_NAL_TYPES,
            NalCodec::Hevc => super::tables::HEVC_NAL_TYPES,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            NalCodec::Avc => "H.264",
            NalCodec::Hevc => "HEVC",
        }
    }

    /// Whether a NAL unit of this type starts a coded picture's slice data.
    pub fn is_slice(self, t: u64) -> bool {
        match self {
            NalCodec::Avc => matches!(t, 1 | 5),
            NalCodec::Hevc => t <= 9 || (16..=21).contains(&t),
        }
    }
}

/// What a NAL unit holds, as far as it was decoded.
#[derive(Clone, Debug, Default)]
pub struct NalInfo {
    pub nal_type: u64,
    /// H.264 `nal_ref_idc`; HEVC `nuh_layer_id`.
    pub ref_idc: u64,
    pub sps: Option<SpsInfo>,
    pub pps: Option<PpsInfo>,
    pub slice: Option<SliceInfo>,
    /// A one-line description of the content.
    pub summary: Option<String>,
    /// An encoder version from a user data SEI message ("x264 core 164").
    pub encoder: Option<String>,
}

/// Decodes a NAL unit (header included, emulation prevention bytes still
/// present) whose bytes are at `base`. With `emit`, also returns its
/// syntax elements as nodes. Callers bound `nal` (parameter sets and
/// headers are small; the slice data is never read).
pub fn parse_nal(
    codec: NalCodec,
    nal: &[u8],
    base: Span,
    ps: &ParamSets,
    emit: bool,
) -> (NalInfo, Vec<Node>) {
    let mut w = Walker::new(nal, base, true, emit);
    let mut info = NalInfo::default();
    let ok = match codec {
        NalCodec::Avc => parse_avc(&mut w, &mut info, ps),
        NalCodec::Hevc => parse_hevc(&mut w, &mut info, ps),
    }
    .is_some();
    (info, w.finish(ok))
}

fn parse_avc(w: &mut Walker, info: &mut NalInfo, ps: &ParamSets) -> Option<()> {
    w.begin("NAL unit header");
    let (r, t) = h264::nal_header(w)?;
    w.end_summary(|| {
        format!(
            "{}, nal_ref_idc {r}",
            super::tables::lookup_or(super::tables::H264_NAL_TYPES, t)
        )
    });
    info.nal_type = t;
    info.ref_idc = r;
    match t {
        7 => {
            w.begin("Sequence parameter set");
            let s = h264::sps(w);
            if let Some(s) = &s {
                info.summary = Some(s.describe());
                let text = s.describe();
                w.end_summary(|| text);
            }
            info.sps = Some(s?);
        }
        8 => {
            w.begin("Picture parameter set");
            let p = h264::pps(w, ps)?;
            let text = format!(
                "PPS {} for SPS {}, {}",
                p.id,
                p.sps_id,
                if p.cabac { "CABAC" } else { "CAVLC" }
            );
            info.summary = Some(text.clone());
            w.end_summary(|| text);
            info.pps = Some(p);
        }
        1 | 5 => {
            w.begin("Slice header");
            let mut s = SliceInfo::default();
            let r = h264::slice_header(w, t, r, ps, &mut s);
            if s.parsed {
                info.summary = Some(s.describe());
                info.slice = Some(s);
                let text = s.describe();
                w.end_summary(|| text);
            }
            r?;
            if w.emitting() && ps.for_pps(s.pps_id).is_some() {
                let rest = w.rest_span(w.pos());
                w.push(
                    Node::new("Slice data")
                        .span(rest)
                        .summary(format!("{} bytes", rest.len)),
                );
            }
        }
        6 => {
            w.begin("SEI messages");
            let names = sei::sei_rbsp(w, false, ps.last());
            if let Some(n) = &names
                && !n.is_empty()
            {
                info.summary = Some(n.join("; "));
                info.encoder = encoder(n);
            }
            let count = names.as_ref().map_or(0, Vec::len);
            w.end_summary(|| super::plural(crate::bytes::to_u64(count), "message"));
            names?;
        }
        9 => {
            let p = h264::aud(w)?;
            info.summary = Some(format!(
                "primary picture types {}",
                super::tables::lookup_or(h264::PRIMARY_PIC_TYPES, p)
            ));
        }
        _ => {}
    }
    Some(())
}

fn parse_hevc(w: &mut Walker, info: &mut NalInfo, ps: &ParamSets) -> Option<()> {
    w.begin("NAL unit header");
    let (t, layer, tid) = hevc::nal_header(w)?;
    w.end_summary(|| {
        format!(
            "{}, layer {layer}, temporal ID {}",
            super::tables::lookup_or(super::tables::HEVC_NAL_TYPES, t),
            tid.saturating_sub(1)
        )
    });
    info.nal_type = t;
    info.ref_idc = layer;
    match t {
        32 => {
            w.begin("Video parameter set");
            let v = hevc::vps(w)?;
            let text = v.profile_level();
            info.summary = Some(text.clone());
            w.end_summary(|| text);
        }
        33 => {
            w.begin("Sequence parameter set");
            let s = hevc::sps(w);
            if let Some(s) = &s {
                info.summary = Some(s.describe());
                let text = s.describe();
                w.end_summary(|| text);
            }
            info.sps = Some(s?);
        }
        34 => {
            w.begin("Picture parameter set");
            let p = hevc::pps(w)?;
            let text = format!("PPS {} for SPS {}", p.id, p.sps_id);
            info.summary = Some(text.clone());
            w.end_summary(|| text);
            info.pps = Some(p);
        }
        0..=9 | 16..=21 => {
            w.begin("Slice segment header");
            let mut s = SliceInfo {
                hevc: true,
                ..SliceInfo::default()
            };
            let r = hevc::slice_header(w, t, ps, &mut s);
            if s.parsed {
                info.summary = Some(s.describe());
                info.slice = Some(s);
                let text = s.describe();
                w.end_summary(|| text);
            }
            r?;
        }
        35 => {
            let p = hevc::aud(w)?;
            info.summary = Some(format!(
                "picture types {}",
                super::tables::lookup_or(&[(0, "I"), (1, "I, P"), (2, "I, P, B")], p)
            ));
        }
        39 | 40 => {
            w.begin("SEI messages");
            let names = sei::sei_rbsp(w, true, ps.last());
            if let Some(n) = &names
                && !n.is_empty()
            {
                info.summary = Some(n.join("; "));
                info.encoder = encoder(n);
            }
            let count = names.as_ref().map_or(0, Vec::len);
            w.end_summary(|| super::plural(crate::bytes::to_u64(count), "message"));
            names?;
        }
        _ => {}
    }
    Some(())
}

/// The encoder version among SEI message summaries.
fn encoder(names: &[String]) -> Option<String> {
    names.iter().find_map(|n| {
        let rest = n.strip_prefix("user data unregistered: ")?;
        (rest.starts_with("x264 core") || rest.starts_with("x265 ")).then(|| rest.to_owned())
    })
}

/// A lazy node holding `nodes`.
pub fn group(
    name: impl Into<std::borrow::Cow<'static, str>>,
    span: Span,
    nodes: Vec<Node>,
) -> Node {
    let node = Node::new(name).span(span);
    if nodes.is_empty() {
        node
    } else {
        node.lazy(emit_nodes, Arc::new(nodes))
    }
}

/// A node for a NAL unit embedded in a configuration record, decoded.
pub fn nal_node(codec: NalCodec, nal: &[u8], span: Span, ps: &ParamSets) -> (Node, NalInfo) {
    let (info, nodes) = parse_nal(codec, nal, span, ps, true);
    let name = nal
        .first()
        .map(|&b| super::tables::lookup_or(codec.types(), codec.nal_type(b).into()))
        .unwrap_or_else(|| "NAL unit".to_owned());
    let node = group(name, span, nodes).summary(match &info.summary {
        Some(s) => format!("{s}, {} bytes", nal.len()),
        None => format!("{} bytes", nal.len()),
    });
    (node, info)
}

/// Reads a 16-bit length and that many bytes of NAL unit, as a node.
/// Returns the SPS it held, if any (`None` if the record ends early).
fn length_prefixed(
    w: &mut Walker,
    codec: NalCodec,
    name: &'static str,
    ps: &mut ParamSets,
) -> Option<Option<SpsInfo>> {
    let len = usize::try_from(w.u(name, 16)?).ok()?;
    let start = w.pos();
    let nal = w.read_bytes(len)?;
    let span = w.since(start);
    let info = if w.emitting() {
        let (node, info) = nal_node(codec, &nal, span, ps);
        w.push(node);
        info
    } else {
        parse_nal(codec, &nal, span, ps, false).0
    };
    ps.update(info.sps.as_ref(), info.pps.as_ref());
    Some(info.sps)
}

/// `AVCDecoderConfigurationRecord` (`avcC`), decoded into nodes with its
/// parameter sets. Returns the SPS's description.
pub fn avcc(d: &[u8], base: Span, emit: bool) -> (Option<SpsInfo>, Vec<Node>) {
    let mut w = Walker::new(d, base, false, emit);
    let mut sps = None;
    let ok = avcc_walk(&mut w, &mut sps).is_some();
    (sps, w.finish(ok))
}

fn avcc_walk(w: &mut Walker, sps: &mut Option<SpsInfo>) -> Option<()> {
    let mut ps = ParamSets::default();
    w.u("configurationVersion", 8)?;
    let profile = w.en("AVCProfileIndication", 8, super::tables::H264_PROFILES)?;
    w.x("profile_compatibility", 8)?;
    let level = w.u("AVCLevelIndication", 8)?;
    w.summary(|| format!("{}.{}", level / 10, level % 10));
    w.u("reserved", 6)?;
    let len = w.u("lengthSizeMinusOne", 2)?;
    w.summary(|| format!("{}-byte NAL unit lengths", len.saturating_add(1)));
    w.u("reserved", 3)?;
    let n = w.u("numOfSequenceParameterSets", 5)?;
    for _ in 0..n {
        let s = length_prefixed(w, NalCodec::Avc, "sequenceParameterSetLength", &mut ps)?;
        if sps.is_none() {
            *sps = s;
        }
    }
    let n = w.u("numOfPictureParameterSets", 8)?;
    for _ in 0..n {
        length_prefixed(w, NalCodec::Avc, "pictureParameterSetLength", &mut ps)?;
    }
    if matches!(profile, 100 | 110 | 122 | 144) && w.bits_left() >= 32 {
        w.u("reserved", 6)?;
        w.en("chroma_format", 2, super::tables::CHROMA_FORMATS)?;
        w.u("reserved", 5)?;
        w.u("bit_depth_luma_minus8", 3)?;
        w.u("reserved", 5)?;
        w.u("bit_depth_chroma_minus8", 3)?;
        let n = w.u("numOfSequenceParameterSetExt", 8)?;
        for _ in 0..n {
            length_prefixed(w, NalCodec::Avc, "sequenceParameterSetExtLength", &mut ps)?;
        }
    }
    Some(())
}

/// `HEVCDecoderConfigurationRecord` (`hvcC`), decoded into nodes with its
/// parameter sets.
pub fn hvcc(d: &[u8], base: Span, emit: bool) -> (Option<SpsInfo>, Vec<Node>) {
    let mut w = Walker::new(d, base, false, emit);
    let mut sps = None;
    let ok = hvcc_walk(&mut w, &mut sps).is_some();
    (sps, w.finish(ok))
}

fn hvcc_walk(w: &mut Walker, sps: &mut Option<SpsInfo>) -> Option<()> {
    let mut ps = ParamSets::default();
    w.u("configurationVersion", 8)?;
    w.u("general_profile_space", 2)?;
    w.flag("general_tier_flag")?;
    w.en("general_profile_idc", 5, super::tables::HEVC_PROFILES)?;
    w.x("general_profile_compatibility_flags", 32)?;
    w.x("general_constraint_indicator_flags", 48)?;
    let level = u8::try_from(w.u("general_level_idc", 8)?).ok()?;
    w.summary(|| super::tables::hevc_level_name(level));
    w.u("reserved", 4)?;
    w.u("min_spatial_segmentation_idc", 12)?;
    w.u("reserved", 6)?;
    w.en(
        "parallelismType",
        2,
        &[
            (0, "unknown"),
            (1, "slices"),
            (2, "tiles"),
            (3, "wavefront"),
        ],
    )?;
    w.u("reserved", 6)?;
    w.en("chromaFormat", 2, super::tables::CHROMA_FORMATS)?;
    w.u("reserved", 5)?;
    w.u("bitDepthLumaMinus8", 3)?;
    w.u("reserved", 5)?;
    w.u("bitDepthChromaMinus8", 3)?;
    let rate = w.u("avgFrameRate", 16)?;
    w.summary(|| format!("{} fps", super::num(rate as f64 / 256.0)));
    w.u("constantFrameRate", 2)?;
    w.u("numTemporalLayers", 3)?;
    w.flag("temporalIdNested")?;
    let len = w.u("lengthSizeMinusOne", 2)?;
    w.summary(|| format!("{}-byte NAL unit lengths", len.saturating_add(1)));
    let arrays = w.u("numOfArrays", 8)?;
    for i in 0..arrays {
        w.begin(format!("Array {i}"));
        w.flag("array_completeness")?;
        w.u("reserved", 1)?;
        let t = w.en("NAL_unit_type", 6, super::tables::HEVC_NAL_TYPES)?;
        let n = w.u("numNalus", 16)?;
        for _ in 0..n {
            let s = length_prefixed(w, NalCodec::Hevc, "nalUnitLength", &mut ps)?;
            if t == 33 && sps.is_none() {
                *sps = s;
            }
        }
        w.end_summary(|| {
            format!(
                "{}, {}",
                super::tables::lookup_or(super::tables::HEVC_NAL_TYPES, t),
                super::plural(n, "unit")
            )
        });
    }
    Some(())
}

/// `AV1CodecConfigurationRecord` (`av1C`) with its config OBUs.
pub fn av1c(d: &[u8], base: Span, emit: bool) -> (Option<String>, Vec<Node>) {
    let mut w = Walker::new(d, base, false, emit);
    let summary = av1::av1c(&mut w);
    let mut ok = summary.is_some();
    let mut seq: Option<SeqInfo> = None;
    if ok {
        ok = obus(&mut w, &mut seq).is_some();
    }
    let summary = seq.map(|s| s.describe()).or(summary);
    (summary, w.finish(ok))
}

/// The OBUs from the walker's position to its end, each as a node.
pub fn obus(w: &mut Walker, seq: &mut Option<SeqInfo>) -> Option<Vec<av1::Obu>> {
    let mut out = Vec::new();
    while w.bits_left() >= 8 && out.len() < 4096 {
        let start = w.pos();
        w.begin("OBU");
        let depth = w.depth();
        let Some(o) = av1::obu(w, seq) else {
            w.fail_to(depth);
            w.end();
            return None;
        };
        let name = super::tables::lookup_or(av1::OBU_TYPES, o.kind);
        let summary = match &o.summary {
            Some(s) => format!("{s}, {} bytes", o.len),
            None => format!("{} bytes", o.len),
        };
        w.rename(name);
        w.end_summary(|| summary);
        if w.pos() <= start {
            break;
        }
        out.push(o);
    }
    Some(out)
}

/// `VPCodecConfigurationRecord` as in `vpcC` (version and flags first).
pub fn vpcc(d: &[u8], base: Span, emit: bool) -> (Option<String>, Vec<Node>) {
    let mut w = Walker::new(d, base, false, emit);
    let summary = (|| {
        w.u("version", 8)?;
        w.x("flags", 24)?;
        vp9::vpcc(&mut w)
    })();
    let ok = summary.is_some();
    (summary, w.finish(ok))
}

/// An MPEG-4 AudioSpecificConfig, decoded into nodes.
pub fn asc(d: &[u8], base: Span, emit: bool) -> (Option<audio::AscInfo>, Vec<Node>) {
    let mut w = Walker::new(d, base, false, emit);
    let a = audio::audio_specific_config(&mut w);
    let ok = a.is_some();
    (a, w.finish(ok))
}
