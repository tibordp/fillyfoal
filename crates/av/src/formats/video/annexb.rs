//! H.264/AVC and H.265/HEVC elementary streams in Annex B byte-stream
//! format: NAL units separated by `00 00 01` start codes.
//!
//! Units are grouped into access units (one coded picture with the
//! parameter sets and SEI messages before it), listed in pages. Each unit
//! decodes on expansion: the NAL unit header, parameter sets (profile,
//! level, picture size and cropping, VUI with aspect ratio, colour and
//! timing, HRD), SEI messages, and slice headers, which are interpreted
//! with the parameter sets seen before them.

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::util::fmt::plural;
use crate::formats::util::vidutil::{self, NalCodec, ParamSets, parse_nal};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

pub static H264: Format = Format {
    name: "h264",
    title: "H.264/AVC elementary stream",
    extensions: &["h264", "264", "avc", "jsv", "26l"],
    mime: "video/h264",
    probe: Probe::Custom(|h| probe(h, NalCodec::Avc)),
    dissect: crate::expander!(dissect: Input),
};

pub static HEVC: Format = Format {
    name: "hevc",
    title: "H.265/HEVC elementary stream",
    extensions: &["hevc", "h265", "265", "bit"],
    mime: "video/h265",
    probe: Probe::Custom(|h| probe(h, NalCodec::Hevc)),
    dissect: crate::expander!(dissect: Input),
};

/// Whether `d` (a NAL unit) looks like a plausible unit of this codec.
fn plausible(codec: NalCodec, d: &[u8], first: bool) -> bool {
    let Some(&b0) = d.first() else {
        return false;
    };
    if b0 & 0x80 != 0 {
        return false;
    }
    let t = codec.nal_type(b0);
    match codec {
        NalCodec::Avc => {
            let ref_idc = b0 >> 5;
            match t {
                1 | 5 => !first,
                6 | 9 => ref_idc == 0,
                7 => {
                    ref_idc != 0
                        && d.get(1).is_some_and(|p| {
                            crate::value::lookup(vidutil::H264_PROFILES, (*p).into()).is_some()
                        })
                }
                8 => ref_idc != 0,
                10..=12 => !first,
                _ => false,
            }
        }
        NalCodec::Hevc => {
            let b1 = d.get(1).copied().unwrap_or(0);
            let layer = ((b0 & 1) << 5) | (b1 >> 3);
            let tid = b1 & 7;
            if layer != 0 || tid == 0 {
                return false;
            }
            if first {
                (32..=40).contains(&t)
            } else {
                t <= 21 || (32..=40).contains(&t)
            }
        }
    }
}

/// Start code length at `at` (3 or 4), if any.
fn start_code(d: &[u8], at: usize) -> Option<usize> {
    let w = d.get(at..at.saturating_add(4))?;
    if w.get(..3) == Some(&[0, 0, 1]) {
        Some(3)
    } else if w == [0, 0, 0, 1] {
        Some(4)
    } else {
        None
    }
}

fn probe(h: &Head<'_>, codec: NalCodec) -> bool {
    let Some(sc) = start_code(h.data, 0) else {
        return false;
    };
    let rest = h.data.get(sc..).unwrap_or_default();
    if !plausible(codec, rest, true) {
        return false;
    }
    // The next unit (if within the probe window) must be plausible too.
    let window = rest.get(..rest.len().min(4096)).unwrap_or_default();
    match window.windows(3).skip(1).position(|w| w == [0, 0, 1]) {
        Some(i) => window
            .get(i.saturating_add(4)..)
            .is_some_and(|next| plausible(codec, next, false)),
        None => to_u64(h.data.len()) == h.len,
    }
}

/// Bytes of a NAL unit read for its summary (headers and parameter sets).
const HEAD_BYTES: u64 = 4096;
/// Bytes of a NAL unit read when it is expanded.
const EXPAND_BYTES: u64 = 0x10000;
/// NAL units in one access unit at most (more start another group).
const MAX_AU_UNITS: u32 = 4096;

/// A NAL unit: where it is and the parameter sets in force before it.
#[derive(Clone, Debug)]
struct Unit {
    codec: NalCodec,
    /// The whole unit, start code included.
    span: Span,
    /// Length of the start code.
    prefix: u64,
    ps: Arc<ParamSets>,
}

impl Unit {
    fn nal(&self) -> Span {
        self.span.tail(self.prefix)
    }
}

/// An access unit: its span and the parameter sets before it.
#[derive(Clone, Debug)]
struct Au {
    codec: NalCodec,
    file: Span,
    span: Span,
    ps: Arc<ParamSets>,
}

/// Where the walk is: resumable state.
#[derive(Clone, Debug)]
struct Walk {
    pos: u64,
    index: u64,
    ps: Arc<ParamSets>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let codec = if probe_codec_is_hevc(&cx, input.span).await? {
        NalCodec::Hevc
    } else {
        NalCodec::Avc
    };
    let file = input.span;
    cx.annotate(stream_summary(&cx, file, codec).await?);
    let mut walk = match cx.resume::<Walk>() {
        Some(w) => w,
        None => {
            let Some(mut pos) = vidutil::next_start_code(&cx, file, 0).await? else {
                cx.emit(Node::new("Data").span(file));
                return Ok(());
            };
            // A 4-byte start code begins with an extra zero byte.
            if pos > 0 && cx.read_avail(file.sub(pos.saturating_sub(1), 1)).await? == [0] {
                pos = pos.saturating_sub(1);
            }
            if pos > 0 {
                cx.emit(Node::new("Leading data").span(file.sub(0, pos)));
            }
            Walk {
                pos,
                index: 0,
                ps: Arc::new(ParamSets::default()),
            }
        }
    };
    while walk.pos < file.len {
        let state = walk.clone();
        cx.mark(move || state);
        let start = walk.pos;
        let ps_before = walk.ps.clone();
        let mut stats = AuStats::default();
        let mut units = 0u32;
        while walk.pos < file.len && units < MAX_AU_UNITS {
            let (unit_span, prefix, end) = next_unit(&cx, file, walk.pos).await?;
            let nal = unit_span.tail(prefix);
            let d = vidutil::read_small(&cx, nal, HEAD_BYTES).await?;
            if units > 0 && stats.slices > 0 && starts_au(codec, &d) {
                break;
            }
            let (info, _) = parse_nal(codec, &d, nal, &walk.ps, false);
            advance(&mut walk.ps, &info);
            stats.add(codec, &info);
            units = units.saturating_add(1);
            walk.pos = end.max(walk.pos.saturating_add(prefix));
            cx.checkpoint().await;
        }
        let au = Au {
            codec,
            file,
            span: file.sub(start, walk.pos.saturating_sub(start)),
            ps: ps_before,
        };
        cx.progress_in(file, file.offset.saturating_add(start));
        cx.push(
            Node::new(format!("Access unit {}", walk.index))
                .span(au.span)
                .summary(stats.describe(units, au.span.len))
                .lazy(expand_au, au),
        )
        .await;
        walk.index = walk.index.saturating_add(1);
    }
    Ok(())
}

/// Records the parameter set a unit carried (copying the shared set only
/// when it changes).
fn advance(ps: &mut Arc<ParamSets>, info: &vidutil::NalInfo) {
    if info.sps.is_none() && info.pps.is_none() {
        return;
    }
    let mut next = (**ps).clone();
    if next.update(info.sps.as_ref(), info.pps.as_ref()) {
        *ps = Arc::new(next);
    }
}

/// The unit at `pos`: its span (start code included), start code length,
/// and where the next one begins.
async fn next_unit(cx: &Cx, file: Span, pos: u64) -> Result<(Span, u64, u64)> {
    let head = cx.read_avail(file.sub(pos, 4)).await?;
    let prefix = to_u64(start_code(&head, 0).unwrap_or(3));
    let next = vidutil::next_start_code(cx, file, pos.saturating_add(prefix))
        .await?
        .unwrap_or(file.len);
    let mut end = next;
    // A zero byte before the next start code belongs to it (4-byte form).
    if end < file.len
        && end > pos
        && cx.read_avail(file.sub(end.saturating_sub(1), 1)).await? == [0]
    {
        end = end.saturating_sub(1);
    }
    let len = end.saturating_sub(pos).max(prefix);
    Ok((file.sub(pos, len), prefix, end))
}

/// Whether a NAL unit (seen after a slice of the current access unit)
/// begins the next access unit (H.264 7.4.1.2.3, H.265 7.4.2.4.4).
fn starts_au(codec: NalCodec, d: &[u8]) -> bool {
    let Some(&b0) = d.first() else {
        return false;
    };
    let t = codec.nal_type(b0);
    match codec {
        NalCodec::Avc => match t {
            6..=9 | 14..=18 => true,
            // first_mb_in_slice == 0: its ue(v) code is a single 1 bit.
            1 | 5 => d.get(1).is_some_and(|b| b & 0x80 != 0),
            _ => false,
        },
        NalCodec::Hevc => match t {
            32..=35 | 39 | 41..=44 | 48..=55 => true,
            // first_slice_segment_in_pic_flag.
            0..=9 | 16..=21 => d.get(2).is_some_and(|b| b & 0x80 != 0),
            _ => false,
        },
    }
}

/// What an access unit holds, for its summary.
#[derive(Default)]
struct AuStats {
    slices: u32,
    kinds: Vec<&'static str>,
    others: Vec<&'static str>,
    irap: Option<&'static str>,
    frame_num: Option<u64>,
    poc: Option<u64>,
    field: Option<bool>,
}

impl AuStats {
    fn add(&mut self, codec: NalCodec, info: &vidutil::NalInfo) {
        let t = info.nal_type;
        if codec.is_slice(t) {
            self.slices = self.slices.saturating_add(1);
            if let Some(s) = &info.slice {
                let k = s.kind();
                if !self.kinds.contains(&k) {
                    self.kinds.push(k);
                }
                if self.slices == 1 {
                    self.frame_num = s.frame_num;
                    self.poc = s.poc_lsb;
                    self.field = s.field;
                }
            }
            let irap = match (codec, t) {
                (NalCodec::Avc, 5) | (NalCodec::Hevc, 19 | 20) => Some("IDR"),
                (NalCodec::Hevc, 21) => Some("CRA"),
                (NalCodec::Hevc, 16..=18) => Some("BLA"),
                _ => None,
            };
            if irap.is_some() {
                self.irap = irap;
            }
            return;
        }
        let name = match (codec, t) {
            (NalCodec::Avc, 7) | (NalCodec::Hevc, 33) => "SPS",
            (NalCodec::Avc, 8) | (NalCodec::Hevc, 34) => "PPS",
            (NalCodec::Hevc, 32) => "VPS",
            (NalCodec::Avc, 6) | (NalCodec::Hevc, 39 | 40) => "SEI",
            (NalCodec::Avc, 9) | (NalCodec::Hevc, 35) => "AUD",
            (NalCodec::Avc, 10) | (NalCodec::Hevc, 36) => "end of sequence",
            (NalCodec::Avc, 11) | (NalCodec::Hevc, 37) => "end of stream",
            (NalCodec::Avc, 12) | (NalCodec::Hevc, 38) => "filler",
            _ => "other",
        };
        if !self.others.contains(&name) {
            self.others.push(name);
        }
    }

    fn describe(&self, units: u32, bytes: u64) -> String {
        let mut parts = Vec::new();
        if !self.kinds.is_empty() {
            let mut pic = format!(
                "{} {}",
                self.kinds.join("/"),
                match self.field {
                    Some(false) => "top field",
                    Some(true) => "bottom field",
                    None => "frame",
                }
            );
            if let Some(i) = self.irap {
                pic = format!("{pic} ({i})");
            }
            parts.push(pic);
        } else if self.slices > 0 {
            parts.push(plural(self.slices, "slice"));
        }
        if let Some(f) = self.frame_num {
            parts.push(format!("frame_num {f}"));
        }
        if let Some(p) = self.poc {
            parts.push(format!("POC lsb {p}"));
        }
        if !self.others.is_empty() {
            parts.push(format!("with {}", self.others.join(", ")));
        }
        parts.push(format!("{}, {bytes} bytes", plural(units, "NAL unit")));
        parts.join(", ")
    }
}

/// "H.264 elementary stream, High@L3.1, 1280×720, ..." from the units in
/// the first 64 KiB.
async fn stream_summary(cx: &Cx, file: Span, codec: NalCodec) -> Result<String> {
    let head = cx.read_avail(file.sub(0, 0x10000)).await?;
    let mut ps = ParamSets::default();
    let mut sps = None;
    let mut encoder = None;
    let mut at = 0usize;
    let mut units = 0u32;
    while units < 256 && (sps.is_none() || encoder.is_none()) {
        let Some(i) = vidutil::find(head.get(at..).unwrap_or_default(), &[0, 0, 1]) else {
            break;
        };
        let start = at.saturating_add(i).saturating_add(3);
        let rest = head.get(start..).unwrap_or_default();
        let len = vidutil::find(rest, &[0, 0, 1]).unwrap_or(rest.len());
        let nal = rest.get(..len.min(4096)).unwrap_or_default();
        let span = vidutil::at(file, start, len);
        let (info, _) = parse_nal(codec, nal, span, &ps, false);
        ps.update(info.sps.as_ref(), info.pps.as_ref());
        if sps.is_none() {
            sps = info.sps;
        }
        if encoder.is_none() {
            encoder = info.encoder;
        }
        at = start;
        units = units.saturating_add(1);
    }
    let mut s = format!("{} elementary stream", codec.name());
    if let Some(sps) = sps {
        s = format!("{s}, {}", sps.describe());
    }
    if let Some(e) = encoder {
        s = format!("{s} ({e})");
    }
    Ok(s)
}

/// Decides between H.264 and HEVC from the first unit.
async fn probe_codec_is_hevc(cx: &Cx, file: Span) -> Result<bool> {
    let d = cx.read_avail(file.sub(0, 4096)).await?;
    Ok(start_code(&d, 0)
        .is_some_and(|sc| plausible(NalCodec::Hevc, d.get(sc..).unwrap_or_default(), true)))
}

async fn expand_au(cx: Cx, au: Au) -> Result<()> {
    let mut ps = au.ps.clone();
    let mut pos = au.span.offset.saturating_sub(au.file.offset);
    let end = au.span.end().saturating_sub(au.file.offset);
    while pos < end {
        let (span, prefix, next) = next_unit(&cx, au.file, pos).await?;
        let span = span.sub(0, end.saturating_sub(pos));
        let nal = span.tail(prefix);
        let d = vidutil::read_small(&cx, nal, HEAD_BYTES).await?;
        let (info, _) = parse_nal(au.codec, &d, nal, &ps, false);
        let name = match d.first() {
            Some(&b) if b & 0x80 == 0 => {
                vidutil::lookup_or(au.codec.types(), au.codec.nal_type(b).into())
            }
            _ => "Invalid NAL unit".to_owned(),
        };
        let unit = Unit {
            codec: au.codec,
            span,
            prefix,
            ps: ps.clone(),
        };
        let summary = match &info.summary {
            Some(s) => format!("{s}, {} bytes", nal.len),
            None => format!("{} bytes", nal.len),
        };
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(expand_unit, unit),
        )
        .await;
        advance(&mut ps, &info);
        pos = next.max(pos.saturating_add(prefix));
    }
    Ok(())
}

async fn expand_unit(cx: Cx, unit: Unit) -> Result<()> {
    cx.emit(
        Node::new("Start code")
            .span(unit.span.sub(0, unit.prefix))
            .summary(format!("{} bytes", unit.prefix)),
    );
    let nal = unit.nal();
    let d = vidutil::read_small(&cx, nal, EXPAND_BYTES).await?;
    let (_, nodes) = parse_nal(unit.codec, &d, nal, &unit.ps, true);
    for node in nodes {
        cx.emit(node);
    }
    Ok(())
}
