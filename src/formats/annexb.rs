//! H.264/AVC and H.265/HEVC elementary streams in Annex B byte-stream
//! format: NAL units separated by `00 00 01` start codes. Units are listed
//! in pages with their type names; parameter sets, SEI messages and slice
//! headers are summarised.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::vidutil::{
    self, Bits, H264_NAL_TYPES, HEVC_NAL_TYPES, SpsInfo, enumerated, flag_node, h264_sps, hevc_sps,
    text, uint, unescape_rbsp,
};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

pub static H264: Format = Format {
    name: "h264",
    title: "H.264/AVC elementary stream",
    extensions: &["h264", "264", "avc", "jsv", "26l"],
    mime: "video/h264",
    probe: Probe::Custom(|h| probe(h, Codec::Avc)),
    dissect: crate::expander!(dissect: Input),
};

pub static HEVC: Format = Format {
    name: "hevc",
    title: "H.265/HEVC elementary stream",
    extensions: &["hevc", "h265", "265", "bit"],
    mime: "video/h265",
    probe: Probe::Custom(|h| probe(h, Codec::Hevc)),
    dissect: crate::expander!(dissect: Input),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Codec {
    Avc,
    Hevc,
}

impl Codec {
    fn nal_type(self, d: &[u8]) -> Option<u8> {
        let b0 = *d.first()?;
        if b0 & 0x80 != 0 {
            return None;
        }
        Some(match self {
            Codec::Avc => b0 & 0x1f,
            Codec::Hevc => (b0 >> 1) & 0x3f,
        })
    }

    fn header_len(self) -> u64 {
        match self {
            Codec::Avc => 1,
            Codec::Hevc => 2,
        }
    }

    fn types(self) -> EnumTable {
        match self {
            Codec::Avc => H264_NAL_TYPES,
            Codec::Hevc => HEVC_NAL_TYPES,
        }
    }

    /// Whether `d` (a NAL unit) looks like a plausible unit of this codec.
    fn plausible(self, d: &[u8], first: bool) -> bool {
        let Some(t) = self.nal_type(d) else {
            return false;
        };
        match self {
            Codec::Avc => {
                let ref_idc = d.first().copied().unwrap_or(0) >> 5;
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
            Codec::Hevc => {
                let b1 = d.get(1).copied().unwrap_or(0);
                let layer = ((d.first().copied().unwrap_or(0) & 1) << 5) | (b1 >> 3);
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

fn probe(h: &Head<'_>, codec: Codec) -> bool {
    let Some(sc) = start_code(h.data, 0) else {
        return false;
    };
    let rest = h.data.get(sc..).unwrap_or_default();
    if !codec.plausible(rest, true) {
        return false;
    }
    // The next unit (if within the probe window) must be plausible too.
    let window = rest.get(..rest.len().min(4096)).unwrap_or_default();
    match window.windows(3).skip(1).position(|w| w == [0, 0, 1]) {
        Some(i) => window
            .get(i.saturating_add(4)..)
            .is_some_and(|next| codec.plausible(next, false)),
        None => to_u64(h.data.len()) == h.len,
    }
}

#[derive(Clone, Copy, Debug)]
struct Unit {
    codec: Codec,
    /// The whole unit, start code included.
    span: Span,
    /// Length of the start code.
    prefix: u64,
}

impl Unit {
    fn nal(&self) -> Span {
        self.span.tail(self.prefix)
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let codec = if probe_codec_is_hevc(&cx, input.span).await? {
        Codec::Hevc
    } else {
        Codec::Avc
    };
    let file = input.span;
    let name = match codec {
        Codec::Avc => "H.264",
        Codec::Hevc => "HEVC",
    };
    cx.annotate(format!("{name} elementary stream"));
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
    let mut annotated = false;
    let mut index = 0u32;
    while pos < file.len {
        let head = cx.read_avail(file.sub(pos, 4)).await?;
        let prefix = to_u64(start_code(&head, 0).unwrap_or(3));
        let next = vidutil::next_start_code(&cx, file, pos.saturating_add(prefix))
            .await?
            .unwrap_or(file.len);
        let mut end = next;
        if end < file.len
            && end > pos
            && cx.read_avail(file.sub(end.saturating_sub(1), 1)).await? == [0]
        {
            end = end.saturating_sub(1);
        }
        let unit = Unit {
            codec,
            span: file.sub(pos, end.saturating_sub(pos).max(prefix)),
            prefix,
        };
        let d = vidutil::read_small(&cx, unit.nal(), 4096).await?;
        let t = codec.nal_type(&d);
        let name = match t {
            Some(t) => vidutil::lookup_or(codec.types(), t.into()),
            None => "Invalid NAL unit".to_owned(),
        };
        let summary = unit_summary(codec, t, &d);
        if !annotated
            && index < 64
            && let Some(sps) = sps_info(codec, t, &d)
        {
            annotated = true;
            let detail = match codec {
                Codec::Avc => sps.h264_summary(),
                Codec::Hevc => sps.hevc_summary(),
            };
            cx.annotate(format!(
                "{name} elementary stream, {detail}",
                name = match codec {
                    Codec::Avc => "H.264",
                    Codec::Hevc => "HEVC",
                }
            ));
        }
        let mut node = Node::new(name).span(unit.span).lazy(expand_unit, unit);
        node = node.summary(match summary {
            Some(s) => format!("{s}, {} bytes", unit.nal().len),
            None => format!("{} bytes", unit.nal().len),
        });
        cx.push(node).await;
        pos = end.max(pos.saturating_add(prefix));
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Decides between H.264 and HEVC from the first unit.
async fn probe_codec_is_hevc(cx: &Cx, file: Span) -> Result<bool> {
    let d = cx.read_avail(file.sub(0, 4096)).await?;
    let probe = Head {
        data: &d,
        tail: &d,
        len: file.len,
    };
    Ok(probe_hevc_first(&probe))
}

fn probe_hevc_first(h: &Head<'_>) -> bool {
    let Some(sc) = start_code(h.data, 0) else {
        return false;
    };
    Codec::Hevc.plausible(h.data.get(sc..).unwrap_or_default(), true)
}

fn sps_info(codec: Codec, t: Option<u8>, d: &[u8]) -> Option<SpsInfo> {
    match (codec, t?) {
        (Codec::Avc, 7) => h264_sps(d),
        (Codec::Hevc, 33) => hevc_sps(d),
        _ => None,
    }
}

const SLICE_TYPES: [&str; 5] = ["P", "B", "I", "SP", "SI"];
const PRIMARY_PIC: [&str; 8] = [
    "I",
    "I, P",
    "I, P, B",
    "SI",
    "SI, SP",
    "I, SI",
    "I, SI, P, SP",
    "I, SI, P, SP, B",
];

fn unit_summary(codec: Codec, t: Option<u8>, d: &[u8]) -> Option<String> {
    let t = t?;
    if let Some(sps) = sps_info(codec, Some(t), d) {
        return Some(match codec {
            Codec::Avc => sps.h264_summary(),
            Codec::Hevc => sps.hevc_summary(),
        });
    }
    let rbsp = unescape_rbsp(d.get(vidutil::us(codec.header_len())..).unwrap_or_default());
    match (codec, t) {
        (Codec::Avc, 1 | 5) => {
            let mut b = Bits::new(&rbsp);
            b.ue()?;
            let st = b.ue()?;
            Some(format!(
                "{} slice",
                SLICE_TYPES.get(vidutil::us(st % 5)).copied().unwrap_or("?")
            ))
        }
        (Codec::Avc, 9) => {
            let p = rbsp.first().copied()? >> 5;
            Some(format!(
                "primary picture types {}",
                PRIMARY_PIC.get(usize::from(p)).copied().unwrap_or("?")
            ))
        }
        (Codec::Avc, 6) | (Codec::Hevc, 39 | 40) => {
            let msgs: Vec<String> = sei_messages(&rbsp)
                .map(|(kind, payload)| sei_name(kind, payload))
                .collect();
            (!msgs.is_empty()).then(|| msgs.join("; "))
        }
        _ => None,
    }
}

/// SEI messages in an RBSP: (payload type, payload).
fn sei_messages(rbsp: &[u8]) -> impl Iterator<Item = (u64, &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        // Stop at the RBSP trailing bits.
        if rbsp.get(at..).is_none_or(|r| r.is_empty() || r == [0x80]) {
            return None;
        }
        let mut read = || {
            let mut v = 0u64;
            loop {
                let b = *rbsp.get(at)?;
                at = at.checked_add(1)?;
                v = v.checked_add(b.into())?;
                if b != 0xff {
                    return Some(v);
                }
            }
        };
        let kind = read()?;
        let size = usize::try_from(read()?).ok()?;
        let payload = rbsp.get(at..at.checked_add(size)?)?;
        at = at.checked_add(size)?;
        Some((kind, payload))
    })
}

fn sei_name(kind: u64, payload: &[u8]) -> String {
    match kind {
        0 => "buffering period".to_owned(),
        1 => "picture timing".to_owned(),
        3 => "filler payload".to_owned(),
        4 => "user data (ITU-T T.35)".to_owned(),
        5 => {
            let text = payload
                .get(16..)
                .map(crate::text::until_nul)
                .unwrap_or_default();
            let short: String = text.chars().take(48).collect();
            if short.is_empty() {
                "user data unregistered".to_owned()
            } else {
                format!("user data unregistered: {short}")
            }
        }
        6 => "recovery point".to_owned(),
        129 => "active parameter sets".to_owned(),
        132 => "decoded picture hash".to_owned(),
        137 => "mastering display colour volume".to_owned(),
        144 => "content light level".to_owned(),
        147 => "alternative transfer characteristics".to_owned(),
        _ => format!("SEI type {kind}"),
    }
}

async fn expand_unit(cx: Cx, unit: Unit) -> Result<()> {
    let span = unit.span;
    cx.emit(Node::new("Start code").span(span.sub(0, unit.prefix)));
    let nal = unit.nal();
    let d = vidutil::read_small(&cx, nal, 0x10000).await?;
    let b0 = d.first().copied().unwrap_or(0);
    let h0 = nal.sub(0, 1);
    cx.emit(flag_node("Forbidden zero bit", h0, b0 & 0x80 != 0));
    match unit.codec {
        Codec::Avc => {
            cx.emit(uint("NAL ref idc", h0, ((b0 >> 5) & 3).into(), 2));
            cx.emit(enumerated(
                "NAL unit type",
                h0,
                (b0 & 0x1f).into(),
                5,
                H264_NAL_TYPES,
            ));
        }
        Codec::Hevc => {
            let b1 = d.get(1).copied().unwrap_or(0);
            let h01 = nal.sub(0, 2);
            cx.emit(enumerated(
                "NAL unit type",
                h0,
                ((b0 >> 1) & 0x3f).into(),
                6,
                HEVC_NAL_TYPES,
            ));
            cx.emit(uint(
                "Layer ID",
                h01,
                (u64::from(b0 & 1) << 5) | u64::from(b1 >> 3),
                6,
            ));
            cx.emit(uint(
                "Temporal ID plus 1",
                nal.sub(1, 1),
                (b1 & 7).into(),
                3,
            ));
        }
    }
    let payload = nal.tail(unit.codec.header_len());
    let t = unit.codec.nal_type(&d);
    if let Some(sps) = sps_info(unit.codec, t, &d) {
        sps_fields(&cx, unit.codec, payload, &sps);
    } else if matches!(
        (unit.codec, t),
        (Codec::Avc, Some(6)) | (Codec::Hevc, Some(39 | 40))
    ) {
        let rbsp = unescape_rbsp(
            d.get(vidutil::us(unit.codec.header_len())..)
                .unwrap_or_default(),
        );
        for (kind, body) in sei_messages(&rbsp) {
            // Spans are approximate when emulation prevention bytes occur.
            let node = Node::new("SEI message")
                .span(payload)
                .summary(sei_name(kind, body));
            cx.emit(node);
        }
    }
    cx.emit(
        Node::new("Payload")
            .span(payload)
            .summary(format!("{} bytes", payload.len)),
    );
    Ok(())
}

fn sps_fields(cx: &Cx, codec: Codec, payload: Span, sps: &SpsInfo) {
    let (profiles, level) = match codec {
        Codec::Avc => (vidutil::H264_PROFILES, vidutil::h264_level(sps.level)),
        Codec::Hevc => (vidutil::HEVC_PROFILES, vidutil::hevc_level(sps.level)),
    };
    let at = |o: u64, n: u64| payload.sub(o, n);
    match codec {
        Codec::Avc => {
            cx.emit(enumerated(
                "Profile",
                at(0, 1),
                sps.profile.into(),
                8,
                profiles,
            ));
            cx.emit(vidutil::hex(
                "Constraint flags",
                at(1, 1),
                sps.tier_or_constraints.into(),
                8,
            ));
            cx.emit(uint("Level", at(2, 1), sps.level.into(), 8).summary(level));
        }
        Codec::Hevc => {
            cx.emit(enumerated(
                "Profile",
                at(1, 1),
                sps.profile.into(),
                5,
                profiles,
            ));
            cx.emit(text(
                "Tier",
                at(1, 1),
                if sps.tier_or_constraints != 0 {
                    "High"
                } else {
                    "Main"
                },
            ));
            cx.emit(uint("Level", at(12, 1), sps.level.into(), 8).summary(level));
        }
    }
    let rest = payload.tail(3);
    cx.emit(
        enumerated(
            "Chroma format",
            rest,
            sps.chroma_format,
            2,
            &[(0, "monochrome"), (1, "4:2:0"), (2, "4:2:2"), (3, "4:4:4")],
        )
        .desc("Decoded from the Exp-Golomb coded remainder"),
    );
    cx.emit(uint("Bit depth", rest, sps.bit_depth, 8));
    cx.emit(uint("Width", rest, sps.width, 32));
    cx.emit(uint("Height", rest, sps.height, 32));
}
