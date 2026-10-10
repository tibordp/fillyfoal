//! MPEG-1 and MPEG-2 video elementary streams (ISO 11172-2, 13818-2).
//!
//! The stream is cut at start codes into units: sequence headers and
//! extensions (sequence, display, quant matrix, copyright, picture
//! coding, picture display), GOP headers, pictures, user data.
//! Consecutive slices are grouped into one node. Units are listed in pages
//! and decode field by field on expansion.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::util::fmt::plural;
use crate::formats::util::vidutil::bitwalk::Walker;
use crate::formats::util::vidutil::{self, Bits};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

pub static MPEG1_VIDEO: Format = Format {
    name: "mpeg1video",
    title: "MPEG-1 video elementary stream",
    extensions: &["m1v", "mpv"],
    mime: "video/mpeg",
    probe: Probe::Custom(|h| sequence_header(h) == Some(1)),
    dissect: crate::expander!(dissect: Input),
};

pub static MPEG2_VIDEO: Format = Format {
    name: "mpeg2video",
    title: "MPEG-2 video elementary stream",
    extensions: &["m2v", "mpv", "mp2v"],
    mime: "video/mpeg",
    probe: Probe::Custom(|h| sequence_header(h) == Some(2)),
    dissect: crate::expander!(dissect: Input),
};

/// 1 or 2 if the input starts with a plausible sequence header (2 when a
/// sequence extension follows).
fn sequence_header(h: &Head<'_>) -> Option<u8> {
    if !h.starts_with(b"\x00\x00\x01\xb3") {
        return None;
    }
    let info = SequenceHeader::parse(h.data.get(4..12)?)?;
    if info.width == 0
        || info.height == 0
        || !(1..=4).contains(&info.aspect)
        || !(1..=8).contains(&info.rate)
    {
        return None;
    }
    let window = h.data.get(..h.data.len().min(512))?;
    let ext = window.windows(5).any(|w| {
        w.get(..4) == Some(b"\x00\x00\x01\xb5".as_slice()) && w.get(4).is_some_and(|b| b >> 4 == 1)
    });
    Some(if ext { 2 } else { 1 })
}

const ASPECT: EnumTable = &[
    (1, "1:1 (square pixels)"),
    (2, "4:3"),
    (3, "16:9"),
    (4, "2.21:1"),
];
/// MPEG-1 pel aspect ratios (height/width).
const ASPECT_MPEG1: EnumTable = &[
    (1, "1.0 (square)"),
    (2, "0.6735"),
    (3, "0.7031 (16:9, 625 lines)"),
    (4, "0.7615"),
    (5, "0.8055"),
    (6, "0.8437 (16:9, 525 lines)"),
    (7, "0.8935"),
    (8, "0.9157 (CCIR 601, 625 lines)"),
    (9, "0.9815"),
    (10, "1.0255"),
    (11, "1.0695"),
    (12, "1.0950 (CCIR 601, 525 lines)"),
    (13, "1.1575"),
    (14, "1.2015"),
];
const FRAME_RATES: [(u64, u64); 9] = [
    (0, 1),
    (24000, 1001),
    (24, 1),
    (25, 1),
    (30000, 1001),
    (30, 1),
    (50, 1),
    (60000, 1001),
    (60, 1),
];
const PICTURE_TYPES: EnumTable = &[(1, "I"), (2, "P"), (3, "B"), (4, "D")];
const EXTENSIONS: EnumTable = &[
    (1, "sequence extension"),
    (2, "sequence display extension"),
    (3, "quant matrix extension"),
    (4, "copyright extension"),
    (5, "sequence scalable extension"),
    (7, "picture display extension"),
    (8, "picture coding extension"),
    (9, "picture spatial scalable extension"),
    (10, "picture temporal scalable extension"),
];
const PROFILES: EnumTable = &[
    (1, "High"),
    (2, "Spatially scalable"),
    (3, "SNR scalable"),
    (4, "Main"),
    (5, "Simple"),
];
const LEVELS: EnumTable = &[(4, "High"), (6, "High 1440"), (8, "Main"), (10, "Low")];
/// Profile and level values with the escape bit set.
const ESCAPED: EnumTable = &[
    (0x82, "4:2:2@High"),
    (0x85, "4:2:2@Main"),
    (0x8a, "Multi-view@High"),
    (0x8b, "Multi-view@High 1440"),
    (0x8d, "Multi-view@Main"),
    (0x8e, "Multi-view@Low"),
];
const CHROMA: EnumTable = &[(1, "4:2:0"), (2, "4:2:2"), (3, "4:4:4")];
const STRUCTURES: EnumTable = &[(1, "top field"), (2, "bottom field"), (3, "frame")];

fn profile_level(v: u64) -> String {
    if v & 0x80 != 0 {
        return vidutil::lookup_or(ESCAPED, v);
    }
    format!(
        "{}@{}",
        vidutil::lookup_or(PROFILES, (v >> 4) & 7),
        vidutil::lookup_or(LEVELS, v & 15)
    )
}

#[derive(Clone, Copy, Debug)]
struct SequenceHeader {
    width: u64,
    height: u64,
    aspect: u64,
    rate: u64,
    bitrate: u64,
    /// MPEG-2 `frame_rate_extension_n`, `frame_rate_extension_d`.
    rate_ext: (u64, u64),
}

impl SequenceHeader {
    /// Parses the 8 bytes after the start code.
    fn parse(d: &[u8]) -> Option<Self> {
        let mut b = Bits::new(d);
        let width = b.bits(12)?;
        let height = b.bits(12)?;
        let aspect = b.bits(4)?;
        let rate = b.bits(4)?;
        let bitrate = b.bits(18)?;
        Some(SequenceHeader {
            width,
            height,
            aspect,
            rate,
            bitrate,
            rate_ext: (0, 0),
        })
    }

    fn fps(&self) -> String {
        let (n, d) = FRAME_RATES
            .get(vidutil::us(self.rate))
            .copied()
            .unwrap_or((0, 1));
        let (en, ed) = self.rate_ext;
        vidutil::tables::rate(
            n.saturating_mul(en.saturating_add(1)),
            d.saturating_mul(ed.saturating_add(1)),
        )
    }

    fn describe(&self, mpeg2: bool) -> String {
        format!(
            "{}×{}, {}, {} fps, {}",
            self.width,
            self.height,
            if mpeg2 {
                vidutil::lookup_or(ASPECT, self.aspect)
            } else {
                format!(
                    "pel aspect {}",
                    vidutil::lookup_or(ASPECT_MPEG1, self.aspect)
                )
            },
            self.fps(),
            bitrate(self.bitrate)
        )
    }
}

fn bitrate(v: u64) -> String {
    if v == 0x3ffff {
        "variable bit rate".to_owned()
    } else {
        format!("{} kb/s", v.saturating_mul(400) / 1000)
    }
}

/// "MPEG-2 video, Main@Main, 720×576, 4:3, 25 fps, ..." from the start of
/// an elementary stream (a PES payload or a file).
pub fn es_summary(d: &[u8]) -> Option<String> {
    let at = vidutil::find(d, b"\x00\x00\x01\xb3")?;
    let seq = SequenceHeader::parse(d.get(at.saturating_add(4)..)?)?;
    let rest = d.get(at..)?;
    let window = rest.get(..rest.len().min(512))?;
    if let Some(e) = vidutil::find(window, b"\x00\x00\x01\xb5")
        && let Some(&b) = window.get(e.saturating_add(4))
        && b >> 4 == 1
    {
        let b5 = window.get(e.saturating_add(5)).copied().unwrap_or(0);
        let b6 = window.get(e.saturating_add(6)).copied().unwrap_or(0);
        let b9 = window.get(e.saturating_add(9)).copied().unwrap_or(0);
        let pl = u64::from(b & 15) << 4 | u64::from(b5 >> 4);
        let progressive = b5 & 0x08 != 0;
        let chroma = (b5 >> 1) & 3;
        let width = seq.width | u64::from(((b5 & 1) << 1) | (b6 >> 7)) << 12;
        let height = seq.height | u64::from((b6 >> 5) & 3) << 12;
        let mut s = SequenceHeader {
            width,
            height,
            rate_ext: (u64::from((b9 >> 5) & 3), u64::from(b9 & 31)),
            ..seq
        }
        .describe(true);
        s = format!(
            "MPEG-2 video, {}, {s}, {}{}",
            profile_level(pl),
            vidutil::lookup_or(CHROMA, chroma.into()),
            if progressive { "" } else { ", interlaced" }
        );
        return Some(s);
    }
    Some(format!("MPEG-1 video, {}", seq.describe(false)))
}

/// The name of a start code's unit.
fn unit_name(code: u8) -> String {
    match code {
        0x00 => "Picture".to_owned(),
        0x01..=0xaf => "Slices".to_owned(),
        0xb2 => "User data".to_owned(),
        0xb3 => "Sequence header".to_owned(),
        0xb4 => "Sequence error".to_owned(),
        0xb5 => "Extension".to_owned(),
        0xb7 => "Sequence end".to_owned(),
        0xb8 => "Group of pictures".to_owned(),
        _ => format!("Start code {code:#04x}"),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 512)).await?;
    if let Some(s) = es_summary(&head) {
        cx.annotate(s);
    }
    let mut pos = match cx.resume::<u64>() {
        Some(p) => p,
        None => {
            let Some(p) = vidutil::next_start_code(&cx, file, 0).await? else {
                cx.emit(Node::new("Data").span(file));
                return Ok(());
            };
            if p > 0 {
                cx.emit(Node::new("Leading data").span(file.sub(0, p)));
            }
            p
        }
    };
    while pos < file.len {
        let code = cx
            .read_avail(file.sub(pos.saturating_add(3), 1))
            .await?
            .first()
            .copied()
            .unwrap_or(0);
        let mut end = vidutil::next_start_code(&cx, file, pos.saturating_add(3))
            .await?
            .unwrap_or(file.len);
        let mut slices = 1u64;
        if (0x01..=0xaf).contains(&code) {
            // Group consecutive slices.
            while end < file.len {
                let next = cx.read_avail(file.sub(end.saturating_add(3), 1)).await?;
                if !next.first().is_some_and(|c| (0x01..=0xaf).contains(c)) {
                    break;
                }
                end = vidutil::next_start_code(&cx, file, end.saturating_add(3))
                    .await?
                    .unwrap_or(file.len);
                slices = slices.saturating_add(1);
            }
        }
        let span = file.sub(pos, end.saturating_sub(pos));
        let d = cx.read_avail(span.sub(0, 256)).await?;
        let summary = summary(code, &d, slices);
        let mut node = Node::new(unit_name(code)).span(span);
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if matches!(code, 0x00 | 0xb2 | 0xb3 | 0xb5 | 0xb8) {
            node = node.lazy(expand_unit, (span, code));
        }
        let at = pos;
        cx.mark(move || at);
        cx.progress_in(file, file.offset.saturating_add(pos));
        cx.push(node).await;
        pos = end.max(pos.saturating_add(4));
    }
    Ok(())
}

fn summary(code: u8, d: &[u8], slices: u64) -> String {
    let body = d.get(4..).unwrap_or_default();
    match code {
        0x00 => {
            let mut b = Bits::new(body);
            let tr = b.bits(10).unwrap_or(0);
            let t = b.bits(3).unwrap_or(0);
            format!(
                "{} picture, temporal reference {tr}",
                vidutil::lookup_or(PICTURE_TYPES, t)
            )
        }
        0x01..=0xaf => plural(slices, "slice"),
        0xb2 => user_data_text(body)
            .map_or_else(|| format!("{} bytes", body.len()), |t| format!("“{t}”")),
        0xb3 => SequenceHeader::parse(body)
            .map(|s| s.describe(true))
            .unwrap_or_default(),
        0xb5 => {
            let id = body.first().copied().unwrap_or(0) >> 4;
            let mut s = vidutil::lookup_or(EXTENSIONS, id.into());
            match id {
                1 => {
                    let pl = u64::from(body.first().copied().unwrap_or(0) & 15) << 4
                        | u64::from(body.get(1).copied().unwrap_or(0) >> 4);
                    s = format!("{s}, {}", profile_level(pl));
                }
                8 => {
                    let st = body.get(2).copied().unwrap_or(0) & 3;
                    s = format!("{s}, {}", vidutil::lookup_or(STRUCTURES, st.into()));
                }
                _ => {}
            }
            s
        }
        0xb8 => {
            let mut b = Bits::new(body);
            let drop = b.bit().unwrap_or(0);
            let h = b.bits(5).unwrap_or(0);
            let m = b.bits(6).unwrap_or(0);
            b.bit();
            let s = b.bits(6).unwrap_or(0);
            let f = b.bits(6).unwrap_or(0);
            let closed = b.bit().unwrap_or(0);
            format!(
                "{h:02}:{m:02}:{s:02}{}{f:02}{}",
                if drop == 1 { ";" } else { ":" },
                if closed == 1 { ", closed" } else { "" }
            )
        }
        _ => String::new(),
    }
}

/// User data as text, if it is printable.
fn user_data_text(d: &[u8]) -> Option<String> {
    let t = crate::text::until_nul(d);
    let ok = !t.is_empty()
        && t.len() >= d.len().min(4)
        && t.chars().all(|c| !c.is_control() || c == '\n');
    ok.then(|| t.chars().take(80).collect())
}

async fn expand_unit(cx: Cx, (span, code): (Span, u8)) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 512)).await?;
    cx.emit(vidutil::hex(
        "Start code",
        span.sub(0, 4),
        0x100u64 | u64::from(code),
        32,
    ));
    let body = span.tail(4);
    let data = d.get(4..).unwrap_or_default();
    let mut w = Walker::new(data, body, false, true);
    let ok = match code {
        0xb3 => sequence(&mut w),
        0xb5 => extension(&mut w),
        0xb8 => gop(&mut w),
        0x00 => picture(&mut w),
        0xb2 => {
            let start = w.pos();
            if let Some(t) = user_data_text(data) {
                w.seek(w.len_bits());
                w.text("user_data", start, t);
            }
            Some(())
        }
        _ => Some(()),
    }
    .is_some();
    for node in w.finish(ok) {
        cx.emit(node);
    }
    if code == 0x00 && body.len > 4 {
        cx.emit(
            Node::new("Picture data")
                .span(body.tail(4))
                .summary("extra information and slices follow"),
        );
    } else if code == 0xb2 && user_data_text(data).is_none() {
        cx.emit(
            Node::new("User data")
                .span(body)
                .summary(format!("{} bytes", body.len)),
        );
    }
    Ok(())
}

fn quant_matrix(w: &mut Walker, flag: &'static str, name: &'static str) -> Option<()> {
    if w.flag(flag)? {
        let start = w.pos();
        let mut values = Vec::with_capacity(64);
        for _ in 0..64 {
            values.push(w.read(8)?.to_string());
        }
        w.text(name, start, values.join(" "));
    }
    Some(())
}

/// `sequence_header()`.
fn sequence(w: &mut Walker) -> Option<()> {
    let width = w.u("horizontal_size_value", 12)?;
    w.summary(|| format!("{width} pixels"));
    let height = w.u("vertical_size_value", 12)?;
    w.summary(|| format!("{height} pixels"));
    let aspect = w.u("aspect_ratio_information", 4)?;
    w.summary(|| {
        format!(
            "{} (MPEG-2) / pel aspect {} (MPEG-1)",
            vidutil::lookup_or(ASPECT, aspect),
            vidutil::lookup_or(ASPECT_MPEG1, aspect)
        )
    });
    let rate = w.u("frame_rate_code", 4)?;
    w.summary(|| {
        let (n, d) = FRAME_RATES
            .get(vidutil::us(rate))
            .copied()
            .unwrap_or((0, 1));
        format!("{} fps", vidutil::tables::rate(n, d))
    });
    let br = w.u("bit_rate_value", 18)?;
    w.summary(|| bitrate(br));
    w.u("marker_bit", 1)?;
    let vbv = w.u("vbv_buffer_size_value", 10)?;
    w.summary(|| format!("{} bytes", vbv.saturating_mul(2048)));
    w.flag("constrained_parameters_flag")?;
    quant_matrix(w, "load_intra_quantiser_matrix", "intra_quantiser_matrix")?;
    quant_matrix(
        w,
        "load_non_intra_quantiser_matrix",
        "non_intra_quantiser_matrix",
    )?;
    Some(())
}

/// The extensions (`extension_start_code_identifier` first).
fn extension(w: &mut Walker) -> Option<()> {
    let id = w.en("extension_start_code_identifier", 4, EXTENSIONS)?;
    match id {
        1 => {
            let pl = w.x("profile_and_level_indication", 8)?;
            w.summary(|| profile_level(pl));
            w.flag("progressive_sequence")?;
            w.en("chroma_format", 2, CHROMA)?;
            w.u("horizontal_size_extension", 2)?;
            w.u("vertical_size_extension", 2)?;
            w.u("bit_rate_extension", 12)?;
            w.u("marker_bit", 1)?;
            w.u("vbv_buffer_size_extension", 8)?;
            w.flag("low_delay")?;
            w.u("frame_rate_extension_n", 2)?;
            w.u("frame_rate_extension_d", 5)?;
        }
        2 => {
            w.en("video_format", 3, vidutil::tables::VIDEO_FORMATS)?;
            if w.flag("colour_description")? {
                w.en("colour_primaries", 8, vidutil::COLOUR_PRIMARIES)?;
                w.en(
                    "transfer_characteristics",
                    8,
                    vidutil::TRANSFER_CHARACTERISTICS,
                )?;
                w.en("matrix_coefficients", 8, vidutil::MATRIX_COEFFICIENTS)?;
            }
            w.u("display_horizontal_size", 14)?;
            w.u("marker_bit", 1)?;
            w.u("display_vertical_size", 14)?;
        }
        3 => {
            quant_matrix(w, "load_intra_quantiser_matrix", "intra_quantiser_matrix")?;
            quant_matrix(
                w,
                "load_non_intra_quantiser_matrix",
                "non_intra_quantiser_matrix",
            )?;
            quant_matrix(
                w,
                "load_chroma_intra_quantiser_matrix",
                "chroma_intra_quantiser_matrix",
            )?;
            quant_matrix(
                w,
                "load_chroma_non_intra_quantiser_matrix",
                "chroma_non_intra_quantiser_matrix",
            )?;
        }
        4 => {
            w.flag("copyright_flag")?;
            w.u("copyright_identifier", 8)?;
            w.flag("original_or_copy")?;
            w.u("reserved", 7)?;
            w.u("marker_bit", 1)?;
            w.u("copyright_number_1", 20)?;
            w.u("marker_bit", 1)?;
            w.u("copyright_number_2", 22)?;
            w.u("marker_bit", 1)?;
            w.u("copyright_number_3", 22)?;
        }
        7 => {
            // The number of offsets depends on the picture; show the first.
            w.su("frame_centre_horizontal_offset", 16)?;
            w.u("marker_bit", 1)?;
            w.su("frame_centre_vertical_offset", 16)?;
            w.u("marker_bit", 1)?;
        }
        8 => {
            for name in [
                "f_code[0][0] (forward horizontal)",
                "f_code[0][1] (forward vertical)",
                "f_code[1][0] (backward horizontal)",
                "f_code[1][1] (backward vertical)",
            ] {
                w.u(name, 4)?;
            }
            let dc = w.u("intra_dc_precision", 2)?;
            w.summary(|| format!("{} bits", dc.saturating_add(8)));
            w.en("picture_structure", 2, STRUCTURES)?;
            for name in [
                "top_field_first",
                "frame_pred_frame_dct",
                "concealment_motion_vectors",
                "q_scale_type",
                "intra_vlc_format",
                "alternate_scan",
                "repeat_first_field",
                "chroma_420_type",
                "progressive_frame",
            ] {
                w.flag(name)?;
            }
            if w.flag("composite_display_flag")? {
                w.flag("v_axis")?;
                w.u("field_sequence", 3)?;
                w.flag("sub_carrier")?;
                w.u("burst_amplitude", 7)?;
                w.u("sub_carrier_phase", 8)?;
            }
        }
        _ => {
            let n = w.bits_left();
            w.skip_as("Extension data", n)?;
        }
    }
    Some(())
}

/// `group_of_pictures_header()`.
fn gop(w: &mut Walker) -> Option<()> {
    w.flag("drop_frame_flag")?;
    w.u("time_code_hours", 5)?;
    w.u("time_code_minutes", 6)?;
    w.u("marker_bit", 1)?;
    w.u("time_code_seconds", 6)?;
    w.u("time_code_pictures", 6)?;
    w.flag("closed_gop")?;
    w.flag("broken_link")?;
    Some(())
}

/// `picture_header()`.
fn picture(w: &mut Walker) -> Option<()> {
    w.u("temporal_reference", 10)?;
    let t = w.en("picture_coding_type", 3, PICTURE_TYPES)?;
    let vbv = w.u("vbv_delay", 16)?;
    w.summary(|| {
        if vbv == 0xffff {
            "variable bit rate".to_owned()
        } else {
            format!("{:.3} ms", vbv as f64 / 90.0)
        }
    });
    if t == 2 || t == 3 {
        w.flag("full_pel_forward_vector")?;
        w.u("forward_f_code", 3)?;
    }
    if t == 3 {
        w.flag("full_pel_backward_vector")?;
        w.u("backward_f_code", 3)?;
    }
    Some(())
}
