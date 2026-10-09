//! MPEG-4 Part 2 (Visual) elementary streams: visual object sequence,
//! visual object (with video signal type), video object layer, GOV and VOP
//! units cut at start codes. The VOL header decodes up to its coding
//! tools; VOP headers decode with the VOL they belong to.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::util::vidutil::bitwalk::Walker;
use crate::formats::util::vidutil::{self, hex};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "mpeg4video",
    title: "MPEG-4 Visual elementary stream",
    extensions: &["m4v", "cmp", "xvid"],
    mime: "video/mp4v-es",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    if d.starts_with(b"\x00\x00\x01\xb0") {
        // Visual object sequence, then a visual object or user data.
        return d
            .get(5..9)
            .is_some_and(|w| w == b"\x00\x00\x01\xb5" || w == b"\x00\x00\x01\xb2");
    }
    // A video object start code followed directly by a VOL header.
    d.get(..3) == Some(b"\x00\x00\x01")
        && d.get(3).is_some_and(|&c| c <= 0x1f)
        && d.get(4..7) == Some(b"\x00\x00\x01")
        && d.get(7).is_some_and(|&c| (0x20..=0x2f).contains(&c))
}

const PROFILES: EnumTable = &[
    (0x01, "Simple Profile L1"),
    (0x02, "Simple Profile L2"),
    (0x03, "Simple Profile L3"),
    (0x04, "Simple Profile L4a"),
    (0x05, "Simple Profile L5"),
    (0x06, "Simple Profile L6"),
    (0x08, "Simple Profile L0"),
    (0x09, "Simple Profile L0b"),
    (0x10, "Simple Scalable Profile L0"),
    (0x11, "Simple Scalable Profile L1"),
    (0x12, "Simple Scalable Profile L2"),
    (0x21, "Core Profile L1"),
    (0x22, "Core Profile L2"),
    (0x32, "Main Profile L2"),
    (0x33, "Main Profile L3"),
    (0x34, "Main Profile L4"),
    (0x91, "Advanced Real Time Simple Profile L1"),
    (0x92, "Advanced Real Time Simple Profile L2"),
    (0x93, "Advanced Real Time Simple Profile L3"),
    (0x94, "Advanced Real Time Simple Profile L4"),
    (0xa1, "Core Scalable Profile L1"),
    (0xa2, "Core Scalable Profile L2"),
    (0xa3, "Core Scalable Profile L3"),
    (0xb1, "Advanced Coding Efficiency Profile L1"),
    (0xb2, "Advanced Coding Efficiency Profile L2"),
    (0xb3, "Advanced Coding Efficiency Profile L3"),
    (0xb4, "Advanced Coding Efficiency Profile L4"),
    (0xc1, "Advanced Core Profile L1"),
    (0xc2, "Advanced Core Profile L2"),
    (0xf0, "Advanced Simple Profile L0"),
    (0xf1, "Advanced Simple Profile L1"),
    (0xf2, "Advanced Simple Profile L2"),
    (0xf3, "Advanced Simple Profile L3"),
    (0xf4, "Advanced Simple Profile L4"),
    (0xf5, "Advanced Simple Profile L5"),
    (0xf7, "Advanced Simple Profile L3b"),
    (0xf8, "Fine Granularity Scalable Profile L0"),
    (0xf9, "Fine Granularity Scalable Profile L1"),
    (0xfa, "Fine Granularity Scalable Profile L2"),
    (0xfb, "Fine Granularity Scalable Profile L3"),
    (0xfc, "Fine Granularity Scalable Profile L4"),
    (0xfd, "Fine Granularity Scalable Profile L5"),
];

const OBJECT_TYPES: EnumTable = &[
    (1, "Simple Object"),
    (2, "Simple Scalable Object"),
    (3, "Core Object"),
    (4, "Main Object"),
    (5, "N-bit Object"),
    (6, "Basic Anim. 2D Texture"),
    (7, "Anim. 2D Mesh"),
    (8, "Simple Face"),
    (9, "Still Scalable Texture"),
    (10, "Advanced Real Time Simple"),
    (11, "Core Scalable"),
    (12, "Advanced Coding Efficiency"),
    (13, "Advanced Scalable Texture"),
    (14, "Simple FBA"),
    (17, "Advanced Simple"),
    (18, "Fine Granularity Scalable"),
];

const VISUAL_TYPES: EnumTable = &[
    (1, "video"),
    (2, "still texture"),
    (3, "mesh"),
    (4, "FBA"),
    (5, "3D mesh"),
];

const ASPECT: EnumTable = &[
    (1, "1:1 (square)"),
    (2, "12:11 (625-type for 4:3)"),
    (3, "10:11 (525-type for 4:3)"),
    (4, "16:11 (625-type stretched for 16:9)"),
    (5, "40:33 (525-type stretched for 16:9)"),
    (15, "extended PAR"),
];

const SHAPES: EnumTable = &[
    (0, "rectangular"),
    (1, "binary"),
    (2, "binary only"),
    (3, "grayscale"),
];

const SPRITES: EnumTable = &[(0, "not used"), (1, "static"), (2, "GMC")];

const VOP_TYPES: EnumTable = &[(0, "I"), (1, "P"), (2, "B"), (3, "S")];

fn unit_name(code: u8) -> String {
    match code {
        0x00..=0x1f => "Video object".to_owned(),
        0x20..=0x2f => "Video object layer".to_owned(),
        0xb0 => "Visual object sequence".to_owned(),
        0xb1 => "Visual object sequence end".to_owned(),
        0xb2 => "User data".to_owned(),
        0xb3 => "Group of VOPs".to_owned(),
        0xb5 => "Visual object".to_owned(),
        0xb6 => "VOP".to_owned(),
        _ => format!("Start code {code:#04x}"),
    }
}

/// What a VOL header says (what VOP headers need, and summaries).
#[derive(Clone, Copy, Debug, Default)]
struct Vol {
    object_type: u64,
    width: u64,
    height: u64,
    shape: u64,
    resolution: u64,
    time_bits: u32,
    interlaced: bool,
    sprite: u64,
    quant_precision: u64,
    complexity: bool,
    par: Option<(u64, u64)>,
    fixed_rate: Option<u64>,
}

impl Vol {
    fn describe(&self) -> String {
        let mut s = format!(
            "{}, {}×{}",
            vidutil::lookup_or(OBJECT_TYPES, self.object_type),
            self.width,
            self.height
        );
        if self.shape != 0 {
            s = format!("{s}, {} shape", vidutil::lookup_or(SHAPES, self.shape));
        }
        if self.interlaced {
            s.push_str(", interlaced");
        }
        if let Some((w, h)) = self.par
            && (w, h) != (1, 1)
        {
            s = format!("{s}, PAR {w}:{h}");
        }
        if let Some(inc) = self.fixed_rate
            && inc > 0
        {
            s = format!("{s}, {} fps", vidutil::tables::rate(self.resolution, inc));
        }
        s
    }
}

fn quant_matrix(w: &mut Walker, flag: &'static str, name: &'static str) -> Option<()> {
    if w.flag(flag)? {
        let start = w.pos();
        let mut values = Vec::with_capacity(64);
        for _ in 0..64 {
            let v = w.read(8)?;
            if v == 0 {
                break;
            }
            values.push(v.to_string());
        }
        w.text(name, start, values.join(" "));
    }
    Some(())
}

/// `VideoObjectLayer()` after the start code.
fn vol(w: &mut Walker) -> Option<Vol> {
    let mut v = Vol {
        quant_precision: 5,
        ..Vol::default()
    };
    w.flag("random_accessible_vol")?;
    v.object_type = w.en("video_object_type_indication", 8, OBJECT_TYPES)?;
    let mut verid = 1;
    if w.flag("is_object_layer_identifier")? {
        verid = w.u("video_object_layer_verid", 4)?;
        w.u("video_object_layer_priority", 3)?;
    }
    let aspect = w.en("aspect_ratio_info", 4, ASPECT)?;
    v.par = match aspect {
        1 => Some((1, 1)),
        2 => Some((12, 11)),
        3 => Some((10, 11)),
        4 => Some((16, 11)),
        5 => Some((40, 33)),
        15 => {
            let a = w.u("par_width", 8)?;
            let b = w.u("par_height", 8)?;
            Some((a, b))
        }
        _ => None,
    };
    if w.flag("vol_control_parameters")? {
        w.u("chroma_format", 2)?;
        w.flag("low_delay")?;
        if w.flag("vbv_parameters")? {
            w.begin("VBV parameters");
            w.u("first_half_bit_rate", 15)?;
            w.u("marker_bit", 1)?;
            w.u("latter_half_bit_rate", 15)?;
            w.u("marker_bit", 1)?;
            w.u("first_half_vbv_buffer_size", 15)?;
            w.u("marker_bit", 1)?;
            w.u("latter_half_vbv_buffer_size", 3)?;
            w.u("first_half_vbv_occupancy", 11)?;
            w.u("marker_bit", 1)?;
            w.u("latter_half_vbv_occupancy", 15)?;
            w.u("marker_bit", 1)?;
            w.end();
        }
    }
    v.shape = w.en("video_object_layer_shape", 2, SHAPES)?;
    if v.shape == 3 && verid != 1 {
        w.u("video_object_layer_shape_extension", 4)?;
    }
    w.u("marker_bit", 1)?;
    v.resolution = w.u("vop_time_increment_resolution", 16)?;
    v.time_bits = 64u32
        .saturating_sub(v.resolution.saturating_sub(1).leading_zeros())
        .max(1);
    w.u("marker_bit", 1)?;
    if w.flag("fixed_vop_rate")? {
        let inc = w.u("fixed_vop_time_increment", v.time_bits)?;
        v.fixed_rate = Some(inc);
    }
    if v.shape == 2 {
        return Some(v);
    }
    if v.shape == 0 {
        w.u("marker_bit", 1)?;
        v.width = w.u("video_object_layer_width", 13)?;
        w.u("marker_bit", 1)?;
        v.height = w.u("video_object_layer_height", 13)?;
        w.u("marker_bit", 1)?;
    }
    v.interlaced = w.flag("interlaced")?;
    w.flag("obmc_disable")?;
    v.sprite = w.en("sprite_enable", if verid == 1 { 1 } else { 2 }, SPRITES)?;
    if v.sprite == 1 || v.sprite == 2 {
        w.begin("Sprite");
        if v.sprite != 2 {
            for name in [
                "sprite_width",
                "sprite_height",
                "sprite_left_coordinate",
                "sprite_top_coordinate",
            ] {
                w.u(name, 13)?;
                w.u("marker_bit", 1)?;
            }
        }
        w.u("no_of_sprite_warping_points", 6)?;
        w.u("sprite_warping_accuracy", 2)?;
        w.flag("sprite_brightness_change")?;
        if v.sprite != 2 {
            w.flag("low_latency_sprite_enable")?;
        }
        w.end();
    }
    if verid != 1 && v.shape != 0 {
        w.flag("sadct_disable")?;
    }
    if w.flag("not_8_bit")? {
        v.quant_precision = w.u("quant_precision", 4)?;
        w.u("bits_per_pixel", 4)?;
    }
    if v.shape == 3 {
        w.flag("no_gray_quant_update")?;
        w.flag("composition_method")?;
        w.flag("linear_composition")?;
    }
    if w.flag("quant_type")? {
        quant_matrix(w, "load_intra_quant_mat", "intra_quant_mat")?;
        quant_matrix(w, "load_nonintra_quant_mat", "nonintra_quant_mat")?;
        if v.shape == 3 {
            // Grayscale alpha matrices are not decoded.
            return Some(v);
        }
    }
    if verid != 1 {
        w.flag("quarter_sample")?;
    }
    v.complexity = !w.flag("complexity_estimation_disable")?;
    if v.complexity {
        w.push(Node::new("Complexity estimation header").desc("Not decoded"));
        return Some(v);
    }
    w.flag("resync_marker_disable")?;
    if w.flag("data_partitioned")? {
        w.flag("reversible_vlc")?;
    }
    if verid != 1 {
        if w.flag("newpred_enable")? {
            w.u("requested_upstream_message_type", 2)?;
            w.flag("newpred_segment_type")?;
        }
        w.flag("reduced_resolution_vop_enable")?;
    }
    w.flag("scalability")?;
    Some(v)
}

/// The start of `VideoObjectPlane()`.
fn vop(w: &mut Walker, vol: Option<&Vol>) -> Option<String> {
    let t = w.en("vop_coding_type", 2, VOP_TYPES)?;
    let kind = vidutil::lookup_or(VOP_TYPES, t);
    let Some(vol) = vol else {
        return Some(format!("{kind}-VOP"));
    };
    let start = w.pos();
    let mut seconds = 0u64;
    for _ in 0..64 {
        if !w.read_flag()? {
            break;
        }
        seconds = seconds.saturating_add(1);
    }
    w.record(
        "modulo_time_base",
        start,
        crate::value::Value::UInt {
            value: seconds,
            bits: 8,
            radix: crate::value::Radix::Dec,
        },
    );
    w.u("marker_bit", 1)?;
    let inc = w.u("vop_time_increment", vol.time_bits)?;
    let res = vol.resolution;
    w.summary(|| format!("{inc}/{res} s"));
    w.u("marker_bit", 1)?;
    if !w.flag("vop_coded")? {
        return Some(format!("{kind}-VOP, not coded"));
    }
    if vol.shape != 0 || vol.sprite != 0 || vol.complexity {
        return Some(format!("{kind}-VOP"));
    }
    if t == 1 {
        w.flag("vop_rounding_type")?;
    }
    w.u("intra_dc_vlc_thr", 3)?;
    if vol.interlaced {
        w.flag("top_field_first")?;
        w.flag("alternate_vertical_scan_flag")?;
    }
    let q = w.u("vop_quant", u32::try_from(vol.quant_precision).ok()?)?;
    if t != 0 {
        w.u("vop_fcode_forward", 3)?;
    }
    if t == 2 {
        w.u("vop_fcode_backward", 3)?;
    }
    Some(format!("{kind}-VOP, quant {q}"))
}

/// "MPEG-4 Visual, Simple Profile L1, Simple Object, 352×288" from the
/// start of a stream.
pub fn es_summary(d: &[u8]) -> Option<String> {
    let profile = vidutil::find(d, b"\x00\x00\x01\xb0")
        .and_then(|at| d.get(at.saturating_add(4)).copied())
        .map(|p| vidutil::lookup_or(PROFILES, p.into()));
    let mut at = 0usize;
    for _ in 0..16 {
        let i = vidutil::find(d.get(at..)?, b"\x00\x00\x01")?;
        let code_at = at.saturating_add(i).saturating_add(3);
        let code = *d.get(code_at)?;
        if (0x20..=0x2f).contains(&code) {
            let body = d.get(code_at.saturating_add(1)..)?;
            let span = Span::new(crate::span::SourceId::default_host(), 0, 0);
            let mut w = Walker::new(body.get(..body.len().min(256))?, span, false, false);
            let v = vol(&mut w)?;
            return Some(match profile {
                Some(p) => format!("{p}, {}", v.describe()),
                None => v.describe(),
            });
        }
        at = code_at;
    }
    profile
}

#[derive(Clone, Copy, Debug)]
struct Walk {
    pos: u64,
    vol: Option<Vol>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = vidutil::read_small(&cx, file, 1024).await?;
    cx.annotate(match es_summary(&head) {
        Some(s) => format!("MPEG-4 Visual, {s}"),
        None => "MPEG-4 Visual".to_owned(),
    });
    let mut walk = match cx.resume::<Walk>() {
        Some(w) => w,
        None => {
            let Some(p) = vidutil::next_start_code(&cx, file, 0).await? else {
                cx.emit(Node::new("Data").span(file));
                return Ok(());
            };
            if p > 0 {
                cx.emit(Node::new("Leading data").span(file.sub(0, p)));
            }
            Walk { pos: p, vol: None }
        }
    };
    while walk.pos < file.len {
        let pos = walk.pos;
        let end = vidutil::next_start_code(&cx, file, pos.saturating_add(3))
            .await?
            .unwrap_or(file.len);
        let span = file.sub(pos, end.saturating_sub(pos));
        let d = vidutil::read_small(&cx, span, 256).await?;
        let code = d.get(3).copied().unwrap_or(0);
        let body = d.get(4..).unwrap_or_default();
        let unit = Unit {
            span,
            code,
            vol: walk.vol,
        };
        let mut w = Walker::new(body, span.tail(4), false, false);
        let summary = match code {
            0xb0 => {
                let p = body.first().copied().unwrap_or(0);
                Some(vidutil::lookup_or(PROFILES, p.into()))
            }
            0xb5 => visual_object(&mut w),
            0x20..=0x2f => {
                let v = vol(&mut w);
                if v.is_some() {
                    walk.vol = v;
                }
                v.map(|v| v.describe())
            }
            0xb6 => vop(&mut w, walk.vol.as_ref()),
            0xb2 => Some(format!("“{}”", crate::text::until_nul(body))),
            0xb3 => gov(&mut w),
            _ => None,
        };
        let mut node = Node::new(unit_name(code)).span(span);
        node = node.summary(match summary {
            Some(s) => format!("{s}, {} bytes", span.len),
            None => format!("{} bytes", span.len),
        });
        if matches!(code, 0xb0 | 0xb3 | 0xb5 | 0x20..=0x2f | 0xb6) {
            node = node.lazy(expand_unit, unit);
        }
        let state = Walk { pos, vol: unit.vol };
        cx.mark(move || state);
        cx.progress_in(file, file.offset.saturating_add(pos));
        cx.push(node).await;
        walk.pos = end.max(pos.saturating_add(4));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Unit {
    span: Span,
    code: u8,
    /// The VOL in force before this unit.
    vol: Option<Vol>,
}

/// `VisualObject()` after the start code.
fn visual_object(w: &mut Walker) -> Option<String> {
    if w.flag("is_visual_object_identifier")? {
        w.u("visual_object_verid", 4)?;
        w.u("visual_object_priority", 3)?;
    }
    let t = w.en("visual_object_type", 4, VISUAL_TYPES)?;
    let mut s = vidutil::lookup_or(VISUAL_TYPES, t);
    if (t == 1 || t == 2) && w.flag("video_signal_type")? {
        w.en(
            "video_format",
            3,
            &[
                (0, "component"),
                (1, "PAL"),
                (2, "NTSC"),
                (3, "SECAM"),
                (4, "MAC"),
                (5, "unspecified"),
            ],
        )?;
        w.flag("video_range")?;
        if w.flag("colour_description")? {
            let p = w.en("colour_primaries", 8, vidutil::COLOUR_PRIMARIES)?;
            let tc = w.en(
                "transfer_characteristics",
                8,
                vidutil::TRANSFER_CHARACTERISTICS,
            )?;
            let m = w.en("matrix_coefficients", 8, vidutil::MATRIX_COEFFICIENTS)?;
            if let Some(c) = vidutil::params::colour_summary(p, tc, m) {
                s = format!("{s}, {c}");
            }
        }
    }
    Some(s)
}

/// `Group_of_VideoObjectPlane()` after the start code.
fn gov(w: &mut Walker) -> Option<String> {
    let h = w.u("time_code_hours", 5)?;
    let m = w.u("time_code_minutes", 6)?;
    w.u("marker_bit", 1)?;
    let s = w.u("time_code_seconds", 6)?;
    let closed = w.flag("closed_gov")?;
    w.flag("broken_link")?;
    Some(format!(
        "{h:02}:{m:02}:{s:02}{}",
        if closed { ", closed" } else { "" }
    ))
}

async fn expand_unit(cx: Cx, unit: Unit) -> Result<()> {
    let span = unit.span;
    let d = vidutil::read_small(&cx, span, 512).await?;
    cx.emit(hex(
        "Start code",
        span.sub(0, 4),
        0x100u64 | u64::from(unit.code),
        32,
    ));
    let body = span.tail(4);
    let data = d.get(4..).unwrap_or_default();
    let mut w = Walker::new(data, body, false, true);
    let ok = match unit.code {
        0xb0 => w
            .en("profile_and_level_indication", 8, PROFILES)
            .map(|_| ()),
        0xb5 => visual_object(&mut w).map(|_| ()),
        0xb3 => gov(&mut w).map(|_| ()),
        0xb6 => vop(&mut w, unit.vol.as_ref()).map(|_| ()),
        _ => vol(&mut w).map(|_| ()),
    }
    .is_some();
    for node in w.finish(ok) {
        cx.emit(node);
    }
    if unit.code == 0xb6 {
        cx.emit(
            Node::new("VOP data")
                .span(body)
                .summary(format!("{} bytes", body.len)),
        );
    }
    Ok(())
}
