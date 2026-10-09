//! AV1 bitstream syntax (AV1 specification section 5): OBU headers, the
//! sequence header with its colour config, the start of frame headers,
//! metadata OBUs (HDR light levels and mastering display), and the `av1C`
//! codec configuration record.

use super::bitwalk::Walker;
use super::params::colour_summary;
use super::tables::{
    COLOUR_PRIMARIES, MATRIX_COEFFICIENTS, TRANSFER_CHARACTERISTICS, rate, reduce,
};
use crate::bytes::to_u64;
use crate::value::EnumTable;

pub const OBU_TYPES: EnumTable = &[
    (1, "Sequence header"),
    (2, "Temporal delimiter"),
    (3, "Frame header"),
    (4, "Tile group"),
    (5, "Metadata"),
    (6, "Frame"),
    (7, "Redundant frame header"),
    (8, "Tile list"),
    (15, "Padding"),
];

pub const PROFILES: EnumTable = &[(0, "Main"), (1, "High"), (2, "Professional")];

const FRAME_TYPES: EnumTable = &[
    (0, "KEY_FRAME"),
    (1, "INTER_FRAME"),
    (2, "INTRA_ONLY_FRAME"),
    (3, "SWITCH_FRAME"),
];

const METADATA_TYPES: EnumTable = &[
    (1, "HDR content light level"),
    (2, "HDR mastering display colour volume"),
    (3, "scalability"),
    (4, "ITU-T T.35"),
    (5, "timecode"),
];

const CHROMA_POSITIONS: EnumTable = &[
    (0, "unknown"),
    (1, "vertical (left)"),
    (2, "colocated (top-left)"),
];

/// What a sequence header says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeqInfo {
    pub profile: u64,
    pub level: u64,
    pub tier: bool,
    pub bit_depth: u64,
    pub mono: bool,
    pub subsampling: (u64, u64),
    pub colour: Option<(u64, u64, u64)>,
    pub full_range: bool,
    pub chroma_position: u64,
    pub width: u64,
    pub height: u64,
    pub frame_rate: Option<(u64, u64)>,
    pub still_picture: bool,
    pub reduced_still_picture_header: bool,
    pub frame_id_numbers_present: bool,
    pub frame_id_length: u32,
    pub equal_picture_interval: bool,
    pub decoder_model_info_present: bool,
    pub frame_presentation_time_length: u32,
}

/// An AV1 level index as "4.0" ("max" for 31).
pub fn level_name(idx: u64) -> String {
    if idx == 31 {
        return "max".to_owned();
    }
    format!("{}.{}", (idx >> 2).saturating_add(2), idx & 3)
}

impl SeqInfo {
    pub fn format(&self) -> String {
        let chroma = if self.mono {
            "monochrome"
        } else {
            match self.subsampling {
                (1, 1) => "4:2:0",
                (1, 0) => "4:2:2",
                (0, 0) => "4:4:4",
                _ => "?",
            }
        };
        format!("{chroma} {}-bit", self.bit_depth)
    }

    /// "Main@L4.0" (with the tier when High).
    pub fn profile_level(&self) -> String {
        format!(
            "{}@L{}{}",
            super::tables::lookup_or(PROFILES, self.profile),
            level_name(self.level),
            if self.tier { " High tier" } else { "" }
        )
    }

    pub fn describe(&self) -> String {
        let mut parts = vec![
            self.profile_level(),
            format!("{}×{}", self.width, self.height),
            self.format(),
        ];
        if let Some((n, d)) = self.frame_rate {
            parts.push(format!("{} fps", rate(n, d)));
        }
        if let Some((p, t, m)) = self.colour
            && let Some(c) = colour_summary(p, t, m)
        {
            parts.push(c);
        }
        if self.still_picture {
            parts.push("still picture".to_owned());
        }
        parts.join(", ")
    }

    /// The codec string of the AV1 ISOBMFF binding (`av01.0.04M.08`).
    pub fn codec_string(&self) -> String {
        format!(
            "av01.{}.{:02}{}.{:02}",
            self.profile,
            self.level,
            if self.tier { "H" } else { "M" },
            self.bit_depth
        )
    }
}

/// `obu_header()`: returns (type, has size field, extension present).
pub fn obu_header(w: &mut Walker) -> Option<(u64, bool, bool)> {
    w.begin("OBU header");
    let forbidden = w.flag("obu_forbidden_bit")?;
    if forbidden {
        w.with(|n| n.diag(crate::error::Diagnostic::malformed("must be 0")));
    }
    let t = w.en("obu_type", 4, OBU_TYPES)?;
    let ext = w.flag("obu_extension_flag")?;
    let sized = w.flag("obu_has_size_field")?;
    w.flag("obu_reserved_1bit")?;
    if ext {
        w.u("temporal_id", 3)?;
        w.u("spatial_id", 2)?;
        w.u("extension_header_reserved_3bits", 3)?;
    }
    w.end();
    Some((t, sized, ext))
}

/// `sequence_header_obu()`.
pub fn sequence_header(w: &mut Walker) -> Option<SeqInfo> {
    let mut s = SeqInfo {
        profile: w.en("seq_profile", 3, PROFILES)?,
        ..SeqInfo::default()
    };
    s.still_picture = w.flag("still_picture")?;
    s.reduced_still_picture_header = w.flag("reduced_still_picture_header")?;
    let mut buffer_delay_length = 0u32;
    if s.reduced_still_picture_header {
        s.level = w.u("seq_level_idx[0]", 5)?;
        let l = s.level;
        w.summary(|| format!("level {}", level_name(l)));
    } else {
        if w.flag("timing_info_present_flag")? {
            w.begin("Timing info");
            let units = w.u("num_units_in_display_tick", 32)?;
            let scale = w.u("time_scale", 32)?;
            s.equal_picture_interval = w.flag("equal_picture_interval")?;
            let mut ticks = 1u64;
            if s.equal_picture_interval {
                ticks = w.uvlc("num_ticks_per_picture_minus_1")?.saturating_add(1);
            }
            if units > 0 && scale > 0 {
                let (n, d) = reduce(scale, units.saturating_mul(ticks));
                s.frame_rate = Some((n, d));
            }
            let fr = s.frame_rate;
            w.end_summary(|| {
                fr.map(|(n, d)| format!("{} fps", rate(n, d)))
                    .unwrap_or_default()
            });
            s.decoder_model_info_present = w.flag("decoder_model_info_present_flag")?;
            if s.decoder_model_info_present {
                w.begin("Decoder model info");
                buffer_delay_length = u32::try_from(w.u("buffer_delay_length_minus_1", 5)?)
                    .ok()?
                    .saturating_add(1);
                w.u("num_units_in_decoding_tick", 32)?;
                w.u("buffer_removal_time_length_minus_1", 5)?;
                s.frame_presentation_time_length =
                    u32::try_from(w.u("frame_presentation_time_length_minus_1", 5)?)
                        .ok()?
                        .saturating_add(1);
                w.end();
            }
        }
        let initial_display_delay = w.flag("initial_display_delay_present_flag")?;
        let points = w.u("operating_points_cnt_minus_1", 5)?;
        for i in 0..=points {
            w.begin(format!("Operating point {i}"));
            w.x(format!("operating_point_idc[{i}]"), 12)?;
            let level = w.u(format!("seq_level_idx[{i}]"), 5)?;
            w.summary(|| format!("level {}", level_name(level)));
            let tier = if level > 7 {
                w.flag(format!("seq_tier[{i}]"))?
            } else {
                false
            };
            if i == 0 {
                s.level = level;
                s.tier = tier;
            }
            if s.decoder_model_info_present
                && w.flag(format!("decoder_model_present_for_this_op[{i}]"))?
            {
                w.u("decoder_buffer_delay", buffer_delay_length)?;
                w.u("encoder_buffer_delay", buffer_delay_length)?;
                w.flag("low_delay_mode_flag")?;
            }
            if initial_display_delay
                && w.flag(format!("initial_display_delay_present_for_this_op[{i}]"))?
            {
                w.u(format!("initial_display_delay_minus_1[{i}]"), 4)?;
            }
            w.end_summary(|| {
                format!(
                    "level {}{}",
                    level_name(level),
                    if tier { ", High tier" } else { "" }
                )
            });
        }
    }
    let wbits = u32::try_from(w.u("frame_width_bits_minus_1", 4)?)
        .ok()?
        .saturating_add(1);
    let hbits = u32::try_from(w.u("frame_height_bits_minus_1", 4)?)
        .ok()?
        .saturating_add(1);
    s.width = w.u("max_frame_width_minus_1", wbits)?.saturating_add(1);
    let width = s.width;
    w.summary(|| format!("{width} pixels"));
    s.height = w.u("max_frame_height_minus_1", hbits)?.saturating_add(1);
    let height = s.height;
    w.summary(|| format!("{height} pixels"));
    if !s.reduced_still_picture_header {
        s.frame_id_numbers_present = w.flag("frame_id_numbers_present_flag")?;
    }
    if s.frame_id_numbers_present {
        let delta = u32::try_from(w.u("delta_frame_id_length_minus_2", 4)?).ok()?;
        let extra = u32::try_from(w.u("additional_frame_id_length_minus_1", 3)?).ok()?;
        s.frame_id_length = delta
            .saturating_add(2)
            .saturating_add(extra)
            .saturating_add(1);
    }
    w.flag("use_128x128_superblock")?;
    w.flag("enable_filter_intra")?;
    w.flag("enable_intra_edge_filter")?;
    if !s.reduced_still_picture_header {
        w.flag("enable_interintra_compound")?;
        w.flag("enable_masked_compound")?;
        w.flag("enable_warped_motion")?;
        w.flag("enable_dual_filter")?;
        let order_hint = w.flag("enable_order_hint")?;
        if order_hint {
            w.flag("enable_jnt_comp")?;
            w.flag("enable_ref_frame_mvs")?;
        }
        let force_screen = if w.flag("seq_choose_screen_content_tools")? {
            2
        } else {
            w.u("seq_force_screen_content_tools", 1)?
        };
        if force_screen > 0 && !w.flag("seq_choose_integer_mv")? {
            w.u("seq_force_integer_mv", 1)?;
        }
        if order_hint {
            w.u("order_hint_bits_minus_1", 3)?;
        }
    }
    w.flag("enable_superres")?;
    w.flag("enable_cdef")?;
    w.flag("enable_restoration")?;
    color_config(w, &mut s)?;
    w.flag("film_grain_params_present")?;
    Some(s)
}

fn color_config(w: &mut Walker, s: &mut SeqInfo) -> Option<()> {
    w.begin("Color config");
    let high = w.flag("high_bitdepth")?;
    s.bit_depth = if s.profile == 2 && high {
        if w.flag("twelve_bit")? { 12 } else { 10 }
    } else if high {
        10
    } else {
        8
    };
    s.mono = if s.profile == 1 {
        false
    } else {
        w.flag("mono_chrome")?
    };
    let (mut p, mut t, mut m) = (2, 2, 2);
    if w.flag("color_description_present_flag")? {
        p = w.en("color_primaries", 8, COLOUR_PRIMARIES)?;
        t = w.en("transfer_characteristics", 8, TRANSFER_CHARACTERISTICS)?;
        m = w.en("matrix_coefficients", 8, MATRIX_COEFFICIENTS)?;
        s.colour = Some((p, t, m));
    }
    if s.mono {
        s.full_range = w.flag("color_range")?;
        s.subsampling = (1, 1);
    } else if p == 1 && t == 13 && m == 0 {
        s.full_range = true;
        s.subsampling = (0, 0);
    } else {
        s.full_range = w.flag("color_range")?;
        s.subsampling = match s.profile {
            0 => (1, 1),
            1 => (0, 0),
            _ => {
                if s.bit_depth == 12 {
                    let x = w.u("subsampling_x", 1)?;
                    let y = if x == 1 { w.u("subsampling_y", 1)? } else { 0 };
                    (x, y)
                } else {
                    (1, 0)
                }
            }
        };
        if s.subsampling == (1, 1) {
            s.chroma_position = w.en("chroma_sample_position", 2, CHROMA_POSITIONS)?;
        }
    }
    if !s.mono {
        w.flag("separate_uv_delta_q")?;
    }
    let summary = s.format();
    w.end_summary(|| summary);
    Some(())
}

/// The first fields of `uncompressed_header()`: frame type and whether it
/// is shown. Returns a summary.
pub fn frame_header(w: &mut Walker, seq: Option<&SeqInfo>) -> Option<String> {
    let Some(seq) = seq else {
        return Some("frame".to_owned());
    };
    if seq.reduced_still_picture_header {
        return Some("KEY_FRAME, shown".to_owned());
    }
    if w.flag("show_existing_frame")? {
        let idx = w.u("frame_to_show_map_idx", 3)?;
        return Some(format!("show existing frame {idx}"));
    }
    let t = w.en("frame_type", 2, FRAME_TYPES)?;
    let shown = w.flag("show_frame")?;
    let mut s = format!(
        "{}, {}",
        super::tables::lookup_or(FRAME_TYPES, t),
        if shown { "shown" } else { "hidden" }
    );
    if shown && seq.decoder_model_info_present && !seq.equal_picture_interval {
        w.u(
            "frame_presentation_time",
            seq.frame_presentation_time_length,
        )?;
    }
    if !shown {
        w.flag("showable_frame")?;
    }
    // Switch frames and shown key frames are always error resilient;
    // otherwise it is signalled.
    if !(t == 3 || (t == 0 && shown)) && w.flag("error_resilient_mode")? {
        s.push_str(", error resilient");
    }
    w.push(
        crate::node::Node::new("Remaining fields")
            .desc("The rest of the uncompressed header is not decoded"),
    );
    Some(s)
}

/// `metadata_obu()`.
pub fn metadata(w: &mut Walker) -> Option<String> {
    let t = w.leb128("metadata_type")?;
    w.with(|n| {
        n.value(crate::value::Value::Enum {
            raw: t,
            bits: 32,
            name: crate::value::lookup(METADATA_TYPES, t),
        })
    });
    match t {
        1 => {
            let cll = w.u("max_cll", 16)?;
            let fall = w.u("max_fall", 16)?;
            Some(format!("MaxCLL {cll}, MaxFALL {fall} cd/m²"))
        }
        2 => {
            for c in 0..3 {
                let x = w.u(format!("primary_chromaticity_x[{c}]"), 16)?;
                w.summary(|| format!("{:.5}", x as f64 / 65536.0));
                let y = w.u(format!("primary_chromaticity_y[{c}]"), 16)?;
                w.summary(|| format!("{:.5}", y as f64 / 65536.0));
            }
            let x = w.u("white_point_chromaticity_x", 16)?;
            w.summary(|| format!("{:.5}", x as f64 / 65536.0));
            let y = w.u("white_point_chromaticity_y", 16)?;
            w.summary(|| format!("{:.5}", y as f64 / 65536.0));
            let max = w.u("luminance_max", 32)?;
            let max = max as f64 / 256.0;
            w.summary(|| format!("{} cd/m²", super::sei::nits(max)));
            let min = w.u("luminance_min", 32)?;
            let min = min as f64 / 16384.0;
            w.summary(|| format!("{} cd/m²", super::sei::nits(min)));
            Some(format!(
                "mastering display {}–{} cd/m²",
                super::sei::nits(min),
                super::sei::nits(max)
            ))
        }
        _ => Some(super::tables::lookup_or(METADATA_TYPES, t)),
    }
}

/// `AV1CodecConfigurationRecord` (`av1C`) up to the config OBUs; returns
/// a summary and the offset of the config OBUs.
pub fn av1c(w: &mut Walker) -> Option<String> {
    w.u("marker", 1)?;
    w.u("version", 7)?;
    let profile = w.en("seq_profile", 3, PROFILES)?;
    let level = w.u("seq_level_idx_0", 5)?;
    w.summary(|| format!("level {}", level_name(level)));
    let tier = w.flag("seq_tier_0")?;
    let high = w.flag("high_bitdepth")?;
    let twelve = w.flag("twelve_bit")?;
    let mono = w.flag("monochrome")?;
    let sx = w.u("chroma_subsampling_x", 1)?;
    let sy = w.u("chroma_subsampling_y", 1)?;
    w.en("chroma_sample_position", 2, CHROMA_POSITIONS)?;
    w.u("reserved", 3)?;
    if w.flag("initial_presentation_delay_present")? {
        w.u("initial_presentation_delay_minus_one", 4)?;
    } else {
        w.u("reserved", 4)?;
    }
    let s = SeqInfo {
        profile,
        level,
        tier,
        bit_depth: if twelve {
            12
        } else if high {
            10
        } else {
            8
        },
        mono,
        subsampling: (sx, sy),
        ..SeqInfo::default()
    };
    Some(format!(
        "{}@L{}{}, {}",
        super::tables::lookup_or(PROFILES, profile),
        level_name(level),
        if tier { " High tier" } else { "" },
        s.format()
    ))
}

/// What [`obu`] found.
#[derive(Clone, Debug, Default)]
pub struct Obu {
    pub kind: u64,
    /// Header and payload length in bytes.
    pub len: usize,
    pub summary: Option<String>,
}

/// One OBU parsed from `w` (positioned at its byte-aligned header), its
/// fields recorded at the top level. `seq` supplies the sequence header
/// for frame headers and is updated by a sequence header OBU.
pub fn obu(w: &mut Walker, seq: &mut Option<SeqInfo>) -> Option<Obu> {
    let start = w.pos() >> 3;
    let (kind, sized, _) = obu_header(w)?;
    let size = if sized {
        usize::try_from(w.leb128("obu_size")?).ok()?
    } else {
        w.bits_left() >> 3
    };
    let body = w.pos() >> 3;
    // The walker may hold only a prefix of a large OBU (a frame's tile
    // data): parse what is there.
    let mut sub = w.sub(body, size);
    let summary = match kind {
        1 => {
            let s = sequence_header(&mut sub);
            if let Some(s) = s {
                *seq = Some(s);
            }
            for n in sub.finish(s.is_some()) {
                w.push(n);
            }
            s.map(|s| s.describe())
        }
        3 | 6 | 7 => {
            let s = frame_header(&mut sub, seq.as_ref());
            let complete = s.is_some();
            for n in sub.finish(complete) {
                w.push(n);
            }
            s
        }
        5 => {
            let s = metadata(&mut sub);
            let complete = s.is_some();
            for n in sub.finish(complete) {
                w.push(n);
            }
            s
        }
        _ => None,
    };
    if matches!(kind, 4 | 6 | 8 | 15) && size > 0 && w.emitting() {
        let rest = w.rest_span(body.saturating_mul(8)).sub(0, to_u64(size));
        let name = match kind {
            4 => "Tile group data",
            6 => "Frame data",
            8 => "Tile list data",
            _ => "Padding",
        };
        let node = crate::node::Node::new(name)
            .span(rest)
            .summary(format!("{size} bytes"));
        w.push(node);
    }
    w.seek(body.saturating_add(size).saturating_mul(8));
    Some(Obu {
        kind,
        len: body.saturating_add(size).saturating_sub(start),
        summary,
    })
}
