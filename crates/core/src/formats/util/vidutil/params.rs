//! What H.264 and HEVC parameter sets say, as plain values: the picture
//! (size, chroma, bit depth, aspect, rate, colour) and what slice headers
//! need to be parsed.

use std::collections::BTreeMap;

use super::tables::{
    COLOUR_PRIMARIES, H264_PROFILES, HEVC_PROFILES, MATRIX_COEFFICIENTS, TRANSFER_CHARACTERISTICS,
    h264_level_name, h264_profile_name, hevc_level_name, lookup_or, rate,
};

/// What an H.264 or HEVC SPS tells about the picture.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpsInfo {
    pub profile: u8,
    pub level: u8,
    /// HEVC tier (0 = Main, 1 = High); H.264 constraint flags.
    pub tier_or_constraints: u8,
    pub chroma_format: u64,
    /// Luma bit depth.
    pub bit_depth: u64,
    /// Display (cropped) size.
    pub width: u64,
    pub height: u64,
    /// Whether this is an HEVC SPS.
    pub hevc: bool,
    pub id: u64,
    pub bit_depth_chroma: u64,
    /// Coded size before cropping.
    pub coded_width: u64,
    pub coded_height: u64,
    /// Field-coded (H.264 `frame_mbs_only_flag` 0; HEVC `field_seq_flag`).
    pub interlaced: bool,
    /// Sample aspect ratio from the VUI.
    pub sar: Option<(u64, u64)>,
    /// Frame rate (numerator, denominator) from the VUI timing info.
    pub frame_rate: Option<(u64, u64)>,
    /// Colour primaries, transfer characteristics, matrix coefficients.
    pub colour: Option<(u64, u64, u64)>,
    pub full_range: Option<bool>,
    /// HEVC `general_profile_space`.
    pub profile_space: u8,
    /// HEVC `general_profile_compatibility_flags`.
    pub compatibility: u32,
    /// HEVC general constraint indicator flags (48 bits).
    pub constraint_flags: u64,
    pub slice: SliceParams,
}

/// SPS values that slice headers and SEI messages depend on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SliceParams {
    pub log2_max_frame_num: u32,
    pub poc_type: u64,
    pub log2_max_poc_lsb: u32,
    pub delta_pic_order_always_zero: bool,
    pub frame_mbs_only: bool,
    pub separate_colour_plane: bool,
    pub chroma_array_type: u64,
    pub pic_size_in_map_units: u64,
    /// HEVC `PicSizeInCtbsY`.
    pub pic_size_in_ctbs: u64,
    /// HRD: CPB counts of the NAL and VCL HRD (0 when absent).
    pub nal_cpb_cnt: u64,
    pub vcl_cpb_cnt: u64,
    pub initial_cpb_removal_delay_length: u32,
    pub cpb_removal_delay_length: u32,
    pub dpb_output_delay_length: u32,
    pub time_offset_length: u32,
    pub pic_struct_present: bool,
    /// HEVC VUI `frame_field_info_present_flag`.
    pub frame_field_info_present: bool,
}

/// What a PPS tells slice headers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PpsInfo {
    pub id: u64,
    pub sps_id: u64,
    pub cabac: bool,
    pub bottom_field_pic_order: bool,
    pub num_slice_groups: u64,
    pub slice_group_map_type: u64,
    pub slice_group_change_rate: u64,
    pub num_ref_idx_default: [u64; 2],
    pub weighted_pred: bool,
    pub weighted_bipred_idc: u64,
    pub pic_init_qp: i64,
    pub deblocking_filter_control: bool,
    pub redundant_pic_cnt_present: bool,
    pub transform_8x8: bool,
    /// HEVC
    pub dependent_slice_segments: bool,
    pub output_flag_present: bool,
    pub num_extra_slice_header_bits: u64,
}

/// What a slice header says, for summaries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SliceInfo {
    /// `slice_type` as coded.
    pub slice_type: u64,
    pub first_mb: u64,
    pub pps_id: u64,
    pub frame_num: Option<u64>,
    pub poc_lsb: Option<u64>,
    /// Some(bottom) for a field slice.
    pub field: Option<bool>,
    pub qp: Option<i64>,
    pub hevc: bool,
    /// Whether `slice_type` was read.
    pub parsed: bool,
}

impl SliceInfo {
    /// "I", "P", "B", "SP", "SI".
    pub fn kind(&self) -> &'static str {
        if self.hevc {
            match self.slice_type {
                0 => "B",
                1 => "P",
                2 => "I",
                _ => "dependent",
            }
        } else {
            match self.slice_type % 5 {
                0 => "P",
                1 => "B",
                2 => "I",
                3 => "SP",
                _ => "SI",
            }
        }
    }

    pub fn describe(&self) -> String {
        let mut s = format!("{} slice", self.kind());
        if let Some(bottom) = self.field {
            s.push_str(if bottom {
                " (bottom field)"
            } else {
                " (top field)"
            });
        }
        if let Some(f) = self.frame_num {
            s.push_str(&format!(", frame_num {f}"));
        }
        if let Some(p) = self.poc_lsb {
            s.push_str(&format!(", POC lsb {p}"));
        }
        if let Some(q) = self.qp {
            s.push_str(&format!(", QP {q}"));
        }
        s
    }
}

/// Parameter sets seen so far in a stream, by ID.
#[derive(Clone, Debug, Default)]
pub struct ParamSets {
    pub sps: BTreeMap<u64, SpsInfo>,
    pub pps: BTreeMap<u64, PpsInfo>,
    /// The ID of the SPS seen last (for SEI messages).
    pub last_sps: Option<u64>,
}

impl ParamSets {
    /// The PPS with this ID and the SPS it refers to.
    pub fn for_pps(&self, id: u64) -> Option<(&PpsInfo, &SpsInfo)> {
        let pps = self.pps.get(&id)?;
        let sps = self.sps.get(&pps.sps_id)?;
        Some((pps, sps))
    }

    /// The SPS seen last.
    pub fn last(&self) -> Option<&SpsInfo> {
        self.sps.get(&self.last_sps?)
    }

    /// Records the parameter set a NAL unit carried. Returns whether
    /// anything changed.
    pub fn update(&mut self, sps: Option<&SpsInfo>, pps: Option<&PpsInfo>) -> bool {
        let mut changed = false;
        if let Some(s) = sps {
            if self.sps.get(&s.id) != Some(s) {
                self.sps.insert(s.id, s.clone());
                changed = true;
            }
            if self.last_sps != Some(s.id) {
                self.last_sps = Some(s.id);
                changed = true;
            }
        }
        if let Some(p) = pps
            && self.pps.get(&p.id) != Some(p)
        {
            self.pps.insert(p.id, *p);
            changed = true;
        }
        changed
    }
}

pub fn h264_level(level: u8) -> String {
    format!("{}.{}", level / 10, level % 10)
}

pub fn hevc_level(level: u8) -> String {
    let tenth = level / 3;
    format!("{}.{}", tenth / 10, tenth % 10)
}

impl SpsInfo {
    pub fn h264_summary(&self) -> String {
        let profile = crate::value::lookup(H264_PROFILES, self.profile.into())
            .map_or_else(|| format!("profile {}", self.profile), str::to_owned);
        format!(
            "{profile}@L{}, {}×{}",
            h264_level(self.level),
            self.width,
            self.height
        )
    }

    pub fn hevc_summary(&self) -> String {
        let profile = crate::value::lookup(HEVC_PROFILES, self.profile.into())
            .map_or_else(|| format!("profile {}", self.profile), str::to_owned);
        let tier = if self.tier_or_constraints != 0 {
            "High"
        } else {
            "Main"
        };
        format!(
            "{profile}@L{} {tier} tier, {}×{}",
            hevc_level(self.level),
            self.width,
            self.height
        )
    }

    /// The profile and level ("High@L4.1", "Main 10@L5.1 Main tier").
    pub fn profile_level(&self) -> String {
        if self.hevc {
            let profile = crate::value::lookup(HEVC_PROFILES, self.profile.into())
                .map_or_else(|| format!("profile {}", self.profile), str::to_owned);
            let tier = if self.tier_or_constraints != 0 {
                "High"
            } else {
                "Main"
            };
            format!("{profile}@L{} {tier} tier", hevc_level_name(self.level))
        } else {
            format!(
                "{}@L{}",
                h264_profile_name(self.profile, self.tier_or_constraints),
                h264_level_name(self.profile, self.tier_or_constraints, self.level)
            )
        }
    }

    /// "4:2:0 8-bit" (or "4:2:0 10-bit").
    pub fn format(&self) -> String {
        let chroma = match self.chroma_format {
            0 => "monochrome",
            1 => "4:2:0",
            2 => "4:2:2",
            3 => "4:4:4",
            _ => "?",
        };
        if self.bit_depth_chroma != 0
            && self.bit_depth_chroma != self.bit_depth
            && self.chroma_format != 0
        {
            format!("{chroma} {}/{}-bit", self.bit_depth, self.bit_depth_chroma)
        } else {
            format!("{chroma} {}-bit", self.bit_depth)
        }
    }

    /// A one-line description: profile, size, format, aspect, rate,
    /// colour.
    pub fn describe(&self) -> String {
        let mut parts = vec![
            self.profile_level(),
            format!(
                "{}×{}{}",
                self.width,
                self.height,
                if self.interlaced { " interlaced" } else { "" }
            ),
            self.format(),
        ];
        if let Some((w, h)) = self.sar
            && (w, h) != (1, 1)
            && w != 0
            && h != 0
        {
            parts.push(format!("SAR {w}:{h}"));
        }
        if let Some((n, d)) = self.frame_rate {
            parts.push(format!("{} fps", rate(n, d)));
        }
        if let Some(c) = self.colour_summary() {
            parts.push(c);
        }
        parts.join(", ")
    }

    /// "BT.709", "BT.2020/PQ", ... when the colour description says more
    /// than "unspecified".
    pub fn colour_summary(&self) -> Option<String> {
        let (p, t, m) = self.colour?;
        colour_summary(p, t, m)
    }

    /// The RFC 6381 codec string (`avc1.64001F`, `hvc1.2.4.L153.B0`).
    pub fn codec_string(&self) -> String {
        if self.hevc {
            hevc_codec_string(
                "hvc1",
                self.profile_space,
                self.profile,
                self.compatibility,
                self.tier_or_constraints != 0,
                self.level,
                self.constraint_flags,
            )
        } else {
            format!(
                "avc1.{:02X}{:02X}{:02X}",
                self.profile, self.tier_or_constraints, self.level
            )
        }
    }
}

/// A short colour description, or `None` when all three are unspecified.
pub fn colour_summary(primaries: u64, transfer: u64, matrix: u64) -> Option<String> {
    if primaries == 2 && transfer == 2 && matrix == 2 {
        return None;
    }
    let p = lookup_or(COLOUR_PRIMARIES, primaries);
    let t = lookup_or(TRANSFER_CHARACTERISTICS, transfer);
    let m = lookup_or(MATRIX_COEFFICIENTS, matrix);
    // The matrix usually follows the primaries (BT.709, BT.2020 non-constant,
    // SMPTE 170M); name it only when it does not.
    let family = |a: &str, b: &str| a.split_whitespace().next() == b.split_whitespace().next();
    let mut parts = vec![p.clone()];
    if t != p {
        parts.push(t);
    }
    if !family(&m, &p) {
        parts.push(m);
    }
    Some(parts.join("/"))
}

/// The HEVC codec string of ISO/IEC 14496-15 Annex E.
pub fn hevc_codec_string(
    fourcc: &str,
    profile_space: u8,
    profile: u8,
    compatibility: u32,
    high_tier: bool,
    level: u8,
    constraints: u64,
) -> String {
    let space = match profile_space {
        1 => "A",
        2 => "B",
        3 => "C",
        _ => "",
    };
    let mut s = format!(
        "{fourcc}.{space}{profile}.{:X}.{}{level}",
        compatibility.reverse_bits(),
        if high_tier { "H" } else { "L" }
    );
    let bytes = (constraints & 0xffff_ffff_ffff).to_be_bytes();
    let bytes = bytes.get(2..).unwrap_or_default();
    let used = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i.saturating_add(1));
    for b in bytes.get(..used).unwrap_or_default() {
        s.push_str(&format!(".{b:X}"));
    }
    s
}
