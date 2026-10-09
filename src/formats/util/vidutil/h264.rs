//! H.264/AVC syntax (ITU-T H.264): NAL unit header, sequence and picture
//! parameter sets with VUI and HRD parameters, slice headers, access unit
//! delimiters and the `avcC` decoder configuration record.
//!
//! Syntax elements keep the names the standard gives them, so a field can
//! be looked up in the specification (and compared with `ffmpeg -bsf:v
//! trace_headers`); derived values are in the summaries.

use super::bitwalk::Walker;
use super::params::{ParamSets, PpsInfo, SliceInfo, SpsInfo};
use super::tables::{
    ASPECT_RATIO_IDC, CHROMA_FORMATS, COLOUR_PRIMARIES, H264_NAL_TYPES, H264_PROFILES,
    MATRIX_COEFFICIENTS, TRANSFER_CHARACTERISTICS, VIDEO_FORMATS, ceil_log2, h264_level_name,
    h264_profile_name, rate, sar_of,
};
use crate::value::{EnumTable, FlagTable, Value, flag};

const CONSTRAINTS: FlagTable = &[
    flag(0x80, "constraint_set0"),
    flag(0x40, "constraint_set1"),
    flag(0x20, "constraint_set2"),
    flag(0x10, "constraint_set3"),
    flag(0x08, "constraint_set4"),
    flag(0x04, "constraint_set5"),
];

pub const SLICE_TYPES: EnumTable = &[
    (0, "P"),
    (1, "B"),
    (2, "I"),
    (3, "SP"),
    (4, "SI"),
    (5, "P (all slices)"),
    (6, "B (all slices)"),
    (7, "I (all slices)"),
    (8, "SP (all slices)"),
    (9, "SI (all slices)"),
];

pub const PRIMARY_PIC_TYPES: EnumTable = &[
    (0, "I"),
    (1, "I, P"),
    (2, "I, P, B"),
    (3, "SI"),
    (4, "SI, SP"),
    (5, "I, SI"),
    (6, "I, SI, P, SP"),
    (7, "I, SI, P, SP, B"),
];

const POC_TYPES: EnumTable = &[
    (0, "explicit LSBs"),
    (1, "cycle of offsets"),
    (2, "follows decoding order"),
];

const SLICE_GROUP_MAP_TYPES: EnumTable = &[
    (0, "interleaved"),
    (1, "dispersed"),
    (2, "foreground with left-over"),
    (3, "box-out"),
    (4, "raster scan"),
    (5, "wipe"),
    (6, "explicit"),
];

const MODIFICATION_IDC: EnumTable = &[
    (0, "subtract from picture number"),
    (1, "add to picture number"),
    (2, "long-term picture"),
    (3, "end of list"),
];

const MMCO: EnumTable = &[
    (0, "end"),
    (1, "mark short-term unused"),
    (2, "mark long-term unused"),
    (3, "short-term to long-term"),
    (4, "set max long-term index"),
    (5, "mark all unused"),
    (6, "current to long-term"),
];

const HIGH_PROFILES: [u8; 13] = [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135];

/// `nal_unit_header()`: returns (`nal_ref_idc`, `nal_unit_type`).
pub fn nal_header(w: &mut Walker) -> Option<(u64, u64)> {
    let forbidden = w.flag("forbidden_zero_bit")?;
    if forbidden {
        w.with(|n| n.diag(crate::error::Diagnostic::malformed("must be 0")));
    }
    let r = w.u("nal_ref_idc", 2)?;
    let t = w.en("nal_unit_type", 5, H264_NAL_TYPES)?;
    if matches!(t, 14 | 20 | 21) {
        w.skip_as("nal_unit_header_extension", 24)?;
    }
    Some((r, t))
}

/// `scaling_list()`, read as one node with the resulting list.
fn scaling_list(w: &mut Walker, name: String, size: usize) -> Option<()> {
    let start = w.pos();
    let (mut last, mut next) = (8i64, 8i64);
    let mut values = Vec::with_capacity(size);
    let mut default = false;
    for j in 0..size {
        if next != 0 {
            let delta = w.read_se()?;
            if !(-128..=127).contains(&delta) {
                return None;
            }
            next = last.checked_add(delta)?.checked_add(256)?.rem_euclid(256);
            default = j == 0 && next == 0;
        }
        let v = if next == 0 { last } else { next };
        values.push(v);
        last = v;
    }
    if w.emitting() {
        let text = if default {
            "default".to_owned()
        } else {
            values
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        };
        w.text(name, start, text);
    }
    Some(())
}

const SCALING_NAMES: [&str; 12] = [
    "4×4 intra Y",
    "4×4 intra Cb",
    "4×4 intra Cr",
    "4×4 inter Y",
    "4×4 inter Cb",
    "4×4 inter Cr",
    "8×8 intra Y",
    "8×8 inter Y",
    "8×8 intra Cb",
    "8×8 inter Cb",
    "8×8 intra Cr",
    "8×8 inter Cr",
];

fn scaling_matrix(w: &mut Walker, prefix: &'static str, lists: usize) -> Option<()> {
    w.begin("Scaling lists");
    for i in 0..lists {
        let present = w.flag(format!("{prefix}_scaling_list_present_flag[{i}]"))?;
        if present {
            let name = format!(
                "Scaling list {}",
                SCALING_NAMES.get(i).copied().unwrap_or("?")
            );
            scaling_list(w, name, if i < 6 { 16 } else { 64 })?;
        }
    }
    w.end();
    Some(())
}

/// `seq_parameter_set_data()` (after the NAL header).
pub fn sps(w: &mut Walker) -> Option<SpsInfo> {
    let mut s = SpsInfo::default();
    let profile = u8::try_from(w.en("profile_idc", 8, H264_PROFILES)?).ok()?;
    let start = w.pos();
    let constraints = u8::try_from(w.read(8)?).ok()?;
    if w.emitting() {
        let (set, unknown) = crate::value::decode_flags(CONSTRAINTS, constraints.into());
        w.record(
            "Constraint flags",
            start,
            Value::Flags {
                raw: constraints.into(),
                bits: 8,
                set,
                unknown,
            },
        );
        w.summary(|| h264_profile_name(profile, constraints));
    }
    let level = u8::try_from(w.u("level_idc", 8)?).ok()?;
    w.summary(|| format!("level {}", h264_level_name(profile, constraints, level)));
    s.profile = profile;
    s.tier_or_constraints = constraints;
    s.level = level;
    s.id = w.ue("seq_parameter_set_id")?;
    if s.id > 31 {
        return None;
    }
    s.chroma_format = 1;
    s.bit_depth = 8;
    s.bit_depth_chroma = 8;
    if HIGH_PROFILES.contains(&profile) {
        s.chroma_format = w.ue_en("chroma_format_idc", CHROMA_FORMATS)?;
        if s.chroma_format > 3 {
            return None;
        }
        if s.chroma_format == 3 {
            s.slice.separate_colour_plane = w.flag("separate_colour_plane_flag")?;
        }
        let luma = w.ue("bit_depth_luma_minus8")?;
        w.summary(|| format!("{}-bit", luma.saturating_add(8)));
        let chroma = w.ue("bit_depth_chroma_minus8")?;
        w.summary(|| format!("{}-bit", chroma.saturating_add(8)));
        if luma > 6 || chroma > 6 {
            return None;
        }
        s.bit_depth = luma.saturating_add(8);
        s.bit_depth_chroma = chroma.saturating_add(8);
        w.flag("qpprime_y_zero_transform_bypass_flag")?;
        if w.flag("seq_scaling_matrix_present_flag")? {
            scaling_matrix(w, "seq", if s.chroma_format == 3 { 12 } else { 8 })?;
        }
    }
    s.slice.chroma_array_type = if s.slice.separate_colour_plane {
        0
    } else {
        s.chroma_format
    };
    let frame_num = w.ue("log2_max_frame_num_minus4")?;
    if frame_num > 12 {
        return None;
    }
    s.slice.log2_max_frame_num = u32::try_from(frame_num).ok()?.saturating_add(4);
    s.slice.poc_type = w.ue_en("pic_order_cnt_type", POC_TYPES)?;
    match s.slice.poc_type {
        0 => {
            let lsb = w.ue("log2_max_pic_order_cnt_lsb_minus4")?;
            if lsb > 12 {
                return None;
            }
            s.slice.log2_max_poc_lsb = u32::try_from(lsb).ok()?.saturating_add(4);
        }
        1 => {
            s.slice.delta_pic_order_always_zero = w.flag("delta_pic_order_always_zero_flag")?;
            w.se("offset_for_non_ref_pic")?;
            w.se("offset_for_top_to_bottom_field")?;
            let cycle = w.ue("num_ref_frames_in_pic_order_cnt_cycle")?;
            if cycle > 255 {
                return None;
            }
            for i in 0..cycle {
                w.se(format!("offset_for_ref_frame[{i}]"))?;
            }
        }
        2 => {}
        _ => return None,
    }
    w.ue("max_num_ref_frames")?;
    w.flag("gaps_in_frame_num_value_allowed_flag")?;
    let width_mbs = w.ue("pic_width_in_mbs_minus1")?.checked_add(1)?;
    w.summary(|| format!("{} pixels", width_mbs.saturating_mul(16)));
    let height_units = w.ue("pic_height_in_map_units_minus1")?.checked_add(1)?;
    s.slice.frame_mbs_only = w.flag("frame_mbs_only_flag")?;
    let fields = if s.slice.frame_mbs_only { 1u64 } else { 2 };
    if !s.slice.frame_mbs_only {
        w.flag("mb_adaptive_frame_field_flag")?;
    }
    w.flag("direct_8x8_inference_flag")?;
    s.interlaced = !s.slice.frame_mbs_only;
    s.slice.pic_size_in_map_units = width_mbs.checked_mul(height_units)?;
    s.coded_width = width_mbs.checked_mul(16)?;
    s.coded_height = height_units.checked_mul(16)?.checked_mul(fields)?;
    let (sub_w, sub_h): (u64, u64) = match s.chroma_format {
        1 => (2, 2),
        2 => (2, 1),
        _ => (1, 1),
    };
    let (crop_x, crop_y) = if s.slice.chroma_array_type == 0 {
        (1u64, fields)
    } else {
        (sub_w, sub_h.saturating_mul(fields))
    };
    s.width = s.coded_width;
    s.height = s.coded_height;
    if w.flag("frame_cropping_flag")? {
        w.begin("Frame cropping");
        let l = w.ue("frame_crop_left_offset")?;
        let r = w.ue("frame_crop_right_offset")?;
        let t = w.ue("frame_crop_top_offset")?;
        let b = w.ue("frame_crop_bottom_offset")?;
        let cut_w = l.saturating_add(r).saturating_mul(crop_x);
        let cut_h = t.saturating_add(b).saturating_mul(crop_y);
        s.width = s.coded_width.saturating_sub(cut_w);
        s.height = s.coded_height.saturating_sub(cut_h);
        let (cw, ch) = (s.coded_width, s.coded_height);
        let (dw, dh) = (s.width, s.height);
        w.end_summary(|| format!("{cw}×{ch} cropped to {dw}×{dh}"));
    }
    if w.flag("vui_parameters_present_flag")? {
        let depth = w.depth();
        if vui(w, &mut s).is_none() {
            w.fail_to(depth);
        }
    }
    Some(s)
}

/// `vui_parameters()` of an H.264 SPS.
fn vui(w: &mut Walker, s: &mut SpsInfo) -> Option<()> {
    w.begin("VUI parameters");
    vui_aspect(w, s)?;
    if w.flag("overscan_info_present_flag")? {
        w.flag("overscan_appropriate_flag")?;
    }
    vui_signal(w, s)?;
    if w.flag("chroma_loc_info_present_flag")? {
        w.ue("chroma_sample_loc_type_top_field")?;
        w.ue("chroma_sample_loc_type_bottom_field")?;
    }
    if w.flag("timing_info_present_flag")? {
        let units = w.u("num_units_in_tick", 32)?;
        let scale = w.u("time_scale", 32)?;
        if units > 0 && scale > 0 {
            let (n, d) = super::tables::reduce(scale, units.saturating_mul(2));
            s.frame_rate = Some((n, d));
            w.summary(|| format!("{} fps", rate(n, d)));
        }
        w.flag("fixed_frame_rate_flag")?;
    }
    let nal = w.flag("nal_hrd_parameters_present_flag")?;
    if nal {
        w.begin("NAL HRD parameters");
        s.slice.nal_cpb_cnt = hrd(w, s)?;
        w.end();
    }
    let vcl = w.flag("vcl_hrd_parameters_present_flag")?;
    if vcl {
        w.begin("VCL HRD parameters");
        s.slice.vcl_cpb_cnt = hrd(w, s)?;
        w.end();
    }
    if nal || vcl {
        w.flag("low_delay_hrd_flag")?;
    }
    s.slice.pic_struct_present = w.flag("pic_struct_present_flag")?;
    if w.flag("bitstream_restriction_flag")? {
        w.flag("motion_vectors_over_pic_boundaries_flag")?;
        w.ue("max_bytes_per_pic_denom")?;
        w.ue("max_bits_per_mb_denom")?;
        w.ue("log2_max_mv_length_horizontal")?;
        w.ue("log2_max_mv_length_vertical")?;
        w.ue("max_num_reorder_frames")?;
        w.ue("max_dec_frame_buffering")?;
    }
    let summary = vui_summary(s);
    w.end_summary(|| summary);
    Some(())
}

fn vui_summary(s: &SpsInfo) -> String {
    let mut parts = Vec::new();
    if let Some((a, b)) = s.sar {
        parts.push(format!("SAR {a}:{b}"));
    }
    if let Some((n, d)) = s.frame_rate {
        parts.push(format!("{} fps", rate(n, d)));
    }
    if let Some(c) = s.colour_summary() {
        parts.push(c);
    }
    if s.full_range == Some(true) {
        parts.push("full range".to_owned());
    }
    parts.join(", ")
}

/// The aspect ratio part of the VUI (same in H.264 and HEVC).
pub(super) fn vui_aspect(w: &mut Walker, s: &mut SpsInfo) -> Option<()> {
    if w.flag("aspect_ratio_info_present_flag")? {
        let idc = w.en("aspect_ratio_idc", 8, ASPECT_RATIO_IDC)?;
        if idc == 255 {
            let a = w.u("sar_width", 16)?;
            let b = w.u("sar_height", 16)?;
            s.sar = Some((a, b));
        } else {
            s.sar = sar_of(idc);
        }
    }
    Some(())
}

/// The video signal type part of the VUI (same in H.264 and HEVC).
pub(super) fn vui_signal(w: &mut Walker, s: &mut SpsInfo) -> Option<()> {
    if w.flag("video_signal_type_present_flag")? {
        w.en("video_format", 3, VIDEO_FORMATS)?;
        let full = w.flag("video_full_range_flag")?;
        w.summary(|| {
            if full {
                "0–255 (full)"
            } else {
                "16–235 (limited)"
            }
            .to_owned()
        });
        s.full_range = Some(full);
        if w.flag("colour_description_present_flag")? {
            let p = w.en("colour_primaries", 8, COLOUR_PRIMARIES)?;
            let t = w.en("transfer_characteristics", 8, TRANSFER_CHARACTERISTICS)?;
            let m = w.en("matrix_coefficients", 8, MATRIX_COEFFICIENTS)?;
            s.colour = Some((p, t, m));
        }
    }
    Some(())
}

/// `hrd_parameters()`: returns the number of CPB specifications.
fn hrd(w: &mut Walker, s: &mut SpsInfo) -> Option<u64> {
    let cnt = w.ue("cpb_cnt_minus1")?.checked_add(1)?;
    if cnt > 32 {
        return None;
    }
    let rate_scale = w.u("bit_rate_scale", 4)?;
    let size_scale = w.u("cpb_size_scale", 4)?;
    for i in 0..cnt {
        let rate = w.ue(format!("bit_rate_value_minus1[{i}]"))?;
        w.summary(|| {
            let v = rate
                .saturating_add(1)
                .checked_shl(u32::try_from(rate_scale.saturating_add(6)).unwrap_or(0))
                .unwrap_or(u64::MAX);
            format!("{} kb/s", v / 1000)
        });
        let size = w.ue(format!("cpb_size_value_minus1[{i}]"))?;
        w.summary(|| {
            let v = size
                .saturating_add(1)
                .checked_shl(u32::try_from(size_scale.saturating_add(4)).unwrap_or(0))
                .unwrap_or(u64::MAX);
            format!("{v} bits")
        });
        w.flag(format!("cbr_flag[{i}]"))?;
    }
    let initial = w.u("initial_cpb_removal_delay_length_minus1", 5)?;
    let removal = w.u("cpb_removal_delay_length_minus1", 5)?;
    let output = w.u("dpb_output_delay_length_minus1", 5)?;
    let offset = w.u("time_offset_length", 5)?;
    s.slice.initial_cpb_removal_delay_length = u32::try_from(initial).ok()?.saturating_add(1);
    s.slice.cpb_removal_delay_length = u32::try_from(removal).ok()?.saturating_add(1);
    s.slice.dpb_output_delay_length = u32::try_from(output).ok()?.saturating_add(1);
    s.slice.time_offset_length = u32::try_from(offset).ok()?;
    Some(cnt)
}

/// `pic_parameter_set_rbsp()` (after the NAL header). `ps` supplies the
/// SPS's chroma format for the scaling lists.
pub fn pps(w: &mut Walker, ps: &ParamSets) -> Option<PpsInfo> {
    let mut p = PpsInfo {
        id: w.ue("pic_parameter_set_id")?,
        sps_id: w.ue("seq_parameter_set_id")?,
        ..PpsInfo::default()
    };
    if p.id > 255 || p.sps_id > 31 {
        return None;
    }
    p.cabac = w.flag("entropy_coding_mode_flag")?;
    let cabac = p.cabac;
    w.summary(|| if cabac { "CABAC" } else { "CAVLC" }.to_owned());
    p.bottom_field_pic_order = w.flag("bottom_field_pic_order_in_frame_present_flag")?;
    p.num_slice_groups = w.ue("num_slice_groups_minus1")?.checked_add(1)?;
    if p.num_slice_groups > 8 {
        return None;
    }
    if p.num_slice_groups > 1 {
        w.begin("Slice groups");
        p.slice_group_map_type = w.ue_en("slice_group_map_type", SLICE_GROUP_MAP_TYPES)?;
        match p.slice_group_map_type {
            0 => {
                for i in 0..p.num_slice_groups {
                    w.ue(format!("run_length_minus1[{i}]"))?;
                }
            }
            2 => {
                for i in 0..p.num_slice_groups.saturating_sub(1) {
                    w.ue(format!("top_left[{i}]"))?;
                    w.ue(format!("bottom_right[{i}]"))?;
                }
            }
            3..=5 => {
                w.flag("slice_group_change_direction_flag")?;
                p.slice_group_change_rate =
                    w.ue("slice_group_change_rate_minus1")?.checked_add(1)?;
            }
            6 => {
                let units = w.ue("pic_size_in_map_units_minus1")?.checked_add(1)?;
                let bits = u64::from(ceil_log2(p.num_slice_groups));
                let total = usize::try_from(units.checked_mul(bits)?).ok()?;
                w.skip_as("slice_group_id[]", total)?;
            }
            1 => {}
            _ => return None,
        }
        w.end();
    }
    let l0 = w
        .ue("num_ref_idx_l0_default_active_minus1")?
        .checked_add(1)?;
    let l1 = w
        .ue("num_ref_idx_l1_default_active_minus1")?
        .checked_add(1)?;
    if l0 > 32 || l1 > 32 {
        return None;
    }
    p.num_ref_idx_default = [l0, l1];
    p.weighted_pred = w.flag("weighted_pred_flag")?;
    p.weighted_bipred_idc = w.u("weighted_bipred_idc", 2)?;
    let qp = w.se("pic_init_qp_minus26")?;
    p.pic_init_qp = qp.checked_add(26)?;
    let init = p.pic_init_qp;
    w.summary(|| format!("QP {init}"));
    w.se("pic_init_qs_minus26")?;
    w.se("chroma_qp_index_offset")?;
    p.deblocking_filter_control = w.flag("deblocking_filter_control_present_flag")?;
    w.flag("constrained_intra_pred_flag")?;
    p.redundant_pic_cnt_present = w.flag("redundant_pic_cnt_present_flag")?;
    if w.more_rbsp_data() {
        p.transform_8x8 = w.flag("transform_8x8_mode_flag")?;
        if w.flag("pic_scaling_matrix_present_flag")? {
            let chroma = ps.sps.get(&p.sps_id).map_or(1, |s| s.chroma_format);
            let extra = if p.transform_8x8 {
                if chroma == 3 { 6 } else { 2 }
            } else {
                0
            };
            scaling_matrix(w, "pic", 6usize.saturating_add(extra))?;
        }
        w.se("second_chroma_qp_index_offset")?;
    }
    Some(p)
}

/// `access_unit_delimiter_rbsp()`.
pub fn aud(w: &mut Walker) -> Option<u64> {
    w.en("primary_pic_type", 3, PRIMARY_PIC_TYPES)
}

/// `slice_header()` of a slice NAL unit (types 1, 5). Fills `info` as far
/// as it gets; without the PPS and SPS it refers to, only the first three
/// elements are read.
pub fn slice_header(
    w: &mut Walker,
    nal_type: u64,
    ref_idc: u64,
    ps: &ParamSets,
    info: &mut SliceInfo,
) -> Option<()> {
    info.first_mb = w.ue("first_mb_in_slice")?;
    info.slice_type = w.ue_en("slice_type", SLICE_TYPES)?;
    if info.slice_type > 9 {
        return None;
    }
    info.parsed = true;
    info.pps_id = w.ue("pic_parameter_set_id")?;
    let Some((pps, sps)) = ps.for_pps(info.pps_id) else {
        w.push(
            crate::node::Node::new("Remaining fields").desc(
                "Not decoded: the picture parameter set this slice refers to has not been seen",
            ),
        );
        return Some(());
    };
    let (pps, sps) = (*pps, sps.slice);
    let st = info.slice_type % 5;
    let idr = nal_type == 5;
    if sps.separate_colour_plane {
        w.u("colour_plane_id", 2)?;
    }
    info.frame_num = Some(w.u("frame_num", sps.log2_max_frame_num)?);
    let mut field_pic = false;
    if !sps.frame_mbs_only {
        field_pic = w.flag("field_pic_flag")?;
        if field_pic {
            info.field = Some(w.flag("bottom_field_flag")?);
        }
    }
    if idr {
        w.ue("idr_pic_id")?;
    }
    if sps.poc_type == 0 {
        info.poc_lsb = Some(w.u("pic_order_cnt_lsb", sps.log2_max_poc_lsb)?);
        if pps.bottom_field_pic_order && !field_pic {
            w.se("delta_pic_order_cnt_bottom")?;
        }
    }
    if sps.poc_type == 1 && !sps.delta_pic_order_always_zero {
        w.se("delta_pic_order_cnt[0]")?;
        if pps.bottom_field_pic_order && !field_pic {
            w.se("delta_pic_order_cnt[1]")?;
        }
    }
    if pps.redundant_pic_cnt_present {
        w.ue("redundant_pic_cnt")?;
    }
    let (p, b, sp, si) = (st == 0, st == 1, st == 3, st == 4);
    if b {
        w.flag("direct_spatial_mv_pred_flag")?;
    }
    let mut refs = pps.num_ref_idx_default;
    if (p || sp || b) && w.flag("num_ref_idx_active_override_flag")? {
        refs[0] = w.ue("num_ref_idx_l0_active_minus1")?.checked_add(1)?;
        if b {
            refs[1] = w.ue("num_ref_idx_l1_active_minus1")?.checked_add(1)?;
        }
    }
    if refs[0] > 32 || refs[1] > 32 {
        return None;
    }
    // ref_pic_list_modification()
    if st != 2 && st != 4 {
        for list in 0..(if b { 2 } else { 1 }) {
            if w.flag(format!("ref_pic_list_modification_flag_l{list}"))? {
                w.begin(format!("Reference list {list} modifications"));
                for _ in 0..=64 {
                    let idc = w.ue_en("modification_of_pic_nums_idc", MODIFICATION_IDC)?;
                    match idc {
                        0 | 1 => {
                            w.ue("abs_diff_pic_num_minus1")?;
                        }
                        2 => {
                            w.ue("long_term_pic_num")?;
                        }
                        3 => break,
                        _ => return None,
                    }
                }
                w.end();
            }
        }
    }
    if (pps.weighted_pred && (p || sp)) || (pps.weighted_bipred_idc == 1 && b) {
        pred_weight_table(w, sps.chroma_array_type, refs, b)?;
    }
    if ref_idc != 0 {
        w.begin("Decoded reference picture marking");
        if idr {
            w.flag("no_output_of_prior_pics_flag")?;
            w.flag("long_term_reference_flag")?;
        } else if w.flag("adaptive_ref_pic_marking_mode_flag")? {
            for _ in 0..=66 {
                let op = w.ue_en("memory_management_control_operation", MMCO)?;
                if op == 0 {
                    break;
                }
                if op == 1 || op == 3 {
                    w.ue("difference_of_pic_nums_minus1")?;
                }
                if op == 2 {
                    w.ue("long_term_pic_num")?;
                }
                if op == 3 || op == 6 {
                    w.ue("long_term_frame_idx")?;
                }
                if op == 4 {
                    w.ue("max_long_term_frame_idx_plus1")?;
                }
                if op > 6 {
                    return None;
                }
            }
        }
        w.end();
    }
    if pps.cabac && st != 2 && st != 4 {
        w.ue("cabac_init_idc")?;
    }
    let delta = w.se("slice_qp_delta")?;
    let qp = pps.pic_init_qp.saturating_add(delta);
    info.qp = Some(qp);
    w.summary(|| format!("QP {qp}"));
    if sp || si {
        if sp {
            w.flag("sp_for_switch_flag")?;
        }
        w.se("slice_qs_delta")?;
    }
    if pps.deblocking_filter_control {
        let idc = w.ue("disable_deblocking_filter_idc")?;
        if idc != 1 {
            w.se("slice_alpha_c0_offset_div2")?;
            w.se("slice_beta_offset_div2")?;
        }
    }
    if pps.num_slice_groups > 1 && (3..=5).contains(&pps.slice_group_map_type) {
        let rate = pps.slice_group_change_rate.max(1);
        let bits =
            ceil_log2((sps.pic_size_in_map_units.checked_div(rate).unwrap_or(0)).saturating_add(1));
        w.u("slice_group_change_cycle", bits)?;
    }
    Some(())
}

/// `pred_weight_table()`.
fn pred_weight_table(w: &mut Walker, chroma: u64, refs: [u64; 2], b: bool) -> Option<()> {
    w.begin("Prediction weight table");
    w.ue("luma_log2_weight_denom")?;
    if chroma != 0 {
        w.ue("chroma_log2_weight_denom")?;
    }
    for list in 0..(if b { 2usize } else { 1 }) {
        let n = refs.get(list).copied().unwrap_or(0);
        for i in 0..n {
            if w.flag(format!("luma_weight_l{list}_flag[{i}]"))? {
                w.se(format!("luma_weight_l{list}[{i}]"))?;
                w.se(format!("luma_offset_l{list}[{i}]"))?;
            }
            if chroma != 0 && w.flag(format!("chroma_weight_l{list}_flag[{i}]"))? {
                for j in 0..2 {
                    w.se(format!("chroma_weight_l{list}[{i}][{j}]"))?;
                    w.se(format!("chroma_offset_l{list}[{i}][{j}]"))?;
                }
            }
        }
    }
    w.end();
    Some(())
}
