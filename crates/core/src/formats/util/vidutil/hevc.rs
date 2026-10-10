//! H.265/HEVC syntax (ITU-T H.265): NAL unit header, video, sequence and
//! picture parameter sets (profile/tier/level, conformance window, VUI,
//! HRD, short-term reference picture sets, scaling lists) and the start
//! of slice segment headers.

use super::bitwalk::Walker;
use super::h264::{vui_aspect, vui_signal};
use super::params::{ParamSets, PpsInfo, SliceInfo, SpsInfo};
use super::tables::{
    CHROMA_FORMATS, HEVC_NAL_TYPES, HEVC_PROFILES, ceil_log2, hevc_level_name, rate, reduce,
};
use crate::value::EnumTable;

pub const SLICE_TYPES: EnumTable = &[(0, "B"), (1, "P"), (2, "I")];

const PIC_TYPES: EnumTable = &[(0, "I"), (1, "I, P"), (2, "I, P, B")];

/// `nal_unit_header()`: returns (`nal_unit_type`, `nuh_layer_id`,
/// `nuh_temporal_id_plus1`).
pub fn nal_header(w: &mut Walker) -> Option<(u64, u64, u64)> {
    let forbidden = w.flag("forbidden_zero_bit")?;
    if forbidden {
        w.with(|n| n.diag(crate::error::Diagnostic::malformed("must be 0")));
    }
    let t = w.en("nal_unit_type", 6, HEVC_NAL_TYPES)?;
    let layer = w.u("nuh_layer_id", 6)?;
    let tid = w.u("nuh_temporal_id_plus1", 3)?;
    Some((t, layer, tid))
}

fn rext_family(profile: u64, compat: u64) -> bool {
    (4..=11).contains(&profile) || (4..=11).any(|j| compat_has(compat, j))
}

/// Whether `general_profile_compatibility_flag[j]` is set.
fn compat_has(compat: u64, j: u64) -> bool {
    j < 32 && compat & (1u64 << 31u64.saturating_sub(j)) != 0
}

/// `profile_tier_level(1, max_sub_layers_minus1)`: fills the general
/// profile fields of `s`.
pub fn profile_tier_level(
    w: &mut Walker,
    max_sub_layers_minus1: u64,
    s: &mut SpsInfo,
) -> Option<()> {
    w.begin("Profile, tier and level");
    s.profile_space = u8::try_from(w.u("general_profile_space", 2)?).ok()?;
    let tier = w.flag("general_tier_flag")?;
    w.summary(|| if tier { "High" } else { "Main" }.to_owned());
    let profile = w.en("general_profile_idc", 5, HEVC_PROFILES)?;
    let compat = w.x("general_profile_compatibility_flags", 32)?;
    if w.emitting() {
        let names: Vec<String> = (0..32u64)
            .filter(|&j| compat_has(compat, j))
            .map(|j| super::tables::lookup_or(HEVC_PROFILES, j))
            .collect();
        w.summary(|| names.join(", "));
    }
    // The 48 constraint bits, read once silently for the codec string.
    let at = w.pos();
    s.constraint_flags = w.read(48)?;
    w.seek(at);
    w.flag("general_progressive_source_flag")?;
    w.flag("general_interlaced_source_flag")?;
    w.flag("general_non_packed_constraint_flag")?;
    w.flag("general_frame_only_constraint_flag")?;
    if rext_family(profile, compat) {
        for name in [
            "general_max_12bit_constraint_flag",
            "general_max_10bit_constraint_flag",
            "general_max_8bit_constraint_flag",
            "general_max_422chroma_constraint_flag",
            "general_max_420chroma_constraint_flag",
            "general_max_monochrome_constraint_flag",
            "general_intra_constraint_flag",
            "general_one_picture_only_constraint_flag",
            "general_lower_bit_rate_constraint_flag",
        ] {
            w.flag(name)?;
        }
        if matches!(profile, 5 | 9 | 10 | 11)
            || [5, 9, 10, 11].iter().any(|&j| compat_has(compat, j))
        {
            w.flag("general_max_14bit_constraint_flag")?;
            w.u("general_reserved_zero_33bits", 33)?;
        } else {
            w.u("general_reserved_zero_34bits", 34)?;
        }
    } else if profile == 2 || compat_has(compat, 2) {
        w.u("general_reserved_zero_7bits", 7)?;
        w.flag("general_one_picture_only_constraint_flag")?;
        w.u("general_reserved_zero_35bits", 35)?;
    } else {
        w.u("general_reserved_zero_43bits", 43)?;
    }
    if matches!(profile, 1..=5 | 9 | 11)
        || [1, 2, 3, 4, 5, 9, 11]
            .iter()
            .any(|&j| compat_has(compat, j))
    {
        w.flag("general_inbld_flag")?;
    } else {
        w.flag("general_reserved_zero_bit")?;
    }
    let level = u8::try_from(w.u("general_level_idc", 8)?).ok()?;
    w.summary(|| format!("level {}", hevc_level_name(level)));
    s.tier_or_constraints = u8::from(tier);
    s.profile = u8::try_from(profile).ok()?;
    s.compatibility = u32::try_from(compat).ok()?;
    s.level = level;
    let n = usize::try_from(max_sub_layers_minus1).ok()?;
    let mut present = Vec::with_capacity(n);
    for i in 0..n {
        let p = w.flag(format!("sub_layer_profile_present_flag[{i}]"))?;
        let l = w.flag(format!("sub_layer_level_present_flag[{i}]"))?;
        present.push((p, l));
    }
    if n > 0 {
        for i in n..8 {
            w.u(format!("reserved_zero_2bits[{i}]"), 2)?;
        }
    }
    for (i, (p, l)) in present.into_iter().enumerate() {
        if p {
            w.skip_as(format!("Sub-layer {i} profile"), 88)?;
        }
        if l {
            let v = u8::try_from(w.u(format!("sub_layer_level_idc[{i}]"), 8)?).ok()?;
            w.summary(|| format!("level {}", hevc_level_name(v)));
        }
    }
    let summary = s.profile_level_hevc();
    w.end_summary(|| summary);
    Some(())
}

impl SpsInfo {
    fn profile_level_hevc(&self) -> String {
        let profile = super::tables::lookup_or(HEVC_PROFILES, self.profile.into());
        format!(
            "{profile}@L{} {} tier",
            hevc_level_name(self.level),
            if self.tier_or_constraints != 0 {
                "High"
            } else {
                "Main"
            }
        )
    }
}

/// `sub_layer_ordering_info`: three ue(v) per sub-layer.
fn ordering_info(w: &mut Walker, prefix: &str, max_sub: u64) -> Option<()> {
    let present = w.flag(format!("{prefix}_sub_layer_ordering_info_present_flag"))?;
    let first = if present { 0 } else { max_sub };
    for i in first..=max_sub {
        w.ue(format!("{prefix}_max_dec_pic_buffering_minus1[{i}]"))?;
        w.ue(format!("{prefix}_max_num_reorder_pics[{i}]"))?;
        w.ue(format!("{prefix}_max_latency_increase_plus1[{i}]"))?;
    }
    Some(())
}

/// `video_parameter_set_rbsp()` (after the NAL header).
pub fn vps(w: &mut Walker) -> Option<SpsInfo> {
    let mut s = SpsInfo {
        hevc: true,
        ..SpsInfo::default()
    };
    s.id = w.u("vps_video_parameter_set_id", 4)?;
    w.flag("vps_base_layer_internal_flag")?;
    w.flag("vps_base_layer_available_flag")?;
    w.u("vps_max_layers_minus1", 6)?;
    let max_sub = w.u("vps_max_sub_layers_minus1", 3)?;
    if max_sub > 6 {
        return None;
    }
    w.flag("vps_temporal_id_nesting_flag")?;
    w.x("vps_reserved_0xffff_16bits", 16)?;
    profile_tier_level(w, max_sub, &mut s)?;
    ordering_info(w, "vps", max_sub)?;
    let max_layer_id = w.u("vps_max_layer_id", 6)?;
    let sets = w.ue("vps_num_layer_sets_minus1")?;
    if sets > 1023 {
        return None;
    }
    if sets > 0 {
        let bits = sets.checked_mul(max_layer_id.checked_add(1)?)?;
        w.skip_as("layer_id_included_flag[][]", usize::try_from(bits).ok()?)?;
    }
    if w.flag("vps_timing_info_present_flag")? {
        let units = w.u("vps_num_units_in_tick", 32)?;
        let scale = w.u("vps_time_scale", 32)?;
        if units > 0 && scale > 0 {
            let (n, d) = reduce(scale, units);
            s.frame_rate = Some((n, d));
            w.summary(|| format!("{} fps", rate(n, d)));
        }
        if w.flag("vps_poc_proportional_to_timing_flag")? {
            w.ue("vps_num_ticks_poc_diff_one_minus1")?;
        }
        let hrds = w.ue("vps_num_hrd_parameters")?;
        if hrds > 1024 {
            return None;
        }
        for i in 0..hrds {
            w.ue(format!("hrd_layer_set_idx[{i}]"))?;
            let common = if i > 0 {
                w.flag(format!("cprms_present_flag[{i}]"))?
            } else {
                true
            };
            w.begin(format!("HRD parameters {i}"));
            hrd(w, common, max_sub, &mut s)?;
            w.end();
        }
    }
    w.flag("vps_extension_flag")?;
    Some(s)
}

/// `scaling_list_data()`, each list as one node.
fn scaling_list_data(w: &mut Walker) -> Option<()> {
    const SIZES: [&str; 4] = ["4×4", "8×8", "16×16", "32×32"];
    w.begin("Scaling list data");
    for size in 0..4usize {
        let step = if size == 3 { 3 } else { 1 };
        let mut matrix = 0usize;
        while matrix < 6 {
            let label = format!(
                "{} matrix {matrix}",
                SIZES.get(size).copied().unwrap_or("?")
            );
            let start = w.pos();
            if !w.read_flag()? {
                let delta = w.read_ue()?;
                w.text(label, start, format!("copy of matrix − {delta}"));
            } else {
                let count = 64usize.min(1usize << (size << 1).saturating_add(4));
                let mut next = 8i64;
                let mut values = Vec::with_capacity(count);
                if size > 1 {
                    let dc = w.read_se()?;
                    next = dc.checked_add(8)?;
                }
                for _ in 0..count {
                    let delta = w.read_se()?;
                    if !(-128..=127).contains(&delta) {
                        return None;
                    }
                    next = next.checked_add(delta)?.checked_add(256)?.rem_euclid(256);
                    values.push(next);
                }
                if w.emitting() {
                    let text = values
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");
                    w.text(label, start, text);
                }
            }
            matrix = matrix.saturating_add(step);
        }
    }
    w.end();
    Some(())
}

/// Delta POCs of one short-term reference picture set.
#[derive(Clone, Default)]
struct Rps {
    s0: Vec<i64>,
    s1: Vec<i64>,
}

/// `st_ref_pic_set(idx)` in an SPS (`num` sets in all).
fn st_ref_pic_set(w: &mut Walker, idx: usize, sets: &[Rps]) -> Option<Rps> {
    w.begin(format!("Short-term reference picture set {idx}"));
    let inter = if idx != 0 {
        w.flag("inter_ref_pic_set_prediction_flag")?
    } else {
        false
    };
    let rps = if inter {
        // In an SPS the reference set is always the previous one.
        let reference = sets.get(idx.checked_sub(1)?)?.clone();
        let sign = w.flag("delta_rps_sign")?;
        let abs = w.ue("abs_delta_rps_minus1")?.checked_add(1)?;
        if abs > 32768 {
            return None;
        }
        let abs = i64::try_from(abs).ok()?;
        let delta_rps = if sign { abs.checked_neg()? } else { abs };
        let n = reference.s0.len().saturating_add(reference.s1.len());
        let mut used = Vec::with_capacity(n.saturating_add(1));
        for j in 0..=n {
            let u = w.flag(format!("used_by_curr_pic_flag[{j}]"))?;
            let d = if u {
                true
            } else {
                w.flag(format!("use_delta_flag[{j}]"))?
            };
            used.push(d);
        }
        let flag = |j: usize| used.get(j).copied().unwrap_or(false);
        // Equations 7-61 and 7-62.
        let mut s0 = Vec::new();
        for (j, &d) in reference.s1.iter().enumerate().rev() {
            let p = d.checked_add(delta_rps)?;
            if p < 0 && flag(reference.s0.len().saturating_add(j)) {
                s0.push(p);
            }
        }
        if delta_rps < 0 && flag(n) {
            s0.push(delta_rps);
        }
        for (j, &d) in reference.s0.iter().enumerate() {
            let p = d.checked_add(delta_rps)?;
            if p < 0 && flag(j) {
                s0.push(p);
            }
        }
        let mut s1 = Vec::new();
        for (j, &d) in reference.s0.iter().enumerate().rev() {
            let p = d.checked_add(delta_rps)?;
            if p > 0 && flag(j) {
                s1.push(p);
            }
        }
        if delta_rps > 0 && flag(n) {
            s1.push(delta_rps);
        }
        for (j, &d) in reference.s1.iter().enumerate() {
            let p = d.checked_add(delta_rps)?;
            if p > 0 && flag(reference.s0.len().saturating_add(j)) {
                s1.push(p);
            }
        }
        Rps { s0, s1 }
    } else {
        let neg = w.ue("num_negative_pics")?;
        let pos = w.ue("num_positive_pics")?;
        if neg > 16 || pos > 16 {
            return None;
        }
        let mut rps = Rps::default();
        let mut poc = 0i64;
        for i in 0..neg {
            let d = w.ue(format!("delta_poc_s0_minus1[{i}]"))?;
            w.flag(format!("used_by_curr_pic_s0_flag[{i}]"))?;
            poc = poc.checked_sub(i64::try_from(d).ok()?.checked_add(1)?)?;
            rps.s0.push(poc);
        }
        poc = 0;
        for i in 0..pos {
            let d = w.ue(format!("delta_poc_s1_minus1[{i}]"))?;
            w.flag(format!("used_by_curr_pic_s1_flag[{i}]"))?;
            poc = poc.checked_add(i64::try_from(d).ok()?.checked_add(1)?)?;
            rps.s1.push(poc);
        }
        rps
    };
    if rps.s0.len() > 16 || rps.s1.len() > 16 {
        return None;
    }
    let text = format!("negative {:?}, positive {:?}", rps.s0, rps.s1);
    w.end_summary(|| text);
    Some(rps)
}

/// `hrd_parameters(common, max_sub_layers_minus1)`.
fn hrd(w: &mut Walker, common: bool, max_sub: u64, s: &mut SpsInfo) -> Option<()> {
    let (mut nal, mut vcl, mut sub_pic) = (false, false, false);
    if common {
        nal = w.flag("nal_hrd_parameters_present_flag")?;
        vcl = w.flag("vcl_hrd_parameters_present_flag")?;
        if nal || vcl {
            sub_pic = w.flag("sub_pic_hrd_params_present_flag")?;
            if sub_pic {
                w.u("tick_divisor_minus2", 8)?;
                w.u("du_cpb_removal_delay_increment_length_minus1", 5)?;
                w.flag("sub_pic_cpb_params_in_pic_timing_sei_flag")?;
                w.u("dpb_output_delay_du_length_minus1", 5)?;
            }
            w.u("bit_rate_scale", 4)?;
            w.u("cpb_size_scale", 4)?;
            if sub_pic {
                w.u("cpb_size_du_scale", 4)?;
            }
            let initial = w.u("initial_cpb_removal_delay_length_minus1", 5)?;
            let removal = w.u("au_cpb_removal_delay_length_minus1", 5)?;
            let output = w.u("dpb_output_delay_length_minus1", 5)?;
            s.slice.initial_cpb_removal_delay_length =
                u32::try_from(initial).ok()?.saturating_add(1);
            s.slice.cpb_removal_delay_length = u32::try_from(removal).ok()?.saturating_add(1);
            s.slice.dpb_output_delay_length = u32::try_from(output).ok()?.saturating_add(1);
        }
    }
    for i in 0..=max_sub {
        let general = w.flag(format!("fixed_pic_rate_general_flag[{i}]"))?;
        let within = if general {
            true
        } else {
            w.flag(format!("fixed_pic_rate_within_cvs_flag[{i}]"))?
        };
        let mut low_delay = false;
        if within {
            w.ue(format!("elemental_duration_in_tc_minus1[{i}]"))?;
        } else {
            low_delay = w.flag(format!("low_delay_hrd_flag[{i}]"))?;
        }
        let mut cpb = 1u64;
        if !low_delay {
            cpb = w.ue(format!("cpb_cnt_minus1[{i}]"))?.checked_add(1)?;
            if cpb > 32 {
                return None;
            }
        }
        for (present, kind) in [(nal, "NAL"), (vcl, "VCL")] {
            if !present {
                continue;
            }
            w.begin(format!("Sub-layer {i} {kind} HRD"));
            for k in 0..cpb {
                w.ue(format!("bit_rate_value_minus1[{k}]"))?;
                w.ue(format!("cpb_size_value_minus1[{k}]"))?;
                if sub_pic {
                    w.ue(format!("cpb_size_du_value_minus1[{k}]"))?;
                    w.ue(format!("bit_rate_du_value_minus1[{k}]"))?;
                }
                w.flag(format!("cbr_flag[{k}]"))?;
            }
            w.end();
            if i == 0 {
                if kind == "NAL" {
                    s.slice.nal_cpb_cnt = cpb;
                } else {
                    s.slice.vcl_cpb_cnt = cpb;
                }
            }
        }
    }
    Some(())
}

/// `seq_parameter_set_rbsp()` (after the NAL header).
pub fn sps(w: &mut Walker) -> Option<SpsInfo> {
    let mut s = SpsInfo {
        hevc: true,
        ..SpsInfo::default()
    };
    w.u("sps_video_parameter_set_id", 4)?;
    let max_sub = w.u("sps_max_sub_layers_minus1", 3)?;
    if max_sub > 6 {
        return None;
    }
    w.flag("sps_temporal_id_nesting_flag")?;
    profile_tier_level(w, max_sub, &mut s)?;
    s.id = w.ue("sps_seq_parameter_set_id")?;
    if s.id > 15 {
        return None;
    }
    s.chroma_format = w.ue_en("chroma_format_idc", CHROMA_FORMATS)?;
    if s.chroma_format > 3 {
        return None;
    }
    if s.chroma_format == 3 {
        s.slice.separate_colour_plane = w.flag("separate_colour_plane_flag")?;
    }
    s.slice.chroma_array_type = if s.slice.separate_colour_plane {
        0
    } else {
        s.chroma_format
    };
    s.coded_width = w.ue("pic_width_in_luma_samples")?;
    s.coded_height = w.ue("pic_height_in_luma_samples")?;
    s.width = s.coded_width;
    s.height = s.coded_height;
    if w.flag("conformance_window_flag")? {
        let (sub_w, sub_h) = match s.slice.chroma_array_type {
            1 => (2u64, 2u64),
            2 => (2, 1),
            _ => (1, 1),
        };
        w.begin("Conformance window");
        let l = w.ue("conf_win_left_offset")?;
        let r = w.ue("conf_win_right_offset")?;
        let t = w.ue("conf_win_top_offset")?;
        let b = w.ue("conf_win_bottom_offset")?;
        s.width = s
            .coded_width
            .saturating_sub(l.saturating_add(r).saturating_mul(sub_w));
        s.height = s
            .coded_height
            .saturating_sub(t.saturating_add(b).saturating_mul(sub_h));
        let (cw, ch, dw, dh) = (s.coded_width, s.coded_height, s.width, s.height);
        w.end_summary(|| format!("{cw}×{ch} cropped to {dw}×{dh}"));
    }
    let luma = w.ue("bit_depth_luma_minus8")?;
    w.summary(|| format!("{}-bit", luma.saturating_add(8)));
    let chroma = w.ue("bit_depth_chroma_minus8")?;
    w.summary(|| format!("{}-bit", chroma.saturating_add(8)));
    if luma > 8 || chroma > 8 {
        return None;
    }
    s.bit_depth = luma.saturating_add(8);
    s.bit_depth_chroma = chroma.saturating_add(8);
    let lsb = w.ue("log2_max_pic_order_cnt_lsb_minus4")?;
    if lsb > 12 {
        return None;
    }
    s.slice.log2_max_poc_lsb = u32::try_from(lsb).ok()?.saturating_add(4);
    ordering_info(w, "sps", max_sub)?;
    let min_cb = w.ue("log2_min_luma_coding_block_size_minus3")?;
    let diff_cb = w.ue("log2_diff_max_min_luma_coding_block_size")?;
    let ctb = min_cb.checked_add(3)?.checked_add(diff_cb)?;
    if ctb > 7 {
        return None;
    }
    w.summary(|| format!("CTB {0}×{0}", 1u64 << ctb));
    let ctb_size = 1u64 << ctb;
    let ctbs_w = s.coded_width.div_ceil(ctb_size);
    let ctbs_h = s.coded_height.div_ceil(ctb_size);
    s.slice.pic_size_in_ctbs = ctbs_w.saturating_mul(ctbs_h);
    w.ue("log2_min_luma_transform_block_size_minus2")?;
    w.ue("log2_diff_max_min_luma_transform_block_size")?;
    w.ue("max_transform_hierarchy_depth_inter")?;
    w.ue("max_transform_hierarchy_depth_intra")?;
    if w.flag("scaling_list_enabled_flag")? && w.flag("sps_scaling_list_data_present_flag")? {
        scaling_list_data(w)?;
    }
    w.flag("amp_enabled_flag")?;
    w.flag("sample_adaptive_offset_enabled_flag")?;
    if w.flag("pcm_enabled_flag")? {
        w.begin("PCM");
        w.u("pcm_sample_bit_depth_luma_minus1", 4)?;
        w.u("pcm_sample_bit_depth_chroma_minus1", 4)?;
        w.ue("log2_min_pcm_luma_coding_block_size_minus3")?;
        w.ue("log2_diff_max_min_pcm_luma_coding_block_size")?;
        w.flag("pcm_loop_filter_disabled_flag")?;
        w.end();
    }
    let sets = w.ue("num_short_term_ref_pic_sets")?;
    if sets > 64 {
        return None;
    }
    let mut rps: Vec<Rps> = Vec::new();
    for i in 0..usize::try_from(sets).ok()? {
        let r = st_ref_pic_set(w, i, &rps)?;
        rps.push(r);
    }
    if w.flag("long_term_ref_pics_present_flag")? {
        let n = w.ue("num_long_term_ref_pics_sps")?;
        if n > 32 {
            return None;
        }
        for i in 0..n {
            w.u(
                format!("lt_ref_pic_poc_lsb_sps[{i}]"),
                s.slice.log2_max_poc_lsb,
            )?;
            w.flag(format!("used_by_curr_pic_lt_sps_flag[{i}]"))?;
        }
    }
    w.flag("sps_temporal_mvp_enabled_flag")?;
    w.flag("strong_intra_smoothing_enabled_flag")?;
    if w.flag("vui_parameters_present_flag")? {
        let depth = w.depth();
        if vui(w, max_sub, &mut s).is_none() {
            w.fail_to(depth);
            return Some(s);
        }
    }
    if w.flag("sps_extension_present_flag")? {
        let range = w.flag("sps_range_extension_flag")?;
        w.flag("sps_multilayer_extension_flag")?;
        w.flag("sps_3d_extension_flag")?;
        w.flag("sps_scc_extension_flag")?;
        w.u("sps_extension_4bits", 4)?;
        if range {
            w.begin("Range extension");
            for name in [
                "transform_skip_rotation_enabled_flag",
                "transform_skip_context_enabled_flag",
                "implicit_rdpcm_enabled_flag",
                "explicit_rdpcm_enabled_flag",
                "extended_precision_processing_flag",
                "intra_smoothing_disabled_flag",
                "high_precision_offsets_enabled_flag",
                "persistent_rice_adaptation_enabled_flag",
                "cabac_bypass_alignment_enabled_flag",
            ] {
                w.flag(name)?;
            }
            w.end();
        }
    }
    Some(s)
}

/// `vui_parameters()` of an HEVC SPS.
fn vui(w: &mut Walker, max_sub: u64, s: &mut SpsInfo) -> Option<()> {
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
    w.flag("neutral_chroma_indication_flag")?;
    s.interlaced = w.flag("field_seq_flag")?;
    s.slice.frame_field_info_present = w.flag("frame_field_info_present_flag")?;
    if w.flag("default_display_window_flag")? {
        w.begin("Default display window");
        w.ue("def_disp_win_left_offset")?;
        w.ue("def_disp_win_right_offset")?;
        w.ue("def_disp_win_top_offset")?;
        w.ue("def_disp_win_bottom_offset")?;
        w.end();
    }
    if w.flag("vui_timing_info_present_flag")? {
        let units = w.u("vui_num_units_in_tick", 32)?;
        let scale = w.u("vui_time_scale", 32)?;
        if units > 0 && scale > 0 {
            let (n, d) = reduce(scale, units);
            s.frame_rate = Some((n, d));
            w.summary(|| format!("{} fps", rate(n, d)));
        }
        if w.flag("vui_poc_proportional_to_timing_flag")? {
            w.ue("vui_num_ticks_poc_diff_one_minus1")?;
        }
        if w.flag("vui_hrd_parameters_present_flag")? {
            w.begin("HRD parameters");
            hrd(w, true, max_sub, s)?;
            w.end();
        }
    }
    if w.flag("bitstream_restriction_flag")? {
        w.flag("tiles_fixed_structure_flag")?;
        w.flag("motion_vectors_over_pic_boundaries_flag")?;
        w.flag("restricted_ref_pic_lists_flag")?;
        w.ue("min_spatial_segmentation_idc")?;
        w.ue("max_bytes_per_pic_denom")?;
        w.ue("max_bits_per_min_cu_denom")?;
        w.ue("log2_max_mv_length_horizontal")?;
        w.ue("log2_max_mv_length_vertical")?;
    }
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
    let summary = parts.join(", ");
    w.end_summary(|| summary);
    Some(())
}

/// `pic_parameter_set_rbsp()` (after the NAL header).
pub fn pps(w: &mut Walker) -> Option<PpsInfo> {
    let mut p = PpsInfo {
        id: w.ue("pps_pic_parameter_set_id")?,
        sps_id: w.ue("pps_seq_parameter_set_id")?,
        ..PpsInfo::default()
    };
    if p.id > 63 || p.sps_id > 15 {
        return None;
    }
    p.dependent_slice_segments = w.flag("dependent_slice_segments_enabled_flag")?;
    p.output_flag_present = w.flag("output_flag_present_flag")?;
    p.num_extra_slice_header_bits = w.u("num_extra_slice_header_bits", 3)?;
    w.flag("sign_data_hiding_enabled_flag")?;
    w.flag("cabac_init_present_flag")?;
    let l0 = w
        .ue("num_ref_idx_l0_default_active_minus1")?
        .checked_add(1)?;
    let l1 = w
        .ue("num_ref_idx_l1_default_active_minus1")?
        .checked_add(1)?;
    p.num_ref_idx_default = [l0, l1];
    let qp = w.se("init_qp_minus26")?;
    p.pic_init_qp = qp.checked_add(26)?;
    let init = p.pic_init_qp;
    w.summary(|| format!("QP {init}"));
    w.flag("constrained_intra_pred_flag")?;
    w.flag("transform_skip_enabled_flag")?;
    if w.flag("cu_qp_delta_enabled_flag")? {
        w.ue("diff_cu_qp_delta_depth")?;
    }
    w.se("pps_cb_qp_offset")?;
    w.se("pps_cr_qp_offset")?;
    w.flag("pps_slice_chroma_qp_offsets_present_flag")?;
    p.weighted_pred = w.flag("weighted_pred_flag")?;
    p.weighted_bipred_idc = u64::from(w.flag("weighted_bipred_flag")?);
    w.flag("transquant_bypass_enabled_flag")?;
    let tiles = w.flag("tiles_enabled_flag")?;
    w.flag("entropy_coding_sync_enabled_flag")?;
    if tiles {
        w.begin("Tiles");
        let cols = w.ue("num_tile_columns_minus1")?;
        let rows = w.ue("num_tile_rows_minus1")?;
        if cols > 64 || rows > 64 {
            return None;
        }
        if !w.flag("uniform_spacing_flag")? {
            for i in 0..cols {
                w.ue(format!("column_width_minus1[{i}]"))?;
            }
            for i in 0..rows {
                w.ue(format!("row_height_minus1[{i}]"))?;
            }
        }
        w.flag("loop_filter_across_tiles_enabled_flag")?;
        w.end_summary(|| {
            format!(
                "{}×{} tiles",
                cols.saturating_add(1),
                rows.saturating_add(1)
            )
        });
    }
    w.flag("pps_loop_filter_across_slices_enabled_flag")?;
    if w.flag("deblocking_filter_control_present_flag")? {
        p.deblocking_filter_control = true;
        w.flag("deblocking_filter_override_enabled_flag")?;
        if !w.flag("pps_deblocking_filter_disabled_flag")? {
            w.se("pps_beta_offset_div2")?;
            w.se("pps_tc_offset_div2")?;
        }
    }
    if w.flag("pps_scaling_list_data_present_flag")? {
        scaling_list_data(w)?;
    }
    w.flag("lists_modification_present_flag")?;
    w.ue("log2_parallel_merge_level_minus2")?;
    w.flag("slice_segment_header_extension_present_flag")?;
    if w.flag("pps_extension_present_flag")? {
        w.flag("pps_range_extension_flag")?;
        w.flag("pps_multilayer_extension_flag")?;
        w.flag("pps_3d_extension_flag")?;
        w.flag("pps_scc_extension_flag")?;
        w.u("pps_extension_4bits", 4)?;
    }
    Some(p)
}

/// `access_unit_delimiter_rbsp()`.
pub fn aud(w: &mut Walker) -> Option<u64> {
    w.en("pic_type", 3, PIC_TYPES)
}

/// The start of `slice_segment_header()`, up to the POC LSBs.
pub fn slice_header(
    w: &mut Walker,
    nal_type: u64,
    ps: &ParamSets,
    info: &mut SliceInfo,
) -> Option<()> {
    info.hevc = true;
    let first = w.flag("first_slice_segment_in_pic_flag")?;
    if (16..=23).contains(&nal_type) {
        w.flag("no_output_of_prior_pics_flag")?;
    }
    info.pps_id = w.ue("slice_pic_parameter_set_id")?;
    let Some((pps, sps)) = ps.for_pps(info.pps_id) else {
        w.push(
            crate::node::Node::new("Remaining fields").desc(
                "Not decoded: the picture parameter set this slice refers to has not been seen",
            ),
        );
        return Some(());
    };
    let (pps, sps) = (*pps, sps.slice);
    let mut dependent = false;
    if !first {
        if pps.dependent_slice_segments {
            dependent = w.flag("dependent_slice_segment_flag")?;
        }
        let address = w.u("slice_segment_address", ceil_log2(sps.pic_size_in_ctbs))?;
        info.first_mb = address;
    }
    if dependent {
        info.slice_type = 3;
        info.parsed = true;
        return Some(());
    }
    for i in 0..pps.num_extra_slice_header_bits {
        w.flag(format!("slice_reserved_flag[{i}]"))?;
    }
    info.slice_type = w.ue_en("slice_type", SLICE_TYPES)?;
    if info.slice_type > 2 {
        return None;
    }
    info.parsed = true;
    if pps.output_flag_present {
        w.flag("pic_output_flag")?;
    }
    if sps.separate_colour_plane {
        w.u("colour_plane_id", 2)?;
    }
    if nal_type != 19 && nal_type != 20 {
        info.poc_lsb = Some(w.u("slice_pic_order_cnt_lsb", sps.log2_max_poc_lsb)?);
    }
    if w.emitting() {
        let rest = w.rest_span(w.pos());
        w.push(
            crate::node::Node::new("Rest of the slice segment")
                .span(rest)
                .summary(format!("{} bytes", rest.len))
                .desc("Reference picture sets, prediction weights and the rest of the header are not decoded, nor is the slice data"),
        );
    }
    Some(())
}
