//! Supplemental enhancement information (H.264 Annex D, H.265 Annex D):
//! the message framing and the payloads people look for (encoder version
//! strings, recovery points, HDR mastering display and light levels,
//! picture timing, closed captions).

use super::bitwalk::Walker;
use super::params::SpsInfo;
use super::tables::{TRANSFER_CHARACTERISTICS, lookup_or};
use crate::value::EnumTable;

pub const H264_SEI_TYPES: EnumTable = &[
    (0, "buffering period"),
    (1, "picture timing"),
    (2, "pan-scan rectangle"),
    (3, "filler payload"),
    (4, "user data registered (ITU-T T.35)"),
    (5, "user data unregistered"),
    (6, "recovery point"),
    (7, "decoded reference picture marking repetition"),
    (8, "spare picture"),
    (9, "scene info"),
    (10, "sub-sequence info"),
    (11, "sub-sequence layer characteristics"),
    (12, "sub-sequence characteristics"),
    (13, "full-frame freeze"),
    (14, "full-frame freeze release"),
    (15, "full-frame snapshot"),
    (16, "progressive refinement segment start"),
    (17, "progressive refinement segment end"),
    (18, "motion-constrained slice group set"),
    (19, "film grain characteristics"),
    (20, "deblocking filter display preference"),
    (21, "stereo video info"),
    (22, "post-filter hint"),
    (23, "tone mapping info"),
    (24, "scalability info"),
    (25, "sub-picture scalable layer"),
    (26, "non-required layer representation"),
    (27, "priority layer info"),
    (28, "layers not present"),
    (29, "layer dependency change"),
    (30, "scalable nesting"),
    (31, "base layer temporal HRD"),
    (32, "quality layer integrity check"),
    (33, "redundant picture property"),
    (34, "temporal level zero dependency representation index"),
    (35, "temporal level switching point"),
    (36, "parallel decoding info"),
    (37, "MVC scalable nesting"),
    (38, "view scalability info"),
    (39, "multiview scene info"),
    (40, "multiview acquisition info"),
    (41, "non-required view component"),
    (42, "view dependency change"),
    (43, "operation points not present"),
    (44, "base view temporal HRD"),
    (45, "frame packing arrangement"),
    (46, "multiview view position"),
    (47, "display orientation"),
    (56, "green metadata"),
    (137, "mastering display colour volume"),
    (142, "colour remapping info"),
    (144, "content light level info"),
    (147, "alternative transfer characteristics"),
    (148, "ambient viewing environment"),
    (149, "content colour volume"),
    (181, "alternative depth info"),
];

pub const HEVC_SEI_TYPES: EnumTable = &[
    (0, "buffering period"),
    (1, "picture timing"),
    (2, "pan-scan rectangle"),
    (3, "filler payload"),
    (4, "user data registered (ITU-T T.35)"),
    (5, "user data unregistered"),
    (6, "recovery point"),
    (9, "scene info"),
    (15, "picture snapshot"),
    (16, "progressive refinement segment start"),
    (17, "progressive refinement segment end"),
    (19, "film grain characteristics"),
    (22, "post-filter hint"),
    (23, "tone mapping info"),
    (45, "frame packing arrangement"),
    (47, "display orientation"),
    (56, "green metadata"),
    (128, "structure of pictures info"),
    (129, "active parameter sets"),
    (130, "decoding unit info"),
    (131, "temporal sub-layer zero index"),
    (132, "decoded picture hash"),
    (133, "scalable nesting"),
    (134, "region refresh info"),
    (135, "no display"),
    (136, "time code"),
    (137, "mastering display colour volume"),
    (138, "segmented rectangular frame packing arrangement"),
    (139, "temporal motion-constrained tile sets"),
    (140, "chroma resampling filter hint"),
    (141, "knee function info"),
    (142, "colour remapping info"),
    (143, "deinterlaced field identification"),
    (144, "content light level info"),
    (145, "dependent RAP indication"),
    (146, "coded region completion"),
    (147, "alternative transfer characteristics"),
    (148, "ambient viewing environment"),
    (149, "content colour volume"),
    (150, "equirectangular projection"),
    (151, "cubemap projection"),
    (154, "sphere rotation"),
    (155, "region-wise packing"),
    (156, "omnidirectional viewport"),
    (168, "frame-field info"),
];

const PIC_STRUCT: EnumTable = &[
    (0, "frame"),
    (1, "top field"),
    (2, "bottom field"),
    (3, "top, bottom"),
    (4, "bottom, top"),
    (5, "top, bottom, top repeated"),
    (6, "bottom, top, bottom repeated"),
    (7, "frame doubling"),
    (8, "frame tripling"),
    (9, "top field, paired with previous bottom"),
    (10, "bottom field, paired with previous top"),
    (11, "top field, paired with next bottom"),
    (12, "bottom field, paired with next top"),
];

const FRAME_PACKING: EnumTable = &[
    (0, "checkerboard"),
    (1, "column interleaving"),
    (2, "row interleaving"),
    (3, "side by side"),
    (4, "top and bottom"),
    (5, "frame alternation"),
    (6, "2D"),
    (7, "tile format"),
];

const HASH_TYPES: EnumTable = &[(0, "MD5"), (1, "CRC"), (2, "checksum")];

const T35_COUNTRIES: EnumTable = &[
    (0x26, "China"),
    (0x3d, "France"),
    (0x42, "Germany"),
    (0x61, "South Korea"),
    (0xb4, "United Kingdom"),
    (0xb5, "United States"),
];

const T35_PROVIDERS_US: EnumTable = &[
    (0x0031, "ATSC"),
    (0x002f, "Direct TV"),
    (0x003b, "Dolby Laboratories"),
    (0x003c, "Samsung"),
];

/// Reads `ff`-extended SEI numbers (payload type and size).
fn sei_number(w: &mut Walker) -> Option<u64> {
    let mut v = 0u64;
    loop {
        let b = w.read(8)?;
        v = v.checked_add(b)?;
        if b != 0xff {
            return Some(v);
        }
    }
}

/// `sei_rbsp()`: every message as a group. Returns a one-line summary per
/// message.
pub fn sei_rbsp(w: &mut Walker, hevc: bool, sps: Option<&SpsInfo>) -> Option<Vec<String>> {
    let table = if hevc { HEVC_SEI_TYPES } else { H264_SEI_TYPES };
    let mut out = Vec::new();
    for _ in 0..256 {
        if !w.byte_aligned() || !w.more_rbsp_data() {
            break;
        }
        let start = w.pos();
        let kind = sei_number(w)?;
        let size_at = w.pos();
        let size = sei_number(w)?;
        let body = w.pos();
        let size_bits = usize::try_from(size).ok()?.checked_mul(8)?;
        if size_bits > w.bits_left() {
            return None;
        }
        let name = lookup_or(table, kind);
        let name = if name == kind.to_string() {
            format!("SEI type {kind}")
        } else {
            name
        };
        let mut sub = w.sub(body >> 3, usize::try_from(size).ok()?);
        let detail = payload(&mut sub, hevc, kind, size, sps);
        let complete = detail.is_some();
        let detail = detail.flatten();
        let nodes = sub.finish(complete);
        w.seek(body.saturating_add(size_bits));
        if w.emitting() {
            let span = w.since(start);
            let mut children = Vec::with_capacity(nodes.len().saturating_add(2));
            children.push(
                crate::node::Node::new("payloadType")
                    .span(w.span_bits(start, size_at))
                    .value(crate::value::Value::Enum {
                        raw: kind,
                        bits: 32,
                        name: crate::value::lookup(table, kind),
                    }),
            );
            children.push(
                crate::node::Node::new("payloadSize")
                    .span(w.span_bits(size_at, body))
                    .value(crate::value::Value::UInt {
                        value: size,
                        bits: 32,
                        radix: crate::value::Radix::Dec,
                    }),
            );
            children.extend(nodes);
            let mut node = crate::node::Node::new(name.clone()).span(span).lazy(
                crate::formats::util::arcutil::emit_nodes,
                std::sync::Arc::new(children),
            );
            node = node.summary(match &detail {
                Some(d) => format!("{d}, {size} bytes"),
                None => format!("{size} bytes"),
            });
            w.push(node);
        }
        out.push(match detail {
            Some(d) => format!("{name}: {d}"),
            None => name,
        });
    }
    Some(out)
}

/// Decodes one payload; `Some(None)` when it was read but has nothing to
/// summarise, `None` when it ended early.
fn payload(
    w: &mut Walker,
    hevc: bool,
    kind: u64,
    size: u64,
    sps: Option<&SpsInfo>,
) -> Option<Option<String>> {
    Some(match kind {
        0 if !hevc => buffering_period(w, sps)?,
        1 => {
            if hevc {
                pic_timing_hevc(w, sps)?
            } else {
                pic_timing(w, sps)?
            }
        }
        4 => t35(w, size)?,
        5 => user_data_unregistered(w, size)?,
        6 => {
            let s = if hevc {
                let cnt = w.se("recovery_poc_cnt")?;
                format!("POC {cnt}")
            } else {
                let cnt = w.ue("recovery_frame_cnt")?;
                format!("{cnt} frames")
            };
            let exact = w.flag("exact_match_flag")?;
            let broken = w.flag("broken_link_flag")?;
            if !hevc {
                w.u("changing_slice_group_idc", 2)?;
            }
            let mut s = s;
            if exact {
                s.push_str(", exact match");
            }
            if broken {
                s.push_str(", broken link");
            }
            Some(s)
        }
        45 => {
            w.ue("frame_packing_arrangement_id")?;
            if w.flag("frame_packing_arrangement_cancel_flag")? {
                Some("cancel".to_owned())
            } else {
                let t = w.en("frame_packing_arrangement_type", 7, FRAME_PACKING)?;
                Some(lookup_or(FRAME_PACKING, t))
            }
        }
        47 => {
            if w.flag("display_orientation_cancel_flag")? {
                Some("cancel".to_owned())
            } else {
                let h = w.flag("hor_flip")?;
                let v = w.flag("ver_flip")?;
                let rot = w.u("anticlockwise_rotation", 16)?;
                let degrees = rot as f64 * 360.0 / 65536.0;
                w.summary(|| format!("{degrees:.1}°"));
                let mut s = format!("rotate {degrees:.1}°");
                if h {
                    s.push_str(", horizontal flip");
                }
                if v {
                    s.push_str(", vertical flip");
                }
                Some(s)
            }
        }
        129 if hevc => {
            w.u("active_video_parameter_set_id", 4)?;
            w.flag("self_contained_cvs_flag")?;
            w.flag("no_parameter_set_update_flag")?;
            let n = w.ue("num_sps_ids_minus1")?;
            if n > 15 {
                return None;
            }
            for i in 0..=n {
                w.ue(format!("active_seq_parameter_set_id[{i}]"))?;
            }
            None
        }
        132 if hevc => {
            let t = w.en("hash_type", 8, HASH_TYPES)?;
            let planes = if sps.is_some_and(|s| s.chroma_format == 0) {
                1
            } else {
                3
            };
            let mut hashes = Vec::new();
            for c in 0..planes {
                match t {
                    0 => {
                        let b = w.bytes(format!("picture_md5[{c}]"), 16)?;
                        hashes.push(b.iter().map(|x| format!("{x:02x}")).collect::<String>());
                    }
                    1 => hashes.push(format!("{:04x}", w.x(format!("picture_crc[{c}]"), 16)?)),
                    2 => hashes.push(format!(
                        "{:08x}",
                        w.x(format!("picture_checksum[{c}]"), 32)?
                    )),
                    _ => return Some(None),
                }
            }
            Some(format!("{} {}", lookup_or(HASH_TYPES, t), hashes.join(" ")))
        }
        136 if hevc => time_code(w)?,
        137 => {
            let mut prim = Vec::new();
            for c in 0..3 {
                let x = w.u(format!("display_primaries_x[{c}]"), 16)?;
                w.summary(|| format!("{:.5}", x as f64 / 50000.0));
                let y = w.u(format!("display_primaries_y[{c}]"), 16)?;
                w.summary(|| format!("{:.5}", y as f64 / 50000.0));
                prim.push((x, y));
            }
            let x = w.u("white_point_x", 16)?;
            w.summary(|| format!("{:.5}", x as f64 / 50000.0));
            let y = w.u("white_point_y", 16)?;
            w.summary(|| format!("{:.5}", y as f64 / 50000.0));
            let max = w.u("max_display_mastering_luminance", 32)?;
            w.summary(|| format!("{} cd/m²", nits(max as f64 / 10000.0)));
            let min = w.u("min_display_mastering_luminance", 32)?;
            w.summary(|| format!("{} cd/m²", nits(min as f64 / 10000.0)));
            Some(format!(
                "{}–{} cd/m², white point ({:.4}, {:.4})",
                nits(min as f64 / 10000.0),
                nits(max as f64 / 10000.0),
                x as f64 / 50000.0,
                y as f64 / 50000.0
            ))
        }
        144 => {
            let cll = w.u("max_content_light_level", 16)?;
            w.summary(|| format!("{cll} cd/m²"));
            let fall = w.u("max_pic_average_light_level", 16)?;
            w.summary(|| format!("{fall} cd/m²"));
            Some(format!("MaxCLL {cll}, MaxFALL {fall} cd/m²"))
        }
        147 => {
            let t = w.en(
                "preferred_transfer_characteristics",
                8,
                TRANSFER_CHARACTERISTICS,
            )?;
            Some(lookup_or(TRANSFER_CHARACTERISTICS, t))
        }
        148 => {
            let lux = w.u("ambient_illuminance", 32)?;
            w.summary(|| format!("{} lux", nits(lux as f64 / 10000.0)));
            w.u("ambient_light_x", 16)?;
            w.u("ambient_light_y", 16)?;
            Some(format!("{} lux", nits(lux as f64 / 10000.0)))
        }
        _ => {
            if size > 0 {
                w.skip_as("Payload data", usize::try_from(size).ok()?.checked_mul(8)?)?;
            }
            None
        }
    })
}

/// A luminance with up to four decimals ("1000", "0.005").
pub fn nits(v: f64) -> String {
    let s = format!("{v:.4}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    s.to_owned()
}

fn user_data_unregistered(w: &mut Walker, size: u64) -> Option<Option<String>> {
    let start = w.pos();
    let uuid = w.read_bytes(16)?;
    let text = super::uuid(&uuid);
    w.text("uuid_iso_iec_11578", start, text);
    let n = usize::try_from(size).ok()?.checked_sub(16)?;
    let start = w.pos();
    let data = w.read_bytes(n)?;
    let body = crate::text::until_nul(&data);
    let printable = !body.is_empty()
        && body
            .chars()
            .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t');
    if printable {
        let short = encoder_version(&body);
        w.text("user_data_payload_byte", start, body.clone());
        if let Some(s) = &short {
            let s = s.clone();
            w.summary(|| s);
        }
        Some(Some(
            short.unwrap_or_else(|| body.chars().take(48).collect()),
        ))
    } else {
        w.record(
            "user_data_payload_byte",
            start,
            crate::value::Value::Bytes(data),
        );
        Some(None)
    }
}

/// "x264 core 164 r3108" from x264's settings string, "x265 3.5+1" from
/// x265's.
pub fn encoder_version(s: &str) -> Option<String> {
    if let Some(rest) = s.strip_prefix("x264 - core ") {
        let mut it = rest.split_whitespace();
        let core = it.next()?;
        let rev = it.next().filter(|r| r.starts_with('r'));
        return Some(match rev {
            Some(r) => format!("x264 core {core} {r}"),
            None => format!("x264 core {core}"),
        });
    }
    if s.starts_with("x265 (build ") {
        let version = s.split(" - ").nth(1)?;
        let version = version.split(':').next()?.trim();
        return Some(format!("x265 {version}"));
    }
    None
}

fn t35(w: &mut Walker, size: u64) -> Option<Option<String>> {
    let country = w.en("itu_t_t35_country_code", 8, T35_COUNTRIES)?;
    let mut used = 1u64;
    if country == 0xff {
        w.u("itu_t_t35_country_code_extension_byte", 8)?;
        used = 2;
    }
    if country != 0xb5 || size < used.saturating_add(2) {
        let rest = usize::try_from(size.saturating_sub(used)).ok()?;
        if rest > 0 {
            w.skip_as("itu_t_t35_payload_byte", rest.checked_mul(8)?)?;
        }
        return Some(Some(format!(
            "country {}",
            lookup_or(T35_COUNTRIES, country)
        )));
    }
    let provider = w.en("itu_t_t35_provider_code", 16, T35_PROVIDERS_US)?;
    used = used.saturating_add(2);
    let mut detail = lookup_or(T35_PROVIDERS_US, provider);
    if provider == 0x0031 && size >= used.saturating_add(4) {
        let start = w.pos();
        let id = w.read_bytes(4)?;
        let id_text = String::from_utf8_lossy(&id).into_owned();
        w.text("user_identifier", start, id_text.clone());
        used = used.saturating_add(4);
        if id == b"GA94" && size > used {
            let code = w.u("user_data_type_code", 8)?;
            used = used.saturating_add(1);
            if code == 3 && size >= used.saturating_add(2) {
                w.begin("cc_data");
                w.flag("process_em_data_flag")?;
                w.flag("process_cc_data_flag")?;
                w.flag("additional_data_flag")?;
                let count = w.u("cc_count", 5)?;
                w.u("em_data", 8)?;
                for i in 0..count {
                    w.begin(format!("Caption {i}"));
                    w.u("marker_bits", 5)?;
                    let valid = w.flag("cc_valid")?;
                    let t = w.en(
                        "cc_type",
                        2,
                        &[
                            (0, "NTSC line 21 field 1"),
                            (1, "NTSC line 21 field 2"),
                            (2, "DTVCC packet data"),
                            (3, "DTVCC packet start"),
                        ],
                    )?;
                    w.x("cc_data_1", 8)?;
                    w.x("cc_data_2", 8)?;
                    w.end_summary(|| format!("type {t}{}", if valid { "" } else { ", not valid" }));
                }
                w.end();
                detail = format!("ATSC A/53 closed captions, {count} entries");
                return Some(Some(detail));
            }
            detail = format!("ATSC {id_text} type {code}");
        } else {
            detail = format!("ATSC {id_text}");
        }
    } else if provider == 0x003c && size >= used.saturating_add(3) {
        let oriented = w.x("itu_t_t35_terminal_provider_oriented_code", 16)?;
        let app = w.u("application_identifier", 8)?;
        used = used.saturating_add(3);
        if oriented == 1 && app == 4 {
            detail = "HDR10+ dynamic metadata".to_owned();
        }
    }
    let rest = usize::try_from(size.saturating_sub(used)).ok()?;
    if rest > 0 && w.bits_left() >= rest.saturating_mul(8) {
        w.skip_as("itu_t_t35_payload_byte", rest.saturating_mul(8))?;
    }
    Some(Some(detail))
}

fn buffering_period(w: &mut Walker, sps: Option<&SpsInfo>) -> Option<Option<String>> {
    w.ue("seq_parameter_set_id")?;
    let Some(sps) = sps else {
        return Some(None);
    };
    let len = sps.slice.initial_cpb_removal_delay_length;
    for (cnt, kind) in [
        (sps.slice.nal_cpb_cnt, "NAL"),
        (sps.slice.vcl_cpb_cnt, "VCL"),
    ] {
        if cnt == 0 {
            continue;
        }
        w.begin(format!("{kind} HRD"));
        for i in 0..cnt {
            w.u(format!("initial_cpb_removal_delay[{i}]"), len)?;
            w.u(format!("initial_cpb_removal_delay_offset[{i}]"), len)?;
        }
        w.end();
    }
    Some(None)
}

fn clock_timestamp(w: &mut Walker, sps: &SpsInfo) -> Option<String> {
    w.u("ct_type", 2)?;
    w.flag("nuit_field_based_flag")?;
    w.u("counting_type", 5)?;
    let full = w.flag("full_timestamp_flag")?;
    w.flag("discontinuity_flag")?;
    w.flag("cnt_dropped_flag")?;
    let frames = w.u("n_frames", 8)?;
    let (mut h, mut m, mut s) = (0, 0, 0);
    if full {
        s = w.u("seconds_value", 6)?;
        m = w.u("minutes_value", 6)?;
        h = w.u("hours_value", 5)?;
    } else if w.flag("seconds_flag")? {
        s = w.u("seconds_value", 6)?;
        if w.flag("minutes_flag")? {
            m = w.u("minutes_value", 6)?;
            if w.flag("hours_flag")? {
                h = w.u("hours_value", 5)?;
            }
        }
    }
    let offset_len = sps.slice.time_offset_length;
    if offset_len > 0 {
        w.su("time_offset", offset_len)?;
    }
    Some(format!("{h:02}:{m:02}:{s:02}:{frames:02}"))
}

fn pic_timing(w: &mut Walker, sps: Option<&SpsInfo>) -> Option<Option<String>> {
    let Some(sps) = sps else {
        return Some(None);
    };
    if sps.slice.nal_cpb_cnt > 0 || sps.slice.vcl_cpb_cnt > 0 {
        w.u("cpb_removal_delay", sps.slice.cpb_removal_delay_length)?;
        w.u("dpb_output_delay", sps.slice.dpb_output_delay_length)?;
    }
    if !sps.slice.pic_struct_present {
        return Some(None);
    }
    let ps = w.en("pic_struct", 4, PIC_STRUCT)?;
    let clocks: u64 = match ps {
        0..=2 => 1,
        3 | 4 | 7 => 2,
        5 | 6 | 8 => 3,
        _ => return Some(Some(lookup_or(PIC_STRUCT, ps))),
    };
    let mut times = Vec::new();
    for i in 0..clocks {
        if w.flag(format!("clock_timestamp_flag[{i}]"))? {
            w.begin(format!("Clock timestamp {i}"));
            let t = clock_timestamp(w, sps)?;
            let tt = t.clone();
            w.end_summary(|| tt);
            times.push(t);
        }
    }
    let mut s = lookup_or(PIC_STRUCT, ps);
    if let Some(t) = times.first() {
        s = format!("{s}, {t}");
    }
    Some(Some(s))
}

fn pic_timing_hevc(w: &mut Walker, sps: Option<&SpsInfo>) -> Option<Option<String>> {
    let Some(sps) = sps else {
        return Some(None);
    };
    if !sps.slice.frame_field_info_present {
        return Some(None);
    }
    let ps = w.en("pic_struct", 4, PIC_STRUCT)?;
    w.en(
        "source_scan_type",
        2,
        &[(0, "interlaced"), (1, "progressive"), (2, "unknown")],
    )?;
    w.flag("duplicate_flag")?;
    Some(Some(lookup_or(PIC_STRUCT, ps)))
}

fn time_code(w: &mut Walker) -> Option<Option<String>> {
    let n = w.u("num_clock_ts", 2)?;
    let mut first = None;
    for i in 0..n {
        if w.flag(format!("clock_timestamp_flag[{i}]"))? {
            w.begin(format!("Clock timestamp {i}"));
            w.flag("units_field_based_flag")?;
            w.u("counting_type", 5)?;
            let full = w.flag("full_timestamp_flag")?;
            w.flag("discontinuity_flag")?;
            w.flag("cnt_dropped_flag")?;
            let frames = w.u("n_frames", 9)?;
            let (mut h, mut m, mut s) = (0, 0, 0);
            if full {
                s = w.u("seconds_value", 6)?;
                m = w.u("minutes_value", 6)?;
                h = w.u("hours_value", 5)?;
            } else if w.flag("seconds_flag")? {
                s = w.u("seconds_value", 6)?;
                if w.flag("minutes_flag")? {
                    m = w.u("minutes_value", 6)?;
                    if w.flag("hours_flag")? {
                        h = w.u("hours_value", 5)?;
                    }
                }
            }
            let len = w.u("time_offset_length", 5)?;
            if len > 0 {
                w.su("time_offset_value", u32::try_from(len).ok()?)?;
            }
            let t = format!("{h:02}:{m:02}:{s:02}:{frames:02}");
            let tt = t.clone();
            w.end_summary(|| tt);
            first.get_or_insert(t);
        }
    }
    Some(first)
}
