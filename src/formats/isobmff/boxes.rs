//! Movie, track and media headers, handlers, data references, sample
//! descriptions, movie fragments, protection and spherical-video boxes.

use crate::bytes::{u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Fields, struct_node};
use crate::formats::util::vidutil::{duration, fixed8, fixed16, fourcc, num, sfixed16, text, uuid};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

use super::{BE, BoxState, Brand, children, full_box, full_box_flags, small};

const TKHD_FLAGS: FlagTable = &[
    flag(0x1, "ENABLED"),
    flag(0x2, "IN_MOVIE"),
    flag(0x4, "IN_PREVIEW"),
    flag(0x8, "SIZE_IS_ASPECT_RATIO"),
];

const TFHD_FLAGS: FlagTable = &[
    flag(0x1, "BASE_DATA_OFFSET"),
    flag(0x2, "SAMPLE_DESCRIPTION_INDEX"),
    flag(0x8, "DEFAULT_SAMPLE_DURATION"),
    flag(0x10, "DEFAULT_SAMPLE_SIZE"),
    flag(0x20, "DEFAULT_SAMPLE_FLAGS"),
    flag(0x10000, "DURATION_IS_EMPTY"),
    flag(0x20000, "DEFAULT_BASE_IS_MOOF"),
];

const PRFT_FLAGS: FlagTable = &[
    flag(0x1, "ENCODER_INPUT"),
    flag(0x2, "ENCODER_OUTPUT"),
    flag(0x4, "MOOF_FINALIZED"),
    flag(0x8, "MOOF_WRITTEN"),
    flag(0x10, "CONSISTENT"),
];

const GRAPHICS_MODES: EnumTable = &[
    (0x0, "copy"),
    (0x20, "blend"),
    (0x24, "transparent"),
    (0x40, "dither copy"),
    (0x100, "straight alpha"),
    (0x101, "premultiplied white alpha"),
    (0x102, "premultiplied black alpha"),
    (0x103, "composition (dither copy)"),
    (0x104, "straight alpha blend"),
];

const STEREO_MODES: EnumTable = &[
    (0, "monoscopic"),
    (1, "top-bottom (left eye on top)"),
    (2, "left-right (left eye on the left)"),
    (3, "stereo-custom"),
    (4, "right-left (right eye on the left)"),
];

/// Well-known handler types.
pub fn handler_name(kind: &[u8]) -> Option<&'static str> {
    Some(match kind {
        b"vide" => "Video",
        b"soun" => "Audio",
        b"hint" => "Hint",
        b"meta" => "Timed metadata",
        b"mdir" => "iTunes metadata",
        b"mdta" => "QuickTime metadata",
        b"pict" => "Picture",
        b"text" => "Text",
        b"sbtl" => "Subtitles",
        b"subt" => "Subtitles",
        b"clcp" => "Closed captions",
        b"tmcd" => "Timecode",
        b"auxv" => "Auxiliary video",
        b"alis" => "Alias data",
        b"url " => "URL data",
        b"odsm" => "Object descriptor",
        b"sdsm" => "Scene description",
        b"camm" => "Camera motion",
        b"MPEG" => "MPEG",
        b"CTMD" => "Canon timed metadata",
        b"ID32" => "ID3 metadata",
        b"fdsm" => "Font",
        b"volv" => "Volumetric video",
        b"hapt" => "Haptics",
        _ => return None,
    })
}

/// Well-known `ftyp` brands.
pub fn brand_name(brand: &[u8]) -> Option<&'static str> {
    Some(match brand {
        b"isom" => "ISO base media",
        b"iso2" => "ISO base media v2",
        b"iso3" => "ISO base media v3",
        b"iso4" => "ISO base media v4",
        b"iso5" => "ISO base media v5 (fragments)",
        b"iso6" => "ISO base media v6 (segments)",
        b"iso7" => "ISO base media v7",
        b"iso8" => "ISO base media v8",
        b"iso9" => "ISO base media v9",
        b"isoa" | b"isob" | b"isoc" => "ISO base media",
        b"mp41" => "MP4 v1",
        b"mp42" => "MP4 v2",
        b"mp71" => "MPEG-7 metadata in MP4",
        b"avc1" => "H.264 in ISO",
        b"hvc1" | b"hev1" => "HEVC in ISO",
        b"av01" => "AV1 in ISO",
        b"dash" => "MPEG-DASH segment",
        b"msdh" => "media segment",
        b"msix" => "indexed media segment",
        b"cmfc" | b"cmf2" => "CMAF",
        b"cmfs" => "CMAF segment",
        b"cmff" => "CMAF fragment",
        b"cmfl" => "CMAF chunk",
        b"qt  " => "QuickTime",
        b"M4A " => "iTunes audio",
        b"M4B " => "iTunes audiobook",
        b"M4P " => "iTunes protected audio",
        b"M4V " | b"M4VH" | b"M4VP" => "iTunes video",
        b"F4V " | b"F4P " => "Flash video",
        b"3gp4" | b"3gp5" | b"3gp6" | b"3gp7" | b"3gp8" | b"3gp9" => "3GPP",
        b"3gg6" | b"3gg9" => "3GPP general",
        b"3gs6" | b"3gs9" => "3GPP streaming server",
        b"3gr6" | b"3gr9" => "3GPP progressive download",
        b"3g2a" | b"3g2b" | b"3g2c" => "3GPP2",
        b"mif1" => "HEIF image",
        b"mif2" => "HEIF image (v2)",
        b"msf1" => "HEIF image sequence",
        b"miaf" => "MIAF",
        b"MiHB" | b"MiHA" | b"MiHE" | b"MiPr" => "MIAF profile",
        b"heic" => "HEIC image",
        b"heix" => "HEIC image (extended)",
        b"hevc" | b"hevx" => "HEVC image sequence",
        b"heim" | b"heis" | b"hevm" | b"hevs" => "HEVC multi-layer image",
        b"avif" => "AVIF image",
        b"avis" => "AVIF image sequence",
        b"avio" => "AVIF intra-only",
        b"MA1B" => "AVIF baseline profile",
        b"MA1A" => "AVIF advanced profile",
        b"jpeg" => "JPEG in HEIF",
        b"crx " => "Canon RAW 3",
        b"CAEP" => "Canon",
        b"mjp2" | b"mj2s" => "Motion JPEG 2000",
        b"jp2 " => "JPEG 2000",
        b"jpx " => "JPEG 2000 extended",
        b"MSNV" => "Sony PSP",
        b"XAVC" => "Sony XAVC",
        b"dby1" => "Dolby",
        b"opus" => "Opus in ISO",
        b"ccff" => "Common File Format",
        b"piff" => "PIFF",
        b"isml" => "Smooth Streaming",
        b"caqv" => "Casio",
        b"nvr1" => "NVR",
        _ => return None,
    })
}

/// DRM system IDs used in `pssh` boxes.
pub fn drm_system(id: &[u8]) -> Option<&'static str> {
    const SYSTEMS: &[([u8; 4], &str)] = &[
        ([0xed, 0xef, 0x8b, 0xa9], "Widevine"),
        ([0x9a, 0x04, 0xf0, 0x79], "PlayReady"),
        ([0x94, 0xce, 0x86, 0xfb], "FairPlay"),
        ([0x10, 0x77, 0xef, 0xec], "W3C Common PSSH (ClearKey)"),
        ([0xe2, 0x71, 0x9d, 0x58], "ClearKey (DASH-IF)"),
        ([0x5e, 0x62, 0x9a, 0xf5], "Marlin"),
        ([0xad, 0xb4, 0x1c, 0x24], "Adobe Primetime"),
        ([0x3d, 0x5e, 0x6d, 0x35], "Verimatrix"),
        ([0x80, 0xa6, 0xbe, 0x7e], "Irdeto"),
        ([0x29, 0x70, 0x1f, 0xe4], "ChinaDRM"),
        ([0x1f, 0x83, 0xe1, 0xe6], "Qualcomm"),
        ([0x64, 0x4f, 0xe7, 0xb5], "Arris Titanium"),
        ([0x9a, 0x27, 0xdd, 0x82], "Nagra"),
    ];
    let prefix = id.get(..4)?;
    SYSTEMS
        .iter()
        .find(|(p, _)| p.as_slice() == prefix)
        .map(|(_, n)| *n)
}

const MAC_LANGUAGES: [&str; 36] = [
    "English",
    "French",
    "German",
    "Italian",
    "Dutch",
    "Swedish",
    "Spanish",
    "Danish",
    "Portuguese",
    "Norwegian",
    "Hebrew",
    "Japanese",
    "Arabic",
    "Finnish",
    "Greek",
    "Icelandic",
    "Maltese",
    "Turkish",
    "Croatian",
    "Chinese (traditional)",
    "Urdu",
    "Hindi",
    "Thai",
    "Korean",
    "Lithuanian",
    "Polish",
    "Hungarian",
    "Estonian",
    "Latvian",
    "Sami",
    "Faroese",
    "Farsi",
    "Russian",
    "Chinese (simplified)",
    "Flemish",
    "Irish",
];

/// A media language: packed ISO 639-2/T (three 5-bit letters) or, below
/// 0x400, a QuickTime Macintosh language code.
pub fn language(code: u16) -> String {
    let code = code & 0x7fff;
    if code == 0x7fff {
        return "unspecified".to_owned();
    }
    if code < 0x400 {
        return match MAC_LANGUAGES.get(usize::from(code)) {
            Some(name) => format!("Mac language {code} ({name})"),
            None => format!("Mac language {code}"),
        };
    }
    let letter = |shift: u16| {
        let v = (code >> shift) & 0x1f;
        if (1..=26).contains(&v) {
            char::from(u8::try_from(v | 0x60).unwrap_or(b'?'))
        } else {
            '?'
        }
    };
    [letter(10), letter(5), letter(0)].iter().collect()
}

/// A short form of [`language`] for summaries ("eng", "en"), `None` for
/// "undetermined" and unspecified.
pub fn short_language(code: u16) -> Option<String> {
    let code = code & 0x7fff;
    match code {
        0x7fff => None,
        0 => Some("eng".to_owned()),
        1..=0x3ff => Some(language(code)),
        _ => Some(language(code)).filter(|l| l != "und"),
    }
}

/// What a 3×3 transformation matrix does to the picture.
pub fn transform(m: &[i32; 9]) -> String {
    let [a, b, _, c, d, _, tx, ty, _] = *m;
    let unit = |v: i32| v.unsigned_abs() == 0x10000;
    let shift = if tx != 0 || ty != 0 {
        format!(", offset {}, {}", num(sfixed16(tx)), num(sfixed16(ty)))
    } else {
        String::new()
    };
    let kind = if b == 0 && c == 0 && a != 0 && d != 0 {
        let scaled = !unit(a) || !unit(d);
        let base = match (a > 0, d > 0) {
            (true, true) => "identity",
            (false, false) => "rotated 180°",
            (false, true) => "mirrored horizontally",
            (true, false) => "mirrored vertically",
        };
        if scaled {
            format!(
                "{} (scaled {}×{})",
                if base == "identity" {
                    "no rotation"
                } else {
                    base
                },
                num(sfixed16(a).abs()),
                num(sfixed16(d).abs())
            )
        } else {
            base.to_owned()
        }
    } else if a == 0 && d == 0 && b != 0 && c != 0 {
        match (b > 0, c > 0) {
            (true, false) => "rotated 90° clockwise".to_owned(),
            (false, true) => "rotated 90° counter-clockwise".to_owned(),
            (true, true) => "transposed (mirrored across the diagonal)".to_owned(),
            (false, false) => "transversed (mirrored across the anti-diagonal)".to_owned(),
        }
    } else {
        let ccw = -f64::from(b).atan2(f64::from(a)).to_degrees();
        format!(
            "rotated {}° counter-clockwise",
            num((ccw * 1000.0).round() / 1000.0)
        )
    };
    format!("{kind}{shift}")
}

/// Reads the nine matrix entries at `at` in `d`.
pub fn matrix_at(d: &[u8], at: usize) -> Option<[i32; 9]> {
    let mut m = [0i32; 9];
    for (i, slot) in m.iter_mut().enumerate() {
        let v = u32_be(d, at.checked_add(i.checked_mul(4)?)?)?;
        *slot = v as i32;
    }
    Some(m)
}

async fn emit_fields(
    cx: &Cx,
    span: Span,
    layout: impl FnOnce(&mut Fields<'_>) -> Result<()>,
) -> Result<()> {
    let block = cx.block(span.sub(0, 0x10000)).await?;
    layout(&mut Fields::emitting(cx, &block, BE))
}

/// Decodes the boxes this module knows. Returns `false` for other types.
pub async fn decode(cx: &Cx, st: &BoxState) -> Result<bool> {
    let body = st.body();
    let ctx = st.ctx;
    match &st.header.kind {
        b"ftyp" | b"styp" => emit_fields(cx, body, ftyp).await?,
        b"mvhd" => emit_fields(cx, body, mvhd).await?,
        b"tkhd" => emit_fields(cx, body, |f| tkhd(f, ctx.movie_timescale)).await?,
        b"mdhd" => emit_fields(cx, body, |f| mdhd(f, ctx.brand)).await?,
        b"hdlr" => emit_fields(cx, body, |f| hdlr(f, ctx.brand)).await?,
        b"vmhd" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u16("Graphics mode").enumeration(GRAPHICS_MODES).emit()?;
                f.u16("Opcolor red").emit()?;
                f.u16("Opcolor green").emit()?;
                f.u16("Opcolor blue").emit()?;
                Ok(())
            })
            .await?;
        }
        b"gmin" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u16("Graphics mode").enumeration(GRAPHICS_MODES).emit()?;
                f.u16("Opcolor red").emit()?;
                f.u16("Opcolor green").emit()?;
                f.u16("Opcolor blue").emit()?;
                balance(f)?;
                f.u16("Reserved").emit()?;
                Ok(())
            })
            .await?;
        }
        b"text" if &ctx.parent == b"gmhd" => {
            emit_fields(cx, body, |f| {
                matrix(f, "Text matrix")?;
                Ok(())
            })
            .await?;
        }
        b"tcmi" => emit_fields(cx, body, tcmi).await?,
        b"smhd" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                balance(f)?;
                f.u16("Reserved").emit()?;
                Ok(())
            })
            .await?;
        }
        b"hmhd" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u16("Max PDU size").emit()?;
                f.u16("Average PDU size").emit()?;
                f.u32("Max bitrate")
                    .with(|&v, n| n.summary(bitrate(v.into())))
                    .emit()?;
                f.u32("Average bitrate")
                    .with(|&v, n| n.summary(bitrate(v.into())))
                    .emit()?;
                f.u32("Reserved").emit()?;
                Ok(())
            })
            .await?;
        }
        b"nmhd" | b"sthd" => emit_fields(cx, body, |f| full_box(f).map(|_| ())).await?,
        b"dref" | b"stsd" => {
            emit_fields(cx, body.sub(0, 8), |f| {
                full_box(f)?;
                f.u32("Entry count").emit()?;
                Ok(())
            })
            .await?;
            let rest = body.tail(8);
            children(cx, st.input, rest, ctx.child(st.header.kind, rest)).await?;
        }
        b"url " => {
            emit_fields(cx, body, |f| {
                let (_, flags) = full_box(f)?;
                if flags & 1 != 0 {
                    f.node(Node::new("Self-contained").summary("media data is in this file"));
                } else if f.remaining() > 0 {
                    f.cstr("Location").emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"urn " => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.cstr("Name").emit()?;
                if f.remaining() > 0 {
                    f.cstr("Location").emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"alis" if &ctx.parent == b"dref" => {
            emit_fields(cx, body, |f| {
                let (_, flags) = full_box(f)?;
                if flags & 1 != 0 {
                    f.node(Node::new("Self-contained").summary("media data is in this file"));
                } else if f.remaining() > 0 {
                    let rest = f.remaining();
                    f.bytes("Alias record", rest).emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"mehd" => {
            let ts = ctx.movie_timescale;
            emit_fields(cx, body, |f| {
                let (v, _) = full_box(f)?;
                f.uword("Fragment duration", v == 1)
                    .with(|&d, n| timed(n, d, ts))
                    .desc("Duration of the whole fragmented movie, in movie timescale units")
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"trex" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u32("Track ID").emit()?;
                f.u32("Default sample description index").emit()?;
                f.u32("Default sample duration").emit()?;
                f.u32("Default sample size").emit()?;
                f.u32("Default sample flags")
                    .hex()
                    .with(|&v, n| n.summary(sample_flags(v)))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"mfhd" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u32("Sequence number").emit()?;
                Ok(())
            })
            .await?;
        }
        b"tfhd" => emit_fields(cx, body, tfhd).await?,
        b"tfdt" => {
            emit_fields(cx, body, |f| {
                let (v, _) = full_box(f)?;
                f.uword("Base media decode time", v == 1)
                    .desc("Decode time of the fragment's first sample, in media timescale units")
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"mfro" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u32("mfra size")
                    .desc("Size of the enclosing 'mfra' box, to find it from the end of the file")
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"pssh" => emit_fields(cx, body, pssh).await?,
        b"tenc" => emit_fields(cx, body, tenc).await?,
        b"schm" => {
            emit_fields(cx, body, |f| {
                let (_, flags) = full_box(f)?;
                f.ascii("Scheme type", 4)
                    .with(|t, n| match scheme_name(t.as_bytes()) {
                        Some(s) => n.summary(s),
                        None => n,
                    })
                    .emit()?;
                f.u32("Scheme version")
                    .hex()
                    .with(|&v, n| n.summary(format!("{}.{}", v >> 16, v & 0xffff)))
                    .emit()?;
                if flags & 1 != 0 {
                    f.cstr("Scheme URI").emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"frma" => {
            emit_fields(cx, body, |f| {
                f.ascii("Original format", 4)
                    .with(
                        |t, n| match crate::formats::util::vidutil::codec_name(t.as_bytes()) {
                            Some(c) => n.summary(c),
                            None => n,
                        },
                    )
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"prft" => {
            emit_fields(cx, body, |f| {
                let (v, _) = full_box_flags(f, PRFT_FLAGS)?;
                f.u32("Reference track ID").emit()?;
                f.u64("NTP timestamp")
                    .with(|&t, n| {
                        n.value(Value::Timestamp {
                            unix_seconds: i64::try_from(t >> 32)
                                .unwrap_or(0)
                                .saturating_sub(2_208_988_800),
                        })
                    })
                    .desc("Wall-clock time (NTP: seconds since 1900 in the high 32 bits)")
                    .emit()?;
                f.uword("Media time", v == 1)
                    .desc("In the reference track's media timescale")
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"emsg" => emit_fields(cx, body, emsg).await?,
        b"kind" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.cstr("Scheme URI").emit()?;
                f.cstr("Value").emit()?;
                Ok(())
            })
            .await?;
        }
        b"elng" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.cstr("Extended language").emit()?;
                Ok(())
            })
            .await?;
        }
        b"st3d" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u8("Stereo mode").enumeration(STEREO_MODES).emit()?;
                Ok(())
            })
            .await?;
        }
        b"svhd" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.cstr("Metadata source").emit()?;
                Ok(())
            })
            .await?;
        }
        b"prhd" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                for name in ["Pose yaw", "Pose pitch", "Pose roll"] {
                    f.i32(name)
                        .with(|&v, n| n.summary(format!("{}°", num(sfixed16(v)))))
                        .emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"equi" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                for name in ["Bound top", "Bound bottom", "Bound left", "Bound right"] {
                    f.u32(name)
                        .with(|&v, n| n.summary(num(f64::from(v) / 4_294_967_296.0)))
                        .emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"cbmp" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u32("Layout").emit()?;
                f.u32("Padding").emit()?;
                Ok(())
            })
            .await?;
        }
        _ if &ctx.parent == b"tref" => {
            emit_fields(cx, body, |f| {
                while f.remaining() >= 4 {
                    f.u32("Track ID").emit()?;
                }
                Ok(())
            })
            .await?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Kinds of track reference.
fn reference_name(kind: &[u8]) -> Option<&'static str> {
    Some(match kind {
        b"chap" => "chapters in",
        b"tmcd" => "timecode in",
        b"hint" => "hint for",
        b"cdsc" => "describes",
        b"font" => "fonts in",
        b"hind" => "hint dependency on",
        b"vdep" => "auxiliary depth video for",
        b"vplx" => "auxiliary parallax video for",
        b"subt" => "subtitles for",
        b"forc" => "forced subtitles in",
        b"sync" => "synchronised to",
        b"fall" => "fallback for",
        b"thmb" => "thumbnails for",
        b"auxl" => "auxiliary to",
        b"sbas" => "base layer",
        b"scal" => "extractor of",
        b"folw" => "follows",
        b"mpod" => "MPEG-4 object descriptor for",
        b"dpnd" => "depends on",
        b"ipir" => "IPI for",
        b"adda" => "additional audio for",
        _ => return None,
    })
}

fn scheme_name(kind: &[u8]) -> Option<&'static str> {
    Some(match kind {
        b"cenc" => "AES-CTR, full sample",
        b"cbc1" => "AES-CBC, full sample",
        b"cens" => "AES-CTR, pattern",
        b"cbcs" => "AES-CBC, pattern (FairPlay, HLS)",
        b"piff" => "PIFF",
        b"odkm" => "OMA DRM",
        b"sdrm" | b"itun" => "Apple FairPlay (iTunes)",
        _ => return None,
    })
}

/// A rate in bits per second, for summaries.
pub fn bitrate(bps: u64) -> String {
    let one_decimal = |v: f64| {
        let s = format!("{v:.1}");
        s.strip_suffix(".0")
            .map_or_else(|| s.clone(), str::to_owned)
    };
    if bps >= 10_000_000 {
        format!("{} Mb/s", one_decimal(bps as f64 / 1_000_000.0))
    } else if bps >= 1000 {
        format!("{} kb/s", one_decimal(bps as f64 / 1000.0))
    } else {
        format!("{bps} b/s")
    }
}

/// Adds a duration summary to a node holding `units` of `1/timescale` s.
fn timed(n: Node, units: u64, timescale: u32) -> Node {
    if timescale == 0 {
        n
    } else {
        n.summary(span_of_time(units, timescale))
    }
}

/// A duration, or "indefinite" for the all-ones value.
pub fn span_of_time(units: u64, timescale: u32) -> String {
    if units == u64::MAX || units == u64::from(u32::MAX) {
        "indefinite".to_owned()
    } else {
        duration(units, timescale.into())
    }
}

fn balance(f: &mut Fields<'_>) -> Result<()> {
    f.int::<i16>("Balance")
        .with(|&b, n| n.summary(num(f64::from(b) / 256.0)))
        .desc("Stereo balance, -1 (left) to 1 (right), 8.8 fixed point")
        .emit()?;
    Ok(())
}

/// Summaries for the box list.
pub async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let body = st.body();
    let kind = &st.header.kind;
    if &st.ctx.parent == b"tref" {
        let d = small(cx, body.sub(0, 64)).await.ok()?;
        let ids: Vec<String> = d
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_be_bytes(*c).to_string())
            .collect();
        let what = reference_name(kind).unwrap_or("references");
        return Some(format!(
            "{what} track{} {}",
            if ids.len() == 1 { "" } else { "s" },
            ids.join(", ")
        ));
    }
    if !matches!(
        kind,
        b"ftyp"
            | b"styp"
            | b"mvhd"
            | b"tkhd"
            | b"mdhd"
            | b"hdlr"
            | b"dref"
            | b"stsd"
            | b"mfhd"
            | b"tfhd"
            | b"tfdt"
            | b"trex"
            | b"mehd"
            | b"pssh"
            | b"tenc"
            | b"frma"
            | b"schm"
            | b"prft"
            | b"emsg"
            | b"st3d"
    ) {
        return None;
    }
    let d = small(cx, body.sub(0, 512)).await.ok()?;
    let version = d.first().copied().unwrap_or(0);
    let wide = version == 1;
    let word = |at: usize, wide: bool| {
        if wide {
            u64_be(&d, at)
        } else {
            u32_be(&d, at).map(u64::from)
        }
    };
    match kind {
        b"ftyp" | b"styp" => {
            let major = d.get(..4)?;
            let compat: Vec<String> = d
                .get(8..)
                .unwrap_or_default()
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| fourcc(c))
                .collect();
            let name = brand_name(major).map_or_else(String::new, |n| format!(" ({n})"));
            Some(format!(
                "{}{name}, compatible: {}",
                fourcc(major),
                compat.join(" ")
            ))
        }
        b"mvhd" => {
            let at = if wide { 20 } else { 12 };
            let timescale = u32_be(&d, at)?;
            let dur = word(at.saturating_add(4), wide)?;
            Some(format!(
                "{} (timescale {timescale})",
                span_of_time(dur, timescale)
            ))
        }
        b"tkhd" => {
            let flags = u32_be(&d, 0)? & 0x00ff_ffff;
            let id = u32_be(&d, if wide { 20 } else { 12 })?;
            let m = if wide { 52 } else { 40 };
            let dims = if wide { 88 } else { 76 };
            let w = u32_be(&d, dims).unwrap_or(0);
            let h = u32_be(&d, dims.saturating_add(4)).unwrap_or(0);
            let mut s = format!("track {id}");
            if w > 0 && h > 0 {
                s = format!("{s}, {}×{}", num(fixed16(w)), num(fixed16(h)));
            }
            if let Some(m) = matrix_at(&d, m) {
                let t = transform(&m);
                if t != "identity" {
                    s = format!("{s}, {t}");
                }
            }
            if flags & 1 == 0 {
                s.push_str(", disabled");
            }
            Some(s)
        }
        b"mdhd" => {
            let at = if wide { 20 } else { 12 };
            let timescale = u32_be(&d, at)?;
            let dur = word(at.saturating_add(4), wide)?;
            let lang = u16_be(&d, at.saturating_add(if wide { 12 } else { 8 }))?;
            Some(format!(
                "{} @ {timescale}/s, {}",
                duration(dur, timescale.into()),
                language(lang)
            ))
        }
        b"hdlr" => {
            let kind = d.get(8..12)?;
            let mut s = fourcc(kind);
            if let Some(name) = handler_name(kind) {
                s = format!("{s} {name}");
            }
            let raw = d.get(24..).unwrap_or_default();
            let name = match raw.first() {
                // QuickTime: a Pascal string filling the rest.
                Some(&n) if usize::from(n) == raw.len().saturating_sub(1) && n > 0 => {
                    crate::text::latin1(raw.get(1..).unwrap_or_default())
                }
                _ => crate::text::until_nul(raw),
            };
            let name = name.trim();
            if !name.is_empty() {
                s = format!("{s}, \"{name}\"");
            }
            Some(s)
        }
        b"dref" | b"stsd" => {
            let n = u32_be(&d, 4)?;
            let first = d.get(12..16).map(fourcc);
            Some(match (kind, first) {
                (b"stsd", Some(t)) if n > 0 => format!("{}: {t}", super::tables::entries(n.into())),
                _ => super::tables::entries(n.into()),
            })
        }
        b"mfhd" => Some(format!("sequence {}", u32_be(&d, 4)?)),
        b"tfhd" => {
            let flags = u32_be(&d, 0)? & 0x00ff_ffff;
            let mut s = format!("track {}", u32_be(&d, 4)?);
            let mut at = 8usize;
            if flags & 1 != 0 {
                at = at.saturating_add(8);
            }
            if flags & 2 != 0 {
                at = at.saturating_add(4);
            }
            if flags & 8 != 0 {
                s = format!("{s}, default duration {}", u32_be(&d, at)?);
                at = at.saturating_add(4);
            }
            if flags & 0x10 != 0 {
                s = format!("{s}, default size {}", u32_be(&d, at)?);
            }
            Some(s)
        }
        b"tfdt" => Some(format!("base decode time {}", word(4, wide)?)),
        b"trex" => Some(format!("track {}", u32_be(&d, 4)?)),
        b"mehd" => {
            let units = word(4, wide)?;
            let ts = st.ctx.movie_timescale;
            Some(if ts > 0 {
                duration(units, ts.into())
            } else {
                format!("{units} units")
            })
        }
        b"pssh" => {
            let mut s = drm_system(d.get(4..20)?)
                .unwrap_or("unknown DRM system")
                .to_owned();
            if version > 0
                && let Some(n) = u32_be(&d, 20)
            {
                s = format!(
                    "{s}, {}",
                    crate::formats::util::vidutil::plural(n, "key ID")
                );
            }
            Some(s)
        }
        b"tenc" => {
            let protected = *d.get(6)?;
            let iv = *d.get(7)?;
            let kid = d.get(8..24)?;
            Some(if protected == 0 {
                "not protected".to_owned()
            } else if iv == 0 {
                format!("constant IV, KID {}", uuid(kid))
            } else {
                format!("{iv}-byte IVs, KID {}", uuid(kid))
            })
        }
        b"frma" => {
            let t = d.get(..4)?;
            Some(match crate::formats::util::vidutil::codec_name(t) {
                Some(c) => format!("{} ({c})", fourcc(t)),
                None => fourcc(t),
            })
        }
        b"schm" => {
            let t = d.get(4..8)?;
            Some(match scheme_name(t) {
                Some(n) => format!("{} ({n})", fourcc(t)),
                None => fourcc(t),
            })
        }
        b"prft" => Some(format!("track {}", u32_be(&d, 4)?)),
        b"emsg" => {
            let uri = if version == 0 {
                crate::text::until_nul(d.get(4..)?)
            } else {
                crate::text::until_nul(d.get(24..)?)
            };
            Some(uri)
        }
        b"st3d" => Some(crate::formats::util::vidutil::lookup_or(
            STEREO_MODES,
            (*d.get(4)?).into(),
        )),
        _ => None,
    }
}

fn ftyp(f: &mut Fields<'_>) -> Result<()> {
    f.ascii("Major brand", 4)
        .with(|b, n| brand_summary(b, n))
        .emit()?;
    f.u32("Minor version").hex().emit()?;
    while f.remaining() >= 4 {
        f.ascii("Compatible brand", 4)
            .with(|b, n| brand_summary(b, n))
            .emit()?;
    }
    Ok(())
}

fn brand_summary(b: &str, n: Node) -> Node {
    // The 4-character brand, padding included ("qt  ").
    let mut raw = b.as_bytes().to_vec();
    raw.resize(4, b' ');
    match brand_name(&raw) {
        Some(name) => n.summary(name),
        None => n,
    }
}

fn mvhd(f: &mut Fields<'_>) -> Result<()> {
    let (v, _) = full_box(f)?;
    let wide = v == 1;
    f.uword("Creation time", wide).mac_time().emit()?;
    f.uword("Modification time", wide).mac_time().emit()?;
    let ts = f.u32("Timescale").desc("Time units per second").emit()?;
    f.uword("Duration", wide)
        .with(|&d, n| n.summary(span_of_time(d, ts)))
        .emit()?;
    f.u32("Preferred rate")
        .with(|&r, n| n.summary(format!("{}×", num(fixed16(r)))))
        .emit()?;
    f.u16("Preferred volume")
        .with(|&r, n| n.summary(format!("{}%", num(fixed8(r) * 100.0))))
        .emit()?;
    f.bytes("Reserved", 10).emit()?;
    matrix(f, "Matrix")?;
    f.u32("Preview time").emit()?;
    f.u32("Preview duration").emit()?;
    f.u32("Poster time").emit()?;
    f.u32("Selection time").emit()?;
    f.u32("Selection duration").emit()?;
    f.u32("Current time").emit()?;
    f.u32("Next track ID").emit()?;
    Ok(())
}

fn tkhd(f: &mut Fields<'_>, movie_timescale: u32) -> Result<()> {
    let version = f.u8("Version").emit()?;
    let wide = version == 1;
    let flags = f.bytes("Flags", 3);
    let span = flags.span();
    let raw = flags
        .get()?
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let (set, unknown) = crate::value::decode_flags(TKHD_FLAGS, raw);
    f.node(Node::new("Flags").span(span).value(Value::Flags {
        raw,
        bits: 24,
        set,
        unknown,
    }));
    f.uword("Creation time", wide).mac_time().emit()?;
    f.uword("Modification time", wide).mac_time().emit()?;
    f.u32("Track ID").emit()?;
    f.u32("Reserved").emit()?;
    f.uword("Duration", wide)
        .with(|&d, n| timed(n, d, movie_timescale))
        .desc("In movie timescale units")
        .emit()?;
    f.bytes("Reserved", 8).emit()?;
    f.int::<i16>("Layer")
        .desc("Front-to-back order; lower layers are closer to the viewer")
        .emit()?;
    f.int::<i16>("Alternate group")
        .desc("Tracks in the same nonzero group are alternatives (languages, bitrates)")
        .emit()?;
    f.u16("Volume")
        .with(|&r, n| n.summary(format!("{}%", num(fixed8(r) * 100.0))))
        .emit()?;
    f.u16("Reserved").emit()?;
    matrix(f, "Matrix")?;
    f.u32("Width")
        .with(|&r, n| n.summary(num(fixed16(r))))
        .desc("Presentation width, 16.16 fixed point")
        .emit()?;
    f.u32("Height")
        .with(|&r, n| n.summary(num(fixed16(r))))
        .desc("Presentation height, 16.16 fixed point")
        .emit()?;
    Ok(())
}

fn mdhd(f: &mut Fields<'_>, brand: Brand) -> Result<()> {
    let (v, _) = full_box(f)?;
    let wide = v == 1;
    f.uword("Creation time", wide).mac_time().emit()?;
    f.uword("Modification time", wide).mac_time().emit()?;
    let ts = f.u32("Timescale").desc("Time units per second").emit()?;
    f.uword("Duration", wide)
        .with(|&d, n| n.summary(span_of_time(d, ts)))
        .emit()?;
    f.u16("Language")
        .hex()
        .with(|&l, n| n.summary(language(l)))
        .desc("ISO 639-2/T code packed as three 5-bit letters; QuickTime uses Macintosh codes below 0x400")
        .emit()?;
    f.u16(if brand == Brand::Mov {
        "Quality"
    } else {
        "Pre-defined"
    })
    .emit()?;
    Ok(())
}

fn hdlr(f: &mut Fields<'_>, brand: Brand) -> Result<()> {
    full_box(f)?;
    f.ascii("Component type", 4)
        .desc("QuickTime: 'mhlr' (media) or 'dhlr' (data); 0 in ISO files")
        .emit()?;
    f.ascii("Handler type", 4)
        .with(|t, n| match handler_name(t.as_bytes()) {
            Some(name) => n.summary(name),
            None => n,
        })
        .emit()?;
    f.ascii("Manufacturer", 4).emit()?;
    f.u32("Component flags").hex().emit()?;
    f.u32("Component flags mask").hex().emit()?;
    let rest = f.remaining();
    if rest == 0 {
        return Ok(());
    }
    let first = f
        .block()
        .data
        .get(crate::bytes::to_usize(f.pos()))
        .copied()
        .unwrap_or(0);
    if brand == Brand::Mov && u64::from(first) == rest.saturating_sub(1) && first > 0 {
        f.u8("Name length").emit()?;
        f.ascii("Name", rest.saturating_sub(1)).emit()?;
    } else {
        f.ascii("Name", rest).emit()?;
    }
    Ok(())
}

fn tcmi(f: &mut Fields<'_>) -> Result<()> {
    full_box(f)?;
    f.u16("Text font").emit()?;
    f.u16("Text face").hex().emit()?;
    f.u16("Text size").emit()?;
    f.u16("Reserved").emit()?;
    for name in [
        "Text color red",
        "Text color green",
        "Text color blue",
        "Background red",
        "Background green",
        "Background blue",
    ] {
        f.u16(name).hex().emit()?;
    }
    if f.remaining() > 0 {
        let n = f.u8("Font name length").emit()?;
        f.ascii("Font name", n.into()).emit()?;
    }
    Ok(())
}

fn tfhd(f: &mut Fields<'_>) -> Result<()> {
    f.u8("Version").emit()?;
    let field = f.bytes("Flags", 3);
    let span = field.span();
    let flags = field
        .get()?
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let (set, unknown) = crate::value::decode_flags(TFHD_FLAGS, flags);
    f.node(Node::new("Flags").span(span).value(Value::Flags {
        raw: flags,
        bits: 24,
        set,
        unknown,
    }));
    f.u32("Track ID").emit()?;
    if flags & 0x1 != 0 {
        f.u64("Base data offset").hex().emit()?;
    }
    if flags & 0x2 != 0 {
        f.u32("Sample description index").emit()?;
    }
    if flags & 0x8 != 0 {
        f.u32("Default sample duration").emit()?;
    }
    if flags & 0x10 != 0 {
        f.u32("Default sample size").emit()?;
    }
    if flags & 0x20 != 0 {
        f.u32("Default sample flags")
            .hex()
            .with(|&v, n| n.summary(sample_flags(v)))
            .emit()?;
    }
    Ok(())
}

/// Describes fragment sample flags (ISO 14496-12 8.8.3.1).
pub fn sample_flags(v: u32) -> String {
    let leading = (v >> 26) & 3;
    let depends = (v >> 24) & 3;
    let depended = (v >> 22) & 3;
    let non_sync = v & 0x1_0000 != 0;
    let mut parts = vec![if non_sync { "non-sync" } else { "sync" }];
    match leading {
        1 => parts.push("leading, depends on earlier"),
        2 => parts.push("not leading"),
        3 => parts.push("leading, decodable"),
        _ => {}
    }
    match depends {
        1 => parts.push("depends on others"),
        2 => parts.push("independent"),
        _ => {}
    }
    match depended {
        1 => parts.push("depended on"),
        2 => parts.push("not depended on"),
        _ => {}
    }
    if (v >> 17) & 7 != 0 {
        parts.push("padded");
    }
    parts.join(", ")
}

fn pssh(f: &mut Fields<'_>) -> Result<()> {
    let (v, _) = full_box(f)?;
    let id = f.bytes("System ID", 16);
    let at = id.span();
    let id = id.get()?;
    let mut node = text("System ID", at, uuid(&id));
    if let Some(name) = drm_system(&id) {
        node = node.summary(name);
    }
    f.node(node);
    if v > 0 {
        let n = f.u32("KID count").emit()?;
        for _ in 0..n.min(256) {
            if f.remaining() < 16 {
                break;
            }
            let kid = f.bytes("KID", 16);
            let span = kid.span();
            let kid = kid.get()?;
            f.node(text("KID", span, uuid(&kid)));
        }
    }
    let size = f.u32("Data size").emit()?;
    f.bytes("Data", size.into())
        .desc("Opaque to ISO BMFF; its format belongs to the DRM system")
        .emit()?;
    Ok(())
}

fn tenc(f: &mut Fields<'_>) -> Result<()> {
    let (v, _) = full_box(f)?;
    f.u8("Reserved").emit()?;
    if v == 0 {
        f.u8("Reserved").emit()?;
    } else {
        f.u8("Crypt/skip byte blocks")
            .with(|&b, n| n.summary(format!("crypt {}, skip {}", b >> 4, b & 15)))
            .desc("Pattern encryption: 16-byte blocks encrypted, then skipped")
            .emit()?;
    }
    let protected = f
        .u8("Default is protected")
        .with(|&p, n| n.summary(if p == 0 { "no" } else { "yes" }))
        .emit()?;
    let iv = f
        .u8("Default per-sample IV size")
        .with(|&s, n| {
            n.summary(if s == 0 {
                "constant IV".to_owned()
            } else {
                format!("{s} bytes")
            })
        })
        .emit()?;
    let kid = f.bytes("Default KID", 16);
    let span = kid.span();
    let kid = kid.get()?;
    f.node(text("Default KID", span, uuid(&kid)));
    if protected == 1 && iv == 0 {
        let n = f.u8("Constant IV size").emit()?;
        f.bytes("Constant IV", n.into()).emit()?;
    }
    Ok(())
}

fn emsg(f: &mut Fields<'_>) -> Result<()> {
    let (v, _) = full_box(f)?;
    if v == 0 {
        f.cstr("Scheme ID URI").emit()?;
        f.cstr("Value").emit()?;
        let ts = f.u32("Timescale").emit()?;
        f.u32("Presentation time delta")
            .with(|&d, n| timed(n, d.into(), ts))
            .emit()?;
        f.u32("Event duration")
            .with(|&d, n| timed(n, d.into(), ts))
            .emit()?;
        f.u32("ID").emit()?;
    } else {
        let ts = f.u32("Timescale").emit()?;
        f.u64("Presentation time")
            .with(|&d, n| timed(n, d, ts))
            .emit()?;
        f.u32("Event duration")
            .with(|&d, n| timed(n, d.into(), ts))
            .emit()?;
        f.u32("ID").emit()?;
        f.cstr("Scheme ID URI").emit()?;
        f.cstr("Value").emit()?;
    }
    let rest = f.remaining();
    f.bytes("Message data", rest).emit()?;
    Ok(())
}

/// The 3×3 transformation matrix of `mvhd` and `tkhd`.
fn matrix(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    let span = f.peek_span(36);
    let mut m = [0i32; 9];
    for slot in &mut m {
        *slot = f.int::<i32>("m").get()?;
    }
    f.node(
        struct_node(name, span, BE, (), matrix_layout)
            .summary(transform(&m))
            .desc("Maps (x, y) to (a·x + c·y + tx, b·x + d·y + ty); a b c d tx ty are 16.16, u v w are 2.30"),
    );
    Ok(())
}

fn matrix_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    const NAMES: [(&str, bool); 9] = [
        ("a", true),
        ("b", true),
        ("u", false),
        ("c", true),
        ("d", true),
        ("v", false),
        ("tx", true),
        ("ty", true),
        ("w", false),
    ];
    for (name, is_16_16) in NAMES {
        f.int::<i32>(name)
            .with(|&v, n| {
                n.summary(num(if is_16_16 {
                    sfixed16(v)
                } else {
                    f64::from(v) / 1_073_741_824.0
                }))
            })
            .emit()?;
    }
    Ok(())
}
