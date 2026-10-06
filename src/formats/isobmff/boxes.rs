//! Movie, track and media headers, handlers, data references, sample
//! descriptions, movie fragments and protection boxes.

use crate::bytes::{u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Fields, struct_node};
use crate::formats::vidutil::{duration, fixed8, fixed16, fourcc, num, sfixed16, text, uuid};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

use super::{BE, BoxState, Brand, Ctx, children, full_box, small};

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

/// Well-known handler types.
pub fn handler_name(kind: &[u8]) -> Option<&'static str> {
    Some(match kind {
        b"vide" => "Video",
        b"soun" => "Audio",
        b"hint" => "Hint",
        b"meta" => "Timed metadata",
        b"mdir" => "iTunes metadata",
        b"mdta" => "QuickTime metadata",
        b"text" => "Text",
        b"sbtl" => "Subtitles",
        b"subt" => "Subtitles",
        b"clcp" => "Closed captions",
        b"tmcd" => "Timecode",
        b"pict" => "Picture",
        b"auxv" => "Auxiliary video",
        b"alis" => "Alias data",
        b"url " => "URL data",
        b"odsm" => "Object descriptor",
        b"sdsm" => "Scene description",
        b"camm" => "Camera motion",
        b"MPEG" => "MPEG",
        b"CTMD" => "Canon timed metadata",
        _ => return None,
    })
}

/// DRM system IDs used in `pssh` boxes.
pub fn drm_system(id: &[u8]) -> Option<&'static str> {
    const SYSTEMS: &[([u8; 4], &str)] = &[
        ([0xed, 0xef, 0x8b, 0xa9], "Widevine"),
        ([0x9a, 0x04, 0xf0, 0x79], "PlayReady"),
        ([0x94, 0xce, 0x86, 0xfb], "FairPlay"),
        ([0x10, 0x77, 0xef, 0xec], "Common (W3C ClearKey)"),
        ([0xe2, 0x71, 0x9d, 0x58], "ClearKey (DASH-IF)"),
        ([0x5e, 0x62, 0x9a, 0xf5], "Marlin"),
        ([0xad, 0xb4, 0x1c, 0x24], "Adobe Primetime"),
        ([0x3d, 0x5e, 0x6d, 0x35], "Verimatrix"),
    ];
    let prefix = id.get(..4)?;
    SYSTEMS
        .iter()
        .find(|(p, _)| p.as_slice() == prefix)
        .map(|(_, n)| *n)
}

/// Packed ISO-639-2/T language code (three 5-bit letters).
pub fn language(code: u16) -> String {
    if code < 0x400 {
        // QuickTime Macintosh language code.
        return format!("Mac language {code}");
    }
    let letter =
        |shift: u16| char::from(u8::try_from(((code >> shift) & 0x1f) | 0x60).unwrap_or(b'?'));
    [letter(10), letter(5), letter(0)].iter().collect()
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
        b"tkhd" => emit_fields(cx, body, tkhd).await?,
        b"mdhd" => emit_fields(cx, body, mdhd).await?,
        b"hdlr" => emit_fields(cx, body, |f| hdlr(f, ctx.brand)).await?,
        b"vmhd" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u16("Graphics mode").emit()?;
                f.u16("Opcolor red").emit()?;
                f.u16("Opcolor green").emit()?;
                f.u16("Opcolor blue").emit()?;
                Ok(())
            })
            .await?;
        }
        b"smhd" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.int::<i16>("Balance")
                    .with(|&b, n| n.summary(num(f64::from(b) / 256.0)))
                    .emit()?;
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
                f.u32("Max bitrate").emit()?;
                f.u32("Average bitrate").emit()?;
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
            let child = Ctx {
                parent: st.header.kind,
                depth: ctx.depth.saturating_add(1),
                siblings: body.tail(8),
                ..ctx
            };
            children(cx, st.input, body.tail(8), child).await?;
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
        b"mehd" => {
            emit_fields(cx, body, |f| {
                let (v, _) = full_box(f)?;
                f.uword("Fragment duration", v == 1).emit()?;
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
                f.uword("Base media decode time", v == 1).emit()?;
                Ok(())
            })
            .await?;
        }
        b"mfro" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u32("mfra size").emit()?;
                Ok(())
            })
            .await?;
        }
        b"pssh" => emit_fields(cx, body, pssh).await?,
        b"tenc" => emit_fields(cx, body, tenc).await?,
        b"schm" => {
            emit_fields(cx, body, |f| {
                let (_, flags) = full_box(f)?;
                f.ascii("Scheme type", 4).emit()?;
                f.u32("Scheme version").hex().emit()?;
                if flags & 1 != 0 {
                    f.cstr("Scheme URI").emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"frma" => {
            emit_fields(cx, body, |f| {
                f.ascii("Original format", 4).emit()?;
                Ok(())
            })
            .await?;
        }
        b"prft" => {
            emit_fields(cx, body, |f| {
                let (v, _) = full_box(f)?;
                f.u32("Reference track ID").emit()?;
                f.u64("NTP timestamp").hex().emit()?;
                f.uword("Media time", v == 1).emit()?;
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

/// Summaries for the box list.
pub async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let body = st.body();
    let kind = &st.header.kind;
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
            | b"pssh"
            | b"frma"
            | b"schm"
            | b"moof"
            | b"traf"
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
            let major = fourcc(d.get(..4)?);
            let compat: Vec<String> = d
                .get(8..)
                .unwrap_or_default()
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| fourcc(c))
                .collect();
            Some(format!("{major}, compatible: {}", compat.join(" ")))
        }
        b"mvhd" => {
            let at = if wide { 20 } else { 12 };
            let timescale = u32_be(&d, at)?;
            let dur = word(at.saturating_add(4), wide)?;
            Some(format!(
                "{} (timescale {timescale})",
                duration(dur, timescale.into())
            ))
        }
        b"tkhd" => {
            let id = u32_be(&d, if wide { 20 } else { 12 })?;
            let dims = if wide { 88 } else { 76 };
            let w = u32_be(&d, dims).unwrap_or(0) >> 16;
            let h = u32_be(&d, dims.saturating_add(4)).unwrap_or(0) >> 16;
            Some(if w > 0 && h > 0 {
                format!("track {id}, {w}×{h}")
            } else {
                format!("track {id}")
            })
        }
        b"mdhd" => {
            let at = if wide { 20 } else { 12 };
            let timescale = u32_be(&d, at)?;
            let dur = word(at.saturating_add(4), wide)?;
            let lang = u16_be(&d, at.saturating_add(if wide { 12 } else { 8 }))?;
            Some(format!(
                "{} @ {timescale}/s, {}",
                duration(dur, timescale.into()),
                language(lang & 0x7fff)
            ))
        }
        b"hdlr" => {
            let kind = d.get(8..12)?;
            let name = handler_name(kind).unwrap_or("");
            Some(format!("{} {name}", fourcc(kind)).trim_end().to_owned())
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
        b"tfhd" => Some(format!("track {}", u32_be(&d, 4)?)),
        b"tfdt" => Some(format!("base decode time {}", word(4, wide)?)),
        b"pssh" => Some(
            drm_system(d.get(4..20)?)
                .unwrap_or("unknown DRM system")
                .to_owned(),
        ),
        b"frma" => Some(fourcc(d.get(..4)?)),
        b"schm" => Some(fourcc(d.get(4..8)?)),
        b"moof" | b"traf" => None,
        _ => None,
    }
}

fn ftyp(f: &mut Fields<'_>) -> Result<()> {
    f.ascii("Major brand", 4).emit()?;
    f.u32("Minor version").hex().emit()?;
    while f.remaining() >= 4 {
        f.ascii("Compatible brand", 4).emit()?;
    }
    Ok(())
}

fn mvhd(f: &mut Fields<'_>) -> Result<()> {
    let (v, _) = full_box(f)?;
    let wide = v == 1;
    f.uword("Creation time", wide).mac_time().emit()?;
    f.uword("Modification time", wide).mac_time().emit()?;
    let ts = f.u32("Timescale").desc("Time units per second").emit()?;
    f.uword("Duration", wide)
        .with(|&d, n| n.summary(duration(d, ts.into())))
        .emit()?;
    f.u32("Preferred rate")
        .with(|&r, n| n.summary(num(fixed16(r))))
        .emit()?;
    f.u16("Preferred volume")
        .with(|&r, n| n.summary(num(fixed8(r))))
        .emit()?;
    f.bytes("Reserved", 10).emit()?;
    matrix(f)?;
    f.u32("Preview time").emit()?;
    f.u32("Preview duration").emit()?;
    f.u32("Poster time").emit()?;
    f.u32("Selection time").emit()?;
    f.u32("Selection duration").emit()?;
    f.u32("Current time").emit()?;
    f.u32("Next track ID").emit()?;
    Ok(())
}

fn tkhd(f: &mut Fields<'_>) -> Result<()> {
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
        .desc("In movie timescale units")
        .emit()?;
    f.bytes("Reserved", 8).emit()?;
    f.int::<i16>("Layer").emit()?;
    f.int::<i16>("Alternate group").emit()?;
    f.u16("Volume")
        .with(|&r, n| n.summary(num(fixed8(r))))
        .emit()?;
    f.u16("Reserved").emit()?;
    matrix(f)?;
    f.u32("Width")
        .with(|&r, n| n.summary(num(fixed16(r))))
        .emit()?;
    f.u32("Height")
        .with(|&r, n| n.summary(num(fixed16(r))))
        .emit()?;
    Ok(())
}

fn mdhd(f: &mut Fields<'_>) -> Result<()> {
    let (v, _) = full_box(f)?;
    let wide = v == 1;
    f.uword("Creation time", wide).mac_time().emit()?;
    f.uword("Modification time", wide).mac_time().emit()?;
    let ts = f.u32("Timescale").desc("Time units per second").emit()?;
    f.uword("Duration", wide)
        .with(|&d, n| n.summary(duration(d, ts.into())))
        .emit()?;
    f.u16("Language")
        .hex()
        .with(|&l, n| n.summary(language(l & 0x7fff)))
        .emit()?;
    f.u16("Quality / pre-defined").emit()?;
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
    f.bytes("Reserved", 12).emit()?;
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
    let depends = (v >> 24) & 3;
    let non_sync = v & 0x1_0000 != 0;
    let mut parts = vec![if non_sync { "non-sync" } else { "sync" }];
    match depends {
        1 => parts.push("depends on others"),
        2 => parts.push("independent"),
        _ => {}
    }
    if (v >> 22) & 3 == 2 {
        parts.push("not depended on");
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
    f.bytes("Data", size.into()).emit()?;
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
            .emit()?;
    }
    let protected = f.u8("Default is protected").emit()?;
    let iv = f.u8("Default per-sample IV size").emit()?;
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
        f.u32("Timescale").emit()?;
        f.u32("Presentation time delta").emit()?;
        f.u32("Event duration").emit()?;
        f.u32("ID").emit()?;
    } else {
        f.u32("Timescale").emit()?;
        f.u64("Presentation time").emit()?;
        f.u32("Event duration").emit()?;
        f.u32("ID").emit()?;
        f.cstr("Scheme ID URI").emit()?;
        f.cstr("Value").emit()?;
    }
    let rest = f.remaining();
    f.bytes("Message data", rest).emit()?;
    Ok(())
}

/// The 3×3 transformation matrix of `mvhd` and `tkhd`.
fn matrix(f: &mut Fields<'_>) -> Result<()> {
    let span = f.peek_span(36);
    let mut m = [0i32; 9];
    for slot in &mut m {
        *slot = f.int::<i32>("m").get()?;
    }
    let summary = match m {
        [0x10000, 0, 0, 0, 0x10000, 0, _, _, 0x4000_0000] => "identity",
        [0, 0x10000, 0, -0x10000, 0, 0, _, _, 0x4000_0000] => "rotate 90°",
        [-0x10000, 0, 0, 0, -0x10000, 0, _, _, 0x4000_0000] => "rotate 180°",
        [0, -0x10000, 0, 0x10000, 0, 0, _, _, 0x4000_0000] => "rotate 270°",
        _ => "transform",
    };
    f.node(struct_node("Matrix", span, BE, (), matrix_layout).summary(summary));
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
