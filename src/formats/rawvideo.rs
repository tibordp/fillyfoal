//! Raw video elementary streams without a container: Dirac/VC-2 (parse
//! info headers chained by offsets), Avid DNxHD/DNxHR frames and H.263
//! pictures. Units are listed in pages.

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::vidutil::{self, Bits, enumerated, hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

// ---------------------------------------------------------------------------
// Dirac / VC-2

pub static DIRAC: Format = Format {
    name: "dirac",
    title: "Dirac/VC-2 video stream",
    extensions: &["drc", "vc2"],
    mime: "video/x-dirac",
    probe: Probe::Custom(|h| {
        h.starts_with(b"BBCD\x00") && u32_be(h.data, 5).is_some_and(|n| n >= 13)
    }),
    dissect: crate::expander!(dissect_dirac: Input),
};

fn parse_code_name(code: u8) -> String {
    match code {
        0x00 => "Sequence header".to_owned(),
        0x10 => "End of sequence".to_owned(),
        0x20 => "Auxiliary data".to_owned(),
        0x30 => "Padding".to_owned(),
        c if c & 0x08 != 0 => {
            let kind = if c & 0x80 != 0 {
                if c & 0x20 != 0 {
                    "High-quality picture"
                } else {
                    "Low-delay picture"
                }
            } else {
                "Core picture"
            };
            let refs = c & 3;
            format!("{kind}{}", if refs == 0 { " (intra)" } else { "" })
        }
        c => format!("Parse code {c:#04x}"),
    }
}

const VIDEO_FORMATS: [(&str, u32, u32); 21] = [
    ("custom", 640, 480),
    ("QSIF525", 176, 120),
    ("QCIF", 176, 144),
    ("SIF525", 352, 240),
    ("CIF", 352, 288),
    ("4SIF525", 704, 480),
    ("4CIF", 704, 576),
    ("SD480I-60", 720, 480),
    ("SD576I-50", 720, 576),
    ("HD720P-60", 1280, 720),
    ("HD720P-50", 1280, 720),
    ("HD1080I-60", 1920, 1080),
    ("HD1080I-50", 1920, 1080),
    ("HD1080P-60", 1920, 1080),
    ("HD1080P-50", 1920, 1080),
    ("DC2K", 2048, 1080),
    ("DC4K", 4096, 2160),
    ("UHDTV 4K-60", 3840, 2160),
    ("UHDTV 4K-50", 3840, 2160),
    ("UHDTV 8K-60", 7680, 4320),
    ("UHDTV 8K-50", 7680, 4320),
];

/// Dirac's interleaved Exp-Golomb code.
fn dirac_ue(b: &mut Bits<'_>) -> Option<u64> {
    let mut value = 1u64;
    for _ in 0..32 {
        if b.bit()? == 1 {
            return value.checked_sub(1);
        }
        value = value.checked_shl(1)? | b.bit()?;
    }
    None
}

/// (major, minor, profile, level, base format, width, height).
fn sequence_header(d: &[u8]) -> Option<[u64; 7]> {
    let mut b = Bits::new(d);
    let major = dirac_ue(&mut b)?;
    let minor = dirac_ue(&mut b)?;
    let profile = dirac_ue(&mut b)?;
    let level = dirac_ue(&mut b)?;
    let base = dirac_ue(&mut b)?;
    let (mut w, mut h) = VIDEO_FORMATS
        .get(vidutil::us(base))
        .map_or((0, 0), |f| (u64::from(f.1), u64::from(f.2)));
    if b.flag()? {
        w = dirac_ue(&mut b)?;
        h = dirac_ue(&mut b)?;
    }
    Some([major, minor, profile, level, base, w, h])
}

pub async fn dissect_dirac(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(13, 32)).await?;
    cx.annotate(match sequence_header(&head) {
        Some([major, minor, profile, level, _, w, h]) => {
            format!("Dirac/VC-2 v{major}.{minor}, profile {profile}, level {level}, {w}×{h}")
        }
        None => "Dirac/VC-2 stream".to_owned(),
    });
    let mut pos = 0u64;
    while pos < file.len {
        let d = cx.read_avail(file.sub(pos, 13)).await?;
        if d.get(..4) != Some(b"BBCD".as_slice()) {
            cx.emit(
                Node::new("Unparsed data")
                    .span(file.tail(pos))
                    .diag(Diagnostic::malformed("expected a parse info header")),
            );
            break;
        }
        let code = d.get(4).copied().unwrap_or(0);
        let next = u64::from(u32_be(&d, 5).unwrap_or(0));
        let len = if next == 0 {
            file.len.saturating_sub(pos)
        } else {
            next.max(13)
        };
        let span = file.sub(pos, len);
        let mut summary = format!("{len} bytes");
        if code & 0x08 != 0 {
            let body = cx.read_avail(span.sub(13, 4)).await?;
            summary = format!("picture {}, {summary}", u32_be(&body, 0).unwrap_or(0));
        }
        cx.push(
            Node::new(parse_code_name(code))
                .span(span)
                .summary(summary)
                .lazy(dirac_unit, span),
        )
        .await;
        pos = pos.saturating_add(len);
    }
    Ok(())
}

async fn dirac_unit(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 64)).await?;
    cx.emit(vidutil::text("Prefix", span.sub(0, 4), "BBCD"));
    let code = d.get(4).copied().unwrap_or(0);
    cx.emit(hex("Parse code", span.sub(4, 1), code.into(), 8).summary(parse_code_name(code)));
    cx.emit(uint(
        "Next parse offset",
        span.sub(5, 4),
        u32_be(&d, 5).unwrap_or(0).into(),
        32,
    ));
    cx.emit(uint(
        "Previous parse offset",
        span.sub(9, 4),
        u32_be(&d, 9).unwrap_or(0).into(),
        32,
    ));
    let body = span.tail(13);
    if code == 0 {
        if let Some([major, minor, profile, level, base, w, h]) =
            d.get(13..).and_then(sequence_header)
        {
            cx.emit(uint("Major version", body, major, 32));
            cx.emit(uint("Minor version", body, minor, 32));
            cx.emit(uint("Profile", body, profile, 32));
            cx.emit(uint("Level", body, level, 32));
            cx.emit(
                uint("Base video format", body, base, 32).summary(
                    VIDEO_FORMATS
                        .get(vidutil::us(base))
                        .map_or("unknown", |f| f.0),
                ),
            );
            cx.emit(uint("Width", body, w, 32));
            cx.emit(uint("Height", body, h, 32));
        }
    } else if code & 0x08 != 0 {
        cx.emit(uint(
            "Picture number",
            span.sub(13, 4),
            u32_be(&d, 13).unwrap_or(0).into(),
            32,
        ));
        cx.emit(Node::new("Picture data").span(span.tail(17)));
    } else if code == 0x20 {
        let text = crate::text::until_nul(d.get(13..).unwrap_or_default());
        cx.emit(vidutil::text("Data", body, text));
    } else if !body.is_empty() {
        cx.emit(Node::new("Data").span(body));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DNxHD / DNxHR

const DNX_PREFIX: &[u8] = b"\x00\x00\x02\x80";

pub static DNXHD: Format = Format {
    name: "dnxhd",
    title: "Avid DNxHD/DNxHR frames",
    extensions: &["dnxhd", "dnxhr", "dnx"],
    mime: "video/x-dnxhd",
    probe: Probe::Custom(|h| {
        h.starts_with(DNX_PREFIX)
            && h.data.get(4).is_some_and(|&b| (1..=3).contains(&b))
            && u16_be(h.data, 0x18).is_some_and(|v| v > 0)
            && u16_be(h.data, 0x1a).is_some_and(|v| v > 0)
    }),
    dissect: crate::expander!(dissect_dnxhd: Input),
};

const DNX_CIDS: EnumTable = &[
    (1235, "DNxHD 1080p 220/185/175 10-bit"),
    (1237, "DNxHD 1080p 145/120/115"),
    (1238, "DNxHD 1080p 220/185/175"),
    (1241, "DNxHD 1080i 220/185 10-bit"),
    (1242, "DNxHD 1080i 145/120"),
    (1243, "DNxHD 1080i 220/185"),
    (1244, "DNxHD 1080i 145/120 (1440)"),
    (1250, "DNxHD 720p 220/185 10-bit"),
    (1251, "DNxHD 720p 220/185"),
    (1252, "DNxHD 720p 90/75"),
    (1253, "DNxHD 1080p 45/36"),
    (1256, "DNxHD 1080p 350/290 4:4:4 10-bit"),
    (1258, "DNxHD 720p 110/90"),
    (1259, "DNxHD 1080p 120/115 (1440)"),
    (1260, "DNxHD 1080i 120/115 (1440)"),
    (1270, "DNxHR 444"),
    (1271, "DNxHR HQX"),
    (1272, "DNxHR HQ"),
    (1273, "DNxHR SQ"),
    (1274, "DNxHR LB"),
];

fn dnx_summary(d: &[u8]) -> String {
    let h = u16_be(d, 0x18).unwrap_or(0);
    let w = u16_be(d, 0x1a).unwrap_or(0);
    let depth = match d.get(0x21).map(|b| (b >> 5) & 3) {
        Some(2) => 10,
        Some(3) => 12,
        _ => 8,
    };
    let cid = u32_be(d, 0x28).unwrap_or(0);
    format!(
        "{}, {w}×{h}, {depth}-bit",
        vidutil::lookup_or(DNX_CIDS, cid.into())
    )
}

pub async fn dissect_dnxhd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x30)).await?;
    cx.annotate(format!("DNx, {}", dnx_summary(&head)));
    let mut pos = 0u64;
    let mut index = 0u32;
    while pos < file.len {
        let next = find_prefix(&cx, file, pos.saturating_add(4), DNX_PREFIX)
            .await?
            .unwrap_or(file.len);
        let span = file.sub(pos, next.saturating_sub(pos));
        let d = cx.read_avail(span.sub(0, 0x30)).await?;
        cx.push(
            Node::new(format!("Frame {index}"))
                .span(span)
                .summary(format!("{}, {} bytes", dnx_summary(&d), span.len))
                .lazy(dnx_frame, span),
        )
        .await;
        pos = next;
        index = index.saturating_add(1);
    }
    Ok(())
}

/// The next occurrence of `needle` at or after `from`.
async fn find_prefix(cx: &Cx, span: Span, from: u64, needle: &[u8]) -> Result<Option<u64>> {
    const WINDOW: u64 = 0x4000;
    let overlap = to_u64(needle.len()).saturating_sub(1);
    let mut pos = from;
    while pos < span.len {
        let d = cx.read_avail(span.sub(pos, WINDOW)).await?;
        if let Some(i) = vidutil::find(&d, needle) {
            return Ok(Some(pos.saturating_add(to_u64(i))));
        }
        if to_u64(d.len()) <= overlap {
            return Ok(None);
        }
        pos = pos.saturating_add(to_u64(d.len()).saturating_sub(overlap));
        cx.checkpoint().await;
    }
    Ok(None)
}

async fn dnx_frame(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 0x30)).await?;
    cx.emit(hex(
        "Header prefix",
        span.sub(0, 5),
        d.get(..5)
            .map_or(0, |b| b.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x))),
        40,
    ));
    cx.emit(uint(
        "Lines",
        span.sub(0x18, 2),
        u16_be(&d, 0x18).unwrap_or(0).into(),
        16,
    ));
    cx.emit(uint(
        "Samples per line",
        span.sub(0x1a, 2),
        u16_be(&d, 0x1a).unwrap_or(0).into(),
        16,
    ));
    cx.emit(enumerated(
        "Compression ID",
        span.sub(0x28, 4),
        u32_be(&d, 0x28).unwrap_or(0).into(),
        32,
        DNX_CIDS,
    ));
    cx.emit(Node::new("Coded data").span(span.tail(0x280)));
    Ok(())
}

// ---------------------------------------------------------------------------
// H.263

pub static H263: Format = Format {
    name: "h263",
    title: "H.263 video stream",
    extensions: &["h263", "263"],
    mime: "video/h263",
    probe: Probe::Custom(probe_h263),
    dissect: crate::expander!(dissect_h263: Input),
};

/// Whether `d` starts with a plausible picture header.
fn picture_header(d: &[u8]) -> Option<(u8, u8, bool)> {
    if d.get(..2) != Some(b"\x00\x00".as_slice()) || d.get(2)? & 0xfc != 0x80 {
        return None;
    }
    let b3 = *d.get(3)?;
    if b3 & 0x03 != 0x02 {
        return None;
    }
    let b4 = *d.get(4)?;
    let format = (b4 >> 2) & 7;
    let tr = ((d.get(2)? & 3) << 6) | (b3 >> 2);
    Some((tr, format, b4 & 2 != 0))
}

fn is_psc(w: &[u8]) -> bool {
    w.first() == Some(&0) && w.get(1) == Some(&0) && w.get(2).is_some_and(|b| b & 0xfc == 0x80)
}

fn probe_h263(h: &Head<'_>) -> bool {
    let Some((_, format, _)) = picture_header(h.data) else {
        return false;
    };
    if !(1..=7).contains(&format) {
        return false;
    }
    let window = h.data.get(..h.data.len().min(0x8000)).unwrap_or_default();
    match window.windows(3).skip(3).position(is_psc) {
        Some(i) => window
            .get(i.saturating_add(3)..)
            .and_then(picture_header)
            .is_some(),
        None => to_u64(h.data.len()) == h.len,
    }
}

const SOURCE_FORMATS: [(&str, u32, u32); 8] = [
    ("forbidden", 0, 0),
    ("sub-QCIF", 128, 96),
    ("QCIF", 176, 144),
    ("CIF", 352, 288),
    ("4CIF", 704, 576),
    ("16CIF", 1408, 1152),
    ("reserved", 0, 0),
    ("extended PTYPE", 0, 0),
];

async fn next_psc(cx: &Cx, span: Span, from: u64) -> Result<Option<u64>> {
    const WINDOW: u64 = 0x4000;
    let mut pos = from;
    while pos < span.len {
        let d = cx.read_avail(span.sub(pos, WINDOW)).await?;
        if let Some(i) = d.windows(3).position(is_psc) {
            return Ok(Some(pos.saturating_add(to_u64(i))));
        }
        if d.len() < 3 {
            return Ok(None);
        }
        pos = pos.saturating_add(to_u64(d.len()).saturating_sub(2));
        cx.checkpoint().await;
    }
    Ok(None)
}

pub async fn dissect_h263(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 8)).await?;
    if let Some((_, format, _)) = picture_header(&head) {
        let f = SOURCE_FORMATS
            .get(usize::from(format))
            .copied()
            .unwrap_or(("?", 0, 0));
        cx.annotate(format!("H.263, {} ({}×{})", f.0, f.1, f.2));
    }
    let mut pos = 0u64;
    let mut index = 0u32;
    while pos < file.len {
        let next = next_psc(&cx, file, pos.saturating_add(3))
            .await?
            .unwrap_or(file.len);
        let span = file.sub(pos, next.saturating_sub(pos));
        let d = cx.read_avail(span.sub(0, 8)).await?;
        let mut node = Node::new(format!("Picture {index}")).span(span);
        node = match picture_header(&d) {
            Some((tr, format, inter)) => node
                .summary(format!(
                    "{}, TR {tr}, {}, {} bytes",
                    if inter { "P" } else { "I" },
                    SOURCE_FORMATS.get(usize::from(format)).map_or("?", |f| f.0),
                    span.len
                ))
                .lazy(h263_picture, span),
            None => node.diag(Diagnostic::malformed("invalid picture header")),
        };
        cx.push(node).await;
        pos = next;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn h263_picture(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 8)).await?;
    let Some((tr, format, inter)) = picture_header(&d) else {
        return Ok(());
    };
    cx.emit(hex("Picture start code", span.sub(0, 3), 0x20, 22));
    cx.emit(uint("Temporal reference", span.sub(2, 2), tr.into(), 8));
    let s4 = span.sub(4, 1);
    let f = SOURCE_FORMATS
        .get(usize::from(format))
        .copied()
        .unwrap_or(("?", 0, 0));
    cx.emit(
        uint("Source format", s4, format.into(), 3).summary(format!("{} ({}×{})", f.0, f.1, f.2)),
    );
    cx.emit(
        uint("Picture coding type", s4, u64::from(inter), 1).summary(if inter {
            "P (inter)"
        } else {
            "I (intra)"
        }),
    );
    cx.emit(Node::new("Picture data").span(span.tail(5)));
    Ok(())
}
