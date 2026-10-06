//! Adobe Flash (SWF): an 8-byte header (`FWS`, or `CWS` for a zlib-
//! compressed body, `ZWS` for LZMA), then the frame size rectangle, frame
//! rate and count, and a sequence of tags (listed in pages). Compressed
//! bodies are inflated when expanded.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::vidutil::{self, Bits, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

pub static FORMAT: Format = Format {
    name: "swf",
    title: "Adobe Flash movie",
    extensions: &["swf"],
    mime: "application/x-shockwave-flash",
    probe: Probe::Custom(|h| {
        (h.starts_with(b"FWS") || h.starts_with(b"CWS") || h.starts_with(b"ZWS"))
            && h.data.get(3).is_some_and(|&v| (1..=50).contains(&v))
            && u32_le(h.data, 4).is_some_and(|n| n >= 8)
    }),
    dissect: crate::expander!(dissect: Input),
};

const TAGS: EnumTable = &[
    (0, "End"),
    (1, "ShowFrame"),
    (2, "DefineShape"),
    (4, "PlaceObject"),
    (5, "RemoveObject"),
    (6, "DefineBits"),
    (7, "DefineButton"),
    (8, "JPEGTables"),
    (9, "SetBackgroundColor"),
    (10, "DefineFont"),
    (11, "DefineText"),
    (12, "DoAction"),
    (13, "DefineFontInfo"),
    (14, "DefineSound"),
    (15, "StartSound"),
    (17, "DefineButtonSound"),
    (18, "SoundStreamHead"),
    (19, "SoundStreamBlock"),
    (20, "DefineBitsLossless"),
    (21, "DefineBitsJPEG2"),
    (22, "DefineShape2"),
    (23, "DefineButtonCxform"),
    (24, "Protect"),
    (26, "PlaceObject2"),
    (28, "RemoveObject2"),
    (32, "DefineShape3"),
    (33, "DefineText2"),
    (34, "DefineButton2"),
    (35, "DefineBitsJPEG3"),
    (36, "DefineBitsLossless2"),
    (37, "DefineEditText"),
    (39, "DefineSprite"),
    (41, "ProductInfo"),
    (43, "FrameLabel"),
    (45, "SoundStreamHead2"),
    (46, "DefineMorphShape"),
    (48, "DefineFont2"),
    (56, "ExportAssets"),
    (57, "ImportAssets"),
    (58, "EnableDebugger"),
    (59, "DoInitAction"),
    (60, "DefineVideoStream"),
    (61, "VideoFrame"),
    (62, "DefineFontInfo2"),
    (63, "DebugID"),
    (64, "EnableDebugger2"),
    (65, "ScriptLimits"),
    (66, "SetTabIndex"),
    (69, "FileAttributes"),
    (70, "PlaceObject3"),
    (71, "ImportAssets2"),
    (73, "DefineFontAlignZones"),
    (74, "CSMTextSettings"),
    (75, "DefineFont3"),
    (76, "SymbolClass"),
    (77, "Metadata"),
    (78, "DefineScalingGrid"),
    (82, "DoABC"),
    (83, "DefineShape4"),
    (84, "DefineMorphShape2"),
    (86, "DefineSceneAndFrameLabelData"),
    (87, "DefineBinaryData"),
    (88, "DefineFontName"),
    (89, "StartSound2"),
    (90, "DefineBitsJPEG4"),
    (91, "DefineFont4"),
    (93, "EnableTelemetry"),
];

const VIDEO_CODECS: EnumTable = &[
    (2, "Sorenson H.263"),
    (3, "Screen video"),
    (4, "VP6"),
    (5, "VP6 with alpha"),
    (6, "Screen video v2"),
    (7, "H.264"),
];

/// The frame rectangle, rate and count at the start of the body:
/// (width, height in twips, rate, count, length in bytes).
fn movie_header(d: &[u8]) -> Option<(i64, i64, f64, u16, usize)> {
    let mut b = Bits::new(d);
    let n = u32::try_from(b.bits(5)?).ok()?;
    let mut sbits = || -> Option<i64> {
        let v = b.bits(n)?;
        let shift = 64u32.checked_sub(n)?;
        Some(i64::from_ne_bytes(v.wrapping_shl(shift).to_ne_bytes()).wrapping_shr(shift))
    };
    let (xmin, xmax, ymin, ymax) = (sbits()?, sbits()?, sbits()?, sbits()?);
    let rect = b.pos().div_ceil(8);
    let rate = u16_le(d, rect)?;
    let count = u16_le(d, rect.checked_add(2)?)?;
    Some((
        xmax.saturating_sub(xmin),
        ymax.saturating_sub(ymin),
        f64::from(rate) / 256.0,
        count,
        rect.checked_add(4)?,
    ))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 8)).await?;
    let sig = head.first().copied().unwrap_or(0);
    let version = head.get(3).copied().unwrap_or(0);
    let length = u32_le(&head, 4).unwrap_or(0);
    let h = file.sub(0, 8);
    cx.emit(vidutil::text(
        "Signature",
        h.sub(0, 3),
        String::from_utf8_lossy(head.get(..3).unwrap_or_default()).into_owned(),
    ).summary(match sig {
        b'C' => "zlib-compressed",
        b'Z' => "LZMA-compressed",
        _ => "uncompressed",
    }));
    cx.emit(uint("Version", h.sub(3, 1), version.into(), 8));
    cx.emit(uint("File length", h.sub(4, 4), length.into(), 32).desc("Uncompressed length of the whole file"));
    let body = file.tail(8);
    match sig {
        b'F' => {
            cx.annotate(format!("SWF v{version}"));
            walk(&cx, body, version, true).await
        }
        b'C' => {
            let decoded = crate::codec::inflate_span(
                &cx,
                body,
                true,
                Some(u64::from(length).saturating_sub(8)),
            )
            .await?;
            let mut node = Node::new("Compressed body")
                .span(body)
                .summary(format!("{} bytes decompressed", decoded.span.len))
                .lazy(expand_body, (decoded.span, version));
            if let Some(e) = decoded.error {
                node = node.diag(e);
            }
            let d = cx.read_avail(decoded.span.sub(0, 32)).await?;
            cx.annotate(summary(version, &d, true));
            cx.emit(node);
            Ok(())
        }
        _ => {
            cx.annotate(format!("SWF v{version}, LZMA-compressed"));
            cx.emit(
                Node::new("Compressed body")
                    .span(body)
                    .diag(Diagnostic::unsupported("LZMA compression")),
            );
            Ok(())
        }
    }
}

fn summary(version: u8, d: &[u8], compressed: bool) -> String {
    let mut s = format!("SWF v{version}");
    if compressed {
        s.push_str(" (zlib)");
    }
    if let Some((w, h, rate, count, _)) = movie_header(d) {
        s = format!(
            "{s}, {}×{}, {} fps, {}",
            w / 20,
            h / 20,
            vidutil::num(rate),
            vidutil::plural(count, "frame")
        );
    }
    s
}

async fn expand_body(cx: Cx, (span, version): (Span, u8)) -> Result<()> {
    walk(&cx, span, version, false).await
}

/// The movie header and the tag list of an (uncompressed) body.
async fn walk(cx: &Cx, body: Span, version: u8, annotate: bool) -> Result<()> {
    let d = cx.read_avail(body.sub(0, 32)).await?;
    let Some((w, h, rate, count, len)) = movie_header(&d) else {
        return Err(Diagnostic::truncated(body.sub(0, 32), crate::bytes::to_u64(d.len())));
    };
    if annotate {
        cx.annotate(summary(version, &d, false));
    }
    let len = crate::bytes::to_u64(len);
    let rect = len.saturating_sub(4);
    cx.emit(
        Node::new("Frame size")
            .span(body.sub(0, rect))
            .summary(format!("{}×{} twips ({}×{} px)", w, h, w / 20, h / 20)),
    );
    cx.emit(uint("Frame rate", body.sub(rect, 2), u16_le(&d, vidutil::us(rect)).unwrap_or(0).into(), 16)
        .summary(format!("{} fps", vidutil::num(rate))));
    cx.emit(uint("Frame count", body.sub(rect.saturating_add(2), 2), count.into(), 16));
    tags(cx, body.tail(len), 0).await
}

const MAX_SPRITE_DEPTH: u32 = 8;

async fn tags(cx: &Cx, span: Span, depth: u32) -> Result<()> {
    let mut pos = 0u64;
    let mut frame = 0u32;
    while pos < span.len {
        let d = cx.read_avail(span.sub(pos, 8)).await?;
        let Some(word) = u16_le(&d, 0) else {
            cx.emit(Node::new("Trailing bytes").span(span.tail(pos)));
            break;
        };
        let code = word >> 6;
        let (len, header) = match word & 0x3f {
            0x3f => (u64::from(u32_le(&d, 2).unwrap_or(0)), 6u64),
            n => (u64::from(n), 2u64),
        };
        let total = header.saturating_add(len);
        let tspan = span.sub(pos, total);
        let name = crate::value::lookup(TAGS, code.into())
            .map_or_else(|| format!("Tag {code}"), str::to_owned);
        let body = tspan.tail(header);
        let preview = cx.read_avail(body.sub(0, 16)).await?;
        let mut node = Node::new(name).span(tspan).value(Value::UInt {
            value: code.into(),
            bits: 10,
            radix: crate::value::Radix::Dec,
        });
        let mut summary = format!("{len} bytes");
        match code {
            1 => {
                summary = format!("frame {frame}");
                frame = frame.saturating_add(1);
            }
            9 => {
                if let Some(rgb) = preview.get(..3) {
                    summary = format!("#{:02x}{:02x}{:02x}", rgb.first().copied().unwrap_or(0), rgb.get(1).copied().unwrap_or(0), rgb.get(2).copied().unwrap_or(0));
                }
            }
            60 => {
                if let (Some(id), Some(n), Some(w), Some(h)) = (
                    u16_le(&preview, 0),
                    u16_le(&preview, 2),
                    u16_le(&preview, 4),
                    u16_le(&preview, 6),
                ) {
                    let codec = preview.get(9).copied().unwrap_or(0);
                    summary = format!(
                        "character {id}, {n} frames, {w}×{h}, {}",
                        vidutil::lookup_or(VIDEO_CODECS, codec.into())
                    );
                }
            }
            61 => {
                if let (Some(id), Some(f)) = (u16_le(&preview, 0), u16_le(&preview, 2)) {
                    summary = format!("stream {id}, frame {f}, {len} bytes");
                }
            }
            69 => {
                let flags = preview.first().copied().unwrap_or(0);
                let mut set = Vec::new();
                if flags & 0x08 != 0 {
                    set.push("ActionScript 3");
                }
                if flags & 0x10 != 0 {
                    set.push("metadata");
                }
                if flags & 0x01 != 0 {
                    set.push("network access");
                }
                summary = set.join(", ");
            }
            _ => {}
        }
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if tspan.len < total {
            node = node.diag(Diagnostic::truncated(Span::new(span.source, tspan.offset, total), tspan.len));
        }
        if code == 39 && depth < MAX_SPRITE_DEPTH {
            // DefineSprite: id, frame count, nested tags.
            node = node.lazy(crate::expander!(self::sprite: (Span, u32)), (body, depth.saturating_add(1)));
        } else if code == 77 {
            node = node.lazy(metadata, body);
        } else if !body.is_empty() {
            node = node.lazy(tag_data, body);
        }
        cx.push(node).await;
        pos = pos.saturating_add(total);
        if code == 0 && depth > 0 {
            break;
        }
    }
    Ok(())
}

async fn sprite(cx: Cx, (body, depth): (Span, u32)) -> Result<()> {
    let d = cx.read_avail(body.sub(0, 4)).await?;
    cx.emit(uint("Sprite ID", body.sub(0, 2), u16_le(&d, 0).unwrap_or(0).into(), 16));
    cx.emit(uint("Frame count", body.sub(2, 2), u16_le(&d, 2).unwrap_or(0).into(), 16));
    tags(&cx, body.tail(4), depth).await
}

async fn metadata(cx: Cx, body: Span) -> Result<()> {
    let d = vidutil::read_small(&cx, body, 0x10000).await?;
    cx.emit(vidutil::text("XMP", body, crate::text::until_nul(&d)));
    Ok(())
}

async fn tag_data(cx: Cx, body: Span) -> Result<()> {
    cx.emit(Node::new("Data").span(body).summary(format!("{} bytes", body.len)));
    Ok(())
}
