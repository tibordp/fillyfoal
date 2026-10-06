//! Adobe Flash movies (`.swf`).
//!
//! An 8-byte header (`FWS` uncompressed, `CWS` zlib, `ZWS` LZMA; version;
//! uncompressed length) precedes the body: the frame size as a bit-packed
//! RECT, frame rate and count, then tagged records. Compressed bodies are
//! decompressed when expanded.

use crate::bytes::{to_u64, u16_le};
use crate::codec::{Codec, decode_span};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::datakit::{clip, size};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const MAX_SPRITE_DEPTH: u32 = 16;

pub static FORMAT: Format = Format {
    name: "swf",
    title: "Adobe Flash movie",
    extensions: &["swf"],
    mime: "application/x-shockwave-flash",
    probe: Probe::Magic(&[(0, b"FWS"), (0, b"CWS"), (0, b"ZWS")]),
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

const FILE_ATTRIBUTES: FlagTable = &[
    flag(0x01, "UseNetwork"),
    flag(0x08, "ActionScript3"),
    flag(0x10, "HasMetadata"),
    flag(0x20, "UseGPU"),
    flag(0x40, "UseDirectBlit"),
];

/// MSB-first bit reader for RECT records.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn take(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = *self.data.get(self.pos / 8)?;
            let bit = (byte << (self.pos % 8)) >> 7;
            v = v.checked_shl(1)? | u32::from(bit);
            self.pos = self.pos.saturating_add(1);
        }
        Some(v)
    }

    fn signed(&mut self, n: u32) -> Option<i32> {
        let v = self.take(n)?;
        if n == 0 {
            return Some(0);
        }
        let shift = 32u32.saturating_sub(n);
        Some(((v << shift) as i32) >> shift)
    }
}

/// `Xmin, Xmax, Ymin, Ymax` in twips and the RECT's byte length.
fn rect(data: &[u8]) -> Option<([i32; 4], u64)> {
    let mut b = Bits { data, pos: 0 };
    let n = b.take(5)?;
    let v = [b.signed(n)?, b.signed(n)?, b.signed(n)?, b.signed(n)?];
    Some((v, to_u64(b.pos.div_ceil(8))))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let sig = f.ascii("Signature", 3).emit()?;
    let version = f.u8("Version").emit()?;
    let length = f
        .u32("File length")
        .desc("Uncompressed length of the whole file")
        .emit()?;
    let body = file.tail(8);
    match sig.as_str() {
        "FWS" => {
            let summary = body_fields(&cx, input, body).await?;
            cx.annotate(format!("Flash movie v{version}, {summary}"));
        }
        "CWS" => {
            cx.annotate(format!(
                "Flash movie v{version}, zlib-compressed, {} uncompressed",
                size(length.into())
            ));
            cx.emit(
                Node::new("Compressed body")
                    .span(body)
                    .summary(format!("zlib, {} bytes", body.len))
                    .lazy(
                        compressed,
                        (input, body, u64::from(length).saturating_sub(8), Codec::Zlib),
                    ),
            );
        }
        _ => {
            cx.annotate(format!("Flash movie v{version}, LZMA-compressed"));
            // A 4-byte compressed length and the 5 LZMA properties bytes,
            // then raw LZMA with a known size (the file length less 8).
            let block = cx.block(body.sub(0, 9)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            f.u32("Compressed length").emit()?;
            let props = f.bytes("LZMA properties", 5).emit()?;
            let stream = body.tail(9);
            let expected = u64::from(length).saturating_sub(8);
            let node = Node::new("Compressed body").span(stream);
            cx.emit(match crate::codec::lzma::Props::from_byte(props.first().copied().unwrap_or(0xff)) {
                Ok(props) => {
                    let codec = Codec::LzmaRaw {
                        props,
                        size: Some(crate::bytes::to_usize(expected)),
                    };
                    node.summary(format!("LZMA, {} bytes", stream.len))
                        .lazy(compressed, (input, stream, expected, codec))
                }
                Err(e) => node.diag(e.at(body.sub(4, 1))),
            });
        }
    }
    Ok(())
}

async fn compressed(cx: Cx, (input, body, expected, codec): (Input, Span, u64, Codec)) -> Result<()> {
    let decoded = decode_span(&cx, body, &codec, Some(expected)).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    let summary = body_fields(&cx, input, decoded.span).await?;
    cx.annotate(summary);
    Ok(())
}

/// Emits the movie header (frame size, rate, count) and the tags.
async fn body_fields(cx: &Cx, input: Input, body: Span) -> Result<String> {
    let head = cx.read_avail(body.sub(0, 17)).await?;
    let (r, rect_len) =
        rect(&head).ok_or_else(|| Diagnostic::truncated(body.sub(0, 17), to_u64(head.len())))?;
    let width = r[1].saturating_sub(r[0]) / 20;
    let height = r[3].saturating_sub(r[2]) / 20;
    let rect_span = body.sub(0, rect_len);
    let node = Node::new("Frame size")
        .span(rect_span)
        .summary(format!("{width}×{height} px"))
        .desc("RECT in twips (1/20 px)");
    cx.emit(node.lazy(rect_fields, (rect_span, r)));
    let rest = cx.read(body.sub(rect_len, 4)).await?;
    let rate = u16_le(&rest, 0).unwrap_or(0);
    let frames = u16_le(&rest, 2).unwrap_or(0);
    cx.emit(
        Node::new("Frame rate")
            .span(body.sub(rect_len, 2))
            .value(Value::Float(f64::from(rate) / 256.0))
            .summary("8.8 fixed point, frames per second"),
    );
    cx.emit(
        Node::new("Frame count")
            .span(body.sub(rect_len.saturating_add(2), 2))
            .value(Value::UInt {
                value: frames.into(),
                bits: 16,
                radix: crate::value::Radix::Dec,
            }),
    );
    let tags = body.tail(rect_len.saturating_add(4));
    cx.emit(Node::new("Tags").span(tags).lazy(
        crate::expander!(self::tag_list: (Input, Span, u32)),
        (input, tags, 0u32),
    ));
    Ok(format!(
        "{width}×{height}, {} fps, {frames} frames",
        f64::from(rate) / 256.0
    ))
}

async fn rect_fields(cx: Cx, (span, r): (Span, [i32; 4])) -> Result<()> {
    let nbits = cx.read(span.sub(0, 1)).await?.first().copied().unwrap_or(0) >> 3;
    cx.emit(Node::new("Nbits").value(Value::UInt {
        value: nbits.into(),
        bits: 5,
        radix: crate::value::Radix::Dec,
    }));
    for (name, v) in ["Xmin", "Xmax", "Ymin", "Ymax"].into_iter().zip(r) {
        cx.emit(
            Node::new(name)
                .value(Value::Int {
                    value: v.into(),
                    bits: 32,
                })
                .summary(format!("{} px", f64::from(v) / 20.0)),
        );
    }
    Ok(())
}

async fn tag_list(cx: Cx, (input, span, depth): (Input, Span, u32)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let mut frame = 0u32;
    while cur.remaining() >= 2 {
        let start = cur.pos();
        let code_len = cur.u16().await?;
        let code = code_len >> 6;
        let mut len = u64::from(code_len & 0x3f);
        if len == 0x3f {
            len = cur.u32().await?.into();
        }
        let body = cur.span(len);
        cur.skip(len);
        let tag = cur.since(start);
        let name = lookup(TAGS, code.into()).map_or_else(|| format!("Tag {code}"), str::to_owned);
        let mut node = Node::new(name).span(tag).summary(format!("{len} bytes"));
        if body.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(body.source, body.offset, len),
                body.len,
            ));
        }
        if code == 1 {
            node = node.summary(format!("frame {frame}"));
            frame = frame.saturating_add(1);
        } else if len > 0 {
            node = node.lazy(
                crate::expander!(self::tag: (Input, Span, u16, u32)),
                (input, body, code, depth),
            );
        }
        cx.push(node).await;
        if code == 0 {
            break;
        }
    }
    Ok(())
}

async fn tag(cx: Cx, (input, body, code, depth): (Input, Span, u16, u32)) -> Result<()> {
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    match code {
        9 => {
            f.bytes("Background colour", 3)
                .with(|b, n| {
                    n.value(Value::Text(format!(
                        "#{}",
                        crate::formats::datakit::hex_string(b)
                    )))
                })
                .emit()?;
        }
        69 => {
            f.u32("Flags").flags(FILE_ATTRIBUTES).emit()?;
        }
        77 => {
            let n = f.remaining();
            f.ascii("XML", n).emit()?;
        }
        43 => {
            f.cstr("Label").emit()?;
        }
        65 => {
            f.u16("Max recursion depth").emit()?;
            f.u16("Script timeout (s)").emit()?;
        }
        56 | 76 => {
            let n = f.u16("Count").emit()?;
            for _ in 0..n {
                let id = f.u16("Character ID").get()?;
                let name = f.cstr("Name").get()?;
                cx.emit(Node::new(clip(&name, 120)).value(Value::UInt {
                    value: id.into(),
                    bits: 16,
                    radix: crate::value::Radix::Dec,
                }));
            }
        }
        87 => {
            f.u16("Character ID").emit()?;
            f.u32("Reserved").emit()?;
            cx.emit(
                embedded("Data", input.nested(body.tail(6)))
                    .summary(format!("{} bytes", body.len.saturating_sub(6))),
            );
        }
        6 | 21 => {
            f.u16("Character ID").emit()?;
            cx.emit(embedded("Image", input.nested(body.tail(2))));
        }
        35 | 90 => {
            f.u16("Character ID").emit()?;
            let alpha = f.u32("Alpha data offset").emit()?;
            if code == 90 {
                f.u16("Deblock parameter").emit()?;
            }
            let at = f.pos();
            cx.emit(embedded("Image", input.nested(body.sub(at, alpha.into()))));
            cx.emit(
                Node::new("Alpha data (zlib)").span(body.tail(at.saturating_add(alpha.into()))),
            );
        }
        82 => {
            f.u32("Flags").hex().desc("1 = lazy initialize").emit()?;
            f.cstr("Name").emit()?;
            let at = f.pos();
            cx.emit(
                Node::new("ABC bytecode")
                    .span(body.tail(at))
                    .summary(format!("{} bytes", body.len.saturating_sub(at))),
            );
        }
        41 => {
            f.u32("Product ID").emit()?;
            f.u32("Edition").emit()?;
            f.u8("Major version").emit()?;
            f.u8("Minor version").emit()?;
            f.u64("Build number").emit()?;
            f.u64("Compilation date")
                .with(|&ms, n| {
                    n.value(Value::Timestamp {
                        unix_seconds: i64::try_from(ms / 1000).unwrap_or(0),
                    })
                })
                .emit()?;
        }
        39 => {
            f.u16("Sprite ID").emit()?;
            f.u16("Frame count").emit()?;
            let tags = body.tail(4);
            if depth < MAX_SPRITE_DEPTH {
                cx.emit(Node::new("Tags").span(tags).lazy(
                    crate::expander!(self::tag_list: (Input, Span, u32)),
                    (input, tags, depth.saturating_add(1)),
                ));
            } else {
                cx.emit(
                    Node::new("Tags")
                        .span(tags)
                        .diag(Diagnostic::limit("sprites nested too deeply")),
                );
            }
        }
        _ => {
            f.node(
                Node::new("Data")
                    .span(body)
                    .summary(format!("{} bytes", body.len)),
            );
        }
    }
    Ok(())
}
