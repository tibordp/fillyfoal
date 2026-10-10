//! Illustration and paint-program files: Aseprite sprites, GEM bitmaps,
//! binary CGM and QuickDraw PICT metafiles, and palette/gradient/LUT text formats (JASC palettes, GIMP
//! gradients, Adobe/Resolve `.cube` colour lookup tables).

use crate::bytes::{to_u64, u16_be, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::probe;
use crate::formats::text::scan::Lines;
use crate::formats::util::val::{hex, int, text, uint};
use crate::formats::{Codec, Head, Input, Probe, content};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Aseprite

declare_format!(pub ASEPRITE = "aseprite", "Aseprite sprite", ["aseprite", "ase"], "image/x-aseprite",
    Probe::Custom(|h| h.at(4, b"\xe0\xa5") && u32_le(h.data, 0).is_some_and(|s| u64::from(s) <= h.len.saturating_add(16) && s >= 128)), aseprite);

record! {
    pub struct AseHeader {
        size: u32 "File size",
        magic: u16 "Magic" .hex(),
        frames: u16 "Frames",
        width: u16 "Width",
        height: u16 "Height",
        depth: u16 "Colour depth" .enumeration(&[(8, "indexed"), (16, "grayscale"), (32, "RGBA")]),
        flags: u32 "Flags" .hex(),
        speed: u16 "Speed (deprecated)",
        _zero1: u32 "Reserved",
        _zero2: u32 "Reserved",
        transparent: u8 "Transparent index",
        _ignore: bytes[3] "Reserved",
        colors: u16 "Colours",
        pixel_width: u8 "Pixel width",
        pixel_height: u8 "Pixel height",
        grid_x: i16 "Grid X",
        grid_y: i16 "Grid Y",
        grid_width: u16 "Grid width",
        grid_height: u16 "Grid height",
        _reserved: bytes[84] "Reserved",
    }
}

record! {
    pub struct AseFrame {
        size: u32 "Frame size",
        magic: u16 "Magic" .hex(),
        old_chunks: u16 "Chunks (old field)",
        duration: u16 "Duration (ms)",
        _reserved: bytes[2] "Reserved",
        chunks: u32 "Chunks",
    }
}

const ASE_CHUNKS: EnumTable = &[
    (0x0004, "Old palette"),
    (0x0011, "Old palette (64 colours)"),
    (0x2004, "Layer"),
    (0x2005, "Cel"),
    (0x2006, "Cel extra"),
    (0x2007, "Colour profile"),
    (0x2008, "External files"),
    (0x2016, "Mask"),
    (0x2017, "Path"),
    (0x2018, "Tags"),
    (0x2019, "Palette"),
    (0x2020, "User data"),
    (0x2022, "Slice"),
    (0x2023, "Tileset"),
];

fn ase_chunk_name(t: u16) -> &'static str {
    ASE_CHUNKS
        .iter()
        .find(|(k, _)| *k == u64::from(t))
        .map_or("Unknown chunk", |(_, v)| v)
}

#[derive(Clone, Copy, Debug)]
struct Sprite {
    input: Input,
    depth: u16,
}

async fn aseprite(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (h, span) = cur.record::<AseHeader>().await?;
    cx.emit(AseHeader::node("Header", span, LE));
    let sprite = Sprite {
        input,
        depth: h.depth,
    };
    for i in 0..h.frames {
        if cur.at_end() {
            break;
        }
        let start = cur.pos();
        let (f, _) = cur.record::<AseFrame>().await?;
        if f.magic != 0xf1fa || f.size < 16 {
            cx.emit(
                Node::new(format!("Frame {i}"))
                    .span(file.tail(start))
                    .diag(Diagnostic::malformed("bad frame magic or size")),
            );
            break;
        }
        let span = file.sub_exact(start, f.size.into())?;
        cur.seek(start.saturating_add(f.size.into()));
        let chunks = if f.chunks == 0 {
            u32::from(f.old_chunks)
        } else {
            f.chunks
        };
        cx.push(
            Node::new(format!("Frame {i}"))
                .span(span)
                .summary(format!("{} ms, {chunks} chunks", f.duration))
                .lazy(ase_frame, (span, chunks, sprite)),
        )
        .await;
    }
    cx.annotate(format!(
        "Aseprite sprite, {}×{}, {} frames, {}",
        h.width,
        h.height,
        h.frames,
        match h.depth {
            8 => "indexed",
            16 => "grayscale",
            _ => "RGBA",
        }
    ));
    Ok(())
}

async fn ase_frame(cx: Cx, (span, count, sprite): (Span, u32, Sprite)) -> Result<()> {
    cx.emit(AseFrame::node(
        "Frame header",
        span.sub(0, AseFrame::SIZE),
        LE,
    ));
    let mut cur = Cursor::new(&cx, span, LE);
    cur.seek(AseFrame::SIZE);
    let mut n = 0u32;
    while n < count && cur.remaining() >= 6 {
        let start = cur.pos();
        let size = cur.u32().await?;
        let kind = cur.u16().await?;
        if size < 6 {
            return Err(Diagnostic::malformed(format!("chunk size {size}")).at(cur.since(start)));
        }
        let chunk = span.sub_exact(start, size.into())?;
        cur.seek(start.saturating_add(size.into()));
        let body = chunk.tail(6);
        let mut node = Node::new(ase_chunk_name(kind))
            .span(chunk)
            .summary(format!("{size} bytes"));
        match kind {
            0x2004 => {
                let b = cx.read(body.sub(0, 18)).await?;
                let name_len = u64::from(u16_le(&b, 16).unwrap_or(0));
                let name = cx.read(body.sub(18, name_len.min(256))).await?;
                node = node
                    .value(text(String::from_utf8_lossy(&name)))
                    .summary(format!(
                        "{} layer, opacity {}",
                        match u16_le(&b, 2) {
                            Some(1) => "group",
                            Some(2) => "tilemap",
                            _ => "image",
                        },
                        b.get(12).copied().unwrap_or(0)
                    ));
            }
            0x2005 => node = node.lazy(ase_cel, (body, sprite)),
            0x2018 => node = node.lazy(ase_tags, body),
            0x2019 => node = node.lazy(ase_palette, body),
            _ => {}
        }
        cx.push(node).await;
        n = n.saturating_add(1);
    }
    Ok(())
}

const CEL_TYPES: EnumTable = &[
    (0, "raw image"),
    (1, "linked"),
    (2, "compressed image"),
    (3, "compressed tilemap"),
];

async fn ase_cel(cx: Cx, (body, sprite): (Span, Sprite)) -> Result<()> {
    let b = cx.read(body.sub_exact(0, 16)?).await?;
    let word = |i: usize| u16_le(&b, i).unwrap_or(0);
    let signed = |i: usize| i16::from_ne_bytes(word(i).to_ne_bytes());
    let kind = word(7);
    cx.emit(
        Node::new("Layer index")
            .span(body.sub(0, 2))
            .value(uint(word(0), 16)),
    );
    cx.emit(
        Node::new("Position")
            .span(body.sub(2, 4))
            .value(text(format!("{}, {}", signed(2), signed(4)))),
    );
    cx.emit(
        Node::new("Opacity")
            .span(body.sub(6, 1))
            .value(uint(b.get(6).copied().unwrap_or(0), 8)),
    );
    cx.emit(
        Node::new("Cel type")
            .span(body.sub(7, 2))
            .value(Value::Enum {
                raw: kind.into(),
                bits: 16,
                name: CEL_TYPES
                    .iter()
                    .find(|(k, _)| *k == u64::from(kind))
                    .map(|(_, v)| *v),
            }),
    );
    cx.emit(
        Node::new("Z-index")
            .span(body.sub(9, 2))
            .value(int(signed(9), 16)),
    );
    match kind {
        1 => cx.emit(Node::new("Linked frame").span(body.sub(16, 2)).value(uint(
            u16_le(&cx.read(body.sub(16, 2)).await?, 0).unwrap_or(0),
            16,
        ))),
        0 | 2 => {
            let wh = cx.read(body.sub_exact(16, 4)?).await?;
            let (w, h) = (u16_le(&wh, 0).unwrap_or(0), u16_le(&wh, 2).unwrap_or(0));
            cx.emit(
                Node::new("Size")
                    .span(body.sub(16, 4))
                    .value(text(format!("{w}×{h}"))),
            );
            let bpp = u64::from(sprite.depth / 8).max(1);
            let pixels = u64::from(w).saturating_mul(h.into()).saturating_mul(bpp);
            let data = body.tail(20);
            cx.emit(if kind == 2 {
                content("Pixels", sprite.input, data, Codec::Zlib, Some(pixels))
                    .summary(format!("zlib, {pixels} bytes decompressed"))
            } else {
                Node::new("Pixels")
                    .span(data)
                    .summary(format!("{pixels} bytes"))
            });
        }
        _ => cx.emit(Node::new("Tilemap").span(body.tail(16))),
    }
    Ok(())
}

async fn ase_string(cur: &mut Cursor<'_>) -> Result<String> {
    let n = cur.u16().await?;
    Ok(String::from_utf8_lossy(&cur.bytes(n.into()).await?).into_owned())
}

async fn ase_tags(cx: Cx, body: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, body, LE);
    let count = cur.u16().await?;
    cur.skip(8);
    for _ in 0..count {
        let start = cur.pos();
        let from = cur.u16().await?;
        let to = cur.u16().await?;
        let dir = cur.u8().await?;
        cur.skip(12);
        let name = ase_string(&mut cur).await?;
        let dir = match dir {
            0 => "forward",
            1 => "reverse",
            2 => "ping-pong",
            _ => "ping-pong reverse",
        };
        cx.push(
            Node::new(name)
                .span(cur.since(start))
                .value(text(format!("frames {from}-{to}")))
                .summary(dir),
        )
        .await;
    }
    Ok(())
}

async fn ase_palette(cx: Cx, body: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, body, LE);
    let _size = cur.u32().await?;
    let first = cur.u32().await?;
    let last = cur.u32().await?;
    cur.skip(8);
    for i in first..=last.min(first.saturating_add(65535)) {
        if cur.at_end() {
            break;
        }
        let start = cur.pos();
        let flags = cur.u16().await?;
        let c = cur.bytes(4).await?;
        let mut node = Node::new(format!("[{i}]"));
        if flags & 1 != 0 {
            node = node.summary(ase_string(&mut cur).await?);
        }
        let [r, g, b, a] = c
            .get(..4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .unwrap_or_default();
        cx.push(
            node.span(cur.since(start))
                .value(text(format!("#{r:02x}{g:02x}{b:02x}{a:02x}"))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GEM bitmap (IMG / XIMG)

fn gem_probe(h: &Head<'_>) -> bool {
    let w = |i: usize| u16_be(h.data, i);
    matches!(w(0), Some(1 | 2))
        && w(2).is_some_and(|l| (8..=64).contains(&l) && u64::from(l).saturating_mul(2) < h.len)
        && w(4).is_some_and(|p| matches!(p, 1 | 2 | 3 | 4 | 8 | 15 | 16 | 24 | 32))
        && w(6).is_some_and(|p| (1..=8).contains(&p))
        && w(12).is_some_and(|x| x > 0)
        && w(14).is_some_and(|y| y > 0)
        && (w(2) == Some(8) || w(2) == Some(9) || h.at(16, b"XIMG"))
}

declare_format!(pub GEM = "gem-img", "GEM bitmap image", ["img", "ximg"], "image/x-gem",
    Probe::Custom(gem_probe), gem);

async fn gem(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = cx.read(file.sub_exact(0, 16)?).await?;
    let w = |i: usize| u16_be(&h, i).unwrap_or(0);
    let words = u64::from(w(2));
    for (i, name) in [
        "Version",
        "Header length (words)",
        "Planes",
        "Pattern length",
        "Pixel width (µm)",
        "Pixel height (µm)",
        "Width",
        "Height",
    ]
    .iter()
    .enumerate()
    {
        let at = i.saturating_mul(2);
        cx.emit(
            Node::new(*name)
                .span(file.sub(to_u64(at), 2))
                .value(uint(w(at), 16)),
        );
    }
    let header = words.saturating_mul(2);
    if header > 16 {
        let ext = cx.read(file.sub(16, header.saturating_sub(16))).await?;
        let node = Node::new("Header extension").span(file.sub(16, header.saturating_sub(16)));
        cx.emit(if ext.starts_with(b"XIMG") {
            let model = u16_be(&ext, 4).unwrap_or(0);
            node.value(text("XIMG")).summary(format!(
                "colour model {}",
                match model {
                    0 => "RGB",
                    1 => "CMY",
                    2 => "HLS",
                    3 => "Pantone",
                    _ => "unknown",
                }
            ))
        } else {
            node
        });
    }
    cx.emit(
        Node::new("Compressed scan lines")
            .span(file.tail(header))
            .summary("pattern runs, solid runs, bit strings, vertical replication"),
    );
    cx.annotate(format!(
        "GEM bitmap{}, {}×{}, {} planes",
        if header > 16 { " (XIMG)" } else { "" },
        w(12),
        w(14),
        w(4)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Computer Graphics Metafile (binary encoding)

fn cgm_probe(h: &Head<'_>) -> bool {
    // BEGIN METAFILE (class 0, element 1) with a string parameter.
    u16_be(h.data, 0).is_some_and(|w| w >> 5 == 1 && (w & 0x1f) > 0)
        && h.data.get(2).is_some_and(|&n| {
            let len = usize::from(w0_len(h.data));
            usize::from(n) < len
                && h.data
                    .get(3..3usize.saturating_add(usize::from(n)))
                    .is_some_and(|s| s.iter().all(|b| b.is_ascii_graphic() || *b == b' '))
        })
}

fn w0_len(d: &[u8]) -> u16 {
    u16_be(d, 0).map_or(0, |w| w & 0x1f)
}

declare_format!(pub CGM = "cgm", "Computer Graphics Metafile (binary)", ["cgm"], "image/cgm",
    Probe::Custom(cgm_probe), cgm);

const CGM_NAMES: &[&[&str]] = &[
    &[
        "No-op",
        "BEGIN METAFILE",
        "END METAFILE",
        "BEGIN PICTURE",
        "BEGIN PICTURE BODY",
        "END PICTURE",
        "BEGIN SEGMENT",
        "END SEGMENT",
        "BEGIN FIGURE",
        "END FIGURE",
    ],
    &[
        "",
        "METAFILE VERSION",
        "METAFILE DESCRIPTION",
        "VDC TYPE",
        "INTEGER PRECISION",
        "REAL PRECISION",
        "INDEX PRECISION",
        "COLOUR PRECISION",
        "COLOUR INDEX PRECISION",
        "MAXIMUM COLOUR INDEX",
        "COLOUR VALUE EXTENT",
        "METAFILE ELEMENT LIST",
        "METAFILE DEFAULTS REPLACEMENT",
        "FONT LIST",
        "CHARACTER SET LIST",
        "CHARACTER CODING ANNOUNCER",
    ],
    &[
        "",
        "SCALING MODE",
        "COLOUR SELECTION MODE",
        "LINE WIDTH SPECIFICATION MODE",
        "MARKER SIZE SPECIFICATION MODE",
        "EDGE WIDTH SPECIFICATION MODE",
        "VDC EXTENT",
        "BACKGROUND COLOUR",
    ],
    &[
        "",
        "VDC INTEGER PRECISION",
        "VDC REAL PRECISION",
        "AUXILIARY COLOUR",
        "TRANSPARENCY",
        "CLIP RECTANGLE",
        "CLIP INDICATOR",
    ],
    &[
        "",
        "POLYLINE",
        "DISJOINT POLYLINE",
        "POLYMARKER",
        "TEXT",
        "RESTRICTED TEXT",
        "APPEND TEXT",
        "POLYGON",
        "POLYGON SET",
        "CELL ARRAY",
        "GENERALIZED DRAWING PRIMITIVE",
        "RECTANGLE",
        "CIRCLE",
        "CIRCULAR ARC 3 POINT",
        "CIRCULAR ARC 3 POINT CLOSE",
        "CIRCULAR ARC CENTRE",
        "CIRCULAR ARC CENTRE CLOSE",
        "ELLIPSE",
        "ELLIPTICAL ARC",
        "ELLIPTICAL ARC CLOSE",
    ],
    &[
        "",
        "LINE BUNDLE INDEX",
        "LINE TYPE",
        "LINE WIDTH",
        "LINE COLOUR",
        "MARKER BUNDLE INDEX",
        "MARKER TYPE",
        "MARKER SIZE",
        "MARKER COLOUR",
        "TEXT BUNDLE INDEX",
        "TEXT FONT INDEX",
        "TEXT PRECISION",
        "CHARACTER EXPANSION FACTOR",
        "CHARACTER SPACING",
        "TEXT COLOUR",
        "CHARACTER HEIGHT",
        "CHARACTER ORIENTATION",
        "TEXT PATH",
        "TEXT ALIGNMENT",
        "CHARACTER SET INDEX",
        "ALTERNATE CHARACTER SET INDEX",
        "FILL BUNDLE INDEX",
        "INTERIOR STYLE",
        "FILL COLOUR",
        "HATCH INDEX",
        "PATTERN INDEX",
        "EDGE BUNDLE INDEX",
        "EDGE TYPE",
        "EDGE WIDTH",
        "EDGE COLOUR",
        "EDGE VISIBILITY",
    ],
    &["", "ESCAPE"],
    &["", "MESSAGE", "APPLICATION DATA"],
];

fn cgm_name(class: u16, id: u16) -> String {
    CGM_NAMES
        .get(usize::from(class))
        .and_then(|c| c.get(usize::from(id)))
        .filter(|s| !s.is_empty())
        .map_or_else(
            || format!("Class {class} element {id}"),
            |s| (*s).to_owned(),
        )
}

/// One element: class, id, the span of the whole element (with padding)
/// and of its parameters.
async fn cgm_element(cur: &mut Cursor<'_>) -> Result<(u16, u16, Span, Span)> {
    let start = cur.pos();
    let w = cur.u16().await?;
    let (class, id) = (w >> 12, (w >> 5) & 0x7f);
    let mut len = u64::from(w & 0x1f);
    let mut params_at = cur.pos();
    if len == 31 {
        // Long form; partitions continue while bit 15 is set.
        let mut total = 0u64;
        loop {
            let l = cur.u16().await?;
            let n = u64::from(l & 0x7fff);
            if total == 0 {
                params_at = cur.pos();
            }
            cur.skip(n.saturating_add(n & 1));
            total = total.saturating_add(n);
            if l & 0x8000 == 0 || cur.at_end() {
                break;
            }
        }
        len = total;
    } else {
        cur.skip(len.saturating_add(len & 1));
    }
    if cur.pos() > cur.region().len {
        return Err(Diagnostic::truncated(
            cur.region().tail(start),
            cur.region().len.saturating_sub(start),
        ));
    }
    let region = cur.region();
    Ok((class, id, cur.since(start), region.sub(params_at, len)))
}

async fn cgm_string(cx: &Cx, params: Span) -> Result<Option<String>> {
    let d = cx.read(params.sub(0, 256)).await?;
    let n = usize::from(d.first().copied().unwrap_or(0));
    Ok(d.get(1..n.saturating_add(1))
        .map(|s| String::from_utf8_lossy(s).into_owned()))
}

async fn cgm_node(cx: &Cx, class: u16, id: u16, span: Span, params: Span) -> Result<Node> {
    let node = Node::new(cgm_name(class, id)).span(span);
    let string = matches!((class, id), (0, 1) | (0, 3) | (1, 2) | (7, 1));
    Ok(if string {
        match cgm_string(cx, params).await? {
            Some(s) => node.value(text(s)),
            None => node,
        }
    } else if (class, id) == (1, 1) {
        node.value(uint(
            u16_be(&cx.read(params.sub(0, 2)).await?, 0).unwrap_or(0),
            16,
        ))
    } else if (class, id) == (4, 4) && params.len > 7 {
        // TEXT: point (16-bit VDC), final flag, string.
        match cgm_string(cx, params.tail(6)).await? {
            Some(s) => node.value(text(s)),
            None => node,
        }
    } else if params.len > 0 {
        node.summary(format!("{} bytes", params.len))
    } else {
        node
    })
}

async fn cgm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let (mut pictures, mut name) = (0u32, String::new());
    while !cur.at_end() {
        let start = cur.pos();
        let (class, id, span, params) = cgm_element(&mut cur).await?;
        if (class, id) == (0, 3) {
            // A picture: up to END PICTURE.
            let title = cgm_string(&cx, params).await?.unwrap_or_default();
            loop {
                if cur.at_end() {
                    break;
                }
                let (c, i, _, _) = cgm_element(&mut cur).await?;
                if (c, i) == (0, 5) {
                    break;
                }
                cx.progress_in(file, file.offset.saturating_add(cur.pos()));
                cx.checkpoint().await;
            }
            pictures = pictures.saturating_add(1);
            let whole = cur.since(start);
            cx.progress_in(file, file.offset.saturating_add(cur.pos()));
            cx.push(
                Node::new(format!("Picture {pictures}"))
                    .span(whole)
                    .value(text(title))
                    .lazy(cgm_elements, whole),
            )
            .await;
            continue;
        }
        let node = cgm_node(&cx, class, id, span, params).await?;
        if (class, id) == (0, 1) {
            name = cgm_string(&cx, params).await?.unwrap_or_default();
        }
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        cx.push(node).await;
        if (class, id) == (0, 2) {
            if !cur.at_end() {
                cx.emit(Node::new("Trailing data").span(file.tail(cur.pos())));
            }
            break;
        }
    }
    cx.annotate(format!("CGM metafile {name:?}, {pictures} pictures"));
    Ok(())
}

async fn cgm_elements(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    while !cur.at_end() {
        let (class, id, s, params) = cgm_element(&mut cur).await?;
        let node = cgm_node(&cx, class, id, s, params).await?;
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// QuickDraw PICT

/// Offset of the picture (0 or 512, after the application header) and
/// whether it is version 2.
fn pict_start(h: &Head<'_>) -> Option<(u64, bool)> {
    [512usize, 0].into_iter().find_map(|at| {
        let v = at.checked_add(10)?;
        if h.at(v, b"\x00\x11\x02\xff\x0c\x00") {
            Some((to_u64(at), true))
        } else if h.at(v, b"\x11\x01") && h.data.get(v.checked_add(2)?).is_some_and(|&op| op < 0xa2)
        {
            Some((to_u64(at), false))
        } else {
            None
        }
    })
}

declare_format!(pub PICT = "pict", "QuickDraw picture (PICT)", ["pict", "pct", "pic"], "image/x-pict",
    Probe::Custom(|h| pict_start(h).is_some()), pict);

/// Opcodes with fixed data lengths (version 2).
fn pict_fixed(op: u16) -> Option<(u64, &'static str)> {
    Some(match op {
        0x0000 => (0, "NOP"),
        0x0002 => (8, "BkPat"),
        0x0003 => (2, "TxFont"),
        0x0004 => (1, "TxFace"),
        0x0005 => (2, "TxMode"),
        0x0006 => (4, "SpExtra"),
        0x0007 => (4, "PnSize"),
        0x0008 => (2, "PnMode"),
        0x0009 => (8, "PnPat"),
        0x000a => (8, "FillPat"),
        0x000b => (4, "OvSize"),
        0x000c => (4, "Origin"),
        0x000d => (2, "TxSize"),
        0x000e => (4, "FgColor"),
        0x000f => (4, "BkColor"),
        0x0010 => (8, "TxRatio"),
        0x0011 => (2, "VersionOp"),
        0x0015 => (2, "PnLocHFrac"),
        0x0016 => (2, "ChExtra"),
        0x001a => (6, "RGBFgCol"),
        0x001b => (6, "RGBBkCol"),
        0x001c => (0, "HiliteMode"),
        0x001d => (6, "HiliteColor"),
        0x001e => (0, "DefHilite"),
        0x001f => (6, "OpColor"),
        0x0020 => (8, "Line"),
        0x0021 => (4, "LineFrom"),
        0x0022 => (6, "ShortLine"),
        0x0023 => (2, "ShortLineFrom"),
        0x0030 => (8, "frameRect"),
        0x0031 => (8, "paintRect"),
        0x0032 => (8, "eraseRect"),
        0x0033 => (8, "invertRect"),
        0x0034 => (8, "fillRect"),
        0x0038..=0x003c => (0, "sameRect"),
        0x0040..=0x0044 => (8, "RRect"),
        0x0048..=0x004c => (0, "sameRRect"),
        0x0050..=0x0054 => (8, "Oval"),
        0x0058..=0x005c => (0, "sameOval"),
        0x0060..=0x0064 => (12, "Arc"),
        0x0068..=0x006c => (4, "sameArc"),
        0x00a0 => (2, "ShortComment"),
        0x00ff => (0, "OpEndPic"),
        0x0c00 => (24, "HeaderOp"),
        _ => return None,
    })
}

async fn pict(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x220)).await?;
    let probe_head = Head {
        data: &head,
        tail: &[],
        len: file.len,
        len_known: true,
    };
    let (at, v2) = pict_start(&probe_head)
        .ok_or_else(|| Diagnostic::malformed("no PICT version opcode").at(file.sub(0, 0x220)))?;
    if at > 0 {
        cx.emit(Node::new("Application header").span(file.sub(0, 512)));
    }
    let h = cx.read(file.sub_exact(at, 10)?).await?;
    let w = |i: usize| i16::from_ne_bytes(u16_be(&h, i).unwrap_or(0).to_ne_bytes());
    cx.emit(
        Node::new("Size (low 16 bits)")
            .span(file.sub(at, 2))
            .value(uint(u16_be(&h, 0).unwrap_or(0), 16)),
    );
    let (top, left, bottom, right) = (w(2), w(4), w(6), w(8));
    cx.emit(
        Node::new("Frame")
            .span(file.sub(at.saturating_add(2), 8))
            .value(text(format!("({left}, {top})–({right}, {bottom})"))),
    );
    let width = i32::from(right).saturating_sub(left.into());
    let height = i32::from(bottom).saturating_sub(top.into());
    if !v2 {
        cx.emit(
            Node::new("Version")
                .span(file.sub(at.saturating_add(10), 2))
                .value(uint(1u8, 8)),
        );
        cx.emit(
            Node::new("Opcodes")
                .span(file.tail(at.saturating_add(12)))
                .diag(Diagnostic::unsupported("version 1 opcodes")),
        );
        cx.annotate(format!("QuickDraw PICT v1, {width}×{height}"));
        return Ok(());
    }
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(at.saturating_add(10));
    let mut n = 0u32;
    while !cur.at_end() {
        let start = cur.pos();
        // Version 2 opcodes are word-aligned.
        if start & 1 == 1 {
            cur.skip(1);
            continue;
        }
        let op = cur.u16().await?;
        n = n.saturating_add(1);
        let (len, name): (u64, String) = if let Some((len, name)) = pict_fixed(op) {
            (len, name.to_owned())
        } else {
            match op {
                0x0001 | 0x0070..=0x0084 | 0x002c | 0x002e => {
                    let l = u64::from(u16_be(&cx.read(cur.span(2)).await?, 0).unwrap_or(0));
                    let name = match op {
                        0x0001 => "Clip",
                        0x002c => "fontName",
                        0x002e => "glyphState",
                        0x0070..=0x007f => "Poly",
                        _ => "Rgn",
                    };
                    // Clip, polygon and region sizes include the size word.
                    (
                        if op == 0x002c || op == 0x002e {
                            l.saturating_add(2)
                        } else {
                            l
                        },
                        name.to_owned(),
                    )
                }
                0x0028 => {
                    let t = cx.read(cur.span(5)).await?;
                    (
                        5u64.saturating_add(t.get(4).copied().unwrap_or(0).into()),
                        "LongText".to_owned(),
                    )
                }
                0x0029 | 0x002a => {
                    let t = cx.read(cur.span(2)).await?;
                    (
                        2u64.saturating_add(t.get(1).copied().unwrap_or(0).into()),
                        if op == 0x29 {
                            "DHText".to_owned()
                        } else {
                            "DVText".to_owned()
                        },
                    )
                }
                0x002b => {
                    let t = cx.read(cur.span(3)).await?;
                    (
                        3u64.saturating_add(t.get(2).copied().unwrap_or(0).into()),
                        "DHDVText".to_owned(),
                    )
                }
                0x00a1 => {
                    let t = cx.read(cur.span(4)).await?;
                    (
                        4u64.saturating_add(u16_be(&t, 2).unwrap_or(0).into()),
                        "LongComment".to_owned(),
                    )
                }
                0x0100..=0x7fff => (
                    u64::from(op >> 8).saturating_mul(2),
                    format!("Reserved {op:#06x}"),
                ),
                0x8000..=0x80ff => (0, format!("Reserved {op:#06x}")),
                0x8100..=0xffff => {
                    let t = cx.read(cur.span(4)).await?;
                    let l = u64::from(u32::from_be_bytes(
                        t.get(..4)
                            .and_then(|s| s.try_into().ok())
                            .unwrap_or_default(),
                    ));
                    (
                        l.saturating_add(4),
                        if op == 0x8200 {
                            "CompressedQuickTime".to_owned()
                        } else {
                            format!("Reserved {op:#06x}")
                        },
                    )
                }
                _ => {
                    // Bitmap opcodes (0x90, 0x91, 0x98, 0x99, 0x9a, 0x9b) need a
                    // pixel map walk to find their end.
                    cx.push(
                        Node::new(format!("Opcode {op:#06x}"))
                            .span(file.tail(start))
                            .diag(Diagnostic::unsupported("pixel map opcodes")),
                    )
                    .await;
                    break;
                }
            }
        };
        cur.skip(len);
        if cur.pos() > file.len {
            return Err(Diagnostic::truncated(
                file.tail(start),
                file.len.saturating_sub(start),
            ));
        }
        let span = cur.since(start);
        let node = Node::new(name).span(span).value(hex(op, 16));
        let node = if op == 0x0c00 {
            node.lazy(pict_header, span.tail(2))
        } else {
            node
        };
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        cx.push(node).await;
        if op == 0x00ff {
            break;
        }
    }
    cx.annotate(format!("QuickDraw PICT v2, {width}×{height}, {n} opcodes"));
    Ok(())
}

async fn pict_header(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read(span).await?;
    let version = i16::from_ne_bytes(u16_be(&d, 0).unwrap_or(0).to_ne_bytes());
    cx.emit(
        Node::new("Version")
            .span(span.sub(0, 2))
            .value(int(version, 16))
            .summary(if version == -2 {
                "extended"
            } else {
                "standard"
            }),
    );
    if version == -2 {
        let fixed = |i: usize| {
            f64::from(u32::from_be_bytes(
                d.get(i..i.saturating_add(4))
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or_default(),
            )) / 65536.0
        };
        cx.emit(
            Node::new("Horizontal resolution")
                .span(span.sub(4, 4))
                .value(Value::Float(fixed(4)))
                .summary("dpi"),
        );
        cx.emit(
            Node::new("Vertical resolution")
                .span(span.sub(8, 4))
                .value(Value::Float(fixed(8)))
                .summary("dpi"),
        );
        let s = |i: usize| u16_be(&d, i).unwrap_or(0);
        cx.emit(
            Node::new("Source rectangle")
                .span(span.sub(12, 8))
                .value(text(format!(
                    "({}, {})–({}, {})",
                    s(14),
                    s(12),
                    s(18),
                    s(16)
                ))),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Text palettes, gradients and LUTs

declare_format!(pub JASC_PAL = "jasc-palette", "JASC (Paint Shop Pro) palette", ["pal", "psppalette"], "application/x-jasc-palette",
    Probe::Custom(|h| h.starts_with(b"JASC-PAL\r\n") || h.starts_with(b"JASC-PAL\n")), jasc);

async fn jasc(cx: Cx, input: Input) -> Result<()> {
    let mut lines = Lines::new(&cx, input.span);
    let mut n = 0u32;
    let mut declared = String::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        match line.number {
            1 => {
                cx.push(Node::new("Signature").span(line.span).value(text(t)))
                    .await
            }
            2 => {
                cx.push(Node::new("Version").span(line.span).value(text(t)))
                    .await
            }
            3 => {
                declared = t.trim().to_owned();
                cx.push(Node::new("Colours").span(line.span).value(text(t.trim())))
                    .await;
            }
            _ if line.is_blank() => {}
            _ => {
                let c: Vec<u8> = t
                    .split_whitespace()
                    .filter_map(|v| v.parse().ok())
                    .collect();
                let node = Node::new(format!("[{n}]")).span(line.span);
                cx.push(match c.as_slice() {
                    [r, g, b, ..] => node.value(text(format!("#{r:02x}{g:02x}{b:02x}"))),
                    _ => node
                        .value(text(t))
                        .diag(Diagnostic::malformed("expected three components")),
                })
                .await;
                n = n.saturating_add(1);
            }
        }
    }
    cx.annotate(format!("JASC palette, {declared} colours"));
    Ok(())
}

declare_format!(pub GGR = "gimp-gradient", "GIMP gradient", ["ggr"], "application/x-gimp-gradient",
    Probe::Custom(|h| h.starts_with(b"GIMP Gradient\n") || h.starts_with(b"GIMP Gradient\r\n")), ggr);

const GGR_BLEND: &[&str] = &[
    "linear",
    "curved",
    "sine",
    "sphere increasing",
    "sphere decreasing",
    "step",
];
const GGR_COLOR: &[&str] = &["RGB", "HSV counter-clockwise", "HSV clockwise"];

async fn ggr(cx: Cx, input: Input) -> Result<()> {
    let mut lines = Lines::new(&cx, input.span);
    let (mut name, mut n) = (String::new(), 0u32);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if line.number == 1 {
            cx.push(Node::new("Signature").span(line.span)).await;
        } else if let Some(v) = t.strip_prefix("Name: ") {
            name = v.to_owned();
            cx.push(Node::new("Name").span(line.span).value(text(v)))
                .await;
        } else if line.number <= 3 && t.trim().parse::<u32>().is_ok() {
            cx.push(Node::new("Segments").span(line.span).value(text(t.trim())))
                .await;
        } else if !line.is_blank() {
            let v: Vec<f64> = t
                .split_whitespace()
                .filter_map(|x| x.parse().ok())
                .collect();
            let node = Node::new(format!("Segment {n}")).span(line.span);
            cx.push(match v.as_slice() {
                [l, m, r, lr, lg, lb, la, rr, rg, rb, ra, rest @ ..] => {
                    let blend = rest
                        .first()
                        .and_then(|&b| GGR_BLEND.get(b as usize))
                        .copied()
                        .unwrap_or("linear");
                    let color = rest
                        .get(1)
                        .and_then(|&c| GGR_COLOR.get(c as usize))
                        .copied()
                        .unwrap_or("RGB");
                    let hexc = |r: f64, g: f64, b: f64, a: f64| {
                        format!(
                            "#{:02x}{:02x}{:02x}{:02x}",
                            (r.clamp(0.0, 1.0) * 255.0).round() as u8,
                            (g.clamp(0.0, 1.0) * 255.0).round() as u8,
                            (b.clamp(0.0, 1.0) * 255.0).round() as u8,
                            (a.clamp(0.0, 1.0) * 255.0).round() as u8
                        )
                    };
                    node.value(text(format!(
                        "{l:.3}–{r:.3} (mid {m:.3}): {} → {}",
                        hexc(*lr, *lg, *lb, *la),
                        hexc(*rr, *rg, *rb, *ra)
                    )))
                    .summary(format!("{blend}, {color}"))
                }
                _ => node
                    .value(text(t))
                    .diag(Diagnostic::malformed("expected at least 11 numbers")),
            })
            .await;
            n = n.saturating_add(1);
        }
    }
    cx.annotate(format!("GIMP gradient {name:?}, {n} segments"));
    Ok(())
}

fn cube_probe(h: &Head<'_>) -> bool {
    let head = h.data.get(..8192).unwrap_or(h.data);
    probe::is_text(h)
        && probe::significant(head, &[b"#"])
            .take(8)
            .any(|l| l.starts_with(b"LUT_3D_SIZE") || l.starts_with(b"LUT_1D_SIZE"))
}

declare_format!(pub CUBE = "cube-lut", "Colour lookup table (.cube)", ["cube"], "application/x-cube-lut",
    Probe::Custom(cube_probe), cube);

async fn cube(cx: Cx, input: Input) -> Result<()> {
    let mut lines = Lines::new(&cx, input.span);
    let (mut title, mut size, mut kind) = (String::new(), String::new(), "3D");
    let mut table_start = None;
    let mut entries = 0u64;
    let mut last = input.span.len;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if t.is_empty() || t.starts_with('#') {
            if t.starts_with('#') && table_start.is_none() {
                cx.push(
                    Node::new("Comment")
                        .span(line.span)
                        .value(text(t.trim_start_matches('#').trim())),
                )
                .await;
            }
            continue;
        }
        let first = t.as_bytes().first().copied().unwrap_or(0);
        if first.is_ascii_alphabetic() {
            let (k, v) = t.split_once(char::is_whitespace).unwrap_or((t, ""));
            match k {
                "TITLE" => title = v.trim().trim_matches('"').to_owned(),
                "LUT_3D_SIZE" => size = v.trim().to_owned(),
                "LUT_1D_SIZE" => {
                    size = v.trim().to_owned();
                    kind = "1D";
                }
                _ => {}
            }
            cx.push(
                Node::new(k.to_owned())
                    .span(line.span)
                    .value(text(v.trim().trim_matches('"'))),
            )
            .await;
            continue;
        }
        if table_start.is_none() {
            table_start = Some(line.start);
        }
        entries = entries.saturating_add(1);
        last = line.next;
    }
    if let Some(start) = table_start {
        let span = input.span.sub(start, last.saturating_sub(start));
        cx.push(
            Node::new("Table")
                .span(span)
                .summary(format!("{entries} entries"))
                .lazy(cube_rows, span),
        )
        .await;
    }
    cx.annotate(format!(
        "{kind} colour LUT{}, size {size}, {entries} entries",
        if title.is_empty() {
            String::new()
        } else {
            format!(" {title:?}")
        }
    ));
    Ok(())
}

async fn cube_rows(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut i = 0u64;
    while let Some(line) = lines.next().await? {
        if line.is_blank() || line.bytes.first() == Some(&b'#') {
            continue;
        }
        cx.push(
            Node::new(format!("[{i}]"))
                .span(line.span)
                .value(text(line.text().trim())),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}
