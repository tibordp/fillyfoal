//! PNG, APNG and MNG/JNG-style chunk streams.
//!
//! The file is a signature followed by chunks `length, type, data, crc`. The
//! top level lists chunks (paged), with a summary of each; expanding one
//! decodes its fields and checks its CRC. Runs of `IDAT` chunks (and of APNG
//! `fdAT` chunks) are grouped: together they hold one zlib stream, shown
//! decompressed as scanlines with their filter types.

use crate::bytes::{i32_be, u16_be, u32_be};
use crate::codec::crc::crc32_update;
use crate::codec::{Codec, decode_span, inflate_span};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::fmt::{count, plural};
use crate::formats::util::val::{text, uint};
use crate::formats::util::vidutil::{
    COLOUR_PRIMARIES, MATRIX_COEFFICIENTS, TRANSFER_CHARACTERISTICS, lookup_or,
};
use crate::formats::{Format, Input, Probe, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::text::latin1;
use crate::value::{EnumTable, Value, lookup};

use super::{ColorOrder, dims, palette, playing_time};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "png",
    title: "Portable Network Graphics",
    extensions: &["png", "apng"],
    mime: "image/png",
    probe: Probe::Magic(&[(0, b"\x89PNG\r\n\x1a\n")]),
    dissect: crate::expander!(dissect: Input),
};

pub static MNG: Format = Format {
    name: "mng",
    title: "Multiple-image Network Graphics",
    extensions: &["mng"],
    mime: "video/x-mng",
    probe: Probe::Magic(&[(0, b"\x8aMNG\r\n\x1a\n")]),
    dissect: crate::expander!(dissect: Input),
};

pub static JNG: Format = Format {
    name: "jng",
    title: "JPEG Network Graphics",
    extensions: &["jng"],
    mime: "image/x-jng",
    probe: Probe::Magic(&[(0, b"\x8bJNG\r\n\x1a\n")]),
    dissect: crate::expander!(dissect: Input),
};

type Kind = [u8; 4];

const COLOR_TYPE: EnumTable = &[
    (0, "Grayscale"),
    (2, "RGB"),
    (3, "Indexed"),
    (4, "Grayscale + alpha"),
    (6, "RGBA"),
];

const COMPRESSION: EnumTable = &[(0, "deflate")];
const FILTER_METHOD: EnumTable = &[(0, "adaptive (five filter types)")];
const INTERLACE: EnumTable = &[(0, "None"), (1, "Adam7")];
const FILTER_TYPE: EnumTable = &[
    (0, "None"),
    (1, "Sub"),
    (2, "Up"),
    (3, "Average"),
    (4, "Paeth"),
];

const UNIT: EnumTable = &[(0, "unknown (aspect ratio only)"), (1, "metre")];
const OFFSET_UNIT: EnumTable = &[(0, "pixel"), (1, "micrometre")];
const SCAL_UNIT: EnumTable = &[(1, "metre"), (2, "radian")];
const STEREO_MODE: EnumTable = &[(0, "cross-fuse layout"), (1, "diverging-fuse layout")];
const PCAL_EQUATION: EnumTable = &[
    (0, "linear"),
    (1, "base-e exponential"),
    (2, "arbitrary-base exponential"),
    (3, "hyperbolic"),
];

const RENDERING_INTENT: EnumTable = &[
    (0, "Perceptual"),
    (1, "Relative colorimetric"),
    (2, "Saturation"),
    (3, "Absolute colorimetric"),
];

const DISPOSE: EnumTable = &[(0, "none"), (1, "background"), (2, "previous")];
const BLEND: EnumTable = &[(0, "source"), (1, "over")];

const ZLIB_LEVEL: EnumTable = &[(0, "fastest"), (1, "fast"), (2, "default"), (3, "maximum")];

/// Decompressed image data larger than this is decoded on demand.
const LAZY_THRESHOLD: u64 = 1 << 20;
/// How much of a chunk the top-level summaries look at.
const PEEK: u64 = 128;
/// Longest text shown as a value.
const MAX_TEXT: u64 = 1 << 20;
/// Longest keyword (79 bytes) plus its terminator.
const KEYWORD: u64 = 80;

const XMP_KEYWORD: &str = "XML:com.adobe.xmp";

/// What the chunks of an image need to know about it (from `IHDR`, `CgBI`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Image {
    width: u32,
    height: u32,
    depth: u8,
    color: u8,
    interlace: u8,
    /// Apple's iOS variant: raw deflate, BGRA, premultiplied alpha.
    cgbi: bool,
}

/// Adam7 passes: first column, first row, column step, row step.
const ADAM7: [(u64, u64, u64, u64); 7] = [
    (0, 0, 8, 8),
    (4, 0, 8, 8),
    (0, 4, 4, 8),
    (2, 0, 4, 4),
    (0, 2, 2, 4),
    (1, 0, 2, 2),
    (0, 1, 1, 2),
];

impl Image {
    fn parse(d: &[u8]) -> Option<Image> {
        Some(Image {
            width: u32_be(d, 0)?,
            height: u32_be(d, 4)?,
            depth: *d.get(8)?,
            color: *d.get(9)?,
            interlace: d.get(12).copied().unwrap_or(0),
            cgbi: false,
        })
    }

    fn channels(&self) -> u64 {
        match self.color {
            0 | 3 => 1,
            4 => 2,
            2 => 3,
            6 => 4,
            _ => 0,
        }
    }

    /// Whether the bit depth is allowed for the color type.
    fn valid_depth(&self) -> bool {
        match self.color {
            0 => matches!(self.depth, 1 | 2 | 4 | 8 | 16),
            3 => matches!(self.depth, 1 | 2 | 4 | 8),
            2 | 4 | 6 => matches!(self.depth, 8 | 16),
            _ => false,
        }
    }

    /// Bytes per row of `width` pixels, without the filter byte.
    fn row_bytes(&self, width: u64) -> u64 {
        let bits = width
            .saturating_mul(self.channels())
            .saturating_mul(self.depth.into());
        bits.saturating_add(7) / 8
    }

    /// The dimensions of Adam7 pass `pass` of a `width×height` image.
    fn pass_dims(width: u64, height: u64, pass: (u64, u64, u64, u64)) -> (u64, u64) {
        let (x0, y0, dx, dy) = pass;
        let count = |n: u64, start: u64, step: u64| {
            n.checked_sub(start).map_or(0, |left| {
                left.saturating_add(step.saturating_sub(1))
                    .checked_div(step)
                    .unwrap_or(0)
            })
        };
        (count(width, x0, dx), count(height, y0, dy))
    }

    /// Size of the filtered scanlines of a `width×height` image (each row
    /// starts with a filter-type byte; an interlaced image has seven passes).
    fn raw_size(&self, width: u64, height: u64) -> u64 {
        if self.interlace == 1 {
            ADAM7.iter().fold(0u64, |total, &pass| {
                let (w, h) = Image::pass_dims(width, height, pass);
                if w == 0 || h == 0 {
                    return total;
                }
                total.saturating_add(h.saturating_mul(self.row_bytes(w).saturating_add(1)))
            })
        } else {
            height.saturating_mul(self.row_bytes(width).saturating_add(1))
        }
    }

    fn color_name(&self) -> String {
        lookup(COLOR_TYPE, self.color.into())
            .map_or_else(|| format!("color type {}", self.color), str::to_owned)
    }

    /// "640×480, 8-bit RGBA, interlaced".
    fn describe(&self) -> String {
        let mut out = format!(
            "{}, {}-bit {}",
            dims(self.width, self.height),
            self.depth,
            self.color_name()
        );
        if self.interlace == 1 {
            out.push_str(", interlaced");
        }
        out
    }
}

/// The animation, as far as the walker has seen it.
#[derive(Clone, Copy, Debug, Default)]
struct Animation {
    declared: Option<u32>,
    plays: u32,
    frames: u64,
    seconds: f64,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, BE);
    let signature = cur.span(8);
    cx.emit(
        Node::new("Signature")
            .span(signature)
            .desc("A high-bit byte, the name, CR LF, EOF (^Z) and LF: catches 7-bit and newline-converting transfers"),
    );
    cur.skip(8);
    let mut image = Image::default();
    let mut headline: Option<String> = None;
    let mut animation = Animation::default();
    // The frame the next fdAT chunks belong to (index, width, height).
    let mut frame: Option<(u64, u32, u32)> = None;
    let mut ended = false;
    while !cur.at_end() {
        let start = cur.pos();
        let header = cur.bytes(8).await?;
        let len = u64::from(u32_be(&header, 0).unwrap_or(0));
        let kind: Kind = crate::bytes::array::<4>(&header, 4).unwrap_or_default();
        let total = len.saturating_add(12);
        let span = input.span.sub(start, total);
        cx.progress_in(input.span, span.end());

        if &kind == b"IDAT" || &kind == b"fdAT" {
            let (group, count) = run(&cx, input.span, start, &kind).await?;
            let (index, width, height) = match (&kind, frame) {
                (b"fdAT", Some(f)) => f,
                (b"IDAT", Some((0, w, h))) => (0, w, h),
                _ => (u64::MAX, image.width, image.height),
            };
            let raw = image.raw_size(width.into(), height.into());
            let (what, overhead) = if &kind == b"IDAT" {
                ("IDAT chunk", 12)
            } else {
                ("fdAT chunk", 16)
            };
            let compressed = group.len.saturating_sub(count.saturating_mul(overhead));
            let mut summary = format!(
                "{}, {} compressed → {} of scanlines",
                plural(count, what),
                human_size(compressed),
                human_size(raw)
            );
            if index != u64::MAX {
                summary = format!("frame {index}: {summary}");
            }
            let name = if &kind == b"IDAT" {
                "Image data"
            } else {
                "Frame data"
            };
            cx.push(
                Node::new(name)
                    .span(group)
                    .summary(summary)
                    .desc("Consecutive data chunks: together they hold one compressed stream")
                    .lazy(
                        image_data,
                        Group {
                            input,
                            span: group,
                            kind,
                            image,
                            width,
                            height,
                        },
                    ),
            )
            .await;
            cur.seek(start.saturating_add(group.len));
            frame = None;
            continue;
        }

        let data = span.sub(8, len);
        let peek = cx.read_avail(data.sub(0, PEEK)).await?;
        let mut summary = summarize(&kind, &peek, len, &image);
        match &kind {
            b"IHDR" => {
                if let Some(parsed) = Image::parse(&peek) {
                    image = Image {
                        cgbi: image.cgbi,
                        ..parsed
                    };
                    if headline.is_none() {
                        let mut line = image.describe();
                        if image.cgbi {
                            line.push_str(", Apple CgBI");
                        }
                        cx.annotate(line.clone());
                        headline = Some(line);
                    }
                }
            }
            b"MHDR" | b"JHDR" if headline.is_none() => {
                if let Some(s) = &summary {
                    cx.annotate(s.clone());
                    headline = Some(s.clone());
                }
            }
            b"CgBI" => image.cgbi = true,
            b"acTL" => {
                animation.declared = u32_be(&peek, 0);
                animation.plays = u32_be(&peek, 4).unwrap_or(0);
            }
            b"fcTL" => {
                let index = animation.frames;
                if let Some(fc) = Fctl::parse(&peek) {
                    frame = Some((index, fc.width, fc.height));
                    animation.seconds += fc.seconds();
                    summary = Some(format!("frame {index}: {}", fc.describe()));
                }
                animation.frames = animation.frames.saturating_add(1);
            }
            b"eXIf" => {
                if let Some(camera) = super::tiff::camera(&cx, input.nested(data)).await {
                    summary = Some(format!("Exif, {camera}"));
                }
            }
            _ => {}
        }
        let mut node = Node::new(crate::formats::util::sound::fourcc(&kind))
            .span(span)
            .summary(summary.unwrap_or_else(|| human_size(len)));
        if let Some(d) = describe_kind(&kind) {
            node = node.desc(d);
        }
        if span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, total),
                span.len,
            ));
        }
        cx.push(node.lazy(
            chunk,
            ChunkState {
                input,
                span,
                kind,
                image,
            },
        ))
        .await;
        cur.seek(start.saturating_add(total));
        if &kind == b"IEND" || &kind == b"MEND" {
            ended = true;
            break;
        }
    }
    if !ended {
        cx.diag(Diagnostic::warning("no IEND chunk: the file is truncated"));
    }
    if animation.declared.is_some() || animation.frames > 0 {
        let mut line = headline.unwrap_or_default();
        let frames = animation.declared.map_or(animation.frames, u64::from);
        line.push_str(&format!(
            ", APNG, {}, {}",
            plural(frames, "frame"),
            playing_time(animation.seconds)
        ));
        line.push_str(&match animation.plays {
            0 => ", loops forever".to_owned(),
            1 => String::new(),
            n => format!(", plays {n} times"),
        });
        cx.annotate(line);
        if let Some(declared) = animation.declared
            && u64::from(declared) != animation.frames
        {
            cx.diag(Diagnostic::warning(format!(
                "acTL declares {declared} frames, {} fcTL chunks found",
                animation.frames
            )));
        }
    }
    if !cur.at_end() {
        let rest = input.span.tail(cur.pos());
        cx.emit(
            embedded("Trailing data", input.nested(rest))
                .summary(format!("{} after the end chunk", human_size(rest.len))),
        );
    }
    Ok(())
}

/// The run of consecutive `kind` chunks starting at `start`: its span and
/// the number of chunks.
async fn run(cx: &Cx, file: Span, start: u64, kind: &Kind) -> Result<(Span, u64)> {
    let mut pos = start;
    let mut count = 0u64;
    loop {
        let head = cx.read_avail(file.sub(pos, 8)).await?;
        if head.get(4..8) != Some(kind.as_slice()) {
            break;
        }
        let len = u64::from(u32_be(&head, 0).unwrap_or(0));
        let total = len.saturating_add(12);
        count = count.saturating_add(1);
        pos = pos.saturating_add(total);
        if pos >= file.len {
            break;
        }
    }
    let end = pos.min(file.len);
    Ok((file.sub(start, end.saturating_sub(start)), count))
}

/// One-line summaries for the top-level list, from the first [`PEEK`]
/// bytes of a chunk's data.
fn summarize(kind: &Kind, d: &[u8], len: u64, image: &Image) -> Option<String> {
    let at = |i: usize| d.get(i).copied();
    let u16_at = |i: usize| u16_be(d, i);
    let u32_at = |i: usize| u32_be(d, i);
    Some(match kind {
        b"IHDR" => Image::parse(d)?.describe(),
        b"PLTE" => plural(len / 3, "color"),
        b"tRNS" => match image.color {
            0 => format!("gray {} is transparent", u16_at(0)?),
            2 => format!(
                "RGB ({}, {}, {}) is transparent",
                u16_at(0)?,
                u16_at(2)?,
                u16_at(4)?
            ),
            3 => format!(
                "alpha for {}",
                count(len, "palette entry", "palette entries")
            ),
            _ => return None,
        },
        b"gAMA" => gamma(u32_at(0)?),
        b"cHRM" => format!(
            "white point ({}, {})",
            chromaticity(u32_at(0)?),
            chromaticity(u32_at(4)?)
        ),
        b"sRGB" => format!(
            "sRGB, {} intent",
            lookup(RENDERING_INTENT, at(0)?.into()).unwrap_or("unknown")
        ),
        b"iCCP" => format!("\"{}\"", latin1(cut(d).0)),
        b"cICP" => {
            let mut out = format!(
                "{}, {}",
                lookup_or(COLOUR_PRIMARIES, at(0)?.into()),
                lookup_or(TRANSFER_CHARACTERISTICS, at(1)?.into())
            );
            out.push_str(if at(3)? == 1 {
                ", full range"
            } else {
                ", narrow range"
            });
            out
        }
        b"mDCV" | b"mDCv" => format!(
            "max {} cd/m², min {} cd/m²",
            luminance(u32_at(16)?),
            luminance(u32_at(20)?)
        ),
        b"cLLI" | b"cLLi" => format!(
            "MaxCLL {} cd/m², MaxFALL {} cd/m²",
            luminance(u32_at(0)?),
            luminance(u32_at(4)?)
        ),
        b"sBIT" => {
            let bits: Vec<String> = d.iter().take(4).map(u8::to_string).collect();
            format!("significant bits {}", bits.join(", "))
        }
        b"bKGD" => match image.color {
            3 => format!("palette index {}", at(0)?),
            0 | 4 => format!("gray {}", u16_at(0)?),
            2 | 6 => format!("RGB ({}, {}, {})", u16_at(0)?, u16_at(2)?, u16_at(4)?),
            _ => return None,
        },
        b"hIST" => count(len / 2, "frequency", "frequencies"),
        b"pHYs" => {
            let (x, y) = (u32_at(0)?, u32_at(4)?);
            if at(8)? == 1 {
                let dpi = |v: u32| f64::from(v) * 0.0254;
                if x == y {
                    format!("{:.0} dpi", dpi(x))
                } else {
                    format!("{:.0}×{:.0} dpi", dpi(x), dpi(y))
                }
            } else {
                format!("aspect ratio {x}:{y}")
            }
        }
        b"sPLT" => {
            let (name, rest) = cut(d);
            let depth = *rest.first()?;
            let entry = if depth == 16 { 10 } else { 6 };
            let entries = len
                .saturating_sub(crate::bytes::to_u64(name.len()).saturating_add(2))
                .checked_div(entry)
                .unwrap_or(0);
            format!(
                "\"{}\", {}, {depth}-bit",
                latin1(name),
                count(entries, "entry", "entries")
            )
        }
        b"tIME" => time(d)?,
        b"tEXt" => {
            let (keyword, rest) = cut(d);
            let keyword = latin1(keyword);
            if keyword == XMP_KEYWORD {
                return Some("XMP metadata".to_owned());
            }
            if keyword.starts_with("Raw profile type ") {
                return Some(keyword);
            }
            format!("{keyword}: {}", clip(&latin1(rest), 60))
        }
        b"zTXt" => {
            let keyword = latin1(cut(d).0);
            if keyword.starts_with("Raw profile type ") || keyword == XMP_KEYWORD {
                return Some(keyword);
            }
            format!("{keyword} (compressed)")
        }
        b"iTXt" => {
            let (keyword, rest) = cut(d);
            let keyword = latin1(keyword);
            if keyword == XMP_KEYWORD {
                return Some("XMP metadata".to_owned());
            }
            if *rest.first()? != 0 {
                return Some(format!("{keyword} (compressed)"));
            }
            // Skip compression flag and method, language and translated keyword.
            let (_, rest) = cut(rest.get(2..)?);
            let (_, rest) = cut(rest);
            format!("{keyword}: {}", clip(&String::from_utf8_lossy(rest), 60))
        }
        b"eXIf" => match d.get(..2)? {
            b"MM" => "Exif, big-endian".to_owned(),
            b"II" => "Exif, little-endian".to_owned(),
            _ => "Exif".to_owned(),
        },
        b"acTL" => {
            let frames = u32_at(0)?;
            let plays = match u32_at(4)? {
                0 => "loops forever".to_owned(),
                1 => "plays once".to_owned(),
                n => format!("plays {n} times"),
            };
            format!("{}, {plays}", plural(frames, "frame"))
        }
        b"CgBI" => "Apple iOS-optimized: BGRA, premultiplied alpha, raw deflate".to_owned(),
        b"oFFs" => format!(
            "offset ({}, {}) {}",
            i32_be(d, 0)?,
            i32_be(d, 4)?,
            lookup(OFFSET_UNIT, at(8)?.into()).unwrap_or("?")
        ),
        b"sCAL" => {
            let unit = lookup(SCAL_UNIT, at(0)?.into()).unwrap_or("?");
            let (width, height) = cut(d.get(1..)?);
            format!("pixel {} × {} {unit}", latin1(width), latin1(height))
        }
        b"sTER" => lookup(STEREO_MODE, at(0)?.into())?.to_owned(),
        b"pCAL" => format!("\"{}\"", latin1(cut(d).0)),
        b"gIFg" => format!("GIF delay {} ms", u32::from(u16_at(2)?).saturating_mul(10)),
        b"MHDR" => format!(
            "MNG {}, {} ticks/s",
            dims(u32_at(0)?, u32_at(4)?),
            u32_at(8)?
        ),
        b"JHDR" => format!("JNG {}, {}-bit", dims(u32_at(0)?, u32_at(4)?), at(9)?),
        b"IEND" | b"MEND" => "end of image".to_owned(),
        _ => return None,
    })
}

/// Splits `d` at its first NUL: the bytes before it, and those after it
/// (empty if there is none).
fn cut(d: &[u8]) -> (&[u8], &[u8]) {
    match d.iter().position(|&b| b == 0) {
        Some(n) => (
            d.get(..n).unwrap_or_default(),
            d.get(n.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (d, &[]),
    }
}

fn clip(s: &str, max: usize) -> String {
    let line = s.lines().next().unwrap_or_default();
    if line.chars().count() > max || line.len() < s.len() {
        let mut out: String = line.chars().take(max).collect();
        out.push('…');
        out
    } else {
        line.to_owned()
    }
}

/// `gAMA`: the image gamma times 100000 (e.g. 45455 for 1/2.2).
fn gamma(v: u32) -> String {
    let g = f64::from(v) / 100_000.0;
    if v == 0 {
        "0 (invalid)".to_owned()
    } else {
        format!("{g:.5} (decoding exponent {:.2})", 1.0 / g)
    }
}

/// A `cHRM` chromaticity: the value times 100000.
fn chromaticity(v: u32) -> String {
    format!("{:.4}", f64::from(v) / 100_000.0)
}

/// A luminance in units of 0.0001 cd/m².
fn luminance(v: u32) -> String {
    let nits = f64::from(v) / 10_000.0;
    let s = format!("{nits:.4}");
    s.trim_end_matches('0').trim_end_matches('.').to_owned()
}

/// `tIME`: year (2 bytes), month, day, hour, minute, second (UTC).
fn time(d: &[u8]) -> Option<String> {
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        u16_be(d, 0)?,
        d.get(2)?,
        d.get(3)?,
        d.get(4)?,
        d.get(5)?,
        d.get(6)?
    ))
}

/// APNG frame control.
#[derive(Clone, Copy, Debug, Default)]
struct Fctl {
    width: u32,
    height: u32,
    x: u32,
    y: u32,
    delay_num: u16,
    delay_den: u16,
    dispose: u8,
    blend: u8,
}

impl Fctl {
    fn parse(d: &[u8]) -> Option<Fctl> {
        Some(Fctl {
            width: u32_be(d, 4)?,
            height: u32_be(d, 8)?,
            x: u32_be(d, 12)?,
            y: u32_be(d, 16)?,
            delay_num: u16_be(d, 20)?,
            delay_den: u16_be(d, 22)?,
            dispose: *d.get(24)?,
            blend: *d.get(25)?,
        })
    }

    /// The delay in seconds (a denominator of 0 means 1/100 s).
    fn seconds(&self) -> f64 {
        let den = if self.delay_den == 0 {
            100
        } else {
            self.delay_den
        };
        f64::from(self.delay_num) / f64::from(den)
    }

    fn describe(&self) -> String {
        format!(
            "{} at ({}, {}), {}, dispose {}, blend {}",
            dims(self.width, self.height),
            self.x,
            self.y,
            delay(self.seconds()),
            lookup(DISPOSE, self.dispose.into()).unwrap_or("?"),
            lookup(BLEND, self.blend.into()).unwrap_or("?")
        )
    }
}

fn delay(seconds: f64) -> String {
    let ms = seconds * 1000.0;
    if (ms - ms.round()).abs() < 1e-9 {
        format!("{ms:.0} ms")
    } else {
        format!("{ms:.2} ms")
    }
}

/// A short description of well-known chunk types.
fn describe_kind(kind: &Kind) -> Option<&'static str> {
    Some(match kind {
        b"IHDR" => "Image header",
        b"PLTE" => "Palette",
        b"IDAT" => "Image data",
        b"IEND" => "Image trailer",
        b"tRNS" => "Transparency",
        b"gAMA" => "Image gamma",
        b"cHRM" => "Primary chromaticities and white point",
        b"sRGB" => "Standard RGB color space",
        b"iCCP" => "Embedded ICC profile",
        b"cICP" => "Coding-independent code points (ITU-T H.273 color description)",
        b"mDCV" | b"mDCv" => "Mastering display color volume (SMPTE ST 2086)",
        b"cLLI" | b"cLLi" => "Content light level information (CTA-861.3)",
        b"sBIT" => "Significant bits per channel",
        b"bKGD" => "Background color",
        b"hIST" => "Palette histogram",
        b"pHYs" => "Physical pixel dimensions",
        b"sPLT" => "Suggested palette",
        b"tIME" => "Last modification time",
        b"tEXt" => "Latin-1 text",
        b"zTXt" => "Compressed Latin-1 text",
        b"iTXt" => "International (UTF-8) text",
        b"eXIf" => "Exif metadata (a TIFF stream)",
        b"acTL" => "APNG animation control",
        b"fcTL" => "APNG frame control",
        b"fdAT" => "APNG frame data",
        b"CgBI" => {
            "Apple CgBI: the image is stored for iOS (BGRA, premultiplied alpha, deflate without zlib header)"
        }
        b"oFFs" => "Image offset (extension)",
        b"pCAL" => "Pixel calibration (extension)",
        b"sCAL" => "Physical scale (extension)",
        b"sTER" => "Stereo image indicator (extension)",
        b"gIFg" => "GIF graphic control extension (extension)",
        b"gIFx" => "GIF application extension (extension)",
        b"gIFt" => "GIF plain text extension (deprecated)",
        b"dSIG" => "Digital signature (extension)",
        b"iDOT" => "Apple: offsets for decoding the image data in parallel",
        b"caBX" => "C2PA content credentials (JUMBF)",
        b"vpAg" => "ImageMagick virtual page",
        b"orNT" => "Orientation",
        b"MHDR" => "MNG header",
        b"MEND" => "MNG trailer",
        b"JHDR" => "JNG header",
        b"JDAT" => "JNG JPEG data",
        b"JDAA" => "JNG alpha as JPEG",
        b"JSEP" => "JNG separator between 8- and 12-bit data",
        _ => return None,
    })
}

const KNOWN: &[&Kind] = &[
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"cICP",
    b"mDCV", b"mDCv", b"cLLI", b"cLLi", b"sBIT", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"tIME",
    b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"acTL", b"fcTL", b"fdAT", b"CgBI", b"oFFs", b"pCAL",
    b"sCAL", b"sTER", b"gIFg", b"gIFx", b"gIFt", b"dSIG", b"iDOT", b"caBX", b"vpAg", b"orNT",
    b"MHDR", b"MEND", b"JHDR", b"JDAT", b"JDAA", b"JSEP",
];

/// The property bits of a chunk type: bit 5 (lowercase) of each letter.
fn property_bits(kind: &Kind) -> u8 {
    kind.iter()
        .fold(0u8, |acc, &b| acc.wrapping_mul(2) | u8::from(b & 0x20 != 0))
}

fn property_summary(bits: u8) -> String {
    format!(
        "{}, {}, {}",
        if bits & 8 != 0 {
            "ancillary"
        } else {
            "critical"
        },
        if bits & 4 != 0 { "private" } else { "public" },
        if bits & 1 != 0 {
            "safe to copy"
        } else {
            "unsafe to copy"
        }
    )
}

#[derive(Clone, Debug)]
struct ChunkState {
    input: Input,
    span: Span,
    kind: Kind,
    image: Image,
}

async fn chunk(cx: Cx, st: ChunkState) -> Result<()> {
    let ChunkState {
        input,
        span,
        kind,
        image,
    } = st;
    let header = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &header, BE);
    let declared = u64::from(f.u32("Length").desc("Size of the data").emit()?);
    let bits = property_bits(&kind);
    f.ascii("Type", 4)
        .summary(property_summary(bits))
        .desc(
            "Bit 5 (lowercase) of each letter is a property: first = ancillary (a decoder \
             may ignore the chunk), second = private (not registered), third = reserved \
             (must be uppercase), fourth = safe to copy (an editor that changed critical \
             chunks may keep it)",
        )
        .check(|_| {
            (bits & 2 != 0).then(|| {
                Diagnostic::warning("the third letter must be uppercase (reserved bit)")
            })
        })
        .check(|_| {
            (!KNOWN.contains(&&kind)).then(|| {
                Diagnostic::note(if bits & 8 != 0 {
                    "unknown ancillary chunk: decoders may ignore it"
                } else {
                    "unknown critical chunk: a decoder cannot display the image without understanding it"
                })
            })
        })
        .emit()?;

    let data = span.sub(8, declared);
    match &kind {
        b"IHDR" => {
            fields(&cx, data, &image, ihdr).await?;
        }
        b"PLTE" => {
            let mut node = palette("Palette", data, ColorOrder::Rgb);
            if data.len % 3 != 0 || data.len > 768 || data.len == 0 {
                node = node.diag(Diagnostic::warning(
                    "PLTE must hold 1 to 256 entries of 3 bytes",
                ));
            }
            cx.emit(node);
        }
        b"tRNS" => match image.color {
            0 | 2 => fields(&cx, data, &image, trns).await?,
            3 => cx.emit(values(
                "Alpha values",
                data,
                1,
                ("alpha value", "alpha values"),
            )),
            _ => cx.emit(Node::new("Data").span(data).diag(Diagnostic::warning(
                "tRNS is not allowed for a color type with alpha",
            ))),
        },
        b"gAMA" => fields(&cx, data, &image, gama).await?,
        b"cHRM" => fields(&cx, data, &image, chrm).await?,
        b"sRGB" => fields(&cx, data, &image, srgb).await?,
        b"iCCP" => {
            let (name, at) = cx.cstr(data.sub(0, KEYWORD)).await?;
            cx.emit(Node::new("Profile name").span(at).value(text(name)));
            let method = data.sub(at.len, 1);
            let m = cx.block(method).await?;
            Fields::emitting(&cx, &m, BE)
                .u8("Compression method")
                .enumeration(COMPRESSION)
                .emit()?;
            let compressed = data.tail(at.len.saturating_add(1));
            cx.emit(crate::formats::content(
                "ICC profile",
                input,
                compressed,
                Codec::Zlib,
                None,
            ));
        }
        b"cICP" => fields(&cx, data, &image, cicp).await?,
        b"mDCV" | b"mDCv" => fields(&cx, data, &image, mdcv).await?,
        b"cLLI" | b"cLLi" => fields(&cx, data, &image, clli).await?,
        b"sBIT" => fields(&cx, data, &image, sbit).await?,
        b"bKGD" => fields(&cx, data, &image, bkgd).await?,
        b"hIST" => cx.emit(values("Frequencies", data, 2, ("frequency", "frequencies"))),
        b"pHYs" => fields(&cx, data, &image, phys).await?,
        b"sPLT" => suggested_palette(&cx, data).await?,
        b"tIME" => fields(&cx, data, &image, time_fields).await?,
        b"tEXt" => text_chunk(&cx, input, data, false).await?,
        b"zTXt" => text_chunk(&cx, input, data, true).await?,
        b"iTXt" => international_text(&cx, input, data).await?,
        b"eXIf" => cx.emit(embedded_as(
            "Exif",
            input.nested(data),
            &super::tiff::FORMAT,
        )),
        b"acTL" => fields(&cx, data, &image, actl).await?,
        b"fcTL" => fields(&cx, data, &image, fctl).await?,
        b"fdAT" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(&cx, &block, BE)
                .u32("Sequence number")
                .emit()?;
            cx.emit(
                Node::new("Frame data")
                    .span(data.tail(4))
                    .desc("Part of the frame's zlib stream (decompressed under the group)"),
            );
        }
        b"IDAT" => cx.emit(
            Node::new("Data")
                .span(data)
                .desc("Part of the image's zlib stream (decompressed under the group)"),
        ),
        b"CgBI" => fields(&cx, data, &image, cgbi).await?,
        b"oFFs" => fields(&cx, data, &image, offs).await?,
        b"sCAL" => fields(&cx, data, &image, scal).await?,
        b"sTER" => fields(&cx, data, &image, ster).await?,
        b"pCAL" => fields(&cx, data, &image, pcal).await?,
        b"gIFg" => fields(&cx, data, &image, gifg).await?,
        b"gIFx" => {
            let block = cx.block(data.sub(0, 11)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            f.ascii("Application identifier", 8).emit()?;
            f.ascii("Authentication code", 3).emit()?;
            cx.emit(Node::new("Application data").span(data.tail(11)));
        }
        b"MHDR" => fields(&cx, data, &image, mhdr).await?,
        b"JHDR" => fields(&cx, data, &image, jhdr).await?,
        b"JDAT" | b"JDAA" => cx.emit(embedded("JPEG stream", input.nested(data))),
        b"IEND" | b"MEND" => {}
        _ => cx.emit(Node::new("Data").span(data)),
    }

    let crc_span = span.sub(declared.saturating_add(8), 4);
    if crc_span.len < 4 {
        return Ok(());
    }
    let stored = cx.read(crc_span).await?;
    let stored = u32_be(&stored, 0).unwrap_or(0);
    let mut node = Node::new("CRC")
        .span(crc_span)
        .value(Value::UInt {
            value: stored.into(),
            bits: 32,
            radix: crate::value::Radix::Hex,
        })
        .desc("CRC-32 of the type and data");
    let covered = span.sub(4, declared.saturating_add(4));
    if covered.len <= cx.limits().max_read {
        let bytes = cx.read(covered).await?;
        // In budgeted pieces: a chunk can be as large as a read.
        let mut register = u32::MAX;
        for (i, piece) in bytes.chunks(1 << 16).enumerate() {
            if i > 0 {
                cx.checkpoint().await;
            }
            register = crc32_update(register, piece);
        }
        let computed = !register;
        node = if computed == stored {
            node.summary("valid")
        } else {
            node.diag(Diagnostic::warning(format!(
                "CRC mismatch: computed {computed:#010x}"
            )))
        };
    }
    cx.emit(node);
    Ok(())
}

/// Emits the fields of a small fixed structure in `data`.
async fn fields(
    cx: &Cx,
    data: Span,
    image: &Image,
    layout: fn(&mut Fields<'_>, &Image) -> Result<()>,
) -> Result<()> {
    let block = cx.block(data.sub(0, 4096)).await?;
    layout(&mut Fields::emitting(cx, &block, BE), image)
}

fn ihdr(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u32("Width").check(nonzero).emit()?;
    f.u32("Height").check(nonzero).emit()?;
    let depth = f
        .u8("Bit depth")
        .desc("Bits per sample (per palette index for indexed images)")
        .emit()?;
    let color = f
        .u8("Color type")
        .enumeration(COLOR_TYPE)
        .desc("Bit 0: palette, bit 1: color, bit 2: alpha")
        .emit()?;
    let image = Image {
        depth,
        color,
        ..Image::default()
    };
    if !image.valid_depth() {
        f.node(
            Node::new("Bit depth / color type")
                .summary(format!("{depth}-bit {}", image.color_name()))
                .diag(Diagnostic::warning(
                    "this bit depth is not allowed for the color type",
                )),
        );
    }
    f.u8("Compression method").enumeration(COMPRESSION).emit()?;
    f.u8("Filter method").enumeration(FILTER_METHOD).emit()?;
    f.u8("Interlace method").enumeration(INTERLACE).emit()?;
    Ok(())
}

fn nonzero(v: &u32) -> Option<Diagnostic> {
    (*v == 0).then(|| Diagnostic::warning("must not be zero"))
}

fn trns(f: &mut Fields<'_>, image: &Image) -> Result<()> {
    if image.color == 0 {
        f.u16("Transparent gray").emit()?;
    } else {
        f.u16("Transparent red").emit()?;
        f.u16("Transparent green").emit()?;
        f.u16("Transparent blue").emit()?;
    }
    Ok(())
}

fn gama(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u32("Gamma")
        .with(|&v, n| n.summary(gamma(v)))
        .desc("Encoding gamma times 100000 (45455 means 1/2.2)")
        .emit()?;
    Ok(())
}

fn chrm(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    for name in [
        "White point x",
        "White point y",
        "Red x",
        "Red y",
        "Green x",
        "Green y",
        "Blue x",
        "Blue y",
    ] {
        f.u32(name)
            .with(|&v, n| n.summary(chromaticity(v)))
            .desc("CIE 1931 chromaticity times 100000")
            .emit()?;
    }
    Ok(())
}

fn srgb(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u8("Rendering intent")
        .enumeration(RENDERING_INTENT)
        .emit()?;
    Ok(())
}

fn cicp(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u8("Colour primaries")
        .enumeration(COLOUR_PRIMARIES)
        .emit()?;
    f.u8("Transfer characteristics")
        .enumeration(TRANSFER_CHARACTERISTICS)
        .emit()?;
    f.u8("Matrix coefficients")
        .enumeration(MATRIX_COEFFICIENTS)
        .check(|&v| (v != 0).then(|| Diagnostic::warning("PNG requires 0 (RGB)")))
        .emit()?;
    f.u8("Video full range flag")
        .with(|&v, n| n.summary(if v == 1 { "full range" } else { "narrow range" }))
        .emit()?;
    Ok(())
}

fn mdcv(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    for name in [
        "Red x",
        "Red y",
        "Green x",
        "Green y",
        "Blue x",
        "Blue y",
        "White point x",
        "White point y",
    ] {
        f.u16(name)
            .with(|&v, n| n.summary(format!("{:.5}", f64::from(v) * 0.00002)))
            .desc("Chromaticity in units of 0.00002")
            .emit()?;
    }
    f.u32("Maximum luminance")
        .with(|&v, n| n.summary(format!("{} cd/m²", luminance(v))))
        .desc("In units of 0.0001 cd/m²")
        .emit()?;
    f.u32("Minimum luminance")
        .with(|&v, n| n.summary(format!("{} cd/m²", luminance(v))))
        .desc("In units of 0.0001 cd/m²")
        .emit()?;
    Ok(())
}

fn clli(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u32("Maximum content light level")
        .with(|&v, n| n.summary(format!("{} cd/m²", luminance(v))))
        .desc("MaxCLL: brightest pixel, in units of 0.0001 cd/m²")
        .emit()?;
    f.u32("Maximum frame-average light level")
        .with(|&v, n| n.summary(format!("{} cd/m²", luminance(v))))
        .desc("MaxFALL: brightest frame average, in units of 0.0001 cd/m²")
        .emit()?;
    Ok(())
}

fn sbit(f: &mut Fields<'_>, image: &Image) -> Result<()> {
    let names: &[&'static str] = match image.color {
        0 => &["Gray"],
        2 | 3 => &["Red", "Green", "Blue"],
        4 => &["Gray", "Alpha"],
        6 => &["Red", "Green", "Blue", "Alpha"],
        _ => &[],
    };
    let max = if image.color == 3 { 8 } else { image.depth };
    for &name in names {
        f.u8(name)
            .check(|&v| {
                (v == 0 || v > max).then(|| Diagnostic::warning(format!("must be 1 to {max}")))
            })
            .emit()?;
    }
    Ok(())
}

fn bkgd(f: &mut Fields<'_>, image: &Image) -> Result<()> {
    match image.color {
        3 => {
            f.u8("Palette index").emit()?;
        }
        0 | 4 => {
            f.u16("Gray").emit()?;
        }
        _ => {
            f.u16("Red").emit()?;
            f.u16("Green").emit()?;
            f.u16("Blue").emit()?;
        }
    }
    Ok(())
}

fn phys(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.seek(8);
    let metre = f.u8("Unit").get().is_ok_and(|u| u == 1);
    f.seek(0);
    let dpi = |&v: &u32, n: Node| {
        if metre {
            n.summary(format!("{:.1} dpi", f64::from(v) * 0.0254))
        } else {
            n
        }
    };
    f.u32("Pixels per unit, X").with(dpi).emit()?;
    f.u32("Pixels per unit, Y").with(dpi).emit()?;
    f.u8("Unit").enumeration(UNIT).emit()?;
    Ok(())
}

fn time_fields(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u16("Year").emit()?;
    f.u8("Month").emit()?;
    f.u8("Day").emit()?;
    f.u8("Hour").emit()?;
    f.u8("Minute").emit()?;
    f.u8("Second")
        .desc("0–60 (60 for a leap second); the time is UTC")
        .emit()?;
    Ok(())
}

fn actl(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u32("Number of frames").emit()?;
    f.u32("Number of plays")
        .with(|&v, n| if v == 0 { n.summary("loop forever") } else { n })
        .emit()?;
    Ok(())
}

fn fctl(f: &mut Fields<'_>, image: &Image) -> Result<()> {
    f.u32("Sequence number")
        .desc("Order of fcTL and fdAT chunks, from 0")
        .emit()?;
    let width = f.u32("Width").check(nonzero).emit()?;
    let height = f.u32("Height").check(nonzero).emit()?;
    let x = f.u32("X offset").emit()?;
    let y = f.u32("Y offset").emit()?;
    if image.width != 0
        && (u64::from(x).saturating_add(width.into()) > image.width.into()
            || u64::from(y).saturating_add(height.into()) > image.height.into())
    {
        f.node(
            Node::new("Frame region")
                .diag(Diagnostic::warning("the frame extends beyond the canvas")),
        );
    }
    let num = f.u16("Delay numerator").emit()?;
    f.u16("Delay denominator")
        .with(|&den, n| {
            let fc = Fctl {
                delay_num: num,
                delay_den: den,
                ..Fctl::default()
            };
            n.summary(format!("delay {}", delay(fc.seconds())))
        })
        .desc("The delay is numerator / denominator seconds; 0 means 100")
        .emit()?;
    f.u8("Dispose op")
        .enumeration(DISPOSE)
        .desc("What happens to the frame's region before the next frame is rendered")
        .emit()?;
    f.u8("Blend op")
        .enumeration(BLEND)
        .desc("source: replace the region; over: alpha-composite onto it")
        .emit()?;
    Ok(())
}

fn cgbi(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u32("Flags")
        .hex()
        .desc("Undocumented (Apple's pngcrush writes 0x50002002 or 0x50002006)")
        .emit()?;
    Ok(())
}

fn offs(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.int::<i32>("X position").emit()?;
    f.int::<i32>("Y position").emit()?;
    f.u8("Unit").enumeration(OFFSET_UNIT).emit()?;
    Ok(())
}

fn scal(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u8("Unit").enumeration(SCAL_UNIT).emit()?;
    f.cstr("Pixel width")
        .desc("ASCII floating-point number")
        .emit()?;
    let left = f.remaining();
    f.ascii("Pixel height", left)
        .desc("ASCII floating-point number")
        .emit()?;
    Ok(())
}

fn ster(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u8("Mode").enumeration(STEREO_MODE).emit()?;
    Ok(())
}

fn pcal(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.cstr("Calibration name").emit()?;
    f.int::<i32>("Original zero (X0)").emit()?;
    f.int::<i32>("Original max (X1)").emit()?;
    f.u8("Equation type").enumeration(PCAL_EQUATION).emit()?;
    let count = f.u8("Number of parameters").emit()?;
    f.cstr("Unit name").emit()?;
    for i in 0..count {
        let last = i.saturating_add(1) == count;
        if last {
            let left = f.remaining();
            f.ascii("Parameter", left).emit()?;
        } else {
            f.cstr("Parameter").emit()?;
        }
    }
    Ok(())
}

fn gifg(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u8("Disposal method").emit()?;
    f.u8("User input flag").emit()?;
    f.u16("Delay time")
        .with(|&v, n| n.summary(format!("{} ms", u32::from(v).saturating_mul(10))))
        .desc("Hundredths of a second")
        .emit()?;
    Ok(())
}

fn mhdr(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u32("Frame width").emit()?;
    f.u32("Frame height").emit()?;
    f.u32("Ticks per second").emit()?;
    f.u32("Nominal layer count")
        .desc("0 = unspecified")
        .emit()?;
    f.u32("Nominal frame count")
        .desc("0 = unspecified")
        .emit()?;
    f.u32("Nominal play time")
        .desc("In ticks; 0 = unspecified")
        .emit()?;
    f.u32("Simplicity profile").hex().emit()?;
    Ok(())
}

const JNG_COLOR: EnumTable = &[
    (8, "Grayscale"),
    (10, "Color"),
    (12, "Grayscale + alpha"),
    (14, "Color + alpha"),
];

fn jhdr(f: &mut Fields<'_>, _: &Image) -> Result<()> {
    f.u32("Width").emit()?;
    f.u32("Height").emit()?;
    f.u8("Color type").enumeration(JNG_COLOR).emit()?;
    f.u8("Image sample depth")
        .desc("8, 12 or 20 (8 and 12)")
        .emit()?;
    f.u8("Image compression method")
        .desc("8 = JPEG baseline")
        .emit()?;
    f.u8("Image interlace method")
        .desc("0 = sequential, 8 = progressive")
        .emit()?;
    f.u8("Alpha sample depth").emit()?;
    f.u8("Alpha compression method")
        .desc("0 = PNG (IDAT), 8 = JPEG (JDAA)")
        .emit()?;
    f.u8("Alpha filter method").emit()?;
    f.u8("Alpha interlace method").emit()?;
    Ok(())
}

/// A lazy list of `size`-byte big-endian values (tRNS alphas, hIST).
fn values(name: &'static str, span: Span, size: u64, nouns: (&str, &str)) -> Node {
    Node::new(name)
        .span(span)
        .summary(count(
            span.len.checked_div(size).unwrap_or(0),
            nouns.0,
            nouns.1,
        ))
        .lazy(list_values, (span, size))
}

async fn list_values(cx: Cx, (span, size): (Span, u64)) -> Result<()> {
    let count = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for index in 0..count {
        let entry = span.sub(index.saturating_mul(size), size);
        let bytes = cx.read(entry).await?;
        let value = if size == 2 {
            u16_be(&bytes, 0).map_or(0, u64::from)
        } else {
            bytes.first().copied().map_or(0, u64::from)
        };
        cx.push(
            Node::new(format!("[{index}]"))
                .span(entry)
                .value(uint(value, 64)),
        )
        .await;
    }
    Ok(())
}

/// `sPLT`: name, sample depth, then entries of red, green, blue, alpha
/// (1 or 2 bytes each) and a 2-byte frequency.
async fn suggested_palette(cx: &Cx, data: Span) -> Result<()> {
    let (name, at) = cx.cstr(data.sub(0, KEYWORD)).await?;
    cx.emit(Node::new("Palette name").span(at).value(text(name)));
    let depth_span = data.sub(at.len, 1);
    let block = cx.block(depth_span).await?;
    let depth = Fields::emitting(cx, &block, BE)
        .u8("Sample depth")
        .check(|&d| (d != 8 && d != 16).then(|| Diagnostic::warning("must be 8 or 16")))
        .emit()?;
    let entries = data.tail(at.len.saturating_add(1));
    let size = if depth == 16 { 10 } else { 6 };
    cx.emit(
        Node::new("Entries")
            .span(entries)
            .summary(count(
                entries.len.checked_div(size).unwrap_or(0),
                "entry",
                "entries",
            ))
            .lazy(splt_entries, (entries, depth)),
    );
    Ok(())
}

async fn splt_entries(cx: Cx, (span, depth): (Span, u8)) -> Result<()> {
    let size: u64 = if depth == 16 { 10 } else { 6 };
    let count = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for index in 0..count {
        let entry = span.sub(index.saturating_mul(size), size);
        let b = cx.read(entry).await?;
        let sample = |i: usize| -> u64 {
            if depth == 16 {
                u16_be(&b, i.saturating_mul(2)).map_or(0, u64::from)
            } else {
                b.get(i).copied().map_or(0, u64::from)
            }
        };
        let freq = u16_be(&b, if depth == 16 { 8 } else { 4 }).unwrap_or(0);
        cx.push(
            Node::new(format!("[{index}]"))
                .span(entry)
                .value(text(format!(
                    "RGBA ({}, {}, {}, {})",
                    sample(0),
                    sample(1),
                    sample(2),
                    sample(3)
                )))
                .summary(format!("frequency {freq}")),
        )
        .await;
    }
    Ok(())
}

/// Reads at most [`MAX_TEXT`] bytes of `span` for display.
async fn read_text(cx: &Cx, span: Span) -> Result<(Vec<u8>, bool)> {
    let bytes = cx.read_avail(span.sub(0, MAX_TEXT)).await?;
    Ok((bytes, span.len > MAX_TEXT))
}

fn text_node(name: &'static str, span: Span, value: String, clipped: bool) -> Node {
    let node = Node::new(name).span(span).value(text(value));
    if clipped {
        node.summary(format!("first {} shown", human_size(MAX_TEXT)))
    } else {
        node
    }
}

/// `tEXt` / `zTXt`: keyword, NUL, (compression method,) text.
async fn text_chunk(cx: &Cx, input: Input, data: Span, compressed: bool) -> Result<()> {
    let (keyword, at) = cx.cstr(data.sub(0, KEYWORD)).await?;
    cx.emit(Node::new("Keyword").span(at).value(text(keyword.clone())));
    let mut body = data.tail(at.len);
    let content = if compressed {
        let m = cx.block(body.sub(0, 1)).await?;
        Fields::emitting(cx, &m, BE)
            .u8("Compression method")
            .enumeration(COMPRESSION)
            .emit()?;
        body = body.tail(1);
        let decoded = inflate_span(cx, body, true, None).await?;
        if let Some(e) = decoded.error {
            cx.diag(e);
        }
        decoded.span
    } else {
        body
    };
    let (bytes, clipped) = read_text(cx, content).await?;
    let value = latin1(&bytes);
    let mut node = text_node("Text", body, value, clipped);
    if compressed {
        node = node.desc(format!("{} decompressed", human_size(content.len)));
    }
    cx.emit(node);
    if keyword == XMP_KEYWORD {
        cx.emit(xmp(input, content));
    } else if let Some(kind) = keyword.strip_prefix("Raw profile type ")
        && !clipped
        && let Some(node) = raw_profile(cx, input, content, kind, &bytes).await?
    {
        cx.emit(node);
    }
    Ok(())
}

/// `iTXt`: keyword, compression flag and method, language tag, translated
/// keyword (UTF-8), text (UTF-8, possibly compressed).
async fn international_text(cx: &Cx, input: Input, data: Span) -> Result<()> {
    let (keyword, at) = cx.cstr(data.sub(0, KEYWORD)).await?;
    cx.emit(Node::new("Keyword").span(at).value(text(keyword.clone())));
    let mut pos = at.len;
    let flags = cx.block(data.sub(pos, 2)).await?;
    let mut f = Fields::emitting(cx, &flags, BE);
    let compressed = f
        .u8("Compression flag")
        .with(|&v, n| n.summary(if v == 0 { "uncompressed" } else { "compressed" }))
        .emit()?
        != 0;
    f.u8("Compression method").enumeration(COMPRESSION).emit()?;
    pos = pos.saturating_add(2);
    let (language, at) = cx.cstr(data.tail(pos)).await?;
    cx.emit(
        Node::new("Language tag")
            .span(at)
            .value(text(language))
            .desc("RFC 3066 language tag; empty if unspecified"),
    );
    pos = pos.saturating_add(at.len);
    let (translated, at) = cx.cstr(data.tail(pos)).await?;
    cx.emit(
        Node::new("Translated keyword")
            .span(at)
            .value(text(translated)),
    );
    pos = pos.saturating_add(at.len);
    let body = data.tail(pos);
    let content = if compressed {
        let decoded = inflate_span(cx, body, true, None).await?;
        if let Some(e) = decoded.error {
            cx.diag(e);
        }
        decoded.span
    } else {
        body
    };
    if keyword == XMP_KEYWORD {
        cx.emit(xmp(input, content).summary(format!("{} of XML", human_size(content.len))));
        return Ok(());
    }
    let (bytes, clipped) = read_text(cx, content).await?;
    let mut node = text_node(
        "Text",
        body,
        String::from_utf8_lossy(&bytes).into_owned(),
        clipped,
    );
    if compressed {
        node = node.desc(format!("{} decompressed", human_size(content.len)));
    }
    cx.emit(node);
    Ok(())
}

fn xmp(input: Input, span: Span) -> Node {
    embedded_as(
        "XMP packet",
        input.nested(span),
        &crate::formats::image::xmp::FORMAT,
    )
}

/// ImageMagick's "Raw profile type <kind>" text: a newline, the kind, a
/// newline, the decimal length (space-padded), a newline, then the profile
/// in hexadecimal, wrapped at 72 digits.
async fn raw_profile(
    cx: &Cx,
    input: Input,
    span: Span,
    kind: &str,
    bytes: &[u8],
) -> Result<Option<Node>> {
    let mut lines = bytes.splitn(4, |&b| b == b'\n');
    let (Some(b""), Some(_), Some(length), Some(hex)) =
        (lines.next(), lines.next(), lines.next(), lines.next())
    else {
        return Ok(None);
    };
    let Ok(length) = latin1(length).trim().parse::<u64>() else {
        return Ok(None);
    };
    let mut out = Vec::with_capacity(crate::bytes::to_usize(
        length.min(crate::bytes::to_u64(hex.len()) / 2),
    ));
    let mut high: Option<u8> = None;
    for (i, &b) in hex.iter().enumerate() {
        if i % 0x10000 == 0xffff {
            cx.checkpoint().await;
        }
        if crate::bytes::to_u64(out.len()) >= length {
            break;
        }
        let digit = match b {
            b'0'..=b'9' => b.wrapping_sub(b'0'),
            b'a'..=b'f' => b.wrapping_sub(b'a').wrapping_add(10),
            b'A'..=b'F' => b.wrapping_sub(b'A').wrapping_add(10),
            b'\n' | b'\r' | b' ' => continue,
            _ => return Ok(None),
        };
        match high.take() {
            Some(h) => out.push(h.wrapping_mul(16) | digit),
            None => high = Some(digit),
        }
    }
    let decoded_len = crate::bytes::to_u64(out.len());
    let exif = out.starts_with(b"Exif\0\0");
    let profile = super::reassembled(cx, span, "png-raw-profile", out)?;
    let mut node = match kind {
        "exif" | "APP1" if exif => {
            embedded_as("Exif", input.nested(profile.tail(6)), &super::tiff::FORMAT)
        }
        "xmp" => xmp(input, profile),
        _ => embedded(format!("{kind} profile"), input.nested(profile)),
    }
    .summary(format!(
        "{} decoded from hexadecimal",
        human_size(decoded_len)
    ));
    if decoded_len < length {
        node = node.diag(Diagnostic::warning(format!(
            "declares {length} bytes, {decoded_len} present"
        )));
    }
    Ok(Some(node))
}

/// A run of `IDAT` (or one frame's `fdAT`) chunks.
#[derive(Clone, Debug)]
struct Group {
    input: Input,
    span: Span,
    kind: Kind,
    image: Image,
    width: u32,
    height: u32,
}

async fn image_data(cx: Cx, g: Group) -> Result<()> {
    let fdat = &g.kind == b"fdAT";
    let skip = if fdat { 4 } else { 0 };
    let mut chunks = Vec::new();
    let mut pieces = Vec::new();
    let mut pos = 0u64;
    while pos < g.span.len {
        let head = cx.read_avail(g.span.sub(pos, 8)).await?;
        let len = u64::from(u32_be(&head, 0).unwrap_or(0));
        let span = g.span.sub(pos, len.saturating_add(12));
        pieces.push(span.sub(8, len).tail(skip));
        chunks.push(span);
        pos = pos.saturating_add(len.saturating_add(12));
    }
    let stream = match pieces.as_slice() {
        [one] => *one,
        _ => {
            let transform = if fdat { "apng-fdat" } else { "png-idat" };
            cx.add_pieces_stepped(
                Origin {
                    parent: g.span,
                    transform,
                },
                &pieces,
            )
            .await?
        }
    };
    let (codec, what) = if g.image.cgbi {
        (Codec::Deflate, "Deflate stream (no zlib header: CgBI)")
    } else {
        (Codec::Zlib, "zlib stream")
    };
    let mut node = Node::new("Compressed stream")
        .span(stream)
        .summary(format!("{what}, {}", human_size(stream.len)));
    if pieces.len() > 1 {
        node = node.desc("The chunks' data joined together");
    }
    if !g.image.cgbi {
        node = node.lazy(zlib_header, stream);
    }
    cx.emit(node);

    let (width, height) = (u64::from(g.width), u64::from(g.height));
    let raw = g.image.raw_size(width, height);
    let rows = if g.image.interlace == 1 {
        format!("7 passes, {}", human_size(raw))
    } else {
        format!(
            "{}, {} each",
            plural(height, "row"),
            human_size(g.image.row_bytes(width).saturating_add(1))
        )
    };
    cx.emit(
        Node::new("Scanlines")
            .summary(rows)
            .desc("The decompressed image data: each row is a filter-type byte and the filtered pixels")
            .lazy(
                scanlines,
                Scan {
                    stream,
                    codec,
                    image: g.image,
                    width,
                    height,
                },
            ),
    );
    cx.set_count(Count::Exact(
        crate::bytes::to_u64(chunks.len()).saturating_add(2),
    ));
    for span in chunks {
        let kind = g.kind;
        cx.push(
            Node::new(crate::formats::util::sound::fourcc(&kind))
                .span(span)
                .summary(human_size(span.len.saturating_sub(12)))
                .lazy(
                    chunk,
                    ChunkState {
                        input: g.input,
                        span,
                        kind,
                        image: g.image,
                    },
                ),
        )
        .await;
    }
    Ok(())
}

/// The two-byte zlib header (RFC 1950).
async fn zlib_header(cx: Cx, stream: Span) -> Result<()> {
    let block = cx.block(stream.sub(0, 2)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    let cmf = f
        .u8("CMF")
        .hex()
        .with(|&v, n| {
            let window = 1u64
                .checked_shl(u32::from(v / 16).saturating_add(8))
                .unwrap_or(0);
            if v & 0x0f == 8 {
                n.summary(format!("deflate, {} window", human_size(window)))
            } else {
                n.diag(Diagnostic::malformed(
                    "compression method must be 8 (deflate)",
                ))
            }
        })
        .desc("Low 4 bits: method (8 = deflate); high 4 bits: log2(window size) − 8")
        .emit()?;
    f.u8("FLG")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{} compression{}",
                lookup(ZLIB_LEVEL, (v / 64).into()).unwrap_or("?"),
                if v & 0x20 != 0 {
                    ", preset dictionary"
                } else {
                    ""
                }
            ))
        })
        .check(|&flg| {
            (u16::from_be_bytes([cmf, flg]) % 31 != 0).then(|| {
                Diagnostic::warning("header check bits: CMF·256 + FLG is not a multiple of 31")
            })
        })
        .desc("Bits 0–4: check bits; bit 5: preset dictionary; bits 6–7: compression level")
        .emit()?;
    Ok(())
}

#[derive(Clone, Debug)]
struct Scan {
    stream: Span,
    codec: Codec,
    image: Image,
    width: u64,
    height: u64,
}

async fn scanlines(cx: Cx, s: Scan) -> Result<()> {
    let expected = s.image.raw_size(s.width, s.height);
    let decoded = if expected > LAZY_THRESHOLD
        && expected <= s.stream.len.saturating_mul(s.codec.max_ratio())
    {
        cx.decode_lazy(s.stream, &s.codec, expected)?
    } else {
        let d = decode_span(&cx, s.stream, &s.codec, Some(expected)).await?;
        if let Some(e) = d.error {
            cx.diag(e);
        } else if d.consumed < s.stream.len {
            cx.diag(Diagnostic::note(format!(
                "{} follow the compressed stream",
                human_size(s.stream.len.saturating_sub(d.consumed))
            )));
        }
        d.span
    };
    if s.image.interlace != 1 {
        let stride = s.image.row_bytes(s.width).saturating_add(1);
        return rows(
            cx,
            Rows {
                span: decoded,
                stride,
                count: s.height,
            },
        )
        .await;
    }
    let mut offset = 0u64;
    for (i, &pass) in ADAM7.iter().enumerate() {
        let (w, h) = Image::pass_dims(s.width, s.height, pass);
        let name = format!("Pass {}", i.saturating_add(1));
        if w == 0 || h == 0 {
            cx.emit(Node::new(name).summary("empty (the image is too small)"));
            continue;
        }
        let stride = s.image.row_bytes(w).saturating_add(1);
        let len = stride.saturating_mul(h);
        let span = decoded.sub(offset, len);
        cx.emit(
            Node::new(name)
                .span(span)
                .summary(format!("{} px, {}", dims(w, h), plural(h, "row")))
                .lazy(
                    rows,
                    Rows {
                        span,
                        stride,
                        count: h,
                    },
                ),
        );
        offset = offset.saturating_add(len);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Rows {
    span: Span,
    stride: u64,
    count: u64,
}

async fn rows(cx: Cx, r: Rows) -> Result<()> {
    if r.span.len >= r.stride.saturating_mul(r.count) {
        cx.set_count(Count::Exact(r.count));
    }
    let first = cx.resume::<u64>().unwrap_or(0);
    for index in first..r.count {
        cx.mark(move || index);
        let row = r.span.sub(index.saturating_mul(r.stride), r.stride);
        if row.is_empty() {
            cx.diag(Diagnostic::warning(format!(
                "the decompressed data ends after {index} of {} rows",
                r.count
            )));
            break;
        }
        let head = cx.read_avail(row.sub(0, 1)).await?;
        let Some(&filter) = head.first() else {
            cx.diag(Diagnostic::warning(format!(
                "the decompressed data ends after {index} of {} rows",
                r.count
            )));
            break;
        };
        let mut node = Node::new(format!("Row {index}"))
            .span(row)
            .value(Value::Enum {
                raw: filter.into(),
                bits: 8,
                name: lookup(FILTER_TYPE, filter.into()),
            });
        if filter > 4 {
            node = node.diag(Diagnostic::warning("filter type must be 0 to 4"));
        }
        if row.len < r.stride {
            node = node.diag(Diagnostic::truncated(
                Span::new(row.source, row.offset, r.stride),
                row.len,
            ));
        }
        cx.push(node).await;
    }
    Ok(())
}
