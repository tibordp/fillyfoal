//! TIFF and BigTIFF, plus the camera raw formats built on them (DNG, CR2,
//! NEF, ARW, ORF, RW2, PEF, SRW). Also serves Exif blocks embedded in JPEG,
//! PNG, WebP, HEIF and JPEG XL, which are TIFF streams, and the MPF index
//! of multi-picture JPEGs.
//!
//! The header points at a chain of image file directories (IFDs). Each IFD
//! is a counted array of 12-byte (BigTIFF: 20-byte) entries `tag, type,
//! count, value-or-offset`. The top level lists the chain; expanding an IFD
//! lists its entries with decoded values (f-numbers, exposure times, GPS
//! coordinates, enumerations and flags); expanding an entry shows its raw
//! fields, its out-of-line data and what it points to: the Exif, GPS and
//! Interoperability IFDs, SubIFDs, maker notes (Canon, Nikon, Sony,
//! Fujifilm, Olympus, Panasonic, Apple, Pentax, Samsung), embedded ICC
//! profiles, XMP, IPTC and Photoshop resources, GeoTIFF keys and DNG opcode
//! lists. Strips and tiles are listed as spans, decompressed on expansion
//! where we have the codec.

mod dng;
mod geo;
pub mod iptc;
pub(super) mod maker;
pub(super) mod render;
mod summary;

use std::collections::BTreeSet;

use crate::bytes::to_u64;
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Prim, struct_node};
use crate::formats::util::arcutil::human_size;
use crate::formats::{Format, Head, Input, Probe, content, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

use super::tiff_tags::{
    COMPRESSION, GPS_TAGS, INTEROP_TAGS, MP_TYPES, PANASONIC_RAW_TAGS, PHOTOMETRIC, SpecTable,
    TAGS, TYPES, spec, type_names,
};
use super::{dims, region};
use maker::{Make, Note};

macro_rules! tiff_variant {
    ($id:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $probe:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom($probe),
            dissect: crate::expander!(dissect: Input),
        };
    };
}

tiff_variant!(
    DNG,
    "dng",
    "Adobe Digital Negative",
    ["dng"],
    "image/x-adobe-dng",
    |h| { ifd0(h).is_some_and(|ifd| ifd.has(0xc612)) }
);
tiff_variant!(
    CR2,
    "cr2",
    "Canon raw (CR2)",
    ["cr2"],
    "image/x-canon-cr2",
    |h| { classic(h) && h.at(8, b"CR\x02\x00") }
);
tiff_variant!(
    NEF,
    "nef",
    "Nikon raw (NEF)",
    ["nef", "nrw"],
    "image/x-nikon-nef",
    |h| { ifd0(h).is_some_and(|ifd| ifd.make_starts_with(b"NIKON") && ifd.has_image()) }
);
tiff_variant!(
    ARW,
    "arw",
    "Sony raw (ARW)",
    ["arw", "srf", "sr2"],
    "image/x-sony-arw",
    |h| { ifd0(h).is_some_and(|ifd| ifd.make_starts_with(b"SONY") && ifd.has_image()) }
);
tiff_variant!(
    PEF,
    "pef",
    "Pentax raw (PEF)",
    ["pef"],
    "image/x-pentax-pef",
    |h| {
        ifd0(h).is_some_and(|ifd| {
            (ifd.make_starts_with(b"PENTAX") || ifd.make_starts_with(b"RICOH")) && ifd.has_image()
        })
    }
);
tiff_variant!(
    SRW,
    "srw",
    "Samsung raw (SRW)",
    ["srw"],
    "image/x-samsung-srw",
    |h| { ifd0(h).is_some_and(|ifd| ifd.make_starts_with(b"SAMSUNG") && ifd.has_image()) }
);
tiff_variant!(
    ORF,
    "orf",
    "Olympus raw (ORF)",
    ["orf"],
    "image/x-olympus-orf",
    |h| {
        h.starts_with(b"IIRO\x08\x00\x00\x00")
            || h.starts_with(b"IIRS\x08\x00\x00\x00")
            || h.starts_with(b"MMOR\x00\x00\x00\x08")
    }
);
tiff_variant!(
    RW2,
    "rw2",
    "Panasonic raw (RW2)",
    ["rw2", "rwl"],
    "image/x-panasonic-rw2",
    |h| { h.starts_with(b"IIU\x00\x18\x00\x00\x00") }
);
tiff_variant!(
    JXR,
    "jxr",
    "JPEG XR (HD Photo)",
    ["jxr", "wdp", "hdp"],
    "image/jxr",
    |h| { h.starts_with(b"II\xbc\x01") }
);

pub static FORMAT: Format = Format {
    name: "tiff",
    title: "Tagged Image File Format",
    extensions: &["tif", "tiff"],
    mime: "image/tiff",
    probe: Probe::Magic(&[
        (0, b"II*\x00"),
        (0, b"MM\x00*"),
        (0, b"II+\x00\x08\x00\x00\x00"),
        (0, b"MM\x00+\x00\x08\x00\x00"),
    ]),
    dissect: crate::expander!(dissect: Input),
};

// ---------------------------------------------------------------------------
// Probing helpers: IFD0 of a classic TIFF within the probe window.

fn classic(h: &Head<'_>) -> bool {
    h.starts_with(b"II*\x00") || h.starts_with(b"MM\x00*")
}

struct ProbeIfd<'a> {
    data: &'a [u8],
    endian: Endian,
    entries: &'a [u8],
}

fn ifd0<'a>(h: &Head<'a>) -> Option<ProbeIfd<'a>> {
    if !classic(h) {
        return None;
    }
    let endian = if h.starts_with(b"II") {
        Endian::Little
    } else {
        Endian::Big
    };
    let get = |at: usize, n: usize| h.data.get(at..at.checked_add(n)?);
    let offset = usize::try_from(u32::decode(get(4, 4)?, endian)?).ok()?;
    let count = usize::from(u16::decode(get(offset, 2)?, endian)?);
    let start = offset.checked_add(2)?;
    let len = count.checked_mul(12)?;
    let entries = h
        .data
        .get(start..start.checked_add(len)?)
        .or_else(|| h.data.get(start..))?;
    Some(ProbeIfd {
        data: h.data,
        endian,
        entries,
    })
}

impl ProbeIfd<'_> {
    fn entry(&self, tag: u16) -> Option<&[u8; 12]> {
        self.entries
            .as_chunks::<12>()
            .0
            .iter()
            .find(|e| e.get(..2).and_then(|t| u16::decode(t, self.endian)) == Some(tag))
    }

    fn has(&self, tag: u16) -> bool {
        self.entry(tag).is_some()
    }

    /// Whether IFD0 describes image data (an Exif block's IFD0 does not, so
    /// a camera's Exif is not mistaken for its raw format).
    fn has_image(&self) -> bool {
        [0x0111, 0x0144, 0x014a, 0x0201]
            .into_iter()
            .any(|t| self.has(t))
    }

    fn make_starts_with(&self, prefix: &[u8]) -> bool {
        let Some(e) = self.entry(0x010f) else {
            return false;
        };
        let count = e
            .get(4..8)
            .and_then(|c| u32::decode(c, self.endian))
            .unwrap_or(0);
        let text = if count <= 4 {
            e.get(8..12)
        } else {
            e.get(8..12)
                .and_then(|o| u32::decode(o, self.endian))
                .and_then(|o| usize::try_from(o).ok())
                .and_then(|o| self.data.get(o..))
        };
        text.is_some_and(|t| t.starts_with(prefix))
    }
}

// ---------------------------------------------------------------------------
// Model

/// A TIFF stream: where its offsets count from, byte order and offset
/// width, and the camera maker (for maker notes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tiff {
    /// The input embedded content is nested in.
    input: Input,
    /// Offsets are relative to the start of this span (the TIFF header,
    /// or a maker note's own base).
    base: Span,
    endian: Endian,
    big: bool,
    make: Make,
}

impl Tiff {
    fn file(&self) -> Span {
        self.base
    }

    fn uint(&self, bytes: &[u8], size: u64) -> Option<u64> {
        match size {
            1 => bytes.first().map(|&b| b.into()),
            2 => u16::decode(bytes.get(..2)?, self.endian).map(u64::from),
            4 => u32::decode(bytes.get(..4)?, self.endian).map(u64::from),
            8 => u64::decode(bytes.get(..8)?, self.endian),
            _ => None,
        }
    }

    fn count_len(&self) -> u64 {
        if self.big { 8 } else { 2 }
    }

    fn entry_len(&self) -> u64 {
        if self.big { 20 } else { 12 }
    }

    fn offset_len(&self) -> u64 {
        if self.big { 8 } else { 4 }
    }
}

/// Which tag namespace an IFD uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dir {
    Main,
    Exif,
    Gps,
    Interop,
    /// IFD0 of a Panasonic RW2 file.
    PanasonicRaw,
    Maker(Note),
}

/// How a tag's value is interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ns {
    /// Baseline TIFF, TIFF/EP, Exif, DNG and GeoTIFF.
    Main,
    Gps,
    Interop,
    /// Private (maker note or raw) tags.
    Other(Option<Note>),
}

impl Dir {
    fn ns(self, tag: u16) -> Ns {
        match self {
            Dir::Main | Dir::Exif => Ns::Main,
            Dir::Gps => Ns::Gps,
            Dir::Interop => Ns::Interop,
            Dir::PanasonicRaw => {
                if lookup(PANASONIC_RAW_TAGS, tag.into()).is_some() {
                    Ns::Other(None)
                } else {
                    Ns::Main
                }
            }
            Dir::Maker(n) => Ns::Other(Some(n)),
        }
    }

    fn name(self, tag: u16) -> Option<&'static str> {
        match self {
            Dir::Main | Dir::Exif => lookup(TAGS, tag.into()),
            Dir::Gps => lookup(GPS_TAGS, tag.into()),
            Dir::Interop => lookup(INTEROP_TAGS, tag.into()),
            Dir::PanasonicRaw => {
                lookup(PANASONIC_RAW_TAGS, tag.into()).or_else(|| lookup(TAGS, tag.into()))
            }
            Dir::Maker(n) => lookup(n.tags(), tag.into()),
        }
    }

    fn spec_table(self, tag: u16) -> Option<SpecTable> {
        match self.ns(tag) {
            Ns::Main => Some(SpecTable::Main),
            Ns::Gps => Some(SpecTable::Gps),
            Ns::Interop => Some(SpecTable::Interop),
            Ns::Other(_) => None,
        }
    }

    /// Whether this directory carries image data (strips, tiles, JPEG).
    fn has_image(self) -> bool {
        matches!(self, Dir::Main | Dir::PanasonicRaw)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    tag: u16,
    kind: u16,
    count: u64,
    /// The 12- or 20-byte entry.
    span: Span,
    /// Where the value lives (inline or out of line), clamped to the file.
    data: Span,
    /// Declared size of the value.
    size: u64,
    inline: bool,
}

fn type_size(kind: u16) -> u64 {
    match kind {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 | 13 => 4,
        5 | 10 | 12 | 16 | 17 | 18 => 8,
        _ => 0,
    }
}

impl Entry {
    fn decode(t: Tiff, bytes: &[u8], span: Span) -> Option<Entry> {
        let tag = u16::try_from(t.uint(bytes, 2)?).ok()?;
        let kind = u16::try_from(t.uint(bytes.get(2..)?, 2)?).ok()?;
        let (count, field_at) = if t.big {
            (t.uint(bytes.get(4..)?, 8)?, 12u64)
        } else {
            (t.uint(bytes.get(4..)?, 4)?, 8u64)
        };
        let size = type_size(kind).saturating_mul(count);
        let inline = size <= t.offset_len();
        let data = if inline {
            span.sub(field_at, size)
        } else {
            let at = usize::try_from(field_at).ok()?;
            let offset = t.uint(bytes.get(at..)?, t.offset_len())?;
            t.file().sub(offset, size)
        };
        Some(Entry {
            tag,
            kind,
            count,
            span,
            data,
            size,
            inline,
        })
    }
}

struct Ifd {
    span: Span,
    entries: Vec<Entry>,
    next: u64,
}

impl Ifd {
    fn find(&self, tag: u16) -> Option<&Entry> {
        self.entries.iter().find(|e| e.tag == tag)
    }
}

async fn read_ifd(cx: &Cx, t: Tiff, offset: u64) -> Result<Ifd> {
    let file = t.file();
    let count_span = file.sub_exact(offset, t.count_len())?;
    let count_bytes = cx.read(count_span).await?;
    let count = t.uint(&count_bytes, t.count_len()).unwrap_or(0);
    let table_len = count.saturating_mul(t.entry_len());
    let table = file.sub_exact(offset.saturating_add(t.count_len()), table_len)?;
    let data = cx.read(table).await?;
    let mut entries = Vec::new();
    for (i, bytes) in data.chunks_exact(if t.big { 20 } else { 12 }).enumerate() {
        if i % 1024 == 1023 {
            cx.checkpoint().await;
        }
        let span = table.sub(to_u64(i).saturating_mul(t.entry_len()), t.entry_len());
        if let Some(e) = Entry::decode(t, bytes, span) {
            entries.push(e);
        }
    }
    let next_span = file.sub(table.end().saturating_sub(file.offset), t.offset_len());
    let next = cx.read_avail(next_span).await?;
    Ok(Ifd {
        span: Span::new(
            file.source,
            count_span.offset,
            next_span.end().saturating_sub(count_span.offset),
        ),
        entries,
        next: t.uint(&next, t.offset_len()).unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// Values

#[derive(Clone, Copy, Debug)]
enum Num {
    U(u64),
    I(i64),
    F(f64),
    R(u64, u64),
    S(i64, i64),
}

#[allow(clippy::cast_precision_loss)]
fn f64_of(v: u64) -> f64 {
    v as f64
}

#[allow(clippy::cast_precision_loss)]
fn f64_of_i(v: i64) -> f64 {
    v as f64
}

impl Num {
    fn as_u64(self) -> Option<u64> {
        match self {
            Num::U(v) => Some(v),
            Num::I(v) => u64::try_from(v).ok(),
            _ => None,
        }
    }

    /// The value as a real number (`None` for a rational with a zero
    /// denominator, which Exif uses for "unknown").
    fn f64(self) -> Option<f64> {
        match self {
            Num::U(v) => Some(f64_of(v)),
            Num::I(v) => Some(f64_of_i(v)),
            Num::F(v) => Some(v),
            Num::R(_, 0) | Num::S(_, 0) => None,
            Num::R(n, d) => Some(f64_of(n) / f64_of(d)),
            Num::S(n, d) => Some(f64_of_i(n) / f64_of_i(d)),
        }
    }

    fn to_value(self, hex: bool) -> Value {
        match self {
            Num::U(value) => Value::UInt {
                value,
                bits: 64,
                radix: if hex { Radix::Hex } else { Radix::Dec },
            },
            Num::I(value) => Value::Int { value, bits: 64 },
            Num::F(f) => Value::Float(f),
            Num::R(..) | Num::S(..) => Value::Float(self.f64().unwrap_or(0.0)),
        }
    }

    /// A short decimal rendering ("0.3333", "72", "-1/0" for unknown).
    fn short(self) -> String {
        match (self, self.f64()) {
            (Num::U(v), _) => v.to_string(),
            (Num::I(v), _) => v.to_string(),
            (_, Some(v)) => render::trim(v, 4),
            (_, None) => self.to_string(),
        }
    }
}

impl std::fmt::Display for Num {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Num::U(v) => write!(f, "{v}"),
            Num::I(v) => write!(f, "{v}"),
            Num::F(v) => write!(f, "{v}"),
            Num::R(n, d) => write!(f, "{n}/{d}"),
            Num::S(n, d) => write!(f, "{n}/{d}"),
        }
    }
}

/// Decodes the value at `index` of an array of `kind` in `bytes`.
fn num(t: Tiff, kind: u16, bytes: &[u8], index: usize) -> Option<Num> {
    let size = usize::try_from(type_size(kind)).ok()?;
    let at = index.checked_mul(size)?;
    let b = bytes.get(at..at.checked_add(size)?)?;
    let e = t.endian;
    Some(match kind {
        1 | 7 => Num::U(b.first().copied()?.into()),
        6 => Num::I(i8::decode(b, e)?.into()),
        3 => Num::U(u16::decode(b, e)?.into()),
        8 => Num::I(i16::decode(b, e)?.into()),
        4 | 13 => Num::U(u32::decode(b, e)?.into()),
        9 => Num::I(i32::decode(b, e)?.into()),
        16 | 18 => Num::U(u64::decode(b, e)?),
        17 => Num::I(i64::decode(b, e)?),
        11 => Num::F(f32::decode(b, e)?.into()),
        12 => Num::F(f64::decode(b, e)?),
        5 => Num::R(
            u32::decode(b.get(..4)?, e)?.into(),
            u32::decode(b.get(4..)?, e)?.into(),
        ),
        10 => Num::S(
            i32::decode(b.get(..4)?, e)?.into(),
            i32::decode(b.get(4..)?, e)?.into(),
        ),
        _ => return None,
    })
}

/// The first `max` values of an entry.
async fn values_of(cx: &Cx, t: Tiff, e: &Entry, max: u64) -> Vec<Num> {
    let n = e.count.min(max);
    let len = type_size(e.kind).saturating_mul(n);
    let bytes = cx.read_avail(e.data.sub(0, len)).await.unwrap_or_default();
    (0..usize::try_from(n).unwrap_or(0))
        .map_while(|i| num(t, e.kind, &bytes, i))
        .collect()
}

/// The first value of `tag` in `ifd`.
async fn first_value(cx: &Cx, t: Tiff, ifd: &Ifd, tag: u16) -> Option<Num> {
    let e = ifd.find(tag)?;
    values_of(cx, t, e, 1).await.first().copied()
}

/// The text of an ASCII entry (up to `cap` bytes), trimmed.
async fn ascii_of(cx: &Cx, e: &Entry, cap: u64) -> Option<String> {
    if e.kind != 2 {
        return None;
    }
    let bytes = cx.read_avail(e.data.sub(0, cap)).await.ok()?;
    let text = render::ascii_text(&bytes);
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Tags whose values are file offsets.
fn is_offset_tag(tag: u16) -> bool {
    matches!(
        tag,
        0x0111
            | 0x0144
            | 0x0201
            | 0x014a
            | 0x8769
            | 0x8825
            | 0xa005
            | 0x0120
            | 0xbcc0
            | 0xbcc2
            | 0xc634
    )
}

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 16)).await?;
    let endian = match head.get(..2) {
        Some(b"II") => Endian::Little,
        Some(b"MM") => Endian::Big,
        _ => return Err(Diagnostic::malformed("bad byte order mark").at(file.sub(0, 2))),
    };
    let magic = u16::decode(head.get(2..4).unwrap_or_default(), endian).unwrap_or(0);
    let big = magic == 43;
    let cr2 = !big && head.get(8..10) == Some(b"CR".as_slice());
    let header_span = file.sub(0, if big || cr2 { 16 } else { 8 });
    let block = cx.block(header_span).await?;
    let ctx = HeaderCtx { big, cr2 };
    let first = header(&mut Fields::new(&block, endian), &ctx)?;
    cx.emit(struct_node("Header", header_span, endian, ctx, header));
    let mut t = Tiff {
        input,
        base: file,
        endian,
        big,
        make: Make::Unknown,
    };
    let dir = if magic == 0x55 {
        Dir::PanasonicRaw
    } else {
        Dir::Main
    };

    let mut offset = first;
    let mut seen = BTreeSet::new();
    let mut count = 0usize;
    let mut kind = "TIFF";
    let mut annotation = String::new();
    while offset != 0 {
        if !seen.insert(offset) {
            cx.diag(Diagnostic::malformed(format!(
                "IFD chain loops back to {offset:#x}"
            )));
            break;
        }
        if count >= MAX_IFDS {
            cx.diag(Diagnostic::limit(format!("more than {MAX_IFDS} IFDs")));
            break;
        }
        let name = format!("IFD{count}");
        let ifd = match read_ifd(&cx, t, offset).await {
            Ok(ifd) => ifd,
            Err(e) => {
                cx.push(Node::new(name).diag(e)).await;
                break;
            }
        };
        if count == 0 {
            if let Some(make) = text_tag(&cx, &ifd, 0x010f).await {
                t.make = maker::make_of(&make);
            }
            kind = match magic {
                43 => "BigTIFF",
                0x4f52 | 0x5352 => "ORF",
                0x55 => "RW2",
                0x01bc => "JPEG XR",
                _ if cr2 => "CR2",
                _ if ifd.find(0xc612).is_some() => "DNG",
                _ => "TIFF",
            };
            annotation = root_summary(&cx, t, dir, &ifd, kind).await;
            cx.annotate(annotation.clone());
        }
        let summary = ifd_summary(&cx, t, dir, &ifd).await;
        cx.push(
            ifd_node(
                name,
                t,
                dir,
                offset,
                vec![file.offset.saturating_add(offset)],
            )
            .span(ifd.span)
            .summary(summary),
        )
        .await;
        offset = ifd.next;
        count = count.saturating_add(1);
    }
    if count > 1 && matches!(kind, "TIFF" | "BigTIFF") && !annotation.starts_with("Exif") {
        cx.annotate(format!("{annotation}, {count} IFDs"));
    }
    Ok(())
}

const MAX_IFDS: usize = 4096;
const MAX_DEPTH: usize = 16;

const VERSIONS: EnumTable = &[
    (42, "TIFF"),
    (43, "BigTIFF"),
    (0x4f52, "Olympus ORF"),
    (0x5352, "Olympus ORF"),
    (0x55, "Panasonic RW2"),
    (0x01bc, "JPEG XR"),
];

#[derive(Clone, Copy, Debug)]
struct HeaderCtx {
    big: bool,
    cr2: bool,
}

fn header(f: &mut Fields<'_>, ctx: &HeaderCtx) -> Result<u64> {
    f.ascii("Byte order", 2)
        .with(|v, n| {
            n.summary(if v == "II" {
                "little-endian"
            } else {
                "big-endian"
            })
        })
        .emit()?;
    f.u16("Version").enumeration(VERSIONS).emit()?;
    if ctx.big {
        f.u16("Offset size").emit()?;
        f.u16("Reserved").emit()?;
    }
    let first = f.uword("First IFD offset", ctx.big).hex().emit()?;
    if ctx.cr2 {
        f.ascii("CR2 signature", 2).emit()?;
        f.u8("CR2 major version").emit()?;
        f.u8("CR2 minor version").emit()?;
        f.u32("Raw IFD offset")
            .hex()
            .desc("The IFD of the raw image (IFD3)")
            .emit()?;
    }
    Ok(first)
}

/// Whether IFD0 describes no image of its own but a camera's metadata: an
/// Exif block.
fn is_exif(ifd: &Ifd) -> bool {
    [0x0100, 0x0111, 0x0144, 0x014a, 0xbcc0, 0xb000]
        .into_iter()
        .all(|t| ifd.find(t).is_none())
        && [0x8769, 0x8825, 0x010f, 0x0110]
            .into_iter()
            .any(|t| ifd.find(t).is_some())
}

async fn root_summary(cx: &Cx, t: Tiff, dir: Dir, ifd: &Ifd, kind: &str) -> String {
    if let Some(n) = first_value(cx, t, ifd, 0xb001).await.and_then(Num::as_u64) {
        return format!("MPF index, {n} images");
    }
    let shot = summary::shot(cx, t, ifd).await;
    if is_exif(ifd) {
        let text = shot.describe(true);
        return if text.is_empty() {
            format!("Exif, {} entries in IFD0", ifd.entries.len())
        } else {
            format!("Exif: {text}")
        };
    }
    let endian = if t.endian == Endian::Little {
        "LE"
    } else {
        "BE"
    };
    let mut s = format!("{kind} {endian}, {}", ifd_summary(cx, t, dir, ifd).await);
    let extra = shot.describe(false);
    if !extra.is_empty() {
        s = format!("{s}, {extra}");
    }
    s
}

/// The text of an ASCII tag.
async fn text_tag(cx: &Cx, ifd: &Ifd, tag: u16) -> Option<String> {
    ascii_of(cx, ifd.find(tag)?, 128).await
}

/// "640×480, 8-bit RGB, LZW" (plus camera make and model when present).
async fn ifd_summary(cx: &Cx, t: Tiff, dir: Dir, ifd: &Ifd) -> String {
    let mut parts = Vec::new();
    let first = |tag: u16| async move { first_value(cx, t, ifd, tag).await?.as_u64() };
    if dir == Dir::Main
        && let Some(camera) = camera_of(cx, ifd).await
    {
        parts.push(camera);
    }
    if let (Some(w), Some(h)) = (first(0x0100).await, first(0x0101).await) {
        parts.push(dims(w, h));
    } else if let (Some(w), Some(h)) = (first(0xbc80).await, first(0xbc81).await) {
        parts.push(dims(w, h));
    } else if dir == Dir::PanasonicRaw
        && let (Some(w), Some(h)) = (first(0x0002).await, first(0x0003).await)
    {
        parts.push(format!("{} sensor", dims(w, h)));
    }
    if let Some(bits) = first(0x0102).await {
        let float = first(0x0153).await == Some(3);
        let photometric = first(0x0106).await.and_then(|p| lookup(PHOTOMETRIC, p));
        let bits = if float {
            format!("{bits}-bit float")
        } else {
            format!("{bits}-bit")
        };
        parts.push(match photometric {
            Some(p) => format!("{bits} {p}"),
            None => bits,
        });
    }
    if let Some(c) = first(0x0103).await {
        parts
            .push(lookup(COMPRESSION, c).map_or_else(|| format!("compression {c}"), str::to_owned));
    }
    if let (Some(w), Some(h)) = (first(0x0142).await, first(0x0143).await) {
        parts.push(format!("{} tiles", dims(w, h)));
    }
    if let Some(flags) = first(0x00fe).await {
        if flags & 1 != 0 {
            parts.push("reduced resolution".to_owned());
        }
        if flags & 4 != 0 {
            parts.push("transparency mask".to_owned());
        }
    }
    if ifd.find(0x87af).is_some() {
        parts.push("GeoTIFF".to_owned());
    }
    if parts.is_empty() {
        format!("{} entries", ifd.entries.len())
    } else {
        parts.join(", ")
    }
}

/// "Make Model" from an IFD's ASCII tags (the model alone when it already
/// names the maker).
async fn camera_of(cx: &Cx, ifd: &Ifd) -> Option<String> {
    let make = text_tag(cx, ifd, 0x010f).await.unwrap_or_default();
    let model = text_tag(cx, ifd, 0x0110).await.unwrap_or_default();
    let first_word = make.split_whitespace().next().unwrap_or_default();
    let camera = if make.is_empty()
        || model
            .to_ascii_lowercase()
            .starts_with(&first_word.to_ascii_lowercase())
    {
        model
    } else if model.is_empty() {
        make
    } else {
        format!("{make} {model}")
    };
    (!camera.is_empty()).then_some(camera)
}

/// Opens a classic TIFF stream at the start of `input` (an Exif block).
async fn open(cx: &Cx, input: Input) -> Option<(Tiff, Ifd)> {
    let head = cx.read_avail(input.span.sub(0, 8)).await.ok()?;
    let endian = match head.get(..2)? {
        b"II" => Endian::Little,
        b"MM" => Endian::Big,
        _ => return None,
    };
    let first = u32::decode(head.get(4..8)?, endian)?;
    let mut t = Tiff {
        input,
        base: input.span,
        endian,
        big: false,
        make: Make::Unknown,
    };
    let ifd = read_ifd(cx, t, first.into()).await.ok()?;
    if let Some(make) = text_tag(cx, &ifd, 0x010f).await {
        t.make = maker::make_of(&make);
    }
    Some((t, ifd))
}

/// The camera that wrote a TIFF stream (e.g. the Exif block of a JPEG), for
/// summaries of the files that embed it.
pub async fn camera(cx: &Cx, input: Input) -> Option<String> {
    let (_, ifd) = open(cx, input).await?;
    camera_of(cx, &ifd).await
}

/// A one-line summary of an Exif block: camera, lens, exposure, date and
/// position ("Canon EOS R5, 24-105mm at 50mm, f/4, 1/250 s, ISO 200,
/// 2024-05-01 12:00").
pub async fn exif_summary(cx: &Cx, input: Input) -> Option<String> {
    let (t, ifd) = open(cx, input).await?;
    let text = summary::shot(cx, t, &ifd).await.describe(true);
    (!text.is_empty()).then_some(text)
}

/// A TIFF stream from a Canon CR3 `CMT1`–`CMT4` box, whose IFD0 is IFD0,
/// the Exif IFD, the Canon maker note or the GPS IFD respectively.
pub fn cr3_metadata(name: &'static str, input: Input, span: Span, kind: [u8; 4]) -> Node {
    Node::new(name)
        .span(span)
        .lazy(cmt, (input.nested(span), kind))
}

async fn cmt(cx: Cx, (input, kind): (Input, [u8; 4])) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let endian = match head.get(..2) {
        Some(b"II") => Endian::Little,
        Some(b"MM") => Endian::Big,
        _ => return Err(Diagnostic::malformed("bad byte order mark").at(file.sub(0, 2))),
    };
    let ctx = HeaderCtx {
        big: false,
        cr2: false,
    };
    let block = cx.block(file.sub(0, 8)).await?;
    let first = header(&mut Fields::new(&block, endian), &ctx)?;
    cx.emit(struct_node("Header", file.sub(0, 8), endian, ctx, header));
    let (name, dir) = match &kind {
        b"CMT1" => ("IFD0", Dir::Main),
        b"CMT2" => ("Exif IFD", Dir::Exif),
        b"CMT3" => ("Canon maker note", Dir::Maker(Note::Canon)),
        _ => ("GPS IFD", Dir::Gps),
    };
    let t = Tiff {
        input,
        base: file,
        endian,
        big: false,
        make: Make::Canon,
    };
    let ifd = read_ifd(&cx, t, first).await?;
    let summary = child_summary(&cx, t, dir, &ifd).await;
    if kind == *b"CMT1" {
        cx.annotate(format!("IFD0, {summary}"));
    } else {
        cx.annotate(format!("{name}, {summary}"));
    }
    cx.emit(
        ifd_node(name, t, dir, first, vec![file.offset.saturating_add(first)])
            .span(ifd.span)
            .summary(summary),
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct IfdState {
    t: Tiff,
    dir: Dir,
    offset: u64,
    /// Source offsets of this IFD and the ones enclosing it (for loops).
    path: Vec<u64>,
}

fn ifd_node(
    name: impl Into<std::borrow::Cow<'static, str>>,
    t: Tiff,
    dir: Dir,
    offset: u64,
    path: Vec<u64>,
) -> Node {
    Node::new(name)
        .span(t.file().sub(offset, t.count_len()))
        .lazy(
            crate::expander!(self::ifd: IfdState),
            IfdState {
                t,
                dir,
                offset,
                path,
            },
        )
}

/// The siblings an entry's expansion needs (GeoTIFF parameter arrays).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Siblings {
    geo_doubles: Option<Entry>,
    geo_ascii: Option<Entry>,
}

async fn ifd(cx: Cx, st: IfdState) -> Result<()> {
    let t = st.t;
    let ifd = read_ifd(&cx, t, st.offset).await?;
    let count_span = ifd.span.sub(0, t.count_len());
    let block = cx.block(count_span).await?;
    let mut f = Fields::emitting(&cx, &block, t.endian);
    if t.big {
        f.u64("Entry count").emit()?;
    } else {
        f.u16("Entry count").emit()?;
    }
    cx.set_count(Count::AtLeast(to_u64(ifd.entries.len())));
    let refs = render::refs(&cx, t, st.dir, &ifd).await;
    let siblings = Siblings {
        geo_doubles: ifd.find(0x87b0).copied(),
        geo_ascii: ifd.find(0x87b1).copied(),
    };
    for e in &ifd.entries {
        let node = entry_node(&cx, t, st.dir, e, &refs).await;
        let state = EntryState {
            t,
            dir: st.dir,
            entry: *e,
            path: st.path.clone(),
            siblings,
        };
        cx.push(node.lazy(crate::expander!(self::entry: EntryState), state))
            .await;
    }
    let next_span = ifd.span.tail(ifd.span.len.saturating_sub(t.offset_len()));
    // Only top-level and sub-image IFDs chain; Exif, GPS, Interoperability
    // and maker-note IFDs end without (or with an ignored) link.
    if st.dir.has_image() {
        let block = cx.block(next_span).await?;
        Fields::emitting(&cx, &block, t.endian)
            .uword("Next IFD offset", t.big)
            .hex()
            .emit()?;
    }
    if st.dir.has_image() {
        image_data(&cx, t, &ifd).await;
    }
    Ok(())
}

/// The node for one entry: tag name, decoded value, type check.
async fn entry_node(cx: &Cx, t: Tiff, dir: Dir, e: &Entry, refs: &render::Refs) -> Node {
    let name = dir
        .name(e.tag)
        .map_or_else(|| format!("Tag {:#06x}", e.tag), str::to_owned);
    let shown = render::describe(cx, t, dir, e, refs).await;
    let mut node = Node::new(name).span(e.span);
    if let Some(v) = shown.value {
        node = node.value(v);
    }
    if let Some(s) = shown.summary {
        node = node.summary(s);
    }
    if !e.inline {
        node = node.target(e.data);
        if e.data.len < e.size {
            node = node.diag(Diagnostic::truncated(
                Span::new(e.data.source, e.data.offset, e.size),
                e.data.len,
            ));
        }
    }
    if type_size(e.kind) == 0 {
        return node.diag(Diagnostic::malformed(format!(
            "unknown field type {}",
            e.kind
        )));
    }
    if let Some(table) = dir.spec_table(e.tag)
        && let Some((types, count)) = spec(table, e.tag)
    {
        let bit = 1u32.checked_shl(u32::from(e.kind)).unwrap_or(0);
        let kind = lookup(TYPES, e.kind.into()).unwrap_or("?");
        if types & bit == 0 {
            node = node.diag(Diagnostic::warning(format!(
                "type {kind}; the specification gives {}",
                type_names(types)
            )));
        } else if count != 0 && e.kind != 2 && e.count != u64::from(count) {
            node = node.diag(Diagnostic::warning(format!(
                "{} values; the specification gives {count}",
                e.count
            )));
        }
    }
    node
}

/// Strips, tiles, the JPEG XR bitstreams and the JPEG image of an IFD.
async fn image_data(cx: &Cx, t: Tiff, ifd: &Ifd) {
    let compression = first_value(cx, t, ifd, 0x0103)
        .await
        .and_then(Num::as_u64)
        .unwrap_or(1);
    for (offsets, counts, what) in [(0x0111, 0x0117, "Strip"), (0x0144, 0x0145, "Tile")] {
        if let (Some(o), Some(c)) = (ifd.find(offsets), ifd.find(counts)) {
            let n = o.count.min(c.count);
            let mut node = Node::new(format!("{what}s"))
                .summary(format!(
                    "{n} {}{}",
                    what.to_lowercase(),
                    if n == 1 { "" } else { "s" }
                ))
                .lazy(
                    pieces,
                    Pieces {
                        t,
                        offsets: *o,
                        counts: *c,
                        compression,
                        what,
                    },
                );
            if o.count != c.count {
                node = node.diag(Diagnostic::warning(format!(
                    "{} offsets but {} byte counts",
                    o.count, c.count
                )));
            }
            cx.push(node).await;
        }
    }
    let read = |e: Entry| async move { values_of(cx, t, &e, 1).await.first()?.as_u64() };
    // JPEG XR keeps its bitstream (and an optional alpha plane) out of line.
    for (offset, count, what) in [
        (0xbcc0, 0xbcc1, "Image bitstream"),
        (0xbcc2, 0xbcc3, "Alpha bitstream"),
    ] {
        if let (Some(o), Some(c)) = (ifd.find(offset), ifd.find(count))
            && let (Some(offset), Some(len)) = (read(*o).await, read(*c).await)
        {
            cx.push(region(what, t.file(), offset, len)).await;
        }
    }
    if let (Some(o), Some(l)) = (ifd.find(0x0201), ifd.find(0x0202))
        && let (Some(offset), Some(len)) = (read(*o).await, read(*l).await)
    {
        let span = t.file().sub(offset, len);
        let name = if ifd.find(0x0100).is_none() {
            "JPEG thumbnail"
        } else {
            "JPEG image"
        };
        let mut node = embedded(name, t.input.nested(span)).summary(human_size(len));
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        cx.push(node).await;
    }
}

#[derive(Clone, Copy, Debug)]
struct Pieces {
    t: Tiff,
    offsets: Entry,
    counts: Entry,
    compression: u64,
    what: &'static str,
}

/// The codec that undoes a TIFF compression, where we have one.
fn codec(compression: u64) -> Option<Codec> {
    match compression {
        5 => Some(Codec::Lzw { early_change: true }),
        8 | 32946 => Some(Codec::Zlib),
        32773 => Some(Codec::PackBits),
        50000 => Some(Codec::Zstd),
        _ => None,
    }
}

async fn pieces(cx: Cx, st: Pieces) -> Result<()> {
    let t = st.t;
    let n = st.offsets.count.min(st.counts.count);
    cx.set_count(Count::Exact(n));
    let (os, cs) = (type_size(st.offsets.kind), type_size(st.counts.kind));
    let start = cx.resume::<u64>().unwrap_or(0);
    for i in start..n {
        cx.mark(move || i);
        let o = cx
            .read(st.offsets.data.sub(i.saturating_mul(os), os))
            .await?;
        let c = cx
            .read(st.counts.data.sub(i.saturating_mul(cs), cs))
            .await?;
        let (Some(offset), Some(len)) = (
            num(t, st.offsets.kind, &o, 0).and_then(Num::as_u64),
            num(t, st.counts.kind, &c, 0).and_then(Num::as_u64),
        ) else {
            break;
        };
        let name = format!("{} {i}", st.what);
        let span = t.file().sub(offset, len);
        let node = match (st.compression, codec(st.compression)) {
            (7 | 34892, _) => embedded(name, t.input.nested(span)),
            (_, Some(codec)) if span.len == len && len > 0 => {
                content(name, t.input, span, codec, None)
            }
            _ => region(name, t.file(), offset, len),
        };
        cx.push(node.summary(format!("{} at {offset:#x}", human_size(len))))
            .await;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct EntryState {
    t: Tiff,
    dir: Dir,
    entry: Entry,
    path: Vec<u64>,
    siblings: Siblings,
}

fn entry_fields(f: &mut Fields<'_>, st: &(Dir, bool, bool)) -> Result<()> {
    let (dir, big, inline) = *st;
    f.u16("Tag")
        .hex()
        .with(|&t, n| match dir.name(t) {
            Some(name) => n.summary(name),
            None => n,
        })
        .emit()?;
    f.u16("Type").enumeration(TYPES).emit()?;
    f.uword("Count", big).emit()?;
    if inline {
        f.bytes("Value", if big { 8 } else { 4 }).emit()?;
    } else {
        f.uword("Value offset", big).hex().emit()?;
    }
    Ok(())
}

/// The IFD a pointer tag leads to.
fn pointer(dir: Dir, tag: u16) -> Option<(&'static str, Dir)> {
    match (dir, tag) {
        (Dir::Main | Dir::Exif | Dir::PanasonicRaw, 0x8769) => Some(("Exif IFD", Dir::Exif)),
        (Dir::Main | Dir::Exif | Dir::PanasonicRaw, 0x8825) => Some(("GPS IFD", Dir::Gps)),
        (Dir::Main | Dir::Exif, 0xa005) => Some(("Interoperability IFD", Dir::Interop)),
        (Dir::Main | Dir::Exif, 0x014a) => Some(("SubIFD", Dir::Main)),
        (Dir::Maker(Note::Nikon), 0x0011) | (Dir::Maker(Note::Samsung), 0x0035) => {
            Some(("Preview IFD", Dir::Main))
        }
        (Dir::Maker(n), tag) => n.subdirectory(tag).map(|s| (s.title(), Dir::Maker(s))),
        _ => None,
    }
}

async fn entry(cx: Cx, st: EntryState) -> Result<()> {
    let t = st.t;
    let e = st.entry;
    let block = cx.block(e.span).await?;
    entry_fields(
        &mut Fields::emitting(&cx, &block, t.endian),
        &(st.dir, t.big, e.inline),
    )?;
    if let Some((name, dir)) = pointer(st.dir, e.tag) {
        return sub_ifds(&cx, &st, name, dir).await;
    }
    let input = t.input.nested(e.data);
    let ns = st.dir.ns(e.tag);
    match (ns, e.tag) {
        (Ns::Main, 0x927c) => return maker_note(&cx, &st).await,
        (Ns::Main, 0x02bc) => {
            cx.emit(embedded("XMP packet", input));
            return Ok(());
        }
        (Ns::Main, 0x8773 | 0xc68f | 0xc691) | (Ns::Other(Some(Note::Nikon)), 0x0e1d) => {
            cx.emit(embedded_as(
                "ICC profile",
                input,
                &super::icc_profile::FORMAT,
            ));
            return Ok(());
        }
        (Ns::Main, 0x83bb) => {
            cx.emit(iptc::node("IPTC-NAA records", t.input, e.data));
            return Ok(());
        }
        (Ns::Main, 0x8649) => {
            cx.emit(super::psd::resources_node(
                "Photoshop image resources",
                t.input,
                e.data,
            ));
            return Ok(());
        }
        (Ns::Main, 0x015b) => {
            cx.emit(embedded("JPEG tables", input));
            return Ok(());
        }
        (Ns::Main, 0x87af) => {
            cx.emit(geo::node(
                t,
                e,
                st.siblings.geo_doubles,
                st.siblings.geo_ascii,
            ));
            return Ok(());
        }
        (Ns::Main, 0xc740 | 0xc741 | 0xc74e) => {
            cx.emit(dng::opcodes_node(e.data));
            return Ok(());
        }
        (Ns::Main, 0xb002) => {
            cx.emit(
                Node::new("Images")
                    .span(e.data)
                    .summary(format!("{} entries", e.size / 16))
                    .lazy(mp_entries, (t, e)),
            );
            return Ok(());
        }
        (Ns::Main, 0xc4a5) | (Ns::Other(_), 0x0e00) => {
            cx.emit(Node::new("PrintIM").span(e.data).lazy(print_im, (t, e)));
            return Ok(());
        }
        _ => {}
    }
    if matches!(e.kind, 1 | 7) && !e.inline {
        let head = cx.read_avail(e.data.sub(0, 8)).await?;
        if head.starts_with(b"\xff\xd8\xff") {
            cx.emit(embedded("JPEG image", input));
            return Ok(());
        }
        if head.starts_with(b"bplist00") {
            cx.emit(embedded("Property list", input));
            return Ok(());
        }
        if head.starts_with(b"II*\x00") || head.starts_with(b"MM\x00*") {
            cx.emit(embedded("TIFF stream", input));
            return Ok(());
        }
    }
    if e.count > 1 && e.kind != 2 && e.kind != 7 && type_size(e.kind) > 0 {
        cx.emit(
            Node::new("Values")
                .span(e.data)
                .summary(format!("{} values", e.count))
                .lazy(values, (t, st.dir, e)),
        );
    } else if !e.inline {
        cx.emit(Node::new("Data").span(e.data));
    }
    Ok(())
}

/// The summary of a child IFD (Exif, GPS, maker note).
async fn child_summary(cx: &Cx, t: Tiff, dir: Dir, ifd: &Ifd) -> String {
    let text = match dir {
        Dir::Exif => summary::exif_ifd(cx, t, ifd).await,
        Dir::Gps => summary::gps(cx, t, ifd).await,
        Dir::Main | Dir::PanasonicRaw => Some(ifd_summary(cx, t, dir, ifd).await),
        Dir::Interop | Dir::Maker(_) => None,
    };
    text.unwrap_or_else(|| format!("{} entries", ifd.entries.len()))
}

async fn sub_ifds(cx: &Cx, st: &EntryState, name: &'static str, dir: Dir) -> Result<()> {
    let t = st.t;
    let e = st.entry;
    if st.path.len() >= MAX_DEPTH {
        cx.diag(Diagnostic::limit(format!(
            "IFDs nested deeper than {MAX_DEPTH}"
        )));
        return Ok(());
    }
    // An IFD stored as the value itself (Olympus subdirectories of type
    // UNDEFINED), or a list of offsets.
    let offsets: Vec<u64> = if e.kind == 7 {
        vec![e.data.offset.saturating_sub(t.file().offset)]
    } else {
        values_of(cx, t, &e, 64)
            .await
            .into_iter()
            .map_while(Num::as_u64)
            .collect()
    };
    let many = offsets.len() > 1;
    for (i, offset) in offsets.into_iter().enumerate() {
        let label = if many {
            format!("{name} #{i}")
        } else {
            name.to_owned()
        };
        let at = t.file().offset.saturating_add(offset);
        if st.path.contains(&at) {
            cx.emit(
                Node::new(label).diag(Diagnostic::malformed(format!("IFD at {offset:#x} loops"))),
            );
            continue;
        }
        let mut path = st.path.clone();
        path.push(at);
        let mut node = ifd_node(label, t, dir, offset, path);
        match read_ifd(cx, t, offset).await {
            Ok(ifd) => {
                let summary = child_summary(cx, t, dir, &ifd).await;
                node = node.span(ifd.span).summary(summary);
            }
            Err(err) => node = node.diag(err),
        }
        cx.emit(node);
    }
    Ok(())
}

/// The TIFF stream a maker note's IFD lives in, and the IFD's offset in it.
fn maker_stream(t: Tiff, data: Span, layout: &maker::Layout) -> (Tiff, u64) {
    let at = data.offset.saturating_sub(t.file().offset);
    let endian = layout.endian.unwrap_or(t.endian);
    match layout.base {
        maker::Base::Outer => (Tiff { endian, ..t }, at.saturating_add(layout.ifd)),
        maker::Base::Note(k) => (
            Tiff {
                base: t.file().tail(at.saturating_add(k)),
                endian,
                big: false,
                ..t
            },
            layout.ifd.saturating_sub(k),
        ),
    }
}

/// Opens the maker note in `e`: its layout, stream and IFD offset.
async fn open_maker(cx: &Cx, t: Tiff, e: &Entry) -> Option<(maker::Layout, Tiff, u64)> {
    let head = cx.read_avail(e.data.sub(0, 32)).await.ok()?;
    let layout = maker::layout(&head, t.make, t.endian)?;
    let (mt, offset) = maker_stream(t, e.data, &layout);
    Some((layout, mt, offset))
}

async fn maker_note(cx: &Cx, st: &EntryState) -> Result<()> {
    let t = st.t;
    let e = st.entry;
    let Some((layout, mt, offset)) = open_maker(cx, t, &e).await else {
        cx.emit(
            Node::new("Data")
                .span(e.data)
                .diag(Diagnostic::unsupported("maker note in an unknown layout")),
        );
        return Ok(());
    };
    if layout.header > 0 {
        let head = e.data.sub(0, layout.header);
        let bytes = cx.read_avail(head).await?;
        let signature = crate::text::latin1(bytes.split(|&b| b == 0).next().unwrap_or_default());
        cx.emit(
            Node::new("Header")
                .span(head)
                .value(Value::Text(signature.trim().to_owned()))
                .summary(layout.label),
        );
    }
    if let maker::Base::Note(k) = layout.base
        && k > 0
    {
        // Nikon type 3: a TIFF header of its own.
        let span = e.data.sub(k, 8);
        let ctx = HeaderCtx {
            big: false,
            cr2: false,
        };
        cx.emit(struct_node("TIFF header", span, mt.endian, ctx, header));
    }
    let at = mt.file().offset.saturating_add(offset);
    if st.path.len() >= MAX_DEPTH || st.path.contains(&at) {
        return Ok(());
    }
    let mut path = st.path.clone();
    path.push(at);
    let dir = Dir::Maker(layout.note);
    let mut node = ifd_node(layout.note.title(), mt, dir, offset, path);
    match read_ifd(cx, mt, offset).await {
        Ok(ifd) => {
            node = node.span(ifd.span).summary(format!(
                "{}, {} entries",
                layout.label,
                ifd.entries.len()
            ));
        }
        Err(err) => node = node.diag(err),
    }
    cx.emit(node);
    Ok(())
}

async fn values(cx: Cx, (t, dir, e): (Tiff, Dir, Entry)) -> Result<()> {
    let size = type_size(e.kind);
    let note = match dir {
        Dir::Maker(n) => Some(n),
        _ => None,
    };
    let names = note.and_then(|n| maker::array_fields(n, e.tag));
    let main = dir.ns(e.tag) == Ns::Main;
    cx.set_count(Count::Exact(e.count));
    let start = cx.resume::<u64>().unwrap_or(0);
    for i in start..e.count {
        cx.mark(move || i);
        let span = e.data.sub(i.saturating_mul(size), size);
        let bytes = cx.read(span).await?;
        let Some(v) = num(t, e.kind, &bytes, 0) else {
            break;
        };
        let name = names
            .and_then(|table| lookup(table, i))
            .map_or_else(|| format!("[{i}]"), str::to_owned);
        let table = match (note, main) {
            (Some(n), _) => maker::array_enum(n, e.tag, i),
            (None, true) => super::tiff_tags::enumeration(e.tag),
            _ => None,
        };
        let value = match (table, v.as_u64()) {
            (Some(table), Some(raw)) => Value::Enum {
                raw,
                bits: u8::try_from(size.saturating_mul(8)).unwrap_or(64),
                name: lookup(table, raw),
            },
            _ => v.to_value(main && is_offset_tag(e.tag)),
        };
        let mut node = Node::new(name).span(span).value(value);
        if matches!(v, Num::R(_, d) if d != 1) || matches!(v, Num::S(_, d) if d != 1) {
            node = node.summary(v.to_string());
        }
        cx.push(node).await;
    }
    Ok(())
}

/// MPF image entries: attributes, size, offset, dependent images.
async fn mp_entries(cx: Cx, (t, e): (Tiff, Entry)) -> Result<()> {
    let n = e.data.len / 16;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let span = e.data.sub(i.saturating_mul(16), 16);
        let block = cx.block(span).await?;
        let mut f = Fields::new(&block, t.endian);
        let attr = f.u32("Attributes").get()?;
        let size = f.u32("Size").get()?;
        let offset = f.u32("Offset").get()?;
        let kind = lookup(MP_TYPES, u64::from(attr & 0x00ff_ffff)).unwrap_or("Unknown type");
        cx.push(
            Node::new(format!("Image {}", i.saturating_add(1)))
                .span(span)
                .summary(format!(
                    "{kind}, {} at {offset:#x}",
                    human_size(size.into())
                ))
                .lazy(mp_entry, (span, t.endian)),
        )
        .await;
    }
    Ok(())
}

async fn mp_entry(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.u32("Attributes")
        .hex()
        .with(|&a, n| {
            let mut parts = Vec::new();
            if a & 0x8000_0000 != 0 {
                parts.push("dependent parent");
            }
            if a & 0x4000_0000 != 0 {
                parts.push("dependent child");
            }
            if a & 0x2000_0000 != 0 {
                parts.push("representative");
            }
            parts.push(if a & 0x0700_0000 == 0 {
                "JPEG"
            } else {
                "other format"
            });
            parts.push(lookup(MP_TYPES, u64::from(a & 0x00ff_ffff)).unwrap_or("unknown type"));
            n.summary(parts.join(", "))
        })
        .emit()?;
    f.u32("Size").emit()?;
    f.u32("Offset")
        .hex()
        .desc("From the MP header (0 for the first image)")
        .emit()?;
    f.u16("Dependent image 1").emit()?;
    f.u16("Dependent image 2").emit()?;
    Ok(())
}

/// Epson's Print Image Matching block: "PrintIM", a version and entries.
async fn print_im(cx: Cx, (t, e): (Tiff, Entry)) -> Result<()> {
    let block = cx.block(e.data.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, t.endian);
    f.ascii("Signature", 8).emit()?;
    f.ascii("Version", 4).emit()?;
    f.u16("Reserved").emit()?;
    let n = f.u16("Entry count").emit()?;
    let entries = e.data.sub(16, u64::from(n).saturating_mul(6));
    let bytes = cx.read_avail(entries).await?;
    for (i, chunk) in bytes.as_chunks::<6>().0.iter().enumerate() {
        let tag = t.uint(chunk, 2).unwrap_or(0);
        let value = chunk.get(2..).and_then(|v| t.uint(v, 4)).unwrap_or(0);
        cx.push(
            Node::new(format!("Entry {tag:#06x}"))
                .span(entries.sub(to_u64(i).saturating_mul(6), 6))
                .value(super::hex(value)),
        )
        .await;
    }
    Ok(())
}
