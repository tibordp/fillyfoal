//! TIFF and BigTIFF, plus the camera raw formats built on them (DNG, CR2,
//! NEF, ARW, ORF, RW2, PEF, SRW). Also serves EXIF blocks embedded in JPEG,
//! PNG, WebP and HEIF, which are TIFF streams.
//!
//! The header points at a chain of image file directories (IFDs). Each IFD
//! is a counted array of 12-byte (BigTIFF: 20-byte) entries `tag, type,
//! count, value-or-offset`. The top level lists the chain; expanding an IFD
//! lists its entries with decoded values; expanding an entry shows its raw
//! fields, its out-of-line data and, for pointer tags (EXIF, GPS, Interop,
//! SubIFDs), the IFDs it points to.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Prim, struct_node};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, decode_flags, lookup};

use super::tiff_tags::{
    COMPRESSION, FLASH_FLAGS, GPS_TAGS, INTEROP_TAGS, SUBFILE_FLAGS, TAGS, TYPES, enumeration,
};
use super::{dims, region};

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

tiff_variant!(DNG, "dng", "Adobe Digital Negative", ["dng"], "image/x-adobe-dng", |h| {
    ifd0(h).is_some_and(|ifd| ifd.has(0xc612))
});
tiff_variant!(CR2, "cr2", "Canon raw (CR2)", ["cr2"], "image/x-canon-cr2", |h| {
    classic(h) && h.at(8, b"CR\x02\x00")
});
tiff_variant!(NEF, "nef", "Nikon raw (NEF)", ["nef", "nrw"], "image/x-nikon-nef", |h| {
    ifd0(h).is_some_and(|ifd| ifd.make_starts_with(b"NIKON"))
});
tiff_variant!(ARW, "arw", "Sony raw (ARW)", ["arw", "srf", "sr2"], "image/x-sony-arw", |h| {
    ifd0(h).is_some_and(|ifd| ifd.make_starts_with(b"SONY"))
});
tiff_variant!(PEF, "pef", "Pentax raw (PEF)", ["pef"], "image/x-pentax-pef", |h| {
    ifd0(h).is_some_and(|ifd| ifd.make_starts_with(b"PENTAX") || ifd.make_starts_with(b"RICOH"))
});
tiff_variant!(SRW, "srw", "Samsung raw (SRW)", ["srw"], "image/x-samsung-srw", |h| {
    ifd0(h).is_some_and(|ifd| ifd.make_starts_with(b"SAMSUNG"))
});
tiff_variant!(ORF, "orf", "Olympus raw (ORF)", ["orf"], "image/x-olympus-orf", |h| {
    h.starts_with(b"IIRO\x08\x00\x00\x00")
        || h.starts_with(b"IIRS\x08\x00\x00\x00")
        || h.starts_with(b"MMOR\x00\x00\x00\x08")
});
tiff_variant!(RW2, "rw2", "Panasonic raw (RW2)", ["rw2", "rwl"], "image/x-panasonic-rw2", |h| {
    h.starts_with(b"IIU\x00\x18\x00\x00\x00")
});
tiff_variant!(JXR, "jxr", "JPEG XR (HD Photo)", ["jxr", "wdp", "hdp"], "image/jxr", |h| {
    h.starts_with(b"II\xbc\x01")
});

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

/// Byte order and offset width of a TIFF stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tiff {
    input: Input,
    endian: Endian,
    big: bool,
}

impl Tiff {
    fn file(&self) -> Span {
        self.input.span
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
}

impl Dir {
    fn tags(self) -> EnumTable {
        match self {
            Dir::Main | Dir::Exif => TAGS,
            Dir::Gps => GPS_TAGS,
            Dir::Interop => INTEROP_TAGS,
        }
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

impl Num {
    fn as_u64(self) -> Option<u64> {
        match self {
            Num::U(v) => Some(v),
            Num::I(v) => u64::try_from(v).ok(),
            _ => None,
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
            #[allow(clippy::cast_precision_loss)]
            Num::R(n, d) => Value::Float(if d == 0 { 0.0 } else { n as f64 / d as f64 }),
            #[allow(clippy::cast_precision_loss)]
            Num::S(n, d) => Value::Float(if d == 0 { 0.0 } else { n as f64 / d as f64 }),
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

/// How many values a summary shows.
const PREVIEW: u64 = 8;

/// Tags whose values are file offsets.
fn is_offset_tag(tag: u16) -> bool {
    matches!(
        tag,
        0x0111 | 0x0144 | 0x0201 | 0x014a | 0x8769 | 0x8825 | 0xa005 | 0x0120 | 0xbcc0 | 0xbcc2
    )
}

/// The value and summary shown for an entry.
async fn describe(cx: &Cx, t: Tiff, dir: Dir, e: &Entry) -> (Option<Value>, Option<String>) {
    let preview_len = match e.kind {
        2 | 7 | 1 => e.size.min(256),
        _ => type_size(e.kind).saturating_mul(e.count.min(PREVIEW)),
    };
    let Ok(bytes) = cx.read_avail(e.data.sub(0, preview_len)).await else {
        return (None, None);
    };
    let main = dir != Dir::Gps && dir != Dir::Interop;
    if e.kind == 2 {
        let text = crate::text::latin1(bytes.split(|&b| b == 0).next().unwrap_or_default());
        return (Some(Value::Text(text)), None);
    }
    if main && (0x9c9b..=0x9c9f).contains(&e.tag) {
        let text = crate::text::utf16z(&bytes, Endian::Little).0;
        return (Some(Value::Text(text)), None);
    }
    if main && e.tag == 0x9286 && bytes.len() >= 8 {
        let (charset, rest) = bytes.split_at(8);
        let text = if charset.starts_with(b"UNICODE") {
            crate::text::utf16z(rest, t.endian).0
        } else {
            crate::text::until_nul(rest)
        };
        return (Some(Value::Text(text)), Some(crate::text::until_nul(charset)));
    }
    if matches!(e.kind, 1 | 7) && e.count > 1 {
        let printable = bytes
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b' ' || b == 0);
        if printable && e.count <= 64 && bytes.first().is_some_and(u8::is_ascii_graphic) {
            return (Some(Value::Text(crate::text::until_nul(&bytes))), None);
        }
        let shown = bytes.get(..bytes.len().min(32)).unwrap_or_default().to_vec();
        return (Some(Value::Bytes(shown)), Some(format!("{} bytes", e.count)));
    }
    let values: Vec<Num> = (0..usize::try_from(e.count.min(PREVIEW)).unwrap_or(0))
        .map_while(|i| num(t, e.kind, &bytes, i))
        .collect();
    if e.count == 1
        && let Some(&v) = values.first()
    {
        let raw = v.as_u64();
        if main
            && let (Some(table), Some(raw)) = (enumeration(e.tag), raw)
        {
            let bits = u8::try_from(type_size(e.kind).saturating_mul(8)).unwrap_or(64);
            let name = lookup(table, raw);
            return (Some(Value::Enum { raw, bits, name }), None);
        }
        if main
            && let Some(raw) = raw
            && let Some(flags) = match e.tag {
                0x00fe => Some(SUBFILE_FLAGS),
                0x9209 => Some(FLASH_FLAGS),
                _ => None,
            }
        {
            let (set, unknown) = decode_flags(flags, raw);
            return (
                Some(Value::Flags {
                    raw,
                    bits: 32,
                    set,
                    unknown,
                }),
                None,
            );
        }
        let summary = match v {
            Num::R(..) | Num::S(..) => Some(v.to_string()),
            _ => None,
        };
        return (Some(v.to_value(main && is_offset_tag(e.tag))), summary);
    }
    let mut list: Vec<String> = values.iter().map(ToString::to_string).collect();
    if e.count > PREVIEW {
        list.push(format!("… ({} values)", e.count));
    }
    (None, Some(format!("[{}]", list.join(", "))))
}

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let endian = match head.get(..2) {
        Some(b"II") => Endian::Little,
        Some(b"MM") => Endian::Big,
        _ => return Err(Diagnostic::malformed("bad byte order mark").at(file.sub(0, 2))),
    };
    let magic = u16::decode(head.get(2..4).unwrap_or_default(), endian).unwrap_or(0);
    let big = magic == 43;
    let header_len = if big { 16 } else { 8 };
    let header_span = file.sub(0, header_len);
    let block = cx.block(header_span).await?;
    let first = header(&mut Fields::new(&block, endian), &big)?;
    cx.emit(struct_node("Header", header_span, endian, big, header));
    let t = Tiff { input, endian, big };

    let mut offset = first;
    let mut seen = Vec::new();
    while offset != 0 {
        let index = seen.len();
        if seen.contains(&offset) {
            cx.diag(Diagnostic::malformed(format!("IFD chain loops back to {offset:#x}")));
            break;
        }
        if index >= MAX_IFDS {
            cx.diag(Diagnostic::limit(format!("more than {MAX_IFDS} IFDs")));
            break;
        }
        seen.push(offset);
        let name = format!("IFD{index}");
        let ifd = match read_ifd(&cx, t, offset).await {
            Ok(ifd) => ifd,
            Err(e) => {
                cx.push(Node::new(name).diag(e)).await;
                break;
            }
        };
        let summary = ifd_summary(&cx, t, &ifd).await;
        if index == 0 {
            let kind = match magic {
                43 => "BigTIFF",
                0x4f52 | 0x5352 => "ORF",
                0x55 => "RW2",
                0x01bc => "JPEG XR",
                _ if ifd.find(0xc612).is_some() => "DNG",
                _ => "TIFF",
            };
            let endian = if endian == Endian::Little { "LE" } else { "BE" };
            cx.annotate(format!("{kind} {endian}, {summary}"));
        }
        cx.push(
            ifd_node(name, t, Dir::Main, offset, vec![offset])
                .span(ifd.span)
                .summary(summary),
        )
        .await;
        offset = ifd.next;
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

fn header(f: &mut Fields<'_>, big: &bool) -> Result<u64> {
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
    if *big {
        f.u16("Offset size").emit()?;
        f.u16("Reserved").emit()?;
    }
    f.uword("First IFD offset", *big).hex().emit()
}

/// "640×480, 8-bit RGB, LZW" (plus camera make and model when present).
async fn ifd_summary(cx: &Cx, t: Tiff, ifd: &Ifd) -> String {
    let mut parts = Vec::new();
    let first = |tag: u16| async move {
        let e = ifd.find(tag)?;
        let bytes = cx.read_avail(e.data.sub(0, 8)).await.ok()?;
        num(t, e.kind, &bytes, 0)?.as_u64()
    };
    if let Some(camera) = camera_of(cx, ifd).await {
        parts.push(camera);
    }
    if let (Some(w), Some(h)) = (first(0x0100).await, first(0x0101).await) {
        parts.push(dims(w, h));
    } else if let (Some(w), Some(h)) = (first(0xbc80).await, first(0xbc81).await) {
        parts.push(dims(w, h));
    }
    if let Some(bits) = first(0x0102).await {
        let photometric = first(0x0106)
            .await
            .and_then(|p| enumeration(0x0106).and_then(|t| lookup(t, p)));
        parts.push(match photometric {
            Some(p) => format!("{bits}-bit {p}"),
            None => format!("{bits}-bit"),
        });
    }
    if let Some(c) = first(0x0103).await {
        parts.push(lookup(COMPRESSION, c).map_or_else(|| format!("compression {c}"), str::to_owned));
    }
    if first(0x00fe).await.is_some_and(|v| v & 1 != 0) {
        parts.push("reduced resolution".to_owned());
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
    let text = |tag: u16| async move {
        let e = ifd.find(tag).filter(|e| e.kind == 2)?;
        let bytes = cx.read_avail(e.data.sub(0, 64)).await.ok()?;
        Some(crate::text::until_nul(&bytes).trim().to_owned())
    };
    let make = text(0x010f).await.unwrap_or_default();
    let model = text(0x0110).await.unwrap_or_default();
    let camera = if model.starts_with(&make) || make.is_empty() {
        model
    } else {
        format!("{make} {model}")
    };
    (!camera.is_empty()).then_some(camera)
}

/// The camera that wrote a TIFF stream (e.g. the Exif block of a JPEG), for
/// summaries of the files that embed it.
pub async fn camera(cx: &Cx, input: Input) -> Option<String> {
    let head = cx.read_avail(input.span.sub(0, 8)).await.ok()?;
    let endian = match head.get(..2)? {
        b"II" => Endian::Little,
        b"MM" => Endian::Big,
        _ => return None,
    };
    let first = u32::decode(head.get(4..8)?, endian)?;
    let t = Tiff {
        input,
        endian,
        big: false,
    };
    let ifd = read_ifd(cx, t, first.into()).await.ok()?;
    camera_of(cx, &ifd).await
}

#[derive(Clone, Debug)]
struct IfdState {
    t: Tiff,
    dir: Dir,
    offset: u64,
    path: Vec<u64>,
}

fn ifd_node(name: impl Into<std::borrow::Cow<'static, str>>, t: Tiff, dir: Dir, offset: u64, path: Vec<u64>) -> Node {
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
    for e in &ifd.entries {
        let name = lookup(st.dir.tags(), e.tag.into())
            .map_or_else(|| format!("Tag {:#06x}", e.tag), str::to_owned);
        let (value, summary) = describe(&cx, t, st.dir, e).await;
        let mut node = Node::new(name).span(e.span);
        if let Some(v) = value {
            node = node.value(v);
        }
        if let Some(s) = summary {
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
            node = node.diag(Diagnostic::malformed(format!("unknown field type {}", e.kind)));
        }
        let state = EntryState {
            t,
            dir: st.dir,
            entry: *e,
            path: st.path.clone(),
        };
        cx.push(node.lazy(crate::expander!(self::entry: EntryState), state))
            .await;
    }
    let next_span = ifd.span.tail(ifd.span.len.saturating_sub(t.offset_len()));
    let block = cx.block(next_span).await?;
    Fields::emitting(&cx, &block, t.endian)
        .uword("Next IFD offset", t.big)
        .hex()
        .emit()?;
    if st.dir == Dir::Main {
        image_data(&cx, t, &ifd).await;
    }
    Ok(())
}

/// Strips, tiles and the JPEG thumbnail of an IFD.
async fn image_data(cx: &Cx, t: Tiff, ifd: &Ifd) {
    let compression = match ifd.find(0x0103) {
        Some(e) => {
            let bytes = cx.read_avail(e.data.sub(0, 8)).await.unwrap_or_default();
            num(t, e.kind, &bytes, 0).and_then(Num::as_u64).unwrap_or(1)
        }
        None => 1,
    };
    for (offsets, counts, what) in [(0x0111, 0x0117, "Strips"), (0x0144, 0x0145, "Tiles")] {
        if let (Some(o), Some(c)) = (ifd.find(offsets), ifd.find(counts)) {
            let n = o.count.min(c.count);
            let node = Node::new(what)
                .summary(format!("{n} {}", what.to_lowercase()))
                .lazy(pieces, (t, *o, *c, compression));
            cx.push(node).await;
        }
    }
    // JPEG XR keeps its bitstream (and an optional alpha plane) out of line.
    for (offset, count, what) in [(0xbcc0, 0xbcc1, "Image bitstream"), (0xbcc2, 0xbcc3, "Alpha bitstream")] {
        if let (Some(o), Some(c)) = (ifd.find(offset), ifd.find(count)) {
            let read = |e: Entry| async move {
                let bytes = cx.read_avail(e.data.sub(0, 8)).await.ok()?;
                num(t, e.kind, &bytes, 0)?.as_u64()
            };
            if let (Some(offset), Some(len)) = (read(*o).await, read(*c).await) {
                cx.push(region(what, t.file(), offset, len)).await;
            }
        }
    }
    if let (Some(o), Some(l)) = (ifd.find(0x0201), ifd.find(0x0202)) {
        let read = |e: Entry| async move {
            let bytes = cx.read_avail(e.data.sub(0, 8)).await.ok()?;
            num(t, e.kind, &bytes, 0)?.as_u64()
        };
        if let (Some(offset), Some(len)) = (read(*o).await, read(*l).await) {
            let span = t.file().sub(offset, len);
            cx.push(embedded("JPEG thumbnail", t.input.nested(span))).await;
        }
    }
}

async fn pieces(cx: Cx, (t, offsets, counts, compression): (Tiff, Entry, Entry, u64)) -> Result<()> {
    let n = offsets.count.min(counts.count);
    cx.set_count(Count::Exact(n));
    let (os, cs) = (type_size(offsets.kind), type_size(counts.kind));
    for i in 0..n {
        let o = cx.read(offsets.data.sub(i.saturating_mul(os), os)).await?;
        let c = cx.read(counts.data.sub(i.saturating_mul(cs), cs)).await?;
        let (Some(offset), Some(len)) = (
            num(t, offsets.kind, &o, 0).and_then(Num::as_u64),
            num(t, counts.kind, &c, 0).and_then(Num::as_u64),
        ) else {
            break;
        };
        let name = format!("[{i}]");
        let node = if compression == 7 {
            embedded(name, t.input.nested(t.file().sub(offset, len)))
        } else {
            region(name, t.file(), offset, len)
        };
        cx.push(node.summary(format!("{len:#x} bytes at {offset:#x}"))).await;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct EntryState {
    t: Tiff,
    dir: Dir,
    entry: Entry,
    path: Vec<u64>,
}

fn entry_fields(f: &mut Fields<'_>, st: &(Dir, bool, bool)) -> Result<()> {
    let (dir, big, inline) = *st;
    f.u16("Tag")
        .hex()
        .with(|&t, n| match lookup(dir.tags(), t.into()) {
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

async fn entry(cx: Cx, st: EntryState) -> Result<()> {
    let t = st.t;
    let e = st.entry;
    let block = cx.block(e.span).await?;
    entry_fields(
        &mut Fields::emitting(&cx, &block, t.endian),
        &(st.dir, t.big, e.inline),
    )?;
    let main = st.dir == Dir::Main || st.dir == Dir::Exif;
    let target = match (main, e.tag) {
        (true, 0x8769) => Some(("Exif IFD", Dir::Exif)),
        (true, 0x8825) => Some(("GPS IFD", Dir::Gps)),
        (true, 0xa005) => Some(("Interoperability IFD", Dir::Interop)),
        (true, 0x014a) => Some(("SubIFD", Dir::Main)),
        _ => None,
    };
    if let Some((name, dir)) = target {
        if st.path.len() >= MAX_DEPTH {
            cx.diag(Diagnostic::limit(format!("IFDs nested deeper than {MAX_DEPTH}")));
            return Ok(());
        }
        let size = type_size(e.kind);
        let n = e.count.min(64);
        for i in 0..n {
            let bytes = cx.read(e.data.sub(i.saturating_mul(size), size)).await?;
            let Some(offset) = num(t, e.kind, &bytes, 0).and_then(Num::as_u64) else {
                break;
            };
            let label = if e.count > 1 {
                format!("{name} #{i}")
            } else {
                name.to_owned()
            };
            if st.path.contains(&offset) {
                cx.emit(
                    Node::new(label)
                        .diag(Diagnostic::malformed(format!("IFD at {offset:#x} loops"))),
                );
                continue;
            }
            let mut path = st.path.clone();
            path.push(offset);
            cx.emit(ifd_node(label, t, dir, offset, path));
        }
        return Ok(());
    }
    let embedded_name = match (main, e.tag) {
        (true, 0x02bc) => Some("XMP packet"),
        (true, 0x8773) => Some("ICC profile"),
        (true, 0x83bb) => Some("IPTC data"),
        (true, 0x8649) => Some("Photoshop image resources"),
        _ => None,
    };
    if let Some(name) = embedded_name {
        cx.emit(embedded(name, t.input.nested(e.data)));
        return Ok(());
    }
    if e.count > 1 && e.kind != 2 && e.kind != 7 && type_size(e.kind) > 0 {
        cx.emit(
            Node::new("Values")
                .span(e.data)
                .summary(format!("{} values", e.count))
                .lazy(values, (t, e)),
        );
    } else if !e.inline {
        cx.emit(Node::new("Data").span(e.data));
    }
    Ok(())
}

async fn values(cx: Cx, (t, e): (Tiff, Entry)) -> Result<()> {
    let size = type_size(e.kind);
    cx.set_count(Count::Exact(e.count));
    for i in 0..e.count {
        let span = e.data.sub(i.saturating_mul(size), size);
        let bytes = cx.read(span).await?;
        let Some(v) = num(t, e.kind, &bytes, 0) else {
            break;
        };
        let mut node = Node::new(format!("[{i}]"))
            .span(span)
            .value(v.to_value(is_offset_tag(e.tag)));
        if matches!(v, Num::R(..) | Num::S(..)) {
            node = node.summary(v.to_string());
        }
        cx.push(node).await;
    }
    Ok(())
}
