//! JPEG (JFIF, Exif and friends).
//!
//! A JPEG file is a sequence of marker segments. Most carry a 16-bit length;
//! SOI, EOI and RSTn do not. After a start-of-scan (SOS) segment comes
//! entropy-coded data, which ends at the next marker that is not a stuffed
//! `FF 00` or a restart marker. The top level lists segments (paged);
//! expanding one decodes it. APP1 Exif is a TIFF stream, handed to the TIFF
//! dissector; data after EOI is identified separately.

use crate::bytes::{to_u64, u16_be};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Format, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

use super::{dims, text};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "jpeg",
    title: "JPEG image",
    extensions: &["jpg", "jpeg", "jpe", "jfif", "jif"],
    mime: "image/jpeg",
    probe: Probe::Magic(&[(0, b"\xff\xd8\xff")]),
    dissect: crate::expander!(dissect: Input),
};

const MARKERS: EnumTable = &[
    (0x01, "TEM"),
    (0xc0, "SOF0"),
    (0xc1, "SOF1"),
    (0xc2, "SOF2"),
    (0xc3, "SOF3"),
    (0xc4, "DHT"),
    (0xc5, "SOF5"),
    (0xc6, "SOF6"),
    (0xc7, "SOF7"),
    (0xc8, "JPG"),
    (0xc9, "SOF9"),
    (0xca, "SOF10"),
    (0xcb, "SOF11"),
    (0xcc, "DAC"),
    (0xcd, "SOF13"),
    (0xce, "SOF14"),
    (0xcf, "SOF15"),
    (0xd0, "RST0"),
    (0xd1, "RST1"),
    (0xd2, "RST2"),
    (0xd3, "RST3"),
    (0xd4, "RST4"),
    (0xd5, "RST5"),
    (0xd6, "RST6"),
    (0xd7, "RST7"),
    (0xd8, "SOI"),
    (0xd9, "EOI"),
    (0xda, "SOS"),
    (0xdb, "DQT"),
    (0xdc, "DNL"),
    (0xdd, "DRI"),
    (0xde, "DHP"),
    (0xdf, "EXP"),
    (0xe0, "APP0"),
    (0xe1, "APP1"),
    (0xe2, "APP2"),
    (0xe3, "APP3"),
    (0xe4, "APP4"),
    (0xe5, "APP5"),
    (0xe6, "APP6"),
    (0xe7, "APP7"),
    (0xe8, "APP8"),
    (0xe9, "APP9"),
    (0xea, "APP10"),
    (0xeb, "APP11"),
    (0xec, "APP12"),
    (0xed, "APP13"),
    (0xee, "APP14"),
    (0xef, "APP15"),
    (0xf7, "SOF55"),
    (0xf8, "LSE"),
    (0xfe, "COM"),
];

const FRAME_TYPES: EnumTable = &[
    (0xc0, "baseline DCT"),
    (0xc1, "extended sequential DCT"),
    (0xc2, "progressive DCT"),
    (0xc3, "lossless"),
    (0xc5, "differential sequential DCT"),
    (0xc6, "differential progressive DCT"),
    (0xc7, "differential lossless"),
    (0xc9, "extended sequential DCT, arithmetic"),
    (0xca, "progressive DCT, arithmetic"),
    (0xcb, "lossless, arithmetic"),
    (0xcd, "differential sequential DCT, arithmetic"),
    (0xce, "differential progressive DCT, arithmetic"),
    (0xcf, "differential lossless, arithmetic"),
    (0xf7, "JPEG-LS"),
];

const DENSITY_UNITS: EnumTable = &[
    (0, "aspect ratio only"),
    (1, "dots per inch"),
    (2, "dots per cm"),
];

const JFXX_CODES: EnumTable = &[
    (0x10, "JPEG thumbnail"),
    (0x11, "1-byte-per-pixel palettized thumbnail"),
    (0x13, "3-byte-per-pixel RGB thumbnail"),
];

const ADOBE_TRANSFORM: EnumTable = &[(0, "none (RGB or CMYK)"), (1, "YCbCr"), (2, "YCCK")];

const EXIF: &[u8] = b"Exif\0";
const XMP: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
const XMP_EXTENSION: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
const ICC: &[u8] = b"ICC_PROFILE\0";
const PHOTOSHOP: &[u8] = b"Photoshop 3.0\0";

fn is_sof(marker: u8) -> bool {
    lookup(FRAME_TYPES, marker.into()).is_some()
}

fn standalone(marker: u8) -> bool {
    matches!(marker, 0x01 | 0xd0..=0xd9)
}

fn marker_name(marker: u8) -> String {
    lookup(MARKERS, marker.into()).map_or_else(|| format!("Marker {marker:#04x}"), str::to_owned)
}

/// One marker segment, as found by the walker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Segment {
    marker: u8,
    /// From the `FF` of the marker to the end of the payload.
    span: Span,
}

impl Segment {
    /// The payload after marker and length.
    fn payload(&self) -> Span {
        self.span.tail(4)
    }
}

/// Reads the segment starting at the cursor (which points at `FF`), skipping
/// fill bytes. Returns `None` if the cursor does not point at a marker.
async fn next_segment(cur: &mut Cursor<'_>) -> Result<Option<Segment>> {
    let start = cur.pos();
    if cur.u8().await? != 0xff {
        cur.seek(start);
        return Ok(None);
    }
    let mut marker = cur.u8().await?;
    while marker == 0xff {
        marker = cur.u8().await?;
    }
    // Fill bytes belong to the segment's span; the marker is the last two
    // bytes before the length.
    let marker_at = cur.pos().saturating_sub(2);
    if !standalone(marker) {
        let len = cur.u16().await?;
        cur.skip(u64::from(len).saturating_sub(2));
    }
    let span = cur
        .region()
        .sub(marker_at, cur.pos().saturating_sub(marker_at));
    Ok(Some(Segment { marker, span }))
}

/// Finds the end of entropy-coded data starting at `start`: the position of
/// the next marker other than `FF 00` and RSTn (or the end of the region).
async fn scan_entropy(cx: &Cx, region: Span, start: u64) -> Result<u64> {
    const STEP: u64 = 0x4000;
    let mut pos = start;
    loop {
        let chunk = cx.read_avail(region.sub(pos, STEP)).await?;
        if chunk.len() < 2 {
            return Ok(region.len);
        }
        let mut i = 0usize;
        let mut resume = None;
        while let Some(off) = chunk
            .get(i..)
            .and_then(|c| c.iter().position(|&b| b == 0xff))
        {
            let at = i.saturating_add(off);
            match chunk.get(at.saturating_add(1)) {
                None => {
                    resume = Some(at);
                    break;
                }
                Some(0x00 | 0xd0..=0xd7) => i = at.saturating_add(2),
                Some(_) => return Ok(pos.saturating_add(to_u64(at))),
            }
        }
        let advance = resume.unwrap_or(chunk.len());
        if advance == 0 {
            return Ok(region.len);
        }
        pos = pos.saturating_add(to_u64(advance));
    }
}

#[derive(Clone, Debug, Default)]
struct Frame {
    marker: u8,
    width: u16,
    height: u16,
    precision: u8,
    /// (id, horizontal, vertical sampling factor)
    components: Vec<(u8, u8, u8)>,
}

impl Frame {
    fn describe(&self) -> String {
        let kind = lookup(FRAME_TYPES, self.marker.into()).unwrap_or("unknown");
        let mut out = format!("{}, {kind}", dims(self.width, self.height));
        if self.precision != 8 {
            out = format!("{out}, {}-bit", self.precision);
        }
        let n = self.components.len();
        let colors = match n {
            1 => "grayscale".to_owned(),
            3 => format!("YCbCr {}", self.subsampling()),
            4 => "CMYK".to_owned(),
            _ => format!("{n} components"),
        };
        format!("{out}, {colors}")
    }

    fn subsampling(&self) -> &'static str {
        let (Some(&(_, yh, yv)), Some(&(_, ch, cv))) =
            (self.components.first(), self.components.get(1))
        else {
            return "";
        };
        match (yh.checked_div(ch), yv.checked_div(cv)) {
            (Some(1), Some(1)) => "4:4:4",
            (Some(2), Some(1)) => "4:2:2",
            (Some(2), Some(2)) => "4:2:0",
            (Some(1), Some(2)) => "4:4:0",
            (Some(4), Some(1)) => "4:1:1",
            _ => "(unusual subsampling)",
        }
    }
}

fn frame_header(f: &mut Fields<'_>, _: &()) -> Result<Frame> {
    let precision = f.u8("Sample precision").desc("Bits per sample").emit()?;
    let height = f.u16("Height").desc("Lines (0: defined by DNL)").emit()?;
    let width = f.u16("Width").desc("Samples per line").emit()?;
    let count = f.u8("Components").emit()?;
    let mut components = Vec::new();
    for _ in 0..count {
        if f.remaining() < 3 {
            break;
        }
        let id = f.u8("Component ID").emit()?;
        let sampling = f
            .u8("Sampling factors")
            .hex()
            .with(|&s, n| n.summary(format!("{}×{}", s >> 4, s & 15)))
            .emit()?;
        f.u8("Quantization table").emit()?;
        components.push((id, sampling >> 4, sampling & 15));
    }
    Ok(Frame {
        marker: 0,
        width,
        height,
        precision,
        components,
    })
}

fn scan_header(f: &mut Fields<'_>, _: &()) -> Result<u8> {
    let count = f.u8("Components in scan").emit()?;
    for _ in 0..count {
        if f.remaining() < 2 {
            break;
        }
        f.u8("Component selector").emit()?;
        f.u8("Entropy tables")
            .hex()
            .with(|&t, n| n.summary(format!("DC {}, AC {}", t >> 4, t & 15)))
            .emit()?;
    }
    f.u8("Spectral selection start").emit()?;
    f.u8("Spectral selection end").emit()?;
    f.u8("Successive approximation")
        .hex()
        .with(|&a, n| n.summary(format!("high {}, low {}", a >> 4, a & 15)))
        .emit()?;
    Ok(count)
}

/// JFIF APP0 fields; returns the thumbnail dimensions.
fn jfif(f: &mut Fields<'_>, _: &()) -> Result<(u8, u8)> {
    f.ascii("Identifier", 5).emit()?;
    f.u8("Major version").emit()?;
    f.u8("Minor version").emit()?;
    f.u8("Density units").enumeration(DENSITY_UNITS).emit()?;
    f.u16("X density").emit()?;
    f.u16("Y density").emit()?;
    let w = f.u8("Thumbnail width").emit()?;
    let h = f.u8("Thumbnail height").emit()?;
    Ok((w, h))
}

fn adobe(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Identifier", 5).emit()?;
    f.u16("Version").emit()?;
    f.u16("Flags 0").hex().emit()?;
    f.u16("Flags 1").hex().emit()?;
    f.u8("Color transform")
        .enumeration(ADOBE_TRANSFORM)
        .emit()?;
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let mut frame_seen = false;
    let mut camera: Option<String> = None;
    let mut scans = 0u64;
    loop {
        if cur.at_end() {
            cx.diag(Diagnostic::warning("no EOI marker"));
            break;
        }
        let Some(seg) = next_segment(&mut cur).await? else {
            return Err(Diagnostic::malformed("expected a marker").at(cur.span(1)));
        };
        let mut summary = segment_summary(&cx, &seg).await;
        if seg.marker == 0xe1 && camera.is_none() && summary.as_deref() == Some("Exif") {
            camera = super::tiff::camera(&cx, input.nested(seg.payload().tail(6))).await;
            if let Some(c) = &camera {
                summary = Some(format!("Exif, {c}"));
            }
        }
        if is_sof(seg.marker) && !frame_seen {
            frame_seen = true;
            if let Some(s) = &summary {
                cx.annotate(match &camera {
                    Some(c) => format!("{s}, {c}"),
                    None => s.clone(),
                });
            }
        }
        let mut node = Node::new(marker_name(seg.marker)).span(seg.span);
        if let Some(s) = summary {
            node = node.summary(s);
        }
        if !standalone(seg.marker) {
            node = node.lazy(segment, (input, seg));
        }
        cx.push(node).await;
        if seg.marker == 0xd9 {
            break;
        }
        if seg.marker == 0xda {
            let end = scan_entropy(&cx, file, cur.pos()).await?;
            let data = file.sub(cur.pos(), end.saturating_sub(cur.pos()));
            scans = scans.saturating_add(1);
            cx.push(
                Node::new("Entropy-coded data")
                    .span(data)
                    .summary(format!("scan {scans}, {:#x} bytes", data.len)),
            )
            .await;
            cur.seek(end);
        }
    }
    if !cur.at_end() {
        let rest = file.tail(cur.pos());
        cx.push(
            embedded("Trailing data", input.nested(rest))
                .summary(format!("{:#x} bytes after EOI", rest.len)),
        )
        .await;
    }
    Ok(())
}

/// The identifier at the start of an APPn payload, if it looks like one.
async fn app_identifier(cx: &Cx, seg: &Segment) -> Option<Vec<u8>> {
    let head = cx.read_avail(seg.payload().sub(0, 40)).await.ok()?;
    let end = head.iter().position(|&b| b == 0)?;
    let id = head.get(..end)?;
    (!id.is_empty() && id.iter().all(|b| b.is_ascii_graphic() || *b == b' '))
        .then(|| head.get(..=end).unwrap_or_default().to_vec())
}

async fn segment_summary(cx: &Cx, seg: &Segment) -> Option<String> {
    let payload = seg.payload();
    match seg.marker {
        m if is_sof(m) => {
            let block = cx.block(payload).await.ok()?;
            let mut frame = frame_header(&mut Fields::new(&block, BE), &()).ok()?;
            frame.marker = m;
            Some(frame.describe())
        }
        0xe0..=0xef => {
            let id = app_identifier(cx, seg).await?;
            let name = String::from_utf8_lossy(id.strip_suffix(b"\0").unwrap_or(&id)).into_owned();
            if id == ICC {
                let b = cx.read_avail(payload.sub(12, 2)).await.ok()?;
                let (seq, count) = (b.first()?, b.get(1)?);
                return Some(format!("ICC profile, chunk {seq} of {count}"));
            }
            if seg.marker == 0xe1 && id == XMP {
                return Some("XMP".to_owned());
            }
            if seg.marker == 0xe1 && id == XMP_EXTENSION {
                return Some("Extended XMP".to_owned());
            }
            Some(name)
        }
        0xfe => {
            let bytes = cx.read_avail(payload.sub(0, 80)).await.ok()?;
            let line = crate::text::latin1(&bytes);
            Some(line.lines().next().unwrap_or_default().to_owned())
        }
        0xdd => {
            let b = cx.read_avail(payload.sub(0, 2)).await.ok()?;
            Some(format!("restart interval {}", u16_be(&b, 0)?))
        }
        _ => None,
    }
}

async fn segment(cx: Cx, (input, seg): (Input, Segment)) -> Result<()> {
    let head = seg.span.sub(0, 4);
    let block = cx.block(head).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("Marker")
        .hex()
        .with(|_, n| n.summary(marker_name(seg.marker)))
        .emit()?;
    f.u16("Length").desc("Includes these two bytes").emit()?;
    let payload = seg.payload();
    match seg.marker {
        m if is_sof(m) => {
            cx.emit(struct_node("Frame header", payload, BE, (), frame_header));
        }
        0xda => {
            cx.emit(struct_node("Scan header", payload, BE, (), scan_header));
        }
        0xdb => quantization_tables(&cx, payload).await?,
        0xc4 => huffman_tables(&cx, payload).await?,
        0xdd => {
            let block = cx.block(payload.sub(0, 2)).await?;
            Fields::emitting(&cx, &block, BE)
                .u16("Restart interval")
                .desc("MCUs between restart markers")
                .emit()?;
        }
        0xfe => {
            let bytes = cx.read(payload).await?;
            cx.emit(
                Node::new("Comment")
                    .span(payload)
                    .value(text(crate::text::latin1(&bytes))),
            );
        }
        0xe0..=0xef => application(&cx, input, &seg).await?,
        _ => cx.emit(Node::new("Data").span(payload)),
    }
    Ok(())
}

async fn application(cx: &Cx, input: Input, seg: &Segment) -> Result<()> {
    let payload = seg.payload();
    if seg.marker == 0xee && cx.read_avail(payload.sub(0, 5)).await? == b"Adobe" {
        cx.emit(struct_node("Adobe", payload, BE, (), adobe));
        return Ok(());
    }
    let Some(id) = app_identifier(cx, seg).await else {
        cx.emit(Node::new("Data").span(payload));
        return Ok(());
    };
    let id_len = to_u64(id.len());
    let id_node = |name: &'static str| {
        Node::new(name)
            .span(payload.sub(0, id_len))
            .value(text(String::from_utf8_lossy(
                id.strip_suffix(b"\0").unwrap_or(&id),
            )))
    };
    let rest = payload.tail(id_len);
    match (seg.marker, id.as_slice()) {
        (0xe0, b"JFIF\0") => {
            let block = cx.block(payload.sub(0, 14)).await?;
            let (w, h) = jfif(&mut Fields::emitting(cx, &block, BE), &())?;
            if w > 0 && h > 0 {
                cx.emit(
                    Node::new("Thumbnail")
                        .span(payload.tail(14))
                        .summary(format!("{}, RGB", dims(w, h))),
                );
            }
        }
        (0xe0, b"JFXX\0") => {
            cx.emit(id_node("Identifier"));
            let block = cx.block(rest.sub(0, 1)).await?;
            let code = Fields::emitting(cx, &block, BE)
                .u8("Extension code")
                .enumeration(JFXX_CODES)
                .emit()?;
            let data = rest.tail(1);
            if code == 0x10 {
                cx.emit(embedded("Thumbnail", input.nested(data)));
            } else {
                cx.emit(Node::new("Thumbnail").span(data));
            }
        }
        (0xe1, EXIF) => {
            // "Exif\0" is followed by one pad byte.
            let tiff = payload.tail(6);
            cx.emit(id_node("Identifier"));
            cx.emit(embedded_as(
                "Exif",
                input.nested(tiff),
                &super::tiff::FORMAT,
            ));
        }
        (0xe1, XMP) => {
            cx.emit(id_node("Namespace"));
            cx.emit(
                embedded("XMP packet", input.nested(rest))
                    .summary(format!("{:#x} bytes of XML", rest.len)),
            );
        }
        (0xe1, XMP_EXTENSION) => {
            cx.emit(id_node("Namespace"));
            let block = cx.block(rest.sub(0, 40)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            f.ascii("GUID", 32)
                .desc("MD5 of the full extended XMP")
                .emit()?;
            f.u32("Full length").emit()?;
            f.u32("Offset").hex().emit()?;
            cx.emit(Node::new("XMP portion").span(rest.tail(40)));
        }
        (0xe2, ICC) => {
            cx.emit(id_node("Identifier"));
            let block = cx.block(rest.sub(0, 2)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            let seq = f.u8("Chunk number").emit()?;
            let count = f.u8("Chunk count").emit()?;
            let data = rest.tail(2);
            if count <= 1 {
                cx.emit(embedded("ICC profile", input.nested(data)));
            } else if seq == 1 {
                let profile = icc_profile(cx, input.span, count).await?;
                cx.emit(
                    embedded("ICC profile", input.nested(profile))
                        .summary(format!("reassembled from {count} chunks")),
                );
            } else {
                cx.emit(Node::new("Profile data").span(data).summary(format!(
                    "chunk {seq} of {count}; the profile is shown under chunk 1"
                )));
            }
        }
        (0xe2, b"MPF\0") => {
            cx.emit(id_node("Identifier"));
            cx.emit(embedded_as(
                "Multi-Picture Format index",
                input.nested(rest),
                &super::tiff::FORMAT,
            ));
        }
        (0xed, PHOTOSHOP) => {
            cx.emit(id_node("Identifier"));
            cx.emit(super::psd::resources_node("Image resources", input, rest));
        }
        _ => {
            cx.emit(id_node("Identifier"));
            cx.emit(Node::new("Data").span(rest));
        }
    }
    Ok(())
}

/// Joins the APP2 ICC_PROFILE chunks of the file into one derived source.
async fn icc_profile(cx: &Cx, file: Span, count: u8) -> Result<Span> {
    let mut chunks: Vec<(u8, Span)> = Vec::new();
    let mut cur = Cursor::new(cx, file, BE);
    cur.skip(2);
    while let Some(seg) = next_segment(&mut cur).await? {
        if seg.marker == 0xda || seg.marker == 0xd9 {
            break;
        }
        if seg.marker == 0xe2 {
            let head = cx.read_avail(seg.payload().sub(0, 14)).await?;
            if head.starts_with(ICC)
                && let Some(&seq) = head.get(12)
            {
                chunks.push((seq, seg.payload().tail(14)));
            }
        }
    }
    chunks.sort_by_key(|&(seq, _)| seq);
    let mut data = Vec::new();
    for (index, (seq, span)) in chunks.iter().enumerate() {
        if to_u64(index).saturating_add(1) != u64::from(*seq) {
            return Err(Diagnostic::malformed(format!(
                "ICC profile chunk {} of {count} is missing",
                index.saturating_add(1)
            )));
        }
        data.extend(cx.read(*span).await?);
    }
    let parent = chunks.first().map_or(file, |&(_, s)| s);
    super::reassembled(cx, parent, "jpeg-icc-chunks", data)
}

async fn quantization_tables(cx: &Cx, payload: Span) -> Result<()> {
    let mut cur = Cursor::new(cx, payload, BE);
    while !cur.at_end() {
        let start = cur.pos();
        let info = cur.u8().await?;
        let wide = info >> 4 != 0;
        cur.skip(if wide { 128 } else { 64 });
        let span = cur.since(start);
        cx.emit(
            struct_node(
                format!("Table {}", info & 15),
                span,
                BE,
                wide,
                quantization_table,
            )
            .summary(if wide { "16-bit" } else { "8-bit" }),
        );
    }
    Ok(())
}

fn quantization_table(f: &mut Fields<'_>, wide: &bool) -> Result<()> {
    f.u8("Precision and destination")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}-bit, table {}",
                if v >> 4 == 0 { 8 } else { 16 },
                v & 15
            ))
        })
        .emit()?;
    f.bytes("Values (zigzag order)", if *wide { 128 } else { 64 })
        .emit()?;
    Ok(())
}

async fn huffman_tables(cx: &Cx, payload: Span) -> Result<()> {
    let mut cur = Cursor::new(cx, payload, BE);
    while !cur.at_end() {
        let start = cur.pos();
        let info = cur.u8().await?;
        let counts = cur.bytes(16).await?;
        let symbols: u64 = counts.iter().map(|&c| u64::from(c)).sum();
        cur.skip(symbols);
        let span = cur.since(start);
        let class = if info >> 4 == 0 { "DC" } else { "AC" };
        cx.emit(
            struct_node(
                format!("{class} table {}", info & 15),
                span,
                BE,
                symbols,
                huffman_table,
            )
            .summary(format!("{symbols} symbols")),
        );
    }
    Ok(())
}

fn huffman_table(f: &mut Fields<'_>, symbols: &u64) -> Result<()> {
    f.u8("Class and destination")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}, table {}",
                if v >> 4 == 0 { "DC" } else { "AC" },
                v & 15
            ))
        })
        .emit()?;
    f.bytes("Code counts by length", 16).emit()?;
    f.bytes("Symbols", *symbols).emit()?;
    Ok(())
}
