//! Lab and neuroimaging images, volumes and overlays: ImageJ ROIs, Bio-Rad
//! PIC, Princeton Instruments SPE, Image Cytometry Standard, IMOD models,
//! Analyze 7.5 headers and FreeSurfer volumes and surfaces.

use crate::bytes::{to_u64, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{Lines, float32, int, is_text, number, preview, text, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn field_text(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_matches(['\0', ' '])
        .to_owned()
}

// ---------------------------------------------------------------------------
// ImageJ ROI

declare_format!(pub IMAGEJ_ROI = "imagej-roi", "ImageJ region of interest", ["roi"], "application/x-imagej-roi",
    Probe::Custom(|h| h.at(0, b"Iout") && u16_be(h.data, 4).is_some_and(|v| v < 1000) && h.data.get(6).is_some_and(|&t| t <= 10)), imagej_roi);

const ROI_TYPES: EnumTable = &[
    (0, "polygon"),
    (1, "rectangle"),
    (2, "oval"),
    (3, "line"),
    (4, "freeline"),
    (5, "polyline"),
    (6, "no ROI"),
    (7, "freehand"),
    (8, "traced"),
    (9, "angle"),
    (10, "point"),
];

record! {
    pub struct RoiHeader {
        magic: ascii[4] "Magic",
        version: u16 "Version",
        kind: u8 "Type" .enumeration(ROI_TYPES),
        pad: u8 "Padding",
        top: i16 "Top",
        left: i16 "Left",
        bottom: i16 "Bottom",
        right: i16 "Right",
        points: u16 "Coordinates",
        x1: f32 "X1",
        y1: f32 "Y1",
        x2: f32 "X2",
        y2: f32 "Y2",
        stroke_width: u16 "Stroke width",
        shape_size: u32 "Shape ROI size",
        stroke_color: u32 "Stroke color" .hex(),
        fill_color: u32 "Fill color" .hex(),
        subtype: u16 "Subtype",
        options: u16 "Options" .hex(),
        arrow_style: u8 "Arrow style / aspect ratio",
        point_type: u8 "Point type",
        arrow_size: u16 "Arrow head size / arc size",
        position: u32 "Position",
        header2: u32 "Header 2 offset" .hex(),
    }
}

async fn imagej_roi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hs = file.sub(0, RoiHeader::SIZE);
    let h: RoiHeader = read_record(&cx, hs, BE).await?;
    cx.emit(RoiHeader::node("Header", hs, BE));
    let n = u64::from(h.points);
    if n > 0 && h.kind != 1 && h.kind != 2 {
        let xs = file.sub(64, n.saturating_mul(2));
        let ys = file.sub(
            64u64.saturating_add(n.saturating_mul(2)),
            n.saturating_mul(2),
        );
        cx.emit(
            Node::new("Coordinates")
                .span(file.sub(64, n.saturating_mul(4)))
                .value(uint(n))
                .lazy(roi_points, (xs, ys, h.left, h.top)),
        );
    }
    let mut name = String::new();
    if h.header2 > 0 {
        let b = cx.block(file.sub(h.header2.into(), 64)).await?;
        let mut f = Fields::new(&b, BE);
        f.skip(4);
        let c = f.u32("C position").get()?;
        let z = f.u32("Z position").get()?;
        let t = f.u32("T position").get()?;
        let name_offset = f.u32("Name offset").get()?;
        let name_len = f.u32("Name length").get()?;
        cx.emit(
            Node::new("Header 2")
                .span(file.sub(h.header2.into(), 64))
                .summary(format!("C {c}, Z {z}, T {t}")),
        );
        if name_offset > 0 && name_len > 0 {
            let ns = file.sub(
                name_offset.into(),
                u64::from(name_len.min(1024)).saturating_mul(2),
            );
            name = crate::text::utf16(&cx.read_avail(ns).await?, BE);
            cx.emit(Node::new("Name").span(ns).value(text(name.clone())));
        }
    }
    cx.annotate(format!(
        "ImageJ ROI v{}, {} ({}, {})–({}, {}){}{}",
        h.version,
        lookup(ROI_TYPES, h.kind.into()).unwrap_or("?"),
        h.left,
        h.top,
        h.right,
        h.bottom,
        if n > 0 {
            format!(", {n} point(s)")
        } else {
            String::new()
        },
        if name.is_empty() {
            String::new()
        } else {
            format!(", {name:?}")
        }
    ));
    Ok(())
}

async fn roi_points(cx: Cx, (xs, ys, left, top): (Span, Span, i16, i16)) -> Result<()> {
    let x = cx.read(xs).await?;
    let y = cx.read(ys).await?;
    for (i, (a, b)) in x
        .as_chunks::<2>()
        .0
        .iter()
        .zip(y.as_chunks::<2>().0.iter())
        .enumerate()
    {
        let (px, py) = (i16::from_be_bytes(*a), i16::from_be_bytes(*b));
        cx.push(Node::new(format!("Point {i}")).value(text(format!(
            "({}, {})",
            i32::from(px).saturating_add(left.into()),
            i32::from(py).saturating_add(top.into())
        ))))
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bio-Rad PIC confocal images

declare_format!(pub BIORAD_PIC = "biorad-pic", "Bio-Rad PIC confocal image", ["pic"], "image/x-biorad-pic",
    Probe::Custom(|h| u16_le(h.data, 54) == Some(12345) && u16_le(h.data, 0).is_some_and(|x| x > 0) && u16_le(h.data, 2).is_some_and(|y| y > 0) && u16_le(h.data, 14).is_some_and(|b| b <= 1)), biorad_pic);

record! {
    pub struct PicHeader {
        nx: u16 "Width",
        ny: u16 "Height",
        npic: u16 "Images",
        ramp1_min: u16 "Ramp 1 min",
        ramp1_max: u16 "Ramp 1 max",
        notes: u32 "Notes flag",
        byte_format: u16 "Byte format" .desc("1 = 8-bit, 0 = 16-bit"),
        image: u16 "Image number",
        name: ascii[32] "Name",
        merged: u16 "Merged",
        color1: u16 "Color 1",
        file_id: u16 "File ID" .desc("Always 12345"),
        ramp2_min: u16 "Ramp 2 min",
        ramp2_max: u16 "Ramp 2 max",
        color2: u16 "Color 2",
        edited: u16 "Edited",
        lens: u16 "Lens magnification",
        mag_factor: f32 "Magnification factor",
        reserved: bytes[6] "Reserved",
    }
}

async fn biorad_pic(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hs = file.sub(0, PicHeader::SIZE);
    let h: PicHeader = read_record(&cx, hs, LE).await?;
    cx.emit(PicHeader::node("Header", hs, LE));
    let bytes = if h.byte_format == 1 { 1u64 } else { 2 };
    let plane = u64::from(h.nx)
        .saturating_mul(h.ny.into())
        .saturating_mul(bytes);
    let images = file.sub(76, plane.saturating_mul(h.npic.into()));
    cx.emit(
        Node::new("Images")
            .span(images)
            .value(uint(h.npic.into()))
            .summary(format!("{}×{} {}-bit", h.nx, h.ny, bytes.saturating_mul(8))),
    );
    let notes = file.tail(76u64.saturating_add(images.len));
    let mut count = 0u64;
    if notes.len >= 96 {
        count = notes.len / 96;
        cx.emit(
            Node::new("Notes")
                .span(notes)
                .value(uint(count))
                .lazy(pic_notes, notes),
        );
    }
    cx.annotate(format!(
        "Bio-Rad PIC {:?}, {}×{}×{} {}-bit, {count} note(s)",
        h.name.trim_end_matches('\0'),
        h.nx,
        h.ny,
        h.npic,
        bytes.saturating_mul(8)
    ));
    Ok(())
}

async fn pic_notes(cx: Cx, span: Span) -> Result<()> {
    let mut at = 0u64;
    while at.saturating_add(96) <= span.len {
        let b = cx.read(span.sub(at, 96)).await?;
        let kind = u16_le(&b, 10).unwrap_or(0);
        let t = field_text(b.get(16..96).unwrap_or_default());
        cx.push(
            Node::new(format!("Note (type {kind})"))
                .span(span.sub(at, 96))
                .value(text(t)),
        )
        .await;
        at = at.saturating_add(96);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Princeton Instruments / Roper SPE

declare_format!(pub PRINCETON_SPE = "princeton-spe", "Princeton Instruments SPE image", ["spe"], "image/x-spe",
    Probe::Custom(|h| u16_le(h.data, 4098) == Some(0x5555) && h.len >= 4100), princeton_spe);

const SPE_TYPES: EnumTable = &[
    (0, "float32"),
    (1, "int32"),
    (2, "int16"),
    (3, "uint16"),
    (5, "float64"),
    (6, "uint8"),
    (8, "uint32"),
];

async fn princeton_spe(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = cx.read(file.sub(0, 4100)).await?;
    let emit = |name: &'static str, at: u64, len: u64, v: Value| {
        cx.emit(Node::new(name).span(file.sub(at, len)).value(v))
    };
    let exposure = f32::from_le_bytes(crate::bytes::array(&h, 10).unwrap_or_default());
    emit("Exposure (s)", 10, 4, float32(exposure));
    emit(
        "Date",
        20,
        10,
        text(field_text(h.get(20..30).unwrap_or_default())),
    );
    let xdim = u16_le(&h, 42).unwrap_or(0);
    emit("X dimension", 42, 2, uint(xdim.into()));
    let dtype = u16_le(&h, 108).unwrap_or(0);
    emit(
        "Data type",
        108,
        2,
        crate::formats::util::lines::enumeration(SPE_TYPES, dtype.into(), 16),
    );
    let comments: Vec<String> = (0..5usize)
        .map(|i| {
            field_text(
                h.get(
                    200usize.saturating_add(i.saturating_mul(80))
                        ..280usize.saturating_add(i.saturating_mul(80)),
                )
                .unwrap_or_default(),
            )
        })
        .filter(|c| !c.is_empty())
        .collect();
    emit("Comments", 200, 400, text(comments.join(" / ")));
    let ydim = u16_le(&h, 656).unwrap_or(0);
    emit("Y dimension", 656, 2, uint(ydim.into()));
    let xml = crate::bytes::u64_le(&h, 678).unwrap_or(0);
    emit(
        "XML footer offset",
        678,
        8,
        crate::formats::util::lines::hex(xml, 64),
    );
    let frames = crate::bytes::i32_le(&h, 1446).unwrap_or(0);
    emit("Frames", 1446, 4, int(frames.into()));
    let version = f32::from_le_bytes(crate::bytes::array(&h, 1992).unwrap_or_default());
    emit("File header version", 1992, 4, float32(version));
    emit(
        "Last value",
        4098,
        2,
        crate::formats::util::lines::hex(0x5555, 16),
    );
    let size: u64 = match dtype {
        0 | 1 | 8 => 4,
        2 | 3 => 2,
        5 => 8,
        _ => 1,
    };
    let frame = u64::from(xdim)
        .saturating_mul(ydim.into())
        .saturating_mul(size);
    let data = file.sub(
        4100,
        frame.saturating_mul(u64::try_from(frames).unwrap_or(0)),
    );
    cx.emit(Node::new("Frames").span(data).value(int(frames.into())));
    if xml > 0 {
        let x = file.tail(xml);
        let head = cx.read_avail(x.sub(0, 512)).await?;
        cx.emit(
            Node::new("XML footer")
                .span(x)
                .value(text(preview(&String::from_utf8_lossy(&head), 200))),
        );
    }
    cx.annotate(format!(
        "Princeton SPE {version}, {xdim}×{ydim} {} × {frames} frame(s), exposure {exposure} s",
        lookup(SPE_TYPES, dtype.into()).unwrap_or("?")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Image Cytometry Standard (ICS)

declare_format!(pub ICS = "ics", "Image Cytometry Standard header", ["ics", "ids"], "image/x-ics",
    Probe::Custom(|h| is_text(h) && h.data.get(2..13) == Some(b"ics_version") && h.data.first().is_some_and(|b| !b.is_ascii_alphanumeric())), ics);

async fn ics(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut items: Vec<(String, String, Span)> = Vec::new();
    let mut data_at = None;
    while let Some(line) = lines.next().await? {
        if line.pos == 0 {
            cx.emit(
                Node::new("Separators")
                    .span(line.span)
                    .desc("Field and line separator characters"),
            );
            continue;
        }
        let t = line.text();
        if t.trim() == "end" {
            data_at = Some(lines.pos());
            break;
        }
        let fields: Vec<&str> = t.split(['\t', ' ']).filter(|f| !f.is_empty()).collect();
        let (key, value) = match fields.as_slice() {
            [cat, key, rest @ ..] if !matches!(*cat, "ics_version" | "filename") => {
                (format!("{cat} {key}"), rest.join(" "))
            }
            [cat, rest @ ..] => ((*cat).to_owned(), rest.join(" ")),
            [] => continue,
        };
        if items.len() < 4096 {
            items.push((key, value, line.content()));
        }
    }
    let get = |k: &str| {
        items
            .iter()
            .find(|(a, _, _)| a == k)
            .map_or(String::new(), |(_, v, _)| v.clone())
    };
    let n = items.len();
    cx.emit(
        Node::new("Parameters")
            .value(uint(to_u64(n)))
            .lazy(kv_spans, items.clone()),
    );
    if let Some(at) = data_at
        && at < file.len
    {
        cx.emit(Node::new("Image data").span(file.tail(at)));
    }
    cx.annotate(format!(
        "ICS {} image, order {}, sizes {}, {} {}",
        get("ics_version"),
        get("layout order"),
        get("layout sizes"),
        get("representation format"),
        get("representation compression")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// IMOD models

declare_format!(pub IMOD = "imod-model", "IMOD model", ["mod", "fid"], "application/x-imod",
    Probe::Magic(&[(0, b"IMODV1.2")]), imod);

async fn imod(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 232)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 8).emit()?;
    let name = f.ascii("Name", 128).emit()?;
    let xmax = f.u32("X max").emit()?;
    let ymax = f.u32("Y max").emit()?;
    let zmax = f.u32("Z max").emit()?;
    let objects = f.u32("Objects").emit()?;
    f.u32("Flags").hex().emit()?;
    f.u32("Draw mode").emit()?;
    f.u32("Mouse mode").emit()?;
    f.u32("Black level").emit()?;
    f.u32("White level").emit()?;
    for n in [
        "X offset", "Y offset", "Z offset", "X scale", "Y scale", "Z scale",
    ] {
        f.f32(n).emit()?;
    }
    for n in [
        "Current object",
        "Current contour",
        "Current point",
        "Resolution",
        "Threshold",
    ] {
        f.u32(n).emit()?;
    }
    f.f32("Pixel size").emit()?;
    f.u32("Units").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(232);
    let (mut contours, mut points) = (0u64, 0u64);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let (summary, len) = match id.as_str() {
            "IEOF" => {
                cx.push(Node::new("IEOF").span(cur.since(start))).await;
                break;
            }
            "OBJT" => {
                let b = cx.read_avail(file.sub(cur.pos(), 176)).await?;
                (
                    format!(
                        "{:?}, {} contour(s)",
                        field_text(b.get(..64).unwrap_or_default()),
                        u32_be(&b, 128).unwrap_or(0)
                    ),
                    176u64,
                )
            }
            "CONT" => {
                let n = u64::from(cur.u32().await?);
                contours = contours.saturating_add(1);
                points = points.saturating_add(n);
                cur.seek(start.saturating_add(4));
                (
                    format!("{n} point(s)"),
                    16u64.saturating_add(n.saturating_mul(12)),
                )
            }
            "MESH" => {
                let v = u64::from(cur.u32().await?);
                let l = u64::from(cur.u32().await?);
                cur.seek(start.saturating_add(4));
                (
                    format!("{v} vertices, {l} indices"),
                    20u64
                        .saturating_add(v.saturating_mul(12))
                        .saturating_add(l.saturating_mul(4)),
                )
            }
            _ => {
                let size = u64::from(cur.u32().await?);
                cur.seek(start.saturating_add(4));
                (format!("{size} bytes"), 4u64.saturating_add(size))
            }
        };
        cur.skip(len);
        cx.push(Node::new(id).span(cur.since(start)).summary(summary))
            .await;
    }
    cx.annotate(format!("IMOD model {:?}, {xmax}×{ymax}×{zmax}, {objects} object(s), {contours} contour(s), {points} point(s)", name.trim_end_matches('\0')));
    Ok(())
}

// ---------------------------------------------------------------------------
// Analyze 7.5 headers

fn analyze_probe(h: &Head<'_>) -> bool {
    (u32_le(h.data, 0) == Some(348) || u32_be(h.data, 0) == Some(348))
        && !h.at(344, b"n+1\0")
        && !h.at(344, b"ni1\0")
        && !h.at(344, b"n+2\0")
        && (h.len == 348 || h.data.get(38) == Some(&b'r'))
}

declare_format!(pub ANALYZE = "analyze-hdr", "Analyze 7.5 image header", ["hdr"], "application/x-analyze",
    Probe::Custom(analyze_probe), analyze);

const ANALYZE_TYPES: EnumTable = &[
    (0, "unknown"),
    (1, "binary"),
    (2, "uint8"),
    (4, "int16"),
    (8, "int32"),
    (16, "float32"),
    (32, "complex64"),
    (64, "float64"),
    (128, "RGB24"),
];

record! {
    pub struct AnalyzeHeader {
        sizeof_hdr: u32 "sizeof_hdr",
        data_type: ascii[10] "data_type",
        db_name: ascii[18] "db_name",
        extents: u32 "extents",
        session_error: u16 "session_error",
        regular: ascii[1] "regular",
        hkey_un0: u8 "hkey_un0",
        dim0: u16 "dim[0] (dimensions)",
        dim1: u16 "dim[1]",
        dim2: u16 "dim[2]",
        dim3: u16 "dim[3]",
        dim4: u16 "dim[4]",
        dim5: u16 "dim[5]",
        dim6: u16 "dim[6]",
        dim7: u16 "dim[7]",
        vox_units: ascii[4] "vox_units",
        cal_units: ascii[8] "cal_units",
        unused1: u16 "unused1",
        datatype: u16 "datatype" .enumeration(ANALYZE_TYPES),
        bitpix: u16 "bitpix",
        dim_un0: u16 "dim_un0",
        pixdim0: f32 "pixdim[0]",
        pixdim1: f32 "pixdim[1]",
        pixdim2: f32 "pixdim[2]",
        pixdim3: f32 "pixdim[3]",
        pixdim4: f32 "pixdim[4]",
        pixdim5: f32 "pixdim[5]",
        pixdim6: f32 "pixdim[6]",
        pixdim7: f32 "pixdim[7]",
        vox_offset: f32 "vox_offset",
        funused: bytes[12] "funused",
        cal_max: f32 "cal_max",
        cal_min: f32 "cal_min",
        compressed: f32 "compressed",
        verified: f32 "verified",
        glmax: i32 "glmax",
        glmin: i32 "glmin",
        descrip: ascii[80] "descrip",
        aux_file: ascii[24] "aux_file",
        orient: u8 "orient",
        originator: bytes[10] "originator",
        generated: ascii[10] "generated",
        scannum: ascii[10] "scannum",
        patient_id: ascii[10] "patient_id",
        exp_date: ascii[10] "exp_date",
        exp_time: ascii[10] "exp_time",
        hist_un0: bytes[3] "hist_un0",
        views: i32 "views",
        vols_added: i32 "vols_added",
        start_field: i32 "start_field",
        field_skip: i32 "field_skip",
        omax: i32 "omax",
        omin: i32 "omin",
        smax: i32 "smax",
        smin: i32 "smin",
    }
}

async fn analyze(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let endian = if u32_le(&cx.read(file.sub(0, 4)).await?, 0) == Some(348) {
        LE
    } else {
        BE
    };
    let hs = file.sub(0, AnalyzeHeader::SIZE);
    let h: AnalyzeHeader = read_record(&cx, hs, endian).await?;
    cx.emit(AnalyzeHeader::node("Header", hs, endian));
    let dims: Vec<String> = [h.dim1, h.dim2, h.dim3, h.dim4]
        .iter()
        .take(usize::from(h.dim0.min(4)))
        .map(u16::to_string)
        .collect();
    cx.annotate(format!(
        "Analyze 7.5 header, {} {}, voxels {}×{}×{} {}{}",
        dims.join("×"),
        lookup(ANALYZE_TYPES, h.datatype.into()).unwrap_or("?"),
        h.pixdim1,
        h.pixdim2,
        h.pixdim3,
        h.vox_units.trim_end_matches('\0'),
        if h.descrip.trim_end_matches('\0').is_empty() {
            String::new()
        } else {
            format!(", {:?}", h.descrip.trim_end_matches('\0'))
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// FreeSurfer MGH volumes and surfaces

fn mgh_size(t: u32) -> u64 {
    match t {
        0 => 1,
        4 => 2,
        1 | 3 => 4,
        _ => 0,
    }
}

fn mgh_probe(h: &Head<'_>) -> bool {
    let g = |o: usize| u32_be(h.data, o).map(u64::from);
    let (Some(1), Some(w), Some(hh), Some(d), Some(f), Some(t)) =
        (g(0), g(4), g(8), g(12), g(16), u32_be(h.data, 20))
    else {
        return false;
    };
    let size = mgh_size(t);
    size > 0
        && w > 0
        && hh > 0
        && d > 0
        && f > 0
        && 284u64.saturating_add(
            w.saturating_mul(hh)
                .saturating_mul(d)
                .saturating_mul(f)
                .saturating_mul(size),
        ) <= h.len
        && u16_be(h.data, 28).is_some_and(|r| r <= 1)
}

declare_format!(pub MGH = "mgh", "FreeSurfer MGH volume", ["mgh"], "application/x-mgh",
    Probe::Custom(mgh_probe), mgh);

const MGH_TYPES: EnumTable = &[(0, "uint8"), (1, "int32"), (3, "float32"), (4, "int16")];

async fn mgh(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 90)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Version").emit()?;
    let w = f.u32("Width").emit()?;
    let h = f.u32("Height").emit()?;
    let d = f.u32("Depth").emit()?;
    let frames = f.u32("Frames").emit()?;
    let t = f.u32("Type").enumeration(MGH_TYPES).emit()?;
    f.u32("Degrees of freedom").emit()?;
    let ras = f.u16("Good RAS flag").emit()?;
    let mut voxel = (0.0, 0.0, 0.0);
    if ras == 1 {
        voxel = (
            f.f32("Voxel size X").emit()?,
            f.f32("Voxel size Y").emit()?,
            f.f32("Voxel size Z").emit()?,
        );
        for n in [
            "x_r", "x_a", "x_s", "y_r", "y_a", "y_s", "z_r", "z_a", "z_s", "c_r", "c_a", "c_s",
        ] {
            f.f32(n).emit()?;
        }
    }
    let size = u64::from(w)
        .saturating_mul(h.into())
        .saturating_mul(d.into())
        .saturating_mul(frames.into())
        .saturating_mul(mgh_size(t));
    cx.emit(Node::new("Voxels").span(file.sub(284, size)));
    let tail = file.tail(284u64.saturating_add(size));
    if tail.len > 0 {
        let b = cx.block(tail.sub(0, 20)).await?;
        let mut g = Fields::new(&b, BE);
        let tr = g.f32("TR").get().unwrap_or(0.0);
        cx.emit(
            Node::new("Scan parameters and tags")
                .span(tail)
                .summary(format!("TR {tr} ms")),
        );
    }
    cx.annotate(format!(
        "FreeSurfer MGH, {w}×{h}×{d}×{frames} {}, voxels {}×{}×{} mm",
        lookup(MGH_TYPES, t.into()).unwrap_or("?"),
        voxel.0,
        voxel.1,
        voxel.2
    ));
    Ok(())
}

declare_format!(pub FREESURFER_SURF = "freesurfer-surf", "FreeSurfer triangle surface", ["white", "pial", "inflated", "sphere", "orig", "smoothwm"], "application/x-freesurfer-surface",
    Probe::Custom(|h| h.at(0, b"\xff\xff\xfe") && h.at(3, b"created by")), freesurfer_surf);

async fn freesurfer_surf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 3))
            .value(crate::formats::util::lines::hex(0xff_fffe, 24)),
    );
    let head = cx.read_avail(file.sub(3, 1024)).await?;
    // The comment ends with two newlines.
    let end = head
        .windows(2)
        .position(|w| w == b"\n\n")
        .map_or(0, |p| p.saturating_add(2));
    let comment = String::from_utf8_lossy(head.get(..end).unwrap_or_default())
        .trim()
        .to_owned();
    cx.emit(
        Node::new("Comment")
            .span(file.sub(3, to_u64(end)))
            .value(text(comment.clone())),
    );
    let at = 3u64.saturating_add(to_u64(end));
    let b = cx.read(file.sub(at, 8)).await?;
    let v = u64::from(u32_be(&b, 0).unwrap_or(0));
    let faces = u64::from(u32_be(&b, 4).unwrap_or(0));
    cx.emit(Node::new("Vertices").span(file.sub(at, 4)).value(uint(v)));
    cx.emit(
        Node::new("Faces")
            .span(file.sub(at.saturating_add(4), 4))
            .value(uint(faces)),
    );
    let vs = file.sub(at.saturating_add(8), v.saturating_mul(12));
    cx.emit(
        Node::new("Vertex coordinates")
            .span(vs)
            .lazy(surf_vertices, vs),
    );
    cx.emit(Node::new("Face indices").span(file.sub(
        vs.end().saturating_sub(file.offset),
        faces.saturating_mul(12),
    )));
    cx.annotate(format!(
        "FreeSurfer surface, {v} vertices, {faces} triangles ({})",
        preview(&comment, 60)
    ));
    Ok(())
}

async fn surf_vertices(cx: Cx, span: Span) -> Result<()> {
    let count = span.len / 12;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let s = span.sub(i.saturating_mul(12), 12);
        let b = cx.read(s).await?;
        let c = |o: usize| f32::from_bits(u32_be(&b, o).unwrap_or(0));
        cx.push(Node::new(format!("Vertex {i}")).span(s).value(text(format!(
            "({}, {}, {})",
            c(0),
            c(4),
            c(8)
        ))))
        .await;
    }
    Ok(())
}

async fn kv_spans(cx: Cx, items: Vec<(String, String, Span)>) -> Result<()> {
    for (k, v, span) in items {
        cx.push(Node::new(k).span(span).value(number(&v))).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(mgh_size(3), 4);
        assert_eq!(field_text(b"ab\0\0 "), "ab");
    }
}
