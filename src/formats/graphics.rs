//! Vector metafiles, film/VFX frames, GPU textures, palettes and other
//! graphics formats.

use crate::bytes::{u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Windows metafiles: WMF (placeable or plain) and EMF

fn wmf_probe(h: &Head<'_>) -> bool {
    h.at(0, b"\xd7\xcd\xc6\x9a")
        || (u16_le(h.data, 0).is_some_and(|t| t == 1 || t == 2)
            && u16_le(h.data, 2) == Some(9)
            && u16_le(h.data, 4).is_some_and(|v| v == 0x0100 || v == 0x0300))
}

declare_format!(pub WMF = "wmf", "Windows metafile", ["wmf"], "image/wmf",
    Probe::Custom(wmf_probe), wmf);

const WMF_RECORDS: EnumTable = &[
    (0x0000, "META_EOF"),
    (0x001e, "META_SAVEDC"),
    (0x0102, "META_SETBKMODE"),
    (0x0103, "META_SETMAPMODE"),
    (0x0104, "META_SETROP2"),
    (0x0106, "META_SETPOLYFILLMODE"),
    (0x0107, "META_SETSTRETCHBLTMODE"),
    (0x0127, "META_RESTOREDC"),
    (0x012c, "META_SELECTCLIPREGION"),
    (0x012d, "META_SELECTOBJECT"),
    (0x012e, "META_SETTEXTALIGN"),
    (0x01f0, "META_DELETEOBJECT"),
    (0x0201, "META_SETBKCOLOR"),
    (0x0209, "META_SETTEXTCOLOR"),
    (0x020b, "META_SETWINDOWORG"),
    (0x020c, "META_SETWINDOWEXT"),
    (0x020d, "META_SETVIEWPORTORG"),
    (0x020e, "META_SETVIEWPORTEXT"),
    (0x0213, "META_LINETO"),
    (0x0214, "META_MOVETO"),
    (0x02fa, "META_CREATEPENINDIRECT"),
    (0x02fb, "META_CREATEFONTINDIRECT"),
    (0x02fc, "META_CREATEBRUSHINDIRECT"),
    (0x0324, "META_POLYGON"),
    (0x0325, "META_POLYLINE"),
    (0x0418, "META_ELLIPSE"),
    (0x041b, "META_RECTANGLE"),
    (0x0521, "META_TEXTOUT"),
    (0x0538, "META_POLYPOLYGON"),
    (0x0626, "META_ESCAPE"),
    (0x0a32, "META_EXTTEXTOUT"),
    (0x0b41, "META_DIBSTRETCHBLT"),
    (0x0f43, "META_STRETCHDIB"),
];

record! {
    pub struct WmfPlaceable {
        key: u32 "Key" .hex(),
        handle: u16 "Handle",
        left: i16 "Left",
        top: i16 "Top",
        right: i16 "Right",
        bottom: i16 "Bottom",
        inch: u16 "Units per inch",
        _reserved: u32 "Reserved",
        checksum: u16 "Checksum" .hex(),
    }
}

record! {
    pub struct WmfHeader {
        kind: u16 "Type" .enumeration(&[(1, "memory"), (2, "disk")]),
        header_size: u16 "Header size (words)",
        version: u16 "Version" .hex(),
        size: u32 "File size (words)",
        objects: u16 "Number of objects",
        max_record: u32 "Largest record (words)",
        _members: u16 "Unused",
    }
}

async fn wmf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    let mut size = String::new();
    if cx.read(file.sub(0, 4)).await? == b"\xd7\xcd\xc6\x9a" {
        let p: WmfPlaceable = read_record(&cx, file.sub(0, WmfPlaceable::SIZE), LE).await?;
        cx.emit(WmfPlaceable::node(
            "Placeable header",
            file.sub(0, WmfPlaceable::SIZE),
            LE,
        ));
        size = format!(
            ", {}×{} units at {}/inch",
            i32::from(p.right).saturating_sub(p.left.into()),
            i32::from(p.bottom).saturating_sub(p.top.into()),
            p.inch
        );
        at = WmfPlaceable::SIZE;
    }
    let h: WmfHeader = read_record(&cx, file.sub(at, WmfHeader::SIZE), LE).await?;
    cx.emit(WmfHeader::node(
        "Metafile header",
        file.sub(at, WmfHeader::SIZE),
        LE,
    ));
    let records = file.tail(at.saturating_add(WmfHeader::SIZE));
    cx.emit(
        Node::new("Records")
            .span(records)
            .lazy(wmf_records, records),
    );
    cx.annotate(format!(
        "WMF v{:#x}, {} objects{size}",
        h.version, h.objects
    ));
    Ok(())
}

async fn wmf_records(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= 6 {
        let start = cur.pos();
        let words = cur.u32().await?;
        let function = cur.u16().await?;
        if words < 3 {
            cx.diag(Diagnostic::malformed("record shorter than its header").at(cur.since(start)));
            break;
        }
        cur.seek(start.saturating_add(u64::from(words).saturating_mul(2)));
        let name = lookup(WMF_RECORDS, function.into())
            .map_or_else(|| format!("{function:#06x}"), str::to_owned);
        cx.push(Node::new(name).span(cur.since(start))).await;
        if function == 0 {
            break;
        }
    }
    Ok(())
}

fn emf_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(1) && h.at(40, b" EMF")
}

declare_format!(pub EMF = "emf", "Enhanced Windows metafile", ["emf", "emz"], "image/emf",
    Probe::Custom(emf_probe), emf);

const EMF_RECORDS: EnumTable = &[
    (1, "EMR_HEADER"),
    (2, "EMR_POLYBEZIER"),
    (3, "EMR_POLYGON"),
    (4, "EMR_POLYLINE"),
    (9, "EMR_SETWINDOWEXTEX"),
    (10, "EMR_SETWINDOWORGEX"),
    (11, "EMR_SETVIEWPORTEXTEX"),
    (12, "EMR_SETVIEWPORTORGEX"),
    (14, "EMR_EOF"),
    (17, "EMR_SETMAPMODE"),
    (18, "EMR_SETBKMODE"),
    (21, "EMR_SETSTRETCHBLTMODE"),
    (22, "EMR_SETTEXTALIGN"),
    (24, "EMR_SETTEXTCOLOR"),
    (25, "EMR_SETBKCOLOR"),
    (27, "EMR_MOVETOEX"),
    (33, "EMR_SAVEDC"),
    (34, "EMR_RESTOREDC"),
    (37, "EMR_SELECTOBJECT"),
    (38, "EMR_CREATEPEN"),
    (39, "EMR_CREATEBRUSHINDIRECT"),
    (40, "EMR_DELETEOBJECT"),
    (42, "EMR_ELLIPSE"),
    (43, "EMR_RECTANGLE"),
    (54, "EMR_LINETO"),
    (70, "EMR_GDICOMMENT"),
    (76, "EMR_BITBLT"),
    (77, "EMR_STRETCHBLT"),
    (81, "EMR_STRETCHDIBITS"),
    (82, "EMR_EXTCREATEFONTINDIRECTW"),
    (84, "EMR_EXTTEXTOUTW"),
    (86, "EMR_POLYGON16"),
    (87, "EMR_POLYLINE16"),
];

record! {
    pub struct EmfHeader {
        kind: u32 "Record type",
        size: u32 "Record size",
        bounds_left: i32 "Bounds left",
        bounds_top: i32 "Bounds top",
        bounds_right: i32 "Bounds right",
        bounds_bottom: i32 "Bounds bottom",
        frame_left: i32 "Frame left (0.01 mm)",
        frame_top: i32 "Frame top (0.01 mm)",
        frame_right: i32 "Frame right (0.01 mm)",
        frame_bottom: i32 "Frame bottom (0.01 mm)",
        signature: ascii[4] "Signature",
        version: u32 "Version" .hex(),
        bytes: u32 "File size",
        records: u32 "Records",
        handles: u16 "Handles",
        _reserved: u16 "Reserved",
        description_len: u32 "Description length (chars)",
        description_offset: u32 "Description offset" .hex(),
        palette: u32 "Palette entries",
        device_width: i32 "Reference device width (px)",
        device_height: i32 "Reference device height (px)",
        mm_width: i32 "Reference device width (mm)",
        mm_height: i32 "Reference device height (mm)",
    }
}

async fn emf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: EmfHeader = read_record(&cx, file.sub(0, EmfHeader::SIZE), LE).await?;
    cx.emit(EmfHeader::node("Header", file.sub(0, h.size.into()), LE));
    let mut description = String::new();
    if h.description_len > 0 {
        let span = file.sub(
            h.description_offset.into(),
            u64::from(h.description_len).saturating_mul(2),
        );
        let text = crate::text::utf16(&cx.read_avail(span).await?, LE);
        description = text
            .split('\0')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" / ");
        cx.emit(
            Node::new("Description")
                .span(span)
                .value(Value::Text(description.clone())),
        );
    }
    let records = file.tail(h.size.into());
    cx.emit(
        Node::new("Records")
            .span(records)
            .summary(format!("{} records", h.records))
            .lazy(emf_records, records),
    );
    cx.annotate(format!(
        "EMF, {}×{} (0.01 mm){}",
        h.frame_right.saturating_sub(h.frame_left),
        h.frame_bottom.saturating_sub(h.frame_top),
        if description.is_empty() {
            String::new()
        } else {
            format!(", {description}")
        }
    ));
    Ok(())
}

async fn emf_records(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let kind = cur.u32().await?;
        let size = cur.u32().await?;
        if size < 8 {
            cx.diag(Diagnostic::malformed("record shorter than its header").at(cur.since(start)));
            break;
        }
        cur.seek(start.saturating_add(size.into()));
        let name = lookup(EMF_RECORDS, kind.into())
            .map_or_else(|| format!("record {kind}"), str::to_owned);
        cx.push(Node::new(name).span(cur.since(start))).await;
        if kind == 14 {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DPX and Cineon (film scanning)

declare_format!(pub DPX = "dpx", "Digital Picture Exchange", ["dpx"], "image/x-dpx",
    Probe::Magic(&[(0, b"SDPX"), (0, b"XPDS")]), dpx);

async fn dpx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let big = cx.read(file.sub(0, 4)).await? == b"SDPX";
    let endian = if big { BE } else { LE };
    let head = cx.block(file.sub(0, 1664)).await?;
    {
        let mut f = crate::fields::Fields::emitting(&cx, &head, endian);
        f.ascii("Magic", 4).emit()?;
        f.u32("Image data offset").hex().emit()?;
        f.ascii("Version", 8).emit()?;
        f.u32("File size").emit()?;
        f.u32("Ditto key").emit()?;
        f.u32("Generic header size").emit()?;
        f.u32("Industry header size").emit()?;
        f.u32("User data size").emit()?;
        f.ascii("File name", 100).emit()?;
        f.ascii("Creation time", 24).emit()?;
        f.ascii("Creator", 100).emit()?;
        f.ascii("Project", 200).emit()?;
        f.ascii("Copyright", 200).emit()?;
        f.u32("Encryption key").hex().emit()?;
        f.skip(104);
        f.u16("Orientation").emit()?;
        f.u16("Elements").emit()?;
        f.u32("Pixels per line").emit()?;
        f.u32("Lines per element").emit()?;
    }
    let width = if big {
        u32_be(&head.data, 772)
    } else {
        u32_le(&head.data, 772)
    }
    .unwrap_or(0);
    let height = if big {
        u32_be(&head.data, 776)
    } else {
        u32_le(&head.data, 776)
    }
    .unwrap_or(0);
    let depth = head.data.get(803).copied().unwrap_or(0);
    let offset = if big {
        u32_be(&head.data, 4)
    } else {
        u32_le(&head.data, 4)
    }
    .unwrap_or(0);
    cx.emit(Node::new("Image data").span(file.tail(offset.into())));
    cx.annotate(format!(
        "{width}×{height}, {depth}-bit, {} endian",
        if big { "big" } else { "little" }
    ));
    Ok(())
}

declare_format!(pub CINEON = "cineon", "Kodak Cineon image", ["cin"], "image/cineon",
    Probe::Magic(&[(0, b"\x80\x2a\x5f\xd7"), (0, b"\xd7\x5f\x2a\x80")]), cineon);

record! {
    pub struct CineonHeader {
        magic: u32 "Magic" .hex(),
        image_offset: u32 "Image data offset" .hex(),
        generic_size: u32 "Generic header size",
        industry_size: u32 "Industry header size",
        user_size: u32 "User data size",
        file_size: u32 "File size",
        version: ascii[8] "Version",
        file_name: ascii[100] "File name",
        date: ascii[12] "Creation date",
        time: ascii[12] "Creation time",
    }
}

async fn cineon(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let big = cx.read(file.sub(0, 4)).await? == b"\x80\x2a\x5f\xd7";
    let endian = if big { BE } else { LE };
    let h: CineonHeader = emit_record(&cx, file.sub(0, CineonHeader::SIZE), endian).await?;
    let dims = cx.read_avail(file.sub(200, 8)).await?;
    let (w, hgt) = if big {
        (u32_be(&dims, 0), u32_be(&dims, 4))
    } else {
        (u32_le(&dims, 0), u32_le(&dims, 4))
    };
    cx.emit(Node::new("Image data").span(file.tail(h.image_offset.into())));
    cx.annotate(format!(
        "Cineon {}, {}×{}",
        h.version.trim(),
        w.unwrap_or(0),
        hgt.unwrap_or(0)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GPU textures: Valve VTF, PowerVR PVR, ASTC, Ericsson PKM

declare_format!(pub VTF = "vtf", "Valve texture", ["vtf"], "image/x-vtf",
    Probe::Magic(&[(0, b"VTF\0")]), vtf);

const VTF_FORMATS: EnumTable = &[
    (0, "RGBA8888"),
    (1, "ABGR8888"),
    (2, "RGB888"),
    (3, "BGR888"),
    (4, "RGB565"),
    (5, "I8"),
    (6, "IA88"),
    (8, "A8"),
    (12, "BGRA8888"),
    (13, "DXT1"),
    (14, "DXT3"),
    (15, "DXT5"),
    (24, "RGBA16161616F"),
];

record! {
    pub struct VtfHeader {
        magic: ascii[4] "Signature",
        major: u32 "Version major",
        minor: u32 "Version minor",
        header_size: u32 "Header size",
        width: u16 "Width",
        height: u16 "Height",
        flags: u32 "Flags" .hex(),
        frames: u16 "Frames",
        first_frame: u16 "First frame",
        _pad: u32 "Padding",
        reflectivity_r: f32 "Reflectivity R",
        reflectivity_g: f32 "Reflectivity G",
        reflectivity_b: f32 "Reflectivity B",
        _pad2: u32 "Padding",
        bump_scale: f32 "Bumpmap scale",
        format: u32 "High-res image format" .enumeration(VTF_FORMATS),
        mipmaps: u8 "Mipmap count",
        low_format: u32 "Low-res image format" .enumeration(VTF_FORMATS),
        low_width: u8 "Low-res width",
        low_height: u8 "Low-res height",
    }
}

async fn vtf(cx: Cx, input: Input) -> Result<()> {
    let h: VtfHeader = emit_record(&cx, input.span.sub(0, VtfHeader::SIZE), LE).await?;
    cx.emit(Node::new("Image data").span(input.span.tail(h.header_size.into())));
    let format = lookup(VTF_FORMATS, h.format.into()).unwrap_or("unknown format");
    cx.annotate(format!(
        "VTF {}.{}, {}×{}, {format}, {} mipmaps",
        h.major, h.minor, h.width, h.height, h.mipmaps
    ));
    Ok(())
}

declare_format!(pub PVR = "pvr", "PowerVR texture", ["pvr"], "image/x-pvr",
    Probe::Magic(&[(0, b"PVR\x03"), (0, b"\x03RVP")]), pvr);

const PVR_FORMATS: EnumTable = &[
    (0, "PVRTC 2bpp RGB"),
    (1, "PVRTC 2bpp RGBA"),
    (2, "PVRTC 4bpp RGB"),
    (3, "PVRTC 4bpp RGBA"),
    (6, "ETC1"),
    (7, "DXT1"),
    (9, "DXT3"),
    (11, "DXT5"),
    (22, "ETC2 RGB"),
    (23, "ETC2 RGBA"),
    (27, "ASTC 4x4"),
];

record! {
    pub struct PvrHeader {
        version: u32 "Version" .hex(),
        flags: u32 "Flags" .hex(),
        pixel_format: u64 "Pixel format" .enumeration(PVR_FORMATS),
        color_space: u32 "Colour space" .enumeration(&[(0, "linear RGB"), (1, "sRGB")]),
        channel_type: u32 "Channel type",
        height: u32 "Height",
        width: u32 "Width",
        depth: u32 "Depth",
        surfaces: u32 "Surfaces",
        faces: u32 "Faces",
        mipmaps: u32 "Mipmaps",
        metadata: u32 "Metadata size",
    }
}

async fn pvr(cx: Cx, input: Input) -> Result<()> {
    let h: PvrHeader = emit_record(&cx, input.span.sub(0, PvrHeader::SIZE), LE).await?;
    let data = PvrHeader::SIZE.saturating_add(h.metadata.into());
    if h.metadata > 0 {
        cx.emit(Node::new("Metadata").span(input.span.sub(PvrHeader::SIZE, h.metadata.into())));
    }
    cx.emit(Node::new("Texture data").span(input.span.tail(data)));
    let format = lookup(PVR_FORMATS, h.pixel_format)
        .map_or_else(|| format!("format {:#x}", h.pixel_format), str::to_owned);
    cx.annotate(format!(
        "{}×{}, {format}, {} mipmaps",
        h.width, h.height, h.mipmaps
    ));
    Ok(())
}

declare_format!(pub ASTC = "astc", "ASTC compressed texture", ["astc"], "image/astc",
    Probe::Magic(&[(0, b"\x13\xab\xa1\x5c")]), astc);

async fn astc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = cx.block(file.sub(0, 16)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &h, LE);
    f.u32("Magic").hex().emit()?;
    let bx = f.u8("Block width").emit()?;
    let by = f.u8("Block height").emit()?;
    let bz = f.u8("Block depth").emit()?;
    let dim = |d: &[u8]| {
        u32::from_le_bytes([
            d.first().copied().unwrap_or(0),
            d.get(1).copied().unwrap_or(0),
            d.get(2).copied().unwrap_or(0),
            0,
        ])
    };
    let w = dim(h.data.get(7..10).unwrap_or_default());
    let hh = dim(h.data.get(10..13).unwrap_or_default());
    let d = dim(h.data.get(13..16).unwrap_or_default());
    for (name, value, at) in [("Width", w, 7u64), ("Height", hh, 10), ("Depth", d, 13)] {
        cx.emit(Node::new(name).span(file.sub(at, 3)).value(Value::UInt {
            value: value.into(),
            bits: 24,
            radix: Radix::Dec,
        }));
    }
    cx.emit(Node::new("Blocks").span(file.tail(16)));
    cx.annotate(format!("{w}×{hh}×{d}, {bx}×{by}×{bz} blocks"));
    Ok(())
}

declare_format!(pub PKM = "pkm", "Ericsson ETC texture (PKM)", ["pkm"], "image/x-pkm",
    Probe::Magic(&[(0, b"PKM 10"), (0, b"PKM 20")]), pkm);

record! {
    pub struct PkmHeader {
        magic: ascii[4] "Magic",
        version: ascii[2] "Version",
        format: u16 "Format" .enumeration(&[(0, "ETC1 RGB"), (1, "ETC2 RGB"), (3, "ETC2 RGBA"), (4, "ETC2 RGBA1"), (5, "EAC R11"), (6, "EAC RG11")]),
        padded_width: u16 "Padded width",
        padded_height: u16 "Padded height",
        width: u16 "Width",
        height: u16 "Height",
    }
}

async fn pkm(cx: Cx, input: Input) -> Result<()> {
    let h: PkmHeader = emit_record(&cx, input.span.sub(0, PkmHeader::SIZE), BE).await?;
    cx.emit(Node::new("Texture data").span(input.span.tail(PkmHeader::SIZE)));
    cx.annotate(format!("PKM {}, {}×{}", h.version, h.width, h.height));
    Ok(())
}

// ---------------------------------------------------------------------------
// Colour swatches: Adobe ASE and ACO

declare_format!(pub ASE = "ase", "Adobe swatch exchange", ["ase"], "application/x-adobe-swatch-exchange",
    Probe::Magic(&[(0, b"ASEF")]), ase);

async fn ase(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    f.u16("Version major").emit()?;
    f.u16("Version minor").emit()?;
    let blocks = f.u32("Blocks").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(12);
    let mut colors = 0u32;
    for _ in 0..blocks.min(100_000) {
        if cur.remaining() < 6 {
            break;
        }
        let start = cur.pos();
        let kind = cur.u16().await?;
        let len = cur.u32().await?;
        let body = cur.span(len.into());
        cur.skip(len.into());
        let label = match kind {
            0xc001 => "Group start",
            0xc002 => "Group end",
            0x0001 => "Color",
            _ => "Block",
        };
        let mut node = Node::new(label).span(cur.since(start));
        if kind == 0x0001 || kind == 0xc001 {
            let data = cx.read_avail(body).await?;
            let units = usize::from(u16_be(&data, 0).unwrap_or(0));
            let name_bytes = data
                .get(2..2usize.saturating_add(units.saturating_mul(2)))
                .unwrap_or_default();
            let name = crate::text::utf16z(name_bytes, BE).0;
            if kind == 0x0001 {
                colors = colors.saturating_add(1);
                let model = String::from_utf8_lossy(
                    data.get(2usize.saturating_add(units.saturating_mul(2))..)
                        .and_then(|r| r.get(..4))
                        .unwrap_or_default(),
                )
                .into_owned();
                node = node.summary(format!("{name} ({})", model.trim()));
            } else {
                node = node.summary(name);
            }
        }
        cx.push(node).await;
    }
    cx.annotate(format!("{colors} colours"));
    Ok(())
}

fn aco_probe(h: &Head<'_>) -> bool {
    // Version 1 or 2, then a plausible count, then colour space ids.
    u16_be(h.data, 0).is_some_and(|v| v == 1 || v == 2)
        && u16_be(h.data, 2)
            .is_some_and(|n| n > 0 && u64::from(n).saturating_mul(10).saturating_add(4) <= h.len)
        && u16_be(h.data, 4).is_some_and(|space| matches!(space, 0..=2 | 7..=9))
        && h.len.saturating_sub(4).is_multiple_of(10)
}

declare_format!(pub ACO = "aco", "Adobe Photoshop colour swatches", ["aco"], "application/x-adobe-color-swatches",
    Probe::Custom(aco_probe), aco);

const ACO_SPACES: EnumTable = &[
    (0, "RGB"),
    (1, "HSB"),
    (2, "CMYK"),
    (7, "Lab"),
    (8, "Grayscale"),
    (9, "Wide CMYK"),
];

async fn aco(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let version = cur.u16().await?;
    let count = cur.u16().await?;
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 4))
            .summary(format!("version {version}, {count} colours")),
    );
    for i in 0..count {
        let start = cur.pos();
        let space = cur.u16().await?;
        let a = cur.u16().await?;
        let b = cur.u16().await?;
        let c = cur.u16().await?;
        let _d = cur.u16().await?;
        let space_name = lookup(ACO_SPACES, space.into()).unwrap_or("unknown");
        cx.push(
            Node::new(format!("Colour {i}"))
                .span(cur.since(start))
                .summary(format!("{space_name} {} {} {}", a >> 8, b >> 8, c >> 8)),
        )
        .await;
    }
    cx.annotate(format!("{count} colours"));
    Ok(())
}

// ---------------------------------------------------------------------------
// GIMP brushes and patterns, Paint.NET

fn gbr_probe(h: &Head<'_>) -> bool {
    h.at(20, b"GIMP")
}

fn gpat_probe(h: &Head<'_>) -> bool {
    h.at(20, b"GPAT")
}

declare_format!(pub GBR = "gbr", "GIMP brush", ["gbr"], "image/x-gimp-gbr",
    Probe::Custom(gbr_probe), gimp_brush);
declare_format!(pub GPAT = "pat", "GIMP pattern", ["pat"], "image/x-gimp-pat",
    Probe::Custom(gpat_probe), gimp_brush);

async fn gimp_brush(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 28)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &head, BE);
    let header = f.u32("Header size").emit()?;
    f.u32("Version").emit()?;
    let w = f.u32("Width").emit()?;
    let h = f.u32("Height").emit()?;
    let bytes = f.u32("Bytes per pixel").emit()?;
    let magic = f.ascii("Magic", 4).emit()?;
    let rest = file.sub(24, u64::from(header).saturating_sub(24));
    let (name, name_span) = if magic == "GIMP" {
        f.u32("Spacing").emit()?;
        (cx.read_avail(rest.tail(4)).await?, rest.tail(4))
    } else {
        (cx.read_avail(rest).await?, rest)
    };
    let name = crate::text::until_nul(&name);
    cx.emit(
        Node::new("Name")
            .span(name_span)
            .value(Value::Text(name.clone())),
    );
    cx.emit(Node::new("Pixels").span(file.tail(header.into())));
    cx.annotate(format!("{name:?}, {w}×{h}, {bytes} byte(s) per pixel"));
    Ok(())
}

declare_format!(pub PDN = "pdn", "Paint.NET image", ["pdn"], "image/x-paintnet",
    Probe::Magic(&[(0, b"PDN3")]), pdn);

async fn pdn(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 7)).await?;
    let len = u64::from(crate::bytes::u24_le(&head, 4).unwrap_or(0));
    cx.emit(Node::new("Magic").span(file.sub(0, 4)));
    let xml = file.sub(7, len);
    cx.emit(embedded("Header (XML)", input.nested(xml)));
    let text = String::from_utf8_lossy(&cx.read_avail(xml.sub(0, 512)).await?).into_owned();
    let attr = |name: &str| {
        text.find(&format!("{name}=\""))
            .and_then(|at| text.get(at.saturating_add(name.len()).saturating_add(2)..))
            .and_then(|r| r.split('"').next())
            .map(str::to_owned)
    };
    cx.emit(Node::new("Document (.NET serialized)").span(file.tail(7u64.saturating_add(len))));
    cx.annotate(format!(
        "Paint.NET, {}×{}",
        attr("width").unwrap_or_default(),
        attr("height").unwrap_or_default()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// BPG, FLIF, JPEG XR

declare_format!(pub BPG = "bpg", "Better Portable Graphics", ["bpg"], "image/bpg",
    Probe::Magic(&[(0, b"BPG\xfb")]), bpg);

/// BPG's ue7 variable-length integers.
fn ue7(data: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    for _ in 0..5 {
        let b = data.get(*at).copied().unwrap_or(0);
        *at = at.saturating_add(1);
        value = value.checked_shl(7).unwrap_or(0) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            break;
        }
    }
    value
}

async fn bpg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 32)).await?;
    let b4 = head.get(4).copied().unwrap_or(0);
    let format = [
        "grayscale",
        "4:2:0",
        "4:2:2",
        "4:4:4",
        "4:2:0 (MPEG2)",
        "4:2:2 (MPEG2)",
    ]
    .get(usize::from(b4 >> 5))
    .copied()
    .unwrap_or("unknown");
    let depth = (b4 & 0x0f).saturating_add(8);
    let mut at = 6usize;
    let width = ue7(&head, &mut at);
    let height = ue7(&head, &mut at);
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, crate::bytes::to_u64(at)))
            .summary(format!("{format}, {depth}-bit, alpha: {}", b4 & 0x10 != 0)),
    );
    cx.emit(Node::new("HEVC data").span(file.tail(crate::bytes::to_u64(at))));
    cx.annotate(format!("{width}×{height}, {format}, {depth}-bit"));
    Ok(())
}

declare_format!(pub FLIF = "flif", "Free Lossless Image Format", ["flif"], "image/flif",
    Probe::Magic(&[(0, b"FLIF")]), flif);

async fn flif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 16)).await?;
    let kind = head.get(4).copied().unwrap_or(0);
    let channels = kind & 0x0f;
    let interlaced = matches!(kind >> 4, 4 | 6);
    let animated = matches!(kind >> 4, 5 | 6);
    let depth = match head.get(5) {
        Some(b'1') => "8-bit",
        Some(b'2') => "16-bit",
        _ => "custom depth",
    };
    // Width and height are varints (minus one).
    let mut at = 6usize;
    let mut varint = || {
        let mut v = 0u64;
        for _ in 0..8 {
            let b = head.get(at).copied().unwrap_or(0);
            at = at.saturating_add(1);
            v = v.checked_shl(7).unwrap_or(0) | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
        v.saturating_add(1)
    };
    let width = varint();
    let height = varint();
    cx.emit(Node::new("Header").span(file.sub(0, crate::bytes::to_u64(at))));
    cx.emit(Node::new("Image data").span(file.tail(crate::bytes::to_u64(at))));
    cx.annotate(format!(
        "{width}×{height}, {channels} channel(s), {depth}{}{}",
        if interlaced { ", interlaced" } else { "" },
        if animated { ", animated" } else { "" }
    ));
    Ok(())
}

declare_format!(pub JXR = "jxr", "JPEG XR / HD Photo", ["jxr", "wdp", "hdp"], "image/jxr",
    Probe::Magic(&[(0, b"II\xbc\x01"), (0, b"II\xbc\x00")]), jxr);

async fn jxr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let ifd = u32_le(&head, 4).unwrap_or(0);
    cx.emit(Node::new("Header").span(file.sub(0, 8)));
    let count_bytes = cx.read(file.sub(ifd.into(), 2)).await?;
    let count = u16_le(&count_bytes, 0).unwrap_or(0);
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(u64::from(ifd).saturating_add(2));
    let mut width = 0u32;
    let mut height = 0u32;
    for _ in 0..count.min(256) {
        let start = cur.pos();
        let tag = cur.u16().await?;
        let kind = cur.u16().await?;
        let n = cur.u32().await?;
        let value = cur.u32().await?;
        match tag {
            0xbc80 => width = value,
            0xbc81 => height = value,
            _ => {}
        }
        let name = match tag {
            0xbc01 => "PixelFormat",
            0xbc02 => "Transformation",
            0xbc80 => "ImageWidth",
            0xbc81 => "ImageHeight",
            0xbcc0 => "ImageOffset",
            0xbcc1 => "ImageByteCount",
            0xbcc2 => "AlphaOffset",
            0xbcc3 => "AlphaByteCount",
            0x8773 => "ICC profile",
            0x02bc => "XMP metadata",
            _ => "Tag",
        };
        cx.push(
            Node::new(format!("{name} ({tag:#06x})"))
                .span(cur.since(start))
                .summary(format!("type {kind}, count {n}, value {value:#x}")),
        )
        .await;
    }
    cx.annotate(format!("{width}×{height}"));
    Ok(())
}
