//! Adobe Photoshop documents (PSD) and large documents (PSB).
//!
//! Five sections: a fixed header, color mode data, image resources (8BIM
//! blocks, also found in JPEG APP13 and TIFF), layer and mask information,
//! and the merged image data. Each length-prefixed section is shown with its
//! span; resources and layers are listed on expansion.

use crate::bytes::{u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::{Format, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

use super::{dims, region, text, uint};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "psd",
    title: "Adobe Photoshop document",
    extensions: &["psd", "psb"],
    mime: "image/vnd.adobe.photoshop",
    probe: Probe::Magic(&[(0, b"8BPS\x00\x01"), (0, b"8BPS\x00\x02")]),
    dissect: crate::expander!(dissect: Input),
};

const COLOR_MODES: EnumTable = &[
    (0, "Bitmap"),
    (1, "Grayscale"),
    (2, "Indexed"),
    (3, "RGB"),
    (4, "CMYK"),
    (7, "Multichannel"),
    (8, "Duotone"),
    (9, "Lab"),
];

const VERSIONS: EnumTable = &[(1, "PSD"), (2, "PSB (large document)")];

const COMPRESSION: EnumTable = &[
    (0, "Raw"),
    (1, "RLE (PackBits)"),
    (2, "ZIP"),
    (3, "ZIP with prediction"),
];

const LAYER_FLAGS: FlagTable = &[
    flag(0x01, "TRANSPARENCY_PROTECTED"),
    flag(0x02, "HIDDEN"),
    flag(0x04, "OBSOLETE"),
    flag(0x08, "BIT4_USEFUL"),
    flag(0x10, "PIXEL_DATA_IRRELEVANT"),
];

const RESOURCES: EnumTable = &[
    (1000, "Channels, rows, columns, depth and mode (obsolete)"),
    (1001, "Macintosh print manager info"),
    (1002, "Macintosh page format"),
    (1003, "Indexed color table (obsolete)"),
    (1005, "Resolution info"),
    (1006, "Alpha channel names"),
    (1007, "Display info (obsolete)"),
    (1008, "Caption"),
    (1009, "Border information"),
    (1010, "Background color"),
    (1011, "Print flags"),
    (1012, "Grayscale halftoning"),
    (1013, "Color halftoning"),
    (1014, "Duotone halftoning"),
    (1015, "Grayscale transfer function"),
    (1016, "Color transfer functions"),
    (1017, "Duotone transfer functions"),
    (1018, "Duotone image information"),
    (1019, "Effective black and white values"),
    (1021, "EPS options"),
    (1022, "Quick mask information"),
    (1024, "Layer state"),
    (1025, "Working path"),
    (1026, "Layers group information"),
    (1028, "IPTC-NAA record"),
    (1029, "Raw image mode"),
    (1030, "JPEG quality"),
    (1032, "Grid and guides"),
    (1033, "Thumbnail (Photoshop 4, BGR)"),
    (1034, "Copyright flag"),
    (1035, "URL"),
    (1036, "Thumbnail"),
    (1037, "Global angle"),
    (1038, "Color samplers (obsolete)"),
    (1039, "ICC profile"),
    (1040, "Watermark"),
    (1041, "ICC untagged profile"),
    (1042, "Effects visible"),
    (1043, "Spot halftone"),
    (1044, "Document ID seed"),
    (1045, "Unicode alpha names"),
    (1046, "Indexed color table count"),
    (1047, "Transparency index"),
    (1049, "Global altitude"),
    (1050, "Slices"),
    (1051, "Workflow URL"),
    (1052, "Jump to XPEP"),
    (1053, "Alpha identifiers"),
    (1054, "URL list"),
    (1057, "Version info"),
    (1058, "EXIF data 1"),
    (1059, "EXIF data 3"),
    (1060, "XMP metadata"),
    (1061, "Caption digest"),
    (1062, "Print scale"),
    (1064, "Pixel aspect ratio"),
    (1065, "Layer comps"),
    (1066, "Alternate duotone colors"),
    (1067, "Alternate spot colors"),
    (1069, "Layer selection IDs"),
    (1070, "HDR toning information"),
    (1071, "Print info"),
    (1072, "Layer groups enabled"),
    (1073, "Color samplers"),
    (1074, "Measurement scale"),
    (1075, "Timeline information"),
    (1076, "Sheet disclosure"),
    (1077, "Display info"),
    (1078, "Onion skins"),
    (1080, "Count information"),
    (1082, "Print information"),
    (1083, "Print style"),
    (1084, "Macintosh NSPrintInfo"),
    (1085, "Windows DEVMODE"),
    (1086, "Auto save file path"),
    (1087, "Auto save format"),
    (1088, "Path selection state"),
    (2999, "Clipping path name"),
    (3000, "Origin path info"),
    (7000, "Image Ready variables"),
    (7001, "Image Ready data sets"),
    (7002, "Image Ready default selected state"),
    (7003, "Image Ready 7 rollover expanded state"),
    (7004, "Image Ready rollover expanded state"),
    (7005, "Image Ready save layer settings"),
    (7006, "Image Ready version"),
    (8000, "Lightroom workflow"),
    (10000, "Print flags information"),
];

fn resource_name(id: u16) -> String {
    if let Some(name) = lookup(RESOURCES, id.into()) {
        return name.to_owned();
    }
    match id {
        2000..=2997 => format!("Path information #{}", id.saturating_sub(2000)),
        4000..=4999 => "Plug-in resource".to_owned(),
        _ => format!("Resource {id}"),
    }
}

record! {
    pub struct Header {
        signature: ascii[4] "Signature",
        version: u16 "Version" .enumeration(VERSIONS),
        reserved: bytes[6] "Reserved",
        channels: u16 "Channels" .desc("Including alpha channels"),
        height: u32 "Height",
        width: u32 "Width",
        depth: u16 "Depth" .desc("Bits per channel"),
        mode: u16 "Color mode" .enumeration(COLOR_MODES),
    }
}

record! {
    pub struct Thumbnail {
        format: u32 "Format" .desc("1 = JPEG (kJpegRGB), 0 = raw RGB"),
        width: u32 "Width",
        height: u32 "Height",
        width_bytes: u32 "Row bytes",
        total: u32 "Total size",
        compressed: u32 "Compressed size",
        bits: u16 "Bits per pixel",
        planes: u16 "Planes",
    }
}

record! {
    pub struct ResolutionInfo {
        h_res: u32 "Horizontal resolution" .desc("Fixed-point 16.16 pixels per inch")
            .with(|&v, n| n.summary(format!("{:.2}", f64::from(v) / 65536.0))),
        h_unit: u16 "Horizontal resolution unit" .desc("1 = pixels per inch, 2 = per cm"),
        width_unit: u16 "Width unit",
        v_res: u32 "Vertical resolution" .desc("Fixed-point 16.16 pixels per inch")
            .with(|&v, n| n.summary(format!("{:.2}", f64::from(v) / 65536.0))),
        v_unit: u16 "Vertical resolution unit",
        height_unit: u16 "Height unit",
    }
}

/// A length-prefixed section at `offset`: returns its whole span (prefix
/// included) and the span of its contents.
async fn section(cx: &Cx, file: Span, offset: u64, wide: bool) -> Result<(Span, Span)> {
    let n = if wide { 8 } else { 4 };
    let bytes = cx.read(file.sub(offset, n)).await?;
    let len = if wide {
        u64_be(&bytes, 0).unwrap_or(0)
    } else {
        u32_be(&bytes, 0).map(u64::from).unwrap_or(0)
    };
    let whole = file.sub(offset, len.saturating_add(n));
    Ok((whole, whole.tail(n)))
}

fn length_field(name: &'static str, span: Span, wide: bool) -> Node {
    crate::fields::struct_node(name, span, BE, wide, |f, &wide| {
        f.uword("Length", wide).emit().map(drop)
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let header = parse(&cx, header_span, BE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, BE));
    let psb = header.version == 2;
    let mode = lookup(COLOR_MODES, header.mode.into()).unwrap_or("unknown mode");
    let mut summary = format!(
        "{}, {mode}, {}-bit, {} channels",
        dims(header.width, header.height),
        header.depth,
        header.channels
    );
    if psb {
        summary = format!("PSB, {summary}");
    }
    cx.annotate(summary.clone());

    let mut pos = Header::SIZE;
    let (whole, data) = section(&cx, file, pos, false).await?;
    let mut node = Node::new("Color Mode Data")
        .span(whole)
        .summary(format!("{:#x} bytes", data.len));
    if header.mode == 2 && data.len == 768 {
        node = node.desc("Indexed color table: 256 red, then 256 green, then 256 blue values");
    }
    cx.emit(node);
    pos = pos.saturating_add(whole.len);

    let (whole, data) = section(&cx, file, pos, false).await?;
    cx.emit(
        resources_node("Image Resources", input, data)
            .span(whole)
            .summary(format!("{:#x} bytes", data.len)),
    );
    pos = pos.saturating_add(whole.len);

    let (whole, data) = section(&cx, file, pos, psb).await?;
    let layers = layer_count(&cx, data, psb).await;
    let mut node = Node::new("Layer and Mask Information").span(whole);
    if let Some(n) = layers {
        node = node.summary(format!("{} layers", n.unsigned_abs()));
        if n != 0 {
            cx.annotate(format!("{summary}, {} layers", n.unsigned_abs()));
        }
    }
    cx.emit(node.lazy(layer_and_mask, (whole, psb)));
    pos = pos.saturating_add(whole.len);

    let image = file.tail(pos);
    let comp = cx.read_avail(image.sub(0, 2)).await?;
    let method = u16_be(&comp, 0).unwrap_or(0);
    cx.emit(
        Node::new("Image Data")
            .span(image)
            .summary(
                lookup(COMPRESSION, method.into())
                    .map_or_else(|| format!("compression {method}"), str::to_owned),
            )
            .lazy(image_data, image),
    );
    Ok(())
}

async fn image_data(cx: Cx, image: Span) -> Result<()> {
    let block = cx.block(image.sub(0, 2)).await?;
    Fields::emitting(&cx, &block, BE)
        .u16("Compression")
        .enumeration(COMPRESSION)
        .emit()?;
    cx.emit(Node::new("Data").span(image.tail(2)));
    Ok(())
}

async fn layer_count(cx: &Cx, data: Span, psb: bool) -> Option<i16> {
    let n = if psb { 8 } else { 4 };
    let bytes = cx.read_avail(data.sub(n, 2)).await.ok()?;
    let len = cx.read_avail(data.sub(0, n)).await.ok()?;
    if len.iter().all(|&b| b == 0) {
        return Some(0);
    }
    u16_be(&bytes, 0).map(|v| i16::from_be_bytes(v.to_be_bytes()))
}

async fn layer_and_mask(cx: Cx, (whole, psb): (Span, bool)) -> Result<()> {
    let n = if psb { 8 } else { 4 };
    cx.emit(length_field("Section length", whole.sub(0, n), psb));
    let data = whole.tail(n);
    let (info, contents) = section(&cx, data, 0, psb).await?;
    if info.len > n {
        let count = layer_count(&cx, data, psb).await.unwrap_or(0);
        cx.emit(
            Node::new("Layer Info")
                .span(info)
                .summary(format!("{} layers", count.unsigned_abs()))
                .lazy(layer_info, (contents, psb)),
        );
    } else {
        cx.emit(length_field("Layer Info", info, psb));
    }
    let after = data.tail(info.len);
    if after.len >= 4 {
        let (mask, _) = section(&cx, after, 0, false).await?;
        cx.emit(Node::new("Global Layer Mask Info").span(mask));
        let rest = after.tail(mask.len);
        if !rest.is_empty() {
            cx.emit(
                Node::new("Additional Layer Information")
                    .span(rest)
                    .lazy(tagged_blocks, (rest, psb)),
            );
        }
    }
    Ok(())
}

record! {
    pub struct LayerRect {
        top: i32 "Top",
        left: i32 "Left",
        bottom: i32 "Bottom",
        right: i32 "Right",
        channels: u16 "Channels",
    }
}

async fn layer_info(cx: Cx, (contents, psb): (Span, bool)) -> Result<()> {
    let mut cur = Cursor::new(&cx, contents, BE);
    let count = cur.u16().await?;
    let count = i16::from_be_bytes(count.to_be_bytes());
    cx.emit(
        Node::new("Layer count")
            .span(contents.sub(0, 2))
            .value(crate::value::Value::Int {
                value: count.into(),
                bits: 16,
            })
            .desc("Negative: the first alpha channel holds the merged transparency"),
    );
    let channel_len: u64 = if psb { 10 } else { 6 };
    for index in 0..count.unsigned_abs() {
        let start = cur.pos();
        let (rect, _) = cur.record::<LayerRect>().await?;
        let mut channel_data = 0u64;
        for _ in 0..rect.channels {
            let entry = cur.bytes(channel_len).await?;
            let len = if psb {
                u64_be(&entry, 2).unwrap_or(0)
            } else {
                u32_be(&entry, 2).map(u64::from).unwrap_or(0)
            };
            channel_data = channel_data.saturating_add(len);
        }
        let blend = cur.bytes(12).await?;
        let extra = u64::from(cur.u32().await?);
        let extra_start = cur.pos();
        let mask_len = u64::from(cur.u32().await?);
        cur.skip(mask_len);
        let ranges_len = u64::from(cur.u32().await?);
        cur.skip(ranges_len);
        let name_len = cur.u8().await?;
        let name = cur.bytes(name_len.into()).await?;
        cur.seek(extra_start.saturating_add(extra));
        let span = cur.since(start);
        let mode = crate::text::latin1(blend.get(4..8).unwrap_or_default());
        let opacity = blend.get(8).copied().unwrap_or(0);
        let width = i64::from(rect.right).saturating_sub(rect.left.into());
        let height = i64::from(rect.bottom).saturating_sub(rect.top.into());
        cx.push(
            Node::new(format!("Layer {index}"))
                .span(span)
                .value(text(crate::text::latin1(&name)))
                .summary(format!(
                    "{}, blend {mode}, opacity {opacity}, {} channel bytes",
                    dims(width, height),
                    channel_data
                ))
                .lazy(layer_record_node, (span, psb)),
        )
        .await;
    }
    if !cur.at_end() {
        cx.push(
            Node::new("Channel image data")
                .span(contents.tail(cur.pos()))
                .summary("compressed per layer and channel"),
        )
        .await;
    }
    Ok(())
}

/// Decodes a layer record up to its name; returns the offset just past the
/// name, which is padded to a multiple of four bytes.
fn layer_record(f: &mut Fields<'_>, psb: &bool) -> Result<u64> {
    let rect = LayerRect::read(f)?;
    for _ in 0..rect.channels {
        f.int::<i16>("Channel ID")
            .desc("-1 = transparency mask, -2 = user mask, -3 = real user mask")
            .emit()?;
        f.uword("Channel data length", *psb).emit()?;
    }
    f.ascii("Blend mode signature", 4).emit()?;
    f.ascii("Blend mode key", 4).emit()?;
    f.u8("Opacity").emit()?;
    f.u8("Clipping").desc("0 = base, 1 = non-base").emit()?;
    f.u8("Flags").flags(LAYER_FLAGS).emit()?;
    f.u8("Filler").emit()?;
    f.u32("Extra data length").emit()?;
    let mask = f.u32("Layer mask data length").emit()?;
    f.skip(mask.into());
    let ranges = f.u32("Blending ranges length").emit()?;
    f.skip(ranges.into());
    let name_start = f.pos();
    let name_len = f.u8("Name length").emit()?;
    f.ascii("Name", name_len.into()).emit()?;
    let padded = (u64::from(name_len).saturating_add(4) / 4).saturating_mul(4);
    Ok(name_start.saturating_add(padded))
}

async fn layer_record_node(cx: Cx, (span, psb): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    // Additional layer information follows the padded Pascal name.
    let name_end = layer_record(&mut f, &psb)?;
    let blocks = span.tail(name_end);
    if !blocks.is_empty() {
        cx.emit(
            Node::new("Additional Layer Information")
                .span(blocks)
                .lazy(tagged_blocks, (blocks, psb)),
        );
    }
    Ok(())
}

/// Keys of tagged blocks whose length is 8 bytes in PSB files.
const WIDE_KEYS: &[&[u8]] = &[
    b"LMsk", b"Lr16", b"Lr32", b"Layr", b"Mt16", b"Mt32", b"Mtrn", b"Alph", b"FMsk", b"lnk2",
    b"FEid", b"FXid", b"PxSD",
];

async fn tagged_blocks(cx: Cx, (span, psb): (Span, bool)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    while cur.remaining() >= 12 {
        let start = cur.pos();
        let sig = cur.bytes(4).await?;
        if sig != b"8BIM" && sig != b"8B64" {
            break;
        }
        let key = cur.bytes(4).await?;
        let wide = psb && WIDE_KEYS.contains(&key.as_slice());
        let len = if wide {
            cur.u64().await?
        } else {
            cur.u32().await?.into()
        };
        cur.skip(len);
        let span = cur.since(start);
        cx.push(
            Node::new(crate::text::latin1(&key))
                .span(span)
                .summary(format!("{len:#x} bytes")),
        )
        .await;
    }
    Ok(())
}

/// A lazy node listing image resource blocks (`8BIM`, id, name, data) in
/// `span`, as found in PSD files, JPEG APP13 segments and TIFF tag 34377.
pub fn resources_node(name: &'static str, input: Input, span: Span) -> Node {
    Node::new(name).span(span).lazy(resources, (input, span))
}

async fn resources(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    while cur.remaining() >= 12 {
        let start = cur.pos();
        let sig = cur.bytes(4).await?;
        if !matches!(sig.as_slice(), b"8BIM" | b"MeSa" | b"AgHg" | b"PHUT" | b"DCSR") {
            return Err(Diagnostic::malformed("expected an 8BIM resource signature")
                .at(cur.since(start)));
        }
        let id = cur.u16().await?;
        let name_len = cur.u8().await?;
        let name = cur.bytes(name_len.into()).await?;
        // The Pascal string (length byte included) is padded to even size.
        if name_len % 2 == 0 {
            cur.skip(1);
        }
        let size = u64::from(cur.u32().await?);
        let data = cur.span(size);
        cur.skip(size.saturating_add(size % 2));
        let span = cur.since(start);
        let mut node = Node::new(resource_name(id))
            .span(span)
            .value(uint(id))
            .summary(format!("{size:#x} bytes"));
        if !name.is_empty() {
            node = node.summary(format!("{:?}, {size:#x} bytes", crate::text::latin1(&name)));
        }
        let state = Resource {
            input,
            span,
            data,
            id,
        };
        cx.push(node.lazy(resource, state)).await;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Resource {
    input: Input,
    span: Span,
    data: Span,
    id: u16,
}

async fn resource(cx: Cx, r: Resource) -> Result<()> {
    let header_len = r.data.offset.saturating_sub(r.span.offset);
    let block = cx.block(r.span.sub(0, header_len)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.ascii("Signature", 4).emit()?;
    f.u16("Resource ID")
        .with(|&id, n| n.summary(resource_name(id)))
        .emit()?;
    let name_len = f.u8("Name length").emit()?;
    f.ascii("Name", name_len.into()).emit()?;
    if name_len % 2 == 0 {
        f.skip(1);
    }
    f.u32("Data size").emit()?;
    let data = r.data;
    let input = r.input;
    match r.id {
        1005 => cx.emit(ResolutionInfo::node("Resolution", data, BE)),
        1039 => cx.emit(embedded("ICC profile", input.nested(data))),
        1058 | 1059 => cx.emit(embedded_as(
            "Exif",
            input.nested(data),
            &super::tiff::FORMAT,
        )),
        1060 => cx.emit(embedded("XMP packet", input.nested(data))),
        1033 | 1036 => {
            cx.emit(Thumbnail::node("Thumbnail header", data.sub(0, Thumbnail::SIZE), BE));
            let image = data.tail(Thumbnail::SIZE);
            let format = cx.read_avail(data.sub(0, 4)).await?;
            if u32_be(&format, 0) == Some(1) {
                cx.emit(embedded("Thumbnail image", input.nested(image)));
            } else {
                cx.emit(Node::new("Thumbnail pixels").span(image));
            }
        }
        _ => cx.emit(region("Data", data, 0, data.len)),
    }
    Ok(())
}
