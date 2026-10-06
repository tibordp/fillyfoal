//! GPU texture containers: ASTC (`.astc`), PowerVR (PVR v3) and Valve
//! Texture Format (VTF).

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

use super::{dims, region};

const LE: Endian = Endian::Little;

pub static ASTC: Format = Format {
    name: "astc",
    title: "ASTC compressed texture",
    extensions: &["astc"],
    mime: "image/astc",
    probe: Probe::Magic(&[(0, b"\x13\xab\xa1\x5c")]),
    dissect: crate::expander!(dissect_astc: Input),
};

pub static PVR: Format = Format {
    name: "pvr",
    title: "PowerVR texture (v3)",
    extensions: &["pvr"],
    mime: "image/x-pvr",
    probe: Probe::Magic(&[(0, b"PVR\x03"), (0, b"\x03RVP")]),
    dissect: crate::expander!(dissect_pvr: Input),
};

pub static VTF: Format = Format {
    name: "vtf",
    title: "Valve texture",
    extensions: &["vtf"],
    mime: "image/x-vtf",
    probe: Probe::Magic(&[(0, b"VTF\0\x07\0\0\0")]),
    dissect: crate::expander!(dissect_vtf: Input),
};

// ---------------------------------------------------------------------------
// ASTC

/// A 24-bit little-endian value.
fn u24(b: &[u8]) -> u32 {
    crate::bytes::u24_le(b, 0).unwrap_or(0)
}

fn astc_header(f: &mut Fields<'_>, _: &()) -> Result<(u8, u8, u8, u32, u32, u32)> {
    f.bytes("Magic", 4).emit()?;
    let bx = f.u8("Block width").emit()?;
    let by = f.u8("Block height").emit()?;
    let bz = f.u8("Block depth").emit()?;
    let mut size = |name: &'static str| {
        f.bytes(name, 3)
            .with(|b, n| n.value(super::uint(u24(b))))
            .emit()
            .map(|b| u24(&b))
    };
    let x = size("Width")?;
    let y = size("Height")?;
    let z = size("Depth")?;
    Ok((bx, by, bz, x, y, z))
}

pub async fn dissect_astc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, 16);
    let block = cx.block(span).await?;
    let (bx, by, bz, x, y, z) = astc_header(&mut Fields::emitting(&cx, &block, LE), &())?;
    let mut summary = format!("{}, {bx}×{by} blocks", dims(x, y));
    if z > 1 || bz > 1 {
        summary = format!("{summary}, depth {z} ({bz})");
    }
    cx.annotate(summary);
    let blocks = |n: u32, b: u8| u64::from(n).div_ceil(u64::from(b.max(1)));
    let count = blocks(x, bx)
        .saturating_mul(blocks(y, by))
        .saturating_mul(blocks(z, bz));
    cx.emit(
        region("Blocks", file, 16, count.saturating_mul(16)).summary(format!("{count} 128-bit blocks")),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// PVR v3

const PVR_FLAGS: FlagTable = &[flag(0x2, "PREMULTIPLIED")];

const PVR_FORMATS: EnumTable = &[
    (0, "PVRTC 2bpp RGB"),
    (1, "PVRTC 2bpp RGBA"),
    (2, "PVRTC 4bpp RGB"),
    (3, "PVRTC 4bpp RGBA"),
    (4, "PVRTC-II 2bpp"),
    (5, "PVRTC-II 4bpp"),
    (6, "ETC1"),
    (7, "DXT1 (BC1)"),
    (8, "DXT2"),
    (9, "DXT3 (BC2)"),
    (10, "DXT4"),
    (11, "DXT5 (BC3)"),
    (12, "BC4"),
    (13, "BC5"),
    (14, "BC6"),
    (15, "BC7"),
    (22, "ETC2 RGB"),
    (23, "ETC2 RGBA"),
    (24, "ETC2 RGB A1"),
    (25, "EAC R11"),
    (26, "EAC RG11"),
    (27, "ASTC 4x4"),
    (28, "ASTC 5x4"),
    (29, "ASTC 5x5"),
    (30, "ASTC 6x5"),
    (31, "ASTC 6x6"),
    (32, "ASTC 8x5"),
    (33, "ASTC 8x6"),
    (34, "ASTC 8x8"),
];

const COLOR_SPACES: EnumTable = &[(0, "Linear RGB"), (1, "sRGB")];

const CHANNEL_TYPES: EnumTable = &[
    (0, "Unsigned byte, normalized"),
    (1, "Signed byte, normalized"),
    (2, "Unsigned byte"),
    (3, "Signed byte"),
    (4, "Unsigned short, normalized"),
    (5, "Signed short, normalized"),
    (6, "Unsigned short"),
    (7, "Signed short"),
    (8, "Unsigned int, normalized"),
    (9, "Signed int, normalized"),
    (10, "Unsigned int"),
    (11, "Signed int"),
    (12, "Float"),
];

record! {
    pub struct PvrHeader {
        version: u32 "Version" .hex(),
        flags: u32 "Flags" .flags(PVR_FLAGS),
        pixel_format: u64 "Pixel format" .hex() .desc("Compressed format id, or channel names and bit counts"),
        color_space: u32 "Color space" .enumeration(COLOR_SPACES),
        channel_type: u32 "Channel type" .enumeration(CHANNEL_TYPES),
        height: u32 "Height",
        width: u32 "Width",
        depth: u32 "Depth",
        surfaces: u32 "Surfaces",
        faces: u32 "Faces",
        mipmaps: u32 "MIP-map count",
        metadata_size: u32 "Metadata size",
    }
}

fn pvr_format(v: u64) -> String {
    if v >> 32 == 0 {
        return lookup(PVR_FORMATS, v).map_or_else(|| format!("format {v}"), str::to_owned);
    }
    // Low four bytes: channel names; high four bytes: bits per channel.
    let names = v.to_le_bytes();
    let mut out = String::new();
    for i in 0..4usize {
        let (Some(&c), Some(&bits)) = (names.get(i), names.get(i.saturating_add(4))) else {
            break;
        };
        if c != 0 {
            out.push(char::from(c));
            out.push_str(&bits.to_string());
        }
    }
    out
}

pub async fn dissect_pvr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let endian = if magic == b"PVR\x03" {
        LE
    } else {
        Endian::Big
    };
    let span = file.sub(0, PvrHeader::SIZE);
    let h = parse(&cx, span, endian, &(), PvrHeader::layout).await?;
    cx.emit(PvrHeader::node("Header", span, endian).summary(pvr_format(h.pixel_format)));
    cx.annotate(format!(
        "{}, {}, {} mip levels",
        dims(h.width, h.height),
        pvr_format(h.pixel_format),
        h.mipmaps
    ));
    let meta = file.sub(PvrHeader::SIZE, h.metadata_size.into());
    if h.metadata_size > 0 {
        cx.emit(
            Node::new("Metadata")
                .span(meta)
                .lazy(pvr_metadata, (meta, endian)),
        );
    }
    let start = PvrHeader::SIZE.saturating_add(h.metadata_size.into());
    cx.emit(region("Texture data", file, start, file.len.saturating_sub(start)));
    Ok(())
}

async fn pvr_metadata(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let mut pos = 0u64;
    while pos.saturating_add(12) <= span.len {
        let head = cx.block(span.sub(pos, 12)).await?;
        let mut f = Fields::new(&head, endian);
        let fourcc = f.bytes("FourCC", 4).get()?;
        let key = f.u32("Key").get()?;
        let size = f.u32("Size").get()?;
        let entry = span.sub(pos, 12u64.saturating_add(size.into()));
        cx.push(
            Node::new(format!("{} {key}", crate::text::latin1(&fourcc)))
                .span(entry)
                .summary(format!("{size} bytes")),
        )
        .await;
        pos = pos.saturating_add(entry.len.max(12));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// VTF

const VTF_FORMATS: EnumTable = &[
    (0, "RGBA8888"),
    (1, "ABGR8888"),
    (2, "RGB888"),
    (3, "BGR888"),
    (4, "RGB565"),
    (5, "I8"),
    (6, "IA88"),
    (7, "P8"),
    (8, "A8"),
    (9, "RGB888_BLUESCREEN"),
    (10, "BGR888_BLUESCREEN"),
    (11, "ARGB8888"),
    (12, "BGRA8888"),
    (13, "DXT1"),
    (14, "DXT3"),
    (15, "DXT5"),
    (16, "BGRX8888"),
    (17, "BGR565"),
    (18, "BGRX5551"),
    (19, "BGRA4444"),
    (20, "DXT1_ONEBITALPHA"),
    (21, "BGRA5551"),
    (22, "UV88"),
    (23, "UVWQ8888"),
    (24, "RGBA16161616F"),
    (25, "RGBA16161616"),
    (26, "UVLX8888"),
    (0xffff_ffff, "NONE"),
];

const VTF_FLAGS: FlagTable = &[
    flag(0x1, "POINTSAMPLE"),
    flag(0x2, "TRILINEAR"),
    flag(0x4, "CLAMPS"),
    flag(0x8, "CLAMPT"),
    flag(0x10, "ANISOTROPIC"),
    flag(0x20, "HINT_DXT5"),
    flag(0x40, "PWL_CORRECTED"),
    flag(0x80, "NORMAL"),
    flag(0x100, "NOMIP"),
    flag(0x200, "NOLOD"),
    flag(0x400, "ALL_MIPS"),
    flag(0x800, "PROCEDURAL"),
    flag(0x1000, "ONEBITALPHA"),
    flag(0x2000, "EIGHTBITALPHA"),
    flag(0x4000, "ENVMAP"),
    flag(0x8000, "RENDERTARGET"),
    flag(0x10000, "DEPTHRENDERTARGET"),
    flag(0x20000, "NODEBUGOVERRIDE"),
    flag(0x40000, "SINGLECOPY"),
];

const VTF_RESOURCES: EnumTable = &[
    (0x01, "Low-resolution image"),
    (0x30, "High-resolution image"),
    (0x10, "Animated particle sheet"),
    // Three-character tags, read as little-endian 24-bit numbers.
    (0x0043_5243, "CRC"),
    (0x0044_4f4c, "Texture LOD settings"),
    (0x004f_5354, "Extended flags"),
    (0x0044_564b, "Key/values"),
];

fn vtf_header(f: &mut Fields<'_>, _: &()) -> Result<(u32, u16, u16, u32, u8, u32)> {
    f.ascii("Signature", 4).emit()?;
    f.u32("Major version").emit()?;
    let minor = f.u32("Minor version").emit()?;
    f.u32("Header size").emit()?;
    let width = f.u16("Width").emit()?;
    let height = f.u16("Height").emit()?;
    f.u32("Flags").flags(VTF_FLAGS).emit()?;
    f.u16("Frames").emit()?;
    f.u16("First frame").emit()?;
    f.bytes("Padding", 4).emit()?;
    f.f32("Reflectivity R").emit()?;
    f.f32("Reflectivity G").emit()?;
    f.f32("Reflectivity B").emit()?;
    f.bytes("Padding", 4).emit()?;
    f.f32("Bump map scale").emit()?;
    let format = f.u32("High-resolution format").enumeration(VTF_FORMATS).emit()?;
    let mipmaps = f.u8("MIP-map count").emit()?;
    f.u32("Low-resolution format").enumeration(VTF_FORMATS).emit()?;
    f.u8("Low-resolution width").emit()?;
    f.u8("Low-resolution height").emit()?;
    if minor >= 2 {
        f.u16("Depth").emit()?;
    }
    let mut resources = 0;
    if minor >= 3 {
        f.bytes("Padding", 3).emit()?;
        resources = f.u32("Resource count").emit()?;
        f.bytes("Padding", 8).emit()?;
    }
    Ok((minor, width, height, format, mipmaps, resources))
}

pub async fn dissect_vtf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let size_bytes = cx.read(file.sub(12, 4)).await?;
    let header_size = u64::from(u32_le(&size_bytes, 0).unwrap_or(0)).clamp(16, 0x1_0000);
    // The fixed part is 80 bytes at most; 7.3 resource entries follow it.
    let span = file.sub(0, header_size.min(80));
    let block = cx.block(span).await?;
    let (minor, width, height, format, mipmaps, resources) = vtf_header(&mut Fields::new(&block, LE), &())?;
    cx.emit(crate::fields::struct_node("Header", span, LE, (), vtf_header));
    let format_name = lookup(VTF_FORMATS, format.into()).unwrap_or("unknown format");
    cx.annotate(format!(
        "VTF 7.{minor}, {}, {format_name}, {mipmaps} mip levels",
        dims(width, height)
    ));
    if resources > 0 {
        // Resource entries follow the 80-byte fixed header.
        let table = file.sub(80, u64::from(resources.min(32)).saturating_mul(8));
        cx.emit(Node::new("Resources").span(table).lazy(vtf_resources, (file, table)));
    } else {
        cx.emit(region("Image data", file, header_size, file.len.saturating_sub(header_size)));
    }
    Ok(())
}

async fn vtf_resources(cx: Cx, (file, table): (Span, Span)) -> Result<()> {
    let n = table.len / 8;
    for i in 0..n {
        let span = table.sub(i.saturating_mul(8), 8);
        let b = cx.read(span).await?;
        let tag = u24(&b);
        let flags = b.get(3).copied().unwrap_or(0);
        let data = u32_le(&b, 4).unwrap_or(0);
        let name = lookup(VTF_RESOURCES, tag.into()).map_or_else(|| format!("Resource {tag:#08x}"), str::to_owned);
        let mut node = Node::new(name).span(span);
        node = if flags & 0x2 != 0 {
            node.value(super::hex(data)).summary("inline value")
        } else {
            node.value(super::hex(data)).target(file.tail(data.into()))
        };
        cx.push(node).await;
    }
    Ok(())
}
