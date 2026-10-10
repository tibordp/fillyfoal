//! GPU texture containers: ASTC (`.astc`), PowerVR (PVR v3) and Valve
//! Texture Format (VTF).
//!
//! All three are a header followed by the (block-compressed or raw) texel
//! data. Where the pixel format's size is known, the data is split into its
//! MIP levels.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse};
use crate::formats::util::arcutil::human_size;
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

/// Size in bytes of a `w`×`h` image stored in `bw`×`bh` blocks of `bytes`
/// bytes.
fn blocks(w: u64, h: u64, bw: u64, bh: u64, bytes: u64) -> u64 {
    w.div_ceil(bw.max(1))
        .saturating_mul(h.div_ceil(bh.max(1)))
        .saturating_mul(bytes)
}

/// "1 MIP level", "5 MIP levels".
fn mip_levels(n: u32) -> String {
    if n == 1 {
        "1 MIP level".to_owned()
    } else {
        format!("{n} MIP levels")
    }
}

/// One MIP level's dimension.
fn mip(size: u64, level: u32) -> u64 {
    size.checked_shr(level).unwrap_or(0).max(1)
}

// ---------------------------------------------------------------------------
// ASTC

/// A 24-bit little-endian value.
fn u24(b: &[u8]) -> u32 {
    crate::bytes::u24_le(b, 0).unwrap_or(0)
}

fn astc_header(f: &mut Fields<'_>, _: &()) -> Result<(u8, u8, u8, u32, u32, u32)> {
    f.u32("Magic").hex().emit()?;
    let bx = f.u8("Block width").desc("Texels").emit()?;
    let by = f.u8("Block height").desc("Texels").emit()?;
    let bz = f.u8("Block depth").desc("Texels; 1 for 2D").emit()?;
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
    let texels = u32::from(bx)
        .saturating_mul(by.into())
        .saturating_mul(bz.max(1).into());
    // Every block is 128 bits, whatever its footprint.
    let bpp = 128.0 / f64::from(texels.max(1));
    let footprint = if bz > 1 {
        format!("{bx}×{by}×{bz}")
    } else {
        dims(bx, by)
    };
    let mut summary = format!("{}, {footprint} blocks ({bpp:.2} bpp)", dims(x, y));
    if z > 1 {
        summary = format!("{summary}, depth {z}");
    }
    cx.annotate(summary);
    let count = blocks(x.into(), y.into(), bx.into(), by.into(), 1)
        .saturating_mul(u64::from(z.max(1)).div_ceil(u64::from(bz.max(1))));
    cx.emit(
        region("Blocks", file, 16, count.saturating_mul(16))
            .summary(format!("{count} 128-bit blocks")),
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
    (16, "UYVY"),
    (17, "YUY2"),
    (18, "1bpp black and white"),
    (19, "R9G9B9E5 shared exponent"),
    (20, "RGBG8888"),
    (21, "GRGB8888"),
    (22, "ETC2 RGB"),
    (23, "ETC2 RGBA"),
    (24, "ETC2 RGB A1"),
    (25, "EAC R11"),
    (26, "EAC RG11"),
    (27, "ASTC 4×4"),
    (28, "ASTC 5×4"),
    (29, "ASTC 5×5"),
    (30, "ASTC 6×5"),
    (31, "ASTC 6×6"),
    (32, "ASTC 8×5"),
    (33, "ASTC 8×6"),
    (34, "ASTC 8×8"),
    (35, "ASTC 10×5"),
    (36, "ASTC 10×6"),
    (37, "ASTC 10×8"),
    (38, "ASTC 10×10"),
    (39, "ASTC 12×10"),
    (40, "ASTC 12×12"),
];

/// The ASTC footprints of PVR formats 27–40.
const PVR_ASTC: [(u64, u64); 14] = [
    (4, 4),
    (5, 4),
    (5, 5),
    (6, 5),
    (6, 6),
    (8, 5),
    (8, 6),
    (8, 8),
    (10, 5),
    (10, 6),
    (10, 8),
    (10, 10),
    (12, 10),
    (12, 12),
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
    (12, "Signed float"),
    (13, "Unsigned float"),
];

/// Keys of the metadata with the FourCC `PVR\x03`.
const PVR_METADATA: EnumTable = &[
    (0, "Texture atlas coordinates"),
    (1, "Bump map"),
    (2, "Cube map order"),
    (3, "Orientation"),
    (4, "Border"),
    (5, "Padding"),
];

record! {
    pub struct PvrHeader {
        version: u32 "Version" .hex(),
        flags: u32 "Flags" .flags(PVR_FLAGS),
        pixel_format: u64 "Pixel format" .hex() .with(|&v, n| n.summary(pvr_format(v))) .desc("Compressed format id, or channel names (low 4 bytes) and bits per channel (high 4 bytes)"),
        color_space: u32 "Color space" .enumeration(COLOR_SPACES),
        channel_type: u32 "Channel type" .enumeration(CHANNEL_TYPES),
        height: u32 "Height",
        width: u32 "Width",
        depth: u32 "Depth",
        surfaces: u32 "Surfaces" .desc("Array layers"),
        faces: u32 "Faces" .desc("6 for a cube map"),
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

/// Bytes of one `w`×`h` image (one face, surface and slice) in `format`.
fn pvr_image_size(format: u64, w: u64, h: u64) -> Option<u64> {
    if format >> 32 != 0 {
        // Uncompressed: the bits of all channels.
        let bits: u64 = format
            .to_le_bytes()
            .iter()
            .skip(4)
            .map(|&b| u64::from(b))
            .sum();
        return Some(w.saturating_mul(h).saturating_mul(bits).div_ceil(8));
    }
    Some(match format {
        // PVRTC needs at least 2×2 blocks.
        0 | 1 => blocks(w.max(16), h.max(8), 8, 4, 8),
        2 | 3 => blocks(w.max(8), h.max(8), 4, 4, 8),
        6 | 7 | 12 | 22 | 24 | 25 => blocks(w, h, 4, 4, 8),
        8..=11 | 13..=15 | 23 | 26 => blocks(w, h, 4, 4, 16),
        27..=40 => {
            let index = crate::bytes::to_usize(format.saturating_sub(27));
            let &(bw, bh) = PVR_ASTC.get(index)?;
            blocks(w, h, bw, bh, 16)
        }
        _ => return None,
    })
}

pub async fn dissect_pvr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let endian = if magic == b"PVR\x03" { LE } else { Endian::Big };
    let span = file.sub(0, PvrHeader::SIZE);
    let h = parse(&cx, span, endian, &(), PvrHeader::layout).await?;
    let format = pvr_format(h.pixel_format);
    cx.emit(PvrHeader::node("Header", span, endian).summary(format.clone()));
    let mut summary = format!("{}, {format}", dims(h.width, h.height));
    if h.depth > 1 {
        summary = format!("{summary}, depth {}", h.depth);
    }
    if h.faces == 6 {
        summary.push_str(", cube map");
    } else if h.faces > 1 {
        summary = format!("{summary}, {} faces", h.faces);
    }
    if h.surfaces > 1 {
        summary = format!("{summary}, {} surfaces", h.surfaces);
    }
    if h.color_space == 1 {
        summary.push_str(", sRGB");
    }
    cx.annotate(format!("{summary}, {}", mip_levels(h.mipmaps)));
    let meta = file.sub(PvrHeader::SIZE, h.metadata_size.into());
    if h.metadata_size > 0 {
        cx.emit(
            Node::new("Metadata")
                .span(meta)
                .lazy(pvr_metadata, (meta, endian)),
        );
    }
    let start = PvrHeader::SIZE.saturating_add(h.metadata_size.into());
    let data = file.tail(start);
    let mut node = region("Texture data", file, start, data.len);
    // Level by level, largest first; each level holds every surface, face
    // and depth slice.
    let copies = u64::from(h.surfaces.max(1)).saturating_mul(h.faces.max(1).into());
    let level_size = |level: u32| {
        let one = pvr_image_size(
            h.pixel_format,
            mip(h.width.into(), level),
            mip(h.height.into(), level),
        )?;
        Some(
            one.saturating_mul(mip(h.depth.into(), level))
                .saturating_mul(copies),
        )
    };
    let levels = h.mipmaps.clamp(1, 32);
    if level_size(0).is_some() {
        let total = (0..levels)
            .filter_map(level_size)
            .fold(0u64, u64::saturating_add);
        node = region("Texture data", file, start, total)
            .summary(format!("{}, {}", mip_levels(levels), human_size(total)))
            .lazy(
                pvr_levels,
                (
                    data,
                    h.pixel_format,
                    h.width,
                    h.height,
                    h.depth,
                    copies,
                    levels,
                ),
            );
    }
    cx.emit(node);
    Ok(())
}

async fn pvr_levels(
    cx: Cx,
    (data, format, width, height, depth, copies, levels): (Span, u64, u32, u32, u32, u64, u32),
) -> Result<()> {
    let mut pos = 0u64;
    for level in 0..levels {
        let (w, h, d) = (
            mip(width.into(), level),
            mip(height.into(), level),
            mip(depth.into(), level),
        );
        let len = pvr_image_size(format, w, h)
            .unwrap_or(0)
            .saturating_mul(d)
            .saturating_mul(copies);
        let mut summary = dims(w, h);
        if d > 1 {
            summary = format!("{summary}×{d}");
        }
        cx.push(
            region(format!("MIP level {level}"), data, pos, len)
                .summary(format!("{summary}, {}", human_size(len))),
        )
        .await;
        pos = pos.saturating_add(len);
    }
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
        let ours = fourcc == b"PVR\x03" || fourcc == b"\x03RVP";
        let name = match lookup(PVR_METADATA, key.into()).filter(|_| ours) {
            Some(name) => name.to_owned(),
            None => format!("{} {key}", crate::text::latin1(&fourcc).escape_debug()),
        };
        let value = entry.tail(12);
        let bytes = cx.read_avail(value.sub(0, 16)).await?;
        let summary = match (ours, key) {
            (true, 2) => format!(
                "{:?}",
                crate::text::latin1(bytes.get(..6).unwrap_or(bytes.as_slice()))
            ),
            (true, 3) => format!(
                "x: {}, y: {}, z: {}",
                if bytes.first() == Some(&1) {
                    "left"
                } else {
                    "right"
                },
                if bytes.get(1) == Some(&1) {
                    "up"
                } else {
                    "down"
                },
                if bytes.get(2) == Some(&1) {
                    "out"
                } else {
                    "in"
                },
            ),
            _ => human_size(size.into()),
        };
        cx.push(Node::new(name).span(entry).summary(summary)).await;
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

const VTF_ENVMAP: u32 = 0x4000;

const VTF_RESOURCES: EnumTable = &[
    (0x01, "Low-resolution image"),
    (0x30, "High-resolution image"),
    (0x10, "Animated particle sheet"),
    // Three-character tags, read as little-endian 24-bit numbers.
    (0x0043_5243, "CRC"),
    (0x0044_4f4c, "Texture LOD settings"),
    // "TS0"; some writers and documents spell it "TSO".
    (0x0030_5354, "Extended flags"),
    (0x004f_5354, "Extended flags"),
    (0x0044_564b, "Key/values"),
];

/// Bytes of a `w`×`h` image in VTF `format`.
fn vtf_image_size(format: u32, w: u64, h: u64) -> Option<u64> {
    let bytes_per_pixel: u64 = match format {
        13 | 20 => return Some(blocks(w, h, 4, 4, 8)),
        14 | 15 => return Some(blocks(w, h, 4, 4, 16)),
        5 | 7 | 8 => 1,
        4 | 6 | 17..=19 | 21 | 22 => 2,
        2 | 3 | 9 | 10 => 3,
        0 | 1 | 11 | 12 | 16 | 23 | 26 => 4,
        24 | 25 => 8,
        _ => return None,
    };
    Some(w.saturating_mul(h).saturating_mul(bytes_per_pixel))
}

/// What the dissector needs from the VTF header.
#[derive(Clone, Copy, Debug)]
struct VtfInfo {
    minor: u32,
    width: u16,
    height: u16,
    flags: u32,
    frames: u16,
    first_frame: u16,
    format: u32,
    mipmaps: u8,
    low_format: u32,
    low_width: u8,
    low_height: u8,
    depth: u16,
    resources: u32,
}

impl VtfInfo {
    /// Faces per frame: 6 for a cube map, 7 (with a sphere map) before 7.5.
    fn faces(&self) -> u64 {
        if self.flags & VTF_ENVMAP == 0 {
            1
        } else if self.minor < 5 && self.first_frame != 0xffff {
            7
        } else {
            6
        }
    }

    /// Bytes of MIP level `level` (all frames, faces and slices).
    fn level_size(&self, level: u32) -> Option<u64> {
        let one = vtf_image_size(
            self.format,
            mip(self.width.into(), level),
            mip(self.height.into(), level),
        )?;
        Some(
            one.saturating_mul(mip(self.depth.max(1).into(), level))
                .saturating_mul(self.faces())
                .saturating_mul(self.frames.max(1).into()),
        )
    }

    fn low_size(&self) -> Option<u64> {
        if self.low_format == u32::MAX || self.low_width == 0 || self.low_height == 0 {
            return None;
        }
        vtf_image_size(
            self.low_format,
            self.low_width.into(),
            self.low_height.into(),
        )
    }
}

fn vtf_header(f: &mut Fields<'_>, _: &()) -> Result<VtfInfo> {
    f.ascii("Signature", 4).emit()?;
    f.u32("Major version").emit()?;
    let minor = f.u32("Minor version").emit()?;
    f.u32("Header size").emit()?;
    let width = f.u16("Width").emit()?;
    let height = f.u16("Height").emit()?;
    let flags = f.u32("Flags").flags(VTF_FLAGS).emit()?;
    let frames = f.u16("Frames").emit()?;
    let first_frame = f.u16("First frame").emit()?;
    f.bytes("Padding", 4).emit()?;
    f.f32("Reflectivity R").emit()?;
    f.f32("Reflectivity G").emit()?;
    f.f32("Reflectivity B").emit()?;
    f.bytes("Padding", 4).emit()?;
    f.f32("Bump map scale").emit()?;
    let format = f
        .u32("High-resolution format")
        .enumeration(VTF_FORMATS)
        .emit()?;
    let mipmaps = f.u8("MIP-map count").emit()?;
    let low_format = f
        .u32("Low-resolution format")
        .enumeration(VTF_FORMATS)
        .emit()?;
    let low_width = f.u8("Low-resolution width").emit()?;
    let low_height = f.u8("Low-resolution height").emit()?;
    let mut depth = 1;
    if minor >= 2 {
        depth = f.u16("Depth").emit()?;
    }
    let mut resources = 0;
    if minor >= 3 {
        f.bytes("Padding", 3).emit()?;
        resources = f.u32("Resource count").emit()?;
        f.bytes("Padding", 8).emit()?;
    }
    Ok(VtfInfo {
        minor,
        width,
        height,
        flags,
        frames,
        first_frame,
        format,
        mipmaps,
        low_format,
        low_width,
        low_height,
        depth,
        resources,
    })
}

pub async fn dissect_vtf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let size_bytes = cx.read(file.sub(12, 4)).await?;
    let header_size = u64::from(u32_le(&size_bytes, 0).unwrap_or(0)).clamp(16, 0x1_0000);
    // The fixed part is 80 bytes at most; 7.3 resource entries follow it.
    let span = file.sub(0, header_size.min(80));
    let block = cx.block(span).await?;
    let info = vtf_header(&mut Fields::new(&block, LE), &())?;
    cx.emit(crate::fields::struct_node(
        "Header",
        span,
        LE,
        (),
        vtf_header,
    ));
    let format_name = lookup(VTF_FORMATS, info.format.into()).unwrap_or("unknown format");
    let mut summary = format!(
        "VTF 7.{}, {}, {format_name}",
        info.minor,
        dims(info.width, info.height)
    );
    if info.depth > 1 {
        summary = format!("{summary}, depth {}", info.depth);
    }
    if info.flags & VTF_ENVMAP != 0 {
        summary.push_str(", environment map");
    }
    if info.frames > 1 {
        summary = format!("{summary}, {} frames", info.frames);
    }
    cx.annotate(format!("{summary}, {}", mip_levels(info.mipmaps.into())));
    // Where the two images are: from the resource table (7.3 and later), or
    // the low-resolution image right after the header and the
    // high-resolution one after that.
    let (mut low, mut high) = (None, None);
    if info.resources > 0 {
        let table = file.sub(80, u64::from(info.resources.min(32)).saturating_mul(8));
        let entries = cx.read_avail(table).await?;
        for entry in entries.as_chunks::<8>().0 {
            let at = u64::from(u32_le(entry, 4).unwrap_or(0));
            let [.., flags, _, _, _, _] = *entry;
            match (u24(entry), flags & 0x2) {
                (0x01, 0) => low = Some(at),
                (0x30, 0) => high = Some(at),
                _ => {}
            }
        }
        cx.emit(
            Node::new("Resources")
                .span(table)
                .summary(format!("{} entries", info.resources))
                .lazy(vtf_resources, (file, table)),
        );
    } else {
        low = Some(header_size);
        high = Some(header_size.saturating_add(info.low_size().unwrap_or(0)));
    }
    if let (Some(at), Some(len)) = (low, info.low_size()) {
        let format = lookup(VTF_FORMATS, info.low_format.into()).unwrap_or("unknown format");
        cx.emit(
            region("Low-resolution image", file, at, len).summary(format!(
                "{}, {format}, {}",
                dims(info.low_width, info.low_height),
                human_size(len)
            )),
        );
    }
    if let Some(at) = high {
        let levels = u32::from(info.mipmaps.max(1));
        let node = if info.level_size(0).is_some() {
            let total = (0..levels)
                .filter_map(|l| info.level_size(l))
                .fold(0u64, u64::saturating_add);
            region("High-resolution image", file, at, total)
                .summary(format!(
                    "{}, {format_name}, {}, {}",
                    dims(info.width, info.height),
                    mip_levels(levels),
                    human_size(total)
                ))
                .lazy(vtf_levels, (file.tail(at), info))
        } else {
            region(
                "High-resolution image",
                file,
                at,
                file.len.saturating_sub(at),
            )
        };
        cx.emit(node);
    }
    Ok(())
}

/// The MIP levels of the high-resolution image, smallest first as stored.
async fn vtf_levels(cx: Cx, (data, info): (Span, VtfInfo)) -> Result<()> {
    let levels = u32::from(info.mipmaps.max(1));
    let mut pos = 0u64;
    for level in (0..levels).rev() {
        let len = info.level_size(level).unwrap_or(0);
        let (w, h) = (
            mip(info.width.into(), level),
            mip(info.height.into(), level),
        );
        cx.push(
            region(format!("MIP level {level}"), data, pos, len).summary(format!(
                "{}, {}",
                dims(w, h),
                human_size(len)
            )),
        )
        .await;
        pos = pos.saturating_add(len);
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
        let name = lookup(VTF_RESOURCES, tag.into()).map_or_else(
            || {
                let raw = b.get(..3).unwrap_or_default();
                format!("Resource {:?}", crate::text::latin1(raw))
            },
            str::to_owned,
        );
        let mut node = Node::new(name).span(span).value(super::hex(data));
        node = if flags & 0x2 != 0 {
            node.summary("inline value")
        } else {
            node.summary(format!("at {data:#x}"))
                .target(file.tail(data.into()))
        };
        cx.push(node).await;
    }
    Ok(())
}
