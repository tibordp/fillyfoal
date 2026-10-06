//! DirectDraw Surface (DDS) textures.
//!
//! `DDS `, a 124-byte header with a 32-byte pixel format, an optional DX10
//! header (when the FourCC is `DX10`), then the surfaces: for each array
//! element or cube face, each mip level from largest to smallest.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

use super::{dims, region};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "dds",
    title: "DirectDraw Surface",
    extensions: &["dds"],
    mime: "image/vnd-ms.dds",
    probe: Probe::Magic(&[(0, b"DDS |\x00\x00\x00")]),
    dissect: crate::expander!(dissect: Input),
};

const HEADER_FLAGS: FlagTable = &[
    flag(0x1, "CAPS"),
    flag(0x2, "HEIGHT"),
    flag(0x4, "WIDTH"),
    flag(0x8, "PITCH"),
    flag(0x1000, "PIXELFORMAT"),
    flag(0x20000, "MIPMAPCOUNT"),
    flag(0x80000, "LINEARSIZE"),
    flag(0x80_0000, "DEPTH"),
];

const PF_FLAGS: FlagTable = &[
    flag(0x1, "ALPHAPIXELS"),
    flag(0x2, "ALPHA"),
    flag(0x4, "FOURCC"),
    flag(0x40, "RGB"),
    flag(0x200, "YUV"),
    flag(0x20000, "LUMINANCE"),
    flag(0x80000, "BUMPDUDV"),
];

const CAPS: FlagTable = &[
    flag(0x8, "COMPLEX"),
    flag(0x1000, "TEXTURE"),
    flag(0x40_0000, "MIPMAP"),
];

const CAPS2: FlagTable = &[
    flag(0x200, "CUBEMAP"),
    flag(0x400, "CUBEMAP_POSITIVEX"),
    flag(0x800, "CUBEMAP_NEGATIVEX"),
    flag(0x1000, "CUBEMAP_POSITIVEY"),
    flag(0x2000, "CUBEMAP_NEGATIVEY"),
    flag(0x4000, "CUBEMAP_POSITIVEZ"),
    flag(0x8000, "CUBEMAP_NEGATIVEZ"),
    flag(0x20_0000, "VOLUME"),
];

const DIMENSIONS: EnumTable = &[
    (2, "TEXTURE1D"),
    (3, "TEXTURE2D"),
    (4, "TEXTURE3D"),
];

const MISC: FlagTable = &[flag(0x4, "TEXTURECUBE")];

const ALPHA_MODES: EnumTable = &[
    (0, "UNKNOWN"),
    (1, "STRAIGHT"),
    (2, "PREMULTIPLIED"),
    (3, "OPAQUE"),
    (4, "CUSTOM"),
];

/// Common DXGI formats.
const DXGI_NAMES: EnumTable = &[
    (2, "R32G32B32A32_FLOAT"),
    (6, "R32G32B32_FLOAT"),
    (10, "R16G16B16A16_FLOAT"),
    (11, "R16G16B16A16_UNORM"),
    (16, "R32G32_FLOAT"),
    (24, "R10G10B10A2_UNORM"),
    (26, "R11G11B10_FLOAT"),
    (28, "R8G8B8A8_UNORM"),
    (29, "R8G8B8A8_UNORM_SRGB"),
    (34, "R16G16_FLOAT"),
    (41, "R32_FLOAT"),
    (49, "R8G8_UNORM"),
    (54, "R16_FLOAT"),
    (56, "R16_UNORM"),
    (61, "R8_UNORM"),
    (65, "A8_UNORM"),
    (67, "R9G9B9E5_SHAREDEXP"),
    (71, "BC1_UNORM"),
    (72, "BC1_UNORM_SRGB"),
    (74, "BC2_UNORM"),
    (75, "BC2_UNORM_SRGB"),
    (77, "BC3_UNORM"),
    (78, "BC3_UNORM_SRGB"),
    (80, "BC4_UNORM"),
    (81, "BC4_SNORM"),
    (83, "BC5_UNORM"),
    (84, "BC5_SNORM"),
    (85, "B5G6R5_UNORM"),
    (86, "B5G5R5A1_UNORM"),
    (87, "B8G8R8A8_UNORM"),
    (88, "B8G8R8X8_UNORM"),
    (91, "B8G8R8A8_UNORM_SRGB"),
    (93, "B8G8R8X8_UNORM_SRGB"),
    (95, "BC6H_UF16"),
    (96, "BC6H_SF16"),
    (98, "BC7_UNORM"),
    (99, "BC7_UNORM_SRGB"),
    (115, "B4G4R4A4_UNORM"),
];

record! {
    pub struct Header {
        magic: ascii[4] "Magic",
        size: u32 "dwSize",
        flags: u32 "dwFlags" .flags(HEADER_FLAGS),
        height: u32 "dwHeight",
        width: u32 "dwWidth",
        pitch: u32 "dwPitchOrLinearSize",
        depth: u32 "dwDepth",
        mipmaps: u32 "dwMipMapCount",
        reserved: bytes[44] "dwReserved1",
        pf_size: u32 "ddspf.dwSize",
        pf_flags: u32 "ddspf.dwFlags" .flags(PF_FLAGS),
        fourcc: ascii[4] "ddspf.dwFourCC",
        bit_count: u32 "ddspf.dwRGBBitCount",
        r_mask: u32 "ddspf.dwRBitMask" .hex(),
        g_mask: u32 "ddspf.dwGBitMask" .hex(),
        b_mask: u32 "ddspf.dwBBitMask" .hex(),
        a_mask: u32 "ddspf.dwABitMask" .hex(),
        caps: u32 "dwCaps" .flags(CAPS),
        caps2: u32 "dwCaps2" .flags(CAPS2),
        caps3: u32 "dwCaps3",
        caps4: u32 "dwCaps4",
        reserved2: u32 "dwReserved2",
    }
}

record! {
    pub struct Dx10 {
        format: u32 "dxgiFormat" .enumeration(DXGI_NAMES),
        dimension: u32 "resourceDimension" .enumeration(DIMENSIONS),
        misc: u32 "miscFlag" .flags(MISC),
        array_size: u32 "arraySize",
        misc2: u32 "miscFlags2" .enumeration(ALPHA_MODES),
    }
}

/// How surfaces are laid out, for computing their sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    width: u64,
    height: u64,
    depth: u64,
    levels: u64,
    surfaces: u64,
    /// Bytes per block (compressed) or per pixel.
    unit: u64,
    compressed: bool,
}

impl Layout {
    fn level_size(&self, level: u64) -> u64 {
        let shrink = |v: u64| v.checked_shr(u32::try_from(level).unwrap_or(u32::MAX)).unwrap_or(0).max(1);
        let (w, h, d) = (shrink(self.width), shrink(self.height), shrink(self.depth));
        let (w, h) = if self.compressed {
            (w.saturating_add(3) / 4, h.saturating_add(3) / 4)
        } else {
            (w, h)
        };
        w.saturating_mul(h).saturating_mul(d).saturating_mul(self.unit)
    }

    fn surface_size(&self) -> u64 {
        (0..self.levels.min(32)).fold(0u64, |a, l| a.saturating_add(self.level_size(l)))
    }
}

/// Bytes per 4×4 block (compressed formats) or per pixel.
fn dxgi_unit(format: u32) -> Option<(u64, bool)> {
    Some(match format {
        2 => (16, false),
        6 => (12, false),
        10 | 11 | 16 => (8, false),
        24 | 26 | 28 | 29 | 34 | 41 | 67 | 87 | 88 | 91 | 93 => (4, false),
        49 | 54 | 56 | 85 | 86 | 115 => (2, false),
        61 | 65 => (1, false),
        71 | 72 | 80 | 81 => (8, true),
        74 | 75 | 77 | 78 | 83 | 84 | 95 | 96 | 98 | 99 => (16, true),
        _ => return None,
    })
}

/// Block size and compression for legacy FourCCs and RGB masks.
fn legacy_unit(h: &Header) -> Option<(u64, bool, String)> {
    if h.pf_flags & 0x4 != 0 {
        let (unit, name) = match h.fourcc.as_str() {
            "DXT1" => (8, "BC1 (DXT1)"),
            "DXT2" | "DXT3" => (16, "BC2 (DXT2/3)"),
            "DXT4" | "DXT5" => (16, "BC3 (DXT4/5)"),
            "ATI1" | "BC4U" | "BC4S" => (8, "BC4"),
            "ATI2" | "BC5U" | "BC5S" => (16, "BC5"),
            _ => return None,
        };
        return Some((unit, true, name.to_owned()));
    }
    let bits = u64::from(h.bit_count);
    (bits > 0 && bits % 8 == 0).then(|| (bits / 8, false, format!("{bits}-bit uncompressed")))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let h = parse(&cx, header_span, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, LE));
    let mut pos = Header::SIZE;
    let mut surfaces = if h.caps2 & 0x200 != 0 { 6u64 } else { 1 };
    let unit = if h.pf_flags & 0x4 != 0 && h.fourcc == "DX10" {
        let span = file.sub(pos, Dx10::SIZE);
        let dx = parse(&cx, span, LE, &(), Dx10::layout).await?;
        cx.emit(Dx10::node("DX10 header", span, LE));
        pos = pos.saturating_add(Dx10::SIZE);
        surfaces = u64::from(dx.array_size.max(1)).saturating_mul(if dx.misc & 4 != 0 { 6 } else { 1 });
        let name = lookup(DXGI_NAMES, dx.format.into())
            .map_or_else(|| format!("DXGI format {}", dx.format), str::to_owned);
        match dxgi_unit(dx.format) {
            Some((unit, compressed)) => Ok((unit, compressed, name)),
            None => Err(name),
        }
    } else {
        legacy_unit(&h).ok_or_else(|| format!("FourCC {:?}", h.fourcc))
    };
    let levels = u64::from(h.mipmaps.max(1));
    let format_name = match &unit {
        Ok((_, _, name)) | Err(name) => name.clone(),
    };
    let mut summary = format!("{}, {format_name}", dims(h.width, h.height));
    if levels > 1 {
        summary = format!("{summary}, {levels} mip levels");
    }
    if surfaces > 1 {
        summary = format!("{summary}, {surfaces} surfaces");
    }
    cx.annotate(summary);
    let data = file.tail(pos);
    match unit {
        Ok((unit, compressed, _)) => {
            let layout = Layout {
                width: h.width.into(),
                height: h.height.into(),
                depth: if h.caps2 & 0x20_0000 != 0 { h.depth.max(1).into() } else { 1 },
                levels,
                surfaces,
                unit,
                compressed,
            };
            cx.emit(
                Node::new("Surfaces")
                    .span(data)
                    .summary(format!("{surfaces} × {levels} levels"))
                    .lazy(list_surfaces, (data, layout)),
            );
        }
        Err(_) => cx.emit(Node::new("Surface data").span(data)),
    }
    Ok(())
}

async fn list_surfaces(cx: Cx, (data, layout): (Span, Layout)) -> Result<()> {
    let levels = layout.levels.min(32);
    let surface = layout.surface_size();
    // Bogus counts must not produce endless empty regions.
    let surfaces = if surface == 0 {
        1
    } else {
        layout.surfaces.min(data.len.div_ceil(surface).max(1))
    };
    cx.set_count(Count::Exact(surfaces.saturating_mul(levels)));
    for s in 0..surfaces {
        let mut pos = s.saturating_mul(surface);
        for level in 0..levels {
            let size = layout.level_size(level);
            let shrink = |v: u64| v.checked_shr(u32::try_from(level).unwrap_or(u32::MAX)).unwrap_or(0).max(1);
            let name = if surfaces > 1 {
                format!("Surface {s}, level {level}")
            } else {
                format!("Level {level}")
            };
            cx.push(
                region(name, data, pos, size)
                    .summary(format!("{}, {size:#x} bytes", dims(shrink(layout.width), shrink(layout.height)))),
            )
            .await;
            pos = pos.saturating_add(size);
        }
    }
    Ok(())
}
