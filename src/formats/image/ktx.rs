//! Khronos texture containers: KTX (version 1) and KTX2.
//!
//! KTX 1: a 64-byte header in the writer's byte order (detected from the
//! endianness field), key/value metadata, then mip levels each prefixed by
//! their size. KTX 2: a little-endian header, an index locating the data
//! format descriptor, key/value data and supercompression data, and a level
//! index giving each mip level's offset and length.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Prim, parse};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

use super::{dims, region, text};

pub static KTX: Format = Format {
    name: "ktx",
    title: "Khronos texture (KTX 1)",
    extensions: &["ktx"],
    mime: "image/ktx",
    probe: Probe::Magic(&[(0, b"\xabKTX 11\xbb\r\n\x1a\n")]),
    dissect: crate::expander!(dissect_ktx1: Input),
};

pub static KTX2: Format = Format {
    name: "ktx2",
    title: "Khronos texture (KTX 2)",
    extensions: &["ktx2"],
    mime: "image/ktx2",
    probe: Probe::Magic(&[(0, b"\xabKTX 20\xbb\r\n\x1a\n")]),
    dissect: crate::expander!(dissect_ktx2: Input),
};

const GL_FORMATS: EnumTable = &[
    (0x1903, "GL_RED"),
    (0x1907, "GL_RGB"),
    (0x1908, "GL_RGBA"),
    (0x1909, "GL_LUMINANCE"),
    (0x190a, "GL_LUMINANCE_ALPHA"),
    (0x8051, "GL_RGB8"),
    (0x8058, "GL_RGBA8"),
    (0x80e1, "GL_BGRA"),
    (0x8814, "GL_RGBA32F"),
    (0x881a, "GL_RGBA16F"),
    (0x8227, "GL_RG"),
    (0x8229, "GL_R8"),
    (0x822b, "GL_RG8"),
    (0x83f0, "GL_COMPRESSED_RGB_S3TC_DXT1"),
    (0x83f1, "GL_COMPRESSED_RGBA_S3TC_DXT1"),
    (0x83f2, "GL_COMPRESSED_RGBA_S3TC_DXT3"),
    (0x83f3, "GL_COMPRESSED_RGBA_S3TC_DXT5"),
    (0x8c41, "GL_SRGB8"),
    (0x8c43, "GL_SRGB8_ALPHA8"),
    (0x8d64, "GL_ETC1_RGB8_OES"),
    (0x8e8c, "GL_COMPRESSED_RGBA_BPTC_UNORM"),
    (0x8e8d, "GL_COMPRESSED_SRGB_ALPHA_BPTC_UNORM"),
    (0x9270, "GL_COMPRESSED_R11_EAC"),
    (0x9272, "GL_COMPRESSED_RG11_EAC"),
    (0x9274, "GL_COMPRESSED_RGB8_ETC2"),
    (0x9275, "GL_COMPRESSED_SRGB8_ETC2"),
    (0x9278, "GL_COMPRESSED_RGBA8_ETC2_EAC"),
    (0x9279, "GL_COMPRESSED_SRGB8_ALPHA8_ETC2_EAC"),
    (0x93b0, "GL_COMPRESSED_RGBA_ASTC_4x4"),
    (0x93b4, "GL_COMPRESSED_RGBA_ASTC_6x6"),
    (0x93b7, "GL_COMPRESSED_RGBA_ASTC_8x8"),
    (0x93d0, "GL_COMPRESSED_SRGB8_ALPHA8_ASTC_4x4"),
    (0x1401, "GL_UNSIGNED_BYTE"),
    (0x1403, "GL_UNSIGNED_SHORT"),
    (0x1405, "GL_UNSIGNED_INT"),
    (0x1406, "GL_FLOAT"),
    (0x140b, "GL_HALF_FLOAT"),
];

const VK_FORMATS: EnumTable = &[
    (0, "UNDEFINED"),
    (9, "R8_UNORM"),
    (16, "R8G8_UNORM"),
    (23, "R8G8B8_UNORM"),
    (29, "R8G8B8_SRGB"),
    (37, "R8G8B8A8_UNORM"),
    (43, "R8G8B8A8_SRGB"),
    (44, "B8G8R8A8_UNORM"),
    (50, "B8G8R8A8_SRGB"),
    (70, "R16_UNORM"),
    (76, "R16_SFLOAT"),
    (83, "R16G16_SFLOAT"),
    (91, "R16G16B16A16_UNORM"),
    (92, "R16G16B16A16_SNORM"),
    (95, "R16G16B16A16_UINT"),
    (96, "R16G16B16A16_SINT"),
    (97, "R16G16B16A16_SFLOAT"),
    (100, "R32_SFLOAT"),
    (109, "R32G32B32A32_SFLOAT"),
    (122, "B10G11R11_UFLOAT_PACK32"),
    (123, "E5B9G9R9_UFLOAT_PACK32"),
    (131, "BC1_RGB_UNORM_BLOCK"),
    (132, "BC1_RGB_SRGB_BLOCK"),
    (133, "BC1_RGBA_UNORM_BLOCK"),
    (134, "BC1_RGBA_SRGB_BLOCK"),
    (135, "BC2_UNORM_BLOCK"),
    (137, "BC3_UNORM_BLOCK"),
    (138, "BC3_SRGB_BLOCK"),
    (139, "BC4_UNORM_BLOCK"),
    (141, "BC5_UNORM_BLOCK"),
    (143, "BC6H_UFLOAT_BLOCK"),
    (145, "BC7_UNORM_BLOCK"),
    (146, "BC7_SRGB_BLOCK"),
    (147, "ETC2_R8G8B8_UNORM_BLOCK"),
    (148, "ETC2_R8G8B8_SRGB_BLOCK"),
    (151, "ETC2_R8G8B8A8_UNORM_BLOCK"),
    (152, "ETC2_R8G8B8A8_SRGB_BLOCK"),
    (153, "EAC_R11_UNORM_BLOCK"),
    (155, "EAC_R11G11_UNORM_BLOCK"),
    (157, "ASTC_4x4_UNORM_BLOCK"),
    (158, "ASTC_4x4_SRGB_BLOCK"),
    (171, "ASTC_8x8_UNORM_BLOCK"),
    (172, "ASTC_8x8_SRGB_BLOCK"),
    (1_000_066_000, "ASTC_4x4_SFLOAT_BLOCK"),
];

const SUPERCOMPRESSION: EnumTable = &[(0, "None"), (1, "BasisLZ"), (2, "Zstandard"), (3, "ZLIB")];

record! {
    pub struct Ktx1Header {
        identifier: bytes[12] "Identifier",
        endianness: u32 "Endianness" .hex() .desc("0x04030201 in the writer's byte order"),
        gl_type: u32 "glType" .enumeration(GL_FORMATS) .desc("0 for compressed textures"),
        gl_type_size: u32 "glTypeSize",
        gl_format: u32 "glFormat" .enumeration(GL_FORMATS),
        gl_internal_format: u32 "glInternalFormat" .enumeration(GL_FORMATS),
        gl_base_internal_format: u32 "glBaseInternalFormat" .enumeration(GL_FORMATS),
        width: u32 "pixelWidth",
        height: u32 "pixelHeight",
        depth: u32 "pixelDepth",
        array_elements: u32 "numberOfArrayElements",
        faces: u32 "numberOfFaces",
        levels: u32 "numberOfMipmapLevels",
        kv_bytes: u32 "bytesOfKeyValueData",
    }
}

record! {
    pub struct Ktx2Header {
        identifier: bytes[12] "Identifier",
        vk_format: u32 "vkFormat" .enumeration(VK_FORMATS),
        type_size: u32 "typeSize",
        width: u32 "pixelWidth",
        height: u32 "pixelHeight",
        depth: u32 "pixelDepth",
        layers: u32 "layerCount",
        faces: u32 "faceCount",
        levels: u32 "levelCount",
        supercompression: u32 "supercompressionScheme" .enumeration(SUPERCOMPRESSION),
        dfd_offset: u32 "dfdByteOffset" .hex(),
        dfd_length: u32 "dfdByteLength",
        kvd_offset: u32 "kvdByteOffset" .hex(),
        kvd_length: u32 "kvdByteLength",
        sgd_offset: u64 "sgdByteOffset" .hex(),
        sgd_length: u64 "sgdByteLength",
    }
}

record! {
    pub struct Ktx2Level {
        offset: u64 "byteOffset" .hex(),
        length: u64 "byteLength",
        uncompressed: u64 "uncompressedByteLength",
    }
}

fn round4(v: u64) -> u64 {
    v.saturating_add(3) & !3
}

fn format_name(table: EnumTable, v: u32) -> String {
    lookup(table, v.into()).map_or_else(|| format!("format {v:#x}"), str::to_owned)
}

pub async fn dissect_ktx1(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let endian_bytes = cx.read(file.sub(12, 4)).await?;
    let endian = if u32_le(&endian_bytes, 0) == Some(0x0403_0201) {
        Endian::Little
    } else {
        Endian::Big
    };
    let header_span = file.sub(0, Ktx1Header::SIZE);
    let h = parse(&cx, header_span, endian, &(), Ktx1Header::layout).await?;
    cx.emit(Ktx1Header::node("Header", header_span, endian));
    let levels = u64::from(h.levels.max(1));
    cx.annotate(format!(
        "{}, {}, {levels} mip levels",
        dims(h.width, h.height.max(1)),
        format_name(GL_FORMATS, h.gl_internal_format)
    ));
    let kv = file.sub(Ktx1Header::SIZE, h.kv_bytes.into());
    if h.kv_bytes > 0 {
        cx.emit(
            Node::new("Key/value data")
                .span(kv)
                .lazy(key_values, (kv, endian)),
        );
    }
    let data = file.tail(Ktx1Header::SIZE.saturating_add(h.kv_bytes.into()));
    let cube = h.faces == 6 && h.array_elements == 0;
    cx.emit(
        Node::new("Mip levels")
            .span(data)
            .summary(format!("{levels} levels"))
            .lazy(ktx1_levels, (data, endian, levels, cube)),
    );
    Ok(())
}

async fn ktx1_levels(cx: Cx, (data, endian, levels, cube): (Span, Endian, u64, bool)) -> Result<()> {
    let mut pos = 0u64;
    for level in 0..levels {
        if pos >= data.len {
            break;
        }
        let size_bytes = cx.read(data.sub(pos, 4)).await?;
        let size = u64::from(u32::decode(&size_bytes, endian).unwrap_or(0));
        let body = if cube {
            round4(size).saturating_mul(6)
        } else {
            size
        };
        let len = round4(body.saturating_add(4));
        cx.push(
            region(format!("Level {level}"), data, pos, len)
                .summary(format!("imageSize {size:#x}")),
        )
        .await;
        pos = pos.saturating_add(len);
    }
    Ok(())
}

/// Key/value pairs: `u32 size, key NUL value`, each padded to 4 bytes.
async fn key_values(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let mut pos = 0u64;
    while pos.saturating_add(4) <= span.len {
        let size_bytes = cx.read(span.sub(pos, 4)).await?;
        let size = u64::from(u32::decode(&size_bytes, endian).unwrap_or(0));
        let pair = span.sub(pos.saturating_add(4), size);
        let bytes = cx.read(pair).await?;
        let split = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let key = crate::text::latin1(bytes.get(..split).unwrap_or_default());
        let value = bytes.get(split.saturating_add(1)..).unwrap_or_default();
        let trimmed = value.strip_suffix(b"\0").unwrap_or(value);
        let shown = if trimmed.is_empty() || crate::text::looks_like_text(trimmed) {
            text(crate::text::until_nul(value))
        } else {
            crate::value::Value::Bytes(value.get(..value.len().min(32)).unwrap_or_default().to_vec())
        };
        cx.push(
            Node::new(key)
                .span(span.sub(pos, size.saturating_add(4)))
                .value(shown),
        )
        .await;
        pos = pos.saturating_add(round4(size.saturating_add(4)));
        if size == 0 {
            break;
        }
    }
    Ok(())
}

pub async fn dissect_ktx2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let le = Endian::Little;
    let header_span = file.sub(0, Ktx2Header::SIZE);
    let h = parse(&cx, header_span, le, &(), Ktx2Header::layout).await?;
    cx.emit(Ktx2Header::node("Header", header_span, le));
    let levels = u64::from(h.levels.max(1));
    let mut summary = format!(
        "{}, {}, {levels} mip levels",
        dims(h.width, h.height.max(1)),
        format_name(VK_FORMATS, h.vk_format)
    );
    if h.supercompression != 0 {
        let scheme = lookup(SUPERCOMPRESSION, h.supercompression.into()).unwrap_or("unknown");
        summary = format!("{summary}, {scheme}");
    }
    cx.annotate(summary);
    let index = file.sub(Ktx2Header::SIZE, levels.saturating_mul(Ktx2Level::SIZE));
    cx.emit(
        Node::new("Level index")
            .span(index)
            .summary(format!("{levels} levels"))
            .lazy(ktx2_levels, (file, index, levels)),
    );
    if h.dfd_length > 0 {
        cx.emit(region("Data format descriptor", file, h.dfd_offset.into(), h.dfd_length.into()));
    }
    if h.kvd_length > 0 {
        let kv = file.sub(h.kvd_offset.into(), h.kvd_length.into());
        cx.emit(
            Node::new("Key/value data")
                .span(kv)
                .lazy(key_values, (kv, le)),
        );
    }
    if h.sgd_length > 0 {
        cx.emit(region("Supercompression global data", file, h.sgd_offset, h.sgd_length));
    }
    Ok(())
}

async fn ktx2_levels(cx: Cx, (file, index, levels): (Span, Span, u64)) -> Result<()> {
    for level in 0..levels {
        let span = index.sub(level.saturating_mul(Ktx2Level::SIZE), Ktx2Level::SIZE);
        if span.len < Ktx2Level::SIZE {
            break;
        }
        let entry = parse(&cx, span, Endian::Little, &(), Ktx2Level::layout).await?;
        let data = file.sub(entry.offset, entry.length);
        cx.push(
            Ktx2Level::node(format!("Level {level}"), span, Endian::Little)
                .summary(format!("{:#x} bytes at {:#x}", entry.length, entry.offset))
                .target(data),
        )
        .await;
    }
    Ok(())
}
