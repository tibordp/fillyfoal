//! Android ART boot/app images (`art\n`): the image header that ties the
//! image to its OAT file, and for image version 119 (Android 17) the
//! section table, the image methods, the compression block table and the
//! sections themselves: the heap objects (opaque: their layout comes from
//! the classes in the boot image), the intern table and class table (ART
//! hash sets of object references), the string reference offsets and the
//! live-object bitmap. Older versions (074 and later share the header
//! prefix) are shown down to the header. Checked against `oatdump`.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::binutil::data_node;
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{hex, name_or};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "art-image",
    title: "Android ART image",
    extensions: &["art"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| h.starts_with(b"art\n") && h.at(7, b"\0")),
    dissect: crate::expander!(dissect: Input),
};

const MODERN: &[&str] = &[
    "image_reservation_size",
    "component_count",
    "image_begin",
    "image_size",
    "image_checksum",
    "oat_checksum",
    "oat_file_begin",
    "oat_data_begin",
    "oat_data_end",
    "oat_file_end",
    "boot_image_begin",
    "boot_image_size",
    "boot_image_component_count",
    "boot_image_checksum",
    "image_roots",
    "pointer_size",
];

const LEGACY: &[&str] = &[
    "image_begin",
    "image_size",
    "oat_checksum",
    "oat_file_begin",
    "oat_data_begin",
    "oat_data_end",
    "oat_file_end",
    "boot_image_begin",
    "boot_image_size",
    "boot_oat_begin",
    "boot_oat_size",
    "patch_delta",
    "image_roots",
    "pointer_size",
    "compile_pic",
    "is_pic",
];

/// The image version whose full layout is decoded.
const SECTIONED: u32 = 119;

const SECTIONS: &[&str] = &[
    "SectionObjects",
    "SectionArtFields",
    "SectionArtMethods",
    "SectionImTables",
    "SectionIMTConflictTables",
    "SectionRuntimeMethods",
    "SectionJniStubMethods",
    "SectionInternedStrings",
    "SectionClassTable",
    "SectionStringReferenceOffsets",
    "SectionDexCacheArrays",
    "SectionMetadata",
    "SectionImageBitmap",
];

const IMAGE_METHODS: &[&str] = &[
    "kResolutionMethod",
    "kImtConflictMethod",
    "kImtUnimplementedMethod",
    "kSaveAllCalleeSavesMethod",
    "kSaveRefsOnlyMethod",
    "kSaveRefsAndArgsMethod",
    "kSaveEverythingMethod",
    "kSaveEverythingMethodForClinit",
    "kSaveEverythingMethodForSuspendCheck",
];

const STORAGE_MODE: EnumTable = &[(0, "Uncompressed"), (1, "LZ4"), (2, "LZ4HC")];

/// Header bytes for version 119: 8 + 16 × 4 + 13 × 8 + 9 × 8 + 3 × 4,
/// rounded up to 8.
const HEADER_119: u64 = 0x108;

fn header_119(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("magic", 4).emit()?;
    f.ascii("version", 4).emit()?;
    for name in MODERN {
        let field = f.u32(name);
        if name.ends_with("_count") || *name == "pointer_size" {
            field.emit()?;
        } else if name.ends_with("_size") {
            field.with(|&v, n| n.summary(size(v.into()))).emit()?;
        } else {
            field.hex().emit()?;
        }
    }
    for name in SECTIONS {
        let at = f.peek_span(8);
        let block = f.block();
        let rel = to_usize(f.pos());
        let offset = u32_le(&block.data, rel).unwrap_or(0);
        let len = u32_le(&block.data, rel.saturating_add(4)).unwrap_or(0);
        f.skip(8);
        f.node(
            struct_node(*name, at, LE, (), |f, _| {
                f.u32("offset").hex().emit()?;
                f.u32("size").emit()?;
                Ok(())
            })
            .summary(format!("{len} bytes at {offset:#x}")),
        );
    }
    for name in IMAGE_METHODS {
        f.u64(name).hex().emit()?;
    }
    f.u32("data_size")
        .desc("Bytes of image data after the header (uncompressed)")
        .emit()?;
    f.u32("blocks_offset").hex().emit()?;
    f.u32("blocks_count").emit()?;
    let rest = HEADER_119.saturating_sub(f.pos());
    if rest > 0 {
        f.bytes("padding", rest).emit()?;
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 8)).await?;
    let version_text = crate::text::until_nul(head.get(4..8).unwrap_or_default());
    let version: u32 = version_text.parse().unwrap_or(0);
    if version >= SECTIONED {
        return sectioned(cx, input, version_text).await;
    }
    let names = if version >= 74 { MODERN } else { LEGACY };
    let len = 8u64.saturating_add(u64::try_from(names.len()).unwrap_or(0).saturating_mul(4));
    let block = cx.block(file.sub(0, len)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("magic", 4).emit()?;
    f.ascii("version", 4).emit()?;
    let mut values = Vec::new();
    for name in names {
        let field = f.u32(name);
        let field = if name.ends_with("_count")
            || *name == "pointer_size"
            || name.starts_with("is_")
            || name.starts_with("compile_")
        {
            field
        } else {
            field.hex()
        };
        values.push((*name, field.emit()?));
    }
    let get = |n: &str| values.iter().find(|(k, _)| *k == n).map_or(0, |(_, v)| *v);
    cx.annotate(format!(
        "Android ART image v{version_text}, image {:#x}+{:#x}, OAT data {:#x}..{:#x}, {}-bit",
        get("image_begin"),
        get("image_size"),
        get("oat_data_begin"),
        get("oat_data_end"),
        get("pointer_size").saturating_mul(8)
    ));
    cx.emit(data_node(
        "Image contents",
        file.tail(len),
        file.len.saturating_sub(len),
    ));
    Ok(())
}

async fn sectioned(cx: Cx, input: Input, version: String) -> Result<()> {
    let file = input.span;
    let h = cx.read(file.sub(0, HEADER_119)).await?;
    let word = |i: usize| u32_le(&h, 8usize.saturating_add(i.saturating_mul(4))).unwrap_or(0);
    let image_begin = word(2);
    let image_size = word(3);
    let roots = word(14);
    let pointer = word(15);
    let section = |i: usize| {
        let at = 0x48usize.saturating_add(i.saturating_mul(8));
        (
            u64::from(u32_le(&h, at).unwrap_or(0)),
            u64::from(u32_le(&h, at.saturating_add(4)).unwrap_or(0)),
        )
    };
    let blocks_offset = u32_le(&h, 0xfc).unwrap_or(0);
    let blocks_count = u32_le(&h, 0x100).unwrap_or(0);
    cx.annotate(format!(
        "Android ART image v{version}, {} at {image_begin:#x}, {}-bit{}",
        size(image_size.into()),
        pointer.saturating_mul(8),
        if blocks_count > 0 {
            format!(", {}", plural(blocks_count, "compressed block"))
        } else {
            String::new()
        }
    ));
    cx.emit(struct_node(
        "Header",
        file.sub(0, HEADER_119),
        LE,
        (),
        header_119,
    ));
    if blocks_count > 0 {
        // The image data is stored in compressed blocks; the sections
        // describe the decompressed image.
        let table = file.sub(
            blocks_offset.into(),
            u64::from(blocks_count).saturating_mul(20),
        );
        cx.emit(
            Node::new("Blocks")
                .span(table)
                .summary(plural(blocks_count, "block"))
                .lazy(blocks, (table, file)),
        );
        let entries = cx.read(table).await?;
        for (i, b) in entries.chunks(20).take(4096).enumerate() {
            let offset = u64::from(u32_le(b, 4).unwrap_or(0));
            let len = u64::from(u32_le(b, 8).unwrap_or(0));
            if len > 0 {
                let s = file.sub(offset, len);
                cx.emit(data_node(format!("Block {i} data"), s, len));
            }
        }
        let (bitmap_at, bitmap_len) = section(12);
        if bitmap_len > 0 {
            let s = file.sub(bitmap_at, bitmap_len);
            cx.emit(data_node("Image bitmap", s, s.len).desc(LIVE_BITMAP));
        }
        return Ok(());
    }
    let mut parts: Vec<(u64, u64, Node)> = Vec::new();
    for (i, name) in SECTIONS.iter().enumerate() {
        let (offset, len) = section(i);
        // The objects section starts with the image header itself.
        let (offset, len) = if i == 0 {
            (HEADER_119, len.saturating_sub(HEADER_119))
        } else {
            (offset, len)
        };
        if len == 0 {
            continue;
        }
        let span = file.sub(offset, len);
        let label = name.trim_start_matches("Section");
        let node = match i {
            0 => {
                let root_at = u64::from(roots.saturating_sub(image_begin));
                data_node("Objects", span, len)
                    .summary(format!("{}, image roots at {root_at:#x}", size(len)))
                    .desc("Heap objects (mirror::Object): their layout comes from classes in the boot image")
            }
            7 | 8 => Node::new(if i == 7 {
                "Interned strings"
            } else {
                "Class table"
            })
            .span(span)
            .summary(size(len))
            .lazy(hash_set, (span, image_begin, i == 8)),
            9 => Node::new("String reference offsets")
                .span(span)
                .summary(plural(len / 8, "reference"))
                .lazy(reference_offsets, span),
            12 => data_node("Image bitmap", span, len).desc(LIVE_BITMAP),
            _ => data_node(label.to_owned(), span, len),
        };
        parts.push((offset, len, node));
    }
    parts.sort_by_key(|p| p.0);
    let mut pos = HEADER_119;
    for (at, len, node) in parts {
        if at > pos {
            cx.emit(gap(file, pos, at, image_size.into()));
        }
        cx.emit(node);
        pos = pos.max(at.saturating_add(len));
    }
    if pos < file.len {
        cx.emit(gap(file, pos, file.len, image_size.into()));
    }
    Ok(())
}

const LIVE_BITMAP: &str = "One bit per 8 bytes of the image: which addresses start a live object";

fn gap(file: Span, from: u64, to: u64, image_size: u64) -> Node {
    let s = file.sub(from, to.saturating_sub(from));
    if from >= image_size {
        Node::new("Padding")
            .span(s)
            .summary(size(s.len))
            .desc("Up to the page-aligned bitmap")
    } else {
        data_node("Unknown", s, s.len)
    }
}

/// An ART `HashSet` written to memory: element count, bucket count,
/// elements until expansion, minimum and maximum load factors, then one
/// `u32` per bucket (a heap reference, 0 for an empty bucket; class table
/// slots keep hash bits in the low bits).
async fn hash_set(cx: Cx, (span, image_begin, slots): (Span, u32, bool)) -> Result<()> {
    let block = cx.block(span.sub(0, 40)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u64("num_elements").emit()?;
    let buckets = f.u64("num_buckets").emit()?;
    f.u64("elements_until_expand").emit()?;
    f.f64("min_load_factor").emit()?;
    f.f64("max_load_factor").emit()?;
    let data = cx.read(span.sub(40, buckets.saturating_mul(4))).await?;
    for (i, w) in data.chunks(4).enumerate() {
        let v = u32_le(w, 0).unwrap_or(0);
        let node = Node::new(format!("{i}"))
            .span(span.sub(40u64.saturating_add(to_u64(i).saturating_mul(4)), 4))
            .value(hex(v, 32));
        let node = if v == 0 {
            node.summary("empty")
        } else {
            let addr = if slots { v & !7 } else { v };
            let place = match addr.checked_sub(image_begin) {
                Some(o) if image_begin != 0 && o < 1 << 30 => format!("object at offset {o:#x}"),
                _ => "boot image object".to_owned(),
            };
            if slots {
                node.summary(format!("{place}, hash bits {}", v & 7))
            } else {
                node.summary(place)
            }
        };
        cx.push(node).await;
    }
    Ok(())
}

/// `AppImageReferenceOffsetInfo`: an object's offset in the image and the
/// offset of a string reference field inside it.
async fn reference_offsets(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, pair) in data.chunks(8).enumerate() {
        let object = u32_le(pair, 0).unwrap_or(0);
        let member = u32_le(pair, 4).unwrap_or(0);
        cx.push(
            struct_node(
                format!("{i}"),
                span.sub(to_u64(i).saturating_mul(8), 8),
                LE,
                (),
                |f, _| {
                    f.u32("object_offset").hex().emit()?;
                    f.u32("member_offset").hex().emit()?;
                    Ok(())
                },
            )
            .summary(format!("field +{member:#x} of the object at {object:#x}")),
        )
        .await;
    }
    Ok(())
}

/// `ImageHeader::Block`: storage mode, data offset and size in the file,
/// offset and size in the image.
async fn blocks(cx: Cx, (table, file): (Span, Span)) -> Result<()> {
    let data = cx.read(table).await?;
    for (i, b) in data.chunks(20).enumerate() {
        let mode = u32_le(b, 0).unwrap_or(0);
        let offset = u32_le(b, 4).unwrap_or(0);
        let len = u32_le(b, 8).unwrap_or(0);
        let image_size = u32_le(b, 16).unwrap_or(0);
        let entry = table.sub(to_u64(i).saturating_mul(20), 20);
        cx.push(
            struct_node(format!("Block {i}"), entry, LE, (), |f, _| {
                f.u32("storage_mode").enumeration(STORAGE_MODE).emit()?;
                f.u32("data_offset").hex().emit()?;
                f.u32("data_size").emit()?;
                f.u32("image_offset").hex().emit()?;
                f.u32("image_size").emit()?;
                Ok(())
            })
            .summary(format!(
                "{} {} → {}",
                name_or(STORAGE_MODE, mode.into(), "mode"),
                size(len.into()),
                size(image_size.into())
            ))
            .target(file.sub(offset.into(), len.into())),
        )
        .await;
    }
    Ok(())
}
