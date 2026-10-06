//! The dyld shared cache (`dyld_shared_cache_arm64e` and its sub-caches):
//! header, mappings, images and sub-cache list.
//!
//! The header has grown over the years; its real size is `mappingOffset`,
//! and fields beyond it are absent.

use super::tables::{PLATFORM, uuid, version};
use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::binutil::{get_at, hex, name_or, perms, text};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "dyld-cache",
    title: "dyld shared cache",
    extensions: &[],
    mime: "application/octet-stream",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"dyld_v") && u32_le(h.data, 0x10).is_some_and(|o| (0x28..0x1000).contains(&o))
}

#[derive(Clone, Copy)]
enum Kind {
    U32,
    Off,
    U64,
    Addr,
    Uuid,
    Platform,
    Version,
}

/// The header, in order: `(name, kind)`.
const HEADER: &[(&str, Kind)] = &[
    ("mappingOffset", Kind::Off),
    ("mappingCount", Kind::U32),
    ("imagesOffsetOld", Kind::Off),
    ("imagesCountOld", Kind::U32),
    ("dyldBaseAddress", Kind::Addr),
    ("codeSignatureOffset", Kind::Addr),
    ("codeSignatureSize", Kind::Addr),
    ("slideInfoOffsetUnused", Kind::Addr),
    ("slideInfoSizeUnused", Kind::Addr),
    ("localSymbolsOffset", Kind::Addr),
    ("localSymbolsSize", Kind::Addr),
    ("uuid", Kind::Uuid),
    ("cacheType", Kind::U64),
    ("branchPoolsOffset", Kind::Off),
    ("branchPoolsCount", Kind::U32),
    ("dyldInCacheMH", Kind::Addr),
    ("dyldInCacheEntry", Kind::Addr),
    ("imagesTextOffset", Kind::Addr),
    ("imagesTextCount", Kind::U64),
    ("patchInfoAddr", Kind::Addr),
    ("patchInfoSize", Kind::Addr),
    ("otherImageGroupAddrUnused", Kind::Addr),
    ("otherImageGroupSizeUnused", Kind::Addr),
    ("progClosuresAddr", Kind::Addr),
    ("progClosuresSize", Kind::Addr),
    ("progClosuresTrieAddr", Kind::Addr),
    ("progClosuresTrieSize", Kind::Addr),
    ("platform", Kind::Platform),
    ("formatVersion (bitfield)", Kind::U32),
    ("sharedRegionStart", Kind::Addr),
    ("sharedRegionSize", Kind::Addr),
    ("maxSlide", Kind::Addr),
    ("dylibsImageArrayAddr", Kind::Addr),
    ("dylibsImageArraySize", Kind::Addr),
    ("dylibsTrieAddr", Kind::Addr),
    ("dylibsTrieSize", Kind::Addr),
    ("otherImageArrayAddr", Kind::Addr),
    ("otherImageArraySize", Kind::Addr),
    ("otherTrieAddr", Kind::Addr),
    ("otherTrieSize", Kind::Addr),
    ("mappingWithSlideOffset", Kind::Off),
    ("mappingWithSlideCount", Kind::U32),
    ("dylibsPBLStateArrayAddrUnused", Kind::Addr),
    ("dylibsPBLSetAddr", Kind::Addr),
    ("programsPBLSetPoolAddr", Kind::Addr),
    ("programsPBLSetPoolSize", Kind::Addr),
    ("programTrieAddr", Kind::Addr),
    ("programTrieSize", Kind::U32),
    ("osVersion", Kind::Version),
    ("altPlatform", Kind::Platform),
    ("altOsVersion", Kind::Version),
    ("swiftOptsOffset", Kind::Addr),
    ("swiftOptsSize", Kind::Addr),
    ("subCacheArrayOffset", Kind::Off),
    ("subCacheArrayCount", Kind::U32),
    ("symbolFileUUID", Kind::Uuid),
    ("rosettaReadOnlyAddr", Kind::Addr),
    ("rosettaReadOnlySize", Kind::Addr),
    ("rosettaReadWriteAddr", Kind::Addr),
    ("rosettaReadWriteSize", Kind::Addr),
    ("imagesOffset", Kind::Off),
    ("imagesCount", Kind::U32),
    ("cacheSubType", Kind::U32),
];

/// Offset of `imagesOffset` and of `cacheSubType` in the header.
const IMAGES_OFFSET: u64 = 0x1c0;
const CACHE_SUB_TYPE: u64 = 0x1c8;
const SUBCACHE_ARRAY: u64 = 0x188;
const OS_VERSION: u64 = 0x16c;
const PLATFORM_OFFSET: u64 = 0xd8;

fn header(f: &mut Fields<'_>, limit: &u64) -> Result<()> {
    f.ascii("magic", 16).emit()?;
    for &(name, kind) in HEADER {
        let size = match kind {
            Kind::U32 | Kind::Off | Kind::Platform | Kind::Version => 4,
            Kind::U64 | Kind::Addr => 8,
            Kind::Uuid => 16,
        };
        if f.pos().saturating_add(size) > *limit {
            break;
        }
        match kind {
            Kind::U32 => {
                f.u32(name).emit()?;
            }
            Kind::Off => {
                f.u32(name).hex().emit()?;
            }
            Kind::U64 => {
                f.u64(name).emit()?;
            }
            Kind::Addr => {
                f.u64(name).hex().emit()?;
            }
            Kind::Uuid => {
                f.bytes(name, 16).with(|v, n| n.summary(uuid(v))).emit()?;
            }
            Kind::Platform => {
                f.u32(name).enumeration(PLATFORM).emit()?;
            }
            Kind::Version => {
                f.u32(name)
                    .hex()
                    .with(|&v, n| n.summary(version(v)))
                    .emit()?;
            }
        }
    }
    Ok(())
}

record! {
    struct Mapping {
        address: u64 "address" .hex(),
        size: u64 "size" .hex(),
        file_offset: u64 "fileOffset" .hex(),
        max_prot: u32 "maxProt" .flags(super::tables::VM_PROT),
        init_prot: u32 "initProt" .flags(super::tables::VM_PROT),
    }
}

record! {
    struct Image {
        address: u64 "address" .hex(),
        mod_time: u64 "modTime",
        inode: u64 "inode",
        path_offset: u32 "pathFileOffset" .hex(),
        pad: u32 "pad",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let fixed = cx.read_avail(file.sub(0, 0x200)).await?;
    let magic = crate::text::until_nul(fixed.get(..16).unwrap_or_default());
    let limit = u64::from(u32_le(&fixed, 0x10).unwrap_or(0)).min(0x1000);
    let span = file.sub(0, limit);
    cx.emit(struct_node("Header", span, LE, limit, header));
    let field = |offset: u64| {
        (offset.saturating_add(4) <= limit)
            .then(|| get_at::<u32>(&fixed, offset, LE))
            .flatten()
    };

    let mapping_offset = u64::from(field(0x10).unwrap_or(0));
    let mapping_count = field(0x14).unwrap_or(0);
    let (images_offset, images_count) =
        match (field(IMAGES_OFFSET), field(IMAGES_OFFSET.saturating_add(4))) {
            (Some(o), Some(c)) if o != 0 => (o, c),
            _ => (field(0x18).unwrap_or(0), field(0x1c).unwrap_or(0)),
        };

    let arch = magic.trim_start_matches("dyld_v1").trim();
    let mut summary = format!("dyld shared cache, {arch}, {images_count} images");
    if let (Some(platform), Some(os)) = (field(PLATFORM_OFFSET), field(OS_VERSION))
        && os != 0
    {
        summary.push_str(&format!(
            ", {} {}",
            name_or(PLATFORM, platform.into(), "platform"),
            version(os)
        ));
    }
    cx.annotate(summary);

    let mappings_span = file.sub(
        mapping_offset,
        u64::from(mapping_count).saturating_mul(Mapping::SIZE),
    );
    let mut mappings = Vec::new();
    for i in 0..mappings_span.len / Mapping::SIZE {
        let at = mappings_span.sub(i.saturating_mul(Mapping::SIZE), Mapping::SIZE);
        mappings.push(parse(&cx, at, LE, &(), Mapping::layout).await?);
    }
    cx.emit(
        Node::new("Mappings")
            .span(mappings_span)
            .summary(format!("{mapping_count} mappings"))
            .lazy(mapping_list, (mappings_span, file)),
    );
    let images = file.sub(
        images_offset.into(),
        u64::from(images_count).saturating_mul(Image::SIZE),
    );
    let ranges: Vec<(u64, u64, u64)> = mappings
        .iter()
        .map(|m| (m.address, m.size, m.file_offset))
        .collect();
    cx.emit(
        Node::new("Images")
            .span(images)
            .summary(format!("{images_count} images"))
            .lazy(image_list, (images, file, ranges)),
    );
    if let (Some(offset), Some(count)) = (
        field(SUBCACHE_ARRAY),
        field(SUBCACHE_ARRAY.saturating_add(4)),
    ) && count > 0
    {
        let v2 = limit > CACHE_SUB_TYPE;
        let size: u64 = if v2 { 56 } else { 24 };
        let span = file.sub(offset.into(), u64::from(count).saturating_mul(size));
        cx.emit(
            Node::new("Sub-caches")
                .span(span)
                .summary(format!("{count} sub-caches"))
                .lazy(subcaches, (span, v2)),
        );
    }
    Ok(())
}

async fn mapping_list(cx: Cx, (span, file): (Span, Span)) -> Result<()> {
    let count = span.len / Mapping::SIZE;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(Mapping::SIZE), Mapping::SIZE);
        let m = parse(&cx, at, LE, &(), Mapping::layout).await?;
        let p = m.init_prot;
        cx.push(
            Mapping::node(format!("Mapping {i}"), at, LE)
                .summary(format!(
                    "{} {:#x}+{:#x} from file {:#x}",
                    perms(p & 1 != 0, p & 2 != 0, p & 4 != 0),
                    m.address,
                    m.size,
                    m.file_offset
                ))
                .target(file.sub(m.file_offset, m.size)),
        )
        .await;
    }
    Ok(())
}

async fn image_list(
    cx: Cx,
    (span, file, mappings): (Span, Span, Vec<(u64, u64, u64)>),
) -> Result<()> {
    let count = span.len / Image::SIZE;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(Image::SIZE), Image::SIZE);
        let image = parse(&cx, at, LE, &(), Image::layout).await?;
        let name = match cx
            .cstr(file.tail(image.path_offset.into()).sub(0, 1024))
            .await
        {
            Ok((s, _)) => s,
            Err(_) => format!("#{i}"),
        };
        let mut node = Image::node(name, at, LE).value(hex(image.address, 64));
        if let Some(offset) = mappings.iter().find_map(|&(addr, size, off)| {
            let delta = image.address.checked_sub(addr)?;
            (delta < size).then(|| off.saturating_add(delta))
        }) {
            node = node.target(file.sub(offset, 0));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn subcaches(cx: Cx, (span, v2): (Span, bool)) -> Result<()> {
    let size: u64 = if v2 { 56 } else { 24 };
    let count = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(size), size);
        let data = cx.read(at).await?;
        let id = uuid(data.get(..16).unwrap_or_default());
        let offset = get_at::<u64>(&data, 16, LE).unwrap_or(0);
        let suffix = if v2 {
            crate::text::until_nul(data.get(24..56).unwrap_or_default())
        } else {
            format!(".{}", i.saturating_add(1))
        };
        cx.push(
            Node::new(suffix)
                .span(at)
                .value(text(id))
                .summary(format!("VM offset {offset:#x}")),
        )
        .await;
    }
    Ok(())
}
