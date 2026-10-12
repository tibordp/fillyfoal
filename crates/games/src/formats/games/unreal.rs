//! Unreal Engine packages (`.upk`, `.u`, `.uasset`, `.umap`): the package
//! file summary of Unreal Engine 1/2, 3 and 4/5, and for UE4/5 the name,
//! import and export tables.
//!
//! Layouts follow UModel (`UnPackage*.cpp`, UE1 to UE3) and UAssetAPI
//! (`UAsset.ReadHeader`, `Import`, `Export.ReadExportMapEntry`, UE4/5).

use std::sync::Arc;

use crate::bytes::{i32_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Layout, parse, struct_node};
use crate::formats::Input;
use crate::formats::util::{fmt, val};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;

/// The longest FString accepted, in bytes. Names and paths are short; a
/// larger length means the layout guess is wrong.
const FSTRING_MAX: u64 = 0x1_0000;

/// How much of the file the summary may span. Real summaries are a few
/// hundred bytes; long custom-version or chunk-ID arrays stay well inside.
const SUMMARY_MAX: u64 = 0x10_0000;

/// Decodes an FString at `f`: an i32 character count that includes the
/// terminating NUL, positive for 8-bit text and negative for UTF-16.
/// Emits one node, spanning the count and the text.
pub(crate) fn fstring(f: &mut Fields<'_>, name: &'static str) -> Result<String> {
    let start = f.pos();
    let count = f.i32(name).get()?;
    let wide = count < 0;
    let units = u64::from(count.unsigned_abs());
    let len = if wide { units.saturating_mul(2) } else { units };
    if len > FSTRING_MAX {
        return Err(Diagnostic::malformed(format!("string length {count}"))
            .at(f.block().span.sub(start, 4)));
    }
    let text = if wide {
        f.utf16(name, units).get()?
    } else {
        let raw = f.bytes(name, len).get()?;
        crate::text::latin1(raw.split(|&b| b == 0).next().unwrap_or_default())
    };
    let span = f.block().span.sub(start, f.pos().saturating_sub(start));
    f.node(Node::new(name).span(span).value(val::text(text.clone())));
    Ok(text)
}

/// Runs `layout` silently from the cursor to measure it, then emits it as a
/// lazy group node and moves past it.
fn group<C, R>(f: &mut Fields<'_>, name: &'static str, ctx: C, layout: Layout<C, R>) -> Result<R>
where
    C: Clone + Send + Sync + 'static,
    R: 'static,
{
    let start = f.pos();
    let mut probe = Fields::new(f.block(), LE);
    probe.seek(start);
    let result = layout(&mut probe, &ctx);
    let len = probe.pos().saturating_sub(start);
    if len > 0 {
        f.node(struct_node(name, f.peek_span(len), LE, ctx, layout));
    }
    f.skip(len);
    result
}

/// Rejects an array count that cannot fit in what is left of the block.
pub(crate) fn check_count(f: &Fields<'_>, count: i32, min_size: u64, what: &str) -> Result<u64> {
    let n = u64::try_from(count)
        .map_err(|_| Diagnostic::malformed(format!("{what} count {count}")).at(f.peek_span(0)))?;
    if n.saturating_mul(min_size) > f.remaining() {
        return Err(Diagnostic::malformed(format!("{what} count {count}")).at(f.peek_span(0)));
    }
    Ok(n)
}

pub async fn package(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let version = i32_le(&head, 4).unwrap_or(0);
    // Since UE4 the second field is a negative "legacy file version"
    // (-1 growing downwards); UE1 to UE3 store the file version in the low
    // half and the licensee version in the high half.
    if version < 0 && version > -0x1000 {
        return ue4_package(cx, input).await;
    }
    let raw = u32_le(&head, 4).unwrap_or(0);
    let file_version = raw & 0xffff;
    let summary = file.sub(0, file.len.min(SUMMARY_MAX));
    let s = parse(&cx, summary, LE, &file_version, legacy_summary).await?;
    let span = file.sub(0, s.len);
    cx.emit(struct_node(
        "Package summary",
        span,
        LE,
        file_version,
        legacy_summary,
    ));
    let engine = if file_version >= UE3_FIRST {
        "Unreal Engine 3"
    } else {
        "Unreal Engine 1/2"
    };
    if file_version >= UE3_FIRST && s.names.0 > 0 {
        let names = name_region(file, s.names.1, s.header_size);
        cx.emit(
            Node::new("Name table")
                .span(names)
                .summary(fmt::plural(s.names.0, "name"))
                .lazy(name_table, (names, s.names.0, NameKind::Ue3(file_version))),
        );
    } else {
        cx.emit(
            Node::new("Name table").summary(format!("{} names at {:#x}", s.names.0, s.names.1)),
        );
    }
    cx.emit(
        Node::new("Import table").summary(format!("{} imports at {:#x}", s.imports.0, s.imports.1)),
    );
    cx.emit(Node::new("Export table").summary(format!(
        "{} at {:#x}",
        crate::formats::util::fmt::plural(s.exports.0, "export"),
        s.exports.1
    )));
    cx.annotate(format!(
        "{engine} package v{file_version}, {}, {}",
        fmt::plural(s.names.0, "name"),
        fmt::plural(s.exports.0, "export")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Unreal Engine 1 to 3

/// The first UE3 file version (UModel's `PACKAGE_V3`).
const UE3_FIRST: u32 = 180;

const UE3_PACKAGE_FLAGS: FlagTable = &[
    flag(0x1, "AllowDownload"),
    flag(0x2, "ClientOptional"),
    flag(0x4, "ServerSideOnly"),
    flag(0x8, "Cooked"),
    flag(0x10, "Unsecure"),
    flag(0x20, "SavedWithNewerVersion"),
    flag(0x8000, "Need"),
    flag(0x20000, "ContainsMap"),
    flag(0x200000, "ContainsScript"),
    flag(0x800000, "StoreCompressed"),
    flag(0x2000000, "StoreFullyCompressed"),
];

struct LegacySummary {
    names: (u32, u32),
    exports: (u32, u32),
    imports: (u32, u32),
    header_size: u32,
    len: u64,
}

/// FPackageFileSummary of UE1/2 (`Serialize2`) and of Epic's UE3
/// (`Serialize3` without the per-game variations).
fn legacy_summary(f: &mut Fields<'_>, &version: &u32) -> Result<LegacySummary> {
    f.u32("Tag").hex().emit()?;
    f.u16("File version").emit()?;
    f.u16("Licensee version").emit()?;
    let ue3 = version >= UE3_FIRST;
    let mut header_size = 0;
    if ue3 {
        if version >= 249 {
            header_size = f.u32("Total header size").emit()?;
        }
        if version >= 269 {
            fstring(f, "Folder name")?;
        }
    }
    f.u32("Package flags").flags(UE3_PACKAGE_FLAGS).emit()?;
    let name_count = f.u32("Name count").emit()?;
    let name_offset = f.u32("Name offset").hex().emit()?;
    let export_count = f.u32("Export count").emit()?;
    let export_offset = f.u32("Export offset").hex().emit()?;
    let import_count = f.u32("Import count").emit()?;
    let import_offset = f.u32("Import offset").hex().emit()?;
    if ue3 {
        if version >= 415 {
            f.u32("Depends offset").hex().emit()?;
        }
        if version >= 623 {
            f.u32("Import/export guids offset").hex().emit()?;
            f.u32("Import guids count").emit()?;
            f.u32("Export guids count").emit()?;
        }
        if version >= 584 {
            f.u32("Thumbnail table offset").hex().emit()?;
        }
        f.guid("Package GUID").emit()?;
        let count = f.i32("Generations").emit()?;
        let size = if version >= 322 { 12 } else { 8 };
        check_count(f, count, size, "generation")?;
        group(f, "Generation list", (count, size), generations)?;
        if version >= 245 {
            f.u32("Engine version").emit()?;
        }
        if version >= 277 {
            f.u32("Cooker version").emit()?;
        }
        if version >= 334 {
            f.u32("Compression flags").flags(COMPRESSION_FLAGS).emit()?;
            let count = f.i32("Compressed chunks").emit()?;
            check_count(f, count, 16, "compressed chunk")?;
            group(f, "Compressed chunk list", count, compressed_chunks)?;
        }
        if version >= 482 {
            f.u32("Package source").hex().emit()?;
        }
    } else if version < 68 {
        f.u32("Heritage count").emit()?;
        f.u32("Heritage offset").hex().emit()?;
    } else {
        f.guid("Package GUID").emit()?;
        let count = f.i32("Generations").emit()?;
        check_count(f, count, 8, "generation")?;
        group(f, "Generation list", (count, 8), generations)?;
    }
    Ok(LegacySummary {
        names: (name_count, name_offset),
        exports: (export_count, export_offset),
        imports: (import_count, import_offset),
        header_size,
        len: f.pos(),
    })
}

/// FGenerationInfo: exports, names and (UE3 from v322) net objects.
fn generations(f: &mut Fields<'_>, &(count, size): &(i32, u64)) -> Result<()> {
    for i in 0..count {
        let start = f.pos();
        let exports = f.i32("Export count").get()?;
        let names = f.i32("Name count").get()?;
        if size >= 12 {
            f.i32("Net object count").get()?;
        }
        let span = f.block().span.sub(start, size);
        f.node(
            Node::new(format!("Generation {i}"))
                .span(span)
                .summary(format!(
                    "{exports_export}, {names_name}",
                    exports_export = crate::formats::util::fmt::plural(exports, "export"),
                    names_name = crate::formats::util::fmt::plural(names, "name")
                )),
        );
    }
    Ok(())
}

const COMPRESSION_FLAGS: FlagTable = &[
    flag(0x1, "ZLIB"),
    flag(0x2, "LZO"),
    flag(0x4, "LZX"),
    flag(0x10, "BiasMemory"),
    flag(0x20, "BiasSpeed"),
];

/// FCompressedChunk: where a compressed piece of the package goes.
fn compressed_chunks(f: &mut Fields<'_>, &count: &i32) -> Result<()> {
    for i in 0..count {
        let start = f.pos();
        let raw_offset = f.i32("Uncompressed offset").get()?;
        let raw_size = f.i32("Uncompressed size").get()?;
        let offset = f.i32("Compressed offset").get()?;
        let size = f.i32("Compressed size").get()?;
        f.node(
            Node::new(format!("Chunk {i}"))
                .span(f.block().span.sub(start, 16))
                .summary(format!(
                    "{size} bytes at {offset:#x} -> {raw_size} bytes at {raw_offset:#x}"
                )),
        );
    }
    Ok(())
}

/// The name table's region: from its offset to the end of the header when
/// the header size is known and past it, else to the end of the file.
fn name_region(file: Span, offset: u32, header_size: u32) -> Span {
    let end = if header_size > offset {
        u64::from(header_size)
    } else {
        file.len
    };
    file.sub(offset.into(), end.saturating_sub(offset.into()))
}

// ---------------------------------------------------------------------------
// Name tables

#[derive(Clone, Copy)]
enum NameKind {
    /// UE3: FString and flags (u64 from v195, u32 before).
    Ue3(u32),
    /// UE4/5: FString and, when `hashes`, two u16 hashes.
    Ue4 { hashes: bool },
}

#[derive(Clone)]
struct NameEntry {
    text: String,
    span: Span,
}

type Names = Arc<Vec<NameEntry>>;

/// Parses `count` names from `region`, once per region.
async fn load_names(cx: &Cx, region: Span, count: u64, kind: NameKind) -> Result<Names> {
    if let Some(names) = cx.cached::<Vec<NameEntry>>(region, "unreal-names") {
        return Ok(names);
    }
    let block = cx.block(region).await?;
    let mut f = Fields::new(&block, LE);
    // Every name takes at least four bytes, which bounds the allocation.
    let mut names = Vec::with_capacity(crate::bytes::to_usize(count.min(region.len / 4)));
    for i in 0..count {
        if f.remaining() == 0 {
            break;
        }
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
        let start = f.pos();
        let text = fstring(&mut f, "Name")?;
        match kind {
            NameKind::Ue3(version) if version >= 195 => f.skip(8),
            NameKind::Ue3(_) => f.skip(4),
            NameKind::Ue4 { hashes: true } if !text.is_empty() => f.skip(4),
            NameKind::Ue4 { .. } => {}
        }
        names.push(NameEntry {
            text,
            span: region.sub(start, f.pos().saturating_sub(start)),
        });
    }
    let names = Arc::new(names);
    cx.cache(region, "unreal-names", names.clone());
    Ok(names)
}

async fn name_table(cx: Cx, (region, count, kind): (Span, u32, NameKind)) -> Result<()> {
    let names = load_names(&cx, region, count.into(), kind).await?;
    cx.set_count(Count::Exact(crate::bytes::to_u64(names.len())));
    for (i, name) in names.iter().enumerate() {
        cx.push(
            Node::new(name.text.clone())
                .span(name.span)
                .summary(format!("#{i}")),
        )
        .await;
    }
    if names.len() < crate::bytes::to_usize(count.into()) {
        cx.diag(Diagnostic::malformed(format!(
            "name table holds {} of {count} names",
            names.len()
        )));
    }
    Ok(())
}

/// An FName (index into the name table and instance number) as text.
fn fname(names: &[NameEntry], index: i32, number: i32) -> String {
    let base = usize::try_from(index)
        .ok()
        .and_then(|i| names.get(i))
        .map_or_else(|| format!("<name {index}>"), |n| n.text.clone());
    if number > 0 {
        format!("{base}_{}", number.saturating_sub(1))
    } else {
        base
    }
}

/// Reads an FName at `f` as one node with the resolved text.
fn fname_field(f: &mut Fields<'_>, name: &'static str, names: &[NameEntry]) -> Result<String> {
    let start = f.pos();
    let index = f.i32(name).get()?;
    let number = f.i32(name).get()?;
    let text = fname(names, index, number);
    f.node(
        Node::new(name)
            .span(f.block().span.sub(start, 8))
            .value(val::text(text.clone()))
            .summary(format!("name #{index}, number {number}")),
    );
    Ok(text)
}

// ---------------------------------------------------------------------------
// Unreal Engine 4/5

/// UE4 object versions that change the summary or the tables (from
/// `EUnrealEngineObjectUE4Version`).
mod ue4v {
    pub const WORLD_LEVEL_INFO: i32 = 224;
    pub const ADDED_CHUNKID_TO_ASSETDATA_AND_UPACKAGE: i32 = 278;
    pub const CHANGED_CHUNKID_TO_BE_AN_ARRAY_OF_CHUNKIDS: i32 = 326;
    pub const ENGINE_VERSION_OBJECT: i32 = 336;
    pub const LOAD_FOR_EDITOR_GAME: i32 = 365;
    pub const ADD_STRING_ASSET_REFERENCES_MAP: i32 = 384;
    pub const PACKAGE_SUMMARY_HAS_COMPATIBLE_ENGINE_VERSION: i32 = 444;
    pub const SERIALIZE_TEXT_IN_PACKAGES: i32 = 459;
    pub const COOKED_ASSETS_IN_EDITOR_SUPPORT: i32 = 485;
    pub const NAME_HASHES_SERIALIZED: i32 = 504;
    pub const PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS: i32 = 507;
    pub const TEMPLATE_INDEX_IN_COOKED_EXPORTS: i32 = 508;
    pub const ADDED_SEARCHABLE_NAMES: i32 = 510;
    pub const EXPORTMAP_64BIT_SERIALSIZES: i32 = 511;
    pub const ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID: i32 = 516;
    pub const ADDED_PACKAGE_OWNER: i32 = 518;
    pub const NON_OUTER_PACKAGE_IMPORT: i32 = 520;
}

/// UE5 object versions (`EUnrealEngineObjectUE5Version`).
mod ue5v {
    pub const NAMES_REFERENCED_FROM_EXPORT_DATA: i32 = 1001;
    pub const PAYLOAD_TOC: i32 = 1002;
    pub const OPTIONAL_RESOURCES: i32 = 1003;
    pub const REMOVE_OBJECT_EXPORT_PACKAGE_GUID: i32 = 1005;
    pub const TRACK_OBJECT_EXPORT_IS_INHERITED: i32 = 1006;
    pub const ADD_SOFTOBJECTPATH_LIST: i32 = 1008;
    pub const DATA_RESOURCES: i32 = 1009;
    pub const SCRIPT_SERIALIZATION_OFFSET: i32 = 1010;
    pub const METADATA_SERIALIZATION_OFFSET: i32 = 1014;
    pub const VERSE_CELLS: i32 = 1015;
    pub const PACKAGE_SAVED_HASH: i32 = 1016;
    pub const IMPORT_TYPE_HIERARCHIES: i32 = 1018;
}

const UE5_VERSIONS: EnumTable = &[
    (1000, "INITIAL_VERSION"),
    (1001, "NAMES_REFERENCED_FROM_EXPORT_DATA"),
    (1002, "PAYLOAD_TOC"),
    (1003, "OPTIONAL_RESOURCES"),
    (1004, "LARGE_WORLD_COORDINATES"),
    (1005, "REMOVE_OBJECT_EXPORT_PACKAGE_GUID"),
    (1006, "TRACK_OBJECT_EXPORT_IS_INHERITED"),
    (1007, "FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES"),
    (1008, "ADD_SOFTOBJECTPATH_LIST"),
    (1009, "DATA_RESOURCES"),
    (1010, "SCRIPT_SERIALIZATION_OFFSET"),
    (1011, "PROPERTY_TAG_EXTENSION_AND_OVERRIDABLE_SERIALIZATION"),
    (1012, "PROPERTY_TAG_COMPLETE_TYPE_NAME"),
    (1013, "ASSETREGISTRY_PACKAGEBUILDDEPENDENCIES"),
    (1014, "METADATA_SERIALIZATION_OFFSET"),
    (1015, "VERSE_CELLS"),
    (1016, "PACKAGE_SAVED_HASH"),
    (1017, "OS_SUB_OBJECT_SHADOW_SERIALIZATION"),
    (1018, "IMPORT_TYPE_HIERARCHIES"),
];

const UE4_PACKAGE_FLAGS: FlagTable = &[
    flag(0x1, "NewlyCreated"),
    flag(0x2, "ClientOptional"),
    flag(0x4, "ServerSideOnly"),
    flag(0x10, "CompiledIn"),
    flag(0x20, "ForDiffing"),
    flag(0x40, "EditorOnly"),
    flag(0x80, "Developer"),
    flag(0x100, "UncookedOnly"),
    flag(0x200, "Cooked"),
    flag(0x400, "ContainsNoAsset"),
    flag(0x2000, "UnversionedProperties"),
    flag(0x4000, "ContainsMapData"),
    flag(0x10000, "Compiling"),
    flag(0x20000, "ContainsMap"),
    flag(0x40000, "RequiresLocalizationGather"),
    flag(0x100000, "PlayInEditor"),
    flag(0x200000, "ContainsScript"),
    flag(0x400000, "DisallowExport"),
    flag(0x10000000, "DynamicImports"),
    flag(0x20000000, "RuntimeGenerated"),
    flag(0x40000000, "ReloadingForCooker"),
    flag(0x80000000, "FilterEditorOnly"),
];

const PKG_UNVERSIONED_PROPERTIES: u32 = 0x2000;
const PKG_FILTER_EDITOR_ONLY: u32 = 0x8000_0000;

/// The versions and flags the table layouts depend on.
#[derive(Clone, Copy, Debug, Default)]
struct Versions {
    legacy: i32,
    ue4: i32,
    ue5: i32,
    flags: u32,
}

impl Versions {
    fn editor_data(&self) -> bool {
        self.flags & PKG_FILTER_EDITOR_ONLY == 0
    }

    fn import_size(&self) -> u64 {
        let mut size: u64 = 28;
        if self.ue4 >= ue4v::NON_OUTER_PACKAGE_IMPORT && self.editor_data() {
            size = size.saturating_add(8);
        }
        if self.ue5 >= ue5v::OPTIONAL_RESOURCES {
            size = size.saturating_add(4);
        }
        size
    }

    fn export_size(&self) -> u64 {
        // Class, super, outer, object name, object flags, three bools,
        // package flags.
        let mut size: u64 = 4 + 4 + 4 + 8 + 4 + 12 + 4;
        let mut add = |cond: bool, n: u64| {
            if cond {
                size = size.saturating_add(n);
            }
        };
        add(self.ue4 >= ue4v::TEMPLATE_INDEX_IN_COOKED_EXPORTS, 4);
        add(
            true,
            if self.ue4 >= ue4v::EXPORTMAP_64BIT_SERIALSIZES {
                16
            } else {
                8
            },
        );
        add(self.ue5 < ue5v::REMOVE_OBJECT_EXPORT_PACKAGE_GUID, 16);
        add(self.ue5 >= ue5v::TRACK_OBJECT_EXPORT_IS_INHERITED, 4);
        add(self.ue4 >= ue4v::LOAD_FOR_EDITOR_GAME, 4);
        add(self.ue4 >= ue4v::COOKED_ASSETS_IN_EDITOR_SUPPORT, 4);
        add(self.ue5 >= ue5v::OPTIONAL_RESOURCES, 4);
        add(self.ue4 >= ue4v::PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS, 20);
        add(
            self.flags & PKG_UNVERSIONED_PROPERTIES == 0
                && self.ue5 >= ue5v::SCRIPT_SERIALIZATION_OFFSET,
            16,
        );
        size
    }
}

#[derive(Default)]
struct Ue4Summary {
    v: Versions,
    licensee: i32,
    /// No versions stored (cooked with -unversioned): the layout past the
    /// name table offset depends on an engine version the file does not say.
    unversioned: bool,
    total_header: i32,
    folder: String,
    names: (i32, i32),
    exports: (i32, i32),
    imports: (i32, i32),
    bulk_start: i64,
    engine: Option<String>,
    len: u64,
}

fn custom_version_format(legacy: i32) -> &'static str {
    match legacy {
        -2 => "enums",
        -5..=-3 => "GUIDs with names",
        _ => "GUIDs",
    }
}

/// FCustomVersionContainer entries, in the format the legacy version picks.
fn custom_versions(f: &mut Fields<'_>, &(legacy, count): &(i32, i32)) -> Result<()> {
    for i in 0..count {
        let start = f.pos();
        let (key, version, friendly) = match legacy {
            -2 => {
                let tag = f.u32("Tag").get()?;
                (format!("tag {tag:#x}"), f.i32("Version").get()?, None)
            }
            _ => {
                let guid = f.guid("Key").get()?;
                let version = f.i32("Version").get()?;
                let friendly = if (-5..=-3).contains(&legacy) {
                    let mut quiet = Fields::new(f.block(), LE);
                    quiet.seek(f.pos());
                    let name = fstring(&mut quiet, "Friendly name")?;
                    f.seek(quiet.pos());
                    Some(name)
                } else {
                    None
                };
                (guid.to_string(), version, friendly)
            }
        };
        let span = f.block().span.sub(start, f.pos().saturating_sub(start));
        let title = friendly.unwrap_or_else(|| format!("Custom version {i}"));
        f.node(
            Node::new(title)
                .span(span)
                .value(val::int(version, 32))
                .summary(key),
        );
    }
    Ok(())
}

/// FEngineVersion: major, minor, patch, changelist and branch.
fn engine_version(f: &mut Fields<'_>, _: &()) -> Result<String> {
    let major = f.u16("Major").emit()?;
    let minor = f.u16("Minor").emit()?;
    let patch = f.u16("Patch").emit()?;
    let changelist = f.u32("Changelist").emit()?;
    let branch = fstring(f, "Branch")?;
    let mut s = format!("{major}.{minor}.{patch}-{}", changelist & 0x7fff_ffff);
    if !branch.is_empty() {
        s.push('+');
        s.push_str(&branch);
    }
    Ok(s)
}

fn strings(f: &mut Fields<'_>, &count: &i32) -> Result<()> {
    for i in 0..count {
        let mut quiet = Fields::new(f.block(), LE);
        quiet.seek(f.pos());
        let start = f.pos();
        let s = fstring(&mut quiet, "String")?;
        f.seek(quiet.pos());
        f.node(
            Node::new(format!("Package {i}"))
                .span(f.block().span.sub(start, f.pos().saturating_sub(start)))
                .value(val::text(s)),
        );
    }
    Ok(())
}

fn int_list(f: &mut Fields<'_>, &count: &i32) -> Result<()> {
    for i in 0..count {
        let start = f.pos();
        let v = f.i32("Value").get()?;
        f.node(
            Node::new(format!("{i}"))
                .span(f.block().span.sub(start, 4))
                .value(val::int(v, 32)),
        );
    }
    Ok(())
}

/// FPackageFileSummary of UE4 and UE5, as UAssetAPI's `ReadHeader` reads it.
fn ue4_summary(f: &mut Fields<'_>, _: &()) -> Result<Ue4Summary> {
    let mut s = Ue4Summary::default();
    f.u32("Tag").hex().emit()?;
    let legacy = f
        .i32("Legacy file version")
        .desc("Version of the summary layout itself, -1 downwards")
        .emit()?;
    if legacy != -4 {
        f.i32("Legacy UE3 version")
            .desc("864 in versioned packages, 0 in unversioned ones")
            .emit()?;
    }
    let ue4 = f.i32("UE4 object version").emit()?;
    let ue5 = if legacy <= -8 {
        f.i32("UE5 object version")
            .with(|&v, n| match u64::try_from(v) {
                Ok(raw) if v > 0 => n.value(val::enumv(raw, 32, UE5_VERSIONS)),
                _ => n,
            })
            .emit()?
    } else {
        0
    };
    s.licensee = f.i32("Licensee version").emit()?;
    s.unversioned = ue4 == 0 && ue5 == 0 && s.licensee == 0;
    s.v = Versions {
        legacy,
        ue4,
        ue5,
        flags: 0,
    };
    if ue5 >= ue5v::PACKAGE_SAVED_HASH {
        f.bytes("Saved hash", 20).emit()?;
        s.total_header = f.i32("Total header size").emit()?;
    }
    if legacy <= -2 {
        let count = f
            .i32("Custom versions")
            .desc(custom_version_format(legacy))
            .emit()?;
        let min = if legacy == -2 { 8 } else { 20 };
        check_count(f, count, min, "custom version")?;
        group(f, "Custom version list", (legacy, count), custom_versions)?;
    }
    if ue5 < ue5v::PACKAGE_SAVED_HASH {
        s.total_header = f.i32("Total header size").emit()?;
    }
    s.folder = fstring(f, "Package name")?;
    let flags = f.u32("Package flags").flags(UE4_PACKAGE_FLAGS).emit()?;
    s.v.flags = flags;
    s.names = (
        f.i32("Name count").emit()?,
        f.i32("Name offset").hex().emit()?,
    );
    if s.unversioned {
        // Everything from here on depends on the engine version.
        s.len = f.pos();
        return Ok(s);
    }
    let v = s.v;
    let editor = v.editor_data();
    if ue5 >= ue5v::ADD_SOFTOBJECTPATH_LIST {
        f.i32("Soft object path count").emit()?;
        f.i32("Soft object path offset").hex().emit()?;
    }
    if editor && ue4 >= ue4v::ADDED_PACKAGE_SUMMARY_LOCALIZATION_ID {
        fstring(f, "Localization ID")?;
    }
    if ue4 >= ue4v::SERIALIZE_TEXT_IN_PACKAGES {
        f.i32("Gatherable text data count").emit()?;
        f.i32("Gatherable text data offset").hex().emit()?;
    }
    s.exports = (
        f.i32("Export count").emit()?,
        f.i32("Export offset").hex().emit()?,
    );
    s.imports = (
        f.i32("Import count").emit()?,
        f.i32("Import offset").hex().emit()?,
    );
    if ue5 >= ue5v::VERSE_CELLS {
        f.i32("Cell export count").emit()?;
        f.i32("Cell export offset").hex().emit()?;
        f.i32("Cell import count").emit()?;
        f.i32("Cell import offset").hex().emit()?;
    }
    if ue5 >= ue5v::METADATA_SERIALIZATION_OFFSET {
        f.i32("Metadata offset").hex().emit()?;
    }
    f.i32("Depends offset").hex().emit()?;
    if ue4 >= ue4v::ADD_STRING_ASSET_REFERENCES_MAP {
        f.i32("Soft package reference count").emit()?;
        f.i32("Soft package reference offset").hex().emit()?;
    }
    if ue4 >= ue4v::ADDED_SEARCHABLE_NAMES {
        f.i32("Searchable names offset").hex().emit()?;
    }
    f.i32("Thumbnail table offset").hex().emit()?;
    if ue5 >= ue5v::IMPORT_TYPE_HIERARCHIES {
        f.i32("Import type hierarchy count").emit()?;
        f.i32("Import type hierarchy offset").hex().emit()?;
    }
    if ue5 < ue5v::PACKAGE_SAVED_HASH {
        f.guid("Package GUID").emit()?;
    }
    if editor {
        if ue4 >= ue4v::ADDED_PACKAGE_OWNER {
            f.guid("Persistent GUID").emit()?;
        }
        if (ue4v::ADDED_PACKAGE_OWNER..ue4v::NON_OUTER_PACKAGE_IMPORT).contains(&ue4) {
            f.guid("Owner persistent GUID").emit()?;
        }
    }
    let count = f.i32("Generations").emit()?;
    check_count(f, count, 8, "generation")?;
    group(f, "Generation list", (count, 8), generations)?;
    if ue4 >= ue4v::ENGINE_VERSION_OBJECT {
        s.engine = Some(group(f, "Saved by engine version", (), engine_version)?);
    } else {
        f.u32("Engine changelist").emit()?;
    }
    if ue4 >= ue4v::PACKAGE_SUMMARY_HAS_COMPATIBLE_ENGINE_VERSION {
        group(f, "Compatible with engine version", (), engine_version)?;
    }
    f.u32("Compression flags").flags(COMPRESSION_FLAGS).emit()?;
    let count = f.i32("Compressed chunks").emit()?;
    check_count(f, count, 16, "compressed chunk")?;
    group(f, "Compressed chunk list", count, compressed_chunks)?;
    f.u32("Package source").hex().emit()?;
    let count = f.i32("Additional packages to cook").emit()?;
    check_count(f, count, 4, "package")?;
    group(f, "Additional package list", count, strings)?;
    if legacy > -7 {
        f.i32("Texture allocations").emit()?;
    }
    f.i32("Asset registry data offset").hex().emit()?;
    s.bulk_start = f.int::<i64>("Bulk data start offset").hex().emit()?;
    if ue4 >= ue4v::WORLD_LEVEL_INFO {
        f.i32("World tile info offset").hex().emit()?;
    }
    if ue4 >= ue4v::CHANGED_CHUNKID_TO_BE_AN_ARRAY_OF_CHUNKIDS {
        let count = f.i32("Chunk IDs").emit()?;
        check_count(f, count, 4, "chunk ID")?;
        group(f, "Chunk ID list", count, int_list)?;
    } else if ue4 >= ue4v::ADDED_CHUNKID_TO_ASSETDATA_AND_UPACKAGE {
        f.i32("Chunk ID").emit()?;
    }
    if ue4 >= ue4v::PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS {
        f.i32("Preload dependency count").emit()?;
        f.i32("Preload dependency offset").hex().emit()?;
    }
    if ue5 >= ue5v::NAMES_REFERENCED_FROM_EXPORT_DATA {
        f.i32("Names referenced from export data").emit()?;
    }
    if ue5 >= ue5v::PAYLOAD_TOC {
        f.int::<i64>("Payload TOC offset").hex().emit()?;
    }
    if ue5 >= ue5v::DATA_RESOURCES {
        f.i32("Data resource offset").hex().emit()?;
    }
    s.len = f.pos();
    Ok(s)
}

/// A table's span from a count and an offset, if both are sane.
fn table_span(file: Span, (count, offset): (i32, i32), size: u64) -> Result<Span> {
    let count =
        u64::try_from(count).map_err(|_| Diagnostic::malformed(format!("table count {count}")))?;
    let offset = u64::try_from(offset)
        .map_err(|_| Diagnostic::malformed(format!("table offset {offset}")))?;
    file.sub_exact(offset, count.saturating_mul(size))
}

#[derive(Clone)]
struct Tables {
    file: Span,
    v: Versions,
    names: (Span, u32, NameKind),
    imports: Option<Span>,
}

impl Tables {
    async fn names(&self, cx: &Cx) -> Names {
        let (region, count, kind) = self.names;
        match load_names(cx, region, count.into(), kind).await {
            Ok(names) => names,
            Err(e) => {
                cx.diag(e);
                Arc::new(Vec::new())
            }
        }
    }

    /// The object names of the imports, for resolving class references.
    async fn import_names(&self, cx: &Cx, names: &[NameEntry]) -> Arc<Vec<String>> {
        let Some(span) = self.imports else {
            return Arc::new(Vec::new());
        };
        if let Some(cached) = cx.cached::<Vec<String>>(span, "unreal-imports") {
            return cached;
        }
        let size = self.v.import_size();
        let mut out = Vec::new();
        if let Ok(data) = cx.read(span).await {
            for (i, entry) in data.chunks_exact(crate::bytes::to_usize(size)).enumerate() {
                if i % 1024 == 1023 {
                    cx.checkpoint().await;
                }
                let at = |o: usize| i32_le(entry, o).unwrap_or(-1);
                out.push(fname(names, at(20), at(24)));
            }
        }
        let out = Arc::new(out);
        cx.cache(span, "unreal-imports", out.clone());
        out
    }
}

async fn ue4_package(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let summary = file.sub(0, file.len.min(SUMMARY_MAX));
    let s = parse(&cx, summary, LE, &(), ue4_summary).await?;
    let span = file.sub(0, s.len);
    cx.emit(struct_node("Package summary", span, LE, (), ue4_summary));
    let v = s.v;
    let hashes = s.unversioned || v.ue4 >= ue4v::NAME_HASHES_SERIALIZED;
    let name_count = u32::try_from(s.names.0).unwrap_or(0);
    let name_offset = u32::try_from(s.names.1).unwrap_or(0);
    let header = u32::try_from(s.total_header).unwrap_or(0);
    let names = (
        name_region(file, name_offset, header),
        name_count,
        NameKind::Ue4 { hashes },
    );
    if name_count > 0 {
        cx.emit(
            Node::new("Name table")
                .span(names.0)
                .summary(fmt::plural(name_count, "name"))
                .lazy(name_table, names),
        );
    }
    let generation = match (v.legacy, v.ue5) {
        (_, 1000..) => "Unreal Engine 5",
        (-7..=-1, _) => "Unreal Engine 4",
        _ => "Unreal Engine 5",
    };
    if s.unversioned {
        cx.emit(
            Node::new("Import and export tables").diag(Diagnostic::unsupported(
                "unversioned package: the rest of the summary depends on the engine version",
            )),
        );
        cx.annotate(format!(
            "{generation} package \"{}\", unversioned, {}",
            s.folder,
            fmt::plural(name_count, "name")
        ));
        return Ok(());
    }
    let mut tables = Tables {
        file,
        v,
        names,
        imports: None,
    };
    match table_span(file, s.imports, v.import_size()) {
        Ok(span) => {
            tables.imports = Some(span);
            if s.imports.0 > 0 {
                cx.emit(
                    Node::new("Import table")
                        .span(span)
                        .summary(fmt::plural(
                            span.len.checked_div(v.import_size()).unwrap_or(0),
                            "import",
                        ))
                        .lazy(import_table, (tables.clone(), span)),
                );
            }
        }
        Err(e) => cx.emit(Node::new("Import table").diag(e)),
    }
    match table_span(file, s.exports, v.export_size()) {
        Ok(span) if s.exports.0 > 0 => cx.emit(
            Node::new("Export table")
                .span(span)
                .summary(fmt::plural(
                    span.len.checked_div(v.export_size()).unwrap_or(0),
                    "export",
                ))
                .lazy(export_table, (tables.clone(), span)),
        ),
        Ok(_) => {}
        Err(e) => cx.emit(Node::new("Export table").diag(e)),
    }
    if let Ok(bulk) = u64::try_from(s.bulk_start)
        && bulk > 0
        && bulk < file.len
    {
        cx.emit(Node::new("Bulk data").span(file.tail(bulk)));
    }
    let mut note = format!("{generation} package \"{}\"", s.folder);
    if let Some(engine) = &s.engine {
        note.push_str(&format!(" ({engine})"));
    }
    cx.annotate(format!(
        "{note}, {}, {}, {}",
        fmt::plural(name_count, "name"),
        fmt::plural(u64::try_from(s.imports.0).unwrap_or(0), "import"),
        fmt::plural(u64::try_from(s.exports.0).unwrap_or(0), "export"),
    ));
    Ok(())
}

#[derive(Clone)]
struct EntryCtx {
    file: Span,
    v: Versions,
    names: Names,
    imports: Arc<Vec<String>>,
}

impl EntryCtx {
    /// What an FPackageIndex refers to.
    fn object(&self, index: i32) -> String {
        match index {
            0 => "none".into(),
            i if i < 0 => {
                let n = usize::try_from(i.unsigned_abs().saturating_sub(1)).unwrap_or(usize::MAX);
                self.imports
                    .get(n)
                    .map_or_else(|| format!("import {n}"), |s| s.clone())
            }
            i => format!("export {}", i.saturating_sub(1)),
        }
    }
}

fn package_index(f: &mut Fields<'_>, name: &'static str, ctx: &EntryCtx) -> Result<i32> {
    let index = f.i32(name).get()?;
    let start = f.pos().saturating_sub(4);
    f.node(
        Node::new(name)
            .span(f.block().span.sub(start, 4))
            .value(val::int(index, 32))
            .summary(ctx.object(index)),
    );
    Ok(index)
}

/// FObjectImport.
fn import_entry(f: &mut Fields<'_>, ctx: &EntryCtx) -> Result<(String, String)> {
    let package = fname_field(f, "Class package", &ctx.names)?;
    let class = fname_field(f, "Class name", &ctx.names)?;
    package_index(f, "Outer", ctx)?;
    let object = fname_field(f, "Object name", &ctx.names)?;
    if ctx.v.ue4 >= ue4v::NON_OUTER_PACKAGE_IMPORT && ctx.v.editor_data() {
        fname_field(f, "Package name", &ctx.names)?;
    }
    if ctx.v.ue5 >= ue5v::OPTIONAL_RESOURCES {
        f.u32("Optional").emit()?;
    }
    Ok((object, format!("{package}.{class}")))
}

async fn import_table(cx: Cx, (tables, span): (Tables, Span)) -> Result<()> {
    let names = tables.names(&cx).await;
    let ctx = EntryCtx {
        file: tables.file,
        v: tables.v,
        imports: tables.import_names(&cx, &names).await,
        names,
    };
    let size = tables.v.import_size();
    let count = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    let data = cx.block(span).await?;
    for i in 0..count {
        let at = i.saturating_mul(size);
        let entry = span.sub(at, size);
        let mut f = Fields::new(&data, LE);
        f.seek(at);
        let (object, class) = import_entry(&mut f, &ctx)?;
        cx.push(
            struct_node(object, entry, LE, ctx.clone(), import_entry)
                .summary(format!("{class} (import {i})")),
        )
        .await;
    }
    Ok(())
}

fn bool32(f: &mut Fields<'_>, name: &'static str) -> Result<u32> {
    f.u32(name).emit()
}

/// FObjectExport (an export map entry). Returns the object name, the class
/// and the serialized data's size.
fn export_entry(f: &mut Fields<'_>, ctx: &EntryCtx) -> Result<(String, String, u64)> {
    let v = ctx.v;
    let class = package_index(f, "Class", ctx)?;
    package_index(f, "Super", ctx)?;
    if v.ue4 >= ue4v::TEMPLATE_INDEX_IN_COOKED_EXPORTS {
        package_index(f, "Template", ctx)?;
    }
    package_index(f, "Outer", ctx)?;
    let object = fname_field(f, "Object name", &ctx.names)?;
    f.u32("Object flags").hex().emit()?;
    let (size, offset) = if v.ue4 >= ue4v::EXPORTMAP_64BIT_SERIALSIZES {
        (
            f.int::<i64>("Serial size").emit()?,
            f.int::<i64>("Serial offset").hex().emit()?,
        )
    } else {
        (
            f.i32("Serial size").emit()?.into(),
            f.i32("Serial offset").hex().emit()?.into(),
        )
    };
    let size = u64::try_from(size).unwrap_or(0);
    if let Ok(offset) = u64::try_from(offset)
        && size > 0
    {
        f.node(Node::new("Serialized data").span(ctx.file.sub(offset, size)));
    }
    bool32(f, "Forced export")?;
    bool32(f, "Not for client")?;
    bool32(f, "Not for server")?;
    if v.ue5 < ue5v::REMOVE_OBJECT_EXPORT_PACKAGE_GUID {
        f.guid("Package GUID").emit()?;
    }
    if v.ue5 >= ue5v::TRACK_OBJECT_EXPORT_IS_INHERITED {
        bool32(f, "Inherited instance")?;
    }
    f.u32("Package flags").flags(UE4_PACKAGE_FLAGS).emit()?;
    if v.ue4 >= ue4v::LOAD_FOR_EDITOR_GAME {
        bool32(f, "Not always loaded for editor game")?;
    }
    if v.ue4 >= ue4v::COOKED_ASSETS_IN_EDITOR_SUPPORT {
        bool32(f, "Is asset")?;
    }
    if v.ue5 >= ue5v::OPTIONAL_RESOURCES {
        bool32(f, "Generate public hash")?;
    }
    if v.ue4 >= ue4v::PRELOAD_DEPENDENCIES_IN_COOKED_EXPORTS {
        f.i32("First export dependency").emit()?;
        f.i32("Serialization before serialization dependencies")
            .emit()?;
        f.i32("Create before serialization dependencies").emit()?;
        f.i32("Serialization before create dependencies").emit()?;
        f.i32("Create before create dependencies").emit()?;
    }
    if v.flags & PKG_UNVERSIONED_PROPERTIES == 0 && v.ue5 >= ue5v::SCRIPT_SERIALIZATION_OFFSET {
        f.int::<i64>("Script serialization start").hex().emit()?;
        f.int::<i64>("Script serialization end").hex().emit()?;
    }
    Ok((object, ctx.object(class), size))
}

async fn export_table(cx: Cx, (tables, span): (Tables, Span)) -> Result<()> {
    let names = tables.names(&cx).await;
    let ctx = EntryCtx {
        file: tables.file,
        v: tables.v,
        imports: tables.import_names(&cx, &names).await,
        names,
    };
    let size = tables.v.export_size();
    let count = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    let data = cx.block(span).await?;
    for i in 0..count {
        let at = i.saturating_mul(size);
        let entry = span.sub(at, size);
        let mut f = Fields::new(&data, LE);
        f.seek(at);
        let (object, class, bytes) = export_entry(&mut f, &ctx)?;
        cx.push(
            struct_node(object, entry, LE, ctx.clone(), export_entry)
                .summary(format!("{class}, {} (export {i})", fmt::size(bytes))),
        )
        .await;
    }
    Ok(())
}
