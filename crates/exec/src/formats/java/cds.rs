//! HotSpot Class Data Sharing archives (`.jsa`): the static archive a JDK
//! dumps with `-Xshare:dump` (magic `0xf00baba2`) and the dynamic archive
//! `-XX:ArchiveClassesAtExit` writes on top of a static one (`0xf00baba8`).
//!
//! The archive is HotSpot's in-memory `FileMapHeader` written out as is
//! (little-endian, C++ struct padding), followed by the regions it maps:
//! `rw` and `ro` metadata, `bm` (relocation bitmaps) and the archived Java
//! heap (`hp`; `ca0`/`ca1`/`oa0`/`oa1` before JDK 21), each at a page
//! aligned file offset. Since version 13 the header starts with a
//! `GenericCDSFileMapHeader` (magic, CRC, version, header size, where the
//! base archive's name is) that every later JDK keeps, so other JDKs can
//! tell an archive is not theirs; the region table and the rest of the
//! header change from release to release.
//!
//! Layouts were taken from HotSpot's `include/cds.h`, `cds/filemap.hpp`,
//! `cds/dynamicArchive.hpp` and `cds/metaspaceShared.hpp` of JDK 17, 21 and
//! 25 (facts only), and checked field by field against archives those
//! JDKs (Temurin 17.0.20.1, 21.0.12.1, 25.0.4.1) wrote: versions 11, 18 and
//! 19. For other versions the generic header and the raw header are shown.
//! The header CRC (from after `_crc` in version 11, after `_header_size`
//! since 13, to the end of the header) and each region's CRC are checked,
//! the latter on request. Region contents are shown as raw data.

use crate::bytes::{to_u64, u32_le};
use crate::codec::crc::crc32_update;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::fmt::plural;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const STATIC_MAGIC: u32 = 0xf00b_aba2;
const DYNAMIC_MAGIC: u32 = 0xf00b_aba8;
/// Largest header whose CRC is checked.
const MAX_HEADER: u64 = 1 << 20;
/// Region bytes hashed between suspension points.
const CRC_CHUNK: u64 = 1 << 20;
/// `JVM_IDENT_MAX`.
const IDENT: u64 = 256;

pub static FORMAT: Format = Format {
    name: "jvm-cds",
    title: "Java class data sharing archive",
    extensions: &["jsa"],
    mime: "application/x-java-cds",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// The magic, a plausible version, and (since version 13) a header size
/// that covers at least the generic header.
fn probe(h: &Head<'_>) -> bool {
    let Some(magic) = u32_le(h.data, 0) else {
        return false;
    };
    let version = u32_le(h.data, 8).unwrap_or(0);
    (magic == STATIC_MAGIC || magic == DYNAMIC_MAGIC)
        && (1..=100).contains(&version)
        && (version < 13 || u32_le(h.data, 12).is_some_and(|s| s >= 24 && u64::from(s) <= h.len))
}

const MAGIC: EnumTable = &[
    (STATIC_MAGIC as u64, "static archive"),
    (DYNAMIC_MAGIC as u64, "dynamic archive"),
];

/// The layouts known, by CDS archive version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    /// Version 11 (JDK 17): no generic header, seven 72-byte regions.
    V11,
    /// Version 18 (JDK 21): four 88-byte regions.
    V18,
    /// Version 19 (JDK 25): five 96-byte regions.
    V19,
}

impl Layout {
    fn of(version: u32) -> Option<Self> {
        match version {
            11 => Some(Layout::V11),
            18 => Some(Layout::V18),
            19 => Some(Layout::V19),
            _ => None,
        }
    }

    fn jdk(self) -> &'static str {
        match self {
            Layout::V11 => "JDK 17",
            Layout::V18 => "JDK 21",
            Layout::V19 => "JDK 25",
        }
    }

    /// Where the region table starts.
    fn regions_at(self) -> u64 {
        match self {
            Layout::V11 => 16,
            Layout::V18 | Layout::V19 => 24,
        }
    }

    fn region_size(self) -> u64 {
        match self {
            Layout::V11 => 72,
            Layout::V18 => 88,
            Layout::V19 => 96,
        }
    }

    fn names(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Layout::V11 => &[
                ("rw", "read-write metadata"),
                ("ro", "read-only metadata"),
                ("bm", "relocation bitmaps"),
                ("ca0", "closed archive heap region 0"),
                ("ca1", "closed archive heap region 1"),
                ("oa0", "open archive heap region 0"),
                ("oa1", "open archive heap region 1"),
            ],
            Layout::V18 => &[
                ("rw", "read-write metadata"),
                ("ro", "read-only metadata"),
                ("bm", "relocation bitmaps"),
                ("hp", "archived heap objects"),
            ],
            Layout::V19 => &[
                ("rw", "read-write metadata"),
                ("ro", "read-only metadata"),
                ("bm", "relocation bitmaps"),
                ("hp", "archived heap objects"),
                ("ac", "AOT code"),
            ],
        }
    }

    fn regions_end(self) -> u64 {
        let n = to_u64(self.names().len());
        self.regions_at()
            .saturating_add(n.saturating_mul(self.region_size()))
    }

    /// Where the header's CRC starts.
    fn crc_from(self) -> u64 {
        match self {
            Layout::V11 => 8,
            Layout::V18 | Layout::V19 => 16,
        }
    }

    /// End of `FileMapHeader` (where a dynamic archive's extra fields
    /// start), and where `_jvm_ident` is.
    fn file_map_end(self) -> u64 {
        match self {
            Layout::V11 => 0x3b4,
            Layout::V18 => 0x310,
            Layout::V19 => 0x3d8,
        }
    }

    fn ident_at(self) -> u64 {
        match self {
            Layout::V11 => 0x269,
            Layout::V18 => 0x1d8,
            Layout::V19 => 0x248,
        }
    }
}

const NARROW_OOP_MODE: EnumTable = &[
    (0, "UnscaledNarrowOop"),
    (1, "ZeroBasedNarrowOop"),
    (2, "DisjointBaseNarrowOop"),
    (3, "HeapBasedNarrowOop"),
];

fn flag(f: &mut Fields<'_>, name: &'static str) -> Result<bool> {
    f.u8(name)
        .with(|&v, n| n.value(Value::Bool(v != 0)))
        .emit()
        .map(|v| v != 0)
}

fn flag32(f: &mut Fields<'_>, name: &'static str) -> Result<bool> {
    f.u32(name)
        .with(|&v, n| n.value(Value::Bool(v != 0)))
        .emit()
        .map(|v| v != 0)
}

/// Moves to `at` (struct padding), never backwards.
fn pad_to(f: &mut Fields<'_>, at: u64) {
    let pos = f.pos();
    if at > pos {
        f.skip(at.saturating_sub(pos));
    }
}

#[derive(Clone, Copy, Debug)]
struct Generic {
    magic: u32,
    version: u32,
    header_size: u64,
    name_offset: u32,
    name_size: u32,
}

/// The first fields: magic, CRC, version and, since version 13, the rest
/// of `GenericCDSFileMapHeader`.
fn generic(f: &mut Fields<'_>, check: &Option<u32>) -> Result<Generic> {
    let magic = f.u32("_magic").hex().enumeration(MAGIC).emit()?;
    f.u32("_crc")
        .hex()
        .desc("CRC-32 of the header")
        .check(|&v| match check {
            Some(c) if *c != v => Some(Diagnostic::malformed(format!(
                "header CRC mismatch: computed {c:#010x}"
            ))),
            _ => None,
        })
        .with(|&v, n| match check {
            Some(c) if *c == v => n.summary("matches"),
            _ => n,
        })
        .emit()?;
    let version = f
        .u32("_version")
        .with(|&v, n| match Layout::of(v) {
            Some(l) => n.summary(l.jdk()),
            None => n,
        })
        .emit()?;
    let mut g = Generic {
        magic,
        version,
        header_size: 0,
        name_offset: 0,
        name_size: 0,
    };
    if version >= 13 {
        g.header_size = f
            .u32("_header_size")
            .desc("Size of the whole header, base archive name included")
            .emit()?
            .into();
        g.name_offset = f
            .u32("_base_archive_name_offset")
            .hex()
            .desc("Where the base archive's name is (0: the JDK's default archive)")
            .emit()?;
        g.name_size = f
            .u32("_base_archive_name_size")
            .desc("Length of the base archive's name, with its NUL")
            .emit()?;
    }
    Ok(g)
}

#[derive(Clone, Copy, Debug, Default)]
struct Region {
    crc: u32,
    file_offset: u64,
    used: u64,
}

/// One `CDSFileMapRegion`.
fn region(f: &mut Fields<'_>, layout: &Layout) -> Result<Region> {
    let crc = f
        .u32("_crc")
        .hex()
        .desc("CRC-32 of the region's used bytes")
        .emit()?;
    flag32(f, "_read_only")?;
    flag32(f, "_allow_exec")?;
    flag32(f, "_is_heap_region")?;
    flag32(f, "_is_bitmap_region")?;
    flag32(f, "_mapped_from_file")?;
    let file_offset = f.u64("_file_offset").hex().emit()?;
    f.u64("_mapping_offset")
        .hex()
        .desc("Where the region is mapped, relative to the requested base address (heap regions: to the heap)")
        .emit()?;
    let used = f
        .u64("_used")
        .desc("Bytes in use (without alignment padding)")
        .emit()?;
    f.u64("_oopmap_offset").hex().emit()?;
    f.u64("_oopmap_size_in_bits").emit()?;
    if *layout != Layout::V11 {
        f.u64("_ptrmap_offset").hex().emit()?;
        f.u64("_ptrmap_size_in_bits").emit()?;
    }
    f.u64("_mapped_base")
        .hex()
        .desc("Mapped address at run time (0 in the file)")
        .emit()?;
    if *layout == Layout::V19 {
        flag(f, "_in_reserved_space")?;
    }
    Ok(Region {
        crc,
        file_offset,
        used,
    })
}

/// The rest of `FileMapHeader`, after the region table.
fn file_map(f: &mut Fields<'_>, layout: &Layout) -> Result<()> {
    let base = layout.regions_end();
    let at = |off: u64| off.saturating_sub(base);
    match layout {
        Layout::V11 => {
            f.u64("_header_size").emit()?;
            f.u64("_core_region_alignment").hex().emit()?;
            f.u32("_obj_alignment").emit()?;
            pad_to(f, at(0x220));
            f.u64("_narrow_oop_base").hex().emit()?;
            f.u32("_narrow_oop_shift").emit()?;
            flag(f, "_compact_strings")?;
            pad_to(f, at(0x230));
            f.u64("_max_heap_size").hex().emit()?;
            f.u32("_narrow_oop_mode")
                .enumeration(NARROW_OOP_MODE)
                .emit()?;
            f.u32("_narrow_klass_shift").emit()?;
            flag(f, "_compressed_oops")?;
            flag(f, "_compressed_class_ptrs")?;
            pad_to(f, at(0x248));
            f.u64("_cloned_vtables_offset").hex().emit()?;
            f.u64("_serialized_data_offset").hex().emit()?;
            f.u64("_heap_begin").hex().emit()?;
            f.u64("_heap_end").hex().emit()?;
            flag(f, "_base_archive_is_default")?;
            f.ascii("_jvm_ident", IDENT).emit()?;
            pad_to(f, at(0x370));
            f.u64("_base_archive_name_size").emit()?;
            f.u64("_shared_path_table_offset").hex().emit()?;
            f.u32("_shared_path_table_size").emit()?;
            path_indices(f)?;
            verify_flags(f)?;
            pad_to(f, at(0x390));
            f.u64("_requested_base_address").hex().emit()?;
            f.u64("_mapped_base_address").hex().emit()?;
            flag(f, "_allow_archiving_with_java_agent")?;
            flag(f, "_use_optimized_module_handling")?;
            flag(f, "_use_full_module_graph")?;
            pad_to(f, at(0x3a8));
            f.u64("_ptrmap_size_in_bits").emit()?;
            f.u32("_heap_obj_roots").hex().emit()?;
        }
        Layout::V18 => {
            f.u64("_core_region_alignment").hex().emit()?;
            f.u32("_obj_alignment").emit()?;
            pad_to(f, at(0x188));
            f.u64("_narrow_oop_base").hex().emit()?;
            f.u32("_narrow_oop_shift").emit()?;
            flag(f, "_compact_strings")?;
            pad_to(f, at(0x198));
            f.u64("_max_heap_size").hex().emit()?;
            f.u32("_narrow_oop_mode")
                .enumeration(NARROW_OOP_MODE)
                .emit()?;
            f.u32("_narrow_klass_shift").emit()?;
            flag(f, "_compressed_oops")?;
            flag(f, "_compressed_class_ptrs")?;
            flag(f, "_use_secondary_supers_table")?;
            pad_to(f, at(0x1b0));
            f.u64("_cloned_vtables_offset").hex().emit()?;
            f.u64("_serialized_data_offset").hex().emit()?;
            f.u64("_heap_begin").hex().emit()?;
            f.u64("_heap_end").hex().emit()?;
            flag(f, "_has_non_jar_in_classpath")?;
            pad_to(f, at(0x1d4));
            f.u32("_common_app_classpath_prefix_size").emit()?;
            f.ascii("_jvm_ident", IDENT).emit()?;
            f.u64("_shared_path_table_offset").hex().emit()?;
            path_indices(f)?;
            verify_flags(f)?;
            pad_to(f, at(0x2f0));
            f.u64("_requested_base_address").hex().emit()?;
            f.u64("_mapped_base_address").hex().emit()?;
            flag(f, "_allow_archiving_with_java_agent")?;
            flag(f, "_use_optimized_module_handling")?;
            flag(f, "_use_full_module_graph")?;
            pad_to(f, at(0x308));
            f.u64("_ptrmap_size_in_bits").emit()?;
        }
        Layout::V19 => {
            f.u64("_core_region_alignment").hex().emit()?;
            f.u32("_obj_alignment").emit()?;
            pad_to(f, at(0x208));
            f.u64("_narrow_oop_base").hex().emit()?;
            f.u32("_narrow_oop_shift").emit()?;
            flag(f, "_compact_strings")?;
            flag(f, "_compact_headers")?;
            pad_to(f, at(0x218));
            f.u64("_max_heap_size").hex().emit()?;
            f.u32("_narrow_oop_mode")
                .enumeration(NARROW_OOP_MODE)
                .emit()?;
            flag(f, "_compressed_oops")?;
            flag(f, "_compressed_class_ptrs")?;
            pad_to(f, at(0x228));
            f.u32("_narrow_klass_pointer_bits").emit()?;
            f.u32("_narrow_klass_shift").emit()?;
            f.u64("_cloned_vtables_offset").hex().emit()?;
            f.u64("_early_serialized_data_offset").hex().emit()?;
            f.u64("_serialized_data_offset").hex().emit()?;
            f.ascii("_jvm_ident", IDENT).emit()?;
            f.u64("_class_location_config_offset").hex().emit()?;
            verify_flags(f)?;
            pad_to(f, at(0x358));
            f.u64("_requested_base_address").hex().emit()?;
            f.u64("_mapped_base_address").hex().emit()?;
            flag(f, "_allow_archiving_with_java_agent")?;
            flag(f, "_use_optimized_module_handling")?;
            flag(f, "_has_aot_linked_classes")?;
            flag(f, "_has_full_module_graph")?;
            pad_to(f, at(0x370));
            f.u64("_heap_root_segments._base_offset").hex().emit()?;
            f.u64("_heap_root_segments._count").emit()?;
            f.u32("_heap_root_segments._roots_count").emit()?;
            f.u32("_heap_root_segments._max_size_in_bytes").emit()?;
            f.u32("_heap_root_segments._max_size_in_elems").emit()?;
            pad_to(f, at(0x390));
            f.u64("_heap_oopmap_start_pos").emit()?;
            f.u64("_heap_ptrmap_start_pos").emit()?;
            f.u64("_rw_ptrmap_start_pos").emit()?;
            f.u64("_ro_ptrmap_start_pos").emit()?;
            f.u32("_type_profile_level").emit()?;
            f.u32("_type_profile_args_limit").emit()?;
            f.u32("_type_profile_parms_limit").emit()?;
            pad_to(f, at(0x3c0));
            f.u64("_type_profile_width").emit()?;
            f.u64("_bci_profile_width").emit()?;
            flag(f, "_profile_traps")?;
            flag(f, "_type_profile_casts")?;
            pad_to(f, at(0x3d4));
            f.u32("_spec_trap_limit_extra_entries").emit()?;
        }
    }
    Ok(())
}

fn path_indices(f: &mut Fields<'_>) -> Result<()> {
    f.u16("_app_class_paths_start_index").emit()?;
    f.u16("_app_module_paths_start_index").emit()?;
    f.u16("_num_module_paths").emit()?;
    f.u16("_max_used_path_index").emit()?;
    Ok(())
}

fn verify_flags(f: &mut Fields<'_>) -> Result<()> {
    flag(f, "_verify_local")?;
    flag(f, "_verify_remote")?;
    flag(f, "_has_platform_or_app_classes")?;
    Ok(())
}

/// `DynamicArchiveHeader`'s own fields: the CRCs of the base archive's
/// header and regions it was made against.
fn dynamic(f: &mut Fields<'_>, layout: &Layout) -> Result<()> {
    f.u32("_base_header_crc").hex().emit()?;
    for (name, _) in layout.names() {
        f.u32("_base_region_crc")
            .hex()
            .summary(format!("base archive's {name} region"))
            .emit()?;
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let first = cx.read(file.sub(0, 24)).await?;
    let version = u32_le(&first, 8).unwrap_or(0);
    let magic = u32_le(&first, 0).unwrap_or(0);
    let layout = Layout::of(version);
    let generic_len: u64 = if version >= 13 { 24 } else { 12 };

    // The header size: in the generic header since version 13, a field of
    // `FileMapHeader` before.
    let header_size = match layout {
        Some(Layout::V11) => {
            let b = cx.read(file.sub(0x208, 8)).await?;
            crate::bytes::u64_le(&b, 0)
        }
        _ if version >= 13 => u32_le(&first, 12).map(u64::from),
        _ => None,
    };
    let check = match (layout, header_size) {
        (Some(l), Some(size)) if size <= MAX_HEADER && size > l.crc_from() => {
            let span = file.sub(l.crc_from(), size.saturating_sub(l.crc_from()));
            let data = cx.read(span).await?;
            cx.charge(to_u64(data.len()) / 256).await;
            (to_u64(data.len()) == span.len).then(|| !crc32_update(!0, &data))
        }
        _ => None,
    };
    let g = parse(&cx, file.sub(0, generic_len), LE, &None, generic).await?;
    let kind = if g.magic == DYNAMIC_MAGIC {
        "dynamic"
    } else {
        "static"
    };
    let header_name = if version >= 13 {
        "Generic header"
    } else {
        "Header"
    };
    cx.emit(struct_node(
        header_name,
        file.sub(0, generic_len),
        LE,
        check,
        generic,
    ));

    let Some(layout) = layout else {
        // Where the rest of the header ends is known only from a header
        // size (version 13 on); before, the node has no span.
        let mut node = Node::new("Header data").diag(Diagnostic::unsupported(format!(
            "the header layout of CDS archive version {version} is not known \
             (versions 11, 18 and 19 are)"
        )));
        if let Some(len) = header_size.filter(|&l| l > generic_len) {
            node = node.span(file.sub(generic_len, len.saturating_sub(generic_len)));
        }
        cx.emit(node);
        let jdk = match version {
            2 => " (JDK 8)",
            5 => " (JDK 11)",
            _ => "",
        };
        cx.annotate(format!("{kind} CDS archive, version {version}{jdk}"));
        return Ok(());
    };

    let names = layout.names();
    let table = file.sub(
        layout.regions_at(),
        layout.regions_end().saturating_sub(layout.regions_at()),
    );
    cx.emit(
        Node::new("Regions")
            .span(table)
            .summary(plural(to_u64(names.len()), "region"))
            .lazy(regions, (input, layout)),
    );
    let fm = file.sub(
        layout.regions_end(),
        layout.file_map_end().saturating_sub(layout.regions_end()),
    );
    cx.emit(struct_node("FileMapHeader", fm, LE, layout, file_map));
    if magic == DYNAMIC_MAGIC {
        let n = to_u64(names.len()).saturating_add(1).saturating_mul(4);
        cx.emit(struct_node(
            "DynamicArchiveHeader",
            file.sub(layout.file_map_end(), n),
            LE,
            layout,
            dynamic,
        ));
    }

    // The base archive's name: at the recorded offset since version 13,
    // right after the header before.
    let name_span = match layout {
        Layout::V11 => {
            let b = cx.read(file.sub(0x370, 8)).await?;
            let size = crate::bytes::u64_le(&b, 0).unwrap_or(0);
            (magic == DYNAMIC_MAGIC && size > 0)
                .then(|| file.sub(header_size.unwrap_or(0), size.min(4096)))
        }
        Layout::V18 | Layout::V19 => (g.name_offset != 0 && g.name_size > 0)
            .then(|| file.sub(g.name_offset.into(), u64::from(g.name_size).min(4096))),
    };
    let mut base = None;
    if let Some(span) = name_span {
        let bytes = cx.read(span).await?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let name = String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned();
        cx.emit(
            Node::new("Base archive name")
                .span(span)
                .value(Value::Text(name.clone())),
        );
        base = Some(name);
    }

    let ident = cx.read(file.sub(layout.ident_at(), IDENT)).await?;
    let end = ident.iter().position(|&b| b == 0).unwrap_or(ident.len());
    let ident = String::from_utf8_lossy(ident.get(..end).unwrap_or_default()).into_owned();
    let vm = ident.split(", built").next().unwrap_or_default().trim();
    let mut summary = format!(
        "{kind} CDS archive, version {} ({})",
        g.version,
        layout.jdk()
    );
    if magic == DYNAMIC_MAGIC {
        summary.push_str(&match &base {
            Some(b) => format!(", base {b}"),
            None => ", on the default base archive".to_owned(),
        });
    }
    if !vm.is_empty() {
        summary.push_str(&format!("; {vm}"));
    }
    cx.annotate(summary);
    Ok(())
}

/// The region table: one entry per region, with its contents.
async fn regions(cx: Cx, (input, layout): (Input, Layout)) -> Result<()> {
    let file = input.span;
    for (i, (name, what)) in layout.names().iter().enumerate() {
        let at = layout
            .regions_at()
            .saturating_add(to_u64(i).saturating_mul(layout.region_size()));
        let span = file.sub(at, layout.region_size());
        let r = parse(&cx, span, LE, &layout, region).await?;
        let mut node = struct_node(*name, span, LE, layout, region);
        if r.used == 0 {
            node = node.summary(format!("{what}, empty"));
            cx.push(node).await;
            continue;
        }
        node = node.summary(format!("{what}, {} bytes at {:#x}", r.used, r.file_offset));
        let data = file.sub(r.file_offset, r.used);
        if data.len < r.used {
            node = node.diag(
                Diagnostic::truncated(
                    Span::new(
                        file.source,
                        file.offset.saturating_add(r.file_offset),
                        r.used,
                    ),
                    data.len,
                )
                .at(span),
            );
        }
        cx.push(node).await;
        if data.len == 0 {
            continue;
        }
        cx.push(
            Node::new(format!("{name} data"))
                .span(data)
                .summary(format!("{what}, {} bytes", r.used))
                .lazy(verify, (data, r.used, r.crc)),
        )
        .await;
    }
    Ok(())
}

/// Checks a region's CRC (hashing it a chunk at a time).
async fn verify(cx: Cx, (data, used, crc): (Span, u64, u32)) -> Result<()> {
    if data.len < used {
        cx.emit(
            Node::new("CRC-32")
                .value(Value::UInt {
                    value: crc.into(),
                    bits: 32,
                    radix: crate::value::Radix::Hex,
                })
                .summary("not checked: the region is cut short"),
        );
        return Ok(());
    }
    let mut reg = !0u32;
    let mut pos = 0u64;
    while pos < data.len {
        let chunk = cx.read(data.sub(pos, CRC_CHUNK)).await?;
        if chunk.is_empty() {
            break;
        }
        reg = crc32_update(reg, &chunk);
        cx.charge(to_u64(chunk.len()) / 256).await;
        pos = pos.saturating_add(to_u64(chunk.len()));
    }
    let computed = !reg;
    let mut node = Node::new("CRC-32").value(Value::UInt {
        value: crc.into(),
        bits: 32,
        radix: crate::value::Radix::Hex,
    });
    node = if computed == crc {
        node.summary("matches the region's contents")
    } else {
        node.diag(Diagnostic::malformed(format!(
            "region CRC mismatch: computed {computed:#010x}"
        )))
    };
    cx.emit(node);
    cx.emit(
        Node::new("Contents")
            .span(data)
            .summary(format!("{used} bytes")),
    );
    Ok(())
}
