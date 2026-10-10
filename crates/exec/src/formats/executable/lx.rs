//! Linear Executables: `LE` (Windows 3.x/9x VxDs, DOS extenders) and `LX`
//! (32-bit OS/2), reached from the PE dissector via the MZ stub's
//! `e_lfanew`. Shows the header, the object table, names and imported
//! modules.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::util::arcutil::push_nodes;
use crate::formats::util::fmt::clip;
use crate::formats::util::val::name_or;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "lx",
    title: "Linear Executable (LE/LX: VxD, OS/2)",
    extensions: &["vxd", "386", "exe", "dll", "sys"],
    mime: "application/x-dosexec",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"MZ")
        && u32_le(h.data, 0x3c).is_some_and(|o| {
            let at = crate::bytes::to_usize(o.into());
            h.at(at, b"LE") || h.at(at, b"LX")
        })
}

const CPU: EnumTable = &[
    (1, "80286"),
    (2, "80386"),
    (3, "80486"),
    (4, "Pentium"),
    (0x20, "i860 (N10)"),
    (0x21, "i860 (N11)"),
    (0x40, "MIPS R2000/R3000"),
    (0x41, "MIPS R6000"),
    (0x42, "MIPS R4000"),
];

const OS: EnumTable = &[
    (0, "unknown"),
    (1, "OS/2"),
    (2, "Windows"),
    (3, "DOS 4.x"),
    (4, "Windows 386"),
    (5, "IBM Microkernel Personality Neutral"),
];

const MODULE_FLAGS: FlagTable = &[
    flag(0x4, "PER_PROCESS_LIBRARY_INIT"),
    flag(0x10, "INTERNAL_FIXUPS_REMOVED"),
    flag(0x20, "EXTERNAL_FIXUPS_REMOVED"),
    field(0x700, 0x100, "PM_INCOMPATIBLE"),
    field(0x700, 0x200, "PM_COMPATIBLE"),
    field(0x700, 0x300, "PM_APP"),
    flag(0x2000, "NOT_LOADABLE"),
    field(0x3_8000, 0x8000, "LIBRARY"),
    field(0x3_8000, 0x1_8000, "PROTECTED_MEMORY_LIBRARY"),
    field(0x3_8000, 0x2_0000, "PHYSICAL_DEVICE_DRIVER"),
    field(0x3_8000, 0x2_8000, "VIRTUAL_DEVICE_DRIVER"),
    flag(0x4000_0000, "PER_PROCESS_LIBRARY_TERMINATION"),
];

const OBJECT_FLAGS: FlagTable = &[
    flag(0x1, "READABLE"),
    flag(0x2, "WRITABLE"),
    flag(0x4, "EXECUTABLE"),
    flag(0x8, "RESOURCE"),
    flag(0x10, "DISCARDABLE"),
    flag(0x20, "SHARED"),
    flag(0x40, "PRELOAD"),
    flag(0x80, "INVALID"),
    flag(0x100, "ZEROFILLED"),
    flag(0x200, "RESIDENT"),
    flag(0x400, "RESIDENT_CONTIGUOUS"),
    flag(0x800, "RESIDENT_LONG_LOCKABLE"),
    flag(0x1000, "IBM_RESERVED"),
    flag(0x2000, "BIG_DEFAULT (32-bit)"),
    flag(0x4000, "CONFORMING"),
    flag(0x8000, "IO_PRIVILEGE"),
];

record! {
    struct Header {
        signature: ascii[2] "Signature",
        byte_order: u8 "ByteOrder" .desc("0: little-endian"),
        word_order: u8 "WordOrder",
        level: u32 "FormatLevel",
        cpu: u16 "CpuType" .enumeration(CPU),
        os: u16 "OsType" .enumeration(OS),
        version: u32 "ModuleVersion",
        flags: u32 "ModuleFlags" .flags(MODULE_FLAGS),
        pages: u32 "ModulePages",
        eip_object: u32 "EipObject",
        eip: u32 "Eip" .hex(),
        esp_object: u32 "EspObject",
        esp: u32 "Esp" .hex(),
        page_size: u32 "PageSize" .hex(),
        page_shift: u32 "LastPageSize/PageShift" .hex(),
        fixup_size: u32 "FixupSectionSize" .hex(),
        fixup_checksum: u32 "FixupSectionChecksum" .hex(),
        loader_size: u32 "LoaderSectionSize" .hex(),
        loader_checksum: u32 "LoaderSectionChecksum" .hex(),
        objects_offset: u32 "ObjectTableOffset" .hex(),
        objects: u32 "ObjectCount",
        page_map: u32 "ObjectPageMapOffset" .hex(),
        iterated: u32 "ObjectIterDataMapOffset" .hex(),
        resources_offset: u32 "ResourceTableOffset" .hex(),
        resources: u32 "ResourceCount",
        resident_names: u32 "ResidentNamesOffset" .hex(),
        entry_table: u32 "EntryTableOffset" .hex(),
        directives: u32 "ModuleDirectivesOffset" .hex(),
        directive_count: u32 "ModuleDirectivesCount",
        fixup_pages: u32 "FixupPageTableOffset" .hex(),
        fixup_records: u32 "FixupRecordTableOffset" .hex(),
        imports_offset: u32 "ImportModuleTableOffset" .hex(),
        imports: u32 "ImportModuleCount",
        import_procs: u32 "ImportProcTableOffset" .hex(),
        page_checksums: u32 "PerPageChecksumOffset" .hex(),
        data_pages: u32 "DataPagesOffset" .hex() .desc("From the start of the file"),
        preload_pages: u32 "PreloadPageCount",
        nonresident_names: u32 "NonResidentNamesOffset" .hex() .desc("From the start of the file"),
        nonresident_length: u32 "NonResidentNamesLength" .hex(),
        nonresident_checksum: u32 "NonResidentNamesChecksum" .hex(),
        auto_data: u32 "AutoDataObject",
        debug_offset: u32 "DebugInfoOffset" .hex(),
        debug_length: u32 "DebugInfoLength" .hex(),
        instance_preload: u32 "InstancePreloadPages",
        instance_demand: u32 "InstanceDemandPages",
        heap: u32 "HeapSize" .hex(),
    }
}

record! {
    struct Object {
        virtual_size: u32 "VirtualSize" .hex(),
        base: u32 "RelocationBase" .hex(),
        flags: u32 "Flags" .flags(OBJECT_FLAGS),
        page_index: u32 "PageTableIndex",
        page_count: u32 "PageTableEntries",
        reserved: u32 "Reserved",
    }
}

/// Length-prefixed strings until a zero length (or `limit` entries); with
/// `ordinals`, each is followed by a 16-bit ordinal.
fn pascal_list(data: &[u8], ordinals: bool, limit: usize, base: Span) -> Vec<Node> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while out.len() < limit {
        let Some((name, n)) = super::ne::pascal(data, at) else {
            break;
        };
        if n <= 1 {
            break;
        }
        let end = at.saturating_add(n);
        let len = if ordinals { n.saturating_add(2) } else { n };
        let mut node = Node::new(name).span(base.sub(to_u64(at), to_u64(len)));
        if ordinals {
            let ordinal = crate::bytes::u16_le(data, end).unwrap_or(0);
            node = node.summary(if out.is_empty() {
                "module name".to_owned()
            } else {
                format!("ordinal {ordinal}")
            });
        }
        out.push(node);
        at = at.saturating_add(len);
    }
    out
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mz = cx.read_avail(file.sub(0, 64)).await?;
    let lfanew = u64::from(u32_le(&mz, 0x3c).unwrap_or(0));
    cx.emit(Node::new("MZ Header").span(file.sub(0, 64)));
    if lfanew > 64 {
        cx.emit(Node::new("DOS Stub").span(file.sub(64, lfanew.saturating_sub(64))));
    }
    let base = file.tail(lfanew);
    let hspan = base.sub(0, Header::SIZE);
    cx.emit(Header::node("Header", hspan, LE));
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;

    let resident_span = base.sub(
        h.resident_names.into(),
        u64::from(h.entry_table.saturating_sub(h.resident_names)),
    );
    let resident_data = cx.read_avail(resident_span.sub(0, 0x10000)).await?;
    let resident = pascal_list(&resident_data, true, 0x4000, resident_span);
    let imports_span = base.sub(
        h.imports_offset.into(),
        u64::from(h.import_procs.saturating_sub(h.imports_offset)),
    );
    let imports_data = cx.read_avail(imports_span.sub(0, 0x10000)).await?;
    let imports = pascal_list(
        &imports_data,
        false,
        crate::bytes::to_usize(h.imports.into()),
        imports_span,
    );
    let module = resident
        .first()
        .map(|n| n.name.to_string())
        .unwrap_or_default();
    let kind = match h.flags & 0x3_8000 {
        0x8000 => "DLL",
        0x2_8000 => "VxD",
        0x2_0000 => "physical device driver",
        _ => "executable",
    };
    let names: Vec<String> = imports.iter().map(|n| n.name.to_string()).collect();
    cx.annotate(format!(
        "{} {kind} ({}, {}), module {module}, {} objects{}",
        if &h.signature == "LX" { "LX" } else { "LE" },
        name_or(OS, h.os.into(), "OS"),
        name_or(CPU, h.cpu.into(), "CPU"),
        h.objects,
        if names.is_empty() {
            String::new()
        } else {
            format!(", imports {}", clip(&names.join(", "), 80))
        }
    ));
    let table = base.sub(
        h.objects_offset.into(),
        u64::from(h.objects).saturating_mul(Object::SIZE),
    );
    cx.emit(
        Node::new("Object Table")
            .span(table)
            .summary(format!("{} objects", h.objects))
            .lazy(objects, table),
    );
    cx.emit(
        Node::new("Resident Names")
            .span(resident_span)
            .lazy(push_nodes, Arc::new(resident)),
    );
    cx.emit(
        Node::new("Imported Modules")
            .span(imports_span)
            .lazy(push_nodes, Arc::new(imports)),
    );
    if h.nonresident_length > 0 {
        let span = file.sub(h.nonresident_names.into(), h.nonresident_length.into());
        let data = cx.read_avail(span.sub(0, 0x10000)).await?;
        cx.emit(
            Node::new("Non-resident Names")
                .span(span)
                .lazy(push_nodes, Arc::new(pascal_list(&data, true, 0x4000, span))),
        );
    }
    Ok(())
}

async fn objects(cx: Cx, table: Span) -> Result<()> {
    let count = table.len / Object::SIZE;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = table.sub(i.saturating_mul(Object::SIZE), Object::SIZE);
        let o = parse(&cx, at, LE, &(), Object::layout).await?;
        let flag = |b: u32, c: char| if o.flags & b != 0 { c } else { '-' };
        cx.push(
            Object::node(format!("Object {}", i.saturating_add(1)), at, LE).summary(format!(
                "{}{}{} {:#x} bytes at {:#x}, {} pages",
                flag(1, 'r'),
                flag(2, 'w'),
                flag(4, 'x'),
                o.virtual_size,
                o.base,
                o.page_count
            )),
        )
        .await;
    }
    Ok(())
}
