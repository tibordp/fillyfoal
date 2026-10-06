//! Preferred Executable Format (`Joy!peff`): classic Mac OS code fragments
//! for PowerPC and 68k (CFM). A container header, section headers, and a
//! loader section listing imported libraries, symbols and exports.

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::util::binutil::{data_node, ellipsize, name_or};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "mac-pef",
    title: "Preferred Executable Format (classic Mac OS)",
    extensions: &["pef", "shlb"],
    mime: "application/x-pef",
    probe: Probe::Magic(&[(0, b"Joy!peff")]),
    dissect: crate::expander!(dissect: Input),
};

const SECTION_KIND: EnumTable = &[
    (0, "code"),
    (1, "unpacked data"),
    (2, "pattern-initialized data"),
    (3, "constant"),
    (4, "loader"),
    (5, "debug"),
    (6, "executable data"),
    (7, "exception"),
    (8, "traceback"),
];

const SHARE_KIND: EnumTable = &[(1, "process"), (4, "global"), (5, "protected")];

record! {
    struct ContainerHeader {
        tag1: ascii[4] "tag1",
        tag2: ascii[4] "tag2",
        architecture: ascii[4] "architecture" .desc("pwpc or m68k"),
        version: u32 "formatVersion",
        timestamp: u32 "dateTimeStamp" .mac_time(),
        old_def: u32 "oldDefVersion" .hex(),
        old_imp: u32 "oldImpVersion" .hex(),
        current: u32 "currentVersion" .hex(),
        sections: u16 "sectionCount",
        inst_sections: u16 "instSectionCount",
        reserved: u32 "reservedA",
    }
}

record! {
    struct SectionHeader {
        name_offset: i32 "nameOffset",
        address: u32 "defaultAddress" .hex(),
        total: u32 "totalLength" .hex(),
        unpacked: u32 "unpackedLength" .hex(),
        container: u32 "containerLength" .hex(),
        offset: u32 "containerOffset" .hex(),
        kind: u8 "sectionKind" .enumeration(SECTION_KIND),
        share: u8 "shareKind" .enumeration(SHARE_KIND),
        alignment: u8 "alignment",
        reserved: u8 "reservedA",
    }
}

record! {
    struct LoaderHeader {
        main_section: i32 "mainSection",
        main_offset: u32 "mainOffset" .hex(),
        init_section: i32 "initSection",
        init_offset: u32 "initOffset" .hex(),
        term_section: i32 "termSection",
        term_offset: u32 "termOffset" .hex(),
        libraries: u32 "importedLibraryCount",
        imports: u32 "totalImportedSymbolCount",
        reloc_sections: u32 "relocSectionCount",
        reloc_offset: u32 "relocInstrOffset" .hex(),
        strings: u32 "loaderStringsOffset" .hex(),
        hash: u32 "exportHashOffset" .hex(),
        hash_power: u32 "exportHashTablePower",
        exports: u32 "exportedSymbolCount",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, ContainerHeader::SIZE);
    cx.emit(ContainerHeader::node("Container Header", hspan, BE));
    let h = parse(&cx, hspan, BE, &(), ContainerHeader::layout).await?;
    let table = file.sub(
        ContainerHeader::SIZE,
        u64::from(h.sections).saturating_mul(SectionHeader::SIZE),
    );
    let names_at = table.end().saturating_sub(file.offset);
    let mut sections = Vec::new();
    for i in 0..table.len.checked_div(SectionHeader::SIZE).unwrap_or(0) {
        let at = table.sub(i.saturating_mul(SectionHeader::SIZE), SectionHeader::SIZE);
        sections.push((at, parse(&cx, at, BE, &(), SectionHeader::layout).await?));
    }
    let mut libraries = Vec::new();
    for (_, s) in &sections {
        if s.kind == 4 {
            let loader = file.sub(s.offset.into(), s.container.into());
            libraries = imported_libraries(&cx, loader).await.unwrap_or_default();
        }
    }
    cx.annotate(format!(
        "PEF {} code fragment, {} sections{}",
        if h.architecture == "pwpc" {
            "PowerPC"
        } else {
            "68k"
        },
        h.sections,
        if libraries.is_empty() {
            String::new()
        } else {
            format!(", imports {}", ellipsize(&libraries.join(", "), 100))
        }
    ));
    for (at, s) in sections {
        let name = if s.name_offset >= 0 {
            let names = file.tail(names_at);
            crate::formats::util::binutil::string_at(
                &cx,
                names,
                u64::try_from(s.name_offset).unwrap_or(0),
            )
            .await
            .map_or_else(|_| String::new(), |(n, _)| n)
        } else {
            String::new()
        };
        let label = if name.is_empty() {
            name_or(SECTION_KIND, s.kind.into(), "section")
        } else {
            name
        };
        let data = file.sub(s.offset.into(), s.container.into());
        cx.emit(
            Node::new(label)
                .span(at)
                .summary(format!(
                    "{}, {:#x} bytes at {:#x}",
                    name_or(SECTION_KIND, s.kind.into(), "kind"),
                    s.container,
                    s.offset
                ))
                .target(data)
                .lazy(section, (at, data, s.kind)),
        );
    }
    Ok(())
}

async fn imported_libraries(cx: &Cx, loader: Span) -> Result<Vec<String>> {
    let h = parse(
        cx,
        loader.sub(0, LoaderHeader::SIZE),
        BE,
        &(),
        LoaderHeader::layout,
    )
    .await?;
    let strings = loader.tail(h.strings.into());
    let mut out = Vec::new();
    for i in 0..u64::from(h.libraries.min(256)) {
        let at = loader.sub(LoaderHeader::SIZE.saturating_add(i.saturating_mul(24)), 4);
        let off = cx.read(at).await?;
        let name = crate::formats::util::binutil::string_at(
            cx,
            strings,
            u32_be(&off, 0).unwrap_or(0).into(),
        )
        .await?
        .0;
        out.push(name);
    }
    Ok(out)
}

async fn section(cx: Cx, (at, data, kind): (Span, Span, u8)) -> Result<()> {
    cx.emit(SectionHeader::node("Section Header", at, BE));
    if kind == 4 {
        let hspan = data.sub(0, LoaderHeader::SIZE);
        cx.emit(LoaderHeader::node("Loader Header", hspan, BE));
        let h = parse(&cx, hspan, BE, &(), LoaderHeader::layout).await?;
        let strings = data.tail(h.strings.into());
        let libs = data.sub(
            LoaderHeader::SIZE,
            u64::from(h.libraries).saturating_mul(24),
        );
        cx.emit(
            Node::new("Imported Libraries")
                .span(libs)
                .summary(format!("{} libraries", h.libraries))
                .lazy(libraries, (libs, strings)),
        );
        let symbols = data.sub(
            libs.end().saturating_sub(data.offset),
            u64::from(h.imports).saturating_mul(4),
        );
        cx.emit(
            Node::new("Imported Symbols")
                .span(symbols)
                .summary(format!("{} symbols", h.imports))
                .lazy(imported_symbols, (symbols, strings)),
        );
        cx.emit(data_node("Loader Strings", strings, strings.len));
    } else {
        cx.emit(data_node("Contents", data, data.len));
    }
    Ok(())
}

async fn libraries(cx: Cx, (span, strings): (Span, Span)) -> Result<()> {
    let count = span.len / 24;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(24), 24);
        let data = cx.read(at).await?;
        let name = crate::formats::util::binutil::string_at(
            &cx,
            strings,
            u32_be(&data, 0).unwrap_or(0).into(),
        )
        .await
        .map_or_else(|_| format!("#{i}"), |(s, _)| s);
        cx.push(Node::new(name).span(at).summary(format!(
            "{} symbols from {}, versions {:#x}..{:#x}",
            u32_be(&data, 12).unwrap_or(0),
            u32_be(&data, 16).unwrap_or(0),
            u32_be(&data, 4).unwrap_or(0),
            u32_be(&data, 8).unwrap_or(0)
        )))
        .await;
    }
    Ok(())
}

const SYMBOL_CLASS: EnumTable = &[
    (0, "code"),
    (1, "data"),
    (2, "transition vector"),
    (3, "TOC"),
    (4, "glue"),
];

async fn imported_symbols(cx: Cx, (span, strings): (Span, Span)) -> Result<()> {
    let count = span.len / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(4), 4);
        let data = cx.read(at).await?;
        let word = u32_be(&data, 0).unwrap_or(0);
        let class = word >> 24;
        let name =
            crate::formats::util::binutil::string_at(&cx, strings, (word & 0x00ff_ffff).into())
                .await
                .map_or_else(|_| format!("#{i}"), |(s, _)| s);
        cx.push(Node::new(name).span(at).summary(format!(
            "{}{}",
            name_or(SYMBOL_CLASS, (class & 0xf).into(), "class"),
            if class & 0x80 != 0 { ", weak" } else { "" }
        )))
        .await;
    }
    Ok(())
}
