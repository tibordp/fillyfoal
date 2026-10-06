//! Android VDEX files (`vdex`): verified DEX files and verifier
//! dependencies written by `dex2oat` next to OAT files.
//!
//! Version 027 (Android 12 and later) is a header and a section table;
//! the DEX section holds the DEX files back to back, shown as embedded
//! DEX. Older versions are shown down to the header.

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse};
use crate::formats::binutil::{data_node, name_or};
use crate::formats::{Format, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "vdex",
    title: "Android verified DEX container",
    extensions: &["vdex"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| h.starts_with(b"vdex") && h.at(7, b"\0")),
    dissect: crate::expander!(dissect: Input),
};

const SECTION: EnumTable = &[
    (0, "kChecksumSection"),
    (1, "kDexFileSection"),
    (2, "kVerifierDepsSection"),
    (3, "kTypeLookupTableSection"),
];

record! {
    struct Section {
        kind: u32 "section_kind" .enumeration(SECTION),
        offset: u32 "section_offset" .hex(),
        size: u32 "section_size" .hex(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("magic", 4).emit()?;
    let version = f.ascii("version", 4).emit()?;
    let number: u32 = version.parse().unwrap_or(0);
    if number < 27 {
        let rest = cx.block(file.sub(8, 20)).await?;
        let mut f = Fields::emitting(&cx, &rest, LE);
        f.ascii("dex_section_version", 4).emit()?;
        let dexes = f.u32("number_of_dex_files").emit()?;
        f.u32("verifier_deps_size").hex().emit()?;
        f.u32("bootclasspath_checksums_size").hex().emit()?;
        f.u32("class_loader_context_size").hex().emit()?;
        cx.annotate(format!("Android VDEX v{version}, {dexes} DEX files"));
        cx.emit(data_node(
            "Contents",
            file.tail(28),
            file.len.saturating_sub(28),
        ));
        return Ok(());
    }
    let count = f.u32("number_of_sections").emit()?;
    let table = file.sub(12, u64::from(count).saturating_mul(Section::SIZE));
    let n = table.len.checked_div(Section::SIZE).unwrap_or(0);
    let mut dexes = 0u64;
    let mut sections = Vec::new();
    for i in 0..n {
        let at = table.sub(i.saturating_mul(Section::SIZE), Section::SIZE);
        let s = parse(&cx, at, LE, &(), Section::layout).await?;
        if s.kind == 0 {
            dexes = u64::from(s.size) / 4;
        }
        sections.push((at, s));
    }
    cx.annotate(format!("Android VDEX v{version}, {dexes} DEX files"));
    for (at, s) in sections {
        let span = file.sub(s.offset.into(), s.size.into());
        let label = name_or(SECTION, s.kind.into(), "section");
        let node = Section::node(label, at, LE)
            .summary(format!("{:#x} bytes at {:#x}", s.size, s.offset))
            .target(span);
        cx.emit(node);
        match s.kind {
            0 => cx.emit(Node::new("Checksums").span(span).lazy(checksums, span)),
            1 if s.size > 0 => cx.emit(
                Node::new("DEX Files")
                    .span(span)
                    .lazy(dex_files, (input, span)),
            ),
            _ if s.size > 0 => cx.emit(data_node(
                name_or(SECTION, s.kind.into(), "section"),
                span,
                s.size.into(),
            )),
            _ => {}
        }
    }
    Ok(())
}

async fn checksums(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let count = to_u64(data.len()) / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let v = u32_le(&data, crate::bytes::to_usize(i.saturating_mul(4))).unwrap_or(0);
        cx.push(
            Node::new(format!("DEX {i}"))
                .span(span.sub(i.saturating_mul(4), 4))
                .value(crate::formats::binutil::hex(v.into(), 32)),
        )
        .await;
    }
    Ok(())
}

/// DEX files back to back, each 4-aligned; sizes come from their headers.
async fn dex_files(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut offset = 0u64;
    let mut index = 0u32;
    while offset.saturating_add(0x70) <= span.len {
        let head = cx.read(span.sub(offset, 0x24)).await?;
        let size = u64::from(u32_le(&head, 0x20).unwrap_or(0));
        if size < 0x70 {
            break;
        }
        let dex = span.sub(offset, size);
        cx.push(embedded_as(
            format!("DEX {index}"),
            input.nested(dex),
            &super::dex::FORMAT,
        ))
        .await;
        offset = offset
            .saturating_add(size)
            .checked_next_multiple_of(4)
            .unwrap_or(u64::MAX);
        index = index.saturating_add(1);
    }
    Ok(())
}
