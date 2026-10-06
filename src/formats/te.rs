//! UEFI Terse Executables (`VZ`): PE images with the DOS and NT headers
//! replaced by a 40-byte header, used for PEI modules in firmware volumes.
//!
//! Section headers keep their PE layout; file offsets in them still count
//! the stripped headers, so they are adjusted by `StrippedSize - 40`.

use crate::bytes::u16_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::util::binutil::{data_node, name_or};
use crate::formats::pe::tables::{MACHINE, SECTION_CHARACTERISTICS, SUBSYSTEM};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::lookup;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "efi-te",
    title: "UEFI Terse Executable",
    extensions: &["te", "efi"],
    mime: "application/octet-stream",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let machine = u16_le(h.data, 2).unwrap_or(0);
    let sections = h.data.get(4).copied().unwrap_or(0);
    let subsystem = h.data.get(5).copied().unwrap_or(0);
    h.starts_with(b"VZ")
        && matches!(
            machine,
            0x14c | 0x8664 | 0x1c2 | 0x1c4 | 0xaa64 | 0x200 | 0xebc | 0x5064 | 0x6264
        )
        && (1..=32).contains(&sections)
        && (10..=13).contains(&subsystem)
}

record! {
    struct TeHeader {
        signature: ascii[2] "Signature",
        machine: u16 "Machine" .enumeration(MACHINE),
        sections: u8 "NumberOfSections",
        subsystem: u8 "Subsystem" .enumeration(SUBSYSTEM),
        stripped: u16 "StrippedSize" .hex() .desc("Bytes of PE headers removed"),
        entry: u32 "AddressOfEntryPoint" .hex(),
        code: u32 "BaseOfCode" .hex(),
        base: u64 "ImageBase" .hex(),
        reloc_rva: u32 "BaseRelocation.VirtualAddress" .hex(),
        reloc_size: u32 "BaseRelocation.Size" .hex(),
        debug_rva: u32 "Debug.VirtualAddress" .hex(),
        debug_size: u32 "Debug.Size" .hex(),
    }
}

record! {
    struct SectionHeader {
        name: ascii[8] "Name",
        virtual_size: u32 "VirtualSize" .hex(),
        virtual_address: u32 "VirtualAddress" .hex(),
        raw_size: u32 "SizeOfRawData" .hex(),
        raw_pointer: u32 "PointerToRawData" .hex() .desc("Counts the stripped headers"),
        relocations: u32 "PointerToRelocations" .hex(),
        linenumbers: u32 "PointerToLinenumbers" .hex(),
        nrelocs: u16 "NumberOfRelocations",
        nlines: u16 "NumberOfLinenumbers",
        characteristics: u32 "Characteristics" .flags(SECTION_CHARACTERISTICS),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, TeHeader::SIZE);
    cx.emit(TeHeader::node("TE Header", hspan, LE));
    let h = parse(&cx, hspan, LE, &(), TeHeader::layout).await?;
    cx.annotate(format!(
        "UEFI TE image, {}, {}, entry {:#x}, {} sections",
        lookup(MACHINE, h.machine.into()).unwrap_or("unknown machine"),
        name_or(SUBSYSTEM, h.subsystem.into(), "subsystem"),
        h.entry,
        h.sections
    ));
    let delta = u64::from(h.stripped).saturating_sub(TeHeader::SIZE);
    let table = file.sub(
        TeHeader::SIZE,
        u64::from(h.sections).saturating_mul(SectionHeader::SIZE),
    );
    cx.emit(
        Node::new("Section Table")
            .span(table)
            .summary(format!("{} sections", h.sections))
            .lazy(sections, (file, table, delta)),
    );
    Ok(())
}

async fn sections(cx: Cx, (file, table, delta): (Span, Span, u64)) -> Result<()> {
    let count = table.len / SectionHeader::SIZE;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = table.sub(i.saturating_mul(SectionHeader::SIZE), SectionHeader::SIZE);
        let s = parse(&cx, at, LE, &(), SectionHeader::layout).await?;
        let offset = u64::from(s.raw_pointer).saturating_sub(delta);
        let data = file.sub(offset, s.raw_size.into());
        cx.push(
            Node::new(if s.name.is_empty() {
                format!("[{i}]")
            } else {
                s.name.clone()
            })
            .span(at)
            .summary(format!(
                "VA {:#x}+{:#x}, file {offset:#x}+{:#x}",
                s.virtual_address, s.virtual_size, s.raw_size
            ))
            .target(data)
            .lazy(section, (at, data, s.raw_size)),
        )
        .await;
    }
    Ok(())
}

async fn section(cx: Cx, (at, data, size): (Span, Span, u32)) -> Result<()> {
    cx.emit(SectionHeader::node("Header", at, LE));
    cx.emit(data_node("Raw Data", data, size.into()));
    Ok(())
}
