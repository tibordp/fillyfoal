//! UEFI firmware volumes (PI specification): an `_FVH` header followed by
//! FFS files, each made of sections. PE32 sections are dissected as PE
//! images, nested firmware volume sections as firmware volumes.

use crate::bytes::{align_up, u16_le, u24_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{guid_le, size};
use crate::formats::util::fmt::capitalize;
use crate::formats::{Format, Input, Probe, embedded, embedded_named};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, Value, flag, lookup};

const LE: Endian = Endian::Little;
/// Files or sections listed per container before assuming corruption.
const MAX_ITEMS: u32 = 4096;
/// Section nesting followed (encapsulation sections inside files).
const MAX_DEPTH: u32 = 8;

pub static FORMAT: Format = Format {
    name: "uefi-fv",
    title: "UEFI firmware volume",
    extensions: &["fv", "fd", "rom", "bin"],
    mime: "application/x-uefi-firmware-volume",
    probe: Probe::Magic(&[(40, b"_FVH")]),
    dissect: crate::expander!(dissect: Input),
};

const FILE_SYSTEMS: &[(&str, &str)] = &[
    ("7a9354d9-0468-444a-81ce-0bf617d890df", "FFS v2"),
    ("8c8ce578-8a3d-4f1c-9935-896185c32dd3", "FFS v3"),
    ("fff12b8d-7696-4c8b-a985-2747075b4f50", "NV variable store"),
    ("04adeead-61ff-4d31-b6ba-64f8bf901f5a", "Apple boot volume"),
];

fn fs_name(g: &Guid) -> Option<&'static str> {
    let text = g.to_string();
    let key = text.trim_matches(|c| c == '{' || c == '}');
    FILE_SYSTEMS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, n)| *n)
}

const FV_ATTRIBUTES: FlagTable = &[
    flag(0x1, "READ_DISABLED_CAP"),
    flag(0x2, "READ_ENABLED_CAP"),
    flag(0x4, "READ_STATUS"),
    flag(0x8, "WRITE_DISABLED_CAP"),
    flag(0x10, "WRITE_ENABLED_CAP"),
    flag(0x20, "WRITE_STATUS"),
    flag(0x40, "LOCK_CAP"),
    flag(0x80, "LOCK_STATUS"),
    flag(0x200, "STICKY_WRITE"),
    flag(0x400, "MEMORY_MAPPED"),
    flag(0x800, "ERASE_POLARITY"),
    flag(0x1000, "READ_LOCK_CAP"),
    flag(0x2000, "READ_LOCK_STATUS"),
    flag(0x4000, "WRITE_LOCK_CAP"),
    flag(0x8000, "WRITE_LOCK_STATUS"),
];

record! {
    /// `EFI_FIRMWARE_VOLUME_HEADER`.
    pub struct VolumeHeader {
        zero: bytes[16] "Zero vector",
        file_system: guid "File system GUID" .with(|g, n| match fs_name(g) { Some(s) => n.summary(s), None => n }),
        length: u64 "Volume length" .with(|&v, n| n.summary(size(v))),
        signature: ascii[4] "Signature",
        attributes: u32 "Attributes" .hex() .flags(FV_ATTRIBUTES),
        header_length: u16 "Header length",
        checksum: u16 "Checksum" .hex(),
        ext_header: u16 "Extended header offset" .hex(),
        _reserved: u8 "Reserved",
        revision: u8 "Revision",
    }
}

const FILE_TYPES: EnumTable = &[
    (0x01, "raw"),
    (0x02, "freeform"),
    (0x03, "SEC core"),
    (0x04, "PEI core"),
    (0x05, "DXE core"),
    (0x06, "PEIM"),
    (0x07, "DXE driver"),
    (0x08, "combined PEIM/driver"),
    (0x09, "application"),
    (0x0a, "MM module"),
    (0x0b, "firmware volume image"),
    (0x0c, "combined MM/DXE"),
    (0x0d, "MM core"),
    (0x0e, "MM standalone"),
    (0x0f, "MM core standalone"),
    (0xf0, "pad"),
];

const FILE_ATTRIBUTES: FlagTable = &[
    flag(0x01, "LARGE_FILE"),
    flag(0x02, "DATA_ALIGNMENT_2"),
    flag(0x04, "FIXED"),
    flag(0x40, "CHECKSUM"),
];

record! {
    /// `EFI_FFS_FILE_HEADER`.
    pub struct FileHeader {
        name: guid "Name",
        header_checksum: u8 "Header checksum" .hex(),
        file_checksum: u8 "File checksum" .hex(),
        kind: u8 "Type" .enumeration(FILE_TYPES),
        attributes: u8 "Attributes" .hex() .flags(FILE_ATTRIBUTES),
        size: bytes[3] "Size" .with(|b, n| n.summary(size(u24_le(b, 0).unwrap_or(0).into()))),
        state: u8 "State" .hex(),
    }
}

const SECTION_TYPES: EnumTable = &[
    (0x01, "compression"),
    (0x02, "GUID defined"),
    (0x03, "disposable"),
    (0x10, "PE32"),
    (0x11, "PIC"),
    (0x12, "TE"),
    (0x13, "DXE dependency"),
    (0x14, "version"),
    (0x15, "user interface"),
    (0x16, "compatibility16"),
    (0x17, "firmware volume image"),
    (0x18, "freeform subtype GUID"),
    (0x19, "raw"),
    (0x1b, "PEI dependency"),
    (0x1c, "MM dependency"),
];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let fv = input.span;
    let span = fv.sub(0, VolumeHeader::SIZE);
    let h = parse(&cx, span, LE, &(), VolumeHeader::layout).await?;
    let header_len = u64::from(h.header_length).max(VolumeHeader::SIZE);
    let raw = cx.read_avail(fv.sub(0, header_len)).await?;
    let sum = raw
        .as_chunks::<2>()
        .0
        .iter()
        .fold(0u16, |s, w| s.wrapping_add(u16::from_le_bytes(*w)));
    let mut node = VolumeHeader::node("Volume header", fv.sub(0, header_len), LE);
    if sum != 0 {
        node = node.diag(Diagnostic::warning("header checksum mismatch"));
    }
    cx.emit(node);
    let kind = fs_name(&h.file_system).unwrap_or("unknown file system");
    let volume = fv.sub(0, h.length);
    cx.annotate(format!(
        "UEFI firmware volume ({kind}), {}",
        size(volume.len)
    ));
    // Block map: (count, length) pairs after the fixed header, ending in zeros.
    let map: Vec<String> = raw
        .get(crate::bytes::to_usize(VolumeHeader::SIZE)..)
        .unwrap_or_default()
        .as_chunks::<8>()
        .0
        .iter()
        .map(|e| (u32_le(e, 0).unwrap_or(0), u32_le(e, 4).unwrap_or(0)))
        .take_while(|&(n, l)| n != 0 || l != 0)
        .map(|(n, l)| format!("{n} × {}", size(l.into())))
        .collect();
    cx.emit(
        Node::new("Block map")
            .span(fv.sub(
                VolumeHeader::SIZE,
                header_len.saturating_sub(VolumeHeader::SIZE),
            ))
            .summary(map.join(", ")),
    );
    let mut files_at = header_len;
    if h.ext_header != 0 {
        let ext = fv.sub(h.ext_header.into(), 20);
        let data = cx.read_avail(ext).await?;
        let ext_len = u64::from(u32_le(&data, 16).unwrap_or(20));
        cx.emit(
            Node::new("Extended header")
                .span(fv.sub(h.ext_header.into(), ext_len))
                .value(Value::Guid(guid_le(&data))),
        );
        files_at = u64::from(h.ext_header).saturating_add(ext_len);
    }
    if kind.starts_with("FFS") {
        let files = volume.tail(align_up(files_at, 8));
        let erase = if h.attributes & 0x800 != 0 {
            0xff
        } else {
            0x00
        };
        cx.emit(
            Node::new("Files")
                .span(files)
                .lazy(list_files, (input, files, erase)),
        );
    } else {
        cx.emit(Node::new("Data").span(volume.tail(header_len)));
    }
    Ok(())
}

async fn list_files(cx: Cx, (input, area, erase): (Input, Span, u8)) -> Result<()> {
    let mut at = 0u64;
    let mut count = 0u32;
    while at.saturating_add(FileHeader::SIZE) <= area.len {
        let head_span = area.sub(at, FileHeader::SIZE);
        let raw = cx.read(head_span).await?;
        if raw.iter().all(|&b| b == erase) {
            cx.push(
                Node::new("Free space")
                    .span(area.tail(at))
                    .summary(size(area.len.saturating_sub(at))),
            )
            .await;
            break;
        }
        if count >= MAX_ITEMS {
            cx.diag(Diagnostic::limit("too many files"));
            break;
        }
        let h = parse(&cx, head_span, LE, &(), FileHeader::layout).await?;
        let mut len = u64::from(u24_le(&h.size, 0).unwrap_or(0));
        let mut header_len = FileHeader::SIZE;
        if h.attributes & 0x01 != 0 {
            let ext = cx
                .read(area.sub(at.saturating_add(FileHeader::SIZE), 8))
                .await?;
            len = u64_le(&ext, 0).unwrap_or(0);
            header_len = FileHeader::SIZE.saturating_add(8);
        }
        if len < header_len {
            cx.diag(Diagnostic::malformed("file smaller than its header").at(head_span));
            break;
        }
        let file = area.sub(at, len);
        let kind = lookup(FILE_TYPES, h.kind.into()).unwrap_or("unknown type");
        cx.progress_in(area, area.offset.saturating_add(at));
        cx.push(
            Node::new(h.name.to_string())
                .span(file)
                .summary(format!("{kind}, {}", size(len)))
                .lazy(file_node, (input, file, header_len, h.kind)),
        )
        .await;
        at = align_up(at.saturating_add(len), 8);
        count = count.saturating_add(1);
    }
    Ok(())
}

async fn file_node(cx: Cx, (input, file, header_len, kind): (Input, Span, u64, u8)) -> Result<()> {
    cx.emit(FileHeader::node("File header", file.sub(0, header_len), LE));
    let body = file.tail(header_len);
    match kind {
        // Raw and pad files have no sections.
        0x01 | 0xf0 => cx.emit(Node::new("Data").span(body)),
        _ => sections(cx, (input, body, 0)).await?,
    }
    Ok(())
}

async fn sections(cx: Cx, (input, area, depth): (Input, Span, u32)) -> Result<()> {
    let mut at = 0u64;
    let mut count = 0u32;
    while at.saturating_add(4) <= area.len && count < MAX_ITEMS {
        let raw = cx.read(area.sub(at, 4)).await?;
        let kind = raw.get(3).copied().unwrap_or(0);
        let mut len = u64::from(u24_le(&raw, 0).unwrap_or(0));
        let mut header = 4u64;
        if len == 0xff_ffff {
            let ext = cx.read(area.sub(at.saturating_add(4), 4)).await?;
            len = u32_le(&ext, 0).unwrap_or(0).into();
            header = 8;
        }
        if len < header {
            cx.diag(Diagnostic::malformed("section smaller than its header").at(area.sub(at, 4)));
            break;
        }
        let span = area.sub(at, len);
        let body = span.tail(header);
        let name = lookup(SECTION_TYPES, kind.into())
            .map_or_else(|| format!("Section {kind:#04x}"), capitalize);
        let node = Node::new(name).span(span);
        let node = match kind {
            0x10 => embedded("PE32 image", input.nested(body)).summary(size(body.len)),
            0x11 => embedded("PIC image", input.nested(body)).summary(size(body.len)),
            0x12 => {
                embedded_named("TE image", input.nested(body), "efi-te").summary(size(body.len))
            }
            0x19 => embedded("Raw data", input.nested(body)).summary(size(body.len)),
            0x17 => embedded("Firmware volume", input.nested(body)).summary(size(body.len)),
            0x15 => {
                let text = crate::text::utf16z(&cx.read_avail(body).await?, LE).0;
                node.value(Value::Text(text))
            }
            0x14 => {
                let data = cx.read_avail(body).await?;
                let text = crate::text::utf16z(data.get(2..).unwrap_or_default(), LE).0;
                node.value(Value::Text(text))
                    .summary(format!("build {}", u16_le(&data, 0).unwrap_or(0)))
            }
            0x01 => {
                let data = cx.read_avail(body.sub(0, 5)).await?;
                match data.get(4) {
                    Some(0) if depth < MAX_DEPTH => node.summary("not compressed").lazy(
                        crate::expander!(self::sections: (Input, Span, u32)),
                        (input, body.tail(5), depth.saturating_add(1)),
                    ),
                    Some(t) => node.diag(Diagnostic::unsupported(format!(
                        "compression type {t} ({})",
                        if *t == 1 { "EFI/Tiano" } else { "unknown" }
                    ))),
                    None => node,
                }
            }
            0x02 => {
                let data = cx.read_avail(body.sub(0, 20)).await?;
                let guid = guid_le(&data);
                let offset = u64::from(u16_le(&data, 16).unwrap_or(0)).saturating_sub(header);
                let attributes = u16_le(&data, 18).unwrap_or(0);
                let node = node.summary(guid.to_string());
                // Not processing-required: the content is plain sections.
                if attributes & 1 == 0 && depth < MAX_DEPTH {
                    node.lazy(
                        crate::expander!(self::sections: (Input, Span, u32)),
                        (input, body.tail(offset), depth.saturating_add(1)),
                    )
                } else {
                    node.diag(Diagnostic::unsupported(
                        "encoded GUID-defined section (e.g. LZMA)",
                    ))
                }
            }
            _ => node.summary(size(body.len)),
        };
        cx.push(node).await;
        at = align_up(at.saturating_add(len), 4);
        count = count.saturating_add(1);
    }
    Ok(())
}
