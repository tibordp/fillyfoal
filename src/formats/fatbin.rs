//! NVIDIA CUDA fat binaries (`.fatbin`, and the `.nv_fatbin` section of
//! CUDA executables): a header and entries holding PTX source or cubin ELF
//! images for each GPU architecture. Uncompressed cubins are dissected as
//! ELF.

use crate::bytes::{u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::binutil::{data_node, text};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "cuda-fatbin",
    title: "CUDA fat binary",
    extensions: &["fatbin"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| h.starts_with(b"\x50\xed\x55\xba") && u16_le(h.data, 6) == Some(16)),
    dissect: crate::expander!(dissect: Input),
};

const KIND: EnumTable = &[(1, "PTX"), (2, "ELF (cubin)"), (4, "Mercury (nvvm IR)")];

const FLAGS: FlagTable = &[
    flag(0x1, "64-bit"),
    flag(0x2, "debug"),
    flag(0x10, "linux"),
    flag(0x20, "mac"),
    flag(0x40, "windows"),
    flag(0x2000, "compressed (LZ4)"),
];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("magic").hex().emit()?;
    f.u16("version").emit()?;
    let header_size = f.u16("header size").emit()?;
    let size = f.u64("fat size").hex().emit()?;
    let body = file.sub(header_size.into(), size);
    let mut at = 0u64;
    let mut archs = Vec::new();
    let mut entries = Vec::new();
    while at.saturating_add(64) <= body.len {
        let data = cx.read(body.sub(at, 64)).await?;
        let kind = u16_le(&data, 0).unwrap_or(0);
        let hsize = u64::from(u32_le(&data, 4).unwrap_or(0));
        let payload = u64_le(&data, 8).unwrap_or(0);
        let flags = u64_le(&data, 40).unwrap_or(0);
        let arch = u32_le(&data, 28).unwrap_or(0);
        if hsize < 64 {
            break;
        }
        let header = body.sub(at, hsize);
        let content = body.sub(at.saturating_add(hsize), payload);
        archs.push(format!(
            "sm_{arch} {}",
            if kind == 1 { "PTX" } else { "SASS" }
        ));
        entries.push((header, content, kind, flags, arch));
        at = at.saturating_add(hsize).saturating_add(payload);
        cx.checkpoint().await;
    }
    cx.annotate(format!(
        "CUDA fat binary, {} entries: {}",
        entries.len(),
        archs.join(", ")
    ));
    for (header, content, kind, flags, arch) in entries {
        let label = format!(
            "{} sm_{arch}",
            crate::formats::binutil::name_or(KIND, kind.into(), "kind")
        );
        cx.emit(
            Node::new(label)
                .span(Span::new(
                    header.source,
                    header.offset,
                    content.end().saturating_sub(header.offset),
                ))
                .summary(format!("{:#x} bytes", content.len))
                .lazy(entry, (input, header, content, kind, flags)),
        );
    }
    Ok(())
}

async fn entry(
    cx: Cx,
    (input, header, content, kind, flags): (Input, Span, Span, u16, u64),
) -> Result<()> {
    let block = cx.block(header.sub(0, 64)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u16("kind").enumeration(KIND).emit()?;
    f.u16("unknown").emit()?;
    f.u32("header size").emit()?;
    f.u64("size").hex().emit()?;
    f.u32("compressed size").hex().emit()?;
    f.u32("unknown").emit()?;
    f.u16("minor version").emit()?;
    f.u16("major version").emit()?;
    f.u32("arch")
        .with(|&v, n| n.summary(format!("sm_{v}")))
        .emit()?;
    f.u32("name offset").hex().emit()?;
    f.u32("name length").emit()?;
    f.u64("flags").flags(FLAGS).emit()?;
    f.u64("zero").emit()?;
    f.u64("uncompressed size").hex().emit()?;
    let node = if flags & 0x2000 != 0 {
        data_node("Compressed payload", content, content.len)
    } else if kind == 1 {
        let ptx = cx.read_avail(content.sub(0, 0x10_0000)).await?;
        Node::new("PTX")
            .span(content)
            .value(text(crate::text::until_nul(&ptx)))
    } else {
        embedded("Cubin", input.nested(content))
    };
    cx.emit(node);
    Ok(())
}
