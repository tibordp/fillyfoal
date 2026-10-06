//! Plain MS-DOS executables (`MZ` without a PE/NE/LE header): the header,
//! the relocation table, the load module and any overlay. Reached from the
//! PE dissector.

use crate::bytes::{to_u64, u16_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::binutil::{data_node, hex};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "mz",
    title: "MS-DOS executable",
    extensions: &["exe"],
    mime: "application/x-dosexec",
    probe: Probe::Magic(&[(0, b"MZ")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    struct Header {
        magic: ascii[2] "e_magic",
        cblp: u16 "e_cblp" .desc("Bytes on the last page"),
        cp: u16 "e_cp" .desc("512-byte pages in the file"),
        crlc: u16 "e_crlc" .desc("Relocation count"),
        cparhdr: u16 "e_cparhdr" .desc("Header size in paragraphs"),
        minalloc: u16 "e_minalloc" .desc("Minimum extra paragraphs"),
        maxalloc: u16 "e_maxalloc" .desc("Maximum extra paragraphs"),
        ss: u16 "e_ss" .hex(),
        sp: u16 "e_sp" .hex(),
        csum: u16 "e_csum" .hex(),
        ip: u16 "e_ip" .hex(),
        cs: u16 "e_cs" .hex(),
        lfarlc: u16 "e_lfarlc" .hex() .desc("File offset of the relocation table"),
        ovno: u16 "e_ovno" .desc("Overlay number"),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    cx.emit(Header::node("DOS Header", hspan, LE));
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    let header_size = u64::from(h.cparhdr).saturating_mul(16);
    let image_size = if h.cblp == 0 {
        u64::from(h.cp).saturating_mul(512)
    } else {
        u64::from(h.cp).saturating_sub(1).saturating_mul(512).saturating_add(h.cblp.into())
    };
    let module = file.sub(header_size, image_size.saturating_sub(header_size));
    cx.annotate(format!(
        "MS-DOS executable, {:#x}-byte load module, {} relocations, entry {:04X}:{:04X}, stack {:04X}:{:04X}",
        module.len, h.crlc, h.cs, h.ip, h.ss, h.sp
    ));
    if h.crlc > 0 {
        let table = file.sub(h.lfarlc.into(), u64::from(h.crlc).saturating_mul(4));
        cx.emit(
            Node::new("Relocation Table")
                .span(table)
                .summary(format!("{} entries", h.crlc))
                .lazy(relocations, (table, module)),
        );
    }
    let entry = u64::from(h.cs).saturating_mul(16).saturating_add(h.ip.into());
    cx.emit(
        data_node("Load Module", module, image_size.saturating_sub(header_size))
            .summary(format!("entry at module offset {entry:#x}"))
            .target(module.sub(entry, 0)),
    );
    if image_size < file.len && image_size > header_size {
        cx.emit(
            Node::new("Overlay")
                .span(file.tail(image_size))
                .lazy(crate::formats::dissect_or_data, input.nested(file.tail(image_size)))
                .summary(format!("{:#x} bytes after the load module", file.len.saturating_sub(image_size))),
        );
    }
    Ok(())
}

async fn relocations(cx: Cx, (table, module): (Span, Span)) -> Result<()> {
    let data = cx.read_avail(table).await?;
    let count = to_u64(data.len()) / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = crate::bytes::to_usize(i.saturating_mul(4));
        let offset = u16_le(&data, at).unwrap_or(0);
        let segment = u16_le(&data, at.saturating_add(2)).unwrap_or(0);
        let linear = u64::from(segment).saturating_mul(16).saturating_add(offset.into());
        cx.push(
            Node::new(format!("{segment:04X}:{offset:04X}"))
                .span(table.sub(i.saturating_mul(4), 4))
                .value(hex(linear, 32))
                .target(module.sub(linear, 2)),
        )
        .await;
    }
    Ok(())
}
