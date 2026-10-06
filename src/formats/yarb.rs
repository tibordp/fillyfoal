//! Ruby YARV instruction sequence binaries (`YARB`, from
//! `RubyVM::InstructionSequence#to_binary`, as cached by Bootsnap): the
//! header, the platform string and the instruction sequence and global
//! object lists.

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::binutil::{data_node, text};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "yarb",
    title: "Ruby YARV bytecode",
    extensions: &["yarb", "rbbin"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| h.starts_with(b"YARB") && u32_le(h.data, 4).is_some_and(|v| (2..=4).contains(&v))),
    dissect: crate::expander!(dissect: Input),
};

record! {
    struct Header {
        magic: ascii[4] "magic",
        major: u32 "major_version",
        minor: u32 "minor_version",
        size: u32 "size" .hex(),
        extra_size: u32 "extra_size" .hex(),
        iseqs: u32 "iseq_list_size",
        objects: u32 "global_object_list_size",
        iseq_offset: u32 "iseq_list_offset" .hex(),
        object_offset: u32 "global_object_list_offset" .hex(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    cx.emit(Header::node("Header", hspan, LE));
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    let (platform, at) = cx.cstr(file.sub(Header::SIZE, 256)).await?;
    cx.emit(Node::new("platform").span(at).value(text(platform.clone())));
    cx.annotate(format!(
        "Ruby {}.{} YARV bytecode ({platform}), {} instruction sequences, {} objects",
        h.major, h.minor, h.iseqs, h.objects
    ));
    let iseqs = file.sub(h.iseq_offset.into(), u64::from(h.iseqs).saturating_mul(4));
    cx.emit(
        Node::new("Instruction Sequence List")
            .span(iseqs)
            .lazy(offsets, (file, iseqs, "iseq")),
    );
    let objects = file.sub(h.object_offset.into(), u64::from(h.objects).saturating_mul(4));
    cx.emit(
        Node::new("Global Object List")
            .span(objects)
            .lazy(offsets, (file, objects, "object")),
    );
    if h.extra_size > 0 {
        let extra = file.sub(h.size.into(), h.extra_size.into());
        cx.emit(data_node("Extra Data", extra, h.extra_size.into()));
    }
    Ok(())
}

async fn offsets(cx: Cx, (file, span, kind): (Span, Span, &'static str)) -> Result<()> {
    let data = cx.read(span).await?;
    let count = to_u64(data.len()) / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let off = u32_le(&data, crate::bytes::to_usize(i.saturating_mul(4))).unwrap_or(0);
        cx.push(
            Node::new(format!("{kind} {i}"))
                .span(span.sub(i.saturating_mul(4), 4))
                .value(crate::formats::binutil::hex(off.into(), 32))
                .target(file.sub(off.into(), 0)),
        )
        .await;
    }
    Ok(())
}
