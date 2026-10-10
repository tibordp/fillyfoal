//! Unix and CP/M compressors: freeze, compact, squeeze and crunch.

use crate::bytes::u16_le;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::archive::legacy::signature_and_body;
use crate::formats::util::val::{text, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Unix and CP/M compressors: freeze, compact, squeeze, crunch

declare_format!(pub FREEZE = "freeze", "freeze compressed file", ["f", "fz"], "application/x-freeze",
    Probe::Magic(&[(0, b"\x1f\x9f"), (0, b"\x1f\x9e")]), freeze);

async fn freeze(cx: Cx, input: Input) -> Result<()> {
    let head = signature_and_body(&cx, input.span, 2, "Frozen data").await?;
    cx.annotate(if head.get(1) == Some(&0x9f) {
        "freeze 2.x compressed data"
    } else {
        "freeze 1.x compressed data"
    });
    Ok(())
}

declare_format!(pub COMPACT = "compact", "compact (Huffman) compressed file", ["c"], "application/x-compact",
    Probe::Magic(&[(0, b"\x1f\xff")]), compact);

async fn compact(cx: Cx, input: Input) -> Result<()> {
    signature_and_body(&cx, input.span, 2, "Adaptive Huffman data").await?;
    cx.annotate("compact (adaptive Huffman) data");
    Ok(())
}

fn cpm_name(h: &Head<'_>, at: usize) -> bool {
    let name = h.data.get(at..).unwrap_or_default();
    let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    (1..=16).contains(&len)
        && name
            .get(..len)
            .is_some_and(|n| n.iter().all(|b| b.is_ascii_graphic()))
}

fn squeeze_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x76\xff") && cpm_name(h, 4)
}

declare_format!(pub SQUEEZE = "squeeze", "CP/M squeezed file", ["qqq", "sq"], "application/x-squeeze",
    Probe::Custom(squeeze_probe), squeeze);

async fn squeeze(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u16("Magic").hex().emit()?;
    f.u16("Checksum").hex().emit()?;
    let (name, span) = cx.cstr(file.sub(4, 32)).await?;
    cx.emit(
        Node::new("Original name")
            .span(span)
            .value(text(name.clone())),
    );
    let at = span.end().saturating_sub(file.offset);
    let nodes = u64::from(u16_le(&cx.read(file.sub(at, 2)).await?, 0).unwrap_or(0));
    cx.emit(
        Node::new("Huffman tree")
            .span(file.sub(at, nodes.saturating_mul(4).saturating_add(2)))
            .summary(format!("{nodes} nodes")),
    );
    cx.emit(
        Node::new("Squeezed data")
            .span(file.tail(at.saturating_add(2).saturating_add(nodes.saturating_mul(4)))),
    );
    cx.annotate(format!("squeezed {name:?}"));
    Ok(())
}

fn crunch_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x76\xfe") && cpm_name(h, 2)
}

declare_format!(pub CRUNCH = "crunch", "CP/M crunched file", ["zzz", "cr"], "application/x-crunch",
    Probe::Custom(crunch_probe), crunch);

async fn crunch(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Magic").span(file.sub(0, 2)));
    let (name, span) = cx.cstr(file.sub(2, 32)).await?;
    cx.emit(
        Node::new("Original name")
            .span(span)
            .value(text(name.clone())),
    );
    let at = span.end().saturating_sub(file.offset);
    let info = cx.read(file.sub(at, 4)).await?;
    cx.emit(
        Node::new("Reference revision")
            .span(file.sub(at, 1))
            .value(uint(info.first().copied().unwrap_or(0), 8)),
    );
    cx.emit(
        Node::new("Significant revision")
            .span(file.sub(at.saturating_add(1), 1))
            .value(uint(info.get(1).copied().unwrap_or(0), 8)),
    );
    cx.emit(Node::new("Crunched data").span(file.tail(at.saturating_add(4))));
    cx.annotate(format!("crunched {name:?} (LZW)"));
    Ok(())
}
