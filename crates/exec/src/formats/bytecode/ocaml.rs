//! OCaml bytecode executables (`ocamlc` output): usually a `#!ocamlrun`
//! line, then sections, a section table and the `Caml1999X0nn` magic at the
//! very end. Primitive and DLL lists are decoded; marshalled sections are
//! shown with their spans.

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::binutil::data_node;
use crate::formats::util::fmt::clip;
use crate::formats::util::val::text;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "ocaml-bytecode",
    title: "OCaml bytecode executable",
    extensions: &["byte", "bc", "cmo"],
    mime: "application/x-ocaml-bytecode",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let n = h.tail.len();
    n >= 16
        && h.tail
            .get(n.saturating_sub(12)..)
            .is_some_and(|t| t.starts_with(b"Caml1999X"))
}

const SECTION: EnumTable = &[
    (u32::from_be_bytes(*b"CODE") as u64, "bytecode"),
    (
        u32::from_be_bytes(*b"DATA") as u64,
        "global data (marshalled)",
    ),
    (u32::from_be_bytes(*b"PRIM") as u64, "primitive names"),
    (u32::from_be_bytes(*b"DLLS") as u64, "shared libraries"),
    (
        u32::from_be_bytes(*b"DLPT") as u64,
        "shared library search path",
    ),
    (
        u32::from_be_bytes(*b"SYMB") as u64,
        "global symbols (marshalled)",
    ),
    (
        u32::from_be_bytes(*b"CRCS") as u64,
        "interface CRCs (marshalled)",
    ),
    (
        u32::from_be_bytes(*b"DBUG") as u64,
        "debug info (marshalled)",
    ),
    (u32::from_be_bytes(*b"RNTM") as u64, "runtime path"),
];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let end = file.len;
    let magic_span = file.sub(end.saturating_sub(12), 12);
    let magic = cx.read(magic_span).await?;
    let count_span = file.sub(end.saturating_sub(16), 4);
    let count = u32_be(&cx.read(count_span).await?, 0).unwrap_or(0);
    let table = file.sub_exact(
        end.saturating_sub(16)
            .saturating_sub(u64::from(count).saturating_mul(8)),
        u64::from(count).saturating_mul(8),
    )?;
    let entries = cx.read(table).await?;
    let mut lengths: Vec<([u8; 4], u64)> = Vec::new();
    for i in 0..crate::bytes::to_usize(count.into()) {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let at = i.saturating_mul(8);
        let mut id = [0u8; 4];
        id.copy_from_slice(entries.get(at..at.saturating_add(4)).unwrap_or(&[0; 4]));
        lengths.push((
            id,
            u32_be(&entries, at.saturating_add(4)).unwrap_or(0).into(),
        ));
    }
    let total: u64 = lengths.iter().fold(0u64, |a, (_, l)| a.saturating_add(*l));
    let table_start = table.offset.saturating_sub(file.offset);
    let Some(mut offset) = table_start.checked_sub(total) else {
        return Err(Diagnostic::malformed("sections are larger than the file").at(table));
    };
    let version = String::from_utf8_lossy(magic.get(9..).unwrap_or_default()).into_owned();
    if offset > 0 {
        let head = cx.read_avail(file.sub(0, offset.min(256))).await?;
        let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
        cx.emit(
            Node::new("Header")
                .span(file.sub(0, offset))
                .value(text(String::from_utf8_lossy(line).into_owned()))
                .desc("Launcher: a #! line or a small native executable"),
        );
    }
    let mut prims = 0usize;
    let mut nodes = Vec::new();
    for (id, len) in &lengths {
        cx.checkpoint().await;
        let span = file.sub(offset, *len);
        let name = String::from_utf8_lossy(id).into_owned();
        let what =
            crate::value::lookup(SECTION, u32::from_be_bytes(*id).into()).unwrap_or("section");
        let node = Node::new(name.clone())
            .span(span)
            .summary(format!("{what}, {len:#x} bytes"));
        let node = match id {
            b"PRIM" | b"DLLS" | b"DLPT" => {
                if id == b"PRIM" {
                    let data = cx.read_avail(span.sub(0, 0x10_0000)).await?;
                    prims = data.iter().filter(|&&b| b == 0).count();
                }
                node.lazy(names, span)
            }
            b"CODE" => node.lazy(code, span),
            b"RNTM" => {
                let data = cx.read_avail(span.sub(0, 4096)).await?;
                node.value(text(crate::text::until_nul(&data)))
            }
            _ => node,
        };
        nodes.push(node);
        offset = offset.saturating_add(*len);
    }
    // The summary shows at most 80 characters, and each ID takes at least
    // two (with its separator): 41 IDs are always enough.
    let ids: Vec<String> = lengths
        .iter()
        .take(41)
        .map(|(id, _)| String::from_utf8_lossy(id).into_owned())
        .collect();
    cx.annotate(format!(
        "OCaml bytecode executable (format {version}), sections {}, {prims} primitives",
        clip(&ids.join(" "), 80)
    ));
    for n in nodes {
        cx.checkpoint().await;
        cx.emit(n);
    }
    cx.emit(
        Node::new("Section Table")
            .span(table)
            .summary(format!("{count} sections")),
    );
    cx.emit(
        Node::new("Section Count")
            .span(count_span)
            .value(crate::formats::util::val::uint(count, 32)),
    );
    cx.emit(
        Node::new("Magic")
            .span(magic_span)
            .value(text(String::from_utf8_lossy(&magic).into_owned())),
    );
    Ok(())
}

async fn names(cx: Cx, span: Span) -> Result<()> {
    crate::formats::util::binutil::cstrings(cx, span).await
}

async fn code(cx: Cx, span: Span) -> Result<()> {
    let words = span.len / 4;
    cx.emit(data_node("Instructions", span, span.len).summary(format!("{words} words")));
    Ok(())
}
