//! R serialization (RDS/RData) and ASDF files.

use crate::bytes::{to_u64, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::val::text;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::value::{EnumTable, Value};

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Data: R serialization (RDS/RData), ASDF

fn r_probe(h: &Head<'_>) -> bool {
    (h.starts_with(b"X\n\0\0\0\x02") || h.starts_with(b"X\n\0\0\0\x03"))
        || ((h.starts_with(b"RDX2\n") || h.starts_with(b"RDX3\n")) && h.at(5, b"X\n"))
}

declare_format!(pub R_DATA = "r-serialized", "R serialized data (RDS/RData)", ["rds", "rdata", "rda"], "application/x-r-data",
    Probe::Custom(r_probe), r_data);

const SEXP_TYPES: EnumTable = &[
    (0, "NULL"),
    (1, "symbol"),
    (2, "pairlist"),
    (3, "closure"),
    (4, "environment"),
    (6, "language"),
    (10, "logical vector"),
    (13, "integer vector"),
    (14, "double vector"),
    (15, "complex vector"),
    (16, "character vector"),
    (19, "list"),
    (20, "expression vector"),
    (24, "raw vector"),
    (25, "S4 object"),
];

async fn r_data(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let rdata =
        cx.read(file.sub(0, 4)).await? == b"RDX2" || cx.read(file.sub(0, 4)).await? == b"RDX3";
    let mut at = 0u64;
    if rdata {
        cx.emit(Node::new("RData signature").span(file.sub(0, 5)));
        at = 5;
    }
    let body = file.tail(at);
    let head = cx.block(body.sub(0, 14)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Format (XDR)", 2).emit()?;
    let version = f.u32("Serialization version").emit()?;
    let writer = f.u32("Written by R").emit()?;
    f.u32("Minimum reader R").emit()?;
    let mut pos = 14u64;
    if version == 3 {
        let l = u64::from(u32_be(&cx.read(body.sub(pos, 4)).await?, 0).unwrap_or(0));
        let enc =
            String::from_utf8_lossy(&cx.read(body.sub(pos.saturating_add(4), l.min(64))).await?)
                .into_owned();
        cx.emit(
            Node::new("Native encoding")
                .span(body.sub(pos, l.saturating_add(4)))
                .value(text(enc)),
        );
        pos = pos.saturating_add(4).saturating_add(l);
    }
    let flags = u32_be(&cx.read(body.sub(pos, 4)).await?, 0).unwrap_or(0);
    let kind = flags & 0xff;
    let name = SEXP_TYPES
        .iter()
        .find(|(k, _)| *k == u64::from(kind))
        .map(|(_, v)| *v);
    cx.emit(
        Node::new("Top-level object")
            .span(body.tail(pos))
            .value(Value::Enum {
                raw: kind.into(),
                bits: 8,
                name,
            })
            .summary(format!("flags {flags:#x}")),
    );
    cx.annotate(format!(
        "R {} (serialization v{version}, R {}.{}.{}), top level {}",
        if rdata {
            "workspace (RData)"
        } else {
            "object (RDS)"
        },
        writer >> 16,
        (writer >> 8) & 0xff,
        writer & 0xff,
        name.unwrap_or("unknown type")
    ));
    Ok(())
}

declare_format!(pub ASDF = "asdf", "Advanced Scientific Data Format", ["asdf"], "application/x-asdf",
    Probe::Magic(&[(0, b"#ASDF ")]), asdf);

async fn asdf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1 << 20)).await?;
    let first = head.iter().position(|&b| b == b'\n').unwrap_or(0);
    let version = String::from_utf8_lossy(head.get(6..first).unwrap_or_default()).into_owned();
    // The YAML tree ends with "...\n"; binary blocks follow (magic \xd3BLK).
    let tree_end = head
        .windows(5)
        .position(|w| w == b"\n...\n")
        .map_or(to_u64(head.len()), |p| to_u64(p).saturating_add(5));
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, to_u64(first)))
            .value(text(version.clone())),
    );
    let yaml_at = head
        .windows(5)
        .position(|w| w == b"%YAML")
        .map_or(0, to_u64);
    cx.emit(embedded(
        "Tree (YAML)",
        input.nested(file.sub(yaml_at, tree_end.saturating_sub(yaml_at))),
    ));
    let mut pos = tree_end;
    let mut blocks = 0u32;
    while pos.saturating_add(6) <= file.len {
        cx.progress(pos, file.len);
        let h = cx.read(file.sub(pos, 6)).await?;
        if !h.starts_with(b"\xd3BLK") {
            break;
        }
        let header_len = u64::from(u16_be(&h, 4).unwrap_or(0));
        let b = cx
            .read(file.sub_exact(pos.saturating_add(6), header_len.min(48))?)
            .await?;
        let compression = String::from_utf8_lossy(b.get(4..8).unwrap_or_default())
            .trim_end_matches('\0')
            .to_owned();
        let allocated = u64_be(&b, 8).unwrap_or(0);
        let used = u64_be(&b, 16).unwrap_or(0);
        let data = file.sub(pos.saturating_add(6).saturating_add(header_len), used);
        let node = Node::new(format!("Block {blocks}"))
            .span(file.sub(
                pos,
                6u64.saturating_add(header_len).saturating_add(allocated),
            ))
            .summary(format!(
                "{used} bytes{}",
                if compression.is_empty() {
                    String::new()
                } else {
                    format!(", {compression}")
                }
            ));
        cx.push(if compression.is_empty() {
            node
        } else {
            node.diag(Diagnostic::note(format!(
                "{compression}-compressed: {data:?}"
            )))
        })
        .await;
        blocks = blocks.saturating_add(1);
        pos = pos
            .saturating_add(6)
            .saturating_add(header_len)
            .saturating_add(allocated);
    }
    cx.annotate(format!("ASDF {version}, {blocks} binary blocks"));
    Ok(())
}
