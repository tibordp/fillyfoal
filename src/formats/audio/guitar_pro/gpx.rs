//! Guitar Pro 6 `.gpx`: a little sector file system (`BCFS`), usually
//! compressed as a whole (`BCFZ`, see [`crate::codec::bcfz`]).
//!
//! `BCFZ`: the magic, the decoded size (`u32` LE), then the compressed
//! stream; it decodes to a `BCFS` image.
//!
//! `BCFS`: the magic, then 4 KiB sectors counted from the byte after it.
//! Sector 0 is not interpreted (it is not a directory entry). Every other
//! sector either holds file data or starts a directory entry: a `u32` type
//! (1 a directory, 2 a file), a 127-byte NUL-padded name at +4, `u32`
//! fields at +0x84 and +0x88 whose meaning is unknown (0 and 1 in the files
//! seen), the file size at +0x8C, an unknown `u32` at +0x90, and from +0x94
//! the file's data sectors as `u32` indices, ended by 0. The content of a
//! file is its sectors in that order, cut to its size. Sectors claimed as
//! data by an earlier entry are not taken for entries.
//!
//! This is the layout the open GPX readers (alphaTab, TuxGuitar) use; it
//! was checked against a real Guitar Pro 6 file (directory `/`, files
//! `score.gpif`, `misc.xml`, `BinaryStylesheet`, `PartConfiguration`,
//! `LayoutConfiguration` and an empty `*` entry). The files are shown as
//! pieces of the decoded image; `score.gpif` is dissected as GPIF.

use std::collections::BTreeSet;

use crate::bytes::{to_u64, u32_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Head, Input, Probe, content, embedded_as};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const SECTOR: u64 = 0x1000;
/// Data sector indices that fit in an entry sector.
const MAX_SECTORS: u64 = (SECTOR - 0x94) / 4;

fn probe(h: &Head<'_>) -> bool {
    if h.at(0, b"BCFS") {
        return h.len >= 4 + SECTOR;
    }
    h.at(0, b"BCFZ") && u32_le(h.data, 4).is_some_and(|n| n >= 4 + 0x1000)
}

declare_format!(pub FORMAT = "guitar-pro-6", "Guitar Pro 6 score", ["gpx"], "application/x-guitar-pro",
    Probe::Custom(probe), dissect);

const ENTRY_TYPES: EnumTable = &[(1, "directory"), (2, "file")];

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    if head.starts_with(b"BCFZ") {
        let block = cx.block(file.sub(0, 8)).await?;
        let mut f = Fields::emitting(&cx, &block, LE);
        f.ascii("Magic", 4).emit()?;
        let size = f.u32("Decoded size").emit()?;
        let body = file.tail(8);
        cx.emit(content(
            "File system (BCFS)",
            input,
            body,
            Codec::Bcfz { size: u64::from(size) },
            Some(u64::from(size)),
        ));
        cx.annotate(format!("Guitar Pro 6 score, compressed ({size:#x} bytes decoded)"));
        return Ok(());
    }
    bcfs(&cx, input).await
}

struct Entry {
    kind: u32,
    name: String,
    size: u32,
    sectors: Vec<u32>,
}

/// Parses the entry at the start of `block` (a whole sector).
fn entry(f: &mut Fields<'_>, _: &()) -> Result<Entry> {
    let kind = f.u32("Type").enumeration(ENTRY_TYPES).emit()?;
    let name = f.ascii("Name", 127).emit()?;
    f.u8("Padding").emit()?;
    f.u32("Unknown 1").emit()?;
    f.u32("Unknown 2").emit()?;
    let size = f.u32("Size").emit()?;
    f.u32("Unknown 3").emit()?;
    let mut sectors = Vec::new();
    let start = f.pos();
    let mut probe = Fields::new(f.block(), LE);
    probe.seek(start);
    for _ in 0..MAX_SECTORS {
        let s = probe.u32("Sector").get()?;
        if s == 0 {
            break;
        }
        sectors.push(s);
    }
    let len = probe.pos().saturating_sub(start);
    f.node(
        Node::new("Data sectors")
            .span(f.peek_span(len))
            .summary(sector_list(&sectors)),
    );
    f.skip(len);
    Ok(Entry {
        kind,
        name,
        size,
        sectors,
    })
}

fn sector_list(sectors: &[u32]) -> String {
    if sectors.is_empty() {
        return "no data sectors".to_owned();
    }
    let shown: Vec<String> = sectors.iter().take(16).map(u32::to_string).collect();
    let more = if sectors.len() > shown.len() { ", ..." } else { "" };
    format!("{} sectors: {}{more}", sectors.len(), shown.join(", "))
}

async fn bcfs(cx: &Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)).value(Value::Text("BCFS".to_owned())));
    let image = file.tail(4);
    cx.emit(
        Node::new("Sector 0")
            .span(image.sub(0, SECTOR))
            .desc("Not interpreted"),
    );
    let count = image.len.div_ceil(SECTOR);
    let mut claimed: BTreeSet<u32> = BTreeSet::new();
    let mut files = 0u32;
    let mut index = 1u64;
    while index < count {
        let at = index.saturating_mul(SECTOR);
        let this = u32::try_from(index).unwrap_or(u32::MAX);
        index = index.saturating_add(1);
        if claimed.contains(&this) {
            continue;
        }
        let sector = image.sub(at, SECTOR);
        let kind = cx.read(sector.sub(0, 4)).await?;
        let kind = u32_le(&kind, 0).unwrap_or(0);
        if kind != 1 && kind != 2 {
            continue;
        }
        let e = crate::fields::parse(cx, sector, LE, &(), entry).await?;
        claimed.extend(e.sectors.iter().copied());
        let len = 0x94u64.saturating_add(to_u64(e.sectors.len()).saturating_add(1).saturating_mul(4));
        let entry_span = sector.sub(0, len);
        if e.kind == 1 {
            cx.push(
                struct_node(format!("Directory {}", e.name), entry_span, LE, (), entry)
                    .summary(format!("sector {this}")),
            )
            .await;
            continue;
        }
        files = files.saturating_add(1);
        let mut pieces = Vec::with_capacity(e.sectors.len());
        let mut left = u64::from(e.size);
        for &s in &e.sectors {
            if left == 0 {
                break;
            }
            let take = left.min(SECTOR);
            pieces.push(image.sub(u64::from(s).saturating_mul(SECTOR), take));
            left = left.saturating_sub(take);
        }
        let mut node = Node::new(e.name.clone())
            .span(entry_span)
            .summary(format!("{} bytes, {}", e.size, sector_list(&e.sectors)))
            .lazy(file_node, (input, entry_span, pieces, e.name.clone()));
        if left > 0 {
            node = node.diag(Diagnostic::malformed("fewer data sectors than the size needs"));
        }
        cx.push(node).await;
    }
    cx.annotate(format!("Guitar Pro 6 file system, {files} files"));
    Ok(())
}

async fn file_node(cx: Cx, (input, entry_span, pieces, name): (Input, Span, Vec<Span>, String)) -> Result<()> {
    cx.emit(struct_node("Entry", entry_span, LE, (), entry));
    let data = cx.add_pieces(
        Origin {
            parent: entry_span,
            transform: "bcfs-file",
        },
        pieces,
    )?;
    if data.len == 0 {
        cx.emit(Node::new("Content").span(data).summary("empty"));
        return Ok(());
    }
    let inner = input.nested(data);
    cx.emit(if name.ends_with(".gpif") {
        embedded_as("Content", inner, &super::gpif::FORMAT)
    } else {
        Node::new("Content").span(data).lazy(crate::formats::dissect_or_data, inner)
    });
    Ok(())
}
