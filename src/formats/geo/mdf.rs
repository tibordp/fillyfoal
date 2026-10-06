//! ASAM MDF (Measurement Data Format) 3.x and 4.x, the measurement files of
//! automotive data loggers and calibration tools.
//!
//! A 64-byte identification block is followed by a graph of blocks joined
//! by links (file offsets). The header block points at a chain of data
//! groups, each with channel groups, each with channels. Chains (`next`
//! links) are shown as lists; other links expand to the block they point
//! to. Cycles and excessive depth are cut off with `dsl::Path`.

use std::borrow::Cow;

use super::{hex, leaf, text, uint};
use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Path, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;
const MAX_DEPTH: usize = 24;
/// Longest chain listed (data groups, channels, …).
const MAX_CHAIN: usize = 1 << 20;

declare_format!(pub MDF = "mdf", "ASAM MDF measurement data", ["mf4", "mdf", "dat"], "application/x-asam-mdf",
    Probe::Custom(|h| h.starts_with(b"MDF     ") && h.data.get(8).is_some_and(u8::is_ascii_digit)), mdf);

record! {
    pub struct IdBlock {
        file_id: ascii[8] "File identifier",
        format_id: ascii[8] "Format identifier",
        program: ascii[8] "Program identifier",
        byte_order: u16 "Byte order (MDF 3) / reserved",
        float_format: u16 "Float format (MDF 3) / reserved",
        version: u16 "Version number",
        code_page: u16 "Code page (MDF 3.30)",
        _reserved: bytes[28] "Reserved",
        unfinalized: u16 "Standard unfinalized flags" .hex(),
        custom: u16 "Custom unfinalized flags" .hex(),
    }
}

/// What the walk needs to know about the file.
#[derive(Clone, Copy)]
struct Mdf {
    file: Span,
    v4: bool,
}

/// Link names per block type, MDF 4.
fn links4(id: &[u8]) -> &'static [&'static str] {
    match id {
        b"HD" => &[
            "dg_first",
            "fh_first",
            "ch_first",
            "at_first",
            "ev_first",
            "md_comment",
        ],
        b"FH" => &["fh_next", "md_comment"],
        b"DG" => &["dg_next", "cg_first", "data", "md_comment"],
        b"CG" => &[
            "cg_next",
            "cn_first",
            "tx_acq_name",
            "si_acq_source",
            "sr_first",
            "md_comment",
            "cg_master",
        ],
        b"CN" => &[
            "cn_next",
            "composition",
            "tx_name",
            "si_source",
            "cc_conversion",
            "data",
            "md_unit",
            "md_comment",
        ],
        b"CC" => &["tx_name", "md_unit", "md_comment", "cc_inverse"],
        b"SI" => &["tx_name", "tx_path", "md_comment"],
        b"AT" => &["at_next", "tx_filename", "tx_mimetype", "md_comment"],
        b"EV" => &["ev_next", "ev_parent", "ev_range", "tx_name", "md_comment"],
        b"CH" => &["ch_next", "ch_first", "tx_name", "md_comment"],
        b"DL" => &["dl_next"],
        b"HL" => &["dl_first"],
        b"SR" => &["sr_next", "data"],
        _ => &[],
    }
}

/// Link names per block type, MDF 3 (32-bit links).
fn links3(id: &[u8]) -> &'static [&'static str] {
    match id {
        b"HD" => &["dg_first", "tx_comment", "pr_program"],
        b"DG" => &["dg_next", "cg_first", "tr_trigger", "data"],
        b"CG" => &["cg_next", "cn_first", "tx_comment"],
        b"CN" => &[
            "cn_next",
            "cc_conversion",
            "ce_extension",
            "cd_dependency",
            "tx_comment",
        ],
        _ => &[],
    }
}

fn block_title(id: &[u8]) -> &'static str {
    match id {
        b"HD" => "Header",
        b"FH" => "File history",
        b"DG" => "Data group",
        b"CG" => "Channel group",
        b"CN" => "Channel",
        b"CC" => "Conversion",
        b"SI" => "Source information",
        b"AT" => "Attachment",
        b"EV" => "Event",
        b"CH" => "Channel hierarchy",
        b"TX" => "Text",
        b"MD" => "Metadata",
        b"DT" => "Data",
        b"DZ" => "Compressed data",
        b"DL" => "Data list",
        b"HL" => "Header list",
        b"SR" => "Sample reduction",
        b"SD" => "Signal data",
        b"RD" => "Reduction data",
        b"PR" => "Program",
        b"TR" => "Trigger",
        b"CE" => "Extension",
        b"CD" => "Dependency",
        _ => "Block",
    }
}

/// A parsed block header.
struct Block {
    id: [u8; 2],
    span: Span,
    links: Vec<u64>,
    /// Where the data section starts (relative to the block).
    data: u64,
}

async fn read_block(cx: &Cx, m: Mdf, offset: u64) -> Result<Block> {
    if m.v4 {
        let h = cx.read(m.file.sub_exact(offset, 24)?).await?;
        if h.get(..2) != Some(b"##") {
            return Err(
                Diagnostic::malformed(format!("no block at {offset:#x}")).at(m.file.sub(offset, 4))
            );
        }
        let id = [
            h.get(2).copied().unwrap_or(0),
            h.get(3).copied().unwrap_or(0),
        ];
        let len = u64_le(&h, 8).unwrap_or(0);
        let count = u64_le(&h, 16).unwrap_or(0);
        let span = m.file.sub_exact(offset, len)?;
        let links_len = count
            .checked_mul(8)
            .filter(|&l| l.saturating_add(24) <= len)
            .ok_or_else(|| Diagnostic::malformed("too many links").at(span.sub(16, 8)))?;
        let raw = cx.read(span.sub(24, links_len)).await?;
        let links = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
            .collect();
        Ok(Block {
            id,
            span,
            links,
            data: 24u64.saturating_add(links_len),
        })
    } else {
        let h = cx.read(m.file.sub_exact(offset, 4)?).await?;
        let id = [
            h.first().copied().unwrap_or(0),
            h.get(1).copied().unwrap_or(0),
        ];
        if !id.iter().all(u8::is_ascii_uppercase) {
            return Err(
                Diagnostic::malformed(format!("no block at {offset:#x}")).at(m.file.sub(offset, 4))
            );
        }
        let len = u64::from(u16_le(&h, 2).unwrap_or(0));
        let span = m.file.sub_exact(offset, len.max(4))?;
        let n = to_u64(links3(&id).len());
        let raw = cx.read(span.sub(4, n.saturating_mul(4))).await?;
        let links = raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u64::from(u32::from_le_bytes(*c)))
            .collect();
        Ok(Block {
            id,
            span,
            links,
            data: 4u64.saturating_add(n.saturating_mul(4)),
        })
    }
}

/// Text of a TX/MD block (MDF 4) or TX block (MDF 3), capped.
async fn block_text(cx: &Cx, m: Mdf, offset: u64) -> Option<String> {
    if offset == 0 {
        return None;
    }
    let b = read_block(cx, m, offset).await.ok()?;
    if &b.id != b"TX" && &b.id != b"MD" {
        return None;
    }
    let raw = cx.read(b.span.sub(b.data, 4096)).await.ok()?;
    let t = crate::text::until_nul(&raw);
    Some(t.trim().chars().take(200).collect())
}

/// A one-line description of a block.
async fn describe(cx: &Cx, m: Mdf, b: &Block) -> Option<String> {
    let link = |name: &str| {
        let names = if m.v4 { links4(&b.id) } else { links3(&b.id) };
        names
            .iter()
            .position(|n| *n == name)
            .and_then(|i| b.links.get(i))
            .copied()
            .unwrap_or(0)
    };
    let data = cx.read(b.span.sub(b.data, 256)).await.ok()?;
    match (&b.id, m.v4) {
        (b"CN", true) => block_text(cx, m, link("tx_name")).await,
        (b"CN", false) => Some(
            crate::text::until_nul(data.get(2..34).unwrap_or_default())
                .trim()
                .to_owned(),
        ),
        (b"CG", true) => {
            let cycles = u64_le(&data, 8).unwrap_or(0);
            let name = block_text(cx, m, link("tx_acq_name"))
                .await
                .map(|n| format!("{n}, "))
                .unwrap_or_default();
            Some(format!("{name}{cycles} records"))
        }
        (b"CG", false) => Some(format!(
            "{} channels, {} records of {} bytes",
            u16_le(&data, 2).unwrap_or(0),
            u32_le(&data, 6).unwrap_or(0),
            u16_le(&data, 4).unwrap_or(0)
        )),
        (b"TX" | b"MD", _) => block_text(cx, m, b.span.offset.saturating_sub(m.file.offset)).await,
        (b"AT", true) => block_text(cx, m, link("tx_filename")).await,
        (b"EV", true) => block_text(cx, m, link("tx_name")).await,
        _ => None,
    }
}

async fn mdf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let id: IdBlock = read_record(&cx, file.sub(0, IdBlock::SIZE), LE).await?;
    cx.emit(IdBlock::node("Identification block", file.sub(0, 64), LE));
    let m = Mdf {
        file,
        v4: id.version >= 400,
    };
    if !m.v4 && id.byte_order != 0 {
        cx.diag(Diagnostic::unsupported(
            "big-endian MDF 3 file; blocks not decoded",
        ));
        return Ok(());
    }
    let node = block_node(&cx, m, 64, Path::new()).await;
    cx.emit(node);
    let program = id.program.trim().to_owned();
    cx.annotate(format!(
        "MDF {}{}",
        id.format_id.trim(),
        if program.is_empty() {
            String::new()
        } else {
            format!(", written by {program}")
        }
    ));
    Ok(())
}

/// A lazy node for the block at `offset`.
async fn block_node(cx: &Cx, m: Mdf, offset: u64, path: Path) -> Node {
    match read_block(cx, m, offset).await {
        Ok(b) => {
            let name = format!(
                "{} ({})",
                block_title(&b.id),
                String::from_utf8_lossy(&b.id)
            );
            let mut node = Node::new(name).span(b.span);
            if let Some(d) = describe(cx, m, &b).await.filter(|d| !d.is_empty()) {
                node = node.summary(d);
            }
            match path.enter(offset, MAX_DEPTH) {
                Ok(child) => node.lazy(
                    crate::expander!(self::block: (Mdf, u64, Path)),
                    (m, offset, child),
                ),
                Err(e) => node.diag(e),
            }
        }
        Err(e) => Node::new(format!("Block at {offset:#x}")).diag(e),
    }
}

async fn block(cx: Cx, (m, offset, path): (Mdf, u64, Path)) -> Result<()> {
    let b = read_block(&cx, m, offset).await?;
    let names = if m.v4 { links4(&b.id) } else { links3(&b.id) };
    let width = if m.v4 { 8 } else { 4 };
    let link_base = if m.v4 { 24 } else { 4 };
    cx.emit(leaf(
        "Block type",
        b.span.sub(0, if m.v4 { 4 } else { 2 }),
        text(String::from_utf8_lossy(&b.id)),
    ));
    cx.emit(leaf(
        "Length",
        b.span
            .sub(if m.v4 { 8 } else { 2 }, if m.v4 { 8 } else { 2 }),
        uint(b.span.len, 64),
    ));
    for (i, &target) in b.links.iter().enumerate() {
        let at = b.span.sub(
            to_u64(i).saturating_mul(width).saturating_add(link_base),
            width,
        );
        let name: Cow<'static, str> = names
            .get(i)
            .map_or_else(|| Cow::Owned(format!("link {i}")), |n| Cow::Borrowed(*n));
        if target == 0 {
            continue;
        }
        let node = if name.ends_with("_first") {
            Node::new(name)
                .span(at)
                .value(hex(target, 64))
                .target(m.file.sub(target, 1))
                .lazy(
                    crate::expander!(self::chain: (Mdf, u64, Path)),
                    (m, target, path.clone()),
                )
        } else if name.ends_with("_next") {
            // Chains are listed by the parent.
            leaf(name, at, hex(target, 64)).target(m.file.sub(target, 1))
        } else {
            let mut n = block_node(&cx, m, target, path.clone()).await;
            n.name = Cow::Owned(format!("{name} → {}", n.name));
            n
        };
        cx.emit(node);
    }
    let data = b.span.tail(b.data);
    match &b.id {
        b"TX" | b"MD" => {
            let raw = cx.read(data.sub(0, 1 << 16)).await?;
            cx.emit(crate::formats::text::text_node(
                "Text",
                data,
                &crate::text::until_nul(&raw),
            ));
        }
        b"HD" if m.v4 => {
            let r = cx.read(data.sub(0, 16)).await?;
            let ns = u64_le(&r, 0).unwrap_or(0);
            cx.emit(
                leaf(
                    "Start time",
                    data.sub(0, 8),
                    Value::Timestamp {
                        unix_seconds: i64::try_from(ns / 1_000_000_000).unwrap_or(0),
                    },
                )
                .summary(format!("{ns} ns")),
            );
            cx.emit(Node::new("Header data").span(data.tail(8)));
        }
        b"HD" => {
            emit_record::<Hd3>(&cx, data.sub(0, Hd3::SIZE), LE).await?;
        }
        b"CN" if !m.v4 => {
            emit_record::<Cn3>(&cx, data.sub(0, Cn3::SIZE), LE).await?;
        }
        b"CN" => {
            emit_record::<Cn4>(&cx, data.sub(0, Cn4::SIZE), LE).await?;
        }
        b"CG" if !m.v4 => {
            emit_record::<Cg3>(&cx, data.sub(0, Cg3::SIZE), LE).await?;
        }
        b"CG" => {
            emit_record::<Cg4>(&cx, data.sub(0, Cg4::SIZE), LE).await?;
        }
        b"DT" | b"SD" | b"RD" => cx.emit(
            Node::new("Records")
                .span(data)
                .summary(format!("{} bytes", data.len)),
        ),
        b"DZ" => cx.emit(
            Node::new("Compressed data")
                .span(data)
                .diag(Diagnostic::unsupported("DZ block data not decompressed")),
        ),
        _ => {
            if data.len > 0 {
                cx.emit(Node::new("Block data").span(data));
            }
        }
    }
    Ok(())
}

/// Lists a chain of blocks joined by their first (`next`) link.
async fn chain(cx: Cx, (m, first, path): (Mdf, u64, Path)) -> Result<()> {
    let mut seen = Vec::new();
    let mut offset = first;
    while offset != 0 && seen.len() < MAX_CHAIN {
        if seen.contains(&offset) {
            cx.diag(Diagnostic::malformed(format!(
                "chain loops back to {offset:#x}"
            )));
            break;
        }
        seen.push(offset);
        let next = match read_block(&cx, m, offset).await {
            Ok(b) => b.links.first().copied().unwrap_or(0),
            Err(e) => {
                cx.push(Node::new(format!("Block at {offset:#x}")).diag(e))
                    .await;
                break;
            }
        };
        let node = block_node(&cx, m, offset, path.clone()).await;
        cx.push(node).await;
        offset = next;
    }
    Ok(())
}

record! {
    pub struct Hd3 {
        groups: u16 "Data groups",
        date: ascii[10] "Date",
        time: ascii[8] "Time",
        author: ascii[32] "Author",
        organization: ascii[32] "Organization",
        project: ascii[32] "Project",
        subject: ascii[32] "Subject",
    }
}

record! {
    pub struct Cg3 {
        record_id: u16 "Record ID",
        channels: u16 "Channels",
        record_size: u16 "Record size",
        records: u32 "Records",
    }
}

record! {
    pub struct Cn3 {
        kind: u16 "Channel type" .enumeration(&[(0, "data"), (1, "time")]),
        name: ascii[32] "Short name",
        description: ascii[128] "Description",
        start_bit: u16 "Start bit",
        bits: u16 "Number of bits",
        data_type: u16 "Data type" .enumeration(&[(0, "unsigned"), (1, "signed"), (2, "float"), (3, "double"), (7, "string"), (8, "byte array")]),
        range_valid: u16 "Value range valid",
        min: f64 "Minimum",
        max: f64 "Maximum",
        rate: f64 "Sampling rate (s)",
    }
}

record! {
    pub struct Cg4 {
        record_id: u64 "Record ID",
        cycles: u64 "Cycle count",
        flags: u16 "Flags" .hex(),
        path_separator: u16 "Path separator",
        _reserved: u32 "Reserved",
        data_bytes: u32 "Data bytes",
        invalidation_bytes: u32 "Invalidation bytes",
    }
}

record! {
    pub struct Cn4 {
        kind: u8 "Channel type" .enumeration(&[(0, "fixed length"), (1, "variable length"), (2, "master"), (3, "virtual master"), (4, "synchronization"), (5, "maximum length"), (6, "virtual data")]),
        sync: u8 "Sync type" .enumeration(&[(0, "none"), (1, "time"), (2, "angle"), (3, "distance"), (4, "index")]),
        data_type: u8 "Data type" .enumeration(&[(0, "unsigned LE"), (1, "unsigned BE"), (2, "signed LE"), (3, "signed BE"), (4, "float LE"), (5, "float BE"), (6, "string Latin-1"), (7, "string UTF-8"), (10, "byte array")]),
        bit_offset: u8 "Bit offset",
        byte_offset: u32 "Byte offset",
        bits: u32 "Bit count",
        flags: u32 "Flags" .hex(),
        invalidation_bit: u32 "Invalidation bit position",
        precision: u8 "Precision",
        _reserved: u8 "Reserved",
        attachments: u16 "Attachments",
        min: f64 "Value range minimum",
        max: f64 "Value range maximum",
    }
}
