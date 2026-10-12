//! Bethesda TES3 and TES4+ plugins (`.esm`, `.esp`, `.esl`).
//!
//! TES3 (Morrowind): records with a 16-byte header (type, data size, a
//! reserved word, flags) holding subrecords with 8-byte headers (type,
//! u32 size). TES4 and later (Oblivion, Fallout 3/NV, Skyrim, Fallout 4,
//! Starfield): 20-byte (Oblivion) or 24-byte record headers (type, data
//! size, flags, form ID, version control, and from Fallout 3 the form
//! version), 6-byte subrecord headers (type, u16 size; an `XXXX`
//! subrecord carries the u32 size of the next one), records compressed
//! when flag 0x40000 is set (a u32 decompressed size, then zlib), and
//! `GRUP` groups (whose size includes their header) nesting records and
//! groups. As documented on UESP ("Mod File Format") and implemented by
//! xEdit and esplugin.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt::plural;
use crate::formats::util::{fmt, val};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::text::until_nul;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;

/// Groups nest at most this deep in real plugins (world, block, sub-block,
/// cell, cell children, persistent/temporary); deeper means a loop.
const MAX_DEPTH: u32 = 16;

fn tes_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"TES3") && h.at(16, b"HEDR")
        || h.starts_with(b"TES4") && (h.at(20, b"HEDR") || h.at(24, b"HEDR"))
}

declare_format!(pub TES = "tes-plugin", "Bethesda game plugin (ESM/ESP)", ["esm", "esp", "esl", "omwaddon"], "application/x-tes-plugin",
    Probe::Custom(tes_probe), tes);

/// Header sizes of a plugin's generation.
#[derive(Clone, Copy, Debug)]
struct Layout {
    tes3: bool,
    /// Record (and group) header length: 16, 20 or 24.
    record: u64,
}

impl Layout {
    fn subrecord(&self) -> u64 {
        if self.tes3 { 8 } else { 6 }
    }
}

const TES4_FLAGS: FlagTable = &[
    flag(0x1, "Master"),
    flag(0x20, "Deleted"),
    flag(0x80, "Localized"),
    flag(0x200, "Light master"),
    flag(0x400, "Persistent"),
    flag(0x800, "Initially disabled"),
    flag(0x1000, "Ignored"),
    flag(0x8000, "Visible when distant"),
    flag(0x40000, "Compressed"),
    flag(0x80000, "Can't wait"),
];

const TES3_FLAGS: FlagTable = &[
    flag(0x20, "Deleted"),
    flag(0x400, "Persistent"),
    flag(0x800, "Initially disabled"),
    flag(0x2000, "Blocked"),
];

const COMPRESSED: u32 = 0x40000;

const GROUP_TYPES: EnumTable = &[
    (0, "Top"),
    (1, "World children"),
    (2, "Interior cell block"),
    (3, "Interior cell sub-block"),
    (4, "Exterior cell block"),
    (5, "Exterior cell sub-block"),
    (6, "Cell children"),
    (7, "Topic children"),
    (8, "Cell persistent children"),
    (9, "Cell temporary children"),
    (10, "Cell visible distant children"),
];

fn record_header(f: &mut Fields<'_>, layout: &Layout) -> Result<u32> {
    f.ascii("Type", 4).emit()?;
    f.u32("Data size").emit()?;
    if layout.tes3 {
        f.u32("Reserved").hex().emit()?;
        return f.u32("Flags").flags(TES3_FLAGS).emit();
    }
    let flags = f.u32("Flags").flags(TES4_FLAGS).emit()?;
    f.u32("Form ID").hex().emit()?;
    f.u32("Version control").hex().emit()?;
    if layout.record >= 24 {
        f.u16("Form version").emit()?;
        f.u16("Unknown").hex().emit()?;
    }
    Ok(flags)
}

fn group_header(f: &mut Fields<'_>, layout: &Layout) -> Result<()> {
    f.ascii("Type", 4).emit()?;
    f.u32("Group size").desc("Including this header").emit()?;
    let at = f.pos();
    let label = f.bytes("Label", 4).get()?;
    let kind = f.u32("Group type").get()?;
    f.node(
        Node::new("Label")
            .span(f.block().span.sub(at, 4))
            .value(group_label(kind, &label)),
    );
    f.seek(at.saturating_add(4));
    f.u32("Group type").enumeration(GROUP_TYPES).emit()?;
    f.u32("Stamp").hex().emit()?;
    if layout.record >= 24 {
        f.u32("Unknown").hex().emit()?;
    }
    Ok(())
}

/// A group's label, by its type: a record type, a form ID, a block number
/// or exterior grid coordinates.
fn group_label(kind: u32, label: &[u8]) -> crate::value::Value {
    let word = u32_le(label, 0).unwrap_or(0);
    match kind {
        0 => val::text(String::from_utf8_lossy(label).into_owned()),
        2 | 3 => val::uint(word, 32),
        4 | 5 => val::text(format!(
            "grid ({}, {})",
            u16_le(label, 2).unwrap_or(0) as i16,
            u16_le(label, 0).unwrap_or(0) as i16
        )),
        _ => val::hex(word, 32),
    }
}

fn group_summary(kind: u32, label: &[u8], size: u64) -> String {
    let what = crate::value::lookup(GROUP_TYPES, kind.into()).unwrap_or("group");
    let label = match group_label(kind, label) {
        crate::value::Value::Text(s) => s,
        crate::value::Value::UInt { value, radix, .. } => match radix {
            crate::value::Radix::Hex => format!("{value:08x}"),
            _ => value.to_string(),
        },
        _ => String::new(),
    };
    format!("{what} {label}, {}", fmt::size(size))
}

async fn tes(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 28)).await?;
    let tes3 = head.starts_with(b"TES3");
    let record = if tes3 {
        16
    } else if head.get(20..24) == Some(b"HEDR") {
        20
    } else {
        24
    };
    let layout = Layout { tes3, record };
    let summary = header_summary(&cx, file, layout).await?;
    cx.annotate(format!(
        "{} plugin, {summary}",
        if tes3 {
            "Morrowind"
        } else {
            "Gamebryo/Creation engine"
        }
    ));
    walk(cx, (input, file, layout, 0)).await
}

/// The plugin header's summary: version, record count, author, masters.
async fn header_summary(cx: &Cx, file: Span, layout: Layout) -> Result<String> {
    let h = cx.read(file.sub(0, layout.record)).await?;
    let size = u64::from(u32_le(&h, 4).unwrap_or(0));
    let body = cx
        .read_avail(file.sub(layout.record, size.min(0x1_0000)))
        .await?;
    let mut summary = String::new();
    let mut masters = Vec::new();
    let mut f = Subrecords::new(&body, layout);
    while let Some((id, data, _)) = f.next() {
        match id {
            b"HEDR" => {
                let version = f32::from_bits(u32_le(data, 0).unwrap_or(0));
                let records = if layout.tes3 {
                    u32_le(data, 296)
                } else {
                    u32_le(data, 4)
                }
                .unwrap_or(0);
                if layout.tes3 {
                    summary = format!("{} ", until_nul(data.get(8..40).unwrap_or_default()));
                }
                summary.push_str(&format!(
                    "v{version:.2}, {records_record}",
                    records_record = plural(records, "record")
                ));
            }
            b"CNAM" => summary = format!("{summary} by {}", until_nul(data)),
            b"MAST" => masters.push(until_nul(data)),
            _ => {}
        }
    }
    if !masters.is_empty() {
        summary.push_str(&format!(", masters: {}", masters.join(", ")));
    }
    Ok(summary)
}

/// Subrecords of an in-memory record body: (type, data, offset of the
/// header), following `XXXX` size overrides.
struct Subrecords<'a> {
    data: &'a [u8],
    at: usize,
    layout: Layout,
}

impl<'a> Subrecords<'a> {
    fn new(data: &'a [u8], layout: Layout) -> Self {
        Subrecords {
            data,
            at: 0,
            layout,
        }
    }

    fn next(&mut self) -> Option<(&'a [u8; 4], &'a [u8], usize)> {
        let start = self.at;
        let head = crate::bytes::to_usize(self.layout.subrecord());
        let id: &[u8; 4] = self
            .data
            .get(start..start.checked_add(4)?)?
            .try_into()
            .ok()?;
        let (mut len, mut data_at) = if self.layout.tes3 {
            (
                crate::bytes::to_usize(u32_le(self.data, start.saturating_add(4))?.into()),
                start.saturating_add(head),
            )
        } else {
            (
                usize::from(u16_le(self.data, start.saturating_add(4))?),
                start.saturating_add(head),
            )
        };
        let mut id = id;
        if !self.layout.tes3 && id == b"XXXX" {
            // The next subrecord's size, which its own u16 cannot hold.
            let big = crate::bytes::to_usize(u32_le(self.data, data_at)?.into());
            let next = data_at.saturating_add(len);
            id = self.data.get(next..next.checked_add(4)?)?.try_into().ok()?;
            len = big;
            data_at = next.saturating_add(head);
        }
        let end = data_at.checked_add(len)?;
        let data = self.data.get(data_at..end.min(self.data.len()))?;
        self.at = end;
        Some((id, data, start))
    }
}

/// Records and groups in `region`, back to back.
async fn walk(cx: Cx, (input, region, layout, depth): (Input, Span, Layout, u32)) -> Result<()> {
    let top = depth == 0;
    let mut pos = if top {
        cx.resume::<u64>().unwrap_or(0)
    } else {
        0
    };
    while pos.saturating_add(layout.record) <= region.len {
        if top {
            let at = pos;
            cx.mark(move || at);
        }
        let header = region.sub(pos, layout.record);
        let h = cx.read(header).await?;
        let kind = h.get(..4).unwrap_or_default();
        let size = u64::from(u32_le(&h, 4).unwrap_or(0));
        let group = !layout.tes3 && kind == b"GRUP";
        // Group sizes include their header; record sizes do not.
        let total = if group {
            size
        } else {
            size.saturating_add(layout.record)
        };
        if total < layout.record {
            return Err(Diagnostic::malformed("record size smaller than its header").at(header));
        }
        let span = region.sub(pos, total);
        let name = String::from_utf8_lossy(kind).into_owned();
        let node = if group {
            let label = h.get(8..12).unwrap_or_default();
            let group_type = u32_le(&h, 12).unwrap_or(u32::MAX);
            let node = Node::new(name)
                .span(span)
                .summary(group_summary(group_type, label, size));
            if depth >= MAX_DEPTH {
                node.diag(Diagnostic::malformed("groups nested too deep"))
            } else {
                node.lazy(
                    crate::expander!(self::group: (Input, Span, Layout, u32)),
                    (input, span, layout, depth.saturating_add(1)),
                )
            }
        } else {
            let flags = u32_le(&h, if layout.tes3 { 12 } else { 8 }).unwrap_or(0);
            let mut summary = fmt::size(size);
            if !layout.tes3 {
                summary = format!("{:08x}, {summary}", u32_le(&h, 12).unwrap_or(0));
            }
            if !layout.tes3 && flags & COMPRESSED != 0 {
                summary.push_str(", compressed");
            }
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(record_body, (span, layout))
        };
        if top {
            cx.progress_in(region, region.offset.saturating_add(pos));
        }
        cx.push(node).await;
        pos = pos.saturating_add(total);
    }
    Ok(())
}

async fn group(cx: Cx, (input, span, layout, depth): (Input, Span, Layout, u32)) -> Result<()> {
    cx.emit(struct_node(
        "Group header",
        span.sub(0, layout.record),
        LE,
        layout,
        group_header,
    ));
    walk(cx, (input, span.tail(layout.record), layout, depth)).await
}

/// A record: its header and subrecords, decompressed first if need be.
async fn record_body(cx: Cx, (span, layout): (Span, Layout)) -> Result<()> {
    let header = span.sub(0, layout.record);
    cx.emit(struct_node(
        "Record header",
        header,
        LE,
        layout,
        record_header,
    ));
    let h = cx.read(header).await?;
    let flags = u32_le(&h, if layout.tes3 { 12 } else { 8 }).unwrap_or(0);
    let mut body = span.tail(layout.record);
    if !layout.tes3 && flags & COMPRESSED != 0 {
        let size = cx.read(body.sub(0, 4)).await?;
        let size = u32_le(&size, 0).unwrap_or(0);
        cx.emit(
            Node::new("Decompressed size")
                .span(body.sub(0, 4))
                .value(val::uint(size, 32)),
        );
        let packed = body.tail(4);
        cx.emit(Node::new("Compressed data").span(packed).summary("zlib"));
        let decoded =
            crate::codec::decode_span(&cx, packed, &Codec::Zlib, Some(size.into())).await?;
        if let Some(e) = decoded.error {
            cx.diag(e);
        }
        body = decoded.span;
    }
    subrecords(&cx, body, layout).await
}

/// Text subrecords worth showing as such.
fn texty(data: &[u8]) -> Option<String> {
    let text = data.strip_suffix(&[0]).unwrap_or(data);
    (!text.is_empty()
        && text
            .iter()
            .all(|&b| b == b'\t' || (0x20..0x7f).contains(&b)))
    .then(|| crate::text::latin1(text))
}

async fn subrecords(cx: &Cx, body: Span, layout: Layout) -> Result<()> {
    let data = cx.read(body).await?;
    let mut subs = Subrecords::new(&data, layout);
    while let Some((id, value, start)) = subs.next() {
        let end = subs.at.min(data.len());
        let span = body.sub(to_u64(start), to_u64(end.saturating_sub(start)));
        let mut node = Node::new(String::from_utf8_lossy(id).into_owned()).span(span);
        node = match texty(value) {
            Some(text) => node.value(val::text(text)),
            None => node.summary(fmt::size(to_u64(value.len()))),
        };
        cx.push(node).await;
    }
    if subs.at < data.len() {
        cx.diag(
            Diagnostic::malformed("trailing bytes after the last subrecord")
                .at(body.tail(to_u64(subs.at))),
        );
    }
    Ok(())
}
