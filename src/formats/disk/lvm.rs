//! LVM2 physical volumes.
//!
//! A label (`LABELONE`) in one of the first four sectors leads to the PV
//! header, which lists data and metadata areas. The metadata area holds the
//! volume group description as text; logical volumes whose segments live on
//! this PV are assembled (piecewise, if they have several segments) and
//! dissected.

use std::sync::Arc;

use crate::bytes::{to_u64, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{assemble, coalesce, size};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;
const SECTOR: u64 = 512;
const MDA_MAGIC: &[u8] = b"\x20LVM2\x20x[5A%r0N*>";
/// Largest metadata text we read.
const MAX_TEXT: u64 = 1 << 20;
/// Area descriptors read before giving up.
const MAX_AREAS: usize = 16;

pub static FORMAT: Format = Format {
    name: "lvm2",
    title: "LVM2 physical volume",
    extensions: &["img", "lvm"],
    mime: "application/x-lvm2",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn label_sector(data: &[u8]) -> Option<u64> {
    (0..4u64).find(|&s| {
        let at = crate::bytes::to_usize(s.saturating_mul(SECTOR));
        data.get(at..at.saturating_add(8)) == Some(b"LABELONE")
            && data.get(at.saturating_add(24)..at.saturating_add(32)) == Some(b"LVM2 001")
    })
}

fn probe(h: &Head<'_>) -> bool {
    label_sector(h.data).is_some()
}

record! {
    pub struct Label {
        id: ascii[8] "Identifier",
        sector: u64 "Sector",
        crc: u32 "CRC" .hex(),
        offset: u32 "PV header offset",
        kind: ascii[8] "Type",
    }
}

record! {
    pub struct PvHeader {
        uuid: ascii[32] "PV UUID" .with(|u, n| n.value(Value::Text(dashed(u)))),
        device_size: u64 "Device size" .with(|&v, n| n.summary(size(v))),
    }
}

record! {
    pub struct Area {
        offset: u64 "Offset" .hex(),
        len: u64 "Size" .with(|&v, n| n.summary(size(v))),
    }
}

record! {
    pub struct MdaHeader {
        checksum: u32 "Checksum" .hex(),
        magic: bytes[16] "Magic",
        version: u32 "Version",
        start: u64 "Start" .hex(),
        len: u64 "Size" .with(|&v, n| n.summary(size(v))),
    }
}

record! {
    pub struct RawLocation {
        offset: u64 "Offset" .hex(),
        len: u64 "Size",
        checksum: u32 "Checksum" .hex(),
        flags: u32 "Flags" .hex(),
    }
}

/// LVM's CRC: CRC-32 polynomial, initial value 0xf597a6cf, no inversion.
fn lvm_crc(data: &[u8]) -> u32 {
    crate::formats::disk::crc32_update(0xf597_a6cf, data)
}

/// LVM UUIDs are 32 characters shown in groups 6-4-4-4-4-4-6.
fn dashed(u: &str) -> String {
    let mut out = String::new();
    for (i, c) in u.chars().enumerate() {
        if matches!(i, 6 | 10 | 14 | 18 | 22 | 26) {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// Reads a zero-terminated list of `(offset, size)` area descriptors.
fn areas(data: &[u8], mut at: usize) -> (Vec<(u64, u64)>, usize) {
    let mut out = Vec::new();
    while let (Some(offset), Some(len)) = (u64_le(data, at), u64_le(data, at.saturating_add(8))) {
        at = at.saturating_add(16);
        if offset == 0 && len == 0 || out.len() >= MAX_AREAS {
            break;
        }
        out.push((offset, len));
    }
    (out, at)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let pv = input.span;
    let head = cx.read_avail(pv.sub(0, 4 * SECTOR)).await?;
    let sector = label_sector(&head).ok_or_else(|| Diagnostic::malformed("no LVM2 label"))?;
    let label_at = sector.saturating_mul(SECTOR);
    let label_span = pv.sub(label_at, Label::SIZE);
    let label = parse(&cx, label_span, LE, &(), Label::layout).await?;
    let mut label_node = Label::node("Label", label_span, LE);
    let sector_bytes = head
        .get(crate::bytes::to_usize(label_at)..)
        .and_then(|s| s.get(20..512))
        .unwrap_or_default();
    if lvm_crc(sector_bytes) != label.crc {
        label_node = label_node.diag(Diagnostic::warning("label CRC mismatch"));
    }
    cx.emit(label_node);

    let header_at = label_at.saturating_add(label.offset.into());
    let header_span = pv.sub(header_at, PvHeader::SIZE);
    let header = parse(&cx, header_span, LE, &(), PvHeader::layout).await?;
    cx.emit(PvHeader::node("PV header", header_span, LE));
    let rest = cx.read_avail(pv.sub(header_at, 512)).await?;
    let (data_areas, next) = areas(&rest, crate::bytes::to_usize(PvHeader::SIZE));
    let (meta_areas, _) = areas(&rest, next);
    for (i, &(offset, len)) in data_areas.iter().enumerate() {
        cx.emit(
            Node::new(format!("Data area {}", i.saturating_add(1)))
                .span(pv.sub(
                    offset,
                    if len == 0 {
                        pv.len.saturating_sub(offset)
                    } else {
                        len
                    },
                ))
                .summary(format!("physical extents from {offset:#x}")),
        );
    }

    let mut vg = None;
    for (i, &(offset, len)) in meta_areas.iter().enumerate() {
        let area = pv.sub(offset, len);
        let mda_span = area.sub(0, MdaHeader::SIZE);
        let mda = parse(&cx, mda_span, LE, &(), MdaHeader::layout).await?;
        let name = format!("Metadata area {}", i.saturating_add(1));
        if mda.magic != MDA_MAGIC {
            cx.emit(
                Node::new(name)
                    .span(area)
                    .diag(Diagnostic::malformed("bad metadata area magic")),
            );
            continue;
        }
        let loc_span = area.sub(MdaHeader::SIZE, RawLocation::SIZE);
        let loc = parse(&cx, loc_span, LE, &(), RawLocation::layout).await?;
        let text_span = area.sub(loc.offset, loc.len.min(MAX_TEXT));
        let text = crate::text::until_nul(&cx.read_avail(text_span).await?);
        let config = Arc::new(parse_config(&text));
        let vg_name = config.first().map(|(k, _)| k.clone()).unwrap_or_default();
        cx.emit(
            Node::new(name)
                .span(area)
                .summary(format!("volume group \"{vg_name}\""))
                .lazy(metadata_area, (area, text_span)),
        );
        if vg.is_none() {
            vg = Some(config);
        }
    }
    let uuid = dashed(&header.uuid);
    let Some(config) = vg else {
        cx.annotate(format!(
            "LVM2 physical volume {uuid}, {}",
            size(header.device_size)
        ));
        return Ok(());
    };
    let Some((vg_name, Val::Section(vg_items))) = config.first() else {
        return Ok(());
    };
    cx.annotate(format!(
        "LVM2 physical volume of volume group \"{vg_name}\", {}",
        size(header.device_size)
    ));
    let extent = get(vg_items, "extent_size").and_then(Val::int).unwrap_or(0);
    // Which PV name in the metadata is this device, and where its extents start.
    let pvs = get(vg_items, "physical_volumes")
        .map(Val::items)
        .unwrap_or_default();
    let this = pvs.iter().find(|(_, v)| {
        get(v.items(), "id")
            .and_then(Val::str)
            .is_some_and(|id| id == uuid)
    });
    let Some((pv_name, pv_val)) = this else {
        cx.diag(Diagnostic::warning(
            "this PV is not listed in its volume group",
        ));
        return Ok(());
    };
    let pe_start = get(pv_val.items(), "pe_start")
        .and_then(Val::int)
        .unwrap_or(0);
    let lvs = get(vg_items, "logical_volumes")
        .map(Val::items)
        .unwrap_or_default();
    for (lv_name, lv) in lvs {
        cx.checkpoint().await;
        let node = logical_volume(&cx, &input, lv_name, lv, pv_name, pe_start, extent);
        cx.emit(node);
    }
    Ok(())
}

/// Assembles a logical volume from its segments on this PV.
fn logical_volume(
    cx: &Cx,
    input: &Input,
    name: &str,
    lv: &Val,
    pv_name: &str,
    pe_start: u64,
    extent: u64,
) -> Node {
    let title = format!("Logical volume \"{name}\"");
    let extent_bytes = extent.saturating_mul(SECTOR);
    let pv = input.span;
    let mut segments: Vec<(u64, u64, u64)> = Vec::new();
    for (key, seg) in lv.items() {
        if !key.starts_with("segment") || !matches!(seg, Val::Section(_)) {
            continue;
        }
        let items = seg.items();
        let start = get(items, "start_extent").and_then(Val::int).unwrap_or(0);
        let count = get(items, "extent_count").and_then(Val::int).unwrap_or(0);
        let kind = get(items, "type").and_then(Val::str).unwrap_or("");
        let stripes = get(items, "stripes").map(Val::list).unwrap_or_default();
        let on_this = stripes.first().and_then(Val::str) == Some(pv_name);
        let pe = stripes.get(1).and_then(Val::int);
        match (kind, stripes.len(), on_this, pe) {
            ("striped", 2, true, Some(pe)) => segments.push((start, count, pe)),
            ("striped", 2, false, _) => {
                return Node::new(title).diag(Diagnostic::unsupported(
                    "logical volume spans other physical volumes",
                ));
            }
            _ => {
                return Node::new(title).diag(Diagnostic::unsupported(format!(
                    "segment type \"{kind}\" (only linear segments are assembled)"
                )));
            }
        }
    }
    segments.sort_unstable();
    let mut pieces = Vec::new();
    let mut next = 0u64;
    for (start, count, pe) in segments {
        if start != next {
            return Node::new(title).diag(Diagnostic::malformed("segments leave a gap"));
        }
        let at = pe_start
            .saturating_mul(SECTOR)
            .saturating_add(pe.saturating_mul(extent_bytes));
        pieces.push(pv.sub(at, count.saturating_mul(extent_bytes)));
        next = start.saturating_add(count);
    }
    let pieces = coalesce(pieces, u64::MAX);
    let count = pieces.len();
    let Some(&anchor) = pieces.first() else {
        return Node::new(title).diag(Diagnostic::note("no segments on this PV"));
    };
    match assemble(cx, anchor, "lvm-segments", pieces) {
        Ok(span) if count == 1 => embedded(title, input.nested(span)).summary(size(span.len)),
        Ok(span) => embedded(title, input.nested(span))
            .summary(format!("{}, {count} segments", size(span.len))),
        Err(e) => Node::new(title).diag(e),
    }
}

async fn metadata_area(cx: Cx, (area, text): (Span, Span)) -> Result<()> {
    cx.emit(MdaHeader::node("Header", area.sub(0, MdaHeader::SIZE), LE));
    cx.emit(RawLocation::node(
        "Raw location",
        area.sub(MdaHeader::SIZE, RawLocation::SIZE),
        LE,
    ));
    let data = cx.read_avail(text).await?;
    let content = crate::text::until_nul(&data);
    cx.emit(
        Node::new("Metadata text")
            .span(text.sub(0, to_u64(content.len())))
            .value(Value::Text(content)),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The LVM metadata language: `key = value`, `name { ... }`, `[a, b]`.

#[derive(Clone, Debug)]
pub enum Val {
    Str(String),
    Int(u64),
    List(Vec<Val>),
    Section(Vec<(String, Val)>),
}

impl Val {
    fn int(&self) -> Option<u64> {
        match self {
            Val::Int(v) => Some(*v),
            _ => None,
        }
    }
    fn str(&self) -> Option<&str> {
        match self {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }
    fn list(&self) -> &[Val] {
        match self {
            Val::List(v) => v,
            _ => &[],
        }
    }
    fn items(&self) -> &[(String, Val)] {
        match self {
            Val::Section(v) => v,
            _ => &[],
        }
    }
}

fn get<'a>(items: &'a [(String, Val)], key: &str) -> Option<&'a Val> {
    items.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Parses metadata text into its top-level items. Malformed input yields
/// whatever parsed before the problem.
pub fn parse_config(text: &str) -> Vec<(String, Val)> {
    let mut p = Parser {
        s: text.as_bytes(),
        at: 0,
        budget: 100_000,
    };
    p.section(0)
}

struct Parser<'a> {
    s: &'a [u8],
    at: usize,
    budget: u32,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.at).copied()
    }

    fn bump(&mut self) {
        self.at = self.at.saturating_add(1);
    }

    fn skip_space(&mut self) {
        while let Some(c) = self.peek() {
            if c == b'#' {
                while self.peek().is_some_and(|c| c != b'\n') {
                    self.bump();
                }
            } else if c.is_ascii_whitespace() {
                self.bump();
            } else {
                break;
            }
        }
    }

    fn word(&mut self) -> String {
        let start = self.at;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'+'))
        {
            self.bump();
        }
        String::from_utf8_lossy(self.s.get(start..self.at).unwrap_or_default()).into_owned()
    }

    fn section(&mut self, depth: u32) -> Vec<(String, Val)> {
        let mut items = Vec::new();
        loop {
            self.budget = self.budget.saturating_sub(1);
            self.skip_space();
            if self.budget == 0 || self.peek().is_none_or(|c| c == b'}') {
                break;
            }
            let key = self.word();
            if key.is_empty() {
                break;
            }
            self.skip_space();
            match self.peek() {
                Some(b'{') if depth < 32 => {
                    self.bump();
                    let inner = self.section(depth.saturating_add(1));
                    self.skip_space();
                    if self.peek() == Some(b'}') {
                        self.bump();
                    }
                    items.push((key, Val::Section(inner)));
                }
                Some(b'=') => {
                    self.bump();
                    match self.value(depth) {
                        Some(v) => items.push((key, v)),
                        None => break,
                    }
                }
                _ => break,
            }
        }
        items
    }

    fn value(&mut self, depth: u32) -> Option<Val> {
        self.budget = self.budget.saturating_sub(1);
        self.skip_space();
        match self.peek()? {
            b'"' => {
                self.bump();
                let start = self.at;
                while self.peek().is_some_and(|c| c != b'"') {
                    if self.peek() == Some(b'\\') {
                        self.bump();
                    }
                    self.bump();
                }
                let text = String::from_utf8_lossy(self.s.get(start..self.at).unwrap_or_default())
                    .into_owned();
                self.bump();
                Some(Val::Str(text))
            }
            b'[' if depth < 32 && self.budget > 0 => {
                self.bump();
                let mut list = Vec::new();
                loop {
                    self.skip_space();
                    match self.peek()? {
                        b']' => {
                            self.bump();
                            break;
                        }
                        b',' => self.bump(),
                        _ => list.push(self.value(depth.saturating_add(1))?),
                    }
                }
                Some(Val::List(list))
            }
            c if c.is_ascii_digit() => self.word().parse().ok().map(Val::Int),
            _ => None,
        }
    }
}
