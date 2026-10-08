//! HDF4 (Hierarchical Data Format version 4) files, including the
//! netCDF-style scientific datasets the SD interface writes.
//!
//! After the magic `0e 03 13 01`, a chain of data descriptor (DD) blocks
//! indexes every object in the file: each block is a count (u16), the offset
//! of the next block (u32, 0 at the end) and that many 12-byte descriptors
//! (tag, reference number, offset, length; all big-endian). An object is
//! named by its (tag, ref) pair; empty slots have tag 1 (`DFTAG_NULL`).
//! Tags with bit 0x4000 set are "special" elements whose data is a header
//! describing where the real data lives: compressed (the bytes are a
//! `DFTAG_COMPRESSED` object), linked blocks (`DFTAG_LINKED` tables and
//! blocks), an external file, or chunks.
//!
//! On top of that, vgroups (`DFTAG_VG`: a list of member tag/ref pairs, a
//! name and a class) and vdatas (`DFTAG_VH` header + `DFTAG_VS` records)
//! build the object model. The SD interface stores each dataset as a
//! vgroup of class `Var0.0` holding the dimension record (`DFTAG_SDD`),
//! number type (`DFTAG_NT`), data (`DFTAG_SD`), dimension vgroups
//! (`Dim0.0`) and attributes (vdatas of class `Attr0.0`); file attributes
//! hang off the `CDF0.0` vgroup.
//!
//! Tag numbers, the DD layout, the vgroup/vdata header layouts and the
//! compressed and linked-block special headers are from memory of the HDF4
//! library, checked against files written by pyhdf (HDF 4.3.0). The tail of
//! a vdata header (after the class) was worked out from those files: the
//! expansion tag/ref, then the version and "more" fields twice for version
//! 3 headers, with flags and attribute references in between for version 4.
//! Raster images and annotations follow the same memory of the format, with
//! only synthetic fixtures.

use super::numarray::{Array, Elem, num};
use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::Input;
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Radix, Value, lookup};
use std::collections::BTreeMap;
use std::sync::Arc;

const BE: Endian = Endian::Big;

const TAGS: EnumTable = &[
    (1, "DFTAG_NULL (empty)"),
    (20, "DFTAG_LINKED (linked block)"),
    (30, "DFTAG_VERSION (library version)"),
    (40, "DFTAG_COMPRESSED (compressed data)"),
    (50, "DFTAG_VLINKED (variable-length linked block)"),
    (51, "DFTAG_VLINKED_DATA"),
    (60, "DFTAG_CHUNKED (chunk table)"),
    (61, "DFTAG_CHUNK (chunk)"),
    (100, "DFTAG_FID (file label)"),
    (101, "DFTAG_FD (file description)"),
    (102, "DFTAG_TID (tag identifier)"),
    (103, "DFTAG_TD (tag description)"),
    (104, "DFTAG_DIL (data label)"),
    (105, "DFTAG_DIA (data annotation)"),
    (106, "DFTAG_NT (number type)"),
    (107, "DFTAG_MT (machine type)"),
    (108, "DFTAG_FREE (free space)"),
    (200, "DFTAG_ID8 (8-bit image dimensions)"),
    (201, "DFTAG_IP8 (8-bit palette)"),
    (202, "DFTAG_RI8 (8-bit raster image)"),
    (203, "DFTAG_CI8 (RLE-compressed 8-bit image)"),
    (204, "DFTAG_II8 (IMCOMP 8-bit image)"),
    (300, "DFTAG_ID (image dimensions)"),
    (301, "DFTAG_LUT (lookup table)"),
    (302, "DFTAG_RI (raster image)"),
    (303, "DFTAG_CI (compressed image)"),
    (304, "DFTAG_NRI (new raster image)"),
    (306, "DFTAG_RIG (raster image group)"),
    (307, "DFTAG_LD (lookup table dimensions)"),
    (308, "DFTAG_MD (matte dimensions)"),
    (309, "DFTAG_MA (matte data)"),
    (310, "DFTAG_CCN (color correction)"),
    (311, "DFTAG_CFM (color format)"),
    (312, "DFTAG_AR (aspect ratio)"),
    (400, "DFTAG_DRAW (draw)"),
    (401, "DFTAG_RUN (run)"),
    (500, "DFTAG_XYP (x-y position)"),
    (501, "DFTAG_MTO (machine-type override)"),
    (602, "DFTAG_T14 (Tektronix 4014)"),
    (603, "DFTAG_T105 (Tektronix 4105)"),
    (700, "DFTAG_SDG (scientific data group)"),
    (701, "DFTAG_SDD (scientific data dimensions)"),
    (702, "DFTAG_SD (scientific data)"),
    (703, "DFTAG_SDS (scales)"),
    (704, "DFTAG_SDL (labels)"),
    (705, "DFTAG_SDU (units)"),
    (706, "DFTAG_SDF (formats)"),
    (707, "DFTAG_SDM (maximum/minimum)"),
    (708, "DFTAG_SDC (coordinate system)"),
    (709, "DFTAG_SDT (transpose)"),
    (710, "DFTAG_SDLNK (SDS link)"),
    (720, "DFTAG_NDG (numeric data group)"),
    (731, "DFTAG_CAL (calibration)"),
    (732, "DFTAG_FV (fill value)"),
    (780, "DFTAG_EREQ"),
    (781, "DFTAG_SDRAG"),
    (799, "DFTAG_BREQ"),
    (1962, "DFTAG_VH (vdata header)"),
    (1963, "DFTAG_VS (vdata records)"),
    (1965, "DFTAG_VG (vgroup)"),
];

const SPECIAL: u16 = 0x4000;

fn tag_name(tag: u16) -> String {
    let base = tag & !SPECIAL;
    let name = lookup(TAGS, base.into()).map_or_else(|| format!("tag {base}"), str::to_owned);
    if tag & SPECIAL != 0 && base != 0 {
        format!("{name}, special")
    } else {
        name
    }
}

fn short_tag(tag: u16) -> String {
    let base = tag & !SPECIAL;
    lookup(TAGS, base.into())
        .and_then(|n| n.split(' ').next())
        .map_or_else(|| format!("tag {base}"), str::to_owned)
}

const NUMBER_TYPES: EnumTable = &[
    (3, "uchar8"),
    (4, "char8"),
    (5, "float32"),
    (6, "float64"),
    (20, "int8"),
    (21, "uint8"),
    (22, "int16"),
    (23, "uint16"),
    (24, "int32"),
    (25, "uint32"),
    (26, "int64"),
    (27, "uint64"),
];

/// Element type and byte order of an HDF number type (`DFNT_*`, with the
/// 0x4000 little-endian and 0x1000 native flags).
fn number_type(code: u16) -> Option<(Elem, Endian)> {
    let endian = if code & 0x4000 != 0 {
        Endian::Little
    } else {
        BE
    };
    let elem = match code & 0xff {
        3 => Elem::U8,
        4 => Elem::Char,
        5 => Elem::F32,
        6 => Elem::F64,
        20 => Elem::I8,
        21 => Elem::U8,
        22 => Elem::I16,
        23 => Elem::U16,
        24 => Elem::I32,
        25 => Elem::U32,
        26 => Elem::I64,
        27 => Elem::U64,
        _ => return None,
    };
    Some((elem, endian))
}

fn type_label(code: u16) -> String {
    lookup(NUMBER_TYPES, (code & 0xff).into()).map_or_else(
        || format!("type {code:#x}"),
        |n| {
            if code & 0x4000 != 0 {
                format!("{n} (little-endian)")
            } else {
                n.to_owned()
            }
        },
    )
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

fn hex(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Hex,
    }
}

// ---------------------------------------------------------------------------
// The DD index and the object model

#[derive(Clone, Copy, Debug)]
struct Dd {
    tag: u16,
    reference: u16,
    offset: u32,
    length: u32,
    /// Offset of the descriptor itself.
    at: u64,
}

impl Dd {
    fn is_empty(&self) -> bool {
        self.tag == 1 || self.tag == 0
    }

    /// The object's data, or `None` for "no data" descriptors (offset and
    /// length all ones or zero length).
    fn data(&self, file: Span) -> Option<Span> {
        if self.offset == u32::MAX || self.length == u32::MAX {
            return None;
        }
        Some(file.sub(self.offset.into(), self.length.into()))
    }
}

#[derive(Clone, Copy, Debug)]
struct DdBlock {
    at: u64,
    count: u16,
    next: u32,
}

#[derive(Debug)]
struct Vgroup {
    reference: u16,
    span: Span,
    name: String,
    class: String,
    members: Vec<(u16, u16)>,
}

#[derive(Clone, Debug)]
struct VField {
    name: String,
    kind: u16,
    size: u16,
    offset: u16,
    order: u16,
}

#[derive(Debug)]
struct Vdata {
    reference: u16,
    span: Span,
    interlace: u16,
    records: u32,
    record_size: u16,
    fields: Vec<VField>,
    name: String,
    class: String,
}

#[derive(Debug, Default)]
struct Model {
    blocks: Vec<DdBlock>,
    dds: Vec<Dd>,
    vgroups: Vec<Vgroup>,
    vdatas: Vec<Vdata>,
    diagnostics: Vec<Diagnostic>,
    /// (tag, reference) to the first descriptor with them.
    index: BTreeMap<(u16, u16), usize>,
    /// Reference to the first vgroup and vdata with it.
    vgroup_index: BTreeMap<u16, usize>,
    vdata_index: BTreeMap<u16, usize>,
}

impl Model {
    fn find(&self, tag: u16, reference: u16) -> Option<&Dd> {
        self.dds.get(*self.index.get(&(tag, reference))?)
    }

    /// The data of (tag, ref), also looking for the special variant.
    fn object(&self, tag: u16, reference: u16) -> Option<&Dd> {
        self.find(tag, reference)
            .or_else(|| self.find(tag | SPECIAL, reference))
    }

    fn vgroup(&self, reference: u16) -> Option<&Vgroup> {
        self.vgroups.get(*self.vgroup_index.get(&reference)?)
    }

    fn vdata(&self, reference: u16) -> Option<&Vdata> {
        self.vdatas.get(*self.vdata_index.get(&reference)?)
    }

    fn count(&self, tag: u16) -> usize {
        self.dds.iter().filter(|d| d.tag & !SPECIAL == tag).count()
    }
}

const MAX_BLOCKS: usize = 65_536;
/// Vgroup and vdata headers larger than this are not parsed.
const MAX_HEADER: u32 = 1 << 16;
/// At most this many vgroup and vdata headers are parsed.
const MAX_OBJECTS: usize = 65_536;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u16(&mut self) -> Option<u16> {
        let v = u16_be(self.data, self.pos)?;
        self.pos = self.pos.saturating_add(2);
        Some(v)
    }
    fn u32(&mut self) -> Option<u32> {
        let v = u32_be(self.data, self.pos)?;
        self.pos = self.pos.saturating_add(4);
        Some(v)
    }
    fn text(&mut self) -> Option<String> {
        let len = usize::from(self.u16()?);
        let s = self.data.get(self.pos..self.pos.checked_add(len)?)?;
        self.pos = self.pos.saturating_add(len);
        Some(String::from_utf8_lossy(s).into_owned())
    }
    fn u16s(&mut self, n: usize) -> Option<Vec<u16>> {
        let end = self.pos.checked_add(n.checked_mul(2)?)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(
            s.as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect(),
        )
    }
}

fn parse_vgroup(data: &[u8], reference: u16, span: Span) -> Option<Vgroup> {
    let mut r = Reader { data, pos: 0 };
    let n = usize::from(r.u16()?);
    let tags = r.u16s(n)?;
    let refs = r.u16s(n)?;
    let name = r.text()?;
    let class = r.text()?;
    Some(Vgroup {
        reference,
        span,
        name,
        class,
        members: tags.into_iter().zip(refs).collect(),
    })
}

fn parse_vdata(data: &[u8], reference: u16, span: Span) -> Option<Vdata> {
    let mut r = Reader { data, pos: 0 };
    let interlace = r.u16()?;
    let records = r.u32()?;
    let record_size = r.u16()?;
    let n = usize::from(r.u16()?);
    let kinds = r.u16s(n)?;
    let sizes = r.u16s(n)?;
    let offsets = r.u16s(n)?;
    let orders = r.u16s(n)?;
    let mut fields = Vec::new();
    for i in 0..n {
        fields.push(VField {
            name: r.text()?,
            kind: kinds.get(i).copied().unwrap_or(0),
            size: sizes.get(i).copied().unwrap_or(0),
            offset: offsets.get(i).copied().unwrap_or(0),
            order: orders.get(i).copied().unwrap_or(0),
        });
    }
    let name = r.text()?;
    let class = r.text()?;
    Some(Vdata {
        reference,
        span,
        interlace,
        records,
        record_size,
        fields,
        name,
        class,
    })
}

async fn build(cx: &Cx, file: Span) -> Result<Arc<Model>> {
    if let Some(m) = cx.cached::<Model>(file, "hdf4-model") {
        return Ok(m);
    }
    let mut m = Model::default();
    let mut at = 4u64;
    while at != 0 && m.blocks.len() < MAX_BLOCKS {
        let head = cx.read(file.sub_exact(at, 6)?).await?;
        let count = u16_be(&head, 0).unwrap_or(0);
        let next = u32_be(&head, 2).unwrap_or(0);
        m.blocks.push(DdBlock { at, count, next });
        let table = match file.sub_exact(at.saturating_add(6), u64::from(count).saturating_mul(12))
        {
            Ok(t) => t,
            Err(e) => {
                m.diagnostics.push(e);
                break;
            }
        };
        let bytes = cx.read(table).await?;
        for (i, dd) in bytes.as_chunks::<12>().0.iter().enumerate() {
            if i.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            m.dds.push(Dd {
                tag: u16_be(dd, 0).unwrap_or(0),
                reference: u16_be(dd, 2).unwrap_or(0),
                offset: u32_be(dd, 4).unwrap_or(0),
                length: u32_be(dd, 8).unwrap_or(0),
                at: table
                    .offset
                    .saturating_sub(file.offset)
                    .saturating_add(to_u64(i).saturating_mul(12)),
            });
        }
        let next = u64::from(next);
        if next != 0 && next <= at {
            m.diagnostics.push(
                Diagnostic::malformed(format!("DD block chain goes back to {next:#x}"))
                    .at(file.sub(at.saturating_add(2), 4)),
            );
            break;
        }
        at = next;
    }
    for (i, dd) in m.dds.iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        m.index.entry((dd.tag, dd.reference)).or_insert(i);
    }
    for (i, dd) in m.dds.clone().into_iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        if m.vgroups.len().saturating_add(m.vdatas.len()) >= MAX_OBJECTS {
            m.diagnostics.push(Diagnostic::limit(format!(
                "more than {MAX_OBJECTS} vgroups and vdatas"
            )));
            break;
        }
        let (Some(span), true) = (dd.data(file), dd.length <= MAX_HEADER) else {
            continue;
        };
        match dd.tag {
            1965 => {
                let data = cx.read_avail(span).await?;
                match parse_vgroup(&data, dd.reference, span) {
                    Some(v) => {
                        m.vgroup_index.entry(v.reference).or_insert(m.vgroups.len());
                        m.vgroups.push(v);
                    }
                    None => m.diagnostics.push(
                        Diagnostic::malformed(format!("vgroup {} is malformed", dd.reference))
                            .at(span),
                    ),
                }
            }
            1962 => {
                let data = cx.read_avail(span).await?;
                match parse_vdata(&data, dd.reference, span) {
                    Some(v) => {
                        m.vdata_index.entry(v.reference).or_insert(m.vdatas.len());
                        m.vdatas.push(v);
                    }
                    None => m.diagnostics.push(
                        Diagnostic::malformed(format!(
                            "vdata header {} is malformed",
                            dd.reference
                        ))
                        .at(span),
                    ),
                }
            }
            _ => {}
        }
    }
    let m = Arc::new(m);
    cx.cache(file, "hdf4-model", m.clone());
    Ok(m)
}

// ---------------------------------------------------------------------------
// Special elements: where an object's bytes really are

enum Resolved {
    Plain(Span),
    Compressed { span: Span, coder: u16, len: u64 },
    Unsupported(String),
}

const CODERS: EnumTable = &[
    (0, "none"),
    (1, "RLE"),
    (2, "N-bit"),
    (3, "skipping Huffman"),
    (4, "deflate"),
    (5, "SZIP"),
];

const SPECIALS: EnumTable = &[
    (1, "linked blocks"),
    (2, "external file"),
    (3, "compressed"),
    (4, "variable-length linked blocks"),
    (5, "chunked"),
    (6, "buffered"),
    (7, "compressed raster"),
];

const MAX_LINKED: usize = 65_536;

async fn resolve(cx: &Cx, file: Span, m: &Model, dd: &Dd) -> Result<Resolved> {
    let Some(span) = dd.data(file) else {
        return Ok(Resolved::Plain(file.sub(0, 0)));
    };
    if dd.tag & SPECIAL == 0 {
        return Ok(Resolved::Plain(span));
    }
    let head = cx.read_avail(span.sub(0, 32)).await?;
    let code = u16_be(&head, 0).unwrap_or(0);
    match code {
        3 => {
            let len = u64::from(u32_be(&head, 4).unwrap_or(0));
            let comp_ref = u16_be(&head, 8).unwrap_or(0);
            let coder = u16_be(&head, 12).unwrap_or(0);
            let data = m
                .find(40, comp_ref)
                .and_then(|d| d.data(file))
                .ok_or_else(|| {
                    Diagnostic::malformed(format!("compressed data {comp_ref} is missing"))
                })?;
            Ok(Resolved::Compressed {
                span: data,
                coder,
                len,
            })
        }
        1 => {
            let total = u64::from(u32_be(&head, 2).unwrap_or(0));
            let per_table = usize::try_from(u32_be(&head, 10).unwrap_or(0)).unwrap_or(0);
            let mut link = u16_be(&head, 14).unwrap_or(0);
            let mut pieces = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            let mut remaining = total;
            while link != 0 && !seen.contains(&link) && pieces.len() < MAX_LINKED {
                seen.insert(link);
                let table = m.find(20, link).and_then(|d| d.data(file)).ok_or_else(|| {
                    Diagnostic::malformed(format!("link table {link} is missing"))
                })?;
                let t = cx.read_avail(table).await?;
                let mut r = Reader { data: &t, pos: 0 };
                let next = r.u16().unwrap_or(0);
                for block in r.u16s(per_table.min(t.len() / 2)).unwrap_or_default() {
                    if block == 0 || remaining == 0 {
                        continue;
                    }
                    if let Some(b) = m.find(20, block).and_then(|d| d.data(file)) {
                        let take = b.len.min(remaining);
                        pieces.push(b.sub(0, take));
                        remaining = remaining.saturating_sub(take);
                    }
                }
                link = next;
            }
            let joined = cx.add_pieces(
                Origin {
                    parent: span,
                    transform: "hdf4-linked-blocks",
                },
                pieces,
            )?;
            Ok(Resolved::Plain(joined))
        }
        _ => Ok(Resolved::Unsupported(format!(
            "{} special element",
            lookup(SPECIALS, code.into()).unwrap_or("unknown")
        ))),
    }
}

/// The bytes of an object, decompressing deflate data lazily.
async fn object_bytes(cx: &Cx, file: Span, m: &Model, dd: &Dd) -> Result<Span> {
    match resolve(cx, file, m, dd).await? {
        Resolved::Plain(span) => Ok(span),
        Resolved::Compressed {
            span,
            coder: 4,
            len,
        } => cx.decode_lazy(span, &crate::codec::Codec::Zlib, len),
        Resolved::Compressed { coder: 0, span, .. } => Ok(span),
        Resolved::Compressed { coder, .. } => Err(Diagnostic::unsupported(format!(
            "{} compression",
            lookup(CODERS, coder.into()).unwrap_or("unknown")
        ))),
        Resolved::Unsupported(what) => Err(Diagnostic::unsupported(what)),
    }
}

// ---------------------------------------------------------------------------
// Top level

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic").span(file.sub(0, 4)).value(hex(
            u32_be(&cx.read(file.sub(0, 4)).await?, 0)
                .unwrap_or(0)
                .into(),
            32,
        )),
    );
    let m = build(&cx, file).await?;
    for d in &m.diagnostics {
        cx.diag(d.clone());
    }
    let used = m.dds.iter().filter(|d| !d.is_empty()).count();
    cx.emit(
        Node::new("Data descriptors")
            .summary(format!(
                "{} block(s), {used} of {} descriptors used",
                m.blocks.len(),
                m.dds.len()
            ))
            .lazy(dd_blocks, file),
    );
    let mut version = String::new();
    if let Some(dd) = m.find(30, 1).or_else(|| m.dds.iter().find(|d| d.tag == 30))
        && let Some(span) = dd.data(file).filter(|s| s.len >= 12)
    {
        {
            let b = cx.read_avail(span.sub(0, 92)).await?;
            let (major, minor, release) = (
                u32_be(&b, 0).unwrap_or(0),
                u32_be(&b, 4).unwrap_or(0),
                u32_be(&b, 8).unwrap_or(0),
            );
            let text = crate::text::until_nul(b.get(12..).unwrap_or_default());
            version = format!("{major}.{minor}.{release}");
            cx.emit(
                Node::new("Library version")
                    .span(span)
                    .value(Value::Text(version.clone()))
                    .summary(text.trim().to_owned())
                    .lazy(version_fields, span),
            );
        }
    }

    let datasets = sds_list(&m);
    let file_attrs = m
        .vgroups
        .iter()
        .find(|v| v.class == "CDF0.0")
        .map(|v| attribute_refs(&m, v))
        .unwrap_or_default();
    if !file_attrs.is_empty() {
        cx.emit(
            Node::new("File attributes")
                .summary(format!("{} attribute(s)", file_attrs.len()))
                .lazy(attributes, (file, file_attrs.clone())),
        );
    }
    let mut shapes = Vec::new();
    if !datasets.is_empty() {
        for &r in datasets.iter().take(4) {
            if let Some(v) = m.vgroup(r) {
                let info = sds_info(&cx, file, &m, v).await?;
                shapes.push(format!("{} {}", v.name, info.shape_text()));
            }
        }
        cx.emit(
            Node::new("Scientific datasets")
                .summary(format!("{} dataset(s)", datasets.len()))
                .lazy(sds_nodes, (file, Arc::new(datasets.clone()))),
        );
    }
    let user_vdatas: Vec<u16> = m
        .vdatas
        .iter()
        .filter(|v| !is_internal_class(&v.class))
        .map(|v| v.reference)
        .collect();
    if !m.vgroups.is_empty() {
        cx.emit(
            Node::new("Vgroups")
                .summary(format!("{} vgroup(s)", m.vgroups.len()))
                .lazy(vgroup_list, file),
        );
    }
    if !m.vdatas.is_empty() {
        cx.emit(
            Node::new("Vdatas")
                .summary(format!(
                    "{} vdata(s), {} not internal to the SD interface",
                    m.vdatas.len(),
                    user_vdatas.len()
                ))
                .lazy(vdata_list, file),
        );
    }
    let annotations = [100u16, 101, 104, 105]
        .iter()
        .map(|&t| m.count(t))
        .sum::<usize>();
    if annotations > 0 {
        cx.emit(
            Node::new("Annotations")
                .summary(format!("{annotations} annotation(s)"))
                .lazy(annotation_list, file),
        );
    }
    let rasters = m.count(306).saturating_add(m.count(202));
    if rasters > 0 {
        cx.emit(
            Node::new("Raster images")
                .summary(format!("{rasters} image(s)"))
                .lazy(raster_list, file),
        );
    }

    let mut summary = String::from("HDF4");
    if !version.is_empty() {
        summary.push_str(&format!(" {version}"));
    }
    if !datasets.is_empty() {
        summary.push_str(&format!(
            ", {} dataset(s): {}{}",
            datasets.len(),
            shapes.join(", "),
            if datasets.len() > shapes.len() {
                ", …"
            } else {
                ""
            }
        ));
    }
    if !user_vdatas.is_empty() {
        let names: Vec<String> = m
            .vdatas
            .iter()
            .filter(|v| !is_internal_class(&v.class))
            .take(3)
            .map(|v| format!("{} ({} records)", v.name, v.records))
            .collect();
        summary.push_str(&format!(
            ", {} vdata(s): {}",
            user_vdatas.len(),
            names.join(", ")
        ));
    }
    if rasters > 0 {
        summary.push_str(&format!(", {rasters} raster image(s)"));
    }
    if annotations > 0 {
        summary.push_str(&format!(", {annotations} annotation(s)"));
    }
    if datasets.is_empty() && user_vdatas.is_empty() && rasters == 0 {
        summary.push_str(&format!(", {used} objects"));
    }
    cx.annotate(summary);
    Ok(())
}

fn is_internal_class(class: &str) -> bool {
    matches!(
        class,
        "Attr0.0"
            | "DimVal0.0"
            | "DimVal0.1"
            | "SDSVar"
            | "CoordVar"
            | "Var0.0"
            | "Dim0.0"
            | "UDim0.0"
            | "CDF0.0"
            | "RIG0.0"
            | "RI0.0"
    )
}

async fn version_fields(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read_avail(span.sub(0, 92)).await?;
    for (i, name) in ["Major", "Minor", "Release"].iter().enumerate() {
        let at = i.saturating_mul(4);
        cx.emit(
            Node::new(*name)
                .span(span.sub(to_u64(at), 4))
                .value(uint(u32_be(&b, at).unwrap_or(0).into(), 32)),
        );
    }
    cx.emit(
        Node::new("Description")
            .span(span.tail(12))
            .value(Value::Text(crate::text::until_nul(
                b.get(12..).unwrap_or_default(),
            ))),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// DD blocks

async fn dd_blocks(cx: Cx, file: Span) -> Result<()> {
    let m = build(&cx, file).await?;
    let mut first = 0usize;
    for (i, b) in m.blocks.iter().enumerate() {
        let count = usize::from(b.count);
        let span = file.sub(
            b.at,
            6u64.saturating_add(u64::from(b.count).saturating_mul(12)),
        );
        let used = m
            .dds
            .get(first..first.saturating_add(count))
            .unwrap_or_default()
            .iter()
            .filter(|d| !d.is_empty())
            .count();
        cx.push(
            Node::new(format!("DD block {}", i.saturating_add(1)))
                .span(span)
                .summary(format!(
                    "{count} descriptors, {used} used, next {}",
                    if b.next == 0 {
                        "none".to_owned()
                    } else {
                        format!("{:#x}", b.next)
                    }
                ))
                .lazy(dd_block, (file, i, first)),
        )
        .await;
        first = first.saturating_add(count);
    }
    Ok(())
}

async fn dd_block(cx: Cx, (file, block, first): (Span, usize, usize)) -> Result<()> {
    let m = build(&cx, file).await?;
    let Some(b) = m.blocks.get(block) else {
        return Ok(());
    };
    cx.emit(
        Node::new("Number of descriptors")
            .span(file.sub(b.at, 2))
            .value(uint(b.count.into(), 16)),
    );
    cx.emit(
        Node::new("Next block")
            .span(file.sub(b.at.saturating_add(2), 4))
            .value(hex(b.next.into(), 32)),
    );
    let dds = m
        .dds
        .get(first..first.saturating_add(usize::from(b.count)))
        .unwrap_or_default();
    cx.set_count(Count::Exact(to_u64(dds.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, dd) in dds.iter().enumerate().skip(start) {
        cx.mark(move || i);
        let mut node = Node::new(format!("{} ref {}", short_tag(dd.tag), dd.reference))
            .span(file.sub(dd.at, 12));
        if dd.is_empty() {
            cx.push(node.summary("empty")).await;
            continue;
        } else if let Some(data) = dd.data(file) {
            node = node
                .summary(format!("{:#x}, {} bytes", dd.offset, dd.length))
                .target(data);
            if data.len < u64::from(dd.length) {
                node = node.diag(Diagnostic::truncated(
                    Span::new(file.source, data.offset, dd.length.into()),
                    data.len,
                ));
            }
        } else {
            node = node.summary("no data");
        }
        node = node.lazy(dd_fields, (file, *dd));
        cx.push(node).await;
    }
    Ok(())
}

async fn dd_fields(cx: Cx, (file, dd): (Span, Dd)) -> Result<()> {
    let at = |o: u64, n: u64| file.sub(dd.at.saturating_add(o), n);
    cx.emit(Node::new("Tag").span(at(0, 2)).value(Value::Enum {
        raw: (dd.tag & !SPECIAL).into(),
        bits: 16,
        name: lookup(TAGS, (dd.tag & !SPECIAL).into()),
    }));
    if dd.tag & SPECIAL != 0 {
        cx.emit(
            Node::new("Special flag")
                .span(at(0, 1))
                .value(hex(SPECIAL.into(), 16)),
        );
    }
    cx.emit(
        Node::new("Reference")
            .span(at(2, 2))
            .value(uint(dd.reference.into(), 16)),
    );
    cx.emit(
        Node::new("Offset")
            .span(at(4, 4))
            .value(hex(dd.offset.into(), 32)),
    );
    cx.emit(
        Node::new("Length")
            .span(at(8, 4))
            .value(uint(dd.length.into(), 32)),
    );
    if dd.tag & SPECIAL != 0
        && let Some(span) = dd.data(file)
    {
        cx.emit(
            Node::new("Special header")
                .span(span)
                .lazy(special_header, span),
        );
    }
    Ok(())
}

async fn special_header(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read_avail(span.sub(0, 64)).await?;
    let code = u16_be(&b, 0).unwrap_or(0);
    let emit = |name: &'static str, off: u64, len: u64, v: Value| {
        cx.emit(Node::new(name).span(span.sub(off, len)).value(v));
    };
    emit(
        "Special code",
        0,
        2,
        Value::Enum {
            raw: code.into(),
            bits: 16,
            name: lookup(SPECIALS, code.into()),
        },
    );
    let w = |o: usize| u64::from(u16_be(&b, o).unwrap_or(0));
    let d = |o: usize| u64::from(u32_be(&b, o).unwrap_or(0));
    match code {
        3 => {
            emit("Version", 2, 2, uint(w(2), 16));
            emit("Uncompressed length", 4, 4, uint(d(4), 32));
            emit("Compressed data ref", 8, 2, uint(w(8), 16));
            emit("Model type", 10, 2, uint(w(10), 16));
            emit(
                "Coder type",
                12,
                2,
                Value::Enum {
                    raw: w(12),
                    bits: 16,
                    name: lookup(CODERS, w(12)),
                },
            );
            if span.len > 14 {
                emit(
                    "Coder parameters",
                    14,
                    span.len.saturating_sub(14),
                    Value::Bytes(b.get(14..).unwrap_or_default().to_vec()),
                );
            }
        }
        1 => {
            emit("Total length", 2, 4, uint(d(2), 32));
            emit("Block length", 6, 4, uint(d(6), 32));
            emit("Blocks per link table", 10, 4, uint(d(10), 32));
            emit("First link table ref", 14, 2, uint(w(14), 16));
        }
        2 => {
            emit("Length", 2, 4, uint(d(2), 32));
            emit("Offset in external file", 6, 4, hex(d(6), 32));
            let n = d(10);
            emit("Name length", 10, 4, uint(n, 32));
            emit(
                "External file",
                14,
                n,
                Value::Text(
                    String::from_utf8_lossy(
                        b.get(14..14usize.saturating_add(to_usize(n)))
                            .unwrap_or_default(),
                    )
                    .into_owned(),
                ),
            );
        }
        _ => {
            emit(
                "Header",
                2,
                span.len.saturating_sub(2),
                Value::Bytes(b.get(2..).unwrap_or_default().to_vec()),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scientific datasets

/// References of the `Var0.0` vgroups that are datasets (not dimension
/// scales).
fn sds_list(m: &Model) -> Vec<u16> {
    m.vgroups
        .iter()
        .filter(|v| v.class == "Var0.0")
        .filter(|v| {
            !v.members
                .iter()
                .any(|&(t, r)| t == 1962 && m.vdata(r).is_some_and(|d| d.class == "CoordVar"))
        })
        .map(|v| v.reference)
        .collect()
}

fn attribute_refs(m: &Model, v: &Vgroup) -> Vec<u16> {
    v.members
        .iter()
        .filter(|&&(t, r)| t == 1962 && m.vdata(r).is_some_and(|d| d.class == "Attr0.0"))
        .map(|&(_, r)| r)
        .collect()
}

struct SdsInfo {
    dims: Vec<u64>,
    dim_names: Vec<String>,
    kind: Option<u16>,
    nt_endian: Endian,
}

impl SdsInfo {
    fn shape_text(&self) -> String {
        let dims: Vec<String> = self.dims.iter().map(u64::to_string).collect();
        format!(
            "{} {}",
            dims.join("×"),
            self.kind.map_or_else(|| "?".to_owned(), type_label)
        )
    }
}

async fn sds_info(cx: &Cx, file: Span, m: &Model, v: &Vgroup) -> Result<SdsInfo> {
    let mut info = SdsInfo {
        dims: Vec::new(),
        dim_names: Vec::new(),
        kind: None,
        nt_endian: BE,
    };
    for &(t, r) in &v.members {
        match t {
            701 => {
                if let Some(span) = m.find(701, r).and_then(|d| d.data(file)) {
                    let b = cx.read_avail(span).await?;
                    let rank = usize::from(u16_be(&b, 0).unwrap_or(0));
                    for i in 0..rank.min(32) {
                        if let Some(d) = u32_be(&b, 2usize.saturating_add(i.saturating_mul(4))) {
                            info.dims.push(d.into());
                        }
                    }
                }
            }
            106 => {
                if let Some(span) = m.find(106, r).and_then(|d| d.data(file)) {
                    let b = cx.read_avail(span.sub(0, 4)).await?;
                    let kind = b.get(1).copied().unwrap_or(0);
                    let class = b.get(3).copied().unwrap_or(0);
                    info.kind = Some(kind.into());
                    if class == 4 {
                        info.nt_endian = Endian::Little;
                    }
                }
            }
            1965 => {
                if let Some(d) = m
                    .vgroup(r)
                    .filter(|d| d.class == "Dim0.0" || d.class == "UDim0.0")
                {
                    info.dim_names.push(d.name.clone());
                }
            }
            _ => {}
        }
    }
    Ok(info)
}

async fn sds_nodes(cx: Cx, (file, list): (Span, Arc<Vec<u16>>)) -> Result<()> {
    let m = build(&cx, file).await?;
    cx.set_count(Count::Exact(to_u64(list.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, &r) in list.iter().enumerate().skip(start) {
        cx.mark(move || i);
        let Some(v) = m.vgroup(r) else { continue };
        let info = sds_info(&cx, file, &m, v).await?;
        let attrs = attribute_refs(&m, v).len();
        let mut summary = info.shape_text();
        if !info.dim_names.is_empty() {
            summary.push_str(&format!(" ({})", info.dim_names.join(" × ")));
        }
        if attrs > 0 {
            summary.push_str(&format!(", {attrs} attribute(s)"));
        }
        cx.push(
            Node::new(v.name.clone())
                .span(v.span)
                .summary(summary)
                .lazy(sds, (file, r, true)),
        )
        .await;
    }
    Ok(())
}

async fn sds(cx: Cx, (file, reference, with_dims): (Span, u16, bool)) -> Result<()> {
    let m = build(&cx, file).await?;
    let v = m
        .vgroup(reference)
        .ok_or_else(|| Diagnostic::internal("dataset vgroup vanished"))?;
    let info = sds_info(&cx, file, &m, v).await?;
    cx.emit(vgroup_node(file, v, "Variable vgroup"));
    // Dimensions: names from the Dim0.0 vgroups, sizes from the SDD.
    let mut dim_index = 0usize;
    // One unit of work per 4096 members looked at.
    let mut work = 0u64;
    for &(t, r) in &v.members {
        work = work.saturating_add(1);
        while work >= 4096 {
            cx.checkpoint().await;
            work = work.saturating_sub(4096);
        }
        if t != 1965 || !with_dims {
            continue;
        }
        let Some(d) = m
            .vgroup(r)
            .filter(|d| d.class == "Dim0.0" || d.class == "UDim0.0")
        else {
            continue;
        };
        let size = info.dims.get(dim_index).copied();
        dim_index = dim_index.saturating_add(1);
        let mut node = Node::new(format!("Dimension {}", d.name)).span(d.span);
        if d.class == "UDim0.0" {
            node = node.summary("unlimited");
        }
        if let Some(size) = size {
            node = node.value(uint(size, 32));
        }
        // A coordinate variable with the same name holds the scale.
        let mut scale = None;
        for c in &m.vgroups {
            work = work.saturating_add(1);
            while work >= 4096 {
                cx.checkpoint().await;
                work = work.saturating_sub(4096);
            }
            if c.class == "Var0.0" && c.name == d.name {
                work = work.saturating_add(to_u64(c.members.len()));
                if c.members
                    .iter()
                    .any(|&(t, r)| t == 1962 && m.vdata(r).is_some_and(|x| x.class == "CoordVar"))
                {
                    scale = Some(c);
                    break;
                }
            }
        }
        if let Some(c) = scale {
            node = node
                .summary("with a coordinate variable (dimension scale)")
                .lazy(
                    crate::expander!(self::sds: (Span, u16, bool)),
                    (file, c.reference, false),
                );
        }
        cx.emit(node);
    }
    for &(t, r) in &v.members {
        match t {
            106 => {
                if let Some(dd) = m.find(106, r)
                    && let Some(span) = dd.data(file)
                {
                    let b = cx.read_avail(span.sub(0, 4)).await?;
                    let kind = b.get(1).copied().unwrap_or(0);
                    cx.emit(
                        Node::new("Number type")
                            .span(span)
                            .value(Value::Enum {
                                raw: kind.into(),
                                bits: 8,
                                name: lookup(NUMBER_TYPES, kind.into()),
                            })
                            .summary(format!(
                                "version {}, {} bits, class {}{}",
                                b.first().copied().unwrap_or(0),
                                b.get(2).copied().unwrap_or(0),
                                b.get(3).copied().unwrap_or(0),
                                match b.get(3) {
                                    Some(1) => " (big-endian)",
                                    Some(4) => " (little-endian)",
                                    _ => "",
                                }
                            )),
                    );
                }
            }
            701 => {
                if let Some(span) = m.find(701, r).and_then(|d| d.data(file)) {
                    cx.emit(
                        Node::new("Dimension record (SDD)")
                            .span(span)
                            .summary(format!("rank {}", info.dims.len()))
                            .lazy(sdd_fields, span),
                    );
                }
            }
            _ => {}
        }
    }
    let attrs = attribute_refs(&m, v);
    if !attrs.is_empty() {
        cx.emit(
            Node::new("Attributes")
                .summary(format!("{} attribute(s)", attrs.len()))
                .lazy(attributes, (file, attrs)),
        );
    }
    let data = v
        .members
        .iter()
        .find(|&&(t, _)| t & !SPECIAL == 702)
        .and_then(|&(_, r)| m.object(702, r));
    let elem = info.kind.and_then(number_type);
    match (data, elem) {
        (None, _) => cx.emit(Node::new("Data").summary("not written (fill value)")),
        (Some(dd), elem) => {
            let raw = dd.data(file).unwrap_or(file.sub(0, 0));
            let mut node = Node::new("Data").span(raw);
            match (object_bytes(&cx, file, &m, dd).await, elem) {
                (Ok(bytes), Some((el, _))) => {
                    let compressed = bytes.source != file.source;
                    let array = Array {
                        span: bytes,
                        elem: el,
                        endian: info.nt_endian,
                        dims: Arc::new(info.dims.clone()),
                        row_major: true,
                        scale: None,
                    };
                    node = array.node("Data");
                    if compressed {
                        node = node.summary(format!(
                            "{} × {}, decompressed from {} bytes",
                            array_count(&info.dims),
                            el.name(),
                            raw.len
                        ));
                    }
                    if dd.tag & SPECIAL != 0 {
                        node = node.desc("Special element; see its descriptor for the header");
                    }
                }
                (Ok(_), None) => {
                    node = node.diag(Diagnostic::unsupported("number type"));
                }
                (Err(e), _) => node = node.diag(e),
            }
            cx.emit(node);
        }
    }
    Ok(())
}

fn array_count(dims: &[u64]) -> u64 {
    dims.iter().fold(1u64, |a, &d| a.saturating_mul(d))
}

async fn sdd_fields(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read_avail(span).await?;
    let rank = u16_be(&b, 0).unwrap_or(0);
    cx.emit(
        Node::new("Rank")
            .span(span.sub(0, 2))
            .value(uint(rank.into(), 16)),
    );
    let mut at = 2usize;
    for i in 0..usize::from(rank).min(32) {
        let _ = i;
        cx.emit(
            Node::new("Dimension size")
                .span(span.sub(to_u64(at), 4))
                .value(uint(u32_be(&b, at).unwrap_or(0).into(), 32)),
        );
        at = at.saturating_add(4);
    }
    for name in std::iter::once("Data number type").chain(std::iter::repeat_n(
        "Scale number type",
        usize::from(rank).min(32),
    )) {
        if at.saturating_add(4) > b.len() {
            break;
        }
        cx.emit(
            Node::new(name)
                .span(span.sub(to_u64(at), 4))
                .value(Value::Text(format!(
                    "{} ref {}",
                    short_tag(u16_be(&b, at).unwrap_or(0)),
                    u16_be(&b, at.saturating_add(2)).unwrap_or(0)
                ))),
        );
        at = at.saturating_add(4);
    }
    Ok(())
}

/// Attribute values: one record of a single field `VALUES`.
async fn attribute_value(cx: &Cx, file: Span, m: &Model, vd: &Vdata) -> Result<(Value, Span)> {
    let Some(field) = vd.fields.first() else {
        return Ok((Value::Text(String::new()), file.sub(0, 0)));
    };
    let Some(dd) = m.object(1963, vd.reference) else {
        return Ok((Value::Text("no data".into()), file.sub(0, 0)));
    };
    let span = object_bytes(cx, file, m, dd).await?;
    let bytes = cx.read_avail(span.sub(0, 4096)).await?;
    let Some((elem, endian)) = number_type(field.kind) else {
        return Ok((Value::Bytes(bytes), span));
    };
    if elem == Elem::Char {
        return Ok((Value::Text(crate::text::until_nul(&bytes)), span));
    }
    let size = to_usize(elem.size());
    let values: Vec<String> = bytes
        .chunks_exact(size.max(1))
        .take(64)
        .filter_map(|c| elem.number(c, endian))
        .map(num)
        .collect();
    if values.len() == 1 {
        let one = bytes.get(..size).and_then(|c| elem.value(c, endian));
        if let Some(v) = one {
            return Ok((v, span));
        }
    }
    Ok((Value::Text(values.join(", ")), span))
}

async fn attributes(cx: Cx, (file, refs): (Span, Vec<u16>)) -> Result<()> {
    let m = build(&cx, file).await?;
    for r in refs {
        let Some(vd) = m.vdata(r) else { continue };
        let mut node = Node::new(vd.name.clone());
        match attribute_value(&cx, file, &m, vd).await {
            Ok((value, span)) => {
                node = node.value(value).span(span);
            }
            Err(e) => node = node.diag(e),
        }
        let kind = vd.fields.first().map_or(0, |f| f.kind);
        let order = vd.fields.first().map_or(0, |f| f.order);
        node = node.summary(format!("{} × {order}", type_label(kind)));
        cx.push(node.lazy(vdata_detail, (file, r))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Vgroups and vdatas

fn vgroup_node(file: Span, v: &Vgroup, name: &'static str) -> Node {
    Node::new(name)
        .span(v.span)
        .value(Value::Text(v.name.clone()))
        .summary(format!(
            "class {:?}, {} member(s)",
            v.class,
            v.members.len()
        ))
        .lazy(vgroup_detail, (file, v.reference))
}

async fn vgroup_list(cx: Cx, file: Span) -> Result<()> {
    let m = build(&cx, file).await?;
    cx.set_count(Count::Exact(to_u64(m.vgroups.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, v) in m.vgroups.iter().enumerate().skip(start) {
        cx.mark(move || i);
        cx.push(
            Node::new(format!("Vgroup {}", v.reference))
                .span(v.span)
                .value(Value::Text(v.name.clone()))
                .summary(format!(
                    "class {:?}, {} member(s)",
                    v.class,
                    v.members.len()
                ))
                .lazy(vgroup_detail, (file, v.reference)),
        )
        .await;
    }
    Ok(())
}

async fn vgroup_detail(cx: Cx, (file, reference): (Span, u16)) -> Result<()> {
    let m = build(&cx, file).await?;
    let v = m
        .vgroup(reference)
        .ok_or_else(|| Diagnostic::internal("vgroup vanished"))?;
    let data = cx.read_avail(v.span).await?;
    let n = v.members.len();
    let at = |o: usize, len: usize| v.span.sub(to_u64(o), to_u64(len));
    cx.emit(
        Node::new("Number of members")
            .span(at(0, 2))
            .value(uint(to_u64(n), 16)),
    );
    cx.emit(
        Node::new("Members")
            .span(at(2, n.saturating_mul(4)))
            .summary(format!("{n} tag/ref pair(s)"))
            .lazy(members, (file, reference)),
    );
    let mut pos = 2usize.saturating_add(n.saturating_mul(4));
    for name in ["Name", "Class"] {
        let len = usize::from(u16_be(&data, pos).unwrap_or(0));
        cx.emit(
            Node::new(name)
                .span(at(pos, len.saturating_add(2)))
                .value(Value::Text(
                    String::from_utf8_lossy(
                        data.get(pos.saturating_add(2)..pos.saturating_add(2).saturating_add(len))
                            .unwrap_or_default(),
                    )
                    .into_owned(),
                )),
        );
        pos = pos.saturating_add(2).saturating_add(len);
    }
    tail_fields(&cx, v.span, &data, pos, false);
    Ok(())
}

/// The fields after the class of a vgroup or vdata header: expansion
/// tag/ref, then (vdata) version and "more" once, then flags and attribute
/// references for version 4, then the version, "more" and a pad byte.
fn tail_fields(cx: &Cx, span: Span, data: &[u8], mut pos: usize, vdata: bool) {
    let field = |name: &'static str, len: usize, pos: &mut usize| {
        let v = match len {
            2 => u16_be(data, *pos).map(|v| uint(v.into(), 16)),
            4 => u32_be(data, *pos).map(|v| uint(v.into(), 32)),
            _ => data.get(*pos).map(|&v| uint(v.into(), 8)),
        };
        if let Some(v) = v {
            cx.emit(
                Node::new(name)
                    .span(span.sub(to_u64(*pos), to_u64(len)))
                    .value(v),
            );
        }
        *pos = pos.saturating_add(len);
    };
    field("Extension tag", 2, &mut pos);
    field("Extension ref", 2, &mut pos);
    let end = data.len();
    // Version, more and pad (5 bytes) close the header.
    let closing = end.saturating_sub(5);
    if vdata && pos.saturating_add(4) <= closing {
        field("Version", 2, &mut pos);
        field("More", 2, &mut pos);
    }
    if pos < closing {
        let flags = u32_be(data, pos).unwrap_or(0);
        field("Flags", 4, &mut pos);
        if flags & 1 != 0 && pos.saturating_add(4) <= closing {
            let n = u32_be(data, pos).unwrap_or(0);
            field("Number of attributes", 4, &mut pos);
            for _ in 0..n.min(4096) {
                if pos.saturating_add(8) > closing {
                    break;
                }
                let findex = u32_be(data, pos).unwrap_or(0);
                let r = u16_be(data, pos.saturating_add(6)).unwrap_or(0);
                cx.emit(
                    Node::new("Attribute")
                        .span(span.sub(to_u64(pos), 8))
                        .value(Value::Text(format!("vdata {r}")))
                        .summary(if findex == u32::MAX {
                            "of the whole object".to_owned()
                        } else {
                            format!("of field {findex}")
                        }),
                );
                pos = pos.saturating_add(8);
            }
        }
        if pos < closing {
            cx.emit(
                Node::new("Unknown")
                    .span(span.sub(to_u64(pos), to_u64(closing.saturating_sub(pos)))),
            );
            pos = closing;
        }
    }
    field("Version", 2, &mut pos);
    field("More", 2, &mut pos);
    if pos < end {
        field("Padding", 1, &mut pos);
    }
}

async fn members(cx: Cx, (file, reference): (Span, u16)) -> Result<()> {
    let m = build(&cx, file).await?;
    let v = m
        .vgroup(reference)
        .ok_or_else(|| Diagnostic::internal("vgroup vanished"))?;
    let n = v.members.len();
    cx.set_count(Count::Exact(to_u64(n)));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, &(tag, r)) in v.members.iter().enumerate().skip(start) {
        cx.mark(move || i);
        let mut node = Node::new(format!("{} ref {r}", short_tag(tag)))
            .span(
                v.span
                    .sub(2u64.saturating_add(to_u64(i).saturating_mul(2)), 2),
            )
            .value(Value::Text(tag_name(tag)));
        let _ = n;
        if let Some(target) = m.object(tag, r).and_then(|d| d.data(file)) {
            node = node.target(target);
        }
        let label = match tag {
            1965 => m
                .vgroup(r)
                .map(|g| format!("vgroup {:?} ({})", g.name, g.class)),
            1962 => m
                .vdata(r)
                .map(|d| format!("vdata {:?} ({})", d.name, d.class)),
            _ => None,
        };
        if let Some(l) = label {
            node = node.summary(l);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn vdata_list(cx: Cx, file: Span) -> Result<()> {
    let m = build(&cx, file).await?;
    cx.set_count(Count::Exact(to_u64(m.vdatas.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, v) in m.vdatas.iter().enumerate().skip(start) {
        cx.mark(move || i);
        let names: Vec<&str> = v.fields.iter().map(|f| f.name.as_str()).collect();
        cx.push(
            Node::new(format!("Vdata {}", v.reference))
                .span(v.span)
                .value(Value::Text(v.name.clone()))
                .summary(format!(
                    "class {:?}, {} record(s) × {} bytes, fields {}",
                    v.class,
                    v.records,
                    v.record_size,
                    names.join(", ")
                ))
                .lazy(vdata_detail, (file, v.reference)),
        )
        .await;
    }
    Ok(())
}

async fn vdata_detail(cx: Cx, (file, reference): (Span, u16)) -> Result<()> {
    let m = build(&cx, file).await?;
    let v = m
        .vdata(reference)
        .ok_or_else(|| Diagnostic::internal("vdata vanished"))?;
    let data = cx.read_avail(v.span).await?;
    let at = |o: usize, len: usize| v.span.sub(to_u64(o), to_u64(len));
    cx.emit(Node::new("Interlace").span(at(0, 2)).value(Value::Enum {
        raw: v.interlace.into(),
        bits: 16,
        name: lookup(
            &[(0, "full (by record)"), (1, "none (by field)")],
            v.interlace.into(),
        ),
    }));
    cx.emit(
        Node::new("Number of records")
            .span(at(2, 4))
            .value(uint(v.records.into(), 32)),
    );
    cx.emit(
        Node::new("Record size")
            .span(at(6, 2))
            .value(uint(v.record_size.into(), 16)),
    );
    let n = v.fields.len();
    cx.emit(
        Node::new("Number of fields")
            .span(at(8, 2))
            .value(uint(to_u64(n), 16)),
    );
    let arrays = 10usize;
    let names_at = arrays.saturating_add(n.saturating_mul(8));
    cx.emit(
        Node::new("Fields")
            .span(at(arrays, names_at.saturating_sub(arrays)))
            .summary(format!("{n} field(s)"))
            .lazy(vdata_fields, (file, reference)),
    );
    let mut pos = names_at;
    for f in &v.fields {
        pos = pos.saturating_add(2).saturating_add(f.name.len());
    }
    cx.emit(Node::new("Field names").span(at(names_at, pos.saturating_sub(names_at))));
    for (name, value) in [("Name", &v.name), ("Class", &v.class)] {
        let len = value.len().saturating_add(2);
        cx.emit(
            Node::new(name)
                .span(at(pos, len))
                .value(Value::Text(value.clone())),
        );
        pos = pos.saturating_add(len);
    }
    tail_fields(&cx, v.span, &data, pos, true);
    match m.object(1963, reference) {
        Some(dd) => {
            let mut node = Node::new("Records").summary(format!("{} record(s)", v.records));
            if let Some(span) = dd.data(file) {
                node = node.span(span);
            } else {
                cx.emit(node.summary("no data"));
                return Ok(());
            }
            match object_bytes(&cx, file, &m, dd).await {
                Ok(span) => {
                    if dd.tag & SPECIAL != 0 {
                        node = node.desc("Stored as a special element (see its descriptor)");
                    }
                    node = node.lazy(records, (file, reference, span));
                }
                Err(e) => node = node.diag(e),
            }
            cx.emit(node);
        }
        None => cx.emit(Node::new("Records").summary("no data")),
    }
    Ok(())
}

async fn vdata_fields(cx: Cx, (file, reference): (Span, u16)) -> Result<()> {
    let m = build(&cx, file).await?;
    let v = m
        .vdata(reference)
        .ok_or_else(|| Diagnostic::internal("vdata vanished"))?;
    let n = to_u64(v.fields.len());
    for (i, f) in v.fields.iter().enumerate() {
        let i = to_u64(i);
        let col = |k: u64| {
            v.span.sub(
                10u64.saturating_add(k.saturating_mul(n).saturating_add(i).saturating_mul(2)),
                2,
            )
        };
        cx.push(
            Node::new(f.name.clone())
                .span(col(0))
                .value(Value::Text(type_label(f.kind)))
                .summary(format!(
                    "order {}, {} bytes, offset {}",
                    f.order, f.size, f.offset
                )),
        )
        .await;
        let _ = col;
    }
    Ok(())
}

fn field_value(elem: Elem, endian: Endian, bytes: &[u8], order: usize) -> Value {
    if elem == Elem::Char {
        return Value::Text(crate::text::until_nul(bytes));
    }
    let size = to_usize(elem.size()).max(1);
    if order == 1
        && let Some(v) = elem.value(bytes, endian)
    {
        return v;
    }
    let parts: Vec<String> = bytes
        .chunks_exact(size)
        .take(order.min(64))
        .filter_map(|c| elem.number(c, endian))
        .map(num)
        .collect();
    Value::Text(parts.join(", "))
}

async fn records(cx: Cx, (file, reference, span): (Span, u16, Span)) -> Result<()> {
    let m = build(&cx, file).await?;
    let v = m
        .vdata(reference)
        .ok_or_else(|| Diagnostic::internal("vdata vanished"))?;
    let size = u64::from(v.record_size);
    let count = u64::from(v.records).min(span.len.checked_div(size).unwrap_or(0));
    cx.set_count(Count::Exact(count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        cx.mark(move || i);
        let mut parts = Vec::new();
        let mut first = None;
        // Field j of record i: at offset × records for unnumbered layouts.
        for f in &v.fields {
            let fsize = u64::from(f.size);
            let at = if v.interlace == 0 {
                i.saturating_mul(size).saturating_add(f.offset.into())
            } else {
                let before: u64 = v
                    .fields
                    .iter()
                    .take_while(|g| g.name != f.name)
                    .map(|g| u64::from(g.size).saturating_mul(count))
                    .sum();
                before.saturating_add(i.saturating_mul(fsize))
            };
            let fspan = span.sub(at, fsize);
            first.get_or_insert(fspan);
            let bytes = cx.read_avail(fspan).await?;
            let value = match number_type(f.kind) {
                Some((elem, endian)) => field_value(elem, endian, &bytes, f.order.into()),
                None => Value::Bytes(bytes),
            };
            parts.push(crate::render::value(&value));
        }
        let rspan = if v.interlace == 0 {
            span.sub(i.saturating_mul(size), size)
        } else {
            first.unwrap_or(span.sub(0, 0))
        };
        cx.push(
            Node::new(format!("Record {i}"))
                .span(rspan)
                .summary(parts.join(", "))
                .lazy(record, (file, reference, span, i, count)),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn record(
    cx: Cx,
    (file, reference, span, i, count): (Span, u16, Span, u64, u64),
) -> Result<()> {
    let m = build(&cx, file).await?;
    let v = m
        .vdata(reference)
        .ok_or_else(|| Diagnostic::internal("vdata vanished"))?;
    let size = u64::from(v.record_size);
    let mut before = 0u64;
    for f in &v.fields {
        let fsize = u64::from(f.size);
        let at = if v.interlace == 0 {
            i.saturating_mul(size).saturating_add(f.offset.into())
        } else {
            before.saturating_add(i.saturating_mul(fsize))
        };
        before = before.saturating_add(fsize.saturating_mul(count));
        let fspan = span.sub(at, fsize);
        let bytes = cx.read_avail(fspan).await?;
        let value = match number_type(f.kind) {
            Some((elem, endian)) => field_value(elem, endian, &bytes, f.order.into()),
            None => Value::Bytes(bytes),
        };
        cx.emit(Node::new(f.name.clone()).span(fspan).value(value));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Annotations and raster images

async fn annotation_list(cx: Cx, file: Span) -> Result<()> {
    let m = build(&cx, file).await?;
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, dd) in m
        .dds
        .iter()
        .enumerate()
        .filter(|(_, d)| matches!(d.tag, 100 | 101 | 104 | 105))
        .skip_while(|(i, _)| *i < start)
    {
        cx.mark(move || i);
        let Some(span) = dd.data(file) else { continue };
        let bytes = cx.read_avail(span.sub(0, 4096)).await?;
        let (kind, object, text) = match dd.tag {
            100 => ("File label", None, bytes.as_slice()),
            101 => ("File description", None, bytes.as_slice()),
            104 => (
                "Data label",
                Some(&bytes),
                bytes.get(4..).unwrap_or_default(),
            ),
            _ => (
                "Data description",
                Some(&bytes),
                bytes.get(4..).unwrap_or_default(),
            ),
        };
        let mut node = Node::new(kind).span(span).value(Value::Text(
            String::from_utf8_lossy(text)
                .trim_end_matches('\0')
                .to_owned(),
        ));
        if let Some(b) = object {
            let tag = u16_be(b, 0).unwrap_or(0);
            let r = u16_be(b, 2).unwrap_or(0);
            node = node.summary(format!("of {} ref {r}", short_tag(tag)));
            if let Some(t) = m.object(tag, r).and_then(|d| d.data(file)) {
                node = node.target(t);
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

const INTERLACES: EnumTable = &[(0, "pixel"), (1, "line"), (2, "component")];

async fn raster_list(cx: Cx, file: Span) -> Result<()> {
    let m = build(&cx, file).await?;
    for (i, dd) in m.dds.iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        if dd.tag != 306 && dd.tag != 202 {
            continue;
        }
        let Some(span) = dd.data(file) else { continue };
        if dd.tag == 202 {
            // 8-bit raster: dimensions in ID8, palette in IP8, same ref.
            let dims = match m.find(200, dd.reference).and_then(|d| d.data(file)) {
                Some(s) => {
                    let b = cx.read_avail(s.sub(0, 4)).await?;
                    Some((u16_be(&b, 0).unwrap_or(0), u16_be(&b, 2).unwrap_or(0), s))
                }
                None => None,
            };
            let palette = m.find(201, dd.reference).and_then(|d| d.data(file));
            let mut node = Node::new(format!("8-bit image {}", dd.reference)).span(span);
            if let Some((w, h, _)) = dims {
                node = node.summary(format!(
                    "{w}×{h}, 8-bit{}",
                    if palette.is_some() {
                        ", with palette"
                    } else {
                        ""
                    }
                ));
            }
            cx.push(node.lazy(raster8, (span, dims.map(|d| (d.0, d.1, d.2)), palette)))
                .await;
            continue;
        }
        let group = cx.read_avail(span).await?;
        let pairs: Vec<(u16, u16)> = group
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| (u16_be(c, 0).unwrap_or(0), u16_be(c, 2).unwrap_or(0)))
            .collect();
        let id = pairs
            .iter()
            .find(|p| p.0 == 300)
            .and_then(|&(t, r)| m.find(t, r))
            .and_then(|d| d.data(file));
        let mut node = Node::new(format!("Raster image group {}", dd.reference)).span(span);
        if let Some(s) = id {
            let b = cx.read_avail(s.sub(0, 20)).await?;
            let w = u32_be(&b, 0).unwrap_or(0);
            let h = u32_be(&b, 4).unwrap_or(0);
            let nt = u16_be(&b, 8).unwrap_or(0);
            let comps = u16_be(&b, 12).unwrap_or(0);
            let _ = nt;
            node = node.summary(format!("{w}×{h}, {comps} component(s)"));
        }
        cx.push(node.lazy(rig, (file, span))).await;
    }
    Ok(())
}

async fn raster8(
    cx: Cx,
    (span, dims, palette): (Span, Option<(u16, u16, Span)>, Option<Span>),
) -> Result<()> {
    if let Some((w, h, s)) = dims {
        cx.emit(
            Node::new("Width")
                .span(s.sub(0, 2))
                .value(uint(w.into(), 16)),
        );
        cx.emit(
            Node::new("Height")
                .span(s.sub(2, 2))
                .value(uint(h.into(), 16)),
        );
        let expected = u64::from(w).saturating_mul(h.into());
        let mut node = Node::new("Pixels")
            .span(span)
            .summary(format!("{} bytes", span.len));
        if span.len != expected {
            node = node.diag(Diagnostic::warning(format!(
                "{} bytes for {w}×{h} pixels",
                span.len
            )));
        }
        cx.emit(node);
    } else {
        cx.emit(Node::new("Pixels").span(span));
    }
    if let Some(p) = palette {
        cx.emit(
            Node::new("Palette")
                .span(p)
                .summary(format!("{} entries", p.len / 3)),
        );
    }
    Ok(())
}

async fn rig(cx: Cx, (file, span): (Span, Span)) -> Result<()> {
    let m = build(&cx, file).await?;
    let group = cx.read_avail(span).await?;
    for (i, c) in group.as_chunks::<4>().0.iter().enumerate() {
        let tag = u16_be(c, 0).unwrap_or(0);
        let r = u16_be(c, 2).unwrap_or(0);
        let target = m.object(tag, r).and_then(|d| d.data(file));
        let mut node = Node::new(format!("{} ref {r}", short_tag(tag)))
            .span(span.sub(to_u64(i).saturating_mul(4), 4))
            .value(Value::Text(tag_name(tag)));
        if let Some(t) = target {
            node = node.target(t);
            if tag == 300 || tag == 307 {
                node = node.lazy(image_dims, t);
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn image_dims(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read_avail(span.sub(0, 20)).await?;
    let at = |o: u64, n: u64| span.sub(o, n);
    cx.emit(
        Node::new("Width")
            .span(at(0, 4))
            .value(uint(u32_be(&b, 0).unwrap_or(0).into(), 32)),
    );
    cx.emit(
        Node::new("Height")
            .span(at(4, 4))
            .value(uint(u32_be(&b, 4).unwrap_or(0).into(), 32)),
    );
    cx.emit(
        Node::new("Number type")
            .span(at(8, 4))
            .value(Value::Text(format!(
                "{} ref {}",
                short_tag(u16_be(&b, 8).unwrap_or(0)),
                u16_be(&b, 10).unwrap_or(0)
            ))),
    );
    cx.emit(
        Node::new("Components")
            .span(at(12, 2))
            .value(uint(u16_be(&b, 12).unwrap_or(0).into(), 16)),
    );
    let il = u16_be(&b, 14).unwrap_or(0);
    cx.emit(Node::new("Interlace").span(at(14, 2)).value(Value::Enum {
        raw: il.into(),
        bits: 16,
        name: lookup(INTERLACES, il.into()),
    }));
    cx.emit(
        Node::new("Compression")
            .span(at(16, 4))
            .value(Value::Text(format!(
                "{} ref {}",
                short_tag(u16_be(&b, 16).unwrap_or(0)),
                u16_be(&b, 18).unwrap_or(0)
            ))),
    );
    Ok(())
}
