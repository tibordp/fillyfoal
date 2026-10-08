//! AutoCAD DWG drawings: the file layouts of R13 to R2018.
//!
//! The layouts follow the Open Design Alliance's "Open Design Specification
//! for .dwg files" as remembered (it could not be consulted), so field
//! names are the spec's where known and unknown fields are shown raw. No
//! DWG writer was available (AutoCAD and the ODA File Converter are not
//! installed; ezdxf only writes DXF), so the fixtures are synthetic, built
//! from the same understanding: the snapshots show self-consistency, not
//! conformance. The handle check in the object list (each object's own
//! handle must match the object map) is the built-in sanity check on real
//! files.
//!
//! - **R13 to R2000** (`AC1012`, `AC1014`, `AC1015`): a file header with
//!   section locator records (header variables, classes, object map, ...)
//!   pointing at sections at absolute offsets, and the preview image at an
//!   offset in the header.
//! - **R2004, R2010, R2013, R2018** (`AC1018`, `AC1024`, `AC1027`,
//!   `AC1032`): a file header, then 0x6c bytes XOR-encrypted with a
//!   pseudo-random sequence that locate the section page map; that map
//!   gives the file address of every page, and the section map (itself a
//!   page) lists the named sections (`AcDb:Header`, `AcDb:Classes`,
//!   `AcDb:Handles`, `AcDb:AcDbObjects`, `AcDb:Preview`,
//!   `AcDb:SummaryInfo`, `AcDb:AppInfo`, ...) and their pages. Each page
//!   has a 32-byte header encrypted with its address and holds up to
//!   0x7400 bytes, compressed with the DWG LZ77 variant
//!   ([`crate::codec::dwg`]). Sections are assembled from their pages
//!   without copying (a piece list over the decoded pages).
//! - **R2007** (`AC1021`) protects its header and system pages with a
//!   Reed-Solomon code and uses another LZ77 variant: only the plain file
//!   header is shown. Releases before R13 store entities in another layout
//!   altogether and get the version only.
//!
//! Inside the sections (see `dwg_data`): the classes list, the object map
//! (handle to location) with the type and handle of every object, the
//! preview images (BMP, WMF, PNG) as embedded files, the summary info
//! (title, author, dates, custom properties) and the application info.
//! Decoding objects beyond their type and handle (entity geometry, table
//! records) and the header variables is out of scope: those stay raw.

use std::sync::Arc;

use super::dwg_data;
use crate::bytes::{to_u64, u32_le, u64_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Radix, Value, flag};

const LE: Endian = Endian::Little;

/// DWG releases with distinct layouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Ver {
    Old,
    R13,
    R14,
    R2000,
    R2004,
    R2007,
    R2010,
    R2013,
    R2018,
}

fn ver_of(tag: &str) -> Ver {
    match tag {
        "AC1012" => Ver::R13,
        "AC1014" => Ver::R14,
        "AC1015" => Ver::R2000,
        "AC1018" => Ver::R2004,
        "AC1021" => Ver::R2007,
        "AC1024" => Ver::R2010,
        "AC1027" => Ver::R2013,
        "AC1032" => Ver::R2018,
        _ => Ver::Old,
    }
}

fn dwg_probe(h: &Head<'_>) -> bool {
    let tag = h.data.get(..6).unwrap_or_default();
    super::VERSIONS.iter().any(|(v, _)| v.as_bytes() == tag)
}

declare_format!(pub DWG = "dwg", "AutoCAD drawing", ["dwg"], "image/vnd.dwg",
    Probe::Custom(dwg_probe), dwg);

/// What a section holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Header,
    Classes,
    Handles,
    Objects,
    Preview,
    SummaryInfo,
    AppInfo,
    Other,
}

fn kind_of_name(name: &str) -> Kind {
    match name {
        "AcDb:Header" => Kind::Header,
        "AcDb:Classes" => Kind::Classes,
        "AcDb:Handles" => Kind::Handles,
        "AcDb:AcDbObjects" => Kind::Objects,
        "AcDb:Preview" => Kind::Preview,
        "AcDb:SummaryInfo" => Kind::SummaryInfo,
        "AcDb:AppInfo" => Kind::AppInfo,
        _ => Kind::Other,
    }
}

/// A page of an R2004+ section.
#[derive(Clone, Debug)]
pub(crate) struct Page {
    pub number: u32,
    /// File offset of the page (its encrypted header), relative to the input.
    pub address: Option<u64>,
    pub data_size: u64,
    pub start: u64,
    /// The page's entry in the section map.
    pub entry: Span,
}

/// A section: a locator record (R13 to R2000) or a named section (R2004+).
#[derive(Clone, Debug)]
pub(crate) struct Section {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    pub compressed: bool,
    pub encrypted: u32,
    pub pages: Vec<Page>,
    /// The section's contents: a span of the file, or of the piece list
    /// over its decoded pages.
    pub data: Span,
}

/// What the section dissectors need to know about the drawing.
#[derive(Debug)]
pub(crate) struct Drawing {
    pub input: Input,
    pub ver: Ver,
    pub maint: u8,
    /// The preview image address from the file header.
    pub preview: u64,
    pub sections: Vec<Section>,
}

impl Drawing {
    pub fn find(&self, kind: Kind) -> Option<&Section> {
        self.sections.iter().find(|s| s.kind == kind)
    }

    /// Where object map locations point: the file (R13 to R2000) or the
    /// `AcDb:AcDbObjects` section.
    pub fn objects(&self) -> Option<Span> {
        if self.ver >= Ver::R2004 {
            self.find(Kind::Objects).map(|s| s.data)
        } else {
            Some(self.input.span)
        }
    }
}

const CODE_PAGES: EnumTable = &[
    (0, "UTF-8"),
    (1, "US ASCII"),
    (2, "ISO 8859-1"),
    (3, "ISO 8859-2"),
    (28, "ANSI 1250"),
    (29, "ANSI 1251"),
    (30, "ANSI 1252"),
    (31, "ANSI 1253"),
    (32, "ANSI 1254"),
    (33, "ANSI 1255"),
    (34, "ANSI 1256"),
    (35, "ANSI 1257"),
    (36, "ANSI 874"),
    (37, "ANSI 932"),
    (38, "ANSI 936"),
    (39, "ANSI 949"),
    (40, "ANSI 950"),
];

async fn dwg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x19)).await?;
    let tag = String::from_utf8_lossy(head.get(..6).unwrap_or_default()).into_owned();
    let release = super::release(&tag).unwrap_or("unknown release");
    cx.annotate(format!("{release} drawing ({tag})"));
    let ver = ver_of(&tag);
    match ver {
        Ver::Old => {
            cx.emit(
                Node::new("Version")
                    .span(file.sub(0, 6))
                    .value(Value::Text(tag))
                    .summary(release),
            );
            cx.diag(Diagnostic::unsupported(
                "drawings before R13 use another layout; only the version is shown",
            ));
            Ok(())
        }
        Ver::R13 | Ver::R14 | Ver::R2000 => r13(cx, input, ver).await,
        Ver::R2007 => {
            cx.emit(
                Node::new("File header")
                    .span(file.sub(0, 0x80))
                    .lazy(file_header_r2004, (file, false)),
            );
            cx.diag(Diagnostic::unsupported(
                "the R2007 layout (Reed-Solomon coded header and pages, its own LZ77) is not decoded",
            ));
            Ok(())
        }
        _ => r2004(cx, input, ver).await,
    }
}

// ---------------------------------------------------------------------------
// R13 to R2000

const LOCATORS: EnumTable = &[
    (0, "Header variables"),
    (1, "Classes"),
    (2, "Object map"),
    (3, "Object free space"),
    (4, "Template"),
    (5, "Second header"),
];

const SENTINEL_FILE_HEADER: [u8; 16] = [
    0x95, 0xa0, 0x4e, 0x28, 0x99, 0x82, 0x1a, 0xe5, 0x5e, 0x41, 0xe0, 0x5f, 0x9d, 0x3a, 0x4d, 0x00,
];

async fn r13(cx: Cx, input: Input, ver: Ver) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x19)).await?;
    let count = u32_le(&head, 0x15).unwrap_or(0);
    let maint = head.get(0x0b).copied().unwrap_or(0);
    let preview = u64::from(u32_le(&head, 0x0d).unwrap_or(0));
    // Count plus records of 9 bytes, the CRC and the sentinel.
    let records_len = u64::from(count).saturating_mul(9);
    let header_len = 0x19u64.saturating_add(records_len).saturating_add(18);
    let records = cx
        .read(file.sub_exact(0x19, records_len.min(file.len))?)
        .await?;
    cx.emit(
        Node::new("File header")
            .span(file.sub(0, header_len))
            .lazy(file_header_r13, file),
    );
    let mut sections = Vec::new();
    for rec in records.as_chunks::<9>().0 {
        cx.checkpoint().await;
        let number = rec.first().copied().unwrap_or(0);
        let seeker = u64::from(u32_le(rec, 1).unwrap_or(0));
        let size = u64::from(u32_le(rec, 5).unwrap_or(0));
        let name = crate::value::lookup(LOCATORS, number.into())
            .map_or_else(|| format!("Section {number}"), str::to_owned);
        let kind = match number {
            0 => Kind::Header,
            1 => Kind::Classes,
            2 => Kind::Handles,
            _ => Kind::Other,
        };
        sections.push(Section {
            name,
            kind,
            size,
            compressed: false,
            encrypted: 0,
            pages: Vec::new(),
            data: file.sub(seeker, size),
        });
    }
    let drawing = Arc::new(Drawing {
        input,
        ver,
        maint,
        preview,
        sections,
    });
    for (i, s) in drawing.sections.iter().enumerate() {
        cx.checkpoint().await;
        let mut node = Node::new(s.name.clone())
            .span(s.data)
            .summary(format!("{:#x} bytes", s.size));
        if s.data.len < s.size {
            node = node.diag(Diagnostic::truncated(
                Span::new(s.data.source, s.data.offset, s.size),
                s.data.len,
            ));
        }
        cx.emit(node.lazy(section, (drawing.clone(), i)));
        if s.kind == Kind::Handles {
            cx.emit(
                Node::new("Objects")
                    .span(file)
                    .desc("The objects listed in the object map")
                    .lazy(dwg_data::objects, drawing.clone()),
            );
        }
    }
    if preview != 0 && preview < file.len {
        let sentinel = cx.read_avail(file.sub(preview, 20)).await?;
        let size = u64::from(u32_le(&sentinel, 16).unwrap_or(0));
        let span = file.sub(preview, size.saturating_add(36));
        cx.emit(
            Node::new("Preview")
                .span(span)
                .lazy(preview_r13, (drawing.clone(), span)),
        );
    }
    Ok(())
}

async fn preview_r13(cx: Cx, (d, span): (Arc<Drawing>, Span)) -> Result<()> {
    dwg_data::preview(&cx, &d, span, d.preview).await
}

async fn file_header_r13(cx: Cx, file: Span) -> Result<()> {
    let head = cx.read_avail(file.sub(0x15, 4)).await?;
    let count = u64::from(u32_le(&head, 0).unwrap_or(0));
    let len = 0x19u64.saturating_add(count.saturating_mul(9));
    let block = cx.block(file.sub(0, len.saturating_add(18))).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    common_header(&mut f)?;
    f.u32("Section locator records").emit()?;
    for _ in 0..count {
        cx.checkpoint().await;
        let at = f.pos();
        let rec = Fields::new(&block, LE);
        let mut rec = rec;
        rec.seek(at);
        let number = rec.u8("Record number").get()?;
        let seeker = rec.u32("Seeker").get()?;
        let size = rec.u32("Size").get()?;
        let name = crate::value::lookup(LOCATORS, number.into()).unwrap_or("unknown");
        f.node(
            Node::new(format!("Record {number}"))
                .span(f.peek_span(9))
                .summary(format!("{name}: {size:#x} bytes at {seeker:#x}"))
                .target(file.sub(u64::from(seeker), u64::from(size)))
                .lazy(locator_record, f.peek_span(9)),
        );
        f.skip(9);
    }
    f.u16("CRC")
        .hex()
        .desc("CRC-16 of the header so far (seed 0xC0C1, XOR a constant by record count)")
        .emit()?;
    f.bytes("Sentinel", 16)
        .check(|s| {
            (s.as_slice() != SENTINEL_FILE_HEADER)
                .then(|| Diagnostic::warning("unexpected sentinel"))
        })
        .emit()?;
    Ok(())
}

async fn locator_record(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("Record number").enumeration(LOCATORS).emit()?;
    f.u32("Seeker").hex().emit()?;
    f.u32("Size").hex().emit()?;
    Ok(())
}

/// The fields shared by every R13+ file header (0x00 to 0x15).
fn common_header(f: &mut Fields<'_>) -> Result<()> {
    f.ascii("Version", 6)
        .with(|v, n| match super::release(v) {
            Some(r) => n.summary(r),
            None => n,
        })
        .emit()?;
    f.bytes("Zeros", 5).emit()?;
    f.u8("Maintenance release").emit()?;
    f.u8("Unknown").hex().emit()?;
    f.u32("Preview address").hex().emit()?;
    f.u8("Application version").emit()?;
    f.u8("Application maintenance release").emit()?;
    f.u16("Code page").enumeration(CODE_PAGES).emit()?;
    Ok(())
}

async fn section(cx: Cx, (d, i): (Arc<Drawing>, usize)) -> Result<()> {
    let s = d
        .sections
        .get(i)
        .ok_or_else(|| Diagnostic::internal("no such section"))?;
    if !s.pages.is_empty() {
        cx.emit(
            Node::new("Pages")
                .summary(format!("{}", s.pages.len()))
                .lazy(pages, (d.clone(), i)),
        );
    }
    if s.encrypted == 1 {
        return Err(Diagnostic::unsupported("encrypted section").at(s.data));
    }
    match s.kind {
        Kind::Header => dwg_data::header_vars(&cx, &d, s.data).await,
        Kind::Classes => dwg_data::classes_node(&cx, &d, s.data).await,
        Kind::Handles => dwg_data::object_map(&cx, s.data).await,
        Kind::Objects => dwg_data::objects(cx, d.clone()).await,
        Kind::Preview => dwg_data::preview(&cx, &d, s.data, d.preview).await,
        Kind::SummaryInfo => dwg_data::summary_info(&cx, &d, s.data).await,
        Kind::AppInfo => dwg_data::app_info(&cx, &d, s.data).await,
        Kind::Other => {
            cx.emit(Node::new("Data").span(s.data));
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// R2004 and later

/// The XOR mask of the encrypted header: the MSVC `rand()` sequence from
/// seed 1, one byte (bits 16..24) per step.
fn header_mask(len: usize) -> Vec<u8> {
    let mut seed = 1u32;
    (0..len)
        .map(|_| {
            seed = seed.wrapping_mul(0x343fd).wrapping_add(0x269ec3);
            u8::try_from(seed >> 16 & 0xff).unwrap_or(0)
        })
        .collect()
}

const PAGE_MAP_TYPE: u32 = 0x4163_0e3b;
const SECTION_MAP_TYPE: u32 = 0x4163_003b;
const DATA_PAGE_TYPE: u32 = 0x4163_043b;
/// Page header XOR constant (combined with the page's file address).
const PAGE_HEADER_MASK: u32 = 0x4164_536b;
/// Where the page addresses of the section page map start.
const PAGES_START: u64 = 0x100;

const SECURITY: FlagTable = &[
    flag(0x1, "ENCRYPT_DATA"),
    flag(0x2, "ENCRYPT_PROPERTIES"),
    flag(0x10, "SIGN_DATA"),
    flag(0x20, "ADD_TIMESTAMP"),
];

const PAGE_TYPES: EnumTable = &[
    (PAGE_MAP_TYPE as u64, "section page map"),
    (SECTION_MAP_TYPE as u64, "section map"),
    (DATA_PAGE_TYPE as u64, "data page"),
];

const COMPRESSION: EnumTable = &[(1, "stored"), (2, "compressed")];
const ENCRYPTION: EnumTable = &[(0, "no"), (1, "yes"), (2, "unknown")];

/// The decrypted 0x6c-byte header.
async fn decrypted_header(cx: &Cx, file: Span) -> Result<Span> {
    let span = file.sub_exact(0x80, 0x6c)?;
    let origin = Origin {
        parent: span,
        transform: "dwg-header-xor",
    };
    if let Some(found) = cx.derived(origin) {
        return Ok(found.span);
    }
    let mut data = cx.read(span).await?;
    for (b, m) in data.iter_mut().zip(header_mask(0x6c)) {
        *b ^= m;
    }
    Ok(cx.add_derived(origin, data, 0x6c, None)?.span)
}

/// A system page (section page map, section map): header and decoded data.
async fn system_page(cx: &Cx, file: Span, address: u64) -> Result<(Span, Span)> {
    let header = file.sub_exact(address, 0x14)?;
    let h = cx.read(header).await?;
    let decompressed = u64::from(u32_le(&h, 4).unwrap_or(0));
    let compressed = u64::from(u32_le(&h, 8).unwrap_or(0));
    let method = u32_le(&h, 12).unwrap_or(0);
    let data = file.sub_exact(address.saturating_add(0x14), compressed)?;
    if method != 2 {
        return Ok((header, data.sub(0, decompressed)));
    }
    let decoded = crate::codec::decode_span(
        cx,
        data,
        &Codec::DwgLz77 { size: decompressed },
        Some(decompressed),
    )
    .await?;
    if let Some(e) = decoded.error {
        return Err(e);
    }
    Ok((header, decoded.span))
}

/// The section page map: (page number, address, size, entry span).
type PageMap = Vec<(i32, u64, u64, Span)>;

async fn parse_page_map(cx: &Cx, data: &[u8], span: Span) -> PageMap {
    let mut out: PageMap = Vec::new();
    let mut address = PAGES_START;
    let mut pos = 0usize;
    while let (Some(number), Some(size)) = (u32_le(data, pos), u32_le(data, pos.saturating_add(4)))
    {
        if out.len().is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        let number = i32::from_le_bytes(number.to_le_bytes());
        let len = if number < 0 { 24 } else { 8 };
        out.push((number, address, u64::from(size), span.sub(to_u64(pos), len)));
        address = address.saturating_add(u64::from(size));
        pos = pos.saturating_add(to_usize_saturating(len));
    }
    out
}

fn to_usize_saturating(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// A named section's description in the section map: fixed part.
const DESC_LEN: usize = 8 + 4 * 6 + 64;

async fn r2004(cx: Cx, input: Input, ver: Ver) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x80)).await?;
    let maint = head.get(0x0b).copied().unwrap_or(0);
    let preview = u64::from(u32_le(&head, 0x0d).unwrap_or(0));
    cx.emit(
        Node::new("File header")
            .span(file.sub(0, 0x80))
            .lazy(file_header_r2004, (file, true)),
    );
    let enc = decrypted_header(&cx, file).await?;
    let eh = cx.read(enc).await?;
    let magic_ok = eh.get(..11) == Some(b"AcFssFcAJMB".as_slice());
    let mut node = Node::new("Encrypted header")
        .span(file.sub(0x80, 0x6c))
        .summary("XOR-encrypted")
        .lazy(encrypted_header, enc);
    if !magic_ok {
        node = node.diag(Diagnostic::malformed(
            "decrypted header lacks its AcFssFcAJMB signature",
        ));
    }
    cx.emit(node);
    cx.emit(Node::new("Encrypted header padding").span(file.sub(0xec, 0x14)));
    if !magic_ok {
        return Ok(());
    }
    let map_id = u32_le(&eh, 0x50).unwrap_or(0);
    let map_address = u64_le(&eh, 0x54).unwrap_or(0).saturating_add(PAGES_START);
    let section_map_id = u32_le(&eh, 0x5c).unwrap_or(0);
    let (map_header, map_data) = system_page(&cx, file, map_address).await?;
    let map_bytes = cx.read(map_data).await?;
    let page_map = parse_page_map(&cx, &map_bytes, map_data).await;
    cx.emit(
        Node::new("Section page map")
            .span(map_header.sub(0, 0x14))
            .summary(format!("page {map_id}, {} entries", page_map.len()))
            .lazy(page_map_node, (file, map_header, map_data)),
    );
    let Some(&(_, sm_address, _, _)) = page_map
        .iter()
        .find(|(n, ..)| u32::try_from(*n).ok() == Some(section_map_id))
    else {
        return Err(Diagnostic::malformed(format!(
            "section map page {section_map_id} is not in the page map"
        )));
    };
    let (sm_header, sm_data) = system_page(&cx, file, sm_address).await?;
    let sm = cx.read(sm_data).await?;
    let count = u32_le(&sm, 0).unwrap_or(0);
    cx.emit(
        Node::new("Section map")
            .span(sm_header)
            .summary(format!("{count} sections"))
            .lazy(section_map_node, (sm_header, sm_data)),
    );
    // Page number to address, the first entry winning (as a linear search
    // would), so that resolving every page is not quadratic.
    let mut addresses = std::collections::BTreeMap::new();
    for (i, &(n, a, _, _)) in page_map.iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        if let Ok(n) = u32::try_from(n) {
            addresses.entry(n).or_insert(a);
        }
    }
    let mut sections = Vec::new();
    let mut pos = 20usize;
    for _ in 0..count {
        cx.checkpoint().await;
        let Some(desc) = sm.get(pos..pos.saturating_add(DESC_LEN)) else {
            cx.diag(Diagnostic::truncated(
                sm_data.sub(to_u64(pos), to_u64(DESC_LEN)),
                to_u64(sm.len().saturating_sub(pos)),
            ));
            break;
        };
        let size = u64_le(desc, 0).unwrap_or(0);
        let page_count = u32_le(desc, 8).unwrap_or(0);
        let max_size = u64::from(u32_le(desc, 12).unwrap_or(0));
        let compressed = u32_le(desc, 20).unwrap_or(0) == 2;
        let encrypted = u32_le(desc, 28).unwrap_or(0);
        let name = crate::text::until_nul(desc.get(32..96).unwrap_or_default());
        let desc_span = sm_data.sub(to_u64(pos), to_u64(DESC_LEN));
        pos = pos.saturating_add(DESC_LEN);
        let mut pages = Vec::new();
        for k in 0..page_count {
            if k > 0 && k.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            let Some(p) = sm.get(pos..pos.saturating_add(16)) else {
                break;
            };
            let number = u32_le(p, 0).unwrap_or(0);
            pages.push(Page {
                number,
                address: addresses.get(&number).copied(),
                data_size: u64::from(u32_le(p, 4).unwrap_or(0)),
                start: u64_le(p, 8).unwrap_or(0),
                entry: sm_data.sub(to_u64(pos), 16),
            });
            pos = pos.saturating_add(16);
        }
        let data = assemble(&cx, file, desc_span, size, max_size, compressed, &pages).await?;
        sections.push(Section {
            kind: kind_of_name(&name),
            name,
            size,
            compressed,
            encrypted,
            pages,
            data,
        });
    }
    let drawing = Arc::new(Drawing {
        input,
        ver,
        maint,
        preview,
        sections,
    });
    for (i, s) in drawing.sections.iter().enumerate() {
        cx.checkpoint().await;
        if s.name.is_empty() && s.size == 0 {
            continue;
        }
        let name = if s.name.is_empty() {
            "(unnamed)".to_owned()
        } else {
            s.name.clone()
        };
        let pages = s.pages.len();
        let how = if s.compressed { "compressed" } else { "stored" };
        cx.emit(
            Node::new(name)
                .span(s.data)
                .summary(format!(
                    "{:#x} bytes in {pages} page{}, {how}",
                    s.size,
                    if pages == 1 { "" } else { "s" }
                ))
                .lazy(section, (drawing.clone(), i)),
        );
    }
    Ok(())
}

/// The section's contents as a piece list over its (lazily decoded) pages.
async fn assemble(
    cx: &Cx,
    file: Span,
    desc: Span,
    size: u64,
    max_size: u64,
    compressed: bool,
    pages: &[Page],
) -> Result<Span> {
    let mut pieces = Vec::new();
    let mut at = 0u64;
    for (i, page) in pages.iter().enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let Some(address) = page.address else {
            continue;
        };
        if page.start < at || page.start >= size {
            continue;
        }
        if page.start > at {
            pieces.push(Span::zeros(page.start.saturating_sub(at)));
        }
        let len = size.saturating_sub(page.start).min(max_size.max(1));
        let data = file.sub(address.saturating_add(32), page.data_size);
        let decoded = if compressed {
            cx.decode_lazy(data, &Codec::DwgLz77 { size: len }, len)?
        } else {
            data.sub(0, len)
        };
        pieces.push(decoded);
        at = page.start.saturating_add(len);
    }
    cx.add_pieces_stepped(
        Origin {
            parent: desc,
            transform: "dwg-section",
        },
        &pieces,
    )
    .await
}

async fn file_header_r2004(cx: Cx, (file, full): (Span, bool)) -> Result<()> {
    let block = cx.block(file.sub(0, 0x80)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    common_header(&mut f)?;
    if !full {
        return Ok(());
    }
    f.bytes("Zeros", 3).emit()?;
    f.u32("Security flags").flags(SECURITY).emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("Summary info address").hex().emit()?;
    f.u32("VBA project address").hex().emit()?;
    f.u32("Encrypted header address").hex().emit()?;
    f.bytes("Padding", 0x80u64.saturating_sub(f.pos())).emit()?;
    Ok(())
}

async fn encrypted_header(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.cstr("File ID").emit()?;
    f.seek(12);
    f.u32("Unknown").hex().emit()?;
    f.u32("Header size").hex().emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("Root tree node gap").emit()?;
    f.u32("Lowermost left tree node gap").emit()?;
    f.u32("Lowermost right tree node gap").emit()?;
    f.u32("Unknown").emit()?;
    f.u32("Last section page ID").emit()?;
    f.u64("Last section page end address").hex().emit()?;
    f.u64("Second header address").hex().emit()?;
    f.u32("Gap amount").emit()?;
    f.u32("Section page amount").emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("Section page map ID").emit()?;
    f.u64("Section page map address")
        .hex()
        .desc("Relative to 0x100")
        .emit()?;
    f.u32("Section map ID").emit()?;
    f.u32("Section page array size").emit()?;
    f.u32("Gap array size").emit()?;
    f.u32("CRC-32").hex().emit()?;
    Ok(())
}

fn system_page_header(f: &mut Fields<'_>) -> Result<()> {
    f.u32("Page type").hex().enumeration(PAGE_TYPES).emit()?;
    f.u32("Decompressed size").hex().emit()?;
    f.u32("Compressed size").hex().emit()?;
    f.u32("Compression").enumeration(COMPRESSION).emit()?;
    f.u32("Checksum").hex().emit()?;
    Ok(())
}

async fn page_map_node(cx: Cx, (file, header, data): (Span, Span, Span)) -> Result<()> {
    let block = cx.block(header).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    system_page_header(&mut f)?;
    let bytes = cx.read(data).await?;
    let map = parse_page_map(&cx, &bytes, data).await;
    cx.set_count(Count::Exact(to_u64(map.len()).saturating_add(5)));
    for (number, address, size, entry) in map {
        let (name, summary) = if number < 0 {
            ("Gap".to_owned(), format!("{size:#x} bytes at {address:#x}"))
        } else {
            (
                format!("Page {number}"),
                format!("{size:#x} bytes at {address:#x}"),
            )
        };
        cx.push(
            Node::new(name)
                .span(entry)
                .summary(summary)
                .target(file.sub(address, size))
                .lazy(page_map_entry, (entry, number < 0)),
        )
        .await;
    }
    Ok(())
}

async fn page_map_entry(cx: Cx, (span, gap): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.int::<i32>("Page number").emit()?;
    f.u32("Size").hex().emit()?;
    if gap {
        f.u32("Parent").emit()?;
        f.u32("Left").emit()?;
        f.u32("Right").emit()?;
        f.u32("Zero").emit()?;
    }
    Ok(())
}

async fn section_map_node(cx: Cx, (header, data): (Span, Span)) -> Result<()> {
    let block = cx.block(header).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    system_page_header(&mut f)?;
    let block = cx.block(data).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let count = f.u32("Section count").emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("Maximum page size").hex().emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("Section count (again)").emit()?;
    for _ in 0..count {
        if f.remaining() < to_u64(DESC_LEN) {
            break;
        }
        let start = f.pos();
        let name_bytes = block
            .data
            .get(to_usize_saturating(start).saturating_add(32)..)
            .unwrap_or_default();
        let name = crate::text::until_nul(name_bytes.get(..64).unwrap_or(name_bytes));
        let pages = u64::from(
            u32_le(
                block
                    .data
                    .get(to_usize_saturating(start)..)
                    .unwrap_or_default(),
                8,
            )
            .unwrap_or(0),
        );
        let len = to_u64(DESC_LEN).saturating_add(pages.saturating_mul(16));
        let span = f.peek_span(len);
        f.node(
            Node::new(if name.is_empty() {
                "(unnamed)".to_owned()
            } else {
                name
            })
            .span(span)
            .lazy(section_desc, span),
        );
        f.skip(len);
        cx.checkpoint().await;
    }
    Ok(())
}

async fn section_desc(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u64("Size").hex().emit()?;
    let pages = f.u32("Page count").emit()?;
    f.u32("Maximum page size").hex().emit()?;
    f.u32("Unknown").emit()?;
    f.u32("Compression").enumeration(COMPRESSION).emit()?;
    f.u32("Section ID").emit()?;
    f.u32("Encrypted").enumeration(ENCRYPTION).emit()?;
    let name = f.peek_span(64);
    f.cstr("Name").emit()?;
    f.seek(name.offset.saturating_sub(span.offset).saturating_add(64));
    for _ in 0..pages {
        if f.remaining() < 16 {
            break;
        }
        cx.checkpoint().await;
        let entry = f.peek_span(16);
        f.node(Node::new("Page").span(entry).lazy(page_entry, entry));
        f.skip(16);
    }
    Ok(())
}

async fn page_entry(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Page number").emit()?;
    f.u32("Data size").hex().emit()?;
    f.u64("Start offset").hex().emit()?;
    Ok(())
}

/// The pages of a named section, with their decrypted headers.
async fn pages(cx: Cx, (d, i): (Arc<Drawing>, usize)) -> Result<()> {
    let s = d
        .sections
        .get(i)
        .ok_or_else(|| Diagnostic::internal("no such section"))?;
    let file = d.input.span;
    cx.set_count(Count::Exact(to_u64(s.pages.len())));
    for page in &s.pages {
        let mut node = Node::new(format!("Page {}", page.number))
            .summary(format!(
                "{:#x} bytes at section offset {:#x}",
                page.data_size, page.start
            ))
            .target(page.entry);
        match page.address {
            Some(address) => {
                let span = file.sub(address, page.data_size.saturating_add(32));
                node = node
                    .span(span)
                    .lazy(page_node, (d.input, address, s.compressed));
            }
            None => {
                node = node.diag(Diagnostic::malformed("page not in the section page map"));
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn page_node(cx: Cx, (input, address, compressed): (Input, u64, bool)) -> Result<()> {
    let file = input.span;
    let span = file.sub_exact(address, 32)?;
    let origin = Origin {
        parent: span,
        transform: "dwg-page-header",
    };
    let header = match cx.derived(origin) {
        Some(found) => found.span,
        None => {
            let mut data = cx.read(span).await?;
            let mask = PAGE_HEADER_MASK ^ u32::try_from(address & 0xffff_ffff).unwrap_or(0);
            for (i, b) in data.iter_mut().enumerate() {
                let m = mask.to_le_bytes();
                *b ^= m.get(i % 4).copied().unwrap_or(0);
            }
            cx.add_derived(origin, data, 32, None)?.span
        }
    };
    let block = cx.block(header).await?;
    let mut f = Fields::new(&block, LE);
    let kind = f.u32("Page type").get()?;
    let _ = f.u32("Section ID").get()?;
    let data_size = u64::from(f.u32("Data size").get()?);
    let page_size = u64::from(f.u32("Page size").get()?);
    cx.emit(
        Node::new("Header")
            .span(span)
            .summary("encrypted with the page address")
            .lazy(page_header, header),
    );
    let data = file.sub(address.saturating_add(32), data_size);
    let mut node = if compressed {
        crate::formats::content(
            "Data",
            input,
            data,
            Codec::DwgLz77 { size: page_size },
            Some(page_size),
        )
    } else {
        Node::new("Data").span(data)
    };
    if u64::from(kind) != u64::from(DATA_PAGE_TYPE) {
        node = node.diag(Diagnostic::warning(format!("page type {kind:#x}")));
    }
    cx.emit(node);
    Ok(())
}

async fn page_header(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Page type").hex().enumeration(PAGE_TYPES).emit()?;
    f.u32("Section ID").emit()?;
    f.u32("Data size").hex().emit()?;
    f.u32("Page size").hex().emit()?;
    f.u32("Start offset").hex().emit()?;
    f.u32("Header checksum").hex().emit()?;
    f.u32("Data checksum").hex().emit()?;
    f.u32("Unknown").hex().emit()?;
    Ok(())
}

/// `Value::UInt` in hex.
pub(crate) fn hex(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Hex,
    }
}

/// `Value::UInt` in decimal.
pub(crate) fn uint(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// The start of the mask the ODA spec prints for the encrypted header.
    #[test]
    fn mask() {
        let m = header_mask(4);
        assert_eq!(m, [0x29, 0x23, 0xbe, 0x84]);
    }
}
