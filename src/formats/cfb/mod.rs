//! OLE2 Compound File Binary (CFB): the container of legacy Office
//! documents, MSI installers, Outlook messages, Thumbs.db and more.
//!
//! Expanding the file reads the header, the DIFAT (to locate FAT sectors),
//! and the directory chain. Sector chains are followed through the FAT on
//! demand, with cycle detection, and every chain becomes a piecewise source:
//! the directory, the MiniFAT, the mini stream (itself built from regular
//! sectors) and each stream. Streams are then shown by well-known decoders
//! (property sets, Word FIB, Excel BIFF, PowerPoint records, Outlook
//! properties, Thumbs.db catalogs) or detected as embedded files.
//!
//! The directory is a red-black tree per storage; it is walked in order with
//! a visited set, and storages carry the path of entries above them.

mod apps;
mod biff;
mod msg;
mod msi;
mod officeart;
mod ppt;
mod propset;
mod ptg;
mod rec;
mod sprm;
mod thumbs;
mod vba;
mod word;

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Radix, Value};

const LE: Endian = Endian::Little;
const MAGIC: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const ENTRY: u64 = 128;
const NO_STREAM: u32 = 0xffff_ffff;
const END_OF_CHAIN: u32 = 0xffff_fffe;
const MAX_REGULAR: u32 = 0xffff_fffa;
/// Deepest storage nesting followed.
const MAX_DEPTH: usize = 32;
/// Root children looked at to recognise the application.
const MAX_ROOT_SCAN: usize = 4096;

// ---------------------------------------------------------------------------
// Formats

macro_rules! cfb_format {
    ($id:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $probe:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom($probe),
            dissect: crate::expander!(dissect: Input),
        };
    };
}

cfb_format!(
    DOC,
    "doc",
    "Microsoft Word 97-2003 document",
    ["doc", "dot"],
    "application/msword",
    |h| probe_names(h).iter().any(|n| n == "WordDocument")
);
cfb_format!(
    XLS,
    "xls",
    "Microsoft Excel 97-2003 workbook",
    ["xls", "xlt", "xla"],
    "application/vnd.ms-excel",
    |h| probe_names(h)
        .iter()
        .any(|n| n == "Workbook" || n == "Book")
);
cfb_format!(
    PPT,
    "ppt",
    "Microsoft PowerPoint 97-2003 presentation",
    ["ppt", "pps", "pot"],
    "application/vnd.ms-powerpoint",
    |h| probe_names(h).iter().any(|n| n == "PowerPoint Document")
);
cfb_format!(
    MSG,
    "msg",
    "Microsoft Outlook message",
    ["msg", "oft"],
    "application/vnd.ms-outlook",
    |h| probe_names(h)
        .iter()
        .any(|n| n == "__properties_version1.0" || n == "__nameid_version1.0")
);
cfb_format!(
    MSI,
    "msi",
    "Windows Installer package",
    ["msi", "msp", "mst"],
    "application/x-msi",
    |h| probe_root_clsid(h).is_some_and(|c| apps::installer_kind(&c).is_some())
);
cfb_format!(
    THUMBS,
    "thumbsdb",
    "Windows thumbnail cache (Thumbs.db)",
    ["db"],
    "application/octet-stream",
    |h| probe_names(h).iter().any(|n| n == "Catalog")
);
cfb_format!(
    PUBLISHER,
    "publisher",
    "Microsoft Publisher document",
    ["pub", "puz"],
    "application/vnd.ms-publisher",
    |h| {
        let n = probe_names(h);
        n.iter().any(|n| n == "Quill") && n.iter().any(|n| n == "Contents")
    }
);
cfb_format!(
    FORMAT,
    "cfb",
    "OLE2 Compound File",
    ["ole", "ole2", "cfb", "vsd", "pub", "mpp", "wps", "sldprt"],
    "application/x-ole-storage",
    |h| h.starts_with(MAGIC)
);

/// Byte offset of the first directory sector, as seen by a probe.
fn probe_directory(h: &Head<'_>) -> Option<(usize, usize)> {
    if !h.starts_with(MAGIC) {
        return None;
    }
    let shift = u16_le(h.data, 30)?;
    if shift != 9 && shift != 12 {
        return None;
    }
    let size = 1usize << shift;
    let first = usize::try_from(u32_le(h.data, 48)?).ok()?;
    let offset = first.checked_add(1)?.checked_mul(size)?;
    Some((offset, size))
}

/// Names of the directory entries visible to a probe: the directory chain
/// is followed through the first FAT sector while both lie in the window.
fn probe_names(h: &Head<'_>) -> Vec<String> {
    const MAX_SECTORS: usize = 64;
    let mut names = Vec::new();
    let Some((_, size)) = probe_directory(h) else {
        return names;
    };
    let fat = u32_le(h.data, 76)
        .and_then(|s| usize::try_from(s).ok()?.checked_add(1)?.checked_mul(size))
        .and_then(|at| h.data.get(at..at.checked_add(size)?));
    let mut sector = u32_le(h.data, 48);
    for _ in 0..MAX_SECTORS {
        let Some(s) = sector.filter(|&s| s < MAX_REGULAR) else {
            break;
        };
        let Some(data) = usize::try_from(s)
            .ok()
            .and_then(|s| s.checked_add(1)?.checked_mul(size))
            .and_then(|at| h.data.get(at..at.checked_add(size)?))
        else {
            break;
        };
        names.extend(data.as_chunks::<128>().0.iter().filter_map(|e| {
            let len = usize::from(u16_le(e, 64)?).min(64);
            let name = e.get(..len.saturating_sub(2))?;
            Some(crate::text::utf16(name, LE))
        }));
        sector = fat.and_then(|f| u32_le(f, usize::try_from(s).ok()?.checked_mul(4)?));
    }
    names
}

fn probe_root_clsid(h: &Head<'_>) -> Option<[u8; 16]> {
    let (offset, _) = probe_directory(h)?;
    crate::bytes::array(h.data, offset.checked_add(80)?)
}

// ---------------------------------------------------------------------------
// Structures

const OBJECT_TYPES: EnumTable = &[
    (0, "unallocated"),
    (1, "storage"),
    (2, "stream"),
    (5, "root storage"),
];
const COLORS: EnumTable = &[(0, "red"), (1, "black")];
const VERSIONS: EnumTable = &[(3, "version 3"), (4, "version 4")];
const BYTE_ORDERS: EnumTable = &[(0xfffe, "little-endian")];
const STATE_DESC: &str = "User-defined flags of the storage or stream";

record! {
    pub struct Header {
        signature: bytes[8] "Signature" .desc("D0 CF 11 E0 A1 B1 1A E1"),
        clsid: guid "CLSID" .desc("Reserved; all zeros"),
        minor: u16 "Minor version" .hex() .desc("0x003E (some writers use 0x003B)"),
        major: u16 "Major version" .enumeration(VERSIONS),
        byte_order: u16 "Byte order" .hex() .enumeration(BYTE_ORDERS),
        sector_shift: u16 "Sector shift" .with(|&s, n| n.summary(format!("{} bytes", 1u64.checked_shl(s.into()).unwrap_or(0)))),
        mini_shift: u16 "Mini sector shift" .with(|&s, n| n.summary(format!("{} bytes", 1u64.checked_shl(s.into()).unwrap_or(0)))),
        _reserved: bytes[6] "Reserved",
        dir_sectors: u32 "Number of directory sectors" .desc("Always 0 in version 3 files"),
        fat_sectors: u32 "Number of FAT sectors",
        first_dir: u32 "First directory sector" .with(|&s, n| n.summary(sector_name(s))),
        transaction: u32 "Transaction signature" .desc("Unused (0) unless the file supports transactions"),
        cutoff: u32 "Mini stream cutoff size" .desc("Streams smaller than this live in the mini stream"),
        first_minifat: u32 "First MiniFAT sector" .with(|&s, n| n.summary(sector_name(s))),
        minifat_sectors: u32 "Number of MiniFAT sectors",
        first_difat: u32 "First DIFAT sector" .with(|&s, n| n.summary(sector_name(s))),
        difat_sectors: u32 "Number of DIFAT sectors",
    }
}

record! {
    pub struct DirEntry {
        name: utf16[32] "Name",
        name_len: u16 "Name length" .desc("Bytes, including the terminating NUL"),
        kind: u8 "Object type" .enumeration(OBJECT_TYPES),
        color: u8 "Color" .enumeration(COLORS),
        left: u32 "Left sibling" .with(|&s, n| n.summary(entry_ref(s))) .desc("Red-black tree: the sibling that sorts before this entry (shorter names first, then case-insensitively)"),
        right: u32 "Right sibling" .with(|&s, n| n.summary(entry_ref(s))) .desc("Red-black tree: the sibling that sorts after this entry"),
        child: u32 "Child" .with(|&s, n| n.summary(entry_ref(s))) .desc("Root of the red-black tree of a storage's children"),
        clsid: guid "CLSID",
        state: u32 "State bits" .hex() .desc(STATE_DESC),
        created: u64 "Creation time" .filetime(),
        modified: u64 "Modification time" .filetime(),
        start: u32 "Starting sector" .with(|&s, n| n.summary(sector_name(s))) .desc("First sector of the stream (a mini sector if the stream is smaller than the cutoff; for the root, the mini stream)"),
        size: u64 "Stream size" .desc("Version 3 files only use the low 32 bits"),
    }
}

fn sector_name(s: u32) -> String {
    match s {
        0xffff_ffff => "FREESECT".to_owned(),
        0xffff_fffe => "ENDOFCHAIN".to_owned(),
        0xffff_fffd => "FATSECT".to_owned(),
        0xffff_fffc => "DIFSECT".to_owned(),
        n => format!("sector {n}"),
    }
}

fn entry_ref(s: u32) -> String {
    if s == NO_STREAM {
        "none".to_owned()
    } else {
        format!("entry {s}")
    }
}

/// A directory entry name for display: control characters (such as the
/// `\x05` of property set streams) escaped, MSI names decoded.
fn display_name(raw: &str) -> String {
    let decoded = apps::msi_name(raw).unwrap_or_else(|| raw.to_owned());
    decoded
        .chars()
        .map(|c| {
            if c.is_control() {
                format!("\\x{:02x}", u32::from(c))
            } else {
                c.to_string()
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The compound file model

pub struct Cfb {
    pub input: Input,
    pub sector: u64,
    pub mini: u64,
    pub cutoff: u64,
    pub version: u16,
    /// FAT sector numbers, in order (from the DIFAT).
    fat: Vec<u32>,
    /// The directory, the MiniFAT and the mini stream as piecewise sources.
    dir: Span,
    minifat: Option<Span>,
    mini_stream: Option<Span>,
    /// Sectors that exist in the file.
    sectors: u64,
}

pub type CfbRef = Arc<Cfb>;

impl Cfb {
    fn sector_span(&self, s: u32) -> Span {
        let offset = u64::from(s).saturating_add(1).saturating_mul(self.sector);
        self.input.span.sub(offset, self.sector)
    }

    pub fn entries(&self) -> u64 {
        self.dir.len / ENTRY
    }

    pub fn entry_span(&self, id: u32) -> Span {
        self.dir.sub(u64::from(id).saturating_mul(ENTRY), ENTRY)
    }
}

/// The FAT entry for sector `s`: the next sector in its chain.
async fn fat_next(cx: &Cx, fat: &[u32], sector: u64, input: Span, s: u32) -> Result<u32> {
    let per = sector / 4;
    let index = u64::from(s).checked_div(per).unwrap_or(0);
    let fat_sector = fat
        .get(to_usize(index))
        .copied()
        .ok_or_else(|| Diagnostic::malformed(format!("sector {s} is beyond the FAT")))?;
    let offset = u64::from(fat_sector)
        .saturating_add(1)
        .saturating_mul(sector)
        .saturating_add(u64::from(s).checked_rem(per).unwrap_or(0).saturating_mul(4));
    let data = cx.read(input.sub_exact(offset, 4)?).await?;
    Ok(u32_le(&data, 0).unwrap_or(END_OF_CHAIN))
}

/// Which allocation table a chain is followed through.
#[derive(Clone, Copy)]
enum Table<'a> {
    Fat {
        fat: &'a [u32],
        sector: u64,
        input: Span,
    },
    Mini(Span),
}

impl Table<'_> {
    async fn next(&self, cx: &Cx, s: u32) -> Result<u32> {
        match *self {
            Table::Fat { fat, sector, input } => fat_next(cx, fat, sector, input, s).await,
            Table::Mini(minifat) => {
                let data = cx
                    .read(minifat.sub_exact(u64::from(s).saturating_mul(4), 4)?)
                    .await?;
                Ok(u32_le(&data, 0).unwrap_or(END_OF_CHAIN))
            }
        }
    }
}

/// Follows a chain from `start`, at most `limit` sectors. Returns the
/// sectors and, if the chain did not end cleanly, why.
async fn follow(
    cx: &Cx,
    table: Table<'_>,
    start: u32,
    limit: u64,
) -> (Vec<u32>, Option<Diagnostic>) {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut s = start;
    while s != END_OF_CHAIN {
        cx.checkpoint().await;
        if s >= MAX_REGULAR {
            return (
                out,
                Some(Diagnostic::malformed(format!(
                    "chain reaches {}",
                    sector_name(s)
                ))),
            );
        }
        if !seen.insert(s) {
            return (
                out,
                Some(Diagnostic::malformed(format!(
                    "chain loops back to sector {s}"
                ))),
            );
        }
        if to_u64(out.len()) >= limit {
            return (
                out,
                Some(Diagnostic::warning(format!(
                    "chain is longer than the {limit} sectors expected"
                ))),
            );
        }
        out.push(s);
        s = match table.next(cx, s).await {
            Ok(n) => n,
            Err(e) => return (out, Some(e)),
        };
    }
    (out, None)
}

/// A regular (FAT) chain.
async fn fat_chain(
    cx: &Cx,
    fat: &[u32],
    sector: u64,
    input: Span,
    start: u32,
    limit: u64,
) -> (Vec<u32>, Option<Diagnostic>) {
    follow(cx, Table::Fat { fat, sector, input }, start, limit).await
}

/// Joins sector spans into as few pieces as possible (a chain can run to
/// millions of sectors).
async fn coalesce(cx: &Cx, spans: impl IntoIterator<Item = Span>) -> Vec<Span> {
    let mut out: Vec<Span> = Vec::new();
    for (i, span) in spans.into_iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        match out.last_mut() {
            Some(last) if last.source == span.source && last.end() == span.offset => {
                last.len = last.len.saturating_add(span.len);
            }
            _ => out.push(span),
        }
    }
    out
}

/// The size of a stream (version 3 files only use the low 32 bits).
pub fn stream_size(cfb: &Cfb, entry: &DirEntry) -> u64 {
    if cfb.version == 3 {
        entry.size & 0xffff_ffff
    } else {
        entry.size
    }
}

/// The sectors of a stream: whether they are mini sectors, the sector
/// numbers and their spans, and a diagnostic if the chain is broken.
async fn sectors_of(
    cx: &Cx,
    cfb: &Cfb,
    entry: &DirEntry,
) -> Result<(bool, Vec<(u32, Span)>, Option<Diagnostic>)> {
    let size = stream_size(cfb, entry);
    let in_mini = size < cfb.cutoff && entry.kind != 5;
    if size == 0 {
        return Ok((in_mini, Vec::new(), None));
    }
    if in_mini {
        let (Some(minifat), Some(mini_stream)) = (cfb.minifat, cfb.mini_stream) else {
            return Err(Diagnostic::malformed(
                "stream is in the mini stream, but there is none",
            ));
        };
        let limit = size.div_ceil(cfb.mini.max(1));
        let (chain, diag) = follow(cx, Table::Mini(minifat), entry.start, limit).await;
        let spans = with_spans(cx, chain, |m| {
            mini_stream.sub(u64::from(m).saturating_mul(cfb.mini), cfb.mini)
        })
        .await;
        Ok((true, spans, diag))
    } else {
        let limit = size.div_ceil(cfb.sector.max(1));
        let (chain, diag) =
            fat_chain(cx, &cfb.fat, cfb.sector, cfb.input.span, entry.start, limit).await;
        let spans = with_spans(cx, chain, |s| cfb.sector_span(s)).await;
        Ok((false, spans, diag))
    }
}

/// Pairs each sector of a chain with its span, yielding every few thousand.
async fn with_spans(cx: &Cx, chain: Vec<u32>, span: impl Fn(u32) -> Span) -> Vec<(u32, Span)> {
    let mut out = Vec::with_capacity(chain.len());
    for (i, s) in chain.into_iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        out.push((s, span(s)));
    }
    out
}

/// A stream's content as a piecewise source, cut to its size. Returns the
/// span and a diagnostic if its chain is broken or short.
pub async fn stream(
    cx: &Cx,
    cfb: &Cfb,
    id: u32,
    entry: &DirEntry,
) -> Result<(Span, Option<Diagnostic>)> {
    let size = stream_size(cfb, entry);
    let (_, sectors, diag) = sectors_of(cx, cfb, entry).await?;
    let pieces = coalesce(cx, sectors.into_iter().map(|(_, span)| span)).await;
    let all = cx
        .add_pieces_stepped(
            Origin {
                parent: cfb.entry_span(id),
                transform: "cfb-chain",
            },
            &pieces,
        )
        .await?;
    let span = all.sub(0, size);
    let diag = diag.or_else(|| {
        (span.len < size).then(|| Diagnostic::truncated(Span::new(span.source, 0, size), span.len))
    });
    Ok((span, diag))
}

pub async fn read_entry(cx: &Cx, cfb: &Cfb, id: u32) -> Result<DirEntry> {
    if u64::from(id) >= cfb.entries() {
        return Err(Diagnostic::malformed(format!(
            "directory entry {id} does not exist ({} entries)",
            cfb.entries()
        )));
    }
    crate::fields::parse(cx, cfb.entry_span(id), LE, &(), DirEntry::layout).await
}

/// The name of an entry, as stored (up to its declared length).
fn entry_name(entry: &DirEntry) -> String {
    let units = usize::from(entry.name_len / 2).saturating_sub(1).min(31);
    entry.name.chars().take(units).collect()
}

/// The child of `storage` named `name`.
pub async fn find_child(cx: &Cx, cfb: &Cfb, storage: u32, name: &str) -> Option<(u32, DirEntry)> {
    let parent = read_entry(cx, cfb, storage).await.ok()?;
    let mut walk = TreeWalk::new(parent.child);
    let mut scanned = 0usize;
    while let Some((id, entry)) = walk.next(cx, cfb).await {
        if entry_name(&entry) == name {
            return Some((id, entry));
        }
        scanned = scanned.saturating_add(1);
        if scanned > MAX_ROOT_SCAN {
            break;
        }
    }
    None
}

/// The content of the stream `name` in `storage`.
pub async fn child_stream(cx: &Cx, cfb: &Cfb, storage: u32, name: &str) -> Option<Span> {
    let (id, entry) = find_child(cx, cfb, storage, name).await?;
    if entry.kind != 2 {
        return None;
    }
    stream(cx, cfb, id, &entry).await.ok().map(|(s, _)| s)
}

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, 76);
    cx.emit(Header::node("Header", header_span, LE));
    let header = crate::fields::parse(&cx, header_span, LE, &(), Header::layout).await?;
    if header.signature != MAGIC {
        return Err(Diagnostic::malformed("not a compound file").at(header_span.sub(0, 8)));
    }
    if header.sector_shift != 9 && header.sector_shift != 12 {
        return Err(Diagnostic::malformed(format!(
            "sector shift {} is not 9 or 12",
            header.sector_shift
        ))
        .at(header_span.sub(30, 2)));
    }
    if header.mini_shift != 6 {
        return Err(
            Diagnostic::unsupported(format!("mini sector shift {}", header.mini_shift))
                .at(header_span.sub(32, 2)),
        );
    }
    let sector = 1u64 << header.sector_shift;
    let sectors = file
        .len
        .saturating_sub(sector)
        .checked_div(sector)
        .unwrap_or(0);

    // DIFAT: 109 entries in the header, then a chain of DIFAT sectors.
    let difat_span = file.sub(76, 436);
    cx.emit(
        Node::new("DIFAT")
            .span(difat_span)
            .summary(format!("{} FAT sectors", header.fat_sectors))
            .desc("Locations of the FAT sectors: 109 in the header, the rest in a chain of DIFAT sectors")
            .lazy(difat_entries, (difat_span, header.first_difat, sector, input)),
    );
    let wanted = u64::from(header.fat_sectors).min(sectors);
    let mut fat = Vec::new();
    let head = cx.read_avail(difat_span).await?;
    fat.extend(
        head.as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c)),
    );
    let mut next = header.first_difat;
    let mut seen = BTreeSet::new();
    let per = to_usize(sector / 4).saturating_sub(1);
    while next < MAX_REGULAR && to_u64(fat.len()) < wanted && seen.insert(next) {
        cx.checkpoint().await;
        let span = file.sub(
            u64::from(next).saturating_add(1).saturating_mul(sector),
            sector,
        );
        let data = cx.read(span).await?;
        let entries: Vec<u32> = data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        fat.extend(entries.iter().take(per));
        next = entries.get(per).copied().unwrap_or(END_OF_CHAIN);
    }
    fat.truncate(to_usize(wanted));

    // The directory chain.
    let (dir_chain, dir_diag) = fat_chain(&cx, &fat, sector, file, header.first_dir, sectors).await;
    let mut dir_spans = coalesce(
        &cx,
        dir_chain.iter().copied().map(|s| {
            file.sub(
                u64::from(s).saturating_add(1).saturating_mul(sector),
                sector,
            )
        }),
    )
    .await;
    if dir_spans.is_empty() {
        dir_spans.push(file.sub(0, 0));
    }
    let dir = cx
        .add_pieces_stepped(
            Origin {
                parent: header_span.sub(48, 4),
                transform: "cfb-directory",
            },
            &dir_spans,
        )
        .await?;
    if let Some(d) = dir_diag {
        cx.diag(d.at(header_span.sub(48, 4)));
    }

    let mut cfb = Cfb {
        input,
        sector,
        mini: 64,
        cutoff: header.cutoff.into(),
        version: header.major,
        fat,
        dir,
        minifat: None,
        mini_stream: None,
        sectors,
    };
    // MiniFAT and mini stream (the root entry's stream).
    if header.first_minifat < MAX_REGULAR {
        let limit = u64::from(header.minifat_sectors).min(sectors);
        let (chain, diag) =
            fat_chain(&cx, &cfb.fat, sector, file, header.first_minifat, limit).await;
        let pieces = coalesce(&cx, chain.iter().copied().map(|s| cfb.sector_span(s))).await;
        cfb.minifat = Some(
            cx.add_pieces_stepped(
                Origin {
                    parent: header_span.sub(60, 4),
                    transform: "cfb-minifat",
                },
                &pieces,
            )
            .await?,
        );
        if let Some(d) = diag {
            cx.diag(d.at(header_span.sub(60, 4)));
        }
    }
    let root = read_entry(&cx, &cfb, 0).await?;
    if root.kind != 5 {
        cx.diag(Diagnostic::malformed(
            "the first directory entry is not the root storage",
        ));
    }
    if cfb.minifat.is_some() {
        let (span, diag) = stream(&cx, &cfb, 0, &root).await?;
        cfb.mini_stream = Some(span);
        if let Some(d) = diag {
            cx.diag(d);
        }
    }
    let cfb: CfbRef = Arc::new(cfb);

    let (app, context) = apps::application(&cx, &cfb, &root).await;
    let mut summary = format!(
        "Compound File v{}, {}-byte sectors, {} directory entries",
        header.major,
        sector,
        cfb.entries()
    );
    if let Some(app) = &app {
        summary = format!("{app}; {summary}");
    }
    cx.annotate(summary);

    cx.emit(
        Node::new("FAT")
            .summary(format!("{} sectors", cfb.fat.len()))
            .desc("Sector allocation table: the next sector of each chain")
            .lazy(fat_sectors, cfb.clone()),
    );
    cx.emit(
        Node::new("Free sectors")
            .desc("Sectors the FAT marks unused (FREESECT)")
            .lazy(free_sectors, cfb.clone()),
    );
    if let Some(minifat) = cfb.minifat {
        cx.emit(
            Node::new("MiniFAT")
                .span(minifat)
                .summary(format!("{} entries", minifat.len / 4))
                .lazy(minifat_entries, minifat),
        );
    }
    cx.emit(
        Node::new("Directory")
            .span(cfb.dir)
            .summary(format!("{} entries", cfb.entries()))
            .desc("All directory entries in storage order")
            .lazy(directory, cfb.clone()),
    );
    let mut root_node = Node::new("Root Entry")
        .span(cfb.entry_span(0))
        .summary(app.unwrap_or_else(|| "root storage".to_owned()))
        .lazy(
            crate::expander!(self::storage: StorageState),
            StorageState {
                cfb: cfb.clone(),
                id: 0,
                context,
                path: Arc::new(vec![0]),
            },
        );
    if root.clsid.data1 != 0 || root.clsid.data4 != [0; 8] {
        root_node = root_node.value(Value::Guid(root.clsid));
    }
    cx.emit(root_node);
    Ok(())
}

async fn difat_entries(
    cx: Cx,
    (header, first, sector, input): (Span, u32, u64, Input),
) -> Result<()> {
    let mut index = 0u64;
    difat_list(&cx, header, 109, &mut index, sector, input).await?;
    let mut next = first;
    let mut seen = BTreeSet::new();
    let per = to_usize(sector / 4).saturating_sub(1);
    while next < MAX_REGULAR && seen.insert(next) {
        let span = input.span.sub(
            u64::from(next).saturating_add(1).saturating_mul(sector),
            sector,
        );
        difat_list(&cx, span, per, &mut index, sector, input).await?;
        let link = span.sub(to_u64(per).saturating_mul(4), 4);
        let data = cx.read(link).await?;
        next = u32_le(&data, 0).unwrap_or(END_OF_CHAIN);
        cx.push(
            Node::new("Next DIFAT sector")
                .span(link)
                .value(Value::UInt {
                    value: next.into(),
                    bits: 32,
                    radix: Radix::Dec,
                })
                .summary(sector_name(next)),
        )
        .await;
    }
    Ok(())
}

async fn difat_list(
    cx: &Cx,
    span: Span,
    count: usize,
    index: &mut u64,
    sector: u64,
    input: Input,
) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let mut unused: Option<(usize, usize)> = None;
    for (i, c) in data.as_chunks::<4>().0.iter().enumerate().take(count) {
        let s = u32::from_le_bytes(*c);
        if s == NO_STREAM {
            unused = Some(unused.map_or((i, 1), |(first, n)| (first, n.saturating_add(1))));
        } else {
            if let Some(run) = unused.take() {
                cx.push(unused_entries(span, run)).await;
            }
            let at = span.sub(to_u64(i).saturating_mul(4), 4);
            cx.push(sector_node(
                format!("FAT sector {index}"),
                s,
                at,
                sector,
                input,
            ))
            .await;
        }
        *index = index.saturating_add(1);
    }
    if let Some(run) = unused {
        cx.push(unused_entries(span, run)).await;
    }
    Ok(())
}

/// A run of unused (FREESECT) DIFAT entries.
fn unused_entries(span: Span, (first, n): (usize, usize)) -> Node {
    Node::new("Unused entries")
        .span(span.sub(to_u64(first).saturating_mul(4), to_u64(n).saturating_mul(4)))
        .value(Value::UInt {
            value: u64::from(NO_STREAM),
            bits: 32,
            radix: Radix::Hex,
        })
        .summary(format!("{n} × FREESECT"))
}

fn sector_node(name: String, s: u32, span: Span, sector: u64, input: Input) -> Node {
    let node = Node::new(name).span(span).value(Value::UInt {
        value: s.into(),
        bits: 32,
        radix: Radix::Dec,
    });
    if s < MAX_REGULAR {
        node.target(input.span.sub(
            u64::from(s).saturating_add(1).saturating_mul(sector),
            sector,
        ))
    } else {
        node.summary(sector_name(s))
    }
}

async fn fat_sectors(cx: Cx, cfb: CfbRef) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(cfb.fat.len())));
    let per = cfb.sector / 4;
    for (i, &s) in cfb.fat.iter().enumerate() {
        let first = to_u64(i).saturating_mul(per);
        let span = cfb.sector_span(s);
        cx.push(
            Node::new(format!("FAT sector {i}"))
                .span(span)
                .summary(format!(
                    "sector {s}: entries for sectors {first}..{}",
                    first.saturating_add(per)
                ))
                .lazy(fat_entries, (span, first, cfb.sectors)),
        )
        .await;
    }
    Ok(())
}

async fn fat_entries(cx: Cx, (span, first, sectors): (Span, u64, u64)) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, c) in data.as_chunks::<4>().0.iter().enumerate() {
        let index = first.saturating_add(to_u64(i));
        if index >= sectors {
            break;
        }
        cx.push(chain_entry(
            format!("Sector {index}"),
            u32::from_le_bytes(*c),
            span.sub(to_u64(i).saturating_mul(4), 4),
        ))
        .await;
    }
    Ok(())
}

fn chain_entry(name: String, next: u32, span: Span) -> Node {
    let node = Node::new(name).span(span).value(Value::UInt {
        value: next.into(),
        bits: 32,
        radix: Radix::Dec,
    });
    if next >= MAX_REGULAR {
        node.summary(sector_name(next))
    } else {
        node.summary(format!("next: {next}"))
    }
}

async fn minifat_entries(cx: Cx, span: Span) -> Result<()> {
    cx.set_count(Count::Exact(span.len / 4));
    for i in 0..span.len / 4 {
        let at = span.sub(i.saturating_mul(4), 4);
        let data = cx.read(at).await?;
        cx.push(chain_entry(
            format!("Mini sector {i}"),
            u32_le(&data, 0).unwrap_or(0),
            at,
        ))
        .await;
    }
    Ok(())
}

async fn directory(cx: Cx, cfb: CfbRef) -> Result<()> {
    cx.set_count(Count::Exact(cfb.entries()));
    for id in 0..cfb.entries() {
        let Ok(id) = u32::try_from(id) else { break };
        let entry = read_entry(&cx, &cfb, id).await?;
        let kind = crate::value::lookup(OBJECT_TYPES, entry.kind.into()).unwrap_or("invalid");
        let name = display_name(&entry_name(&entry));
        let summary = if entry.kind == 0 {
            kind.to_owned()
        } else {
            format!("{kind} {name}")
        };
        cx.push(DirEntry::node(format!("Entry {id}"), cfb.entry_span(id), LE).summary(summary))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The storage hierarchy

#[derive(Clone)]
struct StorageState {
    cfb: CfbRef,
    id: u32,
    context: apps::Context,
    /// Storages from the root to this one.
    path: Arc<Vec<u32>>,
}

/// The children of a storage, in tree order: an in-order walk of the
/// red-black tree rooted at the storage's child entry. Entries seen twice
/// (a cycle, or shared subtrees) are reported and skipped.
struct TreeWalk {
    stack: Vec<(u32, DirEntry)>,
    seen: BTreeSet<u32>,
    node: u32,
}

impl TreeWalk {
    fn new(first: u32) -> Self {
        TreeWalk {
            stack: Vec::new(),
            seen: BTreeSet::new(),
            node: first,
        }
    }

    async fn next(&mut self, cx: &Cx, cfb: &Cfb) -> Option<(u32, DirEntry)> {
        while self.node != NO_STREAM {
            cx.checkpoint().await;
            let id = self.node;
            self.node = NO_STREAM;
            if !self.seen.insert(id) {
                cx.diag(Diagnostic::malformed(format!(
                    "directory tree revisits entry {id}"
                )));
                break;
            }
            match read_entry(cx, cfb, id).await {
                Ok(entry) => {
                    self.node = entry.left;
                    self.stack.push((id, entry));
                }
                Err(e) => cx.diag(e),
            }
        }
        let (id, entry) = self.stack.pop()?;
        self.node = entry.right;
        Some((id, entry))
    }
}

async fn storage(cx: Cx, state: StorageState) -> Result<()> {
    let cfb = &state.cfb;
    let this = read_entry(&cx, cfb, state.id).await?;
    cx.emit(DirEntry::node(
        "Directory entry",
        cfb.entry_span(state.id),
        LE,
    ));
    if state.id == 0
        && let Some(mini) = cfb.mini_stream
    {
        cx.emit(Node::new("Mini stream").span(mini).summary(format!(
            "{:#x} bytes in {}-byte mini sectors",
            mini.len, cfb.mini
        )));
    }
    let names = if state.context.is_msg() {
        Some(msg::name_map(&cx, cfb).await)
    } else {
        None
    };
    let mut walk = TreeWalk::new(this.child);
    while let Some((id, entry)) = walk.next(&cx, cfb).await {
        cx.push(child_node(cfb, &state, id, &entry, names.as_deref()))
            .await;
    }
    Ok(())
}

fn child_node(
    cfb: &CfbRef,
    parent: &StorageState,
    id: u32,
    entry: &DirEntry,
    names: Option<&msg::NameMap>,
) -> Node {
    let raw = entry_name(entry);
    let context = parent.context;
    let (label, detail) = apps::label(&raw, context, names);
    let mut node = Node::new(label).span(cfb.entry_span(id));
    match entry.kind {
        1 | 5 => {
            node = node.summary(detail.unwrap_or_else(|| "storage".to_owned()));
            if parent.path.contains(&id) {
                return node.diag(Diagnostic::malformed(format!(
                    "storage {id} contains itself"
                )));
            }
            if parent.path.len() >= MAX_DEPTH {
                return node.diag(Diagnostic::limit(format!(
                    "storages nested deeper than {MAX_DEPTH}"
                )));
            }
            let mut path = parent.path.to_vec();
            path.push(id);
            node.lazy(
                crate::expander!(self::storage: StorageState),
                StorageState {
                    cfb: cfb.clone(),
                    id,
                    context: apps::Context::child(context, &raw),
                    path: Arc::new(path),
                },
            )
        }
        2 => {
            let size = stream_size(cfb, entry);
            let summary = match detail {
                Some(d) => format!("{d}, {size} bytes"),
                None => format!("stream, {size} bytes"),
            };
            node.summary(summary).lazy(
                stream_node,
                StreamState {
                    cfb: cfb.clone(),
                    id,
                    parent: parent.id,
                    name: raw,
                    context,
                },
            )
        }
        _ => node.summary("unallocated"),
    }
}

#[derive(Clone)]
pub struct StreamState {
    pub cfb: CfbRef,
    pub id: u32,
    /// The storage holding the stream.
    pub parent: u32,
    pub name: String,
    pub context: apps::Context,
}

async fn stream_node(cx: Cx, state: StreamState) -> Result<()> {
    let cfb = &state.cfb;
    let entry = read_entry(&cx, cfb, state.id).await?;
    cx.emit(DirEntry::node(
        "Directory entry",
        cfb.entry_span(state.id),
        LE,
    ));
    let (span, diag) = stream(&cx, cfb, state.id, &entry).await?;
    if let Some(d) = diag {
        cx.diag(d);
    }
    if stream_size(cfb, &entry) == 0 {
        return Ok(());
    }
    cx.emit(
        Node::new("Sector chain")
            .summary(if stream_size(cfb, &entry) < cfb.cutoff {
                "mini sectors"
            } else {
                "sectors"
            })
            .lazy(chain_sectors, (cfb.clone(), state.id)),
    );
    apps::content(&cx, &state, span).await
}

/// The sectors of a stream, in chain order, each pointing at its bytes.
async fn chain_sectors(cx: Cx, (cfb, id): (CfbRef, u32)) -> Result<()> {
    let entry = read_entry(&cx, &cfb, id).await?;
    let (mini, sectors, diag) = sectors_of(&cx, &cfb, &entry).await?;
    let unit = if mini { cfb.mini } else { cfb.sector };
    let total = to_u64(sectors.len()).saturating_mul(unit);
    let size = stream_size(&cfb, &entry);
    let slack = sectors
        .last()
        .filter(|_| total > size && diag.is_none())
        .map(|&(_, last)| last.tail(unit.saturating_sub(total.saturating_sub(size))));
    for (i, (s, span)) in sectors.into_iter().enumerate() {
        let kind = if mini { "mini sector" } else { "sector" };
        cx.push(
            Node::new(format!("Link {i}"))
                .value(Value::UInt {
                    value: s.into(),
                    bits: 32,
                    radix: Radix::Dec,
                })
                .summary(kind)
                .target(span),
        )
        .await;
    }
    if let Some(span) = slack.filter(|s| !s.is_empty()) {
        cx.push(Node::new("Slack").span(span).summary(format!(
            "{} unused bytes after the end of the stream",
            span.len
        )))
        .await;
    }
    if let Some(d) = diag {
        cx.diag(d);
    }
    Ok(())
}

/// Runs of sectors the FAT marks free.
async fn free_sectors(cx: Cx, cfb: CfbRef) -> Result<()> {
    let per = cfb.sector / 4;
    let mut run: Option<(u64, u64)> = None;
    let flush = |run: (u64, u64)| {
        let (first, n) = run;
        Node::new(format!(
            "Sectors {first}–{}",
            first.saturating_add(n).saturating_sub(1)
        ))
        .span(cfb.input.span.sub(
            first.saturating_add(1).saturating_mul(cfb.sector),
            n.saturating_mul(cfb.sector),
        ))
        .summary(format!("{n} free sectors"))
    };
    for (i, &fs) in cfb.fat.iter().enumerate() {
        let data = cx.read_avail(cfb.sector_span(fs)).await?;
        for (k, c) in data.as_chunks::<4>().0.iter().enumerate() {
            let index = to_u64(i).saturating_mul(per).saturating_add(to_u64(k));
            if index >= cfb.sectors {
                break;
            }
            if u32::from_le_bytes(*c) == NO_STREAM {
                run = match run {
                    Some((first, n)) if first.saturating_add(n) == index => {
                        Some((first, n.saturating_add(1)))
                    }
                    Some(r) => {
                        cx.push(flush(r)).await;
                        Some((index, 1))
                    }
                    None => Some((index, 1)),
                };
            }
        }
    }
    if let Some(r) = run {
        cx.push(flush(r)).await;
    }
    Ok(())
}
