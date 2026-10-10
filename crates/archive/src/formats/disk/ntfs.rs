//! NTFS volumes.
//!
//! The boot sector locates the MFT. Each MFT record (and each index
//! record) is protected by an update sequence: the last two bytes of every
//! sector are moved into an array in the header. Records are presented as
//! piecewise sources with those bytes put back, so every field keeps an
//! exact file offset. Attributes are decoded ($STANDARD_INFORMATION,
//! $FILE_NAME, runlists of non-resident attributes, ...); directories are
//! read from $INDEX_ROOT and the INDX records of $INDEX_ALLOCATION and
//! presented as a lazy, paged tree; file content follows the $DATA
//! runlist (sparse runs become holes); compressed streams are decoded one
//! LZNT1 compression unit at a time, on demand.

use std::sync::Arc;

use crate::bytes::{u16_le, u32_le, u64_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::{PieceList, content_node, fragments_node, size};
use crate::formats::util::val::{name_or, text, uint};
use crate::formats::{Format, Input, Probe, embedded_named};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const ROOT_RECORD: u64 = 5;
/// Attributes per record, runs per runlist, directory depth and index
/// records followed before assuming corruption.
const MAX_ATTRIBUTES: usize = 256;
const MAX_RUNS: usize = 1 << 16;
const MAX_DEPTH: usize = 64;
const MAX_INDEX_BYTES: u64 = 64 << 20;

pub static FORMAT: Format = Format {
    name: "ntfs",
    title: "NTFS volume",
    extensions: &["img", "ntfs"],
    mime: "application/x-ntfs",
    probe: Probe::Magic(&[(3, b"NTFS    ")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    /// The NTFS boot sector's BIOS parameter block.
    pub struct BootSector {
        jump: bytes[3] "Jump instruction",
        oem: ascii[8] "OEM id",
        bytes_per_sector: u16 "Bytes per sector",
        sectors_per_cluster: u8 "Sectors per cluster (or 2^-n)",
        _reserved: bytes[7] "Reserved",
        media: u8 "Media descriptor" .hex(),
        _unused: u16 "Unused",
        sectors_per_track: u16 "Sectors per track",
        heads: u16 "Heads",
        hidden: u32 "Hidden sectors",
        _unused2: bytes[8] "Unused",
        total_sectors: u64 "Total sectors" .with(|&v, n| n.summary(size(v.saturating_mul(512)))),
        mft_lcn: u64 "$MFT cluster",
        mftmirr_lcn: u64 "$MFTMirr cluster",
        record_size: u8 "Clusters per MFT record (or 2^-n bytes)",
        _pad: bytes[3] "Unused",
        index_size: u8 "Clusters per index record (or 2^-n bytes)",
        _pad2: bytes[3] "Unused",
        serial: u64 "Volume serial number" .hex(),
        checksum: u32 "Checksum" .hex(),
    }
}

const RECORD_FLAGS: FlagTable = &[
    flag(1, "IN_USE"),
    flag(2, "DIRECTORY"),
    flag(4, "EXTENSION"),
    flag(8, "VIEW_INDEX"),
];

record! {
    /// MFT record header (`FILE`).
    pub struct RecordHeader {
        magic: ascii[4] "Magic",
        usa_offset: u16 "Update sequence offset",
        usa_count: u16 "Update sequence entries",
        lsn: u64 "Log sequence number",
        sequence: u16 "Sequence number",
        links: u16 "Hard links",
        attrs_offset: u16 "First attribute offset",
        flags: u16 "Flags" .hex() .flags(RECORD_FLAGS),
        used: u32 "Bytes used",
        allocated: u32 "Bytes allocated",
        base: u64 "Base record" .hex(),
        next_attr_id: u16 "Next attribute id",
        _pad: u16 "Padding",
        number: u32 "Record number",
    }
}

/// NTFS attribute type codes (`$AttrDef`).
pub const ATTR_TYPES: EnumTable = &[
    (0x10, "$STANDARD_INFORMATION"),
    (0x20, "$ATTRIBUTE_LIST"),
    (0x30, "$FILE_NAME"),
    (0x40, "$OBJECT_ID"),
    (0x50, "$SECURITY_DESCRIPTOR"),
    (0x60, "$VOLUME_NAME"),
    (0x70, "$VOLUME_INFORMATION"),
    (0x80, "$DATA"),
    (0x90, "$INDEX_ROOT"),
    (0xa0, "$INDEX_ALLOCATION"),
    (0xb0, "$BITMAP"),
    (0xc0, "$REPARSE_POINT"),
    (0xd0, "$EA_INFORMATION"),
    (0xe0, "$EA"),
    (0x100, "$LOGGED_UTILITY_STREAM"),
];

/// Windows `FILE_ATTRIBUTE_*` flags (`winnt.h`), as stored by NTFS, FAT and
/// exFAT directory entries, archivers (ACE) and Windows artifacts. Bit 3 is
/// the FAT volume label; the top two are NTFS's `$FILE_NAME` index flags.
pub const FILE_ATTRIBUTES: FlagTable = &[
    flag(0x1, "READONLY"),
    flag(0x2, "HIDDEN"),
    flag(0x4, "SYSTEM"),
    flag(0x8, "VOLUME_ID"),
    flag(0x10, "DIRECTORY"),
    flag(0x20, "ARCHIVE"),
    flag(0x40, "DEVICE"),
    flag(0x80, "NORMAL"),
    flag(0x100, "TEMPORARY"),
    flag(0x200, "SPARSE_FILE"),
    flag(0x400, "REPARSE_POINT"),
    flag(0x800, "COMPRESSED"),
    flag(0x1000, "OFFLINE"),
    flag(0x2000, "NOT_CONTENT_INDEXED"),
    flag(0x4000, "ENCRYPTED"),
    flag(0x8000, "INTEGRITY_STREAM"),
    flag(0x1_0000, "VIRTUAL"),
    flag(0x2_0000, "NO_SCRUB_DATA"),
    flag(0x4_0000, "RECALL_ON_OPEN"),
    flag(0x8_0000, "PINNED"),
    flag(0x10_0000, "UNPINNED"),
    flag(0x40_0000, "RECALL_ON_DATA_ACCESS"),
    flag(0x1000_0000, "DUP_FILE_NAME_INDEX_PRESENT"),
    flag(0x2000_0000, "DUP_VIEW_INDEX_PRESENT"),
];

record! {
    pub struct StandardInformation {
        created: u64 "Created" .filetime(),
        modified: u64 "Modified" .filetime(),
        mft_modified: u64 "MFT record modified" .filetime(),
        accessed: u64 "Accessed" .filetime(),
        attributes: u32 "File attributes" .hex() .flags(FILE_ATTRIBUTES),
        max_versions: u32 "Maximum versions",
        version: u32 "Version",
        class_id: u32 "Class id",
    }
}

/// `$FILE_NAME` namespaces.
pub const NAMESPACES: EnumTable = &[(0, "POSIX"), (1, "Win32"), (2, "DOS"), (3, "Win32 and DOS")];

record! {
    pub struct FileName {
        parent: u64 "Parent reference" .with(|&r, n| n.summary(reference(r))),
        created: u64 "Created" .filetime(),
        modified: u64 "Modified" .filetime(),
        mft_modified: u64 "MFT record modified" .filetime(),
        accessed: u64 "Accessed" .filetime(),
        allocated: u64 "Allocated size",
        real: u64 "Real size",
        attributes: u32 "File attributes" .hex() .flags(FILE_ATTRIBUTES),
        reparse: u32 "Reparse tag / EA size" .hex(),
        name_length: u8 "Name length",
        namespace: u8 "Namespace" .enumeration(NAMESPACES),
    }
}

fn reference(r: u64) -> String {
    format!("record {}, sequence {}", r & 0xffff_ffff_ffff, r >> 48)
}

#[derive(Debug)]
struct Volume {
    input: Input,
    vol: Span,
    cluster: u64,
    record: u64,
    /// Index record size.
    index: u64,
    /// Clusters in the volume.
    clusters: u64,
    /// The $MFT's own data runs (record → location).
    mft: Vec<Span>,
    /// The MFT offset where each of `mft` ends, for binary search.
    mft_ends: Vec<u64>,
}

type Vol = Arc<Volume>;

/// One decoded attribute (its header and value located in a record source).
#[derive(Clone, Debug)]
struct Attr {
    kind: u32,
    name: String,
    span: Span,
    resident: Option<Span>,
    runs: Option<Span>,
    data_size: u64,
    /// Log2 of the compression unit in clusters, for a non-resident
    /// attribute flagged compressed (0 otherwise).
    compression_unit: u32,
}

/// Decodes `n`-byte little-endian integers (signed if requested).
fn le_int(b: &[u8], signed: bool) -> i64 {
    let mut v = 0i64;
    for (i, &byte) in b.iter().enumerate().take(8) {
        v |= i64::from(byte)
            .checked_shl(u32::try_from(i.saturating_mul(8)).unwrap_or(64))
            .unwrap_or(0);
    }
    if signed && !b.is_empty() && b.len() < 8 && b.last().is_some_and(|&x| x & 0x80 != 0) {
        v |= (-1i64)
            .checked_shl(u32::try_from(b.len().saturating_mul(8)).unwrap_or(64))
            .unwrap_or(0);
    }
    v
}

/// A run: cluster count and starting cluster (`None` for sparse runs).
fn parse_runs(data: &[u8]) -> (Vec<(u64, Option<u64>)>, Option<Diagnostic>) {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut lcn = 0i64;
    while let Some(&header) = data.get(at) {
        if header == 0 {
            return (out, None);
        }
        let len_bytes = usize::from(header & 0x0f);
        let off_bytes = usize::from(header >> 4);
        let len_at = at.saturating_add(1);
        let off_at = len_at.saturating_add(len_bytes);
        let (Some(len), Some(off)) = (
            data.get(len_at..off_at),
            data.get(off_at..off_at.saturating_add(off_bytes)),
        ) else {
            return (
                out,
                Some(Diagnostic::malformed("runlist ends inside a run")),
            );
        };
        if len_bytes == 0 || len_bytes > 8 || off_bytes > 8 {
            return (
                out,
                Some(Diagnostic::malformed(format!(
                    "bad run header {header:#04x}"
                ))),
            );
        }
        let count = u64::try_from(le_int(len, false)).unwrap_or(0);
        let start = if off_bytes == 0 {
            None
        } else {
            lcn = lcn.saturating_add(le_int(off, true));
            u64::try_from(lcn).ok()
        };
        out.push((count, start));
        if out.len() >= MAX_RUNS {
            return (out, Some(Diagnostic::limit("too many runs")));
        }
        at = off_at.saturating_add(off_bytes);
    }
    (
        out,
        Some(Diagnostic::malformed("runlist is not terminated")),
    )
}

impl Volume {
    fn cluster_span(&self, lcn: u64, count: u64) -> Span {
        self.vol.sub(
            lcn.saturating_mul(self.cluster),
            count.saturating_mul(self.cluster),
        )
    }

    /// The span of MFT record `n`, located through the $MFT's runs.
    fn record_span(&self, n: u64) -> Option<Span> {
        let want = n.checked_mul(self.record)?;
        let i = self.mft_ends.partition_point(|&end| end <= want);
        let piece = self.mft.get(i)?;
        let start = i
            .checked_sub(1)
            .and_then(|j| self.mft_ends.get(j))
            .copied()
            .unwrap_or(0);
        let span = piece.sub(want.saturating_sub(start), self.record);
        (span.len == self.record).then_some(span)
    }

    /// The bytes of a non-resident attribute, as pieces (holes as zeros).
    fn runs_list(
        &self,
        cx: &Cx,
        anchor: Span,
        runs: &[(u64, Option<u64>)],
        size: u64,
    ) -> Result<PieceList> {
        let mut list = PieceList::new(anchor);
        for &(count, start) in runs {
            if list.len() >= size {
                break;
            }
            let len = count
                .saturating_mul(self.cluster)
                .min(size.saturating_sub(list.len()));
            match start {
                Some(lcn) => list.data(self.vol.sub(lcn.saturating_mul(self.cluster), len)),
                None => list.hole(cx, len)?,
            }
        }
        Ok(list)
    }
}

/// A multi-sector protected structure (an NTFS `FILE` or `INDX` record, or
/// any record with the same header: `magic`, then the update sequence
/// array's offset and entry count at 4 and 6) as a piecewise source with
/// the update sequence applied: the last two bytes of each 512-byte sector
/// are replaced by their saved copies from the array. A sector whose last
/// two bytes are not the update sequence number (a torn write) gets a
/// warning on `span`; a wrong magic or an array that does not fit the
/// record is an error. Read the result with `cx.read`/`cx.block`.
pub async fn fixed_up(cx: &Cx, span: Span, magic: &[u8]) -> Result<Span> {
    match fixup(cx, span, magic).await? {
        Fixup::Applied(fixed, problem) => {
            if let Some(d) = problem {
                cx.diag(d);
            }
            Ok(fixed)
        }
        Fixup::Rejected(d) => Err(d),
    }
}

/// Like [`fixed_up`], but never fails on the record's contents: returns
/// the fixed-up span and the torn-sector warning (located at `span`), if
/// any, without emitting it; a wrong magic or an unusable update sequence
/// array returns `span` itself, unchanged, with the error as the
/// diagnostic. Only a failed read is an `Err`.
pub async fn try_fixed_up(cx: &Cx, span: Span, magic: &[u8]) -> Result<(Span, Option<Diagnostic>)> {
    Ok(match fixup(cx, span, magic).await? {
        Fixup::Applied(fixed, problem) => (fixed, problem),
        Fixup::Rejected(d) => (span, Some(d)),
    })
}

enum Fixup {
    /// The fixed-up source, and a torn-sector warning.
    Applied(Span, Option<Diagnostic>),
    /// Not a record of this kind, or a bad update sequence array.
    Rejected(Diagnostic),
}

async fn fixup(cx: &Cx, span: Span, magic: &[u8]) -> Result<Fixup> {
    let head = cx.read(span.sub(0, 8)).await?;
    if head.get(..4) != Some(magic) {
        return Ok(Fixup::Rejected(
            Diagnostic::malformed(format!(
                "expected {:?} record",
                String::from_utf8_lossy(magic)
            ))
            .at(span.sub(0, 4)),
        ));
    }
    let usa = u64::from(u16_le(&head, 4).unwrap_or(0));
    let count = u64::from(u16_le(&head, 6).unwrap_or(0));
    let sectors = span.len / 512;
    if count != sectors.saturating_add(1) || usa.saturating_add(count.saturating_mul(2)) > 512 {
        return Ok(Fixup::Rejected(
            Diagnostic::malformed(format!(
                "update sequence of {count} entries for {sectors} sectors"
            ))
            .at(span),
        ));
    }
    let array = cx.read(span.sub(usa, count.saturating_mul(2))).await?;
    let mut pieces = Vec::new();
    let mut problem = None;
    for s in 0..sectors {
        let sector = span.sub(s.saturating_mul(512), 512);
        let end = cx.read(sector.sub(510, 2)).await?;
        if end.get(..2) != array.get(..2) {
            problem = Some(Diagnostic::warning(format!(
                "sector {s} fails its update sequence check"
            )));
        }
        pieces.push(sector.sub(0, 510));
        pieces.push(span.sub(usa.saturating_add(s.saturating_add(1).saturating_mul(2)), 2));
    }
    let fixed = cx.add_pieces(
        Origin {
            parent: span,
            transform: "ntfs-fixup",
        },
        pieces,
    )?;
    Ok(Fixup::Applied(fixed, problem.map(|d| d.at(span))))
}

/// Parses the attributes of a (fixed-up) record.
async fn attributes(cx: &Cx, rec: Span) -> Result<Vec<Attr>> {
    let head = cx.read(rec.sub(0, 28)).await?;
    let mut at = u64::from(u16_le(&head, 20).unwrap_or(0));
    let used = u64::from(u32_le(&head, 24).unwrap_or(0)).min(rec.len);
    let mut out = Vec::new();
    while at.saturating_add(16) <= used && out.len() < MAX_ATTRIBUTES {
        let h = cx.read_avail(rec.sub(at, 72)).await?;
        let kind = u32_le(&h, 0).unwrap_or(u32::MAX);
        let len = u64::from(u32_le(&h, 4).unwrap_or(0));
        if kind == u32::MAX || len < 16 {
            break;
        }
        let span = rec.sub(at, len);
        let name_len = u64::from(h.get(9).copied().unwrap_or(0));
        let name_off = u64::from(u16_le(&h, 10).unwrap_or(0));
        let name = crate::text::utf16(
            &cx.read_avail(span.sub(name_off, name_len.saturating_mul(2)))
                .await?,
            LE,
        );
        let mut attr = Attr {
            kind,
            name,
            span,
            resident: None,
            runs: None,
            data_size: 0,
            compression_unit: 0,
        };
        if h.get(8) == Some(&0) {
            let vlen = u64::from(u32_le(&h, 16).unwrap_or(0));
            let voff = u64::from(u16_le(&h, 20).unwrap_or(0));
            attr.resident = Some(span.sub(voff, vlen));
            attr.data_size = vlen;
        } else {
            let roff = u64::from(u16_le(&h, 32).unwrap_or(0));
            attr.runs = Some(span.sub(roff, len.saturating_sub(roff)));
            attr.data_size = u64_le(&h, 48).unwrap_or(0);
            if u16_le(&h, 12).unwrap_or(0) & 0x00ff != 0 {
                attr.compression_unit = u32::from(u16_le(&h, 34).unwrap_or(0));
            }
        }
        out.push(attr);
        at = at.saturating_add(len);
    }
    Ok(out)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(0, BootSector::SIZE);
    let b = parse(&cx, span, LE, &(), BootSector::layout).await?;
    cx.emit(BootSector::node("Boot sector", vol.sub(0, 512), LE));
    let sector = u64::from(b.bytes_per_sector);
    let spc = if b.sectors_per_cluster > 0x80 {
        1u64.checked_shl(256u32.saturating_sub(b.sectors_per_cluster.into()))
            .unwrap_or(0)
    } else {
        b.sectors_per_cluster.into()
    };
    let cluster = sector.saturating_mul(spc);
    let unit = |v: u8| -> u64 {
        if v >= 0x80 {
            1u64.checked_shl(256u32.saturating_sub(v.into()))
                .unwrap_or(0)
        } else {
            u64::from(v).saturating_mul(cluster)
        }
    };
    let record = unit(b.record_size);
    if !matches!(sector, 512 | 1024 | 2048 | 4096)
        || cluster == 0
        || !(512..=65536).contains(&record)
        || record % 512 != 0
    {
        return Err(Diagnostic::malformed("implausible sector, cluster or record size").at(span));
    }
    cx.annotate(format!(
        "NTFS volume, {}, {} clusters",
        size(b.total_sectors.saturating_mul(sector)),
        size(cluster)
    ));
    // Record 0 ($MFT) describes where the MFT itself lives.
    let mft0 = vol.sub(b.mft_lcn.saturating_mul(cluster), record);
    let rec0 = fixed_up(&cx, mft0, b"FILE").await?;
    let attrs0 = attributes(&cx, rec0).await?;
    let mut mft = vec![mft0];
    if let Some(runs) = attrs0
        .iter()
        .find(|a| a.kind == 0x80 && a.name.is_empty())
        .and_then(|a| a.runs.map(|r| (r, a.data_size)))
    {
        let raw = cx.read_avail(runs.0).await?;
        let (list, problem) = parse_runs(&raw);
        if let Some(d) = problem {
            cx.diag(d);
        }
        mft = list
            .iter()
            .filter_map(|&(count, lcn)| {
                lcn.map(|l| vol.sub(l.saturating_mul(cluster), count.saturating_mul(cluster)))
            })
            .collect();
        mft = crate::formats::disk::coalesce(mft, runs.1);
    }
    let mft_ends = mft
        .iter()
        .scan(0u64, |end, p| {
            *end = end.saturating_add(p.len);
            Some(*end)
        })
        .collect();
    let fs: Vol = Arc::new(Volume {
        input,
        vol,
        cluster,
        record,
        index: unit(b.index_size),
        clusters: b
            .total_sectors
            .saturating_mul(sector)
            .checked_div(cluster)
            .unwrap_or(0),
        mft,
        mft_ends,
    });
    let mft_records = fs
        .mft
        .iter()
        .map(|p| p.len)
        .fold(0u64, u64::saturating_add)
        .checked_div(record)
        .unwrap_or(0);
    // The volume label, from $Volume (record 3).
    if let Some(span) = fs.record_span(3)
        && let Ok(rec) = fixed_up(&cx, span, b"FILE").await
        && let Ok(attrs) = attributes(&cx, rec).await
        && let Some(name) = attrs
            .iter()
            .find(|a| a.kind == 0x60)
            .and_then(|a| a.resident)
    {
        let label = crate::text::utf16(&cx.read_avail(name).await?, LE);
        cx.annotate(format!(
            "NTFS volume \"{label}\", {}, {} clusters",
            size(b.total_sectors.saturating_mul(sector)),
            size(cluster)
        ));
    }
    cx.emit(
        Node::new("MFT")
            .summary(format!("{mft_records} records of {}", size(record)))
            .lazy(mft_listing, (fs.clone(), mft_records)),
    );
    cx.emit(Node::new("MFT mirror").span(vol.sub(
        b.mftmirr_lcn.saturating_mul(cluster),
        record.saturating_mul(4),
    )));
    cx.emit(Node::new("Root directory").summary("record 5").lazy(
        crate::expander!(self::directory: Dir),
        Dir {
            fs: fs.clone(),
            record: ROOT_RECORD,
            ancestors: Arc::new(Vec::new()),
        },
    ));
    let clusters = fs.clusters;
    cx.emit(
        Node::new("Free clusters")
            .summary("from $Bitmap")
            .lazy(free_clusters, (fs.clone(), clusters)),
    );
    // The backup boot sector is the last sector, past the sectors the
    // boot sector counts; any part of a cluster before it is unused.
    let end = b.total_sectors.saturating_mul(sector);
    let tail = clusters.saturating_mul(cluster);
    if end > tail {
        cx.emit(
            Node::new("Unused")
                .span(vol.sub(tail, end.saturating_sub(tail)))
                .summary("past the last whole cluster"),
        );
    }
    let backup = vol.sub(end, sector);
    if backup.len == sector && cx.read_avail(backup.sub(3, 8)).await? == b"NTFS    " {
        cx.emit(BootSector::node("Backup boot sector", backup, LE));
    }
    Ok(())
}

/// Runs of clear bits in the cluster bitmap ($Bitmap, record 6).
async fn free_clusters(cx: Cx, (fs, clusters): (Vol, u64)) -> Result<()> {
    let span = fs
        .record_span(6)
        .ok_or_else(|| Diagnostic::malformed("no $Bitmap record"))?;
    let rec = fixed_up(&cx, span, b"FILE").await?;
    let attrs = attributes(&cx, rec).await?;
    let a = attrs
        .iter()
        .find(|a| a.kind == 0x80 && a.name.is_empty())
        .ok_or_else(|| Diagnostic::malformed("$Bitmap has no data"))?;
    let data = if let Some(value) = a.resident {
        value
    } else {
        let raw = cx.read_avail(a.runs.unwrap_or(a.span.sub(0, 0))).await?;
        let (runs, _) = parse_runs(&raw);
        let list = fs.runs_list(&cx, a.span, &runs, a.data_size)?;
        list.finish(&cx, "ntfs-runs").await?
    };
    let bitmap = cx
        .read_avail(data.sub(0, clusters.div_ceil(8).min(1 << 24)))
        .await?;
    let clusters = clusters.min(crate::bytes::to_u64(bitmap.len()).saturating_mul(8));
    let mut from: Option<u64> = None;
    for i in 0..=clusters {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let used = i == clusters
            || bitmap.get(crate::bytes::to_usize(i / 8)).is_none_or(|b| {
                b.checked_shr(u32::try_from(i % 8).unwrap_or(0))
                    .is_some_and(|v| v & 1 != 0)
            });
        match (used, from) {
            (false, None) => from = Some(i),
            (true, Some(f)) => {
                from = None;
                let n = i.saturating_sub(f);
                cx.push(
                    Node::new(format!("Clusters {f}–{}", i.saturating_sub(1)))
                        .span(
                            fs.vol
                                .sub(f.saturating_mul(fs.cluster), n.saturating_mul(fs.cluster)),
                        )
                        .summary(format!("free, {}", size(n.saturating_mul(fs.cluster)))),
                )
                .await;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn mft_listing(cx: Cx, (fs, count): (Vol, u64)) -> Result<()> {
    cx.set_count(Count::Exact(count));
    for n in 0..count {
        let Some(span) = fs.record_span(n) else { break };
        let head = cx.read(span.sub(0, 4)).await?;
        let node = Node::new(format!("Record {n}")).span(span);
        if head != b"FILE" {
            cx.push(node.summary("unused")).await;
            continue;
        }
        let name = match fixed_up(&cx, span, b"FILE").await {
            Ok(rec) => best_name(&cx, &attributes(&cx, rec).await.unwrap_or_default()).await?,
            Err(_) => None,
        };
        cx.push(
            node.summary(name.unwrap_or_default())
                .lazy(record_node, (fs.clone(), n)),
        )
        .await;
    }
    Ok(())
}

/// The record's preferred $FILE_NAME (Win32 over DOS).
async fn best_name(cx: &Cx, attrs: &[Attr]) -> Result<Option<String>> {
    let mut best: Option<(u8, String)> = None;
    for a in attrs.iter().filter(|a| a.kind == 0x30) {
        let Some(value) = a.resident else { continue };
        let raw = cx.read_avail(value).await?;
        let len = usize::from(raw.get(64).copied().unwrap_or(0));
        let namespace = raw.get(65).copied().unwrap_or(0);
        let name = crate::text::utf16(
            raw.get(66..66usize.saturating_add(len.saturating_mul(2)))
                .unwrap_or_default(),
            LE,
        );
        let rank = if namespace == 2 { 0 } else { 1 };
        if best.as_ref().is_none_or(|(r, _)| rank > *r) {
            best = Some((rank, name));
        }
    }
    Ok(best.map(|(_, n)| n))
}

/// Shows a record: header, attributes, and the unnamed $DATA content.
async fn record_node(cx: Cx, (fs, n): (Vol, u64)) -> Result<()> {
    let span = fs
        .record_span(n)
        .ok_or_else(|| Diagnostic::malformed(format!("record {n} is outside the MFT")))?;
    let rec = fixed_up(&cx, span, b"FILE").await?;
    cx.emit(RecordHeader::node(
        "Header",
        rec.sub(0, RecordHeader::SIZE),
        LE,
    ));
    let attrs = attributes(&cx, rec).await?;
    for a in &attrs {
        cx.emit(attribute_node(&fs, a, n));
    }
    if let Some(data) = attrs.iter().find(|a| a.kind == 0x80 && a.name.is_empty()) {
        let node = stream_content(&cx, &fs, data).await?;
        // The MFT and $Boot are the volume's own structures, already shown
        // at the top level: dissecting them again would recurse into the
        // volume (and $Boot alone is not a whole volume).
        let own = match n {
            0 => Some("the MFT itself (its records are listed above)"),
            7 => Some("the volume's boot sector and loader (shown at the top level)"),
            _ => None,
        };
        if let Some(what) = own {
            let mut leaf = Node::new("Content").summary(what);
            if let Some(s) = node.span {
                leaf = leaf.span(s);
            }
            cx.emit(leaf);
        } else if let Some(span) = node.span {
            cx.emit(system_content(&cx, &fs, n, span, node).await?);
        } else {
            cx.emit(node);
        }
    }
    Ok(())
}

/// The content of a system file's unnamed $DATA stream, dissected by what
/// the record number says it is; `node` for any other record.
async fn system_content(cx: &Cx, fs: &Vol, n: u64, span: Span, node: Node) -> Result<Node> {
    let content = Node::new("Content").span(span);
    Ok(match n {
        2 => {
            let head = cx.read_avail(span.sub(0, 4)).await?;
            if matches!(head.as_slice(), b"RSTR" | b"CHKD") {
                embedded_named("Content", fs.input.nested(span), "ntfs-logfile")
            } else {
                content
                    .summary("transaction log, not initialised")
                    .lazy(log_pages, span)
            }
        }
        4 => content.summary("attribute definitions").lazy(attrdef, span),
        6 => {
            let clusters = fs.clusters;
            bitmap_node("Content", span, clusters, "clusters")
        }
        10 => content.summary("upper-case table").lazy(upcase, span),
        _ => node,
    })
}

fn attribute_node(fs: &Vol, a: &Attr, record: u64) -> Node {
    let kind = name_or(ATTR_TYPES, a.kind.into(), "Attribute");
    let name = if a.name.is_empty() {
        kind
    } else {
        format!("{kind}:{}", a.name)
    };
    let node = Node::new(name).span(a.span);
    let summary = if a.resident.is_some() {
        format!("resident, {}", size(a.data_size))
    } else {
        format!("non-resident, {}", size(a.data_size))
    };
    node.summary(summary)
        .lazy(attribute_fields, (fs.clone(), Arc::new(a.clone()), record))
}

async fn attribute_fields(cx: Cx, (fs, a, record): (Vol, Arc<Attr>, u64)) -> Result<()> {
    if let Some(value) = a.resident {
        match a.kind {
            0x10 => cx.emit(StandardInformation::node(
                "Value",
                value.sub(0, StandardInformation::SIZE),
                LE,
            )),
            0x30 => {
                cx.emit(FileName::node("Value", value.sub(0, FileName::SIZE), LE));
                let raw = cx.read_avail(value).await?;
                let len = u64::from(raw.get(64).copied().unwrap_or(0));
                let name = value.sub(66, len.saturating_mul(2));
                let text = crate::text::utf16(&cx.read_avail(name).await?, LE);
                cx.emit(Node::new("Name").span(name).value(Value::Text(text)));
            }
            0x60 => {
                let text = crate::text::utf16(&cx.read_avail(value).await?, LE);
                cx.emit(
                    Node::new("Volume name")
                        .span(value)
                        .value(Value::Text(text)),
                );
            }
            0x70 => cx.emit(VolumeInformation::node(
                "Value",
                value.sub(0, VolumeInformation::SIZE),
                LE,
            )),
            0x40 => cx.emit(struct_node("Value", value, LE, (), object_id_layout)),
            0x50 => cx.emit(struct_node("Value", value, LE, (), sd_layout)),
            0x90 => index_root(&cx, value).await?,
            0xb0 => cx.emit(bitmap_node(
                "Value",
                value,
                value.len.saturating_mul(8),
                "bits",
            )),
            0x80 if record == 10 && a.name == "$Info" => cx.emit(UpcaseInfo::node(
                "Value",
                value.sub(0, UpcaseInfo::SIZE),
                LE,
            )),
            0x80 if !a.name.is_empty() => cx.emit(content_node(&fs.input, value)),
            _ => cx.emit(Node::new("Value").span(value).summary(size(value.len))),
        }
        return Ok(());
    }
    let Some(runs) = a.runs else { return Ok(()) };
    let raw = cx.read_avail(runs).await?;
    let (list, problem) = parse_runs(&raw);
    if let Some(d) = problem {
        cx.diag(d);
    }
    let mut vcn = 0u64;
    for (i, &(count, lcn)) in list.iter().enumerate() {
        let node = Node::new(format!("Run {i}"));
        let node = match lcn {
            Some(l) => node
                .summary(format!("VCN {vcn}: {count} clusters at LCN {l}"))
                .target(fs.cluster_span(l, count)),
            None => node.summary(format!("VCN {vcn}: {count} sparse clusters")),
        };
        cx.push(node).await;
        vcn = vcn.saturating_add(count);
    }
    // Allocated bytes past the end of the data, in the last run.
    if a.compression_unit == 0
        && let Some(&(count, Some(lcn))) = list.last()
    {
        let start = vcn.saturating_sub(count).saturating_mul(fs.cluster);
        let run = fs.cluster_span(lcn, count);
        let slack = run.tail(a.data_size.saturating_sub(start));
        if a.data_size >= start && !slack.is_empty() {
            cx.emit(
                Node::new("Slack")
                    .span(slack)
                    .summary("allocated past the end of the data"),
            );
        }
    }
    // The unnamed $DATA stream is shown with its record; the content of
    // the other non-resident attributes is shown here.
    match a.kind {
        0x80 if a.name.is_empty() => {}
        0x80 => {
            let node = stream_content(&cx, &fs, &a).await?;
            match (record, a.name.as_str(), node.span) {
                (9, "$SDS", Some(span)) => cx.emit(
                    Node::new("Content")
                        .span(span)
                        .summary("security descriptor stream")
                        .lazy(sds, span),
                ),
                _ => cx.emit(node),
            }
        }
        0x50 => {
            let span = fs
                .runs_list(&cx, a.span, &list, a.data_size.min(MAX_INDEX_BYTES))?
                .finish(&cx, "ntfs-runs")
                .await?;
            cx.emit(struct_node("Content", span, LE, (), sd_layout));
        }
        0xa0 | 0xb0 => {
            let span = fs
                .runs_list(&cx, a.span, &list, a.data_size.min(MAX_INDEX_BYTES))?
                .finish(&cx, "ntfs-runs")
                .await?;
            if a.kind == 0xb0 {
                let bits = if record == 0 {
                    // The MFT's bitmap: one bit per record.
                    fs.mft
                        .iter()
                        .map(|p| p.len)
                        .fold(0u64, u64::saturating_add)
                        .checked_div(fs.record)
                        .unwrap_or(0)
                } else {
                    span.len.saturating_mul(8)
                };
                cx.emit(bitmap_node("Content", span, bits, "entries"));
            } else if fs.index == 4096 && span.len.is_multiple_of(4096) {
                // INDX records, dissected by the standalone index format.
                cx.emit(embedded_named(
                    "Index records",
                    fs.input.nested(span),
                    "ntfs-index",
                ));
            } else {
                cx.emit(content_node(&fs.input, span));
            }
        }
        _ => {}
    }
    Ok(())
}

/// The content of a data stream: resident value or runs.
async fn stream_content(cx: &Cx, fs: &Vol, a: &Attr) -> Result<Node> {
    if let Some(value) = a.resident {
        return Ok(content_node(&fs.input, value));
    }
    let raw = cx.read_avail(a.runs.unwrap_or(a.span.sub(0, 0))).await?;
    let (runs, problem) = parse_runs(&raw);
    if let Some(d) = problem {
        cx.diag(d);
    }
    if a.compression_unit != 0 {
        return compressed_content(cx, fs, a, &runs).await;
    }
    let list = fs.runs_list(cx, a.span, &runs, a.data_size)?;
    let span = list.finish(cx, "ntfs-runs").await?;
    cx.emit(fragments_node(cx, "Clusters", list.into_pieces()).await);
    Ok(content_node(&fs.input, span))
}

/// How a run of compression units is stored: first unit, unit count,
/// kind, and the clusters holding them.
type UnitRun = (u64, u64, &'static str, Vec<Span>);

/// The content of a compressed stream. It is stored in compression units
/// (usually 16 clusters): a unit whose clusters are all allocated is
/// stored as is, a wholly sparse one is zeros, and one whose allocated
/// clusters are followed by sparse ones holds LZNT1 data in those clusters,
/// decoded on demand (zero-filled to the unit).
async fn compressed_content(
    cx: &Cx,
    fs: &Vol,
    a: &Attr,
    runs: &[(u64, Option<u64>)],
) -> Result<Node> {
    if a.compression_unit > 16 {
        return Err(Diagnostic::malformed(format!(
            "compression unit of 2^{} clusters",
            a.compression_unit
        ))
        .at(a.span));
    }
    let per_unit = 1u64 << a.compression_unit;
    let unit = per_unit.saturating_mul(fs.cluster);
    let mut list = PieceList::new(a.span);
    let mut units: Vec<UnitRun> = Vec::new();
    let mut index = 0u64;
    // Runs not yet consumed, as (clusters left, next cluster).
    let mut queue: std::collections::VecDeque<(u64, Option<u64>)> =
        runs.iter().copied().filter(|r| r.0 > 0).collect();
    while list.len() < a.data_size {
        let want = a.data_size.saturating_sub(list.len());
        let Some(&(count, start)) = queue.front() else {
            break;
        };
        // Whole units within one run: stored or sparse, in bulk.
        let whole = count.checked_div(per_unit).unwrap_or(0);
        if whole > 0 {
            let clusters = whole.saturating_mul(per_unit);
            let len = clusters.saturating_mul(fs.cluster).min(want);
            let n = len.div_ceil(unit);
            match start {
                Some(lcn) => {
                    let span = fs.vol.sub(lcn.saturating_mul(fs.cluster), len);
                    units.push((index, n, "stored", vec![span]));
                    list.data(span);
                }
                None => {
                    units.push((index, n, "sparse (zeros)", Vec::new()));
                    list.hole(cx, len)?;
                }
            }
            index = index.saturating_add(n);
            if let Some(front) = queue.front_mut() {
                *front = (
                    count.saturating_sub(clusters),
                    start.map(|l| l.saturating_add(clusters)),
                );
                if front.0 == 0 {
                    queue.pop_front();
                }
            }
            continue;
        }
        // A unit spanning runs: gather its clusters.
        let mut need = per_unit;
        let mut pieces = Vec::new();
        let mut sparse = 0u64;
        while need > 0 {
            let Some(front) = queue.front_mut() else {
                break;
            };
            let take = front.0.min(need);
            match front.1 {
                Some(lcn) => pieces.push(fs.cluster_span(lcn, take)),
                None => sparse = sparse.saturating_add(take),
            }
            *front = (
                front.0.saturating_sub(take),
                front.1.map(|l| l.saturating_add(take)),
            );
            if front.0 == 0 {
                queue.pop_front();
            }
            need = need.saturating_sub(take);
        }
        let len = unit.min(want);
        if pieces.is_empty() {
            units.push((index, 1, "sparse (zeros)", Vec::new()));
            list.hole(cx, len)?;
        } else if sparse == 0 && need == 0 {
            let mut left = len;
            for &p in &pieces {
                let take = p.len.min(left);
                list.data(p.sub(0, take));
                left = left.saturating_sub(take);
            }
            units.push((index, 1, "stored", pieces));
        } else {
            let anchor = pieces.first().copied().unwrap_or(a.span);
            let packed = crate::formats::disk::assemble(cx, anchor, "ntfs-unit", &pieces).await?;
            let decoded = cx.decode_lazy(packed, &Codec::Lznt1 { size: Some(unit) }, unit)?;
            list.data(decoded.sub(0, len));
            units.push((index, 1, "LZNT1", pieces));
        }
        index = index.saturating_add(1);
        cx.checkpoint().await;
    }
    let span = list.finish(cx, "ntfs-compressed").await?;
    cx.emit(
        Node::new("Compression units")
            .summary(format!("{index} of {}", size(unit)))
            .lazy(unit_list, Arc::new(units)),
    );
    Ok(content_node(&fs.input, span))
}

async fn unit_list(cx: Cx, units: Arc<Vec<UnitRun>>) -> Result<()> {
    cx.set_count(Count::Exact(crate::bytes::to_u64(units.len())));
    for (first, count, kind, clusters) in units.iter() {
        let name = if *count == 1 {
            format!("Unit {first}")
        } else {
            format!(
                "Units {first}-{}",
                first.saturating_add(*count).saturating_sub(1)
            )
        };
        let stored = clusters.iter().map(|c| c.len).fold(0, u64::saturating_add);
        let mut node = Node::new(name).summary(if clusters.is_empty() {
            (*kind).to_owned()
        } else {
            format!("{kind}, {} in {} fragment(s)", size(stored), clusters.len())
        });
        if let [one] = clusters.as_slice() {
            node = node.span(*one);
        } else if !clusters.is_empty() {
            node = node.lazy(list_pieces, Arc::new(clusters.clone()));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn list_pieces(cx: Cx, pieces: Arc<Vec<Span>>) -> Result<()> {
    for (i, p) in pieces.iter().enumerate() {
        cx.push(
            Node::new(format!("Fragment {i}"))
                .span(*p)
                .summary(size(p.len)),
        )
        .await;
    }
    Ok(())
}

#[derive(Clone)]
struct Dir {
    fs: Vol,
    record: u64,
    ancestors: Arc<Vec<u64>>,
}

/// Lists the entries of an index node (root or INDX record).
async fn index_entries(cx: &Cx, node: Span, out: &mut Vec<(u64, Span)>) -> Result<()> {
    let head = cx.read(node.sub(0, 16)).await?;
    let first = u64::from(u32_le(&head, 0).unwrap_or(0));
    let total = u64::from(u32_le(&head, 4).unwrap_or(0)).min(node.len);
    let mut at = first;
    while at.saturating_add(16) <= total {
        let e = cx.read(node.sub(at, 16)).await?;
        let reference = u64_le(&e, 0).unwrap_or(0);
        let len = u64::from(u16_le(&e, 8).unwrap_or(0));
        let key = u64::from(u16_le(&e, 10).unwrap_or(0));
        let flags = u32_le(&e, 12).unwrap_or(0);
        if flags & 2 != 0 || len < 16 {
            break;
        }
        if key > 0 {
            out.push((reference, node.sub(at.saturating_add(16), key)));
        }
        at = at.saturating_add(len);
        cx.checkpoint().await;
    }
    Ok(())
}

async fn directory(cx: Cx, dir: Dir) -> Result<()> {
    let fs = dir.fs.clone();
    let span = fs.record_span(dir.record).ok_or_else(|| {
        Diagnostic::malformed(format!("record {} is outside the MFT", dir.record))
    })?;
    let rec = fixed_up(&cx, span, b"FILE").await?;
    let attrs = attributes(&cx, rec).await?;
    cx.emit(
        Node::new("MFT record")
            .span(span)
            .lazy(record_node, (fs.clone(), dir.record)),
    );
    let mut entries = Vec::new();
    if let Some(root) = attrs
        .iter()
        .find(|a| a.kind == 0x90 && a.name == "$I30")
        .and_then(|a| a.resident)
    {
        index_entries(&cx, root.tail(16), &mut entries).await?;
    }
    if let Some(alloc) = attrs.iter().find(|a| a.kind == 0xa0 && a.name == "$I30") {
        let raw = cx
            .read_avail(alloc.runs.unwrap_or(alloc.span.sub(0, 0)))
            .await?;
        let (runs, problem) = parse_runs(&raw);
        if let Some(d) = problem {
            cx.diag(d);
        }
        let stream = fs
            .runs_list(&cx, alloc.span, &runs, alloc.data_size.min(MAX_INDEX_BYTES))?
            .finish(&cx, "ntfs-runs")
            .await?;
        let block = match index_block_size(&attrs) {
            Some(v) => u64::from(u32_le(&cx.read_avail(v).await?, 8).unwrap_or(4096)),
            None => 4096,
        };
        let block = if block >= 512 && block % 512 == 0 {
            block
        } else {
            4096
        };
        let mut at = 0u64;
        while at < stream.len {
            cx.progress(at, stream.len);
            let indx = stream.sub(at, block);
            at = at.saturating_add(block);
            if cx.read_avail(indx.sub(0, 4)).await? != b"INDX" {
                continue;
            }
            match fixed_up(&cx, indx, b"INDX").await {
                Ok(fixed) => index_entries(&cx, fixed.tail(24), &mut entries).await?,
                Err(e) => cx.diag(e),
            }
        }
    }
    let mut ancestors = (*dir.ancestors).clone();
    ancestors.push(dir.record);
    let ancestors = Arc::new(ancestors);
    cx.set_count(Count::AtLeast(1));
    for (reference, key) in entries {
        let raw = cx.read_avail(key).await?;
        let namespace = raw.get(65).copied().unwrap_or(0);
        if namespace == 2 {
            continue;
        }
        let len = usize::from(raw.get(64).copied().unwrap_or(0));
        let name = crate::text::utf16(
            raw.get(66..66usize.saturating_add(len.saturating_mul(2)))
                .unwrap_or_default(),
            LE,
        );
        let record = reference & 0xffff_ffff_ffff;
        let attributes = u32_le(&raw, 56).unwrap_or(0);
        let real = u64_le(&raw, 48).unwrap_or(0);
        let node = Node::new(name).span(key);
        let node = if attributes & 0x1000_0000 != 0 {
            let node = node.summary(format!("directory, record {record}"));
            if record == dir.record || ancestors.contains(&record) || ancestors.len() > MAX_DEPTH {
                node.diag(Diagnostic::note(
                    "refers back to an enclosing directory; not followed",
                ))
            } else {
                node.lazy(
                    crate::expander!(self::directory: Dir),
                    Dir {
                        fs: fs.clone(),
                        record,
                        ancestors: ancestors.clone(),
                    },
                )
            }
        } else {
            node.summary(format!("{}, record {record}", size(real)))
                .lazy(record_node, (fs.clone(), record))
        };
        cx.push(node).await;
    }
    Ok(())
}

/// The index record size from $INDEX_ROOT (offset 8 of its value).
fn index_block_size(attrs: &[Attr]) -> Option<Span> {
    attrs
        .iter()
        .find(|a| a.kind == 0x90 && a.name == "$I30")
        .and_then(|a| a.resident)
        .map(|v| v.sub(0, 16))
}

// ---------------------------------------------------------------------------
// System files and attribute values

const VOLUME_FLAGS: FlagTable = &[
    flag(0x1, "DIRTY"),
    flag(0x2, "RESIZE_LOG_FILE"),
    flag(0x4, "UPGRADE_ON_MOUNT"),
    flag(0x8, "MOUNTED_ON_NT4"),
    flag(0x10, "DELETE_USN_UNDERWAY"),
    flag(0x20, "REPAIR_OBJECT_ID"),
    flag(0x4000, "CHKDSK_UNDERWAY"),
    flag(0x8000, "MODIFIED_BY_CHKDSK"),
];

record! {
    /// `$VOLUME_INFORMATION`.
    pub struct VolumeInformation {
        _reserved: u64 "Reserved",
        major: u8 "Major version",
        minor: u8 "Minor version",
        flags: u16 "Flags" .hex() .flags(VOLUME_FLAGS),
    }
}

record! {
    /// `$UpCase:$Info` (Windows 8 and later): how the table was made.
    pub struct UpcaseInfo {
        length: u32 "Length",
        _filler: u32 "Reserved",
        crc: u64 "CRC-64 of the table" .hex(),
        os_major: u32 "OS major version",
        os_minor: u32 "OS minor version",
        build: u32 "OS build",
        sp_major: u16 "Service pack major",
        sp_minor: u16 "Service pack minor",
    }
}

/// Collation rules (`$AttrDef`, `$INDEX_ROOT`).
const COLLATIONS: EnumTable = &[
    (0, "binary"),
    (1, "file name"),
    (2, "Unicode string"),
    (0x10, "ULONG"),
    (0x11, "SID"),
    (0x12, "security hash"),
    (0x13, "ULONGs"),
];

const ATTRDEF_FLAGS: FlagTable = &[
    flag(0x02, "INDEXABLE"),
    flag(0x04, "MULTIPLE"),
    flag(0x08, "NOT_ZERO"),
    flag(0x10, "INDEXED_UNIQUE"),
    flag(0x20, "NAMED_UNIQUE"),
    flag(0x40, "RESIDENT"),
    flag(0x80, "ALWAYS_LOG"),
];

/// Bytes of one `$AttrDef` entry.
const ATTRDEF: u64 = 160;

fn attrdef_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.bytes("Name", 128)
        .with(|b, n| n.value(text(crate::text::utf16_trimmed(b, LE))))
        .emit()?;
    f.u32("Type").hex().enumeration(ATTR_TYPES).emit()?;
    f.u32("Display rule").emit()?;
    f.u32("Collation rule").enumeration(COLLATIONS).emit()?;
    f.u32("Flags").hex().flags(ATTRDEF_FLAGS).emit()?;
    f.u64("Minimum size").emit()?;
    f.u64("Maximum size").hex().emit()?;
    Ok(())
}

/// The attribute definition table ($AttrDef, record 4).
async fn attrdef(cx: Cx, span: Span) -> Result<()> {
    let mut at = 0u64;
    while at.saturating_add(ATTRDEF) <= span.len {
        let entry = span.sub(at, ATTRDEF);
        let raw = cx.read(entry).await?;
        if u32_le(&raw, 128).unwrap_or(0) == 0 {
            break;
        }
        let name = crate::text::utf16_trimmed(raw.get(..128).unwrap_or_default(), LE);
        cx.push(struct_node(name, entry, LE, (), attrdef_layout))
            .await;
        at = at.saturating_add(ATTRDEF);
    }
    if at < span.len {
        cx.push(
            Node::new("End of table")
                .span(span.tail(at))
                .summary("zeros after the last definition"),
        )
        .await;
    }
    Ok(())
}

/// Bits set among the first `bits` of a bitmap (least significant bit
/// first), counted a chunk at a time.
async fn bitmap(cx: Cx, (span, bits): (Span, u64)) -> Result<()> {
    const CHUNK: u64 = 1 << 16;
    let used = span.sub(0, bits.div_ceil(8));
    let mut set = 0u64;
    let mut at = 0u64;
    while at < used.len {
        let chunk = cx.read(used.sub(at, CHUNK)).await?;
        let first = at.saturating_mul(8);
        for (i, &b) in chunk.iter().enumerate() {
            let bit = first.saturating_add(crate::bytes::to_u64(i).saturating_mul(8));
            let keep = bits.saturating_sub(bit).min(8);
            let mask = if keep >= 8 {
                0xff
            } else {
                1u8.checked_shl(u32::try_from(keep).unwrap_or(0))
                    .unwrap_or(0)
                    .wrapping_sub(1)
            };
            set = set.saturating_add(u64::from((b & mask).count_ones()));
        }
        at = at.saturating_add(CHUNK);
    }
    cx.emit(
        Node::new("Bits set")
            .span(used)
            .value(uint(set, 64))
            .summary(format!("of {bits}")),
    );
    if used.len < span.len {
        cx.emit(
            Node::new("Padding")
                .span(span.tail(used.len))
                .summary("past the last bit"),
        );
    }
    Ok(())
}

fn bitmap_node(name: &'static str, span: Span, bits: u64, what: &str) -> Node {
    Node::new(name)
        .span(span)
        .summary(format!("bitmap of {bits} {what}"))
        .lazy(bitmap, (span, bits))
}

/// The upper-case table ($UpCase, record 10): one UTF-16 unit per code
/// unit, summarised per block of 256, identity blocks merged.
async fn upcase(cx: Cx, span: Span) -> Result<()> {
    const BLOCK: u64 = 512;
    let blocks = span.len / BLOCK;
    let mut identity: Option<u64> = None;
    let flush = |from: u64, to: u64| {
        Node::new(format!(
            "U+{:04X}–U+{:04X}",
            from.saturating_mul(256),
            to.saturating_mul(256).saturating_sub(1)
        ))
        .span(span.sub(
            from.saturating_mul(BLOCK),
            to.saturating_sub(from).saturating_mul(BLOCK),
        ))
        .value(uint(0u64, 64))
        .summary("identity: no case mappings")
    };
    for k in 0..blocks {
        let raw = cx.read(span.sub(k.saturating_mul(BLOCK), BLOCK)).await?;
        let base = k.saturating_mul(256);
        let mut mapped = 0u64;
        for (i, c) in raw.as_chunks::<2>().0.iter().enumerate() {
            if u64::from(u16::from_le_bytes(*c)) != base.saturating_add(crate::bytes::to_u64(i)) {
                mapped = mapped.saturating_add(1);
            }
        }
        if mapped == 0 {
            identity.get_or_insert(k);
            continue;
        }
        if let Some(from) = identity.take() {
            cx.push(flush(from, k)).await;
        }
        cx.push(
            Node::new(format!("U+{base:04X}–U+{:04X}", base.saturating_add(255)))
                .span(span.sub(k.saturating_mul(BLOCK), BLOCK))
                .value(uint(mapped, 64))
                .summary("characters mapped to another"),
        )
        .await;
    }
    if let Some(from) = identity {
        cx.push(flush(from, blocks)).await;
    }
    Ok(())
}

/// What a 4 KiB page of an uninitialised $LogFile holds.
fn log_page_class(b: &[u8]) -> &'static str {
    if b.iter().all(|&x| x == 0xff) {
        "unused, filled with 0xff"
    } else if b.iter().all(|&x| x == 0) {
        "unused, zeros"
    } else {
        match b.get(..4) {
            Some(b"RSTR") => "restart page",
            Some(b"RCRD") => "record page",
            Some(b"BAAD") => "bad page",
            _ => "unrecognised page",
        }
    }
}

/// A $LogFile that is not initialised as a log (no restart page): its
/// pages, runs of the same kind merged.
async fn log_pages(cx: Cx, span: Span) -> Result<()> {
    const PAGE: u64 = 4096;
    let pages = span.len / PAGE;
    let flush = |from: u64, to: u64, what: &str| {
        let name = if to.saturating_sub(from) == 1 {
            format!("Page {from}")
        } else {
            format!("Pages {from}–{}", to.saturating_sub(1))
        };
        Node::new(name)
            .span(span.sub(
                from.saturating_mul(PAGE),
                to.saturating_sub(from).saturating_mul(PAGE),
            ))
            .value(text(what))
    };
    let mut run: Option<(u64, &'static str)> = None;
    for p in 0..pages {
        let raw = cx.read(span.sub(p.saturating_mul(PAGE), PAGE)).await?;
        let what = log_page_class(&raw);
        match run {
            Some((_, prev)) if prev == what => {}
            Some((from, prev)) => {
                cx.push(flush(from, p, prev)).await;
                run = Some((p, what));
            }
            None => run = Some((p, what)),
        }
    }
    if let Some((from, what)) = run {
        cx.push(flush(from, pages, what)).await;
    }
    Ok(())
}

/// Block size of the security descriptor stream's mirrored halves.
const SDS_BLOCK: u64 = 0x40000;

/// The security descriptor stream ($Secure:$SDS): 256 KiB blocks, each
/// followed by a mirror copy of itself.
async fn sds(cx: Cx, span: Span) -> Result<()> {
    let blocks = span.len.div_ceil(SDS_BLOCK);
    for k in 0..blocks {
        let block = span.sub(k.saturating_mul(SDS_BLOCK), SDS_BLOCK);
        let name = if k % 2 == 1 {
            format!("Block {k} (mirror of block {})", k.saturating_sub(1))
        } else {
            format!("Block {k}")
        };
        cx.push(
            Node::new(name)
                .span(block)
                .summary(size(block.len))
                .lazy(sds_block, block),
        )
        .await;
    }
    Ok(())
}

const SDS_HEADER: u64 = 20;

/// An $SDS entry: its header, then the self-relative security descriptor
/// (header fields; the SIDs and ACLs it points to are left as bytes).
fn sds_entry_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Hash").hex().emit()?;
    f.u32("Security id").emit()?;
    f.u64("Offset in stream").hex().emit()?;
    let len = f.u32("Length").emit()?;
    security_descriptor(f, u64::from(len).saturating_sub(SDS_HEADER))
}

/// A `$SECURITY_DESCRIPTOR` attribute value.
fn sd_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let len = f.remaining();
    security_descriptor(f, len)
}

/// A self-relative security descriptor of `sd` bytes: its header; the SIDs
/// and ACLs it points to are left as bytes.
fn security_descriptor(f: &mut Fields<'_>, sd: u64) -> Result<()> {
    if sd >= 20 {
        f.u8("Revision").emit()?;
        f.u8("Reserved").emit()?;
        f.u16("Control").hex().emit()?;
        f.u32("Owner offset").hex().emit()?;
        f.u32("Group offset").hex().emit()?;
        f.u32("SACL offset").hex().emit()?;
        f.u32("DACL offset").hex().emit()?;
        if sd > 20 {
            f.bytes("SIDs and ACLs", sd.saturating_sub(20)).emit()?;
        }
    } else if sd > 0 {
        f.bytes("Security descriptor", sd).emit()?;
    }
    Ok(())
}

async fn sds_block(cx: Cx, block: Span) -> Result<()> {
    let mut at = 0u64;
    while at.saturating_add(SDS_HEADER) <= block.len {
        let head = cx.read(block.sub(at, SDS_HEADER)).await?;
        let id = u32_le(&head, 4).unwrap_or(0);
        let len = u64::from(u32_le(&head, 16).unwrap_or(0));
        if len < SDS_HEADER || at.saturating_add(len) > block.len {
            break;
        }
        cx.push(
            struct_node(
                format!("Security id {id}"),
                block.sub(at, len),
                LE,
                (),
                sds_entry_layout,
            )
            .summary(format!("hash {:#010x}", u32_le(&head, 0).unwrap_or(0))),
        )
        .await;
        at = at.saturating_add(len).next_multiple_of(16);
    }
    if at < block.len {
        cx.push(
            Node::new("Free space")
                .span(block.tail(at))
                .summary("after the last descriptor"),
        )
        .await;
    }
    Ok(())
}

const INDEX_FLAGS: FlagTable = &[flag(1, "HAS_SUBNODE"), flag(2, "LAST_ENTRY")];
const INDEX_ROOT_FLAGS: FlagTable = &[flag(1, "LARGE_INDEX")];

fn index_root_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Indexed attribute")
        .hex()
        .enumeration(ATTR_TYPES)
        .emit()?;
    f.u32("Collation rule").enumeration(COLLATIONS).emit()?;
    f.u32("Index record size").emit()?;
    f.u8("Clusters per index record").emit()?;
    f.bytes("Padding", 3).emit()?;
    f.u32("Entries offset").hex().emit()?;
    f.u32("Index length").emit()?;
    f.u32("Allocated length").emit()?;
    f.u8("Flags").hex().flags(INDEX_ROOT_FLAGS).emit()?;
    f.bytes("Padding", 3).emit()?;
    Ok(())
}

/// An index entry: a file name entry of a directory (`$I30`), or a view
/// index entry (`$SDH`, `$SII`, `$O`, `$Q`, `$R`) with its own key and data.
fn index_entry_layout(f: &mut Fields<'_>, view: &bool) -> Result<()> {
    let len;
    let flags;
    if *view {
        let data_off = f.u16("Data offset").hex().emit()?;
        let data_len = f.u16("Data length").emit()?;
        f.u32("Reserved").emit()?;
        len = f.u16("Entry length").emit()?;
        let key = f.u16("Key length").emit()?;
        flags = f.u16("Flags").hex().flags(INDEX_FLAGS).emit()?;
        f.u16("Reserved").emit()?;
        if key > 0 {
            f.bytes("Key", key.into()).emit()?;
        }
        if data_len > 0 {
            f.seek(data_off.into());
            f.bytes("Data", data_len.into()).emit()?;
        }
    } else {
        f.u64("File reference")
            .with(|&r, n| n.summary(reference(r)))
            .emit()?;
        len = f.u16("Entry length").emit()?;
        let key = f.u16("Key length").emit()?;
        flags = f.u16("Flags").hex().flags(INDEX_FLAGS).emit()?;
        f.u16("Reserved").emit()?;
        if u64::from(key) >= FileName::SIZE {
            let name = FileName::layout(f, &())?;
            f.utf16("Name", name.name_length.into()).emit()?;
        } else if key > 0 {
            f.bytes("Key", key.into()).emit()?;
        }
    }
    if flags & 1 != 0 {
        f.seek(u64::from(len).saturating_sub(8));
        f.u64("Subnode VCN").emit()?;
    }
    Ok(())
}

/// The value of an `$INDEX_ROOT`: header, then the root node's entries.
async fn index_root(cx: &Cx, value: Span) -> Result<()> {
    cx.emit(struct_node(
        "Index header",
        value.sub(0, 32),
        LE,
        (),
        index_root_header,
    ));
    let head = cx.read(value.sub(0, 32)).await?;
    let view = u32_le(&head, 0) != Some(0x30);
    let node = value.tail(16);
    let first = u64::from(u32_le(&head, 16).unwrap_or(0));
    let total = u64::from(u32_le(&head, 20).unwrap_or(0)).min(node.len);
    let mut at = first;
    let mut i = 0u32;
    while at.saturating_add(16) <= total && i < 1024 {
        let e = cx.read(node.sub(at, 16)).await?;
        let len = u64::from(u16_le(&e, 8).unwrap_or(0));
        let key = u64::from(u16_le(&e, 10).unwrap_or(0));
        let flags = u16_le(&e, 12).unwrap_or(0);
        if len < 16 {
            break;
        }
        let span = node.sub(at, len);
        let summary = if flags & 2 != 0 {
            "end of node".to_owned()
        } else if !view && key >= FileName::SIZE {
            let raw = cx.read_avail(span).await?;
            let n = usize::from(raw.get(80).copied().unwrap_or(0));
            crate::text::utf16(
                raw.get(82..82usize.saturating_add(n.saturating_mul(2)))
                    .unwrap_or_default(),
                LE,
            )
        } else {
            format!("{key} key bytes")
        };
        cx.emit(
            struct_node(format!("Entry {i}"), span, LE, view, index_entry_layout).summary(summary),
        );
        if flags & 2 != 0 {
            break;
        }
        at = at.saturating_add(len);
        i = i.saturating_add(1);
        cx.checkpoint().await;
    }
    Ok(())
}

fn object_id_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    for name in [
        "Object id",
        "Birth volume id",
        "Birth object id",
        "Domain id",
    ] {
        if f.remaining() < 16 {
            break;
        }
        f.guid(name).emit()?;
    }
    Ok(())
}
