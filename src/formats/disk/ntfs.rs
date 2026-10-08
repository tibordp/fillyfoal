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
use crate::fields::{Endian, parse};
use crate::formats::disk::{PieceList, content_node, fragments_node, size};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

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

const ATTR_TYPES: EnumTable = &[
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

const FILE_ATTRIBUTES: FlagTable = &[
    flag(0x1, "READONLY"),
    flag(0x2, "HIDDEN"),
    flag(0x4, "SYSTEM"),
    flag(0x20, "ARCHIVE"),
    flag(0x40, "DEVICE"),
    flag(0x80, "NORMAL"),
    flag(0x100, "TEMPORARY"),
    flag(0x200, "SPARSE"),
    flag(0x400, "REPARSE_POINT"),
    flag(0x800, "COMPRESSED"),
    flag(0x1000, "OFFLINE"),
    flag(0x2000, "NOT_CONTENT_INDEXED"),
    flag(0x4000, "ENCRYPTED"),
    flag(0x1000_0000, "DIRECTORY"),
    flag(0x2000_0000, "INDEX_VIEW"),
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

const NAMESPACES: EnumTable = &[(0, "POSIX"), (1, "Win32"), (2, "DOS"), (3, "Win32 and DOS")];

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

/// A multi-sector protected structure (MFT or index record) as a piecewise
/// source with the update sequence applied.
async fn fixed_up(cx: &Cx, span: Span, magic: &[u8]) -> Result<Span> {
    let head = cx.read(span.sub(0, 8)).await?;
    if head.get(..4) != Some(magic) {
        return Err(Diagnostic::malformed(format!(
            "expected {:?} record",
            String::from_utf8_lossy(magic)
        ))
        .at(span.sub(0, 4)));
    }
    let usa = u64::from(u16_le(&head, 4).unwrap_or(0));
    let count = u64::from(u16_le(&head, 6).unwrap_or(0));
    let sectors = span.len / 512;
    if count != sectors.saturating_add(1) || usa.saturating_add(count.saturating_mul(2)) > 512 {
        return Err(Diagnostic::malformed(format!(
            "update sequence of {count} entries for {sectors} sectors"
        ))
        .at(span));
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
    if let Some(d) = problem {
        cx.diag(d.at(span));
    }
    cx.add_pieces(
        Origin {
            parent: span,
            transform: "ntfs-fixup",
        },
        pieces,
    )
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
        cx.emit(attribute_node(&fs, a));
    }
    if let Some(data) = attrs.iter().find(|a| a.kind == 0x80 && a.name.is_empty()) {
        cx.emit(stream_content(&cx, &fs, data).await?);
    }
    Ok(())
}

fn attribute_node(fs: &Vol, a: &Attr) -> Node {
    let kind = lookup(ATTR_TYPES, a.kind.into())
        .map_or_else(|| format!("Attribute {:#x}", a.kind), str::to_owned);
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
        .lazy(attribute_fields, (fs.clone(), Arc::new(a.clone())))
}

async fn attribute_fields(cx: Cx, (fs, a): (Vol, Arc<Attr>)) -> Result<()> {
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
            0x70 => {
                let raw = cx.read_avail(value).await?;
                cx.emit(
                    Node::new("NTFS version")
                        .span(value.sub(8, 2))
                        .value(Value::Text(format!(
                            "{}.{}",
                            raw.get(8).copied().unwrap_or(0),
                            raw.get(9).copied().unwrap_or(0)
                        ))),
                );
                cx.emit(
                    Node::new("Flags")
                        .span(value.sub(10, 2))
                        .value(Value::UInt {
                            value: u16_le(&raw, 10).unwrap_or(0).into(),
                            bits: 16,
                            radix: crate::value::Radix::Hex,
                        }),
                );
            }
            _ => cx.emit(Node::new("Value").span(value).summary(size(value.len))),
        }
        return Ok(());
    }
    if let Some(runs) = a.runs {
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
    let pieces = list.pieces().to_vec();
    let span = list.finish(cx, "ntfs-runs")?;
    cx.emit(fragments_node("Clusters", pieces));
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
            let packed = crate::formats::disk::assemble(cx, anchor, "ntfs-unit", pieces.clone())?;
            let decoded = cx.decode_lazy(packed, &Codec::Lznt1 { size: Some(unit) }, unit)?;
            list.data(decoded.sub(0, len));
            units.push((index, 1, "LZNT1", pieces));
        }
        index = index.saturating_add(1);
        cx.checkpoint().await;
    }
    let span = list.finish(cx, "ntfs-compressed")?;
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
            .finish(&cx, "ntfs-runs")?;
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
