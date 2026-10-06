//! exFAT filesystems.
//!
//! The main boot region (boot sector, extended boot sectors, OEM
//! parameters, checksum sector) locates the FAT and the cluster heap. The
//! root directory holds the allocation bitmap, up-case table and volume
//! label entries; files are entry sets (file, stream extension, names).
//! Directories are lazy, paged trees; file content follows its cluster chain
//! (or is contiguous when flagged so) and is assembled when fragmented.

use std::collections::HashSet;
use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{assemble, coalesce, content_node, dos_stamp, fragments_node, size};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const ENTRY: u64 = 32;
/// Directories are at most 256 MiB; we read at most this much of one.
const MAX_DIR_BYTES: u64 = 8 << 20;
const MAX_DEPTH: usize = 64;

pub static FORMAT: Format = Format {
    name: "exfat",
    title: "exFAT filesystem",
    extensions: &["img", "exfat"],
    mime: "application/x-exfat",
    probe: Probe::Magic(&[(3, b"EXFAT   ")]),
    dissect: crate::expander!(dissect: Input),
};

const VOLUME_FLAGS: FlagTable = &[
    flag(1, "ACTIVE_FAT"),
    flag(2, "VOLUME_DIRTY"),
    flag(4, "MEDIA_FAILURE"),
    flag(8, "CLEAR_TO_ZERO"),
];

record! {
    pub struct BootSector {
        jump: bytes[3] "Jump instruction",
        name: ascii[8] "File system name",
        _zero: bytes[53] "Must be zero",
        partition_offset: u64 "Partition offset (sectors)",
        volume_length: u64 "Volume length (sectors)",
        fat_offset: u32 "FAT offset (sectors)",
        fat_length: u32 "FAT length (sectors)",
        heap_offset: u32 "Cluster heap offset (sectors)",
        cluster_count: u32 "Cluster count",
        root_cluster: u32 "Root directory cluster",
        serial: u32 "Volume serial number" .hex(),
        revision: u16 "File system revision" .hex() .with(|&r, n| n.summary(format!("{}.{:02}", r >> 8, r & 0xff))),
        flags: u16 "Volume flags" .hex() .flags(VOLUME_FLAGS),
        sector_shift: u8 "Bytes per sector (log2)" .with(|&s, n| n.summary(size(1u64.checked_shl(s.into()).unwrap_or(0)))),
        cluster_shift: u8 "Sectors per cluster (log2)",
        fats: u8 "Number of FATs",
        drive: u8 "Drive select" .hex(),
        percent_used: u8 "Percent in use",
    }
}

const ATTRS: FlagTable = &[
    flag(0x01, "READ_ONLY"),
    flag(0x02, "HIDDEN"),
    flag(0x04, "SYSTEM"),
    flag(0x10, "DIRECTORY"),
    flag(0x20, "ARCHIVE"),
];

record! {
    /// File directory entry (0x85).
    pub struct FileEntry {
        kind: u8 "Entry type" .hex(),
        secondary: u8 "Secondary entries",
        checksum: u16 "Set checksum" .hex(),
        attributes: u16 "Attributes" .hex() .flags(ATTRS),
        _reserved: u16 "Reserved",
        created: u32 "Created" .with(dos_stamp),
        modified: u32 "Modified" .with(dos_stamp),
        accessed: u32 "Accessed" .with(dos_stamp),
        created_10ms: u8 "Created, 10 ms increment",
        modified_10ms: u8 "Modified, 10 ms increment",
        created_utc: u8 "Created, UTC offset" .with(|&o, n| n.summary(utc_offset(o))),
        modified_utc: u8 "Modified, UTC offset" .with(|&o, n| n.summary(utc_offset(o))),
        accessed_utc: u8 "Accessed, UTC offset" .with(|&o, n| n.summary(utc_offset(o))),
    }
}

const STREAM_FLAGS: FlagTable = &[flag(1, "ALLOCATION_POSSIBLE"), flag(2, "NO_FAT_CHAIN")];

record! {
    /// Stream extension entry (0xC0).
    pub struct StreamEntry {
        kind: u8 "Entry type" .hex(),
        flags: u8 "Flags" .hex() .flags(STREAM_FLAGS),
        _reserved: u8 "Reserved",
        name_length: u8 "Name length",
        name_hash: u16 "Name hash" .hex(),
        _reserved2: u16 "Reserved",
        valid_length: u64 "Valid data length",
        _reserved3: u32 "Reserved",
        first_cluster: u32 "First cluster",
        length: u64 "Data length" .with(|&v, n| n.summary(size(v))),
    }
}

record! {
    /// File name entry (0xC1).
    pub struct NameEntry {
        kind: u8 "Entry type" .hex(),
        flags: u8 "Flags" .hex(),
        name: utf16[15] "Name characters",
    }
}

record! {
    /// Allocation bitmap (0x81) and up-case table (0x82) entries share
    /// this shape.
    pub struct TableEntry {
        kind: u8 "Entry type" .hex(),
        flags: u8 "Flags" .hex(),
        _reserved: bytes[2] "Reserved",
        checksum: u32 "Table checksum (up-case)" .hex(),
        _reserved2: bytes[12] "Reserved",
        first_cluster: u32 "First cluster",
        length: u64 "Data length" .with(|&v, n| n.summary(size(v))),
    }
}

fn utc_offset(o: u8) -> String {
    if o & 0x80 == 0 {
        return "not recorded".to_owned();
    }
    // Seven-bit signed count of 15-minute increments.
    let quarters = i32::from(i8::from_le_bytes([o << 1]) >> 1);
    let minutes = quarters.saturating_mul(15);
    format!(
        "UTC{}{:02}:{:02}",
        if minutes < 0 { '-' } else { '+' },
        minutes.abs() / 60,
        minutes.abs() % 60
    )
}

#[derive(Debug)]
struct Volume {
    input: Input,
    fat: Span,
    heap: Span,
    cluster: u64,
    clusters: u32,
}

type Vol = Arc<Volume>;

impl Volume {
    fn cluster_span(&self, c: u32) -> Option<Span> {
        let index = c.checked_sub(2)?;
        (index < self.clusters).then(|| {
            self.heap
                .sub(u64::from(index).saturating_mul(self.cluster), self.cluster)
        })
    }

    /// The clusters of an allocation: contiguous, or following the FAT.
    async fn chain(
        &self,
        cx: &Cx,
        first: u32,
        contiguous: bool,
        len: u64,
    ) -> Result<(Vec<Span>, Option<Diagnostic>)> {
        let needed = len.div_ceil(self.cluster.max(1));
        if contiguous {
            let start = self
                .cluster_span(first)
                .ok_or_else(|| Diagnostic::malformed(format!("cluster {first} is out of range")))?;
            let span = self.heap.sub(
                start.offset.saturating_sub(self.heap.offset),
                needed.saturating_mul(self.cluster),
            );
            let problem = (span.len < len)
                .then(|| Diagnostic::truncated(Span::new(span.source, span.offset, len), span.len));
            return Ok((vec![span], problem));
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut c = first;
        while to_u64(out.len()) < needed {
            let Some(span) = self.cluster_span(c) else {
                return Ok((
                    out,
                    Some(Diagnostic::malformed(format!(
                        "cluster {c} is out of range"
                    ))),
                ));
            };
            if !seen.insert(c) {
                return Ok((
                    out,
                    Some(Diagnostic::malformed(format!(
                        "cluster chain loops back to {c}"
                    ))),
                ));
            }
            out.push(span);
            let raw = cx
                .read(self.fat.sub(u64::from(c).saturating_mul(4), 4))
                .await?;
            let next = u32_le(&raw, 0).unwrap_or(u32::MAX);
            if next >= 0xffff_fff7 {
                break;
            }
            c = next;
        }
        let problem = (to_u64(out.len()) < needed).then(|| {
            Diagnostic::malformed(format!(
                "cluster chain has {} clusters, {needed} needed",
                out.len()
            ))
        });
        Ok((out, problem))
    }
}

/// The boot region checksum over sectors 0-10 (skipping the volatile
/// VolumeFlags and PercentInUse fields).
fn boot_checksum(data: &[u8]) -> u32 {
    data.iter().enumerate().fold(0u32, |sum, (i, &b)| {
        if matches!(i, 106 | 107 | 112) {
            sum
        } else {
            sum.rotate_right(1).wrapping_add(b.into())
        }
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let bs = parse(
        &cx,
        vol.sub(0, BootSector::SIZE),
        LE,
        &(),
        BootSector::layout,
    )
    .await?;
    if !(9..=12).contains(&bs.sector_shift)
        || bs.cluster_shift > 25u8.saturating_sub(bs.sector_shift)
    {
        return Err(Diagnostic::malformed("implausible sector or cluster size").at(vol.sub(108, 2)));
    }
    let sector = 1u64 << bs.sector_shift;
    let cluster = sector << bs.cluster_shift;
    let region = vol.sub(0, sector.saturating_mul(12));
    let data = cx.read_avail(region).await?;
    let mut boot = BootSector::node("Boot sector", vol.sub(0, sector), LE);
    let computed = boot_checksum(
        data.get(..crate::bytes::to_usize(sector.saturating_mul(11)))
            .unwrap_or_default(),
    );
    let stored = u32_le(&data, crate::bytes::to_usize(sector.saturating_mul(11)));
    if stored.is_some_and(|s| s != computed) {
        boot = boot.diag(Diagnostic::warning(format!(
            "boot region checksum mismatch: computed {computed:#010x}"
        )));
    }
    cx.emit(boot);
    cx.emit(Node::new("Extended boot sectors").span(vol.sub(sector, sector.saturating_mul(8))));
    cx.emit(Node::new("OEM parameters").span(vol.sub(sector.saturating_mul(9), sector)));
    cx.emit(
        Node::new("Boot checksum sector")
            .span(vol.sub(sector.saturating_mul(11), sector))
            .value(Value::UInt {
                value: stored.unwrap_or(0).into(),
                bits: 32,
                radix: crate::value::Radix::Hex,
            }),
    );
    cx.emit(
        Node::new("Backup boot region")
            .span(vol.sub(sector.saturating_mul(12), sector.saturating_mul(12))),
    );
    let fat = vol.sub(
        u64::from(bs.fat_offset).saturating_mul(sector),
        u64::from(bs.fat_length).saturating_mul(sector),
    );
    cx.emit(
        Node::new("FAT")
            .span(fat)
            .summary(format!("{} entries", bs.cluster_count.saturating_add(2))),
    );
    let heap = vol.sub(
        u64::from(bs.heap_offset).saturating_mul(sector),
        u64::from(bs.cluster_count).saturating_mul(cluster),
    );
    let fs: Vol = Arc::new(Volume {
        input,
        fat,
        heap,
        cluster,
        clusters: bs.cluster_count,
    });
    // The volume label lives in the root directory.
    let (root_pieces, _) = fs.chain(&cx, bs.root_cluster, false, cluster).await?;
    let mut label = String::new();
    if let Some(first) = root_pieces.first() {
        let raw = cx.read_avail(*first).await?;
        for e in raw.as_chunks::<32>().0 {
            if e.first() == Some(&0x83) {
                let n = usize::from(e.get(1).copied().unwrap_or(0).min(11));
                label = crate::text::utf16(
                    e.get(2..2usize.saturating_add(n.saturating_mul(2)))
                        .unwrap_or_default(),
                    LE,
                );
                break;
            }
        }
    }
    cx.annotate(format!(
        "exFAT filesystem{}, {}, {} clusters of {}",
        if label.is_empty() {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(bs.volume_length.saturating_mul(sector)),
        bs.cluster_count,
        size(cluster)
    ));
    cx.emit(
        Node::new("Root directory")
            .summary(format!("cluster {}", bs.root_cluster))
            .lazy(
                crate::expander!(self::directory: Dir),
                Dir {
                    vol: fs.clone(),
                    first: bs.root_cluster,
                    contiguous: false,
                    len: MAX_DIR_BYTES,
                    ancestors: Arc::new(Vec::new()),
                },
            ),
    );
    cx.emit(Node::new("Cluster heap").span(heap).summary(size(heap.len)));
    Ok(())
}

#[derive(Clone)]
struct Dir {
    vol: Vol,
    first: u32,
    contiguous: bool,
    len: u64,
    ancestors: Arc<Vec<u32>>,
}

/// Iterates over the 32-byte entries of a directory's clusters.
struct Entries {
    pieces: Vec<Span>,
    piece: usize,
    data: Vec<u8>,
    at: usize,
}

impl Entries {
    async fn next(&mut self, cx: &Cx) -> Result<Option<([u8; 32], Span)>> {
        loop {
            let Some(piece) = self.pieces.get(self.piece).copied() else {
                return Ok(None);
            };
            if self.at == 0 && self.data.is_empty() {
                self.data = cx.read_avail(piece).await?;
            }
            if let Some(raw) = self.data.get(self.at..self.at.saturating_add(32)) {
                let mut e = [0u8; 32];
                e.copy_from_slice(raw);
                let span = piece.sub(to_u64(self.at), ENTRY);
                self.at = self.at.saturating_add(32);
                return Ok(Some((e, span)));
            }
            self.piece = self.piece.saturating_add(1);
            self.at = 0;
            self.data.clear();
        }
    }
}

async fn directory(cx: Cx, dir: Dir) -> Result<()> {
    let fs = dir.vol.clone();
    let (pieces, problem) = fs
        .chain(&cx, dir.first, dir.contiguous, dir.len.min(MAX_DIR_BYTES))
        .await?;
    if let Some(d) = problem.filter(|_| dir.len < MAX_DIR_BYTES) {
        cx.diag(d);
    }
    let mut ancestors = (*dir.ancestors).clone();
    ancestors.push(dir.first);
    let ancestors = Arc::new(ancestors);
    let mut entries = Entries {
        pieces,
        piece: 0,
        data: Vec::new(),
        at: 0,
    };
    while let Some((e, span)) = entries.next(&cx).await? {
        let kind = e[0];
        match kind {
            0x00 => break,
            0x81 | 0x82 => {
                let name = if kind == 0x81 {
                    "Allocation bitmap"
                } else {
                    "Up-case table"
                };
                let first = u32_le(&e, 20).unwrap_or(0);
                let len = u64_le(&e, 24).unwrap_or(0);
                let (pieces, _) = fs.chain(&cx, first, false, len).await?;
                let data = coalesce(pieces, len);
                let mut node = TableEntry::node(name, span, LE).summary(size(len));
                if let Some(first) = data.first() {
                    node = node.target(*first);
                }
                cx.push(node).await;
            }
            0x83 => {
                let n = usize::from(e[1].min(11));
                let label = crate::text::utf16(
                    e.get(2..2usize.saturating_add(n.saturating_mul(2)))
                        .unwrap_or_default(),
                    LE,
                );
                cx.push(
                    Node::new("Volume label")
                        .span(span)
                        .value(Value::Text(label)),
                )
                .await;
            }
            0xa0 => {
                cx.push(Node::new("Volume GUID").span(span).value(Value::Guid(
                    crate::formats::disk::guid_le(e.get(6..22).unwrap_or_default()),
                )))
                .await
            }
            0x85 => {
                let set = file_set(&cx, &mut entries, e, span).await?;
                cx.push(file_node(&fs, &ancestors, set)).await;
            }
            k if k & 0x80 == 0 => cx.checkpoint().await,
            _ => {
                cx.push(Node::new(format!("Entry {kind:#04x}")).span(span))
                    .await
            }
        }
    }
    Ok(())
}

/// A file entry set: the file entry, its stream extension and name entries.
#[derive(Clone, Debug)]
struct FileSet {
    span: Span,
    entries: Vec<Span>,
    name: String,
    attributes: u16,
    modified: u32,
    stream: Option<[u8; 32]>,
    checksum_ok: bool,
}

async fn file_set(cx: &Cx, it: &mut Entries, first: [u8; 32], span: Span) -> Result<FileSet> {
    let secondary = usize::from(first[1]);
    let mut set = FileSet {
        span,
        entries: vec![span],
        name: String::new(),
        attributes: u16_le(&first, 4).unwrap_or(0),
        modified: u32_le(&first, 12).unwrap_or(0),
        stream: None,
        checksum_ok: true,
    };
    let mut checksum = 0u16;
    for (i, &b) in first.iter().enumerate() {
        if i != 2 && i != 3 {
            checksum = checksum.rotate_right(1).wrapping_add(b.into());
        }
    }
    let mut units: Vec<u16> = Vec::new();
    for _ in 0..secondary {
        let Some((e, s)) = it.next(cx).await? else {
            break;
        };
        for &b in &e {
            checksum = checksum.rotate_right(1).wrapping_add(b.into());
        }
        set.entries.push(s);
        match e[0] {
            0xc0 => set.stream = Some(e),
            0xc1 => units.extend(
                e.get(2..)
                    .unwrap_or_default()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|p| u16::from_le_bytes(*p)),
            ),
            _ => {}
        }
    }
    let name_len = set.stream.map_or(0, |s| usize::from(s[3]));
    units.truncate(name_len);
    set.name = String::from_utf16_lossy(&units);
    set.checksum_ok = u16_le(&first, 2) == Some(checksum);
    if let (Some(a), Some(b)) = (set.entries.first(), set.entries.last())
        && a.source == b.source
        && b.end() > a.offset
    {
        set.span = Span::new(a.source, a.offset, b.end().saturating_sub(a.offset));
    }
    Ok(set)
}

fn file_node(fs: &Vol, ancestors: &Arc<Vec<u32>>, set: FileSet) -> Node {
    let when = crate::text::dos_datetime(
        u16::try_from(set.modified >> 16).unwrap_or(0),
        u16::try_from(set.modified & 0xffff).unwrap_or(0),
    );
    let stream = set.stream.unwrap_or([0; 32]);
    let first = u32_le(&stream, 20).unwrap_or(0);
    let len = u64_le(&stream, 24).unwrap_or(0);
    let contiguous = stream[1] & 2 != 0;
    let mut node = Node::new(if set.name.is_empty() {
        "(unnamed)".to_owned()
    } else {
        set.name.clone()
    })
    .span(set.span);
    if !set.checksum_ok {
        node = node.diag(Diagnostic::warning("entry set checksum mismatch"));
    }
    if set.stream.is_none() {
        return node.diag(Diagnostic::malformed(
            "file entry without a stream extension",
        ));
    }
    if set.attributes & 0x10 != 0 {
        node = node.summary(format!("directory, modified {when}"));
        if first == 0 || ancestors.contains(&first) || ancestors.len() > MAX_DEPTH {
            return node.diag(Diagnostic::malformed(format!(
                "directory refers back to cluster {first}; not followed"
            )));
        }
        return node.lazy(
            crate::expander!(self::directory_with_entries: (Dir, Arc<FileSet>)),
            (
                Dir {
                    vol: fs.clone(),
                    first,
                    contiguous,
                    len: len.max(1),
                    ancestors: ancestors.clone(),
                },
                Arc::new(set),
            ),
        );
    }
    node.summary(format!("{}, modified {when}", size(len)))
        .lazy(file, (fs.clone(), Arc::new(set)))
}

/// Emits a directory's own entry set, then its contents.
async fn directory_with_entries(cx: Cx, (dir, set): (Dir, Arc<FileSet>)) -> Result<()> {
    cx.emit(entry_set_node(&set));
    directory(cx, dir).await
}

fn entry_set_node(set: &FileSet) -> Node {
    Node::new("Directory entries")
        .span(set.span)
        .summary(format!("{} entries", set.entries.len()))
        .lazy(entry_set, Arc::new(set.entries.clone()))
}

async fn entry_set(cx: Cx, entries: Arc<Vec<Span>>) -> Result<()> {
    for span in entries.iter() {
        let raw = cx.read(span.sub(0, 1)).await?;
        let node = match raw.first() {
            Some(0x85) => FileEntry::node("File", *span, LE),
            Some(0xc0) => StreamEntry::node("Stream extension", *span, LE),
            Some(0xc1) => NameEntry::node("File name", *span, LE),
            _ => Node::new("Entry").span(*span),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn file(cx: Cx, (fs, set): (Vol, Arc<FileSet>)) -> Result<()> {
    cx.emit(entry_set_node(&set));
    let stream = set.stream.unwrap_or([0; 32]);
    let first = u32_le(&stream, 20).unwrap_or(0);
    let len = u64_le(&stream, 24).unwrap_or(0);
    let valid = u64_le(&stream, 8).unwrap_or(0);
    if len == 0 {
        return Ok(());
    }
    if valid < len {
        cx.diag(Diagnostic::note(format!(
            "only the first {valid} bytes are valid data"
        )));
    }
    let (pieces, problem) = fs.chain(&cx, first, stream[1] & 2 != 0, len).await?;
    if let Some(d) = problem {
        cx.diag(d);
    }
    let pieces = coalesce(pieces, len);
    cx.emit(fragments_node("Clusters", pieces.clone()));
    let content = assemble(&cx, set.span, "exfat-chain", pieces)?;
    cx.emit(content_node(&fs.input, content));
    Ok(())
}
