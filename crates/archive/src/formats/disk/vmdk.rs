//! VMware virtual disks: hosted sparse extents (`KDMV`: monolithicSparse,
//! twoGbMaxExtentSparse extents, streamOptimized) and text descriptor files.
//!
//! A sparse extent maps grains through a grain directory and grain tables
//! (with a redundant copy of both in hosted sparse extents). Stream-optimized
//! extents compress every grain behind a grain marker and, as VMware writes
//! them, keep the tables at the end behind GT and GD markers, with a footer
//! (a copy of the header that knows where the directory is) and an
//! end-of-stream marker. The virtual disk is assembled from the mapping on
//! expansion; the embedded descriptor is shown line by line.

use std::sync::Arc;

use crate::bytes::{align_up, to_u64, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::disk::qcow::{Regions, decoded_leaf};
use crate::formats::disk::{PieceList, size};
use crate::formats::util::val::{enumv, uint};
use crate::formats::{Codec, Format, Input, Probe, dissect_or_data};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const SECTOR: u64 = 512;
const GD_AT_END: u64 = u64::MAX;
/// Largest descriptor shown.
const MAX_DESCRIPTOR: u64 = 1 << 20;
const COMPRESSED: u32 = 0x1_0000;
const MARKERS: u32 = 0x2_0000;
/// Markers listed at most (a stream holds one per grain).
const MAX_MARKERS: u64 = 1 << 24;

pub static FORMAT: Format = Format {
    name: "vmdk",
    title: "VMware sparse virtual disk (VMDK)",
    extensions: &["vmdk"],
    mime: "application/x-vmdk",
    probe: Probe::Magic(&[(0, b"KDMV")]),
    dissect: crate::expander!(dissect: Input),
};

pub static DESCRIPTOR: Format = Format {
    name: "vmdk-descriptor",
    title: "VMware virtual disk descriptor",
    extensions: &["vmdk"],
    mime: "text/x-vmdk-descriptor",
    probe: Probe::Magic(&[(0, b"# Disk DescriptorFile")]),
    dissect: crate::expander!(descriptor_file: Input),
};

const FLAGS: FlagTable = &[
    flag(1, "VALID_NEWLINE_TEST"),
    flag(2, "REDUNDANT_GRAIN_TABLE"),
    flag(4, "ZEROED_GRAIN_GTE"),
    flag(0x1_0000, "COMPRESSED_GRAINS"),
    flag(0x2_0000, "MARKERS"),
];

const COMPRESSION: EnumTable = &[(0, "none"), (1, "deflate")];
const MARKER_TYPES: EnumTable = &[
    (0, "end of stream"),
    (1, "grain table"),
    (2, "grain directory"),
    (3, "footer"),
];

record! {
    /// `SparseExtentHeader`.
    pub struct Header {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        flags: u32 "Flags" .hex() .flags(FLAGS),
        capacity: u64 "Capacity (sectors)" .with(|&v, n| n.summary(size(v.saturating_mul(SECTOR)))),
        grain_size: u64 "Grain size (sectors)" .with(|&v, n| n.summary(size(v.saturating_mul(SECTOR)))),
        descriptor_offset: u64 "Descriptor offset (sectors)",
        descriptor_size: u64 "Descriptor size (sectors)",
        gtes_per_gt: u32 "Entries per grain table",
        rgd_offset: u64 "Redundant grain directory (sector)" .with(sector_or_none),
        gd_offset: u64 "Grain directory (sector)" .with(|&v, n| if v == GD_AT_END { n.summary("at the end (GD_AT_END): see the footer") } else { sector_or_none(&v, n) }),
        overhead: u64 "Overhead (sectors)" .with(|&v, n| n.summary(format!("metadata before the first grain: {}", size(v.saturating_mul(SECTOR))))),
        unclean: u8 "Unclean shutdown",
        newline: u8 "Newline test: single end-of-line" .hex(),
        non_newline: u8 "Newline test: non end-of-line" .hex(),
        crlf1: u8 "Newline test: CR" .hex(),
        crlf2: u8 "Newline test: LF" .hex(),
        compression: u16 "Compression" .enumeration(COMPRESSION),
        _padding: bytes[433] "Padding",
    }
}

fn sector_or_none(v: &u64, n: Node) -> Node {
    if *v == 0 {
        n.summary("none")
    } else {
        n.summary(format!("at {:#x}", v.saturating_mul(SECTOR)))
    }
}

struct Sparse {
    input: Input,
    gd: Span,
    rgd: Option<Span>,
    gtes: u64,
    grain: u64,
    capacity: u64,
    compressed: bool,
    markers: bool,
    /// Header (and footer, for streams), descriptor area.
    header: Span,
    footer: Option<Span>,
    descriptor: Span,
    overhead: u64,
}

impl Sparse {
    fn gt_len(&self) -> u64 {
        self.gtes.saturating_mul(4)
    }

    fn gt_covers(&self) -> u64 {
        self.gtes.saturating_mul(self.grain)
    }

    fn gt(&self, sector: u64) -> Span {
        self.input
            .span
            .sub(sector.saturating_mul(SECTOR), self.gt_len())
    }

    /// A compressed grain: marker header and deflated data.
    async fn compressed_grain(&self, cx: &Cx, sector: u64) -> Result<(Span, Span)> {
        let at = sector.saturating_mul(SECTOR);
        let head = cx.read(self.input.span.sub(at, 12)).await?;
        let len = u64::from(u32_le(&head, 8).unwrap_or(0));
        Ok((
            self.input.span.sub(at, 12),
            self.input.span.sub(at.saturating_add(12), len),
        ))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, SECTOR);
    let mut h = parse(&cx, span, LE, &(), Header::layout).await?;
    cx.emit(newline_check(Header::node("Header", span, LE), &h));
    let mut footer = None;
    if h.gd_offset == GD_AT_END {
        // Stream-optimized: the header that knows where the grain directory
        // is is the footer, behind a footer marker before the end-of-stream
        // marker at the end of the file.
        let at = file.len.saturating_sub(2 * SECTOR);
        let fspan = file.sub(at, SECTOR);
        let f = parse(&cx, fspan, LE, &(), Header::layout).await?;
        if f.magic != "KDMV" || f.gd_offset == GD_AT_END {
            return Err(Diagnostic::malformed(
                "stream-optimized extent without a footer (incomplete stream?)",
            )
            .at(fspan));
        }
        footer = Some(fspan);
        h = f;
    }
    let descriptor = file.sub(
        h.descriptor_offset.saturating_mul(SECTOR),
        h.descriptor_size.saturating_mul(SECTOR).min(MAX_DESCRIPTOR),
    );
    let text = crate::text::until_nul(&cx.read_avail(descriptor).await?);
    let create_type = descriptor_value(&text, "createType").unwrap_or_default();
    let grain = h.grain_size.saturating_mul(SECTOR);
    let compressed = h.compression == 1 || h.flags & COMPRESSED != 0;
    let markers = h.flags & MARKERS != 0;
    cx.annotate(format!(
        "VMDK {}sparse extent{}, version {}, {} virtual, {} grains{}",
        if markers && compressed {
            "stream-optimized "
        } else {
            ""
        },
        if create_type.is_empty() {
            String::new()
        } else {
            format!(" ({create_type})")
        },
        h.version,
        size(h.capacity.saturating_mul(SECTOR)),
        size(grain),
        if compressed {
            ", deflate-compressed"
        } else {
            ""
        },
    ));
    if !descriptor.is_empty() {
        let used = to_u64(text.len());
        if used > 0 {
            cx.emit(
                Node::new("Descriptor")
                    .span(descriptor.sub(0, used))
                    .summary(format!(
                        "{create_type}, {}",
                        crate::formats::util::fmt::count(
                            to_u64(extent_lines(&text)),
                            "extent",
                            "extents"
                        )
                    ))
                    .lazy(descriptor_lines, (descriptor, used)),
            );
        }
        if used < descriptor.len {
            cx.emit(
                Node::new("Descriptor padding")
                    .span(descriptor.tail(used))
                    .summary(format!(
                        "{} of descriptor space unused",
                        size(descriptor.len.saturating_sub(used))
                    )),
            );
        }
    }
    let gtes = u64::from(h.gtes_per_gt);
    if !grain.is_power_of_two() || grain < SECTOR || gtes == 0 || gtes > 1 << 16 {
        return Err(Diagnostic::malformed("implausible grain or grain table size").at(span));
    }
    let per_table = gtes.saturating_mul(grain);
    let tables = h.capacity.saturating_mul(SECTOR).div_ceil(per_table);
    let gd = file.sub_exact(h.gd_offset.saturating_mul(SECTOR), tables.saturating_mul(4))?;
    let rgd = (h.rgd_offset != 0 && h.flags & 2 != 0)
        .then(|| file.sub(h.rgd_offset.saturating_mul(SECTOR), gd.len));
    let sparse = Arc::new(Sparse {
        input,
        gd,
        rgd,
        gtes,
        grain,
        capacity: h.capacity.saturating_mul(SECTOR),
        compressed,
        markers,
        header: span,
        footer,
        descriptor,
        overhead: h.overhead.saturating_mul(SECTOR),
    });
    if let Some(rgd) = rgd {
        cx.emit(
            Node::new("Redundant grain directory")
                .span(rgd)
                .summary(crate::formats::util::fmt::count(
                    tables,
                    "grain table",
                    "grain tables",
                ))
                .lazy(grain_directory, (sparse.clone(), true)),
        );
    }
    cx.emit(
        Node::new("Grain directory")
            .span(gd)
            .summary(format!(
                "{} of {gtes} entries, each covering {}",
                crate::formats::util::fmt::count(tables, "grain table", "grain tables"),
                size(per_table)
            ))
            .lazy(grain_directory, (sparse.clone(), false)),
    );
    if sparse.markers && sparse.compressed {
        cx.emit(
            Node::new("Stream")
                .span(file.tail(sparse.overhead))
                .summary("grain and metadata markers after the overhead")
                .lazy(stream, sparse.clone()),
        );
    }
    cx.emit(
        Node::new("Extent layout")
            .span(file)
            .summary("what each part of the file holds")
            .lazy(layout, sparse.clone()),
    );
    cx.emit(
        Node::new("Virtual disk")
            .summary(size(sparse.capacity))
            .lazy(virtual_disk, sparse),
    );
    Ok(())
}

/// Text-mode transfers corrupt the newline test bytes.
fn newline_check(node: Node, h: &Header) -> Node {
    if h.flags & 1 != 0
        && (h.newline, h.non_newline, h.crlf1, h.crlf2) != (b'\n', b' ', b'\r', b'\n')
    {
        node.diag(Diagnostic::warning(
            "newline test bytes changed: the file went through a text-mode transfer",
        ))
    } else {
        node
    }
}

async fn grain_directory(cx: Cx, (s, redundant): (Arc<Sparse>, bool)) -> Result<()> {
    let gd = if redundant {
        s.rgd.unwrap_or(s.gd)
    } else {
        s.gd
    };
    let data = cx.read_avail(gd).await?;
    let primary = if redundant {
        cx.read_avail(s.gd).await?
    } else {
        Vec::new()
    };
    let covers = s.gt_covers();
    let mut i = 0usize;
    let entries = data.len() / 4;
    while i < entries {
        let sector = u64::from(u32_le(&data, i.saturating_mul(4)).unwrap_or(0));
        let guest = to_u64(i).saturating_mul(covers);
        if sector == 0 {
            let start = i;
            while i < entries && u32_le(&data, i.saturating_mul(4)) == Some(0) {
                i = i.saturating_add(1);
                if i.is_multiple_of(4096) {
                    cx.checkpoint().await;
                }
            }
            cx.push(
                Node::new(range_name("GD", start, i))
                    .span(gd.sub(
                        to_u64(start).saturating_mul(4),
                        to_u64(i.saturating_sub(start)).saturating_mul(4),
                    ))
                    .value(enumv(0u32, 32, &[(0, "no grain table")]))
                    .summary(format!(
                        "guest {guest:#x}–{:#x}: unallocated",
                        to_u64(i).saturating_mul(covers).saturating_sub(1)
                    )),
            )
            .await;
            continue;
        }
        let gt = s.gt(sector);
        let mut node = Node::new(format!("GD[{i}]"))
            .span(gd.sub(to_u64(i).saturating_mul(4), 4))
            .value(uint(sector, 32))
            .summary(format!(
                "guest {guest:#x}–{:#x}: grain table at {:#x}",
                guest.saturating_add(covers).saturating_sub(1),
                sector.saturating_mul(SECTOR)
            ))
            .target(gt)
            .lazy(grain_table, (s.clone(), gt, guest));
        if redundant {
            let p = u64::from(u32_le(&primary, i.saturating_mul(4)).unwrap_or(0));
            if p != 0 {
                let a = cx.read_avail(gt).await?;
                let b = cx.read_avail(s.gt(p)).await?;
                if a != b {
                    node = node.diag(Diagnostic::warning("differs from the primary grain table"));
                }
            }
        }
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

fn range_name(prefix: &str, start: usize, end: usize) -> String {
    if start.saturating_add(1) >= end {
        format!("{prefix}[{start}]")
    } else {
        format!("{prefix}[{start}–{}]", end.saturating_sub(1))
    }
}

async fn grain_table(cx: Cx, (s, gt, guest_base): (Arc<Sparse>, Span, u64)) -> Result<()> {
    let data = cx.read_avail(gt).await?;
    if to_u64(data.len()) < gt.len {
        cx.diag(Diagnostic::truncated(gt, to_u64(data.len())));
    }
    let entries = data.len() / 4;
    let mut i = 0usize;
    while i < entries {
        let sector = u64::from(u32_le(&data, i.saturating_mul(4)).unwrap_or(0));
        let guest = guest_base.saturating_add(to_u64(i).saturating_mul(s.grain));
        if sector <= 1 {
            let start = i;
            while i < entries && u32_le(&data, i.saturating_mul(4)).map(u64::from) == Some(sector) {
                i = i.saturating_add(1);
                if i.is_multiple_of(4096) {
                    cx.checkpoint().await;
                }
            }
            let what = if sector == 0 { "unallocated" } else { "zeroed" };
            cx.push(
                Node::new(range_name("GT", start, i))
                    .span(gt.sub(
                        to_u64(start).saturating_mul(4),
                        to_u64(i.saturating_sub(start)).saturating_mul(4),
                    ))
                    .value(enumv(sector, 32, &[(0, "unallocated"), (1, "zeroed")]))
                    .summary(format!(
                        "guest {guest:#x}–{:#x}: {what}",
                        guest_base
                            .saturating_add(to_u64(i).saturating_mul(s.grain))
                            .saturating_sub(1)
                    )),
            )
            .await;
            continue;
        }
        let span = gt.sub(to_u64(i).saturating_mul(4), 4);
        let at = sector.saturating_mul(SECTOR);
        let mut node = Node::new(format!("GT[{i}]"))
            .span(span)
            .value(uint(sector, 32));
        if s.compressed {
            let (marker, data) = s.compressed_grain(&cx, sector).await?;
            node = node
                .summary(format!(
                    "guest {guest:#x}: compressed grain at {at:#x}, {} bytes",
                    data.len
                ))
                .target(s.input.span.sub(
                    marker.offset.saturating_sub(s.input.span.offset),
                    12u64.saturating_add(data.len),
                ))
                .lazy(grain_node, (s.clone(), sector));
        } else {
            node = node
                .summary(format!("guest {guest:#x}: grain at {at:#x}"))
                .target(s.input.span.sub(at, s.grain));
        }
        cx.push(node).await;
        i = i.saturating_add(1);
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
    }
    Ok(())
}

/// A compressed grain: its marker fields and the inflated data.
async fn grain_node(cx: Cx, (s, sector): (Arc<Sparse>, u64)) -> Result<()> {
    let (marker, data) = s.compressed_grain(&cx, sector).await?;
    let block = cx.block(marker).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u64("Marker: LBA")
        .with(|&v, n| n.summary(format!("guest {:#x}", v.saturating_mul(SECTOR))))
        .emit()?;
    f.u32("Marker: compressed size").emit()?;
    cx.emit(
        Node::new("Compressed grain")
            .span(data)
            .summary(format!("{} bytes", data.len))
            .lazy(decoded_leaf, (data, Codec::Zlib, s.grain)),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Stream markers

/// One marker in a stream: grain (LBA, size) or metadata (sectors, type).
#[derive(Clone, Copy)]
enum Marker {
    Grain { lba: u64, size: u64 },
    Meta { sectors: u64, kind: u32 },
}

async fn read_marker(cx: &Cx, span: Span) -> Result<Marker> {
    let head = cx.read(span.sub(0, 16)).await?;
    let value = u64_le(&head, 0).unwrap_or(0);
    let size = u32_le(&head, 8).unwrap_or(0);
    Ok(if size != 0 {
        Marker::Grain {
            lba: value,
            size: size.into(),
        }
    } else {
        Marker::Meta {
            sectors: value,
            kind: u32_le(&head, 12).unwrap_or(0),
        }
    })
}

impl Marker {
    /// Bytes from the marker to the next one.
    fn len(&self) -> u64 {
        match self {
            Marker::Grain { size, .. } => align_up(12u64.saturating_add(*size), SECTOR),
            Marker::Meta { sectors, .. } => sectors.saturating_add(1).saturating_mul(SECTOR),
        }
    }
}

async fn stream(cx: Cx, s: Arc<Sparse>) -> Result<()> {
    let file = s.input.span;
    let (mut pos, mut count) = cx.resume::<(u64, u64)>().unwrap_or((s.overhead, 0));
    while pos < file.len && count < MAX_MARKERS {
        let at = (pos, count);
        cx.mark(move || at);
        cx.progress_in(file, pos);
        let marker = read_marker(&cx, file.sub(pos, 16)).await?;
        let len = marker.len().min(file.len.saturating_sub(pos));
        let span = file.sub(pos, len);
        let node = match marker {
            Marker::Grain { lba, size: n } => Node::new("Grain marker")
                .span(span)
                .summary(format!(
                    "guest {:#x}, {n} compressed bytes",
                    lba.saturating_mul(SECTOR)
                ))
                .lazy(grain_node, (s.clone(), pos / SECTOR)),
            Marker::Meta { sectors, kind } => {
                let name = lookup(MARKER_TYPES, kind.into()).unwrap_or("unknown");
                Node::new(format!("Marker: {name}"))
                    .span(span)
                    .summary(if sectors == 0 {
                        name.to_owned()
                    } else {
                        format!("{name}, {}", size(sectors.saturating_mul(SECTOR)))
                    })
                    .lazy(meta_marker, (s.clone(), span, kind))
            }
        };
        cx.push(node).await;
        count = count.saturating_add(1);
        if matches!(marker, Marker::Meta { kind: 0, .. }) {
            if pos.saturating_add(SECTOR) < file.len {
                let rest = file.tail(pos.saturating_add(SECTOR));
                cx.push(
                    Node::new("After the end of stream")
                        .span(rest)
                        .summary(size(rest.len)),
                )
                .await;
            }
            break;
        }
        pos = pos.saturating_add(len.max(SECTOR));
    }
    Ok(())
}

async fn meta_marker(cx: Cx, (s, span, kind): (Arc<Sparse>, Span, u32)) -> Result<()> {
    let block = cx.block(span.sub(0, SECTOR)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u64("Sectors").emit()?;
    f.u32("Size").emit()?;
    f.u32("Type").enumeration(MARKER_TYPES).emit()?;
    f.bytes("Padding", 496).emit()?;
    let body = span.tail(SECTOR);
    if body.is_empty() {
        return Ok(());
    }
    match kind {
        1 => cx.emit(
            Node::new("Grain table")
                .span(body)
                .summary(format!("{} entries", body.len / 4))
                .lazy(
                    grain_table,
                    (
                        s.clone(),
                        body.sub(0, s.gt_len()),
                        guest_of_gt(&s, &cx, body).await?,
                    ),
                ),
        ),
        2 => cx.emit(
            Node::new("Grain directory")
                .span(body)
                .lazy(grain_directory, (s.clone(), false)),
        ),
        3 => cx.emit(newline_check(
            Header::node("Footer", body.sub(0, SECTOR), LE),
            &parse(&cx, body.sub(0, SECTOR), LE, &(), Header::layout).await?,
        )),
        _ => cx.emit(Node::new("Data").span(body)),
    }
    Ok(())
}

/// The guest offset a grain table covers, from its slot in the directory.
async fn guest_of_gt(s: &Sparse, cx: &Cx, gt: Span) -> Result<u64> {
    let sector = gt.offset.saturating_sub(s.input.span.offset) / SECTOR;
    let gd = cx.read_avail(s.gd).await?;
    let slot = gd
        .as_chunks::<4>()
        .0
        .iter()
        .position(|e| u64::from(u32::from_le_bytes(*e)) == sector)
        .unwrap_or(0);
    Ok(to_u64(slot).saturating_mul(s.gt_covers()))
}

// ---------------------------------------------------------------------------
// Layout

async fn layout(cx: Cx, s: Arc<Sparse>) -> Result<()> {
    let file = s.input.span;
    let mut r = Regions::default();
    r.span(file, s.header, "Header");
    r.span(file, s.descriptor, "Descriptor");
    if let Some(rgd) = s.rgd {
        r.span(file, sectors(rgd), "Redundant grain directory");
        tables(&cx, &s, rgd, "Redundant grain table", &mut r).await?;
    }
    r.span(file, sectors(s.gd), "Grain directory");
    tables(&cx, &s, s.gd, "Grain table", &mut r).await?;
    if let Some(footer) = s.footer {
        r.span(
            file,
            file.sub(
                footer
                    .offset
                    .saturating_sub(file.offset)
                    .saturating_sub(SECTOR),
                SECTOR,
            ),
            "Footer marker",
        );
        r.span(file, footer, "Footer");
        r.add(
            footer.end().saturating_sub(file.offset),
            SECTOR,
            "End-of-stream marker",
            None,
        );
    }
    r.emit(&cx, file, "not referenced by the grain tables")
        .await;
    Ok(())
}

/// A table rounded up to whole sectors (the rest of its last sector is
/// padding that belongs to it).
fn sectors(span: Span) -> Span {
    Span::new(span.source, span.offset, span.len.next_multiple_of(SECTOR))
}

/// Adds the grain tables of a directory and the grains they map.
async fn tables(cx: &Cx, s: &Sparse, gd: Span, role: &'static str, r: &mut Regions) -> Result<()> {
    let file = s.input.span;
    let dir = cx.read_avail(gd).await?;
    for (i, e) in dir.as_chunks::<4>().0.iter().enumerate() {
        cx.checkpoint().await;
        let sector = u64::from(u32::from_le_bytes(*e));
        if sector == 0 {
            continue;
        }
        let gt = s.gt(sector);
        r.span(file, gt, role);
        if s.footer.is_some() && role == "Grain table" {
            // The GT marker in front of it.
            r.add(
                sector.saturating_sub(1).saturating_mul(SECTOR),
                SECTOR,
                "Grain table marker",
                None,
            );
        }
        let data = cx.read_avail(gt).await?;
        for (j, g) in data.as_chunks::<4>().0.iter().enumerate() {
            if j.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            let at = u64::from(u32::from_le_bytes(*g));
            if at <= 1 {
                continue;
            }
            let guest = to_u64(i)
                .saturating_mul(s.gt_covers())
                .saturating_add(to_u64(j).saturating_mul(s.grain));
            if s.compressed {
                let (marker, data) = s.compressed_grain(cx, at).await?;
                r.add(
                    marker.offset.saturating_sub(file.offset),
                    12u64.saturating_add(data.len).next_multiple_of(SECTOR),
                    "Compressed grain",
                    None,
                );
            } else {
                r.add(at.saturating_mul(SECTOR), s.grain, "Grain", Some(guest));
            }
        }
    }
    if s.footer.is_some() && role == "Grain table" {
        let gd_sector = gd.offset.saturating_sub(file.offset) / SECTOR;
        r.add(
            gd_sector.saturating_sub(1).saturating_mul(SECTOR),
            SECTOR,
            "Grain directory marker",
            None,
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Virtual disk

async fn virtual_disk(cx: Cx, s: Arc<Sparse>) -> Result<()> {
    let file = s.input.span;
    let directory = cx.read(s.gd).await?;
    let mut list = PieceList::new(s.gd);
    'outer: for (i, gde) in directory.as_chunks::<4>().0.iter().enumerate() {
        let table_sector = u64::from(u32::from_le_bytes(*gde));
        let covered = s.gt_covers();
        cx.progress(list.len(), s.capacity);
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        if table_sector == 0 {
            let want = covered.min(s.capacity.saturating_sub(list.len()));
            if let Err(e) = list.hole(&cx, want) {
                cx.diag(e);
                break;
            }
            continue;
        }
        let table = cx.read(s.gt(table_sector)).await?;
        for (j, gte) in table.as_chunks::<4>().0.iter().enumerate() {
            let want = s.grain.min(s.capacity.saturating_sub(list.len()));
            if want == 0 {
                break 'outer;
            }
            if j.is_multiple_of(4096) {
                cx.checkpoint().await;
            }
            let sector = u64::from(u32::from_le_bytes(*gte));
            let step = match sector {
                0 | 1 => list.hole(&cx, want),
                _ if s.compressed => {
                    // Grain marker: LBA (8), compressed size (4), zlib data.
                    let (_, data) = s.compressed_grain(&cx, sector).await?;
                    match crate::codec::inflate_span(&cx, data, true, Some(s.grain)).await {
                        Ok(d) => {
                            list.data(d.span.sub(0, want));
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
                _ => {
                    list.data(file.sub(sector.saturating_mul(SECTOR), want));
                    Ok(())
                }
            };
            if let Err(e) = step {
                cx.diag(e);
                break 'outer;
            }
        }
    }
    let span = list.finish(&cx, "vmdk-grains").await?;
    dissect_or_data(cx, s.input.nested(span)).await
}

// ---------------------------------------------------------------------------
// Descriptors

/// `key="value"` from a descriptor.
fn descriptor_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"').to_owned())
    })
}

/// Extent lines: `RW 4192256 SPARSE "disk-s001.vmdk"`.
fn extent_lines(text: &str) -> usize {
    text.lines()
        .filter(|l| {
            let w = l.split_whitespace().next().unwrap_or("");
            matches!(w, "RW" | "RDONLY" | "NOACCESS")
        })
        .count()
}

const DESCRIPTOR_KEYS: &[(&str, &str)] = &[
    ("version", "Descriptor format version"),
    ("CID", "Content id: changes whenever the disk is written"),
    ("parentCID", "Content id of the parent (ffffffff: none)"),
    ("createType", "Disk type"),
    ("parentFileNameHint", "Parent disk (differencing link)"),
    ("encoding", "Character encoding of the descriptor"),
    ("ddb.adapterType", "Virtual controller"),
    ("ddb.virtualHWVersion", "Virtual hardware version"),
    ("ddb.geometry.cylinders", "BIOS geometry: cylinders"),
    ("ddb.geometry.heads", "BIOS geometry: heads"),
    ("ddb.geometry.sectors", "BIOS geometry: sectors per track"),
    ("ddb.toolsVersion", "VMware Tools version"),
    ("ddb.uuid.image", "Disk UUID"),
    ("ddb.longContentID", "Long content id"),
];

/// Lists a descriptor's lines: comments, extents and `key = value` settings.
async fn descriptor_lines(cx: Cx, (span, len): (Span, u64)) -> Result<()> {
    let data = cx.read_avail(span.sub(0, len)).await?;
    let mut at = 0u64;
    for line in data.split(|&b| b == b'\n') {
        let line_len = to_u64(line.len());
        // The line with its terminator.
        let line_span = span.sub(at, line_len.saturating_add(1).min(len.saturating_sub(at)));
        at = at.saturating_add(line_len).saturating_add(1);
        let text = String::from_utf8_lossy(line).trim().to_owned();
        if text.is_empty() {
            cx.checkpoint().await;
            continue;
        }
        let node = if let Some(comment) = text.strip_prefix('#') {
            Node::new("Comment").value(Value::Text(comment.trim().to_owned()))
        } else if let Some((key, value)) = text.split_once('=') {
            let key = key.trim().to_owned();
            let mut node = Node::new(key.clone())
                .value(Value::Text(value.trim().trim_matches('"').to_owned()));
            if let Some((_, d)) = DESCRIPTOR_KEYS.iter().find(|(k, _)| *k == key) {
                node = node.desc(*d);
            }
            node
        } else {
            let mut words = text.split_whitespace();
            let access = words.next().unwrap_or("");
            let sectors: u64 = words.next().and_then(|w| w.parse().ok()).unwrap_or(0);
            let kind = words.next().unwrap_or("");
            let rest: Vec<&str> = words.collect();
            Node::new("Extent")
                .value(Value::Text(text.clone()))
                .summary(format!(
                    "{access} {kind}, {} in {}",
                    size(sectors.saturating_mul(SECTOR)),
                    rest.join(" ")
                ))
                .desc("Access, size in sectors, type (SPARSE, FLAT, ZERO, VMFS, ...), file name and, for flat extents, the offset in sectors")
        };
        cx.push(node.span(line_span)).await;
    }
    Ok(())
}

async fn descriptor_file(cx: Cx, input: Input) -> Result<()> {
    let span = input.span.sub(0, MAX_DESCRIPTOR);
    let raw = cx.read_avail(span).await?;
    let text = crate::text::until_nul(&raw);
    let kind = descriptor_value(&text, "createType").unwrap_or_else(|| "unknown".to_owned());
    let used = to_u64(text.len());
    cx.annotate(format!(
        "VMDK descriptor ({kind}), {}",
        crate::formats::util::fmt::count(to_u64(extent_lines(&text)), "extent", "extents")
    ));
    if used < input.span.len {
        cx.emit(
            Node::new("Padding")
                .span(input.span.tail(used))
                .summary(size(input.span.len.saturating_sub(used))),
        );
    }
    descriptor_lines(cx, (span, used)).await
}
