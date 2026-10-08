//! VMware virtual disks: hosted sparse extents (`KDMV`, including
//! stream-optimized ones) and text descriptor files.
//!
//! A sparse extent maps grains through a grain directory and grain tables;
//! the virtual disk is assembled from that mapping on expansion (compressed
//! grains are inflated). Its embedded descriptor is shown as text.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{PieceList, size};
use crate::formats::{Format, Input, Probe, dissect_or_data};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const SECTOR: u64 = 512;
const GD_AT_END: u64 = u64::MAX;
/// Largest descriptor shown.
const MAX_DESCRIPTOR: u64 = 1 << 20;

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
        rgd_offset: u64 "Redundant grain directory (sectors)",
        gd_offset: u64 "Grain directory (sectors)" .hex(),
        overhead: u64 "Overhead (sectors)",
        unclean: u8 "Unclean shutdown",
        newline: u8 "Newline test: single end-of-line" .hex(),
        non_newline: u8 "Newline test: non end-of-line" .hex(),
        crlf1: u8 "Newline test: CR" .hex(),
        crlf2: u8 "Newline test: LF" .hex(),
        compression: u16 "Compression" .enumeration(COMPRESSION),
    }
}

struct Sparse {
    input: Input,
    gd: Span,
    gtes: u64,
    grain: u64,
    capacity: u64,
    compressed: bool,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, Header::SIZE);
    let mut h = parse(&cx, span, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", file.sub(0, SECTOR), LE));
    if h.gd_offset == GD_AT_END {
        // Stream-optimized: the real header is the footer, 1 KiB from the end.
        let footer = file.sub(file.len.saturating_sub(2 * SECTOR), Header::SIZE);
        let f = parse(&cx, footer, LE, &(), Header::layout).await?;
        cx.emit(Header::node(
            "Footer",
            file.sub(footer.offset.saturating_sub(file.offset), SECTOR),
            LE,
        ));
        h = f;
    }
    let descriptor = file.sub(
        h.descriptor_offset.saturating_mul(SECTOR),
        h.descriptor_size.saturating_mul(SECTOR).min(MAX_DESCRIPTOR),
    );
    let text = crate::text::until_nul(&cx.read_avail(descriptor).await?);
    let create_type = descriptor_value(&text, "createType").unwrap_or_default();
    cx.annotate(format!(
        "VMDK sparse extent{}, {} virtual, {} grains",
        if create_type.is_empty() {
            String::new()
        } else {
            format!(" ({create_type})")
        },
        size(h.capacity.saturating_mul(SECTOR)),
        size(h.grain_size.saturating_mul(SECTOR))
    ));
    if !descriptor.is_empty() {
        cx.emit(
            Node::new("Descriptor")
                .span(descriptor.sub(0, to_u64(text.len())))
                .value(Value::Text(text.clone()))
                .lazy(descriptor_lines, (descriptor, to_u64(text.len()))),
        );
    }
    let grain = h.grain_size.saturating_mul(SECTOR);
    let gtes = u64::from(h.gtes_per_gt);
    if !grain.is_power_of_two() || grain < SECTOR || gtes == 0 || gtes > 1 << 16 {
        return Err(Diagnostic::malformed("implausible grain or grain table size").at(span));
    }
    let per_table = gtes.saturating_mul(grain);
    let tables = h.capacity.saturating_mul(SECTOR).div_ceil(per_table);
    let gd = file.sub_exact(h.gd_offset.saturating_mul(SECTOR), tables.saturating_mul(4))?;
    cx.emit(
        Node::new("Grain directory")
            .span(gd)
            .summary(format!("{tables} grain tables")),
    );
    if h.rgd_offset != 0 {
        cx.emit(
            Node::new("Redundant grain directory")
                .span(file.sub(h.rgd_offset.saturating_mul(SECTOR), gd.len)),
        );
    }
    let sparse = Arc::new(Sparse {
        input,
        gd,
        gtes,
        grain,
        capacity: h.capacity.saturating_mul(SECTOR),
        compressed: h.compression == 1 || h.flags & 0x1_0000 != 0,
    });
    cx.emit(
        Node::new("Virtual disk")
            .summary(size(sparse.capacity))
            .lazy(virtual_disk, sparse),
    );
    Ok(())
}

async fn virtual_disk(cx: Cx, s: Arc<Sparse>) -> Result<()> {
    let file = s.input.span;
    let directory = cx.read(s.gd).await?;
    let mut list = PieceList::new(s.gd);
    'outer: for (i, gde) in directory.as_chunks::<4>().0.iter().enumerate() {
        let table_sector = u64::from(u32::from_le_bytes(*gde));
        let covered = s.gtes.saturating_mul(s.grain);
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
        let table = cx
            .read(file.sub(
                table_sector.saturating_mul(SECTOR),
                s.gtes.saturating_mul(4),
            ))
            .await?;
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
                    let at = sector.saturating_mul(SECTOR);
                    let head = cx.read(file.sub(at, 12)).await?;
                    let len = u64::from(u32_le(&head, 8).unwrap_or(0));
                    match crate::codec::inflate_span(
                        &cx,
                        file.sub(at.saturating_add(12), len),
                        true,
                        Some(s.grain),
                    )
                    .await
                    {
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

/// `key="value"` from a descriptor.
fn descriptor_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"').to_owned())
    })
}

/// Lists a descriptor's lines: extents and `key = value` settings.
async fn descriptor_lines(cx: Cx, (span, len): (Span, u64)) -> Result<()> {
    let data = cx.read_avail(span.sub(0, len)).await?;
    let mut at = 0u64;
    for line in data.split(|&b| b == b'\n') {
        let line_len = to_u64(line.len());
        let line_span = span.sub(at, line_len);
        at = at.saturating_add(line_len).saturating_add(1);
        let text = String::from_utf8_lossy(line).trim().to_owned();
        if text.is_empty() || text.starts_with('#') {
            cx.checkpoint().await;
            continue;
        }
        let node = if let Some((key, value)) = text.split_once('=') {
            Node::new(key.trim().to_owned())
                .value(Value::Text(value.trim().trim_matches('"').to_owned()))
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
        };
        cx.push(node.span(line_span)).await;
    }
    Ok(())
}

async fn descriptor_file(cx: Cx, input: Input) -> Result<()> {
    let span = input.span.sub(0, MAX_DESCRIPTOR);
    let text = crate::text::until_nul(&cx.read_avail(span).await?);
    let kind = descriptor_value(&text, "createType").unwrap_or_else(|| "unknown".to_owned());
    cx.annotate(format!("VMDK descriptor ({kind})"));
    descriptor_lines(cx, (span, to_u64(text.len()))).await
}
