//! Microsoft Virtual Hard Disk (VHD, "conectix").
//!
//! A 512-byte footer at the end describes the disk. Fixed disks are the raw
//! disk followed by the footer; dynamic and differencing disks have a copy
//! of the footer at the start, a dynamic header (`cxsparse`) and a block
//! allocation table (BAT). The virtual disk is presented as an embedded
//! input (assembled from allocated blocks and zero holes for dynamic disks).

use std::sync::Arc;

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{PieceList, size, uuid_value};
use crate::formats::{Format, Head, Input, Probe, dissect_or_data, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const BE: Endian = Endian::Big;
const COOKIE: &[u8] = b"conectix";
const SECTOR: u64 = 512;
/// Seconds between 1970-01-01 and 2000-01-01 (the VHD epoch).
const EPOCH_2000: i64 = 946_684_800;

pub static FORMAT: Format = Format {
    name: "vhd",
    title: "Microsoft Virtual Hard Disk",
    extensions: &["vhd"],
    mime: "application/x-vhd",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let tail = h.tail;
    let at = |back: usize| {
        tail.len()
            .checked_sub(back)
            .and_then(|i| tail.get(i..))
            .is_some_and(|t| t.starts_with(COOKIE))
    };
    h.starts_with(COOKIE) || at(512) || at(511)
}

const DISK_TYPES: EnumTable = &[
    (0, "none"),
    (2, "fixed"),
    (3, "dynamic"),
    (4, "differencing"),
];

const FEATURES: FlagTable = &[flag(1, "TEMPORARY"), flag(2, "RESERVED")];

fn vhd_time(v: &u32, n: Node) -> Node {
    n.value(Value::Timestamp {
        unix_seconds: i64::from(*v).saturating_add(EPOCH_2000),
    })
}

record! {
    /// The hard disk footer.
    pub struct Footer {
        cookie: ascii[8] "Cookie",
        features: u32 "Features" .hex() .flags(FEATURES),
        version: u32 "File format version" .hex(),
        data_offset: u64 "Data offset (dynamic header)" .hex(),
        timestamp: u32 "Created" .with(vhd_time),
        creator_app: ascii[4] "Creator application",
        creator_version: u32 "Creator version" .hex(),
        creator_os: ascii[4] "Creator host OS",
        original_size: u64 "Original size" .with(|&v, n| n.summary(size(v))),
        current_size: u64 "Current size" .with(|&v, n| n.summary(size(v))),
        cylinders: u16 "Cylinders",
        heads: u8 "Heads",
        sectors: u8 "Sectors per track",
        disk_type: u32 "Disk type" .enumeration(DISK_TYPES),
        checksum: u32 "Checksum" .hex(),
        unique_id: bytes[16] "Unique id" .with(uuid_value),
        saved_state: u8 "Saved state",
    }
}

record! {
    /// The dynamic disk header.
    pub struct DynamicHeader {
        cookie: ascii[8] "Cookie",
        data_offset: u64 "Data offset (unused)" .hex(),
        table_offset: u64 "BAT offset" .hex(),
        version: u32 "Header version" .hex(),
        max_entries: u32 "BAT entries",
        block_size: u32 "Block size" .with(|&v, n| n.summary(size(v.into()))),
        checksum: u32 "Checksum" .hex(),
        parent_id: bytes[16] "Parent unique id" .with(uuid_value),
        parent_time: u32 "Parent modified" .with(vhd_time),
        _reserved: u32 "Reserved",
        parent_name: utf16[256] "Parent name",
    }
}

/// One's complement of the byte sum, skipping the checksum field.
fn checksum(data: &[u8], field: usize) -> u32 {
    let sum = data
        .iter()
        .enumerate()
        .filter(|(i, _)| !(field..field.saturating_add(4)).contains(i))
        .fold(0u32, |s, (_, &b)| s.wrapping_add(b.into()));
    !sum
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // The footer is the last 512 bytes (511 in some old images).
    let tail = cx
        .read_avail(file.tail(file.len.saturating_sub(SECTOR)))
        .await?;
    let footer_at = if tail.starts_with(COOKIE) {
        Some(file.len.saturating_sub(SECTOR))
    } else if tail.get(1..).is_some_and(|t| t.starts_with(COOKIE)) {
        Some(file.len.saturating_sub(511))
    } else {
        None
    };
    let primary = footer_at.unwrap_or(0);
    let footer_span = file.sub(primary, SECTOR);
    let footer = parse(&cx, footer_span, BE, &(), Footer::layout).await?;
    let raw = cx.read_avail(footer_span).await?;
    let mut node = Footer::node(
        if footer_at.is_some() {
            "Footer"
        } else {
            "Footer (copy at start)"
        },
        footer_span,
        BE,
    );
    if checksum(&raw, 64) != footer.checksum {
        node = node.diag(Diagnostic::warning("footer checksum mismatch"));
    }
    if footer_at.is_none() {
        node = node.diag(Diagnostic::warning(
            "no footer at the end; using the copy at the start",
        ));
    }
    let kind = crate::value::lookup(DISK_TYPES, footer.disk_type.into()).unwrap_or("unknown");
    cx.annotate(format!(
        "VHD {kind} disk, {} (created by {:?} on {:?})",
        size(footer.current_size),
        footer.creator_app.trim_end(),
        footer.creator_os.trim_end()
    ));

    if footer.disk_type == 2 {
        cx.emit(node);
        let payload = file.sub(0, primary.min(footer.current_size));
        cx.emit(embedded("Virtual disk", input.nested(payload)).summary(size(payload.len)));
        return Ok(());
    }
    if footer_at.is_some() {
        cx.emit(Footer::node("Footer copy", file.sub(0, SECTOR), BE));
    }
    cx.emit(node);
    let header_span = file.sub(footer.data_offset, 1024);
    let header = parse(&cx, header_span, BE, &(), DynamicHeader::layout).await?;
    let raw = cx.read_avail(header_span).await?;
    let mut hnode = DynamicHeader::node("Dynamic header", header_span, BE);
    if header.cookie != "cxsparse" {
        return Err(Diagnostic::malformed("bad dynamic header cookie").at(header_span.sub(0, 8)));
    }
    if checksum(&raw, 36) != header.checksum {
        hnode = hnode.diag(Diagnostic::warning("dynamic header checksum mismatch"));
    }
    cx.emit(hnode);
    let block = u64::from(header.block_size);
    if block < SECTOR || !block.is_power_of_two() {
        return Err(Diagnostic::malformed(format!("block size {block}")).at(header_span));
    }
    let bat = file.sub_exact(
        header.table_offset,
        u64::from(header.max_entries).saturating_mul(4),
    )?;
    let disk = Arc::new(Dynamic {
        input,
        bat,
        block,
        // Each block is preceded by its sector bitmap, padded to a sector.
        bitmap: (block / SECTOR).div_ceil(8).next_multiple_of(SECTOR),
        size: footer.current_size,
    });
    cx.emit(
        Node::new("Block allocation table")
            .span(bat)
            .summary(format!("{} entries of {}", header.max_entries, size(block)))
            .lazy(bat_entries, disk.clone()),
    );
    if footer.disk_type == 4 {
        let parent = header.parent_name.clone();
        cx.emit(
            Node::new("Virtual disk").diag(Diagnostic::unsupported(format!(
                "differencing disk: unallocated blocks come from the parent {parent:?}"
            ))),
        );
    } else {
        cx.emit(
            Node::new("Virtual disk")
                .summary(size(footer.current_size))
                .lazy(virtual_disk, disk),
        );
    }
    Ok(())
}

struct Dynamic {
    input: Input,
    bat: Span,
    block: u64,
    bitmap: u64,
    size: u64,
}

impl Dynamic {
    fn data(&self, entry: u32) -> Span {
        self.input.span.sub(
            u64::from(entry)
                .saturating_mul(SECTOR)
                .saturating_add(self.bitmap),
            self.block,
        )
    }
}

async fn bat_entries(cx: Cx, d: Arc<Dynamic>) -> Result<()> {
    let count = d.bat.len / 4;
    for i in 0..count {
        cx.progress(i, count);
        let raw = cx.read(d.bat.sub(i.saturating_mul(4), 4)).await?;
        let entry = u32_be(&raw, 0).unwrap_or(u32::MAX);
        if entry == u32::MAX {
            continue;
        }
        cx.push(
            Node::new(format!("Block {i}"))
                .span(d.bat.sub(i.saturating_mul(4), 4))
                .summary(format!("sector {entry}"))
                .target(d.data(entry)),
        )
        .await;
    }
    Ok(())
}

async fn virtual_disk(cx: Cx, d: Arc<Dynamic>) -> Result<()> {
    let table = cx.read(d.bat).await?;
    let mut list = PieceList::new(d.bat);
    let mut problem = None;
    for (i, raw) in table.as_chunks::<4>().0.iter().enumerate() {
        if list.len() >= d.size {
            break;
        }
        let want = d.block.min(d.size.saturating_sub(list.len()));
        if i.is_multiple_of(4096) {
            cx.progress(list.len(), d.size);
            cx.checkpoint().await;
        }
        let entry = u32::from_be_bytes(*raw);
        let step = if entry == u32::MAX {
            list.hole(&cx, want)
        } else {
            list.data(d.data(entry).sub(0, want));
            Ok(())
        };
        if let Err(e) = step {
            problem = Some(e);
            break;
        }
    }
    if let Some(e) = problem {
        cx.diag(e);
    }
    let span = list.finish(&cx, "vhd-blocks")?;
    dissect_or_data(cx, d.input.nested(span)).await
}
