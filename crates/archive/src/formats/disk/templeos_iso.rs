//! TempleOS's RedSea ISOs: the distribution ISO and what `RedSeaISO`
//! (`Adam/Opt/Boot/DskISORedSea.HC` of the public-domain TempleOS V5.03
//! source) writes.
//!
//! Such an ISO is an ISO 9660 shell around a RedSea volume
//! ([`super::redsea`]) whose boot sector is at 512-byte block 88
//! ([`super::redsea::ISO_DRV_OFFSET`], byte 0xB000). `RedSeaISO9660`
//! writes four 2048-byte volume descriptors from sector 16: a primary
//! one, an El Torito boot record, a supplementary one (a copy of the
//! primary with its type changed) and a terminator, then the boot catalog
//! at sector 20 and the stage-1 loader (the no-emulation boot image) at
//! sector 21. The primary and supplementary descriptors are TempleOS's
//! `CISOPriDesc` (`Kernel/KernelA.HH`): only the sizes, the root block of
//! the RedSea volume and the publisher are filled in. There are no ISO
//! 9660 directories; the files are in the RedSea volume.

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::disk::iso9660::{
    DESCRIPTOR_TYPE, DESCRIPTORS_AT, SECTOR, boot_catalog, boot_images, boot_layout, both16,
    both32, plain_layout, unused,
};
use crate::formats::disk::qcow::Regions;
use crate::formats::disk::redsea::{self, ISO_DRV_OFFSET};
use crate::formats::util::fmt;
use crate::formats::util::fmt::{capitalize, count};
use crate::formats::{Format, Head, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Value, lookup};

const LE: Endian = Endian::Little;
/// `BLK_SIZE`, RedSea's block.
const BLK: u64 = 512;
/// Where the RedSea boot sector is.
const REDSEA_AT: u64 = ISO_DRV_OFFSET * BLK;
/// `RedSeaISO9660` writes four descriptors; a few more are read before
/// giving up on a terminator.
const MAX_DESCRIPTORS: u64 = 8;
/// `ISOT_PRI_VOL_DESC`, `ISOT_SUPPLEMENTARY_DESC`, `ISOT_BOOT_RECORD`,
/// `ISOT_TERMINATOR`.
const PRIMARY: u8 = 1;
const SUPPLEMENTARY: u8 = 2;
const BOOT_RECORD: u8 = 0;
const TERMINATOR: u8 = 255;

pub static FORMAT: Format = Format {
    name: "templeos-iso",
    title: "TempleOS RedSea ISO",
    extensions: &["iso"],
    mime: "application/x-iso9660-image",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// A primary volume descriptor, and a RedSea volume that starts at block
/// 88 and says so.
fn probe(h: &Head<'_>) -> bool {
    let at = usize::try_from(REDSEA_AT).unwrap_or(usize::MAX);
    h.data.get(0x8000) == Some(&PRIMARY)
        && h.at(0x8001, b"CD001")
        && h.data
            .get(at..at.saturating_add(512))
            .and_then(redsea::boot)
            .is_some_and(|b| b.drv_offset == ISO_DRV_OFFSET)
}

/// `CISOPriDesc`, as `RedSeaISO9660` fills it; `root_clus` is the RedSea
/// boot sector's, which `root_dir_record` should repeat.
fn pri_desc_layout(f: &mut Fields<'_>, &root_clus: &u64) -> Result<(u32, u16)> {
    f.u8("type").enumeration(DESCRIPTOR_TYPE).emit()?;
    f.ascii("id", 5).emit()?;
    f.u8("version").emit()?;
    unused(f, "pad", 73)?;
    let blocks = both32(f, "vol_space_size")
        .desc("Size of the ISO file in 2048-byte blocks (FSize / DVD_BLK_SIZE)")
        .with(|&v, n| n.summary(fmt::size(u64::from(v).saturating_mul(SECTOR))))
        .emit()?;
    unused(f, "pad", 32)?;
    both16(f, "vol_set_size").emit()?;
    both16(f, "vol_seq_num").emit()?;
    let block_size = both16(f, "log_block_size").emit()?;
    unused(f, "pad", 20)?;
    both32(f, "root_dir_record")
        .desc(
            "The RedSea root directory's block (dv->root_clus), stored as a both-endian \
             number over the start of this CISODirEntry",
        )
        .with(move |&v, n| {
            if u64::from(v) == root_clus {
                n
            } else {
                n.diag(Diagnostic::warning(format!(
                    "the RedSea boot sector's root directory is at block {root_clus}"
                )))
            }
        })
        .emit()?;
    unused(f, "pad", 26)?;
    unused(f, "pad", 128)?;
    f.bytes("publisher_id", 128)
        .with(|b, n| n.value(Value::Text(until_nul(b))))
        .emit()?;
    unused(f, "pad", 435)?;
    f.u8("file_structure_version").emit()?;
    unused(f, "pad", 1166)?;
    // `CISOPriDesc` is 2044 bytes; the rest of the block stays zero.
    unused(f, "Unused", 4)?;
    Ok((blocks, block_size))
}

fn until_nul(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    crate::text::latin1(b.get(..end).unwrap_or_default())
}

/// What the layout node accounts for.
#[derive(Clone, Debug)]
struct LayoutState {
    input: Input,
    descriptors: u64,
    catalog: Option<Span>,
    redsea: Span,
}

async fn layout(cx: Cx, s: Arc<LayoutState>) -> Result<()> {
    let file = s.input.span;
    let mut r = Regions::default();
    r.add(0, DESCRIPTORS_AT, "System area", None);
    r.add(
        DESCRIPTORS_AT,
        s.descriptors.saturating_mul(SECTOR),
        "Volume descriptors",
        None,
    );
    if let Some(c) = s.catalog {
        r.span(file, c, "Boot catalog");
        for img in boot_images(&cx, file, c, SECTOR).await? {
            r.span(file, img, "Boot image");
        }
    }
    r.span(file, s.redsea, "RedSea volume");
    r.emit(&cx, file, "not referenced").await;
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let system_span = file.sub(0, DESCRIPTORS_AT);
    let system = cx.read_avail(system_span).await?;
    if system.iter().any(|&b| b != 0) {
        cx.emit(embedded("System area", input.nested(system_span)).summary("boot code"));
    } else {
        cx.emit(Node::new("System area").span(system_span).summary("empty"));
    }
    let sector = cx.read(file.sub(REDSEA_AT, BLK)).await?;
    let boot = redsea::boot(&sector)
        .ok_or_else(|| Diagnostic::malformed("no RedSea boot sector at block 88"))?;
    let redsea_span = file.sub(REDSEA_AT, boot.sects.saturating_mul(BLK));

    let mut size: Option<u64> = None;
    let mut catalog: Option<u32> = None;
    let mut descriptors = Vec::new();
    for i in 0..MAX_DESCRIPTORS {
        let span = file.sub(
            DESCRIPTORS_AT.saturating_add(i.saturating_mul(SECTOR)),
            SECTOR,
        );
        let head = cx.read_avail(span.sub(0, 7)).await?;
        if head.get(1..6) != Some(b"CD001".as_slice()) {
            break;
        }
        let kind = head.first().copied().unwrap_or(0);
        let name = lookup(DESCRIPTOR_TYPE, kind.into())
            .map_or_else(|| format!("Descriptor type {kind}"), capitalize);
        let node = match kind {
            PRIMARY | SUPPLEMENTARY => {
                let (blocks, block_size) =
                    crate::fields::parse(&cx, span, LE, &boot.root_clus, pri_desc_layout).await?;
                let bytes = u64::from(blocks).saturating_mul(block_size.into());
                if kind == PRIMARY && size.is_none() {
                    size = Some(bytes);
                }
                let publisher = cx.read(span.sub(0x13a, 128)).await?;
                struct_node(name, span, LE, boot.root_clus, pri_desc_layout).summary(format!(
                    "{:?}, {}",
                    until_nul(&publisher),
                    fmt::size(bytes)
                ))
            }
            BOOT_RECORD => {
                let sector = crate::fields::parse(&cx, span, LE, &(), boot_layout).await?;
                let sys = cx.read(span.sub(7, 32)).await?;
                let sys = String::from_utf8_lossy(&sys)
                    .trim_end_matches(['\0', ' '])
                    .to_owned();
                if sys == "EL TORITO SPECIFICATION" && catalog.is_none() {
                    catalog = Some(sector);
                }
                struct_node(name, span, LE, (), boot_layout).summary(sys)
            }
            _ => struct_node(name, span, LE, (), plain_layout),
        };
        descriptors.push(node);
        cx.checkpoint().await;
        if kind == TERMINATOR {
            break;
        }
    }
    let n = to_u64(descriptors.len());
    cx.emit(
        Node::new("Volume descriptors")
            .span(file.sub(DESCRIPTORS_AT, n.saturating_mul(SECTOR)))
            .summary(count(n, "descriptor", "descriptors"))
            .lazy(
                crate::formats::util::arcutil::emit_nodes,
                Arc::new(descriptors),
            ),
    );

    let mut summary = String::from("TempleOS RedSea ISO");
    let size = size.unwrap_or(file.len);
    summary.push_str(&format!(", {}", fmt::size(size)));
    let catalog_span = catalog.map(|c| file.sub(u64::from(c).saturating_mul(SECTOR), SECTOR));
    if let Some(span) = catalog_span {
        summary.push_str(", El Torito");
        cx.emit(
            Node::new("Boot catalog")
                .span(span)
                .lazy(boot_catalog, (input, span, SECTOR)),
        );
    }
    cx.emit(
        embedded_as(
            "RedSea file system",
            input.nested(redsea_span),
            &redsea::FORMAT,
        )
        .summary(fmt::size(redsea_span.len)),
    );
    let volume = file.sub(0, size);
    cx.emit(
        Node::new("Image layout")
            .span(volume)
            .summary("what each sector holds")
            .lazy(
                layout,
                Arc::new(LayoutState {
                    input: input.nested(volume),
                    descriptors: n,
                    catalog: catalog_span,
                    redsea: redsea_span,
                }),
            ),
    );
    if size < file.len {
        cx.emit(Node::new("Data after the volume").span(file.tail(size)));
    }
    cx.annotate(summary);
    Ok(())
}
