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
//! the RedSea volume and the publisher are filled in (the zero padding
//! between them is one node). There are no ISO 9660 directories; the files
//! are in the RedSea volume. The boot image is `BootDVD`'s stage-1 loader,
//! with the place and length of its stage 2 (the kernel) patched in, when
//! `RedSeaISO` found the stage-2 file; otherwise it is zeros.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::disk::iso9660::{
    DESCRIPTOR_TYPE, DESCRIPTORS_AT, SECTOR, boot_catalog_with, boot_images, boot_layout, both16,
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
    // Zero padding: bytes and runs, listed as one node.
    let mut zeros = (0u64, 0u64);
    f.u8("type").enumeration(DESCRIPTOR_TYPE).emit()?;
    f.ascii("id", 5).emit()?;
    f.u8("version").emit()?;
    pad(f, 73, &mut zeros)?;
    let blocks = both32(f, "vol_space_size")
        .desc("Size of the ISO file in 2048-byte blocks (FSize / DVD_BLK_SIZE)")
        .with(|&v, n| n.summary(fmt::size(u64::from(v).saturating_mul(SECTOR))))
        .emit()?;
    pad(f, 32, &mut zeros)?;
    both16(f, "vol_set_size").emit()?;
    both16(f, "vol_seq_num").emit()?;
    let block_size = both16(f, "log_block_size").emit()?;
    pad(f, 20, &mut zeros)?;
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
    pad(f, 26, &mut zeros)?;
    pad(f, 128, &mut zeros)?;
    f.bytes("publisher_id", 128)
        .with(|b, n| n.value(Value::Text(until_nul(b))))
        .emit()?;
    pad(f, 435, &mut zeros)?;
    f.u8("file_structure_version").emit()?;
    pad(f, 1166, &mut zeros)?;
    // `CISOPriDesc` is 2044 bytes; the rest of the block stays zero.
    pad(f, 4, &mut zeros)?;
    if zeros.1 > 0 {
        f.node(
            Node::new("Padding")
                .summary(format!(
                    "zeros: {} in {} runs between the fields",
                    fmt::size(zeros.0),
                    zeros.1
                ))
                .desc("The parts of CISOPriDesc that RedSeaISO9660 leaves zero"),
        );
    }
    Ok((blocks, block_size))
}

/// `len` bytes of padding: counted in `zeros` if they are zero (as
/// `RedSeaISO9660` leaves them), otherwise shown.
fn pad(f: &mut Fields<'_>, len: u64, zeros: &mut (u64, u64)) -> Result<()> {
    let start = f.pos();
    if f.bytes("pad", len).get()?.iter().all(|&b| b == 0) {
        zeros.0 = zeros.0.saturating_add(len);
        zeros.1 = zeros.1.saturating_add(1);
        return Ok(());
    }
    f.seek(start);
    unused(f, "pad", len)
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
                .lazy(boot_catalog_with, (input, span, SECTOR, boot_image)),
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

/// The no-emulation boot image: `RedSeaISO9660Stage1` copies the stage-1
/// DVD loader (`BDVD_START`..`BDVD_END`, `Adam/Opt/Boot/BootDVD.HC`) there
/// with the place of its stage 2 (the kernel) patched in, but only if it
/// finds that stage-2 file; otherwise the sector stays zero.
fn boot_image(input: Input) -> Node {
    Node::new("Boot image")
        .span(input.span)
        .summary(fmt::size(input.span.len))
        .lazy(boot_image_content, input)
}

async fn boot_image_content(cx: Cx, input: Input) -> Result<()> {
    let span = input.span.sub(0, SECTOR);
    let data = cx.read(span).await?;
    if data.iter().all(|&b| b == 0) {
        cx.annotate(
            "empty (zeros): RedSeaISO writes the stage-1 loader only if it finds the stage-2 file",
        );
        return Ok(());
    }
    let Some(f) = boot_dvd(&data) else {
        cx.annotate(format!(
            "boot code, {} (not TempleOS V5.03's BootDVD)",
            fmt::size(input.span.len)
        ));
        cx.emit(Node::new("Code").span(input.span));
        return Ok(());
    };
    let stage2 = u64::from(f.blk)
        .saturating_mul(4)
        .saturating_add(f.shift.into());
    cx.annotate(format!(
        "BootDVD stage-1 loader: loads {} of 2 KiB from block {} (the stage 2 at 512-byte block {stage2})",
        fmt::plural(f.cnt, "block"),
        f.blk
    ));
    let end = data
        .iter()
        .rposition(|&c| c != 0)
        .map_or(0, |i| i.saturating_add(1));
    let at = |off: u64, len: u64| input.span.sub(off, len);
    cx.emit(
        Node::new("Loader")
            .span(at(0, to_u64(end)))
            .summary("real-mode code (Adam/Opt/Boot/BootDVD.HC), not disassembled"),
    );
    let uint = |value: u64, bits: u8| Value::UInt {
        value,
        bits,
        radix: crate::value::Radix::Dec,
    };
    // The loader sits at 2048-byte block 21 of the ISO (`RedSeaISO9660Stage1`
    // writes it there), so the stage 2's block is found from its place.
    let iso = input.span.offset.checked_sub(21 * SECTOR);
    let mut blk = Node::new("BDVD_BLK")
        .span(at(BDVD_BLK, 4))
        .value(uint(f.blk.into(), 32))
        .desc("First 2048-byte block the loader reads: the stage-2 file's first 512-byte block >> 2 (BDVD_BLK_LO and BDVD_BLK_HI)");
    if let Some(off) = iso.and_then(|i| i.checked_add(stage2.checked_mul(BLK)?)) {
        let len = u64::from(f.cnt)
            .saturating_mul(SECTOR)
            .saturating_sub(u64::from(f.shift).saturating_mul(BLK))
            .min(cx.source_len(input.span.source).saturating_sub(off));
        if off < cx.source_len(input.span.source) {
            blk = blk.target(Span::new(input.span.source, off, len));
        }
    }
    cx.emit(blk);
    cx.emit(
        Node::new("BDVD_BLK_CNT")
            .span(at(BDVD_BLK_CNT, 2))
            .value(uint(f.cnt.into(), 16))
            .summary(fmt::size(u64::from(f.cnt).saturating_mul(SECTOR)))
            .desc("2048-byte blocks the loader reads: the stage-2 file's size, rounded up, one more if it is not aligned"),
    );
    cx.emit(
        Node::new("BDVD_SHIFT_BLKS")
            .span(at(BDVD_SHIFT_BLKS, 2))
            .value(uint(f.shift.into(), 16))
            .desc("512-byte blocks the stage 2 starts into the first block read (its block & 3); the loader shifts it back"),
    );
    Ok(())
}

/// Offsets in V5.03's `BootDVD` as assembled (checked against the
/// distribution ISO): its far `JMP` to `BDVD_MAIN` (at 0xB0), and the
/// fields `RedSeaISO9660Stage1` patches: `BDVD_BLK_LO`/`HI` (written as
/// one U32), `BDVD_BLK_CNT` and `BDVD_SHIFT_BLKS` (U16s).
const BDVD_JMP: usize = 0x30;
const BDVD_BLK: u64 = 0x88;
const BDVD_BLK_CNT: u64 = 0x8c;
const BDVD_SHIFT_BLKS: u64 = 0x8e;

struct BootDvd {
    blk: u32,
    cnt: u16,
    shift: u16,
}

fn boot_dvd(b: &[u8]) -> Option<BootDvd> {
    (b.first() == Some(&0xfc)
        && b.get(BDVD_JMP..BDVD_JMP.saturating_add(3)) == Some(&[0xea, 0xb0, 0x00]))
    .then_some(())?;
    let at = |o: u64| usize::try_from(o).ok();
    Some(BootDvd {
        blk: u32_le(b, at(BDVD_BLK)?)?,
        cnt: u16_le(b, at(BDVD_BLK_CNT)?)?,
        shift: u16_le(b, at(BDVD_SHIFT_BLKS)?)?,
    })
}
