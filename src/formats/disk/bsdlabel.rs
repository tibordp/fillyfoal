//! BSD disklabels (FreeBSD, NetBSD, OpenBSD): sector 1 of a disk or slice
//! holds a label with up to 16 partitions (`a` to `p`).

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{size, volume};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

const LE: Endian = Endian::Little;
const MAGIC: u32 = 0x8256_4557;
const LABEL: u64 = 512;
const SECTOR: u64 = 512;
const MAX_PARTITIONS: u16 = 22;

pub static FORMAT: Format = Format {
    name: "bsdlabel",
    title: "BSD disklabel",
    extensions: &["img"],
    mime: "application/x-bsd-disklabel",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 512) == Some(MAGIC) && u32_le(h.data, 512 + 132) == Some(MAGIC)
}

const FSTYPES: EnumTable = &[
    (0, "unused"),
    (1, "swap"),
    (2, "Version 6"),
    (3, "Version 7"),
    (4, "System V"),
    (5, "4.1BSD"),
    (6, "Eighth Edition"),
    (7, "4.2BSD (FFS/UFS)"),
    (8, "MS-DOS"),
    (9, "4.4LFS"),
    (10, "unknown"),
    (11, "HPFS"),
    (12, "ISO 9660"),
    (13, "boot"),
    (14, "ADOS"),
    (15, "HFS"),
    (16, "ADFS"),
    (17, "ext2"),
    (18, "NTFS"),
    (19, "RAID"),
    (20, "ccd"),
    (21, "JFS2"),
    (22, "Apple UFS"),
    (23, "Vinum"),
    (24, "UDF"),
    (25, "SysV BFS"),
    (26, "EFS"),
    (27, "ZFS"),
    (33, "NANDFS"),
];

const DISK_TYPES: EnumTable = &[
    (1, "SMD"),
    (2, "MSCP"),
    (3, "old DEC"),
    (4, "SCSI"),
    (5, "ESDI"),
    (6, "ST506"),
    (7, "HP-IB"),
    (8, "HP-FL"),
    (10, "floppy"),
    (11, "ccd"),
    (12, "vnd"),
    (13, "ATAPI"),
    (14, "RAID"),
    (15, "ld"),
    (16, "jfs"),
    (17, "cgd"),
    (18, "vinum"),
    (19, "flash"),
    (20, "DM"),
    (21, "rump"),
    (22, "MD"),
];

record! {
    pub struct Label {
        magic: u32 "Magic" .hex(),
        kind: u16 "Drive type" .enumeration(DISK_TYPES),
        subtype: u16 "Subtype",
        type_name: ascii[16] "Type name",
        pack_name: ascii[16] "Pack name",
        sector_size: u32 "Sector size",
        sectors: u32 "Sectors per track",
        tracks: u32 "Tracks per cylinder",
        cylinders: u32 "Cylinders",
        sectors_per_cylinder: u32 "Sectors per cylinder",
        sectors_per_unit: u32 "Sectors per unit" .with(|&v, n| n.summary(size(u64::from(v).saturating_mul(SECTOR)))),
        spares_per_track: u16 "Spare sectors per track",
        spares_per_cylinder: u16 "Spare sectors per cylinder",
        alt_cylinders: u32 "Alternate cylinders",
        rpm: u16 "Rotational speed (rpm)",
        interleave: u16 "Interleave",
        track_skew: u16 "Track skew",
        cylinder_skew: u16 "Cylinder skew",
        head_switch: u32 "Head switch time (us)",
        track_seek: u32 "Track seek time (us)",
        flags: u32 "Flags" .hex(),
        _drive_data: bytes[20] "Drive data",
        _spare: bytes[20] "Spare",
        magic2: u32 "Magic (copy)" .hex(),
        checksum: u16 "Checksum" .hex(),
        partitions: u16 "Partitions",
        boot_size: u32 "Boot area size",
        super_size: u32 "Superblock size",
    }
}

record! {
    pub struct Partition {
        sectors: u32 "Sectors",
        offset: u32 "Offset (sectors)",
        fsize: u32 "Fragment size",
        fstype: u8 "Filesystem type" .enumeration(FSTYPES),
        frag: u8 "Fragments per block",
        cpg: u16 "Cylinders per group",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let disk = input.span;
    let span = disk.sub(LABEL, Label::SIZE);
    let label = parse(&cx, span, LE, &(), Label::layout).await?;
    let count = label.partitions.min(MAX_PARTITIONS);
    let table = disk.sub(LABEL.saturating_add(Label::SIZE), u64::from(count).saturating_mul(Partition::SIZE));
    let raw = cx.read_avail(disk.sub(LABEL, Label::SIZE.saturating_add(table.len))).await?;
    // The XOR of all 16-bit words, checksum included, is zero.
    let xor = raw.as_chunks::<2>().0.iter().fold(0u16, |x, w| x ^ u16::from_le_bytes(*w));
    let mut node = Label::node("Disklabel", span, LE);
    if xor != 0 {
        node = node.diag(Diagnostic::warning("disklabel checksum mismatch"));
    }
    cx.emit(node);
    let entries: Vec<(u32, u32, u8)> = raw
        .get(crate::bytes::to_usize(Label::SIZE)..)
        .unwrap_or_default()
        .as_chunks::<16>()
        .0
        .iter()
        .map(|p| (u32_le(p, 0).unwrap_or(0), u32_le(p, 4).unwrap_or(0), p.get(12).copied().unwrap_or(0)))
        .collect();
    // Old-style labels give absolute offsets; the raw partition `c` then
    // starts where this slice starts.
    let base = entries.get(2).map_or(0, |e| e.1);
    let used = entries.iter().filter(|e| e.0 != 0).count();
    cx.annotate(format!(
        "BSD disklabel \"{}\", {used} partitions",
        label.type_name.trim_end()
    ));
    for (i, &(sectors, offset, fstype)) in entries.iter().enumerate() {
        if sectors == 0 {
            continue;
        }
        let letter = char::from(b'a'.saturating_add(u8::try_from(i).unwrap_or(0)));
        let entry = table.sub(to_u64(i).saturating_mul(Partition::SIZE), Partition::SIZE);
        let start = u64::from(offset).saturating_sub(base.into()).saturating_mul(SECTOR);
        let data = disk.sub(start, u64::from(sectors).saturating_mul(SECTOR));
        let kind = lookup(FSTYPES, fstype.into()).unwrap_or("unknown");
        let whole = i == 2 || start == 0;
        cx.push(
            Node::new(format!("Partition {letter}"))
                .span(entry)
                .summary(format!("{kind}, {} at sector {offset}", size(data.len)))
                .lazy(partition, (input, entry, data, whole)),
        )
        .await;
    }
    Ok(())
}

async fn partition(cx: Cx, (input, entry, data, whole): (Input, Span, Span, bool)) -> Result<()> {
    cx.emit(Partition::node("Entry", entry, LE));
    cx.emit(if whole {
        Node::new("Data").span(data).desc("The whole disk or slice")
    } else {
        volume("Volume", &input, data)
    });
    Ok(())
}
