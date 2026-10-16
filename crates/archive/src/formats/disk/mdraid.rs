//! Linux software RAID (md) member devices. Version 1.1 and 1.2
//! superblocks (at 0 or 4 KiB) are recognised by the probe; version 1.0
//! and 0.90 superblocks sit 8 to 128 KiB before the end of the device, out
//! of the probe's reach, and are recognised by a second-phase probe over
//! the deeper tail ([`DEEP`]). That probe takes precedence over the file
//! systems and partition tables a member's data starts with (a RAID1
//! member's data is the array's file system itself). The member's data
//! area is embedded.

use crate::bytes::{to_u64, to_usize, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::{size, text};
use crate::formats::{Deep, DeepProbe, Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{Check, EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const MAGIC: u32 = 0xa92b_4efc;
/// Device roles listed at most.
const MAX_DEVS: u32 = 384;

pub static FORMAT: Format = Format {
    name: "mdraid",
    title: "Linux md RAID member",
    extensions: &["img"],
    mime: "application/x-linux-raid-member",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn superblock_at(data: &[u8]) -> Option<u64> {
    [0usize, 4096].into_iter().find_map(|at| {
        (u32_le(data, at) == Some(MAGIC) && u32_le(data, at.saturating_add(4)) == Some(1))
            .then_some(to_u64(at))
    })
}

fn probe(h: &Head<'_>) -> bool {
    superblock_at(h.data).is_some()
}

/// The second phase: a version 1.0 superblock (whose own offset field
/// names where it is) or a version 0.90 one (magic, major 0, minor 90) at
/// its place near the end of the device.
pub static DEEP: DeepProbe = DeepProbe {
    format: &FORMAT,
    tail: true,
    over: &[
        "ext",
        "xfs",
        "btrfs",
        "f2fs",
        "jfs",
        "ntfs",
        "fat",
        "exfat",
        "hfsplus",
        "nilfs2",
        "ufs",
        "minix",
        "bfs",
        "zfs",
        "erofs",
        "squashfs",
        "cramfs",
        "iso9660",
        "udf",
        "swap",
        "luks",
        "bitlocker",
        "lvm2",
        "mbr",
        "gpt",
        "apm",
        "bsdlabel",
    ],
    probe: deep_probe,
};

fn deep_probe(d: &Deep<'_>) -> bool {
    if !d.head.len_known {
        return false;
    }
    let len = d.head.len;
    let v10 = v10_offset(len).is_some_and(|at| {
        d.bytes(at, 152).is_some_and(|b| {
            u32_le(b, 0) == Some(MAGIC)
                && u32_le(b, 4) == Some(1)
                && u64_le(b, 144) == Some(at / 512)
        })
    });
    v10 || v090_offset(len).is_some_and(|at| {
        d.bytes(at, 12).is_some_and(|b| {
            u32_le(b, 0) == Some(MAGIC) && u32_le(b, 4) == Some(0) && u32_le(b, 8) == Some(90)
        })
    })
}

/// Where a version 1.0 superblock is: 8 to 12 KiB before the end of the
/// device, 4 KiB aligned (mdadm `super1.c`).
fn v10_offset(len: u64) -> Option<u64> {
    (len / 512)
        .checked_sub(16)
        .map(|s| (s & !7).saturating_mul(512))
}

/// Where a version 0.90 superblock is: the last whole 64 KiB block of the
/// device (mdadm `super0.c`, `MD_NEW_SIZE_SECTORS`).
fn v090_offset(len: u64) -> Option<u64> {
    (len & !0xffff).checked_sub(0x1_0000)
}

/// The superblock's offset and major version (0 or 1).
async fn locate(cx: &Cx, dev: Span) -> Result<Option<(u64, u32)>> {
    let head = cx.read_avail(dev.sub(0, 4096 + 8)).await?;
    if let Some(at) = superblock_at(&head) {
        return Ok(Some((at, 1)));
    }
    for (at, major) in [(v10_offset(dev.len), 1), (v090_offset(dev.len), 0)] {
        let Some(at) = at else { continue };
        let b = cx.read_avail(dev.sub(at, 8)).await?;
        if u32_le(&b, 0) == Some(MAGIC) && u32_le(&b, 4) == Some(major) {
            return Ok(Some((at, major)));
        }
    }
    Ok(None)
}

record! {
    /// `mdp_super_t` (version 0.90), its constant part.
    pub struct Superblock090 {
        magic: u32 "Magic" .hex(),
        major: u32 "Major version",
        minor: u32 "Minor version",
        patch: u32 "Patch version",
        gvalid: u32 "Valid words",
        uuid0: u32 "Array UUID (word 0)" .hex(),
        ctime: u32 "Created" .timestamp(),
        level: u32 "RAID level" .enumeration(LEVELS),
        size: u32 "Component size (KiB)",
        nr_disks: u32 "Disks",
        raid_disks: u32 "RAID disks",
        md_minor: u32 "md minor number",
        not_persistent: u32 "Not persistent",
        uuid1: u32 "Array UUID (word 1)" .hex(),
        uuid2: u32 "Array UUID (word 2)" .hex(),
        uuid3: u32 "Array UUID (word 3)" .hex(),
    }
}

record! {
    /// `mdp_super_t` (version 0.90), the generic state words, in the
    /// little-endian order of the hosts that write them.
    pub struct State090 {
        utime: u32 "Updated" .timestamp(),
        state: u32 "State" .flags(SB_STATE),
        active: u32 "Active disks",
        working: u32 "Working disks",
        failed: u32 "Failed disks",
        spare: u32 "Spare disks",
        checksum: u32 "Superblock checksum" .checksum(MD_SUM),
        events_lo: u32 "Events (low)",
        events_hi: u32 "Events (high)",
        cp_events_lo: u32 "Checkpoint events (low)",
        cp_events_hi: u32 "Checkpoint events (high)",
        recovery_cp: u32 "Recovery checkpoint (sectors)" .with(|&v, n| if v == u32::MAX { n.summary("none: the array is in sync") } else { n }),
        reshape_position: u64 "Reshape position",
        new_level: u32 "New level",
        delta_disks: i32 "Delta disks",
        new_layout: u32 "New layout",
        new_chunk: u32 "New chunk size (bytes)",
    }
}

record! {
    /// `mdp_super_t` (version 0.90), the personality words.
    pub struct Personality090 {
        layout: u32 "Layout",
        chunk_size: u32 "Chunk size (bytes)" .with(|&v, n| if v == 0 { n } else { n.summary(size(v.into())) }),
        root_pv: u32 "Root physical volume",
        root_block: u32 "Root block",
    }
}

record! {
    /// `mdp_disk_t`.
    pub struct Disk090 {
        number: u32 "Number",
        major: u32 "Major",
        minor: u32 "Minor",
        raid_disk: u32 "RAID slot",
        state: u32 "State" .flags(DISK_STATE),
    }
}

const SB_STATE: FlagTable = &[
    flag(1, "CLEAN"),
    flag(2, "ERRORS"),
    flag(0x20, "CLUSTERED"),
    flag(0x100, "BITMAP_PRESENT"),
];

const DISK_STATE: FlagTable = &[
    flag(1, "FAULTY"),
    flag(2, "ACTIVE"),
    flag(4, "SYNC"),
    flag(8, "REMOVED"),
    flag(0x10, "CLUSTER_ADD"),
    flag(0x20, "CANDIDATE"),
    flag(0x200, "WRITEMOSTLY"),
    flag(0x400, "FAILFAST"),
];

/// Words of a 0.90 disk descriptor; 27 descriptors start at word 128, this
/// device's own copy at word 992.
const DISK090: u64 = 128;
const DISKS090: u64 = 27;
const THIS_DISK090: u64 = 992 * 4;
/// Byte offset of `sb_csum`.
const CSUM090: usize = (32 + 6) * 4;

fn disk090_summary(d: &[u8]) -> String {
    let word = |i: usize| u32_le(d, i.saturating_mul(4)).unwrap_or(0);
    let (set, _) = crate::value::decode_flags(DISK_STATE, word(4).into());
    format!(
        "number {}, slot {}, device {}:{}{}",
        word(0),
        word(3),
        word(1),
        word(2),
        if set.is_empty() {
            String::new()
        } else {
            format!(", {}", set.join(" "))
        }
    )
}

/// The whole 4 KiB 0.90 superblock: the constant and state words, the
/// personality words, the used disk descriptors and this device's.
fn sb090_layout(f: &mut Fields<'_>, check: &Check) -> Result<()> {
    f.verifying(check.at(to_u64(CSUM090)));
    Superblock090::read(f)?;
    f.bytes("Reserved", 16 * 4).emit()?;
    State090::read(f)?;
    f.bytes("Reserved", 14 * 4).emit()?;
    Personality090::read(f)?;
    f.bytes("Reserved", 60 * 4).emit()?;
    let data: &[u8] = &f.block().data;
    let mut empty = 0u64;
    for i in 0..DISKS090 {
        let span = f.peek_span(DISK090);
        let at = to_usize(f.pos());
        let d = data.get(at..at.saturating_add(128)).unwrap_or_default();
        if d.iter().all(|&b| b == 0) {
            empty = empty.saturating_add(1);
        } else {
            f.node(Disk090::node(format!("Disk {i}"), span, LE).summary(disk090_summary(d)));
        }
        f.skip(DISK090);
    }
    if empty > 0 {
        f.node(Node::new("Unused disk descriptors").summary(empty.to_string()));
    }
    let at = to_usize(f.pos());
    let d = data.get(at..at.saturating_add(128)).unwrap_or_default();
    f.node(Disk090::node("This disk", f.peek_span(DISK090), LE).summary(disk090_summary(d)));
    Ok(())
}

/// A version 0.90 member: the superblock at `at`, the data before it.
async fn dissect_090(cx: &Cx, input: &Input, at: u64) -> Result<()> {
    let dev = input.span;
    let sb_span = dev.sub(at, 4096);
    let sb = parse(cx, sb_span, LE, &(), Superblock090::layout).await?;
    let raw = cx.read_avail(sb_span).await?;
    let this = raw
        .get(to_usize(THIS_DISK090)..)
        .and_then(|d| u32_le(d, 12));
    let computed = (raw.len() == 4096).then(|| md_checksum(&raw, CSUM090));
    let check = Check::new(MD_SUM, u32_le(&raw, CSUM090).unwrap_or(0)).verify_opt(computed);
    let node = struct_node("Superblock", sb_span, LE, check.clone(), sb090_layout)
        .summary("version 0.90, in the last 64 KiB block")
        .check_diag(&check);
    cx.emit(node);
    let level = crate::value::lookup(LEVELS, sb.level.into()).unwrap_or("unknown level");
    let data_span = dev.sub(0, u64::from(sb.size).saturating_mul(1024).min(at));
    let uuid = format!(
        "{:08x}:{:08x}:{:08x}:{:08x}",
        sb.uuid0, sb.uuid1, sb.uuid2, sb.uuid3
    );
    let role = this.map_or_else(String::new, |r| {
        format!("device {r} of {}, ", sb.raid_disks)
    });
    cx.annotate(format!(
        "Linux md {level} member (version 0.90, {role}UUID {uuid}), {}",
        size(data_span.len)
    ));
    cx.emit(data_node(input, data_span, sb.level, sb.raid_disks, level));
    Ok(())
}

/// The member's data: the array's content for RAID1 (and one-disk linear)
/// members, opaque stripes otherwise.
fn data_node(input: &Input, span: Span, level_code: u32, disks: u32, level: &str) -> Node {
    if level_code == 1 || (level_code == 0xffff_ffff && disks == 1) {
        embedded("Data", input.nested(span)).summary(format!("{level} data, {}", size(span.len)))
    } else {
        Node::new("Data")
            .span(span)
            .summary(format!("{level} member data, {}", size(span.len)))
            .desc("Striped or parity data: the array needs its other members to be read")
    }
}

const LEVELS: EnumTable = &[
    (0xffff_fffc, "multipath"),
    (0xffff_ffff, "linear"),
    (0, "RAID0"),
    (1, "RAID1"),
    (4, "RAID4"),
    (5, "RAID5"),
    (6, "RAID6"),
    (10, "RAID10"),
];

const FEATURES: FlagTable = &[
    flag(1, "BITMAP_OFFSET"),
    flag(2, "RECOVERY_OFFSET"),
    flag(4, "RESHAPE_ACTIVE"),
    flag(8, "BAD_BLOCKS"),
    flag(16, "REPLACEMENT"),
    flag(32, "RESHAPE_BACKWARDS"),
    flag(64, "NEW_OFFSET"),
    flag(128, "RECOVERY_BITMAP"),
    flag(256, "CLUSTERED"),
    flag(512, "JOURNAL"),
    flag(1024, "PPL"),
    flag(2048, "MULTIPLE_PPLS"),
];

#[allow(clippy::ptr_arg)] // a `Field::with` decorator
fn uuid_node(b: &Vec<u8>, n: Node) -> Node {
    n.value(Value::uuid(b))
}

/// Decorator for a count of 512-byte sectors.
fn sectors<T: Copy + Into<u64>>(_: &T, n: Node) -> Node {
    n.as_blocks(512u32)
}

/// RAID4/5/6 parity layouts (`ALGORITHM_*` in the kernel's `raid5.h`).
const PARITY_LAYOUTS: EnumTable = &[
    (0, "left-asymmetric"),
    (1, "right-asymmetric"),
    (2, "left-symmetric"),
    (3, "right-symmetric"),
    (4, "parity-first"),
    (5, "parity-last"),
    (6, "ddf-zero-restart"),
    (7, "ddf-N-restart"),
    (8, "ddf-N-continue"),
    (16, "left-asymmetric-6"),
    (17, "right-asymmetric-6"),
    (18, "left-symmetric-6"),
    (19, "right-symmetric-6"),
    (20, "parity-first-6"),
];

/// The layout as mdadm names it: a parity algorithm for RAID4/5/6, near,
/// far and offset copies for RAID10.
fn layout_name(level: u32, layout: u32) -> Option<String> {
    match level {
        4..=6 => crate::value::lookup(PARITY_LAYOUTS, layout.into()).map(str::to_owned),
        10 => {
            let (near, far) = (layout & 0xff, (layout >> 8) & 0xff);
            let far_kind = if layout & 0x1_0000 != 0 {
                "offset"
            } else {
                "far"
            };
            Some(match (near > 1, far > 1) {
                (true, true) => format!("near={near}, {far_kind}={far}"),
                (false, true) => format!("{far_kind}={far}"),
                _ => format!("near={near}"),
            })
        }
        _ => None,
    }
}

fn layout_summary(n: Node, level: u32, layout: u32) -> Node {
    match layout_name(level, layout) {
        Some(name) => n.summary(name),
        None => n,
    }
}

record! {
    /// `struct mdp_superblock_1`.
    pub struct Superblock {
        magic: u32 "Magic" .hex(),
        major: u32 "Major version",
        features: u32 "Feature map" .hex() .flags(FEATURES),
        _pad0: u32 "Padding",
        set_uuid: bytes[16] "Array UUID" .with(uuid_node),
        set_name: bytes[32] "Array name" .with(|b, n| n.value(text(b))),
        ctime: u64 "Created" .with(|&v, n| n.value(Value::utc(i64::try_from(v & 0xff_ffff_ffff).unwrap_or(0)))),
        level: u32 "RAID level" .enumeration(LEVELS),
        layout: u32 "Layout" .with(|&v, n| layout_summary(n, level, v)),
        size: u64 "Component size" .with(sectors),
        chunk: u32 "Chunk size" .with(sectors),
        raid_disks: u32 "RAID disks",
        bitmap_offset: i32 "Bitmap offset (sectors from the superblock)",
        new_level: u32 "New level",
        reshape_position: u64 "Reshape position",
        delta_disks: i32 "Delta disks",
        new_layout: u32 "New layout",
        new_chunk: u32 "New chunk size",
        new_offset: i32 "New data offset (sectors, relative)",
        data_offset: u64 "Data offset (sectors)",
        data_size: u64 "Data size (sectors)",
        super_offset: u64 "Superblock offset (sectors)",
        recovery_offset: u64 "Recovery offset",
        dev_number: u32 "Device number",
        corrected: u32 "Corrected read errors",
        device_uuid: bytes[16] "Device UUID" .with(uuid_node),
        devflags: u8 "Device flags" .hex(),
        bblog_shift: u8 "Bad block log shift",
        bblog_size: u16 "Bad block log size",
        bblog_offset: i32 "Bad block log offset (sectors from the superblock)",
        utime: u64 "Updated" .with(|&v, n| n.value(Value::utc(i64::try_from(v & 0xff_ffff_ffff).unwrap_or(0)))),
        events: u64 "Events",
        resync_offset: u64 "Resync offset" .with(|&v, n| if v == u64::MAX { n.summary("none: the array is in sync") } else { n }),
        checksum: u32 "Superblock checksum" .checksum(MD_SUM),
        max_dev: u32 "Device role slots",
        logical_block_size: u32 "Logical block size" .desc("The array's logical block size; recent kernels store it, older ones leave 0"),
        _pad3: bytes[28] "Padding",
    }
}

/// What md's superblock checksum is.
const MD_SUM: &str = "md word sum";

/// md's checksum: 32-bit sum of little-endian words (checksum field as 0),
/// folded to 32 bits.
fn md_checksum(data: &[u8], csum_at: usize) -> u32 {
    let mut sum = 0u64;
    for (i, w) in data.as_chunks::<4>().0.iter().enumerate() {
        if i != csum_at / 4 {
            sum = sum.wrapping_add(u32::from_le_bytes(*w).into());
        }
    }
    if data.len() % 4 == 2 {
        let tail = data.get(data.len().saturating_sub(2)..).unwrap_or_default();
        sum = sum.wrapping_add(
            u16::from_le_bytes([
                tail.first().copied().unwrap_or(0),
                tail.get(1).copied().unwrap_or(0),
            ])
            .into(),
        );
    }
    let folded = (sum & 0xffff_ffff).wrapping_add(sum >> 32);
    u32::try_from(folded & 0xffff_ffff).unwrap_or(0)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let dev = input.span;
    let (at, major) = locate(&cx, dev)
        .await?
        .ok_or_else(|| Diagnostic::malformed("no md superblock"))?;
    if major == 0 {
        return dissect_090(&cx, &input, at).await;
    }
    let sb_span = dev.sub(at, Superblock::SIZE);
    let sb = parse(&cx, sb_span, LE, &(), Superblock::layout).await?;
    let roles = u64::from(sb.max_dev.min(MAX_DEVS));
    let full = dev.sub(at, Superblock::SIZE.saturating_add(roles.saturating_mul(2)));
    let data = cx.read_avail(full).await?;
    let check = Check::new(MD_SUM, sb.checksum).verify(md_checksum(&data, 216));
    let node = Superblock::checked_node("Superblock", sb_span, LE, check.at(216))
        .summary(match at {
            0 => "version 1.1",
            4096 => "version 1.2",
            _ => "version 1.0, at the end of the device",
        })
        .check_diag(&check);
    cx.emit(node);
    let name = crate::text::until_nul(&sb.set_name);
    let level = crate::value::lookup(LEVELS, sb.level.into()).unwrap_or("unknown level");
    // `dev_roles[dev_number]` is this member's role (mdadm's "Device Role").
    let role_of = |dev: u32| {
        let at = to_usize(u64::from(dev).saturating_mul(2).saturating_add(256));
        data.get(at..at.saturating_add(2))
            .and_then(|r| <[u8; 2]>::try_from(r).ok())
            .map(u16::from_le_bytes)
    };
    let role = match role_of(sb.dev_number) {
        Some(0xffff) => "spare".to_owned(),
        Some(0xfffe) => "faulty".to_owned(),
        Some(0xfffd) => "journal".to_owned(),
        Some(r) => format!("device {r} of {}", sb.raid_disks),
        None => format!("device number {}", sb.dev_number),
    };
    // The array uses `size` sectors of each member; the data area may be
    // larger (mdadm's "Avail Dev Size").
    let used = if sb.size > 0 && sb.size <= sb.data_size {
        sb.size
    } else {
        sb.data_size
    };
    let layout = layout_name(sb.level, sb.layout)
        .map(|l| {
            format!(
                ", {l}, {} chunks",
                size(u64::from(sb.chunk).saturating_mul(512))
            )
        })
        .unwrap_or_default();
    cx.annotate(format!(
        "Linux md {level} member \"{name}\" ({role}{layout}), {}",
        size(used.saturating_mul(512))
    ));
    let roles_span = dev.sub(at.saturating_add(Superblock::SIZE), roles.saturating_mul(2));
    cx.emit(
        Node::new("Device roles")
            .span(roles_span)
            .summary(roles_summary(data.get(256..).unwrap_or_default()))
            .desc("The role of each device number: its slot in the array, or spare (also unused numbers), faulty or journal"),
    );
    let data_span = dev.sub(sb.data_offset.saturating_mul(512), used.saturating_mul(512));
    cx.emit(data_node(&input, data_span, sb.level, sb.raid_disks, level));
    Ok(())
}

/// The device roles in use (`dev_roles` entries other than 0xffff, which
/// marks both spares and unused device numbers).
fn roles_summary(roles: &[u8]) -> String {
    let mut used = Vec::new();
    let mut more = 0usize;
    let mut other = 0usize;
    for (dev, r) in roles.as_chunks::<2>().0.iter().enumerate() {
        let role = u16::from_le_bytes(*r);
        if role == 0xffff {
            other = other.saturating_add(1);
        } else if used.len() >= 16 {
            more = more.saturating_add(1);
        } else {
            used.push(match role {
                0xfffe => format!("{dev}: faulty"),
                0xfffd => format!("{dev}: journal"),
                n => format!("{dev}: slot {n}"),
            });
        }
    }
    if used.is_empty() {
        used.push("none in use".to_owned());
    }
    if more > 0 {
        used.push(format!("{more} more"));
    }
    format!("{}; {other} spare or unused", used.join(", "))
}
