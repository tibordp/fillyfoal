//! Linux software RAID (md) member devices. Version 1.1 and 1.2
//! superblocks (at 0 or 4 KiB) are recognised by the probe; version 1.0
//! and 0.90 superblocks sit near the end of the device, out of the
//! probe's reach, and are found when the device is opened as this format
//! ("inspect as"). The member's data area is embedded, which for RAID1
//! members is the array's filesystem itself.

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{size, text, uuid};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

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

/// A version 0.90 member: the superblock at `at`, the data before it.
async fn dissect_090(cx: &Cx, input: &Input, at: u64) -> Result<()> {
    let dev = input.span;
    let sb_span = dev.sub(at, 4096);
    let sb = parse(cx, sb_span, LE, &(), Superblock090::layout).await?;
    cx.emit(
        Superblock090::node("Superblock", sb_span.sub(0, Superblock090::SIZE), LE)
            .summary("version 0.90, in the last 64 KiB block"),
    );
    let level = crate::value::lookup(LEVELS, sb.level.into()).unwrap_or("unknown level");
    let data_span = dev.sub(0, u64::from(sb.size).saturating_mul(1024).min(at));
    cx.annotate(format!(
        "Linux md {level} member (version 0.90, {} disks), {}",
        sb.raid_disks,
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
    n.value(Value::Text(uuid(b)))
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
        ctime: u64 "Created" .with(|&v, n| n.value(Value::Timestamp { unix_seconds: i64::try_from(v & 0xff_ffff_ffff).unwrap_or(0) })),
        level: u32 "RAID level" .enumeration(LEVELS),
        layout: u32 "Layout",
        size: u64 "Component size (sectors)",
        chunk: u32 "Chunk size (sectors)",
        raid_disks: u32 "RAID disks",
        bitmap_offset: u32 "Bitmap offset (sectors, signed)",
        new_level: u32 "New level",
        reshape_position: u64 "Reshape position",
        delta_disks: u32 "Delta disks",
        new_layout: u32 "New layout",
        new_chunk: u32 "New chunk size",
        new_offset: u32 "New data offset",
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
        bblog_offset: u32 "Bad block log offset",
        utime: u64 "Updated" .with(|&v, n| n.value(Value::Timestamp { unix_seconds: i64::try_from(v & 0xff_ffff_ffff).unwrap_or(0) })),
        events: u64 "Events",
        resync_offset: u64 "Resync offset",
        checksum: u32 "Superblock checksum" .hex(),
        max_dev: u32 "Device role slots",
        _pad3: bytes[32] "Padding",
    }
}

/// md's checksum: 32-bit sum of little-endian words (checksum field as 0),
/// folded to 32 bits.
fn md_checksum(data: &[u8]) -> u32 {
    let mut sum = 0u64;
    for (i, w) in data.as_chunks::<4>().0.iter().enumerate() {
        if i != 216 / 4 {
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
    let mut node = Superblock::node("Superblock", sb_span, LE).summary(match at {
        0 => "version 1.1",
        4096 => "version 1.2",
        _ => "version 1.0, at the end of the device",
    });
    if md_checksum(&data) != sb.checksum {
        node = node.diag(Diagnostic::warning(format!(
            "checksum mismatch: computed {:#010x}",
            md_checksum(&data)
        )));
    }
    cx.emit(node);
    let name = crate::text::until_nul(&sb.set_name);
    let level = crate::value::lookup(LEVELS, sb.level.into()).unwrap_or("unknown level");
    cx.annotate(format!(
        "Linux md {level} member \"{name}\" (device {} of {}), {}",
        sb.dev_number,
        sb.raid_disks,
        size(sb.data_size.saturating_mul(512))
    ));
    let roles_span = dev.sub(at.saturating_add(Superblock::SIZE), roles.saturating_mul(2));
    let summary: Vec<String> = data
        .get(256..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|r| match u16::from_le_bytes(*r) {
            0xffff => "spare".to_owned(),
            0xfffe => "faulty".to_owned(),
            0xfffd => "journal".to_owned(),
            n => n.to_string(),
        })
        .take(16)
        .collect();
    cx.emit(
        Node::new("Device roles")
            .span(roles_span)
            .summary(summary.join(", ")),
    );
    let data_span = dev.sub(
        sb.data_offset.saturating_mul(512),
        sb.data_size.saturating_mul(512),
    );
    cx.emit(data_node(&input, data_span, sb.level, sb.raid_disks, level));
    Ok(())
}
