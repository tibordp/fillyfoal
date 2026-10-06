//! Linux software RAID (md) member devices with a version 1.1 or 1.2
//! superblock (at 0 or 4 KiB). The member's data area is embedded, which
//! for RAID1 members is the array's filesystem itself.

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{size, text, uuid};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
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
        sum = sum.wrapping_add(u16::from_le_bytes([tail.first().copied().unwrap_or(0), tail.get(1).copied().unwrap_or(0)]).into());
    }
    let folded = (sum & 0xffff_ffff).wrapping_add(sum >> 32);
    u32::try_from(folded & 0xffff_ffff).unwrap_or(0)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let dev = input.span;
    let head = cx.read_avail(dev.sub(0, 4096 + 8)).await?;
    let at = superblock_at(&head).ok_or_else(|| Diagnostic::malformed("no md superblock"))?;
    let sb_span = dev.sub(at, Superblock::SIZE);
    let sb = parse(&cx, sb_span, LE, &(), Superblock::layout).await?;
    let roles = u64::from(sb.max_dev.min(MAX_DEVS));
    let full = dev.sub(at, Superblock::SIZE.saturating_add(roles.saturating_mul(2)));
    let data = cx.read_avail(full).await?;
    let mut node = Superblock::node("Superblock", sb_span, LE).summary(format!(
        "version 1.{}",
        if at == 0 { 1 } else { 2 }
    ));
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
    let member = if sb.level == 1 || (sb.level == 0xffff_ffff && sb.raid_disks == 1) {
        embedded("Data", input.nested(data_span)).summary(format!("{level} data, {}", size(data_span.len)))
    } else {
        Node::new("Data")
            .span(data_span)
            .summary(format!("{level} member data, {}", size(data_span.len)))
            .desc("Striped or parity data: the array needs its other members to be read")
    };
    cx.emit(member);
    Ok(())
}
