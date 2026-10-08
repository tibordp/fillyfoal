//! UDF (Universal Disk Format, OSTA UDF 1.02–2.60 on ECMA-167): DVD and
//! Blu-ray images, and the UDF half of ISO 9660 / UDF bridge discs.
//!
//! The volume recognition sequence (`BEA01`, `NSR02`/`NSR03`, `TEA01`) is
//! shown by [`super::iso9660`], which shares the probe area at 32 KiB and
//! hands UDF volumes to this module: [`load`] finds the anchor volume
//! descriptor pointer (sector 256, else the last sector or 256 before it),
//! walks the main volume descriptor sequence (primary, implementation use,
//! partition, logical volume and unallocated space descriptors, up to the
//! terminator; reserve sequence as fallback) and resolves the logical
//! volume's partition maps:
//!
//! - type 1 maps onto a partition descriptor (a run of physical blocks);
//! - type 2 "*UDF Sparable Partition" (CD-RW/DVD-RW) remaps packets through
//!   the first readable sparing table;
//! - type 2 "*UDF Metadata Partition" (UDF 2.50+, Blu-ray) is the content of
//!   the metadata file (falling back to its mirror), assembled from its
//!   extents with `Cx::add_pieces`;
//! - type 2 "*UDF Virtual Partition" (CD-R/DVD-R, UDF 1.50+) translates
//!   blocks through the virtual allocation table found in the last block.
//!
//! The file set descriptor (from the logical volume's contents use) names
//! the root directory ICB. Directories are streams of file identifier
//! descriptors, walked lazily and paged with resume marks; each entry's file
//! entry or extended file entry (ICB tag, owner, permissions, times,
//! extended attributes, short/long/extended allocation descriptors with
//! allocation extent continuations, or data embedded in the ICB) is decoded,
//! and file content is presented as an embedded child: a plain span when
//! contiguous, a piecewise source otherwise (holes for unrecorded extents).
//! Named streams (the stream directory of an extended file entry) and
//! symbolic links (path components) are shown too. Indirect entries are
//! followed; strategy 4096 ICB hierarchies beyond that are not.
//!
//! Layouts are from ECMA-167 3rd edition and OSTA UDF 2.60, written from
//! memory and checked against images from macOS `hdiutil makehybrid` (UDF
//! 1.02 / 1.50, bridge) and pycdlib (UDF 2.60 bridge). Sparable, metadata
//! and virtual partitions are only checked against our own synthetic images
//! (no writer available here); the sparing-table semantics (original
//! locations relative to the partition, mapped locations absolute) follow
//! the Linux driver as remembered. Unknown or reserved fields are shown raw.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::codec::crc::crc16_xmodem;
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::Input;
use crate::formats::disk::{
    align, assemble, civil_to_unix, coalesce, coalesce_stepped, content_node, fragments_node,
};
use crate::formats::util::arcutil::{count, human_size, text, uint};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag};

const LE: Endian = Endian::Little;
/// Volume descriptors read per sequence (and sequence hops).
const MAX_DESCRIPTORS: u64 = 256;
const MAX_HOPS: usize = 16;
/// Allocation extent descriptors followed per file.
const MAX_AED: usize = 1024;
const MAX_DEPTH: usize = 64;
const MAX_MAPS: usize = 64;
/// Largest virtual allocation table read.
const MAX_VAT: u64 = 4 << 20;
const FID_HEAD: u64 = 38;

const TAG_IDS: EnumTable = &[
    (0, "sparing table"),
    (1, "primary volume descriptor"),
    (2, "anchor volume descriptor pointer"),
    (3, "volume descriptor pointer"),
    (4, "implementation use volume descriptor"),
    (5, "partition descriptor"),
    (6, "logical volume descriptor"),
    (7, "unallocated space descriptor"),
    (8, "terminating descriptor"),
    (9, "logical volume integrity descriptor"),
    (256, "file set descriptor"),
    (257, "file identifier descriptor"),
    (258, "allocation extent descriptor"),
    (259, "indirect entry"),
    (260, "terminal entry"),
    (261, "file entry"),
    (262, "extended attribute header descriptor"),
    (263, "unallocated space entry"),
    (264, "space bitmap descriptor"),
    (265, "partition integrity entry"),
    (266, "extended file entry"),
];

const FILE_TYPES: EnumTable = &[
    (0, "unspecified"),
    (1, "unallocated space entry"),
    (2, "partition integrity entry"),
    (3, "indirect entry"),
    (4, "directory"),
    (5, "file"),
    (6, "block device"),
    (7, "character device"),
    (8, "extended attributes"),
    (9, "FIFO"),
    (10, "socket"),
    (11, "terminal entry"),
    (12, "symbolic link"),
    (13, "stream directory"),
    (248, "virtual allocation table"),
    (249, "real-time file"),
    (250, "metadata file"),
    (251, "metadata mirror file"),
    (252, "metadata bitmap file"),
];

const ICB_FLAGS: FlagTable = &[
    field(0x7, 0, "SHORT_AD"),
    field(0x7, 1, "LONG_AD"),
    field(0x7, 2, "EXTENDED_AD"),
    field(0x7, 3, "EMBEDDED"),
    flag(0x8, "SORTED"),
    flag(0x10, "NON_RELOCATABLE"),
    flag(0x20, "ARCHIVE"),
    flag(0x40, "SETUID"),
    flag(0x80, "SETGID"),
    flag(0x100, "STICKY"),
    flag(0x200, "CONTIGUOUS"),
    flag(0x400, "SYSTEM"),
    flag(0x800, "TRANSFORMED"),
    flag(0x1000, "MULTI_VERSIONS"),
    flag(0x2000, "STREAM"),
];

const FID_FLAGS: FlagTable = &[
    flag(0x1, "HIDDEN"),
    flag(0x2, "DIRECTORY"),
    flag(0x4, "DELETED"),
    flag(0x8, "PARENT"),
    flag(0x10, "METADATA"),
];

const ACCESS_TYPES: EnumTable = &[
    (0, "pseudo-overwritable"),
    (1, "read-only"),
    (2, "write-once"),
    (3, "rewritable"),
    (4, "overwritable"),
];

const PVD_FLAGS: FlagTable = &[flag(1, "COMMON_VOLUME_SET_IDENTIFIER")];
const PD_FLAGS: FlagTable = &[flag(1, "ALLOCATED")];
const METADATA_FLAGS: FlagTable = &[flag(1, "DUPLICATE_METADATA")];

const INTEGRITY_TYPES: EnumTable = &[(0, "open"), (1, "close")];

const EA_TYPES: EnumTable = &[
    (1, "character set information"),
    (3, "alternate permissions"),
    (5, "file times"),
    (6, "information times"),
    (12, "device specification"),
    (2048, "implementation use"),
    (65536, "application use"),
];

const OS_CLASSES: EnumTable = &[
    (0, "undefined"),
    (1, "DOS"),
    (2, "OS/2"),
    (3, "Macintosh OS"),
    (4, "UNIX"),
    (5, "Windows 9x"),
    (6, "Windows NT"),
    (7, "OS/400"),
    (8, "BeOS"),
    (9, "Windows CE"),
];

// ---------------------------------------------------------------------------
// Basic types

/// OSTA compressed Unicode (CS0): a compression ID, then 8- or 16-bit units.
fn cs0(b: &[u8]) -> String {
    let rest = b.get(1..).unwrap_or_default();
    match b.first() {
        None => String::new(),
        Some(8 | 254) => crate::text::latin1(rest),
        Some(16 | 255) => crate::text::utf16(rest, Endian::Big),
        Some(_) => String::from_utf8_lossy(rest).into_owned(),
    }
}

/// A `dstring`: CS0 text padded to the field, its length in the last byte.
fn dstring(b: &[u8]) -> String {
    let Some((&len, body)) = b.split_last() else {
        return String::new();
    };
    let s = cs0(body.get(..usize::from(len)).unwrap_or(body));
    s.trim_end_matches('\0').to_owned()
}

fn regid_id(b: &[u8]) -> String {
    crate::text::latin1(b.get(1..24).unwrap_or_default())
        .trim_end_matches(['\0', ' '])
        .to_owned()
}

/// A UDF revision (BCD-ish `0x0150`) as `1.50`.
fn revision(rev: u16) -> String {
    format!("{:x}.{:02x}", rev >> 8, rev & 0xff)
}

/// What a regid's suffix says: the UDF revision of domain and UDF entity
/// identifiers, the operating system of implementation identifiers.
fn regid_suffix(b: &[u8]) -> Option<String> {
    let id = regid_id(b);
    let suffix = b.get(24..32)?;
    if id.is_empty() || id.starts_with('+') {
        return None;
    }
    if id == "*OSTA UDF Compliant" || id.starts_with("*UDF ") {
        let rev = u16_le(suffix, 0)?;
        return (rev != 0).then(|| format!("UDF {}", revision(rev)));
    }
    let class = *suffix.first()?;
    let os = *suffix.get(1)?;
    let name = crate::value::lookup(OS_CLASSES, class.into())?;
    let detail = match (class, os) {
        (3, 1) => Some("Mac OS X"),
        (4, 1) => Some("AIX"),
        (4, 2) => Some("Solaris"),
        (4, 3) => Some("HP-UX"),
        (4, 4) => Some("IRIX"),
        (4, 5) => Some("Linux"),
        (4, 6) => Some("MkLinux"),
        (4, 7) => Some("FreeBSD"),
        (4, 8) => Some("NetBSD"),
        _ => None,
    };
    (class != 0).then(|| match detail {
        Some(d) => format!("{name} ({d})"),
        None => name.to_owned(),
    })
}

/// A 12-byte timestamp as Unix seconds and its recorded UTC offset (in
/// minutes), or `None` if it is all zeros.
fn timestamp(b: &[u8]) -> Option<(i64, Option<i16>)> {
    let tt = u16_le(b, 0)?;
    let year = u16_le(b, 2)?.cast_signed();
    let get = |i: usize| b.get(i).copied().map(u32::from);
    let (month, day) = (get(4)?, get(5)?);
    if year == 0 && month == 0 && day == 0 {
        return None;
    }
    let raw = tt & 0x0fff;
    let tz = if raw & 0x800 != 0 {
        raw.cast_signed().saturating_sub(0x1000)
    } else {
        raw.cast_signed()
    };
    let tz = (tt >> 12 == 1 && tz != -2047).then_some(tz);
    let local = civil_to_unix(year.into(), month, day, get(6)?, get(7)?, get(8)?);
    Some((
        local.saturating_sub(i64::from(tz.unwrap_or(0)).saturating_mul(60)),
        tz,
    ))
}

fn time_text(t: i64) -> String {
    crate::render::value(&Value::Timestamp { unix_seconds: t })
}

/// Problems with a descriptor tag: checksum, CRC, recorded location.
fn verify(b: &[u8], location: Option<u32>) -> Option<Diagnostic> {
    let head = b.get(..16)?;
    let sum = head
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != 4)
        .fold(0u8, |a, (_, &v)| a.wrapping_add(v));
    if head.get(4) != Some(&sum) {
        return Some(Diagnostic::warning("tag checksum mismatch"));
    }
    let crc_len = usize::from(u16_le(head, 10)?);
    if let Some(body) = b.get(16..16usize.saturating_add(crc_len))
        && u16_le(head, 8) != Some(crc16_xmodem(body))
    {
        return Some(Diagnostic::warning("descriptor CRC mismatch"));
    }
    let recorded = u32_le(head, 12)?;
    match location {
        Some(l) if l != recorded => Some(Diagnostic::warning(format!(
            "tag says block {recorded}, found at block {l}"
        ))),
        _ => None,
    }
}

/// Whether a block starts with a plausible tag (id in range, checksum ok).
fn tag_ok(b: &[u8]) -> bool {
    let Some(head) = b.get(..16) else {
        return false;
    };
    let sum = head
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != 4)
        .fold(0u8, |a, (_, &v)| a.wrapping_add(v));
    head.get(4) == Some(&sum) && head.iter().any(|&v| v != 0)
}

/// A `long_ad` (or the address part of an `ext_ad`): extent length with
/// the type in the top two bits, block, partition reference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LongAd {
    len: u32,
    lbn: u32,
    part: u16,
}

impl LongAd {
    fn parse(b: &[u8]) -> Option<Self> {
        Some(LongAd {
            len: u32_le(b, 0)?,
            lbn: u32_le(b, 4)?,
            part: u16_le(b, 8)?,
        })
    }

    fn size(self) -> u64 {
        (self.len & 0x3fff_ffff).into()
    }

    fn kind(self) -> u8 {
        u8::try_from(self.len >> 30).unwrap_or(0)
    }

    fn id(self) -> u64 {
        u64::from(self.part) << 32 | u64::from(self.lbn)
    }
}

fn ad_summary(ad: LongAd, with_part: bool) -> String {
    let mut s = format!("{} at block {}", human_size(ad.size()), ad.lbn);
    if with_part {
        s = format!("{s} of partition {}", ad.part);
    }
    match ad.kind() {
        1 => format!("{s}, allocated, not recorded"),
        2 => format!("{s}, not allocated"),
        3 => format!("{s}, continues the descriptors"),
        _ => s,
    }
}

/// UDF permission bits (`other` 0–4, `group` 5–9, `owner` 10–14; each
/// execute, write, read, change attributes, delete) as `rwxr-xr-x`.
fn perm_text(p: u32) -> String {
    let mut s = String::new();
    for shift in [10u32, 5, 0] {
        let bits = p >> shift;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}

fn kind_char(file_type: u8) -> char {
    match file_type {
        4 | 13 => 'd',
        12 => 'l',
        6 => 'b',
        7 => 'c',
        9 => 'p',
        10 => 's',
        _ => '-',
    }
}

// ---------------------------------------------------------------------------
// Field helpers

fn tag(f: &mut Fields<'_>) -> Result<u16> {
    let at = to_usize(f.pos());
    let id = u16_le(&f.block().data, at).unwrap_or(0);
    let span = f.peek_span(16);
    let mut node = struct_node("Descriptor tag", span, LE, (), tag_layout);
    if let Some(name) = crate::value::lookup(TAG_IDS, id.into()) {
        node = node.summary(name);
    }
    f.node(node);
    f.skip(16);
    Ok(id)
}

fn tag_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let head = f.block().data.clone();
    f.u16("Tag identifier").enumeration(TAG_IDS).emit()?;
    f.u16("Descriptor version").emit()?;
    f.u8("Tag checksum")
        .hex()
        .check(|&c| {
            let sum = head
                .iter()
                .take(16)
                .enumerate()
                .filter(|&(i, _)| i != 4)
                .fold(0u8, |a, (_, &v)| a.wrapping_add(v));
            (sum != c).then(|| Diagnostic::warning(format!("computed {sum:#04x}")))
        })
        .emit()?;
    f.u8("Reserved").emit()?;
    f.u16("Tag serial number").emit()?;
    f.u16("Descriptor CRC").hex().emit()?;
    f.u16("Descriptor CRC length").emit()?;
    f.u32("Tag location")
        .desc("Block this descriptor was written to (partition-relative inside a partition)")
        .emit()?;
    Ok(())
}

fn regid(f: &mut Fields<'_>, name: &'static str) -> Result<String> {
    f.bytes(name, 32)
        .with(|b, n| {
            let n = n.value(text(regid_id(b)));
            match regid_suffix(b) {
                Some(s) => n.summary(s),
                None => n,
            }
        })
        .map(|b| regid_id(&b))
        .emit()
}

fn dstring_field(f: &mut Fields<'_>, name: &'static str, len: u64) -> Result<String> {
    f.bytes(name, len)
        .with(|b, n| n.value(text(dstring(b))))
        .map(|b| dstring(&b))
        .emit()
}

fn charspec(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.bytes(name, 64)
        .with(|b, n| {
            let info = crate::text::latin1(b.get(1..).unwrap_or_default())
                .trim_end_matches('\0')
                .to_owned();
            n.value(text(info))
                .summary(format!("CS{}", b.first().copied().unwrap_or(0)))
        })
        .emit()?;
    Ok(())
}

fn time_field(f: &mut Fields<'_>, name: &'static str) -> Result<Option<i64>> {
    f.bytes(name, 12)
        .with(|b, n| match timestamp(b) {
            Some((t, tz)) => {
                let n = n.value(Value::Timestamp { unix_seconds: t });
                match tz {
                    Some(m) => n.summary(format!(
                        "recorded as local time, UTC{}{:02}:{:02}",
                        if m < 0 { '-' } else { '+' },
                        m.unsigned_abs() / 60,
                        m.unsigned_abs() % 60
                    )),
                    None => n,
                }
            }
            None => n.summary("not set"),
        })
        .map(|b| timestamp(&b).map(|t| t.0))
        .emit()
}

fn extent_ad(f: &mut Fields<'_>, name: &'static str) -> Result<(u32, u32)> {
    f.bytes(name, 8)
        .with(|b, n| {
            let len = u32_le(b, 0).unwrap_or(0);
            let loc = u32_le(b, 4).unwrap_or(0);
            if len == 0 {
                n.summary("none")
            } else {
                n.value(uint(loc.into()))
                    .summary(format!("{} at block {loc}", human_size(len.into())))
            }
        })
        .map(|b| (u32_le(&b, 4).unwrap_or(0), u32_le(&b, 0).unwrap_or(0)))
        .emit()
}

fn long_ad(f: &mut Fields<'_>, name: &'static str) -> Result<LongAd> {
    f.bytes(name, 16)
        .with(|b, n| match LongAd::parse(b) {
            Some(ad) if ad.size() > 0 => n.value(uint(ad.lbn.into())).summary(ad_summary(ad, true)),
            _ => n.summary("none"),
        })
        .map(|b| LongAd::parse(&b).unwrap_or_default())
        .emit()
}

fn short_ad(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.bytes(name, 8)
        .with(|b, n| {
            let ad = LongAd {
                len: u32_le(b, 0).unwrap_or(0),
                lbn: u32_le(b, 4).unwrap_or(0),
                part: 0,
            };
            if ad.size() == 0 {
                n.summary("none")
            } else {
                n.value(uint(ad.lbn.into())).summary(ad_summary(ad, false))
            }
        })
        .emit()?;
    Ok(())
}

fn revision_field(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.u16(name)
        .hex()
        .with(|&r, n| n.summary(format!("UDF {}", revision(r))))
        .emit()?;
    Ok(())
}

fn rest(f: &mut Fields<'_>, name: &'static str, len: u64) -> Result<()> {
    let len = len.min(f.remaining());
    if len > 0 {
        f.bytes(name, len).emit()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Descriptor layouts

fn avdp_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    extent_ad(f, "Main volume descriptor sequence")?;
    extent_ad(f, "Reserve volume descriptor sequence")?;
    Ok(())
}

fn pvd_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    f.u32("Volume descriptor sequence number").emit()?;
    f.u32("Primary volume descriptor number").emit()?;
    dstring_field(f, "Volume identifier", 32)?;
    f.u16("Volume sequence number").emit()?;
    f.u16("Maximum volume sequence number").emit()?;
    f.u16("Interchange level").emit()?;
    f.u16("Maximum interchange level").emit()?;
    f.u32("Character set list").hex().emit()?;
    f.u32("Maximum character set list").hex().emit()?;
    dstring_field(f, "Volume set identifier", 128)?;
    charspec(f, "Descriptor character set")?;
    charspec(f, "Explanatory character set")?;
    extent_ad(f, "Volume abstract")?;
    extent_ad(f, "Volume copyright notice")?;
    regid(f, "Application identifier")?;
    time_field(f, "Recording time")?;
    regid(f, "Implementation identifier")?;
    f.bytes("Implementation use", 64).emit()?;
    f.u32("Predecessor volume descriptor sequence location")
        .emit()?;
    f.u16("Flags").flags(PVD_FLAGS).emit()?;
    Ok(())
}

fn vdp_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    f.u32("Volume descriptor sequence number").emit()?;
    extent_ad(f, "Next volume descriptor sequence")?;
    Ok(())
}

fn iuvd_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    f.u32("Volume descriptor sequence number").emit()?;
    let id = regid(f, "Implementation identifier")?;
    if id == "*UDF LV Info" {
        charspec(f, "LVI character set")?;
        dstring_field(f, "Logical volume identifier", 128)?;
        dstring_field(f, "LV info 1", 36)?;
        dstring_field(f, "LV info 2", 36)?;
        dstring_field(f, "LV info 3", 36)?;
        regid(f, "Implementation identifier")?;
        f.bytes("Implementation use", 128).emit()?;
    } else {
        f.bytes("Implementation use", 460).emit()?;
    }
    Ok(())
}

fn pd_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    f.u32("Volume descriptor sequence number").emit()?;
    f.u16("Partition flags").flags(PD_FLAGS).emit()?;
    f.u16("Partition number").emit()?;
    let contents = regid(f, "Partition contents")?;
    let span = f.peek_span(128);
    if contents.starts_with("+NSR") {
        f.node(struct_node(
            "Partition header descriptor",
            span,
            LE,
            (),
            phd_layout,
        ));
    } else {
        f.node(Node::new("Partition contents use").span(span));
    }
    f.skip(128);
    f.u32("Access type").enumeration(ACCESS_TYPES).emit()?;
    f.u32("Partition starting location").emit()?;
    f.u32("Partition length")
        .with(|&n, node| node.summary(count(n.into(), "block", "blocks")))
        .emit()?;
    regid(f, "Implementation identifier")?;
    f.bytes("Implementation use", 128).emit()?;
    Ok(())
}

fn phd_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    short_ad(f, "Unallocated space table")?;
    short_ad(f, "Unallocated space bitmap")?;
    short_ad(f, "Partition integrity table")?;
    short_ad(f, "Freed space table")?;
    short_ad(f, "Freed space bitmap")?;
    Ok(())
}

fn lvd_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    f.u32("Volume descriptor sequence number").emit()?;
    charspec(f, "Descriptor character set")?;
    dstring_field(f, "Logical volume identifier", 128)?;
    f.u32("Logical block size").emit()?;
    regid(f, "Domain identifier")?;
    long_ad(f, "File set descriptor location")?;
    let table_len = f.u32("Map table length").emit()?;
    let maps = f.u32("Number of partition maps").emit()?;
    regid(f, "Implementation identifier")?;
    f.bytes("Implementation use", 128).emit()?;
    extent_ad(f, "Integrity sequence extent")?;
    let span = f.peek_span(u64::from(table_len).min(f.remaining()));
    f.node(
        struct_node("Partition maps", span, LE, maps, maps_layout).summary(count(
            maps.into(),
            "map",
            "maps",
        )),
    );
    Ok(())
}

fn maps_layout(f: &mut Fields<'_>, n: &u32) -> Result<()> {
    let data = f.block().data.clone();
    for i in 0..*n {
        let at = to_usize(f.pos());
        let (Some(&kind), Some(&len)) = (data.get(at), data.get(at.saturating_add(1))) else {
            break;
        };
        if len < 2 || MAX_MAPS <= to_usize(i.into()) {
            break;
        }
        let span = f.peek_span(len.into());
        let body = data
            .get(at..at.saturating_add(len.into()))
            .unwrap_or_default();
        let summary = match kind {
            1 => format!(
                "type 1, partition {}",
                u16_le(body, 4).map_or("?".to_owned(), |p| p.to_string())
            ),
            2 => format!(
                "{}, partition {}",
                regid_id(body.get(4..36).unwrap_or_default()),
                u16_le(body, 38).map_or("?".to_owned(), |p| p.to_string())
            ),
            k => format!("type {k}"),
        };
        f.node(
            struct_node(format!("Partition map {i}"), span, LE, (), map_layout).summary(summary),
        );
        f.skip(len.into());
    }
    Ok(())
}

fn map_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let kind = f.u8("Partition map type").emit()?;
    let len = f.u8("Partition map length").emit()?;
    match kind {
        1 => {
            f.u16("Volume sequence number").emit()?;
            f.u16("Partition number").emit()?;
        }
        2 => {
            f.bytes("Reserved", 2).emit()?;
            let id = regid(f, "Partition type identifier")?;
            f.u16("Volume sequence number").emit()?;
            f.u16("Partition number").emit()?;
            match id.as_str() {
                "*UDF Sparable Partition" => {
                    f.u16("Packet length")
                        .with(|&n, node| node.summary(count(n.into(), "block", "blocks")))
                        .emit()?;
                    let tables = f.u8("Number of sparing tables").emit()?;
                    f.u8("Reserved").emit()?;
                    f.u32("Size of each sparing table").emit()?;
                    for _ in 0..tables {
                        if f.remaining() < 4 {
                            break;
                        }
                        f.u32("Sparing table location").emit()?;
                    }
                }
                "*UDF Metadata Partition" => {
                    f.u32("Metadata file location").emit()?;
                    f.u32("Metadata mirror file location").emit()?;
                    f.u32("Metadata bitmap file location").emit()?;
                    f.u32("Allocation unit size")
                        .with(|&n, node| node.summary(count(n.into(), "block", "blocks")))
                        .emit()?;
                    f.u16("Alignment unit size").emit()?;
                    f.u8("Flags").flags(METADATA_FLAGS).emit()?;
                }
                _ => {}
            }
            rest(f, "Reserved", u64::from(len).saturating_sub(f.pos()))?;
        }
        _ => rest(f, "Data", u64::from(len).saturating_sub(2))?,
    }
    Ok(())
}

fn usd_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    f.u32("Volume descriptor sequence number").emit()?;
    let n = f.u32("Number of allocation descriptors").emit()?;
    for _ in 0..n {
        if f.remaining() < 8 {
            break;
        }
        extent_ad(f, "Unallocated extent")?;
    }
    Ok(())
}

fn plain_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    Ok(())
}

fn lvid_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    time_field(f, "Recording time")?;
    f.u32("Integrity type")
        .enumeration(INTEGRITY_TYPES)
        .emit()?;
    extent_ad(f, "Next integrity extent")?;
    f.u64("Next unique ID").emit()?;
    f.bytes("Reserved", 24).emit()?;
    let n = f.u32("Number of partitions").emit()?;
    let iu = f.u32("Length of implementation use").emit()?;
    let n = u64::from(n).min(f.remaining() / 8);
    for _ in 0..n {
        f.u32("Free space")
            .with(|&v, node| node.summary(count(v.into(), "block", "blocks")))
            .emit()?;
    }
    for _ in 0..n {
        f.u32("Partition size")
            .with(|&v, node| node.summary(count(v.into(), "block", "blocks")))
            .emit()?;
    }
    if iu >= 46 {
        regid(f, "Implementation identifier")?;
        f.u32("Number of files").emit()?;
        f.u32("Number of directories").emit()?;
        revision_field(f, "Minimum UDF read revision")?;
        revision_field(f, "Minimum UDF write revision")?;
        revision_field(f, "Maximum UDF write revision")?;
        rest(f, "Implementation use", u64::from(iu).saturating_sub(46))?;
    } else {
        rest(f, "Implementation use", iu.into())?;
    }
    Ok(())
}

fn fsd_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    time_field(f, "Recording time")?;
    f.u16("Interchange level").emit()?;
    f.u16("Maximum interchange level").emit()?;
    f.u32("Character set list").hex().emit()?;
    f.u32("Maximum character set list").hex().emit()?;
    f.u32("File set number").emit()?;
    f.u32("File set descriptor number").emit()?;
    charspec(f, "Logical volume identifier character set")?;
    dstring_field(f, "Logical volume identifier", 128)?;
    charspec(f, "File set character set")?;
    dstring_field(f, "File set identifier", 32)?;
    dstring_field(f, "Copyright file identifier", 32)?;
    dstring_field(f, "Abstract file identifier", 32)?;
    long_ad(f, "Root directory ICB")?;
    regid(f, "Domain identifier")?;
    long_ad(f, "Next extent")?;
    long_ad(f, "System stream directory ICB")?;
    Ok(())
}

fn sparing_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    regid(f, "Sparing identifier")?;
    let n = f.u16("Reallocation table length").emit()?;
    f.u16("Reserved").emit()?;
    f.u32("Sequence number").emit()?;
    for _ in 0..n {
        if f.remaining() < 8 {
            break;
        }
        f.bytes("Map entry", 8)
            .with(|b, node| {
                let orig = u32_le(b, 0).unwrap_or(0);
                let mapped = u32_le(b, 4).unwrap_or(0);
                node.summary(match orig {
                    0xffff_ffff => format!("available: block {mapped}"),
                    0xffff_fff0 => format!("defective: block {mapped}"),
                    o => format!("packet at {o} moved to block {mapped}"),
                })
            })
            .emit()?;
    }
    Ok(())
}

fn fid_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    f.u16("File version number").emit()?;
    f.u8("File characteristics").flags(FID_FLAGS).emit()?;
    let l_fi = f.u8("Length of file identifier").emit()?;
    long_ad(f, "ICB")?;
    let l_iu = f.u16("Length of implementation use").emit()?;
    if l_iu > 0 {
        f.bytes("Implementation use", l_iu.into())
            .with(|b, n| {
                if b.len() >= 32 {
                    n.summary(regid_id(b))
                } else {
                    n
                }
            })
            .emit()?;
    }
    if l_fi > 0 {
        f.bytes("File identifier", l_fi.into())
            .with(|b, n| n.value(text(cs0(b))))
            .emit()?;
    }
    rest(f, "Padding", f.remaining())?;
    Ok(())
}

fn icb_tag_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Prior recorded number of direct entries").emit()?;
    f.u16("Strategy type").emit()?;
    f.u16("Strategy parameter").emit()?;
    f.u16("Maximum number of entries").emit()?;
    f.u8("Reserved").emit()?;
    f.u8("File type").enumeration(FILE_TYPES).emit()?;
    f.bytes("Parent ICB location", 6)
        .with(|b, n| {
            n.value(uint(u32_le(b, 0).unwrap_or(0).into()))
                .summary(format!("partition {}", u16_le(b, 4).unwrap_or(0)))
        })
        .emit()?;
    f.u16("Flags").flags(ICB_FLAGS).emit()?;
    Ok(())
}

fn fe_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let data = f.block().data.clone();
    let efe = tag(f)? == 266;
    let ad_type = u16_le(&data, 34).unwrap_or(0) & 7;
    let file_type = data.get(27).copied().unwrap_or(0);
    let span = f.peek_span(20);
    let mut icb = struct_node("ICB tag", span, LE, (), icb_tag_layout);
    if let Some(name) = crate::value::lookup(FILE_TYPES, file_type.into()) {
        icb = icb.summary(name);
    }
    f.node(icb);
    f.skip(20);
    f.u32("Owner").emit()?;
    f.u32("Group").emit()?;
    f.u32("Permissions")
        .hex()
        .with(|&p, n| {
            let mut s = format!("{}{}", kind_char(file_type), perm_text(p));
            if p & 0x4210 != 0 {
                s.push_str(", may delete");
            }
            n.summary(s)
        })
        .emit()?;
    f.u16("File link count").emit()?;
    f.u8("Record format").emit()?;
    f.u8("Record display attributes").emit()?;
    f.u32("Record length").emit()?;
    f.u64("Information length")
        .with(|&v, n| n.summary(human_size(v)))
        .emit()?;
    if efe {
        f.u64("Object size")
            .with(|&v, n| n.summary(human_size(v)))
            .emit()?;
    }
    f.u64("Logical blocks recorded").emit()?;
    time_field(f, "Access time")?;
    time_field(f, "Modification time")?;
    if efe {
        time_field(f, "Creation time")?;
    }
    time_field(f, "Attribute time")?;
    f.u32("Checkpoint").emit()?;
    if efe {
        f.u32("Reserved").emit()?;
    }
    long_ad(f, "Extended attribute ICB")?;
    if efe {
        long_ad(f, "Stream directory ICB")?;
    }
    regid(f, "Implementation identifier")?;
    f.u64("Unique ID").emit()?;
    let l_ea = f.u32("Length of extended attributes").emit()?;
    let l_ad = f.u32("Length of allocation descriptors").emit()?;
    let l_ea = u64::from(l_ea).min(f.remaining());
    if l_ea > 0 {
        let span = f.peek_span(l_ea);
        f.node(
            struct_node("Extended attributes", span, LE, (), ea_layout).summary(human_size(l_ea)),
        );
        f.skip(l_ea);
    }
    let l_ad = u64::from(l_ad).min(f.remaining());
    if l_ad > 0 {
        let span = f.peek_span(l_ad);
        if ad_type == 3 {
            f.node(
                Node::new("Embedded data")
                    .span(span)
                    .summary(human_size(l_ad)),
            );
        } else {
            f.node(struct_node(
                "Allocation descriptors",
                span,
                LE,
                ad_type,
                ads_layout,
            ));
        }
    }
    Ok(())
}

fn ad_size(ad_type: u16) -> Option<usize> {
    match ad_type {
        0 => Some(8),
        1 => Some(16),
        2 => Some(20),
        _ => None,
    }
}

/// An allocation descriptor of the given kind; short ones get `part`.
fn parse_ad(b: &[u8], ad_type: u16, part: u16) -> Option<LongAd> {
    match ad_type {
        0 => Some(LongAd {
            len: u32_le(b, 0)?,
            lbn: u32_le(b, 4)?,
            part,
        }),
        1 => LongAd::parse(b),
        2 => Some(LongAd {
            len: u32_le(b, 0)?,
            lbn: u32_le(b, 12)?,
            part: u16_le(b, 16)?,
        }),
        _ => None,
    }
}

fn ads_layout(f: &mut Fields<'_>, ad_type: &u16) -> Result<()> {
    let Some(size) = ad_size(*ad_type) else {
        return Ok(());
    };
    let data = f.block().data.clone();
    let mut i = 0u64;
    while f.remaining() >= to_u64(size) {
        let at = to_usize(f.pos());
        let raw = data.get(at..at.saturating_add(size)).unwrap_or_default();
        let span = f.peek_span(to_u64(size));
        let Some(ad) = parse_ad(raw, *ad_type, 0) else {
            break;
        };
        if ad.size() == 0 {
            f.node(Node::new("Terminator").span(span));
            break;
        }
        let mut node = Node::new(format!("Extent {i}"))
            .span(span)
            .value(uint(ad.lbn.into()))
            .summary(ad_summary(ad, *ad_type != 0));
        if *ad_type == 2 {
            node = node.desc(format!(
                "recorded {}, information {}",
                human_size(u32_le(raw, 4).unwrap_or(0).into()),
                human_size(u32_le(raw, 8).unwrap_or(0).into())
            ));
        }
        f.node(node);
        f.skip(to_u64(size));
        i = i.saturating_add(1);
    }
    Ok(())
}

fn aed_layout(f: &mut Fields<'_>, ad_type: &u16) -> Result<()> {
    tag(f)?;
    f.u32("Previous allocation extent location").emit()?;
    let len = f.u32("Length of allocation descriptors").emit()?;
    let span = f.peek_span(u64::from(len).min(f.remaining()));
    f.node(struct_node(
        "Allocation descriptors",
        span,
        LE,
        *ad_type,
        ads_layout,
    ));
    Ok(())
}

fn ea_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let data = f.block().data.clone();
    if u16_le(&data, 0) == Some(262) {
        let span = f.peek_span(24);
        f.node(struct_node(
            "Extended attribute header descriptor",
            span,
            LE,
            (),
            ea_header_layout,
        ));
        f.skip(24);
    }
    while f.remaining() >= 12 {
        let at = to_usize(f.pos());
        let kind = u32_le(&data, at).unwrap_or(0);
        let len = u64::from(u32_le(&data, at.saturating_add(8)).unwrap_or(0));
        if len < 12 || len > f.remaining() {
            if data.get(at..).is_some_and(|r| r.iter().any(|&b| b != 0)) {
                f.node(
                    Node::new("Unparsed")
                        .span(f.peek_span(f.remaining()))
                        .diag(Diagnostic::malformed("bad extended attribute length")),
                );
            }
            break;
        }
        let span = f.peek_span(len);
        let name = crate::value::lookup(EA_TYPES, kind.into())
            .map_or_else(|| format!("Attribute type {kind}"), capitalize);
        let mut node = struct_node(name, span, LE, (), ea_one_layout);
        if matches!(kind, 2048 | 65536) {
            let id = regid_id(
                data.get(at.saturating_add(16)..at.saturating_add(48))
                    .unwrap_or_default(),
            );
            node = node.summary(id);
        }
        f.node(node);
        f.skip(len);
    }
    Ok(())
}

fn ea_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    tag(f)?;
    f.u32("Implementation attributes location").emit()?;
    f.u32("Application attributes location").emit()?;
    Ok(())
}

fn ea_one_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let kind = f.u32("Attribute type").enumeration(EA_TYPES).emit()?;
    f.u8("Attribute subtype").emit()?;
    f.bytes("Reserved", 3).emit()?;
    let len = f.u32("Attribute length").emit()?;
    match kind {
        2048 | 65536 => {
            let iu = f.u32("Implementation use length").emit()?;
            regid(f, "Implementation identifier")?;
            rest(f, "Implementation use", iu.into())?;
        }
        5 | 6 => {
            let dl = f.u32("Data length").emit()?;
            f.u32("Existence flags").hex().emit()?;
            for _ in 0..dl / 12 {
                if f.remaining() < 12 {
                    break;
                }
                time_field(f, "Time")?;
            }
        }
        12 => {
            let iu = f.u32("Implementation use length").emit()?;
            f.u32("Major device").emit()?;
            f.u32("Minor device").emit()?;
            rest(f, "Implementation use", iu.into())?;
        }
        _ => rest(f, "Data", u64::from(len).saturating_sub(12))?,
    }
    Ok(())
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

fn descriptor_node(id: u16, span: Span) -> Node {
    let name = crate::value::lookup(TAG_IDS, id.into())
        .map_or_else(|| format!("Descriptor {id}"), capitalize);
    let layout: crate::fields::Layout<(), ()> = match id {
        0 => sparing_layout,
        1 => pvd_layout,
        2 => avdp_layout,
        3 => vdp_layout,
        4 => iuvd_layout,
        5 => pd_layout,
        6 => lvd_layout,
        7 => usd_layout,
        9 => lvid_layout,
        256 => fsd_layout,
        257 => fid_layout,
        261 | 266 => fe_layout,
        _ => plain_layout,
    };
    struct_node(name, span, LE, (), layout)
}

// ---------------------------------------------------------------------------
// The volume

#[derive(Clone, Debug)]
enum Map {
    Physical {
        number: u16,
        start: u64,
        len: u64,
    },
    Sparable {
        number: u16,
        start: u64,
        len: u64,
        packet: u64,
        /// (original partition-relative packet, mapped absolute block).
        spared: Vec<(u32, u32)>,
    },
    Metadata {
        number: u16,
        data: Option<Span>,
        mirror: bool,
    },
    Virtual {
        number: u16,
        start: u64,
        table: Option<Arc<Vec<u32>>>,
    },
    Unknown {
        what: String,
    },
}

impl Map {
    fn summary(&self) -> String {
        match self {
            Map::Physical { number, len, .. } => {
                format!("partition {number}, {}", count(*len, "block", "blocks"))
            }
            Map::Sparable { number, spared, .. } => format!(
                "sparable partition {number}, {}",
                count(to_u64(spared.len()), "spared packet", "spared packets")
            ),
            Map::Metadata {
                number,
                data,
                mirror,
            } => match (data, mirror) {
                (None, _) => format!("metadata partition on {number}, unreadable"),
                (Some(d), false) => {
                    format!("metadata partition on {number}, {}", human_size(d.len))
                }
                (Some(d), true) => format!(
                    "metadata partition on {number} (from the mirror), {}",
                    human_size(d.len)
                ),
            },
            Map::Virtual { number, table, .. } => match table {
                Some(t) => format!(
                    "virtual partition on {number}, {}",
                    count(to_u64(t.len()), "VAT entry", "VAT entries")
                ),
                None => format!("virtual partition on {number}, no VAT found"),
            },
            Map::Unknown { what } => what.clone(),
        }
    }
}

/// A parsed UDF logical volume.
#[derive(Debug)]
pub struct Vol {
    input: Input,
    bs: u64,
    avdp: Span,
    main: (u32, u32),
    reserve: (u32, u32),
    label: String,
    revision: Option<u16>,
    maps: Vec<Map>,
    fsd: Option<LongAd>,
    integrity: (u32, u32),
    vat: Option<Span>,
    problems: Vec<Diagnostic>,
}

impl Vol {
    /// "UDF 1.50" (or plain "UDF" when the domain revision is unknown).
    pub fn version(&self) -> String {
        match self.revision {
            Some(r) => format!("UDF {}", revision(r)),
            None => "UDF".to_owned(),
        }
    }

    fn file(&self) -> Span {
        self.input.span
    }

    fn phys(&self, block: u64, blocks: u64) -> Span {
        self.file().sub(
            block.saturating_mul(self.bs),
            blocks.saturating_mul(self.bs),
        )
    }

    /// The bytes of `len` bytes at `lbn` of partition reference `part`.
    fn extent(&self, part: u16, lbn: u32, len: u64) -> Option<Vec<Span>> {
        let lbn = u64::from(lbn);
        let blocks = len.div_ceil(self.bs.max(1));
        match self.maps.get(usize::from(part))? {
            Map::Physical { start, .. } => Some(vec![
                self.file()
                    .sub(start.saturating_add(lbn).saturating_mul(self.bs), len),
            ]),
            Map::Sparable {
                start,
                packet,
                spared,
                ..
            } => {
                let mut out = Vec::new();
                let mut cur = lbn;
                let end = lbn.saturating_add(blocks);
                // The table is sorted: skip the packets wholly before `lbn`
                // and stop at the first one past the extent.
                let first =
                    spared.partition_point(|&(o, _)| u64::from(o).saturating_add(*packet) <= lbn);
                for &(orig, mapped) in spared.get(first..).unwrap_or_default() {
                    let o = u64::from(orig);
                    let pe = o.saturating_add(*packet);
                    if o >= end {
                        break;
                    }
                    if pe <= cur {
                        continue;
                    }
                    if o > cur {
                        out.push(self.phys(start.saturating_add(cur), o.saturating_sub(cur)));
                        cur = o;
                    }
                    let stop = pe.min(end);
                    out.push(self.phys(
                        u64::from(mapped).saturating_add(cur.saturating_sub(o)),
                        stop.saturating_sub(cur),
                    ));
                    cur = stop;
                }
                if cur < end {
                    out.push(self.phys(start.saturating_add(cur), end.saturating_sub(cur)));
                }
                Some(coalesce(out, len))
            }
            Map::Metadata { data: Some(d), .. } => {
                Some(vec![d.sub(lbn.saturating_mul(self.bs), len)])
            }
            Map::Virtual {
                start,
                table: Some(t),
                ..
            } => {
                let mut out: Vec<Span> = Vec::new();
                for i in 0..blocks {
                    let Some(&p) = usize::try_from(lbn.saturating_add(i))
                        .ok()
                        .and_then(|j| t.get(j))
                    else {
                        break;
                    };
                    out.push(self.phys(start.saturating_add(p.into()), 1));
                }
                Some(coalesce(out, len))
            }
            _ => None,
        }
    }

    /// The span of the block at `lbn` of partition reference `part`.
    fn block(&self, part: u16, lbn: u32) -> Result<Span> {
        self.extent(part, lbn, self.bs)
            .and_then(|p| p.first().copied())
            .ok_or_else(|| {
                Diagnostic::malformed(format!(
                    "block {lbn} of partition reference {part} cannot be located"
                ))
            })
    }
}

/// Reads a volume descriptor sequence (following volume descriptor
/// pointers) up to its terminator: `(tag id, span, absolute block, bytes)`.
async fn read_sequence(
    cx: &Cx,
    file: Span,
    bs: u64,
    (mut loc, mut len): (u32, u32),
) -> Result<Vec<(u16, Span, u32, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut hops = 0usize;
    'seq: loop {
        let blocks = u64::from(len).div_ceil(bs).min(MAX_DESCRIPTORS);
        for i in 0..blocks {
            if to_u64(out.len()) >= MAX_DESCRIPTORS {
                break 'seq;
            }
            let block = u32::try_from(u64::from(loc).saturating_add(i)).unwrap_or(u32::MAX);
            let span = file.sub(u64::from(block).saturating_mul(bs), bs);
            let data = cx.read_avail(span).await?;
            if !tag_ok(&data) {
                break 'seq;
            }
            let id = u16_le(&data, 0).unwrap_or(0);
            let next = (id == 3).then(|| {
                (
                    u32_le(&data, 24).unwrap_or(0),
                    u32_le(&data, 20).unwrap_or(0),
                )
            });
            out.push((id, span, block, data));
            if id == 8 {
                break 'seq;
            }
            if let Some(n) = next {
                hops = hops.saturating_add(1);
                if hops > MAX_HOPS || n.1 == 0 {
                    break 'seq;
                }
                (loc, len) = n;
                continue 'seq;
            }
        }
        break;
    }
    Ok(out)
}

/// Finds the anchor: block 256 at the usual block sizes, else the last
/// block or 256 before it.
async fn find_anchor(cx: &Cx, file: Span) -> Result<Option<(u64, Span)>> {
    for bs in [2048u64, 512, 1024, 4096] {
        let mut spots = vec![256u64];
        let blocks = file.len.checked_div(bs).unwrap_or(0);
        if blocks > 257 {
            spots.push(blocks.saturating_sub(1));
            spots.push(blocks.saturating_sub(257));
        }
        for at in spots {
            let span = file.sub(at.saturating_mul(bs), 512.min(bs));
            if span.len < 32 {
                continue;
            }
            let head = cx.read_avail(span).await?;
            if u16_le(&head, 0) == Some(2)
                && tag_ok(&head)
                && u32_le(&head, 12).map(u64::from) == Some(at)
            {
                return Ok(Some((bs, file.sub(at.saturating_mul(bs), bs))));
            }
        }
    }
    Ok(None)
}

/// Parses the volume behind `input` (cached per input).
pub async fn load(cx: &Cx, input: Input) -> Result<Option<Arc<Vol>>> {
    if let Some(v) = cx.cached::<Option<Arc<Vol>>>(input.span, "udf-volume") {
        return Ok((*v).clone());
    }
    let vol = load_uncached(cx, input).await?.map(Arc::new);
    cx.cache(input.span, "udf-volume", Arc::new(vol.clone()));
    Ok(vol)
}

async fn load_uncached(cx: &Cx, input: Input) -> Result<Option<Vol>> {
    let file = input.span;
    let Some((bs, avdp)) = find_anchor(cx, file).await? else {
        return Ok(None);
    };
    let head = cx.read_avail(avdp.sub(0, 32)).await?;
    let ext = |at: usize| {
        (
            u32_le(&head, at.saturating_add(4)).unwrap_or(0),
            u32_le(&head, at).unwrap_or(0),
        )
    };
    let (main, reserve) = (ext(16), ext(24));
    let mut vol = Vol {
        input,
        bs,
        avdp,
        main,
        reserve,
        label: String::new(),
        revision: None,
        maps: Vec::new(),
        fsd: None,
        integrity: (0, 0),
        vat: None,
        problems: Vec::new(),
    };
    let mut seq = read_sequence(cx, file, bs, main).await?;
    if !seq.iter().any(|d| d.0 == 6) {
        let reserve_seq = read_sequence(cx, file, bs, reserve).await?;
        if reserve_seq.iter().any(|d| d.0 == 6) {
            vol.problems.push(Diagnostic::warning(
                "main volume descriptor sequence unusable; using the reserve",
            ));
            seq = reserve_seq;
        }
    }
    let mut pvd_label = String::new();
    let mut lvd: Option<Vec<u8>> = None;
    let mut parts: Vec<(u16, u64, u64)> = Vec::new();
    for (id, _, _, data) in &seq {
        match id {
            1 if pvd_label.is_empty() => {
                pvd_label = dstring(data.get(24..56).unwrap_or_default());
            }
            5 => {
                let number = u16_le(data, 22).unwrap_or(0);
                let start = u32_le(data, 188).unwrap_or(0);
                let len = u32_le(data, 192).unwrap_or(0);
                parts.retain(|p| p.0 != number);
                parts.push((number, start.into(), len.into()));
            }
            6 => lvd = Some(data.clone()),
            _ => {}
        }
    }
    let Some(lvd) = lvd else {
        vol.label = pvd_label;
        vol.problems.push(Diagnostic::malformed(
            "no logical volume descriptor in the volume descriptor sequence",
        ));
        return Ok(Some(vol));
    };
    let label = dstring(lvd.get(84..212).unwrap_or_default());
    vol.label = if label.is_empty() { pvd_label } else { label };
    let lbs = u32_le(&lvd, 212).unwrap_or(0);
    if u64::from(lbs) != bs && lbs != 0 {
        vol.problems.push(Diagnostic::warning(format!(
            "logical block size {lbs} differs from the sector size {bs}"
        )));
    }
    if regid_id(lvd.get(216..248).unwrap_or_default()) == "*OSTA UDF Compliant" {
        vol.revision = u16_le(&lvd, 240).filter(|&r| r != 0);
    }
    vol.fsd = LongAd::parse(lvd.get(248..264).unwrap_or_default());
    vol.integrity = (
        u32_le(&lvd, 436).unwrap_or(0),
        u32_le(&lvd, 432).unwrap_or(0),
    );
    let n_maps = u32_le(&lvd, 268).unwrap_or(0);
    let table = lvd.get(440..).unwrap_or_default();
    let mut at = 0usize;
    let mut pending: Vec<(usize, Vec<u8>)> = Vec::new();
    for i in 0..to_usize(n_maps.into()).min(MAX_MAPS) {
        let (Some(&kind), Some(&len)) = (table.get(at), table.get(at.saturating_add(1))) else {
            break;
        };
        let body = table
            .get(at..at.saturating_add(len.into()))
            .unwrap_or_default();
        if len < 2 {
            break;
        }
        let physical = |number: u16| parts.iter().find(|p| p.0 == number).copied();
        let map = match kind {
            1 => {
                let number = u16_le(body, 4).unwrap_or(0);
                match physical(number) {
                    Some((_, start, len)) => Map::Physical { number, start, len },
                    None => Map::Unknown {
                        what: format!("partition {number}, no partition descriptor"),
                    },
                }
            }
            2 => {
                let id = regid_id(body.get(4..36).unwrap_or_default());
                let number = u16_le(body, 38).unwrap_or(0);
                match (id.as_str(), physical(number)) {
                    ("*UDF Sparable Partition", Some((_, start, len))) => {
                        pending.push((i, body.to_vec()));
                        Map::Sparable {
                            number,
                            start,
                            len,
                            packet: u16_le(body, 40).unwrap_or(32).max(1).into(),
                            spared: Vec::new(),
                        }
                    }
                    ("*UDF Metadata Partition" | "*UDF Virtual Partition", Some(_)) => {
                        pending.push((i, body.to_vec()));
                        Map::Unknown { what: id }
                    }
                    (_, None) => Map::Unknown {
                        what: format!("{id}, partition {number} has no partition descriptor"),
                    },
                    _ => Map::Unknown {
                        what: format!("{id} (not supported)"),
                    },
                }
            }
            k => Map::Unknown {
                what: format!("partition map type {k} (not supported)"),
            },
        };
        vol.maps.push(map);
        at = at.saturating_add(len.into());
    }
    // Type 2 maps that need reading: sparing tables first (metadata files
    // may live on a sparable partition), then metadata and virtual maps.
    for (i, body) in &pending {
        if regid_id(body.get(4..36).unwrap_or_default()) == "*UDF Sparable Partition" {
            let spared = sparing_table(cx, &vol, body).await?;
            if let Some(Map::Sparable { spared: s, .. }) = vol.maps.get_mut(*i) {
                *s = spared;
            }
        }
    }
    for (i, body) in &pending {
        let id = regid_id(body.get(4..36).unwrap_or_default());
        let number = u16_le(body, 38).unwrap_or(0);
        // The underlying partition's map index, for addressing.
        let base = vol.maps.iter().position(|m| {
            matches!(m, Map::Physical { number: n, .. } | Map::Sparable { number: n, .. } if *n == number)
        });
        let Some(base) = base.and_then(|b| u16::try_from(b).ok()) else {
            continue;
        };
        let map = match id.as_str() {
            "*UDF Metadata Partition" => {
                let mut data = None;
                let mut mirror = false;
                for (k, at) in [(false, 40usize), (true, 44)] {
                    let lbn = u32_le(body, at).unwrap_or(u32::MAX);
                    if let Ok(d) = metadata_file(cx, &vol, base, lbn).await {
                        data = Some(d);
                        mirror = k;
                        break;
                    }
                }
                if data.is_none() {
                    vol.problems.push(Diagnostic::malformed(
                        "neither the metadata file nor its mirror is readable",
                    ));
                }
                Map::Metadata {
                    number,
                    data,
                    mirror,
                }
            }
            "*UDF Virtual Partition" => {
                let start = match vol.maps.get(usize::from(base)) {
                    Some(Map::Physical { start, .. } | Map::Sparable { start, .. }) => *start,
                    _ => 0,
                };
                let (table, span) = match vat(cx, &vol, base, start).await {
                    Ok(Some((t, s))) => (Some(Arc::new(t)), Some(s)),
                    Ok(None) => (None, None),
                    Err(d) => {
                        vol.problems.push(d);
                        (None, None)
                    }
                };
                vol.vat = span;
                Map::Virtual {
                    number,
                    start,
                    table,
                }
            }
            _ => continue,
        };
        if let Some(slot) = vol.maps.get_mut(*i) {
            *slot = map;
        }
    }
    Ok(Some(vol))
}

/// Entries of the first readable sparing table of a sparable map.
async fn sparing_table(cx: &Cx, vol: &Vol, body: &[u8]) -> Result<Vec<(u32, u32)>> {
    let n = body.get(42).copied().unwrap_or(0);
    let size = u64::from(u32_le(body, 44).unwrap_or(0)).min(MAX_VAT);
    for i in 0..usize::from(n.min(4)) {
        let Some(loc) = u32_le(body, 48usize.saturating_add(i.saturating_mul(4))) else {
            break;
        };
        let span = vol.file().sub(u64::from(loc).saturating_mul(vol.bs), size);
        let data = cx.read_avail(span).await?;
        if !tag_ok(&data) || regid_id(data.get(16..48).unwrap_or_default()) != "*UDF Sparing Table"
        {
            continue;
        }
        let len = usize::from(u16_le(&data, 48).unwrap_or(0));
        let mut out: Vec<(u32, u32)> = data
            .get(56..)
            .unwrap_or_default()
            .as_chunks::<8>()
            .0
            .iter()
            .take(len)
            .filter_map(|e| Some((u32_le(e, 0)?, u32_le(e, 4)?)))
            .filter(|&(o, _)| o < 0xffff_fff0)
            .collect();
        out.sort_unstable();
        return Ok(out);
    }
    Ok(Vec::new())
}

/// The content of the metadata (or mirror) file at `lbn` of map `base`.
async fn metadata_file(cx: &Cx, vol: &Vol, base: u16, lbn: u32) -> Result<Span> {
    let icb = read_icb(
        cx,
        vol,
        LongAd {
            len: 0,
            lbn,
            part: base,
        },
    )
    .await?;
    if !matches!(icb.file_type, 250 | 251) {
        return Err(Diagnostic::malformed("not a metadata file").at(icb.span));
    }
    let (pieces, _) = file_pieces(cx, vol, &icb).await?;
    assemble(cx, icb.span, "udf-metadata", &pieces).await
}

/// The virtual allocation table: the file entry in the last block of the
/// image (UDF 2.00 type 248, or a UDF 1.50 unspecified file ending in the
/// "*UDF Virtual Alloc Tbl" identifier).
async fn vat(cx: &Cx, vol: &Vol, base: u16, start: u64) -> Result<Option<(Vec<u32>, Span)>> {
    let last = vol
        .file()
        .len
        .checked_div(vol.bs)
        .unwrap_or(0)
        .saturating_sub(1);
    let Ok(lbn) = u32::try_from(last.saturating_sub(start)) else {
        return Ok(None);
    };
    let Ok(icb) = read_icb(
        cx,
        vol,
        LongAd {
            len: 0,
            lbn,
            part: base,
        },
    )
    .await
    else {
        return Ok(None);
    };
    let (pieces, _) = file_pieces(cx, vol, &icb).await?;
    let span = assemble(cx, icb.span, "udf-vat", &pieces).await?;
    let data = cx.read_avail(span.sub(0, MAX_VAT)).await?;
    let entries = match icb.file_type {
        248 => {
            let header = usize::from(u16_le(&data, 0).unwrap_or(0));
            data.get(header..).unwrap_or_default()
        }
        0 => {
            let trailer = data.len().saturating_sub(36);
            let id = regid_id(data.get(trailer..).unwrap_or_default());
            if id != "*UDF Virtual Alloc Tbl" {
                return Ok(None);
            }
            data.get(..trailer).unwrap_or_default()
        }
        _ => return Ok(None),
    };
    let table = entries
        .as_chunks::<4>()
        .0
        .iter()
        .map(|e| u32::from_le_bytes(*e))
        .collect();
    Ok(Some((table, icb.span)))
}

// ---------------------------------------------------------------------------
// File entries

/// What the walker needs from a file entry or extended file entry.
#[derive(Clone, Debug)]
struct Icb {
    /// The used part of the entry (through its allocation descriptors).
    span: Span,
    addr: LongAd,
    efe: bool,
    file_type: u8,
    flags: u16,
    uid: u32,
    gid: u32,
    perms: u32,
    size: u64,
    mtime: Option<i64>,
    ads: Span,
    ad_data: Arc<Vec<u8>>,
    stream: Option<LongAd>,
}

impl Icb {
    fn is_dir(&self) -> bool {
        matches!(self.file_type, 4 | 13)
    }

    fn mode(&self) -> String {
        format!("{}{}", kind_char(self.file_type), perm_text(self.perms))
    }
}

async fn read_icb(cx: &Cx, vol: &Vol, mut addr: LongAd) -> Result<Icb> {
    for _ in 0..8 {
        let span = vol.block(addr.part, addr.lbn)?;
        let data = cx.read_avail(span).await?;
        let id = u16_le(&data, 0).unwrap_or(0);
        if id == 259 {
            addr = LongAd::parse(data.get(36..52).unwrap_or_default())
                .ok_or_else(|| Diagnostic::malformed("short indirect entry").at(span))?;
            continue;
        }
        if !matches!(id, 261 | 266) {
            return Err(Diagnostic::malformed(format!(
                "expected a file entry at block {} of partition reference {}, found {}",
                addr.lbn,
                addr.part,
                crate::value::lookup(TAG_IDS, id.into())
                    .map_or_else(|| format!("tag {id}"), str::to_owned)
            ))
            .at(span.sub(0, 16)));
        }
        let efe = id == 266;
        let base: u64 = if efe { 216 } else { 176 };
        let at = to_usize(base);
        let l_ea = u64::from(u32_le(&data, at.saturating_sub(8)).unwrap_or(0));
        let l_ad = u64::from(u32_le(&data, at.saturating_sub(4)).unwrap_or(0));
        let ad_at = base.saturating_add(l_ea);
        let ads = span.sub(ad_at, l_ad);
        let ad_data = data
            .get(to_usize(ad_at)..to_usize(ad_at.saturating_add(l_ad)))
            .unwrap_or_default()
            .to_vec();
        let used = ad_at
            .saturating_add(l_ad)
            .min(span.len)
            .max(base.min(span.len));
        let stream = if efe {
            LongAd::parse(data.get(152..168).unwrap_or_default()).filter(|a| a.size() > 0)
        } else {
            None
        };
        return Ok(Icb {
            span: span.sub(0, used),
            addr,
            efe,
            file_type: data.get(27).copied().unwrap_or(0),
            flags: u16_le(&data, 34).unwrap_or(0),
            uid: u32_le(&data, 36).unwrap_or(0),
            gid: u32_le(&data, 40).unwrap_or(0),
            perms: u32_le(&data, 44).unwrap_or(0),
            size: u64_le(&data, 56).unwrap_or(0),
            mtime: timestamp(
                data.get(if efe { 92..104 } else { 84..96 })
                    .unwrap_or_default(),
            )
            .map(|t| t.0),
            ads,
            ad_data: Arc::new(ad_data),
            stream,
        });
    }
    Err(Diagnostic::limit("too many indirect entries"))
}

/// The pieces of a file's data, in order and clipped to its length, plus
/// the allocation extent descriptors visited and any problems.
async fn file_pieces(cx: &Cx, vol: &Vol, icb: &Icb) -> Result<(Vec<Span>, Vec<Span>)> {
    let ad_type = icb.flags & 7;
    if ad_type == 3 {
        return Ok((vec![icb.ads.sub(0, icb.size)], Vec::new()));
    }
    let Some(size) = ad_size(ad_type) else {
        return Err(Diagnostic::unsupported(format!(
            "allocation descriptor type {ad_type}"
        )));
    };
    let mut pieces = Vec::new();
    let mut aeds = Vec::new();
    let mut area: Arc<Vec<u8>> = icb.ad_data.clone();
    let mut total = 0u64;
    'chain: loop {
        let mut next = None;
        for raw in area.chunks_exact(size) {
            // An AED holds up to max_read bytes of descriptors, and a virtual
            // partition's extent maps block by block.
            cx.checkpoint().await;
            let Some(ad) = parse_ad(raw, ad_type, icb.addr.part) else {
                break;
            };
            if ad.size() == 0 {
                break 'chain;
            }
            match ad.kind() {
                0 => match vol.extent(ad.part, ad.lbn, ad.size()) {
                    Some(p) => pieces.extend(p),
                    None => {
                        return Err(Diagnostic::malformed(format!(
                            "extent in unmapped partition reference {}",
                            ad.part
                        )));
                    }
                },
                3 => {
                    next = Some(ad);
                    break;
                }
                _ => pieces.push(Span::zeros(ad.size())),
            }
            total = total.saturating_add(ad.size());
            if total >= icb.size {
                break 'chain;
            }
        }
        let Some(n) = next else {
            break;
        };
        if aeds.len() >= MAX_AED {
            return Err(Diagnostic::limit("too many allocation extent descriptors"));
        }
        let span = vol.block(n.part, n.lbn)?.sub(0, n.size().max(24));
        let data = cx.read_avail(span).await?;
        if u16_le(&data, 0) != Some(258) {
            return Err(Diagnostic::malformed("expected an allocation extent descriptor").at(span));
        }
        aeds.push(span);
        let len = to_usize(u32_le(&data, 20).unwrap_or(0).into());
        area = Arc::new(
            data.get(24..24usize.saturating_add(len))
                .unwrap_or_default()
                .to_vec(),
        );
        cx.checkpoint().await;
    }
    Ok((coalesce_stepped(cx, pieces, icb.size).await, aeds))
}

fn fe_node(icb: &Icb) -> Node {
    let name = if icb.efe {
        "Extended file entry"
    } else {
        "File entry"
    };
    struct_node(name, icb.span, LE, (), fe_layout).summary(format!(
        "{}, {}, uid {} gid {}",
        crate::value::lookup(FILE_TYPES, icb.file_type.into()).unwrap_or("unknown type"),
        icb.mode(),
        icb.uid,
        icb.gid
    ))
}

fn fid_node(span: Span) -> Node {
    struct_node("File identifier descriptor", span, LE, (), fid_layout)
}

// ---------------------------------------------------------------------------
// Directories and files

#[derive(Clone, Debug)]
struct Entry {
    vol: Arc<Vol>,
    addr: LongAd,
    fid: Option<Span>,
    path: Path,
}

fn entry_node(name: String, icb: Option<&Icb>, is_dir: bool, e: Entry) -> Node {
    let mut node = Node::new(name);
    if let Some(span) = e.fid {
        node = node.span(span);
    }
    let summary = match icb {
        Some(i) => {
            let mut s = if i.is_dir() {
                "directory".to_owned()
            } else if i.file_type == 12 {
                "symbolic link".to_owned()
            } else {
                human_size(i.size)
            };
            s = format!("{s}, {}", i.mode());
            if let Some(t) = i.mtime {
                s = format!("{s}, modified {}", time_text(t));
            }
            s
        }
        None if is_dir => "directory".to_owned(),
        None => String::new(),
    };
    if !summary.is_empty() {
        node = node.summary(summary);
    }
    if is_dir || icb.is_some_and(Icb::is_dir) {
        match e.path.enter(e.addr.id(), MAX_DEPTH) {
            Ok(path) => node.lazy(
                crate::expander!(self::directory: Entry),
                Entry { path, ..e },
            ),
            Err(d) => node.diag(d),
        }
    } else {
        node.lazy(crate::expander!(self::file: Entry), e)
    }
}

/// Emits the nodes describing an entry itself: FID, file entry, the
/// allocation extent descriptors, named streams.
async fn describe(cx: &Cx, e: &Entry, icb: &Icb, aeds: &[Span]) {
    if let Some(f) = e.fid {
        cx.emit(fid_node(f));
    }
    cx.emit(fe_node(icb));
    let ad_type = icb.flags & 7;
    for (i, span) in aeds.iter().enumerate() {
        cx.emit(struct_node(
            format!("Allocation extent descriptor {i}"),
            *span,
            LE,
            ad_type,
            aed_layout,
        ));
    }
    if let Some(s) = icb.stream {
        let state = Entry {
            vol: e.vol.clone(),
            addr: s,
            fid: None,
            path: e.path.clone(),
        };
        let node = Node::new("Named streams").summary("stream directory");
        cx.emit(match e.path.enter(s.id(), MAX_DEPTH) {
            Ok(path) => node.lazy(
                crate::expander!(self::directory: Entry),
                Entry { path, ..state },
            ),
            Err(d) => node.diag(d),
        });
    }
}

async fn directory(cx: Cx, e: Entry) -> Result<()> {
    let icb = read_icb(&cx, &e.vol, e.addr).await?;
    let (pieces, aeds) = file_pieces(&cx, &e.vol, &icb).await?;
    let resumed = cx.resume::<u64>();
    if resumed.is_none() {
        describe(&cx, &e, &icb, &aeds).await;
        if pieces.iter().map(|p| p.len).fold(0, u64::saturating_add) < icb.size {
            cx.diag(Diagnostic::warning(
                "allocation descriptors cover less than the directory's length",
            ));
        }
    }
    let span = assemble(&cx, icb.span, "udf-directory", &pieces).await?;
    let mut pos = resumed.unwrap_or(0);
    while pos.saturating_add(FID_HEAD) <= span.len {
        let head_span = span.sub(pos, FID_HEAD);
        let head = cx.read(head_span).await?;
        if u16_le(&head, 0) != Some(257) {
            // Unused space at the end of a directory block reads as zeros.
            if head.iter().any(|&b| b != 0) {
                cx.diag(
                    Diagnostic::malformed("expected a file identifier descriptor").at(head_span),
                );
            }
            break;
        }
        let chars = head.get(18).copied().unwrap_or(0);
        let l_fi = u64::from(head.get(19).copied().unwrap_or(0));
        let l_iu = u64::from(u16_le(&head, 36).unwrap_or(0));
        let total = align(FID_HEAD.saturating_add(l_iu).saturating_add(l_fi), 4);
        let fid = span.sub(pos, total);
        if chars & 0x08 != 0 {
            pos = pos.saturating_add(total);
            cx.checkpoint().await;
            continue;
        }
        let at = pos;
        cx.mark(move || at);
        pos = pos.saturating_add(total);
        let addr = LongAd::parse(head.get(20..36).unwrap_or_default()).unwrap_or_default();
        let child = Entry {
            vol: e.vol.clone(),
            addr,
            fid: Some(fid),
            path: e.path.clone(),
        };
        cx.progress(pos, span.len);
        if cx.skipping() {
            cx.push(Node::new("")).await;
            continue;
        }
        let raw = cx.read(fid).await?;
        let name_at = to_usize(FID_HEAD.saturating_add(l_iu));
        let name = cs0(raw
            .get(name_at..name_at.saturating_add(to_usize(l_fi)))
            .unwrap_or_default());
        let name = if name.is_empty() {
            "(unnamed)".to_owned()
        } else {
            name
        };
        let mut node = if chars & 0x04 != 0 {
            Node::new(name).span(fid).summary("deleted")
        } else {
            match read_icb(&cx, &e.vol, addr).await {
                Ok(icb) => entry_node(name, Some(&icb), chars & 0x02 != 0, child),
                Err(d) => Node::new(name).span(fid).diag(d),
            }
        };
        if let Some(d) = verify(&raw, None) {
            node = node.diag(d);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn file(cx: Cx, e: Entry) -> Result<()> {
    let icb = read_icb(&cx, &e.vol, e.addr).await?;
    let (pieces, aeds) = file_pieces(&cx, &e.vol, &icb).await?;
    describe(&cx, &e, &icb, &aeds).await;
    let have = pieces.iter().map(|p| p.len).fold(0, u64::saturating_add);
    if have < icb.size {
        cx.diag(Diagnostic::warning(format!(
            "allocation descriptors cover {have} of {} bytes",
            icb.size
        )));
    }
    if icb.size == 0 {
        return Ok(());
    }
    let pieces = Arc::new(pieces);
    if icb.flags & 7 != 3 {
        cx.emit(fragments_node(&cx, "Extents", pieces.clone()).await);
    }
    let content = assemble(&cx, icb.span, "udf-extents", &pieces).await?;
    if icb.file_type == 12 {
        let data = cx.read(content.sub(0, 4096)).await?;
        cx.emit(
            Node::new("Link target")
                .span(content)
                .value(text(symlink_target(&data))),
        );
        return Ok(());
    }
    cx.emit(content_node(&e.vol.input, content));
    Ok(())
}

/// A symbolic link's path components (type, length, version, identifier).
fn symlink_target(b: &[u8]) -> String {
    let mut out = String::new();
    let mut at = 0usize;
    while let (Some(&kind), Some(&len)) = (b.get(at), b.get(at.saturating_add(1))) {
        let start = at.saturating_add(4);
        let id = b
            .get(start..start.saturating_add(len.into()))
            .unwrap_or_default();
        let part = match kind {
            1 if len == 0 => None,
            2 => None,
            3 => Some("..".to_owned()),
            4 => Some(".".to_owned()),
            _ => Some(cs0(id)),
        };
        match part {
            None => out = "/".to_owned(),
            Some(p) => {
                if !out.is_empty() && !out.ends_with('/') {
                    out.push('/');
                }
                out.push_str(&p);
            }
        }
        at = start.saturating_add(len.into());
    }
    out
}

// ---------------------------------------------------------------------------
// Volume-level nodes

async fn sequence_node(cx: Cx, (vol, ext): (Arc<Vol>, (u32, u32))) -> Result<()> {
    let seq = read_sequence(&cx, vol.file(), vol.bs, ext).await?;
    for (id, span, block, data) in seq {
        let mut node = descriptor_node(id, span);
        let summary = match id {
            1 => Some(format!(
                "{:?}",
                dstring(data.get(24..56).unwrap_or_default())
            )),
            4 => Some(regid_id(data.get(20..52).unwrap_or_default())),
            5 => Some(format!(
                "partition {}, {} at block {}",
                u16_le(&data, 22).unwrap_or(0),
                count(u32_le(&data, 192).unwrap_or(0).into(), "block", "blocks"),
                u32_le(&data, 188).unwrap_or(0)
            )),
            6 => Some(format!(
                "{:?}",
                dstring(data.get(84..212).unwrap_or_default())
            )),
            _ => None,
        };
        if let Some(s) = summary {
            node = node.summary(s);
        }
        if let Some(d) = verify(&data, Some(block)) {
            node = node.diag(d);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn integrity_node(cx: Cx, vol: Arc<Vol>) -> Result<()> {
    let seq = read_sequence(&cx, vol.file(), vol.bs, vol.integrity).await?;
    let mut ext = vol.integrity;
    let mut hops = 0usize;
    let mut seq = seq;
    loop {
        let mut next = None;
        for (id, span, block, data) in &seq {
            let mut node = descriptor_node(*id, *span);
            if *id == 9 {
                let kind = u32_le(data, 28).unwrap_or(0);
                let n = to_usize(u32_le(data, 72).unwrap_or(0).into());
                let iu = n.saturating_mul(8).saturating_add(80);
                let files = u32_le(data, iu.saturating_add(32));
                let dirs = u32_le(data, iu.saturating_add(36));
                let mut s = crate::value::lookup(INTEGRITY_TYPES, kind.into())
                    .unwrap_or("unknown")
                    .to_owned();
                if let (Some(f), Some(d)) = (files, dirs) {
                    s = format!(
                        "{s}, {}, {}",
                        count(f.into(), "file", "files"),
                        count(d.into(), "directory", "directories")
                    );
                }
                node = node.summary(s);
                let n_len = u32_le(data, 32).unwrap_or(0);
                if n_len > 0 {
                    next = Some((u32_le(data, 36).unwrap_or(0), n_len));
                }
            }
            if let Some(d) = verify(data, Some(*block)) {
                node = node.diag(d);
            }
            cx.push(node).await;
        }
        let Some(n) = next.filter(|&n| n != ext) else {
            break;
        };
        hops = hops.saturating_add(1);
        if hops > MAX_HOPS {
            break;
        }
        ext = n;
        seq = read_sequence(&cx, vol.file(), vol.bs, ext).await?;
    }
    Ok(())
}

async fn maps_node(cx: Cx, vol: Arc<Vol>) -> Result<()> {
    for (i, m) in vol.maps.iter().enumerate() {
        let mut node = Node::new(format!("Partition reference {i}")).summary(m.summary());
        match m {
            Map::Physical { start, len, .. } | Map::Sparable { start, len, .. } => {
                node = node.span(vol.phys(*start, *len));
            }
            Map::Metadata { data: Some(d), .. } => {
                node = node.span(*d);
            }
            Map::Virtual { .. } => {
                if let Some(v) = vol.vat {
                    node = node.target(v);
                }
            }
            _ => {}
        }
        cx.emit(node);
    }
    Ok(())
}

/// Emits the UDF structure of a volume.
pub async fn emit(cx: &Cx, vol: &Arc<Vol>) -> Result<()> {
    for d in &vol.problems {
        cx.diag(d.clone());
    }
    let anchor = cx.read_avail(vol.avdp).await?;
    let mut node = descriptor_node(2, vol.avdp);
    if let Some(d) = verify(&anchor, None) {
        node = node.diag(d);
    }
    cx.emit(node);
    let file = vol.file();
    for (name, ext) in [
        ("Main volume descriptor sequence", vol.main),
        ("Reserve volume descriptor sequence", vol.reserve),
    ] {
        if ext.1 == 0 {
            continue;
        }
        let span = file.sub(u64::from(ext.0).saturating_mul(vol.bs), ext.1.into());
        cx.emit(
            Node::new(name)
                .span(span)
                .summary(format!("{} at block {}", human_size(ext.1.into()), ext.0))
                .lazy(sequence_node, (vol.clone(), ext)),
        );
    }
    if vol.integrity.1 > 0 {
        let span = file.sub(
            u64::from(vol.integrity.0).saturating_mul(vol.bs),
            vol.integrity.1.into(),
        );
        cx.emit(
            Node::new("Logical volume integrity sequence")
                .span(span)
                .lazy(integrity_node, vol.clone()),
        );
    }
    if !vol.maps.is_empty() {
        cx.emit(
            Node::new("Partitions")
                .summary(count(
                    to_u64(vol.maps.len()),
                    "partition map",
                    "partition maps",
                ))
                .lazy(maps_node, vol.clone()),
        );
    }
    let Some(fsd_ad) = vol.fsd else {
        return Ok(());
    };
    let fsd_span = match vol.block(fsd_ad.part, fsd_ad.lbn) {
        Ok(s) => s.sub(0, 512),
        Err(d) => {
            cx.diag(d);
            return Ok(());
        }
    };
    let fsd = cx.read_avail(fsd_span).await?;
    if u16_le(&fsd, 0) != Some(256) {
        cx.emit(
            Node::new("File set descriptor")
                .span(fsd_span)
                .diag(Diagnostic::malformed("no file set descriptor here")),
        );
        return Ok(());
    }
    let mut node = descriptor_node(256, fsd_span).summary(format!(
        "{:?}",
        dstring(fsd.get(304..336).unwrap_or_default())
    ));
    if let Some(d) = verify(&fsd, Some(fsd_ad.lbn)) {
        node = node.diag(d);
    }
    cx.emit(node);
    for (name, at) in [
        ("Root directory", 400usize),
        ("System stream directory", 464),
    ] {
        let Some(ad) = LongAd::parse(fsd.get(at..at.saturating_add(16)).unwrap_or_default()) else {
            continue;
        };
        if ad.size() == 0 {
            continue;
        }
        let e = Entry {
            vol: vol.clone(),
            addr: ad,
            fid: None,
            path: Path::new(),
        };
        let icb = read_icb(cx, vol, ad).await;
        let mut node = match &icb {
            Ok(i) => entry_node(name.to_owned(), Some(i), true, e),
            Err(d) => Node::new(name).diag(d.clone()),
        };
        if let Ok(i) = icb {
            node = node.span(i.span);
        }
        cx.emit(node);
    }
    Ok(())
}

/// Expander for a "UDF file system" node on a bridge disc.
pub async fn volume(cx: Cx, input: Input) -> Result<()> {
    let Some(vol) = load(&cx, input).await? else {
        return Err(Diagnostic::malformed(
            "no UDF anchor volume descriptor pointer",
        ));
    };
    emit(&cx, &vol).await
}

/// The volume label.
pub fn label(vol: &Vol) -> &str {
    &vol.label
}
