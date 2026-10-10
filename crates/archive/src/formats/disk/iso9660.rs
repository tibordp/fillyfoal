//! ISO 9660 CD/DVD images (with Joliet, Rock Ridge, zisofs and El Torito),
//! plus the UDF volume recognition sequence.
//!
//! After a 32 KiB system area, 2048-byte volume descriptors (primary,
//! supplementary/Joliet, enhanced (ISO 9660:1999), boot record, partition)
//! run until a terminator. The primary and Joliet descriptors each hold a
//! root directory record and the locations of their path tables (one
//! little-endian, one big-endian copy, checked against each other);
//! directories are walked lazily from the root, file extents are dissected
//! as embedded files. The System Use area of a directory record holds SUSP
//! entries (continued in continuation areas): Rock Ridge POSIX attributes,
//! names, symbolic links, device numbers, timestamps and relocated
//! directories, and zisofs compression, whose files are decompressed. El
//! Torito boot records point at a boot catalog whose images are dissected
//! too. UDF volumes (UDF-only discs and the UDF side of bridge discs) are
//! handed to [`super::udf`]. An image layout node accounts for every sector.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Field, Fields, struct_node};
use crate::formats::disk::PieceList;
use crate::formats::disk::qcow::Regions;
use crate::formats::util::arcutil::{
    ByteReader, count, emit_nodes, human_size, text, uint, unix_mode,
};
use crate::formats::{Codec, Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const SECTOR: u64 = 2048;
const DESCRIPTORS_AT: u64 = 16 * SECTOR;
/// Volume descriptors read before giving up on a terminator.
const MAX_DESCRIPTORS: u64 = 64;
const MAX_DEPTH: usize = 64;
/// Continuation areas followed for one directory record.
const MAX_CONTINUATIONS: usize = 16;
/// Directories the image layout walks at most.
const MAX_LAYOUT_DIRS: usize = 1 << 16;
/// The zisofs magic at the start of a compressed file.
const ZISOFS_MAGIC: [u8; 8] = [0x37, 0xe4, 0x53, 0x96, 0xc9, 0xdb, 0xd6, 0x07];

pub static FORMAT: Format = Format {
    name: "iso9660",
    title: "ISO 9660 disc image",
    extensions: &["iso", "cdr", "toast"],
    mime: "application/x-iso9660-image",
    probe: Probe::Magic(&[(0x8001, b"CD001")]),
    dissect: crate::expander!(dissect: Input),
};

/// UDF-only discs have no ISO 9660 descriptors, just the extended area
/// (`BEA01`, `NSR02`/`NSR03`, `TEA01`).
pub static UDF: Format = Format {
    name: "udf",
    title: "UDF disc image",
    extensions: &["iso", "udf"],
    mime: "application/x-udf-image",
    probe: Probe::Custom(|h: &Head<'_>| {
        h.at(0x8001, b"BEA01") || (h.at(0x8001, b"NSR0") && h.data.get(0x8000) == Some(&0))
    }),
    dissect: crate::expander!(dissect: Input),
};

const DESCRIPTOR_TYPE: EnumTable = &[
    (0, "boot record"),
    (1, "primary volume descriptor"),
    (2, "supplementary volume descriptor"),
    (3, "volume partition descriptor"),
    (255, "volume descriptor set terminator"),
];

const FILE_FLAGS: FlagTable = &[
    flag(0x01, "HIDDEN"),
    flag(0x02, "DIRECTORY"),
    flag(0x04, "ASSOCIATED"),
    flag(0x08, "RECORD"),
    flag(0x10, "PROTECTION"),
    flag(0x80, "MULTI_EXTENT"),
];

const VOLUME_FLAGS: FlagTable = &[flag(0x01, "ESCAPES_NOT_ISO_2375")];

const PLATFORM: EnumTable = &[(0, "x86"), (1, "PowerPC"), (2, "Mac"), (0xef, "EFI")];
const MEDIA: EnumTable = &[
    (0, "no emulation"),
    (1, "1.2 MB floppy"),
    (2, "1.44 MB floppy"),
    (3, "2.88 MB floppy"),
    (4, "hard disk"),
];
const MEDIA_FLAGS: FlagTable = &[
    flag(0x20, "CONTINUATION_ENTRY_FOLLOWS"),
    flag(0x40, "ATAPI_DRIVER"),
    flag(0x80, "SCSI_DRIVERS"),
];

// ---------------------------------------------------------------------------
// Field helpers

/// A 32-bit number stored twice, little- then big-endian.
fn both32<'a>(f: &mut Fields<'a>, name: &'static str) -> Field<'a, u32> {
    f.bytes(name, 8)
        .with(|b, n| {
            let le = u32_le(b, 0).unwrap_or(0);
            let n = n.value(uint(le.into()));
            if u32_be(b, 4) == Some(le) {
                n
            } else {
                n.diag(Diagnostic::warning("little- and big-endian copies differ"))
            }
        })
        .map(|b| u32_le(&b, 0).unwrap_or(0))
}

fn both16<'a>(f: &mut Fields<'a>, name: &'static str) -> Field<'a, u16> {
    f.bytes(name, 4)
        .with(|b, n| {
            let le = u16_le(b, 0).unwrap_or(0);
            let n = n.value(uint(le.into()));
            if u16_be(b, 2) == Some(le) {
                n
            } else {
                n.diag(Diagnostic::warning("little- and big-endian copies differ"))
            }
        })
        .map(|b| u16_le(&b, 0).unwrap_or(0))
}

/// [`both32`] over in-memory bytes.
fn read_both32(r: &mut ByteReader<'_>, name: &'static str) -> Option<u32> {
    let b = r.bytes(name, 8)?;
    let le = u32_le(b, 0).unwrap_or(0);
    let same = u32_be(b, 4) == Some(le);
    r.with(|n| {
        let n = n.value(uint(le.into()));
        if same {
            n
        } else {
            n.diag(Diagnostic::warning("little- and big-endian copies differ"))
        }
    });
    Some(le)
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y.saturating_sub(1) } else { y };
    let era = y.div_euclid(400);
    let yoe = y.saturating_sub(era.saturating_mul(400));
    let mp = if m > 2 {
        m.saturating_sub(3)
    } else {
        m.saturating_add(9)
    };
    let doy = (153i64.saturating_mul(mp).saturating_add(2) / 5)
        .saturating_add(d)
        .saturating_sub(1);
    let doe = yoe
        .saturating_mul(365)
        .saturating_add(yoe / 4)
        .saturating_sub(yoe / 100)
        .saturating_add(doy);
    era.saturating_mul(146_097)
        .saturating_add(doe)
        .saturating_sub(719_468)
}

/// The 7-byte directory record date (years since 1900, ..., GMT offset in
/// 15-minute units) as Unix seconds.
fn record_time(b: &[u8]) -> Option<i64> {
    let get = |i: usize| b.get(i).map(|&v| i64::from(v));
    if b.get(..6).is_some_and(|d| d.iter().all(|&x| x == 0)) {
        return None;
    }
    let days = days_from_civil(get(0)?.saturating_add(1900), get(1)?, get(2)?);
    let offset = i64::from(b.get(6)?.cast_signed()).saturating_mul(15 * 60);
    Some(
        days.saturating_mul(86_400)
            .saturating_add(get(3)?.saturating_mul(3600))
            .saturating_add(get(4)?.saturating_mul(60))
            .saturating_add(get(5)?)
            .saturating_sub(offset),
    )
}

/// The 17-byte descriptor date "YYYYMMDDHHMMSScc" + offset, as text.
fn long_date(b: &[u8]) -> String {
    let digits = b.get(..16).unwrap_or_default();
    if digits.iter().all(|&c| c == b'0' || c == 0) {
        return "not set".to_owned();
    }
    let s = String::from_utf8_lossy(digits);
    let part = |a: usize, z: usize| s.get(a..z).unwrap_or("??").to_owned();
    let offset = i32::from(b.get(16).copied().unwrap_or(0).cast_signed()).saturating_mul(15);
    format!(
        "{}-{}-{} {}:{}:{}.{} UTC{:+}:{:02}",
        part(0, 4),
        part(4, 6),
        part(6, 8),
        part(8, 10),
        part(10, 12),
        part(12, 14),
        part(14, 16),
        offset / 60,
        (offset % 60).abs()
    )
}

fn long_date_field(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.bytes(name, 17)
        .with(|b, n| n.value(text(long_date(b))))
        .emit()?;
    Ok(())
}

/// A d-character text field (space padded), or UTF-16BE in Joliet.
fn text_field(f: &mut Fields<'_>, name: &'static str, len: u64, joliet: bool) -> Result<String> {
    f.bytes(name, len)
        .with(|b, n| n.value(text(decode_text(b, joliet))))
        .map(|b| decode_text(&b, joliet))
        .emit()
}

fn decode_text(b: &[u8], joliet: bool) -> String {
    let s = if joliet {
        crate::text::utf16(b, Endian::Big)
    } else {
        String::from_utf8_lossy(b).into_owned()
    };
    s.trim_end_matches([' ', '\0']).to_owned()
}

/// A run of unused (normally zero) bytes in a structure.
fn unused(f: &mut Fields<'_>, name: &'static str, len: u64) -> Result<()> {
    f.bytes(name, len)
        .with(|b, n| {
            if b.iter().all(|&x| x == 0) {
                n.summary("zeros")
            } else {
                n
            }
        })
        .emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Volume descriptors

/// What the dissector needs from a primary or supplementary descriptor.
#[derive(Clone, Copy, Debug)]
struct Volume {
    blocks: u32,
    block_size: u16,
    path_table_size: u32,
    path_tables: [u32; 4],
    joliet: bool,
}

fn volume_layout(f: &mut Fields<'_>, _: &()) -> Result<Volume> {
    let kind = f.u8("Type").enumeration(DESCRIPTOR_TYPE).emit()?;
    f.ascii("Identifier", 5).emit()?;
    f.u8("Version")
        .with(|&v, n| {
            if kind == 2 && v == 2 {
                n.summary("enhanced volume descriptor (ISO 9660:1999)")
            } else {
                n
            }
        })
        .emit()?;
    // Joliet is signalled by escape sequences at 88; decide before reading
    // the identifiers.
    let block = f.block().data.clone();
    let joliet = kind == 2 && matches!(block.get(88..91), Some(b"%/@" | b"%/C" | b"%/E"));
    if kind == 2 {
        f.u8("Volume flags").hex().flags(VOLUME_FLAGS).emit()?;
    } else {
        unused(f, "Unused", 1)?;
    }
    text_field(f, "System identifier", 32, joliet)?;
    text_field(f, "Volume identifier", 32, joliet)?;
    unused(f, "Unused", 8)?;
    let blocks = both32(f, "Volume space size")
        .desc("Logical blocks in the volume")
        .emit()?;
    if kind == 2 {
        f.bytes("Escape sequences", 32)
            .with(|b, n| {
                if joliet {
                    let level = match b.get(2) {
                        Some(b'@') => 1,
                        Some(b'C') => 2,
                        _ => 3,
                    };
                    n.summary(format!("Joliet level {level} (UCS-2)"))
                } else {
                    n
                }
            })
            .emit()?;
    } else {
        unused(f, "Unused", 32)?;
    }
    both16(f, "Volume set size").emit()?;
    both16(f, "Volume sequence number").emit()?;
    let block_size = both16(f, "Logical block size").emit()?;
    let path_table_size = both32(f, "Path table size")
        .with(|&v, n| n.summary(human_size(v.into())))
        .emit()?;
    let l = f.u32("L path table location").emit()?;
    let ol = f.u32("Optional L path table location").emit()?;
    let m = f
        .bytes("M path table location", 4)
        .with(|b, n| n.value(uint(u32_be(b, 0).unwrap_or(0).into())))
        .map(|b| u32_be(&b, 0).unwrap_or(0))
        .emit()?;
    let om = f
        .bytes("Optional M path table location", 4)
        .with(|b, n| n.value(uint(u32_be(b, 0).unwrap_or(0).into())))
        .map(|b| u32_be(&b, 0).unwrap_or(0))
        .emit()?;
    let root = f.peek_span(34);
    f.node(struct_node(
        "Root directory record",
        root,
        LE,
        joliet,
        record_layout,
    ));
    f.skip(34);
    text_field(f, "Volume set identifier", 128, joliet)?;
    text_field(f, "Publisher identifier", 128, joliet)?;
    text_field(f, "Data preparer identifier", 128, joliet)?;
    text_field(f, "Application identifier", 128, joliet)?;
    text_field(f, "Copyright file", 37, joliet)?;
    text_field(f, "Abstract file", 37, joliet)?;
    text_field(f, "Bibliographic file", 37, joliet)?;
    long_date_field(f, "Creation time")?;
    long_date_field(f, "Modification time")?;
    long_date_field(f, "Expiration time")?;
    long_date_field(f, "Effective time")?;
    f.u8("File structure version").emit()?;
    unused(f, "Reserved", 1)?;
    unused(f, "Application use", 512)?;
    unused(f, "Reserved", 653)?;
    Ok(Volume {
        blocks,
        block_size,
        path_table_size,
        path_tables: [l, ol, m, om],
        joliet,
    })
}

fn boot_layout(f: &mut Fields<'_>, _: &()) -> Result<u32> {
    f.u8("Type").enumeration(DESCRIPTOR_TYPE).emit()?;
    f.ascii("Identifier", 5).emit()?;
    f.u8("Version").emit()?;
    f.ascii("Boot system identifier", 32).emit()?;
    f.ascii("Boot identifier", 32).emit()?;
    let catalog = f
        .u32("Boot catalog sector")
        .desc("El Torito: sector of the boot catalog")
        .emit()?;
    unused(f, "Boot system use", 1973)?;
    Ok(catalog)
}

fn partition_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Type").enumeration(DESCRIPTOR_TYPE).emit()?;
    f.ascii("Identifier", 5).emit()?;
    f.u8("Version").emit()?;
    unused(f, "Unused", 1)?;
    f.ascii("System identifier", 32).emit()?;
    f.ascii("Volume partition identifier", 32).emit()?;
    both32(f, "Volume partition location").emit()?;
    both32(f, "Volume partition size").emit()?;
    unused(f, "System use", 1960)?;
    Ok(())
}

/// Extended area descriptors (ECMA-167 volume recognition).
fn extended_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Structure type").emit()?;
    f.ascii("Identifier", 5).emit()?;
    f.u8("Version").emit()?;
    unused(f, "Structure data", 2041)?;
    Ok(())
}

fn plain_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Type").enumeration(DESCRIPTOR_TYPE).emit()?;
    f.ascii("Identifier", 5).emit()?;
    f.u8("Version").emit()?;
    unused(f, "Reserved", 2041)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// System Use (SUSP, Rock Ridge, zisofs)

/// SUSP entries: two-letter signature, version, data (after the 4-byte
/// header), and their byte ranges. Stops at `ST` or a malformed entry.
fn susp_entries(su: &[u8]) -> Vec<([u8; 2], u8, std::ops::Range<usize>)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let (Some(&a), Some(&b), Some(&len), Some(&ver)) = (
        su.get(at),
        su.get(at.saturating_add(1)),
        su.get(at.saturating_add(2)),
        su.get(at.saturating_add(3)),
    ) {
        let len = usize::from(len);
        if len < 4 || !a.is_ascii_uppercase() || at.saturating_add(len) > su.len() {
            break;
        }
        out.push(([a, b], ver, at..at.saturating_add(len)));
        if [a, b] == *b"ST" {
            break;
        }
        at = at.saturating_add(len);
    }
    out
}

/// A zisofs (`ZF`) entry: header size in 4-byte units, log2 of the block
/// size, uncompressed size.
#[derive(Clone, Copy, Debug)]
struct Zf {
    header: u8,
    block_log2: u8,
    size: u32,
}

/// A parsed directory record (with its Rock Ridge and zisofs entries).
#[derive(Clone, Debug, Default)]
struct Record {
    extent: u32,
    size: u32,
    flags: u8,
    name: String,
    rr_name: Option<String>,
    rr_mode: Option<u32>,
    symlink: Option<String>,
    device: Option<(u32, u32)>,
    /// `CL`: a relocated directory's real location.
    child_link: Option<u32>,
    /// `RE`: this is a relocated directory (shown at its original place).
    relocated: bool,
    zisofs: Option<Zf>,
    /// `CE`: continuation area (block, offset, length).
    continuation: Option<(u32, u32, u32)>,
}

impl Record {
    fn is_dir(&self) -> bool {
        self.flags & 0x02 != 0 || self.child_link.is_some()
    }

    fn display_name(&self) -> String {
        if let Some(n) = &self.rr_name {
            return n.clone();
        }
        let n = self.name.strip_suffix(";1").unwrap_or(&self.name);
        let n = n.strip_suffix('.').unwrap_or(n);
        n.to_owned()
    }

    /// Applies the SUSP entries of `su` (the system use area or a
    /// continuation area).
    fn apply(&mut self, su: &[u8]) {
        for (sig, _, range) in susp_entries(su) {
            let data = su
                .get(range.start.saturating_add(4)..range.end)
                .unwrap_or_default();
            match &sig {
                b"NM" => {
                    let flags = data.first().copied().unwrap_or(0);
                    if flags & 0x06 == 0 {
                        let part = String::from_utf8_lossy(data.get(1..).unwrap_or_default());
                        self.rr_name.get_or_insert_with(String::new).push_str(&part);
                    }
                }
                b"PX" => self.rr_mode = u32_le(data, 0),
                b"SL" => {
                    let target = symlink_text(data);
                    match &mut self.symlink {
                        Some(s) if !s.is_empty() && !s.ends_with('/') => {
                            s.push('/');
                            s.push_str(&target);
                        }
                        Some(s) => s.push_str(&target),
                        None => self.symlink = Some(target),
                    }
                }
                b"PN" => {
                    self.device =
                        Some((u32_le(data, 0).unwrap_or(0), u32_le(data, 8).unwrap_or(0)));
                }
                b"CL" => self.child_link = u32_le(data, 0),
                b"RE" => self.relocated = true,
                b"ZF" => {
                    if data.get(..2) == Some(b"pz".as_slice()) {
                        self.zisofs = Some(Zf {
                            header: data.get(2).copied().unwrap_or(0),
                            block_log2: data.get(3).copied().unwrap_or(0),
                            size: u32_le(data, 4).unwrap_or(0),
                        });
                    }
                }
                b"CE" => {
                    self.continuation = Some((
                        u32_le(data, 0).unwrap_or(0),
                        u32_le(data, 8).unwrap_or(0),
                        u32_le(data, 16).unwrap_or(0),
                    ));
                }
                _ => {}
            }
        }
    }
}

/// The components of an `SL` entry (after its flags byte) as a path.
fn symlink_text(data: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 1usize;
    // Whether the previous component continues into this one.
    let mut glue = true;
    while let (Some(&flags), Some(&l)) = (data.get(i), data.get(i.saturating_add(1))) {
        let start = i.saturating_add(2);
        let comp = data
            .get(start..start.saturating_add(usize::from(l)))
            .unwrap_or_default();
        if flags & 0x08 != 0 {
            out.push('/');
        } else {
            if !glue && !out.ends_with('/') {
                out.push('/');
            }
            match flags & 0x06 {
                0x02 => out.push('.'),
                0x04 => out.push_str(".."),
                _ => out.push_str(&String::from_utf8_lossy(comp)),
            }
        }
        glue = flags & 0x01 != 0;
        i = start.saturating_add(usize::from(l));
    }
    out
}

/// The system use area of a directory record: after the padded name.
fn system_use(b: &[u8]) -> &[u8] {
    let len = usize::from(b.first().copied().unwrap_or(0));
    let name_len = usize::from(b.get(32).copied().unwrap_or(0));
    let su_at = 33usize
        .saturating_add(name_len)
        .saturating_add(usize::from(name_len % 2 == 0));
    b.get(su_at..len).unwrap_or_default()
}

fn parse_record(b: &[u8], joliet: bool) -> Option<Record> {
    let name_len = usize::from(*b.get(32)?);
    let raw_name = b.get(33..33usize.checked_add(name_len)?)?;
    let name = match raw_name {
        [0] => ".".to_owned(),
        [1] => "..".to_owned(),
        _ if joliet => crate::text::utf16(raw_name, Endian::Big),
        _ => String::from_utf8_lossy(raw_name).into_owned(),
    };
    let mut r = Record {
        extent: u32_le(b, 2)?,
        size: u32_le(b, 10)?,
        flags: *b.get(25)?,
        name,
        ..Record::default()
    };
    r.apply(system_use(b));
    Some(r)
}

/// A record with its continuation areas followed (long Rock Ridge names
/// and symbolic links spill over into them).
async fn load_record(
    cx: &Cx,
    file: Span,
    block: u64,
    b: &[u8],
    joliet: bool,
) -> Result<Option<Record>> {
    let Some(mut r) = parse_record(b, joliet) else {
        return Ok(None);
    };
    let mut seen = 0usize;
    while let Some((lba, offset, len)) = r.continuation.take() {
        if seen >= MAX_CONTINUATIONS {
            break;
        }
        seen = seen.saturating_add(1);
        let area = file.sub(
            u64::from(lba)
                .saturating_mul(block)
                .saturating_add(offset.into()),
            u64::from(len).min(SECTOR),
        );
        let data = cx.read_avail(area).await?;
        r.apply(&data);
    }
    Ok(Some(r))
}

/// What a directory record needs to render its System Use entries.
#[derive(Clone, Copy, Debug)]
struct RecCtx {
    joliet: bool,
    file: Span,
    block: u64,
}

fn record_layout(f: &mut Fields<'_>, joliet: &bool) -> Result<()> {
    record_fields(f, *joliet, None)
}

fn record_layout_with(f: &mut Fields<'_>, ctx: &RecCtx) -> Result<()> {
    record_fields(f, ctx.joliet, Some(*ctx))
}

fn record_fields(f: &mut Fields<'_>, joliet: bool, ctx: Option<RecCtx>) -> Result<()> {
    let len = f.u8("Record length").emit()?;
    f.u8("Extended attribute length").emit()?;
    both32(f, "Extent location").emit()?;
    both32(f, "Data length")
        .with(|&s, n| n.summary(human_size(s.into())))
        .emit()?;
    f.bytes("Recording time", 7)
        .with(|b, n| match record_time(b) {
            Some(t) => n.value(Value::Timestamp { unix_seconds: t }),
            None => n.summary("not set"),
        })
        .emit()?;
    f.u8("File flags").flags(FILE_FLAGS).emit()?;
    f.u8("File unit size").emit()?;
    f.u8("Interleave gap").emit()?;
    both16(f, "Volume sequence number").emit()?;
    let name_len = f.u8("Name length").emit()?;
    f.bytes("Name", name_len.into())
        .with(|b, n| {
            let name = match b.as_slice() {
                [0] => "\\0 (this directory)".to_owned(),
                [1] => "\\1 (parent directory)".to_owned(),
                _ if joliet => crate::text::utf16(b, Endian::Big),
                _ => String::from_utf8_lossy(b).into_owned(),
            };
            n.value(text(name))
        })
        .emit()?;
    if name_len % 2 == 0 {
        f.u8("Padding").emit()?;
    }
    let used = f.pos();
    let len = u64::from(len);
    if len > used {
        let span = f.peek_span(len.saturating_sub(used));
        let data = f
            .block()
            .data
            .get(to_usize(used)..to_usize(len))
            .unwrap_or_default()
            .to_vec();
        let names: Vec<String> = susp_entries(&data)
            .iter()
            .map(|(s, _, _)| String::from_utf8_lossy(s).into_owned())
            .collect();
        let node = Node::new("System use")
            .span(span)
            .summary(if names.is_empty() {
                format!("{} bytes", data.len())
            } else {
                names.join(" ")
            });
        f.node(match ctx {
            Some(ctx) => node.lazy(
                crate::expander!(self::susp_node: SuspState),
                (span, Arc::new(data), ctx, 0),
            ),
            None => node.value(Value::Bytes(data)),
        });
    }
    Ok(())
}

type SuspState = (Span, Arc<Vec<u8>>, RecCtx, usize);

const SUSP_NAMES: EnumTable = &[
    (0x5350, "SP: SUSP indicator"),
    (0x4345, "CE: continuation area"),
    (0x5354, "ST: terminator"),
    (0x5044, "PD: padding"),
    (0x4552, "ER: extensions reference"),
    (0x4553, "ES: extension selector"),
    (0x5252, "RR: Rock Ridge extensions in use"),
    (0x5058, "PX: POSIX attributes"),
    (0x504e, "PN: device number"),
    (0x534c, "SL: symbolic link"),
    (0x4e4d, "NM: alternate name"),
    (0x434c, "CL: child link"),
    (0x504c, "PL: parent link"),
    (0x5245, "RE: relocated directory"),
    (0x5446, "TF: timestamps"),
    (0x5346, "SF: sparse file"),
    (0x5a46, "ZF: zisofs compression"),
    (0x414c, "AL: AAIP ACL or attribute"),
    (0x4141, "AA: AAIP attribute"),
];

const RR_FLAGS: FlagTable = &[
    flag(0x01, "PX"),
    flag(0x02, "PN"),
    flag(0x04, "SL"),
    flag(0x08, "NM"),
    flag(0x10, "CL"),
    flag(0x20, "PL"),
    flag(0x40, "RE"),
    flag(0x80, "TF"),
];
const NM_FLAGS: FlagTable = &[
    flag(0x01, "CONTINUE"),
    flag(0x02, "CURRENT"),
    flag(0x04, "PARENT"),
    flag(0x20, "HOST"),
];
const SL_FLAGS: FlagTable = &[flag(0x01, "CONTINUE")];
const SL_COMPONENT_FLAGS: FlagTable = &[
    flag(0x01, "CONTINUE"),
    flag(0x02, "CURRENT"),
    flag(0x04, "PARENT"),
    flag(0x08, "ROOT"),
];
const TF_FLAGS: FlagTable = &[
    flag(0x01, "CREATION"),
    flag(0x02, "MODIFY"),
    flag(0x04, "ACCESS"),
    flag(0x08, "ATTRIBUTES"),
    flag(0x10, "BACKUP"),
    flag(0x20, "EXPIRATION"),
    flag(0x40, "EFFECTIVE"),
    flag(0x80, "LONG_FORM"),
];
const TF_NAMES: [&str; 7] = [
    "Created",
    "Modified",
    "Accessed",
    "Attributes changed",
    "Backed up",
    "Expires",
    "Effective",
];

/// Decodes one SUSP entry's fields; returns them with the entry's value
/// and summary.
fn susp_fields(entry: &[u8], span: Span) -> (Arc<Vec<Node>>, Option<Value>, String) {
    let mut r = ByteReader::new(entry, span);
    let _ = r.text("Signature", 2);
    let _ = r.u8("Length");
    let _ = r.u8("Version");
    let sig: [u8; 2] = [
        entry.first().copied().unwrap_or(0),
        entry.get(1).copied().unwrap_or(0),
    ];
    let mut value = None;
    let mut summary = String::new();
    let flags_value = |raw: u8, table: FlagTable| {
        let (set, unknown) = crate::value::decode_flags(table, raw.into());
        Value::Flags {
            raw: raw.into(),
            bits: 8,
            set,
            unknown,
        }
    };
    match &sig {
        b"SP" => {
            let _ = r.bytes("Check bytes", 2);
            if let Some(skip) = r.u8("Bytes skipped") {
                summary = format!("SUSP in use, {skip} bytes skipped in each System Use area");
            }
        }
        b"CE" => {
            let block = read_both32(&mut r, "Block").unwrap_or(0);
            let offset = read_both32(&mut r, "Offset").unwrap_or(0);
            let len = read_both32(&mut r, "Length").unwrap_or(0);
            summary = format!("{len} bytes at block {block} + {offset}");
        }
        b"PD" => {
            let n = r.remaining();
            let _ = r.bytes("Padding", to_u64(n));
        }
        b"ER" => {
            let id = u64::from(r.u8("Identifier length").unwrap_or(0));
            let des = u64::from(r.u8("Descriptor length").unwrap_or(0));
            let src = u64::from(r.u8("Source length").unwrap_or(0));
            let _ = r.u8("Extension version");
            let ident = r.text("Identifier", id).unwrap_or_default();
            let _ = r.text("Descriptor", des);
            let _ = r.text("Source", src);
            summary.clone_from(&ident);
            value = Some(text(ident));
        }
        b"ES" => {
            let n = r.u8("Extension sequence").unwrap_or(0);
            summary = format!("entries that follow belong to extension {n}");
        }
        b"RR" => {
            let f = r.u8("Flags").unwrap_or(0);
            r.with(|n| n.value(flags_value(f, RR_FLAGS)));
        }
        b"PX" => {
            let mode = read_both32(&mut r, "Mode").unwrap_or(0);
            r.with(|n| n.summary(format!("0o{mode:o} {}", unix_mode(mode.into()))));
            let links = read_both32(&mut r, "Links").unwrap_or(0);
            let uid = read_both32(&mut r, "User id").unwrap_or(0);
            let gid = read_both32(&mut r, "Group id").unwrap_or(0);
            if r.remaining() >= 8 {
                let _ = read_both32(&mut r, "Serial number (inode)");
            }
            summary = format!(
                "{}, {links} link{}, uid {uid}, gid {gid}",
                unix_mode(mode.into()),
                if links == 1 { "" } else { "s" }
            );
            value = Some(uint(mode.into()));
        }
        b"PN" => {
            let hi = read_both32(&mut r, "Device number (high)").unwrap_or(0);
            let lo = read_both32(&mut r, "Device number (low)").unwrap_or(0);
            summary = if hi == 0 {
                format!("device {}, {}", lo >> 8, lo & 0xff)
            } else {
                format!("device {hi}, {lo}")
            };
        }
        b"SL" => {
            let f = r.u8("Flags").unwrap_or(0);
            r.with(|n| n.value(flags_value(f, SL_FLAGS)));
            let target = symlink_text(entry.get(4..).unwrap_or_default());
            while r.remaining() >= 2 {
                let start = r.at;
                let cf = entry.get(start).copied().unwrap_or(0);
                let len = entry.get(start.saturating_add(1)).copied().unwrap_or(0);
                let comp = entry
                    .get(
                        start.saturating_add(2)..start.saturating_add(2).saturating_add(len.into()),
                    )
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                if r.skip(2u64.saturating_add(len.into())).is_none() {
                    break;
                }
                let shown = match cf & 0x0e {
                    0x02 => ".".to_owned(),
                    0x04 => "..".to_owned(),
                    0x08 => "/".to_owned(),
                    _ => comp,
                };
                let (set, unknown) = crate::value::decode_flags(SL_COMPONENT_FLAGS, cf.into());
                r.push(
                    Node::new("Component")
                        .span(r.since(start))
                        .value(text(shown))
                        .summary(if unknown == 0 {
                            set.join(", ")
                        } else {
                            format!("flags {cf:#04x}")
                        }),
                );
            }
            summary.clone_from(&target);
            value = Some(text(target));
        }
        b"NM" => {
            let f = r.u8("Flags").unwrap_or(0);
            r.with(|n| n.value(flags_value(f, NM_FLAGS)));
            let n = r.remaining();
            let name = r.text("Name", to_u64(n)).unwrap_or_default();
            value = Some(text(name));
        }
        b"CL" => {
            let at = read_both32(&mut r, "Child directory location").unwrap_or(0);
            summary = format!("the directory was relocated to block {at}");
        }
        b"PL" => {
            let at = read_both32(&mut r, "Parent directory location").unwrap_or(0);
            summary = format!("original parent at block {at}");
        }
        b"RE" => {
            summary = "relocated here; listed under its original parent".to_owned();
        }
        b"TF" => {
            let f = r.u8("Flags").unwrap_or(0);
            r.with(|n| n.value(flags_value(f, TF_FLAGS)));
            let long = f & 0x80 != 0;
            for (bit, name) in TF_NAMES.iter().enumerate() {
                if f & (1u8 << bit) == 0 {
                    continue;
                }
                if long {
                    let Some(b) = r.bytes(name, 17) else { break };
                    let t = long_date(b);
                    r.with(|n| n.value(text(t)));
                } else {
                    let Some(b) = r.bytes(name, 7) else { break };
                    let t = record_time(b);
                    r.with(|n| match t {
                        Some(t) => n.value(Value::Timestamp { unix_seconds: t }),
                        None => n.summary("not set"),
                    });
                }
            }
        }
        b"SF" => {
            let hi = read_both32(&mut r, "Virtual size (high)").unwrap_or(0);
            let lo = read_both32(&mut r, "Virtual size (low)").unwrap_or(0);
            let _ = r.u8("Table depth");
            summary = human_size((u64::from(hi) << 32) | u64::from(lo));
        }
        b"ZF" => {
            let alg = r.text("Algorithm", 2).unwrap_or_default();
            let header = r.u8("Header size (4-byte units)").unwrap_or(0);
            let log2 = r.u8("Block size (log2)").unwrap_or(0);
            r.with(|n| n.summary(human_size(1u64.checked_shl(log2.into()).unwrap_or(0))));
            let size = read_both32(&mut r, "Uncompressed size").unwrap_or(0);
            summary = format!(
                "{alg}, {} uncompressed, {}-byte header",
                human_size(size.into()),
                u32::from(header).saturating_mul(4)
            );
        }
        _ => {
            let n = r.remaining();
            let _ = r.bytes("Data", to_u64(n));
        }
    }
    if r.remaining() > 0 {
        let n = r.remaining();
        let _ = r.bytes("Unparsed", to_u64(n));
    }
    (r.into_nodes(), value, summary)
}

async fn susp_node(cx: Cx, (span, data, ctx, depth): SuspState) -> Result<()> {
    for (sig, _, range) in susp_entries(&data) {
        let entry = data.get(range.clone()).unwrap_or_default();
        let espan = span.sub(to_u64(range.start), to_u64(range.len()));
        let key = u64::from(u16::from_be_bytes(sig));
        let name = lookup(SUSP_NAMES, key)
            .map_or_else(|| String::from_utf8_lossy(&sig).into_owned(), str::to_owned);
        let (fields, value, summary) = susp_fields(entry, espan);
        let mut node = Node::new(name).span(espan).lazy(emit_nodes, fields);
        if let Some(v) = value {
            node = node.value(v);
        }
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        cx.emit(node);
        if &sig == b"CE" {
            let block = u32_le(entry, 4).unwrap_or(0);
            let offset = u32_le(entry, 12).unwrap_or(0);
            let len = u32_le(entry, 20).unwrap_or(0);
            let area = ctx.file.sub(
                u64::from(block)
                    .saturating_mul(ctx.block)
                    .saturating_add(offset.into()),
                u64::from(len).min(SECTOR),
            );
            if depth >= MAX_CONTINUATIONS {
                cx.diag(Diagnostic::limit("continuation areas nested too deep"));
                continue;
            }
            let more = cx.read_avail(area).await?;
            cx.emit(
                Node::new("Continuation area")
                    .span(area)
                    .summary(format!("{} bytes", more.len()))
                    .lazy(
                        crate::expander!(self::susp_node: SuspState),
                        (area, Arc::new(more), ctx, depth.saturating_add(1)),
                    ),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Directories and files

/// State of a directory or file node.
#[derive(Clone, Debug)]
struct Entry {
    input: Input,
    record: Span,
    block_size: u64,
    joliet: bool,
    /// Extents of the directories on the path here, for cycle detection.
    path: Arc<Vec<u32>>,
}

fn entry_node(name: String, r: &Record, state: Entry) -> Node {
    let mut summary = if r.child_link.is_some() {
        "directory (relocated)".to_owned()
    } else if r.is_dir() {
        "directory".to_owned()
    } else if let Some(target) = &r.symlink {
        format!("symbolic link → {target}")
    } else if let Some((hi, lo)) = r.device {
        let (major, minor) = if hi == 0 {
            (lo >> 8, lo & 0xff)
        } else {
            (hi, lo)
        };
        format!("device {major}, {minor}")
    } else if let Some(z) = r.zisofs {
        format!(
            "{} (zisofs, {} stored)",
            human_size(z.size.into()),
            human_size(r.size.into())
        )
    } else {
        human_size(r.size.into())
    };
    if let Some(m) = r.rr_mode {
        summary = format!("{summary}, {}", unix_mode(m.into()));
    }
    if r.relocated {
        summary = format!("{summary}; relocated, also listed under its original parent");
    }
    Node::new(name)
        .span(state.record)
        .summary(summary)
        .lazy(crate::expander!(self::entry: Entry), state)
}

async fn entry(cx: Cx, e: Entry) -> Result<()> {
    let file = e.input.span;
    let bytes = cx.read(e.record).await?;
    let r = load_record(&cx, file, e.block_size, &bytes, e.joliet)
        .await?
        .ok_or_else(|| Diagnostic::malformed("bad directory record").at(e.record))?;
    let ctx = RecCtx {
        joliet: e.joliet,
        file,
        block: e.block_size,
    };
    cx.emit(struct_node(
        "Directory record",
        e.record,
        LE,
        ctx,
        record_layout_with,
    ));
    let mut extent = file.sub(
        u64::from(r.extent).saturating_mul(e.block_size),
        r.size.into(),
    );
    let mut dir_extent = r.extent;
    if let Some(cl) = r.child_link {
        // A relocated directory: its "." record gives its size.
        let at = file.sub(u64::from(cl).saturating_mul(e.block_size), 34);
        let dot = cx.read_avail(at).await?;
        let size = u32_le(&dot, 10).unwrap_or(0);
        extent = file.sub(u64::from(cl).saturating_mul(e.block_size), size.into());
        dir_extent = cl;
    }
    if !r.is_dir() {
        if r.symlink.is_some() || r.device.is_some() {
            return Ok(());
        }
        if r.size == 0 {
            return Ok(());
        }
        if let Some(z) = r.zisofs {
            cx.emit(
                Node::new("Compressed content")
                    .span(extent)
                    .summary(format!(
                        "zisofs: {} in {} blocks",
                        human_size(extent.len),
                        human_size(1u64.checked_shl(z.block_log2.into()).unwrap_or(0))
                    ))
                    .lazy(zisofs_node, (e.input, extent, z)),
            );
            return Ok(());
        }
        let node = embedded("Content", e.input.nested(extent)).summary(human_size(r.size.into()));
        cx.emit(crate::formats::util::arcutil::check_len(
            node,
            extent,
            r.size.into(),
        ));
        return Ok(());
    }
    if e.path.contains(&dir_extent) {
        cx.diag(Diagnostic::malformed("directory loop").at(extent));
        return Ok(());
    }
    if e.path.len() >= MAX_DEPTH {
        cx.diag(Diagnostic::limit(format!(
            "directories nested deeper than {MAX_DEPTH}"
        )));
        return Ok(());
    }
    let mut path = (*e.path).clone();
    path.push(dir_extent);
    let path = Arc::new(path);
    list_directory(&cx, &e, extent, path).await
}

/// Pushes a node per record in a directory extent (skipping `.` and `..`
/// and directories relocated elsewhere), then the extent itself.
async fn list_directory(cx: &Cx, e: &Entry, extent: Span, path: Arc<Vec<u32>>) -> Result<()> {
    let file = e.input.span;
    let data = cx.read(extent.sub(0, cx.limits().max_read)).await?;
    let mut at = 0usize;
    let mut records = 0u64;
    while at < data.len() {
        let len = usize::from(data.get(at).copied().unwrap_or(0));
        if len == 0 {
            // Records do not cross sector boundaries: skip to the next one.
            let next = to_usize(
                to_u64(at)
                    .saturating_add(1)
                    .div_ceil(SECTOR)
                    .saturating_mul(SECTOR),
            );
            if next <= at {
                break;
            }
            at = next;
            continue;
        }
        if len < 34 {
            cx.diag(
                Diagnostic::malformed("directory record shorter than 34 bytes")
                    .at(extent.sub(to_u64(at), to_u64(len))),
            );
            break;
        }
        let record_span = extent.sub(to_u64(at), to_u64(len));
        let bytes = data.get(at..at.saturating_add(len)).unwrap_or_default();
        records = records.saturating_add(1);
        match load_record(cx, file, e.block_size, bytes, e.joliet).await? {
            Some(r) if r.name != "." && r.name != ".." => {
                let state = Entry {
                    input: e.input,
                    record: record_span,
                    block_size: e.block_size,
                    joliet: e.joliet,
                    path: path.clone(),
                };
                cx.progress(to_u64(at), to_u64(data.len()));
                cx.push(entry_node(r.display_name(), &r, state)).await;
            }
            // The root's "." record carries the SUSP indicator and the
            // extension references (in its continuation area).
            Some(r) if r.name == "." && path.len() == 1 && bytes.len() > 34 => {
                let ctx = RecCtx {
                    joliet: e.joliet,
                    file,
                    block: e.block_size,
                };
                cx.push(
                    struct_node(". (root)", record_span, LE, ctx, record_layout_with)
                        .summary("System Use: SUSP indicator and extension references"),
                )
                .await;
            }
            _ => cx.checkpoint().await,
        }
        at = at.saturating_add(len);
    }
    cx.push(Node::new("Directory extent").span(extent).summary(format!(
        "{}, {records} records (with . and ..), the rest padding",
        human_size(extent.len)
    )))
    .await;
    Ok(())
}

/// A zisofs file: header, block pointers, compressed blocks, and the
/// decompressed content.
async fn zisofs_node(cx: Cx, (input, extent, z): (Input, Span, Zf)) -> Result<()> {
    let header_len = u64::from(z.header).saturating_mul(4).max(16);
    let head = cx.read_avail(extent.sub(0, header_len)).await?;
    let block = cx.block(extent.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.bytes("Magic", 8)
        .check(|b| {
            (b.as_slice() != ZISOFS_MAGIC.as_slice())
                .then(|| Diagnostic::warning("not the zisofs magic"))
        })
        .emit()?;
    f.u32("Uncompressed size")
        .with(|&v, n| n.summary(human_size(v.into())))
        .emit()?;
    f.u8("Header size (4-byte units)").emit()?;
    f.u8("Block size (log2)").emit()?;
    f.bytes("Reserved", 2).emit()?;
    if head.get(..8) != Some(ZISOFS_MAGIC.as_slice()) {
        return Ok(());
    }
    let size = u64::from(u32_le(&head, 8).unwrap_or(z.size));
    let log2 = head.get(13).copied().unwrap_or(z.block_log2);
    if !(15..=17).contains(&log2) {
        cx.diag(Diagnostic::malformed(format!("zisofs block size 2^{log2}")));
        return Ok(());
    }
    let block_size = 1u64 << log2;
    let blocks = size.div_ceil(block_size);
    let table = extent.sub(header_len, blocks.saturating_add(1).saturating_mul(4));
    let pointers = cx.read_avail(table).await?;
    cx.emit(
        Node::new("Block pointers")
            .span(table)
            .value(Value::Bytes(pointers.iter().take(64).copied().collect()))
            .summary(format!(
                "{} pointers for {blocks} blocks",
                pointers.len() / 4
            )),
    );
    // Decompress block by block into a piecewise source.
    let mut list = PieceList::new(table);
    for i in 0..blocks {
        cx.checkpoint().await;
        let a = u64::from(u32_le(&pointers, to_usize(i.saturating_mul(4))).unwrap_or(0));
        let b = u64::from(
            u32_le(&pointers, to_usize(i.saturating_add(1).saturating_mul(4))).unwrap_or(0),
        );
        let want = block_size.min(size.saturating_sub(i.saturating_mul(block_size)));
        if b <= a {
            // An empty block is all zeros.
            list.data(Span::zeros(want));
            continue;
        }
        let span = extent.sub(a, b.saturating_sub(a));
        match crate::codec::decode_span(&cx, span, &Codec::Zlib, Some(block_size)).await {
            Ok(d) => list.data(d.span.sub(0, want)),
            Err(err) => {
                cx.diag(err);
                break;
            }
        }
    }
    let content = list.finish(&cx, "zisofs").await?;
    cx.emit(crate::formats::disk::content_node(&input, content));
    Ok(())
}

// ---------------------------------------------------------------------------
// Path tables

/// Path table entries: (extent, parent, name bytes, span offset, length).
fn path_entries(data: &[u8], big: bool) -> Vec<(u32, u16, Vec<u8>, usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        let len = usize::from(data.get(at).copied().unwrap_or(0));
        if len == 0 {
            break;
        }
        let (extent, parent) = if big {
            (
                u32_be(data, at.saturating_add(2)).unwrap_or(0),
                u16_be(data, at.saturating_add(6)).unwrap_or(0),
            )
        } else {
            (
                u32_le(data, at.saturating_add(2)).unwrap_or(0),
                u16_le(data, at.saturating_add(6)).unwrap_or(0),
            )
        };
        let name_at = at.saturating_add(8);
        let raw = data
            .get(name_at..name_at.saturating_add(len))
            .unwrap_or_default()
            .to_vec();
        let total = 8usize.saturating_add(len).saturating_add(len % 2);
        out.push((extent, parent, raw, at, total));
        at = at.saturating_add(total);
    }
    out
}

async fn path_table(cx: Cx, (span, big, joliet): (Span, bool, bool)) -> Result<()> {
    let data = cx.read(span.sub(0, cx.limits().max_read)).await?;
    let endian = if big { Endian::Big } else { Endian::Little };
    for (i, (extent, parent, raw, at, total)) in path_entries(&data, big).into_iter().enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let name = if raw == [0] {
            "(root)".to_owned()
        } else if joliet {
            crate::text::utf16(&raw, Endian::Big)
        } else {
            String::from_utf8_lossy(&raw).into_owned()
        };
        let espan = span.sub(to_u64(at), to_u64(total));
        cx.progress(to_u64(at), to_u64(data.len()));
        cx.push(
            struct_node(
                format!("Directory {}", i.saturating_add(1)),
                espan,
                endian,
                joliet,
                path_entry_layout,
            )
            .value(text(name))
            .summary(format!("extent {extent}, parent {parent}")),
        )
        .await;
    }
    Ok(())
}

fn path_entry_layout(f: &mut Fields<'_>, joliet: &bool) -> Result<()> {
    let len = f.u8("Name length").emit()?;
    f.u8("Extended attribute length").emit()?;
    f.u32("Extent location").emit()?;
    f.u16("Parent directory number").emit()?;
    f.bytes("Name", len.into())
        .with(|b, n| {
            n.value(text(if *joliet {
                crate::text::utf16(b, Endian::Big)
            } else {
                String::from_utf8_lossy(b).into_owned()
            }))
        })
        .emit()?;
    if len % 2 == 1 {
        f.u8("Padding").emit()?;
    }
    Ok(())
}

/// Path table nodes for a volume: L and M (and their optional copies),
/// the M table checked against the L table.
async fn path_tables(cx: &Cx, file: Span, v: &Volume, prefix: &str) -> Result<Vec<Node>> {
    let block = u64::from(v.block_size.max(1));
    let size = u64::from(v.path_table_size);
    let names = ["L", "optional L", "M", "optional M"];
    let mut out = Vec::new();
    let mut first_l: Option<Vec<u8>> = None;
    for (i, &lba) in v.path_tables.iter().enumerate() {
        if lba == 0 {
            continue;
        }
        let big = i >= 2;
        let span = file.sub(u64::from(lba).saturating_mul(block), size);
        let mut node = Node::new(format!(
            "{prefix} ({})",
            names.get(i).copied().unwrap_or("?")
        ))
        .span(span)
        .lazy(path_table, (span, big, v.joliet));
        if size <= 1 << 20 {
            let data = cx.read_avail(span).await?;
            cx.checkpoint().await;
            let entries = path_entries(&data, big);
            node = node.summary(count(to_u64(entries.len()), "directory", "directories"));
            // Compare (extent, parent, name) with the L table.
            let key: Vec<u8> = entries
                .iter()
                .flat_map(|(e, p, n, _, _)| {
                    e.to_le_bytes()
                        .into_iter()
                        .chain(p.to_le_bytes())
                        .chain(n.iter().copied())
                })
                .collect();
            match &first_l {
                None => first_l = Some(key),
                Some(l) if *l != key => {
                    node = node.diag(Diagnostic::warning("differs from the L path table"));
                }
                Some(_) => {}
            }
        }
        out.push(node);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// El Torito

/// The size of a boot image: from the media type for floppy emulation,
/// else the sector count (512-byte virtual sectors).
fn boot_image_len(media: u8, sectors: u16) -> u64 {
    match media & 0x0f {
        1 => 1_228_800,
        2 => 1_474_560,
        3 => 2_949_120,
        _ => u64::from(sectors).saturating_mul(512),
    }
}

fn validation_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Header id").hex().emit()?;
    f.u8("Platform").enumeration(PLATFORM).emit()?;
    f.u16("Reserved").emit()?;
    f.ascii("Id string", 24).emit()?;
    f.u16("Checksum").hex().emit()?;
    f.bytes("Key", 2).emit()?;
    Ok(())
}

fn boot_entry_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Boot indicator")
        .hex()
        .with(|&v, n| {
            n.summary(if v == 0x88 {
                "bootable"
            } else {
                "not bootable"
            })
        })
        .emit()?;
    let media = f.block().data.get(to_usize(f.pos())).copied().unwrap_or(0);
    f.u8("Media type")
        .with(|_, n| {
            let (set, unknown) = crate::value::decode_flags(MEDIA_FLAGS, (media & 0xf0).into());
            let n = n.value(Value::Enum {
                raw: media.into(),
                bits: 8,
                name: lookup(MEDIA, (media & 0x0f).into()),
            });
            if set.is_empty() && unknown == 0 {
                n
            } else {
                n.summary(set.join(", "))
            }
        })
        .emit()?;
    f.u16("Load segment")
        .hex()
        .with(|&v, n| {
            n.summary(if v == 0 {
                "default (0x7C0)".to_owned()
            } else {
                format!("{v:#x}")
            })
        })
        .emit()?;
    f.u8("System type")
        .hex()
        .desc("Partition type of the emulated hard disk")
        .emit()?;
    f.u8("Unused").emit()?;
    f.u16("Sector count")
        .desc("512-byte virtual sectors loaded at boot")
        .emit()?;
    f.u32("Load RBA").emit()?;
    f.u8("Selection criteria type").emit()?;
    f.bytes("Selection criteria", 19).emit()?;
    Ok(())
}

fn section_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Header indicator")
        .hex()
        .with(|&v, n| {
            n.summary(if v == 0x91 {
                "last section"
            } else {
                "more sections follow"
            })
        })
        .emit()?;
    f.u8("Platform").enumeration(PLATFORM).emit()?;
    f.u16("Section entries").emit()?;
    f.ascii("Id string", 28).emit()?;
    Ok(())
}

fn extension_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Extension indicator").hex().emit()?;
    f.u8("Flags").hex().emit()?;
    f.bytes("Vendor selection criteria", 30).emit()?;
    Ok(())
}

async fn boot_catalog(cx: Cx, (input, span, block_size): (Input, Span, u64)) -> Result<()> {
    let data = cx.read(span.sub(0, SECTOR)).await?;
    // Validation entry.
    let v = span.sub(0, 32);
    let sum = data
        .get(..32)
        .unwrap_or_default()
        .chunks(2)
        .fold(0u16, |a, w| a.wrapping_add(u16_le(w, 0).unwrap_or(0)));
    let platform = data.get(1).copied().unwrap_or(0);
    let mut validation =
        struct_node("Validation entry", v, LE, (), validation_layout).summary(format!(
            "{}, {:?}",
            lookup(PLATFORM, platform.into()).unwrap_or("unknown platform"),
            String::from_utf8_lossy(data.get(4..28).unwrap_or_default())
                .trim_end_matches(['\0', ' '])
        ));
    if data.get(30..32) != Some(&[0x55, 0xaa]) || sum != 0 {
        validation = validation.diag(Diagnostic::warning(
            "bad validation entry (key or checksum)",
        ));
    }
    cx.emit(validation);
    let mut at = 32usize;
    let mut index = 0u32;
    let mut section = 0u32;
    while at.saturating_add(32) <= data.len() {
        let entry = data.get(at..at.saturating_add(32)).unwrap_or_default();
        let indicator = entry.first().copied().unwrap_or(0);
        let espan = span.sub(to_u64(at), 32);
        match indicator {
            0x88 | 0x00 if entry.iter().any(|&b| b != 0) => {
                let media = entry.get(1).copied().unwrap_or(0);
                let sectors = u16_le(entry, 6).unwrap_or(0);
                let rba = u32_le(entry, 8).unwrap_or(0);
                let image = input.span.sub(
                    u64::from(rba).saturating_mul(block_size),
                    boot_image_len(media, sectors),
                );
                let name = if index == 0 {
                    "Default entry".to_owned()
                } else {
                    format!("Section {section} entry {index}")
                };
                let fields = vec![
                    struct_node("Fields", espan, LE, (), boot_entry_layout),
                    embedded("Boot image", input.nested(image)).summary(human_size(image.len)),
                ];
                cx.emit(
                    Node::new(name)
                        .span(espan)
                        .summary(format!(
                            "{}{}, {} at sector {rba}",
                            if indicator == 0x88 { "bootable, " } else { "" },
                            lookup(MEDIA, (media & 0x0f).into()).unwrap_or("?"),
                            human_size(image.len)
                        ))
                        .target(image)
                        .lazy(emit_nodes, Arc::new(fields)),
                );
            }
            0x90 | 0x91 => {
                section = section.saturating_add(1);
                let p = entry.get(1).copied().unwrap_or(0);
                cx.emit(
                    struct_node(
                        format!("Section header {section}"),
                        espan,
                        LE,
                        (),
                        section_header_layout,
                    )
                    .summary(format!(
                        "{}, {} entries{}",
                        lookup(PLATFORM, p.into()).unwrap_or("unknown platform"),
                        u16_le(entry, 2).unwrap_or(0),
                        if indicator == 0x91 { ", last" } else { "" }
                    )),
                );
            }
            0x44 => cx.emit(struct_node(
                "Section entry extension",
                espan,
                LE,
                (),
                extension_layout,
            )),
            _ => break,
        }
        index = index.saturating_add(1);
        at = at.saturating_add(32);
    }
    let rest = span.tail(to_u64(at));
    if !rest.is_empty() {
        cx.emit(Node::new("Unused").span(rest).summary(human_size(rest.len)));
    }
    Ok(())
}

/// The boot images a catalog lists (spans).
async fn boot_images(cx: &Cx, file: Span, catalog: Span, block_size: u64) -> Result<Vec<Span>> {
    let data = cx.read_avail(catalog.sub(0, SECTOR)).await?;
    let mut out = Vec::new();
    for entry in data.get(32..).unwrap_or_default().as_chunks::<32>().0 {
        match entry.first() {
            Some(0x88 | 0x00) if entry.iter().any(|&b| b != 0) => {
                let media = entry.get(1).copied().unwrap_or(0);
                let sectors = u16_le(entry, 6).unwrap_or(0);
                let rba = u32_le(entry, 8).unwrap_or(0);
                out.push(file.sub(
                    u64::from(rba).saturating_mul(block_size),
                    boot_image_len(media, sectors),
                ));
            }
            Some(0x90 | 0x91 | 0x44) => {}
            _ => break,
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Image layout

/// What the layout walk starts from.
#[derive(Clone, Debug)]
struct LayoutState {
    input: Input,
    descriptors: u64,
    path_tables: Vec<Span>,
    roots: Vec<(Span, bool)>,
    block_size: u64,
    catalog: Option<Span>,
    udf: bool,
}

async fn layout(cx: Cx, s: Arc<LayoutState>) -> Result<()> {
    let file = s.input.span;
    let block = s.block_size;
    let mut r = Regions::default();
    r.add(0, DESCRIPTORS_AT, "System area", None);
    r.add(
        DESCRIPTORS_AT,
        s.descriptors.saturating_mul(SECTOR),
        "Volume descriptors",
        None,
    );
    for pt in &s.path_tables {
        r.span(file, round(*pt, file), "Path table");
    }
    if let Some(c) = s.catalog {
        r.span(file, c, "Boot catalog");
        for img in boot_images(&cx, file, c, block).await? {
            r.span(file, img, "Boot image");
        }
    }
    // Walk the directory trees (iteratively, each directory once).
    let mut seen = BTreeSet::new();
    for (root, joliet) in &s.roots {
        let role = if *joliet {
            "Joliet directory"
        } else {
            "Directory"
        };
        let mut stack = vec![*root];
        while let Some(dir) = stack.pop() {
            if seen.len() >= MAX_LAYOUT_DIRS || !seen.insert((dir.offset, *joliet)) {
                continue;
            }
            r.span(file, round(dir, file), role);
            let data = cx.read_avail(dir.sub(0, cx.limits().max_read)).await?;
            let mut at = 0usize;
            while at < data.len() {
                let len = usize::from(data.get(at).copied().unwrap_or(0));
                if len == 0 {
                    at = to_usize(
                        to_u64(at)
                            .saturating_add(1)
                            .div_ceil(SECTOR)
                            .saturating_mul(SECTOR),
                    );
                    continue;
                }
                if len < 34 {
                    break;
                }
                let bytes = data.get(at..at.saturating_add(len)).unwrap_or_default();
                at = at.saturating_add(len);
                cx.checkpoint().await;
                let Some(rec) = parse_record(bytes, *joliet) else {
                    continue;
                };
                if let Some((lba, offset, len)) = rec.continuation {
                    r.span(
                        file,
                        file.sub(
                            u64::from(lba)
                                .saturating_mul(block)
                                .saturating_add(offset.into()),
                            len.into(),
                        ),
                        "Continuation area",
                    );
                }
                if rec.name == "." || rec.name == ".." {
                    continue;
                }
                let extent = file.sub(u64::from(rec.extent).saturating_mul(block), rec.size.into());
                if rec.flags & 0x02 != 0 {
                    stack.push(extent);
                } else if rec.size > 0 {
                    r.span(file, round(extent, file), "File data");
                }
            }
        }
    }
    if seen.len() >= MAX_LAYOUT_DIRS {
        cx.diag(Diagnostic::limit(format!(
            "more than {MAX_LAYOUT_DIRS} directories; the layout is incomplete"
        )));
    }
    r.emit(
        &cx,
        file,
        if s.udf {
            "not referenced by ISO 9660 structures (UDF structures may be here)"
        } else {
            "not referenced by any directory"
        },
    )
    .await;
    Ok(())
}

/// An extent rounded up to whole sectors (the rest of the last sector is
/// padding that belongs to it).
fn round(span: Span, file: Span) -> Span {
    let rel = span.offset.saturating_sub(file.offset);
    file.sub(rel, span.len.next_multiple_of(SECTOR))
}

// ---------------------------------------------------------------------------
// Top level

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let system = cx.read_avail(file.sub(0, DESCRIPTORS_AT)).await?;
    let system_span = file.sub(0, DESCRIPTORS_AT);
    if system.iter().any(|&b| b != 0) {
        cx.emit(
            embedded("System area", input.nested(system_span))
                .summary("boot code / partition table (hybrid image)"),
        );
    } else {
        cx.emit(Node::new("System area").span(system_span).summary("empty"));
    }
    let mut primary: Option<(Volume, Span)> = None;
    let mut joliet: Option<(Volume, Span)> = None;
    let mut boot: Option<u32> = None;
    let mut udf = false;
    let mut enhanced = false;
    let mut label = String::new();
    let mut descriptors = Vec::new();
    for i in 0..MAX_DESCRIPTORS {
        let span = file.sub(
            DESCRIPTORS_AT.saturating_add(i.saturating_mul(SECTOR)),
            SECTOR,
        );
        let head = cx.read_avail(span.sub(0, 7)).await?;
        let kind = head.first().copied().unwrap_or(0);
        let version = head.get(6).copied().unwrap_or(0);
        let id = head.get(1..6).unwrap_or_default();
        let id_text = String::from_utf8_lossy(id).into_owned();
        match id {
            b"CD001" => {
                let name = if kind == 2 && version == 2 {
                    "Enhanced volume descriptor".to_owned()
                } else {
                    lookup(DESCRIPTOR_TYPE, kind.into())
                        .map_or_else(|| format!("Descriptor type {kind}"), capitalize)
                };
                let node = match kind {
                    1 | 2 => {
                        let v = crate::fields::parse(&cx, span, LE, &(), volume_layout).await?;
                        let block = cx.read(span.sub(40, 32)).await?;
                        let vol = decode_text(&block, v.joliet);
                        let summary = if v.joliet {
                            format!("Joliet, {vol:?}")
                        } else if kind == 2 && version == 2 {
                            enhanced = true;
                            format!("ISO 9660:1999, {vol:?}")
                        } else {
                            format!(
                                "{vol:?}, {}",
                                human_size(u64::from(v.blocks).saturating_mul(v.block_size.into()))
                            )
                        };
                        if kind == 1 && primary.is_none() {
                            label = vol;
                            primary = Some((v, span));
                        } else if v.joliet && joliet.is_none() {
                            joliet = Some((v, span));
                        }
                        struct_node(name, span, LE, (), volume_layout).summary(summary)
                    }
                    0 => {
                        let catalog = crate::fields::parse(&cx, span, LE, &(), boot_layout).await?;
                        let sys = cx.read(span.sub(7, 32)).await?;
                        let sys = String::from_utf8_lossy(&sys)
                            .trim_end_matches(['\0', ' '])
                            .to_owned();
                        if sys == "EL TORITO SPECIFICATION" {
                            boot = Some(catalog);
                        }
                        struct_node(name, span, LE, (), boot_layout).summary(sys)
                    }
                    3 => struct_node(name, span, LE, (), partition_layout),
                    _ => struct_node(name, span, LE, (), plain_layout),
                };
                descriptors.push(node);
                if kind == 255 {
                    // UDF's extended area may follow the terminator.
                    let next = cx
                        .read_avail(
                            file.sub(
                                DESCRIPTORS_AT
                                    .saturating_add(i.saturating_add(1).saturating_mul(SECTOR))
                                    .saturating_add(1),
                                5,
                            ),
                        )
                        .await?;
                    if next.as_slice() != b"BEA01" {
                        break;
                    }
                }
            }
            b"BEA01" | b"NSR02" | b"NSR03" | b"TEA01" | b"BOOT2" | b"CDW02" => {
                if id.starts_with(b"NSR") {
                    udf = true;
                }
                let desc = match id {
                    b"BEA01" => "beginning of extended area",
                    b"TEA01" => "end of extended area",
                    b"NSR02" => "UDF (NSR02, ECMA-167 2nd edition)",
                    b"NSR03" => "UDF (NSR03, ECMA-167 3rd edition)",
                    _ => "extended area descriptor",
                };
                descriptors.push(struct_node(id_text, span, LE, (), extended_layout).summary(desc));
                if id == b"TEA01" {
                    break;
                }
            }
            _ => break,
        }
        cx.checkpoint().await;
    }
    let n = to_u64(descriptors.len());
    cx.emit(
        Node::new("Volume descriptors")
            .span(file.sub(DESCRIPTORS_AT, n.saturating_mul(SECTOR)))
            .summary(count(n, "descriptor", "descriptors"))
            .lazy(emit_nodes, Arc::new(descriptors)),
    );
    let mut features: Vec<String> = Vec::new();
    if enhanced {
        features.push("ISO 9660:1999".to_owned());
    }
    let mut all_path_tables = Vec::new();
    let mut roots = Vec::new();
    for (name, vol, prefix) in [
        ("Root directory", primary, "Path table"),
        ("Joliet root directory", joliet, "Joliet path table"),
    ] {
        let Some((v, span)) = vol else {
            continue;
        };
        let block_size = u64::from(v.block_size.max(1));
        let record = span.sub(156, 34);
        let bytes = cx.read(record).await?;
        let Some(r) = parse_record(&bytes, v.joliet) else {
            continue;
        };
        let state = Entry {
            input,
            record,
            block_size,
            joliet: v.joliet,
            path: Arc::new(Vec::new()),
        };
        let root_extent = file.sub(
            u64::from(r.extent).saturating_mul(block_size),
            r.size.into(),
        );
        roots.push((root_extent, v.joliet));
        if name == "Root directory" {
            // Rock Ridge announces itself in the root's "." record.
            let root = file.sub(u64::from(r.extent).saturating_mul(block_size), 255);
            let dot = cx.read_avail(root).await?;
            if susp_entries(system_use(&dot))
                .iter()
                .any(|(s, _, _)| s == b"SP" || s == b"RR")
            {
                features.push("Rock Ridge".to_owned());
            }
        } else {
            features.push("Joliet".to_owned());
        }
        for node in path_tables(&cx, file, &v, prefix).await? {
            if let Some(s) = node.span {
                all_path_tables.push(s);
            }
            cx.emit(node);
        }
        cx.emit(entry_node(name.to_owned(), &r, state).summary(human_size(r.size.into())));
    }
    let block_size = primary.map_or(SECTOR, |(v, _)| u64::from(v.block_size.max(1)));
    let mut catalog_span = None;
    if let Some(catalog) = boot {
        features.push("El Torito".to_owned());
        let span = file.sub(u64::from(catalog).saturating_mul(block_size), SECTOR);
        catalog_span = Some(span);
        cx.emit(
            Node::new("Boot catalog")
                .span(span)
                .lazy(boot_catalog, (input, span, block_size)),
        );
    }
    let mut udf_summary = None;
    if udf {
        match super::udf::load(&cx, input).await? {
            Some(vol) if primary.is_some() => {
                features.push(vol.version());
                cx.emit(
                    Node::new("UDF file system")
                        .summary(format!("{}, {:?}", vol.version(), super::udf::label(&vol)))
                        .lazy(super::udf::volume, input),
                );
            }
            Some(vol) => {
                super::udf::emit(&cx, &vol).await?;
                udf_summary = Some(format!(
                    "{} image {:?}, {}",
                    vol.version(),
                    super::udf::label(&vol),
                    human_size(file.len)
                ));
            }
            None => cx.diag(Diagnostic::warning(
                "no UDF anchor volume descriptor pointer found",
            )),
        }
    }
    let size = primary.map_or(file.len, |(v, _)| {
        u64::from(v.blocks).saturating_mul(v.block_size.into())
    });
    let mut summary = if primary.is_some() {
        format!("ISO 9660 image {label:?}, {}", human_size(size))
    } else if let Some(s) = udf_summary {
        s
    } else if udf {
        format!("UDF image, {}", human_size(file.len))
    } else {
        "ISO 9660 image".to_owned()
    };
    if !features.is_empty() {
        summary = format!("{summary}, {}", features.join(", "));
    }
    if primary.is_some() {
        cx.emit(
            Node::new("Image layout")
                .span(file.sub(0, size))
                .summary("what each sector holds")
                .lazy(
                    layout,
                    Arc::new(LayoutState {
                        input: input.nested(file.sub(0, size)),
                        descriptors: n,
                        path_tables: all_path_tables,
                        roots,
                        block_size,
                        catalog: catalog_span,
                        udf,
                    }),
                ),
        );
    }
    if primary.is_some() && size < file.len {
        cx.emit(Node::new("Data after the volume").span(file.tail(size)));
    }
    cx.annotate(summary);
    Ok(())
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}
