//! ISO 9660 CD/DVD images (with Joliet, Rock Ridge and El Torito), plus the
//! UDF volume recognition sequence.
//!
//! After a 32 KiB system area, 2048-byte volume descriptors (primary,
//! supplementary/Joliet, boot record, partition) run until a terminator. The
//! primary and Joliet descriptors each hold a root directory record;
//! directories are walked lazily from there, file extents are dissected as
//! embedded files. Rock Ridge `NM` entries give POSIX names; El Torito boot
//! records point at a boot catalog whose images are dissected too. UDF
//! volumes (UDF-only discs and the UDF side of bridge discs) are handed to
//! [`super::udf`].

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Field, Fields, struct_node};
use crate::formats::util::arcutil::{count, emit_nodes, hex, human_size, text, uint, unix_mode};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const SECTOR: u64 = 2048;
const DESCRIPTORS_AT: u64 = 16 * SECTOR;
/// Volume descriptors read before giving up on a terminator.
const MAX_DESCRIPTORS: u64 = 64;
const MAX_DEPTH: usize = 64;

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

const PLATFORM: EnumTable = &[(0, "x86"), (1, "PowerPC"), (2, "Mac"), (0xef, "EFI")];
const MEDIA: EnumTable = &[
    (0, "no emulation"),
    (1, "1.2 MB floppy"),
    (2, "1.44 MB floppy"),
    (3, "2.88 MB floppy"),
    (4, "hard disk"),
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

// ---------------------------------------------------------------------------
// Volume descriptors

/// What the dissector needs from a primary or supplementary descriptor.
#[derive(Clone, Copy, Debug)]
struct Volume {
    blocks: u32,
    block_size: u16,
    path_table_size: u32,
    path_table_l: u32,
    joliet: bool,
}

fn volume_layout(f: &mut Fields<'_>, _: &()) -> Result<Volume> {
    let kind = f.u8("Type").enumeration(DESCRIPTOR_TYPE).emit()?;
    f.ascii("Identifier", 5).emit()?;
    f.u8("Version").emit()?;
    f.u8("Flags").hex().emit()?;
    // Joliet is signalled by escape sequences at 88; decide before reading
    // the identifiers.
    let block = f.block().data.clone();
    let joliet = kind == 2 && matches!(block.get(88..91), Some(b"%/@" | b"%/C" | b"%/E"));
    text_field(f, "System identifier", 32, joliet)?;
    text_field(f, "Volume identifier", 32, joliet)?;
    f.skip(8);
    let blocks = both32(f, "Volume space size").emit()?;
    if kind == 2 {
        f.bytes("Escape sequences", 32)
            .with(|b, n| {
                if joliet {
                    let level = match b.get(2) {
                        Some(b'@') => 1,
                        Some(b'C') => 2,
                        _ => 3,
                    };
                    n.summary(format!("Joliet level {level}"))
                } else {
                    n
                }
            })
            .emit()?;
    } else {
        f.skip(32);
    }
    both16(f, "Volume set size").emit()?;
    both16(f, "Volume sequence number").emit()?;
    let block_size = both16(f, "Logical block size").emit()?;
    let path_table_size = both32(f, "Path table size").emit()?;
    let path_table_l = f.u32("L path table location").emit()?;
    f.u32("Optional L path table location").emit()?;
    f.bytes("M path table location", 4)
        .with(|b, n| n.value(uint(u32_be(b, 0).unwrap_or(0).into())))
        .emit()?;
    f.bytes("Optional M path table location", 4)
        .with(|b, n| n.value(uint(u32_be(b, 0).unwrap_or(0).into())))
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
    Ok(Volume {
        blocks,
        block_size,
        path_table_size,
        path_table_l,
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
    Ok(catalog)
}

/// Extended area descriptors (ECMA-167 volume recognition).
fn extended_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Structure type").emit()?;
    f.ascii("Identifier", 5).emit()?;
    f.u8("Version").emit()?;
    Ok(())
}

fn plain_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Type").enumeration(DESCRIPTOR_TYPE).emit()?;
    f.ascii("Identifier", 5).emit()?;
    f.u8("Version").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Directory records

/// A parsed directory record.
#[derive(Clone, Debug, Default)]
struct Record {
    extent: u32,
    size: u32,
    flags: u8,
    name: String,
    /// Rock Ridge: POSIX name and mode, if present.
    rr_name: Option<String>,
    rr_mode: Option<u32>,
}

impl Record {
    fn is_dir(&self) -> bool {
        self.flags & 0x02 != 0
    }

    fn display_name(&self) -> String {
        if let Some(n) = &self.rr_name {
            return n.clone();
        }
        let n = self.name.strip_suffix(";1").unwrap_or(&self.name);
        let n = n.strip_suffix('.').unwrap_or(n);
        n.to_owned()
    }
}

fn parse_record(b: &[u8], joliet: bool) -> Option<Record> {
    let len = *b.first()?;
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
    // System use area (Rock Ridge), after the padded name.
    let su_at = 33usize
        .saturating_add(name_len)
        .saturating_add(usize::from(name_len % 2 == 0));
    let su = b.get(su_at..usize::from(len)).unwrap_or_default();
    for (sig, data) in susp_entries(su) {
        match &sig {
            b"NM" => {
                let flags = data.first().copied().unwrap_or(0);
                if flags & 0x06 == 0 {
                    let part = String::from_utf8_lossy(data.get(1..).unwrap_or_default());
                    r.rr_name.get_or_insert_with(String::new).push_str(&part);
                }
            }
            b"PX" => r.rr_mode = u32_le(data, 0),
            _ => {}
        }
    }
    Some(r)
}

/// SUSP entries: two-letter signature, length, version, data.
fn susp_entries(su: &[u8]) -> Vec<([u8; 2], &[u8])> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let (Some(&a), Some(&b), Some(&len)) = (
        su.get(at),
        su.get(at.saturating_add(1)),
        su.get(at.saturating_add(2)),
    ) {
        let len = usize::from(len);
        if len < 4 || !a.is_ascii_uppercase() {
            break;
        }
        let Some(data) = su.get(at.saturating_add(4)..at.saturating_add(len)) else {
            break;
        };
        out.push(([a, b], data));
        at = at.saturating_add(len);
    }
    out
}

fn record_layout(f: &mut Fields<'_>, joliet: &bool) -> Result<()> {
    let joliet = *joliet;
    let len = f.u8("Record length").emit()?;
    f.u8("Extended attribute length").emit()?;
    both32(f, "Extent location").emit()?;
    both32(f, "Data length")
        .with(|&s, n| n.summary(human_size(s.into())))
        .emit()?;
    f.bytes("Recording time", 7)
        .with(|b, n| match record_time(b) {
            Some(t) => n.value(Value::Timestamp { unix_seconds: t }),
            None => n,
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
        f.skip(1);
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
        f.node(
            Node::new("System use (SUSP)")
                .span(span)
                .lazy(susp_node, (span, Arc::new(data))),
        );
    }
    Ok(())
}

const SUSP_NAMES: EnumTable = &[
    (0x5350, "SP: SUSP indicator"),
    (0x4345, "CE: continuation area"),
    (0x5354, "ST: terminator"),
    (0x4552, "ER: extensions reference"),
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
];

async fn susp_node(cx: Cx, (span, data): (Span, Arc<Vec<u8>>)) -> Result<()> {
    let mut at = 0u64;
    for (sig, body) in susp_entries(&data) {
        let len = to_u64(body.len()).saturating_add(4);
        let key = u64::from(u16::from_be_bytes(sig));
        let name = crate::value::lookup(SUSP_NAMES, key)
            .map_or_else(|| String::from_utf8_lossy(&sig).into_owned(), str::to_owned);
        let mut node = Node::new(name).span(span.sub(at, len));
        match &sig {
            b"NM" | b"ER" => {
                let t = String::from_utf8_lossy(body.get(1..).unwrap_or_default()).into_owned();
                node = node.value(text(t));
            }
            b"PX" => {
                let mode = u32_le(body, 0).unwrap_or(0);
                node = node
                    .value(uint(mode.into()))
                    .summary(format!("0o{mode:o} {}", unix_mode(mode.into())));
            }
            b"SL" => {
                // Components: flags, length, text.
                let mut parts = Vec::new();
                let mut i = 1usize;
                while let (Some(&flags), Some(&l)) = (body.get(i), body.get(i.saturating_add(1))) {
                    let start = i.saturating_add(2);
                    let comp = body
                        .get(start..start.saturating_add(usize::from(l)))
                        .unwrap_or_default();
                    parts.push(match flags & 0x0e {
                        0x02 => ".".to_owned(),
                        0x04 => "..".to_owned(),
                        0x08 => String::new(),
                        _ => String::from_utf8_lossy(comp).into_owned(),
                    });
                    i = start.saturating_add(usize::from(l));
                }
                node = node.value(text(parts.join("/")));
            }
            _ => {}
        }
        cx.emit(node);
        at = at.saturating_add(len);
    }
    Ok(())
}

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
    let summary = if r.is_dir() {
        "directory".to_owned()
    } else {
        let mut s = human_size(r.size.into());
        if let Some(m) = r.rr_mode {
            s = format!("{s}, {}", unix_mode(m.into()));
        }
        s
    };
    Node::new(name)
        .span(state.record)
        .summary(summary)
        .lazy(crate::expander!(self::entry: Entry), state)
}

async fn entry(cx: Cx, e: Entry) -> Result<()> {
    let bytes = cx.read(e.record).await?;
    let r = parse_record(&bytes, e.joliet)
        .ok_or_else(|| Diagnostic::malformed("bad directory record").at(e.record))?;
    cx.emit(struct_node(
        "Directory record",
        e.record,
        LE,
        e.joliet,
        record_layout,
    ));
    let file = e.input.span;
    let extent = file.sub(
        u64::from(r.extent).saturating_mul(e.block_size),
        r.size.into(),
    );
    if !r.is_dir() {
        if r.size > 0 {
            let node =
                embedded("Content", e.input.nested(extent)).summary(human_size(r.size.into()));
            cx.emit(crate::formats::util::arcutil::check_len(
                node,
                extent,
                r.size.into(),
            ));
        }
        return Ok(());
    }
    if e.path.contains(&r.extent) {
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
    path.push(r.extent);
    let path = Arc::new(path);
    list_directory(&cx, &e, extent, path).await
}

/// Pushes a node per record in a directory extent (skipping `.` and `..`).
async fn list_directory(cx: &Cx, e: &Entry, extent: Span, path: Arc<Vec<u32>>) -> Result<()> {
    let data = cx.read(extent.sub(0, cx.limits().max_read)).await?;
    let mut at = 0usize;
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
        if let Some(r) = parse_record(bytes, e.joliet)
            && r.name != "."
            && r.name != ".."
        {
            let state = Entry {
                input: e.input,
                record: record_span,
                block_size: e.block_size,
                joliet: e.joliet,
                path: path.clone(),
            };
            cx.progress(to_u64(at), to_u64(data.len()));
            cx.push(entry_node(r.display_name(), &r, state)).await;
        } else {
            cx.checkpoint().await;
        }
        at = at.saturating_add(len);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Path table and El Torito

async fn path_table(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span.sub(0, cx.limits().max_read)).await?;
    let mut at = 0usize;
    let mut index = 1u32;
    while at < data.len() {
        let len = usize::from(data.get(at).copied().unwrap_or(0));
        if len == 0 {
            break;
        }
        let extent = u32_le(&data, at.saturating_add(2)).unwrap_or(0);
        let parent = u16_le(&data, at.saturating_add(6)).unwrap_or(0);
        let name_at = at.saturating_add(8);
        let raw = data
            .get(name_at..name_at.saturating_add(len))
            .unwrap_or_default();
        let name = if raw == [0] {
            "(root)".to_owned()
        } else {
            String::from_utf8_lossy(raw).into_owned()
        };
        let total = 8usize.saturating_add(len).saturating_add(len % 2);
        cx.progress(to_u64(at), to_u64(data.len()));
        cx.push(
            Node::new(format!("{index}: {name}"))
                .span(span.sub(to_u64(at), to_u64(total)))
                .summary(format!("extent {extent}, parent {parent}")),
        )
        .await;
        index = index.saturating_add(1);
        at = at.saturating_add(total);
    }
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
    let mut validation = Node::new("Validation entry").span(v).summary(format!(
        "{}, {}",
        crate::value::lookup(PLATFORM, platform.into()).unwrap_or("unknown platform"),
        String::from_utf8_lossy(data.get(4..28).unwrap_or_default()).trim_end_matches(['\0', ' '])
    ));
    if data.get(30..32) != Some(&[0x55, 0xaa]) || sum != 0 {
        validation = validation.diag(Diagnostic::warning(
            "bad validation entry (key or checksum)",
        ));
    }
    cx.emit(validation);
    let mut at = 32usize;
    let mut index = 0u32;
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
                    u64::from(sectors).saturating_mul(512),
                );
                let fields = vec![
                    Node::new("Boot indicator")
                        .span(espan.sub(0, 1))
                        .value(hex(indicator.into()))
                        .summary(if indicator == 0x88 {
                            "bootable"
                        } else {
                            "not bootable"
                        }),
                    Node::new("Media type")
                        .span(espan.sub(1, 1))
                        .value(Value::Enum {
                            raw: media.into(),
                            bits: 8,
                            name: crate::value::lookup(MEDIA, (media & 0x0f).into()),
                        }),
                    Node::new("Load segment")
                        .span(espan.sub(2, 2))
                        .value(hex(u16_le(entry, 2).unwrap_or(0).into())),
                    Node::new("System type")
                        .span(espan.sub(4, 1))
                        .value(hex(entry.get(4).copied().unwrap_or(0).into())),
                    Node::new("Sector count")
                        .span(espan.sub(6, 2))
                        .value(uint(sectors.into()))
                        .summary("512-byte virtual sectors"),
                    Node::new("Load RBA")
                        .span(espan.sub(8, 4))
                        .value(uint(rba.into()))
                        .target(image),
                    embedded("Boot image", input.nested(image)),
                ];
                let name = if index == 0 {
                    "Default entry".to_owned()
                } else {
                    format!("Section entry {index}")
                };
                cx.emit(
                    Node::new(name)
                        .span(espan)
                        .summary(format!(
                            "{}, {}",
                            crate::value::lookup(MEDIA, (media & 0x0f).into()).unwrap_or("?"),
                            human_size(image.len)
                        ))
                        .lazy(emit_nodes, Arc::new(fields)),
                );
            }
            0x90 | 0x91 => {
                let p = entry.get(1).copied().unwrap_or(0);
                cx.emit(Node::new("Section header").span(espan).summary(format!(
                    "{}, {} entries{}",
                    crate::value::lookup(PLATFORM, p.into()).unwrap_or("unknown platform"),
                    u16_le(entry, 2).unwrap_or(0),
                    if indicator == 0x91 { ", last" } else { "" }
                )));
            }
            _ => break,
        }
        index = index.saturating_add(1);
        at = at.saturating_add(32);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Top level

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let system = cx.read_avail(file.sub(0, 512)).await?;
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
    let mut label = String::new();
    let mut descriptors = Vec::new();
    for i in 0..MAX_DESCRIPTORS {
        let span = file.sub(
            DESCRIPTORS_AT.saturating_add(i.saturating_mul(SECTOR)),
            SECTOR,
        );
        let head = cx.read_avail(span.sub(0, 7)).await?;
        let kind = head.first().copied().unwrap_or(0);
        let id = head.get(1..6).unwrap_or_default();
        let id_text = String::from_utf8_lossy(id).into_owned();
        match id {
            b"CD001" => {
                let name = crate::value::lookup(DESCRIPTOR_TYPE, kind.into())
                    .map_or_else(|| format!("Descriptor type {kind}"), capitalize);
                let node = match kind {
                    1 | 2 => {
                        let v = crate::fields::parse(&cx, span, LE, &(), volume_layout).await?;
                        let block = cx.read(span.sub(40, 32)).await?;
                        let vol = decode_text(&block, v.joliet);
                        let summary = if v.joliet {
                            format!("Joliet, {vol:?}")
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
                    _ => struct_node(name, span, LE, (), plain_layout),
                };
                descriptors.push(node);
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
    for (name, vol) in [
        ("Root directory", primary),
        ("Joliet root directory", joliet),
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
        if name == "Root directory" {
            // Rock Ridge announces itself in the root's "." record.
            let root = file.sub(u64::from(r.extent).saturating_mul(block_size), 255);
            let dot = cx.read_avail(root).await?;
            let dot_len = usize::from(dot.first().copied().unwrap_or(0));
            if dot.get(34..dot_len).is_some_and(|su| {
                susp_entries(su)
                    .iter()
                    .any(|(s, _)| s == b"SP" || s == b"RR")
            }) {
                features.push("Rock Ridge".to_owned());
            }
            let pt = file.sub(
                u64::from(v.path_table_l).saturating_mul(block_size),
                v.path_table_size.into(),
            );
            cx.emit(Node::new("Path table").span(pt).lazy(path_table, pt));
        } else {
            features.push("Joliet".to_owned());
        }
        cx.emit(entry_node(name.to_owned(), &r, state).summary(human_size(r.size.into())));
    }
    if let Some(catalog) = boot {
        features.push("El Torito".to_owned());
        let block_size = primary.map_or(SECTOR, |(v, _)| u64::from(v.block_size.max(1)));
        let span = file.sub(u64::from(catalog).saturating_mul(block_size), SECTOR);
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
