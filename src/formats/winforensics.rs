//! Windows forensic artifacts: jump lists, the Win95–XP Recycle Bin index,
//! NTFS change journal and MFT records, Task Scheduler jobs, Outlook
//! autocomplete and Outlook Express stores, the RDP bitmap cache, Internet
//! shortcuts, and Windows 3.x Program Manager groups, Cardfile and Clipboard
//! files.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::{Block, Cx};
use crate::declare_format;
use crate::dsl::{Cursor, Path, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::datakit::{clip, hex, size, text, uint};
use crate::formats::{Head, Input, Probe, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;

fn filetime(ticks: u64) -> Value {
    Value::Timestamp {
        unix_seconds: crate::text::filetime_to_unix(ticks),
    }
}

const FILE_ATTRIBUTES: FlagTable = &[
    flag(0x0001, "READONLY"),
    flag(0x0002, "HIDDEN"),
    flag(0x0004, "SYSTEM"),
    flag(0x0010, "DIRECTORY"),
    flag(0x0020, "ARCHIVE"),
    flag(0x0040, "DEVICE"),
    flag(0x0080, "NORMAL"),
    flag(0x0100, "TEMPORARY"),
    flag(0x0200, "SPARSE_FILE"),
    flag(0x0400, "REPARSE_POINT"),
    flag(0x0800, "COMPRESSED"),
    flag(0x1000, "OFFLINE"),
    flag(0x2000, "NOT_CONTENT_INDEXED"),
    flag(0x4000, "ENCRYPTED"),
    flag(0x1000_0000, "DIRECTORY (index view)"),
];

// ---------------------------------------------------------------------------
// Jump lists: *.customDestinations-ms

fn custom_destinations_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(2)
        && u32_le(h.data, 4).is_some_and(|n| (1..=64).contains(&n))
        && u32_le(h.data, 8) == Some(0)
        && u32_le(h.data, 12).is_some_and(|t| t <= 2)
        && h.tail.ends_with(b"\xab\xfb\xbf\xba")
}

declare_format!(pub CUSTOM_DESTINATIONS = "custom-destinations", "Windows jump list (customDestinations-ms)", ["customdestinations-ms"], "application/x-ms-jumplist",
    Probe::Custom(custom_destinations_probe), custom_destinations);

const CATEGORY_TYPES: EnumTable = &[(0, "custom"), (1, "known"), (2, "tasks")];
const KNOWN_CATEGORIES: EnumTable = &[(1, "Frequent"), (2, "Recent")];
const JUMPLIST_FOOTER: u32 = 0xbabf_fbab;

/// The length of the shell link at the start of `region`, found by walking
/// its optional parts (MS-SHLLINK).
async fn lnk_len(cx: &Cx, region: Span) -> Result<u64> {
    let mut cur = Cursor::new(cx, region, LE);
    let head = cur.bytes(0x4c).await?;
    if u32_le(&head, 0) != Some(0x4c) {
        return Err(Diagnostic::malformed("not a shell link header").at(region.sub(0, 4)));
    }
    let flags = u32_le(&head, 0x14).unwrap_or(0);
    if flags & 0x1 != 0 {
        let n = cur.u16().await?;
        cur.skip(n.into());
    }
    if flags & 0x2 != 0 {
        let start = cur.pos();
        let n = cur.u32().await?;
        cur.seek(start.saturating_add(u64::from(n).max(4)));
    }
    let unit = if flags & 0x80 != 0 { 2u64 } else { 1 };
    for bit in [0x4u32, 0x8, 0x10, 0x20, 0x40] {
        if flags & bit != 0 {
            let n = cur.u16().await?;
            cur.skip(u64::from(n).saturating_mul(unit));
        }
    }
    for _ in 0..256 {
        let start = cur.pos();
        let n = cur.u32().await?;
        if n < 4 {
            return Ok(cur.pos());
        }
        cur.seek(start.saturating_add(n.into()));
    }
    Err(Diagnostic::limit("too many extra data blocks").at(region))
}

async fn custom_destinations(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Format version").emit()?;
    let categories = f.u32("Number of categories").emit()?;
    f.u32("Reserved").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(12);
    let mut links = 0u32;
    for i in 0..categories {
        let start = cur.pos();
        let kind = cur.u32().await?;
        let (name, entries) = match kind {
            0 => {
                let chars = cur.u16().await?;
                let raw = cur.bytes(u64::from(chars).saturating_mul(2)).await?;
                let name = crate::text::utf16(&raw, LE);
                (format!("Custom category {name:?}"), Some(cur.u32().await?))
            }
            1 => {
                let id = cur.u32().await?;
                (
                    format!(
                        "Known category: {}",
                        lookup(KNOWN_CATEGORIES, id.into()).unwrap_or("?")
                    ),
                    None,
                )
            }
            2 => ("Tasks".to_owned(), Some(cur.u32().await?)),
            _ => {
                cx.diag(
                    Diagnostic::malformed(format!("unknown category type {kind}"))
                        .at(cur.since(start)),
                );
                break;
            }
        };
        let mut lnks = Vec::new();
        for _ in 0..entries.unwrap_or(0).min(4096) {
            let at = cur.pos();
            cur.skip(16);
            let len = lnk_len(&cx, file.tail(cur.pos())).await?;
            lnks.push((at, len));
            cur.skip(len);
        }
        let footer = cur.u32().await?;
        links = links.saturating_add(u32::try_from(lnks.len()).unwrap_or(u32::MAX));
        let mut node = Node::new(name)
            .span(cur.since(start))
            .value(Value::Enum {
                raw: kind.into(),
                bits: 32,
                name: lookup(CATEGORY_TYPES, kind.into()),
            })
            .summary(format!("{} links", lnks.len()))
            .lazy(destination_entries, (input, lnks));
        if footer != JUMPLIST_FOOTER {
            node = node.diag(Diagnostic::warning(format!(
                "category footer is {footer:#x}, expected {JUMPLIST_FOOTER:#x}"
            )));
        }
        cx.push(node.desc(format!("Category {i}"))).await;
    }
    cx.annotate(format!(
        "Jump list (custom destinations), {categories} categories, {links} links"
    ));
    Ok(())
}

async fn destination_entries(cx: Cx, (input, lnks): (Input, Vec<(u64, u64)>)) -> Result<()> {
    let file = input.span;
    for (i, (at, len)) in lnks.into_iter().enumerate() {
        let entry = file.sub(at, len.saturating_add(16));
        cx.push(
            Node::new(format!("Entry {i}"))
                .span(entry)
                .lazy(destination_entry, (input, at, len)),
        )
        .await;
    }
    Ok(())
}

async fn destination_entry(cx: Cx, (input, at, len): (Input, u64, u64)) -> Result<()> {
    let file = input.span;
    let block = cx.block(file.sub(at, 16)).await?;
    Fields::emitting(&cx, &block, LE)
        .guid("Shell link class")
        .emit()?;
    cx.emit(embedded_as(
        "Shell link",
        input.nested(file.sub(at.saturating_add(16), len)),
        &crate::formats::lnk::FORMAT,
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Recycle Bin INFO2 (Windows 95 to XP)

fn info2_probe(h: &Head<'_>) -> bool {
    let record = u32_le(h.data, 12).map_or(0, u64::from);
    u32_le(h.data, 0).is_some_and(|v| (3..=5).contains(&v))
        && (record == 280 || record == 800)
        && h.len >= 20
        && h.len.saturating_sub(20).is_multiple_of(record)
}

declare_format!(pub INFO2 = "recycle-bin-info2", "Windows Recycle Bin index (INFO2)", [], "application/x-ms-recycle-bin",
    Probe::Custom(info2_probe), info2);

record! {
    pub struct Info2Header {
        version: u32 "Format version",
        entries: u32 "Number of entries" .desc("Not maintained reliably by every Windows version"),
        _unknown: u32 "Unknown",
        record_size: u32 "Record size",
        total: u32 "Total size of deleted files" .with(|&v, n| n.summary(size(v.into()))),
    }
}

fn info2_layout(f: &mut Fields<'_>, unicode: &bool) -> Result<(String, u32, u64)> {
    let ansi = f.ascii("Original path (ANSI)", 260).emit()?;
    let index = f.u32("Record number").emit()?;
    f.u32("Drive number")
        .with(|&d, n| {
            n.summary(format!(
                "{}:",
                char::from(b'A'.saturating_add(u8::try_from(d).unwrap_or(0)))
            ))
        })
        .emit()?;
    let deleted = f.u64("Deletion time").filetime().emit()?;
    f.u32("Size on disk")
        .with(|&v, n| n.summary(size(v.into())))
        .emit()?;
    let path = if *unicode {
        f.utf16("Original path (Unicode)", 260).emit()?
    } else {
        ansi
    };
    Ok((path, index, deleted))
}

async fn info2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, Info2Header::SIZE);
    let h: Info2Header = read_record(&cx, span, LE).await?;
    cx.emit(Info2Header::node("Header", span, LE));
    let record = u64::from(h.record_size);
    let unicode = record == 800;
    let count = file.len.saturating_sub(20).checked_div(record).unwrap_or(0);
    let mut deleted = 0u64;
    for i in 0..count {
        let span = file.sub(20u64.saturating_add(i.saturating_mul(record)), record);
        let block = cx.block(span).await?;
        let (path, index, time) = info2_layout(&mut Fields::new(&block, LE), &unicode)?;
        // Restored or purged entries have the first byte of the ANSI path cleared.
        let purged = block.data.first() == Some(&0);
        if purged {
            deleted = deleted.saturating_add(1);
        }
        let name = format!("Dc{index}");
        let mut node = struct_node(name, span, LE, unicode, info2_layout)
            .value(filetime(time))
            .summary(path);
        if purged {
            node = node.diag(Diagnostic::note(
                "restored or purged (first path byte cleared)",
            ));
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "Recycle Bin INFO2 v{}, {count} records ({deleted} restored or purged)",
        h.version
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// NTFS change journal ($UsnJrnl:$J)

fn usn_valid(data: &[u8]) -> bool {
    let len = u32_le(data, 0).map_or(0, u64::from);
    let (major, minor) = (u16_le(data, 4), u16_le(data, 6));
    let (name_len, name_off) = match major {
        Some(2) => (u16_le(data, 56), u16_le(data, 58)),
        Some(3) => (u16_le(data, 72), u16_le(data, 74)),
        _ => return false,
    };
    let fixed = if major == Some(2) { 60 } else { 76 };
    minor == Some(0)
        && name_off == Some(fixed)
        && len.is_multiple_of(8)
        && (64..=0x1000).contains(&len)
        && u64::from(fixed).saturating_add(name_len.map_or(0, u64::from)) <= len
}

fn usn_probe(h: &Head<'_>) -> bool {
    usn_valid(h.data)
}

declare_format!(pub USN = "usn-journal", "NTFS change journal ($UsnJrnl:$J)", [], "application/x-ntfs-usn",
    Probe::Custom(usn_probe), usn_journal);

const USN_REASONS: FlagTable = &[
    flag(0x0000_0001, "DATA_OVERWRITE"),
    flag(0x0000_0002, "DATA_EXTEND"),
    flag(0x0000_0004, "DATA_TRUNCATION"),
    flag(0x0000_0010, "NAMED_DATA_OVERWRITE"),
    flag(0x0000_0020, "NAMED_DATA_EXTEND"),
    flag(0x0000_0040, "NAMED_DATA_TRUNCATION"),
    flag(0x0000_0100, "FILE_CREATE"),
    flag(0x0000_0200, "FILE_DELETE"),
    flag(0x0000_0400, "EA_CHANGE"),
    flag(0x0000_0800, "SECURITY_CHANGE"),
    flag(0x0000_1000, "RENAME_OLD_NAME"),
    flag(0x0000_2000, "RENAME_NEW_NAME"),
    flag(0x0000_4000, "INDEXABLE_CHANGE"),
    flag(0x0000_8000, "BASIC_INFO_CHANGE"),
    flag(0x0001_0000, "HARD_LINK_CHANGE"),
    flag(0x0002_0000, "COMPRESSION_CHANGE"),
    flag(0x0004_0000, "ENCRYPTION_CHANGE"),
    flag(0x0008_0000, "OBJECT_ID_CHANGE"),
    flag(0x0010_0000, "REPARSE_POINT_CHANGE"),
    flag(0x0020_0000, "STREAM_CHANGE"),
    flag(0x0040_0000, "TRANSACTED_CHANGE"),
    flag(0x0080_0000, "INTEGRITY_CHANGE"),
    flag(0x8000_0000, "CLOSE"),
];

const USN_SOURCES: FlagTable = &[
    flag(1, "DATA_MANAGEMENT"),
    flag(2, "AUXILIARY_DATA"),
    flag(4, "REPLICATION_MANAGEMENT"),
    flag(8, "CLIENT_REPLICATION_MANAGEMENT"),
];

/// An NTFS file reference: 48-bit record number and 16-bit sequence.
fn file_reference(v: u64, node: Node) -> Node {
    node.summary(format!(
        "record {}, sequence {}",
        v & 0xffff_ffff_ffff,
        v >> 48
    ))
}

fn usn_layout(f: &mut Fields<'_>, _: &()) -> Result<(String, u64, u32)> {
    let len = f.u32("Record length").emit()?;
    let major = f.u16("Major version").emit()?;
    f.u16("Minor version").emit()?;
    if major >= 3 {
        f.bytes("File reference (128-bit)", 16).emit()?;
        f.bytes("Parent file reference (128-bit)", 16).emit()?;
    } else {
        f.u64("File reference")
            .hex()
            .with(|&v, n| file_reference(v, n))
            .emit()?;
        f.u64("Parent file reference")
            .hex()
            .with(|&v, n| file_reference(v, n))
            .emit()?;
    }
    f.u64("USN").hex().emit()?;
    let time = f.u64("Timestamp").filetime().emit()?;
    let reason = f.u32("Reason").flags(USN_REASONS).emit()?;
    f.u32("Source info").flags(USN_SOURCES).emit()?;
    f.u32("Security ID").emit()?;
    f.u32("File attributes").flags(FILE_ATTRIBUTES).emit()?;
    let name_len = f.u16("File name length").emit()?;
    let name_off = f.u16("File name offset").hex().emit()?;
    f.seek(name_off.into());
    let name = f.utf16("File name", u64::from(name_len) / 2).emit()?;
    let _ = len;
    Ok((name, time, reason))
}

fn reason_text(reason: u32) -> String {
    let names: Vec<&str> = USN_REASONS
        .iter()
        .filter(|d| u64::from(reason) & d.mask == d.value)
        .map(|d| d.name)
        .collect();
    names.join(" | ")
}

async fn usn_journal(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    let mut count = 0u64;
    let mut first = None;
    while at.saturating_add(8) <= file.len {
        let head = cx.read_avail(file.sub(at, 8)).await?;
        let len = u64::from(u32_le(&head, 0).unwrap_or(0));
        if len == 0 {
            // Padding up to the next page, or a sparse (zeroed) region.
            let zeros = cx.read_avail(file.sub(at, 0x10000)).await?;
            let skip = zeros
                .iter()
                .position(|&b| b != 0)
                .map_or(to_u64(zeros.len()), |p| to_u64(p) & !7);
            if skip == 0 {
                break;
            }
            at = at.saturating_add(skip);
            continue;
        }
        let span = file.sub(at, len);
        let block = cx.block(span).await?;
        if !usn_valid(&block.data) {
            cx.diag(Diagnostic::malformed("invalid USN record").at(file.sub(at, 8)));
            break;
        }
        let (name, time, reason) = usn_layout(&mut Fields::new(&block, LE), &())?;
        first.get_or_insert(time);
        count = count.saturating_add(1);
        cx.push(
            struct_node(name, span, LE, (), usn_layout)
                .value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(time),
                })
                .summary(reason_text(reason)),
        )
        .await;
        at = at.saturating_add(len);
    }
    cx.annotate(format!("NTFS change journal, {count} records"));
    Ok(())
}

// ---------------------------------------------------------------------------
// NTFS master file table ($MFT) records

fn mft_probe(h: &Head<'_>) -> bool {
    let alloc = u32_le(h.data, 28).map_or(0, u64::from);
    h.starts_with(b"FILE")
        && u16_le(h.data, 4).is_some_and(|o| o == 0x30 || o == 0x2a)
        && (alloc == 1024 || alloc == 4096)
        && u16_le(h.data, 20).is_some_and(|o| u64::from(o) < alloc && o >= 0x30)
        && h.len.is_multiple_of(alloc)
}

declare_format!(pub MFT = "ntfs-mft", "NTFS master file table ($MFT)", [], "application/x-ntfs-mft",
    Probe::Custom(mft_probe), mft);

const MFT_FLAGS: FlagTable = &[
    flag(1, "IN_USE"),
    flag(2, "DIRECTORY"),
    flag(4, "EXTENSION"),
    flag(8, "SPECIAL_INDEX"),
];

const ATTRIBUTE_TYPES: EnumTable = &[
    (0x10, "$STANDARD_INFORMATION"),
    (0x20, "$ATTRIBUTE_LIST"),
    (0x30, "$FILE_NAME"),
    (0x40, "$OBJECT_ID"),
    (0x50, "$SECURITY_DESCRIPTOR"),
    (0x60, "$VOLUME_NAME"),
    (0x70, "$VOLUME_INFORMATION"),
    (0x80, "$DATA"),
    (0x90, "$INDEX_ROOT"),
    (0xa0, "$INDEX_ALLOCATION"),
    (0xb0, "$BITMAP"),
    (0xc0, "$REPARSE_POINT"),
    (0xd0, "$EA_INFORMATION"),
    (0xe0, "$EA"),
    (0x100, "$LOGGED_UTILITY_STREAM"),
];

const ATTRIBUTE_FLAGS: FlagTable = &[
    flag(1, "COMPRESSED"),
    flag(0x4000, "ENCRYPTED"),
    flag(0x8000, "SPARSE"),
];
const NAMESPACES: EnumTable = &[(0, "POSIX"), (1, "Win32"), (2, "DOS"), (3, "Win32 & DOS")];

/// Reads one MFT record and undoes the update sequence fixups (the last two
/// bytes of every 512-byte sector are stored in the update sequence array).
async fn mft_record(cx: &Cx, span: Span) -> Result<(Block, Option<Diagnostic>)> {
    let mut block = cx.block(span).await?;
    let data = &mut block.data;
    let usa = to_usize(u16_le(data, 4).unwrap_or(0).into());
    let count = usize::from(u16_le(data, 6).unwrap_or(0));
    let usn = u16_le(data, usa);
    let mut problem = None;
    for i in 1..count {
        let end = i.saturating_mul(512);
        let Some(fix) = data
            .get(
                usa.saturating_add(i.saturating_mul(2))
                    ..usa.saturating_add(i.saturating_mul(2)).saturating_add(2),
            )
            .map(<[u8]>::to_vec)
        else {
            break;
        };
        let Some(slot) = data.get_mut(end.saturating_sub(2)..end) else {
            break;
        };
        if usn.is_some_and(|u| u.to_le_bytes() != *slot) {
            problem = Some(Diagnostic::warning(format!(
                "sector {i} does not end with the update sequence number (torn write)"
            )));
        }
        slot.copy_from_slice(&fix);
    }
    Ok((block, problem))
}

fn mft_header_layout(f: &mut Fields<'_>, _: &()) -> Result<(u16, u16)> {
    f.ascii("Signature", 4).emit()?;
    f.u16("Update sequence offset").hex().emit()?;
    f.u16("Update sequence size (words)").emit()?;
    f.u64("$LogFile sequence number").emit()?;
    f.u16("Sequence number").emit()?;
    f.u16("Hard link count").emit()?;
    let first = f.u16("First attribute offset").hex().emit()?;
    let flags = f.u16("Flags").flags(MFT_FLAGS).emit()?;
    f.u32("Used size").emit()?;
    f.u32("Allocated size").emit()?;
    f.u64("Base record")
        .hex()
        .with(|&v, n| if v == 0 { n } else { file_reference(v, n) })
        .emit()?;
    f.u16("Next attribute ID").emit()?;
    Ok((first, flags))
}

/// One attribute's location and identity, found by walking a record.
#[derive(Clone, Debug)]
struct MftAttr {
    offset: u64,
    len: u64,
    kind: u32,
    name: String,
    resident: bool,
}

fn mft_attributes(data: &[u8], first: u16) -> Vec<MftAttr> {
    let mut out = Vec::new();
    let mut at = usize::from(first);
    while out.len() < 256 {
        let kind = u32_le(data, at).unwrap_or(u32::MAX);
        let len = u32_le(data, at.saturating_add(4)).map_or(0, |l| to_usize(l.into()));
        if kind == u32::MAX || len < 16 || at.saturating_add(len) > data.len() {
            break;
        }
        let name_len = usize::from(data.get(at.saturating_add(9)).copied().unwrap_or(0));
        let name_off = usize::from(u16_le(data, at.saturating_add(10)).unwrap_or(0));
        let start = at.saturating_add(name_off);
        let raw = data
            .get(start..start.saturating_add(name_len.saturating_mul(2)))
            .unwrap_or_default();
        out.push(MftAttr {
            offset: to_u64(at),
            len: to_u64(len),
            kind,
            name: crate::text::utf16(raw, LE),
            resident: data.get(at.saturating_add(8)) == Some(&0),
        });
        at = at.saturating_add(len);
    }
    out
}

/// The preferred file name ($FILE_NAME, Win32 over DOS) and $SI modified time.
fn mft_summary(data: &[u8], attrs: &[MftAttr]) -> (Option<String>, Option<u64>) {
    let mut name: Option<(u8, String)> = None;
    let mut modified = None;
    for a in attrs.iter().filter(|a| a.resident) {
        let value = to_usize(a.offset).saturating_add(usize::from(
            u16_le(data, to_usize(a.offset).saturating_add(20)).unwrap_or(0),
        ));
        match a.kind {
            0x10 => modified = u64_le(data, value.saturating_add(8)),
            0x30 => {
                let chars = usize::from(data.get(value.saturating_add(64)).copied().unwrap_or(0));
                let space = data.get(value.saturating_add(65)).copied().unwrap_or(0);
                let start = value.saturating_add(66);
                let raw = data
                    .get(start..start.saturating_add(chars.saturating_mul(2)))
                    .unwrap_or_default();
                let rank = if space == 2 { 0 } else { 1 };
                if name.as_ref().is_none_or(|(r, _)| rank > *r) {
                    name = Some((rank, crate::text::utf16(raw, LE)));
                }
            }
            _ => {}
        }
    }
    (name.map(|(_, n)| n), modified)
}

async fn mft(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 32)).await?;
    let record = u64::from(u32_le(&head, 28).unwrap_or(1024)).max(1024);
    let count = file.len.checked_div(record).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    let (mut used, mut dirs) = (0u64, 0u64);
    for i in 0..count {
        let span = file.sub(i.saturating_mul(record), record);
        let (block, problem) = mft_record(&cx, span).await?;
        let data = &block.data;
        let mut node = Node::new(format!("Record {i}")).span(span);
        match data.get(..4) {
            Some(b"FILE") => {
                let first = u16_le(data, 20).unwrap_or(0);
                let flags = u16_le(data, 22).unwrap_or(0);
                let attrs = mft_attributes(data, first);
                let (name, modified) = mft_summary(data, &attrs);
                if flags & 1 != 0 {
                    used = used.saturating_add(1);
                }
                if flags & 2 != 0 {
                    dirs = dirs.saturating_add(1);
                }
                let state = match (flags & 1 != 0, flags & 2 != 0) {
                    (true, true) => "directory",
                    (true, false) => "file",
                    (false, true) => "deleted directory",
                    (false, false) => "deleted/unused",
                };
                node = node
                    .summary(format!(
                        "{}{state}",
                        name.map(|n| format!("{n} — ")).unwrap_or_default()
                    ))
                    .lazy(mft_entry, (input, span));
                if let Some(m) = modified {
                    node = node.value(filetime(m));
                }
                if let Some(p) = problem {
                    node = node.diag(p);
                }
            }
            Some(b"BAAD") => {
                node = node.diag(Diagnostic::warning(
                    "record marked BAAD (failed multi-sector transfer)",
                ))
            }
            _ => node = node.summary("empty"),
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "NTFS MFT, {count} records of {record} bytes, {used} in use ({dirs} directories)"
    ));
    Ok(())
}

async fn mft_entry(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let (block, _) = mft_record(&cx, span).await?;
    let (first, _) = mft_header_layout(&mut Fields::new(&block, LE), &())?;
    cx.emit(
        Node::new("Header")
            .span(span.sub(0, first.into()))
            .lazy(mft_header, span),
    );
    for (i, a) in mft_attributes(&block.data, first).into_iter().enumerate() {
        let type_name = lookup(ATTRIBUTE_TYPES, a.kind.into())
            .map_or_else(|| format!("Attribute {:#x}", a.kind), str::to_owned);
        let name = if a.name.is_empty() {
            type_name
        } else {
            format!("{type_name}:{}", a.name)
        };
        let attr_span = span.sub(a.offset, a.len);
        cx.push(
            Node::new(name)
                .span(attr_span)
                .summary(if a.resident {
                    "resident"
                } else {
                    "non-resident"
                })
                .desc(format!("Attribute {i}"))
                .lazy(mft_attribute, (input, span, a)),
        )
        .await;
    }
    Ok(())
}

async fn mft_header(cx: Cx, span: Span) -> Result<()> {
    let (block, _) = mft_record(&cx, span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let (_, _) = mft_header_layout(&mut f, &())?;
    let usa = u16_le(&block.data, 4).unwrap_or(0);
    let words = u16_le(&block.data, 6).unwrap_or(0);
    if usa >= 0x30 {
        f.seek(0x2c);
        f.u32("MFT record number").emit()?;
    }
    f.seek(usa.into());
    f.u16("Update sequence number").hex().emit()?;
    f.bytes(
        "Update sequence array",
        u64::from(words.saturating_sub(1)).saturating_mul(2),
    )
    .emit()?;
    Ok(())
}

async fn mft_attribute(cx: Cx, (input, span, a): (Input, Span, MftAttr)) -> Result<()> {
    let (record, _) = mft_record(&cx, span).await?;
    let data = record
        .data
        .get(to_usize(a.offset)..to_usize(a.offset.saturating_add(a.len)))
        .unwrap_or_default()
        .to_vec();
    let block = Block {
        span: span.sub(a.offset, a.len),
        data,
    };
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Type").enumeration(ATTRIBUTE_TYPES).emit()?;
    f.u32("Length").emit()?;
    let non_resident = f.u8("Non-resident").emit()?;
    let name_len = f.u8("Name length").emit()?;
    let name_off = f.u16("Name offset").hex().emit()?;
    f.u16("Flags").flags(ATTRIBUTE_FLAGS).emit()?;
    f.u16("Attribute ID").emit()?;
    if non_resident == 0 {
        let len = f.u32("Value length").emit()?;
        let off = f.u16("Value offset").hex().emit()?;
        f.u8("Indexed").emit()?;
        if name_len > 0 {
            f.seek(name_off.into());
            f.utf16("Name", name_len.into()).emit()?;
        }
        f.seek(off.into());
        let value = block.span.sub(off.into(), len.into());
        match a.kind {
            0x10 => {
                f.u64("Created").filetime().emit()?;
                f.u64("Modified").filetime().emit()?;
                f.u64("MFT entry modified").filetime().emit()?;
                f.u64("Accessed").filetime().emit()?;
                f.u32("File attributes").flags(FILE_ATTRIBUTES).emit()?;
                if len >= 72 {
                    f.u32("Maximum versions").emit()?;
                    f.u32("Version").emit()?;
                    f.u32("Class ID").emit()?;
                    f.u32("Owner ID").emit()?;
                    f.u32("Security ID").emit()?;
                    f.u64("Quota charged").emit()?;
                    f.u64("Update sequence number").hex().emit()?;
                }
            }
            0x30 => {
                file_name_fields(&mut f)?;
            }
            0x60 => {
                f.utf16("Volume name", u64::from(len) / 2).emit()?;
            }
            0x80 => cx.emit(text_or_embedded(&cx, input, value).await?),
            _ => cx.emit(Node::new("Value").span(value)),
        }
    } else {
        f.u64("Starting VCN").emit()?;
        f.u64("Last VCN").emit()?;
        let runs = f.u16("Data runs offset").hex().emit()?;
        f.u16("Compression unit").emit()?;
        f.u32("Padding").emit()?;
        let allocated = f.u64("Allocated size").emit()?;
        let real = f.u64("Real size").with(|&v, n| n.summary(size(v))).emit()?;
        f.u64("Initialized size").emit()?;
        if name_len > 0 {
            f.seek(name_off.into());
            f.utf16("Name", name_len.into()).emit()?;
        }
        let run_span = block.span.tail(runs.into());
        let list = block.data.get(usize::from(runs)..).unwrap_or_default();
        let decoded = data_runs(list);
        cx.emit(
            Node::new("Data runs")
                .span(run_span)
                .summary(format!(
                    "{} runs, {} allocated",
                    decoded.len(),
                    size(allocated)
                ))
                .lazy(mft_runs, (run_span, decoded)),
        );
        let _ = real;
    }
    Ok(())
}

/// One data run: (offset in the list, length in bytes, cluster count,
/// starting LCN or None for a sparse run).
type DataRun = (u64, u64, u64, Option<i64>);

/// Decoded data runs: (offset in the list, length in bytes, cluster count,
/// starting LCN or None for a sparse run).
fn data_runs(list: &[u8]) -> Vec<DataRun> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut lcn = 0i64;
    while let Some(&head) = list.get(at) {
        if head == 0 || out.len() >= 4096 {
            break;
        }
        let len_bytes = usize::from(head & 0xf);
        let off_bytes = usize::from(head >> 4);
        let len_start = at.saturating_add(1);
        let off_start = len_start.saturating_add(len_bytes);
        let end = off_start.saturating_add(off_bytes);
        let (Some(len_raw), Some(off_raw)) =
            (list.get(len_start..off_start), list.get(off_start..end))
        else {
            break;
        };
        if len_bytes > 8 || off_bytes > 8 {
            break;
        }
        let clusters = len_raw
            .iter()
            .rev()
            .fold(0u64, |a, &b| (a << 8) | u64::from(b));
        let start = if off_bytes == 0 {
            None
        } else {
            let mut delta = off_raw
                .iter()
                .rev()
                .fold(0i64, |a, &b| (a << 8) | i64::from(b));
            let shift =
                64u32.saturating_sub(u32::try_from(off_bytes.saturating_mul(8)).unwrap_or(64));
            delta = delta.checked_shl(shift).map_or(delta, |d| d >> shift);
            lcn = lcn.saturating_add(delta);
            Some(lcn)
        };
        out.push((to_u64(at), to_u64(end.saturating_sub(at)), clusters, start));
        at = end;
    }
    out
}

async fn mft_runs(cx: Cx, (span, runs): (Span, Vec<DataRun>)) -> Result<()> {
    for (i, (at, len, clusters, lcn)) in runs.into_iter().enumerate() {
        let summary = match lcn {
            Some(l) => format!("{clusters} clusters at LCN {l}"),
            None => format!("{clusters} clusters, sparse"),
        };
        cx.push(
            Node::new(format!("Run {i}"))
                .span(span.sub(at, len))
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

/// The fields of a $FILE_NAME value (MFT attribute or index key); returns
/// the name and the modification time.
fn file_name_fields(f: &mut Fields<'_>) -> Result<(String, u64)> {
    f.u64("Parent directory")
        .hex()
        .with(|&v, n| file_reference(v, n))
        .emit()?;
    f.u64("Created").filetime().emit()?;
    let modified = f.u64("Modified").filetime().emit()?;
    f.u64("MFT entry modified").filetime().emit()?;
    f.u64("Accessed").filetime().emit()?;
    f.u64("Allocated size").emit()?;
    f.u64("Real size").with(|&v, n| n.summary(size(v))).emit()?;
    f.u32("Flags").flags(FILE_ATTRIBUTES).emit()?;
    f.u32("Reparse value").hex().emit()?;
    let chars = f.u8("Name length").emit()?;
    f.u8("Namespace").enumeration(NAMESPACES).emit()?;
    let name = f.utf16("Name", chars.into()).emit()?;
    Ok((name, modified))
}

/// A part of a fixed-up multi-sector record, for decoding with [`Fields`].
async fn fixed_part(cx: &Cx, record: Span, offset: u64, len: u64) -> Result<Block> {
    let (block, _) = mft_record(cx, record).await?;
    let start = to_usize(offset);
    let data = block
        .data
        .get(start..start.saturating_add(to_usize(len)))
        .or_else(|| block.data.get(start..))
        .unwrap_or_default()
        .to_vec();
    Ok(Block {
        span: record.sub(offset, len),
        data,
    })
}

// ---------------------------------------------------------------------------
// NTFS directory index buffers ($I30 INDX records)

fn indx_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"INDX")
        && u16_le(h.data, 4) == Some(0x28)
        && h.len.is_multiple_of(4096)
        && u32_le(h.data, 0x18).is_some_and(|o| (0x10..4096).contains(&o))
}

declare_format!(pub INDX = "ntfs-index", "NTFS directory index ($I30 INDX records)", [], "application/x-ntfs-index",
    Probe::Custom(indx_probe), indx);

const INDEX_ENTRY_FLAGS: FlagTable = &[flag(1, "HAS_SUBNODE"), flag(2, "LAST_ENTRY")];
const INDX_FLAGS: FlagTable = &[flag(1, "HAS_CHILDREN")];
const RESTART_FLAGS: FlagTable = &[flag(2, "CLEAN_DISMOUNT")];
const RCRD_FLAGS: FlagTable = &[flag(1, "RECORD_END")];

/// A plausible $FILE_NAME key at `at` in a fixed-up record (for carving
/// deleted entries out of slack space).
fn plausible_entry(data: &[u8], at: usize) -> Option<u64> {
    let len = usize::from(u16_le(data, at.saturating_add(8))?);
    let key = usize::from(u16_le(data, at.saturating_add(10))?);
    let chars = usize::from(*data.get(at.saturating_add(16 + 64))?);
    let space = *data.get(at.saturating_add(16 + 65))?;
    let modified = u64_le(data, at.saturating_add(16 + 16))?;
    let plausible_time = (0x01b0_0000_0000_0000..0x0300_0000_0000_0000).contains(&modified);
    (chars > 0
        && space <= 3
        && key == 66usize.saturating_add(chars.saturating_mul(2))
        && len >= key.saturating_add(16)
        && len.is_multiple_of(8)
        && len <= 0x260
        && plausible_time)
        .then_some(to_u64(len))
}

async fn indx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = file.len / 4096;
    let mut entries = 0u64;
    for i in 0..count {
        let span = file.sub(i.saturating_mul(4096), 4096);
        let (block, problem) = mft_record(&cx, span).await?;
        let data = &block.data;
        if data.get(..4) != Some(b"INDX") {
            cx.push(
                Node::new(format!("Buffer {i}"))
                    .span(span)
                    .summary("not an index buffer"),
            )
            .await;
            continue;
        }
        let vcn = u64_le(data, 16).unwrap_or(0);
        let first = 0x18u64.saturating_add(u64::from(u32_le(data, 0x18).unwrap_or(0)));
        let used = 0x18u64.saturating_add(u64::from(u32_le(data, 0x1c).unwrap_or(0)));
        let mut list = Vec::new();
        let mut at = first;
        while at.saturating_add(16) <= used.min(4096) && list.len() < 512 {
            let len = u64::from(u16_le(data, to_usize(at.saturating_add(8))).unwrap_or(0));
            let flags = u32_le(data, to_usize(at.saturating_add(12))).unwrap_or(0);
            if len < 16 {
                break;
            }
            list.push((at, len, false));
            if flags & 2 != 0 {
                break;
            }
            at = at.saturating_add(len);
        }
        // Slack: entries left behind past the end of the used area.
        let mut at = used.next_multiple_of(8);
        while at.saturating_add(0x52) <= 4096 {
            match plausible_entry(data, to_usize(at)) {
                Some(len) => {
                    list.push((at, len, true));
                    at = at.saturating_add(len);
                }
                None => at = at.saturating_add(8),
            }
        }
        let live = list.iter().filter(|(_, _, slack)| !slack).count();
        let carved = list.len().saturating_sub(live);
        entries = entries.saturating_add(to_u64(list.len()));
        let mut node = Node::new(format!("Buffer {i} (VCN {vcn})"))
            .span(span)
            .summary(format!(
                "{live} entries{}",
                if carved > 0 {
                    format!(", {carved} recovered from slack")
                } else {
                    String::new()
                }
            ))
            .lazy(indx_buffer, (span, list));
        if let Some(p) = problem {
            node = node.diag(p);
        }
        cx.push(node).await;
    }
    cx.annotate(format!("NTFS index, {count} buffers, {entries} entries"));
    Ok(())
}

fn indx_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Signature", 4).emit()?;
    f.u16("Update sequence offset").hex().emit()?;
    f.u16("Update sequence size (words)").emit()?;
    f.u64("$LogFile sequence number").emit()?;
    f.u64("VCN").emit()?;
    f.u32("Entries offset").hex().emit()?;
    f.u32("Index length").emit()?;
    f.u32("Allocated length").emit()?;
    f.u8("Flags").flags(INDX_FLAGS).emit()?;
    Ok(())
}

async fn indx_buffer(cx: Cx, (span, list): (Span, Vec<(u64, u64, bool)>)) -> Result<()> {
    let header = fixed_part(&cx, span, 0, 0x28).await?;
    let mut f = Fields::new(&header, LE);
    indx_header(&mut f, &())?;
    cx.emit(
        Node::new("Header")
            .span(header.span)
            .lazy(indx_header_node, span),
    );
    for (at, len, slack) in list {
        let block = fixed_part(&cx, span, at, len).await?;
        let key_len = u16_le(&block.data, 10).unwrap_or(0);
        let mut node = Node::new("Entry").span(block.span);
        if key_len >= 66 {
            let mut f = Fields::new(&block, LE);
            f.seek(16);
            if let Ok((name, modified)) = file_name_fields(&mut f) {
                node = Node::new(name).span(block.span).value(filetime(modified));
            }
        } else {
            node = node.summary("end of index");
        }
        if slack {
            node = node.diag(Diagnostic::note(
                "recovered from slack space (deleted or moved entry)",
            ));
        }
        cx.push(node.lazy(indx_entry, (span, at, len))).await;
    }
    Ok(())
}

async fn indx_header_node(cx: Cx, span: Span) -> Result<()> {
    let block = fixed_part(&cx, span, 0, 0x28).await?;
    indx_header(&mut Fields::emitting(&cx, &block, LE), &())?;
    Ok(())
}

async fn indx_entry(cx: Cx, (span, at, len): (Span, u64, u64)) -> Result<()> {
    let block = fixed_part(&cx, span, at, len).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u64("File reference")
        .hex()
        .with(|&v, n| file_reference(v, n))
        .emit()?;
    f.u16("Entry length").emit()?;
    let key = f.u16("Key length").emit()?;
    let flags = f.u32("Flags").flags(INDEX_ENTRY_FLAGS).emit()?;
    if key >= 66 {
        file_name_fields(&mut f)?;
    }
    if flags & 1 != 0 {
        f.seek(len.saturating_sub(8));
        f.u64("Subnode VCN").emit()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NTFS transaction log ($LogFile)

fn logfile_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"RSTR")
        && u16_le(h.data, 4) == Some(0x1e)
        && u32_le(h.data, 16).is_some_and(|p| p.is_power_of_two() && (512..=65536).contains(&p))
        && u32_le(h.data, 20).is_some_and(|p| p.is_power_of_two() && (512..=65536).contains(&p))
}

declare_format!(pub LOGFILE = "ntfs-logfile", "NTFS transaction log ($LogFile)", [], "application/x-ntfs-logfile",
    Probe::Custom(logfile_probe), logfile);

fn restart_layout(f: &mut Fields<'_>, _: &()) -> Result<u64> {
    f.ascii("Signature", 4).emit()?;
    f.u16("Update sequence offset").hex().emit()?;
    f.u16("Update sequence size (words)").emit()?;
    f.u64("Chkdsk LSN").emit()?;
    f.u32("System page size").emit()?;
    f.u32("Log page size").emit()?;
    let area = f.u16("Restart area offset").hex().emit()?;
    f.int::<i16>("Minor version").emit()?;
    f.int::<i16>("Major version").emit()?;
    f.seek(area.into());
    let lsn = f.u64("Current LSN").emit()?;
    f.u16("Log clients").emit()?;
    f.u16("Client free list").emit()?;
    f.u16("Client in-use list").emit()?;
    f.u16("Flags").flags(RESTART_FLAGS).emit()?;
    f.u32("Sequence number bits").emit()?;
    f.u16("Restart area length").emit()?;
    let clients = f.u16("Client array offset").hex().emit()?;
    f.u64("File size").with(|&v, n| n.summary(size(v))).emit()?;
    f.u32("Last LSN data length").emit()?;
    f.u16("Record header length").emit()?;
    f.u16("Log page data offset").hex().emit()?;
    f.u32("Restart log open count").emit()?;
    f.seek(u64::from(area).saturating_add(clients.into()));
    f.u64("Client: oldest LSN").emit()?;
    f.u64("Client: restart LSN").emit()?;
    f.u16("Client: previous").emit()?;
    f.u16("Client: next").emit()?;
    f.u16("Client: sequence number").emit()?;
    f.bytes("Client: padding", 6).emit()?;
    let chars = f.u32("Client: name length (bytes)").emit()?;
    f.utf16("Client: name", u64::from(chars.min(128)) / 2)
        .emit()?;
    Ok(lsn)
}

fn record_page_layout(f: &mut Fields<'_>, _: &()) -> Result<u64> {
    f.ascii("Signature", 4).emit()?;
    f.u16("Update sequence offset").hex().emit()?;
    f.u16("Update sequence size (words)").emit()?;
    f.u64("Last LSN").emit()?;
    f.u32("Flags").flags(RCRD_FLAGS).emit()?;
    f.u16("Page count").emit()?;
    f.u16("Page position").emit()?;
    f.u16("Next record offset").hex().emit()?;
    f.bytes("Padding", 6).emit()?;
    let end = f.u64("Last end LSN").emit()?;
    Ok(end)
}

async fn logfile(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 24)).await?;
    let page = u64::from(u32_le(&head, 20).unwrap_or(4096)).max(512);
    let count = file.len.checked_div(page).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    let (mut restart, mut records, mut empty) = (0u64, 0u64, 0u64);
    let mut lsn = 0u64;
    for i in 0..count {
        let span = file.sub(i.saturating_mul(page), page);
        let sig = cx.read(span.sub(0, 4)).await?;
        let node = match sig.as_slice() {
            b"RSTR" | b"CHKD" => {
                restart = restart.saturating_add(1);
                let (block, _) = mft_record(&cx, span).await?;
                let current = restart_layout(&mut Fields::new(&block, LE), &()).unwrap_or(0);
                lsn = lsn.max(current);
                Node::new(format!("Restart page {i}"))
                    .span(span)
                    .value(uint(current, 64))
                    .desc("Current LSN")
                    .lazy(log_page, (span, true))
            }
            b"RCRD" => {
                records = records.saturating_add(1);
                let (block, _) = mft_record(&cx, span).await?;
                let end = record_page_layout(&mut Fields::new(&block, LE), &()).unwrap_or(0);
                Node::new(format!("Record page {i}"))
                    .span(span)
                    .value(uint(end, 64))
                    .desc("Last end LSN")
                    .lazy(log_page, (span, false))
            }
            b"BAAD" => Node::new(format!("Page {i}"))
                .span(span)
                .diag(Diagnostic::warning("page marked BAAD")),
            _ => {
                empty = empty.saturating_add(1);
                if i.is_multiple_of(64) {
                    cx.checkpoint().await;
                }
                continue;
            }
        };
        cx.push(node).await;
    }
    cx.annotate(format!("NTFS $LogFile, {restart} restart and {records} record pages ({empty} unused), current LSN {lsn}"));
    Ok(())
}

async fn log_page(cx: Cx, (span, restart): (Span, bool)) -> Result<()> {
    let (block, problem) = mft_record(&cx, span).await?;
    if let Some(p) = problem {
        cx.diag(p);
    }
    let mut f = Fields::emitting(&cx, &block, LE);
    if restart {
        restart_layout(&mut f, &())?;
    } else {
        let next = u16_le(&block.data, 0x14).unwrap_or(0);
        record_page_layout(&mut f, &())?;
        cx.emit(
            Node::new("Log records").span(span.sub(0x40, u64::from(next).saturating_sub(0x40))),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Task Scheduler 1.0 jobs (.job)

fn job_probe(h: &Head<'_>) -> bool {
    u16_le(h.data, 0)
        .is_some_and(|v| matches!(v, 0x0400 | 0x0500 | 0x0501 | 0x0502 | 0x0600 | 0x0601))
        && u16_le(h.data, 2) == Some(1)
        && u16_le(h.data, 20) == Some(0x46)
        && u16_le(h.data, 22).is_some_and(|t| t > 0x46 && u64::from(t) < h.len)
}

declare_format!(pub JOB = "windows-job", "Windows Task Scheduler job", ["job"], "application/x-ms-job",
    Probe::Custom(job_probe), job);

const JOB_PRIORITIES: EnumTable = &[
    (0x20, "NORMAL"),
    (0x40, "IDLE"),
    (0x80, "HIGH"),
    (0x100, "REALTIME"),
];
const JOB_STATUS: EnumTable = &[
    (0x0004_1300, "SCHED_S_TASK_READY"),
    (0x0004_1301, "SCHED_S_TASK_RUNNING"),
    (0x0004_1302, "SCHED_S_TASK_DISABLED"),
    (0x0004_1303, "SCHED_S_TASK_HAS_NOT_RUN"),
    (0x0004_1304, "SCHED_S_TASK_NO_MORE_RUNS"),
    (0x0004_1305, "SCHED_S_TASK_NOT_SCHEDULED"),
    (0x0004_1306, "SCHED_S_TASK_TERMINATED"),
    (0x0004_1307, "SCHED_S_TASK_NO_VALID_TRIGGERS"),
    (0x0004_1308, "SCHED_S_EVENT_TRIGGER"),
];
const JOB_FLAGS: FlagTable = &[
    flag(0x0001, "INTERACTIVE"),
    flag(0x0002, "DELETE_WHEN_DONE"),
    flag(0x0004, "DISABLED"),
    flag(0x0010, "START_ONLY_IF_IDLE"),
    flag(0x0020, "KILL_ON_IDLE_END"),
    flag(0x0040, "DONT_START_IF_ON_BATTERIES"),
    flag(0x0080, "KILL_IF_GOING_ON_BATTERIES"),
    flag(0x0100, "RUN_ONLY_IF_DOCKED"),
    flag(0x0200, "HIDDEN"),
    flag(0x0400, "RUN_IF_CONNECTED_TO_INTERNET"),
    flag(0x0800, "RESTART_ON_IDLE_RESUME"),
    flag(0x1000, "SYSTEM_REQUIRED"),
    flag(0x2000, "RUN_ONLY_IF_LOGGED_ON"),
];
const TRIGGER_FLAGS: FlagTable = &[
    flag(1, "HAS_END_DATE"),
    flag(2, "KILL_AT_DURATION_END"),
    flag(4, "DISABLED"),
];
const TRIGGER_TYPES: EnumTable = &[
    (0, "ONCE"),
    (1, "DAILY"),
    (2, "WEEKLY"),
    (3, "MONTHLYDATE"),
    (4, "MONTHLYDOW"),
    (5, "EVENT_ON_IDLE"),
    (6, "EVENT_AT_SYSTEMSTART"),
    (7, "EVENT_AT_LOGON"),
];

/// A SYSTEMTIME (eight 16-bit fields) as text.
fn systemtime_text(raw: &[u8]) -> String {
    let part = |i: usize| u16_le(raw, i.saturating_mul(2)).unwrap_or(0);
    if part(0) == 0 {
        return "never".to_owned();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        part(0),
        part(1),
        part(3),
        part(4),
        part(5),
        part(6)
    )
}

fn systemtime(f: &mut Fields<'_>, name: &'static str) -> Result<String> {
    let raw = f
        .bytes(name, 16)
        .with(|b, n| n.value(text(systemtime_text(b))))
        .emit()?;
    Ok(systemtime_text(&raw))
}

fn job_fixed(f: &mut Fields<'_>, _: &()) -> Result<(u32, String)> {
    f.u16("Product version").hex().emit()?;
    f.u16("File version").emit()?;
    f.guid("Job UUID").emit()?;
    f.u16("Application name offset").hex().emit()?;
    f.u16("Triggers offset").hex().emit()?;
    f.u16("Error retry count").emit()?;
    f.u16("Error retry interval (minutes)").emit()?;
    f.u16("Idle deadline (minutes)").emit()?;
    f.u16("Idle wait (minutes)").emit()?;
    f.u32("Priority").enumeration(JOB_PRIORITIES).emit()?;
    f.u32("Maximum run time (ms)").emit()?;
    f.u32("Exit code").hex().emit()?;
    let status = f.u32("Status").enumeration(JOB_STATUS).emit()?;
    f.u32("Flags").flags(JOB_FLAGS).emit()?;
    let last = systemtime(f, "Last run time")?;
    Ok((status, last))
}

/// Reads a counted UTF-16 string (u16 character count including the NUL).
async fn job_string(cur: &mut Cursor<'_>, name: &'static str) -> Result<(Node, String)> {
    let start = cur.pos();
    let chars = cur.u16().await?;
    let raw = cur.bytes(u64::from(chars).saturating_mul(2)).await?;
    let s = crate::text::utf16z(&raw, LE).0;
    Ok((
        Node::new(name)
            .span(cur.since(start))
            .value(text(s.clone())),
        s,
    ))
}

fn trigger_layout(f: &mut Fields<'_>, _: &()) -> Result<(u32, String)> {
    f.u16("Trigger size").emit()?;
    f.u16("Reserved").emit()?;
    let y = f.u16("Begin year").emit()?;
    let m = f.u16("Begin month").emit()?;
    let d = f.u16("Begin day").emit()?;
    f.u16("End year").emit()?;
    f.u16("End month").emit()?;
    f.u16("End day").emit()?;
    let h = f.u16("Start hour").emit()?;
    let mi = f.u16("Start minute").emit()?;
    f.u32("Duration (minutes)").emit()?;
    f.u32("Interval (minutes)").emit()?;
    f.u32("Flags").flags(TRIGGER_FLAGS).emit()?;
    let kind = f.u32("Trigger type").enumeration(TRIGGER_TYPES).emit()?;
    f.u16("Type-specific 0").hex().emit()?;
    f.u16("Type-specific 1").hex().emit()?;
    f.u16("Type-specific 2").hex().emit()?;
    f.u16("Padding").emit()?;
    f.u16("Reserved").emit()?;
    f.u16("Reserved").emit()?;
    Ok((kind, format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}")))
}

async fn job(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let fixed = file.sub(0, 68);
    let block = cx.block(fixed).await?;
    let (status, last) = job_fixed(&mut Fields::new(&block, LE), &())?;
    cx.emit(struct_node(
        "Fixed-length section",
        fixed,
        LE,
        (),
        job_fixed,
    ));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(68);
    let span = cur.span(2);
    let running = cur.u16().await?;
    cx.emit(
        Node::new("Running instance count")
            .span(span)
            .value(uint(running, 16)),
    );
    let mut app = String::new();
    let mut args = String::new();
    for name in [
        "Application name",
        "Parameters",
        "Working directory",
        "Author",
        "Comment",
    ] {
        let (node, s) = job_string(&mut cur, name).await?;
        match name {
            "Application name" => app = s,
            "Parameters" => args = s,
            _ => {}
        }
        cx.emit(node);
    }
    for name in ["User data", "Reserved data"] {
        let start = cur.pos();
        let n = cur.u16().await?;
        cur.skip(n.into());
        cx.emit(
            Node::new(name)
                .span(cur.since(start))
                .summary(format!("{n} bytes")),
        );
    }
    let start = cur.pos();
    let triggers = cur.u16().await?;
    let mut list = Vec::new();
    for _ in 0..triggers.min(256) {
        let at = cur.pos();
        list.push(file.sub(at, 48));
        cur.skip(48);
    }
    cx.emit(
        Node::new("Triggers")
            .span(cur.since(start))
            .summary(format!("{triggers} triggers"))
            .lazy(job_triggers, list),
    );
    if cur.pos() < file.len {
        cx.emit(Node::new("Job signature").span(file.tail(cur.pos())));
    }
    cx.annotate(format!(
        "Scheduled task: {app}{}{} — {}, last run {last}",
        if args.is_empty() { "" } else { " " },
        args,
        lookup(JOB_STATUS, status.into()).unwrap_or("unknown status")
    ));
    Ok(())
}

async fn job_triggers(cx: Cx, list: Vec<Span>) -> Result<()> {
    for (i, span) in list.into_iter().enumerate() {
        let block = cx.block(span).await?;
        let (kind, start) = trigger_layout(&mut Fields::new(&block, LE), &())?;
        let kind = lookup(TRIGGER_TYPES, kind.into()).unwrap_or("?");
        cx.push(
            struct_node(format!("Trigger {i}"), span, LE, (), trigger_layout)
                .summary(format!("{kind} from {start}")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Outlook autocomplete cache (.nk2)

declare_format!(pub NK2 = "outlook-nk2", "Outlook autocomplete cache (NK2)", ["nk2"], "application/x-ms-nk2",
    Probe::Magic(&[(0, b"\x0d\xf0\xad\xba")]), nk2);

const MAPI_TYPES: EnumTable = &[
    (0x0002, "PT_SHORT"),
    (0x0003, "PT_LONG"),
    (0x0005, "PT_DOUBLE"),
    (0x000b, "PT_BOOLEAN"),
    (0x0014, "PT_I8"),
    (0x001e, "PT_STRING8"),
    (0x001f, "PT_UNICODE"),
    (0x0040, "PT_SYSTIME"),
    (0x0048, "PT_CLSID"),
    (0x0102, "PT_BINARY"),
];

const MAPI_PROPS: EnumTable = &[
    (0x0fff, "PR_ENTRYID"),
    (0x0ffe, "PR_OBJECT_TYPE"),
    (0x3001, "PR_DISPLAY_NAME"),
    (0x3002, "PR_ADDRTYPE"),
    (0x3003, "PR_EMAIL_ADDRESS"),
    (0x300b, "PR_SEARCH_KEY"),
    (0x3900, "PR_DISPLAY_TYPE"),
    (0x39fe, "PR_SMTP_ADDRESS"),
    (0x39ff, "PR_7BIT_DISPLAY_NAME"),
    (0x5ff6, "PR_DROPDOWN_DISPLAY_NAME"),
    (0x5ff7, "PR_NICK_NAME_W"),
    (0x5ffd, "PR_NICK_NAME_FLAGS"),
    (0x6001, "PR_NICK_NAME_DOTSTUFF"),
    (0x6002, "PR_NICK_NAME_COUNT"),
    (0x6003, "PR_NICK_NAME_WEIGHT"),
    (0x6004, "PR_NICK_NAME_LAST_USED"),
];

fn mapi_variable(kind: u16) -> bool {
    matches!(kind, 0x001e | 0x001f | 0x0048 | 0x0102)
}

async fn nk2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Signature").hex().emit()?;
    f.u32("Version").hex().emit()?;
    f.u32("Unknown").emit()?;
    let rows = f.u32("Number of rows").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(16);
    let mut names = Vec::new();
    for i in 0..rows {
        let start = cur.pos();
        let props = cur.u32().await?;
        let table = cur
            .bytes(u64::from(props.min(4096)).saturating_mul(16))
            .await?;
        let mut display = None;
        let mut email = None;
        for p in table.as_chunks::<16>().0 {
            let kind = u16_le(p, 0).unwrap_or(0);
            let id = u16_le(p, 2).unwrap_or(0);
            if mapi_variable(kind) {
                let len = cur.u32().await?;
                let data = cur.bytes(len.into()).await?;
                let s = match kind {
                    0x001f => Some(crate::text::utf16z(&data, LE).0),
                    0x001e => Some(crate::text::until_nul(&data)),
                    _ => None,
                };
                match id {
                    0x3001 => display = s.or(display),
                    0x39fe | 0x3003 => email = email.or(s),
                    _ => {}
                }
            }
        }
        let label = display.clone().or(email.clone()).unwrap_or_default();
        names.push(label.clone());
        cx.push(
            Node::new(format!("Row {i}"))
                .span(cur.since(start))
                .summary(format!(
                    "{label}{}",
                    email.map(|e| format!(" <{e}>")).unwrap_or_default()
                ))
                .lazy(nk2_row, cur.since(start)),
        )
        .await;
    }
    if cur.pos() < file.len {
        cx.emit(Node::new("Footer").span(file.tail(cur.pos())));
    }
    cx.annotate(format!(
        "Outlook autocomplete cache, {rows} entries: {}",
        clip(&names.join(", "), 120)
    ));
    Ok(())
}

async fn nk2_row(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let props = cur.u32().await?;
    let table_span = cur.span(u64::from(props.min(4096)).saturating_mul(16));
    let table = cur.bytes(table_span.len).await?;
    for (i, p) in table.as_chunks::<16>().0.iter().enumerate() {
        let kind = u16_le(p, 0).unwrap_or(0);
        let id = u16_le(p, 2).unwrap_or(0);
        let entry = table_span.sub(to_u64(i).saturating_mul(16), 16);
        let name = lookup(MAPI_PROPS, id.into())
            .map_or_else(|| format!("Property {id:#06x}"), str::to_owned);
        let type_name = lookup(MAPI_TYPES, kind.into()).unwrap_or("?");
        let mut node = Node::new(name)
            .span(entry)
            .desc(format!("{type_name} ({kind:#06x})"));
        if mapi_variable(kind) {
            let start = cur.pos();
            let len = cur.u32().await?;
            let data = cur.bytes(len.into()).await?;
            let value = match kind {
                0x001f => text(crate::text::utf16z(&data, LE).0),
                0x001e => text(crate::text::until_nul(&data)),
                _ => Value::Bytes(data),
            };
            node = node.value(value).target(cur.since(start));
        } else {
            let raw = u64_le(p, 8).unwrap_or(0);
            node = node.value(match kind {
                0x0040 => filetime(raw),
                0x000b => Value::Bool(raw & 0xffff != 0),
                0x0002 => uint(raw & 0xffff, 16),
                0x0003 => uint(raw & 0xffff_ffff, 32),
                0x0005 => Value::Float(f64::from_bits(raw)),
                _ => hex(raw, 64),
            });
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Outlook Express mail store (.dbx)

declare_format!(pub DBX = "outlook-express-dbx", "Outlook Express mail store (DBX)", ["dbx"], "application/x-ms-dbx",
    Probe::Magic(&[(0, b"\xcf\xad\x12\xfe")]), dbx);

fn dbx_kind(class: &[u8]) -> &'static str {
    match class {
        [0xc5, 0xfd, 0x74, 0x6f, ..] => "messages",
        [0xc6, 0xfd, 0x74, 0x6f, ..] => "folders",
        [0x30, 0x9d, 0xfe, 0x26, ..] => "offline",
        [0xc7, 0xfd, 0x74, 0x6f, ..] => "POP3 UIDL",
        _ => "unknown",
    }
}

const DBX_NODE: u64 = 0x27c;

async fn dbx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x24bc)).await?;
    let class = head.data.get(4..20).unwrap_or_default().to_vec();
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Signature").hex().emit()?;
    f.guid("Class ID")
        .with(|_, n| n.summary(dbx_kind(&class)))
        .emit()?;
    f.seek(0xc4);
    let items = f.u32("Number of items").emit()?;
    f.seek(0xe4);
    let root = f.u32("Index root offset").hex().emit()?;
    cx.emit(Node::new("Header").span(file.sub(0, 0x24bc)));
    if root != 0 {
        cx.emit(
            Node::new("Index")
                .span(file.sub(root.into(), DBX_NODE))
                .lazy(dbx_tree, (file, u64::from(root), Path::new())),
        );
    }
    cx.annotate(format!(
        "Outlook Express {} store, {items} items",
        dbx_kind(&class)
    ));
    Ok(())
}

/// Lists one node of the index B-tree: its entries (object offsets) and,
/// lazily, its child nodes.
async fn dbx_tree(cx: Cx, (file, at, path): (Span, u64, Path)) -> Result<()> {
    let span = file.sub(at, DBX_NODE);
    let data = cx.read(span).await?;
    if u32_le(&data, 0).map(u64::from) != Some(at) {
        return Err(Diagnostic::malformed("index node does not point to itself").at(span.sub(0, 4)));
    }
    let child = u32_le(&data, 8).unwrap_or(0);
    let entries = data.get(17).copied().unwrap_or(0).min(0x33);
    let push_child = |name: String, offset: u32, node_span: Span| {
        let node = Node::new(name)
            .span(node_span)
            .summary(format!("node at {offset:#x}"));
        match path.enter(at, 64) {
            Ok(p) => node.lazy(
                crate::expander!(self::dbx_tree: (Span, u64, Path)),
                (file, u64::from(offset), p),
            ),
            Err(d) => node.diag(d),
        }
    };
    if child != 0 {
        cx.push(push_child(
            "Child (before first)".to_owned(),
            child,
            span.sub(8, 4),
        ))
        .await;
    }
    for i in 0..u64::from(entries) {
        let e = 0x18u64.saturating_add(i.saturating_mul(12));
        let value = u32_le(&data, to_usize(e)).unwrap_or(0);
        let sub = u32_le(&data, to_usize(e.saturating_add(4))).unwrap_or(0);
        cx.push(
            Node::new(format!("Entry {i}"))
                .span(span.sub(e, 12))
                .value(hex(value, 32))
                .target(file.sub(value.into(), 4)),
        )
        .await;
        if sub != 0 {
            cx.push(push_child(
                format!("Child after entry {i}"),
                sub,
                span.sub(e.saturating_add(4), 4),
            ))
            .await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RDP bitmap cache (Cache0000.bin)

declare_format!(pub RDP_CACHE = "rdp-bitmap-cache", "Remote Desktop bitmap cache", ["bin"], "application/x-rdp-bitmap-cache",
    Probe::Magic(&[(0, b"RDP8bmp\0")]), rdp_cache);

async fn rdp_cache(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 8).emit()?;
    let version = f.u32("Version").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(12);
    let mut tiles = 0u64;
    while cur.remaining() >= 12 {
        let start = cur.pos();
        let key = cur.u64().await?;
        let w = cur.u16().await?;
        let h = cur.u16().await?;
        let pixels = u64::from(w).saturating_mul(h.into()).saturating_mul(4);
        if pixels == 0 || pixels > cur.remaining() {
            cx.diag(
                Diagnostic::malformed("tile extends past the end of the file").at(cur.since(start)),
            );
            break;
        }
        let data = cur.span(pixels);
        cur.skip(pixels);
        cx.push(
            Node::new(format!("Tile {tiles}"))
                .span(cur.since(start))
                .value(hex(key, 64))
                .summary(format!("{w}×{h} BGRA"))
                .target(data),
        )
        .await;
        tiles = tiles.saturating_add(1);
    }
    cx.annotate(format!("RDP bitmap cache v{version}, {tiles} tiles"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows INI-style artifacts: Shell Command Files (.scf), autorun.inf and
// desktop.ini

/// The first meaningful line (after a BOM, blank lines and `;` comments).
fn ini_first_line<'a>(h: &'a Head<'_>) -> &'a [u8] {
    let data = h.data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(h.data);
    data.split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .find(|l| !l.is_empty() && !l.starts_with(b";"))
        .unwrap_or_default()
}

fn scf_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"[Shell]\r\nCommand=") || h.starts_with(b"[Shell]\nCommand=")
}

fn autorun_probe(h: &Head<'_>) -> bool {
    ini_first_line(h).eq_ignore_ascii_case(b"[autorun]") && h.len < 0x10000
}

fn desktop_ini_probe(h: &Head<'_>) -> bool {
    let first = ini_first_line(h);
    (first.eq_ignore_ascii_case(b"[.ShellClassInfo]") || first.eq_ignore_ascii_case(b"[ViewState]"))
        && h.len < 0x10000
}

declare_format!(pub SCF = "shell-command-file", "Windows Shell Command File (.scf)", ["scf"], "application/x-ms-scf",
    Probe::Custom(scf_probe), shell_command_file);
declare_format!(pub AUTORUN = "autorun-inf", "Windows AutoRun configuration (autorun.inf)", ["inf"], "application/x-autorun-inf",
    Probe::Custom(autorun_probe), autorun_inf);
declare_format!(pub DESKTOP_INI = "desktop-ini", "Windows folder settings (desktop.ini)", ["ini"], "application/x-desktop-ini",
    Probe::Custom(desktop_ini_probe), desktop_ini);

/// A `key=value` line and where it is.
type IniKey = (String, String, Span);

/// Emits the sections of an INI file and returns every `(section, key,
/// value)` for the summary.
async fn ini_file(cx: &Cx, file: Span) -> Result<Vec<(String, String, String)>> {
    let data = cx.read_avail(file.sub(0, 0x10000)).await?;
    let mut at = 0u64;
    let mut section: Option<(String, u64, Vec<IniKey>)> = None;
    let mut sections = Vec::new();
    let mut all = Vec::new();
    for line in data.split_inclusive(|&b| b == b'\n') {
        let len = to_u64(line.len());
        let span = file.sub(at, len);
        let text_line = crate::text::latin1(line.strip_prefix(b"\xef\xbb\xbf").unwrap_or(line))
            .trim()
            .to_owned();
        if let Some(name) = text_line
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
        {
            sections.extend(section.take());
            section = Some((name.to_owned(), at, Vec::new()));
        } else if let Some((k, v)) = text_line.split_once('=')
            && !text_line.starts_with(';')
            && let Some((name, _, keys)) = section.as_mut()
        {
            all.push((name.clone(), k.trim().to_owned(), v.trim().to_owned()));
            keys.push((k.trim().to_owned(), v.trim().to_owned(), span));
        }
        at = at.saturating_add(len);
    }
    sections.extend(section.take());
    let ends: Vec<u64> = sections
        .iter()
        .skip(1)
        .map(|(_, s, _)| *s)
        .chain(std::iter::once(at))
        .collect();
    for ((name, start, keys), end) in sections.into_iter().zip(ends) {
        cx.push(
            Node::new(format!("[{name}]"))
                .span(file.sub(start, end.saturating_sub(start)))
                .summary(format!("{} keys", keys.len()))
                .lazy(ini_keys, keys),
        )
        .await;
    }
    Ok(all)
}

fn ini_get<'a>(all: &'a [(String, String, String)], section: &str, key: &str) -> Option<&'a str> {
    all.iter()
        .find(|(s, k, _)| s.eq_ignore_ascii_case(section) && k.eq_ignore_ascii_case(key))
        .map(|(_, _, v)| v.as_str())
}

async fn ini_keys(cx: Cx, keys: Vec<IniKey>) -> Result<()> {
    for (k, v, span) in keys {
        cx.push(Node::new(k).span(span).value(text(v))).await;
    }
    Ok(())
}

async fn shell_command_file(cx: Cx, input: Input) -> Result<()> {
    let all = ini_file(&cx, input.span).await?;
    let command = ini_get(&all, "Taskbar", "Command")
        .or_else(|| ini_get(&all, "Shell", "Command"))
        .unwrap_or("?");
    let icon = ini_get(&all, "Shell", "IconFile").unwrap_or_default();
    let mut summary = format!("Shell Command File: {command}");
    if !icon.is_empty() {
        summary.push_str(&format!(", icon {}", clip(icon, 100)));
        if icon.starts_with("\\\\") {
            summary.push_str(" (network path)");
        }
    }
    cx.annotate(summary);
    Ok(())
}

async fn autorun_inf(cx: Cx, input: Input) -> Result<()> {
    let all = ini_file(&cx, input.span).await?;
    let open =
        ini_get(&all, "autorun", "open").or_else(|| ini_get(&all, "autorun", "shellexecute"));
    let label = ini_get(&all, "autorun", "label");
    cx.annotate(format!(
        "AutoRun configuration{}{}",
        label.map(|l| format!(" {l:?}")).unwrap_or_default(),
        open.map(|o| format!(", runs {}", clip(o, 100)))
            .unwrap_or_default()
    ));
    Ok(())
}

async fn desktop_ini(cx: Cx, input: Input) -> Result<()> {
    let all = ini_file(&cx, input.span).await?;
    let class = ini_get(&all, ".ShellClassInfo", "CLSID")
        .or_else(|| ini_get(&all, ".ShellClassInfo", "CLSID2"));
    let name = ini_get(&all, ".ShellClassInfo", "LocalizedResourceName");
    let mut summary = "Folder settings".to_owned();
    if let Some(n) = name {
        summary.push_str(&format!(", name {n}"));
    }
    if let Some(c) = class {
        summary.push_str(&format!(", class {c}"));
    }
    cx.annotate(summary);
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows 3.x Program Manager groups (.grp)

declare_format!(pub GRP = "win-grp", "Windows Program Manager group", ["grp"], "application/x-ms-grp",
    Probe::Magic(&[(0, b"PMCC")]), grp);

record! {
    pub struct GrpHeader {
        identifier: ascii[4] "Identifier",
        checksum: u16 "Checksum" .hex(),
        size: u16 "Group size (tag data offset)" .hex(),
        show: u16 "Show command",
        left: i16 "Normal rectangle left",
        top: i16 "Normal rectangle top",
        right: i16 "Normal rectangle right",
        bottom: i16 "Normal rectangle bottom",
        min_x: i16 "Minimized X",
        min_y: i16 "Minimized Y",
        name: u16 "Name offset" .hex(),
        dpi_x: u16 "Logical pixels X",
        dpi_y: u16 "Logical pixels Y",
        bpp: u8 "Bits per pixel",
        planes: u8 "Planes",
        _reserved: u16 "Reserved",
        items: u16 "Number of item slots",
    }
}

fn grp_item_layout(f: &mut Fields<'_>, _: &()) -> Result<(u16, u16, u16)> {
    f.int::<i16>("Icon X").emit()?;
    f.int::<i16>("Icon Y").emit()?;
    f.u16("Icon index").emit()?;
    f.u16("Icon resource size").emit()?;
    f.u16("AND plane size").emit()?;
    f.u16("XOR plane size").emit()?;
    f.u16("Icon header offset").hex().emit()?;
    f.u16("AND plane offset").hex().emit()?;
    f.u16("XOR plane offset").hex().emit()?;
    let name = f.u16("Name offset").hex().emit()?;
    let command = f.u16("Command offset").hex().emit()?;
    let icon = f.u16("Icon path offset").hex().emit()?;
    Ok((name, command, icon))
}

const GRP_TAGS: EnumTable = &[
    (0x8000, "Start"),
    (0x8101, "Working directory"),
    (0x8102, "Hot key"),
    (0x8103, "Run minimized"),
    (0xffff, "End"),
];

async fn grp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, GrpHeader::SIZE);
    let h: GrpHeader = read_record(&cx, span, LE).await?;
    cx.emit(GrpHeader::node("Header", span, LE));
    let (name, name_span) = cx.cstr(file.sub(h.name.into(), 256)).await?;
    cx.emit(
        Node::new("Group name")
            .span(name_span)
            .value(text(name.clone())),
    );
    let slots_span = file.sub_exact(GrpHeader::SIZE, u64::from(h.items).saturating_mul(2))?;
    let slots = cx.read(slots_span).await?;
    let mut programs = Vec::new();
    for (i, s) in slots.as_chunks::<2>().0.iter().enumerate() {
        let at = u16::from_le_bytes(*s);
        if at == 0 {
            continue;
        }
        let item = file.sub(at.into(), 24);
        let block = cx.block(item).await?;
        let (name_at, command_at, _) = grp_item_layout(&mut Fields::new(&block, LE), &())?;
        let (title, _) = cx.cstr(file.sub(name_at.into(), 256)).await?;
        let (command, _) = cx.cstr(file.sub(command_at.into(), 256)).await?;
        programs.push(title.clone());
        cx.push(
            Node::new(title)
                .span(item)
                .summary(command)
                .desc(format!("Item slot {i}"))
                .lazy(grp_item, (input, item)),
        )
        .await;
    }
    if u64::from(h.size) < file.len {
        cx.emit(
            Node::new("Tag data")
                .span(file.tail(h.size.into()))
                .lazy(grp_tags, file.tail(h.size.into())),
        );
    }
    cx.annotate(format!(
        "Program Manager group {name:?}, {} programs",
        programs.len()
    ));
    Ok(())
}

async fn grp_item(cx: Cx, (input, item): (Input, Span)) -> Result<()> {
    let file = input.span;
    let block = cx.block(item).await?;
    let (name, command, icon) = grp_item_layout(&mut Fields::emitting(&cx, &block, LE), &())?;
    for (label, at) in [
        ("Name", name),
        ("Command line", command),
        ("Icon path", icon),
    ] {
        let (s, span) = cx.cstr(file.sub(at.into(), 256)).await?;
        cx.emit(Node::new(label).span(span).value(text(s)));
    }
    Ok(())
}

async fn grp_tags(cx: Cx, region: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, region, LE);
    while cur.remaining() >= 6 {
        let start = cur.pos();
        let id = cur.u16().await?;
        let item = cur.u16().await?;
        let len = u64::from(cur.u16().await?);
        if id == 0xffff {
            cx.push(Node::new("End").span(cur.since(start))).await;
            break;
        }
        if len < 6 {
            cx.diag(Diagnostic::malformed("tag shorter than its header").at(cur.since(start)));
            break;
        }
        let data_span = cur.span(len.saturating_sub(6));
        let data = cur.bytes(len.saturating_sub(6)).await?;
        let name =
            lookup(GRP_TAGS, id.into()).map_or_else(|| format!("Tag {id:#06x}"), str::to_owned);
        let mut node = Node::new(name).span(cur.since(start)).target(data_span);
        node = match id {
            0x8101 | 0x8000 => node.value(text(crate::text::until_nul(&data))),
            0x8102 => node.value(hex(u16_le(&data, 0).unwrap_or(0), 16)),
            _ => node,
        };
        if id != 0x8000 && id != 0xffff {
            node = node.summary(format!("item {item}"));
        }
        cx.push(node).await;
        if id == 0xffff {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows Cardfile (.crd)

fn cardfile_probe(h: &Head<'_>) -> bool {
    let (count_at, index_at) = if h.starts_with(b"MGC") {
        (3usize, 5usize)
    } else if h.starts_with(b"RRG") {
        (7, 9)
    } else {
        return false;
    };
    let Some(count) = u16_le(h.data, count_at) else {
        return false;
    };
    let first_card = to_u64(index_at).saturating_add(u64::from(count).saturating_mul(52));
    count > 0
        && h.at(index_at, &[0; 6])
        && u32_le(h.data, index_at.saturating_add(6))
            .is_some_and(|p| u64::from(p) >= first_card && u64::from(p) < h.len)
}

declare_format!(pub CARDFILE = "cardfile", "Windows Cardfile", ["crd"], "application/x-ms-cardfile",
    Probe::Custom(cardfile_probe), cardfile);

fn card_index_layout(f: &mut Fields<'_>, _: &()) -> Result<(u32, String)> {
    f.bytes("Reserved", 6).emit()?;
    let at = f.u32("Card data offset").hex().emit()?;
    f.u8("Flags").hex().emit()?;
    let title = f.ascii("Index line", 40).emit()?;
    f.u8("Terminator").emit()?;
    Ok((at, title))
}

async fn cardfile(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 3)).await?;
    let rrg = magic == b"RRG";
    let head_len = if rrg { 9 } else { 5 };
    let head = cx.block(file.sub(0, head_len)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 3).emit()?;
    if rrg {
        f.u32("Last object ID").emit()?;
    }
    let count = f.u16("Number of cards").emit()?;
    cx.set_count(Count::Exact(u64::from(count).saturating_add(if rrg {
        3
    } else {
        2
    })));
    let mut titles = Vec::new();
    for i in 0..u64::from(count) {
        let span = file.sub(head_len.saturating_add(i.saturating_mul(52)), 52);
        let block = cx.block(span).await?;
        let (at, title) = card_index_layout(&mut Fields::new(&block, LE), &())?;
        titles.push(title.clone());
        cx.push(
            Node::new(format!("Card {title:?}"))
                .span(span)
                .lazy(card, (input, span, u64::from(at), rrg)),
        )
        .await;
    }
    cx.annotate(format!(
        "Cardfile ({}), {count} cards: {}",
        if rrg {
            "Windows 3.1 with objects"
        } else {
            "Windows 3.0"
        },
        clip(&titles.join(", "), 100)
    ));
    Ok(())
}

async fn card(cx: Cx, (input, index, at, rrg): (Input, Span, u64, bool)) -> Result<()> {
    let file = input.span;
    cx.emit(struct_node("Index entry", index, LE, (), card_index_layout));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(at);
    if rrg {
        let start = cur.pos();
        let object = cur.u16().await?;
        cx.emit(
            Node::new("Object flag")
                .span(cur.since(start))
                .value(uint(object, 16)),
        );
        if object != 0 {
            let start = cur.pos();
            let id = cur.u32().await?;
            cx.emit(
                Node::new("Object ID")
                    .span(cur.since(start))
                    .value(uint(id, 32)),
            );
            let start = cur.pos();
            ole1_skip(&mut cur).await?;
            cx.emit(Node::new("OLE 1.0 object").span(cur.since(start)));
            let start = cur.pos();
            cur.skip(14);
            cx.emit(
                Node::new("Object placement")
                    .span(cur.since(start))
                    .desc("Character width and height, rectangle, object type"),
            );
        }
    } else {
        let start = cur.pos();
        let bitmap = cur.u16().await?;
        cx.emit(
            Node::new("Bitmap size")
                .span(cur.since(start))
                .value(uint(bitmap, 16)),
        );
        if bitmap != 0 {
            let start = cur.pos();
            let w = cur.u16().await?;
            let h = cur.u16().await?;
            cur.skip(4);
            cur.skip(bitmap.into());
            cx.emit(
                Node::new("Bitmap")
                    .span(cur.since(start))
                    .summary(format!("{w}×{h} monochrome")),
            );
        }
    }
    let start = cur.pos();
    let len = cur.u16().await?;
    cx.emit(
        Node::new("Text length")
            .span(cur.since(start))
            .value(uint(len, 16)),
    );
    let span = cur.span(len.into());
    let body = cur.bytes(len.into()).await?;
    cx.emit(
        Node::new("Text")
            .span(span)
            .value(text(crate::text::latin1(&body))),
    );
    Ok(())
}

/// Skips an OLE 1.0 object stream (version, format, class/topic/item names
/// and native or presentation data).
async fn ole1_skip(cur: &mut Cursor<'_>) -> Result<()> {
    async fn string(cur: &mut Cursor<'_>) -> Result<()> {
        let n = cur.u32().await?;
        if u64::from(n) > cur.remaining() {
            return Err(Diagnostic::malformed("OLE string longer than the data"));
        }
        cur.skip(n.into());
        Ok(())
    }
    // An embedded object is followed by its presentation object.
    for _ in 0..2 {
        cur.u32().await?; // OLE version
        let format = cur.u32().await?;
        match format {
            2 => {
                string(cur).await?; // class name
                string(cur).await?; // topic
                string(cur).await?; // item
                string(cur).await?; // native data (size + bytes)
            }
            3 => {
                string(cur).await?; // class name
                cur.skip(8); // width, height
                string(cur).await?; // presentation data
                return Ok(());
            }
            _ => return Ok(()),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows Clipboard Viewer files (.clp)

fn clp_entry_size(id: u16) -> u64 {
    if id == 0xc350 { 89 } else { 170 }
}

fn clp_probe(h: &Head<'_>) -> bool {
    let Some(id) = u16_le(h.data, 0) else {
        return false;
    };
    if !matches!(id, 0xc350..=0xc352) {
        return false;
    }
    let Some(count) = u16_le(h.data, 2) else {
        return false;
    };
    let table_end = 4u64.saturating_add(u64::from(count).saturating_mul(clp_entry_size(id)));
    let offset_at = if id == 0xc350 { 10 } else { 12 };
    (1..=64).contains(&count)
        && table_end <= h.len
        && u32_le(h.data, offset_at)
            .is_some_and(|o| u64::from(o) >= table_end && u64::from(o) <= h.len)
}

declare_format!(pub CLP = "clipboard", "Windows Clipboard file", ["clp"], "application/x-ms-clipboard",
    Probe::Custom(clp_probe), clp);

const CLIPBOARD_FORMATS: EnumTable = &[
    (1, "CF_TEXT"),
    (2, "CF_BITMAP"),
    (3, "CF_METAFILEPICT"),
    (4, "CF_SYLK"),
    (5, "CF_DIF"),
    (6, "CF_TIFF"),
    (7, "CF_OEMTEXT"),
    (8, "CF_DIB"),
    (9, "CF_PALETTE"),
    (10, "CF_PENDATA"),
    (11, "CF_RIFF"),
    (12, "CF_WAVE"),
    (13, "CF_UNICODETEXT"),
    (14, "CF_ENHMETAFILE"),
    (15, "CF_HDROP"),
    (16, "CF_LOCALE"),
    (17, "CF_DIBV5"),
    (0x80, "CF_OWNERDISPLAY"),
    (0x81, "CF_DSPTEXT"),
    (0x82, "CF_DSPBITMAP"),
    (0x83, "CF_DSPMETAFILEPICT"),
    (0x8e, "CF_DSPENHMETAFILE"),
];

fn clp_entry_layout(f: &mut Fields<'_>, nt: &bool) -> Result<(u32, u32, u32, String)> {
    let id = if *nt {
        f.u32("Format ID").enumeration(CLIPBOARD_FORMATS).emit()?
    } else {
        u32::from(f.u16("Format ID").enumeration(CLIPBOARD_FORMATS).emit()?)
    };
    let len = f.u32("Data length").emit()?;
    let at = f.u32("Data offset").hex().emit()?;
    let name = if *nt {
        f.utf16("Format name", 79).emit()?
    } else {
        f.ascii("Format name", 79).emit()?
    };
    Ok((id, len, at, name))
}

async fn clp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let id = f
        .u16("File identifier")
        .enumeration(&[
            (0xc350, "Windows 3.x"),
            (0xc351, "Windows NT"),
            (0xc352, "Windows NT (ClipBook)"),
        ])
        .emit()?;
    let count = f.u16("Number of formats").emit()?;
    let nt = id != 0xc350;
    let entry = clp_entry_size(id);
    let mut names = Vec::new();
    for i in 0..u64::from(count) {
        let span = file.sub(4u64.saturating_add(i.saturating_mul(entry)), entry);
        let block = cx.block(span).await?;
        let (format, len, at, name) = clp_entry_layout(&mut Fields::new(&block, LE), &nt)?;
        let label = lookup(CLIPBOARD_FORMATS, format.into()).map_or_else(
            || {
                if name.is_empty() {
                    format!("Format {format:#x}")
                } else {
                    name.clone()
                }
            },
            str::to_owned,
        );
        names.push(label.clone());
        cx.push(Node::new(label).span(span).summary(size(len.into())).lazy(
            clp_format,
            (input, span, nt, format, file.sub(at.into(), len.into())),
        ))
        .await;
    }
    cx.annotate(format!(
        "Clipboard file ({}), {count} formats: {}",
        if nt { "NT" } else { "Windows 3.x" },
        names.join(", ")
    ));
    Ok(())
}

async fn clp_format(
    cx: Cx,
    (input, entry, nt, format, data): (Input, Span, bool, u32, Span),
) -> Result<()> {
    cx.emit(struct_node(
        "Directory entry",
        entry,
        LE,
        nt,
        clp_entry_layout,
    ));
    match format {
        1 | 7 | 0x81 => {
            let bytes = cx.read_avail(data.sub(0, 0x10000)).await?;
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            cx.emit(Node::new("Text").span(data).value(text(crate::text::latin1(
                bytes.get(..end).unwrap_or_default(),
            ))));
        }
        16 => {
            let bytes = cx.read_avail(data.sub(0, 4)).await?;
            cx.emit(
                Node::new("Locale ID")
                    .span(data)
                    .value(hex(u32_le(&bytes, 0).unwrap_or(0), 32)),
            );
        }
        13 => {
            let bytes = cx.read_avail(data.sub(0, 0x20000)).await?;
            cx.emit(
                Node::new("Text")
                    .span(data)
                    .value(text(crate::text::utf16z(&bytes, LE).0)),
            );
        }
        8 | 17 => {
            let head = cx.read_avail(data.sub(0, 16)).await?;
            let (w, h) = (
                crate::bytes::i32_le(&head, 4).unwrap_or(0),
                crate::bytes::i32_le(&head, 8).unwrap_or(0),
            );
            let bpp = u16_le(&head, 14).unwrap_or(0);
            cx.emit(
                Node::new("Device-independent bitmap")
                    .span(data)
                    .summary(format!("{w}×{} at {bpp} bpp", h.unsigned_abs())),
            );
        }
        3 | 0x83 => {
            // METAFILEPICT (mapping mode, extents, handle) precedes the metafile.
            let header = if nt { 16 } else { 8 };
            cx.emit(Node::new("METAFILEPICT").span(data.sub(0, header)));
            cx.emit(embedded("Metafile", input.nested(data.tail(header))));
        }
        14 | 0x8e => cx.emit(embedded("Enhanced metafile", input.nested(data))),
        _ => cx.emit(text_or_embedded(&cx, input, data).await?),
    }
    Ok(())
}

/// A node for opaque data: its text if it looks like text, otherwise the
/// data identified as an embedded file.
pub(crate) async fn text_or_embedded(cx: &Cx, input: Input, span: Span) -> Result<Node> {
    let head = cx.read_avail(span.sub(0, 0x1000)).await?;
    let printable = head.split(|&b| b == 0).next().unwrap_or_default();
    if !head.is_empty()
        && crate::text::looks_like_text(printable)
        && printable.len() >= head.len().saturating_sub(1)
    {
        let full = cx.read_avail(span.sub(0, 0x10000)).await?;
        return Ok(Node::new("Data")
            .span(span)
            .value(text(crate::text::until_nul(&full))));
    }
    Ok(embedded("Data", input.nested(span)))
}

// ---------------------------------------------------------------------------
// Remote Desktop connection files (.rdp)

/// The start of the file as text: UTF-16LE (with BOM) or 8-bit.
fn rdp_text(data: &[u8]) -> (String, bool) {
    match data.strip_prefix(b"\xff\xfe") {
        Some(rest) => (crate::text::utf16(rest, LE), true),
        None => (
            crate::text::latin1(data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data)),
            false,
        ),
    }
}

/// A `name:type:value` setting line.
fn rdp_setting(line: &str) -> Option<(&str, &str, &str)> {
    let (name, rest) = line.split_once(':')?;
    let (kind, value) = rest.split_once(':')?;
    (matches!(kind, "i" | "s" | "b")
        && !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b' ' || b == b'_'))
    .then_some((name, kind, value))
}

fn rdp_probe(h: &Head<'_>) -> bool {
    let (txt, _) = rdp_text(h.data.get(..2048).unwrap_or(h.data));
    let first = txt.lines().next().unwrap_or_default();
    rdp_setting(first.trim_end()).is_some() && txt.contains("full address:s:")
}

declare_format!(pub RDP_FILE = "rdp-connection", "Remote Desktop connection file (.rdp)", ["rdp"], "application/x-rdp",
    Probe::Custom(rdp_probe), rdp_file);

async fn rdp_file(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, 0x20000)).await?;
    let (txt, wide) = rdp_text(&data);
    let unit = if wide { 2u64 } else { 1 };
    let mut at = if wide { 2u64 } else { 0 };
    let (mut address, mut user, mut gateway) = (String::new(), String::new(), String::new());
    for line in txt.split_inclusive('\n') {
        let len = to_u64(
            line.chars()
                .map(|c| if wide { c.len_utf16() } else { 1 })
                .sum::<usize>(),
        )
        .saturating_mul(unit);
        let span = file.sub(at, len);
        at = at.saturating_add(len);
        let Some((name, kind, value)) = rdp_setting(line.trim_end()) else {
            continue;
        };
        match name {
            "full address" => address = value.to_owned(),
            "username" => user = value.to_owned(),
            "gatewayhostname" => gateway = value.to_owned(),
            _ => {}
        }
        let node = Node::new(name.to_owned()).span(span);
        cx.push(match kind {
            "i" => node.value(
                value
                    .parse::<i64>()
                    .map_or_else(|_| text(value), |v| Value::Int { value: v, bits: 32 }),
            ),
            "b" => node.value(text(clip(value, 200))).desc("binary (hex)"),
            _ => node.value(text(value)),
        })
        .await;
    }
    let mut summary = format!(
        "Remote Desktop connection to {}",
        if address.is_empty() { "?" } else { &address }
    );
    if !user.is_empty() {
        summary.push_str(&format!(" as {user}"));
    }
    if !gateway.is_empty() {
        summary.push_str(&format!(" via {gateway}"));
    }
    cx.annotate(summary);
    Ok(())
}

// ---------------------------------------------------------------------------
// Jump list DestList stream (inside *.automaticDestinations-ms)

fn destlist_probe(h: &Head<'_>) -> bool {
    let version = u32_le(h.data, 0).unwrap_or(0);
    let entries = u32_le(h.data, 4).unwrap_or(u32::MAX);
    let pinned = u32_le(h.data, 8).unwrap_or(u32::MAX);
    // The first entry's NetBIOS name: printable, NUL-padded.
    let host = h.data.get(32 + 72..32 + 88).unwrap_or_default();
    let end = host.iter().position(|&b| b == 0).unwrap_or(host.len());
    matches!(version, 1 | 3 | 4)
        && (1..100_000).contains(&entries)
        && pinned <= entries
        && end > 0
        && host
            .get(..end)
            .is_some_and(|n| n.iter().all(|&b| b.is_ascii_graphic()))
        && host.get(end..).is_some_and(|n| n.iter().all(|&b| b == 0))
}

declare_format!(pub DESTLIST = "jumplist-destlist", "Windows jump list DestList stream", [], "application/x-ms-destlist",
    Probe::Custom(destlist_probe), destlist);

fn destlist_entry(f: &mut Fields<'_>, version: &u32) -> Result<(String, u64, u32, String)> {
    f.u64("Checksum").hex().emit()?;
    f.guid("Volume droid").emit()?;
    f.guid("File droid").emit()?;
    f.guid("Birth volume droid").emit()?;
    f.guid("Birth file droid").emit()?;
    let host = f.ascii("NetBIOS name", 16).emit()?;
    let number = f.u32("Entry number").emit()?;
    f.u32("Unknown").emit()?;
    f.f32("Access weight").emit()?;
    let time = f.u64("Last access time").filetime().emit()?;
    f.int::<i32>("Pin status")
        .with(|&v, n| {
            n.summary(if v < 0 {
                "not pinned".to_owned()
            } else {
                format!("pinned at {v}")
            })
        })
        .emit()?;
    if *version >= 3 {
        f.u32("Unknown").emit()?;
        f.u32("Access count").emit()?;
        f.u64("Unknown").emit()?;
    }
    let chars = f.u16("Path length").emit()?;
    let path = f.utf16("Path", chars.into()).emit()?;
    if *version >= 3 {
        f.u32("Unknown").emit()?;
    }
    Ok((path, time, number, host))
}

async fn destlist(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let version = f.u32("Version").emit()?;
    let entries = f.u32("Number of entries").emit()?;
    let pinned = f.u32("Number of pinned entries").emit()?;
    f.f32("Unknown").emit()?;
    f.u32("Last entry number").emit()?;
    f.u32("Unknown").emit()?;
    f.u32("Last revision number").emit()?;
    f.u32("Unknown").emit()?;
    let fixed: u64 = if version >= 3 { 130 } else { 114 };
    let mut at = 32u64;
    for _ in 0..entries.min(100_000) {
        let head = cx.read_avail(file.sub(at, fixed)).await?;
        let chars =
            u64::from(u16_le(&head, crate::bytes::to_usize(fixed.saturating_sub(2))).unwrap_or(0));
        let len = fixed
            .saturating_add(chars.saturating_mul(2))
            .saturating_add(if version >= 3 { 4 } else { 0 });
        let span = file.sub(at, len);
        let block = cx.block(span).await?;
        let (path, time, number, host) = destlist_entry(&mut Fields::new(&block, LE), &version)?;
        cx.push(
            struct_node(path, span, LE, version, destlist_entry)
                .value(filetime(time))
                .summary(format!("entry {number} on {host}")),
        )
        .await;
        at = at.saturating_add(len);
        if at >= file.len {
            break;
        }
    }
    cx.annotate(format!(
        "Jump list DestList v{version}, {entries} entries ({pinned} pinned)"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// OneDrive sync engine logs (.odl, .odlgz)

declare_format!(pub ODL = "onedrive-odl", "OneDrive sync log (.odl)", ["odl", "odlgz", "odlsent"], "application/x-onedrive-odl",
    Probe::Magic(&[(0, b"EBFGONED")]), odl);

fn odl_header(f: &mut Fields<'_>, _: &()) -> Result<(u32, String, String)> {
    f.ascii("Signature", 8).emit()?;
    let version = f.u32("Version").emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u64("Unknown").hex().emit()?;
    f.u32("Unknown").hex().emit()?;
    let app = f.ascii("OneDrive version", 64).emit()?;
    let os = f.ascii("Windows version", 64).emit()?;
    f.bytes("Reserved", 100).emit()?;
    Ok((version, app, os))
}

const ODL_BLOCK: u64 = 0xccdd_eeff_0000_0000;

async fn odl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, 256);
    let block = cx.block(hspan).await?;
    let (version, app, os) = odl_header(&mut Fields::new(&block, LE), &())?;
    cx.emit(struct_node("Header", hspan, LE, (), odl_header));
    let body = file.tail(256);
    if cx.read_avail(body.sub(0, 2)).await? == b"\x1f\x8b" {
        cx.emit(embedded("Records (gzip)", input.nested(body)));
        cx.annotate(format!(
            "OneDrive log v{version} (compressed), OneDrive {}, {}",
            app.trim(),
            os.trim()
        ));
        return Ok(());
    }
    let header_len: u64 = if version >= 3 { 32 } else { 56 };
    let mut cur = Cursor::new(&cx, body, LE);
    let mut count = 0u64;
    while cur.remaining() >= header_len {
        let start = cur.pos();
        let sig = cur.u64().await?;
        if sig != ODL_BLOCK {
            cx.diag(Diagnostic::malformed("expected a record signature").at(cur.since(start)));
            break;
        }
        let ms = cur.u64().await?;
        cur.skip(header_len.saturating_sub(24));
        let len = u64::from(cur.u32().await?);
        cur.skip(4);
        let data = cur.span(len);
        let raw = cur.bytes(len.min(0x1000)).await?;
        cur.seek(data.end().saturating_sub(body.offset));
        // Data: code file name and function name as length-prefixed strings.
        let s1 = u32_le(&raw, 0).map_or(0, |n| crate::bytes::to_usize(n.into()));
        let code_file =
            String::from_utf8_lossy(raw.get(4..4usize.saturating_add(s1)).unwrap_or_default())
                .into_owned();
        let at2 = 4usize.saturating_add(s1).saturating_add(4);
        let s2 = u32_le(&raw, at2).map_or(0, |n| crate::bytes::to_usize(n.into()));
        let function = String::from_utf8_lossy(
            raw.get(at2.saturating_add(4)..at2.saturating_add(4).saturating_add(s2))
                .unwrap_or_default(),
        )
        .into_owned();
        count = count.saturating_add(1);
        cx.push(
            Node::new(format!("{code_file} {function}").trim().to_owned())
                .span(cur.since(start))
                .target(data)
                .value(Value::Timestamp {
                    unix_seconds: i64::try_from(ms / 1000).unwrap_or(0),
                })
                .summary(size(len)),
        )
        .await;
    }
    cx.annotate(format!(
        "OneDrive log v{version}, {count} records, OneDrive {}, {}",
        app.trim(),
        os.trim()
    ));
    Ok(())
}
