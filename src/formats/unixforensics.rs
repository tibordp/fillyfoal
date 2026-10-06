//! macOS, iOS, Linux and Android forensic artifacts: FSEvents logs, the
//! Unified Log (tracev3 and timesync), Apple System Log stores, iOS backup
//! manifests, login records (utmp/wtmp/btmp) and Android binary XML.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_be, u16_le, u32_be, u32_le, u64_be, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Path, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::datakit::{clip, hex, hex_string, size, text};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn unix_time(seconds: i64) -> Value {
    Value::Timestamp {
        unix_seconds: seconds,
    }
}

// ---------------------------------------------------------------------------
// macOS FSEvents (.fseventsd pages, after gzip decompression)

fn fsevents_probe(h: &Head<'_>) -> bool {
    (h.starts_with(b"1SLD") || h.starts_with(b"2SLD") || h.starts_with(b"3SLD"))
        && u32_le(h.data, 8).is_some_and(|len| len >= 12)
}

declare_format!(pub FSEVENTS = "fsevents", "macOS FSEvents log", [], "application/x-apple-fsevents",
    Probe::Custom(fsevents_probe), fsevents);

const FSEVENT_FLAGS: FlagTable = &[
    flag(0x0000_0001, "FolderEvent"),
    flag(0x0000_0002, "Mount"),
    flag(0x0000_0004, "Unmount"),
    flag(0x0000_0020, "EndOfTransaction"),
    flag(0x0000_0800, "LastHardLinkRemoved"),
    flag(0x0000_1000, "HardLink"),
    flag(0x0000_4000, "SymbolicLink"),
    flag(0x0000_8000, "FileEvent"),
    flag(0x0001_0000, "PermissionChange"),
    flag(0x0002_0000, "ExtendedAttrModified"),
    flag(0x0004_0000, "ExtendedAttrRemoved"),
    flag(0x0010_0000, "DocumentRevisioning"),
    flag(0x0040_0000, "ItemCloned"),
    flag(0x0100_0000, "Created"),
    flag(0x0200_0000, "Removed"),
    flag(0x0400_0000, "InodeMetaMod"),
    flag(0x0800_0000, "Renamed"),
    flag(0x1000_0000, "Modified"),
    flag(0x2000_0000, "Exchange"),
    flag(0x4000_0000, "FinderInfoMod"),
    flag(0x8000_0000, "FolderCreated"),
];

fn flag_names(table: FlagTable, raw: u32) -> String {
    table
        .iter()
        .filter(|d| u64::from(raw) & d.mask == d.value)
        .map(|d| d.name)
        .collect::<Vec<_>>()
        .join(" | ")
}

async fn fsevents(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    let (mut pages, mut records) = (0u32, 0u64);
    let mut version = 0u8;
    while at.saturating_add(12) <= file.len {
        let head = cx.read(file.sub(at, 12)).await?;
        let magic = head.get(..4).unwrap_or_default();
        if !matches!(magic, b"1SLD" | b"2SLD" | b"3SLD") {
            cx.diag(
                Diagnostic::malformed("expected a page signature (1SLD/2SLD/3SLD)")
                    .at(file.sub(at, 4)),
            );
            break;
        }
        version = magic.first().map_or(1, |b| b.saturating_sub(b'0'));
        let len = u64::from(u32_le(&head, 8).unwrap_or(0)).max(12);
        let span = file.sub(at, len);
        let count = fsevents_count(&cx, span, version).await?;
        records = records.saturating_add(count);
        cx.push(
            Node::new(format!("Page {pages}"))
                .span(span)
                .summary(format!("version {version}, {count} records"))
                .lazy(fsevents_page, (span, version)),
        )
        .await;
        pages = pages.saturating_add(1);
        at = at.saturating_add(len);
    }
    cx.annotate(format!(
        "FSEvents log (version {version}), {pages} pages, {records} records"
    ));
    Ok(())
}

/// Bytes after the path: event ID, flags, and (v2+) node ID, (v3) extra.
fn fsevents_tail(version: u8) -> u64 {
    match version {
        1 => 12,
        2 => 20,
        _ => 24,
    }
}

async fn fsevents_count(cx: &Cx, page: Span, version: u8) -> Result<u64> {
    let data = cx.read_avail(page.tail(12)).await?;
    let mut at = 0usize;
    let mut n = 0u64;
    while let Some(nul) = data.get(at..).and_then(|r| r.iter().position(|&b| b == 0)) {
        at = at
            .saturating_add(nul)
            .saturating_add(1)
            .saturating_add(to_usize(fsevents_tail(version)));
        if at > data.len() {
            break;
        }
        n = n.saturating_add(1);
    }
    Ok(n)
}

async fn fsevents_page(cx: Cx, (page, version): (Span, u8)) -> Result<()> {
    let head = cx.block(page.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("Page length").emit()?;
    let mut cur = Cursor::new(&cx, page, LE);
    cur.seek(12);
    while !cur.at_end() {
        let start = cur.pos();
        let (path, _) = cur.cstr(4096).await?;
        if cur.remaining() < fsevents_tail(version) {
            cx.diag(Diagnostic::malformed("record truncated").at(cur.since(start)));
            break;
        }
        let id = cur.u64().await?;
        let flags = cur.u32().await?;
        if version >= 2 {
            cur.skip(8);
        }
        if version >= 3 {
            cur.skip(4);
        }
        let span = cur.since(start);
        cx.push(
            struct_node(path, span, LE, version, fsevents_record)
                .value(hex(id, 64))
                .summary(flag_names(FSEVENT_FLAGS, flags)),
        )
        .await;
    }
    Ok(())
}

fn fsevents_record(f: &mut Fields<'_>, version: &u8) -> Result<()> {
    f.cstr("Path").emit()?;
    f.u64("Event ID").hex().emit()?;
    f.u32("Flags").flags(FSEVENT_FLAGS).emit()?;
    if *version >= 2 {
        f.u64("Node ID").emit()?;
    }
    if *version >= 3 {
        f.u32("Unknown").hex().emit()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS Unified Log: timesync

declare_format!(pub TIMESYNC = "macos-timesync", "macOS Unified Log timesync database", ["timesync"], "application/x-apple-timesync",
    Probe::Magic(&[(0, b"\xb0\xbb\x30\x00")]), timesync);

fn timesync_boot(f: &mut Fields<'_>, _: &()) -> Result<(String, i64)> {
    f.u16("Signature").hex().emit()?;
    f.u16("Header size").emit()?;
    f.u32("Unknown").emit()?;
    let uuid = f.bytes("Boot UUID", 16).emit()?;
    f.u32("Timebase numerator").emit()?;
    f.u32("Timebase denominator").emit()?;
    let ns = f
        .int::<i64>("Boot time")
        .with(|&v, n| n.value(unix_time(v / 1_000_000_000)))
        .emit()?;
    f.int::<i32>("Timezone offset (minutes)").emit()?;
    f.u32("Daylight saving").emit()?;
    Ok((hex_string(&uuid).to_uppercase(), ns / 1_000_000_000))
}

fn timesync_sync(f: &mut Fields<'_>, _: &()) -> Result<i64> {
    f.ascii("Signature", 4).emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u64("Kernel continuous time").emit()?;
    let ns = f
        .int::<i64>("Wall time")
        .with(|&v, n| n.value(unix_time(v / 1_000_000_000)))
        .emit()?;
    f.int::<i32>("Timezone offset (minutes)").emit()?;
    f.u32("Daylight saving").emit()?;
    Ok(ns / 1_000_000_000)
}

async fn timesync(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (mut boots, mut syncs) = (0u32, 0u32);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let sig = cur.peek(4).await?;
        if sig.starts_with(b"\xb0\xbb") {
            let len = u64::from(u16_le(&sig, 2).unwrap_or(48)).max(48);
            let span = file.sub(start, len);
            let block = cx.block(span).await?;
            let (uuid, time) = timesync_boot(&mut Fields::new(&block, LE), &())?;
            cx.push(
                struct_node(format!("Boot {uuid}"), span, LE, (), timesync_boot)
                    .value(unix_time(time)),
            )
            .await;
            boots = boots.saturating_add(1);
            cur.seek(start.saturating_add(len));
        } else if sig == b"Ts \0" {
            let span = file.sub(start, 32);
            let block = cx.block(span).await?;
            let time = timesync_sync(&mut Fields::new(&block, LE), &())?;
            cx.push(struct_node("Sync", span, LE, (), timesync_sync).value(unix_time(time)))
                .await;
            syncs = syncs.saturating_add(1);
            cur.seek(start.saturating_add(32));
        } else {
            cx.diag(Diagnostic::malformed("unknown record signature").at(file.sub(start, 4)));
            break;
        }
    }
    cx.annotate(format!(
        "Unified Log timesync, {boots} boots, {syncs} sync records"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS Unified Log: tracev3

fn tracev3_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(0x1000)
        && u32_le(h.data, 4) == Some(0x11)
        && u64_le(h.data, 8) == Some(0xd0)
}

declare_format!(pub TRACEV3 = "tracev3", "macOS Unified Log (tracev3)", ["tracev3"], "application/x-apple-tracev3",
    Probe::Custom(tracev3_probe), tracev3);

const TRACEV3_CHUNKS: EnumTable = &[
    (0x1000, "Header"),
    (0x6001, "Firehose"),
    (0x6002, "Oversize"),
    (0x6003, "Statedump"),
    (0x6004, "Simpledump"),
    (0x600b, "Catalog"),
    (0x600d, "Chunkset"),
];

fn tracev3_header(f: &mut Fields<'_>, _: &()) -> Result<(String, String)> {
    f.u32("Timebase numerator").emit()?;
    f.u32("Timebase denominator").emit()?;
    f.u64("Start continuous time").emit()?;
    f.u64("Start time").timestamp().emit()?;
    f.u32("Unknown").emit()?;
    f.u32("Timezone bias (minutes)").emit()?;
    f.u32("Daylight saving").emit()?;
    f.u32("Flags").hex().emit()?;
    f.u32("Subchunk tag").hex().emit()?;
    f.u32("Subchunk size").emit()?;
    f.u64("Continuous time").emit()?;
    f.u32("Subchunk tag").hex().emit()?;
    f.u32("Subchunk size").emit()?;
    f.u32("Unknown").emit()?;
    f.u32("Unknown").emit()?;
    let build = f.ascii("Build version", 16).emit()?;
    let model = f.ascii("Hardware model", 32).emit()?;
    f.u32("Subchunk tag").hex().emit()?;
    f.u32("Subchunk size").emit()?;
    f.bytes("Boot UUID", 16).emit()?;
    f.u32("logd PID").emit()?;
    f.u32("logd exit status").emit()?;
    f.u32("Subchunk tag").hex().emit()?;
    f.u32("Subchunk size").emit()?;
    f.ascii("Timezone path", 48).emit()?;
    Ok((build, model))
}

fn tracev3_catalog(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Subsystem strings offset").hex().emit()?;
    f.u16("Process info offset").hex().emit()?;
    f.u16("Number of process info entries").emit()?;
    f.u16("Subchunks offset").hex().emit()?;
    f.u16("Number of subchunks").emit()?;
    f.bytes("Padding", 6).emit()?;
    f.u64("Earliest firehose time").emit()?;
    Ok(())
}

async fn tracev3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut counts = std::collections::BTreeMap::<u32, u32>::new();
    let mut summary = String::new();
    while cur.remaining() >= 16 {
        let start = cur.pos();
        let tag = cur.u32().await?;
        let sub = cur.u32().await?;
        let len = cur.u64().await?;
        if len > cur.remaining() {
            cx.diag(
                Diagnostic::malformed("chunk extends past the end of the file")
                    .at(cur.since(start)),
            );
            break;
        }
        let data = cur.span(len);
        cur.skip(len);
        cur.seek(cur.pos().next_multiple_of(8).min(file.len));
        let entry = counts.entry(tag).or_insert(0);
        *entry = entry.saturating_add(1);
        let name = lookup(TRACEV3_CHUNKS, tag.into())
            .map_or_else(|| format!("Chunk {tag:#x}"), str::to_owned);
        let node = match tag {
            0x1000 => {
                let block = cx.block(data).await?;
                if let Ok((build, model)) = tracev3_header(&mut Fields::new(&block, LE), &()) {
                    summary = format!("{model}, build {build}");
                }
                struct_node(name, data, LE, (), tracev3_header).summary(summary.clone())
            }
            0x600b => struct_node(name, data, LE, (), tracev3_catalog),
            0x600d => {
                let head = cx.read_avail(data.sub(0, 12)).await?;
                let mut node = Node::new(name).span(data);
                if head.starts_with(b"bv41") {
                    let out = u32_le(&head, 4).unwrap_or(0);
                    node = node
                        .summary(format!("LZ4, {} uncompressed", size(out.into())))
                        .diag(Diagnostic::unsupported("LZ4 compression"));
                }
                node
            }
            _ => Node::new(name).span(data),
        };
        cx.push(
            node.target(cur.since(start))
                .desc(format!("Tag {tag:#x}, subtag {sub:#x}")),
        )
        .await;
    }
    let parts: Vec<String> = counts
        .iter()
        .filter(|(t, _)| **t != 0x1000)
        .map(|(t, n)| {
            format!(
                "{n} {}",
                lookup(TRACEV3_CHUNKS, (*t).into())
                    .unwrap_or("other")
                    .to_lowercase()
            )
        })
        .collect();
    cx.annotate(format!(
        "Unified Log tracev3 ({summary}), {}",
        parts.join(", ")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Apple System Log store (ASL DB)

declare_format!(pub ASL = "asl", "Apple System Log store", ["asl"], "application/x-apple-asl",
    Probe::Magic(&[(0, b"ASL DB\0\0\0\0\0\0\0\0\0\x02")]), asl);

record! {
    pub struct AslHeader {
        cookie: ascii[12] "Signature",
        version: u32 "Version",
        first: u64 "First record offset" .hex(),
        time: u64 "Creation time" .timestamp(),
        cache_size: u32 "String cache size",
        filter: u8 "Filter mask" .hex(),
        last: u64 "Last record offset" .hex(),
    }
}

const ASL_LEVELS: EnumTable = &[
    (0, "Emergency"),
    (1, "Alert"),
    (2, "Critical"),
    (3, "Error"),
    (4, "Warning"),
    (5, "Notice"),
    (6, "Info"),
    (7, "Debug"),
];

/// Resolves a string reference: inline (high bit set, length in the low
/// bits of the first byte) or the offset of a string record.
async fn asl_string(cx: &Cx, file: Span, raw: u64) -> Result<String> {
    if raw == 0 {
        return Ok(String::new());
    }
    if raw & (1 << 63) != 0 {
        let bytes = raw.to_be_bytes();
        let len = usize::from(bytes.first().copied().unwrap_or(0) & 0x7f).min(7);
        return Ok(String::from_utf8_lossy(
            bytes.get(1..1usize.saturating_add(len)).unwrap_or_default(),
        )
        .into_owned());
    }
    let head = cx.read(file.sub(raw, 6)).await?;
    let len = u64::from(u32_be(&head, 2).unwrap_or(0));
    let data = cx
        .read_avail(file.sub(raw.saturating_add(6), len.min(0x10000)))
        .await?;
    Ok(crate::text::until_nul(&data))
}

/// The fixed part of a message record (after the 6-byte record header).
fn asl_message(f: &mut Fields<'_>, _: &()) -> Result<(u64, u64, u16, u32)> {
    f.u16("Record type").emit()?;
    f.u32("Record length").emit()?;
    let next = f.u64("Next record").hex().emit()?;
    f.u64("Message ID").emit()?;
    let time = f.u64("Time").timestamp().emit()?;
    f.u32("Nanoseconds").emit()?;
    let level = f.u16("Level").enumeration(ASL_LEVELS).emit()?;
    f.u16("Flags").hex().emit()?;
    let pid = f.u32("PID").emit()?;
    f.u32("UID").emit()?;
    f.u32("GID").emit()?;
    f.u32("Real UID").emit()?;
    f.u32("Real GID").emit()?;
    f.u32("Reference PID").emit()?;
    f.u32("Key/value count").emit()?;
    for name in [
        "Host",
        "Sender",
        "Facility",
        "Message",
        "Reference process",
        "Session",
    ] {
        f.u64(name).hex().emit()?;
    }
    Ok((next, time, level, pid))
}

async fn asl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, AslHeader::SIZE);
    let h: AslHeader = read_record(&cx, span, BE).await?;
    cx.emit(AslHeader::node("Header", file.sub(0, 80), BE));
    let mut at = h.first;
    let mut path = Path::new();
    let mut count = 0u64;
    while at != 0 && at < file.len {
        path = match path.enter(at, 1_000_000) {
            Ok(p) => p,
            Err(d) => {
                cx.diag(d.at(file.sub(at, 6)));
                break;
            }
        };
        let head = cx.read(file.sub(at, 6)).await?;
        let len = u64::from(u32_be(&head, 2).unwrap_or(0));
        let rec = file.sub(at, len.saturating_add(6));
        let block = cx.block(rec).await?;
        let (next, time, level, pid) = asl_message(&mut Fields::new(&block, BE), &())?;
        let refs: Vec<u64> = (0..6usize)
            .map(|i| u64_be(&block.data, 66usize.saturating_add(i.saturating_mul(8))).unwrap_or(0))
            .collect();
        let sender = asl_string(&cx, file, refs.get(1).copied().unwrap_or(0)).await?;
        let message = asl_string(&cx, file, refs.get(3).copied().unwrap_or(0)).await?;
        cx.push(
            Node::new(format!("{sender}[{pid}]"))
                .span(rec)
                .value(unix_time(i64::try_from(time).unwrap_or(0)))
                .summary(format!(
                    "{}: {}",
                    lookup(ASL_LEVELS, level.into()).unwrap_or("?"),
                    clip(&message, 120)
                ))
                .lazy(asl_record, (file, rec)),
        )
        .await;
        count = count.saturating_add(1);
        at = next;
    }
    cx.annotate(format!("Apple System Log v{}, {count} messages", h.version));
    Ok(())
}

async fn asl_record(cx: Cx, (file, rec): (Span, Span)) -> Result<()> {
    let block = cx.block(rec).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    asl_message(&mut f, &())?;
    let kv = u32_be(&block.data, 62).unwrap_or(0);
    for i in 0..u64::from(kv.min(512)) {
        let at = 114u64.saturating_add(i.saturating_mul(8));
        let raw = u64_be(&block.data, to_usize(at)).unwrap_or(0);
        let s = asl_string(&cx, file, raw).await?;
        let label = if i % 2 == 0 { "Key" } else { "Value" };
        cx.push(Node::new(label).span(rec.sub(at, 8)).value(text(s)))
            .await;
    }
    let names = [
        "Host",
        "Sender",
        "Facility",
        "Message",
        "Reference process",
        "Session",
    ];
    for (i, name) in names.iter().enumerate() {
        let raw = u64_be(&block.data, 66usize.saturating_add(i.saturating_mul(8))).unwrap_or(0);
        if raw != 0 {
            let s = asl_string(&cx, file, raw).await?;
            cx.push(Node::new(format!("{name} (resolved)")).value(text(s)))
                .await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// iOS backup manifest (Manifest.mbdb, iOS 5 to 9)

declare_format!(pub MBDB = "mbdb", "iOS backup manifest (Manifest.mbdb)", ["mbdb"], "application/x-apple-mbdb",
    Probe::Magic(&[(0, b"mbdb\x05\x00")]), mbdb);

/// A length-prefixed string; 0xffff means absent.
async fn mbdb_string(cur: &mut Cursor<'_>) -> Result<(Option<Vec<u8>>, Span)> {
    let start = cur.pos();
    let len = cur.u16().await?;
    if len == 0xffff {
        return Ok((None, cur.since(start)));
    }
    let bytes = cur.bytes(len.into()).await?;
    Ok((Some(bytes), cur.since(start)))
}

fn file_mode(mode: u16) -> String {
    let kind = match mode & 0xf000 {
        0x4000 => 'd',
        0xa000 => 'l',
        0x8000 => '-',
        _ => '?',
    };
    let bits: String = (0..9)
        .map(|i| {
            let set = mode & (0o400 >> i) != 0;
            match (set, i % 3) {
                (false, _) => '-',
                (true, 0) => 'r',
                (true, 1) => 'w',
                (true, _) => 'x',
            }
        })
        .collect();
    format!("{kind}{bits}")
}

async fn mbdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 6))
            .value(text("mbdb 5.0")),
    );
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(6);
    let (mut files, mut dirs, mut bytes) = (0u64, 0u64, 0u64);
    while !cur.at_end() {
        let start = cur.pos();
        let (domain, _) = mbdb_string(&mut cur).await?;
        let (path, _) = mbdb_string(&mut cur).await?;
        for _ in 0..3 {
            mbdb_string(&mut cur).await?;
        }
        let mode = cur.u16().await?;
        cur.skip(8 + 4 + 4);
        let mtime = cur.u32().await?;
        cur.skip(8);
        let len = cur.u64().await?;
        cur.skip(1);
        let props = cur.u8().await?;
        for _ in 0..props {
            mbdb_string(&mut cur).await?;
            mbdb_string(&mut cur).await?;
        }
        match mode & 0xf000 {
            0x4000 => dirs = dirs.saturating_add(1),
            0x8000 => {
                files = files.saturating_add(1);
                bytes = bytes.saturating_add(len);
            }
            _ => {}
        }
        let domain = String::from_utf8_lossy(&domain.unwrap_or_default()).into_owned();
        let path = String::from_utf8_lossy(&path.unwrap_or_default()).into_owned();
        let name = if path.is_empty() {
            domain.clone()
        } else {
            format!("{domain}/{path}")
        };
        cx.push(
            Node::new(name)
                .span(cur.since(start))
                .value(unix_time(mtime.into()))
                .summary(format!("{} {}", file_mode(mode), size(len)))
                .lazy(mbdb_record, cur.since(start)),
        )
        .await;
    }
    cx.annotate(format!(
        "iOS backup manifest, {files} files ({}), {dirs} directories",
        size(bytes)
    ));
    Ok(())
}

const PROTECTION_CLASSES: EnumTable = &[
    (1, "Complete"),
    (2, "CompleteUnlessOpen"),
    (3, "CompleteUntilFirstUserAuthentication"),
    (4, "None"),
    (5, "RecoveryIfNotUnlocked"),
    (6, "AccessibleWhenUnlocked"),
    (7, "AfterFirstUnlock"),
    (8, "Always"),
    (9, "WhenUnlockedThisDeviceOnly"),
    (10, "AfterFirstUnlockThisDeviceOnly"),
    (11, "AlwaysThisDeviceOnly"),
];

async fn mbdb_record(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    for name in [
        "Domain",
        "Path",
        "Link target",
        "Data hash (SHA-1)",
        "Encryption key",
    ] {
        let (value, s) = mbdb_string(&mut cur).await?;
        let node = Node::new(name).span(s);
        cx.emit(match value {
            None => node.summary("absent"),
            Some(v) if name.starts_with("Data") || name.starts_with("Encryption") => {
                node.value(text(hex_string(&v)))
            }
            Some(v) => node.value(text(String::from_utf8_lossy(&v).into_owned())),
        });
    }
    let fixed_at = cur.pos();
    let block = cx.block(span.sub(fixed_at, 40)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("Mode").with(|&m, n| n.summary(file_mode(m))).emit()?;
    f.u64("Inode").emit()?;
    f.u32("UID").emit()?;
    f.u32("GID").emit()?;
    f.u32("Modified").timestamp().emit()?;
    f.u32("Accessed").timestamp().emit()?;
    f.u32("Changed").timestamp().emit()?;
    f.u64("Length").with(|&v, n| n.summary(size(v))).emit()?;
    f.u8("Protection class")
        .enumeration(PROTECTION_CLASSES)
        .emit()?;
    let props = f.u8("Property count").emit()?;
    cur.seek(fixed_at.saturating_add(40));
    for _ in 0..props {
        let start = cur.pos();
        let (k, _) = mbdb_string(&mut cur).await?;
        let (v, _) = mbdb_string(&mut cur).await?;
        let v = v.unwrap_or_default();
        let value = if crate::text::looks_like_text(&v) {
            text(String::from_utf8_lossy(&v).into_owned())
        } else {
            Value::Bytes(v)
        };
        cx.push(
            Node::new(String::from_utf8_lossy(&k.unwrap_or_default()).into_owned())
                .span(cur.since(start))
                .value(value),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux login records (utmp, wtmp, btmp)

const UTMP_RECORD: u64 = 384;

const UTMP_TYPES: EnumTable = &[
    (0, "EMPTY"),
    (1, "RUN_LVL"),
    (2, "BOOT_TIME"),
    (3, "NEW_TIME"),
    (4, "OLD_TIME"),
    (5, "INIT_PROCESS"),
    (6, "LOGIN_PROCESS"),
    (7, "USER_PROCESS"),
    (8, "DEAD_PROCESS"),
    (9, "ACCOUNTING"),
];

/// A NUL-padded field holding printable ASCII only.
fn clean_field(data: &[u8]) -> bool {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    data.get(..end)
        .is_some_and(|t| t.iter().all(|&b| (0x20..0x7f).contains(&b)))
}

fn utmp_plausible(r: &[u8]) -> bool {
    let kind = u16_le(r, 0).unwrap_or(u16::MAX);
    let sec = u32_le(r, 340).unwrap_or(u32::MAX);
    kind <= 9
        && r.get(2..4) == Some(&[0, 0])
        && u32_le(r, 4).is_some_and(|p| p < 0x40_0000)
        && sec < 0x8000_0000
        && [(8usize, 32usize), (40, 4), (44, 32), (76, 256)]
            .iter()
            .all(|&(at, len)| r.get(at..at.saturating_add(len)).is_some_and(clean_field))
}

fn utmp_probe(h: &Head<'_>) -> bool {
    if h.len < UTMP_RECORD || !h.len.is_multiple_of(UTMP_RECORD) {
        return false;
    }
    let records: Vec<&[u8]> = h.data.chunks_exact(to_usize(UTMP_RECORD)).take(8).collect();
    !records.is_empty()
        && records.iter().all(|r| utmp_plausible(r))
        && records.iter().any(|r| {
            u16_le(r, 0).is_some_and(|k| (1..=8).contains(&k))
                && u32_le(r, 340).is_some_and(|s| s > 0)
        })
}

declare_format!(pub UTMP = "utmp", "Linux login records (utmp/wtmp/btmp)", ["utmp", "wtmp", "btmp"], "application/x-utmp",
    Probe::Custom(utmp_probe), utmp);

fn utmp_address(r: &[u8]) -> String {
    let words: Vec<u32> = (0..4usize)
        .map(|i| u32_le(r, 348usize.saturating_add(i.saturating_mul(4))).unwrap_or(0))
        .collect();
    let bytes = r.get(348..364).unwrap_or_default();
    if words.iter().all(|&w| w == 0) {
        return String::new();
    }
    if words.iter().skip(1).all(|&w| w == 0) {
        return bytes
            .iter()
            .take(4)
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".");
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| format!("{:x}", u16::from_be_bytes(*c)))
        .collect::<Vec<_>>()
        .join(":")
}

fn utmp_layout(f: &mut Fields<'_>, _: &()) -> Result<(u16, String, String, String, u32)> {
    let kind = f.u16("Type").enumeration(UTMP_TYPES).emit()?;
    f.u16("Padding").emit()?;
    f.int::<i32>("PID").emit()?;
    let line = f.ascii("Terminal", 32).emit()?;
    f.ascii("Terminal ID", 4).emit()?;
    let user = f.ascii("User", 32).emit()?;
    let host = f.ascii("Host", 256).emit()?;
    f.int::<i16>("Termination status").emit()?;
    f.int::<i16>("Exit status").emit()?;
    f.int::<i32>("Session").emit()?;
    let sec = f.u32("Time").timestamp().emit()?;
    f.u32("Microseconds").emit()?;
    let addr = utmp_address(f.block().data.as_slice());
    f.bytes("Address", 16)
        .with(|_, n| {
            if addr.is_empty() {
                n
            } else {
                n.summary(addr.clone())
            }
        })
        .emit()?;
    f.bytes("Unused", 20).emit()?;
    Ok((kind, line, user, host, sec))
}

async fn utmp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = file.len / UTMP_RECORD;
    cx.set_count(Count::Exact(count));
    let mut users = std::collections::BTreeSet::new();
    let mut logins = 0u64;
    for i in 0..count {
        let span = file.sub(i.saturating_mul(UTMP_RECORD), UTMP_RECORD);
        let block = cx.block(span).await?;
        let (kind, line, user, host, sec) = utmp_layout(&mut Fields::new(&block, LE), &())?;
        if kind == 7 {
            logins = logins.saturating_add(1);
            users.insert(user.clone());
        }
        let kind_name = lookup(UTMP_TYPES, kind.into()).unwrap_or("?");
        let mut summary = kind_name.to_owned();
        if !line.is_empty() {
            summary.push_str(&format!(" on {line}"));
        }
        if !host.is_empty() {
            summary.push_str(&format!(" from {host}"));
        }
        let name = if user.is_empty() {
            format!("Record {i}")
        } else {
            user
        };
        cx.push(
            struct_node(name, span, LE, (), utmp_layout)
                .value(unix_time(sec.into()))
                .summary(summary),
        )
        .await;
    }
    cx.annotate(format!(
        "login records, {count} entries, {logins} user sessions ({})",
        users.into_iter().collect::<Vec<_>>().join(", ")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Android binary XML (ABX, Android 12+ system files)

declare_format!(pub ABX = "android-abx", "Android binary XML (ABX)", ["xml"], "application/x-android-abx",
    Probe::Magic(&[(0, b"ABX\0")]), abx);

#[derive(Clone, Debug)]
enum AbxChild {
    Element(usize),
    Text(String, u64, u64),
}

#[derive(Clone, Debug, Default)]
struct AbxElement {
    name: String,
    start: u64,
    end: u64,
    attrs: Vec<(String, Value, u64, u64)>,
    children: Vec<AbxChild>,
}

#[derive(Debug, Default)]
struct AbxDoc {
    elements: Vec<AbxElement>,
    roots: Vec<AbxChild>,
    error: Option<(String, u64)>,
}

struct AbxReader<'a> {
    data: &'a [u8],
    at: usize,
    strings: Vec<String>,
}

impl AbxReader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.data.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).and_then(|b| u16_be(b, 0))
    }

    fn utf(&mut self) -> Option<String> {
        let n = usize::from(self.u16()?);
        self.take(n)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }

    fn interned(&mut self) -> Option<String> {
        let index = self.u16()?;
        if index == 0xffff {
            let s = self.utf()?;
            if self.strings.len() < 0xfffe {
                self.strings.push(s.clone());
            }
            return Some(s);
        }
        self.strings.get(usize::from(index)).cloned()
    }

    fn value(&mut self, kind: u8) -> Option<Value> {
        Some(match kind {
            1 => text("null"),
            2 => text(self.utf()?),
            3 => text(self.interned()?),
            4 | 5 => {
                let n = usize::from(self.u16()?);
                Value::Bytes(self.take(n)?.to_vec())
            }
            6 => Value::Int {
                value: i64::from(crate::bytes::i32_be(self.take(4)?, 0)?),
                bits: 32,
            },
            7 => hex(u32_be(self.take(4)?, 0)?, 32),
            8 => Value::Int {
                value: i64::from_be_bytes(crate::bytes::array::<8>(self.take(8)?, 0)?),
                bits: 64,
            },
            9 => hex(u64_be(self.take(8)?, 0)?, 64),
            10 => Value::Float(f64::from(f32::from_be_bytes(crate::bytes::array::<4>(
                self.take(4)?,
                0,
            )?))),
            11 => Value::Float(f64::from_be_bytes(crate::bytes::array::<8>(
                self.take(8)?,
                0,
            )?)),
            12 => Value::Bool(true),
            13 => Value::Bool(false),
            _ => return None,
        })
    }
}

fn abx_parse(data: &[u8]) -> AbxDoc {
    let mut doc = AbxDoc::default();
    let mut r = AbxReader {
        data,
        at: 4,
        strings: Vec::new(),
    };
    let mut stack: Vec<usize> = Vec::new();
    while r.at < data.len() {
        let start = to_u64(r.at);
        let Some(token) = r.take(1).and_then(|b| b.first().copied()) else {
            break;
        };
        let (command, kind) = (token & 0xf, token >> 4);
        let ok = match command {
            0 | 1 => Some(()),
            2 => r.interned().map(|name| {
                let index = doc.elements.len();
                doc.elements.push(AbxElement {
                    name,
                    start,
                    ..AbxElement::default()
                });
                match stack.last().and_then(|&p| doc.elements.get_mut(p)) {
                    Some(parent) => parent.children.push(AbxChild::Element(index)),
                    None => doc.roots.push(AbxChild::Element(index)),
                }
                stack.push(index);
            }),
            3 => r.interned().map(|_| {
                if let Some(e) = stack.pop().and_then(|i| doc.elements.get_mut(i)) {
                    e.end = to_u64(r.at);
                }
            }),
            4..=10 => {
                let value = if kind == 1 {
                    Some(String::new())
                } else {
                    r.utf()
                };
                value.map(|s| {
                    let child = AbxChild::Text(s, start, to_u64(r.at));
                    match stack.last().and_then(|&p| doc.elements.get_mut(p)) {
                        Some(parent) => parent.children.push(child),
                        None => doc.roots.push(child),
                    }
                })
            }
            15 => r
                .interned()
                .and_then(|name| r.value(kind).map(|v| (name, v)))
                .map(|(name, v)| {
                    if let Some(e) = stack.last().and_then(|&p| doc.elements.get_mut(p)) {
                        e.attrs.push((name, v, start, to_u64(r.at)));
                    }
                }),
            _ => None,
        };
        if ok.is_none() {
            doc.error = Some((format!("bad or truncated token {token:#04x}"), start));
            break;
        }
        if doc.elements.len() > 1_000_000 {
            break;
        }
    }
    // Unclosed elements end where the data ends.
    for i in stack {
        if let Some(e) = doc.elements.get_mut(i) {
            e.end = to_u64(data.len());
        }
    }
    doc
}

async fn abx_doc(cx: &Cx, file: Span) -> Result<Arc<AbxDoc>> {
    if let Some(d) = cx.cached::<AbxDoc>(file, "abx") {
        return Ok(d);
    }
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let doc = Arc::new(abx_parse(&data));
    cx.cache(file, "abx", doc.clone());
    Ok(doc)
}

fn abx_value_text(v: &Value) -> String {
    match v {
        Value::Text(s) => s.clone(),
        Value::Int { value, .. } => value.to_string(),
        Value::UInt { value, .. } => format!("{value:#x}"),
        Value::Float(f) => f.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Bytes(b) => hex_string(b),
        _ => String::new(),
    }
}

fn abx_children(file: Span, doc: &AbxDoc, children: &[AbxChild]) -> Vec<Node> {
    children
        .iter()
        .map(|c| match c {
            AbxChild::Element(i) => {
                let e = doc.elements.get(*i).cloned().unwrap_or_default();
                let attrs: Vec<String> = e
                    .attrs
                    .iter()
                    .take(3)
                    .map(|(k, v, _, _)| format!("{k}={}", abx_value_text(v)))
                    .collect();
                let node = Node::new(format!("<{}>", e.name))
                    .span(file.sub(e.start, e.end.saturating_sub(e.start)))
                    .lazy(abx_element, (file, *i));
                if attrs.is_empty() {
                    node
                } else {
                    node.summary(clip(&attrs.join(" "), 100))
                }
            }
            AbxChild::Text(s, start, end) => Node::new("Text")
                .span(file.sub(*start, end.saturating_sub(*start)))
                .value(text(s.clone())),
        })
        .collect()
}

async fn abx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)).value(text("ABX")));
    let doc = abx_doc(&cx, file).await?;
    for node in abx_children(file, &doc, &doc.roots) {
        cx.push(node).await;
    }
    if let Some((msg, at)) = &doc.error {
        cx.diag(Diagnostic::malformed(msg.clone()).at(file.sub(*at, 1)));
    }
    let root = doc
        .elements
        .first()
        .map(|e| e.name.clone())
        .unwrap_or_default();
    cx.annotate(format!(
        "Android binary XML, root <{root}>, {} elements",
        doc.elements.len()
    ));
    Ok(())
}

async fn abx_element(cx: Cx, (file, index): (Span, usize)) -> Result<()> {
    let doc = abx_doc(&cx, file).await?;
    let Some(e) = doc.elements.get(index) else {
        return Ok(());
    };
    for (name, value, start, end) in &e.attrs {
        cx.push(
            Node::new(format!("@{name}"))
                .span(file.sub(*start, end.saturating_sub(*start)))
                .value(value.clone()),
        )
        .await;
    }
    for node in abx_children(file, &doc, &e.children) {
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS utmpx (/var/run/utmpx)

const UTMPX_RECORD: u64 = 640;

fn utmpx_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"utmpx-1.00\0")
        && h.len.is_multiple_of(UTMPX_RECORD)
        && u16_le(h.data, 296) == Some(10)
}

declare_format!(pub UTMPX = "macos-utmpx", "macOS login records (utmpx)", ["utmpx"], "application/x-utmpx",
    Probe::Custom(utmpx_probe), utmpx);

const UTMPX_TYPES: EnumTable = &[
    (0, "EMPTY"),
    (1, "RUN_LVL"),
    (2, "BOOT_TIME"),
    (3, "OLD_TIME"),
    (4, "NEW_TIME"),
    (5, "INIT_PROCESS"),
    (6, "LOGIN_PROCESS"),
    (7, "USER_PROCESS"),
    (8, "DEAD_PROCESS"),
    (9, "ACCOUNTING"),
    (10, "SIGNATURE"),
    (11, "SHUTDOWN_TIME"),
];

fn utmpx_layout(f: &mut Fields<'_>, _: &()) -> Result<(String, String, u16, i64)> {
    let user = f.ascii("User", 256).emit()?;
    f.ascii("ID", 4).emit()?;
    let line = f.ascii("Terminal", 32).emit()?;
    f.int::<i32>("PID").emit()?;
    let kind = f.u16("Type").enumeration(UTMPX_TYPES).emit()?;
    f.u16("Padding").emit()?;
    f.seek(304);
    let sec = f
        .int::<i64>("Time")
        .with(|&v, n| n.value(unix_time(v)))
        .emit()?;
    f.u32("Microseconds").emit()?;
    f.u32("Padding").emit()?;
    f.ascii("Host", 256).emit()?;
    Ok((user, line, kind, sec))
}

async fn utmpx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = file.len / UTMPX_RECORD;
    cx.set_count(Count::Exact(count));
    let mut sessions = 0u64;
    for i in 0..count {
        let span = file.sub(i.saturating_mul(UTMPX_RECORD), UTMPX_RECORD);
        let block = cx.block(span).await?;
        let (user, line, kind, sec) = utmpx_layout(&mut Fields::new(&block, LE), &())?;
        if kind == 7 {
            sessions = sessions.saturating_add(1);
        }
        let kind_name = lookup(UTMPX_TYPES, kind.into()).unwrap_or("?");
        let name = if user.is_empty() {
            format!("Record {i}")
        } else {
            user
        };
        let summary = if line.is_empty() {
            kind_name.to_owned()
        } else {
            format!("{kind_name} on {line}")
        };
        cx.push(
            struct_node(name, span, LE, (), utmpx_layout)
                .value(unix_time(sec))
                .summary(summary),
        )
        .await;
    }
    cx.annotate(format!(
        "macOS utmpx, {count} records, {sessions} user sessions"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS Unified Log format-string files (/var/db/uuidtext/XX/<UUID>)

fn uuidtext_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(0x6677_8899)
        && u32_le(h.data, 4) == Some(2)
        && u32_le(h.data, 12).is_some_and(|n| n < 0x10_0000)
}

declare_format!(pub UUIDTEXT = "macos-uuidtext", "macOS Unified Log format strings (uuidtext)", [], "application/x-apple-uuidtext",
    Probe::Custom(uuidtext_probe), uuidtext);

async fn uuidtext(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Signature").hex().emit()?;
    let major = f.u32("Major version").emit()?;
    let minor = f.u32("Minor version").emit()?;
    let count = f.u32("Number of ranges").emit()?;
    let table = file.sub_exact(16, u64::from(count).saturating_mul(8))?;
    let raw = cx.read(table).await?;
    // The ranges' strings are stored back to back after the table; the
    // image path ends the file.
    let mut at = table.end().saturating_sub(file.offset);
    let mut ranges = Vec::new();
    for (i, e) in raw.as_chunks::<8>().0.iter().enumerate() {
        let start = u32_le(e, 0).unwrap_or(0);
        let len = u64::from(u32_le(e, 4).unwrap_or(0));
        ranges.push((
            i,
            start,
            file.sub(at, len),
            table.sub(to_u64(i).saturating_mul(8), 8),
        ));
        at = at.saturating_add(len);
    }
    let (path, path_span) = cx.cstr(file.tail(at).sub(0, 4096)).await?;
    cx.emit(
        Node::new("Ranges")
            .span(table)
            .summary(format!("{count} ranges"))
            .lazy(uuidtext_ranges, ranges),
    );
    cx.emit(
        Node::new("Image path")
            .span(path_span)
            .value(text(path.clone())),
    );
    cx.annotate(format!(
        "Unified Log format strings v{major}.{minor} for {path}, {count} ranges"
    ));
    Ok(())
}

/// A range: index, first string offset, data and table entry.
type UuidRange = (usize, u32, Span, Span);

async fn uuidtext_ranges(cx: Cx, ranges: Vec<UuidRange>) -> Result<()> {
    for (i, start, data, entry) in ranges {
        let raw = cx.read_avail(data.sub(0, 0x10000)).await?;
        let strings: Vec<String> = raw
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        cx.push(
            Node::new(format!("Range {i} at {start:#x}"))
                .span(data)
                .target(entry)
                .summary(format!("{} strings", strings.len()))
                .lazy(uuidtext_strings, (data, start)),
        )
        .await;
    }
    Ok(())
}

async fn uuidtext_strings(cx: Cx, (data, base): (Span, u32)) -> Result<()> {
    let raw = cx.read_avail(data.sub(0, 0x10_0000)).await?;
    let mut at = 0usize;
    for s in raw.split(|&b| b == 0) {
        let len = s.len();
        if len > 0 {
            let offset = u64::from(base).saturating_add(to_u64(at));
            cx.push(
                Node::new(format!("{offset:#x}"))
                    .span(data.sub(to_u64(at), to_u64(len)))
                    .value(text(String::from_utf8_lossy(s).into_owned())),
            )
            .await;
        }
        at = at.saturating_add(len).saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// iOS backup manifest index (Manifest.mbdx, iOS 4)

declare_format!(pub MBDX = "mbdx", "iOS backup manifest index (Manifest.mbdx)", ["mbdx"], "application/x-apple-mbdx",
    Probe::Magic(&[(0, b"mbdx\x02\x00")]), mbdx);

async fn mbdx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 10)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    f.u16("Version").hex().emit()?;
    let count = f.u32("Number of records").emit()?;
    let list = file.sub_exact(10, u64::from(count).saturating_mul(26))?;
    cx.set_count(Count::Exact(u64::from(count).saturating_add(3)));
    for i in 0..u64::from(count) {
        let span = list.sub(i.saturating_mul(26), 26);
        let r = cx.read(span).await?;
        let id = hex_string(r.get(..20).unwrap_or_default());
        let offset = u32_be(&r, 20).unwrap_or(0);
        let mode = u16_be(&r, 24).unwrap_or(0);
        cx.push(
            Node::new(id)
                .span(span)
                .value(hex(offset, 32))
                .summary(format!(
                    "{} (record at {:#x} in Manifest.mbdb)",
                    file_mode(mode),
                    u64::from(offset).saturating_add(6)
                )),
        )
        .await;
    }
    cx.annotate(format!("iOS backup manifest index, {count} files"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux lastlog (/var/log/lastlog: one 292-byte record per UID)

const LASTLOG_RECORD: u64 = 292;

fn lastlog_record_ok(r: &[u8]) -> bool {
    let t = u32_le(r, 0).unwrap_or(0);
    let zero = r.iter().all(|&b| b == 0);
    zero || ((100_000_000..0x8000_0000).contains(&t)
        && clean_field(r.get(4..36).unwrap_or_default())
        && clean_field(r.get(36..292).unwrap_or_default()))
}

fn lastlog_probe(h: &Head<'_>) -> bool {
    if h.len < LASTLOG_RECORD || !h.len.is_multiple_of(LASTLOG_RECORD) {
        return false;
    }
    let records: Vec<&[u8]> = h.data.chunks_exact(to_usize(LASTLOG_RECORD)).collect();
    records.iter().all(|r| lastlog_record_ok(r))
        && records.iter().any(|r| r.iter().any(|&b| b != 0))
}

declare_format!(pub LASTLOG = "lastlog", "Linux last login records (lastlog)", ["lastlog"], "application/x-lastlog",
    Probe::Custom(lastlog_probe), lastlog);

fn lastlog_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Time").timestamp().emit()?;
    f.ascii("Terminal", 32).emit()?;
    f.ascii("Host", 256).emit()?;
    Ok(())
}

async fn lastlog(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = file.len / LASTLOG_RECORD;
    let mut logins = 0u64;
    for uid in 0..count {
        let span = file.sub(uid.saturating_mul(LASTLOG_RECORD), LASTLOG_RECORD);
        let r = cx.read_avail(span).await?;
        if r.iter().all(|&b| b == 0) {
            if uid.is_multiple_of(64) {
                cx.checkpoint().await;
            }
            continue;
        }
        logins = logins.saturating_add(1);
        let t = u32_le(&r, 0).unwrap_or(0);
        let line = crate::text::until_nul(r.get(4..36).unwrap_or_default());
        let host = crate::text::until_nul(r.get(36..292).unwrap_or_default());
        let summary = if host.is_empty() {
            line
        } else {
            format!("{line} from {host}")
        };
        cx.push(
            struct_node(format!("UID {uid}"), span, LE, (), lastlog_layout)
                .value(unix_time(t.into()))
                .summary(summary),
        )
        .await;
    }
    cx.annotate(format!(
        "lastlog, {logins} users with logins (UIDs 0–{})",
        count.saturating_sub(1)
    ));
    Ok(())
}
