//! Web browser artifacts: Internet Explorer's URL cache (`index.dat`),
//! Safari cookies, Chromium's disk caches, visited-link table and session
//! files, and Mozilla's Mork databases.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::datakit::{cf_time, clip, size, text};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

/// Chromium's internal time: microseconds since 1601-01-01.
fn chrome_time(us: u64) -> Value {
    Value::Timestamp {
        unix_seconds: crate::text::filetime_to_unix(us.saturating_mul(10)),
    }
}

/// A FAT date/time pair stored as one little-endian u32 (date in the high
/// half), as Internet Explorer does.
fn fat_time(v: u32) -> Value {
    if v == 0 {
        return text("not set");
    }
    let date = u16::try_from(v >> 16).unwrap_or(0);
    let time = u16::try_from(v & 0xffff).unwrap_or(0);
    text(crate::text::dos_datetime(date, time))
}

// ---------------------------------------------------------------------------
// Internet Explorer URL cache (index.dat)

declare_format!(pub IE_INDEX = "ie-index-dat", "Internet Explorer cache index (index.dat)", ["dat"], "application/x-msie-cache",
    Probe::Magic(&[(0, b"Client UrlCache MMF Ver 5.2\0")]), ie_index);

record! {
    pub struct IeHeader {
        signature: ascii[28] "Signature",
        file_size: u32 "File size",
        hash_table: u32 "First hash table offset" .hex(),
        blocks: u32 "Number of blocks",
        allocated: u32 "Number of allocated blocks",
        _unknown1: u32 "Unknown",
        size_limit: u64 "Cache size limit" .with(|&v, n| n.summary(size(v))),
        cache_size: u64 "Cache size" .with(|&v, n| n.summary(size(v))),
        _unknown2: u64 "Non-releasable cache size",
        directories: u32 "Number of cache directories",
    }
}

const IE_BLOCK: u64 = 0x80;
const IE_DATA_START: u64 = 0x4000;

const IE_CACHE_FLAGS: FlagTable = &[
    flag(0x0001, "NORMAL_CACHE_ENTRY"),
    flag(0x0002, "STICKY_CACHE_ENTRY"),
    flag(0x0004, "EDITED_CACHE_ENTRY"),
    flag(0x0008, "TRACK_OFFLINE_CACHE_ENTRY"),
    flag(0x0010, "TRACK_ONLINE_CACHE_ENTRY"),
    flag(0x0040, "SPARSE_CACHE_ENTRY"),
    flag(0x0100, "COOKIE_CACHE_ENTRY"),
    flag(0x0200, "URLHISTORY_CACHE_ENTRY"),
    flag(0x0800, "INSTALLED_CACHE_ENTRY"),
];

async fn ie_index(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, IeHeader::SIZE);
    let h: IeHeader = read_record(&cx, span, LE).await?;
    cx.emit(IeHeader::node("File header", span, LE));
    let dirs = u64::from(h.directories.min(32));
    cx.emit(
        Node::new("Cache directories")
            .span(file.sub(IeHeader::SIZE, dirs.saturating_mul(12)))
            .summary(format!("{dirs} directories"))
            .lazy(ie_directories, (file, dirs)),
    );
    cx.emit(
        Node::new("Allocation bitmap").span(file.sub(0x250, IE_DATA_START.saturating_sub(0x250))),
    );
    cx.emit(Node::new("Hash tables").lazy(ie_hash_tables, (file, h.hash_table)));
    cx.emit(
        Node::new("Records")
            .desc("Records referenced from the hash tables, in table order")
            .lazy(ie_records, (file, h.hash_table)),
    );
    let records = ie_record_offsets(&cx, file, h.hash_table).await?.len();
    cx.annotate(format!(
        "Internet Explorer 5.2 URL cache, {records} records, {} of {} blocks allocated",
        h.allocated, h.blocks
    ));
    Ok(())
}

async fn ie_directories(cx: Cx, (file, count): (Span, u64)) -> Result<()> {
    for i in 0..count {
        let span = file.sub(IeHeader::SIZE.saturating_add(i.saturating_mul(12)), 12);
        let d = cx.read(span).await?;
        let files = u32_le(&d, 0).unwrap_or(0);
        let name = crate::text::latin1(d.get(4..12).unwrap_or_default());
        cx.push(
            Node::new(format!("Directory {i}"))
                .span(span)
                .value(text(name))
                .summary(format!("{files} cached files")),
        )
        .await;
    }
    Ok(())
}

/// Offsets of the hash tables, following their `next` links.
async fn ie_tables(cx: &Cx, file: Span, first: u32) -> Result<Vec<(u64, u64)>> {
    let mut out = Vec::new();
    let mut at = u64::from(first);
    while at != 0 && at < file.len && out.len() < 1024 {
        if out.iter().any(|&(o, _)| o == at) {
            cx.diag(Diagnostic::malformed("hash table chain loops").at(file.sub(at, 16)));
            break;
        }
        let head = cx.read(file.sub(at, 16)).await?;
        if head.get(..4) != Some(b"HASH") {
            cx.diag(Diagnostic::malformed("hash table signature is not HASH").at(file.sub(at, 4)));
            break;
        }
        let blocks = u64::from(u32_le(&head, 4).unwrap_or(0)).max(1);
        out.push((at, blocks.saturating_mul(IE_BLOCK)));
        at = u64::from(u32_le(&head, 8).unwrap_or(0));
    }
    Ok(out)
}

fn ie_free(hash: u32, offset: u32) -> bool {
    hash == 0x3 || hash == 0x1 || offset == 0x3 || offset == 0xdead_beef || offset == 0
}

async fn ie_record_offsets(cx: &Cx, file: Span, first: u32) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for (at, len) in ie_tables(cx, file, first).await? {
        let table = cx
            .read_avail(file.sub(at.saturating_add(16), len.saturating_sub(16)))
            .await?;
        for e in table.as_chunks::<8>().0.iter() {
            let (hash, offset) = (u32_le(e, 0).unwrap_or(0), u32_le(e, 4).unwrap_or(0));
            if !ie_free(hash, offset) && u64::from(offset) < file.len {
                out.push(u64::from(offset));
            }
        }
    }
    Ok(out)
}

async fn ie_hash_tables(cx: Cx, (file, first): (Span, u32)) -> Result<()> {
    for (i, (at, len)) in ie_tables(&cx, file, first).await?.into_iter().enumerate() {
        let span = file.sub(at, len);
        cx.push(
            Node::new(format!("Hash table {i}"))
                .span(span)
                .lazy(ie_hash_table, span),
        )
        .await;
    }
    Ok(())
}

async fn ie_hash_table(cx: Cx, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    f.u32("Number of blocks").emit()?;
    f.u32("Next hash table offset").hex().emit()?;
    f.u32("Sequence number").emit()?;
    let data = cx.read_avail(span.tail(16)).await?;
    for (i, e) in data.as_chunks::<8>().0.iter().enumerate() {
        let (hash, offset) = (u32_le(e, 0).unwrap_or(0), u32_le(e, 4).unwrap_or(0));
        if ie_free(hash, offset) {
            continue;
        }
        let at = to_u64(i).saturating_mul(8).saturating_add(16);
        cx.push(
            Node::new(format!("Entry {i}"))
                .span(span.sub(at, 8))
                .value(crate::formats::util::datakit::hex(offset, 32))
                .summary(format!("hash {hash:#010x}")),
        )
        .await;
    }
    Ok(())
}

fn ie_url_layout(f: &mut Fields<'_>, _: &()) -> Result<String> {
    f.ascii("Signature", 4).emit()?;
    f.u32("Number of blocks").emit()?;
    f.u64("Last modification time").filetime().emit()?;
    f.u64("Last access time").filetime().emit()?;
    f.u32("Expiration time")
        .with(|&v, n| n.value(fat_time(v)))
        .emit()?;
    f.u32("Unknown").emit()?;
    f.u32("Cached file size")
        .with(|&v, n| n.summary(size(v.into())))
        .emit()?;
    f.bytes("Unknown", 16).emit()?;
    let location = f.u32("Location offset").hex().emit()?;
    f.u8("Cache directory index").emit()?;
    f.bytes("Unknown", 3).emit()?;
    let filename = f.u32("Filename offset").hex().emit()?;
    f.u32("Cache entry flags").flags(IE_CACHE_FLAGS).emit()?;
    let data = f.u32("Data offset").hex().emit()?;
    let data_size = f.u32("Data size").emit()?;
    f.u32("Unknown").emit()?;
    f.u32("Last checked time")
        .with(|&v, n| n.value(fat_time(v)))
        .emit()?;
    f.u32("Number of hits").emit()?;
    f.u32("Unknown").emit()?;
    f.u32("Synchronization time")
        .with(|&v, n| n.value(fat_time(v)))
        .emit()?;
    let mut url = String::new();
    if location != 0 {
        f.seek(location.into());
        url = f.cstr("Location").emit()?;
    }
    if filename != 0 {
        f.seek(filename.into());
        f.cstr("Cached file name").emit()?;
    }
    if data != 0 && data_size != 0 {
        f.seek(data.into());
        f.ascii("Data (HTTP headers)", data_size.into()).emit()?;
    }
    Ok(url)
}

fn ie_redr_layout(f: &mut Fields<'_>, _: &()) -> Result<String> {
    f.ascii("Signature", 4).emit()?;
    f.u32("Number of blocks").emit()?;
    f.u32("Unknown").emit()?;
    f.u32("Hash").hex().emit()?;
    f.cstr("Location").emit()
}

async fn ie_records(cx: Cx, (file, first): (Span, u32)) -> Result<()> {
    let offsets = ie_record_offsets(&cx, file, first).await?;
    cx.set_count(Count::Exact(to_u64(offsets.len())));
    for at in offsets {
        let head = cx.read(file.sub(at, 8)).await?;
        let sig = crate::text::latin1(head.get(..4).unwrap_or_default());
        let blocks = u64::from(u32_le(&head, 4).unwrap_or(1)).clamp(1, 512);
        let span = file.sub(at, blocks.saturating_mul(IE_BLOCK));
        let kind = sig.trim_end().to_owned();
        let node = match kind.as_str() {
            "URL" | "LEAK" => {
                let block = cx.block(span).await?;
                let url = ie_url_layout(&mut Fields::new(&block, LE), &()).unwrap_or_default();
                let accessed = u64_le(&block.data, 0x10).unwrap_or(0);
                struct_node(kind, span, LE, (), ie_url_layout)
                    .value(Value::Timestamp {
                        unix_seconds: crate::text::filetime_to_unix(accessed),
                    })
                    .summary(url)
            }
            "REDR" => {
                let block = cx.block(span).await?;
                let url = ie_redr_layout(&mut Fields::new(&block, LE), &()).unwrap_or_default();
                struct_node(kind, span, LE, (), ie_redr_layout).summary(url)
            }
            _ => Node::new(format!("Record {kind:?}")).span(span),
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Safari / WebKit Cookies.binarycookies

declare_format!(pub BINARYCOOKIES = "binarycookies", "Safari binary cookies", ["binarycookies"], "application/x-apple-binarycookies",
    Probe::Custom(binarycookies_probe), binarycookies);

fn binarycookies_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"cook")
        && u32_be(h.data, 4).is_some_and(|n| n > 0 && n < 0x10000)
        && u32_be(h.data, 8).is_some_and(|n| (12..0x100_0000).contains(&n))
}

const COOKIE_FLAGS: FlagTable = &[flag(0x1, "Secure"), flag(0x4, "HttpOnly")];

async fn binarycookies(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    cx.emit(Node::new("Magic").span(cur.span(4)).value(text("cook")));
    cur.skip(4);
    let pages_span = cur.span(4);
    let pages = cur.u32().await?;
    cx.emit(
        Node::new("Number of pages")
            .span(pages_span)
            .value(crate::formats::util::datakit::uint(pages, 32)),
    );
    let sizes_span = file.sub_exact(8, u64::from(pages).saturating_mul(4))?;
    let sizes = cx.read(sizes_span).await?;
    cx.emit(Node::new("Page sizes").span(sizes_span));
    let mut at = sizes_span.end().saturating_sub(file.offset);
    let mut total = 0u64;
    for (i, s) in sizes.as_chunks::<4>().0.iter().enumerate() {
        let len = u64::from(u32_be(s, 0).unwrap_or(0));
        let span = file.sub(at, len);
        let head = cx.read_avail(span.sub(0, 8)).await?;
        let count = u32_le(&head, 4).unwrap_or(0);
        total = total.saturating_add(count.into());
        cx.push(
            Node::new(format!("Page {i}"))
                .span(span)
                .summary(format!("{count} cookies"))
                .lazy(cookie_page, span),
        )
        .await;
        at = at.saturating_add(len);
    }
    if file.len >= at.saturating_add(4) {
        cx.emit(
            Node::new("Checksum")
                .span(file.sub(at, 4))
                .desc("Sum of every fourth byte of each page"),
        );
        let footer = file.sub(at.saturating_add(4), 8);
        cx.emit(Node::new("Footer").span(footer));
        let rest = file.tail(at.saturating_add(12));
        if !rest.is_empty() {
            cx.emit(embedded("Metadata", input.nested(rest)));
        }
    }
    cx.annotate(format!("Safari cookies, {pages} pages, {total} cookies"));
    Ok(())
}

async fn cookie_page(cx: Cx, page: Span) -> Result<()> {
    let head = cx.read(page.sub(0, 8)).await?;
    let count = u64::from(u32_le(&head, 4).unwrap_or(0));
    let offsets_span = page.sub_exact(8, count.saturating_mul(4))?;
    let block = cx
        .block(
            page.sub(
                0,
                offsets_span
                    .end()
                    .saturating_sub(page.offset)
                    .saturating_add(4),
            ),
        )
        .await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.bytes("Page header", 4).emit()?;
    f.u32("Number of cookies").emit()?;
    cx.set_count(Count::Exact(count.saturating_add(3)));
    let offsets = cx.read(offsets_span).await?;
    cx.emit(Node::new("Cookie offsets").span(offsets_span));
    f.seek(offsets_span.end().saturating_sub(page.offset));
    f.u32("Page footer").hex().emit()?;
    for o in offsets.as_chunks::<4>().0.iter() {
        let at = u64::from(u32_le(o, 0).unwrap_or(0));
        let len_bytes = cx.read_avail(page.sub(at, 4)).await?;
        let len = u64::from(u32_le(&len_bytes, 0).unwrap_or(0)).max(4);
        let span = page.sub(at, len);
        let block = cx.block(span).await?;
        let (name, value, domain, path) =
            cookie_layout(&mut Fields::new(&block, LE), &()).unwrap_or_default();
        let expiry = block
            .data
            .get(40..48)
            .and_then(|b| crate::bytes::array::<8>(b, 0))
            .map(f64::from_le_bytes)
            .unwrap_or(0.0);
        cx.push(
            struct_node(format!("Cookie {name}"), span, LE, (), cookie_layout)
                .value(cf_time(expiry))
                .summary(clip(&format!("{domain}{path}: {name}={value}"), 120)),
        )
        .await;
    }
    Ok(())
}

fn cookie_layout(f: &mut Fields<'_>, _: &()) -> Result<(String, String, String, String)> {
    f.u32("Size").emit()?;
    f.u32("Version").emit()?;
    f.u32("Flags").flags(COOKIE_FLAGS).emit()?;
    let has_port = f.u32("Has port").emit()?;
    let offsets = [
        f.u32("Domain offset").hex().emit()?,
        f.u32("Name offset").hex().emit()?,
        f.u32("Path offset").hex().emit()?,
        f.u32("Value offset").hex().emit()?,
        f.u32("Comment offset").hex().emit()?,
    ];
    f.u32("Comment URL offset").hex().emit()?;
    f.f64("Expiry time")
        .with(|&v, n| n.value(cf_time(v)))
        .emit()?;
    f.f64("Creation time")
        .with(|&v, n| n.value(cf_time(v)))
        .emit()?;
    if has_port != 0 {
        f.u16("Port").emit()?;
    }
    let labels = ["Domain", "Name", "Path", "Value", "Comment"];
    let mut values: Vec<String> = Vec::new();
    for (label, &off) in labels.iter().zip(offsets.iter()) {
        if off == 0 {
            values.push(String::new());
            continue;
        }
        f.seek(off.into());
        values.push(f.cstr(label).emit()?);
    }
    let mut it = values.into_iter();
    let domain = it.next().unwrap_or_default();
    let name = it.next().unwrap_or_default();
    let path = it.next().unwrap_or_default();
    let value = it.next().unwrap_or_default();
    Ok((name, value, domain, path))
}

// ---------------------------------------------------------------------------
// Chromium disk cache (blockfile backend): index and data_N files

declare_format!(pub CHROME_CACHE_INDEX = "chrome-cache-index", "Chromium disk cache index", [], "application/x-chrome-cache",
    Probe::Magic(&[(0, b"\xc3\xca\x03\xc1")]), chrome_index);
declare_format!(pub CHROME_CACHE_BLOCK = "chrome-cache-block", "Chromium disk cache block file (data_N)", [], "application/x-chrome-cache",
    Probe::Magic(&[(0, b"\xc3\xca\x04\xc1")]), chrome_block_file);

const CACHE_FILE_TYPES: EnumTable = &[
    (0, "external"),
    (1, "rankings"),
    (2, "block-256"),
    (3, "block-1k"),
    (4, "block-4k"),
    (5, "block-files"),
    (6, "block-entries"),
    (7, "block-evicted"),
];

/// A CacheAddr as text: where the addressed data lives.
fn cache_addr(addr: u32) -> String {
    if addr & 0x8000_0000 == 0 {
        return "not initialized".to_owned();
    }
    let kind = (addr >> 28) & 7;
    if kind == 0 {
        return format!("f_{:06x}", addr & 0x0fff_ffff);
    }
    let blocks = ((addr >> 24) & 3).saturating_add(1);
    let file = (addr >> 16) & 0xff;
    let block = addr & 0xffff;
    let name = lookup(CACHE_FILE_TYPES, kind.into()).unwrap_or("?");
    format!("data_{file} block {block} ({blocks} × {name})")
}

fn addr_value(addr: u32) -> Value {
    crate::formats::util::datakit::hex(addr, 32)
}

record! {
    pub struct ChromeIndexHeader {
        magic: u32 "Magic" .hex(),
        version: u32 "Version" .hex(),
        entries: i32 "Number of entries",
        old_bytes: i32 "Stored bytes (v2)",
        last_file: i32 "Last external file",
        this_id: i32 "Dirty flag (this_id)",
        stats: u32 "Statistics address" .hex().with(|&v, n| n.summary(cache_addr(v))),
        table_len: i32 "Index table length",
        crash: i32 "Crash flag",
        experiment: i32 "Experiment",
        created: u64 "Creation time" .with(|&v, n| n.value(chrome_time(v))),
        bytes: i64 "Stored bytes",
        corruption: i32 "Corruption cause",
    }
}

record! {
    pub struct ChromeLru {
        _pad1: bytes[8] "Padding",
        filled: i32 "Filled",
        size0: i32 "Size (no use)",
        size1: i32 "Size (low use)",
        size2: i32 "Size (high use)",
        size3: i32 "Size (reserved)",
        size4: i32 "Size (deleted)",
        head0: u32 "Head (no use)" .hex().with(|&v, n| n.summary(cache_addr(v))),
        head1: u32 "Head (low use)" .hex().with(|&v, n| n.summary(cache_addr(v))),
        head2: u32 "Head (high use)" .hex().with(|&v, n| n.summary(cache_addr(v))),
        head3: u32 "Head (reserved)" .hex().with(|&v, n| n.summary(cache_addr(v))),
        head4: u32 "Head (deleted)" .hex().with(|&v, n| n.summary(cache_addr(v))),
        tail0: u32 "Tail (no use)" .hex().with(|&v, n| n.summary(cache_addr(v))),
        tail1: u32 "Tail (low use)" .hex().with(|&v, n| n.summary(cache_addr(v))),
        tail2: u32 "Tail (high use)" .hex().with(|&v, n| n.summary(cache_addr(v))),
        tail3: u32 "Tail (reserved)" .hex().with(|&v, n| n.summary(cache_addr(v))),
        tail4: u32 "Tail (deleted)" .hex().with(|&v, n| n.summary(cache_addr(v))),
        transaction: u32 "Transaction" .hex().with(|&v, n| n.summary(cache_addr(v))),
        operation: i32 "Operation",
        operation_list: i32 "Operation list",
        _pad2: bytes[28] "Padding",
    }
}

const CHROME_INDEX_TABLE: u64 = 368;

async fn chrome_index(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, ChromeIndexHeader::SIZE);
    let h: ChromeIndexHeader = read_record(&cx, span, LE).await?;
    cx.emit(ChromeIndexHeader::node("Header", file.sub(0, 256), LE));
    cx.emit(ChromeLru::node(
        "LRU data",
        file.sub(256, ChromeLru::SIZE),
        LE,
    ));
    let table = file.tail(CHROME_INDEX_TABLE);
    cx.emit(
        Node::new("Index table")
            .span(table)
            .summary(format!("{} buckets", table.len / 4))
            .lazy(chrome_index_table, table),
    );
    cx.annotate(format!(
        "Chromium disk cache index v{}.{}, {} entries, {}",
        h.version >> 16,
        h.version & 0xffff,
        h.entries,
        size(u64::try_from(h.bytes).unwrap_or(0))
    ));
    Ok(())
}

async fn chrome_index_table(cx: Cx, table: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, table, LE);
    let mut bucket = 0u64;
    while cur.remaining() >= 4 {
        let span = cur.span(4);
        let addr = cur.u32().await?;
        if addr != 0 {
            cx.push(
                Node::new(format!("Bucket {bucket}"))
                    .span(span)
                    .value(addr_value(addr))
                    .summary(cache_addr(addr)),
            )
            .await;
        } else if bucket.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        bucket = bucket.saturating_add(1);
    }
    Ok(())
}

record! {
    pub struct ChromeBlockHeader {
        magic: u32 "Magic" .hex(),
        version: u32 "Version" .hex(),
        this_file: i16 "This file",
        next_file: i16 "Next file",
        entry_size: i32 "Block size",
        entries: i32 "Number of entries",
        max_entries: i32 "Maximum entries",
        empty1: i32 "Empty runs of 1 block",
        empty2: i32 "Empty runs of 2 blocks",
        empty3: i32 "Empty runs of 3 blocks",
        empty4: i32 "Empty runs of 4 blocks",
        _hints: bytes[16] "Allocation hints",
        updating: i32 "Updating",
        _user: bytes[20] "User data",
    }
}

const CHROME_BLOCK_HEADER: u64 = 0x2000;

async fn chrome_block_file(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, ChromeBlockHeader::SIZE);
    let h: ChromeBlockHeader = read_record(&cx, span, LE).await?;
    cx.emit(ChromeBlockHeader::node("Header", span, LE));
    let map = file.sub(
        ChromeBlockHeader::SIZE,
        CHROME_BLOCK_HEADER.saturating_sub(ChromeBlockHeader::SIZE),
    );
    cx.emit(Node::new("Allocation bitmap").span(map));
    let block = u64::try_from(h.entry_size).unwrap_or(0);
    let kind = match block {
        36 => "rankings",
        256 => "entries",
        1024 => "1 KiB data blocks",
        4096 => "4 KiB data blocks",
        _ => "blocks",
    };
    if block > 0 {
        cx.emit(
            Node::new("Blocks")
                .span(file.tail(CHROME_BLOCK_HEADER))
                .summary(format!("{} allocated", h.entries))
                .lazy(chrome_blocks, (input, map, block)),
        );
    }
    cx.annotate(format!(
        "Chromium cache block file data_{}, {kind}, {} of {} blocks used",
        h.this_file, h.entries, h.max_entries
    ));
    Ok(())
}

async fn chrome_blocks(cx: Cx, (input, map, block): (Input, Span, u64)) -> Result<()> {
    let file = input.span;
    let bitmap = cx.read_avail(map).await?;
    let max_blocks = file
        .len
        .saturating_sub(CHROME_BLOCK_HEADER)
        .checked_div(block)
        .unwrap_or(0);
    let mut skip_until = 0u64;
    for index in 0..max_blocks.min(to_u64(bitmap.len()).saturating_mul(8)) {
        if index < skip_until {
            continue;
        }
        let byte = bitmap.get(to_usize(index / 8)).copied().unwrap_or(0);
        if byte & (1u8 << (index % 8)) == 0 {
            if index.is_multiple_of(64) {
                cx.checkpoint().await;
            }
            continue;
        }
        let at = CHROME_BLOCK_HEADER.saturating_add(index.saturating_mul(block));
        let span = file.sub(at, block);
        let node = match block {
            256 => {
                let data = cx.read(span).await?;
                let key_len = u64::from(u32_le(&data, 32).unwrap_or(0));
                // Keys longer than the inline space spill into following blocks.
                let blocks = (96u64.saturating_add(key_len).saturating_add(1))
                    .div_ceil(256)
                    .clamp(1, 4);
                skip_until = index.saturating_add(blocks);
                let span = file.sub(at, blocks.saturating_mul(256));
                let block = cx.block(span).await?;
                let key =
                    chrome_entry_layout(&mut Fields::new(&block, LE), &()).unwrap_or_default();
                let created = u64_le(&data, 24).unwrap_or(0);
                struct_node(format!("Entry {index}"), span, LE, (), chrome_entry_layout)
                    .value(chrome_time(created))
                    .summary(clip(&key, 160))
            }
            36 => {
                let data = cx.read(span).await?;
                struct_node(
                    format!("Rankings node {index}"),
                    span,
                    LE,
                    (),
                    chrome_rankings_layout,
                )
                .value(chrome_time(u64_le(&data, 0).unwrap_or(0)))
            }
            _ => embedded(format!("Block {index}"), input.nested(span)),
        };
        cx.push(node).await;
    }
    Ok(())
}

const ENTRY_STATES: EnumTable = &[(0, "normal"), (1, "evicted"), (2, "doomed")];
const ENTRY_FLAGS: FlagTable = &[flag(1, "PARENT_ENTRY"), flag(2, "CHILD_ENTRY")];

fn chrome_entry_layout(f: &mut Fields<'_>, _: &()) -> Result<String> {
    f.u32("Hash").hex().emit()?;
    f.u32("Next entry")
        .hex()
        .with(|&v, n| n.summary(cache_addr(v)))
        .emit()?;
    f.u32("Rankings node")
        .hex()
        .with(|&v, n| n.summary(cache_addr(v)))
        .emit()?;
    f.i32("Reuse count").emit()?;
    f.i32("Refetch count").emit()?;
    f.i32("State")
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
        .enumeration(ENTRY_STATES)
        .emit()?;
    f.u64("Creation time")
        .with(|&v, n| n.value(chrome_time(v)))
        .emit()?;
    let key_len = f.i32("Key length").emit()?;
    let long_key = f
        .u32("Long key address")
        .hex()
        .with(|&v, n| n.summary(cache_addr(v)))
        .emit()?;
    for name in [
        "Stream 0 size (headers)",
        "Stream 1 size (body)",
        "Stream 2 size",
        "Stream 3 size",
    ] {
        f.i32(name).emit()?;
    }
    for name in [
        "Stream 0 address",
        "Stream 1 address",
        "Stream 2 address",
        "Stream 3 address",
    ] {
        f.u32(name)
            .hex()
            .with(|&v, n| n.summary(cache_addr(v)))
            .emit()?;
    }
    f.u32("Flags").flags(ENTRY_FLAGS).emit()?;
    f.bytes("Padding", 16).emit()?;
    f.u32("Self hash").hex().emit()?;
    if long_key != 0 {
        return Ok(format!("(long key at {})", cache_addr(long_key)));
    }
    let len = u64::try_from(key_len).unwrap_or(0).min(f.remaining());
    f.ascii("Key", len).emit()
}

fn chrome_rankings_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Last used")
        .with(|&v, n| n.value(chrome_time(v)))
        .emit()?;
    f.u64("Last modified")
        .with(|&v, n| n.value(chrome_time(v)))
        .emit()?;
    f.u32("Next")
        .hex()
        .with(|&v, n| n.summary(cache_addr(v)))
        .emit()?;
    f.u32("Previous")
        .hex()
        .with(|&v, n| n.summary(cache_addr(v)))
        .emit()?;
    f.u32("Entry")
        .hex()
        .with(|&v, n| n.summary(cache_addr(v)))
        .emit()?;
    f.i32("Dirty").emit()?;
    f.u32("Self hash").hex().emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Chromium simple cache entry files (<hash>_0)

declare_format!(pub CHROME_SIMPLE = "chrome-simple-cache", "Chromium simple cache entry", [], "application/x-chrome-cache",
    Probe::Magic(&[(0, b"\x30\x5c\x72\xa7\x1b\x6d\xfb\xfc")]), chrome_simple);

const SIMPLE_EOF_MAGIC: u64 = 0xf4fa_6f45_970d_41d8;
const SIMPLE_EOF: u64 = 24;
const SIMPLE_EOF_FLAGS: FlagTable = &[flag(1, "HAS_CRC32"), flag(2, "HAS_KEY_SHA256")];

fn simple_eof_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Final magic").hex().emit()?;
    f.u32("Flags").flags(SIMPLE_EOF_FLAGS).emit()?;
    f.u32("Data CRC-32").hex().emit()?;
    f.u32("Stream size").emit()?;
    Ok(())
}

async fn chrome_simple(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u64("Initial magic").hex().emit()?;
    let version = f.u32("Version").emit()?;
    let key_len = f.u32("Key length").emit()?;
    f.u32("Key hash").hex().emit()?;
    let key_span = file.sub_exact(20, key_len.into())?;
    let key = String::from_utf8_lossy(&cx.read(key_span).await?).into_owned();
    cx.emit(Node::new("Key").span(key_span).value(text(key.clone())));
    // The rest is laid out back to front: stream 0's EOF record ends the file.
    let end = file.len;
    let eof0_at = end.saturating_sub(SIMPLE_EOF);
    let eof0 = cx.read(file.sub(eof0_at, SIMPLE_EOF)).await?;
    if u64_le(&eof0, 0) != Some(SIMPLE_EOF_MAGIC)
        || eof0_at < key_span.end().saturating_sub(file.offset)
    {
        cx.emit(
            Node::new("Streams")
                .span(file.tail(key_span.end().saturating_sub(file.offset)))
                .diag(Diagnostic::malformed(
                    "no EOF record at the end of the file",
                )),
        );
        cx.annotate(format!(
            "Chromium simple cache entry v{version}: {}",
            clip(&key, 100)
        ));
        return Ok(());
    }
    let flags = u32_le(&eof0, 8).unwrap_or(0);
    let stream0 = u64::from(u32_le(&eof0, 16).unwrap_or(0));
    let mut at = eof0_at;
    let sha = if flags & 2 != 0 {
        at = at.saturating_sub(32);
        Some(file.sub(at, 32))
    } else {
        None
    };
    let s0_at = at.saturating_sub(stream0);
    let eof1_at = s0_at.saturating_sub(SIMPLE_EOF);
    let body_at = key_span.end().saturating_sub(file.offset);
    let body = file.sub(body_at, eof1_at.saturating_sub(body_at));
    cx.emit(embedded("Stream 1 (body)", input.nested(body)).summary(size(body.len)));
    cx.emit(struct_node(
        "Stream 1 EOF",
        file.sub(eof1_at, SIMPLE_EOF),
        LE,
        (),
        simple_eof_layout,
    ));
    cx.emit(
        Node::new("Stream 0 (response headers)")
            .span(file.sub(s0_at, stream0))
            .summary(size(stream0)),
    );
    if let Some(sha) = sha {
        cx.emit(Node::new("Key SHA-256").span(sha));
    }
    cx.emit(struct_node(
        "Stream 0 EOF",
        file.sub(eof0_at, SIMPLE_EOF),
        LE,
        (),
        simple_eof_layout,
    ));
    cx.annotate(format!(
        "Chromium simple cache entry v{version}: {}, {} body",
        clip(&key, 100),
        size(body.len)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Chromium "Visited Links"

declare_format!(pub CHROME_VISITED = "chrome-visited-links", "Chromium visited links table", [], "application/x-chrome-visitedlinks",
    Probe::Magic(&[(0, b"VLnk")]), chrome_visited);

record! {
    pub struct VisitedHeader {
        signature: ascii[4] "Signature",
        version: u32 "Version",
        length: u32 "Table length",
        used: u32 "Used entries",
        salt: bytes[8] "Salt",
    }
}

async fn chrome_visited(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, VisitedHeader::SIZE);
    let h: VisitedHeader = read_record(&cx, span, LE).await?;
    cx.emit(VisitedHeader::node("Header", span, LE));
    let table = file.sub(VisitedHeader::SIZE, u64::from(h.length).saturating_mul(8));
    cx.emit(
        Node::new("Fingerprints")
            .span(table)
            .summary(format!("{} of {} slots used", h.used, h.length))
            .lazy(visited_table, table),
    );
    cx.annotate(format!(
        "Chromium visited links v{}, {} links in {} slots",
        h.version, h.used, h.length
    ));
    Ok(())
}

async fn visited_table(cx: Cx, table: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, table, LE);
    let mut slot = 0u64;
    while cur.remaining() >= 8 {
        let span = cur.span(8);
        let fp = cur.u64().await?;
        if fp != 0 {
            cx.push(
                Node::new(format!("Slot {slot}"))
                    .span(span)
                    .value(crate::formats::util::datakit::hex(fp, 64)),
            )
            .await;
        } else if slot.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        slot = slot.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Chromium session files (SNSS: Current/Last Session, Tabs)

declare_format!(pub SNSS = "chrome-snss", "Chromium session file (SNSS)", [], "application/x-chrome-session",
    Probe::Magic(&[(0, b"SNSS")]), snss);

const SESSION_COMMANDS: EnumTable = &[
    (0, "SetTabWindow"),
    (2, "SetTabIndexInWindow"),
    (5, "TabNavigationPathPrunedFromBack"),
    (6, "UpdateTabNavigation"),
    (7, "SetSelectedNavigationIndex"),
    (8, "SetSelectedTabInIndex"),
    (9, "SetWindowType"),
    (11, "TabNavigationPathPrunedFromFront"),
    (12, "SetPinnedState"),
    (13, "SetExtensionAppID"),
    (14, "SetWindowBounds3"),
    (15, "SetWindowAppName"),
    (16, "TabClosed"),
    (17, "WindowClosed"),
    (18, "SetTabUserAgentOverride"),
    (19, "SessionStorageAssociated"),
    (20, "SetActiveWindow"),
    (21, "LastActiveTime"),
];

async fn snss(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.i32("Version").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(8);
    let (mut count, mut urls) = (0u32, 0u32);
    while cur.remaining() >= 3 {
        let start = cur.pos();
        let len = u64::from(cur.u16().await?);
        if len == 0 || len > cur.remaining() {
            cx.diag(
                Diagnostic::malformed("command extends past the end of the file")
                    .at(cur.since(start)),
            );
            break;
        }
        let id = cur.u8().await?;
        let payload = cur.span(len.saturating_sub(1));
        let data = cur.bytes(len.saturating_sub(1)).await?;
        count = count.saturating_add(1);
        let name = lookup(SESSION_COMMANDS, id.into())
            .map_or_else(|| format!("Command {id}"), str::to_owned);
        let mut node = Node::new(name).span(cur.since(start)).target(payload);
        if let Some((tab, index, url, title)) = navigation(&data) {
            urls = urls.saturating_add(1);
            node = node
                .value(text(url.clone()))
                .summary(clip(&format!("tab {tab} #{index}: {title}"), 120));
        } else {
            node = node.summary(format!("{} bytes", data.len()));
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "Chromium session (SNSS v{version}), {count} commands, {urls} navigations"
    ));
    Ok(())
}

/// Decodes the pickled navigation entry of an UpdateTabNavigation command:
/// payload size, tab id, index, URL (UTF-8) and title (UTF-16).
fn navigation(data: &[u8]) -> Option<(i32, i32, String, String)> {
    let payload = u32_le(data, 0)?;
    if u64::from(payload) != to_u64(data.len()).checked_sub(4)? {
        return None;
    }
    let tab = crate::bytes::i32_le(data, 4)?;
    let index = crate::bytes::i32_le(data, 8)?;
    let url_len = to_usize(u32_le(data, 12)?.into());
    let url = data.get(16..16usize.checked_add(url_len)?)?;
    if !url.iter().all(|&b| (0x20..0x7f).contains(&b)) || url.is_empty() {
        return None;
    }
    let title_at = 16usize.checked_add(url_len.next_multiple_of(4))?;
    let title_chars = to_usize(u32_le(data, title_at)?.into());
    let title_start = title_at.checked_add(4)?;
    let title = data
        .get(title_start..title_start.checked_add(title_chars.checked_mul(2)?)?)
        .unwrap_or_default();
    Some((
        tab,
        index,
        String::from_utf8_lossy(url).into_owned(),
        crate::text::utf16(title, LE),
    ))
}

// ---------------------------------------------------------------------------
// Mozilla Mork (Thunderbird .msf, old Firefox history.dat)
//
// Mork is text: dictionaries `<(id=value)…>` define aliases for column names
// and values, tables `{id:scope …}` hold rows `[id(^col^val)…]`, and
// transaction groups `@$${id{@ … @$$}id}@` wrap incremental updates.

declare_format!(pub MORK = "mork", "Mozilla Mork database", ["msf", "mab", "dat"], "application/x-mozilla-mork",
    Probe::Magic(&[(0, b"// <!-- <mdb:mork:z v=\"")]), mork);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MorkKind {
    Dict,
    Table,
    Row,
    Cell,
    GroupStart,
    GroupEnd,
}

/// The index after the cell `( … )` opening at `at` (escapes honoured).
fn mork_skip_cell(data: &[u8], at: usize) -> usize {
    let mut i = at.saturating_add(1);
    while let Some(&d) = data.get(i) {
        match d {
            b'\\' => i = i.saturating_add(2),
            b')' => return i.saturating_add(1),
            _ => i = i.saturating_add(1),
        }
    }
    data.len()
}

/// The index after a `//` comment at `at`.
fn mork_skip_comment(data: &[u8], at: usize) -> usize {
    data.get(at..)
        .and_then(|r| r.iter().position(|&b| b == b'\n'))
        .map_or(data.len(), |p| at.saturating_add(p).saturating_add(1))
}

fn mork_is_comment(data: &[u8], at: usize) -> bool {
    data.get(at..at.saturating_add(2)) == Some(b"//")
}

/// The index after the bracketed item opening at `at`.
fn mork_item_end(data: &[u8], at: usize) -> usize {
    let mut depth = 0u32;
    let mut i = at;
    while let Some(&c) = data.get(i) {
        match c {
            b'(' => {
                i = mork_skip_cell(data, i);
                continue;
            }
            b'/' if mork_is_comment(data, i) => {
                i = mork_skip_comment(data, i);
                continue;
            }
            b'<' | b'{' | b'[' => depth = depth.saturating_add(1),
            b'>' | b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i.saturating_add(1);
                }
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    data.len()
}

fn mork_kind(c: u8) -> MorkKind {
    match c {
        b'<' => MorkKind::Dict,
        b'{' => MorkKind::Table,
        b'(' => MorkKind::Cell,
        _ => MorkKind::Row,
    }
}

/// The items in `data[from..to]`: cells, nested items and, at the top
/// level, transaction group markers.
fn mork_scan(data: &[u8], from: usize, to: usize) -> Vec<(MorkKind, usize, usize)> {
    let mut out = Vec::new();
    let mut i = from;
    while i < to {
        let Some(&c) = data.get(i) else { break };
        let rest = data.get(i..to).unwrap_or_default();
        let (kind, end) = if rest.starts_with(b"//") {
            i = mork_skip_comment(data, i);
            continue;
        } else if rest.starts_with(b"@$${") || rest.starts_with(b"@$$}") {
            let (kind, close): (MorkKind, &[u8]) = if rest.get(3) == Some(&b'{') {
                (MorkKind::GroupStart, b"{@")
            } else {
                (MorkKind::GroupEnd, b"}@")
            };
            let end = rest
                .windows(2)
                .skip(4)
                .position(|w| w == close)
                .map_or(to, |p| i.saturating_add(p).saturating_add(6));
            (kind, end)
        } else if c == b'(' {
            (MorkKind::Cell, mork_skip_cell(data, i))
        } else if matches!(c, b'<' | b'{' | b'[') {
            (mork_kind(c), mork_item_end(data, i))
        } else {
            i = i.saturating_add(1);
            continue;
        };
        let end = end.clamp(i.saturating_add(1), to);
        out.push((kind, i, end));
        i = end;
    }
    out
}

/// Decodes Mork escapes in a value: `\x` and `$xx` (a hex byte).
fn mork_unescape(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while let Some(&c) = raw.get(i) {
        match c {
            b'\\' => {
                i = i.saturating_add(1);
                if let Some(&n) = raw.get(i)
                    && n != b'\n'
                    && n != b'\r'
                {
                    out.push(n);
                }
            }
            b'$' => {
                let hex = raw
                    .get(i.saturating_add(1)..i.saturating_add(3))
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(b) => {
                        out.push(b);
                        i = i.saturating_add(2);
                    }
                    None => out.push(c),
                }
            }
            b'\n' | b'\r' => {}
            _ => out.push(c),
        }
        i = i.saturating_add(1);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits a cell `(col=value)` or `(^col^atom)` into its two halves; the
/// boolean says whether the value is an atom reference.
fn mork_cell(cell: &[u8]) -> (&[u8], &[u8], bool) {
    let inner = cell
        .get(1..cell.len().saturating_sub(1))
        .unwrap_or_default();
    // The column part ends at '=' or at the next '^'.
    let skip = usize::from(inner.first() == Some(&b'^'));
    let split = inner
        .iter()
        .skip(skip)
        .position(|&b| b == b'=' || b == b'^')
        .map(|p| p.saturating_add(skip));
    match split {
        Some(p) => {
            let atom = inner.get(p) == Some(&b'^');
            (
                inner.get(..p).unwrap_or_default(),
                inner.get(p.saturating_add(1)..).unwrap_or_default(),
                atom,
            )
        }
        None => (inner, &[], false),
    }
}

/// Column-name and value aliases from every dictionary in the file.
#[derive(Default)]
struct MorkAliases {
    columns: std::collections::BTreeMap<String, String>,
    atoms: std::collections::BTreeMap<String, String>,
}

impl MorkAliases {
    fn build(data: &[u8]) -> Self {
        let mut a = MorkAliases::default();
        for (kind, start, end) in mork_scan(data, 0, data.len()) {
            if kind != MorkKind::Dict {
                continue;
            }
            let mut columns = false;
            for (kind, s, e) in mork_scan(data, start.saturating_add(1), end.saturating_sub(1)) {
                let slice = data.get(s..e).unwrap_or_default();
                match kind {
                    // A meta-dictionary `<(a=c)>` switches to the column scope.
                    MorkKind::Dict => columns = slice.windows(5).any(|w| w == b"(a=c)"),
                    MorkKind::Cell => {
                        let (id, value, _) = mork_cell(slice);
                        let map = if columns {
                            &mut a.columns
                        } else {
                            &mut a.atoms
                        };
                        map.insert(
                            String::from_utf8_lossy(id).into_owned(),
                            mork_unescape(value),
                        );
                    }
                    _ => {}
                }
            }
        }
        a
    }

    fn column(&self, raw: &[u8]) -> String {
        let id = String::from_utf8_lossy(raw).into_owned();
        match id.strip_prefix('^') {
            Some(alias) => self.columns.get(alias).cloned().unwrap_or(id),
            None => id,
        }
    }

    fn value(&self, raw: &[u8], atom: bool) -> String {
        if atom {
            let id = String::from_utf8_lossy(raw).into_owned();
            return self
                .atoms
                .get(&id)
                .cloned()
                .unwrap_or_else(|| format!("^{id}"));
        }
        mork_unescape(raw)
    }
}

async fn mork_aliases(cx: &Cx, file: Span) -> Result<Arc<MorkAliases>> {
    if let Some(a) = cx.cached::<MorkAliases>(file, "mork-aliases") {
        return Ok(a);
    }
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let a = Arc::new(MorkAliases::build(&data));
    cx.cache(file, "mork-aliases", a.clone());
    Ok(a)
}

async fn mork(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let first_line = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let magic = String::from_utf8_lossy(data.get(..first_line).unwrap_or_default())
        .trim_end()
        .to_owned();
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, to_u64(first_line)))
            .value(text(magic.clone())),
    );
    let items = mork_scan(&data, first_line, data.len());
    let count = |k: MorkKind| items.iter().filter(|(kind, _, _)| *kind == k).count();
    let (dicts, tables, rows, groups) = (
        count(MorkKind::Dict),
        count(MorkKind::Table),
        count(MorkKind::Row),
        count(MorkKind::GroupStart),
    );
    cx.set_count(Count::Exact(to_u64(items.len()).saturating_add(1)));
    for (kind, start, end) in items {
        let span = file.sub(to_u64(start), to_u64(end.saturating_sub(start)));
        let slice = data.get(start..end).unwrap_or_default();
        let node = match kind {
            MorkKind::GroupStart | MorkKind::GroupEnd => {
                let name = if kind == MorkKind::GroupStart {
                    "Group start"
                } else {
                    "Group end"
                };
                Node::new(name)
                    .span(span)
                    .value(text(String::from_utf8_lossy(slice).into_owned()))
            }
            MorkKind::Cell => Node::new("Cell")
                .span(span)
                .value(text(String::from_utf8_lossy(slice).into_owned())),
            _ => mork_node(kind, file, span, slice, false),
        };
        cx.push(node).await;
    }
    let version = magic.split('"').nth(1).unwrap_or("?").to_owned();
    cx.annotate(format!("Mork {version}, {dicts} dictionaries, {tables} tables, {rows} rows, {groups} transaction groups"));
    Ok(())
}

/// The id after the opening bracket of a table or row (`1:^80`).
fn mork_id(slice: &[u8]) -> String {
    let inner = slice.get(1..).unwrap_or_default();
    let end = inner
        .iter()
        .position(|&b| {
            matches!(
                b,
                b'(' | b'[' | b'{' | b'<' | b'\n' | b'}' | b']' | b'>' | b' '
            )
        })
        .unwrap_or(inner.len());
    String::from_utf8_lossy(inner.get(..end).unwrap_or_default())
        .trim()
        .to_owned()
}

fn mork_node(kind: MorkKind, file: Span, span: Span, slice: &[u8], meta: bool) -> Node {
    let children = mork_scan(slice, 1, slice.len().saturating_sub(1));
    let cells = children
        .iter()
        .filter(|(k, _, _)| *k == MorkKind::Cell)
        .count();
    let rows = children
        .iter()
        .filter(|(k, _, _)| *k == MorkKind::Row)
        .count();
    let (name, summary) = match (kind, meta) {
        (MorkKind::Dict, false) => ("Dictionary".to_owned(), format!("{cells} cells")),
        (MorkKind::Dict, true) => ("Meta-dictionary".to_owned(), format!("{cells} cells")),
        (MorkKind::Table, false) => (format!("Table {}", mork_id(slice)), format!("{rows} rows")),
        (MorkKind::Table, true) => ("Meta-table".to_owned(), format!("{cells} cells")),
        _ => (format!("Row {}", mork_id(slice)), format!("{cells} cells")),
    };
    Node::new(name)
        .span(span)
        .summary(summary)
        .lazy(mork_expand, (file, span, kind))
}

async fn mork_expand(cx: Cx, (file, span, kind): (Span, Span, MorkKind)) -> Result<()> {
    let data = cx.read(span).await?;
    let aliases = mork_aliases(&cx, file).await?;
    for (child, start, end) in mork_scan(&data, 1, data.len().saturating_sub(1)) {
        let sub = span.sub(to_u64(start), to_u64(end.saturating_sub(start)));
        let slice = data.get(start..end).unwrap_or_default();
        let node = match child {
            MorkKind::Cell if kind == MorkKind::Dict => {
                let (id, value, _) = mork_cell(slice);
                Node::new(String::from_utf8_lossy(id).into_owned())
                    .span(sub)
                    .value(text(mork_unescape(value)))
            }
            MorkKind::Cell => {
                let (column, value, atom) = mork_cell(slice);
                Node::new(aliases.column(column))
                    .span(sub)
                    .value(text(aliases.value(value, atom)))
            }
            // Dictionaries and tables nested directly are meta-objects.
            _ => mork_node(child, file, sub, slice, child != MorkKind::Row),
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Firefox cache2 entries (cache2/entries/<SHA1>)
//
// The body comes first; the metadata (hashes, header, key, elements) follows
// it, and the file ends with the metadata's offset (big-endian).

const CACHE2_CHUNK: u64 = 256 * 1024;

/// Reads a big-endian u32 at absolute offset `at` from the head or the tail.
fn head_or_tail_u32(h: &Head<'_>, at: u64) -> Option<u32> {
    if let Some(v) = usize::try_from(at).ok().and_then(|a| u32_be(h.data, a)) {
        return Some(v);
    }
    let tail_start = h.len.checked_sub(to_u64(h.tail.len()))?;
    let rel = usize::try_from(at.checked_sub(tail_start)?).ok()?;
    u32_be(h.tail, rel)
}

/// Where the metadata header starts, given the metadata offset.
fn cache2_header_at(offset: u64) -> u64 {
    let chunks = offset.div_ceil(CACHE2_CHUNK);
    offset
        .saturating_add(4)
        .saturating_add(chunks.saturating_mul(2))
}

fn cache2_probe(h: &Head<'_>) -> bool {
    let Some(offset) = h
        .len
        .checked_sub(4)
        .and_then(|end| head_or_tail_u32(h, end))
        .map(u64::from)
    else {
        return false;
    };
    let header = cache2_header_at(offset);
    // Header (7 or 8 words) plus a key must fit before the trailing offset.
    if header.saturating_add(36) > h.len.saturating_sub(4) {
        return false;
    }
    let version = head_or_tail_u32(h, header);
    let key_size = head_or_tail_u32(h, header.saturating_add(24)).map_or(0, u64::from);
    matches!(version, Some(1..=3))
        && key_size > 0
        && header.saturating_add(28).saturating_add(key_size) < h.len
}

declare_format!(pub FIREFOX_CACHE2 = "firefox-cache2", "Firefox cache entry (cache2)", [], "application/x-firefox-cache2",
    Probe::Custom(cache2_probe), firefox_cache2);

const CACHE2_FLAGS: FlagTable = &[flag(1, "ANONYMOUS"), flag(2, "PINNED")];

fn cache2_header(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32)> {
    let version = f.u32("Version").emit()?;
    f.u32("Fetch count").emit()?;
    f.u32("Last fetched").timestamp().emit()?;
    f.u32("Last modified").timestamp().emit()?;
    f.u32("Frecency").emit()?;
    f.u32("Expiration time")
        .with(|&v, n| {
            if v == u32::MAX {
                n.summary("never")
            } else {
                n.value(Value::Timestamp {
                    unix_seconds: v.into(),
                })
            }
        })
        .emit()?;
    let key = f.u32("Key size").emit()?;
    if version >= 2 {
        f.u32("Flags").flags(CACHE2_FLAGS).emit()?;
    }
    Ok((version, key))
}

async fn firefox_cache2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let end = file.len.saturating_sub(4);
    let tail = cx.read(file.sub(end, 4)).await?;
    let offset = u64::from(u32_be(&tail, 0).unwrap_or(0));
    let body = file.sub(0, offset);
    let mut body_node = crate::formats::winforensics::text_or_embedded(&cx, input, body)
        .await?
        .summary(size(offset));
    body_node.name = "Body".into();
    cx.emit(body_node);
    let chunks = offset.div_ceil(CACHE2_CHUNK);
    cx.emit(Node::new("Metadata hash").span(file.sub(offset, 4)));
    cx.emit(
        Node::new("Chunk hashes")
            .span(file.sub(offset.saturating_add(4), chunks.saturating_mul(2)))
            .summary(format!("{chunks} chunks")),
    );
    let header_at = cache2_header_at(offset);
    let header_span = file.sub(header_at, 32);
    let block = cx.block(header_span).await?;
    let (version, key_len) = cache2_header(&mut Fields::new(&block, BE), &())?;
    let header_len = if version >= 2 { 32 } else { 28 };
    cx.emit(struct_node(
        "Header",
        file.sub(header_at, header_len),
        BE,
        (),
        cache2_header,
    ));
    let key_at = header_at.saturating_add(header_len);
    let key_span = file.sub_exact(key_at, u64::from(key_len).saturating_add(1))?;
    let key = crate::text::until_nul(&cx.read(key_span).await?);
    cx.emit(Node::new("Key").span(key_span).value(text(key.clone())));
    // Elements: NUL-terminated name/value pairs up to the trailing offset.
    let elements_at = key_span.end().saturating_sub(file.offset);
    let elements = file.sub(elements_at, end.saturating_sub(elements_at));
    let data = cx.read_avail(elements.sub(0, cx.limits().max_read)).await?;
    let mut parts = data.split(|&b| b == 0);
    let mut at = 0u64;
    let mut status = String::new();
    let mut list = Vec::new();
    while let (Some(name), Some(value)) = (parts.next(), parts.next()) {
        if name.is_empty() {
            break;
        }
        let len = to_u64(name.len())
            .saturating_add(to_u64(value.len()))
            .saturating_add(2);
        let name = String::from_utf8_lossy(name).into_owned();
        let value = String::from_utf8_lossy(value).into_owned();
        if name == "response-head" {
            status = value.lines().next().unwrap_or_default().to_owned();
        }
        list.push((name, value, elements.sub(at, len)));
        at = at.saturating_add(len);
    }
    cx.emit(
        Node::new("Elements")
            .span(elements)
            .summary(format!("{} elements", list.len()))
            .lazy(cache2_elements, list),
    );
    cx.emit(
        Node::new("Metadata offset")
            .span(file.sub(end, 4))
            .value(crate::formats::util::datakit::hex(offset, 32)),
    );
    // The key is "[flags],:URL" (e.g. "a,:https://...", "O^partitionKey=...,:URL").
    let url = key
        .split_once(":http")
        .map_or(key.as_str(), |(_, rest)| rest);
    let url = if key.contains(":http") {
        format!("http{url}")
    } else {
        key.clone()
    };
    cx.annotate(format!(
        "Firefox cache entry v{version}: {}{}, {} body",
        clip(&url, 120),
        if status.is_empty() {
            String::new()
        } else {
            format!(" ({status})")
        },
        size(offset)
    ));
    Ok(())
}

async fn cache2_elements(cx: Cx, list: Vec<(String, String, Span)>) -> Result<()> {
    for (name, value, span) in list {
        let node = Node::new(name).span(span);
        cx.push(if value.lines().count() > 1 {
            node.value(text(value.lines().next().unwrap_or_default()))
                .summary(clip(value.trim_end().replace("\r\n", " | ").as_str(), 200))
        } else {
            node.value(text(value))
        })
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Chromium simple cache index (index-dir/the-real-index)

fn simple_index_probe(h: &Head<'_>) -> bool {
    u64_le(h.data, 8) == Some(SIMPLE_INDEX_MAGIC)
        && u32_le(h.data, 16).is_some_and(|v| (4..=20).contains(&v))
}

const SIMPLE_INDEX_MAGIC: u64 = 0x656e_7465_7220_796f;

declare_format!(pub CHROME_SIMPLE_INDEX = "chrome-simple-index", "Chromium simple cache index", [], "application/x-chrome-cache",
    Probe::Custom(simple_index_probe), chrome_simple_index);

async fn chrome_simple_index(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 40)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Payload size").emit()?;
    f.u32("CRC-32").hex().emit()?;
    f.u64("Magic").hex().emit()?;
    let version = f.u32("Version").emit()?;
    let entries = f.u64("Number of entries").emit()?;
    let bytes = f
        .u64("Cache size")
        .with(|&v, n| n.summary(size(v)))
        .emit()?;
    let mut at = 36u64;
    if version >= 7 {
        f.u32("Write reason").emit()?;
        at = 40;
    }
    // Entries: hash, then last-used time and size, whose encoding changed in
    // version 7 (seconds and 256-byte units in 32 bits each).
    let entry = if version >= 7 { 16u64 } else { 24 };
    let list = file.sub(at, entries.saturating_mul(entry));
    cx.emit(
        Node::new("Entries")
            .span(list)
            .summary(format!("{entries} entries"))
            .lazy(simple_index_entries, (list, version)),
    );
    let end = at.saturating_add(entries.saturating_mul(entry));
    if file.len >= end.saturating_add(8) {
        let raw = cx.read(file.sub(end, 8)).await?;
        cx.emit(
            Node::new("Last modified")
                .span(file.sub(end, 8))
                .value(chrome_time(u64_le(&raw, 0).unwrap_or(0))),
        );
    }
    cx.annotate(format!(
        "Chromium simple cache index v{version}, {entries} entries, {}",
        size(bytes)
    ));
    Ok(())
}

async fn simple_index_entries(cx: Cx, (list, version): (Span, u32)) -> Result<()> {
    let entry = if version >= 7 { 16u64 } else { 24 };
    let count = list.len.checked_div(entry).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = list.sub(i.saturating_mul(entry), entry);
        let e = cx.read(span).await?;
        let hash = u64_le(&e, 0).unwrap_or(0);
        let (time, bytes) = if version >= 7 {
            let t = u32_le(&e, 8).unwrap_or(0);
            let s = u32_le(&e, 12).unwrap_or(0);
            (
                Value::Timestamp {
                    unix_seconds: t.into(),
                },
                u64::from(s & 0x00ff_ffff).saturating_mul(256),
            )
        } else {
            (
                chrome_time(u64_le(&e, 8).unwrap_or(0)),
                u64_le(&e, 16).unwrap_or(0),
            )
        };
        cx.push(
            Node::new(format!("{hash:016x}"))
                .span(span)
                .value(time)
                .summary(size(bytes)),
        )
        .await;
    }
    Ok(())
}
