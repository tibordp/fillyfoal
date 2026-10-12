//! GVDB, GLib's GVariant database: a read-only hash table of GVariant
//! values, memory-mapped by its readers. Three formats are built on it:
//! GResource bundles (`glib-compile-resources`; resource paths mapped to
//! `(uuay)` size, flags and data, zlib-compressed when flag 1 is set),
//! dconf databases (`dconf compile`, the user database; key paths mapped to
//! variants, locks in a nested `.locks` table) and GSettings schema caches
//! (`gschemas.compiled`; one nested table per schema).
//!
//! The file starts with `GVariant` (byte-swapped, `raVGtnai`, when written
//! in big-endian, values included), a version, options and a pointer to the
//! root hash table. A table is a header (bloom filter size and shift,
//! bucket count), the bloom filter words, the buckets and then 24-byte
//! items: hash, parent item, key pointer, a type (`v` value, `H` nested
//! table, `L` list of child items) and a value pointer. Keys are stored
//! relative to their parent item (`/org/`, `example/`, ...), so an item's
//! full name is the chain of its parents' keys.
//!
//! The probes tell the three apart by what the head shows: a value of type
//! `(uuay)` makes a GResource bundle; a root item whose key starts with `/`
//! a dconf database (a GResource bundle whose first value lies beyond the
//! head reads as dconf too, which the dissector corrects); anything else
//! is a generic GVDB file.

use std::sync::Arc;

use crate::codec::Codec;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::datakit::{ByteReader, le_uint};
use crate::formats::util::fmt::{clip, grouped_count, plural};
use crate::formats::util::val;
use crate::formats::{Format, Head, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::value::{FlagTable, Value, decode_flags, flag};

use super::gvariant::{self as gv, Kind as Kind_, Seg, Style, Ty};

pub static GRESOURCE: Format = Format {
    name: "gresource",
    title: "GLib resource bundle (GResource)",
    extensions: &["gresource"],
    mime: "application/x-gresource",
    probe: Probe::Custom(probe_gresource),
    dissect: crate::expander!(dissect_gresource: Input),
};

pub static DCONF: Format = Format {
    name: "dconf",
    title: "dconf database",
    extensions: &[],
    mime: "application/x-dconf-database",
    probe: Probe::Custom(probe_dconf),
    dissect: crate::expander!(dissect_dconf: Input),
};

pub static GVDB: Format = Format {
    name: "gvdb",
    title: "GVariant database (GVDB)",
    extensions: &["gvdb", "compiled"],
    mime: "application/x-gvdb",
    probe: Probe::Custom(probe_gvdb),
    dissect: crate::expander!(dissect_gvdb: Input),
};

record! {
    pub struct Header {
        signature: ascii[8] "Signature" .desc("\"GVariant\", byte-swapped (\"raVGtnai\") in big-endian files"),
        version: u32 "Version",
        options: u32 "Options",
        root_start: u32 "Root table start" .hex(),
        root_end: u32 "Root table end" .hex(),
    }
}

record! {
    pub struct TableHeader {
        bloom: u32 "Bloom filter" .hex() .desc("Low 27 bits: number of 32-bit bloom filter words; high 5 bits: the shift for the second hash bit"),
        buckets: u32 "Buckets",
    }
}

const ITEM_TYPES: crate::value::EnumTable = &[
    (b'v' as u64, "value"),
    (b'H' as u64, "hash table"),
    (b'L' as u64, "list"),
];

record! {
    pub struct ItemRecord {
        hash: u32 "Hash" .hex() .desc("djb2 hash of the full key"),
        parent: u32 "Parent" .desc("Index of the parent item (0xffffffff: none)"),
        key_start: u32 "Key start" .hex(),
        key_size: u16 "Key size",
        kind: u8 "Type" .enumeration(ITEM_TYPES),
        _unused: u8 "Unused",
        value_start: u32 "Value start" .hex(),
        value_end: u32 "Value end" .hex(),
    }
}

const HEADER_SIZE: u64 = 24;
const ITEM_SIZE: u64 = 24;
const NO_PARENT: u32 = u32::MAX;
/// Parent links followed to build a full key.
const MAX_CHAIN: usize = 64;
/// Bytes of one key read for a name.
const MAX_KEY: u64 = 256;
/// Nested tables (dconf locks, schemas) followed.
const MAX_NESTING: u32 = 16;

const RESOURCE_FLAGS: FlagTable = &[flag(1, "COMPRESSED")];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Resource,
    Dconf,
    Generic,
}

/// The byte order from the signature.
fn signature(data: &[u8]) -> Option<Endian> {
    match data.get(..8)? {
        b"GVariant" => Some(Endian::Little),
        b"raVGtnai" => Some(Endian::Big),
        _ => None,
    }
}

fn u32_at(data: &[u8], at: u64, endian: Endian) -> Option<u32> {
    let at = usize::try_from(at).ok()?;
    let b: [u8; 4] = data.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u32::from_le_bytes(b),
        Endian::Big => u32::from_be_bytes(b),
    })
}

/// What a probe sees of a file: its byte order and root table bounds.
fn probe_header(h: &Head<'_>) -> Option<(Endian, u64, u64)> {
    let endian = signature(h.data)?;
    let version = u32_at(h.data, 8, endian)?;
    let start = u64::from(u32_at(h.data, 16, endian)?);
    let end = u64::from(u32_at(h.data, 20, endian)?);
    let sane = version == 0
        && start <= end
        && start.is_multiple_of(4)
        && (start == end || start >= HEADER_SIZE)
        && (!h.len_known || end <= h.len);
    sane.then_some((endian, start, end))
}

/// The root table's items the head holds: `(parent, key, type, value)`.
/// What a probe sees of one item: parent, key, type and value.
type ProbeItem<'a> = (u32, &'a [u8], u8, Option<&'a [u8]>);

fn probe_items<'a>(h: &Head<'a>) -> Vec<ProbeItem<'a>> {
    let Some((endian, start, end)) = probe_header(h) else {
        return Vec::new();
    };
    let (Some(bloom), Some(buckets)) = (
        u32_at(h.data, start, endian),
        u32_at(h.data, start.saturating_add(4), endian),
    ) else {
        return Vec::new();
    };
    let items = start
        .saturating_add(8)
        .saturating_add(u64::from(bloom & 0x07ff_ffff).saturating_mul(4))
        .saturating_add(u64::from(buckets).saturating_mul(4));
    let mut out = Vec::new();
    let mut at = items;
    while at.saturating_add(ITEM_SIZE) <= end && out.len() < 64 {
        let field = |off: u64| u32_at(h.data, at.saturating_add(off), endian);
        let (Some(parent), Some(key_start), Some(vs), Some(ve)) =
            (field(4), field(8), field(16), field(20))
        else {
            break;
        };
        let get = |s: u64, e: u64| {
            h.data
                .get(usize::try_from(s).ok()?..usize::try_from(e).ok()?)
        };
        let key_size = get(at.saturating_add(12), at.saturating_add(14))
            .map(|b| match endian {
                Endian::Little => le_uint(b),
                Endian::Big => crate::formats::util::datakit::be_uint(b),
            })
            .unwrap_or(0);
        let kind = get(at.saturating_add(14), at.saturating_add(15))
            .and_then(|b| b.first().copied())
            .unwrap_or(0);
        let key = get(
            u64::from(key_start),
            u64::from(key_start).saturating_add(key_size),
        )
        .unwrap_or_default();
        let value = (vs <= ve)
            .then(|| get(u64::from(vs), u64::from(ve)))
            .flatten();
        out.push((parent, key, kind, value));
        at = at.saturating_add(ITEM_SIZE);
    }
    out
}

fn is_resource_value(v: &[u8]) -> bool {
    v.ends_with(b"\0(uuay)")
}

fn probe_gresource(h: &Head<'_>) -> bool {
    probe_items(h)
        .iter()
        .find(|(_, _, kind, value)| *kind == b'v' && value.is_some())
        .and_then(|(_, _, _, value)| *value)
        .is_some_and(is_resource_value)
}

fn probe_dconf(h: &Head<'_>) -> bool {
    let items = probe_items(h);
    let resource = items
        .iter()
        .any(|(_, _, kind, value)| *kind == b'v' && value.is_some_and(is_resource_value));
    !resource
        && items
            .iter()
            .any(|(parent, key, _, _)| *parent == NO_PARENT && key.starts_with(b"/"))
}

fn probe_gvdb(h: &Head<'_>) -> bool {
    probe_header(h).is_some()
}

/// One hash item.
#[derive(Clone, Copy, Debug)]
struct Item {
    parent: u32,
    key_start: u32,
    key_size: u16,
    kind: u8,
    value_start: u32,
    value_end: u32,
}

/// A parsed hash table.
struct Table {
    /// The table's bytes, relative to the file.
    seg: Seg,
    bloom_words: u64,
    bloom_shift: u32,
    buckets: u64,
    items_at: u64,
    items: Vec<Item>,
    /// Bytes after the last whole item.
    leftover: u64,
}

impl Table {
    fn bloom_at(&self) -> u64 {
        self.seg.start.saturating_add(8)
    }
    fn buckets_at(&self) -> u64 {
        self.bloom_at()
            .saturating_add(self.bloom_words.saturating_mul(4))
    }
}

/// What every expansion of one file shares.
#[derive(Clone)]
struct File {
    input: Input,
    endian: Endian,
    kind: Kind,
}

fn read_u(data: &[u8], endian: Endian) -> u64 {
    match endian {
        Endian::Little => le_uint(data),
        Endian::Big => crate::formats::util::datakit::be_uint(data),
    }
}

async fn load_table(cx: &Cx, file: &File, seg: Seg) -> Result<Arc<Table>> {
    let span = file.input.span.sub(seg.start, seg.len());
    if let Some(t) = cx.cached::<Table>(span, "gvdb-table") {
        return Ok(t);
    }
    let mut r = ByteReader::new(cx, file.input.span);
    if seg.len() < 8 {
        return Err(Diagnostic::malformed(format!(
            "hash table of {} bytes is smaller than its header",
            seg.len()
        ))
        .at(span));
    }
    let head = r.bytes(seg.start, 8).await?;
    let bloom = read_u(head.get(..4).unwrap_or_default(), file.endian);
    let buckets = read_u(head.get(4..8).unwrap_or_default(), file.endian);
    let bloom_words = bloom & 0x07ff_ffff;
    let items_at = 8u64
        .saturating_add(bloom_words.saturating_mul(4))
        .saturating_add(buckets.saturating_mul(4));
    if items_at > seg.len() {
        return Err(Diagnostic::malformed(format!(
            "bloom filter ({bloom_words_word}) and buckets ({buckets}) do not fit in the {}-byte table",
            seg.len(), bloom_words_word = plural(bloom_words, "word")
        ))
        .at(span));
    }
    let room = seg.len().saturating_sub(items_at);
    let count = room / ITEM_SIZE;
    let items_at = seg.start.saturating_add(items_at);
    let mut items = Vec::new();
    for i in 0..count {
        let b = r
            .bytes(
                items_at.saturating_add(i.saturating_mul(ITEM_SIZE)),
                ITEM_SIZE,
            )
            .await?;
        let u = |a: usize, n: usize| {
            read_u(
                b.get(a..a.saturating_add(n)).unwrap_or_default(),
                file.endian,
            )
        };
        items.push(Item {
            parent: u32::try_from(u(4, 4)).unwrap_or(NO_PARENT),
            key_start: u32::try_from(u(8, 4)).unwrap_or(0),
            key_size: u16::try_from(u(12, 2)).unwrap_or(0),
            kind: b.get(14).copied().unwrap_or(0),
            value_start: u32::try_from(u(16, 4)).unwrap_or(0),
            value_end: u32::try_from(u(20, 4)).unwrap_or(0),
        });
    }
    let table = Arc::new(Table {
        seg,
        bloom_words,
        bloom_shift: u32::try_from(bloom >> 27).unwrap_or(0),
        buckets,
        items_at,
        items,
        leftover: room % ITEM_SIZE,
    });
    cx.cache(span, "gvdb-table", table.clone());
    Ok(table)
}

/// An item's own key (its first [`MAX_KEY`] bytes, lossy).
async fn own_key(r: &mut ByteReader<'_>, item: &Item) -> Result<String> {
    let len = u64::from(item.key_size).min(MAX_KEY);
    let b = r.bytes(u64::from(item.key_start), len).await?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// An item's full key: its parents' keys, then its own.
async fn full_key(r: &mut ByteReader<'_>, table: &Table, index: u64) -> Result<String> {
    let mut parts = Vec::new();
    let mut at = index;
    let mut seen = Vec::new();
    while let Some(item) = usize::try_from(at).ok().and_then(|i| table.items.get(i)) {
        if seen.contains(&at) || seen.len() >= MAX_CHAIN {
            parts.push("…".to_owned());
            break;
        }
        seen.push(at);
        parts.push(own_key(r, item).await?);
        if item.parent == NO_PARENT {
            break;
        }
        at = u64::from(item.parent);
    }
    parts.reverse();
    Ok(clip(&parts.concat(), 512))
}

/// What a `v` item holds when it is a resource: `(uuay)` size, flags,
/// data.
struct Resource {
    size: u64,
    flags: u64,
    data: Seg,
    size_seg: Seg,
    flags_seg: Seg,
}

async fn resource(r: &mut ByteReader<'_>, seg: Seg, endian: Endian) -> Result<Option<Resource>> {
    let (ty, child) = gv::variant(r, seg).await?;
    if ty.signature() != "(uuay)" {
        return Ok(None);
    }
    let Kind_::Tuple(types) = &ty.kind else {
        return Ok(None);
    };
    let parts = gv::members(r, child, types).await?;
    let (Some(&s), Some(&f), Some(&d)) = (parts.first(), parts.get(1), parts.get(2)) else {
        return Ok(None);
    };
    let size = read_u(&r.bytes(s.start, 4).await?, endian);
    let flags = read_u(&r.bytes(f.start, 4).await?, endian);
    Ok(Some(Resource {
        size,
        flags,
        data: d,
        size_seg: s,
        flags_seg: f,
    }))
}

fn flags_value(raw: u64) -> Value {
    let (set, unknown) = decode_flags(RESOURCE_FLAGS, raw);
    Value::Flags {
        raw,
        bits: 32,
        set,
        unknown,
    }
}

fn type_name(kind: u8) -> String {
    val::name_or(ITEM_TYPES, u64::from(kind), "type ")
}

#[derive(Clone)]
struct TableState {
    file: File,
    seg: Seg,
    nesting: u32,
}

#[derive(Clone)]
struct ItemState {
    table: TableState,
    index: u64,
}

pub async fn dissect_gresource(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, Kind::Resource).await
}

pub async fn dissect_dconf(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, Kind::Dconf).await
}

pub async fn dissect_gvdb(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, Kind::Generic).await
}

async fn dissect(cx: Cx, input: Input, kind: Kind) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, HEADER_SIZE)).await?;
    let Some(endian) = signature(&head) else {
        return Err(Diagnostic::malformed("no GVariant signature").at(input.span.sub(0, 8)));
    };
    cx.emit(Header::node(
        "Header",
        input.span.sub(0, HEADER_SIZE),
        endian,
    ));
    let header = crate::fields::parse(
        &cx,
        input.span.sub(0, HEADER_SIZE),
        endian,
        &(),
        Header::layout,
    )
    .await?;
    let root = Seg::new(u64::from(header.root_start), u64::from(header.root_end));
    let mut file = File {
        input,
        endian,
        kind,
    };
    if header.version != 0 {
        cx.diag(Diagnostic::warning(format!(
            "unknown version {}",
            header.version
        )));
    }
    if root.is_empty() {
        cx.annotate("GVDB, empty");
        return Ok(());
    }
    if root.end > input.span.len || root.start > root.end {
        return Err(Diagnostic::malformed(format!(
            "root table {:#x}..{:#x} lies outside the {}-byte file",
            root.start, root.end, input.span.len
        ))
        .at(input.span.sub(16, 8)));
    }
    let table = load_table(&cx, &file, root).await?;
    // A bundle whose first values lie beyond the probe's view.
    let mut r = ByteReader::new(&cx, input.span);
    cx.charge(crate::bytes::to_u64(table.items.len()) / 256)
        .await;
    let mut values = 0u64;
    for item in table.items.iter().filter(|i| i.kind == b'v') {
        values = values.saturating_add(1);
        if values <= 16
            && file.kind != Kind::Resource
            && let Ok(Some(_)) = resource(
                &mut r,
                Seg::new(u64::from(item.value_start), u64::from(item.value_end)),
                endian,
            )
            .await
        {
            file.kind = Kind::Resource;
        }
    }
    let order = if endian == Endian::Big {
        ", big-endian"
    } else {
        ""
    };
    cx.annotate(match file.kind {
        Kind::Resource => format!(
            "GResource bundle, {}{order}",
            grouped_count(values, "file", "files")
        ),
        Kind::Dconf => format!(
            "dconf database, {}{order}",
            grouped_count(values, "key", "keys")
        ),
        Kind::Generic => format!(
            "GVDB, {}{order}",
            grouped_count(crate::bytes::to_u64(table.items.len()), "item", "items")
        ),
    });
    table_children(
        cx,
        TableState {
            file,
            seg: root,
            nesting: 0,
        },
    )
    .await
}

/// A table's header, bloom filter, buckets and items.
async fn table_children(cx: Cx, state: TableState) -> Result<()> {
    let table = load_table(&cx, &state.file, state.seg).await?;
    let span = |s: u64, n: u64| state.file.input.span.sub(s, n);
    cx.emit(TableHeader::node(
        "Table header",
        span(table.seg.start, 8),
        state.file.endian,
    ));
    let bloom_len = table.bloom_words.saturating_mul(4);
    cx.emit(
        Node::new("Bloom filter")
            .span(span(table.bloom_at(), bloom_len))
            .summary(format!(
                "{}, shift {}",
                grouped_count(table.bloom_words, "word", "words"),
                table.bloom_shift
            )),
    );
    cx.emit(
        Node::new("Buckets")
            .span(span(table.buckets_at(), table.buckets.saturating_mul(4)))
            .summary(grouped_count(table.buckets, "bucket", "buckets"))
            .desc("Index of the first item of each hash bucket"),
    );
    let count = crate::bytes::to_u64(table.items.len());
    let mut items = Node::new("Items")
        .span(span(table.items_at, count.saturating_mul(ITEM_SIZE)))
        .summary(grouped_count(count, "item", "items"));
    if table.leftover != 0 {
        items = items.diag(Diagnostic::warning(format!(
            "{} bytes after the last whole item",
            table.leftover
        )));
    }
    if count > 0 {
        items = items.lazy(crate::expander!(self::items: TableState), state);
    }
    cx.emit(items);
    Ok(())
}

async fn items(cx: Cx, state: TableState) -> Result<()> {
    let table = load_table(&cx, &state.file, state.seg).await?;
    let count = crate::bytes::to_u64(table.items.len());
    cx.set_count(Count::Exact(count));
    let mut r = ByteReader::new(&cx, state.file.input.span);
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        let at = i;
        cx.mark(move || at);
        let node = item_node(&mut r, &table, &state, i).await;
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

fn value_seg(item: &Item) -> Seg {
    Seg::new(u64::from(item.value_start), u64::from(item.value_end))
}

/// An item, named by its full key, showing its value.
async fn item_node(r: &mut ByteReader<'_>, table: &Table, state: &TableState, index: u64) -> Node {
    let Some(item) = usize::try_from(index)
        .ok()
        .and_then(|i| table.items.get(i))
        .copied()
    else {
        return Node::new(format!("[{index}]"));
    };
    let span = r.span(
        table
            .items_at
            .saturating_add(index.saturating_mul(ITEM_SIZE)),
        ITEM_SIZE,
    );
    let name = match full_key(r, table, index).await {
        Ok(k) if !k.is_empty() => k,
        _ => format!("[{index}]"),
    };
    let node = Node::new(name.clone()).span(span);
    let vseg = value_seg(&item);
    let file_len = state.file.input.span.len;
    let node = if vseg.start > vseg.end || vseg.end > file_len {
        node.diag(
            Diagnostic::malformed(format!(
                "value {:#x}..{:#x} lies outside the file",
                vseg.start, vseg.end
            ))
            .at(span),
        )
    } else {
        match item.kind {
            b'v' => {
                if state.file.kind == Kind::Resource
                    && let Ok(Some(res)) = resource(r, vseg, state.file.endian).await
                {
                    let compressed = res.flags & 1 != 0;
                    node.value(val::uint(res.size, 32)).summary(if compressed {
                        format!(
                            "{}, zlib-compressed to {}",
                            grouped_count(res.size, "byte", "bytes"),
                            grouped_count(res.data.len(), "byte", "bytes")
                        )
                    } else {
                        grouped_count(res.size, "byte", "bytes")
                    })
                } else {
                    let shown = gv::node(
                        r,
                        String::new(),
                        vseg,
                        &variant_ty(),
                        Style {
                            endian: state.file.endian,
                        },
                        0,
                    )
                    .await;
                    let mut node = node;
                    node.value = shown.value;
                    node.summary = shown.summary;
                    node.diagnostics = shown.diagnostics;
                    node
                }
            }
            b'L' => node.summary(format!(
                "list, {}",
                grouped_count(vseg.len() / 4, "child", "children")
            )),
            b'H' => node.summary("hash table"),
            k => node
                .summary(type_name(k))
                .diag(Diagnostic::warning(format!("unknown item type {k:#04x}"))),
        }
    };
    node.lazy(
        crate::expander!(self::item_children: ItemState),
        ItemState {
            table: state.clone(),
            index,
        },
    )
}

fn variant_ty() -> Ty {
    Ty::variant()
}

async fn item_children(cx: Cx, state: ItemState) -> Result<()> {
    let file = &state.table.file;
    let table = load_table(&cx, file, state.table.seg).await?;
    let Some(item) = usize::try_from(state.index)
        .ok()
        .and_then(|i| table.items.get(i))
        .copied()
    else {
        return Ok(());
    };
    let mut r = ByteReader::new(&cx, file.input.span);
    let item_span = r.span(
        table
            .items_at
            .saturating_add(state.index.saturating_mul(ITEM_SIZE)),
        ITEM_SIZE,
    );
    cx.emit(ItemRecord::node("Item", item_span, file.endian));
    let key_span = r.span(u64::from(item.key_start), u64::from(item.key_size));
    let key = own_key(&mut r, &item).await?;
    let mut key_node = Node::new("Key").span(key_span).value(Value::Text(key));
    if item.parent != NO_PARENT {
        let parent = full_key(&mut r, &table, u64::from(item.parent)).await?;
        key_node = key_node.summary(format!("under {parent}"));
    }
    cx.emit(key_node);
    let vseg = value_seg(&item);
    if vseg.start > vseg.end || vseg.end > file.input.span.len {
        return Ok(());
    }
    let style = Style {
        endian: file.endian,
    };
    match item.kind {
        b'v' => {
            if file.kind == Kind::Resource
                && let Some(res) = resource(&mut r, vseg, file.endian).await?
            {
                cx.emit(
                    Node::new("Size")
                        .span(r.span(res.size_seg.start, 4))
                        .value(val::uint(res.size, 32))
                        .desc("Uncompressed size"),
                );
                cx.emit(
                    Node::new("Flags")
                        .span(r.span(res.flags_seg.start, 4))
                        .value(flags_value(res.flags)),
                );
                let data = r.span(res.data.start, res.data.len());
                let node = if res.flags & 1 != 0 {
                    content("Data", file.input, data, Codec::Zlib, Some(res.size))
                } else if res.data.len() == res.size.saturating_add(1)
                    && r.byte(res.data.start.saturating_add(res.size)).await? == 0
                {
                    // glib-compile-resources ends uncompressed data with a
                    // NUL the size leaves out, so text works as a C string.
                    cx.emit(embedded(
                        "Data",
                        file.input.nested(r.span(res.data.start, res.size)),
                    ));
                    Node::new("Terminator")
                        .span(r.span(res.data.start.saturating_add(res.size), 1))
                        .desc("NUL after the data, not counted in its size")
                } else {
                    let node = embedded("Data", file.input.nested(data));
                    if res.data.len() != res.size {
                        node.diag(Diagnostic::warning(format!(
                            "{} bytes stored, size says {}",
                            res.data.len(),
                            res.size
                        )))
                    } else {
                        node
                    }
                };
                cx.emit(node);
            } else {
                cx.emit(gv::node(&mut r, "Value".to_owned(), vseg, &variant_ty(), style, 0).await);
            }
        }
        b'L' => {
            let count = vseg.len() / 4;
            let node = Node::new("Children")
                .span(r.span(vseg.start, vseg.len()))
                .summary(grouped_count(count, "child", "children"));
            let node = if count > 0 {
                node.lazy(crate::expander!(self::list: ItemState), state.clone())
            } else {
                node
            };
            cx.emit(if !vseg.len().is_multiple_of(4) {
                node.diag(Diagnostic::warning("list size is not a multiple of 4"))
            } else {
                node
            });
        }
        b'H' => {
            let node = Node::new("Table").span(r.span(vseg.start, vseg.len()));
            if state.table.nesting >= MAX_NESTING {
                cx.emit(node.diag(Diagnostic::limit(format!(
                    "hash tables nested deeper than {MAX_NESTING}"
                ))));
            } else if vseg.start <= state.table.seg.start && vseg.end >= state.table.seg.end {
                cx.emit(node.diag(Diagnostic::malformed("nested table contains its parent")));
            } else {
                cx.emit(node.lazy(
                    crate::expander!(self::table_children: TableState),
                    TableState {
                        file: file.clone(),
                        seg: vseg,
                        nesting: state.table.nesting.saturating_add(1),
                    },
                ));
            }
        }
        _ => cx.emit(Node::new("Value").span(r.span(vseg.start, vseg.len()))),
    }
    Ok(())
}

/// The children of an `L` item: indices of items in the same table.
async fn list(cx: Cx, state: ItemState) -> Result<()> {
    let file = &state.table.file;
    let table = load_table(&cx, file, state.table.seg).await?;
    let Some(item) = usize::try_from(state.index)
        .ok()
        .and_then(|i| table.items.get(i))
        .copied()
    else {
        return Ok(());
    };
    let vseg = value_seg(&item);
    let count = vseg.len() / 4;
    cx.set_count(Count::Exact(count));
    let mut r = ByteReader::new(&cx, file.input.span);
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        let at = i;
        cx.mark(move || at);
        let pos = vseg.start.saturating_add(i.saturating_mul(4));
        let child = read_u(&r.bytes(pos, 4).await?, file.endian);
        let mut node = Node::new(format!("[{i}]"))
            .span(r.span(pos, 4))
            .value(val::uint(child, 32));
        node = if usize::try_from(child)
            .ok()
            .is_some_and(|c| c < table.items.len())
        {
            node.summary(full_key(&mut r, &table, child).await?)
        } else {
            node.diag(Diagnostic::malformed(format!(
                "no item {child} in the table"
            )))
        };
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}
