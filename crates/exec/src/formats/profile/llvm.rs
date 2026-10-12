//! LLVM instrumentation profiles (`-fprofile-instr-generate`,
//! `-fprofile-generate`): the raw profile a program writes when it exits
//! (`.profraw`) and the indexed profile `llvm-profdata merge` builds from
//! raw ones (`.profdata`).
//!
//! A raw profile is a header of 64-bit fields followed by the sections the
//! runtime copied out of the process: binary IDs, per-function data records,
//! counters, MC/DC bitmaps, the (usually zlib-compressed) function names,
//! virtual table records and value-profile data. Data records name their
//! function by the MD5 of its name, so the names section is hashed to label
//! them. Layouts follow `InstrProfData.inc` for raw versions 5 to 10 (LLVM
//! 11 to 19 and later).
//!
//! An indexed profile is a little-endian header, a profile summary, an
//! on-disk chained hash table from function name to its records (hash,
//! counters, bitmap bytes, value-profile data), then optional MemProf,
//! binary-ID, temporal-trace and virtual-table-name sections located by
//! header offsets (indexed versions up to 12).

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::codec::crypto::hash::{Hash, Md5};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::binutil::{Reader, data_node, get, hex_string};
use crate::formats::util::fmt::{count, plural};
use crate::formats::util::lines::flags;
use crate::formats::util::val::{hex, int, text, uint};
use crate::formats::{Codec, Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const RAW64: u64 = 0xff6c_7072_6f66_7281;
const RAW32: u64 = 0xff6c_7072_6f66_5281;
const INDEXED: u64 = 0x8169_666f_7270_6cff;

pub static PROFRAW: Format = Format {
    name: "profraw",
    title: "LLVM raw instrumentation profile",
    extensions: &["profraw"],
    mime: "application/x-llvm-profraw",
    probe: Probe::Custom(probe_raw),
    dissect: crate::expander!(profraw: Input),
};

pub static PROFDATA: Format = Format {
    name: "profdata",
    title: "LLVM indexed instrumentation profile",
    extensions: &["profdata"],
    mime: "application/x-llvm-profdata",
    probe: Probe::Custom(probe_indexed),
    dissect: crate::expander!(profdata: Input),
};

/// The variant bits in the high half of the version word.
const VARIANTS: FlagTable = &[
    flag(1 << 56, "IR_PROF"),
    flag(1 << 57, "CSIR_PROF"),
    flag(1 << 58, "INSTR_ENTRY"),
    flag(1 << 59, "DBG_CORRELATE"),
    flag(1 << 60, "BYTE_COVERAGE"),
    flag(1 << 61, "FUNCTION_ENTRY_ONLY"),
    flag(1 << 62, "MEMPROF"),
    flag(1 << 63, "TEMPORAL_PROF"),
];

const BYTE_COVERAGE: u64 = 1 << 60;
const CSIR: u64 = 1 << 57;

/// Highest version of each kind whose layout is known.
const RAW_MAX: u32 = 10;
const INDEXED_MAX: u32 = 12;

fn raw_kind(h: &[u8]) -> Option<(Endian, bool)> {
    for endian in [Endian::Little, Endian::Big] {
        match get::<u64>(h, 0, endian)? {
            RAW64 => return Some((endian, true)),
            RAW32 => return Some((endian, false)),
            _ => {}
        }
    }
    None
}

fn probe_raw(h: &Head) -> bool {
    raw_kind(h.data).is_some_and(|(endian, _)| {
        get::<u64>(h.data, 8, endian).is_some_and(|v| (1..=64).contains(&(v & 0xffff_ffff)))
    })
}

fn probe_indexed(h: &Head) -> bool {
    get::<u64>(h.data, 0, Endian::Little) == Some(INDEXED)
        && get::<u64>(h.data, 8, Endian::Little)
            .is_some_and(|v| (1..=64).contains(&(v & 0xffff_ffff)))
}

fn variant_summary(version: u64) -> String {
    let kind = if version & (1 << 56) != 0 {
        if version & CSIR != 0 {
            "context-sensitive IR instrumentation"
        } else {
            "IR instrumentation"
        }
    } else {
        "front-end instrumentation"
    };
    let mut s = kind.to_owned();
    if version & BYTE_COVERAGE != 0 {
        s.push_str(", byte coverage");
    }
    if version & (1 << 61) != 0 {
        s.push_str(", entry counts only");
    }
    if version & (1 << 63) != 0 {
        s.push_str(", temporal");
    }
    s
}

fn version_node(span: Span, version: u64) -> Node {
    Node::new("Version")
        .span(span)
        .value(hex(version, 64))
        .summary(format!(
            "version {}, {}",
            version & 0xffff_ffff,
            variant_summary(version)
        ))
}

/// The bytes needed to pad `n` to a multiple of 8.
fn pad8(n: u64) -> u64 {
    n.checked_next_multiple_of(8).unwrap_or(n).saturating_sub(n)
}

// ---------------------------------------------------------------------------
// Function names

/// The names in a names blob (groups of `uleb128 length`, `uleb128
/// compressed length`, then the names separated by 0x01, zlib-compressed
/// when the second length is not zero), with their spans and a map from
/// the MD5-based name reference to the name's index.
struct Names {
    names: Vec<(String, Span)>,
    by_ref: BTreeMap<u64, usize>,
    errors: Vec<Diagnostic>,
}

async fn names(cx: &Cx, blob: Span) -> Arc<Names> {
    if let Some(found) = cx.cached::<Names>(blob, "llvm-prof-names") {
        return found;
    }
    let mut out = Names {
        names: Vec::new(),
        by_ref: BTreeMap::new(),
        errors: Vec::new(),
    };
    let mut pos = 0u64;
    while pos < blob.len {
        let Ok(head) = cx.read_avail(blob.sub(pos, 20)).await else {
            break;
        };
        let mut r = Reader::new(&head);
        let (Some(ulen), Some(clen)) = (r.uleb(), r.uleb()) else {
            break;
        };
        let start = pos.saturating_add(to_u64(r.pos()));
        if ulen == 0 && clen == 0 {
            // Padding inside the section.
            pos = start;
            continue;
        }
        let (span, next) = if clen == 0 {
            (blob.sub(start, ulen), start.saturating_add(ulen))
        } else {
            match crate::codec::decode_span(cx, blob.sub(start, clen), &Codec::Zlib, Some(ulen))
                .await
            {
                Ok(d) => {
                    if let Some(e) = d.error {
                        out.errors.push(e);
                    }
                    (d.span, start.saturating_add(clen))
                }
                Err(e) => {
                    out.errors.push(e);
                    break;
                }
            }
        };
        let Ok(bytes) = cx.read(span).await else {
            break;
        };
        let mut from = 0usize;
        for (i, piece) in bytes.split(|&b| b == 1).enumerate() {
            if i % 64 == 63 {
                cx.checkpoint().await;
            }
            let name = String::from_utf8_lossy(piece).into_owned();
            let digest = Md5::digest(piece);
            let key = get::<u64>(&digest, 0, Endian::Little).unwrap_or(0);
            out.by_ref.entry(key).or_insert(out.names.len());
            out.names
                .push((name, span.sub(to_u64(from), to_u64(piece.len()))));
            from = from.saturating_add(piece.len()).saturating_add(1);
        }
        pos = next;
    }
    let out = Arc::new(out);
    cx.cache(blob, "llvm-prof-names", out.clone());
    out
}

async fn names_node(cx: Cx, blob: Span) -> Result<()> {
    let names = names(&cx, blob).await;
    for e in &names.errors {
        cx.diag(e.clone());
    }
    for (i, (name, span)) in names.names.iter().enumerate() {
        cx.push(
            Node::new(format!("[{i}]"))
                .span(*span)
                .value(text(name.clone())),
        )
        .await;
    }
    Ok(())
}

/// Binary IDs: `u64 length`, the ID, padding to 8; repeated.
async fn binary_ids(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let mut pos = 0u64;
    let mut i = 0u64;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 8)).await?;
        let Some(len) = get::<u64>(&head, 0, endian) else {
            cx.emit(data_node(
                "Trailing bytes",
                span.tail(pos),
                span.len.saturating_sub(pos),
            ));
            break;
        };
        let id = span.sub(pos.saturating_add(8), len.min(256));
        let bytes = cx.read(id).await?;
        let total = 8u64.saturating_add(len).saturating_add(pad8(len));
        cx.push(
            Node::new(format!("Binary ID {i}"))
                .span(span.sub(pos, total))
                .value(text(hex_string(&bytes)))
                .summary(format!("{} bytes", len)),
        )
        .await;
        pos = pos.saturating_add(total);
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Raw profiles

#[derive(Clone, Debug)]
struct Raw {
    endian: Endian,
    ptr64: bool,
    version: u32,
    variant: u64,
    file: Span,
    /// `(name, span)` of each header field.
    header: Vec<(&'static str, u64)>,
    binary_ids: Span,
    data: Span,
    data_count: u64,
    record_size: u64,
    counters: Span,
    counter_size: u64,
    counters_delta: u64,
    bitmap: Span,
    bitmap_delta: u64,
    names: Span,
    vtables: Span,
    vtable_count: u64,
    vnames: Span,
    values: Span,
    value_kinds: u64,
}

impl Raw {
    fn field(&self, name: &str) -> u64 {
        self.header
            .iter()
            .find(|(n, _)| *n == name)
            .map_or(0, |(_, v)| *v)
    }
    fn ptr(&self) -> u64 {
        if self.ptr64 { 8 } else { 4 }
    }
}

fn raw_fields(version: u32) -> Vec<&'static str> {
    let mut f = vec!["Magic", "Version"];
    if version >= 6 {
        f.push("Binary IDs size");
    }
    f.extend([
        "Data records",
        "Padding before counters",
        "Counters",
        "Padding after counters",
    ]);
    if version >= 9 {
        f.extend(["Bitmap bytes", "Padding after bitmap"]);
    }
    f.extend(["Names size", "Counters delta"]);
    if version >= 9 {
        f.push("Bitmap delta");
    }
    f.push("Names delta");
    if version >= 10 {
        f.extend(["Virtual tables", "Virtual table names size"]);
    }
    f.push("Value kind last");
    f
}

fn parse_raw(head: &[u8], file: Span) -> Result<Raw> {
    let (endian, ptr64) =
        raw_kind(head).ok_or_else(|| Diagnostic::malformed("not a raw profile"))?;
    let word = get::<u64>(head, 8, endian).unwrap_or(0);
    let version = u32::try_from(word & 0xffff_ffff).unwrap_or(0);
    let names = raw_fields(version);
    let mut header = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let v = get::<u64>(head, i.saturating_mul(8), endian).ok_or_else(|| {
            Diagnostic::truncated(
                file.sub(0, to_u64(names.len()).saturating_mul(8)),
                to_u64(head.len()),
            )
        })?;
        header.push((*name, v));
    }
    let mut raw = Raw {
        endian,
        ptr64,
        version,
        variant: word & 0xffff_ffff_0000_0000,
        file,
        header,
        binary_ids: Span::zeros(0),
        data: Span::zeros(0),
        data_count: 0,
        record_size: 0,
        counters: Span::zeros(0),
        counter_size: if word & BYTE_COVERAGE != 0 { 1 } else { 8 },
        counters_delta: 0,
        bitmap: Span::zeros(0),
        bitmap_delta: 0,
        names: Span::zeros(0),
        vtables: Span::zeros(0),
        vtable_count: 0,
        vnames: Span::zeros(0),
        values: Span::zeros(0),
        value_kinds: 0,
    };
    raw.value_kinds = raw.field("Value kind last").saturating_add(1).min(16);
    // NameRef, FuncHash, CounterPtr, [BitmapPtr], FunctionPointer, Values,
    // NumCounters, NumValueSites[kinds], [NumBitmapBytes]; 8-aligned.
    let ptrs = if version >= 9 { 4 } else { 3 };
    let mut size = 16u64
        .saturating_add(raw.ptr().saturating_mul(ptrs))
        .saturating_add(4)
        .saturating_add(raw.value_kinds.saturating_mul(2));
    if version >= 9 {
        size = size.next_multiple_of(4).saturating_add(4);
    }
    raw.record_size = size.saturating_add(pad8(size));
    raw.counters_delta = raw.field("Counters delta");
    raw.bitmap_delta = raw.field("Bitmap delta");
    raw.data_count = raw.field("Data records");
    raw.vtable_count = raw.field("Virtual tables");

    let mut pos = to_u64(names.len()).saturating_mul(8);
    let mut take = |len: u64| {
        let span = file.sub(pos, len);
        pos = pos.saturating_add(len);
        span
    };
    raw.binary_ids = take(raw.field("Binary IDs size"));
    raw.data = take(raw.data_count.saturating_mul(raw.record_size));
    take(raw.field("Padding before counters"));
    raw.counters = take(raw.field("Counters").saturating_mul(raw.counter_size));
    take(raw.field("Padding after counters"));
    raw.bitmap = take(raw.field("Bitmap bytes"));
    take(raw.field("Padding after bitmap"));
    let names_size = raw.field("Names size");
    raw.names = take(names_size);
    take(pad8(names_size));
    let vt_size = 8u64.saturating_add(raw.ptr()).saturating_add(4);
    raw.vtables = take(
        raw.vtable_count
            .saturating_mul(vt_size.saturating_add(pad8(vt_size))),
    );
    let vnames_size = raw.field("Virtual table names size");
    raw.vnames = take(vnames_size);
    take(pad8(vnames_size));
    raw.values = file.tail(pos);
    Ok(raw)
}

async fn profraw(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 256)).await?;
    let raw = parse_raw(&head, file)?;
    let raw = Arc::new(raw);
    let header_len = to_u64(raw.header.len()).saturating_mul(8);
    cx.annotate(format!(
        "LLVM raw profile version {} ({}, {}-bit, {}-endian), {}, {}",
        raw.version,
        variant_summary(raw.variant),
        if raw.ptr64 { 64 } else { 32 },
        if raw.endian == Endian::Little {
            "little"
        } else {
            "big"
        },
        plural(raw.data_count, "function"),
        plural(raw.field("Counters"), "counter"),
    ));
    let mut header = Node::new("Header")
        .span(file.sub(0, header_len))
        .lazy(raw_header, raw.clone());
    if !(5..=RAW_MAX).contains(&raw.version) {
        header = header.diag(Diagnostic::unsupported(format!(
            "raw profile version {} (layouts known for 5 to {RAW_MAX})",
            raw.version
        )));
    }
    cx.emit(header);
    if raw.binary_ids.len > 0 {
        cx.emit(
            Node::new("Binary IDs")
                .span(raw.binary_ids)
                .lazy(binary_ids, (raw.binary_ids, raw.endian)),
        );
    }
    cx.emit(
        Node::new("Data")
            .span(raw.data)
            .summary(plural(raw.data_count, "record"))
            .lazy(raw_records, raw.clone()),
    );
    cx.emit(
        Node::new("Counters")
            .span(raw.counters)
            .summary(plural(raw.field("Counters"), "counter"))
            .lazy(raw_counters, (raw.clone(), raw.counters)),
    );
    if raw.bitmap.len > 0 {
        cx.emit(data_node("Bitmap", raw.bitmap, raw.field("Bitmap bytes")));
    }
    let names_size = raw.field("Names size");
    let mut names = Node::new("Names").span(raw.names);
    if raw.names.len < names_size {
        names = names.diag(Diagnostic::truncated(
            Span::new(raw.names.source, raw.names.offset, names_size),
            raw.names.len,
        ));
    }
    cx.emit(names.lazy(names_node, raw.names));
    if raw.vtables.len > 0 {
        cx.emit(
            Node::new("Virtual tables")
                .span(raw.vtables)
                .summary(plural(raw.vtable_count, "record"))
                .lazy(raw_vtables, raw.clone()),
        );
    }
    if raw.vnames.len > 0 {
        cx.emit(
            Node::new("Virtual table names")
                .span(raw.vnames)
                .lazy(names_node, raw.vnames),
        );
    }
    if raw.values.len > 0 {
        cx.emit(data_node("Value profile data", raw.values, raw.values.len));
    }
    Ok(())
}

async fn raw_header(cx: Cx, raw: Arc<Raw>) -> Result<()> {
    for (i, (name, v)) in raw.header.iter().enumerate() {
        let span = raw.file.sub(to_u64(i).saturating_mul(8), 8);
        let node = match *name {
            "Magic" => Node::new("Magic")
                .span(span)
                .value(hex(*v, 64))
                .summary(if raw.ptr64 {
                    "\\xffprofr\\x81 (64-bit)"
                } else {
                    "\\xffprofR\\x81 (32-bit)"
                }),
            "Version" => version_node(span, *v).lazy(variants, *v),
            "Counters delta" | "Bitmap delta" | "Names delta" => Node::new(*name)
                .span(span)
                .value(int(i64::from_ne_bytes(v.to_ne_bytes()), 64))
                .desc(if raw.version >= 8 {
                    "Address of the section minus the address of the data records, in the process"
                } else {
                    "Address of the section in the process"
                }),
            _ => Node::new(*name).span(span).value(uint(*v, 64)),
        };
        cx.emit(node);
    }
    Ok(())
}

async fn variants(cx: Cx, v: u64) -> Result<()> {
    cx.emit(Node::new("Number").value(uint(v & 0xffff_ffff, 32)));
    cx.emit(Node::new("Variant").value(flags(VARIANTS, v & 0xffff_ffff_0000_0000, 64)));
    Ok(())
}

/// One decoded data record.
struct Record {
    name_ref: u64,
    hash: u64,
    counter_ptr: u64,
    counters: u64,
}

fn read_record(raw: &Raw, data: &[u8]) -> Option<Record> {
    let mut r = Reader::new(data);
    let e = raw.endian;
    let name_ref = r.int::<u64>(e)?;
    let hash = r.int::<u64>(e)?;
    let counter_ptr = if raw.ptr64 {
        r.int::<u64>(e)?
    } else {
        // Sign-extend: relative pointers are negative.
        let v = r.int::<u32>(e)?;
        u64::from_ne_bytes(i64::from(i32::from_ne_bytes(v.to_ne_bytes())).to_ne_bytes())
    };
    let skip = raw
        .ptr()
        .saturating_mul(if raw.version >= 9 { 3 } else { 2 });
    r.bytes(to_usize(skip))?;
    let counters = u64::from(r.int::<u32>(e)?);
    Some(Record {
        name_ref,
        hash,
        counter_ptr,
        counters,
    })
}

impl Raw {
    /// The counters of data record `index`, as a span of the counters
    /// section.
    fn counters_of(&self, index: u64, rec: &Record) -> Option<Span> {
        let delta = if self.version >= 8 {
            self.counters_delta
                .wrapping_sub(index.wrapping_mul(self.record_size))
        } else {
            self.counters_delta
        };
        let offset = rec.counter_ptr.wrapping_sub(delta);
        let len = rec.counters.checked_mul(self.counter_size)?;
        (offset.checked_add(len)? <= self.counters.len).then(|| self.counters.sub(offset, len))
    }
}

async fn raw_records(cx: Cx, raw: Arc<Raw>) -> Result<()> {
    let names = names(&cx, raw.names).await;
    let mut index = cx.resume::<u64>().unwrap_or(0);
    while index < raw.data_count {
        let at = index;
        cx.mark(move || at);
        let span = raw
            .data
            .sub(index.saturating_mul(raw.record_size), raw.record_size);
        if span.len < raw.record_size {
            cx.push(data_node(format!("Record {index}"), span, raw.record_size))
                .await;
            break;
        }
        let data = cx.read(span).await?;
        let Some(rec) = read_record(&raw, &data) else {
            break;
        };
        let name = names
            .by_ref
            .get(&rec.name_ref)
            .and_then(|&i| names.names.get(i))
            .map_or_else(|| format!("{:#018x}", rec.name_ref), |(n, _)| n.clone());
        let mut node = Node::new(name).span(span).summary(format!(
            "{}, hash {:#x}",
            plural(rec.counters, "counter"),
            rec.hash
        ));
        if raw.counters_of(index, &rec).is_none() && rec.counters > 0 {
            node = node.diag(Diagnostic::malformed(
                "counters lie outside the counters section",
            ));
        }
        cx.push(node.lazy(raw_record, (raw.clone(), index))).await;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn raw_record(cx: Cx, (raw, index): (Arc<Raw>, u64)) -> Result<()> {
    let span = raw
        .data
        .sub(index.saturating_mul(raw.record_size), raw.record_size);
    let data = cx.read(span).await?;
    let names = names(&cx, raw.names).await;
    let e = raw.endian;
    let ptr = raw.ptr();
    let mut r = Reader::new(&data);
    let mut pos = 0u64;
    let mut field = |r: &Reader| {
        let s = span.sub(pos, to_u64(r.pos()).saturating_sub(pos));
        pos = to_u64(r.pos());
        s
    };
    let read_ptr = |r: &mut Reader| {
        if ptr == 8 {
            r.int::<u64>(e)
        } else {
            r.int::<u32>(e).map(u64::from)
        }
    };
    if let Some(v) = r.int::<u64>(e) {
        let mut node = Node::new("Name reference")
            .span(field(&r))
            .value(hex(v, 64));
        if let Some((name, at)) = names.by_ref.get(&v).and_then(|&i| names.names.get(i)) {
            node = node.summary(format!("MD5 of {name}")).target(*at);
        }
        cx.emit(node);
    }
    if let Some(v) = r.int::<u64>(e) {
        cx.emit(Node::new("Function hash").span(field(&r)).value(hex(v, 64)));
    }
    let mut ptrs = vec!["Counter pointer"];
    if raw.version >= 9 {
        ptrs.push("Bitmap pointer");
    }
    ptrs.extend(["Function pointer", "Values pointer"]);
    for name in ptrs {
        let Some(v) = read_ptr(&mut r) else { break };
        let node = Node::new(name).span(field(&r));
        cx.emit(
            if raw.version >= 8 && name != "Function pointer" && name != "Values pointer" {
                node.value(int(
                    if ptr == 8 {
                        i64::from_ne_bytes(v.to_ne_bytes())
                    } else {
                        i64::from(i32::from_ne_bytes(
                            u32::try_from(v).unwrap_or(0).to_ne_bytes(),
                        ))
                    },
                    if ptr == 8 { 64 } else { 32 },
                ))
                .desc("Relative to this record, in the process")
            } else {
                node.value(hex(v, if ptr == 8 { 64 } else { 32 }))
            },
        );
    }
    if let Some(v) = r.int::<u32>(e) {
        cx.emit(Node::new("Counters").span(field(&r)).value(uint(v, 32)));
    }
    for kind in 0..raw.value_kinds {
        let Some(v) = r.int::<u16>(e) else { break };
        let name = match kind {
            0 => "Indirect call sites",
            1 => "Memory operation size sites",
            2 => "Virtual table sites",
            _ => "Value sites",
        };
        cx.emit(Node::new(name).span(field(&r)).value(uint(v, 16)));
    }
    if raw.version >= 9 {
        let align = r.pos().next_multiple_of(4).saturating_sub(r.pos());
        r.bytes(align);
        field(&r);
        if let Some(v) = r.int::<u32>(e) {
            cx.emit(Node::new("Bitmap bytes").span(field(&r)).value(uint(v, 32)));
        }
    }
    if let Some(rec) = read_record(&raw, &data)
        && let Some(counters) = raw.counters_of(index, &rec)
    {
        cx.emit(
            Node::new("Counter values")
                .span(counters)
                .lazy(raw_counters, (raw.clone(), counters)),
        );
    }
    Ok(())
}

async fn raw_counters(cx: Cx, (raw, span): (Arc<Raw>, Span)) -> Result<()> {
    let base = span
        .offset
        .saturating_sub(raw.counters.offset)
        .checked_div(raw.counter_size)
        .unwrap_or(0);
    let mut i = cx.resume::<u64>().unwrap_or(0);
    let total = span.len.checked_div(raw.counter_size).unwrap_or(0);
    while i < total {
        let at = i;
        cx.mark(move || at);
        let before = i;
        let chunk = total.saturating_sub(i).min(512);
        let bytes = cx
            .read(span.sub(
                i.saturating_mul(raw.counter_size),
                chunk.saturating_mul(raw.counter_size),
            ))
            .await?;
        let mut r = Reader::new(&bytes);
        for _ in 0..chunk {
            let (v, node_span) = if raw.counter_size == 1 {
                let Some(b) = r.u8() else { break };
                (u64::from(b), span.sub(i, 1))
            } else {
                let Some(v) = r.int::<u64>(raw.endian) else {
                    break;
                };
                (v, span.sub(i.saturating_mul(8), 8))
            };
            let mut node = Node::new(format!("[{}]", base.saturating_add(i)))
                .span(node_span)
                .value(uint(v, if raw.counter_size == 1 { 8 } else { 64 }));
            if raw.counter_size == 1 {
                node = node.summary(if v == 0 { "covered" } else { "not covered" });
            }
            cx.push(node).await;
            i = i.saturating_add(1);
        }
        if i == before {
            break;
        }
    }
    Ok(())
}

async fn raw_vtables(cx: Cx, raw: Arc<Raw>) -> Result<()> {
    let names = names(&cx, raw.vnames).await;
    let size = raw.vtables.len.checked_div(raw.vtable_count).unwrap_or(0);
    let mut i = 0u64;
    while i < raw.vtable_count {
        let span = raw.vtables.sub(i.saturating_mul(size), size);
        let data = cx.read(span).await?;
        let mut r = Reader::new(&data);
        let hash = r.int::<u64>(raw.endian).unwrap_or(0);
        let name = names
            .by_ref
            .get(&hash)
            .and_then(|&n| names.names.get(n))
            .map_or_else(|| format!("{hash:#018x}"), |(n, _)| n.clone());
        cx.push(Node::new(name).span(span)).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Indexed profiles

#[derive(Clone, Debug)]
struct Indexed {
    version: u32,
    variant: u64,
    file: Span,
    header: Vec<(&'static str, u64)>,
    /// Where the hash table's payload (the records) starts.
    payload: u64,
}

impl Indexed {
    fn field(&self, name: &str) -> u64 {
        self.header
            .iter()
            .find(|(n, _)| *n == name)
            .map_or(0, |(_, v)| *v)
    }
}

fn indexed_fields(version: u32) -> Vec<&'static str> {
    let mut f = vec![
        "Magic",
        "Version",
        "Unused",
        "Hash type",
        "Hash table offset",
    ];
    if version >= 8 {
        f.push("MemProf offset");
    }
    if version >= 9 {
        f.push("Binary IDs offset");
    }
    if version >= 10 {
        f.push("Temporal traces offset");
    }
    if version >= 12 {
        f.push("Virtual table names offset");
    }
    f
}

const SUMMARY_FIELDS: &[&str] = &[
    "Functions",
    "Blocks",
    "Largest function count",
    "Largest block count",
    "Largest internal block count",
    "Total block count",
];

/// A summary's length at `pos`: two counts, the fields and the cutoffs.
fn summary_len(data: &[u8], pos: u64) -> Option<u64> {
    let fields = get::<u64>(data, to_usize(pos), Endian::Little)?;
    let entries = get::<u64>(data, to_usize(pos.checked_add(8)?), Endian::Little)?;
    16u64
        .checked_add(fields.checked_mul(8)?)?
        .checked_add(entries.checked_mul(24)?)
}

async fn profdata(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 128)).await?;
    let word = get::<u64>(&head, 8, Endian::Little).unwrap_or(0);
    let version = u32::try_from(word & 0xffff_ffff).unwrap_or(0);
    let names = indexed_fields(version);
    let mut header = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let v = get::<u64>(&head, i.saturating_mul(8), Endian::Little).ok_or_else(|| {
            Diagnostic::truncated(
                file.sub(0, to_u64(names.len()).saturating_mul(8)),
                to_u64(head.len()),
            )
        })?;
        header.push((*name, v));
    }
    let header_len = to_u64(names.len()).saturating_mul(8);
    let mut idx = Indexed {
        version,
        variant: word & 0xffff_ffff_0000_0000,
        file,
        header,
        payload: header_len,
    };
    let hash_offset = idx.field("Hash table offset");
    let table = cx.read_avail(file.sub(hash_offset, 16)).await?;
    let entries = get::<u64>(&table, 8, Endian::Little);
    cx.annotate(format!(
        "LLVM indexed profile version {version} ({}){}",
        variant_summary(idx.variant),
        entries.map_or_else(String::new, |n| format!(", {}", plural(n, "function")))
    ));
    let mut hnode = Node::new("Header")
        .span(file.sub(0, header_len))
        .lazy(indexed_header, Arc::new(idx.clone()));
    if !(3..=INDEXED_MAX).contains(&version) {
        hnode = hnode.diag(Diagnostic::unsupported(format!(
            "indexed profile version {version} (layouts known up to {INDEXED_MAX})"
        )));
    }
    cx.emit(hnode);

    // Summaries (version 4 on): the profile's, then a context-sensitive one.
    if version >= 4 {
        let mut pos = header_len;
        let count = if word & CSIR != 0 { 2 } else { 1 };
        for n in 0..count {
            let data = cx.read_avail(file.sub(pos, 16)).await?;
            let Some(len) = summary_len(&data, 0) else {
                cx.emit(data_node("Summary", file.sub(pos, 16), 16));
                break;
            };
            let span = file.sub(pos, len);
            let mut node = Node::new(if n == 0 {
                "Summary"
            } else {
                "Context-sensitive summary"
            })
            .span(span);
            if span.len < len {
                node = node.diag(Diagnostic::truncated(
                    Span::new(span.source, span.offset, len),
                    span.len,
                ));
            }
            cx.emit(node.lazy(summary, span));
            pos = pos.saturating_add(len);
        }
        idx.payload = pos;
    }
    let idx = Arc::new(idx);
    let payload = file.sub(idx.payload, hash_offset.saturating_sub(idx.payload));
    cx.emit(
        Node::new("Functions")
            .span(payload)
            .summary(entries.map_or_else(String::new, |n| count(n, "entry", "entries")))
            .lazy(functions, idx.clone()),
    );
    let buckets = get::<u64>(&table, 0, Endian::Little).unwrap_or(0);
    let table_len = 16u64.saturating_add(buckets.saturating_mul(8));
    cx.emit(
        Node::new("Hash table")
            .span(file.sub(hash_offset, table_len))
            .summary(format!(
                "{}, {}",
                plural(buckets, "bucket"),
                count(entries.unwrap_or(0), "entry", "entries")
            ))
            .lazy(hash_table, idx.clone()),
    );

    // Sections located by header offsets, each up to the next one.
    let mut sections: Vec<(&'static str, u64)> = [
        ("MemProf", idx.field("MemProf offset")),
        ("Binary IDs", idx.field("Binary IDs offset")),
        (
            "Temporal profile traces",
            idx.field("Temporal traces offset"),
        ),
        (
            "Virtual table names",
            idx.field("Virtual table names offset"),
        ),
    ]
    .into_iter()
    .filter(|(_, off)| *off != 0)
    .collect();
    sections.sort_by_key(|(_, off)| *off);
    for (i, (name, off)) in sections.iter().enumerate() {
        let end = sections
            .get(i.saturating_add(1))
            .map_or(file.len, |(_, o)| *o);
        let span = file.sub(*off, end.saturating_sub(*off));
        let node = match *name {
            "Binary IDs" => {
                let data = cx.read_avail(span.sub(0, 8)).await?;
                let size = get::<u64>(&data, 0, Endian::Little).unwrap_or(0);
                Node::new(*name)
                    .span(span.sub(0, size.saturating_add(8)))
                    .lazy(binary_ids, (span.sub(8, size), Endian::Little))
            }
            "Virtual table names" => {
                let data = cx.read_avail(span.sub(0, 8)).await?;
                let size = get::<u64>(&data, 0, Endian::Little).unwrap_or(0);
                Node::new(*name)
                    .span(span.sub(0, size.saturating_add(8).saturating_add(pad8(size))))
                    .summary(format!("{size} bytes"))
                    .lazy(names_node, span.sub(8, size))
            }
            _ => data_node(*name, span, span.len),
        };
        cx.emit(node);
    }
    Ok(())
}

async fn indexed_header(cx: Cx, idx: Arc<Indexed>) -> Result<()> {
    for (i, (name, v)) in idx.header.iter().enumerate() {
        let span = idx.file.sub(to_u64(i).saturating_mul(8), 8);
        let node = match *name {
            "Magic" => Node::new("Magic")
                .span(span)
                .value(hex(*v, 64))
                .summary("\\xfflprofi\\x81"),
            "Version" => version_node(span, *v).lazy(variants, *v),
            "Hash type" => Node::new(*name)
                .span(span)
                .value(uint(*v, 64))
                .summary(if *v == 0 { "MD5" } else { "unknown" }),
            "Unused" => Node::new(*name).span(span).value(uint(*v, 64)),
            _ => Node::new(*name).span(span).value(hex(*v, 64)),
        };
        cx.emit(node);
    }
    Ok(())
}

async fn summary(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader::new(&data);
    let mut pos = 0u64;
    let mut field = |r: &Reader| {
        let s = span.sub(pos, to_u64(r.pos()).saturating_sub(pos));
        pos = to_u64(r.pos());
        s
    };
    let fields = r.int::<u64>(Endian::Little).unwrap_or(0);
    cx.emit(Node::new("Fields").span(field(&r)).value(uint(fields, 64)));
    let entries = r.int::<u64>(Endian::Little).unwrap_or(0);
    cx.emit(
        Node::new("Cutoff entries")
            .span(field(&r))
            .value(uint(entries, 64)),
    );
    for i in 0..fields {
        let Some(v) = r.int::<u64>(Endian::Little) else {
            break;
        };
        let name = SUMMARY_FIELDS
            .get(to_usize(i))
            .map_or_else(|| format!("Field {i}"), |s| (*s).to_owned());
        cx.push(Node::new(name).span(field(&r)).value(uint(v, 64)))
            .await;
    }
    for _ in 0..entries {
        let (Some(cutoff), Some(min), Some(blocks)) = (
            r.int::<u64>(Endian::Little),
            r.int::<u64>(Endian::Little),
            r.int::<u64>(Endian::Little),
        ) else {
            break;
        };
        // Cutoffs are in millionths.
        let pct = format!("{}.{:04}", cutoff / 10_000, cutoff % 10_000);
        let pct = pct.trim_end_matches('0').trim_end_matches('.');
        cx.push(
            Node::new(format!("Cutoff {pct}%"))
                .span(field(&r))
                .value(uint(cutoff, 64))
                .summary(format!("minimum count {min}, {}", plural(blocks, "block"))),
        )
        .await;
    }
    Ok(())
}

/// Walks the hash table's payload: buckets of `u16 count` then items of
/// `u64 hash`, `u64 key length`, `u64 data length`, the key (the function
/// name) and the data (its records).
async fn functions(cx: Cx, idx: Arc<Indexed>) -> Result<()> {
    let file = idx.file;
    let end = idx.field("Hash table offset").min(file.len);
    let table = cx.read_avail(file.sub(end, 16)).await?;
    let entries = get::<u64>(&table, 8, Endian::Little).unwrap_or(u64::MAX);
    let (mut pos, mut left, mut done) =
        cx.resume::<(u64, u64, u64)>()
            .unwrap_or((idx.payload, 0, 0));
    while pos < end && done < entries {
        if left == 0 {
            let data = cx.read_avail(file.sub(pos, 2)).await?;
            let Some(n) = get::<u16>(&data, 0, Endian::Little) else {
                break;
            };
            left = u64::from(n);
            pos = pos.saturating_add(2);
            continue;
        }
        let at = (pos, left, done);
        cx.mark(move || at);
        let head = cx.read_avail(file.sub(pos, 24)).await?;
        let mut r = Reader::new(&head);
        let (Some(hash), Some(klen), Some(dlen)) = (
            r.int::<u64>(Endian::Little),
            r.int::<u64>(Endian::Little),
            r.int::<u64>(Endian::Little),
        ) else {
            cx.push(data_node("Truncated entry", file.sub(pos, 24), 24))
                .await;
            break;
        };
        let key = file.sub(pos.saturating_add(24), klen);
        let data = file.sub(
            key.offset.saturating_sub(file.offset).saturating_add(klen),
            dlen,
        );
        let total = 24u64.saturating_add(klen).saturating_add(dlen);
        let span = file.sub(pos, total);
        let name = cx.read(key.sub(0, 4096)).await?;
        let first = cx.read_avail(data.sub(0, 16)).await?;
        let mut node = Node::new(String::from_utf8_lossy(&name).into_owned()).span(span);
        if let (Some(h), Some(n)) = (
            get::<u64>(&first, 0, Endian::Little),
            get::<u64>(&first, 8, Endian::Little),
        ) {
            node = node.summary(format!("hash {h:#x}, {}", plural(n, "counter")));
        }
        if span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, total),
                span.len,
            ));
        }
        cx.push(node.lazy(function, (idx.version, span, hash, key, data)))
            .await;
        pos = pos.saturating_add(total);
        left = left.saturating_sub(1);
        done = done.saturating_add(1);
    }
    Ok(())
}

async fn function(
    cx: Cx,
    (version, span, hash, key, data): (u32, Span, u64, Span, Span),
) -> Result<()> {
    cx.emit(
        Node::new("Key hash")
            .span(span.sub(0, 8))
            .value(hex(hash, 64))
            .desc("MD5 of the function name (the hash table's key)"),
    );
    cx.emit(
        Node::new("Key length")
            .span(span.sub(8, 8))
            .value(uint(key.len, 64)),
    );
    cx.emit(
        Node::new("Data length")
            .span(span.sub(16, 8))
            .value(uint(data.len, 64)),
    );
    let name = cx.read(key.sub(0, 4096)).await?;
    cx.emit(
        Node::new("Name")
            .span(key)
            .value(text(String::from_utf8_lossy(&name).into_owned())),
    );
    // Records: one per distinct function hash with this name.
    let mut pos = 0u64;
    while pos < data.len {
        let head = cx.read_avail(data.sub(pos, 16)).await?;
        let (Some(h), Some(n)) = (
            get::<u64>(&head, 0, Endian::Little),
            get::<u64>(&head, 8, Endian::Little),
        ) else {
            cx.push(data_node(
                "Trailing bytes",
                data.tail(pos),
                data.len.saturating_sub(pos),
            ))
            .await;
            break;
        };
        let mut len = 16u64.saturating_add(n.saturating_mul(8));
        if version >= 11 {
            let b = cx.read_avail(data.sub(pos.saturating_add(len), 8)).await?;
            let bytes = get::<u64>(&b, 0, Endian::Little).unwrap_or(0);
            len = len
                .saturating_add(8)
                .saturating_add(bytes.saturating_mul(8));
        }
        if version >= 3 {
            let v = cx.read_avail(data.sub(pos.saturating_add(len), 4)).await?;
            let size = get::<u32>(&v, 0, Endian::Little).unwrap_or(0);
            len = len.saturating_add(u64::from(size.max(8)));
        }
        let rec = data.sub(pos, len);
        cx.push(
            Node::new(format!("Record {h:#x}"))
                .span(rec)
                .summary(plural(n, "counter"))
                .lazy(indexed_record, (version, rec)),
        )
        .await;
        pos = pos.saturating_add(len);
    }
    Ok(())
}

async fn indexed_record(cx: Cx, (version, span): (u32, Span)) -> Result<()> {
    let head = cx.read_avail(span.sub(0, 16)).await?;
    let hash = get::<u64>(&head, 0, Endian::Little).unwrap_or(0);
    let n = get::<u64>(&head, 8, Endian::Little).unwrap_or(0);
    cx.emit(
        Node::new("Function hash")
            .span(span.sub(0, 8))
            .value(hex(hash, 64)),
    );
    cx.emit(
        Node::new("Counters")
            .span(span.sub(8, 8))
            .value(uint(n, 64)),
    );
    let counters = span.sub(16, n.saturating_mul(8));
    cx.emit(
        Node::new("Counter values")
            .span(counters)
            .lazy(u64_list, counters),
    );
    let mut pos = 16u64.saturating_add(counters.len);
    if version >= 11 {
        let b = cx.read_avail(span.sub(pos, 8)).await?;
        let bytes = get::<u64>(&b, 0, Endian::Little).unwrap_or(0);
        cx.emit(
            Node::new("Bitmap bytes")
                .span(span.sub(pos, 8))
                .value(uint(bytes, 64)),
        );
        pos = pos.saturating_add(8);
        if bytes > 0 {
            let bitmap = span.sub(pos, bytes.saturating_mul(8));
            cx.emit(Node::new("Bitmap").span(bitmap).lazy(u64_list, bitmap));
            pos = pos.saturating_add(bitmap.len);
        }
    }
    if version >= 3 && pos < span.len {
        let v = cx.read_avail(span.sub(pos, 8)).await?;
        let size = get::<u32>(&v, 0, Endian::Little).unwrap_or(0);
        let kinds = get::<u32>(&v, 4, Endian::Little).unwrap_or(0);
        let vp = span.sub(pos, u64::from(size).max(8));
        cx.emit(
            Node::new("Value profile data")
                .span(vp)
                .summary(format!("{size} bytes, {}", plural(kinds, "value kind"))),
        );
    }
    Ok(())
}

async fn u64_list(cx: Cx, span: Span) -> Result<()> {
    let mut i = cx.resume::<u64>().unwrap_or(0);
    let total = span.len / 8;
    while i < total {
        let at = i;
        cx.mark(move || at);
        let before = i;
        let chunk = total.saturating_sub(i).min(512);
        let bytes = cx
            .read(span.sub(i.saturating_mul(8), chunk.saturating_mul(8)))
            .await?;
        let mut r = Reader::new(&bytes);
        for _ in 0..chunk {
            let Some(v) = r.int::<u64>(Endian::Little) else {
                break;
            };
            cx.push(
                Node::new(format!("[{i}]"))
                    .span(span.sub(i.saturating_mul(8), 8))
                    .value(uint(v, 64)),
            )
            .await;
            i = i.saturating_add(1);
        }
        if i == before {
            break;
        }
    }
    Ok(())
}

async fn hash_table(cx: Cx, idx: Arc<Indexed>) -> Result<()> {
    let at = idx.field("Hash table offset");
    let span = idx.file.tail(at);
    let head = cx.read_avail(span.sub(0, 16)).await?;
    let buckets = get::<u64>(&head, 0, Endian::Little).unwrap_or(0);
    let entries = get::<u64>(&head, 8, Endian::Little).unwrap_or(0);
    cx.emit(
        Node::new("Buckets")
            .span(span.sub(0, 8))
            .value(uint(buckets, 64)),
    );
    cx.emit(
        Node::new("Entries")
            .span(span.sub(8, 8))
            .value(uint(entries, 64)),
    );
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < buckets {
        let at = i;
        cx.mark(move || at);
        let pos = 16u64.saturating_add(i.saturating_mul(8));
        if pos >= span.len {
            break;
        }
        let before = i;
        let chunk = buckets.saturating_sub(i).min(512);
        let bytes = cx
            .read_avail(span.sub(pos, chunk.saturating_mul(8)))
            .await?;
        let mut r = Reader::new(&bytes);
        for _ in 0..chunk {
            let Some(off) = r.int::<u64>(Endian::Little) else {
                break;
            };
            let s = span.sub(16u64.saturating_add(i.saturating_mul(8)), 8);
            let mut node = Node::new(format!("Bucket {i}")).span(s).value(hex(off, 64));
            if off == 0 {
                node = node.summary("empty");
            } else {
                node = node.target(idx.file.sub(off, 2));
            }
            cx.push(node).await;
            i = i.saturating_add(1);
        }
        if i == before {
            break;
        }
    }
    Ok(())
}
