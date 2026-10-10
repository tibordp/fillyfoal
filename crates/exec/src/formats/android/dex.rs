//! Android Dalvik executables: DEX (`dex\n035\0` ... `dex\n041\0`) and
//! compact DEX (`cdex001\0`), plus optimized ODEX wrappers (`dey\n036\0`)
//! (AOSP "Dalvik executable format" documentation).
//!
//! The header gives the location and size of every ID table; expanding a
//! table lists its entries in pages, resolving names through the string
//! and type tables with a few small reads per entry. The map list describes
//! every section of the file; expanding a map item walks that section item
//! by item (string data, type lists, class data, code items with their
//! tries and handlers, debug info programs, annotations, encoded arrays,
//! annotation directories, call sites, method handles, hidden API flags).

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::codec::crypto::{Hash, Sha1};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::binutil::{NodeExt, Reader, get_at, mutf8};
use crate::formats::util::fmt::clip;
use crate::formats::util::sound::sign_extend;
use crate::formats::util::val::{hex, name_or, text, uint};
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::text::hex_lower;
use crate::value::{EnumTable, FlagTable, Value, decode_flags, flag, lookup};

const LE: Endian = Endian::Little;
/// Longest string we look for a terminator in.
const MAX_STRING: u64 = 0x10000;
/// Files up to this size get their checksum and signature verified.
const MAX_VERIFIED: u64 = 16 << 20;
/// Sections larger than this are walked only as far as this.
const MAX_SECTION: u64 = 64 << 20;
/// Nesting limit for encoded values (arrays and annotations in arrays).
const MAX_DEPTH: u32 = 16;

pub static FORMAT: Format = Format {
    name: "dex",
    title: "Android Dalvik executable",
    extensions: &["dex", "cdex"],
    mime: "application/vnd.android.dex",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

pub static ODEX: Format = Format {
    name: "odex",
    title: "Android optimized DEX (Dalvik)",
    extensions: &["odex"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| h.starts_with(b"dey\n03") && h.at(7, b"\0")),
    dissect: crate::expander!(odex: Input),
};

fn probe(h: &Head<'_>) -> bool {
    (h.starts_with(b"dex\n0") && h.at(7, b"\0")) || h.starts_with(b"cdex0")
}

const TYPE_HEADER: u16 = 0x0000;
const TYPE_STRING_ID: u16 = 0x0001;
const TYPE_TYPE_ID: u16 = 0x0002;
const TYPE_PROTO_ID: u16 = 0x0003;
const TYPE_FIELD_ID: u16 = 0x0004;
const TYPE_METHOD_ID: u16 = 0x0005;
const TYPE_CLASS_DEF: u16 = 0x0006;
const TYPE_CALL_SITE_ID: u16 = 0x0007;
const TYPE_METHOD_HANDLE: u16 = 0x0008;
const TYPE_MAP_LIST: u16 = 0x1000;
const TYPE_TYPE_LIST: u16 = 0x1001;
const TYPE_ANNOTATION_SET_REF_LIST: u16 = 0x1002;
const TYPE_ANNOTATION_SET: u16 = 0x1003;
const TYPE_CLASS_DATA: u16 = 0x2000;
const TYPE_CODE: u16 = 0x2001;
const TYPE_STRING_DATA: u16 = 0x2002;
const TYPE_DEBUG_INFO: u16 = 0x2003;
const TYPE_ANNOTATION: u16 = 0x2004;
const TYPE_ENCODED_ARRAY: u16 = 0x2005;
const TYPE_ANNOTATIONS_DIRECTORY: u16 = 0x2006;
const TYPE_HIDDENAPI: u16 = 0xf000;

const MAP_TYPE: EnumTable = &[
    (0x0000, "TYPE_HEADER_ITEM"),
    (0x0001, "TYPE_STRING_ID_ITEM"),
    (0x0002, "TYPE_TYPE_ID_ITEM"),
    (0x0003, "TYPE_PROTO_ID_ITEM"),
    (0x0004, "TYPE_FIELD_ID_ITEM"),
    (0x0005, "TYPE_METHOD_ID_ITEM"),
    (0x0006, "TYPE_CLASS_DEF_ITEM"),
    (0x0007, "TYPE_CALL_SITE_ID_ITEM"),
    (0x0008, "TYPE_METHOD_HANDLE_ITEM"),
    (0x1000, "TYPE_MAP_LIST"),
    (0x1001, "TYPE_TYPE_LIST"),
    (0x1002, "TYPE_ANNOTATION_SET_REF_LIST"),
    (0x1003, "TYPE_ANNOTATION_SET_ITEM"),
    (0x2000, "TYPE_CLASS_DATA_ITEM"),
    (0x2001, "TYPE_CODE_ITEM"),
    (0x2002, "TYPE_STRING_DATA_ITEM"),
    (0x2003, "TYPE_DEBUG_INFO_ITEM"),
    (0x2004, "TYPE_ANNOTATION_ITEM"),
    (0x2005, "TYPE_ENCODED_ARRAY_ITEM"),
    (0x2006, "TYPE_ANNOTATIONS_DIRECTORY_ITEM"),
    (0xf000, "TYPE_HIDDENAPI_CLASS_DATA_ITEM"),
];

const ACCESS: FlagTable = &[
    flag(0x1, "PUBLIC"),
    flag(0x2, "PRIVATE"),
    flag(0x4, "PROTECTED"),
    flag(0x8, "STATIC"),
    flag(0x10, "FINAL"),
    flag(0x20, "SYNCHRONIZED"),
    flag(0x40, "VOLATILE/BRIDGE"),
    flag(0x80, "TRANSIENT/VARARGS"),
    flag(0x100, "NATIVE"),
    flag(0x200, "INTERFACE"),
    flag(0x400, "ABSTRACT"),
    flag(0x800, "STRICT"),
    flag(0x1000, "SYNTHETIC"),
    flag(0x2000, "ANNOTATION"),
    flag(0x4000, "ENUM"),
    flag(0x1_0000, "CONSTRUCTOR"),
    flag(0x2_0000, "DECLARED_SYNCHRONIZED"),
];

const VISIBILITY: EnumTable = &[(0, "BUILD"), (1, "RUNTIME"), (2, "SYSTEM")];

const METHOD_HANDLE_TYPE: EnumTable = &[
    (0, "STATIC_PUT"),
    (1, "STATIC_GET"),
    (2, "INSTANCE_PUT"),
    (3, "INSTANCE_GET"),
    (4, "INVOKE_STATIC"),
    (5, "INVOKE_INSTANCE"),
    (6, "INVOKE_CONSTRUCTOR"),
    (7, "INVOKE_DIRECT"),
    (8, "INVOKE_INTERFACE"),
];

const NO_INDEX: u32 = 0xffff_ffff;

#[derive(Clone, Copy, Debug, Default)]
struct Table {
    size: u32,
    off: u32,
}

#[derive(Clone, Copy, Debug)]
struct Header {
    map_off: u32,
    strings: Table,
    types: Table,
    protos: Table,
    fields: Table,
    methods: Table,
    classes: Table,
}

type Dex = Arc<DexInfo>;

struct DexInfo {
    file: Span,
    compact: bool,
    header: Header,
}

/// Text with references to be named (strings, types, fields, methods,
/// prototypes), from decoding encoded values and debug info synchronously.
#[derive(Clone, Debug)]
enum Piece {
    Text(String),
    Str(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Proto(u32),
}

impl DexInfo {
    /// The span of a table of `width`-byte entries, clamped to the file.
    fn table(&self, t: Table, width: u64) -> Span {
        self.file
            .sub(t.off.into(), u64::from(t.size).saturating_mul(width))
    }

    async fn word(&self, cx: &Cx, t: Table, width: u64, index: u32, at: u64) -> Result<u32> {
        if index >= t.size {
            return Err(Diagnostic::malformed(format!("index {index} out of range")));
        }
        let entry = u64::from(t.off)
            .saturating_add(u64::from(index).saturating_mul(width))
            .saturating_add(at);
        let data = cx.read(self.file.sub(entry, 4)).await?;
        Ok(u32_le(&data, 0).unwrap_or(0))
    }

    async fn half(&self, cx: &Cx, t: Table, width: u64, index: u32, at: u64) -> Result<u16> {
        let word = self.word(cx, t, width, index, at).await?;
        Ok(u16::try_from(word & 0xffff).unwrap_or(0))
    }

    async fn string(&self, cx: &Cx, index: u32) -> Result<String> {
        let off = self.word(cx, self.header.strings, 4, index, 0).await?;
        let data = self.file.tail(off.into());
        let head = cx.read_avail(data.sub(0, 5)).await?;
        let (_, len) = crate::bytes::uleb128(&head)
            .ok_or_else(|| Diagnostic::malformed("bad string length").at(data.sub(0, 5)))?;
        // `cstr` decodes UTF-8 lossily; re-read the raw bytes as MUTF-8.
        let (_, at) = cx.cstr(data.tail(to_u64(len)).sub(0, MAX_STRING)).await?;
        let raw = cx.read(at.sub(0, at.len.saturating_sub(1))).await?;
        Ok(mutf8(&raw))
    }

    async fn type_name(&self, cx: &Cx, index: u32) -> String {
        if index == NO_INDEX || (self.compact && index == 0xffff) {
            return "(none)".to_owned();
        }
        match self.word(cx, self.header.types, 4, index, 0).await {
            Ok(s) => self
                .string(cx, s)
                .await
                .unwrap_or_else(|_| format!("type #{index}")),
            Err(_) => format!("type #{index}"),
        }
    }

    async fn type_list(&self, cx: &Cx, off: u32) -> Vec<String> {
        let mut out = Vec::new();
        if off == 0 {
            return out;
        }
        let Ok(head) = cx.read(self.file.sub(off.into(), 4)).await else {
            return out;
        };
        let n = u32_le(&head, 0).unwrap_or(0).min(256);
        let Ok(list) = cx
            .read_avail(self.file.sub(
                u64::from(off).saturating_add(4),
                u64::from(n).saturating_mul(2),
            ))
            .await
        else {
            return out;
        };
        for i in 0..to_u64(list.len()) / 2 {
            let t = get_at::<u16>(&list, i.saturating_mul(2), LE).unwrap_or(0);
            out.push(self.type_name(cx, t.into()).await);
        }
        out
    }

    async fn proto(&self, cx: &Cx, index: u32) -> String {
        let p = self.header.protos;
        let (Ok(ret), Ok(params)) = (
            self.word(cx, p, 12, index, 4).await,
            self.word(cx, p, 12, index, 8).await,
        ) else {
            return format!("proto #{index}");
        };
        let params = self.type_list(cx, params).await;
        format!("({}){}", params.join(""), self.type_name(cx, ret).await)
    }

    async fn field(&self, cx: &Cx, index: u32) -> String {
        let t = self.header.fields;
        let (Ok(class), Ok(kind), Ok(name)) = (
            self.half(cx, t, 8, index, 0).await,
            self.half(cx, t, 8, index, 2).await,
            self.word(cx, t, 8, index, 4).await,
        ) else {
            return format!("field #{index}");
        };
        format!(
            "{}->{}:{}",
            self.type_name(cx, class.into()).await,
            self.string(cx, name).await.unwrap_or_default(),
            self.type_name(cx, kind.into()).await
        )
    }

    async fn method(&self, cx: &Cx, index: u32) -> (String, String) {
        let t = self.header.methods;
        let (Ok(class), Ok(proto), Ok(name)) = (
            self.half(cx, t, 8, index, 0).await,
            self.half(cx, t, 8, index, 2).await,
            self.word(cx, t, 8, index, 4).await,
        ) else {
            return (format!("method #{index}"), String::new());
        };
        (
            self.type_name(cx, class.into()).await,
            format!(
                "{}{}",
                self.string(cx, name).await.unwrap_or_default(),
                self.proto(cx, proto.into()).await
            ),
        )
    }

    async fn render(&self, cx: &Cx, pieces: &[Piece]) -> String {
        let mut out = String::new();
        for (i, p) in pieces.iter().enumerate() {
            if i.is_multiple_of(64) {
                cx.checkpoint().await;
            }
            match p {
                Piece::Text(t) => out.push_str(t),
                Piece::Str(i) => match self.string(cx, *i).await {
                    Ok(s) => out.push_str(&format!("{s:?}")),
                    Err(_) => out.push_str(&format!("string@{i}")),
                },
                Piece::Type(i) => out.push_str(&self.type_name(cx, *i).await),
                Piece::Field(i) => out.push_str(&self.field(cx, *i).await),
                Piece::Method(i) => {
                    let (class, method) = self.method(cx, *i).await;
                    out.push_str(&format!("{class}->{method}"));
                }
                Piece::Proto(i) => out.push_str(&self.proto(cx, *i).await),
            }
        }
        out
    }
}

/// `Lcom/example/Foo;` as `com.example.Foo`.
fn java_name(descriptor: &str) -> String {
    let dims = descriptor.chars().take_while(|&c| c == '[').count();
    let base = descriptor.get(dims..).unwrap_or_default();
    let name = match base {
        "V" => "void".to_owned(),
        "Z" => "boolean".to_owned(),
        "B" => "byte".to_owned(),
        "S" => "short".to_owned(),
        "C" => "char".to_owned(),
        "I" => "int".to_owned(),
        "J" => "long".to_owned(),
        "F" => "float".to_owned(),
        "D" => "double".to_owned(),
        _ => base
            .strip_prefix('L')
            .and_then(|s| s.strip_suffix(';'))
            .unwrap_or(base)
            .replace('/', "."),
    };
    format!("{name}{}", "[]".repeat(dims.min(255)))
}

// ---------------------------------------------------------------------------
// Header

/// Results of verifying the header's checksum and signature.
#[derive(Clone, Copy, Debug)]
struct Checks {
    adler: u32,
    sha1: [u8; 20],
}

fn table(
    f: &mut Fields<'_>,
    size: &'static str,
    off: &'static str,
    file: Span,
    width: u64,
) -> Result<Table> {
    let size = f.u32(size).emit()?;
    let off = f
        .u32(off)
        .hex()
        .with(|&v, n| {
            if v == 0 {
                n
            } else {
                n.target(file.sub(v.into(), u64::from(size).saturating_mul(width)))
            }
        })
        .emit()?;
    Ok(Table { size, off })
}

fn header(f: &mut Fields<'_>, (file, checks): &(Span, Option<Checks>)) -> Result<Header> {
    let file = *file;
    let compact = f.block().data.starts_with(b"cdex");
    f.ascii("magic", 8)
        .with(|_, n| n.summary(if compact { "compact DEX" } else { "DEX" }))
        .emit()?;
    f.u32("checksum")
        .hex()
        .desc("Adler-32 of everything after this field")
        .with(|&v, n| match checks {
            Some(c) if c.adler == v => n.summary("valid"),
            Some(c) => n.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {:#010x}",
                c.adler
            ))),
            None => n,
        })
        .emit()?;
    f.bytes("signature", 20)
        .desc("SHA-1 of everything after this field")
        .with(|v, n| match checks {
            Some(c) if c.sha1.as_slice() == v.as_slice() => n.summary("valid"),
            Some(c) => n.diag(Diagnostic::warning(format!(
                "signature mismatch: computed {}",
                hex_lower(&c.sha1)
            ))),
            None => n,
        })
        .emit()?;
    f.u32("file_size")
        .hex()
        .check(|&v| {
            (u64::from(v) != file.len)
                .then(|| Diagnostic::warning(format!("the file is {:#x} bytes", file.len)))
        })
        .emit()?;
    let header_size = f.u32("header_size").hex().emit()?;
    f.u32("endian_tag")
        .hex()
        .with(|&v, n| match v {
            0x1234_5678 => n.summary("little-endian"),
            0x7856_3412 => n.summary("byte-swapped"),
            _ => n,
        })
        .emit()?;
    table(f, "link_size", "link_off", file, 1)?;
    let map_off = f
        .u32("map_off")
        .hex()
        .with(|&v, n| n.target(file.sub(v.into(), 4)))
        .emit()?;
    let strings = table(f, "string_ids_size", "string_ids_off", file, 4)?;
    let types = table(f, "type_ids_size", "type_ids_off", file, 4)?;
    let protos = table(f, "proto_ids_size", "proto_ids_off", file, 12)?;
    let fields = table(f, "field_ids_size", "field_ids_off", file, 8)?;
    let methods = table(f, "method_ids_size", "method_ids_off", file, 8)?;
    let classes = table(f, "class_defs_size", "class_defs_off", file, 32)?;
    table(f, "data_size", "data_off", file, 1)?;
    if compact {
        f.u32("feature_flags").hex().emit()?;
        f.u32("debug_info_offsets_pos").hex().emit()?;
        f.u32("debug_info_offsets_table_offset").hex().emit()?;
        f.u32("debug_info_base").hex().emit()?;
        f.u32("owned_data_begin").hex().emit()?;
        f.u32("owned_data_end").hex().emit()?;
    } else if header_size >= 0x78 {
        f.u32("container_size").hex().emit()?;
        f.u32("header_offset").hex().emit()?;
    }
    Ok(Header {
        map_off,
        strings,
        types,
        protos,
        fields,
        methods,
        classes,
    })
}

/// Adler-32 from offset 12 and SHA-1 from offset 32, in budgeted chunks.
async fn verify(cx: &Cx, file: Span) -> Result<Checks> {
    const CHUNK: u64 = 1 << 16;
    let mut sha = Sha1::new();
    let mut adler = crate::codec::Adler32::new();
    let mut pos = 12u64;
    while pos < file.len {
        let data = cx.read(file.sub(pos, CHUNK)).await?;
        if data.is_empty() {
            break;
        }
        // The SHA-1 starts after the signature (offset 32).
        let skip = to_usize(32u64.saturating_sub(pos));
        if let Some(rest) = data.get(skip..) {
            sha.update(rest);
        }
        for chunk in data.chunks(4096) {
            adler.update(chunk);
            cx.checkpoint().await;
        }
        pos = pos.saturating_add(to_u64(data.len()));
    }
    let mut sha1 = [0u8; 20];
    for (d, s) in sha1.iter_mut().zip(sha.finish()) {
        *d = s;
    }
    Ok(Checks {
        adler: adler.value(),
        sha1,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x80)).await?;
    let compact = head.starts_with(b"cdex");
    let header_size = u64::from(u32_le(&head, 36).unwrap_or(0x70)).clamp(0x70, 0x88);
    let header_span = file.sub(0, if compact { 0x88 } else { header_size });

    let stored = u32_le(&head, 8).unwrap_or(0);
    let checks = if file.len <= MAX_VERIFIED && !compact {
        verify(&cx, file).await.ok()
    } else {
        None
    };
    let mut node = struct_node("Header", header_span, LE, (file, checks), header);
    if let Some(c) = checks {
        if c.adler != stored {
            node = node.diag(Diagnostic::warning("checksum mismatch"));
        }
        if head.get(12..32) != Some(c.sha1.as_slice()) {
            node = node.diag(Diagnostic::warning("signature mismatch"));
        }
    }
    cx.emit(node);
    let h = parse(&cx, header_span, LE, &(file, checks), header).await?;
    let version = String::from_utf8_lossy(head.get(4..7).unwrap_or_default()).into_owned();
    let dex: Dex = Arc::new(DexInfo {
        file,
        compact,
        header: h,
    });
    let kind = if compact { "compact DEX" } else { "DEX" };
    let mut summary = format!(
        "Android {kind} v{version}, {} classes, {} methods, {} strings",
        h.classes.size, h.methods.size, h.strings.size
    );
    if h.classes.size > 0 {
        let first = match dex.word(&cx, h.classes, 32, 0, 0).await {
            Ok(t) => java_name(&dex.type_name(&cx, t).await),
            Err(_) => String::new(),
        };
        if !first.is_empty() {
            summary.push_str(&format!(
                " ({first}{})",
                if h.classes.size > 1 { ", …" } else { "" }
            ));
        }
    }
    cx.annotate(summary);

    let lists: [(&str, Table, u64, Kind); 6] = [
        ("Strings", h.strings, 4, Kind::String),
        ("Types", h.types, 4, Kind::Type),
        ("Prototypes", h.protos, 12, Kind::Proto),
        ("Fields", h.fields, 8, Kind::Field),
        ("Methods", h.methods, 8, Kind::Method),
        ("Classes", h.classes, 32, Kind::Class),
    ];
    for (name, t, width, kind) in lists {
        let span = dex.table(t, width);
        cx.emit(
            Node::new(name)
                .span(span)
                .summary(format!("{} entries", t.size))
                .lazy(id_list, (dex.clone(), kind)),
        );
    }
    if h.map_off != 0 && !compact {
        let head = cx.read_avail(file.sub(h.map_off.into(), 4)).await?;
        let n = u32_le(&head, 0).unwrap_or(0);
        let span = file.sub(
            h.map_off.into(),
            4u64.saturating_add(u64::from(n).saturating_mul(MapItem::SIZE)),
        );
        cx.emit(
            Node::new("Map List")
                .span(span)
                .summary(format!("{n} sections"))
                .desc("Every section of the file, in offset order; expand one to walk its items")
                .lazy(map_list, dex.clone()),
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    String,
    Type,
    Proto,
    Field,
    Method,
    Class,
}

record! {
    struct MapItem {
        kind: u16 "type" .enumeration(MAP_TYPE),
        unused: u16 "unused",
        size: u32 "size",
        offset: u32 "offset" .hex(),
    }
}

/// The map items, sorted as in the file.
async fn map_items(cx: &Cx, dex: &DexInfo) -> Result<(Span, Vec<(MapItem, Span)>)> {
    let head = cx.read(dex.file.sub(dex.header.map_off.into(), 4)).await?;
    let n = u32_le(&head, 0).unwrap_or(0);
    let table = dex.file.sub(
        u64::from(dex.header.map_off).saturating_add(4),
        u64::from(n).saturating_mul(MapItem::SIZE),
    );
    let count = table.len / MapItem::SIZE;
    let mut out = Vec::new();
    for i in 0..count.min(1024) {
        let at = table.sub(i.saturating_mul(MapItem::SIZE), MapItem::SIZE);
        let item = parse(cx, at, LE, &(), MapItem::layout).await?;
        out.push((item, at));
    }
    Ok((dex.file.sub(dex.header.map_off.into(), 4), out))
}

async fn map_list(cx: Cx, dex: Dex) -> Result<()> {
    let (size_span, items) = map_items(&cx, &dex).await?;
    let size = cx.read(size_span).await?;
    cx.emit(
        Node::new("size")
            .span(size_span)
            .value(uint(u32_le(&size, 0).unwrap_or(0), 32)),
    );
    // Each section ends where the next one (by offset) starts.
    let mut offsets: Vec<u32> = items.iter().map(|(i, _)| i.offset).collect();
    offsets.sort_unstable();
    for (item, at) in &items {
        let end = offsets
            .iter()
            .find(|&&o| o > item.offset)
            .map_or(dex.file.len, |&o| u64::from(o));
        let name = name_or(MAP_TYPE, item.kind.into(), "type");
        let node = MapItem::node(name, *at, LE)
            .summary(format!("{} items at {:#x}", item.size, item.offset))
            .target(dex.file.sub(item.offset.into(), 0));
        let node = match item.kind {
            TYPE_HEADER | TYPE_MAP_LIST => node,
            TYPE_STRING_ID | TYPE_TYPE_ID | TYPE_PROTO_ID | TYPE_FIELD_ID | TYPE_METHOD_ID
            | TYPE_CLASS_DEF => {
                let kind = match item.kind {
                    TYPE_STRING_ID => Kind::String,
                    TYPE_TYPE_ID => Kind::Type,
                    TYPE_PROTO_ID => Kind::Proto,
                    TYPE_FIELD_ID => Kind::Field,
                    TYPE_METHOD_ID => Kind::Method,
                    _ => Kind::Class,
                };
                Node::new(name_or(MAP_TYPE, item.kind.into(), "type"))
                    .span(*at)
                    .summary(format!("{} items at {:#x}", item.size, item.offset))
                    .target(dex.file.sub(item.offset.into(), 0))
                    .lazy(id_list, (dex.clone(), kind))
            }
            _ => Node::new(name_or(MAP_TYPE, item.kind.into(), "type"))
                .span(*at)
                .summary(format!("{} items at {:#x}", item.size, item.offset))
                .target(dex.file.sub(item.offset.into(), 0))
                .lazy(
                    section,
                    Section {
                        dex: dex.clone(),
                        kind: item.kind,
                        offset: item.offset,
                        count: item.size,
                        end,
                        entry: *at,
                    },
                ),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn id_list(cx: Cx, (dex, kind): (Dex, Kind)) -> Result<()> {
    let h = dex.header;
    let (t, width) = match kind {
        Kind::String => (h.strings, 4),
        Kind::Type => (h.types, 4),
        Kind::Proto => (h.protos, 12),
        Kind::Field => (h.fields, 8),
        Kind::Method => (h.methods, 8),
        Kind::Class => (h.classes, 32),
    };
    let span = dex.table(t, width);
    let count = u32::try_from(span.len.checked_div(width).unwrap_or(0)).unwrap_or(u32::MAX);
    cx.set_count(Count::Exact(count.into()));
    for i in 0..count {
        let at = span.sub(u64::from(i).saturating_mul(width), width);
        let node = match kind {
            Kind::String => {
                let off = dex.word(&cx, t, 4, i, 0).await?;
                let target = dex.file.sub(off.into(), 0);
                match dex.string(&cx, i).await {
                    Ok(s) => Node::new(format!("#{i}"))
                        .value(hex(off, 32))
                        .summary(format!("{s:?}")),
                    Err(e) => Node::new(format!("#{i}")).diag(e),
                }
                .target(target)
            }
            Kind::Type => {
                let name = dex.type_name(&cx, i).await;
                let idx = dex.word(&cx, t, 4, i, 0).await.unwrap_or(0);
                Node::new(format!("#{i}"))
                    .value(uint(idx, 32))
                    .summary(format!("{name} ({})", java_name(&name)))
            }
            Kind::Proto => {
                let shorty = dex.word(&cx, t, 12, i, 0).await?;
                Node::new(format!("#{i}"))
                    .value(text(dex.proto(&cx, i).await))
                    .maybe_summary(dex.string(&cx, shorty).await.unwrap_or_default())
            }
            Kind::Field => Node::new(format!("#{i}")).value(text(dex.field(&cx, i).await)),
            Kind::Method => {
                let (class, method) = dex.method(&cx, i).await;
                Node::new(format!("#{i}"))
                    .value(text(method))
                    .summary(java_name(&class))
            }
            Kind::Class => {
                let class = dex.word(&cx, t, 32, i, 0).await?;
                let access = dex.word(&cx, t, 32, i, 4).await?;
                let superclass = dex.word(&cx, t, 32, i, 8).await?;
                let source = dex.word(&cx, t, 32, i, 16).await?;
                let name = java_name(&dex.type_name(&cx, class).await);
                let (set, _) = decode_flags(ACCESS, access.into());
                let mut summary = set.join(" ").to_lowercase();
                if superclass != NO_INDEX {
                    summary.push_str(&format!(
                        ", extends {}",
                        java_name(&dex.type_name(&cx, superclass).await)
                    ));
                }
                if source != NO_INDEX
                    && let Ok(s) = dex.string(&cx, source).await
                {
                    summary.push_str(&format!(", {s}"));
                }
                cx.push(
                    Node::new(name)
                        .span(at)
                        .summary(summary.trim_start_matches(", ").to_owned())
                        .lazy(class_def, (dex.clone(), at)),
                )
                .await;
                continue;
            }
        };
        let node = node.span(at);
        let node = if matches!(kind, Kind::Proto | Kind::Field | Kind::Method) {
            node.lazy(id_item, (dex.clone(), kind, at))
        } else {
            node
        };
        cx.push(node).await;
    }
    Ok(())
}

/// The raw fields of a proto, field or method ID, with resolved names.
async fn id_item(cx: Cx, (dex, kind, at): (Dex, Kind, Span)) -> Result<()> {
    let data = cx.read(at).await?;
    let u32_at = |o: u64| get_at::<u32>(&data, o, LE).unwrap_or(0);
    let u16_at = |o: u64| u32::from(get_at::<u16>(&data, o, LE).unwrap_or(0));
    let mut parts: Vec<(&'static str, Span, u32, String)> = Vec::new();
    match kind {
        Kind::Proto => {
            let shorty = u32_at(0);
            let ret = u32_at(4);
            let params = u32_at(8);
            parts.push((
                "shorty_idx",
                at.sub(0, 4),
                shorty,
                dex.string(&cx, shorty).await.unwrap_or_default(),
            ));
            parts.push((
                "return_type_idx",
                at.sub(4, 4),
                ret,
                dex.type_name(&cx, ret).await,
            ));
            parts.push((
                "parameters_off",
                at.sub(8, 4),
                params,
                dex.type_list(&cx, params).await.join(", "),
            ));
        }
        Kind::Field | Kind::Method => {
            let class = u16_at(0);
            let second = u16_at(2);
            let name = u32_at(4);
            parts.push((
                "class_idx",
                at.sub(0, 2),
                class,
                dex.type_name(&cx, class).await,
            ));
            if kind == Kind::Field {
                parts.push((
                    "type_idx",
                    at.sub(2, 2),
                    second,
                    dex.type_name(&cx, second).await,
                ));
            } else {
                parts.push((
                    "proto_idx",
                    at.sub(2, 2),
                    second,
                    dex.proto(&cx, second).await,
                ));
            }
            parts.push((
                "name_idx",
                at.sub(4, 4),
                name,
                dex.string(&cx, name).await.unwrap_or_default(),
            ));
        }
        _ => {}
    }
    for (name, span, value, resolved) in parts {
        let bits = if span.len == 2 { 16 } else { 32 };
        let mut node = Node::new(name)
            .span(span)
            .value(if name.ends_with("_off") {
                hex(value, bits)
            } else {
                uint(value, bits)
            })
            .maybe_summary(resolved);
        if name == "parameters_off" && value != 0 {
            node = node.target(dex.file.sub(value.into(), 4));
        }
        cx.emit(node);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Class definitions

record! {
    struct ClassDef {
        class_idx: u32 "class_idx",
        access_flags: u32 "access_flags" .flags(ACCESS),
        superclass_idx: u32 "superclass_idx",
        interfaces_off: u32 "interfaces_off" .hex(),
        source_file_idx: u32 "source_file_idx",
        annotations_off: u32 "annotations_off" .hex(),
        class_data_off: u32 "class_data_off" .hex(),
        static_values_off: u32 "static_values_off" .hex(),
    }
}

async fn class_def(cx: Cx, (dex, at): (Dex, Span)) -> Result<()> {
    let def = parse(&cx, at, LE, &(), ClassDef::layout).await?;
    let block = cx.block(at).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let class = dex.type_name(&cx, def.class_idx).await;
    let superclass = dex.type_name(&cx, def.superclass_idx).await;
    let source = if def.source_file_idx == NO_INDEX {
        String::new()
    } else {
        dex.string(&cx, def.source_file_idx)
            .await
            .unwrap_or_default()
    };
    let target = |off: u32| (off != 0).then(|| dex.file.sub(off.into(), 0));
    f.u32("class_idx")
        .with(|_, n| n.summary(class.clone()))
        .emit()?;
    f.u32("access_flags").flags(ACCESS).emit()?;
    f.u32("superclass_idx")
        .with(|_, n| n.summary(superclass.clone()))
        .emit()?;
    let interfaces = dex.type_list(&cx, def.interfaces_off).await;
    f.u32("interfaces_off")
        .hex()
        .with(|&v, n| {
            let n = n.maybe_summary(clip(&interfaces.join(", "), 120));
            match target(v) {
                Some(t) => n.target(t),
                None => n,
            }
        })
        .emit()?;
    f.u32("source_file_idx")
        .with(|_, n| n.maybe_summary(source.clone()))
        .emit()?;
    for name in ["annotations_off", "class_data_off", "static_values_off"] {
        f.u32(name)
            .hex()
            .with(|&v, n| match target(v) {
                Some(t) => n.target(t),
                None => n,
            })
            .emit()?;
    }
    if def.class_data_off != 0 {
        let span = dex.file.tail(def.class_data_off.into());
        cx.emit(
            Node::new("Members")
                .target(span.sub(0, 0))
                .desc("The class data item, member by member")
                .lazy(class_data, (dex.clone(), span)),
        );
    }
    if def.static_values_off != 0 {
        let span = dex.file.tail(def.static_values_off.into());
        let data = cx.read_avail(span.sub(0, 0x10000)).await?;
        if let Some((len, pieces)) = encoded_array_text(&data) {
            cx.emit(
                Node::new("Static Values")
                    .target(span.sub(0, to_u64(len)))
                    .value(text(dex.render(&cx, &pieces).await)),
            );
        }
    }
    if def.annotations_off != 0 {
        cx.emit(
            Node::new("Annotations")
                .target(dex.file.sub(def.annotations_off.into(), 16))
                .lazy(
                    item_fields,
                    (dex.clone(), TYPE_ANNOTATIONS_DIRECTORY, def.annotations_off),
                ),
        );
    }
    Ok(())
}

async fn class_data(cx: Cx, (dex, span): (Dex, Span)) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 0x10_0000)).await?;
    let mut r = Reader::new(&data);
    let bad = || Diagnostic::malformed("truncated class data").at(span.sub(0, 1));
    let mut counts = [0u64; 4];
    for c in &mut counts {
        *c = r.uleb().ok_or_else(bad)?;
    }
    let labels = [
        "static field",
        "instance field",
        "direct method",
        "virtual method",
    ];
    for (group, (&count, label)) in counts.iter().zip(labels).enumerate() {
        let methods = group >= 2;
        let mut index = 0u32;
        for _ in 0..count {
            let start = r.pos();
            let diff = r.uleb().ok_or_else(bad)?;
            let access = r.uleb().ok_or_else(bad)?;
            let code = if methods {
                r.uleb().ok_or_else(bad)?
            } else {
                0
            };
            index = index.saturating_add(u32::try_from(diff).unwrap_or(u32::MAX));
            let at = span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
            let (set, _) = decode_flags(ACCESS, access);
            let flags = set.join(" ").to_lowercase();
            let node = if methods {
                let (class, method) = dex.method(&cx, index).await;
                let node = Node::new(method)
                    .span(at)
                    .summary(format!("{label}, {flags}"))
                    .desc(format!("Declared in {}", java_name(&class)));
                if code != 0 && !dex.compact {
                    let item = dex.file.sub(code, 16);
                    node.target(item).lazy(
                        crate::expander!(self::code_item: (Dex, u64)),
                        (dex.clone(), code),
                    )
                } else {
                    node
                }
            } else {
                Node::new(dex.field(&cx, index).await)
                    .span(at)
                    .summary(format!("{label}, {flags}"))
            };
            cx.push(node).await;
        }
    }
    Ok(())
}

record! {
    struct CodeItem {
        registers: u16 "registers_size",
        ins: u16 "ins_size" .desc("Words of incoming arguments"),
        outs: u16 "outs_size" .desc("Words of outgoing argument space for calls"),
        tries: u16 "tries_size",
        debug_info: u32 "debug_info_off" .hex(),
        insns: u32 "insns_size" .desc("In 16-bit code units"),
    }
}

async fn code_item(cx: Cx, (dex, off): (Dex, u64)) -> Result<()> {
    let head = dex.file.sub(off, CodeItem::SIZE);
    cx.emit(CodeItem::node("code_item", head, LE));
    let item = parse(&cx, head, LE, &(), CodeItem::layout).await?;
    let insns = dex.file.sub(
        off.saturating_add(CodeItem::SIZE),
        u64::from(item.insns).saturating_mul(2),
    );
    cx.emit(
        Node::new("insns")
            .span(insns)
            .summary(format!("{} code units", item.insns))
            .lazy(disassemble, (dex.clone(), insns)),
    );
    let mut end = off.saturating_add(CodeItem::SIZE).saturating_add(insns.len);
    if item.tries > 0 {
        if item.insns % 2 == 1 {
            cx.emit(
                Node::new("padding")
                    .span(dex.file.sub(end, 2))
                    .desc("Aligns the tries to 4 bytes"),
            );
            end = end.saturating_add(2);
        }
        let tries = dex.file.sub(end, u64::from(item.tries).saturating_mul(8));
        cx.emit(
            Node::new("tries")
                .span(tries)
                .summary(format!("{} try blocks", item.tries))
                .lazy(try_items, (dex.clone(), tries)),
        );
        end = end.saturating_add(tries.len);
        let data = cx.read_avail(dex.file.sub(end, 0x10000)).await?;
        if let Some(len) = handlers_len(&data) {
            let span = dex.file.sub(end, to_u64(len));
            cx.emit(
                Node::new("handlers")
                    .span(span)
                    .desc("encoded_catch_handler_list")
                    .lazy(handler_list, (dex.clone(), span)),
            );
        }
    }
    if item.debug_info != 0 {
        cx.emit(
            Node::new("Debug Info")
                .target(dex.file.sub(item.debug_info.into(), 0))
                .lazy(
                    crate::expander!(self::item_fields: (Dex, u16, u32)),
                    (dex.clone(), TYPE_DEBUG_INFO, item.debug_info),
                ),
        );
    }
    Ok(())
}

async fn try_items(cx: Cx, (_dex, span): (Dex, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    for i in 0..data.len() / 8 {
        let at = i.saturating_mul(8);
        let start = u32_le(&data, at).unwrap_or(0);
        let count = u16_le(&data, at.saturating_add(4)).unwrap_or(0);
        let handler = u16_le(&data, at.saturating_add(6)).unwrap_or(0);
        cx.push(
            struct_node(
                format!("try {i}"),
                span.sub(to_u64(at), 8),
                LE,
                (),
                try_item,
            )
            .summary(format!(
                "{start:#06x}..{:#06x}, handlers at +{handler:#x}",
                start.saturating_add(count.into())
            )),
        )
        .await;
    }
    Ok(())
}

fn try_item(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("start_addr").hex().desc("In code units").emit()?;
    f.u16("insn_count").emit()?;
    f.u16("handler_off")
        .hex()
        .desc("Offset of the handler from the start of the handler list")
        .emit()?;
    Ok(())
}

/// The length of an `encoded_catch_handler_list` at the start of `data`.
fn handlers_len(data: &[u8]) -> Option<usize> {
    let mut r = Reader::new(data);
    let n = r.uleb()?;
    for _ in 0..n.min(65536) {
        let size = r.sleb()?;
        for _ in 0..size.unsigned_abs().min(65536) {
            r.uleb()?;
            r.uleb()?;
        }
        if size <= 0 {
            r.uleb()?;
        }
    }
    Some(r.pos())
}

async fn handler_list(cx: Cx, (dex, span): (Dex, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader::new(&data);
    let n = r.uleb().unwrap_or(0);
    cx.emit(
        Node::new("size")
            .span(span.sub(0, to_u64(r.pos())))
            .value(uint(n, 32)),
    );
    for _ in 0..n.min(65536) {
        let start = r.pos();
        let Some(size) = r.sleb() else { break };
        let mut parts = Vec::new();
        for _ in 0..size.unsigned_abs().min(65536) {
            let (Some(ty), Some(addr)) = (r.uleb(), r.uleb()) else {
                break;
            };
            let name = dex
                .type_name(&cx, u32::try_from(ty).unwrap_or(NO_INDEX))
                .await;
            parts.push(format!("{} → {addr:#06x}", java_name(&name)));
        }
        if size <= 0
            && let Some(addr) = r.uleb()
        {
            parts.push(format!("catch all → {addr:#06x}"));
        }
        cx.push(
            Node::new(format!("+{start:#x}"))
                .span(span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start))))
                .value(text(parts.join(", ")))
                .desc("encoded_catch_handler: (type, address) pairs and an optional catch-all"),
        )
        .await;
    }
    Ok(())
}

/// Lists the instructions of a code item, resolving constant references.
async fn disassemble(cx: Cx, (dex, span): (Dex, Span)) -> Result<()> {
    use super::dalvik::{Ref, decode};
    let bytes = cx.read(span.sub(0, 0x20_0000)).await?;
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .collect();
    let mut pc = 0usize;
    while pc < units.len() {
        let Some(insn) = decode(&units, pc) else {
            cx.push(
                Node::new(format!("{pc:#06x}"))
                    .span(span.tail(to_u64(pc.saturating_mul(2))))
                    .diag(Diagnostic::malformed("truncated instruction")),
            )
            .await;
            break;
        };
        let mut operands = insn.operands.clone();
        if let Some((kind, index)) = insn.reference {
            let resolved = match kind {
                Ref::String => dex.string(&cx, index).await.map(|s| format!("{s:?}")).ok(),
                Ref::Type => Some(dex.type_name(&cx, index).await),
                Ref::Field => Some(dex.field(&cx, index).await),
                Ref::Method => {
                    let (class, method) = dex.method(&cx, index).await;
                    Some(format!("{class}->{method}"))
                }
                Ref::Proto => Some(dex.proto(&cx, index).await),
                Ref::CallSite => Some(format!("call_site@{index}")),
                Ref::MethodHandle => Some(format!("method_handle@{index}")),
            };
            let target = resolved.unwrap_or_else(|| format!("#{index}"));
            operands = if operands.is_empty() {
                target
            } else {
                format!("{operands}, {target}")
            };
        }
        let len = insn.units.max(1);
        cx.push(
            Node::new(format!("{pc:#06x}"))
                .span(span.sub(to_u64(pc.saturating_mul(2)), to_u64(len.saturating_mul(2))))
                .value(text(insn.mnemonic))
                .maybe_summary(operands),
        )
        .await;
        pc = pc.saturating_add(len);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encoded values

/// Reads `n` little-endian bytes as an unsigned value.
fn read_le(r: &mut Reader<'_>, n: usize) -> Option<u64> {
    let bytes = r.bytes(n)?;
    let mut v = 0u64;
    for (i, &b) in bytes.iter().enumerate().take(8) {
        v |= u64::from(b).wrapping_shl(u32::try_from(i.saturating_mul(8)).unwrap_or(0));
    }
    Some(v)
}

/// Decodes an `encoded_value` into text pieces.
fn encoded_value(r: &mut Reader<'_>, out: &mut Vec<Piece>, depth: u32) -> Option<()> {
    let h = r.u8()?;
    let arg = usize::from(h >> 5);
    let size = arg.saturating_add(1);
    let push = |out: &mut Vec<Piece>, s: String| out.push(Piece::Text(s));
    match h & 0x1f {
        0x00 => {
            let v = read_le(r, 1)?;
            push(out, format!("{}", sign_extend(v, 8)));
        }
        0x02 | 0x04 | 0x06 => {
            let v = read_le(r, size)?;
            let suffix = if h & 0x1f == 0x06 { "L" } else { "" };
            let bits = u8::try_from(size.saturating_mul(8)).unwrap_or(64);
            push(out, format!("{}{suffix}", sign_extend(v, bits)));
        }
        0x03 => {
            let v = read_le(r, size)?;
            let c = u32::try_from(v).ok().and_then(char::from_u32);
            push(
                out,
                c.map_or_else(|| format!("{v:#x}"), |c| format!("{c:?}")),
            );
        }
        0x10 => {
            // Zero-extended to the right.
            let v = read_le(r, size)?;
            let shift = u32::try_from(4usize.saturating_sub(size).saturating_mul(8)).unwrap_or(0);
            let bits = u32::try_from(v.wrapping_shl(shift)).unwrap_or(0);
            push(out, format!("{}f", f32::from_bits(bits)));
        }
        0x11 => {
            let v = read_le(r, size)?;
            let shift = u32::try_from(8usize.saturating_sub(size).saturating_mul(8)).unwrap_or(0);
            let bits = v.wrapping_shl(shift);
            push(out, format!("{}", f64::from_bits(bits)));
        }
        kind @ (0x15..=0x1b) => {
            let v = u32::try_from(read_le(r, size)?).unwrap_or(NO_INDEX);
            out.push(match kind {
                0x15 => Piece::Proto(v),
                0x16 => Piece::Text(format!("method_handle@{v}")),
                0x17 => Piece::Str(v),
                0x18 => Piece::Type(v),
                0x19 | 0x1b => Piece::Field(v),
                _ => Piece::Method(v),
            });
        }
        0x1c => {
            if depth > MAX_DEPTH {
                return None;
            }
            encoded_array(r, out, depth.saturating_add(1))?;
        }
        0x1d => {
            if depth > MAX_DEPTH {
                return None;
            }
            encoded_annotation(r, out, depth.saturating_add(1))?;
        }
        0x1e => push(out, "null".to_owned()),
        0x1f => push(out, (arg != 0).to_string()),
        t => {
            push(out, format!("<value type {t:#04x}>"));
            return None;
        }
    }
    Some(())
}

fn encoded_array(r: &mut Reader<'_>, out: &mut Vec<Piece>, depth: u32) -> Option<()> {
    let n = r.uleb()?;
    out.push(Piece::Text("{".to_owned()));
    for i in 0..n.min(65536) {
        if i > 0 {
            out.push(Piece::Text(", ".to_owned()));
        }
        encoded_value(r, out, depth)?;
    }
    out.push(Piece::Text("}".to_owned()));
    Some(())
}

fn encoded_annotation(r: &mut Reader<'_>, out: &mut Vec<Piece>, depth: u32) -> Option<()> {
    let ty = u32::try_from(r.uleb()?).unwrap_or(NO_INDEX);
    let n = r.uleb()?;
    out.push(Piece::Text("@".to_owned()));
    out.push(Piece::Type(ty));
    out.push(Piece::Text("(".to_owned()));
    for i in 0..n.min(65536) {
        if i > 0 {
            out.push(Piece::Text(", ".to_owned()));
        }
        let name = u32::try_from(r.uleb()?).unwrap_or(NO_INDEX);
        out.push(Piece::Str(name));
        out.push(Piece::Text(" = ".to_owned()));
        encoded_value(r, out, depth)?;
    }
    out.push(Piece::Text(")".to_owned()));
    Some(())
}

/// An `encoded_array` at the start of `data`: its length and text.
fn encoded_array_text(data: &[u8]) -> Option<(usize, Vec<Piece>)> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    encoded_array(&mut r, &mut out, 0)?;
    Some((r.pos(), out))
}

// ---------------------------------------------------------------------------
// Data sections

#[derive(Clone)]
struct Section {
    dex: Dex,
    kind: u16,
    offset: u32,
    count: u32,
    end: u64,
    entry: Span,
}

/// Whether items of `kind` are 4-byte aligned.
fn aligned(kind: u16) -> bool {
    matches!(
        kind,
        TYPE_TYPE_LIST
            | TYPE_ANNOTATION_SET_REF_LIST
            | TYPE_ANNOTATION_SET
            | TYPE_CODE
            | TYPE_ANNOTATIONS_DIRECTORY
            | TYPE_CALL_SITE_ID
            | TYPE_METHOD_HANDLE
            | TYPE_HIDDENAPI
    )
}

/// The length of the item of `kind` at the start of `data`.
fn item_len(kind: u16, data: &[u8]) -> Option<usize> {
    let mut r = Reader::new(data);
    match kind {
        TYPE_CALL_SITE_ID => return Some(4),
        TYPE_METHOD_HANDLE => return Some(8),
        TYPE_TYPE_LIST => {
            let n = usize::try_from(r.int::<u32>(LE)?).ok()?;
            r.bytes(n.checked_mul(2)?)?;
        }
        TYPE_ANNOTATION_SET_REF_LIST | TYPE_ANNOTATION_SET => {
            let n = usize::try_from(r.int::<u32>(LE)?).ok()?;
            r.bytes(n.checked_mul(4)?)?;
        }
        TYPE_STRING_DATA => {
            r.uleb()?;
            r.cstr()?;
        }
        TYPE_CLASS_DATA => {
            let mut counts = [0u64; 4];
            for c in &mut counts {
                *c = r.uleb()?;
            }
            for (group, &count) in counts.iter().enumerate() {
                for _ in 0..count.min(1 << 20) {
                    r.uleb()?;
                    r.uleb()?;
                    if group >= 2 {
                        r.uleb()?;
                    }
                }
            }
        }
        TYPE_CODE => {
            // registers_size, ins_size, outs_size, tries_size
            r.bytes(6)?;
            let tries = r.int::<u16>(LE)?;
            r.int::<u32>(LE)?;
            let insns = usize::try_from(r.int::<u32>(LE)?).ok()?;
            r.bytes(insns.checked_mul(2)?)?;
            if tries > 0 {
                if insns % 2 == 1 {
                    r.bytes(2)?;
                }
                r.bytes(usize::from(tries).checked_mul(8)?)?;
                let n = handlers_len(r.rest())?;
                r.bytes(n)?;
            }
        }
        TYPE_DEBUG_INFO => {
            r.uleb()?;
            let params = r.uleb()?;
            for _ in 0..params.min(65536) {
                r.uleb()?;
            }
            loop {
                match r.u8()? {
                    0x00 => break,
                    0x01 | 0x05 | 0x06 | 0x09 => {
                        r.uleb()?;
                    }
                    0x02 => {
                        r.sleb()?;
                    }
                    0x03 => {
                        r.uleb()?;
                        r.uleb()?;
                        r.uleb()?;
                    }
                    0x04 => {
                        r.uleb()?;
                        r.uleb()?;
                        r.uleb()?;
                        r.uleb()?;
                    }
                    _ => {}
                }
            }
        }
        TYPE_ANNOTATION => {
            r.u8()?;
            encoded_annotation(&mut r, &mut Vec::new(), 0)?;
        }
        TYPE_ENCODED_ARRAY => {
            encoded_array(&mut r, &mut Vec::new(), 0)?;
        }
        TYPE_ANNOTATIONS_DIRECTORY => {
            r.int::<u32>(LE)?;
            let mut n = 0usize;
            for _ in 0..3 {
                n = n.checked_add(usize::try_from(r.int::<u32>(LE)?).ok()?)?;
            }
            r.bytes(n.checked_mul(8)?)?;
        }
        TYPE_HIDDENAPI => {
            let size = usize::try_from(r.int::<u32>(LE)?).ok()?;
            return (size >= 4 && size <= data.len()).then_some(size);
        }
        _ => return None,
    }
    Some(r.pos())
}

async fn section(cx: Cx, s: Section) -> Result<()> {
    let start = u64::from(s.offset);
    let region = s
        .dex
        .file
        .sub(start, s.end.saturating_sub(start).min(MAX_SECTION));
    let data = cx.read_avail(region).await?;
    let block = cx.block(s.entry).await?;
    MapItem::layout(&mut Fields::emitting(&cx, &block, LE), &())?;
    let mut pos = 0usize;
    let count = if s.kind == TYPE_HIDDENAPI { 1 } else { s.count };
    for i in 0..count {
        if aligned(s.kind) {
            let next = pos.next_multiple_of(4);
            if next > pos && next <= data.len() {
                cx.push(
                    Node::new("padding")
                        .span(region.sub(to_u64(pos), to_u64(next.saturating_sub(pos))))
                        .desc("Aligns the next item to 4 bytes"),
                )
                .await;
            }
            pos = next;
        }
        let rest = data.get(pos..).unwrap_or_default();
        let Some(len) = item_len(s.kind, rest) else {
            cx.diag(
                Diagnostic::malformed(format!("item {i} could not be parsed"))
                    .at(region.tail(to_u64(pos))),
            );
            break;
        };
        let offset = s
            .offset
            .saturating_add(u32::try_from(pos).unwrap_or(u32::MAX));
        let span = region.sub(to_u64(pos), to_u64(len));
        let item = rest.get(..len).unwrap_or_default();
        let (name, summary) = item_label(&cx, &s.dex, s.kind, item, offset).await;
        cx.push(Node::new(name).span(span).maybe_summary(summary).lazy(
            crate::expander!(self::item_fields: (Dex, u16, u32)),
            (s.dex.clone(), s.kind, offset),
        ))
        .await;
        pos = pos.saturating_add(len.max(1));
        cx.progress(i.into(), count.into());
    }
    Ok(())
}

/// A name and summary for a data item, from its bytes.
async fn item_label(
    cx: &Cx,
    dex: &DexInfo,
    kind: u16,
    data: &[u8],
    offset: u32,
) -> (String, String) {
    let name = format!("{offset:#x}");
    let mut r = Reader::new(data);
    match kind {
        TYPE_STRING_DATA => {
            r.uleb();
            let s = r.cstr().map(mutf8).unwrap_or_default();
            (name, format!("{:?}", clip(&s, 120)))
        }
        TYPE_TYPE_LIST => {
            let types = dex.type_list(cx, offset).await;
            (name, format!("({})", types.join(", ")))
        }
        TYPE_CODE => {
            let regs = u16_le(data, 0).unwrap_or(0);
            let tries = u16_le(data, 6).unwrap_or(0);
            let insns = u32_le(data, 12).unwrap_or(0);
            (
                name,
                format!("{regs} registers, {insns} code units, {tries} try blocks"),
            )
        }
        TYPE_CLASS_DATA => {
            let mut counts = [0u64; 4];
            for c in &mut counts {
                *c = r.uleb().unwrap_or(0);
            }
            (
                name,
                format!(
                    "{} static + {} instance fields, {} direct + {} virtual methods",
                    counts[0], counts[1], counts[2], counts[3]
                ),
            )
        }
        TYPE_ANNOTATION => {
            let vis = r.u8().unwrap_or(0);
            let mut out = Vec::new();
            let _ = encoded_annotation(&mut r, &mut out, 0);
            (
                name,
                format!(
                    "{} {}",
                    lookup(VISIBILITY, vis.into()).unwrap_or("?"),
                    clip(&dex.render(cx, &out).await, 200)
                ),
            )
        }
        TYPE_ENCODED_ARRAY => {
            let mut out = Vec::new();
            let _ = encoded_array(&mut r, &mut out, 0);
            (name, clip(&dex.render(cx, &out).await, 200))
        }
        TYPE_ANNOTATION_SET | TYPE_ANNOTATION_SET_REF_LIST => {
            let n = u32_le(data, 0).unwrap_or(0);
            (name, format!("{n} entries"))
        }
        TYPE_DEBUG_INFO => {
            let line = r.uleb().unwrap_or(0);
            (name, format!("starts at line {line}"))
        }
        TYPE_METHOD_HANDLE => {
            let ty = u16_le(data, 0).unwrap_or(0);
            (name, name_or(METHOD_HANDLE_TYPE, ty.into(), "type"))
        }
        _ => (name, String::new()),
    }
}

/// The fields of the data item of `kind` at file offset `offset`.
async fn item_fields(cx: Cx, (dex, kind, offset): (Dex, u16, u32)) -> Result<()> {
    let span = dex.file.tail(offset.into()).sub(0, 0x10_0000);
    let data = cx.read_avail(span).await?;
    let Some(len) = item_len(kind, &data) else {
        return Err(Diagnostic::malformed("item could not be parsed").at(span.sub(0, 1)));
    };
    let data = data.get(..len).unwrap_or_default();
    let span = span.sub(0, to_u64(len));
    let mut r = Reader::new(data);
    let field = |start: usize, r: &Reader<'_>| {
        span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)))
    };
    match kind {
        TYPE_STRING_DATA => {
            let s = r.pos();
            let units = r.uleb().unwrap_or(0);
            cx.emit(
                Node::new("utf16_size")
                    .span(field(s, &r))
                    .value(uint(units, 32))
                    .desc("Length in UTF-16 code units"),
            );
            let s = r.pos();
            let bytes = r.cstr().unwrap_or_default();
            cx.emit(
                Node::new("data")
                    .span(span.sub(to_u64(s), to_u64(bytes.len())))
                    .value(text(mutf8(bytes)))
                    .desc("Modified UTF-8"),
            );
            cx.emit(Node::new("terminator").span(span.sub(to_u64(r.pos().saturating_sub(1)), 1)));
        }
        TYPE_TYPE_LIST | TYPE_ANNOTATION_SET_REF_LIST | TYPE_ANNOTATION_SET => {
            let n = r.int::<u32>(LE).unwrap_or(0);
            cx.emit(Node::new("size").span(span.sub(0, 4)).value(uint(n, 32)));
            let width = if kind == TYPE_TYPE_LIST { 2usize } else { 4 };
            for i in 0..usize::try_from(n).unwrap_or(0) {
                let at = 4usize.saturating_add(i.saturating_mul(width));
                let entry = span.sub(to_u64(at), to_u64(width));
                let node = if kind == TYPE_TYPE_LIST {
                    let t = u16_le(data, at).unwrap_or(0);
                    Node::new(format!("type_idx[{i}]"))
                        .span(entry)
                        .value(uint(t, 16))
                        .summary(dex.type_name(&cx, t.into()).await)
                } else {
                    let off = u32_le(data, at).unwrap_or(0);
                    let mut node = Node::new(format!("#{i}")).span(entry).value(hex(off, 32));
                    if off != 0 {
                        let target_kind = if kind == TYPE_ANNOTATION_SET {
                            TYPE_ANNOTATION
                        } else {
                            TYPE_ANNOTATION_SET
                        };
                        node = node.target(dex.file.sub(off.into(), 0)).lazy(
                            crate::expander!(self::item_fields: (Dex, u16, u32)),
                            (dex.clone(), target_kind, off),
                        );
                        if target_kind == TYPE_ANNOTATION {
                            let d = cx.read_avail(dex.file.sub(off.into(), 0x1000)).await?;
                            let (_, summary) =
                                item_label(&cx, &dex, TYPE_ANNOTATION, &d, off).await;
                            node = node.summary(summary);
                        }
                    }
                    node
                };
                cx.push(node).await;
            }
        }
        TYPE_CLASS_DATA => {
            let names = [
                "static_fields_size",
                "instance_fields_size",
                "direct_methods_size",
                "virtual_methods_size",
            ];
            let mut counts = [0u64; 4];
            for (c, name) in counts.iter_mut().zip(names) {
                let s = r.pos();
                *c = r.uleb().unwrap_or(0);
                cx.emit(Node::new(name).span(field(s, &r)).value(uint(*c, 32)));
            }
            for (group, &count) in counts.iter().enumerate() {
                let mut index = 0u32;
                for _ in 0..count {
                    let s = r.pos();
                    let (Some(diff), Some(access)) = (r.uleb(), r.uleb()) else {
                        break;
                    };
                    let code = if group >= 2 { r.uleb().unwrap_or(0) } else { 0 };
                    index = index.saturating_add(u32::try_from(diff).unwrap_or(u32::MAX));
                    let (set, _) = decode_flags(ACCESS, access);
                    let (name, mut summary) = if group >= 2 {
                        let (class, method) = dex.method(&cx, index).await;
                        (
                            format!("{}->{method}", java_name(&class)),
                            set.join(" ").to_lowercase(),
                        )
                    } else {
                        (dex.field(&cx, index).await, set.join(" ").to_lowercase())
                    };
                    if code != 0 {
                        summary.push_str(&format!(", code at {code:#x}"));
                    }
                    let mut node = Node::new(name)
                        .span(field(s, &r))
                        .value(text(format!(
                            "{}_idx_diff {diff}, access {access:#x}{}",
                            if group >= 2 { "method" } else { "field" },
                            if group >= 2 {
                                format!(", code_off {code:#x}")
                            } else {
                                String::new()
                            }
                        )))
                        .summary(summary);
                    if code != 0 {
                        node = node.target(dex.file.sub(code, 16)).lazy(
                            crate::expander!(self::code_item: (Dex, u64)),
                            (dex.clone(), code),
                        );
                    }
                    cx.push(node).await;
                }
            }
        }
        TYPE_CODE => {
            code_item(cx, (dex, offset.into())).await?;
        }
        TYPE_DEBUG_INFO => debug_info(&cx, &dex, span, data).await,
        TYPE_ANNOTATION => {
            let vis = r.u8().unwrap_or(0);
            cx.emit(
                Node::new("visibility")
                    .span(span.sub(0, 1))
                    .value(Value::Enum {
                        raw: vis.into(),
                        bits: 8,
                        name: lookup(VISIBILITY, vis.into()),
                    }),
            );
            annotation_body(&cx, &dex, span, data, 1).await;
        }
        TYPE_ENCODED_ARRAY => {
            let s = r.pos();
            let n = r.uleb().unwrap_or(0);
            cx.emit(Node::new("size").span(field(s, &r)).value(uint(n, 32)));
            for i in 0..n.min(65536) {
                let s = r.pos();
                let mut out = Vec::new();
                if encoded_value(&mut r, &mut out, 0).is_none() {
                    break;
                }
                cx.push(
                    Node::new(format!("[{i}]"))
                        .span(field(s, &r))
                        .value(text(dex.render(&cx, &out).await)),
                )
                .await;
            }
        }
        TYPE_ANNOTATIONS_DIRECTORY => {
            let block = cx.block(span.sub(0, 16)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            let class = f.u32("class_annotations_off").hex().emit()?;
            let fields = f.u32("fields_size").emit()?;
            let methods = f.u32("annotated_methods_size").emit()?;
            let params = f.u32("annotated_parameters_size").emit()?;
            if class != 0 {
                cx.emit(
                    Node::new("Class Annotations")
                        .target(dex.file.sub(class.into(), 0))
                        .lazy(
                            crate::expander!(self::item_fields: (Dex, u16, u32)),
                            (dex.clone(), TYPE_ANNOTATION_SET, class),
                        ),
                );
            }
            let mut at = 16usize;
            for (count, what) in [(fields, 0u8), (methods, 1), (params, 2)] {
                for _ in 0..count {
                    let idx = u32_le(data, at).unwrap_or(0);
                    let off = u32_le(data, at.saturating_add(4)).unwrap_or(0);
                    let (label, target_kind) = match what {
                        0 => (dex.field(&cx, idx).await, TYPE_ANNOTATION_SET),
                        1 => {
                            let (c, m) = dex.method(&cx, idx).await;
                            (format!("{c}->{m}"), TYPE_ANNOTATION_SET)
                        }
                        _ => {
                            let (c, m) = dex.method(&cx, idx).await;
                            (
                                format!("parameters of {c}->{m}"),
                                TYPE_ANNOTATION_SET_REF_LIST,
                            )
                        }
                    };
                    let mut node =
                        Node::new(label)
                            .span(span.sub(to_u64(at), 8))
                            .value(text(format!(
                                "{} {idx}, annotations_off {off:#x}",
                                if what == 0 { "field_idx" } else { "method_idx" }
                            )));
                    if off != 0 {
                        node = node.target(dex.file.sub(off.into(), 0)).lazy(
                            crate::expander!(self::item_fields: (Dex, u16, u32)),
                            (dex.clone(), target_kind, off),
                        );
                    }
                    cx.push(node).await;
                    at = at.saturating_add(8);
                }
            }
        }
        TYPE_CALL_SITE_ID => {
            let off = u32_le(data, 0).unwrap_or(0);
            cx.emit(
                Node::new("call_site_off")
                    .span(span.sub(0, 4))
                    .value(hex(off, 32))
                    .target(dex.file.sub(off.into(), 0))
                    .lazy(
                        crate::expander!(self::item_fields: (Dex, u16, u32)),
                        (dex.clone(), TYPE_ENCODED_ARRAY, off),
                    ),
            );
        }
        TYPE_METHOD_HANDLE => {
            let block = cx.block(span.sub(0, 8)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            let ty = f
                .u16("method_handle_type")
                .enumeration(METHOD_HANDLE_TYPE)
                .emit()?;
            f.u16("unused").emit()?;
            let id = u32::from(u16_le(data, 4).unwrap_or(0));
            let target = if ty <= 3 {
                dex.field(&cx, id).await
            } else {
                let (c, m) = dex.method(&cx, id).await;
                format!("{c}->{m}")
            };
            f.u16("field_or_method_id")
                .with(|_, n| n.summary(target.clone()))
                .emit()?;
            f.u16("unused").emit()?;
        }
        TYPE_HIDDENAPI => {
            let block = cx.block(span.sub(0, 4)).await?;
            Fields::emitting(&cx, &block, LE).u32("size").emit()?;
            let classes = usize::try_from(dex.header.classes.size).unwrap_or(0);
            let offsets = span.sub(4, to_u64(classes).saturating_mul(4));
            cx.emit(
                Node::new("offsets")
                    .span(offsets)
                    .summary(format!("{classes} classes"))
                    .desc(
                        "Per class def, offset of its flags from the start of this item (0: none)",
                    ),
            );
            let flags_at = offsets.end().saturating_sub(span.offset);
            if flags_at < span.len {
                cx.emit(
                    Node::new("flags").span(span.tail(flags_at)).desc(
                        "ULEB128 restriction flags per field and method, in class data order",
                    ),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

/// An `encoded_annotation` at `at` in `data`, element by element.
async fn annotation_body(cx: &Cx, dex: &DexInfo, span: Span, data: &[u8], at: usize) {
    let mut r = Reader::at(data, at);
    let s = r.pos();
    let ty = u32::try_from(r.uleb().unwrap_or(0)).unwrap_or(NO_INDEX);
    cx.emit(
        Node::new("type_idx")
            .span(span.sub(to_u64(s), to_u64(r.pos().saturating_sub(s))))
            .value(uint(ty, 32))
            .summary(dex.type_name(cx, ty).await),
    );
    let s = r.pos();
    let n = r.uleb().unwrap_or(0);
    cx.emit(
        Node::new("size")
            .span(span.sub(to_u64(s), to_u64(r.pos().saturating_sub(s))))
            .value(uint(n, 32)),
    );
    for _ in 0..n.min(65536) {
        let s = r.pos();
        let Some(name) = r.uleb() else { break };
        let mut out = Vec::new();
        if encoded_value(&mut r, &mut out, 0).is_none() {
            break;
        }
        let name = dex
            .string(cx, u32::try_from(name).unwrap_or(NO_INDEX))
            .await
            .unwrap_or_default();
        cx.push(
            Node::new(name)
                .span(span.sub(to_u64(s), to_u64(r.pos().saturating_sub(s))))
                .value(text(dex.render(cx, &out).await))
                .desc("annotation_element: name_idx and encoded_value"),
        )
        .await;
    }
}

/// A `debug_info_item`: header, then the state machine's opcodes with the
/// line and address they establish.
async fn debug_info(cx: &Cx, dex: &DexInfo, span: Span, data: &[u8]) {
    let mut r = Reader::new(data);
    let field = |s: usize, r: &Reader<'_>| span.sub(to_u64(s), to_u64(r.pos().saturating_sub(s)));
    let s = r.pos();
    let line_start = r.uleb().unwrap_or(0);
    cx.emit(
        Node::new("line_start")
            .span(field(s, &r))
            .value(uint(line_start, 32)),
    );
    let s = r.pos();
    let params = r.uleb().unwrap_or(0);
    cx.emit(
        Node::new("parameters_size")
            .span(field(s, &r))
            .value(uint(params, 32)),
    );
    for i in 0..params.min(65536) {
        let s = r.pos();
        let raw = r.uleb().unwrap_or(0);
        let name = match raw.checked_sub(1) {
            Some(idx) => dex
                .string(cx, u32::try_from(idx).unwrap_or(NO_INDEX))
                .await
                .unwrap_or_default(),
            None => "(no name)".to_owned(),
        };
        cx.push(
            Node::new(format!("parameter_names[{i}]"))
                .span(field(s, &r))
                .value(uint(raw, 32))
                .summary(name),
        )
        .await;
    }
    let mut line = i64::try_from(line_start).unwrap_or(0);
    let mut address = 0u64;
    let name_of = |v: u64| {
        v.checked_sub(1)
            .map(|i| u32::try_from(i).unwrap_or(NO_INDEX))
    };
    loop {
        let s = r.pos();
        let Some(op) = r.u8() else { break };
        let (mnemonic, mut pieces): (&str, Vec<Piece>) = match op {
            0x00 => ("DBG_END_SEQUENCE", Vec::new()),
            0x01 => {
                let d = r.uleb().unwrap_or(0);
                address = address.saturating_add(d);
                (
                    "DBG_ADVANCE_PC",
                    vec![Piece::Text(format!("+{d} → {address:#06x}"))],
                )
            }
            0x02 => {
                let d = r.sleb().unwrap_or(0);
                line = line.saturating_add(d);
                (
                    "DBG_ADVANCE_LINE",
                    vec![Piece::Text(format!("{d:+} → line {line}"))],
                )
            }
            0x03 | 0x04 => {
                let reg = r.uleb().unwrap_or(0);
                let name = r.uleb().unwrap_or(0);
                let ty = r.uleb().unwrap_or(0);
                let mut p = vec![Piece::Text(format!("v{reg} "))];
                if let Some(n) = name_of(name) {
                    p.push(Piece::Str(n));
                }
                p.push(Piece::Text(": ".to_owned()));
                if let Some(t) = name_of(ty) {
                    p.push(Piece::Type(t));
                }
                if op == 0x04 {
                    let sig = r.uleb().unwrap_or(0);
                    if let Some(n) = name_of(sig) {
                        p.push(Piece::Text(", signature ".to_owned()));
                        p.push(Piece::Str(n));
                    }
                }
                (
                    if op == 0x03 {
                        "DBG_START_LOCAL"
                    } else {
                        "DBG_START_LOCAL_EXTENDED"
                    },
                    p,
                )
            }
            0x05 | 0x06 => {
                let reg = r.uleb().unwrap_or(0);
                (
                    if op == 0x05 {
                        "DBG_END_LOCAL"
                    } else {
                        "DBG_RESTART_LOCAL"
                    },
                    vec![Piece::Text(format!("v{reg}"))],
                )
            }
            0x07 => ("DBG_SET_PROLOGUE_END", Vec::new()),
            0x08 => ("DBG_SET_EPILOGUE_BEGIN", Vec::new()),
            0x09 => {
                let name = r.uleb().unwrap_or(0);
                (
                    "DBG_SET_FILE",
                    name_of(name).map(Piece::Str).into_iter().collect(),
                )
            }
            _ => {
                let adjusted = u64::from(op.saturating_sub(0x0a));
                line = line
                    .saturating_add(i64::try_from(adjusted % 15).unwrap_or(0).saturating_sub(4));
                address = address.saturating_add(adjusted / 15);
                (
                    "special",
                    vec![Piece::Text(format!("line {line} at {address:#06x}"))],
                )
            }
        };
        if op >= 0x0a {
            pieces.insert(0, Piece::Text(format!("{op:#04x}: ")));
        }
        let summary = dex.render(cx, &pieces).await;
        cx.push(
            Node::new(mnemonic)
                .span(field(s, &r))
                .value(Value::UInt {
                    value: op.into(),
                    bits: 8,
                    radix: crate::value::Radix::Hex,
                })
                .maybe_summary(summary),
        )
        .await;
        if op == 0x00 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// ODEX

record! {
    struct OdexHeader {
        magic: ascii[8] "magic",
        dex_offset: u32 "dex_offset" .hex(),
        dex_length: u32 "dex_length" .hex(),
        deps_offset: u32 "deps_offset" .hex(),
        deps_length: u32 "deps_length" .hex(),
        opt_offset: u32 "opt_offset" .hex(),
        opt_length: u32 "opt_length" .hex(),
        flags: u32 "flags" .hex(),
        checksum: u32 "checksum" .hex() .desc("Adler-32 of the dependencies and optimized data"),
    }
}

pub async fn odex(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = file.sub(0, OdexHeader::SIZE);
    cx.emit(OdexHeader::node("Header", head, LE));
    let h = parse(&cx, head, LE, &(), OdexHeader::layout).await?;
    cx.annotate(format!(
        "Android optimized DEX, {:#x}-byte DEX",
        h.dex_length
    ));
    let dex = file.sub(h.dex_offset.into(), h.dex_length.into());
    cx.emit(embedded_as("DEX", input.nested(dex), &FORMAT));
    cx.emit(Node::new("Dependencies").span(file.sub(h.deps_offset.into(), h.deps_length.into())));
    cx.emit(Node::new("Optimized Data").span(file.sub(h.opt_offset.into(), h.opt_length.into())));
    Ok(())
}
