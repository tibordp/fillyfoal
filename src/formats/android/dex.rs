//! Android Dalvik executables: DEX (`dex\n035\0` ... `dex\n041\0`) and
//! compact DEX (`cdex001\0`), plus optimized ODEX wrappers (`dey\n036\0`).
//!
//! The header gives the location and size of every ID table; expanding a
//! table lists its entries in pages, resolving names through the string
//! and type tables with a few small reads per entry.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::binutil::{NodeExt, Reader, ellipsize, get_at, mutf8, name_or, text};
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, decode_flags, flag};

const LE: Endian = Endian::Little;
/// Longest string we look for a terminator in.
const MAX_STRING: u64 = 0x10000;

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

fn header(f: &mut Fields<'_>, (file, checks): &(Span, Option<(u32, bool)>)) -> Result<Header> {
    let file = *file;
    let compact = f.block().data.starts_with(b"cdex");
    f.ascii("magic", 8)
        .with(|_, n| n.summary(if compact { "compact DEX" } else { "DEX" }))
        .emit()?;
    f.u32("checksum")
        .hex()
        .desc("Adler-32 of everything after this field")
        .with(|&v, n| match checks {
            Some((computed, _)) if *computed == v => n.summary("valid"),
            Some((computed, _)) => n.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {computed:#010x}"
            ))),
            None => n,
        })
        .emit()?;
    f.bytes("signature", 20)
        .desc("SHA-1 of everything after this field")
        .emit()?;
    f.u32("file_size").hex().emit()?;
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

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x80)).await?;
    let compact = head.starts_with(b"cdex");
    let header_size = u64::from(u32_le(&head, 36).unwrap_or(0x70)).clamp(0x70, 0x88);
    let header_span = file.sub(0, if compact { 0x88 } else { header_size });

    // The checksum covers the whole file; verify it when that is cheap.
    let stored = u32_le(&head, 8).unwrap_or(0);
    let checks = if file.len <= 4 << 20 && !compact {
        let data = cx.read_avail(file.tail(12)).await?;
        Some((crate::codec::adler32(&data), true))
    } else {
        None
    };
    let mut node = struct_node("Header", header_span, LE, (file, checks), header);
    if let Some((computed, _)) = checks
        && computed != stored
    {
        node = node.diag(Diagnostic::warning("checksum mismatch"));
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

    if h.map_off != 0 {
        cx.emit(
            Node::new("Map List")
                .span(file.sub(h.map_off.into(), 4))
                .lazy(map_list, dex.clone()),
        );
    }
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

async fn map_list(cx: Cx, dex: Dex) -> Result<()> {
    let head = cx.read(dex.file.sub(dex.header.map_off.into(), 4)).await?;
    let n = u32_le(&head, 0).unwrap_or(0);
    let table = dex.file.sub(
        u64::from(dex.header.map_off).saturating_add(4),
        u64::from(n).saturating_mul(MapItem::SIZE),
    );
    let count = table.len / MapItem::SIZE;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = table.sub(i.saturating_mul(MapItem::SIZE), MapItem::SIZE);
        let item = parse(&cx, at, LE, &(), MapItem::layout).await?;
        cx.push(
            MapItem::node(name_or(MAP_TYPE, item.kind.into(), "type"), at, LE)
                .summary(format!("{} items at {:#x}", item.size, item.offset))
                .target(dex.file.sub(item.offset.into(), 0)),
        )
        .await;
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
                    Ok(s) => Node::new(format!("#{i}")).value(text(s)),
                    Err(e) => Node::new(format!("#{i}")).diag(e),
                }
                .target(target)
            }
            Kind::Type => {
                let name = dex.type_name(&cx, i).await;
                Node::new(format!("#{i}"))
                    .value(text(name.clone()))
                    .summary(java_name(&name))
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
        cx.emit(
            Node::new(name)
                .span(span)
                .value(Value::UInt {
                    value: value.into(),
                    bits: if span.len == 2 { 16 } else { 32 },
                    radix: if name.ends_with("_off") {
                        crate::value::Radix::Hex
                    } else {
                        crate::value::Radix::Dec
                    },
                })
                .maybe_summary(resolved),
        );
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
            let n = n.maybe_summary(ellipsize(&interfaces.join(", "), 120));
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
            Node::new("Class Data")
                .span(span.sub(0, 0))
                .lazy(class_data, (dex.clone(), span)),
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
                    node.target(item).lazy(code_item, (dex.clone(), code))
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
        ins: u16 "ins_size",
        outs: u16 "outs_size",
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
    if item.tries > 0 {
        let pad = if item.insns % 2 == 1 { 2 } else { 0 };
        let tries = dex.file.sub(
            insns
                .offset
                .saturating_sub(dex.file.offset)
                .saturating_add(insns.len)
                .saturating_add(pad),
            u64::from(item.tries).saturating_mul(8),
        );
        cx.emit(
            Node::new("tries")
                .span(tries)
                .summary(format!("{} try blocks", item.tries)),
        );
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
