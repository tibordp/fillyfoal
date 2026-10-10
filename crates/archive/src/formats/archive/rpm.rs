//! RPM packages.
//!
//! A 96-byte lead, a signature header (padded to 8 bytes), the main header,
//! and the payload (usually a compressed cpio archive). Both headers are an
//! index of `(tag, type, offset, count)` entries into a data store; entries
//! are listed with their tag names and decoded values.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::util::fmt;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const BE: Endian = Endian::Big;
const LEAD: u64 = 96;
const HEADER_MAGIC: &[u8] = b"\x8e\xad\xe8\x01";
/// Array items shown inline before switching to a paged child list.
const INLINE_ITEMS: u32 = 1;

pub static FORMAT: Format = Format {
    name: "rpm",
    title: "RPM package",
    extensions: &["rpm", "srpm"],
    mime: "application/x-rpm",
    probe: Probe::Magic(&[(0, b"\xed\xab\xee\xdb")]),
    dissect: crate::expander!(dissect: Input),
};

const PACKAGE_TYPE: EnumTable = &[(0, "binary"), (1, "source")];
const SIGNATURE_TYPE: EnumTable = &[(5, "header-style signature")];

const TYPES: EnumTable = &[
    (0, "NULL"),
    (1, "CHAR"),
    (2, "INT8"),
    (3, "INT16"),
    (4, "INT32"),
    (5, "INT64"),
    (6, "STRING"),
    (7, "BIN"),
    (8, "STRING_ARRAY"),
    (9, "I18NSTRING"),
];

const SIGNATURE_TAGS: EnumTable = &[
    (62, "HEADERSIGNATURES"),
    (267, "DSAHEADER"),
    (268, "RSAHEADER"),
    (269, "SHA1HEADER"),
    (270, "LONGSIZE"),
    (271, "LONGARCHIVESIZE"),
    (273, "SHA256HEADER"),
    (1000, "SIZE"),
    (1001, "LEMD5_1"),
    (1002, "PGP"),
    (1003, "LEMD5_2"),
    (1004, "MD5"),
    (1005, "GPG"),
    (1006, "PGP5"),
    (1007, "PAYLOADSIZE"),
    (1008, "RESERVEDSPACE"),
];

const TAGS: EnumTable = &[
    (61, "HEADERIMAGE"),
    (62, "HEADERSIGNATURES"),
    (63, "HEADERIMMUTABLE"),
    (100, "HEADERI18NTABLE"),
    (267, "DSAHEADER"),
    (268, "RSAHEADER"),
    (269, "SHA1HEADER"),
    (273, "SHA256HEADER"),
    (1000, "NAME"),
    (1001, "VERSION"),
    (1002, "RELEASE"),
    (1003, "EPOCH"),
    (1004, "SUMMARY"),
    (1005, "DESCRIPTION"),
    (1006, "BUILDTIME"),
    (1007, "BUILDHOST"),
    (1008, "INSTALLTIME"),
    (1009, "SIZE"),
    (1010, "DISTRIBUTION"),
    (1011, "VENDOR"),
    (1012, "GIF"),
    (1013, "XPM"),
    (1014, "LICENSE"),
    (1015, "PACKAGER"),
    (1016, "GROUP"),
    (1017, "CHANGELOG"),
    (1018, "SOURCE"),
    (1019, "PATCH"),
    (1020, "URL"),
    (1021, "OS"),
    (1022, "ARCH"),
    (1023, "PREIN"),
    (1024, "POSTIN"),
    (1025, "PREUN"),
    (1026, "POSTUN"),
    (1027, "OLDFILENAMES"),
    (1028, "FILESIZES"),
    (1029, "FILESTATES"),
    (1030, "FILEMODES"),
    (1033, "FILERDEVS"),
    (1034, "FILEMTIMES"),
    (1035, "FILEDIGESTS"),
    (1036, "FILELINKTOS"),
    (1037, "FILEFLAGS"),
    (1039, "FILEUSERNAME"),
    (1040, "FILEGROUPNAME"),
    (1044, "SOURCERPM"),
    (1045, "FILEVERIFYFLAGS"),
    (1046, "ARCHIVESIZE"),
    (1047, "PROVIDENAME"),
    (1048, "REQUIREFLAGS"),
    (1049, "REQUIRENAME"),
    (1050, "REQUIREVERSION"),
    (1053, "CONFLICTFLAGS"),
    (1054, "CONFLICTNAME"),
    (1055, "CONFLICTVERSION"),
    (1064, "RPMVERSION"),
    (1065, "TRIGGERSCRIPTS"),
    (1066, "TRIGGERNAME"),
    (1067, "TRIGGERVERSION"),
    (1068, "TRIGGERFLAGS"),
    (1069, "TRIGGERINDEX"),
    (1079, "VERIFYSCRIPT"),
    (1080, "CHANGELOGTIME"),
    (1081, "CHANGELOGNAME"),
    (1082, "CHANGELOGTEXT"),
    (1085, "PREINPROG"),
    (1086, "POSTINPROG"),
    (1087, "PREUNPROG"),
    (1088, "POSTUNPROG"),
    (1090, "OBSOLETENAME"),
    (1094, "COOKIE"),
    (1095, "FILEDEVICES"),
    (1096, "FILEINODES"),
    (1097, "FILELANGS"),
    (1098, "PREFIXES"),
    (1112, "PROVIDEFLAGS"),
    (1113, "PROVIDEVERSION"),
    (1114, "OBSOLETEFLAGS"),
    (1115, "OBSOLETEVERSION"),
    (1116, "DIRINDEXES"),
    (1117, "BASENAMES"),
    (1118, "DIRNAMES"),
    (1122, "OPTFLAGS"),
    (1124, "PAYLOADFORMAT"),
    (1125, "PAYLOADCOMPRESSOR"),
    (1126, "PAYLOADFLAGS"),
    (1131, "RHNPLATFORM"),
    (1132, "PLATFORM"),
    (1140, "FILECOLORS"),
    (1141, "FILECLASS"),
    (1142, "CLASSDICT"),
    (1143, "FILEDEPENDSX"),
    (1144, "FILEDEPENDSN"),
    (1145, "DEPENDSDICT"),
    (1146, "SOURCEPKGID"),
    (5011, "FILEDIGESTALGO"),
    (5062, "ENCODING"),
    (5092, "PAYLOADDIGEST"),
    (5093, "PAYLOADDIGESTALGO"),
];

record! {
    pub struct Lead {
        magic: bytes[4] "Magic",
        major: u8 "Major version",
        minor: u8 "Minor version",
        kind: u16 "Type" .enumeration(PACKAGE_TYPE),
        arch: u16 "Architecture number",
        name: ascii[66] "Name",
        os: u16 "OS number",
        signature: u16 "Signature type" .enumeration(SIGNATURE_TYPE),
        reserved: bytes[16] "Reserved",
    }
}

record! {
    pub struct Preamble {
        magic: bytes[3] "Magic",
        version: u8 "Version",
        reserved: bytes[4] "Reserved",
        entries: u32 "Index entries",
        size: u32 "Data store size" .with(|&s, n| n.summary(fmt::size(s.into()))),
    }
}

/// A header structure located in the file.
#[derive(Clone, Copy, Debug)]
struct Header {
    span: Span,
    entries: u32,
    index: Span,
    store: Span,
}

async fn locate(cx: &Cx, file: Span, at: u64) -> Result<Header> {
    let span = file.sub(at, Preamble::SIZE);
    let p = crate::fields::parse(cx, span, BE, &(), Preamble::layout).await?;
    let mut magic = p.magic.clone();
    magic.push(p.version);
    if magic != HEADER_MAGIC {
        return Err(Diagnostic::malformed("bad header magic").at(span));
    }
    let index_len = u64::from(p.entries).saturating_mul(16);
    let index = file.sub_exact(at.saturating_add(Preamble::SIZE), index_len)?;
    let store = file.sub(
        at.saturating_add(Preamble::SIZE).saturating_add(index_len),
        p.size.into(),
    );
    let total = Preamble::SIZE
        .saturating_add(index_len)
        .saturating_add(p.size.into());
    Ok(Header {
        span: file.sub(at, total),
        entries: p.entries,
        index,
        store,
    })
}

/// One index entry.
#[derive(Clone, Copy, Debug)]
struct Entry {
    tag: u32,
    kind: u32,
    offset: u32,
    count: u32,
}

fn entry_at(index: &[u8], i: usize) -> Option<Entry> {
    let at = i.checked_mul(16)?;
    Some(Entry {
        tag: u32_be(index, at)?,
        kind: u32_be(index, at.checked_add(4)?)?,
        offset: u32_be(index, at.checked_add(8)?)?,
        count: u32_be(index, at.checked_add(12)?)?,
    })
}

/// Decoded entry values: either one value or items.
enum Decoded {
    One(Value, Span),
    Items(Vec<(Value, Span)>),
}

/// Bytes scanned or copied per checkpoint while decoding values: every
/// entry may point at the whole (MiBs large) store.
const STEP: usize = 4096;

/// Bytes of a value copied into its node: every entry may point at the
/// whole store, so a node holds a bounded display copy (the node's target
/// spans the whole value).
const MAX_SHOWN: usize = 64 << 10;

/// A display copy of `bytes` (at most [`MAX_SHOWN`]), yielding every
/// [`STEP`] bytes.
async fn copy(cx: &Cx, bytes: &[u8]) -> Vec<u8> {
    let bytes = bytes.get(..MAX_SHOWN).unwrap_or(bytes);
    let mut out = Vec::with_capacity(bytes.len());
    for chunk in bytes.chunks(STEP) {
        cx.checkpoint().await;
        out.extend_from_slice(chunk);
    }
    out
}

/// A display copy of a string value: at most [`MAX_SHOWN`] bytes, marked
/// with `…` when cut.
fn shown_text(bytes: &[u8]) -> String {
    match bytes.get(..MAX_SHOWN) {
        Some(head) if head.len() < bytes.len() => {
            let mut s = String::from_utf8_lossy(head).into_owned();
            s.push('…');
            s
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Where the next NUL is from the start of every [`STEP`]-byte block of a
/// store, so that finding a string's end scans at most one block (entries
/// can all point at one long unterminated run).
struct Nuls {
    from_block: Vec<Option<usize>>,
}

impl Nuls {
    /// Indexes `store` (read from `span`), or reuses the index built for it.
    async fn of(cx: &Cx, span: Span, store: &[u8]) -> Arc<Nuls> {
        if let Some(found) = cx.cached::<Nuls>(span, "rpm-nuls") {
            return found;
        }
        let blocks = store.len().div_ceil(STEP);
        let mut from_block = vec![None; blocks];
        let mut next = None;
        for (b, slot) in from_block.iter_mut().enumerate().rev() {
            cx.checkpoint().await;
            let start = b.saturating_mul(STEP);
            let chunk = store
                .get(start..start.saturating_add(STEP).min(store.len()))
                .unwrap_or_default();
            if let Some(p) = chunk.iter().position(|&c| c == 0) {
                next = start.checked_add(p);
            }
            *slot = next;
        }
        let nuls = Arc::new(Nuls { from_block });
        cx.cache(span, "rpm-nuls", nuls.clone());
        nuls
    }

    /// The position of the first NUL at or after `at`.
    fn find(&self, store: &[u8], at: usize) -> Option<usize> {
        let block = at / STEP;
        let end = block
            .saturating_add(1)
            .saturating_mul(STEP)
            .min(store.len());
        if let Some(p) = store
            .get(at..end)
            .and_then(|c| c.iter().position(|&b| b == 0))
        {
            return at.checked_add(p);
        }
        self.from_block
            .get(block.saturating_add(1))
            .copied()
            .flatten()
    }
}

/// Reads a header's data store (up to the read limit) and indexes it.
async fn load_store(cx: &Cx, store: Span) -> Result<(Vec<u8>, Arc<Nuls>)> {
    let span = store.sub(0, cx.limits().max_read);
    let bytes = cx.read(span).await?;
    let nuls = Nuls::of(cx, span, &bytes).await;
    Ok((bytes, nuls))
}

/// A header's data store and its NUL index.
struct Store<'a> {
    bytes: &'a [u8],
    nuls: &'a Nuls,
}

/// Decodes up to `limit` items of an entry from the store.
async fn decode(cx: &Cx, e: &Entry, s: &Store<'_>, base: Span, limit: u32) -> Option<Decoded> {
    let store = s.bytes;
    let start = to_usize(e.offset.into());
    let n = e.count.min(limit);
    let mut items = Vec::new();
    let mut at = start;
    let span = |at: usize, len: usize| base.sub(to_u64(at), to_u64(len));
    match e.kind {
        1 | 2 => {
            let bytes = store.get(start..start.checked_add(to_usize(e.count.into()))?)?;
            if e.count != 1 {
                return Some(Decoded::One(
                    Value::Bytes(copy(cx, bytes).await),
                    span(start, bytes.len()),
                ));
            }
            let v = u64::from(*bytes.first()?);
            return Some(Decoded::One(uint(v, 64), span(start, 1)));
        }
        7 => {
            let bytes = store.get(start..start.checked_add(to_usize(e.count.into()))?)?;
            return Some(Decoded::One(
                Value::Bytes(copy(cx, bytes).await),
                span(start, bytes.len()),
            ));
        }
        3..=5 => {
            let width = match e.kind {
                3 => 2usize,
                4 => 4,
                _ => 8,
            };
            for i in 0..n {
                if i.is_multiple_of(1024) {
                    cx.checkpoint().await;
                }
                let v = match width {
                    2 => u64::from(u16_be(store, at)?),
                    4 => u64::from(u32_be(store, at)?),
                    _ => u64_be(store, at)?,
                };
                items.push((uint(v, 64), span(at, width)));
                at = at.checked_add(width)?;
            }
        }
        6 | 8 | 9 => {
            let n = if e.kind == 6 { 1 } else { n };
            for _ in 0..n {
                store.get(at..)?;
                let len = s.nuls.find(store, at)?.checked_sub(at)?;
                // One block scanned, plus the display copy.
                for _ in 0..=len.min(MAX_SHOWN) / STEP {
                    cx.checkpoint().await;
                }
                let shown = shown_text(store.get(at..at.checked_add(len)?)?);
                items.push((text(shown), span(at, len.saturating_add(1))));
                at = at.checked_add(len)?.checked_add(1)?;
            }
        }
        _ => return None,
    }
    if e.kind == 6 || (e.count == 1 && items.len() == 1) {
        let (v, s) = items.pop()?;
        return Some(Decoded::One(v, s));
    }
    Some(Decoded::Items(items))
}

/// A string or number tag's first value, for summaries.
async fn first_text(cx: &Cx, e: &Entry, store: &Store<'_>, base: Span) -> Option<String> {
    match decode(cx, e, store, base, 1).await? {
        Decoded::One(Value::Text(s), _) => Some(s),
        Decoded::Items(items) => match items.into_iter().next()?.0 {
            Value::Text(s) => Some(s),
            _ => None,
        },
        Decoded::One(Value::UInt { value, .. }, _) => Some(value.to_string()),
        _ => None,
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let lead_span = file.sub(0, LEAD);
    let lead = crate::fields::parse(&cx, lead_span, BE, &(), Lead::layout).await?;
    cx.emit(Lead::node("Lead", lead_span, BE).summary(lead.name.clone()));
    cx.annotate(format!("RPM package {}", lead.name));

    let sig = locate(&cx, file, LEAD).await?;
    cx.emit(header_node("Signature", sig, true));
    let main_at = LEAD
        .saturating_add(sig.span.len)
        .div_ceil(8)
        .saturating_mul(8);
    let main = locate(&cx, file, main_at).await?;
    cx.emit(header_node("Header", main, false));

    // Package identity and payload description from the main header.
    let index = cx.read(main.index).await?;
    let (bytes, nuls) = load_store(&cx, main.store).await?;
    let store = Store {
        bytes: &bytes,
        nuls: &nuls,
    };
    let mut tags = std::collections::BTreeMap::new();
    for i in 0..to_usize(main.entries.into()) {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        let Some(e) = entry_at(&index, i) else {
            break;
        };
        if matches!(e.tag, 1000..=1002 | 1022 | 1124 | 1125)
            && let Some(v) = first_text(&cx, &e, &store, main.store).await
        {
            tags.insert(e.tag, v);
        }
    }
    let get = |t: u32| tags.get(&t).cloned().unwrap_or_default();
    let nevra = format!("{}-{}-{}.{}", get(1000), get(1001), get(1002), get(1022));
    let format = tags
        .get(&1124)
        .cloned()
        .unwrap_or_else(|| "cpio".to_owned());
    let compressor = tags
        .get(&1125)
        .cloned()
        .unwrap_or_else(|| "gzip".to_owned());
    let payload = file.tail(main.span.end().saturating_sub(file.offset));
    cx.emit(embedded("Payload", input.nested(payload)).summary(format!(
        "{format}, {compressor}, {}",
        fmt::size(payload.len)
    )));
    cx.annotate(format!("RPM {nevra}, payload {format}/{compressor}"));
    Ok(())
}

fn header_node(name: &'static str, h: Header, signature: bool) -> Node {
    Node::new(name)
        .span(h.span)
        .summary(format!("{} entries, {}", h.entries, fmt::size(h.store.len)))
        .lazy(header, (h, signature))
}

async fn header(cx: Cx, (h, signature): (Header, bool)) -> Result<()> {
    cx.set_count(Count::Exact(u64::from(h.entries).saturating_add(2)));
    cx.emit(Preamble::node(
        "Header preamble",
        h.span.sub(0, Preamble::SIZE),
        BE,
    ));
    let index = cx.read(h.index).await?;
    let (bytes, nuls) = load_store(&cx, h.store).await?;
    let store = Store {
        bytes: &bytes,
        nuls: &nuls,
    };
    let table = if signature { SIGNATURE_TAGS } else { TAGS };
    for i in 0..to_usize(h.entries.into()) {
        let Some(e) = entry_at(&index, i) else {
            break;
        };
        let entry_span = h.index.sub(to_u64(i).saturating_mul(16), 16);
        let name = crate::value::lookup(table, e.tag.into())
            .map_or_else(|| format!("Tag {}", e.tag), str::to_owned);
        let kind = crate::value::lookup(TYPES, e.kind.into()).unwrap_or("?");
        let fields = Arc::new(vec![
            Node::new("Tag")
                .span(entry_span.sub(0, 4))
                .value(Value::Enum {
                    raw: e.tag.into(),
                    bits: 32,
                    name: crate::value::lookup(table, e.tag.into()),
                }),
            Node::new("Type")
                .span(entry_span.sub(4, 4))
                .value(Value::Enum {
                    raw: e.kind.into(),
                    bits: 32,
                    name: crate::value::lookup(TYPES, e.kind.into()),
                }),
            Node::new("Offset")
                .span(entry_span.sub(8, 4))
                .value(hex(e.offset, 64))
                .target(h.store.sub(e.offset.into(), 0)),
            Node::new("Count")
                .span(entry_span.sub(12, 4))
                .value(uint(e.count, 64)),
        ]);
        let mut node = Node::new(name).span(entry_span);
        match decode(&cx, &e, &store, h.store, INLINE_ITEMS).await {
            Some(Decoded::One(v, s)) => {
                node = node.value(present(e.tag, v, signature)).target(s);
                node = node.lazy(emit_nodes, fields);
            }
            Some(Decoded::Items(first)) => {
                let preview = match first.first() {
                    Some((Value::Text(t), _)) => format!(", first {t:?}"),
                    Some((Value::UInt { value, .. }, _)) => format!(", first {value}"),
                    _ => String::new(),
                };
                node = node
                    .summary(format!("{kind}[{}]{preview}", e.count))
                    .lazy(items, (h.store, e, fields));
            }
            None => {
                node = node
                    .summary(kind)
                    .diag(Diagnostic::malformed("value outside the data store"))
                    .lazy(emit_nodes, fields);
            }
        }
        cx.push(node).await;
    }
    cx.emit(Node::new("Data store").span(h.store));
    Ok(())
}

/// Interprets well-known numeric tags.
fn present(tag: u32, v: Value, signature: bool) -> Value {
    match (tag, &v, signature) {
        (1006 | 1008, Value::UInt { value, .. }, false) => Value::Timestamp {
            unix_seconds: i64::try_from(*value).unwrap_or(0),
        },
        _ => v,
    }
}

async fn items(cx: Cx, (store, e, fields): (Span, Entry, Arc<Vec<Node>>)) -> Result<()> {
    emit_nodes(cx.clone(), fields).await?;
    // Read only the part of the store this entry can use.
    let (bytes, nuls) = load_store(&cx, store).await?;
    let data = Store {
        bytes: &bytes,
        nuls: &nuls,
    };
    let Some(Decoded::Items(values)) = decode(&cx, &e, &data, store, e.count).await else {
        return Ok(());
    };
    for (i, (v, s)) in values.into_iter().enumerate() {
        cx.push(Node::new(format!("[{i}]")).span(s).value(v)).await;
    }
    Ok(())
}
