//! OSTree repository objects and flatpak single-file bundles.
//!
//! OSTree stores a file system tree as content-addressed objects, each a
//! GVariant value of a fixed type (see `data::gvariant`): commits
//! (`.commit`, `(a{sv}aya(say)sstayay)`: metadata, parent, related refs,
//! subject, body, timestamp and the root tree's two checksums), detached
//! commit metadata (`.commitmeta`, `a{sv}`), directory trees (`.dirtree`,
//! file and subdirectory names with checksums), directory metadata
//! (`.dirmeta`, owner, mode and extended attributes) and, in archive-mode
//! repositories, content objects (`.filez`: a big-endian header size,
//! the header GVariant with size, owner, mode, symlink target and
//! attributes, then the content as raw DEFLATE). A repository's `summary`
//! lists its refs with their commits; a static delta's `superblock`
//! describes the commit it leads to and the parts that carry its objects,
//! inline in its metadata or in separate files (a compression byte, then
//! the part).
//!
//! OSTree byte-swaps the numbers it stores to big-endian itself
//! (timestamps, owners, modes, sizes), except the commit sizes in a
//! summary, which are in the writer's order (little-endian here).
//!
//! A flatpak bundle (`flatpak build-bundle`) is a static delta superblock
//! with the parts inline and flatpak's metadata first: the key `flatpak`
//! holding 0xe5890001, the ref, the application's metadata keyfile, its
//! AppStream data (gzip) and icons.
//!
//! Commits, content objects, superblocks and bundles are recognised by
//! their structure; directory trees and metadata, detached metadata and
//! summaries, which a few bytes of structure do not tell apart from other
//! data, only when their file names agree (a second-phase probe).

use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::data::gvariant::{self as gv, Frame, Kind, Seg, Style, Ty};
use crate::formats::util::arcutil::unix_mode;
use crate::formats::util::datakit::{ByteReader, be_uint, le_uint};
use crate::formats::util::fmt::{clip, grouped_count};
use crate::formats::util::val;
use crate::formats::{Deep, DeepProbe, Format, Head, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::text::hex_lower;
use crate::value::{EnumTable, Value};

const COMMIT: &[u8] = b"(a{sv}aya(say)sstayay)";
const DIRTREE: &[u8] = b"(a(say)a(sayay))";
const DIRMETA: &[u8] = b"(uuua(ayay))";
const FILE_HEADER: &[u8] = b"(tuuuusa(ayay))";
const SUMMARY: &[u8] = b"(a(s(taya{sv}))a{sv})";
const METADATA: &[u8] = b"a{sv}";
const PAYLOAD: &[u8] = b"(a(uuu)aa(ayay)ayay)";
const SUPERBLOCK: &[u8] = b"(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))";

/// The value flatpak stores under the `flatpak` key of a bundle.
const FLATPAK_MAGIC: u32 = 0xe589_0001;

pub static COMMIT_OBJECT: Format = Format {
    name: "ostree-commit",
    title: "OSTree commit object",
    extensions: &["commit"],
    mime: "application/x-ostree-commit",
    probe: Probe::Custom(probe_commit),
    dissect: crate::expander!(dissect_commit: Input),
};

pub static FILE_OBJECT: Format = Format {
    name: "ostree-filez",
    title: "OSTree content object (archive mode)",
    extensions: &["filez"],
    mime: "application/x-ostree-filez",
    probe: Probe::Custom(probe_filez),
    dissect: crate::expander!(dissect_filez: Input),
};

pub static DIRTREE_OBJECT: Format = Format {
    name: "ostree-dirtree",
    title: "OSTree directory tree object",
    extensions: &["dirtree"],
    mime: "application/x-ostree-dirtree",
    probe: Probe::Custom(second_phase_only),
    dissect: crate::expander!(dissect_dirtree: Input),
};

pub static DIRMETA_OBJECT: Format = Format {
    name: "ostree-dirmeta",
    title: "OSTree directory metadata object",
    extensions: &["dirmeta"],
    mime: "application/x-ostree-dirmeta",
    probe: Probe::Custom(second_phase_only),
    dissect: crate::expander!(dissect_dirmeta: Input),
};

pub static COMMITMETA_OBJECT: Format = Format {
    name: "ostree-commitmeta",
    title: "OSTree detached commit metadata",
    extensions: &["commitmeta"],
    mime: "application/x-ostree-commitmeta",
    probe: Probe::Custom(second_phase_only),
    dissect: crate::expander!(dissect_commitmeta: Input),
};

pub static SUMMARY_FILE: Format = Format {
    name: "ostree-summary",
    title: "OSTree repository summary",
    extensions: &[],
    mime: "application/x-ostree-summary",
    probe: Probe::Custom(second_phase_only),
    dissect: crate::expander!(dissect_summary: Input),
};

pub static DELTA: Format = Format {
    name: "ostree-delta",
    title: "OSTree static delta superblock",
    extensions: &[],
    mime: "application/x-ostree-delta",
    probe: Probe::Custom(probe_superblock),
    dissect: crate::expander!(dissect_delta: Input),
};

pub static DELTA_PART: Format = Format {
    name: "ostree-delta-part",
    title: "OSTree static delta part",
    extensions: &[],
    mime: "application/x-ostree-delta-part",
    probe: Probe::Magic(&[(0, b"x\xfd7zXZ\0")]),
    dissect: crate::expander!(dissect_part: Input),
};

pub static DELTA_PAYLOAD: Format = Format {
    name: "ostree-delta-payload",
    title: "OSTree static delta part payload",
    extensions: &[],
    mime: "application/x-ostree-delta-payload",
    probe: Probe::Never,
    dissect: crate::expander!(dissect_payload: Input),
};

pub static FLATPAK: Format = Format {
    name: "flatpak",
    title: "Flatpak single-file bundle",
    extensions: &["flatpak"],
    mime: "application/vnd.flatpak",
    probe: Probe::Custom(probe_flatpak),
    dissect: crate::expander!(dissect_delta: Input),
};

pub static DIRTREE_DEEP: DeepProbe = DeepProbe {
    format: &DIRTREE_OBJECT,
    tail: false,
    over: &[],
    probe: deep_dirtree,
};

pub static DIRMETA_DEEP: DeepProbe = DeepProbe {
    format: &DIRMETA_OBJECT,
    tail: false,
    over: &[],
    probe: deep_dirmeta,
};

pub static COMMITMETA_DEEP: DeepProbe = DeepProbe {
    format: &COMMITMETA_OBJECT,
    tail: false,
    over: &[],
    probe: deep_commitmeta,
};

pub static SUMMARY_DEEP: DeepProbe = DeepProbe {
    format: &SUMMARY_FILE,
    tail: false,
    over: &[],
    probe: deep_summary,
};

pub static DELTA_DEEP: DeepProbe = DeepProbe {
    format: &DELTA,
    tail: false,
    over: &[],
    probe: deep_superblock,
};

const OBJECT_TYPES: EnumTable = &[
    (1, "file"),
    (2, "dirtree"),
    (3, "dirmeta"),
    (4, "commit"),
    (5, "tombstone commit"),
    (6, "commitmeta"),
    (7, "payload link"),
    (8, "file xattrs"),
    (9, "file xattrs link"),
];

const COMPRESSION: EnumTable = &[(0, "none"), (b'x' as u64, "xz")];

/// Metadata keys whose `t` values are big-endian Unix times.
const TIME_KEYS: &[&str] = &[
    "ostree.commit.timestamp",
    "ostree.summary.last-modified",
    "ostree.summary.expires",
];

/// Flatpak bundle metadata whose bytes are a file of their own.
const EMBEDDED_KEYS: &[&str] = &["appdata", "icon-64", "icon-128", "gpg-keys"];

const BE: Style = Style {
    endian: Endian::Big,
};

fn ty(sig: &[u8]) -> Result<Ty> {
    Ty::parse(sig).ok_or_else(|| {
        Diagnostic::internal(format!(
            "bad built-in type {}",
            String::from_utf8_lossy(sig)
        ))
    })
}

fn tuple_types(t: &Ty) -> &[Ty] {
    match &t.kind {
        Kind::Tuple(m) => m,
        _ => &[],
    }
}

// ---- probes ----

/// Directory trees and metadata, detached metadata and summaries have too
/// little structure to stand alone: only the second phase, with the file
/// name, identifies them (the `*_DEEP` probes).
fn second_phase_only(_: &Head<'_>) -> bool {
    false
}

/// The whole input, when the probe window holds it.
fn whole<'a>(h: &Head<'a>) -> Option<&'a [u8]> {
    (h.len_known && crate::bytes::to_u64(h.data.len()) == h.len).then_some(h.data)
}

fn valid_as(data: &[u8], sig: &[u8]) -> bool {
    Ty::parse(sig).is_some_and(|t| gv::valid(data, &t))
}

/// Whether `data` is a well-formed commit with real checksums.
fn commit_shape(data: &[u8]) -> bool {
    let Some(t) = Ty::parse(COMMIT) else {
        return false;
    };
    if !gv::valid(data, &t) {
        return false;
    }
    let Some(parts) = gv::split(data, tuple_types(&t)) else {
        return false;
    };
    let len = |i: usize| parts.get(i).map_or(usize::MAX, |p| p.len());
    matches!(len(1), 0 | 32) && len(6) == 32 && len(7) == 32
}

fn probe_commit(h: &Head<'_>) -> bool {
    whole(h).is_some_and(|d| d.len() >= 72 && commit_shape(d))
}

/// The header size and header of a content object.
fn filez_header(data: &[u8], len: u64, len_known: bool) -> Option<&[u8]> {
    let size = u64::from(u32::from_be_bytes(data.get(..4)?.try_into().ok()?));
    if data.get(4..8)? != [0, 0, 0, 0] || size < 26 {
        return None;
    }
    let end = size.checked_add(8)?;
    if len_known && end > len {
        return None;
    }
    data.get(8..usize::try_from(end).ok()?)
}

fn probe_filez(h: &Head<'_>) -> bool {
    let Some(header) = filez_header(h.data, h.len, h.len_known) else {
        return false;
    };
    let Some(t) = Ty::parse(FILE_HEADER) else {
        return false;
    };
    if !gv::valid(header, &t) {
        return false;
    }
    let Some(parts) = gv::split(header, tuple_types(&t)) else {
        return false;
    };
    let num = |i: usize| parts.get(i).map(|p| be_uint(p));
    let target = parts.get(5).map_or(0, |p| p.len());
    let size = num(0).unwrap_or(u64::MAX);
    match num(3).map(|m| m & 0o170_000) {
        // A regular file: no target; its content follows.
        Some(0o100_000) => target == 1,
        // A symbolic link: a target and nothing else.
        Some(0o120_000) => target > 1 && size == 0,
        _ => false,
    }
}

fn probe_superblock(h: &Head<'_>) -> bool {
    // `ostree static-delta generate` records the byte order first.
    h.at(0, b"ostree.endianness\0\0\0\0\0\0\0")
        && matches!(h.data.get(24..27), Some([b'l' | b'B', 0, b'y']))
}

fn probe_flatpak(h: &Head<'_>) -> bool {
    // The first entry: key "flatpak", then a variant holding the magic
    // (in the writer's byte order), a zero byte and its type, "u".
    h.at(0, b"flatpak\0")
        && (h.at(8, &FLATPAK_MAGIC.to_le_bytes()) || h.at(8, &FLATPAK_MAGIC.to_be_bytes()))
        && h.at(12, &[0, b'u'])
}

fn base_name<'a>(d: &Deep<'a>) -> Option<&'a str> {
    d.name.map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n))
}

fn deep_dirtree(d: &Deep<'_>) -> bool {
    d.extension_is("dirtree") && whole(d.head).is_some_and(|b| valid_as(b, DIRTREE))
}

fn deep_dirmeta(d: &Deep<'_>) -> bool {
    d.extension_is("dirmeta")
        && whole(d.head).is_some_and(|b| b.len() >= 12 && valid_as(b, DIRMETA))
}

fn deep_commitmeta(d: &Deep<'_>) -> bool {
    d.extension_is("commitmeta") && whole(d.head).is_some_and(|b| valid_as(b, METADATA))
}

fn deep_summary(d: &Deep<'_>) -> bool {
    if base_name(d) != Some("summary") {
        return false;
    }
    match whole(d.head) {
        Some(b) => valid_as(b, SUMMARY),
        // A summary larger than the window (a big remote's): its first ref
        // name, a NUL-terminated printable string padded to 8 bytes.
        None => {
            let data = d.head.data;
            data.iter()
                .take(256)
                .position(|&b| b == 0)
                .is_some_and(|n| {
                    n > 0
                        && data
                            .get(..n)
                            .is_some_and(|name| name.iter().all(|b| b.is_ascii_graphic()))
                        && data
                            .get(
                                n..crate::bytes::to_usize(gv::align_up(
                                    crate::bytes::to_u64(n).saturating_add(1),
                                    8,
                                )),
                            )
                            .is_some_and(|pad| pad.iter().all(|&b| b == 0))
                })
        }
    }
}

fn deep_superblock(d: &Deep<'_>) -> bool {
    base_name(d) == Some("superblock") && whole(d.head).is_some_and(|b| valid_as(b, SUPERBLOCK))
}

// ---- shared rendering ----

/// A checksum: 32 bytes shown as hex, or none.
async fn checksum(r: &mut ByteReader<'_>, name: &str, seg: Seg) -> Result<Node> {
    let node = Node::new(name.to_owned()).span(r.span(seg.start, seg.len()));
    Ok(match seg.len() {
        0 => node.summary("none"),
        32 => {
            let b = r.bytes(seg.start, 32).await?;
            node.value(Value::Text(hex_lower(&b)))
        }
        n => {
            let b = r.bytes(seg.start, n.min(64)).await?;
            node.value(Value::Bytes(b))
                .diag(Diagnostic::malformed(format!(
                    "checksum of {n} bytes, not 32"
                )))
        }
    })
}

/// A hex checksum for a summary, or `None`.
async fn checksum_text(r: &mut ByteReader<'_>, seg: Seg) -> Result<Option<String>> {
    Ok(if seg.len() == 32 {
        Some(hex_lower(&r.bytes(seg.start, 32).await?))
    } else {
        None
    })
}

async fn uint_be(r: &mut ByteReader<'_>, seg: Seg) -> Result<u64> {
    Ok(be_uint(&r.bytes(seg.start, seg.len().min(8)).await?))
}

fn time_value(secs: u64) -> Value {
    Value::utc(i64::try_from(secs).unwrap_or(i64::MAX))
}

async fn string(r: &mut ByteReader<'_>, seg: Seg) -> String {
    gv::string(r, seg, 0x200)
        .await
        .map(|(s, _)| s)
        .unwrap_or_default()
}

#[derive(Clone)]
struct Part {
    input: Input,
    seg: Seg,
    depth: u32,
}

/// A metadata dictionary (`a{sv}`), its entries under their keys.
async fn metadata(r: &mut ByteReader<'_>, input: Input, name: &str, seg: Seg, depth: u32) -> Node {
    let node = Node::new(name.to_owned()).span(r.span(seg.start, seg.len()));
    let count = match ty(METADATA) {
        Ok(t) => match &t.kind {
            Kind::Array(elem) => Frame::open(r, seg, elem).await.map(|f| f.count),
            _ => Ok(0),
        },
        Err(d) => Err(d),
    };
    match count {
        Err(d) => node.diag(d),
        Ok(0) => node.summary("empty"),
        Ok(n) => node.summary(grouped_count(n, "entry", "entries")).lazy(
            crate::expander!(self::metadata_entries: Part),
            Part { input, seg, depth },
        ),
    }
}

async fn metadata_entries(cx: Cx, part: Part) -> Result<()> {
    let mut r = ByteReader::new(&cx, part.input.span);
    let t = ty(METADATA)?;
    let Kind::Array(elem) = &t.kind else {
        return Ok(());
    };
    let Kind::Entry(k, v) = &elem.kind else {
        return Ok(());
    };
    let types = [k.as_ref().clone(), v.as_ref().clone()];
    let frame = Frame::open(&mut r, part.seg, elem).await?;
    cx.set_count(Count::Exact(frame.count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < frame.count {
        let at = i;
        cx.mark(move || at);
        let item = frame.item(&mut r, i).await?;
        let node = entry(&mut r, part.input, item, &types, part.depth, i).await;
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// One metadata entry.
async fn entry(
    r: &mut ByteReader<'_>,
    input: Input,
    item: Seg,
    types: &[Ty],
    depth: u32,
    index: u64,
) -> Node {
    let span = r.span(item.start, item.len());
    let fallback = Node::new(format!("[{index}]")).span(span);
    let parts = match gv::members(r, item, types).await {
        Ok(p) => p,
        Err(d) => return fallback.diag(d),
    };
    let (Some(&ks), Some(&vs)) = (parts.first(), parts.get(1)) else {
        return fallback;
    };
    let key = match gv::string(r, ks, 0x200).await {
        Ok((k, _)) if !k.is_empty() => k,
        Ok(_) => format!("[{index}]"),
        Err(d) => return fallback.diag(d),
    };
    let (inner, child) = match gv::variant(r, vs).await {
        Ok(v) => v,
        Err(d) => return Node::new(key).span(span).diag(d),
    };
    let sig = inner.signature();
    let child_span = r.span(child.start, child.len());
    if sig == "t" && child.len() == 8 && TIME_KEYS.contains(&key.as_str()) {
        return match uint_be(r, child).await {
            Ok(t) => Node::new(key)
                .span(span)
                .value(time_value(t))
                .summary("<t>"),
            Err(d) => Node::new(key).span(span).diag(d),
        };
    }
    if sig == "(yay)" && key.starts_with("deltas/") {
        // An inline part: its compression byte, then its data.
        let node = Node::new(clip(&key, 80)).span(span);
        let Some(types) = ty(b"(yay)").ok() else {
            return node;
        };
        return match gv::members(r, child, tuple_types(&types)).await {
            Ok(m) => match (m.first(), m.get(1)) {
                (Some(&method), Some(&body)) if method.len() == 1 => node
                    .summary(format!(
                        "inline delta part, {}",
                        grouped_count(body.len(), "byte", "bytes")
                    ))
                    .lazy(
                        crate::expander!(self::delta_part: PartData),
                        PartData {
                            input,
                            method: method.start,
                            body,
                        },
                    ),
                _ => node,
            },
            Err(d) => node.diag(d),
        };
    }
    if sig == "ay" && EMBEDDED_KEYS.contains(&key.as_str()) && !child.is_empty() {
        return embedded(key, input.nested(child_span))
            .span(span)
            .summary(format!(
                "<ay>, {}",
                grouped_count(child.len(), "byte", "bytes")
            ));
    }
    if sig == "y" && key == "ostree.endianness" && child.len() == 1 {
        let b = r.byte(child.start).await.unwrap_or(0);
        let order = match b {
            b'l' => "<y> little-endian",
            b'B' => "<y> big-endian",
            _ => "<y>",
        };
        return Node::new(key)
            .span(span)
            .value(Value::Text(char::from(b).to_string()))
            .summary(order)
            .desc("Byte order of the delta's sizes");
    }
    if sig == "u" && key == "flatpak" && child.len() == 4 {
        // Flatpak's bundle magic, in the writer's byte order.
        return match uint_in(r, child, Endian::Little).await {
            Ok(v) => {
                let v = if v == u64::from(FLATPAK_MAGIC.swap_bytes()) {
                    u64::from(FLATPAK_MAGIC)
                } else {
                    v
                };
                let node = Node::new(key)
                    .span(span)
                    .value(val::hex(v, 32))
                    .summary("<u> flatpak bundle magic");
                if v == u64::from(FLATPAK_MAGIC) {
                    node
                } else {
                    node.diag(Diagnostic::warning(
                        "not the flatpak bundle magic 0xe5890001",
                    ))
                }
            }
            Err(d) => Node::new(key).span(span).diag(d),
        };
    }
    let node = gv::node(r, key, child, &inner, BE, depth.saturating_add(1)).await;
    let summary = gv::typed_summary(&clip(&sig, 40), node.summary.as_deref());
    node.span(span).summary(summary)
}

/// Where a delta part's compression byte and data are.
#[derive(Clone)]
struct PartData {
    input: Input,
    method: u64,
    body: Seg,
}

/// A delta part: a compression byte, then the part's GVariant.
async fn delta_part(cx: Cx, part: PartData) -> Result<()> {
    let r = ByteReader::new(&cx, part.input.span);
    let b = cx.read(r.span(part.method, 1)).await?;
    let method = b.first().copied().unwrap_or(0);
    cx.emit(
        Node::new("Compression")
            .span(r.span(part.method, 1))
            .value(val::enumv(method, 8, COMPRESSION)),
    );
    let body = r.span(part.body.start, part.body.len());
    cx.emit(match method {
        0 => crate::formats::embedded_named(
            "Payload",
            part.input.nested(body),
            "ostree-delta-payload",
        ),
        b'x' => Node::new("Payload")
            .span(body)
            .lazy(crate::expander!(self::payload_xz: PartData), part),
        m => Node::new("Payload")
            .span(body)
            .diag(Diagnostic::unsupported(format!(
                "delta part compression {m:#04x}"
            ))),
    });
    Ok(())
}

/// An xz-compressed part's payload, decoded.
async fn payload_xz(cx: Cx, part: PartData) -> Result<()> {
    let span = part.input.span.sub(part.body.start, part.body.len());
    let decoded = crate::codec::decode_span(&cx, span, &Codec::Xz, None).await?;
    cx.annotate(format!("{:#x} bytes decompressed", decoded.span.len));
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    crate::formats::dissect_named(
        cx,
        (part.input.nested(decoded.span), "ostree-delta-payload"),
    )
    .await
}

/// A separate delta part file: the compression byte, then the data.
pub async fn dissect_part(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("OSTree static delta part");
    delta_part(
        cx,
        PartData {
            input,
            method: 0,
            body: Seg::new(1, input.span.len.max(1)),
        },
    )
    .await
}

/// A delta part's payload: modes, extended attributes, the raw data the
/// operations copy from, and the operations.
pub async fn dissect_payload(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let t = ty(PAYLOAD)?;
    let types = tuple_types(&t);
    let parts = gv::members(&mut r, Seg::new(0, input.span.len), types).await?;
    let [modes, attrs, raw, ops] = parts.as_slice() else {
        return Ok(());
    };
    let node = Node::new("Modes").span(r.span(modes.start, modes.len()));
    let elem = ty(b"(uuu)")?;
    cx.emit(match Frame::open(&mut r, *modes, &elem).await {
        Err(d) => node.diag(d),
        Ok(f) if f.count == 0 => node.summary("none"),
        Ok(f) => node
            .summary(grouped_count(f.count, "mode", "modes"))
            .desc("uid, gid and mode of each content object, referred to by index")
            .lazy(
                crate::expander!(self::payload_modes: List),
                List {
                    input,
                    seg: *modes,
                    sig: b"(uuu)",
                    endian: Endian::Big,
                },
            ),
    });
    if let Some(at) = types.get(1) {
        cx.emit(gv::node(&mut r, "Extended attributes".to_owned(), *attrs, at, BE, 0).await);
    }
    cx.emit(
        Node::new("Raw data")
            .span(r.span(raw.start, raw.len()))
            .summary(grouped_count(raw.len(), "byte", "bytes"))
            .desc("Object data the operations copy from"),
    );
    cx.emit(
        Node::new("Operations")
            .span(r.span(ops.start, ops.len()))
            .summary(grouped_count(ops.len(), "byte", "bytes"))
            .desc("Opcodes (S open-splice-and-close, o open, w write, r/R set/unset read source, c close, B bspatch) with variable-length arguments"),
    );
    cx.annotate(format!(
        "OSTree delta payload, {} of data, {} of operations",
        grouped_count(raw.len(), "byte", "bytes"),
        grouped_count(ops.len(), "byte", "bytes")
    ));
    Ok(())
}

async fn payload_modes(cx: Cx, list: List) -> Result<()> {
    let mut r = ByteReader::new(&cx, list.input.span);
    let elem = ty(list.sig)?;
    let frame = Frame::open(&mut r, list.seg, &elem).await?;
    cx.set_count(Count::Exact(frame.count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < frame.count {
        let at = i;
        cx.mark(move || at);
        let item = frame.item(&mut r, i).await?;
        let b = r.bytes(item.start, 12).await?;
        let field = |k: usize| be_uint(b.get(k..k.saturating_add(4)).unwrap_or_default());
        let mode = field(8);
        cx.push(
            Node::new(format!("[{i}]"))
                .span(r.span(item.start, item.len()))
                .value(val::oct(mode, 32))
                .summary(format!("{} {}:{}", unix_mode(mode), field(0), field(4))),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---- commit ----

pub async fn dissect_commit(cx: Cx, input: Input) -> Result<()> {
    let summary = commit_children(&cx, input, Seg::new(0, input.span.len)).await?;
    cx.annotate(format!("OSTree commit{summary}"));
    Ok(())
}

async fn commit_lazy(cx: Cx, part: Part) -> Result<()> {
    commit_children(&cx, part.input, part.seg).await.map(|_| ())
}

/// A commit's fields; returns `", subject, time"` for the summary.
async fn commit_children(cx: &Cx, input: Input, seg: Seg) -> Result<String> {
    let mut r = ByteReader::new(cx, input.span);
    let t = ty(COMMIT)?;
    let parts = gv::members(&mut r, seg, tuple_types(&t)).await?;
    let [meta, parent, related, subject, body, time, tree, dirmeta] = parts.as_slice() else {
        return Ok(String::new());
    };
    cx.emit(metadata(&mut r, input, "Metadata", *meta, 0).await);
    cx.emit(
        checksum(&mut r, "Parent", *parent)
            .await?
            .desc("Checksum of the parent commit"),
    );
    let types = tuple_types(&t);
    if let Some(rt) = types.get(2) {
        cx.emit(gv::node(&mut r, "Related".to_owned(), *related, rt, BE, 0).await);
    }
    let subject_text = string(&mut r, *subject).await;
    if let Some(st) = types.get(3) {
        cx.emit(gv::node(&mut r, "Subject".to_owned(), *subject, st, BE, 0).await);
        cx.emit(gv::node(&mut r, "Body".to_owned(), *body, st, BE, 0).await);
    }
    let mut out = String::new();
    if !subject_text.is_empty() {
        out.push_str(&format!(", {}", clip(&subject_text, 60)));
    }
    if time.len() == 8 {
        let secs = uint_be(&mut r, *time).await?;
        let value = time_value(secs);
        out.push_str(&format!(", {}", crate::render::value(&value)));
        cx.emit(
            Node::new("Timestamp")
                .span(r.span(time.start, 8))
                .value(value),
        );
    }
    cx.emit(
        checksum(&mut r, "Root tree", *tree)
            .await?
            .desc("Checksum of the root .dirtree object"),
    );
    cx.emit(
        checksum(&mut r, "Root metadata", *dirmeta)
            .await?
            .desc("Checksum of the root .dirmeta object"),
    );
    Ok(out)
}

// ---- commitmeta ----

pub async fn dissect_commitmeta(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let node = metadata(&mut r, input, "Metadata", Seg::new(0, input.span.len), 0).await;
    cx.annotate(format!(
        "OSTree detached metadata, {}",
        node.summary.clone().unwrap_or_default()
    ));
    cx.emit(node);
    Ok(())
}

// ---- dirtree ----

#[derive(Clone)]
struct List {
    input: Input,
    seg: Seg,
    sig: &'static [u8],
    /// Byte order of the numbers (a delta's own, for its entries).
    endian: Endian,
}

pub async fn dissect_dirtree(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let t = ty(DIRTREE)?;
    let types = tuple_types(&t);
    let parts = gv::members(&mut r, Seg::new(0, input.span.len), types).await?;
    let mut counts = Vec::new();
    for ((part, elem_ty), (name, sig)) in parts.iter().zip(types).zip([
        ("Files", b"(say)".as_slice()),
        ("Directories", b"(sayay)".as_slice()),
    ]) {
        let Kind::Array(elem) = &elem_ty.kind else {
            continue;
        };
        let node = Node::new(name).span(r.span(part.start, part.len()));
        match Frame::open(&mut r, *part, elem).await {
            Ok(f) => {
                counts.push(f.count);
                let node = node.summary(grouped_count(f.count, "entry", "entries"));
                cx.emit(if f.count == 0 {
                    node
                } else {
                    node.lazy(
                        crate::expander!(self::tree_entries: List),
                        List {
                            input,
                            seg: *part,
                            sig,
                            endian: Endian::Big,
                        },
                    )
                });
            }
            Err(d) => cx.emit(node.diag(d)),
        }
    }
    let (files, dirs) = (
        counts.first().copied().unwrap_or(0),
        counts.get(1).copied().unwrap_or(0),
    );
    cx.annotate(format!(
        "OSTree directory tree, {}, {}",
        grouped_count(files, "file", "files"),
        grouped_count(dirs, "directory", "directories")
    ));
    Ok(())
}

async fn tree_entries(cx: Cx, list: List) -> Result<()> {
    let mut r = ByteReader::new(&cx, list.input.span);
    let elem = ty(list.sig)?;
    let types = tuple_types(&elem);
    let frame = Frame::open(&mut r, list.seg, &elem).await?;
    cx.set_count(Count::Exact(frame.count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < frame.count {
        let at = i;
        cx.mark(move || at);
        let item = frame.item(&mut r, i).await?;
        let span = r.span(item.start, item.len());
        let node = match gv::members(&mut r, item, types).await {
            Err(d) => Node::new(format!("[{i}]")).span(span).diag(d),
            Ok(parts) => {
                let name = match parts.first() {
                    Some(&s) => string(&mut r, s).await,
                    None => String::new(),
                };
                let name = if name.is_empty() {
                    format!("[{i}]")
                } else {
                    clip(&name, 255)
                };
                let csum = match parts.get(1) {
                    Some(&c) => checksum_text(&mut r, c).await?,
                    None => None,
                };
                let node = Node::new(name).span(span);
                let node = match csum {
                    Some(c) => node.value(Value::Text(c)),
                    None => node.diag(Diagnostic::malformed("checksum is not 32 bytes")),
                };
                if parts.len() == 3 {
                    node.summary("directory").lazy(
                        crate::expander!(self::dir_entry: Part),
                        Part {
                            input: list.input,
                            seg: item,
                            depth: 0,
                        },
                    )
                } else {
                    node.summary("file")
                }
            }
        };
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn dir_entry(cx: Cx, part: Part) -> Result<()> {
    let mut r = ByteReader::new(&cx, part.input.span);
    let t = ty(b"(sayay)")?;
    let parts = gv::members(&mut r, part.seg, tuple_types(&t)).await?;
    let [name, tree, meta] = parts.as_slice() else {
        return Ok(());
    };
    if let Some(st) = tuple_types(&t).first() {
        cx.emit(gv::node(&mut r, "Name".to_owned(), *name, st, BE, 0).await);
    }
    cx.emit(
        checksum(&mut r, "Tree", *tree)
            .await?
            .desc("Checksum of the .dirtree object"),
    );
    cx.emit(
        checksum(&mut r, "Metadata", *meta)
            .await?
            .desc("Checksum of the .dirmeta object"),
    );
    Ok(())
}

// ---- dirmeta and file headers ----

async fn owner_fields(
    cx: &Cx,
    r: &mut ByteReader<'_>,
    uid: Seg,
    gid: Seg,
    mode: Seg,
) -> Result<(u64, u64, u64)> {
    let u = uint_be(r, uid).await?;
    let g = uint_be(r, gid).await?;
    let m = uint_be(r, mode).await?;
    cx.emit(
        Node::new("Uid")
            .span(r.span(uid.start, 4))
            .value(val::uint(u, 32)),
    );
    cx.emit(
        Node::new("Gid")
            .span(r.span(gid.start, 4))
            .value(val::uint(g, 32)),
    );
    cx.emit(
        Node::new("Mode")
            .span(r.span(mode.start, 4))
            .value(val::oct(m, 32))
            .summary(unix_mode(m)),
    );
    Ok((u, g, m))
}

/// Extended attributes, `a(ayay)`.
async fn xattrs(r: &mut ByteReader<'_>, input: Input, seg: Seg) -> Node {
    let node = Node::new("Extended attributes").span(r.span(seg.start, seg.len()));
    let Ok(t) = ty(b"a(ayay)") else {
        return node;
    };
    let Kind::Array(elem) = &t.kind else {
        return node;
    };
    match Frame::open(r, seg, elem).await {
        Err(d) => node.diag(d),
        Ok(f) if f.count == 0 => node.summary("none"),
        Ok(f) => node
            .summary(grouped_count(f.count, "attribute", "attributes"))
            .lazy(
                crate::expander!(self::xattr_list: List),
                List {
                    input,
                    seg,
                    sig: b"(ayay)",
                    endian: Endian::Big,
                },
            ),
    }
}

async fn xattr_list(cx: Cx, list: List) -> Result<()> {
    let mut r = ByteReader::new(&cx, list.input.span);
    let elem = ty(list.sig)?;
    let frame = Frame::open(&mut r, list.seg, &elem).await?;
    cx.set_count(Count::Exact(frame.count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < frame.count {
        let at = i;
        cx.mark(move || at);
        let item = frame.item(&mut r, i).await?;
        let span = r.span(item.start, item.len());
        let node = match gv::members(&mut r, item, tuple_types(&elem)).await {
            Err(d) => Node::new(format!("[{i}]")).span(span).diag(d),
            Ok(parts) => {
                let name = match parts.first() {
                    Some(&n) => {
                        let b = r.bytes(n.start, n.len().min(0x100)).await?;
                        let text = b.strip_suffix(&[0]).unwrap_or(&b);
                        String::from_utf8_lossy(text).into_owned()
                    }
                    None => String::new(),
                };
                let name = if name.is_empty() {
                    format!("[{i}]")
                } else {
                    name
                };
                match (parts.get(1), elem.kind.clone()) {
                    (Some(&v), Kind::Tuple(ts)) if ts.len() == 2 => {
                        let vt = ts.get(1).cloned().unwrap_or_else(Ty::variant);
                        gv::node(&mut r, name, v, &vt, BE, 0).await.span(span)
                    }
                    _ => Node::new(name).span(span),
                }
            }
        };
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

pub async fn dissect_dirmeta(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let t = ty(DIRMETA)?;
    let parts = gv::members(&mut r, Seg::new(0, input.span.len), tuple_types(&t)).await?;
    let [uid, gid, mode, attrs] = parts.as_slice() else {
        return Ok(());
    };
    let (u, g, m) = owner_fields(&cx, &mut r, *uid, *gid, *mode).await?;
    cx.emit(xattrs(&mut r, input, *attrs).await);
    cx.annotate(format!(
        "OSTree directory metadata, {} {u}:{g}",
        unix_mode(m)
    ));
    Ok(())
}

pub async fn dissect_filez(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let size = be_uint(&r.bytes(0, 4).await?);
    cx.emit(
        Node::new("Header size")
            .span(r.span(0, 4))
            .value(val::uint(size, 32)),
    );
    cx.emit(Node::new("Padding").span(r.span(4, 4)));
    let header = Seg::new(8, 8u64.saturating_add(size));
    if header.end > input.span.len {
        return Err(Diagnostic::truncated(
            r.span(8, size),
            input.span.len.saturating_sub(8),
        ));
    }
    let t = ty(FILE_HEADER)?;
    let parts = gv::members(&mut r, header, tuple_types(&t)).await?;
    let [len, uid, gid, mode, rdev, target, attrs] = parts.as_slice() else {
        return Ok(());
    };
    let file_size = uint_be(&mut r, *len).await?;
    cx.emit(
        Node::new("Size")
            .span(r.span(len.start, 8))
            .value(val::uint(file_size, 64)),
    );
    let (_, _, m) = owner_fields(&cx, &mut r, *uid, *gid, *mode).await?;
    let rd = uint_be(&mut r, *rdev).await?;
    cx.emit(
        Node::new("Rdev")
            .span(r.span(rdev.start, 4))
            .value(val::uint(rd, 32)),
    );
    let link = string(&mut r, *target).await;
    if let Some(st) = tuple_types(&t).get(5) {
        cx.emit(gv::node(&mut r, "Symlink target".to_owned(), *target, st, BE, 0).await);
    }
    cx.emit(xattrs(&mut r, input, *attrs).await);
    let body = r.span(header.end, input.span.len.saturating_sub(header.end));
    if m & 0o170_000 == 0o120_000 {
        cx.annotate(format!(
            "OSTree content object, symlink to {}",
            clip(&link, 80)
        ));
        if body.len > 0 {
            cx.emit(
                Node::new("Trailing data")
                    .span(body)
                    .diag(Diagnostic::warning("data after a symbolic link's header")),
            );
        }
    } else {
        cx.annotate(format!(
            "OSTree content object, {} {}",
            unix_mode(m),
            grouped_count(file_size, "byte", "bytes")
        ));
        cx.emit(content(
            "Content",
            input,
            body,
            Codec::Deflate,
            Some(file_size),
        ));
    }
    Ok(())
}

// ---- summary ----

pub async fn dissect_summary(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let t = ty(SUMMARY)?;
    let types = tuple_types(&t);
    let parts = gv::members(&mut r, Seg::new(0, input.span.len), types).await?;
    let [refs, meta] = parts.as_slice() else {
        return Ok(());
    };
    let node = Node::new("Refs").span(r.span(refs.start, refs.len()));
    let count = match types.first().map(|t| &t.kind) {
        Some(Kind::Array(elem)) => Frame::open(&mut r, *refs, elem).await,
        _ => Ok(Frame::open(&mut r, Seg::new(0, 0), &Ty::variant()).await?),
    };
    match count {
        Ok(f) => {
            cx.annotate(format!(
                "OSTree summary, {}",
                grouped_count(f.count, "ref", "refs")
            ));
            let node = node.summary(grouped_count(f.count, "ref", "refs"));
            cx.emit(if f.count == 0 {
                node
            } else {
                node.lazy(
                    crate::expander!(self::summary_refs: Part),
                    Part {
                        input,
                        seg: *refs,
                        depth: 0,
                    },
                )
            });
        }
        Err(d) => cx.emit(node.diag(d)),
    }
    cx.emit(metadata(&mut r, input, "Metadata", *meta, 0).await);
    Ok(())
}

async fn summary_refs(cx: Cx, part: Part) -> Result<()> {
    let mut r = ByteReader::new(&cx, part.input.span);
    let elem = ty(b"(s(taya{sv}))")?;
    let inner = ty(b"(taya{sv})")?;
    let frame = Frame::open(&mut r, part.seg, &elem).await?;
    cx.set_count(Count::Exact(frame.count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < frame.count {
        let at = i;
        cx.mark(move || at);
        let item = frame.item(&mut r, i).await?;
        let span = r.span(item.start, item.len());
        let node = match gv::members(&mut r, item, tuple_types(&elem)).await {
            Err(d) => Node::new(format!("[{i}]")).span(span).diag(d),
            Ok(parts) => {
                let name = match parts.first() {
                    Some(&s) => string(&mut r, s).await,
                    None => String::new(),
                };
                let name = if name.is_empty() {
                    format!("[{i}]")
                } else {
                    clip(&name, 255)
                };
                let node = Node::new(name).span(span);
                match parts.get(1) {
                    Some(&data) => {
                        let fields = gv::members(&mut r, data, tuple_types(&inner)).await;
                        let csum = match fields.as_ref().ok().and_then(|f| f.get(1)) {
                            Some(&c) => checksum_text(&mut r, c).await?,
                            None => None,
                        };
                        let node = match csum {
                            Some(c) => node.value(Value::Text(c)),
                            None => node,
                        };
                        node.lazy(
                            crate::expander!(self::summary_ref: Part),
                            Part {
                                input: part.input,
                                seg: data,
                                depth: 0,
                            },
                        )
                    }
                    None => node,
                }
            }
        };
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn summary_ref(cx: Cx, part: Part) -> Result<()> {
    let mut r = ByteReader::new(&cx, part.input.span);
    let t = ty(b"(taya{sv})")?;
    let parts = gv::members(&mut r, part.seg, tuple_types(&t)).await?;
    let [size, csum, meta] = parts.as_slice() else {
        return Ok(());
    };
    let b = r.bytes(size.start, 8).await?;
    cx.emit(
        Node::new("Commit size")
            .span(r.span(size.start, 8))
            .value(val::uint(le_uint(&b), 64))
            .desc("Size of the commit object, in the writer's byte order (read as little-endian)"),
    );
    cx.emit(checksum(&mut r, "Commit", *csum).await?);
    cx.emit(metadata(&mut r, part.input, "Metadata", *meta, 0).await);
    Ok(())
}

// ---- static deltas and flatpak bundles ----

/// The value of key `key` in a metadata dictionary, if it is one of its
/// first entries: its type and where it is.
async fn lookup(r: &mut ByteReader<'_>, seg: Seg, key: &str) -> Result<Option<(Ty, Seg)>> {
    let t = ty(METADATA)?;
    let Kind::Array(elem) = &t.kind else {
        return Ok(None);
    };
    let Kind::Entry(k, v) = &elem.kind else {
        return Ok(None);
    };
    let types = [k.as_ref().clone(), v.as_ref().clone()];
    let frame = Frame::open(r, seg, elem).await?;
    for i in 0..frame.count.min(64) {
        let item = frame.item(r, i).await?;
        let parts = gv::members(r, item, &types).await?;
        let (Some(&ks), Some(&vs)) = (parts.first(), parts.get(1)) else {
            continue;
        };
        if gv::string(r, ks, 0x100).await?.0 != key {
            continue;
        }
        return Ok(Some(gv::variant(r, vs).await?));
    }
    Ok(None)
}

/// A string in a metadata dictionary.
async fn lookup_string(r: &mut ByteReader<'_>, seg: Seg, key: &str) -> Option<String> {
    match lookup(r, seg, key).await.ok().flatten() {
        Some((t, child)) if t.kind == Kind::Basic(b's') => {
            gv::string(r, child, 0x200).await.ok().map(|(s, _)| s)
        }
        _ => None,
    }
}

/// A delta's byte order (`ostree.endianness`), little-endian if not
/// recorded.
async fn delta_endian(r: &mut ByteReader<'_>, seg: Seg) -> Endian {
    match lookup(r, seg, "ostree.endianness").await.ok().flatten() {
        Some((t, child)) if t.kind == Kind::Basic(b'y') && child.len() == 1 => {
            match r.byte(child.start).await {
                Ok(b'B') => Endian::Big,
                _ => Endian::Little,
            }
        }
        _ => Endian::Little,
    }
}

async fn uint_in(r: &mut ByteReader<'_>, seg: Seg, endian: Endian) -> Result<u64> {
    let b = r.bytes(seg.start, seg.len().min(8)).await?;
    Ok(match endian {
        Endian::Big => be_uint(&b),
        Endian::Little => le_uint(&b),
    })
}

pub async fn dissect_delta(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let t = ty(SUPERBLOCK)?;
    let types = tuple_types(&t);
    let parts = gv::members(&mut r, Seg::new(0, input.span.len), types).await?;
    let [meta, time, from, to, commit, prereq, entries, fallback] = parts.as_slice() else {
        return Ok(());
    };
    let flatpak_ref = lookup_string(&mut r, *meta, "ref").await;
    let endian = delta_endian(&mut r, *meta).await;
    let is_bundle = r.bytes(0, 8.min(input.span.len)).await? == b"flatpak\0";
    cx.emit(metadata(&mut r, input, "Metadata", *meta, 0).await);
    if time.len() == 8 {
        let secs = uint_be(&mut r, *time).await?;
        cx.emit(
            Node::new("Timestamp")
                .span(r.span(time.start, 8))
                .value(time_value(secs)),
        );
    }
    cx.emit(
        checksum(&mut r, "From", *from)
            .await?
            .desc("Commit the delta starts from (none: from scratch)"),
    );
    let to_text = checksum_text(&mut r, *to).await?;
    cx.emit(
        checksum(&mut r, "To", *to)
            .await?
            .desc("Commit the delta leads to"),
    );
    cx.emit(
        Node::new("Commit")
            .span(r.span(commit.start, commit.len()))
            .summary("the commit object the delta leads to")
            .lazy(
                crate::expander!(self::commit_lazy: Part),
                Part {
                    input,
                    seg: *commit,
                    depth: 0,
                },
            ),
    );
    if let Some(pt) = types.get(5) {
        cx.emit(gv::node(&mut r, "Prerequisite deltas".to_owned(), *prereq, pt, BE, 0).await);
    }
    for (name, seg, sig) in [
        ("Parts", *entries, b"(uayttay)".as_slice()),
        ("Fallback objects", *fallback, b"(yaytt)".as_slice()),
    ] {
        let elem = ty(sig)?;
        let node = Node::new(name).span(r.span(seg.start, seg.len()));
        cx.emit(match Frame::open(&mut r, seg, &elem).await {
            Err(d) => node.diag(d),
            Ok(f) if f.count == 0 => node.summary("none"),
            Ok(f) => node
                .summary(grouped_count(f.count, "entry", "entries"))
                .lazy(
                    crate::expander!(self::delta_entries: List),
                    List {
                        input,
                        seg,
                        sig,
                        endian,
                    },
                ),
        });
    }
    let target = match (&flatpak_ref, &to_text) {
        (Some(r), _) => format!(", {}", clip(r, 80)),
        (None, Some(c)) => format!(", to {}", c.get(..12).unwrap_or(c)),
        _ => String::new(),
    };
    cx.annotate(if is_bundle {
        format!("Flatpak bundle{target}")
    } else {
        format!("OSTree static delta{target}")
    });
    Ok(())
}

async fn delta_entries(cx: Cx, list: List) -> Result<()> {
    let mut r = ByteReader::new(&cx, list.input.span);
    let elem = ty(list.sig)?;
    let types = tuple_types(&elem);
    let frame = Frame::open(&mut r, list.seg, &elem).await?;
    cx.set_count(Count::Exact(frame.count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < frame.count {
        let at = i;
        cx.mark(move || at);
        let item = frame.item(&mut r, i).await?;
        let span = r.span(item.start, item.len());
        let node = match gv::members(&mut r, item, types).await {
            Err(d) => Node::new(format!("[{i}]")).span(span).diag(d),
            Ok(parts) if types.len() == 5 => {
                // (uayttay): version, checksum, size, uncompressed size, objects.
                let size = match parts.get(2) {
                    Some(&s) => uint_in(&mut r, s, list.endian).await?,
                    None => 0,
                };
                Node::new(format!("Part {i}"))
                    .span(span)
                    .summary(grouped_count(size, "byte", "bytes"))
                    .lazy(
                        crate::expander!(self::part_entry: List),
                        List {
                            input: list.input,
                            seg: item,
                            sig: list.sig,
                            endian: list.endian,
                        },
                    )
            }
            Ok(parts) => {
                // (yaytt): object type, checksum, size, uncompressed size.
                let kind = match parts.first() {
                    Some(&k) => u64::from(r.byte(k.start).await?),
                    None => 0,
                };
                let csum = match parts.get(1) {
                    Some(&c) => checksum_text(&mut r, c).await?,
                    None => None,
                };
                let mut sizes = Vec::new();
                for k in [2usize, 3] {
                    if let Some(&s) = parts.get(k) {
                        sizes.push(uint_in(&mut r, s, list.endian).await?);
                    }
                }
                let (size, usize_) = (
                    sizes.first().copied().unwrap_or(0),
                    sizes.get(1).copied().unwrap_or(0),
                );
                let node = Node::new(format!("[{i}]")).span(span).summary(format!(
                    "{}, {} ({} uncompressed)",
                    val::name_or(OBJECT_TYPES, kind, "type "),
                    grouped_count(size, "byte", "bytes"),
                    grouped_count(usize_, "byte", "bytes")
                ));
                match csum {
                    Some(c) => node.value(Value::Text(c)),
                    None => node,
                }
            }
        };
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn part_entry(cx: Cx, part: List) -> Result<()> {
    let mut r = ByteReader::new(&cx, part.input.span);
    let t = ty(b"(uayttay)")?;
    let parts = gv::members(&mut r, part.seg, tuple_types(&t)).await?;
    let [version, csum, size, usize_, objects] = parts.as_slice() else {
        return Ok(());
    };
    let v = uint_in(&mut r, *version, part.endian).await?;
    cx.emit(
        Node::new("Version")
            .span(r.span(version.start, 4))
            .value(val::uint(v, 32)),
    );
    cx.emit(
        checksum(&mut r, "Checksum", *csum)
            .await?
            .desc("SHA-256 of the part"),
    );
    let s = uint_in(&mut r, *size, part.endian).await?;
    cx.emit(
        Node::new("Size")
            .span(r.span(size.start, 8))
            .value(val::uint(s, 64)),
    );
    let u = uint_in(&mut r, *usize_, part.endian).await?;
    cx.emit(
        Node::new("Uncompressed size")
            .span(r.span(usize_.start, 8))
            .value(val::uint(u, 64)),
    );
    let count = objects.len() / 33;
    let node = Node::new("Objects")
        .span(r.span(objects.start, objects.len()))
        .summary(grouped_count(count, "object", "objects"));
    let node = if objects.len() % 33 != 0 {
        node.diag(Diagnostic::malformed(
            "object list is not a multiple of 33 bytes",
        ))
    } else {
        node
    };
    cx.emit(if count > 0 {
        node.lazy(
            crate::expander!(self::part_objects: Part),
            Part {
                input: part.input,
                seg: *objects,
                depth: 0,
            },
        )
    } else {
        node
    });
    Ok(())
}

/// A part's objects: a type byte and a checksum each.
async fn part_objects(cx: Cx, part: Part) -> Result<()> {
    let mut r = ByteReader::new(&cx, part.input.span);
    let count = part.seg.len() / 33;
    cx.set_count(Count::Exact(count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        let at = i;
        cx.mark(move || at);
        let pos = part.seg.start.saturating_add(i.saturating_mul(33));
        let b = r.bytes(pos, 33).await?;
        let kind = u64::from(b.first().copied().unwrap_or(0));
        let csum = hex_lower(b.get(1..).unwrap_or_default());
        cx.push(
            Node::new(format!("[{i}]"))
                .span(r.span(pos, 33))
                .value(Value::Text(csum))
                .summary(val::name_or(OBJECT_TYPES, kind, "type ")),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}
