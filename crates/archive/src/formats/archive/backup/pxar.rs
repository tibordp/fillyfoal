//! Proxmox file archives (`.pxar`), and the split pair of a metadata
//! archive (`.mpxar`) and a payload archive (`.ppxar`) written by Proxmox
//! Backup Server's client.
//!
//! A pxar archive is a sequence of items, each a 16-byte little-endian
//! header (a 64-bit type hash and the item's full size) and its content. A
//! file is an `ENTRY` (mode, flags, owner, mtime), its extended attributes,
//! ACL entries, file capabilities and quota project ID, then its `PAYLOAD`
//! (regular files), `SYMLINK` target or `DEVICE` numbers. A directory's
//! `ENTRY` and attributes are followed by its entries, each a `FILENAME`
//! and the entry's own items, and end with a `GOODBYE` table: one 24-byte
//! item per entry (the SipHash-2-4 of its name, its offset back from the
//! table and its size) arranged as a binary search tree, and a tail item
//! pointing back to the directory's `ENTRY`. A hard link after the first is
//! a `FILENAME` and a `HARDLINK` (the offset back to the first link's
//! `FILENAME`, and its path).
//!
//! The tree is read the way Proxmox's own accessor reads it: from the
//! goodbye table at the end of each directory, so listing a directory reads
//! only its table and its entries' heads, whatever their size. Every item is
//! also listed in file order ("Items"), which needs no goodbye table and so
//! still shows a truncated archive. Goodbye hashes are checked when the
//! table is expanded.
//!
//! Split archives (format version 2, `FORMAT_VERSION` first) keep file
//! contents in the `.ppxar`: the metadata archive has a `PAYLOAD_REF`
//! (offset of the payload's `PAYLOAD` header in the payload archive, and its
//! size) where a plain archive has the `PAYLOAD`. The payload archive is a
//! start marker, the `PAYLOAD` items (possibly with unreferenced padding
//! between them, from reused chunks) and a tail marker; its payloads are
//! listed and dissected, but which file each belongs to is only in the
//! metadata archive (a separate file).
//!
//! The item types and structures are from the `pxar` crate's
//! `format/mod.rs` and `format/acl.rs` and the entry flags from Proxmox
//! Backup's `pbs-client/src/pxar/flags.rs` (AGPL-3.0), read for facts
//! only, no code taken; the split layout from Proxmox Backup's
//! `docs/file-formats.rst`. Checked against archives written by
//! `pxar create` from proxmox-backup-client 3.4.9.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::emit_record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{unix_kind, unix_mode};
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{enumv, hex, text, uint};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;

const FORMAT_VERSION: u64 = 0x730f_6c75_df16_a40d;
const ENTRY: u64 = 0xd595_6474_e588_acef;
const ENTRY_V1: u64 = 0x11da_850a_1c1c_ceff;
const PRELUDE: u64 = 0xe309_d79d_9f7b_771b;
const FILENAME: u64 = 0x1670_1121_0639_17b3;
const SYMLINK: u64 = 0x27f9_71e7_dbf5_dc5f;
const DEVICE: u64 = 0x9fc9_e906_586d_5ce9;
const XATTR: u64 = 0x0dab_0229_b57d_cd03;
const ACL_USER: u64 = 0x2ce8_540a_457d_55b8;
const ACL_GROUP: u64 = 0x136e_3ece_b04c_03ab;
const ACL_GROUP_OBJ: u64 = 0x1086_8031_e958_2876;
const ACL_DEFAULT: u64 = 0xbbbb_1341_5a68_96f5;
const ACL_DEFAULT_USER: u64 = 0xc893_57b4_0532_cd1f;
const ACL_DEFAULT_GROUP: u64 = 0xf90a_8a58_1603_8ffe;
const FCAPS: u64 = 0x2da9_dd9d_b5f7_fb67;
const QUOTA_PROJID: u64 = 0xe075_40e8_2f7d_1cbb;
const HARDLINK: u64 = 0x5126_9c84_22bd_7275;
const PAYLOAD: u64 = 0x2814_7a1b_0b7c_1a25;
const PAYLOAD_REF: u64 = 0x419d_3d6b_c4ba_977e;
const GOODBYE: u64 = 0x2fec_4fa6_42d5_731d;
const GOODBYE_TAIL: u64 = 0xef5e_ed5b_753e_1555;
const PAYLOAD_START: u64 = 0x834c_68c2_194a_4ed2;
const PAYLOAD_TAIL: u64 = 0x6c72_b78b_984c_81b5;

/// SipHash-2-4 keys of the goodbye table's name hashes.
const HASH_KEY: (u64, u64) = (0x83ac_3f1c_fbb4_50db, 0xaa4f_1b68_7936_9fbd);

const ITEMS: EnumTable = &[
    (FORMAT_VERSION, "FORMAT_VERSION"),
    (ENTRY, "ENTRY"),
    (ENTRY_V1, "ENTRY (version 1)"),
    (PRELUDE, "PRELUDE"),
    (FILENAME, "FILENAME"),
    (SYMLINK, "SYMLINK"),
    (DEVICE, "DEVICE"),
    (XATTR, "XATTR"),
    (ACL_USER, "ACL_USER"),
    (ACL_GROUP, "ACL_GROUP"),
    (ACL_GROUP_OBJ, "ACL_GROUP_OBJ"),
    (ACL_DEFAULT, "ACL_DEFAULT"),
    (ACL_DEFAULT_USER, "ACL_DEFAULT_USER"),
    (ACL_DEFAULT_GROUP, "ACL_DEFAULT_GROUP"),
    (FCAPS, "FCAPS"),
    (QUOTA_PROJID, "QUOTA_PROJID"),
    (HARDLINK, "HARDLINK"),
    (PAYLOAD, "PAYLOAD"),
    (PAYLOAD_REF, "PAYLOAD_REF"),
    (GOODBYE, "GOODBYE"),
    (PAYLOAD_START, "PAYLOAD_START_MARKER"),
    (PAYLOAD_TAIL, "PAYLOAD_TAIL_MARKER"),
];

/// File attribute flags an `ENTRY` records (chattr and FAT attributes).
const ENTRY_FLAGS: FlagTable = &[
    flag(0x2000, "HIDDEN"),
    flag(0x4000, "SYSTEM"),
    flag(0x8000, "ARCHIVE"),
    flag(0x1_0000, "APPEND"),
    flag(0x2_0000, "NOATIME"),
    flag(0x4_0000, "COMPR"),
    flag(0x8_0000, "NOCOW"),
    flag(0x10_0000, "NODUMP"),
    flag(0x20_0000, "DIRSYNC"),
    flag(0x40_0000, "IMMUTABLE"),
    flag(0x80_0000, "SYNC"),
    flag(0x100_0000, "NOCOMP"),
    flag(0x200_0000, "PROJINHERIT"),
    flag(0x400_0000, "SUBVOLUME"),
    flag(0x800_0000, "SUBVOLUME_RO"),
];

pub static PXAR: Format = Format {
    name: "pxar",
    title: "Proxmox file archive",
    extensions: &["pxar"],
    mime: "application/x-proxmox-pxar",
    probe: Probe::Custom(probe_pxar),
    dissect: crate::expander!(dissect: Input),
};

pub static PXAR_META: Format = Format {
    name: "pxar-meta",
    title: "Proxmox file archive, metadata (split archive)",
    extensions: &["mpxar"],
    mime: "application/x-proxmox-mpxar",
    probe: Probe::Custom(probe_meta),
    dissect: crate::expander!(dissect: Input),
};

pub static PXAR_PAYLOAD: Format = Format {
    name: "pxar-payload",
    title: "Proxmox file archive, payloads (split archive)",
    extensions: &["ppxar"],
    mime: "application/x-proxmox-ppxar",
    probe: Probe::Custom(probe_payload),
    dissect: crate::expander!(dissect: Input),
};

fn header_at(b: &[u8], off: usize) -> Option<(u64, u64)> {
    Some((u64_le(b, off)?, u64_le(b, off.checked_add(8)?)?))
}

/// A plain (version 1) archive starts with the root directory's `ENTRY`.
fn probe_pxar(h: &Head<'_>) -> bool {
    matches!(header_at(h.data, 0), Some((ENTRY, 56) | (ENTRY_V1, 48)))
}

/// A version 2 archive starts with `FORMAT_VERSION` 2.
fn probe_meta(h: &Head<'_>) -> bool {
    header_at(h.data, 0) == Some((FORMAT_VERSION, 24)) && u64_le(h.data, 16) == Some(2)
}

fn probe_payload(h: &Head<'_>) -> bool {
    header_at(h.data, 0) == Some((PAYLOAD_START, 16))
}

record! {
    /// `Stat`: an `ENTRY`'s content.
    pub struct Stat {
        mode: u64 "Mode" .with(|&v, n| n.summary(format!("0o{v:o} {}", unix_mode(v)))),
        flags: u64 "Flags" .flags(ENTRY_FLAGS),
        uid: u32 "UID",
        gid: u32 "GID",
        secs: i64 "Modification time" .with(|&v, n| n.value(Value::Timestamp { unix_seconds: v })),
        nanos: u32 "Nanoseconds",
        _pad: u32 "Padding",
    }
}

record! {
    /// `Stat_V1`: an `ENTRY` of the first version (mtime in nanoseconds).
    pub struct StatV1 {
        mode: u64 "Mode" .with(|&v, n| n.summary(format!("0o{v:o} {}", unix_mode(v)))),
        flags: u64 "Flags" .flags(ENTRY_FLAGS),
        uid: u32 "UID",
        gid: u32 "GID",
        mtime: u64 "Modification time (ns)" .with(|&v, n| n.summary(format!("{}", v / 1_000_000_000))),
    }
}

/// What a directory listing needs to know about an entry.
#[derive(Default)]
struct Entry {
    name: Option<Vec<u8>>,
    /// The metadata items (filename, entry, attributes, and the item that
    /// ends a non-directory), as (type, span of the whole item).
    items: Vec<(u64, Span)>,
    mode: Option<u64>,
    payload: Option<Span>,
    payload_ref: Option<(u64, u64)>,
    symlink: Option<Vec<u8>>,
    device: Option<(u64, u64)>,
    hardlink: Option<Vec<u8>>,
    /// For a directory: where its entries (or its goodbye table) start.
    body: Option<u64>,
}

impl Entry {
    fn is_dir(&self) -> bool {
        self.mode.is_some_and(|m| m & 0o170_000 == 0o040_000)
    }

    fn display_name(&self, root: bool) -> String {
        let name = if root {
            "/".to_owned()
        } else {
            self.name.as_deref().map_or_else(
                || "?".to_owned(),
                |n| String::from_utf8_lossy(n).into_owned(),
            )
        };
        if self.is_dir() && !root {
            format!("{name}/")
        } else {
            name
        }
    }

    fn summary(&self) -> String {
        if let Some(target) = &self.hardlink {
            return format!("hard link to {}", String::from_utf8_lossy(target));
        }
        let Some(mode) = self.mode else {
            return "no ENTRY".to_owned();
        };
        let mut out = format!("{} {}", unix_kind(mode), unix_mode(mode));
        if let Some(p) = self.payload {
            out.push_str(&format!(", {}", size(p.len)));
        } else if let Some((_, len)) = self.payload_ref {
            out.push_str(&format!(", {} in the payload archive", size(len)));
        } else if let Some(t) = &self.symlink {
            out.push_str(&format!(" → {}", String::from_utf8_lossy(t)));
        } else if let Some((major, minor)) = self.device {
            out.push_str(&format!(", device {major}:{minor}"));
        }
        out
    }
}

/// Text of a NUL-terminated name or path item's content.
fn cname(b: &[u8]) -> Vec<u8> {
    b.split(|&c| c == 0).next().unwrap_or_default().to_vec()
}

/// Reads one item header at `pos` (relative to `file`), checking that the
/// item fits before `end`.
async fn read_header(cx: &Cx, file: Span, pos: u64, end: u64) -> Result<(u64, u64)> {
    let at = file.sub(pos, 16);
    let b = cx.read(at).await?;
    let Some((kind, len)) = header_at(&b, 0) else {
        return Err(Diagnostic::truncated(at, to_u64(b.len())));
    };
    if len < 16 || len > end.saturating_sub(pos) {
        return Err(Diagnostic::malformed(format!(
            "{} item of {len} bytes does not fit",
            item_name(kind)
        ))
        .at(at));
    }
    Ok((kind, len))
}

fn item_name(kind: u64) -> String {
    crate::value::lookup(ITEMS, kind).map_or_else(|| format!("item {kind:#018x}"), str::to_owned)
}

/// Content bytes of a small item (names, links, xattrs): at most 64 KiB.
async fn small(cx: &Cx, span: Span) -> Result<Vec<u8>> {
    cx.read(span.sub(16, 1 << 16)).await
}

/// Walks an entry's own items from `start` (its `FILENAME`, or the root's
/// `ENTRY`) up to its payload or, for a directory, its first child.
async fn parse_entry(cx: &Cx, file: Span, start: u64, end: u64) -> Result<Entry> {
    let mut e = Entry::default();
    let mut pos = start;
    let mut first = true;
    while pos < end {
        let (kind, len) = read_header(cx, file, pos, end).await?;
        let span = file.sub(pos, len);
        match kind {
            FILENAME if first => e.name = Some(cname(&small(cx, span).await?)),
            FILENAME | GOODBYE => {
                if e.is_dir() {
                    e.body = Some(pos);
                }
                break;
            }
            ENTRY | ENTRY_V1 => {
                let b = cx.read(span.sub(16, 8)).await?;
                e.mode = u64_le(&b, 0);
            }
            HARDLINK => {
                let b = small(cx, span).await?;
                e.hardlink = Some(cname(b.get(8..).unwrap_or_default()));
            }
            PAYLOAD => e.payload = Some(span.tail(16)),
            PAYLOAD_REF => {
                let b = cx.read(span.sub(16, 16)).await?;
                e.payload_ref = u64_le(&b, 0).zip(u64_le(&b, 8));
            }
            SYMLINK => e.symlink = Some(cname(&small(cx, span).await?)),
            DEVICE => {
                let b = cx.read(span.sub(16, 16)).await?;
                e.device = u64_le(&b, 0).zip(u64_le(&b, 8));
            }
            _ => {}
        }
        e.items.push((kind, span));
        pos = pos.saturating_add(len);
        first = false;
        if matches!(kind, HARDLINK | PAYLOAD | PAYLOAD_REF | SYMLINK | DEVICE) {
            break;
        }
        cx.checkpoint().await;
    }
    if e.is_dir() && e.body.is_none() {
        e.body = Some(pos);
    }
    Ok(e)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (kind, len) = read_header(&cx, file, 0, file.len).await?;
    if kind == PAYLOAD_START {
        cx.annotate("Proxmox file archive payloads (split archive)");
        return items(cx, (input, true)).await;
    }
    let mut pos = 0u64;
    let mut version = 1u64;
    if kind == FORMAT_VERSION {
        let span = file.sub(0, len);
        let b = cx.read(span.sub(16, 8)).await?;
        version = u64_le(&b, 0).unwrap_or(0);
        cx.emit(item_node(&cx, input, FORMAT_VERSION, span).await?);
        pos = len;
        let (next, next_len) = read_header(&cx, file, pos, file.len).await?;
        if next == PRELUDE {
            let span = file.sub(pos, next_len);
            cx.emit(
                embedded("Prelude", input.nested(span.tail(16)))
                    .summary(size(span.len.saturating_sub(16))),
            );
            pos = pos.saturating_add(next_len);
        }
    }
    cx.annotate(format!(
        "Proxmox file archive (format version {version}{})",
        if version >= 2 {
            ", payloads in a separate .ppxar"
        } else {
            ""
        }
    ));
    let root = parse_entry(&cx, file, pos, file.len).await?;
    let span = file.tail(pos);
    let mut node = Node::new("Root directory")
        .span(span)
        .summary(root.summary());
    if !root.is_dir() {
        node = node.diag(Diagnostic::malformed(
            "the archive's first entry is not a directory",
        ));
    }
    cx.emit(node.lazy(entry_expand, (input, span)));
    cx.emit(
        Node::new("Items")
            .span(file)
            .desc("Every item in file order")
            .lazy(items, (input, false)),
    );
    Ok(())
}

/// An entry's node for its directory's listing.
fn entry_node(input: Input, span: Span, e: &Entry, root: bool) -> Node {
    Node::new(e.display_name(root))
        .span(span)
        .summary(e.summary())
        .lazy(entry_expand, (input, span))
}

async fn entry_expand(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let file = input.span;
    let start = span.offset.saturating_sub(file.offset);
    let end = start.saturating_add(span.len);
    let e = parse_entry(&cx, file, start, end).await?;
    for &(kind, item) in &e.items {
        if kind == PAYLOAD {
            let content = item.tail(16);
            let name = e.name.as_deref().map_or_else(
                || "Content".to_owned(),
                |n| String::from_utf8_lossy(n).into_owned(),
            );
            cx.emit(embedded(name, input.nested(content)).summary(size(content.len)));
        } else {
            cx.emit(item_node(&cx, input, kind, item).await?);
        }
    }
    let Some(body) = e.body else {
        return Ok(());
    };
    // The goodbye tail points back to the directory's ENTRY (the root's,
    // in a version 2 archive, to the start of the archive).
    let entry_pos = e
        .items
        .iter()
        .find(|(k, _)| matches!(*k, ENTRY | ENTRY_V1))
        .map_or(start, |(_, s)| s.offset.saturating_sub(file.offset));
    let gb = match goodbye(&cx, file, start, entry_pos, body, end).await {
        Ok(gb) => gb,
        Err(err) => {
            cx.emit(Node::new("Entries").diag(err));
            return Ok(());
        }
    };
    cx.emit(
        Node::new("Goodbye table")
            .span(file.sub(gb.start, end.saturating_sub(gb.start)))
            .summary(plural(gb.items.len(), "entry"))
            .lazy(goodbye_expand, (input, gb.clone())),
    );
    cx.set_count(Count::AtLeast(to_u64(gb.order.len())));
    for (i, &idx) in gb.order.iter().enumerate() {
        let Some(&(_, offset, len)) = gb.items.get(idx) else {
            continue;
        };
        let child = gb.start.saturating_sub(offset);
        if cx.skipping() {
            cx.push(Node::new(format!("Entry {i}"))).await;
            continue;
        }
        let cspan = file.sub(child, len);
        if child < body || child.saturating_add(len) > gb.start {
            cx.push(
                Node::new(format!("Entry {i}"))
                    .span(cspan)
                    .diag(Diagnostic::malformed(
                        "goodbye item points outside the directory",
                    )),
            )
            .await;
            continue;
        }
        let node = match parse_entry(&cx, file, child, child.saturating_add(len)).await {
            Ok(ce) => entry_node(input, cspan, &ce, false),
            Err(err) => Node::new(format!("Entry {i}")).span(cspan).diag(err),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// A directory's goodbye table.
struct Goodbye {
    /// Offset of the `GOODBYE` item in the file.
    start: u64,
    /// The items before the tail: (hash, offset back from `start`, size).
    items: Vec<(u64, u64, u64)>,
    /// Indices into `items` in file order of the entries.
    order: Vec<usize>,
}

/// Reads the goodbye table at the end of the directory `[dir, end)`.
async fn goodbye(
    cx: &Cx,
    file: Span,
    dir: u64,
    entry: u64,
    body: u64,
    end: u64,
) -> Result<Arc<Goodbye>> {
    let anchor = file.sub(dir, end.saturating_sub(dir));
    if let Some(found) = cx.cached::<Goodbye>(anchor, "pxar-goodbye") {
        return Ok(found);
    }
    let tail_span = file.sub(end.saturating_sub(24), 24);
    let tail = cx.read(tail_span).await?;
    let (Some(hash), Some(back), Some(len)) =
        (u64_le(&tail, 0), u64_le(&tail, 8), u64_le(&tail, 16))
    else {
        return Err(Diagnostic::truncated(tail_span, to_u64(tail.len())));
    };
    if hash != GOODBYE_TAIL {
        return Err(
            Diagnostic::malformed("no goodbye table at the end of the directory").at(tail_span),
        );
    }
    let start = end.checked_sub(len).filter(|&s| s >= body).ok_or_else(|| {
        Diagnostic::malformed("goodbye table larger than its directory").at(tail_span)
    })?;
    let (kind, hlen) = read_header(cx, file, start, end).await?;
    if kind != GOODBYE || hlen != len || (len.saturating_sub(16)) % 24 != 0 || len < 40 {
        return Err(Diagnostic::malformed("malformed goodbye table").at(file.sub(start, 16)));
    }
    let pointed = start.checked_sub(back);
    if pointed != Some(entry) && !(pointed == Some(0) && dir == entry) {
        cx.diag(
            Diagnostic::warning("the goodbye tail does not point back to the directory's ENTRY")
                .at(tail_span),
        );
    }
    let table = file.sub_exact(start.saturating_add(16), len.saturating_sub(40))?;
    let raw = cx.read(table).await?;
    let mut items = Vec::new();
    for (i, c) in raw.as_chunks::<24>().0.iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        if let (Some(h), Some(o), Some(s)) = (u64_le(c, 0), u64_le(c, 8), u64_le(c, 16)) {
            items.push((h, o, s));
        }
    }
    let mut order: Vec<usize> = (0..items.len()).collect();
    // Larger offsets back from the table come first in the file.
    order.sort_by_key(|&i| std::cmp::Reverse(items.get(i).map_or(0, |it| it.1)));
    // The sort above: charged per item and comparison round.
    cx.charge(to_u64(items.len()).saturating_mul(4)).await;
    let gb = Arc::new(Goodbye {
        start,
        items,
        order,
    });
    cx.cache(anchor, "pxar-goodbye", gb.clone());
    Ok(gb)
}

async fn goodbye_expand(cx: Cx, (input, gb): (Input, Arc<Goodbye>)) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Header").span(file.sub(gb.start, 16)));
    cx.set_count(Count::Exact(to_u64(gb.items.len()).saturating_add(2)));
    for (i, &(hash, back, len)) in gb.items.iter().enumerate() {
        let span = file.sub(
            gb.start
                .saturating_add(16)
                .saturating_add(to_u64(i).saturating_mul(24)),
            24,
        );
        let target = gb.start.saturating_sub(back);
        let mut node = Node::new(format!("Item {i}"))
            .span(span)
            .value(hex(hash, 64))
            .target(file.sub(target, len));
        if !cx.skipping() {
            // The name hashed is the target's FILENAME.
            let b = cx.read(file.sub(target, 16 + 256)).await?;
            match header_at(&b, 0) {
                Some((FILENAME, flen)) => {
                    let name = cname(
                        b.get(16..usize::try_from(flen).unwrap_or(16).min(b.len()))
                            .unwrap_or_default(),
                    );
                    let ok = siphash24(HASH_KEY.0, HASH_KEY.1, &name) == hash;
                    node = node.summary(format!(
                        "{}, offset back {back}, {}",
                        String::from_utf8_lossy(&name),
                        size(len)
                    ));
                    if !ok {
                        node = node.diag(Diagnostic::malformed(
                            "hash does not match the entry's name",
                        ));
                    }
                }
                _ => {
                    node = node.diag(Diagnostic::malformed("does not point at a FILENAME"));
                }
            }
        }
        cx.push(node).await;
    }
    let tail = file.sub(
        gb.start
            .saturating_add(16)
            .saturating_add(to_u64(gb.items.len()).saturating_mul(24)),
        24,
    );
    cx.push(
        Node::new("Tail")
            .span(tail)
            .value(hex(GOODBYE_TAIL, 64))
            .desc("Points back to the directory's ENTRY and repeats the table's size"),
    )
    .await;
    Ok(())
}

/// Every item in file order. At the top of a payload archive, `top` makes
/// the items the file's own children.
async fn items(cx: Cx, (input, top): (Input, bool)) -> Result<()> {
    let file = input.span;
    let (mut pos, mut index, mut payloads) = cx.resume::<(u64, u64, u64)>().unwrap_or((0, 0, 0));
    while pos < file.len {
        let at = (pos, index, payloads);
        cx.mark(move || at);
        cx.progress_in(file, pos);
        let (kind, len) = match read_header(&cx, file, pos, file.len).await {
            Ok(h) => h,
            Err(e) => {
                cx.push(
                    Node::new(format!("Item {index}"))
                        .span(file.tail(pos))
                        .diag(e),
                )
                .await;
                break;
            }
        };
        let span = file.sub(pos, len);
        if kind == PAYLOAD {
            payloads = payloads.saturating_add(1);
        }
        let mut node = if cx.skipping() {
            Node::new(item_name(kind)).span(span)
        } else {
            item_node(&cx, input, kind, span).await?
        };
        if kind == PAYLOAD {
            // PAYLOAD_REFs name payloads by this offset.
            node = node.renamed(format!("PAYLOAD at {pos:#x}"));
        }
        cx.push(node).await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
        if top && kind == PAYLOAD_TAIL && pos < file.len {
            cx.push(Node::new("Data after the tail marker").span(file.tail(pos)))
                .await;
            break;
        }
    }
    if top {
        cx.annotate(format!(
            "Proxmox file archive payloads (split archive), {}",
            plural(payloads, "payload")
        ));
    }
    Ok(())
}

fn perms(v: u64) -> String {
    if v == u64::MAX {
        return "no mask".to_owned();
    }
    let bit = |b: u64, c: char| if v & b != 0 { c } else { '-' };
    format!("{}{}{}", bit(4, 'r'), bit(2, 'w'), bit(1, 'x'))
}

/// A short description of an item from its content.
fn item_summary(kind: u64, len: u64, c: &[u8]) -> String {
    let u = |i: usize| u64_le(c, i.saturating_mul(8)).unwrap_or(0);
    let content = len.saturating_sub(16);
    match kind {
        FORMAT_VERSION => format!("version {}", u(0)),
        ENTRY | ENTRY_V1 => {
            let mode = u(0);
            format!(
                "{} {}, uid {}, gid {}",
                unix_kind(mode),
                unix_mode(mode),
                u32_le(c, 16).unwrap_or(0),
                u32_le(c, 20).unwrap_or(0)
            )
        }
        FILENAME | SYMLINK => String::from_utf8_lossy(&cname(c)).into_owned(),
        HARDLINK => format!(
            "{}, offset back {}",
            String::from_utf8_lossy(&cname(c.get(8..).unwrap_or_default())),
            u(0)
        ),
        DEVICE => format!("{}:{}", u(0), u(1)),
        XATTR => String::from_utf8_lossy(&cname(c)).into_owned(),
        ACL_USER | ACL_DEFAULT_USER => format!("uid {}: {}", u(0), perms(u(1))),
        ACL_GROUP | ACL_DEFAULT_GROUP => format!("gid {}: {}", u(0), perms(u(1))),
        ACL_GROUP_OBJ => perms(u(0)),
        ACL_DEFAULT => format!(
            "user {}, group {}, other {}, mask {}",
            perms(u(0)),
            perms(u(1)),
            perms(u(2)),
            perms(u(3))
        ),
        QUOTA_PROJID => format!("project {}", u(0)),
        PAYLOAD_REF => format!("offset {:#x}, {}", u(0), size(u(1))),
        GOODBYE => plural(content.saturating_sub(24) / 24, "entry"),
        _ => size(content),
    }
}

/// An item's node: its header and its content's fields when expanded.
async fn item_node(cx: &Cx, input: Input, kind: u64, span: Span) -> Result<Node> {
    let peek = cx.read(span.sub(16, 16 + 256)).await?;
    let node = Node::new(item_name(kind))
        .span(span)
        .summary(item_summary(kind, span.len, &peek));
    Ok(match kind {
        PAYLOAD | PRELUDE => embedded(item_name(kind), input.nested(span.tail(16)))
            .summary(size(span.len.saturating_sub(16))),
        _ => node.lazy(item_expand, (input, kind, span)),
    })
}

async fn item_expand(cx: Cx, (_input, kind, span): (Input, u64, Span)) -> Result<()> {
    cx.emit(
        Node::new("Type")
            .span(span.sub(0, 8))
            .value(enumv(kind, 64, ITEMS)),
    );
    cx.emit(
        Node::new("Size")
            .span(span.sub(8, 8))
            .value(uint(span.len, 64))
            .desc("Size of the item, header included"),
    );
    let body = span.tail(16);
    match kind {
        ENTRY => {
            emit_record::<Stat>(&cx, body, LE).await?;
        }
        ENTRY_V1 => {
            emit_record::<StatV1>(&cx, body, LE).await?;
        }
        FORMAT_VERSION => cx.emit(u64_at(&cx, body, "Version", 0).await?),
        FILENAME | SYMLINK => {
            let b = small(&cx, span).await?;
            let name = if kind == FILENAME { "Name" } else { "Target" };
            cx.emit(
                Node::new(name)
                    .span(body)
                    .value(text(String::from_utf8_lossy(&cname(&b)))),
            );
        }
        HARDLINK => {
            cx.emit(
                u64_at(&cx, body, "Offset", 0)
                    .await?
                    .desc("Distance back from this entry's FILENAME to the first link's FILENAME"),
            );
            let b = small(&cx, span).await?;
            cx.emit(
                Node::new("Path")
                    .span(body.tail(8))
                    .value(text(String::from_utf8_lossy(&cname(
                        b.get(8..).unwrap_or_default(),
                    )))),
            );
        }
        DEVICE => {
            cx.emit(u64_at(&cx, body, "Major", 0).await?);
            cx.emit(u64_at(&cx, body, "Minor", 8).await?);
        }
        XATTR => {
            let b = small(&cx, span).await?;
            let name = cname(&b);
            let nlen = to_u64(name.len());
            cx.emit(
                Node::new("Name")
                    .span(body.sub(0, nlen.saturating_add(1)))
                    .value(text(String::from_utf8_lossy(&name))),
            );
            let vspan = body.tail(nlen.saturating_add(1));
            let value = b.get(name.len().saturating_add(1)..).unwrap_or_default();
            let v = if crate::text::looks_like_text(value) {
                text(String::from_utf8_lossy(value))
            } else {
                Value::Bytes(value.get(..256).unwrap_or(value).to_vec())
            };
            cx.emit(Node::new("Value").span(vspan).value(v));
        }
        ACL_USER | ACL_DEFAULT_USER => {
            cx.emit(u64_at(&cx, body, "UID", 0).await?);
            cx.emit(perm_at(&cx, body, "Permissions", 8).await?);
        }
        ACL_GROUP | ACL_DEFAULT_GROUP => {
            cx.emit(u64_at(&cx, body, "GID", 0).await?);
            cx.emit(perm_at(&cx, body, "Permissions", 8).await?);
        }
        ACL_GROUP_OBJ => cx.emit(perm_at(&cx, body, "Permissions", 0).await?),
        ACL_DEFAULT => {
            cx.emit(perm_at(&cx, body, "User object", 0).await?);
            cx.emit(perm_at(&cx, body, "Group object", 8).await?);
            cx.emit(perm_at(&cx, body, "Other", 16).await?);
            cx.emit(perm_at(&cx, body, "Mask", 24).await?);
        }
        QUOTA_PROJID => cx.emit(u64_at(&cx, body, "Project ID", 0).await?),
        PAYLOAD_REF => {
            cx.emit(
                u64_at(&cx, body, "Offset", 0)
                    .await?
                    .desc("Offset of the payload's PAYLOAD header in the payload archive (.ppxar)"),
            );
            cx.emit(u64_at(&cx, body, "Size", 8).await?);
        }
        GOODBYE => {
            let n = body.len / 24;
            for i in 0..n.min(4096) {
                let s = body.sub(i.saturating_mul(24), 24);
                let b = cx.read(s).await?;
                let (h, o, l) = (
                    u64_le(&b, 0).unwrap_or(0),
                    u64_le(&b, 8).unwrap_or(0),
                    u64_le(&b, 16).unwrap_or(0),
                );
                let label = if h == GOODBYE_TAIL {
                    "Tail".to_owned()
                } else {
                    format!("Item {i}")
                };
                cx.push(
                    Node::new(label)
                        .span(s)
                        .value(hex(h, 64))
                        .summary(format!("offset back {o}, size {l}")),
                )
                .await;
            }
            if n > 4096 {
                cx.diag(Diagnostic::note(
                    "further goodbye items are listed under the directory's goodbye table",
                ));
            }
        }
        FCAPS => cx.emit(Node::new("Capabilities").span(body).summary(size(body.len))),
        _ => {
            if !body.is_empty() {
                cx.emit(Node::new("Content").span(body));
            }
        }
    }
    Ok(())
}

async fn u64_at(cx: &Cx, body: Span, name: &'static str, off: u64) -> Result<Node> {
    let s = body.sub(off, 8);
    let b = cx.read(s).await?;
    Ok(Node::new(name)
        .span(s)
        .value(uint(u64_le(&b, 0).unwrap_or(0), 64)))
}

async fn perm_at(cx: &Cx, body: Span, name: &'static str, off: u64) -> Result<Node> {
    let s = body.sub(off, 8);
    let b = cx.read(s).await?;
    let v = u64_le(&b, 0).unwrap_or(0);
    Ok(Node::new(name).span(s).value(hex(v, 64)).summary(perms(v)))
}

/// SipHash-2-4 of `data` with key `(k0, k1)`.
fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    fn round(v: &mut [u64; 4]) {
        let [v0, v1, v2, v3] = v;
        *v0 = v0.wrapping_add(*v1);
        *v1 = v1.rotate_left(13) ^ *v0;
        *v0 = v0.rotate_left(32);
        *v2 = v2.wrapping_add(*v3);
        *v3 = v3.rotate_left(16) ^ *v2;
        *v0 = v0.wrapping_add(*v3);
        *v3 = v3.rotate_left(21) ^ *v0;
        *v2 = v2.wrapping_add(*v1);
        *v1 = v1.rotate_left(17) ^ *v2;
        *v2 = v2.rotate_left(32);
    }
    let compress = |v: &mut [u64; 4], m: u64| {
        v[3] ^= m;
        round(v);
        round(v);
        v[0] ^= m;
    };
    let (chunks, rest) = data.as_chunks::<8>();
    for c in chunks {
        compress(&mut v, u64::from_le_bytes(*c));
    }
    let mut last = [0u8; 8];
    for (d, s) in last.iter_mut().zip(rest) {
        *d = *s;
    }
    last[7] = u8::try_from(data.len() & 0xff).unwrap_or(0);
    compress(&mut v, u64::from_le_bytes(last));
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

#[cfg(test)]
mod tests {
    use super::siphash24;

    #[test]
    fn siphash_reference_vector() {
        // The SipHash paper's test vector: key 00..0f, message 00..0e.
        let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
        let msg: Vec<u8> = (0u8..15).collect();
        assert_eq!(siphash24(k0, k1, &msg), 0xa129_ca61_49be_45e5);
    }
}
