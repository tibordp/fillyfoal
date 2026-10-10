//! StuffIt archives (classic Macintosh `.sit`, and StuffIt 5).
//!
//! Classic: a 22-byte header (`SIT!` ... `rLau`), then entries of a 112-byte
//! header followed by the resource and data forks. Folders are bracketed by
//! start/end marker entries, which the listing turns into paths.
//!
//! StuffIt 5: an 80-byte banner, an archive header and entries tagged
//! `0xA5A5A5A5`, stored depth first: each directory entry is followed by
//! its contents, and says how many entries it holds. An entry has two
//! parts: the header proper (sizes, data fork method, name) up to the size
//! it records, then Finder information and, if there is one, the resource
//! fork's sizes and method; the resource fork's data comes next, then the
//! data fork's. Neither format was ever documented; this follows memory of
//! The Unarchiver's (XADMaster) parsers, unverified against real archives,
//! so fields that are not understood are shown raw.
//!
//! Forks are decompressed by [`crate::codec::stuffit`] (RLE90, LZW,
//! Huffman, LZAH, method 13's dynamic variant and Arsenic) and dissected
//! as embedded files; resource forks are identified like any other content
//! (normally as `mac-rsrc`). Encrypted forks are not decrypted.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::codec::Codec;
use crate::codec::stuffit::Params;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{ByteReader, crc16_arc, emit_nodes, unsupported};
use crate::formats::util::finder::FINDER_FLAGS;
use crate::formats::util::fmt;
use crate::formats::util::fmt::count;
use crate::formats::util::fmt::fourcc_value;
use crate::formats::util::val::hex;
use crate::formats::{Format, Head, Input, Probe, content, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const BE: Endian = Endian::Big;
const ENTRY: u64 = 112;
const SIT5_MAGIC: u32 = 0xa5a5_a5a5;
const MAX_ENTRIES: u64 = 1 << 20;
/// Folder nesting a classic archive may have.
const MAX_DEPTH: usize = 256;
/// The longest StuffIt 5 folder path that children are named under.
const MAX_PATH: usize = 4096;

/// A Finder flags word as a flag set.
fn finder_flags(v: u16) -> Value {
    let (set, unknown) = crate::value::decode_flags(FINDER_FLAGS, v.into());
    Value::Flags {
        raw: v.into(),
        bits: 16,
        set,
        unknown,
    }
}

pub static FORMAT: Format = Format {
    name: "stuffit",
    title: "StuffIt archive",
    extensions: &["sit"],
    mime: "application/x-stuffit",
    probe: Probe::Custom(probe_classic),
    dissect: crate::expander!(dissect_classic: Input),
};

pub static SIT5: Format = Format {
    name: "stuffit5",
    title: "StuffIt 5 archive",
    extensions: &["sit"],
    mime: "application/x-stuffit",
    probe: Probe::Magic(&[(0, b"StuffIt (c)1997-")]),
    dissect: crate::expander!(dissect_sit5: Input),
};

fn probe_classic(h: &Head<'_>) -> bool {
    let sig = h.data.get(..4).unwrap_or_default();
    let known = matches!(
        sig,
        b"SIT!" | b"ST46" | b"ST50" | b"ST60" | b"ST65" | b"STin" | b"STi2" | b"STi3" | b"STi4"
    );
    known && h.at(10, b"rLau")
}

const METHOD: EnumTable = &[
    (0, "none"),
    (1, "RLE90"),
    (2, "LZW"),
    (3, "Huffman"),
    (5, "LZAH"),
    (6, "fixed Huffman"),
    (8, "Miller-Wegman"),
    (13, "LZ + Huffman"),
    (14, "installer"),
    (15, "Arsenic"),
    (32, "folder start"),
    (33, "folder end"),
];

fn method_name(m: u8) -> String {
    let base = crate::value::lookup(METHOD, (m & !0x10).into())
        .map_or_else(|| format!("method {}", m & !0x10), str::to_owned);
    if m & 0x10 != 0 && m < 32 {
        format!("{base}, encrypted")
    } else {
        base
    }
}

/// A node for a fork: dissected in place when stored, decompressed on
/// expansion when the method is supported. `crc` is the CRC-16 of the
/// uncompressed fork, if the archive records one.
fn fork_node(
    name: &'static str,
    input: Input,
    span: Span,
    method: u8,
    len: u64,
    crc: Option<u16>,
    encrypted: bool,
) -> Node {
    if encrypted {
        return Node::new(name)
            .span(span)
            .summary(fmt::size(len))
            .diag(Diagnostic::unsupported("StuffIt encryption"));
    }
    if method == 0 {
        return embedded(name, input.nested(span.sub(0, len))).summary(fmt::size(len));
    }
    if !crate::codec::stuffit::supported(method) {
        return unsupported(name, span, &format!("StuffIt {}", method_name(method)));
    }
    let codec = Codec::StuffIt(Params {
        method,
        size: len,
        // Arsenic carries its own CRC-32.
        crc: crc.filter(|_| method != 15),
    });
    content(name, input, span, codec, Some(len)).summary(format!(
        "{}, {}",
        fmt::size(len),
        method_name(method)
    ))
}

// ---------------------------------------------------------------------------
// Classic

record! {
    pub struct Header {
        signature: ascii[4] "Signature",
        files: u16 "Number of entries",
        length: u32 "Archive length" .with(|&l, n| n.summary(fmt::size(l.into()))),
        signature2: ascii[4] "Signature 2",
        version: u8 "Version",
        reserved: bytes[7] "Reserved",
    }
}

/// The parts of a classic entry header the listing needs.
struct Classic {
    rsrc_method: u8,
    data_method: u8,
    name: String,
    rsrc_len: u32,
    data_len: u32,
    rsrc_packed: u32,
    data_packed: u32,
    rsrc_crc: u16,
    data_crc: u16,
    crc_ok: bool,
}

fn classic(b: &[u8]) -> Option<Classic> {
    let name_len = usize::from(*b.get(2)?).min(63);
    let stored = u16_be(b, 110)?;
    Some(Classic {
        rsrc_method: *b.first()?,
        data_method: *b.get(1)?,
        name: String::from_utf8_lossy(b.get(3..3usize.checked_add(name_len)?)?).into_owned(),
        rsrc_len: u32_be(b, 84)?,
        data_len: u32_be(b, 88)?,
        rsrc_packed: u32_be(b, 92)?,
        data_packed: u32_be(b, 96)?,
        rsrc_crc: u16_be(b, 100)?,
        data_crc: u16_be(b, 102)?,
        crc_ok: crc16_arc(b.get(..110)?) == stored,
    })
}

/// The classic walker's state, for resume marks: offset, folder path,
/// files, total size, entries seen.
type ClassicWalk = (u64, Vec<String>, u64, u64, u64);

pub async fn dissect_classic(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = crate::fields::parse(&cx, file.sub(0, Header::SIZE), BE, &(), Header::layout).await?;
    let end = u64::from(h.length).min(file.len);
    let resumed = cx.resume::<ClassicWalk>();
    if resumed.is_none() {
        cx.emit(
            Header::node("Archive header", file.sub(0, Header::SIZE), BE)
                .summary(h.signature.clone()),
        );
    }
    let (mut at, mut path, mut files, mut total, mut seen) =
        resumed.unwrap_or((Header::SIZE, Vec::new(), 0, 0, 0));
    while at.saturating_add(ENTRY) <= end && seen < MAX_ENTRIES {
        let walk = (at, path.clone(), files, total, seen);
        cx.mark(move || walk);
        seen = seen.saturating_add(1);
        let header_span = file.sub(at, ENTRY);
        let raw = cx.read(header_span).await?;
        let e = classic(&raw).ok_or_else(|| Diagnostic::truncated(header_span, 0))?;
        let forks = u64::from(e.rsrc_packed).saturating_add(e.data_packed.into());
        let folder_marker = e.rsrc_method == 32
            || e.data_method == 32
            || e.rsrc_method == 33
            || e.data_method == 33;
        let span = if folder_marker {
            header_span
        } else {
            file.sub(at, ENTRY.saturating_add(forks))
        };
        let (name, summary) = if e.rsrc_method == 33 || e.data_method == 33 {
            let closed = path.pop().unwrap_or_default();
            (format!("End of folder {closed}"), String::new())
        } else if e.rsrc_method == 32 || e.data_method == 32 {
            // The path is cloned for every entry (and resume mark): keep
            // its cost per entry bounded.
            if path.len() >= MAX_DEPTH {
                cx.diag(Diagnostic::limit("folders nested too deeply").at(header_span));
                break;
            }
            path.push(e.name.clone());
            (format!("{}/", path.join("/")), "folder".to_owned())
        } else {
            files = files.saturating_add(1);
            total = total.saturating_add(u64::from(e.data_len).saturating_add(e.rsrc_len.into()));
            let mut full = path.clone();
            full.push(e.name.clone());
            (
                full.join("/"),
                format!(
                    "data {} ({}), resource {} ({})",
                    fmt::size(e.data_len.into()),
                    method_name(e.data_method),
                    fmt::size(e.rsrc_len.into()),
                    method_name(e.rsrc_method)
                ),
            )
        };
        let mut node = Node::new(name)
            .span(span)
            .lazy(classic_entry, (input, span));
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if !e.crc_ok {
            node = node.diag(Diagnostic::warning("header CRC mismatch"));
        }
        cx.progress_in(file, span.end());
        cx.push(node).await;
        at = at.saturating_add(span.len);
    }
    if end < file.len {
        cx.emit(Node::new("Data after the archive").span(file.tail(end)));
    }
    cx.annotate(format!(
        "StuffIt archive, {}, {} uncompressed",
        count(files, "file", "files"),
        fmt::size(total)
    ));
    Ok(())
}

async fn classic_entry(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let header_span = span.sub(0, ENTRY);
    let raw = cx.read(header_span).await?;
    let e = classic(&raw).ok_or_else(|| Diagnostic::truncated(header_span, 0))?;
    let mut r = ByteReader::new(&raw, header_span);
    let bad = || Diagnostic::truncated(header_span, 0);
    for name in ["Resource fork method", "Data fork method"] {
        let m = r.u8(name).ok_or_else(bad)?;
        r.with(|n| {
            let n = n.value(Value::Enum {
                raw: m.into(),
                bits: 8,
                name: crate::value::lookup(METHOD, (m & !0x10).into()),
            });
            if m & 0x10 != 0 && m < 32 {
                n.summary("encrypted")
            } else {
                n
            }
        });
    }
    r.u8("Name length").ok_or_else(bad)?;
    let name = e.name.clone();
    r.bytes("Name", 63).ok_or_else(bad)?;
    r.with(|n| n.value(Value::Text(name)));
    for name in ["File type", "Creator"] {
        let v = fourcc_value(r.bytes(name, 4).ok_or_else(bad)?);
        r.with(|n| n.value(v));
    }
    let flags = r.u16("Finder flags", BE).ok_or_else(bad)?;
    r.with(|n| n.value(finder_flags(flags)));
    for name in ["Creation time", "Modification time"] {
        let t = r.u32(name, BE).ok_or_else(bad)?;
        r.with(|n| {
            n.value(Value::Timestamp {
                unix_seconds: crate::text::mac_to_unix(t.into()),
            })
        });
    }
    r.u32("Resource fork length", BE).ok_or_else(bad)?;
    r.u32("Data fork length", BE).ok_or_else(bad)?;
    r.u32("Resource fork compressed length", BE)
        .ok_or_else(bad)?;
    r.u32("Data fork compressed length", BE).ok_or_else(bad)?;
    for name in ["Resource fork CRC-16", "Data fork CRC-16"] {
        let c = r.u16(name, BE).ok_or_else(bad)?;
        r.with(|n| n.value(hex(c, 64)));
    }
    r.bytes("Reserved", 6).ok_or_else(bad)?;
    let stored = r.u16("Header CRC", BE).ok_or_else(bad)?;
    let ok = e.crc_ok;
    r.with(|n| {
        let n = n.value(hex(stored, 64));
        if ok {
            n.summary("valid")
        } else {
            n.diag(Diagnostic::warning("header CRC mismatch"))
        }
    });
    cx.emit(
        Node::new("Entry header")
            .span(header_span)
            .lazy(emit_nodes, r.into_nodes()),
    );
    if span.len <= ENTRY {
        return Ok(());
    }
    let rsrc = span.sub(ENTRY, e.rsrc_packed.into());
    let data = span.sub(
        ENTRY.saturating_add(e.rsrc_packed.into()),
        e.data_packed.into(),
    );
    for (name, fork, method, len, crc) in [
        ("Resource fork", rsrc, e.rsrc_method, e.rsrc_len, e.rsrc_crc),
        ("Data fork", data, e.data_method, e.data_len, e.data_crc),
    ] {
        if fork.len == 0 && len == 0 {
            continue;
        }
        let encrypted = method & 0x10 != 0;
        cx.emit(fork_node(
            name,
            input,
            fork,
            method & !0x10,
            len.into(),
            Some(crc),
            encrypted,
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// StuffIt 5

const SIT5_DIRECTORY: u8 = 0x40;
const SIT5_ENCRYPTED: u8 = 0x20;

/// A StuffIt 5 entry as the listing parsed it.
#[derive(Clone, Debug)]
struct Sit5Entry {
    /// Where the entry starts, relative to the archive.
    at: u64,
    /// The parent directory entry's offset (0 at the root).
    parent: u32,
    /// From the entry's start to its first fork's data.
    header: Span,
    /// The first part (up to the recorded header size).
    first: Span,
    version: u8,
    flags: u8,
    name: String,
    /// Entries in a directory.
    children: u16,
    data_len: u32,
    data_packed: u32,
    data_crc: u16,
    data_method: u8,
    rsrc: Option<(u32, u32, u16, u8)>,
}

impl Sit5Entry {
    fn directory(&self) -> bool {
        self.flags & SIT5_DIRECTORY != 0
    }

    fn rsrc_packed(&self) -> u64 {
        self.rsrc.map_or(0, |r| r.1.into())
    }

    /// Where the next entry starts, relative to the archive.
    fn end(&self) -> u64 {
        let start = self.at.saturating_add(self.header.len);
        if self.directory() {
            start
        } else {
            start
                .saturating_add(self.rsrc_packed())
                .saturating_add(self.data_packed.into())
        }
    }
}

async fn sit5_entry_at(cx: &Cx, file: Span, at: u64) -> Result<Option<Sit5Entry>> {
    let fixed = file.sub(at, 48);
    let raw = cx.read_avail(fixed).await?;
    if raw.len() < 48 || u32_be(&raw, 0) != Some(SIT5_MAGIC) {
        return Ok(None);
    }
    let version = raw.get(4).copied().unwrap_or(0);
    let header_size = u64::from(u16_be(&raw, 6).unwrap_or(0)).max(48);
    let flags = raw.get(9).copied().unwrap_or(0);
    let name_len = usize::from(u16_be(&raw, 30).unwrap_or(0));
    let first = file.sub(at, header_size);
    let head = cx.read(first).await?;
    let directory = flags & SIT5_DIRECTORY != 0;
    let (name_at, data_method, children) = if directory {
        (48usize, 0, u16_be(&head, 46).unwrap_or(0))
    } else {
        let pass = usize::from(head.get(47).copied().unwrap_or(0));
        (
            48usize.saturating_add(pass),
            head.get(46).copied().unwrap_or(0),
            0,
        )
    };
    let name = head
        .get(name_at..name_at.saturating_add(name_len))
        .unwrap_or_default();
    // The second part: Finder information, then the resource fork's.
    let second_at = at.saturating_add(header_size);
    let skip = if version == 1 { 22u64 } else { 18 };
    let second_fixed = 14u64.saturating_add(skip);
    let second = cx
        .read(file.sub(second_at, second_fixed.saturating_add(14)))
        .await?;
    let has_rsrc = u16_be(&second, 0).unwrap_or(0) & 1 != 0;
    let mut end = second_at.saturating_add(second_fixed);
    let rsrc = if has_rsrc {
        let o = usize::try_from(second_fixed).unwrap_or(0);
        let r = (
            u32_be(&second, o).unwrap_or(0),
            u32_be(&second, o.saturating_add(4)).unwrap_or(0),
            u16_be(&second, o.saturating_add(8)).unwrap_or(0),
            second.get(o.saturating_add(12)).copied().unwrap_or(0),
        );
        let pass = u64::from(second.get(o.saturating_add(13)).copied().unwrap_or(0));
        end = end.saturating_add(14).saturating_add(pass);
        Some(r)
    } else {
        None
    };
    Ok(Some(Sit5Entry {
        at,
        parent: u32_be(&head, 26).unwrap_or(0),
        header: file.sub(at, end.saturating_sub(at)),
        first,
        version,
        flags,
        name: String::from_utf8_lossy(name).into_owned(),
        children,
        data_len: u32_be(&head, 34).unwrap_or(0),
        data_packed: u32_be(&head, 38).unwrap_or(0),
        data_crc: u16_be(&head, 42).unwrap_or(0),
        data_method,
        rsrc,
    }))
}

pub async fn dissect_sit5(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 100)).await?;
    let mut r = ByteReader::new(&head, file.sub(0, 100));
    let bad = || Diagnostic::truncated(file.sub(0, 100), 0);
    let banner = r.text("Banner", 80).ok_or_else(bad)?;
    r.bytes("Banner end", 2).ok_or_else(bad)?;
    r.u8("Version").ok_or_else(bad)?;
    let flags = r.u8("Flags").ok_or_else(bad)?;
    r.with(|n| n.value(hex(flags, 64)));
    let total = r.u32("Total size", BE).ok_or_else(bad)?;
    r.with(|n| n.summary(fmt::size(total.into())));
    r.u32("Unknown", BE).ok_or_else(bad)?;
    let entries = r.u16("Root entries", BE).ok_or_else(bad)?;
    let first = r.u32("First entry offset", BE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(first, 64)));
    let header_len = to_u64(r.at).max(u64::from(first).min(100));
    if r.at < head.len() && u64::from(first) > to_u64(r.at) {
        let rest = u64::from(first).min(100).saturating_sub(to_u64(r.at));
        r.bytes("Unknown", rest);
    }
    cx.emit(
        Node::new("Archive header")
            .span(file.sub(0, header_len))
            .summary(banner.trim_end().to_owned())
            .lazy(emit_nodes, r.into_nodes()),
    );
    if flags & 0x80 != 0 {
        cx.diag(Diagnostic::unsupported("encrypted StuffIt 5 archive"));
    }
    let mut at = u64::from(first);
    let mut remaining = u64::from(entries);
    let mut seen = 0u64;
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut dirs: BTreeMap<u64, String> = BTreeMap::new();
    while remaining > 0 && seen < MAX_ENTRIES {
        let Some(e) = sit5_entry_at(&cx, file, at).await? else {
            cx.diag(Diagnostic::malformed(format!("no entry at {at:#x}")).at(file.sub(at, 4)));
            break;
        };
        seen = seen.saturating_add(1);
        remaining = remaining.saturating_sub(1);
        let path = match dirs.get(&u64::from(e.parent)) {
            Some(p) => format!("{p}/{}", e.name),
            None => e.name.clone(),
        };
        let span = file.sub(at, e.end().saturating_sub(at).max(e.header.len));
        let summary = if e.directory() {
            remaining = remaining.saturating_add(e.children.into());
            // Paths grow with nesting: past a bound, children are named on
            // their own (a deep chain must not cost quadratic time and
            // memory).
            if path.len() <= MAX_PATH {
                dirs.insert(at, path.clone());
            }
            format!("folder, {}", count(e.children, "entry", "entries"))
        } else {
            files = files.saturating_add(1);
            let rsrc_len = e.rsrc.map_or(0, |r| u64::from(r.0));
            bytes = bytes
                .saturating_add(e.data_len.into())
                .saturating_add(rsrc_len);
            let mut s = format!(
                "data {} ({})",
                fmt::size(e.data_len.into()),
                method_name(e.data_method)
            );
            if let Some((len, _, _, m)) = e.rsrc {
                s.push_str(&format!(
                    ", resource {} ({})",
                    fmt::size(len.into()),
                    method_name(m)
                ));
            }
            if e.flags & SIT5_ENCRYPTED != 0 {
                s.push_str(", encrypted");
            }
            s
        };
        let name = if e.directory() {
            format!("{path}/")
        } else {
            path
        };
        let next = e.end();
        cx.progress_in(file, span.end());
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(sit5_entry, (input, Arc::new(e))),
        )
        .await;
        if next <= at {
            break;
        }
        at = next;
    }
    cx.annotate(format!(
        "StuffIt 5 archive, {}, {} uncompressed",
        count(files, "file", "files"),
        fmt::size(bytes)
    ));
    Ok(())
}

async fn sit5_entry(cx: Cx, (input, e): (Input, Arc<Sit5Entry>)) -> Result<()> {
    let raw = cx.read(e.header).await?;
    let mut r = ByteReader::new(&raw, e.header);
    let bad = || Diagnostic::truncated(e.header, 0);
    r.u32("Magic", BE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(SIT5_MAGIC, 64)));
    r.u8("Version").ok_or_else(bad)?;
    r.u8("Unknown").ok_or_else(bad)?;
    r.u16("Header size", BE).ok_or_else(bad)?;
    r.u8("Unknown").ok_or_else(bad)?;
    let flags = r.u8("Flags").ok_or_else(bad)?;
    r.with(|n| {
        n.value(hex(flags, 64))
            .summary(match (flags & 0x40 != 0, flags & 0x20 != 0) {
                (true, _) => "directory",
                (false, true) => "encrypted",
                _ => "file",
            })
    });
    for name in ["Creation time", "Modification time"] {
        let t = r.u32(name, BE).ok_or_else(bad)?;
        r.with(|n| {
            n.value(Value::Timestamp {
                unix_seconds: crate::text::mac_to_unix(t.into()),
            })
        });
    }
    for name in ["Previous entry", "Next entry", "Parent directory"] {
        let o = r.u32(name, BE).ok_or_else(bad)?;
        r.with(|n| n.value(hex(o, 64)));
    }
    let name_len = r.u16("Name length", BE).ok_or_else(bad)?;
    let crc = r.u16("Header CRC", BE).ok_or_else(bad)?;
    // CRC-16 of the first part with this field zeroed, as far as we know;
    // only a match is reported.
    let mut zeroed = raw
        .get(..crate::bytes::to_usize(e.first.len))
        .unwrap_or_default()
        .to_vec();
    if let Some(f) = zeroed.get_mut(32..34) {
        f.fill(0);
    }
    let matches = crc16_arc(&zeroed) == crc;
    r.with(|n| {
        let n = n.value(hex(crc, 64));
        if matches { n.summary("valid") } else { n }
    });
    r.u32("Data length", BE).ok_or_else(bad)?;
    r.u32("Data compressed length", BE).ok_or_else(bad)?;
    let dcrc = r.u16("Data CRC-16", BE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(dcrc, 64)));
    r.u16("Unknown", BE).ok_or_else(bad)?;
    if e.directory() {
        r.u16("Number of entries", BE).ok_or_else(bad)?;
    } else {
        let m = r.u8("Data method").ok_or_else(bad)?;
        r.with(|n| n.summary(method_name(m)));
        let pass = r.u8("Password length").ok_or_else(bad)?;
        if pass > 0 {
            r.bytes("Password data", pass.into()).ok_or_else(bad)?;
        }
    }
    r.text("Name", name_len.into()).ok_or_else(bad)?;
    let first_len = crate::bytes::to_usize(e.first.len);
    if r.at < first_len {
        let rest = to_u64(first_len.saturating_sub(r.at));
        r.bytes("Rest of header (comment)", rest).ok_or_else(bad)?;
    }
    // The second part.
    let flags2 = r.u16("Flags 2", BE).ok_or_else(bad)?;
    r.with(|n| {
        let n = n.value(hex(flags2, 64));
        if flags2 & 1 != 0 {
            n.summary("has a resource fork")
        } else {
            n
        }
    });
    r.u16("Unknown", BE).ok_or_else(bad)?;
    for name in ["File type", "Creator"] {
        let v = fourcc_value(r.bytes(name, 4).ok_or_else(bad)?);
        r.with(|n| n.value(v));
    }
    let finder = r.u16("Finder flags", BE).ok_or_else(bad)?;
    r.with(|n| n.value(finder_flags(finder)));
    r.bytes("Unknown", if e.version == 1 { 22 } else { 18 })
        .ok_or_else(bad)?;
    if e.rsrc.is_some() {
        r.u32("Resource fork length", BE).ok_or_else(bad)?;
        r.u32("Resource fork compressed length", BE)
            .ok_or_else(bad)?;
        let c = r.u16("Resource fork CRC-16", BE).ok_or_else(bad)?;
        r.with(|n| n.value(hex(c, 64)));
        r.u16("Unknown", BE).ok_or_else(bad)?;
        let m = r.u8("Resource fork method").ok_or_else(bad)?;
        r.with(|n| n.summary(method_name(m)));
        let pass = r.u8("Password length").ok_or_else(bad)?;
        if pass > 0 {
            r.bytes("Password data", pass.into()).ok_or_else(bad)?;
        }
    }
    cx.emit(
        Node::new("Entry header")
            .span(e.header)
            .lazy(emit_nodes, r.into_nodes()),
    );
    if e.directory() {
        return Ok(());
    }
    let file = input.span;
    let base = e.at.saturating_add(e.header.len);
    let encrypted = e.flags & SIT5_ENCRYPTED != 0;
    if let Some((len, packed, crc, method)) = e.rsrc {
        let span = file.sub(base, packed.into());
        cx.emit(fork_node(
            "Resource fork",
            input,
            span,
            method,
            len.into(),
            Some(crc),
            encrypted,
        ));
    }
    let span = file.sub(base.saturating_add(e.rsrc_packed()), e.data_packed.into());
    if span.len > 0 || e.data_len > 0 {
        cx.emit(fork_node(
            "Data fork",
            input,
            span,
            e.data_method,
            e.data_len.into(),
            Some(e.data_crc),
            encrypted,
        ));
    }
    Ok(())
}
