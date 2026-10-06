//! StuffIt archives (classic Macintosh `.sit`, and StuffIt 5).
//!
//! Classic: a 22-byte header (`SIT!` ... `rLau`), then entries of a 112-byte
//! header followed by the resource and data forks. Folders are bracketed by
//! start/end marker entries, which the listing turns into paths.
//!
//! StuffIt 5: an 80-byte banner, an archive header and a linked list of
//! entries tagged `0xA5A5A5A5`. Its layout is undocumented; this follows
//! the reverse-engineered description used by The Unarchiver and decodes
//! the entry headers only.
//!
//! The StuffIt codecs (RLE, LZW, Huffman, Arsenic, ...) are unsupported;
//! uncompressed forks are dissected in place.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{
    ByteReader, count, crc16_arc, emit_nodes, hex, human_size, unsupported,
};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const BE: Endian = Endian::Big;
const ENTRY: u64 = 112;
const SIT5_MAGIC: u32 = 0xa5a5_a5a5;
const MAX_ENTRIES: u64 = 1 << 20;

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
    (5, "LZ + adaptive Huffman"),
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

record! {
    pub struct Header {
        signature: ascii[4] "Signature",
        files: u16 "Number of entries",
        length: u32 "Archive length" .with(|&l, n| n.summary(human_size(l.into()))),
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
        crc_ok: crc16_arc(b.get(..110)?) == stored,
    })
}

pub async fn dissect_classic(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = crate::fields::parse(&cx, file.sub(0, Header::SIZE), BE, &(), Header::layout).await?;
    cx.emit(
        Header::node("Archive header", file.sub(0, Header::SIZE), BE).summary(h.signature.clone()),
    );
    let end = u64::from(h.length).min(file.len);
    let mut at = Header::SIZE;
    let mut path: Vec<String> = Vec::new();
    let mut files = 0u64;
    let mut total = 0u64;
    let mut seen = 0u64;
    while at.saturating_add(ENTRY) <= end && seen < MAX_ENTRIES {
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
                    human_size(e.data_len.into()),
                    method_name(e.data_method),
                    human_size(e.rsrc_len.into()),
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
        cx.push(node).await;
        at = at.saturating_add(span.len);
    }
    if end < file.len {
        cx.emit(Node::new("Data after the archive").span(file.tail(end)));
    }
    cx.annotate(format!(
        "StuffIt archive, {}, {} uncompressed",
        count(files, "file", "files"),
        human_size(total)
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
        let v = r.bytes(name, 4).ok_or_else(bad)?;
        let t = String::from_utf8_lossy(v).into_owned();
        r.with(|n| n.value(Value::Text(t)));
    }
    let flags = r.u16("Finder flags", BE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(flags.into())));
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
    for name in ["Resource fork CRC", "Data fork CRC"] {
        let c = r.u16(name, BE).ok_or_else(bad)?;
        r.with(|n| n.value(hex(c.into())));
    }
    r.bytes("Reserved", 6).ok_or_else(bad)?;
    let stored = r.u16("Header CRC", BE).ok_or_else(bad)?;
    let ok = e.crc_ok;
    r.with(|n| {
        let n = n.value(hex(stored.into()));
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
    for (name, fork, method, len) in [
        ("Resource fork", rsrc, e.rsrc_method, e.rsrc_len),
        ("Data fork", data, e.data_method, e.data_len),
    ] {
        if fork.len == 0 && len == 0 {
            continue;
        }
        let node = if method == 0 {
            embedded(name, input.nested(fork)).summary(human_size(len.into()))
        } else {
            unsupported(name, fork, &format!("StuffIt {}", method_name(method)))
        };
        cx.emit(node);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// StuffIt 5

pub async fn dissect_sit5(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 100)).await?;
    let mut r = ByteReader::new(&head, file.sub(0, 100));
    let bad = || Diagnostic::truncated(file.sub(0, 100), 0);
    let banner = r.text("Banner", 80).ok_or_else(bad)?;
    r.bytes("Banner end", 2).ok_or_else(bad)?;
    r.u8("Version").ok_or_else(bad)?;
    r.u8("Flags").ok_or_else(bad)?;
    let total = r.u32("Total size", BE).ok_or_else(bad)?;
    r.with(|n| n.summary(human_size(total.into())));
    r.u32("Unknown", BE).ok_or_else(bad)?;
    let entries = r.u16("Root entries", BE).ok_or_else(bad)?;
    let first = r.u32("First entry offset", BE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(first.into())));
    let header_len = to_u64(r.at);
    cx.emit(
        Node::new("Archive header")
            .span(file.sub(0, header_len))
            .summary(banner.trim_end().to_owned())
            .lazy(emit_nodes, r.into_nodes()),
    );
    let mut at = u64::from(first);
    let mut seen = 0u64;
    while at > 0 && seen < MAX_ENTRIES && seen < u64::from(entries).max(1).saturating_mul(4096) {
        let fixed = file.sub(at, 48);
        let raw = cx.read_avail(fixed).await?;
        if u32_be(&raw, 0) != Some(SIT5_MAGIC) {
            if seen == 0 {
                cx.diag(Diagnostic::malformed("no entry at the first entry offset").at(fixed));
            }
            break;
        }
        seen = seen.saturating_add(1);
        let header_size = u64::from(u16_be(&raw, 6).unwrap_or(0));
        let flags = raw.get(9).copied().unwrap_or(0);
        let next = u64::from(u32_be(&raw, 22).unwrap_or(0));
        let name_len = u64::from(u16_be(&raw, 30).unwrap_or(0));
        let length = u32_be(&raw, 34).unwrap_or(0);
        let directory = flags & 0x40 != 0;
        let name_at = if directory {
            48u64
        } else {
            46u64
                .saturating_add(2)
                .saturating_add(u64::from(raw.get(47).copied().unwrap_or(0)))
        };
        let name = cx
            .read_avail(file.sub(at.saturating_add(name_at), name_len.min(1024)))
            .await?;
        let span = file.sub(at, header_size.max(48));
        cx.push(
            Node::new(String::from_utf8_lossy(&name).into_owned())
                .span(span)
                .summary(if directory {
                    "folder".to_owned()
                } else {
                    human_size(length.into())
                })
                .lazy(sit5_entry, (span, directory)),
        )
        .await;
        if next <= at {
            break;
        }
        at = next;
    }
    cx.annotate(format!(
        "StuffIt 5 archive, {}, {}",
        count(entries.into(), "root entry", "root entries"),
        human_size(total.into())
    ));
    Ok(())
}

async fn sit5_entry(cx: Cx, (span, directory): (Span, bool)) -> Result<()> {
    let raw = cx.read(span).await?;
    let mut r = ByteReader::new(&raw, span);
    let bad = || Diagnostic::truncated(span, 0);
    r.u32("Magic", BE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(SIT5_MAGIC.into())));
    r.u8("Version").ok_or_else(bad)?;
    r.u8("Unknown").ok_or_else(bad)?;
    r.u16("Header size", BE).ok_or_else(bad)?;
    r.u8("Unknown").ok_or_else(bad)?;
    let flags = r.u8("Flags").ok_or_else(bad)?;
    r.with(|n| {
        n.value(hex(flags.into()))
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
        r.with(|n| n.value(hex(o.into())));
    }
    let name_len = r.u16("Name length", BE).ok_or_else(bad)?;
    let crc = r.u16("Header CRC", BE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(crc.into())));
    r.u32("Data length", BE).ok_or_else(bad)?;
    r.u32("Data compressed length", BE).ok_or_else(bad)?;
    let dcrc = r.u16("Data CRC", BE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(dcrc.into())));
    r.u16("Unknown", BE).ok_or_else(bad)?;
    if directory {
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
    if r.remaining() > 0 {
        r.bytes("Rest of header", to_u64(r.remaining()));
    }
    emit_nodes(cx, Arc::new(r.nodes)).await
}
