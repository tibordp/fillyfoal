//! ZOO archives.
//!
//! A text banner and an archive header pointing at the first directory
//! entry; entries form a linked list (each holds the offset of the next and
//! of its data). The list ends with an entry whose `next` is zero. Stored
//! members are dissected in place; LZW and LZH data are unsupported leaves.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{ByteReader, count, emit_nodes, hex, human_size, unsupported};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const TAG: u32 = 0xfdc4_a7dc;
/// The fixed part of a directory entry.
const ENTRY: u64 = 51;
const MAX_ENTRIES: u64 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "zoo",
    title: "ZOO archive",
    extensions: &["zoo"],
    mime: "application/x-zoo",
    probe: Probe::Custom(|h| h.at(20, b"\xdc\xa7\xc4\xfd") && h.starts_with(b"ZOO ")),
    dissect: crate::expander!(dissect: Input),
};

const METHOD: EnumTable = &[(0, "stored"), (1, "LZW"), (2, "LZH")];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 34)).await?;
    let start = u32_le(&head, 24).unwrap_or(0);
    let minus = u32_le(&head, 28).unwrap_or(0);
    let banner = crate::text::until_nul(head.get(..20).unwrap_or_default());
    let mut r = ByteReader::new(&head, file.sub(0, 34));
    r.text("Banner", 20);
    r.with(|n| {
        n.value(crate::formats::util::arcutil::text(
            banner.trim_end_matches('\x1a').trim(),
        ))
    });
    r.u32("Tag", LE);
    r.with(|n| n.value(hex(TAG.into())));
    r.u32("First entry offset", LE);
    r.with(|n| {
        n.value(hex(start.into()))
            .target(file.sub(start.into(), ENTRY))
    });
    r.u32("Consistency check", LE);
    r.with(|n| {
        if start.wrapping_add(minus) == 0 {
            n.value(hex(minus.into()))
                .summary("valid (negated first entry offset)")
        } else {
            n.value(hex(minus.into())).diag(Diagnostic::warning(
                "does not negate the first entry offset",
            ))
        }
    });
    r.u8("Major version");
    r.u8("Minor version");
    cx.emit(
        Node::new("Archive header")
            .span(file.sub(0, 34))
            .summary(banner.trim_end_matches('\x1a').trim().to_owned())
            .lazy(emit_nodes, r.into_nodes()),
    );
    let mut at = u64::from(start);
    let mut files = 0u64;
    let mut total = 0u64;
    let mut seen = 0u64;
    loop {
        if seen >= MAX_ENTRIES {
            cx.diag(Diagnostic::limit("too many directory entries"));
            break;
        }
        seen = seen.saturating_add(1);
        let span = file.sub(at, ENTRY);
        let e = cx.read(span).await?;
        if u32_le(&e, 0) != Some(TAG) {
            return Err(Diagnostic::malformed("directory entry without tag").at(span));
        }
        let next = u64::from(u32_le(&e, 6).unwrap_or(0));
        if next == 0 {
            cx.emit(Node::new("End of directory").span(span));
            break;
        }
        let kind = e.get(4).copied().unwrap_or(0);
        let var = if kind == 2 {
            let v = cx.read_avail(file.sub(at.saturating_add(ENTRY), 2)).await?;
            u64::from(u16_le(&v, 0).unwrap_or(0)).saturating_add(2)
        } else {
            0
        };
        let entry_span = file.sub(at, ENTRY.saturating_add(var));
        let entry = cx.read(entry_span).await?;
        let (name, original, deleted) = entry_name(&entry);
        files = files.saturating_add(1);
        total = total.saturating_add(original);
        let mut node = Node::new(name)
            .span(entry_span)
            .summary(human_size(original))
            .lazy(directory_entry, (input, entry_span));
        if deleted {
            node = node.summary(format!("{}, deleted", human_size(original)));
        }
        cx.push(node).await;
        if next <= at {
            cx.diag(Diagnostic::malformed("directory entries do not move forward").at(span));
            break;
        }
        at = next;
    }
    cx.annotate(format!(
        "ZOO archive, {}, {} uncompressed",
        count(files, "file", "files"),
        human_size(total)
    ));
    Ok(())
}

/// The best name of an entry (long name and directory, if present), its
/// original size, and whether it is marked deleted.
fn entry_name(e: &[u8]) -> (String, u64, bool) {
    let short = crate::text::until_nul(e.get(38..51).unwrap_or_default());
    let original = u64::from(u32_le(e, 20).unwrap_or(0));
    let deleted = e.get(30).is_some_and(|&d| d != 0);
    let mut name = short;
    if e.get(4) == Some(&2) {
        let namlen = usize::from(e.get(56).copied().unwrap_or(0));
        let dirlen = usize::from(e.get(57).copied().unwrap_or(0));
        let long = e
            .get(58..58usize.saturating_add(namlen))
            .map(crate::text::until_nul);
        let dir_at = 58usize.saturating_add(namlen);
        let dir = e
            .get(dir_at..dir_at.saturating_add(dirlen))
            .map(crate::text::until_nul);
        if let Some(l) = long.filter(|l| !l.is_empty()) {
            name = l;
        }
        if let Some(d) = dir.filter(|d| !d.is_empty()) {
            name = format!("{}/{name}", d.trim_end_matches('/'));
        }
    }
    (name, original, deleted)
}

async fn directory_entry(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let e = cx.read(span).await?;
    let mut r = ByteReader::new(&e, span);
    let bad = || Diagnostic::malformed("truncated directory entry").at(span);
    r.u32("Tag", LE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(TAG.into())));
    let kind = r.u8("Type").ok_or_else(bad)?;
    let method = r.u8("Packing method").ok_or_else(bad)?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: method.into(),
            bits: 8,
            name: crate::value::lookup(METHOD, method.into()),
        })
    });
    let next = r.u32("Next entry", LE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(next.into())));
    let offset = r.u32("Data offset", LE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(offset.into())));
    let date = r.u16("Date", LE).ok_or_else(bad)?;
    let time = r.u16("Time", LE).ok_or_else(bad)?;
    r.with(|n| n.summary(crate::text::dos_datetime(date, time)));
    let crc = r.u16("File CRC-16", LE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(crc.into())));
    let original = r.u32("Original size", LE).ok_or_else(bad)?;
    r.with(|n| n.summary(human_size(original.into())));
    let packed = r.u32("Compressed size", LE).ok_or_else(bad)?;
    r.u8("Major version").ok_or_else(bad)?;
    r.u8("Minor version").ok_or_else(bad)?;
    r.u8("Deleted").ok_or_else(bad)?;
    r.u8("Structure").ok_or_else(bad)?;
    let comment = r.u32("Comment offset", LE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(comment.into())));
    r.u16("Comment size", LE).ok_or_else(bad)?;
    let short = crate::text::until_nul(e.get(38..51).unwrap_or_default());
    r.bytes("Short name", 13).ok_or_else(bad)?;
    r.with(|n| n.value(crate::formats::util::arcutil::text(short)));
    if kind == 2 {
        r.u16("Variable part length", LE).ok_or_else(bad)?;
        r.u8("Time zone").ok_or_else(bad)?;
        r.u16("Entry CRC-16", LE).ok_or_else(bad)?;
        let namlen = r.u8("Long name length").ok_or_else(bad)?;
        let dirlen = r.u8("Directory length").ok_or_else(bad)?;
        for (name, len) in [("Long name", namlen), ("Directory", dirlen)] {
            if len > 0 {
                let raw = r.bytes(name, len.into()).ok_or_else(bad)?;
                let value = crate::formats::util::arcutil::text(crate::text::until_nul(raw));
                r.with(|n| n.value(value));
            }
        }
        if r.remaining() >= 2 {
            r.u16("System ID", LE);
        }
        if r.remaining() > 0 {
            let rest = crate::bytes::to_u64(r.remaining());
            r.bytes("Attributes and version", rest);
        }
    }
    cx.emit(
        Node::new("Directory entry")
            .span(span)
            .lazy(emit_nodes, r.into_nodes()),
    );
    let file = input.span;
    let data = file.sub(offset.into(), packed.into());
    let node = if method == 0 {
        embedded("Content", input.nested(data)).summary(human_size(packed.into()))
    } else {
        let m = crate::value::lookup(METHOD, method.into()).unwrap_or("unknown");
        unsupported("Compressed data", data, &format!("ZOO {m}"))
    };
    cx.emit(crate::formats::util::arcutil::check_len(
        node,
        data,
        packed.into(),
    ));
    Ok(())
}
