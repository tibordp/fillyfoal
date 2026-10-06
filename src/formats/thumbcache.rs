//! Windows thumbnail and icon caches (`thumbcache_*.db`, `iconcache_*.db`,
//! Vista and later).
//!
//! A cache database (`CMMM`) is a header followed by entries, each with a
//! hash, an identifier string and the image data (BMP, JPEG or PNG). The
//! index database (`IMMM`) maps hashes to entries; only its header is shown.

use crate::bytes::{u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::datakit::clip;
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "thumbcache",
    title: "Windows thumbnail cache",
    extensions: &["db"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"CMMM")]),
    dissect: crate::expander!(dissect: Input),
};

pub static INDEX: Format = Format {
    name: "thumbcache-index",
    title: "Windows thumbnail cache index",
    extensions: &["db"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"IMMM")]),
    dissect: crate::expander!(index: Input),
};

const VERSIONS: EnumTable = &[
    (20, "Windows Vista"),
    (21, "Windows 7"),
    (30, "Windows 8"),
    (31, "Windows 8.1"),
    (32, "Windows 10/11"),
];

/// Cache types differ between versions; these are the Windows 8+ names.
const CACHE_TYPES: EnumTable = &[
    (0, "16"),
    (1, "32"),
    (2, "48"),
    (3, "96"),
    (4, "256"),
    (5, "768"),
    (6, "1280"),
    (7, "1920"),
    (8, "2560"),
    (9, "sr"),
    (10, "wide"),
    (11, "exif"),
    (12, "wide_alternate"),
    (13, "custom_stream"),
];

fn header(f: &mut Fields<'_>, _: &()) -> Result<(u32, u64)> {
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Format version").enumeration(VERSIONS).emit()?;
    f.u32("Cache type").enumeration(CACHE_TYPES).emit()?;
    if version >= 30 {
        f.u32("Unknown").emit()?;
    }
    let first = f.u32("First cache entry offset").hex().emit()?;
    f.u32("Available cache entry offset").hex().emit()?;
    if version < 30 {
        f.u32("Number of cache entries").emit()?;
    }
    Ok((version, first.into()))
}

fn entry_header_size(version: u32) -> u64 {
    match version {
        20 | 30.. => 56,
        _ => 48,
    }
}

fn entry(f: &mut Fields<'_>, version: &u32) -> Result<(u32, u32, u32)> {
    f.ascii("Signature", 4).emit()?;
    f.u32("Entry size").emit()?;
    f.u64("Entry hash").hex().emit()?;
    if *version == 20 {
        f.utf16("File extension", 4).emit()?;
    }
    let id = f.u32("Identifier size").emit()?;
    let padding = f.u32("Padding size").emit()?;
    let data = f.u32("Data size").emit()?;
    if *version >= 30 {
        f.u32("Width").emit()?;
        f.u32("Height").emit()?;
    }
    f.u32("Unknown").emit()?;
    f.u64("Data checksum").hex().emit()?;
    f.u64("Header checksum").hex().emit()?;
    Ok((id, padding, data))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_size = 24;
    let hspan = file.sub(0, header_size);
    let (version, first) = parse(&cx, hspan, LE, &(), header).await?;
    cx.emit(struct_node("Header", hspan, LE, (), header));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(first.max(header_size));
    let hsize = entry_header_size(version);
    let mut count = 0u64;
    while cur.remaining() >= hsize {
        let start = cur.pos();
        let head = cur.peek(hsize).await?;
        if !head.starts_with(b"CMMM") {
            break;
        }
        let size = u32_le(&head, 4).unwrap_or(0);
        if u64::from(size) < hsize {
            return Err(Diagnostic::malformed("cache entry smaller than its header")
                .at(file.sub(start, 8)));
        }
        let span = file.sub(start, size.into());
        cur.seek(start.saturating_add(size.into()));
        let entry_hdr = span.sub(0, hsize);
        let (id_size, padding, data_size) = parse(&cx, entry_hdr, LE, &version, entry).await?;
        let id_span = span.sub(hsize, id_size.into());
        let id = crate::text::utf16(&cx.read_avail(id_span.sub(0, 0x400)).await?, LE);
        let hash = u64_le(&head, 8).unwrap_or(0);
        let mut summary = format!("{data_size} bytes");
        if version >= 30 {
            let w = u32_le(&head, 36).unwrap_or(0);
            let h = u32_le(&head, 40).unwrap_or(0);
            if w > 0 {
                summary = format!("{w}×{h}, {summary}");
            }
        }
        let name = if id.is_empty() {
            format!("Entry {hash:016x}")
        } else {
            clip(&id, 80)
        };
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(cache_entry, (input, span, version, id_size, padding, data_size)),
        )
        .await;
        count = count.saturating_add(1);
    }
    cx.annotate(format!(
        "Windows thumbnail cache ({}), {count} entries",
        crate::value::lookup(VERSIONS, version.into()).unwrap_or("unknown version")
    ));
    Ok(())
}

async fn cache_entry(
    cx: Cx,
    (input, span, version, id_size, padding, data_size): (Input, Span, u32, u32, u32, u32),
) -> Result<()> {
    let hsize = entry_header_size(version);
    cx.emit(struct_node("Entry header", span.sub(0, hsize), LE, version, entry));
    let id_span = span.sub(hsize, id_size.into());
    if id_size > 0 {
        let id = crate::text::utf16(&cx.read(id_span).await?, LE);
        cx.emit(Node::new("Identifier").span(id_span).value(Value::Text(id)));
    }
    let data_at = hsize.saturating_add(id_size.into()).saturating_add(padding.into());
    if padding > 0 {
        cx.emit(Node::new("Padding").span(span.sub(hsize.saturating_add(id_size.into()), padding.into())));
    }
    if data_size > 0 {
        let data = span.sub(data_at, data_size.into());
        cx.emit(embedded("Data", input.nested(data)).summary(format!("{data_size} bytes")));
    }
    Ok(())
}

pub async fn index(cx: Cx, input: Input) -> Result<()> {
    let span = input.span.sub(0, 24);
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Format version").enumeration(VERSIONS).emit()?;
    f.u32("Unknown").emit()?;
    let used = f.u32("Used entries").emit()?;
    let total = f.u32("Entries").emit()?;
    f.u32("Unknown").emit()?;
    cx.annotate(format!(
        "Windows thumbnail cache index ({}), {used} of {total} entries used",
        crate::value::lookup(VERSIONS, version.into()).unwrap_or("unknown version")
    ));
    let rest = input.span.tail(24);
    if !rest.is_empty() {
        cx.emit(Node::new("Index entries").span(rest));
    }
    Ok(())
}
