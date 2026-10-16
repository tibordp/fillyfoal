//! Proxmox Backup Server catalogs: the file list of a backup snapshot
//! (`catalog.pcat1`, stored in the datastore as `catalog.pcat1.didx`, so
//! the raw catalog is the content of its chunks or of a restored copy).
//!
//! After an 8-byte magic come directory tables, each written after the
//! tables of its subdirectories, and at the end the little-endian offset of
//! the root's table. A table is its size and entry count (LEB128), then the
//! entries: a type byte (`d` directory, `f` file, `l` symlink, `h` hard
//! link, `b`/`c` block and character devices, `p` FIFO, `s` socket), the
//! name's length and the name, then for a directory how far before this
//! table its own table starts, and for a file its size and modification
//! time (seconds; negative times are written as the magnitude's LEB128
//! continued by a zero byte). The root lists the snapshot's archives
//! (`files.pxar.didx`) as directories.
//!
//! The layout is from Proxmox Backup's `pbs-datastore/src/catalog.rs`
//! (AGPL-3.0), read for facts only; checked against catalogs written by
//! proxmox-backup-client 3.4.9.

use crate::bytes::u64_le;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt::{grouped_count, size};
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const MAGIC: [u8; 8] = [145, 253, 96, 249, 196, 103, 88, 213];
/// Longest name read (a Linux path component is at most 255 bytes).
const MAX_NAME: u64 = 4096;

const KINDS: EnumTable = &[
    (b'd' as u64, "directory"),
    (b'f' as u64, "file"),
    (b'l' as u64, "symlink"),
    (b'h' as u64, "hard link"),
    (b'b' as u64, "block device"),
    (b'c' as u64, "character device"),
    (b'p' as u64, "FIFO"),
    (b's' as u64, "socket"),
];

pub static FORMAT: Format = Format {
    name: "pbs-catalog",
    title: "Proxmox Backup Server catalog",
    extensions: &["pcat1"],
    mime: "application/x-proxmox-backup-catalog",
    probe: Probe::Magic(&[(0, &MAGIC)]),
    dissect: crate::expander!(dissect: Input),
};

/// A directory table: the catalog and the table's offset in it.
#[derive(Clone, Copy)]
struct Table {
    file: Span,
    at: u64,
}

/// A table's entries span and entry count.
async fn table_head(cx: &Cx, t: Table) -> Result<(Span, Span, u64)> {
    let mut cur = Cursor::new(cx, t.file, Endian::Little);
    cur.seek(t.at);
    let len = cur.uleb128().await?;
    let head_end = cur.pos();
    let body = t.file.sub_exact(head_end, len)?;
    let mut inner = Cursor::new(cx, body, Endian::Little);
    let count = inner.uleb128().await?;
    let head = t.file.sub(
        t.at,
        head_end.saturating_sub(t.at).saturating_add(inner.pos()),
    );
    Ok((head, body.tail(inner.pos()), count))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 8))
            .value(text("catalog 1.0")),
    );
    if file.len < 16 {
        return Err(Diagnostic::truncated(
            file.tail(8),
            file.len.saturating_sub(8),
        ));
    }
    let ptr = file.sub(file.len.saturating_sub(8), 8);
    let root = u64_le(&cx.read(ptr).await?, 0).unwrap_or(0);
    let mut ptr_node = Node::new("Root table offset")
        .span(ptr)
        .value(hex(root, 64))
        .target(file.sub(root, 1));
    if root < 8 || root >= ptr.offset.saturating_sub(file.offset) {
        ptr_node = ptr_node.diag(Diagnostic::malformed("outside the directory tables"));
        cx.emit(ptr_node);
        return Ok(());
    }
    cx.emit(ptr_node);
    let tables = file.sub(0, file.len.saturating_sub(8));
    let t = Table {
        file: tables,
        at: root,
    };
    let (_, _, count) = table_head(&cx, t).await?;
    cx.annotate(format!(
        "Proxmox Backup catalog, {}",
        grouped_count(count, "archive", "archives")
    ));
    cx.emit(
        Node::new("Root")
            .span(tables.sub(root, tables.len.saturating_sub(root)))
            .summary(grouped_count(count, "entry", "entries"))
            .lazy(directory, t),
    );
    Ok(())
}

/// A catalog's signed integer: LEB128 of the magnitude, and for a negative
/// value a zero byte after a byte with the continuation bit set.
async fn catalog_i64(cur: &mut Cursor<'_>) -> Result<i64> {
    let start = cur.pos();
    let mut v: u64 = 0;
    for i in 0..11u32 {
        let b = cur.u8().await?;
        if b == 0 {
            if i == 0 {
                return Ok(0);
            }
            let m = i64::try_from(v.saturating_sub(1)).unwrap_or(i64::MAX);
            return Ok(m.saturating_neg().saturating_sub(1));
        }
        let shift = i.saturating_mul(7);
        v |= u64::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
        if b < 0x80 {
            return Ok(i64::try_from(v).unwrap_or(i64::MAX));
        }
    }
    Err(Diagnostic::malformed("integer longer than 11 bytes").at(cur.since(start)))
}

/// One entry of a table.
struct Entry {
    kind: u8,
    name: Vec<u8>,
    name_span: Span,
    /// Directory: its table's offset; file: size and mtime.
    dir: Option<u64>,
    file: Option<(u64, i64)>,
}

async fn entry(cur: &mut Cursor<'_>, table_at: u64) -> Result<Entry> {
    let kind = cur.u8().await?;
    if !KINDS.iter().any(|&(k, _)| k == u64::from(kind)) {
        return Err(
            Diagnostic::malformed(format!("unknown entry type {kind:#04x}")).at(cur.span(1)),
        );
    }
    let len = cur.uleb128().await?;
    if len > MAX_NAME {
        return Err(Diagnostic::malformed(format!("{len}-byte name")).at(cur.span(1)));
    }
    let name_span = cur.span(len);
    let name = cur.bytes(len).await?;
    let mut e = Entry {
        kind,
        name,
        name_span,
        dir: None,
        file: None,
    };
    match kind {
        b'd' => {
            let delta = cur.uleb128().await?;
            e.dir = Some(table_at.wrapping_sub(delta));
            if delta == 0 || delta > table_at {
                e.dir = None;
            }
        }
        b'f' => {
            let size = cur.uleb128().await?;
            let mtime = catalog_i64(cur).await?;
            e.file = Some((size, mtime));
        }
        _ => {}
    }
    Ok(e)
}

/// A directory's entries.
async fn directory(cx: Cx, t: Table) -> Result<()> {
    let (head, body, count) = table_head(&cx, t).await?;
    let resumed = cx.resume::<(u64, u64)>();
    let (pos, mut index) = resumed.unwrap_or((0, 0));
    if resumed.is_none() {
        cx.push(Node::new("Table header").span(head).summary(format!(
            "{}, {}",
            size(head.len.saturating_add(body.len)),
            grouped_count(count, "entry", "entries")
        )))
        .await;
    }
    let mut cur = Cursor::new(&cx, body, Endian::Little);
    cur.seek(pos);
    while index < count {
        let start = cur.pos();
        if cur.at_end() {
            cx.diag(Diagnostic::malformed(format!(
                "the table ends after {index} of {count} entries"
            )));
            break;
        }
        let mark = (start, index);
        cx.mark(move || mark);
        let e = entry(&mut cur, t.at).await?;
        let span = cur.since(start);
        let name = String::from_utf8_lossy(&e.name).into_owned();
        let kind = crate::formats::util::val::name_or(KINDS, u64::from(e.kind), "type");
        let mut node = Node::new(name).span(span);
        node = match (e.kind, e.dir, e.file) {
            (b'd', Some(at), _) => node.summary(kind).lazy(
                crate::expander!(self::directory: Table),
                Table { file: t.file, at },
            ),
            (b'd', None, _) => node.summary(kind).diag(Diagnostic::malformed(
                "its table offset is not before this table",
            )),
            (_, _, Some((size_, mtime))) => node
                .value(Value::utc(mtime))
                .summary(format!("{kind}, {}", size(size_)))
                .lazy(fields, (span, e.name_span)),
            _ => node.summary(kind).lazy(fields, (span, e.name_span)),
        };
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    if index >= count && !cur.at_end() {
        cx.emit(
            Node::new("Unused")
                .span(body.tail(cur.pos()))
                .diag(Diagnostic::warning("bytes after the table's last entry")),
        );
    }
    Ok(())
}

/// An entry's fields, re-read from its span.
async fn fields(cx: Cx, (span, name_span): (Span, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, Endian::Little);
    let kind = cur.u8().await?;
    cx.emit(
        Node::new("Type")
            .span(span.sub(0, 1))
            .value(crate::formats::util::val::enumv(kind, 8, KINDS)),
    );
    let start = cur.pos();
    let len = cur.uleb128().await?;
    cx.emit(
        Node::new("Name length")
            .span(cur.since(start))
            .value(uint(len, 64)),
    );
    cx.emit(Node::new("Name").span(name_span).value(Value::Text(
        String::from_utf8_lossy(&cx.read(name_span).await?).into_owned(),
    )));
    cur.skip(len);
    if kind == b'f' {
        let start = cur.pos();
        let size_ = cur.uleb128().await?;
        cx.emit(
            Node::new("Size")
                .span(cur.since(start))
                .value(crate::formats::util::val::size(size_, 64)),
        );
        let start = cur.pos();
        let mtime = catalog_i64(&mut cur).await?;
        cx.emit(
            Node::new("Modification time")
                .span(cur.since(start))
                .value(Value::utc(mtime)),
        );
    }
    Ok(())
}
