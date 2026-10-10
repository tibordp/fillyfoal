//! Windows Help files (`.hlp`, WinHelp 3.x/4.x).
//!
//! The file is a small file system: a header points at the directory, a
//! B+ tree mapping internal file names (`|SYSTEM`, `|TOPIC`, `|Phrases`,
//! ...) to offsets. Each internal file starts with a 9-byte header. The
//! `|SYSTEM` file is decoded (version, date, title and other records).

use crate::bytes::{i16_le, to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::util::fmt::clip;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const MAX_LEVELS: u16 = 16;

pub static FORMAT: Format = Format {
    name: "winhelp",
    title: "Windows Help file",
    extensions: &["hlp", "gid"],
    mime: "application/winhlp",
    probe: Probe::Magic(&[(0, b"\x3f\x5f\x03\x00")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    pub struct Header {
        magic: u32 "Magic" .hex(),
        directory: u32 "Directory offset" .hex(),
        free: i32 "First free block",
        size: u32 "File size",
    }
}

record! {
    pub struct FileHeader {
        reserved: u32 "Reserved space",
        used: u32 "Used space",
        flags: u8 "File flags" .hex(),
    }
}

record! {
    pub struct BTreeHeader {
        magic: u16 "Magic" .hex(),
        flags: u16 "Flags" .hex(),
        page_size: u16 "Page size",
        structure: ascii[16] "Structure",
        _zero: u16 "Must be zero",
        splits: u16 "Page splits",
        root: u16 "Root page",
        _minus_one: i16 "Must be -1",
        pages: u16 "Total pages",
        levels: u16 "Levels",
        entries: u32 "Total entries",
    }
}

const SYSTEM_RECORDS: EnumTable = &[
    (1, "Title"),
    (2, "Copyright"),
    (3, "Contents topic"),
    (4, "Macro"),
    (5, "Icon"),
    (6, "Window"),
    (8, "Citation"),
    (9, "Language ID"),
    (10, "Contents file"),
    (11, "Charset"),
    (12, "Default dialog font"),
    (13, "Defined groups"),
    (14, "Index separators"),
    (18, "Language"),
    (19, "DLL maps"),
];

#[derive(Clone, Copy, Debug)]
struct Tree {
    file: Span,
    /// The pages, after the B-tree header.
    pages: Span,
    page_size: u64,
    root: u16,
    levels: u16,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", hspan, LE));
    let dir = file.tail(h.directory.into());
    let fh = dir.sub(0, FileHeader::SIZE);
    cx.emit(FileHeader::node("Directory file header", fh, LE));
    let bspan = dir.sub(FileHeader::SIZE, BTreeHeader::SIZE);
    let b = parse(&cx, bspan, LE, &(), BTreeHeader::layout).await?;
    cx.emit(BTreeHeader::node("Directory B-tree header", bspan, LE));
    if b.magic != 0x293b || b.page_size < 8 {
        return Err(Diagnostic::malformed("bad directory B-tree").at(bspan));
    }
    let tree = Tree {
        file,
        pages: dir.tail(FileHeader::SIZE.saturating_add(BTreeHeader::SIZE)),
        page_size: b.page_size.into(),
        root: b.root,
        levels: b.levels.min(MAX_LEVELS),
    };
    let mut summary = format!("Windows Help file, {} internal files", b.entries);
    if let Ok(Some(offset)) = find(&cx, &tree, "|SYSTEM").await
        && let Ok(Some(title)) = system_title(&cx, file, offset).await
    {
        summary = format!("{summary}, {title:?}");
    }
    cx.annotate(summary);
    cx.emit(
        Node::new("Internal files")
            .summary(format!("{}", b.entries))
            .lazy(files, tree),
    );
    Ok(())
}

/// The leftmost leaf page.
async fn first_leaf(cx: &Cx, tree: &Tree) -> Result<u16> {
    let mut page = tree.root;
    for _ in 1..tree.levels {
        let span = tree
            .pages
            .sub_exact(u64::from(page).saturating_mul(tree.page_size), 6)?;
        let data = cx.read(span).await?;
        page = u16_le(&data, 4).unwrap_or(0);
    }
    Ok(page)
}

/// Leaf entries `(name, offset, span)` of one page, and the next page.
async fn leaf(cx: &Cx, tree: &Tree, page: u16) -> Result<(Vec<(String, u32, Span)>, i16)> {
    let span = tree.pages.sub_exact(
        u64::from(page).saturating_mul(tree.page_size),
        tree.page_size,
    )?;
    let data = cx.read(span).await?;
    let count = u16_le(&data, 2).unwrap_or(0);
    let next = i16_le(&data, 6).unwrap_or(-1);
    let mut at = 8usize;
    let mut out = Vec::new();
    for _ in 0..count {
        let rest = data.get(at..).unwrap_or_default();
        let Some(nul) = rest.iter().position(|&b| b == 0) else {
            break;
        };
        let name = crate::text::latin1(rest.get(..nul).unwrap_or_default());
        let Some(offset) = u32_le(rest, nul.saturating_add(1)) else {
            break;
        };
        let len = nul.saturating_add(5);
        out.push((name, offset, span.sub(to_u64(at), to_u64(len))));
        at = at.saturating_add(len);
    }
    Ok((out, next))
}

async fn find(cx: &Cx, tree: &Tree, wanted: &str) -> Result<Option<u32>> {
    let mut page = i32::from(first_leaf(cx, tree).await?);
    let mut seen = 0u32;
    while page >= 0 && seen < 4096 {
        let (entries, next) = leaf(cx, tree, u16::try_from(page).unwrap_or(0)).await?;
        if let Some((_, offset, _)) = entries.iter().find(|(n, _, _)| n == wanted) {
            return Ok(Some(*offset));
        }
        page = next.into();
        seen = seen.saturating_add(1);
    }
    Ok(None)
}

async fn files(cx: Cx, tree: Tree) -> Result<()> {
    let mut page = i32::from(first_leaf(&cx, &tree).await?);
    let mut seen = Vec::new();
    while page >= 0 {
        if seen.contains(&page) {
            cx.diag(Diagnostic::malformed("leaf pages form a cycle"));
            break;
        }
        seen.push(page);
        let (entries, next) = leaf(&cx, &tree, u16::try_from(page).unwrap_or(0)).await?;
        for (name, offset, entry) in entries {
            let head = cx
                .read_avail(tree.file.sub(offset.into(), FileHeader::SIZE))
                .await?;
            let used = u32_le(&head, 4).unwrap_or(0);
            let span = tree
                .file
                .sub(offset.into(), FileHeader::SIZE.saturating_add(used.into()));
            cx.push(
                Node::new(name.clone())
                    .span(span)
                    .summary(format!("{used} bytes"))
                    .target(entry)
                    .lazy(internal_file, (tree.file, offset, name)),
            )
            .await;
        }
        page = next.into();
    }
    Ok(())
}

async fn internal_file(cx: Cx, (file, offset, name): (Span, u32, String)) -> Result<()> {
    let hspan = file.sub(offset.into(), FileHeader::SIZE);
    let h = parse(&cx, hspan, LE, &(), FileHeader::layout).await?;
    cx.emit(FileHeader::node("File header", hspan, LE));
    let body = file.sub(
        u64::from(offset).saturating_add(FileHeader::SIZE),
        h.used.into(),
    );
    if name == "|SYSTEM" {
        return system(&cx, body).await;
    }
    cx.emit(
        Node::new("Data")
            .span(body)
            .summary(format!("{} bytes", body.len)),
    );
    Ok(())
}

async fn system_title(cx: &Cx, file: Span, offset: u32) -> Result<Option<String>> {
    let body = file.sub(u64::from(offset).saturating_add(FileHeader::SIZE), 0x1000);
    let data = cx.read_avail(body).await?;
    let minor = u16_le(&data, 2).unwrap_or(0);
    if minor <= 16 {
        return Ok(Some(crate::text::until_nul(
            data.get(12..).unwrap_or_default(),
        )));
    }
    let mut at = 12usize;
    while let (Some(kind), Some(len)) = (u16_le(&data, at), u16_le(&data, at.saturating_add(2))) {
        let start = at.saturating_add(4);
        if kind == 1 {
            return Ok(Some(crate::text::until_nul(
                data.get(start..).unwrap_or_default(),
            )));
        }
        at = start.saturating_add(usize::from(len));
    }
    Ok(None)
}

async fn system(cx: &Cx, body: Span) -> Result<()> {
    let block = cx.block(body.sub(0, 12)).await?;
    let mut f = Fields::emitting(cx, &block, LE);
    f.u16("Magic").hex().emit()?;
    let minor = f
        .u16("Minor version")
        .desc("15 = 3.0, 21 = 3.1, 33 = 4.0")
        .emit()?;
    f.u16("Major version").emit()?;
    f.u32("Generated").timestamp().emit()?;
    f.u16("Flags").hex().emit()?;
    let data = cx.read(body).await?;
    if minor <= 16 {
        let title = crate::text::until_nul(data.get(12..).unwrap_or_default());
        cx.emit(
            Node::new("Title")
                .span(body.tail(12))
                .value(Value::Text(title)),
        );
        return Ok(());
    }
    let mut at = 12usize;
    let mut records = 0u32;
    while let (Some(kind), Some(len)) = (u16_le(&data, at), u16_le(&data, at.saturating_add(2))) {
        let start = at.saturating_add(4);
        let end = start.saturating_add(usize::from(len));
        let value = data.get(start..end).unwrap_or_default();
        let name = crate::value::lookup(SYSTEM_RECORDS, kind.into())
            .map_or_else(|| format!("Record {kind}"), str::to_owned);
        let mut node = Node::new(name).span(body.sub(to_u64(at), to_u64(end.saturating_sub(at))));
        node = match kind {
            1 | 2 | 4 | 8 | 10 | 18 => {
                node.value(Value::Text(clip(&crate::text::until_nul(value), 400)))
            }
            3 | 9 | 11 => node.value(Value::UInt {
                value: crate::formats::util::datakit::le_uint(value.get(..4).unwrap_or(value)),
                bits: 32,
                radix: crate::value::Radix::Hex,
            }),
            _ => node.summary(format!("{len} bytes")),
        };
        cx.emit(node);
        records = records.wrapping_add(1);
        if records.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        at = end;
        if to_usize(to_u64(at)) >= data.len() {
            break;
        }
    }
    Ok(())
}
