//! Fonts: TrueType/OpenType (sfnt) and collections, WOFF and WOFF2,
//! Embedded OpenType, PostScript Type 1 (PFB), X11 PCF and BDF.
//!
//! An sfnt font is an offset table and a table directory pointing at tagged
//! tables. The directory is listed at once (cheap); a table is read only
//! when expanded, which also verifies its checksum.

pub mod bitmap;
pub mod eot;
pub mod pfb;
pub mod tables;
pub mod woff;

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::datakit::{clip, fourcc};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

const BE: Endian = Endian::Big;
const MAX_TABLES: u16 = 1024;

pub static SFNT: Format = Format {
    name: "sfnt",
    title: "TrueType / OpenType font",
    extensions: &["ttf", "otf", "dfont"],
    mime: "font/sfnt",
    probe: Probe::Custom(probe_sfnt),
    dissect: crate::expander!(dissect: Input),
};

pub static TTC: Format = Format {
    name: "ttc",
    title: "TrueType / OpenType font collection",
    extensions: &["ttc", "otc"],
    mime: "font/collection",
    probe: Probe::Custom(probe_ttc),
    dissect: crate::expander!(collection: Input),
};

/// A plausible table count after a known sfnt version.
fn probe_sfnt(h: &Head<'_>) -> bool {
    let version_ok = h.starts_with(b"\x00\x01\x00\x00")
        || h.starts_with(b"OTTO")
        || h.starts_with(b"true")
        || h.starts_with(b"typ1");
    let tables = u16_be(h.data, 4).unwrap_or(0);
    // searchRange is 16 * the largest power of two <= numTables.
    let search = u16_be(h.data, 6).unwrap_or(0);
    version_ok && (1..=MAX_TABLES).contains(&tables) && search.is_power_of_two() && search >= 16
}

fn probe_ttc(h: &Head<'_>) -> bool {
    h.starts_with(b"ttcf") && matches!(u32_be(h.data, 4), Some(0x0001_0000 | 0x0002_0000))
}

pub fn flavor(version: u32) -> &'static str {
    match &version.to_be_bytes() {
        b"OTTO" => "OpenType (CFF outlines)",
        b"true" => "TrueType (Apple)",
        b"typ1" => "PostScript Type 1 in sfnt",
        _ => "TrueType outlines",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let summary = font_at(&cx, input.span, 0).await?;
    cx.annotate(summary);
    Ok(())
}

/// One entry of the table directory.
#[derive(Clone, Debug)]
pub struct TableEntry {
    pub tag: String,
    pub checksum: u32,
    pub span: Span,
}

/// Emits the offset table and the table directory of the font whose offset
/// table is at `base` (table offsets are relative to `file`, which matters
/// in collections). Returns a summary.
async fn font_at(cx: &Cx, file: Span, base: u64) -> Result<String> {
    let head = cx.read(file.sub_exact(base, 12)?).await?;
    let version = u32_be(&head, 0).unwrap_or(0);
    let count = u16_be(&head, 4).unwrap_or(0);
    cx.emit(struct_node(
        "Offset table",
        file.sub(base, 12),
        BE,
        (),
        |f, _| {
            f.u32("sfnt version")
                .hex()
                .with(|&v, n| n.summary(flavor(v)))
                .emit()?;
            f.u16("Number of tables").emit()?;
            f.u16("Search range").emit()?;
            f.u16("Entry selector").emit()?;
            f.u16("Range shift").emit()?;
            Ok(())
        },
    ));
    if count > MAX_TABLES {
        return Err(Diagnostic::malformed(format!("{count} tables")).at(file.sub(base, 6)));
    }
    let dir = file.sub_exact(base.saturating_add(12), u64::from(count).saturating_mul(16))?;
    let data = cx.read(dir).await?;
    let mut entries = Vec::new();
    for rec in data.as_chunks::<16>().0 {
        let tag = fourcc(rec.get(..4).unwrap_or_default());
        let checksum = u32_be(rec, 4).unwrap_or(0);
        let offset = u64::from(u32_be(rec, 8).unwrap_or(0));
        let length = u64::from(u32_be(rec, 12).unwrap_or(0));
        entries.push(TableEntry {
            tag,
            checksum,
            span: file.sub(offset, length),
        });
    }
    let mut summary = flavor(version).to_owned();
    let names = entries.iter().find(|e| e.tag == "name").map(|e| e.span);
    if let Some(name) = names {
        let family = tables::find_name(cx, name, 4)
            .await
            .or(tables::find_name(cx, name, 1).await);
        if let Some(family) = family {
            summary = format!("{:?}, {summary}", clip(&family, 80));
        }
    }
    if let Some(maxp) = entries.iter().find(|e| e.tag == "maxp") {
        let m = cx.read_avail(maxp.span.sub(0, 6)).await?;
        if let Some(glyphs) = u16_be(&m, 4) {
            summary = format!("{summary}, {glyphs} glyphs");
        }
    }
    summary = format!("{summary}, {count} tables");
    cx.emit(
        Node::new("Table directory")
            .span(dir)
            .summary(format!("{count} tables"))
            .lazy(directory, dir),
    );
    for entry in entries {
        let head = cx.read_avail(entry.span.sub(0, 64)).await?;
        let mut node = table_node(&entry);
        if let Some(s) = tables::short(&entry.tag, &head) {
            let base = node.summary.clone().unwrap_or_default();
            node = node.summary(format!("{base}, {s}"));
        }
        cx.push(node).await;
    }
    Ok(summary)
}

fn table_node(entry: &TableEntry) -> Node {
    let mut summary = format!("{} bytes", entry.span.len);
    if let Some(name) = tables::table_name(&entry.tag) {
        summary = format!("{name}, {summary}");
    }
    Node::new(format!("'{}'", entry.tag))
        .span(entry.span)
        .summary(summary)
        .lazy(table, entry.clone())
}

async fn directory(cx: Cx, dir: Span) -> Result<()> {
    let n = dir.len / 16;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let span = dir.sub(i.saturating_mul(16), 16);
        let data = cx.read(span).await?;
        let tag = fourcc(data.get(..4).unwrap_or_default());
        cx.push(struct_node(format!("'{tag}'"), span, BE, (), |f, _| {
            f.ascii("Tag", 4).emit()?;
            f.u32("Checksum").hex().emit()?;
            f.u32("Offset").hex().emit()?;
            f.u32("Length").emit()?;
            Ok(())
        }))
        .await;
    }
    Ok(())
}

async fn table(cx: Cx, entry: TableEntry) -> Result<()> {
    let padded = entry
        .span
        .len
        .checked_next_multiple_of(4)
        .unwrap_or(u64::MAX);
    let whole = Span::new(entry.span.source, entry.span.offset, padded);
    if padded <= cx.limits().max_read {
        let data = cx.read_avail(whole).await?;
        let computed = tables::checksum(&data, entry.tag == "head");
        let node = Node::new("Checksum").value(crate::formats::datakit::hex(entry.checksum, 32));
        cx.emit(if computed == entry.checksum {
            node.summary("valid")
        } else {
            node.diag(Diagnostic::warning(format!(
                "mismatch: computed {computed:#010x}"
            )))
        });
    }
    tables::decode(&cx, &entry.tag, entry.span).await
}

/// TrueType collections: a header listing the offset tables of the fonts.
pub async fn collection(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub_exact(0, 12)?).await?;
    let version = u32_be(&head, 4).unwrap_or(0);
    let count = u32_be(&head, 8).unwrap_or(0);
    let header_len = 12u64.saturating_add(u64::from(count).saturating_mul(4));
    let dsig = version >= 0x0002_0000;
    let header_span = file.sub(0, header_len.saturating_add(if dsig { 12 } else { 0 }));
    let block = cx.block(header_span).await?;
    let mut offsets = Vec::new();
    {
        let mut f = Fields::emitting(&cx, &block, BE);
        f.ascii("Tag", 4).emit()?;
        f.u32("Version").hex().emit()?;
        f.u32("Number of fonts").emit()?;
        let n = crate::bytes::to_usize(header_span.len.saturating_sub(12) / 4);
        for _ in 0..count.min(u32::try_from(n).unwrap_or(u32::MAX)) {
            offsets.push(f.u32("Offset table offset").hex().emit()?);
        }
        if dsig {
            f.ascii("DSIG tag", 4).emit()?;
            f.u32("DSIG length").emit()?;
            f.u32("DSIG offset").hex().emit()?;
        }
    }
    cx.annotate(format!("font collection, {count} fonts"));
    for (i, offset) in offsets.into_iter().enumerate() {
        let at = u64::from(offset);
        let mut node = Node::new(format!("Font {i}"))
            .span(file.sub(at, 12))
            .lazy(collection_font, (file, at));
        if let Ok(names) = font_name_at(&cx, file, at).await {
            node = node.summary(names);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn collection_font(cx: Cx, (file, at): (Span, u64)) -> Result<()> {
    let summary = font_at(&cx, file, at).await?;
    cx.annotate(summary);
    Ok(())
}

/// The full name of the font whose offset table is at `base`.
async fn font_name_at(cx: &Cx, file: Span, base: u64) -> Result<String> {
    let head = cx.read(file.sub_exact(base, 12)?).await?;
    let count = u16_be(&head, 4).unwrap_or(0).min(MAX_TABLES);
    let dir = cx
        .read(file.sub_exact(base.saturating_add(12), u64::from(count).saturating_mul(16))?)
        .await?;
    for rec in dir.as_chunks::<16>().0 {
        if rec.get(..4) == Some(b"name".as_slice()) {
            let span = file.sub(
                u32_be(rec, 8).unwrap_or(0).into(),
                u32_be(rec, 12).unwrap_or(0).into(),
            );
            if let Some(name) = tables::find_name(cx, span, 4).await {
                return Ok(name);
            }
        }
    }
    Ok(String::new())
}

/// A text value node (for format-specific headers).
pub fn text_node(name: &'static str, span: Span, text: String) -> Node {
    Node::new(name).span(span).value(Value::Text(text))
}
