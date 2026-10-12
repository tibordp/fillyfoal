//! OpenType tables that stand on their own: the layout tables GSUB and GPOS
//! (script, feature and lookup lists), DSIG (PKCS#7 signatures) and SVG
//! (glyph documents). Field names follow the OpenType specification.

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt::{fourcc, plural};
use crate::formats::{Input, embedded, embedded_named};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const BE: Endian = Endian::Big;

const GSUB_LOOKUPS: EnumTable = &[
    (1, "Single"),
    (2, "Multiple"),
    (3, "Alternate"),
    (4, "Ligature"),
    (5, "Context"),
    (6, "Chained context"),
    (7, "Extension"),
    (8, "Reverse chained single"),
];

const GPOS_LOOKUPS: EnumTable = &[
    (1, "Single adjustment"),
    (2, "Pair adjustment"),
    (3, "Cursive attachment"),
    (4, "Mark-to-base attachment"),
    (5, "Mark-to-ligature attachment"),
    (6, "Mark-to-mark attachment"),
    (7, "Context positioning"),
    (8, "Chained context positioning"),
    (9, "Extension positioning"),
];

/// A table's tag from a record's first four bytes.
fn tag_at(b: &[u8], at: usize) -> String {
    b.get(at..at.saturating_add(4))
        .map(fourcc)
        .unwrap_or_default()
}

/// Reads the `count`-prefixed array of `size`-byte records at `at` in
/// `span`: the records' span and bytes.
async fn records(cx: &Cx, span: Span, at: u64, size: u64) -> Result<(u16, Span, Vec<u8>)> {
    let head = cx.read(span.sub_exact(at, 2)?).await?;
    let count = u16_be(&head, 0).unwrap_or(0);
    let table = span.sub_exact(at.saturating_add(2), u64::from(count).saturating_mul(size))?;
    let data = cx.read(table).await?;
    Ok((count, table, data))
}

/// GSUB or GPOS: the header, then the three lists as lazy nodes.
pub async fn layout(cx: &Cx, span: Span, gpos: bool) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 10)?).await?;
    let minor = u16_be(&head, 2).unwrap_or(0);
    let header_len = if minor >= 1 { 14 } else { 10 };
    cx.emit(struct_node(
        "Header",
        span.sub(0, header_len),
        BE,
        (),
        |f: &mut Fields<'_>, _| {
            f.u16("Major version").emit()?;
            let minor = f.u16("Minor version").emit()?;
            f.u16("Script list offset").hex().emit()?;
            f.u16("Feature list offset").hex().emit()?;
            f.u16("Lookup list offset").hex().emit()?;
            if minor >= 1 {
                f.u32("Feature variations offset").hex().emit()?;
            }
            Ok(())
        },
    ));
    let offset = |at: usize| u64::from(u16_be(&head, at).unwrap_or(0));
    let lists = [
        ("Scripts", offset(4)),
        ("Features", offset(6)),
        ("Lookups", offset(8)),
    ];
    for (i, (name, at)) in lists.into_iter().enumerate() {
        if at == 0 {
            continue;
        }
        let list = span.tail(at);
        let count = cx
            .read_avail(list.sub(0, 2))
            .await
            .ok()
            .and_then(|b| u16_be(&b, 0));
        let record = if i == 2 { 2 } else { 6 };
        let n = count.unwrap_or(0);
        let mut node = Node::new(name)
            .span(list.sub(0, 2u64.saturating_add(u64::from(n).saturating_mul(record))));
        if count.is_some() {
            node = node.summary(format!("{n}"));
        }
        cx.emit(match i {
            0 => node.lazy(script_list, list),
            1 => node.lazy(feature_list, list),
            _ => node.lazy(lookup_list, (list, gpos)),
        });
    }
    Ok(())
}

async fn script_list(cx: Cx, list: Span) -> Result<()> {
    let (count, table, data) = records(&cx, list, 0, 6).await?;
    cx.set_count(Count::Exact(count.into()));
    for (i, rec) in data.as_chunks::<6>().0.iter().enumerate() {
        let tag = tag_at(rec, 0);
        let script = list.tail(u64::from(u16_be(rec, 4).unwrap_or(0)));
        let sh = cx.read_avail(script.sub(0, 4)).await?;
        let default = u16_be(&sh, 0).unwrap_or(0) != 0;
        let langs = u16_be(&sh, 2).unwrap_or(0);
        let summary = format!(
            "{}{langs} language systems",
            if default { "default + " } else { "" }
        );
        cx.push(
            Node::new(format!("'{tag}'"))
                .span(table.sub(to_u64(i).saturating_mul(6), 6))
                .summary(summary)
                .lazy(script_table, script),
        )
        .await;
    }
    Ok(())
}

async fn script_table(cx: Cx, script: Span) -> Result<()> {
    let sh = cx.read(script.sub_exact(0, 2)?).await?;
    let default = u64::from(u16_be(&sh, 0).unwrap_or(0));
    if default != 0 {
        cx.emit(lang_sys(&cx, "Default language system".into(), script.tail(default)).await?);
    }
    let (_, _, data) = records(&cx, script, 2, 6).await?;
    for rec in data.as_chunks::<6>().0 {
        let tag = tag_at(rec, 0);
        let at = u64::from(u16_be(rec, 4).unwrap_or(0));
        cx.push(lang_sys(&cx, format!("'{tag}'"), script.tail(at)).await?)
            .await;
    }
    Ok(())
}

/// A LangSys table: the required feature and the feature indices.
async fn lang_sys(cx: &Cx, name: String, span: Span) -> Result<Node> {
    let h = cx.read_avail(span.sub(0, 6)).await?;
    let required = u16_be(&h, 2).unwrap_or(0xffff);
    let count = u16_be(&h, 4).unwrap_or(0);
    let all = span.sub(0, 6u64.saturating_add(u64::from(count).saturating_mul(2)));
    let indices = cx.read_avail(all.sub(6, 2u64.saturating_mul(64))).await?;
    let mut list: Vec<String> = indices
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c).to_string())
        .collect();
    if count > 64 {
        list.push("…".into());
    }
    let mut summary = plural(count, "feature");
    if required != 0xffff {
        summary = format!("{summary}, required feature {required}");
    }
    let node = Node::new(name).span(all).summary(summary);
    Ok(if list.is_empty() {
        node
    } else {
        node.value(Value::Text(format!("feature indices {}", list.join(", "))))
    })
}

async fn feature_list(cx: Cx, list: Span) -> Result<()> {
    let (count, table, data) = records(&cx, list, 0, 6).await?;
    cx.set_count(Count::Exact(count.into()));
    for (i, rec) in data.as_chunks::<6>().0.iter().enumerate() {
        let tag = tag_at(rec, 0);
        let feature = list.tail(u64::from(u16_be(rec, 4).unwrap_or(0)));
        let fh = cx.read_avail(feature.sub(0, 4)).await?;
        let n = u16_be(&fh, 2).unwrap_or(0);
        let indices = cx
            .read_avail(feature.sub(4, 2u64.saturating_mul(32)))
            .await?;
        let mut lookups: Vec<String> = indices
            .as_chunks::<2>()
            .0
            .iter()
            .take(n.into())
            .map(|c| u16::from_be_bytes(*c).to_string())
            .collect();
        if n > 32 {
            lookups.push("…".into());
        }
        let mut node = Node::new(format!("[{i}] '{tag}'"))
            .span(table.sub(to_u64(i).saturating_mul(6), 6))
            .summary(plural(n, "lookup"));
        if !lookups.is_empty() {
            node = node.value(Value::Text(format!(
                "lookup indices {}",
                lookups.join(", ")
            )));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn lookup_list(cx: Cx, (list, gpos): (Span, bool)) -> Result<()> {
    let (count, _, data) = records(&cx, list, 0, 2).await?;
    cx.set_count(Count::Exact(count.into()));
    let types = if gpos { GPOS_LOOKUPS } else { GSUB_LOOKUPS };
    for (i, rec) in data.as_chunks::<2>().0.iter().enumerate() {
        let at = u64::from(u16::from_be_bytes(*rec));
        let lh = cx.read_avail(list.tail(at).sub(0, 6)).await?;
        let kind = u16_be(&lh, 0).unwrap_or(0);
        let flags = u16_be(&lh, 2).unwrap_or(0);
        let subtables = u16_be(&lh, 4).unwrap_or(0);
        let name = lookup(types, kind.into()).map_or_else(|| format!("type {kind}"), str::to_owned);
        let lspan = list.tail(at).sub(
            0,
            6u64.saturating_add(u64::from(subtables).saturating_mul(2)),
        );
        cx.push(
            Node::new(format!("Lookup {i}"))
                .span(lspan)
                .summary(format!(
                    "{name}, {subtables_subtable}, flags {flags:#06x}",
                    subtables_subtable = plural(subtables, "subtable")
                ))
                .lazy(lookup_table, lspan),
        )
        .await;
    }
    Ok(())
}

async fn lookup_table(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 6)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("Lookup type").emit()?;
    f.u16("Lookup flag")
        .hex()
        .desc("1 right-to-left, 2 ignore base glyphs, 4 ignore ligatures, 8 ignore marks, 0x10 use mark filtering set, 0xff00 mark attachment type")
        .emit()?;
    f.u16("Subtable count").emit()?;
    let offsets = span.tail(6);
    if !offsets.is_empty() {
        cx.emit(
            Node::new("Subtable offsets")
                .span(offsets)
                .summary(format!("{}", offsets.len / 2)),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DSIG

/// DSIG: the signature records; each format 1 block holds a PKCS#7
/// SignedData, handed to the PKCS#7 dissector.
pub async fn dsig(cx: &Cx, input: Input, span: Span) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 8)?).await?;
    let count = u16_be(&head, 4).unwrap_or(0);
    cx.emit(struct_node("Header", span.sub(0, 8), BE, (), |f, _| {
        f.u32("Version").emit()?;
        f.u16("Number of signatures").emit()?;
        f.u16("Flags").hex().desc("1 = cannot be resigned").emit()?;
        Ok(())
    }));
    let table = span.sub_exact(8, u64::from(count).saturating_mul(12))?;
    let data = cx.read(table).await?;
    for (i, rec) in data.as_chunks::<12>().0.iter().enumerate() {
        let format = u32_be(rec, 0).unwrap_or(0);
        let length = u64::from(u32_be(rec, 4).unwrap_or(0));
        let offset = u64::from(u32_be(rec, 8).unwrap_or(0));
        let block = span.sub(offset, length);
        let mut node = Node::new(format!("Signature {i}"))
            .span(block)
            .summary(format!("format {format}, {length} bytes"));
        if format == 1 {
            let bh = cx.read_avail(block.sub(0, 8)).await?;
            let sig_len = u64::from(u32_be(&bh, 4).unwrap_or(0));
            let sig = block.sub(8, sig_len);
            node = node.lazy(dsig_block, (input, block, sig));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn dsig_block(cx: Cx, (input, block, sig): (Input, Span, Span)) -> Result<()> {
    cx.emit(struct_node("Header", block.sub(0, 8), BE, (), |f, _| {
        f.u16("Reserved 1").emit()?;
        f.u16("Reserved 2").emit()?;
        f.u32("Signature length").emit()?;
        Ok(())
    }));
    cx.emit(embedded_named(
        "PKCS#7 signature",
        input.nested(sig),
        "pkcs7",
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// SVG

/// SVG: the document index; each document (SVG text, possibly gzipped) is
/// dissected as whatever it is.
pub async fn svg(cx: &Cx, input: Input, span: Span) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 10)?).await?;
    cx.emit(struct_node("Header", span.sub(0, 10), BE, (), |f, _| {
        f.u16("Version").emit()?;
        f.u32("Document list offset").hex().emit()?;
        f.u32("Reserved").emit()?;
        Ok(())
    }));
    let list = span.tail(u64::from(u32_be(&head, 2).unwrap_or(0)));
    let (count, table, _) = records(cx, list, 0, 12).await?;
    cx.emit(
        Node::new("Documents")
            .span(list.sub(0, table.len.saturating_add(2)))
            .summary(format!("{count}"))
            .lazy(svg_documents, (input, list, count)),
    );
    Ok(())
}

async fn svg_documents(cx: Cx, (input, list, count): (Input, Span, u16)) -> Result<()> {
    let table = list.sub_exact(2, u64::from(count).saturating_mul(12))?;
    cx.set_count(Count::Exact(count.into()));
    for i in 0..u64::from(count) {
        let rec = cx.read(table.sub(i.saturating_mul(12), 12)).await?;
        let first = u16_be(&rec, 0).unwrap_or(0);
        let last = u16_be(&rec, 2).unwrap_or(0);
        let doc = list.sub(
            u64::from(u32_be(&rec, 4).unwrap_or(0)),
            u64::from(u32_be(&rec, 8).unwrap_or(0)),
        );
        // The glyph range goes in the name: expanding the document replaces
        // its summary with that of the detected format.
        let name = if first == last {
            format!("Glyph {first}")
        } else {
            format!("Glyphs {first}–{last}")
        };
        cx.push(embedded(name, input.nested(doc)).summary(format!("{} bytes", doc.len)))
            .await;
    }
    Ok(())
}
