//! GNU gettext message catalogs (`.mo`).
//!
//! A header gives the number of strings and the offsets of two parallel
//! tables of `(length, offset)` descriptors, for the original strings and
//! their translations, plus an optional hash table. The entry with an empty
//! original holds the catalog's metadata (`Language:`, `Plural-Forms:`, ...).

use crate::bytes::{u32_be, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::util::datakit::clip;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::Value;

pub static FORMAT: Format = Format {
    name: "mo",
    title: "GNU gettext message catalog",
    extensions: &["mo", "gmo"],
    mime: "application/x-gettext-translation",
    probe: Probe::Magic(&[(0, b"\xde\x12\x04\x95"), (0, b"\x95\x04\x12\xde")]),
    dissect: crate::expander!(dissect: Input),
};

/// Longest string decoded into a value.
const MAX_TEXT: u64 = 0x4000;

record! {
    pub struct Header {
        magic: u32 "Magic" .hex(),
        revision: u32 "Revision" .hex() .with(|&r, n| n.summary(format!("{}.{}", r >> 16, r & 0xffff))),
        count: u32 "Number of strings",
        originals: u32 "Original strings table offset" .hex(),
        translations: u32 "Translated strings table offset" .hex(),
        hash_size: u32 "Hash table size",
        hash_offset: u32 "Hash table offset" .hex(),
    }
}

#[derive(Clone, Copy)]
struct Catalog {
    file: Span,
    endian: Endian,
    count: u32,
    originals: u32,
    translations: u32,
}

impl Catalog {
    /// The string described by entry `i` of the table at `table`.
    async fn string(&self, cx: &Cx, table: u32, i: u64) -> Result<(Span, Span)> {
        let entry = self
            .file
            .sub_exact(u64::from(table).saturating_add(i.saturating_mul(8)), 8)?;
        let d = cx.read(entry).await?;
        let (len, offset) = match self.endian {
            Endian::Little => (u32_le(&d, 0), u32_le(&d, 4)),
            Endian::Big => (u32_be(&d, 0), u32_be(&d, 4)),
        };
        let text = self
            .file
            .sub(offset.unwrap_or(0).into(), len.unwrap_or(0).into());
        Ok((entry, text))
    }
}

async fn text(cx: &Cx, span: Span) -> Result<String> {
    let bytes = cx.read_avail(span.sub(0, MAX_TEXT)).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let endian = if magic == b"\xde\x12\x04\x95" {
        Endian::Little
    } else {
        Endian::Big
    };
    let hspan = file.sub(0, Header::SIZE);
    let h = parse(&cx, hspan, endian, &(), Header::layout).await?;
    cx.emit(Header::node("Header", hspan, endian));
    let cat = Catalog {
        file,
        endian,
        count: h.count,
        originals: h.originals,
        translations: h.translations,
    };
    // Validate the tables before listing them.
    let table_len = u64::from(h.count).saturating_mul(8);
    let originals = file.sub_exact(h.originals.into(), table_len)?;
    let translations = file.sub_exact(h.translations.into(), table_len)?;

    let mut summary = format!("gettext catalog, {} messages", h.count);
    if h.count > 0
        && let Ok((_, first)) = cat.string(&cx, h.originals, 0).await
        && first.is_empty()
        && let Ok((_, meta)) = cat.string(&cx, h.translations, 0).await
    {
        let meta = text(&cx, meta).await?;
        for key in ["Project-Id-Version: ", "Language: "] {
            if let Some(line) = meta.lines().find_map(|l| l.strip_prefix(key)) {
                summary = format!("{summary}, {}", clip(line, 60));
            }
        }
    }
    cx.annotate(summary);
    cx.emit(Node::new("Original strings table").span(originals));
    cx.emit(Node::new("Translated strings table").span(translations));
    if h.hash_size > 0 {
        cx.emit(
            Node::new("Hash table")
                .span(file.sub(
                    h.hash_offset.into(),
                    u64::from(h.hash_size).saturating_mul(4),
                ))
                .summary(format!("{} slots", h.hash_size)),
        );
    }
    cx.emit(
        Node::new("Messages")
            .summary(format!("{}", h.count))
            .lazy(messages, cat),
    );
    Ok(())
}

async fn messages(cx: Cx, cat: Catalog) -> Result<()> {
    cx.set_count(Count::Exact(cat.count.into()));
    for i in 0..u64::from(cat.count) {
        let (oentry, ospan) = cat.string(&cx, cat.originals, i).await?;
        let (tentry, tspan) = cat.string(&cx, cat.translations, i).await?;
        let original = text(&cx, ospan).await?;
        let translation = text(&cx, tspan).await?;
        // msgctxt is separated by EOT, plural forms by NUL.
        let (context, msgid) = match original.split_once('\u{4}') {
            Some((c, m)) => (Some(c.to_owned()), m.to_owned()),
            None => (None, original.clone()),
        };
        let singular = msgid.split('\0').next().unwrap_or_default().to_owned();
        let name = if singular.is_empty() {
            "(header)".to_owned()
        } else {
            clip(&singular, 80)
        };
        let forms = translation.split('\0').count();
        let mut node = Node::new(name).span(tspan).value(Value::Text(
            translation
                .split('\0')
                .next()
                .unwrap_or_default()
                .to_owned(),
        ));
        if forms > 1 {
            node = node.summary(format!("{forms} plural forms"));
        }
        if let Some(c) = &context {
            node = node.desc(format!("context: {c}"));
        }
        if ospan.len > MAX_TEXT || tspan.len > MAX_TEXT {
            node = node.diag(Diagnostic::note("long string truncated for display"));
        }
        cx.push(node.lazy(message, (oentry, ospan, tentry, tspan)))
            .await;
    }
    Ok(())
}

async fn message(cx: Cx, (oentry, ospan, tentry, tspan): (Span, Span, Span, Span)) -> Result<()> {
    cx.emit(Node::new("Original descriptor").span(oentry));
    let original = text(&cx, ospan).await?;
    for (i, part) in original.split('\0').enumerate() {
        match (i, part.split_once('\u{4}')) {
            (0, Some((context, msgid))) => {
                cx.emit(Node::new("msgctxt").value(Value::Text(context.to_owned())));
                cx.emit(Node::new("msgid").value(Value::Text(msgid.to_owned())));
            }
            (0, None) => cx.emit(Node::new("msgid").value(Value::Text(part.to_owned()))),
            _ => cx.emit(Node::new("msgid_plural").value(Value::Text(part.to_owned()))),
        }
    }
    cx.emit(
        Node::new("Original")
            .span(ospan)
            .summary(format!("{} bytes", ospan.len)),
    );
    cx.emit(Node::new("Translation descriptor").span(tentry));
    let translation = text(&cx, tspan).await?;
    for (i, part) in translation.split('\0').enumerate() {
        cx.emit(Node::new(format!("msgstr[{i}]")).value(Value::Text(part.to_owned())));
    }
    cx.emit(
        Node::new("Translation")
            .span(tspan)
            .summary(format!("{} bytes", tspan.len)),
    );
    Ok(())
}
