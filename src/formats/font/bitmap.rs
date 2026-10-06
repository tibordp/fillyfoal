//! X11 bitmap fonts: PCF (compiled, binary) and BDF (text).
//!
//! PCF starts with a table of contents; each table carries its own format
//! word, which also sets the table's byte order. BDF is line-oriented:
//! global keywords, a property block and `STARTCHAR`...`ENDCHAR` glyphs.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::datakit::clip;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

pub static PCF: Format = Format {
    name: "pcf",
    title: "X11 Portable Compiled Font",
    extensions: &["pcf"],
    mime: "application/x-font-pcf",
    probe: Probe::Magic(&[(0, b"\x01fcp")]),
    dissect: crate::expander!(pcf: Input),
};

pub static BDF: Format = Format {
    name: "bdf",
    title: "Glyph Bitmap Distribution Format font",
    extensions: &["bdf"],
    mime: "application/x-font-bdf",
    probe: Probe::Magic(&[(0, b"STARTFONT ")]),
    dissect: crate::expander!(bdf: Input),
};

const TABLE_TYPES: EnumTable = &[
    (1, "PCF_PROPERTIES"),
    (2, "PCF_ACCELERATORS"),
    (4, "PCF_METRICS"),
    (8, "PCF_BITMAPS"),
    (16, "PCF_INK_METRICS"),
    (32, "PCF_BDF_ENCODINGS"),
    (64, "PCF_SWIDTHS"),
    (128, "PCF_GLYPH_NAMES"),
    (256, "PCF_BDF_ACCELERATORS"),
];

const PCF_FORMAT: FlagTable = &[
    field(0x3, 0x1, "GLYPH_PAD_2"),
    field(0x3, 0x2, "GLYPH_PAD_4"),
    field(0x3, 0x3, "GLYPH_PAD_8"),
    flag(0x4, "MSB_BYTE_FIRST"),
    flag(0x8, "MSB_BIT_FIRST"),
    field(0x30, 0x10, "SCAN_UNIT_2"),
    field(0x30, 0x20, "SCAN_UNIT_4"),
    flag(0x100, "ACCEL_W_INKBOUNDS / COMPRESSED_METRICS"),
    flag(0x200, "INKBOUNDS"),
];

/// Bounds on tables and entries read.
const MAX_ENTRIES: u32 = 1 << 20;

fn table_endian(format: u32) -> Endian {
    if format & 4 != 0 {
        Endian::Big
    } else {
        Endian::Little
    }
}

#[derive(Clone, Copy, Debug)]
struct Toc {
    kind: u32,
    format: u32,
    span: Span,
}

async fn toc(cx: &Cx, file: Span) -> Result<Vec<Toc>> {
    let head = cx.read(file.sub_exact(0, 8)?).await?;
    let count = u32_le(&head, 4).unwrap_or(0).min(MAX_ENTRIES);
    let data = cx
        .read(file.sub_exact(8, u64::from(count).saturating_mul(16))?)
        .await?;
    Ok(data
        .as_chunks::<16>()
        .0
        .iter()
        .map(|e| Toc {
            kind: u32_le(e, 0).unwrap_or(0),
            format: u32_le(e, 4).unwrap_or(0),
            span: file.sub(
                u32_le(e, 12).unwrap_or(0).into(),
                u32_le(e, 8).unwrap_or(0).into(),
            ),
        })
        .collect())
}

/// Properties as `(name, value)` pairs, with spans.
async fn properties(cx: &Cx, t: &Toc) -> Result<Vec<(String, Value, Span)>> {
    let endian = table_endian(t.format);
    let data = cx.read(t.span).await?;
    let get = |at: usize| match endian {
        Endian::Little => crate::bytes::u32_le(&data, at),
        Endian::Big => crate::bytes::u32_be(&data, at),
    };
    let n = get(4).unwrap_or(0).min(MAX_ENTRIES);
    let props_end = 8usize.saturating_add(to_usize(n.into()).saturating_mul(9));
    let pad = if n & 3 == 0 {
        0
    } else {
        4usize.saturating_sub(to_usize((n & 3).into()))
    };
    let strings_at = props_end.saturating_add(pad).saturating_add(4);
    let strings = data.get(strings_at..).unwrap_or_default();
    let mut out = Vec::new();
    for i in 0..to_usize(n.into()) {
        let at = 8usize.saturating_add(i.saturating_mul(9));
        let (Some(name), Some(&is_string), Some(value)) = (
            get(at),
            data.get(at.saturating_add(4)),
            get(at.saturating_add(5)),
        ) else {
            break;
        };
        let text_at =
            |o: u32| crate::text::until_nul(strings.get(to_usize(o.into())..).unwrap_or_default());
        let v = if is_string != 0 {
            Value::Text(text_at(value))
        } else {
            Value::Int {
                value: i64::from(value as i32),
                bits: 32,
            }
        };
        out.push((text_at(name), v, t.span.sub(to_u64(at), 9)));
    }
    Ok(out)
}

pub async fn pcf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let tables = toc(&cx, file).await?;
    let header = cx
        .block(file.sub(
            0,
            8u64.saturating_add(to_u64(tables.len()).saturating_mul(16)),
        ))
        .await?;
    {
        let mut f = Fields::emitting(&cx, &header, Endian::Little);
        f.bytes("Signature", 4).emit()?;
        f.u32("Table count").emit()?;
    }
    let mut summary = String::from("X11 PCF font");
    if let Some(t) = tables.iter().find(|t| t.kind == 1)
        && let Ok(props) = properties(&cx, t).await
    {
        for key in ["FONT", "FAMILY_NAME"] {
            if let Some((_, Value::Text(v), _)) = props.iter().find(|(k, _, _)| k == key) {
                summary = format!("{summary} {:?}", clip(v, 100));
                break;
            }
        }
    }
    cx.annotate(format!("{summary}, {} tables", tables.len()));
    for (i, t) in tables.iter().enumerate() {
        let entry = file.sub(8u64.saturating_add(to_u64(i).saturating_mul(16)), 16);
        let name = lookup(TABLE_TYPES, t.kind.into())
            .map_or_else(|| format!("Table type {:#x}", t.kind), str::to_owned);
        cx.push(
            Node::new(name)
                .span(t.span)
                .summary(format!("{} bytes", t.span.len))
                .lazy(pcf_table, (*t, entry)),
        )
        .await;
    }
    Ok(())
}

async fn pcf_table(cx: Cx, (t, entry): (Toc, Span)) -> Result<()> {
    let block = cx.block(entry).await?;
    {
        let mut f = Fields::emitting(&cx, &block, Endian::Little);
        f.u32("Type").enumeration(TABLE_TYPES).emit()?;
        f.u32("Format").flags(PCF_FORMAT).emit()?;
        f.u32("Size").emit()?;
        f.u32("Offset").hex().emit()?;
    }
    let endian = table_endian(t.format);
    let head = cx.block(t.span.sub(0, 48)).await?;
    let mut f = Fields::emitting(&cx, &head, endian);
    // The format word is always stored little-endian.
    f.seek(4);
    match t.kind {
        1 => {
            f.u32("Properties").emit()?;
            let props = properties(&cx, &t).await?;
            cx.emit(
                Node::new("Property list")
                    .span(t.span.tail(8))
                    .summary(format!("{}", props.len()))
                    .lazy(property_list, t),
            );
        }
        2 | 256 => {
            for name in [
                "noOverlap",
                "constantMetrics",
                "terminalFont",
                "constantWidth",
                "inkInside",
                "inkMetrics",
                "drawDirection",
                "padding",
            ] {
                f.u8(name).emit()?;
            }
            f.i32("fontAscent").emit()?;
            f.i32("fontDescent").emit()?;
            f.i32("maxOverlap").emit()?;
        }
        4 | 16 => {
            if t.format & 0x100 != 0 {
                f.u16("Metrics count (compressed)").emit()?;
            } else {
                f.u32("Metrics count").emit()?;
            }
        }
        8 => {
            f.u32("Glyph count").emit()?;
        }
        32 => {
            for name in [
                "min_char_or_byte2",
                "max_char_or_byte2",
                "min_byte1",
                "max_byte1",
                "default_char",
            ] {
                f.u16(name).emit()?;
            }
        }
        64 | 128 => {
            let n = f.u32("Glyph count").emit()?;
            if t.kind == 128 {
                cx.emit(
                    Node::new("Glyph names")
                        .span(t.span.tail(8))
                        .summary(format!("{n}"))
                        .lazy(glyph_names, t),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

async fn property_list(cx: Cx, t: Toc) -> Result<()> {
    for (name, value, span) in properties(&cx, &t).await? {
        cx.push(Node::new(name).span(span).value(value)).await;
    }
    Ok(())
}

async fn glyph_names(cx: Cx, t: Toc) -> Result<()> {
    let endian = table_endian(t.format);
    let data = cx.read(t.span).await?;
    let get = |at: usize| match endian {
        Endian::Little => crate::bytes::u32_le(&data, at),
        Endian::Big => crate::bytes::u32_be(&data, at),
    };
    let n = get(4).unwrap_or(0).min(MAX_ENTRIES);
    let strings_at = 8usize
        .saturating_add(to_usize(n.into()).saturating_mul(4))
        .saturating_add(4);
    let strings = data.get(strings_at..).unwrap_or_default();
    cx.set_count(Count::Exact(n.into()));
    for i in 0..to_usize(n.into()) {
        let Some(offset) = get(8usize.saturating_add(i.saturating_mul(4))) else {
            break;
        };
        let at = to_usize(offset.into());
        let name = crate::text::until_nul(strings.get(at..).unwrap_or_default());
        let len = to_u64(name.len()).saturating_add(1);
        cx.push(
            Node::new(format!("Glyph {i}"))
                .span(t.span.sub(to_u64(strings_at.saturating_add(at)), len))
                .value(Value::Text(name)),
        )
        .await;
    }
    Ok(())
}

/// Lines of a text region: `(start, end without newline, next)`.
async fn next_line(cx: &Cx, region: Span, pos: u64) -> Result<Option<(u64, u64, u64)>> {
    if pos >= region.len {
        return Ok(None);
    }
    let mut at = pos;
    loop {
        let window = cx.read_avail(region.sub(at, 0x400)).await?;
        if let Some(n) = window.iter().position(|&b| b == b'\n') {
            let end = at.saturating_add(to_u64(n));
            return Ok(Some((pos, end, end.saturating_add(1))));
        }
        at = at.saturating_add(to_u64(window.len()));
        if window.is_empty() || at >= region.len {
            return Ok(Some((pos, region.len, region.len)));
        }
        if at.saturating_sub(pos) > 0x10000 {
            return Err(Diagnostic::limit("line longer than 64 KiB").at(region.sub(pos, 1)));
        }
    }
}

async fn line_text(cx: &Cx, region: Span, start: u64, end: u64) -> Result<String> {
    let bytes = cx
        .read(region.sub(start, end.saturating_sub(start).min(0x10000)))
        .await?;
    Ok(String::from_utf8_lossy(&bytes)
        .trim_end_matches('\r')
        .to_owned())
}

pub async fn bdf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut font = String::new();
    while let Some((start, end, next)) = next_line(&cx, file, pos).await? {
        let line = line_text(&cx, file, start, end).await?;
        let (key, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        let span = file.sub(start, end.saturating_sub(start));
        match key {
            "STARTPROPERTIES" => {
                // Find the end of the property block.
                let mut p = next;
                let mut block_end = next;
                while let Some((s, e, n)) = next_line(&cx, file, p).await? {
                    cx.checkpoint().await;
                    let l = line_text(&cx, file, s, e).await?;
                    block_end = n;
                    p = n;
                    if l.starts_with("ENDPROPERTIES") {
                        break;
                    }
                }
                let block = file.sub(start, block_end.saturating_sub(start));
                cx.emit(
                    Node::new("Properties")
                        .span(block)
                        .summary(rest.to_owned())
                        .lazy(bdf_properties, block),
                );
                pos = block_end;
                continue;
            }
            "CHARS" => {
                let glyphs = file.tail(start);
                cx.emit(
                    Node::new("Glyphs")
                        .span(glyphs)
                        .summary(rest.to_owned())
                        .lazy(bdf_glyphs, glyphs),
                );
                break;
            }
            "FONT" => font = rest.to_owned(),
            "COMMENT" => {}
            _ => {}
        }
        cx.emit(
            Node::new(key.to_owned())
                .span(span)
                .value(Value::Text(rest.to_owned())),
        );
        pos = next;
        cx.checkpoint().await;
    }
    cx.annotate(format!("BDF font {:?}", clip(&font, 100)));
    Ok(())
}

async fn bdf_properties(cx: Cx, block: Span) -> Result<()> {
    let mut pos = 0u64;
    let mut first = true;
    while let Some((start, end, next)) = next_line(&cx, block, pos).await? {
        pos = next;
        if first {
            first = false;
            continue;
        }
        let line = line_text(&cx, block, start, end).await?;
        if line.starts_with("ENDPROPERTIES") {
            break;
        }
        let (key, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        let value = rest.trim();
        let value = match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            Some(text) => Value::Text(text.replace("\"\"", "\"")),
            None => match value.parse::<i64>() {
                Ok(n) => Value::Int { value: n, bits: 64 },
                Err(_) => Value::Text(value.to_owned()),
            },
        };
        cx.push(
            Node::new(key.to_owned())
                .span(block.sub(start, end.saturating_sub(start)))
                .value(value),
        )
        .await;
    }
    Ok(())
}

async fn bdf_glyphs(cx: Cx, region: Span) -> Result<()> {
    let mut pos = 0u64;
    let mut current: Option<(u64, String, String, String)> = None;
    while let Some((start, end, next)) = next_line(&cx, region, pos).await? {
        pos = next;
        let line = line_text(&cx, region, start, end).await?;
        let (key, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        match key {
            "STARTCHAR" => current = Some((start, rest.to_owned(), String::new(), String::new())),
            "ENCODING" => {
                if let Some(c) = current.as_mut() {
                    c.2 = rest.to_owned();
                }
            }
            "BBX" => {
                if let Some(c) = current.as_mut() {
                    c.3 = rest.to_owned();
                }
            }
            "ENDCHAR" => {
                if let Some((s, name, enc, bbx)) = current.take() {
                    let span = region.sub(s, next.saturating_sub(s));
                    let code = enc
                        .split_whitespace()
                        .next()
                        .and_then(|c| c.parse::<u32>().ok());
                    let mut summary = format!("encoding {enc}");
                    if let Some(ch) = code.and_then(char::from_u32).filter(|c| !c.is_control()) {
                        summary = format!("{summary} ({ch:?})");
                    }
                    cx.push(
                        Node::new(name)
                            .span(span)
                            .summary(format!("{summary}, BBX {bbx}"))
                            .lazy(bdf_glyph, span),
                    )
                    .await;
                }
            }
            "ENDFONT" => break,
            _ => cx.checkpoint().await,
        }
    }
    Ok(())
}

async fn bdf_glyph(cx: Cx, span: Span) -> Result<()> {
    let mut pos = 0u64;
    let mut bitmap: Option<u64> = None;
    while let Some((start, end, next)) = next_line(&cx, span, pos).await? {
        pos = next;
        let line = line_text(&cx, span, start, end).await?;
        let (key, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        if key == "BITMAP" {
            bitmap = Some(next);
            continue;
        }
        if key == "ENDCHAR" {
            if let Some(b) = bitmap {
                cx.emit(Node::new("BITMAP").span(span.sub(b, start.saturating_sub(b))));
            }
            break;
        }
        if bitmap.is_none() {
            cx.emit(
                Node::new(key.to_owned())
                    .span(span.sub(start, end.saturating_sub(start)))
                    .value(Value::Text(rest.to_owned())),
            );
        }
    }
    Ok(())
}
