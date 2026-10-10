//! Adobe Photoshop presets: brushes (ABR), patterns (PAT), gradients (GRD),
//! layer styles (ASL), actions (ATN), curves (ACV), colour books (ACB),
//! colour tables (ACT) and custom shapes (CSH).
//!
//! Many of them store an *action descriptor*, read by
//! [`crate::formats::image::psd::descriptor`], which PSD shares.

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::fourcc;
use crate::formats::util::val::{text, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

use crate::formats::image::psd::descriptor::{
    MAX_READ, Rd, descriptor, descriptor_items, key, pattern_node, patterns, skip_value, ustr,
    versioned_descriptor,
};

const BE: Endian = Endian::Big;

declare_format!(pub PAT = "photoshop-pattern", "Adobe Photoshop patterns", ["pat"], "application/x-photoshop-pattern",
    Probe::Custom(|h| h.starts_with(b"8BPT") && u16_be(h.data, 4).is_some_and(|v| v == 1)), pat);

async fn pat(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 10)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    f.u16("Version").emit()?;
    let count = f.u32("Patterns").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(10);
    let mut n = 0u32;
    while n < count && !cur.at_end() {
        let node = pattern_node(&cx, &mut cur, n).await?;
        cx.push(node).await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!("Photoshop patterns, {count} patterns"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Brushes (.abr)

fn abr_probe(h: &Head<'_>) -> bool {
    match u16_be(h.data, 0) {
        Some(6 | 7 | 10) => matches!(u16_be(h.data, 2), Some(1 | 2)) && h.at(4, b"8BIM"),
        Some(1 | 2) => {
            u16_be(h.data, 2).is_some_and(|n| n > 0 && n < 1000)
                && matches!(u16_be(h.data, 4), Some(1 | 2))
                && u32_be(h.data, 6)
                    .is_some_and(|s| s >= 14 && u64::from(s).saturating_add(10) <= h.len)
        }
        _ => false,
    }
}

declare_format!(pub ABR = "photoshop-brushes", "Adobe Photoshop brushes", ["abr"], "application/x-photoshop-brushes",
    Probe::Custom(abr_probe), abr);

const BRUSH_TYPES: EnumTable = &[(1, "computed"), (2, "sampled")];

async fn abr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let version = f.u16("Version").emit()?;
    if version <= 2 {
        let count = f.u16("Brushes").emit()?;
        let mut cur = Cursor::new(&cx, file, BE);
        cur.seek(4);
        let mut n = 0u32;
        while n < u32::from(count) && !cur.at_end() {
            let start = cur.pos();
            let kind = cur.u16().await?;
            let len = cur.u32().await?;
            let body = cur.span(len.into());
            if body.len < u64::from(len) {
                return Err(Diagnostic::truncated(
                    Span::new(body.source, body.offset, len.into()),
                    body.len,
                ));
            }
            cur.skip(len.into());
            let name = BRUSH_TYPES
                .iter()
                .find(|(k, _)| *k == u64::from(kind))
                .map_or("unknown", |(_, v)| v);
            cx.push(
                Node::new(format!("Brush {n}"))
                    .span(cur.since(start))
                    .summary(format!("{name}, {len} bytes")),
            )
            .await;
            n = n.saturating_add(1);
        }
        cx.annotate(format!("Photoshop brushes v{version}, {count} brushes"));
        return Ok(());
    }
    f.u16("Subversion").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(4);
    let mut kinds = Vec::new();
    while let Some(chunk) = cur.chunk(ChunkLayout::new(8, 4, BE)).await? {
        let key = chunk.id.get(4..).map(fourcc).unwrap_or_default();
        if !chunk.id.starts_with(b"8BIM") {
            cx.emit(
                Node::new("Unknown section")
                    .span(chunk.span)
                    .diag(Diagnostic::malformed("section signature is not 8BIM")),
            );
            break;
        }
        let node = Node::new(key.clone())
            .span(chunk.span)
            .summary(format!("{} bytes", chunk.body.len));
        let node = match key.as_str() {
            "samp" => node
                .desc("Sampled brush tips")
                .lazy(abr_samples, chunk.body),
            "patt" => node
                .desc("Patterns used by brushes")
                .lazy(patterns, chunk.body),
            "desc" => node
                .desc("Brush presets (descriptor)")
                .lazy(abr_desc, chunk.body),
            "phry" => node
                .desc("Brush hierarchy (descriptor)")
                .lazy(abr_desc, chunk.body),
            _ => node,
        };
        kinds.push(key);
        cx.push(node).await;
    }
    cx.annotate(format!(
        "Photoshop brushes v{version} ({})",
        kinds.join(", ")
    ));
    Ok(())
}

/// Sampled brushes: u32 length, data, padded to four bytes.
async fn abr_samples(cx: Cx, body: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, body, BE);
    let mut n = 0u32;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let len = cur.u32().await?;
        let data = cur.span(len.into());
        if data.len < u64::from(len) {
            return Err(Diagnostic::truncated(
                Span::new(data.source, data.offset, len.into()),
                data.len,
            ));
        }
        cur.skip(crate::bytes::align_up(len.into(), 4));
        let id = cx.read_avail(data.sub(0, 37)).await?;
        let mut node = Node::new(format!("Brush {n}"))
            .span(cur.since(start))
            .summary(format!("{len} bytes"));
        if id.first() == Some(&36) {
            node = node.value(text(String::from_utf8_lossy(
                id.get(1..).unwrap_or_default(),
            )));
        }
        cx.push(node).await;
        n = n.saturating_add(1);
    }
    Ok(())
}

async fn abr_desc(cx: Cx, body: Span) -> Result<()> {
    if body.len > MAX_READ {
        return Err(Diagnostic::limit("descriptor larger than 16 MiB").at(body));
    }
    let data = cx.read(body).await?;
    let (node, _) = versioned_descriptor(&cx, "Descriptor", body, &data, 0).await;
    cx.emit(node);
    Ok(())
}

// ---------------------------------------------------------------------------
// Gradients (.grd)

declare_format!(pub GRD = "photoshop-gradients", "Adobe Photoshop gradients", ["grd"], "application/x-photoshop-gradients",
    Probe::Custom(|h| h.starts_with(b"8BGR") && matches!(u16_be(h.data, 4), Some(1..=5))), grd);

async fn grd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 6)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u16("Version").emit()?;
    if version != 5 {
        let count = u16_be(&cx.read(file.sub(6, 2)).await?, 0).unwrap_or(0);
        cx.emit(
            Node::new("Gradients")
                .span(file.sub(6, 2))
                .value(uint(count, 16)),
        );
        cx.emit(
            Node::new("Gradient data")
                .span(file.tail(8))
                .diag(Diagnostic::unsupported("pre-CS gradient records")),
        );
        cx.annotate(format!("Photoshop gradients v{version}, {count} gradients"));
        return Ok(());
    }
    let rest = file.tail(6);
    if rest.len > MAX_READ {
        return Err(Diagnostic::limit("gradient file larger than 16 MiB").at(rest));
    }
    let data = cx.read(rest).await?;
    let (node, end) = versioned_descriptor(&cx, "Gradients", rest, &data, 0).await;
    cx.emit(node);
    if let Some(end) = end.filter(|&e| e < data.len()) {
        cx.emit(Node::new("Trailing data").span(rest.tail(to_u64(end))));
    }
    // GrdL list count, for the summary: name, class, items, key, type, count.
    let mut r = Rd::at(&data, 4, BE);
    let count = (|| {
        r.unicode()?;
        key(&mut r)?;
        r.u32()?;
        let k = key(&mut r)?;
        (k == "GrdL" && r.fourcc()? == *b"VlLs").then_some(())?;
        r.u32()
    })();
    cx.annotate(match count {
        Some(n) => format!("Photoshop gradients, {n} gradients"),
        None => "Photoshop gradients".to_owned(),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Layer styles (.asl)

declare_format!(pub ASL = "photoshop-styles", "Adobe Photoshop layer styles", ["asl"], "application/x-photoshop-styles",
    Probe::Custom(|h| h.starts_with(b"\x00\x02") && h.at(2, b"8BSL")), asl);

async fn asl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u16("Version").emit()?;
    f.ascii("Signature", 4).emit()?;
    f.u16("Patterns version").emit()?;
    let plen = f.u32("Patterns length").emit()?;
    let pattern_span = file.sub_exact(12, plen.into())?;
    cx.emit(
        Node::new("Patterns")
            .span(pattern_span)
            .summary(format!("{plen} bytes"))
            .lazy(patterns, pattern_span),
    );
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(12u64.saturating_add(plen.into()));
    let at = cur.pos();
    let count = cur.u32().await?;
    cx.emit(
        Node::new("Styles")
            .span(cur.since(at))
            .value(uint(count, 32)),
    );
    let mut n = 0u32;
    while n < count && !cur.at_end() {
        let start = cur.pos();
        let len = cur.u32().await?;
        let body = cur.span(len.into());
        if body.len < u64::from(len) {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, len.into()),
                body.len,
            ));
        }
        cur.skip(crate::bytes::align_up(len.into(), 4));
        let name = if len <= 0x1000 {
            style_name(&cx, body).await?
        } else {
            None
        };
        cx.push(
            Node::new(name.unwrap_or_else(|| format!("Style {n}")))
                .span(cur.since(start))
                .summary(format!("{len} bytes"))
                .lazy(asl_style, body),
        )
        .await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!("Photoshop layer styles, {count} styles"));
    Ok(())
}

/// The `Nm  ` item of a style's first descriptor.
async fn style_name(cx: &Cx, body: Span) -> Result<Option<String>> {
    let data = cx.read(body).await?;
    let mut r = Rd::at(&data, 4, BE);
    Ok(async {
        r.unicode()?;
        key(&mut r)?;
        let n = r.u32()?;
        for _ in 0..n.min(64) {
            let k = key(&mut r)?;
            let t = r.fourcc()?;
            if k == "Nm" && t == *b"TEXT" {
                return r.unicode();
            }
            skip_value(cx, &mut r, &t, 0).await?;
        }
        None
    }
    .await)
}

async fn asl_style(cx: Cx, body: Span) -> Result<()> {
    if body.len > MAX_READ {
        return Err(Diagnostic::limit("style larger than 16 MiB").at(body));
    }
    let data = cx.read(body).await?;
    let (node, end) = versioned_descriptor(&cx, "Identity", body, &data, 0).await;
    cx.emit(node);
    if let Some(end) = end {
        let (node, _) = versioned_descriptor(&cx, "Effects", body, &data, end).await;
        cx.emit(node);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Actions (.atn)

fn atn_probe(h: &Head<'_>) -> bool {
    // Version 16, then the set name: a short UTF-16BE string ending in NUL.
    let Some(units) = u32_be(h.data, 4).and_then(|n| usize::try_from(n).ok()) else {
        return false;
    };
    h.starts_with(b"\x00\x00\x00\x10")
        && (1..=256).contains(&units)
        && h.data
            .get(8..8usize.saturating_add(units.saturating_mul(2)))
            .is_some_and(|s| {
                s.ends_with(b"\x00\x00")
                    && s.as_chunks::<2>()
                        .0
                        .iter()
                        .take(units.saturating_sub(1))
                        .all(|c| c != &[0, 0])
            })
}

declare_format!(pub ATN = "photoshop-actions", "Adobe Photoshop actions", ["atn"], "application/x-photoshop-actions",
    Probe::Custom(atn_probe), atn);

/// Skips one action event; returns its event name and the byte range of
/// its descriptor, if any.
async fn atn_event(cx: &Cx, r: &mut Rd<'_>) -> Option<(String, Option<(usize, usize)>)> {
    r.skip(4)?; // expanded, enabled, with dialog, dialog options
    let id_type = r.fourcc()?;
    let name = match &id_type {
        b"TEXT" => {
            let n = usize::try_from(r.u32()?).ok()?;
            crate::text::latin1(r.take(n)?)
        }
        b"long" => fourcc(&r.fourcc()?),
        _ => return None,
    };
    let n = usize::try_from(r.u32()?).ok()?;
    r.skip(n)?;
    if r.i32()? != -1 {
        return Some((name, None));
    }
    let start = r.pos;
    descriptor(cx, r, 0).await?;
    Some((name, Some((start, r.pos))))
}

/// Skips one action; returns its name and event count.
async fn atn_action(cx: &Cx, r: &mut Rd<'_>) -> Option<(String, u32)> {
    r.skip(6)?; // function key, shift, command, colour
    let name = r.unicode()?;
    r.skip(1)?;
    let n = r.u32()?;
    for i in 0..n {
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
        atn_event(cx, r).await?;
    }
    Some((name, n))
}

async fn atn(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if file.len > MAX_READ {
        return Err(Diagnostic::limit("action set larger than 16 MiB").at(file));
    }
    let data = cx.read(file).await?;
    let mut r = Rd::new(&data, BE);
    let sub = |a: usize, b: usize| file.sub(to_u64(a), to_u64(b.saturating_sub(a)));
    let short = || Diagnostic::truncated(file.tail(file.len), 0);
    r.u32().ok_or_else(short)?;
    cx.emit(Node::new("Version").span(sub(0, 4)).value(uint(16u32, 32)));
    let set = r.unicode().ok_or_else(short)?;
    cx.emit(
        Node::new("Set name")
            .span(sub(4, r.pos))
            .value(text(set.clone())),
    );
    let at = r.pos;
    let expanded = r.u8().ok_or_else(short)?;
    cx.emit(
        Node::new("Expanded")
            .span(sub(at, r.pos))
            .value(Value::Bool(expanded != 0)),
    );
    let at = r.pos;
    let count = r.u32().ok_or_else(short)?;
    cx.emit(
        Node::new("Actions")
            .span(sub(at, r.pos))
            .value(uint(count, 32)),
    );
    for i in 0..count {
        let at = r.pos;
        let Some((name, events)) = atn_action(&cx, &mut r).await else {
            cx.emit(
                Node::new(format!("Action {i}"))
                    .span(sub(at, data.len()))
                    .diag(Diagnostic::malformed("action is cut off or not understood")),
            );
            break;
        };
        let span = sub(at, r.pos);
        cx.push(
            Node::new(name)
                .span(span)
                .summary(format!("{events} steps"))
                .lazy(atn_steps, span),
        )
        .await;
    }
    cx.annotate(format!("Photoshop actions {set:?}, {count} actions"));
    Ok(())
}

async fn atn_steps(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let sub = |a: usize, b: usize| span.sub(to_u64(a), to_u64(b.saturating_sub(a)));
    let mut r = Rd::new(&data, BE);
    let err = || Diagnostic::malformed("action is cut off").at(span);
    let key_index = r.u16().ok_or_else(err)?;
    let shift = r.u8().ok_or_else(err)?;
    let command = r.u8().ok_or_else(err)?;
    let colour = r.u16().ok_or_else(err)?;
    cx.emit(
        Node::new("Function key")
            .span(sub(0, 2))
            .value(uint(key_index, 16)),
    );
    cx.emit(
        Node::new("Shift")
            .span(sub(2, 3))
            .value(Value::Bool(shift != 0)),
    );
    cx.emit(
        Node::new("Command")
            .span(sub(3, 4))
            .value(Value::Bool(command != 0)),
    );
    cx.emit(
        Node::new("Colour index")
            .span(sub(4, 6))
            .value(uint(colour, 16)),
    );
    let name = r.unicode().ok_or_else(err)?;
    cx.emit(Node::new("Name").span(sub(6, r.pos)).value(text(name)));
    r.skip(1).ok_or_else(err)?;
    let count = r.u32().ok_or_else(err)?;
    for i in 0..count {
        let at = r.pos;
        let Some((event, desc)) = atn_event(&cx, &mut r).await else {
            cx.emit(
                Node::new(format!("Step {i}"))
                    .span(sub(at, data.len()))
                    .diag(err()),
            );
            break;
        };
        let node = Node::new(format!("Step {i}"))
            .span(sub(at, r.pos))
            .value(text(event));
        let node = match desc {
            Some((a, b)) => node
                .summary("with descriptor")
                .lazy(descriptor_items, sub(a, b)),
            None => node,
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Curves (.acv)

/// Walks the curves; returns the end offset when all are well formed.
fn acv_measure(data: &[u8]) -> Option<usize> {
    let mut r = Rd::new(data, BE);
    let version = r.u16()?;
    let count = r.u16()?;
    if !matches!(version, 1 | 4) || !(1..=32).contains(&count) {
        return None;
    }
    for _ in 0..count {
        let points = r.u16()?;
        if !(2..=19).contains(&points) {
            return None;
        }
        let mut last = None;
        for _ in 0..points {
            let out = r.u16()?;
            let input = r.u16()?;
            if out > 255 || input > 255 || last.is_some_and(|l| input <= l) {
                return None;
            }
            last = Some(input);
        }
    }
    Some(r.pos)
}

fn acv_probe(h: &Head<'_>) -> bool {
    acv_measure(h.data).is_some_and(|end| {
        let end = to_u64(end);
        if h.data.starts_with(b"\x00\x01") {
            end == h.len
        } else {
            end <= h.len
        }
    })
}

declare_format!(pub ACV = "photoshop-curves", "Adobe Photoshop curves preset", ["acv"], "application/x-photoshop-curves",
    Probe::Custom(acv_probe), acv);

const CURVE_NAMES: &[&str] = &[
    "Composite",
    "Channel 1",
    "Channel 2",
    "Channel 3",
    "Channel 4",
];

async fn acv(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let version = cur.u16().await?;
    cx.emit(
        Node::new("Version")
            .span(file.sub(0, 2))
            .value(uint(version, 16)),
    );
    let count = cur.u16().await?;
    cx.emit(
        Node::new("Curves")
            .span(file.sub(2, 2))
            .value(uint(count, 16)),
    );
    for i in 0..count {
        let start = cur.pos();
        let points = cur.u16().await?;
        let mut pts = Vec::new();
        for _ in 0..points.min(64) {
            let out = cur.u16().await?;
            let input = cur.u16().await?;
            pts.push(format!("{input}→{out}"));
        }
        let name = CURVE_NAMES
            .get(usize::from(i))
            .map_or_else(|| format!("Curve {i}"), |s| (*s).to_owned());
        cx.push(
            Node::new(name)
                .span(cur.since(start))
                .value(text(pts.join(", ")))
                .summary(format!("{points} points")),
        )
        .await;
    }
    if !cur.at_end() {
        cx.emit(
            Node::new("Extra data")
                .span(file.tail(cur.pos()))
                .desc("Version 4 per-channel curve records"),
        );
    }
    cx.annotate(format!("Photoshop curves v{version}, {count} curves"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Colour books (.acb)

declare_format!(pub ACB = "photoshop-colorbook", "Adobe Photoshop colour book", ["acb"], "application/x-photoshop-colorbook",
    Probe::Custom(|h| h.starts_with(b"8BCB") && u16_be(h.data, 4) == Some(1)), acb);

/// The default text of a ZString (`$$$/key/path=Default text`).
fn localized(s: &str) -> &str {
    match s.strip_prefix("$$$/") {
        Some(rest) => rest.split_once('=').map_or(rest, |(_, text)| text),
        None => s,
    }
}

const COLOR_SPACES: EnumTable = &[(0, "RGB"), (2, "CMYK"), (7, "Lab")];

async fn acb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(4);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    let version = cur.u16().await?;
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 2))
            .value(uint(version, 16)),
    );
    let id = cur.u16().await?;
    cx.emit(
        Node::new("Book ID")
            .span(file.sub(6, 2))
            .value(uint(id, 16)),
    );
    let mut title = String::new();
    for name in ["Title", "Prefix", "Postfix", "Description"] {
        let at = cur.pos();
        let s = ustr(&mut cur).await?;
        if name == "Title" {
            title = localized(&s).to_owned();
        }
        cx.emit(Node::new(name).span(cur.since(at)).value(text(s)));
    }
    let at = cur.pos();
    let count = cur.u16().await?;
    cx.emit(
        Node::new("Colours")
            .span(cur.since(at))
            .value(uint(count, 16)),
    );
    let at = cur.pos();
    let page = cur.u16().await?;
    cx.emit(
        Node::new("Page size")
            .span(cur.since(at))
            .value(uint(page, 16)),
    );
    let at = cur.pos();
    let selector = cur.u16().await?;
    cx.emit(
        Node::new("Page selector offset")
            .span(cur.since(at))
            .value(uint(selector, 16)),
    );
    let at = cur.pos();
    let space = cur.u16().await?;
    let space_name = COLOR_SPACES
        .iter()
        .find(|(k, _)| *k == u64::from(space))
        .map(|(_, v)| *v);
    cx.emit(
        Node::new("Colour space")
            .span(cur.since(at))
            .value(Value::Enum {
                raw: space.into(),
                bits: 16,
                name: space_name,
            }),
    );
    let comps: u64 = if space == 2 { 4 } else { 3 };
    let start = cur.pos();
    let colours = Node::new("Colour records")
        .span(file.tail(start))
        .summary(format!("{count} colours"));
    cx.emit(colours.lazy(acb_colours, (file.tail(start), count, space)));
    // Skip the records to find the spot/process marker at the end.
    for _ in 0..count {
        ustr(&mut cur).await?;
        cur.skip(6u64.saturating_add(comps));
        if cur.pos() > file.len {
            return Err(Diagnostic::truncated(
                file.tail(start),
                file.len.saturating_sub(start),
            ));
        }
        cx.checkpoint().await;
    }
    if cur.remaining() >= 8 {
        let at = cur.pos();
        let kind = cur.bytes(8).await?;
        cx.emit(
            Node::new("Kind")
                .span(cur.since(at))
                .value(text(String::from_utf8_lossy(&kind))),
        );
    }
    cx.annotate(format!(
        "Photoshop colour book {title:?}, {count} {} colours",
        space_name.unwrap_or("unknown")
    ));
    Ok(())
}

async fn acb_colours(cx: Cx, (region, count, space): (Span, u16, u16)) -> Result<()> {
    let mut cur = Cursor::new(&cx, region, BE);
    let comps: u64 = if space == 2 { 4 } else { 3 };
    for _ in 0..count {
        let start = cur.pos();
        let name = ustr(&mut cur).await?;
        let code = cur.bytes(6).await?;
        let c = cur.bytes(comps).await?;
        let value = match (space, c.as_slice()) {
            (0, [r, g, b]) => format!("#{r:02x}{g:02x}{b:02x}"),
            (2, [c0, m, y, k]) => {
                // Stored inverted: 0 is full ink.
                let pct = |v: &u8| {
                    (255u32.saturating_sub(u32::from(*v)))
                        .saturating_mul(100)
                        .checked_div(255)
                        .unwrap_or(0)
                };
                format!("C{} M{} Y{} K{}", pct(c0), pct(m), pct(y), pct(k))
            }
            (7, [l, a, b]) => {
                let l = u32::from(*l)
                    .saturating_mul(100)
                    .checked_div(255)
                    .unwrap_or(0);
                format!(
                    "L{l} a{} b{}",
                    i16::from(*a).saturating_sub(128),
                    i16::from(*b).saturating_sub(128)
                )
            }
            _ => format!("{c:02x?}"),
        };
        let code = String::from_utf8_lossy(&code).trim().to_owned();
        let name = localized(&name);
        let label = match (name.is_empty(), code.is_empty()) {
            (false, _) => name.to_owned(),
            (true, false) => code.clone(),
            (true, true) => "(unnamed)".to_owned(),
        };
        cx.push(
            Node::new(label)
                .span(cur.since(start))
                .value(text(value))
                .summary(code),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Colour tables (.act): weak, identified by size only

fn act_probe(h: &Head<'_>) -> bool {
    h.len == 772
        && u16_be(h.data, 768).is_some_and(|n| (1..=256).contains(&n))
        && u16_be(h.data, 770).is_some_and(|t| t <= 255 || t == 0xffff)
        && !crate::text::looks_like_text(h.data)
}

declare_format!(pub ACT = "photoshop-color-table", "Adobe Photoshop colour table", ["act"], "application/x-photoshop-color-table",
    Probe::Custom(act_probe), act);

async fn act(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let tail = cx.read(file.sub_exact(768, 4)?).await?;
    let count = u16_be(&tail, 0).unwrap_or(256).min(256);
    let transparent = u16_be(&tail, 2).unwrap_or(0xffff);
    let table = file.sub(0, u64::from(count).saturating_mul(3));
    cx.emit(
        Node::new("Colours")
            .span(table)
            .summary(format!("{count} entries"))
            .lazy(act_colours, table),
    );
    cx.emit(
        Node::new("Unused entries").span(file.sub(table.len, 768u64.saturating_sub(table.len))),
    );
    cx.emit(
        Node::new("Colour count")
            .span(file.sub(768, 2))
            .value(uint(count, 16)),
    );
    cx.emit(Node::new("Transparent index").span(file.sub(770, 2)).value(
        if transparent == 0xffff {
            text("none")
        } else {
            uint(transparent, 16)
        },
    ));
    cx.annotate(format!("Photoshop colour table, {count} colours"));
    Ok(())
}

async fn act_colours(cx: Cx, table: Span) -> Result<()> {
    let data = cx.read(table).await?;
    for (i, c) in data.as_chunks::<3>().0.iter().enumerate() {
        let [r, g, b] = *c;
        cx.push(
            Node::new(format!("[{i}]"))
                .span(table.sub(to_u64(i).saturating_mul(3), 3))
                .value(text(format!("#{r:02x}{g:02x}{b:02x}"))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Custom shapes (.csh)

declare_format!(pub CSH = "photoshop-shapes", "Adobe Photoshop custom shapes", ["csh"], "application/x-photoshop-shapes",
    Probe::Custom(|h| h.starts_with(b"cush") && u32_be(h.data, 4).is_some_and(|v| (1..=4).contains(&v))), csh);

async fn csh(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").emit()?;
    let count = f.u32("Shapes").emit()?;
    cx.emit(
        Node::new("Shape records")
            .span(file.tail(12))
            .diag(Diagnostic::unsupported("custom shape records")),
    );
    cx.annotate(format!(
        "Photoshop custom shapes v{version}, {count} shapes"
    ));
    Ok(())
}
