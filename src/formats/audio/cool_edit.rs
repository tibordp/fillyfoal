//! Cool Edit Pro / Adobe Audition multitrack sessions (`.ses`).
//!
//! A session is `COOLNESS`, a u32 little-endian size of the rest, then
//! chunks of a 4-byte ASCII tag and a u32 little-endian body size, packed.
//!
//! **Reverse-engineered from a single Audition 3.0 session**, which had
//! seven tracks and no clips, so most of this is inferred and labelled so:
//!
//! - `hdr `: the session sample rate (u32; 48000 in the sample, matching the
//!   session's setting), then a value that equals 30 s of samples (taken as
//!   the session length) and 32 (taken as the bit depth); the rest is shown
//!   raw, with the text found in it (device and master-track names).
//! - `vers`: the writing application's version string.
//! - `stat`, `tmpo`, `MTRO`/`mtro`: two floats spanning the session (view
//!   range), the tempo (the same float appears in `tmpo` and `MTRO`), and
//!   metronome settings with a time signature and click pattern as
//!   length-prefixed strings (UTF-16 in `MTRO`, ANSI in `mtro`).
//! - `TRKM` and `TRKS` (same layout, mostly the same bytes): a track count
//!   and another u32, then per track a u32 (2 for the master track, 0 for the
//!   others) and an `AudioTrack` object.
//! - `blk `, `bk25`, `envp`, `ep20`, `loop`, `cues`: empty lists in the
//!   sample (a zero u32, plus 0x70 in `bk25`); clips (blocks), envelopes,
//!   loops and cues presumably live here but their records are unknown, so
//!   any data is shown raw (with embedded audio and text, such as file
//!   paths, picked out).
//!
//! Audition 3 serialises its mixer objects as `u32 length, UTF-16 class name
//! (with NUL), u32 body size, body`; bodies mix plain fields, length-prefixed
//! UTF-16 strings (`u32` count of units including the NUL) and nested
//! objects. Classes seen: `AudioTrack` (u32 track ID, name, routing
//! strings, then components), `AudioComp`, `SendComp`, `OutputComp`,
//! `EfxGrpComp`, `AudioParams0` (u32 count, then `AudioParam0`s) and
//! `AudioParam0` (a byte, the f32 value, a byte, then an `Env` object whose
//! body has a u32 and the parameter name as NUL-terminated UTF-16). Objects
//! and strings inside bodies are found by their shape (an identifier class
//! name whose size fits its parent; a printable NUL-terminated string whose
//! length prefix matches), not from a schema; everything between them is
//! shown raw. Parameter values (`Fader Volume`, `Output Pan`,
//! `[NOUI]Muting`, EQ bands, sends) are shown as stored.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{float, uint};
use crate::formats::{Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;
/// Deepest object nesting we follow.
const MAX_DEPTH: u32 = 16;

declare_format!(pub SES = "cool-edit-session", "Cool Edit Pro / Adobe Audition session", ["ses"], "application/x-cool-edit-session",
    Probe::Magic(&[(0, b"COOLNESS")]), ses);

fn chunk_title(tag: &[u8]) -> Option<&'static str> {
    Some(match tag {
        b"hdr " => "Session header",
        b"vers" => "Application version",
        b"stat" => "View state (inferred)",
        b"tmpo" => "Tempo (inferred)",
        b"TRKM" | b"TRKS" => "Tracks",
        b"blk " | b"bk25" => "Blocks (clips; layout unknown)",
        b"envp" | b"ep20" => "Envelopes (layout unknown)",
        b"loop" => "Loops (layout unknown)",
        b"cues" => "Cues (layout unknown)",
        b"MTRO" | b"mtro" => "Metronome (inferred)",
        _ => return None,
    })
}

async fn ses(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let size = {
        let mut f = Fields::emitting(&cx, &head, LE);
        f.ascii("Signature", 8).emit()?;
        f.u32("Size")
            .desc("Bytes after this field")
            .check(|&v| {
                (u64::from(v) != file.len.saturating_sub(12)).then(|| {
                    Diagnostic::malformed(format!(
                        "size {v:#x} does not match the file ({:#x} bytes after the header)",
                        file.len.saturating_sub(12)
                    ))
                })
            })
            .emit()?
    };
    let body = file.sub(12, u64::from(size).min(file.len.saturating_sub(12)));
    let mut cur = Cursor::new(&cx, body, LE);
    let mut version = String::new();
    let mut rate = None;
    let mut tracks = None;
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, LE)).await? {
        let tag = chunk.id.clone();
        let mut node = chunk.node();
        if let Some(title) = chunk_title(&tag) {
            node = node.desc(title);
        }
        match tag.as_slice() {
            b"hdr " => {
                let h = cx.read_avail(chunk.body.sub(0, 4)).await?;
                rate = u32_le(&h, 0);
                if let Some(r) = rate {
                    node = node.summary(format!("{r} Hz"));
                }
                node = node.lazy(header, (input, chunk.body));
            }
            b"vers" => {
                let data = cx.read_avail(chunk.body.sub(0, 256)).await?;
                version = crate::text::until_nul(&data);
                node = node.value(Value::Text(version.clone())).span(chunk.span);
            }
            b"TRKM" | b"TRKS" => {
                let h = cx.read_avail(chunk.body.sub(0, 4)).await?;
                let count = u32_le(&h, 0).unwrap_or(0);
                if tag.as_slice() == b"TRKM" {
                    tracks = Some(count);
                }
                node = node
                    .summary(format!("{count} tracks"))
                    .lazy(track_list, (input, chunk.body));
            }
            b"tmpo" => {
                let h = cx.read_avail(chunk.body.sub(0, 8)).await?;
                if let Some(t) = f64_le(&h, 0) {
                    node = node.summary(format!("{t:.3} (tempo?)"));
                }
                node = node.lazy(tempo, (input, chunk.body));
            }
            b"stat" => node = node.lazy(view_state, (input, chunk.body)),
            b"MTRO" | b"mtro" => {
                node = node.lazy(metronome, (input, chunk.body, tag.as_slice() == b"MTRO"));
            }
            _ => node = node.lazy(opaque, (input, chunk.body)),
        }
        cx.push(node).await;
    }
    if cur.remaining() > 0 {
        cx.push(Node::new("Trailing data").span(body.tail(cur.pos())))
            .await;
    }
    let mut summary = "Multitrack session".to_owned();
    if !version.is_empty() {
        summary = format!("{version} multitrack session");
    }
    if let Some(t) = tracks {
        summary.push_str(&format!(", {t} tracks"));
    }
    if let Some(r) = rate {
        summary.push_str(&format!(", {r} Hz"));
    }
    cx.annotate(summary);
    Ok(())
}

fn f64_le(data: &[u8], at: usize) -> Option<f64> {
    let b: [u8; 8] = data.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(f64::from_le_bytes(b))
}

fn f32_le(data: &[u8], at: usize) -> Option<f32> {
    let b: [u8; 4] = data.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(f32::from_le_bytes(b))
}

async fn header(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Sample rate").emit()?;
    let rate = u32_le(&block.data, 0).unwrap_or(0);
    f.u32("Length (samples, inferred)")
        .with(|&v, n| {
            if rate > 0 {
                n.summary(format!("{:.3} s", f64::from(v) / f64::from(rate)))
            } else {
                n
            }
        })
        .emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u16("Bits per sample (inferred)").emit()?;
    f.u16("Unknown").emit()?;
    f.f64("Unknown (f64)").emit()?;
    f.f64("Unknown (f64)").emit()?;
    let rest = span.tail(32);
    if rest.len > 0 {
        cx.emit(
            Node::new("Rest")
                .span(rest)
                .summary("not decoded; text found in it shown")
                .lazy(scanned, (input, rest, 0u32)),
        );
    }
    Ok(())
}

async fn tempo(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    Fields::emitting(&cx, &block, LE)
        .f64("Tempo (BPM, inferred)")
        .emit()?;
    if span.len > 8 {
        cx.emit(raw_node(input, span.tail(8)));
    }
    Ok(())
}

async fn view_state(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.f64("Start (samples, inferred)").emit()?;
    f.f64("End (samples, inferred)").emit()?;
    if span.len > 16 {
        cx.emit(raw_node(input, span.tail(16)));
    }
    Ok(())
}

async fn metronome(cx: Cx, (input, span, wide): (Input, Span, bool)) -> Result<()> {
    let block = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Size of the rest").emit()?;
    f.u32("Unknown (a sample rate?)").emit()?;
    f.f64("Tempo (BPM, inferred)").emit()?;
    let rest = span.tail(16);
    let data = cx.read_avail(rest).await?;
    let items = scan(&data, 0, data.len(), wide, !wide);
    emit_items(&cx, input, rest, &data, &items, 0).await;
    Ok(())
}

/// Any other chunk: embedded audio if it starts like an audio file, else
/// the raw bytes with any text found in them.
async fn opaque(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let head = cx.read_avail(span.sub(0, 4)).await?;
    let audio = [&b"RIFF"[..], b"RIFX", b"FORM", b"OggS", b"fLaC", b"ID3"];
    if audio.iter().any(|m| head.starts_with(m)) {
        cx.emit(embedded("Embedded audio", input.nested(span)));
        return Ok(());
    }
    if span.len <= 16 {
        let block = cx.block(span).await?;
        let mut f = Fields::emitting(&cx, &block, LE);
        while f.remaining() >= 4 {
            f.u32("Value (u32)").emit()?;
        }
        if f.remaining() > 0 {
            f.bytes("Rest", f.remaining()).emit()?;
        }
        return Ok(());
    }
    cx.emit(
        Node::new("Data")
            .span(span)
            .summary(format!("{} bytes, not decoded", span.len))
            .lazy(scanned_runs, (input, span)),
    );
    Ok(())
}

fn raw_node(input: Input, span: Span) -> Node {
    Node::new("Rest")
        .span(span)
        .summary(format!("{} bytes, not decoded", span.len))
        .lazy(scanned, (input, span, 0u32))
}

// ---------------------------------------------------------------------------
// Tracks and the object serialisation

async fn track_list(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    let count = {
        let mut f = Fields::emitting(&cx, &block, LE);
        let count = f.u32("Track count").emit()?;
        f.u32("Unknown (equals the count in the sample)").emit()?;
        count
    };
    let mut pos = 8u64;
    for index in 0..count {
        let start = pos;
        let head = cx.read_avail(span.sub(pos, 4 + 4 + 2 * 64 + 4)).await?;
        let kind = u32_le(&head, 0).unwrap_or(0);
        let Some((class, body_at, body_len)) = object_header(&head, 4) else {
            cx.push(
                Node::new(format!("Track {index}"))
                    .span(span.tail(pos))
                    .diag(Diagnostic::malformed("no track object here").at(span.sub(pos, 4))),
            )
            .await;
            break;
        };
        let body_len = to_u64(body_len);
        let object = span.sub(
            start.saturating_add(4),
            to_u64(body_at).saturating_sub(4).saturating_add(body_len),
        );
        let entry = span.sub(start, 4u64.saturating_add(object.len));
        if object.len < to_u64(body_at).saturating_sub(4).saturating_add(body_len) {
            cx.push(
                Node::new(format!("Track {index}"))
                    .span(entry)
                    .diag(Diagnostic::truncated(entry, entry.len)),
            )
            .await;
            break;
        }
        let data = cx.read(object).await?;
        let mut node = Node::new(format!("Track {index}")).span(entry);
        let mut summary = vec![class.clone()];
        if class == "AudioTrack" {
            let at = body_at.saturating_sub(4);
            let id = u32_le(&data, at);
            if let Some((name, _)) = len_string(&data, at.saturating_add(4), data.len(), true) {
                node.name = format!("Track {index}: {name}").into();
            }
            if let Some(id) = id {
                summary.push(format!("ID {id}"));
            }
            let params = params(&data, 0, data.len(), 0);
            for wanted in ["Fader Volume", "Output Pan", "[NOUI]Muting"] {
                if let Some((_, v)) = params.iter().find(|(n, _)| n == wanted) {
                    summary.push(format!("{} {v}", wanted.trim_start_matches("[NOUI]")));
                }
            }
        }
        if kind == 2 {
            summary.push("kind 2 (master?)".to_owned());
        }
        node = node
            .summary(summary.join(", "))
            .lazy(track_entry, (input, entry));
        cx.push(node).await;
        pos = start.saturating_add(entry.len);
    }
    if pos < span.len {
        cx.push(raw_node(input, span.tail(pos))).await;
    }
    Ok(())
}

async fn track_entry(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 4)).await?;
    Fields::emitting(&cx, &block, LE)
        .u32("Kind (raw)")
        .desc("2 for the master track and 0 for the others in the one sample seen")
        .emit()?;
    let object = span.tail(4);
    let data = cx.read(object).await?;
    let items = scan(&data, 0, data.len(), true, false);
    emit_items(&cx, input, object, &data, &items, 0).await;
    Ok(())
}

/// An object at `at`: `u32 n`, `n` UTF-16 units of an identifier ending in
/// NUL, `u32 size`, then `size` body bytes ending at or before `end`.
/// Returns the class name and the body range.
fn object_at(data: &[u8], at: usize, end: usize) -> Option<(String, usize, usize)> {
    let (name, body, size) = object_header(data, at)?;
    let body_end = body.checked_add(size)?;
    (size >= 4 && body_end <= end.min(data.len())).then_some((name, body, body_end))
}

/// The header of an object at `at`: class name, body offset and body size
/// (not checked against the data).
fn object_header(data: &[u8], at: usize) -> Option<(String, usize, usize)> {
    let n = to_usize(u32_le(data, at)?.into());
    if !(2..=64).contains(&n) {
        return None;
    }
    let name_at = at.checked_add(4)?;
    let mut name = String::new();
    for i in 0..n {
        let unit = u16_le(data, name_at.checked_add(i.checked_mul(2)?)?)?;
        let last = i.checked_add(1)? == n;
        let ok = if last {
            unit == 0
        } else if i == 0 {
            (0x41..=0x5a).contains(&unit)
        } else {
            unit < 0x80
                && (char::from(u8::try_from(unit).ok()?).is_ascii_alphanumeric() || unit == 0x5f)
        };
        if !ok {
            return None;
        }
        if !last {
            name.push(char::from(u8::try_from(unit).ok()?));
        }
    }
    let size_at = name_at.checked_add(n.checked_mul(2)?)?;
    let size = to_usize(u32_le(data, size_at)?.into());
    let body = size_at.checked_add(4)?;
    Some((name, body, size))
}

/// A length-prefixed string at `at`: `u32 n` (units including the NUL),
/// then `n` UTF-16 units (or bytes), printable and NUL-terminated. Returns
/// the text and the end offset.
fn len_string(data: &[u8], at: usize, end: usize, wide: bool) -> Option<(String, usize)> {
    let n = to_usize(u32_le(data, at)?.into());
    if !(2..=1024).contains(&n) {
        return None;
    }
    let text_at = at.checked_add(4)?;
    let unit = if wide { 2 } else { 1 };
    let stop = text_at.checked_add(n.checked_mul(unit)?)?;
    if stop > end.min(data.len()) {
        return None;
    }
    // Check the terminator first: most candidates fail there.
    let get = |i: usize| {
        let p = text_at.saturating_add(i.saturating_mul(unit));
        if wide {
            u16_le(data, p)
        } else {
            data.get(p).copied().map(u16::from)
        }
    };
    if get(n.saturating_sub(1))? != 0 {
        return None;
    }
    let mut units = Vec::new();
    for i in 0..n.saturating_sub(1) {
        let u = get(i)?;
        if u < 0x20 || (0xd800..0xe000).contains(&u) {
            return None;
        }
        units.push(u);
    }
    let body = units.as_slice();
    let text = if wide {
        String::from_utf16_lossy(body)
    } else {
        body.iter()
            .filter_map(|&u| char::from_u32(u.into()))
            .collect()
    };
    Some((text, stop))
}

/// A run of at least four printable ASCII characters ending in NUL, as
/// single bytes or UTF-16 units. Returns the text, the end (after the NUL)
/// and whether it is UTF-16.
fn text_run(data: &[u8], at: usize, end: usize) -> Option<(String, usize, bool)> {
    let printable = |b: u8| (0x20..0x7f).contains(&b);
    // Runs are short; the cap keeps a scan over long text linear.
    let end = end.min(data.len()).min(at.saturating_add(2048));
    // UTF-16
    let mut i = at;
    let mut text = String::new();
    while i.saturating_add(1) < end {
        let lo = *data.get(i)?;
        let hi = *data.get(i.saturating_add(1))?;
        if hi != 0 || !printable(lo) {
            break;
        }
        text.push(char::from(lo));
        i = i.saturating_add(2);
    }
    if text.len() >= 4 && u16_le(data, i) == Some(0) && i.saturating_add(2) <= end {
        return Some((text, i.saturating_add(2), true));
    }
    let n = data
        .get(at..end)?
        .iter()
        .take_while(|&&b| printable(b))
        .count();
    let stop = at.saturating_add(n);
    (n >= 4 && stop < end && data.get(stop) == Some(&0)).then(|| {
        (
            crate::text::latin1(data.get(at..stop).unwrap_or_default()),
            stop.saturating_add(1),
            false,
        )
    })
}

enum Item {
    Raw(usize, usize),
    Object {
        at: usize,
        class: String,
        body: usize,
        end: usize,
    },
    Str {
        at: usize,
        end: usize,
        text: String,
    },
    Text {
        at: usize,
        end: usize,
        text: String,
        wide: bool,
    },
}

/// Splits `data[from..to]` into objects, length-prefixed strings (UTF-16
/// when `wide`, else ANSI), optionally plain NUL-terminated text runs, and
/// raw bytes between them.
fn scan(data: &[u8], from: usize, to: usize, wide: bool, runs: bool) -> Vec<Item> {
    let to = to.min(data.len());
    let mut items = Vec::new();
    let mut raw = from;
    let mut at = from;
    while at < to {
        let found = if let Some((class, body, end)) = object_at(data, at, to) {
            Some((
                Item::Object {
                    at,
                    class,
                    body,
                    end,
                },
                end,
            ))
        } else if let Some((text, end)) = len_string(data, at, to, wide) {
            Some((Item::Str { at, end, text }, end))
        } else if runs && (at == raw || data.get(at.wrapping_sub(1)) == Some(&0)) {
            text_run(data, at, to).map(|(text, end, wide)| {
                (
                    Item::Text {
                        at,
                        end,
                        text,
                        wide,
                    },
                    end,
                )
            })
        } else {
            None
        };
        match found {
            Some((item, end)) if end > at => {
                if at > raw {
                    items.push(Item::Raw(raw, at));
                }
                items.push(item);
                at = end;
                raw = end;
            }
            _ => at = at.saturating_add(1),
        }
    }
    if to > raw {
        items.push(Item::Raw(raw, to));
    }
    items
}

/// `AudioParam0` values (parameter name, value) anywhere in `data[from..to]`.
fn params(data: &[u8], from: usize, to: usize, depth: u32) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if depth > MAX_DEPTH {
        return out;
    }
    for item in scan(data, from, to, true, false) {
        if let Item::Object {
            class, body, end, ..
        } = item
        {
            if class == "AudioParam0" {
                if let Some(p) = param(data, body, end) {
                    out.push((p.0, format_value(p.1)));
                }
            } else {
                out.extend(params(data, body, end, depth.saturating_add(1)));
            }
        }
    }
    out
}

fn format_value(v: f32) -> String {
    format!("{v}")
}

/// An f32 as the f64 with the same shortest decimal form (0.33, not
/// 0.33000001311302185).
fn f32_to_f64(v: f32) -> f64 {
    format!("{v}").parse().unwrap_or(f64::from(v))
}

/// An `AudioParam0` body: a byte, the f32 value, a byte, then an `Env`
/// object holding the parameter name.
fn param(data: &[u8], body: usize, end: usize) -> Option<(String, f32)> {
    let value = f32_le(data, body.checked_add(1)?)?;
    let (_, env_body, env_end) = object_at(data, body.checked_add(6)?, end)?;
    let name = env_name(data, env_body, env_end)?;
    Some((name, value))
}

/// The parameter name in an `Env` body: NUL-terminated UTF-16 after a u32.
fn env_name(data: &[u8], body: usize, end: usize) -> Option<String> {
    let rest = data.get(body.checked_add(4)?..end)?;
    let (text, _, terminated) = crate::text::utf16z(rest, LE);
    terminated.then_some(text)
}

/// Pushes nodes for scanned items; `span` covers `data`.
async fn emit_items(cx: &Cx, input: Input, span: Span, data: &[u8], items: &[Item], depth: u32) {
    let at = |a: usize, b: usize| span.sub(to_u64(a), to_u64(b.saturating_sub(a)));
    for item in items {
        let node = match item {
            Item::Raw(a, b) => Node::new("Data")
                .span(at(*a, *b))
                .summary(format!("{} bytes, not decoded", b.saturating_sub(*a))),
            Item::Str { at: a, end, text } => Node::new("String")
                .span(at(*a, *end))
                .value(Value::Text(text.clone())),
            Item::Text {
                at: a,
                end,
                text,
                wide,
            } => Node::new("Text")
                .span(at(*a, *end))
                .value(Value::Text(text.clone()))
                .summary(if *wide {
                    "UTF-16, found in undecoded data"
                } else {
                    "found in undecoded data"
                }),
            Item::Object {
                at: a,
                class,
                body,
                end,
            } => object_node(input, span, data, *a, class, *body, *end, depth),
        };
        cx.push(node).await;
    }
}

#[allow(clippy::too_many_arguments)]
fn object_node(
    input: Input,
    span: Span,
    data: &[u8],
    at: usize,
    class: &str,
    body: usize,
    end: usize,
    depth: u32,
) -> Node {
    let whole = span.sub(to_u64(at), to_u64(end.saturating_sub(at)));
    let mut node = Node::new(class.to_owned()).span(whole);
    match class {
        "AudioParam0" => {
            if let Some((name, v)) = param(data, body, end) {
                node.name = format!("AudioParam0: {name}").into();
                node = node.value(float(f32_to_f64(v)));
            }
        }
        "Env" => {
            if let Some(name) = env_name(data, body, end) {
                node = node.summary(name);
            }
        }
        "AudioTrack" => {
            if let Some((name, _)) = len_string(data, body.saturating_add(4), end, true) {
                node = node.summary(name);
            }
        }
        _ => {
            node = node.summary(format!("{} bytes", end.saturating_sub(body)));
        }
    }
    if depth >= MAX_DEPTH {
        return node.diag(Diagnostic::limit(format!(
            "objects nested deeper than {MAX_DEPTH}"
        )));
    }
    let body_offset = to_u64(body.saturating_sub(at));
    node.lazy(
        crate::expander!(self::expand_object: (Input, Span, u64, String, u32)),
        (input, whole, body_offset, class.to_owned(), depth),
    )
}

async fn expand_object(
    cx: Cx,
    (input, span, body_offset, class, depth): (Input, Span, u64, String, u32),
) -> Result<()> {
    let data = cx.read(span).await?;
    let body = to_usize(body_offset);
    let name_len = body.saturating_sub(8);
    cx.emit(
        Node::new("Class name")
            .span(span.sub(0, to_u64(name_len).saturating_add(4)))
            .value(Value::Text(class.clone())),
    );
    let size = u32_le(&data, body.saturating_sub(4)).unwrap_or(0);
    cx.emit(
        Node::new("Body size")
            .span(span.sub(to_u64(body.saturating_sub(4)), 4))
            .value(uint(size.into())),
    );
    let mut from = body;
    let end = data.len();
    let field = |a: usize, len: usize| span.sub(to_u64(a), to_u64(len));
    match class.as_str() {
        "AudioTrack" => {
            if let Some(id) = u32_le(&data, body) {
                cx.emit(
                    Node::new("Track ID")
                        .span(field(body, 4))
                        .value(uint(id.into())),
                );
                from = body.saturating_add(4);
            }
            if let Some((name, stop)) = len_string(&data, from, end, true) {
                cx.emit(
                    Node::new("Name")
                        .span(field(from, stop.saturating_sub(from)))
                        .value(Value::Text(name)),
                );
                from = stop;
            }
        }
        "AudioParam0" if end.saturating_sub(body) >= 6 => {
            if let Some(b) = data.get(body) {
                cx.emit(
                    Node::new("Unknown (u8)")
                        .span(field(body, 1))
                        .value(uint((*b).into())),
                );
            }
            if let Some(v) = f32_le(&data, body.saturating_add(1)) {
                cx.emit(
                    Node::new("Value")
                        .span(field(body.saturating_add(1), 4))
                        .value(float(f32_to_f64(v))),
                );
            }
            if let Some(b) = data.get(body.saturating_add(5)) {
                cx.emit(
                    Node::new("Unknown (u8)")
                        .span(field(body.saturating_add(5), 1))
                        .value(uint((*b).into())),
                );
            }
            from = body.saturating_add(6);
        }
        "AudioParams0" => {
            if let Some(n) = u32_le(&data, body) {
                cx.emit(
                    Node::new("Count")
                        .span(field(body, 4))
                        .value(uint(n.into())),
                );
                from = body.saturating_add(4);
            }
        }
        "Env" => {
            if let Some(v) = u32_le(&data, body) {
                cx.emit(
                    Node::new("Unknown (u32)")
                        .span(field(body, 4))
                        .value(uint(v.into())),
                );
                from = body.saturating_add(4);
                let rest = data.get(from..).unwrap_or_default();
                let (name, used, terminated) = crate::text::utf16z(rest, LE);
                if terminated {
                    cx.emit(
                        Node::new("Parameter name")
                            .span(field(from, used))
                            .value(Value::Text(name)),
                    );
                    from = from.saturating_add(used);
                }
            }
            if from < end {
                cx.emit(
                    Node::new("Data")
                        .span(field(from, end.saturating_sub(from)))
                        .summary("not decoded"),
                );
            }
            return Ok(());
        }
        _ => {}
    }
    let items = scan(&data, from, end, true, false);
    emit_items(&cx, input, span, &data, &items, depth.saturating_add(1)).await;
    Ok(())
}

/// Undecoded bytes with objects, strings and text runs picked out.
async fn scanned(cx: Cx, (input, span, depth): (Input, Span, u32)) -> Result<()> {
    let data = cx.read(span).await?;
    let items = scan(&data, 0, data.len(), true, true);
    emit_items(&cx, input, span, &data, &items, depth).await;
    Ok(())
}

async fn scanned_runs(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    scanned(cx, (input, span, 0)).await
}
