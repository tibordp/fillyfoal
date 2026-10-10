//! Playlists and cue sheets: extended M3U (and HLS, its streaming dialect),
//! PLS, and CUE sheets.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::preview;
use super::encoding::prepare;
use super::piece::Piece;
use super::scan::{LineBuf, Lines};
use super::{plural, probe, text_node};

pub static HLS: Format = Format {
    name: "hls",
    title: "HLS playlist (M3U8)",
    extensions: &["m3u8"],
    mime: "application/vnd.apple.mpegurl",
    probe: Probe::Custom(|h| {
        let head = probe::head(h);
        head.starts_with(b"#EXTM3U") && probe::contains(&head, b"#EXT-X-")
    }),
    dissect: crate::expander!(dissect_m3u: Input),
};

pub static M3U: Format = Format {
    name: "m3u",
    title: "M3U playlist",
    extensions: &["m3u", "m3u8"],
    mime: "audio/x-mpegurl",
    probe: Probe::Custom(|h| probe::head(h).starts_with(b"#EXTM3U")),
    dissect: crate::expander!(dissect_m3u: Input),
};

pub static PLS: Format = Format {
    name: "pls",
    title: "PLS playlist",
    extensions: &["pls"],
    mime: "audio/x-scpls",
    probe: Probe::Custom(|h| {
        let head = probe::head(h);
        probe::significant(&head, &[b";", b"#"])
            .next()
            .is_some_and(|l| probe::trim(l).eq_ignore_ascii_case(b"[playlist]"))
    }),
    dissect: crate::expander!(dissect_pls: Input),
};

pub static CUE: Format = Format {
    name: "cue",
    title: "CUE sheet",
    extensions: &["cue"],
    mime: "application/x-cue",
    probe: Probe::Custom(probe_cue),
    dissect: crate::expander!(dissect_cue: Input),
};

// ---------------------------------------------------------------------------
// M3U / HLS

/// Splits an attribute list (`A=1,B="x,y"`) into pieces.
fn attribute_list(p: Piece<'_>) -> Vec<(Piece<'_>, Piece<'_>)> {
    let mut out = Vec::new();
    let b = p.bytes();
    let mut start = 0usize;
    let mut quoted = false;
    let mut i = 0usize;
    loop {
        let c = b.get(i).copied();
        match c {
            Some(b'"') => quoted = !quoted,
            Some(b',') | None if !quoted => {
                let item = p.slice(start, i).trim();
                if let Some((k, v)) = item.split_once(b'=') {
                    out.push((k.trim(), v.trim()));
                }
                start = i.saturating_add(1);
                if c.is_none() {
                    return out;
                }
            }
            None => return out,
            _ => {}
        }
        i = i.saturating_add(1);
    }
}

/// `#TAG:value` split into name and value.
fn tag(line: Piece<'_>) -> (Piece<'_>, Option<Piece<'_>>) {
    match line.split_once(b':') {
        Some((name, value)) => (name, Some(value)),
        None => (line, None),
    }
}

/// Tags that describe the next URI.
fn entry_tag(name: &[u8]) -> bool {
    matches!(
        name,
        b"#EXTINF"
            | b"#EXT-X-STREAM-INF"
            | b"#EXT-X-BYTERANGE"
            | b"#EXT-X-PROGRAM-DATE-TIME"
            | b"#EXT-X-DISCONTINUITY"
            | b"#EXTGRP"
            | b"#EXTVLCOPT"
            | b"#EXT-X-GAP"
            | b"#EXT-X-BITRATE"
    )
}

async fn tag_fields(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let p = line.piece().trim();
        if p.is_empty() {
            continue;
        }
        if p.first() != Some(b'#') {
            cx.emit(text_node("URI", p.span(), &p.text()));
            continue;
        }
        let (name, value) = tag(p);
        let Some(value) = value else {
            cx.emit(Node::new(name.text()).span(p.span()));
            continue;
        };
        if name.bytes() == b"#EXTINF" {
            // `#EXTINF:duration [key="value" ...],title`
            let (head, title) = value.split_once(b',').unwrap_or((value, value.to(0)));
            let (duration, attrs) = head.split_word();
            cx.emit(match duration.text().parse::<f64>() {
                Ok(d) => Node::new("Duration")
                    .span(duration.span())
                    .value(Value::Float(d))
                    .summary("seconds"),
                Err(_) => text_node("Duration", duration.span(), &duration.text()),
            });
            for word in attrs.words() {
                if let Some((k, v)) = word.split_once(b'=') {
                    cx.emit(text_node(k.text(), v.unquote().span(), &v.unquote().text()));
                }
            }
            if !title.trim().is_empty() {
                cx.emit(text_node(
                    "Title",
                    title.trim().span(),
                    &title.trim().text(),
                ));
            }
            continue;
        }
        let attrs = attribute_list(value);
        if attrs.is_empty() || !value.contains(b"=") {
            let v = value.trim();
            cx.emit(match super::number(&v.text()) {
                Some(n) => Node::new(name.text()).span(v.span()).value(n),
                None => text_node(name.text(), v.span(), &v.text()),
            });
            continue;
        }
        for (k, v) in attrs {
            let v = v.unquote();
            let node = match super::number(&v.text()) {
                Some(n) if v.first() != Some(b'"') => Node::new(k.text()).span(v.span()).value(n),
                _ => text_node(k.text(), v.span(), &v.text()),
            };
            cx.emit(node);
        }
    }
    Ok(())
}

pub async fn dissect_m3u(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut pending: Option<(u64, String, Option<f64>, bool)> = None; // start, title, duration, variant
    let mut entries = 0u64;
    let mut variants = 0u64;
    let mut segments = 0u64;
    let mut total = 0.0f64;
    let mut hls = false;
    while let Some(line) = lines.next().await? {
        let p = line.piece().trim();
        if p.is_empty() {
            continue;
        }
        if p.first() == Some(b'#') {
            let (name, value) = tag(p);
            hls |= name.starts_with(b"#EXT-X-");
            if entry_tag(name.bytes()) {
                let entry = pending.get_or_insert((line.start, String::new(), None, false));
                if name.bytes() == b"#EXTINF"
                    && let Some(v) = value
                {
                    let (head, title) = v.split_once(b',').unwrap_or((v, v.to(0)));
                    entry.1 = title.trim().text();
                    entry.2 = head.split_word().0.text().parse().ok();
                }
                if name.bytes() == b"#EXT-X-STREAM-INF" {
                    entry.3 = true;
                    if let Some(v) = value {
                        let attrs = attribute_list(v);
                        let get = |k: &[u8]| {
                            attrs
                                .iter()
                                .find(|(n, _)| n.bytes() == k)
                                .map(|(_, v)| v.unquote().text())
                        };
                        let mut parts = Vec::new();
                        parts.extend(get(b"RESOLUTION"));
                        parts.extend(get(b"BANDWIDTH").map(|b| format!("{b} bit/s")));
                        parts.extend(get(b"CODECS"));
                        entry.1 = parts.join(", ");
                    }
                }
                continue;
            }
            if name.bytes() == b"#EXTM3U" {
                cx.push(
                    Node::new("Header")
                        .span(p.span())
                        .value(Value::Text(p.text())),
                )
                .await;
                continue;
            }
            let node = match value {
                // `#TAG:A=1,B="x"`: attributes as children.
                Some(v) if v.contains(b"=") => Node::new(name.text())
                    .span(line.span)
                    .summary(preview(&v.text(), 80))
                    .lazy(tag_fields, line.span),
                Some(v) => match super::number(&v.trim().text()) {
                    Some(n) => Node::new(name.text()).span(v.trim().span()).value(n),
                    None => text_node(name.text(), v.trim().span(), &v.trim().text()),
                },
                None => Node::new(name.text()).span(line.span),
            };
            cx.push(node).await;
            continue;
        }
        // A URI: closes the pending entry.
        let (start, title, duration, variant) =
            pending
                .take()
                .unwrap_or((line.start, String::new(), None, false));
        let entry = span.sub(
            start,
            line.start
                .saturating_add(line.span.len)
                .saturating_sub(start),
        );
        entries = entries.saturating_add(1);
        let uri = p.text();
        let (name, kind) = if variant {
            variants = variants.saturating_add(1);
            (format!("Variant {variants}"), title)
        } else {
            if let Some(d) = duration {
                segments = segments.saturating_add(1);
                total += d;
            }
            let name = if title.is_empty() {
                format!("Entry {entries}")
            } else {
                title
            };
            (name, duration.map(|d| format!("{d} s")).unwrap_or_default())
        };
        let summary = if kind.is_empty() {
            uri
        } else {
            format!("{kind}: {uri}")
        };
        lines.progress();
        cx.push(
            Node::new(name)
                .span(entry)
                .summary(preview(&summary, 120))
                .lazy(tag_fields, entry),
        )
        .await;
    }
    let summary = if variants > 0 {
        format!(
            "HLS master playlist, {}",
            plural(variants, "variant", "variants")
        )
    } else if hls {
        format!(
            "HLS media playlist, {}, {total:.1} s",
            plural(segments, "segment", "segments")
        )
    } else {
        format!("M3U playlist, {}", plural(entries, "entry", "entries"))
    };
    cx.annotate(summary);
    Ok(())
}

// ---------------------------------------------------------------------------
// PLS

/// `File12` → (`File`, 12).
fn indexed(key: &str) -> Option<(&str, u64)> {
    let digits = key.bytes().rev().take_while(u8::is_ascii_digit).count();
    let split = key.len().checked_sub(digits)?;
    let (name, n) = (key.get(..split)?, key.get(split..)?);
    Some((name, n.parse().ok()?))
}

pub async fn dissect_pls(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut group: Option<(u64, u64, u64, String)> = None; // index, start, end, title
    let mut count = 0u64;
    let flush = |cx: &Cx, g: (u64, u64, u64, String)| {
        let (index, start, end, title) = g;
        let entry = span.sub(start, end.saturating_sub(start));
        let node = Node::new(format!("Entry {index}"))
            .span(entry)
            .summary(title)
            .lazy(pls_entry, entry);
        let cx = cx.clone();
        async move { cx.push(node).await }
    };
    while let Some(line) = lines.next().await? {
        let p = line.piece().trim();
        if p.is_empty() || p.first() == Some(b'[') || p.first() == Some(b';') {
            continue;
        }
        let Some((k, v)) = p.split_once(b'=') else {
            continue;
        };
        let key = k.trim().text();
        let value = v.trim();
        match indexed(&key) {
            Some((name, index)) => {
                if group.as_ref().is_some_and(|g| g.0 != index)
                    && let Some(g) = group.take()
                {
                    flush(&cx, g).await;
                    count = count.saturating_add(1);
                }
                let end = line.start.saturating_add(line.span.len);
                let g = group.get_or_insert((index, line.start, end, String::new()));
                g.2 = end;
                if name == "File" && g.3.is_empty() || name == "Title" {
                    g.3 = value.text();
                }
            }
            None => {
                if let Some(g) = group.take() {
                    flush(&cx, g).await;
                    count = count.saturating_add(1);
                }
                cx.push(match super::number(&value.text()) {
                    Some(n) => Node::new(key).span(value.span()).value(n),
                    None => text_node(key, value.span(), &value.text()),
                })
                .await;
            }
        }
    }
    if let Some(g) = group.take() {
        flush(&cx, g).await;
        count = count.saturating_add(1);
    }
    cx.annotate(format!(
        "PLS playlist, {}",
        plural(count, "entry", "entries")
    ));
    Ok(())
}

async fn pls_entry(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let p = line.piece().trim();
        let Some((k, v)) = p.split_once(b'=') else {
            continue;
        };
        let key = k.trim().text();
        let name = indexed(&key).map_or(key.clone(), |(n, _)| n.to_owned());
        let v = v.trim();
        cx.emit(match (name.as_str(), super::number(&v.text())) {
            ("Length", Some(n)) => Node::new(name)
                .span(v.span())
                .value(n)
                .summary("seconds (-1: unknown)"),
            _ => text_node(name, v.span(), &v.text()),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CUE sheets

const CUE_COMMANDS: &[&[u8]] = &[
    b"REM",
    b"CATALOG",
    b"CDTEXTFILE",
    b"FILE",
    b"FLAGS",
    b"INDEX",
    b"ISRC",
    b"PERFORMER",
    b"POSTGAP",
    b"PREGAP",
    b"SONGWRITER",
    b"TITLE",
    b"TRACK",
];

fn probe_cue(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut tracks = false;
    let mut file = false;
    for line in probe::significant(&head, &[]).take(40) {
        let t = probe::trim(line);
        let word = t.split(|&b| b == b' ').next().unwrap_or_default();
        if !CUE_COMMANDS.iter().any(|c| word.eq_ignore_ascii_case(c)) {
            return false;
        }
        tracks |= word.eq_ignore_ascii_case(b"TRACK");
        file |= word.eq_ignore_ascii_case(b"FILE");
    }
    tracks && file && probe::is_text(h)
}

/// `mm:ss:ff` (75 frames per second) in seconds.
fn msf(text: &str) -> Option<f64> {
    let mut parts = text.trim().split(':');
    let m: f64 = parts.next()?.parse().ok()?;
    let s: f64 = parts.next()?.parse().ok()?;
    let f: f64 = parts.next()?.parse().ok()?;
    Some(m * 60.0 + s + f / 75.0)
}

/// The node for one CUE command line.
fn command(line: &LineBuf) -> Node {
    let p = line.piece().trim();
    let (word, rest) = p.split_word();
    let name = word.text().to_ascii_uppercase();
    match name.as_str() {
        "INDEX" | "PREGAP" | "POSTGAP" => {
            let (first, second) = rest.split_word();
            let (label, time) = if name == "INDEX" {
                (format!("INDEX {}", first.text()), second)
            } else {
                (name.clone(), first)
            };
            match msf(&time.text()) {
                Some(s) => Node::new(label)
                    .span(time.span())
                    .value(Value::Float(s))
                    .summary(format!("{} (mm:ss:ff), seconds", time.text())),
                None => text_node(label, time.span(), &time.text()),
            }
        }
        "REM" => {
            let (key, value) = rest.split_word();
            text_node(
                format!("REM {}", key.text()),
                value.span(),
                &value.unquote().text(),
            )
        }
        _ => text_node(name, rest.span(), &rest.unquote().text()),
    }
}

#[derive(Clone, Debug)]
struct Group {
    span: Span,
    /// The command that starts a child group (`FILE` at the top level,
    /// `TRACK` inside a file).
    child: &'static [u8],
}

/// Pushes commands, grouping lines from each `child` command onward.
async fn cue_group(cx: Cx, g: Group) -> Result<()> {
    let mut lines = Lines::new(&cx, g.span);
    // A FILE or TRACK group starts with its own command line.
    let mut skip_first = g.child != b"FILE";
    let mut current: Option<(LineBuf, u64, Vec<String>)> = None;
    loop {
        let before = lines.pos();
        let line = lines.next().await?;
        if skip_first {
            skip_first = false;
            if let Some(l) = &line {
                // The group's own FILE/TRACK line: show its fields.
                let p = l.piece().trim();
                let (word, rest) = p.split_word();
                if word.eq_nocase(b"FILE") || word.eq_nocase(b"TRACK") {
                    let (a, b) = if rest.first() == Some(b'"') {
                        let end = rest
                            .from(1)
                            .find(b'"')
                            .map_or(rest.len(), |e| e.saturating_add(2));
                        (rest.to(end), rest.from(end).trim())
                    } else {
                        rest.split_word()
                    };
                    let (first, second) = if word.eq_nocase(b"FILE") {
                        ("File name", "Type")
                    } else {
                        ("Number", "Type")
                    };
                    cx.emit(text_node(first, a.span(), &a.unquote().text()));
                    cx.emit(text_node(second, b.span(), &b.text()));
                    continue;
                }
            }
        }
        let starts = line.as_ref().is_some_and(|l| {
            !g.child.is_empty() && l.piece().trim().split_word().0.eq_nocase(g.child)
        });
        if line.is_none() || starts {
            if let Some((first, start, notes)) = current.take() {
                let span = g.span.sub(start, before.saturating_sub(start));
                let p = first.piece().trim();
                let label = p.split_word().1;
                let name = format!(
                    "{} {}",
                    String::from_utf8_lossy(g.child),
                    label.unquote().text()
                );
                let next: &'static [u8] = if g.child == b"FILE" { b"TRACK" } else { b"" };
                cx.push(Node::new(name).span(span).summary(notes.join(", ")).lazy(
                    crate::expander!(self::cue_group: Group),
                    Group { span, child: next },
                ))
                .await;
            }
            let Some(l) = line else {
                break;
            };
            current = Some((l.clone(), l.start, Vec::new()));
            continue;
        }
        let Some(l) = line else {
            break;
        };
        if l.piece().trim().is_empty() {
            continue;
        }
        match current.as_mut() {
            Some((_, _, notes)) => {
                let p = l.piece().trim();
                let (word, rest) = p.split_word();
                if notes.len() < 3
                    && (word.eq_nocase(b"TITLE")
                        || word.eq_nocase(b"PERFORMER")
                        || word.eq_nocase(b"TRACK"))
                {
                    notes.push(preview(&rest.unquote().text(), 40));
                }
            }
            None => cx.push(command(&l)).await,
        }
    }
    Ok(())
}

pub async fn dissect_cue(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let head = cx.read_avail(prepared.span.sub(0, 16 * 1024)).await?;
    let text = super::encoding::probe_text(&head);
    let get = |cmd: &[u8]| {
        probe::lines(&text).find_map(|l| {
            let t = probe::trim(l);
            let rest = t.strip_prefix(cmd)?.strip_prefix(b" ")?;
            Some(
                super::encoding::decode_8bit(probe::trim(rest))
                    .trim_matches('"')
                    .to_owned(),
            )
        })
    };
    let tracks = probe::lines(&text)
        .filter(|l| probe::trim(l).starts_with(b"TRACK "))
        .count();
    let mut summary = String::from("CUE sheet");
    match (get(b"PERFORMER"), get(b"TITLE")) {
        (Some(p), Some(t)) => summary = format!("{summary}: {p} – {t}"),
        (None, Some(t)) => summary = format!("{summary}: {t}"),
        _ => {}
    }
    cx.annotate(format!(
        "{summary}, {}",
        plural(crate::bytes::to_u64(tracks), "track", "tracks")
    ));
    cue_group(
        cx,
        Group {
            span: prepared.span,
            child: b"FILE",
        },
    )
    .await
}
