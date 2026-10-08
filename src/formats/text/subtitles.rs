//! Timed text: SubRip (`.srt`), WebVTT and LRC lyrics.
//!
//! Cues are a paged collection; each shows its times (as seconds, with the
//! original notation in the summary), settings and text.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::preview;
use super::encoding::prepare;
use super::piece::Piece;
use super::scan::{LineBuf, Lines};
use super::{plural, probe, text_node};

pub static SRT: Format = Format {
    name: "srt",
    title: "SubRip subtitles",
    extensions: &["srt"],
    mime: "application/x-subrip",
    probe: Probe::Custom(probe_srt),
    dissect: crate::expander!(dissect_srt: Input),
};

pub static WEBVTT: Format = Format {
    name: "webvtt",
    title: "WebVTT subtitles",
    extensions: &["vtt"],
    mime: "text/vtt",
    probe: Probe::Custom(|h| {
        let head = probe::head(h);
        head.starts_with(b"WEBVTT")
            && matches!(head.get(6), None | Some(b' ' | b'\t' | b'\r' | b'\n'))
    }),
    dissect: crate::expander!(dissect_vtt: Input),
};

pub static LRC: Format = Format {
    name: "lrc",
    title: "LRC lyrics",
    extensions: &["lrc"],
    mime: "application/x-lrc",
    probe: Probe::Custom(probe_lrc),
    dissect: crate::expander!(dissect_lrc: Input),
};

/// `h:mm:ss.mmm`, `mm:ss.mmm` or `mm:ss` (`,` or `.` before the fraction)
/// in seconds.
pub fn clock(text: &str) -> Option<f64> {
    let t = text.trim().replace(',', ".");
    let mut parts: Vec<&str> = t.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }
    let seconds: f64 = parts.pop()?.parse().ok()?;
    let mut total = seconds;
    let mut scale = 60.0;
    while let Some(p) = parts.pop() {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let v: f64 = p.parse().ok()?;
        total += v * scale;
        scale *= 60.0;
    }
    (seconds.is_finite() && seconds >= 0.0).then_some(total)
}

/// Splits a timing line `start --> end [settings]`.
fn timing<'a>(line: Piece<'a>) -> Option<(Piece<'a>, Piece<'a>, Piece<'a>)> {
    let arrow = line.find_seq(b"-->")?;
    let start = line.to(arrow).trim();
    let rest = line.from(arrow.saturating_add(3)).trim_start();
    let (end, settings) = rest.split_word();
    clock(&start.text())?;
    clock(&end.text())?;
    Some((start, end, settings.trim()))
}

fn probe_srt(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut lines = probe::significant(&head, &[]);
    let (Some(index), Some(time)) = (lines.next(), lines.next()) else {
        return false;
    };
    let index = probe::trim(index);
    let span = Span::new(crate::span::SourceId(0), 0, 0);
    !index.is_empty()
        && index.iter().all(u8::is_ascii_digit)
        && timing(Piece::new(time, span)).is_some()
}

fn probe_lrc(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let tagged = probe::significant(&head, &[])
        .take(10)
        .filter(|l| {
            let t = probe::trim(l);
            t.starts_with(b"[")
                && t.iter().position(|&b| b == b']').is_some_and(|e| {
                    let inner = t.get(1..e).unwrap_or_default();
                    inner.contains(&b':') && inner.len() < 200
                })
        })
        .count();
    let total = probe::significant(&head, &[]).take(10).count();
    tagged >= 2 && tagged == total && probe::is_text(h)
}

fn time_node(name: &'static str, piece: Piece<'_>) -> Node {
    let text = piece.text();
    match clock(&text) {
        Some(s) => Node::new(name)
            .span(piece.span())
            .value(Value::Float(s))
            .summary(format!("{text} (seconds)")),
        None => text_node(name, piece.span(), &text).diag(Diagnostic::malformed("invalid time")),
    }
}

/// Reads a block of non-blank lines (skipping leading blank lines).
async fn block(lines: &mut Lines<'_>) -> Result<Vec<LineBuf>> {
    let mut out = Vec::new();
    while let Some(line) = lines.peek().await? {
        if line.is_blank() {
            lines.next().await?;
            if !out.is_empty() {
                break;
            }
            continue;
        }
        lines.next().await?;
        out.push(line);
        if out.len() > 1000 {
            break;
        }
    }
    Ok(out)
}

fn block_span(block: &[LineBuf]) -> Option<Span> {
    let first = block.first()?.span;
    let last = block.last()?.span;
    Some(Span::new(
        first.source,
        first.offset,
        last.end().saturating_sub(first.offset),
    ))
}

/// A cue: identifier, timing line and text lines.
#[derive(Clone, Debug)]
struct Cue {
    span: Span,
}

fn cue_summary(block: &[LineBuf], timing_at: usize) -> Option<String> {
    let t = block.get(timing_at)?;
    let (start, end, _) = timing(t.piece())?;
    let text: Vec<String> = block
        .iter()
        .skip(timing_at.saturating_add(1))
        .map(LineBuf::text)
        .collect();
    let a = clock(&start.text())?;
    let b = clock(&end.text())?;
    Some(format!(
        "{} → {} ({:.3} s): {}",
        start.text(),
        end.text(),
        b - a,
        preview(&text.join(" / "), 60)
    ))
}

async fn cue(cx: Cx, c: Cue) -> Result<()> {
    let mut lines = Lines::new(&cx, c.span);
    let block = block(&mut lines).await?;
    let at = block.iter().position(|l| timing(l.piece()).is_some());
    let Some(at) = at else {
        return Ok(());
    };
    for line in block.iter().take(at) {
        let p = line.piece().trim();
        match super::number(&p.text()) {
            Some(v) => cx.emit(Node::new("Index").span(p.span()).value(v)),
            None => cx.emit(text_node("Identifier", p.span(), &p.text())),
        }
    }
    if let Some((start, end, settings)) = block.get(at).and_then(|l| timing(l.piece())) {
        cx.emit(time_node("Start", start));
        cx.emit(time_node("End", end));
        if !settings.is_empty() {
            cx.emit(text_node("Settings", settings.span(), &settings.text()));
        }
    }
    let text: Vec<&LineBuf> = block.iter().skip(at.saturating_add(1)).collect();
    if let (Some(first), Some(last)) = (text.first(), text.last()) {
        let span = Span::new(
            first.span.source,
            first.span.offset,
            last.span.end().saturating_sub(first.span.offset),
        );
        let joined: Vec<String> = text.iter().map(|l| l.text()).collect();
        cx.emit(text_node("Text", span, &joined.join("\n")));
    }
    Ok(())
}

pub async fn dissect_srt(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    cx.annotate(format!("SubRip subtitles{}", prepared.note()));
    let mut lines = Lines::new(&cx, prepared.span);
    let mut count = 0u64;
    let mut last_end = None;
    loop {
        let block = block(&mut lines).await?;
        let Some(span) = block_span(&block) else {
            break;
        };
        count = count.saturating_add(1);
        let at = block.iter().position(|l| timing(l.piece()).is_some());
        let name = block
            .first()
            .map(|l| l.piece().trim().text())
            .filter(|_| at == Some(1))
            .map_or_else(|| format!("Cue {count}"), |i| format!("Cue {i}"));
        let mut node = Node::new(name).span(span);
        match at {
            Some(at) => {
                if let Some(s) = cue_summary(&block, at) {
                    node = node.summary(s);
                }
                last_end = block
                    .get(at)
                    .and_then(|l| timing(l.piece()))
                    .map(|(_, e, _)| e.text());
                node = node.lazy(cue, Cue { span });
            }
            None => node = node.diag(Diagnostic::malformed("no timing line")),
        }
        lines.progress();
        cx.push(node).await;
    }
    let mut summary = format!(
        "SubRip subtitles{}, {}",
        prepared.note(),
        plural(count, "cue", "cues")
    );
    if let Some(end) = last_end {
        summary = format!("{summary}, until {end}");
    }
    cx.annotate(summary);
    Ok(())
}

pub async fn dissect_vtt(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let mut lines = Lines::new(&cx, prepared.span);
    let header = block(&mut lines).await?;
    if let Some(span) = block_span(&header) {
        let first = header.first().map(LineBuf::text).unwrap_or_default();
        cx.emit(text_node("Header", span, &first));
        for line in header.iter().skip(1) {
            if let Some((k, v)) = line.piece().split_once(b':') {
                cx.emit(text_node(
                    k.trim().text(),
                    v.trim().span(),
                    &v.trim().text(),
                ));
            }
        }
    }
    let mut cues = 0u64;
    loop {
        let block = block(&mut lines).await?;
        let Some(span) = block_span(&block) else {
            break;
        };
        let first = block.first().map(LineBuf::piece);
        let kind = first.map(|p| p.split_word().0.text()).unwrap_or_default();
        let node = match kind.as_str() {
            "NOTE" | "STYLE" | "REGION" => {
                let text: Vec<String> = block.iter().map(LineBuf::text).collect();
                text_node(kind, span, &text.join("\n"))
            }
            _ => {
                let at = block.iter().position(|l| timing(l.piece()).is_some());
                cues = cues.saturating_add(1);
                let name = match (at, first) {
                    (Some(1), Some(id)) => id.trim().text(),
                    _ => format!("Cue {cues}"),
                };
                let node = Node::new(name).span(span);
                match at.and_then(|a| cue_summary(&block, a)) {
                    Some(s) => node.summary(s).lazy(cue, Cue { span }),
                    None => node.diag(Diagnostic::malformed("no timing line")),
                }
            }
        };
        lines.progress();
        cx.push(node).await;
    }
    cx.annotate(format!(
        "WebVTT subtitles{}, {}",
        prepared.note(),
        plural(cues, "cue", "cues")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// MicroDVD: `{start frame}{end frame}text|second line`

pub static MICRODVD: Format = Format {
    name: "microdvd",
    title: "MicroDVD subtitles",
    extensions: &["sub"],
    mime: "text/x-microdvd",
    probe: Probe::Custom(|h| {
        let head = probe::head(h);
        let mut lines = probe::significant(&head, &[]).take(5).peekable();
        lines.peek().is_some()
            && lines.all(|l| frames(probe::trim(l)).is_some())
            && probe::is_text(h)
    }),
    dissect: crate::expander!(dissect_microdvd: Input),
};

/// `{a}{b}` at the start: the frame numbers and the rest.
fn frames(line: &[u8]) -> Option<(u64, Option<u64>, usize)> {
    let num = |s: &[u8]| String::from_utf8_lossy(s).parse::<u64>().ok();
    let rest = line.strip_prefix(b"{")?;
    let a_end = rest.iter().position(|&b| b == b'}')?;
    let a = num(rest.get(..a_end)?)?;
    let rest = rest.get(a_end.saturating_add(1)..)?.strip_prefix(b"{")?;
    let b_end = rest.iter().position(|&b| b == b'}')?;
    let b_text = rest.get(..b_end)?;
    let b = if b_text.is_empty() {
        None
    } else {
        Some(num(b_text)?)
    };
    Some((a, b, a_end.saturating_add(b_end).saturating_add(4)))
}

pub async fn dissect_microdvd(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let mut lines = Lines::new(&cx, prepared.span);
    let mut cues = 0u64;
    let mut fps = None;
    while let Some(line) = lines.next().await? {
        let p = line.piece().trim();
        let Some((a, b, used)) = frames(p.bytes()) else {
            continue;
        };
        let text = p.from(used);
        let shown = text.text().replace('|', "\n");
        // `{1}{1}23.976` declares the frame rate.
        if a == 1
            && b == Some(1)
            && cues == 0
            && fps.is_none()
            && let Ok(rate) = text.text().trim().parse::<f64>()
        {
            fps = Some(rate);
            cx.push(
                Node::new("Frame rate")
                    .span(text.span())
                    .value(Value::Float(rate)),
            )
            .await;
            continue;
        }
        cues = cues.saturating_add(1);
        let end = b.map_or_else(|| "?".to_owned(), |b| b.to_string());
        let mut summary = format!("frames {a}–{end}");
        if let Some(rate) = fps.filter(|r| *r > 0.0) {
            #[allow(clippy::cast_precision_loss)]
            let at = a as f64 / rate;
            summary = format!("{summary} ({at:.3} s)");
        }
        lines.progress();
        cx.push(text_node(format!("Cue {cues}"), line.span, &shown).summary(summary))
            .await;
    }
    cx.annotate(format!(
        "MicroDVD subtitles, {}",
        plural(cues, "cue", "cues")
    ));
    Ok(())
}

/// LRC ID tags.
fn lrc_tag(name: &str) -> &str {
    match name {
        "ti" => "Title",
        "ar" => "Artist",
        "al" => "Album",
        "au" => "Author",
        "by" => "Creator",
        "re" => "Editor",
        "ve" => "Version",
        "length" => "Length",
        "offset" => "Offset (ms)",
        _ => name,
    }
}

pub async fn dissect_lrc(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let mut lines = Lines::new(&cx, prepared.span);
    let mut title = None;
    let mut artist = None;
    let mut count = 0u64;
    while let Some(line) = lines.next().await? {
        let mut rest = line.piece().trim();
        if rest.is_empty() {
            continue;
        }
        let mut times = Vec::new();
        while rest.first() == Some(b'[') {
            let Some(end) = rest.find(b']') else {
                break;
            };
            let inner = rest.slice(1, end);
            match clock(&inner.text()) {
                Some(s) => times.push((s, inner)),
                None => {
                    if let Some((k, v)) = inner.split_once(b':') {
                        let key = k.trim().text();
                        let value = v.trim();
                        match key.as_str() {
                            "ti" => title = Some(value.text()),
                            "ar" => artist = Some(value.text()),
                            _ => {}
                        }
                        cx.push(text_node(
                            lrc_tag(&key).to_owned(),
                            value.span(),
                            &value.text(),
                        ))
                        .await;
                    }
                }
            }
            rest = rest.from(end.saturating_add(1));
        }
        if times.is_empty() {
            continue;
        }
        let text = rest.trim();
        lines.progress();
        for (s, stamp) in times {
            count = count.saturating_add(1);
            cx.push(
                text_node(format!("[{}]", stamp.text()), line.span, &text.text())
                    .summary(format!("at {s:.2} s")),
            )
            .await;
        }
    }
    let mut summary = String::from("LRC lyrics");
    match (title, artist) {
        (Some(t), Some(a)) => summary = format!("{summary}: {a} – {t}"),
        (Some(t), None) => summary = format!("{summary}: {t}"),
        _ => {}
    }
    cx.annotate(format!("{summary}, {}", plural(count, "line", "lines")));
    Ok(())
}
