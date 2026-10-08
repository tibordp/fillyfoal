//! Microsoft Keyboard Layout Creator sources (`.klc`).
//!
//! MSKLC saves layouts as UTF-16LE text (with a byte order mark; other
//! tools also write UTF-8 or ANSI) of keyword sections: header keywords with
//! a value on the same line (`KBD`, `COPYRIGHT`, `COMPANY`, `LOCALENAME`,
//! `LOCALEID`, `VERSION`), then table sections whose rows follow on the next
//! lines (`SHIFTSTATE`, `LAYOUT`, `LIGATURE`, `DEADKEY <code>`, `KEYNAME`,
//! `KEYNAME_EXT`, `KEYNAME_DEAD`, `DESCRIPTIONS`, `LANGUAGENAMES`) up to
//! `ENDKBD`. `//` starts a comment, as does `;` on keyword lines.
//!
//! `LAYOUT` rows are: scan code (hex), virtual key (`VK_` name without the
//! prefix), caps flags, then one character per `SHIFTSTATE` column: a
//! single character, a code point in hex (four or more digits), `-1` for
//! none, `%%` for a ligature (see `LIGATURE`), with a trailing `@` for a dead
//! key (see `DEADKEY`).

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::encoding::prepare;
use super::piece::Piece;
use super::scan::Lines;
use super::{probe, text_node};

pub static FORMAT: Format = Format {
    name: "klc",
    title: "Microsoft Keyboard Layout Creator source",
    extensions: &["klc"],
    mime: "text/plain",
    probe: Probe::Custom(|h| {
        let head = probe::head(h);
        let first = probe::lines(&head)
            .map(probe::trim)
            .find(|l| !l.is_empty())
            .unwrap_or_default();
        first.starts_with(b"KBD")
            && first.get(3).is_some_and(|b| *b == b'\t' || *b == b' ')
            && (probe::contains(&head, b"\nSHIFTSTATE")
                || probe::contains(&head, b"\nLOCALEID")
                || probe::contains(&head, b"\nLAYOUT"))
    }),
    dissect: crate::expander!(dissect: Input),
};

/// Keywords that take a value on their own line.
const HEADER: &[&str] = &[
    "KBD",
    "COPYRIGHT",
    "COMPANY",
    "LOCALENAME",
    "LOCALEID",
    "VERSION",
];

/// Keywords that start a table of rows.
const TABLES: &[&str] = &[
    "ATTRIBUTES",
    "SHIFTSTATE",
    "LAYOUT",
    "LIGATURE",
    "DEADKEY",
    "KEYNAME",
    "KEYNAME_EXT",
    "KEYNAME_DEAD",
    "DESCRIPTIONS",
    "LANGUAGENAMES",
];

/// The line without its comment.
fn uncomment<'a>(line: Piece<'a>, semicolon: bool) -> Piece<'a> {
    let mut line = match line.find_seq(b"//") {
        Some(i) => line.to(i),
        None => line,
    };
    if semicolon && let Some(i) = line.find(b';') {
        line = line.to(i);
    }
    line.trim()
}

/// The keyword a line starts with, if it is one.
fn keyword(line: Piece<'_>) -> Option<&'static str> {
    let (word, _) = line.split_word();
    let word = word.bytes();
    HEADER
        .iter()
        .chain(TABLES)
        .chain(&["ENDKBD"])
        .copied()
        .find(|k| k.as_bytes() == word)
}

/// The names of the modifiers in a shift state.
fn shift_state_name(state: u32) -> String {
    let mut parts = Vec::new();
    if state & 1 != 0 {
        parts.push("Shift");
    }
    if state & 2 != 0 {
        parts.push("Ctrl");
    }
    if state & 4 != 0 {
        parts.push("Alt");
    }
    if state & 8 != 0 {
        parts.push("Kana");
    }
    if state & !0xf != 0 {
        parts.push("other");
    }
    if parts.is_empty() {
        "Base".to_owned()
    } else {
        parts.join("+")
    }
}

#[derive(Clone, Debug)]
struct Section {
    span: Span,
    kind: &'static str,
    /// Shift states, for `LAYOUT`.
    states: Vec<u32>,
}

/// The most shift states kept (a layout's columns).
const MAX_STATES: usize = 64;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut name = String::new();
    let mut description = String::new();
    let mut states: Vec<u32> = Vec::new();
    let mut keys = 0u64;
    let mut dead = 0u64;
    // (start of the section, keyword, its value/argument)
    let mut open: Option<(u64, &'static str, String)> = None;
    let mut ended = false;
    // Rows in the open section.
    let mut rows = 0u64;

    loop {
        let line = lines.next().await?;
        let kw = line
            .as_ref()
            .and_then(|l| keyword(uncomment(l.piece(), true)));
        if (kw.is_some() || line.is_none())
            && let Some((start, kind, arg)) = open.take()
        {
            let end = line.as_ref().map_or(lines.pos(), |l| l.start);
            let section = span.sub(start, end.saturating_sub(start));
            let label = if arg.is_empty() {
                kind.to_owned()
            } else {
                format!("{kind} {arg}")
            };
            let mut node = Node::new(label).span(section).lazy(
                expand_section,
                Section {
                    span: section,
                    kind,
                    states: states.clone(),
                },
            );
            if kind == "DEADKEY" {
                node = node.summary(format!("{}, {rows} compositions", code_point_summary(&arg)));
            } else if kind == "LAYOUT" {
                node = node.summary(format!("{rows} rows"));
            } else if kind.starts_with("KEYNAME") {
                node = node.summary(format!("{rows} names"));
            } else if kind == "SHIFTSTATE" {
                let names: Vec<String> = states.iter().map(|&s| shift_state_name(s)).collect();
                node = node.summary(names.join(", "));
            }
            cx.push(node).await;
        }
        let Some(line) = line else {
            break;
        };
        let content = uncomment(line.piece(), true);
        let Some(kw) = kw else {
            if !content.is_empty() {
                rows = rows.saturating_add(1);
            }
            // Real layouts have a handful of shift states; the list is
            // copied into every section, so a bogus file must not grow it.
            if let Some((_, "SHIFTSTATE", _)) = &open
                && states.len() < MAX_STATES
                && let Some(v) = content.words().next().and_then(|w| w.text().parse().ok())
            {
                states.push(v);
            }
            if let Some((_, "LAYOUT", _)) = &open
                && !content.is_empty()
            {
                keys = keys.saturating_add(1);
            }
            continue;
        };
        let (_, rest) = content.split_word();
        if kw == "ENDKBD" {
            cx.push(Node::new("ENDKBD").span(line.span)).await;
            ended = true;
            continue;
        }
        if TABLES.contains(&kw) {
            if kw == "DEADKEY" {
                dead = dead.saturating_add(1);
            }
            open = Some((line.start, kw, rest.text()));
            rows = 0;
            continue;
        }
        // A header keyword and its value(s).
        let mut node = match kw {
            "KBD" => {
                let (id, desc) = rest.split_word();
                name = id.text();
                description = desc.unquote().text();
                text_node("KBD", rest.span(), &name).summary(description.clone())
            }
            "LOCALEID" => {
                let v = rest.unquote();
                let mut node = text_node(kw, v.span(), &v.text());
                if let Some(n) = u32::from_str_radix(&v.text(), 16)
                    .ok()
                    .and_then(crate::formats::util::lcid::name)
                {
                    node = node.summary(n);
                }
                node
            }
            _ => {
                let v = rest.unquote();
                text_node(kw, v.span(), &v.text())
            }
        };
        node.span = Some(line.span);
        cx.push(node).await;
    }

    let mut summary = format!("Keyboard layout {name}");
    if !description.is_empty() {
        summary.push_str(&format!(" ({description})"));
    }
    summary.push_str(&format!(
        ", {keys} keys, {} shift states, {dead} dead keys{}",
        states.len(),
        prepared.note()
    ));
    cx.annotate(summary);
    if !ended {
        cx.diag(crate::error::Diagnostic::malformed(
            "no ENDKBD: the layout is incomplete",
        ));
    }
    Ok(())
}

/// "U+00B4 ´" for a hex code point.
fn code_point_summary(hex: &str) -> String {
    match u32::from_str_radix(hex.trim_end_matches('@'), 16)
        .ok()
        .and_then(char::from_u32)
    {
        Some(c) if !c.is_control() => format!("U+{:04X} {c}", u32::from(c)),
        Some(c) => format!("U+{:04X}", u32::from(c)),
        None => hex.to_owned(),
    }
}

/// A character cell of a `LAYOUT` row: its text and a description.
fn cell(token: &str) -> (Option<String>, String) {
    if token == "-1" {
        return (None, "none".to_owned());
    }
    if token == "%%" {
        return (None, "ligature (see LIGATURE)".to_owned());
    }
    let (body, dead) = match token.strip_suffix('@') {
        Some(b) => (b, true),
        None => (token, false),
    };
    let ch = if body.chars().count() == 1 {
        body.chars().next()
    } else if body.len() >= 4 && body.bytes().all(|b| b.is_ascii_hexdigit()) {
        u32::from_str_radix(body, 16).ok().and_then(char::from_u32)
    } else {
        None
    };
    match ch {
        Some(c) => {
            let mut d = format!("U+{:04X}", u32::from(c));
            if dead {
                d.push_str(", dead key");
            }
            (Some(c.to_string()), d)
        }
        None => (None, format!("unrecognised token {token:?}")),
    }
}

/// How a character shows in a summary.
fn show(c: &str) -> String {
    if c.chars().all(|c| !c.is_control()) {
        c.to_owned()
    } else {
        c.chars()
            .map(|c| format!("U+{:04X}", u32::from(c)))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

const CAPS: &[(u32, &str)] = &[
    (0x01, "CAPLOK"),
    (0x02, "SGCAPS"),
    (0x04, "CAPLOKALTGR"),
    (0x08, "KANALOK"),
    (0x80, "GRPSELTAP"),
];

fn caps_summary(text: &str) -> String {
    if text.eq_ignore_ascii_case("SGCap") {
        return "SGCAPS".to_owned();
    }
    match text.parse::<u32>() {
        Ok(0) => "none".to_owned(),
        Ok(v) => CAPS
            .iter()
            .filter(|(bit, _)| v & bit != 0)
            .map(|(_, n)| *n)
            .collect::<Vec<_>>()
            .join(" | "),
        Err(_) => text.to_owned(),
    }
}

async fn expand_section(cx: Cx, s: Section) -> Result<()> {
    let mut lines = Lines::new(&cx, s.span);
    let mut first = true;
    while let Some(line) = lines.next().await? {
        if first {
            first = false;
            continue;
        }
        let content = uncomment(line.piece(), false);
        if content.is_empty() {
            continue;
        }
        let comment = line
            .piece()
            .find_seq(b"//")
            .map(|i| line.piece().from(i.saturating_add(2)).trim());
        let words: Vec<Piece<'_>> = content.words().collect();
        let node = match s.kind {
            "SHIFTSTATE" => {
                let state = words.first().and_then(|w| w.text().parse::<u32>().ok());
                let mut node = text_node("Shift state", content.span(), &content.text());
                if let Some(st) = state {
                    node = Node::new(format!("Shift state {st}"))
                        .span(content.span())
                        .value(crate::formats::util::lines::uint(st.into()))
                        .summary(shift_state_name(st));
                }
                node
            }
            "LAYOUT" => layout_row(&words, &s.states, &content, comment),
            "LIGATURE" => {
                let vk = words.first().map(Piece::text).unwrap_or_default();
                let column = words.get(1).map(Piece::text).unwrap_or_default();
                let chars: Vec<String> = words
                    .iter()
                    .skip(2)
                    .filter_map(|w| cell(&w.text()).0)
                    .collect();
                Node::new(format!("VK_{vk} column {column}"))
                    .span(content.span())
                    .value(Value::Text(chars.concat()))
            }
            "DEADKEY" => {
                let base = words.first().map(Piece::text).unwrap_or_default();
                let out = words.get(1).map(Piece::text).unwrap_or_default();
                let shown = |h: &str| {
                    u32::from_str_radix(h, 16)
                        .ok()
                        .and_then(char::from_u32)
                        .map_or_else(|| h.to_owned(), |c| show(&c.to_string()))
                };
                Node::new(format!("{} → {}", shown(&base), shown(&out)))
                    .span(content.span())
                    .summary(format!(
                        "{} + dead key → {}",
                        code_point_summary(&base),
                        code_point_summary(&out)
                    ))
            }
            _ => {
                // KEYNAME*, DESCRIPTIONS, LANGUAGENAMES: a key and a text.
                let (key, value) = content.split_word();
                let mut node = if value.is_empty() {
                    Node::new(key.text())
                } else {
                    text_node(key.text(), value.span(), &value.unquote().text())
                };
                node.span = Some(content.span());
                if s.kind == "DESCRIPTIONS" || s.kind == "LANGUAGENAMES" {
                    if let Some(n) = u32::from_str_radix(&key.text(), 16)
                        .ok()
                        .and_then(crate::formats::util::lcid::name)
                    {
                        node = node.summary(n);
                    }
                } else if s.kind == "KEYNAME_DEAD" {
                    node = node.summary(code_point_summary(&key.text()));
                }
                node
            }
        };
        cx.push(node).await;
    }
    Ok(())
}

fn layout_row(
    words: &[Piece<'_>],
    states: &[u32],
    content: &Piece<'_>,
    comment: Option<Piece<'_>>,
) -> Node {
    let sc = words.first().map(Piece::text).unwrap_or_default();
    let vk = words.get(1).map(Piece::text).unwrap_or_default();
    let mut shown = Vec::new();
    for (i, w) in words.iter().skip(3).enumerate() {
        let text = w.text();
        if let (Some(c), _) = cell(&text) {
            let state = states
                .get(i)
                .copied()
                .map_or_else(|| format!("[{i}]"), shift_state_name);
            let dead = if text.ends_with('@') { " (dead)" } else { "" };
            shown.push(format!("{state}: {}{dead}", show(&c)));
        }
    }
    let label = if sc == "-1" {
        "SGCAPS second row".to_owned()
    } else {
        format!("{sc} VK_{vk}")
    };
    let mut node = Node::new(label)
        .span(content.span())
        .summary(shown.join(", "))
        .lazy(
            expand_row,
            Row {
                span: content.span(),
                states: states.to_vec(),
            },
        );
    if let Some(c) = comment.filter(|c| !c.is_empty()) {
        node = node.desc(c.text());
    }
    node
}

#[derive(Clone, Debug)]
struct Row {
    span: Span,
    states: Vec<u32>,
}

async fn expand_row(cx: Cx, row: Row) -> Result<()> {
    let data = cx.read_avail(row.span).await?;
    let piece = Piece::new(&data, row.span);
    let words: Vec<Piece<'_>> = piece.words().collect();
    if let Some(sc) = words.first() {
        let mut node = text_node("Scan code", sc.span(), &sc.text());
        if let Ok(v) = u32::from_str_radix(&sc.text(), 16) {
            node = Node::new("Scan code")
                .span(sc.span())
                .value(crate::formats::util::lines::hex(v.into(), 8));
        }
        cx.emit(node);
    }
    if let Some(vk) = words.get(1) {
        cx.emit(text_node(
            "Virtual key",
            vk.span(),
            &format!("VK_{}", vk.text()),
        ));
    }
    if let Some(caps) = words.get(2) {
        cx.emit(text_node("Caps", caps.span(), &caps.text()).summary(caps_summary(&caps.text())));
    }
    for (i, w) in words.iter().skip(3).enumerate() {
        let label = match row.states.get(i) {
            Some(&st) => format!("Shift state {st} ({})", shift_state_name(st)),
            None => format!("Column {i}"),
        };
        let (c, desc) = cell(&w.text());
        let mut node = Node::new(label).span(w.span()).summary(desc);
        if let Some(c) = c {
            node = node.value(Value::Text(c));
        }
        cx.emit(node);
    }
    Ok(())
}
