//! INI-style configuration and its relatives: XDG `.desktop` entries,
//! Windows `.reg` exports, `.url` Internet shortcuts, systemd units, Windows
//! `.inf` setup files and ASS/SSA subtitles.
//!
//! Entries before the first section are top-level nodes; each `[section]`
//! is a lazy node (found by scanning lines) whose entries are `key = value`
//! nodes with spans for the value. `.reg` values are decoded by type
//! (`dword:`, `hex(2):` ...), and ASS events are split into their fields.

use std::sync::Arc;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

use super::decode::preview;
use super::encoding::prepare;
use super::piece::Piece;
use super::scan::{LineBuf, Lines};
use super::{plural, probe, text_node};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flavor {
    Ini,
    Desktop,
    Reg,
    Url,
    Systemd,
    Inf,
    EditorConfig,
    Ass,
}

macro_rules! ini_format {
    ($id:ident, $f:ident, $flavor:expr, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $probe:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom($probe),
            dissect: crate::expander!($f: Input),
        };
        async fn $f(cx: Cx, input: Input) -> Result<()> {
            dissect(cx, input, $flavor).await
        }
    };
}

ini_format!(
    FORMAT,
    dissect_ini,
    Flavor::Ini,
    "ini",
    "INI configuration",
    ["ini", "cfg", "conf", "cnf", "properties", "lnk2"],
    "text/plain",
    probe_ini
);
ini_format!(
    DESKTOP,
    dissect_desktop,
    Flavor::Desktop,
    "desktop",
    "Desktop entry",
    ["desktop", "directory"],
    "application/x-desktop",
    |h| first_section(h).is_some_and(|s| s == b"Desktop Entry")
);
ini_format!(
    REG,
    dissect_reg,
    Flavor::Reg,
    "reg",
    "Windows Registry export",
    ["reg"],
    "text/x-ms-regedit",
    |h| {
        let head = probe::head(h);
        let head = probe::trim_start(&head);
        head.starts_with(b"Windows Registry Editor Version") || head.starts_with(b"REGEDIT4")
    }
);
ini_format!(
    URL,
    dissect_url,
    Flavor::Url,
    "url",
    "Internet shortcut",
    ["url", "website"],
    "application/x-mswinurl",
    |h| first_section(h).is_some_and(|s| s == b"InternetShortcut" || s == b"DEFAULT")
        && probe::contains(&probe::head(h), b"[InternetShortcut]")
);
ini_format!(
    SYSTEMD,
    dissect_systemd,
    Flavor::Systemd,
    "systemd-unit",
    "systemd unit",
    [
        "service",
        "socket",
        "timer",
        "mount",
        "automount",
        "path",
        "slice",
        "target",
        "network",
        "netdev",
        "link"
    ],
    "text/plain",
    |h| first_section(h).is_some_and(|s| SYSTEMD_SECTIONS.contains(&s.as_slice()))
);
ini_format!(
    INF,
    dissect_inf,
    Flavor::Inf,
    "inf",
    "Windows setup information",
    ["inf"],
    "application/x-setupscript",
    |h| {
        let head = probe::head(h).to_ascii_lowercase();
        first_section(h).is_some()
            && probe::contains(&head, b"[version]")
            && probe::contains(&head, b"signature")
            && (probe::contains(&head, b"$windows nt$") || probe::contains(&head, b"$chicago$"))
    }
);
ini_format!(
    EDITORCONFIG,
    dissect_editorconfig,
    Flavor::EditorConfig,
    "editorconfig",
    "EditorConfig",
    ["editorconfig"],
    "text/plain",
    |h| {
        let head = probe::head(h);
        let keys: [&[u8]; 6] = [
            b"indent_style",
            b"indent_size",
            b"end_of_line",
            b"charset",
            b"trim_trailing_whitespace",
            b"insert_final_newline",
        ];
        let first = probe::significant(&head, &[b";", b"#"])
            .next()
            .map(probe::trim);
        let glob = first_section(h).is_some_and(|s| s.contains(&b'*'));
        let root = first.is_some_and(|l| l.starts_with(b"root"));
        (glob || root) && keys.iter().any(|k| probe::contains(&head, k)) && probe::is_text(h)
    }
);
ini_format!(
    ASS,
    dissect_ass,
    Flavor::Ass,
    "ass",
    "SubStation Alpha subtitles",
    ["ass", "ssa"],
    "text/x-ssa",
    |h| first_section(h).is_some_and(|s| s == b"Script Info")
);

const SYSTEMD_SECTIONS: &[&[u8]] = &[
    b"Unit",
    b"Service",
    b"Socket",
    b"Timer",
    b"Mount",
    b"Automount",
    b"Path",
    b"Slice",
    b"Install",
    b"Swap",
    b"Match",
    b"Network",
    b"NetDev",
    b"Link",
];

/// The name of the first `[section]`, if the first significant line is one.
fn first_section(h: &Head<'_>) -> Option<Vec<u8>> {
    let head = probe::head(h);
    let line = probe::significant(&head, &[b";", b"#"]).next()?;
    let line = probe::trim(line);
    let name = line.strip_prefix(b"[")?.strip_suffix(b"]")?;
    (!name.is_empty() && !name.contains(&b'[') && name.len() < 128).then(|| name.to_vec())
}

/// Plain INI: a section first, and key/value lines (no TOML-only syntax).
fn probe_ini(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut lines = probe::significant(&head, &[b";", b"#"]);
    let starts_with_section = first_section(h).is_some();
    let mut entries = 0usize;
    let mut sections = 0usize;
    for line in lines.by_ref().take(40) {
        let line = probe::trim(line);
        if line.starts_with(b"[") && line.ends_with(b"]") {
            sections = sections.saturating_add(1);
        } else if let Some(eq) = line.iter().position(|&b| b == b'=' || b == b':') {
            let key = probe::trim(line.get(..eq).unwrap_or_default());
            if key.is_empty() || key.len() > 128 {
                return false;
            }
            entries = entries.saturating_add(1);
        } else if line.len() > 256 {
            return false;
        }
    }
    starts_with_section && sections >= 1 && entries >= 1 && probe::is_text(h)
}

// ---------------------------------------------------------------------------
// Dissection

/// A `[section]` header line, if `line` is one.
fn section_name<'a>(line: &Piece<'a>) -> Option<Piece<'a>> {
    let t = line.trim();
    let inner = t.strip_prefix(b"[")?;
    let end = inner.rfind(b']')?;
    Some(inner.to(end).trim())
}

fn is_comment(line: &Piece<'_>, flavor: Flavor) -> bool {
    let t = line.trim_start();
    match t.first() {
        Some(b';') => true,
        Some(b'#') => flavor != Flavor::Reg,
        Some(b'!') => flavor == Flavor::Ass,
        _ => false,
    }
}

/// Reads one logical line: `.reg` values continue on the next line after a
/// trailing backslash.
async fn logical(lines: &mut Lines<'_>, flavor: Flavor) -> Result<Option<(LineBuf, Span)>> {
    let Some(first) = lines.next().await? else {
        return Ok(None);
    };
    let mut full = first.span;
    if flavor == Flavor::Reg {
        let mut last = first.piece().trim_end().last();
        while last == Some(b'\\') {
            let Some(more) = lines.next().await? else {
                break;
            };
            full = Span::new(
                full.source,
                full.offset,
                more.span.end().saturating_sub(full.offset),
            );
            last = more.piece().trim_end().last();
        }
    }
    Ok(Some((first, full)))
}

#[derive(Clone)]
struct Section {
    /// From the header line (or the start) to the next header.
    span: Span,
    flavor: Flavor,
    /// Lines to skip (the header).
    skip_header: bool,
    reg_version: u8,
}

pub async fn dissect(cx: Cx, input: Input, flavor: Flavor) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let head = cx.read_avail(span.sub(0, 16 * 1024)).await?;
    cx.annotate(annotation(flavor, &head));
    let mut lines = Lines::new(&cx, span);
    let mut reg_version = 5u8;
    if flavor == Flavor::Reg
        && let Some(first) = lines.next().await?
    {
        let p = first.piece();
        if p.trim().starts_with(b"REGEDIT4") {
            reg_version = 4;
        }
        cx.emit(text_node("Header", first.span, &p.trim().text()));
    }
    // Entries before the first section come first, then the sections.
    let global_start = lines.pos();
    let mut current: Option<(u64, String, u64)> = None; // (start, name, entries)
    let mut globals = 0u64;
    loop {
        let before = lines.pos();
        let next = logical(&mut lines, flavor).await?;
        let header = next
            .as_ref()
            .and_then(|(line, _)| section_name(&line.piece()).map(|n| n.text()));
        if next.is_none() || header.is_some() {
            match current.take() {
                Some((start, name, n)) => {
                    let section = span.sub(start, before.saturating_sub(start));
                    lines.progress();
                    push_section(&cx, section, &name, n, flavor, reg_version).await;
                }
                None if globals > 0 => {
                    let section = span.sub(global_start, before.saturating_sub(global_start));
                    let state = Section {
                        span: section,
                        flavor,
                        skip_header: false,
                        reg_version,
                    };
                    entries(cx.clone(), state).await?;
                }
                None => {}
            }
            match header {
                Some(name) => current = Some((before, name, 0)),
                None => break,
            }
            continue;
        }
        let Some((line, _)) = next else { break };
        let p = line.piece();
        if p.trim().is_empty() || is_comment(&p, flavor) {
            continue;
        }
        match current.as_mut() {
            Some((_, _, n)) => *n = n.saturating_add(1),
            None => globals = globals.saturating_add(1),
        }
    }
    Ok(())
}

async fn push_section(
    cx: &Cx,
    span: Span,
    name: &str,
    entries: u64,
    flavor: Flavor,
    reg_version: u8,
) {
    let mut node = Node::new(format!("[{name}]"))
        .span(span)
        .summary(plural(entries, "entry", "entries"));
    if flavor == Flavor::Reg && name.starts_with('-') {
        node = node.summary("key deleted");
    }
    let state = Section {
        span,
        flavor,
        skip_header: true,
        reg_version,
    };
    node = if entries > 0 {
        node.lazy(self::entries, state)
    } else {
        node
    };
    cx.push(node).await;
}
/// The entries of a section.
async fn entries(cx: Cx, s: Section) -> Result<()> {
    let mut lines = Lines::new(&cx, s.span);
    if s.skip_header {
        lines.next().await?;
    }
    let mut format: Option<Arc<Vec<String>>> = None;
    while let Some((line, full)) = logical(&mut lines, s.flavor).await? {
        let p = line.piece();
        if p.trim().is_empty() || is_comment(&p, s.flavor) {
            continue;
        }
        let sep = match s.flavor {
            Flavor::Ass => p.find(b':'),
            Flavor::Ini => p.find_by(|b| b == b'=' || b == b':'),
            // `.reg` names are quoted and may contain '='.
            Flavor::Reg => reg_separator(&p),
            _ => p.find(b'='),
        };
        let Some(sep) = sep else {
            cx.push(
                text_node("Line", line.span, &p.trim().text())
                    .diag(Diagnostic::warning("not a key/value entry")),
            )
            .await;
            continue;
        };
        let key = p.to(sep).trim();
        let value = p.from(sep.saturating_add(1)).trim();
        let node = match s.flavor {
            Flavor::Reg => {
                let full_value = Span::new(
                    full.source,
                    value.span().offset,
                    full.end().saturating_sub(value.span().offset),
                );
                reg_value(&cx, key, full_value, s.reg_version).await?
            }
            Flavor::Ass => {
                let name = key.text();
                if name == "Format" {
                    format = Some(Arc::new(
                        value.split(b',').map(|f| f.trim().text()).collect(),
                    ));
                    text_node(name, value.span(), &value.text())
                } else if let Some(fields) = &format
                    && value.contains(b",")
                {
                    ass_event(&name, value, Arc::clone(fields))
                } else {
                    text_node(name, value.span(), &value.text())
                }
            }
            _ => {
                let text = value.unquote().text();
                let node = text_node(key.text(), value.span(), &text);
                // URLs (Internet shortcuts, desktop entries): readable form.
                match text
                    .contains("://")
                    .then(|| crate::text::url::display_url(&text))
                    .flatten()
                {
                    Some(shown) => node.summary(shown),
                    None => node,
                }
            }
        };
        lines.progress();
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ASS / SSA events

fn ass_event(name: &str, value: Piece<'_>, format: Arc<Vec<String>>) -> Node {
    let parts = split_fields(value, format.len());
    let field = |n: &str| {
        format
            .iter()
            .position(|f| f.eq_ignore_ascii_case(n))
            .and_then(|i| parts.get(i))
            .map(|p| p.text())
    };
    let summary = match (field("Start"), field("End"), field("Text")) {
        (Some(a), Some(b), Some(t)) => format!("{a} → {b}: {}", preview(&t, 60)),
        _ => preview(&value.text(), 80),
    };
    Node::new(name.to_owned())
        .span(value.span())
        .summary(summary)
        .lazy(ass_fields, (value.span(), format))
}

/// Splits `value` at commas into `n` fields, the last taking the rest.
fn split_fields(value: Piece<'_>, n: usize) -> Vec<Piece<'_>> {
    let mut out = Vec::new();
    let mut rest = value;
    while out.len().saturating_add(1) < n {
        let Some((a, b)) = rest.split_once(b',') else {
            break;
        };
        out.push(a.trim());
        rest = b;
    }
    out.push(rest.trim());
    out
}

async fn ass_fields(cx: Cx, (span, format): (Span, Arc<Vec<String>>)) -> Result<()> {
    let owned = super::scan::Scanner::new(&cx, span)
        .owned(0, span.len, super::scan::LINE_CAP)
        .await?;
    for (i, part) in split_fields(owned.piece(), format.len())
        .into_iter()
        .enumerate()
    {
        let name = format
            .get(i)
            .cloned()
            .unwrap_or_else(|| format!("Field {}", i.saturating_add(1)));
        cx.emit(match super::number(&part.text()) {
            Some(v) if name != "Text" => Node::new(name).span(part.span()).value(v),
            _ => text_node(name, part.span(), &part.text()),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows Registry values

/// The `=` after a quoted value name (or `@`).
fn reg_separator(p: &Piece<'_>) -> Option<usize> {
    let t = p.bytes();
    if t.first() == Some(&b'"') {
        let mut i = 1usize;
        while let Some(&b) = t.get(i) {
            match b {
                b'\\' => i = i.saturating_add(2),
                b'"' => {
                    let rest = t.get(i.saturating_add(1)..)?;
                    let eq = rest.iter().position(|&c| c == b'=')?;
                    return Some(i.saturating_add(1).saturating_add(eq));
                }
                _ => i = i.saturating_add(1),
            }
        }
        None
    } else {
        p.find(b'=')
    }
}

fn reg_unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            out.extend(chars.next());
        } else {
            out.push(c);
        }
    }
    out
}

async fn reg_value(cx: &Cx, key: Piece<'_>, value: Span, version: u8) -> Result<Node> {
    let name = if key.bytes() == b"@" {
        "(Default)".to_owned()
    } else {
        reg_unescape(&key.unquote().text())
    };
    let owned = super::scan::Scanner::new(cx, value)
        .owned(0, value.len, 1 << 20)
        .await?;
    let v = owned.piece().trim();
    let node = Node::new(name).span(value);
    if v.bytes() == b"-" {
        return Ok(node.summary("value deleted"));
    }
    if v.first() == Some(b'"') {
        return Ok(
            text_node(node.name, value, &reg_unescape(&v.unquote().text())).summary("REG_SZ"),
        );
    }
    if let Some(hex) = v.strip_prefix(b"dword:") {
        let parsed = u32::from_str_radix(hex.trim().text().as_str(), 16);
        return Ok(match parsed {
            Ok(n) => node
                .value(Value::UInt {
                    value: n.into(),
                    bits: 32,
                    radix: Radix::Hex,
                })
                .summary(format!("REG_DWORD ({n})")),
            Err(_) => node.diag(Diagnostic::malformed("invalid dword")),
        });
    }
    let (kind, data) = if let Some(rest) = v.strip_prefix(b"hex:") {
        (3u32, rest)
    } else if let Some(rest) = v.strip_prefix(b"hex(") {
        let Some((t, data)) = rest.split_once(b')') else {
            return Ok(node.diag(Diagnostic::malformed("invalid hex value")));
        };
        let kind = u32::from_str_radix(t.text().as_str(), 16).unwrap_or(u32::MAX);
        (kind, data.strip_prefix(b":").unwrap_or(data))
    } else {
        return Ok(text_node(node.name, value, &v.text())
            .diag(Diagnostic::warning("unrecognised value syntax")));
    };
    let decoded = super::decode::hex(data.bytes());
    let bytes = decoded.bytes;
    let type_name = match kind {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        0xb => "REG_QWORD",
        _ => "unknown type",
    };
    let wide = version == 5;
    let text = |b: &[u8]| {
        if wide {
            crate::text::utf16(b, crate::fields::Endian::Little)
        } else {
            super::encoding::decode_8bit(b)
        }
    };
    let mut node = match kind {
        1 | 2 | 6 => {
            let s = text(&bytes);
            text_node(node.name, value, s.trim_end_matches('\0'))
        }
        7 => {
            let s = text(&bytes);
            let items: Vec<&str> = s.split('\0').filter(|x| !x.is_empty()).collect();
            text_node(node.name, value, &items.join("\n")).summary(format!(
                "{type_name}, {}",
                plural(crate::bytes::to_u64(items.len()), "string", "strings")
            ))
        }
        4 | 5 | 0xb if matches!(bytes.len(), 4 | 8) => {
            let n = match (kind, bytes.as_slice()) {
                (5, b) => crate::bytes::u32_be(b, 0).map(u64::from),
                (_, b) if b.len() == 8 => crate::bytes::u64_le(b, 0),
                (_, b) => crate::bytes::u32_le(b, 0).map(u64::from),
            }
            .unwrap_or(0);
            node.value(Value::UInt {
                value: n,
                bits: if bytes.len() == 8 { 64 } else { 32 },
                radix: Radix::Hex,
            })
        }
        _ => node.value(Value::Bytes(
            bytes
                .get(..bytes.len().min(super::VALUE_CAP))
                .unwrap_or_default()
                .to_vec(),
        )),
    };
    if node.summary.is_none() {
        node = node.summary(type_name);
    }
    if let Some(e) = decoded.error {
        node = node.diag(Diagnostic::malformed(e));
    }
    Ok(node)
}

// ---------------------------------------------------------------------------
// Annotations

/// The value of `key=` in the head (first occurrence at a line start).
fn scrape(head: &[u8], key: &[u8]) -> Option<String> {
    probe::lines(head).find_map(|l| {
        let l = probe::trim(l);
        let rest = l.strip_prefix(key)?;
        let rest = probe::trim_start(rest).strip_prefix(b"=")?;
        Some(super::encoding::decode_8bit(probe::trim(rest)))
    })
}

fn annotation(flavor: Flavor, head: &[u8]) -> String {
    let text = super::encoding::probe_text(head);
    let get = |k: &[u8]| scrape(&text, k);
    let (title, detail) = match flavor {
        Flavor::Ini => ("INI configuration", None),
        Flavor::Desktop => {
            let name = get(b"Name");
            let kind = get(b"Type");
            let detail = match (name, kind) {
                (Some(n), Some(t)) => Some(format!("{n} ({t})")),
                (n, t) => n.or(t),
            };
            ("Desktop entry", detail)
        }
        Flavor::Reg => ("Windows Registry export", None),
        Flavor::EditorConfig => ("EditorConfig", get(b"root").map(|r| format!("root = {r}"))),
        Flavor::Url => ("Internet shortcut", get(b"URL")),
        Flavor::Systemd => ("systemd unit", get(b"Description")),
        Flavor::Inf => (
            "Windows setup information",
            get(b"Class").or_else(|| get(b"Provider")),
        ),
        Flavor::Ass => {
            let title = probe::lines(&text).find_map(|l| {
                let rest = probe::trim(l).strip_prefix(b"Title:")?;
                Some(super::encoding::decode_8bit(probe::trim(rest)))
            });
            ("SubStation Alpha subtitles", title)
        }
    };
    match detail {
        Some(d) if !d.is_empty() => format!("{title}: {}", preview(&d, 80)),
        _ => title.to_owned(),
    }
}
