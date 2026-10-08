//! Text formats from the emulation scene: ROM-management DATs (clrmamepro
//! and Logiqx XML, MAME software lists), cdrdao TOC files and RetroArch
//! cheat files.

use super::util::{dec, is_ascii_text, lines, size, text};
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

/// Reads a text input (up to 4 MiB) for line- or token-based parsing.
async fn read_text(cx: &Cx, file: Span) -> Result<(Vec<u8>, bool)> {
    let limit = (4u64 << 20).min(cx.limits().max_read);
    let data = cx.read(file.sub(0, file.len.min(limit))).await?;
    Ok((data, file.len > limit))
}

fn head_text<'a>(h: &Head<'a>, n: usize) -> &'a [u8] {
    let d = h.data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(h.data);
    d.get(..d.len().min(n)).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// clrmamepro DAT

fn cmp_probe(h: &Head<'_>) -> bool {
    let t = head_text(h, 2048);
    let s = String::from_utf8_lossy(t);
    is_ascii_text(t.get(..t.len().min(256)).unwrap_or_default()) && {
        let trimmed = s.trim_start();
        trimmed.starts_with("clrmamepro (")
            || trimmed.starts_with("clrmamepro(")
            || trimmed.starts_with("emulator (")
    }
}

declare_format!(pub CLRMAMEPRO = "clrmamepro-dat", "clrmamepro ROM DAT", ["dat"],
    "text/x-clrmamepro", Probe::Custom(cmp_probe), clrmamepro);

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Word(String),
    Open,
    Close,
}

/// Splits clrmamepro syntax into words, quoted strings and parentheses,
/// each with its byte range.
async fn tokenize(cx: &Cx, data: &[u8]) -> Vec<(Token, usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut steps = 0u32;
    while let Some(&b) = data.get(i) {
        steps = steps.wrapping_add(1);
        if steps & 0xfff == 0 {
            cx.checkpoint().await;
        }
        match b {
            b'(' => {
                out.push((Token::Open, i, i.saturating_add(1)));
                i = i.saturating_add(1);
            }
            b')' => {
                out.push((Token::Close, i, i.saturating_add(1)));
                i = i.saturating_add(1);
            }
            b'"' => {
                let start = i;
                let body = i.saturating_add(1);
                let end = data
                    .get(body..)
                    .and_then(|r| r.iter().position(|&c| c == b'"'))
                    .map_or(data.len(), |p| body.saturating_add(p));
                out.push((
                    Token::Word(
                        String::from_utf8_lossy(data.get(body..end).unwrap_or_default())
                            .into_owned(),
                    ),
                    start,
                    end.saturating_add(1),
                ));
                i = end.saturating_add(1);
            }
            _ if b.is_ascii_whitespace() => i = i.saturating_add(1),
            _ => {
                let start = i;
                while data
                    .get(i)
                    .is_some_and(|&c| !c.is_ascii_whitespace() && c != b'(' && c != b')')
                {
                    i = i.saturating_add(1);
                }
                out.push((
                    Token::Word(
                        String::from_utf8_lossy(data.get(start..i).unwrap_or_default())
                            .into_owned(),
                    ),
                    start,
                    i,
                ));
            }
        }
    }
    out
}

/// One top-level `name ( key value ... )` block.
#[derive(Clone, Debug)]
struct Block {
    kind: String,
    span: (usize, usize),
    fields: Vec<(String, String)>,
    children: Vec<(String, Vec<(String, String)>)>,
}

async fn blocks(cx: &Cx, tokens: &[(Token, usize, usize)]) -> Vec<Block> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut steps = 0u32;
    while let Some((tok, start, _)) = tokens.get(i) {
        steps = steps.wrapping_add(1);
        if steps & 0xff == 0 {
            cx.checkpoint().await;
        }
        let Token::Word(kind) = tok else {
            i = i.saturating_add(1);
            continue;
        };
        if tokens.get(i.saturating_add(1)).map(|t| &t.0) != Some(&Token::Open) {
            i = i.saturating_add(1);
            continue;
        }
        let mut block = Block {
            kind: kind.clone(),
            span: (*start, *start),
            fields: Vec::new(),
            children: Vec::new(),
        };
        let mut j = i.saturating_add(2);
        while let Some((t, _, end)) = tokens.get(j) {
            match t {
                Token::Close => {
                    block.span.1 = *end;
                    j = j.saturating_add(1);
                    break;
                }
                Token::Word(key) => {
                    match tokens.get(j.saturating_add(1)).map(|t| &t.0) {
                        Some(Token::Open) => {
                            // Nested block: collect key/value pairs until ')'.
                            let mut k = j.saturating_add(2);
                            let mut pairs = Vec::new();
                            while let Some((Token::Word(a), _, _)) = tokens.get(k) {
                                let v = match tokens.get(k.saturating_add(1)) {
                                    Some((Token::Word(v), _, _)) => v.clone(),
                                    _ => String::new(),
                                };
                                pairs.push((a.clone(), v));
                                k = k.saturating_add(2);
                            }
                            block.children.push((key.clone(), pairs));
                            j = k.saturating_add(1);
                        }
                        Some(Token::Word(v)) => {
                            block.fields.push((key.clone(), v.clone()));
                            j = j.saturating_add(2);
                        }
                        _ => j = j.saturating_add(1),
                    }
                }
                Token::Open => j = j.saturating_add(1),
            }
        }
        if block.span.1 == block.span.0 {
            block.span.1 = tokens.last().map_or(block.span.0, |t| t.2);
        }
        out.push(block);
        i = j.max(i.saturating_add(1));
    }
    out
}

fn get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs.iter().find(|p| p.0 == key).map(|p| p.1.as_str())
}

async fn clrmamepro(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (data, cut) = read_text(&cx, file).await?;
    let tokens = tokenize(&cx, &data).await;
    let all = blocks(&cx, &tokens).await;
    let mut header = String::new();
    let mut games = Vec::new();
    let mut roms = 0usize;
    for b in all {
        let span = file.sub(to_u64(b.span.0), to_u64(b.span.1.saturating_sub(b.span.0)));
        if b.kind == "clrmamepro" || b.kind == "emulator" {
            header = get(&b.fields, "description")
                .or_else(|| get(&b.fields, "name"))
                .unwrap_or_default()
                .to_owned();
            let version = get(&b.fields, "version").unwrap_or_default().to_owned();
            cx.emit(
                Node::new(b.kind.clone())
                    .span(span)
                    .value(text(header.clone()))
                    .summary(format!("version {version}"))
                    .lazy(dat_pairs, b.fields.clone()),
            );
        } else {
            roms = roms.saturating_add(
                b.children
                    .iter()
                    .filter(|c| c.0 == "rom" || c.0 == "disk")
                    .count(),
            );
            games.push((b, span));
        }
    }
    let count = games.len();
    cx.emit(
        Node::new("Entries")
            .summary(format!("{count} games, {roms} ROMs"))
            .lazy(dat_games, games),
    );
    if cut {
        cx.diag(Diagnostic::limit("only the first 4 MiB were parsed"));
    }
    cx.annotate(format!(
        "clrmamepro DAT {header:?}, {count} games, {roms} ROMs"
    ));
    Ok(())
}

async fn dat_pairs(cx: Cx, pairs: Vec<(String, String)>) -> Result<()> {
    for (k, v) in pairs {
        cx.push(Node::new(k).value(text(v))).await;
    }
    Ok(())
}

async fn dat_games(cx: Cx, games: Vec<(Block, Span)>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(games.len())));
    for (b, span) in games {
        let name = get(&b.fields, "name").unwrap_or("?").to_owned();
        let desc = get(&b.fields, "description").unwrap_or_default().to_owned();
        let roms: Vec<(String, String)> = b
            .children
            .iter()
            .map(|(k, pairs)| {
                let size_crc = format!(
                    "{} bytes, CRC {}",
                    get(pairs, "size").unwrap_or("?"),
                    get(pairs, "crc").unwrap_or("?")
                );
                (
                    format!("{k} {}", get(pairs, "name").unwrap_or("?")),
                    size_crc,
                )
            })
            .collect();
        cx.push(
            Node::new(format!("{} {name}", b.kind))
                .span(span)
                .value(text(desc))
                .summary(format!("{} ROMs", roms.len()))
                .lazy(dat_pairs, roms),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Logiqx XML DAT and MAME software lists

fn xml_dat_kind(h: &Head<'_>) -> Option<&'static str> {
    let t = String::from_utf8_lossy(head_text(h, 4096));
    if !t.trim_start().starts_with('<') {
        return None;
    }
    if t.contains("<datafile") && (t.contains("Logiqx") || t.contains("<header>")) {
        Some("logiqx")
    } else if t.contains("<softwarelist") {
        Some("softlist")
    } else {
        None
    }
}

declare_format!(pub LOGIQX = "logiqx-dat", "Logiqx XML ROM DAT", ["dat", "xml"],
    "application/x-logiqx-dat", Probe::Custom(|h| xml_dat_kind(h) == Some("logiqx")), xml_dat);
declare_format!(pub SOFTLIST = "mame-softlist", "MAME software list", ["xml"],
    "application/x-mame-softlist", Probe::Custom(|h| xml_dat_kind(h) == Some("softlist")), xml_dat);

fn attr(tag: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let at = tag.find(&needle)?.saturating_add(needle.len());
    let rest = tag.get(at..)?;
    let end = rest.find('"')?;
    Some(unescape(rest.get(..end)?))
}

fn unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn element(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let at = body.find(&open)?.saturating_add(open.len());
    let end = body.get(at..)?.find(&close)?;
    Some(unescape(body.get(at..at.saturating_add(end))?.trim()))
}

/// An entry of an XML DAT: name, description, extra, ROM count, byte range.
type XmlEntry = (String, String, String, usize, usize, usize);

async fn xml_dat(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (data, cut) = read_text(&cx, file).await?;
    let s = String::from_utf8_lossy(&data).into_owned();
    let softlist = s.contains("<softwarelist");
    let (list_name, list_desc) = if softlist {
        let at = s.find("<softwarelist").unwrap_or(0);
        let tag = s
            .get(at..)
            .and_then(|r| r.find('>').map(|e| r.get(..e).unwrap_or_default()))
            .unwrap_or_default();
        (
            attr(tag, "name").unwrap_or_default(),
            attr(tag, "description").unwrap_or_default(),
        )
    } else {
        let header = s
            .find("<header>")
            .and_then(|a| s.get(a..))
            .and_then(|r| r.find("</header>").map(|e| r.get(..e).unwrap_or_default()))
            .unwrap_or_default();
        if let Some(a) = s.find("<header>") {
            let end = s
                .get(a..)
                .and_then(|r| r.find("</header>"))
                .map_or(a, |e| a.saturating_add(e).saturating_add(9));
            let fields: Vec<(String, String)> = [
                "name",
                "description",
                "version",
                "date",
                "author",
                "homepage",
                "url",
            ]
            .iter()
            .filter_map(|k| element(header, k).map(|v| ((*k).to_owned(), v)))
            .collect();
            cx.emit(
                Node::new("Header")
                    .span(file.sub(to_u64(a), to_u64(end.saturating_sub(a))))
                    .lazy(dat_pairs, fields),
            );
        }
        (
            element(header, "name").unwrap_or_default(),
            element(header, "description").unwrap_or_default(),
        )
    };
    let tags: &[&str] = if softlist {
        &["software"]
    } else {
        &["game", "machine"]
    };
    let mut entries: Vec<XmlEntry> = Vec::new();
    let mut roms = 0usize;
    let mut pos = 0usize;
    // The next occurrence of each tag at or after `pos` (`None`: no more),
    // kept between entries so a tag the file does not use is searched for
    // once, not once per entry.
    let mut next: Vec<Option<usize>> = tags.iter().map(|t| s.find(&format!("<{t} "))).collect();
    loop {
        if entries.len() & 0xff == 0xff {
            cx.checkpoint().await;
        }
        for (t, n) in tags.iter().zip(next.iter_mut()) {
            if n.is_some_and(|p| p < pos) {
                *n = s
                    .get(pos..)
                    .and_then(|r| r.find(&format!("<{t} ")).map(|p| pos.saturating_add(p)));
            }
        }
        let Some((start, tag)) = tags
            .iter()
            .zip(&next)
            .filter_map(|(t, n)| n.map(|p| (p, *t)))
            .min()
        else {
            break;
        };
        let close = format!("</{tag}>");
        let end = s
            .get(start..)
            .and_then(|r| r.find(&close))
            .map_or(s.len(), |e| {
                start.saturating_add(e).saturating_add(close.len())
            });
        let body = s.get(start..end).unwrap_or_default();
        let open = body.get(..body.find('>').unwrap_or(0)).unwrap_or_default();
        let name = attr(open, "name").unwrap_or_default();
        let desc = element(body, "description").unwrap_or_default();
        let extra = if softlist {
            format!(
                "{} {}",
                element(body, "year").unwrap_or_default(),
                element(body, "publisher").unwrap_or_default()
            )
        } else {
            attr(open, "cloneof").map_or_else(String::new, |c| format!("clone of {c}"))
        };
        let n = body.matches("<rom ").count();
        roms = roms.saturating_add(n);
        entries.push((name, desc, extra.trim().to_owned(), n, start, end));
        pos = end.max(start.saturating_add(1));
        if entries.len() >= 1_000_000 {
            break;
        }
    }
    let count = entries.len();
    cx.emit(
        Node::new(if softlist { "Software" } else { "Games" })
            .summary(format!("{count} entries, {roms} ROMs"))
            .lazy(xml_entries, (file, entries)),
    );
    if cut {
        cx.diag(Diagnostic::limit("only the first 4 MiB were parsed"));
    }
    cx.annotate(format!(
        "{} {:?}{}, {count} entries, {roms} ROMs",
        if softlist {
            "MAME software list"
        } else {
            "Logiqx DAT"
        },
        list_name,
        if list_desc.is_empty() || list_desc == list_name {
            String::new()
        } else {
            format!(" ({list_desc})")
        }
    ));
    Ok(())
}

async fn xml_entries(cx: Cx, (file, entries): (Span, Vec<XmlEntry>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(entries.len())));
    for (name, desc, extra, roms, start, end) in entries {
        let summary = if extra.is_empty() {
            format!("{roms} ROMs")
        } else {
            format!("{extra}, {roms} ROMs")
        };
        cx.push(
            Node::new(name)
                .span(file.sub(to_u64(start), to_u64(end.saturating_sub(start))))
                .value(text(desc))
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cdrdao TOC

/// Lines of a block with their spans.
type Statements = Vec<(String, Span)>;

const TOC_TYPES: [&str; 4] = ["CD_DA", "CD_ROM_XA", "CD_ROM", "CD_I"];

fn toc_probe(h: &Head<'_>) -> bool {
    let t = head_text(h, 4096);
    if !is_ascii_text(t) {
        return false;
    }
    let s = String::from_utf8_lossy(t);
    let first = s
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("//"));
    first.is_some_and(|l| {
        TOC_TYPES
            .iter()
            .any(|k| l == *k || l.starts_with(&format!("{k} ")))
    }) && s.contains("TRACK ")
}

declare_format!(pub CDRDAO_TOC = "cdrdao-toc", "cdrdao table of contents", ["toc"],
    "text/x-cdrdao-toc", Probe::Custom(toc_probe), cdrdao_toc);

async fn cdrdao_toc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (data, _) = read_text(&cx, file).await?;
    let mut disc = String::new();
    let mut tracks: Vec<(String, Span, Statements)> = Vec::new();
    let mut files = 0u32;
    for (i, (line, span)) in lines(&data, file).into_iter().enumerate() {
        if i & 0x3ff == 0x3ff {
            cx.checkpoint().await;
        }
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if disc.is_empty() && TOC_TYPES.iter().any(|k| t.starts_with(k)) {
            disc = t.to_owned();
            cx.emit(Node::new("Disc type").span(span).value(text(t.to_owned())));
            continue;
        }
        if let Some(mode) = t.strip_prefix("TRACK ") {
            tracks.push((mode.trim().to_owned(), span, Vec::new()));
            continue;
        }
        if t.starts_with("FILE ") || t.starts_with("DATAFILE ") || t.starts_with("AUDIOFILE ") {
            files = files.saturating_add(1);
        }
        match tracks.last_mut() {
            Some((_, tspan, children)) => {
                *tspan = Span {
                    len: span.end().saturating_sub(tspan.offset),
                    ..*tspan
                };
                children.push((t.to_owned(), span));
            }
            None => cx.emit(Node::new("Disc").span(span).value(text(t.to_owned()))),
        }
    }
    let count = tracks.len();
    let modes: Vec<String> = tracks.iter().map(|t| t.0.clone()).collect();
    for (i, (mode, span, children)) in tracks.into_iter().enumerate() {
        cx.push(
            Node::new(format!("Track {}", i.saturating_add(1)))
                .span(span)
                .value(text(mode))
                .summary(format!("{} statements", children.len()))
                .lazy(toc_lines, children),
        )
        .await;
    }
    let mut distinct = modes.clone();
    distinct.dedup();
    cx.annotate(format!(
        "cdrdao TOC, {disc}, {count} tracks ({}), {files} data file reference(s)",
        distinct.join(", ")
    ));
    Ok(())
}

async fn toc_lines(cx: Cx, children: Statements) -> Result<()> {
    for (line, span) in children {
        let (k, v) = line.split_once(' ').unwrap_or((&line, ""));
        cx.push(
            Node::new(k.to_owned())
                .span(span)
                .value(text(v.trim().to_owned())),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RetroArch cheat file (.cht)

/// `(field, value, line)` of one cheat.
type CheatFields = Vec<(String, String, Span)>;

fn cht_probe(h: &Head<'_>) -> bool {
    let t = head_text(h, 512);
    is_ascii_text(t)
        && String::from_utf8_lossy(t)
            .trim_start()
            .starts_with("cheats = ")
}

declare_format!(pub RETROARCH_CHT = "retroarch-cht", "RetroArch cheat file", ["cht"],
    "text/x-retroarch-cht", Probe::Custom(cht_probe), cht);

async fn cht(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (data, _) = read_text(&cx, file).await?;
    let mut declared = 0u64;
    let mut cheats: Vec<(u64, Span, CheatFields)> = Vec::new();
    for (i, (line, span)) in lines(&data, file).into_iter().enumerate() {
        if i & 0x3ff == 0x3ff {
            cx.checkpoint().await;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim().trim_matches('"'));
        if k == "cheats" {
            declared = v.parse().unwrap_or(0);
            cx.emit(Node::new("cheats").span(span).value(dec(declared, 32)));
            continue;
        }
        let Some(rest) = k.strip_prefix("cheat") else {
            continue;
        };
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        let Ok(index) = digits.parse::<u64>() else {
            continue;
        };
        let field = rest
            .get(digits.len()..)
            .unwrap_or_default()
            .trim_start_matches('_')
            .to_owned();
        match cheats.iter_mut().find(|c| c.0 == index) {
            Some((_, cspan, fields)) => {
                *cspan = Span {
                    len: span.end().saturating_sub(cspan.offset).max(cspan.len),
                    ..*cspan
                };
                fields.push((field, v.to_owned(), span));
            }
            None => cheats.push((index, span, vec![(field, v.to_owned(), span)])),
        }
    }
    let enabled = cheats
        .iter()
        .filter(|c| c.2.iter().any(|f| f.0 == "enable" && f.1 == "true"))
        .count();
    let count = cheats.len();
    for (index, span, fields) in cheats {
        let desc = fields
            .iter()
            .find(|f| f.0 == "desc")
            .map(|f| f.1.clone())
            .unwrap_or_default();
        let code = fields
            .iter()
            .find(|f| f.0 == "code")
            .map(|f| f.1.clone())
            .unwrap_or_default();
        cx.push(
            Node::new(format!("Cheat {index}"))
                .span(span)
                .value(text(desc))
                .summary(code)
                .lazy(cht_fields, fields),
        )
        .await;
    }
    if to_u64(count) != declared {
        cx.diag(Diagnostic::warning(format!(
            "header declares {declared} cheats, found {count}"
        )));
    }
    cx.annotate(format!(
        "RetroArch cheat file, {count} cheats ({enabled} enabled), {}",
        size(file.len)
    ));
    Ok(())
}

async fn cht_fields(cx: Cx, fields: CheatFields) -> Result<()> {
    for (k, v, span) in fields {
        let value = match v.as_str() {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => v
                .parse::<i64>()
                .map_or_else(|_| text(v.clone()), |n| Value::Int { value: n, bits: 64 }),
        };
        cx.push(Node::new(k).span(span).value(value)).await;
    }
    Ok(())
}
