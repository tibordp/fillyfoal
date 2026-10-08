//! Apple developer and diagnostic text files: `.strings` tables, text-based
//! dylib stubs (`.tbd`), Xcode project files (`project.pbxproj`), crash
//! reports (`.ips` JSON and legacy `.crash` text) and bitcode symbol maps.

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::ml::text::block_lines;
use crate::formats::text::encoding::prepare;
use crate::formats::text::probe::{self, contains, significant, trim_start};
use crate::formats::text::scan::Lines;
use crate::formats::text::{json, yaml};
use crate::formats::{Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// .strings

/// Parses `"key" = "value";` (unquoted keys allowed); `None` if the line
/// is not an entry.
fn strings_entry(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let (key, rest) = quoted_or_word(line)?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let (value, rest) = quoted_or_word(rest)?;
    rest.trim_start().starts_with(';').then_some((key, value))
}

/// A quoted string (with escapes) or a bare word at the start of `s`.
fn quoted_or_word(s: &str) -> Option<(String, &str)> {
    if let Some(body) = s.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = body.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => return Some((out, body.get(i.saturating_add(1)..)?)),
                '\\' => match chars.next()?.1 {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    other => out.push(other),
                },
                _ => out.push(c),
            }
        }
        None
    } else {
        let end = s
            .find(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '.' | '-')))
            .unwrap_or(s.len());
        (end > 0).then(|| {
            (
                s.get(..end).unwrap_or_default().to_owned(),
                s.get(end..).unwrap_or_default(),
            )
        })
    }
}

fn strings_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    let mut entries = significant(&data, &[b"/*", b"//", b"*"]).map(|l| {
        let s = String::from_utf8_lossy(trim_start(l)).into_owned();
        s.starts_with('"') && strings_entry(&s).is_some()
    });
    entries.next() == Some(true) && (entries.next() == Some(true) || probe::complete(h))
}

declare_format!(pub STRINGS = "apple-strings", "Apple strings table (.strings)", ["strings"], "text/x-apple-strings",
    Probe::Custom(strings_probe), strings);

async fn strings(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let mut lines = Lines::new(&cx, prepared.span);
    let mut in_comment = false;
    let mut comment = String::new();
    let mut count = 0u64;
    while let Some(line) = lines.next().await? {
        cx.progress_in(
            prepared.span,
            prepared.span.offset.saturating_add(line.start),
        );
        let t = line.text();
        let trimmed = t.trim();
        if in_comment || trimmed.starts_with("/*") {
            in_comment = !trimmed.ends_with("*/");
            let c = trimmed
                .trim_start_matches("/*")
                .trim_end_matches("*/")
                .trim();
            if !c.is_empty() {
                if !comment.is_empty() {
                    comment.push(' ');
                }
                comment.push_str(c);
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        let node = match strings_entry(trimmed) {
            Some((key, value)) => {
                count = count.saturating_add(1);
                Node::new(key).value(text(value))
            }
            None => Node::new(format!("Line {}", line.number)).value(text(trimmed)),
        };
        let node = if comment.is_empty() {
            node
        } else {
            node.desc(std::mem::take(&mut comment))
        };
        cx.push(node.span(line.span)).await;
    }
    cx.annotate(format!(
        "Apple strings table ({}), {count} entries",
        prepared.encoding.name()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Text-based dylib stub (.tbd)

fn tbd_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"--- !tapi-tbd")
        || (trim_start(&probe::head(h)).starts_with(b"{")
            && contains(h.data, b"\"tapi_tbd_version\""))
}

declare_format!(pub TBD = "tbd", "Text-based dylib stub (.tbd)", ["tbd"], "text/x-tbd",
    Probe::Custom(tbd_probe), tbd);

async fn tbd(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 64 * 1024)).await?;
    let lines: Vec<String> = probe::lines(&head)
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    let field = |key: &str| {
        lines.iter().find_map(|l| {
            l.trim_start_matches(['-', ' '])
                .strip_prefix(key)
                .map(|v| v.trim().trim_matches(['\'', '"']).to_owned())
        })
    };
    let documents = lines.iter().filter(|l| l.starts_with("--- !tapi")).count();
    let summary = if head.starts_with(b"---") {
        yaml::dissect(cx.clone(), input).await?;
        let version = lines
            .first()
            .and_then(|l| l.strip_prefix("--- !tapi-tbd"))
            .unwrap_or_default()
            .trim_start_matches('-');
        let version = match field("tbd-version:") {
            Some(v) => format!("v{v}"),
            None if version.is_empty() => "v1".to_owned(),
            None => version.to_owned(),
        };
        format!(
            "Text-based stub {version}, {}, targets {}, {documents} document(s)",
            field("install-name:").unwrap_or_default(),
            field("targets:")
                .or_else(|| field("archs:"))
                .unwrap_or_default()
        )
    } else {
        json::dissect(cx.clone(), input).await?;
        let name = crate::formats::text::probe::find(&head, b"\"install_names\"")
            .and_then(|at| head.get(at..))
            .and_then(|rest| {
                let s = String::from_utf8_lossy(rest);
                let name = s.split("\"name\"").nth(1)?.split('"').nth(1)?.to_owned();
                Some(name)
            })
            .unwrap_or_default();
        format!("Text-based stub (JSON), {name}")
    };
    cx.annotate(summary);
    Ok(())
}

// ---------------------------------------------------------------------------
// Xcode project (project.pbxproj)

declare_format!(pub PBXPROJ = "pbxproj", "Xcode project file (project.pbxproj)", ["pbxproj"], "text/x-pbxproj",
    Probe::Magic(&[(0, b"// !$*UTF8*$!")]), pbxproj);

/// A 24-hex-digit object identifier at the start of `s`.
fn object_id(s: &str) -> Option<&str> {
    let id = s.get(..24)?;
    id.chars().all(|c| c.is_ascii_hexdigit()).then_some(id)
}

async fn pbxproj(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut section: Option<(u64, String, u64)> = None;
    let mut sections = 0u64;
    let mut objects = 0u64;
    let mut archive = String::new();
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(line.start));
        let t = line.text();
        let trimmed = t.trim();
        if let Some(name) = trimmed
            .strip_prefix("/* Begin ")
            .and_then(|r| r.strip_suffix(" section */"))
        {
            section = Some((line.start, name.to_owned(), 0));
            continue;
        }
        if let Some((start, name, n)) = section.as_mut() {
            if trimmed.starts_with("/* End ") {
                let span = file.sub(*start, line.next.saturating_sub(*start));
                cx.push(
                    Node::new(name.clone())
                        .span(span)
                        .summary(format!("{n} objects"))
                        .lazy(pbx_section, span),
                )
                .await;
                sections = sections.saturating_add(1);
                objects = objects.saturating_add(*n);
                section = None;
            } else if object_id(trimmed).is_some() && trimmed.contains(" = {") {
                *n = n.saturating_add(1);
            }
            continue;
        }
        let node = if line.number == 1 {
            Node::new("Encoding marker").value(text(trimmed))
        } else if let Some((key, value)) = trimmed.split_once(" = ") {
            let value = value.trim_end_matches(';').trim();
            if key == "objectVersion" {
                archive = value.to_owned();
            }
            if value == "{" {
                continue;
            }
            Node::new(key.trim().to_owned()).value(text(value))
        } else {
            continue;
        };
        cx.push(node.span(line.span)).await;
    }
    cx.annotate(format!(
        "Xcode project, object version {archive}, {objects} objects in {sections} sections"
    ));
    Ok(())
}

async fn pbx_section(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut current: Option<(u64, String, String, String)> = None;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let trimmed = t.trim();
        if let Some(id) = object_id(trimmed).filter(|_| trimmed.contains(" = {")) {
            let comment = trimmed
                .split_once("/*")
                .and_then(|(_, r)| r.split_once("*/"))
                .map(|(c, _)| c.trim().to_owned())
                .unwrap_or_default();
            let isa = trimmed
                .split("isa = ")
                .nth(1)
                .and_then(|r| r.split(';').next())
                .unwrap_or_default()
                .to_owned();
            current = Some((line.start, id.to_owned(), comment, isa));
        } else if let Some((_, _, _, isa)) = current.as_mut()
            && isa.is_empty()
            && let Some(v) = trimmed.strip_prefix("isa = ")
        {
            *isa = v.trim_end_matches(';').to_owned();
        }
        let closes = trimmed.ends_with("};");
        if closes && let Some((start, id, comment, isa)) = current.take() {
            let obj = span.sub(start, line.next.saturating_sub(start));
            let name = if comment.is_empty() {
                id.clone()
            } else {
                comment
            };
            cx.push(
                Node::new(name)
                    .span(obj)
                    .value(text(isa))
                    .summary(id)
                    .lazy(block_lines, obj),
            )
            .await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Crash reports

fn ips_probe(h: &Head<'_>) -> bool {
    let mut lines = probe::lines(h.data);
    lines
        .next()
        .is_some_and(|l| l.starts_with(b"{") && contains(l, b"\"bug_type\""))
}

declare_format!(pub IPS = "apple-ips", "Apple diagnostic report (.ips)", ["ips"], "application/x-apple-ips",
    Probe::Custom(ips_probe), ips);

/// A JSON string field from one line of JSON.
fn json_field(line: &str, key: &str) -> Option<String> {
    let rest = line.split(&format!("\"{key}\"")).nth(1)?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    if let Some(s) = rest.strip_prefix('"') {
        Some(s.split('"').next()?.to_owned())
    } else {
        Some(rest.split([',', '}']).next()?.trim().to_owned())
    }
}

async fn ips(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let Some(first) = lines.next().await? else {
        return Ok(());
    };
    let header = first.text();
    let body = file.tail(first.next);
    if body.is_empty() {
        json::dissect(cx.clone(), input).await?;
    } else {
        cx.emit(embedded_as(
            "Header",
            input.nested(first.span),
            &json::FORMAT,
        ));
        cx.emit(embedded_as("Report", input.nested(body), &json::FORMAT));
    }
    let get = |k: &str| json_field(&header, k).unwrap_or_default();
    let name = json_field(&header, "app_name")
        .or_else(|| json_field(&header, "name"))
        .unwrap_or_default();
    cx.annotate(format!(
        "Apple diagnostic report, bug type {}, {name} {}, {}, {}",
        get("bug_type"),
        get("app_version"),
        get("os_version"),
        get("timestamp")
    ));
    Ok(())
}

declare_format!(pub CRASH = "apple-crash-report", "Apple crash report (text)", ["crash", "ips"], "text/x-apple-crash",
    Probe::Magic(&[(0, b"Incident Identifier: ")]), crash);

async fn crash(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut section: Option<(u64, String, u64)> = None;
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut crashed = String::new();
    loop {
        let line = lines.next().await?;
        let t = line.as_ref().map(|l| l.text()).unwrap_or_default();
        let blank = t.trim().is_empty();
        if (blank || line.is_none())
            && let Some((start, name, n)) = section.take()
        {
            let end = line.as_ref().map_or(file.len, |l| l.start);
            let span = file.sub(start, end.saturating_sub(start));
            cx.push(
                Node::new(name)
                    .span(span)
                    .summary(format!("{n} lines"))
                    .lazy(block_lines, span),
            )
            .await;
        }
        let Some(line) = line else { break };
        cx.progress_in(file, file.offset.saturating_add(line.start));
        if blank {
            continue;
        }
        if let Some((_, _, n)) = section.as_mut() {
            *n = n.saturating_add(1);
            if t.starts_with("Thread ") && t.contains("Crashed") {
                crashed = t.trim_end().trim_end_matches(':').to_owned();
            }
            continue;
        }
        let starts_section = !t.starts_with([' ', '\t'])
            && (t.trim_end().ends_with(':')
                || t.starts_with("Thread ")
                || t.starts_with("Binary Images"));
        if starts_section {
            let name = t.trim_end().trim_end_matches(':').to_owned();
            if name.contains("Crashed") {
                crashed = name.clone();
            }
            section = Some((line.start, name, 0));
            continue;
        }
        let (key, value) = t
            .split_once(':')
            .map_or((t.as_str(), ""), |(k, v)| (k, v.trim()));
        fields.push((key.trim().to_owned(), value.to_owned()));
        cx.push(
            Node::new(key.trim().to_owned())
                .span(line.span)
                .value(text(value)),
        )
        .await;
    }
    let get = |k: &str| {
        fields
            .iter()
            .find(|(f, _)| f == k)
            .map_or("", |(_, v)| v.as_str())
    };
    cx.annotate(format!(
        "Apple crash report: {}, {}, {}",
        get("Process"),
        get("Exception Type"),
        if crashed.is_empty() {
            "no crashed thread"
        } else {
            crashed.as_str()
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Bitcode symbol map (.bcsymbolmap)

declare_format!(pub BCSYMBOLMAP = "bcsymbolmap", "Bitcode symbol map", ["bcsymbolmap"], "text/x-bcsymbolmap",
    Probe::Magic(&[(0, b"BCSymbolMap Version: ")]), bcsymbolmap);

async fn bcsymbolmap(cx: Cx, input: Input) -> Result<()> {
    let mut lines = Lines::new(&cx, input.span);
    let mut version = String::new();
    let mut n = 0u64;
    while let Some(line) = lines.next().await? {
        cx.progress_in(input.span, input.span.offset.saturating_add(line.start));
        let t = line.text();
        let node = if line.number == 1 {
            version = t
                .trim_start_matches("BCSymbolMap Version:")
                .trim()
                .to_owned();
            Node::new("Version").value(text(version.clone()))
        } else {
            let index = n;
            n = n.saturating_add(1);
            Node::new(format!("__hidden#{index}_")).value(text(t))
        };
        cx.push(node.span(line.span)).await;
    }
    cx.annotate(format!("Bitcode symbol map v{version}, {n} symbols"));
    Ok(())
}
