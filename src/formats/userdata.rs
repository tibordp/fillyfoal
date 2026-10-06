//! Text artifacts from user profiles: shell histories (zsh, bash, fish,
//! libedit, less), browser exports and settings (Netscape cookies and
//! bookmarks, Opera hotlists, Firefox prefs.js and certificate overrides),
//! wget's HSTS database, freedesktop Trash records and recently-used files.

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::util::datakit::{clip, text};
use crate::formats::logs::{Lines, line_group, strip_bom, text_lines};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

fn unix_time(seconds: i64) -> Value {
    Value::Timestamp {
        unix_seconds: seconds,
    }
}

fn first_line<'a>(h: &'a Head<'_>) -> &'a [u8] {
    let d = strip_bom(h.data);
    let line = d.split(|&b| b == b'\n').next().unwrap_or_default();
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn digits(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(u8::is_ascii_digit)
}

use crate::text::url::percent_decode;

/// One history entry: lines, optional time, and the command text.
fn history_node(
    file: Span,
    lines: Lines,
    time: Option<i64>,
    command: &str,
    extra: Option<String>,
) -> Node {
    let mut node = line_group(clip(&command.replace('\n', " ⏎ "), 120), file, lines);
    if let Some(t) = time {
        node = node.value(unix_time(t));
    }
    if let Some(e) = extra {
        node = node.summary(e);
    }
    node
}

fn time_range(times: &[i64]) -> String {
    match (times.iter().min(), times.iter().max()) {
        (Some(a), Some(b)) => format!(", {} s span", b.saturating_sub(*a)),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// zsh extended history (": <start>:<elapsed>;<command>")

fn zsh_entry(line: &str) -> Option<(i64, i64, &str)> {
    let rest = line.strip_prefix(": ")?;
    let (stamps, command) = rest.split_once(';')?;
    let (start, elapsed) = stamps.split_once(':')?;
    Some((
        start.trim().parse().ok()?,
        elapsed.trim().parse().ok()?,
        command,
    ))
}

fn zsh_probe(h: &Head<'_>) -> bool {
    let line = first_line(h);
    line.starts_with(b": ")
        && std::str::from_utf8(line)
            .ok()
            .and_then(zsh_entry)
            .is_some_and(|(t, _, _)| t > 100_000_000)
}

declare_format!(pub ZSH = "zsh-history", "zsh extended history", ["zsh_history", "histfile"], "text/x-zsh-history",
    Probe::Custom(zsh_probe), zsh_history);

async fn zsh_history(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut times = Vec::new();
    let mut current: Option<(i64, i64, String, Lines)> = None;
    for l in all {
        if let Some((start, elapsed, command)) = zsh_entry(&l.2) {
            if let Some((t, e, c, lines)) = current.take() {
                cx.push(history_node(
                    file,
                    lines,
                    Some(t),
                    &c,
                    Some(format!("{e} s")),
                ))
                .await;
            }
            times.push(start);
            current = Some((start, elapsed, command.to_owned(), vec![l]));
        } else if let Some((_, _, c, lines)) = current.as_mut() {
            // Multi-line commands continue with a trailing backslash.
            c.push('\n');
            c.push_str(&l.2);
            lines.push(l);
        }
    }
    if let Some((t, e, c, lines)) = current.take() {
        cx.push(history_node(
            file,
            lines,
            Some(t),
            &c,
            Some(format!("{e} s")),
        ))
        .await;
    }
    cx.annotate(format!(
        "zsh history, {} commands{}",
        times.len(),
        time_range(&times)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// bash history with HISTTIMEFORMAT ("#<epoch>" before each command)

fn bash_stamp(line: &str) -> Option<i64> {
    let d = line.strip_prefix('#')?;
    (d.len() >= 9 && d.len() <= 11 && digits(d.as_bytes()))
        .then(|| d.parse().ok())
        .flatten()
}

fn bash_probe(h: &Head<'_>) -> bool {
    let d = strip_bom(h.data);
    let mut it = d.split(|&b| b == b'\n');
    let first = std::str::from_utf8(it.next().unwrap_or_default())
        .unwrap_or_default()
        .trim_end();
    let second = it.next().unwrap_or_default();
    bash_stamp(first).is_some() && !second.is_empty() && !second.starts_with(b"#")
}

declare_format!(pub BASH = "bash-history", "bash history (timestamped)", ["bash_history"], "text/x-bash-history",
    Probe::Custom(bash_probe), bash_history);

async fn bash_history(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut times = Vec::new();
    let mut stamp: Option<(i64, crate::formats::logs::Line)> = None;
    let mut count = 0u64;
    for l in all {
        if let Some(t) = bash_stamp(l.2.trim_end()) {
            stamp = Some((t, l));
            continue;
        }
        if l.2.is_empty() {
            continue;
        }
        count = count.saturating_add(1);
        let (time, mut lines) = match stamp.take() {
            Some((t, s)) => {
                times.push(t);
                (Some(t), vec![s])
            }
            None => (None, Vec::new()),
        };
        let command = l.2.clone();
        lines.push(l);
        cx.push(history_node(file, lines, time, &command, None))
            .await;
    }
    cx.annotate(format!(
        "bash history, {count} commands, {} timestamped{}",
        times.len(),
        time_range(&times)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// fish history (YAML-like "- cmd:" / "  when:")

fn fish_probe(h: &Head<'_>) -> bool {
    let d = strip_bom(h.data);
    d.starts_with(b"- cmd: ")
        && d.get(..512)
            .unwrap_or(d)
            .windows(9)
            .any(|w| w == b"\n  when: ")
}

declare_format!(pub FISH = "fish-history", "fish shell history", ["fish_history"], "text/x-fish-history",
    Probe::Custom(fish_probe), fish_history);

async fn fish_history(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut times = Vec::new();
    let mut current: Option<(String, Option<i64>, Lines)> = None;
    for l in all {
        if let Some(cmd) = l.2.strip_prefix("- cmd: ") {
            if let Some((c, t, lines)) = current.take() {
                cx.push(history_node(file, lines, t, &c, None)).await;
            }
            current = Some((cmd.replace("\\n", "\n"), None, vec![l]));
            continue;
        }
        if let Some((_, t, lines)) = current.as_mut() {
            if let Some(w) = l.2.trim_start().strip_prefix("when: ")
                && let Ok(v) = w.trim().parse::<i64>()
            {
                *t = Some(v);
                times.push(v);
            }
            lines.push(l);
        }
    }
    if let Some((c, t, lines)) = current.take() {
        cx.push(history_node(file, lines, t, &c, None)).await;
    }
    cx.annotate(format!(
        "fish history, {} commands{}",
        times.len(),
        time_range(&times)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// libedit history (_HiStOrY_V2_: MySQL, SQLite, psql on BSD)

declare_format!(pub LIBEDIT = "libedit-history", "libedit history (_HiStOrY_V2_)", ["mysql_history", "sqlite_history", "psql_history"], "text/x-libedit-history",
    Probe::Magic(&[(0, b"_HiStOrY_V2_\n"), (0, b"_HiStOrY_V2_\r\n")]), libedit_history);

/// Undoes libedit's `\ooo` octal escapes (space is stored as `\040`).
fn unvis(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        let oct = (c == b'\\')
            .then(|| b.get(i.saturating_add(1)..i.saturating_add(4)))
            .flatten()
            .filter(|o| o.iter().all(|d| (b'0'..=b'7').contains(d)))
            .and_then(|o| std::str::from_utf8(o).ok())
            .and_then(|o| u8::from_str_radix(o, 8).ok());
        match oct {
            Some(v) => {
                out.push(v);
                i = i.saturating_add(4);
            }
            None => {
                out.push(c);
                i = i.saturating_add(1);
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn libedit_history(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut count = 0u64;
    for l in all.into_iter().skip(1) {
        if l.2.is_empty() {
            continue;
        }
        count = count.saturating_add(1);
        let span = file.sub(l.0, l.1);
        cx.push(
            Node::new(format!("Entry {count}"))
                .span(span)
                .value(text(unvis(&l.2))),
        )
        .await;
    }
    cx.annotate(format!("libedit history, {count} entries"));
    Ok(())
}

// ---------------------------------------------------------------------------
// less history (.lesshst)

declare_format!(pub LESS = "less-history", "less history (.lesshst)", ["lesshst"], "text/x-less-history",
    Probe::Magic(&[(0, b".less-history-file:\n"), (0, b".less-history-file:\r\n")]), less_history);

async fn less_history(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut section: Option<(String, Lines)> = None;
    let mut searches = 0u64;
    for l in all.into_iter().skip(1) {
        if let Some(name) = l.2.strip_prefix('.') {
            if let Some((n, lines)) = section.take() {
                let count = lines.len();
                cx.push(
                    line_group(format!(".{n}"), file, lines).summary(format!("{count} entries")),
                )
                .await;
            }
            section = Some((name.to_owned(), Vec::new()));
            continue;
        }
        if let Some((n, lines)) = section.as_mut() {
            if n == "search" {
                searches = searches.saturating_add(1);
            }
            lines.push(l);
        }
    }
    if let Some((n, lines)) = section.take() {
        let count = lines.len();
        cx.push(line_group(format!(".{n}"), file, lines).summary(format!("{count} entries")))
            .await;
    }
    cx.annotate(format!("less history, {searches} searches"));
    Ok(())
}

// ---------------------------------------------------------------------------
// GNU Wget HSTS database (.wget-hsts)

declare_format!(pub WGET_HSTS = "wget-hsts", "GNU Wget HSTS database", ["wget-hsts"], "text/x-wget-hsts",
    Probe::Magic(&[(0, b"# HSTS 1.0 Known Hosts database for GNU Wget.")]), wget_hsts);

async fn wget_hsts(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut hosts = 0u64;
    for l in all {
        let span = file.sub(l.0, l.1);
        if l.2.starts_with('#') || l.2.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = l.2.split_whitespace().collect();
        let (host, port, subs, created, max_age) = (
            f.first().copied().unwrap_or(""),
            f.get(1).copied().unwrap_or("0"),
            f.get(2).copied().unwrap_or("0"),
            f.get(3).copied().unwrap_or("0"),
            f.get(4).copied().unwrap_or("0"),
        );
        hosts = hosts.saturating_add(1);
        let mut node = Node::new(host.to_owned()).span(span);
        if let Ok(t) = created.parse::<i64>() {
            node = node.value(unix_time(t));
        }
        let port = if port == "0" {
            String::new()
        } else {
            format!("port {port}, ")
        };
        cx.push(node.summary(format!(
            "{port}max-age {max_age}{}",
            if subs == "1" {
                ", includeSubDomains"
            } else {
                ""
            }
        )))
        .await;
    }
    cx.annotate(format!("Wget HSTS database, {hosts} hosts"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Netscape cookies.txt (curl, wget, browser exports)

fn cookies_probe(h: &Head<'_>) -> bool {
    let line = first_line(h);
    line.starts_with(b"# Netscape HTTP Cookie File") || line.starts_with(b"# HTTP Cookie File")
}

declare_format!(pub COOKIES_TXT = "netscape-cookies", "Netscape cookies.txt", ["txt"], "text/x-netscape-cookies",
    Probe::Custom(cookies_probe), netscape_cookies);

async fn netscape_cookies(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut domains = std::collections::BTreeSet::new();
    let mut count = 0u64;
    for l in all {
        let line = l.2.strip_prefix("#HttpOnly_").unwrap_or(&l.2);
        let http_only = line.len() != l.2.len();
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 7 {
            continue;
        }
        let get = |i: usize| f.get(i).copied().unwrap_or("");
        count = count.saturating_add(1);
        domains.insert(get(0).trim_start_matches('.').to_owned());
        let mut node =
            Node::new(format!("{}={}", get(5), clip(get(6), 60))).span(file.sub(l.0, l.1));
        if let Ok(t) = get(4).parse::<i64>() {
            node = node.value(if t == 0 {
                text("session")
            } else {
                unix_time(t)
            });
        }
        let flags = [(get(3) == "TRUE", "secure"), (http_only, "HttpOnly")]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, n)| *n)
            .collect::<Vec<_>>()
            .join(", ");
        cx.push(node.summary(format!(
            "{}{}{}",
            get(0),
            get(2),
            if flags.is_empty() {
                String::new()
            } else {
                format!(" ({flags})")
            }
        )))
        .await;
    }
    cx.annotate(format!(
        "Netscape cookie file, {count} cookies for {} domains",
        domains.len()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Netscape bookmark files (bookmarks.html exports)

fn bookmarks_probe(h: &Head<'_>) -> bool {
    let line = first_line(h);
    line.len() >= 35
        && line
            .get(..35)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"<!DOCTYPE NETSCAPE-Bookmark-file-1>"))
}

declare_format!(pub BOOKMARKS = "netscape-bookmarks", "Netscape bookmark file (bookmarks.html)", ["html", "htm"], "text/x-netscape-bookmarks",
    Probe::Custom(bookmarks_probe), netscape_bookmarks);

#[derive(Clone, Debug, Default)]
struct Bookmark {
    title: String,
    href: Option<String>,
    added: Option<i64>,
    start: u64,
    end: u64,
    children: Vec<usize>,
}

#[derive(Debug, Default)]
struct BookmarkTree {
    items: Vec<Bookmark>,
    roots: Vec<usize>,
}

/// The value of `name="..."` inside a tag (case-insensitive name).
fn attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let key = format!("{}=\"", name.to_ascii_lowercase());
    let at = lower.find(&key)?.saturating_add(key.len());
    let rest = tag.get(at..)?;
    Some(rest.split('"').next()?.to_owned())
}

fn unescape_html(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn parse_bookmarks(data: &str) -> BookmarkTree {
    let mut tree = BookmarkTree::default();
    let mut stack: Vec<usize> = Vec::new();
    let mut pending_folder: Option<usize> = None;
    let mut i = 0usize;
    let lower = data.to_ascii_lowercase();
    while let Some(p) = lower.get(i..).and_then(|r| r.find('<')) {
        let open = i.saturating_add(p);
        let Some(close) = lower
            .get(open..)
            .and_then(|r| r.find('>'))
            .map(|c| open.saturating_add(c))
        else {
            break;
        };
        let tag = data.get(open..=close).unwrap_or_default();
        let tag_lower = lower.get(open..=close).unwrap_or_default();
        i = close.saturating_add(1);
        let push = |tree: &mut BookmarkTree, item: Bookmark, stack: &[usize]| -> usize {
            let index = tree.items.len();
            tree.items.push(item);
            match stack.last().and_then(|&s| tree.items.get_mut(s)) {
                Some(parent) => parent.children.push(index),
                None => tree.roots.push(index),
            }
            index
        };
        if tag_lower.starts_with("<h3") || tag_lower.starts_with("<a ") {
            let end_tag = if tag_lower.starts_with("<h3") {
                "</h3>"
            } else {
                "</a>"
            };
            let text_end = lower
                .get(i..)
                .and_then(|r| r.find(end_tag))
                .map_or(data.len(), |e| i.saturating_add(e));
            let title = unescape_html(data.get(i..text_end).unwrap_or_default().trim());
            let item = Bookmark {
                title,
                href: if end_tag == "</a>" {
                    attr(tag, "href")
                } else {
                    None
                },
                added: attr(tag, "add_date").and_then(|d| d.parse().ok()),
                start: to_u64(open),
                end: to_u64(text_end.saturating_add(end_tag.len()).min(data.len())),
                children: Vec::new(),
            };
            let is_folder = end_tag == "</h3>";
            let index = push(&mut tree, item, &stack);
            if is_folder {
                pending_folder = Some(index);
            }
            i = text_end;
        } else if tag_lower.starts_with("<dl") {
            if let Some(f) = pending_folder.take() {
                stack.push(f);
            }
        } else if tag_lower.starts_with("</dl")
            && let Some(f) = stack.pop()
            && let Some(item) = tree.items.get_mut(f)
        {
            item.end = to_u64(i);
        }
        if tree.items.len() > 1_000_000 {
            break;
        }
    }
    tree
}

async fn bookmark_tree(cx: &Cx, file: Span) -> Result<Arc<BookmarkTree>> {
    if let Some(t) = cx.cached::<BookmarkTree>(file, "netscape-bookmarks") {
        return Ok(t);
    }
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let tree = Arc::new(parse_bookmarks(&String::from_utf8_lossy(&data)));
    cx.cache(file, "netscape-bookmarks", tree.clone());
    Ok(tree)
}

fn bookmark_nodes(file: Span, tree: &BookmarkTree, list: &[usize]) -> Vec<Node> {
    list.iter()
        .filter_map(|&i| tree.items.get(i).map(|b| (i, b)))
        .map(|(i, b)| {
            let mut node = Node::new(if b.title.is_empty() {
                "(untitled)".to_owned()
            } else {
                b.title.clone()
            })
            .span(file.sub(b.start, b.end.saturating_sub(b.start)));
            if let Some(t) = b.added {
                node = node.value(unix_time(t));
            }
            match &b.href {
                Some(h) => node.summary(clip(h, 160)),
                None => node
                    .summary(format!("folder, {} items", b.children.len()))
                    .lazy(bookmark_folder, (file, i)),
            }
        })
        .collect()
}

async fn netscape_bookmarks(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let tree = bookmark_tree(&cx, file).await?;
    for node in bookmark_nodes(file, &tree, &tree.roots) {
        cx.push(node).await;
    }
    let links = tree.items.iter().filter(|b| b.href.is_some()).count();
    let folders = tree.items.len().saturating_sub(links);
    cx.annotate(format!(
        "Netscape bookmarks, {links} links in {folders} folders"
    ));
    Ok(())
}

async fn bookmark_folder(cx: Cx, (file, index): (Span, usize)) -> Result<()> {
    let tree = bookmark_tree(&cx, file).await?;
    let Some(folder) = tree.items.get(index) else {
        return Ok(());
    };
    cx.set_count(Count::Exact(to_u64(folder.children.len())));
    for node in bookmark_nodes(file, &tree, &folder.children) {
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Opera hotlists (bookmarks.adr, notes.adr, contacts.adr)

declare_format!(pub OPERA_HOTLIST = "opera-hotlist", "Opera hotlist (bookmarks.adr)", ["adr"], "text/x-opera-hotlist",
    Probe::Magic(&[(0, b"Opera Hotlist version 2.0")]), opera_hotlist);

async fn opera_hotlist(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut record: Option<(String, Lines)> = None;
    let (mut urls, mut folders) = (0u64, 0u64);
    // Folder names from the root to the current folder.
    let mut path: Vec<String> = Vec::new();
    let flush = |record: Option<(String, Lines)>, path: &[String]| -> Option<(Node, String)> {
        let (kind, lines) = record?;
        let get = |key: &str| {
            lines
                .iter()
                .find_map(|l| l.2.trim_start().strip_prefix(key).map(str::to_owned))
        };
        let name = get("NAME=").unwrap_or_default();
        let mut node = line_group(
            if name.is_empty() {
                kind.clone()
            } else {
                name.clone()
            },
            file,
            lines.clone(),
        );
        if !path.is_empty() {
            node = node.desc(format!("In {}", path.join(" › ")));
        }
        if let Some(t) = get("CREATED=").and_then(|c| c.parse::<i64>().ok()) {
            node = node.value(unix_time(t));
        }
        let summary = match kind.as_str() {
            "#URL" => get("URL=").unwrap_or_default(),
            "#NOTE" => clip(&get("NAME=").unwrap_or_default(), 100),
            other => other.trim_start_matches('#').to_lowercase(),
        };
        Some((node.summary(clip(&summary, 160)), name))
    };
    for l in all.into_iter().skip(1) {
        let t = l.2.trim();
        if t.starts_with('#') || t == "-" {
            // A record ends at the next one; a folder's contents follow it
            // until a lone "-".
            let opened = record.as_ref().is_some_and(|(k, _)| k == "#FOLDER");
            if let Some((n, name)) = flush(record.take(), &path) {
                cx.push(n).await;
                if opened && path.len() < 64 {
                    path.push(name);
                }
            }
            if t == "-" {
                path.pop();
                continue;
            }
            if t == "#FOLDER" {
                folders = folders.saturating_add(1);
            } else if t == "#URL" {
                urls = urls.saturating_add(1);
            }
            record = Some((t.to_owned(), vec![l]));
        } else if let Some((_, lines)) = record.as_mut()
            && !t.is_empty()
        {
            lines.push(l);
        }
    }
    if let Some((n, _)) = flush(record.take(), &path) {
        cx.push(n).await;
    }
    cx.annotate(format!(
        "Opera hotlist, {urls} bookmarks in {folders} folders"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Firefox prefs.js

declare_format!(pub FIREFOX_PREFS = "firefox-prefs", "Firefox preferences (prefs.js)", ["js"], "text/x-firefox-prefs",
    Probe::Magic(&[(0, b"// Mozilla User Preferences")]), firefox_prefs);

/// Parses `user_pref("name", value);`.
fn pref_line(line: &str) -> Option<(String, String)> {
    let rest = line.trim().strip_prefix("user_pref(")?.strip_suffix(");")?;
    let rest = rest.strip_prefix('"')?;
    let mut name = String::new();
    let mut chars = rest.char_indices();
    let mut value_at = None;
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                if let Some((_, n)) = chars.next() {
                    name.push(n);
                }
            }
            '"' => {
                value_at = Some(i.saturating_add(1));
                break;
            }
            _ => name.push(c),
        }
    }
    let value = rest
        .get(value_at?..)?
        .trim_start()
        .strip_prefix(',')?
        .trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .map_or_else(
            || value.to_owned(),
            |v| v.replace("\\\"", "\"").replace("\\\\", "\\"),
        );
    Some((name, value))
}

async fn firefox_prefs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut count = 0u64;
    let mut notable = Vec::new();
    for l in all {
        let Some((name, value)) = pref_line(&l.2) else {
            continue;
        };
        count = count.saturating_add(1);
        if matches!(
            name.as_str(),
            "browser.startup.homepage"
                | "browser.download.dir"
                | "browser.download.lastDir"
                | "network.proxy.http"
        ) {
            notable.push(format!("{name}={}", clip(&value, 60)));
        }
        let node = Node::new(name.clone()).span(file.sub(l.0, l.1));
        let node = match value.parse::<i64>() {
            Ok(v)
                if name.ends_with("Time")
                    || name.ends_with("_time")
                    || name.contains("lastUpdate") =>
            {
                // Times are seconds, or milliseconds when they look too large.
                node.value(unix_time(if v > 100_000_000_000 { v / 1000 } else { v }))
                    .summary(value)
            }
            Ok(v) => node.value(Value::Int { value: v, bits: 64 }),
            Err(_) if value == "true" || value == "false" => {
                node.value(Value::Bool(value == "true"))
            }
            Err(_) => node.value(text(value)),
        };
        cx.push(node).await;
    }
    cx.annotate(format!(
        "Firefox prefs.js, {count} preferences{}",
        if notable.is_empty() {
            String::new()
        } else {
            format!(" ({})", clip(&notable.join("; "), 160))
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Firefox cert_override.txt

declare_format!(pub CERT_OVERRIDE = "firefox-cert-override", "Firefox certificate overrides (cert_override.txt)", ["txt"], "text/x-firefox-cert-override",
    Probe::Magic(&[(0, b"# PSM Certificate Override Settings file")]), cert_override);

async fn cert_override(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut count = 0u64;
    for l in all {
        if l.2.starts_with('#') || l.2.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = l.2.split('\t').collect();
        let host = f.first().copied().unwrap_or_default().trim_end_matches(':');
        let fingerprint = f.get(2).copied().unwrap_or_default();
        let flags = f.get(3).copied().unwrap_or_default();
        let reasons: Vec<&str> = [
            ('M', "mismatched domain"),
            ('U', "untrusted"),
            ('T', "expired"),
        ]
        .iter()
        .filter(|(c, _)| flags.contains(*c))
        .map(|(_, n)| *n)
        .collect();
        count = count.saturating_add(1);
        cx.push(
            Node::new(host.to_owned())
                .span(file.sub(l.0, l.1))
                .value(text(fingerprint))
                .summary(if reasons.is_empty() {
                    flags.to_owned()
                } else {
                    reasons.join(", ")
                }),
        )
        .await;
    }
    cx.annotate(format!("Firefox certificate overrides, {count} exceptions"));
    Ok(())
}

// ---------------------------------------------------------------------------
// freedesktop.org Trash records (*.trashinfo)

fn trashinfo_probe(h: &Head<'_>) -> bool {
    first_line(h) == b"[Trash Info]" && h.len < 0x10000
}

declare_format!(pub TRASHINFO = "trashinfo", "freedesktop.org Trash record (.trashinfo)", ["trashinfo"], "text/x-trashinfo",
    Probe::Custom(trashinfo_probe), trashinfo);

async fn trashinfo(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let (mut path, mut date) = (String::new(), String::new());
    for l in all {
        let span = file.sub(l.0, l.1);
        if let Some(p) = l.2.strip_prefix("Path=") {
            path = percent_decode(p);
            cx.push(
                Node::new("Path")
                    .span(span)
                    .value(text(path.clone()))
                    .summary(p.to_owned()),
            )
            .await;
        } else if let Some(d) = l.2.strip_prefix("DeletionDate=") {
            date = d.to_owned();
            cx.push(Node::new("DeletionDate").span(span).value(text(d)))
                .await;
        } else if !l.2.is_empty() {
            cx.push(Node::new("Line").span(span).value(text(l.2))).await;
        }
    }
    cx.annotate(format!("Trash record: {path} deleted {date}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// GTK recently-used files (recently-used.xbel)

fn xbel_probe(h: &Head<'_>) -> bool {
    let d = h.data.get(..1024).unwrap_or(h.data);
    d.windows(5).any(|w| w == b"<xbel") && d.windows(17).any(|w| w == b"desktop-bookmarks")
}

declare_format!(pub XBEL = "recently-used-xbel", "GTK recently used files (recently-used.xbel)", ["xbel"], "application/x-xbel",
    Probe::Custom(xbel_probe), recently_used);

async fn recently_used(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let s = String::from_utf8_lossy(&data);
    let mut at = 0usize;
    let mut count = 0u64;
    let mut apps = std::collections::BTreeSet::new();
    while let Some(p) = s.get(at..).and_then(|r| r.find("<bookmark ")) {
        let start = at.saturating_add(p);
        let end = s
            .get(start..)
            .and_then(|r| r.find("</bookmark>"))
            .map_or(s.len(), |e| start.saturating_add(e).saturating_add(11));
        let tag_end = s
            .get(start..)
            .and_then(|r| r.find('>'))
            .map_or(end, |e| start.saturating_add(e));
        let tag = s.get(start..=tag_end).unwrap_or_default();
        let body = s.get(start..end).unwrap_or_default();
        let href = attr(tag, "href").unwrap_or_default();
        let visited = attr(tag, "visited")
            .or_else(|| attr(tag, "modified"))
            .unwrap_or_default();
        let names: Vec<String> = body
            .match_indices("<bookmark:application ")
            .filter_map(|(i, _)| {
                body.get(i..)
                    .and_then(|r| attr(r.split('>').next().unwrap_or_default(), "name"))
            })
            .collect();
        apps.extend(names.iter().cloned());
        count = count.saturating_add(1);
        cx.push(
            Node::new(percent_decode(
                href.strip_prefix("file://").unwrap_or(&href),
            ))
            .span(file.sub(to_u64(start), to_u64(end.saturating_sub(start))))
            .value(text(visited))
            .summary(names.join(", ")),
        )
        .await;
        at = end.max(start.saturating_add(1));
    }
    cx.annotate(format!(
        "Recently used files, {count} entries from {} applications",
        apps.len()
    ));
    Ok(())
}
