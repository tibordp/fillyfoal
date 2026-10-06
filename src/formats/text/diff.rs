//! Unified diffs and patches (`diff -u`, `git diff`, `svn diff`): files,
//! their headers, hunks and changed lines with line numbers.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

use super::encoding::prepare;
use super::piece::Piece;
use super::scan::Lines;
use super::{count, plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "diff",
    title: "Unified diff",
    extensions: &["diff", "patch", "debdiff", "rej"],
    mime: "text/x-diff",
    probe: Probe::Custom(probe_diff),
    dissect: crate::expander!(dissect: Input),
};

fn probe_diff(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let lines: Vec<&[u8]> = probe::lines(&head).take(60).collect();
    let first = lines.first().copied().unwrap_or_default();
    let header = first.starts_with(b"diff --git ") || first.starts_with(b"Index: ");
    let unified = lines.windows(3).any(|w| {
        matches!(w, [a, b, c] if a.starts_with(b"--- ") && b.starts_with(b"+++ ") && c.starts_with(b"@@ -"))
    });
    (header || unified) && probe::is_text(h)
}

/// `@@ -a,b +c,d @@ context` → (a, b, c, d).
fn hunk_header(line: &[u8]) -> Option<(u64, u64, u64, u64)> {
    let rest = line.strip_prefix(b"@@ -")?;
    let end = probe::find(rest, b" @@")?;
    let ranges = String::from_utf8_lossy(rest.get(..end)?).into_owned();
    let (old, new) = ranges.split_once(" +")?;
    let range = |r: &str| -> Option<(u64, u64)> {
        match r.split_once(',') {
            Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
            None => Some((r.parse().ok()?, 1)),
        }
    };
    let (a, b) = range(old)?;
    let (c, d) = range(new)?;
    Some((a, b, c, d))
}

/// A path from a `---`/`+++` line, without timestamps and `a/`, `b/`.
fn path(line: Piece<'_>) -> String {
    let rest = line.from(4);
    let rest = rest.split_once(b'\t').map_or(rest, |(p, _)| p).trim();
    let text = rest.text();
    text.strip_prefix("a/")
        .or_else(|| text.strip_prefix("b/"))
        .unwrap_or(&text)
        .to_owned()
}

/// Old and new paths from `diff --git a/x b/y`.
fn git_paths(line: &[u8]) -> Option<(String, String)> {
    let rest = String::from_utf8_lossy(line.strip_prefix(b"diff --git a/")?).into_owned();
    let (old, new) = rest.rsplit_once(" b/")?;
    Some((old.to_owned(), new.to_owned()))
}

struct File {
    start: u64,
    old: String,
    new: String,
    added: u64,
    removed: u64,
    hunks: u64,
    /// Whether its `---`/`+++` lines were seen.
    unified: bool,
}

async fn push_file(cx: &Cx, span: Span, f: File, end: u64) {
    let s = span.sub(f.start, end.saturating_sub(f.start));
    let name = if f.new.is_empty() || f.new == "/dev/null" {
        f.old.clone()
    } else {
        f.new.clone()
    };
    let name = if name.is_empty() { "(file)".to_owned() } else { name };
    let mut summary = format!("+{} −{}, {}", f.added, f.removed, plural(f.hunks, "hunk", "hunks"));
    if f.old == "/dev/null" {
        summary = format!("new file, {summary}");
    } else if f.new == "/dev/null" {
        summary = format!("deleted, {summary}");
    } else if !f.old.is_empty() && !f.new.is_empty() && f.old != f.new {
        summary = format!("renamed from {}, {summary}", f.old);
    }
    cx.push(Node::new(name).span(s).summary(summary).lazy(file, s)).await;
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut current: Option<File> = None;
    let mut old_left = 0u64;
    let mut new_left = 0u64;
    let mut files = 0u64;
    let (mut added, mut removed) = (0u64, 0u64);
    let mut preamble_end = None;
    let new_file = |start| File {
        start,
        old: String::new(),
        new: String::new(),
        added: 0,
        removed: 0,
        hunks: 0,
        unified: false,
    };
    loop {
        let before = lines.pos();
        let Some(line) = lines.next().await? else {
            if let Some(f) = current.take() {
                push_file(&cx, span, f, before).await;
            }
            break;
        };
        let b = line.bytes.as_slice();
        if old_left > 0 || new_left > 0 {
            match b.first() {
                Some(b' ') | None => {
                    old_left = old_left.saturating_sub(1);
                    new_left = new_left.saturating_sub(1);
                    continue;
                }
                Some(b'-') => {
                    old_left = old_left.saturating_sub(1);
                    removed = removed.saturating_add(1);
                    if let Some(f) = current.as_mut() {
                        f.removed = f.removed.saturating_add(1);
                    }
                    continue;
                }
                Some(b'+') => {
                    new_left = new_left.saturating_sub(1);
                    added = added.saturating_add(1);
                    if let Some(f) = current.as_mut() {
                        f.added = f.added.saturating_add(1);
                    }
                    continue;
                }
                Some(b'\\') => continue,
                // The hunk was shorter than announced.
                _ => {
                    old_left = 0;
                    new_left = 0;
                }
            }
        }
        if b.starts_with(b"\\") {
            continue;
        }
        let starts_header = b.starts_with(b"diff ") || b.starts_with(b"Index: ");
        let starts_unified = b.starts_with(b"--- ")
            && lines.peek().await?.is_some_and(|n| n.bytes.starts_with(b"+++ "));
        // `---` after a `diff` header belongs to the same file.
        let same_file = starts_unified && current.as_ref().is_some_and(|f| f.hunks == 0 && !f.unified);
        if starts_header || (starts_unified && !same_file) {
            match current.take() {
                Some(f) => push_file(&cx, span, f, before).await,
                None => preamble_end = Some(before),
            }
            files = files.saturating_add(1);
            let mut f = new_file(before);
            if let Some((old, new)) = git_paths(b) {
                f.old = old;
                f.new = new;
            }
            current = Some(f);
        }
        if starts_unified {
            if let Some(f) = current.as_mut() {
                f.old = path(line.piece());
                f.unified = true;
            }
            if let Some(next) = lines.next().await?
                && let Some(f) = current.as_mut()
            {
                f.new = path(next.piece());
            }
            continue;
        }
        if let Some((_, b_len, _, d_len)) = hunk_header(b) {
            old_left = b_len;
            new_left = d_len;
            if let Some(f) = current.as_mut() {
                f.hunks = f.hunks.saturating_add(1);
            }
        }
    }
    if let Some(end) = preamble_end.filter(|&e| e > 0) {
        cx.push(Node::new("Preamble").span(span.sub(0, end))).await;
    }
    cx.annotate(format!(
        "Unified diff: {}, +{} −{}",
        plural(files, "file", "files"),
        count(added),
        count(removed)
    ));
    Ok(())
}

/// A file: header lines, then hunks.
async fn file(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut hunk: Option<(u64, String)> = None;
    loop {
        let before = lines.pos();
        let line = lines.next().await?;
        let starts = line.as_ref().is_some_and(|l| hunk_header(&l.bytes).is_some());
        if line.is_none() || starts {
            if let Some((start, header)) = hunk.take() {
                let s = span.sub(start, before.saturating_sub(start));
                cx.push(Node::new(header).span(s).lazy(hunk_lines, s)).await;
            }
            let Some(l) = line else {
                break;
            };
            hunk = Some((l.start, l.text()));
            continue;
        }
        let Some(l) = line else {
            break;
        };
        if hunk.is_some() {
            continue;
        }
        let p = l.piece();
        let node = if p.starts_with(b"--- ") {
            text_node("Old file", p.from(4).span(), &path(p))
        } else if p.starts_with(b"+++ ") {
            text_node("New file", p.from(4).span(), &path(p))
        } else if let Some((key, value)) = extended_header(&p) {
            text_node(key, value.span(), &value.text())
        } else {
            text_node("Header", p.span(), &p.text())
        };
        cx.push(node).await;
    }
    Ok(())
}

/// Git extended header lines: `index abc..def 100644`, `new file mode
/// 100644`, `rename from x` → (`index`, `abc..def 100644`) ...
fn extended_header<'a>(p: &Piece<'a>) -> Option<(String, Piece<'a>)> {
    const KEYS: &[&str] = &[
        "diff --git", "index", "new file mode", "deleted file mode", "old mode", "new mode",
        "similarity index", "dissimilarity index", "rename from", "rename to", "copy from",
        "copy to", "Index:", "Binary files",
    ];
    let text = p.text();
    let key = KEYS.iter().find(|k| text.starts_with(*k))?;
    Some(((*key).trim_end_matches(':').to_owned(), p.from(key.len()).trim()))
}

/// The lines of a hunk, numbered in the old and new file.
async fn hunk_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let Some(header) = lines.next().await? else {
        return Ok(());
    };
    let Some((mut old, _, mut new, _)) = hunk_header(&header.bytes) else {
        return Err(Diagnostic::malformed("invalid hunk header").at(header.span));
    };
    if let Some(ctx) = header.piece().from(4).find_seq(b" @@").map(|i| header.piece().from(4).from(i.saturating_add(3)).trim())
        && !ctx.is_empty()
    {
        cx.push(text_node("Context", ctx.span(), &ctx.text())).await;
    }
    while let Some(line) = lines.next().await? {
        let p = line.piece();
        let content = p.from(1);
        let (name, summary) = match p.first() {
            Some(b'+') => {
                new = new.saturating_add(1);
                ("Added", format!("new line {}", new.saturating_sub(1)))
            }
            Some(b'-') => {
                old = old.saturating_add(1);
                ("Removed", format!("old line {}", old.saturating_sub(1)))
            }
            Some(b'\\') => ("Note", String::new()),
            _ => {
                old = old.saturating_add(1);
                new = new.saturating_add(1);
                ("Context", format!("line {} → {}", old.saturating_sub(1), new.saturating_sub(1)))
            }
        };
        let mut node = text_node(name, line.span, &content.text());
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        cx.push(node).await;
    }
    Ok(())
}
