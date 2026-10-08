//! Android text artifacts: build properties (`build.prop`), native crash
//! tombstones and ANR stack-trace dumps (`traces.txt`).

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::ml::text::block_lines;
use crate::formats::text::probe::{self, significant};
use crate::formats::text::scan::Lines;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// build.prop

fn is_property(line: &[u8]) -> bool {
    let Some(eq) = line.iter().position(|&b| b == b'=') else {
        return false;
    };
    eq > 0
        && line.get(..eq).is_some_and(|k| {
            k.iter()
                .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

fn build_prop_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    let lines: Vec<&[u8]> = significant(&data, &[b"#"]).take(8).collect();
    lines.len() >= 3
        && lines
            .iter()
            .take(lines.len().saturating_sub(1))
            .all(|l| is_property(l))
        && lines.iter().filter(|l| l.starts_with(b"ro.")).count() >= 2
}

declare_format!(pub BUILD_PROP = "android-build-prop", "Android build properties (build.prop)", ["prop"], "text/x-android-prop",
    Probe::Custom(build_prop_probe), build_prop);

async fn build_prop(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut props = Vec::<(String, String)>::new();
    let mut section: Option<(u64, String, u64)> = None;
    let close = |section: &mut Option<(u64, String, u64)>, end: u64| {
        section.take().map(|(start, name, n)| {
            let span = file.sub(start, end.saturating_sub(start));
            Node::new(name)
                .span(span)
                .summary(format!("{n} properties"))
                .lazy(block_lines, span)
        })
    };
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(line.start));
        let t = line.text();
        let trimmed = t.trim();
        if let Some(name) = trimmed.strip_prefix("# begin ") {
            if let Some(node) = close(&mut section, line.start) {
                cx.push(node).await;
            }
            section = Some((line.start, name.to_owned(), 0));
            continue;
        }
        if trimmed.starts_with("# end ") {
            if let Some(node) = close(&mut section, line.next) {
                cx.push(node).await;
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (key, value) = trimmed.split_once('=').unwrap_or((trimmed, ""));
        props.push((key.to_owned(), value.to_owned()));
        if let Some((_, _, n)) = section.as_mut() {
            *n = n.saturating_add(1);
        } else {
            cx.push(Node::new(key.to_owned()).span(line.span).value(text(value)))
                .await;
        }
    }
    if let Some(node) = close(&mut section, file.len) {
        cx.push(node).await;
    }
    let get = |k: &str| props.iter().find(|(p, _)| p == k).map(|(_, v)| v.as_str());
    let device = get("ro.product.model")
        .or_else(|| get("ro.product.system.model"))
        .or_else(|| get("ro.product.vendor.model"))
        .unwrap_or("");
    let release = get("ro.build.version.release")
        .or_else(|| get("ro.system.build.version.release"))
        .or_else(|| get("ro.vendor.build.version.release"))
        .unwrap_or("?");
    let id = get("ro.build.display.id")
        .or_else(|| get("ro.build.id"))
        .unwrap_or("");
    cx.annotate(
        format!(
            "Android build properties, {} entries, Android {release} {id} {device}",
            props.len()
        )
        .trim_end()
        .to_owned(),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Tombstones and ANR traces

const TOMBSTONE: &[u8] = b"*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***";

declare_format!(pub TOMBSTONE_FORMAT = "android-tombstone", "Android native crash tombstone", ["txt"], "text/x-android-tombstone",
    Probe::Magic(&[(0, TOMBSTONE)]), tombstone);

/// Section headings in tombstones (lines that start a block).
fn tombstone_section(t: &str) -> bool {
    let t = t.trim_end();
    t == "backtrace:"
        || t == "stack:"
        || t.starts_with("memory map")
        || t.starts_with("memory near ")
        || t.starts_with("code around ")
        || t.starts_with("--- --- ---")
        || t.starts_with("open files:")
        || t.starts_with("log main:")
        || t.starts_with("log system:")
        || t.starts_with("logcat:")
}

async fn tombstone(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut section: Option<(u64, String, u64)> = None;
    let mut process = String::new();
    let mut signal = String::new();
    let mut fingerprint = String::new();
    loop {
        let line = lines.next().await?;
        let t = line.as_ref().map(|l| l.text()).unwrap_or_default();
        let starts = line.is_some() && tombstone_section(&t);
        if (starts || line.is_none())
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
        if starts {
            section = Some((line.start, t.trim().trim_end_matches(':').to_owned(), 0));
            continue;
        }
        if let Some((_, _, n)) = section.as_mut() {
            *n = n.saturating_add(1);
            continue;
        }
        if line.number == 1 || line.is_blank() {
            continue;
        }
        let node = if let Some(rest) = t.strip_prefix("pid: ") {
            process = rest
                .split(">>>")
                .nth(1)
                .and_then(|r| r.split("<<<").next())
                .unwrap_or(rest)
                .trim()
                .to_owned();
            Node::new("Thread").value(text(format!("pid: {rest}")))
        } else if t.starts_with("signal ") {
            signal = t.split(',').next().unwrap_or_default().to_owned();
            Node::new("Signal").value(text(t.trim()))
        } else if let Some((key, value)) = t.split_once(": ").filter(|(k, _)| !k.starts_with(' ')) {
            if key == "Build fingerprint" {
                fingerprint = value.trim_matches('\'').to_owned();
            }
            Node::new(key.trim().to_owned()).value(text(value.trim()))
        } else {
            Node::new(format!("Line {}", line.number)).value(text(t.trim()))
        };
        cx.push(node.span(line.span)).await;
    }
    cx.annotate(format!(
        "Android tombstone: {process}, {signal}, {fingerprint}"
    ));
    Ok(())
}

fn anr_probe(h: &Head<'_>) -> bool {
    let data = probe::trim_start(h.data);
    data.starts_with(b"----- pid ") && probe::contains(data, b" at ")
}

declare_format!(pub ANR = "android-anr-trace", "Android ANR stack traces (traces.txt)", ["txt"], "text/x-android-traces",
    Probe::Custom(anr_probe), anr);

async fn anr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut current: Option<(u64, String, String, u64)> = None;
    let mut processes = 0u64;
    let mut first = String::new();
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(line.start));
        let t = line.text();
        if let Some(rest) = t.strip_prefix("----- pid ") {
            let pid = rest.split(' ').next().unwrap_or_default().to_owned();
            let at = rest
                .split(" at ")
                .nth(1)
                .unwrap_or_default()
                .trim_end_matches(" -----")
                .to_owned();
            current = Some((line.start, pid, at, 0));
            continue;
        }
        if let Some((_, _, _, threads)) = current.as_mut() {
            if t.starts_with('"') {
                *threads = threads.saturating_add(1);
            }
            if let Some(cmd) = t.strip_prefix("Cmd line: ")
                && first.is_empty()
            {
                first = cmd.to_owned();
            }
        }
        if t.starts_with("----- end ")
            && let Some((start, pid, at, threads)) = current.take()
        {
            let span = file.sub(start, line.next.saturating_sub(start));
            cx.push(
                Node::new(format!("pid {pid}"))
                    .span(span)
                    .value(text(at))
                    .summary(format!("{threads} threads"))
                    .lazy(anr_process, span),
            )
            .await;
            processes = processes.saturating_add(1);
        }
    }
    cx.annotate(format!(
        "Android ANR traces, {processes} process(es), {first}"
    ));
    Ok(())
}

/// A process block: header lines, then one node per thread.
async fn anr_process(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut thread: Option<(u64, String, String)> = None;
    loop {
        let line = lines.next().await?;
        let t = line.as_ref().map(|l| l.text()).unwrap_or_default();
        let ends = line.is_none() || t.starts_with('"') || t.starts_with("----- end ");
        if ends && let Some((start, name, state)) = thread.take() {
            let end = line.as_ref().map_or(span.len, |l| l.start);
            let s = span.sub(start, end.saturating_sub(start));
            cx.push(
                Node::new(name)
                    .span(s)
                    .value(text(state))
                    .lazy(block_lines, s),
            )
            .await;
        }
        let Some(line) = line else { break };
        if t.starts_with('"') {
            let name = t.split('"').nth(1).unwrap_or_default().to_owned();
            let state = t.rsplit(' ').next().unwrap_or_default().to_owned();
            thread = Some((line.start, name, state));
        } else if thread.is_none() && !line.is_blank() {
            let node = match t.split_once(": ") {
                Some((k, v)) => Node::new(k.to_owned()).value(text(v)),
                None => Node::new(format!("Line {}", line.number)).value(text(t.trim())),
            };
            cx.push(node.span(line.span)).await;
        }
    }
    Ok(())
}
