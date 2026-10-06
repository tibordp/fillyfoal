//! Dockerfiles (and Containerfiles): build stages, one per `FROM`, with
//! their instructions (continuation lines joined).

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

use super::decode::preview;
use super::encoding::prepare;
use super::scan::Lines;
use super::{plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "dockerfile",
    title: "Dockerfile",
    extensions: &["dockerfile", "containerfile"],
    mime: "text/x-dockerfile",
    probe: Probe::Custom(probe_dockerfile),
    dissect: crate::expander!(dissect: Input),
};

const INSTRUCTIONS: &[&str] = &[
    "FROM",
    "RUN",
    "CMD",
    "LABEL",
    "EXPOSE",
    "ENV",
    "ADD",
    "COPY",
    "ENTRYPOINT",
    "VOLUME",
    "USER",
    "WORKDIR",
    "ARG",
    "ONBUILD",
    "STOPSIGNAL",
    "HEALTHCHECK",
    "SHELL",
    "MAINTAINER",
];

fn instruction(line: &[u8]) -> Option<&'static str> {
    let t = probe::trim_start(line);
    let word = t.split(|b| b.is_ascii_whitespace()).next()?;
    INSTRUCTIONS
        .iter()
        .find(|i| word.eq_ignore_ascii_case(i.as_bytes()))
        .copied()
}

fn probe_dockerfile(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut continued = false;
    let mut seen = 0usize;
    let mut first: Option<&str> = None;
    for line in probe::significant(&head, &[b"#"]).take(40) {
        let t = probe::trim(line);
        if !continued {
            let Some(i) = instruction(line) else {
                return false;
            };
            first.get_or_insert(i);
            seen = seen.saturating_add(1);
        }
        continued = t.ends_with(b"\\");
    }
    matches!(first, Some("FROM" | "ARG")) && seen >= 2 && probe::is_text(h)
}

/// One instruction: keyword, arguments (continuations joined), span.
struct Instr {
    keyword: String,
    args: String,
    span: Span,
    start: u64,
}

/// Reads the next instruction, skipping blank and comment lines.
async fn next(lines: &mut Lines<'_>) -> Result<Option<Instr>> {
    loop {
        let Some(line) = lines.next().await? else {
            return Ok(None);
        };
        let t = line.piece().trim();
        if t.is_empty() || t.first() == Some(b'#') {
            continue;
        }
        let (word, rest) = t.split_word();
        let mut args = rest.text();
        let mut end = line.span.end();
        let mut continued = args.ends_with('\\');
        if continued {
            args.pop();
        }
        while continued {
            let Some(more) = lines.next().await? else {
                break;
            };
            let m = more.piece().trim();
            end = more.span.end();
            // Comment lines inside a continuation are skipped.
            if m.first() == Some(b'#') {
                continue;
            }
            args.push(' ');
            args.push_str(&m.text());
            continued = args.ends_with('\\');
            if continued {
                args.pop();
            }
        }
        let args = args.split_whitespace().collect::<Vec<_>>().join(" ");
        return Ok(Some(Instr {
            keyword: word.text().to_ascii_uppercase(),
            args,
            span: Span::new(
                line.span.source,
                line.span.offset,
                end.saturating_sub(line.span.offset),
            ),
            start: line.start,
        }));
    }
}

fn instr_node(i: &Instr) -> Node {
    text_node(i.keyword.clone(), i.span, &i.args)
}

#[derive(Clone, Debug)]
struct Stage {
    span: Span,
}

async fn stage(cx: Cx, s: Stage) -> Result<()> {
    let mut lines = Lines::new(&cx, s.span);
    while let Some(i) = next(&mut lines).await? {
        cx.push(instr_node(&i)).await;
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut current: Option<(u64, String, u64)> = None; // start, title, instructions
    let mut stages = 0u64;
    let mut images: Vec<String> = Vec::new();
    loop {
        let before = lines.pos();
        let instr = next(&mut lines).await?;
        let from = instr.as_ref().is_some_and(|i| i.keyword == "FROM");
        if instr.is_some() && !from {
            match (&mut current, &instr) {
                (Some((_, _, n)), _) => *n = n.saturating_add(1),
                (None, Some(i)) => cx.push(instr_node(i)).await,
                _ => {}
            }
            continue;
        }
        if let Some((start, title, n)) = current.take() {
            let s = span.sub(start, before.saturating_sub(start));
            cx.push(
                Node::new(title)
                    .span(s)
                    .summary(plural(n, "instruction", "instructions"))
                    .lazy(stage, Stage { span: s }),
            )
            .await;
        }
        let Some(i) = instr else {
            break;
        };
        stages = stages.saturating_add(1);
        let words: Vec<&str> = i
            .args
            .split_whitespace()
            .filter(|w| !w.starts_with("--"))
            .collect();
        let image = words.first().copied().unwrap_or_default().to_owned();
        let title = match words.as_slice() {
            [_, kw, name, ..] if kw.eq_ignore_ascii_case("as") => format!("Stage {name} ({image})"),
            _ => format!("Stage {stages} ({image})"),
        };
        images.push(image);
        current = Some((i.start, title, 1));
    }
    cx.annotate(format!(
        "Dockerfile, {}: {}",
        plural(stages, "stage", "stages"),
        preview(&images.join(", "), 80)
    ));
    Ok(())
}
