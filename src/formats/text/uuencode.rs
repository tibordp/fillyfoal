//! uuencoded files (`begin 644 name` ... `end`) and their base64 variant
//! (`begin-base64`): each embedded file is decoded into a derived source and
//! dissected.

use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::{self, Decoded, Transform};
use super::encoding::prepare;
use super::scan::Lines;
use super::{plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "uuencode",
    title: "uuencoded data",
    extensions: &["uue", "uu", "xxe"],
    mime: "text/x-uuencode",
    probe: Probe::Custom(|h| {
        let head = probe::head(h);
        probe::significant(&head, &[])
            .take(20)
            .any(|l| begin(l).is_some())
            && probe::is_text(h)
    }),
    dissect: crate::expander!(dissect: Input),
};

/// `begin[-base64] MODE NAME`: (base64?, mode, name).
fn begin(line: &[u8]) -> Option<(bool, &[u8], &[u8])> {
    let (base64, rest) = match line.strip_prefix(b"begin-base64 ") {
        Some(rest) => (true, rest),
        None => (false, line.strip_prefix(b"begin ")?),
    };
    let space = rest.iter().position(|&b| b == b' ')?;
    let mode = rest.get(..space)?;
    let name = probe::trim(rest.get(space.saturating_add(1)..)?);
    ((3..=4).contains(&mode.len())
        && mode.iter().all(|b| (b'0'..=b'7').contains(b))
        && !name.is_empty())
    .then_some((base64, mode, name))
}

/// Decodes uuencoded lines up to the terminating empty line.
fn uudecode(data: &[u8]) -> Decoded {
    let mut bytes = Vec::with_capacity((data.len() / 4).saturating_mul(3));
    let mut error = None;
    for line in data.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if matches!(line, b"`" | b" ") {
            break;
        }
        if !decode::uu_line(line, &mut bytes) && error.is_none() {
            error = Some("line shorter than its length character says".to_owned());
        }
    }
    Decoded { bytes, error }
}

#[derive(Clone, Debug)]
struct Block {
    input: Input,
    body: Span,
    base64: bool,
}

async fn content(cx: Cx, b: Block) -> Result<()> {
    let (span, error) = if b.base64 {
        decode::derive_with(&cx, b.body, Transform::Base64).await?
    } else {
        decode::derive(&cx, b.body, "uudecode", uudecode).await?
    };
    if let Some(e) = error {
        cx.diag(e);
    }
    cx.annotate(format!("{:#x} bytes decoded", span.len));
    crate::formats::dissect_or_data(cx, b.input.nested(span)).await
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let inner = prepared.input(input);
    let mut lines = Lines::new(&cx, span);
    let mut files = 0u64;
    while let Some(line) = lines.next().await? {
        let Some((base64, mode, name)) = begin(&line.bytes) else {
            continue;
        };
        let name = super::encoding::decode_8bit(name);
        let mode = String::from_utf8_lossy(mode).into_owned();
        let body_start = line.next;
        let mut body_end = body_start;
        let mut end_line = None;
        while let Some(l) = lines.next().await? {
            let t = l.piece().trim();
            if (!base64 && t.bytes() == b"end") || (base64 && t.bytes() == b"====") {
                end_line = Some(l);
                break;
            }
            body_end = l.next;
        }
        files = files.saturating_add(1);
        let body = span.sub(body_start, body_end.saturating_sub(body_start));
        let stop = end_line.as_ref().map_or(body_end, |l| l.next);
        let block = span.sub(line.start, stop.saturating_sub(line.start));
        let mut node = Node::new(name.clone())
            .span(block)
            .summary(format!(
                "mode {mode}, {}",
                if base64 { "base64" } else { "uuencoded" }
            ))
            .lazy(block_fields, (inner, block, body, base64, mode, name));
        if end_line.is_none() {
            node = node.diag(Diagnostic::new(DiagKind::Truncated, "end line missing"));
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "uuencoded data, {}",
        plural(files, "file", "files")
    ));
    Ok(())
}

async fn block_fields(
    cx: Cx,
    (input, block, body, base64, mode, name): (Input, Span, Span, bool, String, String),
) -> Result<()> {
    let first = block.sub(0, body.offset.saturating_sub(block.offset));
    cx.emit(text_node("File name", first, &name));
    cx.emit(
        Node::new("Mode")
            .value(Value::Text(mode))
            .desc("Unix permissions, octal"),
    );
    cx.emit(Node::new("Content").span(body).lazy(
        content,
        Block {
            input,
            body,
            base64,
        },
    ));
    Ok(())
}
