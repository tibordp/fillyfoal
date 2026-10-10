//! WARC web archives (ISO 28500).

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::val::text;
use crate::formats::{Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;

// ---------------------------------------------------------------------------
// WARC web archives

declare_format!(pub WARC = "warc", "Web archive (WARC)", ["warc"], "application/warc",
    Probe::Magic(&[(0, b"WARC/1.0\r\n"), (0, b"WARC/1.1\r\n"), (0, b"WARC/0.")]), warc);

async fn warc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut records = 0u32;
    while pos < file.len {
        let head = cx.read_avail(file.sub(pos, 16384)).await?;
        let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
            cx.diag(Diagnostic::malformed("record headers do not end").at(file.sub(pos, 4)));
            break;
        };
        let headers = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
        let field = |name: &str| {
            headers.lines().find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.trim().to_owned())
            })
        };
        let length: u64 = field("Content-Length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let kind = field("WARC-Type").unwrap_or_default();
        let target = field("WARC-Target-URI").unwrap_or_default();
        let header_len = to_u64(end).saturating_add(4);
        let block = file.sub(pos.saturating_add(header_len), length);
        let total = header_len.saturating_add(length).saturating_add(4);
        records = records.saturating_add(1);
        cx.progress_in(file, file.offset.saturating_add(pos).saturating_add(total));
        cx.push(
            Node::new(format!("{kind} {target}").trim().to_owned())
                .span(file.sub(pos, total))
                .lazy(
                    warc_record,
                    (input, file.sub(pos, to_u64(end)), block, headers),
                ),
        )
        .await;
        pos = pos.saturating_add(total);
    }
    cx.annotate(format!("WARC, {records} records"));
    Ok(())
}

async fn warc_record(
    cx: Cx,
    (input, header_span, block, headers): (Input, Span, Span, String),
) -> Result<()> {
    let mut at = 0u64;
    for line in headers.split("\r\n") {
        let len = to_u64(line.len());
        if let Some((k, v)) = line.split_once(':') {
            cx.emit(
                Node::new(k.trim().to_owned())
                    .span(header_span.sub(at, len))
                    .value(text(v.trim())),
            );
        } else {
            cx.emit(
                Node::new("Version")
                    .span(header_span.sub(at, len))
                    .value(text(line)),
            );
        }
        at = at.saturating_add(len).saturating_add(2);
    }
    cx.emit(embedded("Content block", input.nested(block)).summary(format!("{} bytes", block.len)));
    Ok(())
}
