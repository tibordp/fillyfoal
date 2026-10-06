//! PuTTY private keys (`.ppk`).

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::text::decode::{Transform, decoded_node};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

use crate::formats::text::scan::head_lines as header_lines;

// ---------------------------------------------------------------------------
// Keys: PuTTY private keys

declare_format!(pub PPK = "putty-key", "PuTTY private key (PPK)", ["ppk"], "application/x-putty-private-key",
    Probe::Magic(&[(0, b"PuTTY-User-Key-File-")]), ppk);

async fn ppk(cx: Cx, input: Input) -> Result<()> {
    let all = header_lines(&cx, input.span, 1 << 16).await?;
    let mut version = String::new();
    let mut algorithm = String::new();
    let mut encryption = String::new();
    let mut comment = String::new();
    let mut i = 0usize;
    while let Some((line, span)) = all.get(i) {
        i = i.saturating_add(1);
        let Some((key, value)) = line.split_once(": ") else {
            continue;
        };
        if let Some(n) = key.strip_suffix("-Lines").map(str::to_owned) {
            let count: usize = value.trim().parse().unwrap_or(0);
            let (Some((_, first)), Some((_, last))) = (
                all.get(i),
                all.get(
                    i.saturating_add(count)
                        .saturating_sub(1)
                        .min(all.len().saturating_sub(1)),
                ),
            ) else {
                continue;
            };
            let body = Span::new(
                first.source,
                first.offset,
                last.end().saturating_sub(first.offset),
            );
            i = i.saturating_add(count);
            if n == "Public" {
                cx.emit(decoded_node("Public key", input, body, Transform::Base64));
            } else {
                cx.emit(Node::new(format!("{n} key")).span(body).summary(
                    if encryption == "none" {
                        "base64"
                    } else {
                        "encrypted, base64"
                    },
                ));
            }
            continue;
        }
        if let Some(v) = key.strip_prefix("PuTTY-User-Key-File-") {
            version = v.to_owned();
            algorithm = value.to_owned();
        }
        match key {
            "Encryption" => encryption = value.to_owned(),
            "Comment" => comment = value.to_owned(),
            _ => {}
        }
        cx.emit(Node::new(key.to_owned()).span(*span).value(text(value)));
    }
    cx.annotate(format!(
        "PuTTY v{version} {algorithm} key {comment:?}, encryption {encryption}"
    ));
    Ok(())
}
