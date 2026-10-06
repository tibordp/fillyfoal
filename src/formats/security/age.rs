//! age encrypted files (`age-encryption.org/v1`).

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::value::Value;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// age encryption

declare_format!(pub AGE = "age", "age-encrypted file", ["age"], "application/x-age",
    Probe::Magic(&[(0, b"age-encryption.org/v1\n")]), age);

async fn age(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 16384)).await?;
    let mac = head
        .windows(4)
        .position(|w| w == b"\n---")
        .ok_or_else(|| Diagnostic::malformed("no header MAC line"))?;
    let header = String::from_utf8_lossy(head.get(..mac).unwrap_or_default()).into_owned();
    let mut pos = 0u64;
    let mut kinds = Vec::new();
    for line in header.split('\n') {
        let len = to_u64(line.len()).saturating_add(1);
        if let Some(stanza) = line.strip_prefix("-> ") {
            let kind = stanza
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            kinds.push(kind.clone());
            cx.emit(
                Node::new(format!("Recipient stanza ({kind})"))
                    .span(file.sub(pos, len))
                    .value(text(stanza)),
            );
        } else if pos == 0 {
            cx.emit(
                Node::new("Version")
                    .span(file.sub(pos, len))
                    .value(text(line)),
            );
        }
        pos = pos.saturating_add(len);
    }
    let mac_line_end = head
        .get(mac.saturating_add(1)..)
        .and_then(|r| r.iter().position(|&b| b == b'\n'))
        .map_or(head.len(), |p| {
            mac.saturating_add(1).saturating_add(p).saturating_add(1)
        });
    cx.emit(Node::new("Header MAC").span(file.sub(
        to_u64(mac).saturating_add(1),
        to_u64(mac_line_end.saturating_sub(mac).saturating_sub(1)),
    )));
    cx.emit(
        Node::new("Payload")
            .span(file.tail(to_u64(mac_line_end)))
            .diag(Diagnostic::note("ChaCha20-Poly1305 encrypted")),
    );
    cx.annotate(format!("age, recipients: {}", kinds.join(", ")));
    Ok(())
}
