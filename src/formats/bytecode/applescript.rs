//! Compiled AppleScript (`.scpt`).

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::value::Value;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// Compiled AppleScript

declare_format!(pub APPLESCRIPT = "applescript", "Compiled AppleScript", ["scpt"], "application/x-applescript",
    Probe::Magic(&[(0, b"FasdUAS ")]), applescript);

async fn applescript(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let version = String::from_utf8_lossy(head.get(8..16).unwrap_or_default())
        .trim_end()
        .to_owned();
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 8))
            .value(text("FasdUAS")),
    );
    cx.emit(
        Node::new("Version")
            .span(file.sub(8, 8))
            .value(text(version.clone())),
    );
    cx.emit(Node::new("Serialized script").span(file.tail(16)));
    let tail = cx
        .read_avail(file.sub(file.len.saturating_sub(16), 16))
        .await?;
    if tail.windows(4).any(|w| w == b"ascr") {
        cx.emit(
            Node::new("Trailer")
                .span(file.sub(file.len.saturating_sub(16), 16))
                .summary("ascr marker"),
        );
    }
    cx.annotate(format!("compiled AppleScript (FasdUAS {version})"));
    Ok(())
}
