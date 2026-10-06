//! Emacs Lisp byte-compiled files (`.elc`): a `;ELC` magic with the
//! bytecode format version, comment lines recording the compiler, and the
//! printed byte-code forms.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::binutil::{dec, ellipsize, text};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;

pub static FORMAT: Format = Format {
    name: "elc",
    title: "Emacs Lisp bytecode",
    extensions: &["elc"],
    mime: "application/x-elc",
    probe: Probe::Custom(|h| h.starts_with(b";ELC") && h.at(5, b"\0\0\0")),
    dissect: crate::expander!(dissect: Input),
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x1000)).await?;
    let version = head.get(4).copied().unwrap_or(0);
    cx.emit(Node::new("magic").span(file.sub(0, 4)).value(text(";ELC")));
    cx.emit(
        Node::new("version")
            .span(file.sub(4, 1))
            .value(dec(version.into(), 8))
            .desc("Bytecode format version (usually the Emacs major version)"),
    );
    cx.emit(Node::new("padding").span(file.sub(5, 3)));
    // Leading comment lines describe the compilation.
    let mut at = 8usize;
    let mut compiler = None;
    for line in head.get(8..).unwrap_or_default().split(|&b| b == b'\n') {
        let start = at;
        at = at.saturating_add(line.len()).saturating_add(1);
        let s = String::from_utf8_lossy(line).into_owned();
        if s.is_empty() {
            continue;
        }
        if !s.starts_with(';') {
            at = start;
            break;
        }
        if let Some(v) = s.strip_prefix(";;; in Emacs version ") {
            compiler = Some(v.trim().to_owned());
        }
        let span = file.sub(
            u64::try_from(start).unwrap_or(0),
            u64::try_from(line.len()).unwrap_or(0),
        );
        cx.emit(Node::new("comment").span(span).value(text(s)));
    }
    let code = file.tail(u64::try_from(at).unwrap_or(0));
    let preview = cx.read_avail(code.sub(0, 4096)).await?;
    cx.emit(
        Node::new("Byte-code forms")
            .span(code)
            .value(text(ellipsize(&String::from_utf8_lossy(&preview), 400))),
    );
    cx.annotate(match compiler {
        Some(v) => format!("Emacs Lisp bytecode (format {version}), compiled by Emacs {v}"),
        None => format!("Emacs Lisp bytecode (format {version})"),
    });
    Ok(())
}
