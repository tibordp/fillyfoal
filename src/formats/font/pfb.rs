//! PostScript Type 1 fonts in PFB (printer font binary) form.
//!
//! The file is a sequence of segments `0x80, type, length (LE)`: ASCII
//! (cleartext font dictionary), binary (eexec-encrypted part) and EOF.

use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::datakit::{clip, text_preview};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "pfb",
    title: "PostScript Type 1 font (PFB)",
    extensions: &["pfb"],
    mime: "application/x-font-type1",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// An ASCII segment of plausible length whose text starts with `%!`.
fn probe(h: &crate::formats::Head<'_>) -> bool {
    h.starts_with(b"\x80\x01")
        && h.at(6, b"%!")
        && crate::bytes::u32_le(h.data, 2).is_some_and(|n| n >= 16 && u64::from(n) < h.len)
}

const SEGMENTS: EnumTable = &[(1, "ASCII"), (2, "Binary (eexec)"), (3, "End of file")];

/// The value of a `/Key (value)` or `/Key /Value` entry in cleartext.
fn ps_entry(text: &str, key: &str) -> Option<String> {
    let at = text.find(key)?;
    let rest = text.get(at.saturating_add(key.len())..)?.trim_start();
    if let Some(inner) = rest.strip_prefix('(') {
        return inner.split(')').next().map(str::to_owned);
    }
    rest.strip_prefix('/')
        .and_then(|r| r.split_whitespace().next())
        .map(str::to_owned)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, Endian::Little);
    let mut index = 0u32;
    while cur.remaining() >= 2 {
        let start = cur.pos();
        let marker = cur.u8().await?;
        let kind = cur.u8().await?;
        if marker != 0x80 {
            return Err(Diagnostic::malformed("expected a segment marker").at(file.sub(start, 1)));
        }
        if kind == 3 {
            cx.emit(
                Node::new("End of file")
                    .span(cur.since(start))
                    .value(Value::Enum { raw: 3, bits: 8, name: lookup(SEGMENTS, 3) }),
            );
            break;
        }
        let len = cur.u32().await?;
        let body = cur.span(len.into());
        cur.skip(len.into());
        let mut node = Node::new(format!("Segment {index}"))
            .span(cur.since(start))
            .value(Value::Enum {
                raw: kind.into(),
                bits: 8,
                name: lookup(SEGMENTS, kind.into()),
            })
            .summary(format!("{len} bytes"));
        if kind == 1 {
            let text = text_preview(&cx, body, 0x2000).await?;
            if index == 0 {
                let name = ps_entry(&text, "/FontName").unwrap_or_default();
                let full = ps_entry(&text, "/FullName").unwrap_or_default();
                cx.annotate(format!("PostScript Type 1 font {name}, {full:?}"));
            }
            node = node.lazy(ascii_segment, body);
        } else if kind == 2 {
            node = node.lazy(binary_segment, body);
        }
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn ascii_segment(cx: Cx, body: Span) -> Result<()> {
    let text = text_preview(&cx, body, 0x2000).await?;
    let header = text.lines().next().unwrap_or_default().to_owned();
    cx.emit(Node::new("Header").value(Value::Text(header)));
    for key in ["/FontName", "/FullName", "/FamilyName", "/Weight", "/version", "/Notice", "/FontType", "/ItalicAngle", "/isFixedPitch"] {
        if let Some(v) = ps_entry(&text, key) {
            cx.emit(Node::new(key.trim_start_matches('/').to_owned()).value(Value::Text(clip(&v, 200))));
        }
    }
    cx.emit(Node::new("Text").span(body).summary(format!("{} bytes", body.len)));
    Ok(())
}

async fn binary_segment(cx: Cx, body: Span) -> Result<()> {
    cx.emit(
        Node::new("eexec-encrypted data")
            .span(body)
            .desc("Private dictionary and CharStrings, encrypted with key 55665"),
    );
    Ok(())
}
