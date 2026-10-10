//! Adobe font metrics (AFM) and ASCII Type 1 fonts (PFA).

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::util::val::text;
use crate::formats::{Input, Probe};
use crate::node::Node;

use crate::formats::text::scan::head_lines as lines;

// ---------------------------------------------------------------------------
// Adobe font metrics and PFA fonts

declare_format!(pub AFM = "afm", "Adobe font metrics", ["afm"], "application/x-font-afm",
    Probe::Magic(&[(0, b"StartFontMetrics")]), afm);

async fn afm(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut name = String::new();
    let mut chars = 0u32;
    for (n, (line, span)) in all.iter().enumerate() {
        if n % 1024 == 1023 {
            cx.checkpoint().await;
        }
        let (k, v) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        match k {
            "FontName" | "FullName" | "FamilyName" | "Weight" | "Version" | "Notice"
            | "EncodingScheme" | "ItalicAngle" | "IsFixedPitch" | "FontBBox" | "CapHeight"
            | "XHeight" | "Ascender" | "Descender" | "StartFontMetrics" => {
                if k == "FontName" {
                    name = v.to_owned();
                }
                cx.emit(Node::new(k.to_owned()).span(*span).value(text(v)));
            }
            "StartCharMetrics" => chars = v.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    cx.annotate(format!("{name}, {chars} character metrics"));
    Ok(())
}

declare_format!(pub PFA = "pfa", "PostScript Type 1 font (ASCII)", ["pfa", "pfb.txt", "t1"], "application/x-font-type1",
    Probe::Magic(&[(0, b"%!PS-AdobeFont-"), (0, b"%!FontType1")]), pfa);

async fn pfa(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 8192).await?;
    let first = all.first().map(|(l, _)| l.clone()).unwrap_or_default();
    if let Some((_, span)) = all.first() {
        cx.emit(Node::new("Header").span(*span).value(text(first.clone())));
    }
    let mut name = first
        .split(':')
        .nth(1)
        .unwrap_or_default()
        .trim()
        .to_owned();
    for (line, span) in &all {
        if let Some(rest) = line.trim().strip_prefix("/FontName") {
            name = rest
                .trim()
                .trim_start_matches('/')
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            cx.emit(Node::new("FontName").span(*span).value(text(name.clone())));
        } else if line.contains("eexec") {
            let encrypted = input
                .span
                .tail(span.end().saturating_sub(input.span.offset));
            cx.emit(crate::formats::font::type1::private_node(
                input, encrypted, true,
            ));
            break;
        }
    }
    cx.annotate(format!("Type 1 font {name}"));
    Ok(())
}
