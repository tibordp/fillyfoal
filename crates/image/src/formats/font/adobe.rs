//! Adobe font metrics (AFM) and ASCII Type 1 fonts (PFA).

use crate::bytes::to_u64;
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
            let rest = input
                .span
                .tail(span.end().saturating_sub(input.span.offset));
            // The encrypted part starts after the line break: hex digits
            // in a PFA file, binary when the font program comes from a
            // PDF `/FontFile` or a PFB segment saved as is. A clear-text
            // part on its own (PDF's `/Length1` bytes) ends here.
            let head = cx.read_avail(rest.sub(0, 64)).await?;
            let skip = head
                .iter()
                .take_while(|&&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                .count();
            let encrypted = rest.tail(to_u64(skip));
            if !encrypted.is_empty() {
                let hex = head
                    .get(skip..skip.saturating_add(4))
                    .is_some_and(|h| h.len() == 4 && h.iter().all(u8::is_ascii_hexdigit));
                cx.emit(crate::formats::font::type1::private_node(
                    input, encrypted, hex,
                ));
            }
            break;
        }
    }
    cx.annotate(format!("Type 1 font {name}"));
    Ok(())
}
