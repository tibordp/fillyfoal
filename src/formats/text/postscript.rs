//! PostScript and Encapsulated PostScript, structured by their Document
//! Structuring Conventions comments (`%%Title`, `%%BoundingBox`,
//! `%%Page` ...), and DOS EPS binary files with TIFF/WMF previews.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::{Format, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

use super::decode::preview;
use super::encoding::{Encoding, decode_8bit};
use super::scan::Lines;
use super::{plural, probe, text_node};

pub static EPS: Format = Format {
    name: "eps",
    title: "Encapsulated PostScript",
    extensions: &["eps", "epsf", "epsi", "ai"],
    mime: "application/postscript",
    probe: Probe::Custom(|h| {
        h.starts_with(b"%!PS-Adobe-")
            && probe::lines(h.data)
                .next()
                .is_some_and(|l| probe::contains(l, b"EPSF"))
    }),
    dissect: crate::expander!(dissect: Input),
};

pub static POSTSCRIPT: Format = Format {
    name: "postscript",
    title: "PostScript document",
    extensions: &["ps"],
    mime: "application/postscript",
    probe: Probe::Magic(&[(0, b"%!PS"), (0, b"\x04%!PS")]),
    dissect: crate::expander!(dissect: Input),
};

pub static DOS_EPS: Format = Format {
    name: "dos-eps",
    title: "DOS EPS binary file",
    extensions: &["eps", "epsf"],
    mime: "application/postscript",
    probe: Probe::Magic(&[(0, b"\xc5\xd0\xd3\xc6")]),
    dissect: crate::expander!(dissect_dos: Input),
};

record! {
    /// The DOS EPS binary header.
    pub struct DosHeader {
        magic: bytes[4] "Magic",
        ps_offset: u32 "PostScript offset" .hex(),
        ps_len: u32 "PostScript length" .hex(),
        wmf_offset: u32 "WMF offset" .hex(),
        wmf_len: u32 "WMF length" .hex(),
        tiff_offset: u32 "TIFF offset" .hex(),
        tiff_len: u32 "TIFF length" .hex(),
        checksum: u16 "Checksum" .hex() .desc("0xFFFF: none"),
    }
}

const LE: Endian = Endian::Little;

pub async fn dissect_dos(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let header = crate::fields::parse(
        &cx,
        span.sub(0, DosHeader::SIZE),
        LE,
        &(),
        DosHeader::layout,
    )
    .await?;
    cx.emit(DosHeader::node("Header", span.sub(0, DosHeader::SIZE), LE));
    let mut parts = Vec::new();
    let section = |offset: u32, len: u32| span.sub(offset.into(), len.into());
    if header.ps_len > 0 {
        let s = section(header.ps_offset, header.ps_len);
        cx.emit(embedded_as("PostScript", input.nested(s), &EPS));
        parts.push("PostScript");
    }
    if header.wmf_len > 0 {
        let s = section(header.wmf_offset, header.wmf_len);
        cx.emit(embedded("WMF preview", input.nested(s)));
        parts.push("WMF preview");
    }
    if header.tiff_len > 0 {
        let s = section(header.tiff_offset, header.tiff_len);
        cx.emit(embedded("TIFF preview", input.nested(s)));
        parts.push("TIFF preview");
    }
    cx.annotate(format!("DOS EPS binary: {}", parts.join(", ")));
    Ok(())
}

/// A DSC comment line: `%%Key: value` (or `%%Key`).
fn dsc(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let rest = line.strip_prefix(b"%%")?;
    let end = rest
        .iter()
        .position(|&b| b == b':' || b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    let key = rest.get(..end)?;
    let value = rest.get(end..).unwrap_or_default();
    let value = value.strip_prefix(b":").unwrap_or(value);
    Some((key, probe::trim(value)))
}

/// What a section is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Header,
    Code,
    Named,
    Page,
}

struct Open {
    name: String,
    kind: Kind,
    start: u64,
    first_line: u64,
    summary: String,
    end_marker: Option<&'static [u8]>,
}

#[derive(Clone, Debug)]
struct Section {
    span: Span,
    first_line: u64,
    header: bool,
}

async fn push(cx: &Cx, span: Span, open: Open, end: u64) {
    let len = end.saturating_sub(open.start);
    if len == 0 {
        return;
    }
    let s = span.sub(open.start, len);
    let mut node = Node::new(open.name).span(s);
    if !open.summary.is_empty() {
        node = node.summary(open.summary);
    }
    let state = Section {
        span: s,
        first_line: open.first_line,
        header: open.kind == Kind::Header,
    };
    cx.progress_in(span, span.offset.saturating_add(end));
    cx.push(node.lazy(section, state)).await;
}

/// Section names for `%%BeginX` comments.
fn begin_section(key: &[u8]) -> Option<(&'static str, &'static [u8])> {
    Some(match key {
        b"BeginProlog" => ("Prolog", b"EndProlog"),
        b"BeginSetup" => ("Setup", b"EndSetup"),
        b"BeginPreview" => ("Preview", b"EndPreview"),
        b"BeginDefaults" => ("Defaults", b"EndDefaults"),
        b"BeginPageSetup" => ("Page setup", b"EndPageSetup"),
        _ => return None,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let mut lines = Lines::new(&cx, span);
    let mut open: Option<Open> = Some(Open {
        name: "Header".to_owned(),
        kind: Kind::Header,
        start: 0,
        first_line: 0,
        summary: String::new(),
        end_marker: Some(b"EndComments"),
    });
    let mut title = None;
    let mut creator = None;
    let mut bbox = None;
    let mut pages_declared = None;
    let mut pages = 0u64;
    let mut eps = false;
    let mut first = true;
    loop {
        let before = lines.pos();
        let number = lines.number();
        let Some(line) = lines.next_bounds().await? else {
            if let Some(o) = open.take() {
                push(&cx, span, o, before).await;
            }
            break;
        };
        // Only the start of each line matters here.
        let head = lines.scanner().bytes(line.start, line.end, 256).await?;
        if first {
            first = false;
            eps = probe::contains(&head, b"EPSF");
            continue;
        }
        let Some((key, value)) = dsc(&head) else {
            // Plain code: closes the header, opens a code section.
            match &open {
                Some(o) if o.kind == Kind::Header => {
                    if let Some(o) = open.take() {
                        push(&cx, span, o, before).await;
                    }
                }
                Some(_) => continue,
                None => {}
            }
            open = Some(Open {
                name: "Code".to_owned(),
                kind: Kind::Code,
                start: before,
                first_line: number,
                summary: String::new(),
                end_marker: None,
            });
            continue;
        };
        let value_text = decode_8bit(value);
        if open.as_ref().is_some_and(|o| o.kind == Kind::Header) {
            match key {
                b"Title" => title = Some(value_text.trim_matches(['(', ')']).to_owned()),
                b"Creator" => creator = Some(value_text.trim_matches(['(', ')']).to_owned()),
                b"BoundingBox" if !value_text.starts_with("(atend)") => {
                    bbox = Some(value_text.clone())
                }
                b"Pages" => {
                    pages_declared = value_text
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<u64>().ok())
                }
                _ => {}
            }
        }
        // End of an explicit section (inclusive).
        if let Some(o) = &open
            && o.end_marker == Some(key)
        {
            if let Some(o) = open.take() {
                push(&cx, span, o, line.next).await;
            }
            continue;
        }
        let starts = if let Some((name, end)) = begin_section(key) {
            let mut summary = String::new();
            if key == b"BeginPreview" {
                summary = format!("{value_text} (width height depth lines)");
            }
            Some(Open {
                name: name.to_owned(),
                kind: Kind::Named,
                start: before,
                first_line: number,
                summary,
                end_marker: Some(end),
            })
        } else if key == b"Page" {
            pages = pages.saturating_add(1);
            let label = value_text
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            Some(Open {
                name: format!("Page {label}"),
                kind: Kind::Page,
                start: before,
                first_line: number,
                summary: format!("page {pages}"),
                end_marker: None,
            })
        } else if key == b"Trailer" {
            Some(Open {
                name: "Trailer".to_owned(),
                kind: Kind::Named,
                start: before,
                first_line: number,
                summary: String::new(),
                end_marker: Some(b"EOF"),
            })
        } else {
            None
        };
        if let Some(new) = starts {
            // Page setup belongs to its page.
            let nested = new.kind == Kind::Named
                && open.as_ref().is_some_and(|o| o.kind == Kind::Page)
                && new.name == "Page setup";
            if !nested {
                if let Some(o) = open.take() {
                    push(&cx, span, o, before).await;
                }
                open = Some(new);
            }
            continue;
        }
        if key == b"EOF" {
            if let Some(o) = open.take() {
                push(&cx, span, o, before).await;
            }
            cx.push(
                Node::new("%%EOF").span(span.sub(line.start, line.end.saturating_sub(line.start))),
            )
            .await;
            continue;
        }
        if open.is_none() {
            open = Some(Open {
                name: "Code".to_owned(),
                kind: Kind::Code,
                start: before,
                first_line: number,
                summary: String::new(),
                end_marker: None,
            });
        }
    }
    let mut summary = if eps {
        String::from("Encapsulated PostScript")
    } else {
        String::from("PostScript document")
    };
    if let Some(t) = title.filter(|t| !t.is_empty()) {
        summary = format!("{summary}: {}", preview(&t, 60));
    }
    if let Some(b) = bbox {
        let n: Vec<f64> = b
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        if let [x0, y0, x1, y1] = n.as_slice() {
            summary = format!("{summary}, {}×{} pt", x1 - x0, y1 - y0);
        }
    }
    let pages = pages_declared.unwrap_or(pages);
    if pages > 0 {
        summary = format!("{summary}, {}", plural(pages, "page", "pages"));
    }
    if let Some(c) = creator.filter(|c| !c.is_empty()) {
        summary = format!("{summary} ({})", preview(&c, 40));
    }
    cx.annotate(summary);
    Ok(())
}

/// A section: DSC comments as fields (in the header), lines otherwise.
async fn section(cx: Cx, s: Section) -> Result<()> {
    if !s.header {
        return super::plain::lines(cx, (s.span, Encoding::Utf8, s.first_line)).await;
    }
    let mut lines = Lines::new(&cx, s.span);
    let mut last: Option<String> = None;
    while let Some(line) = lines.next().await? {
        let p = line.piece();
        if p.starts_with(b"%!") {
            cx.push(text_node("Version", p.span(), &p.text())).await;
            continue;
        }
        let Some((key, _)) = dsc(p.bytes()) else {
            continue;
        };
        let key_text = decode_8bit(key);
        let value = p.from(key.len().saturating_add(2));
        let value = value.strip_prefix(b":").unwrap_or(value).trim();
        let name = if key_text == "+" {
            last.clone().unwrap_or_else(|| "+".to_owned())
        } else {
            last = Some(key_text.clone());
            key_text
        };
        if value.is_empty() {
            cx.push(Node::new(name).span(p.span())).await;
            continue;
        }
        let mut node = text_node(name.clone(), value.span(), &value.text());
        if name.ends_with("BoundingBox") {
            let n: Vec<f64> = value
                .text()
                .split_whitespace()
                .filter_map(|v| v.parse().ok())
                .collect();
            if let [x0, y0, x1, y1] = n.as_slice() {
                node = node.summary(format!("{}×{} pt at ({x0}, {y0})", x1 - x0, y1 - y0));
            }
        }
        if name == "CreationDate"
            && let Some(t) = super::parse_datetime(value.text().trim_matches(['(', ')']))
        {
            node = Node::new(name)
                .span(value.span())
                .value(Value::Timestamp { unix_seconds: t });
        }
        cx.push(node).await;
    }
    Ok(())
}
