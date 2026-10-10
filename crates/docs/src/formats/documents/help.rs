//! Help and e-book formats: OS/2 INF/HLP, Psion TCR and AmigaGuide.

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::val::text;
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;

const LE: Endian = Endian::Little;

use crate::formats::text::scan::head_lines as lines;

// ---------------------------------------------------------------------------
// Help and e-book formats: OS/2 INF/HLP, Psion TCR, AmigaGuide

declare_format!(pub OS2_INF = "os2-inf", "OS/2 Information Presentation Facility (INF/HLP)", ["inf", "hlp"], "application/x-os2-inf",
    Probe::Magic(&[(0, b"HSP\x01"), (0, b"HSP\x10")]), os2_inf);

async fn os2_inf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x9b)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 3).emit()?;
    let kind = f
        .u8("Flags")
        .enumeration(&[(1, "INF"), (0x10, "HLP")])
        .emit()?;
    f.u16("Header size").emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    let toc = f.u16("Table of contents entries").emit()?;
    f.u32("Table of contents offset").hex().emit()?;
    f.u32("Table of contents size").emit()?;
    f.u32("TOC offsets offset").hex().emit()?;
    let resources = f.u16("Resource panels").emit()?;
    f.u32("Resource index offset").hex().emit()?;
    let names = f.u16("Named panels").emit()?;
    f.u32("Name index offset").hex().emit()?;
    let index = f.u16("Index entries").emit()?;
    f.u32("Index offset").hex().emit()?;
    f.u32("Index size").emit()?;
    f.bytes("Reserved", 10).emit()?;
    f.u32("Search table offset").hex().emit()?;
    f.u32("Search table size").emit()?;
    let slots = f.u16("Slots").emit()?;
    f.u32("Slot table offset").hex().emit()?;
    f.u32("Dictionary size").emit()?;
    let words = f.u16("Dictionary words").emit()?;
    f.u32("Dictionary offset").hex().emit()?;
    f.u32("Image offset").hex().emit()?;
    f.u8("Maximum TOC level").emit()?;
    f.u32("NLS table offset").hex().emit()?;
    f.u32("NLS table size").emit()?;
    f.u32("Extended header offset").hex().emit()?;
    f.bytes("Reserved", 12).emit()?;
    let title = f.ascii("Title", 48).emit()?;
    let _ = (resources, names);
    cx.annotate(format!(
        "OS/2 {} {major}.{minor} {:?}: {toc} topics, {index} index entries, {slots} slots, {words} words",
        if kind == 0x10 { "HLP" } else { "INF" },
        title.trim()
    ));
    Ok(())
}

declare_format!(pub TCR = "psion-tcr", "Psion TCR text", ["tcr"], "text/x-psion-tcr",
    Probe::Magic(&[(0, b"!!8-Bit!!")]), tcr);

async fn tcr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 9)));
    // 256 Pascal strings: the dictionary each output byte expands to.
    let mut pos = 9u64;
    let mut sample = Vec::new();
    for i in 0..256u32 {
        let len = u64::from(
            cx.read(file.sub_exact(pos, 1)?)
                .await?
                .first()
                .copied()
                .unwrap_or(0),
        );
        if i < 8 {
            sample.push(
                String::from_utf8_lossy(&cx.read(file.sub(pos.saturating_add(1), len)).await?)
                    .into_owned(),
            );
        }
        pos = pos.saturating_add(1).saturating_add(len);
    }
    cx.emit(
        Node::new("Dictionary")
            .span(file.sub(9, pos.saturating_sub(9)))
            .summary(format!("256 entries, starting {sample:?}")),
    );
    cx.emit(Node::new("Compressed text").span(file.tail(pos)));
    cx.annotate(format!(
        "Psion TCR, {} compressed bytes",
        file.len.saturating_sub(pos)
    ));
    Ok(())
}

declare_format!(pub AMIGAGUIDE = "amigaguide", "AmigaGuide hypertext", ["guide"], "text/x-amigaguide",
    Probe::Magic(&[(0, b"@database"), (0, b"@DATABASE")]), amigaguide);

async fn amigaguide(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut nodes = 0u32;
    let mut open: Option<(String, String, Span)> = None;
    for (n, (line, span)) in all.iter().enumerate() {
        if n % 1024 == 1023 {
            cx.checkpoint().await;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("@node") {
            let rest = line.get(5..).unwrap_or(rest).trim();
            let (name, title) = match rest.split_once(' ') {
                Some((n, t)) => (n.to_owned(), t.trim_matches('"').to_owned()),
                None => (rest.to_owned(), String::new()),
            };
            open = Some((name, title, *span));
        } else if lower.starts_with("@endnode") {
            if let Some((name, title, start)) = open.take() {
                nodes = nodes.saturating_add(1);
                let whole = Span::new(
                    start.source,
                    start.offset,
                    span.end().saturating_sub(start.offset),
                );
                cx.push(Node::new(name).span(whole).summary(title)).await;
            }
        } else if open.is_none() && line.starts_with('@') {
            let (k, v) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            cx.push(
                Node::new(k.to_owned())
                    .span(*span)
                    .value(text(v.trim_matches('"'))),
            )
            .await;
        }
    }
    cx.annotate(format!("AmigaGuide, {nodes} nodes"));
    Ok(())
}
