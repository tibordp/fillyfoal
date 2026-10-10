//! Linux swap areas: a header page ending in `SWAPSPACE2` (or the old
//! `SWAP-SPACE` bitmap format).

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{size, text, uuid_value};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;

const LE: Endian = Endian::Little;
/// Page sizes whose signature the probe can see.
const PAGES: [u64; 4] = [4096, 8192, 16384, 32768];

pub static FORMAT: Format = Format {
    name: "swap",
    title: "Linux swap area",
    extensions: &["swap", "swp"],
    mime: "application/x-linux-swap",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn signature_at(page: u64) -> usize {
    crate::bytes::to_usize(page.saturating_sub(10))
}

fn probe(h: &Head<'_>) -> bool {
    PAGES
        .iter()
        .any(|&p| h.at(signature_at(p), b"SWAPSPACE2") || h.at(signature_at(p), b"SWAP-SPACE"))
}

record! {
    /// `union swap_header.info`, after 1 KiB of boot bits.
    pub struct Info {
        version: u32 "Version",
        last_page: u32 "Last page",
        bad_pages: u32 "Bad pages",
        uuid: bytes[16] "UUID" .with(uuid_value),
        label: bytes[16] "Label" .with(|b, n| n.value(text(b))),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let area = input.span;
    let head = cx.read_avail(area.sub(0, 32768)).await?;
    let found = PAGES.iter().copied().find_map(|p| {
        let at = signature_at(p);
        let sig = head.get(at..at.saturating_add(10))?;
        (sig == b"SWAPSPACE2" || sig == b"SWAP-SPACE").then_some((p, sig == b"SWAPSPACE2"))
    });
    let Some((page, v2)) = found else {
        return Err(Diagnostic::malformed("no swap signature").at(area.sub(0, 4096)));
    };
    cx.emit(Node::new("Boot bits").span(area.sub(0, 1024)));
    let sig = area.sub(page.saturating_sub(10), 10);
    if !v2 {
        cx.annotate(format!(
            "Linux swap (old bitmap format), {}-byte pages",
            page
        ));
        cx.emit(
            Node::new("Page bitmap")
                .span(area.sub(0, page.saturating_sub(10)))
                .desc("One bit per usable page"),
        );
        cx.emit(Node::new("Signature").span(sig).value(text(b"SWAP-SPACE")));
        return Ok(());
    }
    let info_span = area.sub(1024, Info::SIZE);
    let info = parse(&cx, info_span, LE, &(), Info::layout).await?;
    let label = crate::text::until_nul(&info.label);
    let pages = u64::from(info.last_page).saturating_add(1);
    cx.annotate(format!(
        "Linux swap v{}{}, {} ({} pages of {})",
        info.version,
        if label.is_empty() {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(pages.saturating_mul(page)),
        pages,
        size(page),
    ));
    cx.emit(Info::node("Header", info_span, LE));
    if info.bad_pages > 0 {
        let count = u64::from(info.bad_pages).min(page.saturating_sub(1536) / 4);
        let list = area.sub(
            1024u64.saturating_add(Info::SIZE).saturating_add(117 * 4),
            count.saturating_mul(4),
        );
        let data = cx.read_avail(list).await?;
        let pages: Vec<String> = data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| u32::from_le_bytes(*b).to_string())
            .collect();
        cx.emit(Node::new("Bad pages").span(list).summary(pages.join(", ")));
    }
    cx.emit(Node::new("Signature").span(sig).value(text(b"SWAPSPACE2")));
    let used = area.sub(page, pages.saturating_sub(1).saturating_mul(page));
    let mut node = Node::new("Swap pages").span(used).summary(size(used.len));
    if to_u64(head.len()) < page {
        node = node.diag(Diagnostic::truncated(area.sub(0, page), to_u64(head.len())));
    }
    cx.emit(node);
    Ok(())
}
