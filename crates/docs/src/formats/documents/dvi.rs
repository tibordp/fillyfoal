//! TeX device-independent output (DVI).

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::plural;
use crate::formats::util::val::text;
use crate::formats::{Input, Probe};
use crate::node::Node;

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// TeX DVI

// Identification bytes: 2 for TeX, 3 for pTeX with direction commands,
// 5, 6 and 7 for XeTeX's extended DVI (`.xdv`; 7 since XeTeX 0.99996, the
// current TeX Live). Only the preamble and postamble are read, so the XDV
// opcodes need no handling here.
declare_format!(pub DVI = "dvi", "TeX device-independent output", ["dvi", "xdv"], "application/x-dvi",
    Probe::Magic(&[
        (0, b"\xf7\x02"),
        (0, b"\xf7\x03"),
        (0, b"\xf7\x05"),
        (0, b"\xf7\x06"),
        (0, b"\xf7\x07"),
    ]), dvi);

async fn dvi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 15)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u8("pre").hex().emit()?;
    let id = f.u8("Identification").emit()?;
    f.u32("Numerator").emit()?;
    f.u32("Denominator").emit()?;
    let mag = f.u32("Magnification").emit()?;
    let k = f.u8("Comment length").emit()?;
    let comment = cx.read_avail(file.sub(15, k.into())).await?;
    let comment = String::from_utf8_lossy(&comment).into_owned();
    cx.emit(
        Node::new("Comment")
            .span(file.sub(15, k.into()))
            .value(text(comment.trim())),
    );
    // The postamble is found from the end: post_post, then 4+ 223 bytes.
    let tail = cx.read(file.sub(file.len.saturating_sub(64), 64)).await?;
    let end = tail.iter().rposition(|&b| b != 223).unwrap_or(0);
    let mut pages = None;
    let mut pages_end = file.len;
    if end >= 5 && tail.get(end.saturating_sub(5)) == Some(&249) {
        let post = u64::from(u32_be(&tail, end.saturating_sub(4)).unwrap_or(0));
        let p = cx.read_avail(file.sub(post, 29)).await?;
        pages = crate::bytes::u16_be(&p, 27);
        pages_end = post.min(file.len);
        cx.emit(Node::new("Postamble").span(file.sub(post, file.len.saturating_sub(post))));
    }
    let pages_at = 15u64.saturating_add(k.into());
    cx.emit(Node::new("Pages").span(file.sub(pages_at, pages_end.saturating_sub(pages_at))));
    cx.annotate(format!(
        "DVI (id {id}), {}{}, magnification {mag}",
        comment.trim(),
        pages.map_or(String::new(), |p| format!(
            ", {p_page}",
            p_page = plural(p, "page")
        ))
    ));
    Ok(())
}
