//! TeX device-independent output (DVI).

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::val::text;
use crate::formats::{Input, Probe};
use crate::node::Node;

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// TeX DVI

declare_format!(pub DVI = "dvi", "TeX device-independent output", ["dvi"], "application/x-dvi",
    Probe::Magic(&[(0, b"\xf7\x02"), (0, b"\xf7\x05")]), dvi);

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
    if end >= 5 && tail.get(end.saturating_sub(5)) == Some(&249) {
        let post = u64::from(u32_be(&tail, end.saturating_sub(4)).unwrap_or(0));
        let p = cx.read_avail(file.sub(post, 29)).await?;
        pages = crate::bytes::u16_be(&p, 27);
        cx.emit(Node::new("Postamble").span(file.sub(post, file.len.saturating_sub(post))));
    }
    cx.emit(Node::new("Pages").span(file.sub(15u64.saturating_add(k.into()), file.len)));
    cx.annotate(format!(
        "DVI (id {id}), {}{}, magnification {mag}",
        comment.trim(),
        pages.map_or(String::new(), |p| format!(", {p} pages"))
    ));
    Ok(())
}
