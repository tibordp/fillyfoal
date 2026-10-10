//! Desktop publishing, graphic design, illustration, multimedia authoring,
//! font development and printer files.
//!
//! - [`adobe`]: Photoshop presets (brushes, patterns, gradients, styles,
//!   actions, curves, colour books, colour tables, custom shapes) and the
//!   action descriptor structure most of them share.
//! - [`dtp`]: page-layout documents (InDesign, QuarkXPress, Xara,
//!   Scribus).
//! - [`authoring`]: Director/Shockwave movies, HyperCard stacks, After
//!   Effects projects, Corel CMX, Figma, Rive, Live2D.
//! - [`design`]: pixel-art and paint-program images, palettes, gradients,
//!   colour lookup tables, metafiles (CGM, PICT) and GEM bitmaps.
//! - [`fonts`]: font sources and font binaries not covered elsewhere (CFF,
//!   FontForge, Glyphs, FontLab, Windows FNT/PFM, TeX TFM/VF, Amiga, PFR,
//!   BGI, UFO).
//! - [`printing`]: printer languages and descriptions (PJL, PCL, PCL XL,
//!   HP-GL, ESC/P, ZPL, PPD, GPD, CUPS and Apple raster).

pub mod adobe;
pub mod authoring;
pub mod design;
pub mod dtp;
pub mod fonts;
pub mod printing;

pub(crate) use crate::formats::image::psd::descriptor::Rd;
use crate::formats::text::piece::Piece;
use crate::formats::text::xml;
use crate::span::Span;

/// The value of attribute `name` in the first `tag` start tag (`b"<glyph"`)
/// of `head`, a prefix of `span` read for a summary.
pub(crate) fn tag_attr(head: &[u8], span: Span, tag: &[u8], name: &str) -> Option<String> {
    let mut from = 0;
    let start = loop {
        let at = crate::bytes::find(head, tag, from)?;
        let next = head.get(at.saturating_add(tag.len())).copied();
        if next.is_none_or(|b| b.is_ascii_whitespace() || b == b'>' || b == b'/') {
            break at;
        }
        from = at.saturating_add(1);
    };
    let piece = Piece::new(head.get(start..)?, span.sub(crate::bytes::to_u64(start), 0));
    xml::attributes(piece)
        .into_iter()
        .find(|a| a.name.bytes() == name.as_bytes())?
        .value
        .map(|v| xml::decode_entities(&v.text(), false))
}
