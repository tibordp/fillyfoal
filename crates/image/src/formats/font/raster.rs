//! More bitmap fonts: PSF console fonts, BMFont binary, FIGlet, and TeX PK
//! and GF fonts.

use crate::bytes::{u16_le, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, Radix, Value, flag};

const LE: Endian = Endian::Little;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// NUL-terminated (or padded) Latin-1 text.
fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

use crate::formats::text::scan::head_lines as header_lines;

// ---------------------------------------------------------------------------
// Fonts: PSF console fonts, BMFont binary, FIGlet, TeX PK and GF

fn psf_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x72\xb5\x4a\x86")
        || h.starts_with(b"\x36\x04") && h.data.get(2).is_some_and(|&m| m < 8)
}

const PSF1_MODE: FlagTable = &[
    flag(1, "512 glyphs"),
    flag(2, "Unicode table"),
    flag(4, "Unicode sequences"),
];
const PSF2_FLAGS: FlagTable = &[flag(1, "Unicode table")];

declare_format!(pub PSF_FONT = "psf-font", "PC Screen Font (console font)", ["psf", "psfu"], "application/x-font-psf",
    Probe::Custom(psf_probe), psf_font);

async fn psf_font(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if cx.read(file.sub(0, 2)).await? == b"\x36\x04" {
        let head = cx.block(file.sub(0, 4)).await?;
        let mut f = Fields::emitting(&cx, &head, LE);
        f.u16("Magic").hex().emit()?;
        let mode = f.u8("Mode").flags(PSF1_MODE).emit()?;
        let height = f.u8("Glyph height").emit()?;
        let glyphs: u64 = if mode & 1 != 0 { 512 } else { 256 };
        let bitmaps = file.sub(4, glyphs.saturating_mul(height.into()));
        cx.emit(
            Node::new("Glyphs")
                .span(bitmaps)
                .summary(format!("{glyphs} × 8×{height}")),
        );
        if mode & 2 != 0 {
            cx.emit(
                Node::new("Unicode table")
                    .span(file.tail(bitmaps.end().saturating_sub(file.offset))),
            );
        }
        cx.annotate(format!("PSF1 font, {glyphs} glyphs, 8×{height}"));
    } else {
        let head = cx.block(file.sub(0, 32)).await?;
        let mut f = Fields::emitting(&cx, &head, LE);
        f.u32("Magic").hex().emit()?;
        f.u32("Version").emit()?;
        let header = f.u32("Header size").emit()?;
        let flags = f.u32("Flags").flags(PSF2_FLAGS).emit()?;
        let glyphs = f.u32("Glyphs").emit()?;
        let size = f.u32("Bytes per glyph").emit()?;
        let height = f.u32("Height").emit()?;
        let width = f.u32("Width").emit()?;
        let bitmaps = file.sub(header.into(), u64::from(glyphs).saturating_mul(size.into()));
        cx.emit(
            Node::new("Glyphs")
                .span(bitmaps)
                .summary(format!("{glyphs} × {width}×{height}")),
        );
        if flags & 1 != 0 {
            cx.emit(
                Node::new("Unicode table")
                    .span(file.tail(bitmaps.end().saturating_sub(file.offset))),
            );
        }
        cx.annotate(format!("PSF2 font, {glyphs} glyphs, {width}×{height}"));
    }
    Ok(())
}

declare_format!(pub BMFONT = "bmfont", "AngelCode bitmap font (binary)", ["fnt"], "application/x-bmfont",
    Probe::Magic(&[(0, b"BMF\x03")]), bmfont);

async fn bmfont(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(4);
    let mut name = String::new();
    let mut chars = 0u64;
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let kind = cur.u8().await?;
        let size = u64::from(cur.u32().await?);
        let body = file.sub(cur.pos(), size);
        let (label, summary) = match kind {
            1 => {
                let b = cx.read_avail(body.sub(0, 256)).await?;
                name = zstr(b.get(14..).unwrap_or_default());
                (
                    "Info",
                    format!(
                        "{name:?}, {} px",
                        i16::from_le_bytes([
                            b.first().copied().unwrap_or(0),
                            b.get(1).copied().unwrap_or(0)
                        ])
                    ),
                )
            }
            2 => {
                let b = cx.read_avail(body.sub(0, 15)).await?;
                (
                    "Common",
                    format!(
                        "line height {}, {} page(s)",
                        u16_le(&b, 0).unwrap_or(0),
                        u16_le(&b, 8).unwrap_or(0)
                    ),
                )
            }
            3 => (
                "Pages",
                String::from_utf8_lossy(&cx.read_avail(body.sub(0, 256)).await?)
                    .replace('\0', ", ")
                    .trim_end_matches(", ")
                    .to_owned(),
            ),
            4 => {
                chars = size / 20;
                ("Characters", format!("{chars} × 20 bytes"))
            }
            5 => ("Kerning pairs", format!("{} × 10 bytes", size / 10)),
            _ => ("Unknown block", format!("type {kind}")),
        };
        cx.push(
            Node::new(label)
                .span(file.sub(start, size.saturating_add(5)))
                .summary(summary),
        )
        .await;
        cur.skip(size);
    }
    cx.annotate(format!("BMFont {name:?}, {chars} characters"));
    Ok(())
}

declare_format!(pub FIGLET = "figlet", "FIGlet font", ["flf"], "application/x-figlet",
    Probe::Magic(&[(0, b"flf2a")]), figlet);

async fn figlet(cx: Cx, input: Input) -> Result<()> {
    let all = header_lines(&cx, input.span, 1 << 16).await?;
    let Some((first, span)) = all.first() else {
        return Ok(());
    };
    let params: Vec<&str> = first
        .get(6..)
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    let names = [
        "Height",
        "Baseline",
        "Maximum length",
        "Old layout",
        "Comment lines",
        "Print direction",
        "Full layout",
        "Code-tagged characters",
    ];
    cx.emit(Node::new("Signature").span(span.sub(0, 5)));
    cx.emit(
        Node::new("Hard blank")
            .span(span.sub(5, 1))
            .value(text(first.get(5..6).unwrap_or_default())),
    );
    for (label, value) in names.iter().zip(&params) {
        cx.emit(Node::new(*label).span(*span).value(text(*value)));
    }
    let comments: usize = params.get(4).and_then(|c| c.parse().ok()).unwrap_or(0);
    if let (Some((_, a)), Some((_, b))) = (
        all.get(1),
        all.get(comments.min(all.len().saturating_sub(1))),
    ) && comments > 0
    {
        cx.emit(Node::new("Comments").span(Span::new(
            a.source,
            a.offset,
            b.end().saturating_sub(a.offset),
        )));
    }
    cx.annotate(format!(
        "FIGlet font, height {}",
        params.first().unwrap_or(&"?")
    ));
    Ok(())
}

declare_format!(pub TEX_PK = "tex-pk", "TeX packed font (PK)", ["pk"], "application/x-tex-pk",
    Probe::Magic(&[(0, b"\xf7\x59")]), tex_pk);

declare_format!(pub TEX_GF = "tex-gf", "TeX generic font (GF)", ["gf"], "application/x-tex-gf",
    Probe::Magic(&[(0, b"\xf7\x83")]), tex_gf);

async fn tex_pk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let k = u64::from(cx.read(file.sub(2, 1)).await?.first().copied().unwrap_or(0));
    let comment = String::from_utf8_lossy(&cx.read(file.sub(3, k)).await?).into_owned();
    cx.emit(Node::new("Preamble").span(file.sub(0, k.saturating_add(19))));
    cx.emit(
        Node::new("Comment")
            .span(file.sub(3, k))
            .value(text(comment.clone())),
    );
    let rest = cx.read(file.sub(3u64.saturating_add(k), 16)).await?;
    let design = u32_be(&rest, 0).unwrap_or(0);
    cx.emit(
        Node::new("Design size")
            .span(file.sub(3u64.saturating_add(k), 4))
            .value(Value::Float(f64::from(design) / 1_048_576.0))
            .summary("pt"),
    );
    cx.emit(
        Node::new("Checksum")
            .span(file.sub(7u64.saturating_add(k), 4))
            .value(Value::UInt {
                value: u32_be(&rest, 4).unwrap_or(0).into(),
                bits: 32,
                radix: Radix::Hex,
            }),
    );
    cx.emit(Node::new("Character packets").span(file.tail(k.saturating_add(19))));
    cx.annotate(format!(
        "PK font {:?}, design size {:.1} pt",
        comment.trim(),
        f64::from(design) / 1_048_576.0
    ));
    Ok(())
}

async fn tex_gf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let k = u64::from(cx.read(file.sub(2, 1)).await?.first().copied().unwrap_or(0));
    let comment = String::from_utf8_lossy(&cx.read(file.sub(3, k)).await?).into_owned();
    cx.emit(
        Node::new("Comment")
            .span(file.sub(3, k))
            .value(text(comment.clone())),
    );
    cx.emit(Node::new("Characters").span(file.tail(k.saturating_add(3))));
    cx.annotate(format!("GF font {:?}", comment.trim()));
    Ok(())
}
