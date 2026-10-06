//! Metadata: `meta` (ISO and QuickTime flavours), iTunes-style `ilst`
//! items and their `data` atoms, `keys`, QuickTime `©xxx` user-data text
//! and 3GPP asset boxes.

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Fields;
use crate::formats::embedded;
use crate::formats::vidutil::fourcc;
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

use super::boxes::language;
use super::{BE, BoxState, Ctx, children, find_child, full_box, small};

/// Well-known iTunes metadata item names.
pub fn item_name(kind: &[u8]) -> Option<&'static str> {
    Some(match kind {
        b"\xa9nam" => "Title",
        b"\xa9ART" => "Artist",
        b"aART" => "Album artist",
        b"\xa9alb" => "Album",
        b"\xa9gen" | b"gnre" => "Genre",
        b"\xa9day" => "Year",
        b"trkn" => "Track number",
        b"disk" => "Disc number",
        b"\xa9wrt" => "Composer",
        b"\xa9too" => "Encoder",
        b"\xa9enc" => "Encoded by",
        b"\xa9cmt" => "Comment",
        b"covr" => "Cover art",
        b"cpil" => "Compilation",
        b"tmpo" => "Tempo",
        b"\xa9lyr" => "Lyrics",
        b"desc" => "Description",
        b"ldes" => "Long description",
        b"tvsh" => "TV show",
        b"tven" => "TV episode ID",
        b"tvsn" => "TV season",
        b"tves" => "TV episode",
        b"stik" => "Media kind",
        b"\xa9grp" => "Grouping",
        b"sonm" => "Sort title",
        b"soar" => "Sort artist",
        b"soaa" => "Sort album artist",
        b"soal" => "Sort album",
        b"soco" => "Sort composer",
        b"pgap" => "Gapless playback",
        b"rtng" => "Content rating",
        b"purd" => "Purchase date",
        b"apID" => "Account",
        b"cprt" | b"\xa9cpy" => "Copyright",
        b"\xa9xyz" => "Location (ISO 6709)",
        b"\xa9mak" => "Make",
        b"\xa9mod" => "Model",
        b"\xa9swr" => "Software",
        b"\xa9des" => "Description",
        b"\xa9dir" => "Director",
        b"\xa9prd" => "Producer",
        b"\xa9inf" => "Information",
        b"\xa9req" => "Requirements",
        b"\xa9fmt" => "Format",
        b"\xa9src" => "Source",
        b"----" => "Custom",
        b"titl" => "Title",
        b"auth" => "Author",
        b"perf" => "Performer",
        b"dscp" => "Description",
        b"albm" => "Album",
        b"yrrc" => "Recording year",
        _ => return None,
    })
}

const DATA_TYPES: EnumTable = &[
    (0, "implicit"),
    (1, "UTF-8"),
    (2, "UTF-16"),
    (3, "S/JIS"),
    (4, "UTF-8 sort"),
    (5, "UTF-16 sort"),
    (13, "JPEG"),
    (14, "PNG"),
    (21, "signed integer"),
    (22, "unsigned integer"),
    (23, "float32"),
    (24, "float64"),
    (27, "BMP"),
    (28, "QuickTime metadata atom"),
    (65, "int8"),
    (66, "int16"),
    (67, "int32"),
    (74, "int64"),
    (75, "uint8"),
    (76, "uint16"),
    (77, "uint32"),
    (78, "uint64"),
];

const ASSET_BOXES: &[&[u8; 4]] = &[
    b"titl", b"auth", b"perf", b"gnre", b"dscp", b"cprt", b"albm",
];

/// Decodes metadata boxes. Returns `false` for other types.
pub async fn decode(cx: &Cx, st: &BoxState) -> Result<bool> {
    let body = st.body();
    let kind = st.header.kind;
    let ctx = st.ctx;
    match &kind {
        b"meta" => {
            let head = cx.read_avail(body.sub(0, 12)).await?;
            let full = head.get(4..8) != Some(b"hdlr".as_slice());
            let inner = if full {
                let block = cx.block(body.sub(0, 4)).await?;
                full_box(&mut Fields::emitting(cx, &block, BE))?;
                body.tail(4)
            } else {
                body
            };
            let handler = match find_child(cx, inner, b"hdlr").await? {
                Some((h, span)) => {
                    let d = cx.read_avail(span.tail(h.header_len).sub(8, 4)).await?;
                    crate::bytes::array::<4>(&d, 0).unwrap_or(ctx.handler)
                }
                None => ctx.handler,
            };
            let child = Ctx {
                handler,
                ..ctx.child_of(kind, inner)
            };
            children(cx, st.input, inner, child).await?;
        }
        b"data" => data(cx, st, body).await?,
        b"mean" | b"name" => {
            let block = cx.block(body.sub(0, 0x1000)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            full_box(&mut f)?;
            let rest = f.remaining();
            f.ascii(if &kind == b"mean" { "Namespace" } else { "Name" }, rest)
                .emit()?;
        }
        b"keys" => {
            let block = cx.block(body.sub(0, 0x10000)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            full_box(&mut f)?;
            let n = f.u32("Entry count").emit()?;
            for _ in 0..n {
                if f.remaining() < 8 {
                    break;
                }
                let size = f.u32("Key size").emit()?;
                f.ascii("Namespace", 4).emit()?;
                f.ascii("Key", u64::from(size).saturating_sub(8)).emit()?;
            }
        }
        b"XMP_" => cx.emit(embedded("XMP", st.input.nested(body))),
        [0xa9, ..] if &ctx.parent == b"udta" => {
            let block = cx.block(body.sub(0, 0x10000)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            while f.remaining() >= 4 {
                let len = f.u16("Text size").emit()?;
                f.u16("Language")
                    .with(|&l, n| n.summary(language(l)))
                    .emit()?;
                f.ascii("Text", len.into()).emit()?;
            }
        }
        _ if ASSET_BOXES.contains(&&kind) && &ctx.parent == b"udta" => {
            let block = cx.block(body.sub(0, 0x10000)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            full_box(&mut f)?;
            f.u16("Language")
                .with(|&l, n| n.summary(language(l & 0x7fff)))
                .emit()?;
            let rest = f.remaining();
            f.ascii("Text", rest).emit()?;
        }
        b"yrrc" => {
            let block = cx.block(body.sub(0, 6)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            full_box(&mut f)?;
            f.u16("Year").emit()?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

async fn data(cx: &Cx, st: &BoxState, body: Span) -> Result<()> {
    let head = cx.read_avail(body.sub(0, 8)).await?;
    let kind = u32_be(&head, 0).unwrap_or(0) & 0x00ff_ffff;
    let value = body.tail(8);
    let block = cx.block(body.sub(0, 8)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.u32("Type").enumeration(DATA_TYPES).emit()?;
    f.u32("Locale").emit()?;
    match kind {
        13 | 14 | 27 => {
            cx.emit(
                embedded("Image", st.input.nested(value))
                    .summary(format!("{} bytes", value.len)),
            );
        }
        _ => {
            let bytes = cx.read_avail(value.sub(0, 0x10000)).await?;
            let node = Node::new("Value").span(value);
            cx.emit(match render(&st.ctx.parent, kind, &bytes) {
                Some(text) => node.value(crate::value::Value::Text(text)),
                None => node.value(crate::value::Value::Bytes(bytes)),
            });
        }
    }
    Ok(())
}

/// Renders a `data` atom value as text, if it has a textual form.
fn render(item: &[u8; 4], kind: u32, v: &[u8]) -> Option<String> {
    match kind {
        1 | 4 => Some(String::from_utf8_lossy(v).into_owned()),
        2 | 5 => Some(crate::text::utf16(v, crate::fields::Endian::Big)),
        21 | 65..=67 | 74 => {
            let n = v
                .iter()
                .fold(0i64, |acc, &b| acc.wrapping_shl(8) | i64::from(b));
            let bits = u32::try_from(v.len().saturating_mul(8)).ok()?;
            if bits == 0 || bits > 64 {
                return None;
            }
            let shift = 64u32.saturating_sub(bits);
            Some(format!("{}", n.wrapping_shl(shift).wrapping_shr(shift)))
        }
        22 | 75..=78 => {
            if v.is_empty() || v.len() > 8 {
                return None;
            }
            Some(format!(
                "{}",
                v.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
            ))
        }
        0 if item == b"trkn" || item == b"disk" => {
            let n = u16_be(v, 2)?;
            let total = u16_be(v, 4).unwrap_or(0);
            Some(if total > 0 {
                format!("{n} of {total}")
            } else {
                format!("{n}")
            })
        }
        0 if item == b"gnre" => u16_be(v, 0).map(|g| format!("ID3 genre {}", g.saturating_sub(1))),
        _ => None,
    }
}

/// Summaries for the box list: item values.
pub async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let kind = &st.header.kind;
    let parent = &st.ctx.parent;
    if parent == b"ilst" {
        let d = small(cx, st.body().sub(0, 512)).await.ok()?;
        let name = item_name(kind)
            .map(str::to_owned)
            .or_else(|| key_index(kind))?;
        return Some(match item_value(kind, &d) {
            Some(v) => format!("{name}: {v}"),
            None => name,
        });
    }
    if kind.first() == Some(&0xa9) && parent == b"udta" {
        let d = small(cx, st.body().sub(0, 256)).await.ok()?;
        let len = usize::from(u16_be(&d, 0)?);
        let text = d.get(4..4usize.saturating_add(len))?;
        let name = item_name(kind).unwrap_or("Text");
        return Some(format!("{name}: {}", String::from_utf8_lossy(text)));
    }
    if ASSET_BOXES.contains(&kind) && parent == b"udta" {
        let d = small(cx, st.body().sub(0, 256)).await.ok()?;
        let text = crate::text::until_nul(d.get(6..)?);
        return Some(format!("{}: {text}", item_name(kind).unwrap_or("Text")));
    }
    match kind {
        b"data" => {
            let d = small(cx, st.body().sub(0, 256)).await.ok()?;
            let t = u32_be(&d, 0)? & 0x00ff_ffff;
            render(parent, t, d.get(8..)?).or_else(|| {
                crate::value::lookup(DATA_TYPES, t.into()).map(str::to_owned)
            })
        }
        b"mean" | b"name" => {
            let d = small(cx, st.body().sub(0, 256)).await.ok()?;
            Some(String::from_utf8_lossy(d.get(4..)?).into_owned())
        }
        b"meta" => {
            let d = small(cx, st.body().sub(0, 24)).await.ok()?;
            let at: usize = if d.get(4..8) == Some(b"hdlr".as_slice()) { 16 } else { 20 };
            Some(fourcc(d.get(at..at.saturating_add(4))?))
        }
        _ => None,
    }
}

/// Items of QuickTime `mdta` metadata are numbered keys.
fn key_index(kind: &[u8; 4]) -> Option<String> {
    let n = u32::from_be_bytes(*kind);
    (n > 0 && n < 0x1000).then(|| format!("Key {n}"))
}

/// The value of an `ilst` item, from its first `data` child.
fn item_value(item: &[u8; 4], d: &[u8]) -> Option<String> {
    // Custom '----' items: mean, name, data.
    let mut at = 0usize;
    let mut name = None;
    for _ in 0..4 {
        let size = usize::try_from(u32_be(d, at)?).ok()?;
        let kind = d.get(at.saturating_add(4)..at.saturating_add(8))?;
        let body = d.get(at.saturating_add(8)..at.saturating_add(size).min(d.len()))?;
        match kind {
            b"name" => name = Some(String::from_utf8_lossy(body.get(4..)?).into_owned()),
            b"data" => {
                let t = u32_be(body, 0)? & 0x00ff_ffff;
                let value = render(item, t, body.get(8..)?).unwrap_or_else(|| {
                    crate::value::lookup(DATA_TYPES, t.into())
                        .map_or_else(|| format!("{} bytes", body.len()), |n| format!("{n} data"))
                });
                return Some(match name {
                    Some(n) => format!("{n} = {value}"),
                    None => value,
                });
            }
            _ => {}
        }
        if size < 8 {
            return None;
        }
        at = at.saturating_add(size);
    }
    None
}
