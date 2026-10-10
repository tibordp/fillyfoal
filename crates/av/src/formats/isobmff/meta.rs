//! Metadata: `meta` (ISO and QuickTime flavours), iTunes-style `ilst`
//! items and their `data` atoms, QuickTime `keys`, `©xxx` user-data text,
//! Nero chapters (`chpl`), 3GPP asset boxes, `ID32` and location.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Fields;
use crate::formats::util::sound::clip;
use crate::formats::util::vidutil::{fourcc, num, plural, seconds_ms};
use crate::formats::{embedded, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

use super::boxes::language;
use super::{BE, BoxState, Ctx, children, find_child, full_box, small};

/// Well-known iTunes metadata item names.
pub fn item_name(kind: &[u8]) -> Option<&'static str> {
    Some(match kind {
        b"\xa9nam" => "Title",
        b"\xa9ART" => "Artist",
        b"aART" => "Album artist",
        b"\xa9alb" => "Album",
        b"\xa9gen" => "Genre",
        b"gnre" => "Genre (ID3)",
        b"\xa9day" => "Year",
        b"trkn" => "Track number",
        b"disk" => "Disc number",
        b"\xa9wrt" => "Composer",
        b"\xa9too" => "Encoder",
        b"\xa9enc" => "Encoded by",
        b"\xa9cmt" => "Comment",
        b"covr" => "Cover art",
        b"cpil" => "Compilation",
        b"tmpo" => "Tempo (BPM)",
        b"\xa9lyr" => "Lyrics",
        b"desc" => "Description",
        b"ldes" => "Long description",
        b"tvsh" => "TV show",
        b"tven" => "TV episode ID",
        b"tvsn" => "TV season",
        b"tves" => "TV episode",
        b"tvnn" => "TV network",
        b"stik" => "Media kind",
        b"hdvd" => "HD video",
        b"pcst" => "Podcast",
        b"purl" => "Podcast URL",
        b"egid" => "Episode GUID",
        b"catg" => "Category",
        b"keyw" => "Keywords",
        b"\xa9grp" => "Grouping",
        b"\xa9wrk" => "Work",
        b"\xa9mvn" => "Movement",
        b"shwm" => "Show work and movement",
        b"sonm" => "Sort title",
        b"soar" => "Sort artist",
        b"soaa" => "Sort album artist",
        b"soal" => "Sort album",
        b"soco" => "Sort composer",
        b"sosn" => "Sort show",
        b"pgap" => "Gapless playback",
        b"rtng" => "Content rating",
        b"purd" => "Purchase date",
        b"apID" => "Account",
        b"ownr" => "Owner",
        b"cnID" => "Catalog ID",
        b"atID" => "Artist ID",
        b"plID" => "Playlist ID",
        b"geID" => "Genre ID",
        b"sfID" => "Storefront ID",
        b"akID" => "Account type",
        b"cmID" => "Composer ID",
        b"xid " => "Vendor ID",
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
        b"\xa9aut" => "Author",
        b"\xa9PRD" => "Product",
        b"\xa9st3" => "Subtitle",
        b"\xa9url" => "URL",
        b"\xa9hst" => "Host computer",
        b"\xa9wrn" => "Warning",
        b"\xa9ed1" => "Edit date",
        b"----" => "Custom",
        b"titl" => "Title",
        b"auth" => "Author",
        b"perf" => "Performer",
        b"dscp" => "Description",
        b"albm" => "Album",
        b"yrrc" => "Recording year",
        b"loci" => "Location",
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
    (70, "point (2 × float32)"),
    (71, "dimensions (2 × float32)"),
    (72, "rectangle (4 × float32)"),
    (74, "int64"),
    (75, "uint8"),
    (76, "uint16"),
    (77, "uint32"),
    (78, "uint64"),
    (79, "affine transform (9 × float64)"),
];

const MEDIA_KINDS: EnumTable = &[
    (0, "movie (legacy)"),
    (1, "music"),
    (2, "audiobook"),
    (5, "whacked bookmark"),
    (6, "music video"),
    (9, "movie"),
    (10, "TV show"),
    (11, "booklet"),
    (14, "ringtone"),
    (21, "podcast"),
    (23, "iTunes U"),
];

const RATINGS: EnumTable = &[
    (0, "none"),
    (1, "explicit"),
    (2, "clean"),
    (4, "explicit (old)"),
];

const LOCATION_ROLES: EnumTable = &[
    (0, "shooting location"),
    (1, "real location"),
    (2, "fictional location"),
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
                ..ctx.child(kind, inner)
            };
            children(cx, st.input, inner, child).await?;
        }
        b"data" => data(cx, st, body).await?,
        b"mean" | b"name" if &ctx.parent == b"----" => {
            let block = cx.block(body.sub(0, 0x1000)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            full_box(&mut f)?;
            let rest = f.remaining();
            f.ascii(
                if &kind == b"mean" {
                    "Namespace"
                } else {
                    "Name"
                },
                rest,
            )
            .emit()?;
        }
        b"name" if &ctx.parent == b"udta" => {
            let block = cx.block(body.sub(0, 0x1000)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            let rest = f.remaining();
            f.ascii("Track name", rest).emit()?;
        }
        b"keys" => {
            let block = cx.block(body.sub(0, 0x10000)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            full_box(&mut f)?;
            let n = f.u32("Entry count").emit()?;
            for i in 0..n {
                if f.remaining() < 8 {
                    break;
                }
                let start = f.pos();
                let size = u32_be(&block.data, crate::bytes::to_usize(start)).unwrap_or(0);
                let len = u64::from(size).max(8);
                let key = block
                    .data
                    .get(
                        crate::bytes::to_usize(start.saturating_add(8))
                            ..crate::bytes::to_usize(start.saturating_add(len)),
                    )
                    .map(|k| String::from_utf8_lossy(k).into_owned())
                    .unwrap_or_default();
                f.node(
                    crate::fields::struct_node(
                        format!("Key {}", i.saturating_add(1)),
                        f.peek_span(len),
                        BE,
                        (),
                        key_layout,
                    )
                    .summary(key),
                );
                f.skip(len);
            }
        }
        b"chpl" => chpl(cx, body).await?,
        b"ID32" => {
            let block = cx.block(body.sub(0, 6)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            full_box(&mut f)?;
            f.u16("Language")
                .hex()
                .with(|&l, n| n.summary(language(l)))
                .emit()?;
            cx.emit(embedded_as(
                "ID3v2 tag",
                st.input.nested(body.tail(6)),
                &crate::formats::audio::id3::FORMAT,
            ));
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
                f.ascii("Text", len.into())
                    .with(|t, n| match iso6709(t).filter(|_| &kind == b"\xa9xyz") {
                        Some(s) => n.summary(s),
                        None => n,
                    })
                    .emit()?;
            }
        }
        b"loci" if &ctx.parent == b"udta" => {
            let block = cx.block(body.sub(0, 0x10000)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            full_box(&mut f)?;
            f.u16("Language")
                .with(|&l, n| n.summary(language(l)))
                .emit()?;
            f.cstr("Name").emit()?;
            f.u8("Role").enumeration(LOCATION_ROLES).emit()?;
            for name in ["Longitude", "Latitude", "Altitude"] {
                f.i32(name)
                    .with(|&v, n| n.summary(num(f64::from(v) / 65536.0)))
                    .emit()?;
            }
            f.cstr("Astronomical body").emit()?;
            if f.remaining() > 0 {
                f.cstr("Additional notes").emit()?;
            }
        }
        _ if ASSET_BOXES.contains(&&kind) && &ctx.parent == b"udta" => {
            let block = cx.block(body.sub(0, 0x10000)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            full_box(&mut f)?;
            f.u16("Language")
                .with(|&l, n| n.summary(language(l)))
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

fn key_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let size = f.u32("Key size").emit()?;
    f.ascii("Namespace", 4)
        .with(|t, n| match t.as_str() {
            "mdta" => n.summary("reverse-DNS key"),
            "udta" => n.summary("user data type"),
            _ => n,
        })
        .emit()?;
    f.ascii("Key", u64::from(size).saturating_sub(8)).emit()?;
    Ok(())
}

async fn chpl(cx: &Cx, body: Span) -> Result<()> {
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    let (v, _) = full_box(&mut f)?;
    if v >= 1 {
        f.u32("Reserved").emit()?;
    }
    let n = f.u8("Chapter count").emit()?;
    for i in 0..n {
        if f.remaining() < 9 {
            break;
        }
        let start = crate::bytes::to_usize(f.pos());
        let time = u64_be(&block.data, start).unwrap_or(0);
        let len = block
            .data
            .get(start.saturating_add(8))
            .copied()
            .unwrap_or(0);
        let title = block
            .data
            .get(start.saturating_add(9)..start.saturating_add(9).saturating_add(len.into()))
            .map(|t| String::from_utf8_lossy(t).into_owned())
            .unwrap_or_default();
        let size = 9u64.saturating_add(len.into());
        f.node(
            crate::fields::struct_node(
                format!("Chapter {}", u16::from(i).saturating_add(1)),
                f.peek_span(size),
                BE,
                (),
                chapter_layout,
            )
            .summary(format!("{} {title}", seconds_ms(time / 10_000))),
        );
        f.skip(size);
    }
    Ok(())
}

fn chapter_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Start time")
        .with(|&t, n| n.summary(seconds_ms(t / 10_000)))
        .desc("In 100-nanosecond units")
        .emit()?;
    let len = f.u8("Title length").emit()?;
    f.ascii("Title", len.into()).emit()?;
    Ok(())
}

async fn data(cx: &Cx, st: &BoxState, body: Span) -> Result<()> {
    let head = cx.read_avail(body.sub(0, 8)).await?;
    let kind = u32_be(&head, 0).unwrap_or(0) & 0x00ff_ffff;
    let value = body.tail(8);
    let block = cx.block(body.sub(0, 8)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    let mut b = super::codec::bits_at(Some(cx), &mut f, 1);
    b.field("Type set", 8)
        .desc("0 = the well-known types")
        .emit()?;
    let mut b = super::codec::bits_at(Some(cx), &mut f, 3);
    b.field("Data type", 24).enumeration(DATA_TYPES).emit()?;
    f.u16("Country").emit()?;
    f.u16("Language").emit()?;
    match kind {
        13 | 14 | 27 => {
            cx.emit(
                embedded("Image", st.input.nested(value)).summary(format!("{} bytes", value.len)),
            );
        }
        _ => {
            let bytes = cx.read_avail(value.sub(0, 0x10000)).await?;
            let node = Node::new("Value").span(value);
            cx.emit(match render(&st.ctx.parent, kind, &bytes) {
                Some(text) => node.value(Value::Text(text)),
                None => node.value(Value::Bytes(bytes)),
            });
        }
    }
    Ok(())
}

/// Renders a `data` atom value as text, if it has a textual form.
fn render(item: &[u8; 4], kind: u32, v: &[u8]) -> Option<String> {
    let text = match kind {
        1 | 4 => String::from_utf8_lossy(v).into_owned(),
        2 | 5 => crate::text::utf16(v, crate::fields::Endian::Big),
        21 | 65..=67 | 74 => {
            let n = v
                .iter()
                .fold(0i64, |acc, &b| acc.wrapping_shl(8) | i64::from(b));
            let bits = u32::try_from(v.len().saturating_mul(8)).ok()?;
            if bits == 0 || bits > 64 {
                return None;
            }
            let shift = 64u32.saturating_sub(bits);
            format!("{}", n.wrapping_shl(shift).wrapping_shr(shift))
        }
        22 | 75..=78 => {
            if v.is_empty() || v.len() > 8 {
                return None;
            }
            format!(
                "{}",
                v.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
            )
        }
        23 => num(f64::from(f32::from_bits(u32_be(v, 0)?))),
        24 => num(f64::from_bits(u64_be(v, 0)?)),
        0 if item == b"trkn" || item == b"disk" => {
            let n = u16_be(v, 2)?;
            let total = u16_be(v, 4).unwrap_or(0);
            if total > 0 {
                format!("{n} of {total}")
            } else {
                format!("{n}")
            }
        }
        0 if item == b"gnre" => {
            let g = u16_be(v, 0)?.saturating_sub(1);
            match crate::formats::audio::id3::genre(g.into()) {
                Some(name) => format!("{name} (ID3 genre {g})"),
                None => format!("ID3 genre {g}"),
            }
        }
        _ => return None,
    };
    Some(name_value(item, &text).unwrap_or(text))
}

/// Gives names to enumerated item values.
fn name_value(item: &[u8; 4], text: &str) -> Option<String> {
    let n: u64 = text.parse().ok()?;
    let name = match item {
        b"stik" => crate::value::lookup(MEDIA_KINDS, n)?,
        b"rtng" => crate::value::lookup(RATINGS, n)?,
        b"cpil" | b"pgap" | b"pcst" | b"shwm" => {
            if n == 0 {
                "no"
            } else {
                "yes"
            }
        }
        b"hdvd" => match n {
            0 => "SD",
            1 => "720p",
            2 => "1080p",
            _ => return None,
        },
        _ => return None,
    };
    Some(format!("{name} ({n})"))
}

/// An ISO 6709 location ("+46.0500+014.5000/") as degrees.
pub fn iso6709(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('/');
    let mut parts = Vec::new();
    let mut current = String::new();
    for c in s.chars() {
        if (c == '+' || c == '-') && !current.is_empty() {
            parts.push(std::mem::take(&mut current));
            if parts.len() > 3 {
                return None;
            }
        }
        current.push(c);
    }
    if !current.is_empty() {
        parts.push(current);
    }
    let lat: f64 = parts.first()?.parse().ok()?;
    let lon: f64 = parts.get(1)?.parse().ok()?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    let mut out = format!(
        "{}° {}, {}° {}",
        lat.abs(),
        if lat < 0.0 { 'S' } else { 'N' },
        lon.abs(),
        if lon < 0.0 { 'W' } else { 'E' }
    );
    if let Some(alt) = parts.get(2).and_then(|a| a.parse::<f64>().ok()) {
        out = format!("{out}, {alt} m");
    }
    Some(out)
}

/// The keys of a QuickTime `keys` box in the `meta` region `outer`.
async fn keys(cx: &Cx, outer: Span) -> Option<Arc<Vec<String>>> {
    let (h, span) = find_child(cx, outer, b"keys").await.ok()??;
    if let Some(k) = cx.cached::<Vec<String>>(span, "isobmff-keys") {
        return Some(k);
    }
    let d = small(cx, span.tail(h.header_len)).await.ok()?;
    let n = u32_be(&d, 4).unwrap_or(0);
    let mut out = Vec::new();
    let mut at = 8usize;
    for _ in 0..n.min(4096) {
        let Some(size) = u32_be(&d, at) else { break };
        let size = usize::try_from(size).unwrap_or(0);
        if size < 8 {
            break;
        }
        let key = d
            .get(at.saturating_add(8)..at.saturating_add(size).min(d.len()))
            .map(|k| String::from_utf8_lossy(k).into_owned())
            .unwrap_or_default();
        out.push(key);
        at = at.saturating_add(size);
    }
    let out = Arc::new(out);
    cx.cache(span, "isobmff-keys", out.clone());
    Some(out)
}

/// Summaries for the box list: item values.
pub async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let kind = &st.header.kind;
    let parent = &st.ctx.parent;
    if parent == b"ilst" {
        let d = small(cx, st.body().sub(0, 512)).await.ok()?;
        let name = match item_name(kind) {
            Some(n) => n.to_owned(),
            None => {
                let index = u32::from_be_bytes(*kind);
                if index == 0 || index > 0xffff {
                    return None;
                }
                let key = keys(cx, st.ctx.outer).await.and_then(|k| {
                    k.get(usize::try_from(index.saturating_sub(1)).ok()?)
                        .cloned()
                });
                key.unwrap_or_else(|| format!("Key {index}"))
            }
        };
        let value = item_value(kind, &d).map(|v| {
            let located = name.ends_with("ISO6709") || kind == b"\xa9xyz";
            match iso6709(&v).filter(|_| located) {
                Some(loc) => format!("{v} ({loc})"),
                None => v,
            }
        });
        return Some(match value {
            Some(v) => format!("{name}: {}", clip(&v, 80)),
            None => name,
        });
    }
    if kind.first() == Some(&0xa9) && parent == b"udta" {
        let d = small(cx, st.body().sub(0, 256)).await.ok()?;
        let len = usize::from(u16_be(&d, 0)?);
        let text = String::from_utf8_lossy(d.get(4..4usize.saturating_add(len))?).into_owned();
        let name = item_name(kind).unwrap_or("Text");
        return Some(match iso6709(&text).filter(|_| kind == b"\xa9xyz") {
            Some(loc) => format!("{name}: {text} ({loc})"),
            None => format!("{name}: {}", clip(&text, 80)),
        });
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
            render(parent, t, d.get(8..)?)
                .map(|v| clip(&v, 80))
                .or_else(|| {
                    crate::value::lookup(DATA_TYPES, t.into())
                        .map(|n| format!("{n}, {} bytes", st.body().len.saturating_sub(8)))
                })
        }
        b"mean" | b"name" if parent == b"----" => {
            let d = small(cx, st.body().sub(0, 256)).await.ok()?;
            Some(String::from_utf8_lossy(d.get(4..)?).into_owned())
        }
        b"name" if parent == b"udta" => {
            let d = small(cx, st.body().sub(0, 256)).await.ok()?;
            Some(String::from_utf8_lossy(&d).into_owned())
        }
        b"keys" => {
            let d = small(cx, st.body().sub(0, 8)).await.ok()?;
            Some(plural(u32_be(&d, 4)?, "key"))
        }
        b"chpl" => {
            let d = small(cx, st.body().sub(0, 16)).await.ok()?;
            let at = if d.first().copied().unwrap_or(0) >= 1 {
                8
            } else {
                4
            };
            Some(plural(*d.get(at)?, "chapter"))
        }
        b"meta" => {
            let d = small(cx, st.body().sub(0, 24)).await.ok()?;
            let at: usize = if d.get(4..8) == Some(b"hdlr".as_slice()) {
                16
            } else {
                20
            };
            let h = d.get(at..at.saturating_add(4))?;
            Some(match super::boxes::handler_name(h) {
                Some(n) => format!("{} ({n})", fourcc(h)),
                None => fourcc(h),
            })
        }
        b"ID32" => Some(format!("ID3v2, {} bytes", st.body().len.saturating_sub(6))),
        _ => None,
    }
}

/// The value of an `ilst` item, from its `data` children.
fn item_value(item: &[u8; 4], d: &[u8]) -> Option<String> {
    // Custom '----' items: mean, name, data.
    let mut at = 0usize;
    let mut name = None;
    let mut count = 0usize;
    let mut first = None;
    for _ in 0..16 {
        let size = usize::try_from(u32_be(d, at)?).ok()?;
        let kind = d.get(at.saturating_add(4)..at.saturating_add(8))?;
        let body = d.get(at.saturating_add(8)..at.saturating_add(size).min(d.len()))?;
        match kind {
            b"mean" => name = Some(String::from_utf8_lossy(body.get(4..)?).into_owned()),
            b"name" => {
                let n = String::from_utf8_lossy(body.get(4..)?).into_owned();
                name = Some(match name {
                    Some(ns) => format!("{ns}:{n}"),
                    None => n,
                });
            }
            b"data" => {
                let t = u32_be(body, 0)? & 0x00ff_ffff;
                let value = render(item, t, body.get(8..)?).unwrap_or_else(|| {
                    crate::value::lookup(DATA_TYPES, t.into()).map_or_else(
                        || format!("{} bytes", body.len().saturating_sub(8)),
                        |n| format!("{n}, {} bytes", body.len().saturating_sub(8)),
                    )
                });
                if first.is_none() {
                    first = Some(value);
                }
                count = count.saturating_add(1);
            }
            _ => {}
        }
        if size < 8 {
            break;
        }
        at = at.saturating_add(size);
        if to_u64(at) >= to_u64(d.len()) {
            break;
        }
    }
    let mut value = first?;
    if count > 1 {
        value = format!("{value} (+{} more)", count.saturating_sub(1));
    }
    Some(match name {
        Some(n) => format!("{n} = {value}"),
        None => value,
    })
}
