//! Vorbis comments (`KEY=value` tags, little-endian lengths), shared by
//! FLAC, Ogg Vorbis, Opus, Speex and Theora.
//!
//! Cover art in a `METADATA_BLOCK_PICTURE` comment (a base64-encoded FLAC
//! PICTURE block) or an old-style `COVERART` comment (a base64-encoded
//! image) is decoded and shown.

use crate::bytes::{to_u64, to_usize, u32_be, u32_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::Input;
use crate::formats::audio::{flac, id3};
use crate::formats::text::decode::{Transform, derive_with};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::sound::{clip, image_info, leaf, text, uint};
use crate::node::{Count, Node};
use crate::span::Span;

const LE: Endian = Endian::Little;

/// Emits the vendor string and a paged list of comments for the comment
/// block at `span`; returns the number of bytes it occupies.
pub async fn emit(cx: &Cx, input: Input, span: Span) -> Result<u64> {
    let mut cur = Cursor::new(cx, span, LE);
    let start = cur.pos();
    let vendor_len = cur.u32().await?;
    cx.emit(leaf(
        "Vendor length",
        cur.since(start),
        uint(vendor_len, 32),
    ));
    let vendor = cur.span(vendor_len.into());
    let text_bytes = cx.read(vendor.sub(0, vendor.len.min(0x10000))).await?;
    cx.emit(leaf(
        "Vendor",
        vendor,
        text(String::from_utf8_lossy(&text_bytes).into_owned()),
    ));
    cur.skip(vendor_len.into());
    let at = cur.pos();
    let count = cur.u32().await?;
    cx.emit(leaf("Comment count", cur.since(at), uint(count, 32)));
    let list = span.tail(cur.pos());
    let used = comments_len(cx, list, count).await.unwrap_or(list.len);
    let list = list.sub(0, used);
    let mut node = Node::new("Comments")
        .span(list)
        .summary(crate::formats::util::arcutil::count(
            count.into(),
            "comment",
            "comments",
        ))
        .lazy(expand, (input, list, count));
    if let Some(t) = title(cx, span).await {
        node = node.summary(format!(
            "{}: {t}",
            crate::formats::util::arcutil::count(count.into(), "comment", "comments")
        ));
    }
    cx.emit(node);
    Ok(cur.pos().saturating_add(used))
}

/// The length of `count` comments at the start of `span`.
async fn comments_len(cx: &Cx, span: Span, count: u32) -> Result<u64> {
    let mut cur = Cursor::new(cx, span, LE);
    for _ in 0..count {
        if cur.at_end() {
            break;
        }
        let len = cur.u32().await?;
        cur.skip(len.into());
    }
    Ok(cur.pos().min(span.len))
}

/// Comments holding base64-encoded pictures.
fn picture_key(key: &str) -> Option<bool> {
    if key.eq_ignore_ascii_case("METADATA_BLOCK_PICTURE") {
        Some(true)
    } else if key.eq_ignore_ascii_case("COVERART") {
        Some(false)
    } else {
        None
    }
}

/// "Cover (front), 600×600 JPEG" from the first base64 characters of a
/// picture comment.
fn picture_summary(b64: &[u8], block: bool) -> Option<String> {
    let d = Transform::Base64.decode(b64).bytes;
    if !block {
        return image_info(&d);
    }
    let kind = u32_be(&d, 0)?;
    let mime_len = to_usize(u32_be(&d, 4)?.into());
    let mime = crate::text::latin1(d.get(8..8usize.saturating_add(mime_len))?);
    let at = 8usize.saturating_add(mime_len);
    let desc_len = to_usize(u32_be(&d, at)?.into());
    let image = d
        .get(
            at.saturating_add(4)
                .saturating_add(desc_len)
                .saturating_add(20)..,
        )
        .unwrap_or_default();
    let kind = crate::value::lookup(id3::PICTURE_TYPE, kind.into()).unwrap_or("Picture");
    Some(format!("{kind}, {}", image_info(image).unwrap_or(mime)))
}

async fn expand(cx: Cx, (input, span, count): (Input, Span, u32)) -> Result<()> {
    cx.set_count(Count::Exact(count.into()));
    let mut cur = Cursor::new(&cx, span, LE);
    for _ in 0..count {
        if cur.at_end() {
            break;
        }
        let start = cur.pos();
        let len = cur.u32().await?;
        let body = cur.span(len.into());
        let preview = cx.read_avail(body.sub(0, 4096)).await?;
        cur.skip(len.into());
        let eq = preview.iter().position(|&b| b == b'=');
        let key = eq.map_or("", |e| {
            std::str::from_utf8(preview.get(..e).unwrap_or_default()).unwrap_or("")
        });
        let value = eq
            .and_then(|e| preview.get(e.saturating_add(1)..))
            .unwrap_or(&preview);
        let name = if key.is_empty() {
            "Comment".to_owned()
        } else {
            key.to_owned()
        };
        let summary = match picture_key(key) {
            Some(block) => picture_summary(value, block)
                .map_or_else(|| human_size(body.len), |s| format!("{s}, base64")),
            None => clip(
                &String::from_utf8_lossy(value.get(..512.min(value.len())).unwrap_or_default()),
                60,
            ),
        };
        let entry = cur.since(start);
        cx.push(
            Node::new(name)
                .span(entry)
                .summary(summary)
                .lazy(comment, (input, entry)),
        )
        .await;
    }
    Ok(())
}

async fn comment(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let head = cx.read(span.sub(0, 4)).await?;
    let len = u32_le(&head, 0).unwrap_or(0);
    cx.emit(leaf("Length", span.sub(0, 4), uint(len, 32)));
    let body = span.sub(4, len.into());
    let prefix = cx.read_avail(body.sub(0, 256)).await?;
    let Some(eq) = prefix.iter().position(|&b| b == b'=') else {
        let data = cx.read(body.sub(0, body.len.min(1 << 20))).await?;
        cx.emit(leaf(
            "Text",
            body,
            text(String::from_utf8_lossy(&data).into_owned()),
        ));
        return Ok(());
    };
    let key = String::from_utf8_lossy(prefix.get(..eq).unwrap_or_default()).into_owned();
    let key_len = to_u64(eq);
    let value = body.tail(key_len.saturating_add(1));
    cx.emit(leaf("Field", body.sub(0, key_len), text(key.clone())));
    match picture_key(&key) {
        Some(block) => {
            cx.emit(
                Node::new("Value")
                    .span(value)
                    .summary(format!("{} of base64", human_size(value.len))),
            );
            let name = if block { "Picture block" } else { "Picture" };
            cx.emit(
                Node::new(name)
                    .span(value)
                    .desc("The value, base64-decoded")
                    .lazy(expand_picture, (input, value, block)),
            );
        }
        None => {
            let data = cx.read(value.sub(0, value.len.min(1 << 20))).await?;
            cx.emit(leaf(
                "Value",
                value,
                text(String::from_utf8_lossy(&data).into_owned()),
            ));
        }
    }
    Ok(())
}

async fn expand_picture(cx: Cx, (input, span, block): (Input, Span, bool)) -> Result<()> {
    let (decoded, error) = derive_with(&cx, span, Transform::Base64).await?;
    if let Some(e) = error {
        cx.diag(e);
    }
    if block {
        flac::picture(&cx, input, decoded).await
    } else {
        crate::formats::dissect_or_data(cx, input.nested(decoded)).await
    }
}

/// Looks up `ARTIST` and `TITLE` in the comment block at `span`:
/// "Artist – Title".
pub async fn title(cx: &Cx, span: Span) -> Option<String> {
    let mut cur = Cursor::new(cx, span, LE);
    let vendor = cur.u32().await.ok()?;
    cur.skip(vendor.into());
    let count = cur.u32().await.ok()?;
    let (mut artist, mut title) = (None, None);
    for _ in 0..count.min(256) {
        let len = cur.u32().await.ok()?;
        let body = cur.span(len.into());
        cur.skip(len.into());
        let data = cx.read_avail(body.sub(0, 256)).await.ok()?;
        let text = String::from_utf8_lossy(&data).into_owned();
        if let Some((k, v)) = text.split_once('=') {
            match k.to_ascii_uppercase().as_str() {
                "ARTIST" if artist.is_none() => artist = Some(v.to_owned()),
                "TITLE" if title.is_none() => title = Some(v.to_owned()),
                _ => {}
            }
        }
    }
    match (artist, title) {
        (Some(a), Some(t)) => Some(format!("{a} – {t}")),
        (a, t) => a.or(t),
    }
}
