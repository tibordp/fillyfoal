//! Vorbis comments (`KEY=value` tags, little-endian lengths), shared by
//! FLAC, Ogg Vorbis, Opus, Speex and Theora.

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::util::sound::{clip, leaf, text, uint};
use crate::node::{Count, Node};
use crate::span::Span;

const LE: Endian = Endian::Little;

/// Emits the vendor string and a paged list of comments for the comment
/// block at `span`; returns the number of bytes it occupies.
pub async fn emit(cx: &Cx, span: Span) -> Result<u64> {
    let mut cur = Cursor::new(cx, span, LE);
    let start = cur.pos();
    let vendor_len = cur.u32().await?;
    cx.emit(leaf(
        "Vendor length",
        cur.since(start),
        uint(vendor_len, 32),
    ));
    let vendor = cur.span(vendor_len.into());
    let text_bytes = cx.read(vendor).await?;
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
    cx.emit(
        Node::new("Comments")
            .span(list)
            .summary(format!("{count} comments"))
            .lazy(expand, (list, count)),
    );
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

async fn expand(cx: Cx, (span, count): (Span, u32)) -> Result<()> {
    cx.set_count(Count::Exact(count.into()));
    let mut cur = Cursor::new(&cx, span, LE);
    for _ in 0..count {
        if cur.at_end() {
            break;
        }
        let start = cur.pos();
        let len = cur.u32().await?;
        let body = cur.span(len.into());
        let preview = cx.read_avail(body.sub(0, 512)).await?;
        let preview = String::from_utf8_lossy(&preview).into_owned();
        cur.skip(len.into());
        let (key, value) = preview.split_once('=').unwrap_or(("", preview.as_str()));
        let name = if key.is_empty() {
            "Comment".to_owned()
        } else {
            key.to_owned()
        };
        cx.push(
            Node::new(name)
                .span(cur.since(start))
                .summary(clip(value, 60))
                .lazy(comment, cur.since(start)),
        )
        .await;
    }
    Ok(())
}

async fn comment(cx: Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub(0, 4)).await?;
    let len = u32_le(&head, 0).unwrap_or(0);
    cx.emit(leaf("Length", span.sub(0, 4), uint(len, 32)));
    let body = span.sub(4, len.into());
    let data = cx.read(body.sub(0, body.len.min(1 << 20))).await?;
    let text_value = String::from_utf8_lossy(&data).into_owned();
    match text_value.split_once('=') {
        Some((key, value)) => {
            let key_len = to_u64(key.len());
            cx.emit(leaf("Field", body.sub(0, key_len), text(key)));
            cx.emit(leaf(
                "Value",
                body.tail(key_len.saturating_add(1)),
                text(value),
            ));
        }
        None => cx.emit(leaf("Text", body, text(text_value))),
    }
    Ok(())
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
                "ARTIST" => artist = Some(v.to_owned()),
                "TITLE" => title = Some(v.to_owned()),
                _ => {}
            }
        }
    }
    match (artist, title) {
        (Some(a), Some(t)) => Some(format!("{a} – {t}")),
        (a, t) => a.or(t),
    }
}
