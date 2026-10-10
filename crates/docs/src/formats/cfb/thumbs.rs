//! Windows XP thumbnail caches (`Thumbs.db`): the `Catalog` stream lists
//! cached files (index, modification time, name); each thumbnail is a
//! stream named by its index written backwards, holding a small header and
//! a JPEG image.

use super::rec::LE;
use crate::bytes::{u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::Input;
use crate::formats::util::val::uint;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

fn catalog_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Header size").emit()?;
    f.u16("Version")
        .desc("5 (Windows 2000/XP), 6 or 7 (XP SP2 and later)")
        .emit()?;
    f.u32("Thumbnail count").emit()?;
    f.u32("Width").emit()?;
    f.u32("Height").emit()?;
    Ok(())
}

pub async fn catalog(cx: &Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub(0, 16)).await?;
    let header_len = u64::from(u16_le(&head, 0).unwrap_or(16)).max(16);
    let count = u32_le(&head, 4).unwrap_or(0);
    let width = u32_le(&head, 8).unwrap_or(0);
    let height = u32_le(&head, 12).unwrap_or(0);
    cx.emit(
        struct_node(
            "Catalog header",
            span.sub(0, header_len),
            LE,
            (),
            catalog_header,
        )
        .summary(format!("{count} thumbnails, up to {width}×{height}")),
    );
    cx.set_count(Count::Exact(u64::from(count).saturating_add(1)));
    let mut at = header_len;
    let mut seen = 0u32;
    while at.saturating_add(16) <= span.len && seen < count {
        let head = cx.read(span.sub(at, 16)).await?;
        let len = u64::from(u32_le(&head, 0).unwrap_or(0));
        if len < 16 {
            cx.push(
                Node::new("Invalid entry")
                    .span(span.sub(at, 4))
                    .diag(Diagnostic::malformed(format!(
                        "entry length {len} is less than 16"
                    ))),
            )
            .await;
            break;
        }
        let index = u32_le(&head, 4).unwrap_or(0);
        let time = u64_le(&head, 8).unwrap_or(0);
        let entry = span.sub(at, len);
        let name = cx.read_avail(entry.sub(16, len.saturating_sub(16))).await?;
        let name = crate::text::utf16z(&name, LE).0;
        let stream: String = index.to_string().chars().rev().collect();
        cx.push(
            Node::new(name.clone())
                .span(entry)
                .value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(time),
                })
                .summary(format!("thumbnail {index} (stream \"{stream}\")"))
                .lazy(catalog_entry, entry),
        )
        .await;
        at = at.saturating_add(len);
        seen = seen.saturating_add(1);
    }
    if at < span.len {
        cx.emit(Node::new("Unused").span(span.tail(at)).summary(format!(
            "{} bytes after the last entry",
            span.len.saturating_sub(at)
        )));
    }
    Ok(())
}

async fn catalog_entry(cx: Cx, entry: Span) -> Result<()> {
    let block = cx.block(entry).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Entry length").emit()?;
    f.u32("Index")
        .desc("The thumbnail stream's name is this number written backwards")
        .emit()?;
    f.u64("Modified").filetime().emit()?;
    f.utf16z("Name").emit()?;
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Padding", rest).emit()?;
    }
    Ok(())
}

fn thumb_header(f: &mut Fields<'_>, len: &u64) -> Result<()> {
    f.u32("Header size").emit()?;
    f.u32("Type")
        .desc("1: JPEG, 2: JPEG with a custom header")
        .emit()?;
    f.u32("Image size").emit()?;
    if *len > 12 {
        f.bytes("Extra header", len.saturating_sub(12)).emit()?;
    }
    Ok(())
}

pub async fn thumbnail(cx: &Cx, input: Input, span: Span) -> Result<()> {
    let head = cx.read_avail(span.sub(0, 12)).await?;
    let header = u64::from(u32_le(&head, 0).unwrap_or(0));
    if !(12..=64).contains(&header) {
        cx.emit(
            Node::new("Content")
                .span(span)
                .lazy(crate::formats::dissect_or_data, input.nested(span)),
        );
        return Ok(());
    }
    let size = u64::from(u32_le(&head, 8).unwrap_or(0));
    cx.emit(struct_node(
        "Thumbnail header",
        span.sub(0, header),
        LE,
        header,
        thumb_header,
    ));
    let image = span.tail(header);
    let image = if size > 0 && size <= image.len {
        image.sub(0, size)
    } else {
        image
    };
    let preview = cx.read_avail(image.sub(0, 2)).await?;
    cx.emit(
        crate::formats::embedded("Image", input.nested(image)).summary(format!(
            "{}, {} bytes",
            if preview == [0xff, 0xd8] {
                "JPEG"
            } else {
                "image"
            },
            image.len
        )),
    );
    let used = header.saturating_add(image.len);
    if used < span.len {
        cx.emit(
            Node::new("Trailing data")
                .span(span.tail(used))
                .value(uint(span.len.saturating_sub(used), 32)),
        );
    }
    Ok(())
}
