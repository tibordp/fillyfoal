//! GIF (87a and 89a).
//!
//! Header, logical screen descriptor and global color table, then a stream
//! of blocks: extensions (graphic control, application, comment, plain text)
//! and images, each followed by length-prefixed data sub-blocks. Blocks are
//! listed in pages; images and extensions decode their fields on expansion.

use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::{Input, Format, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, flag};

use super::{ColorOrder, dims, palette, text, uint};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "gif",
    title: "Graphics Interchange Format",
    extensions: &["gif"],
    mime: "image/gif",
    probe: Probe::Magic(&[(0, b"GIF87a"), (0, b"GIF89a")]),
    dissect: crate::expander!(dissect: Input),
};

const SCREEN_FLAGS: FlagTable = &[
    flag(0x80, "GLOBAL_COLOR_TABLE"),
    field(0x70, 0x00, "COLOR_RESOLUTION_1"),
    field(0x70, 0x10, "COLOR_RESOLUTION_2"),
    field(0x70, 0x20, "COLOR_RESOLUTION_3"),
    field(0x70, 0x30, "COLOR_RESOLUTION_4"),
    field(0x70, 0x40, "COLOR_RESOLUTION_5"),
    field(0x70, 0x50, "COLOR_RESOLUTION_6"),
    field(0x70, 0x60, "COLOR_RESOLUTION_7"),
    field(0x70, 0x70, "COLOR_RESOLUTION_8"),
    flag(0x08, "SORTED"),
    field(0x07, 0x01, "TABLE_4"),
    field(0x07, 0x02, "TABLE_8"),
    field(0x07, 0x03, "TABLE_16"),
    field(0x07, 0x04, "TABLE_32"),
    field(0x07, 0x05, "TABLE_64"),
    field(0x07, 0x06, "TABLE_128"),
    field(0x07, 0x07, "TABLE_256"),
];

const IMAGE_FLAGS: FlagTable = &[
    flag(0x80, "LOCAL_COLOR_TABLE"),
    flag(0x40, "INTERLACED"),
    flag(0x20, "SORTED"),
    field(0x07, 0x01, "TABLE_4"),
    field(0x07, 0x02, "TABLE_8"),
    field(0x07, 0x03, "TABLE_16"),
    field(0x07, 0x04, "TABLE_32"),
    field(0x07, 0x05, "TABLE_64"),
    field(0x07, 0x06, "TABLE_128"),
    field(0x07, 0x07, "TABLE_256"),
];

const GCE_FLAGS: FlagTable = &[
    field(0x1c, 0x04, "DISPOSE_NONE"),
    field(0x1c, 0x08, "DISPOSE_BACKGROUND"),
    field(0x1c, 0x0c, "DISPOSE_PREVIOUS"),
    flag(0x02, "USER_INPUT"),
    flag(0x01, "TRANSPARENT_COLOR"),
];

const LABELS: EnumTable = &[
    (0x01, "Plain Text Extension"),
    (0xf9, "Graphic Control Extension"),
    (0xfe, "Comment Extension"),
    (0xff, "Application Extension"),
];

/// Size in bytes of a color table whose packed size field is `bits`.
fn table_size(packed: u8) -> u64 {
    3u64.saturating_mul(2u64.checked_shl((packed & 7).into()).unwrap_or(0))
}

record! {
    pub struct ScreenDescriptor {
        width: u16 "Logical screen width",
        height: u16 "Logical screen height",
        flags: u8 "Flags" .flags(SCREEN_FLAGS) .with(|&v, n| if v & 0x80 != 0 {
            n.summary(format!("global color table of {} entries", 2u32 << (v & 7)))
        } else { n }),
        background: u8 "Background color index",
        aspect: u8 "Pixel aspect ratio" .desc("(aspect + 15) / 64; 0 = not given"),
    }
}

record! {
    pub struct ImageDescriptor {
        separator: u8 "Image separator" .hex(),
        left: u16 "Left",
        top: u16 "Top",
        width: u16 "Width",
        height: u16 "Height",
        flags: u8 "Flags" .flags(IMAGE_FLAGS) .with(|&v, n| if v & 0x80 != 0 {
            n.summary(format!("local color table of {} entries", 2u32 << (v & 7)))
        } else { n }),
    }
}

record! {
    pub struct GraphicControl {
        size: u8 "Block size",
        flags: u8 "Flags" .flags(GCE_FLAGS),
        delay: u16 "Delay time" .desc("In hundredths of a second")
            .with(|&d, n| n.summary(format!("{} ms", u32::from(d).saturating_mul(10)))),
        transparent: u8 "Transparent color index",
    }
}

record! {
    pub struct PlainText {
        size: u8 "Block size",
        left: u16 "Text grid left",
        top: u16 "Text grid top",
        width: u16 "Text grid width",
        height: u16 "Text grid height",
        cell_width: u8 "Character cell width",
        cell_height: u8 "Character cell height",
        foreground: u8 "Foreground color index",
        background: u8 "Background color index",
    }
}

record! {
    pub struct Application {
        size: u8 "Block size",
        identifier: ascii[8] "Application identifier",
        auth: ascii[3] "Authentication code",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, LE);
    let version = cur.bytes(6).await?;
    cx.emit(
        Node::new("Signature")
            .span(input.span.sub(0, 6))
            .value(text(String::from_utf8_lossy(&version))),
    );
    let (screen, screen_span) = cur.record::<ScreenDescriptor>().await?;
    cx.emit(ScreenDescriptor::node("Logical Screen Descriptor", screen_span, LE));
    let version = String::from_utf8_lossy(version.get(3..).unwrap_or_default()).into_owned();
    let mut summary = format!("GIF{version}, {}", dims(screen.width, screen.height));
    if screen.flags & 0x80 != 0 {
        let len = table_size(screen.flags);
        cx.emit(palette("Global Color Table", cur.span(len), ColorOrder::Rgb));
        cur.skip(len);
        summary = format!("{summary}, {} colors", 2u32 << (screen.flags & 7));
    }
    cx.annotate(summary);

    let mut images = 0u64;
    while !cur.at_end() {
        let start = cur.pos();
        let kind = cur.u8().await?;
        match kind {
            0x3b => {
                cx.push(Node::new("Trailer").span(cur.since(start))).await;
                break;
            }
            0x21 => {
                let label = cur.u8().await?;
                if label == 0xff {
                    cur.skip(Application::SIZE);
                } else if label == 0x01 {
                    cur.skip(PlainText::SIZE);
                } else if label == 0xf9 {
                    cur.skip(GraphicControl::SIZE);
                }
                let (count, len) = skip_sub_blocks(&mut cur).await?;
                let span = cur.since(start);
                let name = crate::value::lookup(LABELS, label.into())
                    .map_or_else(|| format!("Extension {label:#04x}"), str::to_owned);
                let summary = extension_summary(&cx, span, label).await;
                cx.push(
                    Node::new(name)
                        .span(span)
                        .summary(summary.unwrap_or_else(|| sub_block_summary(count, len)))
                        .lazy(extension, (input, span, label)),
                )
                .await;
            }
            0x2c => {
                cur.seek(start);
                let (desc, _) = cur.record::<ImageDescriptor>().await?;
                if desc.flags & 0x80 != 0 {
                    cur.skip(table_size(desc.flags));
                }
                cur.skip(1);
                skip_sub_blocks(&mut cur).await?;
                let span = cur.since(start);
                let mut summary = dims(desc.width, desc.height);
                if desc.left != 0 || desc.top != 0 {
                    summary = format!("{summary} at ({}, {})", desc.left, desc.top);
                }
                if desc.flags & 0x40 != 0 {
                    summary.push_str(", interlaced");
                }
                cx.push(
                    Node::new(format!("Image #{images}"))
                        .span(span)
                        .summary(summary)
                        .lazy(image, span),
                )
                .await;
                images = images.saturating_add(1);
            }
            _ => {
                return Err(Diagnostic::malformed(format!(
                    "unexpected block introducer {kind:#04x}"
                ))
                .at(cur.since(start)));
            }
        }
    }
    if !cur.at_end() {
        let rest = input.span.tail(cur.pos());
        cx.push(
            embedded("Trailing data", input.nested(rest))
                .summary(format!("{:#x} bytes after the trailer", rest.len)),
        )
        .await;
    }
    Ok(())
}

fn sub_block_summary(count: u64, len: u64) -> String {
    format!("{count} sub-blocks, {len:#x} bytes")
}

/// Skips data sub-blocks up to and including the terminator; returns the
/// number of sub-blocks and their total data length.
async fn skip_sub_blocks(cur: &mut Cursor<'_>) -> Result<(u64, u64)> {
    let mut count = 0u64;
    let mut total = 0u64;
    loop {
        let len = cur.u8().await?;
        if len == 0 {
            return Ok((count, total));
        }
        cur.skip(len.into());
        count = count.saturating_add(1);
        total = total.saturating_add(len.into());
    }
}

/// The data of the sub-blocks in `span`, concatenated (at most `max` bytes).
async fn sub_block_data(cx: &Cx, span: Span, max: u64) -> Result<Vec<u8>> {
    let mut cur = Cursor::new(cx, span, LE);
    let mut out = Vec::new();
    while !cur.at_end() && crate::bytes::to_u64(out.len()) < max {
        let len = cur.u8().await?;
        if len == 0 {
            break;
        }
        out.extend(cur.bytes(len.into()).await?);
    }
    Ok(out)
}

/// A one-line summary for well-known extensions (loop count, delay, text).
async fn extension_summary(cx: &Cx, span: Span, label: u8) -> Option<String> {
    match label {
        0xf9 => {
            let gce = parse(cx, span.sub(2, GraphicControl::SIZE), LE, &(), GraphicControl::layout)
                .await
                .ok()?;
            let mut out = format!("delay {} ms", u32::from(gce.delay).saturating_mul(10));
            if gce.flags & 1 != 0 {
                out = format!("{out}, transparent index {}", gce.transparent);
            }
            Some(out)
        }
        0xff => {
            let app = parse(cx, span.sub(2, Application::SIZE), LE, &(), Application::layout)
                .await
                .ok()?;
            let id = format!("{}{}", app.identifier, app.auth);
            if id == "NETSCAPE2.0" || id == "ANIMEXTS1.0" {
                let data = sub_block_data(cx, span.tail(2u64.saturating_add(Application::SIZE)), 16)
                    .await
                    .ok()?;
                if data.first() == Some(&1) {
                    let loops = crate::bytes::u16_le(&data, 1)?;
                    return Some(if loops == 0 {
                        format!("{id}, loops forever")
                    } else {
                        format!("{id}, {loops} loops")
                    });
                }
            }
            Some(id)
        }
        0xfe => {
            let data = sub_block_data(cx, span.tail(2), 80).await.ok()?;
            let line = String::from_utf8_lossy(&data);
            Some(line.lines().next().unwrap_or_default().chars().take(60).collect())
        }
        _ => None,
    }
}

async fn extension(cx: Cx, (input, span, label): (Input, Span, u8)) -> Result<()> {
    let block = cx.block(span.sub(0, 2)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("Extension introducer").hex().emit()?;
    f.u8("Label").enumeration(LABELS).emit()?;
    let mut pos = 2u64;
    match label {
        0xf9 => {
            cx.emit(GraphicControl::node(
                "Graphic Control",
                span.sub(pos, GraphicControl::SIZE),
                LE,
            ));
            pos = pos.saturating_add(GraphicControl::SIZE);
        }
        0x01 => {
            cx.emit(PlainText::node("Text grid", span.sub(pos, PlainText::SIZE), LE));
            pos = pos.saturating_add(PlainText::SIZE);
        }
        0xff => {
            let header = span.sub(pos, Application::SIZE);
            cx.emit(Application::node("Application", header, LE));
            pos = pos.saturating_add(Application::SIZE);
            let app = parse(&cx, header, LE, &(), Application::layout).await?;
            let data = span.tail(pos);
            if app.identifier == "NETSCAPE" || app.identifier == "ANIMEXTS" {
                let bytes = sub_block_data(&cx, data, 16).await?;
                if bytes.first() == Some(&1) {
                    let loops = crate::bytes::u16_le(&bytes, 1).unwrap_or(0);
                    cx.emit(
                        Node::new("Loop count")
                            .span(data.sub(2, 2))
                            .value(uint(loops))
                            .desc("0 = loop forever"),
                    );
                }
            } else if app.identifier == "ICCRGBG1" {
                let profile = sub_block_data(&cx, data, cx.limits().max_read).await?;
                let decoded = super::reassembled(&cx, data, "gif-sub-blocks", profile)?;
                cx.emit(
                    embedded("ICC profile", input.nested(decoded))
                        .summary(format!("{:#x} bytes from sub-blocks", decoded.len)),
                );
            }
        }
        0xfe => {
            let data = span.tail(pos);
            let bytes = sub_block_data(&cx, data, 0x10000).await?;
            cx.emit(
                Node::new("Comment")
                    .span(data)
                    .value(text(crate::text::latin1(&bytes))),
            );
        }
        _ => {}
    }
    cx.emit(sub_blocks("Data sub-blocks", span.tail(pos)));
    Ok(())
}

async fn image(cx: Cx, span: Span) -> Result<()> {
    let desc_span = span.sub(0, ImageDescriptor::SIZE);
    let desc = parse(&cx, desc_span, LE, &(), ImageDescriptor::layout).await?;
    cx.emit(ImageDescriptor::node("Image Descriptor", desc_span, LE));
    let mut pos = ImageDescriptor::SIZE;
    if desc.flags & 0x80 != 0 {
        let len = table_size(desc.flags);
        cx.emit(palette("Local Color Table", span.sub(pos, len), ColorOrder::Rgb));
        pos = pos.saturating_add(len);
    }
    let code_size = cx.block(span.sub(pos, 1)).await?;
    Fields::emitting(&cx, &code_size, LE)
        .u8("LZW minimum code size")
        .emit()?;
    pos = pos.saturating_add(1);
    cx.emit(sub_blocks("Image data", span.tail(pos)).desc("LZW-compressed pixel indices"));
    Ok(())
}

/// A lazy node listing the data sub-blocks in `span`, paged.
fn sub_blocks(name: &'static str, span: Span) -> Node {
    Node::new(name).span(span).lazy(list_sub_blocks, span)
}

async fn list_sub_blocks(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let mut index = 0u64;
    while !cur.at_end() {
        let start = cur.pos();
        let len = cur.u8().await?;
        if len == 0 {
            cx.push(Node::new("Block terminator").span(cur.since(start)))
                .await;
            break;
        }
        cur.skip(len.into());
        cx.push(
            Node::new(format!("[{index}]"))
                .span(cur.since(start))
                .summary(format!("{len} bytes")),
        )
        .await;
        index = index.saturating_add(1);
    }
    Ok(())
}
