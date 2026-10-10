//! GIF (87a and 89a).
//!
//! Header, logical screen descriptor and global color table, then a stream
//! of blocks: extensions (graphic control, application, comment, plain text)
//! and images, each followed by length-prefixed data sub-blocks. Blocks are
//! listed in pages; images and extensions decode their fields on expansion.
//! Each image's summary carries the timing of the graphic control extension
//! before it, and the file's summary the frame count, total duration and
//! loop count.

use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::fmt::plural;
use crate::formats::util::val::{text, uint};
use crate::formats::{Format, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, flag};

use super::{ColorOrder, dims, palette, playing_time};

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
    field(0x1c, 0x04, "DO_NOT_DISPOSE"),
    field(0x1c, 0x08, "RESTORE_TO_BACKGROUND"),
    field(0x1c, 0x0c, "RESTORE_TO_PREVIOUS"),
    flag(0x02, "USER_INPUT"),
    flag(0x01, "TRANSPARENT_COLOR"),
];

const DISPOSAL: EnumTable = &[
    (0, "unspecified"),
    (1, "do not dispose"),
    (2, "restore to background"),
    (3, "restore to previous"),
];

const LABELS: EnumTable = &[
    (0x01, "Plain Text Extension"),
    (0xf9, "Graphic Control Extension"),
    (0xfe, "Comment Extension"),
    (0xff, "Application Extension"),
];

const NETSCAPE_SUB_BLOCKS: EnumTable = &[(1, "loop count"), (2, "buffering size")];

/// Size in bytes of a color table whose packed size field is `bits`.
fn table_size(packed: u8) -> u64 {
    3u64.saturating_mul(2u64.checked_shl((packed & 7).into()).unwrap_or(0))
}

fn table_entries(packed: u8) -> u32 {
    2u32 << (packed & 7)
}

record! {
    pub struct ScreenDescriptor {
        width: u16 "Logical screen width",
        height: u16 "Logical screen height",
        flags: u8 "Flags" .flags(SCREEN_FLAGS) .with(|&v, n| if v & 0x80 != 0 {
            n.summary(format!("global color table of {} entries", 2u32 << (v & 7)))
        } else { n })
            .desc("Bit 7: global color table; bits 4–6: color resolution − 1 (bits per primary); bit 3: table sorted by importance; bits 0–2: log2(table entries) − 1"),
        background: u8 "Background color index" .desc("Index into the global color table"),
        aspect: u8 "Pixel aspect ratio" .with(|&a, n| if a == 0 { n.summary("not given (square)") } else {
            n.summary(format!("{:.3} (width / height)", (f64::from(a) + 15.0) / 64.0))
        }) .desc("(aspect + 15) / 64; 0 = not given"),
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
        } else { n })
            .desc("Bit 7: local color table; bit 6: interlaced (rows in 4 passes: every 8th from 0, every 8th from 4, every 4th from 2, every 2nd from 1); bit 5: sorted; bits 0–2: log2(table entries) − 1"),
    }
}

record! {
    pub struct GraphicControl {
        size: u8 "Block size" .desc("Always 4"),
        flags: u8 "Flags" .flags(GCE_FLAGS) .with(|&v, n| n.summary(format!(
            "disposal: {}",
            crate::value::lookup(DISPOSAL, ((v >> 2) & 7).into()).unwrap_or("reserved")
        ))) .desc("Bits 2–4: disposal method (what happens to the image's area before the next one is drawn); bit 1: wait for user input; bit 0: transparent color index is valid"),
        delay: u16 "Delay time" .desc("In hundredths of a second")
            .with(|&d, n| n.summary(format!("{} ms", u32::from(d).saturating_mul(10)))),
        transparent: u8 "Transparent color index" .desc("Pixels of this index are not drawn (only if the transparency flag is set)"),
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
        size: u8 "Block size" .desc("Always 11"),
        identifier: ascii[8] "Application identifier",
        auth: ascii[3] "Authentication code",
    }
}

/// The 258 bytes that end an XMP application extension: 0x01, 0xff down
/// to 0x00, then the block terminator. Whatever byte a sub-block reader
/// lands on in the packet, it skips to the terminator.
const XMP_TRAILER: u64 = 258;

/// Timing and transparency for the next image.
#[derive(Clone, Copy, Debug, Default)]
struct Control {
    delay: u16,
    disposal: u8,
    transparent: Option<u8>,
    user_input: bool,
}

impl Control {
    fn from_record(gce: &GraphicControl) -> Self {
        Control {
            delay: gce.delay,
            disposal: (gce.flags >> 2) & 7,
            transparent: (gce.flags & 1 != 0).then_some(gce.transparent),
            user_input: gce.flags & 2 != 0,
        }
    }

    fn describe(&self) -> String {
        let mut out = format!("delay {} ms", u32::from(self.delay).saturating_mul(10));
        if self.disposal != 0 {
            out.push_str(", ");
            out.push_str(
                crate::value::lookup(DISPOSAL, self.disposal.into()).unwrap_or("reserved disposal"),
            );
        }
        if let Some(t) = self.transparent {
            out.push_str(&format!(", transparent index {t}"));
        }
        if self.user_input {
            out.push_str(", waits for input");
        }
        out
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, LE);
    let version = cur.bytes(6).await?;
    let version = String::from_utf8_lossy(version.get(3..).unwrap_or_default()).into_owned();
    cx.emit(
        Node::new("Signature")
            .span(input.span.sub(0, 6))
            .value(text(format!("GIF{version}")))
            .desc("\"GIF\" and the version: 87a, or 89a (extensions)"),
    );
    let (screen, screen_span) = cur.record::<ScreenDescriptor>().await?;
    cx.emit(
        ScreenDescriptor::node("Logical Screen Descriptor", screen_span, LE)
            .summary(dims(screen.width, screen.height)),
    );
    let mut summary = format!("GIF{version}, {}", dims(screen.width, screen.height));
    if screen.flags & 0x80 != 0 {
        let len = table_size(screen.flags);
        cx.emit(palette(
            "Global Color Table",
            cur.span(len),
            ColorOrder::Rgb,
        ));
        cur.skip(len);
        summary = format!("{summary}, {} colors", table_entries(screen.flags));
    }
    cx.annotate(summary.clone());
    let mut looping: Option<u16> = None;
    let mut control: Option<Control> = None;
    let mut centiseconds = 0u64;
    let mut images = 0u64;
    let mut trailer = false;

    while !cur.at_end() {
        let start = cur.pos();
        cx.progress_in(input.span, input.span.offset.saturating_add(start));
        let kind = cur.u8().await?;
        match kind {
            0x3b => {
                cx.push(
                    Node::new("Trailer")
                        .span(cur.since(start))
                        .desc("End of the GIF data stream (0x3b)"),
                )
                .await;
                trailer = true;
                break;
            }
            0x21 => {
                let label = cur.u8().await?;
                let (count, len) = skip_sub_blocks(&mut cur).await?;
                let span = cur.since(start);
                let name = crate::value::lookup(LABELS, label.into())
                    .map_or_else(|| format!("Extension {label:#04x}"), str::to_owned);
                let info = extension_summary(&cx, span, label).await;
                match &info {
                    Some(Info::Control(c)) => {
                        control = Some(*c);
                    }
                    Some(Info::Loop(l)) => looping = Some(*l),
                    _ => {}
                }
                let line = match info {
                    Some(i) => i.describe(),
                    None => sub_block_summary(count, len),
                };
                cx.push(
                    Node::new(name)
                        .span(span)
                        .summary(line)
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
                let (_, data_len) = skip_sub_blocks(&mut cur).await?;
                let span = cur.since(start);
                let mut line = dims(desc.width, desc.height);
                if desc.left != 0 || desc.top != 0 {
                    line = format!("{line} at ({}, {})", desc.left, desc.top);
                }
                if desc.flags & 0x40 != 0 {
                    line.push_str(", interlaced");
                }
                if desc.flags & 0x80 != 0 {
                    line = format!("{line}, {} local colors", table_entries(desc.flags));
                }
                if let Some(c) = control.take() {
                    centiseconds = centiseconds.saturating_add(c.delay.into());
                    line = format!("{line}, {}", c.describe());
                }
                line = format!("{line}, {} of LZW data", human_size(data_len));
                cx.push(
                    Node::new(format!("Image #{images}"))
                        .span(span)
                        .summary(line)
                        .lazy(image, span),
                )
                .await;
                images = images.saturating_add(1);
            }
            _ => {
                cx.diag(
                    Diagnostic::malformed(format!("unexpected block introducer {kind:#04x}"))
                        .at(cur.since(start)),
                );
                cur.seek(start);
                break;
            }
        }
    }
    if !trailer && cur.at_end() {
        cx.diag(Diagnostic::warning(
            "no trailer (0x3b): the file is truncated",
        ));
    }
    // Once the whole stream has been listed, the frame count is known.
    if images > 1 {
        let mut full = format!(
            "{summary}, {}, {}",
            plural(images, "frame"),
            playing_time(centiseconds as f64 / 100.0)
        );
        match looping {
            Some(0) => full.push_str(", loops forever"),
            Some(n) => full.push_str(&format!(", repeats {}", plural(n, "time"))),
            None => {}
        }
        cx.annotate(full);
    }
    if !cur.at_end() {
        let rest = input.span.tail(cur.pos());
        cx.push(
            embedded("Trailing data", input.nested(rest))
                .summary(format!("{} after the last block", human_size(rest.len))),
        )
        .await;
    }
    Ok(())
}

fn sub_block_summary(count: u64, len: u64) -> String {
    format!("{}, {}", plural(count, "sub-block"), human_size(len))
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

/// What the list shows for an extension.
enum Info {
    Control(Control),
    Loop(u16),
    Text(String),
}

impl Info {
    fn describe(self) -> String {
        match self {
            Info::Control(c) => c.describe(),
            Info::Loop(0) => "NETSCAPE2.0, loops forever".to_owned(),
            Info::Loop(n) => format!("NETSCAPE2.0, repeats {}", plural(n, "time")),
            Info::Text(s) => s,
        }
    }
}

/// Whether the application extension in `span` ends in the XMP magic
/// trailer.
async fn has_xmp_trailer(cx: &Cx, span: Span) -> bool {
    let at = span.len.saturating_sub(XMP_TRAILER);
    let Ok(t) = cx.read_avail(span.sub(at, XMP_TRAILER)).await else {
        return false;
    };
    crate::bytes::to_u64(t.len()) == XMP_TRAILER
        && t.first() == Some(&1)
        && t.get(1..257).is_some_and(|ramp| {
            ramp.iter()
                .zip((0u8..=255).rev())
                .all(|(&b, want)| b == want)
        })
        && t.get(257) == Some(&0)
}

/// A one-line summary for well-known extensions (loop count, delay, text).
async fn extension_summary(cx: &Cx, span: Span, label: u8) -> Option<Info> {
    match label {
        0xf9 => {
            let gce = parse(
                cx,
                span.sub(2, GraphicControl::SIZE),
                LE,
                &(),
                GraphicControl::layout,
            )
            .await
            .ok()?;
            Some(Info::Control(Control::from_record(&gce)))
        }
        0xff => {
            let app = parse(
                cx,
                span.sub(2, Application::SIZE),
                LE,
                &(),
                Application::layout,
            )
            .await
            .ok()?;
            let id = format!("{}{}", app.identifier, app.auth);
            let data = span.tail(2u64.saturating_add(Application::SIZE));
            match id.as_str() {
                "NETSCAPE2.0" | "ANIMEXTS1.0" => {
                    let bytes = sub_block_data(cx, data, 16).await.ok()?;
                    if bytes.first() == Some(&1) {
                        let loops = crate::bytes::u16_le(&bytes, 1)?;
                        if id.starts_with("NETSCAPE") {
                            return Some(Info::Loop(loops));
                        }
                        return Some(Info::Text(if loops == 0 {
                            format!("{id}, loops forever")
                        } else {
                            format!("{id}, repeats {}", plural(loops, "time"))
                        }));
                    }
                    Some(Info::Text(id))
                }
                "XMP DataXMP" if has_xmp_trailer(cx, span).await => Some(Info::Text(format!(
                    "XMP packet, {}",
                    human_size(data.len.saturating_sub(XMP_TRAILER))
                ))),
                "ICCRGBG1012" => {
                    let (count, len) = sub_block_totals(cx, data).await.ok()?;
                    Some(Info::Text(format!(
                        "ICC profile, {} in {}",
                        human_size(len),
                        plural(count, "sub-block")
                    )))
                }
                _ => Some(Info::Text(id)),
            }
        }
        0xfe => {
            let data = sub_block_data(cx, span.tail(2), 80).await.ok()?;
            let line = crate::text::latin1(&data);
            Some(Info::Text(
                line.lines()
                    .next()
                    .unwrap_or_default()
                    .chars()
                    .take(60)
                    .collect(),
            ))
        }
        0x01 => {
            let data = sub_block_data(cx, span.tail(2u64.saturating_add(PlainText::SIZE)), 80)
                .await
                .ok()?;
            let line = crate::text::latin1(&data);
            Some(Info::Text(format!(
                "\"{}\"",
                line.chars().take(60).collect::<String>()
            )))
        }
        _ => None,
    }
}

/// Number and total data length of the sub-blocks in `span`.
async fn sub_block_totals(cx: &Cx, span: Span) -> Result<(u64, u64)> {
    let mut cur = Cursor::new(cx, span, LE);
    skip_sub_blocks(&mut cur).await
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
            cx.emit(PlainText::node(
                "Text grid",
                span.sub(pos, PlainText::SIZE),
                LE,
            ));
            pos = pos.saturating_add(PlainText::SIZE);
            let data = span.tail(pos);
            let bytes = sub_block_data(&cx, data, 0x10000).await?;
            cx.emit(
                Node::new("Text")
                    .span(data)
                    .value(text(crate::text::latin1(&bytes)))
                    .desc("Rendered into the text grid, one character per cell"),
            );
        }
        0xff => {
            let header = span.sub(pos, Application::SIZE);
            let app = parse(&cx, header, LE, &(), Application::layout).await?;
            let id = format!("{}{}", app.identifier, app.auth);
            cx.emit(Application::node("Application", header, LE).summary(id.clone()));
            pos = pos.saturating_add(Application::SIZE);
            let data = span.tail(pos);
            match id.as_str() {
                "NETSCAPE2.0" | "ANIMEXTS1.0" => netscape(&cx, data).await?,
                "XMP DataXMP" if has_xmp_trailer(&cx, span).await => {
                    let packet = data.sub(0, data.len.saturating_sub(XMP_TRAILER));
                    cx.emit(
                        embedded_as(
                            "XMP packet",
                            input.nested(packet),
                            &crate::formats::image::xmp::FORMAT,
                        )
                        .summary(format!("{} of XML, stored raw", human_size(packet.len))),
                    );
                    cx.emit(
                        Node::new("Magic trailer")
                            .span(data.tail(packet.len))
                            .desc("0x01, 0xff … 0x00 and the block terminator: lets readers that parse the packet as sub-blocks skip it"),
                    );
                    return Ok(());
                }
                "ICCRGBG1012" => {
                    let profile = sub_block_data(&cx, data, cx.limits().max_read).await?;
                    let decoded = super::reassembled(&cx, data, "gif-sub-blocks", profile)?;
                    cx.emit(
                        embedded("ICC profile", input.nested(decoded))
                            .summary(format!("{} from sub-blocks", human_size(decoded.len))),
                    );
                }
                _ => {}
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

/// NETSCAPE2.0 / ANIMEXTS1.0 sub-blocks: an ID, then a loop count (1) or a
/// buffer size (2).
async fn netscape(cx: &Cx, data: Span) -> Result<()> {
    let mut cur = Cursor::new(cx, data, LE);
    while !cur.at_end() {
        let start = cur.pos();
        let len = cur.u8().await?;
        if len == 0 {
            break;
        }
        let body = data.sub(start.saturating_add(1), len.into());
        cur.skip(len.into());
        let bytes = cx.read(body).await?;
        let id = bytes.first().copied().unwrap_or(0);
        let value = body.tail(1);
        match id {
            1 => {
                let loops = crate::bytes::u16_le(&bytes, 1).unwrap_or(0);
                cx.emit(
                    Node::new("Loop count")
                        .span(value)
                        .value(uint(loops, 64))
                        .summary(if loops == 0 {
                            "loop forever".to_owned()
                        } else {
                            format!("repeat {}", plural(loops, "time"))
                        })
                        .desc("Sub-block 1: times to repeat the animation; 0 = forever"),
                );
            }
            2 => {
                let size = crate::bytes::u32_le(&bytes, 1).unwrap_or(0);
                cx.emit(
                    Node::new("Buffering size")
                        .span(value)
                        .value(uint(size, 64))
                        .desc("Sub-block 2: bytes to buffer before playing"),
                );
            }
            _ => cx.emit(Node::new(format!("Sub-block {id}")).span(body).summary(
                crate::value::lookup(NETSCAPE_SUB_BLOCKS, id.into()).unwrap_or("unknown"),
            )),
        }
    }
    Ok(())
}

async fn image(cx: Cx, span: Span) -> Result<()> {
    let desc_span = span.sub(0, ImageDescriptor::SIZE);
    let desc = parse(&cx, desc_span, LE, &(), ImageDescriptor::layout).await?;
    cx.emit(ImageDescriptor::node("Image Descriptor", desc_span, LE));
    let mut pos = ImageDescriptor::SIZE;
    if desc.flags & 0x80 != 0 {
        let len = table_size(desc.flags);
        cx.emit(palette(
            "Local Color Table",
            span.sub(pos, len),
            ColorOrder::Rgb,
        ));
        pos = pos.saturating_add(len);
    }
    let code_size = cx.block(span.sub(pos, 1)).await?;
    Fields::emitting(&cx, &code_size, LE)
        .u8("LZW minimum code size")
        .with(|&v, n| {
            n.summary(format!(
                "codes start at {} bits; clear = {}, end = {}",
                u32::from(v).saturating_add(1),
                1u32.checked_shl(v.into()).unwrap_or(0),
                1u32.checked_shl(v.into()).unwrap_or(0).saturating_add(1)
            ))
        })
        .check(|&v| (!(2..=8).contains(&v)).then(|| Diagnostic::warning("must be 2 to 8")))
        .emit()?;
    pos = pos.saturating_add(1);
    let data = span.tail(pos);
    let (count, len) = sub_block_totals(&cx, data).await?;
    cx.emit(
        sub_blocks("Image data", data)
            .summary(format!(
                "{} of LZW codes in {}",
                human_size(len),
                plural(count, "sub-block")
            ))
            .desc("LZW-compressed color indices, in sub-blocks of up to 255 bytes"),
    );
    Ok(())
}

/// A lazy node listing the data sub-blocks in `span`, paged.
fn sub_blocks(name: &'static str, span: Span) -> Node {
    Node::new(name).span(span).lazy(list_sub_blocks, span)
}

async fn list_sub_blocks(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let (first, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    cur.seek(first);
    while !cur.at_end() {
        let start = cur.pos();
        let at = (start, index);
        cx.mark(move || at);
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
