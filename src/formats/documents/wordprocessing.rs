//! Word-processor and authoring documents: WordPerfect, Windows Write and
//! FrameMaker (OneNote is in [`super::onenote`]).

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// WordPerfect, Windows Write, FrameMaker

declare_format!(pub WORDPERFECT = "wordperfect", "WordPerfect document", ["wpd", "wp", "wp5", "wp6"], "application/vnd.wordperfect",
    Probe::Magic(&[(0, b"\xffWPC")]), wordperfect);

const WP_TYPES: EnumTable = &[
    (10, "document"),
    (11, "dictionary"),
    (12, "thesaurus"),
    (17, "macro"),
    (22, "graphics"),
];

async fn wordperfect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Magic", 4).emit()?;
    let doc = f.u32("Document area offset").hex().emit()?;
    f.u8("Product type").emit()?;
    let kind = f.u8("File type").enumeration(WP_TYPES).emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    f.u16("Encryption").hex().emit()?;
    cx.emit(Node::new("Prefix packets").span(file.sub(16, u64::from(doc).saturating_sub(16))));
    cx.emit(Node::new("Document area").span(file.tail(doc.into())));
    let version = match major {
        1 => "5.x",
        2 => "6.x or later",
        _ => "unknown version",
    };
    cx.annotate(format!(
        "WordPerfect {version} {} (format {major}.{minor})",
        lookup(WP_TYPES, kind.into()).unwrap_or("file")
    ));
    Ok(())
}

declare_format!(pub WRITE = "mswrite", "Microsoft Write document", ["wri"], "application/x-mswrite",
    Probe::Magic(&[(0, b"\x31\xbe\x00\x00\x00\xab"), (0, b"\x32\xbe\x00\x00\x00\xab")]), mswrite);

async fn mswrite(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 128)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u16("Identifier").hex().emit()?;
    f.u16("Reserved").emit()?;
    f.u16("Tool").hex().emit()?;
    f.bytes("Reserved", 8).emit()?;
    let text_end = f.u32("End of text (fcMac)").emit()?;
    let _ = f.u16("Paragraph info page (pnPara)").emit()?;
    let text_span = file.sub(128, u64::from(text_end).saturating_sub(128));
    let sample = cx.read_avail(text_span.sub(0, 120)).await?;
    cx.emit(
        Node::new("Text")
            .span(text_span)
            .summary(String::from_utf8_lossy(&sample).replace(['\r', '\n'], " ")),
    );
    cx.annotate(format!("Write document, {} characters", text_span.len));
    Ok(())
}

declare_format!(pub FRAMEMAKER = "framemaker", "Adobe FrameMaker document", ["fm", "book", "mif"], "application/vnd.framemaker",
    Probe::Magic(&[(0, b"<MakerFile"), (0, b"<MIFFile"), (0, b"<BookFile"), (0, b"<MakerDictionary"), (0, b"<MakerScreenFont")]), framemaker);

async fn framemaker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 64)).await?;
    let end = head.iter().position(|&b| b == b'>').unwrap_or(0);
    let tag =
        String::from_utf8_lossy(head.get(..end.saturating_add(1)).unwrap_or_default()).into_owned();
    cx.emit(
        Node::new("Identification")
            .span(file.sub(0, to_u64(end).saturating_add(1)))
            .value(text(tag.clone())),
    );
    cx.emit(Node::new("Body").span(file.tail(to_u64(end).saturating_add(1))));
    cx.annotate(tag.trim_matches(['<', '>']).to_owned());
    Ok(())
}
